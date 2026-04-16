#requires -RunAsAdministrator
#requires -Modules ActiveDirectory

# =============================================================================
# Copyright (c) 2026 realworldtec
# Licensed under the PolyForm Noncommercial License 1.0.0
# https://polyformproject.org/licenses/noncommercial/1.0.0
# Commercial use requires a separate written agreement.
# Repository: https://github.com/realworldtec/windows-ca-pki-hardening
# =============================================================================

<#
.SYNOPSIS

Invoke-PKIComplianceSuite.ps1
Git Private Repository CA VSCode Test

Validates the effective AD CS certificate issuance posture for a target Enterprise CA.

.DESCRIPTION
This script performs a read-only compliance review of the hardened certificate templates
that are currently configured in the CA's "Certificate Templates to Issue" list.

By default, it validates only the templates actively published by the specified CA.
If -AllTemplates is used, it validates all hardened templates defined in the script baseline.

For each template in scope, it checks:
- Display name
- Schema version
- Minimum key size
- EKUs / application policies
- Validity period
- Renewal period
- CSP / KSP list
- Template ACLs

It also performs:
- Enterprise CA AD registration permissions audit
- Live CA service permissions audit
- PKI role-based access reporting

This script is intended to support:
- audit evidence generation
- drift detection
- pre/post-change validation
- PKI governance reviews

.PARAMETER OutputPath
Directory where JSON and CSV artifacts will be written.

.PARAMETER IncludeAclDetail
Includes raw ACL detail in the JSON output.

.PARAMETER CACommonName
Common name of the CA, for example:
    [domain]-Internal-CA

If omitted and only one Enterprise CA exists in AD, that CA is used automatically.
If multiple CAs exist, this parameter is required.

.PARAMETER CAHostName
DNS name or NetBIOS name of the CA server for live CA service permission auditing.
Example:
    [ca-hostname]
    [ca-hostname].[domain].local

If omitted, live CA service permissions are audited locally.

.PARAMETER AllTemplates
Evaluates all hardened templates defined in the script baseline instead of limiting
scope to the CA's current "Certificates to Issue" list.

.EXAMPLE
.\Invoke-PKIComplianceSuite.ps1 -CACommonName '[domain]-Internal-CA' -CAHostName '[ca-hostname]'

Runs compliance validation against only the templates currently issued by [domain]-Internal-CA,
plus AD registration and live CA service permission audits.

.EXAMPLE
.\Invoke-PKIComplianceSuite.ps1 -CACommonName '[domain]-Internal-CA' -CAHostName '[ca-hostname]' -IncludeAclDetail

Runs compliance validation and includes template ACL detail in the JSON output.

.EXAMPLE
.\Invoke-PKIComplianceSuite.ps1 -AllTemplates -CAHostName '[ca-hostname]'

Runs compliance validation against all hardened baseline templates, regardless of whether
they are currently configured to issue from the CA.

.NOTES
Run this script from Windows PowerShell 5.1 on a management host such as [management-host].
Do not run AD CS deployment or governance tooling from PowerShell 7.

This script is read-only. It does not modify templates, CA configuration, or ACLs.
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\PKICompliance",
    [switch]$IncludeAclDetail,
    [string]$CACommonName = '',
    [string]$CAHostName = '',
    [switch]$AllTemplates
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------

$ConfigNC = (Get-ADRootDSE).configurationNamingContext
$TemplateBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"
$EnrollmentBase = "CN=Enrollment Services,CN=Public Key Services,CN=Services,$ConfigNC"

if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}

$TimeStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$JsonOut = Join-Path $OutputPath "TemplateCompliance_$TimeStamp.json"
$CsvOut = Join-Path $OutputPath "TemplateCompliance_$TimeStamp.csv"
$RoleCsvOut = Join-Path $OutputPath "PKIRoleAccessReport_$TimeStamp.csv"
$CaCsvOut = Join-Path $OutputPath "CARegistrationPermissions_$TimeStamp.csv"
$LiveCaCsvOut = Join-Path $OutputPath "LiveCAPermissions_$TimeStamp.csv"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

function Write-Info {
    param([string]$Message)
    Write-Host "[INFO] $Message" -ForegroundColor Cyan
}

function Write-Ok {
    param([string]$Message)
    Write-Host "[ OK ] $Message" -ForegroundColor Green
}

function Write-WarnMsg {
    param([string]$Message)
    Write-Host "[WARN] $Message" -ForegroundColor Yellow
}

function Write-Fail {
    param([string]$Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}

# ---------------------------------------------------------------------------
# General helpers
# ---------------------------------------------------------------------------

function Convert-FileTimePeriod {
    param(
        [byte[]]$Bytes
    )

    if (-not $Bytes -or $Bytes.Count -ne 8) {
        return $null
    }

    $ticks = [System.BitConverter]::ToInt64($Bytes, 0)
    if ($ticks -eq 0) { return $null }

    $span = [TimeSpan]::FromTicks([math]::Abs($ticks))

    [pscustomobject]@{
        Days     = [math]::Round($span.TotalDays, 2)
        Hours    = [math]::Round($span.TotalHours, 2)
        RawTicks = $ticks
    }
}

function Get-NormalizedCspList {
    param($Value)

    if (-not $Value) { return @() }

    $items = foreach ($entry in @($Value)) {
        $text = $entry.ToString().Trim()

        if ($text -match '^\d+,(.+)$') {
            $cspName = $Matches[1].Trim()
            if ($cspName) { $cspName }
        }
        else {
            $text
        }
    }

    @($items | Sort-Object -Unique)
}

function Get-TemplateEkuList {
    param(
        [Parameter(Mandatory)]
        $TemplateObject
    )

    $ekuValues = @()

    if ($TemplateObject.PSObject.Properties['pKIExtendedKeyUsage']) {
        $ekuValues += @($TemplateObject.'pKIExtendedKeyUsage')
    }

    if ($TemplateObject.PSObject.Properties['msPKI-Certificate-Application-Policy']) {
        $ekuValues += @($TemplateObject.'msPKI-Certificate-Application-Policy')
    }

    @($ekuValues | Where-Object { $_ } | Sort-Object -Unique)
}

function Test-ExpectedValue {
    param(
        [string]$Name,
        $Actual,
        $Expected
    )

    if ($null -eq $Expected) {
        return [pscustomobject]@{
            Name     = $Name
            Result   = 'SKIP'
            Actual   = $Actual
            Expected = $Expected
        }
    }

    $pass = $false

    if ($Actual -is [System.Array] -or $Expected -is [System.Array]) {
        $actualSet = @($Actual) | Sort-Object
        $expectedSet = @($Expected) | Sort-Object
        $pass = (@(Compare-Object -ReferenceObject $expectedSet -DifferenceObject $actualSet).Count -eq 0)
    }
    else {
        $pass = ($Actual -eq $Expected)
    }

    [pscustomobject]@{
        Name     = $Name
        Result   = if ($pass) { 'PASS' } else { 'FAIL' }
        Actual   = $Actual
        Expected = $Expected
    }
}

# ---------------------------------------------------------------------------
# Template lookup and CA scope helpers
# ---------------------------------------------------------------------------

function Get-TemplateObjectByDisplayName {
    param(
        [Parameter(Mandatory)]
        [string]$DisplayName
    )

    $all = Get-ADObject `
        -SearchBase $TemplateBase `
        -LDAPFilter "(objectClass=pKICertificateTemplate)" `
        -Properties displayName, cn, * `
        -ErrorAction Stop

    $normalized = ($DisplayName -replace '[\s\-–—]', '').ToLowerInvariant()

    $obj = $all | Where-Object {
        ($_.displayName -and $_.displayName -eq $DisplayName) -or
        ($_.cn -and (($_.cn -replace '[\s\-–—]', '').ToLowerInvariant() -eq $normalized))
    } | Select-Object -First 1

    return $obj
}

function Get-TemplateAclSummary {
    param(
        [Parameter(Mandatory)]
        [string]$DistinguishedName
    )

    $enrollGuid = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $autoEnrollGuid = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

    $de = [ADSI]("LDAP://$DistinguishedName")
    $acl = $de.ObjectSecurity

    $rules = foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])) {
        $rightType =
        switch ($ace.ObjectType.Guid) {
            $enrollGuid { 'Enroll'; break }
            $autoEnrollGuid { 'AutoEnroll'; break }
            default {
                if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericRead) {
                    'Read'
                }
                else {
                    'Other'
                }
            }
        }

        [pscustomobject]@{
            Principal  = ($ace.IdentityReference.Value -replace '^.+\\', '')
            Rights     = $rightType
            Access     = $ace.AccessControlType.ToString()
            ObjectType = $ace.ObjectType.Guid
        }
    }

    $rules | Sort-Object Principal, Rights
}

function Get-IssuedTemplateNamesFromCA {
    [CmdletBinding()]
    param(
        [string]$CACommonName
    )

    if ([string]::IsNullOrWhiteSpace($CACommonName)) {
        $caObjects = Get-ADObject `
            -SearchBase $EnrollmentBase `
            -LDAPFilter '(objectClass=pKIEnrollmentService)' `
            -Properties displayName, cn, certificateTemplates

        if (@($caObjects).Count -eq 0) {
            throw "No Enrollment Services CA objects found in AD."
        }

        if (@($caObjects).Count -gt 1) {
            $names = @($caObjects | ForEach-Object { $_.displayName })
            throw "Multiple CA objects found. Specify -CACommonName. Found: $($names -join ', ')"
        }

        $ca = $caObjects | Select-Object -First 1
    }
    else {
        $ca = Get-ADObject `
            -SearchBase $EnrollmentBase `
            -LDAPFilter "(&(objectClass=pKIEnrollmentService)(cn=$CACommonName))" `
            -Properties displayName, cn, certificateTemplates `
            -ErrorAction Stop
    }

    if (-not $ca) {
        throw "CA Enrollment Services object not found for [$CACommonName]."
    }

    return @($ca.certificateTemplates | Sort-Object -Unique)
}

# ---------------------------------------------------------------------------
# Template baseline
# ---------------------------------------------------------------------------

$ExpectedTemplates = @{
    'Code Signing - Hardened'                     = @{
        SchemaVersion  = 4
        MinimalKeySize = 3072
        Ekus           = @('1.3.6.1.5.5.7.3.3')
        ValidityDays   = 365
        RenewalDays    = 42
        CspLike        = @('Microsoft Software Key Storage Provider')
        AclExpected    = @(
            'PKI-CodeSigners|Read|Allow',
            'PKI-CodeSigners|Enroll|Allow',
            'PKI-Admins|Read|Allow'
        )
    }

    'Computer - Hardened'                         = @{
        SchemaVersion  = 4
        MinimalKeySize = 3072
        Ekus           = @(
            '1.3.6.1.5.5.7.3.1',
            '1.3.6.1.5.5.7.3.2'
        )
        ValidityDays   = 365
        RenewalDays    = 42
        CspLike        = @('Microsoft Software Key Storage Provider')
        AclExpected    = @(
            'Domain Computers|Read|Allow',
            'Domain Computers|Enroll|Allow',
            'Domain Computers|AutoEnroll|Allow',
            'PKI-Admins|Read|Allow'
        )
    }

    'Directory Email Replication - Hardened'      = @{
        SchemaVersion  = 4
        MinimalKeySize = 3072
        Ekus           = @('1.3.6.1.4.1.311.21.19')
        ValidityDays   = 365
        RenewalDays    = 42
        CspLike        = @('Microsoft Software Key Storage Provider')
        AclExpected    = @(
            'Domain Controllers|Read|Allow',
            'Domain Controllers|Enroll|Allow',
            'Domain Controllers|AutoEnroll|Allow',
            'PKI-Admins|Read|Allow'
        )
    }

    'Domain Controller - Hardened'                = @{
        SchemaVersion  = 4
        MinimalKeySize = 3072
        Ekus           = @(
            '1.3.6.1.5.5.7.3.1',
            '1.3.6.1.5.5.7.3.2'
        )
        ValidityDays   = 365
        RenewalDays    = 42
        CspLike        = @('Microsoft Software Key Storage Provider')
        AclExpected    = @(
            'Domain Controllers|Read|Allow',
            'Domain Controllers|Enroll|Allow',
            'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS|Read|Allow',
            'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS|Enroll|Allow',
            'PKI-Admins|Read|Allow'
        )
    }

    'Domain Controller Authentication - Hardened' = @{
        SchemaVersion  = 4
        MinimalKeySize = 3072
        Ekus           = @(
            '1.3.6.1.5.5.7.3.1',
            '1.3.6.1.5.5.7.3.2',
            '1.3.6.1.4.1.311.20.2.2'
        )
        ValidityDays   = 365
        RenewalDays    = 42
        CspLike        = @('Microsoft Software Key Storage Provider')
        AclExpected    = @(
            'Domain Controllers|Read|Allow',
            'Domain Controllers|Enroll|Allow',
            'Domain Controllers|AutoEnroll|Allow',
            'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS|Read|Allow',
            'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS|Enroll|Allow',
            'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS|AutoEnroll|Allow',
            'PKI-Admins|Read|Allow'
        )
    }

    'Kerberos Authentication - Hardened'          = @{
        SchemaVersion  = 4
        MinimalKeySize = 3072
        Ekus           = @(
            '1.3.6.1.5.5.7.3.1',
            '1.3.6.1.5.5.7.3.2',
            '1.3.6.1.5.2.3.5'
        )
        ValidityDays   = 365
        RenewalDays    = 42
        CspLike        = @('Microsoft Software Key Storage Provider')
        AclExpected    = @(
            'Domain Controllers|Read|Allow',
            'Domain Controllers|Enroll|Allow',
            'Domain Controllers|AutoEnroll|Allow',
            'PKI-Admins|Read|Allow'
        )
    }

    'RDP-WinRM - Hardened'                        = @{
        SchemaVersion  = 4
        MinimalKeySize = 3072
        Ekus           = @('1.3.6.1.5.5.7.3.1')
        ValidityDays   = 365
        RenewalDays    = 42
        CspLike        = @('Microsoft Software Key Storage Provider')
        AclExpected    = @(
            'Domain Computers|Read|Allow',
            'Domain Computers|Enroll|Allow',
            'PKI-Admins|Read|Allow'
        )
    }

    'Web Server - Appliance'                      = @{
        SchemaVersion  = 4
        MinimalKeySize = 2048
        Ekus           = @('1.3.6.1.5.5.7.3.1')
        ValidityDays   = 730
        RenewalDays    = 42
        CspLike        = @('Microsoft Software Key Storage Provider')
        AclExpected    = @(
            'PKI-ApplianceCerts|Read|Allow',
            'PKI-ApplianceCerts|Enroll|Allow',
            'PKI-Admins|Read|Allow'
        )
    }

    'Web Server - Hardened'                       = @{
        SchemaVersion  = 4
        MinimalKeySize = 2048
        Ekus           = @('1.3.6.1.5.5.7.3.1')
        ValidityDays   = 730
        RenewalDays    = 42
        CspLike        = @('Microsoft Software Key Storage Provider')
        AclExpected    = @(
            'PKI-Admins|Read|Allow',
            'PKI-Admins|Enroll|Allow'
        )
    }
}

$ExpectedTemplateMap = @{
    'Code Signing - Hardened'                     = 'CodeSigning-Hardened'
    'Computer - Hardened'                         = 'Computer-Hardened'
    'Directory Email Replication - Hardened'      = 'DirectoryEmailReplication-Hardened'
    'Domain Controller - Hardened'                = 'DomainController-Hardened'
    'Domain Controller Authentication - Hardened' = 'DomainControllerAuthentication-Hardened'
    'Kerberos Authentication - Hardened'          = 'KerberosAuthentication-Hardened'
    'RDP-WinRM - Hardened'                        = 'RDP-WinRM-Hardened'
    'Web Server - Appliance'                      = 'WebServer-Appliance'
    'Web Server - Hardened'                       = 'WebServer-Hardened'
}

# ---------------------------------------------------------------------------
# Enterprise CA AD registration permissions audit
# ---------------------------------------------------------------------------

function Test-CAPermissions {
    [CmdletBinding()]
    param(
        [string]$CACommonName = '',
        [string[]]$ExpectedAdminPrincipals = @('PKI-Admins'),
        [string[]]$WarnIfPresentPrincipals = @('Domain Admins', 'Enterprise Admins', 'Authenticated Users')
    )

    if ([string]::IsNullOrWhiteSpace($CACommonName)) {
        $caObjects = Get-ADObject `
            -SearchBase $EnrollmentBase `
            -LDAPFilter '(objectClass=pKIEnrollmentService)' `
            -Properties displayName, dNSHostName, distinguishedName, nTSecurityDescriptor `
            -ErrorAction Stop
    }
    else {
        $caObjects = Get-ADObject `
            -SearchBase $EnrollmentBase `
            -LDAPFilter "(&(objectClass=pKIEnrollmentService)(cn=$CACommonName))" `
            -Properties displayName, dNSHostName, distinguishedName, nTSecurityDescriptor `
            -ErrorAction Stop
    }

    if (-not @($caObjects).Count) {
        throw "No Enterprise CA Enrollment Services objects found."
    }

    $results = foreach ($ca in $caObjects) {
        $de = [ADSI]("LDAP://$($ca.DistinguishedName)")
        $acl = $de.ObjectSecurity

        foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])) {
            $principal = $ace.IdentityReference.Value -replace '^.+\\', ''

            $finding =
            if ($ExpectedAdminPrincipals -contains $principal) {
                'ExpectedAdminPrincipalPresent'
            }
            elseif ($WarnIfPresentPrincipals -contains $principal) {
                'ReviewPrincipalPresent'
            }
            else {
                'Informational'
            }

            [PSCustomObject]@{
                CAName            = $ca.displayName
                HostName          = $ca.dNSHostName
                DistinguishedName = $ca.DistinguishedName
                Principal         = $principal
                IdentityReference = $ace.IdentityReference.Value
                Rights            = $ace.ActiveDirectoryRights.ToString()
                AccessType        = $ace.AccessControlType.ToString()
                ObjectType        = $ace.ObjectType.Guid
                InheritanceType   = $ace.InheritanceType.ToString()
                IsInherited       = [bool]$ace.IsInherited
                Finding           = $finding
            }
        }
    }

    @($results | Sort-Object CAName, Principal, Rights)
}

# ---------------------------------------------------------------------------
# Live CA service permissions audit
# ---------------------------------------------------------------------------

function Test-LiveCAPermissions {
    [CmdletBinding()]
    param(
        [string]$CAHostName = '',
        [string]$CACommonName = '',
        [string[]]$ExpectedAdminPrincipals = @('PKI-Admins'),
        [string[]]$WarnIfPresentPrincipals = @('Domain Admins', 'Enterprise Admins', 'Authenticated Users')
    )

    $scriptBlock = {
        param($RemoteCACommonName)

        function Convert-CaAccessMask {
            param([int]$AccessMask)

            $rights = New-Object System.Collections.Generic.List[string]

            if ($AccessMask -band 0x00000001) { $rights.Add('Manage CA') }
            if ($AccessMask -band 0x00000002) { $rights.Add('Issue and Manage Certificates') }
            if ($AccessMask -band 0x00000100) { $rights.Add('Read') }
            if ($AccessMask -band 0x00000200) { $rights.Add('Request Certificates') }
            if ($AccessMask -band 0x00000004) { $rights.Add('Audit Log') }
            if ($AccessMask -band 0x00000008) { $rights.Add('Operator') }

            if ($rights.Count -eq 0) {
                $rights.Add(("Unknown(0x{0:X})" -f $AccessMask))
            }

            return @($rights)
        }

        $configRoot = 'HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration'

        if (-not (Test-Path $configRoot)) {
            throw "Certification Services configuration registry path not found: $configRoot"
        }

        $caName = $RemoteCACommonName

        if ([string]::IsNullOrWhiteSpace($caName)) {
            $candidateKeys = Get-ChildItem -Path $configRoot -ErrorAction Stop |
            Where-Object {
                (Get-ItemProperty -Path $_.PSPath -Name Security -ErrorAction SilentlyContinue)
            }

            if (@($candidateKeys).Count -eq 0) {
                throw "No CA configuration keys with a Security descriptor were found."
            }

            if (@($candidateKeys).Count -gt 1) {
                $names = @($candidateKeys | ForEach-Object { $_.PSChildName })
                throw "Multiple CA configuration keys found. Specify -CACommonName. Found: $($names -join ', ')"
            }

            $caName = $candidateKeys[0].PSChildName
        }

        $caRegPath = Join-Path $configRoot $caName

        if (-not (Test-Path $caRegPath)) {
            throw "CA configuration registry path not found: $caRegPath"
        }

        $secValue = (Get-ItemProperty -Path $caRegPath -Name Security -ErrorAction Stop).Security
        if (-not $secValue) {
            throw "Security descriptor value not found at: $caRegPath"
        }

        $rawSd = New-Object System.Security.AccessControl.RawSecurityDescriptor ($secValue, 0)

        $owner = $null
        $group = $null

        try { $owner = $rawSd.Owner.Translate([System.Security.Principal.NTAccount]).Value } catch { $owner = $rawSd.Owner.Value }
        try { $group = $rawSd.Group.Translate([System.Security.Principal.NTAccount]).Value } catch { $group = $rawSd.Group.Value }

        $results = foreach ($ace in $rawSd.DiscretionaryAcl) {
            $sidValue = $ace.SecurityIdentifier.Value

            $resolvedName = $sidValue
            try {
                $resolvedName = $ace.SecurityIdentifier.Translate([System.Security.Principal.NTAccount]).Value
            }
            catch { }

            $principalShort = $resolvedName -replace '^.+\\', ''
            $rights = Convert-CaAccessMask -AccessMask $ace.AccessMask

            [PSCustomObject]@{
                CAName                        = $caName
                Principal                     = $principalShort
                IdentityReference             = $resolvedName
                SID                           = $sidValue
                AceType                       = $ace.AceType.ToString()
                AccessMask                    = $ace.AccessMask
                Rights                        = ($rights -join '; ')
                HasManageCA                   = [bool]($ace.AccessMask -band 0x00000001)
                HasIssueAndManageCertificates = [bool]($ace.AccessMask -band 0x00000002)
                HasRead                       = [bool]($ace.AccessMask -band 0x00000100)
                HasRequestCertificates        = [bool]($ace.AccessMask -band 0x00000200)
                Owner                         = $owner
                Group                         = $group
            }
        }

        @($results | Sort-Object Principal, IdentityReference, AccessMask)
    }

    $liveResults =
    if ([string]::IsNullOrWhiteSpace($CAHostName)) {
        & $scriptBlock $CACommonName
    }
    else {
        Invoke-Command -ComputerName $CAHostName -ScriptBlock $scriptBlock -ArgumentList $CACommonName
    }

    foreach ($row in $liveResults) {
        if ($ExpectedAdminPrincipals -contains $row.Principal) {
            Add-Member -InputObject $row -NotePropertyName Finding -NotePropertyValue 'ExpectedAdminPrincipalPresent' -Force
        }
        elseif ($WarnIfPresentPrincipals -contains $row.Principal) {
            Add-Member -InputObject $row -NotePropertyName Finding -NotePropertyValue 'ReviewPrincipalPresent' -Force
        }
        else {
            Add-Member -InputObject $row -NotePropertyName Finding -NotePropertyValue 'Informational' -Force
        }
    }

    @($liveResults)
}

# ---------------------------------------------------------------------------
# Role-based access report
# ---------------------------------------------------------------------------

function Get-PKIRoleAccessReport {
    [CmdletBinding()]
    param(
        [string[]]$TemplateNamesInScope
    )

    $enrollGuid = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
    $autoEnrollGuid = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

    $report = @()

    foreach ($templateName in $TemplateNamesInScope) {
        $tmpl = Get-TemplateObjectByDisplayName -DisplayName $templateName
        if (-not $tmpl) { continue }

        $de = [ADSI]("LDAP://$($tmpl.DistinguishedName)")
        $acl = $de.ObjectSecurity

        foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])) {
            $principal = ($ace.IdentityReference.Value -replace '^.+\\', '')

            $right =
            switch ($ace.ObjectType.Guid) {
                $enrollGuid { 'Enroll'; break }
                $autoEnrollGuid { 'AutoEnroll'; break }
                default {
                    if ($ace.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::GenericRead) {
                        'Read'
                    }
                    else {
                        'Other'
                    }
                }
            }

            if ($right -eq 'Other') { continue }

            $role =
            switch ($principal) {
                'PKI-Admins' { 'PKI Governance'; break }
                'PKI-CodeSigners' { 'Code Signing'; break }
                'PKI-ApplianceCerts' { 'Appliance Issuance'; break }
                'Domain Computers' { 'Machine Autoenrollment'; break }
                'Domain Controllers' { 'Domain Controller Autoenrollment'; break }
                'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS' { 'Domain Controller Autoenrollment'; break }
                default { 'Unclassified / Review Required' }
            }

            $report += [PSCustomObject]@{
                TemplateName = $tmpl.displayName
                Principal    = $principal
                Role         = $role
                Right        = $right
                Access       = $ace.AccessControlType.ToString()
            }
        }
    }

    $report | Sort-Object TemplateName, Role, Principal, Right
}

# ---------------------------------------------------------------------------
# Determine template scope
# ---------------------------------------------------------------------------

if ($AllTemplates) {
    Write-Info "Template scope: all hardened baseline templates"
    $TemplatesToEvaluate = $ExpectedTemplates.Keys | Sort-Object
}
else {
    Write-Info "Template scope: only templates currently issued by the CA"
    $IssuedTemplateCnList = Get-IssuedTemplateNamesFromCA -CACommonName $CACommonName

    $TemplatesToEvaluate = foreach ($displayName in ($ExpectedTemplates.Keys | Sort-Object)) {
        $cnName = $ExpectedTemplateMap[$displayName]
        if ($IssuedTemplateCnList -contains $cnName) {
            $displayName
        }
    }

    if (@($TemplatesToEvaluate).Count -eq 0) {
        throw "No expected hardened templates were found in the CA 'Certificates to Issue' list."
    }

    $ExpectedTemplateMapValues = @($ExpectedTemplateMap.Values)
    $UnexpectedIssuedTemplates = @($IssuedTemplateCnList | Where-Object { $ExpectedTemplateMapValues -notcontains $_ })

    if (@($UnexpectedIssuedTemplates).Count -gt 0) {
        Write-WarnMsg "CA is issuing unexpected templates: $($UnexpectedIssuedTemplates -join ', ')"
    }
    else {
        Write-Ok "CA issuance list contains only expected templates"
    }

    Write-Info "CA is currently configured to issue: $($TemplatesToEvaluate -join ', ')"
}

# ---------------------------------------------------------------------------
# Main template validation
# ---------------------------------------------------------------------------

Write-Info "Starting hardened template compliance validation"

$Results = foreach ($templateName in $TemplatesToEvaluate) {
    try {
        $expected = $ExpectedTemplates[$templateName]
        $obj = Get-TemplateObjectByDisplayName -DisplayName $templateName

        if (-not $obj) {
            throw "Template must exist and be readable"
        }

        $validityBytes = if ($obj.PSObject.Properties['pKIExpirationPeriod']) { $obj.'pKIExpirationPeriod' } else { $null }
        $renewalBytes = if ($obj.PSObject.Properties['pKIOverlapPeriod']) { $obj.'pKIOverlapPeriod' } else { $null }

        $validity = if ($validityBytes) { Convert-FileTimePeriod -Bytes $validityBytes } else { $null }
        $renewal = if ($renewalBytes) { Convert-FileTimePeriod -Bytes $renewalBytes } else { $null }

        $ekus = Get-TemplateEkuList -TemplateObject $obj
        $cspList = Get-NormalizedCspList -Value $obj.'pKIDefaultCSPs'
        $aclRaw = Get-TemplateAclSummary -DistinguishedName $obj.DistinguishedName
        $aclNorm = @(
            $aclRaw |
            Where-Object { $_.Rights -ne 'Other' } |
            ForEach-Object { "{0}|{1}|{2}" -f $_.Principal, $_.Rights, $_.Access }
        ) | Sort-Object -Unique

        $checks = @(
            Test-ExpectedValue -Name 'DisplayName'    -Actual $obj.displayName                     -Expected $templateName
            Test-ExpectedValue -Name 'SchemaVersion'  -Actual $obj.'msPKI-Template-Schema-Version' -Expected $expected.SchemaVersion
            Test-ExpectedValue -Name 'MinimalKeySize' -Actual $obj.'msPKI-Minimal-Key-Size'        -Expected $expected.MinimalKeySize
            Test-ExpectedValue -Name 'EKUs'           -Actual $ekus                                -Expected $expected.Ekus
            Test-ExpectedValue -Name 'ValidityDays'   -Actual ([math]::Round($validity.Days, 0))    -Expected $expected.ValidityDays
            Test-ExpectedValue -Name 'RenewalDays'    -Actual ([math]::Round($renewal.Days, 0))     -Expected $expected.RenewalDays
        )

        $cspCheck = Test-ExpectedValue -Name 'CSPs' -Actual $cspList -Expected $expected.CspLike
        if ($cspCheck.Result -eq 'FAIL') { $cspCheck.Result = 'WARN' }

        $aclCheck = Test-ExpectedValue -Name 'ACL' -Actual $aclNorm -Expected $expected.AclExpected
        if ($aclCheck.Result -eq 'FAIL') { $aclCheck.Result = 'WARN' }

        $checks += $cspCheck
        $checks += $aclCheck

        $overall =
        if ($checks.Result -contains 'FAIL') { 'FAIL' }
        elseif ($checks.Result -contains 'WARN') { 'WARN' }
        else { 'PASS' }

        [pscustomobject]@{
            TemplateName      = $templateName
            DistinguishedName = $obj.DistinguishedName
            OverallResult     = $overall
            Checks            = $checks
            RawAttributes     = [pscustomobject]@{
                TemplateCN          = $obj.cn
                DisplayName         = $obj.displayName
                SchemaVersion       = $obj.'msPKI-Template-Schema-Version'
                MinimalKeySize      = $obj.'msPKI-Minimal-Key-Size'
                EKUs                = $ekus
                CspList             = $cspList
                Validity            = $validity
                Renewal             = $renewal
                NameFlags           = $obj.'msPKI-Certificate-Name-Flag'
                EnrollmentFlags     = $obj.'msPKI-Enrollment-Flag'
                PrivateKeyFlags     = $obj.'msPKI-Private-Key-Flag'
                KeyUsage            = $obj.'pKIKeyUsage'
                ApplicationPolicies = if ($obj.PSObject.Properties['msPKI-Certificate-Application-Policy']) {
                    @($obj.'msPKI-Certificate-Application-Policy')
                }
                else {
                    @()
                }
            }
            AclDetail         = if ($IncludeAclDetail) { $aclRaw } else { $null }
        }
    }
    catch {
        [pscustomobject]@{
            TemplateName      = $templateName
            DistinguishedName = $null
            OverallResult     = 'FAIL'
            Checks            = @(
                [pscustomobject]@{
                    Name     = 'Lookup'
                    Result   = 'FAIL'
                    Actual   = $_.Exception.Message
                    Expected = 'Template must exist and be readable'
                }
            )
            RawAttributes     = $null
            AclDetail         = $null
        }
    }
}

# ---------------------------------------------------------------------------
# Outputs
# ---------------------------------------------------------------------------

$summary = $Results | Select-Object TemplateName, OverallResult
$summary | Export-Csv -Path $CsvOut -NoTypeInformation
$Results | ConvertTo-Json -Depth 8 | Out-File -FilePath $JsonOut -Encoding utf8

Write-Host ""
Write-Host "Compliance Summary" -ForegroundColor Cyan
$summary | Format-Table -AutoSize
Write-Host ""

$failCount = @($summary | Where-Object { $_.OverallResult -eq 'FAIL' }).Count
$passCount = @($summary | Where-Object { $_.OverallResult -eq 'PASS' }).Count
$warnCount = @($summary | Where-Object { $_.OverallResult -eq 'WARN' }).Count

Write-Host "PASS: $passCount  WARN: $warnCount  FAIL: $failCount" -ForegroundColor White

foreach ($result in $Results) {
    if ($result.OverallResult -eq 'FAIL') {
        Write-Host ""
        Write-Host "Template: $($result.TemplateName)" -ForegroundColor Yellow
        $result.Checks |
        Where-Object { $_.Result -eq 'FAIL' } |
        Format-Table Name, Actual, Expected -AutoSize
    }
}

Write-Host ""
Write-Info "Running Enterprise CA AD registration permissions audit"
$CaPermissionResults = Test-CAPermissions -CACommonName $CACommonName
$CaPermissionResults | Export-Csv -Path $CaCsvOut -NoTypeInformation
$CaPermissionResults | Format-Table -AutoSize
Write-Info "CA registration permissions report : $CaCsvOut"

Write-Host ""
Write-Info "Running live CA service permissions audit"
$LiveCaPermissionResults = Test-LiveCAPermissions -CAHostName $CAHostName -CACommonName $CACommonName
$LiveCaPermissionResults | Export-Csv -Path $LiveCaCsvOut -NoTypeInformation
$LiveCaPermissionResults |
Select-Object CAName, Principal, Rights, HasManageCA, HasIssueAndManageCertificates, HasRead, HasRequestCertificates, Finding |
Format-Table -AutoSize
Write-Info "Live CA permissions report : $LiveCaCsvOut"

Write-Host ""
Write-Info "Generating PKI role-based access report"
$RoleAccessReport = Get-PKIRoleAccessReport -TemplateNamesInScope $TemplatesToEvaluate
$RoleAccessReport | Export-Csv -Path $RoleCsvOut -NoTypeInformation
$RoleAccessReport | Format-Table -AutoSize
Write-Info "Role report : $RoleCsvOut"

if ($failCount -eq 0) {
    Write-Ok "All templates passed compliance validation"
}
else {
    Write-Fail "$failCount template(s) failed compliance validation"
}

Write-Info "CSV output : $CsvOut"
Write-Info "JSON output: $JsonOut"
Write-Info "Validation complete"
