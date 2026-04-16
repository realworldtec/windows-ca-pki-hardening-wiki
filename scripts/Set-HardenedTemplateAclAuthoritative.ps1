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
Authoritatively enforces hardened certificate template ACLs with built-in backup and restore.

.DESCRIPTION
This script implements least-privilege ACL enforcement for the hardened certificate templates
used by the Enterprise CA. It supports three modes:

- Review / dry-run
- Enforce with automatic backup
- Restore from a prior backup

When -Enforce is used, the script automatically creates a rollback backup of the current
template ACL state before making changes.

Backups include:
- template name
- distinguished name
- owner SID
- group SID
- DACL protection state
- full ACE list and metadata

This script is intended to:
- remove duplication residue and over-privileged principals
- standardize template ACLs
- support auditable change control
- provide rollback safety

.PARAMETER Enforce
Applies the authoritative ACL changes. Automatically performs a backup first.

.PARAMETER ShowFinalAcl
Shows the projected or resulting ACL state for each template.

.PARAMETER BackupPath
Directory where automatic backup files are written.

.PARAMETER RestoreFromBackup
Restores template ACLs from the specified backup file and exits.

.EXAMPLE
.\Set-HardenedTemplateAclAuthoritative.ps1

Runs in review mode only. No changes are made.

.EXAMPLE
.\Set-HardenedTemplateAclAuthoritative.ps1 -ShowFinalAcl

Runs in review mode and shows the projected final ACL state.

.EXAMPLE
.\Set-HardenedTemplateAclAuthoritative.ps1 -Enforce

Creates an automatic backup, then applies authoritative ACL cleanup.

.EXAMPLE
.\Set-HardenedTemplateAclAuthoritative.ps1 -RestoreFromBackup .\TemplateAclBackup\[domain]_TemplateAclBackup_20260327_171822.json

Restores ACLs from a previously captured backup file.

.NOTES
Run this script from Windows PowerShell 5.1 on a management host such as [management-host].
This script modifies AD certificate template ACLs when -Enforce or -RestoreFromBackup is used.
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Enforce,
    [switch]$ShowFinalAcl,
    [string]$BackupPath = '.\TemplateAclBackup',
    [string]$RestoreFromBackup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module ActiveDirectory

$ConfigNC = (Get-ADRootDSE).configurationNamingContext
$TemplateBase = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigNC"

$EnrollGuid = [Guid]'0e10c968-78fb-11d2-90d4-00c04f79dc55'
$AutoEnrollGuid = [Guid]'a05b8cc2-17bc-4802-a710-e7c15ab866a2'
$ReadRights = [System.DirectoryServices.ActiveDirectoryRights]::GenericRead
$AllowType = [System.Security.AccessControl.AccessControlType]::Allow

function Write-Info { param([string]$m) Write-Host "[INFO] $m" -ForegroundColor Cyan }
function Write-Ok { param([string]$m) Write-Host "[ OK ] $m" -ForegroundColor Green }
function Write-Warn { param([string]$m) Write-Host "[WARN] $m" -ForegroundColor Yellow }
function Write-Fail { param([string]$m) Write-Host "[FAIL] $m" -ForegroundColor Red }

function Get-TemplateObjectByDisplayName {
    param([Parameter(Mandatory)][string]$DisplayName)

    $all = Get-ADObject `
        -SearchBase $TemplateBase `
        -LDAPFilter "(objectClass=pKICertificateTemplate)" `
        -Properties displayName, cn, nTSecurityDescriptor, distinguishedName `
        -ErrorAction Stop

    $normalized = ($DisplayName -replace '[\s\-–—]', '').ToLowerInvariant()

    $obj = $all | Where-Object {
        ($_.displayName -and $_.displayName -eq $DisplayName) -or
        ($_.cn -and (($_.cn -replace '[\s\-–—]', '').ToLowerInvariant() -eq $normalized))
    } | Select-Object -First 1

    if (-not $obj) {
        throw "Template not found: $DisplayName"
    }

    return $obj
}

function Get-DirectoryEntry {
    param([Parameter(Mandatory)][string]$DistinguishedName)
    [ADSI]("LDAP://$DistinguishedName")
}

function Resolve-Principal {
    param(
        [Parameter(Mandatory)]
        [string]$Name
    )

    switch ($Name.ToUpperInvariant()) {
        'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS' { return New-Object System.Security.Principal.SecurityIdentifier('S-1-5-9') }
        'ENTERPRISE DOMAIN CONTROLLERS' { return New-Object System.Security.Principal.SecurityIdentifier('S-1-5-9') }
        'NT AUTHORITY\AUTHENTICATED USERS' { return New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11') }
        'AUTHENTICATED USERS' { return New-Object System.Security.Principal.SecurityIdentifier('S-1-5-11') }
    }

    if ($Name -match '^S-\d-\d+(-\d+)+$') {
        return New-Object System.Security.Principal.SecurityIdentifier($Name)
    }

    try {
        if ($Name -match '^[^\\]+\\[^\\]+$') {
            $nt = New-Object System.Security.Principal.NTAccount($Name)
            return $nt.Translate([System.Security.Principal.SecurityIdentifier])
        }
    }
    catch { }

    try {
        $group = Get-ADGroup -Identity $Name -Properties SID -ErrorAction Stop
        return New-Object System.Security.Principal.SecurityIdentifier($group.SID.Value)
    }
    catch { }

    try {
        $user = Get-ADUser -Identity $Name -Properties SID -ErrorAction Stop
        return New-Object System.Security.Principal.SecurityIdentifier($user.SID.Value)
    }
    catch { }

    try {
        $obj = Get-ADObject `
            -LDAPFilter "(|(cn=$Name)(name=$Name)(sAMAccountName=$Name))" `
            -Properties objectSid `
            -ErrorAction Stop |
        Select-Object -First 1

        if ($obj -and $obj.objectSid) {
            return New-Object System.Security.Principal.SecurityIdentifier($obj.objectSid, 0)
        }
    }
    catch { }

    try {
        $domain = $env:USERDOMAIN
        if ($domain) {
            $nt = New-Object System.Security.Principal.NTAccount($domain, $Name)
            return $nt.Translate([System.Security.Principal.SecurityIdentifier])
        }
    }
    catch { }

    throw "Unable to resolve principal: $Name"
}

function New-ExpectedAceMap {
    param([array]$Entries)

    $map = @{}
    foreach ($e in $Entries) {
        $key = "{0}|{1}|Allow" -f $e.Principal, $e.Right
        $map[$key] = $true
    }
    return $map
}

function Get-AceRightLabel {
    param($Ace)

    if ($Ace.ObjectType -eq $EnrollGuid) { return 'Enroll' }
    if ($Ace.ObjectType -eq $AutoEnrollGuid) { return 'AutoEnroll' }

    if ($Ace.ObjectType -eq [Guid]::Empty -and ($Ace.ActiveDirectoryRights -band $ReadRights)) {
        return 'Read'
    }

    return 'Other'
}

function Get-AclSummary {
    param([System.DirectoryServices.ActiveDirectorySecurity]$Acl)

    foreach ($ace in $Acl.GetAccessRules($true, $true, [System.Security.Principal.NTAccount])) {
        [pscustomobject]@{
            Principal = ($ace.IdentityReference.Value -replace '^.+\\', '')
            Right     = Get-AceRightLabel -Ace $ace
            Access    = $ace.AccessControlType.ToString()
            Raw       = $ace
        }
    }
}

function Add-ExpectedAce {
    param(
        [System.DirectoryServices.ActiveDirectorySecurity]$Acl,
        [string]$Principal,
        [ValidateSet('Read', 'Enroll', 'AutoEnroll')][string]$Right
    )

    $sid = Resolve-Principal -Name $Principal

    switch ($Right) {
        'Read' {
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($sid, $ReadRights, $AllowType)
        }
        'Enroll' {
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $sid,
                [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                $AllowType,
                $EnrollGuid
            )
        }
        'AutoEnroll' {
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $sid,
                [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight,
                $AllowType,
                $AutoEnrollGuid
            )
        }
    }

    $Acl.AddAccessRule($rule) | Out-Null
}

function Remove-UnexpectedAces {
    param(
        [System.DirectoryServices.ActiveDirectorySecurity]$Acl,
        [hashtable]$ExpectedMap
    )

    $removed = New-Object System.Collections.Generic.List[string]
    $summary = Get-AclSummary -Acl $Acl

    foreach ($row in $summary) {
        if ($row.Right -eq 'Other') { continue }
        $key = "{0}|{1}|{2}" -f $row.Principal, $row.Right, $row.Access
        if (-not $ExpectedMap.ContainsKey($key)) {
            $Acl.RemoveAccessRuleSpecific($row.Raw)
            $removed.Add($key)
        }
    }

    return $removed
}

function Set-MissingAces {
    param(
        [System.DirectoryServices.ActiveDirectorySecurity]$Acl,
        [array]$ExpectedEntries
    )

    $added = New-Object System.Collections.Generic.List[string]
    $current = Get-AclSummary -Acl $Acl | ForEach-Object {
        "{0}|{1}|{2}" -f $_.Principal, $_.Right, $_.Access
    }

    foreach ($e in $ExpectedEntries) {
        $key = "{0}|{1}|Allow" -f $e.Principal, $e.Right
        if ($current -notcontains $key) {
            Add-ExpectedAce -Acl $Acl -Principal $e.Principal -Right $e.Right
            $added.Add($key)
        }
    }

    return $added
}

function Get-ShortDomainName {
    [CmdletBinding()]
    param()

    $dnsRoot = (Get-ADDomain).DNSRoot
    return ($dnsRoot -split '\.')[0].ToLowerInvariant()
}

function Backup-HardenedTemplateAcl {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$TemplateNames,

        [Parameter(Mandatory)]
        [string]$OutputPath
    )

    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $shortDomain = Get-ShortDomainName
    $timeStamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $outFile = Join-Path $OutputPath ("{0}_TemplateAclBackup_{1}.json" -f $shortDomain, $timeStamp)

    $backup = foreach ($name in $TemplateNames) {
        $tmpl = Get-TemplateObjectByDisplayName -DisplayName $name
        if (-not $tmpl) {
            throw "Template not found during backup: $name"
        }

        $de = [ADSI]("LDAP://$($tmpl.DistinguishedName)")
        $acl = $de.ObjectSecurity

        $owner = $null
        $group = $null
        try { $owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value } catch { }
        try { $group = $acl.GetGroup([System.Security.Principal.SecurityIdentifier]).Value } catch { }

        $aces = foreach ($ace in $acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
            [pscustomobject]@{
                IdentityReference     = $ace.IdentityReference.Value
                ActiveDirectoryRights = [int]$ace.ActiveDirectoryRights
                AccessControlType     = [string]$ace.AccessControlType
                ObjectType            = $ace.ObjectType.Guid
                InheritedObjectType   = $ace.InheritedObjectType.Guid
                InheritanceType       = [string]$ace.InheritanceType
                InheritanceFlags      = [string]$ace.InheritanceFlags
                PropagationFlags      = [string]$ace.PropagationFlags
                IsInherited           = [bool]$ace.IsInherited
            }
        }

        [pscustomobject]@{
            TemplateName            = $name
            DistinguishedName       = $tmpl.DistinguishedName
            Owner                   = $owner
            Group                   = $group
            AreAccessRulesProtected = $acl.AreAccessRulesProtected
            Aces                    = $aces
        }
    }

    $backup | ConvertTo-Json -Depth 10 | Out-File -FilePath $outFile -Encoding utf8
    Write-Ok "Backup written to $outFile"
    return $outFile
}

function Restore-HardenedTemplateAcl {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [string]$BackupFile
    )

    if (-not (Test-Path $BackupFile)) {
        throw "Backup file not found: $BackupFile"
    }

    $data = Get-Content -LiteralPath $BackupFile -Raw | ConvertFrom-Json

    foreach ($template in $data) {
        $de = [ADSI]("LDAP://$($template.DistinguishedName)")
        $acl = New-Object System.DirectoryServices.ActiveDirectorySecurity

        foreach ($ace in $template.Aces) {
            $sid = New-Object System.Security.Principal.SecurityIdentifier($ace.IdentityReference)

            $rights = [System.DirectoryServices.ActiveDirectoryRights]$ace.ActiveDirectoryRights
            $accessType = [System.Security.AccessControl.AccessControlType]::$($ace.AccessControlType)
            $objectTypeGuid = if ($ace.ObjectType) { [Guid]$ace.ObjectType }          else { [Guid]::Empty }
            $inheritedGuid = if ($ace.InheritedObjectType) { [Guid]$ace.InheritedObjectType } else { [Guid]::Empty }
            $inheritanceType = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::$($ace.InheritanceType)

            if ($objectTypeGuid -eq [Guid]::Empty -and $inheritedGuid -eq [Guid]::Empty) {
                $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $sid,
                    $rights,
                    $accessType
                )
            }
            elseif ($inheritedGuid -eq [Guid]::Empty) {
                $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $sid,
                    $rights,
                    $accessType,
                    $objectTypeGuid
                )
            }
            else {
                $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $sid,
                    $rights,
                    $accessType,
                    $objectTypeGuid,
                    $inheritanceType,
                    $inheritedGuid
                )
            }

            $acl.AddAccessRule($rule) | Out-Null
        }

        if ($template.Owner) {
            $ownerSid = New-Object System.Security.Principal.SecurityIdentifier($template.Owner)
            $acl.SetOwner($ownerSid)
        }

        if ($template.Group) {
            $groupSid = New-Object System.Security.Principal.SecurityIdentifier($template.Group)
            $acl.SetGroup($groupSid)
        }

        $preserveInheritance = -not [bool]$template.AreAccessRulesProtected
        $acl.SetAccessRuleProtection([bool]$template.AreAccessRulesProtected, $preserveInheritance)

        if ($PSCmdlet.ShouldProcess($template.TemplateName, "Restore ACL/security descriptor")) {
            $de.ObjectSecurity = $acl
            $de.CommitChanges()
            Write-Ok "Restored ACL for $($template.TemplateName)"
        }
    }
}

$TemplateAclPolicy = @{
    'Code Signing - Hardened'                     = @(
        @{ Principal = 'PKI-CodeSigners'; Right = 'Read' }
        @{ Principal = 'PKI-CodeSigners'; Right = 'Enroll' }
        @{ Principal = 'PKI-Admins'; Right = 'Read' }
    )

    'Computer - Hardened'                         = @(
        @{ Principal = 'Domain Computers'; Right = 'Read' }
        @{ Principal = 'Domain Computers'; Right = 'Enroll' }
        @{ Principal = 'Domain Computers'; Right = 'AutoEnroll' }
        @{ Principal = 'PKI-Admins'; Right = 'Read' }
    )

    'Directory Email Replication - Hardened'      = @(
        @{ Principal = 'Domain Controllers'; Right = 'Read' }
        @{ Principal = 'Domain Controllers'; Right = 'Enroll' }
        @{ Principal = 'Domain Controllers'; Right = 'AutoEnroll' }
        @{ Principal = 'PKI-Admins'; Right = 'Read' }
    )

    'Domain Controller - Hardened'                = @(
        @{ Principal = 'Domain Controllers'; Right = 'Read' }
        @{ Principal = 'Domain Controllers'; Right = 'Enroll' }
        @{ Principal = 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'; Right = 'Read' }
        @{ Principal = 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'; Right = 'Enroll' }
        @{ Principal = 'PKI-Admins'; Right = 'Read' }
    )

    'Domain Controller Authentication - Hardened' = @(
        @{ Principal = 'Domain Controllers'; Right = 'Read' }
        @{ Principal = 'Domain Controllers'; Right = 'Enroll' }
        @{ Principal = 'Domain Controllers'; Right = 'AutoEnroll' }
        @{ Principal = 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'; Right = 'Read' }
        @{ Principal = 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'; Right = 'Enroll' }
        @{ Principal = 'NT AUTHORITY\ENTERPRISE DOMAIN CONTROLLERS'; Right = 'AutoEnroll' }
        @{ Principal = 'PKI-Admins'; Right = 'Read' }
    )

    'Kerberos Authentication - Hardened'          = @(
        @{ Principal = 'Domain Controllers'; Right = 'Read' }
        @{ Principal = 'Domain Controllers'; Right = 'Enroll' }
        @{ Principal = 'Domain Controllers'; Right = 'AutoEnroll' }
        @{ Principal = 'PKI-Admins'; Right = 'Read' }
    )

    'RDP-WinRM - Hardened'                        = @(
        @{ Principal = 'Domain Computers'; Right = 'Read' }
        @{ Principal = 'Domain Computers'; Right = 'Enroll' }
        @{ Principal = 'PKI-Admins'; Right = 'Read' }
    )

    'Web Server - Appliance'                      = @(
        @{ Principal = 'PKI-ApplianceCerts'; Right = 'Read' }
        @{ Principal = 'PKI-ApplianceCerts'; Right = 'Enroll' }
        @{ Principal = 'PKI-Admins'; Right = 'Read' }
    )

    'Web Server - Hardened'                       = @(
        @{ Principal = 'PKI-Admins'; Right = 'Read' }
        @{ Principal = 'PKI-Admins'; Right = 'Enroll' }
    )
}

$TemplateNames = $TemplateAclPolicy.Keys | Sort-Object

if ($RestoreFromBackup) {
    Write-Info "Restore requested from backup file: $RestoreFromBackup"
    Restore-HardenedTemplateAcl -BackupFile $RestoreFromBackup
    Write-Ok "Restore operation complete"
    return
}

$backupFile = $null
if ($Enforce) {
    Write-Info "Enforcement requested; creating automatic rollback backup first"
    $backupFile = Backup-HardenedTemplateAcl -TemplateNames $TemplateNames -OutputPath $BackupPath
    Write-Info "Rollback backup file: $backupFile"
}

Write-Info "Starting authoritative template ACL cleanup"

foreach ($templateName in $TemplateNames) {
    try {
        $tmpl = Get-TemplateObjectByDisplayName -DisplayName $templateName
        $de = Get-DirectoryEntry -DistinguishedName $tmpl.DistinguishedName
        $acl = $de.ObjectSecurity

        $expected = $TemplateAclPolicy[$templateName]
        $expectedMap = New-ExpectedAceMap -Entries $expected

        $removed = Remove-UnexpectedAces -Acl $acl -ExpectedMap $expectedMap
        $added = Set-MissingAces    -Acl $acl -ExpectedEntries $expected

        if (($removed.Count -eq 0) -and ($added.Count -eq 0)) {
            Write-Ok "$templateName already matches authoritative ACL"
        }
        else {
            Write-Warn "$templateName requires cleanup"
            foreach ($r in $removed) { Write-Host "       REMOVE $r" -ForegroundColor Yellow }
            foreach ($a in $added) { Write-Host "       ADD    $a" -ForegroundColor Yellow }

            if ($Enforce -and $PSCmdlet.ShouldProcess($templateName, "Apply authoritative ACL")) {
                $de.ObjectSecurity = $acl
                $de.CommitChanges()
                Write-Ok "$templateName ACL updated"
            }
        }

        if ($ShowFinalAcl) {
            Write-Host ""
            Write-Host "       Final ACL view:" -ForegroundColor DarkCyan
            Get-AclSummary -Acl $acl |
            Where-Object { $_.Right -ne 'Other' } |
            Select-Object Principal, Right, Access |
            Sort-Object Principal, Right |
            Format-Table -AutoSize
            Write-Host ""
        }
    }
    catch {
        Write-Fail "$templateName -> $($_.Exception.Message)"
    }
}

Write-Info "Authoritative template ACL cleanup complete"

if ($backupFile) {
    Write-Info "Rollback backup available at: $backupFile"
    Write-Info "To restore, run:"
    Write-Host "    .\Set-HardenedTemplateAclAuthoritative.ps1 -RestoreFromBackup `"$backupFile`"" -ForegroundColor Yellow
}
