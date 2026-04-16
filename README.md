# windows-ca-pki-hardening

Hardened Active Directory Certificate Services (AD CS) baseline for enterprise
Windows environments — templates, ACL enforcement, compliance auditing, and
audit-ready documentation.

## What this is

A complete, opinionated hardened PKI baseline for internal enterprise CA deployments.
Covers nine certificate templates, two AD security groups, least-privilege ACL
enforcement, and a compliance validation suite that produces audit-ready JSON and CSV
artifacts.

External-facing services use commercial/public CAs. This baseline supports internal
trust: domain authentication, LDAPS, Kerberos PKINIT, WinRM/RDP TLS, code signing,
and appliance certificate issuance.

## Scripts

| Script | Purpose | Mode |
|---|---|---|
| `Invoke-PKIComplianceSuite.ps1` | Validates template configuration, CA permissions, and ACLs against the hardened baseline | Read-only |
| `Set-HardenedTemplateAclAuthoritative.ps1` | Enforces least-privilege ACLs with automatic backup and restore | Read/Write |

## Certificate templates covered

| Template | Key Size | Validity | Autoenroll |
|---|---|---|---|
| Computer -- Hardened | RSA 3072 | 1 year | Domain Computers |
| Web Server -- Hardened | RSA 2048 | 2 years | No |
| Domain Controller -- Hardened | RSA 3072 | 1 year | No |
| Domain Controller Authentication -- Hardened | RSA 3072 | 1 year | Domain Controllers |
| Kerberos Authentication -- Hardened | RSA 3072 | 1 year | Domain Controllers |
| RDP-WinRM -- Hardened | RSA 3072 | 1 year | No |
| Web Server -- Appliance | RSA 2048 | 2 years | No |
| Code Signing -- Hardened | RSA 3072 | 1 year | No |
| Directory Email Replication -- Hardened | RSA 3072 | 1 year | Domain Controllers |

## Quick start

```powershell
# Run from Windows PowerShell 5.1 on a domain-joined management host
# Requires: ActiveDirectory module, elevated session

# Compliance audit — templates currently issued by the CA
.\Invoke-PKIComplianceSuite.ps1 -CACommonName '[domain]-Internal-CA' -CAHostName '[ca-hostname]'

# Full baseline audit
.\Invoke-PKIComplianceSuite.ps1 -CACommonName '[domain]-Internal-CA' -CAHostName '[ca-hostname]' -AllTemplates

# ACL review (dry run, no changes)
.\Set-HardenedTemplateAclAuthoritative.ps1

# ACL enforcement (creates automatic backup first)
.\Set-HardenedTemplateAclAuthoritative.ps1 -Enforce

# Restore from backup
.\Set-HardenedTemplateAclAuthoritative.ps1 -RestoreFromBackup '.\TemplateAclBackup\backup.json'
```

## Requirements

- Windows PowerShell 5.1 (not PowerShell 7)
- `ActiveDirectory` module (RSAT)
- Domain-joined management host
- Run as Administrator
- Enterprise CA registered in AD

## Documentation

Full documentation is in the [wiki](../../wiki):

- [Overview](../../wiki/Overview)
- [Template Reference](../../wiki/Template-Reference)
- [Script Reference](../../wiki/Script-Reference)
- [AD Security Groups](../../wiki/AD-Security-Groups)
- [Cryptographic Design Decisions](../../wiki/Cryptographic-Design-Decisions)
- [Control Framework Alignment](../../wiki/Control-Framework-Alignment)
- [Release and Change Control](../../wiki/Release-and-Change-Control)
- [Auditor Walkthrough](../../wiki/Auditor-Walkthrough)

The full audit package document (`docs/`) contains screenshots, configuration
artifacts, and evidence suitable for formal audit presentation.

## License

[PolyForm Noncommercial License 1.0.0](LICENSE)

Commercial use requires a separate license agreement.
