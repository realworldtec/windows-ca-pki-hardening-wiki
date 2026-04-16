# Script Reference

Both scripts require Windows PowerShell 5.1, the ActiveDirectory module, and an
elevated session on a domain-joined management host. Do not run from PowerShell 7.

---

## Invoke-PKIComplianceSuite.ps1

Read-only compliance audit. Does not modify templates, CA configuration, or ACLs.

### What it validates

For each template in scope:
- Display name and schema version
- Minimum key size
- EKUs and application policies
- Validity and renewal periods
- CSP/KSP list
- Template ACLs

Additionally performs:
- Enterprise CA AD registration permissions audit
- Live CA service permissions audit (registry-based, via `Invoke-Command` if remote)
- PKI role-based access report

### Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `-CACommonName` | string | auto-detect | CA common name. Required if multiple CAs exist. |
| `-CAHostName` | string | localhost | CA server hostname for live permissions audit. |
| `-OutputPath` | string | `.\PKICompliance` | Directory for JSON and CSV output. |
| `-IncludeAclDetail` | switch | — | Include raw ACL detail in JSON output. |
| `-AllTemplates` | switch | — | Validate all baseline templates, not just CA-issued ones. |

### Output files

| File | Contents |
|---|---|
| `TemplateCompliance_{timestamp}.json` | Full compliance results with raw attributes |
| `TemplateCompliance_{timestamp}.csv` | Summary: template name and PASS/WARN/FAIL |
| `PKIRoleAccessReport_{timestamp}.csv` | Per-template role-based access summary |
| `CARegistrationPermissions_{timestamp}.csv` | Enterprise CA AD object ACL |
| `LiveCAPermissions_{timestamp}.csv` | CA service registry permissions |

### Result codes

| Code | Meaning |
|---|---|
| `PASS` | All checks match the baseline |
| `WARN` | CSP list or ACL deviation — review required but not blocking |
| `FAIL` | Critical deviation — template does not match baseline |

### Examples

```powershell
# Validate templates currently issued by the CA
.\Invoke-PKIComplianceSuite.ps1 -CACommonName '[domain]-Internal-CA' -CAHostName '[ca-hostname]'

# Full baseline including ACL detail in JSON
.\Invoke-PKIComplianceSuite.ps1 -CACommonName '[domain]-Internal-CA' -CAHostName '[ca-hostname]' -AllTemplates -IncludeAclDetail

# Local-only — no remote CA service audit
.\Invoke-PKIComplianceSuite.ps1 -AllTemplates
```

---

## Set-HardenedTemplateAclAuthoritative.ps1

Enforces least-privilege ACLs on all hardened templates. Supports three modes:
review (default), enforce, and restore.

### Modes

| Mode | Command | Effect |
|---|---|---|
| Review | (default, no switches) | Reports what would change. No modifications. |
| Review with projection | `-ShowFinalAcl` | Shows the resulting ACL state for each template. |
| Enforce | `-Enforce` | Creates automatic backup, then applies changes. |
| Restore | `-RestoreFromBackup path` | Restores all template ACLs from a backup file. |

### Parameters

| Parameter | Type | Default | Purpose |
|---|---|---|---|
| `-Enforce` | switch | — | Apply authoritative ACL changes. Auto-backup first. |
| `-ShowFinalAcl` | switch | — | Display projected or resulting ACL after processing. |
| `-BackupPath` | string | `.\TemplateAclBackup` | Directory for automatic backup files. |
| `-RestoreFromBackup` | string | — | Path to backup JSON file to restore from. |

### Backup files

When `-Enforce` is used, a backup is written before any changes:

```
.\TemplateAclBackup\[domain]_TemplateAclBackup_YYYYMMDD_HHmmss.json
```

The backup captures: template name, distinguished name, owner SID, group SID,
DACL protection state, and the full ACE list with all metadata. It is sufficient
for complete ACL restoration.

### Examples

```powershell
# Review — what would change?
.\Set-HardenedTemplateAclAuthoritative.ps1

# Review with projected final state
.\Set-HardenedTemplateAclAuthoritative.ps1 -ShowFinalAcl

# Enforce (backup created automatically)
.\Set-HardenedTemplateAclAuthoritative.ps1 -Enforce

# Enforce and show final ACL
.\Set-HardenedTemplateAclAuthoritative.ps1 -Enforce -ShowFinalAcl

# Restore from backup
.\Set-HardenedTemplateAclAuthoritative.ps1 -RestoreFromBackup '.\TemplateAclBackup\[domain]_TemplateAclBackup_20260327_171822.json'
```

### ACL policy enforced

| Template | Principals | Rights |
|---|---|---|
| Computer -- Hardened | Domain Computers | Read, Enroll, AutoEnroll |
| Computer -- Hardened | PKI-Admins | Read |
| Web Server -- Hardened | PKI-Admins | Read, Enroll |
| Domain Controller -- Hardened | Domain Controllers | Read, Enroll |
| Domain Controller -- Hardened | Enterprise Domain Controllers | Read, Enroll |
| Domain Controller -- Hardened | PKI-Admins | Read |
| Domain Controller Authentication -- Hardened | Domain Controllers | Read, Enroll, AutoEnroll |
| Domain Controller Authentication -- Hardened | Enterprise Domain Controllers | Read, Enroll, AutoEnroll |
| Domain Controller Authentication -- Hardened | PKI-Admins | Read |
| Kerberos Authentication -- Hardened | Domain Controllers | Read, Enroll, AutoEnroll |
| Kerberos Authentication -- Hardened | PKI-Admins | Read |
| RDP-WinRM -- Hardened | Domain Computers | Read, Enroll |
| RDP-WinRM -- Hardened | PKI-Admins | Read |
| Web Server -- Appliance | PKI-ApplianceCerts | Read, Enroll |
| Web Server -- Appliance | PKI-Admins | Read |
| Code Signing -- Hardened | PKI-CodeSigners | Read, Enroll |
| Code Signing -- Hardened | PKI-Admins | Read |
| Directory Email Replication -- Hardened | Domain Controllers | Read, Enroll, AutoEnroll |
| Directory Email Replication -- Hardened | PKI-Admins | Read |

---

## Downloads

The scripts and audit package are available in the public companion repository.

| File | Description | Download |
|---|---|---|
| `Invoke-PKIComplianceSuite.ps1` | Read-only compliance audit script | [Download](https://github.com/realworldtec/windows-ca-pki-hardening-wiki/blob/main/scripts/Invoke-PKIComplianceSuite.ps1) |
| `Set-HardenedTemplateAclAuthoritative.ps1` | ACL enforcement and backup/restore script | [Download](https://github.com/realworldtec/windows-ca-pki-hardening-wiki/blob/main/scripts/Set-HardenedTemplateAclAuthoritative.ps1) |
| `CertTemplateFullAuditPackage-web.pdf` | Full audit evidence package with screenshots and configuration artifacts | [Download](https://github.com/realworldtec/windows-ca-pki-hardening-wiki/blob/main/docs/CertTemplateFullAuditPackage-web.pdf) |

> **License:** Scripts are released under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0).
> Commercial use requires a separate written agreement — contact [realworldtec](https://github.com/realworldtec).
