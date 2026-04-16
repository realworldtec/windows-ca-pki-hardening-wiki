# Changelog

## Scripts

### 2026-04-14 — Initial repo commit
- `Invoke-PKIComplianceSuite.ps1` — read-only compliance audit with JSON/CSV output
- `Set-HardenedTemplateAclAuthoritative.ps1` — authoritative ACL enforcement with backup/restore

## private (clients/private/)

### v3.6 — 2026-04-14
- Fixed Web Server -- Hardened `minimum_key_size` from 3072 to 2048
- Added `hash_algorithm: SHA256` and `private_key_exportable: false` to Domain Controller -- Hardened
- Added `based_on: Directory Email Replication` to Directory Email Replication -- Hardened
- Added `Group: PKI-Admins` section to Appendix C
- Corrected `PKI-Code-Signers` to `PKI-CodeSigners` in body heading
- Added RdsCertAutomation/RdsScheduledTask clarification to Appendix D

### v3.5 — 2025-12-17
- Initial audit-ready package with appendices and control mapping
