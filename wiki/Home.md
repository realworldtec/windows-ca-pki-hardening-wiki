# windows-ca-pki-hardening Wiki

Hardened AD CS baseline — templates, ACL enforcement, compliance auditing, and
audit documentation for enterprise Windows PKI deployments.

## Pages

- [Overview](Overview.md) — design intent, scope, and cryptographic rationale
- [Template Reference](Template-Reference.md) — all nine hardened templates with full specifications
- [Script Reference](Script-Reference.md) — usage, parameters, and output artifacts
- [AD Security Groups](AD-Security-Groups.md) — PKI-Admins, PKI-CodeSigners, PKI-ApplianceCerts
- [Cryptographic Design Decisions](Cryptographic-Design-Decisions.md) — algorithm selection rationale
- [Control Framework Alignment](Control-Framework-Alignment.md) — NIST SP 800-53 and ISO/IEC 27001
- [Release and Change Control](Release-and-Change-Control.md) — versioning, tagging, and release process
- [Auditor Walkthrough](Auditor-Walkthrough.md) — guided evidence walkthrough for audit engagements

## Quick orientation

This baseline enforces:

- **KSP/CNG on all templates** — no legacy CAPI CSP
- **RSA 3072 / SHA-256** for domain controllers, Kerberos, WinRM, RDP, and code signing
- **RSA 2048 / SHA-256** for internal web services and appliances
- **Non-exportable private keys** by default; exportability permitted only by exception
- **Least-privilege enrollment** — no Authenticated Users enrollment on any template
- **Template supersession** — all hardened templates replace their weaker base counterparts
