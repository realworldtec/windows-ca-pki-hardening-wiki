# Overview

## Purpose

This baseline implements a hardened internal AD CS PKI for enterprise Windows
environments. External-facing services use commercial/public CAs. This PKI
supports internal trust and secure management channels.

Core design goals:

- Repeatable, documented certificate template configuration
- Least-privilege enrollment scoped to specific AD security groups or computer accounts
- Modern cryptographic standards throughout
- Automated certificate lifecycle management via autoenrollment and scheduled tasks
- Audit-ready evidence and governance documentation

## Scope

**In scope:** Internal certificate issuance for domain-joined systems, domain
controllers, Kerberos KDC authentication, WinRM/RDP management channels, internal
web services, non-domain appliances (ESXi, iDRAC, network switches), and code signing
for internal automation.

**Out of scope:** External-facing TLS, S/MIME, smart card user certificates,
cross-domain trust certificates.

## Template separation philosophy

Templates are separated by purpose rather than consolidated. Each template covers
one authentication or encryption function with the minimum required EKUs. This:

- prevents certificate reuse across unintended services
- simplifies audit validation
- limits the blast radius of a compromised private key
- makes enrollment scope unambiguous

## Enrollment model

All enrollment is role-scoped. No template grants enrollment to
`Authenticated Users` or `Domain Users`. Enrollment rights are assigned to:

- **Domain Computers** — machine identity and RDP/WinRM templates
- **Domain Controllers / Enterprise Domain Controllers** — DC identity, Kerberos, directory replication
- **PKI-Admins** — governance read access only, no enroll
- **PKI-CodeSigners** — Code Signing enroll
- **PKI-ApplianceCerts** — Web Server Appliance enroll

## CA configuration

Templates are added to the CA's issuance list using `certsrv.msc`. After adding
hardened templates, the corresponding base templates are removed to eliminate
certificate ambiguity. The hardened `* -- Hardened` templates supersede their
base counterparts in all cases.

See the `docs/` folder for the full audit package with screenshots and configuration
evidence captured during implementation.
