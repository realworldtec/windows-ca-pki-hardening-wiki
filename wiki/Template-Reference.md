# Template Reference

All templates use:
- **Provider category:** Key Storage Provider (KSP/CNG)
- **Provider:** Microsoft Software Key Storage Provider
- **Hash algorithm:** SHA256
- **Schema version:** 4
- **Renewal period:** 6 weeks
- **CA/Windows Server compatibility:** Windows Server 2016

---

## Computer -- Hardened

**Purpose:** Primary machine identity for domain-joined workstations and member servers.
Supports mutual authentication, TLS, and machine-level trust.

**Based on:** Computer

| Field | Value |
|---|---|
| Key size | RSA 3072 |
| Private key exportable | No |
| Validity | 1 year |
| Subject name source | Active Directory |
| SAN | DNS |
| EKUs | Client Authentication, Server Authentication |
| Key usage | Digital Signature, Key Encipherment |
| Publish to AD | Yes |
| Enrollment | Domain Computers (Enroll, AutoEnroll) |
| Supersedes | Computer |

---

## Web Server -- Hardened

**Purpose:** TLS certificates for internal web services. Secures IIS, WinRM HTTPS
listeners, and application-layer HTTPS endpoints. SAN enforcement prevents CN-only misuse.

**Based on:** Web Server

| Field | Value |
|---|---|
| Key size | RSA 2048 |
| Private key exportable | No |
| Validity | 2 years |
| Subject name source | Request |
| SAN | DNS, IP |
| EKUs | Server Authentication |
| Key usage | Digital Signature, Key Encipherment |
| Publish to AD | No |
| Enrollment | PKI-Admins (Enroll) |
| Supersedes | Web Server, Web Server - 2 Years |

---

## Domain Controller -- Hardened

**Purpose:** Primary machine identity for Active Directory Domain Controllers.
Supports secure DC-to-DC communications, LDAPS, SYSVOL replication, and general
DC service authentication.

**Based on:** Domain Controller

| Field | Value |
|---|---|
| Key size | RSA 3072 |
| Private key exportable | No |
| Validity | 1 year |
| Subject name source | Active Directory |
| SAN | DNS |
| EKUs | Server Authentication, Client Authentication |
| Key usage | Digital Signature, Key Encipherment |
| Publish to AD | Yes |
| Enrollment | Domain Controllers, Enterprise Domain Controllers (Enroll) |
| Supersedes | Domain Controller |

---

## Domain Controller Authentication -- Hardened

**Purpose:** DC identity enabling LDAPS, smart card logon support, and DC service
authentication. Requires SAN=DNS for modern LDAPS and DC identity validation.

**Based on:** Domain Controller Authentication

| Field | Value |
|---|---|
| Key size | RSA 3072 |
| Private key exportable | No |
| Validity | 1 year |
| Subject name source | Active Directory |
| SAN | DNS |
| EKUs | Client Authentication, Server Authentication, Smart Card Logon |
| Key usage | Digital Signature, Key Encipherment |
| Publish to AD | Yes |
| Enrollment | Domain Controllers, Enterprise Domain Controllers (Enroll, AutoEnroll) |
| Supersedes | Domain Controller Authentication |

---

## Kerberos Authentication -- Hardened

**Purpose:** KDC certificates for Kerberos Key Distribution Centers. Supports
secure Kerberos authentication and PKINIT ticket issuance. Must coexist with
Domain Controller Authentication.

**Based on:** Kerberos Authentication

| Field | Value |
|---|---|
| Key size | RSA 3072 |
| Private key exportable | No |
| Validity | 1 year |
| Subject name source | Active Directory |
| EKUs | KDC Authentication, Server Authentication, Client Authentication |
| Key usage | Digital Signature, Key Encipherment |
| Publish to AD | Yes |
| Enrollment | Domain Controllers (Enroll, AutoEnroll) |
| Supersedes | Kerberos Authentication |

---

## RDP-WinRM -- Hardened

**Purpose:** Certificates for Remote Desktop and WinRM HTTPS listeners. Prevents
self-signed certificates on management endpoints. Enforces TLS for administrative
access channels.

**Based on:** Web Server

| Field | Value |
|---|---|
| Key size | RSA 3072 |
| Private key exportable | No |
| Validity | 1 year |
| Subject name source | Request |
| SAN | DNS, IP |
| EKUs | Server Authentication |
| Key usage | Digital Signature, Key Encipherment |
| Publish to AD | No |
| Enrollment | Domain Computers (Enroll, no AutoEnroll) |
| Supersedes | Web Server |

---

## Web Server -- Appliance

**Purpose:** TLS certificates for non-domain-joined infrastructure appliances
(ESXi, iDRAC, network switches, load balancers, storage platforms). Allows private
key export for vendor-required PEM/KEY pair deployments. Exportability is intentional
and controlled via group membership.

**Based on:** Web Server

| Field | Value |
|---|---|
| Key size | RSA 2048 |
| **Private key exportable** | **Yes — intentional, controlled via PKI-ApplianceCerts membership** |
| Validity | 2 years |
| Subject name source | Request |
| SAN | DNS, IP |
| EKUs | Server Authentication |
| Key usage | Digital Signature, Key Encipherment |
| Publish to AD | No |
| Enrollment | PKI-ApplianceCerts (Enroll) |
| Supersedes | Web Server |

---

## Code Signing -- Hardened

**Purpose:** Signing internal scripts and automation tooling. Protects PowerShell,
scheduled tasks, and administrative tooling from unauthorized modification. Enrollment
restricted to approved signing identities.

**Based on:** Code Signing

| Field | Value |
|---|---|
| Key size | RSA 3072 |
| Private key exportable | No |
| Validity | 1 year |
| Subject name source | Request |
| EKUs | Code Signing |
| Key usage | Digital Signature |
| Publish to AD | No |
| Enrollment | PKI-CodeSigners (Enroll) |
| Supersedes | Code Signing |

---

## Directory Email Replication -- Hardened

**Purpose:** AD directory service email-style replication certificates. EKU scoping
to a single OID prevents certificate reuse for authentication or TLS. Required for
secure replication behavior on modern domain controllers.

**Based on:** Directory Email Replication

| Field | Value |
|---|---|
| Key size | RSA 3072 |
| Private key exportable | No |
| Validity | 1 year |
| Subject name source | Active Directory |
| SAN | DNS |
| EKUs | Directory Service Email Replication (1.3.6.1.4.1.311.21.19) |
| Key usage | Digital Signature, Key Encipherment |
| Publish to AD | Yes |
| Enrollment | Domain Controllers (Enroll, AutoEnroll) |
| Supersedes | Directory Email Replication |
