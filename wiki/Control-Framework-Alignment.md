# Control Framework Alignment

## NIST SP 800-53 Rev. 5

| Control | Description | How this baseline satisfies it |
|---|---|---|
| **IA-7** | Cryptographic module authentication | KSP/CNG enforced on all templates; RSA and SHA-256 are NIST-approved mechanisms |
| **IA-5** | Authenticator management | Certificate lifetimes defined; non-exportable keys; renewal windows enforced |
| **SC-12** | Cryptographic key establishment and management | Enterprise PKI provides key establishment; private keys non-exportable by default |
| **SC-13** | Cryptographic protection | Approved algorithms (RSA, SHA-256) documented with rationale |
| **CM-2** | Baseline configuration | Hardened templates documented with all configuration parameters |
| **CM-6** | Configuration settings | Template ACLs enforced programmatically via `Set-HardenedTemplateAclAuthoritative.ps1` |
| **AU-3** | Content of audit records | CA database records all issuance; revocation information included in all certificates |
| **AU-12** | Audit record generation | CA logs all enrollment and revocation events |
| **AC-6** | Least privilege | Enrollment scoped to specific groups and computer accounts; PKI-Admins holds read-only access |
| **CM-5** | Access restrictions for change | Code signing enrollment restricted to PKI-CodeSigners; template changes require documented review |
| **CM-14** | Signed components | Code Signing -- Hardened template enables signing of internal scripts and automation |
| **IA-12** | Identity proofing | Appliance certificate enrollment requires manual CSR validation |

---

## ISO/IEC 27001:2022

| Control | Description | How this baseline satisfies it |
|---|---|---|
| **A.5.15** | Access control | Least-privilege enrollment enforced via AD security groups |
| **A.5.17** | Authentication information | Certificate-based authentication with controlled issuance and lifecycle |
| **A.8.24** | Use of cryptography | Approved algorithms selected and documented with explicit rationale |
| **A.8.28** | Secure authentication | Kerberos PKINIT, LDAPS, and TLS management channels all certificate-protected |
| **A.8.32** | Change management | Template versioning, peer review requirement, and approval workflow documented |
| **A.9.2** | User registration and de-registration | Enrollment group membership governed; removal does not auto-revoke (explicit revocation required) |
| **A.9.4** | System and application access control | Appliance enrollment requires explicit group membership and CSR validation |
| **A.10.1** | Policy on the use of cryptographic controls | Algorithm selection policy documented; reassessment triggers defined |
| **A.12.5** | Installation of software on operational systems | Code signing restricts unauthorized software execution |
| **A.13.2** | Information transfer | Appliance certificate issuance workflow documented and group-controlled |
| **A.14.2** | Security in development and support processes | Code Signing template protects internal development tooling |

---

## RACI

| Activity | Security | Infrastructure | Operations | Audit |
|---|---|---|---|---|
| PKI Architecture & Design | A | R | C | I |
| Certificate Template Management | A | R | C | I |
| CA Operations & Monitoring | A | R | R | I |
| Cryptographic Policy Decisions | A | C | I | I |
| Audit Support & Evidence | R | C | I | I |

R = Responsible, A = Accountable, C = Consulted, I = Informed
