# AD Security Groups

Three AD security groups control certificate enrollment. All are Global Security
groups. Membership is explicit and governed — no nested group expansion that would
silently grant enrollment rights to unintended principals.

---

## PKI-Admins

**Purpose:** PKI governance. Holds Read access on all hardened certificate templates.
Does not hold Enroll or AutoEnroll rights on any template.

| Field | Value |
|---|---|
| Scope | Global |
| Category | Security |
| Enrollment rights | Read only — no Enroll, no AutoEnroll |
| Approved members | PKI Administrators, Security Operations |
| Prohibited members | Authenticated Users, Domain Users, Domain Computers |

**Risk statement:** Without a dedicated PKI governance group, template ACL
administration could be performed by principals with broader AD rights, undermining
the least-privilege enrollment model enforced across all templates.

**NIST alignment:** IA-5, CM-2, AC-6

**ISO alignment:** A.5.15, A.8.24, A.5.17

---

## PKI-CodeSigners

**Purpose:** Restricts enrollment of Code Signing certificates to explicitly
authorized personnel. Prevents uncontrolled issuance of signing certificates that
could bypass application trust controls or undermine software integrity enforcement.

| Field | Value |
|---|---|
| Scope | Global |
| Category | Security |
| Supported templates | Code Signing -- Hardened |
| Enrollment rights | Read, Enroll (no AutoEnroll) |
| Membership type | Explicit — PKI administrators and designated signing identities |
| Prohibited members | Authenticated Users, Domain Users |

**Risk statement:** Without a dedicated Code Signing group, unauthorized users could
obtain signing certificates and introduce malicious or untrusted software into the
enterprise environment.

**NIST alignment:** IA-5, CM-5, CM-14

**ISO alignment:** A.9.2, A.12.5, A.14.2

---

## PKI-ApplianceCerts

**Purpose:** Controls issuance of certificates to non-domain-joined infrastructure
appliances. Supports controlled CSR-based enrollment workflows for hypervisors,
management controllers, network switches, load balancers, and storage platforms.

| Field | Value |
|---|---|
| Scope | Global |
| Category | Security |
| Supported templates | Web Server -- Appliance |
| Enrollment model | CSR-based, no autoenrollment, key generation external |
| Enrollment rights | Read, Enroll (no AutoEnroll) |
| Membership type | Explicit — PKI Administrators only |
| Prohibited members | Authenticated Users, Domain Users |

**Note on key exportability:** Web Server -- Appliance permits private key export.
This is intentional — many appliances require PEM/KEY pairs and have no native
domain-joined enrollment capability. The risk is mitigated by restricting enrollment
to this group and requiring manual CSR validation before issuance.

**Risk statement:** Without a dedicated appliance issuance group, certificates could
be issued to infrastructure without proper validation, increasing exposure to
impersonation or man-in-the-middle attacks against management interfaces.

**NIST alignment:** IA-7, IA-12, SC-12

**ISO alignment:** A.9.4, A.10.1, A.13.2

---

## Group membership governance

- Membership changes require documented approval
- Quarterly review of all three groups is recommended
- Removal from PKI-CodeSigners or PKI-ApplianceCerts does not revoke previously
  issued certificates — revoke explicitly via the CA if access should be terminated
