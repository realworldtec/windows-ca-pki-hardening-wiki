# Cryptographic Design Decisions

This page documents the algorithm selections and the rationale behind them.
Cryptographic choices balance security strength, enterprise interoperability, and
operational stability.

---

## Algorithm selections

| Algorithm | Usage | Rationale |
|---|---|---|
| RSA | All templates | Broad enterprise compatibility with Windows, Linux, network devices, and appliances |
| SHA-256 | All templates | Standards compliance, interoperability, and NIST approval |
| KSP/CNG | All templates | Modern Windows key storage; eliminates legacy CAPI CSP |

---

## Key size decisions

### RSA 3072 — identity-critical and management templates

Used for: Computer, Domain Controller, Domain Controller Authentication, Kerberos
Authentication, RDP-WinRM, Code Signing, Directory Email Replication.

RSA 3072 exceeds the NIST SP 800-57 baseline through 2030 while remaining operationally
practical. The additional key size is warranted for:
- Domain controllers — compromise affects the entire domain trust model
- Kerberos KDC — compromise affects all ticket issuance
- Management channels (WinRM/RDP) — protect privileged administrative access
- Code signing — protect software integrity enforcement

### RSA 2048 — internal web services and appliances

Used for: Web Server -- Hardened, Web Server -- Appliance.

RSA 2048 is appropriate for internal TLS where session security is primarily
provided by ephemeral key exchange (ECDHE/DHE) and symmetric ciphers, not by
the certificate key itself. The TLS handshake uses the certificate key only for
authentication; forward secrecy is provided by the ephemeral session key.

Appliance certificates use RSA 2048 for maximum compatibility with embedded
firmware and vendor-supplied TLS stacks that may not support RSA 3072.

---

## Private key exportability

Non-exportable by default on all templates. The single exception is
Web Server -- Appliance, where export is explicitly permitted because:

- Appliances have no domain-joined enrollment capability
- Vendor deployment workflows require PEM/KEY pairs
- Risk is mitigated by group-controlled enrollment (PKI-ApplianceCerts)
  and manual CSR validation

---

## Cryptographic reassessment triggers

Reassessment of algorithm selections will occur upon any of the following:

- Updated NIST guidance impacting RSA or SHA-256
- New regulatory or compliance requirements
- Material changes to the enterprise threat landscape
- Introduction of services requiring ECC
- Major OS or Active Directory functional level changes

---

## Provider selection — KSP/CNG

All templates specify Key Storage Provider (KSP) as the provider category, with
Microsoft Software Key Storage Provider as the default. This eliminates the legacy
Cryptographic Service Provider (CSP/CAPI) layer, which:

- Does not support keys larger than RSA 2048 on older CSPs
- Lacks the security isolation model of CNG
- Cannot support hardware attestation (TPM) without provider-specific workarounds

The `requests_can_use_any_provider: false` flag prevents requestors from
substituting a different or weaker provider.
