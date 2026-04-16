# Auditor Walkthrough

Use this page to guide an audit walkthrough when the PKI architects are not present.
The numbered sections correspond to the typical audit evidence request sequence.

---

## 1. Purpose and scope

**Statement:** Internal PKI supports authentication and encryption for enterprise
systems. External services use commercial/public CAs.

**Evidence to show:**
- This README and the Overview wiki page
- The Executive Summary in the audit package document

**Key point:** The CA does not issue certificates to external-facing services.
Trust scope is explicitly bounded.

---

## 2. Design intent

**Statement:** The design enforces modern cryptography, least-privilege enrollment,
and automated certificate lifecycle management while preserving compatibility.

**Evidence to show:**
- [Cryptographic Design Decisions](Cryptographic-Design-Decisions.md) — algorithm
  rationale with explicit justification for each key size decision
- [Overview](Overview.md) — enrollment model and template separation philosophy

**Key point:** RSA 2048 vs 3072 decisions are documented with rationale, not
arbitrary. The 3072 selections exceed NIST baseline; the 2048 selections are
appropriate for their use cases.

---

## 3. Template separation

**Statement:** Templates are separated by purpose to prevent certificate misuse
and simplify audit validation.

**Evidence to show:**
- [Template Reference](Template-Reference.md) — nine templates, each with a
  single EKU set and defined enrollment scope
- The `supersedes:` field in each template spec — hardened templates replace
  their weaker base counterparts, eliminating certificate ambiguity

**Key point:** No template grants enrollment to Authenticated Users or Domain Users.
Each template covers exactly one function.

---

## 4. Cryptographic standards

**Statement:** RSA 3072/SHA-256 for critical identity and management channels;
RSA 2048/SHA-256 for internal web services; private keys non-exportable by default.

**Evidence to show:**
- [Template Reference](Template-Reference.md) — key size per template
- [Cryptographic Design Decisions](Cryptographic-Design-Decisions.md)
- Compliance script output: `TemplateCompliance_{timestamp}.csv` — PASS on
  `MinimalKeySize` for all templates

**Key point:** The one exportable exception (Web Server -- Appliance) is intentional,
documented with rationale, and controlled via group membership.

---

## 5. Enrollment controls

**Statement:** Enrollment and autoenrollment are role-scoped and reviewed. No broad
user enrollment is granted.

**Evidence to show:**
- [AD Security Groups](AD-Security-Groups.md) — three groups, explicit membership
- Compliance script output: `PKIRoleAccessReport_{timestamp}.csv` — enrollment
  principals mapped to roles
- `Set-HardenedTemplateAclAuthoritative.ps1` output in `-ShowFinalAcl` mode

**Key point:** PKI-Admins holds Read only — the governance group cannot enroll.
Enrollment rights are on purpose-specific groups only.

---

## 6. Compliance validation

**Statement:** Template configuration is validated programmatically against the
hardened baseline. Drift is detectable.

**Evidence to show:**
- Run `Invoke-PKIComplianceSuite.ps1` live during the walkthrough if the
  environment is available, or show pre-run output artifacts:
  - `TemplateCompliance_{timestamp}.json` — full details
  - `TemplateCompliance_{timestamp}.csv` — summary
  - `CARegistrationPermissions_{timestamp}.csv`
  - `LiveCAPermissions_{timestamp}.csv`

**Key point:** PASS result on all nine templates is the audit-ready baseline state.
WARN on ACL or CSP means review required but not blocking. FAIL is a finding.

---

## 7. Risk residual and mitigations

**Statement:** Residual risk is low and mitigated by short lifetimes, automated
renewal, revocation distribution, and defined reassessment triggers.

**Evidence to show:**
- Template validity periods: 1 year for identity-critical, 2 years for web services
- 6-week renewal windows on all templates
- Revocation information included flag on all templates
- [Cryptographic Design Decisions](Cryptographic-Design-Decisions.md) —
  reassessment triggers section

**Key point:** Short lifetimes limit the window of exposure from a compromised
certificate. Automated renewal (autoenrollment + scheduled task) prevents operational
lapses.

---

## 8. Evidence index

| Evidence item | Location |
|---|---|
| Template configuration screenshots | Audit package document, Appendix B |
| AD security group screenshots | Audit package document, Appendix C |
| Group policy scheduled task configuration | Audit package document, Appendix D |
| Applied certificate sampling | Audit package document, Appendix E |
| Compliance script output (JSON) | `PKICompliance/TemplateCompliance_{timestamp}.json` |
| Compliance script output (CSV) | `PKICompliance/TemplateCompliance_{timestamp}.csv` |
| CA registration permissions | `PKICompliance/CARegistrationPermissions_{timestamp}.csv` |
| Live CA permissions | `PKICompliance/LiveCAPermissions_{timestamp}.csv` |
| Role access report | `PKICompliance/PKIRoleAccessReport_{timestamp}.csv` |
| ACL backup (pre-enforcement) | `TemplateAclBackup/[domain]_TemplateAclBackup_{timestamp}.json` |

---

## Common auditor questions

**Q: Why RSA instead of ECC?**
A: Broad enterprise compatibility. ECC is on the reassessment roadmap when
Active Directory functional level and endpoint support align.

**Q: Who approved the cryptographic selections?**
A: See the RACI in [Control Framework Alignment](Control-Framework-Alignment.md).
Security is accountable; Infrastructure is responsible.

**Q: What happens when a template is compromised?**
A: Revoke via the CA console. The ACL enforcement script can remove Enroll rights
immediately. Short certificate lifetimes (1 year) bound the forward exposure window.

**Q: How do you know the templates haven't drifted from this documentation?**
A: Run `Invoke-PKIComplianceSuite.ps1 -AllTemplates` live. PASS on all nine
templates confirms configuration matches the documented baseline.

**Q: Who can modify template ACLs?**
A: Only principals with Write access to the template object in AD, which requires
Domain Admin or Enterprise Admin rights, or delegation to PKI-Admins. The ACL
enforcement script is the authoritative mechanism for maintaining the hardened state.

---

## Downloads

All audit evidence materials are available in the public companion repository.

| File | Description | Download |
|---|---|---|
| `CertTemplateFullAuditPackage-web.pdf` | Full audit package — screenshots, configuration evidence, appendices | [Download](https://github.com/realworldtec/windows-ca-pki-hardening-wiki/blob/main/docs/CertTemplateFullAuditPackage-web.pdf) |
| `Invoke-PKIComplianceSuite.ps1` | Compliance validation script — run live during audit walkthrough | [Download](https://github.com/realworldtec/windows-ca-pki-hardening-wiki/blob/main/scripts/Invoke-PKIComplianceSuite.ps1) |
| `Set-HardenedTemplateAclAuthoritative.ps1` | ACL enforcement script — dry-run output used as review artifact | [Download](https://github.com/realworldtec/windows-ca-pki-hardening-wiki/blob/main/scripts/Set-HardenedTemplateAclAuthoritative.ps1) |
