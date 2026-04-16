# Release and Change Control

PKI configuration is security-critical. Certificate template changes, enrollment
scope changes, and CA configuration changes require documented review prior to
implementation.

---

## Versioning scheme

Two tag schemes are used.

### Baseline tags

One-time tags marking the initial controlled deployment. Format:

```
v{MAJOR}-baseline
```

Example: `v3-baseline`

### Release tags

All releases after the initial baseline follow semantic versioning:

```
v{MAJOR}.{MINOR}.{PATCH}
```

| Increment | When to use |
|---|---|
| **MAJOR** | Breaking change in template configuration, key size, EKU set, or enrollment scope that requires reviewer awareness before deploying updated certificates |
| **MINOR** | New template added, materially improved compliance coverage, new ACL enforcement rule. Backward compatible. |
| **PATCH** | Documentation correction, script bug fix, non-structural improvement. No configuration change. |

---

## Pre-release checklist

### Scripts
- [ ] All changes committed to working branch
- [ ] No untracked changes remain
- [ ] Tested against a non-production CA or test environment

### Templates
- [ ] Template configuration changes documented in CHANGELOG
- [ ] `Invoke-PKIComplianceSuite.ps1` passes with no FAIL results after change
- [ ] ACL policy in `Set-HardenedTemplateAclAuthoritative.ps1` updated if enrollment scope changed
- [ ] Supersedes list updated if new template replaces an existing one

### Documentation
- [ ] CHANGELOG updated with release entry
- [ ] Wiki pages updated if template or script behavior changed
- [ ] Audit package document updated if configuration artifacts changed

---

## Release steps

1. Run `Invoke-PKIComplianceSuite.ps1 -AllTemplates` and confirm no FAIL results
2. Run `Set-HardenedTemplateAclAuthoritative.ps1` (dry run) and review output
3. Update CHANGELOG with release entry
4. Commit all changes
5. Create annotated git tag:
   ```powershell
   git tag -a v3.6.0 -m "v3.6.0: description of changes"
   git push origin --tags
   ```
6. Use the tagged release for any production CA operations

---

## Production run rule

Production CA operations — template deployment, ACL enforcement, compliance auditing
for formal evidence — must reference a tagged release. Record the git tag and commit
hash in the run log and review documentation.

---

## Change control governance

- Template changes require peer review before implementation
- ACL changes use `-ShowFinalAcl` dry run output as the review artifact
- Backup files from `-Enforce` runs are retained as rollback evidence
- Cryptographic algorithm changes require reassessment against the triggers
  defined in [Cryptographic Design Decisions](Cryptographic-Design-Decisions.md)

---

## Scheduled review triggers

Reassessment of this baseline is triggered by any of the following:

- Updated NIST guidance impacting RSA or SHA-256
- New regulatory or compliance requirements
- Material changes to the enterprise threat landscape
- Introduction of services requiring ECC
- Major OS or Active Directory functional level changes
- Certificate validity or renewal period changes required by policy
