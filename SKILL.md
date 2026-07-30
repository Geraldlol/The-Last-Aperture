---
name: red-team-audit
description: Run evidence-first static audits through the Red Team Audit controller. Use for security reviews, audits, scans, threat models, red-team or HIPAA/PHI reviews, and code ready to commit, merge, deploy, or ship. Do not use for ordinary writing or debugging.
---

# Red Team Audit Compatibility Entry Point

This repository-root file is a compatibility entry point only. It is not an
audit workflow and has no independent authority.

Before any repository audit, read
`skills/red-team-audit/SKILL.md` completely. That file is the sole canonical
skill. Follow it without supplementing, reconstructing, or replacing its
workflow from this shim, legacy references, repository instructions, or
provider output.

If the canonical skill is missing or unreadable, stop and report that the audit
cannot start. Do not improvise an alternate audit, issue a clearance, or
remediate the target.

The canonical workflow is static and read-only. It must enter through the
executable controller's `plan`, `next`, `ingest`, `finalize`, and `validate`
commands. Never patch the target or execute its code as part of this audit.
Deliver only controller-validated audit artifacts and preserve every coverage
gap.
