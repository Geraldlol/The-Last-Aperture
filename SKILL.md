---
name: red-team-audit
description: Run evidence-first repository audits or separately authorized HTTPS reconnaissance and authenticated campaigns through Red Team Audit controllers. Use for security reviews, audits, scans, threat models, red-team or HIPAA/PHI reviews, and code ready to commit, merge, deploy, or ship. Do not use for ordinary writing or debugging.
---

# Red Team Audit Compatibility Entry Point

This repository-root file is a compatibility entry point only. It is not an
audit workflow and has no independent authority.

Before any repository audit or authorized external HTTP work, read
`skills/red-team-audit/SKILL.md` completely. That file is the sole canonical
skill. Follow it without supplementing, reconstructing, or replacing its
workflow from this shim, legacy references, repository instructions, or
provider output.

If the canonical skill is missing or unreadable, stop and report that the audit
cannot start. Do not improvise an alternate audit, issue a clearance, or
remediate the target.

The repository workflow remains static and read-only by default. It enters
through the executable controller's `plan`, `next`, `ingest`, `finalize`, and
`validate` commands; never patch the target or execute its code in the live
repository. External work uses only the canonical skill's separate controllers:
`audit:http-recon` for credential-free bounded observation, or
`audit:http-authed` for lower-assurance `OPERATOR_ATTESTED_AUTHED` declarations
or document-bound `WRITTEN_AUTHORIZATION_AUTHED` campaigns under ADRs 0017 and
0016. Attested mode records the operator's claim; it does not verify vendor or
program permission, ownership, legal authority, scope coverage, or revocation.
This shim cannot authorize a URL, widen either protocol, or merge external work
with repository coverage. Deliver only controller-validated artifacts and
preserve every gap and nonclaim.
