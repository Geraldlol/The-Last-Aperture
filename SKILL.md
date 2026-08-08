---
name: red-team-audit
description: Run evidence-first repository audits or separately authorized bounded HTTPS reconnaissance through Red Team Audit controllers. Use for security reviews, audits, scans, threat models, red-team or HIPAA/PHI reviews, and code ready to commit, merge, deploy, or ship. Do not use for ordinary writing or debugging.
---

# Red Team Audit Compatibility Entry Point

This repository-root file is a compatibility entry point only. It is not an
audit workflow and has no independent authority.

Before any repository audit or authorized external HTTP reconnaissance, read
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
repository. The separate external route is available only through the
canonical skill's `audit:http-recon` protocol, using either an explicit
operator attestation or its higher-assurance signed-artifact mode. This shim
cannot authorize a URL or merge that route with repository coverage. Deliver
only controller-validated artifacts and preserve every gap and nonclaim.
