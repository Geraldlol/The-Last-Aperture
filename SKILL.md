---
name: red-team-audit
description: Run evidence-first repository audits and controller-bounded HTTPS reconnaissance or fixed authenticated campaigns while keeping generic live execution fail-closed. Use for security reviews, audits, scans, threat models, fuzzing, vulnerability proof, red-team or HIPAA/PHI reviews, and code ready to commit, merge, deploy, or ship. Do not use for ordinary writing or debugging.
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

The repository workflow remains static and read-only by default. For a local
repository, an operator's `go` directive starts a static `plan`; the agent must
continue through `next`, scoped analysis and `ingest`, then `finalize` and
`validate` rather than stopping at `PLANNED`. Never patch the target or execute
its code in the live repository.

For external work, the operator phrase `target <HTTPS URL> and go` is sufficient
authority to launch one exact, bounded live HTTP-recon action through the public
controller. The fixed, already-sealed `http-authed` `campaign-attested` route is
also active; invoking it launches that sealed campaign without asking the
operator to repeat confirmation flags. Even a
single action uses a campaign ledger; standalone probe dispatch is not public.
These routes do not create repository coverage or proof.

Generic live/L3 adversarial execution, provider/remote execution, `run-proof`,
bounty/OOB execution, and evidence acquisition remain unavailable. The
canonical skill defines the complete boundary, including target-bound Break
Their Bones semantics and inert scope expansion. This shim cannot widen a
target, activate a disabled protocol, or merge external work with repository
coverage. Deliver only controller-validated artifacts and preserve every gap
and nonclaim.
