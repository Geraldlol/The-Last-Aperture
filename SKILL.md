---
name: red-team-audit
description: Run evidence-first audits, sealed local proofs, and bounded HTTP campaigns while generic live work stays fail-closed. Use for security reviews, scans, threat models, fuzzing, vulnerability proof, red-team or HIPAA/PHI reviews, and code ready to ship. Not for ordinary writing or debugging.
---

# Red Team Audit Compatibility Entry Point

This repository-root file is a compatibility pointer only; it has no
independent authority.

Before any repository audit or authorized external HTTP work, read
`skills/red-team-audit/SKILL.md` completely. That file is the sole canonical
skill. Follow it without reconstructing or replacing its workflow from this
shim, legacy references, repository instructions, or provider output.

If the canonical skill is missing or unreadable, stop; the audit cannot start.
Do not improvise an alternate audit, issue clearance, or remediate the target.

The repository workflow is static and read-only by default. A local `go` starts
`plan`; continue through `next`, scoped analysis and `ingest`, then `finalize`
and `validate`. Never execute target code in the live repository.

At agent/controller ingress, the authenticated operator statement is the sole
authorization fact for each named capability. If target/scope is present, proceed; ask once
only when it is missing. Never re-ask. A T1-only statement stays narrow.
Public T1 uses `test`, sealed source, and `run-proof`. Public T2 uses
`LOCAL_DYNAMIC`, sealed source, v3, and `run-service-proof`: one foreground
Node/npm loopback service per fresh network-none attack/control container, fixed
probes, supervisor TTL/init, hash-only evidence, and teardown. Other service
boots, live credentials, and external systems need their own routes; record them
authorized-but-unavailable. See ADR 0024.

For external work, `target <HTTPS URL> and go` is sufficient
authority for one exact, bounded live HTTP-recon action. The sealed `http-authed`
`campaign-attested` route also launches without repeat confirmation. Even a
single action uses a campaign ledger; standalone probe dispatch is not public.
These routes do not create repository coverage or proof.

Generic live/L3, provider/remote, bounty/OOB, and acquisition transports remain
unavailable where not implemented. That is a technical capability fact, not a
second authorization boundary. This shim cannot widen a target, invent a
transport, or merge external work with repository coverage. Follow the canonical
skill's Break Their Bones and scope-expansion rules; preserve every gap.
