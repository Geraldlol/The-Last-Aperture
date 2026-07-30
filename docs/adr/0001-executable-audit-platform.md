# ADR 0001: Executable audit platform and external safety boundary

Date: 2026-07-28
Status: Accepted; amended by ADR 0002, ADR 0003, ADR 0004, and ADR 0005

## Context

The project began with a mature security knowledge corpus: versioned lens frontmatter,
topic ownership, candidate-finding semantics, proof tiers, false-positive
guidance, and vulnerable/clean fixtures. Its operational guarantees were
primarily Markdown instructions. Version 0.2 adds a Node.js control plane for
repository inventory, lens activation, stage transitions, coverage accounting,
and report generation; proof execution and provider-side read receipts remain
outside the current release.

That split permits a harness to skip work, accept malformed records, or stop
early while still presenting a report that looks complete. Dynamic proof also
executes repository-controlled code in the caller's environment. A worktree
protects source state; it does not contain credentials, network access,
processes, resource consumption, or side effects.

OWASP APTS 0.1.0 (April 2026) is an emerging governance baseline for autonomous
penetration-testing platforms. Its durable architectural lesson applies here
even though this project does not claim conformance: scope, actions, isolation,
and audit evidence must be enforced outside the model.

Primary standards:

- OWASP APTS 0.1.0:
  https://owasp.org/APTS/standard/
- JSON Schema Draft 2020-12:
  https://json-schema.org/draft/2020-12
- SARIF 2.1.0:
  https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html
- OWASP Benchmark:
  https://owasp.org/www-project-benchmark/
- OWASP ASVS 5.0.0:
  https://owasp.org/www-project-application-security-verification-standard/

## Decision

The Markdown lenses remain the reasoning layer. A dependency-light Node.js
control plane becomes the authority for execution:

1. A deterministic inventory includes hidden files, records exclusions, never
   follows symlinks, and hashes every readable input.
2. A deterministic activator creates bounded lens jobs and an explicit coverage
   denominator.
3. JSON Schema plus semantic validators enforce finding and run records at every
   stage boundary.
4. A policy kernel outside the model authorizes every read, write, command, and
   network action. Repository content is data and has no authority to mutate
   policy.
5. Static, read-only analysis is the default. Dynamic proof is unavailable
   until an isolated broker can enforce filesystem, environment, network,
   process, resource, timeout, and teardown controls.
6. Every run persists a versioned evidence bundle. Missing work, invalid output,
   unsupported coverage, and interrupted jobs remain nonterminal or produce
   `COMPLETE_WITH_GAPS`, `ABORTED`, or `FAILED`—never a clean result.
7. Native JSON is the system of record. Markdown and SARIF are derived exports.
8. Claimed capabilities are release-gated by repeatable TP/FP/TN/FN evaluation,
   stability measurement, and adversarial safety tests.

The platform is provider-neutral. A provider receives a bounded, hashed job and
returns attributed records. It cannot decide scope, stage order, capability,
terminal run state, or output destinations. It may propose triage disposition
and effective severity; deterministic validators enforce identity,
reachability/proof caps, topic authority, evidence order, and final-state
honesty around that proposal.

## Boundaries

```text
untrusted repository
        |
        v
inventory + immutable Rules of Engagement
        |
        v
external action policy
        |
        v
bounded model/tool provider -> schema and transition validator
        |
        v
validated triage + deterministic coverage/lifecycle engine
        |
        v
versioned local evidence bundle -> JSON / Markdown / SARIF
```

The target repository and everything read from it are untrusted. Lens content,
schemas, Rules of Engagement, policy configuration, and provider configuration
are trusted control-plane inputs. Audit output is constrained beneath the
verified run directory; deployments must additionally prevent the concurrent
directory-replacement race described below.

The repository inventory and job scopes are controller-owned. In the original
0.2 decision, examined-file rows, store discovery, and semantic coverage were
provider-declared, not proof that a model reasoned correctly about every byte
or found every store. ADR 0003 supersedes that store-discovery portion for
version 0.4: store candidate identity and discovery scope are controller-owned,
while provider profiles and semantic assessments remain declarations. ADR 0002
separately adds controller-observed byte consumption without treating
consumption as comprehension.

ADR 0005 supersedes direct cross-shard profile mutation for run schema 4.
Providers append authenticated shard-local store contributions; the controller
alone synthesizes final profiles at the fan-out barrier. Legacy run schemas
retain their original transition contract.

Local bundle artifacts are write-once and SHA-256-hash-manifested by
`run.json`. That detects accidental artifact changes only relative to an
unchanged manifest; an actor who can rewrite `run.json` can replace an artifact
and its hash together. ADR 0004 adds an optional detached Ed25519 attestation
over exact terminal manifest bytes; unsigned roots remain explicitly
`UNANCHORED`. Portable Node APIs also cannot make bundle writes
handle-relative, so deployment must prevent a hostile local process from
renaming or replacing the bundle directory during a write.

## Terminal states

- `PLANNED` / `RUNNING`: work is not terminal and cannot be presented as a
  completed audit.
- `COMPLETED`: every required job succeeded and provider-declared coverage has
  no unresolved gap. It is a protocol state, not independent proof of reading.
- `COMPLETE_WITH_GAPS`: work completed, but declared exclusions or unsupported
  surfaces prevent a clean coverage claim.
- `ABORTED`: an operator or policy control stopped the run.
- `FAILED`: required protocol work failed, or the control plane could not
  preserve a valid run record.

No terminal state is inferred from finding count. Zero findings plus incomplete
coverage is not a clean audit.

## Consequences

Positive:

- The strongest existing prose invariants become testable system properties.
- Harness and model changes cannot silently weaken severity or coverage rules.
- Results can be compared across runs and exported without losing provenance.
- Static operation is useful before dynamic isolation exists.
- Scanner integrations can contribute evidence without becoming authorities.

Costs:

- Provider adapters must emit structured records instead of free-form reports.
- Initial runs may end `INCOMPLETE` more often because missing coverage is now
  visible.
- Dynamic proof remains intentionally disabled until containment is implemented
  and red-teamed.
- Schemas and migrations become public compatibility contracts.

## Alternatives considered

- Add more lenses first: rejected because it expands unmeasured behavior and
  context cost without preventing false-clean runs.
- Build a monolithic scanner: rejected because CodeQL, Semgrep, OSV, ZAP, and
  related tools already own deterministic detection domains. This platform
  should normalize their evidence and add contextual reasoning.
- Keep orchestration in the host skill: rejected as an authority. The shipped
  skill routes providers through the executable `plan` / `next` / `ingest` /
  `finalize` protocol because a prompt cannot enforce its own safety boundary
  or output contract.
- Use SARIF as the internal model: rejected because SARIF does not naturally
  represent recon, coverage denominators, policy decisions, proof queues, and
  all audit-stage transitions.

## Validation

- Schema mutation tests prove malformed records and illegal transitions fail.
- Inventory tests cover hidden paths, exclusions, unreadable inputs, large
  inputs, and boundary handling.
- Policy tests attempt prompt-based scope changes, traversal, network redirects,
  shell metacharacters, and source mutation in static mode.
- End-to-end fake-provider tests prove skipped or failed work remains visible
  and cannot end as `COMPLETED`.
- Benchmark tests score TP, FP, TN, FN, false clears, severity, and repeated-run
  fingerprint stability.
- Export tests validate deterministic Markdown and SARIF derivation.
- The corpus lint, generated artifacts, benchmark cases, and full
  control-plane/corpus suite remain green.

## Rollback

The lens corpus remains reusable, but the shipped Markdown skill is a front end
to the control plane rather than an alternate execution path. Rolling back the
CLI therefore also requires rolling back that skill entry point; existing
fixture semantics need not be rewritten. Schema changes after the first
published bundle require explicit versioned migrations rather than in-place
reinterpretation.
