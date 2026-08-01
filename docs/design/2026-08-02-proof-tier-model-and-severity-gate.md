# Proof tier model and severity gate

- Status: Proposed
- Date: 2026-08-02
- Owners: Red Team Audit platform
- Relates to: ADR 0004 (detached root attestation), ADR 0006 (disposable
  conformance lab)

## Context

The severity gate does not discriminate. Measured against the most recent
completed audit of a real target (`PeerStar-Prod`, tool 0.4.0, 43 findings,
8,647 of 8,769 files examined, all 15 lenses `RAN`):

```
proof_tier          : { "T0": 43 }        every finding
verification_status : { "UNPROVEN": 43 }  every finding

19 findings claim above Medium (3 Critical, 16 High)
caps firing: PROOF_TIER 19, VERIFICATION 19, REACHABILITY 4
effective severity reported: Medium 40, Low 3, High 0, Critical 0
```

`findingInvariantErrors` caps effective severity at Medium when
`proof_tier ∈ {T0, T3}` and again when
`verification_status ∈ {UNPROVEN, INCONCLUSIVE}`. In a static run those are the
only reachable states, so both caps fire on every finding that claims above
Medium. Fifteen of the nineteen have concrete `reachable_from` and are capped
anyway.

Each rule is individually sound. The input space is degenerate: there is exactly
one reachable state, so the gate is a constant ceiling wearing the costume of a
risk assessment. The consequence is that a configuration fact readable directly
from the target — a PostgreSQL Flexible Server accepting connections from every
Azure service, Key Vault data planes on public endpoints — is reported at the
same severity as an unevidenced guess.

For an operator whose primary risk is an unreported breach, a report containing
no Critical findings is the most dangerous output the tool can produce.

The tiers are not the problem. `T0`–`T3` already exist in
`schemas/finding.schema.json`, and so does a fully specified anchor type that
nothing currently consumes:

```json
"sourceAnchor": {
  "required": ["file_id", "snapshot_sha256", "start_byte", "end_byte", "excerpt_sha256"]
}
```

A byte range plus an excerpt digest, bound to a snapshot. That is a mechanically
checkable claim, and the controller already seals the bytes needed to check it.

## Decision

### 1. Tiers become evidence classes

| Tier | Meaning | Cap |
|---|---|---|
| `T0` | Asserted. No anchored evidence. | Medium |
| `T1` | Anchored. A configuration or code fact located by byte range in sealed source. | none |
| `T2` | Demonstrated against a disposable non-production instance, pre/post state captured. | none |
| `T3` | Demonstrated against production by non-destructive probe under an authorising RoE. | none |

`T0` stops being the default bucket. `T3` stops being capped: it is currently
capped because the proof broker does not exist, which conflates "not permitted
yet" with "weak evidence." Availability is enforced by RoE mode, not by a
severity penalty.

### 2. `T1` is verified by the controller, not declared by the provider

A provider claiming `T1` or above supplies `source_anchors`. At ingest the
controller, for each anchor:

1. resolves `file_id` in the run's sealed snapshot index;
2. confirms `snapshot_sha256` equals the run's `source_snapshot.root_sha256`;
3. reads bytes `[start_byte, end_byte)` from the sealed file;
4. computes SHA-256 over those exact bytes;
5. compares to `excerpt_sha256`.

All anchors verifying is the definition of `CONFIRMED` at `T1`. No model
judgement participates: either the quoted bytes are in the sealed source at the
stated offsets or they are not.

This also closes a hole nothing currently checks — a finding quoting evidence
that does not exist in the sealed source is presently indistinguishable from one
that does.

### 3. Failed verification rejects the result

An anchor that does not verify is a contract violation and rejects the job
result, consistent with the platform's fail-closed posture elsewhere. A provider
asserting evidence absent from the sealed bytes is precisely the condition the
platform exists to detect; silently downgrading it would discard the signal.

Providers are free to declare `T0` with no anchors and face no verification. The
rule is that claiming more evidence invites more checking.

### 4. `T1` and above require a sealed run

Anchor verification reads the sealed byte store, so it is unavailable when
`plan` ran without `--seal-source`. In an unsealed run every finding is `T0` and
the Medium ceiling stands. This is stated as a precondition rather than a
failure: an unsealed run has no reproducible bytes to appeal to, so it has not
earned a claim above Medium.

## Changes

### `scripts/lib/contracts.mjs`

`findingInvariantErrors` stays pure — no I/O — and changes in two places:

- `PROOF_TIER_CAP` (line 573): `['T0', 'T3'].includes(record.proof_tier)`
  becomes `record.proof_tier === 'T0'`.
- New `UNSEALED_TIER_CLAIM`: a finding declaring `T1` or above in a run without
  `source_snapshot` is invalid. This needs run context, so it goes in
  `runInvariantErrors` (line 2450) alongside the other cross-record checks, not
  in `findingInvariantErrors`.

`VERIFICATION_CAP`, `REACHABILITY_CAP`, and `UNAUTHORISED_SEVERITY_ELEVATION`
are unchanged. `REACHABILITY_CAP` fires on 4 of 19 findings and is doing honest
work; the other two are correct rules that were starved of inputs.

### New: `scripts/lib/anchor-verification.mjs`

`sealed-snapshot.mjs` parses and validates the index but exposes no byte-read
API, and it imports only `node:crypto` by design to keep the seal's trusted
computing base minimal. Verification therefore gets its own module rather than
growing that one.

```
verifySourceAnchors(finding, snapshotIndex, readSealedBytes) -> AnchorOutcome[]
```

`readSealedBytes` is injected, so the function is pure with respect to its
inputs and testable against a synthetic index with no bundle on disk.

It returns per-anchor outcomes rather than a boolean, so a rejection can name
which anchor failed and how: unknown `file_id`, `snapshot_sha256` from another
run, range beyond file length, inverted or empty range, or digest mismatch.
"The evidence is not in the sealed bytes" and "the offsets are wrong" are
different operator problems and must not collapse into one message.

### Ingest wiring

`ingest` and `ingest-batch` call anchor verification for any finding declaring
`T1` or above, before the result is committed. Verification happens inside the
existing write-once boundary; a rejected result is not partially applied.

### Schema

`schemas/finding.schema.json` gains a conditional: `proof_tier` of `T1` or above
requires `source_anchors` to be present and non-empty. The existing
`sourceAnchor` definition is unchanged — it is already correct.

## Provider obligations, and why this needs a helper

No finding in any recorded run carries a single `source_anchor`. The type is
fully specified and entirely unused, so this change does not merely relax a gate
— it asks providers to start producing evidence they have never produced.

An anchor requires the provider to state a `file_id`, a byte range, and a
SHA-256 over exactly those bytes. Computing that by hand, from an agent reading
a file as text, will be wrong often: byte offsets are not character offsets,
UTF-8 multi-byte sequences and CRLF line endings both break naive arithmetic,
and a wrong offset produces a rejection rather than a wrong answer. Rejections
are safe but they are also the whole loop's cost.

The controller must therefore supply the anchor rather than ask for it:

```
red-team-audit anchor <bundle> <path> --start-line <n> --end-line <n>
```

resolving the path to its `file_id` in the sealed index, converting the line
range to byte offsets against the sealed bytes, and emitting a complete
`sourceAnchor` object. The provider quotes what it found; the controller
computes what makes the quote checkable.

This keeps authority in the right place. A provider that could hand-craft
anchors could hand-craft ones that verify against bytes it never read; one that
must ask the controller for an anchor to a path and line range is constrained to
evidence that exists.

`skills/red-team-audit/SKILL.md` gains the corresponding rule: a finding
claiming `T1` or above must carry anchors obtained this way, and a finding
without anchors is `T0` and capped, which is a legitimate outcome rather than a
failure.

## Expected effect

Applied to the measured run, 15 of the 19 suppressed findings become eligible to
surface at their claimed severity, including all 3 Criticals, conditional on
their anchors re-verifying against sealed source. The remaining 4 stay at Medium
under `REACHABILITY_CAP`, which is the rule working as intended.

That run was planned without `--seal-source`, so it cannot be re-scored in
place. It must be re-planned sealed to benefit. This is the correct outcome:
its findings were never anchored to reproducible bytes.

Nothing in this change executes code, contacts a target, or reads a record.

## Testing

- Anchor verification: exact-match, off-by-one at both range ends, unknown
  `file_id`, `snapshot_sha256` from a different run, range exceeding file
  length, empty range, multi-byte UTF-8 split across the boundary.
- `anchor` command round-trip: an anchor it emits for a line range verifies;
  the byte offsets are correct across CRLF line endings, a file with no trailing
  newline, and a file containing multi-byte UTF-8; the command refuses a path
  absent from the sealed index rather than inventing a `file_id`.
- Gate behaviour: a `T1`/`CONFIRMED` finding with concrete reachability reaches
  Critical; the same finding at `T0` caps at Medium; the same finding with
  `reachable_from: unknown` caps at Medium regardless of tier.
- `T3` no longer caps on tier alone, and is refused when RoE mode does not
  authorise it.
- A `T1` claim in an unsealed run is rejected.
- Regression: replay the measured 43-finding corpus and assert the severity
  distribution changes only where anchors verify.

Every test above is derived from a rule in this document. A test that passes
before the change is not evidence for it — each gate test must be shown failing
against current `main` first.

## Out of scope

`T2` and `T3` mechanics: the disposable-instance harness, the RoE capability
grammar, the proof broker, and the invariant that no proof step may read, write,
or transmit protected health information. Those are specified separately. This
document defines the ladder they attach to and unblocks the tiers that need no
execution at all.
