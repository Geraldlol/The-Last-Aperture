# TEST_EXECUTION capability mode

- Status: Proposed
- Date: 2026-08-02
- Owners: Red Team Audit platform
- Relates to: ADR 0002 (sealed provider execution), ADR 0006 (disposable
  conformance lab), `skills/red-team-audit/lenses/_harness.md`

## Context

No audit this platform can currently run is capable of producing a High or
Critical finding, and this is a consequence of one unimplemented mode rather
than a defect in the severity gate.

The proof tiers, defined in `_harness.md`:

| Tier | Meaning | Cap |
|---|---|---|
| `T0` | Static reasoning with a cited code path | Medium |
| `T1` | Executed by the project's own test runner | none |
| `T2` | Booted locally, real request to a loopback socket | none |
| `T3` | A written proof-of-concept, never executed | Medium |

`T0` and `T3` cap at Medium deliberately: neither executed anything, and *"an
argument that has never met the code's actual behaviour is a hypothesis."* The
ladder is not ordered by strength — `T3` is weaker than `T1`.

`contracts.mjs` authorises tiers by capability mode:

```js
STATIC:         new Set(['T0', 'T3'])
TEST_EXECUTION: new Set(['T0', 'T1', 'T3'])
LOCAL_DYNAMIC:  new Set(['T0', 'T1', 'T2', 'T3'])
```

`STATIC` admits exactly the two capped tiers. Every completed audit to date ran
`STATIC`, so every finding was `T0`/`UNPROVEN` and the Medium ceiling was
correct. The most recent `PeerStar-Prod` run claimed 3 Critical and 16 High and
reported all 43 findings at Medium or Low. That was the system working.

Most of the machinery for `TEST_EXECUTION` is already built and unreachable:

- `policy.mjs` lists `test` in `POLICY_MODES`; `authorizeAction` special-cases
  only `static` and `remote_static`, so `execute` and `write_file` actions fall
  through to capability checks. `authorizeExecute` and `authorizeFile` exist.
- `run-engine.mjs:537` already maps RoE `mode: 'test'` to
  `capability_mode: 'TEST_EXECUTION'`.
- `job-protocol.mjs` already emits `proof-existence:<candidate_id>` and
  `proof-verification:<candidate_id>` jobs in a `PROOF` phase.
- `finding.schema.json` already carries `proof_tier`, `verification_status`,
  `artifact`, `command`, `pre_result`, `post_result`, `blocking_reason`.
- `contracts.mjs:2828` already requires proof artifacts be SHA-256-manifested in
  the bundle (`UNBOUND_PROOF_ARTIFACT`).

Two guards block all of it. `audit.mjs:3210` refuses a `test` RoE at plan time;
`audit.mjs:1524` refuses a non-`STATIC` run at dispatch. Confirmed by planning
`fixtures/vulnerable` with a hand-written `test` RoE and receiving
*"test and local_dynamic Rules of Engagement require the proof broker, which is
not available in 0.10.0."*

What genuinely does not exist: anything that executes an authorised command,
the disposable mirror, the owned-paths manifest, and the egress guard.

## Hard rails

These bind the design and are not negotiable by consent or mode. From
`_harness.md`:

1. Targets are files in the target tree and `localhost`. Never a remote host,
   and specifically never a hostname read from configuration — reading a
   `DATABASE_URL` is the audit, connecting to it is the violation.
2. No destructive payloads. Where a bug class can only be shown by causing
   damage, the recipe is written and left unexecuted at `T3`.
3. Security tests live in their own `test/security/` directory and never edit
   the project's existing tests. Proof work belongs in a disposable mirror, and
   the audit returns a manifest of owned paths rather than a mutated target.
4. Never commit.
5. Never source production credentials. A proof that cannot run without a
   credential it was not given returns `INCONCLUSIVE`.
6. Install the destination guard before running anything that could open a
   socket.

And the disclosure, which this design adopts verbatim rather than softening:
test execution runs the repository's own command with the repository's own
environment. If that applies migrations, starts containers, or emits telemetry,
the audit does all of it. **This is disclosure, not a sandbox.**

## Decision

### 1. The controller executes; the provider authors

A new `run-proof` command stands in the same relationship to a `PROOF` job that
`run-provider` stands in to a `LENS` job: it executes the job instead of the
agent answering it.

The agent authors the proof — a detector plus a vulnerable/clean fixture pair,
or a security test — and the controller runs it. The agent never produces
`pre_result`, so it cannot fabricate one. This is the difference between a proof
and one more provider claim, and it is the only split consistent with a platform
whose premise is not trusting provider assertions.

```
red-team-audit run-proof <run.json|bundle-directory> <proof-config.json>
```

`proof-config.json` names the target job, the authored files and their content
digests, and the command to run. The command must match a `commandRule` in the
RoE's `execute` allowlist or the run is refused before anything is copied.

### 2. Execution happens in a disposable copy, and non-mutation is proved

1. Copy the target tree to a disposable mirror outside the target.
2. Materialise the authored proof files under `test/security/` in the mirror.
3. Authorise the command with `authorizeAction(policy, { type: 'execute', … })`.
4. Run it in the mirror, capturing exit status, stdout and stderr.
5. Recompute the **target's** tree digest and require it to equal the value
   recorded at plan time.
6. Emit the owned-paths manifest, then destroy the mirror.

A copy rather than a `git worktree`: it works identically whether or not the
target is a repository, shares no object store, and is one code path instead of
two. Rail 3's "original index preserved byte-for-byte" is git phrasing; step 5
is the git-free equivalent and is stronger — a content digest recomputed after
execution is cryptographic proof of non-mutation rather than a promise about an
index. A mismatch fails the run.

### 2a. The destination guard is authored, not installed by the controller

Rail 6 requires the destination guard, but the controller cannot install it.
The recorder hooks name resolution and the connect path **in-process**, in the
target's own language, and its second trap is explicit that it must be installed
*before the application imports its clients*. A parent process copying files
cannot do that.

So the guard is part of the authored proof harness. The controller's obligations
are narrower and honest about it:

- `proof-config.json` declares whether the harness installs the guard;
- the finding records that declaration alongside the command and results;
- a proof that declares no guard is accepted but marked, because a proof run
  without one is an unmonitored `npm test` and the report should say so.

The controller cannot verify the declaration. Claiming otherwise would be the
same error as calling the mirror a sandbox.

Two consequences worth stating plainly. The guard is *disclosure, not
isolation* — `_harness.md` says it "fails loudly on an unexpected connection;
it does not prevent a determined one." And only a **Python** harness ships
today. A Node, Go, or JVM target needs one authored before rail 6 can be
satisfied at all, which is a real constraint on which targets can reach `T1`
safely rather than merely reaching it.

### 3. The RoE is the consent artifact

The RoE is external, dated, carries a `policy_id`, and its `execute.commands`
allowlist is an explicit grant of specific programs and arguments. That
satisfies "state under whose consent" without a runtime prompt, and matches how
this platform already handles trusted policy.

`_harness.md`'s ask-every-time rule is specific to `T2` booting an application,
which is out of scope here.

### 4. `test` mode gets a schema conditional

`static` and `remote_static` each have an `allOf` conditional in
`roe.schema.json` and a contradiction check in `normalizePolicy`. `test` has
neither, so an RoE could today declare `mode: test` with network enabled to any
host. Rail 1 would exist only in prose.

`test` mode requires:

- `execute.enabled: true` with a non-empty `commands` allowlist;
- `write_file.enabled: true` with every root under a `security` leaf;
- `network.enabled: false`.

Network stays off because `T1` is the project's own test runner, not a loopback
request — that is `T2`. Where the repository's own test command boots an
ephemeral dependency it already boots, that is the command's business and the
destination guard is what catches anything unexpected leaving the machine.

The matching contradiction check goes in `normalizePolicy` beside the existing
two, so the rule holds for a policy constructed in code as well as one loaded
from disk.

### 5. Evidence shape, and why a proof carries a patch

`CONFIRMED` is not a statement that a bug exists. The schema's tenth conditional
requires, when `verification_status` is `CONFIRMED`: `existence_check.status`
`located`, `proof_tier` in `{T1, T2}`, all four of `artifact`, `command`,
`pre_result`, `post_result`, and `post_result.status` equal to `passed`.

And the two results are not two directions of one assertion. They are two
moments:

```
pre_result   required: assertion, path_reached, control
post_result  required: status ∈ {passed, failed}, regressions
```

`control` is the two-subject canary; `regressions` only means something once
something changed. `pre_result` is the bug demonstrated, `post_result` is the
suite green after a fix. **A finding cannot reach `CONFIRMED` without a
candidate fix that works and regresses nothing.**

That is the right requirement and this design adopts it rather than working
around it. `run-proof` performs the whole cycle inside the disposable mirror:

1. demonstrate the bug against the unmodified mirror — `pre_result`;
2. apply the authored candidate patch to the mirror;
3. re-run the proof command and the project's own suite — `post_result`;
4. destroy the mirror.

The real target is never written to at any point, so this needs no authorization
beyond the RoE's `execute` grant. The `PATCH` phase stays stubbed as
`patch:read-only / SKIPPED`, because that phase is about applying a fix to the
target itself, which remains out of scope.

The consequence is worth stating positively: a `CONFIRMED` finding ships with a
patch demonstrated to fix the bug and to break nothing else. That is a work
order rather than a report line.

Statuses:

- `CONFIRMED` — bug demonstrated, patch applied, suite passed, no regressions;
- `NOT_REPRODUCED` — the demonstration did not fire against the unmodified
  mirror, with `reason`;
- `DISPROVED` — the demonstration asserts the behaviour is already correct, with
  `reason`;
- `INCONCLUSIVE` — the command could not complete, including the rail-5
  missing-credential case, with `reason`;
- `UNPROVEN` — a demonstration exists but no candidate patch was authored, with
  `blocking_reason`. This is the honest resting state for a finding proven to
  exist and not yet fixed, and it caps at Medium.

That last row matters: demonstrating a bug without fixing it is a legitimate and
common outcome, and it does not reach Critical. The ceiling lifts for findings
that come with a working fix.

The detector-and-fixture-pair runner's two counts —
`detect(vulnerable).length == 1` and `detect(clean).length == 0` — both belong
to the demonstration and are recorded in `pre_result.assertion` and
`pre_result.detail`. `pre_result.control` names the clean fixture, which is
exactly the control the field is for.

### 6. Rule 6 downgrades without a VCS

The pair runner's sixth rule runs the tightened rule against the previous
revision and requires it to fail there, via `git show HEAD~1:path`. A target
with no history has no previous revision.

Where the target is not a repository, rule 6 is recorded as not-applied on the
finding, named. It is not skipped silently. The platform records gaps
everywhere else and this is a gap.

Nothing else in the audit path touches git. The inventory excludes `.git` and
derives `tree_digest` from file content, so a non-repository target plans,
seals, and digests identically — verified by planning a de-gitted copy of
`fixtures/vulnerable` and obtaining the same `tree_digest`.

## Failure modes

| Condition | Outcome |
|---|---|
| Command absent from the RoE `execute` allowlist | Refused before the mirror is created |
| Target tree digest changed after execution | Run fails; the mirror is preserved for inspection |
| Command exits non-zero for a reason other than the assertion | `INCONCLUSIVE` with `blocking_reason` |
| Credential absent | `INCONCLUSIVE` with `blocking_reason`, never a silent pass |
| Vulnerable fixture does not fire | `NOT_REPRODUCED`; the finding stays at its prior tier |
| Authored guard records an unexpected connection | The test fails in-process; the result is `NOT_REPRODUCED` or `INCONCLUSIVE` with the destination named |
| No destination guard declared | Run proceeds, finding records that execution was unmonitored |
| Mirror cannot be destroyed | Owned-paths manifest is still emitted; the run reports the residue |

The mirror is preserved rather than destroyed on a digest mismatch, because that
is the one failure where the evidence of what happened matters more than
cleanliness.

## Testing

- A `test` RoE plans successfully and yields `capability_mode: TEST_EXECUTION`.
- A `test` RoE with `network.enabled: true` is rejected by both the schema and
  `normalizePolicy`.
- A `test` RoE whose `write_file` roots escape a `security` leaf is rejected.
- A command absent from the allowlist is refused, and no mirror is created —
  assert the filesystem is untouched, not merely that an error was thrown.
- A proof whose command mutates the target fails the digest re-check, and the
  mirror survives.
- A pair fixture where the detector fires on both vulnerable and clean yields
  `NOT_REPRODUCED`, not `CONFIRMED`.
- A proof with a demonstration and no candidate patch yields `UNPROVEN` with a
  `blocking_reason`, and its effective severity caps at Medium.
- A candidate patch that fixes the bug but fails the project's suite yields
  `post_result.status: failed`, which the schema forbids pairing with
  `CONFIRMED` — assert the finding does not reach Critical.
- The target tree digest is unchanged after a full demonstrate-patch-rerun
  cycle, proving the patch touched only the mirror.
- A `T1` finding with concrete reachability reaches Critical; the same finding
  at `T0` caps at Medium.
- A `T1` claim in a `STATIC` run is rejected by `CAPABILITY_TIER_BYPASS`.
- Proof artifacts absent from the bundle manifest trigger
  `UNBOUND_PROOF_ARTIFACT`.
- A non-repository target completes a full proof cycle and records rule 6 as
  not-applied.
- A proof declaring no destination guard is accepted and the finding records the
  execution as unmonitored.

Each gate test must be shown failing against current `main` before its change
lands.

## Out of scope

`T2` and `LOCAL_DYNAMIC` — booting the application and issuing loopback
requests. `T2` reuses every component here and adds only the boot and its
consent prompt, so this work is on its critical path rather than beside it.

Artifact unpacking — turning an `.apk` or other distributable into an inventory
the existing lenses can read. Independent of this work and valuable on its own,
since `mobile-app-security` already activates on the shapes an unpacked APK
contains.

Testing a deployed site. Rail 1 forbids it at any tier under any consent, and
`_harness.md` is explicit that probing a running site requires written
authorization naming the site, scoped and dated, obtained before the first
request — and happens outside this skill. `T2` against a local boot is the
in-scope way to obtain real adversarial behaviour.
