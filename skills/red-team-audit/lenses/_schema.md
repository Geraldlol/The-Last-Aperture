# Candidate-finding contract

This file is a contract, not a lens. It owns no topics, activates on nothing, and the linter skips it.

One record per candidate finding. The record is created by a lens at fan-out and then **accumulates**: triage adds fields, proof adds more, and no stage overwrites what an earlier stage wrote. That is the single most important property in the file, and it exists because the two most damaging things an audit pipeline can do to a finding are both overwrites — replacing the claimed impact with a capped one, and replacing an unproven result with a confident one.

Where a later stage disagrees with an earlier one it says so **beside** the original value rather than in place of it. `effective_severity` sits next to `claimed_impact_severity`; `verification_status` sits next to `confidence`. A reader can always see both what the lens believed and what survived, which is what makes a report auditable after the fact.

---

## Stage 1 — written by the lens at fan-out

| Field | Type | Notes |
|---|---|---|
| `candidate_id` | stable string | **Required.** Survives dedup, merge and re-runs. Every later stage and every report line references it |
| `lens` | string | The originating lens's `name` |
| `topic` | topic slug | **Required.** Topic ownership is the deduplication boundary |
| `title` | string | Short and specific |
| `claimed_impact_severity` | Critical / High / Medium / Low / Info | What the impact would be if the finding is real and reachable. **Never overwritten** |
| `location` | `file:line`, one or more | Multiple sites allowed after semantic dedup |
| `cwe` | string | CWE identifier where one applies |
| `evidence` | quoted code | The actual vulnerable text, not a paraphrase |
| `attack` | string | A concrete payload, request, or sequence |
| `impact` | string | What the attacker gets |
| `reachable_from` | entry point name, `contingent:<entry point name>`, or the literal `unknown` | **Required** |
| `contingent_fact` | string | **Required when `reachable_from` carries a `contingent:` value.** The one runtime fact the traced path waits on, written as a proposition |
| `contingent_query` | string | **Required when `reachable_from` carries a `contingent:` value.** The single query, command or API call that settles it, runnable by the reader |
| `confidence` | High / Medium / Low | The auditor's own calibration, before any proof |
| `proof_plan` | string | How this could be proven, for the proof phase to execute |
| `store_context` | object | **Required when `lens: database-and-data-stores`.** Stable store identity, selected adapter and the evidence that selected it; shape below |
| `principal_path` | object | **Required when `lens: database-and-data-stores`.** Authenticated/session/effective/owner-definer identities plus bypass capabilities |
| `enforcement_plane` | application / database / cloud / filesystem / unknown | **Required when `lens: database-and-data-stores`.** Where the claimed invariant is actually enforced |
| `copy_path` | string or string[] | Optional database context: primary, replica, CDC, history, backup, clone, export, index or another named copy |
| `adapter_rule_id` | stable string | **Required for version- or deployment-sensitive database claims.** Resolves to the selected adapter's rule |
| `semantic_source` | URL + verified date | **Required with `adapter_rule_id`.** Primary documentation establishing the engine behavior, not a search result or secondary summary |

### Database store context

Database findings are unusually easy to make confidently wrong: identical words
such as role, policy, deny, definer, transaction, replica and audit have different
semantics across engines, versions, editions and managed deployments. The
database lens therefore carries an additional context rather than laundering an
engine guess through prose.

`store_context` has this shape:

```yaml
store_id: orders-primary
family: relational
engine: postgresql
engine_version: "16"
deployment_variant: self-managed
adapter_id: postgresql
detection_evidence:
  - package.json:31 @prisma/client
  - docker-compose.yml:19 postgres:16
confidence: high
```

`store_id`, `family`, `engine`, `deployment_variant`, `adapter_id`,
`detection_evidence[]` and `confidence` are required. `engine_version` is a
version or the literal `unknown`; do not infer it from remembered defaults. One
record concerns one store. A multi-store root cause is merged later through
ordinary candidate ids and locations, never by putting two adapters in this
object.

`principal_path` records the identities whose difference matters to the claim:
authenticated principal, session/current role, effective principal,
owner/definer/signer and any policy-bypass or administrative capability. Use the
literal `unknown` for an unresolved leg. `enforcement_plane` says where the
claimed invariant lives; an application predicate and a database policy are not
interchangeable controls.

An ambiguous profile selects adapter `inventory-only`. It may inventory assets
and write a Coverage gap, but it cannot clear a candidate. A version- or
deployment-sensitive database candidate with `engine_version: unknown`, an
inventory-only adapter, no `adapter_rule_id`, or no primary `semantic_source`
cannot be confirmed High or Critical: it is `UNPROVEN` and capped at Medium
until that semantic premise is established. Reuse `contingent_fact` and
`contingent_query` when one live fact would settle it; there is no parallel
database uncertainty field.

### `candidate_id` — stable across dedup, merge and re-runs

The id is the handle everything downstream uses: the triage record, the proof artifact, the patch, the report line, and a cross-lens chain that names this finding as a component. If it changes when a finding is merged or when the audit is re-run, every one of those references breaks silently.

"Stable" therefore means derived from what the finding *is*, not from when it was found. A content-addressed form — a hash over `topic`, the normalised primary `location`, and a normalised `title` — is stable across re-runs of an unchanged repository and across a merge that adds locations, and it changes only when the finding itself becomes a different finding. A sequence number assigned at fan-out has none of those properties and must not be used.

### `topic` — required, because it is the deduplication boundary

A finding without its topic slug **cannot be deduplicated by the mechanism the whole registry exists to provide.** Topic ownership is what lets the pipeline say "these two lenses found the same thing, and this one owns it"; strip the slug and that machinery has nothing to match on, so the finding either survives as a duplicate or is dropped by a heuristic. There is no default and no inference from the title. A record with no `topic` is malformed.

The slug must be one the lens named in `lens` actually owns, per `_topics.md` — with one exemption, for the two lens shapes that own nothing.

#### Exemption — a lens whose `owns` is empty

Two shapes in this registry own no slugs, and both must be able to write a Stage 1 record. `ai-generated-code` is always-on and reports against whatever domain the *consequence* belongs to. The triage lenses — `business-logic`, `completeness` — read the merged set and may originate a finding nobody filed. Read as an unconditional rule, the sentence above rejects every record either shape can produce, so **it does not apply to a lens whose `owns` is empty.**

**A lens with `owns: []` sets `topic` to the slug of the lens that owns the topic, and `lens` to itself.** `raised_by` repeats its own name. The pair is what makes the record legal, and each half carries one of the two things that would otherwise be lost:

- **`lens` (with `raised_by`) preserves attribution.** The record is authored by the lens that actually found the defect. Writing the topic owner's name into `lens` to satisfy the invariant would falsify the record's authorship, which is worse than the violation it avoids.
- **`topic` preserves the dedup boundary.** The finding lands on the owner's slug, so it collides with the owner's own record for the same defect and triage can merge them. A record carrying no slug, or an invented one, is invisible to the only dedup mechanism the registry provides.

The owning slug is chosen by the finding's **consequence**, not by the shape of the tell or the framing of the workflow. Where no registry slug covers the consequence the two shapes diverge, each by the rule stated in its own body at the point of use:

- `ai-generated-code` files nothing. It invents no slug, records the finding in the audit's notes, and reports the registry gap.
- A triage lens originates under its own `name`: `lens: business-logic`, `topic: business-logic`, `raised_by: business-logic`. That exact label, with no invented sub-slug. This is the one case where `topic` is not a registry slug at all, and it is deliberate — one honest label is better than a shadow registry of pseudo-slugs that nothing partitions and no rule can see.

**What a consumer must therefore never assume: that `topic` implies `lens` owns it.** Ownership is resolved through `_topics.md` and nowhere else. Any consumer that infers the owner from the record — a validator reading invariant 2 as unconditional, a report grouping findings by `lens`, a dedup key built from `lens` rather than `topic` — is wrong on every record these two shapes write, and wrong in the worst direction: it rejects or misfiles precisely the always-on and triage output that exists to catch what the domain lenses missed.

### `claimed_impact_severity` — never overwritten

This is what the impact would be **if** the finding is real and reachable. It is deliberately a claim about consequence, not a blended judgement about likelihood, and nothing later in the pipeline edits it.

Keeping it immutable is what breaks the deadlock between two true statements: an unreachable SQL injection is still a SQL injection, and an unreachable SQL injection should not be reported as Critical. Both survive here, in two fields. The capping happens in `effective_severity`, and the claim stays readable next to it.

It also decides queue order. **The proof queue is built from `claimed_impact_severity`, not from `effective_severity`** — otherwise a finding capped to Medium by the reachability gate would be deprioritised precisely when proving it is what would resolve the reachability question.

### `reachable_from` — required, and the cheapest precision mechanism in the design

Naming the path from untrusted input to the vulnerable line, at the moment the finding is written, eliminates a large class of findings about code nothing can reach. Making it required is the point: the field cannot be skipped, so the auditor either finds the path, or names the one runtime fact the traced path waits on, or writes `unknown` and accepts the consequence. Three values, in descending order of what the auditor established.

`unknown` is a legitimate value, not a failure. It survives to triage and caps `effective_severity` at Medium. It does **not** remove the record from the proof queue, because a proof is often exactly what resolves it.

#### `contingent:<entry point>` — the path is traced and one named runtime fact decides whether it is live

**`unknown` and a fully traced path are not the only two states, and collapsing them is expensive.** A permission grant to a guest or anonymous principal can be traced end to end in committed metadata — the profile, the permission set, the object and field permissions it confers, the classes it can reach — with exactly one thing left open: whether that permission set is assigned to anybody. One query answers it, and that query runs against a live system — a host `_harness.md`'s first hard rail forbids the auditor to reach, which is exactly why the fact is still open. Written as `unknown`, the record is priced identically to one where no path was found at all, and it queues behind findings nobody can close.

The third form says what is actually true. Everything after the first `:` is the entry point, written exactly as it would have been written had the path been unconditional, and two companion fields carry the rest:

- **`contingent_fact`** — the fact as a single proposition whose truth decides the path: `the Site_Intake_Team permission set is assigned to at least one active user`. Not a topic, not a list of concerns. **One fact.** Two open facts is `unknown`, and a value that has accumulated a second fact has become `unknown` and must be rewritten as one.
- **`contingent_query`** — the one query, command or API call the reader runs to settle it, verbatim and runnable: `SELECT COUNT() FROM PermissionSetAssignment WHERE PermissionSet.Name = 'Site_Intake_Team'`. It is named because the auditor is forbidden to run it, not because the auditor did not think of it.

Three rules keep the form from becoming a way to launder a half-traced path:

1. **If the checkout answers the fact, answer it.** A fact resolvable from a file in the repository is not a runtime fact. Resolve it and write the entry point plainly. This form is only for what a running system knows and a checkout does not.
2. **It caps at Medium, exactly as `unknown` does.** A traced path waiting on an unverified fact is still not a demonstrated path, and the cap is arithmetic — invariant 6, with no discretion in it. Severity is not what the form buys.
3. **It is never a `drop_reason`.** An unresolved fact is a reason to queue the record and say so, not a reason to drop it; dropping on it discards a fully traced path on a guess.

What the form buys is queue position and a report line. Within a `claimed_impact_severity` band, `contingent:` records precede `unknown` ones, because one named query closes them and nothing closes an `unknown`. And the report prints the fact and the query beside the finding, so the reader can resolve in one step what the audit could not resolve at all: **a report that renders this value as `unknown` has thrown away the entire distinction**, which is the failure the form exists to fix.

### `location`, `evidence`, `attack`

`location` is one or more `file:line`. Multiple entries mean one finding at several sites after semantic dedup, not several findings. For a defect that spans a range, name the first line and let `evidence` carry the span.

`evidence` is the code, quoted. A paraphrase is not evidence — it is the reader having to take the auditor's word for the thing most worth checking, and it is where a hallucinated finding hides. If the artifact is there and the quoted text does not appear at the quoted location, the finding's premise is falsified and the proof stage records `DISPROVED`. Where the artifact cannot be located at all there is no quoted location to check, and that grades `NOT_REPRODUCED`, never `DISPROVED` — invariant 14, and the distinction is load-bearing. Confirming that the text does appear is the **first** thing every later reader does, before arguing anything else about the record — see `## The proof oracle` → **Existence first**.

`attack` is a concrete payload, request or sequence. "An attacker could manipulate the input" is not an attack; `?id=../../etc/passwd` is.

---

## Stage 2 — added at triage

| Field | Type | Notes |
|---|---|---|
| `effective_severity` | Critical / High / Medium / Low / Info | After reachability capping, floors and chain elevation. Derived; `claimed_impact_severity` remains readable beside it |
| `triage_disposition` | `queued` / `merged` / `dropped` / `elevated` | What triage did to the record |
| `drop_reason` | string | **Required when dropped** |
| `raised_by` | lens name | Set when a triage lens elevated the finding, or when one lens raised it against another lens's topic |
| `component_finding_ids` | `candidate_id[]` | For a chain finding: the components that compose into it |

### `effective_severity` — derived, and sitting beside the claim rather than replacing it

Computed, in this order, from `claimed_impact_severity`:

1. **Reachability gate.** `reachable_from: unknown` caps it at Medium, and a `contingent:` value caps it at Medium too — a traced path waiting on an unverified runtime fact is not a demonstrated path. The two cap identically and are queued and reported differently.
2. **Tier cap.** T0 and T3 cap at Medium. So do `verification_status: UNPROVEN` and `INCONCLUSIVE`. These apply at Stage 3 and revise `effective_severity` there — which is the one case where a later stage rewrites a Stage 2 field, and it is allowed precisely because the field is declared derived.
3. **Chain elevation.** A composed path may raise it above the claim.

Two rules keep it honest. It may **exceed** `claimed_impact_severity` only when `triage_disposition` is `elevated` and `raised_by` is set — an elevation with no author is an unexplained promotion. And a Critical or High carrying T0, T3, `UNPROVEN` or `INCONCLUSIVE` is **a contract violation, not a judgement call**: the cap is arithmetic, not advice.

### `triage_disposition`

- **`queued`** — survives to the proof phase.
- **`merged`** — collapsed into another record for the same topic. The merged record keeps its own `candidate_id`, which is what "stable across merge" means: a chain or a report line that already referenced it still resolves. The survivor's `location` carries the union of the sites.
- **`dropped`** — removed, with `drop_reason`.
- **`elevated`** — severity raised, with `raised_by` naming who raised it and `component_finding_ids` listing the components where the elevation is a composition.

**One known thinness, stated rather than papered over:** a `merged` record carries no pointer to the record it merged into. The survivor is identifiable by shared `topic` plus the accumulated `location`, which is enough for a human reading the run but not enough for a mechanical walk from a merged id to its survivor. Adding a pointer field is a Phase B decision, not something to improvise per run.

### `drop_reason` — required when dropped

**A drop with no reason is indistinguishable from a loss.** That is the entire argument. A record that vanished because triage judged it a false positive and a record that vanished because a step failed look exactly the same in the output, and only one of them is acceptable. The reason is what separates them, so it is required rather than encouraged.

Write the discriminator, not the verdict. "Not a finding" is not a reason. "The route is behind the admin guard at `middleware/auth.ts:41`, which the fan-out record did not account for" is.

### `raised_by`

Set when the record's severity or existence originates somewhere other than the lens in `lens`: a triage lens elevating a chain, or a cross-cutting lens raising a finding against a domain lens's topic. The `topic` still belongs to its owner — `raised_by` records who pushed, which keeps a cross-cutting lens from silently acquiring topics it does not own.

Two cases, and they differ in what `lens` says:

- **An existing record was elevated.** The record was authored by the lens named in `lens`, and a triage lens raised its severity or composed it into a chain. `lens` is untouched; `raised_by` names the raiser.
- **A lens that owns no slugs originated the record.** `lens` names that lens itself and `topic` names the owning lens's slug, per the exemption under Stage 1's `topic`. Authorship is never reassigned to the topic's owner.

---

## Stage 3 — added at proof

| Field | Type | Notes |
|---|---|---|
| `existence_check` | `located` / `not_located`, plus how | **Written before every other field at this stage.** Whether the cited artifact was opened at `location` and the quoted `evidence` found there, and by what read or command |
| `proof_tier` | T0 / T1 / T2 / T3 | The tier **actually reached**, not attempted |
| `verification_status` | see below | `CONFIRMED` / `NOT_REPRODUCED` / `INCONCLUSIVE` / `DISPROVED` / `UNPROVEN` |
| `artifact` | path + hash | The test file or capture, hashed so the report is checkable after the fact |
| `command` | string | The exact command run. **Identical before and after the patch** |
| `pre_result` | structured | The outcome before the patch, including the assertion that fired |
| `post_result` | structured | The outcome after the patch |

Tier definitions, severity caps and the static-checker resolution live in `_harness.md` → `## Proof tiers`. They are not restated here; this file records the field, that file defines the values.

### `existence_check` — written before anything else at this stage

The one field whose position in the record is a rule about order. It says whether the cited artifact was opened at `location` and the quoted `evidence` found there, and by what read or command, and it is written **before** a tier is chosen or an impact is argued. The rule and the three outcomes are in `## The proof oracle` → **Existence first**; the reader who performs the check writes the field — triage, if triage got there first — and no later reader overwrites it.

The artifact this field is about is **the file at `location`**. It is not the Stage 3 `artifact` field, which is the proof's own test file or capture and is a different thing that happens to share the word.

### `proof_tier` — the tier reached, not the tier attempted

A T1 recipe that never ran does not land at T1. It lands at whatever its surviving evidence supports — T0 where a code path is cited, T3 where a runnable proof-of-concept was written and left unexecuted. Recording the ambition rather than the result is how a Medium-capped finding escapes its cap, and it is the most likely place for this contract to be violated by accident.

### `command` — identical before and after the patch

The field is single-valued on purpose: there is no `pre_command` and `post_command`, so the two cannot drift. An *equivalent* command is not the same command. A pre-patch run of `pytest test/security/test_authz.py::test_cross_tenant -x` and a post-patch run of `pytest test/security/` differ in what they measure, and the difference is invisible in the report.

This is also why security tests live in their own directory and never edit the project's existing tests: appending an assertion to an existing test file changes what the project's own command measures, which makes the identical-command requirement unsatisfiable.

### `artifact` — path plus hash

The path locates the test file or capture; the hash is what makes the report checkable later. An artifact reference with no hash cannot distinguish the file that produced the recorded result from the file as it stands today, and the whole reason for recording pre and post results is that somebody may want to re-derive them.

### `pre_result` and `post_result`

`pre_result` carries the **assertion that fired** — the actual failure text, not "failed". `post_result` carries the pass, plus the outcome of the project's own relevant regression tests, because a patch that blocks the attack by breaking the feature is not a patch.

---

## The proof oracle

**Existence first — an ordering rule, not a sixth condition.** Before any argument about reachability, severity or impact, the cited artifact is opened at the cited `location` and the quoted `evidence` is confirmed present there, verbatim. That is step one for every reader of the record — the proof phase, a triage lens, a second auditor brought in specifically to attack the finding — and the outcome is written to `existence_check` before the argument starts.

**The ordering is the whole rule, because effort was never what failed.** One path was attacked from opposite sides by two independent readers, one going after reachability and one after enforcement and impact, and both agreed it was Critical. Both reasoned about what the cited record *would mean*. Neither opened it. Its credential-shaped fields read `REDACTED_DO_NOT_COMMIT`, and a false Critical shipped to the report. **Two skeptics who assume the artifact are not two verifications; they are one unchecked premise, argued twice** — and the more skilled each argument is, the more convincing the result.

Three outcomes, and only the third leads anywhere:

- **The artifact cannot be located at all** — the path does not resolve in this checkout, the record is not present, the reference is ambiguous — and the finding is `NOT_REPRODUCED`, **however plausible the reasoning is.** It is deliberately not `INCONCLUSIVE`: locating a file needs no harness, so failing to locate one is a statement about the claim rather than about the setup, and `INCONCLUSIVE` would report at Medium what has to be withdrawn.
- **The artifact is there and the quoted evidence is provably not** — the field holds a placeholder, the function is not in the file, the line says something else — and the premise is falsified: `DISPROVED`, quoting what was actually found at that location in place of what was claimed.
- **Both check out.** Only then do the five conditions below mean anything, and only then is a tier assigned.

A record that argues a grade with no `existence_check` is malformed, not optimistic (invariant 14).

`verification_status` cannot be assigned from a test's exit code. **A result counts as evidence only when all five of these hold:**

1. **A declared assertion signature**, named *before* the run. "It failed" is not a signature. `AssertionError: expected 403, got 200 with body containing other_user_email` is.
2. **Path-reached evidence** — proof that the vulnerable line executed. A spy, a coverage marker, a log line, an injected canary observed downstream.
3. **A control** — a positive control that must fail, or a sensitivity control showing the test detects the condition when it is present. This is what distinguishes a test that passes because the code is safe from one that passes because it asserts nothing.
4. **The identical command before and after the patch.**
5. **The project's relevant regression tests passing after the patch.**

Condition 3 is the one most often skipped and the one that most often changes the answer. A sweep with no planted-marker control, an enumerator with no committed count, a limiter test with no positive case: each of those passes on a codebase whose entry point the harness failed to resolve, and each of those passes looks exactly like safety.

---

## Why the verification states are five, not three

A two-outcome oracle — passed means safe, failed means vulnerable — is wrong in **both** directions at once, and the two errors are not symmetric in cost.

- **A test failing at import is not a confirmed finding.** `ModuleNotFoundError`, a missing fixture, a database that never came up: the command exits non-zero and nothing was learned about the code. Reported as `CONFIRMED`, that is a fabricated Critical.
- **A test passing because it never reached the vulnerable line is not a disproof.** The route was renamed, the payload was rejected by a validator before the sink, the spy was attached to the wrong module. Reported as a disproof, that silently deletes a real finding on the strength of a typo.

Five states separate the four distinct things a run can mean from the two things it can be mistaken for.

| State | Meaning | Reported as |
|---|---|---|
| `CONFIRMED` | The assertion fired pre-patch, passed post-patch, and all five oracle conditions were met | Full severity |
| `NOT_REPRODUCED` | The oracle was valid and the test ran correctly; the predicted behaviour did not occur — **or** the cited artifact could not be located at all, which needs no test to settle | Withdrawn from findings, recorded in `Coverage`, naming which of the two |
| `INCONCLUSIVE` | Setup failed, the path was never reached, a control failed, or the oracle itself was invalid | Reported, capped at Medium, **with the specific reason** |
| `DISPROVED` | A validated oracle showed the code is not vulnerable, **or** the finding's code premise was falsified | Removed, with the falsified premise stated |
| `UNPROVEN` | No proof was attempted or none is possible in the current capability mode | Reported, capped at Medium, with the blocking reason |

### `DISPROVED` is a strong claim, and the distinctions around it are the point

**`DISPROVED` requires a validated oracle or a falsified code premise.** Nothing weaker. Either a test that satisfies all five oracle conditions demonstrated the code is not vulnerable, or the finding's own premise turned out to be false — the quoted `evidence` does not appear at the quoted `location`, the function named does not exist, the parameter is not user-controlled.

**The falsified premise is the *located* case, and the distinction from an unlocatable artifact is load-bearing.** `DISPROVED` here means the file was opened and the claim is not in it. An artifact that could not be found at all is `NOT_REPRODUCED`: "I could not locate it" is not a demonstration that the code is safe, and grading it as a disproof would let a mis-typed path close a real finding.

**Everything that used to collapse into `DISPROVED` becomes `INCONCLUSIVE`:** an import error, a test that never reached the path, a missing fixture, an environment the proof needed and did not get, a control that failed. Each of those is a statement about the harness, and a statement about the harness is not a statement about the code. A design that lets them read as disproof deletes real findings on the strength of a `ModuleNotFoundError`, which is the specific failure this split exists to prevent.

**`NOT_REPRODUCED` and `DISPROVED` are different claims, and the difference is worth keeping.** `NOT_REPRODUCED` says *my attack did not work*, or *the thing I attacked was not there* — the oracle was sound, the test ran, the predicted behaviour did not occur, and the attack may simply have been wrong; or the existence check never found the artifact to attack. `DISPROVED` says *the vulnerability is not there*. The first leaves the door open and is recorded in `Coverage` so a later run can try a different attack; the second closes the finding and states what was falsified. Collapsing them loses the ability to distinguish a bad exploit from a safe codebase.

**`UNPROVEN` is not a soft `NOT_REPRODUCED`.** Nothing ran. It is the honest label for a T3 proof-of-concept, for a T2 boot the user declined, and for an assertion that needs an engine this repository stubs. It always carries the blocking reason, and it is never reported as a pass.

---

## Invariants

A validator for this contract enforces exactly these. Each one corresponds to a way a real audit has gone wrong.

1. `candidate_id`, `lens`, `topic`, `title`, `claimed_impact_severity`, `location`, `reachable_from` are present at Stage 1. `topic` and `reachable_from` have no default.
2. `topic` is owned by `lens` per `_topics.md`, **unless `lens` owns no slugs** — in which case `topic` is a slug owned by some lens, or, for a triage-originated record, `lens`'s own `name`; and `raised_by` equals `lens`. A validator must read this exemption as part of the invariant: applied unconditionally, invariant 2 rejects every record `ai-generated-code`, `business-logic` and `completeness` can write.
3. `claimed_impact_severity` is byte-identical across every appearance of the same `candidate_id` in a run, and across runs where the finding has not changed.
4. `effective_severity` exceeds `claimed_impact_severity` only when `triage_disposition` is `elevated` and `raised_by` is set.
5. `triage_disposition: dropped` implies `drop_reason` is present and non-empty.
6. `reachable_from: unknown` **or** a `contingent:` value implies `effective_severity` is at most Medium, and neither implies removal from the proof queue. A `contingent:` value additionally implies `contingent_fact` and `contingent_query` are both present and non-empty, that `contingent_fact` states one fact rather than several, and that the value is **not** normalized to `unknown` by any consumer: the cap is identical, the queue position and the report line are not.
7. `proof_tier` in {T0, T3} implies `effective_severity` is at most Medium.
8. `verification_status` in {`UNPROVEN`, `INCONCLUSIVE`} implies `effective_severity` is at most Medium.
9. `proof_tier: T3` implies `verification_status: UNPROVEN`. The converse does not hold.
10. `verification_status: CONFIRMED` implies `proof_tier` in {T1, T2}, and `existence_check`, `artifact`, `command`, `pre_result` and `post_result` are all present, and `existence_check` records `located`, and `pre_result` names the assertion that fired.
11. `verification_status: INCONCLUSIVE` implies a recorded reason; `UNPROVEN` implies a recorded blocking reason.
12. `command` appears once. A record with two commands is malformed, not lenient.
13. The proof queue is ordered by `claimed_impact_severity`. Every Critical and High is enqueued, including those capped to Medium by invariant 6. Within a band, `contingent:` records precede `unknown` ones, because a named query closes them.
14. No `verification_status` is assigned without `existence_check`, and `existence_check: not_located` implies `verification_status: NOT_REPRODUCED`. The check is ordered before the argument, so a record that grades an artifact nobody opened is malformed, not optimistic.
15. A record with `lens: database-and-data-stores` has `store_context`, `principal_path` and `enforcement_plane`. A version- or deployment-sensitive claim also has `adapter_rule_id` and `semantic_source`; otherwise `verification_status` is `UNPROVEN` and `effective_severity` is at most Medium. An `inventory-only` adapter can appear in Coverage but cannot produce a clearance.

Invariants 7, 8 and 10 together are the criterion that makes the whole contract worth having: **every Critical or High in a shipped report carries `CONFIRMED` with T1 or T2 evidence attached.** Anything else caps at Medium, arithmetically, with no room for a judgement call. Invariant 14 is what keeps that criterion from being satisfied by a well-argued claim about a file nobody opened — the criterion is about evidence, and an unread artifact is not evidence at any tier.

---

## A record at each stage

```json
{
  "candidate_id": "authz-object-level:a3f19c2e",
  "lens": "web-and-api",
  "topic": "authz-object-level",
  "title": "Invoice detail route loads by id with no ownership scope",
  "claimed_impact_severity": "High",
  "location": ["src/routes/invoices.ts:88"],
  "cwe": "CWE-639",
  "evidence": "const invoice = await repo.findById(req.params.id)",
  "attack": "GET /api/invoices/8814 as a user in another tenant",
  "impact": "Reads any invoice in any tenant, including line items and the billing address",
  "reachable_from": "GET /api/invoices/:id",
  "confidence": "High",
  "proof_plan": "Two-subject fixture; request A's invoice as B; assert refusal and marker absence",

  "effective_severity": "High",
  "triage_disposition": "queued",

  "existence_check": "located — src/routes/invoices.ts:88 read; the quoted line is present verbatim",
  "proof_tier": "T1",
  "verification_status": "CONFIRMED",
  "artifact": {
    "path": "test/security/test_invoice_authz.py",
    "sha256": "9c1e7d4b0f2a8c6153e9a0d7b4c28f1e5a3906dd82b7f4c1e0a5d93b6c7e2f80"
  },
  "command": "pytest test/security/test_invoice_authz.py -x",
  "pre_result": {
    "assertion": "AssertionError: expected a refusal, got 200",
    "detail": "marker CANARY-SUBJECT-A-R1 present in body",
    "path_reached": "spy on repo.findById recorded 1 call with id=8814"
  },
  "post_result": {
    "status": "passed",
    "regressions": "npm test — 412 passed, 0 failed"
  }
}
```

The record above is one object accumulating three times, not three objects. `claimed_impact_severity` is the same string it was at fan-out; `effective_severity` sits beside it and happens to agree, which is the outcome the whole apparatus exists to make legible when it does not.
