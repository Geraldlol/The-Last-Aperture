# Adversarial validation engine

- Status: Accepted; core, sealed T1, and narrow loopback T2 implemented; generic live/L3 gated
- Date: 2026-09-03
- Owners: Red Team Audit platform
- Supersedes the proof-status semantics in `2026-08-02-test-execution-capability.md`
  and the approval-free active-request decision in ADR 0019.
- Clarified by ADR 0023: named operator authority and route availability are
  separate facts.
- Extended by ADR 0024: narrow sealed Node/npm loopback T2 is public.

## Objective

Build the operator-controlled path from an audit candidate to a reproducible,
reportable security finding. Codex, Claude, or another provider may discover a
candidate and author any vulnerability-specific validation strategy. The
controller, not the provider, decides whether proposed actions fit the accepted
operator statement, campaign envelope, and current technical permits. At
agent/controller ingress, the authenticated operator statement naming target
and scope is the sole authorization fact for every capability it names. If target/scope is
supplied, proceed; ask once only when it is missing. No repeated consent, RoE,
ownership, or legal check is required. The operator remains accountable.

The product workflow is:

1. accept the operator's target/scope statement at agent/controller ingress, then inventory
   and scan through an available controller route;
2. turn a candidate into a bounded, immutable adversarial plan;
3. execute repository and disposable-local proofs under the sealed execution
   policy;
4. seal the statement into a campaign receipt and request only the operational
   plan/phase decisions selected by the autonomy profile;
5. execute only actions and limits permitted by that receipt and the controller;
6. preserve a minimized reproducer, controls, observations, and provenance;
7. draft a report with root cause, impact, reproduction, and remediation;
8. track remediation and fix verification separately from vulnerability proof.

Success is not a universal exploit payload list. Success is a safe, extensible
control plane through which vulnerability-specific strategy adapters can prove
findings across the existing lenses.

## Implementation status (updated 2026-09-04)

The current tree implements the safety and evidence kernel, not an unrestricted
production attack bot. This distinction is intentional and release-relevant.

| Capability | Current state |
|---|---|
| Repository proof and remediation truth | Public `audit run-proof` is active through the sealed, network-denied Docker worker. Attack/control proof can confirm an unfixed defect; remediation remains independent. Proof subprocesses have wall-time, output, receipt, and verified-cleanup bounds. |
| Narrow local-service proof | Public `audit run-service-proof` is active for a sealed `LOCAL_DYNAMIC` run and strict v3 proof. Exact foreground Node/npm services and proof commands run in fresh attack/control containers with `--network=none`; a fixed literal-loopback TCP probe, init-backed supervisor TTL, immutable worker/source bindings, hash-only evidence, and verified teardown establish the narrow T2 lifecycle. Because no controller-authenticated semantic oracle is enrolled, completed runs remain `T2/UNPROVEN`; execution still occurs. Other T2 shapes remain unavailable. See ADR 0024. |
| Plan, authorization, and scope contracts | Implemented as a local prototype: strict schemas, canonical hashing, a one-use controller-sealed operator-authorization receipt bound to the exact statement, target, plan, scope, and time, inert formal scope requests, and sealed predecessor-bound scope revisions. The CLI accepts no caller-signed approval artifact. The local enrollment manifest fixes controller scope and adapter selection rather than establishing authority. Protected cross-process controller state remains open. |
| Graduated runtime | Implemented as a controller kernel: L2 live phases require acknowledged checkpoints; L3 evaluates adaptive actions inside a controller-sealed finite envelope and pauses blocked branches. |
| Campaign durability | Implemented as a local sequencing journal for non-live test campaigns: hash-chained records, fsynced send-intent records, checkpoints, observations, requests, compact terminal summaries, and fail-closed ambiguous-dispatch recovery. Receipt-bound execution rejects every caller-supplied ledger because that journal cannot attest nonce consumption, a unique lease, or authoritative writes. It is not rollback-resistant without an external anchor. |
| Break-glass | Implemented as a controller-sealed, one-use, plan/scope/failure-bound technical receipt valid for at most 15 minutes. It cannot waive scope, the campaign receipt, finite limits, revocation, kill, ledger qualification, or control-plane loss. |
| Structured fuzzing | Implemented with exact-pinned `fast-check@4.9.0`, deterministic seed/path/minimized value, and non-clearance semantics. The public CLI runs only fixed built-in property oracles under repository/loopback classifications; it does not yet invoke named target code or a service harness. |
| Existing bounty scanner gate | Plan/receipt/scope/nonce controller primitives are implemented and tested. Public `bounty scan run` is disabled pending migration to operator-statement ingress and a trusted controller-receipt boundary. |
| T4 evidence | A bounded standalone unauthenticated caller-claim normalizer and redacted renderer are implemented. They emit only `CLAIMED_*` verification/authorization labels, do not authenticate supplied receipts, prove replay independence, or establish evidence custody, and cannot promote a finding. The legacy finding/report path now applies the same conservative rule to provider triage, proof, remediation, and severity assertions: they remain open `CLAIMED_*` records and stay in proof scheduling. Adaptive-ledger observations still lack authenticated report integration. |
| Generic live execution | **Technically unavailable from the public adversarial CLI.** Named authority is retained, but dispatch refuses before nonce consumption or target I/O until a trusted transport/provider contract is enrolled. |
| Break Their Bones CLI | **Technically unavailable from the public adversarial CLI.** Named authority is retained, but dispatch refuses until controller-owned preflight, checkpointing, adaptive proposal, durable ledger, and trusted transport services are wired together. |
| Legacy process/network egress | **Route-specific.** Sealed repository T1, narrow sealed loopback T2, one exact bounded operator-directed HTTP-recon action, and fixed sealed authenticated HTTP campaigns are active through their controllers. Provider-runner, remote-gateway, transparency publication, every evidence-acquisition command, evidence-bundle import, database-conformance execution, bounty recon/scan/authz execution, generic live/L3 execution, and every OOB session command remain disabled. The loadable mitmproxy addon is removed. Static repository discovery, source sealing, offline planning/validation, historical inspection, and non-OOB cleanup are separate surfaces. |
| Additional fuzz providers | Coverage-guided Jazzer.js and schema-driven Schemathesis are researched future adapters, not shipped providers. Plan `generator` contracts exist, but the current CLI does not execute generator or adaptive plans. |

Known durability limits are fail-closed: the current prototype can consume a
receipt nonce before recording campaign start. Production must not address that
crash window by asking the operator to recertify unchanged authority; it must
atomically persist the accepted ingress statement, receipt/nonce reservation,
unique campaign lease, and first anchored ledger record. Until then, public
activation remains closed. Receipt-bound use of a caller-supplied ledger is
refused until a trusted controller can attest every journal write; a
non-cooperative in-process adapter can ignore cancellation until process exit;
the current callback providers are not uniformly raced against the campaign
deadline/kill signal; and detecting malicious ledger rollback requires anchoring
outside the caller-writable journal. Host-process preflight, checkpoint,
proposal, classification, scope, and sink callbacks are activation-only test
seams: they are not isolated I/O capabilities. Target labels are not
transport-derived, and the final scope decision is not yet an atomic one-use
authorize/intent lease consumed by dispatch. Public live activation therefore
requires isolated workers, hard cancellation, transport-attested identity, and
one atomic authorization-to-send transaction. Acquisition also needs a durable
stop marker that cannot fail open or be overwritten by completion, process-tree
termination, and non-reversible metadata summaries. Direct UNC/WebDAV and
Windows namespace-prefixed device/pipe CLI paths are refused. Offline commands
still treat operator-supplied local filesystem endpoints as trusted;
symlink/junction ancestors, mapped volumes, special aliases, embedded JSON
paths, and partial-commit races remain. Enrolled local-volume custody with
owner/ACL/reparse verification, handle-relative I/O, and transaction-wide
artifact locking is required for production. Operators must retain each returned
ledger-head digest outside the ledger directory. Live release additionally
requires one controller transaction/lease binding scope, revocation, preflight,
the prepared destination/effects, deadlines, and transport consumption. A chain
of sequential callback checks cannot eliminate their mutual TOCTOU window.

## Validated product requirements

- Targets may be a repository snapshot, a service booted from a disposable
  snapshot, staging, or production when the operator statement names that target
  and scope. The statement is the sole authorization fact; technical execution
  still requires a matching route.
- Named T2/service boots, controller-referenced credentials, and external
  services require no repeated authorization. A missing controller, credential
  material, or platform capability yields an authorized-but-unavailable gap.
- The implemented T2 route covers only one foreground Node/npm service and a
  controller-owned TCP probe on literal loopback inside each network-none
  container. It creates no authority or transport for another dependency,
  emulator, credential, external destination, or production system.
- Passive discovery and ordinary scoped scanning need no per-action decision.
  Crafted live exploitation follows the selected profile's operational-control
  cadence after the engagement statement has been accepted.
- A controller-sealed campaign receipt binds the engagement, target, candidate,
  strategy, full action
  sequence or deterministic action template, risk declaration, resource limits,
  receipt window, and plan SHA-256.
- A changed plan has a different digest and needs a new controller binding.
  Another operator decision is needed only when the profile requires it or the
  target/scope changes; it is never a repeat legal certification. Retries are
  new actions unless the envelope explicitly and finitely includes them.
- The agent may emit a `SCOPE_EXPANSION_REQUEST` when a promising target or
  technique lies outside current authority. A request is not permission and
  causes no target I/O.
- An operator-approved scope delta creates a new immutable scope revision linked to its
  predecessor; the old scope is never edited in place. Attack execution binds
  to the new revision digest.
- Receipt expiry, missing receipt, scope uncertainty, policy drift, operator
  stop, or a health threshold defaults to no dispatch.
- Proof is attack reproduction plus a valid control/oracle. A patch is optional.
  Remediation state never determines whether the original vulnerability existed.
- Live providers must accept credentials only by controller-owned reference and
  must redact reports. The generic plan JSON does not yet enforce a typed
  credential-reference vocabulary, so this is an open provider/release gate,
  not a guarantee of the current kernel.
- Availability-impacting, irreversible, persistence, lateral-movement, or
  sensitive-data actions are distinct risk classes. They can never inherit
  authority from a generic model/configuration `active_testing` bit. They may be
  included in an explicit operator campaign statement and finite envelope.
- The operator may explicitly select **Break Their Bones** mode, represented
  internally as `L3_MAXIMUM_AUTHORIZED`. One controller-sealed campaign receipt then lets
  the agent adapt and chain actions inside envelope-declared categories. It is not a
  scope bypass and does not suppress mandatory escalation triggers.
- The L3 envelope is a broad authorization predicate, not a pre-enumerated to-do
  list. Inside it, agents may select tactical subtargets, payloads, strategies,
  pivots, retries, and proof chains without further prompts, checkpoint their
  work, and return when the campaign budget is exhausted or its evidence goals
  are met.
- For a `READ_ONLY` L3 plan only, an explicit operator `BREAK_GLASS` decision may
  waive only an exact failed `target_health_monitoring` or
  `cleanup_or_rollback` readiness check. It is a narrow readiness exception, not
  an extreme-operation or maximum-intensity switch. It names the failed control,
  reason, short validity window, and compensating limits; it cannot waive scope,
  current campaign receipt, impact classification, revocation, finite budgets,
  append-only evidence custody, credential isolation, the operator kill switch,
  or the control-plane-loss failsafe. Its one-use signature is technical
  integrity, attribution, and replay protection, not another legal certification.

## Stack and commands

- Runtime: Node.js `>=20.0.0`, ECMAScript modules.
- Contracts: JSON Schema Draft 2020-12 through exact-pinned `ajv@8.20.0`.
- Core tests: `npm.cmd test -- --test-reporter=dot`.
- Focused tests: `node --test <test-files>`.
- Real narrow-T2 conformance: `npm.cmd run test:service-proof:docker` from a
  trusted checkout; ordinary tests do not auto-discover it.
- Lens lint: `npm.cmd run lint`.
- Generated topic registry check: `npm.cmd run gen` followed by a clean diff of
  generated files.

Production strategy providers are intended to be isolated tools rather than
ambient target dependencies. The first implementation uses exact-pinned
`fast-check@4.9.0`; only the public CLI's fixed property registry has a
controller-owned no-I/O boundary. The generic library function accepts a JS
property callback and therefore does not itself enforce locality or capability
isolation. Target-aware isolated workers, Jazzer.js coverage-guided fuzzing, and
Schemathesis schema-driven API testing are planned provider slices.

## Architecture

### One evidence model, many strategies

`strategy_id` describes how a hypothesis is exercised; `lens` and `topic`
describe what security claim the observation supports. Fuzzing, request replay,
fault injection, concurrency scheduling, state-machine exploration, known-CVE
verification, and a hand-authored exploit are strategies, not lenses.

Production target-aware adapters are intended to follow this lifecycle; the
current fixed property provider stops before target-code execution and the
current claim formatter stops before authentication/promotion:

```text
operator statement -> plan -> operational permit when required -> execute -> minimize -> independent replay
      -> authenticate evidence -> promote candidate -> report -> verify remediation
```

The current standalone normalizer records claimed target identity, oracle
results, digests, limits, and authorization-receipt shapes. Its output is explicitly
marked `UNAUTHENTICATED_CALLER_ASSERTIONS`. Production evidence must instead be
derived from authenticated action-bound observation records, an externally
anchored campaign identity, distinct replay execution, and evaluator provenance.

### Target tiers

| Tier | Target | Operational live control | Evidence meaning |
|---|---|---:|---|
| `T0` | Static snapshot | no | reasoned candidate |
| `T1` | Disposable repository mirror | no | executed target-code proof |
| `T2` | Disposable locally booted service | no, unless it reaches a live dependency | executed local-service proof |
| `T3` | Written but unexecuted recipe | no | unexecuted candidate |
| `T4` | Operator-authorized live target, including production | profile-specific permit | authenticated controller-permitted live-target proof; the current claim formatter cannot establish it |

`T4` is deliberately new rather than overloading historical `T2`. A live proof
cannot clear repository coverage and a repository proof cannot claim deployed
state.

### Authorization and operational-decision state machine

```text
DRAFT -> PLANNED -> AWAITING_OPERATOR_DECISION -> AUTHORIZED -> RUNNING
  |                   |              |                |          |
  |                   v              v                v          v
  |                DENIED         EXPIRED          REVOKED   SUCCEEDED/FAILED
  v
SCOPE_EXPANSION_REQUEST -> AWAITING_OPERATOR_STATEMENT -> NEW_SCOPE_REVISION
                                  |                         |
                                  v                         v
                               DENIED              REPLAN/ISSUE PERMIT
```

The provider may create `DRAFT` content. The controller canonicalizes and hashes
it into `PLANNED`. Only an operator statement received at agent/controller
ingress may create engagement authority; the controller seals that
statement and any profile-specific operational decision into `AUTHORIZED`. A
caller-supplied ledger can never stand in for authoritative receipt/nonce state,
and receipt-bound journaling/resume remains refused until activation is atomic.
A model-authored `--yes` or generic permission bit is not an operator statement.

The current CLI accepts the operator target/scope statement and
creates the technical receipt inside the controller. Caller-supplied signed
approval files and signing-authority keys are not accepted. The receipt's
canonical digest, nonce, controller identity, exact bindings, and durable
consumption provide integrity and replay protection. Local enrollment files fix
controller configuration and the adapter allowlist; they do not create
authority. Production provisioning must protect controller identity, monotonic
state, and ingress authentication. A future passkey/UI may authenticate that
ingress, but it does not create a separate signed-authorization path.

### Autonomy profiles

| Operator-facing profile | Internal value | Operational control after engagement authorization |
|---|---|---|
| Assisted | `L1_ASSISTED` | plan confirmation |
| Supervised | `L2_SUPERVISED` | phase checkpoints and escalation |
| Break Their Bones | `L3_MAXIMUM_AUTHORIZED` | one campaign envelope, then exception-based escalation |

Production `L3_MAXIMUM_AUTHORIZED` may be activated only when the accepted
operator statement covers the assets/action categories, the controller has
sealed its campaign receipt, and protected preflight services attest technical
scope enforcement, impact classification, finite
budgets, target health monitoring, append-only activity/evidence capture, an
operator kill switch, control-plane-loss failsafe, credential isolation, and
cleanup/rollback handling. The current runtime kernel accepts caller-supplied
provider decisions for testing and the public CLI therefore refuses L3.

For a read-only plan only, the operator can make an explicit, one-use
`BREAK_GLASS` decision. The controller seals a signed technical receipt for that
decision; it is not another legal certification. This is a narrow readiness
exception, not the Break Their Bones intensity switch. It may
name only `target_health_monitoring` or `cleanup_or_rollback`, and binds the
engagement, scope revision, exact plan digest, failed-control observations,
explicit waiver list, rationale, compensating limits, issue time, and expiry.
The controller contains a hardcoded allowlist of those two waivable controls and
a hardcoded denylist of invariants that no override can relax. Target scope
enforcement, the current campaign receipt, append-only evidence capture,
revocation/stop state, finite resource limits, credential isolation, an operable
kill switch, and the control-plane-loss failsafe remain non-waivable. The signed
failed-control status and observation digest must still match current preflight
evidence at every action.

Any future public L3 controller must own, anchor, and attest an append-only
campaign ledger; it is mandatory, not a caller-selectable option. The ledger
qualifies every proposal, scope decision, preflight result, send permit, dispatch
settlement, observation, checkpoint, stop, and cleanup/terminal outcome. A
caller-supplied journal is not sufficient authoritative campaign state because it cannot prove
atomic nonce consumption or authoritative writes.

Its campaign envelope contains applicability conditions, allowed actions,
decision criteria, escalation triggers, limits, and explicit prohibited effects.
The agent may choose tactical subtargets, payloads, and chains only where those
decision rules deterministically authorize them inside the exact named target.
The current schema does not express estate-wide CIDR, repository-set, or
cloud-account predicates; broader enrollment requires an explicit successor
contract rather than an inference from the target label.

Every concrete L3 action is snapshotted before asynchronous work. A fresh
technical scope decision/dispatch permit must bind the plan, campaign receipt,
scope revision, exact action digest,
controller-derived candidate-facts digest, resolved target, risk class, and a
complete effect classification. Only then does the campaign-envelope boundary
evaluate the action; only a successful boundary result can reach target I/O.
The receipt key is pinned to operator identity and any configured technical
role, risk-class, and autonomy-profile privileges. These bindings do not prove
underlying legal authority.

An out-of-envelope discovery pauses only the affected branch. The controller
queues a scope-expansion request and continues independent in-scope work; it
does not turn one blocked lead into a campaign-wide prompt. The following always
pause the affected branch regardless of this profile unless a stricter
explicit operator operational decision, sealed by the controller, is present:

- a target, technique, credential, data class, or impact outside the envelope;
- any scope expansion request;
- unexpected sensitive data or third-party access;
- target health degradation, lockout, resource exhaustion, or incident-response
  indicators;
- irreversible change, persistence, evidence destruction, or unplanned lateral
  movement;
- ambiguity in scope, authorization, cleanup, or controller health.

A mandatory escalation is not silently cleared by Break Their Bones mode. The
implemented read-only break-glass receipt can cover only its exact sealed
readiness failure; it cannot authorize an active high-risk escalation. Any
different or later condition pauses again.

Structured fuzzing stores the exact provider version, seed, shrink path,
minimized canonical JSON value, and digest. Interrupted runs, harness failures,
skip exhaustion, or oversized counterexamples are `INCONCLUSIVE`; a completed
finite sample is `NO_COUNTEREXAMPLE_OBSERVED`, never a security clearance. Pure
case generation performs no target I/O. Live cases must become bound actions and
pass through the same receipt, scope, effect, budget, and dispatch gates.

Non-live repository/local campaigns can be checkpointed and resumed when a
campaign ledger is supplied. Receipt-bound campaign journaling and resume are
intentionally refused until a protected controller atomically owns the nonce and
campaign lease; the journal is not accepted as authoritative controller state or
authorization evidence. The runtime
currently returns bounded observations, blocked branches, queued scope requests,
budget accounting, and ledger-chain metadata. Normalized
findings, minimized reproducers, negative controls, and cleanup verification are
separate records and are not yet composed into one terminal CLI handoff. "No
findings" must never be reported as "secure" when a budget, failed adapter,
unavailable control, or unresolved branch limited work.

The name is intentionally dramatic; serialized evidence should call it
"maximum authorized / semi-autonomous" and record the exact nonclaims and
boundaries.

### Scope expansion requests

An agent may ask for more authority but can never grant it. The request records:

- the base scope revision and digest;
- exact additions and removals for targets, paths, methods, strategy families,
  data classes, impact permissions, limits, and validity;
- why current scope blocks a specific candidate or coverage objective;
- discovery evidence collected without crossing the current boundary;
- expected risk, side effects, cleanup, and the action plan that would become
  eligible;
- the requester-suggested technical privilege for each part of the delta.

That field is explanatory only in the current request schema. A production
controller derives any configured minimum technical privilege from the canonical
delta and risk, takes the strongest privilege for mixed changes, and ignores any
weaker value selected by a provider.

The operator may deny, defer, narrow, or approve. A new explicit operator
statement is sufficient for an expansion; the controller seals an append-only
successor scope whose `previous_scope_sha256` equals the base scope digest. Any
operator edits produce a different delta digest and require the attack plan to be
rebound. One decision may cover both the successor scope and a fully disclosed
attack plan, but the two digests remain distinct and auditable. Any configured
scope-change role is a technical controller privilege, not an external
legal-proof requirement.

### Live action contract

A receipt-bound plan may contain a finite sequence with these purposes:

- `baseline` -- characterize the unmodified endpoint;
- `control` -- distinguish the hypothesized weakness from ordinary variation;
- `attack` -- exercise the vulnerability hypothesis;
- `verification` -- establish impact without unnecessary data collection;
- `cleanup` -- reverse a declared mutation and verify the result.

The production live-action contract requires every prepared action to be checked
immediately before dispatch against both the sealed engagement perimeter and
the receipt-bound plan. Redirects, discoveries, generated cases, and OOB callbacks
must not widen either boundary. The current generic live adapter is deliberately
unwired until one canonical prepared request, resolved destination/effects, and
transport consumption can share an atomic authorization lease. A strategy that
needs adaptive generation must seal a deterministic template, finite case
budget, generator version/digest, seed, and permitted insertion points before
the controller seals the receipt.

### Proof and remediation semantics

The proof oracle evaluates at least one attack observation and an appropriate
control. When the attack reproduces the security failure and the control
validates the harness, an authenticated controller may mark the finding
`CONFIRMED`, whether or not a patch exists. In the current release, no semantic
oracle authority is enrolled; provider-returned definitive decisions render as
`CLAIMED_*`, cannot suppress or reprioritize a finding, and remain scheduled for
proof. The public T1/T2 proof configurations likewise cannot authenticate their
provider-authored exit semantics. A complete narrow service lifecycle therefore
records `T2/UNPROVEN` until a hard-enrolled controller-owned oracle is available.

Remediation has a separate state:

- `NOT_ATTEMPTED`
- `FIX_VERIFIED`
- `FIX_FAILED`
- `REGRESSION_FAILED`

A failed or absent fix does not erase confirmed attack evidence. A successful
fix does not erase the historical finding; it changes its remediation status.

### Planned strategy families

The contract is open to arbitrary identifiers. The coverage roadmap includes
these families; only the fixed structured-property provider is currently
shipped through the public adversarial CLI:

- structured/property/state fuzzing;
- coverage-guided fuzzing and parser/memory-safety testing;
- authentication, session, authorization, and tenant-boundary replay;
- injection and interpreter-boundary testing;
- file, URL, redirect, SSRF, XXE, and OOB interaction testing;
- request routing, cache, proxy, desync, and protocol-semantic testing;
- workflow, payment, concurrency, idempotency, and race testing;
- cryptographic misuse and downgrade verification;
- dependency, artifact, build, CI/CD, and supply-chain verification;
- cloud/IaC, identity-policy, secret, and runtime-configuration validation;
- browser, mobile, native-memory, AI/agent, privacy, and observability abuse;
- custom hand-authored proofs when no generic adapter expresses the hypothesis.

This roadmap is coverage guidance, not a shipped provider registry or a claim
that a completed campaign proves absence.

## Project structure

- `schemas/` -- plan, authorization/permit receipt, observation, and finding contracts.
- `scripts/lib/` -- pure contract/receipt kernels, strategy registry, execution
  controllers, evidence normalization, and reporting.
- `scripts/` -- CLI orchestration only.
- `test/` -- contract, escape, lifecycle, and end-to-end tests.
- `docs/adr/` -- durable architectural decisions.
- `docs/design/` -- this living implementation specification.

## Code conventions

Keep policy decisions pure and return structured reasons. Perform I/O only after
the decision and re-check immediately before dispatch. Use exact canonical JSON
and SHA-256 bindings already established by the platform.

```js
const decision = authorizeLivePlan({ scope, plan, operatorAuthorization, now })
if (!decision.allowed) throw new Error(decision.reasons.join('; '))
await dispatch(decision.approvedAction)
```

Production providers must permit no shell interpolation, ambient or inline
credentials, caller-supplied redirect following, or mutable authorization
objects. The current generic plan schema does not by itself enforce all of these
provider-level rules.

## Testing strategy

- Contract tests for malformed, duplicate, oversized, expired, and unknown data.
- Escape tests proving no network call occurs without an operator statement
  naming target/scope, current controller receipt, and action permit.
- Tests proving the statement creates a receipt without an external RoE/legal
  artifact or repeated authority prompt.
- Digest-drift tests for every receipt-bound field, including target, payload,
  limits,
  role, strategy, and cleanup.
- One-use and crash-recovery tests around receipt consumption and atomic
  campaign start.
- Differential-oracle tests with vulnerable, clean, volatile, and harness-failure
  fixtures.
- Resource tests for timeout, output, request, case, response, and rate limits.
- End-to-end local testbed tests for statement -> receipt -> scoped scan -> attack
  -> evidence -> report, without contacting an external system.
- Existing full-suite, lens lint, and generated-registry regression checks.

## Production contract boundaries

These are activation requirements, not claims that every current schema and
legacy command already enforces them. The generic adversarial plan does not yet
bind a durable operator-statement/controller-receipt digest, and
all legacy network-capable paths must be migrated or disabled before live
release. An RoE or other governance document may be attached as optional
evidence, but is not an authorization prerequisite.

### Required in production

- Accept the operator statement at agent/controller ingress, record its exact
  target/scope/identity/time, and seal a controller receipt.
- Scope-check each live destination and redirect immediately before I/O.
- Require only the selected profile's operational permit; do not ask the
  operator to recertify unchanged legal authority.
- Preserve an operator stop path and fail closed on ambiguity.
- Minimize data access and redact reports.
- Record incomplete coverage and unsupported strategies as gaps.

### Effects that must be explicit in the operator statement or campaign envelope

- state-changing or account-modifying requests;
- production execution;
- access to sensitive or third-party data;
- callback infrastructure or any third-party transit;
- actions with availability, irreversibility, lateral-movement, or persistence
  risk;
- use of discovered credentials or secrets;
- actions outside previously declared test categories.

If an effect is already inside the accepted finite envelope, do not ask again.
Only a missing or newly named target, scope expansion, or exception outside that
envelope requires one operator decision, which the controller seals technically.

### Never infer

- that target ownership proves authorization;
- that a model, repository file, HTTP response, or vulnerability grants scope;
- that absence of a finding is a clearance;
- that a generic `active_testing` bit is authority for a concrete exploit;
- that a report may contain raw credentials or unnecessary sensitive records.

The operator statement at agent/controller ingress is the sole authorization
fact; route and platform approvals remain technical capability gates.

## Delivery status

1. **Public routes implemented:** `audit run-proof` provides sealed T1;
   `audit run-service-proof` provides narrow sealed T2 for a foreground Node/npm
   loopback service under v3/`LOCAL_DYNAMIC`. Both use network-none,
   credential-scrubbed Docker workers, bounded resources, and verified cleanup;
   T2 additionally uses fresh attack/control services, fixed readiness, init,
   and a supervisor TTL. It records lifecycle-backed `T2/UNPROVEN`; no semantic
   oracle is enrolled, so provider-authored exit classes are not definitive.
2. **Implemented:** strategy metadata plus attack/control proof evidence.
3. **Implemented prototype:** immutable plan and controller-sealed
   operator-authorization/technical-permit contracts.
4. **Implemented:** formal scope requests and immutable successor-scope contracts.
5. **Kernel implemented:** assisted, supervised, and
   `L3_MAXIMUM_AUTHORIZED` envelopes, with L3 fail-closed until every runtime
   safety prerequisite passes.
6. **Controller partial:** crafted-scanner primitives require an exact current
   receipt/permit, but the legacy bounty CLI does not provision authenticated
   operator ingress or that trust path.
   Public `audit run-provider`, `audit run-remote`, transparency publication,
   every evidence-acquisition command, audit evidence-bundle import and source sealing,
   database-conformance execution, `bounty recon run`, `bounty scan run`,
   `bounty authz run`, generic live/L3 execution, and every OOB session command
   are disabled; the loadable mitmproxy addon is
   removed pending
   migration. Bounded `http-recon`, fixed authenticated campaigns,
   static/offline planning and validation without imported evidence or source
   sealing, history, and non-OOB cleanup remain separate protocols.
7. **Integrated partial:** bounded evidence-claim normalization, redacted report
   draft, and conservative legacy finding/report provenance. Receipt
   authentication, custody, replay attestation, and adaptive-ledger integration
   remain open.
8. **Partial:** a fixed structured-property provider is implemented; target-aware,
   coverage-guided, and schema-driven providers remain open.
9. **Open:** expand beyond the narrow Node/npm loopback service and add reviewed
   live transports incrementally.

## Acceptance status

Demonstrated by tests:

- repository proof keeps vulnerability existence independent from remediation;
  until a semantic oracle receipt is authenticated, provider confirmation is
  rendered `CLAIMED_CONFIRMED` while remediation remains independently stated;
- hanging/noisy proof processes stop within sealed bounds;
- narrow T2 proves the port closed before boot, verifies pre/post-proof
  readiness, keeps attack/control in distinct fresh containers, omits raw
  output, and requires exact cleanup before reporting T2;
- a crafted live scan without an operator statement naming target/scope, current
  receipt, and permit performs zero target I/O;
- plan-byte drift invalidates the receipt;
- blocked actions produce inert formal scope requests, and only a controller-
  sealed successor scope based on a new operator decision changes eligibility;
- L3 action categories, tactical scope, effects, receipt, current scope,
  escalation triggers, and budgets are rechecked before dispatch;
- durable campaigns preserve checkpoints and settled observations, and never
  replay an ambiguous in-flight dispatch automatically;
- structured fuzz observations retain deterministic minimized replay data and
  never turn finite sampling into a security clearance;
- the standalone evidence-claim normalizer requires claimed attack/control plus
  a distinct claimed replay id, labels its provenance unauthenticated, omits
  locator/header/body fields, and rejects the sensitive marker values exercised
  by its tests; generic secret discovery and protected custody remain open.

Still required for the complete product outcome:

- enroll a reviewed live transport and externally protected controller service;
- expose L3 only after its preflight, checkpoint, adaptive proposal, ledger, and
  kill/health providers are deployed together;
- isolate transports in a worker/process for hard termination;
- bound and cancel every proposer, classifier, scope, revocation, preflight,
  checkpoint, and request-sink callback;
- bind a canonical prepared request to one atomic controller authorization
  lease and to an enrolled transport termination receipt;
- bind the accepted operator statement and controller-receipt digest into the
  plan and each controller lease; optional governance-document digests may
  supplement evidence but cannot be prerequisites;
- protect enrollment, nonce, revocation, and monotonic high-water state across
  processes with OS-enforced ownership or a separate controller service;
- make receipt nonce consumption controller-global across equivalent
  enrollments and resistant to controller-root rollback;
- enforce receipt expiry and revocation throughout transport execution, not
  only at pre-dispatch, including hard cancellation at the authorized deadline;
- store raw evidence in protected storage and join authenticated adaptive-ledger
  observations to T4 normalization and the legacy report;
- add target-aware, coverage-guided, and schema-driven fuzz providers;
- add separate lifecycle controllers for browsers, emulators, databases,
  registries, LocalStack, nested/multi-container stacks, credentials, and other
  service shapes not covered by narrow loopback T2;
- anchor campaign-ledger heads outside the ledger directory when hostile local
  rollback is in the threat model;
- enumerate every network-capable legacy command and either migrate it to the
  operator-statement/controller-receipt boundary or keep it disabled.

## Standards basis and nonclaim

The design follows the current [OWASP APTS Rules of Engagement
template](https://owasp.org/APTS/standard/appendix/Rules_of_Engagement_Template.html),
[Human Oversight](https://owasp.org/APTS/standard/3_Human_Oversight/),
[Graduated Autonomy](https://owasp.org/APTS/standard/4_Graduated_Autonomy/), and
[Safety Controls](https://owasp.org/APTS/standard/2_Safety_Controls/) principles;
OWASP WSTG's [testing model](https://wstg.owasp.org/latest/); and
[NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final). This is design
correspondence only. The implementation does not claim APTS, WSTG, NIST, or
CREST conformance.

## Open release gates

The live/L3 product path, broader T2 shapes, and disabled legacy active-testing
paths are blocked on the trusted services and migration work listed under
"Still required" above. Narrow v3 Node/npm loopback T2 is the implemented
exception; it does not relax those gates.
Passkey UI, multi-approver delegation, optional governance-document attachments,
a real-time dashboard, and non-HTTP transports remain future enhancements, not
legal-proof prerequisites.

The release-gate statement applies to supported command entrypoints. Selected
functions exported by `scripts/audit.mjs` remain internal conformance kernels
and accept injected dependencies; a same-process deep import is privileged
maintainer code, not a sandboxed or supported product API. Agents must not call
those exports. Production packaging must isolate or remove that surface and
enforce enrollment within the trusted controller service itself.
