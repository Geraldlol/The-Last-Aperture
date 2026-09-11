# ADR 0020: Operator-approved adversarial validation

- Status: Accepted
- Date: 2026-09-03
- Owners: The Last Aperture platform
- Supersedes in policy: ADR 0019's approval-free active-request decision;
  migration of every legacy network-capable path is a release requirement
- Amends: the proof-status semantics of the 2026-08-02 `TEST_EXECUTION` design
- Amended by: ADR 0021 makes the authenticated operator target/scope statement
  the sole authorization primitive and removes caller-signed authority paths

## Context

Before this hardening decision, the platform could inventory a repository, run
an authored repository test in a disposable mirror, and execute a narrow live
bounty scanner. Those capabilities did not form a coherent penetration-testing
lifecycle and the public active routes are now fail-closed pending migration:

- the mirror runner calls a reproduced but unfixed vulnerability `UNPROVEN`;
- the live scanner can send crafted payloads from a bare campaign flag without
  a controller receipt/permit bound to the concrete attack;
- scan findings are not normalized into the main evidence/report model;
- fuzzing and other dynamic techniques have no common strategy contract;
- local dynamic and generalized live proof tiers are absent.

The product requirement is broader: an AI provider should be able to propose any
useful white-hat validation technique against an authorized target. At
authenticated controller ingress, the operator's explicit statement authorizing
the named target and scope is accepted as the controller's authorization fact;
the controller does not require an external RoE, ownership, or legal-proof
artifact or ask the operator to certify unchanged authority again. The statement
is not independent proof of underlying legal authority, for which the operator
remains accountable. The selected autonomy profile determines later operational
checkpoints for live attacks; those checkpoints do not re-establish authority.

## Decision

Introduce an adversarial-validation control plane shared by repository, local,
and live strategies.

1. Vulnerability lenses remain the claim taxonomy. Fuzzing, replay, fault
   injection, concurrency, OOB, and hand-authored exploits are strategies that
   produce observations for those lenses.
2. Repository `T1` proof uses a disposable mirror at the kernel/test layer. Its
   public command remains disabled until the worker also provides enforced
   network denial, credential scrubbing, and descendant termination. `T2` is a
   locally booted disposable target. New `T4` denotes an authorized live target.
3. A vulnerability is `CONFIRMED` when an attack is reproduced under a valid
   authenticated oracle/control. Patch availability is irrelevant to existence
   proof. Until that controller authority exists, provider decisions are
   `CLAIMED_*`, cannot suppress or lower a finding, and remain proof obligations.
4. Remediation is recorded separately as not attempted, fix verified, fix
   failed, or regression failed.
5. An authenticated, explicit operator statement creates authority for its named
   target and campaign scope. A generic model/configuration `active_testing` bit
   is not such a statement. The controller canonicalizes and seals the statement
   into a current technical receipt bound to the plan or finite envelope.
6. The receipt is consumed durably before network dispatch. Drift, expiry,
   revocation, reuse outside an explicit finite retry budget, or scope uncertainty
   fails closed. Its controller seal, digest, nonce, and identity binding provide
   integrity, attribution, replay resistance, and technical
   role/risk/profile enforcement; they do not independently prove legal
   authority. No caller-signed artifact is required to create authority.
7. Passive discovery belongs inside a current sealed perimeter. The public
   release enables one exact bounded `http-recon go` action and fixed sealed
   authenticated campaigns through their dedicated controllers. Broader or
   adaptive target I/O remains a release gate, not an authorization model.
8. Production live execution must retain the scope kernel and add typed
   credential references, redirect refusal/re-authorization, rate controls,
   mutation/rollback controls, OOB accounting, redaction, protected evidence,
   controller-global rollback-resistant nonce/lease state, continuous
   approval-expiry and revocation enforcement, and an externally anchored
   append-only audit trail. The current generic plan schema and local journal do
   not yet establish all of those guarantees.
9. Providers may create `SCOPE_EXPANSION_REQUEST` records. These are inert
   proposals bound to the current scope digest. A valid operator decision creates
   an append-only successor scope; no provider or target-derived content edits
   current authority. The attack is replanned against the successor digest.
10. One explicit operator decision may cover both a scope delta and an already
    disclosed attack plan. The controller seals the decision and keeps the scope
    and attack digests separate so one cannot be substituted for the other. Any
    configured scope-change role is a technical privilege policy, not a demand
    for external legal-proof material.
11. Expose three autonomy profiles. After the engagement authorization,
    `L1_ASSISTED` requires operational confirmation per live exploit plan;
    `L2_SUPERVISED` permits chaining within a confirmed phase;
    `L3_MAXIMUM_AUTHORIZED`, branded **Break Their Bones**, permits adaptive
    complete attack chains within one controller-sealed campaign envelope. These
    controls do not recertify the operator's underlying authority. Scope changes,
    irreversible actions, unexpected data access, health degradation, and any
    ambiguity remain mandatory escalation points at every level.
12. The maximum-authority profile fails closed unless scope, kill switch,
    control-plane-loss failsafe, health monitoring, impact limits, evidence
    capture, credential isolation, and cleanup controls pass preflight.
13. The implemented `BREAK_GLASS` artifact is a narrow read-only readiness
    exception, not an extreme-operation or maximum-intensity switch. After an
    explicit operator exception decision, the controller seals a signed, one-use
    receipt that may waive only the exact failed
    `target_health_monitoring` or `cleanup_or_rollback` check. The waiver is plan-
    and scope-bound, valid for at most 15 minutes, requires a `break_glass`
    technical privilege, records compensating limits, and cannot waive scope enforcement,
    the current campaign receipt, append-only evidence capture, revocation/stop state,
    finite budgets, credential isolation, the operator kill switch, or the
    control-plane-loss failsafe. Its signed failure status and observation digest
    must match current preflight evidence. There is no magic string, environment
    variable, or model-settable flag that disables preflight globally. Its
    signature is an integrity, attribution, and replay control, not another legal
    certification.
14. Before L3 target I/O, the controller snapshots the action and requires a
    fresh technical scope decision and dispatch permit bound to its digest,
    controller-derived candidate facts, resolved target, risk class, effect
    classification, current campaign receipt, and scope revision. Agent-supplied
    candidate claims cannot satisfy this gate.
15. A production controller derives any configured minimum technical scope-
    change privilege from the canonical delta and risk. It never trusts a
    provider-selected `required_approver_role`; mixed target, data, impact,
    credential, and limit deltas inherit the strongest configured privilege.

The full specification is
`docs/design/2026-09-03-adversarial-validation-engine.md`.

Implementation note (2026-09-04): the contracts, receipt/scope/break-glass
kernels, graduated runtime, local hash-chained journal, fixed built-in property
provider, crafted-scanner gate, bounded proof engine, and standalone
unauthenticated evidence-claim renderer are implemented. Manual triage, proof,
remediation, severity, and lifecycle decisions now carry conservative
unauthenticated semantics through Markdown and SARIF. The property provider
does not yet invoke target code, the public proof command lacks a qualifying
sandbox, and the evidence normalizer does not authenticate its inputs. Generic
live dispatch and the L3 public CLI remain intentionally unavailable until a
trusted transport and controller-owned preflight/checkpoint/adaptive/ledger
services are deployed together. This ADR authorizes that architecture; it does
not claim the remaining product wiring exists. Separately, one exact bounded
operator-directed HTTP-recon action and fixed sealed authenticated HTTP
campaigns now execute through their protocol-specific controllers; they are not
generic L3 activation.

Receipt-bound use of the caller-supplied campaign journal is also refused: the
journal cannot prove nonce consumption or authoritative writes. Any public L3
activation must require a trusted controller-owned append-only ledger; intensity
cannot make it optional. The controller must atomically consume the nonce, create
and attest one campaign lease, and qualify every proposal, scope decision,
preflight result, send permit, dispatch settlement, observation, checkpoint,
stop, and cleanup/terminal outcome in its anchored monotonic state. Each
asynchronous proposer, classifier, scope, preflight, and checkpoint call also
needs a durable write-ahead intent and idempotency key, a controller-owned
deadline/kill race, and an atomic bounded result append before the result can
authorize a later action. A restart that can only infer a safe stop does not
qualify the exact callback result and therefore is not sufficient for public
L3 activation. Public
`audit run-proof`, `audit run-provider`, `audit
run-remote`, transparency publication, every evidence-acquisition command,
audit evidence-bundle import and source sealing, database-conformance execution,
`bounty recon run`, `bounty scan run`, `bounty authz run`, and every OOB session command are
disabled pending the required sandbox, enrollment, or authenticated
operator-ingress/controller-receipt
migration. Static/offline planning and validation without imported evidence or
source sealing, historical inspection, non-OOB cleanup, bounded `http-recon`,
and fixed authenticated campaigns remain separate protocols.

The former mitmproxy addon is removed entirely. An addon-level exception is not
a process-level fail-closed guarantee because the proxy may continue without the
addon; only pure offline conformance helpers remain.

## Consequences

The AI can be inventive about how to validate a hypothesis without possessing
authority to execute its own proposal. The authenticated operator statement
creates engagement authority once. For L1/L2, operators then make the selected
profile's operational plan/phase decisions. For L3, the controller seals the
target predicate, allowed operations/categories/strategies, decision rules,
risks, limits, prohibited effects, checkpoints, escalation triggers, and cleanup
policy into one campaign receipt; individual tactical payloads are chosen later
inside that envelope without another legal certification.
Reports already distinguish claimed vulnerability existence from claimed fix
verification; unqualified authenticated states remain unavailable until the
open evidence-attestation gates are implemented.

The same queue can now carry a request for additional authority. This makes an
out-of-scope lead actionable without treating discovery as permission. It also
adds a scope-version ledger and delegation checks to the control plane.

The maximum-authority profile reduces per-action ceremony for a fully authorized
engagement, at the cost of stronger preflight, monitoring, audit, and fail-closed
pause requirements. It is designed to be broad inside its envelope and to deny
anything outside it; public live activation remains fail-closed until the
controller services in the implementation note exist.

As network-capable paths are migrated, profile-specific operational controls
replace ADR 0019's "free per request" behavior for crafted payloads. They do not
repeat the engagement-authority certification. Unmigrated active paths stay
disabled. One envelope may cover a finite deterministic batch, so it need not
become a click per fuzz case. Passive recon and ordinary observations are
unaffected.

Where the controller cryptographically signs a technical receipt, the signature
authenticates the controller seal and protects the integrity of the operator
statement, plan, scope, and controller state. It does not independently prove
legal sufficiency, target ownership, operator competence, or that policy remains
unrevoked. The controller accepts the authenticated operator statement as its
sole authorization fact. Underlying authority remains the operator's
engagement-governance obligation and an explicit report nonclaim.

## Alternatives considered

### Treat a generic campaign flag as operator authorization

Rejected. A model-authored or caller-configured boolean is not an authenticated
operator statement and cannot create a campaign receipt. A real operator
statement may authorize a bounded campaign envelope, including L3.

### Require a prompt or `--yes`

Rejected when the prompt or flag can be supplied by the proposing automation.
Authenticated operator ingress is sufficient; the controller records the exact
statement and seals immutable technical receipts without demanding an external
legal-proof artifact or repeated certification.

### Literal free-reign execution

Rejected. "Full authority" does not make target identity, third-party ownership,
service health, evidence custody, or operator revocation irrelevant. A sealed
high-autonomy envelope provides the desired attack freedom without turning a
model mistake into unbounded network authority.

### Add a universal preflight bypass flag

Rejected. A hardcoded boolean or password is indistinguishable from a reusable
authorization bypass once automation can set or leak it. A signed break-glass
artifact provides the required override while keeping its target, plan, waived
controls, time window, and operator attributable.

### Build one universal fuzzer

Rejected. Fuzzing is an input-generation technique, not a vulnerability taxonomy,
and cannot express authorization, workflow, cryptographic, supply-chain, or many
deployed-state hypotheses on its own.

### Require a patch before confirming a finding

Rejected. It conflates vulnerability existence with remediation completion and
systematically suppresses the severity of real, reproducible unfixed defects.

## Standards correspondence

The decision is informed by OWASP APTS Human Oversight and Rules of Engagement
guidance, OWASP WSTG's separation of broad automated scanning from targeted
verification, and NIST SP 800-115. No conformance claim is made.
