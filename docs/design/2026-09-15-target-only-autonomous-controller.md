# Target-Only Autonomous Controller

**Status:** Approved for implementation
**Date:** 2026-09-15
**Product phrase:** Point. Click. Shoot.
**Operating doctrine:** Black-hat creativity. White-hat control, proof, cleanup, and repair.

## BORG directive

The campaign operates as one durable collective instead of isolated chat turns.
Perimeter, identity, API, data, client, exploit, forensics, and skeptic roles
share the same target graph and evidence-bound hypothesis frontier. Each round
fans out independent reasoning, merges only schema-valid candidates, challenges
the strongest claims, admits typed actions through the controller, and expands
the frontier from verified observations.

The collective does not stop at the first finding. It continues until every
discovered surface and applicable registered technique reaches a terminal
coverage state, the operator presses Stop, or a controller budget or technical
gap prevents further work. Provider prose never establishes proof; registered
attack/control oracles, independent observation, cleanup, and replay do.

## 1. North star

The runtime input is one target.

```text
https://xyz.com
postgres://db.xyz.com:5432/app
arn:aws:apigateway:us-east-1::/restapis/abc123
tcp://203.0.113.10:443
```

The operator pastes, selects, or double-clicks that target. Last Aperture resolves what it is, maps its exposed surface, asks a configured reasoning engine such as Codex or Claude to think adversarially, selects every applicable registered tool, verifies real impact, follows new evidence, cleans up, retests, and reports findings and blind spots.

There is no authorization form, profile selector, route picker, local-repository setup, JSON editing, or output-directory choice in the Point-Click-Shoot path. Engagement authority and effect limits are deployment policy owned by the controller. They are prerequisites of the environment, not steps in the run flow and not values a model or target can change.

## 2. What "find everything" means

No finite system can prove the absence of every unknown weakness. Last Aperture will make a stronger, auditable claim:

> For every declared or discovered in-policy surface, the controller ran every applicable capability registered in this build, or recorded the exact reason it could not.

The campaign maintains a versioned coverage denominator. New discoveries expand it. A quiet tool, a completed process, or a confident model response never reduces it. The final result is findings plus a machine-readable list of untested, unavailable, blocked, failed, and out-of-policy cells.

## 3. Experience

### Point

The operator supplies one opaque target descriptor. A deterministic resolver classifies and canonicalizes it into one or more exact identities without contacting it.

Initial target families are:

- HTTPS website or API origin;
- database endpoint or managed-database resource;
- network service endpoint;
- cloud resource identifier;
- application or authenticated browser origin;
- binary, process, device, or firmware target supplied through a registered remote worker.

Unsupported or ambiguous descriptors fail with candidate interpretations. The resolver never guesses between identities that would change where requests go.

### Click

The UI renders the canonical target and one action: **Unleash**. Double-clicking a saved target performs the same action. The controller chooses the output location, capability set, reasoning provider, concurrency, and evidence store from controller-owned configuration.

### Shoot

The campaign starts immediately and shows:

- discovered assets and trust relationships;
- the current hypothesis frontier;
- queued, running, completed, waiting, and unavailable tools;
- proof strength for every finding;
- the selected action-risk profile, rationale, expected defender exposure, and
  residual uncertainty before dispatch;
- cleanup and retest state;
- durable Pause and owner-bound Resume controls that revalidate current authority;
- bounded local rollback and a permanent Stop kill switch;
- exact coverage gaps;
- Markdown, JSON, and SARIF results bound to one verified snapshot.

## 4. Adversarial campaign loop

The controller runs a repeated observe-think-act-verify loop:

1. **Resolve** the supplied descriptor to an exact target identity.
2. **Inventory** all immediately observable surfaces with deterministic collectors.
3. **Hypothesize** with one or more provider-neutral reasoning agents. Agents receive bounded evidence packets and generate competing attack hypotheses.
4. **Propose** typed actions using only capabilities in the frozen tool registry.
5. **Assess** likely defender exposure and operational impact with the versioned action-risk catalog and frozen generic detection-pattern model, recording stable matched pattern IDs, the selected profile, and residual uncertainty.
6. **Admit** actions through controller checks for exact target binding, deployment policy, effect budget, profile limits, prerequisites, rate, concurrency, deadline, and any exact receipt-bound confirmation.
7. **Execute** admitted actions in isolated workers with fixed entry points and structured arguments.
8. **Verify** the claimed security invariant independently of the proposing model.
9. **Expand** the target graph and hypothesis frontier from schema-valid discoveries.
10. **Chain** verified preconditions into new hypotheses and revisit earlier assumptions when evidence changes.
11. **Clean up** every mutation and verify the cleanup result.
12. **Retest** repaired targets with ordinary regression checks and the security replay.
13. **Stop** when the frontier is quiescent, a controller limit is reached, the operator stops the run, or all remaining work has an explicit gap state.

Models can be creative about hypotheses and ordering. They cannot add tools, construct shell commands, change target identity, alter effect policy, declare their own output verified, or erase coverage obligations.

## 5. Core contracts

### 5.1 Target descriptor

Public input:

```js
{ target: "https://xyz.com" }
```

Normalized record:

```js
{
  schema_version: "1.0.0",
  kind: "last-aperture/target",
  target_id: "target:sha256:...",
  family: "https",
  canonical_locator: "https://xyz.com/",
  identities: [
    { kind: "origin", value: "https://xyz.com", confidence: "EXACT" }
  ],
  supplied_sha256: "..."
}
```

Credentials are controller-managed references attached after resolution. Secret values never enter renderer state, model packets, mission records, reports, or diagnostic exports.

### 5.2 Campaign plan

The deterministic planner freezes:

- target digest;
- deployment-policy digest;
- deployment-policy validity window and revocation-check contract;
- tool-registry version and digest;
- reasoning-provider protocol version;
- immediately applicable collectors;
- known unavailable capabilities;
- initial coverage obligations;
- budgets and deadlines;
- campaign-plan digest.

Preview, execution, recovery, and reporting use the same digest. The operator does not edit this plan. The controller revalidates the external policy before every dispatch and after recovery. Expiry or revocation prevents new work and moves the campaign into cleanup and durable stop handling; a frozen digest cannot preserve withdrawn authority.

### 5.3 Target graph

Nodes represent origins, hosts, ports, services, APIs, databases, identities, data stores, cloud resources, binaries, processes, devices, and dependencies. Edges represent observed relationships such as serves, calls, trusts, authenticates-to, reads, writes, loads, exposes, and depends-on.

Every node and edge records whether it was supplied, deterministically observed, model-hypothesized, or independently verified. Only observations admitted by the controller can create executable coverage work. An off-target discovery remains a recorded boundary event and is not contacted.

### 5.4 Hypothesis

A reasoning provider returns schema-valid hypotheses:

- evidence references;
- proposed invariant to test;
- required preconditions;
- one registered technique or collector ID;
- structured parameters from that technique's schema;
- expected observation;
- confidence and competing explanations;
- suggested next actions if confirmed or refuted.

Hypotheses are inert data until admitted by the controller.

### 5.5 Coverage obligation

Every target-graph surface crossed with every applicable technique family ends in one of:

- `TESTED_NO_FINDING`;
- `FINDING_CANDIDATE`;
- `EXPLOIT_VERIFIED`;
- `PARTIAL`;
- `INCONCLUSIVE`;
- `WAITING_FOR_MATERIAL`;
- `UNAVAILABLE`;
- `UNSUPPORTED`;
- `BLOCKED_BY_POLICY`;
- `FAILED_CLOSED`;
- `STOPPED`.

The UI and exports report the denominator revision and counts for every state. Pagination cannot imply omitted rows do not exist.

### 5.6 Exploit proof

A verified exploit requires:

- exact target and runtime identity;
- campaign plan and execution-permit digests;
- technique and preconditions;
- a baseline or negative control;
- the bounded test action;
- the security invariant;
- independently observed invariant failure;
- timestamps and evidence hashes;
- a replay recipe;
- cleanup obligation identifier;
- reproduction state and competing explanations.

Proof progresses through `CANDIDATE`, `REPRODUCED`, `CONTROLLER_OBSERVED`, `AUTHENTICATED_VERIFIED`, and `FIXED_RETESTED`. `AUTHENTICATED_VERIFIED` requires a registered attack/control predicate plus a separately enrolled verifier whose identity and signed result validate against an externally pinned trust root. A reasoning provider cannot enroll or impersonate that verifier. Until such an authority is implemented and enrolled, findings remain at the strongest lower state their evidence supports. `FIXED_RETESTED` additionally requires an authenticated negative security replay and an ordinary regression result against the repaired target revision.

Proof and cleanup are independent dimensions. A verified invariant violation remains a verified finding when cleanup fails; the report elevates the unresolved cleanup residue as a separate critical campaign condition. Every mutation records `NOT_REQUIRED`, `PENDING`, `VERIFIED`, `FAILED`, or `UNCERTAIN` cleanup status. Both `VERIFIED` and the positive `NOT_REQUIRED` decision require a separate authenticated receipt bound to the exact proof receipt and cleanup evidence manifest.

Each exploit family has a versioned proof oracle. For example, an exfiltration proof moves a controller-generated canary to an authorized sink while its negative control remains absent; an XSS proof executes a unique sentinel in an isolated browser while the encoded control does not; an authorization-bypass proof records an attack/control identity differential for the same object and operation.

### 5.7 Vulnerability ledger

The current HTTPS slice defines a fail-closed target-bound vulnerability-record contract for later exploit-oracle routes. It binds CWE, reviewed CVSS, authenticated proof manifests, and cleanup tied to the exact proof receipt and ordered after the observation. Known CVE mappings require an authenticated exact product/version association to the canonical CVE record. A novel issue can be represented as `CVE_CANDIDATE` only after a separate authenticated review binds every disclosure and affected-product claim to proof-receipt evidence; the controller never invents a CVE identifier. The shipped controller does not yet emit these records. Other target families fail closed until they have exact canonicalizers and plan-target bindings. Existing finding contracts remain unchanged and can be referenced from a future campaign envelope.

## 6. Model and tool architecture

### Campaign brain

Codex, Claude, or another compatible provider plugs into one versioned protocol. The controller sends bounded, redacted evidence packets and accepts only JSON that validates against the campaign-proposal schema. Provider receipts bind packet and response digests and may carry declared attribution; they do not authenticate producer identity or semantic truth without an externally pinned verifier key.

Multiple agents may take attacker roles such as perimeter mapper, identity attacker, API abuser, data-layer attacker, reverse engineer, cloud attacker, and skeptic. A separate verification role tries to disprove each claimed exploit before controller admission.

### Tool registry

Every executable capability declares:

- supported target families;
- input and output schemas;
- fixed entry point and structured arguments;
- discovery and effect classes;
- rate, concurrency, resource, and timeout bounds;
- target-binding check;
- success and proof semantics;
- cleanup contract;
- recovery mode.

The model references a tool ID and typed parameters. The controller builds the invocation. No provider-generated executable, package installation, shell string, URL redirect decision, or credential value reaches a worker.

### Scheduler

The scheduler uses durable risk preflights, pre-dispatch permits, and attempt states. Independent routes continue after waiting conditions and recoverable route failures. Evidence-integrity failures, policy revocation, ambiguous mutation delivery, or uncertain cleanup halt new dispatch and move the run into reconciliation or cleanup. Restart recovery never repeats an ambiguous action automatically. Pause closes new dispatch while in-flight work settles; Resume requires the exclusive owner. Rollback cancels eligible local future work and inert proposals. Stop prevents new dispatch and drives outstanding cleanup before terminal projection.

## 7. Trust boundaries

| Boundary | Attacker's opportunity | Controller requirement |
|---|---|---|
| Target descriptor | ambiguity, parser abuse, rebinding | strict canonicalization, exact identity, bounded resolution |
| Target response | prompt injection, malicious files, redirects, oversized data | inert evidence, limits, redirect revalidation, isolated parsers |
| Reasoning provider | fabricated proof, scope drift, tool injection, data leakage | redaction, schema validation, no ambient credentials, proposals only |
| Tool worker | command injection, duplicate effects, host compromise | fixed invocations, isolation, permit binding, resource limits, cleanup |
| Evidence store | tampering, rollback, mixed revisions, secret retention | append-only hash chain, external anchors, snapshot-bound reads, redaction |
| Desktop renderer | arbitrary filesystem/process access | sandbox, context isolation, restrictive CSP, allowlisted sender-validated IPC |

Controller-owned deployment policy defines target ownership, allowed effects,
excluded networks, validity, revocation, target environment, risk tolerance, and
action-risk profile for the environment. The runtime target field and models
cannot modify it. Contextual `AUTO` selection records the reason for its choice;
scores are uncalibrated relative exposure, not alert probability. This boundary
does not add a Point-Click-Shoot screen.

## 8. Architecture

The existing engagement controller, route registry, durable permits, stop/recovery logic, and append-only ledgers remain authoritative. Add:

1. **Universal target resolver** — pure classification and canonicalization with adapter dispatch.
2. **Campaign planner** — freezes target, registry, provider protocol, policy, and initial coverage.
3. **Campaign brain protocol** — provider-neutral Codex/Claude hypothesis and action proposals.
4. **Target graph and frontier** — versioned discoveries, hypotheses, obligations, and gap accounting.
5. **Action-risk model** — versioned defender-control exposure and impact
   assessment with hard profile limits and exact confirmation receipts.
6. **Evidence verifier** — converts observations into proof levels without trusting provider prose.
7. **Snapshot API** — verified, paginated views of progress, graph, findings,
   gaps, detection context, controls, cleanup, and timeline.
8. **Cockpit** — target field and Unleash action over a sandboxed local desktop boundary.

## 9. Delivery slices

### Slice 1 — Target-only HTTPS/API campaign

- accept only `unleash <https-target>` at runtime;
- choose an app-owned output directory automatically;
- resolve and bind the exact origin;
- freeze a complete route/capability inventory and known gaps;
- execute the existing bounded HTTPS reconnaissance collector;
- assess and record its action-risk before dispatch, blocking on hard profile
  limits or required exact confirmation;
- create a sealed evidence packet for a provider-neutral reasoning adapter;
- accept schema-valid, evidence-linked hypotheses as candidates only;
- expose status, detection context, Pause, rollback, Stop, findings, and gaps
  from one snapshot;
- ship a synthetic remote HTTP target for deterministic end-to-end tests.

This is the first remotely useful shot. It does not depend on a local repository.

### Slice 2 — Adversarial web campaign

- add deterministic crawling and surface discovery;
- admit model-selected registered web/API techniques;
- verify findings through controls, independent observation, cleanup, and replay;
- add authenticated sessions through controller-owned credential references;
- add discovery-driven graph expansion and multi-agent challenge/review.

### Slice 3 — Cockpit

- paste, choose recent target, or double-click target;
- Unleash, live progress, detection context, Pause/Resume, rollback, Stop,
  findings, gaps, evidence, and SARIF;
- zero terminal, JSON, route, profile, output-path, or provider setup in the run flow;
- packaged Windows smoke test from the exact release commit.

### Slice 4 — Any target

- database endpoints and managed database resources;
- cloud resource identifiers and estates;
- network services;
- binary/process/device targets through enrolled workers;
- repair and replay loops;
- remote/team operation after identity, tenant, retention, and worker-isolation gates pass.

## 10. Acceptance criteria

- Runtime accepts one target and one action.
- The same campaign-plan digest binds preview, execution, recovery, and report.
- Every registered route has an explicit disposition for the resolved target.
- Provider output cannot change target, policy, tool registry, budget, evidence, or proof state directly.
- Every verified exploit satisfies the proof contract.
- Every verified vulnerability has a CWE/CVSS record and either a trusted existing-CVE mapping or an explicitly unassigned CVE-candidate state.
- Every mutation has a cleanup obligation before dispatch and a separately reported cleanup result after execution.
- Policy expiry or revocation prevents new dispatch without erasing retained evidence or cleanup obligations.
- Every target dispatch has one immutable action-risk receipt; required
  confirmation binds the exact action, assessment, and receipt, while profile
  constraint violations stay blocked.
- Restart does not duplicate an in-flight or completed effect.
- Pause prevents new dispatch without losing recoverable state. Rollback makes
  no target-side reversal claim. Stop prevents new dispatch and preserves durable evidence.
- Final output enumerates findings and every coverage gap against one verified snapshot.
- Existing conformance and release gates remain green.

## 11. Initial implementation boundary

The first implementation adds the universal target and campaign-plan contracts, a target-only `engage unleash` entry point for HTTPS/API targets, complete route disposition output, automatic run storage, and a provider-neutral proposal schema. It reuses existing bounded HTTPS reconnaissance and does not grant model output direct execution authority. Subsequent slices expand registered techniques and proof verification behind the same target-only interaction.
