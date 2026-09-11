# The Last Aperture: CTO brief

## What it does

The Last Aperture is an evidence-first security assessment system for codebases and
operator-authorized runtime targets. It inventories a target, selects the
security lenses that actually apply, traces suspected weaknesses to reachable
security impact, challenges false positives, combines proven weaknesses into
attack chains, and records both findings and coverage gaps. A keyword or scanner
alert is only a lead; confirmation requires a reproducible attack, a valid
control/oracle, and evidence bound to the target and test plan.

At agent/controller ingress, the operator statement naming target and scope is
the sole authorization fact for every capability it names, including T2/service
boots, controller-referenced credentials, and named external services. If
target/scope is supplied, proceed; ask once only when it is missing. No repeated
consent, RoE, ownership, or legal check is required. A T1-only statement remains
narrow, and the operator is accountable. See ADR 0023.

The new adversarial controller contracts and runtime kernel extend that workflow
from source review toward adversarial validation. The repository proof engine
ships public `run-proof` for sealed T1 execution and `run-service-proof` for
narrow loopback T2 execution. Both use an external worker configuration binding
an immutable local Docker image and dependency manifests. Attack and control
receive separate fresh non-root containers from the same sealed source, with
no network or host mounts, minimal environment, resource/output limits, and
verified teardown. T1 does not boot services. T2 permits one foreground Node/npm
service and its fixed loopback probe inside each network-none container; it
does not provide live credentials, external dependencies, or arbitrary service
stacks. See the [repository proof routes](../README.md#authorized-repository-t1-proof).

T2 has one cumulative monotonic deadline per attack or control session across setup,
execution, transfer, and teardown, with supervisor TTL/init bounding descendants.
A durable v7 attempt lease records both exact container names before Docker is
contacted. Interrupted work can recover expired leases after verified cleanup
or commit an already captured receipt without replay; a process-owned lock
prevents takeover while the original controller remains alive. These receipts
record execution and cleanup facts, hashes, and counts, without raw target
output. T2 remains `UNPROVEN` until a controller-authenticated semantic oracle is
enrolled; successful service execution alone cannot establish `CONFIRMED` or
`FIX_VERIFIED`. See [ADR 0024](adr/0024-public-sealed-t2-loopback-service-proof.md).

The public adversarial CLI also supports `go`: an exact HTTPS
target runs one bounded reconnaissance action, while a local directory enters
the static repository-audit controller. Separately, the authenticated-HTTP CLI
runs only fixed sealed campaigns and records every attempted action and outcome
in its durable campaign ledger. Generic adversarial `execute` can currently use
only fixed, no-target-I/O property oracles. For any future crafted live plan, the
controller must cryptographically seal the accepted operator statement into a
technical campaign receipt binding target, scope revision, strategy, actions or
finite envelope, risk, limits, controls, cleanup expectations, and operator
identity. The receipt supplies integrity, attribution, scope binding, and replay
protection, not independent legal proof. Its validity is capped by the plan's
wall-time budget plus a fixed 15-minute start grace (and can never exceed 24
hours 15 minutes).
Its tests recheck scope and stop on drift, expiry, revocation, ambiguous effects,
health degradation, or control-plane loss. Generic live dispatch is not publicly
enabled because those checks still need one protected atomic controller lease
rather than sequential callbacks.

Vulnerability proof and remediation are independent. A reproduced vulnerability
is reported even when no patch exists; a later fix changes remediation status
without erasing the historical finding. The current public-evidence component
can redact and normalize caller-supplied proof claims, but it does not yet
authenticate receipts, prove replay independence, or establish evidence
custody. Manual providers likewise cannot authenticate their own semantic
decisions: confirmation, disproof, non-reproduction, drop, merge, remediation,
and severity-change assertions are controller-stamped as unauthenticated,
rendered as `CLAIMED_*`, cannot suppress a finding or lower report/SARIF
priority, and do not remove it from the proof queue. The unqualified lifecycle
state `fixed` is reserved for a future authenticated semantic-negative oracle;
this release emits `claimed-fixed` for comparable-coverage absence. Those
authentication guarantees remain a release gate for live findings. Pack
evolution no longer erases every comparison: when repository root and Rules of
Engagement match, an unchanged lens digest and owned-topic contract can remain
individually comparable while the whole run is marked only partially comparable,
but only when the shared schema/harness/adapter contract digest also matches.

## Adversarial runtime-kernel modes

| Mode | Agent freedom | Human control |
|---|---|---|
| `L1_ASSISTED` | Executes an exact sealed plan. | Technical plan acknowledgement selected by the profile; not another authorization. |
| `L2_SUPERVISED` | Executes an acknowledged live sequence. | Technical phase checkpoints and mandatory escalations; no renewed authority check. |
| `L3_MAXIMUM_AUTHORIZED` / **Break Their Bones** | The implemented kernel can validate and orchestrate tactical subtargets, payloads, retries, pivots, and chains supplied by a future enrolled proposer inside one controller-sealed finite campaign envelope; it can continue independent branches and queue inert scope requests. It does not itself invent tactics today. | One campaign directive, repeated technical scope/safety checks, periodic checkpoints, kill switch, finite budgets, and exception-based escalation. Public live activation is still blocked on the trusted controller services listed below. |

The L3 contract is deliberately broad inside the controller-sealed envelope and denies
out-of-envelope actions. An agent may create a formal request for additional
targets, techniques, data classes, impact, time, or limits, but that request is
inert. A new explicit operator statement is sufficient for expansion; the
controller seals a predecessor-bound successor scope and newly bound attack
plan. Any configured scope-change role is a technical privilege policy derived
by the production controller, not an external legal-proof requirement. The
requester's suggested role cannot itself establish authority.

Break Their Bones never weakens the evidence ledger. Production activation
requires one atomic start transaction for campaign-receipt/break-glass nonce reservation,
initial preflight, campaign lease creation, and the first anchored ledger head.
Every asynchronous controller decision must have a durable write-ahead intent,
an idempotency key, a deadline/kill race, and an atomic bounded result append.
The current post-start file-ledger kernel exercises recovery semantics, but the
public L3 route remains closed until those controller guarantees and external
rollback-resistant anchoring exist.

The extreme preflight mechanism is `BREAK_GLASS`, not a password or hidden flag.
After an explicit operator exception decision, the controller seals a signed,
one-use technical receipt valid for at most 15 minutes. It provides integrity,
attribution, and replay protection, not another legal certification. It may
waive only named target-health or cleanup/rollback readiness failures, only for
a read-only plan, and only while materially reducing action, wall-time, output,
and concurrency limits. It cannot waive target scope, the current campaign receipt,
revocation, effect classification, finite budgets, append-only evidence,
credential isolation, the operator kill switch, or the control-plane-loss
failsafe.

## The 22 security lenses

Cross-cutting controls:

1. `ai-generated-code`
2. `attack-chaining`
3. `business-logic`
4. `completeness`

Domain lenses:

5. `ai-model-and-mlops-security`
6. `cicd-and-supply-chain`
7. `cloud-and-iac`
8. `crypto-and-key-management`
9. `database-and-data-stores`
10. `desktop-and-thick-client-security`
11. `embedded-iot-ot-security`
12. `failure-semantics-and-resilience`
13. `hipaa-and-phi`
14. `llm-and-ai`
15. `mobile-app-security`
16. `native-and-memory-safety`
17. `privacy-and-data-protection`
18. `salesforce-platform`
19. `security-observability-and-response`
20. `smart-contract-and-web3-security`
21. `threat-modeling`
22. `web-and-api`

The 18 domain lenses currently partition 243 uniquely owned security topics with
1,471 typed activation selectors. The four cross-cutting lenses intentionally
own zero topics and operate through explicit attribution/triage rules. The
latest modernization added dedicated ownership
for adversarial model/MLOps security, native memory safety, security
observability/response, and secure failure semantics, while deepening web/API,
crypto, mobile, LLM/agent, CI/CD, business-logic, and completeness coverage.
The target-driven expansion adds dedicated desktop/thick-client,
embedded/IoT/OT, and smart-contract/Web3 ownership with bounded package,
firmware, native-binary, and contract-build artifact vocabularies. Deployed and
live-runtime acquisition adapters exist, but their provider-side semantic
analysis remains explicitly `NOT_ASSESSED` until supported sealed-byte or
controller-analysis delivery is available.

For OCI built artifacts, the controller now preserves the exact
adapter-authored evidence context, verifies the manifest and each payload read,
and evaluates all five shipped OCI rules over the sealed bytes. Providers see
only bounded locator observations and controller rule matches, not raw evidence
bytes. Missing, unreadable, or truncated indexes remain non-clear gaps and
cannot create clearance. Each retained match is bound to one owning lens/topic
and must be reported exactly once; these positive detectors keep supported
topics `PARTIAL`, while unsupported topics stay `NOT_ASSESSED`. Truncation does
not discard a retained positive match, but omitted locators remain unauthorized.

The same release strengthens the control plane around every lens. Activation
uses bounded literal selectors with an explicit `any_of` form and expands source
scope over local dependency/dependent edges for no more than two hops and 256
additional files. Every lens shard must disposition its full owned-topic set,
so reading all assigned bytes is no longer treated as semantic completion.
Business-logic triage receives a bounded union of active domain-lens source
scope; cross-cutting, zero-topic lenses cannot widen it, and truncation is an
explicit gap. It then hands a normalized candidate set to attack chaining.
Findings can carry versioned,
requirement-level framework references and attack chains now have structured
prerequisites, ordered evidence-flow steps, and blast radius. Benchmark gates
measure both per-topic and per-lens recall and require vulnerable representation
for all 18 domain lenses.

Fuzzing is not a separate lens. It is one validation strategy that can exercise
many lens-owned claims. The first shipped provider is exact-pinned structured
property fuzzing with deterministic seed, shrink path, and minimized replay
value. Its public CLI registry currently exercises built-in controller/property
oracles; it does not yet invoke arbitrary repository code or a named loopback
service. Target harnesses, coverage-guided fuzzing, and schema-driven API fuzz
providers remain planned.

## Delivery status

Implemented and tested: strict plan/receipt/scope schemas; a one-use Ed25519
technical receipt under a key pinned in the local enrollment manifest;
enrollment-local prototype nonce consumption; formal scope expansion; signed break-glass; L2/L3
runtime gates; a local hash-chained campaign ledger; the public isolated T1
worker and narrow T2 service-proof route with cumulative deadlines and durable
attempt recovery; the fixed built-in structured-property provider; crafted-scanner controller
gates; and a standalone redacted evidence-claim normalizer. These are kernel and
test-harness capabilities plus the explicitly shipped local proof routes; they
do not enable generic live dispatch.

Manual result ingestion and finalization now serialize their manifest commit
and immutable artifacts under the run lock. Results use content-addressed
paths; final report artifacts commit after the terminal manifest and are
deterministically repairable on retry. A killed ingest can leave an unreferenced
content-addressed file that has no manifest authority and is not counted by the
bundle budget, so an enrolled controller still needs orphan reclamation and a
physical disk quota.

Before generic live activation, nonce/lease state must be controller-global and
rollback-resistant rather than local to a cloneable enrollment root. Receipt
expiry and revocation must also be enforced during execution by the transport,
not only checked before a local strategy starts.

Current public target-I/O includes sealed repository T1 proof, narrow isolated
loopback T2 service proof, an exact bounded HTTPS reconnaissance action through
`adversarial go`/`http-recon-v1`, and fixed sealed `http-authed-v1` campaign actions.
Standalone authenticated probes and discovery-derived action dispatch remain
unavailable. Other containment is
explicit: `bounty scan run`, `bounty authz run`, `bounty
recon run`, `audit run-provider`, `audit run-remote`, transparency publication,
every evidence-acquisition plan/run route,
`audit plan --evidence-bundle`, database-conformance
execution, and every OOB session route fail closed before
target/process traffic (or, where applicable, before reading caller paths,
credentials, bundles, sessions, or receipt/authorization state). Static repository discovery,
offline adversarial/audit planning and validation without imported evidence,
historical inspection, and non-OOB cleanup remain separate
surfaces. The Chrome companion is inert and requests no host authority. The
formerly loadable mitmproxy addon has been removed; only pure offline
scope/User-Agent conformance helpers and an internal historical-JSONL library
remain, while all public proxy capture/import/query commands refuse execution.
A hosted OOB allowlist is transport
validation, not authority to disclose target callback data through a third party.

Not yet production-ready: public provider-runner,
remote-gateway, transparency-publication, live evidence-acquisition, or database
lab execution; generic crafted live transport; public L3 CLI; controller
enrollment provisioning; independently enrolled executable, gateway, log,
target, and outbound-data policy; a canonical
prepared-request adapter that binds the resolved destination to scope, one
atomic controller lease over scope,
revocation and preflight state, bounded/cancellable provider callbacks, hard
termination for non-cooperative adapters, protected raw-evidence storage,
externally anchored campaign state, authenticated ledger-to-T4 report
integration, controller-signed evidence manifests and acquisition plans,
single-handle verification, enrolled local artifact roots, durable fail-closed
stop state with descendant-process termination, non-reversible live metadata
summaries, transport-derived target identity, isolated controller callbacks,
and an atomic one-use authorize/intent/dispatch lease consumed by the transport.
Independent monotonic and wall clocks now stop on regression in-process; their
high-water marks still need controller-owned durable persistence across restart.
Target-aware fuzz providers, credential-reference-only action fields, and
controller-bound scope-change statement and permit bindings are also provider
requirements, not yet generic plan/request-schema guarantees. The generic plan
does not yet durably bind the accepted operator statement and controller-receipt
digest, and per-user nonce/revocation state is not yet protected by an
OS-attested, cross-process controller transaction. Optional RoE or authorization-
document digests may supplement evidence but are not prerequisites. Receipt-bound campaign journaling and
resume are therefore refused rather than trusting caller-supplied journal state.
Timeouts around in-process callbacks are cooperative and cannot prove hard
termination; no such callback may become a public live adapter. Direct
UNC/WebDAV and Windows namespace-prefixed device/pipe command-line paths are
refused. Offline commands still trust the operator's local filesystem endpoints;
symlink/junction ancestors, mapped/remote volumes, special aliases, embedded
JSON paths, and process-death orphan accounting require enrolled local roots,
owner/ACL and reparse verification, handle-relative I/O, reclamation, and a
physical disk quota.
The public adversarial CLI refuses generic live and L3 execution before
consuming a receipt nonce or performing target I/O until those services exist.
When the statement named that work, this is an authorized-but-unavailable
technical result, not an authorization denial or reason to ask again.
That release claim applies to supported CLI/package entrypoints, not privileged
same-process deep imports: several legacy audit command functions remain
exported for dependency-injected conformance tests. They are not a supported API
and must be split behind the enrolled controller or removed from production
packaging before live activation.

## Research basis and nonclaim

The architecture follows the separation of scope, safety, oversight, autonomy,
audit, and reporting in the [OWASP Autonomous Penetration Testing Standard](https://owasp.org/APTS/),
including its [machine-readable Rules of Engagement template](https://owasp.org/APTS/standard/appendix/Rules_of_Engagement_Template.html),
[Human Oversight](https://owasp.org/APTS/standard/3_Human_Oversight/), and
[Safety Controls](https://owasp.org/APTS/standard/2_Safety_Controls/). Test
coverage is informed by the [OWASP WSTG](https://wstg.owasp.org/latest/), while
engagement planning and evidence lifecycle align with
[NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final) and formal scope
sign-off with the [CREST Guide to Penetration Testing](https://www.crest-approved.org/wp-content/uploads/2023/04/A-Guide-to-Penetration-Testing-2022.pdf).

Those materials inform optional governance and evidence documentation; the
controller does not require them as legal proof at operator ingress.

These are design inputs, not claims of OWASP, NIST, or CREST conformance.
