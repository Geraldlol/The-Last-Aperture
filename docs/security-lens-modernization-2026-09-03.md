# Red Team Audit: security lens modernization

Research snapshot: 2026-09-03; implementation status updated 2026-09-04
Decision status: implemented and contract-validated
Scope: evidence-first repository audits; deployed-state and live-runtime conclusions require separately consumed evidence

## CTO-ready summary

Red Team Audit is an evidence-first security review system for source repositories. It inventories the codebase, activates domain lenses supported by the repository's files and technologies, runs the always-on and triage lenses at their defined stages, assigns every registered security topic to one domain owner, and requires findings to show a concrete source, reachable path, unsafe decision or side effect, and testable impact. It then deduplicates cross-domain findings, challenges likely false positives, composes proven attack chains, and reports what was not examined as explicitly as what was found.

Its core value is defensible precision: a risky keyword is only a lead, a framework category is not a severity, and an absent repository control is not proof that an external control does not exist. Static findings are kept separate from executed proofs, deployment assumptions, and live operational claims. The result is a report engineering and leadership can act on without treating scanner noise as fact or silence as assurance.

This modernization and target-driven expansion grew the registry from **15 to
22 lenses**, from **174 to 243 uniquely owned security topics**, and from **963
to 1,471 contract-mapped activation selectors**. The 18 domain lenses partition
those 243 topics; the four cross-cutting lenses (`ai-generated-code`,
`attack-chaining`, `business-logic`, and `completeness`) intentionally own zero
registered topics and use the schema's explicit zero-owner rules. Seven
previously material blind spots now have dedicated domain owners:

1. adversarial AI model and MLOps security;
2. native code and memory safety;
3. security observability and response;
4. exceptional states, failure semantics, and resilience;
5. desktop and thick-client trust boundaries;
6. embedded, IoT, OT, and cyber-physical systems; and
7. smart contracts and Web3 state/economic invariants.

The existing web, crypto, mobile, LLM, CI/CD, business-logic, and completeness lenses were also updated with current, edition-qualified requirements and explicit framework/nonconformance boundaries. Where an upstream project has conflicting or living release metadata, this memo says so instead of claiming a false version lock.

## What changed and why

| Decision | Risk now covered | Why it was not safe to leave implicit |
|---|---|---|
| Add `ai-model-and-mlops-security` | training-data provenance, poisoning, model-release integrity, adversarial evasion, model extraction, inversion/membership inference, inference-plane exhaustion, security drift and rollback | The existing LLM lens correctly owns prompt, tool, agent, MCP, RAG, and output risks; stretching it into the model lifecycle would mix two distinct trust boundaries and duplicate findings. |
| Add `native-and-memory-safety` | bounds and integer conversions, lifetime/UAF, uninitialized memory, double release, unsafe FFI, native races, parser state, fuzz/sanitizer coverage, compiler/platform hardening | No prior lens owned first-party C/C++ memory corruption or unsafe native boundaries. CISA and the 2025 CWE Top 25 make this too consequential to remain an informal sub-check. |
| Add `security-observability-and-response` | security-event obligations, application audit integrity, detection and escalation, telemetry loss, security-control failure signals | The web lens covered unsafe log content and threat modeling covered architectural detectability; neither followed the source-visible signal chain from decision through event, rule, route, and loss handling. |
| Add `failure-semantics-and-resilience` | fail-open controls, partial state and rollback, retry/redelivery, bounded work, unknown/default states, cleanup, degraded/last-resort behavior | OWASP Top 10:2025 made exceptional-condition handling a standalone category. HTTP error disclosure alone does not cover secure state when dependencies and operations fail. |
| Add `desktop-and-thick-client-security` | installer/update trust, local storage, IPC/process identity, URI/file handlers, web-to-native bridges, extensions, privilege brokers, diagnostics, and shell/OS integration | Desktop applications cross local process, operating-system, package, and embedded-web boundaries that neither mobile nor web ownership closes. |
| Add `embedded-iot-ot-security` | device onboarding, boot/update trust, debug and field protocols, physical access, cyber-physical safety, reset/disposal, radio provisioning, command/telemetry, and remote maintenance | Firmware and control systems need physical, lifecycle, safety, and hardware-root evidence that a generic native-code lens cannot infer. |
| Add `smart-contract-and-web3-security` | on-chain roles, initialization/upgrades, external calls, reentrancy, proxies, oracles, economic invariants, ordering/MEV, token accounting, gas/liveness, signatures, bridges, and emergency governance | Publicly callable deterministic state and economic composition create ownership and proof requirements distinct from web/API business logic. |
| Harden activation, semantic coverage, evidence, and lifecycle contracts | bounded `any_of` signals, dependency/dependent scope, per-topic assessments, per-lens benchmark gates, expanded artifact kinds, structured framework/chain records, and per-lens comparison | File-byte coverage and whole-pack equality were too coarse: they could hide an unassessed topic, miss adjacent source context, or discard valid history for an unchanged lens. |
| Extend `web-and-api` | browser messaging/origin trust and specialized interpreter/format injection | ASVS 5.0.0 identifies concrete checks that generic XSS/injection coverage can miss: `postMessage`, DOM clobbering, JSONP/XSSI, Fetch Metadata/CORP, prototype pollution, CSV formulas, JNDI, memcache, format strings, mail protocols, and ReDoS. |
| Extend `crypto-and-key-management` | reproducible crypto inventory, agility, migration, and post-quantum planning | Primitive misuse checks cannot answer “where is this algorithm used, can it rotate, and how will it be retired?” Two inaccurate strength statements were also corrected. |
| Extend completeness and business logic | trusted high-value-flow denominator, selected-framework requirement ledger, maker-checker proof | Route and file coverage can be complete while a multi-step abuse path or unreviewed framework requirement remains invisible. The controller now validates, seals, and dispatches these optional denominators while distinguishing unavailable (`null`) from explicitly empty (`[]`). |
| Version-pin mobile and supply-chain references | MASVS/MASWE/MASTG chain, SLSA Build and Source tracks, OSPS and SCVS | “OWASP-aligned” and “SLSA” are too ambiguous to audit or reproduce. Exact editions and requirement dispositions are now required. |

## The 22 lenses and what they target

### Cross-cutting and audit-control lenses

| Lens | Target |
|---|---|
| `ai-generated-code` | Always-on scrutiny for machine-authored code patterns: plausible but nonexistent APIs, insecure defaults, copied secrets, missing checks, and confidence without evidence. |
| `attack-chaining` | Triage-stage composition of separately proven findings into realistic end-to-end attack paths without double-counting component defects. |
| `business-logic` | Legal-operation sequences that violate product invariants: money arithmetic, workflow order/re-entry, idempotency, concurrency, time windows, and multi-principal approval. |
| `completeness` | Measured audit gaps across lenses, files, entry points, stores, dropped candidates, ownership, high-value flows, framework requirements, and coverage claims. |

### Domain lenses

| Lens | Target |
|---|---|
| `ai-model-and-mlops-security` | Dataset/training trust, poisoning, model artifacts and promotion, adversarial ML, extraction/privacy attacks, serving availability, security monitoring and rollback. |
| `cicd-and-supply-chain` | Workflow triggers, runner trust, tokens/OIDC, dependency resolution, malicious or vulnerable components, signing/provenance, SBOMs, scanner gates, and deployment gates. |
| `cloud-and-iac` | Cloud IAM and OIDC trust, network/storage exposure, secrets/KMS, Terraform state, containers/images, Kubernetes/admission, serverless, BaaS, backups, and deployed configuration evidence. |
| `crypto-and-key-management` | TLS, JWT/JWS/JWKS, SAML/OAuth/OIDC, password KDFs, symmetric/asymmetric constructions, signatures, randomness, key material, inventory, agility, and migration. |
| `database-and-data-stores` | Database principals, native authorization/tenancy, privileged code, integrity/concurrency, encryption, replication/CDC/history/copies, lifecycle, and resource controls across supported engines. |
| `desktop-and-thick-client-security` | Desktop package/update trust, local storage, IPC and process identity, URI/file handlers, embedded web/native bridges, plugin/script trust, privilege brokers, diagnostics, and OS launch integration. |
| `embedded-iot-ot-security` | Device onboarding, boot and firmware trust, update/rollback, debug and service protocols, physical-access assumptions, safety interlocks, lifecycle/reset, wireless provisioning, telemetry, and OT remote maintenance. |
| `failure-semantics-and-resilience` | Security-control failures, rollback/partial operations, bounded retry and work, null/unknown defaults, cleanup, safe degradation, and last-resort handlers. |
| `hipaa-and-phi` | PHI classification, minimum necessary, access audit, encryption sufficiency, de-identification, BAA perimeter, lower environments, tracking, breach exposure, and severity uplift. |
| `llm-and-ai` | LLM application data flow, prompt injection, system-prompt misuse, tool/agent/MCP authority, RAG and derived stores, output sinks, exfiltration, spend controls, and model origin/loading safety. |
| `mobile-app-security` | Android/iOS/React Native configuration, local storage and keystores, shipped secrets, transport policy and pinning, mobile OAuth, links/IPC, WebViews, privacy/UI leakage, OTA integrity, and native provenance. |
| `native-and-memory-safety` | C/C++ and unsafe Rust bounds, lifetime, initialization, resource ownership, FFI/ABI contracts, races, native parsers/drivers/firmware, fuzz/sanitizer coverage, and build hardening. |
| `privacy-and-data-protection` | Personal-data inventory, minimization, lawful basis/consent, cookies/tracking, processors/destinations, retention/deletion, data-subject rights, children, transfers, automated decisions, pseudonymization, and PCI scope. |
| `salesforce-platform` | Apex sharing/CRUD/FLS and entry points, SOQL/SOSL, Flow context, LWC/Aura/VF sinks, guest/site exposure, Named Credentials/Connected Apps, Shield caveats, and Agentforce actions. |
| `security-observability-and-response` | Security-event completeness, application audit integrity/access, detection rules and escalation, telemetry-pipeline resilience, and distinguishable security-control failures. |
| `smart-contract-and-web3-security` | Contract roles and initialization, external-call/reentrancy order, proxy/delegate trust, upgrades, oracles, economic invariants, transaction ordering, tokens, gas/liveness, block context, signed authorization, bridges, and emergency governance. |
| `threat-modeling` | Trust boundaries, attacker profiles, STRIDE decomposition, attack trees, exfiltration paths, cross-boundary attribution, architectural trust gaps, and detectability gaps. |
| `web-and-api` | Authentication, authorization and tenancy, sessions/CSRF/CORS/headers, injection/XSS/deserialization/XXE, files/SSRF, proxy/cache behavior, GraphQL/streaming, APIs/webhooks, browser trust, logs/errors, quotas, and races. |

The generated topic registry remains the authority for the detailed 243-topic partition; a lens may raise context for another owner, but it may not silently claim that owner's topic.

## Control-plane contract changes

1. Every planned lens shard seals its owned topics as `topic_obligations` and a
   successful result must return one evidence-backed `topic_assessments`
   disposition per topic. `partial` and `not-assessed` retain named gaps even
   when every scoped byte was consumed.
2. Signal activation accepts a scalar literal or a bounded `any_of` list of
   2-32 atomic literals. Regex selectors and prose pretending to be compound
   selectors are rejected. Direct text matches expand deterministically across
   repository-local dependencies and dependents for at most two hops and 256
   additional files, with truncation recorded as a gap.
3. `business-logic` receives a bounded active domain-lens source union and the
   merged candidate set for invariant analysis, normalization, and
   false-positive challenge. Cross-cutting zero-topic lenses cannot inflate
   the packet; truncation remains a named gap. `attack-chaining` follows with
   only the controller-validated source locations of its components.
4. Evaluation publishes per-lens TP/FN/recall and
   `minimum_vulnerable_lens_recall`; the release profile requires vulnerable
   representation for all 18 domain lenses as well as the existing per-topic
   floor.
5. The artifact vocabulary adds desktop packages, firmware images, native
   executables, shared libraries, and smart-contract builds, with bounded claim
   kinds for signature, hardening, firmware trust, deployment drift, embedded
   secrets, unexpected content, and vulnerable components. Provider packets
   seal the complete shared lens-support set as trusted control, not only the
   selected top-level lens file.
6. Findings can carry versioned requirement-level `framework_refs`. Attack
   chains carry prerequisites, blast radius, and ordered component steps with
   consumed/produced state and joint evidence. Historical comparisons remain
   whole-run non-comparable when packs differ, but an unchanged lens digest,
   sorted topic contract, and shared schema/harness/adapter digest can support
   explicitly per-lens partial comparability. The generated additive
   `_topics.md` registry is deliberately excluded from that shared digest.

## Standards reconciliation

### OWASP

- [OWASP Top 10:2025](https://owasp.org/Top10/2025/) remains the broad web-risk spine. A09 now routes event/detection obligations to the observability lens while unsafe log content stays in web/API. A10 now routes secure failure state to the resilience lens while HTTP response disclosure stays in web/API.
- [OWASP ASVS 5.0.0](https://owasp.org/www-project-application-security-verification-standard/) is used at the exact requirement level, based on the [official version-tagged CSV](https://raw.githubusercontent.com/OWASP/ASVS/v5.0.0/5.0/docs_en/OWASP_Application_Security_Verification_Standard_5.0.0_en.csv). Representative mappings are documented below; no lens may infer whole-level conformance from selected checks.
- [OWASP API Security Top 10:2023](https://owasp.org/API-Security/) remains the API category crosswalk; the detailed audit still requires a repository mechanism and impact.
- [OWASP AISVS 1.0](https://owasp.org/www-project-artificial-intelligence-security-verification-standard-aisvs-docs/) is the model/MLOps verification baseline, with exact `v1.0-Cx.y.z` identifiers and explicit gaps where AISVS does not mandate an attack test.
- [OWASP LLM Top 10 2026](https://genai.owasp.org/resource/owasp-genai-llm-top-10-2026/), [LLMSVS 2.0](https://owasp.org/www-project-llm-verification-standard/LLMSVS-v2.0-en.html), and the [Agentic Top 10 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/) update the existing LLM/agent application lens.
- The [Agent Control Standard](https://genai.owasp.org/resource/agent-control-standard-acs/), [MCP Top 10](https://owasp.org/www-project-mcp-top-10/), and [Agentic Skills Top 10](https://owasp.org/www-project-agentic-skills-top-10/) are labeled preview, beta, or public-review material in this snapshot. They inform hypotheses, not conformance claims.
- [MASVS 2.1.0](https://mas.owasp.org/MASVS/), MASWE 1.0.0, and MASTG 2.0.0 are treated as a control → weakness → test chain. A missing published test is recorded as unsupported coverage, not a pass.
- [OWASP SCVS 1.0](https://owasp.org/www-project-software-component-verification-standard/) is the stable component-verification baseline; later draft material is not silently promoted.

### Other primary sources

- [NIST AI 100-2 E2025](https://csrc.nist.gov/pubs/ai/100/2/e2025/final) supplies the adversarial-machine-learning taxonomy for poisoning, evasion, privacy, extraction, misuse, and availability. [NIST SP 800-218A](https://csrc.nist.gov/pubs/sp/800/218/a/final) supplies AI-specific secure-development practices.
- [MITRE ATLAS](https://atlas.mitre.org/) is a living taxonomy, not a control standard or severity system. No ATLAS release is pinned in this revision, so the lens does not declare ATLAS as a conformance framework; a future adoption must record an exact data release or commit.
- [CISA's memory-safe roadmap guidance](https://www.cisa.gov/resources-tools/resources/case-memory-safe-roadmaps) supports prioritizing high-risk native boundaries and long-term migration. C/C++ use alone is not a vulnerability.
- [NIST CSF 2.0](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20) and [CIS Controls 8.1](https://www.cisecurity.org/controls/v8-1) exposed the Detect/Respond/Recover coverage gap. Their organizational outcomes require external and runtime evidence; source configuration proves intent only.
- [SLSA 1.2](https://slsa.dev/spec/v1.2/) is the approved current specification. The CI lens now assesses Build and Source tracks independently and does not infer branch-control enforcement from a checkout.
- [OpenSSF OSPS Baseline 2026.08.28](https://baseline.openssf.org/versions/2026-08-28) supplies open-source project controls with explicit maturity applicability. Provider settings such as MFA and branch protection remain unverified unless exported evidence is consumed.
- [CISA Secure by Design product bad-practice guidance](https://www.cisa.gov/news-events/alerts/2025/01/17/cisa-and-fbi-release-updated-guidance-product-security-bad-practices) and [NIST SSDF 1.1](https://csrc.nist.gov/pubs/sp/800/218/final) inform the future product-security posture track; they are not converted into repository vulnerabilities when the needed organizational evidence is absent.
- [NIST IR 8259 Rev. 1](https://csrc.nist.gov/pubs/ir/8259/r1/final) and [NIST SP 800-82 Rev. 3](https://csrc.nist.gov/pubs/sp/800/82/r3/final) support the dedicated IoT/OT/cyber-physical lens. Its OWASP ISVS reference is pinned to the selected `1.0.0-rc2` artifact rather than silently treating inconsistent release channels as interchangeable.

## Exact requirement upgrades that materially change results

| Area | Version-pinned requirement | Audit consequence |
|---|---|---|
| Browser and specialist injection | ASVS `v5.0.0-1.2.10`, `1.3.8`–`1.3.12`, `3.2.3`, `3.5.5`–`3.5.8`, `15.3.6` | Adds explicit checks for spreadsheet formulas, JNDI/memcache/format/mail/ReDoS, DOM clobbering, cross-window messages, JSONP/XSSI, Fetch Metadata/CORP, and prototype-pollution source-to-gadget paths. |
| GraphQL | ASVS `v5.0.0-4.3.1`, `4.3.2` | Pins cost and introspection checks already substantially present in the web lens. |
| Business flow | ASVS `v5.0.0-2.3.5` | Adds a two-principal maker-checker proof for a transaction proven applicable and critical; it does not invent product criticality. |
| Crypto inventory/agility | ASVS `v5.0.0-11.1.2`, `11.1.3`, `11.1.4`, `11.2.2` | Requires a reproducible inventory, discovery mechanism, controlled agility, and a post-quantum migration strategy where relevant. |
| Crypto strength | ASVS `v5.0.0-11.2.3`, `11.5.1` | RSA 3072 is the 128-bit-strength profile floor; UUIDv4's 122 random bits do not satisfy the applicable 128-bit random-value requirement. |
| Security events | ASVS `v5.0.0-16.1.1`, `16.2.1`–`16.2.5`, `16.3.1`–`16.3.4`, `16.4.1`–`16.4.3` | Adds an event denominator, context/correlation, outcome coverage, modification protection, separated sink intent, and explicit failed-control telemetry. |
| Exceptional conditions | ASVS `v5.0.0-16.5.1`–`16.5.4`, `13.1.2`, `13.1.3`, `13.2.6`, `15.1.3`, `15.2.2` | Adds safe responses, external-resource failure, fail-closed degradation, last-resort handlers, documented resource limits, and enforceable bounded work. |
| Native memory safety | ASVS `v5.0.0-1.4.1`–`1.4.3` | Adds exact unmanaged-code checks for strings/copies/pointer arithmetic, sign/range/overflow validation, and safe allocation/lifetime release. |

## Deliberately deferred expansion

The next useful additions are not “more OWASP lists”; they are scopes with a distinct evidence model and non-overlapping owner.

| Candidate | Recommendation | Why deferred from this tranche |
|---|---|---|
| Product-security lifecycle and maintainer governance | Add as a posture/control assessment, not ordinary vulnerability findings | SSDF, Secure by Design, SAMM, and OSPS often require policy, staffing, provider settings, disclosure, support, and governance evidence outside a checkout. |
| WebRTC profile | Add conditionally inside or beside web/API | ASVS V17 has exact requirements, but only real media/RTC code justifies activation. |
| Machine/workload/non-human identity | Design the ownership partition first | CI OIDC, cloud IAM, service identities, secrets, and agent identities already have partial owners; a premature lens would duplicate all of them. |

No separate container/serverless or agentic-AI lens is recommended: those topics already have deep, explicit owners in `cloud-and-iac` and `llm-and-ai`.

## Evidence and conformance limits

The updated audit intentionally does **not** claim from repository source alone that:

- a deployed edge, WAF, gateway, IAM policy, database role, SIEM, alert route, or runtime limit has the intended effective value;
- an alert is delivered or acknowledged, an on-call responder acts, or an incident playbook succeeds;
- a production model is robust, private, unpoisoned, drift-free, or the same artifact represented in source;
- a shipped binary has ASLR, DEP/NX, RELRO, CFI/CFG, stack canaries, PAC/MTE, or sanitizers active;
- a shipped desktop package or firmware image is authentic, a hardware trust
  control is fused/enforced, or a deployed smart contract matches its reviewed
  build without the corresponding consumed artifact or deployment evidence;
- a framework level or regulatory regime is satisfied end to end.

Every selected verification framework needs a requirement applicability ledger with one disposition per in-scope requirement: `mapped-and-tested`, `mapped-not-tested`, `not-applicable` with evidence, `not-repository-provable` with the required external artifact, or `not-assessed` with a reason. Representative requirement mappings never become blanket conformance.

CISA KEV may raise priority when an affected component is known exploited; absence from KEV never lowers a finding. CIS Benchmarks remain product- and version-specific. PCI DSS 4.0.1 is an overlay only after cardholder-data scope is established.

## Verification completed

- Lens linter: **PASS**, rules R1–R9 and ledger gate clean.
- Registry: **22 lenses, 243 uniquely owned topics**.
- Activation contract: **1,471/1,471 typed selectors mapped exactly once**, with hash locks, exact rendered-family checks, bounded `any_of` literals, and regressions for absence-shaped observability and failure paths.
- Evidence declarations: all 22 lenses explicitly declare source, built-artifact, deployed-state, and live-runtime consumption.
- Generated registry and ownership overlap: regenerated and drift-checkable.
- Full project suite: required before release; use the named CI run or current command output as the count authority rather than embedding a total that drifts during development.

## Recommended next move

Adopt this 22-lens set as the repository-audit baseline. For a high-assurance engagement, select applicable verification profiles up front, export provider/deployment evidence as separate declared evidence classes, and require the controller to close file and topic obligations plus any high-value business-flow and version-pinned requirement ledgers. Start another lens tranche only when actual target repositories justify WebRTC, product-security posture, or non-human-identity ownership that cannot be expressed by the current domains.
