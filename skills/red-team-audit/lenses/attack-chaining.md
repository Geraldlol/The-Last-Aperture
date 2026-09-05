---
name: attack-chaining
title: Cross-lens attack chaining
runs_in: triage
activates_on:
  paths: []
  signals: []
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
owns: []
defers: {}
frameworks: [mitre-attack]
severity_floor: info
---

## Scope

This lens starts from **findings, not a fresh code search.** Its input is the normalized candidate set emitted by the preceding `business-logic` triage stage after structural dedup, semantic dedup, reachability adjudication, and the false-positive sweep — the one point in the pipeline where every lens's output is visible at once. No fan-out auditor can do this work: each one receives its own lens file and its own file list, and a composition whose hops were filed by three different lenses is invisible from inside any of them.

Its job is the one thing no per-lens pass can produce: **individually-Medium findings that compose into account takeover, data exfiltration or privilege escalation.** The unit of output is a *chain* — an ordered sequence of filed records where each hop supplies a precondition the next hop needs — written step by step, with the components' `candidate_id`s recorded in `component_finding_ids`.

The controller delivers the sealed source locations cited by the component records. It opens those files for exactly one reason: to confirm that two components actually meet, meaning the value one produces is the value the other consumes. It never authors a hop from code no lens filed. **A hop with no `candidate_id` is not a hop** — see `## Severity calibration`.

### Does not own

`owns: []` is not a formality here. Every record this lens touches keeps the `lens` and `topic` of the lens that filed it, because ownership is declared and never inferred from which pass emitted a record.

- **It does not own any topic slug, and it never originates a record.** Unlike `business-logic`, which may originate, this lens only ever elevates something another lens already filed. That is why it needs no exception to the schema's ownership invariant: a record with `lens: attack-chaining` would carry a `topic` this lens does not own and is malformed by construction. Never write one.
- **It does not own its components' severities.** `claimed_impact_severity` is immutable across every appearance of a `candidate_id`. Nothing here edits a component's claim to make a chain look worse, and nothing here edits it to make a chain's proof queue position better.
- **It does not own `pivot-feasibility`, `attack-tree-construction`, `exfiltration-path-enumeration` or `architecture-trust-design-gaps`** — all `threat-modeling`'s. The boundary from that side is already written into that lens: it reasons about feasibility from architecture, *before* anything is filed, and it is instructed never to pre-elevate a severity on a chain it constructed there. The boundary from this side is the reciprocal: **chain elevation happens here and only here.** When `threat-modeling` has filed a `pivot-feasibility` record covering part of the same path, that record is a **component** of the chain, cited by id — not a duplicate to restate and not a second elevation to add. And if the composition turns out to be exactly that record's path with nothing added, there is no chain: the composition is `merged` into it and this lens files nothing.
- **It does not do what `ai-generated-code` does.** That lens raises a finding *within* another lens's topic, tagged with `raised_by`. This lens composes *across* records that already exist. A single record whose severity someone thinks is too low is not a chain.
- **It does not re-prove components.** Each component's proof belongs to the lens that filed it, executed in Phase 3 by that lens's recipes. This lens adds exactly one proof obligation of its own, and it is the composition — see `## Proof recipes`.

### The record a chain writes

**A chain is not a new record.** The schema has a zero-owner exemption, but this
lens deliberately does not use it to originate chain records. Its policy is to
record the chain on one existing record — the **host** — chosen as the component
whose topic the composed impact actually lands on. That is usually the terminal
hop: the one whose sink is the data, the session or the privilege the attacker
ends up holding.

The host keeps its `lens`, its `topic`, its `candidate_id`, its `location` and its `claimed_impact_severity` unchanged, and gains five fields:

| Field | Value |
|---|---|
| `triage_disposition` | `elevated` |
| `raised_by` | `attack-chaining`. **Required** — an `effective_severity` above the claim with no `raised_by` is a contract violation, not a stylistic gap |
| `component_finding_ids` | Every component, **including the host**, in execution order: first hop first |
| `chain` | Prerequisites, blast radius, and one structured step per component with `candidate_id`, `produces`, `consumes`, `joint_evidence`, and optional versioned `framework_refs` |
| `effective_severity` | The composed impact, subject to every cap in `## Severity calibration` |

**`component_finding_ids` and `chain.steps` are both ordered and must carry the
same candidate IDs in the same order.** One step per id, one id per step. The
validator rejects a missing structured chain or any mismatch; consumers no
longer reconstruct joints from prose.

**A step with no `candidate_id` is not a step.** Either the finding exists and nobody filed it — in which case raise it first, through the lens that owns the topic, so it gets its own id and its own proof — or it is an assumption, and an assumption cannot be a hop. This is the rule that stops a chain from being completed by an invented hop, which is the characteristic failure of chain reasoning and the reason chain findings have a bad reputation.

**Components stay `queued` at their own severities.** A component does not dissolve into the chain. Each keeps its own `candidate_id` and its own report line, because a patch that breaks the chain at one joint leaves every other component live and reportable.

**Where the step-by-step narrative lives.** Stage 1's `attack` remains
immutable. Stage 2 writes the composition into `chain`: `prerequisites` states
attacker premises, `blast_radius` bounds the terminal effect, and every ordered
step names the value it consumes, the value it produces, and the exact joint
evidence. Markdown and SARIF render from this object; provider prose is not a
second source of truth.

### ATT&CK annotation — cite technique identifiers or do not claim the framework

`frameworks: [mitre-attack]` is a promise about output, and an advertised-but-unused framework is a defect this project has already had to repair once. It is kept here for one reason: a chain, alone among this skill's outputs, is a **tactic-ordered sequence**, and a tactic-ordered sequence is the form a detection or incident-response team can act on. They read it to find which tactic in the path they have no coverage for.

So **every chain elevation carries technique identifiers, one per step, or the annotation is not written for that finding.** Not "MITRE ATT&CK informed this analysis" — identifiers, or nothing.

**Where the identifier goes.** Each step uses `framework_refs` with
`framework_id: mitre-attack`, a version, the technique identifier,
`relationship: technique`, `applicability: applicable`, and its canonical HTTPS
source. A run may additionally map the host finding to other versioned
framework requirements through the finding-level `framework_refs` array.

Five rules, all load-bearing:

1. **One technique per step, anchored by that step's component.** The anchor is the component record's own `evidence` — the quoted code. A step whose evidence supports no technique gets no technique; write the step without one. Never tag the chain as a whole with a technique that no individual step anchors, and never tag a step because the technology is present. A container manifest that requests host privileges anchors `T1611`; the mere existence of containers does not.
2. **The sequence is tactic-ordered, and the tactics must be ones the matrix lists for those techniques.** A sequence running backwards — Exfiltration before Initial Access — is either a mis-ordered chain or a mis-chosen technique. Fix the chain, not the label. Most techniques carry several tactics; where the matrix and any table disagree about which, the matrix wins.
3. **The anchor-to-technique mapping table is not duplicated here.** It lives once, in `threat-modeling`'s ATT&CK item, covering repository anchors from an internet-reachable route (`T1190`) through unsecured credentials in files (`T1552.001`), the metadata API (`T1552.005`), valid accounts (`T1078`), escape to host (`T1611`), collection (`T1005` / `T1530`) and exfiltration (`T1567` / `T1048`). Two copies of a mapping table drift, and a drifted technique identifier is worse than none. **Where a step's anchor is not in that table, cite the parent technique or omit the annotation. Do not invent an identifier and do not stretch a row** — a detection team handed an identifier that does not match their environment searches, finds nothing, and records coverage.
4. **The mapping table is an input to this lens, and its absence is not a verdict.** Triage must be handed that table along with the merged set. Where it was not, the chain still ships and **the annotation does not**, and the coverage block says `ATT&CK annotation not produced: mapping table unavailable`. It must never say that no technique applied — "ran and found nothing" and "could not have found anything" are different sentences, and only one of them is true here.
5. **The annotation never establishes ownership, severity or reachability.** It is a label for a downstream team. No row in `## Severity calibration` is earned by a technique identifier, and a technique on a step whose control belongs to another lens does not move that finding here.

**Record the matrix version once per run, in the report header.** Identifiers are durable across versions where names and sub-technique structure are not, which is why this lens pins no version rather than pinning a stale one. Durable is not immutable: identifiers do get deprecated and superseded, so if the one you were going to cite is absent from the version you record, find its replacement rather than handing over a dead identifier.

## Severity calibration

`severity_floor: info` is presentational. It orders this lens's output in the report and never suppresses anything — which matters more here than anywhere else, because the Lows and Mediums a floor would suppress pre-triage are the raw material every chain is built from.

A chain's `effective_severity` is **the severity of the terminal state**, graded by what the attacker holds when the last hop completes, on the same rubric every other lens uses. It is not the maximum component severity plus one, and it is not earned by language. "Trivially chainable", "attacker-controlled end to end", "a determined attacker would obviously" — none of those is a composition. The composition is the justification, or there is no elevation.

### Three gates, applied in order, before any severity is written

**Gate 1 — the delta test.** If the composed impact equals the strongest component's `claimed_impact_severity`, **there is no chain and no elevation.** A SQL injection that already returns arbitrary rows does not become Critical by being reachable from the unauthenticated route its own `reachable_from` already names. Compose only where the composition *adds*: a hop supplies a precondition another finding needed, so the pair reaches a state neither reaches alone.

**Gate 2 — the joint test, and it is the one that fails most chains.** For every joint, the output of hop N must be the input hop N+1 requires: **the same value, the same encoding, the same principal, the same trust context, the same time window.** Write the carried value out explicitly at every joint. If hop 2 needs an authenticated session and hop 1 yields an unauthenticated read of a non-secret, the chain is broken and no wording repairs it. **A chain that cannot name the value carried across each joint is a list of findings, not a chain.**

**Gate 3 — one deployment, one principal.** The hops must be reachable by one actor in one running system. A development-only debug endpoint plus a production authorization gap is not a chain; two tenants of two different systems is not a chain. Where a hop rests on infrastructure outside the checkout — "the gateway forwards the header", "the mesh permits it" — that hop is an assumption, it caps the chain per the table below, and it is written into the run's assumptions output rather than into the step list.

### Composition table

Each row is a shape, not a template to fill: the condition column is what must be *cited from the component records*, and every claim is `claimed_impact_severity` for the composition, before the caps below.

| Composition | Terminal state | Claimed impact |
|---|---|---|
| An unauthenticated or low-privilege read that yields a value carrying authority — a reset token, a session identifier, a signed cookie, an invite or share token — plus a handler that accepts that value without binding it to the account | Session or account of another principal | **Critical** where the reachable account set is arbitrary or includes an administrator; **High** where it is one known low-privilege account |
| An object-level or property-level authorization gap that permits identifier enumeration, plus a bulk read, export or report route that accepts an enumerated identifier set | Data exfiltration at volume | **Critical** where the data class is regulated or credential material per the uplift lenses; otherwise **High**. One record is the component's finding; the table is the chain's |
| Any write primitive — mass assignment, an unscoped update, an upload with a controlled path — plus a read or execute path that consumes what was written: a role or permission field, a template, a configuration value, a served static path | Privilege escalation or code execution | **Critical** where the consumed value is a role, a permission or executed content; **High** where it is displayed content |
| An outbound fetch on an attacker-influenced URL, plus a credential reachable at a destination that fetch can reach — a metadata endpoint, an internal admin service with no authentication | Credential access, then whatever the credential holds | Graded by the credential's scope **as evidenced in the checkout** — an IAM policy, a role binding, a secret reference. Never by assumption about what a credential "probably" allows |
| A missing or bypassable rate limit, plus a guessable secret whose search space another lens has **quantified** | Credential access by brute force | **High** only where the entropy finding is filed *and* states the search space. A rate-limit finding plus an unquantified "guessable" is not a chain |
| A leak into a log, URL, error body or cache, plus a second filed finding that reads that sink from a lower privilege | Exposure of the leaked class to the lower privilege | Graded by what leaked, per the owning lens's calibration |
| Any composition whose steps are all one lens's topics | — | **Still a chain.** The most common real one — an object-level authorization gap plus a bulk export — is entirely `web-and-api`'s. A cross-lens pair is a hint, never a requirement |

### The caps, which are arithmetic

The schema's invariants are per record; a chain is a claim about several records at once, so the composed rule is stated here, where it is applied.

- **The chain is capped by its weakest component.** Any component with `reachable_from: unknown` caps the composition at Medium — if hop 1's entry is unknown, the chain's entry is unknown. A component carrying the schema's `contingent:` value caps the composition at Medium in exactly the same way, and the chain inherits its `contingent_fact` and `contingent_query` verbatim: one named query decides the whole chain, which is worth printing rather than flattening to `unknown`. After Phase 3, any component at T0 or T3, or carrying `UNPROVEN` or `INCONCLUSIVE`, caps the composition at Medium. **A chain of five unproven Mediums is a Medium.**
- **This is the most likely place for this lens to violate the contract**, because the elevation is written at Phase 2 and the proof lands at Phase 3. The elevation is a claim that has to be paid for. Where it is not paid, the report shows the cap and the reason — never the ambition.
- **A `DISPROVED` component breaks the chain.** Remove the elevation: `effective_severity` returns to what the host record's own gates give it, and the reason is recorded. `effective_severity` is a derived field and Stage 3 is allowed to revise it, so this is a legal write, not an overwrite. **Do not re-route the chain through a different hop to save the elevation** — a re-routed chain is a new chain and is written from scratch, through all three gates.
- **A `NOT_REPRODUCED` component withdraws the chain rather than downgrading it.** A chain missing a hop is not a weaker chain. The component itself is withdrawn to the coverage block as its own lens prescribes.
- **Never elevate on a path already elevated.** If `threat-modeling` filed a pivot record covering hops 1 and 2 and this lens composes hops 1 through 3, there is one elevation, on the composition, and the pivot record is a component. Elevating in both places double-counts one path.

### The proof-queue consequence, stated because it bites

The proof queue is ordered by `claimed_impact_severity`, and nothing edits that
field. The controller also propagates an attack-chain host's stronger effective
severity to every ID in `component_finding_ids` for queue ordering. A chain
elevated to Critical therefore promotes its Medium components as one proof
priority without rewriting any component claim.

**Do not edit `claimed_impact_severity` on any component.** That is a contract
violation and destroys the immutability the report's auditability rests on.
Where the proof budget still does not reach every component, the chain ships at
Medium with `elevation unpaid: N of M components proven` in the coverage block,
never at Critical.

## Known false positives

Each entry is a shape that reads as a chain and is not one. **None of them is a licence to drop a component** — every entry names what survives, and several name what it does not clear.

1. **Two findings on the same route reported as a chain.** Sharing an entry point is not composition; two independent defects in one handler are two findings.
   **What survives:** one finding's output being what the other requires — the first leaks the identifier the second fails to authorize, the value quoted at both ends.
   **What this does not clear:** a genuine pair in one handler. Co-location is not evidence either way; the joint test decides.

2. **A chain whose first hop is a precondition rather than a filed finding** — "an attacker with a valid session", "a compromised laptop", "once the attacker holds the API key".
   **What survives:** the chain starting from the first hop that is a filed record, with the earlier premise written as a stated assumption at the head of the step list. A premise the product itself grants — any registered user, any tenant member — is a real attacker and the chain is graded normally. "The attacker already has administrator" grants no elevation at all, because the terminal state was the premise.
   **What this does not clear:** an in-repo artifact that makes the premise cheap. A committed credential or a long-lived token is a finding in its own right, filed by its owning lens, and once filed it is a legitimate hop.

3. **Elevation because the components are numerous.** Five Mediums that all read the same non-sensitive value compose to one Medium. Count is not composition, and a chain assembled by counting is how a report acquires manufactured Criticals at scale.
   **What survives:** the subset that actually joins. Drop the rest from `component_finding_ids` — a component that carries no joint is padding, and padding in that field breaks the one-step-one-id correspondence the report line depends on.

4. **Re-stating reachability as hop 0.** `reachable_from` already names the entry point the component is reachable from. Wrapping it as a first hop double-counts the same fact and inflates the step count.
   **What survives:** a hop that *changes* reachability — a finding that turns an authenticated path into an unauthenticated one, or reaches an internal route from an external one.

5. **A composition only demonstrable off this machine.** A hop through a cloud API, hosted forge, or identity provider is never repository proof. An accepted authenticated operator statement naming every external destination, scope, effect, and credential use may authorize separate external evidence without another prompt, but only through matching destination-bound controllers; otherwise record the technical gap. External observations do not promote the chain's repository proof tier.
   **What survives:** the chain up to the last local hop, with the remaining hops recorded as unproven steps naming what each would demonstrate, and the composition capped accordingly. `threat-modeling` records `pivot-feasibility` as unprovable for exactly this reason; a chain in the same position inherits that status rather than escaping it.

6. **The same path shipped twice — once as `pivot-feasibility`, once as a chain.** Merge, keeping both `candidate_id`s so any report line or chain that cited either still resolves, and ship one.
   **What this does not clear:** an architectural pivot finding and a chain that genuinely differ in their hops. Compare the step lists before merging.

### Rejected candidates

Considered and deliberately excluded. Each would have suppressed real findings or manufactured false ones.

- **"Elevate any pair of Mediums that share an entry point."** Mechanical, cheap, and it manufactures a Critical on any repository with two findings in one handler. The joint test exists because the *value* has to travel, and no entry-point heuristic can check that.
- **"A chain must cross two lenses."** It would delete the single most common real chain — an object-level authorization gap plus a bulk export, both `web-and-api`'s.
- **"Cap every chain at its strongest component's severity."** That is the same as deleting this lens: a composition that adds nothing is already refused by Gate 1, so the only chains left are the ones where the terminal state genuinely exceeds every component, and capping them re-hides exactly what the pipeline built this pass to find.

## Proof recipes

A chain has **two proof obligations and both are required.**

1. **Every component is proven on its own**, by the recipe of the lens that filed it. This lens writes no component proofs and re-proves nothing.
2. **The composition is demonstrated end to end**, in one command, with the value carried between hops being the value the previous hop actually produced.

Neither half substitutes for the other. All five oracle conditions apply to the composition test, and its `verification_status` is capped by its weakest component per `## Severity calibration`.

### C1 — The end-to-end composition test (T1; T2 where the accepted operator statement names the boot and a matching implemented controller exists)

One test, one command, hops in order, one process and one session per principal. Six rules, and the first is the one that decides whether the test proves a chain or proves nothing.

- **Carry the artifact; never re-seed it.** The token the second hop presents must be the exact string the first hop returned. A test that mints an equivalent token from a fixture proves the hops and not the chain, and it is the characteristic false pass here — it passes identically on a codebase where the joint does not exist.
- **Use the canary fixture set for the carried value.** Plant a marker in the resource the first hop reads and assert the *same* marker arrives at the terminal sink. That identity is what makes it one chain rather than two findings. Use the derived-encoding expander: a hop that base64s or URL-encodes the value in transit is still the same chain, and a literal-only sweep reports that the chain broke.
- **Use the two-subject fixture wherever a hop crosses a principal.** A's marker observed in B's terminal output is the end-to-end assertion, and the fixture's positive case — a record B legitimately owns — is the control that stops "refuses everything" from passing the whole sweep.
- **Where the terminal hop calls a provider or downstream API, use the counting fake provider client** and assert on the recorded call, specifically that its arguments carry the value obtained at hop 1. Never assert on the response: a system that executes and then truncates looks identical from outside to one that refused.
- **Where the terminal hop is exfiltration, install the socket-layer destination recorder first**, allowlist nothing but the loopback the application itself needs, and let the recorded destination be the assertion. Its deny-by-default is what keeps the proof from performing the exfiltration it demonstrates.
- **Where a hop needs a window** — a token still valid, an approval not yet expired, a hold not yet released — use clock control, and back-date the rows rather than freezing the process clock if the predicate is evaluated by the database.
- **Where the terminal hop is one of a family** — several routes, verbs or export formats that accept the same value — use the **registry-driven enumerator** to parametrize the last hop over all of them, with its committed-count assertion intact. A chain proven against one export route and reported as though it covered the family is an anecdote; a chain proven against the enumerated set fails the day somebody adds an unguarded sibling.

Two further requirements specific to compositions:

- **Path-reached evidence per hop, not only at the end.** A spy, marker or log assertion at every hop, so a test that "passed" because hops 2 and 3 short-circuited is distinguishable from one that walked the whole path. A single terminal assertion cannot tell you which hop ran, and a chain whose middle hop never executed is not a chain.
- **Declare the assertion signature before the run, naming the joint.** "It failed" is not a signature. `AssertionError: hop 3 accepted the reset token minted at hop 1 - 200 with body containing CANARY-SUBJECT-A-R1` is.

### C2 — The patch check a chain adds

A chain has a cheapest break point, and the post-patch run must show **the chain** broken rather than one hop tidied. The same command, before and after — one `command` field, no equivalent substitute.

1. Re-run C1 and assert the composition now fails at the patched joint, naming which joint.
2. Then confirm the remaining components' own tests **still fail**. They are still findings; they do not disappear because the chain did, and a patch report that quietly drops them has converted three findings into one.
3. Then the project's own relevant regression tests, per the shared rails: a patch that breaks the chain by breaking the feature is not a patch.

### Where the rails stop a chain, and what that costs

- **A terminal hop that can only be shown by damage** — delete the tenant's data, issue the refund, send the mail, make the payment — is written and not executed: `proof_tier: T3`, `verification_status: UNPROVEN`, capped at Medium, with the blocking reason named. Demonstrate authorization and reachability up to the destructive call and assert on the call, not its effect.
- **A hop that leaves this machine is never repository proof.** The repository-proof chain stops at the last local hop and records the remaining hops as unproven steps. An accepted authenticated operator statement that names the external destination, scope, effect, and any credential use authorizes a separate external-evidence route without another prompt; the operator is accountable for that statement, and the auditor does not independently adjudicate legal authority. Execution requires a matching implemented destination-bound controller and explicitly supplied or controller-referenced credential material. If either is absent, record the technical transport or credential gap as `UNPROVEN`; authority does not conjure either. Never infer a destination from repository configuration, and never promote an external observation into a repository proof tier.
- **Where a component's own proof is unavailable** — an authorized boot with no matching implemented controller, a stubbed engine, a runner out of rails — the chain is capped by that component. Record which one, by `candidate_id`. "The chain is unproven" is not a finding anybody can act on; "hop 2, `<id>`, is `UNPROVEN` because the T2 boot has a technical transport gap" is. Do not ask the operator to re-authorize a boot already named in the accepted statement.

### Where no shared component applies, plainly

**No component in `_harness.md` demonstrates a composition.** C1 is assembled from the components named above, and the discipline that makes it a chain proof — carry the artifact, assert per hop, name the joint in the signature — lives here because no shared component encodes it. Should a second lens ever need it, that is the trigger for a harness section rather than a reason to add one now.

The **detector-and-fixture-pair runner** and the **local log and artifact collector** have no role in this lens. There is no static rule to run in two directions and no build output to collect — unless a *component* is itself a supply-chain or infrastructure finding, in which case that component's proof is that lens's work and this lens cites its result.

The **capturing log handler** applies only in the narrow case where the value carried across a joint is one that a log emits; assert on the sink the next hop actually reads, not on the log line, unless the log *is* that sink.
