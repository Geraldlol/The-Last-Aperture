# red-team-audit: enhancement and open-source release

**Date:** 2026-07-26
**Status:** Approved design, pending implementation plan
**License target:** MIT
**Companions:**
- `2026-07-26-recon-punch-list.md` — a 22-agent recon pass over the existing reference files and the external facts they cite. Carries the per-lens correction list, seed content for the new lens sections, the verified packaging schema, and the fixture proposal.
- `2026-07-26-recon-punch-list-repair.md` — the complete topic-ownership assignment (165 slugs, 350 deferrals, 13 frontmatter blocks, the overlap resolution table) plus an adversarial invariant verification that found fifteen defects invisible to the originally specified lint rules.

This spec records decisions; the companions record the evidence behind them.

## 1. Purpose

Turn the existing `red-team-audit` skill from a single-pass prose auditor into a verifying audit pipeline, and publish it as an MIT-licensed open-source project that works both as a portable markdown skill and as an installable Claude Code plugin.

Two goals, and they reinforce each other. The pipeline is what makes the project worth publishing; publishing is what forces the pipeline to be legible to people who did not write it.

### Goals

1. Every Critical and High finding ships with a proof artifact, or is labelled as unproven and capped in severity.
2. An audit can cover a whole repository, not just pasted code.
3. Findings are deduplicated and reachability-checked before they reach the user.
4. Domain coverage grows by adding one file, with no changes to the orchestrator.
5. The skill runs on any agent harness that can read markdown; Claude Code users additionally get real parallel orchestration.
6. Anyone can verify the skill works, and any contributor can prove a change does not regress it.

### Non-goals

- Not a scanner. This is an adversarial reading pipeline that uses tests as evidence, not a rules engine competing with Semgrep or CodeQL.
- Not a live pentest tool. Targets are the local repository and `localhost`, never remote or production systems.
- Not a CI product for v1. It runs inside an agent session.

## 2. What exists today

`SKILL.md` (18.7 KB) plus ten reference files (8.5-12.9 KB each), roughly 118 KB total. Content quality is high: a two-phase attack/patch workflow, an honest severity rubric, a routing table over domain references, an auto-trigger on commit and deploy language, plus HIPAA and threat-modeling modes.

Four structural problems:

| Problem | Consequence |
|---|---|
| Findings are prose with no verification step | No way to separate a real bug from a plausible-sounding one. This is the single biggest credibility gap. |
| Implicitly assumes pasted code or a small diff | No recon phase, so a whole-repo audit either blows context or silently covers a fraction of the code. |
| Reference files have no declared scope boundaries | Two references covering adjacent ground produce the same finding twice, and there is no merge step to catch it. |
| Two identical copies on disk | `~/.claude/skills/red-team-audit` and the working copy have the same hash today and no mechanism keeping them that way. |

The modes are also implemented as parallel structures rather than as variations on one flow, which triples the surface that has to stay consistent.

## 3. Decisions

Each of these was decided explicitly. Rationale is recorded because the reasoning matters more than the choice when someone revisits it.

| Decision | Choice | Why |
|---|---|---|
| Distribution | Portable markdown core plus a thin Claude Code plugin wrapper | Widest audience for small extra cost. A Claude-Code-only design makes the portable path an untested fallback. |
| Architecture | Lens registry: each reference becomes a self-contained dispatchable auditor | Collapses two taxonomies into one file per domain. Adding coverage becomes a single-file PR. |
| Proof mechanism | Tiered: static, repo-local test, optional local dynamic run, written-PoC fallback | A test that flips from failing to passing is the strongest evidence obtainable without a live target. Tiers keep it usable in repos that will not boot. |
| License | MIT | Maximum adoption, minimum friction, matches the norm for skill packs. |
| Evaluation | Committed fixture corpus with vulnerable and clean cases | Reproducible, reviewable, and the clean cases test the failure mode that actually erodes trust. |
| Coverage breadth | Deferred to v1.1 | Unbounded content authoring. Shipping must not wait on writing a Rust memory-safety document. |

## 4. Architecture

### 4.1 Repository layout

The repository root is the plugin root. The skill lives one level down, which is what Claude Code's plugin discovery expects.

```
red-team-audit/                      # repo root == plugin root
├── .claude-plugin/
│   ├── plugin.json                  # plugin manifest
│   └── marketplace.json             # lets users add this repo as a marketplace directly
├── skills/
│   └── red-team-audit/
│       ├── SKILL.md                 # orchestrator only
│       └── lenses/
│           ├── _schema.md           # candidate-finding contract
│           ├── _topics.md           # GENERATED from frontmatter — never hand-edited
│           ├── _harness.md          # shared proof-harness pieces lenses reference by name
│           ├── web-and-api.md
│           ├── mobile-app-security.md      # renamed from mobile.md
│           ├── llm-and-ai.md
│           ├── cloud-and-iac.md
│           ├── cicd-and-supply-chain.md
│           ├── crypto-and-key-management.md    # renamed from crypto-deep-dive.md
│           ├── salesforce-platform.md      # renamed from salesforce.md
│           ├── hipaa-and-phi.md
│           ├── privacy-and-data-protection.md   # renamed from privacy-and-compliance.md
│           ├── threat-modeling.md
│           ├── attack-chaining.md   # cross-cutting
│           ├── business-logic.md    # cross-cutting
│           └── completeness.md      # cross-cutting
├── fixtures/
│   ├── vulnerable/
│   ├── clean/
│   └── EXPECTED.md
├── .github/workflows/lint-lenses.yml
├── scripts/
│   ├── lint-lenses.mjs          # R1–R6, plus the migration-ledger gate
│   └── gen-topics.mjs           # emits _topics.md and the overlap table from frontmatter
├── docs/
│   ├── migration-ledger.tsv     # every source check → destination → disposition
│   └── design/
├── AGENTS.md                        # entry point for Codex, Cursor, and similar
├── CONTRIBUTING.md
├── README.md
└── LICENSE
```

`SKILL.md` shrinks from 18.7 KB to a target of 8 KB or less. Everything domain-specific moves into a lens; what remains is the pipeline, the severity rubric, the safety rails, and the routing rule.

`docs/design/` rather than `docs/superpowers/specs/`: this repository is public, and internal tooling conventions should not leak into a published artifact.

### 4.2 The lens contract

Every lens carries frontmatter so activation and ownership are mechanical rather than re-derived on each run.

```yaml
---
name: web-and-api
title: Web and API security
cross_cutting: false
activates_on:
  paths: ["**/routes/**", "**/controllers/**", "**/api/**", "**/middleware/**"]
  signals: ["express", "fastapi", "gin-gonic", "graphql", "@app.route", "actix-web"]
owns: [authz-object-level, cors-policy, csrf, xss-and-output-encoding, open-redirect,
       ssrf-application-path, rate-limiting-and-request-quotas, security-headers-and-csp]
defers:
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  jwt-jws-and-jwks-verification: crypto-and-key-management
  phi-classification: hipaa-and-phi
frameworks: [owasp-top-10, owasp-api-top-10, nist-sp-800-63b]
severity_floor: low
---
```

**This block is illustrative, not normative.** The authoritative values live in the generated ownership artifact described in §4.3 — a prose example in a design document is exactly the kind of second source of truth that drifts. `owasp-asvs` is deliberately absent: the existing file's "ASVS L1/L2" claim is not traceable to any ASVS requirement ID, and 5.0.0 renumbered the catalogue, so the identifier is not claimed until real requirement IDs appear in the body.

Framework identifiers are unversioned in frontmatter; specific editions and versions are cited in the lens body, where they can be updated without touching the machine-readable contract.

Cross-cutting lenses set `cross_cutting: true`, carry an empty `activates_on`, and declare `owns: []`. They activate on the presence of findings rather than on file paths, and they run in triage rather than in fan-out. Owning no topic slugs is correct for them: they reason over other lenses' output instead of claiming territory of their own.

Fixed body skeleton, so a lens can be handed to a subagent verbatim with no wrapper prose:

| Section | Purpose |
|---|---|
| `## Scope` | What this lens owns, and an explicit list of what it does not own |
| `## Checklist` | Domain content, largely carried over from today's reference files |
| `## Severity calibration` | Domain-specific severity calls that override the general rubric |
| `## Known false positives` | Patterns that look like vulnerabilities in this domain and are not |
| `## Proof recipes` | How to write a failing test for this domain's bug classes |
| `## Report format override` | **Optional.** Only for lenses whose mode replaces the standard report. Used by `hipaa-and-phi`; absent everywhere else. |

`Known false positives` and `Proof recipes` are new content and are the two sections that carry the enhancement. The first is where precision comes from; the second is what makes the proof phase tractable inside a domain.

`severity_floor` sets the lowest severity this lens may report on its own. A lens with `severity_floor: medium` drops its own Lows before triage, which suppresses domain noise without hiding anything that matters. Chain elevation in phase 2 overrides the floor, since a suppressed Low that participates in a chain is reported as part of that chain.

### 4.3 Topic ownership, and enforcing it

`lenses/_topics.md` holds the canonical list of topic slugs. The invariant: **every slug is owned by exactly one lens.** This is what prevents duplicate findings by construction instead of cleaning them up afterwards.

The registry is larger than it sounds: the assignment produced **165 slugs across the ten activating lenses with 350 deferrals between them**, which becomes **164** once the pseudonymisation duplicate below is resolved. At that scale nobody maintains consistency by reading carefully, which is the entire argument for machine enforcement.

### One canonical representation, everything else generated

**Lens frontmatter is the single source of truth.** Nothing else is authoritative. `_topics.md`, the overlap resolution table, every slug count, and the deferral report are all **generated from frontmatter**, never hand-maintained alongside it.

This is a correction to how the design work itself was done. The ownership assignment currently exists as prose spread across two companion documents, and they already disagree: this spec resolves the pseudonymisation duplicate while the repair companion still assigns and registers the slug, which is also why the two documents state incompatible counts. Any number written by hand in prose is a claim; only a generated number is a fact.

Concretely, the first deliverable of Phase A is a normalised machine-readable assignment extracted from the two companions, plus `scripts/gen-topics.mjs` that emits `_topics.md` and the overlap table from the thirteen frontmatter blocks. After that point, a slug count appearing anywhere in prose is a bug, not a statement. Implementation agents read one artifact, never reconcile two prose documents.

`scripts/lint-lenses.mjs`, run by `.github/workflows/lint-lenses.yml` on every pull request, asserts:

| # | Rule |
|---|---|
| R1 | No topic slug appears in more than one lens's `owns`, and no lens both owns and defers the same slug |
| R2 | The registry is exactly the union of all `owns` lists — no unowned entries, no missing ones |
| R3 | Every `defers` key resolves to the lens that actually owns that slug |
| R4 | Every registry slug has exactly one row in the overlap resolution table |
| R5 | Slug orthography is consistent — one spelling convention, enforced by regex |
| R6 | Every lens has all required frontmatter keys; cross-cutting lenses have empty `activates_on` and `owns: []` |

### Why R1–R3 alone are not enough

An adversarial verification pass over the completed ownership assignment found **fifteen real defects, every one of which passes R1, R2 and R3.** That result is more useful than a clean bill of health, and it is why R4 and R5 exist:

- **The overlap table had 158 rows for 165 slugs.** Seven slugs were owned but never appeared in the table. R1–R3 never look at the table, so nothing caught it. R4 does.
- **Ten `defers` keys were missing entirely.** R3 only validates keys that *exist*, so a lens that keeps reporting a topic another lens absorbed is invisible to it. The strongest example: `mobile-app-security` still declares `__DEV__` and `android:debuggable` as activation signals for a topic the table says `web-and-api` absorbed — the lens advertises a signal for a topic it neither owns nor defers.
- **The slug namespace mixed British and American spelling** — `payment-page-script-authorisation` sitting three slugs from `rag-retrieval-authorization`. A typo hazard with no detector. R5 fixes it; the convention is American `-ization`.

**32 of 165 slugs have zero inbound `defers` references.** For those, no rule constrains anything, so nothing detects a lens quietly starting to report one. Only the `completeness` lens would notice. This is a known and accepted gap in v1: the rule that would close it — *every pair of lenses whose bodies both discuss a slug must have a `defers` entry* — requires the lens bodies, which do not exist until Phase A is done. It becomes a Phase B addition, not a v1.1 deferral.

Two things CI must special-case rather than flag:

1. The three cross-cutting lenses have `owns: []` and `defers: {}`, so R1 and R3 are vacuous for them and R2 must not expect them to own anything.
2. `web-and-api` owns `client-trusted-business-rules` and `race-conditions-and-toctou`, but `business-logic` is the lens that *raises* findings against them. Any rule inferring ownership from which lens emitted a finding will misfire here. Ownership is declared, never inferred.

### One genuine ownership breach, resolved

The same pass found a single real duplication that a string comparison cannot see: `hash-as-pseudonym-reversibility` (crypto) and `pseudonymisation-and-reidentification-risk` (privacy) are one defect on one line of code, split by *analysis type* rather than by code. Both lenses would fire on the same `sha256(ssn)` call. Every other parallel pair in the registry splits by regime or by platform — axes that partition code — and therefore does not duplicate.

**Resolution:** `privacy-and-data-protection` owns `pseudonymisation-and-reidentification-risk`; `crypto-and-key-management` contributes the reversibility proof as evidence under its existing deferral. The crypto-side slug is removed.

Four further renames make scope legible from the name rather than requiring the body: `client-cached-sensitive-state` → `lwc-client-state-exposure`, `hipaa-documentation-retention` → `hipaa-policy-documentation-retention`, `mobile-network-config-artifacts` → `mobile-cleartext-and-ats-config`, `native-module-provenance` → `vendored-native-code-provenance`.

### 4.4 Candidate-finding schema

`lenses/_schema.md` defines what every lens returns, so merging is mechanical.

The record accumulates fields as it moves through the pipeline. Written at fan-out, extended at triage, extended again at proof.

**Written by the lens at fan-out:**

| Field | Type | Notes |
|---|---|---|
| `candidate_id` | stable string | Required. Survives dedup, merge and re-runs; every later stage and every report line references it |
| `lens` | string | Originating lens `name` |
| `topic` | topic slug | **Required.** Topic ownership is the deduplication boundary, so a finding that does not carry its slug cannot be deduplicated by the mechanism the whole registry exists to provide |
| `title` | string | Short, specific |
| `claimed_impact_severity` | Critical…Info | What the impact would be if the finding is real and reachable. **Never overwritten** |
| `location` | `file:line`, one or more | Multiple sites allowed after semantic dedup |
| `cwe` | string | CWE identifier where one applies |
| `evidence` | quoted code | The actual vulnerable text, not a paraphrase |
| `attack` | string | Concrete payload, request, or sequence |
| `impact` | string | What the attacker gets |
| `reachable_from` | entry point name, or `unknown` | Required |
| `confidence` | High / Medium / Low | Auditor's own calibration |
| `proof_plan` | string | How this could be proven, for the proof phase to execute |

**Added at triage:**

| Field | Type | Notes |
|---|---|---|
| `effective_severity` | Critical…Info | After reachability capping, floors and chain elevation. Derived; `claimed_impact_severity` remains readable beside it |
| `triage_disposition` | `queued` / `merged` / `dropped` / `elevated` | What triage did to it |
| `drop_reason` | string | Required when dropped. A drop with no reason is indistinguishable from a loss |
| `raised_by` | lens name | Set when a cross-cutting lens elevated it |
| `component_finding_ids` | `candidate_id[]` | For chain findings: the components that compose into it |

**Added at proof:**

| Field | Type | Notes |
|---|---|---|
| `proof_tier` | T0 / T1 / T2 / T3 | Tier actually reached, not attempted |
| `verification_status` | see §6 | `CONFIRMED` / `NOT_REPRODUCED` / `INCONCLUSIVE` / `DISPROVED` / `UNPROVEN` |
| `artifact` | path + hash | The test file or capture, hashed so the report is checkable after the fact |
| `command` | string | The exact command run. **Identical before and after the patch** |
| `pre_result` | structured | Outcome before the patch, including the assertion that fired |
| `post_result` | structured | Outcome after the patch |

Separating `claimed_impact_severity` from `effective_severity` is what breaks the deadlock described in §5.

`reachable_from` is required and is the cheapest precision mechanism in the design. Forcing the auditor to name the path from untrusted input to the vulnerable line, at the moment it writes the finding, eliminates a large class of findings about code nothing can reach. `unknown` survives to triage but caps at Medium unless a proof lands.

## 5. Pipeline

### Phase 0: Recon

One pass, no findings. Produces a repo map: entry points (HTTP routes, CLI commands, queue consumers, webhooks, scheduled jobs), where authentication and authorization are actually enforced, trust boundaries, data stores and which hold sensitive data, outbound calls, secret handling, the test framework and its run command, and how the application boots.

Then it matches the repository against every lens's `activates_on.paths` and `activates_on.signals` to compute the active lens set.

Recon is what makes whole-repo audits work: fan-out auditors receive a scoped file list, never "the repository." Its map is surfaced to the user before the expensive phase, so a wrong scope can be corrected while it is still cheap.

### Phase 1: Fan-out

One auditor per active lens. Each receives its lens file verbatim, the repo map, its assigned file list, and `_schema.md`. Each returns candidate findings only, in schema form. No prose reports, no patches, no severity negotiation.

Cross-cutting lenses do not run here.

### Phase 2: Triage

Strict order, because later steps depend on earlier ones:

1. **Structural dedup** — identical `file:line` plus `cwe` collapses; highest confidence wins.
2. **Semantic dedup** — one root cause at several sites becomes one finding with several locations.
3. **Reachability gate** — `reachable_from: unknown` sets `effective_severity` to Medium. It does **not** overwrite `claimed_impact_severity`, and it does **not** remove the finding from the proof queue.
4. **False-positive sweep** — each candidate re-checked against its own lens's `Known false positives`.
5. **Cross-cutting lenses run** — `attack-chaining`, `business-logic`, and `completeness` read the merged set, which is the only point at which they have the input they need.
6. **Chain elevation** — Mediums that compose into account takeover, data exfiltration, or privilege escalation are raised, with the chain written out step by step.

### Phase 3: Prove

**The proof queue is built from `claimed_impact_severity`, not from `effective_severity`.** Every candidate whose claimed impact is High or Critical is enqueued, including those triage capped to Medium for unknown reachability.

Ordering the other way round deadlocks, and the earlier draft of this spec did exactly that: triage capped unknown-reachability findings to Medium, proof only accepted Critical and High, so the findings whose reachability most needed resolving were the precise set that could never reach the phase that resolves it. A capped finding stayed capped forever, and the cap looked like a considered severity judgement rather than an artifact of queue ordering.

The final severity is therefore computed **after** proof, not before it:

1. Enqueue on `claimed_impact_severity` ≥ High.
2. Run the tiered proof (§6). A successful proof establishes reachability as a side effect — a test that drives the vulnerable path from an entry point *is* the reachability evidence.
3. Apply the final cap using what proof returned: reachability now known and confirmed lifts the Medium cap; still-unknown reachability keeps it, and the report says which.

See section 6 for the tiers and the verification states.

### Phase 4: Patch

As today, with one addition: the patch must make its own proof pass. A patch that does not flip its test from failing to passing is not accepted as a patch.

### Phase 5: Report

Today's output format, plus a mandatory `## Coverage` block stating: which lenses ran, which did not and why, files never examined, findings dropped in triage with the reason, and the proof tier each surviving finding reached.

Silent truncation reads as complete coverage. If 60% of the repository was examined, the report says 60%.

### Phase 6: Completeness critic

A final pass over the finished report asking what was never examined: a lens that should have activated and did not, an entry point with no findings and no explanation, a data store nobody looked at. Output either loops back into a second fan-out or is written into `Coverage` as a stated gap.

### Degradation

| Harness capability | Phase 1 becomes |
|---|---|
| Claude Code subagents | Real parallel fan-out, one agent per active lens |
| Any other subagent primitive | Same, mapped onto that primitive |
| No subagents | Sequential lens passes in one context |

Identical lens files, identical schema, identical triage in all three cases. Only wall-clock time differs. This is what the portable core buys, and it is why `SKILL.md` must not name harness-specific tools in its normative text.

### Modes

Three overlays on one pipeline, replacing today's three parallel structures:

- **General** — the pipeline as written.
- **HIPAA / PHI** — `hipaa-and-phi` force-activated regardless of path matching, plus that lens's report format.
- **Threat model** — input is architecture rather than code, so file-scoped fan-out is skipped and `threat-modeling` runs against the described system.

Auto-trigger behaviour on commit and deploy language is carried over unchanged.

## 6. Proof tiers and safety rails

Tier describes **what evidence exists.** Capability mode, below, describes **what the skill is permitted to do.** They are orthogonal, and conflating them was the defect that made the earlier "Restricted" mode meaningless.

| Tier | Mechanism | Severity cap | Requires mode |
|---|---|---|---|
| T0 | Static reasoning with a cited code path | Medium | Static |
| T1 | Detector or failing test executed by the project's own runner | None | Isolated test |
| T2 | Application booted locally, real request to a loopback socket | None | Local dynamic |
| T3 | Written PoC, never executed, tagged `UNPROVEN` | Medium | Static |

A static checker counts as T1, not T0, when the repository's own test runner executes it and it asserts both directions — `detect(vulnerable) == 1` **and** `detect(clean) == 0`. Without that rule every cloud/IaC and CI/CD finding caps at Medium the moment dynamic proof is unavailable, which systematically under-rates the two domains with the largest blast radius. A detector that only passes on good input proves nothing about detection.

### The proof oracle

A test result is not a verdict. "The test failed" can mean the vulnerability is real, or that an import blew up. "The test passed" can mean the code is safe, or that the test never reached the vulnerable line. The earlier two-outcome rule treated both ambiguities as certainties, in opposite directions — it could falsely confirm *and* falsely disprove.

**A result counts as evidence only when all five hold:**

1. **A declared assertion signature** — the specific security assertion, or the observable failure signature, named *before* the run. "It failed" is not a signature; `AssertionError: expected 403, got 200 with body containing other_user_email` is.
2. **Path-reached evidence** — proof the vulnerable line executed. A log line, a spy, a coverage marker, an injected canary observed downstream.
3. **A control** — a positive control that must fail, or a sensitivity control showing the test detects the condition when it is present. This is what distinguishes a test that passes because the code is safe from one that passes because it tests nothing.
4. **The identical command before and after the patch.** Not an equivalent command. The same string.
5. **The project's relevant regression tests passing after the patch** — a patch that blocks the attack by breaking the feature is not a patch.

**Five states, not three:**

| State | Meaning | Reported as |
|---|---|---|
| `CONFIRMED` | Assertion fired pre-patch, passed post-patch, all five conditions met | Full severity |
| `NOT_REPRODUCED` | Oracle valid, ran correctly, the predicted behaviour did not occur | Withdrawn from findings, recorded in `Coverage` |
| `INCONCLUSIVE` | Setup failed, path never reached, control failed, or the oracle was invalid | Reported, capped at Medium, with the specific reason |
| `DISPROVED` | A validated oracle showed the code is not vulnerable, **or** the finding's code premise was falsified | Removed, with the falsified premise stated |
| `UNPROVEN` | No proof attempted or possible in the current capability mode | Reported, capped at Medium, with the blocking reason |

`DISPROVED` is now a strong claim requiring a validated oracle or a falsified premise. Everything that used to collapse into it — an import error, a test that never reached the path, a missing fixture — lands in `INCONCLUSIVE` instead. The earlier design would have silently deleted real findings on the strength of a `ModuleNotFoundError`.

### Capability modes, chosen per audit

Modes are defined by **capability granted**, not by tier permitted. The earlier design got this backwards: it defined "Restricted" as T1-only and called that a safety boundary. It isn't one. T1 runs the repository's own test command, which can execute lifecycle hooks, run migrations, start Docker containers and emulators, emit telemetry, and reach remote services using whatever ambient credentials are in the environment. "Only T1" grants arbitrary code execution with the user's full credential set.

Binding to loopback does not help either. The proof request goes to `localhost`, but the application under test reads `DATABASE_URL` from `.env` and connects wherever that points — including production.

| Mode | Capability | Requirements |
|---|---|---|
| **Static** | No writes, no execution | T0 and T3 only. Nothing runs. Always available, always safe. |
| **Isolated test** | Runs the project's test command | Explicit consent. Sanitised environment. No implicit installs. Egress denied where the platform permits, with the achieved level declared. Wall-clock timeout. Process-tree cleanup. |
| **Local dynamic** | Boots the application | Everything above, plus a disclosed boot manifest, a disposable datastore, a literal loopback bind, a random port the skill owns, and guaranteed teardown. |

Asked before Phase 3, per audit, never remembered — the right answer depends on what the repository is wired to today, not on what it was wired to last week.

**The sanitised environment is the real control**, not the loopback binding. Before any execution: credential-shaped variables are withheld rather than inherited, cloud credential files are not mounted, and any variable the repository's own configuration reads for a datastore or API endpoint is redirected to a disposable local instance or removed. If a test cannot run without a credential, that is reported as `INCONCLUSIVE`, not solved by supplying the credential.

**Honest limits, stated in the README rather than implied away:**

- Egress denial is not portable. It requires OS-level isolation — Linux network namespaces, cgroups, or a container. On Windows or macOS without Docker there is no mechanism a markdown skill can invoke. Where it cannot be enforced, Isolated mode **says so and asks** rather than claiming isolation it does not have.
- The optional `PreToolUse` hook is weaker than a sandbox. It inspects a command string; it cannot see syscalls inside a child process. It stops `curl https://prod.example.com`. It does not stop a test that opens a socket.

### Filesystem and Git transaction contract

A dedicated test directory is not containment. Test runs also write coverage files, snapshots, caches, local databases, migration state, and whatever child processes decide to write. And automatically staging results is actively destructive: `git add` against a file with partially staged hunks discards the user's carefully split index.

Proof work therefore runs in a **disposable mirror or worktree**, and the original index is preserved byte-for-byte. The audit returns a manifest rather than a mutated repository:

1. **Owned paths** — every path the proof run created or modified — and the generated patch.
2. **Exact commands** run, and the environment policy applied.
3. **Pre and post results**, with artifact hashes so the report is checkable after the fact.
4. **Cleanup report**, including any process still running and any path deliberately left behind.

Staging remains supported, but only for **named files after explicit approval** — never as a default side effect, and never as a bulk `git add`.

This is about the portable default promised to downstream users. Authorisation for this particular repository is settled; the default is what ships to people who have not thought about it.

## 7. Evaluation

`fixtures/` holds at least twelve vulnerable cases and at least four clean ones, with `EXPECTED.md` as the manifest. The exact file list is enumerated in the implementation plan.

Vulnerable fixtures cover one bug class per major lens, each with the expected severity and CWE recorded in the manifest.

Clean fixtures are the more important half, and are deliberately adversarial toward the auditor: parameterized SQL assembled in a way that reads like concatenation, `dangerouslySetInnerHTML` fed a sanitized constant, MD5 used as a cache key rather than a password hash, `verify=False` confined to a test-only file. Each must produce **zero findings at Low severity or above**; an `Info` observation is acceptable, since Info is explicitly not a vulnerability claim. A skill that flags these as vulnerabilities will cry wolf on real repositories, and crying wolf is what makes security tooling get switched off.

`CONTRIBUTING.md` documents the procedure: run the skill against `fixtures/`, compare with `EXPECTED.md`, and report both misses and false positives. Automated scoring is out of scope for v1 because it requires driving an agent, not running a script.

**Every bullet in a lens's `Known false positives` section is backed by a case in `fixtures/clean/`.** This is what keeps those sections load-bearing rather than decorative: a false-positive rule with no canary behind it is an untested assertion, and an over-firing lens is caught by nothing else in the design. It also guards the inverse failure — a false-positive rule written so broadly that it suppresses a real finding — because the vulnerable fixture for the same bug class must still be caught.

**Vulnerable fixtures ship non-functional.** No working payloads, no real or realistic-looking credentials, `fixtures/` excluded from code scanning, and a README warning explaining why the directory exists. A repository of working exploits reads as a malware sample to scanners and to people, and would drown the project in Dependabot and CodeQL noise. Both `vulnerable/` and `clean/` fixtures are written from scratch, never reduced from real code.

## 8. Packaging and release

The plugin manifest and marketplace descriptor must validate against the current Claude Code plugin reference. The implementation plan includes an explicit step that reads the official plugin documentation and at least one known-good plugin manifest already installed on this machine, and pins the exact field set before publication; no manifest is written from recollection.

Requirements independent of the manifest's exact field set:

- `.claude-plugin/plugin.json` at the repository root.
- The skill discoverable at `skills/red-team-audit/SKILL.md`.
- `.claude-plugin/marketplace.json` present, so a user can add the GitHub repository directly as a marketplace.
- `SKILL.md` frontmatter keeps `name` and `description`. The description retains the trigger language that makes auto-triggering work, since that behaviour is load-bearing.
- `AGENTS.md` at the root as the entry point for harnesses that look for it, pointing at `skills/red-team-audit/SKILL.md`.

### Source of truth

The repository is canonical. `~/.claude/skills/red-team-audit` is replaced with a directory junction into `skills/red-team-audit/` inside the repository, so editing the repository updates the installed skill and the two copies cannot diverge. The existing duplicate is removed only after the junction is verified to resolve.

### README

Claims are limited to what the design actually delivers: parallel lens fan-out, deduplication and reachability triage, proof-backed findings with an explicit unproven label, and a fixture corpus including false-positive canaries. It states plainly that this is not a scanner and does not replace SAST, and it does not claim detection rates that have not been measured.

### Attribution and disclaimers

- Copyright in the author's personal name. This is a personal project; no employer, tenant, product, or person names appear anywhere in the content.
- Commit history is authored from a personal email address. The two commits predating this decision are rewritten before any remote exists.
- A "not legal advice, no attorney-client relationship, verify against current OCR / EDPB / PCI SSC guidance" banner appears in the README and at the top of both `hipaa-and-phi.md` and `privacy-and-data-protection.md`.
- One `AS_OF: 2026-07` line in the README, plus an explicit note that the lenses are point-in-time and will drift. **No review cadence is promised** and no CI staleness check is added — a cadence is a commitment only a maintainer can make, and an unmet one is worse than none.
- **The pre-scrub reference files are never committed.** The existing `SKILL.md` and `references/` stay untracked until Phase A's de-branding pass is complete, so the first commit of lens content is already clean. Private-product residue in git history is exactly as durable as an email address in it, and much harder to notice. Named examples currently present and requiring removal before any commit: consumer-app feature names in the mobile lens, named-vendor BAA verdicts in the HIPAA lens, and a Microsoft 365 section.
- Date-bound content is neutralised rather than kept fresh. `frameworks` identifiers stay unversioned; named-vendor compliance verdicts are deleted rather than relocated; provider-specific guidance becomes an undated provider-agnostic questionnaire, because questions rot far more slowly than answers. Named incidents are cited with dates as illustrations, never as a current-threat inventory.

## 9. Implementation phasing

The work is large enough that a single undifferentiated plan would have no checkpoints. Four phases, each ending in something verifiable:

| Phase | Work | Checkpoint |
|---|---|---|
| **A · Lens registry and content correction** | Restructure the ten reference files into lenses with frontmatter and the fixed skeleton, **correcting the content in the same pass**. Author `_schema.md` and `_harness.md`; generate `_topics.md`. Write the lint and generator scripts. De-brand. Five internal gates, A0–A4, below. | A4 closes: lint green on R1–R6, and **zero unresolved migration-ledger entries** |
| **B · Orchestrator** | Rewrite `SKILL.md` as the six-phase pipeline. Author the three cross-cutting lenses. Add the body-aware lint rule now that bodies exist: every pair of lenses whose bodies both discuss a slug must have a `defers` entry. | `SKILL.md` ≤ 8 KB, no harness-specific tool named in normative text, lint green over thirteen lenses including the body-aware rule |
| **C · Evaluation** | Build `fixtures/vulnerable/`, `fixtures/clean/`, and `EXPECTED.md`. Run the skill against every fixture. | Success criteria 3 and 4 |
| **D · Packaging** | Pin `plugin.json` and `marketplace.json` against the official reference. Write `README.md`, `CONTRIBUTING.md`, `AGENTS.md`, `LICENSE`. Swap the installed copy for a junction. | Success criteria 7 and 8 |

B depends on A. C depends on B. D can proceed in parallel with C, since packaging does not depend on fixture results.

### Phase A internal gates

Phase A is large enough that "lint passes" is not a completion signal — lint checks metadata, and the risk in Phase A is losing *content*. Five gates:

| Gate | Work | Closes when |
|---|---|---|
| **A0** | Checksum a private baseline of `SKILL.md` and all ten references. Freeze the canonical schema, the thirteen lens names, and the normalised ownership assignment. | Baseline hashed; schema, names and ownership are frozen and machine-readable |
| **A1** | Migrate the ten lenses independently, recording every move in the migration ledger | All ten migrated, ledger rows written for each |
| **A2** | For every corrected search instruction, supply a positive and a negative detector example, plus the evidence for the correction | No corrected instruction lacks a demonstrated match |
| **A3** | Global validation: ownership, deferrals, schema conformance, and every `_harness.md` reference resolving | `lint-lenses.mjs` green; `gen-topics.mjs` output matches committed `_topics.md` |
| **A4** | De-branding and history scan | Zero unresolved ledger entries; no employer, tenant, product or person name in any tracked file |

The A0 baseline **stays untracked**, which matters because it collides with the release rule in §8: the baseline exists so migration can be verified against it, but it holds pre-scrub content and must never be committed. Checksums of it may be.

### The migration ledger

Phase A's checkpoint was originally metadata lint plus "every correction in punch list §1 is applied." Neither proves content was preserved, and the loss is not hypothetical: `references/web-and-api.md` currently delegates injection, deserialization and JWT handling back to `SKILL.md` with "Covered in main SKILL.md" — and Phase B rewrites `SKILL.md`. Those checks would evaporate with nothing detecting it.

So every check, heading, severity rule and citation in `SKILL.md` and all ten references gets a ledger row in `docs/migration-ledger.tsv`:

```
source_location → destination_lens/topic → disposition → evidence_id
```

with `disposition` one of `preserved`, `corrected`, `moved`, or `intentionally_removed`. **Phase A closes only at zero unresolved rows**, and `lint-lenses.mjs` enforces that gate rather than a human declaring it done. `intentionally_removed` is a valid disposition — silent removal is not.

Phase A's checkpoint also names punch list **§§4–6**, not just §1: the fixed body skeleton requires `Known false positives` (§4) and `Proof recipes` (§5), and Phase A owns the de-branding checklist (§6). A lens missing either new section is incomplete regardless of what lint says about its frontmatter.

Phase A needs only the deterministic contract tests that show a corrected check can actually fire. Full end-to-end agent evaluation stays in Phase C.

### Phase A is mostly content correction, not restructuring

A 22-agent recon pass over the existing reference files, recorded in `2026-07-26-recon-punch-list.md`, rates **nine of the ten as not publication-ready** — almost entirely for factual errors rather than structural problems. Restructuring and correcting are therefore the same pass, not sequential ones, and Phase A should be budgeted accordingly.

Three classes of error, in descending order of how much they matter:

1. **Checks that can never match real code** — eleven of them across six lenses. Grepping for `pwn-request` (a research label that never appears in a vulnerable workflow), `.pip.conf` (not a real filename), `Crypto.AES` (does not exist in PyCrypto or PyCryptodome), PyJWT `verify=False` (removed in 2.0), React Native `fetch` with `rejectUnauthorized` (ignored by the RN polyfill). These are worse than missing checks: they run, match nothing, and produce a **silent all-clear**.
2. **Advice that is inverted** — `crypto-deep-dive.md` labels a fresh per-call CSPRNG nonce as `VULNERABLE` and a monotonic counter nonce as `CATASTROPHIC`, and attributes GCM nonce reuse to key compromise rather than to GHASH subkey recovery. `cloud-and-iac.md` inverts AWS policy evaluation twice, claiming bucket policies override Block Public Access and that resource policies can override an identity-based `Deny`. Lenses in this state generate false positives against correct code.
3. **Framework claims that do not hold** — `SANS Top 25` is not a separate list (SANS co-branding ended after 2011); `web-and-api.md` claims ASVS L1/L2 while no requirement in it is traceable to an ASVS ID; two internal cross-references still use 2021 category numbering, so a reader chasing SSRF lands on exception handling.

Because unfireable checks are the highest-consequence class and cannot be caught by frontmatter linting, Phase A adds a review requirement: **every literal string, filename, or API symbol a lens tells an auditor to search for must be verified to occur in real code of that stack.** Where it cannot be, the check is rewritten structurally.

One correction the recon pass got wrong is worth recording, because it shows the failure mode: an inventory agent proposed "fixing" the `A09: Security Logging and Alerting Failures` heading. The independent fact-check confirmed that name is the official 2025 title. Applying the proposed fix would have broken name-based routing while citing a category OWASP never published. Where a lens inventory and the framework fact-check disagree, the fact-check wins.

## 10. Success criteria

Verifiable, in the order they can be checked:

1. `node scripts/lint-lenses.mjs` exits zero across R1–R6: ownership is a partition, every `defers` target resolves, every registry slug has exactly one overlap-table row, and slug orthography is uniform. No slug count is asserted here — counts are generated, and a count written by hand is a defect.
2. `SKILL.md` is 8 KB or smaller and names no harness-specific tool in normative text.
3. Running the skill against each `fixtures/vulnerable/` case reports the expected finding at the expected severity.
4. Running it against each `fixtures/clean/` case reports **zero findings at Low severity or above**.
5. On a repository with a working test framework, **every finding reported at Critical or High has `verification_status: CONFIRMED`** with T1 or T2 evidence attached — the declared assertion signature, path-reached evidence, a control, the identical pre/post command, and passing regression tests. `UNPROVEN`, `INCONCLUSIVE` and T0/T3 evidence all cap at Medium, so a Critical or High carrying any of them is a contract violation, not a judgement call. T2 request-and-response evidence satisfies this criterion exactly as an executed test does.
6. On the same repository, the report includes a `Coverage` block naming any file or lens not examined.
7. The plugin installs from a local clone and the skill appears in the available-skills list.
8. `~/.claude/skills/red-team-audit` resolves through the junction to the repository, and no second copy of `SKILL.md` exists on disk.
9. Every bullet in every lens's `Known false positives` section has a corresponding case in `fixtures/clean/`.
10. Every literal string, filename, or API symbol a lens instructs an auditor to search for has been verified to occur in real code of that stack, or has been rewritten as a structural check.
11. The skill asks for a capability mode before Phase 3, and each mode's tier ceiling is enforced rather than advertised: Static reaches T0/T3, Isolated test reaches T1, Local dynamic reaches T2.
12. `git log` shows no employer email address and no employer, tenant, product, or person name appears in any tracked file.
13. `node scripts/gen-topics.mjs` reproduces the committed `_topics.md` and overlap table byte-for-byte from frontmatter alone. Any divergence means a second source of truth has appeared.
14. `docs/migration-ledger.tsv` has zero unresolved rows, and every row's disposition is one of `preserved`, `corrected`, `moved`, `intentionally_removed`.
15. Every `_harness.md` component referenced by a lens's `Proof recipes` section exists and is referenced by name rather than re-described inline.
16. After a proof run, `git diff --cached` is byte-identical to what it was before the audit started, and the audit returned a manifest naming every path it touched and every process it left running.
17. In Static mode the skill executes nothing and writes nothing; in Isolated mode it states the egress-denial level it actually achieved on this platform rather than asserting isolation generically.

## 11. Deferred to v1.1

- Additional lenses: Rust and C++ memory safety, OAuth/OIDC/SAML protocol flows, Kubernetes and container runtime, desktop and Electron, data pipelines, smart contracts.
- A deterministic orchestration script for Claude Code, which is a small addition once the lens registry exists and is not needed for correctness.
- Automated fixture scoring.
- A GitHub Action that runs the audit on pull requests.

## 12. Risks

| Risk | Mitigation |
|---|---|
| Proof phase edits a user's repository in ways they did not expect | The transaction contract in §6: proof runs in a disposable mirror or worktree, the original index is preserved byte-for-byte, and the audit returns a manifest of owned paths, commands, results with hashes, and leftover processes. Staging happens only for named files after explicit approval. A dedicated test directory was the earlier mitigation and was insufficient — test runs also write coverage, snapshots, caches, local databases and migration state, and a bulk `git add` destroys partially staged hunks. |
| Proof execution reaches production despite loopback binding | The sanitised environment, not the binding, is the control: credential-shaped variables withheld, cloud credential files unmounted, datastore and endpoint variables redirected to disposable local instances. A test that cannot run without a real credential returns `INCONCLUSIVE` rather than being handed one. |
| Recon mis-scopes a large repository and the audit silently covers a fraction of it | Recon map surfaced before fan-out; `Coverage` block mandatory; completeness critic in phase 6. |
| Lens content ages faster than anyone maintains it | Framework editions cited in lens bodies rather than in frontmatter, so an update touches one section. Contribution path optimised for single-lens PRs. |
| Thirteen lenses activating at once makes an audit expensive | `activates_on` restricts the active set to stacks actually present; `severity_floor` suppresses low-value output per lens. |
| Ownership of the material | **Resolved: the author confirms this is a personal project.** No further gating. |
| The corpus fingerprints its origin even after de-branding | Unscrubbable without changing coverage, and accepted. A reader who notes that `hipaa-and-phi` is among the most detailed lenses, that a Salesforce lens exists, that PHI needed removing from three unrelated lenses, and that a Microsoft 365 section was deleted can infer a US behavioural-health provider on Salesforce and M365. That is a category, not an identity. What *is* actionable is handled at release: commit-author email, and fixtures being synthetic rather than reduced from real code. |
| Publishing compliance verdicts under a personal name | `hipaa-and-phi` and `privacy-and-data-protection` keep their verdict language, gated behind a prominent "not legal advice, no attorney-client relationship, verify against current OCR / EDPB / PCI SSC guidance" banner in the README **and** at the top of both lens bodies. |
