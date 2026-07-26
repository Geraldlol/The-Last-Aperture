# red-team-audit: enhancement and open-source release

**Date:** 2026-07-26
**Status:** Approved design, pending implementation plan
**License target:** MIT
**Companion:** `2026-07-26-recon-punch-list.md` — a 22-agent recon pass over the existing reference files and the external facts they cite. It carries the per-lens correction list, the topic-ownership assignment, seed content for the new lens sections, the verified packaging schema, and the fixture proposal. This spec records decisions; the punch list records the evidence behind them.

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
│           ├── _topics.md           # canonical topic-slug registry
│           ├── web-and-api.md
│           ├── mobile-app-security.md      # renamed from mobile.md
│           ├── llm-and-ai.md
│           ├── cloud-and-iac.md
│           ├── cicd-and-supply-chain.md
│           ├── crypto-deep-dive.md
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
├── scripts/lint-lenses.mjs
├── docs/design/
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
owns: [http-authz, cors, csrf, xss, open-redirect, ssrf-http, rate-limiting, security-headers]
defers:
  secrets-management: cicd-and-supply-chain
  jwt-algorithm-confusion: crypto-deep-dive
  phi-handling: hipaa-and-phi
frameworks: [OWASP-Top-10, OWASP-API-Top-10, OWASP-ASVS]
severity_floor: low
---
```

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

`scripts/lint-lenses.mjs`, run by `.github/workflows/lint-lenses.yml` on every pull request, asserts:

1. Every lens has all required frontmatter keys.
2. No topic slug appears in more than one lens's `owns`.
3. Every slug in `_topics.md` is owned by some lens.
4. Every slug used as a key in any `defers` map is owned by the lens named as its value.
5. Cross-cutting lenses have empty `activates_on`; non-cross-cutting lenses do not.

Without this, the non-overlap property is a promise in a document that a contributor can break without noticing. With it, breaking the property fails the build.

### 4.4 Candidate-finding schema

`lenses/_schema.md` defines what every lens returns, so merging is mechanical.

| Field | Type | Notes |
|---|---|---|
| `lens` | string | Originating lens `name` |
| `title` | string | Short, specific |
| `severity` | Critical / High / Medium / Low / Info | No hedged pairs |
| `location` | `file:line`, one or more | Multiple sites allowed after semantic dedup |
| `cwe` | string | CWE identifier where one applies |
| `evidence` | quoted code | The actual vulnerable text, not a paraphrase |
| `attack` | string | Concrete payload, request, or sequence |
| `impact` | string | What the attacker gets |
| `reachable_from` | entry point name, or `unknown` | Required |
| `confidence` | High / Medium / Low | Auditor's own calibration |
| `proof_plan` | string | How this could be proven, for the proof phase to execute |

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
3. **Reachability gate** — `reachable_from: unknown` caps at Medium pending proof.
4. **False-positive sweep** — each candidate re-checked against its own lens's `Known false positives`.
5. **Cross-cutting lenses run** — `attack-chaining`, `business-logic`, and `completeness` read the merged set, which is the only point at which they have the input they need.
6. **Chain elevation** — Mediums that compose into account takeover, data exfiltration, or privilege escalation are raised, with the chain written out step by step.

### Phase 3: Prove

Per surviving Critical and High. See section 6.

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

| Tier | Mechanism | Severity cap | Availability |
|---|---|---|---|
| T0 | Static reasoning with a cited code path | Medium | Always |
| T1 | Failing test in the project's own framework, executed | None | Default, when a test framework exists |
| T2 | Application booted locally, real request to `localhost` | None | Opt-in, when the app boots clean. The skill asks before booting anything, every time; there is no persistent opt-in. |
| T3 | Written PoC, never executed, tagged `UNPROVEN` | Medium | Fallback |

### Three outcomes, not two

- Test **fails** before the patch: **confirmed.** Report at full severity.
- Test **passes** before the patch: the vulnerability is not there. **Drop the finding.** Record it in `Coverage` as disproved.
- Test could not be written or run: **`UNPROVEN`.** Report anyway, capped at Medium, with the reason stated.

Separating *disproved* from *unproven* is the mechanism that removes false positives rather than merely flagging them. Today's skill cannot distinguish the two, so both ship as findings at full severity.

### Rails

Stated in `SKILL.md` as non-negotiable, because the proof phase is the only part of the skill that executes anything:

1. Targets are files in this repository and `localhost`. Never a remote host, never a hostname read from configuration or environment.
2. No destructive payloads, even locally. Prove by observation, not by `DROP TABLE` or `rm -rf`.
3. Security tests are written to their own directory. Existing project tests are never edited.
4. Never commit. Changes are left staged for the user.
5. Never source production credentials to make a proof succeed.

### Rail mode, chosen per audit

Before Phase 3 begins, the skill asks which enforcement mode this audit runs under. The choice is per-audit and never remembered, because the right answer depends on what the repository is connected to today.

| Mode | Behaviour |
|---|---|
| **Guided** | Rails stated, T2 available. The skill self-polices and asks before booting anything. |
| **Restricted** | T2 is declined outright. Proof stops at T1, and findings that needed a running app are reported `UNPROVEN` rather than proven against a live process. |

Restricted mode is enforcement by self-restriction rather than by tooling, which is what makes it portable: it works identically on a harness with no hook system. For users who want mechanical rather than instructed enforcement across all sessions, the README documents an opt-in `PreToolUse` hook that denies non-loopback hosts and blocks `git commit` and `git push`. That hook is documented, never bundled as mandatory, and is Claude Code specific — which is exactly why it cannot be the primary mechanism.

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
| **A · Lens registry and content correction** | Restructure the ten reference files into lenses with frontmatter and the fixed skeleton. **Correct the content at the same time** — see below. Author `_topics.md` and `_schema.md`. Write the lint script and CI workflow. Apply the de-branding pass. | `node scripts/lint-lenses.mjs` exits zero, and every correction in punch list §1 is applied |
| **B · Orchestrator** | Rewrite `SKILL.md` as the six-phase pipeline. Author the three cross-cutting lenses. | `SKILL.md` ≤ 8 KB, no harness-specific tool named in normative text, lint still green with thirteen lenses |
| **C · Evaluation** | Build `fixtures/vulnerable/`, `fixtures/clean/`, and `EXPECTED.md`. Run the skill against every fixture. | Success criteria 3 and 4 |
| **D · Packaging** | Pin `plugin.json` and `marketplace.json` against the official reference. Write `README.md`, `CONTRIBUTING.md`, `AGENTS.md`, `LICENSE`. Swap the installed copy for a junction. | Success criteria 7 and 8 |

B depends on A. C depends on B. D can proceed in parallel with C, since packaging does not depend on fixture results.

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

1. `node scripts/lint-lenses.mjs` exits zero: all thirteen lenses have valid frontmatter, topic ownership is a partition, and every `defers` target is correct.
2. `SKILL.md` is 8 KB or smaller and names no harness-specific tool in normative text.
3. Running the skill against each `fixtures/vulnerable/` case reports the expected finding at the expected severity.
4. Running it against each `fixtures/clean/` case reports **zero findings at Low severity or above**.
5. On a repository with a working test framework, every reported Critical and High carries either an executed failing-then-passing test or an explicit `UNPROVEN` label with a reason.
6. On the same repository, the report includes a `Coverage` block naming any file or lens not examined.
7. The plugin installs from a local clone and the skill appears in the available-skills list.
8. `~/.claude/skills/red-team-audit` resolves through the junction to the repository, and no second copy of `SKILL.md` exists on disk.
9. Every bullet in every lens's `Known false positives` section has a corresponding case in `fixtures/clean/`.
10. Every literal string, filename, or API symbol a lens instructs an auditor to search for has been verified to occur in real code of that stack, or has been rewritten as a structural check.
11. The skill offers a rail mode before Phase 3, and Restricted mode declines T2 rather than merely warning about it.
12. `git log` shows no employer email address and no employer, tenant, product, or person name appears in any tracked file.

## 11. Deferred to v1.1

- Additional lenses: Rust and C++ memory safety, OAuth/OIDC/SAML protocol flows, Kubernetes and container runtime, desktop and Electron, data pipelines, smart contracts.
- A deterministic orchestration script for Claude Code, which is a small addition once the lens registry exists and is not needed for correctness.
- Automated fixture scoring.
- A GitHub Action that runs the audit on pull requests.

## 12. Risks

| Risk | Mitigation |
|---|---|
| Proof phase edits a user's repository in ways they did not expect | Rails in section 6: dedicated test directory, never commit, changes left staged and reported. |
| Recon mis-scopes a large repository and the audit silently covers a fraction of it | Recon map surfaced before fan-out; `Coverage` block mandatory; completeness critic in phase 6. |
| Lens content ages faster than anyone maintains it | Framework editions cited in lens bodies rather than in frontmatter, so an update touches one section. Contribution path optimised for single-lens PRs. |
| Thirteen lenses activating at once makes an audit expensive | `activates_on` restricts the active set to stacks actually present; `severity_floor` suppresses low-value output per lens. |
| Ownership of the material | **Resolved: the author confirms this is a personal project.** No further gating. |
| The corpus fingerprints its origin even after de-branding | Unscrubbable without changing coverage, and accepted. A reader who notes that `hipaa-and-phi` is among the most detailed lenses, that a Salesforce lens exists, that PHI needed removing from three unrelated lenses, and that a Microsoft 365 section was deleted can infer a US behavioural-health provider on Salesforce and M365. That is a category, not an identity. What *is* actionable is handled at release: commit-author email, and fixtures being synthetic rather than reduced from real code. |
| Publishing compliance verdicts under a personal name | `hipaa-and-phi` and `privacy-and-compliance` keep their verdict language, gated behind a prominent "not legal advice, no attorney-client relationship, verify against current OCR / EDPB / PCI SSC guidance" banner in the README **and** at the top of both lens bodies. |
