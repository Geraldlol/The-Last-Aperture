# Evidence-Class Boundary — Design

> **Superseded security notice (2026-09-03):** This is a historical design
> record, not current operational guidance. Every public acquisition command,
> plus audit `--evidence-bundle` import, is disabled
> before argument, caller-path, bundle, or process access. Review found that
> artifact paths could trigger UNC/device/pipe access and unbounded reads;
> evidence manifests did not authenticate semantic profile or plan identity;
> planning invoked PATH-resolved
> CLI probes (including a context-ambient `kubectl version`), serialized plans
> were mutable and
> could carry arbitrary executable/argument vectors, Kubernetes `context` was
> recorded but not bound to dispatch, stop-state read failures were fail-open,
> and metadata-only runtime file capture could retain secret-bearing lines.
> Re-enable only after controller-sealed canonical plans, command reconstruction from a
> fixed operation identifier, attested target identity, fail-closed stop state,
> and protected/redacted evidence storage are implemented and independently
> reviewed. Any contrary `run` examples or “read-only” guarantees below describe
> the old design and must not be followed.
> ADR 0021 also supersedes every signed-authorization or owner-artifact rule
> below. Only an authenticated operator target/scope statement creates authority;
> controller permits supply technical integrity and replay protection.

- **Date:** 2026-08-08
- **Status:** Historical; the public acquisition CLI and audit evidence import were superseded and disabled 2026-09-03.
- **Scope:** Phase 0 of a four-phase program (see *Program phases*)
- **Motivating incident:** DEF CON 34 Kubernetes Learning CTF — "Terminate Transfer", "Shell in the Ghost"
- **Canonical contracts this design extends:** `skills/red-team-audit/lenses/_schema.md`, `skills/red-team-audit/lenses/_topics.md`, `skills/red-team-audit/lenses/_harness.md`, `skills/red-team-audit/lenses/_database-adapters/contract.md`

## Directory note

The canonical lens registry is `skills/red-team-audit/lenses/` (15 lenses plus `_schema.md`, `_topics.md`, `_harness.md`, `_database-adapters/`). The ten files under `references/` at the repository root are a **legacy copy** with superseded names. This design edits the canonical registry only. Deciding the fate of `references/` is out of scope; do not delete it as a side effect of this work.

Canonical lenses:

`ai-generated-code`, `attack-chaining`, `business-logic`, `cicd-and-supply-chain`, `cloud-and-iac`, `completeness`, `crypto-and-key-management`, `database-and-data-stores`, `hipaa-and-phi`, `llm-and-ai`, `mobile-app-security`, `privacy-and-data-protection`, `salesforce-platform`, `threat-modeling`, `web-and-api`.

## Problem

Repository audits have exactly one evidence source: files in the repository. Lenses activate on `activates_on.paths` globs, so every lens reasons about the *recipe* and reports on the *result*.

`lenses/cloud-and-iac.md` activates on `**/Dockerfile`, `**/.dockerignore`, `**/k8s/**/*.y*ml`, `**/Chart.yaml` and similar. Given:

```dockerfile
COPY secret.txt /secret.txt
RUN rm /secret.txt
```

a source-only audit reads `RUN rm` and concludes the secret was removed. In an OCI image it was not: the deletion writes a `.wh.secret.txt` whiteout marker into the upper layer while the original bytes stay fully readable in the layer below.

**The machinery to prevent the resulting false clearance already exists.** `_database-adapters/contract.md:329` rules that `INVENTORY_ONLY` and `NOT_ASSESSED` are never rendered as pass, clean, secure, or no findings. What is missing is that **evidence class is not a dimension of coverage**, so "we examined the Dockerfile but never the image" is not expressible as a gap. The audit is silent about its own blind spot, and silence reads as clearance.

The gap is not container-specific:

| Lens | Reads today | Cannot reach |
|---|---|---|
| `cloud-and-iac` | Terraform, Dockerfiles, K8s manifests, Helm | deployed cloud and cluster state |
| `mobile-app-security` | app source | the built APK/IPA — same removed-but-recoverable problem |
| `cicd-and-supply-chain` | workflow YAML, lockfiles | the artifacts those pipelines emit |
| `crypto-and-key-management` | crypto code paths | the TLS/cipher configuration actually negotiated |
| `hipaa-and-phi` | code touching PHI | PHI actually at rest |
| `salesforce-platform` | repo metadata | live org state |
| `web-and-api` | route/handler source | responses actually served |
| `database-and-data-stores` | migrations, config | live grants and effective policy (already named as an open question at `contract.md:347`) |

That last row is the tell: the database contract **already says** "Unknown live grants, policy state, feature licensing, or drift are open questions. Static absence is not a clearance." It names the limitation precisely and has no mechanism to lift it. This design supplies the mechanism.

## Framing: this generalizes detection precedence

`_database-adapters/contract.md:435-444` already ranks evidence by authority for engine identification:

> 1. committed output produced by the server or engine; 2. an exact pinned server image/package; 3. provider resource configuration with an exact engine declaration; 4. migration-generator metadata; 5. SQL dialect; 6. driver or ORM package.
>
> "A lower-precedence signal never overrides a conflicting higher-precedence one."

Evidence classes are that principle promoted from one lens to the registry. A built artifact is a higher-precedence signal than the source that claims to produce it; runtime state is higher still. The rule carries over unchanged: **where classes disagree, the higher-precedence class wins and the conflict is recorded, never silently reconciled.**

This is deliberately not a new concept. It is an existing, proven concept applied one level up.

## Goals

1. Make evidence class a first-class, controller-owned dimension of coverage, expressed in the **existing** coverage vocabulary.
2. Let each lens declare which classes it can speak to, so absent evidence renders as a named gap rather than silence.
3. Provide four acquisition adapters behind one contract modeled on the database adapter contract.
4. Keep the repository control plane offline and read-only by quarantining network, credential, and runtime access in a separate control plane.
5. Extend `location` and `existence_check` so findings from non-repository evidence can be graded at all.
6. Prevent the audit tool from becoming a PHI breach surface of its own.

## Non-goals

- Replacing or absorbing `audit:http-recon`. It works, it is sealed, it stays.
- Any target mutation. That is Phase 3 and requires the hard-rail amendment recorded at the end.
- Moving detection logic into Node. Detection stays in lens prose and adapter rules.
- Introducing any new coverage state, verification state, or severity mechanism. This design adds **one dimension** to existing states and nothing else.

## Program phases

| Phase | Subsystem | Nature | Spec |
|---|---|---|---|
| **0** | Evidence-class boundary + four adapters | Cross-cutting foundation | **this document** |
| 1 | Container image forensics rules | First `built-artifact` consumer | future |
| 2 | Live in-cluster assessment | First `live-runtime` reader | future |
| 3 | Exploitation tier | Mutating, free-form supervised | future |

Phase 3 depends on Phase 2. Phase 1 is independent of both.

## Architecture

### Evidence classes

| Class | Definition | Precedence |
|---|---|---|
| `source` | Files in the repository under audit | 1 (lowest) |
| `built-artifact` | Packaged build output: OCI image, APK/IPA, jar, dist bundle | 2 |
| `deployed-state` | Configuration as it exists in a live system, read-only | 3 |
| `live-runtime` | Behavior or contents of a running instance | 4 (highest) |

Exploitation is **not** a class. It is a mutation tier layered on `live-runtime` in Phase 3.

`audit:http-recon` observations remain in their own protocol and are **not** retro-labelled as `live-runtime`. Folding a working sealed path into a new abstraction risks a functioning capability for tidiness.

### Coverage states are reused, not replaced

Per-class coverage uses the existing enum from `_database-adapters/contract.md:321-327`, unchanged:

| State | Meaning for an evidence class |
|---|---|
| `COVERED` | The class was acquired complete for the declared scope |
| `PARTIAL` | Some of the class was acquired; omissions listed |
| `INVENTORY_ONLY` | The class was acquired but the lens has no sound actionable rule for it |
| `NOT_ASSESSED` | The class was not acquired, or acquisition failed |
| `NOT_APPLICABLE` | The class's precondition is demonstrably false for this target |

Coverage therefore becomes a matrix of *lens × topic × evidence class*, where it is currently *lens × topic*. No new state is introduced, and the existing rule that `INVENTORY_ONLY` and `NOT_ASSESSED` never render as clean does the work that motivated this project.

Acquisition failure maps to `NOT_ASSESSED` with a named reason, consistent with `contract.md:196-197` ("`NOT_ASSESSED` requires a reason and prevents an overall `ASSESSED` disposition").

### Two control planes

**`audit:acquire <class>`** — new controller, four adapter subcommands, existing verb shape:

```powershell
npm.cmd run audit:acquire artifact  -- plan --source <path> --out <evidence-bundle>
npm.cmd run audit:acquire registry  -- plan --image <ref@sha256:...> --credential-ref <ref> --target-class <class> --phi-scope <scope> --attest-authorized --out <evidence-bundle>
npm.cmd run audit:acquire deployed  -- plan --context <ctx> --target-class <class> --phi-scope <scope> --attest-authorized --out <evidence-bundle>
npm.cmd run audit:acquire runtime   -- plan --context <ctx> --pod <ns/pod> --target-class <class> --phi-scope <scope> --attest-authorized --out <evidence-bundle>

npm.cmd run audit:acquire <class> -- run <evidence-bundle> --operator-id <id> --confirm-authorization-current
npm.cmd run audit:acquire <class> -- finalize <evidence-bundle>
npm.cmd run audit:acquire <class> -- validate <evidence-bundle>
npm.cmd run audit:acquire <class> -- stop <evidence-bundle> --operator-id <id> --reason <text>
```

The registry/deployed/runtime `plan` and `run` forms shown above are historical
and currently refuse before argument or bundle access. The artifact adapter has
a separate local-file boundary.

**`audit`** — existing workflow, one new repeatable input:

```powershell
npm.cmd run audit -- plan <repository> --evidence-bundle <path> --out <outside-target-directory>
```

Rationale for separation: the repository control plane's identity is "static and read-only by default" (`SKILL.md:21`). Registry credentials, cluster reads, and runtime inspection are exactly what that guarantee must exclude. Separation mirrors `http-recon`, keeps acquisition independently reviewable and stoppable, and makes bundles reusable across audits and reproducible later.

### `evidence_profile` and `evidence_context`

Mirroring the `store_profile` / `store_context` split, which exists for the same reason — a large validated envelope, plus a small immutable projection into every finding.

**`evidence_profile`** is the bundle's `manifest.json`, the validated acquisition envelope:

```yaml
evidence_profile:
  schema: evidence-bundle-v1
  evidence_context:
    evidence_id: peerstar-api-image
    evidence_class: built-artifact
    adapter_id: artifact
    target_identity: sha256:9f2c...           # image digest, cluster context, or input hash
    acquisition_mode: offline-export
    acquired_on: 2026-08-08T14:22:10Z
    detection_evidence:
      - shell-in-the-ghost.tar.gz sha256:4aaff082...
    confidence: high
  target_class: LAB                            # LAB | NONPROD | PRODUCTION | THIRD_PARTY
  phi_scope: none                              # none | possible | confirmed
  phi_bearing: false
  adapter_version: "1.0.0"
  contract_version: 1
  coverage_state: COVERED                      # existing enum
  artifact_kind: oci-image                     # required for built-artifact, forbidden otherwise
  files:
    - path: payload/layers/02/entries.json
      sha256: 6c1f...
  attestation: null                            # required for registry/deployed/runtime
  coverage_gaps: []
```

**`evidence_context`** is the immutable routing projection stamped into every candidate finding derived from this bundle. Required fields: `evidence_id`, `evidence_class`, `adapter_id`, `target_identity`, `acquisition_mode`, `acquired_on`, `detection_evidence[]`, `confidence`. Its shape is owned by `_schema.md`; adapters must not substitute a private shape.

`evidence_id` is operator-assigned, unique within a run, and stable across re-acquisitions of the same target — it is the handle `location` resolves through, so an id that changes between runs breaks every finding referencing it, exactly as `_schema.md:85-87` describes for `candidate_id`. It must not contain a hostname, mirroring the `store_id` rule at `contract.md:163-164`. One bundle carries one `evidence_id`; two acquisitions of the same target at different times are two bundles with the same `evidence_id` and different `acquired_on` and `target_identity` values.

Credential **values** never appear in a bundle — only `credential_ref`. This mirrors `contract.md:48` ("Never put a password, token, private endpoint, or full credential-bearing connection string in the record").

Bundles live outside their target, like audit bundles.

### Lens declarations extend `activates_on`

Lens frontmatter today carries `name`, `title`, `runs_in`, `activates_on.paths[]`, and topic ownership. Evidence classes extend the existing activation block rather than adding a parallel one:

```yaml
---
name: cloud-and-iac
title: Cloud and infrastructure as code
runs_in: fanout
activates_on:
  paths:
    - '**/Dockerfile'
    # ... existing globs unchanged
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: consumed
      artifact_kinds: [oci-image]
      may_conclude: [secret-present-in-artifact, unexpected-artifact-content]
    deployed-state:
      state: consumed
      may_conclude: [drift-from-source, runtime-misconfiguration]
    live-runtime:
      state: not-consumed
---
```

Rules:

- `state` is `consumed` or `not-consumed`. Every canonical class must appear; omission is a lint failure, mirroring the database rule that an adapter "may not rename or omit a canonical one" (`contract.md:314`).
- `artifact_kinds` is required when `built-artifact` is `consumed`, and names the artifact kinds the lens can interpret from the canonical set: `oci-image`, `apk`, `ipa`, `jar`, `dist-bundle`. A lens must not claim coverage of a kind it has no rules for — `mobile-app-security` declares `[apk, ipa]`, `cloud-and-iac` declares `[oci-image]`. An acquired artifact whose kind no activated lens declares yields `INVENTORY_ONLY`, never silence.
- `may_conclude` bounds what a finding from that class may assert, drawn from the canonical claim-kind vocabulary declared in `_evidence-adapters/contract.md` → `## Claim kinds`. A finding names its assertion in the Stage-1 field `evidence_claim`; a record whose `evidence_claim` falls outside its class's `may_conclude` is malformed. It is required for every consumed class except `source`, which is exempt — `source` is what every lens in this registry already does, and bounding it would re-litigate all 174 owned topics.
- A lens with `state: not-consumed` for a class contributes `NOT_APPLICABLE` for it, not `NOT_ASSESSED` — the lens has nothing to say, which is different from evidence being missing.
- `threat-modeling` is advisory and makes no coverage claim (`SKILL.md:23-24`). It declares all four classes `not-consumed` and is exempt from evidence-class coverage reporting.
- `business-logic`, `completeness`, `attack-chaining`, and `ai-generated-code` own no topics and read the merged set. They declare classes `consumed` where they can reason over another lens's evidence, and inherit the `owns: []` exemption at `_schema.md:95-109` unchanged.

### Detection stays in lens and adapter rules

The controller makes evidence legible and provenance-stamped. It implements no detectors. Whiteout archaeology, orphan-blob detection, and sibling-deviation heuristics are **rules**, using the existing stable-rule-ID discipline (`contract.md:349-385`) with a new namespace:

```text
ev.<evidence-class>.<adapter-id>.<semantic-name>

ev.built-artifact.oci.whiteout-named-file-with-content
ev.built-artifact.oci.blob-unreferenced-by-manifest
ev.built-artifact.oci.sibling-size-mtime-outlier
ev.built-artifact.oci.recursive-encoded-payload
ev.built-artifact.oci.secret-in-config-history
```

Same constraints as database rule IDs: lowercase ASCII, dot-separated, no version, severity, path, line, or sequence number; a changed oracle gets a new ID plus a `supersedes` link; an ID is valid only when declared as a rule anchor in the owning document.

This keeps code small and security knowledge editable without a release.

## Components

### Foundation

- **Evidence-class registry** — canonical class identifiers, precedence order, and required authorization per class. Pure data plus validation.
- **`schemas/evidence-bundle.schema.json`** — `evidence_profile` shape; reader/writer that can create, hash, seal, verify, and read a bundle. Testable against fixture bundles alone.
- **`lenses/_evidence-adapters/contract.md`** — the acquisition adapter contract, modeled directly on `_database-adapters/contract.md`: contract version, `verified_on`, canonical `adapter_id` routing table, capability enum, fail-closed ambiguity rules, stable rule IDs, conformance matrix.

### Acquisition adapters

| `adapter_id` | Class | Mechanism | External dependency |
|---|---|---|---|
| `artifact` | `built-artifact` | Read a supplied tarball or OCI layout | none (file I/O, tar, gzip) |
| `registry` | `built-artifact` | `crane pull` / `docker save`, digest-pinned, sealed credential ref | `crane` or `docker` |
| `deployed` | `deployed-state` | `kubectl get -o json`, cloud CLI, `sf`; read-only verbs enforced by controller-side allowlist | respective CLIs |
| `runtime` | `live-runtime` | `kubectl exec` read-only inspection | `kubectl` |

An unlisted acquisition target selects `inventory-only`, mirroring `contract.md:274` — it may inventory and write a coverage gap, but cannot clear anything.

Adapter capability enum reuses the database values verbatim (`NATIVE`, `COMPOSABLE`, `EXTERNAL_ONLY`, `UNSUPPORTED`, `UNKNOWN`) describing what the adapter can obtain, not audit outcome.

- **`audit:acquire` controller** — verb dispatch, authorization sealing, adapter invocation, bundle emission.

### Consumption

- **Lens frontmatter migration** — add `activates_on.evidence_classes` to all 15 canonical lenses; extend the existing lens linter to require it.
- **Coverage matrix extension** — activate by *topic × available class*; carry per-class coverage into `report.md` and `results.sarif`.
- **`_schema.md` amendment** — `evidence_context` field, extended `location`/`existence_check` semantics, and one new invariant (below).
- **Artifact normalizer** — converts an OCI layout into something the packet model can scope and a provider can read: layer index in manifest order, per-layer entry listings with mode/size/mtime/link target, and entry contents addressable by path. Required because providers cannot run `tar`; without it, `next` has nothing to hand a provider.

## `location` and `existence_check` for non-repository evidence

This is the integration point that makes findings from new classes gradeable, and without it they cannot be graded at all.

`_schema.md:240-250` requires that before any argument about severity, the cited artifact is opened at `location` and the quoted `evidence` confirmed verbatim; an artifact that cannot be located grades `NOT_REPRODUCED`, and a located artifact whose quoted evidence is absent grades `DISPROVED`. Today `location` is `file:line` in the repository.

**Extension.** `location` accepts an evidence-qualified form:

```text
<evidence_id>:<class-specific-locator>

peerstar-api-image:layer/02/var/lib/db/sbom/zsh-5.9r7.spdx.json
peerstar-api-image:config/history[8]
prod-cluster:v1/Namespace/sidecars/Pod/sidecars/spec.volumes[0]
```

`<evidence_id>` must resolve to an `evidence_context` present in the run. The three `existence_check` outcomes carry over exactly:

- **Bundle absent from the run, or locator does not resolve within it** → `NOT_REPRODUCED`. Consistent with the existing rule that failing to locate an artifact is a statement about the claim, not the harness.
- **Locator resolves and the quoted `evidence` is not there** → `DISPROVED`, quoting what was actually found.
- **Both check out** → proceed to tier assignment.

Because bundles are hashed and content-addressed, re-verification months later is exact rather than approximate — a stronger guarantee than the repository case, where a checkout may have moved.

**New invariant, in the style of invariant 15:**

> **16.** A record whose `location` carries an evidence-qualified form has `evidence_context` present, and its `evidence_class` is declared `consumed` by the lens named in `lens`. Its `evidence_claim` lies within that class's `may_conclude`. Where two classes yield conflicting claims for one topic, the higher-precedence class prevails and the conflict is recorded; a lower-precedence class never overrides a higher one. A claim resting on a class whose coverage is `NOT_ASSESSED` or `INVENTORY_ONLY` is `UNPROVEN` and capped at Medium.

The final clause reuses invariant 8's existing arithmetic rather than adding a mechanism.

## Data flow

```
OPERATOR                  audit:acquire artifact              evidence bundle ev/
  ./img.tar  ───────────► plan   hash input, seal target   ─►  manifest.json
                                 identity, target_class,        (evidence_profile)
                                 phi_scope                      ├─ evidence_context
                          run    normalize OCI layout      ─►    ├─ per-file sha256
                                 → layer index (manifest         ├─ coverage_state
                                   order) + per-entry            ├─ adapter/contract version
                                   mode/size/mtime + content     └─ attestation | null
                          finalize / validate

                                    │  bundle hash
                                    ▼
REPO ──────────────────►  audit -- plan <repo> --evidence-bundle ev/
                          ├─ verify bundle integrity; pin hash into run.json
                          ├─ classify denominators per class
                          ├─ activate lenses by  topic × available class
                          └─ seal packets scoping normalized entries

                          next ─► packet {lens, topics, scoped entries, evidence_context}
                          provider reads → job-result JSON, stamped evidence_context
                          ingest → triage → proof (existence_check on locator) → finalize

                          report.md
                          ├─ findings, provenance to evidence_id + locator + bundle hash
                          └─ coverage matrix: lens × topic × class, existing state enum
```

## Authorization model

### By class

| Class | Requirements |
|---|---|
| `source` | Existing: user may inspect the repository |
| `built-artifact` via `artifact` | File access only; no attestation |
| `built-artifact` via `registry` | Sealed `credential_ref`, digest-pinned image, attestation |
| `deployed-state` | Read-only verb allowlist enforced controller-side, attestation |
| `live-runtime` | Attestation, `target_class`, named operator, reason, `--confirm-authorization-current`, kill switch, impact counters |

`PRODUCTION` and `THIRD_PARTY` require explicit acknowledgment. `THIRD_PARTY` routes through the existing higher-assurance signed-artifact mode (signed RoE, authorization document, externally pinned owner key); this design neither creates nor approves those artifacts.

**Impact counters for read-only classes** count commands executed, bytes read, and distinct objects touched per target, each with a cap that halts acquisition when exceeded. They exist for `deployed-state` and `live-runtime` even though both are read-only, because an unbounded read against production is an availability risk regardless of intent.

### PHI scope

Gated on a declared PHI scope, **independent of target class**, so non-PHI systems pay no PHI friction:

| `--phi-scope` | Default | Marking |
|---|---|---|
| `none` (attested) | Full content capture, no redaction | none |
| `possible` | Metadata-only; contents require an explicit flag | `phi_bearing: true` if contents captured |
| `confirmed` | Metadata-only; contents require flag plus acknowledgment | `phi_bearing: true`, retention limit, noted in report |

Metadata-only means names, shapes, sizes, hashes, and key names — never values or record contents.

Rationale: `deployed-state` and `live-runtime` against production can pull real PHI into a local bundle — Secrets, ConfigMaps, log lines, database rows, a container's merged filesystem. Writing unencrypted PHI-bearing bundles would create a new breach surface using the audit tool itself. Redaction is the default where PHI is possible and freely disabled where it is attested absent.

Interaction with `hipaa-and-phi`: a `phi_bearing` bundle is itself an auditable artifact. The report names its existence and location; it does not inline its contents.

### Integrity and stop

A bundle whose manifest does not verify, or whose file hashes do not match, causes `audit -- plan` to **refuse** — not warn and continue. Evidence of uncertain provenance is worse than absent evidence because it launders into findings.

`stop` is idempotent and requires no still-valid authority artifact, matching `http-recon`.

## Error handling

**A missing dependency is a failure, never an empty success.** This has already happened one layer down in this repository: two tests fail permanently because ripgrep is absent from the development machine, and that same absence can make an audit look clean because a *tool* was missing rather than because the target was safe.

Therefore:

- Each adapter probes for its external CLI during `plan` and fails there when absent.
- A missing CLI, refused authentication, or unreachable target yields `coverage_state: NOT_ASSESSED` with a named reason in `coverage_gaps`.
- No adapter may report `COVERED` with an empty payload.
- Output that cannot be parsed is `PARTIAL` with the unparsed portion named, never silently dropped.

Ambiguity is fail-closed, mirroring `contract.md:333-347`: if two artifact kinds are plausible, record the conflict and mark class-semantic rules `NOT_ASSESSED`.

## Testing

### Fixture pairs

Following the existing pattern (`.superpowers/sdd/2026-07-26-phase-a-lens-registry/task-fixtures-vuln-report.md`, `task-fixtures-clean-report.md`): one deliberately vulnerable synthetic OCI image and one clean image; assert planted issues are found in the first and **zero** findings in the second. Generated by a fixture-builder script so fixtures stay a few KB and reproducible; no large real-world exports committed.

One planted pattern per rule anchor:

1. A real whiteout (0 bytes, mode 0600) beside a file merely *named* `.wh.*` (non-zero, mode 0664) → `ev.built-artifact.oci.whiteout-named-file-with-content`
2. A blob unreferenced by any manifest or config → `…blob-unreferenced-by-manifest`
3. A sibling size and mtime outlier among otherwise uniform files → `…sibling-size-mtime-outlier`
4. A recursively encoded payload (base64 of base64) → `…recursive-encoded-payload`
5. A secret in image config `history` → `…secret-in-config-history`

Pattern 3 is the one a human auditor most reliably misses; it was dismissed as routine cleanup noise twice during the motivating incident before the outlier was noticed. Mechanical sibling comparison does not form favourite theories.

### The false-clearance regression test

Run an audit with **no** evidence bundle. Assert `built-artifact` coverage is `NOT_ASSESSED` with a reason, and that the report contains no clearance language for the affected topics. This encodes the reason the project exists and must fail loudly if the coverage matrix is ever relaxed.

### The precedence test

Supply a `source` bundle and a `built-artifact` bundle that disagree — a Dockerfile whose `RUN rm` implies absence, and an image where the file is present. Assert the `built-artifact` claim prevails, the conflict is recorded, and the `source`-derived conclusion never suppresses it.

### Adapter conformance suite

One shared suite every adapter must pass: `describe`/`plan`/`run` shapes, `NOT_ASSESSED` on missing dependency, provenance completeness, refusal to report `COVERED` with an empty payload, `evidence_context` completeness and immutability. Makes a fifth adapter inexpensive.

### `existence_check` tests

For each class: a resolvable locator whose quoted evidence is present (`located`); a resolvable locator whose evidence is absent (`DISPROVED`); an unresolvable locator and a missing bundle (both `NOT_REPRODUCED`). This is the highest-risk new surface, because a wrong outcome here either fabricates or deletes findings.

### Hermetic CI

`registry`, `deployed`, and `runtime` tests inject a stub `crane`/`kubectl`/`sf` on `PATH` replaying canned JSON. No test depends on a live cluster, registry, or org.

### PHI redaction tests

A `phi-scope: confirmed` acquisition emits key names and shapes but no values; `phi_bearing` propagates into `report.md`.

### Integrity tests

Mutate one byte of a fixture bundle payload; assert `audit -- plan` refuses.

### Lens lint tests

Every canonical lens declares all four classes; a lens omitting one fails lint; a finding asserting outside its class's `may_conclude` fails validation.

## Decisions and rationale

| Decision | Choice | Why |
|---|---|---|
| Integration shape | Separate `audit:acquire` control plane | Quarantines network/credential/runtime risk outside the read-only repository plane; mirrors `http-recon`; makes provenance controller-owned; bundles reusable and reproducible |
| Coverage vocabulary | Reuse `COVERED`/`PARTIAL`/`INVENTORY_ONLY`/`NOT_ASSESSED`/`NOT_APPLICABLE` | A parallel state set would be the shadow-registry failure `_schema.md:107` warns about; the existing states already carry the never-render-as-clean rule |
| Conceptual framing | Generalize the existing detection-precedence rule | Proven concept applied one level up, rather than a novel dimension needing its own conflict semantics |
| Profile/context split | Mirror `store_profile` / `store_context` | Same problem, same proven solution: validated envelope plus immutable routing projection |
| Lens declaration | Extend `activates_on` | Activation already lives there; a separate block would fragment the mechanism |
| Phase 0 breadth | Boundary **and** all four adapters | Operator decision. One design, adapters sequenced as separate implementation plans |
| Adapter mechanism | Shell out to existing CLIs | Precedent: the `sf` CLI is already driven this way. Avoids reimplementing registry and cluster protocols |
| Credentials | Sealed reference only, never values | Existing rail plus `contract.md:48` |
| PHI gate | Declared `phi-scope`, independent of target class | Operator refinement: non-PHI production gets the same freedom as a lab |
| Detection location | Lens and adapter rules, not Node | Keeps code small and knowledge editable; matches existing rule-ID discipline |
| `http-recon` | Untouched, not retro-labelled | Working sealed path; folding it in risks a functioning capability for tidiness |
| `references/` legacy copy | Left alone | Out of scope; deciding its fate is a separate task |

## Phase 3 prerequisite: hard-rail amendment

Recorded here so it is a deliberate decision rather than an accident of implementation.

Phase 3 was chosen as a **free-form supervised session**: the operator works interactively, the controller records every action, and enforcement is a kill switch plus target attestation plus impact counters. This was selected over a sealed capability envelope and over a strictly sealed action list.

Consequences Phase 3's spec must address:

1. **`SKILL.md:47-48` ("Responses cannot add actions") cannot hold for this tier.** Real exploitation is response-driven: in the motivating incident, each action's *existence* was derived from the previous action's response, and no sealed list could have expressed the chain.
2. **Two hard rails need an explicit, narrowly-typed carve-out**, or they become decorative:
   - "Never execute dynamic proof against production or shared infrastructure."
   - "Never mutate, stage, commit, push, deploy, or message external systems."
3. **Reports from this tier must not claim bounded scope.** With no sealed action contract there is nothing to bound them. They are *transcript-attested* — "here is everything that was done" — and must say so rather than inheriting the recon path's sealed-scope language.
4. **Impact counters become the primary blast-radius signal**, since actions are not pre-declared. `SKILL.md:69-70` already requires them for this tier.
5. **`_harness.md` tier interaction must be settled.** T2 is currently "a consented local loopback boot, never a hosted target" (`SKILL.md:133`). An exploitation tier against a remote authorized target is not T2 and must not be smuggled in as one; it needs its own tier label and caps.

Phase 3 is out of scope for this document and must not be implemented from it.

## Implementation sequencing

One design, five plans:

1. **Foundation** — evidence-class registry, `evidence-bundle` schema and reader/writer, `_evidence-adapters/contract.md`, conformance suite.
2. **Consumption** — `activates_on.evidence_classes` across all 15 lenses, lens linter extension, `_schema.md` amendment (`evidence_context`, extended `location`/`existence_check`, invariant 16), coverage matrix, false-clearance and precedence regression tests. *Delivers value with zero adapters: every existing report becomes honest about its blind spots.*
3. **`artifact` adapter + normalizer** — offline, no new authorization surface. Unblocks Phase 1.
4. **`registry` adapter** — credential sealing, digest pinning.
5. **`deployed` and `runtime` adapters** — read-only allowlists, attestation, PHI scope enforcement, impact counters, kill switch.

Plan 2 is deliberately ordered before any adapter: it is the smallest change that removes the false-clearance failure mode, and it is independently shippable.

All five shipped, in that order, merged to `main` on 2026-08-09 across 22 commits.
Plan 2's claim held: after it and before any adapter existed, an audit of a
repository containing only the motivating Dockerfile already printed *"An
unexamined evidence class is a coverage gap, not a clearance."*

---

## Implementation reconciliation

Every place the built system differs from the design above, and why. Recorded
here rather than left to drift, because a design nobody reconciles becomes a
document that describes a system that does not exist.

### Contract gaps this design had

Three things were unenforceable as specified. Each was found by trying to
implement the rule, not by re-reading it.

1. **`may_conclude` had nothing to check against.** The design says a finding
   asserting outside its class's `may_conclude` is malformed but names no field
   carrying the assertion. Resolved: Stage-1 `evidence_claim`, required with
   `evidence_context`, drawn from a closed six-value vocabulary declared in
   `_evidence-adapters/contract.md`. Without both halves the rule validates
   nothing, and every lens invents its own labels — the shadow-registry failure
   `_schema.md:107` warns about.

2. **`location`'s pattern rejected the evidence form outright.**
   `finding.schema.json` required a trailing `:line`, so
   `peerstar-api-image:layer/02/…json` was not merely ungradeable, it was
   unrepresentable. The two forms are now disjoint by construction — a
   repository path carries `/` or `.` and cannot be an `evidence_id`; a
   repository line is purely digits and cannot be a locator — so no reader has
   to guess which one it holds.

3. **A bundle recorded no artifact kind.** The design puts `artifact_kinds` on
   the lens but never records what kind a given bundle carries, making "an
   acquired artifact whose kind no activated lens declares yields
   `INVENTORY_ONLY`" uncomputable. Resolved: `evidence_profile.artifact_kind`.

### Decisions the design left open

- **One record, one evidence source.** A record may not mix a repository
  location with an evidence-qualified one. `store_context`'s "one record
  concerns one store" is the same rule for the same reason, and a mixed record
  makes precedence unresolvable — which class is the record resting on?
- **The four owns-nothing lenses consume `source` only.** They reason over the
  merged finding set, not over raw evidence, and a finding they originate lands
  on the owning lens's topic where the owner's declaration bounds it. Declaring
  classes they have no rules for would manufacture coverage.
- **`--evidence-bundle` takes a comma-separated list**, not a repeated flag:
  `audit.mjs`'s argument parser rejects a duplicated option, and one string
  stays one immutable value in the plan digest.

### Where enforcement actually lives

Invariant 16 could not be enforced in one place, because its four clauses need
different inputs:

| Clause | Enforced in | Why there |
|---|---|---|
| `evidence_context` present, ids match, no mixed locations | `contracts.mjs`, unconditional | Record-local; needs nothing else |
| Class declared `consumed`, claim within `may_conclude`, coverage cap | `contracts.mjs`, when the caller supplies `options.evidence` | Needs the lens pack and the run's coverage matrix, which `validateFinding` has no access to |
| Precedence between two records | `evidenceConflicts(findings)`, a set-level resolver | A conflict is a property of a pair; a single-record validator cannot see one |

The coverage matrix is hashed into `plan_digest`, so it cannot be edited after
planning — which means `validate` recomputes the same field. Both sides are
conditional so a run planned before the matrix existed still validates.

### Operational constraints found by building it

- **npm shims on Windows needed resolving, not refusing.** `execFile` cannot
  launch a `.cmd` shim without `shell: true`, which this controller never uses,
  so `sf` — installed by npm as `sf.cmd` — was initially reported absent and
  the `sf.*` operations could not run at all. Resolved by reading the shim and
  executing the node invocation it declares (`node --no-deprecation <entry>
  <args>`) directly: still no shell, the argument vector still never re-parsed
  as a command string. Verified against the real install: `sf` probes at
  `@salesforce/cli/2.144.6` and `sf.org-display` plans end to end. Deliberately
  not a general `.bat` interpreter — an unmatched shape, a missing entry
  script, or any other `%VAR%` expansion resolves to nothing and the plan
  refuses. `kubectl` ships a real executable and never needed this.
- **Impact counters were built one tier earlier than specified.** The design
  attaches them to `deployed-state` and `live-runtime`. `registry` is the first
  adapter that leaves the machine, so the mechanism was written there and
  reused twice rather than implemented twice.
- **PHI redaction identifies structure by field name, never by value shape.** A
  value-shape heuristic passed `TXJzIFJvc2EgTGVl` through verbatim: base64 PHI
  is frequently pure alphanumeric and indistinguishable from a resource kind by
  inspection.
- **A non-image archive grades `NOT_ASSESSED`, not `PARTIAL`.** `PARTIAL` means
  some was acquired and the omissions are named; an archive with no readable
  structure acquired nothing.
- **Payload prefixes are positional.** Keying them by `operation_id` collided
  when one plan ran two `k8s.resource` reads of different objects — a
  legitimate plan — and duplicated `detection_evidence` against a `uniqueItems`
  constraint.

### Still open

- **Phase 1 is unblocked but unstarted.** `artifact.md` declares all five OCI
  rule anchors and the fixtures plant all five patterns; no detection rule is
  written. That is Phase 1, in lens and adapter prose, not in Node.
- **Phase 2 has no rule anchors.** `deployed.md` and `runtime.md` declare none.
- **Phase 3 remains out of scope** and must not be implemented from this
  document. The hard-rail amendment recorded above is still a prerequisite, and
  `runtime.md` says so in its own body so the next reader of that file does not
  have to reconstruct the boundary from a spec they may never see.
