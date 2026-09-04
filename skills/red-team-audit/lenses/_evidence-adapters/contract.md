# Evidence acquisition adapter contract

> **Release gate (2026-09-03):** The entire public acquisition CLI, and audit
> evidence-bundle import, are disabled before caller-path, bundle, process, or
> target access. The
> adapter contracts below describe retained kernels, not current execution
> authority. Re-enablement requires controller-sealed immutable plans and semantic
> manifests, one-handle bounded/no-follow reads, enrolled source roots,
> controller-enrolled executable and target identities, fail-closed durable stop
> state with descendant termination, and protected output.

Contract version: `1`

Verified: `2026-08-08`

This file is a contract, not a lens. It owns no topics and emits no findings.
A lens supplies the threat families; an acquisition adapter supplies one class
of evidence, its provenance, and the exact bound of what it obtained.

An adapter answers four questions:

1. Which evidence class and target identity is this, exactly?
2. What was actually acquired, and what was not?
3. Under what authorization, and with what impact on the target?
4. What may a finding derived from this evidence assert?

The adapter never turns acquisition into a clearance. Reading an image is
evidence about that image; it is not evidence about the cluster running it.

## Evidence classes and precedence

| Class | Definition | Precedence |
|---|---|---|
| `source` | Files in the repository under audit | 1 (lowest) |
| `built-artifact` | Packaged build output: OCI image, APK/IPA, jar, dist bundle | 2 |
| `deployed-state` | Configuration as it exists in a live system, read-only | 3 |
| `live-runtime` | Behavior or contents of a running instance | 4 (highest) |

This is `_database-adapters/contract.md`'s detection-precedence rule promoted
from one lens to the registry, and the rule carries over unchanged: **a
lower-precedence signal never overrides a conflicting higher-precedence one.**
Where two classes disagree about one topic, the higher-precedence class
prevails and the conflict is recorded, never silently reconciled.

Exploitation is not a class. It is a mutation tier layered on `live-runtime`
in Phase 3. `audit:http-recon` observations remain in their own protocol and
are not retro-labelled `live-runtime`.

## Canonical adapter routing

| `adapter_id` | Class | Mechanism | External dependency |
|---|---|---|---|
| `artifact` | `built-artifact` | Read a supplied tarball or OCI layout | none |
| `registry` | `built-artifact` | `crane pull` / `docker save`, digest-pinned | `crane` or `docker` |
| `deployed` | `deployed-state` | Read-only cluster, cloud and org queries | respective CLIs |
| `runtime` | `live-runtime` | Read-only in-container inspection | `kubectl` |
| `inventory-only` | — | no adapter; load `contract.md` only | none |

An unlisted acquisition target selects `inventory-only`. Do not manufacture an
adapter ID from a file extension or a registry hostname. `inventory-only` may
inventory what it saw and write a coverage gap; it cannot clear anything.

## Artifact kinds

`oci-image`, `apk`, `ipa`, `jar`, `dist-bundle`.

A `built-artifact` bundle names exactly one kind. A lens declares the kinds it
has rules for and must not claim coverage of a kind it cannot interpret. An
acquired artifact whose kind no activated lens declares yields
`INVENTORY_ONLY`, never silence.

## Capability enum

Each adapter declares every canonical capability below using exactly one value.
The values are `_database-adapters/contract.md`'s, verbatim:

| Value | Meaning |
|---|---|
| `NATIVE` | The adapter obtains this directly from the target. |
| `COMPOSABLE` | The adapter can obtain it, but only if every named precondition is true. |
| `EXTERNAL_ONLY` | The adapter cannot obtain it; a separate tool or class must. |
| `UNSUPPORTED` | The identified target cannot express it in scope. |
| `UNKNOWN` | Target, version, or configuration ambiguity prevents classification. |

These describe what the adapter can obtain, not audit outcome.

Every adapter declares these canonical capabilities:

| Capability ID | What is being classified |
|---|---|
| `target-identity` | The target can be pinned to an exact immutable identity. |
| `content-enumeration` | Every member object of the target can be listed. |
| `content-retrieval` | The bytes of a named member object can be read. |
| `layer-or-revision-history` | The target's construction history is readable. |
| `metadata-provenance` | Build or deploy metadata is readable and attributable. |
| `deletion-recoverability` | Content deleted during construction remains detectable. |
| `effective-configuration` | Configuration as effective, not as declared, is readable. |
| `principal-and-permission-state` | Effective principals and grants are readable. |
| `secret-material-surface` | Locations that can carry secret material are enumerable. |
| `impact-accounting` | Commands, bytes and objects touched can be counted and capped. |

An adapter may add namespaced capabilities, but it may not rename or omit a
canonical one.

## Coverage states

Capability and coverage are separate axes. The states are
`_database-adapters/contract.md`'s, unchanged:

| Coverage state | Meaning for an evidence class |
|---|---|
| `COVERED` | The class was acquired complete for the declared scope. |
| `PARTIAL` | Some of the class was acquired; the omissions are listed. |
| `INVENTORY_ONLY` | The class was acquired but no activated lens has a sound actionable rule for it. |
| `NOT_ASSESSED` | The class was not acquired, or acquisition failed. |
| `NOT_APPLICABLE` | The class's precondition is demonstrably false for this target. |

`INVENTORY_ONLY` and `NOT_ASSESSED` are never rendered as pass, clean, secure,
or no findings. They appear in `Coverage` with the exact missing evidence.

Acquisition failure is `NOT_ASSESSED` with a named reason. **A missing
dependency is a failure, never an empty success**: an audit that looks clean
because a tool was absent is the exact failure this contract exists to prevent.

### Ambiguity is fail-closed

- A file extension, a registry hostname, or a MIME type alone activates
  inventory only.
- If two artifact kinds remain plausible, record the conflict and mark every
  class-semantic rule `NOT_ASSESSED`.
- Output that cannot be parsed is `PARTIAL` with the unparsed portion named,
  never silently dropped.
- No adapter reports `COVERED` with an empty payload.
- A bundle whose manifest or file hashes do not verify causes `audit -- plan`
  to refuse. Evidence of uncertain provenance is worse than absent evidence
  because it launders into findings.

## Claim kinds

A finding derived from a non-`source` class asserts exactly one of these, and
only where the lens declares it in `may_conclude`:

| Claim kind | What it asserts |
|---|---|
| `secret-present-in-artifact` | Secret material is readable in the acquired evidence. |
| `unexpected-artifact-content` | Content is present that the source does not account for. |
| `vulnerable-component-present` | A component with a known defect is present in the evidence. |
| `drift-from-source` | Deployed or built state differs from what the repository declares. |
| `runtime-misconfiguration` | Effective configuration is unsafe as it actually stands. |
| `sensitive-data-at-rest` | Regulated or sensitive data is present in the acquired evidence. |

A finding asserting outside its class's declared `may_conclude` is malformed.
A new claim kind is added here first; a lens may not invent one.

## Stable rule IDs

Adapter and lens rules over acquired evidence use:

```text
ev.<evidence-class>.<adapter-id>.<semantic-name>
```

Examples:

```text
ev.built-artifact.oci.whiteout-named-file-with-content
ev.built-artifact.oci.blob-unreferenced-by-manifest
ev.deployed-state.kubernetes.secret-readable-by-default-service-account
```

Rules:

1. IDs are lowercase ASCII, dot-separated, and contain no version, severity,
   path, line number, or sequence number.
2. The evidence-class segment is a canonical class.
3. The adapter segment is the canonical adapter or artifact-format ID declared
   by the selected adapter, not a marketing alias.
4. A compatible refinement keeps the ID. A changed oracle, protected resource,
   or security meaning gets a new ID and a `supersedes` link.
5. The rule ID is not the candidate finding ID. `_schema.md` still derives
   `candidate_id` from topic, normalized primary location, and title.
6. A rule ID is valid only when that exact ID is declared as a rule anchor —
   a `###`-or-deeper heading whose text is the backticked ID — in the owning
   adapter document. Syntactically plausible but undeclared IDs are rejected.

## Authorization

| Class | Floor |
|---|---|
| `source` | Existing: the user may inspect the repository. |
| `built-artifact` via `artifact` | File access only; no attestation. |
| `built-artifact` via `registry` | Sealed credential reference, digest-pinned image, attestation. |
| `deployed-state` | Read-only verb allowlist enforced controller-side, attestation, target class, named operator, impact counters, kill switch. |
| `live-runtime` | All of the above plus a per-run authorization confirmation. |

An adapter may exceed its class floor. It may never fall below it.

Credential **values** never appear in a bundle — only a `credential_ref`. This
mirrors `_database-adapters/contract.md:48`.

For any re-enabled live adapter, the authenticated operator target/scope
statement is the sole authorization primitive. Target class, acknowledgments,
credentials, impact limits, and stop state are controller-bound execution
parameters; none is an independent authority source. A controller-sealed permit
must bind the exact plan and be durably consumed before dispatch. Changing the
target or scope requires a new operator statement. The separate
`http-authed-v1` controller never widens this adapter.

**Impact counters exist for read-only classes.** They count commands executed,
bytes read, and distinct objects touched per target, each with a cap that halts
acquisition when exceeded, because an unbounded read against production is an
availability risk regardless of intent.

`stop` is idempotent and requires no still-valid authority artifact, matching
`http-recon`.

## PHI scope

Gated on a declared PHI scope, independent of target class, so non-PHI systems
pay no PHI friction:

| `--phi-scope` | Default | Marking |
|---|---|---|
| `none` (attested) | Full content capture, no redaction | none |
| `possible` | Metadata-only; contents require an explicit flag | `phi_bearing: true` if contents captured |
| `confirmed` | Metadata-only; contents require flag plus acknowledgment | `phi_bearing: true`, retention limit, noted in report |

Metadata-only means names, shapes, sizes, hashes, and key names — never values
or record contents. A `phi_bearing` bundle is itself an auditable artifact: the
report names its existence and location and does not inline its contents.

## Conformance matrix

Every adapter passes one shared suite:

- `describe` returns the adapter's canonical ID, class, capabilities, and
  external dependency.
- `plan` seals target identity, target class and PHI scope, performs no
  acquisition, and probes for its external CLI, failing there when absent.
- `run` emits a bundle whose `evidence_context` is complete and immutable.
- A missing dependency yields `NOT_ASSESSED` with a named reason, never an
  empty success.
- `COVERED` with an empty payload is refused.
- Unparsed output yields `PARTIAL` with the unparsed portion named.
- Every command the adapter would run against a live target is replayable from
  a stub on `PATH`, so no test depends on a live cluster, registry, or org.
