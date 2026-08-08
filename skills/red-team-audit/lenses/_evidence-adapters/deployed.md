# `deployed` acquisition adapter

Adapter ID: `deployed`

Evidence class: `deployed-state`

Contract version: `1`

Verified: `2026-08-08`

Reads configuration as it exists in a live system — cluster objects, org
settings, effective permissions — and records it as acquired evidence. Every
command is **read-only**, built by a controller-side allowlist rather than
supplied by the adapter, so a mutating command is unconstructible rather than
merely unwritten.

This adapter mutates nothing.

## Capabilities

| Capability ID | Value |
|---|---|
| `target-identity` | `COMPOSABLE` |
| `content-enumeration` | `NATIVE` |
| `content-retrieval` | `NATIVE` |
| `layer-or-revision-history` | `UNSUPPORTED` |
| `metadata-provenance` | `COMPOSABLE` |
| `deletion-recoverability` | `UNSUPPORTED` |
| `effective-configuration` | `NATIVE` |
| `principal-and-permission-state` | `NATIVE` |
| `secret-material-surface` | `NATIVE` |
| `impact-accounting` | `NATIVE` |

## Read-only operations

Only these may be planned. An operation outside the table cannot be built, and
a parameter that fails its own pattern is refused rather than interpolated.

| `operation_id` | CLI | Vector |
|---|---|---|
| `k8s.namespaces` | `kubectl` | `get namespaces -o json` |
| `k8s.resources` | `kubectl` | `get <kind> -n <namespace> -o json` |
| `k8s.resource` | `kubectl` | `get <kind> <name> -n <namespace> -o json` |
| `k8s.api-resources` | `kubectl` | `api-resources -o wide` |
| `k8s.auth-can-i` | `kubectl` | `auth can-i --list -n <namespace>` |
| `sf.org-display` | `sf` | `org display --json -o <alias>` |
| `sf.query` | `sf` | `data query --json -o <alias> -q <SELECT ...>` |

`sf.query` accepts a single `SELECT` and nothing else. A second gate rejects
any vector containing a mutating verb or an impersonation flag, for the day
someone adds an operation here that smuggles one in.

## Authorization

Attestation, a declared target class, a named operator, impact counters and a
kill switch are floors for this class. `PRODUCTION` requires an explicit
acknowledgment; `THIRD_PARTY` routes through the existing higher-assurance
signed-artifact mode, which this adapter neither creates nor approves.

Attestation is a recorded operator declaration, not independently verified
owner permission.

## Impact counters and stop

Commands executed, bytes read and distinct objects touched are counted against
caps and recorded in `payload/impact-counters.json`. Exceeding a cap **halts**
the acquisition: what was already acquired stays, the stopping point is named
in `coverage_gaps`, and coverage becomes `PARTIAL`. They exist even though
every operation is read-only, because an unbounded read against production is
an availability risk regardless of intent.

The acquisition loop re-checks the stop marker before every operation, so a
`stop` issued mid-run halts the remaining operations. `stop` is idempotent and
requires no still-valid authority artifact: the one command an operator needs
during an incident must not depend on the thing that may have gone wrong.

## PHI scope

| `--phi-scope` | Default | Marking |
|---|---|---|
| `none` (attested) | Full content capture | none |
| `possible` | Metadata-only; contents require an explicit flag | `phi_bearing: true` if contents captured |
| `confirmed` | Metadata-only; contents require flag plus acknowledgment | `phi_bearing: true`, retention limit, named in the report |

Metadata-only means names, shapes, sizes, hashes and key names — never values
or record contents. Structure is identified by **field name**, never by the
shape of a value: base64 PHI is frequently pure alphanumeric and
indistinguishable from a resource kind by inspection.

## Bundle payload

```text
payload/operations.json          every operation run, its exit code, object count and payload prefix
payload/objects/NN/<i>.json      the acquired object, redacted per policy
payload/impact-counters.json     commands, bytes and objects, with their caps
```

`NN` is the operation's position, not its ID: two `k8s.resource` reads of
different objects are a legitimate plan and would otherwise collide on one path.

## Locator form

`<evidence_id>:<apiVersion>/<Kind>/<namespace>/<name>`, resolved by scanning
the payload prefixes recorded in `operations.json`.

## Coverage

`COVERED` when every planned operation succeeded. `PARTIAL` when some
succeeded and the rest are named — a cap, a stop, a failed command, or output
that could not be parsed. `NOT_ASSESSED` when nothing was acquired. Output that
cannot be parsed is never silently dropped, and `kubectl` or `sf` being absent
fails at plan time rather than later as an empty success.

## Rule anchors

None yet. Detection over acquired cluster state is Phase 2.
