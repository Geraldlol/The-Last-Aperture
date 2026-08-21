# `runtime` acquisition adapter

Adapter ID: `runtime`

Evidence class: `live-runtime`

Contract version: `1`

Verified: `2026-08-08`

Inspects one named running container, read-only, and records what the reads
returned. `live-runtime` is the highest-precedence class: where it disagrees
with source or with deployed state, it prevails and the conflict is recorded.

## What this tier is not

This adapter mutates nothing. It runs a fixed set of read commands inside one
named container and records what they returned. It is **not an exploitation
tier**, and it must not be treated as a precedent for one: exploitation is
Phase 3, it requires an explicit amendment to two hard rails, and that
amendment does not exist. A report from this adapter carries the recon path's
sealed-scope language honestly, because the action set here really is sealed.

## Capabilities

| Capability ID | Value |
|---|---|
| `target-identity` | `COMPOSABLE` |
| `content-enumeration` | `COMPOSABLE` |
| `content-retrieval` | `NATIVE` |
| `layer-or-revision-history` | `UNSUPPORTED` |
| `metadata-provenance` | `UNKNOWN` |
| `deletion-recoverability` | `UNSUPPORTED` |
| `effective-configuration` | `NATIVE` |
| `principal-and-permission-state` | `COMPOSABLE` |
| `secret-material-surface` | `NATIVE` |
| `impact-accounting` | `NATIVE` |

## Read-only operations

Bound to one namespace, pod and container named at plan time. A cluster-wide
sweep is the `deployed` adapter's job and is not reachable here.

| `operation_id` | Command inside the container |
|---|---|
| `runtime.read-file` | `cat <absolute path>` |
| `runtime.list-directory` | `ls -la <absolute path>` |
| `runtime.process-list` | `ps ax` |
| `runtime.env-keys` | `sh -c 'env \| cut -d= -f1'` |

`sh -c` appears exactly once, and its script is a constant rather than a
parameter. `runtime.env-keys` returns **key names only** — metadata-only is
applied at acquisition rather than trusted to a redaction pass that runs after
the values are already local. A second gate rejects any in-container command
outside this table.

## Authorization

Everything `deployed-state` requires — attestation, target class, named
operator, impact counters, kill switch — **plus a per-run authorization
confirmation**. Attestation at plan time is not enough for this class:
authorization can lapse between planning and running, and this is the tier
where that difference has consequences.

`PRODUCTION` requires an explicit acknowledgment. Until the higher-assurance
signed-artifact controller is available, `THIRD_PARTY` also requires
`--acknowledge-third-party`. This interim route is operator-attested, not
independently verified, and remains restricted to controller-built read-only
inspection; it does not authorize mutation or exploitation.

## Impact counters and stop

Identical to `deployed`: counted, capped, halting, and recorded in
`payload/impact-counters.json`. The loop re-checks the stop marker before every
operation. `stop` is idempotent and requires no still-valid authority artifact.

## PHI scope

Gated on `--phi-scope`, exactly as `deployed` is:

| `--phi-scope` | Default | Marking |
|---|---|---|
| `none` (attested) | Full content capture | none |
| `possible` | Metadata-only; contents require an explicit flag | `phi_bearing: true` if contents captured |
| `confirmed` | Metadata-only; contents require flag plus acknowledgment | `phi_bearing: true`, retention limit, named in the report |

Under `possible` or `confirmed` without an explicit contents flag, text output
is reduced to its line shapes with everything after the first `=` dropped.
A container's merged filesystem and environment are exactly where real PHI
turns up, so the default here is the one that matters.

## Bundle payload

```text
payload/operations.json          every operation run, its exit code and payload prefix
payload/observations/NN.txt      the command output, redacted per policy
payload/impact-counters.json     commands, bytes and objects, with their caps
```

## Coverage

`COVERED` when every planned read returned output. `PARTIAL` when some did and
the rest are named. `NOT_ASSESSED` when nothing was acquired — a permission
denial inside the container is a named gap, not a clearance.

## Rule anchors

Each anchor names an oracle over acquired `live-runtime` evidence. The
detection prose that fires it is Phase 2.

### `ev.live-runtime.kubernetes.credential-material-in-container-environment`

An environment key whose name marks it as credential-bearing, observed in the
running container. Under any PHI scope but `none` this is established from key
names alone — which is sufficient, because the finding is that the key is
there, not what its value is.

### `ev.live-runtime.kubernetes.process-running-unexpected-binary`

A process in the container that no layer of the image accounts for. This is the
`built-artifact` and `live-runtime` classes composing: the image says what
should be able to run, the runtime says what is running, and the higher class
prevails where they disagree.

### `ev.live-runtime.kubernetes.writable-path-outside-declared-volume`

A writable path in the merged filesystem that no declared volume or image layer
accounts for. Content written after deployment is invisible to both the
repository and the image.
