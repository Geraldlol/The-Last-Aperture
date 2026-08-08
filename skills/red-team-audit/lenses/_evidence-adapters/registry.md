# `registry` acquisition adapter

Adapter ID: `registry`

Evidence class: `built-artifact`

Contract version: `1`

Verified: `2026-08-08`

Pulls one digest-pinned image from a container registry through `crane` (or
`docker save`) and hands the resulting archive to the same normalizer the
`artifact` adapter uses. This is the first acquisition in the registry that
leaves the machine, and its authorization sits above its class floor for
exactly that reason.

## Capabilities

| Capability ID | Value | Why |
|---|---|---|
| `target-identity` | `NATIVE` | The reference is digest-pinned before anything runs. |
| `content-enumeration` | `NATIVE` | Every entry of every layer is listed. |
| `content-retrieval` | `NATIVE` | Entry bytes are captured up to the content cap. |
| `layer-or-revision-history` | `NATIVE` | Layers arrive in manifest order. |
| `metadata-provenance` | `NATIVE` | Registry-side config and history are pulled with the image. |
| `deletion-recoverability` | `NATIVE` | Content below a whiteout stays fully readable. |
| `effective-configuration` | `EXTERNAL_ONLY` | An image is not a running configuration. |
| `principal-and-permission-state` | `EXTERNAL_ONLY` | Registry ACLs are not image content. |
| `secret-material-surface` | `NATIVE` | Every entry and every history line is enumerable. |
| `impact-accounting` | `NATIVE` | Commands and bytes pulled are counted and capped. |

## Digest pinning

A reference must be `<repository>@sha256:<64 hex>`. A tag is refused.

**A tag is not an identity.** `app:latest` resolves to different bytes
tomorrow, which makes the bundle unreproducible and every finding citing it
uncheckable — and exact re-verification months later is the one guarantee a
bundle has that a repository checkout does not. A registry port
(`registry.example.com:5000/...`) is legal; a tag is not.

## Credentials

A bundle carries a `credential_ref` and **never a credential value**. The
reference names its resolver — `env:`, `file:`, `keychain:` or `vault:` — and
the acquisition process resolves it at run time. Anything that looks like a
credential value is refused at plan time rather than sealed.

Every string that reaches a log, an error, or a `coverage_gaps` reason is
redacted first, and the redacted form is itself checked so it cannot read as a
credential to the bundle contract's own last-resort guard.

## Authorization

Above the `built-artifact` floor, this adapter requires:

- `--attest-authorized`, a recorded operator declaration, not independently
  verified owner permission;
- a named operator, the authorizing party, and an authorization reference;
- a digest-pinned reference;
- a sealed credential reference.

`PRODUCTION` and `THIRD_PARTY` target classes require explicit acknowledgment.
`THIRD_PARTY` routes through the existing higher-assurance signed-artifact
mode; this adapter neither creates nor approves those artifacts.

## Impact

Commands executed and bytes read are counted against caps and recorded in
`payload/impact-counters.json`. A pull is one command against one pinned
digest; the counters exist so that stays true and is checkable afterwards.

## Coverage

`COVERED` when the pull succeeded and every layer was read. `PARTIAL` when
some entry exceeded the content cap or a layer could not be read, with the
omission named. `NOT_ASSESSED` when the pull failed — an authentication
refusal, an unreachable registry, an absent `crane` — with the redacted reason
recorded. A failed pull is never an empty `COVERED`.

`crane` is probed during `plan` and the plan fails there when it is absent, so
a missing dependency surfaces where an operator is watching rather than later
as an empty success.

## Rule anchors

None. Detection over an acquired image is the image format's business and its
anchors are declared in `artifact.md` under the `oci` adapter segment. Two
documents declaring the same anchor would make the ID ambiguous, which
`contract.md` → `## Stable rule IDs` rule 6 exists to prevent.
