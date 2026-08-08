# `artifact` acquisition adapter

Adapter ID: `artifact`

Evidence class: `built-artifact`

Contract version: `1`

Verified: `2026-08-08`

Reads a supplied tarball — an OCI layout or a `docker save` archive — and
normalizes it into evidence a lens can actually read. It makes no network
request, resolves no reference, and needs no attestation: the operator hands it
a file it already has.

The adapter never turns acquisition into a clearance. Reading an image is
evidence about that image; it says nothing about the cluster running it, and
nothing about any other tag of the same repository.

## Capabilities

| Capability ID | Value | Why |
|---|---|---|
| `target-identity` | `NATIVE` | The supplied bytes are hashed at plan time and sealed. |
| `content-enumeration` | `NATIVE` | Every entry of every layer is listed. |
| `content-retrieval` | `NATIVE` | Entry bytes are captured up to the content cap. |
| `layer-or-revision-history` | `NATIVE` | Layers are carried in manifest order. |
| `metadata-provenance` | `COMPOSABLE` | Image config history is readable; who built it is not. |
| `deletion-recoverability` | `NATIVE` | Content below a whiteout stays fully readable. |
| `effective-configuration` | `EXTERNAL_ONLY` | An image is not a running configuration. |
| `principal-and-permission-state` | `EXTERNAL_ONLY` | File modes are not effective grants. |
| `secret-material-surface` | `NATIVE` | Every entry and every history line is enumerable. |
| `impact-accounting` | `EXTERNAL_ONLY` | Offline file reading touches no target; there is nothing to count. |

## Bundle payload

```text
payload/normalized.json                  format, config digest, layer descriptors, gaps
payload/config/history.json              the image config history array
payload/orphan-blobs.json                digest and size of every unreferenced blob
payload/layers/NN/entries.json           per-entry mode, size, mtime, type, link target,
                                         content hash and whiteout verdict
payload/layers/NN/content/<entry path>   entry bytes, for entries at or below the content cap
```

`NN` is the zero-padded layer index in **manifest order**, which is what makes
"the layer below" mean anything. An entry above the content cap is listed in
`entries.json` and named in `coverage_gaps`; it is never silently dropped.

## Locator forms

A finding cites `<evidence_id>:<locator>`. This adapter resolves three forms
and no more; an unrecognised form resolves to nothing rather than being
interpreted generously.

| Form | Resolves to |
|---|---|
| `layer/NN/<entry path>` | `payload/layers/NN/content/<entry path>` |
| `config/history[N]` | element `N` of `payload/config/history.json` |
| `orphan/<sha256:digest>` | the matching record in `payload/orphan-blobs.json` |

## Coverage

`COVERED` when every layer was read and no gap was recorded. `PARTIAL` when
some layer or some entry could not be captured, with the omission named.
`NOT_ASSESSED` when the archive is neither an OCI layout nor a `docker save`
tarball, or when no layer could be read at all — an archive with no readable
structure has acquired nothing, and nothing acquired is not a partial success.

## Rule anchors

Each anchor names an oracle. The detection prose that fires it is Phase 1;
declaring the anchor here is what makes the ID valid, per `contract.md`
→ `## Stable rule IDs` rule 6.

### `ev.built-artifact.oci.whiteout-named-file-with-content`

An entry whose basename begins `.wh.` and whose size is greater than zero. A
genuine whiteout is a 0-byte marker; a non-empty one is a file wearing the
convention as a disguise. The normalizer records `whiteout: false` for it,
which is the discriminator.

### `ev.built-artifact.oci.blob-unreferenced-by-manifest`

A blob under `blobs/sha256/` that no manifest, config, or layer descriptor
references. Reported in `payload/orphan-blobs.json`.

### `ev.built-artifact.oci.sibling-size-mtime-outlier`

Within one directory of otherwise uniform files, an entry deviating in both
size and mtime. This is the pattern a human auditor most reliably misses — it
was dismissed as routine cleanup noise twice during the motivating incident
before the outlier was noticed. Mechanical sibling comparison does not form
favourite theories.

### `ev.built-artifact.oci.recursive-encoded-payload`

Entry content that decodes as base64 to something that itself decodes as
base64. One layer of encoding is ordinary; two is a choice.

### `ev.built-artifact.oci.secret-in-config-history`

A `history[].created_by` entry containing credential-shaped material. The build
command is preserved in the image config whether or not the file it wrote
survives.
