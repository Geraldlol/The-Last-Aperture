# `artifact` acquisition adapter

> **Release gate (2026-09-03):** Every public artifact command is disabled
> before reading `--source`. A caller string can name a UNC/WebDAV path, device,
> pipe, link, sparse file, or compressed bomb; the retained implementation is a
> test kernel, not current file-read authority. Re-enable only with enrolled
> local roots, bounded no-follow same-handle hashing, digest/size revalidation,
> bounded decompression, and a controller-authenticated plan.

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

Each anchor states its oracle as a predicate over the normalized entry index a
packet carries, the `evidence_claim` a finding may assert, and the locator to
cite. Every one is demonstrated firing on the vulnerable fixture and *not*
firing on the clean one — `test/evidence-oci-rules.test.mjs` enforces both
directions for every anchor declared here, so a rule nobody showed
discriminating cannot be added silently. That is R7's discipline applied to
acquired evidence: a check that runs, matches nothing, and reports clean is
worse than a missing check.

A finding cites `<evidence_id>:<locator>` and asserts exactly one claim, which
must lie within the citing lens's `may_conclude` for `built-artifact`.

### `ev.built-artifact.oci.whiteout-named-file-with-content`

**Predicate.** An entry whose basename begins `.wh.` and whose `whiteout` is
`false` — the normalizer sets that flag only for a genuine 0-byte marker, so a
non-empty `.wh.` file is a file wearing the convention as a disguise.

**Claim.** `unexpected-artifact-content`. **Cite** the entry's own locator.

**Does not fire on.** A real whiteout: 0 bytes, `whiteout: true`. Both appear
side by side in the vulnerable fixture precisely so the discriminator is
exercised rather than assumed.

### `ev.built-artifact.oci.blob-unreferenced-by-manifest`

**Predicate.** A non-empty `payload/orphan-blobs.json` — a blob under
`blobs/sha256/` that no manifest, config, or layer descriptor references.

**Claim.** `unexpected-artifact-content`. **Cite** `orphan/<sha256:digest>`.

**Does not fire on.** An image whose every blob is reachable from its index.

### `ev.built-artifact.oci.sibling-size-mtime-outlier`

**Predicate.** Within one directory, where at least four entries share a size
and an mtime, an entry deviating in **both**. Both matter: size alone flags
ordinary content variation, mtime alone flags an ordinary rebuild.

**Claim.** `unexpected-artifact-content`. **Cite** the outlier's locator.

**Does not fire on.** A directory of uniform siblings, or one whose members
were never uniform to begin with — there is no baseline to deviate from.

This is the pattern a human auditor most reliably misses. It was dismissed as
routine cleanup noise twice during the motivating incident before the outlier
was noticed. Mechanical sibling comparison does not form favourite theories.

### `ev.built-artifact.oci.recursive-encoded-payload`

**Predicate.** Entry content that decodes as base64 to text that itself decodes
as base64 to printable bytes. One layer of encoding is ordinary; two is a
choice.

**Claim.** `unexpected-artifact-content`. **Cite** the entry's locator.

**Does not fire on.** Singly-encoded content, or a string that merely looks
base64-shaped and decodes to noise.

### `ev.built-artifact.oci.secret-in-config-history`

**Predicate.** A `history[].created_by` entry in `payload/config/history.json`
containing credential-shaped material. The build command is preserved in the
image config whether or not the file it wrote survives — the whole point being
that `RUN rm` removes the file and leaves the command.

**Claim.** `secret-present-in-artifact`. **Cite** `config/history[N]`.

**Does not fire on.** A history whose commands carry no credential material.
