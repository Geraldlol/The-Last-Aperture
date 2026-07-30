# Reference byte consumer

This image is a protocol-conformance peer, not a vulnerability analyzer. It
requests every offered sealed capability, verifies its digest, returns the
required byte-challenge HMAC, and emits an explicit coverage gap saying that no
semantic analysis occurred. It fails jobs that require triage, proof, or
database semantic inventory.

The Dockerfile intentionally has no mutable base-image default. Supply an
independently verified, digest-pinned Node image. The adapter runtime is
separate from the Node 24 host-controller requirement; the current CI pin is:

```text
docker build \
  --build-arg NODE_IMAGE=node:22-bookworm@sha256:c601a46abb4d2ab80a9dc3da208d50d1122642d53f17a101926ace71e5a9bf1c \
  --tag red-team-audit-reference-byte-consumer \
  providers/reference-byte-consumer
```

Then obtain the immutable local image ID with `docker image inspect` and use
that `sha256:<64 hex>` value in the external provider configuration. Do not use
this adapter to infer that a repository has no vulnerabilities.

The separate `Dockerfile.conformance` enables hostile in-container probes with
the exact resource limits used by `test/provider-docker-conformance.test.mjs`.
It checks denied root writes, `/work` no-exec behavior, absent outbound network
and host state, Linux privilege state, cgroup limits, actual PID/file-descriptor
exhaustion, and timeout cleanup:

```text
docker build \
  --file providers/reference-byte-consumer/Dockerfile.conformance \
  --build-arg NODE_IMAGE=node:22-bookworm@sha256:c601a46abb4d2ab80a9dc3da208d50d1122642d53f17a101926ace71e5a9bf1c \
  --tag red-team-audit-reference-byte-consumer:conformance \
  providers/reference-byte-consumer
```

The real-Docker gate requires this conformance image and rejects an ordinary or
stale image by checking its result marker.
