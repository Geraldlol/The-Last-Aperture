# ADR 0008: Remote attempt ledger integration

Date: 2026-07-30
Status: Accepted for 0.8.0

## Context

ADR 0007 defined a signed, replay-safe remote gateway boundary but deliberately
left controller state integration unresolved. The controller must persist
enough evidence to recover after a crash, reject configuration or key rotation,
verify historical receipts without storing external secrets, and keep remote
acceptance distinct from local byte-challenge consumption.

Adding remote fields silently to schema v5 would change the meaning of an
already released manifest version. Reusing the local container lease would
also imply cleanup and consumption guarantees a remote call cannot provide.

## Decision

Version 0.8.0 creates schema-v6 run manifests and a second authenticated
attempt backend:

- `SEALED_CONTAINER` retains the existing provider-config, sandbox-policy, and
  container identity.
- `REMOTE_GATEWAY` binds the remote configuration digest, controller and
  gateway Ed25519 key IDs, one-use request ID, and exact signed-request
  artifact.

Historical v1-v5 runs remain valid. Legacy local leases may omit the backend;
new v6 leases must declare it.

### Policy boundary

Remote planning requires an external `remote_static` Rules of Engagement
policy and `--seal-source`. That mode permits repository reads and explicitly
allowlisted network destinations, but forbids writes and execution. The
provider-facing policy projection is reduced to static, read-only authority;
network permission remains controller-only.

`run-remote` re-authorizes the exact configured HTTPS URL before every new
attempt. The client follows no redirects, pins one validated public DNS answer
for the connection, and additionally pins the certificate
SPKI and gateway receipt key.

### Durable sequence

For a new attempt the controller:

1. derives the portable packet and exact sealed FILE/CONTROL artifacts;
2. creates and writes the canonical signed request artifact;
3. persists a `REMOTE_GATEWAY` lease referencing that artifact;
4. persists `STARTED`;
5. sends the exact request;
6. verifies and writes the signed gateway acceptance;
7. persists `RESULT_CAPTURED`, `VALIDATED`, and `COMMITTED`; and
8. assigns `REMOTE_REQUEST_ACCEPTED` to the terminal job.

The acceptance artifact digest is the attempt receipt digest. Bundle
verification recomputes the planned artifact set, verifies both signatures and
all request/acceptance bindings, checks sealed source anchors, and confirms the
committed job reflects the accepted raw result.

External key bytes and gateway credentials never enter the run bundle. The
lease records externally established key IDs, while the signed envelopes carry
public keys for self-contained signature verification.

### Recovery and replay

`RESULT_CAPTURED` and `VALIDATED` attempts resume from durable artifacts
without another network call. An unexpired `LEASED` or `STARTED` attempt cannot
be stolen or replayed.

After expiry, the controller records a recoverable failure and may create a new
attempt with a new nonce and request ID. It never reuses the ambiguous request
ID. This provides at-most-once invocation per request ID, not global
exactly-once model execution across retries.

Configuration, endpoint, certificate pin, prompt transform, controller key, or
gateway key rotation within one run is rejected. Rotation starts a new run.

## Consequences

Positive:

- remote requests and receipts participate in the same hash-chained,
  crash-recoverable attempt lifecycle as local execution;
- historical schemas keep their released meaning;
- verification remains self-contained without embedding secrets;
- reports and lifecycle comparisons preserve remote authority separately.

Costs and residual risks:

- source bytes leave the local machine when `remote_static` explicitly permits
  the gateway;
- a crash after the upstream call but before receipt capture can cause a later
  retry under a new request ID, so cross-attempt exactly-once execution is not
  claimed;
- gateway compromise can fabricate gateway assertions under its pinned key;
  and
- `REMOTE_REQUEST_ACCEPTED` remains weaker than observed byte consumption and
  is never semantic or independent proof.

## Alternatives considered

- Extend schema v5 in place: rejected because released manifest semantics must
  remain stable.
- Reuse `CONTROLLER_OBSERVED_CONSUMPTION`: rejected because the controller
  observes request acceptance, not remote model byte consumption.
- Store external keys or credentials in the bundle: rejected because the
  bundle contains target-derived material and is not a secret store.
- Retry the same request ID after timeout: rejected because the upstream call
  may already have acted.

## Validation

- schema and invariant tests for backend-specific leases, request artifacts,
  authority/backend matching, and one-use request IDs;
- policy tests for `remote_static` read/network-only authority;
- end-to-end in-process gateway coverage for lease through commit;
- adversarial response, signature, transform, artifact, replay, and key
  rotation tests; and
- full historical compatibility, report, lifecycle, lint, generation, and
  release-wiring suites.

## Rollback

Stop creating `remote_static` plans and remove the `run-remote` command. Existing
schema-v6 bundles remain verifiable from their signed request and acceptance
artifacts. Local schema-v1-v5 execution and manual ingestion remain unchanged.
