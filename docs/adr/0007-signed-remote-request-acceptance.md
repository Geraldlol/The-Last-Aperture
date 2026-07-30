# ADR 0007: Signed remote request acceptance

Date: 2026-07-30
Status: Accepted for the v0.8 build

## Context

The sealed provider path proves that one trusted local adapter consumed exact
planned bytes, but it deliberately has no credential and no external network.
Remote model use needs a credential-holding gateway without giving the
sandbox, repository, or provider packet an upstream API credential. It must
also preserve the distinction between a gateway accepting bytes and a model
understanding or correctly analyzing them.

The boundary has three independent integrity problems:

1. bind the exact canonical request body, including sealed source and controls;
2. authenticate the controller and gateway without a bearer secret in either
   payload; and
3. record the gateway's exact prompt-transform and upstream-request digests
   without overstating them as semantic proof.

The transport design follows the security properties in RFC 9421 and RFC 9530:
the endpoint and content must both be bound, and a digest without a signature
is not an authentication mechanism.

Primary sources:

- RFC 9421, HTTP Message Signatures:
  https://www.rfc-editor.org/rfc/rfc9421.html
- RFC 9530, Digest Fields:
  https://www.rfc-editor.org/rfc/rfc9530.html
- Node.js 20 `crypto.sign` and Ed25519 behavior:
  https://nodejs.org/download/release/latest-v20.x/docs/api/crypto.html
- OWASP Secrets Management Cheat Sheet:
  https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

## Decision

Version 0.8 introduces a provider-neutral `remote-gateway-v1` protocol.

### Trust and credential boundary

- The upstream model credential exists only in the gateway's secret manager.
- The controller holds a gateway-scoped Ed25519 client key, not the upstream
  credential.
- The gateway holds its own Ed25519 receipt key.
- Both key paths and the gateway configuration remain outside the target and
  run bundle. Embedded public keys establish self-consistency only; external
  key pins establish identity.
- HTTPS is mandatory. The controller pins both the certificate SPKI digest and
  the gateway receipt key.

### Exact request

The controller sends canonical JSON containing:

- immutable run, job, packet, plan, repository, policy, lens-pack, and sealed
  snapshot digests;
- one request ID, one attempt ID, a nonce, and a short validity window;
- the exact portable job packet;
- exact sealed source/control bytes with path, size, and SHA-256 bindings; and
- an externally configured prompt-transform ID and digest.

The controller signs the complete application envelope with Ed25519. The HTTP
request additionally carries RFC 9530 `Content-Digest`. Redirects, URL
credentials, query strings, fragments, content encodings, and non-canonical
JSON are rejected.

The application envelope is used instead of a partial RFC 9421 profile because
the security object is already a bounded canonical document and must remain
portable outside HTTP. This avoids signing intermediary-sensitive header
representations while retaining an exact body digest and fixed endpoint.

### Acceptance receipt

The gateway verifies the controller key, time window, request signature,
artifact digests, packet binding, prompt-transform pin, and one-use request ID
before invoking a provider. It signs an acceptance envelope that binds:

- the exact HTTP request body digest;
- the request, attempt, nonce, run, job, and packet identities;
- the accepted prompt-transform ID and digest;
- the exact upstream request body digest; and
- the exact raw job-result digest.

`REMOTE_REQUEST_ACCEPTED` means only that the trusted gateway accepted that
exact request and returned the packet-bound result. It does not mean that a
model consumed every byte, comprehended it, performed semantic analysis
correctly, or proved a finding. `semantic_analysis_proven` is fixed to `false`.

### Replay and failure behavior

The gateway consumes the request ID before the provider call. A provider error
does not make that identifier reusable, because the upstream call may have
acted before failing. Production gateways must retain a durable terminal
record and return the cached outcome or an explicit duplicate response.

The first implementation slice supplies strict schemas, signing and
verification primitives, an SPKI-pinned HTTPS client, and a replay-safe
reference acceptor. Controller attempt-ledger integration is the next step in
the same v0.8 build and may not weaken these contracts.

## Consequences

Positive:

- Upstream credentials never enter a target-derived prompt, sandbox, or run
  bundle.
- Exact bytes, transform identity, and returned result are independently
  content-addressed.
- Request replay and transform drift are fail-closed.
- The protocol is provider-neutral and uses the project's existing Ed25519 and
  canonical-JSON conventions.

Costs and residual risks:

- Source leaves the local machine when the external Rules of Engagement and
  gateway configuration authorize it.
- Gateway compromise can expose source and fabricate gateway claims. External
  key pinning proves which gateway signed, not that the gateway is honest.
- HTTPS PKI and the explicit SPKI pin become operational dependencies.
- Acceptance is weaker than controller-observed byte challenge consumption and
  much weaker than independent semantic proof.
- Key rotation requires an explicit configuration and run boundary; silent
  in-run rotation is forbidden.

## Alternatives considered

- Put the upstream credential in the container: rejected because repository
  data and provider logic would share the credential boundary.
- Send a bearer token from the controller: rejected as the primary identity
  mechanism because it is replayable and easy to leak in logs. A deployment
  may add transport authentication, but it does not replace signed envelopes.
- Sign only the body digest: rejected because request, attempt, transform, and
  expiry metadata must be covered together.
- Trust TLS without an application receipt: rejected because no durable
  artifact would bind the returned job result to the accepted request.
- Claim controller-observed consumption: rejected because the controller does
  not observe a remote model consuming or understanding the bytes.

## Validation

- Schema and semantic rejection for HTTP URLs, mutable URL components,
  impossible byte budgets, unsafe artifact paths, duplicate IDs, malformed
  timestamps, and non-canonical base64.
- Request signature, external controller-key pin, packet digest, payload
  digest, exact artifact byte, prompt-transform, lifetime, and expiry tests.
- Acceptance signature, external gateway-key pin, exact request digest,
  transform, upstream request, job result, and time-window tests.
- RFC 9530 content-digest mismatch and non-canonical JSON rejection.
- Replay test proving the provider is invoked exactly once.
- End-to-end reference acceptor/client test with no external network or
  credential.

## Rollback

The protocol modules and schemas are additive until controller ledger
integration lands. Removing the remote command later leaves sealed local
execution and manual ingestion unchanged. A `REMOTE_REQUEST_ACCEPTED` artifact
must never be reinterpreted as `CONTROLLER_OBSERVED_CONSUMPTION` or
`INDEPENDENTLY_PROVEN`.
