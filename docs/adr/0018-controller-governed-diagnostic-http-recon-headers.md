# ADR 0018: Controller-governed diagnostic HTTP-recon headers

Status: Accepted

Date: 2026-08-18

Amended by: ADR 0021 retires the separate signed authorization mode; the
controller-owned diagnostic-header profile boundary remains current.

> **Current 0.16.0 execution status: active through the bounded controller.**
> A `go` or lower-level `run` may select only the finite controller-owned header
> profiles defined here. Raw caller-selected header names and values remain
> outside the public interface.

> **Supersession notice (2026-09-04):** Signed-mode references below are
> historical. Authorization comes from the authenticated operator target/scope
> statement.

## Context

`http-recon-v1` originally emitted one fixed credential-free header set. That
made CORS, reverse-proxy trust, route-override, and safe-method-override
hypotheses impossible to test through the evidence controller. Sending such
requests outside the controller would lose the sealed action, durable
pre-dispatch record, transport identity, stop handling, and no-retry semantics.

## Decision

Operator-attested scope schema `1.1.0` may seal one named diagnostic
request-header profile. A profile is code-owned and finite; the CLI accepts only
`--request-header-profile <name>`, never a raw header name or value. The durable
descriptor contains the profile name, sorted header names, and a SHA-256 binding
of the exact controller-owned header set. Request-profile values are not written
as request metadata. Independently returned values may appear only through the
existing allowlisted response-header projection.

The initial profiles cover an actual hostile-origin `GET`, exact read-only
routing canaries, loopback proxy identity claims, and `OPTIONS`-to-`GET` method
override. All profile values are fixed in `http-recon-request-headers.mjs`;
protected paths are public API paths selected for non-PHI structural comparison. Unknown profiles, forged
descriptors, method mismatches, signed-mode target-proof use, and post-plan
overrides fail before network I/O.

The descriptor is included in the scope digest, plan digest, action ID, mutable
run projection, action lease, and pre-dispatch event. The transport expands it
only after schema/semantic verification and verifies it again before creating
the request. `Host`, credentials, cookies, framing headers, and arbitrary
caller-supplied headers remain unavailable.

## Invariants

- Operator-attested only; externally signed target-proof requests remain fixed.
- Exactly one target request, `HEAD`/`GET`/`OPTIONS` only, with no request body.
- No redirect, retry, discovery, response-body retention, or runtime override.
- `request.end()` remains argument-free.
- Request-profile values never enter durable request evidence.
- Legacy schema `1.0.0` scopes, action IDs, and bundles remain unchanged.

## Consequences

The controller can now produce disclosure-grade differentials for a narrow set
of proxy and routing hypotheses without becoming a general-purpose raw HTTP
client. Adding a new value requires a reviewed code/schema/test change rather
than an operator-provided string.
