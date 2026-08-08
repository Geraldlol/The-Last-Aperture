# Authorized external HTTP reconnaissance protocol

Protocol: `http-recon-v1`

Platform release: 0.11.0

This is a narrow external-target observation protocol. It is not a repository
audit, the `remote_static` provider gateway, a T2 proof recipe, a crawler, or an
exploitation engine. See
[`ADR 0013`](adr/0013-authorized-external-http-recon.md) and its
[`ADR 0014`](adr/0014-operator-attested-http-recon.md) and
[`ADR 0015`](adr/0015-url-first-pkix-http-recon.md) amendments.

## Authorization modes

`OPERATOR_ATTESTED` is the default no-file path. The operator supplies one
exact HTTPS URL, their identity, the declared authorizer, an authorization
reference, and an explicit attestation. `HEAD` is the default method. The
controller creates `attested-scope.json`, seals exactly one action, an explicit
TLS policy, and a 15-minute window, and performs no DNS or network I/O during
planning. The default `PKIX_HOSTNAME` policy needs no advance certificate
lookup or SPKI value. This is an operator declaration only. It does not
independently verify owner permission, ownership, legal authority, or current
revocation.

`EXTERNAL_SIGNED` is the optional higher-assurance path. It requires an
externally signed RoE, independently pinned owner Ed25519 public key, the
authorization document whose SHA-256 the RoE binds, and a fresh signed
target-control proof before each action. The controller never authors or signs
those artifacts.

Both modes seal the exact target, TLS verification policy, method, URL,
validity, limits, and action IDs before network access. Target content and
responses cannot add actions or change authority. Signed mode remains exactly
SPKI-pinned. Operator-attested mode may optionally add the same advance pin,
but does not require one.

## Commands

The command family is deliberately separate from `npm.cmd run audit`:

```powershell
npm.cmd run audit:http-recon -- plan `
  --target-url https://target.example/exact-path `
  --operator-id <operator-id> `
  --authorized-by "asset owner name or role" `
  --authorization-reference "ticket, email, or conversation reference" `
  --attest-authorized `
  --out C:\audit-runs\http-recon-run-001

npm.cmd run audit:http-recon -- next `
  C:\audit-runs\http-recon-run-001

npm.cmd run audit:http-recon -- run `
  C:\audit-runs\http-recon-run-001 <action-id> `
  --operator-id <operator-id> `
  --rationale "authorized header and status observation" `
  --confirm-authorization-current

npm.cmd run audit:http-recon -- stop `
  C:\audit-runs\http-recon-run-001 `
  --operator-id <operator-id> `
  --reason "operator stop"

npm.cmd run audit:http-recon -- finalize `
  C:\audit-runs\http-recon-run-001

npm.cmd run audit:http-recon -- validate `
  C:\audit-runs\http-recon-run-001

npm.cmd run audit:http-recon -- report C:\audit-runs\http-recon-run-001
```

The default method is `HEAD`. Use `--method OPTIONS` when needed. For `GET`,
use `--method GET --safe-to-get`; that acknowledgment is not proof that a
broken target has no side effects. An operator-attested plan may add
`--tls-spki-sha256 <64-lowercase-hex>` when an independently obtained pin is
available.

The optional signed mode uses `plan-signed` with `--roe`,
`--authorization-document`, and `--owner-public-key`. Its later `next`, `run`,
`finalize`, and `validate` calls receive the document and key options exactly as
described by ADR 0013. Those options are rejected for operator-attested bundles.

`next` returns the next legal sealed action. `run` accepts only that
`action-id`; no URL, target, method, TLS policy, header, credential, payload,
proof URL, retry, or limit can be changed after planning. Operator-attested `run`
requires the same operator ID that created the attestation and
`--confirm-authorization-current` before every dispatch. It makes zero
proof requests and at most one target request. Signed `run` makes one bounded
proof request and at most one target request.

`stop` is idempotent and remains usable after authorization expiry or bundle
failure. `finalize` reports the terminal denominator; `validate` rechecks the
mode-specific scope bindings; `report` returns the generated report path and
does not contact the target.

## Exact v1 network boundary

Target actions are exact normalized URLs under the one sealed `https://`
origin, using only `HEAD`, `GET`, or `OPTIONS`. A `GET` additionally requires
an explicit `safe_to_get` acknowledgment in either authority mode; that
assertion is not proof that a broken target has no side effects. URLs cannot
contain user information, fragments,
literal-IP or wildcard hosts, or target-derived substitutions. DNS and
connection checks reject loopback,
private, link-local, multicast, documentation, unspecified, and otherwise
non-public destinations; redirects are never followed. TLS certificate and
hostname validation remain enabled. Under `PKIX_HOSTNAME`, the action uses the
runtime-configured CA trust and normal hostname verification. The controller
records the leaf certificate and SPKI SHA-256 values from that same connection
before sending the request; it does not make a certificate-discovery preflight
and does not silently promote the observed hash into a future pin.

The request headers are fixed by the controller and credential-free. There is
no request body, authentication, cookies, client certificate, token, custom
authorization header, or ambient proxy credential. The controller neither
crawls nor parses links. Status, bounded response headers, timing, byte count,
and a streaming body digest may be recorded. A normal response body is never
exposed to the agent, parsed, searched, reported, or retained; it is discarded
after bounded hashing/counting. Only signed mode may retain bounded signed
target-control proof JSON as control evidence.

The shipped v1 ceilings are hard controller/schema maxima:

| Resource | v1 ceiling |
|---|---:|
| Exact target actions | 1 operator-attested; 64 externally signed |
| Live target-control proof requests | 0 operator-attested; 64 externally signed |
| Exact target origins | 1 per engagement |
| Concurrent target actions | 1 |
| Maximum network-request start rate | 1 request per second |
| Target-control proof age | 5 minutes |
| Per-proof or action deadline | 30 seconds |
| Total execution window | 15 minutes |
| Target-control proof JSON | 65,536 bytes |
| Normal response body transport | 1,048,576 bytes per action |
| Aggregate proof and response bytes | 1,048,576 operator-attested; 8,388,608 externally signed |
| Response headers | 16,384 bytes |
| Redirects followed | 0 |
| Automatic retries | 0 |

Operator-attested limits are fixed by the controller. A signed RoE may choose
lower signed-mode values. No response, operator rationale, or later command may
raise either mode's sealed limits. Response-header projection retains at most
64 safe header names and redacts credential-bearing values. A cap breach stops
the current operation and closes future dispatch.

The controller performs no path discovery, crawling, authentication, body
analysis, mutation, exploitation, fuzzing, brute force, persistence, lateral
movement, data exfiltration, social engineering, or load testing. `GET`,
`HEAD`, and `OPTIONS` names do not establish that a target implementation is
side-effect free. Any `3xx`, `429`, or `5xx` response is recorded and stops
later dispatch rather than being followed or retried.

## Signed-mode live target-control proof

Every externally signed `run` performs a new proof fetch before its one action. The proof URL is
an exact signed RoE input, uses HTTPS, follows no redirect, and cannot be
learned or replaced from target content. The bounded JSON proof must be fresh,
signed by the externally pinned owner key, and bind the engagement and
authorization IDs, authorization-document digest, target origin and TLS SPKI,
proof URL, RoE challenge nonce, and plan digest. Key rotation, expiry, clock
invalidity, signature failure, binding mismatch, DNS drift, unexpected content
type, oversize JSON, or an ambiguous proof fetch prevents the target action.

The proof demonstrates only that the holder of the pinned key made a fresh
target-control assertion. It is not independently verified asset ownership,
legal authorization, a trusted-time attestation, or permission to add actions.

Operator-attested mode performs no proof fetch and has no machine revocation
signal. The mandatory per-action confirmation records only that the executing
operator says permission remains current.

## State, stop, and ambiguous delivery

Before each applicable proof fetch and target request, the controller durably records a
lease/intention bound to the exact action. Immediately before sending request
bytes it also records the verified DNS set, selected address, server name,
certificate hash, observed SPKI hash, and TLS verification mode. An action is
`NOT_SENT` only when the controller can establish that no action bytes left the
process. Once bytes may have left, a missing response is `OUTCOME_UNCERTAIN`,
including after timeout, connection reset, process crash, restart, or
cancellation.

`stop` first writes a durable stop marker. New dispatch checks that marker and
fails closed; an in-flight request is asked to cancel and its actual or
uncertain outcome is retained. Stop, authorization expiry, signed-mode proof failure,
destination drift, integrity failure, or any budget breach prevents later
actions. An uncertain action is consumed, is never called not sent, and is
never retried automatically. Repeating it requires a new plan and a new
mode-appropriate authorization decision.

Terminalization never hides partial work. A fully observed denominator may end
`PROBE_PLAN_COMPLETE`. Operator or policy stop, failure, and uncertainty remain
distinct terminal outcomes in the bundle and report.

## Report contract and nonclaims

Every signed-mode report includes:

> Authorized external HTTP reconnaissance only. No repository or source was
> supplied; repository inventory, lens activation, source closure, and code
> coverage are NOT APPLICABLE. Completion means only that the hash-bound HTTP
> request denominator ran within the signed Rules of Engagement.

Every operator-attested report begins with "Operator-attested external HTTP
reconnaissance only" and replaces the last sentence with:

> Completion means only that the locally hash-bound HTTP request denominator
> ran within the operator-attested scope.

It also states that no signed RoE, authorization document, independently
pinned owner key, ownership proof, or live revocation signal was supplied or
verified, and that permission is an operator declaration only.

The denominator lists every exact action and its observed, not-sent, failed,
stopped, or uncertain outcome.
`NO_FINDINGS_OBSERVED_IN_AUTHORIZED_PROBED_SURFACE` is permitted only for a
complete, unambiguous denominator with no security observation. Never write
"clean", "safe", "secure", or `NO_FINDINGS_REPORTED` for this protocol.

The report makes no claim of:

- repository inventory, lens activation, source closure, code coverage, or a
  T0-T3 proof tier;
- vulnerability absence, response-body review, authenticated behavior, access
  control, exploitability, persistence, or data-exposure coverage;
- behavior outside the exact URLs, methods, time window, and caps;
- independent ownership, legal sufficiency, revocation status, or trusted time;
- independent verification of an operator-attested permission declaration;
- conformance with OWASP APTS or NIST SP 800-115.

External metadata observations cannot be imported as repository coverage or
used to raise a repository finding's proof tier.

## Machine contracts

- [`http-recon-roe.schema.json`](../schemas/http-recon-roe.schema.json)
- [`http-recon-target-proof.schema.json`](../schemas/http-recon-target-proof.schema.json)
- [`http-recon-attested-scope.schema.json`](../schemas/http-recon-attested-scope.schema.json)
- [`http-recon-run.schema.json`](../schemas/http-recon-run.schema.json)
- [`http-recon-observation.schema.json`](../schemas/http-recon-observation.schema.json)

## No implicit exploitation tier

`http-recon-v1` has no exploit transition. A future exploitation protocol must
define a separate typed action and schema, exact payload and cleanup rules,
fresh authorization and live control checks, monotonic action and cumulative
impact counters, and a fresh human countersignature for every exploit action.
The reconnaissance signature or operator attestation, rationale, live proof,
response, and completion state cannot satisfy that countersignature. No
response-driven or automatic chaining is allowed.

## Standards posture

The design uses [OWASP APTS 0.1.0](https://owasp.org/APTS/standard/) as a
governance baseline for machine-enforced scope, action allowlisting, bounded
impact, redirects, live safety controls, and audit trails. It uses
[NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final), especially
section 6.5 and Appendix B, as the baseline for approved assessment planning,
scope, authorized actors, logistics, incident handling, and written Rules of
Engagement. These are design inputs only. This project claims conformance with
neither source. In particular, operator-attested mode does not provide the
signed authorization proof called for by APTS-SE-001 and is documented as a
lower-assurance exception rather than a conforming autonomous-pentest mode.
