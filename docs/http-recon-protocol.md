# Authorized external HTTP reconnaissance protocol

Protocol: `http-recon-v1`

Protocol design: introduced in 0.11.0. Version 0.16.0 retains exact read support
for the target-neutral run 1.0 and 1.1 formats. Retired target-specific run 1.2
response-profile artifacts require the 0.12 verifier and cannot resume under the
current controller. Run 1.3 is the target-neutral continuation used after a
controller-proven before-send Pause; the corresponding
`ACTION_PAUSED_BEFORE_SEND` event uses event-record 1.1 while legacy event shapes
remain event-record 1.0.

> **Current 0.16.0 execution status: active.** `go <exact-https-url>` records the
> invocation as the operator's launch directive and completes one bounded live
> action. Lower-level `plan` and `run` invocations are also operator directives;
> the controller does not request a second confirmation flag.

This is a narrow external-target observation protocol. It is not a repository
audit, the `remote_static` provider gateway, a T2 proof recipe, a crawler, or an
exploitation engine. See
[`ADR 0013`](adr/0013-authorized-external-http-recon.md) and its
[`ADR 0014`](adr/0014-operator-attested-http-recon.md) and
[`ADR 0015`](adr/0015-url-first-pkix-http-recon.md) and
[`ADR 0018`](adr/0018-controller-governed-diagnostic-http-recon-headers.md)
amendments. [`ADR 0021`](adr/0021-operator-statement-authorization.md) defines
the current authorization model.

## Authorization

The authorization model below applies to the direct and legacy `http-recon-v1`
command family. Target-only `engage unleash <target>` is a separate controller
entrypoint: it accepts no operator identity, attestation, profile, authority
file, output path, provider, or credential input. The Unleash controller loads
deployment policy and revocation state, admits the exact canonical target for
the observation effect, and binds that controller-policy authority to its plan
and retained completion evidence. Its current enrolled route fixes `HEAD`, uses
only native transport-default headers, and accepts no caller-selected,
diagnostic-profile, or credential headers. Before that action dispatches, the
Unleash controller writes an immutable risk receipt, records a contextual or
explicit aggressive/balanced/cautious profile, and enforces hard volume limits.
An exact high-risk or high-noise receipt requires controller confirmation bound
to its action and assessment digests. This technical gate does not replace or
renew deployment authority. Direct and legacy `http-recon-v1` commands retain
the authorization behavior described below and do not use the Unleash profile.

`OPERATOR_ATTESTED` is the authorization path. The operator supplies one
exact HTTPS URL, their identity, the declared authorizer, an authorization
reference, and invokes the attested route. That invocation is the explicit
operator statement and is accepted as the controller's authorization fact.
`HEAD` is the default method. The
controller creates `attested-scope.json`, seals exactly one action, an explicit
TLS policy, and a 15-minute window, and performs no DNS or network I/O during
planning. The default `PKIX_HOSTNAME` policy needs no advance certificate
lookup or SPKI value. No external RoE/legal-proof artifact or repeat
certification is required. The controller does not independently prove the
operator's underlying legal authority or current external revocation state.

The controller seals the exact target, TLS verification policy, method, URL,
validity, limits, and action ID before network access. Target content and
responses cannot add actions or change authority. The operator may optionally
supply an advance SPKI pin; it is a transport-identity constraint, not a second
authority source. Schema `1.1.0` may additionally seal one finite
controller-owned diagnostic request-header profile. It never accepts a raw
header name or value.

## Commands

The command family is deliberately separate from `npm.cmd run audit`:

```powershell
npm.cmd run audit:http-recon -- go `
  https://target.example/exact-path `
  --out C:\audit-runs\http-recon-run-001

npm.cmd run audit:http-recon -- plan `
  --target-url https://target.example/exact-path `
  --operator-id <operator-id> `
  --authorized-by "operator-declared authorizer" `
  --authorization-reference "operator-held reference or none" `
  --out C:\audit-runs\http-recon-run-001

npm.cmd run audit:http-recon -- next `
  C:\audit-runs\http-recon-run-001

npm.cmd run audit:http-recon -- run `
  C:\audit-runs\http-recon-run-001 <action-id> `
  --operator-id <operator-id> `
  --rationale "authorized header and status observation"

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
available. A reviewed diagnostic experiment may add
`--request-header-profile <controller-profile>`. The profile is immutable after
planning.

`go` is the shortest path: the invocation supplies the operator declaration,
plans one exact action, executes it, finalizes the bundle, and returns its report.
`next` returns the next legal sealed action. The transport accepts only that
`action-id`; no URL, target, method, TLS policy, header
profile, credential, payload, retry, or limit could change after
planning. A lower-level operator-attested `run` requires the same operator ID;
its invocation is the operational launch decision and does not repeat the legal-
authority statement.

`stop` is idempotent and remains usable after authorization expiry or bundle
failure. `finalize` reports the terminal denominator; `validate` rechecks the
scope and operator-statement bindings; `report` returns the generated report path and
does not contact the target.

The 15-minute authority and wall-clock windows continue to elapse while an
action is in a controller-proven before-send Pause. Resume revalidates current
authority before dispatch can reopen; expiry or revocation keeps it closed.
Stop remains available after that point. Any later target dispatch requires a
successor campaign with current authority.

## Exact v1 network boundary

Target actions are exact normalized URLs under the one sealed `https://`
origin, using only `HEAD`, `GET`, or `OPTIONS`. A `GET` additionally requires
an explicit `safe_to_get` acknowledgment in the sealed scope; that
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

Request headers are controller-owned and credential-free. Legacy schema `1.0.0`
uses only the fixed baseline set. Operator-attested schema `1.1.0` may add one
sealed named diagnostic profile whose exact values exist only in controller
code; durable evidence retains the profile, header names, and binding digest,
not values. Arbitrary headers, `Host`, authentication, cookies, client
certificates, tokens, custom authorization headers, and ambient proxy
credentials remain refused. There is no request body. The controller neither
crawls nor parses links. Status, bounded response headers, timing, byte count,
and a streaming body digest may be recorded. A normal response body is never
exposed to the agent, parsed, searched, reported, or retained; it is discarded
after bounded hashing/counting.

The shipped v1 ceilings are hard controller/schema maxima:

| Resource | v1 ceiling |
|---|---:|
| Exact target actions | 1 |
| Exact target origins | 1 per engagement |
| Concurrent target actions | 1 |
| Maximum network-request start rate | 1 request per second |
| Per-action deadline | 30 seconds |
| Total execution window | 15 minutes |
| Normal response body transport | 1,048,576 bytes per action |
| Aggregate response bytes | 1,048,576 |
| Response headers | 16,384 bytes |
| Redirects followed | 0 |
| Automatic retries | 0 |

The limits are fixed by the controller. No response, operator rationale, or
later command may raise the sealed limits. Response-header projection retains at most
64 safe header names and redacts credential-bearing values. A cap breach stops
the current operation and closes future dispatch.

The controller performs no path discovery, crawling, authentication, body
analysis, mutation, fuzzing, brute force, persistence, lateral
movement, data exfiltration, social engineering, or load testing. `GET`,
`HEAD`, and `OPTIONS` names do not establish that a target implementation is
side-effect free. Any `3xx`, `429`, or `5xx` response is recorded and stops
later dispatch rather than being followed or retried.

## State, stop, and ambiguous delivery

Before the target request, the controller durably records a lease/intention
bound to the exact action. Immediately before sending request
bytes it also records the verified DNS set, selected address, server name,
certificate hash, observed SPKI hash, and TLS verification mode. An action is
`NOT_SENT` only when the controller can establish that no action bytes left the
process. Once bytes may have left, a missing response is `OUTCOME_UNCERTAIN`,
including after timeout, connection reset, process crash, restart, or
cancellation.

`stop` first writes a durable stop marker. New dispatch checks that marker and
fails closed; an in-flight request is asked to cancel and its actual or
uncertain outcome is retained. Stop, authorization expiry, destination drift,
integrity failure, or any budget breach prevents later
actions. An uncertain action is consumed, is never called not sent, and is
never retried automatically. Repeating it requires a new plan and a new
operator statement.

Terminalization never hides partial work. A fully observed denominator may end
`PROBE_PLAN_COMPLETE`. Operator or policy stop, failure, and uncertainty remain
distinct terminal outcomes in the bundle and report.

## Report contract and nonclaims

Every direct/legacy `OPERATOR_ATTESTED` report begins with "Operator-attested
external HTTP reconnaissance only" and includes:

> Completion means only that the locally hash-bound HTTP request denominator
> ran within the operator-attested scope.

It also states that authorization is the operator's declaration and that the
controller did not independently establish its legal basis or external
revocation state.

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
- independent verification of the operator's permission declaration;
- conformance with OWASP APTS or NIST SP 800-115.

External metadata observations cannot be imported as repository coverage or
used to raise a repository finding's proof tier.

## Machine contracts

- [`http-recon-attested-scope.schema.json`](../schemas/http-recon-attested-scope.schema.json)
- [`http-recon-run.schema.json`](../schemas/http-recon-run.schema.json)
- [`http-recon-observation.schema.json`](../schemas/http-recon-observation.schema.json)

## No implicit exploitation tier

`http-recon-v1` has no exploit transition. ADR 0017 defines the separate
operator-attested `http-authed-v1` route; ADR 0016 defines its shared campaign
mechanics. Each controller uses its own scope, credential, ledger, mutation,
rollback, and technical action-permit contracts. A reconnaissance statement,
rationale, response, or completion state cannot authorize the authenticated
route; it requires its own target/scope statement. Response-driven chaining remains
forbidden here. Public authenticated campaigns reject discovery-enabled scopes
and dispatch only the fixed actions sealed before launch; no response can add or
authorize another action.

## Standards posture

The design uses [OWASP APTS 0.1.0](https://owasp.org/APTS/standard/) as a
governance baseline for machine-enforced scope, action allowlisting, bounded
impact, redirects, live safety controls, and audit trails. It uses
[NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final), especially
section 6.5 and Appendix B, as the baseline for approved assessment planning,
scope, authorized actors, logistics, incident handling, and written Rules of
Engagement. These are design inputs only. This project claims conformance with
neither source. The controller accepts the authenticated operator statement as
its authorization fact and does not claim that this proves legal authority or
standards conformance.
