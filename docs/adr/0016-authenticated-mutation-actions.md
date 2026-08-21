# ADR 0016: Authenticated, scope-bounded active HTTP testing (http-authed-v1)

- Status: Accepted - implemented in v0.12.0
- Date: 2026-08-16
- Owners: Red Team Audit platform
- Extends: ADR 0013, which reserved authenticated/mutation actions for a separate
  typed tier; relates to ADR 0014 (operator-attested lower-assurance mode) and
  ADR 0015 (PKIX defaults). Does NOT extend `http-recon-v1` or the repository
  proof tiers.
- Amended: ADR 0017 (2026-08-17) supersedes this ADR's operator-attested routing,
  runtime-command, and reporting restrictions.

## Amendment notice

ADR 0017 implements `plan-attested`, `validate-attested`, and
`campaign-attested` as a distinct declaration-only route. Do not use this ADR's
original routing matrix, `(non-production only)` operator-attested qualification,
or written-only runtime wording as the current release contract. ADR 0017 permits
the attested mode across declared classifications while requiring
`independently_verified: false` and explicit nonclaims. This ADR continues to
govern transport, discovery, mutation, rollback, browser-session, evidence, ledger,
and uncertainty mechanics.

## Context

`http-recon-v1` is deliberately credential-free and read-only: fixed headers, no
cookies, no request body, response body discarded, no redirects, one exact URL.
ADR 0013 walled off anything beyond that — "Exploitation is not a flag or
continuation of `http-recon-v1`. Any future capability requires a separate typed
action tier and schema, an auditable monotonic action ledger,
exact payload and cleanup semantics, fresh scope and target-control validation,
and a fresh human countersignature binding each exploit action."

This ADR defines that tier for the specific case of **authenticated, state-
changing HTTP actions**: send a credential without exposing its value, confirm
liveness, issue exact bounded requests, and — before any state-changing request —
enforce target, expected mutation, before/after verification, rollback, and fresh
confirmation.

The authority problem is sharper than in recon. A credential, a URL, and an
operator's assertion of ownership are not authorization. For a system the operator
does not own — for example a third-party SaaS holding PHI — only the asset owner
can authorize mutation testing, and the operator holding "owner" keys they minted
themselves makes the gate decorative rather than real. The design must therefore
keep two assurance levels *and* prevent the cheap one from standing in for the
expensive one where it matters.

## Decision

Create `http-authed-v1` as a controller protocol separate from `http-recon-v1`,
the `remote_static` gateway, and the repository proof tiers. Its actions may carry
one sealed credential reference and may use canonical uppercase application-method
tokens explicitly listed in the engagement authorization, including standard write
and extension methods. Native transport refuses `CONNECT` and protocol upgrades;
browser transport also refuses `TRACE` and `TRACK`. Canonical uppercase is required
because the Node transport normalizes method casing and HTTP method tokens are
case-sensitive. Planning is
network-free. Runtime discoveries may produce new
candidate actions, but every candidate is checked against the sealed campaign
scope before dispatch; a response can never widen that scope. Once the durable
campaign ledger is opened, it records those candidates for sequencing and
evidence without imposing an action-count ceiling.

### Current implementation status

The current authorization routing and command surface are amended by ADR 0017.
The text below records the initially accepted written-mode implementation; both
attested and written runtime routes now share these technical mechanics.

The implementation includes the schema and semantic validators, written-document
rehash/current-validity checks, canonical path/method/category checks, a canonical
`campaign_grant_sha256`, the offline generic `plan-written` scope generator, the
one-shot `probe-written` compatibility command, and
the ledger-backed `campaign-written` runtime. The HTTPS transport uses
public-address DNS binding, PKIX (and optional SPKI pinning), follows no redirect,
performs no retry, and returns metadata only. The controller rereads the scope and
written authorization and checks the controller-held campaign grant immediately
before every send. New work must remain before `validity.not_after`; only
ledger-proven rollback and rollback verification may continue through
`validity.cleanup_not_after`.

`plan-written` may omit a per-mutation approver for a written, probe-only scope.
Explicit mutation authority still requires a pinned Ed25519 approver and its
enrollment metadata before the scope can validate.

`campaign-written` opens an external immutable hash-chained ledger, enqueues the
sealed plan, drains response-derived candidates sequentially, and dispatches each
candidate at most once. Discovery accepts bounded Link, Location, Allow, HTML
links and safe GET forms, recognized JSON hypermedia links, OpenAPI operations,
and sitemap locations. Query values and OpenAPI path parameters are replaced by
sealed `SYNTHETIC_*` values. Response-derived execution is limited to
GET/HEAD/OPTIONS; write-capable hints require a predeclared mutation envelope.
There is no candidate-count ceiling.

Declared mutations perform credential preflight, exact before-state verification,
one mutation attempt, after-state and sibling-context verification, one always-on
rollback attempt, and rollback verification. Each mutation requires a fresh
campaign-bound Ed25519 countersignature. Its nonce is durably consumed after the
before-state matches and before the mutation send permit; it cannot be reused for
another action. Ambiguous mutation or rollback delivery is never retried. Bodies
are transient bounded buffers and only status, byte count, header names, and
verification booleans reach the result and ledger. The approver signature is also
bound to the canonical campaign-ledger directory, and the controller reserves
enough time through `validity.cleanup_not_after` for mutation settlement plus the
cleanup sequence.

There is no campaign action-count, cumulative-impact, aggregate-response, or
controller wall-time ceiling. Repeated candidates can be dispatched throughout the
authorization window. The ledger atomically allocates monotonic sequences, uses
immutable canonical records with a predecessor-byte hash chain, serializes writers,
and fails closed on tampering, gaps, links/junctions, stale leases, and unexpected
entries. A durable pre-dispatch record is a consumed attempt. Restart recovery
never resends a mutation or rollback: it stops new campaign work, converts the
interrupted phase to an ambiguous settlement, and runs only the remaining sealed
rollback/verification phases. A retained record-count/head checkpoint can anchor
later replay and detect deletion beneath that retained prefix.

Restart cleanup cannot reconstruct the pre-mutation sibling-context token without
persisting a response-derived digest, so a recovered rollback can verify the
declared field but reports sibling context as unavailable and keeps the campaign
stopped for review. Accepted static route segments also cannot be proven PHI-free by syntax; operators
must use synthetic route identifiers. Raw candidate URLs, response/request bodies,
header values, arbitrary target-controlled header names, credentials, and rejected discovery values are not copied into the
ledger or public result. A general content-sensitive PHI classifier remains future
work, so the implementation claims non-persistence at these controlled boundaries,
not universal de-identification of arbitrary operator-supplied scope text.

### Three authorization modes

1. **`OPERATOR_ATTESTED_AUTHED`** (lower assurance). The operator supplies the
   credential reference and an explicit ownership + authorization attestation. No
   independent cryptographic verification and no live revocation signal. Carries
   the ADR-0014-style non-claims: permission is an operator declaration only.

2. **`WRITTEN_AUTHORIZATION_AUTHED`** (document-bound interim assurance). The
   operator supplies the vendor's written authorization as bounded bytes outside
   the target workspace. The controller seals and re-checks its SHA-256 before
   dispatch, records its issuer/reference/issue date, and requires an explicit
   extraction of the permissions it grants: active testing, production,
   third-party, PHI-sensitive, and mutation. It also binds authorized origins,
   path prefixes, methods, test categories, every dispatched action, and a
   renewable execution lease. Actions may be discovered during the campaign,
   but each is validated against that engagement scope before dispatch. The
   controller records this document-bound grant
   but does not claim to judge its legal sufficiency or cryptographically verify
   its issuer. The validator emits `campaign_grant_sha256` over the canonical
   extracted scope. A controller-held copy detects later scope widening; the hash
   does not prove that the operator's extraction faithfully interprets the source
   document.

3. **`EXTERNAL_SIGNED_AUTHED`** (higher assurance). Requires an asset-owner-signed
   RoE naming each exact action, its `expected_mutation`, and its rollback; an
   independently pinned owner Ed25519 key; a fresh live target-control proof; and
   an **independent approver key** — distinct from the operator identity — for the
   per-action countersignature.

### Routing matrix (enforced at plan time, fail-closed)

> **Superseded by ADR 0017.** This matrix records the original ADR 0016 routing
> decision and is not the current operator-attested release boundary.

The operator DECLARES target ownership, environment, and data class at plan time.
The matrix then *forces* the minimum assurance mode; it can raise the requirement
but never lower it.

| Target ownership          | Environment      | Data class | Required mode                                   |
| ------------------------- | ---------------- | ---------- | ----------------------------------------------- |
| operator-owned/controlled | `non_production` | non-PHI    | `OPERATOR_ATTESTED_AUTHED` permitted            |
| any with matching written vendor authorization | any | permissions explicitly extracted from the writing | `WRITTEN_AUTHORIZATION_AUTHED` permitted |
| operator-owned            | `production`     | any        | `WRITTEN_AUTHORIZATION_AUTHED` or `EXTERNAL_SIGNED_AUTHED` |
| third-party-owned         | any              | any        | `WRITTEN_AUTHORIZATION_AUTHED` or owner-provisioned `EXTERNAL_SIGNED_AUTHED` |
| any                       | any              | PHI        | Written mode with explicit PHI permission, or `EXTERNAL_SIGNED_AUTHED` |

The controller cannot verify ownership from a declaration — but it can bind the
declaration to the run and fail closed on contradiction: if the live proof's owner
identity, or the sealed target origin matching a known third-party host list,
contradicts an "operator-owned/non-production/non-PHI" declaration, the plan is
rejected. A `production`, `PHI`, `third-party-owned`, or mutation declaration
cannot select `OPERATOR_ATTESTED_AUTHED`. It must select document-bound written
authorization or the higher-assurance externally signed mode; schema
`const`/`if-then` enforces this rather than relying on prose.

### Key provisioning and enrollment (internal passkey-approver mode)

The v1 approver mechanism is a **platform passkey (WebAuthn)**, chosen so a
non-technical approver never generates or handles a key by hand:

- **Enrollment (once):** an internal approver registers a passkey on their own
  device (Face ID / Touch ID / Windows Hello). The resulting credential public key
  becomes the pinned owner/approver key; the private half stays non-exportable in
  the device secure element. Enrollment is performed and recorded by the org's
  IT/security function, **not** by the operator running the test — that separation
  is what makes the pin trustworthy for internal targets.
- **Authorization:** the approver signs the RoE with a single passkey gesture; the
  WebAuthn challenge is the RoE payload digest.
- **Per-action approval:** each mutating action is a fresh passkey assertion whose
  challenge is that action's digest (`action_id` + `expected_mutation` + rollback +
  `plan_sha256` + nonce). One biometric tap per action; not reusable.
- **Controller verification:** a WebAuthn verification path alongside the existing
  `verifySignedDocument` — verify the assertion signature, that the signed
  challenge equals the expected digest, that `authenticatorData` shows user
  presence/verification, and that the credential public key equals the pinned one.

This internal mode satisfies the operator-owned rows of the routing matrix,
including "operator-owned + production", where the approver must be independent of
the operator — an internal executive's passkey is that independent approver. It
does **not** satisfy the third-party-owned rows: a third-party target still
requires a passkey (or key) enrolled by *that owner's* organization, not an
internal one. A separately supplied written vendor authorization can instead
select `WRITTEN_AUTHORIZATION_AUTHED`; it is reported at its lower,
document-bound assurance level and never represented as an owner-key signature.

### Pin-provenance attestation

At enrollment the bundle records the credential fingerprint plus who enrolled it,
when, and under whose authority (four-eyes optional). The controller cannot verify
provenance but forces it to be recorded, so a later key substitution is evident.

### Sealed authentication modes (values never exposed)

The scope stores `{ ref, kind, binding_sha256 }`, where `ref` is `env:NAME` or
`stdin:PIPE`, `kind` is `cookie` or `bearer`, and `binding_sha256` is the SHA-256 of
the resolved secret at seal time. `--credential-env` serves controlled automation;
the mutually exclusive `--credential-stdin` serves an operator-mediated secret
handoff. Stdin must be redirected, is read once with a 64 KiB ceiling, and is never
echoed. The reader removes at most one pipeline-added terminal LF or CRLF and
rejects an empty value, any remaining CR/LF, NUL/control/header-invalid bytes, and
a `Cookie:` prefix. This preserves the exact copied request-header value while
preventing header injection and accidental inclusion of the header name.

Planning hashes the normalized stdin bytes, and every live invocation using that
scope requires the operator to redirect the same bytes again. The client compares
the current digest before attaching the secret transiently to the request.
`validate-written` needs no credential. No raw value is written to the scope,
ledger, result, report, error, or logs. Transport identity records omit it; only
the credential-bearing header name is retained, with its value redacted.

For a rotating Chrome login, `--credential-browser --browser-extension-id <id>`
instead seals `{ mode: "CHROME_ACTIVE_TAB_SESSION", extension_id, origin }`. It
stores no credential value or digest and is mutually exclusive with `env:` and
`stdin:`. Browser scopes require Chrome-managed PKIX/hostname TLS; controller SPKI
pin mode is refused because the companion cannot observe or enforce that pin.

The packaged Manifest V3 companion in `browser/http-authed-chrome` has only
`activeTab`, `scripting`, and loopback-host access. It has no cookie, storage,
debugger, request-observer, broad target-host, or profile permission. The
controller starts an IPv4-only loopback bridge and creates a random one-use
pairing capability bound to the sealed extension ID, campaign, and origin. In the
exact logged-in tab, one explicit operator attach binds that tab and document for
the campaign. Every action then follows `PREPARE -> READY -> COMMIT -> RESULT`,
with one action in flight, immediate pre-send authorization revalidation, and no
automatic retry.

The fixed injected function rechecks the tab origin, document nonce, action
binding, uppercase method, relative URL, body digest, and bounded headers before
one same-origin fetch. Chrome applies its current session and processes normal
cookie rotation internally on every request. Neither controller nor companion
reads cookie or Authorization values, `document.cookie`, browser storage, a
profile database, CDP, or HAR. Only bounded response material needed transiently
for discovery and mutation verification crosses loopback; evidence contracts
still forbid durable body or header values. Tab, document, origin, pairing,
protocol, or action drift fails closed.

### PHI-minimizing evidence handling

At the contract layer, every authenticated scope fixes `persist_request_bodies`,
`persist_response_bodies`, `persist_credential_values`, and
`persist_header_values` to `false`, requires synthetic test data, and stops when
unexpected sensitive data is detected. Request bodies are represented only by an
opaque body id, content type, byte length, and SHA-256; their bytes exist only
transiently at dispatch. The public result and ledger retain bounded status, size,
header names, binding digests, and verification booleans. These schema constraints reject raw body fields, but they cannot prove
that an arbitrary URL, identifier, or free-text label is PHI-free. The current
probe client enforces digest-bound synthetic bodies and metadata-only response
projection, but it has no content-sensitive detector. Operators must use synthetic
identifiers. The implemented boundaries are tested for non-persistence of raw
request/response bodies, header values, credential values, and rejected discovery
values; a future sensitive-data detector is still required for a universal claim.

### Liveness

- **Authorization liveness** — written mode rereads and rehashes the authorization
  document before every send. Ordinary actions require the current time to remain
  before `validity.not_after`; only a ledger-proven, already-consumed mutation's
  rollback and rollback verification may run before `validity.cleanup_not_after`.
  The `EXTERNAL_SIGNED_AUTHED` live target-control proof remains a separate future
  runtime path.
- **Credential liveness** — a sealed, bounded authenticated pre-flight
  (`GET` to a designated session-validity/"whoami" endpoint) requires a 2xx
  response before any mutation. Status and response byte count are recorded; the
  body is not persisted and the current slice does not claim a principal id. In
  browser mode Chrome selects the current session at each request; no exported
  binding becomes stale when the site rotates its cookie.

### The mutation gate (before every state-changing action)

1. **Target** — the action URL must lie within the sealed authorized origin and be
   covered by an authorized path prefix and method (and, in signed mode, by the
   owner-signed RoE). A discovered candidate is allowed only after this same
   just-in-time scope validation.
2. **Expected mutation** — a sealed `expected_mutation` descriptor: resource id,
   field, expected before-value, expected after-value. Signed in
   `EXTERNAL_SIGNED_AUTHED`. The controller will not dispatch a mutation whose
   effect is not declared.
3. **Before verification** — a sealed read (`GET`) captures the `before` state
   digest and checks it equals the declared expected-before; mismatch aborts before
   any write.
4. **Mutation** — one action dispatched.
5. **After verification** — a sealed read captures the `after` state digest;
   the observed change must equal `expected_mutation` and nothing outside the
   declared field may have changed (bounded diff). Any mismatch triggers rollback
   and stop.
6. **Rollback** — a pre-authorized inverse action, sealed in scope (and signed in
   signed mode), auto-executed on verification failure or stop-mid-mutation, with
   its own outcome verified. Recorded as `ROLLBACK_VERIFIED`,
   `ROLLBACK_ATTEMPTED`, or `ROLLBACK_UNCERTAIN`. The controller never claims
   guaranteed reversibility — audit trails, timestamps, and downstream propagation
   (e.g. a bidirectional record sync) may persist independently of the inverse
   write.
7. **Fresh confirmation** — a per-action human countersignature (Ed25519 over
   `action_id` + `expected_mutation` + rollback + `plan_sha256` + a fresh nonce +
   timestamp), verified with the pinned approver key within a short
   freshness window immediately before dispatch. Not reusable across actions; a
   recon signature, a prior action's signature, an operator rationale, or a
   response cannot satisfy it. Under ADR 0017, `OPERATOR_ATTESTED_AUTHED` records
   this as operator-declaration-only in any truthfully classified sealed scope;
   possession of the key does not prove the approver's identity, independence, or
   vendor authority. In `WRITTEN_AUTHORIZATION_AUTHED`, the
   countersignature is additionally bound through the plan digest to the written
   authorization digest and extracted campaign scope. Active probes that declare
   no expected state change use the campaign authorization and do not require a
   separate human approval for every request; declared mutations retain the
   mutation gate above.

### Campaign controls and cleanup

- There is no mutation-count, action-count, or cumulative-impact ceiling. A
  monotonic ledger exists for evidence and sequencing, not as a dispatch cap.
  Authorized exploration may continue for the engagement window, including
  actions discovered during the campaign, provided every action remains within
  the authorized origin, path, method, test-category, data-handling, and mutation
  permissions. There is no aggregate-response or controller wall-time cap; the
  ordinary authorization window (`validity.not_after`) defines how long new work
  may continue. `validity.cleanup_not_after` extends only the deadline for
  ledger-proven rollback and rollback verification.
  Per-request timeout/response-size, rate, concurrency, and emergency-stop
  controls remain operational safeguards and do not define the assessment's
  completeness denominator. The 64 MiB input-file bound protects the validator;
  runtime discoveries belong in the separate ledger rather than growing that file.
- Terminalization never leaves a half-applied, unverified mutation silent: either
  rollback completes and verifies, or the run terminates
  `MANUAL_INTERVENTION_REQUIRED` with the exact residual state recorded.
- `OUTCOME_UNCERTAIN` applies more strictly than in recon: a mutation whose
  delivery is ambiguous is consumed, never rewritten as not-sent, and never
  auto-retried. Cleanup recovery uses only that same sealed action and its durably
  consumed approval through `cleanup_not_after`; it cannot enqueue or send a new
  mutation. New mutations require the ordinary window and a fresh countersignature.

### Runtime material layout

`campaign-written` requires `--ledger` to name an absolute external directory.
Mutating actions and body-bearing probes also require an absolute `--materials`
directory. A countersignature for allocated sequence `N` is read from
`countersignature-N.json`. Synthetic body bytes are read from
`body-<sha256(body_id UTF-8)>.bin`; using the digest as the filename prevents a
body identifier from becoming a path traversal. Material files are bounded,
re-read without following links, and never copied into the ledger.

The controller-held `campaign_grant_sha256` comes from `validate-written`; it must
be supplied unchanged to `campaign-written`. The command also requires the exact
operator id and `--confirm-authorization-current` for every invocation.
Scopes sealed as `stdin:PIPE` additionally require `--credential-stdin` and
redirected stdin at every credential-bearing live invocation. Scopes sealed as
`CHROME_ACTIVE_TAB_SESSION` instead require `--credential-browser`, the expected
extension, and one explicit active-tab attach per campaign; they never accept an
exported credential fallback.

### Reporting non-claims

Reports state what ran — per-action before/after/rollback outcomes and the
authorization mode — and never "clean", "safe", "secure", or `NO_FINDINGS_REPORTED`.
No claim of legal authority, asset ownership, revocation status, trusted time, or
that rollback reversed downstream effects. `OPERATOR_ATTESTED_AUTHED` reports state
that permission is an operator declaration only and that no owner key, live proof,
or independent approver was verified. `WRITTEN_AUTHORIZATION_AUTHED` reports
state that the document digest and operator extraction were checked, but the
issuer was not cryptographically verified and legal sufficiency was not judged.

## Explicitly out of scope / refused

- A self-attested path that authorizes a credentialed **production** mutation of a
  system the operator does **not** own without either matching written vendor
  authorization or owner-provisioned signatures. A reporting form or operator
  rationale alone cannot select `WRITTEN_AUTHORIZATION_AUTHED`; the supplied
  document digest, extracted permissions, target scope, lease, and candidate
  action must all match at dispatch.
- Automatic retry of a mutation with uncertain delivery. Response-driven path
  discovery, crawling, and chaining are allowed only inside the authorized
  campaign scope and each derived request is revalidated before dispatch.

## Consequences

Positive: authorized, scope-bounded active testing with credential secrecy,
campaign-level approval for non-mutating probes, a human in the loop for declared
mutations, and honest uncertainty accounting. Both
self-owned non-production engagements and owner-authorized production/third-party
engagements are supported without collapsing the assurance distinction between
them.

Costs: `EXTERNAL_SIGNED_AUTHED` requires owner and independent-approver key
custody; the self-attested mode is deliberately capped at non-production, non-PHI,
operator-owned targets; the interim written mode depends on an operator's faithful
extraction of a vendor document whose issuer is not cryptographically verified;
rollback is best-effort wherever downstream systems propagate state; and the
operator must declare ownership/environment/data class honestly — a false
declaration is a governance failure the controller can detect only on
contradiction, not prevent outright.

## Rejected alternatives

- A single, freely selectable mode: rejected — operators would default to the
  cheaper self-attested path, nullifying owner authorization.
- Extending `http-recon-v1` with a POST flag or a credential option: rejected —
  ADR 0013 forbids it; mutation needs its own engagement scope, action ledger,
  rollback, and authorization checks.
- Trusting ownership from the operator's declaration alone to *lower* assurance:
  rejected — the declaration routes assurance up but can never route it down for
  production, PHI, or third-party targets.
- Cookie extraction through an extension, browser automation/CDP, profile
  databases, `document.cookie`, or HAR: rejected — it exposes unrelated session
  state. The companion dispatches a sealed request inside the selected origin;
  it never extracts browser authentication.
- Interactive cookie delivery through argv, a file, or a persistent environment
  variable: rejected — each leaves avoidable shell, process, filesystem, or crash
  residue. Redirected stdin keeps the controller blind to the browser and lets the
  operator supply only the already-sent request-header value.
- A browser companion with broad target host access, cookie/debugger/storage APIs,
  background crawling, or automatic replay: rejected — the active tab, origin,
  document, and action bindings are the browser transport's confinement boundary.

## Future work

- **Cloud signing service** — an owner SSO/MFA front end over a cloud HSM/KMS, as a
  higher-scale, higher-assurance approver for cross-org or many-approver
  engagements. It reuses the same controller verification unchanged: the controller
  pins the service's public key and verifies its signatures exactly as it verifies
  a passkey or a file-based owner key. Deferred until the internal passkey mode is
  in use.

## References

- ADR 0013 (separate protocol for authorized external HTTP reconnaissance)
- ADR 0014 (operator-attested authorization) and ADR 0015 (PKIX defaults)
- `docs/http-recon-protocol.md`
- OWASP Autonomous Penetration Testing Standard 0.1.0; NIST SP 800-115 §6.5, App. B
