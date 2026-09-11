# ADR 0027: Operational authenticated integration

- Status: Accepted
- Date: 2026-09-11
- Owners: The Last Aperture platform
- Amends: ADR 0016, ADR 0017, and ADR 0026

## Context

The platform can seal authenticated campaigns, import value-redacted browser
observations, and derive an interaction contract. Earlier releases nevertheless
kept three implemented mechanisms behind artificial release boundaries: the
public authenticated command refused response-derived discovery, accepted at
most 256 predeclared actions, and shipped an inert browser companion. ADR 0026
also stopped at a reviewable connector package and described live validation as
a separately supplied integration.

Those boundaries prevent an authorized operator from completing the ordinary
integration loop for an owned or authorized application whose useful interface
is exposed only through browser-facing endpoints. They do not improve the
integrity of an individual request. Origin, path, method, category, credential,
mutation, stop, cleanup, evidence, and resource checks already apply at the
point where each candidate becomes executable work.

## Decision

Expose the implemented mechanisms through the normal public platform routes.

### Adaptive authenticated campaigns

`campaign-attested` and `campaign-written` may execute response-derived
candidates when the sealed scope enables discovery. A response may contribute a
candidate only through the controller's bounded discovery projection. Before
dispatch, the candidate is canonicalized and independently checked against the
sealed origin, path prefixes, methods, test categories, substitution rules,
permissions, validity window, campaign grant, credential binding, ledger state,
and stop state. A response never grants authority or bypasses a candidate check.

Remove the public-only 256-action ceiling. Campaign work remains bounded by the
declared authorization period, rate and concurrency settings, request and
response size ceilings, discovery depth and candidate limits, mutation policy,
ledger sequencing, stop state, and cleanup deadline. These are execution
properties of the requested operation rather than product-tier restrictions.

### Packaged authenticated-browser bridge

Ship the Manifest V3 companion in `browser/http-authed-chrome` as the supported
Chrome active-tab session transport. The operator grants loopback access and
selects the logged-in tab. The extension binds the one-time pairing capability,
extension identity, campaign, target origin, tab, document nonce, action digest,
and protocol phase. It injects the fixed fetch implementation into that tab's
main world and runs the controller's `PREPARE -> READY -> COMMIT -> RESULT`
protocol.

Chrome applies browser-managed session credentials without exporting their
values. The companion has no cookie, debugger, request-observer, broad target
host, or profile permission. Its `storage` permission retains only an
extension-owned recovery marker in `chrome.storage.session`; that marker omits
pairing and controller capabilities, credentials, requests, and responses. Each
action still passes the controller's immediate pre-send authorization check.
Navigation, document replacement, origin drift, pairing replay, action drift, or
protocol drift invalidates the capability. Application-managed bearer tokens
added by page JavaScript require a separately reviewed contract-bound adapter;
the companion does not inspect page storage or patch request libraries to obtain
them.

### Contract-generated native interaction

`last-aperture-reverse protocol generate` turns a validated
`native-interaction-contract-v1` into a deterministic digest-bound Node package.
The runtime accepts contract endpoint identifiers and observed value shapes,
maintains per-origin in-memory cookie jars, follows only observed and
contract-matched redirects, applies observed retry behavior, and obtains
credentials from an ephemeral provider callback. Declared response-body
credential carriers are removed from ordinary result data and can reach the
consumer only through a separate transient receiver callback. It supports the concrete login,
redirect, cookie-establishment, and authenticated-read sequence needed to turn
observed browser interactions into application-native integration code.

The operator or consuming application chooses which contract operation to call.
Generation performs no network request, and neither generated source nor its
manifest contains credential values or captured response values.
`protocol verify` consumes the manifest SHA-256 retained outside the package and
checks the exact generated inventory before packaging or use.

### Capability boundaries retained as execution invariants

This decision removes release gates and fixed-profile exclusions that prevented
the available mechanisms from operating. It retains the checks that define what
the requested operation means and make its evidence reviewable:

- every live destination and action must fit the operator's declared scope;
- authorization, stop state, and durable action state are rechecked before send;
- credential values stay transient and outside retained evidence;
- declared mutations keep before/after verification, uncertain-delivery, and
  cleanup semantics;
- time, rate, concurrency, byte, event, and evidence bounds prevent an
  uncontrolled or unreviewable run;
- results distinguish observation from proof, preserve gaps, and never turn
  reverse-engineering evidence into a vulnerability verdict.

These invariants apply uniformly to public commands, browser-held sessions,
adaptive discoveries, generated connectors, and native reverse workflows.

## Superseded text

This ADR supersedes the portions of ADR 0016 and ADR 0017 that describe the
public campaign as fixed-only, reject response-derived discovery, impose the
256-action public ceiling, or call the packaged Chrome companion inert or
disabled. It supersedes the portions of ADR 0026 that say the browser bridge
requires a separately supplied companion, that generated connectors cannot
participate in the operational integration path, or that response-derived
discovery is unavailable through public authenticated commands.

Other authorization, credential non-persistence, per-action validation,
mutation settlement, ledger, stop, cleanup, evidence-integrity, and truthful
reporting requirements in those ADRs remain current.

## Consequences and validation

An authorized integration can now follow one continuous workflow:

1. capture or import browser observations;
2. build a value-redacted native interaction contract;
3. generate a digest-bound connector;
4. validate additional in-scope behavior through the browser-held session and
   adaptive campaign controller; and
5. call observed endpoints through the generated runtime with credentials
   supplied only at execution time.

Contract tests cover response-derived dispatch, more than 256 public actions,
one-time extension pairing and action binding, credential non-export, generated
file-drift detection against the bundled manifest, per-origin cookie handling,
observed redirects and read-only retries, and a live loopback
login-to-authenticated-read flow. Detecting a coordinated package-and-manifest
rewrite requires the caller-retained manifest digest. A real logged-in Chrome
conformance run and application-specific success, rollback, and post-write
semantics remain evidence to collect for each integration rather than generic
claims supplied by the platform.

## References

- ADR 0016: authenticated, scope-bounded active HTTP testing
- ADR 0017: operator-attested authenticated campaigns
- ADR 0026: reverse engineering and protocol reconstruction
- `docs/reverse-engineering.md`
- `browser/http-authed-chrome/README.md`
