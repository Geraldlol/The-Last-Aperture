# ADR 0013: Separate protocol for authorized external HTTP reconnaissance

- Status: Superseded for authorization mechanics by ADR 0021; retained as a
  historical record of the v0.11 externally signed route
- Date: 2026-08-04
- Owners: Red Team Audit platform
- Extends: ADR 0001; does not extend the repository proof tiers
- Amended by: ADR 0014 added an operator-attested one-action mode; ADR 0015 made
  that mode URL-first under PKIX; ADR 0021 retired `EXTERNAL_SIGNED` as an
  authorization mode

> **Supersession notice (2026-09-04):** The signed RoE, authorization document,
> owner key, and target-proof requirements below are historical. ADR 0021 makes
> the authenticated operator target/scope statement the sole authorization
> primitive. Transport, redirect, evidence, budget, stop, and uncertain-delivery
> mechanics remain relevant where the current controller retains them.
>
> **Current 0.12.0 execution status: active through the bounded
> operator-statement controller.** This status does not reactivate the historical
> signed authority path.

## Context

The repository audit protocol answers questions about supplied source. Its
inventory, lens activation, closure rounds, proof tiers, and coverage
denominators cannot describe a no-source observation of a deployed HTTPS
origin. Treating a URL as a repository, or treating a remote response as T2,
would manufacture coverage and weaken the long-standing rule that T2 is a
locally booted application reached only through loopback.

Remote target contact also has a different authority problem. A URL in chat, a
hostname found in source, or a user's assertion of ownership is not an
executable scope. Static authorization can expire or be copied to a target the
signer no longer controls. Conversely, a live target-control signal does not by
itself establish legal authorization. Both forms of evidence are required and
neither may be created or approved by the agent performing the work.

[OWASP APTS 0.1.0](https://owasp.org/APTS/standard/) is the design baseline for
external enforcement of scope, time, allowed actions, rate and impact limits,
redirect policy, stop controls, and audit evidence. In particular, this
decision follows the architectural direction of APTS-SE-001, SE-004, SE-006,
SE-008, SE-012, SE-019, SC-004, SC-009, SC-020, HO-003, HO-006, HO-008,
AL-001, AL-004, MR-001, MR-007, MR-008, MR-010, MR-012, and RP-008. APTS is a
governance standard rather than this project's test method, and the project
does **not** claim APTS conformance.

[NIST SP 800-115](https://csrc.nist.gov/pubs/sp/800/115/final), section 6.5 and
Appendix B, is the planning and authorization baseline. It calls for an
approved assessment plan that identifies scope, authorized assessors,
logistics, data handling, incident handling, authorized systems, exclusions,
allowable activities, and boundaries. This protocol uses those planning
principles but does **not** claim NIST conformance or determine that a supplied
document is legally sufficient.

## Decision

Create `http-recon-v1` as a controller protocol separate from repository
audits, the `remote_static` provider gateway, and T0-T3 proof recipes. Its only
target action is a single exact HTTPS `HEAD`, `GET`, or `OPTIONS` request. One
`run` invocation may execute one pre-authorized action and nothing discovered
in a response can create another action.

The controller fails closed unless all four authority inputs agree:

1. A canonical, externally created Rules of Engagement (RoE) names the exact
   actions, proof endpoint, time window, stop contact, and limits.
2. The RoE signature verifies with an Ed25519 owner public key supplied from an
   externally pinned path. A key embedded in the RoE, target response, or run
   bundle is never a trust root.
3. The SHA-256 digest of the separately supplied authorization document equals
   the digest bound by the signed RoE. Only the digest enters the bundle.
4. Immediately before every target action, the controller fetches a fresh,
   bounded target-control proof from the exact RoE-authorized HTTPS proof URL
   and verifies its signature and bindings with the same externally pinned
   owner key. A stale, malformed, redirected, mismatched, or unverifiable proof
   prevents the action.

The source RoE, authorization document, and owner key must pre-exist outside the
target and run bundle. The controller copies the verified signed RoE into the
bundle but never copies the authorization document or owner key. It may validate
the artifacts but neither controller nor agent may author, infer, repair,
self-sign, or self-approve them. The live proof confirms only the signed control
assertion at execution time; it does not replace the authorization document.

Planning is network-free and seals a hash-bound denominator of exact action
tuples. CLI options cannot override a target, URL, method, header, credential,
body, limit, or proof endpoint. Operator identity and rationale are recorded
for each action but cannot widen it.

## v1 action boundary

The controller permits only:

- one exact `https://` origin and the methods `HEAD`, `GET`, and `OPTIONS`, with
  `GET` requiring the owner's explicit signed `safe_to_get: true` assertion;
- normal public TLS validation, one controller-selected public DNS result, and
  destination revalidation before connection;
- a fixed, credential-free request-header set and no request body;
- one action at a time, in the signed order, after a new live proof check; and
- bounded response status, headers, timing, byte count, and digest evidence.

The v1 ceilings are controller/schema constants. The signed RoE may lower but
never raise them. They include a small action denominator, concurrency one, a
minimum inter-request interval, a per-request deadline, a total execution
window, and bounded proof/header/body bytes. The protocol document records the
exact shipped values.

The controller does not follow redirects, retry automatically, crawl, parse
links, discover paths, authenticate, send cookies or credentials, send a
request body, retain or analyze a normal response body, mutate state, fuzz,
brute force, exploit, persist, exfiltrate, or generate load. A response body is
streamed only through the hard size/digest boundary and discarded; bounded
signed proof JSON is the only target response body retained. A `3xx` response
is an observation, never a scope transition.

## Durable stop and uncertain delivery

`stop` is always available and does not depend on a still-valid RoE. It first
writes an idempotent durable stop marker, then prevents new dispatch and asks
the in-flight operation to cancel. Expiry, proof failure, destination drift,
cap breach, target-health threshold, integrity failure, or operator stop also
closes dispatch by default.

Before network I/O, the controller durably leases the exact proof fetch/action
attempt. If it cannot prove that no action bytes left the process, the outcome
is `OUTCOME_UNCERTAIN`; it is never rewritten as not sent. A timeout, reset,
crash, or stop during an in-flight request may therefore consume the action.
There is no automatic retry. Recovery preserves the attempt and stops the run;
repeating it requires a new signed authorization decision and a new plan.

This rule applies even to `GET`, `HEAD`, and `OPTIONS`: conventional method
semantics do not prove that a broken or hostile application has no side
effects.

## Reporting boundary

Every report carries this statement:

> Authorized external HTTP reconnaissance only. No repository or source was
> supplied; repository inventory, lens activation, source closure, and code
> coverage are NOT APPLICABLE. Completion means only that the hash-bound HTTP
> request denominator ran within the signed Rules of Engagement.

Reports distinguish observed, not-sent, stopped, failed, and uncertain actions.
When a complete denominator yields no security observation, the result phrase
is `NO_FINDINGS_OBSERVED_IN_AUTHORIZED_PROBED_SURFACE`, never "clean", "safe",
"secure", or `NO_FINDINGS_REPORTED`. An uncertain or incomplete denominator
cannot use that phrase.

The report claims no repository coverage, source closure, proof tier,
vulnerability absence, body-content assessment, authenticated behavior,
authorization-control coverage, asset ownership beyond the supplied signed
evidence, legal sufficiency, trusted time, exploitation, or APTS/NIST
conformance. Controller observations are not repository findings and cannot
raise a repository finding's T0-T3 tier.

## Original exploit-action boundary and later L3 qualification

When this ADR was accepted, exploitation was not a flag or continuation of
`http-recon-v1`. Any future capability required a separate typed action tier and
schema, new monotonic action and cumulative-impact counters, exact payload and
cleanup semantics, fresh scope and target-control validation, and a fresh human
countersignature binding each exploit action. A reconnaissance signature,
operator rationale, response, or successful completion could not be reused as
that countersignature, and automated chaining remained prohibited.

ADR 0020 later supersedes only that per-action approval cadence for a separate,
target-bound `L3_MAXIMUM_AUTHORIZED` campaign: one signed campaign envelope may
authorize adaptive actions inside that envelope once its controller services
exist. It does not convert reconnaissance authorization into exploit authority
or permit cross-target or unscoped chaining. Generic public L3 remains
unavailable, and any scope expansion must name the new asset and await operator
approval.

## Consequences

Positive:

- Remote observation can be useful without falsifying repository coverage.
- Authorization, live control, destinations, methods, and budgets are enforced
  outside the agent and target response.
- One-action dispatch, durable stop, and uncertainty accounting prevent hidden
  retries or response-driven expansion.
- The historical local-only meaning of T2 remains intact.

Costs:

- Operators must maintain signed external artifacts and a live proof endpoint.
- Benign network ambiguity ends a run instead of being retried.
- The slice intentionally cannot test authenticated or body-dependent behavior.
- Authorization evidence supports enforcement but is not legal advice or proof
  of ownership.

## Rejected alternatives

- Extend T2 to a hosted target: rejected because T2 is a local loopback proof
  tier and its consent prompt is not external authorization.
- Put URLs into repository RoE mode: rejected because repository scope and HTTP
  action scope have different denominators and claims.
- Trust a key or URL returned by the target: rejected because target-controlled
  data cannot establish its own authority.
- Allow response-driven crawl or retries: rejected because both create actions
  outside the signed denominator.
- Treat safe HTTP method names as harmless: rejected because delivery and
  server-side effects can be ambiguous.

## References

- [OWASP Autonomous Penetration Testing Standard 0.1.0](https://owasp.org/APTS/standard/)
- [OWASP APTS Rules of Engagement template](https://owasp.org/APTS/standard/appendix/Rules_of_Engagement_Template.html)
- [NIST SP 800-115 landing page](https://csrc.nist.gov/pubs/sp/800/115/final)
- [NIST SP 800-115 PDF](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-115.pdf)
