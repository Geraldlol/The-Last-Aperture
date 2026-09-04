# ADR 0019: Bounty program perimeter protocol (`bounty-v1`)

Status: Accepted

Date: 2026-08-21

> **Current-release safety amendment (2026-09-03):** the live capabilities
> described in this historical decision are not exposed by the product CLI.
> Recon execution, authenticated replay, scanning, OOB operations, and all proxy
> capture/query/import commands fail closed pending migration to the detached
> signed-plan controller in ADR 0020. No loadable mitmproxy addon ships. The pure
> scope kernels, planners, historical-import libraries, and fixture helpers remain
> only as offline/reference components. Where this ADR says a phase is "built" or
> a socket opens, read it as the original architecture, not a current capability.

## Context

`http-recon-v1` seals exactly one URL, defaults to `HEAD`, and refuses body,
redirect, retry, discovery, and mutation. `http-authed-v1` seals an enumerated
request list before execution. Both are correct for work a clearance is staked
on, and neither can carry bug bounty hunting: the request worth sending is the
one discovered mid-session, and enumerating it in advance is precisely what
cannot be done.

Bounty hunting also needs a *harder* boundary than an audit, not a softer one.
Straying costs program removal or unauthorized contact with an uninvolved third
party, and the volume involved means a single wrong inference is sent thousands
of times before anyone notices.

Forcing a fuzzer into `http-recon-v1` would have damaged both: the protocol whose
identity is restraint would acquire a discovery loop, and the hunting work would
inherit per-action ceremony that makes exploration unaffordable.

## Decision

A third protocol, `bounty-v1`, seals a **predicate** rather than an action.

`plan` digests a program policy snapshot into `policy_snapshot_sha256` and seals
mode `PROGRAM_POLICY_SEALED`: platform, program handle, scope rules, validity
window, and permissions including an `intensity` tier. The original design made
requests inside that perimeter low-ceremony; the current release does not treat
the perimeter alone as action approval and exposes no live request path.

The ceremony gradient inverts relative to `http-authed-v1`: expensive to
authorize once per program, free per request thereafter.

The original design required every egress path to pass one pure decision
function (`scripts/lib/bounty-scope-kernel.mjs`) before a socket opened. The
current release retains the Node/Python scope kernels and proves their decisions
identical against a shared fixture suite, but exposes no egress path and ships no
interception-proxy addon.

Offline/reference components exist for perimeter sealing, historical capture
ingestion, authorization analysis, scan planning, report drafting, and OOB
contracts. Their former live entry points are disabled as described above.

## Invariants

- **Fail closed.** No branch returns ALLOW by default. An unlisted candidate, a
  malformed scope, a refused canonicalization, and a rule that throws all land on
  DENY with a reason.
- **Deny beats allow**, unconditionally. A program's carve-out cannot be undone
  by a broader wildcard.
- **A wildcard excludes its own apex.** `*.example.com` does not cover
  `example.com`, which must be listed separately.
- **Hostnames and IP literals never substitute for one another.** A name
  resolving to an address says nothing about who owns that address.
- **Loopback, RFC1918, link-local, and cloud metadata endpoints are denied** even
  when a rule names them, unless private targets are separately sealed.
- **The sealed rate limit is the authorization.** It is enforced, never advisory,
  and no intensity tier outranks it: `ham` requests unbounded concurrency and
  receives the sealed limit.
- **Intensity never moves the perimeter.** Sealing at `ham` produces `scope_rules`
  identical to `normal`, asserted in tests.
- **The validity window is enforced, not decorative.** `plan` refuses a window
  excluding its own attestation; `recon` and `authz` refuse an expired grant
  before any socket. `validate` reports currency and still opens the bundle,
  because evidence outlives authorization.
- **Two implementations of the boundary must agree.** The Node and Python kernels
  are asserted to return identical decisions *and reasons* for every shared
  fixture.
- **Redirects are recorded, never followed.** The target becomes a fresh
  candidate that must pass the gate on its own.
- **No PHI.** `data_class` is `const non_phi` and `permissions.phi` is
  `const false` in the schema; a PHI target cannot be sealed by any caller.
- **Credentials are referenced, never stored.** Roles name environment variables;
  captures and reports are redacted before persistence, and a missing variable is
  a hard error rather than a silent unauthenticated replay.
- **Identifier substitution uses declared identifiers only.** The schema has no
  range, wildcard, or increment form, because enumerating undeclared identifiers
  means reading a stranger's data to prove a bug.

## Nonclaims

- Operator enrollment in a program is **declared, not verified**. The controller
  does not check enrollment, asset ownership, scope currency, or revocation.
  `independently_verified` is `const false`.
- `bounty-v1` output is never repository coverage, never an audit clearance, and
  never an attestation. `COMPLETED` semantics do not apply and there is no
  `compare` path against an audit bundle.
- The strongest verdict any phase emits is a **candidate**. Nothing asserts a
  vulnerability, and no verdict string reads as one.
- A denial, a differing response, or an absent out-of-band callback is evidence
  about one request under one role. None of them clears an endpoint.
- A surface inventory reports `OBSERVED` or `PARTIAL`. There is deliberately no
  `COMPLETE`: any failed source leaves a recorded gap, and gaps force `PARTIAL`
  permanently.
- Passive scanner output is labelled as leads, not findings. A disclosed version
  string is not a vulnerability.

## Consequences

The repository becomes polyglot for the first time. The boundary is a process and
a JSONL contract rather than a shared library: the proxy only appends JSONL and
only Node touches SQLite, so there is no cross-language locking and the raw
capture stays replayable. The cost is a second implementation of the scope
kernel, which is why its agreement is machine-checked rather than reviewed.

Report drafting is deliberately conservative. Only an authorization-bypass
candidate is drafted; the other verdicts are declined with a stated reason,
because submitting unproven observations destroys the researcher signal that
earns private invites. Severity is a suggestion with per-metric justification,
never an assertion.

Submitting a report remains a human act; nothing is sent automatically. The
current release has no mitmproxy addon and therefore no certificate-installation
workflow.

Remaining known limits: no stateful multi-step authorization flows, no automatic
session refresh (an expired credential surfaces as uniform `ACCESS_DENIED`, which
the operator must notice), and no SMTP or LDAP out-of-band protocols.
