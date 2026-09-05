# bounty-v1 — Authorized Bug Bounty Hunting Protocol (Design)

> **Historical design; superseded for public execution.** The current release
> disables recon, authorization replay, crafted scanning, proxy forwarding, and
> OOB mint/poll before target, session, or network access. These paths may be
> reactivated only through authenticated operator ingress, controller-sealed
> permits, and the trusted transport/ledger gates, not by the mutable bundle
> trust model described below. ADR 0021 supersedes every signed-authorization,
> document-as-authority, owner-key, and caller-countersignature rule below.

- **Date:** 2026-08-20
- **Status:** Proposed — awaiting operator review
- **Becomes:** ADR 0019 at implementation time
- **Operator:** gmaida@peerstarllc.com
- **Platform target:** YesWeHack first; platform-agnostic by construction

## 1. Problem

`red-team-audit` ships two external HTTP protocols. Neither can carry bug bounty work.

`http-recon-v1` seals exactly one URL, defaults to `HEAD`, and refuses body,
redirect, retry, discovery, and mutation. That restraint is correct when a
clearance is staked on the result. It cannot hunt.

`http-authed-v1` enumerates every request in the sealed plan before execution.
Correct for a bounded campaign against a known application. Bounty hunting
cannot satisfy it: the interesting request is the one you discover mid-session,
and enumerating it in advance is precisely the thing you cannot do.

Bounty hunting needs high request volume, discovery-driven traversal, retry
tolerance, fuzzing, and an interception proxy for manual work. It also needs a
*harder* scope boundary than an audit, because straying costs program removal or
unauthorized contact with an uninvolved third party.

## 2. Core decision — seal the perimeter, free the interior

`http-authed-v1` seals **actions**. `bounty-v1` seals a **predicate**.

- One sealing event per program: policy snapshot digest, scope rules, validity
  window, permissions, rate limit.
- Inside the sealed perimeter: unlimited, unceremonious requests. No per-request
  ledger for reads.
- Every request passes the Scope Kernel before egress. Fail closed.
- Mutations retain `http-authed-v1` discipline: pinned approver, countersignature,
  before/after checks, inverse rollback, rollback verification.

This inverts the ceremony gradient. `http-authed-v1` is cheap to authorize and
expensive per action. `bounty-v1` is expensive to authorize and free per action.

## 3. Non-goals

- **Not Burp Suite Pro by feature count.** No crawler, no ~200-check active
  scanner, no Sequencer/Comparer/Decoder, no DOM Invader, no extension ecosystem.
- **Not a clearance.** `bounty-v1` output is never repository proof, never an
  audit result, never an attestation. `COMPLETED` semantics do not apply.
- **No PHI.** `data_class` must be `non_phi`. A target declared `phi` or
  `unknown` is refused at plan time.
- **No coverage claim.** Absence of findings means `NO_FINDINGS_REPORTED`, as
  everywhere else in this framework.

## 4. Protocol relationship

| | `http-recon-v1` | `http-authed-v1` | `bounty-v1` |
|---|---|---|---|
| Sealed unit | One URL | Enumerated request list | Scope predicate |
| Credentials | Never | Yes | Yes |
| Discovery | Refused | In-scope, planned | Core capability |
| Retry | Refused | Refused on ambiguity | Permitted, rate-limited |
| Volume | Single-digit | Bounded plan | Unbounded within scope |
| Per-action ceremony | Full | Full | Reads free, mutations full |
| Proxy | None | None | Yes (Shiny) |
| Output | Observations | Campaign ledger | Findings + evidence bundle |

The three protocols never merge. A `bounty-v1` bundle cannot be ingested as
repository coverage and has no `compare` path against an audit bundle.

## 5. Authorization — program sealing

New mode `PROGRAM_POLICY_SEALED`, sibling to `WRITTEN_AUTHORIZATION_AUTHED`.

A bounty program policy *is* a written authorization document: it names the
grantor, enumerates permitted assets, states prohibited actions, and carries a
validity period. We seal it as one.

Sealed fields:

- `platform` — `yeswehack` | `hackerone` | `intigriti` | `direct`
- `program_handle`, `policy_url`
- `policy_snapshot_sha256` — digest of the policy text as fetched at seal time
- `scope_rules` — allow and deny rule sets (see §6)
- `validity` — `not_before`, `not_after`
- `permissions` — `active_testing`, `production`, `third_party`,
  `phi` (forced `false`), `mutation`, `automation_allowed`,
  `intensity` (`normal` | `aggressive` | `ham`), `desync_probes`, `rate_limit_rps`
- `operator_id`, `attested_at`, `independently_verified: false`

**Nonclaim, recorded in the bundle verbatim.** Operator enrollment in the program
is *declared*. The controller does not verify that the operator is enrolled, that
the policy snapshot is authentic, that the program owns the listed assets, that
the scope has not since changed, or that the authorization has not been revoked.
`PROGRAM_POLICY_SEALED` records a claim; it does not validate one.

**Policy drift detection.** `revalidate` re-fetches the policy, re-digests it, and
refuses to continue when the digest differs. Programs silently remove assets and
narrow scope; a stale snapshot is how an in-scope request becomes an out-of-scope
one without anybody touching the rig. Drift forces a re-seal.

## 6. Scope Kernel — the safety-critical core

A pure function. No network, no clock, no filesystem, no environment access.

```
decide(sealedScope, candidate) -> { decision: ALLOW | DENY, rule_id, reason }
```

Decision rules, in order:

1. **Deny precedence, always.** An explicit deny beats any allow, including a
   more specific allow.
2. **Unlisted is DENY.** No implicit scope. There is no inference path from
   "resolves to the same host" to "in scope".
3. **Wildcard semantics.** `*.example.com` matches `sub.example.com` and
   `a.b.example.com`. It does **not** match the apex `example.com`, which must be
   listed separately. This is the most common scope error in the field.
4. **IP literals are never inferred.** A hostname resolving to an address does
   not put that address in scope. Shared hosting and CDN front-ends make the
   inverse assumption actively dangerous.
5. **Unconditional deny** for loopback, RFC1918, link-local, and cloud metadata
   endpoints (`169.254.169.254`, `metadata.google.internal`, `100.100.100.200`)
   unless explicitly and separately sealed.
6. **Ports.** 80 and 443 only, unless other ports are sealed.
7. **Path scope.** Supported — some programs scope `/api/*` and nothing else.
8. **Kernel error is DENY.** Any exception, malformed input, or unreachable
   branch fails closed.

**Cross-language conformance.** The Node implementation is the reference. The
Python proxy addon implements the same decision table and must pass a
byte-identical shared fixture suite, following the pattern already established by
`database-conformance`. Two implementations of a security boundary are only safe
when a machine proves they agree.

## 7. Components and data flow

```
  YWH program policy
        |
        v
  [ intake ] --seal--> bounty-scope.json  (policy digest + rules + validity)
        |
        +-----------------+-----------------+
        v                 v                 v
  [ recon ]        [ Shiny proxy ]    [ scanner ]
  subfinder/httpx   mitmproxy +        narrow checks
  every candidate   scope addon        every request
  scope-checked     every flow         scope-checked
        |           scope-checked            |
        v                 v                 v
   surface-inventory   flows.jsonl      candidates
        |                 |                 |
        +--------> [ ingest ] <-------------+
                        |
                        v
                  flows.sqlite  <---- [ authz grinder ]
                        |                  multi-role replay
                        v                  + response diffing
                   findings (finding.schema.json)
                        |
                        v
                  evidence bundle --> [ report --format ywh ]
```

Chrome (via Chrome MCP) routes through Shiny, so authenticated browsing is
captured without the rig ever reading a cookie — consistent with the existing
`CHROME_ACTIVE_TAB_SESSION` boundary in `http-authed-v1`.

## 8. Shiny — the interception proxy

mitmproxy core, separate process, Python. We do not reimplement TLS
interception, HTTP/2 framing, WebSocket handling, or chunked-encoding edge cases.
Bugs there become silent false negatives, which in this trade means unpaid bugs.

The addon owns: scope enforcement (deny is blocked *and* logged), flow capture,
passive rule evaluation, and tagging.

**Store boundary.** The proxy appends canonical JSONL. A Node `ingest-flows`
command loads it into SQLite via built-in `node:sqlite` (Node 24.13.0 confirmed
present). Rationale: no cross-language SQLite locking, the raw capture stays
replayable, and it matches the repo's existing `ingest` idiom.

This makes the repo polyglot for the first time. The boundary is a process and a
JSONL contract — not a shared library — and the scope decision is
conformance-tested across both sides.

## 9. The authz grinder

The highest-yield automatable bug class, and the thing Burp Pro is weakest at.

- **Role registry.** N credential sets, each with a refresh procedure, plus the
  unauthenticated role.
- **Matrix.** For every captured request, replay as every other role and as
  unauthenticated.
- **Normalization before diffing.** Strip timestamps, CSRF tokens, request IDs,
  nonces, and cache headers. Unnormalized diffing produces noise that buries
  signal.
- **Classification.** Equivalent response across roles is a candidate authz
  bypass. Distinct-but-successful is a candidate information leak. Denied is
  correct behavior.

An overnight run across a few thousand captured requests is the concrete form of
"you are the hunter" — volume no human works through by hand.

## 10. Scanner scope — narrow by default

**In:** injection into JSON and GraphQL bodies; URL-valued parameters flagged as
SSRF candidates (parked until OOB exists); path traversal; passive rules for
secrets in JS bundles, internal hostnames, verbose errors, and debug headers.

**Out:** mass XSS fuzzing, mass SQLi fuzzing, CVE template sweeps. `nuclei` does
these better than anything we would write. Run it separately and ingest its JSON.

Breadth here is a duplicate-and-N/A factory on picked-over programs. Depth on
logic bugs is where the money is. §20 defines the escape hatch when narrow is not
enough.

## 11. Recon pipeline

Install Windows-native Go binaries: Go toolchain, `subfinder`, `httpx`, `ffuf`,
`nuclei`. No WSL distro needed; no Docker daemon needed.

Every candidate host passes the Scope Kernel *before* any probe touches it —
including passive-source candidates, which is where wildcard scope errors leak
into third-party infrastructure. Output is a surface inventory sealed into the
bundle.

## 12. Controller surface

`scripts/bounty.mjs`, exposed as `npm run audit:bounty`. Verbs match existing
controller idiom.

```powershell
npm.cmd run audit:bounty -- plan --platform yeswehack --program <handle> --policy-file <snapshot> --operator-id <id> --attest-enrolled --out <bundle>
npm.cmd run audit:bounty -- validate <bundle>
npm.cmd run audit:bounty -- revalidate <bundle> --policy-file <fresh-snapshot>
npm.cmd run audit:bounty -- scope <bundle> --check <url>
npm.cmd run audit:bounty -- recon <bundle> --confirm-authorization-current
npm.cmd run audit:bounty -- proxy <bundle> start|status|stop
npm.cmd run audit:bounty -- ingest-flows <bundle> <flows.jsonl>
npm.cmd run audit:bounty -- flows <bundle> --query <expr>
npm.cmd run audit:bounty -- grind <bundle> --roles <roles.json>
npm.cmd run audit:bounty -- scan <bundle> --select <expr> --checks <list>
npm.cmd run audit:bounty -- hunt <bundle> --intensity <normal|aggressive|ham> --confirm-authorization-current
npm.cmd run audit:bounty -- finding <bundle> add|list|promote
npm.cmd run audit:bounty -- report <bundle> <finding-id> --format ywh
npm.cmd run audit:bounty -- stop <bundle>
npm.cmd run audit:bounty -- finalize <bundle>
```

Bundles live outside any target directory, as everywhere else in this framework.

## 13. Schemas

New:

- `schemas/bounty-scope.schema.json` — modeled on `http-authed-scope.schema.json`,
  with `requests` replaced by `scope_rules`, plus the `program` block.
- `schemas/bounty-flow.schema.json` — canonical captured-flow record.
- `schemas/bounty-run.schema.json` — run state, intensity, and stop conditions.

Reused unchanged: `finding.schema.json`, `evidence-bundle.schema.json`,
`controller-execution-envelope.schema.json`, `controller-failure-envelope.schema.json`.

## 14. Findings and reporting

Findings use the existing `finding.schema.json`. The nonclaim discipline carries
over intact and matters commercially here: an unproven finding stays `UNPROVEN`,
and unproven findings do not get submitted. Speculative reports burn program
reputation and hunter signal, which is the currency that buys private invites.

`report --format ywh` emits YesWeHack-shaped markdown: summary, impact, sealed
scope reference, reproduction as copy-pasteable `curl`, evidence references, CVSS
vector, and remediation. Every claim traces to a captured flow ID.

## 15. Testing strategy

- **Scope Kernel adversarial fixtures** — the critical suite. Wildcard apex
  handling, trailing dots, IDN/Unicode homographs, `http://allowed.com@evil.com`
  userinfo confusion, IPv6 literal forms, case folding, port confusion,
  path-prefix escapes, and every deny-precedence combination.
- **Cross-language conformance** — Node and Python agree on every fixture.
- **Proxy** — recorded flow fixtures, no live network.
- **Authz grinder** — synthetic multi-role app with known-correct answers.
- **Intensity tiers** — asserts intensity rises and the scope perimeter does not
  move. See §20.
- **No live-network tests in CI.** Ever.

## 16. Phasing

| Phase | Deliverable | Gate |
|---|---|---|
| P0 | Scope Kernel + program sealing + CLI skeleton + adversarial fixtures | Kernel passes full fixture suite |
| P1 | Recon pipeline + surface inventory | Every candidate provably scope-checked |
| P2 | Shiny proxy + flow ingest + cross-language conformance | Both implementations agree |
| P3 | Role registry + authz grinder | Synthetic app findings correct |
| P4 | Narrow scanner + passive rules + nuclei ingestion | No false-positive flood |
| P5 | Intensity dial (`normal`/`aggressive`/`ham`) across P1–P4 | Perimeter provably unmoved at every tier |
| P6 | YWH report generator | Report traces every claim to a flow |
| P7 | OOB interaction server | **Blocked** — needs domain + VPS |

P0 ships before anything touches a network. The kernel is the whole safety story.

## 17. Blind spots until P7

Blind SSRF, blind XXE, blind RCE and deserialization, out-of-band SQLi, and most
blind SSTI are invisible without an interaction server. A domain with wildcard
DNS and a low-cost VPS unblocks the category.

## 18. Risks

| Risk | Mitigation |
|---|---|
| Scope Kernel defect sends an unauthorized request | Fail closed, deny precedence, no implicit scope, adversarial fixtures, cross-language conformance |
| Program silently narrows scope | `revalidate` digest check refuses to continue on drift |
| Automation trips rate limits, operator gets banned | Sealed `rate_limit_rps` enforced in both proxy and recon paths |
| Python enters a zero-dep Node repo | Process boundary plus JSONL contract; no shared library; conformance-tested |
| Bounty output mistaken for audit clearance | Separate bundle kind, explicit nonclaim, no shared result types, no `compare` path |
| HAM used where the program forbids automation | Gated on sealed `permissions.intensity` plus `automation_allowed`; refuses to seal `ham` unless the policy grants both |

## 19. Open questions for the operator

1. ~~`node:sqlite` experimental warning~~ — **Resolved 2026-08-20:** use `node:sqlite`
   and accept the warning. Queryable SQL over captured traffic is worth a noisy
   stderr line, and it keeps the dependency count at zero.
2. mitmproxy install route on Windows — `pipx` or `py -m pip`?
3. Is `nuclei` ingestion wanted in P4, or deferred until the manual loop is proven?

## 20. Intensity — normal, aggressive, and HAM

**Operator requirement:** a trigger for when we *need* to find something. Rarely
used, and when used it removes every brake that exists to make the rig polite
rather than effective.

Intensity is a sealed enum in `permissions`, recorded in the bundle, and read by
every component in §9–§11. It is **not** a separate code path — one path means the
perimeter cannot be forgotten in the aggressive branch.

| Tier | Posture | Requires |
|---|---|---|
| `normal` | Narrow, sampled, cheap. The daily driver. | — |
| `aggressive` | Exhaustive within each bug class, sequentially. | `active_testing` |
| `ham` | **Hounds of war.** Every class at once, recursive, until convergence. | `active_testing` + `automation_allowed` |

### HAM — what `ham` adds on top of `aggressive`

`aggressive` is exhaustive *within* a class. `ham` is exhaustive *across* all of
them simultaneously and recursively:

- **All classes in parallel.** One worker per bug class against the same sealed
  surface, all running at once, rather than class-after-class.
- **Recursive convergence.** Every newly discovered endpoint, parameter, or role
  immediately re-enters the full pipeline from the top. The run ends when a full
  pass discovers nothing new — not when a checklist is finished.
- **Compound attacks.** Primitives get chained rather than tested in isolation:
  IDOR + race, SSRF + redirect chain, cache poisoning + reflected input, auth
  bypass + mass assignment. Most real critical findings are compounds.
- **No early exit.** No "probably not vulnerable, moving on." The candidate space
  is exhausted.
- **Auto-escalation.** Any anomaly signal — timing deviation, inconsistent status
  code, unexpected content-length, error-message change — spawns a focused
  deep-dive worker on that endpoint immediately.
- **Third-order tracking.** Payload effects correlated across sessions, roles, and
  days, not just within one response.
- **Multi-day campaigns.** Checkpointed state, resumable, running as long as the
  sealed validity window allows.
- **Sustained ceiling.** Concurrency pinned at the sealed rate limit for the
  duration, not ramped politely.

### What both tiers take off

| Brake | Aggressive and HAM behavior |
|---|---|
| Sampled authz matrix | **Exhaustive.** Every role × every captured request × every mutated identifier. No sampling, no early exit. |
| Concurrency throttle | Raised to the sealed rate ceiling and held there. |
| Narrow payload sets | Full sets: polyglots, encoding chains, nested/double encoding, content-type confusion, parser-differential payloads. |
| First-order only | **Second-order tracking.** Stored payloads correlated across later responses and out-of-band sinks. |
| Single-request testing | **Race and concurrency classes.** Parallel burst testing for TOCTOU, double-spend, limit-bypass, and state races. High-payout, rarely tested. |
| Surface-level auth | **Session and token attacks.** JWT `alg` confusion, `kid` injection, key confusion, signature stripping, session fixation, reset-token entropy. |
| Single-step flows | **Business-logic chains.** Multi-step state manipulation, step skipping, replay, parameter carry-over between steps. |
| Shallow JS reading | **Deep client analysis.** Sourcemap recovery, bundle parsing for hidden endpoints, embedded credentials, feature flags, internal API contracts. |
| Wordlist ceilings | Full parameter mining and content discovery within scope. |
| Session-length runs | Overnight and multi-day grinds with checkpointed state. |
| Sequential bug classes | Parallel fan-out — independent workers per bug class against the same sealed surface. |
| Polite protocol handling | **Desync and smuggling probes** — CL.TE, TE.CL, TE.TE, H2 downgrade — *gated separately* on `permissions.desync_probes`, because desync can affect other users and some programs forbid it explicitly. |

### What does not come off, and why

Four things stay fixed at every intensity. Not caution — these are the conditions
that make flooring it survivable.

1. **The Scope Kernel.** Never bypassed, never softened, no override flag. A
   request outside the sealed perimeter is unauthorized access to someone who
   never invited us: instant program removal, plausibly criminal, and it ends the
   whole enterprise rather than one session. The perimeter is what *permits* the
   aggression — we can run every payload in the book at full concurrency
   precisely because we know with certainty where the track ends.
2. **The program's own rate limit.** When the policy states a limit, that limit
   *is* the authorization. Exceeding it is out of scope by definition, and it is
   the single most common way automated hunters get banned. Where the policy is
   silent, we set our own ceiling and hold it.
3. **Availability.** No DoS, no resource exhaustion, no data destruction. Every
   program forbids it, it is never a payable finding, and it is the fastest known
   route from researcher to defendant.
4. **Real user data.** Synthetic accounts only. Never pull, store, or enumerate
   real user records to prove a bug — demonstrate access on our own test objects
   and stop. Mutations keep §2 rollback discipline even here.

### Invocation and record

```powershell
npm.cmd run audit:bounty -- hunt <bundle> --intensity ham --confirm-authorization-current
```

The bundle records the intensity, the permissions that authorized it, the
operator, and the timestamp. A HAM run is auditable after the fact — which is the
point, since it is the run most likely to need explaining.
