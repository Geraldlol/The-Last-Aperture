# bounty-v1 P3 — Authorization Grinder Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replay captured requests across every role and detect broken authorization, at a signal quality good enough to submit — which means the grinder must know when it *cannot* trust its own comparison and say so.

**Architecture:** Every captured request has an owning role. The grinder first replays it as that owner **twice** to establish a noise floor; differences between two identical-role runs are volatile by definition. It then replays as every other role plus unauthenticated, normalizes each response, and compares against the owner's. Equivalence beyond the noise floor is an authorization-bypass candidate. If the baseline itself was unstable, the comparison is reported as unproven rather than guessed at.

**Tech Stack:** Node 24 ESM, `node:crypto`, `node:http` (synthetic testbed), `fetch`, `node:test`. No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-20-bounty-v1-design.md` §9

**Note on this plan's form:** interfaces, semantics, and gates are specified fully; test bodies are written at implementation time since the same session executes it. The exit gate is the contract.

## Global Constraints

- **Zero new dependencies.** `acorn`, `ajv`, `yaml` remain the complete set.
- Node 24 ESM `.mjs`, `node:` prefixes, no semicolons, 2-space indent, single quotes.
- Layout: `scripts/lib/bounty-authz-*.mjs`, tests `test/bounty-authz-*.test.mjs`, schemas `schemas/bounty-authz-*.schema.json`.
- **Purity boundary:** `bounty-authz-request.mjs`, `bounty-authz-normalize.mjs`, and `bounty-authz-classify.mjs` must not import `node:fs`, `node:http(s)`, or read the ambient clock.
- **Reuse the P1 chokepoint.** Every replay target passes `gateCandidates`/`assertApproved` from `bounty-recon-gate.mjs` and is paced by `createRateLimiter` from the sealed `rate_limit_rps`. The grinder introduces no new egress path.
- **Never say VULNERABLE.** The strongest verdict is `AUTHZ_BYPASS_CANDIDATE`. A candidate needs human proof before submission, and no string in this module may read as a confirmed finding.
- **Never say NOT VULNERABLE.** A denied or differing response is evidence about one request under one role, never a clearance for the endpoint.
- **Credentials are never written to the bundle.** The role registry stores credentials by reference; captured artifacts are redacted before persistence.

## The signal-quality problem

A naive grinder fails in one of two directions:

| Failure | Cause | Consequence |
|---|---|---|
| Finds nothing | Byte comparison; every response differs on timestamps, CSRF tokens, request ids | Silent uselessness |
| Finds everything | Over-aggressive stripping collapses genuinely different responses | Duplicate/N-A flood, reputation burned |

**Self-baseline calibration** is the way out. For request R owned by role A:

1. Replay R as A. Call it `A1`.
2. Replay R as A again. Call it `A2`.
3. `normalize(A1) == normalize(A2)` → the endpoint is **stable** under normalization, so any cross-role equivalence is meaningful.
4. `normalize(A1) != normalize(A2)` → the endpoint is **volatile**; equality comparison cannot support a claim, and every cross-role result for it is reported `UNPROVEN_VOLATILE`.

Step 4 is the honest half and the reason this design is worth the extra requests: it converts "we don't know" from a silent false negative into a recorded nonclaim.

## Classification

For request R owned by A, replayed as tester B:

| Verdict | Condition | Meaning |
|---|---|---|
| `AUTHZ_BYPASS_CANDIDATE` | baseline stable **and** `normalize(B) == normalize(A1)` | B received content specific to A |
| `UNPROVEN_VOLATILE` | baseline unstable and B matched | Cannot support a claim either way |
| `ACCESS_DENIED` | B status 401 or 403 | Correct-looking behavior for this one request |
| `NOT_FOUND` | B status 404 | Ambiguous: proper scoping, or an existence oracle |
| `DIFFERENT_CONTENT` | B 2xx, not equivalent | Usually correct per-role scoping — B seeing B's own data is not a bug |
| `SERVER_ERROR` | B status 5xx | An unexpected role crashing a handler is worth reading |
| `REPLAY_FAILED` | transport error | Recorded, never silently dropped |

`DIFFERENT_CONTENT` deliberately is not a finding. On `/api/me`, role B correctly receives B's own profile with a 200; treating "different but successful" as a leak is the single most common source of authz-grinder noise.

---

## File Structure

| File | Responsibility |
|---|---|
| `scripts/lib/bounty-authz-request.mjs` | Captured-request shape, HAR import, credential redaction. Pure. |
| `scripts/lib/bounty-authz-normalize.mjs` | Response normalization and canonical digest. Pure. |
| `scripts/lib/bounty-authz-classify.mjs` | Baseline calibration and verdict assignment. Pure. |
| `scripts/lib/bounty-authz-roles.mjs` | Role registry: credential application, role listing. |
| `scripts/lib/bounty-authz-replay.mjs` | Gated, paced replay of one request as one role. Network. |
| `scripts/lib/bounty-authz-controller.mjs` | The matrix run, persistence, and CLI commands. |
| `schemas/bounty-authz-roles.schema.json` | Role registry. |
| `schemas/bounty-authz-findings.schema.json` | Matrix results. |
| `test/fixtures/authz-testbed.mjs` | Synthetic three-role app with **deliberate, known** authz bugs. |

---

### Task 1: Captured requests and HAR import

**Files:** create `scripts/lib/bounty-authz-request.mjs`, test `test/bounty-authz-request.test.mjs`

**Interfaces:**
- `CAPTURED_REQUEST_KIND = 'red-team-audit/bounty-authz-request'`
- `normalizeCapturedRequest(raw) -> request` — throws on a missing method or url
- `importHarEntries(har, { ownerRole }) -> { requests, skipped }` — skips non-http schemes and records why
- `redactRequest(request) -> request` — strips `authorization`, `cookie`, `x-api-key`, `x-auth-token`, `set-cookie` and any header named in `extraSensitive`
- `requestSignature(request) -> string` — stable id from method + url + sorted body keys, for dedupe

**Semantics:** HAR is the ingestion path that makes P3 usable before the P2 proxy exists — Chrome DevTools exports it directly. Imported requests carry an owner role supplied by the operator, because a HAR cannot know whose session it captured. Redaction happens before anything is persisted, so a bundle never contains a live credential.

- [ ] **Step 1:** Failing tests — HAR entry with headers array and `postData.text` imported; non-http entry skipped with a reason; redaction removes every sensitive header while keeping the rest; signature stable across header reordering and differing on method or path.
- [ ] **Step 2:** Confirm failure. **Step 3:** Implement. **Step 4:** Green. **Step 5:** Purity grep. **Step 6:** Commit.

---

### Task 2: Response normalization

**Files:** create `scripts/lib/bounty-authz-normalize.mjs`, test `test/bounty-authz-normalize.test.mjs`

**Interfaces:**
- `VOLATILE_HEADERS` — the dropped set
- `normalizeResponseBody(body, contentType) -> string`
- `normalizeResponse({ status, headers, body, contentType }) -> { status, headerDigest, bodyDigest, normalizedBody }`
- `responseDigest(normalized) -> string` — sha256 over status + bodyDigest

**Semantics.** Dropped headers: `date`, `set-cookie`, `etag`, `last-modified`, `age`, `expires`, `x-request-id`, `x-trace-id`, `x-correlation-id`, `x-runtime`, `x-served-by`, `cf-ray`, `server-timing`, `content-length`, `keep-alive`, `connection`.

Body placeholder substitutions, applied in this order: UUIDs → `<uuid>`; ISO-8601 timestamps → `<ts>`; 10–13 digit epochs → `<epoch>`; hex runs of 16+ → `<hex>`; JSON values under volatile-looking keys (`csrf`, `token`, `nonce`, `_token`, `requestId`, `traceId`, `timestamp`) → `<redacted>`; then whitespace collapsed.

JSON bodies are parsed and re-serialized with sorted keys so key order cannot masquerade as a difference. A body that fails to parse falls back to text normalization.

**The deliberate limit:** normalization cannot strip a rendered username or account number, so two roles seeing genuinely different data still differ — which is correct. It only removes machine noise.

- [ ] **Step 1:** Failing tests — each substitution class; JSON key-order insensitivity; volatile headers dropped and stable ones kept; two responses differing only in a UUID normalize identical; two responses differing in an account number stay different; malformed JSON falls back without throwing.
- [ ] **Step 2:** Confirm failure. **Step 3:** Implement. **Step 4:** Green. **Step 5:** Purity grep. **Step 6:** Commit.

---

### Task 3: Baseline calibration and classification

**Files:** create `scripts/lib/bounty-authz-classify.mjs`, test `test/bounty-authz-classify.test.mjs`

**Interfaces:**
- `calibrateBaseline({ first, second }) -> { stable, digest, reason }`
- `classifyAuthzOutcome({ baseline, ownerResponse, testerResponse, testerRole }) -> { verdict, confidence, rationale }`
- `summarizeMatrix(results) -> { total, byVerdict, candidates, unproven }`
- `AUTHZ_VERDICTS` — the frozen verdict list

**Semantics:** `confidence` is `high` only when the baseline is stable and the digests match exactly; `low` whenever the baseline is unstable. `rationale` is a human sentence naming the comparison that produced the verdict, because a finding without a stated basis is unsubmittable.

- [ ] **Step 1:** Failing tests — stable baseline plus matching tester yields `AUTHZ_BYPASS_CANDIDATE` at high confidence; unstable baseline plus matching tester yields `UNPROVEN_VOLATILE` at low confidence; 401/403 yields `ACCESS_DENIED`; 404 yields `NOT_FOUND`; 2xx non-matching yields `DIFFERENT_CONTENT`; 5xx yields `SERVER_ERROR`; transport error yields `REPLAY_FAILED`; no verdict string contains "VULNERABLE" or "SECURE".
- [ ] **Step 2:** Confirm failure. **Step 3:** Implement. **Step 4:** Green. **Step 5:** Purity grep. **Step 6:** Commit.

---

### Task 4: Role registry

**Files:** create `schemas/bounty-authz-roles.schema.json`, `scripts/lib/bounty-authz-roles.mjs`, test `test/bounty-authz-roles.test.mjs`

**Interfaces:**
- `loadRoleRegistry(path) -> Promise<registry>`
- `assertValidRoleRegistry(value) -> void`
- `applyRole(request, role) -> request` — returns a request with the role's auth applied
- `ANONYMOUS_ROLE` — the always-present unauthenticated role
- `rolesToTest(registry, ownerRoleId) -> role[]` — every role except the owner, plus anonymous

**Semantics:** a role carries an `id`, a `label`, and an `auth` block of `{ kind: 'header' | 'cookie' | 'none', name, value_env }`. **Credential values are read from environment variables named by `value_env`, never stored in the registry file**, so a registry can be committed and a bundle can be shared without leaking a session. A missing environment variable is a hard error at load, not a silent unauthenticated replay — silently dropping auth would make every result a false `ACCESS_DENIED`.

- [ ] **Step 1:** Failing tests — schema accepts a valid registry and rejects an inline credential value; `applyRole` sets a header or cookie; anonymous strips auth entirely; a missing env var throws naming the variable; `rolesToTest` excludes the owner and includes anonymous.
- [ ] **Step 2:** Confirm failure. **Step 3:** Implement plus schema. **Step 4:** Green. **Step 5:** Commit.

---

### Task 5: Gated, paced replay

**Files:** create `scripts/lib/bounty-authz-replay.mjs`, test `test/bounty-authz-replay.test.mjs`

**Interfaces:**
- `replayAsRole({ request, role, sealedScope, limiter, fetchImpl, timeoutMs }) -> Promise<response>`

**Semantics:** derives the target host from the request url and runs it through `gateCandidates`; a request whose host is out of scope is refused before any socket opens, exactly as in P1. Calls `limiter.acquire()` unconditionally. Sends no redirect following. Captures status, headers, and a length-capped body.

- [ ] **Step 1:** Failing tests — out-of-scope request refused with the kernel reason and no fetch; limiter called once per replay; role auth applied to the outgoing headers; redirect not followed; transport error returned as a `REPLAY_FAILED`-shaped result rather than thrown; body cap enforced.
- [ ] **Step 2:** Confirm failure. **Step 3:** Implement. **Step 4:** Green. **Step 5:** Commit.

---

### Task 6: The synthetic testbed

**Files:** create `test/fixtures/authz-testbed.mjs`

A three-role app on loopback with **known** answers, so the grinder is measured against ground truth rather than against its own assumptions:

| Endpoint | Intended behavior | Planted bug |
|---|---|---|
| `GET /api/me` | returns the caller's own profile | none — must classify `DIFFERENT_CONTENT` |
| `GET /api/orders/1` | order 1 belongs to alice | **none** — bob gets 403 |
| `GET /api/orders/2` | order 2 belongs to alice | **BROKEN**: any authenticated role sees it |
| `GET /api/admin/users` | admin only | **BROKEN**: no check at all, anonymous included |
| `GET /api/volatile` | returns a fresh uuid and timestamp every call | none — must classify `UNPROVEN_VOLATILE` |
| `GET /api/health` | public | none |

The `/api/volatile` endpoint exists specifically to prove the calibration path fires. Any grinder that reports a bypass there is over-stripping.

- [ ] **Step 1:** Implement the testbed with an ephemeral port and a `close()`. **Step 2:** Commit.

---

### Task 7: Matrix controller, CLI, and live proof

**Files:** create `schemas/bounty-authz-findings.schema.json`, `scripts/lib/bounty-authz-controller.mjs`, modify `scripts/bounty.mjs`, test `test/bounty-authz-controller.test.mjs`

**Interfaces:**
- `runAuthzMatrix({ bundlePath, requests, registry, now, fetchImpl }) -> Promise<summary>`
- `authzStatus({ bundlePath }) -> Promise<summary>`
- `importAuthzRequests({ bundlePath, harPath, ownerRole }) -> Promise<{ imported, skipped }>`

CLI:
```
bounty authz import <bundle> --har <file> --owner-role <id> [--json]
bounty authz run <bundle> --roles <registry.json> [--json]
bounty authz status <bundle> [--json]
```

**Semantics:** for each request, two owner replays then one replay per other role. Persists `authz-findings.json` with every verdict retained — `ACCESS_DENIED` results are kept, because the shape of what was denied is what makes a bypass elsewhere credible. Prints candidates and unproven counts separately so a volatile endpoint can never inflate the candidate number.

- [ ] **Step 1:** Failing tests against the testbed — `/api/orders/2` yields `AUTHZ_BYPASS_CANDIDATE`; `/api/orders/1` yields `ACCESS_DENIED`; `/api/admin/users` yields a candidate for anonymous; `/api/me` yields `DIFFERENT_CONTENT` and **not** a candidate; `/api/volatile` yields `UNPROVEN_VOLATILE`; request count equals `requests × (2 + otherRoles)`.
- [ ] **Step 2:** Confirm failure. **Step 3:** Implement plus CLI. **Step 4:** Green. **Step 5:** Wire tests into `test:platform`. **Step 6:** Commit.

---

## P3 Exit Gate

- [ ] `npm test` shows no new failures beyond the two known pre-existing ones
- [ ] Purity grep clean for request, normalize, and classify modules
- [ ] No new entry in `package.json` `dependencies`
- [ ] **Against the testbed with known answers:** the two planted bugs are found, and the three clean endpoints produce no candidate
- [ ] `/api/volatile` classifies `UNPROVEN_VOLATILE`, proving calibration fires rather than over-stripping
- [ ] `/api/me` classifies `DIFFERENT_CONTENT` and is not counted as a candidate
- [ ] An out-of-scope request is refused before any socket opens
- [ ] No credential value appears anywhere in the persisted bundle
- [ ] No verdict string reads as a confirmed or cleared finding
- [ ] Replay pacing honours the sealed `rate_limit_rps`

## Deferred

- **Identifier mutation (horizontal IDOR).** Substituting role A's known object ids into role B's requests. Higher yield than role replay alone but needs a declared map of role-owned identifiers; it belongs in a follow-on once the matrix is proven.
- Stateful multi-step flows, where authorization depends on prior requests in a sequence.
- Automatic session refresh on expiry — for now an expired credential surfaces as `ACCESS_DENIED` across the board, which the operator must notice. Worth a heuristic warning when *every* result for a role is denied.
