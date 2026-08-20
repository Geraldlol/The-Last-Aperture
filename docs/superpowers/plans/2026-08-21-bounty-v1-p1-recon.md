# bounty-v1 P1 — Recon Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Discover the attack surface inside a sealed program perimeter and persist it as an inventory, so later phases have parameters and endpoints to work with — without any candidate ever reaching the network before the Scope Kernel approves it.

**Architecture:** Candidates flow through a hard chokepoint. Discovery sources emit raw names; the gate runs each through `decideScope` and emits a *branded* approval object; probes accept nothing else. The sealed `rate_limit_rps` is enforced in the probe path by a token bucket, because a program's stated limit *is* the authorization. Any source that fails is recorded as a coverage gap rather than dropped, so an inventory can never read as complete when it is not.

**Tech Stack:** Node 24 ESM, `node:tls`, `node:crypto`, `fetch`, `node:test`. No new dependencies. No Go toolchain — external binaries are optional accelerants, never required.

**Spec:** `docs/superpowers/specs/2026-08-20-bounty-v1-design.md` §11

**Note on this plan's form:** interfaces, semantics, and gates are specified fully below; test bodies are written at implementation time rather than pre-transcribed, because the same session executes it. The exit gate is the contract.

## Global Constraints

- **Zero new dependencies.** `acorn`, `ajv`, `yaml` remain the complete set.
- Node 24 ESM `.mjs`, `node:` prefixes, no semicolons, 2-space indent, single quotes.
- Layout: `scripts/lib/bounty-recon-*.mjs`, tests `test/bounty-recon-*.test.mjs`, schema `schemas/bounty-surface-inventory.schema.json`.
- **Purity boundary:** `bounty-recon-candidate.mjs`, `bounty-recon-gate.mjs`, and `bounty-recon-ratelimit.mjs` must not import `node:fs`, `node:tls`, `node:http(s)`, `node:dns`, or read the ambient clock. Clocks and fetch are injected.
- **No probe without approval.** Every network-touching function accepts only a branded approval from the gate. There is no parameter that lets a caller pass a raw hostname to a probe.
- **The rate limit is the authorization.** Enforced, never advisory. Exceeding a program's stated limit is out of scope by definition.
- **Failure is a gap.** A source that errors, times out, or returns nothing usable is recorded in `gaps[]` with a reason. Absence of a finding is never presented as absence of surface.
- **Never claim completeness.** The inventory reports `PARTIAL` unless every activated source succeeded, and there is no code path that emits a "complete" verdict.

## Verified source facts

Probed 2026-08-21.

| Source | Result |
|---|---|
| **TLS certificate SANs** via `node:tls` | Works, zero dependencies, no third party. `www.wikipedia.org` yielded 41 DNS SANs (26 wildcards); `github.com` yielded 2. Fields available: `subject.CN`, `issuer.O`, `valid_to`, `subjectaltname`, `fingerprint256`. |
| **crt.sh CT log JSON** | **HTTP 502 on three consecutive attempts.** The service is unreliable, so it is built as a degradable source whose failure records a gap. Never load-bearing. |

A wildcard SAN (`*.m.wikipedia.org`) proves a zone exists but names no host. Wildcards are recorded as **zone hints**, a distinct kind, and are never probed directly.

---

## File Structure

| File | Responsibility |
|---|---|
| `scripts/lib/bounty-recon-ratelimit.mjs` | Token bucket over the sealed rate limit. Injected clock. Pure. |
| `scripts/lib/bounty-recon-candidate.mjs` | Normalize, classify (`host` / `zone_hint`), and dedupe candidates. Pure. |
| `scripts/lib/bounty-recon-gate.mjs` | The chokepoint. Runs `decideScope`, emits branded approvals, records refusals. Pure. |
| `scripts/lib/bounty-recon-tls.mjs` | TLS SAN harvest. Network, approval-gated. |
| `scripts/lib/bounty-recon-ctlog.mjs` | crt.sh source with failure→gap semantics. Network. |
| `scripts/lib/bounty-recon-probe.mjs` | HTTP liveness probe. Network, approval-gated, rate-limited. |
| `scripts/lib/bounty-recon-inventory.mjs` | Inventory shape, merge, dedupe, gap recording, `PARTIAL` status. |
| `scripts/lib/bounty-recon-controller.mjs` | Bundle persistence and the `recon` commands. |
| `schemas/bounty-surface-inventory.schema.json` | Persisted inventory. |

---

### Task 1: Rate limiter

**Files:** create `scripts/lib/bounty-recon-ratelimit.mjs`, test `test/bounty-recon-ratelimit.test.mjs`

**Interfaces:**
- `createRateLimiter({ ratePerSecond, now, sleep }) -> limiter`
- `limiter.acquire() -> Promise<void>` — resolves when a token is available
- `limiter.stats() -> { issued, waitedMs }`
- `now` returns milliseconds; `sleep(ms)` is injected. Neither is read from the ambient environment, so tests are deterministic and instant.

**Semantics:** a token bucket of capacity 1 refilling at `ratePerSecond`. `ratePerSecond` must be a positive integer; anything else throws. There is no bypass parameter and no burst allowance beyond the single token, because the sealed limit is the authorization rather than a performance knob.

- [ ] **Step 1:** Write failing tests — issuing N tokens at rate R waits at least (N-1)/R seconds of injected time; a non-positive or non-integer rate throws; `stats()` reports issued count and accumulated wait.
- [ ] **Step 2:** Run to confirm module-not-found failure.
- [ ] **Step 3:** Implement the bucket with injected `now`/`sleep`.
- [ ] **Step 4:** Run to green.
- [ ] **Step 5:** Purity grep — no fs, net, or ambient clock.
- [ ] **Step 6:** Commit.

---

### Task 2: Candidate normalization and classification

**Files:** create `scripts/lib/bounty-recon-candidate.mjs`, test `test/bounty-recon-candidate.test.mjs`

**Interfaces:**
- `classifyCandidate(raw) -> { kind: 'host' | 'zone_hint', value } | null`
- `normalizeCandidateName(raw) -> string | null` — lowercase, strip trailing dot, strip a `DNS:` prefix, reject empty/whitespace/scheme-bearing input
- `dedupeCandidates(candidates) -> candidates` — stable order, first occurrence wins
- `expandZoneHint(hint) -> string` — returns the apex the wildcard covers, for recording only

**Semantics:** `*.example.com` classifies as `zone_hint` with value `example.com`; a wildcard is never a probe target. Bare names classify as `host`. Anything carrying a scheme, path, port, or whitespace is rejected — sources emit names, and a source emitting a URL is a source bug worth surfacing rather than silently coercing.

- [ ] **Step 1:** Write failing tests, including the wildcard/zone-hint split, `DNS:` prefix stripping, trailing dots, case folding, dedupe stability, and rejection of `http://x`, `x/y`, `x:443`, and whitespace.
- [ ] **Step 2:** Confirm failure. **Step 3:** Implement. **Step 4:** Green. **Step 5:** Purity grep. **Step 6:** Commit.

---

### Task 3: The scope gate — the chokepoint

**Files:** create `scripts/lib/bounty-recon-gate.mjs`, test `test/bounty-recon-gate.test.mjs`

**Interfaces:**
- `gateCandidates({ sealedScope, candidates, port }) -> { approved: Approval[], refused: Refusal[] }`
- `Approval = { __scopeApproved: true, host, port, url, ruleId }`
- `Refusal = { host, reason, ruleId }`
- `assertApproved(value) -> void` — throws unless `__scopeApproved === true`

**Semantics:** every candidate is converted to a concrete `https://host/` URL and run through `decideScope`. Only ALLOW yields an approval. Zone hints are refused with reason `zone-hint-not-probeable`. The brand exists so a probe can refuse anything that did not come through here — the same fail-closed reasoning as the kernel, one layer up.

- [ ] **Step 1:** Write failing tests — in-scope host approved with its rule id; out-of-scope refused; zone hint refused; a hand-forged object without the brand rejected by `assertApproved`; refusals carry the kernel's reason verbatim.
- [ ] **Step 2:** Confirm failure. **Step 3:** Implement over `decideScope`. **Step 4:** Green. **Step 5:** Purity grep. **Step 6:** Commit.

---

### Task 4: Inventory with gap recording

**Files:** create `schemas/bounty-surface-inventory.schema.json`, `scripts/lib/bounty-recon-inventory.mjs`, test `test/bounty-recon-inventory.test.mjs`

**Interfaces:**
- `createInventory({ engagementId, createdAt }) -> inventory`
- `recordHost(inventory, { host, port, source, observedAt, probe }) -> inventory`
- `recordZoneHint(inventory, { zone, source }) -> inventory`
- `recordRefusal(inventory, refusal) -> inventory`
- `recordGap(inventory, { source, reason, detail }) -> inventory`
- `inventorySummary(inventory) -> { hosts, zoneHints, refused, gaps, status }`
- `assertValidInventory(value) -> void`

**Semantics:** `status` is `PARTIAL` whenever `gaps.length > 0`, otherwise `OBSERVED`. There is no `COMPLETE`. Hosts dedupe on `host:port`, keeping the richest probe record. Refusals are retained rather than discarded — a refused candidate is evidence about the perimeter's shape.

- [ ] **Step 1:** Write failing tests including dedupe-on-merge, gap forcing `PARTIAL`, refusals retained, and schema rejection of a `COMPLETE` status.
- [ ] **Step 2:** Confirm failure. **Step 3:** Implement plus schema. **Step 4:** Green. **Step 5:** Commit.

---

### Task 5: TLS SAN source

**Files:** create `scripts/lib/bounty-recon-tls.mjs`, test `test/bounty-recon-tls.test.mjs`

**Interfaces:**
- `harvestTlsSans({ approval, timeoutMs, connectImpl }) -> Promise<{ names, certificate }>`
- `parseSubjectAltName(subjectaltname) -> { dns: string[], ip: string[] }`
- `certificateFacts(cert) -> { commonName, issuer, validTo, fingerprint256 }`

**Semantics:** takes an approval, never a hostname. `connectImpl` is injected so parsing and error paths are tested without a socket. A connect failure returns a gap-shaped error rather than throwing through the pipeline. `parseSubjectAltName` and `certificateFacts` are pure and carry the bulk of the tests.

- [ ] **Step 1:** Write failing tests — parse the real `www.wikipedia.org` SAN string (41 DNS entries, 26 wildcards) from a recorded fixture; parse `IP Address:` entries; `certificateFacts` extraction; `assertApproved` rejection of an unbranded input; injected connect failure yields a gap reason.
- [ ] **Step 2:** Confirm failure. **Step 3:** Implement. **Step 4:** Green. **Step 5:** Commit.

---

### Task 6: HTTP liveness probe

**Files:** create `scripts/lib/bounty-recon-probe.mjs`, test `test/bounty-recon-probe.test.mjs`

**Interfaces:**
- `probeHost({ approval, limiter, fetchImpl, timeoutMs }) -> Promise<probe>`
- `probe = { url, status, server, title, contentType, contentLength, location, techHints[], error }`
- `extractTitle(html) -> string | null`
- `deriveTechHints(headers) -> string[]`

**Semantics:** calls `limiter.acquire()` before every request, with no code path that skips it. Follows no redirects — `location` is recorded and the redirect target becomes a *new candidate* that must pass the gate on its own, which is precisely how open-redirect chains escape a scope if followed blindly. `extractTitle` caps its scan length so a hostile multi-megabyte response cannot stall the pipeline.

- [ ] **Step 1:** Write failing tests — `assertApproved` refusal of unbranded input; limiter called exactly once per probe; redirects recorded not followed; title extraction with a length cap and with no title present; tech hints from `server`/`x-powered-by`; a fetch rejection recorded as `error` rather than thrown.
- [ ] **Step 2:** Confirm failure. **Step 3:** Implement. **Step 4:** Green. **Step 5:** Commit.

---

### Task 7: crt.sh source, degradable

**Files:** create `scripts/lib/bounty-recon-ctlog.mjs`, test `test/bounty-recon-ctlog.test.mjs`

**Interfaces:**
- `fetchCtLogNames({ apex, fetchImpl, timeoutMs, attempts }) -> Promise<{ names, gap }>`
- `parseCtLogRows(rows) -> string[]`

**Semantics:** returns `{ names, gap: null }` on success and `{ names: [], gap: { source: 'crt.sh', reason, detail } }` on any failure, retrying up to `attempts`. It never throws into the pipeline. `name_value` is newline-separated and may contain wildcards, so parsing splits and hands everything to `classifyCandidate`. Verified 2026-08-21: this service returns 502 often enough that the degradation path is the common path, not the edge case.

- [ ] **Step 1:** Write failing tests — multi-name `name_value` splitting; 502 producing a gap after N attempts; a timeout producing a gap; malformed JSON producing a gap; success returning names.
- [ ] **Step 2:** Confirm failure. **Step 3:** Implement. **Step 4:** Green. **Step 5:** Commit.

---

### Task 8: Controller and CLI

**Files:** create `scripts/lib/bounty-recon-controller.mjs`, modify `scripts/bounty.mjs`, test `test/bounty-recon-controller.test.mjs`

**Interfaces:**
- `runRecon({ bundlePath, sources, seeds, now, fetchImpl, connectImpl }) -> Promise<summary>`
- `reconStatus({ bundlePath }) -> Promise<summary>`
- Persists `surface-inventory.json` beside the sealed scope.

CLI:
```
bounty recon run <bundle> --seed <host> [--seed <host>...] [--sources tls,ctlog] [--json]
bounty recon status <bundle> [--json]
```

**Semantics:** loads the sealed scope from the bundle and gates every candidate against it — the recon command cannot be pointed at a host the perimeter does not already permit. Reads `rate_limit_rps` from the sealed scope to build the limiter. Prints the `PARTIAL` status and the gap list prominently, because a quiet gap is how an incomplete sweep gets mistaken for a clean one.

- [ ] **Step 1:** Write failing tests — an out-of-scope seed is refused and never probed; the limiter is constructed from the sealed rate limit; a failing source yields `PARTIAL` with the gap recorded; inventory persists and reloads; `recon status` reports without re-probing.
- [ ] **Step 2:** Confirm failure. **Step 3:** Implement plus CLI wiring. **Step 4:** Green. **Step 5:** Wire test files into `test:platform`. **Step 6:** Commit.

---

### Task 9: Live verification

- [ ] Seal a scope for a host we are permitted to touch, run recon, and confirm real SANs land in the inventory.
- [ ] Confirm an out-of-scope seed is refused with the kernel's reason and never probed.
- [ ] Confirm the rate limiter measurably paces real requests.
- [ ] Confirm a dead crt.sh produces `PARTIAL` with a recorded gap rather than a crash or a silent pass.
- [ ] Record results in the exit gate.

---

## P1 Exit Gate

- [ ] `npm.cmd test` shows no new failures beyond the two known pre-existing ones
- [ ] Purity grep clean for ratelimit, candidate, and gate modules
- [ ] No new entry in `package.json` `dependencies`
- [ ] **No probe function accepts an unbranded input** — every one calls `assertApproved`
- [ ] An out-of-scope seed is refused before any socket opens, with the kernel's reason recorded
- [ ] The sealed `rate_limit_rps` measurably paces live requests
- [ ] A failed source produces `PARTIAL` plus a recorded gap; no path emits `COMPLETE`
- [ ] Redirects are recorded and never followed
- [ ] Wildcard SANs are recorded as zone hints and never probed
- [ ] Live run against a permitted host yields real SANs in the inventory

## Deferred

- Go-binary ingestion (`subfinder`, `httpx`, `nuclei` JSON) behind the same source interface. Optional accelerants; the pipeline must never require them.
- Port scanning. Out of scope for a bounty program in most policies and rarely payable.
- Content discovery and parameter mining — those belong with the P4 scanner and the P2 proxy's observed traffic, not with surface discovery.
