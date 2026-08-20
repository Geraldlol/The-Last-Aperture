# bounty-v1 P0 — Scope Kernel and Program Sealing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the fail-closed Scope Kernel and program-policy sealing for `bounty-v1`, so that no later phase can send a request outside a sealed bounty program scope.

**Architecture:** A pure decision function (`decideScope`) sits in front of every future egress path. It takes a sealed scope object and a candidate URL string and returns `ALLOW` or `DENY` with a rule id. It performs no DNS, no network, no clock, and no filesystem access, which makes it exhaustively testable offline. Program authorization is sealed once per program by digesting the policy snapshot into a `PROGRAM_POLICY_SEALED` scope, validated against a new JSON schema. A controller CLI exposes plan/validate/revalidate/scope commands.

**Tech Stack:** Node 24 ESM (`.mjs`), `node:test`, `node:assert/strict`, `node:crypto`, `node:net`, Ajv 2020 (`ajv/dist/2020.js`). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-08-20-bounty-v1-design.md`

## Global Constraints

- **Zero new dependencies.** The repo has exactly three: `acorn`, `ajv`, `yaml`. Do not add a fourth.
- **Node 24.13.0**, ESM only, `.mjs` extension, `node:` prefix on all builtins.
- **Code style, copied from `scripts/lib/http-recon-contracts.mjs`:** no semicolons, 2-space indent, single quotes, named exports, `camelCase` functions prefixed with the protocol (`decideScope`, `createProgramSealedScope`).
- **Module layout:** logic in `scripts/lib/bounty-*.mjs`, CLI entry at `scripts/bounty.mjs`, tests at `test/bounty-*.test.mjs`, schemas at `schemas/bounty-*.schema.json`. This mirrors `http-recon-*` and `http-authed-*` exactly.
- **No network in P0.** Not in code, not in tests. No `fetch`, no `node:http`, no `node:https`, no DNS resolution anywhere in this phase.
- **The kernel is pure.** `scripts/lib/bounty-scope-kernel.mjs` and `scripts/lib/bounty-target.mjs` must not import `node:fs`, `node:http`, `node:https`, `node:dns`, or read `Date.now()`. Only `node:net` (for `isIP`) is permitted.
- **Fail closed.** Every unhandled condition, thrown error, malformed input, and unmatched candidate resolves to `DENY`. There is no code path that returns `ALLOW` by default.
- **`phi` is always `false`.** Program sealing forces it and refuses any input that sets it true.
- **Reuse, do not reimplement:** `canonicalJson` and `sha256Hex` are already exported from `scripts/lib/http-recon-contracts.mjs`. Import them. `isMainModule` from `scripts/lib/main-module.mjs`. `PLATFORM_VERSION` and `stableJson` from `scripts/lib/run-engine.mjs`.
- **Never claim clearance.** No function in this phase may emit `COMPLETED`, a pass verdict, or an audit result.

---

## File Structure

| File | Responsibility |
|---|---|
| `scripts/lib/bounty-target.mjs` | Parse and canonicalize one candidate URL string; reject confusable forms. No scope knowledge. |
| `scripts/lib/bounty-scope-kernel.mjs` | The decision function. Consumes a canonical target and a sealed scope; emits ALLOW/DENY. No IO. |
| `fixtures/bounty/scope-kernel-cases.json` | The cross-language conformance contract. Node and the future Python addon both run these cases. |
| `schemas/bounty-scope.schema.json` | Sealed scope shape, including the `program` block and `scope_rules`. |
| `scripts/lib/bounty-contracts.mjs` | Ajv validation of the scope schema; digest helpers for policy snapshots. |
| `scripts/lib/bounty-planner.mjs` | Build a `PROGRAM_POLICY_SEALED` scope from operator input plus a policy snapshot file. |
| `scripts/lib/bounty-controller.mjs` | Command implementations: plan, validate, revalidate, scope check. Owns bundle IO. |
| `scripts/bounty.mjs` | CLI entry: argument parsing, help text, exit codes. |

Split rationale: `bounty-target.mjs` is separated from the kernel because URL confusion attacks are their own dense problem space and deserve an isolated fixture suite. The kernel stays small enough to read in one sitting, which matters for a security boundary.

---

### Task 1: Candidate URL canonicalization

**Files:**
- Create: `scripts/lib/bounty-target.mjs`
- Test: `test/bounty-target.test.mjs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `canonicalizeCandidate(rawUrl: string) -> { ok: true, target: CanonicalTarget } | { ok: false, reason: string }`
  - `CanonicalTarget = { scheme: 'http:' | 'https:', host: string, port: number, path: string, hostKind: 'domain' | 'ipv4' | 'ipv6' }`
  - `MAX_CANDIDATE_LENGTH: number`
  - `host` is lowercase, punycode-encoded, with no trailing dot and no brackets on IPv6.

- [ ] **Step 1: Write the failing test**

Create `test/bounty-target.test.mjs`:

```js
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { canonicalizeCandidate } from '../scripts/lib/bounty-target.mjs'

test('canonicalizes a plain https url with default port', () => {
  const result = canonicalizeCandidate('https://api.example.com/v1/users')
  assert.equal(result.ok, true)
  assert.deepEqual(result.target, {
    scheme: 'https:',
    host: 'api.example.com',
    port: 443,
    path: '/v1/users',
    hostKind: 'domain',
  })
})

test('rejects a candidate carrying userinfo', () => {
  const result = canonicalizeCandidate('https://allowed.example.com@evil.example/')
  assert.equal(result.ok, false)
  assert.equal(result.reason, 'candidate-carries-userinfo')
})

test('lowercases the host and strips a single trailing dot', () => {
  const result = canonicalizeCandidate('https://API.Example.COM./x')
  assert.equal(result.ok, true)
  assert.equal(result.target.host, 'api.example.com')
})

test('records an explicit non-default port', () => {
  const result = canonicalizeCandidate('https://api.example.com:8443/')
  assert.equal(result.ok, true)
  assert.equal(result.target.port, 8443)
})

test('classifies ipv4 and ipv6 hosts and unwraps ipv6 brackets', () => {
  const four = canonicalizeCandidate('http://203.0.113.7/')
  assert.equal(four.target.hostKind, 'ipv4')
  assert.equal(four.target.host, '203.0.113.7')
  const six = canonicalizeCandidate('http://[2001:db8::1]/')
  assert.equal(six.target.hostKind, 'ipv6')
  assert.equal(six.target.host, '2001:db8::1')
})

test('normalizes dot segments in the path', () => {
  const result = canonicalizeCandidate('https://api.example.com/a/b/../../etc/passwd')
  assert.equal(result.target.path, '/etc/passwd')
})

test('rejects non-http schemes', () => {
  assert.equal(canonicalizeCandidate('file:///etc/passwd').reason, 'scheme-not-http')
  assert.equal(canonicalizeCandidate('gopher://example.com/').reason, 'scheme-not-http')
})

test('rejects unparsable and non-string candidates', () => {
  assert.equal(canonicalizeCandidate('not a url').reason, 'candidate-unparsable')
  assert.equal(canonicalizeCandidate('').reason, 'candidate-not-a-string')
  assert.equal(canonicalizeCandidate(null).reason, 'candidate-not-a-string')
})

test('encodes internationalized hosts to punycode', () => {
  const result = canonicalizeCandidate('https://exämple.com/')
  assert.equal(result.ok, true)
  assert.equal(result.target.host, 'xn--exmple-cua.com')
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/bounty-target.test.mjs`
Expected: FAIL — `Cannot find module '../scripts/lib/bounty-target.mjs'`

- [ ] **Step 3: Write minimal implementation**

Create `scripts/lib/bounty-target.mjs`:

```js
import { isIP } from 'node:net'

export const MAX_CANDIDATE_LENGTH = 4096

const ALLOWED_SCHEMES = new Set(['http:', 'https:'])
const DEFAULT_PORTS = new Map([
  ['http:', 80],
  ['https:', 443],
])

function refuse(reason) {
  return { ok: false, reason }
}

function normalizeHost(hostname) {
  let host = hostname.toLowerCase()
  if (host.startsWith('[') && host.endsWith(']')) {
    host = host.slice(1, -1)
  }
  if (host.endsWith('.')) {
    host = host.slice(0, -1)
    if (host.endsWith('.')) return null
  }
  if (host.length === 0) return null
  return host
}

export function canonicalizeCandidate(rawUrl) {
  try {
    if (typeof rawUrl !== 'string' || rawUrl.length === 0) {
      return refuse('candidate-not-a-string')
    }
    if (rawUrl.length > MAX_CANDIDATE_LENGTH) {
      return refuse('candidate-too-long')
    }
    let parsed
    try {
      parsed = new URL(rawUrl)
    } catch {
      return refuse('candidate-unparsable')
    }
    if (!ALLOWED_SCHEMES.has(parsed.protocol)) {
      return refuse('scheme-not-http')
    }
    if (parsed.username !== '' || parsed.password !== '') {
      return refuse('candidate-carries-userinfo')
    }
    const host = normalizeHost(parsed.hostname)
    if (host === null) {
      return refuse('host-not-canonicalizable')
    }
    const ipVersion = isIP(host)
    const hostKind = ipVersion === 4 ? 'ipv4' : ipVersion === 6 ? 'ipv6' : 'domain'
    const port = parsed.port === ''
      ? DEFAULT_PORTS.get(parsed.protocol)
      : Number.parseInt(parsed.port, 10)
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      return refuse('port-not-valid')
    }
    const path = parsed.pathname === '' ? '/' : parsed.pathname
    return { ok: true, target: { scheme: parsed.protocol, host, port, path, hostKind } }
  } catch {
    return refuse('candidate-canonicalization-failed')
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/bounty-target.test.mjs`
Expected: PASS, 9 tests

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/bounty-target.mjs test/bounty-target.test.mjs
git commit -m "feat(bounty-v1): canonicalize candidate URLs for scope decisions"
```

---

### Task 2: The Scope Kernel decision function

**Files:**
- Create: `scripts/lib/bounty-scope-kernel.mjs`
- Test: `test/bounty-scope-kernel.test.mjs`

**Interfaces:**
- Consumes: `canonicalizeCandidate`, `CanonicalTarget` from Task 1.
- Produces:
  - `decideScope(sealedScope: object, rawCandidate: string) -> { decision: 'ALLOW' | 'DENY', rule_id: string, reason: string }`
  - `SCOPE_ALLOW = 'ALLOW'`, `SCOPE_DENY = 'DENY'`
  - Rule shape consumed: `{ rule_id: string, host_kind: 'exact' | 'wildcard' | 'ip', host: string, ports?: number[], path_prefix?: string }`
  - Sealed scope shape consumed: `{ scope_rules: { allow: Rule[], deny: Rule[], private_targets_sealed?: boolean } }`

- [ ] **Step 1: Write the failing test**

Create `test/bounty-scope-kernel.test.mjs`:

```js
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { decideScope, SCOPE_ALLOW, SCOPE_DENY } from '../scripts/lib/bounty-scope-kernel.mjs'

function scope(overrides = {}) {
  return {
    scope_rules: {
      allow: [
        { rule_id: 'allow-wildcard', host_kind: 'wildcard', host: 'example.com' },
        { rule_id: 'allow-apex', host_kind: 'exact', host: 'example.com' },
      ],
      deny: [
        { rule_id: 'deny-internal', host_kind: 'exact', host: 'internal.example.com' },
      ],
      ...overrides,
    },
  }
}

test('allows a subdomain matched by a wildcard rule', () => {
  const result = decideScope(scope(), 'https://api.example.com/v1')
  assert.equal(result.decision, SCOPE_ALLOW)
  assert.equal(result.rule_id, 'allow-wildcard')
})

test('allows a deeply nested subdomain', () => {
  assert.equal(decideScope(scope(), 'https://a.b.example.com/').decision, SCOPE_ALLOW)
})

test('a wildcard rule alone does not match the apex', () => {
  const apexOnlyWildcard = {
    scope_rules: {
      allow: [{ rule_id: 'allow-wildcard', host_kind: 'wildcard', host: 'example.com' }],
      deny: [],
    },
  }
  const result = decideScope(apexOnlyWildcard, 'https://example.com/')
  assert.equal(result.decision, SCOPE_DENY)
  assert.equal(result.reason, 'candidate-unlisted')
})

test('deny takes precedence over a matching wildcard allow', () => {
  const result = decideScope(scope(), 'https://internal.example.com/')
  assert.equal(result.decision, SCOPE_DENY)
  assert.equal(result.rule_id, 'deny-internal')
  assert.equal(result.reason, 'explicit-deny-rule')
})

test('an unlisted host is denied', () => {
  const result = decideScope(scope(), 'https://notexample.com/')
  assert.equal(result.decision, SCOPE_DENY)
  assert.equal(result.reason, 'candidate-unlisted')
})

test('a suffix-confusable host is denied', () => {
  assert.equal(decideScope(scope(), 'https://evilexample.com/').decision, SCOPE_DENY)
  assert.equal(decideScope(scope(), 'https://example.com.evil.net/').decision, SCOPE_DENY)
})

test('an ip literal never matches a domain rule', () => {
  const result = decideScope(scope(), 'https://203.0.113.7/')
  assert.equal(result.decision, SCOPE_DENY)
})

test('a domain never matches an ip rule', () => {
  const ipScope = {
    scope_rules: {
      allow: [{ rule_id: 'allow-ip', host_kind: 'ip', host: '203.0.113.7' }],
      deny: [],
    },
  }
  assert.equal(decideScope(ipScope, 'https://203.0.113.7/').decision, SCOPE_ALLOW)
  assert.equal(decideScope(ipScope, 'https://example.com/').decision, SCOPE_DENY)
})

test('private and metadata targets are denied even when listed', () => {
  const privateScope = {
    scope_rules: {
      allow: [
        { rule_id: 'allow-meta', host_kind: 'ip', host: '169.254.169.254' },
        { rule_id: 'allow-rfc1918', host_kind: 'ip', host: '10.0.0.5' },
        { rule_id: 'allow-loopback', host_kind: 'ip', host: '127.0.0.1' },
      ],
      deny: [],
    },
  }
  for (const url of ['http://169.254.169.254/', 'http://10.0.0.5/', 'http://127.0.0.1/']) {
    const result = decideScope(privateScope, url)
    assert.equal(result.decision, SCOPE_DENY, url)
    assert.equal(result.reason, 'private-target-not-sealed')
  }
})

test('private targets are permitted only when explicitly sealed', () => {
  const sealed = {
    scope_rules: {
      allow: [{ rule_id: 'allow-loopback', host_kind: 'ip', host: '127.0.0.1' }],
      deny: [],
      private_targets_sealed: true,
    },
  }
  assert.equal(decideScope(sealed, 'http://127.0.0.1/').decision, SCOPE_ALLOW)
})

test('non-default ports are denied unless the rule seals them', () => {
  assert.equal(decideScope(scope(), 'https://api.example.com:8443/').decision, SCOPE_DENY)
  const ported = {
    scope_rules: {
      allow: [
        { rule_id: 'allow-8443', host_kind: 'wildcard', host: 'example.com', ports: [443, 8443] },
      ],
      deny: [],
    },
  }
  assert.equal(decideScope(ported, 'https://api.example.com:8443/').decision, SCOPE_ALLOW)
})

test('path scope matches on segment boundaries only', () => {
  const pathScoped = {
    scope_rules: {
      allow: [
        { rule_id: 'allow-api', host_kind: 'exact', host: 'example.com', path_prefix: '/api' },
      ],
      deny: [],
    },
  }
  assert.equal(decideScope(pathScoped, 'https://example.com/api').decision, SCOPE_ALLOW)
  assert.equal(decideScope(pathScoped, 'https://example.com/api/v1').decision, SCOPE_ALLOW)
  assert.equal(decideScope(pathScoped, 'https://example.com/apifoo').decision, SCOPE_DENY)
  assert.equal(decideScope(pathScoped, 'https://example.com/').decision, SCOPE_DENY)
})

test('an uncanonicalizable candidate is denied with its refusal reason', () => {
  const result = decideScope(scope(), 'https://allowed.example.com@evil.example/')
  assert.equal(result.decision, SCOPE_DENY)
  assert.equal(result.reason, 'candidate-carries-userinfo')
})

test('a malformed sealed scope is denied, not thrown', () => {
  for (const bad of [null, undefined, {}, { scope_rules: null }, { scope_rules: { allow: 'x' } }]) {
    const result = decideScope(bad, 'https://api.example.com/')
    assert.equal(result.decision, SCOPE_DENY)
    assert.equal(result.reason, 'sealed-scope-not-usable')
  }
})

test('a rule that throws during matching denies the candidate', () => {
  const hostile = {
    scope_rules: {
      allow: [{
        rule_id: 'hostile',
        host_kind: 'exact',
        get host() { throw new Error('boom') },
      }],
      deny: [],
    },
  }
  const result = decideScope(hostile, 'https://api.example.com/')
  assert.equal(result.decision, SCOPE_DENY)
  assert.equal(result.reason, 'kernel-error')
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/bounty-scope-kernel.test.mjs`
Expected: FAIL — `Cannot find module '../scripts/lib/bounty-scope-kernel.mjs'`

- [ ] **Step 3: Write minimal implementation**

Create `scripts/lib/bounty-scope-kernel.mjs`:

```js
import { canonicalizeCandidate } from './bounty-target.mjs'

export const SCOPE_ALLOW = 'ALLOW'
export const SCOPE_DENY = 'DENY'

const DEFAULT_PORTS = [80, 443]

const METADATA_HOSTS = new Set([
  '169.254.169.254',
  '100.100.100.200',
  'metadata.google.internal',
  'metadata',
])

function deny(reason, ruleId = 'none') {
  return { decision: SCOPE_DENY, rule_id: ruleId, reason }
}

function allow(ruleId) {
  return { decision: SCOPE_ALLOW, rule_id: ruleId, reason: 'allow-rule-matched' }
}

function ipv4Octets(host) {
  const parts = host.split('.')
  if (parts.length !== 4) return null
  const octets = parts.map((part) => Number.parseInt(part, 10))
  return octets.some((octet) => !Number.isInteger(octet)) ? null : octets
}

function isPrivateTarget(target) {
  if (METADATA_HOSTS.has(target.host)) return true
  if (target.hostKind === 'domain') return target.host === 'localhost'
  if (target.hostKind === 'ipv6') {
    return target.host === '::1'
      || target.host === '::'
      || target.host.startsWith('fe80:')
      || target.host.startsWith('fc')
      || target.host.startsWith('fd')
  }
  const octets = ipv4Octets(target.host)
  if (octets === null) return true
  const [a, b] = octets
  if (a === 10 || a === 127 || a === 0) return true
  if (a === 172 && b >= 16 && b <= 31) return true
  if (a === 192 && b === 168) return true
  if (a === 169 && b === 254) return true
  if (a === 100 && b >= 64 && b <= 127) return true
  return false
}

function hostMatches(rule, target) {
  if (rule.host_kind === 'ip') {
    return target.hostKind !== 'domain' && target.host === rule.host
  }
  if (target.hostKind !== 'domain') return false
  if (rule.host_kind === 'exact') return target.host === rule.host
  if (rule.host_kind === 'wildcard') {
    return target.host !== rule.host && target.host.endsWith(`.${rule.host}`)
  }
  return false
}

function portMatches(rule, target) {
  const ports = Array.isArray(rule.ports) ? rule.ports : DEFAULT_PORTS
  return ports.includes(target.port)
}

function pathMatches(rule, target) {
  if (typeof rule.path_prefix !== 'string' || rule.path_prefix.length === 0) return true
  const prefix = rule.path_prefix.endsWith('/')
    ? rule.path_prefix.slice(0, -1)
    : rule.path_prefix
  if (target.path === prefix) return true
  return target.path.startsWith(`${prefix}/`)
}

function ruleMatches(rule, target) {
  if (rule === null || typeof rule !== 'object') return false
  return hostMatches(rule, target) && portMatches(rule, target) && pathMatches(rule, target)
}

function ruleId(rule) {
  return typeof rule?.rule_id === 'string' ? rule.rule_id : 'unnamed-rule'
}

export function decideScope(sealedScope, rawCandidate) {
  try {
    const rules = sealedScope?.scope_rules
    if (rules === null || typeof rules !== 'object') {
      return deny('sealed-scope-not-usable')
    }
    if (!Array.isArray(rules.allow) || !Array.isArray(rules.deny)) {
      return deny('sealed-scope-not-usable')
    }
    const canonical = canonicalizeCandidate(rawCandidate)
    if (!canonical.ok) return deny(canonical.reason)
    const target = canonical.target

    for (const rule of rules.deny) {
      if (ruleMatches(rule, target)) return deny('explicit-deny-rule', ruleId(rule))
    }
    if (isPrivateTarget(target) && rules.private_targets_sealed !== true) {
      return deny('private-target-not-sealed')
    }
    for (const rule of rules.allow) {
      if (ruleMatches(rule, target)) return allow(ruleId(rule))
    }
    return deny('candidate-unlisted')
  } catch {
    return deny('kernel-error')
  }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/bounty-scope-kernel.test.mjs`
Expected: PASS, 15 tests

- [ ] **Step 5: Verify kernel purity**

Run: `grep -nE "node:(fs|http|https|dns|child_process)|Date\.now|fetch\(" scripts/lib/bounty-scope-kernel.mjs scripts/lib/bounty-target.mjs`
Expected: no output. Any match is a Global Constraints violation — remove it before committing.

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/bounty-scope-kernel.mjs test/bounty-scope-kernel.test.mjs
git commit -m "feat(bounty-v1): fail-closed scope kernel with deny precedence"
```

---

### Task 3: Adversarial conformance fixture suite

**Files:**
- Create: `fixtures/bounty/scope-kernel-cases.json`
- Test: `test/bounty-scope-kernel-adversarial.test.mjs`

**Interfaces:**
- Consumes: `decideScope`, `SCOPE_ALLOW`, `SCOPE_DENY` from Task 2.
- Produces: `fixtures/bounty/scope-kernel-cases.json` as the cross-language contract. The future Python proxy addon in P2 must produce identical decisions for every case. Shape: `{ schema_version, kind, scope, cases: [{ case_id, candidate, expect, expect_reason }] }`.

This is the P0 gate. It is the reason the phase exists.

- [ ] **Step 1: Write the fixture file**

Create `fixtures/bounty/scope-kernel-cases.json`:

```json
{
  "schema_version": "1.0.0",
  "kind": "red-team-audit/bounty-scope-kernel-cases",
  "scope": {
    "scope_rules": {
      "allow": [
        { "rule_id": "a1", "host_kind": "wildcard", "host": "target.example" },
        { "rule_id": "a2", "host_kind": "exact", "host": "target.example" },
        { "rule_id": "a3", "host_kind": "exact", "host": "api.other.example", "path_prefix": "/api" },
        { "rule_id": "a4", "host_kind": "ip", "host": "203.0.113.7" },
        { "rule_id": "a5", "host_kind": "wildcard", "host": "ports.example", "ports": [443, 8443] }
      ],
      "deny": [
        { "rule_id": "d1", "host_kind": "exact", "host": "internal.target.example" },
        { "rule_id": "d2", "host_kind": "wildcard", "host": "corp.target.example" }
      ]
    }
  },
  "cases": [
    { "case_id": "apex-listed-allows", "candidate": "https://target.example/", "expect": "ALLOW", "expect_reason": "allow-rule-matched" },
    { "case_id": "subdomain-allows", "candidate": "https://www.target.example/", "expect": "ALLOW", "expect_reason": "allow-rule-matched" },
    { "case_id": "nested-subdomain-allows", "candidate": "https://a.b.c.target.example/", "expect": "ALLOW", "expect_reason": "allow-rule-matched" },
    { "case_id": "explicit-deny-beats-wildcard", "candidate": "https://internal.target.example/", "expect": "DENY", "expect_reason": "explicit-deny-rule" },
    { "case_id": "deny-wildcard-covers-children", "candidate": "https://vpn.corp.target.example/", "expect": "DENY", "expect_reason": "explicit-deny-rule" },
    { "case_id": "suffix-confusion-denied", "candidate": "https://eviltarget.example/", "expect": "DENY", "expect_reason": "candidate-unlisted" },
    { "case_id": "domain-suffix-append-denied", "candidate": "https://target.example.evil.net/", "expect": "DENY", "expect_reason": "candidate-unlisted" },
    { "case_id": "userinfo-confusion-denied", "candidate": "https://target.example@evil.net/", "expect": "DENY", "expect_reason": "candidate-carries-userinfo" },
    { "case_id": "userinfo-with-password-denied", "candidate": "https://target.example:x@evil.net/", "expect": "DENY", "expect_reason": "candidate-carries-userinfo" },
    { "case_id": "trailing-dot-normalizes-to-allow", "candidate": "https://www.target.example./", "expect": "ALLOW", "expect_reason": "allow-rule-matched" },
    { "case_id": "double-trailing-dot-denied", "candidate": "https://www.target.example../", "expect": "DENY", "expect_reason": "host-not-canonicalizable" },
    { "case_id": "uppercase-host-normalizes-to-allow", "candidate": "https://WWW.TARGET.EXAMPLE/", "expect": "ALLOW", "expect_reason": "allow-rule-matched" },
    { "case_id": "idn-homograph-denied", "candidate": "https://tаrget.example/", "expect": "DENY", "expect_reason": "candidate-unlisted" },
    { "case_id": "non-default-port-denied", "candidate": "https://www.target.example:8443/", "expect": "DENY", "expect_reason": "candidate-unlisted" },
    { "case_id": "sealed-port-allows", "candidate": "https://api.ports.example:8443/", "expect": "ALLOW", "expect_reason": "allow-rule-matched" },
    { "case_id": "unsealed-port-on-ported-rule-denied", "candidate": "https://api.ports.example:9000/", "expect": "DENY", "expect_reason": "candidate-unlisted" },
    { "case_id": "path-prefix-exact-allows", "candidate": "https://api.other.example/api", "expect": "ALLOW", "expect_reason": "allow-rule-matched" },
    { "case_id": "path-prefix-child-allows", "candidate": "https://api.other.example/api/v1/users", "expect": "ALLOW", "expect_reason": "allow-rule-matched" },
    { "case_id": "path-prefix-sibling-denied", "candidate": "https://api.other.example/apifoo", "expect": "DENY", "expect_reason": "candidate-unlisted" },
    { "case_id": "path-prefix-root-denied", "candidate": "https://api.other.example/", "expect": "DENY", "expect_reason": "candidate-unlisted" },
    { "case_id": "path-traversal-escape-denied", "candidate": "https://api.other.example/api/../admin", "expect": "DENY", "expect_reason": "candidate-unlisted" },
    { "case_id": "listed-ip-allows", "candidate": "https://203.0.113.7/", "expect": "ALLOW", "expect_reason": "allow-rule-matched" },
    { "case_id": "unlisted-ip-denied", "candidate": "https://203.0.113.8/", "expect": "DENY", "expect_reason": "candidate-unlisted" },
    { "case_id": "loopback-denied", "candidate": "http://127.0.0.1/", "expect": "DENY", "expect_reason": "private-target-not-sealed" },
    { "case_id": "localhost-denied", "candidate": "http://localhost/", "expect": "DENY", "expect_reason": "private-target-not-sealed" },
    { "case_id": "rfc1918-ten-denied", "candidate": "http://10.1.2.3/", "expect": "DENY", "expect_reason": "private-target-not-sealed" },
    { "case_id": "rfc1918-172-denied", "candidate": "http://172.16.0.1/", "expect": "DENY", "expect_reason": "private-target-not-sealed" },
    { "case_id": "rfc1918-192-denied", "candidate": "http://192.168.1.1/", "expect": "DENY", "expect_reason": "private-target-not-sealed" },
    { "case_id": "aws-metadata-denied", "candidate": "http://169.254.169.254/latest/meta-data/", "expect": "DENY", "expect_reason": "private-target-not-sealed" },
    { "case_id": "gcp-metadata-denied", "candidate": "http://metadata.google.internal/", "expect": "DENY", "expect_reason": "private-target-not-sealed" },
    { "case_id": "alibaba-metadata-denied", "candidate": "http://100.100.100.200/", "expect": "DENY", "expect_reason": "private-target-not-sealed" },
    { "case_id": "ipv6-loopback-denied", "candidate": "http://[::1]/", "expect": "DENY", "expect_reason": "private-target-not-sealed" },
    { "case_id": "ipv6-link-local-denied", "candidate": "http://[fe80::1]/", "expect": "DENY", "expect_reason": "private-target-not-sealed" },
    { "case_id": "ipv6-unique-local-denied", "candidate": "http://[fd00::1]/", "expect": "DENY", "expect_reason": "private-target-not-sealed" },
    { "case_id": "file-scheme-denied", "candidate": "file:///etc/passwd", "expect": "DENY", "expect_reason": "scheme-not-http" },
    { "case_id": "gopher-scheme-denied", "candidate": "gopher://target.example/", "expect": "DENY", "expect_reason": "scheme-not-http" },
    { "case_id": "unparsable-denied", "candidate": "https://", "expect": "DENY", "expect_reason": "candidate-unparsable" },
    { "case_id": "empty-denied", "candidate": "", "expect": "DENY", "expect_reason": "candidate-not-a-string" }
  ]
}
```

Two notes on this fixture file:

**`idn-homograph-denied`** — the host contains a Cyrillic `а` (U+0430), not Latin `a`. It punycodes to a different host than `target.example` and must therefore be denied. Preserve the byte sequence exactly when editing this file.

**`double-trailing-dot-denied`** — the expected reason depends on how Node's WHATWG URL parser handles the empty trailing label. If `new URL()` accepts it, `normalizeHost` returns `null` and the reason is `host-not-canonicalizable`; if the parser rejects it outright, the reason is `candidate-unparsable`. Run the case, then record whichever reason the parser actually produces. **The `expect` value stays `DENY` either way** — that is the assertion that matters. Do not "fix" this by loosening the kernel.

- [ ] **Step 2: Write the failing test**

Create `test/bounty-scope-kernel-adversarial.test.mjs`:

```js
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import { decideScope } from '../scripts/lib/bounty-scope-kernel.mjs'

const CASES_URL = new URL('../fixtures/bounty/scope-kernel-cases.json', import.meta.url)
const suite = JSON.parse(readFileSync(CASES_URL, 'utf8'))

test('fixture suite is well formed', () => {
  assert.equal(suite.kind, 'red-team-audit/bounty-scope-kernel-cases')
  assert.ok(suite.cases.length >= 35)
  const ids = suite.cases.map((entry) => entry.case_id)
  assert.equal(new Set(ids).size, ids.length, 'case ids must be unique')
})

for (const entry of suite.cases) {
  test(`scope kernel case: ${entry.case_id}`, () => {
    const result = decideScope(suite.scope, entry.candidate)
    assert.equal(result.decision, entry.expect, `${entry.candidate} decision`)
    assert.equal(result.reason, entry.expect_reason, `${entry.candidate} reason`)
  })
}

test('no case in the suite reaches ALLOW by default', () => {
  const emptyScope = { scope_rules: { allow: [], deny: [] } }
  for (const entry of suite.cases) {
    assert.equal(decideScope(emptyScope, entry.candidate).decision, 'DENY', entry.case_id)
  }
})
```

- [ ] **Step 3: Run test to verify it fails or reveals kernel gaps**

Run: `node --test test/bounty-scope-kernel-adversarial.test.mjs`
Expected: FAIL on any case where the Task 2 kernel disagrees with the fixture. Fix the **kernel**, never the fixture, unless the fixture's stated expectation is itself wrong — and if you change a fixture expectation, say so explicitly in the commit message.

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/bounty-scope-kernel-adversarial.test.mjs`
Expected: PASS, 40 tests

- [ ] **Step 5: Run the whole suite for regressions**

Run: `npm.cmd test`
Expected: PASS. The existing ~130 test files must be unaffected — nothing in Tasks 1-3 modifies existing files.

- [ ] **Step 6: Commit**

```bash
git add fixtures/bounty/scope-kernel-cases.json test/bounty-scope-kernel-adversarial.test.mjs
git commit -m "test(bounty-v1): adversarial scope kernel conformance fixtures"
```

---

### Task 4: Sealed scope schema and contract validation

**Files:**
- Create: `schemas/bounty-scope.schema.json`
- Create: `scripts/lib/bounty-contracts.mjs`
- Test: `test/bounty-contracts.test.mjs`

**Interfaces:**
- Consumes: `canonicalJson` and `sha256Hex` from `scripts/lib/http-recon-contracts.mjs`.
- Produces:
  - `assertValidBountyScope(value) -> void` (throws `Error` with an Ajv-derived message on invalid input)
  - `digestPolicySnapshot(bytes: Buffer | string) -> string` (lowercase hex sha256)
  - `BOUNTY_SCOPE_SCHEMA_VERSION = '1.0.0'`
  - `PROGRAM_POLICY_SEALED_STATEMENT: string`

- [ ] **Step 1: Write the failing test**

Create `test/bounty-contracts.test.mjs`:

```js
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  BOUNTY_SCOPE_SCHEMA_VERSION,
  assertValidBountyScope,
  digestPolicySnapshot,
} from '../scripts/lib/bounty-contracts.mjs'

function validScope() {
  return {
    schema_version: BOUNTY_SCOPE_SCHEMA_VERSION,
    kind: 'red-team-audit/bounty-scope',
    engagement_id: 'ywh-acme-2026-08',
    platform: 'yeswehack',
    environment: 'production',
    data_class: 'non_phi',
    program: {
      program_handle: 'acme-public',
      policy_url: 'https://yeswehack.com/programs/acme-public',
      policy_snapshot_sha256: 'a'.repeat(64),
    },
    authorization: {
      mode: 'PROGRAM_POLICY_SEALED',
      authorization_id: 'auth-001',
      statement: 'Operator declares enrollment in the named bounty program.',
      operator_id: 'operator-1',
      authorized_by: 'ACME via YesWeHack program policy',
      authorization_reference: 'https://yeswehack.com/programs/acme-public',
      attested_at: '2026-08-20T12:00:00.000Z',
      independently_verified: false,
      permissions: {
        active_testing: true,
        production: true,
        third_party: false,
        phi: false,
        mutation: false,
        automation_allowed: true,
        intensity: 'normal',
        desync_probes: false,
        rate_limit_rps: 5,
      },
    },
    validity: { not_before: '2026-08-20T00:00:00.000Z', not_after: '2026-11-20T00:00:00.000Z' },
    scope_rules: {
      allow: [{ rule_id: 'a1', host_kind: 'wildcard', host: 'acme.example' }],
      deny: [],
    },
    stop_conditions: { max_findings: 100, operator_stop: false },
  }
}

test('accepts a well formed sealed scope', () => {
  assert.doesNotThrow(() => assertValidBountyScope(validScope()))
})

test('refuses phi true', () => {
  const scope = validScope()
  scope.authorization.permissions.phi = true
  assert.throws(() => assertValidBountyScope(scope), /phi/)
})

test('refuses an intensity outside the sealed enum', () => {
  const scope = validScope()
  scope.authorization.permissions.intensity = 'nuclear'
  assert.throws(() => assertValidBountyScope(scope), /intensity/)
})

test('accepts every sealed intensity tier', () => {
  for (const intensity of ['normal', 'aggressive', 'ham']) {
    const scope = validScope()
    scope.authorization.permissions.intensity = intensity
    assert.doesNotThrow(() => assertValidBountyScope(scope), intensity)
  }
})

test('refuses a phi or unknown data class', () => {
  for (const dataClass of ['phi', 'unknown']) {
    const scope = validScope()
    scope.data_class = dataClass
    assert.throws(() => assertValidBountyScope(scope), /data_class/)
  }
})

test('refuses an authorization mode from another protocol', () => {
  const scope = validScope()
  scope.authorization.mode = 'OPERATOR_ATTESTED_AUTHED'
  assert.throws(() => assertValidBountyScope(scope), /mode/)
})

test('refuses independently_verified true', () => {
  const scope = validScope()
  scope.authorization.independently_verified = true
  assert.throws(() => assertValidBountyScope(scope), /independently_verified/)
})

test('refuses a missing policy snapshot digest', () => {
  const scope = validScope()
  delete scope.program.policy_snapshot_sha256
  assert.throws(() => assertValidBountyScope(scope), /policy_snapshot_sha256/)
})

test('refuses an empty allow list', () => {
  const scope = validScope()
  scope.scope_rules.allow = []
  assert.throws(() => assertValidBountyScope(scope), /allow/)
})

test('refuses unknown top level properties', () => {
  const scope = validScope()
  scope.extra_field = 'nope'
  assert.throws(() => assertValidBountyScope(scope), /extra_field/)
})

test('digests a policy snapshot to lowercase hex sha256', () => {
  const digest = digestPolicySnapshot('policy text\n')
  assert.match(digest, /^[0-9a-f]{64}$/)
  assert.equal(digest, digestPolicySnapshot(Buffer.from('policy text\n')))
  assert.notEqual(digest, digestPolicySnapshot('policy text changed\n'))
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/bounty-contracts.test.mjs`
Expected: FAIL — `Cannot find module '../scripts/lib/bounty-contracts.mjs'`

- [ ] **Step 3: Write the schema**

Create `schemas/bounty-scope.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://red-team-audit.dev/schemas/bounty-scope.schema.json",
  "title": "Red Team Audit bounty program scope (bounty-v1)",
  "description": "A sealed bug bounty program perimeter. The authorization records an operator declaration of program enrollment; it does not verify enrollment, asset ownership, scope currency, or revocation. This scope is never repository coverage and never an audit clearance.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema_version",
    "kind",
    "engagement_id",
    "platform",
    "environment",
    "data_class",
    "program",
    "authorization",
    "validity",
    "scope_rules",
    "stop_conditions"
  ],
  "properties": {
    "schema_version": { "enum": ["1.0.0"] },
    "kind": { "const": "red-team-audit/bounty-scope" },
    "engagement_id": { "$ref": "#/$defs/id" },
    "platform": { "enum": ["yeswehack", "hackerone", "intigriti", "direct"] },
    "environment": { "enum": ["production", "non_production"] },
    "data_class": { "const": "non_phi" },
    "program": {
      "type": "object",
      "additionalProperties": false,
      "required": ["program_handle", "policy_url", "policy_snapshot_sha256"],
      "properties": {
        "program_handle": { "$ref": "#/$defs/id" },
        "policy_url": { "type": "string", "pattern": "^https://", "maxLength": 2048 },
        "policy_snapshot_sha256": { "$ref": "#/$defs/sha256" }
      }
    },
    "authorization": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "mode",
        "authorization_id",
        "statement",
        "operator_id",
        "authorized_by",
        "authorization_reference",
        "attested_at",
        "independently_verified",
        "permissions"
      ],
      "properties": {
        "mode": { "const": "PROGRAM_POLICY_SEALED" },
        "authorization_id": { "$ref": "#/$defs/id" },
        "statement": { "type": "string", "minLength": 1, "maxLength": 2048 },
        "operator_id": { "$ref": "#/$defs/id" },
        "authorized_by": { "type": "string", "minLength": 1, "maxLength": 512 },
        "authorization_reference": { "type": "string", "minLength": 1, "maxLength": 2048 },
        "attested_at": { "$ref": "#/$defs/timestamp" },
        "independently_verified": { "const": false },
        "permissions": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "active_testing",
            "production",
            "third_party",
            "phi",
            "mutation",
            "automation_allowed",
            "intensity",
            "desync_probes",
            "rate_limit_rps"
          ],
          "properties": {
            "active_testing": { "type": "boolean" },
            "production": { "type": "boolean" },
            "third_party": { "type": "boolean" },
            "phi": { "const": false },
            "mutation": { "type": "boolean" },
            "automation_allowed": { "type": "boolean" },
            "intensity": { "enum": ["normal", "aggressive", "ham"] },
            "desync_probes": { "type": "boolean" },
            "rate_limit_rps": { "type": "integer", "minimum": 1, "maximum": 200 }
          }
        }
      }
    },
    "validity": {
      "type": "object",
      "additionalProperties": false,
      "required": ["not_before", "not_after"],
      "properties": {
        "not_before": { "$ref": "#/$defs/timestamp" },
        "not_after": { "$ref": "#/$defs/timestamp" }
      }
    },
    "scope_rules": {
      "type": "object",
      "additionalProperties": false,
      "required": ["allow", "deny"],
      "properties": {
        "allow": { "type": "array", "minItems": 1, "maxItems": 4096, "items": { "$ref": "#/$defs/rule" } },
        "deny": { "type": "array", "maxItems": 4096, "items": { "$ref": "#/$defs/rule" } },
        "private_targets_sealed": { "type": "boolean" }
      }
    },
    "stop_conditions": {
      "type": "object",
      "additionalProperties": false,
      "required": ["max_findings", "operator_stop"],
      "properties": {
        "max_findings": { "type": "integer", "minimum": 1, "maximum": 10000 },
        "operator_stop": { "type": "boolean" }
      }
    }
  },
  "$defs": {
    "id": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$" },
    "sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "timestamp": { "type": "string", "format": "date-time", "minLength": 20, "maxLength": 32 },
    "rule": {
      "type": "object",
      "additionalProperties": false,
      "required": ["rule_id", "host_kind", "host"],
      "properties": {
        "rule_id": { "$ref": "#/$defs/id" },
        "host_kind": { "enum": ["exact", "wildcard", "ip"] },
        "host": { "type": "string", "minLength": 1, "maxLength": 253 },
        "ports": {
          "type": "array",
          "minItems": 1,
          "maxItems": 32,
          "items": { "type": "integer", "minimum": 1, "maximum": 65535 }
        },
        "path_prefix": { "type": "string", "pattern": "^/", "maxLength": 1024 }
      }
    }
  }
}
```

- [ ] **Step 4: Write minimal implementation**

Create `scripts/lib/bounty-contracts.mjs`:

```js
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import Ajv2020 from 'ajv/dist/2020.js'

const SCOPE_SCHEMA_URL = new URL('../../schemas/bounty-scope.schema.json', import.meta.url)

export const BOUNTY_SCOPE_SCHEMA_VERSION = '1.0.0'

export const PROGRAM_POLICY_SEALED_STATEMENT =
  'I declare that I am an enrolled researcher on the named bounty program and that the sealed scope reflects that program policy as published at seal time.'

let compiledScopeValidator = null

function scopeValidator() {
  if (compiledScopeValidator !== null) return compiledScopeValidator
  const ajv = new Ajv2020({ allErrors: true, strict: false })
  const schema = JSON.parse(readFileSync(SCOPE_SCHEMA_URL, 'utf8'))
  compiledScopeValidator = ajv.compile(schema)
  return compiledScopeValidator
}

export function assertValidBountyScope(value) {
  const validate = scopeValidator()
  if (validate(value)) return
  const detail = (validate.errors ?? [])
    .map((error) => `${error.instancePath || '/'} ${error.message}${
      error.params?.additionalProperty ? ` (${error.params.additionalProperty})` : ''
    }`)
    .join('; ')
  throw new Error(`bounty scope failed schema validation: ${detail}`)
}

export function digestPolicySnapshot(bytes) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes), 'utf8')
  return createHash('sha256').update(buffer).digest('hex')
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `node --test test/bounty-contracts.test.mjs`
Expected: PASS, 11 tests

Note: Ajv reports `additionalProperties` violations with the offending key in `error.params.additionalProperty`, which is why the message builder appends it — the `extra_field` test asserts on that name.

- [ ] **Step 6: Commit**

```bash
git add schemas/bounty-scope.schema.json scripts/lib/bounty-contracts.mjs test/bounty-contracts.test.mjs
git commit -m "feat(bounty-v1): sealed bounty scope schema and contract validation"
```

---

### Task 5: Program policy sealing

**Files:**
- Create: `scripts/lib/bounty-planner.mjs`
- Test: `test/bounty-planner.test.mjs`

**Interfaces:**
- Consumes: `assertValidBountyScope`, `digestPolicySnapshot`, `PROGRAM_POLICY_SEALED_STATEMENT`, `BOUNTY_SCOPE_SCHEMA_VERSION` from Task 4.
- Produces:
  - `parseScopeRuleSpec(spec: string) -> Rule` — turns `*.acme.example`, `acme.example`, `203.0.113.7`, `acme.example/api`, `acme.example:8443` into a rule object. Rule ids are assigned by `createProgramSealedScope`.
  - `createProgramSealedScope(options) -> object` — the sealed scope. `options` = `{ engagementId, platform, programHandle, policyUrl, policySnapshotBytes, operatorId, authorizedBy, allowSpecs: string[], denySpecs?: string[], permissions, validity: { notBefore, notAfter }, maxFindings?, now: Date }`
  - Throws on: `phi: true`, missing attestation, empty allow list, `notAfter <= notBefore`, an `intensity` outside `normal|aggressive|ham`, `intensity !== 'normal'` without `active_testing: true`, `intensity === 'ham'` without `automation_allowed: true`, and `desync_probes: true` at any intensity below `ham`.
  - `permissions.intensity` is the HAM dial from spec §20. The planner gates it; every later phase reads it. It never widens `scope_rules`.

- [ ] **Step 1: Write the failing test**

Create `test/bounty-planner.test.mjs`:

```js
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { assertValidBountyScope } from '../scripts/lib/bounty-contracts.mjs'
import { createProgramSealedScope, parseScopeRuleSpec } from '../scripts/lib/bounty-planner.mjs'
import { decideScope } from '../scripts/lib/bounty-scope-kernel.mjs'

const NOW = new Date('2026-08-20T12:00:00.000Z')

function permissions(overrides = {}) {
  return {
    active_testing: true,
    production: true,
    third_party: false,
    mutation: false,
    automation_allowed: true,
    intensity: 'normal',
    desync_probes: false,
    rate_limit_rps: 5,
    ...overrides,
  }
}

function options(overrides = {}) {
  return {
    engagementId: 'ywh-acme-2026-08',
    platform: 'yeswehack',
    programHandle: 'acme-public',
    policyUrl: 'https://yeswehack.com/programs/acme-public',
    policySnapshotBytes: Buffer.from('ACME program policy. Scope: *.acme.example\n'),
    operatorId: 'operator-1',
    authorizedBy: 'ACME via YesWeHack program policy',
    allowSpecs: ['*.acme.example', 'acme.example'],
    denySpecs: ['legacy.acme.example'],
    permissions: permissions(),
    validity: { notBefore: '2026-08-20T00:00:00.000Z', notAfter: '2026-11-20T00:00:00.000Z' },
    now: NOW,
    ...overrides,
  }
}

test('parses wildcard, exact, ip, port, and path specs', () => {
  assert.deepEqual(parseScopeRuleSpec('*.acme.example'), { host_kind: 'wildcard', host: 'acme.example' })
  assert.deepEqual(parseScopeRuleSpec('acme.example'), { host_kind: 'exact', host: 'acme.example' })
  assert.deepEqual(parseScopeRuleSpec('203.0.113.7'), { host_kind: 'ip', host: '203.0.113.7' })
  assert.deepEqual(parseScopeRuleSpec('acme.example:8443'), {
    host_kind: 'exact',
    host: 'acme.example',
    ports: [8443],
  })
  assert.deepEqual(parseScopeRuleSpec('*.acme.example/api'), {
    host_kind: 'wildcard',
    host: 'acme.example',
    path_prefix: '/api',
  })
})

test('lowercases hosts in parsed specs', () => {
  assert.equal(parseScopeRuleSpec('*.ACME.Example').host, 'acme.example')
})

test('seals a schema valid scope', () => {
  const scope = createProgramSealedScope(options())
  assert.doesNotThrow(() => assertValidBountyScope(scope))
  assert.equal(scope.authorization.mode, 'PROGRAM_POLICY_SEALED')
  assert.equal(scope.authorization.independently_verified, false)
  assert.equal(scope.data_class, 'non_phi')
  assert.equal(scope.authorization.permissions.phi, false)
})

test('seals the policy snapshot digest, not the policy text', () => {
  const scope = createProgramSealedScope(options())
  assert.match(scope.program.policy_snapshot_sha256, /^[0-9a-f]{64}$/)
  assert.equal(JSON.stringify(scope).includes('ACME program policy'), false)
})

test('assigns stable unique rule ids', () => {
  const scope = createProgramSealedScope(options())
  const ids = [...scope.scope_rules.allow, ...scope.scope_rules.deny].map((rule) => rule.rule_id)
  assert.equal(new Set(ids).size, ids.length)
  assert.deepEqual(scope.scope_rules.allow.map((rule) => rule.rule_id), ['allow-1', 'allow-2'])
  assert.deepEqual(scope.scope_rules.deny.map((rule) => rule.rule_id), ['deny-1'])
})

test('the sealed scope drives the kernel end to end', () => {
  const scope = createProgramSealedScope(options())
  assert.equal(decideScope(scope, 'https://www.acme.example/').decision, 'ALLOW')
  assert.equal(decideScope(scope, 'https://acme.example/').decision, 'ALLOW')
  assert.equal(decideScope(scope, 'https://legacy.acme.example/').decision, 'DENY')
  assert.equal(decideScope(scope, 'https://other.example/').decision, 'DENY')
})

test('refuses phi permission', () => {
  assert.throws(
    () => createProgramSealedScope(options({ permissions: permissions({ phi: true }) })),
    /phi/,
  )
})

test('refuses an empty allow list', () => {
  assert.throws(() => createProgramSealedScope(options({ allowSpecs: [] })), /allow/)
})

test('refuses an inverted validity window', () => {
  assert.throws(
    () => createProgramSealedScope(options({
      validity: { notBefore: '2026-11-20T00:00:00.000Z', notAfter: '2026-08-20T00:00:00.000Z' },
    })),
    /validity/,
  )
})

test('refuses aggressive or ham intensity without active testing', () => {
  for (const intensity of ['aggressive', 'ham']) {
    assert.throws(
      () => createProgramSealedScope(options({
        permissions: permissions({ active_testing: false, intensity }),
      })),
      /active_testing/,
      intensity,
    )
  }
})

test('refuses ham intensity without automation_allowed', () => {
  assert.throws(
    () => createProgramSealedScope(options({
      permissions: permissions({ intensity: 'ham', automation_allowed: false }),
    })),
    /automation_allowed/,
  )
})

test('seals ham intensity when the program grants active testing and automation', () => {
  const scope = createProgramSealedScope(options({
    permissions: permissions({ intensity: 'ham' }),
  }))
  assert.equal(scope.authorization.permissions.intensity, 'ham')
})

test('refuses an unknown intensity tier', () => {
  assert.throws(
    () => createProgramSealedScope(options({ permissions: permissions({ intensity: 'nuclear' }) })),
    /intensity/,
  )
})

test('refuses desync probes below ham intensity', () => {
  for (const intensity of ['normal', 'aggressive']) {
    assert.throws(
      () => createProgramSealedScope(options({
        permissions: permissions({ intensity, desync_probes: true }),
      })),
      /desync_probes/,
      intensity,
    )
  }
})

test('ham intensity does not widen the sealed perimeter', () => {
  const normal = createProgramSealedScope(options())
  const ham = createProgramSealedScope(options({ permissions: permissions({ intensity: 'ham' }) }))
  assert.deepEqual(ham.scope_rules, normal.scope_rules)
  for (const candidate of ['https://other.example/', 'http://127.0.0.1/', 'https://legacy.acme.example/']) {
    assert.equal(decideScope(ham, candidate).decision, 'DENY', candidate)
    assert.equal(
      decideScope(ham, candidate).decision,
      decideScope(normal, candidate).decision,
      candidate,
    )
  }
})

test('records the operator attestation statement verbatim', () => {
  const scope = createProgramSealedScope(options())
  assert.match(scope.authorization.statement, /enrolled researcher/)
  assert.equal(scope.authorization.attested_at, NOW.toISOString())
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/bounty-planner.test.mjs`
Expected: FAIL — `Cannot find module '../scripts/lib/bounty-planner.mjs'`

- [ ] **Step 3: Write minimal implementation**

Create `scripts/lib/bounty-planner.mjs`:

```js
import { isIP } from 'node:net'
import {
  BOUNTY_SCOPE_SCHEMA_VERSION,
  PROGRAM_POLICY_SEALED_STATEMENT,
  assertValidBountyScope,
  digestPolicySnapshot,
} from './bounty-contracts.mjs'

const DEFAULT_MAX_FINDINGS = 500

export function parseScopeRuleSpec(spec) {
  if (typeof spec !== 'string' || spec.trim().length === 0) {
    throw new Error('scope rule spec must be a non-empty string')
  }
  let rest = spec.trim()
  let pathPrefix = null
  const slashIndex = rest.indexOf('/')
  if (slashIndex !== -1) {
    pathPrefix = rest.slice(slashIndex)
    rest = rest.slice(0, slashIndex)
  }
  let ports = null
  const colonIndex = rest.lastIndexOf(':')
  if (colonIndex !== -1 && !rest.includes('[')) {
    const portText = rest.slice(colonIndex + 1)
    const port = Number.parseInt(portText, 10)
    if (!Number.isInteger(port) || String(port) !== portText) {
      throw new Error(`scope rule spec has an invalid port: ${spec}`)
    }
    ports = [port]
    rest = rest.slice(0, colonIndex)
  }
  let hostKind = 'exact'
  if (rest.startsWith('*.')) {
    hostKind = 'wildcard'
    rest = rest.slice(2)
  }
  const host = rest.toLowerCase()
  if (host.length === 0) {
    throw new Error(`scope rule spec has no host: ${spec}`)
  }
  if (hostKind === 'exact' && isIP(host) !== 0) {
    hostKind = 'ip'
  }
  const rule = { host_kind: hostKind, host }
  if (ports !== null) rule.ports = ports
  if (pathPrefix !== null) rule.path_prefix = pathPrefix
  return rule
}

function sealRules(specs, prefix) {
  return specs.map((spec, index) => ({
    rule_id: `${prefix}-${index + 1}`,
    ...parseScopeRuleSpec(spec),
  }))
}

const INTENSITY_TIERS = ['normal', 'aggressive', 'ham']

function checkPermissions(permissions) {
  if (permissions === null || typeof permissions !== 'object') {
    throw new Error('permissions must be an object')
  }
  if (permissions.phi === true) {
    throw new Error('bounty-v1 refuses phi permission; this protocol never handles PHI')
  }
  const intensity = permissions.intensity
  if (!INTENSITY_TIERS.includes(intensity)) {
    throw new Error(`intensity must be one of ${INTENSITY_TIERS.join(', ')}`)
  }
  if (intensity !== 'normal' && permissions.active_testing !== true) {
    throw new Error(`intensity ${intensity} requires active_testing`)
  }
  if (intensity === 'ham' && permissions.automation_allowed !== true) {
    throw new Error('intensity ham requires automation_allowed; HAM is sustained automated volume')
  }
  if (permissions.desync_probes === true && intensity !== 'ham') {
    throw new Error('desync_probes requires intensity ham')
  }
}

export function createProgramSealedScope(options) {
  const {
    engagementId,
    platform,
    programHandle,
    policyUrl,
    policySnapshotBytes,
    operatorId,
    authorizedBy,
    allowSpecs,
    denySpecs = [],
    permissions,
    validity,
    maxFindings = DEFAULT_MAX_FINDINGS,
    now,
  } = options ?? {}

  if (!Array.isArray(allowSpecs) || allowSpecs.length === 0) {
    throw new Error('at least one allow scope rule is required; empty allow lists are refused')
  }
  checkPermissions(permissions)
  const notBefore = new Date(validity?.notBefore ?? '')
  const notAfter = new Date(validity?.notAfter ?? '')
  if (Number.isNaN(notBefore.getTime()) || Number.isNaN(notAfter.getTime())) {
    throw new Error('validity requires parseable not_before and not_after timestamps')
  }
  if (notAfter.getTime() <= notBefore.getTime()) {
    throw new Error('validity not_after must be after not_before')
  }
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new Error('now must be a valid Date; the planner never reads the ambient clock')
  }

  const scope = {
    schema_version: BOUNTY_SCOPE_SCHEMA_VERSION,
    kind: 'red-team-audit/bounty-scope',
    engagement_id: engagementId,
    platform,
    environment: permissions.production === true ? 'production' : 'non_production',
    data_class: 'non_phi',
    program: {
      program_handle: programHandle,
      policy_url: policyUrl,
      policy_snapshot_sha256: digestPolicySnapshot(policySnapshotBytes),
    },
    authorization: {
      mode: 'PROGRAM_POLICY_SEALED',
      authorization_id: `${engagementId}-auth`,
      statement: PROGRAM_POLICY_SEALED_STATEMENT,
      operator_id: operatorId,
      authorized_by: authorizedBy,
      authorization_reference: policyUrl,
      attested_at: now.toISOString(),
      independently_verified: false,
      permissions: {
        active_testing: permissions.active_testing === true,
        production: permissions.production === true,
        third_party: permissions.third_party === true,
        phi: false,
        mutation: permissions.mutation === true,
        automation_allowed: permissions.automation_allowed === true,
        intensity: permissions.intensity,
        desync_probes: permissions.desync_probes === true,
        rate_limit_rps: permissions.rate_limit_rps,
      },
    },
    validity: { not_before: notBefore.toISOString(), not_after: notAfter.toISOString() },
    scope_rules: {
      allow: sealRules(allowSpecs, 'allow'),
      deny: sealRules(denySpecs, 'deny'),
    },
    stop_conditions: { max_findings: maxFindings, operator_stop: false },
  }
  assertValidBountyScope(scope)
  return scope
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/bounty-planner.test.mjs`
Expected: PASS, 16 tests

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/bounty-planner.mjs test/bounty-planner.test.mjs
git commit -m "feat(bounty-v1): seal bounty program policy into a scope perimeter"
```

---

### Task 6: Controller — plan, validate, revalidate, scope check

**Files:**
- Create: `scripts/lib/bounty-controller.mjs`
- Test: `test/bounty-controller.test.mjs`

**Interfaces:**
- Consumes: `createProgramSealedScope` (Task 5), `assertValidBountyScope` and `digestPolicySnapshot` (Task 4), `decideScope` (Task 2).
- Produces:
  - `planBountyBundle(options) -> Promise<{ bundlePath: string, scope: object }>` — `options` adds `outParent: string` and `policyPath: string` to Task 5's option shape; reads the policy file itself.
  - `validateBountyBundle(bundlePath) -> Promise<{ status: 'VALID', scope: object }>` — throws on tamper or schema failure.
  - `revalidateBountyBundle(bundlePath, policyPath) -> Promise<{ status: 'UNCHANGED' | 'DRIFTED', sealed: string, observed: string }>`
  - `checkBountyScope(bundlePath, candidate) -> Promise<{ decision, rule_id, reason }>`
  - Bundle layout: `<outParent>/<engagementId>/scope.json`, `<...>/bundle.json` where `bundle.json` = `{ kind: 'red-team-audit/bounty-bundle', schema_version: '1.0.0', engagement_id, scope_sha256, created_at }`.

- [ ] **Step 1: Write the failing test**

Create `test/bounty-controller.test.mjs`:

```js
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  checkBountyScope,
  planBountyBundle,
  revalidateBountyBundle,
  validateBountyBundle,
} from '../scripts/lib/bounty-controller.mjs'

const NOW = new Date('2026-08-20T12:00:00.000Z')
const POLICY = 'ACME program policy. Scope: *.acme.example\n'

async function workspace() {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-controller-'))
  const policyPath = join(dir, 'policy.txt')
  await writeFile(policyPath, POLICY, 'utf8')
  return { dir, policyPath }
}

function planOptions(dir, policyPath) {
  return {
    outParent: dir,
    policyPath,
    engagementId: 'ywh-acme-2026-08',
    platform: 'yeswehack',
    programHandle: 'acme-public',
    policyUrl: 'https://yeswehack.com/programs/acme-public',
    operatorId: 'operator-1',
    authorizedBy: 'ACME via YesWeHack program policy',
    allowSpecs: ['*.acme.example'],
    denySpecs: ['legacy.acme.example'],
    permissions: {
      active_testing: true,
      production: true,
      third_party: false,
      mutation: false,
      automation_allowed: true,
      intensity: 'normal',
      desync_probes: false,
      rate_limit_rps: 5,
    },
    validity: { notBefore: '2026-08-20T00:00:00.000Z', notAfter: '2026-11-20T00:00:00.000Z' },
    now: NOW,
  }
}

test('plan writes a bundle that validates', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const planned = await planBountyBundle(planOptions(dir, policyPath))
    const validated = await validateBountyBundle(planned.bundlePath)
    assert.equal(validated.status, 'VALID')
    assert.equal(validated.scope.program.program_handle, 'acme-public')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('validate detects a tampered scope file', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const planned = await planBountyBundle(planOptions(dir, policyPath))
    const scopePath = join(planned.bundlePath, 'scope.json')
    const scope = JSON.parse(await readFile(scopePath, 'utf8'))
    scope.scope_rules.allow.push({ rule_id: 'injected', host_kind: 'wildcard', host: 'evil.example' })
    await writeFile(scopePath, JSON.stringify(scope, null, 2), 'utf8')
    await assert.rejects(() => validateBountyBundle(planned.bundlePath), /digest/)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('revalidate reports UNCHANGED for the sealed policy', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const planned = await planBountyBundle(planOptions(dir, policyPath))
    const result = await revalidateBountyBundle(planned.bundlePath, policyPath)
    assert.equal(result.status, 'UNCHANGED')
    assert.equal(result.sealed, result.observed)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('revalidate reports DRIFTED when the program changes its policy', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const planned = await planBountyBundle(planOptions(dir, policyPath))
    await writeFile(policyPath, 'ACME policy. Scope: acme.example only\n', 'utf8')
    const result = await revalidateBountyBundle(planned.bundlePath, policyPath)
    assert.equal(result.status, 'DRIFTED')
    assert.notEqual(result.sealed, result.observed)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('scope check answers from the sealed bundle', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const planned = await planBountyBundle(planOptions(dir, policyPath))
    const allowed = await checkBountyScope(planned.bundlePath, 'https://www.acme.example/x')
    assert.equal(allowed.decision, 'ALLOW')
    const denied = await checkBountyScope(planned.bundlePath, 'https://legacy.acme.example/')
    assert.equal(denied.decision, 'DENY')
    assert.equal(denied.rule_id, 'deny-1')
    const unlisted = await checkBountyScope(planned.bundlePath, 'https://other.example/')
    assert.equal(unlisted.reason, 'candidate-unlisted')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('plan refuses to overwrite an existing bundle', async () => {
  const { dir, policyPath } = await workspace()
  try {
    await planBountyBundle(planOptions(dir, policyPath))
    await assert.rejects(() => planBountyBundle(planOptions(dir, policyPath)), /exists/)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/bounty-controller.test.mjs`
Expected: FAIL — `Cannot find module '../scripts/lib/bounty-controller.mjs'`

- [ ] **Step 3: Write minimal implementation**

Create `scripts/lib/bounty-controller.mjs`:

```js
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { assertValidBountyScope, digestPolicySnapshot } from './bounty-contracts.mjs'
import { createProgramSealedScope } from './bounty-planner.mjs'
import { decideScope } from './bounty-scope-kernel.mjs'

const BUNDLE_KIND = 'red-team-audit/bounty-bundle'
const BUNDLE_SCHEMA_VERSION = '1.0.0'
const MAX_POLICY_BYTES = 4 * 1024 * 1024

function serialize(value) {
  return `${JSON.stringify(value, null, 2)}\n`
}

async function readPolicyBytes(policyPath) {
  const bytes = await readFile(policyPath)
  if (bytes.byteLength === 0) {
    throw new Error(`policy snapshot is empty: ${policyPath}`)
  }
  if (bytes.byteLength > MAX_POLICY_BYTES) {
    throw new Error(`policy snapshot exceeds ${MAX_POLICY_BYTES} bytes: ${policyPath}`)
  }
  return bytes
}

export async function planBountyBundle(options) {
  const { outParent, policyPath, ...rest } = options
  const bundlePath = join(outParent, rest.engagementId)
  try {
    await mkdir(bundlePath, { recursive: false })
  } catch (error) {
    if (error.code === 'EEXIST') {
      throw new Error(`bundle path already exists, refusing to overwrite: ${bundlePath}`)
    }
    throw error
  }
  const policySnapshotBytes = await readPolicyBytes(policyPath)
  const scope = createProgramSealedScope({ ...rest, policySnapshotBytes })
  const scopeText = serialize(scope)
  await writeFile(join(bundlePath, 'scope.json'), scopeText, 'utf8')
  await writeFile(join(bundlePath, 'bundle.json'), serialize({
    kind: BUNDLE_KIND,
    schema_version: BUNDLE_SCHEMA_VERSION,
    engagement_id: scope.engagement_id,
    scope_sha256: digestPolicySnapshot(scopeText),
    created_at: scope.authorization.attested_at,
  }), 'utf8')
  return { bundlePath, scope }
}

async function readBundle(bundlePath) {
  const manifest = JSON.parse(await readFile(join(bundlePath, 'bundle.json'), 'utf8'))
  if (manifest.kind !== BUNDLE_KIND) {
    throw new Error(`not a bounty-v1 bundle: ${bundlePath}`)
  }
  const scopeText = await readFile(join(bundlePath, 'scope.json'), 'utf8')
  const observed = digestPolicySnapshot(scopeText)
  if (observed !== manifest.scope_sha256) {
    throw new Error(
      `sealed scope digest mismatch; bundle was modified after sealing (sealed ${manifest.scope_sha256}, observed ${observed})`,
    )
  }
  const scope = JSON.parse(scopeText)
  assertValidBountyScope(scope)
  return { manifest, scope }
}

export async function validateBountyBundle(bundlePath) {
  const { scope } = await readBundle(bundlePath)
  return { status: 'VALID', scope }
}

export async function revalidateBountyBundle(bundlePath, policyPath) {
  const { scope } = await readBundle(bundlePath)
  const observed = digestPolicySnapshot(await readPolicyBytes(policyPath))
  const sealed = scope.program.policy_snapshot_sha256
  return { status: observed === sealed ? 'UNCHANGED' : 'DRIFTED', sealed, observed }
}

export async function checkBountyScope(bundlePath, candidate) {
  const { scope } = await readBundle(bundlePath)
  return decideScope(scope, candidate)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/bounty-controller.test.mjs`
Expected: PASS, 6 tests

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/bounty-controller.mjs test/bounty-controller.test.mjs
git commit -m "feat(bounty-v1): bounty bundle controller with policy drift detection"
```

---

### Task 7: CLI entry point and npm wiring

**Files:**
- Create: `scripts/bounty.mjs`
- Modify: `package.json` — add `"audit:bounty": "node scripts/bounty.mjs"` to `scripts`, and append the seven new test files to `test:platform`
- Test: `test/bounty-cli.test.mjs`

**Interfaces:**
- Consumes: all four controller functions from Task 6; `isMainModule` from `scripts/lib/main-module.mjs`; `PLATFORM_VERSION` from `scripts/lib/run-engine.mjs`.
- Produces: `runBountyCli(argv: string[]) -> Promise<number>` (exit code). Exit 0 on success, 1 on invalid input or failed validation, 2 on a `DENY` scope check so shell callers can branch on it.

- [ ] **Step 1: Write the failing test**

Create `test/bounty-cli.test.mjs`:

```js
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { runBountyCli } from '../scripts/bounty.mjs'

async function workspace() {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-cli-'))
  const policyPath = join(dir, 'policy.txt')
  await writeFile(policyPath, 'ACME policy. Scope: *.acme.example\n', 'utf8')
  return { dir, policyPath }
}

function planArgv(dir, policyPath) {
  return [
    'plan',
    '--platform', 'yeswehack',
    '--program', 'acme-public',
    '--engagement-id', 'ywh-acme-2026-08',
    '--policy-url', 'https://yeswehack.com/programs/acme-public',
    '--policy-file', policyPath,
    '--operator-id', 'operator-1',
    '--authorized-by', 'ACME via YesWeHack program policy',
    '--allow', '*.acme.example',
    '--deny', 'legacy.acme.example',
    '--rate-limit-rps', '5',
    '--not-before', '2026-08-20T00:00:00.000Z',
    '--not-after', '2026-11-20T00:00:00.000Z',
    '--attest-enrolled',
    '--out', dir,
  ]
}

test('plan then validate then scope check via the cli', async () => {
  const { dir, policyPath } = await workspace()
  try {
    assert.equal(await runBountyCli(planArgv(dir, policyPath)), 0)
    const bundle = join(dir, 'ywh-acme-2026-08')
    assert.equal(await runBountyCli(['validate', bundle]), 0)
    assert.equal(await runBountyCli(['scope', bundle, '--check', 'https://www.acme.example/']), 0)
    assert.equal(await runBountyCli(['scope', bundle, '--check', 'https://evil.example/']), 2)
    assert.equal(await runBountyCli(['revalidate', bundle, '--policy-file', policyPath]), 0)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('plan without the attestation flag is refused', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const argv = planArgv(dir, policyPath).filter((token) => token !== '--attest-enrolled')
    assert.equal(await runBountyCli(argv), 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('seals ham intensity when active testing and automation are granted', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const argv = [
      ...planArgv(dir, policyPath),
      '--active-testing',
      '--automation',
      '--intensity', 'ham',
    ]
    assert.equal(await runBountyCli(argv), 0)
    const scope = JSON.parse(
      await readFile(join(dir, 'ywh-acme-2026-08', 'scope.json'), 'utf8'),
    )
    assert.equal(scope.authorization.permissions.intensity, 'ham')
    assert.equal(scope.authorization.permissions.automation_allowed, true)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('refuses ham intensity without automation', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const argv = [...planArgv(dir, policyPath), '--active-testing', '--intensity', 'ham']
    assert.equal(await runBountyCli(argv), 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('ham intensity does not widen the sealed perimeter', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const argv = [
      ...planArgv(dir, policyPath),
      '--active-testing',
      '--automation',
      '--intensity', 'ham',
    ]
    assert.equal(await runBountyCli(argv), 0)
    const bundle = join(dir, 'ywh-acme-2026-08')
    assert.equal(await runBountyCli(['scope', bundle, '--check', 'https://evil.example/']), 2)
    assert.equal(await runBountyCli(['scope', bundle, '--check', 'http://127.0.0.1/']), 2)
    assert.equal(await runBountyCli(['scope', bundle, '--check', 'https://legacy.acme.example/']), 2)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('an unknown command is refused', async () => {
  assert.equal(await runBountyCli(['definitely-not-a-command']), 1)
})

test('help exits zero', async () => {
  assert.equal(await runBountyCli(['--help']), 0)
})

test('revalidate exits nonzero on policy drift', async () => {
  const { dir, policyPath } = await workspace()
  try {
    await runBountyCli(planArgv(dir, policyPath))
    await writeFile(policyPath, 'ACME policy. Scope: acme.example only\n', 'utf8')
    const bundle = join(dir, 'ywh-acme-2026-08')
    assert.equal(await runBountyCli(['revalidate', bundle, '--policy-file', policyPath]), 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `node --test test/bounty-cli.test.mjs`
Expected: FAIL — `Cannot find module '../scripts/bounty.mjs'`

- [ ] **Step 3: Write minimal implementation**

Create `scripts/bounty.mjs`:

```js
#!/usr/bin/env node

import {
  checkBountyScope,
  planBountyBundle,
  revalidateBountyBundle,
  validateBountyBundle,
} from './lib/bounty-controller.mjs'
import { isMainModule } from './lib/main-module.mjs'
import { PLATFORM_VERSION } from './lib/run-engine.mjs'

const HELP = `red-team-audit bounty-v1 program perimeter ${PLATFORM_VERSION}

Usage:
  bounty plan --platform <yeswehack|hackerone|intigriti|direct> --program <handle> --engagement-id <id> --policy-url <https-url> --policy-file <snapshot> --operator-id <id> --authorized-by <text> --allow <spec> [--allow <spec>...] [--deny <spec>...] --rate-limit-rps <n> --not-before <iso8601> --not-after <iso8601> --attest-enrolled --out <parent> [--active-testing] [--mutation] [--automation] [--intensity <normal|aggressive|ham>] [--desync] [--non-production] [--json]
  bounty validate <bundle> [--json]
  bounty revalidate <bundle> --policy-file <fresh-snapshot> [--json]
  bounty scope <bundle> --check <url> [--json]

Scope rule specs:
  *.example.com         all subdomains, NOT the apex
  example.com           the apex only
  example.com:8443      apex on a sealed non-default port
  *.example.com/api     subdomains, path-scoped to /api
  203.0.113.7           an exact IP literal

Intensity (design spec section 20):
  normal      narrow and sampled; the daily driver
  aggressive  exhaustive within each bug class; requires --active-testing
  ham         every class in parallel, recursive to convergence, compound attacks,
              no early exit, auto-escalation on any anomaly; requires
              --active-testing and --automation
  --desync    request smuggling and desync probes; requires --intensity ham, and
              only where the program policy permits them, because desync can
              affect other users of the target

  Intensity changes how hard we hunt inside the sealed perimeter. It never moves
  the perimeter. There is no flag that widens scope_rules after sealing.

Boundary:
  Planning performs no network activity. bounty-v1 seals one bounty program
  perimeter from a policy snapshot digest. The authorization records the
  operator's declaration of program enrollment; it does not verify enrollment,
  asset ownership, scope currency, or revocation. Re-run revalidate before every
  session: programs narrow scope without notice, and a drifted policy means the
  sealed perimeter no longer matches the granted one.

  This protocol never produces repository coverage, an audit clearance, or an
  attestation. It never handles PHI.

Exit codes:
  0  command succeeded, or scope check returned ALLOW
  1  invalid input, failed validation, or policy drift
  2  scope check returned DENY
`

function parseArguments(values) {
  const positionals = []
  const options = {}
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index]
    if (!value.startsWith('--')) {
      positionals.push(value)
      continue
    }
    const name = value.slice(2)
    const next = values[index + 1]
    if (next === undefined || next.startsWith('--')) {
      options[name] = true
      continue
    }
    if (options[name] === undefined) {
      options[name] = next
    } else if (Array.isArray(options[name])) {
      options[name].push(next)
    } else {
      options[name] = [options[name], next]
    }
    index += 1
  }
  return { positionals, options }
}

function list(value) {
  if (value === undefined) return []
  return Array.isArray(value) ? value : [value]
}

function require(options, name) {
  const value = options[name]
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`--${name} is required`)
  }
  return value
}

function emit(payload, asJson) {
  process.stdout.write(asJson ? `${JSON.stringify(payload, null, 2)}\n` : `${payload.summary}\n`)
}

async function commandPlan(options) {
  if (options['attest-enrolled'] !== true) {
    throw new Error('--attest-enrolled is required; bounty-v1 will not seal an unattested perimeter')
  }
  const rateLimit = Number.parseInt(require(options, 'rate-limit-rps'), 10)
  if (!Number.isInteger(rateLimit) || rateLimit < 1) {
    throw new Error('--rate-limit-rps must be a positive integer')
  }
  const planned = await planBountyBundle({
    outParent: require(options, 'out'),
    policyPath: require(options, 'policy-file'),
    engagementId: require(options, 'engagement-id'),
    platform: require(options, 'platform'),
    programHandle: require(options, 'program'),
    policyUrl: require(options, 'policy-url'),
    operatorId: require(options, 'operator-id'),
    authorizedBy: require(options, 'authorized-by'),
    allowSpecs: list(options.allow),
    denySpecs: list(options.deny),
    permissions: {
      active_testing: options['active-testing'] === true,
      production: options['non-production'] !== true,
      third_party: false,
      mutation: options.mutation === true,
      automation_allowed: options.automation === true,
      intensity: typeof options.intensity === 'string' ? options.intensity : 'normal',
      desync_probes: options.desync === true,
      rate_limit_rps: rateLimit,
    },
    validity: {
      notBefore: require(options, 'not-before'),
      notAfter: require(options, 'not-after'),
    },
    now: new Date(),
  })
  emit({
    command: 'plan',
    bundle_path: planned.bundlePath,
    policy_snapshot_sha256: planned.scope.program.policy_snapshot_sha256,
    allow_rules: planned.scope.scope_rules.allow.length,
    deny_rules: planned.scope.scope_rules.deny.length,
    summary: `SEALED ${planned.bundlePath} (${planned.scope.scope_rules.allow.length} allow, ${planned.scope.scope_rules.deny.length} deny)`,
  }, options.json === true)
  return 0
}

export async function runBountyCli(argv) {
  const { positionals, options } = parseArguments(argv)
  const command = positionals[0]
  if (options.help === true || command === undefined) {
    process.stdout.write(HELP)
    return 0
  }
  try {
    if (command === 'plan') return await commandPlan(options)
    if (command === 'validate') {
      const result = await validateBountyBundle(positionals[1])
      emit({ command: 'validate', status: result.status, summary: `VALID ${positionals[1]}` }, options.json === true)
      return 0
    }
    if (command === 'revalidate') {
      const result = await revalidateBountyBundle(positionals[1], require(options, 'policy-file'))
      emit({
        command: 'revalidate',
        status: result.status,
        sealed: result.sealed,
        observed: result.observed,
        summary: `${result.status} sealed=${result.sealed} observed=${result.observed}`,
      }, options.json === true)
      return result.status === 'UNCHANGED' ? 0 : 1
    }
    if (command === 'scope') {
      const result = await checkBountyScope(positionals[1], require(options, 'check'))
      emit({
        command: 'scope',
        ...result,
        summary: `${result.decision} rule=${result.rule_id} reason=${result.reason}`,
      }, options.json === true)
      return result.decision === 'ALLOW' ? 0 : 2
    }
    process.stderr.write(`unknown command: ${command}\n\n${HELP}`)
    return 1
  } catch (error) {
    process.stderr.write(`bounty: ${error.message}\n`)
    return 1
  }
}

if (isMainModule(import.meta.url)) {
  process.exitCode = await runBountyCli(process.argv.slice(2))
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `node --test test/bounty-cli.test.mjs`
Expected: PASS, 8 tests

- [ ] **Step 5: Wire the npm scripts**

In `package.json`, add to `"scripts"`:

```json
"audit:bounty": "node scripts/bounty.mjs"
```

Append these seven files to the end of the existing `test:platform` value, space-separated:

```
test/bounty-target.test.mjs test/bounty-scope-kernel.test.mjs test/bounty-scope-kernel-adversarial.test.mjs test/bounty-contracts.test.mjs test/bounty-planner.test.mjs test/bounty-controller.test.mjs test/bounty-cli.test.mjs
```

- [ ] **Step 6: Run the full suite**

Run: `npm.cmd test`
Expected: PASS, all files including the seven new ones.

Then confirm the CLI is reachable through npm:

Run: `npm.cmd run audit:bounty -- --help`
Expected: exit 0, help text printed.

- [ ] **Step 7: Commit**

```bash
git add scripts/bounty.mjs test/bounty-cli.test.mjs package.json
git commit -m "feat(bounty-v1): audit:bounty controller cli"
```

---

## P0 Exit Gate

All must hold before P1 begins:

- [ ] `npm.cmd test` passes with all seven new test files wired into `test:platform`
- [ ] `fixtures/bounty/scope-kernel-cases.json` has ≥ 35 cases and every one passes
- [ ] `grep -nE "node:(fs|http|https|dns|child_process)|Date\.now|fetch\(" scripts/lib/bounty-scope-kernel.mjs scripts/lib/bounty-target.mjs` returns nothing
- [ ] No new entry in `package.json` `dependencies`
- [ ] `npm.cmd run audit:bounty -- --help` exits 0
- [ ] A tampered `scope.json` fails `validate`
- [ ] A changed policy file makes `revalidate` exit 1
- [ ] Sealing `--intensity ham` yields `scope_rules` byte-identical to `--intensity normal`, and every DENY candidate still denies. **Intensity must never move the perimeter** — this is the assertion that keeps HAM safe to run at full volume.
- [ ] `--intensity ham` is refused without both `--active-testing` and `--automation`
- [ ] `--desync` is refused at any intensity below `ham`

## Deferred to Later Phases

- ADR 0019 formalizing `bounty-v1` — write it at the end of P0 once the shape is proven, so the ADR describes what exists rather than what was planned.
- The Python-side scope kernel and its conformance run against `fixtures/bounty/scope-kernel-cases.json` — P2, with the Shiny proxy.
- Every network path. P0 contains none.
