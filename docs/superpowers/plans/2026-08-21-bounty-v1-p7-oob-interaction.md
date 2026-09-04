# bounty-v1 P7 — Out-of-Band Interaction Server Implementation Plan

> [!CAUTION]
> **SUPERSEDED SECURITY GUIDANCE (2026-09-03):** This document is retained as a
> historical implementation record, not as current operational guidance. Every
> public OOB action (`open`, `mint`, `poll`, `status`, and `close`) now fails
> closed before bundle/session I/O pending a trusted controller-owned local root
> and atomic backend/transport lease. The current bounty scope also seals
> `permissions.third_party: false`; a fixed hosted-server allowlist constrains
> destination selection but is not authorization for third-party transit. Do
> not use the historical commands below to re-enable OOB.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `bounty-v1` an out-of-band interaction channel so blind SSRF, blind XXE, blind RCE, OOB SQLi, and blind SSTI become observable, with two interchangeable backends: a hosted interactsh client that needs no infrastructure, and a self-hosted DNS + HTTP listener for when a domain and VPS exist.

**Architecture:** The valuable component is the correlator, not the listener. Every payload embeds a 13-character nonce inside its hostname; a callback carries that hostname back, and the correlator maps it to the exact request, insertion point, role, and bug class that minted it. Correlation and payload minting are pure functions with no IO, so they are exhaustively testable offline. The two backends sit behind one interface, and the interactsh crypto path is testable offline by constructing ciphertext locally.

**Tech Stack:** Node 24 ESM (`.mjs`), `node:crypto`, `node:dgram`, `node:http`, `node:test`. No new dependencies. No Go toolchain — the interactsh wire protocol is spoken directly over `fetch`.

**Spec:** `docs/superpowers/specs/2026-08-20-bounty-v1-design.md` (§17 and §20 name this phase; the OOB module was originally deferred as P7)

## Global Constraints

- **Zero new dependencies.** `acorn`, `ajv`, `yaml` remain the complete set.
- **Node 24 ESM**, `.mjs`, `node:` prefix on builtins, no semicolons, 2-space indent, single quotes, named exports prefixed `bountyOob`/`oob` per module concern.
- **Module layout:** `scripts/lib/bounty-oob-*.mjs`, tests `test/bounty-oob-*.test.mjs`, schemas `schemas/bounty-oob-*.schema.json`.
- **Purity boundary:** `bounty-oob-payload.mjs` and `bounty-oob-correlator.mjs` must not import `node:fs`, `node:http`, `node:https`, `node:dgram`, `node:dns`, or read the ambient clock. Randomness and timestamps are injected.
- **Historical network boundary — superseded for public hosted use.** The original module treated registration with `oast.fun` as contact with OOB infrastructure rather than the bounty target. Current guidance also accounts for target-derived callback data transiting that third party: public hosted `open`, `mint`, and `poll` must remain fail-closed until a trusted controller validates current scope and explicit third-party authority. Payloads sent to targets still require the target phase's own authorization gate.
- **Case-insensitive matching.** DNS is case-insensitive and resolvers may randomize case (0x20 encoding). Every hostname comparison lowercases first.
- **Historical `third_party` decision — superseded.** The 2026-08-21 implementation recorded hosted transit without gating it. That is no longer valid operational guidance: `permissions.third_party` is authorization, not telemetry, and the current scope seals it to `false`. A hostname appearing in the fixed hosted-server allowlist does not grant that authority.
- **Never claim clearance.** An absent callback is `NO_INTERACTION_OBSERVED`, never proof the target is not vulnerable. A blind-vector test that produced no callback is inconclusive, not negative.

## Verified protocol facts

Established empirically against `oast.fun` on 2026-08-21. Do not "correct" these from memory; they were wrong from memory once already.

| Element | Verified behavior |
|---|---|
| Register | `POST https://<server>/register`, JSON `{"public-key": <base64 of SPKI PEM>, "secret-key": <uuid>, "correlation-id": <20 lowercase alnum>}` → `200 {"message":"registration successful"}` |
| Payload host | `<correlation-id (20)><nonce (13)>.<server>` — a 33-character label |
| Poll | `GET https://<server>/poll?id=<correlation-id>&secret=<uuid>` → `{"data": [base64...], "aes_key": base64, "extra": null}` |
| AES key unwrap | RSA-OAEP with `oaepHash: 'sha256'` over `aes_key` → 32-byte key |
| Interaction cipher | **`aes-256-ctr`**, IV is the first 16 bytes of each decoded `data` item, ciphertext is the remainder. Not CFB — CFB, OFB and CTR share an identical first block, which masks the error for exactly 16 bytes. |
| Record fields | `protocol` (`dns`/`http`/`smtp`/…), `unique-id`, `full-id`, `q-type` (dns only), `raw-request`, `raw-response`, `remote-address`, `timestamp` (RFC3339 with nanoseconds) |
| Deregister | `POST https://<server>/deregister`, JSON `{"correlation-id", "secret-key"}` |
| Poll semantics | Polling drains; interactions are returned once. The session must persist what it has already seen. |

Historical protocol endpoints, now retained only as a fixed destination allowlist
inside the disabled hosted transport: `oast.fun`, `oast.pro`, `oast.site`,
`oast.live`, `oast.online`, `oast.me`. Membership limits where the transport could
connect; it does not authorize hosted OOB use.

---

## File Structure

| File | Responsibility |
|---|---|
| `scripts/lib/bounty-oob-payload.mjs` | Mint correlation ids, nonces, and payload hosts. Maintain the mint ledger. Pure. |
| `scripts/lib/bounty-oob-correlator.mjs` | Normalize a raw interaction, then map it to a ledger entry. Pure. |
| `scripts/lib/bounty-oob-crypto.mjs` | interactsh key generation, register-body construction, AES key unwrap, interaction decryption. Pure — no network. |
| `scripts/lib/bounty-oob-hosted.mjs` | interactsh HTTP transport: register, poll, deregister. Network. |
| `scripts/lib/bounty-oob-dns.mjs` | DNS wire parse/serialize (pure) plus a `node:dgram` listener. |
| `scripts/lib/bounty-oob-http.mjs` | Self-hosted HTTP capture listener plus host-header extraction (pure). |
| `scripts/lib/bounty-oob-backend.mjs` | The backend interface and selection between hosted and self-hosted. |
| `scripts/lib/bounty-oob-contracts.mjs` | Ajv validation for the session and interaction schemas. |
| `scripts/lib/bounty-oob-controller.mjs` | Session persistence in the bundle; register/mint/poll/status/deregister commands. |
| `schemas/bounty-oob-session.schema.json` | Sealed OOB session: backend, server, correlation id, ledger. |
| `schemas/bounty-oob-interaction.schema.json` | Canonical normalized interaction record. |

Crypto is split from transport (`-crypto` vs `-hosted`) specifically so the entire decryption path is unit-testable with no network at all.

---

### Task 1: Payload minting and the mint ledger

**Files:**
- Create: `scripts/lib/bounty-oob-payload.mjs`
- Test: `test/bounty-oob-payload.test.mjs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `CORRELATION_ID_LENGTH = 20`, `NONCE_LENGTH = 13`, `OOB_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789'`
  - `createCorrelationId(randomBytes) -> string` — 20 chars from the alphabet
  - `mintNonce(randomBytes) -> string` — 13 chars
  - `buildPayloadHost({ correlationId, nonce, server }) -> string` — lowercase `<cid><nonce>.<server>`
  - `extractNonce({ host, correlationId, server }) -> string | null` — case-insensitive; returns null when the label does not carry this correlation id or the server does not match
  - `createMintLedger() -> ledger` and `recordMint(ledger, { nonce, label, requestId, insertionPoint, role, bugClass, mintedAt }) -> ledger` and `lookupMint(ledger, nonce) -> entry | null`
  - `randomBytes` is injected as `(n) => Buffer` so tests are deterministic.

- [x] **Step 1: Write the failing test**

```js
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  buildPayloadHost,
  createCorrelationId,
  createMintLedger,
  extractNonce,
  lookupMint,
  mintNonce,
  recordMint,
} from '../scripts/lib/bounty-oob-payload.mjs'

// deterministic byte source: 0,1,2,3... so index selection is predictable
const seq = (n) => Buffer.from(Array.from({ length: n }, (_, i) => i))

test('correlation ids and nonces have the interactsh lengths and alphabet', () => {
  const cid = createCorrelationId(seq)
  const nonce = mintNonce(seq)
  assert.equal(cid.length, 20)
  assert.equal(nonce.length, 13)
  assert.match(cid, /^[a-z0-9]{20}$/)
  assert.match(nonce, /^[a-z0-9]{13}$/)
})

test('builds a lowercase 33 character label plus the server', () => {
  const host = buildPayloadHost({ correlationId: 'c'.repeat(20), nonce: 'n'.repeat(13), server: 'oast.fun' })
  assert.equal(host, `${'c'.repeat(20)}${'n'.repeat(13)}.oast.fun`)
  assert.equal(host.split('.')[0].length, 33)
})

test('rejects a correlation id or nonce of the wrong length', () => {
  assert.throws(() => buildPayloadHost({ correlationId: 'short', nonce: 'n'.repeat(13), server: 'oast.fun' }), /correlation/)
  assert.throws(() => buildPayloadHost({ correlationId: 'c'.repeat(20), nonce: 'short', server: 'oast.fun' }), /nonce/)
})

test('extracts the nonce back out of a callback host', () => {
  const correlationId = 'c'.repeat(20)
  const host = buildPayloadHost({ correlationId, nonce: 'abcdefghijklm', server: 'oast.fun' })
  assert.equal(extractNonce({ host, correlationId, server: 'oast.fun' }), 'abcdefghijklm')
})

test('extraction is case insensitive because resolvers randomize case', () => {
  const correlationId = 'c'.repeat(20)
  const host = `${'C'.repeat(20)}ABCDEFGHIJKLM.OAST.FUN`
  assert.equal(extractNonce({ host, correlationId, server: 'oast.fun' }), 'abcdefghijklm')
})

test('extraction tolerates a trailing dot and deeper labels', () => {
  const correlationId = 'c'.repeat(20)
  assert.equal(
    extractNonce({ host: `${'c'.repeat(20)}abcdefghijklm.oast.fun.`, correlationId, server: 'oast.fun' }),
    'abcdefghijklm',
  )
  assert.equal(
    extractNonce({ host: `x.y.${'c'.repeat(20)}abcdefghijklm.oast.fun`, correlationId, server: 'oast.fun' }),
    'abcdefghijklm',
  )
})

test('extraction refuses a foreign correlation id or server', () => {
  const correlationId = 'c'.repeat(20)
  const host = buildPayloadHost({ correlationId: 'd'.repeat(20), nonce: 'abcdefghijklm', server: 'oast.fun' })
  assert.equal(extractNonce({ host, correlationId, server: 'oast.fun' }), null)
  const ours = buildPayloadHost({ correlationId, nonce: 'abcdefghijklm', server: 'oast.fun' })
  assert.equal(extractNonce({ host: ours, correlationId, server: 'evil.example' }), null)
})

test('extraction refuses a malformed label length', () => {
  const correlationId = 'c'.repeat(20)
  assert.equal(extractNonce({ host: `${'c'.repeat(20)}short.oast.fun`, correlationId, server: 'oast.fun' }), null)
  assert.equal(extractNonce({ host: 'oast.fun', correlationId, server: 'oast.fun' }), null)
  assert.equal(extractNonce({ host: '', correlationId, server: 'oast.fun' }), null)
  assert.equal(extractNonce({ host: null, correlationId, server: 'oast.fun' }), null)
})

test('the ledger records and retrieves mint provenance', () => {
  let ledger = createMintLedger()
  ledger = recordMint(ledger, {
    nonce: 'abcdefghijklm',
    label: 'checkout-callback-url',
    requestId: 'flow-42',
    insertionPoint: 'body:json:/order/callbackUrl',
    role: 'customer',
    bugClass: 'ssrf',
    mintedAt: '2026-08-21T10:00:00.000Z',
  })
  const entry = lookupMint(ledger, 'abcdefghijklm')
  assert.equal(entry.requestId, 'flow-42')
  assert.equal(entry.insertionPoint, 'body:json:/order/callbackUrl')
  assert.equal(entry.bugClass, 'ssrf')
  assert.equal(lookupMint(ledger, 'nnnnnnnnnnnnn'), null)
})

test('the ledger refuses a duplicate nonce', () => {
  let ledger = createMintLedger()
  const mint = {
    nonce: 'abcdefghijklm',
    label: 'a',
    requestId: 'r',
    insertionPoint: 'p',
    role: 'x',
    bugClass: 'ssrf',
    mintedAt: '2026-08-21T10:00:00.000Z',
  }
  ledger = recordMint(ledger, mint)
  assert.throws(() => recordMint(ledger, mint), /already/)
})

test('ledger lookup is case insensitive', () => {
  let ledger = createMintLedger()
  ledger = recordMint(ledger, {
    nonce: 'abcdefghijklm', label: 'a', requestId: 'r', insertionPoint: 'p',
    role: 'x', bugClass: 'ssrf', mintedAt: '2026-08-21T10:00:00.000Z',
  })
  assert.equal(lookupMint(ledger, 'ABCDEFGHIJKLM').requestId, 'r')
})
```

- [x] **Step 2: Run test to verify it fails**

Run: `node --test test/bounty-oob-payload.test.mjs`
Expected: FAIL — `Cannot find module '../scripts/lib/bounty-oob-payload.mjs'`

- [x] **Step 3: Write minimal implementation**

```js
export const OOB_ALPHABET = 'abcdefghijklmnopqrstuvwxyz0123456789'
export const CORRELATION_ID_LENGTH = 20
export const NONCE_LENGTH = 13

function pick(randomBytes, length) {
  const bytes = randomBytes(length)
  let out = ''
  for (let index = 0; index < length; index += 1) {
    out += OOB_ALPHABET[bytes[index] % OOB_ALPHABET.length]
  }
  return out
}

export function createCorrelationId(randomBytes) {
  return pick(randomBytes, CORRELATION_ID_LENGTH)
}

export function mintNonce(randomBytes) {
  return pick(randomBytes, NONCE_LENGTH)
}

export function buildPayloadHost({ correlationId, nonce, server }) {
  if (typeof correlationId !== 'string' || correlationId.length !== CORRELATION_ID_LENGTH) {
    throw new Error(`correlation id must be ${CORRELATION_ID_LENGTH} characters`)
  }
  if (typeof nonce !== 'string' || nonce.length !== NONCE_LENGTH) {
    throw new Error(`nonce must be ${NONCE_LENGTH} characters`)
  }
  if (typeof server !== 'string' || server.length === 0) {
    throw new Error('server is required')
  }
  return `${correlationId}${nonce}.${server}`.toLowerCase()
}

export function extractNonce({ host, correlationId, server }) {
  if (typeof host !== 'string' || host.length === 0) return null
  if (typeof correlationId !== 'string' || typeof server !== 'string') return null
  let normalized = host.toLowerCase()
  if (normalized.endsWith('.')) normalized = normalized.slice(0, -1)
  const suffix = `.${server.toLowerCase()}`
  if (!normalized.endsWith(suffix)) return null
  const labels = normalized.slice(0, -suffix.length).split('.')
  const candidate = labels[labels.length - 1]
  if (candidate === undefined) return null
  if (candidate.length !== CORRELATION_ID_LENGTH + NONCE_LENGTH) return null
  if (!candidate.startsWith(correlationId.toLowerCase())) return null
  return candidate.slice(CORRELATION_ID_LENGTH)
}

export function createMintLedger() {
  return { schema_version: '1.0.0', mints: {} }
}

export function recordMint(ledger, mint) {
  const nonce = String(mint.nonce).toLowerCase()
  if (nonce.length !== NONCE_LENGTH) {
    throw new Error(`nonce must be ${NONCE_LENGTH} characters`)
  }
  if (Object.hasOwn(ledger.mints, nonce)) {
    throw new Error(`nonce already minted: ${nonce}`)
  }
  return {
    ...ledger,
    mints: {
      ...ledger.mints,
      [nonce]: {
        nonce,
        label: mint.label,
        requestId: mint.requestId,
        insertionPoint: mint.insertionPoint,
        role: mint.role,
        bugClass: mint.bugClass,
        mintedAt: mint.mintedAt,
      },
    },
  }
}

export function lookupMint(ledger, nonce) {
  if (typeof nonce !== 'string') return null
  return ledger.mints[nonce.toLowerCase()] ?? null
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `node --test test/bounty-oob-payload.test.mjs`
Expected: PASS, 10 tests

- [x] **Step 5: Verify purity**

Run: `grep -nE "node:(fs|http|https|dns|dgram|crypto)|Date\.now|fetch\(" scripts/lib/bounty-oob-payload.mjs`
Expected: no output.

- [x] **Step 6: Commit**

```bash
git add scripts/lib/bounty-oob-payload.mjs test/bounty-oob-payload.test.mjs
git commit -m "feat(bounty-v1): mint correlated OOB payload hosts with a provenance ledger"
```

---

### Task 2: Interaction normalization and correlation

**Files:**
- Create: `scripts/lib/bounty-oob-correlator.mjs`
- Test: `test/bounty-oob-correlator.test.mjs`

**Interfaces:**
- Consumes: `extractNonce`, `lookupMint` from Task 1.
- Produces:
  - `normalizeInteraction(raw) -> { protocol, fullId, qType, remoteAddress, observedAt, rawRequest, rawResponse }` — throws on a missing `protocol` or `full-id`
  - `correlateInteraction({ ledger, correlationId, server, interaction }) -> { matched: true, nonce, mint, interaction } | { matched: false, reason, interaction }`
  - `summarizeCorrelation(results) -> { total, matched, unmatched, byBugClass }`
  - Unmatched reasons: `host-not-ours`, `nonce-not-in-ledger`.

- [x] **Step 1: Write the failing test**

```js
import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  correlateInteraction,
  normalizeInteraction,
  summarizeCorrelation,
} from '../scripts/lib/bounty-oob-correlator.mjs'
import { createMintLedger, recordMint } from '../scripts/lib/bounty-oob-payload.mjs'

const CID = 'c'.repeat(20)
const NONCE = 'abcdefghijklm'
const SERVER = 'oast.fun'

function ledgerWithMint() {
  return recordMint(createMintLedger(), {
    nonce: NONCE,
    label: 'checkout-callback-url',
    requestId: 'flow-42',
    insertionPoint: 'body:json:/order/callbackUrl',
    role: 'customer',
    bugClass: 'ssrf',
    mintedAt: '2026-08-21T10:00:00.000Z',
  })
}

function dnsRaw(host = `${CID}${NONCE}.${SERVER}`) {
  return {
    protocol: 'dns',
    'unique-id': host.split('.')[0],
    'full-id': host,
    'q-type': 'A',
    'raw-request': ';; opcode: QUERY',
    'raw-response': ';; opcode: QUERY, status: NOERROR',
    'remote-address': '194.65.39.214',
    timestamp: '2026-08-21T10:05:00.123456789Z',
  }
}

test('normalizes a dns interaction into the canonical shape', () => {
  const record = normalizeInteraction(dnsRaw())
  assert.equal(record.protocol, 'dns')
  assert.equal(record.fullId, `${CID}${NONCE}.${SERVER}`)
  assert.equal(record.qType, 'A')
  assert.equal(record.remoteAddress, '194.65.39.214')
  assert.equal(record.observedAt, '2026-08-21T10:05:00.123456789Z')
})

test('normalizes an http interaction with no q-type', () => {
  const record = normalizeInteraction({
    protocol: 'http',
    'full-id': `${CID}${NONCE}.${SERVER}`,
    'raw-request': 'GET /hit?x=1 HTTP/1.1\r\nHost: x\r\n\r\n',
    'remote-address': '203.0.113.9',
    timestamp: '2026-08-21T10:06:00Z',
  })
  assert.equal(record.protocol, 'http')
  assert.equal(record.qType, null)
  assert.match(record.rawRequest, /^GET \/hit/)
})

test('refuses an interaction missing protocol or full-id', () => {
  assert.throws(() => normalizeInteraction({ 'full-id': 'x' }), /protocol/)
  assert.throws(() => normalizeInteraction({ protocol: 'dns' }), /full-id/)
})

test('correlates a callback back to the minting request', () => {
  const result = correlateInteraction({
    ledger: ledgerWithMint(),
    correlationId: CID,
    server: SERVER,
    interaction: normalizeInteraction(dnsRaw()),
  })
  assert.equal(result.matched, true)
  assert.equal(result.nonce, NONCE)
  assert.equal(result.mint.requestId, 'flow-42')
  assert.equal(result.mint.insertionPoint, 'body:json:/order/callbackUrl')
  assert.equal(result.mint.bugClass, 'ssrf')
})

test('correlates despite resolver case randomization', () => {
  const shouty = dnsRaw(`${CID}${NONCE}.${SERVER}`.toUpperCase())
  const result = correlateInteraction({
    ledger: ledgerWithMint(), correlationId: CID, server: SERVER,
    interaction: normalizeInteraction(shouty),
  })
  assert.equal(result.matched, true)
  assert.equal(result.nonce, NONCE)
})

test('reports a foreign host as not ours', () => {
  const result = correlateInteraction({
    ledger: ledgerWithMint(), correlationId: CID, server: SERVER,
    interaction: normalizeInteraction(dnsRaw('somebody.else.example')),
  })
  assert.equal(result.matched, false)
  assert.equal(result.reason, 'host-not-ours')
})

test('reports a well formed host whose nonce was never minted', () => {
  const result = correlateInteraction({
    ledger: createMintLedger(), correlationId: CID, server: SERVER,
    interaction: normalizeInteraction(dnsRaw()),
  })
  assert.equal(result.matched, false)
  assert.equal(result.reason, 'nonce-not-in-ledger')
})

test('summarizes a batch by bug class', () => {
  const ledger = ledgerWithMint()
  const results = [
    correlateInteraction({ ledger, correlationId: CID, server: SERVER, interaction: normalizeInteraction(dnsRaw()) }),
    correlateInteraction({ ledger, correlationId: CID, server: SERVER, interaction: normalizeInteraction(dnsRaw()) }),
    correlateInteraction({ ledger, correlationId: CID, server: SERVER, interaction: normalizeInteraction(dnsRaw('nope.example')) }),
  ]
  const summary = summarizeCorrelation(results)
  assert.equal(summary.total, 3)
  assert.equal(summary.matched, 2)
  assert.equal(summary.unmatched, 1)
  assert.equal(summary.byBugClass.ssrf, 2)
})
```

- [x] **Step 2: Run test to verify it fails**

Run: `node --test test/bounty-oob-correlator.test.mjs`
Expected: FAIL — module not found.

- [x] **Step 3: Write minimal implementation**

```js
import { extractNonce, lookupMint } from './bounty-oob-payload.mjs'

export function normalizeInteraction(raw) {
  if (raw === null || typeof raw !== 'object') {
    throw new Error('interaction must be an object')
  }
  const protocol = raw.protocol
  if (typeof protocol !== 'string' || protocol.length === 0) {
    throw new Error('interaction is missing protocol')
  }
  const fullId = raw['full-id'] ?? raw['unique-id']
  if (typeof fullId !== 'string' || fullId.length === 0) {
    throw new Error('interaction is missing full-id')
  }
  return {
    protocol,
    fullId,
    qType: typeof raw['q-type'] === 'string' ? raw['q-type'] : null,
    remoteAddress: typeof raw['remote-address'] === 'string' ? raw['remote-address'] : null,
    observedAt: typeof raw.timestamp === 'string' ? raw.timestamp : null,
    rawRequest: typeof raw['raw-request'] === 'string' ? raw['raw-request'] : null,
    rawResponse: typeof raw['raw-response'] === 'string' ? raw['raw-response'] : null,
  }
}

export function correlateInteraction({ ledger, correlationId, server, interaction }) {
  const nonce = extractNonce({ host: interaction.fullId, correlationId, server })
  if (nonce === null) {
    return { matched: false, reason: 'host-not-ours', interaction }
  }
  const mint = lookupMint(ledger, nonce)
  if (mint === null) {
    return { matched: false, reason: 'nonce-not-in-ledger', interaction }
  }
  return { matched: true, nonce, mint, interaction }
}

export function summarizeCorrelation(results) {
  const byBugClass = {}
  let matched = 0
  for (const result of results) {
    if (!result.matched) continue
    matched += 1
    const bugClass = result.mint.bugClass ?? 'unknown'
    byBugClass[bugClass] = (byBugClass[bugClass] ?? 0) + 1
  }
  return { total: results.length, matched, unmatched: results.length - matched, byBugClass }
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `node --test test/bounty-oob-correlator.test.mjs`
Expected: PASS, 8 tests

- [x] **Step 5: Commit**

```bash
git add scripts/lib/bounty-oob-correlator.mjs test/bounty-oob-correlator.test.mjs
git commit -m "feat(bounty-v1): correlate OOB callbacks to the request that minted them"
```

---

### Task 3: interactsh crypto, offline-testable

**Files:**
- Create: `scripts/lib/bounty-oob-crypto.mjs`
- Test: `test/bounty-oob-crypto.test.mjs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `generateSessionKeypair() -> { publicKey, privateKey, publicKeyBase64 }` (base64 of the SPKI PEM, which is what the server expects)
  - `buildRegisterBody({ publicKeyBase64, secret, correlationId }) -> string` (JSON)
  - `unwrapAesKey({ privateKey, aesKeyBase64 }) -> Buffer` — RSA-OAEP sha256
  - `decryptInteraction({ aesKey, dataBase64 }) -> object` — `aes-256-ctr`, IV is the leading 16 bytes
  - `sealInteractionForTest({ aesKey, interaction, iv }) -> string` — test-only inverse so the decrypt path is exercised without network
  - `INTERACTSH_CIPHER = 'aes-256-ctr'`, `INTERACTSH_IV_LENGTH = 16`, `INTERACTSH_OAEP_HASH = 'sha256'`

- [x] **Step 1: Write the failing test**

```js
import assert from 'node:assert/strict'
import { constants, publicEncrypt, randomBytes } from 'node:crypto'
import { test } from 'node:test'
import {
  INTERACTSH_CIPHER,
  buildRegisterBody,
  decryptInteraction,
  generateSessionKeypair,
  sealInteractionForTest,
  unwrapAesKey,
} from '../scripts/lib/bounty-oob-crypto.mjs'

test('the cipher is aes-256-ctr, not cfb', () => {
  assert.equal(INTERACTSH_CIPHER, 'aes-256-ctr')
})

test('generates a keypair whose public half is base64 of an SPKI PEM', () => {
  const keys = generateSessionKeypair()
  const pem = Buffer.from(keys.publicKeyBase64, 'base64').toString('utf8')
  assert.match(pem, /^-----BEGIN PUBLIC KEY-----/)
})

test('builds the register body with the exact server field names', () => {
  const body = JSON.parse(buildRegisterBody({
    publicKeyBase64: 'UEs=', secret: 'sec', correlationId: 'c'.repeat(20),
  }))
  assert.deepEqual(Object.keys(body).sort(), ['correlation-id', 'public-key', 'secret-key'])
  assert.equal(body['correlation-id'], 'c'.repeat(20))
})

test('unwraps an RSA-OAEP sha256 wrapped aes key', () => {
  const keys = generateSessionKeypair()
  const aesKey = randomBytes(32)
  const wrapped = publicEncrypt(
    { key: keys.publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    aesKey,
  )
  const out = unwrapAesKey({ privateKey: keys.privateKey, aesKeyBase64: wrapped.toString('base64') })
  assert.equal(out.length, 32)
  assert.equal(Buffer.compare(out, aesKey), 0)
})

test('round trips an interaction through the real cipher', () => {
  const aesKey = randomBytes(32)
  const interaction = { protocol: 'dns', 'full-id': 'x'.repeat(33) + '.oast.fun', 'q-type': 'A' }
  const sealed = sealInteractionForTest({ aesKey, interaction, iv: randomBytes(16) })
  assert.deepEqual(decryptInteraction({ aesKey, dataBase64: sealed }), interaction)
})

test('decrypting with the wrong key does not yield the plaintext', () => {
  const aesKey = randomBytes(32)
  const sealed = sealInteractionForTest({ aesKey, interaction: { protocol: 'dns', 'full-id': 'a' }, iv: randomBytes(16) })
  assert.throws(() => decryptInteraction({ aesKey: randomBytes(32), dataBase64: sealed }))
})

test('refuses a payload too short to carry an iv', () => {
  assert.throws(
    () => decryptInteraction({ aesKey: randomBytes(32), dataBase64: Buffer.alloc(8).toString('base64') }),
    /too short/,
  )
})
```

- [x] **Step 2: Run test to verify it fails**

Run: `node --test test/bounty-oob-crypto.test.mjs`
Expected: FAIL — module not found.

- [x] **Step 3: Write minimal implementation**

```js
import {
  constants,
  createCipheriv,
  createDecipheriv,
  generateKeyPairSync,
  privateDecrypt,
} from 'node:crypto'

export const INTERACTSH_CIPHER = 'aes-256-ctr'
export const INTERACTSH_IV_LENGTH = 16
export const INTERACTSH_OAEP_HASH = 'sha256'

export function generateSessionKeypair() {
  const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 })
  const pem = publicKey.export({ type: 'spki', format: 'pem' })
  return { publicKey, privateKey, publicKeyBase64: Buffer.from(pem).toString('base64') }
}

export function buildRegisterBody({ publicKeyBase64, secret, correlationId }) {
  return JSON.stringify({
    'public-key': publicKeyBase64,
    'secret-key': secret,
    'correlation-id': correlationId,
  })
}

export function unwrapAesKey({ privateKey, aesKeyBase64 }) {
  return privateDecrypt(
    { key: privateKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: INTERACTSH_OAEP_HASH },
    Buffer.from(aesKeyBase64, 'base64'),
  )
}

export function decryptInteraction({ aesKey, dataBase64 }) {
  const raw = Buffer.from(dataBase64, 'base64')
  if (raw.length <= INTERACTSH_IV_LENGTH) {
    throw new Error('interaction payload too short to carry an iv')
  }
  const decipher = createDecipheriv(INTERACTSH_CIPHER, aesKey, raw.subarray(0, INTERACTSH_IV_LENGTH))
  const plain = Buffer.concat([
    decipher.update(raw.subarray(INTERACTSH_IV_LENGTH)),
    decipher.final(),
  ]).toString('utf8')
  return JSON.parse(plain)
}

export function sealInteractionForTest({ aesKey, interaction, iv }) {
  const cipher = createCipheriv(INTERACTSH_CIPHER, aesKey, iv)
  const body = Buffer.concat([
    cipher.update(Buffer.from(JSON.stringify(interaction), 'utf8')),
    cipher.final(),
  ])
  return Buffer.concat([iv, body]).toString('base64')
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `node --test test/bounty-oob-crypto.test.mjs`
Expected: PASS, 7 tests

- [x] **Step 5: Commit**

```bash
git add scripts/lib/bounty-oob-crypto.mjs test/bounty-oob-crypto.test.mjs
git commit -m "feat(bounty-v1): interactsh crypto with the verified aes-256-ctr payload cipher"
```

---

### Task 4: Hosted backend transport

**Files:**
- Create: `scripts/lib/bounty-oob-hosted.mjs`
- Test: `test/bounty-oob-hosted.test.mjs`

**Interfaces:**
- Consumes: everything from Task 3.
- Produces:
  - `HOSTED_SERVERS = ['oast.fun', 'oast.pro', 'oast.site', 'oast.live', 'oast.online', 'oast.me']`
  - `registerHostedSession({ server, correlationId, secret, publicKeyBase64, fetchImpl }) -> Promise<void>` — throws on non-2xx
  - `pollHostedSession({ server, correlationId, secret, privateKey, fetchImpl }) -> Promise<object[]>` — returns decrypted raw interaction objects, `[]` when the server reports none
  - `deregisterHostedSession({ server, correlationId, secret, fetchImpl }) -> Promise<void>`
  - `fetchImpl` defaults to global `fetch` and is injected in tests, so no test touches the network.

- [x] **Step 1: Write the failing test**

```js
import assert from 'node:assert/strict'
import { publicEncrypt, constants, randomBytes } from 'node:crypto'
import { test } from 'node:test'
import { generateSessionKeypair, sealInteractionForTest } from '../scripts/lib/bounty-oob-crypto.mjs'
import {
  HOSTED_SERVERS,
  deregisterHostedSession,
  pollHostedSession,
  registerHostedSession,
} from '../scripts/lib/bounty-oob-hosted.mjs'

const CID = 'c'.repeat(20)

function stubFetch(handler) {
  const calls = []
  const impl = async (url, init) => {
    calls.push({ url: String(url), init })
    return handler(String(url), init)
  }
  impl.calls = calls
  return impl
}

const ok = (body) => new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })

test('the documented public servers are present', () => {
  assert.ok(HOSTED_SERVERS.includes('oast.fun'))
})

test('register posts to /register and succeeds on 200', async () => {
  const fetchImpl = stubFetch(() => ok({ message: 'registration successful' }))
  await registerHostedSession({
    server: 'oast.fun', correlationId: CID, secret: 's', publicKeyBase64: 'UEs=', fetchImpl,
  })
  assert.match(fetchImpl.calls[0].url, /^https:\/\/oast\.fun\/register$/)
  assert.equal(fetchImpl.calls[0].init.method, 'POST')
  assert.equal(JSON.parse(fetchImpl.calls[0].init.body)['correlation-id'], CID)
})

test('register throws on a non-2xx response', async () => {
  const fetchImpl = stubFetch(() => new Response('nope', { status: 400 }))
  await assert.rejects(
    () => registerHostedSession({ server: 'oast.fun', correlationId: CID, secret: 's', publicKeyBase64: 'UEs=', fetchImpl }),
    /400/,
  )
})

test('poll decrypts every returned interaction', async () => {
  const keys = generateSessionKeypair()
  const aesKey = randomBytes(32)
  const wrapped = publicEncrypt(
    { key: keys.publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' },
    aesKey,
  ).toString('base64')
  const one = { protocol: 'dns', 'full-id': 'a'.repeat(33) + '.oast.fun', 'q-type': 'A' }
  const two = { protocol: 'http', 'full-id': 'b'.repeat(33) + '.oast.fun' }
  const fetchImpl = stubFetch(() => ok({
    aes_key: wrapped,
    data: [
      sealInteractionForTest({ aesKey, interaction: one, iv: randomBytes(16) }),
      sealInteractionForTest({ aesKey, interaction: two, iv: randomBytes(16) }),
    ],
  }))
  const out = await pollHostedSession({
    server: 'oast.fun', correlationId: CID, secret: 's', privateKey: keys.privateKey, fetchImpl,
  })
  assert.equal(out.length, 2)
  assert.equal(out[0].protocol, 'dns')
  assert.equal(out[1].protocol, 'http')
  assert.match(fetchImpl.calls[0].url, /\/poll\?id=c{20}&secret=s$/)
})

test('poll returns an empty list when the server reports no data', async () => {
  const fetchImpl = stubFetch(() => ok({ aes_key: null, data: null }))
  const out = await pollHostedSession({
    server: 'oast.fun', correlationId: CID, secret: 's', privateKey: generateSessionKeypair().privateKey, fetchImpl,
  })
  assert.deepEqual(out, [])
})

test('deregister posts the correlation id and secret', async () => {
  const fetchImpl = stubFetch(() => ok({ message: 'deregistration successful' }))
  await deregisterHostedSession({ server: 'oast.fun', correlationId: CID, secret: 's', fetchImpl })
  assert.match(fetchImpl.calls[0].url, /\/deregister$/)
  assert.equal(JSON.parse(fetchImpl.calls[0].init.body)['secret-key'], 's')
})
```

- [x] **Step 2: Run test to verify it fails**

Run: `node --test test/bounty-oob-hosted.test.mjs`
Expected: FAIL — module not found.

- [x] **Step 3: Write minimal implementation**

```js
import { buildRegisterBody, decryptInteraction, unwrapAesKey } from './bounty-oob-crypto.mjs'

export const HOSTED_SERVERS = [
  'oast.fun',
  'oast.pro',
  'oast.site',
  'oast.live',
  'oast.online',
  'oast.me',
]

const JSON_HEADERS = { 'Content-Type': 'application/json' }

async function requireOk(response, what) {
  if (response.ok) return response
  const body = await response.text().catch(() => '')
  throw new Error(`interactsh ${what} failed: HTTP ${response.status} ${body.slice(0, 200)}`)
}

export async function registerHostedSession({
  server,
  correlationId,
  secret,
  publicKeyBase64,
  fetchImpl = fetch,
}) {
  const response = await fetchImpl(`https://${server}/register`, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: buildRegisterBody({ publicKeyBase64, secret, correlationId }),
  })
  await requireOk(response, 'register')
}

export async function pollHostedSession({
  server,
  correlationId,
  secret,
  privateKey,
  fetchImpl = fetch,
}) {
  const response = await fetchImpl(
    `https://${server}/poll?id=${encodeURIComponent(correlationId)}&secret=${encodeURIComponent(secret)}`,
  )
  await requireOk(response, 'poll')
  const body = await response.json()
  if (!Array.isArray(body.data) || body.data.length === 0) return []
  if (typeof body.aes_key !== 'string') {
    throw new Error('interactsh poll returned data without an aes key')
  }
  const aesKey = unwrapAesKey({ privateKey, aesKeyBase64: body.aes_key })
  return body.data.map((dataBase64) => decryptInteraction({ aesKey, dataBase64 }))
}

export async function deregisterHostedSession({ server, correlationId, secret, fetchImpl = fetch }) {
  const response = await fetchImpl(`https://${server}/deregister`, {
    method: 'POST',
    headers: JSON_HEADERS,
    body: JSON.stringify({ 'correlation-id': correlationId, 'secret-key': secret }),
  })
  await requireOk(response, 'deregister')
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `node --test test/bounty-oob-hosted.test.mjs`
Expected: PASS, 6 tests

- [x] **Step 5: Commit**

```bash
git add scripts/lib/bounty-oob-hosted.mjs test/bounty-oob-hosted.test.mjs
git commit -m "feat(bounty-v1): hosted interactsh backend transport"
```

---

### Task 5: Self-hosted DNS wire format and listener

**Files:**
- Create: `scripts/lib/bounty-oob-dns.mjs`
- Test: `test/bounty-oob-dns.test.mjs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `parseDnsQuery(buffer) -> { id, name, qtype, qclass, questionEnd }` — throws on a malformed or non-query packet
  - `buildDnsResponse({ query, buffer, address, ttl }) -> Buffer` — echoes the question and answers A with `address`
  - `DNS_TYPE = { A: 1, NS: 2, CNAME: 5, AAAA: 28, TXT: 16 }`
  - `startDnsListener({ port, address, onQuery, dgramImpl }) -> Promise<{ port, close }>`
  - Name compression is not emitted; the question is echoed verbatim from the request bytes, which every resolver accepts.

- [x] **Step 1: Write the failing test**

```js
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { DNS_TYPE, buildDnsResponse, parseDnsQuery, startDnsListener } from '../scripts/lib/bounty-oob-dns.mjs'
import { createSocket } from 'node:dgram'

// Hand-built A query for "abc.example" — 12 byte header, then labels, then qtype/qclass
function queryFor(name, qtype = DNS_TYPE.A) {
  const labels = name.split('.').map((label) => {
    const out = Buffer.alloc(1 + label.length)
    out.writeUInt8(label.length, 0)
    out.write(label, 1, 'ascii')
    return out
  })
  const header = Buffer.alloc(12)
  header.writeUInt16BE(0x1234, 0)
  header.writeUInt16BE(0x0100, 2)
  header.writeUInt16BE(1, 4)
  const tail = Buffer.alloc(5)
  tail.writeUInt8(0, 0)
  tail.writeUInt16BE(qtype, 1)
  tail.writeUInt16BE(1, 3)
  return Buffer.concat([header, ...labels, tail])
}

test('parses a well formed A query', () => {
  const parsed = parseDnsQuery(queryFor('abc.example'))
  assert.equal(parsed.id, 0x1234)
  assert.equal(parsed.name, 'abc.example')
  assert.equal(parsed.qtype, DNS_TYPE.A)
})

test('parses a 33 character interactsh style label', () => {
  const host = `${'c'.repeat(20)}${'n'.repeat(13)}.oob.example`
  assert.equal(parseDnsQuery(queryFor(host)).name, host)
})

test('parses an AAAA query type', () => {
  assert.equal(parseDnsQuery(queryFor('x.example', DNS_TYPE.AAAA)).qtype, DNS_TYPE.AAAA)
})

test('refuses a truncated packet', () => {
  assert.throws(() => parseDnsQuery(Buffer.alloc(4)), /too short/)
})

test('refuses a packet with no question', () => {
  const header = Buffer.alloc(12)
  header.writeUInt16BE(0, 4)
  assert.throws(() => parseDnsQuery(header), /question/)
})

test('refuses a label length that runs past the packet', () => {
  const bad = Buffer.concat([queryFor('abc.example').subarray(0, 12), Buffer.from([0x40, 0x61])])
  assert.throws(() => parseDnsQuery(bad), /malformed/)
})

test('builds a response that echoes the id and question and answers A', () => {
  const buffer = queryFor('abc.example')
  const query = parseDnsQuery(buffer)
  const response = buildDnsResponse({ query, buffer, address: '203.0.113.7', ttl: 60 })
  assert.equal(response.readUInt16BE(0), 0x1234)
  assert.equal((response.readUInt16BE(2) & 0x8000) !== 0, true, 'QR bit set')
  assert.equal(response.readUInt16BE(4), 1, 'QDCOUNT echoed')
  assert.equal(response.readUInt16BE(6), 1, 'ANCOUNT is 1')
  const rdata = response.subarray(response.length - 4)
  assert.deepEqual([...rdata], [203, 0, 113, 7])
})

test('answers with zero records for a non-A query but still responds', () => {
  const buffer = queryFor('abc.example', DNS_TYPE.AAAA)
  const query = parseDnsQuery(buffer)
  const response = buildDnsResponse({ query, buffer, address: '203.0.113.7', ttl: 60 })
  assert.equal(response.readUInt16BE(6), 0, 'ANCOUNT is 0 for AAAA')
})

test('the listener captures a real query over loopback udp', async () => {
  const seen = []
  const listener = await startDnsListener({
    port: 0,
    address: '127.0.0.1',
    onQuery: (event) => { seen.push(event) },
  })
  const client = createSocket('udp4')
  const host = `${'c'.repeat(20)}${'n'.repeat(13)}.oob.example`
  await new Promise((resolve, reject) => {
    client.send(queryFor(host), listener.port, '127.0.0.1', (error) => (error ? reject(error) : resolve()))
  })
  await new Promise((resolve) => { client.once('message', resolve) })
  client.close()
  await listener.close()
  assert.equal(seen.length, 1)
  assert.equal(seen[0].name, host)
  assert.equal(seen[0].protocol, 'dns')
  assert.equal(seen[0].qType, 'A')
})
```

- [x] **Step 2: Run test to verify it fails**

Run: `node --test test/bounty-oob-dns.test.mjs`
Expected: FAIL — module not found.

- [x] **Step 3: Write minimal implementation**

```js
import { createSocket } from 'node:dgram'

export const DNS_TYPE = { A: 1, NS: 2, CNAME: 5, TXT: 16, AAAA: 28 }

const TYPE_NAME = new Map(Object.entries(DNS_TYPE).map(([name, value]) => [value, name]))

const HEADER_LENGTH = 12

export function parseDnsQuery(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length < HEADER_LENGTH) {
    throw new Error('dns packet too short')
  }
  const id = buffer.readUInt16BE(0)
  const qdcount = buffer.readUInt16BE(4)
  if (qdcount < 1) {
    throw new Error('dns packet carries no question')
  }
  const labels = []
  let offset = HEADER_LENGTH
  for (;;) {
    if (offset >= buffer.length) throw new Error('malformed dns name: ran past packet')
    const length = buffer.readUInt8(offset)
    if (length === 0) {
      offset += 1
      break
    }
    if ((length & 0xc0) !== 0) throw new Error('malformed dns name: compression in question')
    if (offset + 1 + length > buffer.length) throw new Error('malformed dns name: label overruns packet')
    labels.push(buffer.toString('ascii', offset + 1, offset + 1 + length))
    offset += 1 + length
  }
  if (offset + 4 > buffer.length) throw new Error('malformed dns question: missing type or class')
  const qtype = buffer.readUInt16BE(offset)
  const qclass = buffer.readUInt16BE(offset + 2)
  return { id, name: labels.join('.'), qtype, qclass, questionEnd: offset + 4 }
}

export function buildDnsResponse({ query, buffer, address, ttl = 60 }) {
  const question = buffer.subarray(HEADER_LENGTH, query.questionEnd)
  const answerable = query.qtype === DNS_TYPE.A && typeof address === 'string'
  const header = Buffer.alloc(HEADER_LENGTH)
  header.writeUInt16BE(query.id, 0)
  // QR=1, AA=1, RD copied as 1, RA=0, RCODE=0
  header.writeUInt16BE(0x8580, 2)
  header.writeUInt16BE(1, 4)
  header.writeUInt16BE(answerable ? 1 : 0, 6)
  if (!answerable) return Buffer.concat([header, question])
  const octets = address.split('.').map((part) => Number.parseInt(part, 10))
  if (octets.length !== 4 || octets.some((octet) => !Number.isInteger(octet) || octet < 0 || octet > 255)) {
    throw new Error(`not an ipv4 address: ${address}`)
  }
  const answer = Buffer.alloc(question.length + 10 + 4)
  question.copy(answer, 0)
  let cursor = question.length
  // rewrite the name as the same labels rather than a compression pointer
  answer.writeUInt16BE(DNS_TYPE.A, cursor - 4)
  cursor = question.length
  answer.writeUInt16BE(DNS_TYPE.A, cursor)
  answer.writeUInt16BE(1, cursor + 2)
  answer.writeUInt32BE(ttl, cursor + 4)
  answer.writeUInt16BE(4, cursor + 8)
  Buffer.from(octets).copy(answer, cursor + 10)
  return Buffer.concat([header, question, answer.subarray(question.length)])
}

export function startDnsListener({ port = 53, address = '0.0.0.0', onQuery, answerAddress = '127.0.0.1' }) {
  const socket = createSocket('udp4')
  socket.on('message', (message, remote) => {
    let query
    try {
      query = parseDnsQuery(message)
    } catch {
      return
    }
    try {
      const response = buildDnsResponse({ query, buffer: message, address: answerAddress })
      socket.send(response, remote.port, remote.address)
    } catch {
      // a malformed answer must never take the listener down
    }
    onQuery?.({
      protocol: 'dns',
      name: query.name,
      qType: TYPE_NAME.get(query.qtype) ?? String(query.qtype),
      remoteAddress: remote.address,
      rawRequest: message.toString('base64'),
    })
  })
  return new Promise((resolve, reject) => {
    socket.once('error', reject)
    socket.bind(port, address, () => {
      resolve({
        port: socket.address().port,
        close: () => new Promise((done) => socket.close(done)),
      })
    })
  })
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `node --test test/bounty-oob-dns.test.mjs`
Expected: PASS, 9 tests

If `buildDnsResponse` produces a malformed answer section, fix the offsets against the parsed `questionEnd` rather than loosening the assertions — the `rdata` check is the one that proves the packet is real.

- [x] **Step 5: Commit**

```bash
git add scripts/lib/bounty-oob-dns.mjs test/bounty-oob-dns.test.mjs
git commit -m "feat(bounty-v1): self-hosted DNS listener with hand-rolled wire format"
```

---

### Task 6: Self-hosted HTTP listener

**Files:**
- Create: `scripts/lib/bounty-oob-http.mjs`
- Test: `test/bounty-oob-http.test.mjs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces:
  - `hostFromHeader(hostHeader) -> string | null` — strips the port, lowercases
  - `startHttpListener({ port, address, onRequest, maxBodyBytes }) -> Promise<{ port, close }>`
  - The listener answers `200 OK` with a fixed short body, captures method, path, headers and a length-capped body, and never follows or echoes attacker input into the response.

- [x] **Step 1: Write the failing test**

```js
import assert from 'node:assert/strict'
import { test } from 'node:test'
import { hostFromHeader, startHttpListener } from '../scripts/lib/bounty-oob-http.mjs'

test('extracts a host without its port', () => {
  assert.equal(hostFromHeader('ABC.oob.example:8080'), 'abc.oob.example')
  assert.equal(hostFromHeader('abc.oob.example'), 'abc.oob.example')
  assert.equal(hostFromHeader(undefined), null)
  assert.equal(hostFromHeader(''), null)
})

test('captures a request over loopback', async () => {
  const seen = []
  const listener = await startHttpListener({ port: 0, address: '127.0.0.1', onRequest: (e) => seen.push(e) })
  const response = await fetch(`http://127.0.0.1:${listener.port}/hit?x=1`, {
    method: 'POST',
    headers: { 'X-Probe': 'oob', Host: `${'c'.repeat(20)}${'n'.repeat(13)}.oob.example` },
    body: 'payload-body',
  })
  assert.equal(response.status, 200)
  await listener.close()
  assert.equal(seen.length, 1)
  assert.equal(seen[0].protocol, 'http')
  assert.equal(seen[0].method, 'POST')
  assert.equal(seen[0].path, '/hit?x=1')
  assert.equal(seen[0].host, `${'c'.repeat(20)}${'n'.repeat(13)}.oob.example`)
  assert.equal(seen[0].headers['x-probe'], 'oob')
  assert.equal(seen[0].body, 'payload-body')
})

test('caps the captured body', async () => {
  const seen = []
  const listener = await startHttpListener({ port: 0, address: '127.0.0.1', maxBodyBytes: 16, onRequest: (e) => seen.push(e) })
  await fetch(`http://127.0.0.1:${listener.port}/`, { method: 'POST', body: 'x'.repeat(512) })
  await listener.close()
  assert.equal(seen[0].body.length, 16)
  assert.equal(seen[0].bodyTruncated, true)
})
```

- [x] **Step 2: Run test to verify it fails**

Run: `node --test test/bounty-oob-http.test.mjs`
Expected: FAIL — module not found.

- [x] **Step 3: Write minimal implementation**

```js
import { createServer } from 'node:http'

const DEFAULT_MAX_BODY_BYTES = 64 * 1024

export function hostFromHeader(hostHeader) {
  if (typeof hostHeader !== 'string' || hostHeader.length === 0) return null
  const withoutPort = hostHeader.startsWith('[')
    ? hostHeader.slice(0, hostHeader.indexOf(']') + 1)
    : hostHeader.split(':')[0]
  const host = withoutPort.toLowerCase()
  return host.length === 0 ? null : host
}

export function startHttpListener({
  port = 80,
  address = '0.0.0.0',
  onRequest,
  maxBodyBytes = DEFAULT_MAX_BODY_BYTES,
}) {
  const server = createServer((request, response) => {
    const chunks = []
    let received = 0
    let truncated = false
    request.on('data', (chunk) => {
      received += chunk.length
      if (received > maxBodyBytes) {
        truncated = true
        const room = maxBodyBytes - (received - chunk.length)
        if (room > 0) chunks.push(chunk.subarray(0, room))
        return
      }
      chunks.push(chunk)
    })
    request.on('end', () => {
      onRequest?.({
        protocol: 'http',
        method: request.method,
        path: request.url,
        host: hostFromHeader(request.headers.host),
        headers: { ...request.headers },
        body: Buffer.concat(chunks).toString('utf8'),
        bodyTruncated: truncated,
        remoteAddress: request.socket.remoteAddress,
      })
      response.writeHead(200, { 'Content-Type': 'text/plain' })
      response.end('ok\n')
    })
  })
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(port, address, () => {
      resolve({
        port: server.address().port,
        close: () => new Promise((done) => server.close(done)),
      })
    })
  })
}
```

- [x] **Step 4: Run test to verify it passes**

Run: `node --test test/bounty-oob-http.test.mjs`
Expected: PASS, 3 tests

- [x] **Step 5: Commit**

```bash
git add scripts/lib/bounty-oob-http.mjs test/bounty-oob-http.test.mjs
git commit -m "feat(bounty-v1): self-hosted HTTP capture listener"
```

---

### Task 7: Backend interface, session schema, and controller

**Files:**
- Create: `schemas/bounty-oob-session.schema.json`
- Create: `scripts/lib/bounty-oob-controller.mjs`
- Modify: `scripts/bounty.mjs` — add the `oob` command group
- Test: `test/bounty-oob-controller.test.mjs`

**Interfaces:**
- Consumes: all prior tasks.
- Produces:
  - `createOobSession({ backend, server, correlationId, secret, privateKeyPem, createdAt }) -> session`
  - `assertValidOobSession(value) -> void`
  - `openOobSession({ bundlePath, backend, server, randomBytes, now, fetchImpl }) -> Promise<session>` — registers with the hosted backend, writes `oob-session.json` into the bundle
  - `mintOobPayload({ bundlePath, label, requestId, insertionPoint, role, bugClass, randomBytes, now }) -> Promise<{ host, nonce }>`
  - `pollOobSession({ bundlePath, fetchImpl }) -> Promise<{ results, summary }>` — correlates and appends to `oob-interactions.jsonl`
  - `oobSessionStatus({ bundlePath }) -> Promise<{ backend, server, correlationId, mints, observed }>`
  - `closeOobSession({ bundlePath, fetchImpl }) -> Promise<void>`
  - Historical backend values: `'hosted'` and `'self_hosted'`. The original controller recorded the backend but did not gate on `third_party`. Current public hosted `open`, `mint`, and `poll` fail closed; neither a recorded backend nor fixed-server allowlisting supplies authorization. Re-enablement requires a trusted controller to validate current scope and explicit third-party authority.

- [x] **Step 1: Write the failing test**

```js
import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { publicEncrypt, constants, randomBytes as cryptoRandomBytes, createPublicKey } from 'node:crypto'
import { sealInteractionForTest } from '../scripts/lib/bounty-oob-crypto.mjs'
import {
  closeOobSession,
  mintOobPayload,
  oobSessionStatus,
  openOobSession,
  pollOobSession,
} from '../scripts/lib/bounty-oob-controller.mjs'

const NOW = new Date('2026-08-21T10:00:00.000Z')
// deterministic-enough randomness for ids while staying in the alphabet
const seq = (n) => cryptoRandomBytes(n)

function okJson(body) {
  return new Response(JSON.stringify(body), { status: 200, headers: { 'Content-Type': 'application/json' } })
}

async function bundle() {
  return mkdtemp(join(tmpdir(), 'bounty-oob-'))
}

test('open registers a hosted session and persists it', async () => {
  const dir = await bundle()
  try {
    const calls = []
    const fetchImpl = async (url, init) => { calls.push(String(url)); return okJson({ message: 'registration successful' }) }
    const session = await openOobSession({
      bundlePath: dir, backend: 'hosted', server: 'oast.fun', randomBytes: seq, now: NOW, fetchImpl,
    })
    assert.equal(session.backend, 'hosted')
    assert.equal(session.server, 'oast.fun')
    assert.equal(session.correlation_id.length, 20)
    assert.match(calls[0], /\/register$/)
    const onDisk = JSON.parse(await readFile(join(dir, 'oob-session.json'), 'utf8'))
    assert.equal(onDisk.correlation_id, session.correlation_id)
    assert.ok(onDisk.private_key_pem.includes('PRIVATE KEY'), 'private key persisted for later polling')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('mint produces a host carrying the session correlation id and records provenance', async () => {
  const dir = await bundle()
  try {
    const fetchImpl = async () => okJson({ message: 'registration successful' })
    const session = await openOobSession({
      bundlePath: dir, backend: 'hosted', server: 'oast.fun', randomBytes: seq, now: NOW, fetchImpl,
    })
    const minted = await mintOobPayload({
      bundlePath: dir, label: 'checkout-callback', requestId: 'flow-42',
      insertionPoint: 'body:json:/order/callbackUrl', role: 'customer', bugClass: 'ssrf',
      randomBytes: seq, now: NOW,
    })
    assert.equal(minted.host, `${session.correlation_id}${minted.nonce}.oast.fun`)
    assert.equal(minted.host.split('.')[0].length, 33)
    const status = await oobSessionStatus({ bundlePath: dir })
    assert.equal(status.mints, 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('poll correlates a callback back to the mint and records it', async () => {
  const dir = await bundle()
  try {
    let session
    const aesKey = cryptoRandomBytes(32)
    const fetchImpl = async (url) => {
      if (String(url).endsWith('/register')) return okJson({ message: 'registration successful' })
      const pub = createPublicKey({ key: session.private_key_pem, format: 'pem' })
      const wrapped = publicEncrypt(
        { key: pub, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, aesKey,
      ).toString('base64')
      return okJson({
        aes_key: wrapped,
        data: [sealInteractionForTest({
          aesKey,
          interaction: {
            protocol: 'dns',
            'full-id': hostUnderTest,
            'q-type': 'A',
            'remote-address': '194.65.39.214',
            timestamp: '2026-08-21T10:05:00Z',
          },
          iv: cryptoRandomBytes(16),
        })],
      })
    }
    session = await openOobSession({
      bundlePath: dir, backend: 'hosted', server: 'oast.fun', randomBytes: seq, now: NOW, fetchImpl,
    })
    const minted = await mintOobPayload({
      bundlePath: dir, label: 'ssrf-probe', requestId: 'flow-9', insertionPoint: 'query:url',
      role: 'anonymous', bugClass: 'ssrf', randomBytes: seq, now: NOW,
    })
    var hostUnderTest = minted.host
    const { results, summary } = await pollOobSession({ bundlePath: dir, fetchImpl })
    assert.equal(summary.matched, 1)
    assert.equal(results[0].mint.requestId, 'flow-9')
    assert.equal(results[0].mint.bugClass, 'ssrf')
    const jsonl = await readFile(join(dir, 'oob-interactions.jsonl'), 'utf8')
    assert.equal(jsonl.trim().split('\n').length, 1)
    const status = await oobSessionStatus({ bundlePath: dir })
    assert.equal(status.observed, 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('a callback for an unminted nonce is recorded as unmatched, not dropped', async () => {
  const dir = await bundle()
  try {
    let session
    const aesKey = cryptoRandomBytes(32)
    const fetchImpl = async (url) => {
      if (String(url).endsWith('/register')) return okJson({ message: 'registration successful' })
      const pub = createPublicKey({ key: session.private_key_pem, format: 'pem' })
      const wrapped = publicEncrypt(
        { key: pub, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: 'sha256' }, aesKey,
      ).toString('base64')
      return okJson({
        aes_key: wrapped,
        data: [sealInteractionForTest({
          aesKey,
          interaction: { protocol: 'dns', 'full-id': `${session.correlation_id}zzzzzzzzzzzzz.oast.fun`, 'q-type': 'A' },
          iv: cryptoRandomBytes(16),
        })],
      })
    }
    session = await openOobSession({
      bundlePath: dir, backend: 'hosted', server: 'oast.fun', randomBytes: seq, now: NOW, fetchImpl,
    })
    const { summary, results } = await pollOobSession({ bundlePath: dir, fetchImpl })
    assert.equal(summary.matched, 0)
    assert.equal(summary.unmatched, 1)
    assert.equal(results[0].reason, 'nonce-not-in-ledger')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('close deregisters a hosted session', async () => {
  const dir = await bundle()
  try {
    const calls = []
    const fetchImpl = async (url) => { calls.push(String(url)); return okJson({ message: 'ok' }) }
    await openOobSession({ bundlePath: dir, backend: 'hosted', server: 'oast.fun', randomBytes: seq, now: NOW, fetchImpl })
    await closeOobSession({ bundlePath: dir, fetchImpl })
    assert.ok(calls.some((url) => url.endsWith('/deregister')))
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('a self-hosted session opens with no network call at all', async () => {
  const dir = await bundle()
  try {
    const fetchImpl = async () => { throw new Error('self-hosted must not call the network') }
    const session = await openOobSession({
      bundlePath: dir, backend: 'self_hosted', server: 'oob.mydomain.example',
      randomBytes: seq, now: NOW, fetchImpl,
    })
    assert.equal(session.backend, 'self_hosted')
    assert.equal(session.server, 'oob.mydomain.example')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
```

- [x] **Step 2: Run test to verify it fails**

Run: `node --test test/bounty-oob-controller.test.mjs`
Expected: FAIL — module not found.

- [x] **Step 3: Write the session schema**

`schemas/bounty-oob-session.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://red-team-audit.dev/schemas/bounty-oob-session.schema.json",
  "title": "Red Team Audit bounty-v1 out-of-band session",
  "description": "An OOB interaction session and its mint ledger. The backend is recorded as evidence of where callbacks were observed; a hosted backend means callback data transited a third party. Absence of a callback is NO_INTERACTION_OBSERVED and never proof that a target is not vulnerable.",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "kind", "backend", "server", "correlation_id", "secret", "private_key_pem", "created_at", "ledger"],
  "properties": {
    "schema_version": { "enum": ["1.0.0"] },
    "kind": { "const": "red-team-audit/bounty-oob-session" },
    "backend": { "enum": ["hosted", "self_hosted"] },
    "server": { "type": "string", "minLength": 1, "maxLength": 253 },
    "correlation_id": { "type": "string", "pattern": "^[a-z0-9]{20}$" },
    "secret": { "type": "string", "minLength": 8, "maxLength": 128 },
    "private_key_pem": { "type": "string", "minLength": 1 },
    "created_at": {
      "type": "string",
      "minLength": 24,
      "maxLength": 24,
      "pattern": "^\\d{4}-\\d{2}-\\d{2}T\\d{2}:\\d{2}:\\d{2}\\.\\d{3}Z$"
    },
    "ledger": {
      "type": "object",
      "additionalProperties": false,
      "required": ["schema_version", "mints"],
      "properties": {
        "schema_version": { "enum": ["1.0.0"] },
        "mints": {
          "type": "object",
          "additionalProperties": {
            "type": "object",
            "additionalProperties": false,
            "required": ["nonce", "label", "requestId", "insertionPoint", "role", "bugClass", "mintedAt"],
            "properties": {
              "nonce": { "type": "string", "pattern": "^[a-z0-9]{13}$" },
              "label": { "type": "string", "minLength": 1, "maxLength": 256 },
              "requestId": { "type": "string", "maxLength": 256 },
              "insertionPoint": { "type": "string", "maxLength": 512 },
              "role": { "type": "string", "maxLength": 128 },
              "bugClass": { "type": "string", "maxLength": 64 },
              "mintedAt": { "type": "string", "minLength": 24, "maxLength": 24 }
            }
          }
        }
      }
    }
  }
}
```

- [x] **Step 4: Write the controller**

```js
import { appendFile, readFile, writeFile } from 'node:fs/promises'
import { randomUUID } from 'node:crypto'
import { join } from 'node:path'
import Ajv2020 from 'ajv/dist/2020.js'
import { readFileSync } from 'node:fs'
import { generateSessionKeypair } from './bounty-oob-crypto.mjs'
import {
  deregisterHostedSession,
  pollHostedSession,
  registerHostedSession,
} from './bounty-oob-hosted.mjs'
import {
  buildPayloadHost,
  createCorrelationId,
  createMintLedger,
  mintNonce,
  recordMint,
} from './bounty-oob-payload.mjs'
import {
  correlateInteraction,
  normalizeInteraction,
  summarizeCorrelation,
} from './bounty-oob-correlator.mjs'

const SESSION_FILE = 'oob-session.json'
const INTERACTIONS_FILE = 'oob-interactions.jsonl'
const SESSION_SCHEMA_URL = new URL('../../schemas/bounty-oob-session.schema.json', import.meta.url)

let validator = null

export function assertValidOobSession(value) {
  if (validator === null) {
    const ajv = new Ajv2020({ allErrors: true, strict: false })
    validator = ajv.compile(JSON.parse(readFileSync(SESSION_SCHEMA_URL, 'utf8')))
  }
  if (validator(value)) return
  const detail = (validator.errors ?? [])
    .map((error) => `${error.instancePath || '/'} ${error.message}`)
    .join('; ')
  throw new Error(`oob session failed schema validation: ${detail}`)
}

function sessionPath(bundlePath) {
  return join(bundlePath, SESSION_FILE)
}

async function loadSession(bundlePath) {
  const session = JSON.parse(await readFile(sessionPath(bundlePath), 'utf8'))
  assertValidOobSession(session)
  return session
}

async function saveSession(bundlePath, session) {
  assertValidOobSession(session)
  await writeFile(sessionPath(bundlePath), `${JSON.stringify(session, null, 2)}\n`, 'utf8')
}

export async function openOobSession({
  bundlePath,
  backend,
  server,
  randomBytes,
  now,
  fetchImpl = fetch,
}) {
  if (backend !== 'hosted' && backend !== 'self_hosted') {
    throw new Error(`unknown oob backend: ${backend}`)
  }
  const keys = generateSessionKeypair()
  const correlationId = createCorrelationId(randomBytes)
  const secret = randomUUID()
  if (backend === 'hosted') {
    await registerHostedSession({
      server,
      correlationId,
      secret,
      publicKeyBase64: keys.publicKeyBase64,
      fetchImpl,
    })
  }
  const session = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/bounty-oob-session',
    backend,
    server,
    correlation_id: correlationId,
    secret,
    private_key_pem: keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    created_at: now.toISOString(),
    ledger: createMintLedger(),
  }
  await saveSession(bundlePath, session)
  return session
}

export async function mintOobPayload({
  bundlePath,
  label,
  requestId,
  insertionPoint,
  role,
  bugClass,
  randomBytes,
  now,
}) {
  const session = await loadSession(bundlePath)
  const nonce = mintNonce(randomBytes)
  const host = buildPayloadHost({ correlationId: session.correlation_id, nonce, server: session.server })
  session.ledger = recordMint(session.ledger, {
    nonce,
    label,
    requestId,
    insertionPoint,
    role,
    bugClass,
    mintedAt: now.toISOString(),
  })
  await saveSession(bundlePath, session)
  return { host, nonce }
}

export async function pollOobSession({ bundlePath, fetchImpl = fetch }) {
  const session = await loadSession(bundlePath)
  if (session.backend !== 'hosted') {
    throw new Error('poll applies to the hosted backend; a self-hosted listener records interactions directly')
  }
  const raw = await pollHostedSession({
    server: session.server,
    correlationId: session.correlation_id,
    secret: session.secret,
    privateKey: session.private_key_pem,
    fetchImpl,
  })
  const results = raw.map((item) => correlateInteraction({
    ledger: session.ledger,
    correlationId: session.correlation_id,
    server: session.server,
    interaction: normalizeInteraction(item),
  }))
  if (results.length > 0) {
    const lines = results.map((result) => JSON.stringify({
      matched: result.matched,
      reason: result.reason ?? null,
      nonce: result.nonce ?? null,
      mint: result.mint ?? null,
      interaction: result.interaction,
    })).join('\n')
    await appendFile(join(bundlePath, INTERACTIONS_FILE), `${lines}\n`, 'utf8')
  }
  return { results, summary: summarizeCorrelation(results) }
}

export async function oobSessionStatus({ bundlePath }) {
  const session = await loadSession(bundlePath)
  let observed = 0
  try {
    const text = await readFile(join(bundlePath, INTERACTIONS_FILE), 'utf8')
    observed = text.split('\n').filter((line) => line.trim().length > 0).length
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
  return {
    backend: session.backend,
    server: session.server,
    correlationId: session.correlation_id,
    mints: Object.keys(session.ledger.mints).length,
    observed,
  }
}

export async function closeOobSession({ bundlePath, fetchImpl = fetch }) {
  const session = await loadSession(bundlePath)
  if (session.backend !== 'hosted') return
  await deregisterHostedSession({
    server: session.server,
    correlationId: session.correlation_id,
    secret: session.secret,
    fetchImpl,
  })
}
```

- [x] **Step 5: Run test to verify it passes**

Run: `node --test test/bounty-oob-controller.test.mjs`
Expected: PASS, 6 tests

- [x] **Step 6: Wire the CLI**

Historical implementation step: add to `scripts/bounty.mjs` an `oob` command group
dispatching to the controller. The command listing below records the original
interface; it is not an instruction to bypass the current hosted-OOB fail-closed
gate.

```
bounty oob open <bundle> --backend <hosted|self-hosted> [--server <domain>] [--json]
bounty oob mint <bundle> --label <text> --bug-class <class> [--request-id <id>] [--insertion-point <text>] [--role <name>] [--json]
bounty oob poll <bundle> [--json]
bounty oob status <bundle> [--json]
bounty oob close <bundle> [--json]
```

The historical help requirement stated that a hosted backend sends callback data
through a third-party service and that an absent callback is
`NO_INTERACTION_OBSERVED`, never proof of absence. Current help instead states
that every public OOB session command is disabled pending a trusted
controller-owned local root and atomic transport lease, and that destination
allowlisting is not authorization.

- [x] **Step 7: Add the new test files to `test:platform` in package.json and commit**

```bash
git add schemas/bounty-oob-session.schema.json scripts/lib/bounty-oob-controller.mjs scripts/bounty.mjs test/bounty-oob-controller.test.mjs package.json
git commit -m "feat(bounty-v1): oob session controller and cli"
```

---

### Task 8: Live end-to-end verification

**Files:**
- Create: `docs/superpowers/plans/2026-08-21-p7-live-verification.md` (a short evidence record, not code)

**Interfaces:** none — this task produces evidence.

- [x] **Step 1: Hosted backend, real callback (historical verification only)**

This verification was performed against `oast.fun` on 2026-08-21 by opening a
session, minting one payload, resolving it, polling, and recording the resulting
correlation. Do not repeat it through the current public CLI: hosted `open`,
`mint`, and `poll` are now fail-closed pending a trusted controller.

- [x] **Step 2: Self-hosted backend over loopback**

Start the DNS listener on an ephemeral port and the HTTP listener on another, send a query and a request for a minted host, and confirm both capture and correlate.

- [x] **Step 3: Confirm the negative case is not a clearance**

Poll a session with no interactions and confirm the output says `NO_INTERACTION_OBSERVED` rather than anything resembling "not vulnerable".

- [x] **Step 4: Record results and commit**

---

## P7 Exit Gate

Verified 2026-08-21.

- [x] Purity grep clean for `bounty-oob-payload.mjs` and `bounty-oob-correlator.mjs`
- [x] No new entry in `package.json` `dependencies` — still `acorn`, `ajv`, `yaml`
- [x] **A real `oast.fun` callback correlates to the exact mint that produced it** — 4/4 matched, each resolving to `ssrf @ body:json:/order/callbackUrl as customer (req flow-42)`
- [x] The self-hosted DNS and HTTP listeners both capture and correlate over loopback — 2/2, with two concurrent mints correctly discriminated (DNS→xxe mint, HTTP→rce mint)
- [x] A hosted session records `backend: "hosted"` in the bundle
- [x] Historical result: the 2026-08-21 code did not gate on `permissions.third_party` and recorded `third_party_transit` as evidence only. **Superseded:** current public hosted `open`, `mint`, and `poll` fail closed because the sealed scope does not authorize third-party transit; the fixed hosted-server allowlist is a destination constraint, not authorization.
- [x] An empty poll reports `NO_INTERACTION_OBSERVED` and never implies absence of vulnerability
- [x] **67 OOB tests across 7 files, all passing**; every unit test runs with `fetch` injected, so none opens a socket
- [x] `npm.cmd test` — **1615 tests, 1610 pass, 2 fail, 3 skipped.** The 2 failures are the same pre-existing pair from P0 (`canonical-ordering.test.mjs:126` and `http-authed-credential.test.mjs:355`); zero bounty or OOB failures. Baseline at the end of P0 was 1548, and 1548 + 67 = 1615 exactly, so nothing regressed. **The suite does not pass clean, and this checkbox does not claim it does.**

### The defect the live run caught

The first live end-to-end attempt returned `total=1, matched=0, unmatched=1` with
reason `host-not-ours`.

Cause: interactsh reports `full-id` as the **bare 33-character label**
(`"<cid><nonce>"`) with no domain attached. Our own DNS listener, by contrast,
observes the full FQDN the resolver asked for. `extractNonce` required the
`.<server>` suffix, so it rejected every genuine hosted callback.

Every offline test passed throughout, because all of them constructed hosts with
`buildPayloadHost`, which produces the FQDN form. The fixture agreed with the
implementation and both disagreed with the server.

Fixed by stripping the domain suffix when present and tolerating its absence,
with regression tests for the bare-label form and a comment in the source
recording why the tolerance exists so it does not get "tidied up" later.

**Lesson for later phases, same as P0's `format: "date-time"` finding:** a test
suite written against your own assumptions cannot falsify those assumptions. Both
real defects in this protocol so far were found by running the thing against
reality, not by adding tests. Keep a live smoke path in every phase.

## Deferred

- SMTP and LDAP OOB protocols. DNS and HTTP cover the overwhelming majority of blind vectors; SMTP matters for a narrow set of XXE and SSRF cases and can be added behind the same interface.
- Wildcard TLS for the self-hosted HTTPS listener — needs a real certificate for the operator's domain, so it waits on the domain existing.
- Automatic payload injection. P4's scanner calls `mintOobPayload` and P7 does not reach into it.
