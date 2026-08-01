# Proof Tier Model and Severity Gate Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a finding whose evidence is a byte range in sealed source exceed the Medium severity ceiling, verified mechanically by the controller rather than asserted by the provider.

**Architecture:** Proof tiers become evidence classes. `T0` (asserted) keeps the Medium cap; `T1` (anchored in sealed bytes), `T2` (disposable instance) and `T3` (production probe) do not. `T1` is verified by resolving each `source_anchor` against the run's sealed snapshot — read the byte range, hash it, compare to `excerpt_sha256`. A new `anchor` command issues anchors so providers never compute byte offsets themselves.

**Tech Stack:** Node.js ESM, plain `.mjs`, no build step. Tests are `node:test` + `node:assert/strict`. Schema validation is Ajv 2020 against `schemas/*.json`.

## Global Constraints

- Source style: **no semicolons**, 2-space indent, single quotes. Match surrounding code exactly.
- `scripts/lib/sealed-snapshot.mjs` imports **only `node:crypto`** and must stay that way — it is the seal's trusted computing base.
- `findingInvariantErrors` in `scripts/lib/contracts.mjs` must stay **pure with no I/O**. Checks needing run context go in `runInvariantErrors`.
- Ordering of any hashed or signed collection uses `compareCanonicalStrings` from `scripts/lib/canonical-order.mjs`, never `localeCompare`. A guard test enforces this.
- Every gate test must be **demonstrated failing against current `main`** before its change lands. A test that passes before the change is not evidence for it.
- Baseline suite: **724 tests, 721 passing, 1 skipped, 2 failing**. The 2 failures are `test/cloud-iac-fixtures.test.mjs` shelling out to `rg`, which is absent on this machine. They are pre-existing and must stay at exactly 2.

## Reference: shapes you will need

Sealed snapshot index, at `<bundle>/snapshots/source/index.json`:

```json
{
  "schema_version": "1.0.0",
  "snapshot_kind": "source",
  "source_tree_digest": "<sha256>",
  "file_manifest_sha256": "<sha256>",
  "shard_encoding": "raw",
  "compression": "none",
  "max_shard_bytes": 67108864,
  "files": [
    {
      "availability": "AVAILABLE",
      "file_id": "file_44e10e1f…",
      "path": ".github/workflows/pr-preview.yml",
      "kind": "text",
      "size": 2344,
      "sha256": "649a877c…",
      "shard": "shard_000000",
      "offset": 0,
      "length": 2344
    }
  ],
  "shards": [{ "shard_id": "shard_000000", "size": 68163, "sha256": "ef05e1de…" }]
}
```

Shard bytes are raw and uncompressed at `<bundle>/snapshots/source/shard_000000.bin`.
`file.offset` is the file's offset **within its shard**. An anchor's `start_byte`
is relative to the **file**, so the shard offset is `file.offset + start_byte`.

`run.source_snapshot.root_sha256` equals `sha256(<index.json bytes>)`. Verified.

A `sourceAnchor` (already in `schemas/finding.schema.json`, currently unused):

```json
{
  "file_id": "file_<64 hex>",
  "snapshot_sha256": "<64 hex>",
  "start_byte": 0,
  "end_byte": 1,
  "excerpt_sha256": "<64 hex>"
}
```

---

### Task 1: Stop capping T3 for being unavailable

`PROOF_TIER_CAP` caps effective severity at Medium when `proof_tier` is `T0` **or `T3`**. `T3` is capped because the proof broker does not exist, which conflates "not permitted yet" with "weak evidence." Availability belongs to RoE enforcement, not the severity gate.

**Files:**
- Modify: `scripts/lib/contracts.mjs:573-583`
- Test: `test/proof-tier-gate.test.mjs` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: nothing later tasks depend on.

- [ ] **Step 1: Write the failing test**

Create `test/proof-tier-gate.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { validateFinding } from '../scripts/lib/contracts.mjs'

function finding(overrides = {}) {
  return {
    candidate_id: 'cand:web:001',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Tenant object loads without an ownership check',
    claimed_impact_severity: 'Critical',
    effective_severity: 'Critical',
    location: ['src/orders.js:42'],
    evidence: 'return Orders.findById(req.params.id)',
    reachable_from: 'GET /orders/:id',
    proof_tier: 'T1',
    verification_status: 'CONFIRMED',
    ...overrides,
  }
}

const codes = (record) => validateFinding(record).errors.map((error) => error.code)

test('T3 evidence no longer caps effective severity', () => {
  assert.equal(codes(finding({ proof_tier: 'T3' })).includes('PROOF_TIER_CAP'), false)
})

test('T0 evidence still caps effective severity at Medium', () => {
  assert.equal(codes(finding({ proof_tier: 'T0' })).includes('PROOF_TIER_CAP'), true)
})

test('T1 and T2 evidence do not cap effective severity', () => {
  for (const tier of ['T1', 'T2']) {
    assert.equal(codes(finding({ proof_tier: tier })).includes('PROOF_TIER_CAP'), false)
  }
})

test('unresolved reachability still caps regardless of tier', () => {
  const codesFor = codes(finding({ proof_tier: 'T1', reachable_from: 'unknown' }))
  assert.equal(codesFor.includes('REACHABILITY_CAP'), true)
})
```

`validateFinding(record, options)` is exported at `contracts.mjs:815` and
returns `{ valid, errors, stage }`, where each error carries `code`,
`instancePath`, and `message`. Do not export `findingInvariantErrors` — the
public validator is the right surface to test through.

- [ ] **Step 2: Run the test and confirm it fails**

```bash
node --test test/proof-tier-gate.test.mjs
```

Expected: the `T3` test FAILS (`PROOF_TIER_CAP` is present). The `T0`, `T1`/`T2`
and reachability tests should already PASS. If the `T0` test fails, stop — the
gate is not where this plan says it is.

- [ ] **Step 3: Make the change**

In `scripts/lib/contracts.mjs`, in `findingInvariantErrors`:

```js
  if (
    effectiveSeverity
    && record.proof_tier === 'T0'
    && severityAbove(effectiveSeverity, 'Medium')
  ) {
    addError(
      errors,
      'PROOF_TIER_CAP',
      '/effective_severity',
      `${record.proof_tier} evidence caps effective severity at Medium`,
    )
  }
```

Only the condition changes. `T3` availability is enforced by RoE mode, not here.

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
node --test test/proof-tier-gate.test.mjs
```

Expected: 4 passing.

- [ ] **Step 5: Run the full suite**

```bash
node --test 2>&1 | tail -20
```

Expected: **728 tests, 725 passing, 1 skipped, 2 failing** (the pre-existing
ripgrep pair). Any third failure is a regression from this change — investigate
before committing.

- [ ] **Step 6: Commit**

```bash
git add test/proof-tier-gate.test.mjs scripts/lib/contracts.mjs
git commit -m "fix: stop capping T3 severity for proof-broker unavailability"
```

---

### Task 2: Reject T1+ claims in an unsealed run

Anchor verification reads the sealed byte store. A run planned without `--seal-source` has none, so a `T1`-or-above claim in such a run can never be checked and must be refused rather than trusted.

**Files:**
- Modify: `scripts/lib/contracts.mjs` — inside `runInvariantErrors` (line 2450)
- Test: `test/proof-tier-gate.test.mjs` (extend)

**Interfaces:**
- Consumes: `PROOF_TIER_CAP` behaviour from Task 1.
- Produces: error code `UNSEALED_TIER_CLAIM` at pointer `/findings/<i>/proof_tier`.

- [ ] **Step 1: Write the failing test**

Append to `test/proof-tier-gate.test.mjs`:

```js
import { validateRun } from '../scripts/lib/contracts.mjs'

function run(findings, extra = {}) {
  return {
    schema_version: '6.0.0',
    run_id: 'run:a',
    state: 'RUNNING',
    phase: 'RECON',
    capability_mode: 'STATIC',
    created_at: '2026-08-02T00:00:00.000Z',
    tool: { name: 'red-team-audit', version: '0.10.0', corpus_sha256: 'a'.repeat(64) },
    repository: { root: '/repo' },
    lens_pack_digest: 'b'.repeat(64),
    policy_digest: 'c'.repeat(64),
    jobs: [],
    coverage: { inventory: [], examined: [], unexamined: [], lenses: [], gaps: [] },
    findings,
    ...extra,
  }
}

const runCodes = (record) => validateRun(record).errors.map((error) => error.code)

test('a T1 claim in an unsealed run is rejected', () => {
  const codes = runCodes(run([finding({ proof_tier: 'T1' })]))
  assert.equal(codes.includes('UNSEALED_TIER_CLAIM'), true)
})

test('a T0 claim in an unsealed run is accepted', () => {
  const codes = runCodes(run([finding({ proof_tier: 'T0', effective_severity: 'Medium' })]))
  assert.equal(codes.includes('UNSEALED_TIER_CLAIM'), false)
})

test('a T1 claim in a sealed run is accepted', () => {
  const sealed = {
    source_snapshot: {
      kind: 'SOURCE',
      root_sha256: 'd'.repeat(64),
      index_artifact_key: 'source_snapshot_index',
      available_files: 1,
      available_bytes: 10,
    },
  }
  const codes = runCodes(run([finding({ proof_tier: 'T1' })], sealed))
  assert.equal(codes.includes('UNSEALED_TIER_CLAIM'), false)
})
```

`validateRun(run)` is exported at `contracts.mjs:3098` and returns
`{ valid, errors }`. The run fixture above may still be missing fields that
`schemas/run.schema.json` lists as `required` — add only what the schema
demands. Each test asserts on the presence or absence of one error code, so
unrelated schema errors do not affect the result.

- [ ] **Step 2: Run the test and confirm it fails**

```bash
node --test test/proof-tier-gate.test.mjs
```

Expected: the unsealed-`T1` test FAILS (no such code yet). The other two PASS
vacuously.

- [ ] **Step 3: Implement the check**

Add a helper next to the other record-level helpers in `scripts/lib/contracts.mjs`:

```js
const ANCHORED_TIERS = new Set(['T1', 'T2', 'T3'])

function unsealedTierClaimErrors(run) {
  const errors = []
  if (run.source_snapshot !== undefined) return errors
  const findings = Array.isArray(run.findings) ? run.findings : []
  findings.forEach((finding, index) => {
    if (finding === null || typeof finding !== 'object') return
    if (!ANCHORED_TIERS.has(finding.proof_tier)) return
    addError(
      errors,
      'UNSEALED_TIER_CLAIM',
      `/findings/${index}/proof_tier`,
      `${finding.proof_tier} requires a sealed source snapshot; plan with --seal-source`,
    )
  })
  return errors
}
```

Call it from `runInvariantErrors`, beside the existing sub-validator pushes:

```js
  errors.push(...unsealedTierClaimErrors(run))
```

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
node --test test/proof-tier-gate.test.mjs
```

Expected: 7 passing.

- [ ] **Step 5: Run the full suite**

```bash
node --test 2>&1 | tail -20
```

Expected: 731 tests, 728 passing, 1 skipped, 2 failing.

- [ ] **Step 6: Commit**

```bash
git add test/proof-tier-gate.test.mjs scripts/lib/contracts.mjs
git commit -m "feat: reject anchored proof-tier claims in unsealed runs"
```

---

### Task 3: Anchor verification module

The core mechanic. Resolve a `file_id` in the sealed index, read the byte range, hash it, compare. `sealed-snapshot.mjs` parses the index but exposes no byte reader, and must stay dependency-free — so this is a new module with the reader injected.

**Files:**
- Create: `scripts/lib/anchor-verification.mjs`
- Test: `test/anchor-verification.test.mjs` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces, relied on by Tasks 5 and 6:
  - `verifySourceAnchors(finding, snapshot) -> AnchorOutcome[]`
  - `anchorForLineRange(snapshot, path, startLine, endLine) -> SourceAnchor`
  - `snapshot` is `{ index, rootSha256, readBytes }` where
    `readBytes(shardId, offset, length) -> Buffer`
  - `AnchorOutcome` is `{ ok: true, file_id }` or
    `{ ok: false, file_id, reason, detail }` with `reason` one of
    `UNKNOWN_FILE_ID`, `SNAPSHOT_MISMATCH`, `FILE_UNAVAILABLE`,
    `RANGE_INVALID`, `RANGE_OUT_OF_BOUNDS`, `EXCERPT_DIGEST_MISMATCH`
  - `SourceAnchor` is `{ file_id, snapshot_sha256, start_byte, end_byte, excerpt_sha256 }`

**Line range semantics:** `startLine` and `endLine` are 1-indexed and inclusive.
The byte range runs from the first byte of `startLine` to the first byte of
`endLine + 1`, so line terminators are included; at end of file the range ends
at the file length. Terminators are found by scanning the raw bytes for `0x0A`,
so CRLF is handled without special cases — the `\r` is simply part of the line.

- [ ] **Step 1: Write the failing test**

Create `test/anchor-verification.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { verifySourceAnchors, anchorForLineRange } from '../scripts/lib/anchor-verification.mjs'

const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex')
const ROOT = 'a'.repeat(64)

// Two files packed into one shard, exactly as packSnapshot lays them out.
const FILE_A = Buffer.from('alpha\nbravo\ncharlie\n', 'utf8')
const FILE_B = Buffer.from('delta\r\necho\r\n', 'utf8')
const SHARD = Buffer.concat([FILE_A, FILE_B])

const INDEX = {
  schema_version: '1.0.0',
  snapshot_kind: 'source',
  files: [
    {
      availability: 'AVAILABLE',
      file_id: 'file_' + '1'.repeat(64),
      path: 'a.txt',
      kind: 'text',
      size: FILE_A.length,
      shard: 'shard_000000',
      offset: 0,
      length: FILE_A.length,
    },
    {
      availability: 'AVAILABLE',
      file_id: 'file_' + '2'.repeat(64),
      path: 'b.txt',
      kind: 'text',
      size: FILE_B.length,
      shard: 'shard_000000',
      offset: FILE_A.length,
      length: FILE_B.length,
    },
    {
      availability: 'UNAVAILABLE',
      file_id: 'file_' + '3'.repeat(64),
      path: 'c.bin',
      kind: 'binary',
      size: 4,
      unavailable_reason: 'non-text',
    },
  ],
  shards: [{ shard_id: 'shard_000000', size: SHARD.length, sha256: sha256(SHARD) }],
}

const readBytes = (shardId, offset, length) => {
  assert.equal(shardId, 'shard_000000')
  return SHARD.subarray(offset, offset + length)
}
const SNAPSHOT = { index: INDEX, rootSha256: ROOT, readBytes }

const anchor = (overrides = {}) => ({
  file_id: 'file_' + '1'.repeat(64),
  snapshot_sha256: ROOT,
  start_byte: 0,
  end_byte: 5,
  excerpt_sha256: sha256(Buffer.from('alpha', 'utf8')),
  ...overrides,
})

const only = (a) => verifySourceAnchors({ source_anchors: [a] }, SNAPSHOT)[0]

test('an anchor matching the sealed bytes verifies', () => {
  assert.deepEqual(only(anchor()), { ok: true, file_id: 'file_' + '1'.repeat(64) })
})

test('an anchor into the second file resolves against its shard offset', () => {
  const outcome = only(anchor({
    file_id: 'file_' + '2'.repeat(64),
    start_byte: 0,
    end_byte: 5,
    excerpt_sha256: sha256(Buffer.from('delta', 'utf8')),
  }))
  assert.equal(outcome.ok, true)
})

test('a one-byte-short range fails on digest, not silently', () => {
  assert.equal(only(anchor({ end_byte: 4 })).reason, 'EXCERPT_DIGEST_MISMATCH')
})

test('a one-byte-long range fails on digest', () => {
  assert.equal(only(anchor({ end_byte: 6 })).reason, 'EXCERPT_DIGEST_MISMATCH')
})

test('an unknown file_id is distinguished from a bad digest', () => {
  assert.equal(only(anchor({ file_id: 'file_' + '9'.repeat(64) })).reason, 'UNKNOWN_FILE_ID')
})

test('an anchor from another snapshot is rejected', () => {
  assert.equal(only(anchor({ snapshot_sha256: 'b'.repeat(64) })).reason, 'SNAPSHOT_MISMATCH')
})

test('an anchor into an unavailable file is rejected', () => {
  assert.equal(only(anchor({ file_id: 'file_' + '3'.repeat(64) })).reason, 'FILE_UNAVAILABLE')
})

test('a range past end of file is rejected before reading', () => {
  assert.equal(only(anchor({ start_byte: 0, end_byte: 999 })).reason, 'RANGE_OUT_OF_BOUNDS')
})

test('an inverted or empty range is rejected', () => {
  assert.equal(only(anchor({ start_byte: 5, end_byte: 5 })).reason, 'RANGE_INVALID')
  assert.equal(only(anchor({ start_byte: 6, end_byte: 2 })).reason, 'RANGE_INVALID')
})

test('a finding with no anchors yields no outcomes', () => {
  assert.deepEqual(verifySourceAnchors({}, SNAPSHOT), [])
})

test('anchorForLineRange round-trips through verification', () => {
  const built = anchorForLineRange(SNAPSHOT, 'a.txt', 2, 2)
  assert.equal(built.file_id, 'file_' + '1'.repeat(64))
  assert.equal(built.snapshot_sha256, ROOT)
  assert.deepEqual(only(built), { ok: true, file_id: built.file_id })
})

test('anchorForLineRange includes the line terminator', () => {
  const built = anchorForLineRange(SNAPSHOT, 'a.txt', 1, 1)
  assert.equal(built.start_byte, 0)
  assert.equal(built.end_byte, 6)
  assert.equal(built.excerpt_sha256, sha256(Buffer.from('alpha\n', 'utf8')))
})

test('anchorForLineRange keeps CR in a CRLF file', () => {
  const built = anchorForLineRange(SNAPSHOT, 'b.txt', 1, 1)
  assert.equal(built.excerpt_sha256, sha256(Buffer.from('delta\r\n', 'utf8')))
})

test('anchorForLineRange on the last line without trailing newline stops at EOF', () => {
  const noEol = Buffer.from('one\ntwo', 'utf8')
  const snapshot = {
    rootSha256: ROOT,
    index: {
      files: [{
        availability: 'AVAILABLE',
        file_id: 'file_' + '4'.repeat(64),
        path: 'd.txt',
        kind: 'text',
        size: noEol.length,
        shard: 'shard_000000',
        offset: 0,
        length: noEol.length,
      }],
      shards: [{ shard_id: 'shard_000000', size: noEol.length, sha256: sha256(noEol) }],
    },
    readBytes: (_id, offset, length) => noEol.subarray(offset, offset + length),
  }
  const built = anchorForLineRange(snapshot, 'd.txt', 2, 2)
  assert.equal(built.end_byte, noEol.length)
  assert.equal(built.excerpt_sha256, sha256(Buffer.from('two', 'utf8')))
})

test('anchorForLineRange rejects a path absent from the index', () => {
  assert.throws(() => anchorForLineRange(SNAPSHOT, 'nope.txt', 1, 1), /nope\.txt/)
})

test('anchorForLineRange rejects a line range beyond the file', () => {
  assert.throws(() => anchorForLineRange(SNAPSHOT, 'a.txt', 9, 9), /line/)
})
```

- [ ] **Step 2: Run the test and confirm it fails**

```bash
node --test test/anchor-verification.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND` — the module does not exist yet.

- [ ] **Step 3: Implement the module**

Create `scripts/lib/anchor-verification.mjs`:

```js
/**
 * Verify that a finding's quoted evidence is present in sealed source at the
 * byte offsets it claims.
 *
 * The byte reader is injected so this stays pure with respect to its inputs and
 * testable against a synthetic index. sealed-snapshot.mjs deliberately imports
 * only node:crypto, so the reader does not belong there.
 */
import { createHash } from 'node:crypto'

const ANCHORED_TIERS = new Set(['T1', 'T2', 'T3'])

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

export function requiresAnchorVerification(finding) {
  return ANCHORED_TIERS.has(finding?.proof_tier)
}

function findFile(index, fileId) {
  return (index?.files ?? []).find((file) => file.file_id === fileId)
}

function fail(fileId, reason, detail) {
  return { ok: false, file_id: fileId, reason, detail }
}

function verifyOne(anchor, snapshot) {
  const fileId = anchor?.file_id
  if (anchor?.snapshot_sha256 !== snapshot.rootSha256) {
    return fail(fileId, 'SNAPSHOT_MISMATCH', 'anchor was taken against a different snapshot')
  }
  const file = findFile(snapshot.index, fileId)
  if (file === undefined) {
    return fail(fileId, 'UNKNOWN_FILE_ID', 'no such file in the sealed index')
  }
  if (file.availability !== 'AVAILABLE') {
    return fail(fileId, 'FILE_UNAVAILABLE', `sealed file is ${file.availability}`)
  }
  const { start_byte: start, end_byte: end } = anchor
  if (!Number.isSafeInteger(start) || !Number.isSafeInteger(end) || start < 0 || end <= start) {
    return fail(fileId, 'RANGE_INVALID', 'range must be a non-empty ascending byte interval')
  }
  if (end > file.length) {
    return fail(fileId, 'RANGE_OUT_OF_BOUNDS', `range ends at ${end}, file is ${file.length} bytes`)
  }
  const bytes = snapshot.readBytes(file.shard, file.offset + start, end - start)
  if (sha256(bytes) !== anchor.excerpt_sha256) {
    return fail(fileId, 'EXCERPT_DIGEST_MISMATCH', 'sealed bytes do not hash to the claimed excerpt')
  }
  return { ok: true, file_id: fileId }
}

export function verifySourceAnchors(finding, snapshot) {
  const anchors = finding?.source_anchors
  if (!Array.isArray(anchors)) return []
  return anchors.map((anchor) => verifyOne(anchor, snapshot))
}

function lineStarts(bytes) {
  const starts = [0]
  for (let index = 0; index < bytes.length; index += 1) {
    if (bytes[index] === 0x0a && index + 1 < bytes.length) starts.push(index + 1)
  }
  return starts
}

export function anchorForLineRange(snapshot, path, startLine, endLine) {
  const file = (snapshot.index?.files ?? []).find((entry) => entry.path === path)
  if (file === undefined) {
    throw new Error(`no sealed file at path ${path}`)
  }
  if (file.availability !== 'AVAILABLE') {
    throw new Error(`sealed file ${path} is ${file.availability}`)
  }
  if (
    !Number.isSafeInteger(startLine) || !Number.isSafeInteger(endLine)
    || startLine < 1 || endLine < startLine
  ) {
    throw new Error('line range must be ascending 1-indexed integers')
  }
  const bytes = snapshot.readBytes(file.shard, file.offset, file.length)
  const starts = lineStarts(bytes)
  if (startLine > starts.length || endLine > starts.length) {
    throw new Error(`line ${Math.max(startLine, endLine)} is beyond ${path} (${starts.length} lines)`)
  }
  const start = starts[startLine - 1]
  const end = endLine < starts.length ? starts[endLine] : bytes.length
  return {
    file_id: file.file_id,
    snapshot_sha256: snapshot.rootSha256,
    start_byte: start,
    end_byte: end,
    excerpt_sha256: sha256(bytes.subarray(start, end)),
  }
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
node --test test/anchor-verification.test.mjs
```

Expected: 16 passing.

- [ ] **Step 5: Confirm the ordering guard still holds**

```bash
node --test test/canonical-ordering.test.mjs
```

Expected: all passing. The new module must not contain `localeCompare`.

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/anchor-verification.mjs test/anchor-verification.test.mjs
git commit -m "feat: verify source anchors against sealed snapshot bytes"
```

---

### Task 4: Require anchors for anchored tiers in the schema

A `T1`-or-above claim without `source_anchors` is unverifiable. Reject it at schema level so the contract states the requirement rather than leaving it to a runtime check.

**Files:**
- Modify: `schemas/finding.schema.json` — append to the existing `allOf`
- Test: `test/proof-tier-gate.test.mjs` (extend)

**Interfaces:**
- Consumes: nothing.
- Produces: schema rejection for anchored tiers lacking anchors.

- [ ] **Step 1: Write the failing test**

Append to `test/proof-tier-gate.test.mjs`:

```js
test('an anchored tier without source_anchors is invalid', () => {
  for (const tier of ['T1', 'T2', 'T3']) {
    const result = validateFinding(finding({ proof_tier: tier }))
    assert.equal(result.valid, false, `${tier} without anchors should be invalid`)
  }
})

test('an anchored tier with a source_anchor is schema-valid', () => {
  const result = validateFinding(finding({
    proof_tier: 'T1',
    source_anchors: [{
      file_id: 'file_' + '1'.repeat(64),
      snapshot_sha256: 'a'.repeat(64),
      start_byte: 0,
      end_byte: 5,
      excerpt_sha256: 'b'.repeat(64),
    }],
  }))
  const schemaErrors = result.errors.filter((error) => error.code.startsWith('SCHEMA_'))
  assert.deepEqual(schemaErrors, [])
})

test('T0 without source_anchors stays valid', () => {
  const result = validateFinding(finding({ proof_tier: 'T0', effective_severity: 'Medium' }))
  assert.equal(result.valid, true)
})
```

Schema failures are coded `SCHEMA_<KEYWORD>` by `normalizeAjvErrors`
(`contracts.mjs:324`), so the missing-anchors case surfaces as
`SCHEMA_REQUIRED`. That is why the filter matches on the prefix rather than an
exact code.

- [ ] **Step 2: Run the test and confirm it fails**

```bash
node --test test/proof-tier-gate.test.mjs
```

Expected: the anchored-tier-without-anchors test FAILS (currently valid).

- [ ] **Step 3: Add the conditional**

In `schemas/finding.schema.json`, append one entry to the existing top-level
`allOf` array, matching the `if`/`then` style already used there 18 times:

```json
{
  "if": { "properties": { "proof_tier": { "enum": ["T1", "T2", "T3"] } }, "required": ["proof_tier"] },
  "then": { "required": ["source_anchors"] }
}
```

`source_anchors` already declares `"minItems": 1`, so presence is enough — an
empty array is rejected by the existing definition.

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
node --test test/proof-tier-gate.test.mjs
```

Expected: 10 passing.

- [ ] **Step 5: Run the full suite**

```bash
node --test 2>&1 | tail -20
```

Expected: 750 tests, 747 passing, 1 skipped, 2 failing. If a pre-existing test
fixture declares `T1` with no anchors it will now fail — fix the fixture by
adding an anchor, not by weakening the schema.

- [ ] **Step 6: Commit**

```bash
git add schemas/finding.schema.json test/proof-tier-gate.test.mjs
git commit -m "feat: require source anchors for anchored proof tiers"
```

---

### Task 5: The `anchor` command

No run has ever produced an anchor. Byte offsets are not character offsets, and UTF-8 and CRLF both defeat naive arithmetic, so the controller issues anchors rather than asking providers to compute them. This also constrains a provider to evidence that exists.

**Files:**
- Modify: `scripts/audit.mjs` — `HELP` (line 198), `COMMAND_ARGUMENTS` (line 253), `main` dispatch (line 5556)
- Test: `test/anchor-command.test.mjs` (create)

**Interfaces:**
- Consumes: `anchorForLineRange` from Task 3.
- Produces: `loadSealedSnapshot(bundleDir)` returning `{ index, rootSha256, readBytes }`, reused by Task 6.

- [ ] **Step 1: Write the failing test**

Create `test/anchor-command.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readdirSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

function planSealed() {
  const out = mkdtempSync(join(tmpdir(), 'rta-anchor-'))
  execFileSync(process.execPath, [
    'scripts/audit.mjs', 'plan', 'fixtures/vulnerable', '--seal-source', '--out', out,
  ], { stdio: 'pipe' })
  return join(out, readdirSync(out).find((name) => name.startsWith('run_')))
}

function anchorCli(bundle, args) {
  return JSON.parse(execFileSync(process.execPath, [
    'scripts/audit.mjs', 'anchor', bundle, ...args,
  ], { encoding: 'utf8' }))
}

test('anchor emits a complete sourceAnchor for a line range', () => {
  const bundle = planSealed()
  const index = JSON.parse(
    readFileSync(join(bundle, 'snapshots', 'source', 'index.json'), 'utf8'),
  )
  const target = index.files.find((file) => file.availability === 'AVAILABLE')
  const anchor = anchorCli(bundle, [target.path, '--start-line', '1', '--end-line', '1'])
  assert.match(anchor.file_id, /^file_[a-f0-9]{64}$/)
  assert.match(anchor.snapshot_sha256, /^[a-f0-9]{64}$/)
  assert.equal(anchor.start_byte, 0)
  assert.ok(anchor.end_byte > 0)
  assert.match(anchor.excerpt_sha256, /^[a-f0-9]{64}$/)
})

test('anchor refuses a path that is not in the sealed index', () => {
  const bundle = planSealed()
  assert.throws(
    () => anchorCli(bundle, ['no/such/file.ts', '--start-line', '1', '--end-line', '1']),
    /no sealed file at path/,
  )
})

test('anchor refuses an unsealed bundle', () => {
  const out = mkdtempSync(join(tmpdir(), 'rta-unsealed-'))
  execFileSync(process.execPath, [
    'scripts/audit.mjs', 'plan', 'fixtures/vulnerable', '--out', out,
  ], { stdio: 'pipe' })
  const bundle = join(out, readdirSync(out).find((name) => name.startsWith('run_')))
  assert.throws(
    () => anchorCli(bundle, ['anything.ts', '--start-line', '1', '--end-line', '1']),
    /seal-source/,
  )
})
```

Delete the unused `path` line if the linter objects; it is a leftover guard.

- [ ] **Step 2: Run the test and confirm it fails**

```bash
node --test test/anchor-command.test.mjs
```

Expected: FAIL with `unknown command "anchor"`.

- [ ] **Step 3: Add the loader and the command**

In `scripts/audit.mjs`, near the other bundle-reading helpers:

```js
function loadSealedSnapshot(bundleDirectory) {
  const directory = join(bundleDirectory, 'snapshots', 'source')
  const indexPath = join(directory, 'index.json')
  if (!existsSync(indexPath)) {
    throw new Error(
      'bundle has no sealed source snapshot; re-plan with --seal-source',
    )
  }
  const indexBytes = readFileSync(indexPath)
  const index = JSON.parse(indexBytes.toString('utf8'))
  const rootSha256 = sha256(indexBytes)
  const shards = new Map()
  const readBytes = (shardId, offset, length) => {
    if (!shards.has(shardId)) {
      shards.set(shardId, readFileSync(join(directory, `${shardId}.bin`)))
    }
    return shards.get(shardId).subarray(offset, offset + length)
  }
  return { index, rootSha256, readBytes }
}

async function anchorCommand(positionals, options) {
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  const filePath = requirePositional(positionals, 1, 'repository-relative path')
  const snapshot = loadSealedSnapshot(loaded.directory)
  const startLine = Number.parseInt(options['start-line'], 10)
  const endLine = Number.parseInt(options['end-line'] ?? options['start-line'], 10)
  const anchor = anchorForLineRange(snapshot, filePath, startLine, endLine)
  process.stdout.write(`${stableJson(anchor)}\n`)
}
```

`loadRun(path)` returns `{ run, directory, path, sourceDigest }` and is how
every other bundle command resolves its first positional — see `ingestCommand`
at `audit.mjs:5161`. Reuse the file's existing `sha256` helper and its
`join`/`readFileSync`/`existsSync` imports; add only what is missing.

Import the builder at the top of the file:

```js
import { anchorForLineRange, verifySourceAnchors, requiresAnchorVerification } from './lib/anchor-verification.mjs'
```

Register the argument shape in `COMMAND_ARGUMENTS`:

```js
  anchor: {
    positionals: 2,
    options: { 'start-line': 'value', 'end-line': 'value' },
  },
```

Dispatch it in `main`, after `compare`:

```js
  if (command === 'anchor') return anchorCommand(positionals, options)
```

Add one `HELP` line, matching the surrounding format:

```
  red-team-audit anchor <run.json|bundle-directory> <repository-relative-path> --start-line <n> [--end-line <n>]
```

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
node --test test/anchor-command.test.mjs
```

Expected: 3 passing.

- [ ] **Step 5: Check the CLI by hand**

```bash
node scripts/audit.mjs plan fixtures/vulnerable --seal-source --out /tmp/anchor-demo
node scripts/audit.mjs anchor /tmp/anchor-demo/run_* app.js --start-line 1 --end-line 3
```

Expected: a JSON object with all five anchor fields. Substitute any path that
appears in the sealed index if `app.js` is absent.

- [ ] **Step 6: Run the full suite and commit**

```bash
node --test 2>&1 | tail -20
git add scripts/audit.mjs test/anchor-command.test.mjs
git commit -m "feat: add the anchor command for controller-issued source anchors"
```

Expected before committing: 753 tests, 750 passing, 1 skipped, 2 failing.

---

### Task 6: Verify anchors at ingest

Verification must happen inside the write-once boundary, so a result whose evidence is not in the sealed bytes is never partially applied. A failed anchor rejects the result: a provider asserting evidence it did not read is exactly what the platform exists to catch, and downgrading silently would discard that signal.

**Files:**
- Modify: `scripts/audit.mjs` — `prepareOneResult`
- Test: `test/anchor-command.test.mjs` (extend)

**Interfaces:**
- Consumes: `verifySourceAnchors`, `requiresAnchorVerification` (Task 3), `loadSealedSnapshot` (Task 5).
- Produces: ingest rejection naming the failing anchor and reason.

- [ ] **Step 1: Write the failing test**

Append to `test/anchor-command.test.mjs`:

```js
import { writeFileSync } from 'node:fs'

test('ingest rejects a T1 finding whose anchor does not verify', () => {
  const bundle = planSealed()
  const packet = JSON.parse(execFileSync(process.execPath, [
    'scripts/audit.mjs', 'next', bundle,
  ], { encoding: 'utf8' })).pending_jobs[0]

  const result = {
    schema_version: '1.0.0',
    run_id: packet.run_id,
    job_id: packet.job_id,
    input_sha256: packet.packet_sha256,
    state: 'SUCCEEDED',
    producer: { name: 'test', version: '1' },
    examined_files: packet.scoped_files,
    findings: [{
      candidate_id: 'cand:test:001',
      lens: packet.lens,
      topic: packet.owned_topics[0],
      title: 'Fabricated evidence that is not in the sealed bytes',
      claimed_impact_severity: 'Critical',
      effective_severity: 'Critical',
      location: [`${packet.scoped_files[0]}:1`],
      evidence: 'this text was never read',
      reachable_from: 'GET /',
      proof_tier: 'T1',
      verification_status: 'CONFIRMED',
      source_anchors: [{
        file_id: 'file_' + '1'.repeat(64),
        snapshot_sha256: 'a'.repeat(64),
        start_byte: 0,
        end_byte: 5,
        excerpt_sha256: 'b'.repeat(64),
      }],
    }],
  }
  const resultPath = join(mkdtempSync(join(tmpdir(), 'rta-result-')), 'result.json')
  writeFileSync(resultPath, JSON.stringify(result))

  assert.throws(
    () => execFileSync(process.execPath, ['scripts/audit.mjs', 'ingest', bundle, resultPath], { stdio: 'pipe' }),
    /SNAPSHOT_MISMATCH|anchor/i,
  )
})
```

The result fixture must satisfy `schemas/job-result.schema.json`; read its
`required` list and add any missing field rather than guessing. The assertion is
on rejection, so extra valid fields are harmless.

- [ ] **Step 2: Run the test and confirm it fails**

```bash
node --test test/anchor-command.test.mjs
```

Expected: FAIL — the result is currently ingested without anchor checking.

- [ ] **Step 3: Wire verification into ingest**

Add a shared helper in `scripts/audit.mjs`:

```js
function assertAnchorsVerify(bundleDirectory, jobResult) {
  const findings = (jobResult?.findings ?? []).filter(requiresAnchorVerification)
  if (findings.length === 0) return
  const snapshot = loadSealedSnapshot(bundleDirectory)
  for (const finding of findings) {
    for (const outcome of verifySourceAnchors(finding, snapshot)) {
      if (outcome.ok) continue
      throw new Error(
        `finding ${finding.candidate_id} anchor ${outcome.file_id} failed ` +
        `verification: ${outcome.reason} — ${outcome.detail}`,
      )
    }
  }
}
```

Call it from inside `prepareOneResult`, after `jobResult` has been read and
schema-validated and before that function returns. Both `ingestCommand` and
`ingestBatchCommand` funnel through `prepareOneResult`, so one call covers both
and neither needs a signature change. `prepareOneResult` does not return the
parsed `jobResult`, which is the other reason the check belongs there rather
than in `ingestOneResult`.

Placement matters: `ingestOneResult` calls `prepareOneResult` and only then
`writeOnceBundleArtifact`. Verifying inside preparation means a rejected result
throws before any artifact is written and before `persistRun`, so the bundle is
untouched.

The call needs the bundle directory, which is available as `loaded.directory`
inside `prepareOneResult`:

```js
  assertAnchorsVerify(loaded.directory, jobResult)
```

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
node --test test/anchor-command.test.mjs
```

Expected: 4 passing.

- [ ] **Step 5: Prove the happy path with a real anchor**

```bash
node scripts/audit.mjs plan fixtures/vulnerable --seal-source --out /tmp/ingest-demo
node scripts/audit.mjs anchor /tmp/ingest-demo/run_* <a path from the index> --start-line 1
```

Build a job result using that anchor verbatim and ingest it. Expected: accepted.
This confirms the rejection in Step 1 is specific to bad anchors rather than
rejecting everything.

- [ ] **Step 6: Run the full suite and commit**

```bash
node --test 2>&1 | tail -20
git add scripts/audit.mjs test/anchor-command.test.mjs
git commit -m "feat: verify source anchors before ingesting anchored findings"
```

Expected before committing: 754 tests, 751 passing, 1 skipped, 2 failing.

---

### Task 7: Document the provider rule

`SKILL.md` drives the agent that produces findings. Without a rule there, nothing will ever emit an anchor and the whole change stays dormant.

**Files:**
- Modify: `skills/red-team-audit/SKILL.md`
- Test: `node scripts/lint-lenses.mjs` (byte-budget gate)

**Interfaces:**
- Consumes: the `anchor` command from Task 5.
- Produces: nothing.

- [ ] **Step 1: Check the byte budget before editing**

```bash
wc -c skills/red-team-audit/SKILL.md
grep -n "MAX_SKILL_BYTES" scripts/lint-lenses.mjs
```

The file is capped at 8000 bytes and was last measured at 7991 — about 9 bytes
of headroom. Adding the rule below requires compressing existing prose by
roughly as many bytes as you add. Prefer tightening wordy sentences over
deleting any rule.

- [ ] **Step 2: Add the rule**

In the per-packet instructions, after the step describing the job result:

```
Claim `proof_tier: T1` only with anchors from `audit -- anchor <bundle> <path>
--start-line <n> [--end-line <n>]`. Never hand-compute one. No anchors means
`T0`, which caps effective severity at Medium and is a legitimate result.
```

- [ ] **Step 3: Verify the budget and the lint gate**

```bash
wc -c skills/red-team-audit/SKILL.md
node scripts/lint-lenses.mjs
```

Expected: under 8000 bytes, and `PASS: R1-R8, SKILL and ledger gate clean.`

- [ ] **Step 4: Run the full suite**

```bash
node --test 2>&1 | tail -20
```

Expected: 754 tests, 751 passing, 1 skipped, 2 failing.

- [ ] **Step 5: Commit**

```bash
git add skills/red-team-audit/SKILL.md
git commit -m "docs: require controller-issued anchors for anchored proof tiers"
```

---

## Acceptance

The change is complete when a sealed audit of `fixtures/vulnerable` can carry a
finding at `T1`/`CONFIRMED` with concrete reachability and a verifying anchor,
and that finding reports `effective_severity: Critical` — while the same finding
reports Medium if its tier is `T0`, if its reachability is `unknown`, or if the
run was planned without `--seal-source`.

Final expected suite state: **754 tests, 751 passing, 1 skipped, 2 failing**,
where the 2 failures remain the pre-existing ripgrep pair in
`test/cloud-iac-fixtures.test.mjs`.

## Not in this plan

`T2` and `T3` mechanics — the disposable-instance harness, the RoE capability
grammar, the proof broker, and the invariant that no proof step may read, write,
or transmit protected health information. This plan builds the ladder those
tiers attach to and delivers the two rungs that need no execution at all.

Test counts in each task assume the tasks run in order. If you reorder them,
recompute rather than trusting the stated numbers.
