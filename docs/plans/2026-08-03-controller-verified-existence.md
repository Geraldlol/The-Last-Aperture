# Controller-Verified Existence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the controller independently verify that a finding's quoted evidence is really at the location it cites, and that a finding's absence claim really holds, instead of accepting the provider's word for both.

**Architecture:** Providers gain two optional, immutable claim fields — `quotes` and `absence_claims` — that an LLM can actually produce (a path, a line, verbatim text). The controller checks them against the decoded file content it *already holds in memory* from the inventory pass that `verifyRepositorySnapshot` runs on every ingest, and writes its verdicts to a controller-owned `run.existence_verifications` that is recomputed during `validate` rather than stamped onto immutable finding fields. An opt-in plan-time policy turns the verdicts into a finalization gate.

**Tech Stack:** Node.js 20+, ESM (`.mjs`), `node:test` + `node:assert/strict`, JSON Schema Draft 2020-12 via ajv 8.

**The two load-bearing modules in this plan are pre-verified.** `matchQuote` (Task 2) and `searchAbsence` (Task 3) were extracted and run standalone before this plan was written: 14/14 and 7/7 passing, including the byte-offset arithmetic across CRLF and non-ASCII lines and the sibling-directory scope-prefix case. The code in those tasks is transcribed from a working run, not sketched.

## Global Constraints

- Branch: `agent/red-team-audit-v11-existence`. Already created.
- Baseline before this work: **778 tests, 775 pass, 1 skipped, 2 failing.** The 2 failures are `cloud-iac-fixtures.test.mjs` needing ripgrep, which this machine lacks. They are environmental and must not be counted as regressions or "fixed".
- `skills/red-team-audit/SKILL.md` is **7,995 of 8,000 bytes**. Do not add prose to it. Documentation goes to `skills/red-team-audit/lenses/_schema.md`.
- `npm.cmd run lint` must stay `PASS: R1-R8, SKILL and ledger gate clean` after every task.
- `npm.cmd run gen -- --check` must stay PASS at 174 slugs.
- Run commands with `npm.cmd`, not `npm` — this is Windows with Git Bash.
- Every schema object in this repo uses `"additionalProperties": false`. Keep it.
- Ordering must be locale-independent (ADR 0012). Use `compareCanonicalStrings` from `scripts/lib/canonical-order.mjs`, never `localeCompare`.
- Do not use `Date.now()` for anything that lands in an attested digest.

---

### Task 1: The two provider claim fields

**Files:**
- Modify: `schemas/finding.schema.json`
- Modify: `scripts/lib/contracts.mjs:107-131` (`STAGE_ONE_FIELDS`)
- Test: `test/existence-claims.test.mjs` (create)

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: the `quotes` and `absence_claims` shapes every later task reads.
  - `quotes: Array<{ path: string, line: integer>=1, text: string }>`
  - `absence_claims: Array<{ pattern: string, kind: 'literal'|'literal_ci', scope: string[] }>`

- [ ] **Step 1: Write the failing test**

Create `test/existence-claims.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { validateFinding } from '../scripts/lib/contracts.mjs'

function stageOne(overrides = {}) {
  return {
    candidate_id: 'authz-object-level:a3f19c2e',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Invoice route loads another tenant by identifier',
    claimed_impact_severity: 'High',
    location: ['src/routes/invoices.ts:88'],
    cwe: 'CWE-639',
    evidence: 'const invoice = await repo.findById(req.params.id)',
    attack: 'GET /api/invoices/8814 while authenticated to another tenant',
    impact: 'Reads another tenant invoice and billing address',
    reachable_from: 'GET /api/invoices/:id',
    confidence: 'High',
    proof_plan: 'Request subject A invoice as subject B and assert refusal',
    ...overrides,
  }
}

test('a finding may carry quotes', () => {
  const errors = validateFinding(stageOne({
    quotes: [{
      path: 'src/routes/invoices.ts',
      line: 88,
      text: 'const invoice = await repo.findById(req.params.id)',
    }],
  }))
  assert.deepEqual(errors, [])
})

test('a finding may carry absence claims', () => {
  const errors = validateFinding(stageOne({
    absence_claims: [{
      pattern: 'constantTimeEquals',
      kind: 'literal',
      scope: ['src/routes'],
    }],
  }))
  assert.deepEqual(errors, [])
})

test('a quote line must be a positive integer', () => {
  const errors = validateFinding(stageOne({
    quotes: [{ path: 'src/routes/invoices.ts', line: 0, text: 'x' }],
  }))
  assert.ok(errors.length > 0)
})

test('an absence claim rejects an empty scope', () => {
  const errors = validateFinding(stageOne({
    absence_claims: [{ pattern: 'x', kind: 'literal', scope: [] }],
  }))
  assert.ok(errors.length > 0)
})

test('an absence claim rejects a regex kind', () => {
  const errors = validateFinding(stageOne({
    absence_claims: [{ pattern: 'x', kind: 'regex', scope: ['src'] }],
  }))
  assert.ok(errors.length > 0)
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm.cmd test -- --test-name-pattern="carry quotes"`
Expected: FAIL — ajv rejects `quotes` because `finding.schema.json` sets `additionalProperties: false`.

`validateFinding` is exported at `contracts.mjs:827` and returns an array of errors. `assertValidFindingTransition` is at `contracts.mjs:1018`.

- [ ] **Step 3: Add the schema definitions**

In `schemas/finding.schema.json`, add to `$defs`:

```json
"findingQuote": {
  "type": "object",
  "additionalProperties": false,
  "required": ["path", "line", "text"],
  "properties": {
    "path": { "type": "string", "minLength": 1, "maxLength": 1024 },
    "line": { "type": "integer", "minimum": 1 },
    "text": { "type": "string", "minLength": 1, "maxLength": 4096 }
  }
},
"absenceClaim": {
  "type": "object",
  "additionalProperties": false,
  "required": ["pattern", "kind", "scope"],
  "properties": {
    "pattern": { "type": "string", "minLength": 1, "maxLength": 512 },
    "kind": { "enum": ["literal", "literal_ci"] },
    "scope": {
      "type": "array",
      "minItems": 1,
      "maxItems": 64,
      "items": { "type": "string", "minLength": 1, "maxLength": 1024 }
    }
  }
}
```

And to `properties`, immediately after `source_anchors`:

```json
"quotes": {
  "type": "array",
  "minItems": 1,
  "maxItems": 32,
  "items": { "$ref": "#/$defs/findingQuote" }
},
"absence_claims": {
  "type": "array",
  "minItems": 1,
  "maxItems": 16,
  "items": { "$ref": "#/$defs/absenceClaim" }
}
```

Both stay out of `required` — they are optional.

- [ ] **Step 4: Add both to the immutable claim set**

In `scripts/lib/contracts.mjs`, inside `STAGE_ONE_FIELDS` (starts line 107), add after `'source_anchors',`:

```js
  'quotes',
  'absence_claims',
```

- [ ] **Step 5: Run the new tests and the full suite**

Run: `npm.cmd test 2>&1 | grep -aE "^. (tests|pass|fail|skipped) "`
Expected: 783 tests, 780 pass, 1 skipped, 2 fail (the ripgrep pair).

- [ ] **Step 6: Verify immutability actually bites**

Add to `test/existence-claims.test.mjs`:

```js
import { assertValidFindingTransition } from '../scripts/lib/contracts.mjs'

test('quotes cannot change across a transition', () => {
  const before = stageOne({
    quotes: [{ path: 'src/routes/invoices.ts', line: 88, text: 'a' }],
  })
  const after = structuredClone(before)
  after.quotes[0].text = 'b'
  assert.throws(() => assertValidFindingTransition(before, after), /immutable/i)
})
```

Run: `npm.cmd test -- --test-name-pattern="cannot change across"`
Expected: PASS — `CLAIM_FIELD_CHANGED`, because Step 4 put `quotes` in `STAGE_ONE_FIELDS`.

- [ ] **Step 7: Commit**

```bash
git add schemas/finding.schema.json scripts/lib/contracts.mjs test/existence-claims.test.mjs
git commit -m "feat: admit machine-checkable quote and absence claims on a finding"
```

---

### Task 2: The quote matcher

**Files:**
- Create: `scripts/lib/existence-matcher.mjs`
- Test: `test/existence-matcher.test.mjs` (create)

**Interfaces:**
- Consumes: the `quotes` shape from Task 1.
- Produces:
  - `indexFileLines(content) -> { lines: string[], normalized: string[], byteStarts: number[], byteEnds: number[] }` — `byteStarts[i]`/`byteEnds[i]` bracket line `i`'s content in UTF-8 bytes, excluding the terminator.
  - `normalizeQuote(text) -> string[]`
  - `matchQuote(content, quoteText, claimedLine) -> { outcome, foundLine, matchCount, startByte, endByte }` where `outcome` is `'LOCATED' | 'LOCATED_OFF_LINE' | 'NOT_LOCATED'`. On `NOT_LOCATED`, `foundLine`, `startByte` and `endByte` are `null` and `matchCount` is `0` — `match_count` is a required non-nullable integer in the Task 4 schema, so it must never be null.

- [ ] **Step 1: Write the failing test**

Create `test/existence-matcher.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { matchQuote, normalizeQuote } from '../scripts/lib/existence-matcher.mjs'

const FILE = [
  'resource pg "Microsoft.DBforPostgreSQL" = {',
  '  properties: {',
  "    publicNetworkAccess: 'Enabled'",
  '  }',
  '}',
].join('\n')

test('an exact quote at the claimed line is LOCATED', () => {
  const r = matchQuote(FILE, "    publicNetworkAccess: 'Enabled'", 3)
  assert.equal(r.outcome, 'LOCATED')
  assert.equal(r.foundLine, 3)
  assert.equal(r.matchCount, 1)
})

test('a re-indented quote is still LOCATED', () => {
  const r = matchQuote(FILE, "publicNetworkAccess: 'Enabled'", 3)
  assert.equal(r.outcome, 'LOCATED')
  assert.equal(r.foundLine, 3)
})

test('a tab-indented quote matches a space-indented file', () => {
  const r = matchQuote(FILE, "\t\tpublicNetworkAccess: 'Enabled'", 3)
  assert.equal(r.outcome, 'LOCATED')
})

test('correct content at the wrong line is LOCATED_OFF_LINE', () => {
  const r = matchQuote(FILE, "publicNetworkAccess: 'Enabled'", 27)
  assert.equal(r.outcome, 'LOCATED_OFF_LINE')
  assert.equal(r.foundLine, 3)
})

test('fabricated content is NOT_LOCATED', () => {
  const r = matchQuote(FILE, "publicNetworkAccess: 'Disabled'", 3)
  assert.equal(r.outcome, 'NOT_LOCATED')
  assert.equal(r.foundLine, null)
})

test('a multi-line quote must match contiguously', () => {
  const good = matchQuote(FILE, "properties: {\npublicNetworkAccess: 'Enabled'", 2)
  assert.equal(good.outcome, 'LOCATED')
  const bad = matchQuote(FILE, "properties: {\n}", 2)
  assert.equal(bad.outcome, 'NOT_LOCATED')
})

test('CRLF in the file matches an LF quote', () => {
  const crlf = FILE.replaceAll('\n', '\r\n')
  assert.equal(matchQuote(crlf, "publicNetworkAccess: 'Enabled'", 3).outcome, 'LOCATED')
})

test('CR-only line endings are handled', () => {
  const cr = FILE.replaceAll('\n', '\r')
  assert.equal(matchQuote(cr, "publicNetworkAccess: 'Enabled'", 3).outcome, 'LOCATED')
})

test('byte offsets bracket the matched text', () => {
  const r = matchQuote(FILE, "publicNetworkAccess: 'Enabled'", 3)
  const bytes = Buffer.from(FILE, 'utf8').subarray(r.startByte, r.endByte)
  assert.equal(bytes.toString('utf8'), "publicNetworkAccess: 'Enabled'")
})

test('byte offsets are correct after a non-ASCII line', () => {
  const content = ['// café — note', 'const x = 1'].join('\n')
  const r = matchQuote(content, 'const x = 1', 2)
  const bytes = Buffer.from(content, 'utf8').subarray(r.startByte, r.endByte)
  assert.equal(bytes.toString('utf8'), 'const x = 1')
})

test('CRLF byte offsets are correct', () => {
  const crlf = FILE.replaceAll('\n', '\r\n')
  const r = matchQuote(crlf, "publicNetworkAccess: 'Enabled'", 3)
  const bytes = Buffer.from(crlf, 'utf8').subarray(r.startByte, r.endByte)
  assert.equal(bytes.toString('utf8'), "publicNetworkAccess: 'Enabled'")
})

test('a multi-line byte span covers both lines including the terminator', () => {
  const r = matchQuote(FILE, "properties: {\npublicNetworkAccess: 'Enabled'", 2)
  const bytes = Buffer.from(FILE, 'utf8').subarray(r.startByte, r.endByte)
  assert.equal(bytes.toString('utf8'), "properties: {\n    publicNetworkAccess: 'Enabled'")
})

test('the nearest occurrence to the claimed line wins and matchCount reports all', () => {
  const repeated = ['a', 'dup', 'b', 'dup', 'c'].join('\n')
  const r = matchQuote(repeated, 'dup', 4)
  assert.equal(r.foundLine, 4)
  assert.equal(r.matchCount, 2)
})

test('a quote that normalizes to nothing never matches', () => {
  assert.deepEqual(normalizeQuote('   \n\t\n  '), [])
  assert.equal(matchQuote(FILE, '   \n  ', 1).outcome, 'NOT_LOCATED')
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm.cmd test -- test/existence-matcher.test.mjs`
Expected: FAIL — `Cannot find module '../scripts/lib/existence-matcher.mjs'`.

- [ ] **Step 3: Implement the matcher**

Create `scripts/lib/existence-matcher.mjs`:

```js
const HORIZONTAL_WHITESPACE = /^[ \t]+|[ \t]+$/g

function trimHorizontal(line) {
  return line.replace(HORIZONTAL_WHITESPACE, '')
}

export function normalizeQuote(text) {
  const lines = String(text).split(/\r\n|\n|\r/).map(trimHorizontal)
  let start = 0
  let end = lines.length
  while (start < end && lines[start] === '') start += 1
  while (end > start && lines[end - 1] === '') end -= 1
  return lines.slice(start, end)
}

export function indexFileLines(content) {
  const text = String(content)
  const lines = []
  const byteStarts = []
  const byteEnds = []
  let byteCursor = 0
  let index = 0
  while (index <= text.length) {
    let breakAt = text.length
    let terminator = 0
    for (let scan = index; scan < text.length; scan += 1) {
      const ch = text[scan]
      if (ch === '\n') {
        breakAt = scan
        terminator = 1
        break
      }
      if (ch === '\r') {
        breakAt = scan
        terminator = text[scan + 1] === '\n' ? 2 : 1
        break
      }
    }
    const line = text.slice(index, breakAt)
    const lineBytes = Buffer.byteLength(line, 'utf8')
    lines.push(line)
    byteStarts.push(byteCursor)
    byteEnds.push(byteCursor + lineBytes)
    byteCursor += lineBytes + (
      terminator === 0
        ? 0
        : Buffer.byteLength(text.slice(breakAt, breakAt + terminator), 'utf8')
    )
    if (terminator === 0) break
    index = breakAt + terminator
  }
  return {
    lines,
    normalized: lines.map(trimHorizontal),
    byteStarts,
    byteEnds,
  }
}

function leadingWhitespaceBytes(line) {
  const trimmedStart = line.length - line.replace(/^[ \t]+/, '').length
  return Buffer.byteLength(line.slice(0, trimmedStart), 'utf8')
}

function trailingWhitespaceBytes(line) {
  const trimmedEnd = line.length - line.replace(/[ \t]+$/, '').length
  return Buffer.byteLength(line.slice(line.length - trimmedEnd), 'utf8')
}

export function matchQuote(content, quoteText, claimedLine) {
  const miss = {
    outcome: 'NOT_LOCATED',
    foundLine: null,
    matchCount: 0,
    startByte: null,
    endByte: null,
  }
  const needle = normalizeQuote(quoteText)
  if (needle.length === 0) return miss

  const file = indexFileLines(content)
  const starts = []
  const limit = file.normalized.length - needle.length
  for (let offset = 0; offset <= limit; offset += 1) {
    let matched = true
    for (let step = 0; step < needle.length; step += 1) {
      if (file.normalized[offset + step] !== needle[step]) {
        matched = false
        break
      }
    }
    if (matched) starts.push(offset)
  }
  if (starts.length === 0) return miss

  const target = Number.isInteger(claimedLine) ? claimedLine - 1 : 0
  let best = starts[0]
  for (const candidate of starts) {
    if (Math.abs(candidate - target) < Math.abs(best - target)) best = candidate
  }

  const lastIndex = best + needle.length - 1
  const startByte = file.byteStarts[best]
    + leadingWhitespaceBytes(file.lines[best])
  const endByte = file.byteEnds[lastIndex]
    - trailingWhitespaceBytes(file.lines[lastIndex])

  return {
    outcome: best === target ? 'LOCATED' : 'LOCATED_OFF_LINE',
    foundLine: best + 1,
    matchCount: starts.length,
    startByte,
    endByte,
  }
}
```

- [ ] **Step 4: Run the tests**

Run: `npm.cmd test -- test/existence-matcher.test.mjs`
Expected: PASS, 12 tests.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/existence-matcher.mjs test/existence-matcher.test.mjs
git commit -m "feat: per-line trimmed contiguous quote matcher with byte anchors"
```

---

### Task 3: The absence search

**Files:**
- Modify: `scripts/lib/existence-matcher.mjs`
- Modify: `test/existence-matcher.test.mjs`

**Interfaces:**
- Consumes: `absence_claims` from Task 1; inventory entries shaped `{ path, kind, content }` as produced by `inventory.mjs:523-532`.
- Produces: `searchAbsence(entries, claim) -> { outcome, matchCount, searchedFiles, hits }` where `outcome` is `'ABSENCE_HOLDS' | 'ABSENCE_CONTRADICTED' | 'ABSENCE_UNCHECKABLE'` and `hits` is at most 16 `{ path, line }` in canonical path order.

- [ ] **Step 1: Write the failing test**

Append to `test/existence-matcher.test.mjs`:

```js
import { searchAbsence } from '../scripts/lib/existence-matcher.mjs'

const ENTRIES = [
  { path: 'src/a.cls', kind: 'text', content: 'void f() {}\nBoolean ok = constantTimeEquals(x, y);' },
  { path: 'src/b.cls', kind: 'text', content: 'void g() {}' },
  { path: 'docs/n.md', kind: 'text', content: 'mentions ConstantTimeEquals here' },
  { path: 'bin/blob.png', kind: 'binary', content: null },
]

test('an absence that holds reports ABSENCE_HOLDS', () => {
  const r = searchAbsence(ENTRIES, {
    pattern: 'notPresentAnywhere', kind: 'literal', scope: ['src'],
  })
  assert.equal(r.outcome, 'ABSENCE_HOLDS')
  assert.equal(r.matchCount, 0)
  assert.equal(r.searchedFiles, 2)
})

test('a contradicted absence names where', () => {
  const r = searchAbsence(ENTRIES, {
    pattern: 'constantTimeEquals', kind: 'literal', scope: ['src'],
  })
  assert.equal(r.outcome, 'ABSENCE_CONTRADICTED')
  assert.equal(r.matchCount, 1)
  assert.deepEqual(r.hits, [{ path: 'src/a.cls', line: 2 }])
})

test('scope restricts the search', () => {
  const r = searchAbsence(ENTRIES, {
    pattern: 'constantTimeEquals', kind: 'literal', scope: ['src/b.cls'],
  })
  assert.equal(r.outcome, 'ABSENCE_HOLDS')
  assert.equal(r.searchedFiles, 1)
})

test('literal_ci matches a differently cased occurrence', () => {
  const sensitive = searchAbsence(ENTRIES, {
    pattern: 'constanttimeequals', kind: 'literal', scope: ['docs'],
  })
  assert.equal(sensitive.outcome, 'ABSENCE_HOLDS')
  const insensitive = searchAbsence(ENTRIES, {
    pattern: 'constanttimeequals', kind: 'literal_ci', scope: ['docs'],
  })
  assert.equal(insensitive.outcome, 'ABSENCE_CONTRADICTED')
})

test('a scope matching no inventory entry is UNCHECKABLE, never HOLDS', () => {
  const r = searchAbsence(ENTRIES, {
    pattern: 'anything', kind: 'literal', scope: ['src/typo-does-not-exist'],
  })
  assert.equal(r.outcome, 'ABSENCE_UNCHECKABLE')
  assert.equal(r.searchedFiles, 0)
})

test('a scope of only binary entries is UNCHECKABLE', () => {
  const r = searchAbsence(ENTRIES, {
    pattern: 'anything', kind: 'literal', scope: ['bin'],
  })
  assert.equal(r.outcome, 'ABSENCE_UNCHECKABLE')
  assert.equal(r.searchedFiles, 0)
})

test('a scope prefix does not leak into a sibling directory', () => {
  const entries = [{ path: 'srcx/a.ts', kind: 'text', content: 'boom' }]
  const r = searchAbsence(entries, {
    pattern: 'boom', kind: 'literal', scope: ['src'],
  })
  assert.equal(r.outcome, 'ABSENCE_UNCHECKABLE')
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm.cmd test -- test/existence-matcher.test.mjs`
Expected: FAIL — `searchAbsence` is not exported.

- [ ] **Step 3: Implement the search**

Append to `scripts/lib/existence-matcher.mjs`:

```js
import { compareCanonicalStrings } from './canonical-order.mjs'

const MAX_RECORDED_HITS = 16

function inScope(path, scope) {
  return scope.some((prefix) => path === prefix || path.startsWith(`${prefix}/`))
}

export function searchAbsence(entries, claim) {
  const scope = [...claim.scope]
  const fold = claim.kind === 'literal_ci'
  const needle = fold ? claim.pattern.toLowerCase() : claim.pattern

  const searchable = entries
    .filter((entry) =>
      entry.kind === 'text'
      && typeof entry.content === 'string'
      && inScope(entry.path, scope))
    .sort((left, right) => compareCanonicalStrings(left.path, right.path))

  if (searchable.length === 0) {
    return {
      outcome: 'ABSENCE_UNCHECKABLE',
      matchCount: 0,
      searchedFiles: 0,
      hits: [],
    }
  }

  let matchCount = 0
  const hits = []
  for (const entry of searchable) {
    const lines = String(entry.content).split(/\r\n|\n|\r/)
    for (let index = 0; index < lines.length; index += 1) {
      const haystack = fold ? lines[index].toLowerCase() : lines[index]
      if (!haystack.includes(needle)) continue
      matchCount += 1
      if (hits.length < MAX_RECORDED_HITS) {
        hits.push({ path: entry.path, line: index + 1 })
      }
    }
  }

  return {
    outcome: matchCount > 0 ? 'ABSENCE_CONTRADICTED' : 'ABSENCE_HOLDS',
    matchCount,
    searchedFiles: searchable.length,
    hits,
  }
}
```

Move the `import` line to the top of the file with the other imports.

- [ ] **Step 4: Run the tests**

Run: `npm.cmd test -- test/existence-matcher.test.mjs`
Expected: PASS, 18 tests.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/existence-matcher.mjs test/existence-matcher.test.mjs
git commit -m "feat: bounded literal absence search that refuses to clear an empty scope"
```

---

### Task 4: Schema 7.0.0

**Files:**
- Modify: `schemas/run.schema.json`
- Modify: every file listed by `grep -rln "'6\.0\.0'" scripts/`
- Test: `test/existence-schema-version.test.mjs` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: `'7.0.0'` accepted everywhere `'6.0.0'` is, and a new optional top-level `run.existence_verifications`.

**Why a bump:** `run.schema.json` is `additionalProperties: false` with a `schema_version` enum capped at `6.0.0`. The version is also the signal that verdicts are present and re-derivable — without it, a missing `existence_verifications` is ambiguous between "not computed" and "computed and empty", which this platform does not tolerate.

**The hazard:** there are 24 sites in `scripts/` holding literal version arrays like `['3.0.0', '4.0.0', '5.0.0', '6.0.0']`, and they do not all share a floor. Missing one means a 7.0.0 run silently loses a modern behaviour — a fail-open regression. Do not blanket sed. Add `'7.0.0'` to the end of each array, preserving each array's distinct floor, then rely on the lifecycle test below to catch a miss.

- [ ] **Step 1: Write the failing test**

Create `test/existence-schema-version.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

test('run schema admits 7.0.0', () => {
  const schema = JSON.parse(readFileSync('schemas/run.schema.json', 'utf8'))
  assert.ok(schema.properties.schema_version.enum.includes('7.0.0'))
})

test('run schema declares existence_verifications', () => {
  const schema = JSON.parse(readFileSync('schemas/run.schema.json', 'utf8'))
  assert.ok(schema.properties.existence_verifications)
})

test('no version gate in scripts stops at 6.0.0', () => {
  const files = ['scripts/audit.mjs', 'scripts/lib/contracts.mjs',
    'scripts/lib/job-protocol.mjs', 'scripts/lib/attempts.mjs']
  const offenders = []
  for (const file of files) {
    const source = readFileSync(file, 'utf8')
    const pattern = /\[[^\]\n]*'6\.0\.0'[^\]\n]*\]/g
    for (const [array] of source.matchAll(pattern)) {
      if (!array.includes('7.0.0')) offenders.push(`${file}: ${array}`)
    }
  }
  assert.deepEqual(offenders, [])
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm.cmd test -- test/existence-schema-version.test.mjs`
Expected: FAIL on all three.

- [ ] **Step 3: Update the run schema**

In `schemas/run.schema.json`, add `"7.0.0"` to the `schema_version` enum, and add to `properties`:

```json
"existence_verifications": {
  "type": "array",
  "maxItems": 4096,
  "items": { "$ref": "#/$defs/existenceVerification" }
}
```

Add to `$defs`:

```json
"existenceVerification": {
  "type": "object",
  "additionalProperties": false,
  "required": ["candidate_id", "quote_results", "absence_results", "outcome"],
  "properties": {
    "candidate_id": { "type": "string", "minLength": 1, "maxLength": 200 },
    "outcome": {
      "enum": ["VERIFIED", "DRIFTED", "UNVERIFIED", "NOT_APPLICABLE", "NOT_REDERIVABLE"]
    },
    "quote_results": {
      "type": "array",
      "maxItems": 32,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["index", "outcome", "claimed_line", "match_count"],
        "properties": {
          "index": { "type": "integer", "minimum": 0 },
          "outcome": { "enum": ["LOCATED", "LOCATED_OFF_LINE", "NOT_LOCATED"] },
          "path": { "type": "string", "minLength": 1, "maxLength": 1024 },
          "claimed_line": { "type": "integer", "minimum": 1 },
          "found_line": { "type": ["integer", "null"], "minimum": 1 },
          "match_count": { "type": "integer", "minimum": 0 },
          "start_byte": { "type": ["integer", "null"], "minimum": 0 },
          "end_byte": { "type": ["integer", "null"], "minimum": 0 },
          "excerpt_sha256": { "type": ["string", "null"], "pattern": "^[a-f0-9]{64}$" },
          "anchor_state": { "enum": ["ANCHORED", "ANCHOR_UNAVAILABLE"] }
        }
      }
    },
    "absence_results": {
      "type": "array",
      "maxItems": 16,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["index", "outcome", "match_count", "searched_files"],
        "properties": {
          "index": { "type": "integer", "minimum": 0 },
          "outcome": {
            "enum": ["ABSENCE_HOLDS", "ABSENCE_CONTRADICTED", "ABSENCE_UNCHECKABLE"]
          },
          "match_count": { "type": "integer", "minimum": 0 },
          "searched_files": { "type": "integer", "minimum": 0 },
          "hits": {
            "type": "array",
            "maxItems": 16,
            "items": {
              "type": "object",
              "additionalProperties": false,
              "required": ["path", "line"],
              "properties": {
                "path": { "type": "string", "minLength": 1, "maxLength": 1024 },
                "line": { "type": "integer", "minimum": 1 }
              }
            }
          }
        }
      }
    }
  }
}
```

- [ ] **Step 4: Add 7.0.0 to every version gate**

For each file from `grep -rln "'6\.0\.0'" scripts/`, open each array containing `'6.0.0'` and append `'7.0.0'`. Leave `attempts.mjs:230` and `audit.mjs:4504` — which compare `=== '6.0.0'` rather than membership — for individual judgement: both must become membership checks including `'7.0.0'`, because they gate schema-6 features that 7.0.0 also has.

- [ ] **Step 5: Run the guard test and the full suite**

Run: `npm.cmd test -- test/existence-schema-version.test.mjs`
Expected: PASS, 3 tests.

Run: `npm.cmd test 2>&1 | grep -aE "^. (tests|pass|fail|skipped) "`
Expected: 789 tests, 786 pass, 1 skipped, 2 fail.

- [ ] **Step 6: Prove a 7.0.0 run survives the whole lifecycle**

This is the test that catches a version gate you missed. Find the existing end-to-end lifecycle test with `grep -rln "finalize\|buildFinalizedRun" test/*.test.mjs | head -3`, copy its setup into `test/existence-schema-version.test.mjs` as a new test that plans at `schema_version: '7.0.0'` and drives plan through finalize, asserting the run reaches `COMPLETED` or `COMPLETE_WITH_GAPS`.

Run: `npm.cmd test -- test/existence-schema-version.test.mjs`
Expected: PASS. A failure here names the gate that still excludes 7.0.0.

- [ ] **Step 7: Commit**

```bash
git add schemas/run.schema.json scripts test/existence-schema-version.test.mjs
git commit -m "feat: schema 7.0.0 carrying controller existence verdicts"
```

---

### Task 5: Thread the live inventory into ingest

**Files:**
- Modify: `scripts/audit.mjs:2056-2085` (`verifyRepositorySnapshot`)
- Modify: `scripts/audit.mjs:5156-5219` (`prepareOneResult`), `:5227-5247` (`ingestOneResult`, `ingestCommand`), `:5249` (`ingestBatchCommand`)
- Test: `test/existence-ingest.test.mjs` (create)

**Interfaces:**
- Consumes: nothing from Tasks 1–4 at runtime.
- Produces: `verifyRepositorySnapshot` returns `{ ...control, inventoryEntries }` where `inventoryEntries` is the live `inventory.entries` array carrying `{ path, kind, content, sha256, size }`. `applyJobResult` accepts `options.inventoryEntries`.

**Why this is free:** `verifyRepositorySnapshot` already builds this inventory on every ingest and throws unless it is byte-identical to the committed snapshot. `inventory.mjs:521` has already decoded every text file. The entries are discarded today; this task stops discarding them. No new read, no new TOCTOU window.

- [ ] **Step 1: Write the failing test**

Create `test/existence-ingest.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { verifyRepositorySnapshot } from '../scripts/audit.mjs'

test('verifyRepositorySnapshot is exported for inventory reuse', () => {
  assert.equal(typeof verifyRepositorySnapshot, 'function')
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm.cmd test -- test/existence-ingest.test.mjs`
Expected: FAIL — not exported.

- [ ] **Step 3: Return the live inventory and export the function**

In `scripts/audit.mjs`, change the tail of `verifyRepositorySnapshot`:

```js
  return { ...control, inventoryEntries: current.entries }
}
```

`audit.mjs` has no `export { ... }` block — it marks declarations inline, as at `audit.mjs:3736` (`export function pendingJobsForCurrentPhase`). So change the declaration itself at `audit.mjs:2056` to `export async function verifyRepositorySnapshot(`.

- [ ] **Step 4: Thread it to applyJobResult**

`prepareOneResult` gains a parameter and passes it through:

```js
async function prepareOneResult(
  loaded,
  resultPath,
  artifactCapacity,
  inventoryEntries,
) {
```

and inside, add to the `applyJobResult` options object:

```js
    inventoryEntries,
```

`ingestOneResult` takes and forwards it:

```js
async function ingestOneResult(loaded, resultPath, artifactCapacity, inventoryEntries) {
  const prepared = await prepareOneResult(
    loaded, resultPath, artifactCapacity, inventoryEntries,
  )
```

`ingestCommand` passes `control.inventoryEntries`:

```js
  await ingestOneResult(
    loaded, resultPath, control.artifactCapacity, control.inventoryEntries,
  )
```

Apply the same change in `ingestBatchCommand` at `scripts/audit.mjs:5249`.

- [ ] **Step 5: Run the full suite**

Run: `npm.cmd test 2>&1 | grep -aE "^. (tests|pass|fail|skipped) "`
Expected: 790 tests, 787 pass, 1 skipped, 2 fail. No behaviour has changed yet.

- [ ] **Step 6: Commit**

```bash
git add scripts/audit.mjs test/existence-ingest.test.mjs
git commit -m "feat: keep the verified inventory that ingest already builds"
```

---

### Task 6: Compute and record the verdicts

**Files:**
- Modify: `scripts/lib/existence-matcher.mjs`
- Modify: `scripts/lib/job-protocol.mjs:819-853` (`applyFindings`), `:1053` (`applyJobResult`)
- Modify: `test/existence-ingest.test.mjs`

**Interfaces:**
- Consumes: `matchQuote` and `searchAbsence` from Tasks 2–3; `options.inventoryEntries` from Task 5.
- Produces: `verifyFindingExistence(finding, entries) -> existenceVerification` matching the Task 4 schema, and `run.existence_verifications` populated at ingest.

**The UTF-8 round-trip guard:** byte anchors are computed from a UTF-8 re-encode of the decoded content. That round-trips exactly only if the original bytes were valid UTF-8. The inventory already carries the authoritative `sha256` of the original bytes, so use it as the oracle: if `sha256(Buffer.from(content,'utf8')) !== entry.sha256`, the file contained invalid UTF-8, the offsets cannot be trusted, and the result records `anchor_state: 'ANCHOR_UNAVAILABLE'` with null offsets. The match outcome still stands — only the anchor is withheld.

- [ ] **Step 1: Write the failing test**

Append to `test/existence-ingest.test.mjs`:

```js
import { verifyFindingExistence } from '../scripts/lib/existence-matcher.mjs'

const ENTRIES = [{
  path: 'src/routes/invoices.ts',
  kind: 'text',
  content: 'import x\nconst invoice = await repo.findById(req.params.id)\n',
  sha256: null,
}]

function withQuote(line, text) {
  return {
    candidate_id: 'c:1',
    quotes: [{ path: 'src/routes/invoices.ts', line, text }],
  }
}

test('a correct quote yields VERIFIED', () => {
  const v = verifyFindingExistence(
    withQuote(2, 'const invoice = await repo.findById(req.params.id)'), ENTRIES)
  assert.equal(v.outcome, 'VERIFIED')
  assert.equal(v.quote_results[0].outcome, 'LOCATED')
})

test('a correct quote at a wrong line yields DRIFTED', () => {
  const v = verifyFindingExistence(
    withQuote(88, 'const invoice = await repo.findById(req.params.id)'), ENTRIES)
  assert.equal(v.outcome, 'DRIFTED')
  assert.equal(v.quote_results[0].found_line, 2)
})

test('a fabricated quote yields UNVERIFIED', () => {
  const v = verifyFindingExistence(
    withQuote(2, 'const invoice = await repo.findByTenant(req.params.id)'), ENTRIES)
  assert.equal(v.outcome, 'UNVERIFIED')
})

test('a quote naming a path outside inventory yields UNVERIFIED', () => {
  const v = verifyFindingExistence({
    candidate_id: 'c:2',
    quotes: [{ path: 'src/does-not-exist.ts', line: 1, text: 'x' }],
  }, ENTRIES)
  assert.equal(v.outcome, 'UNVERIFIED')
  assert.equal(v.quote_results[0].outcome, 'NOT_LOCATED')
})

test('a finding with no claims yields NOT_APPLICABLE', () => {
  const v = verifyFindingExistence({ candidate_id: 'c:3' }, ENTRIES)
  assert.equal(v.outcome, 'NOT_APPLICABLE')
})

test('an uncheckable absence makes the finding UNVERIFIED', () => {
  const v = verifyFindingExistence({
    candidate_id: 'c:4',
    absence_claims: [{ pattern: 'x', kind: 'literal', scope: ['no/such/dir'] }],
  }, ENTRIES)
  assert.equal(v.absence_results[0].outcome, 'ABSENCE_UNCHECKABLE')
  assert.equal(v.outcome, 'UNVERIFIED')
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm.cmd test -- test/existence-ingest.test.mjs`
Expected: FAIL — `verifyFindingExistence` is not exported.

- [ ] **Step 3: Implement the per-finding verdict**

Append to `scripts/lib/existence-matcher.mjs` (add `createHash` to the imports at the top):

```js
import { createHash } from 'node:crypto'

function sha256Hex(buffer) {
  return createHash('sha256').update(buffer).digest('hex')
}

export function verifyFindingExistence(finding, entries) {
  const byPath = new Map(entries.map((entry) => [entry.path, entry]))
  const quotes = Array.isArray(finding.quotes) ? finding.quotes : []
  const claims = Array.isArray(finding.absence_claims) ? finding.absence_claims : []

  const quoteResults = quotes.map((quote, index) => {
    const entry = byPath.get(quote.path)
    if (!entry || entry.kind !== 'text' || typeof entry.content !== 'string') {
      return {
        index,
        outcome: 'NOT_LOCATED',
        path: quote.path,
        claimed_line: quote.line,
        found_line: null,
        match_count: 0,
        start_byte: null,
        end_byte: null,
        excerpt_sha256: null,
        anchor_state: 'ANCHOR_UNAVAILABLE',
      }
    }
    const match = matchQuote(entry.content, quote.text, quote.line)
    const base = {
      index,
      outcome: match.outcome,
      path: quote.path,
      claimed_line: quote.line,
      found_line: match.foundLine,
      match_count: match.matchCount,
    }
    if (match.outcome === 'NOT_LOCATED') {
      return {
        ...base,
        start_byte: null,
        end_byte: null,
        excerpt_sha256: null,
        anchor_state: 'ANCHOR_UNAVAILABLE',
      }
    }
    const bytes = Buffer.from(entry.content, 'utf8')
    const roundTrips = typeof entry.sha256 !== 'string'
      || sha256Hex(bytes) === entry.sha256.toLowerCase()
    if (!roundTrips) {
      return {
        ...base,
        start_byte: null,
        end_byte: null,
        excerpt_sha256: null,
        anchor_state: 'ANCHOR_UNAVAILABLE',
      }
    }
    const excerpt = bytes.subarray(match.startByte, match.endByte)
    return {
      ...base,
      start_byte: match.startByte,
      end_byte: match.endByte,
      excerpt_sha256: sha256Hex(excerpt),
      anchor_state: 'ANCHORED',
    }
  })

  const absenceResults = claims.map((claim, index) => ({
    index,
    ...searchAbsence(entries, claim),
  })).map(({ matchCount, searchedFiles, ...rest }) => ({
    ...rest,
    match_count: matchCount,
    searched_files: searchedFiles,
  }))

  let outcome = 'NOT_APPLICABLE'
  if (quotes.length > 0 || claims.length > 0) {
    const failed = quoteResults.some((r) => r.outcome === 'NOT_LOCATED')
      || absenceResults.some((r) => r.outcome !== 'ABSENCE_HOLDS')
    const drifted = quoteResults.some((r) => r.outcome === 'LOCATED_OFF_LINE')
    outcome = failed ? 'UNVERIFIED' : (drifted ? 'DRIFTED' : 'VERIFIED')
  }

  return {
    candidate_id: finding.candidate_id,
    quote_results: quoteResults,
    absence_results: absenceResults,
    outcome,
  }
}
```

- [ ] **Step 4: Run the unit tests**

Run: `npm.cmd test -- test/existence-ingest.test.mjs`
Expected: PASS, 7 tests.

- [ ] **Step 5: Record verdicts during ingest**

In `scripts/lib/job-protocol.mjs`, import the verifier at the top:

```js
import { verifyFindingExistence } from './existence-matcher.mjs'
```

`applyFindings` (line 819) ends with `return candidateIds` at `job-protocol.mjs:957`, immediately after the `job.kind === 'PROOF'` candidate-id check. Insert this directly before that `return`, so every candidate touched by the result — pushed or replaced — is re-verified once, using the loop variables `candidateIds` and `byId` already in scope:

```js
  if (Array.isArray(options.inventoryEntries)) {
    run.existence_verifications ??= []
    const byCandidate = new Map(
      run.existence_verifications.map((row) => [row.candidate_id, row]),
    )
    for (const candidateId of candidateIds) {
      const index = byId.get(candidateId)
      if (index === undefined) continue
      byCandidate.set(
        candidateId,
        verifyFindingExistence(run.findings[index], options.inventoryEntries),
      )
    }
    run.existence_verifications = [...byCandidate.values()]
      .sort((left, right) =>
        compareCanonicalStrings(left.candidate_id, right.candidate_id))
  }
```

`compareCanonicalStrings` is already imported at `job-protocol.mjs:6`. Do not add a second import.

Then in `applyJobResult` (line 1053), forward the option to `applyFindings` — the call is at `job-protocol.mjs:1090` (`applyFindings(next, job, jobResult.findings, {`). Add `inventoryEntries: options.inventoryEntries,` to its options object.

- [ ] **Step 6: Run the full suite**

Run: `npm.cmd test 2>&1 | grep -aE "^. (tests|pass|fail|skipped) "`
Expected: 796 tests, 793 pass, 1 skipped, 2 fail.

- [ ] **Step 7: Commit**

```bash
git add scripts/lib/existence-matcher.mjs scripts/lib/job-protocol.mjs test/existence-ingest.test.mjs
git commit -m "feat: record controller existence verdicts at ingest"
```

---

### Task 7: Re-derive during validate

**Files:**
- Modify: `scripts/audit.mjs:3634` (`validateCommand`)
- Test: `test/existence-validate.test.mjs` (create)

**Interfaces:**
- Consumes: `verifyFindingExistence` from Task 6.
- Produces: `validate` fails closed when a stored verdict does not equal a freshly derived one; records `NOT_REDERIVABLE` when the target is unavailable.

- [ ] **Step 1: Write the failing test**

Create `test/existence-validate.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { assertExistenceVerificationsRederive } from '../scripts/audit.mjs'

const ENTRIES = [{
  path: 'a.ts',
  kind: 'text',
  content: 'const x = 1\n',
  sha256: null,
}]

function runWith(outcome) {
  return {
    findings: [{ candidate_id: 'c:1', quotes: [{ path: 'a.ts', line: 1, text: 'const x = 1' }] }],
    existence_verifications: [{
      candidate_id: 'c:1',
      quote_results: [{
        index: 0, outcome: 'LOCATED', path: 'a.ts', claimed_line: 1,
        found_line: 1, match_count: 1, start_byte: 0, end_byte: 11,
        excerpt_sha256: null, anchor_state: 'ANCHORED',
      }],
      absence_results: [],
      outcome,
    }],
  }
}

test('a matching verdict re-derives', () => {
  assert.doesNotThrow(() =>
    assertExistenceVerificationsRederive(runWith('VERIFIED'), ENTRIES))
})

test('a hand-edited verdict fails closed', () => {
  assert.throws(
    () => assertExistenceVerificationsRederive(runWith('UNVERIFIED'), ENTRIES),
    /existence verification/i,
  )
})

test('an absent target yields NOT_REDERIVABLE rather than trust', () => {
  const run = runWith('VERIFIED')
  assert.throws(
    () => assertExistenceVerificationsRederive(run, null),
    /NOT_REDERIVABLE/,
  )
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm.cmd test -- test/existence-validate.test.mjs`
Expected: FAIL — `assertExistenceVerificationsRederive` is not exported.

- [ ] **Step 3: Implement re-derivation**

In `scripts/audit.mjs`, add near the other assert helpers, and export it:

```js
export function assertExistenceVerificationsRederive(run, inventoryEntries) {
  const stored = run.existence_verifications
  if (!Array.isArray(stored) || stored.length === 0) return
  if (!Array.isArray(inventoryEntries)) {
    throw new Error(
      'existence verifications are NOT_REDERIVABLE: the target inventory is unavailable',
    )
  }
  const byCandidate = new Map(
    run.findings.map((finding) => [finding.candidate_id, finding]),
  )
  for (const row of stored) {
    const finding = byCandidate.get(row.candidate_id)
    if (!finding) {
      throw new Error(
        `existence verification names unknown candidate ${row.candidate_id}`,
      )
    }
    const derived = verifyFindingExistence(finding, inventoryEntries)
    if (stableJson(derived) !== stableJson(row)) {
      throw new Error(
        `existence verification for ${row.candidate_id} does not re-derive`,
      )
    }
  }
}
```

Import `verifyFindingExistence` from `./lib/existence-matcher.mjs` at the top of `audit.mjs`.

- [ ] **Step 4: Call it from validate**

In `validateCommand`, after the existing run validation and after `verifyRepositorySnapshot` has produced `control`, add:

```js
  assertExistenceVerificationsRederive(loaded.run, control.inventoryEntries)
```

Where `validateCommand` supports validating a historical bundle without the target present, pass `null` so the NOT_REDERIVABLE path fires rather than silently skipping.

- [ ] **Step 5: Run the tests**

Run: `npm.cmd test -- test/existence-validate.test.mjs`
Expected: PASS, 3 tests.

Run: `npm.cmd test 2>&1 | grep -aE "^. (tests|pass|fail|skipped) "`
Expected: 799 tests, 796 pass, 1 skipped, 2 fail.

- [ ] **Step 6: Commit**

```bash
git add scripts/audit.mjs test/existence-validate.test.mjs
git commit -m "feat: re-derive existence verdicts during validate"
```

---

### Task 8: The plan-time gate

**Files:**
- Modify: `scripts/audit.mjs:206` (usage), `:270` (option table), `:3278` (option read)
- Modify: `scripts/lib/run-engine.mjs:149-164`, `:261`
- Modify: `schemas/run.schema.json` (closure policy)
- Modify: `scripts/lib/job-protocol.mjs:1613-1630` (`buildFinalizedRun`)
- Test: `test/existence-gate.test.mjs` (create)

**Interfaces:**
- Consumes: `run.existence_verifications` from Task 6.
- Produces: `--require-verified-existence` on `plan`, recorded as `run.coverage.closure.required_verified_existence`, enforced at finalization.

**Shape to copy:** `--require-source-closure` is the exact precedent. It is a `plan` flag (`audit.mjs:270`), passed as `requireSourceClosure` into `run-engine.mjs:149`, stored as `policy.require_source_closure` (`:164`), projected to `closure.required_source_closure` (`:261`), and enforced in `buildFinalizedRun` (`job-protocol.mjs:1613`). Mirror each step.

- [ ] **Step 1: Write the failing test**

Create `test/existence-gate.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { assertVerifiedExistenceGate } from '../scripts/lib/job-protocol.mjs'

function run(required, outcomes) {
  return {
    coverage: { closure: { required_verified_existence: required } },
    findings: outcomes.map((_, index) => ({
      candidate_id: `c:${index}`,
      triage_disposition: 'queued',
    })),
    existence_verifications: outcomes.map((outcome, index) => ({
      candidate_id: `c:${index}`, outcome, quote_results: [], absence_results: [],
    })),
  }
}

test('the gate off allows anything', () => {
  assert.doesNotThrow(() =>
    assertVerifiedExistenceGate(run(false, ['UNVERIFIED', 'NOT_APPLICABLE'])))
})

test('the gate on allows VERIFIED and DRIFTED', () => {
  assert.doesNotThrow(() =>
    assertVerifiedExistenceGate(run(true, ['VERIFIED', 'DRIFTED'])))
})

test('the gate on refuses UNVERIFIED', () => {
  assert.throws(
    () => assertVerifiedExistenceGate(run(true, ['VERIFIED', 'UNVERIFIED'])),
    /verified existence/i,
  )
})

test('the gate on refuses NOT_APPLICABLE so omitting quotes cannot buy passage', () => {
  assert.throws(
    () => assertVerifiedExistenceGate(run(true, ['NOT_APPLICABLE'])),
    /verified existence/i,
  )
})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `npm.cmd test -- test/existence-gate.test.mjs`
Expected: FAIL — `assertVerifiedExistenceGate` is not exported.

- [ ] **Step 3: Implement the gate check**

In `scripts/lib/job-protocol.mjs`, add and export:

```js
const EXISTENCE_GATE_PASSING = new Set(['VERIFIED', 'DRIFTED'])

export function assertVerifiedExistenceGate(run) {
  if (!run.coverage?.closure?.required_verified_existence) return
  const byCandidate = new Map(
    (run.existence_verifications ?? []).map((row) => [row.candidate_id, row]),
  )
  const blocking = (run.findings ?? [])
    .filter((finding) => ACTIVE_FINDING_DISPOSITIONS.has(finding.triage_disposition))
    .filter((finding) =>
      !EXISTENCE_GATE_PASSING.has(byCandidate.get(finding.candidate_id)?.outcome))
    .map((finding) => finding.candidate_id)
  if (blocking.length === 0) return
  const preview = blocking.slice(0, 8)
  throw resultError(
    `verified existence is required, but ${blocking.length} finding` +
    `${blocking.length === 1 ? '' : 's'} did not verify: ` +
    `${preview.join(', ')}${blocking.length > preview.length ? ', ...' : ''}`,
  )
}
```

`ACTIVE_FINDING_DISPOSITIONS` is defined at `job-protocol.mjs:65` as `new Set(['queued', 'elevated'])` — the same set `proofExistenceJobs` filters on. The schema's full `triage_disposition` enum is `queued`, `merged`, `dropped`, `elevated`, so a merged or dropped candidate is correctly outside the gate.

Call it from `buildFinalizedRun` immediately after the `required_source_closure` block ends (line 1630):

```js
  assertVerifiedExistenceGate(run)
```

- [ ] **Step 4: Wire the plan flag**

`scripts/audit.mjs:206` — add `[--require-verified-existence]` to the `plan` usage line.

`scripts/audit.mjs:270` — add to the `plan` option table:

```js
      'require-verified-existence': 'flag',
```

`scripts/audit.mjs:3278` — beside `requireSourceClosure`, add:

```js
      requireVerifiedExistence: options['require-verified-existence'] === true,
```

`scripts/lib/run-engine.mjs:149` — add the parameter beside `requireSourceClosure = false`:

```js
  requireVerifiedExistence = false,
```

and its type check beside the existing one at `:153`, and the policy field at `:164`:

```js
    require_verified_existence: requireVerifiedExistence,
```

and the closure projection at `:261`:

```js
      required_verified_existence: policy.require_verified_existence,
```

`schemas/run.schema.json` — add `require_verified_existence` and `required_verified_existence` as required booleans alongside `require_source_closure` in the closure policy objects (line 859 area).

- [ ] **Step 5: Run the tests**

Run: `npm.cmd test -- test/existence-gate.test.mjs`
Expected: PASS, 4 tests.

Run: `npm.cmd test 2>&1 | grep -aE "^. (tests|pass|fail|skipped) "`
Expected: 803 tests, 800 pass, 1 skipped, 2 fail.

- [ ] **Step 6: Commit**

```bash
git add scripts schemas/run.schema.json test/existence-gate.test.mjs
git commit -m "feat: plan-time verified-existence finalization gate"
```

---

### Task 9: Report the verdicts

**Files:**
- Modify: `scripts/lib/report.mjs:540-582`
- Test: `test/existence-report.test.mjs` (create)

**Interfaces:**
- Consumes: `run.existence_verifications`.
- Produces: an `### Existence verification` block in the executive summary and a contradiction list.

- [ ] **Step 1: Write the failing test**

Create `test/existence-report.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { renderMarkdownReport } from '../scripts/lib/report.mjs'

function baseRun(verifications, findings) {
  return {
    run_id: 'run_1',
    schema_version: '7.0.0',
    state: 'COMPLETED',
    phase: 'FINALIZED',
    capability_mode: 'STATIC',
    repository: { root: '.', tree_digest: 'a'.repeat(64) },
    coverage: { inventory: [], denominators: [] },
    jobs: [],
    errors: [],
    artifacts: {},
    findings,
    existence_verifications: verifications,
  }
}

test('the report counts existence outcomes', () => {
  const md = renderMarkdownReport(baseRun(
    [
      { candidate_id: 'c:1', outcome: 'VERIFIED', quote_results: [], absence_results: [] },
      { candidate_id: 'c:2', outcome: 'UNVERIFIED', quote_results: [], absence_results: [] },
    ],
    [
      { candidate_id: 'c:1', title: 'A', claimed_impact_severity: 'Low' },
      { candidate_id: 'c:2', title: 'B', claimed_impact_severity: 'Low' },
    ],
  ))
  assert.match(md, /### Existence verification/)
  assert.match(md, /c:2/)
})

test('a provider claiming located against a NOT_LOCATED verdict is flagged', () => {
  const md = renderMarkdownReport(baseRun(
    [{
      candidate_id: 'c:1',
      outcome: 'UNVERIFIED',
      quote_results: [{ index: 0, outcome: 'NOT_LOCATED', claimed_line: 5, match_count: 0 }],
      absence_results: [],
    }],
    [{
      candidate_id: 'c:1', title: 'A', claimed_impact_severity: 'Low',
      existence_check: 'located — read at line 5, present verbatim',
    }],
  ))
  assert.match(md, /contradict/i)
})

test('a run with no verifications renders without the block', () => {
  const md = renderMarkdownReport(baseRun([], []))
  assert.doesNotMatch(md, /### Existence verification/)
})
```

If `renderMarkdownReport` rejects this minimal run shape, copy the run fixture from an existing report test — find one with `grep -rln "renderMarkdownReport" test/*.test.mjs`.

- [ ] **Step 2: Run test to verify it fails**

Run: `npm.cmd test -- test/existence-report.test.mjs`
Expected: FAIL — no such section is rendered.

- [ ] **Step 3: Render the section**

In `scripts/lib/report.mjs`, after the `### Unverified high-impact claims` block closes (line 577) and before `'## Findings'` is pushed (line 579), insert:

```js
  const verifications = Array.isArray(run.existence_verifications)
    ? run.existence_verifications
    : []
  if (verifications.length > 0) {
    const counts = { VERIFIED: 0, DRIFTED: 0, UNVERIFIED: 0, NOT_APPLICABLE: 0, NOT_REDERIVABLE: 0 }
    for (const row of verifications) {
      if (row.outcome in counts) counts[row.outcome] += 1
    }
    lines.push(
      '### Existence verification',
      '',
      'The controller independently checked each quoted span against the inventoried file content and re-ran each absence claim. These outcomes are controller-derived, not provider declarations.',
      '',
      '| Verified | Drifted | Unverified | Not applicable | Not re-derivable |',
      '|---:|---:|---:|---:|---:|',
      `| ${counts.VERIFIED} | ${counts.DRIFTED} | ${counts.UNVERIFIED} | ` +
      `${counts.NOT_APPLICABLE} | ${counts.NOT_REDERIVABLE} |`,
      '',
    )
    const failed = verifications.filter((row) => row.outcome === 'UNVERIFIED')
    if (failed.length > 0) {
      lines.push(
        '| Candidate | Failing check |',
        '|---|---|',
      )
      for (const row of failed) {
        const reasons = [
          ...row.quote_results
            .filter((quote) => quote.outcome === 'NOT_LOCATED')
            .map((quote) => `quote ${quote.index} not located`),
          ...row.absence_results
            .filter((claim) => claim.outcome !== 'ABSENCE_HOLDS')
            .map((claim) => `absence ${claim.index} ${claim.outcome.toLowerCase()}`),
        ]
        lines.push(`| ${tableCell(row.candidate_id)} | ${tableCell(reasons.join('; '))} |`)
      }
      lines.push('')
    }
    const byCandidate = new Map(verifications.map((row) => [row.candidate_id, row]))
    const contradicted = (run.findings ?? []).filter((finding) => {
      const row = byCandidate.get(finding.candidate_id)
      return typeof finding.existence_check === 'string'
        && finding.existence_check.trim().toLowerCase().startsWith('located')
        && row?.quote_results?.some((quote) => quote.outcome === 'NOT_LOCATED')
    })
    if (contradicted.length > 0) {
      lines.push(
        'These providers attested that they located the cited evidence, and the controller did not. The contradiction is a provider-integrity signal, not a formatting note.',
        '',
        '| Candidate | Provider attestation |',
        '|---|---|',
      )
      for (const finding of contradicted) {
        lines.push(
          `| ${tableCell(finding.candidate_id)} | ${tableCell(finding.existence_check)} |`,
        )
      }
      lines.push('')
    }
  }
```

- [ ] **Step 4: Run the tests**

Run: `npm.cmd test -- test/existence-report.test.mjs`
Expected: PASS, 3 tests.

Run: `npm.cmd test 2>&1 | grep -aE "^. (tests|pass|fail|skipped) "`
Expected: 806 tests, 803 pass, 1 skipped, 2 fail.

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/report.mjs test/existence-report.test.mjs
git commit -m "feat: report controller existence verdicts and provider contradictions"
```

---

### Task 10: Documentation and the backward-compatibility proof

**Files:**
- Modify: `skills/red-team-audit/lenses/_schema.md`
- Modify: `README.md` (the `## Current release` list)
- Test: `test/existence-backcompat.test.mjs` (create)

**Interfaces:**
- Consumes: everything above.
- Produces: no code interface. This task proves the change is safe on the existing corpus and documents the two new fields where lens authors will read them.

**Do not touch `skills/red-team-audit/SKILL.md`** — it is 7,995 of 8,000 bytes and `npm.cmd run lint` enforces that ceiling.

- [ ] **Step 1: Write the backward-compatibility test**

Create `test/existence-backcompat.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { verifyFindingExistence } from '../scripts/lib/existence-matcher.mjs'

test('a finding with neither quotes nor absence claims is NOT_APPLICABLE', () => {
  const legacy = {
    candidate_id: 'cand:cicd:002',
    location: ['.github/dependabot.yml:9'],
    evidence: 'The npm entries list 13 directory patterns including the /react-apps/* glob',
  }
  const v = verifyFindingExistence(legacy, [
    { path: '.github/dependabot.yml', kind: 'text', content: 'version: 2\n', sha256: null },
  ])
  assert.equal(v.outcome, 'NOT_APPLICABLE')
  assert.deepEqual(v.quote_results, [])
  assert.deepEqual(v.absence_results, [])
})

test('an empty inventory does not throw', () => {
  const v = verifyFindingExistence({ candidate_id: 'c:1' }, [])
  assert.equal(v.outcome, 'NOT_APPLICABLE')
})
```

- [ ] **Step 2: Run it**

Run: `npm.cmd test -- test/existence-backcompat.test.mjs`
Expected: PASS, 2 tests. If it fails, the change is not backward compatible — stop and fix Task 6 before continuing.

- [ ] **Step 3: Document the two fields**

In `skills/red-team-audit/lenses/_schema.md`, in the field table near the `evidence` row (line 146 area), add:

```markdown
| `quotes` | `[{path, line, text}]` | The verbatim span, separately from the prose in `evidence`. The controller opens the file and confirms the text is there, comparing each line with leading and trailing whitespace trimmed so re-indentation does not fail a true quote. It records the line it actually found. Nothing here is taken on trust: `existence_check` is what you assert, `quotes` is what the controller checks. |
| `absence_claims` | `[{pattern, kind, scope}]` | Required to make a claim that something is *not* there. Name the literal you searched for and the paths you searched, and the controller re-runs that search over its own inventory. A scope matching no file is `ABSENCE_UNCHECKABLE`, never a clean result — a search that ran against nothing must never read as an absence. `kind` is `literal` or `literal_ci`. |
```

- [ ] **Step 4: Document the release change**

In `README.md`, add to the `## Current release` bullet list:

```markdown
- Controller-verified finding existence: quoted spans re-checked against
  inventoried file content, absence claims re-run over the controller's own
  inventory, verdicts re-derived during validation, and an opt-in
  `--require-verified-existence` finalization gate.
```

- [ ] **Step 5: Run every gate**

```bash
npm.cmd test 2>&1 | grep -aE "^. (tests|pass|fail|skipped) "
npm.cmd run lint 2>&1 | tail -2
npm.cmd run gen -- --check 2>&1 | tail -2
npm.cmd run gen:benchmarks -- --check 2>&1 | tail -2
git diff --check
```

Expected: 808 tests, 805 pass, 1 skipped, 2 fail (ripgrep); `PASS: R1-R8, SKILL and ledger gate clean`; gen PASS at 174 slugs; benchmarks PASS; no whitespace errors.

- [ ] **Step 6: Commit**

```bash
git add skills/red-team-audit/lenses/_schema.md README.md test/existence-backcompat.test.mjs
git commit -m "docs: document controller-verified existence for lens authors"
```

---

## Acceptance

Run this end to end against a scratch repository:

1. `plan` a target with `--require-verified-existence`.
2. Ingest a LENS result whose finding quotes real code at the line it cites. The run records `outcome: VERIFIED`.
3. Ingest a second finding with one identifier altered inside the quote. The run records `UNVERIFIED`.
4. `finalize` refuses, naming the second candidate.
5. Remove the second finding's fabrication, re-run, and `finalize` succeeds.
6. Hand-edit one `existence_verifications` outcome in `run.json` from `UNVERIFIED` to `VERIFIED`. `validate` refuses.
7. A finding claiming a token is absent from a directory where the controller finds it reports `ABSENCE_CONTRADICTED` with the file and line.
8. The same run planned *without* the flag finalizes in every case above and reports the outcomes instead of blocking.

## Not in this plan

Making `evidence` itself verbatim. `quotes` gives `_schema.md:146` a machine-checkable home; tightening the prose field is a separate decision.

`regex` absence claims — excluded on ReDoS grounds; Node's `RegExp` backtracks and the pattern is provider-controlled.

Retiring the `proof-existence` job kind, which the controller verdict makes redundant for findings carrying quotes.

Teaching the lenses to emit `quotes`. This plan makes the fields exist, checked, reported and gateable. Getting 15 lenses to populate them is a separate change against the lens corpus and the `gen` slug gates.

**Test counts assume the tasks run in order.** If you reorder them, recompute rather than trusting the stated numbers.
