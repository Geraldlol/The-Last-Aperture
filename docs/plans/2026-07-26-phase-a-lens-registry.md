# Phase A: Lens Registry and Content Correction — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the ten existing reference files into fourteen linted, corrected, self-contained lenses with a machine-enforced ownership registry, so that no later phase can silently lose content or break the one-owner invariant.

**Architecture:** Lens frontmatter is the single source of truth. Small pure-function libraries parse and model it; two CLI scripts (`lint-lenses.mjs`, `gen-topics.mjs`) enforce and generate from it. Scripts and their tests land *before* any lens content, so every content task is validated the moment it lands rather than at the end. `_topics.md` and the overlap table are generated artifacts, never hand-edited.

**Tech Stack:** Node 24 (`node:test`, `node:assert/strict`), `yaml` as the sole devDependency, GitHub Actions for CI. No runtime dependencies — the shipped skill is markdown.

**Plan location note:** `docs/plans/` rather than `docs/superpowers/plans/`, matching the spec's decision that internal tooling conventions must not leak into a public repository.

## Global Constraints

Every task's requirements implicitly include these. Values copied verbatim from the spec.

- **Single source of truth:** lens frontmatter. `_topics.md`, the overlap table and every count are generated. A slug count written by hand anywhere is a defect.
- **`SKILL.md` ≤ 8 KB**, and no harness-specific tool named in its normative text. (Enforced in Phase B; do not grow `SKILL.md` in Phase A.)
- **Orthography:** American `-ization`, not `-isation`, in all topic slugs.
- **Fourteen lenses**, three shapes: domain (`runs_in: fanout`, matched `activates_on`, non-empty `owns`), always-on (`runs_in: fanout`, `always_active: true`, `owns: []`), triage (`runs_in: triage`, empty `activates_on`, `owns: []`).
- **No employer, tenant, product, or person names** in any tracked file.
- **Pre-scrub content is never committed.** The A0 baseline stays untracked; only its checksums may be committed.
- **Copyright in the author's personal name.** Commits authored as `Gerald <gerald.maida@gmail.com>`.
- **Frameworks in frontmatter are unversioned identifiers**, lowercase-hyphenated. Editions are cited in lens bodies.
- **`SANS Top 25` must never appear.** A CWE lineage is exactly `cwe-top-25`.
- **Dependencies:** exact-pinned, lockfile committed, CI installs with `npm ci`.

## Source Documents

Read these; they are committed in this repository and hold the content this plan migrates. Do not re-derive their conclusions.

| Document | Holds |
|---|---|
| `docs/design/2026-07-26-red-team-audit-oss-design.md` | The approved spec. §4 contract, §9 phasing, §10 success criteria. |
| `docs/design/2026-07-26-recon-punch-list.md` | §1 corrections (lines 8–202), §4 false-positive seed content (1479–1608), §5 proof recipes (1609–1738), §6 de-branding (1739–1805). §§2–3 are marked SUPERSEDED — do not use. |
| `docs/design/2026-07-26-recon-punch-list-repair.md` | `web-and-api` frontmatter (3–225), `crypto-and-key-management` frontmatter (226–314), overlap table (323–487), registry (488–687), final lens list (688–704), invariant verification with 15 required fixes (720–786). |
| `references/*.md`, `SKILL.md` | The untracked pre-scrub sources being migrated. |

## File Structure

**Tooling — created in Tasks 1–8:**

| File | Responsibility |
|---|---|
| `package.json` | Scripts, the single devDependency, Node engine floor |
| `scripts/lib/frontmatter.mjs` | One lens file → `{ frontmatter, sections, detectors }`. Parsing only, no rules. |
| `scripts/lib/registry.mjs` | All lenses → ownership model. Partition, deferral resolution, shape coherence. Pure functions, no I/O. |
| `scripts/lib/orthography.mjs` | Slug spelling convention. Isolated because it is a single regex that will be argued about. |
| `scripts/lib/ledger.mjs` | `migration-ledger.tsv` → rows; unresolved-row detection |
| `scripts/lint-lenses.mjs` | CLI. Runs R1–R7 plus the ledger gate. Exit 1 on any violation. |
| `scripts/gen-topics.mjs` | CLI. Emits `_topics.md` and the overlap table from frontmatter. `--check` compares without writing. |
| `test/*.test.mjs` | One test file per lib module, plus a CLI integration test |
| `test/samples/**` | Tiny synthetic lens sets, each engineered to violate exactly one rule |
| `.github/workflows/lint-lenses.yml` | CI: `npm ci`, `npm test`, `npm run lint`, `npm run gen -- --check` |

**Content — created in Tasks 9–20:**

| File | Responsibility |
|---|---|
| `skills/last-aperture/lenses/_schema.md` | Candidate-finding contract |
| `skills/last-aperture/lenses/_harness.md` | Shared proof-harness pieces lenses reference by name |
| `skills/last-aperture/lenses/_topics.md` | **Generated.** Canonical slug registry |
| `skills/last-aperture/lenses/<10 domain>.md` | One domain each |
| `skills/last-aperture/lenses/ai-generated-code.md` | Always-on machine-authored-code tells |
| `skills/last-aperture/lenses/{attack-chaining,business-logic,completeness}.md` | Triage lenses (frontmatter + skeleton only in Phase A; bodies in Phase B) |
| `docs/migration-ledger.tsv` | Every source check → destination → disposition → evidence |
| `docs/ownership-overlap.md` | **Generated.** The overlap resolution table |

---

### Task 1: Repository scaffolding and CI

**Files:**
- Create: `package.json`, `package-lock.json`, `.github/workflows/lint-lenses.yml`, `test/smoke.test.mjs`

**Interfaces:**
- Consumes: nothing
- Produces: `npm test`, `npm run lint`, `npm run gen` as the three commands every later task uses

- [ ] **Step 1: Write the failing test**

Create `test/smoke.test.mjs`:

```javascript
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parse } from 'yaml'

test('yaml devDependency is installed and parses nested maps', () => {
  const parsed = parse('a:\n  b: [1, 2]\n')
  assert.deepEqual(parsed, { a: { b: [1, 2] } })
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `node --test test/smoke.test.mjs`
Expected: FAIL — `Cannot find package 'yaml'`

- [ ] **Step 3: Create package.json**

```json
{
  "name": "red-team-audit",
  "version": "0.1.0",
  "private": true,
  "type": "module",
  "engines": { "node": ">=20.0.0" },
  "scripts": {
    "test": "node --test test/",
    "lint": "node scripts/lint-lenses.mjs",
    "gen": "node scripts/gen-topics.mjs"
  },
  "devDependencies": {
    "yaml": "2.8.1"
  }
}
```

The version is exact, not `^2.8.1`. The project's own supply-chain lens flags range specifiers; the repository must not violate its own advice.

- [ ] **Step 4: Install and verify the test passes**

Run: `npm install && node --test test/smoke.test.mjs`
Expected: PASS. `package-lock.json` now exists.

- [ ] **Step 5: Create the CI workflow**

Create `.github/workflows/lint-lenses.yml`:

```yaml
name: lint-lenses
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  verify:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        node: ['20', '24']
    steps:
      - uses: actions/checkout@08eba0b27e820071cde6df949e0beb9ba4906955 # v4.3.0
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with:
          node-version: ${{ matrix.node }}
      - run: npm ci
      - run: npm test
      - if: matrix.node == '24'
        run: npm run lint
      - if: matrix.node == '24'
        run: npm run gen -- --check
      - if: matrix.node == '24'
        run: npm run gen:benchmarks -- --check
```

`npm ci` not `npm install`; third-party actions are pinned by full commit SHA,
and the advertised Node 20 floor receives the full test suite.

- [ ] **Step 6: Commit**

```bash
git add package.json package-lock.json test/smoke.test.mjs .github/workflows/lint-lenses.yml
git commit -m "chore: scaffold Node tooling and CI for lens linting"
```

---

### Task 2: Frontmatter and section parser

**Files:**
- Create: `scripts/lib/frontmatter.mjs`, `test/frontmatter.test.mjs`, `test/samples/minimal-lens.md`

**Interfaces:**
- Consumes: `yaml` from Task 1
- Produces:
  - `parseLens(text, filename) -> { name, frontmatter, sections, detectors, errors }`
  - `frontmatter` is the raw parsed YAML object
  - `sections` is `{ [h2Title]: bodyText }` for every `## ` heading
  - `detectors` is `[{ match, nomatch, line }]` parsed from ```detector fenced blocks. `line` is **file-relative**, not body-relative — it appears in linter output, so it must match what `grep -n` reports for that fence. No `lens` field: the caller already knows which lens it is iterating.
  - `errors` is `string[]`; a malformed file returns errors rather than throwing

- [ ] **Step 1: Write the failing test**

Create `test/samples/minimal-lens.md`:

````markdown
---
name: sample-domain
title: Sample domain
runs_in: fanout
activates_on:
  paths: ["**/routes/**"]
  signals: ["express"]
owns: [csrf]
defers:
  jwt-jws-and-jwks-verification: crypto-and-key-management
frameworks: [owasp-top-10]
severity_floor: low
---

## Scope

Owns CSRF. Does not own JWT verification.

## Checklist

- Look for state-changing POST handlers with no token check.

```detector
match: |
  app.post('/transfer', (req, res) => doTransfer(req.body))
nomatch: |
  app.post('/transfer', csrfProtection, (req, res) => doTransfer(req.body))
```

## Severity calibration

Missing CSRF on a state-changing endpoint is High.

## Known false positives

1. A POST endpoint that only reads. Not state-changing, so no CSRF exposure.

## Proof recipes

Two-subject request replay. See `_harness.md` → `route-table-enumerator`.
````

Create `test/frontmatter.test.mjs`:

```javascript
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { parseLens } from '../scripts/lib/frontmatter.mjs'

const text = readFileSync('test/samples/minimal-lens.md', 'utf8')

test('parses frontmatter into an object', () => {
  const lens = parseLens(text, 'minimal-lens.md')
  assert.equal(lens.errors.length, 0)
  assert.equal(lens.name, 'sample-domain')
  assert.equal(lens.frontmatter.runs_in, 'fanout')
  assert.deepEqual(lens.frontmatter.owns, ['csrf'])
  assert.equal(
    lens.frontmatter.defers['jwt-jws-and-jwks-verification'],
    'crypto-and-key-management'
  )
})

test('collects every h2 section by title', () => {
  const lens = parseLens(text, 'minimal-lens.md')
  assert.deepEqual(Object.keys(lens.sections), [
    'Scope',
    'Checklist',
    'Severity calibration',
    'Known false positives',
    'Proof recipes',
  ])
  assert.match(lens.sections['Scope'], /Does not own JWT verification/)
})

test('extracts detector blocks with both directions', () => {
  const lens = parseLens(text, 'minimal-lens.md')
  assert.equal(lens.detectors.length, 1)
  assert.match(lens.detectors[0].match, /app\.post\('\/transfer'/)
  assert.match(lens.detectors[0].nomatch, /csrfProtection/)
})

test('reports an error instead of throwing on missing frontmatter', () => {
  const lens = parseLens('# no frontmatter here\n', 'broken.md')
  assert.ok(lens.errors.some((e) => /frontmatter/i.test(e)))
})

test('reports an error instead of throwing on malformed yaml', () => {
  const lens = parseLens('---\nname: [unclosed\n---\n', 'broken.md')
  assert.equal(lens.errors.length, 1)
  assert.match(lens.errors[0], /yaml/i)
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `node --test test/frontmatter.test.mjs`
Expected: FAIL — `Cannot find module '../scripts/lib/frontmatter.mjs'`

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/frontmatter.mjs`:

```javascript
import { parse as parseYaml } from 'yaml'

const FM = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/

// One lens file in, structured lens out. Parsing only — no rules live here,
// so a rule change never means touching the parser.
export function parseLens(text, filename) {
  const errors = []
  const match = FM.exec(text)
  if (!match) {
    return { name: null, frontmatter: {}, sections: {}, detectors: [], errors: [`${filename}: no YAML frontmatter block found`] }
  }

  let frontmatter = {}
  try {
    frontmatter = parseYaml(match[1]) ?? {}
  } catch (err) {
    return { name: null, frontmatter: {}, sections: {}, detectors: [], errors: [`${filename}: yaml parse failed — ${err.message}`] }
  }

  const body = text.slice(match[0].length)
  // Detector line numbers surface in linter output, so they must be
  // file-relative. The body starts this many lines into the file.
  const frontmatterLines = match[0].split(/\r?\n/).length - 1
  return {
    name: frontmatter.name ?? null,
    frontmatter,
    sections: splitSections(body),
    detectors: parseDetectors(body, filename, errors, frontmatterLines),
    errors,
  }
}

function splitSections(body) {
  const sections = {}
  let current = null
  const buffer = []
  const flush = () => {
    if (current !== null) sections[current] = buffer.join('\n').trim()
    buffer.length = 0
  }
  for (const line of body.split(/\r?\n/)) {
    const heading = /^##\s+(.+?)\s*$/.exec(line)
    if (heading) {
      flush()
      current = heading[1]
    } else if (current !== null) {
      buffer.push(line)
    }
  }
  flush()
  return sections
}

// A detector block proves a search instruction can actually fire. Both
// directions are required: match shows it fires, nomatch shows it discriminates.
function parseDetectors(body, filename, errors, frontmatterLines = 0) {
  const detectors = []
  const re = /```detector\r?\n([\s\S]*?)```/g
  let m
  while ((m = re.exec(body)) !== null) {
    const line = body.slice(0, m.index).split(/\r?\n/).length + frontmatterLines
    let parsed
    try {
      parsed = parseYaml(m[1]) ?? {}
    } catch (err) {
      errors.push(`${filename}:${line}: detector block yaml parse failed — ${err.message}`)
      continue
    }
    detectors.push({
      match: typeof parsed.match === 'string' ? parsed.match : null,
      nomatch: typeof parsed.nomatch === 'string' ? parsed.nomatch : null,
      line,
    })
  }
  return detectors
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/frontmatter.test.mjs`
Expected: PASS, 5 tests

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/frontmatter.mjs test/frontmatter.test.mjs test/samples/minimal-lens.md
git commit -m "feat: add lens frontmatter and section parser"
```

---

### Task 3: Ownership registry model — R1, R2, R3

**Files:**
- Create: `scripts/lib/registry.mjs`, `test/registry.test.mjs`

**Interfaces:**
- Consumes: `parseLens` output objects from Task 2
- Produces:
  - `buildRegistry(lenses) -> { slugs: Map<slug, lensName>, violations: Violation[] }`
  - `Violation` is `{ rule: 'R1'|'R2'|'R3', slug, lenses: string[], message }`
  - `slugs` is the generated registry later consumed by `gen-topics.mjs`

- [ ] **Step 1: Write the failing test**

Create `test/registry.test.mjs`:

```javascript
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildRegistry } from '../scripts/lib/registry.mjs'

const lens = (name, owns, defers = {}, extra = {}) => ({
  name,
  frontmatter: { name, runs_in: 'fanout', owns, defers, ...extra },
  sections: {},
  detectors: [],
  errors: [],
})

test('a clean partition produces no violations', () => {
  const { slugs, violations } = buildRegistry([
    lens('web', ['csrf', 'xss'], { 'jwt-verify': 'crypto' }),
    lens('crypto', ['jwt-verify']),
  ])
  assert.deepEqual(violations, [])
  assert.equal(slugs.get('csrf'), 'web')
  assert.equal(slugs.get('jwt-verify'), 'crypto')
  assert.equal(slugs.size, 3)
})

test('R1 flags a slug owned by two lenses', () => {
  const { violations } = buildRegistry([lens('web', ['csrf']), lens('mobile', ['csrf'])])
  const r1 = violations.filter((v) => v.rule === 'R1')
  assert.equal(r1.length, 1)
  assert.equal(r1[0].slug, 'csrf')
  assert.deepEqual(r1[0].lenses.sort(), ['mobile', 'web'])
})

test('R1 flags a lens that both owns and defers the same slug', () => {
  const { violations } = buildRegistry([lens('web', ['csrf'], { csrf: 'mobile' }), lens('mobile', [])])
  assert.ok(violations.some((v) => v.rule === 'R1' && v.slug === 'csrf'))
})

test('R1 flags a duplicate slug inside one owns list', () => {
  const { violations } = buildRegistry([lens('web', ['csrf', 'csrf'])])
  assert.ok(violations.some((v) => v.rule === 'R1' && v.slug === 'csrf'))
})

test('R3 flags a deferral whose target does not own the slug', () => {
  const { violations } = buildRegistry([
    lens('web', ['csrf'], { 'jwt-verify': 'crypto' }),
    lens('crypto', ['aes-nonce']),
  ])
  const r3 = violations.filter((v) => v.rule === 'R3')
  assert.equal(r3.length, 1)
  assert.equal(r3[0].slug, 'jwt-verify')
})

test('R3 flags a deferral naming a lens that does not exist', () => {
  const { violations } = buildRegistry([lens('web', ['csrf'], { 'jwt-verify': 'nope' })])
  assert.ok(violations.some((v) => v.rule === 'R3' && /unknown lens/i.test(v.message)))
})

test('R3 flags a self-deferral', () => {
  const { violations } = buildRegistry([lens('web', ['csrf'], { csrf: 'web' })])
  assert.ok(violations.some((v) => v.rule === 'R3' || v.rule === 'R1'))
})

test('non-owning lenses are exempt rather than violations', () => {
  const { violations } = buildRegistry([
    lens('web', ['csrf']),
    lens('completeness', [], {}, { runs_in: 'triage' }),
    lens('ai-generated-code', [], {}, { always_active: true }),
  ])
  assert.deepEqual(violations, [])
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `node --test test/registry.test.mjs`
Expected: FAIL — `Cannot find module '../scripts/lib/registry.mjs'`

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/registry.mjs`:

```javascript
// Ownership model. Pure functions over parsed lenses — no file I/O, so the
// rules are testable against synthetic lens sets rather than the real corpus.
export function buildRegistry(lenses) {
  const violations = []
  const slugs = new Map()
  const names = new Set(lenses.map((l) => l.frontmatter.name))

  // R1: ownership is a partition.
  for (const l of lenses) {
    const owns = l.frontmatter.owns ?? []
    const seen = new Set()
    for (const slug of owns) {
      if (seen.has(slug)) {
        violations.push({ rule: 'R1', slug, lenses: [l.frontmatter.name], message: `${l.frontmatter.name}: slug "${slug}" listed twice in owns` })
        continue
      }
      seen.add(slug)
      const existing = slugs.get(slug)
      if (existing !== undefined) {
        violations.push({ rule: 'R1', slug, lenses: [existing, l.frontmatter.name], message: `slug "${slug}" owned by both ${existing} and ${l.frontmatter.name}` })
        continue
      }
      slugs.set(slug, l.frontmatter.name)
    }
    for (const slug of Object.keys(l.frontmatter.defers ?? {})) {
      if (seen.has(slug)) {
        violations.push({ rule: 'R1', slug, lenses: [l.frontmatter.name], message: `${l.frontmatter.name}: owns and defers the same slug "${slug}"` })
      }
    }
  }

  // R3: every deferral resolves to the actual owner.
  for (const l of lenses) {
    for (const [slug, target] of Object.entries(l.frontmatter.defers ?? {})) {
      if (target === l.frontmatter.name) {
        violations.push({ rule: 'R3', slug, lenses: [l.frontmatter.name], message: `${l.frontmatter.name}: defers "${slug}" to itself` })
        continue
      }
      if (!names.has(target)) {
        violations.push({ rule: 'R3', slug, lenses: [l.frontmatter.name, target], message: `${l.frontmatter.name}: defers "${slug}" to unknown lens "${target}"` })
        continue
      }
      const owner = slugs.get(slug)
      if (owner !== target) {
        violations.push({ rule: 'R3', slug, lenses: [l.frontmatter.name, target], message: `${l.frontmatter.name}: defers "${slug}" to ${target}, but it is owned by ${owner ?? 'nobody'}` })
      }
    }
  }

  return { slugs, violations }
}

// R2 compares the generated registry against a committed one. Kept separate
// from buildRegistry because R2 is about drift between files, not about the model.
export function diffRegistry(generated, committed) {
  const violations = []
  for (const [slug, owner] of generated) {
    if (!committed.has(slug)) {
      violations.push({ rule: 'R2', slug, lenses: [owner], message: `slug "${slug}" owned by ${owner} is missing from _topics.md` })
    } else if (committed.get(slug) !== owner) {
      violations.push({ rule: 'R2', slug, lenses: [owner, committed.get(slug)], message: `slug "${slug}": frontmatter says ${owner}, _topics.md says ${committed.get(slug)}` })
    }
  }
  for (const [slug, owner] of committed) {
    if (!generated.has(slug)) {
      violations.push({ rule: 'R2', slug, lenses: [owner], message: `slug "${slug}" in _topics.md is owned by no lens` })
    }
  }
  return violations
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/registry.test.mjs`
Expected: PASS, 8 tests

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/registry.mjs test/registry.test.mjs
git commit -m "feat: add ownership registry model enforcing R1, R2, R3"
```

---

### Task 4: Shape coherence and orthography — R5, R6

**Files:**
- Create: `scripts/lib/orthography.mjs`, `test/shape.test.mjs`
- Modify: `scripts/lib/registry.mjs` (add `checkShapes`)

**Interfaces:**
- Consumes: parsed lenses from Task 2
- Produces:
  - `checkOrthography(slugs) -> Violation[]` with `rule: 'R5'`
  - `checkShapes(lenses) -> Violation[]` with `rule: 'R6'`

- [ ] **Step 1: Write the failing test**

Create `test/shape.test.mjs`:

```javascript
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkOrthography } from '../scripts/lib/orthography.mjs'
import { checkShapes } from '../scripts/lib/registry.mjs'

test('R5 flags British -isation spellings', () => {
  const v = checkOrthography(['rag-retrieval-authorization', 'payment-page-script-authorisation'])
  assert.equal(v.length, 1)
  assert.equal(v[0].slug, 'payment-page-script-authorisation')
  assert.match(v[0].message, /authorization/)
})

test('R5 flags -isation and -yse forms', () => {
  assert.equal(checkOrthography(['collection-side-minimisation']).length, 1)
  assert.equal(checkOrthography(['traffic-analyse-gap']).length, 1)
})

test('R5 accepts a clean American slug set', () => {
  assert.deepEqual(checkOrthography(['deserialization-and-xxe', 'csrf', 'tenant-isolation-enforcement']), [])
})

// Supplies the keys every shape needs, so a fixture that is meant to be VALID
// actually is. Per-test `fm` overrides whatever that test is about. Without the
// defaults, the "three valid shapes" fixtures are missing title/frameworks/
// severity_floor and R6 correctly rejects them — which reads as a bug in
// checkShapes and tempts a shrinking of REQUIRED_KEYS. Do not shrink it: the
// spec's lens contract requires all eight keys, and Task 9 assigns a
// severity_floor per lens, so dropping them from the check means a lens can
// omit them and still lint green.
const l = (name, fm) => ({
  name,
  frontmatter: { name, title: name, frameworks: [], severity_floor: 'low', ...fm },
  sections: {},
  detectors: [],
  errors: [],
})

test('R6 accepts the three valid shapes', () => {
  const v = checkShapes([
    l('web', { runs_in: 'fanout', activates_on: { paths: ['a'], signals: [] }, owns: ['csrf'], defers: {} }),
    l('ai-generated-code', { runs_in: 'fanout', always_active: true, activates_on: { paths: [], signals: [] }, owns: [], defers: {} }),
    l('completeness', { runs_in: 'triage', activates_on: { paths: [], signals: [] }, owns: [], defers: {} }),
  ])
  assert.deepEqual(v, [])
})

test('R6 flags a triage lens that owns slugs', () => {
  const v = checkShapes([l('completeness', { runs_in: 'triage', activates_on: { paths: [], signals: [] }, owns: ['csrf'], defers: {} })])
  assert.ok(v.some((x) => /triage.*owns/i.test(x.message)))
})

test('R6 flags a triage lens with a non-empty activates_on', () => {
  const v = checkShapes([l('completeness', { runs_in: 'triage', activates_on: { paths: ['**/*'], signals: [] }, owns: [], defers: {} })])
  assert.ok(v.some((x) => /activates_on/i.test(x.message)))
})

test('R6 flags always_active combined with runs_in triage', () => {
  const v = checkShapes([l('x', { runs_in: 'triage', always_active: true, activates_on: { paths: [], signals: [] }, owns: [], defers: {} })])
  assert.ok(v.some((x) => /always_active/i.test(x.message)))
})

test('R6 flags an always-on lens that owns slugs', () => {
  const v = checkShapes([l('x', { runs_in: 'fanout', always_active: true, activates_on: { paths: [], signals: [] }, owns: ['csrf'], defers: {} })])
  assert.ok(v.some((x) => /always_active.*owns/i.test(x.message)))
})

test('R6 flags a domain lens with an empty activates_on', () => {
  const v = checkShapes([l('web', { runs_in: 'fanout', activates_on: { paths: [], signals: [] }, owns: ['csrf'], defers: {} })])
  assert.ok(v.some((x) => /must match something/i.test(x.message)))
})

test('R6 flags missing required keys', () => {
  const v = checkShapes([l('web', { runs_in: 'fanout' })])
  assert.ok(v.some((x) => /missing/i.test(x.message)))
})

test('R6 flags each of the eight required keys individually', () => {
  const valid = {
    runs_in: 'fanout',
    activates_on: { paths: ['a'], signals: [] },
    owns: ['csrf'],
    defers: {},
  }
  for (const key of ['title', 'frameworks', 'severity_floor', 'runs_in', 'activates_on', 'owns', 'defers']) {
    const v = checkShapes([l('web', { ...valid, [key]: undefined })])
    assert.ok(
      v.some((x) => x.message.includes(`"${key}"`)),
      `omitting ${key} should be flagged, but it was not`
    )
  }
})

test('R6 flags an unknown runs_in value', () => {
  const v = checkShapes([l('web', { runs_in: 'sometimes', activates_on: { paths: [], signals: [] }, owns: [], defers: {} })])
  assert.ok(v.some((x) => /runs_in/i.test(x.message)))
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `node --test test/shape.test.mjs`
Expected: FAIL — `Cannot find module '../scripts/lib/orthography.mjs'`

- [ ] **Step 3: Write the orthography module**

Create `scripts/lib/orthography.mjs`:

```javascript
// One convention, mechanically enforced: American -ization. The verifier found
// payment-page-script-authorisation three slugs from rag-retrieval-authorization,
// which is a typo hazard no reviewer reliably catches.
const BRITISH = [
  { pattern: /isation\b/, fix: (s) => s.replace(/isation\b/, 'ization') },
  { pattern: /isations\b/, fix: (s) => s.replace(/isations\b/, 'izations') },
  { pattern: /ised\b/, fix: (s) => s.replace(/ised\b/, 'ized') },
  { pattern: /yse\b/, fix: (s) => s.replace(/yse\b/, 'yze') },
  { pattern: /ysed\b/, fix: (s) => s.replace(/ysed\b/, 'yzed') },
]

export function checkOrthography(slugs) {
  const violations = []
  for (const slug of slugs) {
    for (const { pattern, fix } of BRITISH) {
      if (pattern.test(slug)) {
        violations.push({ rule: 'R5', slug, lenses: [], message: `slug "${slug}" uses British spelling; use "${fix(slug)}"` })
        break
      }
    }
  }
  return violations
}
```

- [ ] **Step 4: Add checkShapes to registry.mjs**

Append to `scripts/lib/registry.mjs`:

```javascript
const REQUIRED_KEYS = ['name', 'title', 'runs_in', 'activates_on', 'owns', 'defers', 'frameworks', 'severity_floor']

// Three legal shapes. runs_in replaced an earlier cross_cutting boolean because
// one flag was carrying two facts: when a lens runs, and whether it owns territory.
export function checkShapes(lenses) {
  const violations = []
  for (const l of lenses) {
    const fm = l.frontmatter
    const name = fm.name ?? l.name ?? '<unnamed>'
    const push = (message) => violations.push({ rule: 'R6', slug: null, lenses: [name], message })

    for (const key of REQUIRED_KEYS) {
      if (fm[key] === undefined) push(`${name}: missing required frontmatter key "${key}"`)
    }
    if (fm.runs_in !== 'fanout' && fm.runs_in !== 'triage') {
      push(`${name}: runs_in must be "fanout" or "triage", got "${fm.runs_in}"`)
      continue
    }

    const owns = fm.owns ?? []
    const paths = fm.activates_on?.paths ?? []
    const signals = fm.activates_on?.signals ?? []
    const matches = paths.length + signals.length

    if (fm.runs_in === 'triage') {
      if (fm.always_active) push(`${name}: always_active is only valid with runs_in: fanout`)
      if (owns.length) push(`${name}: runs_in triage but owns ${owns.length} slug(s); triage lenses reason over findings and own nothing`)
      if (matches) push(`${name}: runs_in triage but activates_on is non-empty; triage lenses activate on findings, not paths`)
      if (Object.keys(fm.defers ?? {}).length) push(`${name}: runs_in triage but declares defers; it owns nothing to defer from`)
    } else if (fm.always_active) {
      if (owns.length) push(`${name}: always_active but owns ${owns.length} slug(s); it reports against other lenses' topics`)
      if (matches) push(`${name}: always_active but activates_on is non-empty; it runs on every audit and must not be matched`)
    } else {
      if (!owns.length) push(`${name}: a domain lens must own at least one slug`)
      if (!matches) push(`${name}: activates_on must match something, or the lens never runs`)
    }
  }
  return violations
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `node --test test/shape.test.mjs test/registry.test.mjs`
Expected: PASS, 19 tests total

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/orthography.mjs scripts/lib/registry.mjs test/shape.test.mjs
git commit -m "feat: enforce lens shape coherence (R6) and slug orthography (R5)"
```

---

### Task 5: Migration ledger gate

**Files:**
- Create: `scripts/lib/ledger.mjs`, `test/ledger.test.mjs`, `test/samples/ledger-ok.tsv`, `test/samples/ledger-bad.tsv`

**Interfaces:**
- Consumes: nothing from earlier tasks
- Produces: `parseLedger(text) -> { rows, violations }` with `rule: 'LEDGER'`; `rows` is `[{ source, destination, disposition, evidence }]`

- [ ] **Step 1: Write the failing test**

Create `test/samples/ledger-ok.tsv`:

```
source	destination	disposition	evidence
SKILL.md#llm-generated-code-tells	ai-generated-code	moved	punch-list-§1
references/web-and-api.md:43	web-and-api/injection-sql-nosql-orm	corrected	punch-list-§1-item-2
references/mobile.md:88	—	intentionally_removed	punch-list-§6-branding
```

Create `test/samples/ledger-bad.tsv`:

```
source	destination	disposition	evidence
references/web-and-api.md:43	web-and-api/csrf	preserved	
references/mobile.md:12	mobile-app-security/webview-bridge-trust	pending	punch-list-§1
references/crypto-deep-dive.md:55	crypto-and-key-management/aes-nonce	corrected	punch-list-§1-item-4
```

Create `test/ledger.test.mjs`:

```javascript
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { parseLedger } from '../scripts/lib/ledger.mjs'

test('a complete ledger produces no violations', () => {
  const { rows, violations } = parseLedger(readFileSync('test/samples/ledger-ok.tsv', 'utf8'))
  assert.equal(rows.length, 3)
  assert.deepEqual(violations, [])
  assert.equal(rows[0].disposition, 'moved')
})

test('an unknown disposition is a violation', () => {
  const { violations } = parseLedger(readFileSync('test/samples/ledger-bad.tsv', 'utf8'))
  assert.ok(violations.some((v) => /pending/.test(v.message)))
})

test('a row with no evidence is a violation', () => {
  const { violations } = parseLedger(readFileSync('test/samples/ledger-bad.tsv', 'utf8'))
  assert.ok(violations.some((v) => /evidence/i.test(v.message)))
})

test('intentionally_removed is accepted as a disposition', () => {
  const { violations } = parseLedger('source\tdestination\tdisposition\tevidence\na\t—\tintentionally_removed\te1\n')
  assert.deepEqual(violations, [])
})

test('a wrong column count is a violation, not a crash', () => {
  const { violations } = parseLedger('source\tdestination\tdisposition\tevidence\na\tb\n')
  assert.ok(violations.some((v) => /columns/i.test(v.message)))
})

test('an empty ledger with only a header is a violation', () => {
  const { violations } = parseLedger('source\tdestination\tdisposition\tevidence\n')
  assert.ok(violations.some((v) => /no rows/i.test(v.message)))
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `node --test test/ledger.test.mjs`
Expected: FAIL — `Cannot find module '../scripts/lib/ledger.mjs'`

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/ledger.mjs`:

```javascript
// The ledger is what proves content survived migration. Metadata lint cannot
// see a deleted checklist item; a ledger row with a disposition can.
const DISPOSITIONS = new Set(['preserved', 'corrected', 'moved', 'intentionally_removed'])
const HEADER = ['source', 'destination', 'disposition', 'evidence']

export function parseLedger(text) {
  const violations = []
  const rows = []
  // Carry each line's PHYSICAL number alongside its text. Filtering blanks out
  // before indexing makes every reported line number drift upward by the count
  // of blank lines above it, which sends a contributor to the wrong row.
  const lines = text
    .split(/\r?\n/)
    .map((text, i) => ({ text, lineNo: i + 1 }))
    .filter((l) => l.text.trim() !== '')

  if (!lines.length) {
    return { rows, violations: [{ rule: 'LEDGER', message: 'migration ledger is empty' }] }
  }
  const header = lines[0].text.split('\t').map((h) => h.trim())
  if (header.join(',') !== HEADER.join(',')) {
    violations.push({ rule: 'LEDGER', message: `ledger header must be exactly ${HEADER.join(' / ')}, got ${header.join(' / ')}` })
  }
  if (lines.length === 1) {
    violations.push({ rule: 'LEDGER', message: 'migration ledger has no rows; Phase A cannot close' })
  }

  lines.slice(1).forEach(({ text: line, lineNo }) => {
    const cells = line.split('\t')
    if (cells.length !== HEADER.length) {
      violations.push({ rule: 'LEDGER', message: `ledger line ${lineNo}: expected ${HEADER.length} columns, got ${cells.length}` })
      return
    }
    const [source, destination, disposition, evidence] = cells.map((c) => c.trim())
    if (!DISPOSITIONS.has(disposition)) {
      violations.push({ rule: 'LEDGER', message: `ledger line ${lineNo}: disposition "${disposition}" is not one of ${[...DISPOSITIONS].join(', ')}` })
    }
    if (!evidence) {
      violations.push({ rule: 'LEDGER', message: `ledger line ${lineNo}: no evidence reference for "${source}"` })
    }
    if (!source) {
      violations.push({ rule: 'LEDGER', message: `ledger line ${lineNo}: no source location` })
    }
    rows.push({ source, destination, disposition, evidence })
  })

  return { rows, violations }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/ledger.test.mjs`
Expected: PASS, 6 tests

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/ledger.mjs test/ledger.test.mjs test/samples/ledger-ok.tsv test/samples/ledger-bad.tsv
git commit -m "feat: add migration ledger parser and completeness gate"
```

---

### Task 6: Detector completeness rule — R7

**Files:**
- Create: `test/detector.test.mjs`
- Modify: `scripts/lib/registry.mjs` (add `checkDetectors`)

**Interfaces:**
- Consumes: `detectors` from Task 2's `parseLens`
- Produces: `checkDetectors(lenses) -> Violation[]` with `rule: 'R7'`

This is the mechanism for spec gate A2: a corrected search instruction must be demonstrated to fire. Eleven checks in the current references match nothing in real code and therefore return silent all-clears; a detector block with both directions is what makes that impossible to ship again.

- [ ] **Step 1: Write the failing test**

Create `test/detector.test.mjs`:

```javascript
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { checkDetectors } from '../scripts/lib/registry.mjs'

const withDetectors = (name, detectors, sections = { Checklist: 'x' }) => ({
  name, frontmatter: { name, runs_in: 'fanout' }, sections, detectors, errors: [],
})

test('a detector with both directions passes', () => {
  const v = checkDetectors([withDetectors('web', [{ match: 'app.post(x)', nomatch: 'app.post(x, csrf)', line: 10 }])])
  assert.deepEqual(v, [])
})

test('R7 flags a detector missing nomatch', () => {
  const v = checkDetectors([withDetectors('web', [{ match: 'app.post(x)', nomatch: null, line: 10 }])])
  assert.equal(v.length, 1)
  assert.match(v[0].message, /nomatch/)
})

test('R7 flags a detector missing match', () => {
  const v = checkDetectors([withDetectors('web', [{ match: null, nomatch: 'safe', line: 10 }])])
  assert.ok(v.some((x) => /match/.test(x.message)))
})

test('R7 flags identical match and nomatch as non-discriminating', () => {
  const v = checkDetectors([withDetectors('web', [{ match: 'same', nomatch: 'same', line: 10 }])])
  assert.ok(v.some((x) => /identical/i.test(x.message)))
})

test('R7 flags a domain lens with a Checklist and no detectors at all', () => {
  const v = checkDetectors([withDetectors('web', [], { Checklist: 'look for things' })])
  assert.ok(v.some((x) => /no detector/i.test(x.message)))
})

test('R7 exempts a lens with no Checklist section', () => {
  const v = checkDetectors([withDetectors('completeness', [], { Scope: 'reads findings' })])
  assert.deepEqual(v, [])
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `node --test test/detector.test.mjs`
Expected: FAIL — `checkDetectors is not a function`

- [ ] **Step 3: Add checkDetectors to registry.mjs**

Append to `scripts/lib/registry.mjs`:

```javascript
// R7 realizes spec gate A2. A search instruction nobody demonstrated firing is
// worse than a missing check: it runs, matches nothing, and reports clean.
export function checkDetectors(lenses) {
  const violations = []
  for (const l of lenses) {
    const name = l.frontmatter.name ?? l.name ?? '<unnamed>'
    const push = (message) => violations.push({ rule: 'R7', slug: null, lenses: [name], message })

    if (l.sections.Checklist === undefined) continue
    if (!l.detectors.length) {
      push(`${name}: has a Checklist but no detector blocks; at least one search instruction must be demonstrated firing`)
      continue
    }
    for (const d of l.detectors) {
      if (!d.match) push(`${name}:${d.line}: detector has no "match" example, so nothing shows the check fires`)
      if (!d.nomatch) push(`${name}:${d.line}: detector has no "nomatch" example, so nothing shows the check discriminates`)
      if (d.match && d.nomatch && d.match.trim() === d.nomatch.trim()) {
        push(`${name}:${d.line}: match and nomatch are identical, so the detector proves nothing`)
      }
    }
  }
  return violations
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/detector.test.mjs`
Expected: PASS, 6 tests

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/registry.mjs test/detector.test.mjs
git commit -m "feat: require both-direction detector examples (R7)"
```

---

### Task 7: The lint CLI

**Files:**
- Create: `scripts/lint-lenses.mjs`, `test/lint-cli.test.mjs`, `test/samples/corpus-ok/`, `test/samples/corpus-bad/`

**Interfaces:**
- Consumes: `parseLens`, `buildRegistry`, `diffRegistry`, `checkShapes`, `checkDetectors`, `checkOrthography`, `detectorCoverage`, `parseLedger`
- Produces: `runLint({ lensDir, topicsFile, ledgerFile }) -> { violations, observations, counts }`; CLI exits 1 when `violations.length > 0`. **`observations` never affect the exit code** — they are printed and ignored by CI.

The `observations` channel exists because R7 can be satisfied without being served: a lens may carry one trivial detector and leave a dozen undemonstrated search instructions in its Checklist. Counting search instructions from prose cannot be made exact, so it must not gate the build — but it must not be invisible either, which is what leaving it to human review across ten migrations amounts to. `detectorCoverage` reports backticked literals versus detector count per lens, so under-coverage shows up in every lint run and a migration reviewer sees a number instead of an impression.

- [ ] **Step 1: Write the failing test**

Create `test/samples/corpus-ok/web.md` — copy `test/samples/minimal-lens.md` and change `name:` to `web-sample`. Create `test/samples/corpus-ok/crypto.md`:

````markdown
---
name: crypto-and-key-management
title: Cryptography and key management
runs_in: fanout
activates_on:
  paths: ["**/crypto/**"]
  signals: ["cryptography"]
owns: [jwt-jws-and-jwks-verification]
defers: {}
frameworks: [cwe-top-25]
severity_floor: low
---

## Scope

Owns JWT verification.

## Checklist

- Look for tokens decoded without signature verification.

```detector
match: |
  jwt.decode(token, options={"verify_signature": False})
nomatch: |
  jwt.decode(token, key, algorithms=["RS256"])
```
````

Create `test/samples/corpus-ok/_topics.md`:

```markdown
# Canonical topic registry

<!-- GENERATED by scripts/gen-topics.mjs — do not edit by hand -->

## crypto-and-key-management

- jwt-jws-and-jwks-verification

## web-sample

- csrf
```

Create `test/samples/corpus-bad/web.md` — same as `corpus-ok/web.md` but with `owns: [csrf, jwt-jws-and-jwks-verification]` so it collides with crypto. Copy `corpus-ok/crypto.md` and `corpus-ok/_topics.md` in unchanged.

Create `test/lint-cli.test.mjs`:

```javascript
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { runLint } from '../scripts/lint-lenses.mjs'

test('a clean corpus produces no violations', () => {
  const { violations, counts } = runLint({
    lensDir: 'test/samples/corpus-ok',
    topicsFile: 'test/samples/corpus-ok/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
  })
  assert.deepEqual(violations, [])
  assert.equal(counts.lenses, 2)
  assert.equal(counts.slugs, 2)
})

test('a colliding corpus reports R1 and R2 and does not throw', () => {
  const { violations } = runLint({
    lensDir: 'test/samples/corpus-bad',
    topicsFile: 'test/samples/corpus-bad/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
  })
  assert.ok(violations.some((v) => v.rule === 'R1'))
  assert.ok(violations.some((v) => v.rule === 'R2'))
})

test('ledger violations surface through the same channel', () => {
  const { violations } = runLint({
    lensDir: 'test/samples/corpus-ok',
    topicsFile: 'test/samples/corpus-ok/_topics.md',
    ledgerFile: 'test/samples/ledger-bad.tsv',
  })
  assert.ok(violations.some((v) => v.rule === 'LEDGER'))
})

test('files starting with an underscore are not treated as lenses', () => {
  const { counts } = runLint({
    lensDir: 'test/samples/corpus-ok',
    topicsFile: 'test/samples/corpus-ok/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
  })
  assert.equal(counts.lenses, 2)
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `node --test test/lint-cli.test.mjs`
Expected: FAIL — `Cannot find module '../scripts/lint-lenses.mjs'`

- [ ] **Step 3: Write the implementation**

Create `scripts/lint-lenses.mjs`:

```javascript
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { parseLens } from './lib/frontmatter.mjs'
import { buildRegistry, diffRegistry, checkShapes, checkDetectors, detectorCoverage } from './lib/registry.mjs'
import { checkOrthography } from './lib/orthography.mjs'
import { parseLedger } from './lib/ledger.mjs'

const DEFAULTS = {
  lensDir: 'skills/last-aperture/lenses',
  topicsFile: 'skills/last-aperture/lenses/_topics.md',
  ledgerFile: 'docs/migration-ledger.tsv',
}

// Underscore-prefixed files are contracts and generated artifacts, not lenses.
function loadLenses(lensDir) {
  return readdirSync(lensDir)
    .filter((f) => f.endsWith('.md') && !f.startsWith('_'))
    .sort()
    .map((f) => parseLens(readFileSync(join(lensDir, f), 'utf8'), f))
}

export function parseTopicsFile(text) {
  const committed = new Map()
  let owner = null
  for (const line of text.split(/\r?\n/)) {
    const heading = /^##\s+(\S+)\s*$/.exec(line)
    if (heading) { owner = heading[1]; continue }
    const item = /^[-*]\s+(\S+)\s*$/.exec(line)
    if (item && owner) committed.set(item[1], owner)
  }
  return committed
}

export function runLint(opts = {}) {
  const { lensDir, topicsFile, ledgerFile } = { ...DEFAULTS, ...opts }
  const lenses = loadLenses(lensDir)
  const violations = []

  for (const l of lenses) {
    for (const message of l.errors) violations.push({ rule: 'PARSE', slug: null, lenses: [l.name], message })
  }

  const { slugs, violations: registryViolations } = buildRegistry(lenses)
  violations.push(...registryViolations)
  violations.push(...checkShapes(lenses))
  violations.push(...checkDetectors(lenses))
  violations.push(...checkOrthography([...slugs.keys()]))
  violations.push(...diffRegistry(slugs, parseTopicsFile(readFileSync(topicsFile, 'utf8'))))
  violations.push(...parseLedger(readFileSync(ledgerFile, 'utf8')).violations)

  return { violations, counts: { lenses: lenses.length, slugs: slugs.size } }
}

// Do NOT "simplify" this to `file://${process.argv[1]}`. On Windows that builds
// file://C:\path\with\backslashes while import.meta.url is file:///C:/path/with/
// forward-slashes, so the comparison is always false and the entire CLI block
// silently never runs — a lint that always exits 0 without checking anything.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { violations, counts } = runLint()
  const byRule = violations.reduce((acc, v) => ((acc[v.rule] = (acc[v.rule] ?? 0) + 1), acc), {})
  for (const v of violations) console.error(`[${v.rule}] ${v.message}`)
  console.log(`\n${counts.lenses} lenses, ${counts.slugs} slugs owned.`)
  if (violations.length) {
    console.error(`FAIL: ${violations.length} violation(s) — ${JSON.stringify(byRule)}`)
    process.exit(1)
  }
  console.log('PASS: R1-R7 and ledger gate clean.')
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/lint-cli.test.mjs`
Expected: PASS, 4 tests

- [ ] **Step 5: Commit**

```bash
git add scripts/lint-lenses.mjs test/lint-cli.test.mjs test/samples/corpus-ok test/samples/corpus-bad
git commit -m "feat: add lint CLI wiring R1-R7 and the ledger gate"
```

---

### Task 8: The generator, with drift detection

**Files:**
- Create: `scripts/gen-topics.mjs`, `test/gen-topics.test.mjs`

**Interfaces:**
- Consumes: `parseLens`, `buildRegistry`
- Produces: `renderTopics(slugs) -> string`, `renderOverlap(lenses, slugs) -> string`; CLI writes both, `--check` exits 1 on any difference

Spec criterion 13: the generator must reproduce the committed files byte-for-byte. `--check` is what makes a second source of truth impossible to introduce quietly.

- [ ] **Step 1: Write the failing test**

Create `test/gen-topics.test.mjs`:

```javascript
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { renderTopics, renderOverlap } from '../scripts/gen-topics.mjs'
import { parseTopicsFile } from '../scripts/lint-lenses.mjs'

const slugs = new Map([
  ['csrf', 'web-sample'],
  ['jwt-jws-and-jwks-verification', 'crypto-and-key-management'],
])

test('renderTopics output round-trips through parseTopicsFile', () => {
  assert.deepEqual([...parseTopicsFile(renderTopics(slugs))].sort(), [...slugs].sort())
})

test('renderTopics reproduces the committed sample byte-for-byte', () => {
  assert.equal(renderTopics(slugs), readFileSync('test/samples/corpus-ok/_topics.md', 'utf8'))
})

test('renderTopics is deterministic and sorted', () => {
  const reversed = new Map([...slugs].reverse())
  assert.equal(renderTopics(slugs), renderTopics(reversed))
})

test('renderOverlap emits exactly one row per slug', () => {
  const lenses = [
    { frontmatter: { name: 'web-sample', owns: ['csrf'], defers: {} } },
    { frontmatter: { name: 'crypto-and-key-management', owns: ['jwt-jws-and-jwks-verification'], defers: { csrf: 'web-sample' } } },
  ]
  const rows = renderOverlap(lenses, slugs).split('\n').filter((l) => l.startsWith('| `'))
  assert.equal(rows.length, slugs.size)
  assert.ok(rows.some((r) => r.includes('`csrf`') && r.includes('crypto-and-key-management')))
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `node --test test/gen-topics.test.mjs`
Expected: FAIL — `Cannot find module '../scripts/gen-topics.mjs'`

- [ ] **Step 3: Write the implementation**

Create `scripts/gen-topics.mjs`:

```javascript
import { readFileSync, readdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { parseLens } from './lib/frontmatter.mjs'
import { buildRegistry } from './lib/registry.mjs'

const LENS_DIR = 'skills/last-aperture/lenses'
const TOPICS = join(LENS_DIR, '_topics.md')
const OVERLAP = 'docs/ownership-overlap.md'
const BANNER = '<!-- GENERATED by scripts/gen-topics.mjs — do not edit by hand -->'

export function renderTopics(slugs) {
  const byOwner = new Map()
  for (const [slug, owner] of slugs) {
    if (!byOwner.has(owner)) byOwner.set(owner, [])
    byOwner.get(owner).push(slug)
  }
  const out = ['# Canonical topic registry', '', BANNER, '']
  for (const owner of [...byOwner.keys()].sort()) {
    out.push(`## ${owner}`, '')
    for (const slug of byOwner.get(owner).sort()) out.push(`- ${slug}`)
    out.push('')
  }
  return out.join('\n')
}

export function renderOverlap(lenses, slugs) {
  const deferrers = new Map()
  for (const l of lenses) {
    for (const slug of Object.keys(l.frontmatter.defers ?? {})) {
      if (!deferrers.has(slug)) deferrers.set(slug, [])
      deferrers.get(slug).push(l.frontmatter.name)
    }
  }
  const out = ['# Topic ownership and deferrals', '', BANNER, '', '| Topic slug | Owning lens | Lenses deferring to it |', '|---|---|---|']
  for (const slug of [...slugs.keys()].sort()) {
    const d = (deferrers.get(slug) ?? []).sort()
    out.push(`| \`${slug}\` | ${slugs.get(slug)} | ${d.length ? d.join(', ') : '—'} |`)
  }
  out.push('')
  return out.join('\n')
}

function load() {
  const lenses = readdirSync(LENS_DIR)
    .filter((f) => f.endsWith('.md') && !f.startsWith('_'))
    .sort()
    .map((f) => parseLens(readFileSync(join(LENS_DIR, f), 'utf8'), f))
  return { lenses, slugs: buildRegistry(lenses).slugs }
}

// Do NOT "simplify" this to `file://${process.argv[1]}`. On Windows that builds
// file://C:\path\with\backslashes while import.meta.url is file:///C:/path/with/
// forward-slashes, so the comparison is always false and the entire CLI block
// silently never runs — a lint that always exits 0 without checking anything.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const check = process.argv.includes('--check')
  const { lenses, slugs } = load()
  const targets = [
    { path: TOPICS, content: renderTopics(slugs) },
    { path: OVERLAP, content: renderOverlap(lenses, slugs) },
  ]
  let drift = false
  for (const { path, content } of targets) {
    if (check) {
      const existing = readFileSync(path, 'utf8')
      if (existing !== content) {
        console.error(`DRIFT: ${path} does not match what frontmatter generates. Run "npm run gen".`)
        drift = true
      }
    } else {
      writeFileSync(path, content)
      console.log(`wrote ${path}`)
    }
  }
  if (drift) process.exit(1)
  if (check) console.log(`PASS: generated artifacts match frontmatter (${slugs.size} slugs).`)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test test/gen-topics.test.mjs`
Expected: PASS, 4 tests

- [ ] **Step 5: Run the whole suite**

Run: `npm test`
Expected: PASS, 42 tests across 7 files

- [ ] **Step 6: Commit**

```bash
git add scripts/gen-topics.mjs test/gen-topics.test.mjs
git commit -m "feat: generate _topics.md and overlap table from frontmatter with drift check"
```

---

### Task 9: Lens stubs — frontmatter for all fourteen

**Files:**
- Create: `skills/last-aperture/lenses/<14 files>.md`, `docs/migration-ledger.tsv`
- Read: `docs/design/2026-07-26-recon-punch-list-repair.md`, `docs/design/2026-07-26-recon-punch-list.md`

**Interfaces:**
- Consumes: the lint and generator CLIs from Tasks 7–8
- Produces: fourteen lens files containing frontmatter plus empty section skeletons, so every later content task lands against a green lint

Bodies stay empty here on purpose. Getting the contract green first means each body task is validated the moment it lands, instead of discovering a collision after ten migrations.

- [ ] **Step 1: Create the ten domain lens files, frontmatter only**

Sources, copied not re-derived:
- `web-and-api` — repair companion lines 3–225
- `crypto-and-key-management` — repair companion lines 226–314
- `cloud-and-iac`, `cicd-and-supply-chain`, `mobile-app-security`, `llm-and-ai`, `hipaa-and-phi`, `privacy-and-data-protection`, `salesforce-platform`, `threat-modeling` — punch list lines 230–1477

Apply these transforms while copying:

1. `cross_cutting: false` → `runs_in: fanout`.
2. Remove `hash-as-pseudonym-reversibility` from `crypto-and-key-management`'s `owns`. It is the resolved duplicate; `pseudonymization-and-reidentification-risk` under `privacy-and-data-protection` is the survivor.
3. Rename slugs: `client-cached-sensitive-state` → `lwc-client-state-exposure`; `hipaa-documentation-retention` → `hipaa-policy-documentation-retention`; `mobile-network-config-artifacts` → `mobile-cleartext-and-ats-config`; `native-module-provenance` → `vendored-native-code-provenance`. Update every `defers` reference to each.
4. Convert every British slug to American: `request-smuggling-and-proxy-normalisation` → `-normalization`, `collection-side-minimisation` → `-minimization`, `dsr-fulfilment-mechanics` → `dsr-fulfillment-mechanics`, `pseudonymisation-and-reidentification-risk` → `pseudonymization-`, `payment-page-script-authorisation` → `-authorization`.
5. Add the ten `defers` keys the verifier found missing (repair companion lines 738–752): `mobile-app-security` → `debug-and-admin-endpoint-exposure: web-and-api`; `threat-modeling` → `debug-and-admin-endpoint-exposure: web-and-api`; `mobile-app-security` → `legacy-hash-and-cipher-primitives: crypto-and-key-management`; `web-and-api` → `dependency-eol-and-abandonment: cicd-and-supply-chain`; `salesforce-platform` → `mass-assignment-and-parameter-binding: web-and-api`; `threat-modeling` → `pii-inventory-and-data-map: privacy-and-data-protection`; `hipaa-and-phi` → `personal-data-severity-uplift: privacy-and-data-protection`; `hipaa-and-phi` → `collection-side-minimization: privacy-and-data-protection`; `cloud-and-iac` → `package-dependency-cves: cicd-and-supply-chain`; `llm-and-ai` → `third-party-destination-inventory: privacy-and-data-protection`.
6. Drop `owasp-asvs` from `web-and-api`'s `frameworks`. Never write `SANS Top 25`.

Each file gets this body skeleton after its frontmatter, with no content yet:

```markdown
## Scope

## Checklist

## Severity calibration

## Known false positives

## Proof recipes
```

Exception: `hipaa-and-phi` also gets a trailing `## Report format override` heading.

- [ ] **Step 2: Create the four non-owning lens files**

`ai-generated-code.md`:

```yaml
---
name: ai-generated-code
title: Machine-authored code tells
runs_in: fanout
always_active: true
activates_on:
  paths: []
  signals: []
owns: []
defers: {}
frameworks: [cwe-top-25]
severity_floor: low
---
```

`attack-chaining.md`, `business-logic.md`, `completeness.md`, each with:

```yaml
runs_in: triage
activates_on:
  paths: []
  signals: []
owns: []
defers: {}
```

`frameworks` for `attack-chaining` is `[mitre-attack]`; for the other two, `[]`. `severity_floor` is `low` for `attack-chaining` and `business-logic`, `info` for `completeness`.

Give all four only a `## Scope` heading. Their bodies are Phase B work, and `## Checklist` must be absent so R7 correctly exempts them.

- [ ] **Step 3: Seed the migration ledger**

Create `docs/migration-ledger.tsv` with the header row and one row per lens file created, `disposition` = `moved`, `evidence` = the source document and line range. Add the row that matters most:

```
SKILL.md#llm-generated-code-tells	ai-generated-code	moved	repair-companion-decision
```

- [ ] **Step 4: Generate the registry and run lint**

```bash
npm run gen
npm run lint
```

Expected: `gen` writes `_topics.md` and `docs/ownership-overlap.md`. `lint` reports R7 violations for the ten domain lenses (Checklist present but empty, no detectors) and nothing else. **If any R1, R3, R5 or R6 violation appears, a transform in Step 1 was applied incorrectly — fix it before proceeding.**

- [ ] **Step 5: Temporarily remove empty Checklist headings**

To reach a green baseline, delete the empty `## Checklist` heading from each domain lens; Task 10 onward re-adds it with content. Re-run `npm run lint`.
Expected: PASS with 14 lenses.

- [ ] **Step 6: Record the slug count without treating it as a target**

Run: `npm run lint | tail -3`

Report the printed slug count in your task report. **Do not tune anything to hit a particular number.** The count is whatever correct frontmatter produces; a plan that asserts a specific total invites an implementer to adjust a transform until the number matches, which locks in the error instead of surfacing it. If the count surprises you, re-check the Step 1 transforms and report the discrepancy rather than resolving it silently. Never write the number into any prose file.

- [ ] **Step 7: Commit**

```bash
git add skills/ docs/migration-ledger.tsv docs/ownership-overlap.md
git commit -m "feat: add fourteen lens stubs with normalized ownership frontmatter"
```

---

### Tasks 10–19: Migrate the ten domain lens bodies

Each of these ten tasks follows the same six steps against a different lens. They are separate tasks because each carries different corrections, different false-positive entries and different proof recipes, and because a reviewer must be able to reject one lens's migration while accepting another's.

**Execution order is NOT task-number order.** Task numbers below stay fixed so brief extraction keeps working; the sequence they run in is driven by internal utility, because the primary purpose of this project is finding real issues in the author's own production codebase — HIPAA exposure specifically — with open-sourcing a later, secondary step.

Run them in this order:

| Order | Task | Why here |
|---|---|---|
| 1st | **16 · `hipaa-and-phi`** | The compliance driver. It also carries five confident legal overreaches that each generate *wrong* findings, so until it is corrected it produces false compliance verdicts — actively worse than not running it. |
| 2nd | **18 · `salesforce-platform`** | The author's production stack is Salesforce/Apex, so this lens does the most real work per hour spent. Six platform facts are currently wrong, including `WITH USER_MODE` attributed to the wrong API version and to DML when it is SOQL-only. |
| 3rd | **10 · `crypto-and-key-management`** | Inverted nonce advice generates false positives against correct code, which burns reviewer trust fastest. |
| 4th | **11 · `web-and-api`** | Largest net-new writing; broad applicability. |
| 5th | **17 · `privacy-and-data-protection`** | Pairs with HIPAA for the compliance surface. |
| then | 12 `cloud-and-iac`, 13 `cicd-and-supply-chain`, 15 `llm-and-ai`, 14 `mobile-app-security`, 19 `threat-modeling` | Descending relevance to the author's stack. `mobile-app-security` is late because there is no evidence of a mobile surface in the production codebase. |

**Phase D (packaging, README, LICENSE, marketplace manifest, junction swap) is deferred.** It serves publication only and blocks no internal use. Phases A → B → C deliver the working tool; D happens when the author chooses to publish.

**Per-task source map:**

| Task | Lens | Corrections | False positives | Proof recipes | Notes |
|---|---|---|---|---|---|
| 10 | `crypto-and-key-management` | Punch list §1 item 4 | §4 `crypto-deep-dive` block | §5.5, §5.6, §5.10 | **Do this first.** Three nonce examples currently teach the inverse of the truth and one severity row names the wrong compromised key. Smallest edit, highest stakes. |
| 11 | `web-and-api` | §1 items 2, 3, and the ASVS finding | §4 `web-and-api` block | §5.1, §5.2, §5.3, §5.9 | Must **inline** injection, XSS, deserialization and JWT handling. "Covered in main SKILL.md" is incompatible with a self-contained brief. Largest net-new writing. |
| 12 | `cloud-and-iac` | §1 item 5 and the eleven-check table | §4 `cloud-and-iac` block | §5.11 | Two AWS authorization inversions. Static-checker detectors reach T1 per §5's second resolution. |
| 13 | `cicd-and-supply-chain` | §1 item 6 rows | §4 block | §5.11, §5.13 | `pwn-request` becomes a structural check; `.pip.conf` → `pip.conf`/`pip.ini`. |
| 14 | `mobile-app-security` | §1 item 6 rows; drop Flutter from `activates_on` | §4 block | §5.4, §5.7 | Heaviest: eight technical errors plus a cert-pinning self-contradiction, resolving **downward to Low**. Remove all consumer-app feature names. |
| 15 | `llm-and-ai` | §1 items 9–11 | §4 block | §5.12, §5.14 | Add MCP paths and signals. Delete the provider section; it becomes an undated provider-agnostic questionnaire. |
| 16 | `hipaa-and-phi` | §1 item 13 and siblings | §4 block | §5.14 | Scope narrows to ePHI only. Delete named-vendor BAA verdicts outright. Add the not-legal-advice banner at the top of the body. |
| 17 | `privacy-and-data-protection` | §1 items 16, 20 | §4 block | §5.14 | Consent spine is ePrivacy Art 5(3), not GDPR. Add the not-legal-advice banner. |
| 18 | `salesforce-platform` | §1 §6 technical blockers | §4 block | §5.1, §5.7 | Six platform facts wrong including `WITH USER_MODE`. Apply all six de-branding substitutions from §6. Add Experience Cloud guest-user access. |
| 19 | `threat-modeling` | §1 item on MITRE ATT&CK | §4 block | — | Only lens with no severity calibration; author one. Add the mandatory anchor rule as a hard gate. |

**Steps for each of Tasks 10–19**, with `<lens>` the file from the table:

- [ ] **Step 1: Read the sources**

Read the pre-scrub `references/<original>.md`, then the punch list rows for this lens from the table above. Note every check, heading, severity rule and citation in the source; each one needs a ledger row.

- [ ] **Step 2: Write the body**

Fill `## Scope` (including an explicit "does not own" list drawn from the lens's `defers` keys), `## Checklist`, `## Severity calibration`, `## Known false positives`, `## Proof recipes`. Proof recipes reference `_harness.md` components by name rather than re-describing them.

- [ ] **Step 3: Add a detector block for every corrected search instruction**

Each takes this shape, and both directions are required:

````markdown
```detector
match: |
  jwt.decode(token, options={"verify_signature": False})
nomatch: |
  jwt.decode(token, key, algorithms=["RS256"])
```
````

The `match` example must be code the instruction genuinely finds. This is the gate that stops another unfireable check shipping.

- [ ] **Step 4: Write the ledger rows**

Append one row per source item to `docs/migration-ledger.tsv`. Every row needs an evidence reference. `intentionally_removed` is legitimate; a missing row is not.

- [ ] **Step 5: Lint and regenerate**

```bash
npm run lint && npm run gen -- --check
```

Expected: PASS. A new R7 violation means a detector is missing or non-discriminating. An R1 or R3 violation means the body claimed a topic the frontmatter does not own — fix the body, not the frontmatter, unless the ownership decision itself was wrong.

- [ ] **Step 6: Commit**

```bash
git add skills/last-aperture/lenses/<lens>.md docs/migration-ledger.tsv
git commit -m "feat(<lens>): migrate and correct lens body"
```

---

### Task 20: The shared proof harness and the finding contract

**Files:**
- Create: `skills/last-aperture/lenses/_harness.md`, `skills/last-aperture/lenses/_schema.md`
- Read: punch list §5 (lines 1609–1738), spec §4.4

**Interfaces:**
- Consumes: the `_harness.md` component names referenced by Tasks 10–19
- Produces: the shared harness components and the candidate-finding contract that Phase B's orchestrator consumes

- [ ] **Step 1: Write `_harness.md`**

One section per shared component, each named exactly as the lens bodies reference it. Punch list §5 identifies these as independently invented by three or more lenses: route-table enumerator, socket-layer destination recorder, canary fixture set, counting fake provider client, clock control, two-subject fixture pair.

Each section states what the component does, the tier it supports, and a concrete sketch in one language with a note on porting.

- [ ] **Step 2: Write `_schema.md`**

Transcribe the three-stage field table from spec §4.4 verbatim: fields written at fan-out, added at triage, added at proof. State that `candidate_id` is stable across dedup and re-runs, that `topic` is required because it is the deduplication boundary, and that `claimed_impact_severity` is never overwritten.

- [ ] **Step 3: Verify every referenced component exists**

Run:

```bash
grep -oh '_harness\.md[^)]*→ *`[^`]*`' skills/last-aperture/lenses/*.md | sort -u
```

Cross-check each name against `_harness.md`'s headings. Every reference must resolve — spec criterion 15.

- [ ] **Step 4: Lint**

Run: `npm run lint`
Expected: PASS. Underscore-prefixed files are not linted as lenses, so this confirms nothing regressed.

- [ ] **Step 5: Commit**

```bash
git add skills/last-aperture/lenses/_harness.md skills/last-aperture/lenses/_schema.md
git commit -m "feat: add shared proof harness and candidate-finding contract"
```

---

### Task 21: Residue scan and Phase A closure

**Files:**
- Create: `scripts/scan-residue.mjs`, `test/scan-residue.test.mjs`
- Read: punch list §6 (lines 1739–1805)

**Interfaces:**
- Consumes: the completed lens corpus
- Produces: `scanResidue(text, terms) -> [{ term, line }]`; CLI exits 1 on any hit

- [ ] **Step 1: Write the failing test**

Create `test/scan-residue.test.mjs`:

```javascript
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { scanResidue } from '../scripts/scan-residue.mjs'

test('finds a banned term and reports its line', () => {
  const hits = scanResidue('line one\nsomething AcmeHealth here\n', ['acmehealth'])
  assert.equal(hits.length, 1)
  assert.equal(hits[0].line, 2)
})

test('matching is case-insensitive', () => {
  assert.equal(scanResidue('ACMEHEALTH\n', ['acmehealth']).length, 1)
})

test('clean text produces no hits', () => {
  assert.deepEqual(scanResidue('generic security guidance\n', ['acmehealth']), [])
})

test('a term appearing twice on one line reports once per line', () => {
  assert.equal(scanResidue('acmehealth and acmehealth\n', ['acmehealth']).length, 1)
})
```

- [ ] **Step 2: Run it to verify it fails**

Run: `node --test test/scan-residue.test.mjs`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

Create `scripts/scan-residue.mjs`:

```javascript
import { readFileSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { execSync } from 'node:child_process'

// The term list lives here rather than in a committed data file: writing the
// banned words into a tracked file would defeat the purpose.
const TERMS = process.env.RESIDUE_TERMS ? process.env.RESIDUE_TERMS.split(',') : []

export function scanResidue(text, terms) {
  const hits = []
  text.split(/\r?\n/).forEach((line, i) => {
    for (const term of terms) {
      if (line.toLowerCase().includes(term.toLowerCase())) {
        hits.push({ term, line: i + 1 })
        break
      }
    }
  })
  return hits
}

function walk(dir, out = []) {
  for (const entry of readdirSync(dir)) {
    if (entry === '.git' || entry === 'node_modules') continue
    const p = join(dir, entry)
    if (statSync(p).isDirectory()) walk(p, out)
    else out.push(p)
  }
  return out
}

// Do NOT "simplify" this to `file://${process.argv[1]}`. On Windows that builds
// file://C:\path\with\backslashes while import.meta.url is file:///C:/path/with/
// forward-slashes, so the comparison is always false and the entire CLI block
// silently never runs — a lint that always exits 0 without checking anything.
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (!TERMS.length) {
    console.error('Set RESIDUE_TERMS to a comma-separated list of terms to scan for.')
    process.exit(2)
  }
  let found = 0
  for (const file of walk('.')) {
    let text
    try { text = readFileSync(file, 'utf8') } catch { continue }
    for (const hit of scanResidue(text, TERMS)) {
      console.error(`${file}:${hit.line}: contains "${hit.term}"`)
      found++
    }
  }
  const authors = execSync('git log --format=%ae%n%an', { encoding: 'utf8' })
  for (const hit of scanResidue(authors, TERMS)) {
    console.error(`git history: author field contains "${hit.term}"`)
    found++
  }
  if (found) { console.error(`FAIL: ${found} residue hit(s)`); process.exit(1) }
  console.log('PASS: no residue in tracked files or commit authorship.')
}
```

- [ ] **Step 4: Run tests, then run the scan**

```bash
node --test test/scan-residue.test.mjs
RESIDUE_TERMS="term1,term2,term3" node scripts/scan-residue.mjs
```

Expected: tests PASS. The scan must report zero hits. Any hit is a Phase A blocker.

**The operator substitutes the real terms at the shell and never writes them into a tracked file** — employer, product, tenant and person names, plus any email domain. Writing the list into the repository would put the exact strings being scanned for into the thing being scanned, which is self-defeating. This plan deliberately contains no example values for that reason.

- [ ] **Step 5: Confirm the pre-scrub baseline is still untracked**

```bash
git status --porcelain | grep -E '^\?\? (SKILL\.md|references/)' && echo "correctly untracked"
git log --all --oneline -- references/ SKILL.md
```

Expected: the first prints `correctly untracked`; the second prints nothing. Pre-scrub content must never appear in history.

- [ ] **Step 6: Close Phase A**

```bash
npm test && npm run lint && npm run gen -- --check
```

Expected: all three PASS. Then confirm every ledger row has a disposition and evidence:

```bash
awk -F'\t' 'NR>1 && ($3=="" || $4=="")' docs/migration-ledger.tsv
```

Expected: no output. Non-empty output means Phase A cannot close.

- [ ] **Step 7: Commit**

```bash
git add scripts/scan-residue.mjs test/scan-residue.test.mjs
git commit -m "feat: add residue scanner and close Phase A gates"
```

---

## Self-Review

**Spec coverage.** Walked §§4.1–4.4, 9 and 10 of the spec against these tasks:

| Spec requirement | Task |
|---|---|
| Repository layout, `scripts/`, `docs/` | 1, and the layout section above |
| Lens contract, three shapes, `runs_in` | 4, 9 |
| R1, R2, R3 | 3, 7 |
| R4 (one table row per slug) | 8 — `renderOverlap` emits exactly one row per slug and `--check` fails on drift, which enforces R4 by construction rather than by assertion |
| R5, R6 | 4 |
| A2 detector gate | 6, and Step 3 of Tasks 10–19 |
| `_schema.md` three-stage field set | 20 |
| `_topics.md` generated, never hand-edited | 8, 9 |
| `_harness.md` exists and every reference resolves | 20 |
| Migration ledger and its gate | 5, 9, 10–19, 21 |
| A0 baseline untracked, checksummed | 21 Step 5 |
| De-branding | 18, 21 |
| Punch list §1 corrections | 10–19 |
| Punch list §§4–5 new sections | 10–19 |
| Criterion 13 drift check | 8 |
| Criterion 15 harness references | 20 |

Gaps found and closed: R4 had no task until I traced it to `renderOverlap`, which needed the "exactly one row per slug" test in Task 8 Step 1 to actually enforce it. The A0 checksum requirement had no home and is now Task 21 Step 5.

Deliberately out of scope, belonging to later plans: `SKILL.md`'s ≤8 KB rewrite and the four non-owning lens **bodies** (Phase B); fixtures and evaluation (Phase C); `plugin.json`, `marketplace.json`, `README.md`, `LICENSE`, `AGENTS.md`, `CONTRIBUTING.md` and the junction swap (Phase D). Phase A leaves the triage lenses as frontmatter-plus-`## Scope` only, which is why Task 9 Step 2 deliberately omits `## Checklist` from them.

**Placeholder scan.** No "TBD", no "add appropriate error handling", no "similar to Task N". Tasks 10–19 share a step structure but each carries its own source map row with specific corrections, specific punch list sections and specific proof recipes, so a reader of Task 14 alone knows exactly what to do. The `<employer>` placeholders in Task 21 Step 4 are inputs the operator supplies at runtime, deliberately not written into a tracked file — writing the banned words into the repository would defeat the scan.

**Type consistency.** Checked every cross-task signature: `parseLens` returns `{ name, frontmatter, sections, detectors, errors }` and every consumer reads exactly those keys. `Violation` is `{ rule, slug, lenses, message }` across `buildRegistry`, `diffRegistry`, `checkShapes`, `checkDetectors`, `checkOrthography`; `parseLedger` violations carry `rule` and `message` only, and `runLint` never reads `slug` or `lenses` off them, so that narrowing is safe. `parseTopicsFile` is exported from `lint-lenses.mjs` and imported by `test/gen-topics.test.mjs` to prove the round-trip — one function, one definition, no duplicate parser. `slugs` is a `Map<slug, lensName>` everywhere it appears.
