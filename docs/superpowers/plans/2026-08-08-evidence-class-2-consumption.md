# Evidence-Class Consumption Implementation Plan (Plan 2 of 5)

> **Historical implementation plan.** Public `audit plan --evidence-bundle` is
> disabled before repository or bundle access. The legacy payload-root check is
> structural integrity, not authentication of coverage or attestation claims.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make evidence class a dimension of coverage, so an audit that never opened the image says so instead of reading as clean — with zero adapters, on every audit that runs today.

**Architecture:** Each lens declares, in the `activates_on` block it already has, which evidence classes it consumes and what a finding from each may assert. A new lint rule R9 makes the declaration mandatory. The run gains a `lens × topic × class` coverage matrix built from those declarations, whose default cell — no bundle supplied — is `NOT_ASSESSED` with a named reason, which the existing never-render-as-clean rule then carries into `report.md`. `_schema.md` gains `evidence_context`, `evidence_claim`, an evidence-qualified `location` form, and invariant 16; `contracts.mjs` enforces the record-local half and the ingest path enforces the declaration-aware half.

**Tech Stack:** Node.js 20+, ESM (`.mjs`), `node:test` + `node:assert/strict`, JSON Schema Draft 2020-12 via ajv 8, YAML frontmatter via the `yaml` package.

**Depends on:** Plan 1 (`scripts/lib/evidence-classes.mjs`, `scripts/lib/evidence-bundle.mjs`, `scripts/lib/evidence-adapters.mjs`). Do not start before Plan 1 is committed.

**Ships independently valuable.** After this plan and before any adapter exists, every report names the classes it could not reach. That is the whole false-clearance failure mode, removed with no new acquisition capability.

## Global Constraints

- Branch: `agent/red-team-audit-v11-existence`. **`scripts/audit.mjs`, `scripts/lib/run-engine.mjs`, `scripts/lib/job-protocol.mjs` and `scripts/lib/existence-matcher.mjs` carry uncommitted in-flight controller-verified-existence work.** Tasks 5, 6 and 7 touch the first three. Keep every edit additive and in one place per file; re-read the file immediately before editing rather than trusting a line number from this plan.
- Baseline: 2 permanently failing tests in `cloud-iac-fixtures.test.mjs` (ripgrep absent, exit 127). Environmental. Not regressions, not to be fixed.
- `npm.cmd run lint` must end `PASS: R1-R9, SKILL and ledger gate clean.` from Task 1 onward — note the rule range changes, and `lint-lenses.mjs`'s final `console.log` must change with it.
- `npm.cmd run gen -- --check` must stay `PASS ... (174 slugs)`. `evidence_classes` introduces no slugs; if the count moves, something was mis-edited.
- `skills/red-team-audit/SKILL.md` is at 7,995 of 8,000 bytes. **Add no prose to it.**
- Run commands with `npm.cmd`, not `npm`.
- `"additionalProperties": false` everywhere in `schemas/`.
- Locale-independent ordering only: `compareCanonicalStrings`, never `localeCompare`.
- **Naming:** an inventory record's `coverage_class` is a *file* class (`CANONICAL_SOURCE`…`BINARY`) and is unrelated. Evidence classes are `evidence_class`. Never conflate them.
- The four canonical classes, in ascending precedence: `source`, `built-artifact`, `deployed-state`, `live-runtime`.

---

### Task 1: Lens evidence-class declarations and lint rule R9

**Files:**
- Modify: all 15 lens files in `skills/red-team-audit/lenses/` — frontmatter only
- Modify: `scripts/lib/registry.mjs` (add `checkEvidenceClasses`)
- Modify: `scripts/lint-lenses.mjs` (call it; update the PASS banner)
- Modify: `test/samples/corpus-ok/web.md`, `test/samples/corpus-ok/crypto.md`, `test/samples/corpus-bad/*.md`, `test/samples/minimal-lens.md`
- Test: `test/evidence-class-declarations.test.mjs` (create)

**Interfaces:**
- Consumes: `EVIDENCE_CLASS_ORDER`, `EVIDENCE_ARTIFACT_KINDS`, `EVIDENCE_CLAIM_KINDS` from Plan 1's `evidence-classes.mjs`.
- Produces:
  - `checkEvidenceClasses(lenses): Array<{rule:'R9', slug:null, lenses:string[], message:string}>`
  - `lensEvidenceDeclarations(lenses): Map<string, Record<evidenceClass, {state, artifact_kinds?, may_conclude?}>>` — the accessor Tasks 4, 5 and 6 read.

The declaration block, added inside the existing `activates_on`:

```yaml
activates_on:
  paths:
    - '**/Dockerfile'
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: consumed
      artifact_kinds: [oci-image]
      may_conclude: [secret-present-in-artifact, unexpected-artifact-content]
    deployed-state:
      state: consumed
      may_conclude: [drift-from-source, runtime-misconfiguration]
    live-runtime:
      state: not-consumed
```

R9's rules:

1. Every canonical class appears exactly once. Omission is a violation — mirroring the database rule that an adapter "may not rename or omit a canonical one" (`_database-adapters/contract.md:314`).
2. `state` is `consumed` or `not-consumed`.
3. `artifact_kinds` is required and non-empty when `built-artifact` is `consumed`, forbidden otherwise, and every entry is a canonical kind.
4. `may_conclude` is required and non-empty for every consumed class **other than `source`**, forbidden for a `not-consumed` class, and every entry is a canonical claim kind. `source` is exempt because it is what every lens already does and bounding it now would re-litigate 174 topics.
5. A `not-consumed` class carries no other key.

Because R6 computes `matches` from `activates_on.paths` and `activates_on.signals` only (`registry.mjs:102-104`), adding `evidence_classes` does **not** make a triage lens's `activates_on` "non-empty" and does not break the always-active lens. Verified against `checkShapes` before writing this.

- [ ] **Step 1: Write the failing test**

Create `test/evidence-class-declarations.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { parseLens } from '../scripts/lib/frontmatter.mjs'
import { checkEvidenceClasses, lensEvidenceDeclarations } from '../scripts/lib/registry.mjs'
import { EVIDENCE_CLASS_ORDER } from '../scripts/lib/evidence-classes.mjs'

const LENS_DIR = 'skills/red-team-audit/lenses'

function corpus() {
  return readdirSync(LENS_DIR)
    .filter((file) => file.endsWith('.md') && !file.startsWith('_'))
    .sort()
    .map((file) => parseLens(readFileSync(join(LENS_DIR, file), 'utf8'), file))
}

const declare = (name, evidenceClasses, extra = {}) => ({
  name,
  frontmatter: {
    name,
    runs_in: 'fanout',
    owns: ['x'],
    defers: {},
    activates_on: { paths: ['**/*.ts'], evidence_classes: evidenceClasses },
    ...extra,
  },
  sections: {},
  detectors: [],
  errors: [],
})

const ALL_NOT_CONSUMED = Object.fromEntries(
  EVIDENCE_CLASS_ORDER.map((evidenceClass) => [evidenceClass, { state: 'not-consumed' }]),
)

test('every canonical lens declares all four evidence classes', () => {
  const lenses = corpus()
  assert.equal(lenses.length, 15)
  assert.deepEqual(checkEvidenceClasses(lenses), [])
  for (const lens of lenses) {
    const declared = lens.frontmatter.activates_on?.evidence_classes ?? {}
    assert.deepEqual(
      Object.keys(declared).sort(),
      [...EVIDENCE_CLASS_ORDER].sort(),
      `${lens.frontmatter.name} must declare every canonical class`,
    )
  }
})

test('threat-modeling is advisory and consumes nothing', () => {
  const lens = corpus().find((l) => l.frontmatter.name === 'threat-modeling')
  const declared = lens.frontmatter.activates_on.evidence_classes
  for (const evidenceClass of EVIDENCE_CLASS_ORDER) {
    assert.equal(declared[evidenceClass].state, 'not-consumed')
  }
})

test('cloud-and-iac can conclude about images and deployed state, not runtime', () => {
  const declared = corpus()
    .find((l) => l.frontmatter.name === 'cloud-and-iac')
    .frontmatter.activates_on.evidence_classes
  assert.deepEqual(declared['built-artifact'].artifact_kinds, ['oci-image'])
  assert.deepEqual(declared['built-artifact'].may_conclude, [
    'secret-present-in-artifact',
    'unexpected-artifact-content',
  ])
  assert.equal(declared['live-runtime'].state, 'not-consumed')
})

test('mobile-app-security claims apk and ipa, never oci-image', () => {
  const declared = corpus()
    .find((l) => l.frontmatter.name === 'mobile-app-security')
    .frontmatter.activates_on.evidence_classes
  assert.deepEqual(declared['built-artifact'].artifact_kinds, ['apk', 'ipa'])
})

test('R9 rejects an omitted class', () => {
  const { 'live-runtime': _omitted, ...partial } = ALL_NOT_CONSUMED
  const violations = checkEvidenceClasses([declare('web', partial)])
  assert.equal(violations.length, 1)
  assert.equal(violations[0].rule, 'R9')
  assert.match(violations[0].message, /live-runtime/)
})

test('R9 rejects a missing declaration block outright', () => {
  const lens = declare('web', undefined)
  delete lens.frontmatter.activates_on.evidence_classes
  assert.ok(checkEvidenceClasses([lens]).some((v) => /evidence_classes/.test(v.message)))
})

test('R9 rejects an unknown class, state, kind or claim', () => {
  assert.ok(checkEvidenceClasses([
    declare('web', { ...ALL_NOT_CONSUMED, exploitation: { state: 'consumed' } }),
  ]).some((v) => /exploitation/.test(v.message)))

  assert.ok(checkEvidenceClasses([
    declare('web', { ...ALL_NOT_CONSUMED, source: { state: 'maybe' } }),
  ]).some((v) => /state/.test(v.message)))

  assert.ok(checkEvidenceClasses([declare('web', {
    ...ALL_NOT_CONSUMED,
    'built-artifact': {
      state: 'consumed',
      artifact_kinds: ['docker-image'],
      may_conclude: ['secret-present-in-artifact'],
    },
  })]).some((v) => /docker-image/.test(v.message)))

  assert.ok(checkEvidenceClasses([declare('web', {
    ...ALL_NOT_CONSUMED,
    'deployed-state': { state: 'consumed', may_conclude: ['looks-bad'] },
  })]).some((v) => /looks-bad/.test(v.message)))
})

test('R9 requires artifact_kinds exactly when built-artifact is consumed', () => {
  assert.ok(checkEvidenceClasses([declare('web', {
    ...ALL_NOT_CONSUMED,
    'built-artifact': { state: 'consumed', may_conclude: ['secret-present-in-artifact'] },
  })]).some((v) => /artifact_kinds/.test(v.message)))

  assert.ok(checkEvidenceClasses([declare('web', {
    ...ALL_NOT_CONSUMED,
    'built-artifact': { state: 'not-consumed', artifact_kinds: ['oci-image'] },
  })]).some((v) => /artifact_kinds/.test(v.message)))
})

test('R9 requires may_conclude for a consumed non-source class and exempts source', () => {
  assert.deepEqual(
    checkEvidenceClasses([declare('web', { ...ALL_NOT_CONSUMED, source: { state: 'consumed' } })]),
    [],
  )
  assert.ok(checkEvidenceClasses([declare('web', {
    ...ALL_NOT_CONSUMED,
    'live-runtime': { state: 'consumed' },
  })]).some((v) => /may_conclude/.test(v.message)))
})

test('lensEvidenceDeclarations exposes the corpus as a lookup', () => {
  const declarations = lensEvidenceDeclarations(corpus())
  assert.equal(declarations.size, 15)
  assert.equal(declarations.get('cloud-and-iac')['built-artifact'].state, 'consumed')
  assert.equal(declarations.get('threat-modeling')['built-artifact'].state, 'not-consumed')
  assert.equal(declarations.get('no-such-lens'), undefined)
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-class-declarations.test.mjs`
Expected: FAIL — `checkEvidenceClasses is not a function`

- [ ] **Step 3: Implement R9**

Append to `scripts/lib/registry.mjs`:

```js
import {
  EVIDENCE_ARTIFACT_KINDS,
  EVIDENCE_CLASSES,
  EVIDENCE_CLASS_ORDER,
  isEvidenceArtifactKind,
  isEvidenceClaimKind,
} from './evidence-classes.mjs'

const EVIDENCE_STATES = new Set(['consumed', 'not-consumed'])

// R9. A lens that never says which evidence classes it can speak to makes
// "we read the Dockerfile but never the image" inexpressible, and an audit
// that cannot express a blind spot reports it as silence. Silence reads as
// clearance, which is the failure this rule exists to make impossible.
export function checkEvidenceClasses(lenses) {
  const violations = []
  for (const l of lenses) {
    const name = l.frontmatter?.name ?? l.name ?? '<unnamed>'
    const push = (message) => violations.push({ rule: 'R9', slug: null, lenses: [name], message })
    const declared = l.frontmatter?.activates_on?.evidence_classes

    if (declared === null || typeof declared !== 'object' || Array.isArray(declared)) {
      push(`${name}: activates_on.evidence_classes is missing; every lens declares all four classes`)
      continue
    }

    for (const key of Object.keys(declared)) {
      if (!EVIDENCE_CLASS_ORDER.includes(key)) {
        push(`${name}: unknown evidence class "${key}"`)
      }
    }

    for (const evidenceClass of EVIDENCE_CLASS_ORDER) {
      const entry = declared[evidenceClass]
      if (entry === undefined) {
        push(`${name}: evidence class "${evidenceClass}" is not declared`)
        continue
      }
      if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
        push(`${name}: evidence class "${evidenceClass}" must be a mapping with a state`)
        continue
      }
      if (!EVIDENCE_STATES.has(entry.state)) {
        push(
          `${name}: evidence class "${evidenceClass}" state must be consumed or not-consumed, `
          + `got "${entry.state}"`,
        )
        continue
      }

      const consumed = entry.state === 'consumed'
      const kinds = entry.artifact_kinds
      const claims = entry.may_conclude

      if (!consumed) {
        for (const key of ['artifact_kinds', 'may_conclude']) {
          if (entry[key] !== undefined) {
            push(`${name}: "${evidenceClass}" is not-consumed and must not declare ${key}`)
          }
        }
        continue
      }

      if (evidenceClass === EVIDENCE_CLASSES.BUILT_ARTIFACT) {
        if (!Array.isArray(kinds) || kinds.length === 0) {
          push(
            `${name}: "built-artifact" is consumed and must declare a non-empty artifact_kinds `
            + `from ${EVIDENCE_ARTIFACT_KINDS.join(', ')}`,
          )
        } else {
          for (const kind of kinds) {
            if (!isEvidenceArtifactKind(kind)) {
              push(`${name}: unknown artifact kind "${kind}" in "built-artifact"`)
            }
          }
        }
      } else if (kinds !== undefined) {
        push(`${name}: artifact_kinds is only meaningful for "built-artifact", not "${evidenceClass}"`)
      }

      // source is exempt: it is what every lens in this registry already does,
      // and bounding it now would re-litigate all 174 owned topics.
      if (evidenceClass === EVIDENCE_CLASSES.SOURCE) {
        if (claims !== undefined) {
          push(`${name}: "source" needs no may_conclude; its claims are bounded by topic ownership`)
        }
        continue
      }
      if (!Array.isArray(claims) || claims.length === 0) {
        push(`${name}: "${evidenceClass}" is consumed and must declare a non-empty may_conclude`)
        continue
      }
      for (const claim of claims) {
        if (!isEvidenceClaimKind(claim)) {
          push(`${name}: unknown claim kind "${claim}" in "${evidenceClass}"`)
        }
      }
    }
  }
  return violations
}

// The corpus as a lookup, for the coverage matrix and the finding validator.
export function lensEvidenceDeclarations(lenses) {
  return new Map(lenses.map((l) => [
    l.frontmatter?.name ?? l.name,
    l.frontmatter?.activates_on?.evidence_classes ?? {},
  ]))
}
```

- [ ] **Step 4: Wire R9 into the linter**

In `scripts/lint-lenses.mjs`, add the import and the call, and update the banner:

```js
import { buildRegistry, checkBodyClaims, checkDetectors, checkEvidenceClasses, checkShapes, detectorCoverage } from './lib/registry.mjs'
```

```js
  violations.push(...checkBodyClaims(lenses, slugs))
  violations.push(...checkEvidenceClasses(lenses))
```

```js
  console.log('\nPASS: R1-R9, SKILL and ledger gate clean.')
```

- [ ] **Step 5: Add the declaration block to all 15 lenses**

Insert `evidence_classes:` as the last key under `activates_on:` in each file, using exactly these declarations. Indentation is two spaces under `activates_on`, four under the class name.

`ai-generated-code`, `attack-chaining`, `business-logic`, `completeness` — these four own no slugs and reason over the merged finding set, not over raw evidence. A finding they originate lands on the owning lens's topic, and the owner's declaration bounds it:

```yaml
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
```

`llm-and-ai` uses the same block as the four above.

`threat-modeling` — advisory, makes no coverage claim, so all four are `not-consumed`:

```yaml
  evidence_classes:
    source:
      state: not-consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
```

`cicd-and-supply-chain`:

```yaml
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: consumed
      artifact_kinds: [dist-bundle, jar, oci-image]
      may_conclude: [secret-present-in-artifact, unexpected-artifact-content, vulnerable-component-present]
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
```

`cloud-and-iac`:

```yaml
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: consumed
      artifact_kinds: [oci-image]
      may_conclude: [secret-present-in-artifact, unexpected-artifact-content]
    deployed-state:
      state: consumed
      may_conclude: [drift-from-source, runtime-misconfiguration]
    live-runtime:
      state: not-consumed
```

`crypto-and-key-management`:

```yaml
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: consumed
      artifact_kinds: [apk, ipa, jar, oci-image]
      may_conclude: [secret-present-in-artifact]
    deployed-state:
      state: consumed
      may_conclude: [runtime-misconfiguration]
    live-runtime:
      state: consumed
      may_conclude: [runtime-misconfiguration]
```

`database-and-data-stores`:

```yaml
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: consumed
      may_conclude: [drift-from-source, runtime-misconfiguration]
    live-runtime:
      state: consumed
      may_conclude: [runtime-misconfiguration, sensitive-data-at-rest]
```

`hipaa-and-phi`:

```yaml
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: consumed
      artifact_kinds: [oci-image]
      may_conclude: [sensitive-data-at-rest]
    deployed-state:
      state: consumed
      may_conclude: [sensitive-data-at-rest]
    live-runtime:
      state: consumed
      may_conclude: [sensitive-data-at-rest]
```

`mobile-app-security`:

```yaml
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: consumed
      artifact_kinds: [apk, ipa]
      may_conclude: [secret-present-in-artifact, unexpected-artifact-content, vulnerable-component-present]
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
```

`privacy-and-data-protection`:

```yaml
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: consumed
      may_conclude: [sensitive-data-at-rest]
    live-runtime:
      state: consumed
      may_conclude: [sensitive-data-at-rest]
```

`salesforce-platform`:

```yaml
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: consumed
      may_conclude: [drift-from-source, runtime-misconfiguration]
    live-runtime:
      state: not-consumed
```

`web-and-api`:

```yaml
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: consumed
      may_conclude: [runtime-misconfiguration]
    live-runtime:
      state: consumed
      may_conclude: [drift-from-source, runtime-misconfiguration]
```

- [ ] **Step 6: Add the block to the lint sample corpora**

`test/samples/corpus-ok/web.md`, `test/samples/corpus-ok/crypto.md`, every lens under `test/samples/corpus-bad/`, and `test/samples/minimal-lens.md` all parse through the same linter. Add the all-`not-consumed` block from `threat-modeling` to each, so `lint-cli.test.mjs`'s "a clean corpus produces no violations" keeps passing and `corpus-bad` still fails only on the R1/R3 collisions it is built to demonstrate.

- [ ] **Step 7: Run the tests**

Run: `npm.cmd test -- test/evidence-class-declarations.test.mjs test/lint-cli.test.mjs test/registry.test.mjs test/frontmatter.test.mjs`
Expected: PASS

Run: `npm.cmd run lint`
Expected: `PASS: R1-R9, SKILL and ledger gate clean.`

Run: `npm.cmd run gen -- --check`
Expected: `PASS: generated artifacts match frontmatter (174 slugs).`

- [ ] **Step 8: Commit**

```bash
git add skills/red-team-audit/lenses scripts/lib/registry.mjs scripts/lint-lenses.mjs test/samples test/evidence-class-declarations.test.mjs
git commit -m "feat: every lens declares the evidence classes it can speak to (R9)"
```

---

### Task 2: `evidence_context`, `evidence_claim`, and the evidence-qualified `location`

**Files:**
- Modify: `schemas/finding.schema.json`
- Modify: `scripts/lib/contracts.mjs` — `STAGE_ONE_FIELDS` only
- Test: `test/evidence-finding-shape.test.mjs` (create)

**Interfaces:**
- Consumes: Task 1's declarations only indirectly (enforcement is Task 4).
- Produces, for Tasks 3-7:
  - `finding.evidence_context: {evidence_id, evidence_class, adapter_id, target_identity, acquisition_mode, acquired_on, detection_evidence[], confidence}` — identical to the bundle's projection
  - `finding.evidence_claim: string` — one canonical claim kind
  - `location` accepts `<evidence_id>:<locator>` alongside `file:line`

**The disjointness rule, because it decides everything downstream.** Today `location` items match `^.+:[1-9][0-9]*(?::[1-9][0-9]*)?$` — every item must end in a line number. `peerstar-api-image:layer/02/var/lib/db/sbom/zsh-5.9r7.spdx.json` does not match, so without this change a container finding cannot be written at all, let alone graded. The evidence form is `^[a-z0-9][a-z0-9-]{0,63}:(?!\d+$).+$`: an `evidence_id`-shaped prefix followed by a locator that is **not** purely digits. A repository path (`src/routes/invoices.ts`) contains `/` or `.` and cannot match the prefix; a repository line (`88`) is purely digits and cannot match the locator. The two forms are syntactically disjoint, so no reader has to guess which one it is holding.

- [ ] **Step 1: Write the failing test**

Create `test/evidence-finding-shape.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { validateFinding } from '../scripts/lib/contracts.mjs'

function stageOne(overrides = {}) {
  return {
    candidate_id: 'container-image-content:5c1a7f30',
    lens: 'cloud-and-iac',
    topic: 'container-image-content',
    title: 'Deleted build secret is still readable in the layer below the whiteout',
    claimed_impact_severity: 'High',
    location: ['peerstar-api-image:layer/02/secret.txt'],
    evidence: 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI',
    attack: 'docker save the image, extract layer 02, read secret.txt',
    impact: 'Recovers a deployment credential the Dockerfile claims to have removed',
    reachable_from: 'anyone who can pull the image',
    confidence: 'High',
    proof_plan: 'Extract layer 02 from the sealed bundle and read the quoted bytes',
    evidence_claim: 'secret-present-in-artifact',
    evidence_context: {
      evidence_id: 'peerstar-api-image',
      evidence_class: 'built-artifact',
      adapter_id: 'artifact',
      target_identity: 'sha256:9f2c1d0e4b6a8c3f5e7d9b1a3c5e7f9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c',
      acquisition_mode: 'offline-export',
      acquired_on: '2026-08-08T14:22:10Z',
      detection_evidence: ['shell-in-the-ghost.tar.gz sha256:4aaff082'],
      confidence: 'high',
    },
    ...overrides,
  }
}

test('an evidence-qualified finding validates', () => {
  const validation = validateFinding(stageOne())
  assert.deepEqual(validation.errors, [])
  assert.equal(validation.valid, true)
})

test('the repository location form is unchanged', () => {
  const validation = validateFinding(stageOne({
    location: ['src/routes/invoices.ts:88'],
    evidence_claim: undefined,
    evidence_context: undefined,
    lens: 'web-and-api',
    topic: 'authz-object-level',
    candidate_id: 'authz-object-level:a3f19c2e',
  }))
  assert.deepEqual(validation.errors, [])
})

test('the two location forms are disjoint', () => {
  // A repository path can never be read as an evidence id.
  assert.equal(validateFinding(stageOne({ location: ['src/app.ts:12'] })).valid, false)
  // A bare line number can never be read as a locator.
  assert.equal(validateFinding(stageOne({ location: ['peerstar-api-image:88'] })).valid, false)
})

test('an evidence-qualified location without evidence_context is malformed', () => {
  const validation = validateFinding(stageOne({ evidence_context: undefined }))
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((e) => e.code === 'EVIDENCE_CONTEXT_REQUIRED'))
})

test('evidence_context whose id does not match the location prefix is malformed', () => {
  const validation = validateFinding(stageOne({
    location: ['prod-cluster:v1/Namespace/sidecars'],
  }))
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((e) => e.code === 'EVIDENCE_ID_MISMATCH'))
})

test('evidence_context requires evidence_claim and vice versa', () => {
  assert.ok(
    validateFinding(stageOne({ evidence_claim: undefined }))
      .errors.some((e) => e.code === 'EVIDENCE_CLAIM_REQUIRED'),
  )
  assert.ok(
    validateFinding(stageOne({
      location: ['src/main.ts:4'],
      evidence_context: undefined,
    })).errors.some((e) => e.code === 'EVIDENCE_CLAIM_WITHOUT_CONTEXT'),
  )
})

test('evidence_claim must be a canonical claim kind', () => {
  assert.equal(validateFinding(stageOne({ evidence_claim: 'looks-bad' })).valid, false)
})

test('a source-class evidence_context is refused; source needs no bundle', () => {
  const context = { ...stageOne().evidence_context, evidence_class: 'source' }
  const validation = validateFinding(stageOne({ evidence_context: context }))
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((e) => e.code === 'EVIDENCE_CLASS_NOT_ACQUIRED'))
})

test('mixing repository and evidence locations in one record is refused', () => {
  const validation = validateFinding(stageOne({
    location: ['peerstar-api-image:layer/02/secret.txt', 'Dockerfile:14'],
  }))
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((e) => e.code === 'MIXED_LOCATION_CLASSES'))
})
```

The last case is a decision worth naming: one record concerns one evidence source, exactly as `store_context`'s "one record concerns one store" rule (`_schema.md:63`). A finding that spans the Dockerfile *and* the image is the precedence case, and the precedence case is two records with a recorded conflict — not one record with two premises.

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-finding-shape.test.mjs`
Expected: FAIL — the schema rejects `evidence_context` as an unknown property and rejects the evidence-qualified `location`.

- [ ] **Step 3: Extend the finding schema**

In `schemas/finding.schema.json`, replace the `location` property with:

```json
    "location": {
      "type": "array",
      "minItems": 1,
      "maxItems": 128,
      "uniqueItems": true,
      "items": {
        "anyOf": [
          {
            "type": "string",
            "minLength": 3,
            "pattern": "^.+:[1-9][0-9]*(?::[1-9][0-9]*)?$"
          },
          {
            "type": "string",
            "minLength": 3,
            "maxLength": 1024,
            "pattern": "^[a-z0-9][a-z0-9-]{0,63}:(?!\\d+$).+$"
          }
        ]
      }
    },
```

Add two properties beside `store_context`:

```json
    "evidence_context": { "$ref": "#/$defs/evidenceContext" },
    "evidence_claim": {
      "enum": [
        "drift-from-source",
        "runtime-misconfiguration",
        "secret-present-in-artifact",
        "sensitive-data-at-rest",
        "unexpected-artifact-content",
        "vulnerable-component-present"
      ]
    },
```

And add the `$def`, byte-identical in shape to `evidence-bundle.schema.json`'s so the projection cannot drift:

```json
    "evidenceContext": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "evidence_id",
        "evidence_class",
        "adapter_id",
        "target_identity",
        "acquisition_mode",
        "acquired_on",
        "detection_evidence",
        "confidence"
      ],
      "properties": {
        "evidence_id": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,63}$" },
        "evidence_class": {
          "enum": ["source", "built-artifact", "deployed-state", "live-runtime"]
        },
        "adapter_id": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]*$" },
        "target_identity": { "$ref": "#/$defs/nonEmptyString" },
        "acquisition_mode": { "$ref": "#/$defs/nonEmptyString" },
        "acquired_on": {
          "type": "string",
          "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
        },
        "detection_evidence": {
          "type": "array",
          "minItems": 1,
          "maxItems": 256,
          "uniqueItems": true,
          "items": { "$ref": "#/$defs/nonEmptyString" }
        },
        "confidence": { "enum": ["high", "medium", "low"] }
      }
    },
```

- [ ] **Step 4: Register the fields as Stage 1**

In `scripts/lib/contracts.mjs`, add to `STAGE_ONE_FIELDS` (the set beginning at line 107), immediately after `'store_context'`:

```js
  'evidence_context',
  'evidence_claim',
```

`evidence_context` accumulates like `store_context`: written by the lens at fan-out and never overwritten. Adding it to `STAGE_ONE_FIELDS` is what makes `inferFindingStage` and the transition rules treat it that way.

- [ ] **Step 5: Add the record-local invariants**

In `scripts/lib/contracts.mjs`, inside `findingInvariantErrors`, add — the run-context half of invariant 16 arrives in Task 4:

```js
const EVIDENCE_LOCATION_PATTERN = /^([a-z0-9][a-z0-9-]{0,63}):(?!\d+$)(.+)$/

function evidenceQualifiedLocations(record) {
  const locations = Array.isArray(record.location) ? record.location : []
  return locations
    .map((value) => EVIDENCE_LOCATION_PATTERN.exec(String(value)))
    .filter(Boolean)
    .map((match) => ({ evidence_id: match[1], locator: match[2] }))
}

function evidenceInvariantErrors(record) {
  const errors = []
  const qualified = evidenceQualifiedLocations(record)
  const locationCount = Array.isArray(record.location) ? record.location.length : 0
  const context = record.evidence_context

  if (qualified.length > 0 && qualified.length !== locationCount) {
    addError(
      errors,
      'MIXED_LOCATION_CLASSES',
      '/location',
      'one record concerns one evidence source; a repository location and an '
      + 'evidence-qualified location in one record is the precedence case, which is two records',
    )
  }

  if (qualified.length > 0 && !context) {
    addError(
      errors,
      'EVIDENCE_CONTEXT_REQUIRED',
      '/evidence_context',
      'an evidence-qualified location requires evidence_context (invariant 16)',
    )
  }
  if (context && qualified.length === 0) {
    addError(
      errors,
      'EVIDENCE_CONTEXT_WITHOUT_LOCATION',
      '/location',
      'evidence_context requires at least one evidence-qualified location',
    )
  }
  if (context && !record.evidence_claim) {
    addError(
      errors,
      'EVIDENCE_CLAIM_REQUIRED',
      '/evidence_claim',
      'a finding from an acquired class names the claim it asserts',
    )
  }
  if (!context && record.evidence_claim !== undefined) {
    addError(
      errors,
      'EVIDENCE_CLAIM_WITHOUT_CONTEXT',
      '/evidence_claim',
      'evidence_claim is meaningless without evidence_context',
    )
  }
  if (context && context.evidence_class === 'source') {
    addError(
      errors,
      'EVIDENCE_CLASS_NOT_ACQUIRED',
      '/evidence_context/evidence_class',
      'source evidence is the repository itself and carries no evidence_context',
    )
  }
  for (const { evidence_id: evidenceId } of qualified) {
    if (context && context.evidence_id !== evidenceId) {
      addError(
        errors,
        'EVIDENCE_ID_MISMATCH',
        '/location',
        `location names evidence "${evidenceId}" but evidence_context is `
        + `"${context.evidence_id}"`,
      )
    }
  }
  return errors
}
```

and call it from `findingInvariantErrors` alongside the existing checks:

```js
  errors.push(...evidenceInvariantErrors(record))
```

- [ ] **Step 6: Run the tests**

Run: `npm.cmd test -- test/evidence-finding-shape.test.mjs test/contracts-runtime.test.mjs test/shape.test.mjs test/v3-contract-adversarial.test.mjs test/verification-contract.test.mjs test/existence-claims.test.mjs`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add schemas/finding.schema.json scripts/lib/contracts.mjs test/evidence-finding-shape.test.mjs
git commit -m "feat: evidence-qualified locations, evidence_context and evidence_claim on a finding"
```

---

### Task 3: The `_schema.md` amendment and invariant 16

**Files:**
- Modify: `skills/red-team-audit/lenses/_schema.md`
- Test: `test/evidence-schema-doc.test.mjs` (create)

**Interfaces:**
- Consumes: the field names Task 2 established.
- Produces: the prose contract every lens author and every later reader works from. No code depends on it, which is exactly why it needs a test — a contract nobody checks drifts from the validator that enforces it.

- [ ] **Step 1: Write the failing test**

Create `test/evidence-schema-doc.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const SCHEMA_DOC = 'skills/red-team-audit/lenses/_schema.md'

function doc() {
  return readFileSync(SCHEMA_DOC, 'utf8')
}

test('invariant 16 is stated and numbered', () => {
  const text = doc()
  const invariant = /^16\. (.+?)(?=\n\n|\n\d{1,2}\. |\n---)/ms.exec(text)
  assert.ok(invariant, 'invariant 16 must exist')
  const body = invariant[1]
  assert.match(body, /evidence_context/)
  assert.match(body, /consumed/)
  assert.match(body, /may_conclude/)
  assert.match(body, /higher-precedence/)
  assert.match(body, /NOT_ASSESSED/)
  assert.match(body, /INVENTORY_ONLY/)
  assert.match(body, /UNPROVEN/)
  assert.match(body, /Medium/)
})

test('invariant 15 is untouched and 17 does not exist', () => {
  const text = doc()
  assert.match(text, /^15\. A record with `lens: database-and-data-stores`/m)
  assert.equal(/^17\. /m.test(text), false)
})

test('the Stage 1 table declares evidence_context and evidence_claim', () => {
  const text = doc()
  assert.match(text, /^\| `evidence_context` \| object \|/m)
  assert.match(text, /^\| `evidence_claim` \|/m)
})

test('the location section documents the evidence-qualified form', () => {
  const text = doc()
  assert.match(text, /peerstar-api-image:layer\/02\//)
  assert.match(text, /prod-cluster:v1\/Namespace\//)
})

test('the three existence_check outcomes carry over unchanged', () => {
  const text = doc()
  const section = text.slice(text.indexOf('### Evidence-qualified `location`'))
  assert.match(section, /NOT_REPRODUCED/)
  assert.match(section, /DISPROVED/)
})

test('every evidence_context field named in the doc matches the schema', () => {
  const schema = JSON.parse(readFileSync('schemas/finding.schema.json', 'utf8'))
  const required = schema.$defs.evidenceContext.required
  const text = doc()
  const block = text.slice(text.indexOf('### Evidence context'))
  for (const field of required) {
    assert.ok(block.includes(field), `_schema.md must document ${field}`)
  }
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-schema-doc.test.mjs`
Expected: FAIL — invariant 16 does not exist.

- [ ] **Step 3: Amend `_schema.md`**

Three edits, in file order.

**(a)** In the Stage 1 field table, immediately after the `store_context` / `principal_path` / `enforcement_plane` rows and before `copy_path`, add:

```markdown
| `evidence_context` | object | **Required when `location` carries an evidence-qualified form.** Stable evidence identity, the acquiring adapter and the evidence that identified it; shape below |
| `evidence_claim` | claim kind | **Required with `evidence_context`.** The one thing this finding asserts, bounded by the lens's `may_conclude` for that class |
```

**(b)** After the `### Database store context` section, add:

````markdown
### Evidence context

A repository audit has exactly one evidence source: files in the repository.
Every lens therefore reasons about the *recipe* and reports on the *result* —
and `COPY secret.txt` followed by `RUN rm /secret.txt` reads as a removal in
the Dockerfile while the bytes stay fully readable in the layer below the
whiteout marker. A finding derived from anything other than the repository
carries an additional context rather than laundering an acquisition guess
through prose, for the same reason `store_context` exists.

`evidence_context` has this shape:

```yaml
evidence_id: peerstar-api-image
evidence_class: built-artifact
adapter_id: artifact
target_identity: sha256:9f2c...
acquisition_mode: offline-export
acquired_on: 2026-08-08T14:22:10Z
detection_evidence:
  - shell-in-the-ghost.tar.gz sha256:4aaff082
confidence: high
```

All eight fields are required. It is the small immutable routing projection of
the bundle's `evidence_profile`, exactly as `store_context` is the projection
of `store_profile`; adapters must not substitute a private shape.

`evidence_id` is operator-assigned, unique within a run, and stable across
re-acquisitions of the same target. It is the handle `location` resolves
through, so an id that changes between runs breaks every finding referencing
it — the same property `candidate_id` needs, for the same reason. It must not
contain a hostname. One bundle carries one `evidence_id`; two acquisitions of
one target at different times are two bundles with the same `evidence_id` and
different `acquired_on` and `target_identity`.

`evidence_class` is one of `source`, `built-artifact`, `deployed-state`,
`live-runtime`, in ascending precedence. `source` never appears here: the
repository is the default evidence source and needs no context to name it.

One record concerns one evidence source. A finding that would cite both the
Dockerfile and the image is the precedence case, and the precedence case is
two records with a recorded conflict — never one record with two premises.

### Evidence-qualified `location`

`location` is `file:line` in the repository, and it now also accepts an
evidence-qualified form:

```text
<evidence_id>:<class-specific-locator>

peerstar-api-image:layer/02/var/lib/db/sbom/zsh-5.9r7.spdx.json
peerstar-api-image:config/history[8]
prod-cluster:v1/Namespace/sidecars/Pod/sidecars/spec.volumes[0]
```

The two forms are disjoint by construction: a repository path carries `/` or
`.` and cannot be an `evidence_id`, and a repository line is purely digits and
cannot be a locator. `<evidence_id>` must resolve to an `evidence_context`
present in the run.

**The three `existence_check` outcomes carry over exactly**, because the
ordering rule they encode has nothing to do with where the artifact lives:

- **The bundle is absent from the run, or the locator does not resolve within
  it** — `NOT_REPRODUCED`. Consistent with the existing rule that failing to
  locate an artifact is a statement about the claim, not about the harness.
- **The locator resolves and the quoted `evidence` is not there** —
  `DISPROVED`, quoting what was actually found.
- **Both check out** — proceed to tier assignment.

Because bundles are content-addressed and hashed, re-verification months later
is exact rather than approximate — a stronger guarantee than the repository
case, where a checkout may have moved.
````

**(c)** After invariant 15, add:

```markdown
16. A record whose `location` carries an evidence-qualified form has `evidence_context` present, and its `evidence_class` is declared `consumed` by the lens named in `lens`. Its `evidence_claim` lies within that class's `may_conclude`. Where two classes yield conflicting claims for one topic, the higher-precedence class prevails and the conflict is recorded; a lower-precedence class never overrides a higher one. A claim resting on a class whose coverage is `NOT_ASSESSED` or `INVENTORY_ONLY` is `UNPROVEN` and capped at Medium.
```

The final clause reuses invariant 8's existing arithmetic rather than adding a
mechanism, exactly as the `contingent:` cap reuses invariant 6's.

- [ ] **Step 4: Run the tests**

Run: `npm.cmd test -- test/evidence-schema-doc.test.mjs test/skill.test.mjs`
Expected: PASS

Run: `npm.cmd run lint` → `PASS: R1-R9, SKILL and ledger gate clean.` (`_schema.md` is underscore-prefixed; the linter skips it, so this only confirms nothing else moved.)

- [ ] **Step 5: Commit**

```bash
git add skills/red-team-audit/lenses/_schema.md test/evidence-schema-doc.test.mjs
git commit -m "docs: evidence context, evidence-qualified location and invariant 16"
```

---

### Task 4: Declaration-aware enforcement of invariant 16

**Files:**
- Modify: `scripts/lib/contracts.mjs`
- Test: `test/evidence-invariant-16.test.mjs` (create)

**Interfaces:**
- Consumes: `lensEvidenceDeclarations` (Task 1); `evidence_context` / `evidence_claim` (Task 2); `higherPrecedenceEvidenceClass`, `evidenceCoverageStateClears` (Plan 1).
- Produces:
  - `validateFinding(record, {evidence})` where `evidence` is `{declarations: Map, coverage: Map<'lens\0topic\0class', coverageState>}` — omitting `evidence` keeps today's behaviour exactly, so no existing caller changes
  - `evidenceConflicts(findings): Array<{topic, prevailing_candidate_id, superseded_candidate_id, prevailing_class, superseded_class}>` — the precedence resolver Task 6's report uses

Why the split: `validateFinding` has no access to the lens pack or the run, and giving it one would make every existing caller load the corpus. The record-local half (Task 2) is unconditional; the declaration-aware half activates only when a caller supplies the context — which the ingest path does and a unit test does.

- [ ] **Step 1: Write the failing test**

Create `test/evidence-invariant-16.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { evidenceConflicts, validateFinding } from '../scripts/lib/contracts.mjs'

const DECLARATIONS = new Map([
  ['cloud-and-iac', {
    source: { state: 'consumed' },
    'built-artifact': {
      state: 'consumed',
      artifact_kinds: ['oci-image'],
      may_conclude: ['secret-present-in-artifact', 'unexpected-artifact-content'],
    },
    'deployed-state': { state: 'consumed', may_conclude: ['drift-from-source'] },
    'live-runtime': { state: 'not-consumed' },
  }],
  ['web-and-api', {
    source: { state: 'consumed' },
    'built-artifact': { state: 'not-consumed' },
    'deployed-state': { state: 'consumed', may_conclude: ['runtime-misconfiguration'] },
    'live-runtime': { state: 'consumed', may_conclude: ['runtime-misconfiguration'] },
  }],
])

const COVERED = new Map([['cloud-and-iac\0container-image-content\0built-artifact', 'COVERED']])

function record(overrides = {}) {
  return {
    candidate_id: 'container-image-content:5c1a7f30',
    lens: 'cloud-and-iac',
    topic: 'container-image-content',
    title: 'Deleted build secret is readable below the whiteout',
    claimed_impact_severity: 'High',
    location: ['peerstar-api-image:layer/02/secret.txt'],
    evidence: 'AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI',
    attack: 'extract layer 02 and read secret.txt',
    impact: 'Recovers a deployment credential',
    reachable_from: 'anyone who can pull the image',
    confidence: 'High',
    proof_plan: 'Read the quoted bytes from the sealed bundle',
    evidence_claim: 'secret-present-in-artifact',
    evidence_context: {
      evidence_id: 'peerstar-api-image',
      evidence_class: 'built-artifact',
      adapter_id: 'artifact',
      target_identity: 'sha256:9f2c',
      acquisition_mode: 'offline-export',
      acquired_on: '2026-08-08T14:22:10Z',
      detection_evidence: ['image.tar sha256:4aaff082'],
      confidence: 'high',
    },
    ...overrides,
  }
}

test('a declared class with covered evidence validates', () => {
  const validation = validateFinding(record(), {
    evidence: { declarations: DECLARATIONS, coverage: COVERED },
  })
  assert.deepEqual(validation.errors, [])
})

test('omitting the evidence context leaves today behaviour untouched', () => {
  assert.deepEqual(validateFinding(record()).errors, [])
})

test('a lens cannot conclude from a class it declares not-consumed', () => {
  const validation = validateFinding(
    record({ lens: 'web-and-api', topic: 'authz-object-level' }),
    { evidence: { declarations: DECLARATIONS, coverage: COVERED } },
  )
  assert.ok(validation.errors.some((e) => e.code === 'EVIDENCE_CLASS_NOT_CONSUMED'))
})

test('a claim outside may_conclude is malformed', () => {
  const validation = validateFinding(
    record({ evidence_claim: 'sensitive-data-at-rest' }),
    { evidence: { declarations: DECLARATIONS, coverage: COVERED } },
  )
  assert.ok(validation.errors.some((e) => e.code === 'EVIDENCE_CLAIM_OUT_OF_BOUNDS'))
})

test('a claim on NOT_ASSESSED coverage is UNPROVEN and capped at Medium', () => {
  const coverage = new Map([
    ['cloud-and-iac\0container-image-content\0built-artifact', 'NOT_ASSESSED'],
  ])
  const errors = validateFinding(
    record({ effective_severity: 'High', triage_disposition: 'queued', verification_status: 'CONFIRMED' }),
    { evidence: { declarations: DECLARATIONS, coverage } },
  ).errors
  assert.ok(errors.some((e) => e.code === 'EVIDENCE_COVERAGE_UNPROVEN'))
  assert.ok(errors.some((e) => e.code === 'EVIDENCE_COVERAGE_SEVERITY_CAP'))
})

test('INVENTORY_ONLY caps identically to NOT_ASSESSED', () => {
  const coverage = new Map([
    ['cloud-and-iac\0container-image-content\0built-artifact', 'INVENTORY_ONLY'],
  ])
  const errors = validateFinding(
    record({ effective_severity: 'Critical', triage_disposition: 'queued' }),
    { evidence: { declarations: DECLARATIONS, coverage } },
  ).errors
  assert.ok(errors.some((e) => e.code === 'EVIDENCE_COVERAGE_SEVERITY_CAP'))
})

test('an unknown lens in the declaration set is a violation, not a pass', () => {
  const validation = validateFinding(record({ lens: 'no-such-lens' }), {
    evidence: { declarations: DECLARATIONS, coverage: COVERED },
  })
  assert.ok(validation.errors.some((e) => e.code === 'EVIDENCE_LENS_UNDECLARED'))
})

test('the higher-precedence class prevails and the conflict is recorded', () => {
  const sourceClaim = {
    candidate_id: 'container-image-content:aaaa1111',
    lens: 'cloud-and-iac',
    topic: 'container-image-content',
    location: ['Dockerfile:14'],
  }
  const artifactClaim = {
    candidate_id: 'container-image-content:5c1a7f30',
    lens: 'cloud-and-iac',
    topic: 'container-image-content',
    location: ['peerstar-api-image:layer/02/secret.txt'],
    evidence_context: { evidence_class: 'built-artifact' },
  }
  const conflicts = evidenceConflicts([sourceClaim, artifactClaim])
  assert.equal(conflicts.length, 1)
  assert.equal(conflicts[0].prevailing_class, 'built-artifact')
  assert.equal(conflicts[0].superseded_class, 'source')
  assert.equal(conflicts[0].prevailing_candidate_id, 'container-image-content:5c1a7f30')
})

test('two records in the same class are not a precedence conflict', () => {
  const conflicts = evidenceConflicts([
    { candidate_id: 'a', lens: 'web-and-api', topic: 't', location: ['a.ts:1'] },
    { candidate_id: 'b', lens: 'web-and-api', topic: 't', location: ['b.ts:2'] },
  ])
  assert.deepEqual(conflicts, [])
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-invariant-16.test.mjs`
Expected: FAIL — `evidenceConflicts is not a function`

- [ ] **Step 3: Implement**

In `scripts/lib/contracts.mjs`, add the import:

```js
import {
  EVIDENCE_CLASSES,
  compareEvidenceClassPrecedence,
  evidenceCoverageStateClears,
} from './evidence-classes.mjs'
```

Add the declaration-aware checks and export the conflict resolver:

```js
const EVIDENCE_COVERAGE_CAP = 'Medium'

function evidenceCoverageKey(lens, topic, evidenceClass) {
  return `${lens}\0${topic}\0${evidenceClass}`
}

// Invariant 16's declaration-aware half. Runs only when the caller supplies the
// lens declarations and the run's coverage matrix; without them the record-local
// half from evidenceInvariantErrors still applies.
function evidenceDeclarationErrors(record, evidence) {
  const errors = []
  const context = record.evidence_context
  if (!context || !evidence) return errors

  const declared = evidence.declarations?.get(record.lens)
  if (!declared) {
    addError(
      errors,
      'EVIDENCE_LENS_UNDECLARED',
      '/lens',
      `lens ${String(record.lens)} declares no evidence classes; a finding cannot rest on one`,
    )
    return errors
  }

  const entry = declared[context.evidence_class]
  if (entry?.state !== 'consumed') {
    addError(
      errors,
      'EVIDENCE_CLASS_NOT_CONSUMED',
      '/evidence_context/evidence_class',
      `${record.lens} declares "${context.evidence_class}" as `
      + `${entry?.state ?? 'undeclared'} and cannot conclude from it`,
    )
    return errors
  }

  const permitted = entry.may_conclude ?? []
  if (!permitted.includes(record.evidence_claim)) {
    addError(
      errors,
      'EVIDENCE_CLAIM_OUT_OF_BOUNDS',
      '/evidence_claim',
      `${record.lens} may conclude ${permitted.join(', ') || 'nothing'} from `
      + `"${context.evidence_class}"; this record asserts "${String(record.evidence_claim)}"`,
    )
  }

  const state = evidence.coverage?.get(
    evidenceCoverageKey(record.lens, record.topic, context.evidence_class),
  )
  if (typeof state === 'string' && !evidenceCoverageStateClears(state)) {
    if (
      record.verification_status !== undefined
      && record.verification_status !== 'UNPROVEN'
    ) {
      addError(
        errors,
        'EVIDENCE_COVERAGE_UNPROVEN',
        '/verification_status',
        `evidence-class coverage is ${state}; a claim resting on it is UNPROVEN`,
      )
    }
    if (
      record.effective_severity !== undefined
      && severityAbove(record.effective_severity, EVIDENCE_COVERAGE_CAP)
    ) {
      addError(
        errors,
        'EVIDENCE_COVERAGE_SEVERITY_CAP',
        '/effective_severity',
        `evidence-class coverage is ${state}; effective severity is capped at `
        + `${EVIDENCE_COVERAGE_CAP}`,
      )
    }
  }
  return errors
}

/**
 * The precedence resolver. Two records on one topic whose evidence classes
 * differ are not two findings — they are one disagreement, and the higher
 * class wins. Recording the conflict is what keeps the loser visible: a
 * silently reconciled disagreement is indistinguishable from agreement.
 */
export function evidenceConflicts(findings) {
  const byTopic = new Map()
  for (const finding of findings ?? []) {
    const key = `${finding.lens}\0${finding.topic}`
    if (!byTopic.has(key)) byTopic.set(key, [])
    byTopic.get(key).push({
      candidate_id: finding.candidate_id,
      topic: finding.topic,
      evidence_class: finding.evidence_context?.evidence_class ?? EVIDENCE_CLASSES.SOURCE,
    })
  }

  const conflicts = []
  for (const records of byTopic.values()) {
    const classes = new Set(records.map(({ evidence_class: c }) => c))
    if (classes.size < 2) continue
    const ranked = [...records].sort((left, right) =>
      compareEvidenceClassPrecedence(right.evidence_class, left.evidence_class)
      || compareCanonicalStrings(left.candidate_id, right.candidate_id))
    const [prevailing, ...superseded] = ranked
    for (const loser of superseded) {
      if (loser.evidence_class === prevailing.evidence_class) continue
      conflicts.push({
        topic: prevailing.topic,
        prevailing_candidate_id: prevailing.candidate_id,
        prevailing_class: prevailing.evidence_class,
        superseded_candidate_id: loser.candidate_id,
        superseded_class: loser.evidence_class,
      })
    }
  }
  return conflicts.sort((left, right) =>
    compareCanonicalStrings(left.prevailing_candidate_id, right.prevailing_candidate_id)
    || compareCanonicalStrings(left.superseded_candidate_id, right.superseded_candidate_id))
}
```

and thread the option through `validateFinding`:

```js
  errors.push(...findingInvariantErrors(record))
  errors.push(...evidenceDeclarationErrors(record, options.evidence))
```

`compareCanonicalStrings` is already imported by `contracts.mjs`; confirm before adding a duplicate import. `severityAbove` is the existing helper used by the elevation check.

- [ ] **Step 4: Run the tests**

Run: `npm.cmd test -- test/evidence-invariant-16.test.mjs test/contracts-runtime.test.mjs test/v3-contract-adversarial.test.mjs`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/contracts.mjs test/evidence-invariant-16.test.mjs
git commit -m "feat: invariant 16 — declared classes, bounded claims, precedence and the coverage cap"
```

---

### Task 5: The evidence-class coverage matrix

**Files:**
- Create: `scripts/lib/evidence-coverage.mjs`
- Modify: `schemas/run.schema.json`
- Modify: `scripts/lib/run-engine.mjs` — **in-flight; re-read before editing**
- Test: `test/evidence-coverage.test.mjs` (create)

**Interfaces:**
- Consumes: `lensEvidenceDeclarations` (Task 1); `EVIDENCE_CLASS_ORDER` (Plan 1).
- Produces:
  - `buildEvidenceCoverage({lenses, activatedLenses, bundles}): {cells: Array<{lens, topic, evidence_class, state, reason}>, summary: {…}}`
  - `evidenceCoverageIndex(coverage): Map<'lens\0topic\0class', state>` — the map Task 4's validator consumes
  - `run.evidence_coverage` and `run.evidence_bundles` on the run object

The state each cell gets:

| Condition | State | Reason |
|---|---|---|
| Lens declares the class `not-consumed` | `NOT_APPLICABLE` | the lens has nothing to say — different from evidence being missing |
| Lens is not activated in this run | `NOT_APPLICABLE` | the lens did not run |
| Class is `source` and the lens is activated | `COVERED` | the repository is the run's evidence |
| Class is consumed and no bundle of that class was supplied | `NOT_ASSESSED` | `no <class> evidence was acquired for this run` |
| A bundle exists but its `artifact_kind` is declared by no activated lens | `INVENTORY_ONLY` | `<kind> was acquired; no activated lens declares a rule for it` |
| A bundle exists and its kind is declared | the bundle's own `coverage_state` | carried through from the acquisition |

The fourth row is the entire point of Plan 2: it is the cell that today does
not exist, and its absence is what makes a source-only audit read as clean.

- [ ] **Step 1: Write the failing test**

Create `test/evidence-coverage.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildEvidenceCoverage,
  evidenceCoverageIndex,
} from '../scripts/lib/evidence-coverage.mjs'

const LENSES = [
  {
    frontmatter: {
      name: 'cloud-and-iac',
      owns: ['container-image-content', 'iac-secrets'],
      activates_on: {
        evidence_classes: {
          source: { state: 'consumed' },
          'built-artifact': {
            state: 'consumed',
            artifact_kinds: ['oci-image'],
            may_conclude: ['secret-present-in-artifact'],
          },
          'deployed-state': { state: 'consumed', may_conclude: ['drift-from-source'] },
          'live-runtime': { state: 'not-consumed' },
        },
      },
    },
  },
  {
    frontmatter: {
      name: 'mobile-app-security',
      owns: ['mobile-storage'],
      activates_on: {
        evidence_classes: {
          source: { state: 'consumed' },
          'built-artifact': {
            state: 'consumed',
            artifact_kinds: ['apk', 'ipa'],
            may_conclude: ['secret-present-in-artifact'],
          },
          'deployed-state': { state: 'not-consumed' },
          'live-runtime': { state: 'not-consumed' },
        },
      },
    },
  },
]

const cell = (coverage, lens, topic, evidenceClass) => coverage.cells.find(
  (entry) => entry.lens === lens
    && entry.topic === topic
    && entry.evidence_class === evidenceClass,
)

test('with no bundle, every consumed non-source class is NOT_ASSESSED with a reason', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [],
  })
  const artifact = cell(coverage, 'cloud-and-iac', 'container-image-content', 'built-artifact')
  assert.equal(artifact.state, 'NOT_ASSESSED')
  assert.match(artifact.reason, /no built-artifact evidence was acquired/)
  assert.equal(
    cell(coverage, 'cloud-and-iac', 'container-image-content', 'deployed-state').state,
    'NOT_ASSESSED',
  )
})

test('source is COVERED for an activated lens and the repository needs no bundle', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [],
  })
  assert.equal(cell(coverage, 'cloud-and-iac', 'iac-secrets', 'source').state, 'COVERED')
})

test('a not-consumed class is NOT_APPLICABLE, never NOT_ASSESSED', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [],
  })
  const runtime = cell(coverage, 'cloud-and-iac', 'container-image-content', 'live-runtime')
  assert.equal(runtime.state, 'NOT_APPLICABLE')
  assert.match(runtime.reason, /nothing to say/)
})

test('an inactive lens contributes NOT_APPLICABLE across the board', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [],
  })
  for (const evidenceClass of ['source', 'built-artifact', 'deployed-state', 'live-runtime']) {
    assert.equal(
      cell(coverage, 'mobile-app-security', 'mobile-storage', evidenceClass).state,
      'NOT_APPLICABLE',
    )
  }
})

test('a supplied bundle carries its own coverage state into the matrix', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [{
      evidence_id: 'peerstar-api-image',
      evidence_class: 'built-artifact',
      artifact_kind: 'oci-image',
      coverage_state: 'PARTIAL',
      root_sha256: 'a'.repeat(64),
    }],
  })
  const artifact = cell(coverage, 'cloud-and-iac', 'container-image-content', 'built-artifact')
  assert.equal(artifact.state, 'PARTIAL')
  assert.match(artifact.reason, /peerstar-api-image/)
})

test('an artifact kind no activated lens declares is INVENTORY_ONLY, never silence', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [{
      evidence_id: 'peerstar-mobile',
      evidence_class: 'built-artifact',
      artifact_kind: 'apk',
      coverage_state: 'COVERED',
      root_sha256: 'b'.repeat(64),
    }],
  })
  const artifact = cell(coverage, 'cloud-and-iac', 'container-image-content', 'built-artifact')
  assert.equal(artifact.state, 'INVENTORY_ONLY')
  assert.match(artifact.reason, /apk/)
})

test('the summary counts the classes an audit could not reach', () => {
  const coverage = buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [],
  })
  assert.equal(coverage.summary.unreached_class_count, 2)
  assert.deepEqual(coverage.summary.unreached_classes, ['built-artifact', 'deployed-state'])
  assert.equal(coverage.summary.bundle_count, 0)
})

test('the index is keyed for the finding validator', () => {
  const index = evidenceCoverageIndex(buildEvidenceCoverage({
    lenses: LENSES,
    activatedLenses: ['cloud-and-iac'],
    bundles: [],
  }))
  assert.equal(
    index.get('cloud-and-iac\0container-image-content\0built-artifact'),
    'NOT_ASSESSED',
  )
})

test('cells are canonically ordered so the run digest is stable', () => {
  const first = buildEvidenceCoverage({ lenses: LENSES, activatedLenses: ['cloud-and-iac'], bundles: [] })
  const second = buildEvidenceCoverage({
    lenses: [...LENSES].reverse(),
    activatedLenses: ['cloud-and-iac'],
    bundles: [],
  })
  assert.deepEqual(first.cells, second.cells)
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-coverage.test.mjs`
Expected: FAIL — `Cannot find module '.../scripts/lib/evidence-coverage.mjs'`

- [ ] **Step 3: Implement the matrix**

Create `scripts/lib/evidence-coverage.mjs`:

```js
import { compareCanonicalStrings } from './canonical-order.mjs'
import { EVIDENCE_CLASSES, EVIDENCE_CLASS_ORDER } from './evidence-classes.mjs'

/**
 * Coverage becomes lens x topic x evidence class, where it is currently
 * lens x topic. No new state is introduced: the five states are the database
 * contract's, and the existing rule that INVENTORY_ONLY and NOT_ASSESSED never
 * render as clean is what does the work.
 *
 * The load-bearing cell is the one nobody writes today: a lens that consumes
 * built-artifact in a run where no image was acquired. Without it, "we examined
 * the Dockerfile but never the image" is not expressible, and an audit that
 * cannot express its blind spot reports silence — which reads as clearance.
 */
export function buildEvidenceCoverage({ lenses = [], activatedLenses = [], bundles = [] }) {
  const active = new Set(activatedLenses)
  const bundlesByClass = new Map(EVIDENCE_CLASS_ORDER.map((c) => [c, []]))
  for (const bundle of bundles) {
    bundlesByClass.get(bundle.evidence_class)?.push(bundle)
  }

  const cells = []
  const unreached = new Set()

  for (const lens of lenses) {
    const name = lens.frontmatter?.name ?? lens.name
    const declared = lens.frontmatter?.activates_on?.evidence_classes ?? {}
    const topics = [...(lens.frontmatter?.owns ?? [])].sort(compareCanonicalStrings)
    const activated = active.has(name)

    for (const topic of topics) {
      for (const evidenceClass of EVIDENCE_CLASS_ORDER) {
        const entry = declared[evidenceClass]
        if (entry?.state !== 'consumed') {
          cells.push({
            lens: name,
            topic,
            evidence_class: evidenceClass,
            state: 'NOT_APPLICABLE',
            reason: `${name} declares "${evidenceClass}" not-consumed; it has nothing to say`,
          })
          continue
        }
        if (!activated) {
          cells.push({
            lens: name,
            topic,
            evidence_class: evidenceClass,
            state: 'NOT_APPLICABLE',
            reason: `${name} did not activate in this run`,
          })
          continue
        }
        if (evidenceClass === EVIDENCE_CLASSES.SOURCE) {
          cells.push({
            lens: name,
            topic,
            evidence_class: evidenceClass,
            state: 'COVERED',
            reason: 'the repository under audit is the run evidence',
          })
          continue
        }

        const available = bundlesByClass.get(evidenceClass) ?? []
        if (available.length === 0) {
          unreached.add(evidenceClass)
          cells.push({
            lens: name,
            topic,
            evidence_class: evidenceClass,
            state: 'NOT_ASSESSED',
            reason: `no ${evidenceClass} evidence was acquired for this run`,
          })
          continue
        }

        const kinds = entry.artifact_kinds ?? null
        const usable = kinds === null
          ? available
          : available.filter((bundle) => kinds.includes(bundle.artifact_kind))
        if (usable.length === 0) {
          const acquired = [...new Set(available.map(({ artifact_kind: kind }) => kind))]
            .sort(compareCanonicalStrings)
          cells.push({
            lens: name,
            topic,
            evidence_class: evidenceClass,
            state: 'INVENTORY_ONLY',
            reason: `${acquired.join(', ')} was acquired; ${name} declares no rule for it`,
          })
          continue
        }

        // Where several bundles cover one class, the run is only as covered as
        // its weakest — the same reason PARTIAL exists at all.
        const ranked = ['NOT_ASSESSED', 'INVENTORY_ONLY', 'PARTIAL', 'COVERED']
        const weakest = usable.reduce((worst, bundle) =>
          ranked.indexOf(bundle.coverage_state) < ranked.indexOf(worst.coverage_state)
            ? bundle
            : worst)
        cells.push({
          lens: name,
          topic,
          evidence_class: evidenceClass,
          state: weakest.coverage_state,
          reason: `${weakest.evidence_id} (${weakest.root_sha256.slice(0, 12)})`,
        })
      }
    }
  }

  cells.sort((left, right) =>
    compareCanonicalStrings(left.lens, right.lens)
    || compareCanonicalStrings(left.topic, right.topic)
    || EVIDENCE_CLASS_ORDER.indexOf(left.evidence_class)
      - EVIDENCE_CLASS_ORDER.indexOf(right.evidence_class))

  const unreachedClasses = [...unreached]
    .sort((left, right) =>
      EVIDENCE_CLASS_ORDER.indexOf(left) - EVIDENCE_CLASS_ORDER.indexOf(right))

  return {
    cells,
    summary: {
      cell_count: cells.length,
      bundle_count: bundles.length,
      unreached_class_count: unreachedClasses.length,
      unreached_classes: unreachedClasses,
      not_assessed_cell_count: cells.filter(({ state }) => state === 'NOT_ASSESSED').length,
      inventory_only_cell_count: cells.filter(({ state }) => state === 'INVENTORY_ONLY').length,
    },
  }
}

export function evidenceCoverageIndex(coverage) {
  return new Map((coverage?.cells ?? []).map((cell) => [
    `${cell.lens}\0${cell.topic}\0${cell.evidence_class}`,
    cell.state,
  ]))
}
```

- [ ] **Step 4: Extend the run schema**

In `schemas/run.schema.json`, add two properties to the run object (not to `required` — a run planned before this change stays valid):

```json
    "evidence_bundles": {
      "type": "array",
      "maxItems": 64,
      "items": {
        "type": "object",
        "additionalProperties": false,
        "required": ["evidence_id", "evidence_class", "coverage_state", "root_sha256", "adapter_id"],
        "properties": {
          "evidence_id": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]{0,63}$" },
          "evidence_class": {
            "enum": ["source", "built-artifact", "deployed-state", "live-runtime"]
          },
          "adapter_id": { "type": "string", "pattern": "^[a-z0-9][a-z0-9-]*$" },
          "artifact_kind": { "enum": ["apk", "dist-bundle", "ipa", "jar", "oci-image"] },
          "coverage_state": {
            "enum": ["COVERED", "PARTIAL", "INVENTORY_ONLY", "NOT_ASSESSED", "NOT_APPLICABLE"]
          },
          "phi_bearing": { "type": "boolean" },
          "root_sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" }
        }
      }
    },
    "evidence_coverage": {
      "type": "object",
      "additionalProperties": false,
      "required": ["cells", "summary"],
      "properties": {
        "cells": {
          "type": "array",
          "maxItems": 8192,
          "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["lens", "topic", "evidence_class", "state", "reason"],
            "properties": {
              "lens": { "type": "string" },
              "topic": { "type": "string" },
              "evidence_class": {
                "enum": ["source", "built-artifact", "deployed-state", "live-runtime"]
              },
              "state": {
                "enum": ["COVERED", "PARTIAL", "INVENTORY_ONLY", "NOT_ASSESSED", "NOT_APPLICABLE"]
              },
              "reason": { "type": "string", "minLength": 1, "maxLength": 512 }
            }
          }
        },
        "summary": {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "cell_count",
            "bundle_count",
            "unreached_class_count",
            "unreached_classes",
            "not_assessed_cell_count",
            "inventory_only_cell_count"
          ],
          "properties": {
            "cell_count": { "type": "integer", "minimum": 0 },
            "bundle_count": { "type": "integer", "minimum": 0 },
            "unreached_class_count": { "type": "integer", "minimum": 0 },
            "unreached_classes": {
              "type": "array",
              "uniqueItems": true,
              "items": {
                "enum": ["source", "built-artifact", "deployed-state", "live-runtime"]
              }
            },
            "not_assessed_cell_count": { "type": "integer", "minimum": 0 },
            "inventory_only_cell_count": { "type": "integer", "minimum": 0 }
          }
        }
      }
    },
```

- [ ] **Step 5: Wire it into the plan**

**Re-read `scripts/lib/run-engine.mjs` before editing — it has uncommitted changes.**

In `createRunPlan`, accept `evidenceBundles = []` in the destructured options, and after `buildActivationPlan` returns:

```js
  const evidenceCoverage = buildEvidenceCoverage({
    lenses,
    activatedLenses: activation.active_lenses,
    bundles: evidenceBundles,
  })
```

Add to `planMaterial`, so the coverage matrix is inside the plan digest and cannot be edited after planning:

```js
    evidence_coverage_sha256: sha256(stableJson(evidenceCoverage, 0)),
```

Add to the `run` object, beside `database_discovery`:

```js
    evidence_bundles: evidenceBundles,
    evidence_coverage: evidenceCoverage,
```

- [ ] **Step 6: Run the tests**

Run: `npm.cmd test -- test/evidence-coverage.test.mjs test/contracts-runtime.test.mjs test/inventory-runner.test.mjs test/coverage-model.test.mjs test/smoke.test.mjs`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add scripts/lib/evidence-coverage.mjs schemas/run.schema.json scripts/lib/run-engine.mjs test/evidence-coverage.test.mjs
git commit -m "feat: lens x topic x evidence-class coverage matrix pinned into the plan digest"
```

---

### Task 6: `--evidence-bundle` and the report

**Files:**
- Modify: `scripts/audit.mjs` — **in-flight; re-read before editing**
- Modify: `scripts/lib/report.mjs`
- Test: `test/evidence-report.test.mjs` (create)

**Interfaces:**
- Consumes: `loadEvidenceBundle` (Plan 1, Task 3); `run.evidence_coverage` (Task 5); `evidenceConflicts` (Task 4).
- Produces: `red-team-audit plan <repository> --evidence-bundle <path>` (repeatable), an `### Evidence-class coverage` section in `report.md`, and a `Precedence conflicts` table when two classes disagree.

`--evidence-bundle` follows `--database-conformance` exactly: resolved outside the target repository, `realpath`-checked before and after the read so the path cannot be swapped mid-read, verified, and refused on any integrity failure. `parseArguments` in `audit.mjs` rejects a duplicate option, so repeatability needs the option to accept a comma-separated list rather than being repeated — which is also how it stays one immutable string in the plan digest.

- [ ] **Step 1: Write the failing test**

Create `test/evidence-report.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { renderMarkdownReport } from '../scripts/lib/report.mjs'

function run(overrides = {}) {
  return {
    run_id: 'run-2026-08-08-aaaa',
    state: 'COMPLETE',
    phase: 'REPORT',
    created_at: '2026-08-08T14:00:00Z',
    capability_mode: 'STATIC',
    tool: { name: 'red-team-audit', version: '0.11.0', corpus_sha256: 'a'.repeat(64) },
    repository: { root: '/repo', tree_digest: 'b'.repeat(64), dirty: 'unknown' },
    activated_lenses: ['cloud-and-iac'],
    jobs: [],
    coverage: { inventory: [], examined: [], gaps: [] },
    findings: [],
    errors: [],
    artifacts: {},
    attempt_events: [],
    evidence_bundles: [],
    evidence_coverage: {
      cells: [
        {
          lens: 'cloud-and-iac',
          topic: 'container-image-content',
          evidence_class: 'source',
          state: 'COVERED',
          reason: 'the repository under audit is the run evidence',
        },
        {
          lens: 'cloud-and-iac',
          topic: 'container-image-content',
          evidence_class: 'built-artifact',
          state: 'NOT_ASSESSED',
          reason: 'no built-artifact evidence was acquired for this run',
        },
      ],
      summary: {
        cell_count: 2,
        bundle_count: 0,
        unreached_class_count: 1,
        unreached_classes: ['built-artifact'],
        not_assessed_cell_count: 1,
        inventory_only_cell_count: 0,
      },
    },
    ...overrides,
  }
}

test('the report names every class the audit could not reach', () => {
  const report = renderMarkdownReport(run())
  assert.match(report, /### Evidence-class coverage/)
  assert.match(report, /built-artifact/)
  assert.match(report, /NOT_ASSESSED/)
  assert.match(report, /no built-artifact evidence was acquired for this run/)
})

test('an unreached class is stated as a blind spot, not omitted', () => {
  const report = renderMarkdownReport(run())
  const section = report.slice(report.indexOf('### Evidence-class coverage'))
  assert.match(
    section,
    /1 evidence class was not acquired[\s\S]*not a clearance/,
  )
})

test('a run with every class covered says so without the blind-spot notice', () => {
  const covered = run({
    evidence_bundles: [{
      evidence_id: 'peerstar-api-image',
      evidence_class: 'built-artifact',
      adapter_id: 'artifact',
      artifact_kind: 'oci-image',
      coverage_state: 'COVERED',
      root_sha256: 'c'.repeat(64),
    }],
    evidence_coverage: {
      cells: [{
        lens: 'cloud-and-iac',
        topic: 'container-image-content',
        evidence_class: 'built-artifact',
        state: 'COVERED',
        reason: 'peerstar-api-image (cccccccccccc)',
      }],
      summary: {
        cell_count: 1,
        bundle_count: 1,
        unreached_class_count: 0,
        unreached_classes: [],
        not_assessed_cell_count: 0,
        inventory_only_cell_count: 0,
      },
    },
  })
  const report = renderMarkdownReport(covered)
  assert.match(report, /peerstar-api-image/)
  assert.equal(/was not acquired/.test(report), false)
})

test('a precedence conflict is printed, never silently reconciled', () => {
  const conflicted = run({
    findings: [
      {
        candidate_id: 'container-image-content:aaaa1111',
        lens: 'cloud-and-iac',
        topic: 'container-image-content',
        title: 'Dockerfile removes the build secret',
        claimed_impact_severity: 'Info',
        effective_severity: 'Info',
        location: ['Dockerfile:14'],
      },
      {
        candidate_id: 'container-image-content:5c1a7f30',
        lens: 'cloud-and-iac',
        topic: 'container-image-content',
        title: 'Build secret is readable below the whiteout',
        claimed_impact_severity: 'High',
        effective_severity: 'High',
        location: ['peerstar-api-image:layer/02/secret.txt'],
        evidence_context: { evidence_class: 'built-artifact', evidence_id: 'peerstar-api-image' },
      },
    ],
  })
  const report = renderMarkdownReport(conflicted)
  assert.match(report, /Precedence conflicts/)
  assert.match(report, /container-image-content:5c1a7f30/)
  assert.match(report, /container-image-content:aaaa1111/)
  assert.match(report, /built-artifact/)
})

test('a run planned before this change still renders', () => {
  const legacy = run()
  delete legacy.evidence_coverage
  delete legacy.evidence_bundles
  assert.doesNotThrow(() => renderMarkdownReport(legacy))
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-report.test.mjs`
Expected: FAIL — no `### Evidence-class coverage` section.

- [ ] **Step 3: Render the section**

In `scripts/lib/report.mjs`, immediately after the `### Data-store coverage` block ends (the `lines.push('')` that closes it), add:

```js
  const evidenceCoverage = run.evidence_coverage
  if (evidenceCoverage) {
    const summary = evidenceCoverage.summary ?? {}
    lines.push(
      '### Evidence-class coverage',
      '',
      '| Lens | Topic | Evidence class | Coverage | Basis |',
      '|---|---|---|---|---|',
    )
    for (const cell of evidenceCoverage.cells ?? []) {
      lines.push(
        `| ${tableCell(cell.lens)} | ${tableCell(cell.topic)} | ` +
        `${tableCell(cell.evidence_class)} | ${tableCell(cell.state)} | ` +
        `${tableCell(cell.reason)} |`,
      )
    }
    lines.push('')
    // INVENTORY_ONLY and NOT_ASSESSED are never rendered as pass, clean, secure
    // or no findings. Stating the blind spot is the whole point: silence about
    // an unexamined class is what reads as clearance.
    if ((summary.unreached_class_count ?? 0) > 0) {
      const classes = (summary.unreached_classes ?? []).join(', ')
      lines.push(
        `${summary.unreached_class_count} evidence ` +
        `class${summary.unreached_class_count === 1 ? ' was' : 'es were'} not acquired ` +
        `for this run: ${classes}. Findings and clean results below cover the ` +
        'repository only. An unexamined evidence class is a coverage gap, not a clearance.',
        '',
      )
    }
    if ((summary.inventory_only_cell_count ?? 0) > 0) {
      lines.push(
        `${summary.inventory_only_cell_count} lens/topic obligation` +
        `${summary.inventory_only_cell_count === 1 ? '' : 's'} received evidence no ` +
        'activated lens has a rule for; those are inventoried, not assessed.',
        '',
      )
    }
  }

  const conflicts = evidenceConflicts(run.findings ?? [])
  if (conflicts.length > 0) {
    lines.push(
      '### Precedence conflicts',
      '',
      'Where two evidence classes disagree about one topic the higher-precedence ' +
      'class prevails and the disagreement is recorded here. A lower-precedence ' +
      'signal never overrides a conflicting higher-precedence one.',
      '',
      '| Topic | Prevailing | Class | Superseded | Class |',
      '|---|---|---|---|---|',
    )
    for (const conflict of conflicts) {
      lines.push(
        `| ${tableCell(conflict.topic)} | ` +
        `${inlineCode(conflict.prevailing_candidate_id)} | ` +
        `${tableCell(conflict.prevailing_class)} | ` +
        `${inlineCode(conflict.superseded_candidate_id)} | ` +
        `${tableCell(conflict.superseded_class)} |`,
      )
    }
    lines.push('')
  }
```

and import the resolver at the top of `report.mjs`:

```js
import { evidenceConflicts } from './contracts.mjs'
```

- [ ] **Step 4: Wire the CLI option**

**Re-read `scripts/audit.mjs` before editing.**

In `COMMAND_ARGUMENTS.plan.options`, add `'evidence-bundle': 'value'`. In `HELP`, add `[--evidence-bundle <bundle>[,<bundle>…]]` to the `plan` usage line. In `planCommand`, immediately after the `database-conformance` block:

```js
  const evidenceBundles = []
  if (typeof options['evidence-bundle'] === 'string') {
    for (const argument of options['evidence-bundle'].split(',')) {
      const bundleArgument = resolve(argument.trim())
      const before = await realpath(bundleArgument)
      if (pathWithin(targetRoot, before)) {
        throw new Error(
          'evidence bundles must be supplied from outside the untrusted target repository',
        )
      }
      const loaded = await loadEvidenceBundle(before)
      const after = await realpath(bundleArgument)
      if (after !== before || pathWithin(targetRoot, after)) {
        throw new Error('evidence bundle path changed while it was read')
      }
      evidenceBundles.push({
        evidence_id: loaded.evidence_context.evidence_id,
        evidence_class: loaded.evidence_context.evidence_class,
        adapter_id: loaded.evidence_context.adapter_id,
        ...(loaded.profile.artifact_kind
          ? { artifact_kind: loaded.profile.artifact_kind }
          : {}),
        coverage_state: loaded.profile.coverage_state,
        phi_bearing: loaded.profile.phi_bearing,
        root_sha256: loaded.root_sha256,
      })
    }
    const ids = evidenceBundles.map(({ evidence_id: id }) => id)
    if (new Set(ids).size !== ids.length) {
      throw new Error('each evidence_id must be unique within a run')
    }
  }
```

and pass `evidenceBundles` through to `createRunPlan`. Add the import:

```js
import { loadEvidenceBundle } from './lib/evidence-bundle.mjs'
```

- [ ] **Step 5: Run the tests**

Run: `npm.cmd test -- test/evidence-report.test.mjs test/report-sarif.test.mjs test/platform-cli.test.mjs test/release-wiring.test.mjs`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add scripts/audit.mjs scripts/lib/report.mjs test/evidence-report.test.mjs
git commit -m "feat: attach verified evidence bundles at plan time and report per-class coverage"
```

---

### Task 7: The false-clearance and precedence regression tests

**Files:**
- Test: `test/evidence-false-clearance.test.mjs` (create)

**Interfaces:**
- Consumes: everything above. Produces nothing — it exists to fail loudly if the coverage matrix is ever relaxed.

This task encodes the reason the project exists. It is deliberately end-to-end
rather than unit: the unit tests above can all pass while the wiring between
them silently drops the matrix.

- [ ] **Step 1: Write the test**

Create `test/evidence-false-clearance.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, mkdir, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRunPlan } from '../scripts/lib/run-engine.mjs'
import { renderMarkdownReport } from '../scripts/lib/report.mjs'
import { writeEvidenceBundle } from '../scripts/lib/evidence-bundle.mjs'

const CLEARANCE_LANGUAGE = /\b(?:no findings|clean|secure|passed|no issues)\b/i

async function repositoryWithADockerfile() {
  const root = await mkdtemp(join(tmpdir(), 'rta-false-clearance-'))
  await mkdir(join(root, 'deploy'), { recursive: true })
  await writeFile(
    join(root, 'Dockerfile'),
    'FROM node:20-alpine\nCOPY secret.txt /secret.txt\nRUN rm /secret.txt\n',
    'utf8',
  )
  await writeFile(join(root, 'deploy', 'app.yaml'), 'kind: Deployment\n', 'utf8')
  return root
}

test('an audit with no evidence bundle reports built-artifact as NOT_ASSESSED with a reason', async () => {
  const plan = await createRunPlan({ targetRoot: await repositoryWithADockerfile() })
  const cells = plan.run.evidence_coverage.cells.filter(
    (cell) => cell.lens === 'cloud-and-iac' && cell.evidence_class === 'built-artifact',
  )
  assert.ok(cells.length > 0, 'cloud-and-iac must contribute built-artifact cells')
  for (const cell of cells) {
    assert.equal(cell.state, 'NOT_ASSESSED')
    assert.match(cell.reason, /no built-artifact evidence was acquired/)
  }
  assert.ok(plan.run.evidence_coverage.summary.unreached_classes.includes('built-artifact'))
})

test('the report never renders an unreached class as clean', async () => {
  const plan = await createRunPlan({ targetRoot: await repositoryWithADockerfile() })
  const report = renderMarkdownReport(plan.run)
  const section = report.slice(report.indexOf('### Evidence-class coverage'))
  const table = section.slice(0, section.indexOf('\n\n', section.indexOf('|---')))
  for (const line of table.split('\n')) {
    if (!line.includes('NOT_ASSESSED') && !line.includes('INVENTORY_ONLY')) continue
    assert.equal(
      CLEARANCE_LANGUAGE.test(line),
      false,
      `an unassessed class must not read as a clearance: ${line}`,
    )
  }
  assert.match(section, /not a clearance/)
})

test('the Dockerfile whiteout case is the one this encodes', async () => {
  // COPY secret.txt / RUN rm /secret.txt reads as a removal in source and is
  // not one in the image. Before this matrix existed the run said nothing at
  // all about the image, and saying nothing is what read as clearance.
  const plan = await createRunPlan({ targetRoot: await repositoryWithADockerfile() })
  assert.ok(plan.run.activated_lenses.includes('cloud-and-iac'))
  assert.equal(plan.run.evidence_coverage.summary.bundle_count, 0)
  assert.ok(plan.run.evidence_coverage.summary.not_assessed_cell_count > 0)
})

test('supplying a covering bundle lifts exactly the class it covers', async () => {
  const bundleDirectory = join(await mkdtemp(join(tmpdir(), 'rta-ev-')), 'ev')
  const bundle = await writeEvidenceBundle({
    directory: bundleDirectory,
    profile: {
      schema: 'evidence-bundle-v1',
      evidence_context: {
        evidence_id: 'peerstar-api-image',
        evidence_class: 'built-artifact',
        adapter_id: 'artifact',
        target_identity: 'sha256:9f2c',
        acquisition_mode: 'offline-export',
        acquired_on: '2026-08-08T14:22:10Z',
        detection_evidence: ['image.tar sha256:4aaff082'],
        confidence: 'high',
      },
      target_class: 'LAB',
      phi_scope: 'none',
      phi_bearing: false,
      adapter_version: '1.0.0',
      contract_version: 1,
      coverage_state: 'COVERED',
      artifact_kind: 'oci-image',
      attestation: null,
      coverage_gaps: [],
    },
    payload: [{ path: 'layers/02/entries.json', bytes: Buffer.from('[]', 'utf8') }],
  })

  const plan = await createRunPlan({
    targetRoot: await repositoryWithADockerfile(),
    evidenceBundles: [{
      evidence_id: 'peerstar-api-image',
      evidence_class: 'built-artifact',
      adapter_id: 'artifact',
      artifact_kind: 'oci-image',
      coverage_state: 'COVERED',
      phi_bearing: false,
      root_sha256: bundle.root_sha256,
    }],
  })

  const artifact = plan.run.evidence_coverage.cells.filter(
    (cell) => cell.lens === 'cloud-and-iac' && cell.evidence_class === 'built-artifact',
  )
  for (const cell of artifact) assert.equal(cell.state, 'COVERED')

  // deployed-state was not supplied and must stay unreached.
  assert.ok(plan.run.evidence_coverage.summary.unreached_classes.includes('deployed-state'))
  assert.equal(
    plan.run.evidence_coverage.summary.unreached_classes.includes('built-artifact'),
    false,
  )
})
```

- [ ] **Step 2: Run the test**

Run: `npm.cmd test -- test/evidence-false-clearance.test.mjs`
Expected: PASS. If the third case fails on `activated_lenses`, check that the fixture repository's `Dockerfile` matches `cloud-and-iac`'s `'**/Dockerfile'` glob — it does at the repository root, verified against `pathActivatorMatches`.

- [ ] **Step 3: Add the new tests to the platform suite**

In `package.json`, append to the `test:platform` script, in the existing order:

```text
test/evidence-classes.test.mjs test/evidence-contracts.test.mjs test/evidence-bundle.test.mjs test/evidence-adapters.test.mjs test/evidence-adapter-conformance.test.mjs test/evidence-class-declarations.test.mjs test/evidence-finding-shape.test.mjs test/evidence-invariant-16.test.mjs test/evidence-coverage.test.mjs test/evidence-report.test.mjs test/evidence-false-clearance.test.mjs
```

- [ ] **Step 4: Run everything**

Run: `npm.cmd test`
Expected: the 2 known ripgrep failures only.

Run: `npm.cmd run test:platform` → PASS
Run: `npm.cmd run lint` → `PASS: R1-R9, SKILL and ledger gate clean.`
Run: `npm.cmd run gen -- --check` → `PASS ... (174 slugs).`

- [ ] **Step 5: Commit**

```bash
git add test/evidence-false-clearance.test.mjs package.json
git commit -m "test: an audit that never opened the image says so, and says it is not a clearance"
```

---

## Decisions this plan makes that the spec left open

1. **`evidence_claim` is a new Stage-1 field.** The spec says `may_conclude`
   "bounds what a finding from that class may assert" and that "a finding
   asserting outside its class's `may_conclude` is malformed", but names no
   field carrying the assertion — so the rule was unenforceable as written.
   Resolved in Task 2: `evidence_claim`, required with `evidence_context`,
   drawn from the six canonical claim kinds Plan 1 declares.

2. **`source` is exempt from `may_conclude`.** Requiring it would mean writing
   a claim vocabulary for all 174 owned topics before anything ships. The
   spec's own example declares `source: {state: consumed}` with no
   `may_conclude`, so this codifies what the spec already shows.

3. **One record, one evidence source.** The spec does not say whether a record
   may cite both a repository file and an evidence locator. It may not:
   `store_context`'s "one record concerns one store" is the same rule for the
   same reason, and a mixed record makes the precedence machinery
   unresolvable — which class is the record resting on?

4. **The four owns-nothing lenses consume `source` only.** The spec permits
   them to declare other classes `consumed` "where they can reason over
   another lens's evidence". They reason over the merged finding set, and a
   finding they originate lands on the owning lens's topic where the owner's
   declaration bounds it. Declaring classes they have no rules for would
   manufacture coverage.

5. **`--evidence-bundle` takes a comma-separated list, not a repeated flag.**
   `audit.mjs`'s `parseArguments` throws on a duplicate option
   (`audit.mjs:245`), so a repeated flag would need a parser change affecting
   every command. One string also stays one immutable value in the plan digest.

## Self-review

**Spec coverage.** `## Components` → `### Consumption` in full: lens frontmatter
migration across all 15 lenses and the linter extension (Task 1), coverage
matrix carried into `report.md` (Tasks 5 and 6), and the `_schema.md` amendment
with `evidence_context`, extended `location`/`existence_check` and invariant 16
(Tasks 2, 3, 4). `## location and existence_check for non-repository evidence`
in full (Tasks 2 and 3). `## Testing` → "The false-clearance regression test"
and "The precedence test" (Tasks 6 and 7). `## Coverage states are reused, not
replaced` (Task 5 — five states, no new ones).

**Deliberately deferred, and why.**

- **The artifact normalizer** is listed under `### Consumption` in the spec but
  belongs with the adapter that produces the layout it normalizes. It is Plan 3,
  Task 2. Nothing in Plan 2 needs it: the coverage matrix reasons about whether
  a bundle of a class exists, not about its contents.
- **SARIF.** The spec says per-class coverage goes into `report.md` *and*
  `results.sarif`. `renderSarif` emits findings, and a coverage cell is not a
  finding; expressing one needs a SARIF `invocation.toolExecutionNotifications`
  decision that is a design question, not a mechanical one. Plan 2 ships the
  Markdown surface, which is what the false-clearance failure mode needs. **This
  is a real, named gap** — it should be a Plan 3 task or its own follow-up, not
  quietly dropped.
- **The evidence-qualified `existence_check` resolver.** Task 3 documents the
  three outcomes; the controller code that resolves a locator inside a bundle
  and verifies quoted bytes needs the normalizer to exist. Plan 3, Task 4.
  Until then an evidence-qualified finding grades `NOT_REPRODUCED` because its
  locator cannot be resolved — which is the correct conservative behaviour and
  not a silent pass.

**Type consistency.** `evidence_context`'s eight fields are identical in
`finding.schema.json`, `evidence-bundle.schema.json`, `_schema.md` and every
test fixture. The coverage-cell key format `lens\0topic\0class` is written once
in `evidenceCoverageIndex` and read once in `evidenceDeclarationErrors`; both
appear in this plan and match. `coverage_state` is the five-value evidence
enum everywhere, never the store profile's three-value one.

**`references/` is dead and Plan 2 correctly skips it.** Verified rather than
assumed: `references/` is named exactly once in the entire repository outside
its own ten files — `test/skill.test.mjs:288`, as a *negative* fixture asserting
that a root entrypoint pointing at `references/web-and-api.md` must fail. No
script, schema, lens, or npm script reads it. The ten files need no
`evidence_classes` block and R9 never sees them, because `runLint` loads lenses
only from `skills/red-team-audit/lenses`.
