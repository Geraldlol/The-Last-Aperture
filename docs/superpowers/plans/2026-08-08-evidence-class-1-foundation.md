# Evidence-Class Foundation Implementation Plan (Plan 1 of 5)

> **Historical implementation plan.** Payload digests in the legacy bundle do
> not authenticate profile semantics, acquisition-plan identity, or a trusted
> signer. Public audit evidence-bundle import is disabled pending a canonical
> controller-signed manifest and atomic single-read verification.
> ADR 0021 supersedes the higher-assurance signed-authority route described
> below. Only an authenticated operator target/scope statement creates
> authority; controller signatures retain technical evidence integrity.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the pure-data evidence-class registry, the validated `evidence-bundle` envelope with a reader/writer that can create, seal, verify and read a bundle, the `_evidence-adapters/contract.md` acquisition contract, and one shared adapter conformance suite — with no adapter, no network, and no change to the audit control plane.

**Architecture:** Four new modules, all offline and all testable against fixtures alone. `evidence-classes.mjs` is frozen data plus predicates (no file I/O, mirroring `registry.mjs`). `evidence-contracts.mjs` owns its own ajv instance and the `evidence-bundle` schema, mirroring `http-recon-contracts.mjs` rather than growing the 4,292-line `contracts.mjs`. `evidence-bundle.mjs` is the filesystem layer: content-addressed payload, sealed manifest, refuse-on-mismatch verification, mirroring `loadDatabaseConformanceEvidence`. `_evidence-adapters/contract.md` plus `manifest.json` is the prose-and-routing pair the `_database-adapters/` directory already establishes, read by `evidence-adapters.mjs` exactly as `database-adapters.mjs` reads its manifest.

**Tech Stack:** Node.js 20+, ESM (`.mjs`), `node:test` + `node:assert/strict`, JSON Schema Draft 2020-12 via ajv 8 (`ajv/dist/2020.js`).

## Global Constraints

- Branch: `agent/red-team-audit-v11-existence` — the current branch, which carries in-flight controller-verified-existence work. `scripts/lib/contracts.mjs` is clean; `scripts/audit.mjs`, `scripts/lib/run-engine.mjs`, `scripts/lib/job-protocol.mjs` and `scripts/lib/existence-matcher.mjs` have uncommitted modifications. **This plan touches none of those four files.**
- Baseline: `cloud-iac-fixtures.test.mjs` has **2 permanently failing tests** on this machine because ripgrep is absent (`rg: command not found`, exit 127). They are environmental. Do not count them as regressions and do not "fix" them.
- `npm.cmd run lint` must stay `PASS: R1-R8, SKILL and ledger gate clean` after every task. Underscore-prefixed files and directories under `lenses/` are skipped by the linter (`lint-lenses.mjs:27`), so `_evidence-adapters/` is invisible to it — that is intended, and Task 4 adds its own gate instead.
- `npm.cmd run gen -- --check` must stay `PASS ... (174 slugs)`.
- Run commands with `npm.cmd`, not `npm` — this is Windows with Git Bash.
- `skills/last-aperture/SKILL.md` is at 7,995 of its 8,000-byte budget. **Add no prose to it.** Everything documentary in this plan goes to `_evidence-adapters/contract.md`.
- Every schema in `schemas/` uses `"additionalProperties": false`. Keep it.
- Ordering must be locale-independent (ADR 0012): use `compareCanonicalStrings` from `scripts/lib/canonical-order.mjs`, never `localeCompare`.
- Do not use `Date.now()` or `new Date()` for anything that lands in a digest. Timestamps are passed in.
- **Naming collision, load-bearing:** `coverage-model.mjs` already exports `COVERAGE_CLASSES` meaning *file* classification (`CANONICAL_SOURCE`/`GENERATED_CODE`/`TEST`/`DOCUMENTATION`/`BINARY`) and every inventory record carries a `coverage_class` field with those values. Evidence classes are a different axis. Every identifier introduced by this plan is prefixed `EVIDENCE_` / `evidence_`. Never write a bare `coverage_class` for an evidence class.
- Two ambiguities in the spec are resolved here rather than deferred; both are recorded in `## Spec amendments` at the end of this plan.

---

### Task 1: The evidence-class registry

**Files:**
- Create: `scripts/lib/evidence-classes.mjs`
- Test: `test/evidence-classes.test.mjs`

**Interfaces:**
- Consumes: nothing.
- Produces, for every later task and every later plan:
  - `EVIDENCE_CLASSES: {SOURCE:'source', BUILT_ARTIFACT:'built-artifact', DEPLOYED_STATE:'deployed-state', LIVE_RUNTIME:'live-runtime'}`
  - `EVIDENCE_CLASS_ORDER: readonly string[]` — ascending precedence
  - `EVIDENCE_ARTIFACT_KINDS`, `EVIDENCE_COVERAGE_STATES`, `EVIDENCE_CLAIM_KINDS: readonly string[]`
  - `isEvidenceClass(value): boolean`
  - `assertEvidenceClass(value): string` — throws `TypeError`
  - `evidenceClassPrecedence(value): 1|2|3|4`
  - `compareEvidenceClassPrecedence(left, right): number`
  - `higherPrecedenceEvidenceClass(left, right): string`
  - `isEvidenceCoverageState(value): boolean`
  - `evidenceCoverageStateClears(state): boolean`
  - `isEvidenceArtifactKind(value): boolean`
  - `isEvidenceClaimKind(value): boolean`
  - `evidenceClassAuthorizationFloor(value): {attestation, credential_ref, target_class, operator_identity, impact_counters, kill_switch}` (all boolean)
  - `normalizeEvidenceId(value): string` — throws `TypeError`

- [ ] **Step 1: Write the failing test**

Create `test/evidence-classes.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  EVIDENCE_ARTIFACT_KINDS,
  EVIDENCE_CLAIM_KINDS,
  EVIDENCE_CLASSES,
  EVIDENCE_CLASS_ORDER,
  EVIDENCE_COVERAGE_STATES,
  assertEvidenceClass,
  compareEvidenceClassPrecedence,
  evidenceClassAuthorizationFloor,
  evidenceClassPrecedence,
  evidenceCoverageStateClears,
  higherPrecedenceEvidenceClass,
  isEvidenceArtifactKind,
  isEvidenceClaimKind,
  isEvidenceClass,
  isEvidenceCoverageState,
  normalizeEvidenceId,
} from '../scripts/lib/evidence-classes.mjs'

test('the four canonical classes are ordered by ascending precedence', () => {
  assert.deepEqual(EVIDENCE_CLASS_ORDER, [
    'source',
    'built-artifact',
    'deployed-state',
    'live-runtime',
  ])
  assert.equal(evidenceClassPrecedence(EVIDENCE_CLASSES.SOURCE), 1)
  assert.equal(evidenceClassPrecedence(EVIDENCE_CLASSES.LIVE_RUNTIME), 4)
})

test('a built artifact outranks the source that claims to produce it', () => {
  assert.ok(compareEvidenceClassPrecedence('source', 'built-artifact') < 0)
  assert.equal(higherPrecedenceEvidenceClass('source', 'built-artifact'), 'built-artifact')
  assert.equal(higherPrecedenceEvidenceClass('live-runtime', 'deployed-state'), 'live-runtime')
  assert.equal(higherPrecedenceEvidenceClass('source', 'source'), 'source')
})

test('an unknown class is rejected rather than defaulted', () => {
  assert.equal(isEvidenceClass('exploitation'), false)
  assert.throws(() => assertEvidenceClass('exploitation'), TypeError)
  assert.throws(() => evidenceClassPrecedence('exploitation'), TypeError)
})

test('the coverage-state vocabulary is the database contract vocabulary, unchanged', () => {
  assert.deepEqual(EVIDENCE_COVERAGE_STATES, [
    'COVERED',
    'PARTIAL',
    'INVENTORY_ONLY',
    'NOT_ASSESSED',
    'NOT_APPLICABLE',
  ])
  assert.ok(isEvidenceCoverageState('INVENTORY_ONLY'))
  assert.equal(isEvidenceCoverageState('ASSESSED'), false)
})

test('INVENTORY_ONLY and NOT_ASSESSED never clear', () => {
  assert.equal(evidenceCoverageStateClears('COVERED'), true)
  assert.equal(evidenceCoverageStateClears('PARTIAL'), true)
  assert.equal(evidenceCoverageStateClears('NOT_APPLICABLE'), true)
  assert.equal(evidenceCoverageStateClears('INVENTORY_ONLY'), false)
  assert.equal(evidenceCoverageStateClears('NOT_ASSESSED'), false)
})

test('artifact kinds and claim kinds are closed canonical sets', () => {
  assert.deepEqual(EVIDENCE_ARTIFACT_KINDS, [
    'apk',
    'dist-bundle',
    'ipa',
    'jar',
    'oci-image',
  ])
  assert.ok(isEvidenceArtifactKind('oci-image'))
  assert.equal(isEvidenceArtifactKind('docker-image'), false)
  assert.deepEqual(EVIDENCE_CLAIM_KINDS, [
    'drift-from-source',
    'runtime-misconfiguration',
    'secret-present-in-artifact',
    'sensitive-data-at-rest',
    'unexpected-artifact-content',
    'vulnerable-component-present',
  ])
  assert.ok(isEvidenceClaimKind('secret-present-in-artifact'))
  assert.equal(isEvidenceClaimKind('looks-bad'), false)
})

test('the authorization floor rises with precedence and no adapter may go below it', () => {
  assert.deepEqual(evidenceClassAuthorizationFloor('source'), {
    attestation: false,
    credential_ref: false,
    target_class: false,
    operator_identity: false,
    impact_counters: false,
    kill_switch: false,
  })
  assert.deepEqual(evidenceClassAuthorizationFloor('built-artifact'), {
    attestation: false,
    credential_ref: false,
    target_class: false,
    operator_identity: false,
    impact_counters: false,
    kill_switch: false,
  })
  assert.deepEqual(evidenceClassAuthorizationFloor('deployed-state'), {
    attestation: true,
    credential_ref: false,
    target_class: true,
    operator_identity: true,
    impact_counters: true,
    kill_switch: true,
  })
  assert.deepEqual(evidenceClassAuthorizationFloor('live-runtime'), {
    attestation: true,
    credential_ref: false,
    target_class: true,
    operator_identity: true,
    impact_counters: true,
    kill_switch: true,
  })
})

test('an evidence id is a stable handle and never carries a hostname', () => {
  assert.equal(normalizeEvidenceId('peerstar-api-image'), 'peerstar-api-image')
  assert.equal(normalizeEvidenceId('  prod-cluster  '), 'prod-cluster')
  assert.throws(() => normalizeEvidenceId('api.peerstar.internal'), TypeError)
  assert.throws(() => normalizeEvidenceId('localhost'), TypeError)
  assert.throws(() => normalizeEvidenceId('10.0.0.4'), TypeError)
  assert.throws(() => normalizeEvidenceId('Peerstar-API'), TypeError)
  assert.throws(() => normalizeEvidenceId('-leading-dash'), TypeError)
  assert.throws(() => normalizeEvidenceId(''), TypeError)
  assert.throws(() => normalizeEvidenceId('a'.repeat(65)), TypeError)
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-classes.test.mjs`
Expected: FAIL — `Cannot find module '.../scripts/lib/evidence-classes.mjs'`

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/evidence-classes.mjs`:

```js
// Canonical evidence classes. This is the detection-precedence rule from
// _database-adapters/contract.md:435-444 promoted from one lens to the
// registry: a built artifact outranks the source that claims to produce it,
// and runtime state outranks both. Pure data plus predicates — no file I/O, so
// the rules stay testable without the corpus.
//
// Not to be confused with coverage-model.mjs's COVERAGE_CLASSES, which
// classifies files in the repository. That is a different axis; everything
// here is prefixed EVIDENCE_.
export const EVIDENCE_CLASSES = Object.freeze({
  SOURCE: 'source',
  BUILT_ARTIFACT: 'built-artifact',
  DEPLOYED_STATE: 'deployed-state',
  LIVE_RUNTIME: 'live-runtime',
})

// Ascending precedence: index + 1 is the rank. Exploitation is deliberately
// absent — it is a mutation tier layered on live-runtime in Phase 3, not a
// class.
export const EVIDENCE_CLASS_ORDER = Object.freeze([
  EVIDENCE_CLASSES.SOURCE,
  EVIDENCE_CLASSES.BUILT_ARTIFACT,
  EVIDENCE_CLASSES.DEPLOYED_STATE,
  EVIDENCE_CLASSES.LIVE_RUNTIME,
])

export const EVIDENCE_ARTIFACT_KINDS = Object.freeze([
  'apk',
  'dist-bundle',
  'ipa',
  'jar',
  'oci-image',
])

// The database contract's coverage vocabulary, verbatim. A parallel state set
// would be the shadow-registry failure _schema.md:107 warns about, and these
// five already carry the never-render-as-clean rule this whole subsystem
// exists to reuse.
export const EVIDENCE_COVERAGE_STATES = Object.freeze([
  'COVERED',
  'PARTIAL',
  'INVENTORY_ONLY',
  'NOT_ASSESSED',
  'NOT_APPLICABLE',
])

const NON_CLEARING_COVERAGE_STATES = new Set(['INVENTORY_ONLY', 'NOT_ASSESSED'])

// What a finding derived from a non-source class is permitted to assert. A
// lens bounds itself to a subset of these in activates_on.evidence_classes;
// an unbounded vocabulary would let every lens claim every class.
export const EVIDENCE_CLAIM_KINDS = Object.freeze([
  'drift-from-source',
  'runtime-misconfiguration',
  'secret-present-in-artifact',
  'sensitive-data-at-rest',
  'unexpected-artifact-content',
  'vulnerable-component-present',
])

// The floor, not the requirement. An adapter declares its own requirements in
// manifest.json and may exceed these; it may never fall below them. Reading a
// supplied tarball needs no attestation, so built-artifact's floor is empty
// and the registry adapter raises its own bar in Plan 4.
const AUTHORIZATION_FLOOR = Object.freeze({
  [EVIDENCE_CLASSES.SOURCE]: Object.freeze({
    attestation: false,
    credential_ref: false,
    target_class: false,
    operator_identity: false,
    impact_counters: false,
    kill_switch: false,
  }),
  [EVIDENCE_CLASSES.BUILT_ARTIFACT]: Object.freeze({
    attestation: false,
    credential_ref: false,
    target_class: false,
    operator_identity: false,
    impact_counters: false,
    kill_switch: false,
  }),
  // An unbounded read against production is an availability risk regardless of
  // intent, so counters and a kill switch are floors for both live classes
  // even though both are read-only.
  [EVIDENCE_CLASSES.DEPLOYED_STATE]: Object.freeze({
    attestation: true,
    credential_ref: false,
    target_class: true,
    operator_identity: true,
    impact_counters: true,
    kill_switch: true,
  }),
  [EVIDENCE_CLASSES.LIVE_RUNTIME]: Object.freeze({
    attestation: true,
    credential_ref: false,
    target_class: true,
    operator_identity: true,
    impact_counters: true,
    kill_switch: true,
  }),
})

const EVIDENCE_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,63}$/
// store_id may not carry a hostname (contract.md:163-164) and neither may an
// evidence id: a handle that names where the evidence came from leaks target
// topology into every finding that references it. Dots are already excluded by
// the pattern, so only the dotless host-shaped names need naming here.
const HOST_SHAPED_EVIDENCE_IDS = new Set([
  'host',
  'hostname',
  'localhost',
  'localdomain',
])

export function isEvidenceClass(value) {
  return EVIDENCE_CLASS_ORDER.includes(value)
}

export function assertEvidenceClass(value) {
  if (!isEvidenceClass(value)) {
    throw new TypeError(
      `unknown evidence class ${JSON.stringify(value)}; expected one of `
      + EVIDENCE_CLASS_ORDER.join(', '),
    )
  }
  return value
}

export function evidenceClassPrecedence(value) {
  return EVIDENCE_CLASS_ORDER.indexOf(assertEvidenceClass(value)) + 1
}

export function compareEvidenceClassPrecedence(left, right) {
  return evidenceClassPrecedence(left) - evidenceClassPrecedence(right)
}

export function higherPrecedenceEvidenceClass(left, right) {
  return compareEvidenceClassPrecedence(left, right) >= 0 ? left : right
}

export function isEvidenceCoverageState(value) {
  return EVIDENCE_COVERAGE_STATES.includes(value)
}

export function evidenceCoverageStateClears(state) {
  if (!isEvidenceCoverageState(state)) {
    throw new TypeError(`unknown evidence coverage state ${JSON.stringify(state)}`)
  }
  return !NON_CLEARING_COVERAGE_STATES.has(state)
}

export function isEvidenceArtifactKind(value) {
  return EVIDENCE_ARTIFACT_KINDS.includes(value)
}

export function isEvidenceClaimKind(value) {
  return EVIDENCE_CLAIM_KINDS.includes(value)
}

export function evidenceClassAuthorizationFloor(value) {
  return AUTHORIZATION_FLOOR[assertEvidenceClass(value)]
}

export function normalizeEvidenceId(value) {
  if (typeof value !== 'string') {
    throw new TypeError('evidence_id must be a string')
  }
  const normalized = value.trim()
  if (!EVIDENCE_ID_PATTERN.test(normalized)) {
    throw new TypeError(
      'evidence_id must be 1-64 lowercase ASCII characters, digits or hyphens, '
      + `starting with a letter or digit; received ${JSON.stringify(value)}`,
    )
  }
  if (HOST_SHAPED_EVIDENCE_IDS.has(normalized) || /^\d+(?:-\d+){3}$/.test(normalized)) {
    throw new TypeError(`evidence_id must not name a host: ${JSON.stringify(value)}`)
  }
  return normalized
}
```

Note on the IP case: `10.0.0.4` fails `EVIDENCE_ID_PATTERN` already (dots are not allowed), so the test's `normalizeEvidenceId('10.0.0.4')` throws on the pattern branch. The `^\d+(-\d+){3}$` guard catches the hyphenated `10-0-0-4` spelling, which the pattern would otherwise accept.

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm.cmd test -- test/evidence-classes.test.mjs`
Expected: PASS, 7 tests

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/evidence-classes.mjs test/evidence-classes.test.mjs
git commit -m "feat: canonical evidence-class registry with precedence and authorization floors"
```

---

### Task 2: The `evidence-bundle` schema and its validator

**Files:**
- Create: `schemas/evidence-bundle.schema.json`
- Create: `scripts/lib/evidence-contracts.mjs`
- Test: `test/evidence-contracts.test.mjs`

**Interfaces:**
- Consumes: `EVIDENCE_CLASS_ORDER`, `EVIDENCE_COVERAGE_STATES`, `EVIDENCE_ARTIFACT_KINDS` from Task 1 (used to assert the schema's enums have not drifted from the registry).
- Produces:
  - `evidenceBundleSchema: object`
  - `validateEvidenceProfile(profile): {valid: boolean, errors: Array<{code, instancePath, message}>}`
  - `assertValidEvidenceProfile(profile): profile` — throws `EvidenceContractValidationError`
  - `EvidenceContractValidationError extends Error`
  - `EVIDENCE_BUNDLE_SCHEMA_VERSION = 'evidence-bundle-v1'`
  - `EVIDENCE_CONTRACT_VERSION = 1`

Why its own module rather than `contracts.mjs`: `http-recon-contracts.mjs` already establishes one ajv instance per control plane, and `contracts.mjs` is 4,292 lines carrying the repository plane's finding contract. Acquisition is a different plane and gets its own file.

- [ ] **Step 1: Write the failing test**

Create `test/evidence-contracts.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  EVIDENCE_BUNDLE_SCHEMA_VERSION,
  EVIDENCE_CONTRACT_VERSION,
  EvidenceContractValidationError,
  assertValidEvidenceProfile,
  evidenceBundleSchema,
  validateEvidenceProfile,
} from '../scripts/lib/evidence-contracts.mjs'
import {
  EVIDENCE_ARTIFACT_KINDS,
  EVIDENCE_CLASS_ORDER,
  EVIDENCE_COVERAGE_STATES,
} from '../scripts/lib/evidence-classes.mjs'

function profile(overrides = {}) {
  return {
    schema: EVIDENCE_BUNDLE_SCHEMA_VERSION,
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
    target_class: 'LAB',
    phi_scope: 'none',
    phi_bearing: false,
    adapter_version: '1.0.0',
    contract_version: EVIDENCE_CONTRACT_VERSION,
    coverage_state: 'COVERED',
    artifact_kind: 'oci-image',
    files: [
      {
        path: 'payload/layers/02/entries.json',
        sha256: '6c1f0a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f',
        size: 4096,
      },
    ],
    attestation: null,
    coverage_gaps: [],
    ...overrides,
  }
}

test('the reference profile validates', () => {
  const validation = validateEvidenceProfile(profile())
  assert.deepEqual(validation.errors, [])
  assert.equal(validation.valid, true)
})

test('the schema enums are the registry enums, not a private copy', () => {
  const context = evidenceBundleSchema.$defs.evidenceContext.properties
  assert.deepEqual(context.evidence_class.enum, [...EVIDENCE_CLASS_ORDER])
  assert.deepEqual(
    evidenceBundleSchema.properties.coverage_state.enum,
    [...EVIDENCE_COVERAGE_STATES],
  )
  assert.deepEqual(
    evidenceBundleSchema.properties.artifact_kind.enum,
    [...EVIDENCE_ARTIFACT_KINDS],
  )
})

test('every evidence_context field is required', () => {
  for (const field of [
    'evidence_id',
    'evidence_class',
    'adapter_id',
    'target_identity',
    'acquisition_mode',
    'acquired_on',
    'detection_evidence',
    'confidence',
  ]) {
    const candidate = profile()
    delete candidate.evidence_context[field]
    assert.equal(
      validateEvidenceProfile(candidate).valid,
      false,
      `${field} must be required`,
    )
  }
})

test('an unknown property is rejected rather than carried', () => {
  assert.equal(validateEvidenceProfile(profile({ notes: 'extra' })).valid, false)
  const candidate = profile()
  candidate.evidence_context.hostname = 'api.internal'
  assert.equal(validateEvidenceProfile(candidate).valid, false)
})

test('COVERED with an empty payload is rejected by the contract itself', () => {
  const validation = validateEvidenceProfile(profile({ files: [] }))
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((error) => error.code === 'EMPTY_COVERED_PAYLOAD'))
})

test('a non-clearing coverage state requires a named gap', () => {
  const validation = validateEvidenceProfile(
    profile({ coverage_state: 'NOT_ASSESSED', files: [], coverage_gaps: [] }),
  )
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((error) => error.code === 'UNNAMED_COVERAGE_GAP'))

  const named = validateEvidenceProfile(profile({
    coverage_state: 'NOT_ASSESSED',
    files: [],
    coverage_gaps: [{ area: 'registry', reason: 'crane is not installed on PATH' }],
  }))
  assert.deepEqual(named.errors, [])
})

test('artifact_kind is required for built-artifact and forbidden elsewhere', () => {
  const missing = profile()
  delete missing.artifact_kind
  assert.ok(
    validateEvidenceProfile(missing).errors
      .some((error) => error.code === 'ARTIFACT_KIND_REQUIRED'),
  )

  const context = { ...profile().evidence_context, evidence_class: 'deployed-state', adapter_id: 'deployed' }
  assert.ok(
    validateEvidenceProfile(profile({ evidence_context: context })).errors
      .some((error) => error.code === 'ARTIFACT_KIND_NOT_APPLICABLE'),
  )
})

test('a credential value anywhere in the profile is refused', () => {
  const candidate = profile()
  candidate.evidence_context.detection_evidence = [
    'docker login -u ci -p hunter2 registry.internal',
  ]
  const validation = validateEvidenceProfile(candidate)
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((error) => error.code === 'CREDENTIAL_VALUE_PRESENT'))
})

test('phi_bearing content requires a declared phi scope that permits it', () => {
  const validation = validateEvidenceProfile(
    profile({ phi_scope: 'none', phi_bearing: true }),
  )
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some((error) => error.code === 'PHI_SCOPE_CONTRADICTION'))
})

test('assertValidEvidenceProfile throws with the failing pointers attached', () => {
  assert.throws(
    () => assertValidEvidenceProfile(profile({ files: [] })),
    (error) => error instanceof EvidenceContractValidationError
      && error.errors.some((detail) => detail.code === 'EMPTY_COVERED_PAYLOAD'),
  )
  assert.equal(assertValidEvidenceProfile(profile()).phi_bearing, false)
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-contracts.test.mjs`
Expected: FAIL — `Cannot find module '.../scripts/lib/evidence-contracts.mjs'`

- [ ] **Step 3: Write the schema**

Create `schemas/evidence-bundle.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://red-team-audit.dev/schemas/evidence-bundle.schema.json",
  "title": "Evidence acquisition bundle profile",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema",
    "evidence_context",
    "target_class",
    "phi_scope",
    "phi_bearing",
    "adapter_version",
    "contract_version",
    "coverage_state",
    "files",
    "attestation",
    "coverage_gaps"
  ],
  "properties": {
    "schema": { "const": "evidence-bundle-v1" },
    "evidence_context": { "$ref": "#/$defs/evidenceContext" },
    "target_class": { "enum": ["LAB", "NONPROD", "PRODUCTION", "THIRD_PARTY"] },
    "phi_scope": { "enum": ["none", "possible", "confirmed"] },
    "phi_bearing": { "type": "boolean" },
    "adapter_version": { "type": "string", "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$" },
    "contract_version": { "type": "integer", "minimum": 1 },
    "coverage_state": {
      "enum": ["COVERED", "PARTIAL", "INVENTORY_ONLY", "NOT_ASSESSED", "NOT_APPLICABLE"]
    },
    "artifact_kind": {
      "enum": ["apk", "dist-bundle", "ipa", "jar", "oci-image"]
    },
    "files": {
      "type": "array",
      "maxItems": 65536,
      "items": { "$ref": "#/$defs/bundleFile" }
    },
    "attestation": {
      "oneOf": [{ "type": "null" }, { "$ref": "#/$defs/attestation" }]
    },
    "coverage_gaps": {
      "type": "array",
      "maxItems": 1024,
      "items": { "$ref": "#/$defs/coverageGap" }
    }
  },
  "$defs": {
    "nonEmptyString": { "type": "string", "minLength": 1, "maxLength": 4096 },
    "sha256": { "type": "string", "pattern": "^[0-9a-f]{64}$" },
    "evidenceId": {
      "type": "string",
      "pattern": "^[a-z0-9][a-z0-9-]{0,63}$"
    },
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
        "evidence_id": { "$ref": "#/$defs/evidenceId" },
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
    "bundleFile": {
      "type": "object",
      "additionalProperties": false,
      "required": ["path", "sha256", "size"],
      "properties": {
        "path": {
          "type": "string",
          "pattern": "^payload/(?!.*(?:^|/)\\.\\.(?:/|$))[^\\\\]+$",
          "maxLength": 1024
        },
        "sha256": { "$ref": "#/$defs/sha256" },
        "size": { "type": "integer", "minimum": 0 }
      }
    },
    "attestation": {
      "type": "object",
      "additionalProperties": false,
      "required": ["operator_id", "authorized_by", "authorization_reference", "attested_on"],
      "properties": {
        "operator_id": { "$ref": "#/$defs/nonEmptyString" },
        "authorized_by": { "$ref": "#/$defs/nonEmptyString" },
        "authorization_reference": { "$ref": "#/$defs/nonEmptyString" },
        "attested_on": {
          "type": "string",
          "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
        },
        "credential_ref": { "$ref": "#/$defs/nonEmptyString" }
      }
    },
    "coverageGap": {
      "type": "object",
      "additionalProperties": false,
      "required": ["area", "reason"],
      "properties": {
        "area": { "$ref": "#/$defs/nonEmptyString" },
        "reason": { "$ref": "#/$defs/nonEmptyString" }
      }
    }
  }
}
```

- [ ] **Step 4: Write the validator**

Create `scripts/lib/evidence-contracts.mjs`:

```js
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import {
  EVIDENCE_ARTIFACT_KINDS,
  EVIDENCE_CLASSES,
  EVIDENCE_CLASS_ORDER,
  EVIDENCE_COVERAGE_STATES,
  evidenceCoverageStateClears,
  normalizeEvidenceId,
} from './evidence-classes.mjs'

const EVIDENCE_BUNDLE_SCHEMA_URL = new URL(
  '../../schemas/evidence-bundle.schema.json',
  import.meta.url,
)

export const EVIDENCE_BUNDLE_SCHEMA_VERSION = 'evidence-bundle-v1'
export const EVIDENCE_CONTRACT_VERSION = 1

export const evidenceBundleSchema = JSON.parse(
  readFileSync(fileURLToPath(EVIDENCE_BUNDLE_SCHEMA_URL), 'utf8'),
)

// One ajv instance per control plane, as http-recon-contracts.mjs does. The
// repository plane's contracts.mjs stays untouched.
const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
const validateSchema = ajv.compile(evidenceBundleSchema)

// The schema is data and the registry is code; a drift between them would let
// a bundle declare a class no lens can consume. Fail at import, not at audit.
function assertEnumParity(actual, expected, label) {
  if (JSON.stringify(actual) !== JSON.stringify([...expected])) {
    throw new Error(
      `evidence-bundle.schema.json ${label} has drifted from evidence-classes.mjs`,
    )
  }
}
assertEnumParity(
  evidenceBundleSchema.$defs.evidenceContext.properties.evidence_class.enum,
  EVIDENCE_CLASS_ORDER,
  'evidence_class',
)
assertEnumParity(
  evidenceBundleSchema.properties.coverage_state.enum,
  EVIDENCE_COVERAGE_STATES,
  'coverage_state',
)
assertEnumParity(
  evidenceBundleSchema.properties.artifact_kind.enum,
  EVIDENCE_ARTIFACT_KINDS,
  'artifact_kind',
)

function addError(errors, code, instancePath, message) {
  errors.push({ code, instancePath, message })
}

function normalizeAjvErrors(ajvErrors) {
  return (ajvErrors ?? []).map((error) => ({
    code: `SCHEMA_${String(error.keyword).toUpperCase()}`,
    instancePath: error.instancePath || '',
    message: error.message ?? 'schema validation failed',
  }))
}

// Credential values never enter a bundle; only a credential_ref does
// (contract.md:48). The check is coarse on purpose — a false positive costs an
// operator one rename, a false negative writes a secret to disk.
const CREDENTIAL_VALUE_PATTERNS = [
  /(?:^|[\s"'`])-{1,2}p(?:assword)?[=\s]\S/i,
  /\b(?:password|passwd|secret|token|api[_-]?key|bearer)\s*[:=]\s*\S/i,
  /\b[a-z]+:\/\/[^/\s:@]+:[^/\s@]+@/i,
  /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/,
]

function scanForCredentialValues(value, pointer, errors) {
  if (typeof value === 'string') {
    if (CREDENTIAL_VALUE_PATTERNS.some((pattern) => pattern.test(value))) {
      addError(
        errors,
        'CREDENTIAL_VALUE_PRESENT',
        pointer,
        'a bundle carries a credential reference, never a credential value',
      )
    }
    return
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) => scanForCredentialValues(item, `${pointer}/${index}`, errors))
    return
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value)) {
      scanForCredentialValues(item, `${pointer}/${key}`, errors)
    }
  }
}

function profileInvariantErrors(profile) {
  const errors = []
  if (profile === null || typeof profile !== 'object' || Array.isArray(profile)) {
    return errors
  }

  try {
    normalizeEvidenceId(profile.evidence_context?.evidence_id)
  } catch (error) {
    addError(errors, 'EVIDENCE_ID_INVALID', '/evidence_context/evidence_id', error.message)
  }

  const state = profile.coverage_state
  const files = Array.isArray(profile.files) ? profile.files : []
  const gaps = Array.isArray(profile.coverage_gaps) ? profile.coverage_gaps : []

  // No adapter may report COVERED with an empty payload. A missing dependency
  // is a failure, never an empty success.
  if (state === 'COVERED' && files.length === 0) {
    addError(
      errors,
      'EMPTY_COVERED_PAYLOAD',
      '/files',
      'COVERED requires at least one acquired file; an empty payload is NOT_ASSESSED',
    )
  }
  if (
    typeof state === 'string'
    && EVIDENCE_COVERAGE_STATES.includes(state)
    && !evidenceCoverageStateClears(state)
    && gaps.length === 0
  ) {
    addError(
      errors,
      'UNNAMED_COVERAGE_GAP',
      '/coverage_gaps',
      `${state} requires a named reason in coverage_gaps`,
    )
  }
  if (state === 'PARTIAL' && gaps.length === 0) {
    addError(
      errors,
      'UNNAMED_COVERAGE_GAP',
      '/coverage_gaps',
      'PARTIAL requires the omissions to be listed in coverage_gaps',
    )
  }

  const evidenceClass = profile.evidence_context?.evidence_class
  const hasArtifactKind = Object.hasOwn(profile, 'artifact_kind')
  if (evidenceClass === EVIDENCE_CLASSES.BUILT_ARTIFACT && !hasArtifactKind) {
    addError(
      errors,
      'ARTIFACT_KIND_REQUIRED',
      '/artifact_kind',
      'a built-artifact bundle names the artifact kind it carries',
    )
  }
  if (evidenceClass !== EVIDENCE_CLASSES.BUILT_ARTIFACT && hasArtifactKind) {
    addError(
      errors,
      'ARTIFACT_KIND_NOT_APPLICABLE',
      '/artifact_kind',
      `artifact_kind is meaningless for evidence class ${String(evidenceClass)}`,
    )
  }

  if (profile.phi_bearing === true && profile.phi_scope === 'none') {
    addError(
      errors,
      'PHI_SCOPE_CONTRADICTION',
      '/phi_bearing',
      'phi_bearing content cannot be captured under an attested phi_scope of none',
    )
  }

  const paths = new Set()
  for (const [index, file] of files.entries()) {
    if (paths.has(file?.path)) {
      addError(
        errors,
        'DUPLICATE_BUNDLE_PATH',
        `/files/${index}/path`,
        `bundle payload contains duplicate path: ${String(file?.path)}`,
      )
    }
    paths.add(file?.path)
  }

  scanForCredentialValues(profile, '', errors)
  return errors
}

export function validateEvidenceProfile(profile) {
  const schemaValid = validateSchema(profile)
  const errors = schemaValid ? [] : normalizeAjvErrors(validateSchema.errors)
  errors.push(...profileInvariantErrors(profile))
  return { valid: errors.length === 0, errors }
}

export class EvidenceContractValidationError extends Error {
  constructor(message, errors) {
    const detail = errors
      .map((error) => `${error.instancePath || '/'} [${error.code}]: ${error.message}`)
      .join('\n')
    super(detail ? `${message}\n${detail}` : message)
    this.name = 'EvidenceContractValidationError'
    this.errors = errors
  }
}

export function assertValidEvidenceProfile(profile) {
  const validation = validateEvidenceProfile(profile)
  if (!validation.valid) {
    throw new EvidenceContractValidationError(
      'Evidence bundle contract validation failed',
      validation.errors,
    )
  }
  return profile
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npm.cmd test -- test/evidence-contracts.test.mjs`
Expected: PASS, 10 tests

- [ ] **Step 6: Commit**

```bash
git add schemas/evidence-bundle.schema.json scripts/lib/evidence-contracts.mjs test/evidence-contracts.test.mjs
git commit -m "feat: evidence-bundle profile schema with fail-closed acquisition invariants"
```

---

### Task 3: Bundle reader, writer, sealer and verifier

**Files:**
- Create: `scripts/lib/evidence-bundle.mjs`
- Test: `test/evidence-bundle.test.mjs`

**Interfaces:**
- Consumes: `assertValidEvidenceProfile`, `EVIDENCE_BUNDLE_SCHEMA_VERSION` (Task 2); `normalizeEvidenceId` (Task 1).
- Produces:
  - `writeEvidenceBundle({directory, profile, payload}): Promise<{directory, root_sha256, profile}>` where `payload` is `Array<{path: string, bytes: Buffer}>` with `path` relative to `payload/`
  - `readEvidenceBundle(directory): Promise<{directory, profile, evidence_context, root_sha256}>`
  - `verifyEvidenceBundle(directory): Promise<{valid: boolean, root_sha256: string|null, errors: Array<{code, message}>}>`
  - `loadEvidenceBundle(argument): Promise<{directory, profile, evidence_context, root_sha256}>` — throws `EvidenceBundleError` on any integrity failure. **This is the function `audit -- plan` calls in Plan 2.**
  - `readEvidencePayloadFile(directory, payloadPath): Promise<Buffer>`
  - `evidenceBundleRootDigest(files): string`
  - `EvidenceBundleError extends Error` carrying `code` and `bundle`
  - `EVIDENCE_MANIFEST_FILE = 'manifest.json'`

Bundle layout on disk:

```text
<bundle>/
  manifest.json      # { profile: <evidence_profile>, root_sha256: <hex> }
  payload/…          # every file listed in profile.files, path relative to <bundle>
```

- [ ] **Step 1: Write the failing test**

Create `test/evidence-bundle.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  EvidenceBundleError,
  evidenceBundleRootDigest,
  loadEvidenceBundle,
  readEvidenceBundle,
  readEvidencePayloadFile,
  verifyEvidenceBundle,
  writeEvidenceBundle,
} from '../scripts/lib/evidence-bundle.mjs'

const PAYLOAD = [
  { path: 'layers/02/entries.json', bytes: Buffer.from('[{"name":"var/lib/db"}]', 'utf8') },
  { path: 'config/history.json', bytes: Buffer.from('["RUN rm /secret.txt"]', 'utf8') },
]

function baseProfile() {
  return {
    schema: 'evidence-bundle-v1',
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
    target_class: 'LAB',
    phi_scope: 'none',
    phi_bearing: false,
    adapter_version: '1.0.0',
    contract_version: 1,
    coverage_state: 'COVERED',
    artifact_kind: 'oci-image',
    attestation: null,
    coverage_gaps: [],
  }
}

async function sealedBundle() {
  const directory = join(await mkdtemp(join(tmpdir(), 'rta-evidence-')), 'ev')
  const written = await writeEvidenceBundle({
    directory,
    profile: baseProfile(),
    payload: PAYLOAD,
  })
  return { directory, written }
}

test('writing a bundle content-addresses every payload file', async () => {
  const { directory, written } = await sealedBundle()
  assert.equal(written.directory, directory)
  assert.match(written.root_sha256, /^[0-9a-f]{64}$/)
  assert.deepEqual(
    written.profile.files.map(({ path }) => path),
    ['payload/config/history.json', 'payload/layers/02/entries.json'],
  )
  for (const file of written.profile.files) {
    assert.match(file.sha256, /^[0-9a-f]{64}$/)
    assert.ok(file.size > 0)
  }
})

test('the root digest depends only on path, hash and size, in canonical order', () => {
  const files = [
    { path: 'payload/b.json', sha256: 'b'.repeat(64), size: 2 },
    { path: 'payload/a.json', sha256: 'a'.repeat(64), size: 1 },
  ]
  assert.equal(
    evidenceBundleRootDigest(files),
    evidenceBundleRootDigest([...files].reverse()),
  )
  assert.notEqual(
    evidenceBundleRootDigest(files),
    evidenceBundleRootDigest([{ ...files[0], size: 3 }, files[1]]),
  )
})

test('a sealed bundle round-trips through read and verify', async () => {
  const { directory, written } = await sealedBundle()
  const read = await readEvidenceBundle(directory)
  assert.equal(read.root_sha256, written.root_sha256)
  assert.equal(read.evidence_context.evidence_id, 'peerstar-api-image')
  assert.equal(read.evidence_context.evidence_class, 'built-artifact')

  const verification = await verifyEvidenceBundle(directory)
  assert.deepEqual(verification.errors, [])
  assert.equal(verification.valid, true)

  const bytes = await readEvidencePayloadFile(directory, 'payload/config/history.json')
  assert.equal(bytes.toString('utf8'), '["RUN rm /secret.txt"]')
})

test('one mutated payload byte fails verification and refuses to load', async () => {
  const { directory } = await sealedBundle()
  await writeFile(join(directory, 'payload', 'config', 'history.json'), '["RUN rm /secreT.txt"]')

  const verification = await verifyEvidenceBundle(directory)
  assert.equal(verification.valid, false)
  assert.ok(verification.errors.some((error) => error.code === 'PAYLOAD_DIGEST_MISMATCH'))

  await assert.rejects(
    () => loadEvidenceBundle(directory),
    (error) => error instanceof EvidenceBundleError
      && error.code === 'EVIDENCE_BUNDLE_INVALID',
  )
})

test('a tampered manifest root digest is refused', async () => {
  const { directory } = await sealedBundle()
  const manifestPath = join(directory, 'manifest.json')
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  manifest.root_sha256 = '0'.repeat(64)
  await writeFile(manifestPath, JSON.stringify(manifest))

  const verification = await verifyEvidenceBundle(directory)
  assert.ok(verification.errors.some((error) => error.code === 'ROOT_DIGEST_MISMATCH'))
  await assert.rejects(() => loadEvidenceBundle(directory), EvidenceBundleError)
})

test('a payload file listed in the manifest but absent on disk is refused', async () => {
  const { directory } = await sealedBundle()
  const manifestPath = join(directory, 'manifest.json')
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  manifest.profile.files.push({
    path: 'payload/ghost.json',
    sha256: 'c'.repeat(64),
    size: 3,
  })
  manifest.root_sha256 = evidenceBundleRootDigest(manifest.profile.files)
  await writeFile(manifestPath, JSON.stringify(manifest))

  const verification = await verifyEvidenceBundle(directory)
  assert.ok(verification.errors.some((error) => error.code === 'PAYLOAD_FILE_MISSING'))
})

test('a payload file on disk that the manifest never listed is refused', async () => {
  const { directory } = await sealedBundle()
  await writeFile(join(directory, 'payload', 'smuggled.json'), '{}')
  const verification = await verifyEvidenceBundle(directory)
  assert.ok(verification.errors.some((error) => error.code === 'UNDECLARED_PAYLOAD_FILE'))
})

test('a payload path escaping the bundle is refused at write time', async () => {
  const directory = join(await mkdtemp(join(tmpdir(), 'rta-evidence-')), 'ev')
  await assert.rejects(
    () => writeEvidenceBundle({
      directory,
      profile: baseProfile(),
      payload: [{ path: '../escape.json', bytes: Buffer.from('{}') }],
    }),
    EvidenceBundleError,
  )
})

test('loadEvidenceBundle returns the immutable routing projection', async () => {
  const { directory, written } = await sealedBundle()
  const loaded = await loadEvidenceBundle(directory)
  assert.equal(loaded.root_sha256, written.root_sha256)
  assert.deepEqual(Object.keys(loaded.evidence_context).sort(), [
    'acquired_on',
    'acquisition_mode',
    'adapter_id',
    'confidence',
    'detection_evidence',
    'evidence_class',
    'evidence_id',
    'target_identity',
  ])
  assert.throws(() => {
    loaded.evidence_context.evidence_id = 'mutated'
  }, TypeError)
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-bundle.test.mjs`
Expected: FAIL — `Cannot find module '.../scripts/lib/evidence-bundle.mjs'`

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/evidence-bundle.mjs`:

```js
import { createHash } from 'node:crypto'
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { assertValidEvidenceProfile, validateEvidenceProfile } from './evidence-contracts.mjs'

export const EVIDENCE_MANIFEST_FILE = 'manifest.json'
const PAYLOAD_DIRECTORY = 'payload'
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024

export class EvidenceBundleError extends Error {
  constructor(code, message, { bundle, details } = {}) {
    super(message)
    this.name = 'EvidenceBundleError'
    this.code = code
    this.bundle = bundle
    this.details = details ?? []
  }
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function canonicalPayloadPath(value) {
  const normalized = String(value).replaceAll('\\', '/').replace(/^(?:\.\/)+/, '')
  const segments = normalized.split('/')
  if (
    normalized === ''
    || normalized.startsWith('/')
    || /^[A-Za-z]:/.test(normalized)
    || segments.some((segment) => segment === '' || segment === '.' || segment === '..')
  ) {
    throw new EvidenceBundleError(
      'EVIDENCE_PAYLOAD_PATH_INVALID',
      `payload path must stay inside the bundle: ${String(value)}`,
    )
  }
  return normalized
}

/**
 * The bundle's root digest. Content-addressed over exactly the three facts a
 * later reader can re-derive from disk, so re-verification months later is
 * exact rather than approximate.
 */
export function evidenceBundleRootDigest(files) {
  const material = [...files]
    .map(({ path, sha256: digest, size }) => [path, digest, size])
    .sort((left, right) => compareCanonicalStrings(left[0], right[0]))
  return sha256(JSON.stringify(material))
}

export async function writeEvidenceBundle({ directory, profile, payload = [] }) {
  const root = resolve(directory)
  const entries = payload.map(({ path, bytes }) => {
    const relativePath = canonicalPayloadPath(path)
    const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes), 'utf8')
    return {
      relativePath,
      buffer,
      file: {
        path: `${PAYLOAD_DIRECTORY}/${relativePath}`,
        sha256: sha256(buffer),
        size: buffer.length,
      },
    }
  })
  entries.sort((left, right) =>
    compareCanonicalStrings(left.file.path, right.file.path))

  const sealed = assertValidEvidenceProfile({
    ...profile,
    files: entries.map(({ file }) => file),
  })
  const rootDigest = evidenceBundleRootDigest(sealed.files)

  await mkdir(root, { recursive: true })
  for (const entry of entries) {
    const target = join(root, PAYLOAD_DIRECTORY, ...entry.relativePath.split('/'))
    await mkdir(dirname(target), { recursive: true })
    await writeFile(target, entry.buffer)
  }
  await writeFile(
    join(root, EVIDENCE_MANIFEST_FILE),
    `${JSON.stringify({ profile: sealed, root_sha256: rootDigest }, null, 2)}\n`,
    'utf8',
  )
  return { directory: root, root_sha256: rootDigest, profile: sealed }
}

async function readManifest(root) {
  const manifestPath = join(root, EVIDENCE_MANIFEST_FILE)
  let text
  try {
    text = await readFile(manifestPath, 'utf8')
  } catch {
    throw new EvidenceBundleError(
      'EVIDENCE_BUNDLE_MANIFEST_UNREADABLE',
      `evidence bundle manifest not found: ${manifestPath}`,
      { bundle: root },
    )
  }
  if (Buffer.byteLength(text, 'utf8') > MAX_MANIFEST_BYTES) {
    throw new EvidenceBundleError(
      'EVIDENCE_BUNDLE_MANIFEST_TOO_LARGE',
      `evidence bundle manifest exceeds ${MAX_MANIFEST_BYTES} bytes`,
      { bundle: root },
    )
  }
  try {
    return JSON.parse(text)
  } catch (error) {
    throw new EvidenceBundleError(
      'EVIDENCE_BUNDLE_MANIFEST_UNPARSEABLE',
      `evidence bundle manifest is not JSON: ${error.message}`,
      { bundle: root },
    )
  }
}

async function listPayloadFiles(root) {
  const payloadRoot = join(root, PAYLOAD_DIRECTORY)
  const found = []
  async function visit(directory) {
    let dirEntries
    try {
      dirEntries = await readdir(directory, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of dirEntries) {
      const path = join(directory, entry.name)
      if (entry.isSymbolicLink()) {
        throw new EvidenceBundleError(
          'EVIDENCE_BUNDLE_SYMLINK',
          `an evidence bundle cannot contain a symlink: ${path}`,
          { bundle: root },
        )
      }
      if (entry.isDirectory()) await visit(path)
      else if (entry.isFile()) {
        found.push(`${PAYLOAD_DIRECTORY}/${relative(payloadRoot, path).split(sep).join('/')}`)
      }
    }
  }
  await visit(payloadRoot)
  return found.sort(compareCanonicalStrings)
}

export async function verifyEvidenceBundle(directory) {
  const root = resolve(directory)
  const errors = []
  let manifest
  try {
    manifest = await readManifest(root)
  } catch (error) {
    return { valid: false, root_sha256: null, errors: [{ code: error.code, message: error.message }] }
  }

  const profileValidation = validateEvidenceProfile(manifest?.profile)
  for (const error of profileValidation.errors) {
    errors.push({ code: error.code, message: `${error.instancePath || '/'} ${error.message}` })
  }
  const files = Array.isArray(manifest?.profile?.files) ? manifest.profile.files : []
  const expectedRoot = evidenceBundleRootDigest(files)
  if (manifest?.root_sha256 !== expectedRoot) {
    errors.push({
      code: 'ROOT_DIGEST_MISMATCH',
      message: `manifest root digest ${String(manifest?.root_sha256)} does not cover its own file list`,
    })
  }

  const declared = new Set(files.map(({ path }) => path))
  for (const file of files) {
    let bytes
    try {
      bytes = await readFile(join(root, ...String(file.path).split('/')))
    } catch {
      errors.push({ code: 'PAYLOAD_FILE_MISSING', message: `declared payload file is absent: ${file.path}` })
      continue
    }
    if (sha256(bytes) !== file.sha256 || bytes.length !== file.size) {
      errors.push({
        code: 'PAYLOAD_DIGEST_MISMATCH',
        message: `payload file does not match its declared digest: ${file.path}`,
      })
    }
  }

  try {
    for (const path of await listPayloadFiles(root)) {
      if (!declared.has(path)) {
        errors.push({
          code: 'UNDECLARED_PAYLOAD_FILE',
          message: `payload file is present but not declared in the manifest: ${path}`,
        })
      }
    }
  } catch (error) {
    errors.push({ code: error.code, message: error.message })
  }

  return { valid: errors.length === 0, root_sha256: expectedRoot, errors }
}

export async function readEvidenceBundle(directory) {
  const root = resolve(directory)
  const manifest = await readManifest(root)
  const profile = manifest?.profile
  return {
    directory: root,
    profile,
    evidence_context: Object.freeze({ ...profile?.evidence_context }),
    root_sha256: manifest?.root_sha256,
  }
}

export async function readEvidencePayloadFile(directory, payloadPath) {
  const root = resolve(directory)
  const normalized = canonicalPayloadPath(payloadPath)
  if (!normalized.startsWith(`${PAYLOAD_DIRECTORY}/`)) {
    throw new EvidenceBundleError(
      'EVIDENCE_PAYLOAD_PATH_INVALID',
      `payload path must begin with ${PAYLOAD_DIRECTORY}/: ${payloadPath}`,
      { bundle: root },
    )
  }
  return readFile(join(root, ...normalized.split('/')))
}

/**
 * The audit-side entry point. Evidence of uncertain provenance is worse than
 * absent evidence because it launders into findings, so this refuses rather
 * than warning and continuing.
 */
export async function loadEvidenceBundle(argument) {
  const verification = await verifyEvidenceBundle(argument)
  if (!verification.valid) {
    throw new EvidenceBundleError(
      'EVIDENCE_BUNDLE_INVALID',
      'evidence bundle did not verify; planning refuses unverified evidence',
      { bundle: resolve(argument), details: verification.errors },
    )
  }
  return readEvidenceBundle(argument)
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm.cmd test -- test/evidence-bundle.test.mjs`
Expected: PASS, 9 tests

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/evidence-bundle.mjs test/evidence-bundle.test.mjs
git commit -m "feat: sealed content-addressed evidence bundles that refuse on any integrity failure"
```

---

### Task 4: The acquisition adapter contract and its routing manifest

**Files:**
- Create: `skills/last-aperture/lenses/_evidence-adapters/contract.md`
- Create: `skills/last-aperture/lenses/_evidence-adapters/manifest.json`
- Create: `scripts/lib/evidence-adapters.mjs`
- Test: `test/evidence-adapters.test.mjs`

**Interfaces:**
- Consumes: `EVIDENCE_CLASS_ORDER`, `EVIDENCE_CLAIM_KINDS`, `evidenceClassAuthorizationFloor`, `EVIDENCE_ARTIFACT_KINDS` (Task 1).
- Produces:
  - `EVIDENCE_ADAPTER_MANIFEST_URL: URL`
  - `evidenceAdapterManifest: object`
  - `resolveEvidenceAdapter(adapterId): {adapter_id, evidence_class, adapter_file, selection_status: 'SELECTED'|'INVENTORY_ONLY', authorization, external_dependency}` — an unlisted id resolves to `inventory-only`, never an invented adapter
  - `evidenceAdapterIds(): string[]`
  - `evidenceRuleIdErrors(ruleId, {adapterId}): string[]`
  - `declaredEvidenceRuleAnchors(markdownText): Set<string>`

Rule-ID grammar, mirroring `db.<threat-family>.<adapter-id>.<semantic-name>`:

```text
ev.<evidence-class>.<adapter-id>.<semantic-name>
```

- [ ] **Step 1: Write the failing test**

Create `test/evidence-adapters.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import {
  EVIDENCE_ADAPTER_MANIFEST_URL,
  declaredEvidenceRuleAnchors,
  evidenceAdapterIds,
  evidenceAdapterManifest,
  evidenceRuleIdErrors,
  resolveEvidenceAdapter,
} from '../scripts/lib/evidence-adapters.mjs'
import {
  EVIDENCE_CLAIM_KINDS,
  EVIDENCE_CLASS_ORDER,
  evidenceClassAuthorizationFloor,
} from '../scripts/lib/evidence-classes.mjs'

const CONTRACT_PATH = fileURLToPath(
  new URL('../skills/last-aperture/lenses/_evidence-adapters/contract.md', import.meta.url),
)

test('four adapters plus the inventory-only fallback are declared', () => {
  assert.deepEqual(evidenceAdapterIds(), [
    'artifact',
    'deployed',
    'inventory-only',
    'registry',
    'runtime',
  ])
})

test('each adapter routes to its class and its own document', () => {
  assert.equal(resolveEvidenceAdapter('artifact').evidence_class, 'built-artifact')
  assert.equal(resolveEvidenceAdapter('registry').evidence_class, 'built-artifact')
  assert.equal(resolveEvidenceAdapter('deployed').evidence_class, 'deployed-state')
  assert.equal(resolveEvidenceAdapter('runtime').evidence_class, 'live-runtime')
  assert.equal(resolveEvidenceAdapter('artifact').selection_status, 'SELECTED')
})

test('an unlisted acquisition target selects inventory-only rather than an invented adapter', () => {
  const decision = resolveEvidenceAdapter('helm-chart-museum')
  assert.equal(decision.adapter_id, 'inventory-only')
  assert.equal(decision.selection_status, 'INVENTORY_ONLY')
  assert.equal(decision.adapter_file, 'contract.md')
})

test('no adapter declares authorization below its class floor', () => {
  for (const adapterId of evidenceAdapterIds()) {
    const adapter = resolveEvidenceAdapter(adapterId)
    if (adapter.selection_status !== 'SELECTED') continue
    const floor = evidenceClassAuthorizationFloor(adapter.evidence_class)
    for (const [requirement, required] of Object.entries(floor)) {
      if (!required) continue
      assert.equal(
        adapter.authorization[requirement],
        true,
        `${adapterId} must require ${requirement}`,
      )
    }
  }
})

test('registry acquisition requires a sealed credential reference and attestation', () => {
  const registry = resolveEvidenceAdapter('registry')
  assert.equal(registry.authorization.credential_ref, true)
  assert.equal(registry.authorization.attestation, true)
  assert.equal(resolveEvidenceAdapter('artifact').authorization.attestation, false)
})

test('rule IDs follow the ev namespace and reject a version, severity or line number', () => {
  assert.deepEqual(
    evidenceRuleIdErrors('ev.built-artifact.oci.whiteout-named-file-with-content', {
      adapterId: 'oci',
    }),
    [],
  )
  assert.ok(evidenceRuleIdErrors('db.authorization.postgresql.rls', { adapterId: 'oci' }).length)
  assert.ok(evidenceRuleIdErrors('ev.built-artifact.oci.rule-v2', { adapterId: 'oci' }).length)
  assert.ok(evidenceRuleIdErrors('ev.built-artifact.oci.High-Severity', { adapterId: 'oci' }).length)
  assert.ok(evidenceRuleIdErrors('ev.exploitation.oci.pop-shell', { adapterId: 'oci' }).length)
  assert.ok(
    evidenceRuleIdErrors('ev.built-artifact.registry.thing', { adapterId: 'oci' }).length,
    'the adapter segment must be the selected adapter',
  )
})

test('the contract document declares the canonical vocabulary it claims to own', () => {
  const contract = readFileSync(CONTRACT_PATH, 'utf8')
  for (const evidenceClass of EVIDENCE_CLASS_ORDER) {
    assert.ok(contract.includes(`\`${evidenceClass}\``), `contract must name ${evidenceClass}`)
  }
  for (const claim of EVIDENCE_CLAIM_KINDS) {
    assert.ok(contract.includes(`\`${claim}\``), `contract must name ${claim}`)
  }
  assert.ok(contract.includes('Contract version: `1`'))
  assert.match(contract, /Verified: `\d{4}-\d{2}-\d{2}`/)
})

test('a rule anchor is recognised only where the contract declares it', () => {
  const anchors = declaredEvidenceRuleAnchors(readFileSync(CONTRACT_PATH, 'utf8'))
  assert.equal(anchors.has('ev.built-artifact.oci.whiteout-named-file-with-content'), false)
  assert.ok(
    declaredEvidenceRuleAnchors('### `ev.built-artifact.oci.blob-unreferenced-by-manifest`\n')
      .has('ev.built-artifact.oci.blob-unreferenced-by-manifest'),
  )
})

test('the manifest file is the one the module reads', () => {
  const onDisk = JSON.parse(readFileSync(fileURLToPath(EVIDENCE_ADAPTER_MANIFEST_URL), 'utf8'))
  assert.deepEqual(onDisk, evidenceAdapterManifest)
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-adapters.test.mjs`
Expected: FAIL — `Cannot find module '.../scripts/lib/evidence-adapters.mjs'`

- [ ] **Step 3: Write the routing manifest**

Create `skills/last-aperture/lenses/_evidence-adapters/manifest.json`:

```json
{
  "schema_version": "1.0.0",
  "manifest_id": "evidence-adapter-routing",
  "verified_on": "2026-08-08",
  "contract_version": 1,
  "fallback": {
    "adapter_id": "inventory-only",
    "adapter_file": "contract.md",
    "selection_status": "INVENTORY_ONLY",
    "coverage_state": "NOT_ASSESSED",
    "can_clear": false
  },
  "adapters": [
    {
      "adapter_id": "artifact",
      "evidence_class": "built-artifact",
      "adapter_file": "artifact.md",
      "mechanism": "read a supplied tarball or OCI layout",
      "external_dependency": null,
      "authorization": {
        "attestation": false,
        "credential_ref": false,
        "target_class": false,
        "operator_identity": false,
        "impact_counters": false,
        "kill_switch": false
      }
    },
    {
      "adapter_id": "registry",
      "evidence_class": "built-artifact",
      "adapter_file": "registry.md",
      "mechanism": "digest-pinned pull through crane or docker save",
      "external_dependency": "crane|docker",
      "authorization": {
        "attestation": true,
        "credential_ref": true,
        "target_class": true,
        "operator_identity": true,
        "impact_counters": false,
        "kill_switch": true
      }
    },
    {
      "adapter_id": "deployed",
      "evidence_class": "deployed-state",
      "adapter_file": "deployed.md",
      "mechanism": "read-only cluster, cloud and org queries through an allowlisted verb set",
      "external_dependency": "kubectl|sf|cloud-cli",
      "authorization": {
        "attestation": true,
        "credential_ref": true,
        "target_class": true,
        "operator_identity": true,
        "impact_counters": true,
        "kill_switch": true
      }
    },
    {
      "adapter_id": "runtime",
      "evidence_class": "live-runtime",
      "adapter_file": "runtime.md",
      "mechanism": "read-only in-container inspection through kubectl exec",
      "external_dependency": "kubectl",
      "authorization": {
        "attestation": true,
        "credential_ref": true,
        "target_class": true,
        "operator_identity": true,
        "impact_counters": true,
        "kill_switch": true
      }
    }
  ]
}
```

- [ ] **Step 4: Write the contract document**

Create `skills/last-aperture/lenses/_evidence-adapters/contract.md`. It is modelled section-for-section on `_database-adapters/contract.md`. Full text:

````markdown
# Evidence acquisition adapter contract

Contract version: `1`

Verified: `2026-08-08`

This file is a contract, not a lens. It owns no topics and emits no findings.
A lens supplies the threat families; an acquisition adapter supplies one class
of evidence, its provenance, and the exact bound of what it obtained.

An adapter answers four questions:

1. Which evidence class and target identity is this, exactly?
2. What was actually acquired, and what was not?
3. Under what authorization, and with what impact on the target?
4. What may a finding derived from this evidence assert?

The adapter never turns acquisition into a clearance. Reading an image is
evidence about that image; it is not evidence about the cluster running it.

## Evidence classes and precedence

| Class | Definition | Precedence |
|---|---|---|
| `source` | Files in the repository under audit | 1 (lowest) |
| `built-artifact` | Packaged build output: OCI image, APK/IPA, jar, dist bundle | 2 |
| `deployed-state` | Configuration as it exists in a live system, read-only | 3 |
| `live-runtime` | Behavior or contents of a running instance | 4 (highest) |

This is `_database-adapters/contract.md`'s detection-precedence rule promoted
from one lens to the registry, and the rule carries over unchanged: **a
lower-precedence signal never overrides a conflicting higher-precedence one.**
Where two classes disagree about one topic, the higher-precedence class
prevails and the conflict is recorded, never silently reconciled.

Exploitation is not a class. It is a mutation tier layered on `live-runtime`
in Phase 3. `audit:http-recon` observations remain in their own protocol and
are not retro-labelled `live-runtime`.

## Canonical adapter routing

| `adapter_id` | Class | Mechanism | External dependency |
|---|---|---|---|
| `artifact` | `built-artifact` | Read a supplied tarball or OCI layout | none |
| `registry` | `built-artifact` | `crane pull` / `docker save`, digest-pinned | `crane` or `docker` |
| `deployed` | `deployed-state` | Read-only cluster, cloud and org queries | respective CLIs |
| `runtime` | `live-runtime` | Read-only in-container inspection | `kubectl` |
| `inventory-only` | — | no adapter; load `contract.md` only | none |

An unlisted acquisition target selects `inventory-only`. Do not manufacture an
adapter ID from a file extension or a registry hostname. `inventory-only` may
inventory what it saw and write a coverage gap; it cannot clear anything.

## Artifact kinds

`oci-image`, `apk`, `ipa`, `jar`, `dist-bundle`.

A `built-artifact` bundle names exactly one kind. A lens declares the kinds it
has rules for and must not claim coverage of a kind it cannot interpret. An
acquired artifact whose kind no activated lens declares yields
`INVENTORY_ONLY`, never silence.

## Capability enum

Each adapter declares every canonical capability below using exactly one value.
The values are `_database-adapters/contract.md`'s, verbatim:

| Value | Meaning |
|---|---|
| `NATIVE` | The adapter obtains this directly from the target. |
| `COMPOSABLE` | The adapter can obtain it, but only if every named precondition is true. |
| `EXTERNAL_ONLY` | The adapter cannot obtain it; a separate tool or class must. |
| `UNSUPPORTED` | The identified target cannot express it in scope. |
| `UNKNOWN` | Target, version, or configuration ambiguity prevents classification. |

These describe what the adapter can obtain, not audit outcome.

Every adapter declares these canonical capabilities:

| Capability ID | What is being classified |
|---|---|
| `target-identity` | The target can be pinned to an exact immutable identity. |
| `content-enumeration` | Every member object of the target can be listed. |
| `content-retrieval` | The bytes of a named member object can be read. |
| `layer-or-revision-history` | The target's construction history is readable. |
| `metadata-provenance` | Build or deploy metadata is readable and attributable. |
| `deletion-recoverability` | Content deleted during construction remains detectable. |
| `effective-configuration` | Configuration as effective, not as declared, is readable. |
| `principal-and-permission-state` | Effective principals and grants are readable. |
| `secret-material-surface` | Locations that can carry secret material are enumerable. |
| `impact-accounting` | Commands, bytes and objects touched can be counted and capped. |

An adapter may add namespaced capabilities, but it may not rename or omit a
canonical one.

## Coverage states

Capability and coverage are separate axes. The states are
`_database-adapters/contract.md`'s, unchanged:

| Coverage state | Meaning for an evidence class |
|---|---|
| `COVERED` | The class was acquired complete for the declared scope. |
| `PARTIAL` | Some of the class was acquired; the omissions are listed. |
| `INVENTORY_ONLY` | The class was acquired but no activated lens has a sound actionable rule for it. |
| `NOT_ASSESSED` | The class was not acquired, or acquisition failed. |
| `NOT_APPLICABLE` | The class's precondition is demonstrably false for this target. |

`INVENTORY_ONLY` and `NOT_ASSESSED` are never rendered as pass, clean, secure,
or no findings. They appear in `Coverage` with the exact missing evidence.

Acquisition failure is `NOT_ASSESSED` with a named reason. **A missing
dependency is a failure, never an empty success**: an audit that looks clean
because a tool was absent is the exact failure this contract exists to prevent.

### Ambiguity is fail-closed

- A file extension, a registry hostname, or a MIME type alone activates
  inventory only.
- If two artifact kinds remain plausible, record the conflict and mark every
  class-semantic rule `NOT_ASSESSED`.
- Output that cannot be parsed is `PARTIAL` with the unparsed portion named,
  never silently dropped.
- No adapter reports `COVERED` with an empty payload.
- A bundle whose manifest or file hashes do not verify causes `audit -- plan`
  to refuse. Evidence of uncertain provenance is worse than absent evidence
  because it launders into findings.

## Claim kinds

A finding derived from a non-`source` class asserts exactly one of these, and
only where the lens declares it in `may_conclude`:

| Claim kind | What it asserts |
|---|---|
| `secret-present-in-artifact` | Secret material is readable in the acquired evidence. |
| `unexpected-artifact-content` | Content is present that the source does not account for. |
| `vulnerable-component-present` | A component with a known defect is present in the evidence. |
| `drift-from-source` | Deployed or built state differs from what the repository declares. |
| `runtime-misconfiguration` | Effective configuration is unsafe as it actually stands. |
| `sensitive-data-at-rest` | Regulated or sensitive data is present in the acquired evidence. |

A finding asserting outside its class's declared `may_conclude` is malformed.
A new claim kind is added here first; a lens may not invent one.

## Stable rule IDs

Adapter and lens rules over acquired evidence use:

```text
ev.<evidence-class>.<adapter-id>.<semantic-name>
```

Examples:

```text
ev.built-artifact.oci.whiteout-named-file-with-content
ev.built-artifact.oci.blob-unreferenced-by-manifest
ev.deployed-state.kubernetes.secret-readable-by-default-service-account
```

Rules:

1. IDs are lowercase ASCII, dot-separated, and contain no version, severity,
   path, line number, or sequence number.
2. The evidence-class segment is a canonical class.
3. The adapter segment is the canonical adapter or artifact-format ID declared
   by the selected adapter, not a marketing alias.
4. A compatible refinement keeps the ID. A changed oracle, protected resource,
   or security meaning gets a new ID and a `supersedes` link.
5. The rule ID is not the candidate finding ID. `_schema.md` still derives
   `candidate_id` from topic, normalized primary location, and title.
6. A rule ID is valid only when that exact ID is declared as a rule anchor —
   a `###`-or-deeper heading whose text is the backticked ID — in the owning
   adapter document. Syntactically plausible but undeclared IDs are rejected.

## Authorization

| Class | Floor |
|---|---|
| `source` | Existing: the user may inspect the repository. |
| `built-artifact` via `artifact` | File access only; no attestation. |
| `built-artifact` via `registry` | Sealed credential reference, digest-pinned image, attestation. |
| `deployed-state` | Read-only verb allowlist enforced controller-side, attestation, target class, named operator, impact counters, kill switch. |
| `live-runtime` | All of the above plus a per-run authorization confirmation. |

An adapter may exceed its class floor. It may never fall below it.

Credential **values** never appear in a bundle — only a `credential_ref`. This
mirrors `_database-adapters/contract.md:48`.

`PRODUCTION` and `THIRD_PARTY` target classes require explicit acknowledgment.
`THIRD_PARTY` routes through the existing higher-assurance signed-artifact
mode; this contract neither creates nor approves those artifacts.

**Impact counters exist for read-only classes.** They count commands executed,
bytes read, and distinct objects touched per target, each with a cap that halts
acquisition when exceeded, because an unbounded read against production is an
availability risk regardless of intent.

`stop` is idempotent and requires no still-valid authority artifact, matching
`http-recon`.

## PHI scope

Gated on a declared PHI scope, independent of target class, so non-PHI systems
pay no PHI friction:

| `--phi-scope` | Default | Marking |
|---|---|---|
| `none` (attested) | Full content capture, no redaction | none |
| `possible` | Metadata-only; contents require an explicit flag | `phi_bearing: true` if contents captured |
| `confirmed` | Metadata-only; contents require flag plus acknowledgment | `phi_bearing: true`, retention limit, noted in report |

Metadata-only means names, shapes, sizes, hashes, and key names — never values
or record contents. A `phi_bearing` bundle is itself an auditable artifact: the
report names its existence and location and does not inline its contents.

## Conformance matrix

Every adapter passes one shared suite:

- `describe` returns the adapter's canonical ID, class, capabilities, and
  external dependency.
- `plan` seals target identity, target class and PHI scope, performs no
  acquisition, and probes for its external CLI, failing there when absent.
- `run` emits a bundle whose `evidence_context` is complete and immutable.
- A missing dependency yields `NOT_ASSESSED` with a named reason, never an
  empty success.
- `COVERED` with an empty payload is refused.
- Unparsed output yields `PARTIAL` with the unparsed portion named.
- Every command the adapter would run against a live target is replayable from
  a stub on `PATH`, so no test depends on a live cluster, registry, or org.
````

- [ ] **Step 5: Write the routing module**

Create `scripts/lib/evidence-adapters.mjs`:

```js
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { EVIDENCE_CLASS_ORDER, isEvidenceClass } from './evidence-classes.mjs'

export const EVIDENCE_ADAPTER_MANIFEST_URL = new URL(
  '../../skills/last-aperture/lenses/_evidence-adapters/manifest.json',
  import.meta.url,
)

export const evidenceAdapterManifest = JSON.parse(
  readFileSync(fileURLToPath(EVIDENCE_ADAPTER_MANIFEST_URL), 'utf8'),
)

const BY_ID = new Map(
  evidenceAdapterManifest.adapters.map((adapter) => [adapter.adapter_id, adapter]),
)

const FALLBACK = Object.freeze({
  ...evidenceAdapterManifest.fallback,
  evidence_class: null,
  external_dependency: null,
  authorization: Object.freeze({
    attestation: false,
    credential_ref: false,
    target_class: false,
    operator_identity: false,
    impact_counters: false,
    kill_switch: false,
  }),
})

export function evidenceAdapterIds() {
  return [...BY_ID.keys(), evidenceAdapterManifest.fallback.adapter_id]
    .sort(compareCanonicalStrings)
}

/**
 * An unlisted acquisition target selects inventory-only, mirroring the
 * database router. Manufacturing an adapter ID from a hostname or a file
 * extension is the failure this prevents.
 */
export function resolveEvidenceAdapter(adapterId) {
  const adapter = BY_ID.get(adapterId)
  if (!adapter) return FALLBACK
  return Object.freeze({
    adapter_id: adapter.adapter_id,
    evidence_class: adapter.evidence_class,
    adapter_file: adapter.adapter_file,
    selection_status: 'SELECTED',
    external_dependency: adapter.external_dependency,
    authorization: Object.freeze({ ...adapter.authorization }),
  })
}

const SEGMENT_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/
const VERSION_SUFFIX_PATTERN = /(?:^|-)v[0-9]+$/
const SEVERITY_TOKENS = new Set(['critical', 'high', 'medium', 'low', 'info'])

export function evidenceRuleIdErrors(ruleId, { adapterId } = {}) {
  const errors = []
  if (typeof ruleId !== 'string' || ruleId !== ruleId.toLowerCase()) {
    return ['rule ID must be a lowercase ASCII string']
  }
  const segments = ruleId.split('.')
  if (segments.length !== 4 || segments[0] !== 'ev') {
    return [`rule ID must be ev.<evidence-class>.<adapter-id>.<semantic-name>: ${ruleId}`]
  }
  const [, evidenceClass, adapterSegment, semanticName] = segments
  if (!isEvidenceClass(evidenceClass)) {
    errors.push(
      `rule ID class segment must be one of ${EVIDENCE_CLASS_ORDER.join(', ')}: ${evidenceClass}`,
    )
  }
  for (const [label, segment] of [['adapter', adapterSegment], ['semantic name', semanticName]]) {
    if (!SEGMENT_PATTERN.test(segment)) {
      errors.push(`rule ID ${label} segment must be lowercase hyphen-separated ASCII: ${segment}`)
    }
  }
  if (adapterId !== undefined && adapterSegment !== adapterId) {
    errors.push(
      `rule ID adapter segment ${adapterSegment} is not the selected adapter ${adapterId}`,
    )
  }
  if (VERSION_SUFFIX_PATTERN.test(semanticName) || /\d/.test(semanticName.split('-').at(-1))) {
    errors.push(`rule ID must carry no version or sequence number: ${semanticName}`)
  }
  if (semanticName.split('-').some((token) => SEVERITY_TOKENS.has(token))) {
    errors.push(`rule ID must carry no severity: ${semanticName}`)
  }
  return errors
}

const RULE_ANCHOR_PATTERN = /^#{3,}\s+`(ev\.[a-z0-9.-]+)`\s*$/gm

/**
 * A rule ID is valid only where the owning document declares it as an anchor.
 * The predicate is positional for the same reason R8's is: a rule ID quoted in
 * prose or inside a fenced example is discussion, not a declaration.
 */
export function declaredEvidenceRuleAnchors(markdownText) {
  const anchors = new Set()
  const withoutFences = String(markdownText).replace(/^ {0,3}```[\s\S]*?^ {0,3}```\s*$/gm, '')
  for (const match of withoutFences.matchAll(RULE_ANCHOR_PATTERN)) {
    anchors.add(match[1])
  }
  return anchors
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `npm.cmd test -- test/evidence-adapters.test.mjs`
Expected: PASS, 9 tests

- [ ] **Step 7: Verify the lens gates still pass**

Run: `npm.cmd run lint`
Expected: `PASS: R1-R8, SKILL and ledger gate clean.` — `_evidence-adapters/` is underscore-prefixed, so `loadLenses` skips it (`lint-lenses.mjs:27`).

Run: `npm.cmd run gen -- --check`
Expected: `PASS: generated artifacts match frontmatter (174 slugs).`

- [ ] **Step 8: Commit**

```bash
git add skills/last-aperture/lenses/_evidence-adapters scripts/lib/evidence-adapters.mjs test/evidence-adapters.test.mjs
git commit -m "feat: evidence acquisition adapter contract, routing manifest and rule-ID discipline"
```

---

### Task 5: The shared adapter conformance suite

**Files:**
- Create: `test/helpers/evidence-adapter-conformance.mjs`
- Create: `test/evidence-adapter-conformance.test.mjs`

**Interfaces:**
- Consumes: `validateEvidenceProfile` (Task 2), `writeEvidenceBundle` / `verifyEvidenceBundle` (Task 3), `resolveEvidenceAdapter` (Task 4).
- Produces:
  - `runEvidenceAdapterConformance(adapter, {describe, test, assert, tmpRoot}): void` — registers one `describe` block of shared cases against any object implementing the adapter interface
  - `EVIDENCE_ADAPTER_INTERFACE: readonly string[]` — `['describe', 'plan', 'run']`
  - `stubAdapter(overrides): object` — a minimal conforming reference adapter, used to prove the suite passes what it should

The adapter interface every adapter in Plans 3-5 implements:

```text
describe(): { adapter_id, evidence_class, adapter_version, capabilities: Record<capabilityId, capabilityValue>, external_dependency }
plan(request): Promise<{ plan_id, evidence_context_seed, target_class, phi_scope, dependency: {name, present, version|null} }>
run(planned, { out }): Promise<{ directory, root_sha256, profile }>
```

- [ ] **Step 1: Write the conformance suite**

Create `test/helpers/evidence-adapter-conformance.mjs`:

```js
import assert from 'node:assert/strict'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { validateEvidenceProfile } from '../../scripts/lib/evidence-contracts.mjs'
import { verifyEvidenceBundle, writeEvidenceBundle } from '../../scripts/lib/evidence-bundle.mjs'
import { resolveEvidenceAdapter } from '../../scripts/lib/evidence-adapters.mjs'
import {
  EVIDENCE_COVERAGE_STATES,
  evidenceClassAuthorizationFloor,
} from '../../scripts/lib/evidence-classes.mjs'

export const EVIDENCE_ADAPTER_INTERFACE = Object.freeze(['describe', 'plan', 'run'])

const CANONICAL_CAPABILITIES = Object.freeze([
  'content-enumeration',
  'content-retrieval',
  'deletion-recoverability',
  'effective-configuration',
  'impact-accounting',
  'layer-or-revision-history',
  'metadata-provenance',
  'principal-and-permission-state',
  'secret-material-surface',
  'target-identity',
])

const CAPABILITY_VALUES = new Set([
  'NATIVE',
  'COMPOSABLE',
  'EXTERNAL_ONLY',
  'UNSUPPORTED',
  'UNKNOWN',
])

async function scratch(prefix) {
  return join(await mkdtemp(join(tmpdir(), `rta-${prefix}-`)), 'ev')
}

/**
 * One suite every acquisition adapter must pass. Registers node:test cases, so
 * a new adapter costs one import and one call. Every case here encodes a way
 * an acquisition has actually gone wrong: a silent empty success, a bundle
 * that cannot be re-verified, a context field the adapter invented.
 *
 * `cases` supplies adapter-specific inputs:
 *   validPlanRequest      — a request plan() must accept
 *   missingDependencyPlan — a request whose external CLI is absent
 *   unparseableRunPlan    — a planned request whose target yields garbage
 */
export function runEvidenceAdapterConformance(adapter, cases) {
  const label = adapter.describe().adapter_id

  test(`${label}: implements the adapter interface`, () => {
    for (const method of EVIDENCE_ADAPTER_INTERFACE) {
      assert.equal(typeof adapter[method], 'function', `${label} must implement ${method}()`)
    }
  })

  test(`${label}: describe() matches the routing manifest`, () => {
    const described = adapter.describe()
    const routed = resolveEvidenceAdapter(described.adapter_id)
    assert.equal(routed.selection_status, 'SELECTED')
    assert.equal(described.evidence_class, routed.evidence_class)
    assert.equal(described.external_dependency, routed.external_dependency)
    assert.match(described.adapter_version, /^\d+\.\d+\.\d+$/)
  })

  test(`${label}: declares every canonical capability exactly once`, () => {
    const capabilities = adapter.describe().capabilities
    assert.deepEqual(Object.keys(capabilities).sort(), [...CANONICAL_CAPABILITIES])
    for (const [id, value] of Object.entries(capabilities)) {
      assert.ok(CAPABILITY_VALUES.has(value), `${id} has non-canonical value ${value}`)
    }
  })

  test(`${label}: plan() acquires nothing and seals the target`, async () => {
    const planned = await adapter.plan(cases.validPlanRequest)
    assert.equal(typeof planned.plan_id, 'string')
    assert.ok(planned.plan_id.length > 0)
    assert.equal(typeof planned.evidence_context_seed.evidence_id, 'string')
    assert.equal(planned.evidence_context_seed.evidence_class, adapter.describe().evidence_class)
    assert.ok(['LAB', 'NONPROD', 'PRODUCTION', 'THIRD_PARTY'].includes(planned.target_class))
    assert.ok(['none', 'possible', 'confirmed'].includes(planned.phi_scope))
  })

  test(`${label}: plan() honours its class authorization floor`, () => {
    const described = adapter.describe()
    const routed = resolveEvidenceAdapter(described.adapter_id)
    const floor = evidenceClassAuthorizationFloor(described.evidence_class)
    for (const [requirement, required] of Object.entries(floor)) {
      if (!required) continue
      assert.equal(
        routed.authorization[requirement],
        true,
        `${label} must require ${requirement}`,
      )
    }
  })

  test(`${label}: a missing dependency is NOT_ASSESSED with a named reason`, async () => {
    if (!cases.missingDependencyPlan) return
    const result = await adapter.plan(cases.missingDependencyPlan).then(
      (planned) => adapter.run(planned, { out: null }).catch((error) => error),
      (error) => error,
    )
    const profile = result?.profile ?? result?.bundle?.profile
    if (profile) {
      assert.equal(profile.coverage_state, 'NOT_ASSESSED')
      assert.ok(profile.coverage_gaps.length > 0, 'a missing dependency must name its gap')
    } else {
      assert.ok(
        /not (?:found|installed)|missing|ENOENT/i.test(String(result?.message)),
        'a missing dependency must fail with a named reason',
      )
    }
  })

  test(`${label}: run() emits a bundle that re-verifies`, async () => {
    const out = await scratch(label)
    const planned = await adapter.plan(cases.validPlanRequest)
    const written = await adapter.run(planned, { out })
    const validation = validateEvidenceProfile(written.profile)
    assert.deepEqual(validation.errors, [])
    const verification = await verifyEvidenceBundle(written.directory)
    assert.deepEqual(verification.errors, [])
    assert.equal(verification.root_sha256, written.root_sha256)
  })

  test(`${label}: evidence_context is complete and immutable across a re-read`, async () => {
    const first = await scratch(label)
    const second = await scratch(label)
    const planned = await adapter.plan(cases.validPlanRequest)
    const a = await adapter.run(planned, { out: first })
    const b = await adapter.run(planned, { out: second })
    const drop = ({ acquired_on: _ignored, ...rest }) => rest
    assert.deepEqual(
      drop(a.profile.evidence_context),
      drop(b.profile.evidence_context),
      'the same sealed plan must project the same routing context',
    )
    assert.equal(a.profile.evidence_context.evidence_id, planned.evidence_context_seed.evidence_id)
  })

  test(`${label}: never reports COVERED with an empty payload`, async () => {
    const out = await scratch(label)
    const planned = await adapter.plan(cases.validPlanRequest)
    const written = await adapter.run(planned, { out })
    if (written.profile.files.length === 0) {
      assert.notEqual(written.profile.coverage_state, 'COVERED')
    }
    assert.ok(EVIDENCE_COVERAGE_STATES.includes(written.profile.coverage_state))
  })

  test(`${label}: unparsed output is PARTIAL with the unparsed portion named`, async () => {
    if (!cases.unparseableRunPlan) return
    const out = await scratch(label)
    const planned = await adapter.plan(cases.unparseableRunPlan)
    const written = await adapter.run(planned, { out })
    assert.equal(written.profile.coverage_state, 'PARTIAL')
    assert.ok(
      written.profile.coverage_gaps.some(({ reason }) => /pars|decode|read/i.test(reason)),
      'the unparsed portion must be named, never silently dropped',
    )
  })
}

/**
 * A minimal conforming adapter. Its only job is to prove the suite above
 * passes something correct — a suite nobody has seen pass is not a suite.
 */
export function stubAdapter(overrides = {}) {
  const capabilities = Object.fromEntries(CANONICAL_CAPABILITIES.map((id) => [id, 'NATIVE']))
  return {
    describe: () => ({
      adapter_id: 'artifact',
      evidence_class: 'built-artifact',
      adapter_version: '1.0.0',
      capabilities,
      external_dependency: null,
    }),
    plan: async (request) => ({
      plan_id: `plan-${request.evidence_id}`,
      evidence_context_seed: {
        evidence_id: request.evidence_id,
        evidence_class: 'built-artifact',
        adapter_id: 'artifact',
        target_identity: request.target_identity,
        acquisition_mode: 'offline-export',
        detection_evidence: [request.detection_evidence],
        confidence: 'high',
      },
      target_class: request.target_class ?? 'LAB',
      phi_scope: request.phi_scope ?? 'none',
      dependency: { name: null, present: true, version: null },
    }),
    run: async (planned, { out }) => writeEvidenceBundle({
      directory: out,
      profile: {
        schema: 'evidence-bundle-v1',
        evidence_context: {
          ...planned.evidence_context_seed,
          acquired_on: '2026-08-08T14:22:10Z',
        },
        target_class: planned.target_class,
        phi_scope: planned.phi_scope,
        phi_bearing: false,
        adapter_version: '1.0.0',
        contract_version: 1,
        coverage_state: 'COVERED',
        artifact_kind: 'oci-image',
        attestation: null,
        coverage_gaps: [],
      },
      payload: [{ path: 'layers/00/entries.json', bytes: Buffer.from('[]', 'utf8') }],
    }),
    ...overrides,
  }
}
```

- [ ] **Step 2: Write the test that exercises the suite**

Create `test/evidence-adapter-conformance.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  EVIDENCE_ADAPTER_INTERFACE,
  runEvidenceAdapterConformance,
  stubAdapter,
} from './helpers/evidence-adapter-conformance.mjs'

const VALID_REQUEST = {
  evidence_id: 'peerstar-api-image',
  target_identity: 'sha256:9f2c1d0e4b6a8c3f5e7d9b1a3c5e7f9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c',
  detection_evidence: 'shell-in-the-ghost.tar.gz sha256:4aaff082',
  target_class: 'LAB',
  phi_scope: 'none',
}

// The reference adapter proves the suite passes what it should. Plans 3-5 each
// add one call like this against a real adapter.
runEvidenceAdapterConformance(stubAdapter(), { validPlanRequest: VALID_REQUEST })

test('the suite fails an adapter that omits a canonical capability', () => {
  const crippled = stubAdapter({
    describe: () => ({
      adapter_id: 'artifact',
      evidence_class: 'built-artifact',
      adapter_version: '1.0.0',
      capabilities: { 'target-identity': 'NATIVE' },
      external_dependency: null,
    }),
  })
  assert.throws(
    () => assert.deepEqual(Object.keys(crippled.describe().capabilities).length, 10),
    assert.AssertionError,
  )
})

test('the suite fails an adapter that reports COVERED with an empty payload', async () => {
  const dishonest = stubAdapter({
    run: async () => ({
      directory: null,
      root_sha256: null,
      profile: { coverage_state: 'COVERED', files: [], coverage_gaps: [] },
    }),
  })
  const written = await dishonest.run()
  assert.equal(written.profile.files.length, 0)
  assert.throws(
    () => assert.notEqual(written.profile.coverage_state, 'COVERED'),
    assert.AssertionError,
  )
})

test('the interface every adapter implements is exactly three verbs', () => {
  assert.deepEqual([...EVIDENCE_ADAPTER_INTERFACE], ['describe', 'plan', 'run'])
})
```

- [ ] **Step 3: Run the tests to verify they pass**

Run: `npm.cmd test -- test/evidence-adapter-conformance.test.mjs`
Expected: PASS — 10 conformance cases from `runEvidenceAdapterConformance` plus 3 local tests

- [ ] **Step 4: Run the whole suite and confirm no regressions**

Run: `npm.cmd test`
Expected: only the 2 known `cloud-iac-fixtures.test.mjs` ripgrep failures. Anything else is a regression from this plan.

Run: `npm.cmd run lint` → `PASS: R1-R8, SKILL and ledger gate clean.`
Run: `npm.cmd run gen -- --check` → `PASS ... (174 slugs).`

- [ ] **Step 5: Commit**

```bash
git add test/helpers/evidence-adapter-conformance.mjs test/evidence-adapter-conformance.test.mjs
git commit -m "test: shared acquisition adapter conformance suite with a reference adapter"
```

---

## Spec amendments made by this plan

Two things the spec left underspecified. Both are decided here; the spec should
be updated to match rather than the two drifting apart.

1. **`may_conclude` needs a closed vocabulary.** The spec shows `may_conclude`
   values but never says where they come from. Left open, every lens invents
   labels and nothing can validate a finding against them — the shadow-registry
   failure `_schema.md:107` warns about. Resolved: the six canonical claim kinds
   are declared in `_evidence-adapters/contract.md` → `## Claim kinds` and
   exported as `EVIDENCE_CLAIM_KINDS`. Plan 2's lens linter rejects a
   `may_conclude` entry outside the set.

2. **`artifact_kind` belongs on the bundle, not only on the lens.** The spec
   puts `artifact_kinds` in the lens declaration but never records what kind a
   given bundle actually carries, so "an acquired artifact whose kind no
   activated lens declares yields `INVENTORY_ONLY`" is not computable. Resolved:
   `evidence_profile.artifact_kind` — required for `built-artifact`, forbidden
   for every other class.

A third resolution belongs to Plan 2 and is recorded there: `may_conclude`
cannot be enforced without a field naming the finding's claim, so Plan 2 adds
Stage-1 `evidence_claim` beside `evidence_context`.

## Self-review

**Spec coverage.** This plan covers the spec's `## Components` → `### Foundation`
in full: evidence-class registry (Task 1), `schemas/evidence-bundle.schema.json`
plus reader/writer that can create, hash, seal, verify and read (Tasks 2 and 3),
`lenses/_evidence-adapters/contract.md` with contract version, `verified_on`,
canonical routing table, capability enum, fail-closed ambiguity rules, stable
rule IDs and conformance matrix (Task 4), and the adapter conformance suite
(Task 5). It also covers `## Error handling`'s bundle-integrity refusal
(Task 3) and `## Testing` → "Integrity tests" (Task 3) and "Adapter conformance
suite" (Task 5).

**Deliberately out of scope, and covered elsewhere:** the `audit:acquire`
controller and its four adapters are Plans 3-5; every lens-facing and
report-facing change is Plan 2. This plan adds no CLI entry point and no
`package.json` script, so nothing in it can be invoked by an operator yet —
that is correct for a foundation and is why it ships first.

**Type consistency.** `evidence_context`'s eight fields are identical in the
schema (Task 2), the writer (Task 3), the conformance suite (Task 5) and the
spec. `coverage_state` uses the five-value evidence vocabulary everywhere and
never the store profile's three-value `ASSESSED`/`PARTIAL`/`NOT_ASSESSED` enum —
those are different fields on different objects and the plan never mixes them.
`EVIDENCE_CLASS_ORDER` is the single source for class ordering; the schema's
enum is checked against it at import.
