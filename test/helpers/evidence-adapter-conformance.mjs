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
