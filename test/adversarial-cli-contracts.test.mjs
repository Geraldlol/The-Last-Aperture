import { createHash } from 'node:crypto'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  AdversarialCliContractError,
  assertPlanWithinCurrentScope,
  canonicalAdversarialCurrentScope,
  digestAdversarialCurrentScope,
  inspectAdversarialPlan,
  sealAdversarialPlan,
  validateAdversarialCurrentScope,
} from '../scripts/lib/adversarial-cli-contracts.mjs'

const SHA_A = 'a'.repeat(64)

function currentScope(overrides = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-current-scope',
    scope_id: 'scope:repository-fuzz',
    engagement_id: 'engagement:cli-test',
    targets: [{
      kind: 'repository',
      target_id: 'target:disposable-repository',
      locator: 'repository://disposable-mirror',
      identity_sha256: SHA_A,
    }],
    allowed_risk_classes: ['READ_ONLY'],
    allowed_autonomy_profiles: ['L2_SUPERVISED'],
    allowed_strategy_ids: ['structured-fuzz/v1'],
    allowed_operations: ['fuzz.structured'],
    allowed_action_categories: ['fuzz.property'],
    allowed_strategy_families: ['structured-fuzz'],
    validity: {
      not_before: '2026-09-03T09:00:00.000Z',
      not_after: '2026-09-03T11:00:00.000Z',
    },
    ...overrides,
  }
}

function draft(overrides = {}) {
  return {
    plan_id: 'plan:repository-fuzz',
    engagement_id: 'engagement:cli-test',
    candidate_id: 'candidate:json-boundary',
    target: currentScope().targets[0],
    strategy_id: 'structured-fuzz/v1',
    risk_class: 'READ_ONLY',
    autonomy_profile: 'L2_SUPERVISED',
    attack: {
      id: 'attack:integer-boundary',
      description: 'Search for values that violate the declared integer boundary.',
      expected_observation: 'A minimized counterexample is recorded when the property fails.',
    },
    control: {
      id: 'control:integer-domain',
      description: 'Sample the same bounded integer domain with the declared property.',
      expected_observation: 'The harness returns only structured fuzz observations.',
    },
    oracle: {
      id: 'oracle:boolean-property',
      confirmation_condition: 'The property returns false for a generated value.',
      inconclusive_condition: 'The harness fails, times out, or exceeds evidence limits.',
    },
    limits: {
      max_actions: 1,
      max_wall_time_ms: 5_000,
      max_action_time_ms: 2_000,
      max_input_bytes: 16_384,
      max_output_bytes: 65_536,
      max_aggregate_output_bytes: 65_536,
      max_concurrency: 1,
      min_action_interval_ms: 0,
    },
    actions: [{
      action_id: 'action:fuzz-integer',
      purpose: 'attack',
      action_category: 'fuzz.property',
      operation: 'fuzz.structured',
      parameters: {
        seed: 424242,
        num_runs: 100,
        timeout_ms: 1_000,
        max_counterexample_bytes: 4_096,
        arbitrary: { kind: 'integer', min: -100, max: 100 },
        property: { kind: 'integer-less-than', value: 10 },
      },
    }],
    ...overrides,
  }
}

test('current scope has canonical bytes and a content-addressed digest', () => {
  const scope = currentScope()
  assert.deepEqual(validateAdversarialCurrentScope(scope), { valid: true, errors: [] })
  const canonical = canonicalAdversarialCurrentScope(scope)
  assert.equal(canonical.endsWith('\n'), false)
  assert.equal(
    digestAdversarialCurrentScope(scope),
    createHash('sha256').update(canonical).digest('hex'),
  )

  const reordered = Object.fromEntries(Object.entries(scope).reverse())
  assert.equal(canonicalAdversarialCurrentScope(reordered), canonical)
})

test('plan sealing derives scope binding and inspection reports the exact plan digest', () => {
  const scope = currentScope()
  const plan = sealAdversarialPlan({ draft: draft(), currentScope: scope })
  assert.equal(plan.scope_revision_sha256, digestAdversarialCurrentScope(scope))
  assert.equal(plan.kind, 'red-team-audit/adversarial-plan')
  assert.equal(plan.schema_version, '1.0.0')

  const inspected = inspectAdversarialPlan({ plan, currentScope: scope })
  assert.equal(inspected.valid, true)
  assert.equal(inspected.scope_binding, 'CURRENT_SCOPE_MATCH')
  assert.match(inspected.plan_sha256, /^[a-f0-9]{64}$/)
  assert.equal(inspected.action_count, 1)
})

test('scope validation and plan authorization fail closed on unknown or widened data', () => {
  assert.equal(validateAdversarialCurrentScope(currentScope({ unsigned_override: true })).valid, false)

  const scope = currentScope()
  const plan = sealAdversarialPlan({ draft: draft(), currentScope: scope })
  const changedScope = structuredClone(scope)
  changedScope.allowed_operations = ['filesystem.delete']

  assert.throws(
    () => assertPlanWithinCurrentScope({ plan, currentScope: changedScope, now: '2026-09-03T10:00:00.000Z' }),
    (error) => error instanceof AdversarialCliContractError
      && error.code === 'ADVERSARIAL_SCOPE_BINDING_MISMATCH',
  )

  const wrongStrategy = structuredClone(scope)
  wrongStrategy.allowed_strategy_ids = ['different/strategy']
  assert.throws(
    () => sealAdversarialPlan({ draft: draft(), currentScope: wrongStrategy }),
    (error) => error.code === 'ADVERSARIAL_PLAN_OUTSIDE_CURRENT_SCOPE',
  )
})

test('scope authorization rejects expired scope and targets not exactly enumerated', () => {
  const scope = currentScope()
  const plan = sealAdversarialPlan({ draft: draft(), currentScope: scope })
  assert.throws(
    () => assertPlanWithinCurrentScope({ plan, currentScope: scope, now: '2026-09-03T11:00:00.000Z' }),
    (error) => error.code === 'ADVERSARIAL_CURRENT_SCOPE_EXPIRED',
  )

  const otherTarget = structuredClone(scope)
  otherTarget.targets[0].target_id = 'target:different-repository'
  const otherPlan = structuredClone(plan)
  otherPlan.scope_revision_sha256 = digestAdversarialCurrentScope(otherTarget)
  assert.throws(
    () => assertPlanWithinCurrentScope({ plan: otherPlan, currentScope: otherTarget, now: '2026-09-03T10:00:00.000Z' }),
    /invalid|scope/i,
  )
})

test('plan sealing rejects accessors and non-JSON array properties before canonicalization', () => {
  let getterCalls = 0
  const accessorDraft = draft()
  Object.defineProperty(accessorDraft, 'hidden_authority', {
    enumerable: true,
    get() {
      getterCalls += 1
      return true
    },
  })
  assert.throws(
    () => sealAdversarialPlan({ draft: accessorDraft, currentScope: currentScope() }),
    (error) => error.code === 'ADVERSARIAL_PLAN_DRAFT_INVALID',
  )
  assert.equal(getterCalls, 0)

  const namedArrayDraft = draft()
  namedArrayDraft.actions.unsigned_override = true
  assert.throws(
    () => sealAdversarialPlan({ draft: namedArrayDraft, currentScope: currentScope() }),
    (error) => error.code === 'ADVERSARIAL_PLAN_DRAFT_INVALID',
  )
})

test('scope target kinds require honest locator classes', () => {
  const remoteAsLocal = currentScope()
  remoteAsLocal.targets[0] = {
    ...remoteAsLocal.targets[0],
    kind: 'local_service',
    locator: 'https://remote.example.test',
  }
  assert.equal(validateAdversarialCurrentScope(remoteAsLocal).valid, false)

  const filesystemAsRepository = currentScope()
  filesystemAsRepository.targets[0].locator = 'file:///workspace'
  assert.equal(validateAdversarialCurrentScope(filesystemAsRepository).valid, false)

  const credentialsInLiveUrl = currentScope()
  credentialsInLiveUrl.targets[0] = {
    ...credentialsInLiveUrl.targets[0],
    kind: 'live',
    locator: 'https://operator:secret@authorized.example.test',
  }
  assert.equal(validateAdversarialCurrentScope(credentialsInLiveUrl).valid, false)
})
