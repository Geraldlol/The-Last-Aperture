import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  AdversarialScopeContractError,
  adversarialScopeRequestDigest,
  adversarialScopeRevisionDigest,
  assertAdversarialScopeSuccessorAppend,
  assertValidAdversarialScopeRequest,
  assertValidAdversarialScopeRevision,
  canonicalAdversarialScopeDecision,
  canonicalAdversarialScopeRequest,
  canonicalAdversarialScopeRevision,
  createAdversarialScopeDecision,
  createAdversarialScopeRequest,
  resolveAdversarialScopeRequest,
  verifyAdversarialScopeDecision,
} from '../scripts/lib/adversarial-scope-contracts.mjs'

const SHA_A = 'a'.repeat(64)
const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)
const SHA_D = 'd'.repeat(64)
const DECISION_NOW = '2026-09-03T09:05:30.000Z'

function delta(overrides = {}) {
  return {
    targets: {
      add: [{
        target_id: 'api-staging',
        kind: 'live_service',
        locator: 'https://staging.example.test',
        identity_sha256: SHA_B,
      }],
      remove: [],
    },
    paths: {
      add: [{ target_id: 'api-staging', path: '/api/admin/' }],
      remove: [],
    },
    methods: { add: ['POST'], remove: [] },
    strategy_families: {
      add: ['authorization-and-tenant-replay'],
      remove: [],
    },
    data_classes: { add: ['synthetic-account-data'], remove: [] },
    impact_permissions: { add: ['state-change'], remove: [] },
    limits: {
      add: [{ limit_id: 'max-requests', value: 25, unit: 'count' }],
      remove: [],
    },
    validity: {
      add: [{
        not_before: '2026-09-03T10:00:00.000Z',
        not_after: '2026-09-03T11:00:00.000Z',
      }],
      remove: [],
    },
    ...overrides,
  }
}

function requestOptions(overrides = {}) {
  return {
    requestId: 'scope-request-001',
    engagementId: 'engagement-001',
    requestedAt: '2026-09-03T09:00:00.000Z',
    baseScopeRevision: 4,
    baseScopeSha256: SHA_A,
    delta: delta(),
    rationale: 'The tenant-admin candidate cannot be tested inside the current path perimeter.',
    blockedObjective: 'Validate candidate cand-authz-001 with a two-subject control.',
    discoveryEvidence: [
      { evidence_id: 'passive-route-map', sha256: SHA_C },
      { evidence_id: 'candidate-record', sha256: SHA_B },
    ],
    expectedRisk: 'One synthetic tenant record may be created.',
    sideEffects: 'A synthetic audit event is expected.',
    cleanupPlan: 'Delete the synthetic record and verify absence by identifier.',
    eligibleActionPlan: 'POST one synthetic record, replay as the other tenant, then clean up.',
    attackPlanSha256: SHA_D,
    ...overrides,
  }
}

function operatorDecision(request, overrides = {}) {
  return createAdversarialScopeDecision({
    decisionId: 'scope-decision-001',
    request,
    disposition: 'APPROVE',
    rationale: 'The exact bounded expansion is authorized.',
    decidedAt: '2026-09-03T09:05:00.000Z',
    now: DECISION_NOW,
    operatorId: 'operator:engagement-owner',
    authorizationReference: 'operator-directive:scope-expansion-001',
    ...overrides,
  })
}

test('request creation is synchronous, inert, canonical, and predecessor-bound', () => {
  const priorFetch = globalThis.fetch
  let targetIo = 0
  globalThis.fetch = async () => {
    targetIo += 1
    throw new Error('scope requests must never perform target I/O')
  }
  try {
    const request = createAdversarialScopeRequest(requestOptions())
    assert.equal(request instanceof Promise, false)
    assert.equal(targetIo, 0)
    assert.equal(request.base_scope.revision, 4)
    assert.equal(request.base_scope.sha256, SHA_A)
    assert.equal(request.delta_sha256.length, 64)
    assert.equal(request.request_sha256, adversarialScopeRequestDigest(request))
    assert.deepEqual(
      request.discovery_evidence.map(({ evidence_id: id }) => id),
      ['candidate-record', 'passive-route-map'],
      'set-like evidence is canonicalized rather than caller-order-bound',
    )
    assert.equal(Object.isFrozen(request), true)
    assert.equal(Object.isFrozen(request.delta.targets.add[0]), true)
    assert.equal(assertValidAdversarialScopeRequest(request), request)
  } finally {
    globalThis.fetch = priorFetch
  }
})

test('an exact operator statement resolves scope without a signing key', () => {
  const request = createAdversarialScopeRequest(requestOptions())
  const decision = createAdversarialScopeDecision({
    decisionId: 'scope-decision-operator-statement-001',
    request,
    disposition: 'APPROVE',
    rationale: 'The exact bounded expansion is authorized.',
    decidedAt: '2026-09-03T09:05:00.000Z',
    now: DECISION_NOW,
    operatorId: 'operator:engagement-owner',
    authorizationReference: 'operator-directive:scope-expansion-001',
    statement: 'I confirm this exact scope decision.',
  })

  const resolved = resolveAdversarialScopeRequest({ request, decision, now: DECISION_NOW })
  assert.equal(resolved.disposition, 'APPROVE')
  assert.equal(resolved.revision.previous_scope_sha256, SHA_A)
  assert.equal(resolved.revision.request_sha256, request.request_sha256)
  assert.equal(resolved.revision.operator_decision.operator_id, 'operator:engagement-owner')
  assert.equal('signing' in resolved.revision.operator_decision, false)
  assert.equal('signature' in resolved.revision.operator_decision, false)
})

test('scope decisions are controller-current and expire before they can change scope', () => {
  const request = createAdversarialScopeRequest(requestOptions())
  assert.throws(
    () => operatorDecision(request, {
      decidedAt: '2026-09-03T09:06:00.000Z',
      now: DECISION_NOW,
    }),
    (error) => error.code === 'ADVERSARIAL_SCOPE_DECISION_FUTURE',
  )

  const decision = operatorDecision(request)
  assert.equal(decision.valid_until, '2026-09-03T09:10:00.000Z')
  assert.throws(
    () => resolveAdversarialScopeRequest({
      request,
      decision,
      now: '2026-09-03T09:10:00.001Z',
    }),
    (error) => error.code === 'ADVERSARIAL_SCOPE_DECISION_EXPIRED',
  )

  const forgedWindow = structuredClone(decision)
  forgedWindow.valid_until = '2026-09-03T10:10:00.000Z'
  assert.throws(
    () => verifyAdversarialScopeDecision({ request, decision: forgedWindow }),
    (error) => error.code === 'ADVERSARIAL_SCOPE_DECISION_WINDOW_INVALID',
  )
})

test('every governed delta category participates in the request digest', () => {
  const request = createAdversarialScopeRequest(requestOptions())
  const edits = {
    targets(value) { value.delta.targets.add[0].locator += '/v2' },
    paths(value) { value.delta.paths.add[0].path += 'reports/' },
    methods(value) { value.delta.methods.add[0] = 'PUT' },
    strategy_families(value) { value.delta.strategy_families.add[0] = 'workflow-race-testing' },
    data_classes(value) { value.delta.data_classes.add[0] = 'customer-metadata' },
    impact_permissions(value) { value.delta.impact_permissions.add[0] = 'availability-impact' },
    limits(value) { value.delta.limits.add[0].value += 1 },
    validity(value) { value.delta.validity.add[0].not_after = '2026-09-03T11:01:00.000Z' },
  }
  for (const [category, edit] of Object.entries(edits)) {
    const changed = structuredClone(request)
    edit(changed)
    assert.notEqual(
      adversarialScopeRequestDigest(changed),
      request.request_sha256,
      `${category} edits must change the request digest`,
    )
  }
})

test('request contracts reject an empty delta, overlap, and malformed validity', () => {
  const empty = delta()
  for (const category of Object.values(empty)) {
    category.add = []
    category.remove = []
  }
  assert.throws(
    () => createAdversarialScopeRequest(requestOptions({ delta: empty })),
    (error) => error instanceof AdversarialScopeContractError
      && error.code === 'ADVERSARIAL_SCOPE_DELTA_EMPTY',
  )

  const overlap = delta({ methods: { add: ['POST'], remove: ['POST'] } })
  assert.throws(
    () => createAdversarialScopeRequest(requestOptions({ delta: overlap })),
    (error) => error instanceof AdversarialScopeContractError
      && error.code === 'ADVERSARIAL_SCOPE_DELTA_OVERLAP',
  )

  const invalidWindow = delta()
  invalidWindow.validity.add[0].not_after = invalidWindow.validity.add[0].not_before
  assert.throws(
    () => createAdversarialScopeRequest(requestOptions({ delta: invalidWindow })),
    (error) => error instanceof AdversarialScopeContractError
      && error.code === 'ADVERSARIAL_SCOPE_VALIDITY_INVALID',
  )
})

test('one exact operator decision creates a predecessor-bound successor', () => {
  const request = createAdversarialScopeRequest(requestOptions())
  const decision = operatorDecision(request)
  const verified = verifyAdversarialScopeDecision({
    request,
    decision,
  })
  assert.equal(verified, decision)

  const resolved = resolveAdversarialScopeRequest({
    request,
    decision,
    now: DECISION_NOW,
  })
  assert.equal(resolved.disposition, 'APPROVE')
  assert.ok(resolved.revision)
  assert.equal(resolved.revision.scope_revision, 5)
  assert.equal(resolved.revision.previous_scope_sha256, SHA_A)
  assert.equal(resolved.revision.request_sha256, request.request_sha256)
  assert.equal(resolved.revision.operator_decision.operator_id, 'operator:engagement-owner')
  assert.equal(
    resolved.revision.operator_decision.authority_basis,
    'OPERATOR_DECLARATION_ACCEPTED_AS_FACT',
  )
  assert.equal('signature' in resolved.revision.operator_decision, false)
  assert.equal('key_id' in resolved.revision.operator_decision, false)
  assert.equal(resolved.revision.attack_plan_sha256, SHA_D)
  assert.equal(
    resolved.revision.scope_sha256,
    adversarialScopeRevisionDigest(resolved.revision),
  )
  assert.equal(Object.isFrozen(resolved.revision), true)
  assert.equal(
    assertValidAdversarialScopeRevision(resolved.revision, {
      request,
    }),
    resolved.revision,
  )
})

test('operator-decision tampering and request drift fail closed', () => {
  const request = createAdversarialScopeRequest(requestOptions())
  const decision = operatorDecision(request)

  for (const mutate of [
    (value) => { value.statement = 'Approve this scope.' },
    (value) => { value.authority_basis = 'CALLER_ASSERTED' },
    (value) => { value.unbounded_override = true },
  ]) {
    const tampered = structuredClone(decision)
    mutate(tampered)
    assert.throws(
      () => verifyAdversarialScopeDecision({ request, decision: tampered }),
      (error) => error.code === 'ADVERSARIAL_SCOPE_DECISION_SCHEMA_INVALID',
    )
  }

  const requestDrift = structuredClone(decision)
  requestDrift.request_sha256 = SHA_C
  assert.throws(
    () => verifyAdversarialScopeDecision({ request, decision: requestDrift }),
    (error) => error.code === 'ADVERSARIAL_SCOPE_DECISION_BINDING_MISMATCH',
  )

  const deltaDrift = structuredClone(decision)
  deltaDrift.approved_delta.methods.add = ['PUT']
  assert.throws(
    () => verifyAdversarialScopeDecision({ request, decision: deltaDrift }),
    (error) => error.code === 'ADVERSARIAL_SCOPE_DELTA_DIGEST_MISMATCH',
  )
})

test('deny and defer are exact operator decisions but never scope revisions', () => {
  const request = createAdversarialScopeRequest(requestOptions())
  for (const disposition of ['DENY', 'DEFER']) {
    const decision = operatorDecision(request, {
      decisionId: `scope-decision-${disposition.toLowerCase()}`,
      disposition,
      rationale: disposition === 'DENY'
        ? 'The requested impact is outside the program policy.'
        : 'Awaiting written confirmation from the asset owner.',
    })
    const resolved = resolveAdversarialScopeRequest({
      request,
      decision,
      now: DECISION_NOW,
    })
    assert.equal(resolved.disposition, disposition)
    assert.equal(resolved.revision, null)
  }
})

test('a narrowed decision is a strict subset and rebinds a disclosed attack plan', () => {
  const requestedDelta = delta({
    methods: { add: ['POST', 'PUT'], remove: [] },
    impact_permissions: { add: ['state-change', 'account-modification'], remove: [] },
  })
  const request = createAdversarialScopeRequest(requestOptions({ delta: requestedDelta }))
  const narrowed = structuredClone(request.delta)
  narrowed.methods.add = ['POST']
  narrowed.impact_permissions.add = ['state-change']
  const decision = operatorDecision(request, {
    disposition: 'NARROW',
    approvedDelta: narrowed,
    attackPlanSha256: SHA_C,
  })
  const result = resolveAdversarialScopeRequest({
    request,
    decision,
    now: DECISION_NOW,
  })
  assert.equal(result.disposition, 'NARROW')
  assert.deepEqual(result.revision.operator_decision.approved_delta, narrowed)
  assert.equal(result.revision.attack_plan_sha256, SHA_C)

  const broadened = structuredClone(narrowed)
  broadened.methods.add.push('DELETE')
  assert.throws(
    () => operatorDecision(request, {
      disposition: 'NARROW',
      approvedDelta: broadened,
      attackPlanSha256: SHA_C,
    }),
    (error) => error.code === 'ADVERSARIAL_SCOPE_NARROWING_INVALID',
  )
  assert.throws(
    () => operatorDecision(request, {
      disposition: 'NARROW',
      approvedDelta: narrowed,
      attackPlanSha256: request.attack_plan_sha256,
    }),
    (error) => error.code === 'ADVERSARIAL_SCOPE_ATTACK_PLAN_REBIND_REQUIRED',
  )
})

test('scope decision never silently authorizes a changed or undisclosed attack plan', () => {
  const request = createAdversarialScopeRequest(requestOptions())
  assert.throws(
    () => operatorDecision(request, { attackPlanSha256: SHA_C }),
    (error) => error.code === 'ADVERSARIAL_SCOPE_ATTACK_PLAN_BINDING_MISMATCH',
  )

  const withoutPlan = createAdversarialScopeRequest(requestOptions({
    attackPlanSha256: undefined,
  }))
  assert.throws(
    () => operatorDecision(withoutPlan, { attackPlanSha256: SHA_C }),
    (error) => error.code === 'ADVERSARIAL_SCOPE_ATTACK_PLAN_BINDING_MISMATCH',
  )
})

test('successor edits change the digest and fail revision validation', () => {
  const request = createAdversarialScopeRequest(requestOptions())
  const result = resolveAdversarialScopeRequest({
    request,
    decision: operatorDecision(request),
    now: DECISION_NOW,
  })
  const edited = structuredClone(result.revision)
  edited.scope_revision += 1
  assert.notEqual(
    adversarialScopeRevisionDigest(edited),
    result.revision.scope_sha256,
  )
  assert.throws(
    () => assertValidAdversarialScopeRevision(edited, {
      request,
    }),
    (error) => error.code === 'ADVERSARIAL_SCOPE_REVISION_DIGEST_MISMATCH',
  )
})

test('canonical persistence bytes and append verification bind the live predecessor head', () => {
  const request = createAdversarialScopeRequest(requestOptions())
  const result = resolveAdversarialScopeRequest({
    request,
    decision: operatorDecision(request),
    now: DECISION_NOW,
  })

  const reorderedRequest = structuredClone(request)
  reorderedRequest.discovery_evidence.reverse()
  reorderedRequest.delta.methods.add.reverse()
  assert.equal(
    canonicalAdversarialScopeRequest(reorderedRequest),
    canonicalAdversarialScopeRequest(request),
    'canonical persistence must collapse equivalent set ordering',
  )
  assert.deepEqual(
    JSON.parse(canonicalAdversarialScopeRequest(request)),
    request,
  )
  assert.deepEqual(
    JSON.parse(canonicalAdversarialScopeDecision(result.decision, {
      request,
    })),
    result.decision,
  )
  assert.deepEqual(
    JSON.parse(canonicalAdversarialScopeRevision(result.revision, {
      request,
    })),
    result.revision,
  )
  assert.equal(
    assertAdversarialScopeSuccessorAppend({
      currentScope: request.base_scope,
      request,
      successorRevision: result.revision,
      now: DECISION_NOW,
    }),
    result.revision,
  )
  assert.throws(
    () => assertAdversarialScopeSuccessorAppend({
      currentScope: {
        revision: request.base_scope.revision + 1,
        sha256: SHA_B,
      },
      request,
      successorRevision: result.revision,
      now: DECISION_NOW,
    }),
    (error) => error.code === 'ADVERSARIAL_SCOPE_PREDECESSOR_MISMATCH',
    'a stale request must not append after the live scope head advances',
  )
})
