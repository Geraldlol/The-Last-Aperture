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
    requiredUserAgent: 'BugBounty-acme',
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
