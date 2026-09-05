import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  BOUNTY_SCOPE_SCHEMA_VERSION,
  assertValidBountyScope,
  digestPolicySnapshot,
} from '../scripts/lib/bounty-contracts.mjs'

function validScope() {
  return {
    schema_version: BOUNTY_SCOPE_SCHEMA_VERSION,
    kind: 'red-team-audit/bounty-scope',
    engagement_id: 'ywh-acme-2026-08',
    platform: 'yeswehack',
    environment: 'production',
    data_class: 'non_phi',
    program: {
      program_handle: 'acme-public',
      policy_url: 'https://yeswehack.com/programs/acme-public',
      policy_snapshot_sha256: 'a'.repeat(64),
      required_user_agent: 'BugBounty-acme',
    },
    authorization: {
      mode: 'PROGRAM_POLICY_SEALED',
      authorization_id: 'auth-001',
      statement: 'Operator declares enrollment in the named bounty program.',
      operator_id: 'operator-1',
      authorized_by: 'ACME via YesWeHack program policy',
      authorization_reference: 'https://yeswehack.com/programs/acme-public',
      attested_at: '2026-08-20T12:00:00.000Z',
      independently_verified: false,
      permissions: {
        active_testing: true,
        production: true,
        third_party: false,
        phi: false,
        mutation: false,
        automation_allowed: true,
        intensity: 'normal',
        desync_probes: false,
        rate_limit_rps: 5,
      },
    },
    validity: { not_before: '2026-08-20T00:00:00.000Z', not_after: '2026-11-20T00:00:00.000Z' },
    scope_rules: {
      allow: [{ rule_id: 'a1', host_kind: 'wildcard', host: 'acme.example' }],
      deny: [],
    },
    stop_conditions: { max_findings: 100, operator_stop: false },
  }
}

test('accepts a well formed sealed scope', () => {
  assert.doesNotThrow(() => assertValidBountyScope(validScope()))
})

test('refuses phi true', () => {
  const scope = validScope()
  scope.authorization.permissions.phi = true
  assert.throws(() => assertValidBountyScope(scope), /phi/)
})

test('refuses an intensity outside the sealed enum', () => {
  const scope = validScope()
  scope.authorization.permissions.intensity = 'nuclear'
  assert.throws(() => assertValidBountyScope(scope), /intensity/)
})

test('accepts every sealed intensity tier', () => {
  for (const intensity of ['normal', 'aggressive', 'ham']) {
    const scope = validScope()
    scope.authorization.permissions.intensity = intensity
    assert.doesNotThrow(() => assertValidBountyScope(scope), intensity)
  }
})

test('refuses a phi or unknown data class', () => {
  for (const dataClass of ['phi', 'unknown']) {
    const scope = validScope()
    scope.data_class = dataClass
    assert.throws(() => assertValidBountyScope(scope), /data_class/)
  }
})

test('refuses an authorization mode from another protocol', () => {
  const scope = validScope()
  scope.authorization.mode = 'OPERATOR_ATTESTED_AUTHED'
  assert.throws(() => assertValidBountyScope(scope), /mode/)
})

test('refuses independently_verified true', () => {
  const scope = validScope()
  scope.authorization.independently_verified = true
  assert.throws(() => assertValidBountyScope(scope), /independently_verified/)
})

test('refuses a missing policy snapshot digest', () => {
  const scope = validScope()
  delete scope.program.policy_snapshot_sha256
  assert.throws(() => assertValidBountyScope(scope), /policy_snapshot_sha256/)
})

test('refuses an empty allow list', () => {
  const scope = validScope()
  scope.scope_rules.allow = []
  assert.throws(() => assertValidBountyScope(scope), /allow/)
})

test('refuses unknown top level properties', () => {
  const scope = validScope()
  scope.extra_field = 'nope'
  assert.throws(() => assertValidBountyScope(scope), /extra_field/)
})

test('digests a policy snapshot to lowercase hex sha256', () => {
  const digest = digestPolicySnapshot('policy text\n')
  assert.match(digest, /^[0-9a-f]{64}$/)
  assert.equal(digest, digestPolicySnapshot(Buffer.from('policy text\n')))
  assert.notEqual(digest, digestPolicySnapshot('policy text changed\n'))
})
