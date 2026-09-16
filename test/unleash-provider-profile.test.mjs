import assert from 'node:assert/strict'
import { test } from 'node:test'

import { createUnleashReasoningAdapter } from '../scripts/lib/unleash-reasoning-adapter.mjs'
import {
  UNLEASH_PROVIDER_PROTOCOL,
  createUnleashProviderProfile,
} from '../scripts/lib/unleash-provider-profile.mjs'

function adapter() {
  return createUnleashReasoningAdapter({
    identity: {
      adapter_id: 'adapter:synthetic-reasoner',
      adapter_version: '1.0.0',
      adapter_config_sha256: 'a'.repeat(64),
    },
    invoke: async () => Buffer.from('{}'),
  })
}

test('default BORG profile retains every role as one explicit unavailable assignment', () => {
  assert.equal(UNLEASH_PROVIDER_PROTOCOL.protocol_version, '2.0.0')
  assert.equal(UNLEASH_PROVIDER_PROTOCOL.roles.length, 7)
  assert.deepEqual(
    UNLEASH_PROVIDER_PROTOCOL.assignments.map(({ role_id: roleId }) => roleId),
    UNLEASH_PROVIDER_PROTOCOL.roles.map(({ role_id: roleId }) => roleId),
  )
  assert.equal(
    UNLEASH_PROVIDER_PROTOCOL.assignments.every((assignment) => (
      assignment.availability === 'UNAVAILABLE'
      && assignment.reason_code === 'REASONING_ADAPTER_UNAVAILABLE'
      && assignment.adapter_id === null
    )),
    true,
  )
  assert.equal(Object.isFrozen(UNLEASH_PROVIDER_PROTOCOL.assignments), true)
})

test('profile binds an assigned role to one exact adapter identity', () => {
  const reasoner = adapter()
  const profile = createUnleashProviderProfile({
    assignments: [{ roleId: 'attacker:api', adapterIdentity: reasoner.identity }],
  })
  const assigned = profile.assignments.find(({ role_id: roleId }) => roleId === 'attacker:api')

  assert.deepEqual(assigned, {
    role_id: 'attacker:api',
    adapter_id: reasoner.identity.adapter_id,
    adapter_version: reasoner.identity.adapter_version,
    adapter_config_sha256: reasoner.identity.adapter_config_sha256,
    availability: 'AVAILABLE',
    reason_code: null,
  })
  assert.equal(profile.assignments.filter(({ availability }) => availability === 'AVAILABLE').length, 1)
})

test('profile rejects unknown, duplicate, and computed assignments before invoking accessors', () => {
  const reasoner = adapter()
  for (const assignments of [
    [{ roleId: 'attacker:unknown', adapterIdentity: reasoner.identity }],
    [
      { roleId: 'attacker:api', adapterIdentity: reasoner.identity },
      { roleId: 'attacker:api', adapterIdentity: reasoner.identity },
    ],
  ]) assert.throws(() => createUnleashProviderProfile({ assignments }))

  let invoked = false
  const computed = {}
  Object.defineProperty(computed, 'assignments', {
    enumerable: true,
    get() {
      invoked = true
      return []
    },
  })
  assert.throws(() => createUnleashProviderProfile(computed))
  assert.equal(invoked, false)
})
