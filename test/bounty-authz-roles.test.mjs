import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  ANONYMOUS_ROLE,
  applyRole,
  assertValidRoleRegistry,
  findRole,
  resolveRoleCredential,
  rolesToTest,
} from '../scripts/lib/bounty-authz-roles.mjs'

function registry() {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/bounty-authz-roles',
    roles: [
      { id: 'alice', label: 'owner', auth: { kind: 'header', name: 'Authorization', value_env: 'TB_ALICE' } },
      { id: 'bob', label: 'other', auth: { kind: 'cookie', name: 'session', value_env: 'TB_BOB' } },
    ],
  }
}

const ENV = { TB_ALICE: 'Bearer alice', TB_BOB: 'bobsession' }

const captured = {
  method: 'GET',
  url: 'https://api.acme.example/orders/2',
  headers: { accept: 'application/json', authorization: 'Bearer ORIGINAL', cookie: 'session=ORIGINAL' },
  body: null,
}

test('accepts a valid registry', () => {
  assert.doesNotThrow(() => assertValidRoleRegistry(registry()))
})

test('refuses an inline credential value, which the schema has no property for', () => {
  const bad = registry()
  bad.roles[0].auth.value = 'Bearer literal-secret'
  assert.throws(() => assertValidRoleRegistry(bad))
})

test('refuses an env var name that is not a shouty identifier', () => {
  const bad = registry()
  bad.roles[0].auth.value_env = 'lowercase'
  assert.throws(() => assertValidRoleRegistry(bad))
})

test('refuses an empty role list', () => {
  const bad = registry()
  bad.roles = []
  assert.throws(() => assertValidRoleRegistry(bad))
})

test('applies a header credential and strips the captured one', () => {
  const prepared = applyRole(captured, registry().roles[0], ENV)
  assert.equal(prepared.headers.authorization, 'Bearer alice')
  assert.equal(Object.hasOwn(prepared.headers, 'cookie'), false, 'captured cookie removed')
  assert.equal(prepared.headers.accept, 'application/json')
  assert.equal(prepared.applied_role, 'alice')
})

test('applies a cookie credential', () => {
  const prepared = applyRole(captured, registry().roles[1], ENV)
  assert.equal(prepared.headers.cookie, 'session=bobsession')
  assert.equal(Object.hasOwn(prepared.headers, 'authorization'), false)
})

test('the anonymous role strips every credential the capture carried', () => {
  const prepared = applyRole(captured, ANONYMOUS_ROLE, ENV)
  assert.equal(Object.hasOwn(prepared.headers, 'authorization'), false)
  assert.equal(Object.hasOwn(prepared.headers, 'cookie'), false)
  assert.equal(prepared.applied_role, 'anonymous')
})

test('a missing environment variable throws and names the variable', () => {
  // Silently replaying without the credential would turn every result into a
  // false ACCESS_DENIED and read as "this endpoint is fine".
  assert.throws(
    () => resolveRoleCredential(registry().roles[0], {}),
    /TB_ALICE/,
  )
  assert.throws(
    () => applyRole(captured, registry().roles[1], { TB_ALICE: 'x' }),
    /TB_BOB/,
  )
})

test('an empty environment variable is treated as missing', () => {
  assert.throws(() => resolveRoleCredential(registry().roles[0], { TB_ALICE: '' }), /TB_ALICE/)
})

test('the anonymous role needs no credential', () => {
  assert.equal(resolveRoleCredential(ANONYMOUS_ROLE, {}), null)
})

test('rolesToTest excludes the owner and always includes anonymous', () => {
  const roles = rolesToTest(registry(), 'alice')
  const ids = roles.map((role) => role.id)
  assert.equal(ids.includes('alice'), false)
  assert.ok(ids.includes('bob'))
  assert.ok(ids.includes('anonymous'), 'unauthenticated is the highest-severity question')
})

test('rolesToTest does not duplicate an explicitly declared anonymous role', () => {
  const withAnon = registry()
  withAnon.roles.push({ id: 'anonymous', label: 'none', auth: { kind: 'none' } })
  const ids = rolesToTest(withAnon, 'alice').map((role) => role.id)
  assert.equal(ids.filter((id) => id === 'anonymous').length, 1)
})

test('findRole resolves declared roles and anonymous, and throws on unknown', () => {
  assert.equal(findRole(registry(), 'bob').id, 'bob')
  assert.equal(findRole(registry(), 'anonymous').id, 'anonymous')
  assert.throws(() => findRole(registry(), 'nobody'), /unknown role/)
})
