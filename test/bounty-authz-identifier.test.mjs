import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  assertValidIdentifierMap,
  describeOccurrence,
  findIdentifierOccurrences,
  identifiersInRequest,
  mutationPlan,
  substituteIdentifier,
} from '../scripts/lib/bounty-authz-identifier.mjs'

// The default url deliberately contains NO identifier, so a test focused on the
// body or a header sees only the occurrence it is about. Tests that care about
// the path pass their own url.
function request(overrides = {}) {
  return {
    method: 'GET',
    url: 'https://api.acme.example/api/orders',
    headers: { accept: 'application/json' },
    body: null,
    ...overrides,
  }
}

const pathRequest = (overrides = {}) => request({
  url: 'https://api.acme.example/api/orders/2',
  ...overrides,
})

function identifierMap() {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/bounty-authz-identifiers',
    identifiers: [
      { id: 'order-alice', value: '2', kind: 'order', owner_role: 'alice' },
      { id: 'order-bob', value: '5', kind: 'order', owner_role: 'bob' },
    ],
  }
}

test('finds an identifier in a path segment', () => {
  const found = findIdentifierOccurrences(pathRequest(), '2')
  assert.equal(found.length, 1)
  assert.equal(found[0].location, 'path')
  assert.equal(describeOccurrence(found[0]), 'path:3')
})

test('finds an identifier in a query value', () => {
  const found = findIdentifierOccurrences(
    request({ url: 'https://api.acme.example/api/orders?id=2&page=1' }), '2',
  )
  assert.equal(found.length, 1)
  assert.equal(found[0].location, 'query')
  assert.equal(found[0].pointer, 'id')
})

test('finds an identifier in a nested json scalar, string or number', () => {
  const asNumber = findIdentifierOccurrences(
    request({ method: 'POST', body: JSON.stringify({ order: { id: 2 }, page: 1 }) }), '2',
  )
  assert.equal(asNumber.length, 1)
  assert.equal(asNumber[0].pointer, '/order/id')
  assert.equal(asNumber[0].original, 2)

  const asString = findIdentifierOccurrences(
    request({ method: 'POST', body: JSON.stringify({ ids: ['9', '2'] }) }), '2',
  )
  assert.equal(asString[0].pointer, '/ids/1')
})

test('finds an identifier in a header value', () => {
  const found = findIdentifierOccurrences(
    request({ headers: { 'x-account-id': '2', accept: '*/*' } }), '2',
  )
  assert.equal(found.length, 1)
  assert.equal(found[0].location, 'header')
  assert.equal(found[0].pointer, 'x-account-id')
})

test('never matches a substring inside a larger token', () => {
  // An identifier of "2" must not rewrite an api version, a page number inside a
  // word, or a digit within another id. A mangled request yields a meaningless
  // verdict, which is worse than no test.
  assert.equal(findIdentifierOccurrences(request({ url: 'https://api.acme.example/v2/orders/42' }), '2').length, 0)
  assert.equal(findIdentifierOccurrences(request({ url: 'https://api.acme.example/api/orders/1234' }), '2').length, 0)
  assert.equal(findIdentifierOccurrences(request({ headers: { 'user-agent': 'curl/2.0' } }), '2').length, 0)
  assert.equal(
    findIdentifierOccurrences(request({ method: 'POST', body: JSON.stringify({ note: 'order 2 shipped' }) }), '2').length,
    0,
  )
})

test('finds every occurrence when an identifier appears more than once', () => {
  const found = findIdentifierOccurrences(
    request({ url: 'https://api.acme.example/api/users/2/orders?owner=2' }), '2',
  )
  assert.equal(found.length, 2)
  assert.deepEqual(found.map((o) => o.location).sort(), ['path', 'query'])
})

test('an opaque non-json body is not searched', () => {
  const found = findIdentifierOccurrences(
    request({ method: 'POST', body: 'binary-2-blob' }), '2',
  )
  assert.equal(found.length, 0, 'blind replacement in an opaque payload corrupts the request')
})

test('substitutes in a path segment', () => {
  const found = findIdentifierOccurrences(pathRequest(), '2')
  const mutated = substituteIdentifier(pathRequest(), found[0], '5')
  assert.equal(mutated.url, 'https://api.acme.example/api/orders/5')
})

test('substitutes in a query value', () => {
  const original = request({ url: 'https://api.acme.example/api/orders?id=2&page=1' })
  const found = findIdentifierOccurrences(original, '2')
  const mutated = substituteIdentifier(original, found[0], '5')
  assert.match(mutated.url, /id=5/)
  assert.match(mutated.url, /page=1/, 'other params untouched')
})

test('substitutes in a header', () => {
  const original = request({ headers: { 'x-account-id': '2', accept: '*/*' } })
  const found = findIdentifierOccurrences(original, '2')
  const mutated = substituteIdentifier(original, found[0], '5')
  assert.equal(mutated.headers['x-account-id'], '5')
  assert.equal(mutated.headers.accept, '*/*')
})

test('substitution preserves the original json type', () => {
  const numeric = request({ method: 'POST', body: JSON.stringify({ order: { id: 2 } }) })
  const numericFound = findIdentifierOccurrences(numeric, '2')
  const numericMutated = substituteIdentifier(numeric, numericFound[0], '5')
  assert.equal(JSON.parse(numericMutated.body).order.id, 5)
  assert.equal(typeof JSON.parse(numericMutated.body).order.id, 'number')

  const stringy = request({ method: 'POST', body: JSON.stringify({ order: { id: '2' } }) })
  const stringyFound = findIdentifierOccurrences(stringy, '2')
  const stringyMutated = substituteIdentifier(stringy, stringyFound[0], '5')
  assert.equal(typeof JSON.parse(stringyMutated.body).order.id, 'string')
})

test('substitution does not mutate the original request', () => {
  const original = request({ method: 'POST', body: JSON.stringify({ order: { id: 2 } }) })
  const found = findIdentifierOccurrences(original, '2')
  substituteIdentifier(original, found[0], '5')
  assert.equal(JSON.parse(original.body).order.id, 2)
  assert.equal(original.url, 'https://api.acme.example/api/orders')
})

test('the mutation plan substitutes only same-kind, other identifiers', () => {
  const identifiers = [
    { id: 'order-alice', value: '2', kind: 'order', owner_role: 'alice' },
    { id: 'order-bob', value: '5', kind: 'order', owner_role: 'bob' },
    { id: 'user-bob', value: '77', kind: 'user', owner_role: 'bob' },
  ]
  const plan = mutationPlan({ identifiers, sourceIdentifier: identifiers[0] })
  assert.deepEqual(plan.map((i) => i.id), ['order-bob'])
})

test('identifiersInRequest pairs each declared identifier with its occurrences', () => {
  const found = identifiersInRequest({ request: pathRequest(), identifiers: identifierMap().identifiers })
  assert.equal(found.length, 1)
  assert.equal(found[0].identifier.id, 'order-alice')
  assert.equal(found[0].occurrence.location, 'path')
})

test('the schema accepts a valid declared map', () => {
  assert.doesNotThrow(() => assertValidIdentifierMap(identifierMap()))
})

test('the schema requires an owning role unless the identifier is declared absent', () => {
  const orphan = identifierMap()
  orphan.identifiers[0].owner_role = null
  assert.throws(() => assertValidIdentifierMap(orphan))

  const absent = identifierMap()
  absent.identifiers.push({ id: 'order-gone', value: '99999999', kind: 'order', owner_role: null, absent: true })
  assert.doesNotThrow(() => assertValidIdentifierMap(absent))
})

test('the schema has no wildcard, range, or pattern form', () => {
  // Enumerating undeclared ids means reading a stranger's data to prove a bug.
  const ranged = identifierMap()
  ranged.identifiers[0].range = { from: 1, to: 1000 }
  assert.throws(() => assertValidIdentifierMap(ranged), /additional|range/)
  const patterned = identifierMap()
  patterned.identifiers[0].pattern = 'order-*'
  assert.throws(() => assertValidIdentifierMap(patterned))
})

test('the schema requires at least two identifiers to have anything to swap', () => {
  const single = identifierMap()
  single.identifiers = [single.identifiers[0]]
  assert.throws(() => assertValidIdentifierMap(single))
})
