import assert from 'node:assert/strict'
import { test } from 'node:test'

import {
  HttpAuthedJsonShapeError,
  observeHttpAuthedJsonShape,
  sanitizeHttpAuthedJsonShape,
} from '../scripts/lib/http-authed-json-shape.mjs'

function jsonResponse(value, contentType = 'application/json; charset=utf-8') {
  return {
    headers: [{ name: 'content-type', value: contentType }],
    bodyChunks: [Buffer.from(JSON.stringify(value), 'utf8')],
  }
}

function observeJson(value, safeKeyNames, options = {}) {
  return observeHttpAuthedJsonShape({
    ...jsonResponse(value),
    safeKeyNames,
    ...options,
  })
}

function observeAspNetD(value, safeKeyNames, options = {}) {
  return observeHttpAuthedJsonShape({
    ...jsonResponse({ d: JSON.stringify(value) }),
    safeKeyNames,
    mode: 'ASPNET_D_JSON_SHAPE_ONLY',
    ...options,
  })
}

test('JSON shape observer retains bounded schema metadata without scalar values', () => {
  const secretName = 'SYNTHETIC_PATIENT_NAME_SHOULD_NOT_PERSIST'
  const secretCode = 'SYNTHETIC_CLINICAL_CODE_SHOULD_NOT_PERSIST'
  const shape = observeJson({
    client: {
      id: 8675309,
      name: secretName,
      active: true,
      notes: null,
    },
    items: [
      { code: secretCode },
      { code: 42, nested: { flag: false } },
    ],
  }, ['active', 'client', 'code', 'flag', 'id', 'items', 'name', 'nested', 'notes'])

  assert.deepEqual(shape, {
    kind: 'red-team-audit/http-authed-json-shape',
    schema_version: '1.0.0',
    root_type: 'object',
    object_count: 5,
    array_count: 1,
    key_names: ['active', 'client', 'code', 'flag', 'id', 'items', 'name', 'nested', 'notes'],
    value_types: [
      { path: ['client'], types: ['object'] },
      { path: ['client', 'active'], types: ['boolean'] },
      { path: ['client', 'id'], types: ['number'] },
      { path: ['client', 'name'], types: ['string'] },
      { path: ['client', 'notes'], types: ['null'] },
      { path: ['items'], types: ['array'] },
      { path: ['items', '[]'], types: ['object'] },
      { path: ['items', '[]', 'code'], types: ['number', 'string'] },
      { path: ['items', '[]', 'nested'], types: ['object'] },
      { path: ['items', '[]', 'nested', 'flag'], types: ['boolean'] },
    ],
    max_depth_observed: 4,
    omitted_key_count: 0,
    truncated: false,
  })

  const rendered = JSON.stringify(shape)
  assert.equal(rendered.includes(secretName), false)
  assert.equal(rendered.includes(secretCode), false)
  assert.equal(rendered.includes('8675309'), false)
  assert.doesNotMatch(rendered, /[a-f0-9]{64}/)
})

test('ASP.NET d observer projects exactly one JSON string without retaining scalar values', () => {
  const secret = 'SYNTHETIC_ASMX_VALUE_MUST_NOT_PERSIST'
  const shape = observeAspNetD({
    records: [
      { id: 41, label: secret },
      { id: '42', dynamic: { hidden: true } },
    ],
  }, ['id', 'label', 'records'])

  assert.deepEqual(shape, {
    kind: 'red-team-audit/http-authed-json-shape',
    schema_version: '1.1.0',
    projection: 'ASPNET_D_JSON_STRING',
    root_type: 'object',
    object_count: 4,
    array_count: 1,
    key_names: ['id', 'label', 'records'],
    value_types: [
      { path: ['records'], types: ['array'] },
      { path: ['records', '[]'], types: ['object'] },
      { path: ['records', '[]', '*'], types: ['object'] },
      { path: ['records', '[]', '*', '*'], types: ['boolean'] },
      { path: ['records', '[]', 'id'], types: ['number', 'string'] },
      { path: ['records', '[]', 'label'], types: ['string'] },
    ],
    max_depth_observed: 4,
    omitted_key_count: 2,
    truncated: true,
  })
  assert.equal(JSON.stringify(shape).includes(secret), false)
  assert.equal(shape.key_names.includes('d'), false)
})

test('ASP.NET d observer fails closed on envelope drift, invalid inner JSON, and markup', () => {
  const marker = 'SYNTHETIC_ASMX_SECRET_MUST_NOT_ESCAPE'
  const cases = [
    {
      value: { d: JSON.stringify({ id: 1 }), extra: true },
      code: 'HTTP_AUTHED_JSON_SHAPE_ASPNET_ENVELOPE_INVALID',
    },
    {
      value: { d: null },
      code: 'HTTP_AUTHED_JSON_SHAPE_ASPNET_ENVELOPE_INVALID',
    },
    {
      value: { d: `{\"id\":\"${marker}\"` },
      code: 'HTTP_AUTHED_JSON_SHAPE_ASPNET_D_PARSE_FAILED',
    },
    {
      value: { d: `<html>${marker}</html>` },
      code: 'HTTP_AUTHED_JSON_SHAPE_ASPNET_D_PARSE_FAILED',
    },
    {
      value: { d: `<root>${marker}</root>` },
      code: 'HTTP_AUTHED_JSON_SHAPE_ASPNET_D_PARSE_FAILED',
    },
  ]

  for (const scenario of cases) {
    assert.throws(
      () => observeHttpAuthedJsonShape({
        ...jsonResponse(scenario.value),
        safeKeyNames: ['id'],
        mode: 'ASPNET_D_JSON_SHAPE_ONLY',
      }),
      (error) => {
        assert.equal(error.code, scenario.code)
        assert.equal(error.message.includes(marker), false)
        return true
      },
    )
  }
})

test('ASP.NET d observer unwraps once and never sniffs non-JSON media or recursively unwraps', () => {
  assert.equal(observeHttpAuthedJsonShape({
    headers: [{ name: 'content-type', value: 'text/html' }],
    bodyChunks: [Buffer.from('{"d":"{\\"id\\":1}"}')],
    safeKeyNames: ['id'],
    mode: 'ASPNET_D_JSON_SHAPE_ONLY',
  }), undefined)

  const shape = observeAspNetD({ d: JSON.stringify({ id: 1 }) }, ['d', 'id'])
  assert.equal(shape.root_type, 'object')
  assert.deepEqual(shape.value_types, [{ path: ['d'], types: ['string'] }])
})

test('observer ignores non-JSON representations and fails closed for malformed claimed JSON', () => {
  assert.equal(observeHttpAuthedJsonShape({
    headers: [{ name: 'content-type', value: 'text/plain' }],
    bodyChunks: [Buffer.from('SYNTHETIC_VALUE')],
  }), undefined)

  const marker = 'SYNTHETIC_MALFORMED_RESPONSE_VALUE'
  assert.throws(
    () => observeHttpAuthedJsonShape({
      headers: [{ name: 'content-type', value: 'application/problem+json' }],
      bodyChunks: [Buffer.from(`{"value":"${marker}"`)],
      safeKeyNames: ['value'],
    }),
    (error) => {
      assert.equal(error instanceof HttpAuthedJsonShapeError, true)
      assert.equal(error.code, 'HTTP_AUTHED_JSON_SHAPE_PARSE_FAILED')
      assert.equal(error.message.includes(marker), false)
      return true
    },
  )

  assert.throws(
    () => observeHttpAuthedJsonShape({
      headers: [
        { name: 'content-type', value: 'application/json' },
        { name: 'content-encoding', value: 'gzip' },
      ],
      bodyChunks: [Buffer.from('{}')],
      safeKeyNames: ['value'],
    }),
    { code: 'HTTP_AUTHED_JSON_SHAPE_REPRESENTATION_UNSUPPORTED' },
  )
})

test('dynamic or unsafe object keys are omitted rather than persisted', () => {
  const dynamicKey = '8675309'
  const unsafeKey = 'Patient Name'
  const shape = observeJson({
    [dynamicKey]: { status: 'SYNTHETIC_PRIVATE_VALUE' },
    [unsafeKey]: false,
    safe_field: 1,
  }, ['safe_field', 'status'])

  assert.deepEqual(shape.key_names, ['safe_field', 'status'])
  assert.equal(shape.omitted_key_count, 2)
  assert.equal(shape.truncated, true)
  assert.equal(JSON.stringify(shape).includes(dynamicKey), false)
  assert.equal(JSON.stringify(shape).includes(unsafeKey), false)
  assert.deepEqual(shape.value_types.find(({ path }) => path.join('/') === '*')?.types, [
    'boolean',
    'object',
  ])
})

test('depth and node limits report honest truncation without retaining descendants', () => {
  const depthLimited = observeJson(
    { one: { two: { three: { four: { five: 'SYNTHETIC_SECRET' } } } } },
    ['one', 'two', 'three', 'four', 'five'],
    { limits: { maxDepth: 2, maxNodes: 100, maxPaths: 100, maxKeys: 100 } },
  )
  assert.equal(depthLimited.truncated, true)
  assert.equal(depthLimited.max_depth_observed, 2)
  assert.equal(depthLimited.key_names.includes('three'), false)
  assert.equal(JSON.stringify(depthLimited).includes('SYNTHETIC_SECRET'), false)

  const nodeLimited = observeJson(
    [1, 2, 3, 4, 5],
    ['unused'],
    { limits: { maxDepth: 4, maxNodes: 2, maxPaths: 100, maxKeys: 100 } },
  )
  assert.equal(nodeLimited.truncated, true)
  assert.equal(nodeLimited.root_type, 'array')
})

test('shape sanitizer rejects injected values and returns canonical metadata', () => {
  const shape = observeJson({ z: 1, a: 'secret' }, ['a', 'z'])
  const reordered = {
    ...shape,
    key_names: ['z', 'a'],
    value_types: [...shape.value_types].reverse(),
  }
  assert.deepEqual(sanitizeHttpAuthedJsonShape(reordered).key_names, ['a', 'z'])

  assert.throws(
    () => sanitizeHttpAuthedJsonShape({ ...shape, response_value: 'SYNTHETIC_SECRET' }),
    { code: 'HTTP_AUTHED_JSON_SHAPE_INVALID' },
  )
  assert.throws(
    () => sanitizeHttpAuthedJsonShape({
      ...shape,
      value_types: [{ path: ['a'], types: ['string'], sample: 'SYNTHETIC_SECRET' }],
    }),
    { code: 'HTTP_AUTHED_JSON_SHAPE_INVALID' },
  )

  const projected = observeAspNetD({ a: 1 }, ['a'])
  assert.throws(
    () => sanitizeHttpAuthedJsonShape(projected, {
      safeKeyNames: ['a'],
      mode: 'JSON_SHAPE_ONLY',
    }),
    { code: 'HTTP_AUTHED_JSON_SHAPE_INVALID' },
  )
  assert.throws(
    () => sanitizeHttpAuthedJsonShape(shape, {
      safeKeyNames: ['a', 'z'],
      mode: 'ASPNET_D_JSON_SHAPE_ONLY',
    }),
    { code: 'HTTP_AUTHED_JSON_SHAPE_INVALID' },
  )
})
