import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

import Ajv2020 from 'ajv/dist/2020.js'

import {
  assertValidWebSessionEvidence,
  canonicalWebSessionEvidence,
  digestWebSessionEvidence,
  importWebHarEvidence,
} from '../scripts/lib/reverse-web-har.mjs'

const SOURCE_HASH = 'a'.repeat(64)
const STRUCTURAL_PATH_LITERALS = ['check', 'clients', 'start']
const WEB_SESSION_SCHEMA = JSON.parse(readFileSync(new URL('../schemas/web-session-evidence.schema.json', import.meta.url), 'utf8'))
const validateWebSessionSchema = new Ajv2020({
  strict: true,
  strictTuples: false,
  allErrors: true,
  allowUnionTypes: true,
}).compile(WEB_SESSION_SCHEMA)

function harEntry({
  startedDateTime,
  method = 'GET',
  url,
  requestHeaders = [],
  requestCookies = [],
  postData,
  status = 200,
  responseHeaders = [],
  responseCookies = [],
  responseContent = { mimeType: 'application/json', size: 0 },
  time = 12,
}) {
  return {
    startedDateTime,
    time,
    request: {
      method,
      url,
      headers: requestHeaders,
      cookies: requestCookies,
      ...(postData === undefined ? {} : { postData }),
    },
    response: {
      status,
      headers: responseHeaders,
      cookies: responseCookies,
      content: responseContent,
    },
  }
}

function genericApplicationHar() {
  return {
    log: {
      creator: { name: 'Chrome', version: '140.0.0' },
      entries: [
        harEntry({
          startedDateTime: '2026-09-11T10:00:00.000Z',
          method: 'POST',
          url: 'https://app.example/auth/check?tenant=ExampleTenant&returnUrl=%2Fhome',
          requestHeaders: [
            { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
            { name: 'X-CSRF-Token', value: 'csrf-secret' },
          ],
          postData: {
            mimeType: 'application/x-www-form-urlencoded',
            text: 'username=alice%40example.com&password=hunter2',
            params: [
              { name: 'username', value: 'alice@example.com' },
              { name: 'password', value: 'hunter2' },
            ],
          },
          status: 302,
          responseHeaders: [
            { name: 'Location', value: 'https://app.example/session/start?ticket=top-secret' },
            { name: 'Set-Cookie', value: 'SessionId=session-secret; Secure; HttpOnly' },
          ],
          responseCookies: [{ name: 'SessionId', value: 'session-secret' }],
          responseContent: { mimeType: 'text/html', size: 128, text: 'private response' },
        }),
        harEntry({
          startedDateTime: '2026-09-11T10:00:01.000Z',
          method: 'POST',
          url: 'https://app.example/session/start',
          requestHeaders: [{ name: 'Cookie', value: 'SessionId=session-secret' }],
          requestCookies: [{ name: 'SessionId', value: 'session-secret' }],
          postData: {
            mimeType: 'application/x-www-form-urlencoded',
            params: [{ name: 'SessionId', value: 'session-secret' }],
          },
          status: 302,
          responseHeaders: [
            { name: 'Location', value: 'https://app.example/api/v1/clients/123?view=full' },
            { name: 'Set-Cookie', value: 'SessionToken=cookie-secret; Secure' },
          ],
          responseCookies: [{ name: 'SessionToken', value: 'cookie-secret' }],
        }),
        harEntry({
          startedDateTime: '2026-09-11T10:00:02.000Z',
          url: 'https://app.example/api/v1/clients/123?limit=50&page=1&name=PatientName',
          requestHeaders: [
            { name: 'Accept', value: 'application/json' },
            { name: 'Cookie', value: 'SessionToken=cookie-secret' },
          ],
          requestCookies: [{ name: 'SessionToken', value: 'cookie-secret' }],
          responseContent: {
            mimeType: 'application/json',
            size: 512,
            text: JSON.stringify({ id: 123, name: 'Patient Name', records: [{ ssn: '111-22-3333' }] }),
          },
        }),
        harEntry({
          startedDateTime: '2026-09-11T10:00:03.000Z',
          url: 'https://analytics.example/collect?user=alice',
        }),
      ],
    },
  }
}

test('HAR import emits bounded protocol metadata and removes credential and data values', () => {
  const evidence = importWebHarEvidence(genericApplicationHar(), {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
    pathLiterals: STRUCTURAL_PATH_LITERALS,
  })

  assert.equal(assertValidWebSessionEvidence(evidence), evidence)
  assert.equal(evidence.schema_version, '1.1.0')
  assert.equal(validateWebSessionSchema(evidence), true)
  assert.equal(evidence.entries.length, 3)
  assert.equal(evidence.skipped.off_scope, 1)
  assert.equal(evidence.entries[0].request.path_template, '/auth/check')
  assert.deepEqual(evidence.entries[0].request.query_parameters.map(({ name }) => name), [
    'returnUrl',
    'tenant',
  ])
  assert.deepEqual(evidence.entries[0].request.body.fields.map(({ name }) => name), [
    'password',
    'username',
  ])
  assert.equal(evidence.entries[0].request.body.fields[0].sensitive, true)
  assert.deepEqual(evidence.entries[0].response.cookie_names, ['SessionId'])
  assert.equal(evidence.entries[0].response.redirect.path_template, '/session/start')
  assert.equal(evidence.entries[2].request.path_template, '/api/v1/clients/{integer}')
  assert.deepEqual(evidence.entries[2].response.body.fields.map(({ path }) => path), [
    'id',
    'name',
    'records',
    'records[].ssn',
  ])

  const serialized = canonicalWebSessionEvidence(evidence)
  for (const secret of [
    'ExampleTenant', 'top-secret', 'csrf-secret', 'session-secret', 'cookie-secret',
    'Patient Name', '111-22-3333', 'alice@example.com', 'hunter2', 'private response',
  ]) assert.equal(serialized.includes(secret), false, secret)
  assert.match(digestWebSessionEvidence(evidence), /^[a-f0-9]{64}$/)
})

test('new web evidence uses 1.1.0 while the reader retains the HAR-only 1.0.0 shape', () => {
  const evidence = importWebHarEvidence({ log: { entries: [harEntry({
    url: 'https://app.example/api',
  })] } }, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
  })
  assert.equal(evidence.schema_version, '1.1.0')
  assert.equal(validateWebSessionSchema(evidence), true)

  const compatibleHar = structuredClone(evidence)
  compatibleHar.schema_version = '1.0.0'
  assert.equal(assertValidWebSessionEvidence(compatibleHar), compatibleHar)
  assert.equal(validateWebSessionSchema(compatibleHar), true)

  const mislabeledBurp = structuredClone(compatibleHar)
  mislabeledBurp.source.kind = 'BURP_XML'
  assert.throws(() => assertValidWebSessionEvidence(mislabeledBurp), /1\.0\.0.*HAR/i)
  assert.equal(validateWebSessionSchema(mislabeledBurp), false)
})

test('released 1.0 evidence retains recorded carrier classifications while 1.1 uses current derivation', () => {
  const fixtureUrls = [
    './fixtures/compat/0.12/web-session-evidence-1.0.0-expanded-cookie-carrier.json',
    './fixtures/compat/0.12/web-session-evidence-1.0.0-retired-cookie-carrier.json',
  ]
  for (const fixtureUrl of fixtureUrls) {
    const legacy = JSON.parse(readFileSync(new URL(fixtureUrl, import.meta.url), 'utf8'))
    const before = JSON.stringify(legacy)
    assert.equal(assertValidWebSessionEvidence(legacy), legacy)
    assert.equal(JSON.stringify(legacy), before)
    assert.equal(validateWebSessionSchema(legacy), true, JSON.stringify(validateWebSessionSchema.errors))
    assert.match(digestWebSessionEvidence(legacy), /^[a-f0-9]{64}$/u)

    const changedRecordedClassification = structuredClone(legacy)
    const recorded = changedRecordedClassification.entries[0].response
    if (recorded.credential_carriers.length > 0) recorded.credential_carriers = []
    else recorded.credential_carriers = [`cookie:${recorded.cookie_names[0]}`]
    assert.throws(
      () => assertValidWebSessionEvidence(changedRecordedClassification),
      /credential carriers do not match its shape/i,
    )

    const unsupportedCarrier = structuredClone(legacy)
    unsupportedCarrier.entries[0].response.credential_carriers.push('cookie:notObserved')
    unsupportedCarrier.entries[0].response.credential_carriers.sort()
    assert.throws(
      () => assertValidWebSessionEvidence(unsupportedCarrier),
      /credential carrier.*shape|credential carriers do not match/i,
    )

    const current = structuredClone(legacy)
    current.schema_version = '1.1.0'
    assert.equal(validateWebSessionSchema(current), true, JSON.stringify(validateWebSessionSchema.errors))
    assert.throws(
      () => assertValidWebSessionEvidence(current),
      /credential carriers do not match its shape/i,
    )
  }
})

test('request body buckets prefer a finite representative source size', () => {
  const evidence = importWebHarEvidence({ log: { entries: [
    harEntry({
      method: 'POST',
      url: 'https://app.example/large',
      postData: {
        mimeType: 'application/x-www-form-urlencoded',
        size: 1_048_577,
        params: [{ name: 'token', value: 'x' }],
      },
    }),
    harEntry({
      method: 'POST',
      url: 'https://app.example/representative',
      postData: {
        mimeType: 'application/x-www-form-urlencoded',
        size: 2_048,
        params: [{ name: 'mode', value: 'tiny' }],
      },
    }),
  ] } }, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
    pathLiterals: ['large', 'representative'],
  })

  assert.equal(evidence.entries[0].request.body.byte_bucket, 'OVER_1_MIB')
  assert.equal(evidence.entries[0].request.body.shape_status, 'OMITTED_SIZE_LIMIT')
  assert.deepEqual(evidence.entries[0].request.body.fields, [])
  assert.equal(evidence.entries[1].request.body.byte_bucket, 'LE_4_KIB')
  assert.equal(evidence.entries[1].request.body.shape_status, 'OBSERVED')
  assert.deepEqual(evidence.entries[1].request.body.fields.map(({ name }) => name), ['mode'])
})

test('HAR import preserves field and carrier names needed to reconstruct auth', () => {
  const evidence = importWebHarEvidence(genericApplicationHar(), {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
    pathLiterals: STRUCTURAL_PATH_LITERALS,
  })
  const [login, exchange] = evidence.entries

  assert.deepEqual(login.request.header_names, ['content-type', 'x-csrf-token'])
  assert.deepEqual(login.request.credential_carriers, ['body:password', 'body:username', 'header:x-csrf-token'])
  assert.deepEqual(exchange.request.cookie_names, ['SessionId'])
  assert.deepEqual(exchange.request.credential_carriers, ['body:SessionId', 'cookie:SessionId'])
  assert.deepEqual(exchange.response.cookie_names, ['SessionToken'])
  assert.deepEqual(exchange.response.credential_carriers, ['cookie:SessionToken'])
  assert.deepEqual(exchange.response.redirect.query_parameters.map(({ name }) => name), ['view'])
})

test('HAR import requires explicit canonical origins and rejects malformed input bounds', () => {
  assert.throws(
    () => importWebHarEvidence(genericApplicationHar(), {
      sourceSha256: SOURCE_HASH,
      targetOrigins: [],
    }),
    /origin/i,
  )
  assert.throws(
    () => importWebHarEvidence(genericApplicationHar(), {
      sourceSha256: SOURCE_HASH,
      targetOrigins: ['https://app.example/path'],
    }),
    /origin/i,
  )
  assert.throws(
    () => importWebHarEvidence({ log: { entries: Array(10_001).fill({}) } }, {
      sourceSha256: SOURCE_HASH,
      targetOrigins: ['https://app.example'],
    }),
    /entry limit/i,
  )
})

test('HAR import enforces an exact raw path-prefix boundary before retaining entries', () => {
  const evidence = importWebHarEvidence({ log: { entries: [
    harEntry({
      url: 'https://app.example/app',
      responseHeaders: [{ name: 'Location', value: '/application?ticket=private' }],
      responseContent: {
        mimeType: 'application/json',
        size: 256,
        text: JSON.stringify({
          childUrl: '/app/clients/123?view=full',
          exactUrl: '/app',
          adminUrl: '/admin',
          lookalikeUrl: '/application',
        }),
      },
    }),
    harEntry({ url: 'https://app.example/app/clients/123' }),
    harEntry({ url: 'https://app.example/application' }),
    harEntry({ url: 'https://app.example/admin' }),
    harEntry({ url: 'https://app.example/app%2Fencoded-boundary' }),
    harEntry({ url: 'https://app.example/app/segment%2F..%2F..%2Fadmin' }),
  ] } }, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
    targetPathPrefix: '/app',
    pathLiterals: ['app', 'clients'],
  })

  assert.deepEqual(evidence.entries.map(({ sequence }) => sequence), [1, 2])
  assert.equal(evidence.skipped.off_scope, 4)
  assert.equal(evidence.entries[0].response.redirect, null)
  assert.deepEqual(evidence.entries[0].response.destinations.map((destination) => ({
    field: destination.field_path,
    path: destination.path_template,
  })), [
    { field: 'childUrl', path: '/app/clients/{integer}' },
    { field: 'exactUrl', path: '/app' },
  ])
})

test('HAR import rejects non-canonical and ambiguous target path prefixes', () => {
  const prefixes = [
    'app',
    '//other.example/app',
    '/app/../admin',
    '/app?query=1',
    '/app#fragment',
    '/app%2fadmin',
    '/app%',
  ]
  for (const targetPathPrefix of prefixes) {
    assert.throws(
      () => importWebHarEvidence({ log: { entries: [] } }, {
        sourceSha256: SOURCE_HASH,
        targetOrigins: ['https://app.example'],
        targetPathPrefix,
      }),
      /path prefix|pathname/i,
      targetPathPrefix,
    )
  }
})

test('a trailing slash remains an exact path-prefix boundary', () => {
  const evidence = importWebHarEvidence({ log: { entries: [
    harEntry({ url: 'https://app.example/app' }),
    harEntry({ url: 'https://app.example/app/' }),
    harEntry({ url: 'https://app.example/app/child' }),
  ] } }, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
    targetPathPrefix: '/app/',
  })
  assert.deepEqual(evidence.entries.map(({ sequence }) => sequence), [2, 3])
  assert.equal(evidence.skipped.off_scope, 1)
})

test('validator rejects raw value fields and evidence that claims an audit verdict', () => {
  const evidence = importWebHarEvidence(genericApplicationHar(), {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
    pathLiterals: STRUCTURAL_PATH_LITERALS,
  })
  const withValue = structuredClone(evidence)
  withValue.entries[0].request.query_parameters[0].value = 'secret'
  assert.throws(() => assertValidWebSessionEvidence(withValue), /field|value|invalid/i)
  assert.throws(
    () => assertValidWebSessionEvidence({ ...evidence, security_verdict: 'PASSED' }),
    /verdict/i,
  )
})

test('unknown textual path segments are masked unless explicitly declared structural', () => {
  const sample = { log: { entries: [harEntry({
    method: 'GET',
    url: 'https://app.example/resources/Alice-Smith?action=delete',
    status: 200,
  })] } }
  const masked = importWebHarEvidence(sample, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
    pathLiterals: ['resources'],
  })
  assert.equal(masked.entries[0].request.path_template, '/resources/{segment}')
  assert.deepEqual(masked.entries[0].request.query_parameters[0].semantic_classes, ['WRITE_ACTION'])
  assert.equal(canonicalWebSessionEvidence(masked).includes('Alice-Smith'), false)
  assert.equal(canonicalWebSessionEvidence(masked).includes('delete'), false)

  const forged = structuredClone(masked)
  forged.entries[0].request.path_template = '/resources/123'
  assert.throws(() => assertValidWebSessionEvidence(forged), /canonical/i)
})

test('validator binds sanitized evidence to source, scope, ids, and derived carriers', () => {
  const evidence = importWebHarEvidence(genericApplicationHar(), {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
    pathLiterals: STRUCTURAL_PATH_LITERALS,
  })
  const mutations = [
    (value) => { value.capture_id = `web:${'0'.repeat(32)}` },
    (value) => { value.entries[0].observation_id = `webobs:${'0'.repeat(32)}` },
    (value) => { value.entries[0].request.origin = 'https://other.example' },
    (value) => { value.entries[0].response.redirect.origin = 'https://other.example' },
    (value) => { value.entries[0].request.credential_carriers.push('body:inventedSecret') },
    (value) => { value.entries[0].request.body.fields[0].sensitive = false },
    (value) => { value.entries[0].request.query_parameters.find(({ name }) => name === 'tenant').semantic_classes = ['WRITE_ACTION'] },
  ]
  for (const mutate of mutations) {
    const changed = structuredClone(evidence)
    mutate(changed)
    assert.throws(() => assertValidWebSessionEvidence(changed))
  }
})

test('HAR import masks value-like protocol names and does not classify presentation cookies as credentials', () => {
  const evidence = importWebHarEvidence({ log: { entries: [harEntry({
    method: 'POST',
    url: 'https://app.example/api?test%40example.com=one&999-88-7777=two&stableField=three',
    requestHeaders: [
      { name: '999-88-7777', value: 'private' },
      { name: 'Cookie', value: 'theme=dark; sidebar=collapsed; authorPreference=compact' },
      { name: 'X-Stable-Field', value: 'private' },
    ],
    requestCookies: [
      { name: 'test@example.com', value: 'private' },
      { name: 'authorPreference', value: 'compact' },
      { name: 'sidebar', value: 'collapsed' },
      { name: 'theme', value: 'dark' },
    ],
    postData: {
      mimeType: 'application/x-www-form-urlencoded',
      params: [
        { name: 'test@example.com', value: 'private' },
        { name: '999-88-7777', value: 'private' },
        { name: 'stableField', value: 'private' },
      ],
    },
    responseContent: {
      mimeType: 'application/json',
      size: 128,
      text: JSON.stringify({
        'test@example.com': 'private',
        '999-88-7777': 'private',
        stableField: 'private',
      }),
    },
  })] } }, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
  })

  const [{ request, response }] = evidence.entries
  assert.deepEqual(request.query_parameters.map(({ name }) => name), ['redacted_name', 'stableField'])
  assert.deepEqual(request.header_names, ['cookie', 'x-redacted-name', 'x-stable-field'])
  assert.deepEqual(request.cookie_names, ['authorPreference', 'redacted_name', 'sidebar', 'theme'])
  assert.deepEqual(request.body.fields.map(({ name }) => name), ['redacted_name', 'stableField'])
  assert.deepEqual(response.body.fields.map(({ name }) => name), ['redacted_name', 'stableField'])
  assert.deepEqual(request.credential_carriers, [])
  assert.equal(evidence.redaction.value_like_names_masked, true)

  const serialized = canonicalWebSessionEvidence(evidence)
  assert.equal(serialized.includes('test@example.com'), false)
  assert.equal(serialized.includes('999-88-7777'), false)
})

test('HAR import resolves relative Location and response-body destinations against the request URL', () => {
  const evidence = importWebHarEvidence({ log: { entries: [harEntry({
    method: 'POST',
    url: 'https://app.example/auth/login',
    responseHeaders: [{ name: 'Location', value: 'session/start?ticket=private' }],
    responseContent: {
      mimeType: 'application/json',
      size: 128,
      text: JSON.stringify({ nextUrl: 'clients/123?view=full' }),
    },
  })] } }, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
    pathLiterals: ['clients', 'start'],
  })

  const [{ response }] = evidence.entries
  assert.deepEqual(response.redirect, {
    origin: 'https://app.example',
    path_template: '/auth/session/start',
    query_parameters: [{ name: 'ticket', semantic_classes: [], sensitive: false, types: ['string'] }],
  })
  assert.deepEqual(response.destinations, [{
    field_path: 'nextUrl',
    origin: 'https://app.example',
    path_template: '/auth/clients/{integer}',
    query_parameters: [{ name: 'view', semantic_classes: ['OTHER_ACTION'], sensitive: false, types: ['string'] }],
  }])
})

test('HAR import derives path action class before path segments are masked', () => {
  const evidence = importWebHarEvidence({ log: { entries: [harEntry({
    method: 'GET',
    url: 'https://app.example/records/delete',
  })] } }, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
  })

  assert.equal(evidence.entries[0].request.path_template, '/{segment}/{segment}')
  assert.equal(evidence.entries[0].request.path_action_class, 'WRITE_ACTION')
})

test('app-specific path words require explicit structural declarations', () => {
  const appSpecific = ['workspacealpha', 'workspacebeta', 'workspacegamma', 'workspacedelta', 'workspaceepsilon', 'workspacezeta']
  const sample = { log: { entries: [harEntry({
    url: `https://app.example/${appSpecific.join('/')}`,
  })] } }
  const masked = importWebHarEvidence(sample, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
  })
  const declared = importWebHarEvidence(sample, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
    pathLiterals: appSpecific,
  })

  assert.equal(masked.entries[0].request.path_template, appSpecific.map(() => '/{segment}').join(''))
  assert.equal(declared.entries[0].request.path_template, `/${appSpecific.join('/')}`)
})

test('HAR import caps total query and form parameter pairs even when names repeat', () => {
  const withinLimit = new URLSearchParams()
  for (let index = 0; index < 4_096; index += 1) withinLimit.append('duplicate', String(index))
  const accepted = importWebHarEvidence({ log: { entries: [harEntry({
    url: `https://app.example/api?${withinLimit}`,
  })] } }, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
  })
  assert.deepEqual(accepted.entries[0].request.query_parameters.map(({ name }) => name), ['duplicate'])

  withinLimit.append('duplicate', 'overflow')
  assert.throws(() => importWebHarEvidence({ log: { entries: [harEntry({
    url: `https://app.example/api?${withinLimit}`,
  })] } }, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
  }), /parameter pair limit/i)

  assert.throws(() => importWebHarEvidence({ log: { entries: [harEntry({
    method: 'POST',
    url: 'https://app.example/api',
    postData: {
      mimeType: 'application/x-www-form-urlencoded',
      params: Array.from({ length: 4_097 }, () => ({ name: 'duplicate', value: 'private' })),
    },
  })] } }, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
  }), /parameter pair limit/i)
})

test('HAR import makes body shape omissions and truncation explicit', () => {
  const manyFields = Object.fromEntries(Array.from({ length: 1_025 }, (_, index) => [`field${String(index).padStart(4, '0')}`, index]))
  const overLimitJson = JSON.stringify({ payload: 'x'.repeat(1_048_577) })
  const evidence = importWebHarEvidence({ log: { entries: [
    harEntry({
      method: 'POST',
      url: 'https://app.example/api',
      postData: { mimeType: 'application/json', text: JSON.stringify(manyFields) },
    }),
    harEntry({
      url: 'https://app.example/api/malformed',
      responseContent: { mimeType: 'application/json', size: 1, text: '{' },
    }),
    harEntry({
      method: 'POST',
      url: 'https://app.example/api/large',
      postData: { mimeType: 'application/json', text: overLimitJson },
    }),
  ] } }, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
  })

  assert.equal(evidence.entries[0].request.body.shape_status, 'OBSERVED')
  assert.equal(evidence.entries[0].request.body.fields.length, 1_024)
  assert.equal(evidence.entries[0].request.body.fields_truncated, true)
  assert.equal(evidence.entries[1].response.body.shape_status, 'MALFORMED')
  assert.deepEqual(evidence.entries[1].response.body.fields, [])
  assert.equal(evidence.entries[2].request.body.shape_status, 'OMITTED_SIZE_LIMIT')
  assert.equal(evidence.entries[2].request.body.byte_bucket, 'OVER_1_MIB')
  assert.deepEqual(evidence.entries[2].request.body.fields, [])
  assert.deepEqual(evidence.gaps.map(({ code }) => code), [
    'HAR_METADATA_ONLY',
    'BODY_FIELDS_TRUNCATED',
    'BODY_SHAPE_OMITTED_SIZE_LIMIT',
    'BODY_SHAPE_MALFORMED',
  ])
})

test('HAR import flags destination inventories that exceed their cap', () => {
  const destinations = Object.fromEntries(Array.from({ length: 65 }, (_, index) => [
    `next${String(index).padStart(3, '0')}Url`,
    `route-${index}`,
  ]))
  const evidence = importWebHarEvidence({ log: { entries: [harEntry({
    url: 'https://app.example/api/base',
    responseContent: {
      mimeType: 'application/json',
      size: 2_048,
      text: JSON.stringify(destinations),
    },
  })] } }, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
  })

  assert.equal(evidence.entries[0].response.destinations.length, 64)
  assert.equal(evidence.entries[0].response.destinations_truncated, true)
  assert.equal(evidence.gaps.some(({ code }) => code === 'RESPONSE_DESTINATIONS_TRUNCATED'), true)
})

test('validator enforces per-array and aggregate metadata bounds', () => {
  const evidence = importWebHarEvidence({ log: { entries: [harEntry({
    url: 'https://app.example/api',
  })] } }, {
    sourceSha256: SOURCE_HASH,
    targetOrigins: ['https://app.example'],
  })
  const parameters = Array.from({ length: 1_025 }, (_, index) => ({
    name: `field${String(index).padStart(4, '0')}`,
    semantic_classes: [],
    sensitive: false,
    types: ['string'],
  }))
  const tooManyParameters = structuredClone(evidence)
  tooManyParameters.entries[0].request.query_parameters = parameters
  assert.throws(() => assertValidWebSessionEvidence(tooManyParameters), /parameters/i)

  const tooManyHeaders = structuredClone(evidence)
  tooManyHeaders.entries[0].request.header_names = Array.from({ length: 513 }, (_, index) => `x-field-${String(index).padStart(4, '0')}`)
  assert.throws(() => assertValidWebSessionEvidence(tooManyHeaders), /headers/i)

  const aggregate = structuredClone(evidence)
  const boundedParameters = parameters.slice(0, 1_024)
  aggregate.entries = Array.from({ length: 100 }, (_, index) => {
    const entry = structuredClone(evidence.entries[0])
    entry.sequence = index + 1
    entry.request.query_parameters = boundedParameters
    const id = createHash('sha256').update(`${SOURCE_HASH}\n${entry.sequence}\n${entry.request.method}\n${entry.request.origin}\n${entry.request.path_template}\n${entry.request.path_action_class}`).digest('hex').slice(0, 32)
    entry.observation_id = `webobs:${id}`
    return entry
  })
  assert.throws(() => assertValidWebSessionEvidence(aggregate), /aggregate metadata item limit/i)
})

test('web session schema publishes every runtime array bound', () => {
  const { request, response, redirect, destination, body, field, parameter, limits } = WEB_SESSION_SCHEMA.$defs
  assert.equal(request.properties.query_parameters.maxItems, 1_024)
  assert.equal(request.properties.header_names.maxItems, 512)
  assert.equal(request.properties.cookie_names.maxItems, 512)
  assert.equal(request.properties.credential_carriers.maxItems, 2_048)
  assert.equal(response.properties.destinations.maxItems, 64)
  assert.equal(redirect.properties.query_parameters.maxItems, 1_024)
  assert.equal(destination.properties.query_parameters.maxItems, 1_024)
  assert.equal(body.properties.fields.maxItems, 1_024)
  assert.equal(field.properties.types.maxItems, 8)
  assert.equal(field.properties.semantic_classes.maxItems, 3)
  assert.equal(parameter.properties.semantic_classes.maxItems, 3)
  assert.equal(limits.properties.max_aggregate_metadata_items.const, 100_000)
})
