import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  discoverHttpAuthedCandidates,
  HttpAuthedDiscoveryError,
} from '../scripts/lib/http-authed-discovery.mjs'

function sealedPolicy(overrides = {}) {
  return {
    enabled: true,
    origin: 'https://peerstar-test.example.test',
    path_prefixes: ['/approved'],
    sources: [
      'link_header',
      'location_header',
      'allow_header',
      'html_links',
    ],
    candidate_methods: ['GET', 'HEAD', 'OPTIONS', 'PROPFIND'],
    test_category: 'api_security',
    synthetic_query_values: {
      page: 'SYNTHETIC_PAGE_001',
      subject: 'SYNTHETIC_SUBJECT_001',
    },
    synthetic_path_values: {
      encounter_id: 'SYNTHETIC_ENCOUNTER_001',
      patient_id: 'SYNTHETIC_PATIENT_001',
    },
    max_response_bytes: 1_048_576,
    ...overrides,
  }
}

function sourceAction(overrides = {}) {
  return {
    kind: 'probe',
    method: 'GET',
    url: 'https://peerstar-test.example.test/approved/start',
    test_category: 'api_security',
    expected_effect: 'none',
    ...overrides,
  }
}

test('Link and Location references become synthetic-safe candidate drafts', () => {
  const result = discoverHttpAuthedCandidates({
    policy: sealedPolicy(),
    sourceAction: sourceAction(),
    headers: [
      {
        name: 'link',
        value: '</approved/next?subject=real-record-id>; rel="next", </approved/help>; rel="help"',
      },
      {
        name: 'location',
        value: 'https://peerstar-test.example.test/approved/created?page=real-page-value',
      },
    ],
    bodyChunks: [],
  })

  assert.deepEqual(result.candidates, [
    {
      kind: 'probe',
      test_category: 'api_security',
      method: 'GET',
      url: 'https://peerstar-test.example.test/approved/next?subject=SYNTHETIC_SUBJECT_001',
      expected_effect: 'none',
    },
    {
      kind: 'probe',
      test_category: 'api_security',
      method: 'GET',
      url: 'https://peerstar-test.example.test/approved/help',
      expected_effect: 'none',
    },
    {
      kind: 'probe',
      test_category: 'api_security',
      method: 'GET',
      url: 'https://peerstar-test.example.test/approved/created?page=SYNTHETIC_PAGE_001',
      expected_effect: 'none',
    },
  ])
  assert.deepEqual(result.summary, {
    accepted_count: 3,
    duplicate_count: 0,
    rejected_count: 0,
    rejected_by_code: {},
  })
  assert.deepEqual(result.location_candidate_indexes, [2])
  for (const candidate of result.candidates) {
    assert.equal('sequence' in candidate, false)
    assert.notEqual(candidate.kind, 'mutate')
  }
  assert.doesNotMatch(JSON.stringify(result), /real-record-id|real-page-value/)
})

test('Location provenance survives same-response Link deduplication in either header order', () => {
  for (const headers of [
    [
      { name: 'link', value: '</approved/same>; rel="next"' },
      { name: 'location', value: '/approved/same' },
    ],
    [
      { name: 'location', value: '/approved/same' },
      { name: 'link', value: '</approved/same>; rel="next"' },
    ],
  ]) {
    const result = discoverHttpAuthedCandidates({
      policy: sealedPolicy(),
      sourceAction: sourceAction(),
      headers,
      bodyChunks: [],
    })

    assert.equal(result.candidates.length, 1)
    assert.equal(result.candidates[0].url, 'https://peerstar-test.example.test/approved/same')
    assert.equal(result.accepted_location_count, 1)
    assert.deepEqual(result.location_candidate_indexes, [0])
    assert.equal(result.summary.duplicate_count, 1)
  }
})

test('Location reports its own per-response candidate limit rejection', () => {
  const result = discoverHttpAuthedCandidates({
    policy: sealedPolicy({ max_candidates: 1 }),
    sourceAction: sourceAction(),
    headers: [
      { name: 'link', value: '</approved/unrelated>; rel="next"' },
      { name: 'location', value: '/approved/redirect' },
    ],
    bodyChunks: [],
  })

  assert.deepEqual(result.candidates.map(({ url }) => url), [
    'https://peerstar-test.example.test/approved/unrelated',
  ])
  assert.equal(result.accepted_location_count, 0)
  assert.deepEqual(result.location_candidate_indexes, [])
  assert.equal(result.location_candidate_limit_reached, true)
  assert.deepEqual(result.summary.rejected_by_code, { CANDIDATE_LIMIT_REACHED: 1 })
})

test('Allow methods are intersected with the sealed policy and never create mutations', () => {
  const result = discoverHttpAuthedCandidates({
    policy: sealedPolicy(),
    sourceAction: sourceAction({
      url: 'https://peerstar-test.example.test/approved/resource?subject=live-value',
    }),
    headers: [{ name: 'allow', value: 'GET, PROPFIND, DELETE, lowercase, B@D' }],
    bodyChunks: [],
  })

  assert.deepEqual(
    result.candidates.map(({ kind, method, url }) => ({ kind, method, url })),
    [],
  )
  assert.deepEqual(result.summary.rejected_by_code, {
    METHOD_INVALID: 2,
    METHOD_NOT_ALLOWED: 1,
    METHOD_REQUIRES_DECLARED_ACTION: 1,
  })
  assert.equal(result.summary.duplicate_count, 1)
  assert.equal(result.summary.rejected_count, 4)
  assert.doesNotMatch(JSON.stringify(result), /live-value|DELETE|lowercase|B@D/)
})

test('origin, path boundaries, ambiguous encodings, dot segments, and unknown queries fail closed', () => {
  const rejectedSecrets = [
    'OFF_ORIGIN_SECRET',
    'PREFIX_ESCAPE_SECRET',
    'ENCODED_ESCAPE_SECRET',
    'DOUBLE_ENCODED_ESCAPE_SECRET',
    'DOT_ESCAPE_SECRET',
    'UNKNOWN_QUERY_SECRET',
  ]
  const result = discoverHttpAuthedCandidates({
    policy: sealedPolicy(),
    sourceAction: sourceAction(),
    headers: [
      { name: 'location', value: `https://elsewhere.example.test/approved/${rejectedSecrets[0]}` },
      { name: 'location', value: `/approved-evil/${rejectedSecrets[1]}` },
      { name: 'location', value: `/approved/%2f..%2fadmin/${rejectedSecrets[2]}` },
      { name: 'location', value: `/approved/%252f..%252fadmin/${rejectedSecrets[3]}` },
      { name: 'location', value: `/approved/../admin/${rejectedSecrets[4]}` },
      { name: 'location', value: `/approved/search?token=${rejectedSecrets[5]}` },
    ],
    bodyChunks: [],
  })

  assert.deepEqual(result.candidates, [])
  assert.deepEqual(result.summary, {
    accepted_count: 0,
    duplicate_count: 0,
    rejected_count: 6,
    rejected_by_code: {
      AMBIGUOUS_PATH: 3,
      OFF_ORIGIN: 1,
      PATH_OUT_OF_SCOPE: 1,
      UNKNOWN_QUERY_PARAMETER: 1,
    },
  })
  const rendered = JSON.stringify(result)
  for (const secret of rejectedSecrets) assert.doesNotMatch(rendered, new RegExp(secret))
})

test('bounded HTML parsing handles chunk boundaries, ignores script/comment text, and deduplicates', () => {
  const result = discoverHttpAuthedCandidates({
    policy: sealedPolicy(),
    sourceAction: sourceAction(),
    headers: [
      { name: 'content-type', value: 'text/html; charset=utf-8' },
      { name: 'link', value: '</approved/two>; rel="duplicate"' },
    ],
    bodyChunks: [
      Buffer.from('<!doctype html><!-- <a href="/approved/comment-secret"> -->'),
      Buffer.from('<script>const x = `<a href="/approved/script-secret">`</script>'),
      Buffer.from('<a hr'),
      Buffer.from('ef="/approved/one?subject=discard-me">one</a>'),
      Buffer.from('<a HREF=/approved/two>two</a>'),
      Buffer.from('<link href="/approved/three?page=discard-this-too">'),
    ],
  })

  assert.deepEqual(
    result.candidates.map(({ url }) => url),
    [
      'https://peerstar-test.example.test/approved/two',
      'https://peerstar-test.example.test/approved/one?subject=SYNTHETIC_SUBJECT_001',
      'https://peerstar-test.example.test/approved/three?page=SYNTHETIC_PAGE_001',
    ],
  )
  assert.equal(result.summary.accepted_count, 3)
  assert.equal(result.summary.duplicate_count, 1)
  assert.equal(result.summary.rejected_count, 0)
  assert.doesNotMatch(
    JSON.stringify(result),
    /comment-secret|script-secret|discard-me|discard-this-too/,
  )
})

test('HTML discovery exceeds the former public ceiling within its sealed budget', () => {
  const count = 3_000
  const html = Array.from(
    { length: count },
    (_unused, index) => `<a href="/approved/route-${index}">route</a>`,
  ).join('')
  const result = discoverHttpAuthedCandidates({
    policy: sealedPolicy({ max_candidates: count }),
    sourceAction: sourceAction(),
    headers: [{ name: 'content-type', value: 'text/html' }],
    bodyChunks: [Buffer.from(html)],
  })

  assert.equal(result.candidates.length, count)
  assert.equal(result.summary.accepted_count, count)
  assert.equal(result.summary.rejected_count, 0)
  assert.equal(result.candidates.at(-1).url.endsWith('/approved/route-2999'), true)
})

test('discovery applies the operator-sealed per-response candidate budget', () => {
  const result = discoverHttpAuthedCandidates({
    policy: sealedPolicy({ max_candidates: 2 }),
    sourceAction: sourceAction(),
    headers: [{
      name: 'link',
      value: '</approved/one>; rel="next", </approved/two>; rel="next", </approved/three>; rel="next"',
    }],
    bodyChunks: [],
  })

  assert.deepEqual(result.candidates.map(({ url }) => url), [
    'https://peerstar-test.example.test/approved/one',
    'https://peerstar-test.example.test/approved/two',
  ])
  assert.deepEqual(result.summary.rejected_by_code, { CANDIDATE_LIMIT_REACHED: 1 })
  assert.equal(result.summary.rejected_count, 1)
})

test('oversized, transformed, and non-HTML bodies produce count-only gaps without partial body discovery', () => {
  const scenarios = [
    {
      policy: sealedPolicy({ max_response_bytes: 32 }),
      headers: [{ name: 'content-type', value: 'text/html' }],
      bodyChunks: [Buffer.from('<a href="/approved/body-secret-route">secret route</a>')],
      code: 'BODY_LIMIT_EXCEEDED',
    },
    {
      policy: sealedPolicy(),
      headers: [
        { name: 'content-type', value: 'text/html' },
        { name: 'content-encoding', value: 'gzip' },
      ],
      bodyChunks: [Buffer.from('<a href="/approved/compressed-secret-route">route</a>')],
      code: 'CONTENT_ENCODING_UNSUPPORTED',
    },
    {
      policy: sealedPolicy(),
      headers: [{ name: 'content-type', value: 'application/json' }],
      bodyChunks: [Buffer.from('{"href":"/approved/json-secret-route"}')],
      code: 'CONTENT_TYPE_UNSUPPORTED',
    },
  ]

  for (const scenario of scenarios) {
    const result = discoverHttpAuthedCandidates({
      policy: scenario.policy,
      sourceAction: sourceAction(),
      headers: scenario.headers,
      bodyChunks: scenario.bodyChunks,
    })
    assert.deepEqual(result.candidates, [])
    assert.deepEqual(result.summary.rejected_by_code, { [scenario.code]: 1 })
    assert.equal(result.summary.rejected_count, 1)
    assert.doesNotMatch(JSON.stringify(result), /secret-route/)
  }
})

test('the pure discovery boundary refuses unsafe response headers without echoing values', () => {
  const secret = 'SESSION_SECRET_SHOULD_NEVER_REACH_DISCOVERY'
  assert.throws(
    () => discoverHttpAuthedCandidates({
      policy: sealedPolicy(),
      sourceAction: sourceAction(),
      headers: [{ name: 'set-cookie', value: secret }],
      bodyChunks: [],
    }),
    (error) => {
      assert.equal(error instanceof HttpAuthedDiscoveryError, true)
      assert.equal(error.code, 'HTTP_AUTHED_DISCOVERY_HEADER_UNSAFE')
      assert.doesNotMatch(error.message, new RegExp(secret))
      return true
    },
  )
})

test('disabled sources are ignored and policy-controlled category cannot come from a response', () => {
  const result = discoverHttpAuthedCandidates({
    policy: sealedPolicy({ sources: ['location_header'] }),
    sourceAction: sourceAction(),
    headers: [
      { name: 'allow', value: 'PROPFIND' },
      { name: 'link', value: '</approved/ignored>; test_category="destructive_stress"' },
      { name: 'location', value: '/approved/accepted' },
      { name: 'content-type', value: 'text/html' },
    ],
    bodyChunks: [Buffer.from('<a href="/approved/body-ignored">ignored</a>')],
  })

  assert.deepEqual(result.candidates, [{
    kind: 'probe',
    test_category: 'api_security',
    method: 'GET',
    url: 'https://peerstar-test.example.test/approved/accepted',
    expected_effect: 'none',
  }])
  assert.deepEqual(result.summary, {
    accepted_count: 1,
    duplicate_count: 0,
    rejected_count: 0,
    rejected_by_code: {},
  })
})

test('HTML forms discover only GET actions and never infer a mutation', () => {
  const result = discoverHttpAuthedCandidates({
    policy: sealedPolicy({ sources: ['html_forms'] }),
    sourceAction: sourceAction(),
    headers: [{ name: 'content-type', value: 'text/html; charset=UTF-8' }],
    bodyChunks: [Buffer.from(`
      <form method="GET" action="/approved/search?subject=discarded-record-id"></form>
      <form action='/approved/default-get'></form>
      <form method="POST" action="/approved/POST_SECRET_MUST_NOT_ESCAPE"></form>
      <script>const fake = '<form method="get" action="/approved/script-secret"></form>'</script>
    `)],
  })

  assert.deepEqual(result.candidates, [
    {
      kind: 'probe',
      test_category: 'api_security',
      method: 'GET',
      url: 'https://peerstar-test.example.test/approved/search?subject=SYNTHETIC_SUBJECT_001',
      expected_effect: 'none',
    },
    {
      kind: 'probe',
      test_category: 'api_security',
      method: 'GET',
      url: 'https://peerstar-test.example.test/approved/default-get',
      expected_effect: 'none',
    },
  ])
  assert.deepEqual(result.summary.rejected_by_code, { FORM_METHOD_UNSAFE: 1 })
  assert.equal(result.summary.rejected_count, 1)
  const rendered = JSON.stringify(result)
  assert.doesNotMatch(rendered, /discarded-record-id|POST_SECRET|script-secret/)
  assert.equal(result.candidates.some(({ kind }) => kind === 'mutate'), false)
})

test('JSON discovery traverses only recognized link fields and ignores examples and arbitrary strings', () => {
  const result = discoverHttpAuthedCandidates({
    policy: sealedPolicy({ sources: ['json_links'] }),
    sourceAction: sourceAction(),
    headers: [{ name: 'content-type', value: 'application/hal+json' }],
    bodyChunks: [Buffer.from(JSON.stringify({
      href: '/approved/root-link',
      records: [
        { self: '/approved/record?subject=discard-me' },
        { next: '/approved/page?page=discard-this' },
        { url: '/approved/from-url' },
        { link: '/approved/from-link' },
      ],
      example: { href: '/approved/EXAMPLE_SECRET_IGNORED' },
      description: '/approved/DESCRIPTION_SECRET_IGNORED',
      patient_name: '/approved/PATIENT_NAME_SECRET_IGNORED',
      unknown: { endpoint: '/approved/ENDPOINT_SECRET_IGNORED' },
    }))],
  })

  assert.deepEqual(result.candidates.map(({ url }) => url), [
    'https://peerstar-test.example.test/approved/root-link',
    'https://peerstar-test.example.test/approved/record?subject=SYNTHETIC_SUBJECT_001',
    'https://peerstar-test.example.test/approved/page?page=SYNTHETIC_PAGE_001',
    'https://peerstar-test.example.test/approved/from-url',
    'https://peerstar-test.example.test/approved/from-link',
  ])
  assert.deepEqual(result.summary, {
    accepted_count: 5,
    duplicate_count: 0,
    rejected_count: 0,
    rejected_by_code: {},
  })
  assert.doesNotMatch(
    JSON.stringify(result),
    /discard-me|discard-this|EXAMPLE_SECRET|DESCRIPTION_SECRET|PATIENT_NAME_SECRET|ENDPOINT_SECRET/,
  )
})

test('OpenAPI discovery substitutes every path parameter and intersects sealed methods', () => {
  const result = discoverHttpAuthedCandidates({
    policy: sealedPolicy({
      sources: ['openapi_paths'],
      candidate_methods: ['GET', 'POST'],
    }),
    sourceAction: sourceAction(),
    headers: [{ name: 'content-type', value: 'application/vnd.oai.openapi+json' }],
    bodyChunks: [Buffer.from(JSON.stringify({
      openapi: '3.1.0',
      paths: {
        '/approved/patients/{patient_id}': {
          get: { responses: {} },
          post: { requestBody: {} },
          delete: { responses: {} },
          parameters: [{ example: '/approved/OPERATION_EXAMPLE_SECRET' }],
        },
        '/approved/encounters/{encounter_id}': {
          get: { example: '/approved/NESTED_EXAMPLE_SECRET' },
        },
        '/approved/unknown/{account_id}': { get: {} },
        '/outside/{patient_id}': { get: {} },
      },
      example: { url: '/approved/TOP_LEVEL_EXAMPLE_SECRET' },
    }))],
  })

  assert.deepEqual(
    result.candidates.map(({ kind, method, url }) => ({ kind, method, url })),
    [
      {
        kind: 'probe',
        method: 'GET',
        url: 'https://peerstar-test.example.test/approved/patients/SYNTHETIC_PATIENT_001',
      },
      {
        kind: 'probe',
        method: 'GET',
        url: 'https://peerstar-test.example.test/approved/encounters/SYNTHETIC_ENCOUNTER_001',
      },
    ],
  )
  assert.deepEqual(result.summary.rejected_by_code, {
    METHOD_NOT_ALLOWED: 1,
    METHOD_REQUIRES_DECLARED_ACTION: 1,
    PATH_OUT_OF_SCOPE: 1,
    UNKNOWN_PATH_PARAMETER: 1,
  })
  assert.equal(result.candidates.some(({ kind }) => kind === 'mutate'), false)
  assert.doesNotMatch(
    JSON.stringify(result),
    /account_id|OPERATION_EXAMPLE|NESTED_EXAMPLE|TOP_LEVEL_EXAMPLE/,
  )
})

test('sitemap XML loc entries remain scope-bound and use synthetic query substitutions', () => {
  const result = discoverHttpAuthedCandidates({
    policy: sealedPolicy({ sources: ['sitemap_xml'] }),
    sourceAction: sourceAction(),
    headers: [{ name: 'content-type', value: 'application/sitemap+xml' }],
    bodyChunks: [
      Buffer.from('<?xml version="1.0"?><urlset>'),
      Buffer.from('<url><loc>https://peerstar-test.example.test/approved/one</loc></url>'),
      Buffer.from('<url><loc>/approved/two?subject=discarded&amp;page=also-discarded</loc></url>'),
      Buffer.from('<!-- <loc>/approved/COMMENT_SECRET_IGNORED</loc> -->'),
      Buffer.from('<url><loc>https://other.example.test/approved/OFF_ORIGIN_XML_SECRET</loc></url>'),
      Buffer.from('</urlset>'),
    ],
  })

  assert.deepEqual(result.candidates.map(({ url }) => url), [
    'https://peerstar-test.example.test/approved/one',
    'https://peerstar-test.example.test/approved/two?subject=SYNTHETIC_SUBJECT_001&page=SYNTHETIC_PAGE_001',
  ])
  assert.deepEqual(result.summary.rejected_by_code, { OFF_ORIGIN: 1 })
  assert.doesNotMatch(
    JSON.stringify(result),
    /discarded|also-discarded|COMMENT_SECRET|OFF_ORIGIN_XML_SECRET/,
  )
})

test('body parser selection is content-type gated and does not cross-interpret formats', () => {
  const result = discoverHttpAuthedCandidates({
    policy: sealedPolicy({
      sources: ['html_links', 'json_links', 'openapi_paths', 'sitemap_xml'],
    }),
    sourceAction: sourceAction(),
    headers: [{ name: 'content-type', value: 'application/json' }],
    bodyChunks: [Buffer.from(JSON.stringify({
      href: '/approved/json-only',
      markup: '<a href="/approved/HTML_SECRET_IN_JSON">not HTML</a>',
      xml: '<loc>/approved/XML_SECRET_IN_JSON</loc>',
    }))],
  })

  assert.deepEqual(result.candidates.map(({ url }) => url), [
    'https://peerstar-test.example.test/approved/json-only',
  ])
  assert.deepEqual(result.summary.rejected_by_code, {})
  assert.doesNotMatch(JSON.stringify(result), /HTML_SECRET|XML_SECRET/)
})

test('unsupported content types are refused before transient UTF-8 decoding', () => {
  const result = discoverHttpAuthedCandidates({
    policy: sealedPolicy({ sources: ['html_links', 'json_links', 'sitemap_xml'] }),
    sourceAction: sourceAction(),
    headers: [{ name: 'content-type', value: 'application/octet-stream' }],
    bodyChunks: [Buffer.from([0xff, 0xfe, 0xfd])],
  })

  assert.deepEqual(result.candidates, [])
  assert.deepEqual(result.summary.rejected_by_code, { CONTENT_TYPE_UNSUPPORTED: 1 })
})

test('malformed structured bodies produce count-only parser errors', () => {
  const scenarios = [
    {
      sources: ['json_links'],
      contentType: 'application/json',
      body: '{"href":"/approved/JSON_SECRET"',
      code: 'BODY_JSON_INVALID',
    },
    {
      sources: ['sitemap_xml'],
      contentType: 'application/xml',
      body: '<urlset><loc>/approved/XML_SECRET',
      code: 'BODY_XML_INVALID',
    },
  ]

  for (const scenario of scenarios) {
    const result = discoverHttpAuthedCandidates({
      policy: sealedPolicy({ sources: scenario.sources }),
      sourceAction: sourceAction(),
      headers: [{ name: 'content-type', value: scenario.contentType }],
      bodyChunks: [Buffer.from(scenario.body)],
    })
    assert.deepEqual(result.candidates, [])
    assert.deepEqual(result.summary.rejected_by_code, { [scenario.code]: 1 })
    assert.doesNotMatch(JSON.stringify(result), /JSON_SECRET|XML_SECRET/)
  }
})

test('synthetic OpenAPI path substitutions reject non-synthetic sealed values without echoing them', () => {
  const unsafeValue = 'real-patient-identifier'
  assert.throws(
    () => discoverHttpAuthedCandidates({
      policy: sealedPolicy({
        sources: ['openapi_paths'],
        synthetic_path_values: { patient_id: unsafeValue },
      }),
      sourceAction: sourceAction(),
      headers: [],
      bodyChunks: [],
    }),
    (error) => {
      assert.equal(error.code, 'HTTP_AUTHED_DISCOVERY_POLICY_INVALID')
      assert.doesNotMatch(error.message, new RegExp(unsafeValue))
      return true
    },
  )
})
