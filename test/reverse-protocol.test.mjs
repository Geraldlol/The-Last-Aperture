import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { test } from 'node:test'

import {
  assertValidNativeInteractionContract,
  buildNativeInteractionContract,
  canonicalNativeInteractionContract,
  digestNativeInteractionContract,
} from '../scripts/lib/reverse-protocol.mjs'
import { importWebHarEvidence } from '../scripts/lib/reverse-web-har.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'

const HASH = 'b'.repeat(64)

function rebindContractId(contract) {
  const { contract_id: ignored, ...material } = contract
  contract.contract_id = `interaction:${createHash('sha256').update(stableJson(material, 0)).digest('hex').slice(0, 32)}`
}

function entry({ method, url, requestHeaders = [], requestCookies = [], postData, status = 200, responseHeaders = [], responseCookies = [], content }) {
  return {
    startedDateTime: '2026-09-11T12:00:00.000Z',
    time: 10,
    request: { method, url, headers: requestHeaders, cookies: requestCookies, ...(postData ? { postData } : {}) },
    response: {
      status,
      headers: responseHeaders,
      cookies: responseCookies,
      content: content ?? { mimeType: 'application/json', size: 10, text: '{}' },
    },
  }
}

function webEvidence() {
  const har = { log: { entries: [
    entry({
      method: 'POST',
      url: 'https://portal.example/CheckLogin',
      requestHeaders: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
      postData: { mimeType: 'application/x-www-form-urlencoded', params: [
        { name: 'UserName', value: 'alice' },
        { name: 'Password', value: 'secret' },
      ] },
      status: 200,
      responseHeaders: [{ name: 'Set-Cookie', value: 'SessionCookie=secret' }],
      responseCookies: [{ name: 'SessionCookie', value: 'secret' }],
      content: { mimeType: 'application/json', size: 30, text: '{"Status":"OK","WebsiteURL":"https://portal.example/Home"}' },
    }),
    entry({
      method: 'POST',
      url: 'https://portal.example/SessionStart',
      requestHeaders: [{ name: 'Cookie', value: 'SessionCookie=secret' }],
      requestCookies: [{ name: 'SessionCookie', value: 'secret' }],
      postData: { mimeType: 'application/x-www-form-urlencoded', params: [{ name: 'SessionId', value: 'secret' }] },
      status: 302,
      responseHeaders: [
        { name: 'Location', value: 'https://portal.example/api/clients/42' },
        { name: 'Set-Cookie', value: 'cbh=secret' },
      ],
      responseCookies: [{ name: 'cbh', value: 'secret' }],
    }),
    entry({
      method: 'PUT',
      url: 'https://portal.example/api/clients/42',
      requestCookies: [{ name: 'cbh', value: 'secret' }],
      requestHeaders: [{ name: 'Content-Type', value: 'application/json' }],
      postData: { mimeType: 'application/json', text: '{"status":"active","client_id":42}' },
      status: 204,
      content: { mimeType: 'application/json', size: 0 },
    }),
    entry({
      method: 'GET',
      url: 'https://portal.example/api/clients/42?page=1&limit=25',
      requestCookies: [{ name: 'cbh', value: 'secret' }],
      status: 200,
      content: { mimeType: 'application/json', size: 40, text: '{"status":"active","client_id":42}' },
    }),
  ] } }
  return importWebHarEvidence(har, {
    sourceSha256: HASH,
    targetOrigins: ['https://portal.example'],
    pathLiterals: ['CheckLogin', 'Home', 'SessionStart', 'clients'],
  })
}

test('builds a Credible-style native interaction contract from redacted web evidence', () => {
  const evidence = webEvidence()
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [evidence],
    reverseEvidence: [],
    generatedAt: '2026-09-11T12:01:00.000Z',
  })

  assert.equal(assertValidNativeInteractionContract(contract), contract)
  assert.equal(contract.status, 'DRAFT_OBSERVED')
  assert.equal(contract.generated_client_status, 'CONTRACT_ONLY')
  assert.equal(contract.security_verdict, 'NOT_ASSESSED')
  assert.equal(contract.subjects.origins[0], 'https://portal.example')
  assert.equal(contract.basis.web_session_evidence_sha256.length, 1)
  assert.equal(contract.auth_flows.length, 1)
  assert.deepEqual(contract.auth_flows[0].steps.map(({ request_action: action }) => action), [
    'CREDENTIAL_SUBMIT',
    'AUTHENTICATED_REQUEST',
    'AUTHENTICATED_REQUEST',
    'AUTHENTICATED_REQUEST',
  ])
  assert.deepEqual(contract.auth_flows[0].steps[0].response_transitions, [
    'CREDENTIAL_CARRIER_OBSERVED',
    'REDIRECT_DESTINATION_OBSERVED',
  ])

  const write = contract.endpoints.find(({ method }) => method === 'PUT')
  assert.equal(write.path_template, '/api/clients/{integer}')
  assert.deepEqual(write.side_effect, { classification: 'WRITE_CANDIDATE', basis: 'HTTP_METHOD_ONLY' })
  assert.equal(write.write_verification, 'FOLLOWUP_READ_SAME_TEMPLATE_OBSERVED')
  assert.deepEqual(write.request.fields.map(({ name }) => name), ['client_id', 'status'])
  assert.equal(write.exchanges.length, 1)
  assert.deepEqual(write.exchanges[0].request, {
    action: 'AUTHENTICATED_REQUEST',
    action_basis: 'OBSERVED_CARRIERS',
    credential_carriers: ['cookie:cbh'],
  })
  assert.deepEqual(write.exchanges[0].response, {
    status: 204,
    credential_carriers: [],
    destinations: [],
  })

  const read = contract.endpoints.find(({ method }) => method === 'GET')
  assert.equal(read.pagination, 'OFFSET_OR_PAGE_PARAMETERS_OBSERVED')
  assert.deepEqual(read.side_effect, { classification: 'UNKNOWN', basis: 'UNCLASSIFIED' })
  assert.deepEqual(read.request.query_parameters.map(({ name }) => name), ['limit', 'page'])
  assert.deepEqual(read.auth.request_cookie_names, ['cbh'])

  const login = contract.endpoints.find(({ path_template: path }) => path === '/CheckLogin')
  assert.equal(login.redirects[0].source, 'RESPONSE_BODY_FIELD')
  assert.equal(login.redirects[0].field_path, 'WebsiteURL')
  assert.equal(login.exchanges[0].evidence_ref, contract.auth_flows[0].steps[0].evidence_ref)
  assert.equal(login.exchanges[0].capture_id, contract.auth_flows[0].capture_id)
  assert.equal(login.exchanges[0].sequence, contract.auth_flows[0].steps[0].sequence)
  assert.deepEqual(login.exchanges[0].response.destinations, contract.auth_flows[0].steps[0].destination_candidates)

  const serialized = canonicalNativeInteractionContract(contract)
  for (const secret of ['alice', 'secret', 'active', '42']) {
    assert.equal(serialized.includes(`\"${secret}\"`), false, secret)
  }
  assert.match(digestNativeInteractionContract(contract), /^[a-f0-9]{64}$/)
  assert.equal(contract.redaction.value_like_names_masked, true)
})

test('contract records linked native evidence without upgrading unsupported observations', () => {
  const reverseEvidence = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/reverse-evidence',
    protocol: 'reverse-evidence-v1',
    run_id: 'reverse:0123456789abcdef0123456789abcdef',
    engine: 'ghidra',
    profile_id: 'ghidra-headless-fixed-export-v1',
    started_at: '2026-09-11T12:00:00.000Z',
    finished_at: '2026-09-11T12:00:01.000Z',
    artifact: { kind: 'native-executable', path: 'bin/app.exe', sha256: 'c'.repeat(64), size_bytes: 4096 },
    tool: { name: 'Ghidra', version: '12.1.3', invocation_sha256: 'd'.repeat(64) },
    limits: { timeout_ms: 300000, max_output_bytes: 8192, max_observations: 100 },
    status: 'SUCCEEDED',
    target_execution: 'NOT_PERFORMED',
    security_verdict: 'NOT_ASSESSED',
    applied_to_audit_bundle: false,
    observations: [
      {
        type: 'program-summary', executable_format: 'Portable Executable (PE)',
        executable_sha256: 'c'.repeat(64), language_id: 'x86:LE:64:default',
        compiler_spec_id: 'windows', image_base: '140000000', minimum_address: '140001000',
        maximum_address: '140001100', available_functions: 0, emitted_functions: 0,
        truncated: false,
      },
      {
        type: 'protocol-summary', network_import_limit: 512,
        references_per_import_limit: 128, external_functions_scanned: 0,
        matching_network_imports: 0, emitted_network_imports: 0,
        external_function_scan_truncated: false, network_imports_truncated: false,
        string_record_limit: 100000, string_records_scanned: 0, string_values_scanned: 0,
        truncated_string_values: 0, string_scan_truncated: false, endpoint_limit: 512,
        endpoint_candidates: 0, emitted_endpoints: 0, endpoints_truncated: false,
        auth_hint_limit: 512, auth_hint_candidates: 0, emitted_auth_hints: 0,
        auth_hints_truncated: false,
      },
    ],
    gaps: [],
    cleanup: { attempted: true, verified: true },
  }
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [webEvidence()],
    reverseEvidence: [reverseEvidence],
    generatedAt: '2026-09-11T12:01:00.000Z',
  })
  assert.deepEqual(contract.subjects.artifact_sha256, ['c'.repeat(64)])
  assert.equal(contract.basis.reverse_evidence_sha256.length, 1)
  assert.equal(contract.gaps.some(({ code }) => code === 'NATIVE_OBSERVATIONS_REQUIRE_CORRELATION'), true)
})

test('strict contract rejects value-bearing fields and unsupported claims', () => {
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [webEvidence()],
    reverseEvidence: [],
    generatedAt: '2026-09-11T12:01:00.000Z',
  })
  const forged = structuredClone(contract)
  forged.endpoints[0].request.query_parameters.push({ name: 'token', types: ['string'], value: 'secret' })
  assert.throws(() => assertValidNativeInteractionContract(forged), /field|parameter|invalid/i)
  assert.throws(
    () => assertValidNativeInteractionContract({ ...contract, generated_client_status: 'READY' }),
    /client status/i,
  )
  for (const mutate of [
    (value) => { value.endpoints[0].endpoint_id = `endpoint:${'0'.repeat(32)}` },
    (value) => { value.endpoints[0].method = 'AliceSecret' },
    (value) => { value.endpoints[0].path_template = '/patients/Alice-Smith' },
    (value) => { value.auth_flows[0].steps[0].inputs = ['actual-secret-value'] },
  ]) {
    const changed = structuredClone(contract)
    mutate(changed)
    assert.throws(() => assertValidNativeInteractionContract(changed))
  }
})

test('write-followup and retry hints never correlate across captures', () => {
  const mutation = importWebHarEvidence({ log: { entries: [entry({
    method: 'PUT', url: 'https://portal.example/api/clients/1', status: 204,
  })] } }, { sourceSha256: '1'.repeat(64), targetOrigins: ['https://portal.example'] })
  const unrelatedRead = importWebHarEvidence({ log: { entries: [entry({
    method: 'GET', url: 'https://portal.example/api/clients/999', status: 200,
  })] } }, { sourceSha256: '2'.repeat(64), targetOrigins: ['https://portal.example'] })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [mutation, unrelatedRead], reverseEvidence: [],
    generatedAt: '2026-09-11T12:01:00.000Z',
  })
  const write = contract.endpoints.find(({ method }) => method === 'PUT')
  assert.equal(write.write_verification, 'NOT_OBSERVED')
})

test('side effects are classified independently of the HTTP verb without retaining action values', () => {
  const evidence = importWebHarEvidence({ log: { entries: [entry({
    method: 'GET', url: 'https://portal.example/api/clients/1?action=delete', status: 200,
  })] } }, { sourceSha256: '3'.repeat(64), targetOrigins: ['https://portal.example'] })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [evidence], reverseEvidence: [],
    generatedAt: '2026-09-11T12:01:00.000Z',
  })
  assert.deepEqual(contract.endpoints[0].side_effect, {
    classification: 'WRITE_CANDIDATE',
    basis: 'SEMANTIC_ACTION_CLASS',
  })
  assert.equal(canonicalNativeInteractionContract(contract).includes('delete'), false)
})

test('Credible CheckDataCenter is retained as an authentication request without its values', () => {
  const evidence = importWebHarEvidence({ log: { entries: [entry({
    method: 'POST',
    url: 'https://portal.example/CheckDataCenter',
    postData: {
      mimeType: 'application/x-www-form-urlencoded',
      params: [{ name: 'UserName', value: 'alice' }],
    },
    status: 200,
  })] } }, { sourceSha256: '4'.repeat(64), targetOrigins: ['https://portal.example'], pathLiterals: ['CheckDataCenter'] })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [evidence], reverseEvidence: [],
    generatedAt: '2026-09-11T12:01:00.000Z',
  })
  assert.equal(contract.endpoints[0].path_template, '/CheckDataCenter')
  assert.equal(contract.endpoints[0].protocol_role, 'AUTH')
  assert.equal(contract.auth_flows[0].steps[0].request_action, 'AUTH_REQUEST')
  assert.equal(canonicalNativeInteractionContract(contract).includes('alice'), false)
})

test('contract generation is deterministic across distinct evidence input order', () => {
  const makeEvidence = (hash, page) => importWebHarEvidence({ log: { entries: [entry({
    method: 'GET',
    url: `https://portal.example/api/clients/1?page=${page}`,
    status: 200,
  })] } }, { sourceSha256: hash.repeat(64), targetOrigins: ['https://portal.example'] })
  const first = makeEvidence('5', '1')
  const second = makeEvidence('6', 'next')
  const options = { reverseEvidence: [], generatedAt: '2026-09-11T12:01:00.000Z' }
  assert.deepEqual(
    buildNativeInteractionContract({ ...options, webSessionEvidence: [first, second] }),
    buildNativeInteractionContract({ ...options, webSessionEvidence: [second, first] }),
  )
  assert.throws(() => buildNativeInteractionContract({
    ...options,
    webSessionEvidence: [first, structuredClone(first)],
  }), /distinct|capture|observation/i)
})

test('contract validator rejects forged scope and derived endpoint states', () => {
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [webEvidence()], reverseEvidence: [],
    generatedAt: '2026-09-11T12:01:00.000Z',
  })
  const mutations = [
    (value) => { value.endpoints.find(({ method }) => method === 'GET').write_verification = 'NOT_OBSERVED' },
    (value) => { value.endpoints.find(({ method }) => method === 'GET').pagination = 'CURSOR_PARAMETER_OBSERVED' },
    (value) => { value.endpoints.find(({ redirects }) => redirects.length > 0).redirects[0].origin = 'https://other.example' },
    (value) => { value.auth_flows.push(structuredClone(value.auth_flows[0])) },
    (value) => { value.endpoints[1].evidence_refs = [...value.endpoints[0].evidence_refs] },
  ]
  for (const mutate of mutations) {
    const changed = structuredClone(contract)
    mutate(changed)
    assert.throws(() => assertValidNativeInteractionContract(changed))
  }
})

test('ordinary cookies do not create credential carriers or authentication flows', () => {
  const evidence = importWebHarEvidence({ log: { entries: [entry({
    method: 'GET',
    url: 'https://portal.example/preferences',
    requestCookies: [{ name: 'theme', value: 'dark' }],
    status: 200,
  })] } }, { sourceSha256: '7'.repeat(64), targetOrigins: ['https://portal.example'] })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [evidence], reverseEvidence: [], generatedAt: '2026-09-11T12:01:00.000Z',
  })
  assert.equal(contract.endpoints[0].auth.request_carriers.length, 0)
  assert.equal(contract.auth_flows.length, 0)
})

test('correlates a unique response-provided auth destination within three later observations', () => {
  const evidence = importWebHarEvidence({ log: { entries: [
    entry({
      method: 'POST', url: 'https://portal.example/CheckLogin', status: 200,
      postData: { mimeType: 'application/x-www-form-urlencoded', params: [{ name: 'Password', value: 'secret' }] },
      content: { mimeType: 'application/json', size: 80, text: '{"DocsURL":"/docs","WebsiteURL":"/Home"}' },
    }),
    entry({ method: 'GET', url: 'https://portal.example/ping', status: 200 }),
    entry({ method: 'GET', url: 'https://portal.example/assets', status: 200 }),
    entry({ method: 'GET', url: 'https://portal.example/Home', status: 200 }),
  ] } }, {
    sourceSha256: '8'.repeat(64), targetOrigins: ['https://portal.example'],
    pathLiterals: ['CheckLogin', 'Home', 'assets', 'docs', 'ping'],
  })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [evidence], reverseEvidence: [], generatedAt: '2026-09-11T12:01:00.000Z',
  })
  const login = contract.auth_flows[0].steps[0]
  assert.equal(login.destination_candidates.length, 2)
  assert.equal(login.destination_correlation, 'UNIQUE_WITHIN_3_STEPS')
  assert.equal(login.destination.field_path, 'WebsiteURL')
  assert.equal(login.next_observation_id, contract.auth_flows[0].steps[3].evidence_ref)
})

test('validator rejects forged auth metadata even when the content-bound id is recomputed', () => {
  const mutations = [
    (value) => { value.auth_flows[0].steps[0].response_status = 418 },
    (value) => { value.auth_flows[0].steps[0].inputs = ['cookie:cbh'] },
    (value) => { value.auth_flows[0].steps[0].next_observation_id = value.auth_flows[0].steps.at(-1).evidence_ref },
    (value) => {
      value.endpoints[0].response.fields[0].name = 'test@example.com'
      value.endpoints[0].response.fields[0].path = 'test@example.com'
    },
  ]
  for (const mutate of mutations) {
    const contract = buildNativeInteractionContract({
      webSessionEvidence: [webEvidence()], reverseEvidence: [], generatedAt: '2026-09-11T12:01:00.000Z',
    })
    mutate(contract)
    rebindContractId(contract)
    assert.throws(() => assertValidNativeInteractionContract(contract))
  }
})

test('auth steps bind to one exact endpoint exchange instead of aggregate endpoint facets', () => {
  const evidence = importWebHarEvidence({ log: { entries: [
    entry({
      method: 'POST', url: 'https://portal.example/CheckLogin', status: 401,
      postData: { mimeType: 'application/x-www-form-urlencoded', params: [{ name: 'Password', value: 'first' }] },
    }),
    entry({
      method: 'POST', url: 'https://portal.example/CheckLogin', status: 200,
      postData: { mimeType: 'application/x-www-form-urlencoded', params: [{ name: 'Password', value: 'second' }] },
      responseHeaders: [{ name: 'Set-Cookie', value: 'SessionCookie=secret' }],
      responseCookies: [{ name: 'SessionCookie', value: 'secret' }],
      content: { mimeType: 'application/json', size: 40, text: '{"WebsiteURL":"/Home"}' },
    }),
    entry({ method: 'GET', url: 'https://portal.example/Home', status: 200 }),
  ] } }, {
    sourceSha256: '9'.repeat(64),
    targetOrigins: ['https://portal.example'],
    pathLiterals: ['CheckLogin', 'Home'],
  })
  const original = buildNativeInteractionContract({
    webSessionEvidence: [evidence], reverseEvidence: [], generatedAt: '2026-09-11T12:01:00.000Z',
  })
  const login = original.endpoints.find(({ path_template: path }) => path === '/CheckLogin')
  assert.equal(login.exchanges.length, 2)
  assert.deepEqual(login.response.statuses, [200, 401])
  assert.deepEqual(login.auth.response_carriers, ['cookie:SessionCookie'])

  const mutations = [
    (contract) => { contract.auth_flows[0].steps[0].response_status = 200 },
    (contract) => { contract.auth_flows[0].steps[0].outputs = ['cookie:SessionCookie'] },
    (contract) => { contract.auth_flows[0].steps[0].sequence = 2 },
    (contract) => { contract.endpoints.find(({ path_template: path }) => path === '/CheckLogin').exchanges[0].response.status = 200 },
    (contract) => { contract.endpoints.find(({ path_template: path }) => path === '/CheckLogin').exchanges[0].request.action = 'AUTH_REQUEST' },
    (contract) => { contract.endpoints.find(({ path_template: path }) => path === '/CheckLogin').exchanges[0].unexpected = true },
  ]
  for (const mutate of mutations) {
    const changed = structuredClone(original)
    mutate(changed)
    rebindContractId(changed)
    assert.throws(() => assertValidNativeInteractionContract(changed), /exchange|exact|request|response|field|sequence|identity/i)
  }
})

test('redacted destination path templates never correlate different concrete paths', () => {
  const evidence = importWebHarEvidence({ log: { entries: [
    entry({
      method: 'POST', url: 'https://portal.example/CheckLogin', status: 200,
      postData: { mimeType: 'application/x-www-form-urlencoded', params: [{ name: 'Password', value: 'secret' }] },
      content: { mimeType: 'application/json', size: 50, text: '{"WebsiteURL":"/tenant/Alice"}' },
    }),
    entry({ method: 'GET', url: 'https://portal.example/tenant/Bob', status: 200 }),
  ] } }, {
    sourceSha256: 'a'.repeat(64),
    targetOrigins: ['https://portal.example'],
    pathLiterals: ['CheckLogin', 'tenant'],
  })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [evidence], reverseEvidence: [], generatedAt: '2026-09-11T12:01:00.000Z',
  })
  const login = contract.auth_flows[0].steps[0]
  assert.equal(login.destination_candidates[0].path_template, '/tenant/{segment}')
  assert.equal(contract.auth_flows[0].steps[1].endpoint_id, contract.endpoints.find(({ path_template: path }) => path === '/tenant/{segment}').endpoint_id)
  assert.equal(login.destination_correlation, 'OBSERVED_NOT_LINKED')
  assert.equal(login.destination.path_template, '/tenant/{segment}')
  assert.equal(login.next_observation_id, null)
  assert.equal(login.redirect_endpoint_id, null)
  assert.equal(contract.gaps.some(({ code }) => code === 'REDACTED_DESTINATION_CORRELATION_UNPROVEN'), true)

  const forged = structuredClone(contract)
  const next = forged.auth_flows[0].steps[1]
  forged.auth_flows[0].steps[0].destination_correlation = 'UNIQUE_WITHIN_3_STEPS'
  forged.auth_flows[0].steps[0].next_observation_id = next.evidence_ref
  forged.auth_flows[0].steps[0].redirect_endpoint_id = next.endpoint_id
  rebindContractId(forged)
  assert.throws(
    () => assertValidNativeInteractionContract(forged),
    /destination correlation|transition link/i,
  )
})

test('endpoint exchange lists are bounded independently of aggregate facets', () => {
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [webEvidence()], reverseEvidence: [], generatedAt: '2026-09-11T12:01:00.000Z',
  })
  const endpoint = contract.endpoints[0]
  endpoint.exchanges = Array(10_001).fill(endpoint.exchanges[0])
  rebindContractId(contract)
  assert.throws(() => assertValidNativeInteractionContract(contract), /exchange limit|exchanges are invalid/i)
})

test('contract construction rejects aggregate entry growth before flattening', () => {
  const evidence = webEvidence()
  evidence.entries = Array(20_001).fill(evidence.entries[0])
  assert.throws(() => buildNativeInteractionContract({
    webSessionEvidence: [evidence], reverseEvidence: [], generatedAt: '2026-09-11T12:01:00.000Z',
  }), /aggregate entry limit/i)
})

test('contract preserves source-capture shape omission gaps', () => {
  const response = Object.fromEntries(Array.from({ length: 1_025 }, (_, index) => [`field_${index}`, index]))
  const evidence = importWebHarEvidence({ log: { entries: [entry({
    method: 'GET',
    url: 'https://portal.example/api',
    content: {
      mimeType: 'application/json',
      size: 16_000,
      text: JSON.stringify(response),
    },
  })] } }, {
    sourceSha256: 'd'.repeat(64),
    targetOrigins: ['https://portal.example'],
  })
  assert.equal(evidence.gaps.some(({ code }) => code === 'BODY_FIELDS_TRUNCATED'), true)

  const contract = buildNativeInteractionContract({
    webSessionEvidence: [evidence],
    reverseEvidence: [],
    generatedAt: '2026-09-11T12:01:00.000Z',
  })
  assert.equal(
    contract.gaps.some(({ code }) => code === 'WEB_EVIDENCE_BODY_FIELDS_TRUNCATED'),
    true,
  )
})
