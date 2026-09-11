import assert from 'node:assert/strict'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import * as httpAuthedContracts from '../scripts/lib/http-authed-contracts.mjs'
import {
  assertValidHttpAuthedScope,
  OPERATOR_ATTESTED_AUTHED_STATEMENT,
} from '../scripts/lib/http-authed-contracts.mjs'

function operatorAttestedScope({ actionCount = 128 } = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-authed-scope',
    engagement_id: 'example-authorized-assessment',
    environment: 'production',
    data_class: 'phi',
    authorization: {
      mode: 'OPERATOR_ATTESTED_AUTHED',
      authorization_id: 'operator-attestation-2026-08-16',
      statement: OPERATOR_ATTESTED_AUTHED_STATEMENT,
      operator_id: 'example-security-operator',
      authorized_by: 'engagement operator',
      authorization_reference: 'Operator-held engagement authorization reference 2026-08-16',
      attested_at: '2026-08-16T12:00:00.000Z',
      independently_verified: false,
      permissions: {
        active_testing: true,
        production: true,
        third_party: true,
        phi: true,
        mutation: true,
      },
      authorized_scope: {
        origins: ['https://app.example.test'],
        path_prefixes: ['/'],
        methods: ['HEAD', 'GET', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'],
        test_categories: [
          'authentication',
          'authorization',
          'session_management',
          'input_validation',
          'business_logic',
          'api_security',
        ],
      },
    },
    credential: {
      ref: 'env:SYNTHETIC_TEST_CREDENTIAL',
      kind: 'bearer',
      binding_sha256: '1'.repeat(64),
    },
    evidence_handling: {
      persist_request_bodies: false,
      persist_response_bodies: false,
      persist_credential_values: false,
      persist_header_values: false,
      stop_on_sensitive_data: true,
      test_data: 'synthetic_only',
    },
    liveness: {
      credential_preflight: {
        method: 'GET',
        url: 'https://app.example.test/whoami',
      },
    },
    target: {
      origin: 'https://app.example.test',
      ownership: 'third_party_owned',
      tls: { mode: 'PKIX_HOSTNAME' },
    },
    validity: {
      not_before: '2026-08-16T11:59:00.000Z',
      not_after: '2026-08-16T12:04:00.000Z',
      cleanup_not_after: '2026-08-16T12:04:00.000Z',
    },
    limits: {
      request_timeout_ms: 10_000,
      max_response_bytes: 65_536,
      min_interval_ms: 1_000,
      concurrency: 1,
    },
    stop_conditions: [
      'AUTHORIZATION_WITHDRAWN',
      'EMERGENCY_STOP_REQUESTED',
      'AUTHORIZATION_WINDOW_CLOSED',
      'TARGET_IDENTITY_CHANGED',
      'LIMIT_REACHED',
      'UNEXPECTED_SIDE_EFFECT',
      'VERIFICATION_MISMATCH',
      'ROLLBACK_REQUIRED',
      'CREDENTIAL_INVALID',
    ],
    requests: Array.from({ length: actionCount }, (_unused, index) => {
      const sequence = index + 1
      const url = `https://app.example.test/security-test-resource/${sequence}`
      return {
        kind: 'mutate',
        sequence,
        test_category: 'api_security',
        method: 'POST',
        url,
        success_statuses: [200, 201, 204],
        request_body: {
          body_id: `SYNTHETIC_SECURITY_TEST_PAYLOAD_${sequence}`,
          sha256: '4'.repeat(64),
          byte_length: 64,
          content_type: 'application/json',
          data_class: 'synthetic_non_phi',
        },
        expected_mutation: {
          resource_ref: `SYNTHETIC_SECURITY_TEST_RECORD_${sequence}`,
          field: '/synthetic_marker',
          representation: 'CANONICAL_JSON_VALUE_SHA256',
          before_digest: '2'.repeat(64),
          after_digest: '3'.repeat(64),
        },
        before_read: {
          method: 'GET',
          url,
          expected_statuses: [200],
          observation: { format: 'JSON', json_pointer: '/synthetic_marker' },
        },
        after_read: {
          method: 'GET',
          url,
          expected_statuses: [200],
          observation: { format: 'JSON', json_pointer: '/synthetic_marker' },
        },
        rollback: {
          method: 'PATCH',
          url,
          expected_after_digest: '2'.repeat(64),
          idempotent_restore: true,
          success_statuses: [200],
          request_body: {
            body_id: `SYNTHETIC_SECURITY_TEST_ROLLBACK_${sequence}`,
            sha256: '5'.repeat(64),
            byte_length: 64,
            content_type: 'application/json',
            data_class: 'synthetic_non_phi',
          },
          verification_read: {
            method: 'GET',
            url,
            expected_statuses: [200],
            observation: { format: 'JSON', json_pointer: '/synthetic_marker' },
          },
        },
        rollback_policy: 'ALWAYS',
      }
    }),
  }
}

test('operator-attested probe-only campaigns require no approver or countersignature', () => {
  const scope = operatorAttestedScope({ actionCount: 1 })
  scope.authorization.permissions.mutation = false
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: 'https://app.example.test/security-start',
    expected_effect: 'none',
  }]
  assert.equal('approver' in scope, false)
  assert.equal('requires_countersignature' in scope.requests[0], false)
  assert.doesNotThrow(() => assertValidHttpAuthedScope(scope))
})

test('operator-attested mutation authorization requires no approver or countersignature', () => {
  const scope = operatorAttestedScope({ actionCount: 1 })
  assert.equal(scope.authorization.permissions.mutation, true)
  assert.equal('approver' in scope, false)
  assert.equal('requires_countersignature' in scope.requests[0], false)
  assert.doesNotThrow(() => assertValidHttpAuthedScope(scope))
})

test('operator-attested scopes reject URL credentials and fragments before runtime transport', () => {
  const base = operatorAttestedScope({ actionCount: 1 })
  base.authorization.permissions.mutation = false
  base.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: 'https://app.example.test/security-start',
    expected_effect: 'none',
  }]

  const credentialUrl = structuredClone(base)
  credentialUrl.requests[0].url =
    'https://synthetic-user:synthetic-password@app.example.test/security-start'
  assert.throws(
    () => assertValidHttpAuthedScope(credentialUrl),
    (error) => error.code === 'HTTP_AUTHED_URL_CREDENTIALS_REFUSED',
  )

  const fragmentUrl = structuredClone(base)
  fragmentUrl.liveness.credential_preflight.url =
    'https://app.example.test/whoami#fragment'
  assert.throws(
    () => assertValidHttpAuthedScope(fragmentUrl),
    (error) => error.code === 'HTTP_AUTHED_URL_FRAGMENT_REFUSED',
  )
})

const CAMPAIGN_NOW = new Date('2026-08-16T12:00:00.000Z')

function plannedCampaignGrantSha256(scope) {
  return httpAuthedContracts.verifyHttpAuthedAuthorization({
    scope,
    now: CAMPAIGN_NOW,
  }).campaignGrantSha256
}

function verifyCandidate(scope, action, {
  expectedCampaignGrantSha256 = plannedCampaignGrantSha256(scope),
  now = CAMPAIGN_NOW,
} = {}) {
  return httpAuthedContracts.verifyHttpAuthedCandidate({
    scope,
    action,
    expectedCampaignGrantSha256,
    now,
  })
}

test('operator statement admits a multi-action third-party production campaign', () => {
  const scope = operatorAttestedScope()
  assert.equal(scope.requests.length, 128)
  assert.equal('max_mutations' in scope.limits, false)
  assert.equal('max_cumulative_impact' in scope.limits, false)
  assert.doesNotThrow(() => assertValidHttpAuthedScope(scope))
})

test('operator-attested authorization has no legacy fixed action-count ceiling', () => {
  const scope = operatorAttestedScope({ actionCount: 1_024 })
  assert.equal(scope.requests.length, 1_024)
  assert.equal(httpAuthedContracts.httpAuthedScopeSchema.properties.requests.maxItems, undefined)
  assert.doesNotThrow(() => assertValidHttpAuthedScope(scope))
})

test('operator-attested engagement permits explicitly authorized non-tunneling HTTP methods', () => {
  const scope = operatorAttestedScope({ actionCount: 1 })
  const methods = [
    'HEAD', 'GET', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE',
    'TRACE', 'PROPFIND', 'COPY', 'MOVE', 'LOCK', 'UNLOCK',
  ]
  assert.equal(methods.includes('CONNECT'), false)
  scope.authorization.authorized_scope.methods = methods
  scope.requests = methods.map((method, index) => ({
    kind: 'probe',
    sequence: index + 1,
    test_category: 'api_security',
    method,
    url: `https://app.example.test/method-probe/${index + 1}`,
    expected_effect: 'none',
  }))

  assert.doesNotThrow(() => assertValidHttpAuthedScope(scope))
})

test('native authenticated scopes refuse CONNECT tunnel actions', () => {
  const scope = operatorAttestedScope({ actionCount: 1 })
  scope.authorization.authorized_scope.methods = ['GET', 'CONNECT']
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'CONNECT',
    url: 'https://app.example.test/tunnel-target',
    expected_effect: 'none',
  }]

  assert.throws(
    () => assertValidHttpAuthedScope(scope),
    /CONNECT|tunnel|method.*unsupported|method.*refused/i,
  )
})

test('operator-attested engagement requires canonical uppercase method tokens', () => {
  const scope = operatorAttestedScope({ actionCount: 1 })
  scope.authorization.authorized_scope.methods.push('customProbe')
  scope.requests[0] = {
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'customProbe',
    url: 'https://app.example.test/method-probe/custom',
    expected_effect: 'none',
  }

  assert.throws(
    () => assertValidHttpAuthedScope(scope),
    (error) => error.code === 'HTTP_AUTHED_SCHEMA_INVALID'
      && error.details.some((detail) => detail.keyword === 'pattern'),
  )
})

test('runtime discoveries are admitted by engagement scope without an action-count gate', () => {
  assert.equal(
    typeof httpAuthedContracts.verifyHttpAuthedCandidate,
    'function',
  )
  const scope = operatorAttestedScope({ actionCount: 1 })
  scope.authorization.authorized_scope.methods.push('PROPFIND')
  const expectedCampaignGrantSha256 = plannedCampaignGrantSha256(scope)
  const candidate = {
    kind: 'probe',
    sequence: 1_000_000,
    test_category: 'api_security',
    method: 'PROPFIND',
    url: 'https://app.example.test/discovered/webdav/resource',
    expected_effect: 'none',
  }

  assert.doesNotThrow(() => verifyCandidate(scope, candidate, { expectedCampaignGrantSha256 }))
  assert.throws(
    () => httpAuthedContracts.verifyHttpAuthedCandidate({
      scope,
      action: candidate,
      now: CAMPAIGN_NOW,
    }),
    /campaign grant|controller-held/i,
  )

  assert.throws(
    () => verifyCandidate(scope, { ...candidate, method: 'SEARCH' }, {
      expectedCampaignGrantSha256,
    }),
    /method|operator-attested scope/i,
  )
  assert.throws(
    () => verifyCandidate(scope, { ...candidate, test_category: 'destructive_stress' }, {
      expectedCampaignGrantSha256,
    }),
    /category|operator-attested scope/i,
  )
  scope.authorization.authorized_scope.methods.push('SEARCH')
  assert.throws(
    () => verifyCandidate(scope, { ...candidate, method: 'SEARCH' }, {
      expectedCampaignGrantSha256,
    }),
    /campaign|grant|binding|digest/i,
  )
})

test('write-capable and body-bearing probes require explicit mutation permission', () => {
  const scope = operatorAttestedScope({ actionCount: 1 })
  scope.authorization.permissions.mutation = false
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: 'https://app.example.test/safe-probe',
    expected_effect: 'none',
  }]
  assert.doesNotThrow(() => assertValidHttpAuthedScope(scope))

  for (const action of [
    { ...scope.requests[0], method: 'DELETE' },
    {
      ...scope.requests[0],
      request_body: {
        body_id: 'SYNTHETIC_PROBE_BODY_0001',
        sha256: '5'.repeat(64),
        byte_length: 16,
        content_type: 'application/json',
        data_class: 'synthetic_non_phi',
      },
    },
  ]) {
    assert.throws(
      () => verifyCandidate(scope, action),
      /mutation.*permission|explicitly permit mutation/i,
    )
  }
})

test('operator-attested campaign can span its authorization window without aggregate or wall-time caps', () => {
  const scope = operatorAttestedScope()
  scope.validity.not_after = '2027-08-16T12:00:00.000Z'
  scope.validity.cleanup_not_after = scope.validity.not_after
  scope.limits.min_interval_ms = 0
  scope.limits.concurrency = 4

  assert.equal('max_aggregate_response_bytes' in scope.limits, false)
  assert.equal('max_wall_time_ms' in scope.limits, false)
  assert.doesNotThrow(() => assertValidHttpAuthedScope(scope))
})

test('authenticated validity requires an explicit ordered cleanup deadline', () => {
  const missing = operatorAttestedScope({ actionCount: 1 })
  delete missing.validity.cleanup_not_after
  assert.throws(
    () => assertValidHttpAuthedScope(missing),
    (error) => error.code === 'HTTP_AUTHED_SCHEMA_INVALID'
      && error.details.some((detail) => detail.instancePath === '/validity'),
  )

  const equalToActionDeadline = operatorAttestedScope({ actionCount: 1 })
  equalToActionDeadline.validity.cleanup_not_after = equalToActionDeadline.validity.not_after
  assert.doesNotThrow(() => assertValidHttpAuthedScope(equalToActionDeadline))

  const beforeActionDeadline = operatorAttestedScope({ actionCount: 1 })
  beforeActionDeadline.validity.cleanup_not_after = '2026-08-16T12:03:59.999Z'
  assert.throws(
    () => assertValidHttpAuthedScope(beforeActionDeadline),
    (error) => error.code === 'HTTP_AUTHED_CLEANUP_WINDOW_INVALID'
      && /cleanup/i.test(error.message),
  )
})

test('cleanup deadline never extends ordinary candidate authorization', () => {
  const scope = operatorAttestedScope({ actionCount: 1 })
  scope.validity.cleanup_not_after = '2026-08-16T12:10:00.000Z'
  const verified = httpAuthedContracts.verifyHttpAuthedAuthorization({
    scope,
    now: new Date('2026-08-16T12:00:00.000Z'),
  })

  assert.throws(
    () => httpAuthedContracts.verifyHttpAuthedCandidate({
      scope,
      action: scope.requests[0],
      expectedCampaignGrantSha256: verified.campaignGrantSha256,
      now: new Date(scope.validity.not_after),
    }),
    (error) => error.code === 'HTTP_AUTHED_AUTHORIZATION_EXPIRED',
  )
})

test('campaign cannot widen the operator-attested origin, path, or method scope', () => {
  const methodDrift = operatorAttestedScope()
  methodDrift.authorization.authorized_scope.methods = ['GET', 'DELETE']
  assert.throws(() => assertValidHttpAuthedScope(methodDrift), /method|operator-attested scope/i)

  const pathDrift = operatorAttestedScope()
  pathDrift.authorization.authorized_scope.path_prefixes = ['/approved/']
  assert.throws(() => assertValidHttpAuthedScope(pathDrift), /path|operator-attested scope/i)

  const originDrift = operatorAttestedScope()
  originDrift.authorization.authorized_scope.origins = ['https://different.example.test']
  assert.throws(() => assertValidHttpAuthedScope(originDrift), /origin|operator-attested scope/i)
})

test('operator-attested path prefixes use canonical segment boundaries', () => {
  const scope = operatorAttestedScope({ actionCount: 1 })
  scope.authorization.authorized_scope.path_prefixes = ['/approved']
  scope.liveness.credential_preflight.url = 'https://app.example.test/approved/whoami'
  scope.requests[0].url = 'https://app.example.test/approved/seed'
  scope.requests[0].before_read.url = scope.requests[0].url
  scope.requests[0].after_read.url = scope.requests[0].url
  scope.requests[0].rollback.url = scope.requests[0].url
  scope.requests[0].rollback.verification_read.url = scope.requests[0].url
  assert.doesNotThrow(() => assertValidHttpAuthedScope(scope))

  const candidate = {
    kind: 'probe',
    sequence: 2,
    test_category: 'api_security',
    method: 'GET',
    url: 'https://app.example.test/approved/nested',
    expected_effect: 'none',
  }
  const expectedCampaignGrantSha256 = plannedCampaignGrantSha256(scope)
  assert.doesNotThrow(() => verifyCandidate(scope, candidate, { expectedCampaignGrantSha256 }))

  for (const url of [
    'https://app.example.test/approved-evil',
    'https://app.example.test/approved/%2f..%2fadmin',
    'https://app.example.test/approved/%252f..%252fadmin',
  ]) {
    assert.throws(
      () => verifyCandidate(scope, { ...candidate, url }, { expectedCampaignGrantSha256 }),
      /path|canonical|encoded|operator-attested scope/i,
    )
  }
})

for (const permission of ['active_testing', 'production', 'third_party', 'phi', 'mutation']) {
  test(`operator attestation must explicitly permit ${permission}`, () => {
    const scope = operatorAttestedScope()
    scope.authorization.permissions[permission] = false
    assert.throws(
      () => assertValidHttpAuthedScope(scope),
      /operator attestation|permission/i,
    )
  })
}

test('operator authorization is content-bound and time-bound', () => {
  assert.equal(typeof httpAuthedContracts.verifyHttpAuthedAuthorization, 'function')
  const scope = operatorAttestedScope()
  const verified = httpAuthedContracts.verifyHttpAuthedAuthorization({
    scope,
    now: new Date('2026-08-16T12:00:00.000Z'),
  })
  assert.equal(verified.scope, scope)
  assert.equal(
    verified.authorizationBindingSha256,
    httpAuthedContracts.httpAuthedAuthorizationBindingSha256(scope),
  )
  const changed = structuredClone(scope)
  changed.authorization.authorized_by = 'different operator authority'
  const changedVerified = httpAuthedContracts.verifyHttpAuthedAuthorization({
    scope: changed,
    now: new Date('2026-08-16T12:00:00.000Z'),
  })
  assert.notEqual(
    changedVerified.authorizationBindingSha256,
    verified.authorizationBindingSha256,
  )
  assert.notEqual(changedVerified.campaignGrantSha256, verified.campaignGrantSha256)
  assert.throws(
    () => httpAuthedContracts.verifyHttpAuthedAuthorization({
      scope,
      now: new Date('2026-08-16T12:04:00.000Z'),
    }),
    /expired|validity/i,
  )
})

test('operator-attested scope disables sensitive persistence and rejects raw body fields', () => {
  const scope = operatorAttestedScope()
  assert.deepEqual(scope.evidence_handling, {
    persist_request_bodies: false,
    persist_response_bodies: false,
    persist_credential_values: false,
    persist_header_values: false,
    stop_on_sensitive_data: true,
    test_data: 'synthetic_only',
  })

  const rawBody = operatorAttestedScope()
  rawBody.requests[0].request_body.body_bytes = 'never persist this'
  assert.throws(() => assertValidHttpAuthedScope(rawBody), /schema/i)

  const responseBody = operatorAttestedScope()
  responseBody.requests[0].response_body = 'never persist this either'
  assert.throws(() => assertValidHttpAuthedScope(responseBody), /schema/i)
})

test('JSON shape observation modes require their exact versioned scope contract', () => {
  const observation = {
    mode: 'JSON_SHAPE_ONLY',
    max_depth: 3,
    safe_key_names: ['records', 'id'],
  }
  const legacyWithObservation = operatorAttestedScope()
  legacyWithObservation.response_observation = observation
  assert.throws(() => assertValidHttpAuthedScope(legacyWithObservation), /schema/i)

  const extensionWithoutObservation = operatorAttestedScope()
  extensionWithoutObservation.schema_version = '1.1.0'
  assert.throws(() => assertValidHttpAuthedScope(extensionWithoutObservation), /schema/i)

  const optedIn = operatorAttestedScope()
  optedIn.schema_version = '1.1.0'
  optedIn.response_observation = observation
  assert.doesNotThrow(() => assertValidHttpAuthedScope(optedIn))

  const aspNetObservation = {
    mode: 'ASPNET_D_JSON_SHAPE_ONLY',
    max_depth: 3,
    safe_key_names: ['records', 'id'],
  }
  const aspNetOptedIn = operatorAttestedScope()
  aspNetOptedIn.schema_version = '1.2.0'
  aspNetOptedIn.response_observation = aspNetObservation
  assert.doesNotThrow(() => assertValidHttpAuthedScope(aspNetOptedIn))

  for (const [version, responseObservation] of [
    ['1.1.0', aspNetObservation],
    ['1.2.0', observation],
  ]) {
    const mismatched = operatorAttestedScope()
    mismatched.schema_version = version
    mismatched.response_observation = responseObservation
    assert.throws(() => assertValidHttpAuthedScope(mismatched), /schema/i)
  }
})

test('bounded file loading verifies the operator-attested scope and exact mode', async (t) => {
  assert.equal(typeof httpAuthedContracts.readAndVerifyHttpAuthedAuthorization, 'function')
  const directory = await mkdtemp(join(tmpdir(), 'rta-http-authed-attested-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const scopePath = join(directory, 'scope.json')
  await writeFile(scopePath, `${JSON.stringify(operatorAttestedScope())}\n`, 'utf8')

  const verified = await httpAuthedContracts.readAndVerifyHttpAuthedAuthorization({
    scopePath,
    requiredMode: 'OPERATOR_ATTESTED_AUTHED',
    now: new Date('2026-08-16T12:00:00.000Z'),
  })
  assert.equal(verified.scope.engagement_id, 'example-authorized-assessment')
  assert.match(verified.authorizationBindingSha256, /^[a-f0-9]{64}$/)
})

test('historical file loading retains structural and digest verification after expiry', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'rta-http-authed-historical-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const scopePath = join(directory, 'scope.json')
  const scope = operatorAttestedScope()
  await writeFile(scopePath, `${JSON.stringify(scope)}\n`, 'utf8')

  await assert.rejects(
    httpAuthedContracts.readAndVerifyHttpAuthedAuthorization({
      scopePath,
      requiredMode: 'OPERATOR_ATTESTED_AUTHED',
      now: new Date('2027-08-16T12:00:00.000Z'),
    }),
    (error) => error.code === 'HTTP_AUTHED_AUTHORIZATION_EXPIRED',
  )
  const historical = await httpAuthedContracts.readAndVerifyHistoricalHttpAuthedAuthorization({
    scopePath,
    requiredMode: 'OPERATOR_ATTESTED_AUTHED',
  })
  assert.deepEqual(historical.scope, scope)
  assert.match(historical.authorizationBindingSha256, /^[a-f0-9]{64}$/)
  assert.equal(historical.campaignGrantSha256, plannedCampaignGrantSha256(scope))
})

test('CLI validates an operator-attested campaign without printing sensitive material', async (t) => {
  const { main } = await import('../scripts/http-authed.mjs')
  const directory = await mkdtemp(join(tmpdir(), 'rta-http-authed-cli-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const scopePath = join(directory, 'scope.json')
  const scope = operatorAttestedScope()
  await writeFile(scopePath, `${JSON.stringify(scope)}\n`, 'utf8')
  let output = ''

  await main([
    'validate-attested',
    '--scope', scopePath,
    '--json',
  ], {
    clock: () => new Date('2026-08-16T12:00:00.000Z'),
    write: (text) => { output += text },
  })

  const summary = JSON.parse(output)
  assert.equal(summary.authorization_mode, 'OPERATOR_ATTESTED_AUTHED')
  assert.equal(summary.request_count, 128)
  assert.match(summary.authorization_binding_sha256, /^[a-f0-9]{64}$/)
  assert.equal(summary.campaign_grant_sha256, plannedCampaignGrantSha256(scope))
  assert.doesNotMatch(output, /SYNTHETIC_TEST_CREDENTIAL/)
  assert.doesNotMatch(output, /SYNTHETIC_SECURITY_TEST_PAYLOAD/)
})

test('legacy written-authorization commands retire before scope, document, credential, or transport I/O', async () => {
  const { main } = await import('../scripts/http-authed.mjs')
  let credentialReads = 0
  let transportCalls = 0

  await assert.rejects(
    main([
      'validate-written',
      '--scope', 'must-not-read-scope.json',
      '--authorization-document', 'must-not-read-authorization.txt',
      '--json',
    ], {
      credentialStdinReader: async () => {
        credentialReads += 1
        throw new Error('credential input must remain unread')
      },
      transport: async () => { transportCalls += 1 },
      write: () => {},
    }),
    /supported http-authed command/i,
  )

  assert.equal(credentialReads, 0)
  assert.equal(transportCalls, 0)
})

export { operatorAttestedScope }
