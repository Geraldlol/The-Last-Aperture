import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import * as httpAuthedContracts from '../scripts/lib/http-authed-contracts.mjs'
import {
  assertValidHttpAuthedScope,
  sha256Hex,
  WRITTEN_AUTHORIZATION_AUTHED_STATEMENT,
} from '../scripts/lib/http-authed-contracts.mjs'

const AUTHORIZATION_DOCUMENT = Buffer.from('synthetic authorization fixture')

function approver() {
  const { publicKey } = generateKeyPairSync('ed25519')
  const der = publicKey.export({ type: 'spki', format: 'der' })
  return {
    mechanism: 'ed25519_file',
    key_id: `ed25519:${sha256Hex(der)}`,
    public_key: {
      format: 'spki_der_b64',
      value_base64: der.toString('base64'),
    },
    enrollment: {
      enrolled_by: 'Peerstar security lead',
      enrolled_at: '2026-04-15T12:00:00.000Z',
      provenance: 'Peerstar internal approver enrollment for the written vendor authorization',
    },
  }
}

function writtenScope({ actionCount = 128 } = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-authed-scope',
    engagement_id: 'peerstar-credible-authorized-assessment',
    environment: 'production',
    data_class: 'phi',
    authorization: {
      mode: 'WRITTEN_AUTHORIZATION_AUTHED',
      authorization_id: 'credible-april-2026-authorization',
      statement: WRITTEN_AUTHORIZATION_AUTHED_STATEMENT,
      operator_id: 'peerstar-security-operator',
      authorized_by: 'Credible/Qualifacts security',
      authorization_reference: 'Credible/Qualifacts written authorization, April 2026',
      attested_at: '2026-08-16T12:00:00.000Z',
      independently_verified: false,
      written_authorization_sha256: sha256Hex(AUTHORIZATION_DOCUMENT),
      document_issuer: 'Credible/Qualifacts security',
      document_issued_at: '2026-04-15T12:00:00.000Z',
      permissions: {
        active_testing: true,
        production: true,
        third_party: true,
        phi: true,
        mutation: true,
      },
      authorized_scope: {
        origins: ['https://peerstar-test.example.test'],
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
    approver: approver(),
    liveness: {
      credential_preflight: {
        method: 'GET',
        url: 'https://peerstar-test.example.test/whoami',
      },
    },
    target: {
      origin: 'https://peerstar-test.example.test',
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
      const url = `https://peerstar-test.example.test/security-test-resource/${sequence}`
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
        requires_countersignature: true,
      }
    }),
  }
}

test('written probe-only campaigns do not require a mutation approver', () => {
  const scope = writtenScope({ actionCount: 1 })
  scope.authorization.permissions.mutation = false
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: 'https://peerstar-test.example.test/security-start',
    expected_effect: 'none',
  }]
  delete scope.approver
  assert.doesNotThrow(() => assertValidHttpAuthedScope(scope))
})

test('written mutation authorization still requires a pinned approver', () => {
  const scope = writtenScope({ actionCount: 1 })
  delete scope.approver
  assert.throws(
    () => assertValidHttpAuthedScope(scope),
    (error) => error.code === 'HTTP_AUTHED_SCHEMA_INVALID',
  )
})

test('written scopes reject URL credentials and fragments before runtime transport', () => {
  const base = writtenScope({ actionCount: 1 })
  base.authorization.permissions.mutation = false
  base.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: 'https://peerstar-test.example.test/security-start',
    expected_effect: 'none',
  }]
  delete base.approver

  const credentialUrl = structuredClone(base)
  credentialUrl.requests[0].url =
    'https://synthetic-user:synthetic-password@peerstar-test.example.test/security-start'
  assert.throws(
    () => assertValidHttpAuthedScope(credentialUrl),
    (error) => error.code === 'HTTP_AUTHED_URL_CREDENTIALS_REFUSED',
  )

  const fragmentUrl = structuredClone(base)
  fragmentUrl.liveness.credential_preflight.url =
    'https://peerstar-test.example.test/whoami#fragment'
  assert.throws(
    () => assertValidHttpAuthedScope(fragmentUrl),
    (error) => error.code === 'HTTP_AUTHED_URL_FRAGMENT_REFUSED',
  )
})

const CAMPAIGN_NOW = new Date('2026-08-16T12:00:00.000Z')

function plannedCampaignGrantSha256(scope) {
  return httpAuthedContracts.verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: CAMPAIGN_NOW,
  }).campaignGrantSha256
}

function verifyCandidate(scope, action, {
  documentBytes = AUTHORIZATION_DOCUMENT,
  expectedCampaignGrantSha256 = plannedCampaignGrantSha256(scope),
  now = CAMPAIGN_NOW,
} = {}) {
  return httpAuthedContracts.verifyHttpAuthedWrittenCandidate({
    scope,
    action,
    documentBytes,
    expectedCampaignGrantSha256,
    now,
  })
}

test('written vendor authorization admits a multi-action third-party production campaign', () => {
  const scope = writtenScope()
  assert.equal(scope.requests.length, 128)
  assert.equal('max_mutations' in scope.limits, false)
  assert.equal('max_cumulative_impact' in scope.limits, false)
  assert.doesNotThrow(() => assertValidHttpAuthedScope(scope))
})

test('written authorization has no legacy fixed action-count ceiling', () => {
  const scope = writtenScope({ actionCount: 1_024 })
  assert.equal(scope.requests.length, 1_024)
  assert.equal(httpAuthedContracts.httpAuthedScopeSchema.properties.requests.maxItems, undefined)
  assert.doesNotThrow(() => assertValidHttpAuthedScope(scope))
})

test('written engagement permits explicitly authorized non-tunneling HTTP methods', () => {
  const scope = writtenScope({ actionCount: 1 })
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
    url: `https://peerstar-test.example.test/method-probe/${index + 1}`,
    expected_effect: 'none',
  }))

  assert.doesNotThrow(() => assertValidHttpAuthedScope(scope))
})

test('native authenticated scopes refuse CONNECT tunnel actions', () => {
  const scope = writtenScope({ actionCount: 1 })
  scope.authorization.authorized_scope.methods = ['GET', 'CONNECT']
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'CONNECT',
    url: 'https://peerstar-test.example.test/tunnel-target',
    expected_effect: 'none',
  }]

  assert.throws(
    () => assertValidHttpAuthedScope(scope),
    /CONNECT|tunnel|method.*unsupported|method.*refused/i,
  )
})

test('written engagement requires canonical uppercase method tokens', () => {
  const scope = writtenScope({ actionCount: 1 })
  scope.authorization.authorized_scope.methods.push('customProbe')
  scope.requests[0] = {
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'customProbe',
    url: 'https://peerstar-test.example.test/method-probe/custom',
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
    typeof httpAuthedContracts.verifyHttpAuthedWrittenCandidate,
    'function',
  )
  const scope = writtenScope({ actionCount: 1 })
  scope.authorization.authorized_scope.methods.push('PROPFIND')
  const expectedCampaignGrantSha256 = plannedCampaignGrantSha256(scope)
  const candidate = {
    kind: 'probe',
    sequence: 1_000_000,
    test_category: 'api_security',
    method: 'PROPFIND',
    url: 'https://peerstar-test.example.test/discovered/webdav/resource',
    expected_effect: 'none',
  }

  assert.doesNotThrow(() => verifyCandidate(scope, candidate, { expectedCampaignGrantSha256 }))
  assert.throws(
    () => httpAuthedContracts.verifyHttpAuthedWrittenCandidate({
      scope,
      action: candidate,
      documentBytes: AUTHORIZATION_DOCUMENT,
      now: CAMPAIGN_NOW,
    }),
    /campaign grant|controller-held/i,
  )

  assert.throws(
    () => verifyCandidate(scope, { ...candidate, method: 'SEARCH' }, {
      expectedCampaignGrantSha256,
    }),
    /method|written scope/i,
  )
  assert.throws(
    () => verifyCandidate(scope, { ...candidate, test_category: 'destructive_stress' }, {
      expectedCampaignGrantSha256,
    }),
    /category|written scope/i,
  )
  assert.throws(
    () => verifyCandidate(scope, candidate, {
      documentBytes: Buffer.from('substituted authorization'),
      expectedCampaignGrantSha256,
    }),
    /document|digest/i,
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
  const scope = writtenScope({ actionCount: 1 })
  scope.authorization.permissions.mutation = false
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: 'https://peerstar-test.example.test/safe-probe',
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

test('written campaign can span its authorization window without aggregate or wall-time caps', () => {
  const scope = writtenScope()
  scope.validity.not_after = '2027-08-16T12:00:00.000Z'
  scope.validity.cleanup_not_after = scope.validity.not_after
  scope.limits.min_interval_ms = 0
  scope.limits.concurrency = 4

  assert.equal('max_aggregate_response_bytes' in scope.limits, false)
  assert.equal('max_wall_time_ms' in scope.limits, false)
  assert.doesNotThrow(() => assertValidHttpAuthedScope(scope))
})

test('authenticated validity requires an explicit ordered cleanup deadline', () => {
  const missing = writtenScope({ actionCount: 1 })
  delete missing.validity.cleanup_not_after
  assert.throws(
    () => assertValidHttpAuthedScope(missing),
    (error) => error.code === 'HTTP_AUTHED_SCHEMA_INVALID'
      && error.details.some((detail) => detail.instancePath === '/validity'),
  )

  const equalToActionDeadline = writtenScope({ actionCount: 1 })
  equalToActionDeadline.validity.cleanup_not_after = equalToActionDeadline.validity.not_after
  assert.doesNotThrow(() => assertValidHttpAuthedScope(equalToActionDeadline))

  const beforeActionDeadline = writtenScope({ actionCount: 1 })
  beforeActionDeadline.validity.cleanup_not_after = '2026-08-16T12:03:59.999Z'
  assert.throws(
    () => assertValidHttpAuthedScope(beforeActionDeadline),
    (error) => error.code === 'HTTP_AUTHED_CLEANUP_WINDOW_INVALID'
      && /cleanup/i.test(error.message),
  )
})

test('cleanup deadline never extends ordinary candidate authorization', () => {
  const scope = writtenScope({ actionCount: 1 })
  scope.validity.cleanup_not_after = '2026-08-16T12:10:00.000Z'
  const verified = httpAuthedContracts.verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: new Date('2026-08-16T12:00:00.000Z'),
  })

  assert.throws(
    () => httpAuthedContracts.verifyHttpAuthedCandidate({
      scope,
      action: scope.requests[0],
      documentBytes: AUTHORIZATION_DOCUMENT,
      expectedCampaignGrantSha256: verified.campaignGrantSha256,
      now: new Date(scope.validity.not_after),
    }),
    (error) => error.code === 'HTTP_AUTHED_AUTHORIZATION_EXPIRED',
  )
})

test('written campaign cannot widen the document-derived origin, path, or method scope', () => {
  const methodDrift = writtenScope()
  methodDrift.authorization.authorized_scope.methods = ['GET', 'DELETE']
  assert.throws(() => assertValidHttpAuthedScope(methodDrift), /method|written scope/i)

  const pathDrift = writtenScope()
  pathDrift.authorization.authorized_scope.path_prefixes = ['/approved/']
  assert.throws(() => assertValidHttpAuthedScope(pathDrift), /path|written scope/i)

  const originDrift = writtenScope()
  originDrift.authorization.authorized_scope.origins = ['https://different.example.test']
  assert.throws(() => assertValidHttpAuthedScope(originDrift), /origin|written scope/i)
})

test('written path prefixes use canonical segment boundaries', () => {
  const scope = writtenScope({ actionCount: 1 })
  scope.authorization.authorized_scope.path_prefixes = ['/approved']
  scope.liveness.credential_preflight.url = 'https://peerstar-test.example.test/approved/whoami'
  scope.requests[0].url = 'https://peerstar-test.example.test/approved/seed'
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
    url: 'https://peerstar-test.example.test/approved/nested',
    expected_effect: 'none',
  }
  const expectedCampaignGrantSha256 = plannedCampaignGrantSha256(scope)
  assert.doesNotThrow(() => verifyCandidate(scope, candidate, { expectedCampaignGrantSha256 }))

  for (const url of [
    'https://peerstar-test.example.test/approved-evil',
    'https://peerstar-test.example.test/approved/%2f..%2fadmin',
    'https://peerstar-test.example.test/approved/%252f..%252fadmin',
  ]) {
    assert.throws(
      () => verifyCandidate(scope, { ...candidate, url }, { expectedCampaignGrantSha256 }),
      /path|canonical|encoded|written scope/i,
    )
  }
})

for (const permission of ['active_testing', 'production', 'third_party', 'phi', 'mutation']) {
  test(`written authorization must explicitly permit ${permission}`, () => {
    const scope = writtenScope()
    scope.authorization.permissions[permission] = false
    assert.throws(
      () => assertValidHttpAuthedScope(scope),
      /written authorization|permission/i,
    )
  })
}

test('written authorization document bytes are rehashed and checked against the current lease', () => {
  assert.equal(typeof httpAuthedContracts.verifyHttpAuthedWrittenAuthorization, 'function')
  const scope = writtenScope()
  const verified = httpAuthedContracts.verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: new Date('2026-08-16T12:00:00.000Z'),
  })
  assert.equal(verified.scope, scope)
  assert.equal(verified.authorizationDocumentSha256, sha256Hex(AUTHORIZATION_DOCUMENT))
  assert.doesNotMatch(JSON.stringify(verified), /synthetic authorization fixture/)

  assert.throws(
    () => httpAuthedContracts.verifyHttpAuthedWrittenAuthorization({
      scope,
      documentBytes: Buffer.from('changed authorization document'),
      now: new Date('2026-08-16T12:00:00.000Z'),
    }),
    /document|digest/i,
  )
  assert.throws(
    () => httpAuthedContracts.verifyHttpAuthedWrittenAuthorization({
      scope,
      documentBytes: AUTHORIZATION_DOCUMENT,
      now: new Date('2026-08-16T12:04:00.000Z'),
    }),
    /expired|validity/i,
  )
})

test('written campaign scope disables sensitive persistence and rejects raw body fields', () => {
  const scope = writtenScope()
  assert.deepEqual(scope.evidence_handling, {
    persist_request_bodies: false,
    persist_response_bodies: false,
    persist_credential_values: false,
    persist_header_values: false,
    stop_on_sensitive_data: true,
    test_data: 'synthetic_only',
  })

  const rawBody = writtenScope()
  rawBody.requests[0].request_body.body_bytes = 'never persist this'
  assert.throws(() => assertValidHttpAuthedScope(rawBody), /schema/i)

  const responseBody = writtenScope()
  responseBody.requests[0].response_body = 'never persist this either'
  assert.throws(() => assertValidHttpAuthedScope(responseBody), /schema/i)
})

test('JSON shape observation modes require their exact versioned scope contract', () => {
  const observation = {
    mode: 'JSON_SHAPE_ONLY',
    max_depth: 3,
    safe_key_names: ['records', 'id'],
  }
  const legacyWithObservation = writtenScope()
  legacyWithObservation.response_observation = observation
  assert.throws(() => assertValidHttpAuthedScope(legacyWithObservation), /schema/i)

  const extensionWithoutObservation = writtenScope()
  extensionWithoutObservation.schema_version = '1.1.0'
  assert.throws(() => assertValidHttpAuthedScope(extensionWithoutObservation), /schema/i)

  const optedIn = writtenScope()
  optedIn.schema_version = '1.1.0'
  optedIn.response_observation = observation
  assert.doesNotThrow(() => assertValidHttpAuthedScope(optedIn))

  const aspNetObservation = {
    mode: 'ASPNET_D_JSON_SHAPE_ONLY',
    max_depth: 3,
    safe_key_names: ['records', 'id'],
  }
  const aspNetOptedIn = writtenScope()
  aspNetOptedIn.schema_version = '1.2.0'
  aspNetOptedIn.response_observation = aspNetObservation
  assert.doesNotThrow(() => assertValidHttpAuthedScope(aspNetOptedIn))

  for (const [version, responseObservation] of [
    ['1.1.0', aspNetObservation],
    ['1.2.0', observation],
  ]) {
    const mismatched = writtenScope()
    mismatched.schema_version = version
    mismatched.response_observation = responseObservation
    assert.throws(() => assertValidHttpAuthedScope(mismatched), /schema/i)
  }
})

test('bounded file loading verifies the scope and written authorization together', async (t) => {
  assert.equal(typeof httpAuthedContracts.readAndVerifyHttpAuthedWrittenAuthorization, 'function')
  const directory = await mkdtemp(join(tmpdir(), 'rta-http-authed-written-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const scopePath = join(directory, 'scope.json')
  const authorizationDocumentPath = join(directory, 'authorization.txt')
  await writeFile(scopePath, `${JSON.stringify(writtenScope())}\n`, 'utf8')
  await writeFile(authorizationDocumentPath, AUTHORIZATION_DOCUMENT)

  const verified = await httpAuthedContracts.readAndVerifyHttpAuthedWrittenAuthorization({
    scopePath,
    authorizationDocumentPath,
    now: new Date('2026-08-16T12:00:00.000Z'),
  })
  assert.equal(verified.scope.engagement_id, 'peerstar-credible-authorized-assessment')
  assert.equal(verified.authorizationDocumentSha256, sha256Hex(AUTHORIZATION_DOCUMENT))
})

test('CLI validates a written-authorized campaign without printing sensitive material', async (t) => {
  const { main } = await import('../scripts/http-authed.mjs')
  const directory = await mkdtemp(join(tmpdir(), 'rta-http-authed-cli-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const scopePath = join(directory, 'scope.json')
  const authorizationDocumentPath = join(directory, 'authorization.txt')
  const scope = writtenScope()
  await writeFile(scopePath, `${JSON.stringify(scope)}\n`, 'utf8')
  await writeFile(authorizationDocumentPath, AUTHORIZATION_DOCUMENT)
  let output = ''

  await main([
    'validate-written',
    '--scope', scopePath,
    '--authorization-document', authorizationDocumentPath,
    '--json',
  ], {
    clock: () => new Date('2026-08-16T12:00:00.000Z'),
    write: (text) => { output += text },
  })

  const summary = JSON.parse(output)
  assert.equal(summary.authorization_mode, 'WRITTEN_AUTHORIZATION_AUTHED')
  assert.equal(summary.request_count, 128)
  assert.equal(summary.authorization_document_sha256, sha256Hex(AUTHORIZATION_DOCUMENT))
  assert.equal(summary.campaign_grant_sha256, plannedCampaignGrantSha256(scope))
  assert.doesNotMatch(output, /synthetic authorization fixture/)
  assert.doesNotMatch(output, /SYNTHETIC_TEST_CREDENTIAL/)
  assert.doesNotMatch(output, /SYNTHETIC_SECURITY_TEST_PAYLOAD/)
})

export { writtenScope }
