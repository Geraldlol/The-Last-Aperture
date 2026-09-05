import assert from 'node:assert/strict'
import { test } from 'node:test'
import * as httpReconContracts from '../scripts/lib/http-recon-contracts.mjs'
import {
  assertValidHttpReconObservation,
  assertValidOperatorAttestedHttpReconScope,
  buildOperatorAttestedHttpReconPlan,
  canonicalJson,
  createOperatorAttestedHttpReconScope,
} from '../scripts/lib/http-recon-contracts.mjs'

const NOW = new Date('2026-08-04T12:00:00.000Z')

test('signed authorization contracts are absent from the public module surface', () => {
  for (const retiredExport of [
    'httpReconRoeSchema',
    'httpReconTargetProofSchema',
    'validateHttpReconRoe',
    'assertValidHttpReconRoe',
    'signHttpReconRoe',
    'verifyHttpReconRoeSignature',
    'readAndVerifyHttpReconRoe',
    'buildHttpReconPlan',
    'validateHttpReconTargetProof',
    'assertValidHttpReconTargetProof',
    'signHttpReconTargetProof',
    'verifyHttpReconTargetProof',
  ]) {
    assert.equal(
      Object.hasOwn(httpReconContracts, retiredExport),
      false,
      retiredExport,
    )
  }
})

test('operator-attested plans reject ambiguous URLs, target drift, and spare request authority', () => {
  const input = {
    engagementId: 'operator-attested-boundary-engagement',
    authorizationId: 'operator-attested-boundary-authorization',
    targetUrl: 'https://target.example/',
    operatorId: 'operator-001',
    authorizedBy: 'A. Asset Owner',
    authorizationReference: 'operator authorization reference 2026-08-04',
    environment: 'production',
    now: NOW,
  }
  for (const targetUrl of [
    'https://target.example/?admin=true',
    'https://target.example/%2e%2e/admin',
  ]) {
    assert.throws(
      () => createOperatorAttestedHttpReconScope({ ...input, targetUrl }),
      /query|ambiguous|canonical|schema/i,
    )
  }
  for (const mutate of [
    (scope) => { scope.requests[0].url = 'https://other.example/' },
    (scope) => { scope.limits.max_probe_requests = 2 },
  ]) {
    const scope = createOperatorAttestedHttpReconScope(input)
    mutate(scope)
    assert.throws(
      () => buildOperatorAttestedHttpReconPlan(scope),
      /origin|action count|schema|limits/i,
    )
  }
})

test('operator attestation deterministically seals one exact proof-less action', () => {
  const input = {
    engagementId: 'operator-attested-engagement',
    authorizationId: 'operator-attested-authorization',
    targetUrl: 'https://target.example/security.txt',
    operatorId: 'operator-001',
    authorizedBy: 'A. Asset Owner',
    authorizationReference: 'operator authorization reference 2026-08-04',
    environment: 'production',
    now: NOW,
  }
  const first = createOperatorAttestedHttpReconScope(input)
  const second = createOperatorAttestedHttpReconScope(input)
  assert.deepEqual(first, second)
  const built = buildOperatorAttestedHttpReconPlan(first)
  assert.equal(built.actions.length, 1)
  assert.equal(built.actions[0].method, 'HEAD')
  assert.equal(built.plan.authorization_mode, 'OPERATOR_ATTESTED')
  assert.equal(Object.hasOwn(built.plan.target, 'proof'), false)
  assert.deepEqual(built.plan.target.tls, { mode: 'PKIX_HOSTNAME' })
  assert.equal(built.plan.limits.max_target_proof_requests, 0)
  assert.match(built.plan_sha256, /^[a-f0-9]{64}$/)
  assert.match(built.scope_sha256, /^[a-f0-9]{64}$/)

  assert.throws(
    () => createOperatorAttestedHttpReconScope({
      ...input,
      method: 'GET',
    }),
    /safe-to-get acknowledgment/,
  )
  assert.throws(
    () => createOperatorAttestedHttpReconScope({
      ...input,
      tlsSpkiSha256: 'not-a-pin',
    }),
    /JSON schema/,
  )
  const pinned = createOperatorAttestedHttpReconScope({
    ...input,
    tlsSpkiSha256: 'a'.repeat(64),
  })
  assert.deepEqual(pinned.target.tls, {
    mode: 'PKIX_HOSTNAME_AND_SPKI_PIN',
    spki_sha256: 'a'.repeat(64),
  })
  const drifted = structuredClone(first)
  drifted.requests[0].url = 'https://other.example/'
  assert.throws(
    () => buildOperatorAttestedHttpReconPlan(drifted),
    /exact attested target origin/,
  )
})

test('operator attestation hash-binds one controller-owned diagnostic header profile', () => {
  const input = {
    engagementId: 'operator-attested-header-engagement',
    authorizationId: 'operator-attested-header-authorization',
    targetUrl: 'https://target.example/api/TabAccess/GetAll',
    method: 'GET',
    safeToGet: true,
    requestHeaderProfile: 'x-original-url-order-programs-v1',
    operatorId: 'operator-001',
    authorizedBy: 'A. Asset Owner',
    authorizationReference: 'operator authorization reference 2026-08-04',
    environment: 'production',
    now: NOW,
  }
  const scope = createOperatorAttestedHttpReconScope(input)
  const built = buildOperatorAttestedHttpReconPlan(scope)
  assert.equal(scope.schema_version, '1.1.0')
  assert.equal(built.plan.schema_version, '1.1.0')
  assert.equal(scope.requests[0].request_headers.profile, input.requestHeaderProfile)
  assert.deepEqual(built.actions[0].request_headers, scope.requests[0].request_headers)

  const baseline = buildOperatorAttestedHttpReconPlan(
    createOperatorAttestedHttpReconScope({ ...input, requestHeaderProfile: undefined }),
  )
  assert.notEqual(built.actions[0].action_id, baseline.actions[0].action_id)
  assert.notEqual(built.plan_sha256, baseline.plan_sha256)

  const forged = structuredClone(scope)
  forged.requests[0].request_headers.header_set_sha256 = '0'.repeat(64)
  assert.throws(() => assertValidOperatorAttestedHttpReconScope(forged), /header|descriptor/i)

  const downgraded = structuredClone(scope)
  downgraded.schema_version = '1.0.0'
  assert.throws(() => assertValidOperatorAttestedHttpReconScope(downgraded), /schema/i)

  assert.throws(
    () => createOperatorAttestedHttpReconScope({
      ...input,
      method: 'HEAD',
      safeToGet: false,
    }),
    /method/i,
  )
})

test('operator attestation hash-binds the narrow Credible bundle-src observer', () => {
  const input = {
    engagementId: 'operator-attested-bundle-src-engagement',
    authorizationId: 'operator-attested-bundle-src-authorization',
    targetUrl: 'https://www.cbh3.crediblebh.com/secure/index.aspx',
    method: 'GET',
    safeToGet: true,
    responseObservationProfile: 'credible-bundle-src-v1',
    operatorId: 'operator-001',
    authorizedBy: 'A. Asset Owner',
    authorizationReference: 'operator authorization reference 2026-08-04',
    environment: 'production',
    now: NOW,
  }
  const scope = createOperatorAttestedHttpReconScope(input)
  const built = buildOperatorAttestedHttpReconPlan(scope)
  assert.equal(scope.schema_version, '1.2.0')
  assert.equal(built.plan.schema_version, '1.2.0')
  assert.equal(
    scope.requests[0].response_observation.profile,
    'credible-bundle-src-v1',
  )
  assert.deepEqual(
    built.actions[0].response_observation,
    scope.requests[0].response_observation,
  )

  const baseline = buildOperatorAttestedHttpReconPlan(
    createOperatorAttestedHttpReconScope({
      ...input,
      responseObservationProfile: undefined,
    }),
  )
  assert.notEqual(built.actions[0].action_id, baseline.actions[0].action_id)
  assert.notEqual(built.plan_sha256, baseline.plan_sha256)

  const forged = structuredClone(scope)
  forged.requests[0].response_observation.profile_binding_sha256 = '0'.repeat(64)
  assert.throws(
    () => assertValidOperatorAttestedHttpReconScope(forged),
    /response-observation|descriptor/iu,
  )

  const downgraded = structuredClone(scope)
  downgraded.schema_version = '1.1.0'
  assert.throws(() => assertValidOperatorAttestedHttpReconScope(downgraded), /schema/iu)

  for (const overrides of [
    { method: 'HEAD', safeToGet: false },
    { targetUrl: 'https://assets.cbh3.crediblebh.com/index.html' },
    { targetUrl: 'https://www.cbh3.crediblebh.com.evil.invalid/index.html' },
  ]) {
    assert.throws(
      () => createOperatorAttestedHttpReconScope({ ...input, ...overrides }),
      /method, origin, or byte boundary|schema/iu,
    )
  }
})

test('operator attestation binds the two exact digest-pinned cross-origin AST assets', () => {
  const base = {
    engagementId: 'operator-attested-cross-origin-ast-engagement',
    authorizationId: 'operator-attested-cross-origin-ast-authorization',
    method: 'GET',
    safeToGet: true,
    responseObservationProfile: 'credible-cross-origin-js-ast-v1',
    operatorId: 'operator-001',
    authorizedBy: 'A. Asset Owner',
    authorizationReference: 'operator authorization reference 2026-08-04',
    environment: 'production',
    now: NOW,
  }
  const urls = [
    'https://assets.cbh3.crediblebh.com/js/cross-origin-messaging.js',
    'https://assets.cbh3.crediblebh.com/js/global-cross-origin-helpers.js',
  ]
  const built = urls.map((targetUrl, index) => {
    const scope = createOperatorAttestedHttpReconScope({
      ...base,
      engagementId: `${base.engagementId}-${index}`,
      authorizationId: `${base.authorizationId}-${index}`,
      targetUrl,
    })
    const plan = buildOperatorAttestedHttpReconPlan(scope)
    assert.equal(scope.schema_version, '1.2.0')
    assert.equal(
      scope.requests[0].response_observation.profile,
      'credible-cross-origin-js-ast-v1',
    )
    assert.deepEqual(
      plan.actions[0].response_observation,
      scope.requests[0].response_observation,
    )
    return plan
  })
  assert.notEqual(built[0].actions[0].action_id, built[1].actions[0].action_id)

  for (const targetUrl of [
    'https://assets.cbh3.crediblebh.com/js/other.js',
    'https://assets.cbh3.crediblebh.com/js/cross-origin-messaging.js?cache=1',
    'https://www.cbh3.crediblebh.com/js/cross-origin-messaging.js',
  ]) {
    assert.throws(
      () => createOperatorAttestedHttpReconScope({ ...base, targetUrl }),
      /method, origin, or byte boundary|targetUrl/iu,
    )
  }
})

test('observation contract retains transport metadata but never response bytes', () => {
  const digest = 'c'.repeat(64)
  const observation = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-recon-observation',
    run_id: `http-recon-run:${digest}`,
    engagement_id: 'acme-2026-08-04-http-recon',
    action_id: `http-recon-action:${digest}`,
    sequence: 1,
    observed_at: NOW.toISOString(),
    authority: {
      mode: 'OPERATOR_ATTESTED',
      authorization_id: 'operator-attested-authorization',
      operator_id: 'operator-001',
      scope_sha256: digest,
      plan_sha256: digest,
      independently_verified: false,
    },
    method: 'HEAD',
    url: 'https://target.example/',
    status_code: 200,
    response_headers: [{ name: 'content-type', value: 'text/html' }],
    response_header_summary: {
      retained_bytes: 21,
      omitted_count: 0,
      redacted_names: [],
      truncated: false,
    },
    body: {
      bytes: null,
      sha256: digest,
      size: 42,
      retained_size: 0,
      retained: false,
      truncated: false,
      digest_scope: 'complete',
    },
    network: {
      dns_sha256: digest,
      dns_answers: [{ address: '93.184.216.34', family: 4 }],
      resolved_ip: '93.184.216.34',
      resolved_family: 4,
      tls_protocol: 'TLSv1.3',
      tls_cipher: 'TLS_AES_256_GCM_SHA384',
      tls_verification: 'PKIX_HOSTNAME_AND_SPKI_PIN',
      peer_certificate_sha256: digest,
      peer_spki_sha256: digest,
    },
    timing_ms: {
      dns_ms: 1,
      tls_handshake_ms: 2,
      before_send_ms: 1,
      time_to_first_byte_ms: 3,
      total_ms: 7,
    },
    stop_condition: null,
  }
  assert.equal(assertValidHttpReconObservation(observation), observation)
  const retiredAuthority = structuredClone(observation)
  retiredAuthority.authority = {
    mode: 'EXTERNAL_SIGNED',
    authorization_id: 'retired-authorization',
    authorization_document_sha256: digest,
    owner_key_id: `ed25519:${digest}`,
    plan_sha256: digest,
    target_proof_sha256: digest,
  }
  assert.throws(
    () => assertValidHttpReconObservation(retiredAuthority),
    /schema/,
  )
  const leaked = structuredClone(observation)
  leaked.body.bytes = 'secret'
  assert.throws(() => assertValidHttpReconObservation(leaked), /schema/)

  const astObservation = structuredClone(observation)
  astObservation.schema_version = '1.1.0'
  astObservation.method = 'GET'
  astObservation.url =
    'https://assets.cbh3.crediblebh.com/js/cross-origin-messaging.js'
  astObservation.response_observation = {
    profile: 'credible-cross-origin-js-ast-v1',
    profile_binding_sha256: digest,
    analysis: {
      analysis_complete: true,
      message_listeners: {
        count: 1,
        inline_handler_count: 1,
        resolved_handler_count: 1,
        unresolved_handler_count: 0,
        origin_guard_candidate_count: 0,
        source_guard_candidate_count: 0,
        both_guard_candidate_count: 0,
        without_origin_guard_candidate_count: 1,
        without_source_guard_candidate_count: 1,
        has_resolved_handler_without_origin_guard_candidate: true,
        has_resolved_handler_without_source_guard_candidate: true,
      },
      post_message_calls: {
        count: 1,
        targets: {
          wildcard_literal_count: 1,
          same_origin_expression_count: 0,
          static_origin_literal_count: 0,
          opaque_or_null_literal_count: 0,
          other_static_literal_count: 0,
          dynamic_expression_count: 0,
          missing_count: 0,
        },
        has_wildcard_target: true,
        has_dynamic_target: false,
      },
      token_like_flows: {
        reference_count: 0,
        message_listener_candidate_count: 0,
        message_input_to_token_sink_candidate_count: 0,
        post_message_payload_candidate_count: 0,
        candidate_count: 0,
        present: false,
      },
    },
  }
  assert.equal(assertValidHttpReconObservation(astObservation), astObservation)
  const leakedAnalysis = structuredClone(astObservation)
  leakedAnalysis.response_observation.analysis.source_snippet = 'not allowed'
  assert.throws(() => assertValidHttpReconObservation(leakedAnalysis), /schema/)
  assert.match(canonicalJson(observation), /CONTROLLER|http-recon-observation/)
})
