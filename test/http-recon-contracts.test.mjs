import assert from 'node:assert/strict'
import { generateKeyPairSync } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  assertValidHttpReconObservation,
  assertValidOperatorAttestedHttpReconScope,
  buildHttpReconPlan,
  buildOperatorAttestedHttpReconPlan,
  canonicalJson,
  createOperatorAttestedHttpReconScope,
  readAndVerifyHttpReconRoe,
  sha256Hex,
  signHttpReconRoe,
  signHttpReconTargetProof,
  verifyHttpReconTargetProof,
} from '../scripts/lib/http-recon-contracts.mjs'

const NOW = new Date('2026-08-04T12:00:00.000Z')
const AUTHORIZATION = Buffer.from('Owner-approved bounded staging reconnaissance.\n')

function keys() {
  const pair = generateKeyPairSync('ed25519')
  return {
    privateKeyBytes: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }),
    publicKeyBytes: pair.publicKey.export({ type: 'spki', format: 'pem' }),
  }
}

function roeDraft() {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-recon-roe',
    engagement_id: 'acme-2026-08-04-http-recon',
    environment: 'production',
    authorization: {
      authorization_id: 'acme-auth-0042',
      statement: 'I authorize the bounded HTTP reconnaissance described by this RoE against the exact target, request list, and validity window.',
      authorized_by: {
        organization: 'Acme Corporation',
        approver_name: 'A. Owner',
        approver_role: 'Chief Information Security Officer',
        contact: 'security@example.com',
      },
      emergency_stop_contact: {
        name: 'Security Operations',
        contact: 'soc@example.com',
      },
      document_sha256: sha256Hex(AUTHORIZATION),
    },
    target: {
      origin: 'https://target.example',
      tls_spki_sha256: 'a'.repeat(64),
      proof: {
        method: 'GET',
        url: 'https://target.example/.well-known/red-team-authorization.json',
        challenge_nonce: 'b'.repeat(64),
        max_age_ms: 60_000,
      },
    },
    validity: {
      not_before: '2026-08-04T11:59:00.000Z',
      not_after: '2026-08-04T12:04:00.000Z',
    },
    limits: {
      max_probe_requests: 2,
      max_target_proof_requests: 2,
      max_target_proof_response_bytes: 16_384,
      request_timeout_ms: 10_000,
      max_response_bytes: 65_536,
      max_aggregate_response_bytes: 262_144,
      max_wall_time_ms: 300_000,
      min_interval_ms: 1_000,
      concurrency: 1,
    },
    evidence_handling: {
      classification: 'CONFIDENTIAL',
      retention_days: 30,
    },
    stop_conditions: [
      'AUTHORIZATION_REVOKED',
      'EMERGENCY_STOP_REQUESTED',
      'AUTHORIZATION_WINDOW_CLOSED',
      'TARGET_PROOF_INVALID',
      'TARGET_IDENTITY_CHANGED',
      'LIMIT_REACHED',
      'UNEXPECTED_SIDE_EFFECT',
    ],
    requests: [
      { method: 'HEAD', url: 'https://target.example/' },
      {
        method: 'GET',
        url: 'https://target.example/security.txt',
        safe_to_get: true,
      },
    ],
  }
}

async function temporaryDirectory(t) {
  const directory = await mkdtemp(join(tmpdir(), 'rta-http-recon-contracts-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  return directory
}

test('externally pinned signature and authorization document bind one deterministic plan', async (t) => {
  const key = keys()
  const roe = signHttpReconRoe({ roe: roeDraft(), privateKeyBytes: key.privateKeyBytes })
  const directory = await temporaryDirectory(t)
  const path = join(directory, 'roe.json')
  await writeFile(path, `${JSON.stringify(roe)}\n`)

  const verified = await readAndVerifyHttpReconRoe({
    roePath: path,
    ownerPublicKeyBytes: key.publicKeyBytes,
    authorizationDocumentBytes: AUTHORIZATION,
    now: NOW,
  })
  assert.equal(verified.ownerKeyId, roe.signing.key_id)
  assert.equal(verified.authorizationDocumentSha256, roe.authorization.document_sha256)
  const first = buildHttpReconPlan(roe)
  const second = buildHttpReconPlan(structuredClone(roe))
  assert.equal(first.plan_sha256, second.plan_sha256)
  assert.equal(first.actions.length, 2)
  assert.equal(first.actions[0].safe_to_get, false)
  assert.match(first.actions[0].action_id, /^http-recon-action:[a-f0-9]{64}$/)
})

test('wrong external key, wrong document, and expired authorization fail closed', async (t) => {
  const key = keys()
  const other = keys()
  const roe = signHttpReconRoe({ roe: roeDraft(), privateKeyBytes: key.privateKeyBytes })
  const directory = await temporaryDirectory(t)
  const path = join(directory, 'roe.json')
  await writeFile(path, JSON.stringify(roe))
  await assert.rejects(
    readAndVerifyHttpReconRoe({
      roePath: path,
      ownerPublicKeyBytes: other.publicKeyBytes,
      authorizationDocumentBytes: AUTHORIZATION,
      now: NOW,
    }),
    /externally pinned owner key/,
  )
  await assert.rejects(
    readAndVerifyHttpReconRoe({
      roePath: path,
      ownerPublicKeyBytes: key.publicKeyBytes,
      authorizationDocumentBytes: Buffer.from('different'),
      now: NOW,
    }),
    /authorization document/,
  )
  await assert.rejects(
    readAndVerifyHttpReconRoe({
      roePath: path,
      ownerPublicKeyBytes: key.publicKeyBytes,
      authorizationDocumentBytes: AUTHORIZATION,
      now: new Date('2026-08-04T12:04:00.000Z'),
    }),
    /expired/,
  )
  const historical = await readAndVerifyHttpReconRoe({
    roePath: path,
    ownerPublicKeyBytes: key.publicKeyBytes,
    authorizationDocumentBytes: AUTHORIZATION,
    now: new Date('2027-01-01T00:00:00.000Z'),
    requireCurrentValidity: false,
  })
  assert.equal(historical.roe.engagement_id, roe.engagement_id)
})

test('target proof binds the exact plan, origin, TLS pin, nonce, and freshness', () => {
  const key = keys()
  const roe = signHttpReconRoe({ roe: roeDraft(), privateKeyBytes: key.privateKeyBytes })
  const plan = buildHttpReconPlan(roe)
  const proof = signHttpReconTargetProof({
    privateKeyBytes: key.privateKeyBytes,
    proof: {
      schema_version: '1.0.0',
      kind: 'red-team-audit/http-recon-target-proof',
      engagement_id: roe.engagement_id,
      authorization_id: roe.authorization.authorization_id,
      authorization_document_sha256: roe.authorization.document_sha256,
      target_origin: roe.target.origin,
      target_tls_spki_sha256: roe.target.tls_spki_sha256,
      proof_url: roe.target.proof.url,
      challenge_nonce: roe.target.proof.challenge_nonce,
      plan_sha256: plan.plan_sha256,
      issued_at: '2026-08-04T11:59:59.000Z',
      expires_at: '2026-08-04T12:00:30.000Z',
    },
  })
  assert.equal(verifyHttpReconTargetProof({
    proof,
    roe,
    planSha256: plan.plan_sha256,
    ownerPublicKeyBytes: key.publicKeyBytes,
    now: NOW,
  }), proof)
  assert.throws(
    () => verifyHttpReconTargetProof({
      proof,
      roe,
      planSha256: 'f'.repeat(64),
      ownerPublicKeyBytes: key.publicKeyBytes,
      now: NOW,
    }),
    /plan_sha256/,
  )
  assert.throws(
    () => verifyHttpReconTargetProof({
      proof,
      roe,
      planSha256: plan.plan_sha256,
      ownerPublicKeyBytes: key.publicKeyBytes,
      now: new Date('2026-08-04T12:00:30.000Z'),
    }),
    /not fresh/,
  )
})

test('ambiguous URLs, query scope, and spare request authority are rejected', () => {
  const key = keys()
  for (const mutate of [
    (roe) => { roe.requests[0].url = 'https://target.example/?admin=true' },
    (roe) => { roe.requests[0].url = 'https://target.example/%2e%2e/admin' },
    (roe) => { roe.requests[0].url = 'https://other.example/' },
    (roe) => { roe.limits.max_probe_requests = 3 },
  ]) {
    const draft = roeDraft()
    mutate(draft)
    assert.throws(
      () => signHttpReconRoe({ roe: draft, privateKeyBytes: key.privateKeyBytes }),
      /query|ambiguous|canonical|origin|action count|schema/i,
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
    authorizationReference: 'owner approval conversation 2026-08-04',
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
  assert.equal(built.plan.target.proof, null)
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
    authorizationReference: 'owner approval conversation 2026-08-04',
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
    authorizationReference: 'owner approval conversation 2026-08-04',
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
    authorizationReference: 'owner approval conversation 2026-08-04',
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
      mode: 'EXTERNAL_SIGNED',
      authorization_id: 'acme-auth-0042',
      authorization_document_sha256: digest,
      owner_key_id: `ed25519:${digest}`,
      plan_sha256: digest,
      target_proof_sha256: digest,
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
