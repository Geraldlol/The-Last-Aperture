import assert from 'node:assert/strict'
import { test } from 'node:test'
import * as httpReconContracts from '../scripts/lib/http-recon-contracts.mjs'
import {
  assertValidControllerPolicyHttpReconAuthority,
  assertValidControllerPolicyHttpReconReceipt,
  assertValidHttpReconObservation,
  assertValidOperatorAttestedHttpReconScope,
  buildControllerPolicyHttpReconPlan,
  buildOperatorAttestedHttpReconPlan,
  canonicalJson,
  controllerPolicyHttpReconTargetId,
  createControllerPolicyHttpReconAuthority,
  createControllerPolicyHttpReconReceipt,
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
    'https://target.example/%252e%252e%252fadmin',
    'https://target.example/%25252e%25252e%25252fadmin',
    'https://target.example/%25%32%65%25%32%65%25%32%66admin',
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
    targetUrl: 'https://target.example/diagnostics/headers',
    method: 'GET',
    safeToGet: true,
    requestHeaderProfile: 'x-forwarded-for-loopback-v1',
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

  const targetSpecificExtension = structuredClone(scope)
  targetSpecificExtension.schema_version = '1.2.0'
  targetSpecificExtension.requests[0].response_observation = {
    profile: 'target-specific-parser-v1',
    profile_binding_sha256: '0'.repeat(64),
  }
  assert.throws(
    () => assertValidOperatorAttestedHttpReconScope(targetSpecificExtension),
    /schema/i,
  )

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

test('controller deployment-policy authority seals one exact HEAD target without operator claims', () => {
  const targetUrl = 'https://target.example/security.txt'
  const admission = {
    policy_id: 'deployment-policy-2026-08-04',
    policy_sha256: 'a'.repeat(64),
    target_id: controllerPolicyHttpReconTargetId(targetUrl),
    effect: 'OBSERVE',
    admitted_at: NOW.toISOString(),
    revocation_check_id: 'deployment-revocations-v1',
  }
  const authority = createControllerPolicyHttpReconAuthority({
    controllerPolicyAuthority: admission,
  })
  assert.deepEqual(Object.keys(authority).toSorted(), [
    'admitted_at',
    'effect',
    'mode',
    'policy_id',
    'policy_sha256',
    'revocation_check_id',
    'target_id',
  ])
  assert.equal(Object.hasOwn(authority, 'operator_id'), false)
  assert.equal(Object.hasOwn(authority, 'statement'), false)
  assert.equal(Object.hasOwn(authority, 'independently_verified'), false)
  assert.equal(
    assertValidControllerPolicyHttpReconAuthority(authority, { now: NOW }),
    authority,
  )

  const built = buildControllerPolicyHttpReconPlan({
    engagementId: 'controller-policy-engagement',
    authority,
    targetUrl,
  })
  assert.equal(built.plan.authorization_mode, 'CONTROLLER_DEPLOYMENT_POLICY')
  assert.equal(built.actions.length, 1)
  assert.deepEqual(built.actions[0], {
    action_id: built.actions[0].action_id,
    sequence: 1,
    method: 'HEAD',
    url: targetUrl,
    safe_to_get: false,
  })
  assert.equal(Object.hasOwn(built.actions[0], 'request_headers'), false)
  const receipt = createControllerPolicyHttpReconReceipt({
    authority,
    targetUrl,
    planSha256: built.plan_sha256,
  })
  assert.equal(
    assertValidControllerPolicyHttpReconReceipt(receipt, { now: NOW }),
    receipt,
  )

  assert.throws(
    () => createControllerPolicyHttpReconAuthority({
      controllerPolicyAuthority: { ...admission, operator_id: 'fabricated' },
    }),
    /exactly|authority/i,
  )
  assert.throws(
    () => createControllerPolicyHttpReconAuthority({
      controllerPolicyAuthority: { ...admission, effect: 'MUTATE' },
    }),
    /schema/i,
  )
  assert.throws(
    () => buildControllerPolicyHttpReconPlan({
      engagementId: 'controller-policy-engagement',
      authority: { ...authority, target_id: `target:sha256:${'b'.repeat(64)}` },
      targetUrl,
    }),
    /target_id|bind/i,
  )
  const limitsDrift = structuredClone(receipt)
  limitsDrift.limits.max_probe_requests = 2
  assert.throws(
    () => assertValidControllerPolicyHttpReconReceipt(limitsDrift, { now: NOW }),
    /limits|schema/i,
  )
  const targetDrift = structuredClone(receipt)
  targetDrift.canonical_target = 'https://other.example/security.txt'
  assert.throws(
    () => assertValidControllerPolicyHttpReconReceipt(targetDrift, { now: NOW }),
    /target_id|target/i,
  )
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
  const controllerPolicyObservation = structuredClone(observation)
  controllerPolicyObservation.authority = createControllerPolicyHttpReconAuthority({
    controllerPolicyAuthority: {
      policy_id: 'deployment-policy-2026-08-04',
      policy_sha256: 'a'.repeat(64),
      target_id: controllerPolicyHttpReconTargetId(observation.url),
      effect: 'OBSERVE',
      admitted_at: NOW.toISOString(),
      revocation_check_id: 'deployment-revocations-v1',
    },
  })
  assert.equal(
    assertValidHttpReconObservation(controllerPolicyObservation),
    controllerPolicyObservation,
  )
  controllerPolicyObservation.authority.operator_id = 'fabricated-operator'
  assert.throws(
    () => assertValidHttpReconObservation(controllerPolicyObservation),
    /schema/i,
  )
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

  const targetSpecificExtension = structuredClone(observation)
  targetSpecificExtension.response_observation = {
    profile: 'target-specific-parser-v1',
    profile_binding_sha256: digest,
  }
  assert.throws(
    () => assertValidHttpReconObservation(targetSpecificExtension),
    /schema/,
  )

  assert.match(canonicalJson(observation), /CONTROLLER|http-recon-observation/)
})
