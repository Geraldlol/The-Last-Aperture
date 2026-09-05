import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  assertValidProviderConfig,
  validateProviderConfig,
  validateProviderExecution,
} from '../scripts/lib/provider-contracts.mjs'
import {
  buildDockerCreateArgs,
  sanitizeProviderPacket,
} from '../scripts/lib/provider-runner.mjs'
import {
  providerConfig,
  providerPacket,
  SHA_A,
} from './helpers/provider-fixtures.mjs'

test('provider config requires a trusted absolute runtime and immutable image', () => {
  assert.equal(validateProviderConfig(providerConfig()).valid, true)

  const relativeRuntime = providerConfig({ runtime_path: 'docker' })
  assert.equal(validateProviderConfig(relativeRuntime).valid, false)

  const mutableImage = providerConfig({ image: 'audit-provider:latest' })
  assert.equal(validateProviderConfig(mutableImage).valid, false)

  const imageId = providerConfig({ image: `sha256:${SHA_A}` })
  assert.equal(validateProviderConfig(imageId).valid, true)
})

test('provider config enforces internally usable bounded limits', () => {
  const invalid = providerConfig({
    limits: {
      max_file_bytes: 8192,
      max_total_delivery_bytes: 4096,
      max_frame_bytes: 4096,
      max_stdout_bytes: 2048,
      tmpfs_bytes: 134217728,
      memory_bytes: 67108864,
      delivery_timeout_ms: 6000,
    },
  })
  const validation = validateProviderConfig(invalid)
  const codes = new Set(validation.errors.map(({ code }) => code))
  assert.ok(codes.has('PROVIDER_FILE_LIMIT_EXCEEDS_TOTAL'))
  assert.ok(codes.has('PROVIDER_FRAME_TOO_SMALL_FOR_FILE_LIMIT'))
  assert.ok(codes.has('PROVIDER_STDOUT_LIMIT_BELOW_FRAME_LIMIT'))
  assert.ok(codes.has('PROVIDER_TMPFS_EXCEEDS_MEMORY'))
  assert.ok(codes.has('PROVIDER_TIMEOUT_EXCEEDS_WALL_TIME'))
})

test('packet sanitization is an allowlist and strips target absolute paths', () => {
  const packet = sanitizeProviderPacket({
    ...providerPacket(),
    shard: { shard_id: 'shard-0001-aaaaaaaaaaaa', index: 1, count: 1 },
    evidence: [{ evidence_id: 'build-image', evidence_class: 'built-artifact' }],
    database_discovery: { schema_version: 1, stores: [] },
    database_store_ids: ['orders-primary'],
    profile_authority_store_ids: ['orders-primary'],
    future_host_secret: 'do-not-copy',
  })
  assert.equal(packet.repository_root, undefined)
  assert.equal(packet.lens_file, undefined)
  assert.equal(packet.future_host_secret, undefined)
  assert.equal(packet.scoped_files[0], 'src/app.js')
  assert.equal(packet.shard.shard_id, 'shard-0001-aaaaaaaaaaaa')
  assert.equal(packet.evidence[0].evidence_id, 'build-image')
  assert.deepEqual(packet.database_store_ids, ['orders-primary'])
  assert.deepEqual(packet.profile_authority_store_ids, ['orders-primary'])
  assert.deepEqual(packet.database_discovery, { schema_version: 1, stores: [] })
  assert.equal(packet.trust_boundary.provider_has_target_filesystem_authority, false)
  assert.equal(packet.trust_boundary.provider_has_network_authority, false)
  assert.equal(packet.trust_boundary.provider_has_host_process_authority, false)
})

test('Docker create argv fixes the hardened profile and never includes signing key material', () => {
  const config = assertValidProviderConfig(providerConfig())
  const args = buildDockerCreateArgs(
    config,
    'rta-provider-123456781234123412341234567890ab',
  )
  for (const expected of [
    '--context',
    'default',
    '--pull=never',
    '--network=none',
    '--read-only',
    '--cap-drop=ALL',
    '--security-opt=no-new-privileges=true',
    '--security-opt=seccomp=builtin',
    '--user=65532:65532',
    '--ipc=none',
    '--log-driver=none',
    '--no-healthcheck',
  ]) {
    assert.ok(args.includes(expected), `missing ${expected}`)
  }
  assert.equal(args.some((value) => value.startsWith('--mount')), false)
  assert.equal(args.some((value) => value.startsWith('--volume=')), false)
  assert.equal(args.includes(config.receipt_signing_private_key_path), false)
  assert.equal(args.at(-1), config.image)
})

test('execution contract rejects examined files without a consumed FILE delivery', () => {
  const packet = providerPacket()
  const result = {
    schema_version: '1.0.0',
    run_id: packet.run_id,
    job_id: packet.job_id,
    input_sha256: packet.packet_sha256,
    producer: {
      name: 'fixture-provider',
      version: '1.0.0',
      instance_id: 'fixture-provider:instance-1',
    },
    state: 'SUCCEEDED',
    examined_files: ['src/app.js'],
    findings: [],
    coverage_gaps: [],
  }
  const execution = {
    schema_version: '1.0.0',
    protocol: 'docker-stdio-v1',
    job_result: result,
    receipt: {
      schema_version: '1.0.0',
      observer: 'red-team-audit-controller',
      receipt_scope: 'BYTE_DELIVERY_AND_CHALLENGE_CONSUMPTION_ONLY',
      semantic_analysis_proven: false,
      run_id: packet.run_id,
      job_id: packet.job_id,
      packet_sha256: packet.packet_sha256,
      session_id: 'sessionopaqueidentifier01',
      started_at: '2026-07-29T10:00:00.000Z',
      completed_at: '2026-07-29T10:00:01.000Z',
      backend: {
        type: 'OCI_DOCKER',
        runtime_path: '/trusted/bin/docker',
        runtime_version: '99.0.0',
        context: 'default',
        image: `audit-provider@sha256:${SHA_A}`,
        container_name: 'rta-provider-123456781234123412341234567890ab',
        container_id: 'b'.repeat(64),
        security_profile: 'builtin',
      },
      deliveries: [],
      transcript_sha256: 'c'.repeat(64),
    },
  }
  const validation = validateProviderExecution(execution)
  assert.equal(validation.valid, false)
  assert.ok(validation.errors.some(
    ({ code }) => code === 'PROVIDER_EXAMINED_FILE_NOT_CONSUMED',
  ))
})
