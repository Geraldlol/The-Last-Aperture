import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync } from 'node:crypto'
import {
  RootAttestationError,
  assertValidRootAttestation,
  createRootAttestation,
  verifyRootAttestation,
} from '../scripts/lib/root-attestation.mjs'

function keyPair() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
  })
}

function terminalRun(overrides = {}) {
  return {
    schema_version: '3.0.0',
    run_id: 'run:2026-07-30T10-00-00-000Z:123456789abc',
    state: 'COMPLETED',
    phase: 'FINALIZED',
    ...overrides,
  }
}

function digest(value) {
  return createHash('sha256').update(value).digest('hex')
}

test('root attestation signs and verifies the exact terminal run identity', () => {
  const keys = keyPair()
  const run = terminalRun()
  const runSha256 = digest('exact run.json bytes\n')
  const attestation = createRootAttestation({
    run,
    runSha256,
    privateKeyBytes: keys.privateKey,
    signedAt: new Date('2026-07-30T10:01:02.003Z'),
  })

  assertValidRootAttestation(attestation)
  assert.deepEqual(
    verifyRootAttestation({
      attestation,
      run,
      runSha256,
      publicKeyBytes: keys.publicKey,
    }),
    {
      status: 'SIGNATURE_VERIFIED_WITH_SUPPLIED_KEY',
      key_id: attestation.signing.key_id,
      run_sha256: runSha256,
      signed_at: '2026-07-30T10:01:02.003Z',
    },
  )
})

test('root attestation rejects manifest replacement and signature tampering', () => {
  const keys = keyPair()
  const run = terminalRun()
  const runSha256 = digest('original run.json bytes\n')
  const attestation = createRootAttestation({
    run,
    runSha256,
    privateKeyBytes: keys.privateKey,
  })

  assert.throws(
    () => verifyRootAttestation({
      attestation,
      run,
      runSha256: digest('rewritten run.json bytes\n'),
      publicKeyBytes: keys.publicKey,
    }),
    /does not describe the exact loaded run manifest/i,
  )

  const tampered = structuredClone(attestation)
  const signature = Buffer.from(tampered.signature, 'base64')
  signature[0] ^= 1
  tampered.signature = signature.toString('base64')
  assert.throws(
    () => verifyRootAttestation({
      attestation: tampered,
      run,
      runSha256,
      publicKeyBytes: keys.publicKey,
    }),
    /signature verification failed/i,
  )
})

test('root attestation requires the externally pinned Ed25519 key', () => {
  const signingKeys = keyPair()
  const unrelatedKeys = keyPair()
  const run = terminalRun({ state: 'COMPLETE_WITH_GAPS' })
  const runSha256 = digest('run with gaps\n')
  const attestation = createRootAttestation({
    run,
    runSha256,
    privateKeyBytes: signingKeys.privateKey,
  })

  assert.throws(
    () => verifyRootAttestation({
      attestation,
      run,
      runSha256,
      publicKeyBytes: unrelatedKeys.publicKey,
    }),
    /does not match the externally pinned public key/i,
  )
})

test('root attestation refuses active runs and non-Ed25519 keys', () => {
  const keys = keyPair()
  assert.throws(
    () => createRootAttestation({
      run: terminalRun({ state: 'RUNNING', phase: 'FANOUT' }),
      runSha256: digest('active\n'),
      privateKeyBytes: keys.privateKey,
    }),
    /only a terminal FINALIZED run/i,
  )

  const rsa = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: {
      type: 'pkcs8',
      format: 'pem',
    },
    publicKeyEncoding: {
      type: 'spki',
      format: 'pem',
    },
  })
  assert.throws(
    () => createRootAttestation({
      run: terminalRun(),
      runSha256: digest('terminal\n'),
      privateKeyBytes: rsa.privateKey,
    }),
    RootAttestationError,
  )
})
