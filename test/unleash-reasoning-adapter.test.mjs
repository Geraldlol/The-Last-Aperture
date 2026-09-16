import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import test from 'node:test'

import {
  createUnleashRoleRequest,
  createUnleashSwarmBasis,
  UNLEASH_SWARM_DEFAULT_LIMITS,
} from '../scripts/lib/unleash-swarm-contracts.mjs'
import {
  UnleashReasoningAdapterError,
  assertValidUnleashReasoningAdapterIdentity,
  captureUnleashReasoningResponse,
  createUnleashReasoningAdapter,
} from '../scripts/lib/unleash-reasoning-adapter.mjs'

const SHA = Object.freeze(Object.fromEntries(
  'abcdefghijklmnop'.split('').map((letter, index) => [
    letter,
    '0123456789abcdef'[index].repeat(64),
  ]),
))
const ARTIFACT_BYTES = Buffer.alloc(128, 0x41)
const ARTIFACT_SHA256 = createHash('sha256').update(ARTIFACT_BYTES).digest('hex')

function basis() {
  return createUnleashSwarmBasis({
    recordedAt: '2026-09-15T14:00:00.000Z',
    campaignId: `campaign:sha256:${SHA.a}`,
    campaignStateRevision: 2,
    campaignStateSha256: SHA.b,
    planSha256: SHA.c,
    targetId: `target:sha256:${SHA.d}`,
    registrySha256: SHA.e,
    providerProfileSha256: SHA.f,
    evidencePacketSha256: SHA.g,
    completionReceiptSha256: SHA.h,
    limits: structuredClone(UNLEASH_SWARM_DEFAULT_LIMITS),
  })
}

function request(swarmBasis = basis()) {
  return createUnleashRoleRequest({
    basis: swarmBasis,
    round: 1,
    roleId: 'attacker:perimeter',
    inputFrontierSha256: SHA.i,
    inputChallengeSetSha256: SHA.j,
    evidenceRefs: [`evidence:sha256:${ARTIFACT_SHA256}`],
    allowedToolIds: ['tool:https-recon'],
    artifacts: [{
      artifact_id: `artifact:sha256:${SHA.l}`,
      kind: 'EVIDENCE',
      logical_name: 'verified-https-recon.json',
      sha256: ARTIFACT_SHA256,
      size: ARTIFACT_BYTES.length,
    }],
  })
}

function artifactPayloads() {
  return [{
    artifact_id: `artifact:sha256:${SHA.l}`,
    media_type: 'application/json',
    sha256: ARTIFACT_SHA256,
    size: ARTIFACT_BYTES.length,
    bytes: Buffer.from(ARTIFACT_BYTES),
  }]
}

function identity() {
  return {
    adapter_id: 'adapter:fixture-provider',
    adapter_version: '1.0.0',
    adapter_config_sha256: SHA.m,
  }
}

function limits(overrides = {}) {
  return {
    wall_time_ms: 500,
    max_response_bytes: 1024,
    max_frame_bytes: 512,
    max_frames: 8,
    ...overrides,
  }
}

function rejectsCode(code) {
  return (error) => error instanceof UnleashReasoningAdapterError && error.code === code
}

test('captures bounded byte frames and binds a transport-only receipt to the request and adapter', async () => {
  const swarmBasis = basis()
  const roleRequest = request(swarmBasis)
  const observed = []
  const adapter = createUnleashReasoningAdapter({
    identity: identity(),
    async invoke(envelope, context) {
      observed.push({ envelope, context })
      return (async function * frames() {
        yield Buffer.from('{"answer":')
        yield new Uint8Array(Buffer.from('true}'))
      }())
    },
  })

  const result = await captureUnleashReasoningResponse({
    adapter,
    basis: swarmBasis,
    request: roleRequest,
    artifactPayloads: artifactPayloads(),
    limits: limits(),
  })

  assert.equal(result.responseBytes.toString('utf8'), '{"answer":true}')
  assert.equal(result.transportReceipt.adapter_id, identity().adapter_id)
  assert.equal(result.transportReceipt.adapter_version, identity().adapter_version)
  assert.equal(
    result.transportReceipt.adapter_config_sha256,
    identity().adapter_config_sha256,
  )
  assert.equal(result.transportReceipt.request_id, roleRequest.request_id)
  assert.equal(result.transportReceipt.request_sha256, roleRequest.request_sha256)
  assert.equal(
    result.transportReceipt.response_sha256,
    createHash('sha256').update(result.responseBytes).digest('hex'),
  )
  assert.equal(result.transportReceipt.scope, 'TRANSPORT_ONLY')
  assert.equal(result.transportReceipt.semantic_analysis_proven, false)
  assert.equal(Object.isFrozen(result.transportReceipt), true)
  assert.equal(Object.isFrozen(observed[0].envelope), true)
  assert.equal(Object.isFrozen(observed[0].envelope.request), true)
  assert.equal(Object.isFrozen(observed[0].envelope.artifact_payloads), true)
  assert.equal(
    Buffer.from(observed[0].envelope.artifact_payloads[0].content_base64, 'base64')
      .equals(ARTIFACT_BYTES),
    true,
  )
  assert.equal(observed[0].context.signal instanceof AbortSignal, true)
  assert.deepEqual(observed[0].context.limits, limits())
  assert.deepEqual(
    assertValidUnleashReasoningAdapterIdentity(adapter.identity),
    adapter.identity,
  )
})

test('rejects computed adapter input without invoking the accessor', () => {
  let getterCalls = 0
  const computedIdentity = identity()
  Object.defineProperty(computedIdentity, 'adapter_version', {
    enumerable: true,
    get() {
      getterCalls += 1
      throw new Error('must not execute')
    },
  })

  assert.throws(
    () => createUnleashReasoningAdapter({ identity: computedIdentity, invoke() {} }),
    rejectsCode('UNLEASH_REASONING_ADAPTER_INPUT_INVALID'),
  )
  assert.equal(getterCalls, 0)
})

test('enforces frame and aggregate byte bounds before returning provider bytes', async () => {
  const swarmBasis = basis()
  const roleRequest = request(swarmBasis)
  const oversizedFrame = createUnleashReasoningAdapter({
    identity: identity(),
    invoke: async () => Buffer.alloc(513),
  })
  await assert.rejects(
    captureUnleashReasoningResponse({
      adapter: oversizedFrame,
      basis: swarmBasis,
      request: roleRequest,
      artifactPayloads: artifactPayloads(),
      limits: limits(),
    }),
    rejectsCode('UNLEASH_REASONING_FRAME_LIMIT'),
  )

  const aggregateOverflow = createUnleashReasoningAdapter({
    identity: identity(),
    async invoke() {
      return (async function * frames() {
        yield Buffer.alloc(500)
        yield Buffer.alloc(500)
        yield Buffer.alloc(25)
      }())
    },
  })
  await assert.rejects(
    captureUnleashReasoningResponse({
      adapter: aggregateOverflow,
      basis: swarmBasis,
      request: roleRequest,
      artifactPayloads: artifactPayloads(),
      limits: limits(),
    }),
    rejectsCode('UNLEASH_REASONING_RESPONSE_LIMIT'),
  )
})

test('rejects over-bound provider frames before copying or encoding them', async () => {
  const swarmBasis = basis()
  const roleRequest = request(swarmBasis)
  const oversizedBuffer = Buffer.alloc(513)
  const oversizedUint8Array = new Uint8Array(513)
  let computedLengthCalls = 0
  for (const source of [oversizedBuffer, oversizedUint8Array]) {
    for (const field of ['byteLength', 'length']) {
      Object.defineProperty(source, field, {
        configurable: true,
        get() {
          computedLengthCalls += 1
          throw new Error('provider length accessors must not execute')
        },
      })
    }
  }
  const oversizedString = 'x'.repeat(513)
  const aggregateBufferTail = Buffer.alloc(25)
  const aggregateStringTail = 'x'.repeat(25)
  const forbiddenCopies = new Set([
    oversizedBuffer,
    oversizedUint8Array,
    oversizedString,
    aggregateBufferTail,
    aggregateStringTail,
  ])
  const forbiddenByteLengths = new Set([oversizedString, aggregateStringTail])
  const originalBufferFrom = Buffer.from
  const originalBufferByteLength = Buffer.byteLength
  let rejectedCopyCount = 0
  let rejectedByteLengthCount = 0
  Buffer.from = function guardedBufferFrom(value, ...args) {
    if (forbiddenCopies.has(value)) {
      rejectedCopyCount += 1
      throw new Error('rejected provider data must not be copied')
    }
    return Reflect.apply(originalBufferFrom, Buffer, [value, ...args])
  }
  Buffer.byteLength = function guardedBufferByteLength(value, ...args) {
    if (forbiddenByteLengths.has(value)) {
      rejectedByteLengthCount += 1
      throw new Error('over-bound strings must not be scanned')
    }
    return Reflect.apply(originalBufferByteLength, Buffer, [value, ...args])
  }

  try {
    for (const source of [oversizedBuffer, oversizedUint8Array, oversizedString]) {
      const adapter = createUnleashReasoningAdapter({
        identity: identity(),
        invoke: async () => source,
      })
      await assert.rejects(
        captureUnleashReasoningResponse({
          adapter,
          basis: swarmBasis,
          request: roleRequest,
          artifactPayloads: artifactPayloads(),
          limits: limits(),
        }),
        rejectsCode('UNLEASH_REASONING_FRAME_LIMIT'),
      )
    }

    const aggregateOverflow = createUnleashReasoningAdapter({
      identity: identity(),
      async invoke() {
        return (async function * frames() {
          yield Buffer.alloc(500)
          yield Buffer.alloc(500)
          yield aggregateBufferTail
        }())
      },
    })
    await assert.rejects(
      captureUnleashReasoningResponse({
        adapter: aggregateOverflow,
        basis: swarmBasis,
        request: roleRequest,
        artifactPayloads: artifactPayloads(),
        limits: limits(),
      }),
      rejectsCode('UNLEASH_REASONING_RESPONSE_LIMIT'),
    )

    const aggregateStringOverflow = createUnleashReasoningAdapter({
      identity: identity(),
      async invoke() {
        return (async function * frames() {
          yield 'x'.repeat(500)
          yield 'x'.repeat(500)
          yield aggregateStringTail
        }())
      },
    })
    await assert.rejects(
      captureUnleashReasoningResponse({
        adapter: aggregateStringOverflow,
        basis: swarmBasis,
        request: roleRequest,
        artifactPayloads: artifactPayloads(),
        limits: limits(),
      }),
      rejectsCode('UNLEASH_REASONING_RESPONSE_LIMIT'),
    )
  } finally {
    Buffer.from = originalBufferFrom
    Buffer.byteLength = originalBufferByteLength
  }
  assert.equal(rejectedCopyCount, 0)
  assert.equal(rejectedByteLengthCount, 0)
  assert.equal(computedLengthCalls, 0)
})

test('aborts before dispatch and times out a stalled frame without parsing or replaying it', async () => {
  const swarmBasis = basis()
  const roleRequest = request(swarmBasis)
  let invocations = 0
  const adapter = createUnleashReasoningAdapter({
    identity: identity(),
    invoke: async () => {
      invocations += 1
      return (async function * stalled() {
        await new Promise(() => {})
        yield Buffer.from('unreachable')
      }())
    },
  })
  const stopped = new AbortController()
  stopped.abort(new Error('operator stop'))
  await assert.rejects(
    captureUnleashReasoningResponse({
      adapter,
      basis: swarmBasis,
      request: roleRequest,
      artifactPayloads: artifactPayloads(),
      limits: limits(),
      signal: stopped.signal,
    }),
    rejectsCode('UNLEASH_REASONING_ABORTED'),
  )
  assert.equal(invocations, 0)

  await assert.rejects(
    captureUnleashReasoningResponse({
      adapter,
      basis: swarmBasis,
      request: roleRequest,
      artifactPayloads: artifactPayloads(),
      limits: limits({ wall_time_ms: 20 }),
    }),
    rejectsCode('UNLEASH_REASONING_TIMEOUT'),
  )
  assert.equal(invocations, 1)
})

test('rejects computed, mismatched, and oversized artifact payloads before invoking the adapter', async () => {
  const swarmBasis = basis()
  const roleRequest = request(swarmBasis)
  let invocations = 0
  const adapter = createUnleashReasoningAdapter({
    identity: identity(),
    invoke: async () => {
      invocations += 1
      return Buffer.from('{}')
    },
  })
  let getterCalls = 0
  const computed = artifactPayloads()[0]
  Object.defineProperty(computed, 'bytes', {
    enumerable: true,
    get() {
      getterCalls += 1
      throw new Error('must not execute')
    },
  })
  await assert.rejects(
    captureUnleashReasoningResponse({
      adapter,
      basis: swarmBasis,
      request: roleRequest,
      artifactPayloads: [computed],
      limits: limits(),
    }),
    rejectsCode('UNLEASH_REASONING_ARTIFACT_INVALID'),
  )
  assert.equal(getterCalls, 0)

  const mismatched = artifactPayloads()
  mismatched[0].bytes[0] ^= 0xff
  await assert.rejects(
    captureUnleashReasoningResponse({
      adapter,
      basis: swarmBasis,
      request: roleRequest,
      artifactPayloads: mismatched,
      limits: limits(),
    }),
    rejectsCode('UNLEASH_REASONING_ARTIFACT_MISMATCH'),
  )

  const hugeBytes = Buffer.alloc(4_194_304, 0x42)
  const hugeSha256 = createHash('sha256').update(hugeBytes).digest('hex')
  const artifacts = Array.from({ length: 5 }, (_, index) => ({
    artifact_id: `artifact:sha256:${String(index + 1).repeat(64)}`,
    kind: index === 0 ? 'EVIDENCE' : 'CONTROL',
    logical_name: `artifact-${index}.bin`,
    sha256: hugeSha256,
    size: hugeBytes.length,
  }))
  const hugeRequest = createUnleashRoleRequest({
    basis: swarmBasis,
    round: 1,
    roleId: 'attacker:perimeter',
    inputFrontierSha256: SHA.i,
    inputChallengeSetSha256: SHA.j,
    evidenceRefs: [`evidence:sha256:${hugeSha256}`],
    allowedToolIds: [],
    artifacts,
  })
  await assert.rejects(
    captureUnleashReasoningResponse({
      adapter,
      basis: swarmBasis,
      request: hugeRequest,
      artifactPayloads: artifacts.map(({ artifact_id: artifactId, sha256, size }) => ({
        artifact_id: artifactId,
        media_type: 'application/octet-stream',
        sha256,
        size,
        bytes: hugeBytes,
      })),
      limits: limits(),
    }),
    rejectsCode('UNLEASH_REASONING_ARTIFACT_LIMIT'),
  )
  assert.equal(invocations, 0)
})

test('preflights artifact manifest and byte budgets before copying payload data', async () => {
  const swarmBasis = basis()
  const roleRequest = request(swarmBasis)
  let invocations = 0
  const adapter = createUnleashReasoningAdapter({
    identity: identity(),
    invoke: async () => {
      invocations += 1
      return Buffer.from('{}')
    },
  })

  const mismatchedLength = Buffer.alloc(ARTIFACT_BYTES.length + 1)
  const oversizedArtifact = Buffer.alloc(4_194_305)
  let computedLengthCalls = 0
  for (const field of ['byteLength', 'length']) {
    Object.defineProperty(oversizedArtifact, field, {
      configurable: true,
      get() {
        computedLengthCalls += 1
        throw new Error('artifact length accessors must not execute')
      },
    })
  }
  const aggregateBytes = Buffer.alloc(4_194_304, 0x42)
  const aggregateSha256 = createHash('sha256').update(aggregateBytes).digest('hex')
  const aggregateArtifacts = Array.from({ length: 5 }, (_, index) => ({
    artifact_id: `artifact:sha256:${String(index + 1).repeat(64)}`,
    kind: index === 0 ? 'EVIDENCE' : 'CONTROL',
    logical_name: `aggregate-${index}.bin`,
    sha256: aggregateSha256,
    size: aggregateBytes.length,
  }))
  const aggregateRequest = createUnleashRoleRequest({
    basis: swarmBasis,
    round: 1,
    roleId: 'attacker:perimeter',
    inputFrontierSha256: SHA.i,
    inputChallengeSetSha256: SHA.j,
    evidenceRefs: [`evidence:sha256:${aggregateSha256}`],
    allowedToolIds: [],
    artifacts: aggregateArtifacts,
  })

  const forbiddenCopies = new Set([mismatchedLength, oversizedArtifact, aggregateBytes])
  const originalBufferFrom = Buffer.from
  let rejectedCopyCount = 0
  Buffer.from = function guardedBufferFrom(value, ...args) {
    if (forbiddenCopies.has(value)) {
      rejectedCopyCount += 1
      throw new Error('rejected artifact data must not be copied')
    }
    return Reflect.apply(originalBufferFrom, Buffer, [value, ...args])
  }

  try {
    await assert.rejects(
      captureUnleashReasoningResponse({
        adapter,
        basis: swarmBasis,
        request: roleRequest,
        artifactPayloads: [{
          ...artifactPayloads()[0],
          bytes: mismatchedLength,
        }],
        limits: limits(),
      }),
      rejectsCode('UNLEASH_REASONING_ARTIFACT_MISMATCH'),
    )

    await assert.rejects(
      captureUnleashReasoningResponse({
        adapter,
        basis: swarmBasis,
        request: roleRequest,
        artifactPayloads: [{
          ...artifactPayloads()[0],
          size: 4_194_305,
          bytes: oversizedArtifact,
        }],
        limits: limits(),
      }),
      rejectsCode('UNLEASH_REASONING_ARTIFACT_LIMIT'),
    )

    await assert.rejects(
      captureUnleashReasoningResponse({
        adapter,
        basis: swarmBasis,
        request: aggregateRequest,
        artifactPayloads: aggregateArtifacts.map(({ artifact_id: artifactId, sha256, size }) => ({
          artifact_id: artifactId,
          media_type: 'application/octet-stream',
          sha256,
          size,
          bytes: aggregateBytes,
        })),
        limits: limits(),
      }),
      rejectsCode('UNLEASH_REASONING_ARTIFACT_LIMIT'),
    )
  } finally {
    Buffer.from = originalBufferFrom
  }

  assert.equal(rejectedCopyCount, 0)
  assert.equal(computedLengthCalls, 0)
  assert.equal(invocations, 0)
})
