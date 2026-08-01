import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash, generateKeyPairSync } from 'node:crypto'

import {
  TransparencyLogContractError,
  assertValidTransparencyConsistencyProof,
  assertValidTransparencyConsistencyRequest,
  assertValidTransparencyLogConfig,
  assertValidTransparencyPublishRequest,
  assertValidTransparencySignedCheckpoint,
  canonicalAttestationBytes,
  createTransparencyConsistencyProof,
  createTransparencyConsistencyRequest,
  createTransparencyInclusionReceipt,
  createTransparencyPublishRequest,
  createTransparencySignedCheckpoint,
  projectTransparencySignedCheckpoint,
  transparencyConsistencyProofLength,
  transparencyLeafHash,
  transparencyNodeHash,
  validateTransparencyConsistencyProof,
  verifyTransparencyConsistency,
  verifyTransparencyConsistencyProof,
  verifyTransparencyInclusion,
  verifyTransparencySignedCheckpoint,
} from '../scripts/lib/transparency-log-contracts.mjs'
import { createRootAttestation } from '../scripts/lib/root-attestation.mjs'

function keyPair() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
}

function digest(value) {
  return createHash('sha256').update(value).digest('hex')
}

function merkleFixture(values) {
  const leaves = values.map((value) => transparencyLeafHash(value))
  const roots = new Map()

  function root(start, size) {
    const key = `${start}:${size}`
    if (roots.has(key)) return roots.get(key)
    let result
    if (size === 1) {
      result = leaves[start]
    } else {
      let split = 1
      while (split * 2 < size) split *= 2
      result = transparencyNodeHash(
        root(start, split),
        root(start + split, size - split),
      )
    }
    roots.set(key, result)
    return result
  }

  function subproof(start, firstSize, secondSize, complete) {
    if (firstSize === secondSize) {
      return complete ? [] : [root(start, secondSize)]
    }
    let split = 1
    while (split * 2 < secondSize) split *= 2
    if (firstSize <= split) {
      return [
        ...subproof(start, firstSize, split, complete),
        root(start + split, secondSize - split),
      ]
    }
    return [
      ...subproof(
        start + split,
        firstSize - split,
        secondSize - split,
        false,
      ),
      root(start, split),
    ]
  }

  return {
    leaves,
    root: (size) => root(0, size),
    rangeRoot: root,
    consistencyPath: (firstSize, secondSize) =>
      subproof(0, firstSize, secondSize, true),
  }
}

function attestation(rootKeys, suffix = 'a') {
  return createRootAttestation({
    run: {
      schema_version: '6.0.0',
      run_id: `run:2026-08-01T10-00-00-000Z:${suffix.repeat(12)}`,
      state: 'COMPLETED',
      phase: 'FINALIZED',
    },
    runSha256: digest(`run-${suffix}`),
    privateKeyBytes: rootKeys.privateKey,
    signedAt: new Date('2026-08-01T10:01:00.000Z'),
  })
}

test('transparency receipt verifies a multi-leaf Merkle inclusion proof', () => {
  const rootKeys = keyPair()
  const logKeys = keyPair()
  const entries = ['a', 'b', 'c'].map((suffix) => attestation(rootKeys, suffix))
  const leaves = entries.map((entry) =>
    transparencyLeafHash(canonicalAttestationBytes(entry)))
  const leftRoot = transparencyNodeHash(leaves[0], leaves[1])
  const treeRoot = transparencyNodeHash(leftRoot, leaves[2])
  const receipt = createTransparencyInclusionReceipt({
    attestation: entries[2],
    leafIndex: 2,
    treeSize: 3,
    inclusionPath: [leftRoot],
    rootHash: treeRoot,
    origin: 'audit-log.example/v1',
    privateKeyBytes: logKeys.privateKey,
    issuedAt: new Date('2026-08-01T10:02:00.000Z'),
  })

  assert.deepEqual(
    verifyTransparencyInclusion({
      receipt,
      attestation: entries[2],
      publicKeyBytes: logKeys.publicKey,
      expectedOrigin: 'audit-log.example/v1',
      now: new Date('2026-08-01T10:03:00.000Z'),
    }),
    {
      status: 'VERIFIED',
      claim: 'INCLUSION_AT_SIGNED_CHECKPOINT',
      log_key_id: receipt.checkpoint.signing.key_id,
      origin: 'audit-log.example/v1',
      tree_size: 3,
      leaf_index: 2,
      root_hash: treeRoot,
      issued_at: '2026-08-01T10:02:00.000Z',
      consistency: 'NOT_VERIFIED',
      witness_quorum: 'NOT_VERIFIED',
      trusted_time: false,
    },
  )
})

test('transparency receipt rejects substitution, wrong keys, bad proofs, and future checkpoints', () => {
  const rootKeys = keyPair()
  const logKeys = keyPair()
  const unrelatedLogKeys = keyPair()
  const first = attestation(rootKeys, 'a')
  const second = attestation(rootKeys, 'b')
  const firstLeaf = transparencyLeafHash(canonicalAttestationBytes(first))
  const secondLeaf = transparencyLeafHash(canonicalAttestationBytes(second))
  const treeRoot = transparencyNodeHash(firstLeaf, secondLeaf)
  const receipt = createTransparencyInclusionReceipt({
    attestation: first,
    leafIndex: 0,
    treeSize: 2,
    inclusionPath: [secondLeaf],
    rootHash: treeRoot,
    origin: 'audit-log.example/v1',
    privateKeyBytes: logKeys.privateKey,
    issuedAt: new Date('2026-08-01T10:02:00.000Z'),
  })

  assert.throws(
    () => verifyTransparencyInclusion({
      receipt,
      attestation: second,
      publicKeyBytes: logKeys.publicKey,
      now: new Date('2026-08-01T10:03:00.000Z'),
    }),
    /does not bind the supplied root attestation/i,
  )
  assert.throws(
    () => verifyTransparencyInclusion({
      receipt,
      attestation: first,
      publicKeyBytes: unrelatedLogKeys.publicKey,
      now: new Date('2026-08-01T10:03:00.000Z'),
    }),
    /does not match the externally pinned public key/i,
  )
  assert.throws(
    () => verifyTransparencyInclusion({
      receipt,
      attestation: first,
      publicKeyBytes: logKeys.publicKey,
      expectedOrigin: 'different-log.example/v1',
      now: new Date('2026-08-01T10:03:00.000Z'),
    }),
    /origin does not match the trusted log configuration/i,
  )

  const badProof = structuredClone(receipt)
  badProof.inclusion_path[0] = digest('wrong sibling')
  assert.throws(
    () => verifyTransparencyInclusion({
      receipt: badProof,
      attestation: first,
      publicKeyBytes: logKeys.publicKey,
      now: new Date('2026-08-01T10:03:00.000Z'),
    }),
    /does not produce the signed checkpoint root/i,
  )
  assert.throws(
    () => verifyTransparencyInclusion({
      receipt,
      attestation: first,
      publicKeyBytes: logKeys.publicKey,
      now: new Date('2026-08-01T10:01:59.999Z'),
    }),
    /issued in the future/i,
  )

  const extraProof = structuredClone(receipt)
  extraProof.inclusion_path.push(digest('unused'))
  assert.throws(
    () => verifyTransparencyInclusion({
      receipt: extraProof,
      attestation: first,
      publicKeyBytes: logKeys.publicKey,
      now: new Date('2026-08-01T10:03:00.000Z'),
    }),
    /unused nodes/i,
  )
})

test('transparency publication request binds canonical attestation bytes', () => {
  const entry = attestation(keyPair())
  const request = createTransparencyPublishRequest(entry)
  assertValidTransparencyPublishRequest(request)
  assert.equal(
    Buffer.from(request.entry.content_base64, 'base64').toString('utf8'),
    canonicalAttestationBytes(entry).toString('utf8'),
  )

  const replaced = structuredClone(request)
  replaced.entry.content_sha256 = digest('replacement')
  assert.throws(
    () => assertValidTransparencyPublishRequest(replaced),
    TransparencyLogContractError,
  )
})

test('transparency log configuration requires one exact HTTPS endpoint', () => {
  const config = {
    schema_version: '1.0.0',
    protocol: 'transparency-log-v1',
    log_url: 'https://log.example/v1/entries',
    log_origin: 'audit-log.example/v1',
    log_public_key_path: 'C:\\trusted\\log-public.pem',
    tls_spki_sha256: digest('tls spki'),
    limits: {
      request_timeout_ms: 30000,
      max_clock_skew_ms: 30000,
      max_request_bytes: 262144,
      max_response_bytes: 262144,
    },
  }
  assertValidTransparencyLogConfig(config)
  assert.throws(
    () => assertValidTransparencyLogConfig({
      ...config,
      log_url: 'https://user:secret@log.example/v1/entries?replace=true',
    }),
    TransparencyLogContractError,
  )
  assert.throws(
    () => assertValidTransparencyLogConfig({
      ...config,
      log_url: 'http://log.example/v1/entries',
    }),
    TransparencyLogContractError,
  )
})

test('versioned transparency configuration requires a distinct exact consistency endpoint', () => {
  const config = {
    schema_version: '1.1.0',
    protocol: 'transparency-log-v1',
    log_url: 'https://log.example/v1/entries',
    consistency_url: 'https://log.example/v1/consistency',
    log_origin: 'audit-log.example/v1',
    log_public_key_path: '/trusted/log-public.pem',
    tls_spki_sha256: digest('tls spki'),
    limits: {
      request_timeout_ms: 30000,
      max_clock_skew_ms: 30000,
      max_request_bytes: 262144,
      max_response_bytes: 262144,
    },
  }
  assertValidTransparencyLogConfig(config)

  for (const consistencyUrl of [
    config.log_url,
    'http://log.example/v1/consistency',
    'https://user:secret@log.example/v1/consistency',
    'https://log.example/v1/consistency?first=1',
    'https://log.example/v1/consistency#fragment',
  ]) {
    assert.throws(
      () => assertValidTransparencyLogConfig({
        ...config,
        consistency_url: consistencyUrl,
      }),
      TransparencyLogContractError,
    )
  }
  assert.throws(
    () => assertValidTransparencyLogConfig({
      ...config,
      schema_version: '1.0.0',
    }),
    TransparencyLogContractError,
  )
  const { consistency_url: ignored, ...missingConsistencyUrl } = config
  assert.equal(ignored, config.consistency_url)
  assert.throws(
    () => assertValidTransparencyLogConfig(missingConsistencyUrl),
    TransparencyLogContractError,
  )
})

test('standalone signed checkpoints project from receipts and verify one bounded claim', () => {
  const rootKeys = keyPair()
  const logKeys = keyPair()
  const entry = attestation(rootKeys)
  const leaf = transparencyLeafHash(canonicalAttestationBytes(entry))
  const receipt = createTransparencyInclusionReceipt({
    attestation: entry,
    leafIndex: 0,
    treeSize: 1,
    inclusionPath: [],
    rootHash: leaf,
    origin: 'audit-log.example/v1',
    privateKeyBytes: logKeys.privateKey,
    issuedAt: new Date('2026-08-01T10:02:00.000Z'),
  })
  const projected = projectTransparencySignedCheckpoint(receipt)

  assert.deepEqual(projected.checkpoint, receipt.checkpoint)
  assert.equal(projected.signature, receipt.signature)
  assertValidTransparencySignedCheckpoint(projected)
  assert.deepEqual(
    verifyTransparencySignedCheckpoint({
      signedCheckpoint: projected,
      publicKeyBytes: logKeys.publicKey,
      expectedOrigin: 'audit-log.example/v1',
      now: new Date('2026-08-01T10:03:00.000Z'),
    }),
    {
      status: 'VERIFIED',
      claim: 'SIGNED_TRANSPARENCY_CHECKPOINT',
      log_key_id: projected.checkpoint.signing.key_id,
      origin: 'audit-log.example/v1',
      tree_size: 1,
      root_hash: leaf,
      issued_at: '2026-08-01T10:02:00.000Z',
      consistency: 'NOT_VERIFIED',
      witness_quorum: 'NOT_VERIFIED',
      trusted_time: false,
    },
  )

  const standalone = createTransparencySignedCheckpoint({
    treeSize: 1,
    rootHash: leaf,
    origin: 'audit-log.example/v1',
    privateKeyBytes: logKeys.privateKey,
    issuedAt: '2026-08-01T10:02:00.000Z',
  })
  assert.deepEqual(standalone, projected)
})

test('signed checkpoint verification rejects key, origin, signature, time, and schema substitution', () => {
  const logKeys = keyPair()
  const otherKeys = keyPair()
  const checkpoint = createTransparencySignedCheckpoint({
    treeSize: 4,
    rootHash: digest('root'),
    origin: 'audit-log.example/v1',
    privateKeyBytes: logKeys.privateKey,
    issuedAt: '2026-08-01T10:02:00.000Z',
  })
  const verification = {
    signedCheckpoint: checkpoint,
    publicKeyBytes: logKeys.publicKey,
    now: new Date('2026-08-01T10:03:00.000Z'),
  }

  assert.throws(
    () => verifyTransparencySignedCheckpoint({
      ...verification,
      publicKeyBytes: otherKeys.publicKey,
    }),
    /externally pinned public key/i,
  )
  assert.throws(
    () => verifyTransparencySignedCheckpoint({
      ...verification,
      expectedOrigin: 'other-log.example/v1',
    }),
    /origin does not match/i,
  )
  const tamperedSignature = structuredClone(checkpoint)
  tamperedSignature.signature = `${
    checkpoint.signature[0] === 'A' ? 'B' : 'A'
  }${checkpoint.signature.slice(1)}`
  assert.throws(
    () => verifyTransparencySignedCheckpoint({
      ...verification,
      signedCheckpoint: tamperedSignature,
    }),
    /signature verification failed/i,
  )
  assert.throws(
    () => verifyTransparencySignedCheckpoint({
      ...verification,
      now: new Date('2026-08-01T10:01:59.999Z'),
    }),
    /issued in the future/i,
  )
  const noncanonicalTime = structuredClone(checkpoint)
  noncanonicalTime.checkpoint.issued_at = '2026-08-01T10:02:00Z'
  assert.throws(
    () => assertValidTransparencySignedCheckpoint(noncanonicalTime),
    TransparencyLogContractError,
  )
  const extraProperty = structuredClone(checkpoint)
  extraProperty.untrusted_hint = 'ignore me'
  assert.throws(
    () => assertValidTransparencySignedCheckpoint(extraProperty),
    TransparencyLogContractError,
  )
})

test('consistency requests use their endpoint protocol and enforce ordered safe sizes', () => {
  const request = createTransparencyConsistencyRequest({
    firstSize: 7,
    secondSize: 7,
  })
  assert.deepEqual(request, {
    schema_version: '1.0.0',
    protocol: 'transparency-log-consistency-v1',
    kind: 'red-team-audit/transparency-consistency-request',
    first_tree_size: 7,
    second_tree_size: 7,
  })
  assertValidTransparencyConsistencyRequest(request)

  for (const invalid of [
    { ...request, first_tree_size: 8 },
    { ...request, first_tree_size: 0 },
    { ...request, second_tree_size: Number.MAX_SAFE_INTEGER + 1 },
    { ...request, protocol: 'transparency-log-v1' },
    { ...request, extra: true },
  ]) {
    assert.throws(
      () => assertValidTransparencyConsistencyRequest(invalid),
      TransparencyLogContractError,
    )
  }
})

test('RFC consistency paths have the expected decomposition for non-power-of-two trees', () => {
  const fixture = merkleFixture(
    Array.from({ length: 7 }, (_, index) => Buffer.from(`leaf-${index}`)),
  )

  assert.deepEqual(fixture.consistencyPath(3, 7), [
    fixture.leaves[2],
    fixture.leaves[3],
    fixture.rangeRoot(0, 2),
    fixture.rangeRoot(4, 3),
  ])
  assert.deepEqual(fixture.consistencyPath(4, 7), [
    fixture.rangeRoot(4, 3),
  ])
  assert.deepEqual(fixture.consistencyPath(6, 7), [
    fixture.rangeRoot(4, 2),
    fixture.leaves[6],
    fixture.rangeRoot(0, 4),
  ])

  for (const firstSize of [3, 4, 6]) {
    const result = verifyTransparencyConsistency({
      firstTreeSize: firstSize,
      firstRootHash: fixture.root(firstSize),
      secondTreeSize: 7,
      secondRootHash: fixture.root(7),
      consistencyPath: fixture.consistencyPath(firstSize, 7),
    })
    assert.equal(result.relation, 'APPEND_ONLY_EXTENSION')
  }
})

test('RFC consistency verification is exhaustive for every tree-size pair through 257 leaves', () => {
  const fixture = merkleFixture(
    Array.from(
      { length: 257 },
      (_, index) => Buffer.from(`exhaustive-leaf-${index}`),
    ),
  )

  for (let secondSize = 1; secondSize <= 257; secondSize += 1) {
    for (let firstSize = 1; firstSize <= secondSize; firstSize += 1) {
      const consistencyPath = fixture.consistencyPath(firstSize, secondSize)
      assert.equal(
        consistencyPath.length,
        transparencyConsistencyProofLength(firstSize, secondSize),
      )
      const result = verifyTransparencyConsistency({
        firstTreeSize: firstSize,
        firstRootHash: fixture.root(firstSize),
        secondTreeSize: secondSize,
        secondRootHash: fixture.root(secondSize),
        consistencyPath,
      })
      assert.equal(
        result.relation,
        firstSize === secondSize
          ? 'SAME_SIZE_SAME_ROOT'
          : 'APPEND_ONLY_EXTENSION',
      )
      assert.equal(result.consumed_nodes, consistencyPath.length)
    }
  }
})

test('consistency verification uses safe arithmetic beyond JavaScript bitwise range', () => {
  const firstSize = 2 ** 40
  const secondSize = firstSize + 1
  const firstRootHash = digest('large old root')
  const appendedRootHash = digest('large appended subtree')
  const secondRootHash = transparencyNodeHash(firstRootHash, appendedRootHash)

  assert.equal(transparencyConsistencyProofLength(firstSize, secondSize), 1)
  assert.deepEqual(
    verifyTransparencyConsistency({
      firstTreeSize: firstSize,
      firstRootHash,
      secondTreeSize: secondSize,
      secondRootHash,
      consistencyPath: [appendedRootHash],
    }),
    {
      status: 'VERIFIED',
      relation: 'APPEND_ONLY_EXTENSION',
      first_tree_size: firstSize,
      second_tree_size: secondSize,
      first_root_hash: firstRootHash,
      second_root_hash: secondRootHash,
      consumed_nodes: 1,
    },
  )
})

test('signed consistency artifacts verify both checkpoints and state bounded nonclaims', () => {
  const logKeys = keyPair()
  const fixture = merkleFixture(
    Array.from({ length: 7 }, (_, index) => Buffer.from(`leaf-${index}`)),
  )
  const firstCheckpoint = createTransparencySignedCheckpoint({
    treeSize: 3,
    rootHash: fixture.root(3),
    origin: 'audit-log.example/v1',
    privateKeyBytes: logKeys.privateKey,
    issuedAt: '2026-08-01T10:02:00.000Z',
  })
  const secondCheckpoint = createTransparencySignedCheckpoint({
    treeSize: 7,
    rootHash: fixture.root(7),
    origin: 'audit-log.example/v1',
    privateKeyBytes: logKeys.privateKey,
    issuedAt: '2026-08-01T10:03:00.000Z',
  })
  const proof = createTransparencyConsistencyProof({
    firstCheckpoint,
    secondCheckpoint,
    consistencyPath: fixture.consistencyPath(3, 7),
  })
  assertValidTransparencyConsistencyProof(proof)

  assert.deepEqual(
    verifyTransparencyConsistencyProof({
      proof,
      publicKeyBytes: logKeys.publicKey,
      expectedOrigin: 'audit-log.example/v1',
      now: '2026-08-01T10:04:00.000Z',
    }),
    {
      status: 'VERIFIED',
      claim: 'CONSISTENCY_BETWEEN_SIGNED_CHECKPOINTS',
      relation: 'APPEND_ONLY_EXTENSION',
      log_key_id: firstCheckpoint.checkpoint.signing.key_id,
      origin: 'audit-log.example/v1',
      first_tree_size: 3,
      first_root_hash: fixture.root(3),
      first_issued_at: '2026-08-01T10:02:00.000Z',
      second_tree_size: 7,
      second_root_hash: fixture.root(7),
      second_issued_at: '2026-08-01T10:03:00.000Z',
      consistency: 'VERIFIED_BETWEEN_SUPPLIED_CHECKPOINTS',
      split_view_detection: 'NOT_VERIFIED',
      witness_quorum: 'NOT_VERIFIED',
      trusted_time: false,
    },
  )

  const sameSizeCheckpoint = createTransparencySignedCheckpoint({
    treeSize: 7,
    rootHash: fixture.root(7),
    origin: 'audit-log.example/v1',
    privateKeyBytes: logKeys.privateKey,
    issuedAt: '2026-08-01T10:03:30.000Z',
  })
  const sameSizeProof = createTransparencyConsistencyProof({
    firstCheckpoint: secondCheckpoint,
    secondCheckpoint: sameSizeCheckpoint,
    consistencyPath: [],
  })
  assert.equal(
    verifyTransparencyConsistencyProof({
      proof: sameSizeProof,
      publicKeyBytes: logKeys.publicKey,
      expectedOrigin: 'audit-log.example/v1',
      now: '2026-08-01T10:04:00.000Z',
    }).relation,
    'SAME_SIZE_SAME_ROOT',
  )
})

test('consistency validation rejects malleable paths and checkpoint discontinuities', () => {
  const logKeys = keyPair()
  const otherKeys = keyPair()
  const fixture = merkleFixture(
    Array.from({ length: 7 }, (_, index) => Buffer.from(`leaf-${index}`)),
  )
  const firstCheckpoint = createTransparencySignedCheckpoint({
    treeSize: 3,
    rootHash: fixture.root(3),
    origin: 'audit-log.example/v1',
    privateKeyBytes: logKeys.privateKey,
    issuedAt: '2026-08-01T10:02:00.000Z',
  })
  const secondCheckpoint = createTransparencySignedCheckpoint({
    treeSize: 7,
    rootHash: fixture.root(7),
    origin: 'audit-log.example/v1',
    privateKeyBytes: logKeys.privateKey,
    issuedAt: '2026-08-01T10:03:00.000Z',
  })
  const consistencyPath = fixture.consistencyPath(3, 7)
  const proof = createTransparencyConsistencyProof({
    firstCheckpoint,
    secondCheckpoint,
    consistencyPath,
  })

  for (const badPath of [
    consistencyPath.slice(0, -1),
    [...consistencyPath, digest('unused')],
  ]) {
    assert.throws(
      () => createTransparencyConsistencyProof({
        firstCheckpoint,
        secondCheckpoint,
        consistencyPath: badPath,
      }),
      TransparencyLogContractError,
    )
  }
  for (const badPath of [
    [consistencyPath[1], consistencyPath[0], ...consistencyPath.slice(2)],
    [digest('wrong'), ...consistencyPath.slice(1)],
  ]) {
    assert.throws(
      () => verifyTransparencyConsistency({
        firstTreeSize: 3,
        firstRootHash: fixture.root(3),
        secondTreeSize: 7,
        secondRootHash: fixture.root(7),
        consistencyPath: badPath,
      }),
      /does not prove/i,
    )
  }
  assert.throws(
    () => verifyTransparencyConsistency({
      firstTreeSize: 7,
      firstRootHash: fixture.root(7),
      secondTreeSize: 3,
      secondRootHash: fixture.root(3),
      consistencyPath: [],
    }),
    /sizes must satisfy/i,
  )
  assert.throws(
    () => verifyTransparencyConsistency({
      firstTreeSize: 7,
      firstRootHash: fixture.root(7),
      secondTreeSize: 7,
      secondRootHash: digest('different same-size root'),
      consistencyPath: [],
    }),
    /same-size.*different roots/i,
  )
  assert.throws(
    () => verifyTransparencyConsistency({
      firstTreeSize: 7,
      firstRootHash: fixture.root(7),
      secondTreeSize: 7,
      secondRootHash: fixture.root(7),
      consistencyPath: [digest('unused')],
    }),
    /exactly 0 nodes/i,
  )
  assert.throws(
    () => verifyTransparencyConsistency({
      firstTreeSize: 3,
      firstRootHash: fixture.root(3),
      secondTreeSize: 7,
      secondRootHash: fixture.root(7),
      consistencyPath: ['A'.repeat(64), ...consistencyPath.slice(1)],
    }),
    /non-digest/i,
  )

  const differentOrigin = createTransparencySignedCheckpoint({
    treeSize: 7,
    rootHash: fixture.root(7),
    origin: 'other-log.example/v1',
    privateKeyBytes: logKeys.privateKey,
    issuedAt: '2026-08-01T10:03:00.000Z',
  })
  const differentKey = createTransparencySignedCheckpoint({
    treeSize: 7,
    rootHash: fixture.root(7),
    origin: 'audit-log.example/v1',
    privateKeyBytes: otherKeys.privateKey,
    issuedAt: '2026-08-01T10:03:00.000Z',
  })
  const earlierCheckpoint = createTransparencySignedCheckpoint({
    treeSize: 7,
    rootHash: fixture.root(7),
    origin: 'audit-log.example/v1',
    privateKeyBytes: logKeys.privateKey,
    issuedAt: '2026-08-01T10:01:59.999Z',
  })
  for (const invalidSecond of [differentOrigin, differentKey, earlierCheckpoint]) {
    assert.throws(
      () => createTransparencyConsistencyProof({
        firstCheckpoint,
        secondCheckpoint: invalidSecond,
        consistencyPath,
      }),
      TransparencyLogContractError,
    )
  }

  const extraProperty = structuredClone(proof)
  extraProperty.untrusted_hint = true
  const validation = validateTransparencyConsistencyProof(extraProperty)
  assert.equal(validation.valid, false)
  assert(validation.errors.some((error) =>
    error.code === 'SCHEMA_ADDITIONALPROPERTIES'))
})

test('consistency proof verification independently authenticates both signed checkpoints', () => {
  const logKeys = keyPair()
  const unrelatedKeys = keyPair()
  const fixture = merkleFixture(
    Array.from({ length: 5 }, (_, index) => Buffer.from(`leaf-${index}`)),
  )
  const firstCheckpoint = createTransparencySignedCheckpoint({
    treeSize: 3,
    rootHash: fixture.root(3),
    origin: 'audit-log.example/v1',
    privateKeyBytes: logKeys.privateKey,
    issuedAt: '2026-08-01T10:02:00.000Z',
  })
  const secondCheckpoint = createTransparencySignedCheckpoint({
    treeSize: 5,
    rootHash: fixture.root(5),
    origin: 'audit-log.example/v1',
    privateKeyBytes: logKeys.privateKey,
    issuedAt: '2026-08-01T10:03:00.000Z',
  })
  const proof = createTransparencyConsistencyProof({
    firstCheckpoint,
    secondCheckpoint,
    consistencyPath: fixture.consistencyPath(3, 5),
  })
  const verification = {
    proof,
    publicKeyBytes: logKeys.publicKey,
    expectedOrigin: 'audit-log.example/v1',
    now: '2026-08-01T10:04:00.000Z',
  }

  assert.throws(
    () => verifyTransparencyConsistencyProof({
      ...verification,
      publicKeyBytes: unrelatedKeys.publicKey,
    }),
    /externally pinned public key/i,
  )
  assert.throws(
    () => verifyTransparencyConsistencyProof({
      ...verification,
      expectedOrigin: 'other-log.example/v1',
    }),
    /origin does not match/i,
  )
  for (const field of ['first_checkpoint', 'second_checkpoint']) {
    const badSignature = structuredClone(proof)
    const signature = badSignature[field].signature
    badSignature[field].signature = `${signature[0] === 'A' ? 'B' : 'A'}${
      signature.slice(1)
    }`
    assert.throws(
      () => verifyTransparencyConsistencyProof({
        ...verification,
        proof: badSignature,
      }),
      /signature verification failed/i,
    )
  }
  assert.throws(
    () => verifyTransparencyConsistencyProof({
      ...verification,
      now: '2026-08-01T10:02:59.999Z',
    }),
    /issued in the future/i,
  )
})
