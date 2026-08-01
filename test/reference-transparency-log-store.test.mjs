import assert from 'node:assert/strict'
import { execFile } from 'node:child_process'
import {
  createHash,
  generateKeyPairSync,
} from 'node:crypto'
import {
  copyFile,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  symlink,
  utimes,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { promisify } from 'node:util'
import { test } from 'node:test'

import {
  openReferenceTransparencyLogStore,
} from '../providers/reference-transparency-log/store.mjs'
import { createRootAttestation } from '../scripts/lib/root-attestation.mjs'
import {
  canonicalAttestationBytes,
  createTransparencyConsistencyRequest,
  createTransparencyPublishRequest,
  projectTransparencySignedCheckpoint,
  transparencyLeafHash,
  verifyTransparencyConsistency,
  verifyTransparencyConsistencyProof,
  verifyTransparencyInclusion,
} from '../scripts/lib/transparency-log-contracts.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'

const execFileAsync = promisify(execFile)
const ORIGIN = 'reference.audit-log.example/v1'
const FIXED_TIME = new Date('2026-08-01T10:02:00.000Z')

function keyPair() {
  return generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  })
}

function digest(value) {
  return createHash('sha256').update(value).digest('hex')
}

function fixtureRequests(count) {
  const rootKeys = keyPair()
  return Array.from({ length: count }, (_, index) => {
    const token = index.toString(36).padStart(12, '0')
    const attestation = createRootAttestation({
      run: {
        schema_version: '6.0.0',
        run_id: `run:2026-08-01T10-00-00-000Z:${token}`,
        state: 'COMPLETED',
        phase: 'FINALIZED',
      },
      runSha256: digest(`terminal-run-${index}`),
      privateKeyBytes: rootKeys.privateKey,
      signedAt: new Date('2026-08-01T10:01:00.000Z'),
    })
    return {
      attestation,
      request: createTransparencyPublishRequest(attestation),
    }
  })
}

async function temporaryDirectory(t, prefix = 'rta-reference-log-test-') {
  const directory = await mkdtemp(join(tmpdir(), prefix))
  t.after(() => rm(directory, { recursive: true, force: true }))
  return directory
}

function rawLeafHash(content) {
  return createHash('sha256')
    .update(Buffer.concat([Buffer.from([0]), content]))
    .digest()
}

function rawNodeHash(left, right) {
  return createHash('sha256')
    .update(Buffer.concat([Buffer.from([1]), left, right]))
    .digest()
}

function largestPowerOfTwoBelow(size) {
  let power = 1
  while (power * 2 < size) power *= 2
  return power
}

function independentRfc6962Root(leaves) {
  if (leaves.length === 1) return leaves[0]
  const split = largestPowerOfTwoBelow(leaves.length)
  return rawNodeHash(
    independentRfc6962Root(leaves.slice(0, split)),
    independentRfc6962Root(leaves.slice(split)),
  )
}

function assertVerifies(receipt, attestation, logKeys) {
  const verification = verifyTransparencyInclusion({
    receipt,
    attestation,
    publicKeyBytes: logKeys.publicKey,
    expectedOrigin: ORIGIN,
    now: new Date('2026-08-01T10:03:00.000Z'),
  })
  assert.equal(verification.claim, 'INCLUSION_AT_SIGNED_CHECKPOINT')
}

test('store produces RFC6962 roots and valid proofs for every leaf at tree sizes 1 through 17', async (t) => {
  const parent = await temporaryDirectory(t)
  const stateDirectory = join(parent, 'state')
  const logKeys = keyPair()
  const fixtures = fixtureRequests(17)
  const store = await openReferenceTransparencyLogStore({
    directory: stateDirectory,
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    now: () => FIXED_TIME,
  })

  for (let size = 1; size <= fixtures.length; size += 1) {
    const appended = await store.publish(fixtures[size - 1].request, {
      issuedAt: FIXED_TIME,
    })
    assert.equal(appended.created, true)
    assert.equal(appended.idempotent, false)
    assert.equal(appended.receipt.leaf_index, size - 1)

    const expectedRoot = independentRfc6962Root(
      fixtures.slice(0, size).map(({ attestation }) =>
        rawLeafHash(canonicalAttestationBytes(attestation))),
    ).toString('hex')
    assert.equal(appended.receipt.checkpoint.root_hash, expectedRoot)
    assert.equal(store.snapshot().root_hash, expectedRoot)

    for (let leafIndex = 0; leafIndex < size; leafIndex += 1) {
      const replay = await store.publish(fixtures[leafIndex].request, {
        now: FIXED_TIME,
      })
      assert.equal(replay.created, false)
      assert.equal(replay.idempotent, true)
      assert.equal(replay.receipt.leaf_index, leafIndex)
      assert.equal(replay.receipt.checkpoint.tree_size, size)
      assert.equal(replay.receipt.checkpoint.root_hash, expectedRoot)
      assertVerifies(replay.receipt, fixtures[leafIndex].attestation, logKeys)
    }
  }

  await store.close()
})

test('store returns exact historical roots and valid consistency paths for every committed size pair', async (t) => {
  const parent = await temporaryDirectory(t)
  const logKeys = keyPair()
  const fixtures = fixtureRequests(9)
  const store = await openReferenceTransparencyLogStore({
    directory: join(parent, 'state'),
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    now: () => FIXED_TIME,
  })
  const historicalRoots = [null]

  for (const fixture of fixtures) {
    const published = await store.publish(fixture.request, { now: FIXED_TIME })
    historicalRoots.push(published.receipt.checkpoint.root_hash)
  }

  for (let secondSize = 1; secondSize <= fixtures.length; secondSize += 1) {
    for (let firstSize = 1; firstSize <= secondSize; firstSize += 1) {
      const historical = await store.consistencyProof({
        firstSize,
        secondSize,
        firstRootHash: historicalRoots[firstSize],
        secondRootHash: historicalRoots[secondSize],
      })
      assert.deepEqual(historical.first, {
        tree_size: firstSize,
        root_hash: historicalRoots[firstSize],
      })
      assert.deepEqual(historical.second, {
        tree_size: secondSize,
        root_hash: historicalRoots[secondSize],
      })
      const verified = verifyTransparencyConsistency({
        firstTreeSize: firstSize,
        firstRootHash: historical.first.root_hash,
        secondTreeSize: secondSize,
        secondRootHash: historical.second.root_hash,
        consistencyPath: historical.consistency_path,
      })
      assert.equal(
        verified.relation,
        firstSize === secondSize
          ? 'SAME_SIZE_SAME_ROOT'
          : 'APPEND_ONLY_EXTENSION',
      )
    }
  }

  await assert.rejects(
    store.consistencyProof({
      firstSize: 3,
      secondSize: 9,
      firstRootHash: digest('not the historical root'),
    }),
    /does not match the exact committed historical tree/i,
  )

  const request = createTransparencyConsistencyRequest({
    firstSize: 3,
    secondSize: 9,
  })
  const proof = await store.proveConsistency(request, { now: FIXED_TIME })
  const verification = verifyTransparencyConsistencyProof({
    proof,
    publicKeyBytes: logKeys.publicKey,
    expectedOrigin: ORIGIN,
    now: FIXED_TIME,
  })
  assert.equal(verification.relation, 'APPEND_ONLY_EXTENSION')
  assert.equal(verification.first_root_hash, historicalRoots[3])
  assert.equal(verification.second_root_hash, historicalRoots[9])
  await store.close()
})

test('consistency proof remains coherent when an append commits concurrently', async (t) => {
  const parent = await temporaryDirectory(t)
  const logKeys = keyPair()
  const fixtures = fixtureRequests(6)
  const store = await openReferenceTransparencyLogStore({
    directory: join(parent, 'state'),
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    now: () => FIXED_TIME,
  })
  const historicalRoots = [null]
  for (let index = 0; index < 5; index += 1) {
    const published = await store.publish(fixtures[index].request, {
      now: FIXED_TIME,
    })
    historicalRoots.push(published.receipt.checkpoint.root_hash)
  }
  const request = createTransparencyConsistencyRequest({
    firstSize: 2,
    secondSize: 5,
  })

  const [proof, appended] = await Promise.all([
    store.proveConsistency(request, { now: FIXED_TIME }),
    store.publish(fixtures[5].request, { now: FIXED_TIME }),
  ])
  assert.equal(appended.receipt.checkpoint.tree_size, 6)
  const verification = verifyTransparencyConsistencyProof({
    proof,
    publicKeyBytes: logKeys.publicKey,
    expectedOrigin: ORIGIN,
    now: FIXED_TIME,
  })
  assert.equal(verification.first_tree_size, 2)
  assert.equal(verification.first_root_hash, historicalRoots[2])
  assert.equal(verification.second_tree_size, 5)
  assert.equal(verification.second_root_hash, historicalRoots[5])
  assert.equal((await store.refresh()).tree_size, 6)
  await store.close()
})

test('duplicate publication is stable across restart and origin or key drift fails closed', async (t) => {
  const parent = await temporaryDirectory(t)
  const stateDirectory = join(parent, 'state')
  const logKeys = keyPair()
  const [fixture] = fixtureRequests(1)
  const options = {
    directory: stateDirectory,
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    now: () => FIXED_TIME,
  }
  const firstStore = await openReferenceTransparencyLogStore(options)
  const first = await firstStore.publish(fixture.request, { now: FIXED_TIME })
  const duplicate = await firstStore.publish(fixture.request, { now: FIXED_TIME })
  assert.equal(first.created, true)
  assert.equal(duplicate.created, false)
  assert.equal(duplicate.receipt.leaf_index, first.receipt.leaf_index)
  assert.equal(firstStore.snapshot().tree_size, 1)
  const beforeRestart = firstStore.snapshot()
  await firstStore.close()

  const restarted = await openReferenceTransparencyLogStore(options)
  assert.deepEqual(restarted.snapshot(), beforeRestart)
  const replay = await restarted.publish(fixture.request, { now: FIXED_TIME })
  assert.equal(replay.idempotent, true)
  assert.equal(replay.receipt.checkpoint.tree_size, 1)
  assertVerifies(replay.receipt, fixture.attestation, logKeys)
  await restarted.close()

  await assert.rejects(
    openReferenceTransparencyLogStore({
      ...options,
      origin: 'substituted.audit-log.example/v1',
    }),
    /origin and signing key|identity/i,
  )
  await assert.rejects(
    openReferenceTransparencyLogStore({
      ...options,
      privateKeyBytes: keyPair().privateKey,
    }),
    /origin and signing key|identity/i,
  )
})

test('store enforces entry count, request, entry, and cumulative byte limits', async (t) => {
  const parent = await temporaryDirectory(t)
  const logKeys = keyPair()
  const fixtures = fixtureRequests(2)
  const firstContentBytes = Buffer.from(
    fixtures[0].request.entry.content_base64,
    'base64',
  ).length

  const countStore = await openReferenceTransparencyLogStore({
    directory: join(parent, 'count-state'),
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    limits: { maxEntries: 1 },
    now: () => FIXED_TIME,
  })
  await countStore.publish(fixtures[0].request, { now: FIXED_TIME })
  await assert.rejects(
    countStore.publish(fixtures[1].request, { now: FIXED_TIME }),
    /maxEntries/i,
  )
  await countStore.close()

  const entryStore = await openReferenceTransparencyLogStore({
    directory: join(parent, 'entry-state'),
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    limits: { maxEntryBytes: firstContentBytes - 1 },
    now: () => FIXED_TIME,
  })
  await assert.rejects(
    entryStore.publish(fixtures[0].request, { now: FIXED_TIME }),
    /maxEntryBytes/i,
  )
  await entryStore.close()

  const requestStore = await openReferenceTransparencyLogStore({
    directory: join(parent, 'request-state'),
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    limits: { maxRequestBytes: 256 },
    now: () => FIXED_TIME,
  })
  await assert.rejects(
    requestStore.publish(fixtures[0].request, { now: FIXED_TIME }),
    /maxRequestBytes/i,
  )
  await requestStore.close()

  const totalStore = await openReferenceTransparencyLogStore({
    directory: join(parent, 'total-state'),
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    limits: { maxTotalEntryBytes: firstContentBytes },
    now: () => FIXED_TIME,
  })
  await totalStore.publish(fixtures[0].request, { now: FIXED_TIME })
  await assert.rejects(
    totalStore.publish(fixtures[1].request, { now: FIXED_TIME }),
    /maxTotalEntryBytes/i,
  )
  await totalStore.close()

  const directoryBoundOptions = {
    directory: join(parent, 'directory-bound-state'),
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    limits: { maxEntries: 1 },
    now: () => FIXED_TIME,
  }
  const directoryBoundStore = await openReferenceTransparencyLogStore(
    directoryBoundOptions,
  )
  await directoryBoundStore.close()
  await Promise.all(Array.from({ length: 18 }, (_, index) =>
    writeFile(
      join(directoryBoundOptions.directory, 'entries', `unexpected-${index}`),
      'x',
    )))
  await assert.rejects(
    openReferenceTransparencyLogStore(directoryBoundOptions),
    /directory limit/i,
  )
})

test('one durable uncheckpointed leaf and one durable checkpoint both recover after injected crashes', async (t) => {
  const parent = await temporaryDirectory(t)
  const logKeys = keyPair()
  const fixtures = fixtureRequests(2)

  for (const phase of ['after-entry-durable', 'after-checkpoint-durable']) {
    const stateDirectory = join(parent, phase)
    let injected = false
    const crashing = await openReferenceTransparencyLogStore({
      directory: stateDirectory,
      origin: ORIGIN,
      privateKeyBytes: logKeys.privateKey,
      now: () => FIXED_TIME,
      faultInjector: (observedPhase) => {
        if (!injected && observedPhase === phase) {
          injected = true
          throw new Error(`synthetic crash at ${phase}`)
        }
      },
    })
    await assert.rejects(
      crashing.publish(fixtures[0].request, { now: FIXED_TIME }),
      new RegExp(phase),
    )
    await crashing.close()

    const restarted = await openReferenceTransparencyLogStore({
      directory: stateDirectory,
      origin: ORIGIN,
      privateKeyBytes: logKeys.privateKey,
      now: () => FIXED_TIME,
    })
    assert.equal(restarted.snapshot().tree_size, 1)
    const replay = await restarted.publish(fixtures[0].request, {
      now: FIXED_TIME,
    })
    assert.equal(replay.idempotent, true)
    assertVerifies(replay.receipt, fixtures[0].attestation, logKeys)
    const second = await restarted.publish(fixtures[1].request, {
      now: FIXED_TIME,
    })
    assert.equal(second.receipt.checkpoint.tree_size, 2)
    assertVerifies(second.receipt, fixtures[1].attestation, logKeys)
    await restarted.close()
  }
})

test('atomic target/temp crash windows reconcile exact inodes and reject conflicting temporaries', async (t) => {
  const parent = await temporaryDirectory(t)
  const logKeys = keyPair()
  const [fixture] = fixtureRequests(1)
  const optionsFor = (name) => ({
    directory: join(parent, name),
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    now: () => FIXED_TIME,
  })

  const recoverOptions = optionsFor('recover')
  const original = await openReferenceTransparencyLogStore(recoverOptions)
  await original.publish(fixture.request, { now: FIXED_TIME })
  await original.close()
  const atomicPairs = [
    [
      join(recoverOptions.directory, 'metadata.json'),
      join(
        recoverOptions.directory,
        `.metadata.json.tmp-999-${'a'.repeat(24)}`,
      ),
    ],
    [
      join(recoverOptions.directory, 'entries', '0000000000000000.entry.json'),
      join(
        recoverOptions.directory,
        'entries',
        `.0000000000000000.entry.json.tmp-999-${'b'.repeat(24)}`,
      ),
    ],
    [
      join(
        recoverOptions.directory,
        'checkpoints',
        '0000000000000000.checkpoint.json',
      ),
      join(
        recoverOptions.directory,
        'checkpoints',
        `.0000000000000000.checkpoint.json.tmp-999-${'c'.repeat(24)}`,
      ),
    ],
  ]
  for (const [target, temporary] of atomicPairs) {
    await link(target, temporary)
    assert.equal((await lstat(target)).nlink, 2)
  }
  const recovered = await openReferenceTransparencyLogStore(recoverOptions)
  assert.equal(recovered.snapshot().tree_size, 1)
  for (const [target, temporary] of atomicPairs) {
    assert.equal((await lstat(target)).nlink, 1)
    await assert.rejects(lstat(temporary), /ENOENT/)
  }
  await recovered.close()

  const pendingOptions = optionsFor('pending')
  const empty = await openReferenceTransparencyLogStore(pendingOptions)
  await empty.close()
  const pending = join(
    pendingOptions.directory,
    'entries',
    `.0000000000000000.entry.json.tmp-777-${'d'.repeat(24)}`,
  )
  await writeFile(pending, 'uncommitted bytes')
  const pendingRecovered = await openReferenceTransparencyLogStore(pendingOptions)
  assert.equal(pendingRecovered.snapshot().tree_size, 0)
  await assert.rejects(lstat(pending), /ENOENT/)
  await pendingRecovered.close()

  const conflictOptions = optionsFor('conflict')
  const conflictStore = await openReferenceTransparencyLogStore(conflictOptions)
  await conflictStore.publish(fixture.request, { now: FIXED_TIME })
  await conflictStore.close()
  const conflicting = join(
    conflictOptions.directory,
    'entries',
    `.0000000000000000.entry.json.tmp-888-${'e'.repeat(24)}`,
  )
  await writeFile(conflicting, 'different inode')
  await assert.rejects(
    openReferenceTransparencyLogStore(conflictOptions),
    /same two-link durable inode|atomic.*conflict/i,
  )
  assert.equal(await readFile(conflicting, 'utf8'), 'different inode')
})

test('receipt creation uses its locked append result even when a later append finishes first', async (t) => {
  const parent = await temporaryDirectory(t)
  const logKeys = keyPair()
  const fixtures = fixtureRequests(2)
  const store = await openReferenceTransparencyLogStore({
    directory: join(parent, 'state'),
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    now: () => FIXED_TIME,
  })
  const append = store.append.bind(store)
  let interleave = true
  store.append = async (...arguments_) => {
    const result = await append(...arguments_)
    if (interleave) {
      interleave = false
      await append({
        request: fixtures[1].request,
        now: new Date('2026-08-01T10:03:00.000Z'),
      })
    }
    return result
  }
  const first = await store.publish(fixtures[0].request, { now: FIXED_TIME })
  assert.equal(first.receipt.checkpoint.tree_size, 1)
  assert.equal(store.snapshot().tree_size, 2)
  assertVerifies(first.receipt, fixtures[0].attestation, logKeys)
  await assert.rejects(
    store.publish(fixtures[0].request, { now: FIXED_TIME }),
    /clock cannot move backward/i,
  )
  await store.close()
})

test('reload rejects signed-state tampering, rollback evidence, and symlink substitution', async (t) => {
  const parent = await temporaryDirectory(t)
  const logKeys = keyPair()
  const fixtures = fixtureRequests(2)
  const optionsFor = (name) => ({
    directory: join(parent, name),
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    now: () => FIXED_TIME,
  })

  const tamperedOptions = optionsFor('tampered')
  const tampered = await openReferenceTransparencyLogStore(tamperedOptions)
  await tampered.publish(fixtures[0].request, { now: FIXED_TIME })
  await tampered.close()
  const firstEntryPath = join(
    tamperedOptions.directory,
    'entries',
    '0000000000000000.entry.json',
  )
  const firstEntry = JSON.parse(await readFile(firstEntryPath, 'utf8'))
  firstEntry.content_bytes += 1
  await writeFile(firstEntryPath, stableJson(firstEntry, 0))
  await assert.rejects(
    openReferenceTransparencyLogStore(tamperedOptions),
    /signature|exact request content|tamper/i,
  )

  const rollbackOptions = optionsFor('rollback')
  const rollback = await openReferenceTransparencyLogStore(rollbackOptions)
  await rollback.publish(fixtures[0].request, { now: FIXED_TIME })
  await rollback.publish(fixtures[1].request, { now: FIXED_TIME })
  await rollback.close()
  await rm(join(
    rollbackOptions.directory,
    'entries',
    '0000000000000001.entry.json',
  ))
  await assert.rejects(
    openReferenceTransparencyLogStore(rollbackOptions),
    /rollback|impossible entry\/checkpoint/i,
  )

  const symlinkOptions = optionsFor('symlink')
  const symlinkStore = await openReferenceTransparencyLogStore(symlinkOptions)
  await symlinkStore.publish(fixtures[0].request, { now: FIXED_TIME })
  await symlinkStore.close()
  const symlinkEntryPath = join(
    symlinkOptions.directory,
    'entries',
    '0000000000000000.entry.json',
  )
  const backupPath = join(parent, 'entry-backup.json')
  await copyFile(symlinkEntryPath, backupPath)
  await rm(symlinkEntryPath)
  try {
    await symlink(backupPath, symlinkEntryPath, 'file')
  } catch (error) {
    if (process.platform === 'win32' && error.code === 'EPERM') {
      return
    }
    throw error
  }
  await assert.rejects(
    openReferenceTransparencyLogStore(symlinkOptions),
    /regular non-symlink file/i,
  )
})

test('externally trusted checkpoints allow equal or older prefixes and reject rollback, ahead, fork, key, and origin drift', async (t) => {
  const parent = await temporaryDirectory(t)
  const logKeys = keyPair()
  const fixtures = fixtureRequests(4)

  async function createState({
    name,
    entries,
    keys = logKeys,
    origin = ORIGIN,
  }) {
    const options = {
      directory: join(parent, name),
      origin,
      privateKeyBytes: keys.privateKey,
      now: () => FIXED_TIME,
    }
    const store = await openReferenceTransparencyLogStore(options)
    const checkpoints = []
    for (const fixture of entries) {
      const published = await store.publish(fixture.request, { now: FIXED_TIME })
      checkpoints.push(projectTransparencySignedCheckpoint(published.receipt))
    }
    await store.close()
    return { options, checkpoints }
  }

  const baseline = await createState({
    name: 'baseline',
    entries: fixtures.slice(0, 3),
  })
  const equal = await openReferenceTransparencyLogStore({
    ...baseline.options,
    trustedCheckpoint: baseline.checkpoints[2],
  })
  assert.deepEqual(equal.snapshot().external_checkpoint, {
    status: 'EXTENDS_EXTERNAL_CHECKPOINT',
    checkpoint_sha256: digest(Buffer.from(
      stableJson(baseline.checkpoints[2], 0),
      'utf8',
    )),
    tree_size: 3,
    root_hash: baseline.checkpoints[2].checkpoint.root_hash,
  })
  await equal.close()

  const older = await openReferenceTransparencyLogStore({
    ...baseline.options,
    trustedCheckpoint: baseline.checkpoints[1],
  })
  assert.equal(older.snapshot().tree_size, 3)
  assert.equal(older.snapshot().external_checkpoint.tree_size, 2)
  await older.close()

  await rm(join(
    baseline.options.directory,
    'entries',
    '0000000000000002.entry.json',
  ))
  await rm(join(
    baseline.options.directory,
    'checkpoints',
    '0000000000000002.checkpoint.json',
  ))
  await assert.rejects(
    openReferenceTransparencyLogStore({
      ...baseline.options,
      trustedCheckpoint: baseline.checkpoints[2],
    }),
    /older than the externally trusted checkpoint/i,
  )

  const localBehind = await createState({
    name: 'local-behind',
    entries: fixtures.slice(0, 3),
  })
  const future = await createState({
    name: 'future',
    entries: fixtures,
  })
  await assert.rejects(
    openReferenceTransparencyLogStore({
      ...localBehind.options,
      trustedCheckpoint: future.checkpoints[3],
    }),
    /older than the externally trusted checkpoint/i,
  )

  const localFork = await createState({
    name: 'local-fork',
    entries: fixtures.slice(0, 3),
  })
  const alternateFork = await createState({
    name: 'alternate-fork',
    entries: fixtureRequests(3),
  })
  await assert.rejects(
    openReferenceTransparencyLogStore({
      ...localFork.options,
      trustedCheckpoint: alternateFork.checkpoints[2],
    }),
    /does not extend the externally trusted checkpoint/i,
  )

  const wrongKey = await createState({
    name: 'wrong-key',
    entries: fixtures.slice(0, 1),
    keys: keyPair(),
  })
  await assert.rejects(
    openReferenceTransparencyLogStore({
      ...localFork.options,
      trustedCheckpoint: wrongKey.checkpoints[0],
    }),
    /trusted checkpoint verification failed.*pinned public key/i,
  )

  const wrongOrigin = await createState({
    name: 'wrong-origin',
    entries: fixtures.slice(0, 1),
    origin: 'other.audit-log.example/v1',
  })
  await assert.rejects(
    openReferenceTransparencyLogStore({
      ...localFork.options,
      trustedCheckpoint: wrongOrigin.checkpoints[0],
    }),
    /trusted checkpoint verification failed.*origin/i,
  )
})

test('non-claim: restoring a whole valid prefix is not locally detectable without an external checkpoint', async (t) => {
  const parent = await temporaryDirectory(t)
  const stateDirectory = join(parent, 'state')
  const logKeys = keyPair()
  const fixtures = fixtureRequests(2)
  const options = {
    directory: stateDirectory,
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    now: () => FIXED_TIME,
  }
  const store = await openReferenceTransparencyLogStore(options)
  await store.publish(fixtures[0].request, { now: FIXED_TIME })
  await store.publish(fixtures[1].request, { now: FIXED_TIME })
  await store.close()
  await rm(join(
    stateDirectory,
    'entries',
    '0000000000000001.entry.json',
  ))
  await rm(join(
    stateDirectory,
    'checkpoints',
    '0000000000000001.checkpoint.json',
  ))

  const restoredPrefix = await openReferenceTransparencyLogStore(options)
  assert.equal(restoredPrefix.snapshot().tree_size, 1)
  assert.equal('external_checkpoint' in restoredPrefix.snapshot(), false)
  const first = await restoredPrefix.publish(fixtures[0].request, {
    now: FIXED_TIME,
  })
  assert.equal(first.receipt.checkpoint.tree_size, 1)
  assertVerifies(first.receipt, fixtures[0].attestation, logKeys)
  await restoredPrefix.close()
})

test('stale-lock recovery removes only an unchanged dead-owner lock', async (t) => {
  const parent = await temporaryDirectory(t)
  const stateDirectory = join(parent, 'state')
  const logKeys = keyPair()
  const base = {
    directory: stateDirectory,
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    now: () => FIXED_TIME,
    limits: {
      lockTimeoutMs: 40,
      staleLockMs: 1,
      lockPollMs: 2,
    },
  }
  const initial = await openReferenceTransparencyLogStore(base)
  await initial.close()
  const lockDirectory = join(stateDirectory, '.state.lock')
  const ownerPath = join(lockDirectory, 'owner.json')
  const owner = (pid) => stableJson({
    schema_version: '1.0.0',
    pid,
    acquired_at: '2000-01-01T00:00:00.000Z',
    nonce: 'a'.repeat(32),
  }, 0)

  await mkdir(lockDirectory)
  await writeFile(ownerPath, owner(process.pid), { flag: 'wx' })
  await assert.rejects(
    openReferenceTransparencyLogStore(base),
    /active transparency state lock/i,
  )
  assert.equal(JSON.parse(await readFile(ownerPath, 'utf8')).pid, process.pid)
  await rm(lockDirectory, { recursive: true })

  await mkdir(lockDirectory)
  await utimes(lockDirectory, new Date(0), new Date(0))
  const recoveredIncomplete = await openReferenceTransparencyLogStore(base)
  assert.equal(recoveredIncomplete.snapshot().tree_size, 0)
  await recoveredIncomplete.close()

  await mkdir(lockDirectory)
  const ownerTemporary = join(
    lockDirectory,
    `.owner.json.tmp-123-${'f'.repeat(24)}`,
  )
  await writeFile(ownerTemporary, owner(2_147_483_647), { flag: 'wx' })
  await link(ownerTemporary, ownerPath)
  const recovered = await openReferenceTransparencyLogStore(base)
  assert.equal(recovered.snapshot().tree_size, 0)
  await recovered.close()
  await assert.rejects(readFile(ownerPath), /ENOENT/)
  await assert.rejects(readFile(ownerTemporary), /ENOENT/)

  await mkdir(lockDirectory)
  await writeFile(ownerPath, 'not a valid atomic owner')
  await utimes(lockDirectory, new Date(0), new Date(0))
  await assert.rejects(
    openReferenceTransparencyLogStore(base),
    /active transparency state lock/i,
  )
  assert.equal(await readFile(ownerPath, 'utf8'), 'not a valid atomic owner')
  await rm(lockDirectory, { recursive: true })

  await mkdir(lockDirectory)
  await writeFile(ownerPath, owner(2_147_483_647))
  await writeFile(join(lockDirectory, 'unexpected.txt'), 'do not delete')
  await assert.rejects(
    openReferenceTransparencyLogStore(base),
    /lock contains unexpected files/i,
  )
  assert.equal(
    await readFile(join(lockDirectory, 'unexpected.txt'), 'utf8'),
    'do not delete',
  )
})

test('parallel child processes serialize appends without lost or duplicate leaves', async (t) => {
  const parent = await temporaryDirectory(t, 'rta-reference-log-process-test-')
  const stateDirectory = join(parent, 'state')
  const logKeys = keyPair()
  const fixtures = fixtureRequests(6)
  const keyPath = join(parent, 'log-private.pem')
  await writeFile(keyPath, logKeys.privateKey, { mode: 0o600 })
  const requestPaths = []
  for (let index = 0; index < fixtures.length; index += 1) {
    const path = join(parent, `request-${index}.json`)
    await writeFile(path, stableJson(fixtures[index].request, 0))
    requestPaths.push(path)
  }

  const workerPath = join(parent, 'append-worker.mjs')
  await writeFile(workerPath, `
    import { readFile } from 'node:fs/promises'
    const [storeUrl, directory, keyPath, requestPath, origin] = process.argv.slice(2)
    const { openReferenceTransparencyLogStore } = await import(storeUrl)
    const store = await openReferenceTransparencyLogStore({
      directory,
      origin,
      privateKeyBytes: await readFile(keyPath),
      limits: { lockTimeoutMs: 20000, staleLockMs: 30000, lockPollMs: 2 },
      now: () => new Date('2026-08-01T10:02:00.000Z'),
    })
    const request = JSON.parse(await readFile(requestPath, 'utf8'))
    const result = await store.publish(request, {
      now: new Date('2026-08-01T10:02:00.000Z'),
    })
    process.stdout.write(JSON.stringify({
      created: result.created,
      leaf_index: result.receipt.leaf_index,
    }))
    await store.close()
  `)
  const storeUrl = pathToFileURL(
    resolve('providers/reference-transparency-log/store.mjs'),
  ).href
  const children = await Promise.all(requestPaths.map((requestPath) =>
    execFileAsync(process.execPath, [
      workerPath,
      storeUrl,
      stateDirectory,
      keyPath,
      requestPath,
      ORIGIN,
    ], {
      encoding: 'utf8',
      windowsHide: true,
      timeout: 30_000,
    })))
  const results = children.map(({ stdout }) => JSON.parse(stdout))
  assert.ok(results.every(({ created }) => created))
  assert.deepEqual(
    results.map(({ leaf_index: index }) => index).sort((a, b) => a - b),
    [0, 1, 2, 3, 4, 5],
  )

  const restarted = await openReferenceTransparencyLogStore({
    directory: stateDirectory,
    origin: ORIGIN,
    privateKeyBytes: logKeys.privateKey,
    now: () => FIXED_TIME,
  })
  assert.equal(restarted.snapshot().tree_size, fixtures.length)
  const entryFiles = await readdir(join(stateDirectory, 'entries'))
  const checkpointFiles = await readdir(join(stateDirectory, 'checkpoints'))
  assert.equal(entryFiles.length, fixtures.length)
  assert.equal(checkpointFiles.length, fixtures.length)
  for (const fixture of fixtures) {
    const duplicate = await restarted.publish(fixture.request, { now: FIXED_TIME })
    assert.equal(duplicate.idempotent, true)
    assertVerifies(duplicate.receipt, fixture.attestation, logKeys)
  }
  await restarted.close()
})

test('state directory is rejected when nested in an audit bundle', async (t) => {
  const parent = await temporaryDirectory(t)
  const bundle = join(parent, 'audit-bundle')
  await mkdir(bundle)
  await writeFile(join(bundle, 'run.json'), JSON.stringify({
    run_id: 'run:2026-08-01T10-00-00-000Z:abcdef123456',
    phase: 'FINALIZED',
    state: 'COMPLETED',
  }))
  await assert.rejects(
    openReferenceTransparencyLogStore({
      directory: join(bundle, 'transparency-state'),
      origin: ORIGIN,
      privateKeyBytes: keyPair().privateKey,
    }),
    /outside the audit bundle/i,
  )
})

test('state directory rejects a symlink or junction in an ancestor path', async (t) => {
  const parent = await temporaryDirectory(t)
  const realParent = join(parent, 'real-parent')
  const linkedParent = join(parent, 'linked-parent')
  await mkdir(realParent)
  try {
    await symlink(
      realParent,
      linkedParent,
      process.platform === 'win32' ? 'junction' : 'dir',
    )
  } catch (error) {
    if (process.platform === 'win32' && error.code === 'EPERM') {
      t.skip('creating a directory junction requires additional privileges')
      return
    }
    throw error
  }
  await assert.rejects(
    openReferenceTransparencyLogStore({
      directory: join(linkedParent, 'state'),
      origin: ORIGIN,
      privateKeyBytes: keyPair().privateKey,
    }),
    /symlink or junction ancestor|path.*alias/i,
  )
})

test('leaf hashing in fixtures agrees with the transparency contract', () => {
  const [{ attestation }] = fixtureRequests(1)
  assert.equal(
    rawLeafHash(canonicalAttestationBytes(attestation)).toString('hex'),
    transparencyLeafHash(canonicalAttestationBytes(attestation)),
  )
})
