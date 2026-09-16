import assert from 'node:assert/strict'
import {
  createHash,
  generateKeyPairSync,
  sign as signBytes,
} from 'node:crypto'
import {
  link as hardLink,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  rmdir,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'

import {
  referenceTransparencyConsistencyPath,
  referenceTransparencyMerkleRoot,
} from '../providers/reference-transparency-log/store.mjs'
import {
  openTransparencyCheckpointJournal,
  validateTransparencyCheckpointJournalRecord,
} from '../scripts/lib/transparency-checkpoint-journal.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'

const CHECKPOINT_CONTEXT = Buffer.from(
  'red-team-audit/transparency-checkpoint/v1\0',
  'utf8',
)
const ORIGIN = 'journal-test.example/v1'
const VERIFY_NOW = new Date('2030-01-01T00:00:00.000Z')

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function leafHash(index, branch = 'main') {
  return sha256(Buffer.concat([
    Buffer.from([0]),
    Buffer.from(`${branch}-leaf-${index}`, 'utf8'),
  ]))
}

function keyFixture() {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519')
  const publicDer = publicKey.export({ type: 'spki', format: 'der' })
  return {
    privateKey,
    publicKeyBytes: Buffer.from(
      publicKey.export({ type: 'spki', format: 'pem' }),
      'utf8',
    ),
    keyId: `ed25519:${sha256(publicDer)}`,
  }
}

function signedCheckpoint(keys, leaves, size, second = size) {
  const checkpoint = {
    origin: ORIGIN,
    tree_size: size,
    root_hash: referenceTransparencyMerkleRoot(leaves.slice(0, size)),
    issued_at: `2026-08-01T00:00:${String(second).padStart(2, '0')}.000Z`,
    signing: {
      algorithm: 'Ed25519',
      key_id: keys.keyId,
    },
  }
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/transparency-signed-checkpoint',
    checkpoint,
    signature: signBytes(
      null,
      Buffer.concat([
        CHECKPOINT_CONTEXT,
        Buffer.from(stableJson(checkpoint, 0), 'utf8'),
      ]),
      keys.privateKey,
    ).toString('base64'),
  }
}

function consistencyProof(first, second, leaves) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/transparency-consistency-proof',
    first_checkpoint: structuredClone(first),
    second_checkpoint: structuredClone(second),
    consistency_path: referenceTransparencyConsistencyPath(
      leaves,
      first.checkpoint.tree_size,
      second.checkpoint.tree_size,
    ),
  }
}

async function temporaryDirectory(t, suffix = '') {
  const directory = await mkdtemp(join(tmpdir(), `rta-checkpoint-journal-${suffix}`))
  t.after(async () => {
    await rm(directory, { recursive: true, force: true })
  })
  return directory
}

function journalOptions(directory, keys, additions = {}) {
  return {
    directory,
    expectedOrigin: ORIGIN,
    publicKeyBytes: keys.publicKeyBytes,
    now: () => VERIFY_NOW,
    ...additions,
  }
}

function deferred() {
  let resolvePromise
  const promise = new Promise((resolve) => {
    resolvePromise = resolve
  })
  return { promise, resolve: resolvePromise }
}

test('journal record schema is strict and distinguishes its baseline', () => {
  const keys = keyFixture()
  const leaves = [leafHash(0)]
  const checkpoint = signedCheckpoint(keys, leaves, 1)
  const baseline = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/transparency-checkpoint-journal-record',
    sequence: 0,
    previous_record_sha256: null,
    checkpoint,
    consistency_proof: null,
  }
  assert.equal(validateTransparencyCheckpointJournalRecord(baseline).valid, true)

  assert.equal(validateTransparencyCheckpointJournalRecord({
    ...baseline,
    unexpected: true,
  }).valid, false)
  assert.equal(validateTransparencyCheckpointJournalRecord({
    ...baseline,
    previous_record_sha256: '0'.repeat(64),
  }).valid, false)
  assert.equal(validateTransparencyCheckpointJournalRecord({
    ...baseline,
    sequence: 1,
  }).valid, false)
})

test('journal initializes explicitly, advances, chains exact bytes, and reloads offline', async (t) => {
  const directory = await temporaryDirectory(t, 'roundtrip-')
  const keys = keyFixture()
  const leaves = Array.from({ length: 5 }, (_, index) => leafHash(index))
  const first = signedCheckpoint(keys, leaves, 1)
  const second = signedCheckpoint(keys, leaves, 5)
  const serviceFirst = signedCheckpoint(keys, leaves, 1, 20)
  const serviceSecond = signedCheckpoint(keys, leaves, 5, 21)
  const proof = consistencyProof(serviceFirst, serviceSecond, leaves)

  const journal = await openTransparencyCheckpointJournal(
    journalOptions(directory, keys),
  )
  assert.equal(journal.snapshot().record_count, 0)
  const baseline = await journal.advance({ checkpoint: first })
  assert.equal(baseline.created, true)
  assert.equal(baseline.sequence, 0)

  const advanced = await journal.advance({
    expectedHead: first,
    checkpoint: second,
    consistencyProof: proof,
  })
  assert.equal(advanced.created, true)
  assert.equal(advanced.sequence, 1)
  assert.equal(journal.snapshot().head.checkpoint.tree_size, 5)
  await journal.close()

  const firstBytes = await readFile(join(
    directory,
    '0000000000000000.checkpoint-journal.json',
  ))
  const secondRecord = JSON.parse(await readFile(join(
    directory,
    '0000000000000001.checkpoint-journal.json',
  ), 'utf8'))
  assert.equal(secondRecord.previous_record_sha256, sha256(firstBytes))
  assert.notDeepEqual(secondRecord.consistency_proof.first_checkpoint, first)
  assert.notDeepEqual(secondRecord.consistency_proof.second_checkpoint, second)
  assert.equal(
    secondRecord.consistency_proof.first_checkpoint.checkpoint.root_hash,
    first.checkpoint.root_hash,
  )
  assert.equal(
    secondRecord.consistency_proof.second_checkpoint.checkpoint.root_hash,
    second.checkpoint.root_hash,
  )

  const reopened = await openTransparencyCheckpointJournal(
    journalOptions(directory, keys),
  )
  const snapshot = await reopened.load()
  assert.equal(snapshot.record_count, 2)
  assert.equal(snapshot.head.checkpoint.tree_size, 5)
  assert.match(snapshot.head_record_sha256, /^[a-f0-9]{64}$/)
  await reopened.close()

  await assert.rejects(
    openTransparencyCheckpointJournal(journalOptions(
      directory,
      keyFixture(),
    )),
    /pinned log identity|public key|signature/i,
  )
  await assert.rejects(
    openTransparencyCheckpointJournal({
      ...journalOptions(directory, keys),
      expectedOrigin: 'substituted.example/v1',
    }),
    /pinned log identity|origin/i,
  )
})

test('read-only journal verification takes no lock and never reconciles crash residue', async (t) => {
  const directory = await temporaryDirectory(t, 'read-only-')
  const keys = keyFixture()
  const leaves = [leafHash(0)]
  const checkpoint = signedCheckpoint(keys, leaves, 1)
  const writable = await openTransparencyCheckpointJournal(
    journalOptions(directory, keys),
  )
  await writable.advance({ checkpoint })
  await writable.close()

  const namesBefore = await readdir(directory)
  const readOnly = await openTransparencyCheckpointJournal(
    journalOptions(directory, keys, { readOnly: true }),
  )
  assert.equal((await readOnly.load()).record_count, 1)
  assert.equal(
    (await readOnly.continuityForCheckpoint(checkpoint)).claim,
    'CHECKPOINT_BASELINE_ONLY',
  )
  await assert.rejects(
    readOnly.advance({ checkpoint }),
    /read-only checkpoint journal cannot be advanced/i,
  )
  await readOnly.close()
  assert.deepEqual(await readdir(directory), namesBefore)

  const residue = join(
    directory,
    `.0000000000000001.checkpoint-journal.json.tmp-999-${'a'.repeat(24)}`,
  )
  await writeFile(residue, 'uncommitted residue')
  await assert.rejects(
    openTransparencyCheckpointJournal(
      journalOptions(directory, keys, { readOnly: true }),
    ),
    /unexpected|temporary|residue/i,
  )
  assert.equal(await readFile(residue, 'utf8'), 'uncommitted residue')
})

test('continuity lookup distinguishes a baseline and finds older retained heads', async (t) => {
  const directory = await temporaryDirectory(t, 'continuity-')
  const keys = keyFixture()
  const leaves = Array.from({ length: 4 }, (_, index) => leafHash(index))
  const first = signedCheckpoint(keys, leaves, 1)
  const second = signedCheckpoint(keys, leaves, 2)
  const fourth = signedCheckpoint(keys, leaves, 4)
  const journal = await openTransparencyCheckpointJournal(
    journalOptions(directory, keys),
  )
  await journal.advance({ checkpoint: first })
  const baseline = await journal.continuityForCheckpoint(
    signedCheckpoint(keys, leaves, 1, 30),
  )
  assert.equal(baseline.status, 'NOT_VERIFIED')
  assert.equal(baseline.claim, 'CHECKPOINT_BASELINE_ONLY')
  assert.equal(baseline.record_sequence, 0)

  await journal.advance({
    expectedHead: first,
    checkpoint: second,
    consistencyProof: consistencyProof(
      signedCheckpoint(keys, leaves, 1, 31),
      signedCheckpoint(keys, leaves, 2, 32),
      leaves,
    ),
  })
  await journal.advance({
    expectedHead: second,
    checkpoint: fourth,
    consistencyProof: consistencyProof(second, fourth, leaves),
  })
  const retained = await journal.continuityForCheckpoint(
    signedCheckpoint(keys, leaves, 2, 33),
  )
  assert.equal(retained.status, 'VERIFIED')
  assert.equal(
    retained.claim,
    'CONSISTENT_WITH_EXTERNALLY_RETAINED_CHECKPOINT',
  )
  assert.equal(retained.baseline_tree_size, 1)
  assert.equal(retained.current_tree_size, 2)
  assert.equal(retained.record_sequence, 1)
  assert.equal(retained.witness_quorum, 'NOT_VERIFIED')

  const skipped = signedCheckpoint(keys, leaves, 3)
  await assert.rejects(
    journal.continuityForCheckpoint(skipped),
    /not an exact checkpoint retained|absent/i,
  )
  const forkLeaves = [leaves[0], leafHash(1, 'fork')]
  const fork = signedCheckpoint(keys, forkLeaves, 2, 34)
  await assert.rejects(
    journal.continuityForCheckpoint(fork),
    /conflicts|fork/i,
  )
  await journal.close()
})

test('same-head advancement is idempotent and stale expected heads conflict', async (t) => {
  const directory = await temporaryDirectory(t, 'cas-')
  const keys = keyFixture()
  const leaves = Array.from({ length: 3 }, (_, index) => leafHash(index))
  const first = signedCheckpoint(keys, leaves, 1)
  const second = signedCheckpoint(keys, leaves, 2)
  const third = signedCheckpoint(keys, leaves, 3)
  const journal = await openTransparencyCheckpointJournal(
    journalOptions(directory, keys),
  )
  await journal.advance({ checkpoint: first })
  await journal.advance({
    expectedHead: first,
    checkpoint: second,
    consistencyProof: consistencyProof(first, second, leaves),
  })

  const duplicate = await journal.advance({
    expectedHead: first,
    checkpoint: second,
    consistencyProof: consistencyProof(first, second, leaves),
  })
  assert.equal(duplicate.created, false)
  assert.equal(duplicate.idempotent, true)
  assert.equal(journal.snapshot().record_count, 2)

  await assert.rejects(
    journal.advance({
      expectedHead: first,
      checkpoint: third,
      consistencyProof: consistencyProof(second, third, leaves),
    }),
    /head differs|CAS/i,
  )
  assert.equal(journal.snapshot().record_count, 2)
  await journal.close()
})

test('concurrent same-head advances yield one winner and one idempotent result', async (t) => {
  const directory = await temporaryDirectory(t, 'concurrent-same-')
  const keys = keyFixture()
  const leaves = [leafHash(0), leafHash(1)]
  const first = signedCheckpoint(keys, leaves, 1)
  const second = signedCheckpoint(keys, leaves, 2)
  const proof = consistencyProof(first, second, leaves)
  const left = await openTransparencyCheckpointJournal(
    journalOptions(directory, keys),
  )
  await left.advance({ checkpoint: first })
  const right = await openTransparencyCheckpointJournal(
    journalOptions(directory, keys),
  )

  const results = await Promise.all([
    left.advance({
      expectedHead: first,
      checkpoint: second,
      consistencyProof: proof,
    }),
    right.advance({
      expectedHead: first,
      checkpoint: second,
      consistencyProof: proof,
    }),
  ])
  assert.deepEqual(
    results.map(({ created }) => created).sort(),
    [false, true],
  )
  assert.equal((await left.load()).record_count, 2)
  await left.close()
  await right.close()
})

test('concurrent divergent advances preserve one branch and reject the fork', async (t) => {
  const directory = await temporaryDirectory(t, 'concurrent-fork-')
  const keys = keyFixture()
  const common = leafHash(0)
  const leftLeaves = [common, leafHash(1, 'left')]
  const rightLeaves = [common, leafHash(1, 'right')]
  const first = signedCheckpoint(keys, leftLeaves, 1)
  const leftHead = signedCheckpoint(keys, leftLeaves, 2, 2)
  const rightHead = signedCheckpoint(keys, rightLeaves, 2, 3)
  const left = await openTransparencyCheckpointJournal(
    journalOptions(directory, keys),
  )
  await left.advance({ checkpoint: first })
  const right = await openTransparencyCheckpointJournal(
    journalOptions(directory, keys),
  )

  const results = await Promise.allSettled([
    left.advance({
      expectedHead: first,
      checkpoint: leftHead,
      consistencyProof: consistencyProof(first, leftHead, leftLeaves),
    }),
    right.advance({
      expectedHead: first,
      checkpoint: rightHead,
      consistencyProof: consistencyProof(first, rightHead, rightLeaves),
    }),
  ])
  assert.equal(results.filter(({ status }) => status === 'fulfilled').length, 1)
  assert.equal(results.filter(({ status }) => status === 'rejected').length, 1)
  assert.match(
    results.find(({ status }) => status === 'rejected').reason.message,
    /fork|current tree size/i,
  )
  assert.equal((await left.load()).record_count, 2)
  await left.close()
  await right.close()
})

test('an incomplete lock owner publication still serializes divergent advances', { timeout: 10_000 }, async (t) => {
  const directory = await temporaryDirectory(t, 'incomplete-lock-owner-')
  const keys = keyFixture()
  const common = leafHash(0)
  const leftLeaves = [common, leafHash(1, 'left')]
  const rightLeaves = [common, leafHash(1, 'right')]
  const first = signedCheckpoint(keys, leftLeaves, 1)
  const leftHead = signedCheckpoint(keys, leftLeaves, 2, 2)
  const rightHead = signedCheckpoint(keys, rightLeaves, 2, 3)
  const left = await openTransparencyCheckpointJournal(
    journalOptions(directory, keys),
  )
  await left.advance({ checkpoint: first })
  const ownerObserved = deferred()
  const releaseObservation = deferred()
  let observationArmed = false
  const right = await openTransparencyCheckpointJournal(
    journalOptions(directory, keys, {
      faultInjector: async (phase) => {
        if (observationArmed && phase === 'after-incomplete-lock-owner-observed') {
          ownerObserved.resolve()
          await releaseObservation.promise
        }
      },
    }),
  )
  const lockPath = join(directory, '.checkpoint-journal.lock')
  const ownerPath = join(lockPath, 'owner.json')
  await mkdir(lockPath, { mode: 0o700 })
  await writeFile(ownerPath, '', { flag: 'wx', mode: 0o600 })
  observationArmed = true

  const rightAdvance = right.advance({
    expectedHead: first,
    checkpoint: rightHead,
    consistencyProof: consistencyProof(first, rightHead, rightLeaves),
  })
  await ownerObserved.promise
  assert.equal(await readFile(ownerPath, 'utf8'), '')
  await unlink(ownerPath)
  await rmdir(lockPath)
  const leftAdvance = left.advance({
    expectedHead: first,
    checkpoint: leftHead,
    consistencyProof: consistencyProof(first, leftHead, leftLeaves),
  })
  releaseObservation.resolve()

  const results = await Promise.allSettled([leftAdvance, rightAdvance])
  assert.equal(results.filter(({ status }) => status === 'fulfilled').length, 1)
  assert.equal(results.filter(({ status }) => status === 'rejected').length, 1)
  assert.match(
    results.find(({ status }) => status === 'rejected').reason.message,
    /fork|current tree size/i,
  )
  assert.equal((await left.load()).record_count, 2)
  assert.equal((await readdir(directory)).includes('.checkpoint-journal.lock'), false)
  await left.close()
  await right.close()
})

test('a stable malformed lock owner remains untouched and fails closed', async (t) => {
  const directory = await temporaryDirectory(t, 'malformed-lock-owner-')
  const keys = keyFixture()
  const lockPath = join(directory, '.checkpoint-journal.lock')
  const ownerPath = join(lockPath, 'owner.json')
  const malformedOwner = stableJson({ forged: true }, 0)
  await mkdir(lockPath, { mode: 0o700 })
  await writeFile(ownerPath, malformedOwner, { flag: 'wx', mode: 0o600 })

  await assert.rejects(
    openTransparencyCheckpointJournal(journalOptions(directory, keys, {
      limits: { lockTimeoutMs: 250, lockPollMs: 1 },
    })),
    (error) => error.code === 'TRANSPARENCY_CHECKPOINT_JOURNAL_LOCK_UNSAFE'
      && /malformed and cannot be stolen/i.test(error.message),
  )
  assert.equal(await readFile(ownerPath, 'utf8'), malformedOwner)
  assert.deepEqual(await readdir(lockPath), ['owner.json'])
})

test('fault windows recover only an orphan temp or the exact durable record', async (t) => {
  const expectations = new Map([
    ['after-temporary-durable', 1],
    ['after-record-linked', 2],
    ['after-record-durable', 2],
    ['after-temporary-removed', 2],
  ])
  for (const [phase, expectedRecords] of expectations) {
    const directory = await temporaryDirectory(t, `${phase}-`)
    const keys = keyFixture()
    const leaves = [leafHash(0), leafHash(1)]
    const first = signedCheckpoint(keys, leaves, 1)
    const second = signedCheckpoint(keys, leaves, 2)
    const baseline = await openTransparencyCheckpointJournal(
      journalOptions(directory, keys),
    )
    await baseline.advance({ checkpoint: first })
    await baseline.close()

    let injected = false
    const crashing = await openTransparencyCheckpointJournal(
      journalOptions(directory, keys, {
        faultInjector(observed, details) {
          if (!injected && observed === phase && details.sequence === 1) {
            injected = true
            throw new Error(`injected ${phase}`)
          }
        },
      }),
    )
    await assert.rejects(
      crashing.advance({
        expectedHead: first,
        checkpoint: second,
        consistencyProof: consistencyProof(first, second, leaves),
      }),
      new RegExp(`injected ${phase}`),
    )
    await crashing.close()

    const recovered = await openTransparencyCheckpointJournal(
      journalOptions(directory, keys),
    )
    assert.equal(recovered.snapshot().record_count, expectedRecords)
    const names = await readdir(directory)
    assert.equal(names.some((name) => name.includes('.tmp-')), false)
    const retry = await recovered.advance({
      expectedHead: first,
      checkpoint: second,
      consistencyProof: consistencyProof(first, second, leaves),
    })
    assert.equal(retry.created, expectedRecords === 1)
    assert.equal(recovered.snapshot().record_count, 2)
    await recovered.close()
  }
})

test('malformed chains, invalid proofs, unexpected files, and unsafe links fail closed', async (t) => {
  const keys = keyFixture()
  const leaves = [leafHash(0), leafHash(1)]
  const first = signedCheckpoint(keys, leaves, 1)
  const second = signedCheckpoint(keys, leaves, 2)

  const chainDirectory = await temporaryDirectory(t, 'bad-chain-')
  const chainJournal = await openTransparencyCheckpointJournal(
    journalOptions(chainDirectory, keys),
  )
  await chainJournal.advance({ checkpoint: first })
  await chainJournal.close()
  const forgedRecord = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/transparency-checkpoint-journal-record',
    sequence: 1,
    previous_record_sha256: '0'.repeat(64),
    checkpoint: second,
    consistency_proof: consistencyProof(first, second, leaves),
  }
  await writeFile(
    join(chainDirectory, '0000000000000001.checkpoint-journal.json'),
    stableJson(forgedRecord, 0),
    { flag: 'wx', mode: 0o600 },
  )
  await assert.rejects(
    openTransparencyCheckpointJournal(journalOptions(chainDirectory, keys)),
    /does not bind its predecessor|chain/i,
  )

  const proofDirectory = await temporaryDirectory(t, 'bad-proof-')
  const proofJournal = await openTransparencyCheckpointJournal(
    journalOptions(proofDirectory, keys),
  )
  await proofJournal.advance({ checkpoint: first })
  const badProof = consistencyProof(first, second, leaves)
  badProof.consistency_path[0] = 'f'.repeat(64)
  await assert.rejects(
    proofJournal.advance({
      expectedHead: first,
      checkpoint: second,
      consistencyProof: badProof,
    }),
    /consistency proof/i,
  )
  assert.equal(proofJournal.snapshot().record_count, 1)
  await proofJournal.close()

  const unexpectedDirectory = await temporaryDirectory(t, 'unexpected-')
  await writeFile(join(unexpectedDirectory, 'notes.txt'), 'not journal state')
  await assert.rejects(
    openTransparencyCheckpointJournal(journalOptions(unexpectedDirectory, keys)),
    /unexpected entry/i,
  )

  const ambiguousDirectory = await temporaryDirectory(t, 'ambiguous-temp-')
  const ambiguousJournal = await openTransparencyCheckpointJournal(
    journalOptions(ambiguousDirectory, keys),
  )
  await ambiguousJournal.advance({ checkpoint: first })
  await ambiguousJournal.close()
  for (const nonce of ['a'.repeat(24), 'b'.repeat(24)]) {
    await writeFile(
      join(
        ambiguousDirectory,
        `.0000000000000001.checkpoint-journal.json.tmp-999-${nonce}`,
      ),
      'ambiguous',
      { flag: 'wx', mode: 0o600 },
    )
  }
  await assert.rejects(
    openTransparencyCheckpointJournal(journalOptions(ambiguousDirectory, keys)),
    /multiple temporaries|ambiguous/i,
  )

  const hardLinkDirectory = await temporaryDirectory(t, 'unsafe-hard-link-')
  const hardLinkJournal = await openTransparencyCheckpointJournal(
    journalOptions(hardLinkDirectory, keys),
  )
  await hardLinkJournal.advance({ checkpoint: first })
  await hardLinkJournal.close()
  await hardLink(
    join(hardLinkDirectory, '0000000000000000.checkpoint-journal.json'),
    join(hardLinkDirectory, '0000000000000001.checkpoint-journal.json'),
  )
  await assert.rejects(
    openTransparencyCheckpointJournal(journalOptions(hardLinkDirectory, keys)),
    /regular non-symlink|link count|unsafe/i,
  )

  const linkDirectory = await temporaryDirectory(t, 'unsafe-link-')
  const linkJournal = await openTransparencyCheckpointJournal(
    journalOptions(linkDirectory, keys),
  )
  await linkJournal.advance({ checkpoint: first })
  await linkJournal.close()
  try {
    await symlink(
      join(linkDirectory, '0000000000000000.checkpoint-journal.json'),
      join(linkDirectory, '0000000000000001.checkpoint-journal.json'),
    )
  } catch (error) {
    if (['EPERM', 'EACCES'].includes(error.code)) {
      t.diagnostic('symlink creation is unavailable; unsafe-link assertion skipped')
      return
    }
    throw error
  }
  await assert.rejects(
    openTransparencyCheckpointJournal(journalOptions(linkDirectory, keys)),
    /regular non-symlink|unsafe/i,
  )
})

test('absolute external placement and record bounds are enforced', async (t) => {
  const directory = await temporaryDirectory(t, 'limits-')
  const keys = keyFixture()
  const leaves = [leafHash(0), leafHash(1)]
  const first = signedCheckpoint(keys, leaves, 1)
  const second = signedCheckpoint(keys, leaves, 2)

  await assert.rejects(
    openTransparencyCheckpointJournal({
      directory: 'relative-journal',
      expectedOrigin: ORIGIN,
      publicKeyBytes: keys.publicKeyBytes,
    }),
    /absolute path/i,
  )
  await assert.rejects(
    openTransparencyCheckpointJournal(journalOptions(directory, keys, {
      auditBundleDirectory: directory,
    })),
    /separate|external/i,
  )

  const journal = await openTransparencyCheckpointJournal(
    journalOptions(directory, keys, {
      limits: { maxRecords: 1 },
    }),
  )
  await journal.advance({ checkpoint: first })
  await assert.rejects(
    journal.advance({
      expectedHead: first,
      checkpoint: second,
      consistencyProof: consistencyProof(first, second, leaves),
    }),
    /record limit/i,
  )
  assert.equal(journal.snapshot().record_count, 1)
  await journal.close()
})
