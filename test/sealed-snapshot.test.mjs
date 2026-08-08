import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { inventoryRepository } from '../scripts/lib/inventory.mjs'
import {
  assertValidSealedSnapshotIndex,
  buildSealedControlSnapshot,
  buildSealedSourceSnapshot,
  MAX_SEALED_SHARD_BYTES,
  readSealedSnapshotFile,
  serializeSealedSnapshotIndex,
  verifySealedSnapshot,
} from '../scripts/lib/sealed-snapshot.mjs'

const digest = (value) => createHash('sha256').update(value).digest('hex')
const TREE_SHA = 'a'.repeat(64)

function sourceEntry(path, content) {
  const bytes = Buffer.from(content, 'utf8')
  return {
    path,
    absolutePath: `C:\\untrusted\\${path}`,
    kind: 'text',
    size: bytes.length,
    sha256: digest(bytes),
    content,
    examined: true,
    reason: null,
  }
}

function binaryEntry(path, bytes) {
  return {
    path,
    absolutePath: `C:\\untrusted\\${path}`,
    kind: 'binary',
    size: bytes.length,
    sha256: digest(bytes),
    content: null,
    examined: false,
    reason: 'binary-content-not-decoded',
  }
}

test('source snapshots deterministically seal exact text bytes without indexing live paths or content', async () => {
  const inventory = {
    root: 'C:\\untrusted',
    treeDigest: TREE_SHA,
    entries: [
      binaryEntry('assets/logo.bin', Buffer.from([0, 1, 2])),
      sourceEntry('src/z.js', 'export const z = 1\n'),
      sourceEntry('src/a.js', 'export const a = 1\n'),
    ],
  }

  const first = buildSealedSourceSnapshot(inventory, { maxShardBytes: 64 })
  const second = buildSealedSourceSnapshot({
    ...inventory,
    entries: [...inventory.entries].reverse(),
  }, { maxShardBytes: 64 })

  assert.deepEqual(first.indexBytes, second.indexBytes)
  assert.deepEqual(
    first.shards.map(({ bytes }) => bytes),
    second.shards.map(({ bytes }) => bytes),
  )
  assert.equal(first.index.source_tree_digest, TREE_SHA)
  assert.equal(first.index.shard_encoding, 'raw')
  assert.equal(first.index.compression, 'none')
  assert.deepEqual(first.index.files.map(({ path }) => path), [
    'assets/logo.bin',
    'src/a.js',
    'src/z.js',
  ])

  const serialized = first.indexBytes.toString('utf8')
  assert.equal(serialized.includes('C:\\untrusted'), false)
  assert.equal(serialized.includes('export const'), false)
  assert.equal(serialized.includes('"content"'), false)
  assert.equal(serialized.includes('"absolutePath"'), false)

  const binary = first.index.files[0]
  assert.equal(binary.availability, 'UNAVAILABLE')
  assert.equal(binary.unavailable_reason, 'non-text')
  assert.equal(Object.hasOwn(binary, 'shard'), false)
  assert.equal(Object.hasOwn(binary, 'offset'), false)

  const text = first.index.files.find(({ path }) => path === 'src/a.js')
  assert.match(text.file_id, /^file_[a-f0-9]{64}$/)
  assert.equal(text.availability, 'AVAILABLE')
  const read = await readSealedSnapshotFile(first.indexBytes, text.file_id, first.shards)
  assert.deepEqual(read, Buffer.from('export const a = 1\n'))
  assert.deepEqual(await verifySealedSnapshot(first.indexBytes, first.shards), {
    valid: true,
    snapshot_kind: 'source',
    source_tree_digest: TREE_SHA,
    files: 3,
    available_files: 2,
    unavailable_files: 1,
    shards: 1,
  })
})

test('raw shard packing is deterministic, contiguous, uncompressed, and bounded', () => {
  const snapshot = buildSealedControlSnapshot([
    ['c.txt', Buffer.from('c')],
    ['a.txt', Buffer.from('12345')],
    ['b.txt', Buffer.from('6789')],
  ], { maxShardBytes: 8 })

  assert.equal(MAX_SEALED_SHARD_BYTES, 64 * 1024 * 1024)
  assert.deepEqual(snapshot.shards.map(({ bytes }) => bytes.toString('utf8')), [
    '12345',
    '6789c',
  ])
  assert.ok(snapshot.shards.every(({ size }) => size <= 8))
  assert.deepEqual(
    snapshot.index.files.map(({ shard, offset, length }) => ({ shard, offset, length })),
    [
      { shard: 'shard_000000', offset: 0, length: 5 },
      { shard: 'shard_000001', offset: 0, length: 4 },
      { shard: 'shard_000001', offset: 4, length: 1 },
    ],
  )
  assert.throws(
    () => buildSealedControlSnapshot(
      [['too-large.txt', Buffer.alloc(9)]],
      { maxShardBytes: 8 },
    ),
    (error) => error.code === 'FILE_EXCEEDS_SHARD_LIMIT',
  )
  assert.throws(
    () => buildSealedControlSnapshot([], {
      maxShardBytes: MAX_SEALED_SHARD_BYTES + 1,
    }),
    (error) => error.code === 'SHARD_LIMIT_INVALID',
  )
})

test('source sealing rejects text whose UTF-8 representation is not the inventoried raw bytes', () => {
  const raw = Buffer.from([0xff])
  assert.throws(
    () => buildSealedSourceSnapshot({
      treeDigest: TREE_SHA,
      entries: [{
        path: 'invalid.txt',
        kind: 'text',
        size: raw.length,
        sha256: digest(raw),
        content: raw.toString('utf8'),
      }],
    }),
    (error) =>
      error.code === 'UTF8_ROUNDTRIP_MISMATCH'
      && error.details.expected_sha256 === digest(raw),
  )

  assert.throws(
    () => buildSealedSourceSnapshot({
      treeDigest: TREE_SHA,
      entries: [{
        path: 'missing.txt',
        kind: 'text',
        size: 0,
        sha256: digest(Buffer.alloc(0)),
      }],
    }),
    (error) => error.code === 'TEXT_CONTENT_UNAVAILABLE',
  )
})

test('verification and reads consume shard artifacts rather than repository paths', async () => {
  const snapshot = buildSealedControlSnapshot([
    { path: 'lenses/a.md', bytes: Buffer.from('alpha') },
    { path: 'lenses/b.md', bytes: Buffer.from('beta') },
  ], { snapshotKind: 'lens', maxShardBytes: 5 })
  const requested = []
  const byId = new Map(snapshot.shards.map(({ shard_id: shardId, bytes }) => [
    shardId,
    bytes,
  ]))

  const verified = await verifySealedSnapshot(snapshot.index, async (shardId, expected) => {
    requested.push({ shardId, expected })
    return byId.get(shardId)
  })
  assert.equal(verified.snapshot_kind, 'lens')
  assert.deepEqual(requested.map(({ shardId }) => shardId), [
    'shard_000000',
    'shard_000001',
  ])
  assert.ok(requested.every(({ expected }) =>
    Object.keys(expected).sort().join(',') === 'sha256,shard_id,size'))
  assert.equal(requested.some((entry) => JSON.stringify(entry).includes('lenses/')), false)

  const target = snapshot.index.files.find(({ path }) => path === 'lenses/b.md')
  assert.deepEqual(
    await readSealedSnapshotFile(snapshot.index, target.file_id, byId.get(target.shard)),
    Buffer.from('beta'),
  )

  const tampered = new Map(byId)
  tampered.set('shard_000000', Buffer.from('ALPHA'))
  await assert.rejects(
    verifySealedSnapshot(snapshot.index, tampered),
    (error) => error.code === 'SHARD_DIGEST_MISMATCH',
  )
})

test('control and lens snapshot identities are deterministic, opaque, and domain-separated', () => {
  const entries = [
    ['schema/run.json', Buffer.from('{"type":"object"}')],
    ['lenses/web.md', Buffer.from('# Web')],
    ['unicode/é.md', Buffer.from('# Composed')],
    ['unicode/e\u0301.md', Buffer.from('# Decomposed')],
  ]
  const control = buildSealedControlSnapshot(entries)
  const reordered = buildSealedControlSnapshot([...entries].reverse())
  const lens = buildSealedControlSnapshot(entries, { snapshotKind: 'lens' })

  assert.deepEqual(control.indexBytes, reordered.indexBytes)
  assert.deepEqual(
    control.shards.map(({ bytes }) => bytes),
    reordered.shards.map(({ bytes }) => bytes),
  )
  assert.equal(control.index.source_tree_digest, reordered.index.source_tree_digest)
  assert.notEqual(
    control.index.files[0].file_id,
    lens.index.files[0].file_id,
  )
  assert.equal(control.index.source_tree_digest, lens.index.source_tree_digest)
  assert.deepEqual(
    control.index.files.filter(({ path }) => path.startsWith('unicode/'))
      .map(({ path }) => path),
    ['unicode/e\u0301.md', 'unicode/é.md'],
  )
})

test('index validation rejects traversal, duplicate paths, hidden bytes, and unavailable reads', async () => {
  assert.throws(
    () => buildSealedControlSnapshot([['../escape', Buffer.from('x')]]),
    (error) => error.code === 'PATH_INVALID',
  )
  assert.throws(
    () => buildSealedControlSnapshot([['bad/\ud800.txt', Buffer.from('x')]]),
    (error) => error.code === 'PATH_INVALID',
  )
  assert.throws(
    () => buildSealedControlSnapshot([
      ['same', Buffer.from('a')],
      ['same', Buffer.from('b')],
    ]),
    (error) => error.code === 'DUPLICATE_PATH',
  )

  const snapshot = buildSealedSourceSnapshot({
    treeDigest: TREE_SHA,
    entries: [
      sourceEntry('empty.txt', ''),
      binaryEntry('opaque.bin', Buffer.from([1])),
    ],
  }, { maxShardBytes: 1 })
  assert.equal(snapshot.shards.length, 1)
  assert.equal(snapshot.shards[0].size, 0)
  const binary = snapshot.index.files.find(({ path }) => path === 'opaque.bin')
  await assert.rejects(
    readSealedSnapshotFile(snapshot.index, binary.file_id, snapshot.shards),
    (error) => error.code === 'CONTENT_UNAVAILABLE',
  )

  const forged = JSON.parse(serializeSealedSnapshotIndex(snapshot.index))
  forged.shards[0].size = 1
  assert.throws(
    () => assertValidSealedSnapshotIndex(forged),
    (error) =>
      ['SHARD_LAYOUT_INVALID', 'FILE_MANIFEST_DIGEST_MISMATCH'].includes(error.code),
  )
})

test('real inventory entries without a content digest still seal and stay counted', async () => {
  const fixtureRoot = await mkdtemp(join(tmpdir(), 'red-team-seal-undigested-'))
  try {
    await writeFile(join(fixtureRoot, 'app.js'), 'export const a = 1\n')
    await writeFile(join(fixtureRoot, 'big.txt'), 'a'.repeat(256))
    await writeFile(join(fixtureRoot, 'small.bin'), Buffer.from([0, 1, 2]))
    await writeFile(
      join(fixtureRoot, 'big.bin'),
      Buffer.concat([Buffer.alloc(256), Buffer.from([1])]),
    )
    const inventory = await inventoryRepository(fixtureRoot, { maxTextBytes: 64 })
    assert.deepEqual(
      inventory.entries.map((entry) =>
        [entry.path, entry.kind, Object.hasOwn(entry, 'sha256')]),
      [
        ['app.js', 'text', true],
        ['big.bin', 'binary', false],
        ['big.txt', 'too-large', false],
        ['small.bin', 'binary', true],
      ],
    )

    const snapshot = buildSealedSourceSnapshot(inventory)
    assert.deepEqual(
      snapshot.index.files.map(({ path, availability }) => [path, availability]),
      [
        ['app.js', 'AVAILABLE'],
        ['big.bin', 'UNAVAILABLE'],
        ['big.txt', 'UNAVAILABLE'],
        ['small.bin', 'UNAVAILABLE'],
      ],
    )
    const undigested = snapshot.index.files.find(({ path }) => path === 'big.txt')
    assert.equal(Object.hasOwn(undigested, 'sha256'), false)
    assert.equal(undigested.size, 256)
    const digested = snapshot.index.files.find(({ path }) => path === 'small.bin')
    assert.equal(
      digested.sha256,
      inventory.entries.find(({ path }) => path === 'small.bin').sha256,
    )
    assert.deepEqual(await verifySealedSnapshot(snapshot.indexBytes, snapshot.shards), {
      valid: true,
      snapshot_kind: 'source',
      source_tree_digest: inventory.treeDigest,
      files: 4,
      available_files: 1,
      unavailable_files: 3,
      shards: 1,
    })
    await assert.rejects(
      readSealedSnapshotFile(snapshot.indexBytes, undigested.file_id, snapshot.shards),
      (error) => error.code === 'CONTENT_UNAVAILABLE',
    )

    const forged = JSON.parse(serializeSealedSnapshotIndex(snapshot.index))
    delete forged.files.find(({ path }) => path === 'app.js').sha256
    assert.throws(
      () => assertValidSealedSnapshotIndex(forged),
      (error) => error.code === 'INDEX_KEYS_INVALID',
    )
  } finally {
    await rm(fixtureRoot, { recursive: true, force: true })
  }
})

test('sealed snapshot primitive has no filesystem dependency', async () => {
  const source = await readFile(
    new URL('../scripts/lib/sealed-snapshot.mjs', import.meta.url),
    'utf8',
  )
  assert.doesNotMatch(source, /node:fs|from ['"]fs/)
})
