import assert from 'node:assert/strict'
import test from 'node:test'
import {
  DEFAULT_WORK_SHARD_LIMITS,
  WorkShardError,
  buildRetryJobTemplate,
  digestWorkScope,
  packWorkShards,
  validateWorkShardLimits,
  workShardId,
} from '../scripts/lib/work-shards.mjs'

const SHA_A = 'a'.repeat(64)
const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)
const SHA_D = 'd'.repeat(64)

const file = (path, size, sha256) => ({ path, size, sha256 })

test('work shard limits expose immutable validated defaults', () => {
  const defaults = validateWorkShardLimits()

  assert.deepEqual(defaults, DEFAULT_WORK_SHARD_LIMITS)
  assert.ok(Object.isFrozen(defaults))
  assert.ok(Object.isFrozen(DEFAULT_WORK_SHARD_LIMITS))
  assert.throws(
    () => validateWorkShardLimits({ maxFiles: 0 }),
    (error) =>
      error instanceof WorkShardError
      && error.code === 'WORK_SHARD_LIMITS_INVALID',
  )
  assert.throws(
    () => validateWorkShardLimits({ maxBytes: 0 }),
    (error) =>
      error instanceof WorkShardError
      && error.code === 'WORK_SHARD_LIMITS_INVALID',
  )
})

test('greedy packing honors exact file and byte boundaries', () => {
  const shards = packWorkShards([
    file('d.js', 4, SHA_D),
    file('b.js', 5, SHA_B),
    file('a.js', 5, SHA_A),
    file('c.js', 6, SHA_C),
  ], {
    maxFiles: 2,
    maxBytes: 10,
  })

  assert.equal(shards.length, 2)
  assert.deepEqual(
    shards.map(({ scoped_files: scopedFiles }) => scopedFiles),
    [
      ['a.js', 'b.js'],
      ['c.js', 'd.js'],
    ],
  )
  for (const [offset, { scoped_files: scopedFiles, shard }] of shards.entries()) {
    assert.equal(shard.index, offset + 1)
    assert.equal(shard.count, 2)
    assert.equal(shard.file_count, 2)
    assert.equal(shard.byte_count, 10)
    assert.equal(shard.max_files, 2)
    assert.equal(shard.max_bytes, 10)
    assert.equal(shard.scope_sha256, digestWorkScope(
      scopedFiles.map((path) => ({
        path,
        size: path === 'c.js' ? 6 : path === 'd.js' ? 4 : 5,
        sha256: {
          'a.js': SHA_A,
          'b.js': SHA_B,
          'c.js': SHA_C,
          'd.js': SHA_D,
        }[path],
      })),
    ))
    assert.equal(shard.shard_id, workShardId(shard.index, shard.scope_sha256))
  }
})

test('packing and scope identities are stable under input permutation', () => {
  const files = [
    file('src/z.js', 2, SHA_D.toUpperCase()),
    file('src/a.js', 3, SHA_A),
    file('src/m.js', 4, SHA_C),
    file('src/b.js', 5, SHA_B),
  ]
  const limits = { maxFiles: 2, maxBytes: 7 }

  const forward = packWorkShards(files, limits)
  const permuted = packWorkShards(
    [files[2], files[0], files[3], files[1]],
    limits,
  )

  assert.deepEqual(permuted, forward)
  assert.equal(
    digestWorkScope(files),
    digestWorkScope([files[1], files[3], files[0], files[2]]),
  )
  assert.match(forward[0].shard.scope_sha256, /^[a-f0-9]{64}$/)
  assert.match(forward[0].shard.shard_id, /^shard-0001-[a-f0-9]{12}$/)
})

test('a single file over the byte limit is rejected instead of making an oversized shard', () => {
  assert.throws(
    () => packWorkShards([
      file('src/oversized.js', 11, SHA_A),
    ], {
      maxFiles: 10,
      maxBytes: 10,
    }),
    (error) =>
      error instanceof WorkShardError
      && error.code === 'WORK_FILE_EXCEEDS_SHARD_BYTE_LIMIT'
      && error.details.path === 'src/oversized.js'
      && error.details.size === 11
      && error.details.maxBytes === 10,
  )
})

test('retry identity is deterministic and the retry template preserves the whole shard', () => {
  const files = [
    file('src/one.js', 3, SHA_A),
    file('src/two.js', 4, SHA_B),
    file('src/three.js', 8, SHA_C),
  ]
  const [originalShard] = packWorkShards(files, {
    maxFiles: 2,
    maxBytes: 8,
  })
  const [sameShard] = packWorkShards(
    [files[1], files[2], files[0]],
    { maxFiles: 2, maxBytes: 8 },
  )
  const options = {
    parentJobId: 'lens:web:shard-0001',
    lens: 'web',
    closureRound: 1,
  }

  const first = buildRetryJobTemplate(originalShard, options)
  const repeated = buildRetryJobTemplate(originalShard, options)
  const permuted = buildRetryJobTemplate(sameShard, options)

  assert.deepEqual(repeated, first)
  assert.deepEqual(permuted, first)
  assert.match(
    first.job_id,
    /^closure:01:shard-0001-[a-f0-9]{12}:[a-f0-9]{12}$/,
  )
  assert.equal(first.parent_job_id, options.parentJobId)
  assert.equal(first.closure_round, 1)
  assert.deepEqual(first.scoped_files, originalShard.scoped_files)
  assert.equal(first.scoped_files.length, originalShard.shard.file_count)
  assert.equal(first.shard.byte_count, originalShard.shard.byte_count)
  assert.ok(Object.isFrozen(first))
  assert.ok(Object.isFrozen(first.scoped_files))
  assert.ok(Object.isFrozen(first.shard))

  const nextRound = buildRetryJobTemplate(originalShard, {
    ...options,
    closureRound: 2,
  })
  assert.notEqual(nextRound.job_id, first.job_id)
  assert.deepEqual(nextRound.scoped_files, first.scoped_files)
})
