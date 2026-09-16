import assert from 'node:assert/strict'
import { chmod, link, lstat, mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, posix, resolve, win32 } from 'node:path'
import { spawnSync } from 'node:child_process'
import { test } from 'node:test'

import { stableJson } from '../scripts/lib/run-engine.mjs'
import { digestUnleashValue } from '../scripts/lib/unleash-contracts.mjs'
import {
  assertUnleashPrivateEndpoint,
  defaultUnleashControllerRoot,
  loadUnleashControllerPolicy,
} from '../scripts/lib/unleash-policy-loader.mjs'

const SCRATCH_PREFIX = 'last-aperture-unleash-policy-loader-'

function secureWindowsTestDirectory(path) {
  if (process.platform !== 'win32') return
  const systemRoot = process.env.SystemRoot
  assert.equal(typeof systemRoot, 'string')
  const whoami = win32.join(systemRoot, 'System32', 'whoami.exe')
  const identity = spawnSync(whoami, ['/user', '/fo', 'csv', '/nh'], {
    encoding: 'utf8',
    windowsHide: true,
  })
  assert.equal(identity.status, 0, identity.stderr)
  const sid = identity.stdout.match(/,"(S-[0-9-]+)"\s*$/u)?.[1]
  assert.match(sid ?? '', /^S-[0-9-]+$/u)
  const icacls = win32.join(systemRoot, 'System32', 'icacls.exe')
  const run = (args) => {
    const result = spawnSync(icacls, args, { encoding: 'utf8', windowsHide: true })
    assert.equal(result.status, 0, result.stderr)
  }
  run([path, '/grant:r', `*${sid}:(OI)(CI)F`])
  run([path, '/inheritance:r'])
  run([path, '/grant:r', '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F'])
}

function policyInput() {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-deployment-policy',
    policy_id: 'policy:loader-test',
    valid_from: '2026-09-15T09:00:00.000Z',
    valid_until: '2026-09-15T10:00:00.000Z',
    allowed_origins: ['https://example.test'],
    allowed_target_families: ['https'],
    allowed_effects: ['OBSERVE'],
    budgets: {
      max_actions: 4,
      max_parallel_actions: 1,
      max_duration_ms: 30_000,
      max_response_bytes: 65_536,
    },
    credential_references: [],
    revocation: { check_id: 'revocation:loader-test', fail_mode: 'CLOSED' },
  }
}

function revocations(
  revokedPolicyIds = [],
  updatedAt = '2026-09-15T09:15:00.000Z',
  generation = 1,
  overrides = {},
) {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-revocations',
    check_id: 'revocation:loader-test',
    policy_sha256: digestUnleashValue(policyInput()),
    generation,
    updated_at: updatedAt,
    revoked_policy_ids: revokedPolicyIds,
    ...overrides,
  }
}

async function harness(t) {
  const scratch = await mkdtemp(join(resolve(tmpdir()), SCRATCH_PREFIX))
  t.after(async () => {
    assert.equal(dirname(scratch), resolve(tmpdir()))
    await rm(scratch, { recursive: true, force: true })
  })
  const controlRoot = join(scratch, 'controller')
  await mkdir(controlRoot, { recursive: true, mode: 0o700 })
  secureWindowsTestDirectory(controlRoot)
  const policyPath = join(controlRoot, 'deployment-policy.json')
  const revocationsPath = join(controlRoot, 'revocations.json')
  const highWaterPath = join(controlRoot, '.revocation-high-water.json')
  await writeFile(policyPath, stableJson(policyInput()), { encoding: 'utf8', flag: 'wx', mode: 0o600 })
  await writeFile(revocationsPath, stableJson(revocations()), { encoding: 'utf8', flag: 'wx', mode: 0o600 })
  return { controlRoot, policyPath, revocationsPath, highWaterPath }
}

function checkRequest(overrides = {}) {
  return {
    check_id: 'revocation:loader-test',
    policy_id: 'policy:loader-test',
    target_id: `target:sha256:${'1'.repeat(64)}`,
    checked_at: '2026-09-15T09:30:00.000Z',
    ...overrides,
  }
}

test('uses one fixed app-owned controller root per platform', () => {
  assert.equal(
    defaultUnleashControllerRoot({
      platform: 'win32',
      localAppData: 'C:\\Users\\operator\\AppData\\Local',
      home: 'C:\\Users\\operator',
    }),
    win32.resolve('C:\\Users\\operator\\AppData\\Local', 'LastAperture', 'controller'),
  )
  assert.equal(
    defaultUnleashControllerRoot({ platform: 'linux', home: '/home/operator' }),
    posix.resolve('/home/operator', '.config', 'last-aperture', 'controller'),
  )
})

test('rejects Windows network and object-manager controller roots lexically before filesystem access', {
  skip: process.platform !== 'win32',
}, async () => {
  for (const controlRoot of [
    '\\\\server\\share\\LastAperture\\controller',
    '\\\\?\\UNC\\server\\share\\LastAperture\\controller',
    '\\\\.\\pipe\\last-aperture-controller',
    '\\??\\UNC\\server\\share\\LastAperture\\controller',
  ]) {
    await assert.rejects(
      loadUnleashControllerPolicy({ controlRoot }),
      (error) => error.code === 'UNLEASH_CONTROL_ROOT_INVALID'
        && error.cause?.code === 'FILESYSTEM_ENDPOINT_NOT_LOCAL',
      controlRoot,
    )
  }
})

test('loads, validates, detaches, and freezes the controller-owned policy', async (t) => {
  const h = await harness(t)
  const loaded = await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })

  assert.equal(loaded.policy.policy_id, 'policy:loader-test')
  assert.equal(Object.isFrozen(loaded), true)
  assert.equal(Object.isFrozen(loaded.policy), true)
  assert.equal(typeof loaded.isRevoked, 'function')
  assert.equal(loaded.isRevoked(checkRequest()), false)
  assert.equal(
    await assertUnleashPrivateEndpoint(h.controlRoot, 'directory'),
    resolve(h.controlRoot),
  )
  assert.equal(
    await assertUnleashPrivateEndpoint(h.policyPath, 'file'),
    resolve(h.policyPath),
  )
  assert.deepEqual(Object.keys(loaded).toSorted(), ['control_root', 'isRevoked', 'policy'])
})

test('legacy revocation binding is accepted only when detection was absent from the stored policy', async (t) => {
  const h = await harness(t)
  const explicitPolicy = {
    ...policyInput(),
    detection: {
      noise_profile: 'AUTO',
      target_environment: 'UNKNOWN',
      risk_tolerance: 'UNSPECIFIED',
      confirmation_mode: 'REQUIRED',
    },
  }
  await writeFile(h.policyPath, stableJson(explicitPolicy), 'utf8')

  await assert.rejects(
    () => loadUnleashControllerPolicy({ controlRoot: h.controlRoot }),
    (error) => error.code === 'UNLEASH_REVOCATION_STATE_INVALID',
  )

  await writeFile(h.revocationsPath, stableJson(revocations(
    [],
    '2026-09-15T09:15:00.000Z',
    1,
    { policy_sha256: digestUnleashValue(explicitPolicy) },
  )), 'utf8')
  const loaded = await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  assert.deepEqual(loaded.policy.detection, explicitPolicy.detection)
})

test('re-reads revocation state for every admission and observes withdrawal', async (t) => {
  const h = await harness(t)
  const loaded = await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })

  assert.equal(loaded.isRevoked(checkRequest()), false)
  await writeFile(h.revocationsPath, stableJson(revocations(
    ['policy:loader-test'],
    '2026-09-15T09:16:00.000Z',
    2,
  )), 'utf8')
  assert.equal(loaded.isRevoked(checkRequest()), true)
})

test('revocation state is monotonic and a withdrawn policy cannot be restored after restart', async (t) => {
  const h = await harness(t)
  const loaded = await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  assert.equal(loaded.isRevoked(checkRequest()), false)

  await writeFile(h.revocationsPath, stableJson(revocations(
    ['policy:loader-test'],
    '2026-09-15T09:16:00.000Z',
    2,
  )), 'utf8')
  assert.equal(loaded.isRevoked(checkRequest()), true)

  await writeFile(h.revocationsPath, stableJson(revocations(
    [],
    '2026-09-15T09:17:00.000Z',
    3,
  )), 'utf8')
  assert.equal(loaded.isRevoked(checkRequest()), true)

  const fresh = await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  assert.equal(fresh.isRevoked(checkRequest()), true)

  await writeFile(h.revocationsPath, stableJson(revocations(
    [],
    '2026-09-15T09:16:30.000Z',
    2,
  )), 'utf8')
  assert.throws(() => fresh.isRevoked(checkRequest()))
  await assert.rejects(() => loadUnleashControllerPolicy({ controlRoot: h.controlRoot }))
})

test('revocation tombstones survive a policy digest rotation with the same policy identity', async (t) => {
  const h = await harness(t)
  const loaded = await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  await writeFile(h.revocationsPath, stableJson(revocations(
    ['policy:loader-test'],
    '2026-09-15T09:16:00.000Z',
    2,
  )), 'utf8')
  assert.equal(loaded.isRevoked(checkRequest()), true)

  const rotatedPolicy = policyInput()
  rotatedPolicy.budgets.max_actions = 3
  await writeFile(h.policyPath, stableJson(rotatedPolicy), 'utf8')
  await writeFile(h.revocationsPath, stableJson(revocations(
    [],
    '2026-09-15T09:17:00.000Z',
    1,
    { policy_sha256: digestUnleashValue(rotatedPolicy) },
  )), 'utf8')

  const fresh = await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  assert.equal(fresh.isRevoked(checkRequest()), true)
  const durable = JSON.parse(await readFile(h.highWaterPath, 'utf8'))
  assert.equal(durable.entries.length, 2)
  assert.ok(durable.entries.every(({ revoked_policy_ids: ids }) => ids.includes('policy:loader-test')))
})

test('binds every revocation snapshot to the exact policy digest and a positive generation', async (t) => {
  const h = await harness(t)
  await writeFile(h.revocationsPath, stableJson(revocations(
    [],
    '2026-09-15T09:15:00.000Z',
    1,
    { policy_sha256: '0'.repeat(64) },
  )), 'utf8')
  await assert.rejects(() => loadUnleashControllerPolicy({ controlRoot: h.controlRoot }))

  await writeFile(h.revocationsPath, stableJson(revocations(
    [],
    '2026-09-15T09:15:00.000Z',
    0,
  )), 'utf8')
  await assert.rejects(() => loadUnleashControllerPolicy({ controlRoot: h.controlRoot }))
})

test('rejects same-generation mutation and preserves the durable high-water mark', async (t) => {
  const h = await harness(t)
  const loaded = await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })

  await writeFile(h.revocationsPath, stableJson(revocations(
    [],
    '2026-09-15T09:15:01.000Z',
    1,
  )), 'utf8')
  assert.throws(() => loaded.isRevoked(checkRequest()))

  await writeFile(h.revocationsPath, stableJson(revocations(
    [],
    '2026-09-15T09:15:00.000Z',
    2,
  )), 'utf8')
  assert.throws(() => loaded.isRevoked(checkRequest()))

  const durable = JSON.parse(await readFile(h.highWaterPath, 'utf8'))
  assert.equal(durable.kind, 'last-aperture/unleash-revocation-high-water')
  assert.equal(durable.entries[0].high_generation, 1)
  assert.equal(durable.entries[0].policy_sha256, digestUnleashValue(policyInput()))
})

test('fails closed for missing, malformed, mismatched, or oversized controller state', async (t) => {
  const h = await harness(t)
  const loaded = await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })

  await writeFile(h.revocationsPath, '{', 'utf8')
  assert.throws(() => loaded.isRevoked(checkRequest()))

  await writeFile(h.revocationsPath, stableJson({ ...revocations(), check_id: 'revocation:other' }), 'utf8')
  assert.throws(() => loaded.isRevoked(checkRequest()))

  await writeFile(h.revocationsPath, ' '.repeat(65 * 1024), 'utf8')
  assert.throws(() => loaded.isRevoked(checkRequest()))

  await rm(h.revocationsPath)
  assert.throws(() => loaded.isRevoked(checkRequest()))
})

test('rejects malformed policy state and unsafe aliases before returning authority', async (t) => {
  const h = await harness(t)
  await writeFile(h.policyPath, stableJson({ ...policyInput(), unknown: true }), 'utf8')
  await assert.rejects(() => loadUnleashControllerPolicy({ controlRoot: h.controlRoot }))

  await writeFile(h.policyPath, ' '.repeat(65 * 1024), 'utf8')
  await assert.rejects(() => loadUnleashControllerPolicy({ controlRoot: h.controlRoot }))

  await writeFile(h.policyPath, stableJson(policyInput()), 'utf8')
  await link(h.policyPath, join(h.controlRoot, 'deployment-policy-hardlink.json'))
  await assert.rejects(() => loadUnleashControllerPolicy({ controlRoot: h.controlRoot }))
})

test('requires private owner-only POSIX modes for the controller root and authority files', {
  skip: process.platform === 'win32',
}, async (t) => {
  const h = await harness(t)
  await chmod(h.policyPath, 0o644)
  await assert.rejects(() => loadUnleashControllerPolicy({ controlRoot: h.controlRoot }))

  await chmod(h.policyPath, 0o600)
  await chmod(h.controlRoot, 0o755)
  await assert.rejects(() => loadUnleashControllerPolicy({ controlRoot: h.controlRoot }))
})

test('creates its durable revocation state as one private regular file', async (t) => {
  const h = await harness(t)
  await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  const metadata = await lstat(h.highWaterPath)
  assert.equal(metadata.isFile(), true)
  assert.equal(metadata.isSymbolicLink(), false)
  assert.equal(metadata.nlink, 1)
  if (process.platform !== 'win32') assert.equal(metadata.mode & 0o077, 0)
})

test('fails closed for malformed durable state or a pre-existing durability lock', async (t) => {
  await t.test('malformed high-water state', async (t) => {
    const h = await harness(t)
    await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
    await writeFile(h.highWaterPath, '{', 'utf8')
    await assert.rejects(() => loadUnleashControllerPolicy({ controlRoot: h.controlRoot }))
  })

  await t.test('pre-existing high-water lock', async (t) => {
    const h = await harness(t)
    await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
    await writeFile(join(h.controlRoot, '.revocation-high-water.lock'), 'lock\n', {
      encoding: 'utf8',
      flag: 'wx',
      mode: 0o600,
    })
    await assert.rejects(() => loadUnleashControllerPolicy({ controlRoot: h.controlRoot }))
  })
})

test('reclaims a complete identity-bound revocation lock left by a crashed child process', async (t) => {
  const h = await harness(t)
  await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  const script = String.raw`
    const { closeSync, fsyncSync, linkSync, openSync, writeSync } = require('node:fs')
    const { join } = require('node:path')
    const root = process.argv[1]
    const nonce = 'a'.repeat(32)
    const owner = {
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-revocation-high-water-lock',
      pid: process.pid,
      acquired_at: new Date().toISOString(),
      nonce,
    }
    const temporary = join(root, '.revocation-high-water.lock.tmp-' + process.pid + '-' + nonce)
    const lock = join(root, '.revocation-high-water.lock')
    const bytes = Buffer.from(JSON.stringify(owner, null, 2) + '\n')
    const descriptor = openSync(temporary, 'wx', 0o600)
    writeSync(descriptor, bytes)
    fsyncSync(descriptor)
    closeSync(descriptor)
    if (process.argv[2] !== 'orphan') linkSync(temporary, lock)
  `
  const child = spawnSync(process.execPath, ['-e', script, h.controlRoot], {
    encoding: 'utf8',
    windowsHide: true,
  })
  assert.equal(child.status, 0, child.stderr)

  const loaded = await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  assert.equal(loaded.isRevoked(checkRequest()), false)
  assert.deepEqual(
    (await readdir(h.controlRoot)).filter((name) => name.startsWith('.revocation-high-water.lock')),
    [],
  )

  const orphan = spawnSync(process.execPath, ['-e', script, h.controlRoot, 'orphan'], {
    encoding: 'utf8',
    windowsHide: true,
  })
  assert.equal(orphan.status, 0, orphan.stderr)
  await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  assert.deepEqual(
    (await readdir(h.controlRoot)).filter((name) => name.startsWith('.revocation-high-water.lock')),
    [],
  )
})

test('recovers complete staged high-water state and discards a private truncated crash residue', async (t) => {
  const h = await harness(t)
  await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  const nextRevocations = revocations(
    ['policy:loader-test'],
    '2026-09-15T09:16:00.000Z',
    2,
  )
  const stored = JSON.parse(await readFile(h.highWaterPath, 'utf8'))
  stored.entries[0] = {
    ...stored.entries[0],
    high_generation: 2,
    high_updated_at: nextRevocations.updated_at,
    snapshot_sha256: digestUnleashValue(nextRevocations),
    revoked_policy_ids: ['policy:loader-test'],
  }
  await writeFile(h.revocationsPath, stableJson(nextRevocations), 'utf8')
  const temporaryPath = join(h.controlRoot, '.revocation-high-water.tmp')
  const writer = String.raw`
    const { closeSync, fsyncSync, openSync, writeSync } = require('node:fs')
    const path = process.argv[1]
    const bytes = Buffer.from(process.argv[2], 'utf8')
    const descriptor = openSync(path, 'wx', 0o600)
    writeSync(descriptor, bytes)
    fsyncSync(descriptor)
    closeSync(descriptor)
  `
  const complete = spawnSync(
    process.execPath,
    ['-e', writer, temporaryPath, stableJson(stored)],
    { encoding: 'utf8', windowsHide: true },
  )
  assert.equal(complete.status, 0, complete.stderr)

  const recovered = await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  assert.equal(recovered.isRevoked(checkRequest()), true)
  assert.equal((await readdir(h.controlRoot)).includes('.revocation-high-water.tmp'), false)

  await writeFile(temporaryPath, '{', { encoding: 'utf8', flag: 'wx', mode: 0o600 })
  const afterTruncation = await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  assert.equal(afterTruncation.isRevoked(checkRequest()), true)
  assert.equal((await readdir(h.controlRoot)).includes('.revocation-high-water.tmp'), false)
})

test('rejects a Windows authority ACL that grants Everyone write access', {
  skip: process.platform !== 'win32',
}, async (t) => {
  const h = await harness(t)
  await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  const systemRoot = process.env.SystemRoot
  assert.equal(typeof systemRoot, 'string')
  const icacls = win32.join(systemRoot, 'System32', 'icacls.exe')
  const changed = spawnSync(icacls, [h.revocationsPath, '/grant', '*S-1-1-0:(W)'], {
    encoding: 'utf8',
    windowsHide: true,
  })
  assert.equal(changed.status, 0, changed.stderr)
  await assert.rejects(() => loadUnleashControllerPolicy({ controlRoot: h.controlRoot }))
})

test('rejects a Windows controller-root ACL that grants Everyone write access', {
  skip: process.platform !== 'win32',
}, async (t) => {
  const h = await harness(t)
  await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  const systemRoot = process.env.SystemRoot
  assert.equal(typeof systemRoot, 'string')
  const icacls = win32.join(systemRoot, 'System32', 'icacls.exe')
  const changed = spawnSync(icacls, [h.controlRoot, '/grant', '*S-1-1-0:(W)'], {
    encoding: 'utf8',
    windowsHide: true,
  })
  assert.equal(changed.status, 0, changed.stderr)
  await assert.rejects(() => loadUnleashControllerPolicy({ controlRoot: h.controlRoot }))
})

test('accepts an inherit-only Windows CREATOR OWNER ACE', {
  skip: process.platform !== 'win32',
}, async (t) => {
  const h = await harness(t)
  const systemRoot = process.env.SystemRoot
  assert.equal(typeof systemRoot, 'string')
  const icacls = win32.join(systemRoot, 'System32', 'icacls.exe')
  const changed = spawnSync(icacls, [
    h.controlRoot,
    '/grant',
    '*S-1-3-0:(OI)(CI)(IO)(F)',
  ], {
    encoding: 'utf8',
    windowsHide: true,
  })
  assert.equal(changed.status, 0, changed.stderr)
  const loaded = await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  assert.equal(loaded.isRevoked(checkRequest()), false)
})

test('revocation checker rejects caller-shaped requests that do not match loaded policy', async (t) => {
  const h = await harness(t)
  const loaded = await loadUnleashControllerPolicy({ controlRoot: h.controlRoot })
  for (const request of [
    null,
    {},
    checkRequest({ check_id: 'revocation:other' }),
    checkRequest({ policy_id: 'policy:other' }),
    { ...checkRequest(), extra: true },
  ]) assert.throws(() => loaded.isRevoked(request))
})
