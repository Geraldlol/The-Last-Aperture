import assert from 'node:assert/strict'
import {
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  rmdir,
  unlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'

import {
  acquireUnleashSwarmOwner,
  assertUnleashSwarmOwner,
  bindUnleashSwarmOwnerStorage,
  inspectUnleashSwarmOwner,
  releaseUnleashSwarmOwner,
} from '../scripts/lib/unleash-swarm-owner.mjs'

const CAMPAIGN_ID = `campaign:sha256:${'a'.repeat(64)}`
const PLAN_SHA256 = 'b'.repeat(64)
const DEAD_PID = 2_000_000_000
const DEAD_RETIRER_PID = 1_999_999_999
const fixtureRoots = new WeakMap()

async function fixture(t) {
  const root = resolve(await mkdtemp(join(tmpdir(), 'last-aperture-swarm-owner-')))
  const campaignDirectory = join(root, `campaign-${'c'.repeat(24)}`)
  await mkdir(campaignDirectory, { mode: 0o700 })
  t.after(async () => rm(root, { recursive: true, force: true }))
  const input = {
    campaignDirectory,
    campaignId: CAMPAIGN_ID,
    planSha256: PLAN_SHA256,
  }
  fixtureRoots.set(input, root)
  return input
}

function linuxDependencies(overrides = {}) {
  return {
    directorySyncImpl: async () => {},
    publicationPlatform: 'linux',
    ...overrides,
  }
}

function sameIdentity(left, right) {
  return left.dev === right.dev && left.ino === right.ino
}

async function lockEntries(input) {
  return readdir(join(input.campaignDirectory, 'swarm-owner-lock'))
}

async function assertMissing(path) {
  await assert.rejects(lstat(path), (cause) => cause?.code === 'ENOENT')
}

function deferred() {
  let resolvePromise
  const promise = new Promise((resolve) => { resolvePromise = resolve })
  return { promise, resolve: resolvePromise }
}

test('a pre-existing empty stable container cannot be replaced by concurrent POSIX claimers', async (t) => {
  const input = await fixture(t)
  const lock = join(input.campaignDirectory, 'swarm-owner-lock')
  await mkdir(lock, { mode: 0o700 })
  const before = await lstat(lock, { bigint: true })

  const outcomes = await Promise.all([
    acquireUnleashSwarmOwner(input, linuxDependencies()),
    acquireUnleashSwarmOwner(input, linuxDependencies()),
  ])
  assert.deepEqual(outcomes.map(({ state }) => state).sort(), ['ACQUIRED', 'BUSY'])
  const acquired = outcomes.find(({ state }) => state === 'ACQUIRED')
  const busy = outcomes.find(({ state }) => state === 'BUSY')
  assert.equal(busy.owner.owner_id, acquired.owner.owner_id)
  assert.equal(sameIdentity(before, await lstat(lock, { bigint: true })), true)
  assert.deepEqual(await lockEntries(input), ['owner.json'])
  assert.equal(await assertUnleashSwarmOwner(acquired.owner), true)

  await releaseUnleashSwarmOwner(acquired.owner)
  assert.equal(sameIdentity(before, await lstat(lock, { bigint: true })), true)
  assert.deepEqual(await lockEntries(input), [])
  assert.deepEqual(await inspectUnleashSwarmOwner(input), { state: 'AVAILABLE', owner: null })
})

test('the Win32 claim requests a no-replace durable move', async (t) => {
  const input = await fixture(t)
  const replaceValues = []
  const acquired = await acquireUnleashSwarmOwner(input, {
    publicationPlatform: 'win32',
    win32MoveImpl: async (source, destination, replace) => {
      replaceValues.push(replace)
      assert.equal(replace, false)
      await link(source, destination)
      await unlink(source)
    },
  })
  assert.equal(acquired.state, 'ACQUIRED')
  assert.deepEqual(replaceValues, [false])
  await releaseUnleashSwarmOwner(acquired.owner)
})

test('a live POSIX claim publication tail is BUSY until its publisher completes', async (t) => {
  const input = await fixture(t)
  let visibleResolve
  let continueResolve
  const visible = new Promise((resolvePromise) => { visibleResolve = resolvePromise })
  const continuePublication = new Promise((resolvePromise) => { continueResolve = resolvePromise })
  const publishing = acquireUnleashSwarmOwner(input, linuxDependencies({
    faultInjector: async (phase) => {
      if (phase !== 'after-owner-claim-visible') return
      visibleResolve()
      await continuePublication
    },
  }))

  await visible
  try {
    const contender = await acquireUnleashSwarmOwner(input, linuxDependencies())
    assert.equal(contender.state, 'BUSY')
    assert.equal((await lstat(join(input.campaignDirectory, 'swarm-owner-lock', 'owner.json'), {
      bigint: true,
    })).nlink, 2n)
  } finally {
    continueResolve()
  }
  const acquired = await publishing
  assert.equal(acquired.state, 'ACQUIRED')
  assert.equal((await lstat(join(input.campaignDirectory, 'swarm-owner-lock', 'owner.json'), {
    bigint: true,
  })).nlink, 1n)
  await releaseUnleashSwarmOwner(acquired.owner)
})

test('startup removes an exact dead pre-publication stage while status stays read-only', async (t) => {
  const input = await fixture(t)
  const simulatedCrash = new Error('simulated process loss after durable staging')
  await assert.rejects(
    acquireUnleashSwarmOwner(input, linuxDependencies({
      faultInjector: (phase) => {
        if (phase === 'after-owner-stage-durable') throw simulatedCrash
      },
      pid: DEAD_PID,
      processIsAlive: () => false,
    })),
    (cause) => cause === simulatedCrash,
  )
  const residues = (await readdir(input.campaignDirectory))
    .filter((name) => name.startsWith('swarm-owner-stage-'))
  assert.equal(residues.length, 1)
  const residue = join(input.campaignDirectory, residues[0])
  assert.equal((await lstat(residue, { bigint: true })).nlink, 1n)

  assert.deepEqual(
    await inspectUnleashSwarmOwner(input, { processIsAlive: () => false }),
    { state: 'AVAILABLE', owner: null },
  )
  await lstat(residue)

  const acquired = await acquireUnleashSwarmOwner(input, linuxDependencies({
    processIsAlive: (pid) => pid !== DEAD_PID,
  }))
  assert.equal(acquired.state, 'ACQUIRED')
  await assertMissing(residue)
  await releaseUnleashSwarmOwner(acquired.owner)
})

test('acquire recovers only the exact dead two-link POSIX publication tail', async (t) => {
  const input = await fixture(t)
  const simulatedCrash = new Error('simulated process loss after create-only link')
  let temporary
  let ownerPath
  let ownerBytes
  const reconciled = await acquireUnleashSwarmOwner(input, linuxDependencies({
    faultInjector: async (phase, details) => {
      if (phase === 'after-owner-claim-visible') {
        temporary = details.temporary
        ownerPath = details.destination
        ownerBytes = await readFile(details.temporary)
        throw simulatedCrash
      }
    },
    pid: DEAD_PID,
    processIsAlive: () => false,
  }))
  assert.equal(reconciled.state, 'ACQUIRED')
  await assertMissing(temporary)
  assert.equal((await lstat(ownerPath, { bigint: true })).nlink, 1n)
  await releaseUnleashSwarmOwner(reconciled.owner)

  await writeFile(temporary, ownerBytes, { flag: 'wx', mode: 0o600 })
  await link(temporary, ownerPath)
  const temporaryBefore = await lstat(temporary, { bigint: true })
  const ownerBefore = await lstat(ownerPath, { bigint: true })
  assert.equal(temporaryBefore.nlink, 2n)
  assert.equal(ownerBefore.nlink, 2n)
  assert.equal(sameIdentity(temporaryBefore, ownerBefore), true)

  assert.equal((await inspectUnleashSwarmOwner(input, {
    processIsAlive: () => false,
  })).state, 'STALE')
  assert.equal((await lstat(temporary, { bigint: true })).nlink, 2n)

  const replacement = await acquireUnleashSwarmOwner(input, linuxDependencies({
    processIsAlive: (pid) => pid !== DEAD_PID,
  }))
  assert.equal(replacement.state, 'ACQUIRED')
  await assertMissing(temporary)
  assert.equal((await lstat(ownerPath, { bigint: true })).nlink, 1n)
  await releaseUnleashSwarmOwner(replacement.owner)
})

test('acquire reconciles its exact nlink1 claim after the second publication sync fails', async (t) => {
  const input = await fixture(t)
  const simulatedSyncFailure = new Error('simulated second publication directory sync failure')
  let syncCalls = 0
  const acquired = await acquireUnleashSwarmOwner(input, linuxDependencies({
    directorySyncImpl: async () => {
      syncCalls += 1
      if (syncCalls === 2) throw simulatedSyncFailure
    },
  }))

  assert.equal(acquired.state, 'ACQUIRED')
  assert.equal(syncCalls, 3)
  assert.deepEqual(
    (await readdir(input.campaignDirectory))
      .filter((name) => name.startsWith('swarm-owner-stage-')),
    [],
  )
  assert.equal((await lstat(join(
    input.campaignDirectory,
    'swarm-owner-lock',
    'owner.json',
  ), { bigint: true })).nlink, 1n)
  await releaseUnleashSwarmOwner(acquired.owner)
})

test('obstructed owner publication withdrawal never removes a successor', async (t) => {
  const input = await fixture(t)
  const obstruction = join(
    input.campaignDirectory,
    'swarm-owner-lock',
    'unexpected-obstruction',
  )
  const simulatedFailure = new Error('simulated owner publication failure behind obstruction')
  let successor
  await assert.rejects(
    acquireUnleashSwarmOwner(input, linuxDependencies({
      faultInjector: async (phase) => {
        if (phase === 'after-owner-claim-visible') {
          await writeFile(obstruction, 'obstructed\n', { flag: 'wx', mode: 0o600 })
          throw simulatedFailure
        }
        if (phase === 'after-owner-claim-withdrawn') {
          await unlink(obstruction)
          successor = await acquireUnleashSwarmOwner(input, linuxDependencies())
        }
      },
    })),
    { code: 'UNLEASH_SWARM_OWNER_CLAIM_FAILED' },
  )

  assert.equal(successor.state, 'ACQUIRED')
  assert.equal(await assertUnleashSwarmOwner(successor.owner), true)
  assert.deepEqual(
    (await readdir(input.campaignDirectory))
      .filter((name) => name.startsWith('swarm-owner-stage-')),
    [],
  )
  assert.deepEqual(await lockEntries(input), ['owner.json'])
  await releaseUnleashSwarmOwner(successor.owner)
})

test('an obstructed ambiguous Win32 owner move is withdrawn without a token', async (t) => {
  const input = await fixture(t)
  const obstruction = join(
    input.campaignDirectory,
    'swarm-owner-lock',
    'unexpected-obstruction',
  )
  const simulatedFailure = new Error('simulated ambiguous committed owner move')
  let successor
  await assert.rejects(
    acquireUnleashSwarmOwner(input, {
      publicationPlatform: 'win32',
      win32MoveImpl: async (source, destination, replace) => {
        assert.equal(replace, false)
        await link(source, destination)
        await unlink(source)
        await writeFile(obstruction, 'obstructed\n', { flag: 'wx', mode: 0o600 })
        throw simulatedFailure
      },
      faultInjector: async (phase) => {
        if (phase !== 'after-owner-claim-withdrawn') return
        await unlink(obstruction)
        successor = await acquireUnleashSwarmOwner(input, linuxDependencies())
      },
    }),
    { code: 'UNLEASH_SWARM_OWNER_CLAIM_FAILED' },
  )

  assert.equal(successor.state, 'ACQUIRED')
  assert.equal(await assertUnleashSwarmOwner(successor.owner), true)
  assert.deepEqual(
    (await readdir(input.campaignDirectory))
      .filter((name) => name.startsWith('swarm-owner-stage-')),
    [],
  )
  assert.deepEqual(await lockEntries(input), ['owner.json'])
  await releaseUnleashSwarmOwner(successor.owner)
})

test('acquire recovers an exact dead two-link retirement publication tail without helping its owner unlink', async (t) => {
  const input = await fixture(t)
  const stale = await acquireUnleashSwarmOwner(input, linuxDependencies({
    pid: DEAD_PID,
    processIsAlive: () => false,
  }))
  assert.equal(stale.state, 'ACQUIRED')
  const simulatedCrash = new Error('simulated retirement publisher loss after create-only link')
  let residue
  let marker
  let retirementBytes
  await assert.rejects(
    acquireUnleashSwarmOwner(input, linuxDependencies({
      faultInjector: async (phase, details) => {
        if (phase === 'after-owner-retirement-visible') {
          residue = details.temporary
          marker = details.destination
          retirementBytes = await readFile(details.temporary)
          throw simulatedCrash
        }
      },
      pid: DEAD_RETIRER_PID,
      processIsAlive: () => false,
    })),
    (cause) => cause === simulatedCrash,
  )
  await assertMissing(residue)
  await assertMissing(marker)

  await writeFile(residue, retirementBytes, { flag: 'wx', mode: 0o600 })
  await link(residue, marker)
  const residueInfo = await lstat(residue, { bigint: true })
  const markerInfo = await lstat(marker, { bigint: true })
  assert.equal(residueInfo.nlink, 2n)
  assert.equal(sameIdentity(residueInfo, markerInfo), true)
  assert.equal((await lockEntries(input)).includes('owner.json'), true)

  const replacement = await acquireUnleashSwarmOwner(input, linuxDependencies({
    processIsAlive: (pid) => ![DEAD_PID, DEAD_RETIRER_PID].includes(pid),
  }))
  assert.equal(replacement.state, 'ACQUIRED')
  await assertMissing(residue)
  await assertMissing(marker)
  assert.equal(await assertUnleashSwarmOwner(replacement.owner), true)
  await releaseUnleashSwarmOwner(replacement.owner)
})

test('a live same-process stale reclaimer cleans its failed transition before retry', async (t) => {
  const input = await fixture(t)
  const stale = await acquireUnleashSwarmOwner(input, linuxDependencies({
    pid: DEAD_PID,
    processIsAlive: () => false,
  }))
  assert.equal(stale.state, 'ACQUIRED')

  const simulatedFailure = new Error('simulated stale-owner retirement publication failure')
  let failOnce = true
  const reclaimerDependencies = linuxDependencies({
    processIsAlive: (pid) => pid !== DEAD_PID,
    faultInjector: (phase) => {
      if (phase !== 'after-owner-retirement-visible' || !failOnce) return
      failOnce = false
      throw simulatedFailure
    },
  })
  await assert.rejects(
    acquireUnleashSwarmOwner(input, reclaimerDependencies),
    (cause) => cause === simulatedFailure,
  )
  assert.deepEqual(await lockEntries(input), ['owner.json'])
  assert.equal(
    (await readdir(input.campaignDirectory))
      .some((name) => name.startsWith('swarm-owner-release-')),
    false,
  )

  const replacement = await acquireUnleashSwarmOwner(input, reclaimerDependencies)
  assert.equal(replacement.state, 'ACQUIRED')
  assert.deepEqual(await lockEntries(input), ['owner.json'])
  await releaseUnleashSwarmOwner(replacement.owner)
})

test('retirement resumes safely before and after the owner claim is unlinked', async (t) => {
  for (const phase of ['after-owner-retirement-linked', 'after-owner-claim-retired']) {
    await t.test(phase, async (child) => {
      const input = await fixture(child)
      const abandoned = await acquireUnleashSwarmOwner(input, linuxDependencies({
        pid: DEAD_PID,
        processIsAlive: () => false,
      }))
      assert.equal(abandoned.state, 'ACQUIRED')
      const simulatedCrash = new Error(`simulated process loss at ${phase}`)
      let crashedMarker
      let crashedMarkerBytes
      await assert.rejects(
        acquireUnleashSwarmOwner(input, linuxDependencies({
          faultInjector: async (observed, details) => {
            if (observed === phase) {
              crashedMarker = details.marker
              crashedMarkerBytes = await readFile(details.marker)
              throw simulatedCrash
            }
          },
          pid: DEAD_RETIRER_PID,
          processIsAlive: () => false,
        })),
        (cause) => cause === simulatedCrash,
      )

      await writeFile(crashedMarker, crashedMarkerBytes, { flag: 'wx', mode: 0o600 })

      const entries = await lockEntries(input)
      const marker = entries.find((name) => name.startsWith('retiring-'))
      assert.equal(typeof marker, 'string')
      assert.equal(entries.includes('owner.json'), phase === 'after-owner-retirement-linked')
      assert.equal((await inspectUnleashSwarmOwner(input, {
        processIsAlive: () => false,
      })).state, 'STALE')

      const replacement = await acquireUnleashSwarmOwner(input, linuxDependencies({
        processIsAlive: (pid) => ![DEAD_PID, DEAD_RETIRER_PID].includes(pid),
      }))
      assert.equal(replacement.state, 'ACQUIRED')
      assert.deepEqual(await lockEntries(input), ['owner.json'])
      await releaseUnleashSwarmOwner(replacement.owner)
    })
  }
})

test('concurrent stale reclaimers preserve the one successor claim', async (t) => {
  const input = await fixture(t)
  const stale = await acquireUnleashSwarmOwner(input, linuxDependencies({
    pid: DEAD_PID,
    processIsAlive: () => false,
  }))
  assert.equal(stale.state, 'ACQUIRED')

  const outcomes = await Promise.all(Array.from({ length: 4 }, () => (
    acquireUnleashSwarmOwner(input, linuxDependencies({
      processIsAlive: (pid) => pid !== DEAD_PID,
    }))
  )))
  assert.equal(outcomes.filter(({ state }) => state === 'ACQUIRED').length, 1)
  assert.equal(outcomes.filter(({ state }) => state === 'BUSY').length, 3)
  const acquired = outcomes.find(({ state }) => state === 'ACQUIRED')
  assert.ok(outcomes.filter(({ state }) => state === 'BUSY')
    .every(({ owner }) => typeof owner.owner_id === 'string'))
  assert.equal(await assertUnleashSwarmOwner(acquired.owner), true)
  await assert.rejects(
    releaseUnleashSwarmOwner(stale.owner),
    { code: 'UNLEASH_SWARM_OWNER_SUPERSEDED' },
  )
  assert.equal(await assertUnleashSwarmOwner(acquired.owner), true)
  await releaseUnleashSwarmOwner(acquired.owner)
})

test('a stale pre-transition snapshot cannot retire a successor', async (t) => {
  const input = await fixture(t)
  const stale = await acquireUnleashSwarmOwner(input, linuxDependencies({
    pid: DEAD_PID,
    processIsAlive: () => false,
  }))
  assert.equal(stale.state, 'ACQUIRED')
  const beforeLink = deferred()
  const resumeLink = deferred()
  let paused = false
  const staleReclaimer = acquireUnleashSwarmOwner(input, linuxDependencies({
    faultInjector: async (phase) => {
      if (phase !== 'before-owner-retirement-link' || paused) return
      paused = true
      beforeLink.resolve()
      await resumeLink.promise
    },
    pid: 101_001,
    processIsAlive: (pid) => pid !== DEAD_PID,
  }))
  await beforeLink.promise

  const successor = await acquireUnleashSwarmOwner(input, linuxDependencies({
    pid: 101_002,
    processIsAlive: (pid) => pid !== DEAD_PID,
  }))
  assert.equal(successor.state, 'ACQUIRED')
  const successorPath = join(input.campaignDirectory, 'swarm-owner-lock', 'owner.json')
  const successorInfo = await lstat(successorPath, { bigint: true })
  resumeLink.resolve()

  const staleOutcome = await staleReclaimer
  assert.equal(staleOutcome.state, 'BUSY')
  assert.equal(staleOutcome.owner.owner_id, successor.owner.owner_id)
  assert.equal(sameIdentity(successorInfo, await lstat(successorPath, { bigint: true })), true)
  assert.deepEqual(await lockEntries(input), ['owner.json'])
  assert.equal(await assertUnleashSwarmOwner(successor.owner), true)
  await releaseUnleashSwarmOwner(successor.owner)
})

test('two validated retirement barriers drain before a successor can publish', async (t) => {
  const input = await fixture(t)
  const stale = await acquireUnleashSwarmOwner(input, linuxDependencies({
    pid: DEAD_PID,
    processIsAlive: () => false,
  }))
  assert.equal(stale.state, 'ACQUIRED')

  const beforeLinkReady = deferred()
  const resumeBeforeLink = deferred()
  const linkedReady = deferred()
  const resumeLinked = deferred()
  const beforeUnlinkA = deferred()
  const beforeUnlinkB = deferred()
  const resumeUnlinkA = deferred()
  const resumeUnlinkB = deferred()
  const ownerUnlinkedByB = deferred()
  const resumeBarrierRemovalB = deferred()
  let beforeLinkCount = 0
  let linkedCount = 0

  function reclaimerDependencies(label, pid) {
    let firstBeforeLink = true
    let firstLinked = true
    let firstBeforeUnlink = true
    let firstAfterUnlink = true
    return linuxDependencies({
      faultInjector: async (phase) => {
        if (phase === 'before-owner-retirement-link' && firstBeforeLink) {
          firstBeforeLink = false
          beforeLinkCount += 1
          if (beforeLinkCount === 2) beforeLinkReady.resolve()
          await resumeBeforeLink.promise
        }
        if (phase === 'after-owner-retirement-linked' && firstLinked) {
          firstLinked = false
          linkedCount += 1
          if (linkedCount === 2) linkedReady.resolve()
          await resumeLinked.promise
        }
        if (phase === 'before-owner-claim-retired' && firstBeforeUnlink) {
          firstBeforeUnlink = false
          ;(label === 'A' ? beforeUnlinkA : beforeUnlinkB).resolve()
          await (label === 'A' ? resumeUnlinkA : resumeUnlinkB).promise
        }
        if (label === 'B' && phase === 'after-owner-claim-retired' && firstAfterUnlink) {
          firstAfterUnlink = false
          ownerUnlinkedByB.resolve()
          await resumeBarrierRemovalB.promise
        }
      },
      pid,
      processIsAlive: (observedPid) => observedPid !== DEAD_PID,
    })
  }

  const reclaimerA = acquireUnleashSwarmOwner(input, reclaimerDependencies('A', 102_001))
  const reclaimerB = acquireUnleashSwarmOwner(input, reclaimerDependencies('B', 102_002))
  await beforeLinkReady.promise
  resumeBeforeLink.resolve()
  await linkedReady.promise
  assert.equal((await lockEntries(input)).filter((name) => name.startsWith('retiring-')).length, 2)
  resumeLinked.resolve()
  await Promise.all([beforeUnlinkA.promise, beforeUnlinkB.promise])

  resumeUnlinkB.resolve()
  await ownerUnlinkedByB.promise
  const blockedWithTwo = await acquireUnleashSwarmOwner(input, linuxDependencies({
    processIsAlive: (pid) => pid !== DEAD_PID,
  }))
  assert.equal(blockedWithTwo.state, 'BUSY')
  await assertMissing(join(input.campaignDirectory, 'swarm-owner-lock', 'owner.json'))

  resumeUnlinkA.resolve()
  const outcomeA = await reclaimerA
  assert.equal(outcomeA.state, 'BUSY')
  const blockedWithOne = await acquireUnleashSwarmOwner(input, linuxDependencies({
    processIsAlive: (pid) => pid !== DEAD_PID,
  }))
  assert.equal(blockedWithOne.state, 'BUSY')
  await assertMissing(join(input.campaignDirectory, 'swarm-owner-lock', 'owner.json'))

  resumeBarrierRemovalB.resolve()
  const outcomeB = await reclaimerB
  assert.equal(outcomeB.state, 'ACQUIRED')
  assert.deepEqual(await lockEntries(input), ['owner.json'])
  assert.equal(await assertUnleashSwarmOwner(outcomeB.owner), true)
  await releaseUnleashSwarmOwner(outcomeB.owner)
})

test('retirement admission saturation self-cleans without stranding barriers', async (t) => {
  const input = await fixture(t)
  const stale = await acquireUnleashSwarmOwner(input, linuxDependencies({
    pid: DEAD_PID,
    processIsAlive: () => false,
  }))
  assert.equal(stale.state, 'ACQUIRED')
  const allReady = deferred()
  const resume = deferred()
  let readyCount = 0
  const outcomesPromise = Promise.all(Array.from({ length: 65 }, (_, index) => {
    let first = true
    return acquireUnleashSwarmOwner(input, linuxDependencies({
      faultInjector: async (phase) => {
        if (phase !== 'before-owner-retirement-link' || !first) return
        first = false
        readyCount += 1
        if (readyCount === 65) allReady.resolve()
        await resume.promise
      },
      pid: 103_000 + index,
      processIsAlive: (pid) => pid !== DEAD_PID,
    }))
  }))
  await allReady.promise
  resume.resolve()
  const outcomes = await outcomesPromise
  assert.equal(outcomes.every(({ state }) => ['ACQUIRED', 'BUSY'].includes(state)), true)
  assert.equal(outcomes.filter(({ state }) => state === 'ACQUIRED').length <= 1, true)
  const acquired = outcomes.find(({ state }) => state === 'ACQUIRED')
    ?? await acquireUnleashSwarmOwner(input, linuxDependencies({
      processIsAlive: (pid) => pid !== DEAD_PID,
    }))
  assert.equal(acquired.state, 'ACQUIRED')
  assert.deepEqual(await lockEntries(input), ['owner.json'])
  assert.deepEqual(
    (await readdir(input.campaignDirectory)).filter((name) => name.startsWith('swarm-owner-release-')),
    [],
  )
  assert.equal(await assertUnleashSwarmOwner(acquired.owner), true)
  await releaseUnleashSwarmOwner(acquired.owner)
})

test('release accepts a valid successor published after its unique marker is removed', async (t) => {
  const input = await fixture(t)
  let successor
  const first = await acquireUnleashSwarmOwner(input, linuxDependencies({
    faultInjector: async (phase) => {
      if (phase !== 'after-owner-retirement-removed' || successor !== undefined) return
      successor = await acquireUnleashSwarmOwner(input, linuxDependencies())
    },
  }))
  assert.equal(first.state, 'ACQUIRED')

  await releaseUnleashSwarmOwner(first.owner)
  assert.equal(successor.state, 'ACQUIRED')
  assert.equal(await assertUnleashSwarmOwner(successor.owner), true)
  await releaseUnleashSwarmOwner(successor.owner)
})

test('a pre-unlink release failure removes its transition and retains a retryable token', async (t) => {
  const input = await fixture(t)
  const simulatedFailure = new Error('simulated pre-unlink release failure')
  let failOnce = true
  const acquired = await acquireUnleashSwarmOwner(input, linuxDependencies({
    faultInjector: (phase) => {
      if (phase !== 'after-owner-retirement-linked' || !failOnce) return
      failOnce = false
      throw simulatedFailure
    },
  }))
  await assert.rejects(
    releaseUnleashSwarmOwner(acquired.owner),
    (cause) => cause === simulatedFailure,
  )
  assert.deepEqual(await lockEntries(input), ['owner.json'])
  assert.equal(await assertUnleashSwarmOwner(acquired.owner), true)
  await releaseUnleashSwarmOwner(acquired.owner)
  assert.deepEqual(await lockEntries(input), [])
})

test('a post-unlink release failure clears its barrier and invalidates the spent token', async (t) => {
  const input = await fixture(t)
  const simulatedFailure = new Error('simulated post-unlink release failure')
  let failOnce = true
  const acquired = await acquireUnleashSwarmOwner(input, linuxDependencies({
    faultInjector: (phase) => {
      if (phase !== 'after-owner-claim-retired' || !failOnce) return
      failOnce = false
      throw simulatedFailure
    },
  }))
  await assert.rejects(
    releaseUnleashSwarmOwner(acquired.owner),
    (cause) => cause === simulatedFailure,
  )
  assert.deepEqual(await lockEntries(input), [])
  await assert.rejects(
    releaseUnleashSwarmOwner(acquired.owner),
    { code: 'UNLEASH_SWARM_OWNER_TOKEN_INVALID' },
  )
})

test('a barrier-removal failure remains retryable and blocks contenders', async (t) => {
  const input = await fixture(t)
  const simulatedFailure = new Error('simulated barrier removal failure')
  let failOnce = true
  const acquired = await acquireUnleashSwarmOwner(input, linuxDependencies({
    faultInjector: (phase) => {
      if (phase !== 'before-owner-retirement-removed' || !failOnce) return
      failOnce = false
      throw simulatedFailure
    },
  }))
  await assert.rejects(
    releaseUnleashSwarmOwner(acquired.owner),
    (cause) => cause === simulatedFailure,
  )
  assert.equal((await lockEntries(input)).some((name) => name.startsWith('retiring-')), true)
  await assertMissing(join(input.campaignDirectory, 'swarm-owner-lock', 'owner.json'))
  const contender = await acquireUnleashSwarmOwner(input, linuxDependencies())
  assert.equal(contender.state, 'BUSY')

  await releaseUnleashSwarmOwner(acquired.owner)
  assert.deepEqual(await lockEntries(input), [])
  await assert.rejects(
    assertUnleashSwarmOwner(acquired.owner),
    { code: 'UNLEASH_SWARM_OWNER_TOKEN_INVALID' },
  )
})

test('concurrent releases of one token share one retryable transition', async (t) => {
  const input = await fixture(t)
  const beforeLink = deferred()
  const resumeLink = deferred()
  const simulatedFailure = new Error('simulated shared release transition failure')
  let beforeLinkCount = 0
  let failOnce = true
  const acquired = await acquireUnleashSwarmOwner(input, linuxDependencies({
    faultInjector: async (phase) => {
      if (phase === 'before-owner-retirement-link') {
        beforeLinkCount += 1
        beforeLink.resolve()
        await resumeLink.promise
      }
      if (phase === 'before-owner-retirement-removed' && failOnce) {
        failOnce = false
        throw simulatedFailure
      }
    },
  }))

  const firstRelease = releaseUnleashSwarmOwner(acquired.owner)
  await beforeLink.promise
  const secondRelease = releaseUnleashSwarmOwner(acquired.owner)
  resumeLink.resolve()
  const releases = await Promise.allSettled([firstRelease, secondRelease])
  assert.equal(beforeLinkCount, 1)
  assert.deepEqual(releases.map(({ status }) => status), ['rejected', 'rejected'])
  assert.ok(releases.every(({ reason }) => reason === simulatedFailure))
  assert.equal((await lockEntries(input)).filter((name) => name.startsWith('retiring-')).length, 1)
  const contender = await acquireUnleashSwarmOwner(input, linuxDependencies())
  assert.equal(contender.state, 'BUSY')

  await releaseUnleashSwarmOwner(acquired.owner)
  assert.deepEqual(await lockEntries(input), [])
  await assert.rejects(
    assertUnleashSwarmOwner(acquired.owner),
    { code: 'UNLEASH_SWARM_OWNER_TOKEN_INVALID' },
  )
})

test('the same token resumes its exact live retirement publication tail', async (t) => {
  const input = await fixture(t)
  const simulatedFailure = new Error('simulated same-process retirement publication interruption')
  let failOnce = true
  const acquired = await acquireUnleashSwarmOwner(input, linuxDependencies({
    faultInjector: (phase) => {
      if (phase !== 'after-owner-retirement-visible' || !failOnce) return
      failOnce = false
      throw simulatedFailure
    },
  }))
  await assert.rejects(
    releaseUnleashSwarmOwner(acquired.owner),
    (cause) => cause === simulatedFailure,
  )
  assert.equal((await lockEntries(input)).includes('owner.json'), true)
  assert.equal((await lockEntries(input)).some((name) => name.startsWith('retiring-')), true)
  assert.equal(
    (await readdir(input.campaignDirectory))
      .some((name) => name.startsWith('swarm-owner-release-')),
    true,
  )
  const contender = await acquireUnleashSwarmOwner(input, linuxDependencies())
  assert.equal(contender.state, 'BUSY')

  await releaseUnleashSwarmOwner(acquired.owner)
  assert.deepEqual(await lockEntries(input), [])
  assert.equal(
    (await readdir(input.campaignDirectory))
      .some((name) => name.startsWith('swarm-owner-release-')),
    false,
  )
})

test('a token adopts its visible retirement before catch inspection can be obstructed', async (t) => {
  const input = await fixture(t)
  const obstruction = join(
    input.campaignDirectory,
    'swarm-owner-lock',
    'unexpected-obstruction',
  )
  const simulatedFailure = new Error('simulated visible transition failure behind obstruction')
  let failOnce = true
  const acquired = await acquireUnleashSwarmOwner(input, linuxDependencies({
    faultInjector: async (phase) => {
      if (phase !== 'after-owner-retirement-visible' || !failOnce) return
      failOnce = false
      await writeFile(obstruction, 'obstructed\n', { flag: 'wx', mode: 0o600 })
      throw simulatedFailure
    },
  }))

  await assert.rejects(
    releaseUnleashSwarmOwner(acquired.owner),
    { code: 'UNLEASH_SWARM_OWNER_CHANGED' },
  )
  await unlink(obstruction)
  assert.equal((await lockEntries(input)).includes('owner.json'), true)
  assert.equal((await lockEntries(input)).some((name) => name.startsWith('retiring-')), true)
  assert.equal(
    (await readdir(input.campaignDirectory))
      .some((name) => name.startsWith('swarm-owner-release-')),
    true,
  )
  const contender = await acquireUnleashSwarmOwner(input, linuxDependencies())
  assert.equal(contender.state, 'BUSY')

  await releaseUnleashSwarmOwner(acquired.owner)
  assert.deepEqual(await lockEntries(input), [])
  assert.equal(
    (await readdir(input.campaignDirectory))
      .some((name) => name.startsWith('swarm-owner-release-')),
    false,
  )
})

test('a token adopts a Win32 retirement before an ambiguous committed move rejects', async (t) => {
  const input = await fixture(t)
  const obstruction = join(
    input.campaignDirectory,
    'swarm-owner-lock',
    'unexpected-obstruction',
  )
  const simulatedFailure = new Error('simulated ambiguous Win32 move result')
  let rejectCommittedRetirement = false
  const dependencies = {
    publicationPlatform: 'win32',
    win32MoveImpl: async (source, destination, replace) => {
      assert.equal(replace, false)
      await link(source, destination)
      await unlink(source)
      if (rejectCommittedRetirement) {
        await writeFile(obstruction, 'obstructed\n', { flag: 'wx', mode: 0o600 })
        throw simulatedFailure
      }
    },
  }
  const acquired = await acquireUnleashSwarmOwner(input, dependencies)
  rejectCommittedRetirement = true

  await assert.rejects(
    releaseUnleashSwarmOwner(acquired.owner),
    { code: 'UNLEASH_SWARM_OWNER_CLAIM_FAILED' },
  )
  await unlink(obstruction)
  assert.equal((await lockEntries(input)).includes('owner.json'), true)
  assert.equal((await lockEntries(input)).some((name) => name.startsWith('retiring-')), true)
  assert.equal(
    (await readdir(input.campaignDirectory))
      .some((name) => name.startsWith('swarm-owner-release-')),
    false,
  )
  const contender = await acquireUnleashSwarmOwner(input, linuxDependencies())
  assert.equal(contender.state, 'BUSY')

  rejectCommittedRetirement = false
  await releaseUnleashSwarmOwner(acquired.owner)
  assert.deepEqual(await lockEntries(input), [])
})

test('an adopted published transition remains retryable when immediate cleanup also fails', async (t) => {
  const input = await fixture(t)
  const publishFailure = new Error('simulated post-publication failure')
  const cleanupFailure = new Error('simulated immediate cleanup failure')
  let failPublish = true
  let failCleanup = true
  const acquired = await acquireUnleashSwarmOwner(input, linuxDependencies({
    faultInjector: (phase) => {
      if (phase === 'after-owner-retirement-published' && failPublish) {
        failPublish = false
        throw publishFailure
      }
      if (phase === 'before-owner-retirement-cleanup' && failCleanup) {
        failCleanup = false
        throw cleanupFailure
      }
    },
  }))
  await assert.rejects(
    releaseUnleashSwarmOwner(acquired.owner),
    { code: 'UNLEASH_SWARM_OWNER_CHANGED' },
  )
  assert.equal((await lockEntries(input)).includes('owner.json'), true)
  assert.equal((await lockEntries(input)).some((name) => name.startsWith('retiring-')), true)
  const contender = await acquireUnleashSwarmOwner(input, linuxDependencies())
  assert.equal(contender.state, 'BUSY')

  await releaseUnleashSwarmOwner(acquired.owner)
  assert.deepEqual(await lockEntries(input), [])
})

test('a successor survives an error after the old barrier was removed', async (t) => {
  const input = await fixture(t)
  const simulatedFailure = new Error('simulated post-removal release failure')
  let successor
  const acquired = await acquireUnleashSwarmOwner(input, linuxDependencies({
    faultInjector: async (phase) => {
      if (phase !== 'after-owner-retirement-removed' || successor !== undefined) return
      successor = await acquireUnleashSwarmOwner(input, linuxDependencies())
      throw simulatedFailure
    },
  }))
  await assert.rejects(
    releaseUnleashSwarmOwner(acquired.owner),
    (cause) => cause === simulatedFailure,
  )
  await assert.rejects(
    releaseUnleashSwarmOwner(acquired.owner),
    { code: 'UNLEASH_SWARM_OWNER_TOKEN_INVALID' },
  )
  assert.equal(successor.state, 'ACQUIRED')
  assert.equal(await assertUnleashSwarmOwner(successor.owner), true)
  await releaseUnleashSwarmOwner(successor.owner)
})

test('elapsed wall time never permits takeover from a live campaign owner', async (t) => {
  const input = await fixture(t)
  const first = await acquireUnleashSwarmOwner(input, linuxDependencies({
    now: () => new Date('2026-01-01T00:00:00.000Z'),
  }))
  const delayed = await acquireUnleashSwarmOwner(input, linuxDependencies({
    now: () => new Date('2036-01-01T00:00:00.000Z'),
  }))
  assert.equal(delayed.state, 'BUSY')
  assert.equal(delayed.owner.owner_id, first.owner.owner_id)
  await releaseUnleashSwarmOwner(first.owner)
})

test('owner-bound storage revalidates the exact file claim before every mutation', async (t) => {
  const input = await fixture(t)
  const acquired = await acquireUnleashSwarmOwner(input, linuxDependencies())
  const calls = []
  const storage = {
    runs_root: fixtureRoots.get(input),
    campaign_directory: input.campaignDirectory,
    writeImmutableJson: async (...args) => calls.push(['immutable', ...args]),
    replaceMutableJson: async (...args) => calls.push(['mutable', ...args]),
    readJson: async () => null,
    listJsonFilenames: async () => [],
  }
  const bound = bindUnleashSwarmOwnerStorage(storage, acquired.owner)
  await bound.writeImmutableJson('one.json', { value: 1 })
  await bound.replaceMutableJson('two.json', { value: 2 })
  assert.deepEqual(calls.map(([kind]) => kind), ['immutable', 'mutable'])
  await releaseUnleashSwarmOwner(acquired.owner)
  await assert.rejects(
    bound.writeImmutableJson('three.json', { value: 3 }),
    { code: 'UNLEASH_SWARM_OWNER_TOKEN_INVALID' },
  )
  assert.equal(calls.length, 2)
})

test('a live owner for another plan fails closed instead of appearing available', async (t) => {
  const input = await fixture(t)
  const acquired = await acquireUnleashSwarmOwner(input, linuxDependencies())
  await assert.rejects(
    inspectUnleashSwarmOwner({ ...input, planSha256: 'd'.repeat(64) }),
    { code: 'UNLEASH_SWARM_OWNER_BINDING_MISMATCH' },
  )
  await releaseUnleashSwarmOwner(acquired.owner)
})

test('partial and unexpected stable-container children fail closed untouched', async (t) => {
  await t.test('malformed campaign residue name', async (child) => {
    const input = await fixture(child)
    const malformed = join(input.campaignDirectory, 'swarm-owner-stage-not-a-record')
    await writeFile(malformed, 'retain me')
    await assert.rejects(
      acquireUnleashSwarmOwner(input, linuxDependencies()),
      { code: 'UNLEASH_SWARM_OWNER_RECORD_UNSAFE' },
    )
    assert.equal(await readFile(malformed, 'utf8'), 'retain me')
  })

  await t.test('recognized campaign residue with a partial record', async (child) => {
    const input = await fixture(child)
    const partial = join(
      input.campaignDirectory,
      `swarm-owner-stage-1-${'a'.repeat(24)}`,
    )
    await writeFile(partial, '{"partial":true}\n', { flag: 'wx', mode: 0o600 })
    await assert.rejects(
      acquireUnleashSwarmOwner(input, linuxDependencies()),
      { code: 'UNLEASH_SWARM_OWNER_RECORD_UNSAFE' },
    )
    assert.equal(await readFile(partial, 'utf8'), '{"partial":true}\n')
  })

  await t.test('partial owner record', async (child) => {
    const input = await fixture(child)
    const lock = join(input.campaignDirectory, 'swarm-owner-lock')
    const owner = join(lock, 'owner.json')
    await mkdir(lock, { mode: 0o700 })
    await writeFile(owner, '{"partial":true}\n', { flag: 'wx', mode: 0o600 })
    await assert.rejects(
      acquireUnleashSwarmOwner(input, linuxDependencies()),
      { code: 'UNLEASH_SWARM_OWNER_RECORD_UNSAFE' },
    )
    assert.equal(await readFile(owner, 'utf8'), '{"partial":true}\n')
  })

  await t.test('unexpected child', async (child) => {
    const input = await fixture(child)
    const lock = join(input.campaignDirectory, 'swarm-owner-lock')
    const unexpected = join(lock, 'unexpected')
    await mkdir(lock, { mode: 0o700 })
    await writeFile(unexpected, 'retain me')
    await assert.rejects(
      acquireUnleashSwarmOwner(input, linuxDependencies()),
      { code: 'UNLEASH_SWARM_OWNER_LOCK_UNSAFE' },
    )
    assert.equal(await readFile(unexpected, 'utf8'), 'retain me')
  })

  await t.test('partial retirement marker', async (child) => {
    const input = await fixture(child)
    const lock = join(input.campaignDirectory, 'swarm-owner-lock')
    const marker = join(lock, `retiring-1-${'a'.repeat(24)}.json`)
    await mkdir(lock, { mode: 0o700 })
    await writeFile(marker, '{"partial":true}\n', { flag: 'wx', mode: 0o600 })
    await assert.rejects(
      acquireUnleashSwarmOwner(input, linuxDependencies()),
      { code: 'UNLEASH_SWARM_OWNER_RECORD_UNSAFE' },
    )
    assert.equal(await readFile(marker, 'utf8'), '{"partial":true}\n')
  })
})

test('replacement of the vetted stable container never yields an owner token', async (t) => {
  const input = await fixture(t)
  const lock = join(input.campaignDirectory, 'swarm-owner-lock')
  await mkdir(lock, { mode: 0o700 })
  const before = await lstat(lock, { bigint: true })
  let replaced = false
  await assert.rejects(
    acquireUnleashSwarmOwner(input, linuxDependencies({
      faultInjector: async (phase) => {
        if (phase !== 'before-owner-claim-publication' || replaced) return
        replaced = true
        await rmdir(lock)
        await mkdir(join(input.campaignDirectory, 'identity-spacer'), { mode: 0o700 })
        await mkdir(lock, { mode: 0o700 })
      },
    })),
    { code: 'UNLEASH_SWARM_OWNER_CHANGED' },
  )
  assert.equal(replaced, true)
  assert.equal(sameIdentity(before, await lstat(lock, { bigint: true })), false)
  assert.deepEqual(await lockEntries(input), ['owner.json'])
  assert.equal((await inspectUnleashSwarmOwner(input)).state, 'ACTIVE')
})
