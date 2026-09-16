import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rename,
  rm,
  rmdir,
  symlink,
  unlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join, parse, resolve, sep, win32 } from 'node:path'
import { test } from 'node:test'

import {
  MAX_UNLEASH_CAMPAIGN_JSON_BYTES,
  UnleashCampaignStorageError,
  canonicalUnleashCampaignJson,
  createUnleashCampaignStorage,
  defaultUnleashCampaignRunsRoot,
  openUnleashCampaignStorage,
} from '../scripts/lib/unleash-campaign-storage.mjs'

const CAMPAIGN_DIRECTORY = 'campaign-0123456789abcdef01234567'

function windowsSecurityTools() {
  const systemRoot = process.env.SystemRoot
  assert.equal(typeof systemRoot, 'string')
  return {
    whoami: win32.join(systemRoot, 'System32', 'whoami.exe'),
    icacls: win32.join(systemRoot, 'System32', 'icacls.exe'),
  }
}

function runWindowsSecurityTool(executable, args) {
  const result = spawnSync(executable, args, { encoding: 'utf8', windowsHide: true })
  assert.equal(result.status, 0, result.stderr)
  return result.stdout
}

function secureWindowsTestDirectory(path) {
  if (process.platform !== 'win32') return
  const { whoami, icacls } = windowsSecurityTools()
  const identity = runWindowsSecurityTool(whoami, ['/user', '/fo', 'csv', '/nh'])
  const sid = identity.match(/,"(S-[0-9-]+)"\s*$/u)?.[1]
  assert.match(sid ?? '', /^S-[0-9-]+$/u)
  runWindowsSecurityTool(icacls, [path, '/grant:r', `*${sid}:(OI)(CI)F`])
  runWindowsSecurityTool(icacls, [path, '/inheritance:r'])
  runWindowsSecurityTool(icacls, [
    path,
    '/grant:r',
    '*S-1-5-18:(OI)(CI)F',
    '*S-1-5-32-544:(OI)(CI)F',
  ])
}

function rejectsCode(code) {
  return (error) => {
    assert.equal(error instanceof UnleashCampaignStorageError, true)
    assert.equal(error.code, code)
    return true
  }
}

async function fixture(t, label) {
  const scratch = await mkdtemp(join(resolve(tmpdir()), `last-aperture-campaign-storage-${label}-`))
  const runsRoot = join(scratch, 'LastAperture', 'campaigns')
  await mkdir(runsRoot, { recursive: true, mode: 0o700 })
  if (process.platform === 'win32') secureWindowsTestDirectory(runsRoot)
  else await chmod(runsRoot, 0o700)
  t.after(async () => {
    assert.equal(dirname(scratch), resolve(tmpdir()))
    await rm(scratch, { recursive: true, force: true })
  })
  return { scratch, runsRoot }
}

async function linkDirectory(t, target, path) {
  try {
    await symlink(target, path, process.platform === 'win32' ? 'junction' : 'dir')
    return true
  } catch (error) {
    if (error?.code === 'EPERM' || error?.code === 'EACCES') {
      t.skip('this host does not allow creating a test link')
      return false
    }
    throw error
  }
}

test('canonical JSON is deterministic and rejects non-plain, computed, cyclic, and oversized values', () => {
  assert.equal(
    canonicalUnleashCampaignJson({ z: 1, a: { y: true, b: [2, null] } }),
    '{"a":{"b":[2,null],"y":true},"z":1}\n',
  )

  const computed = {}
  Object.defineProperty(computed, 'value', { enumerable: true, get: () => 'surprise' })
  const cyclic = {}
  cyclic.self = cyclic
  const disappearing = new Proxy({}, {
    ownKeys: () => ['value'],
    getOwnPropertyDescriptor: () => undefined,
  })
  for (const value of [
    computed,
    cyclic,
    disappearing,
    new Date(),
    { value: Number.NaN },
    { value: undefined },
  ]) {
    assert.throws(
      () => canonicalUnleashCampaignJson(value),
      rejectsCode('UNLEASH_STORAGE_JSON_INVALID'),
    )
  }
  assert.throws(
    () => canonicalUnleashCampaignJson('x'.repeat(MAX_UNLEASH_CAMPAIGN_JSON_BYTES)),
    rejectsCode('UNLEASH_STORAGE_JSON_BOUNDS'),
  )
})

test('Windows storage and controller defaults share the fallback when LOCALAPPDATA is relative', {
  skip: process.platform !== 'win32',
}, async (t) => {
  const scratch = await mkdtemp(join(resolve(tmpdir()), 'last-aperture-localappdata-fallback-'))
  const home = join(scratch, 'home')
  const runsRoot = join(home, 'AppData', 'Local', 'LastAperture', 'campaigns')
  await mkdir(runsRoot, { recursive: true, mode: 0o700 })
  secureWindowsTestDirectory(runsRoot)
  t.after(async () => {
    assert.equal(dirname(scratch), resolve(tmpdir()))
    await rm(scratch, { recursive: true, force: true })
  })
  assert.equal(
    defaultUnleashCampaignRunsRoot({ platform: 'win32', localAppData: 'relative', home }),
    runsRoot,
  )
  const moduleUrl = new URL('../scripts/lib/unleash-campaign-storage.mjs', import.meta.url).href
  const child = spawnSync(process.execPath, [
    '--input-type=module',
    '-e',
    `
      const { createUnleashCampaignStorage, defaultUnleashCampaignRunsRoot } = await import(process.argv[1])
      const runsRoot = defaultUnleashCampaignRunsRoot()
      await createUnleashCampaignStorage({ runsRoot, campaignDirectory: '${CAMPAIGN_DIRECTORY}' })
    `,
    moduleUrl,
  ], {
    encoding: 'utf8',
    windowsHide: true,
    env: { ...process.env, LOCALAPPDATA: 'relative', USERPROFILE: home, HOME: home },
  })
  assert.equal(child.status, 0, child.stderr)
})

test('creates one private campaign directory and returns verified canonical paths', async (t) => {
  const { runsRoot } = await fixture(t, 'create')
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })

  assert.deepEqual(Object.keys(storage).toSorted(), [
    'campaign_directory',
    'listJsonFilenames',
    'readJson',
    'replaceMutableJson',
    'runs_root',
    'writeImmutableJson',
  ])
  assert.equal(Object.isFrozen(storage), true)
  assert.equal(storage.runs_root, await import('node:fs/promises').then(({ realpath }) => realpath(runsRoot)))
  assert.equal(storage.campaign_directory, join(storage.runs_root, CAMPAIGN_DIRECTORY))
  const metadata = await lstat(storage.campaign_directory, { bigint: true })
  assert.equal(metadata.isDirectory(), true)
  assert.equal(metadata.isSymbolicLink(), false)
  if (process.platform !== 'win32') assert.equal(Number(metadata.mode & 0o077n), 0)
})

test('rejects relative, non-canonical, remote, filesystem-root, and broadly accessible roots', async (t) => {
  const { runsRoot } = await fixture(t, 'root-validation')
  const invalidRoots = [
    'relative/campaigns',
    `${runsRoot}${sep}..${sep}campaigns`,
    '\\\\host\\share\\campaigns',
    parse(runsRoot).root,
  ]
  if (process.platform === 'win32') {
    invalidRoots.push(join(
      parse(runsRoot).root,
      'last-aperture-outside-local-app-data',
      'LastAperture',
      'campaigns',
    ))
  }
  for (const invalidRoot of invalidRoots) {
    await assert.rejects(
      createUnleashCampaignStorage({ runsRoot: invalidRoot, campaignDirectory: CAMPAIGN_DIRECTORY }),
      rejectsCode('UNLEASH_STORAGE_ROOT_INVALID'),
      invalidRoot,
    )
  }

  if (process.platform !== 'win32') {
    await chmod(runsRoot, 0o777)
    await assert.rejects(
      createUnleashCampaignStorage({ runsRoot, campaignDirectory: CAMPAIGN_DIRECTORY }),
      rejectsCode('UNLEASH_STORAGE_ROOT_UNSAFE'),
    )
  } else {
    const { icacls } = windowsSecurityTools()
    runWindowsSecurityTool(icacls, [runsRoot, '/grant', '*S-1-1-0:(OI)(CI)M'])
    await assert.rejects(
      createUnleashCampaignStorage({ runsRoot, campaignDirectory: CAMPAIGN_DIRECTORY }),
      rejectsCode('UNLEASH_STORAGE_AUTHORITY_UNSAFE'),
    )
  }
})

test('rejects a symbolic-link or junction anywhere in the supplied root path', async (t) => {
  const { scratch } = await fixture(t, 'linked-root')
  const alias = join(scratch, 'root-alias')
  if (!await linkDirectory(t, scratch, alias)) return

  await assert.rejects(
    createUnleashCampaignStorage({
      runsRoot: join(alias, 'LastAperture', 'campaigns'),
      campaignDirectory: CAMPAIGN_DIRECTORY,
    }),
    rejectsCode('UNLEASH_STORAGE_ROOT_UNSAFE'),
  )
})

test('campaign directory names are a fixed non-traversable identity', async (t) => {
  const { runsRoot } = await fixture(t, 'campaign-name')
  for (const campaignDirectory of [
    '../outside',
    'campaign-0123456789abcdef0123456',
    'campaign-0123456789ABCDEF01234567',
    'campaign-0123456789abcdef01234567/child',
    'campaign-0123456789abcdef01234567:stream',
  ]) {
    await assert.rejects(
      createUnleashCampaignStorage({ runsRoot, campaignDirectory }),
      rejectsCode('UNLEASH_CAMPAIGN_NAME_INVALID'),
      campaignDirectory,
    )
  }
})

test('campaign creation and immutable JSON publication are exclusive', async (t) => {
  const { runsRoot } = await fixture(t, 'exclusive')
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  await assert.rejects(
    createUnleashCampaignStorage({ runsRoot, campaignDirectory: CAMPAIGN_DIRECTORY }),
    rejectsCode('UNLEASH_CAMPAIGN_EXISTS'),
  )

  const path = await storage.writeImmutableJson('campaign-plan.json', { z: 2, a: 1 })
  assert.equal(path, join(storage.campaign_directory, 'campaign-plan.json'))
  assert.equal(await readFile(path, 'utf8'), '{"a":1,"z":2}\n')
  await assert.rejects(
    storage.writeImmutableJson('campaign-plan.json', { changed: true }),
    rejectsCode('UNLEASH_STORAGE_FILE_EXISTS'),
  )
  assert.equal(await readFile(path, 'utf8'), '{"a":1,"z":2}\n')
})

test('rejects campaign JSON whose POSIX mode or Windows DACL permits an untrusted writer', async (t) => {
  const { runsRoot } = await fixture(t, 'file-authority')
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  const path = await storage.writeImmutableJson('campaign-plan.json', { revision: 1 })
  if (process.platform === 'win32') {
    const { icacls } = windowsSecurityTools()
    runWindowsSecurityTool(icacls, [path, '/grant', '*S-1-1-0:(W)'])
  } else {
    await chmod(path, 0o644)
  }

  await assert.rejects(
    storage.readJson('campaign-plan.json'),
    rejectsCode('UNLEASH_STORAGE_AUTHORITY_UNSAFE'),
  )
})

test('rejects a nested campaign directory whose Windows DACL permits an untrusted writer', {
  skip: process.platform !== 'win32',
}, async (t) => {
  const { runsRoot } = await fixture(t, 'nested-directory-authority')
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  const nested = join(storage.campaign_directory, 'recon')
  await mkdir(nested)
  const { icacls } = windowsSecurityTools()
  runWindowsSecurityTool(icacls, [nested, '/grant', '*S-1-1-0:(OI)(CI)M'])

  await assert.rejects(
    storage.listJsonFilenames(),
    rejectsCode('UNLEASH_STORAGE_AUTHORITY_UNSAFE'),
  )
})

test('JSON filenames cannot escape the campaign or address alternate streams', async (t) => {
  const { runsRoot } = await fixture(t, 'filename')
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  for (const filename of [
    '../outside.json',
    'nested/state.json',
    'state\\file.json',
    'state.json:stream',
    'CON.json',
    'state.JSON',
    '.json',
  ]) {
    await assert.rejects(
      storage.writeImmutableJson(filename, { ok: true }),
      rejectsCode('UNLEASH_STORAGE_FILENAME_INVALID'),
      filename,
    )
  }
})

test('mutable JSON replacement publishes complete canonical versions and leaves no temporary files', async (t) => {
  const { runsRoot } = await fixture(t, 'replace')
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })

  const path = await storage.replaceMutableJson('campaign-state.json', { status: 'PLANNED', count: 1 })
  assert.equal(path, join(storage.campaign_directory, 'campaign-state.json'))
  assert.equal(await readFile(path, 'utf8'), '{"count":1,"status":"PLANNED"}\n')
  await storage.replaceMutableJson('campaign-state.json', { status: 'COMPLETE', count: 2 })
  assert.equal(await readFile(path, 'utf8'), '{"count":2,"status":"COMPLETE"}\n')
  assert.deepEqual(await readdir(storage.campaign_directory), ['campaign-state.json'])
})

test('reopens an existing campaign for crash recovery without recreating it', async (t) => {
  const { runsRoot } = await fixture(t, 'reopen')
  const created = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  await created.replaceMutableJson('campaign-state.json', { revision: 1, status: 'RUNNING' })

  const reopened = await openUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  assert.equal(reopened.campaign_directory, created.campaign_directory)
  await reopened.replaceMutableJson('campaign-state.json', { revision: 2, status: 'RECOVERED' })
  assert.equal(
    await readFile(join(reopened.campaign_directory, 'campaign-state.json'), 'utf8'),
    '{"revision":2,"status":"RECOVERED"}\n',
  )
  const recovered = await reopened.readJson('campaign-state.json')
  assert.deepEqual(recovered, { revision: 2, status: 'RECOVERED' })
  assert.equal(Object.isFrozen(recovered), true)
})

test('recovery reads only bounded exact canonical JSON through a stable regular file', async (t) => {
  const { runsRoot } = await fixture(t, 'read-json')
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  const statePath = join(storage.campaign_directory, 'campaign-state.json')

  await assert.rejects(
    storage.readJson('campaign-state.json'),
    rejectsCode('UNLEASH_STORAGE_FILE_NOT_FOUND'),
  )
  await writeFile(statePath, '{"status":"RUNNING","revision":1}\n', {
    encoding: 'utf8',
    flag: 'wx',
    mode: 0o600,
  })
  await assert.rejects(
    storage.readJson('campaign-state.json'),
    rejectsCode('UNLEASH_STORAGE_JSON_NONCANONICAL'),
  )
  await writeFile(statePath, 'x'.repeat(MAX_UNLEASH_CAMPAIGN_JSON_BYTES + 1), 'utf8')
  await assert.rejects(
    storage.readJson('campaign-state.json'),
    rejectsCode('UNLEASH_STORAGE_JSON_BOUNDS'),
  )
})

test('recovery lists a sorted frozen JSON inventory and rejects unsafe residue', async (t) => {
  const { scratch, runsRoot } = await fixture(t, 'list-json')
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  await storage.writeImmutableJson('campaign-plan.json', { revision: 1 })
  await storage.writeImmutableJson('campaign-event-000002.json', { sequence: 2 })
  await storage.writeImmutableJson('campaign-event-000001.json', { sequence: 1 })
  await mkdir(join(storage.campaign_directory, 'recon'), { mode: 0o700 })

  const filenames = await storage.listJsonFilenames()
  assert.deepEqual(filenames, [
    'campaign-event-000001.json',
    'campaign-event-000002.json',
    'campaign-plan.json',
  ])
  assert.equal(Object.isFrozen(filenames), true)

  const temporary = join(storage.campaign_directory, '.campaign-state.json.abcd.tmp')
  await writeFile(temporary, '{}\n')
  await assert.rejects(
    storage.listJsonFilenames(),
    rejectsCode('UNLEASH_STORAGE_TEMP_RESIDUE'),
  )
  await rm(temporary)
  const outside = join(scratch, 'outside.json')
  await writeFile(outside, '{}\n')
  await link(outside, join(storage.campaign_directory, 'campaign-event-000003.json'))
  await assert.rejects(
    storage.listJsonFilenames(),
    rejectsCode('UNLEASH_STORAGE_FILE_UNSAFE'),
  )
})

test('reclaims an identity-bound temporary publication left by a crashed child process', async (t) => {
  const { runsRoot } = await fixture(t, 'stale-temp-recovery')
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  const script = String.raw`
    const { closeSync, fsyncSync, openSync, writeSync } = require('node:fs')
    const { join } = require('node:path')
    const directory = process.argv[1]
    const path = join(
      directory,
      '.campaign-state.json.' + process.pid + '.' + 'a'.repeat(32) + '.tmp',
    )
    const descriptor = openSync(path, 'wx', 0o600)
    writeSync(descriptor, Buffer.from('{"incomplete":', 'utf8'))
    fsyncSync(descriptor)
    closeSync(descriptor)
  `
  const child = spawnSync(process.execPath, ['-e', script, storage.campaign_directory], {
    encoding: 'utf8',
    windowsHide: true,
  })
  assert.equal(child.status, 0, child.stderr)

  const reopened = await openUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  assert.deepEqual(await reopened.listJsonFilenames(), [])
  assert.deepEqual(
    (await readdir(storage.campaign_directory)).filter((name) => name.endsWith('.tmp')),
    [],
  )
})

test('recovers the exact two-link POSIX create-only publication crash tail', async (t) => {
  const { runsRoot } = await fixture(t, 'linked-publication-tail')
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  const publicationModule = new URL(
    '../scripts/lib/durable-file-publication.mjs',
    import.meta.url,
  ).href
  const script = String.raw`
    import { writeFile } from 'node:fs/promises'
    import { join } from 'node:path'
    const { publishFileCreateOnlyDurably } = await import(process.argv[1])
    const directory = process.argv[2]
    const temporary = join(
      directory,
      '.campaign-plan.json.' + process.pid + '.' + 'd'.repeat(32) + '.tmp',
    )
    const destination = join(directory, 'campaign-plan.json')
    await writeFile(temporary, '{"revision":1}\n', { encoding: 'utf8', flag: 'wx', mode: 0o600 })
    try {
      await publishFileCreateOnlyDurably(temporary, destination, {
        platform: 'linux',
        afterVisible() {
          throw new Error('simulated process loss after create-only link publication')
        },
      })
    } catch {}
    process.stdout.write(temporary)
  `
  const child = spawnSync(process.execPath, [
    '--input-type=module',
    '-e',
    script,
    publicationModule,
    storage.campaign_directory,
  ], {
    encoding: 'utf8',
    windowsHide: true,
  })
  assert.equal(child.status, 0, child.stderr)
  const publicationTemporary = child.stdout
  assert.equal(typeof publicationTemporary, 'string')
  assert.notEqual(publicationTemporary, '')
  const destination = join(storage.campaign_directory, 'campaign-plan.json')
  const temporaryBefore = await lstat(publicationTemporary, { bigint: true })
  const destinationBefore = await lstat(destination, { bigint: true })
  assert.equal(temporaryBefore.nlink, 2n)
  assert.equal(destinationBefore.nlink, 2n)
  assert.equal(temporaryBefore.dev, destinationBefore.dev)
  assert.equal(temporaryBefore.ino, destinationBefore.ino)
  assert.equal(temporaryBefore.size, destinationBefore.size)

  const reopened = await openUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  assert.deepEqual(await reopened.listJsonFilenames(), ['campaign-plan.json'])
  await assert.rejects(lstat(publicationTemporary), (error) => error?.code === 'ENOENT')
  const destinationAfter = await lstat(destination, { bigint: true })
  assert.equal(destinationAfter.nlink, 1n)
  assert.equal(destinationAfter.dev, destinationBefore.dev)
  assert.equal(destinationAfter.ino, destinationBefore.ino)
  assert.equal(destinationAfter.size, destinationBefore.size)
  assert.deepEqual(await reopened.readJson('campaign-plan.json'), { revision: 1 })
})

test('rejects an exact dead-owner temporary whose second link is not its named destination', async (t) => {
  const { scratch, runsRoot } = await fixture(t, 'linked-publication-alias')
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  const child = spawnSync(process.execPath, ['-e', 'process.stdout.write(String(process.pid))'], {
    encoding: 'utf8',
    windowsHide: true,
  })
  assert.equal(child.status, 0, child.stderr)
  const deadPid = Number(child.stdout)
  assert.equal(Number.isSafeInteger(deadPid) && deadPid > 0, true)
  const temporary = join(
    storage.campaign_directory,
    `.campaign-plan.json.${deadPid}.${'c'.repeat(32)}.tmp`,
  )
  const unexplainedAlias = join(scratch, 'unexplained-alias.json')
  await writeFile(temporary, '{"revision":1}\n', { encoding: 'utf8', flag: 'wx', mode: 0o600 })
  await link(temporary, unexplainedAlias)

  const reopened = await openUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  await assert.rejects(
    reopened.listJsonFilenames(),
    rejectsCode('UNLEASH_STORAGE_TEMP_RESIDUE'),
  )
  assert.equal((await lstat(temporary, { bigint: true })).nlink, 2n)
  assert.equal((await lstat(unexplainedAlias, { bigint: true })).nlink, 2n)
  await unlink(unexplainedAlias)
})

test('does not reclaim a temporary campaign publication owned by a live process', async (t) => {
  const { runsRoot } = await fixture(t, 'live-temp')
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  const temporary = join(
    storage.campaign_directory,
    `.campaign-state.json.${process.pid}.${'b'.repeat(32)}.tmp`,
  )
  await writeFile(temporary, '{}\n', { encoding: 'utf8', flag: 'wx', mode: 0o600 })
  await assert.rejects(
    storage.listJsonFilenames(),
    rejectsCode('UNLEASH_STORAGE_TEMP_RESIDUE'),
  )
  assert.equal(await readFile(temporary, 'utf8'), '{}\n')
})

test('reconciles publication errors that occur after complete bytes become visible', async (t) => {
  const { runsRoot } = await fixture(t, 'commit-reconciliation')
  const failAfterRename = async (source, destination) => {
    await rename(source, destination)
    throw new Error('simulated failure after commit')
  }
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  }, {
    publishCreateOnly: failAfterRename,
    replaceFile: failAfterRename,
  })

  assert.equal(
    await storage.writeImmutableJson('campaign-plan.json', { revision: 1 }),
    join(storage.campaign_directory, 'campaign-plan.json'),
  )
  assert.equal(
    await storage.replaceMutableJson('campaign-state.json', { revision: 2 }),
    join(storage.campaign_directory, 'campaign-state.json'),
  )
  assert.equal(
    await readFile(join(storage.campaign_directory, 'campaign-state.json'), 'utf8'),
    '{"revision":2}\n',
  )
})

test('serializes mutable publishers inside one campaign store', async (t) => {
  const { runsRoot } = await fixture(t, 'single-writer')
  let active = 0
  let maximumActive = 0
  const delayedReplace = async (source, destination) => {
    active += 1
    maximumActive = Math.max(maximumActive, active)
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 20))
    await rename(source, destination)
    active -= 1
  }
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  }, { replaceFile: delayedReplace })

  await Promise.all([
    storage.replaceMutableJson('campaign-state.json', { revision: 1 }),
    storage.replaceMutableJson('campaign-state.json', { revision: 2 }),
  ])

  assert.equal(maximumActive, 1)
  assert.equal(
    await readFile(join(storage.campaign_directory, 'campaign-state.json'), 'utf8'),
    '{"revision":2}\n',
  )
})

test('mutable replacement refuses a linked or multiply-linked destination', async (t) => {
  const { scratch, runsRoot } = await fixture(t, 'unsafe-destination')
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  const outside = join(scratch, 'outside.json')
  const destination = join(storage.campaign_directory, 'campaign-state.json')
  await writeFile(outside, '{}\n', { encoding: 'utf8', flag: 'wx' })
  await link(outside, destination)

  await assert.rejects(
    storage.replaceMutableJson('campaign-state.json', { status: 'COMPLETE' }),
    rejectsCode('UNLEASH_STORAGE_FILE_UNSAFE'),
  )
  assert.equal(await readFile(outside, 'utf8'), '{}\n')
})

test('every write rejects a campaign directory that became an alias', async (t) => {
  const { scratch, runsRoot } = await fixture(t, 'swapped-campaign')
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  await rmdir(storage.campaign_directory)
  const outside = join(scratch, 'outside')
  await mkdir(outside)
  if (!await linkDirectory(t, outside, storage.campaign_directory)) return

  await assert.rejects(
    storage.writeImmutableJson('campaign-plan.json', { safe: false }),
    rejectsCode('UNLEASH_STORAGE_CHANGED'),
  )
  assert.deepEqual(await readdir(outside), [])
})

test('every write rechecks private campaign permissions', async (t) => {
  if (process.platform === 'win32') {
    t.skip('POSIX mode bits are unavailable on Windows')
    return
  }
  const { runsRoot } = await fixture(t, 'campaign-permissions')
  const storage = await createUnleashCampaignStorage({
    runsRoot,
    campaignDirectory: CAMPAIGN_DIRECTORY,
  })
  await chmod(storage.campaign_directory, 0o777)

  await assert.rejects(
    storage.writeImmutableJson('campaign-plan.json', { safe: false }),
    rejectsCode('UNLEASH_STORAGE_CHANGED'),
  )
  assert.deepEqual(await readdir(storage.campaign_directory), [])
})
