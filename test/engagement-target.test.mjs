import assert from 'node:assert/strict'
import { mkdir, mkdtemp, realpath, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import {
  assertValidEngagementIntake,
  canonicalEngagementTarget,
  createEngagementIntake,
  digestEngagementTarget,
  normalizeEngagementTarget,
} from '../scripts/lib/engagement-contracts.mjs'

const PROCESS_INSTANCE = 'a'.repeat(64)
const REPLACEMENT_INSTANCE = 'b'.repeat(64)
const DEVICE_INSTANCE = 'c'.repeat(64)

test('HTTPS aliases normalize to one credential-free canonical target', async () => {
  const first = await normalizeEngagementTarget('https://APP.Example:443/a/../internal')
  const second = await normalizeEngagementTarget({
    kind: 'https',
    locator: 'https://app.example/internal',
  })

  assert.deepEqual(first, {
    kind: 'https',
    locator: 'https://app.example/internal',
  })
  assert.deepEqual(second, first)
  assert.equal(digestEngagementTarget(first), digestEngagementTarget(second))
  assert.equal(canonicalEngagementTarget(first), '{"kind":"https","locator":"https://app.example/internal"}')
})

test('web target normalization refuses credentials, fragments, ambiguous encodings, and non-HTTPS schemes', async () => {
  for (const value of [
    'https://user:secret@app.example/',
    'https://app.example/search?token=secret',
    'https://app.example/#admin',
    'https://app.example/%2e%2e/admin',
    'https://app.example/a%2fb',
    'https://app.example/app/%252e%252e%252fadmin',
    'https://app.example/app/%25252e%25252e%25252fadmin',
    'https://app.example/app/%25%32%65%25%32%65%25%32%66admin',
    'https://app.example./',
    'http://app.example/',
    'file:///etc/passwd',
  ]) {
    await assert.rejects(() => normalizeEngagementTarget(value), /target|HTTPS|credential|fragment|ambiguous|host/i)
  }
})

test('query values are refused as durable target locators', async () => {
  await assert.rejects(
    () => normalizeEngagementTarget('https://app.example/search?q=%2e%2fvalue'),
    /query|credential-free|target/i,
  )
})

test('local directories and files normalize through their real local identity', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-engagement-target-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const repository = join(root, 'repository')
  const artifact = join(repository, 'application.bin')
  await mkdir(repository)
  await writeFile(artifact, Buffer.from('synthetic target bytes'))

  const normalizedRepository = await normalizeEngagementTarget(join(root, '.', 'repository'))
  const normalizedArtifact = await normalizeEngagementTarget(artifact)

  assert.deepEqual(normalizedRepository, {
    kind: 'repository',
    locator: await realpath(repository),
  })
  assert.deepEqual(normalizedArtifact, {
    kind: 'artifact',
    locator: await realpath(artifact),
  })
  assert.notEqual(digestEngagementTarget(normalizedRepository), digestEngagementTarget(normalizedArtifact))
})

test('local target normalization rejects remote namespaces and links before resolving them', async () => {
  let filesystemCalls = 0
  const dependencies = {
    lstatImpl: async () => {
      filesystemCalls += 1
      return { isSymbolicLink: () => false, isDirectory: () => true, isFile: () => false }
    },
    realpathImpl: async (value) => value,
  }

  await assert.rejects(
    () => normalizeEngagementTarget('\\\\server\\share\\target', dependencies),
    /local filesystem|UNC|WebDAV/i,
  )
  assert.equal(filesystemCalls, 0)

  await assert.rejects(
    () => normalizeEngagementTarget('C:\\local-link', {
      lstatImpl: async () => ({ isSymbolicLink: () => true, isDirectory: () => false, isFile: () => false }),
      realpathImpl: async () => { throw new Error('must not resolve a link') },
    }),
    /symbolic|reparse|link/i,
  )
})

test('process and device selectors bind a trusted concrete runtime instance', async () => {
  const resolved = []
  const resolveRuntimeIdentity = async (selector) => {
    assert.equal(Object.isFrozen(selector), true)
    resolved.push(selector)
    return selector.kind === 'process' ? PROCESS_INSTANCE : DEVICE_INSTANCE
  }

  assert.deepEqual(await normalizeEngagementTarget(
    { kind: 'process', locator: 'pid:0042' },
    { resolveRuntimeIdentity },
  ), {
    kind: 'process', locator: 'pid:42', instance_sha256: PROCESS_INSTANCE,
  })
  assert.deepEqual(await normalizeEngagementTarget(
    { kind: 'device', locator: 'id:device-001' },
    { resolveRuntimeIdentity },
  ), {
    kind: 'device', locator: 'id:device-001', instance_sha256: DEVICE_INSTANCE,
  })
  assert.deepEqual(resolved, [
    { kind: 'process', locator: 'pid:42' },
    { kind: 'device', locator: 'id:device-001' },
  ])
})

test('browser selectors retain credential-free canonical URL semantics without a runtime adapter', async () => {
  assert.deepEqual(await normalizeEngagementTarget({ kind: 'browser', locator: 'https://APP.example:443/login' }), {
    kind: 'browser', locator: 'https://app.example/login',
  })
})

test('runtime targets reject ambiguous selectors and require a trusted identity adapter', async () => {
  for (const value of [
    { kind: 'process', locator: 'pid:42' },
    { kind: 'device', locator: 'id:device-001' },
  ]) {
    await assert.rejects(
      () => normalizeEngagementTarget(value),
      (error) => error?.code === 'ENGAGEMENT_RUNTIME_IDENTITY_ADAPTER_REQUIRED',
    )
  }

  for (const value of [
    { kind: 'process', locator: 'pid:0' },
    { kind: 'process', locator: 'name:browser.exe' },
    { kind: 'process', locator: '42' },
    { kind: 'device', locator: 'usb' },
    { kind: 'device', locator: 'token:secret' },
    { kind: 'browser', locator: 'https://user:secret@app.example/' },
    { kind: 'unknown', locator: 'anything' },
  ]) {
    await assert.rejects(
      () => normalizeEngagementTarget(value, { resolveRuntimeIdentity: async () => PROCESS_INSTANCE }),
      /target|selector|locator|credential|kind/i,
    )
  }
})

test('runtime identity adapters fail closed on invalid or unavailable identities', async () => {
  for (const instanceIdentity of [
    '',
    'A'.repeat(64),
    'a'.repeat(63),
    { instance_sha256: PROCESS_INSTANCE },
    null,
  ]) {
    await assert.rejects(
      () => normalizeEngagementTarget(
        { kind: 'process', locator: 'pid:42' },
        { resolveRuntimeIdentity: async () => instanceIdentity },
      ),
      (error) => error?.code === 'ENGAGEMENT_RUNTIME_IDENTITY_INVALID',
    )
  }

  await assert.rejects(
    () => normalizeEngagementTarget(
      { kind: 'device', locator: 'id:device-001' },
      { resolveRuntimeIdentity: async () => { throw new Error('device disconnected') } },
    ),
    (error) => error?.code === 'ENGAGEMENT_RUNTIME_IDENTITY_UNAVAILABLE'
      && error.cause?.message === 'device disconnected',
  )
})

test('a replacement at the same runtime selector produces a different canonical target binding', async () => {
  const original = await normalizeEngagementTarget(
    { kind: 'process', locator: 'pid:42' },
    { resolveRuntimeIdentity: async () => PROCESS_INSTANCE },
  )
  const replacement = await normalizeEngagementTarget(
    { kind: 'process', locator: 'pid:42' },
    { resolveRuntimeIdentity: async () => REPLACEMENT_INSTANCE },
  )

  assert.notDeepEqual(replacement, original)
  assert.notEqual(digestEngagementTarget(replacement), digestEngagementTarget(original))
  assert.match(canonicalEngagementTarget(original), /"instance_sha256":"a{64}"/u)
  assert.throws(
    () => canonicalEngagementTarget({ kind: 'process', locator: 'pid:42' }),
    /instance_sha256|target/i,
  )
  assert.throws(
    () => canonicalEngagementTarget({
      kind: 'process', locator: 'pid:42', instance_sha256: PROCESS_INSTANCE.toUpperCase(),
    }),
    /lowercase|instance digest/i,
  )
  assert.throws(
    () => canonicalEngagementTarget({
      kind: 'https', locator: 'https://app.example/', instance_sha256: PROCESS_INSTANCE,
    }),
    /only kind and locator/i,
  )
})

test('intake binds the canonical target while preserving statement and named credential references', async () => {
  const intake = await createEngagementIntake({
    operatorId: 'operator:workspace-owner',
    declaredAt: '2026-09-11T09:00:00.000Z',
    statement: 'We own and authorize a complete review of this target.',
    objective: 'Assess and integrate the application.',
    target: 'https://APP.example:443/a/../portal',
    authorizationProfile: 'full',
    credentialReferences: ['browser-session:primary'],
    inputs: [],
  })

  assert.deepEqual(intake.target, { kind: 'https', locator: 'https://app.example/portal' })
  assert.equal(intake.statement, 'We own and authorize a complete review of this target.')
  assert.deepEqual(intake.credential_references, ['browser-session:primary'])
  assert.equal(Object.isFrozen(intake.target), true)
  assert.equal(Object.isFrozen(intake.credential_references), true)
  assert.equal(Object.isFrozen(intake.inputs), true)
  assert.doesNotThrow(() => assertValidEngagementIntake(intake))
})

test('already canonical target records reject extensions and lexical drift', () => {
  assert.throws(
    () => canonicalEngagementTarget({ kind: 'https', locator: 'https://APP.example/', extra: true }),
    /target|field|schema|canonical/i,
  )
  assert.throws(
    () => canonicalEngagementTarget({ kind: 'repository', locator: 'relative/path' }),
    /target|absolute|canonical/i,
  )
})
