import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { access, mkdtemp, readFile, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { createRegistryAdapter } from '../scripts/lib/evidence-adapters/registry.mjs'
import { verifyEvidenceBundle } from '../scripts/lib/evidence-bundle.mjs'
import { readTarEntries, readTarEntryBytes } from '../scripts/lib/oci-normalizer.mjs'
import { runEvidenceAdapterConformance } from './helpers/evidence-adapter-conformance.mjs'
import { absentCliResolver, stubCli } from './helpers/stub-cli.mjs'

const DIGEST = 'sha256:459cf49d9cfb62f0a2a602b2364b80f16c22911e0b9f9270dccc8b63095c3a3c'
const REFERENCE = `registry.example.com/example/application@${DIGEST}`
const FIXTURE = resolve('test/fixtures/evidence/vulnerable-image.tar')

// The stub streams the committed fixture to stdout, so the bounded runner
// supervises every byte before the adapter accepts an archive.
// Every registry test runs against these bytes; none touches a network.
async function craneStub() {
  const archive = await readFile(FIXTURE)
  const entries = readTarEntries(archive)
  const blobs = Object.fromEntries(entries
    .filter(({ path }) => /^blobs\/sha256\/[0-9a-f]{64}$/.test(path))
    .map((entry) => [
      `sha256:${entry.path.slice('blobs/sha256/'.length)}`,
      readTarEntryBytes(archive, entry).toString('base64'),
    ]))
  return stubCli('crane', `
    if (args[0] === 'version') { process.stdout.write('0.19.1\\n') }
    else {
      if (process.env.REGISTRY_TOKEN !== 'test-only-registry-token') process.exit(9)
      const blobs = ${JSON.stringify(blobs)}
      const digest = args[1].slice(args[1].lastIndexOf('@') + 1)
      const encoded = blobs[digest] ?? blobs[${JSON.stringify(DIGEST)}]
      if (!encoded) process.exit(8)
      process.stdout.write(Buffer.from(encoded, 'base64'))
    }
  `)
}

async function envCredentialResolver(reference, { env }) {
  const name = reference.slice('env:'.length)
  if (typeof env?.[name] !== 'string' || env[name] === '') throw new Error('credential unavailable')
  return { env, secret_values: [env[name]] }
}

async function adapterWithStub() {
  const stub = await craneStub()
  return createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    credentialResolver: envCredentialResolver,
    env: { ...process.env, REGISTRY_TOKEN: 'test-only-registry-token' },
  })
}

const REQUEST = {
  evidence_id: 'sample-api-image',
  image: REFERENCE,
  credential_ref: 'env:REGISTRY_TOKEN',
  target_class: 'NONPROD',
  phi_scope: 'none',
  attest_authorized: true,
  operator_id: 'gmaida',
  authorized_by: 'platform-lead',
  authorization_reference: 'JIRA-4417',
}

// The shared suite, unmodified, against the second real adapter.
runEvidenceAdapterConformance(await adapterWithStub(), { validPlanRequest: REQUEST })

test('plan pins the digest and never contacts the registry', async () => {
  const adapter = await adapterWithStub()
  const planned = await adapter.plan(REQUEST)
  assert.equal(planned.evidence_context_seed.target_identity, DIGEST)
  assert.equal(planned.evidence_context_seed.acquisition_mode, 'registry-pull')
  assert.equal(planned.image_reference, REFERENCE)
  assert.equal(planned.dependency.present, true)
  assert.deepEqual(planned.execution_profile.initial_command, {
    cli: 'crane', args: ['manifest', REFERENCE],
  })
  assert.equal(planned.execution_profile.descriptor_commands.blob.require_sha256_match, true)
  assert.equal(planned.execution_profile.limits.traversal.maxInflatedBytes > 0, true)
  assert.equal(planned.execution_profile.limits.traversal.maxProjectedBytes > 0, true)
  assert.equal(planned.execution_profile.limits.traversal.maxMetadataItems > 0, true)
  assert.equal(planned.execution_profile.limits.traversal.maxMetadataBytes > 0, true)
  assert.equal(planned.execution_profile.limits.traversal.maxCapturedBytes > 0, true)
  assert.equal(planned.execution_profile.limits.traversal.maxCapturedFiles > 0, true)
})

test('invalid registry capture limits fail before crane is probed', () => {
  let resolverCalls = 0
  assert.throws(
    () => createRegistryAdapter({
      limits: { maxCapturedBytes: Number.POSITIVE_INFINITY },
      resolver: () => {
        resolverCalls += 1
        throw new Error('must not resolve')
      },
    }),
    /maxCapturedBytes.*positive safe integer/i,
  )
  assert.equal(resolverCalls, 0)
})

test('run revalidates crane executable identity before any registry read', async () => {
  const first = await stubCli('crane', `
    if (args[0] === 'version') process.stdout.write('0.19.1\\n')
  `)
  const touched = join(await mkdtemp(join(tmpdir(), 'rta-registry-profile-')), 'target-read.txt')
  const second = await stubCli('crane', `
    if (args[0] === 'version') process.stdout.write('0.19.1\\n')
    else (await import('node:fs')).writeFileSync(${JSON.stringify(touched)}, 'read')
  `)
  let active = first.resolver
  const adapter = createRegistryAdapter({
    resolver: (name, args) => active(name, args),
    env: { ...process.env, REGISTRY_TOKEN: 'test-only-registry-token' },
  })
  const planned = await adapter.plan(REQUEST)
  active = second.resolver
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-profile-out-')), 'ev')
  await assert.rejects(
    () => adapter.run(planned, { out }),
    /executable identity|execution profile/i,
  )
  await assert.rejects(() => access(touched))
})

test('same-path crane replacement is rejected before probe execution or credential resolution', async () => {
  const stub = await stubCli('crane', `
    if (args[0] === 'version') process.stdout.write('0.19.1\\n')
  `)
  const marker = join(await mkdtemp(join(tmpdir(), 'rta-registry-same-path-')), 'dispatched.txt')
  let credentialCalls = 0
  const adapter = createRegistryAdapter({
    resolver: stub.resolver,
    credentialResolver: async () => {
      credentialCalls += 1
      return { env: {}, secret_values: ['secret'] }
    },
    env: { ...process.env, REGISTRY_TOKEN: 'must-not-reach-replacement' },
  })
  const planned = await adapter.plan(REQUEST)
  await writeFile(stub.path, [
    "const args = process.argv.slice(2)",
    `await (await import('node:fs/promises')).writeFile(${JSON.stringify(marker)}, process.env.REGISTRY_TOKEN ?? 'missing')`,
  ].join('\n'))
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-same-path-out-')), 'ev')
  await assert.rejects(
    () => adapter.run(planned, { out }),
    /executable identity/i,
  )
  assert.equal(credentialCalls, 0)
  await assert.rejects(() => access(marker))
})

test('identity drift after the run probe remains zero-touch at the dispatch boundary', async () => {
  const stub = await stubCli('crane', `
    if (args[0] === 'version') process.stdout.write('0.19.1\\n')
  `)
  const marker = join(await mkdtemp(join(tmpdir(), 'rta-registry-dispatch-drift-')), 'dispatched.txt')
  let replaceOnCredential = false
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    credentialResolver: async () => {
      if (replaceOnCredential) {
        await writeFile(stub.path, [
          "const args = process.argv.slice(2)",
          `await (await import('node:fs/promises')).writeFile(${JSON.stringify(marker)}, 'dispatched')`,
        ].join('\n'))
      }
      return {
        env: { ...process.env, REGISTRY_TOKEN: 'test-only-registry-token' },
        secret_values: ['test-only-registry-token'],
      }
    },
    env: { ...process.env, REGISTRY_TOKEN: 'test-only-registry-token' },
  })
  const planned = await adapter.plan(REQUEST)
  replaceOnCredential = true
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-dispatch-drift-out-')), 'ev')
  const written = await adapter.run(planned, { out })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.match(written.profile.coverage_gaps[0].reason, /executable identity/i)
  await assert.rejects(() => access(marker))
  const counters = JSON.parse(await readFile(join(out, 'payload', 'impact-counters.json'), 'utf8'))
  assert.deepEqual(
    { commands: counters.commands, objects_touched: counters.objects_touched },
    { commands: 0, objects_touched: 0 },
  )
})

test('plan refuses an unpinned reference', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, image: 'registry.example.com/example/application:latest' }),
    /digest|pinned/i,
  )
})

test('plan refuses without attestation, because built-artifact via registry requires it', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(() => adapter.plan({ ...REQUEST, attest_authorized: false }), /attest/i)
})

test('plan fails when crane is absent rather than succeeding emptily', async () => {
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: absentCliResolver,
  })
  await assert.rejects(() => adapter.plan(REQUEST), /crane|not found|absent/i)
})

test('the sealed plan carries a credential reference and no credential value', async () => {
  const adapter = await adapterWithStub()
  const planned = await adapter.plan(REQUEST)
  assert.equal(planned.credential_ref, 'env:REGISTRY_TOKEN')
  assert.equal(JSON.stringify(planned).includes('REGISTRY_TOKEN='), false)
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, credential_ref: 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }),
    /credential value/i,
  )
})

test('the version probe receives no target credential and retains no provider-controlled stdout', async () => {
  const secret = 'registry-version-probe-secret'
  const marker = join(await mkdtemp(join(tmpdir(), 'rta-registry-probe-env-')), 'credential-seen.txt')
  const stub = await stubCli('crane', `
    if (args[0] === 'version') {
      if (process.env.REGISTRY_TOKEN) {
        await (await import('node:fs/promises')).writeFile(${JSON.stringify(marker)}, process.env.REGISTRY_TOKEN)
      }
      process.stdout.write('provider-controlled-version-output')
    }
  `)
  const adapter = createRegistryAdapter({
    resolver: stub.resolver,
    env: { ...process.env, REGISTRY_TOKEN: secret },
  })
  const planned = await adapter.plan(REQUEST)
  assert.equal(planned.dependency.version, null)
  assert.equal(JSON.stringify(planned).includes(secret), false)
  await assert.rejects(() => access(marker))
})

test('run streams the manifest and blobs into a verifiable built-artifact bundle', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.deepEqual((await verifyEvidenceBundle(written.directory)).errors, [])
  assert.equal(written.profile.evidence_context.evidence_class, 'built-artifact')
  assert.equal(written.profile.artifact_kind, 'oci-image')
  assert.equal(written.profile.coverage_state, 'COVERED')
  assert.equal(written.profile.attestation.operator_id, 'gmaida')
  assert.equal(written.profile.attestation.credential_ref, 'env:REGISTRY_TOKEN')
  assert.equal(written.profile.evidence_context.target_identity, DIGEST)
})

test('a pull that fails authentication is NOT_ASSESSED with a redacted reason', async () => {
  const stub = await stubCli('crane', `
    if (args[0] === 'version') { process.stdout.write('0.19.1\\n') }
    else {
      process.stderr.write('UNAUTHORIZED for https://ci:hunter2@registry.example.com\\n')
      process.exit(1)
    }
  `)
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    credentialResolver: envCredentialResolver,
    env: { ...process.env, REGISTRY_TOKEN: 'test-only-registry-token' },
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.deepEqual(written.profile.files.map(({ path }) => path), ['payload/impact-counters.json'])
  const reason = written.profile.coverage_gaps[0].reason
  assert.match(reason, /crane manifest exited 1.*stderr withheld/i)
  assert.equal(reason.includes('hunter2'), false)
  assert.equal(reason.includes('test-only-registry-token'), false)
  const counters = JSON.parse(await readFile(join(out, 'payload', 'impact-counters.json'), 'utf8'))
  assert.equal(counters.commands, 1)
  assert.ok(counters.bytes_read > 0)
  assert.equal(counters.objects_touched, 1)
})

test('an env credential is derived as redaction material even when a resolver returns the same env object', async () => {
  const secret = 'review-secret-12345'
  const environment = { ...process.env, REGISTRY_TOKEN: secret }
  const stub = await stubCli('crane', `
    if (args[0] === 'version') process.stdout.write('0.19.1\\n')
    else { process.stderr.write('denied token=${secret}\\n'); process.exit(1) }
  `)
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    env: environment,
    credentialResolver: async (_reference, { env }) => ({ env }),
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  const manifest = await readFile(join(out, 'manifest.json'), 'utf8')
  assert.equal(manifest.includes(secret), false)
  assert.match(written.profile.coverage_gaps[0].reason, /stderr withheld/i)
})

test('registry failure evidence cannot persist an unclassified environment secret from stderr', async () => {
  const selectedSecret = 'selected-registry-secret'
  const unrelatedSecret = 'unclassified-environment-secret'
  const environment = {
    ...process.env,
    REGISTRY_TOKEN: selectedSecret,
    UNRELATED_PRIVATE_VALUE: unrelatedSecret,
  }
  const stub = await stubCli('crane', `
    if (args[0] === 'version') process.stdout.write('0.19.1\\n')
    else {
      process.stderr.write('denied ${unrelatedSecret} and ${selectedSecret}\\n')
      process.exit(1)
    }
  `)
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    env: environment,
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  const manifest = await readFile(join(out, 'manifest.json'), 'utf8')
  assert.equal(manifest.includes(selectedSecret), false)
  assert.equal(manifest.includes(unrelatedSecret), false)
  assert.match(written.profile.coverage_gaps[0].reason, /stderr withheld/i)
})

test('the registry adapter resolves env credentials without an injected provider', async () => {
  const stub = await craneStub()
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    env: { ...process.env, REGISTRY_TOKEN: 'test-only-registry-token' },
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.equal(written.profile.coverage_state, 'COVERED')
})

test('impact counters are recorded on the bundle', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  const counters = JSON.parse(
    (await readFile(join(written.directory, 'payload', 'impact-counters.json'))).toString('utf8'),
  )
  assert.equal(counters.commands, 4)
  assert.ok(counters.bytes_read > 0)
})

test('run refuses pulled bytes whose top-level OCI digest is not the requested identity', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const wrongDigest = `sha256:${'1'.repeat(64)}`
  const written = await adapter.run(await adapter.plan({
    ...REQUEST,
    image: `registry.example.com/example/application@${wrongDigest}`,
  }), { out })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.match(written.profile.coverage_gaps[0].reason, /requested manifest.*sha256 digest/i)
  assert.equal(written.profile.evidence_context.target_identity, wrongDigest)
})

test('non-environment credential references resolve only through an injected provider', async () => {
  const stub = await craneStub()
  const calls = []
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    credentialResolver: async (reference, context) => {
      calls.push({ reference, imageReference: context.imageReference })
      return {
        env: { ...process.env, REGISTRY_TOKEN: 'test-only-registry-token' },
        secret_values: ['test-only-registry-token'],
      }
    },
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const written = await adapter.run(await adapter.plan({
    ...REQUEST,
    credential_ref: 'keychain:example-registry',
  }), { out })
  assert.equal(written.profile.coverage_state, 'COVERED')
  assert.deepEqual(calls, [{ reference: 'keychain:example-registry', imageReference: REFERENCE }])
  const manifest = await readFile(join(written.directory, 'manifest.json'), 'utf8')
  assert.equal(manifest.includes('test-only-registry-token'), false)
})

test('registry output is halted while streaming when a manifest or blob byte cap is crossed', async () => {
  const stub = await stubCli('crane', `
    if (args[0] === 'version') process.stdout.write('0.19.1\\n')
    else process.stdout.write(Buffer.alloc(32 * 1024, 0x61))
  `)
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    credentialResolver: envCredentialResolver,
    env: { ...process.env, REGISTRY_TOKEN: 'test-only-registry-token' },
    limits: { maxStdoutBytes: 1024, maxTotalOutputBytes: 1024 },
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.match(written.profile.coverage_gaps[0].reason, /stdout_bytes|bounded|cap/i)
})

test('the bounded JSON policy caps the unknown top manifest before parsing it', async () => {
  const stub = await stubCli('crane', `
    if (args[0] === 'version') process.stdout.write('0.19.1\\n')
    else process.stdout.write(Buffer.alloc(32 * 1024, 0x61))
  `)
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    credentialResolver: envCredentialResolver,
    env: { ...process.env, REGISTRY_TOKEN: 'test-only-registry-token' },
    limits: {
      maxEntryBytes: 1024,
      maxStdoutBytes: 64 * 1024,
      maxTotalOutputBytes: 64 * 1024,
    },
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-json-cap-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.match(written.profile.coverage_gaps[0].reason, /stdout_bytes.*1024|bounded.*1024/i)
})

test('an exact-size manifest remains valid when crane emits bounded warning stderr', async () => {
  const config = Buffer.from(JSON.stringify({ history: [], rootfs: { diff_ids: [] } }))
  const configDigest = `sha256:${createHash('sha256').update(config).digest('hex')}`
  const document = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    config: { digest: configDigest, size: config.length },
    layers: [],
  }))
  const digest = `sha256:${createHash('sha256').update(document).digest('hex')}`
  const reference = `registry.example.com/example/application@${digest}`
  const stub = await stubCli('crane', `
    if (args[0] === 'version') process.stdout.write('0.19.1\\n')
    else {
      process.stderr.write('registry warning\\n')
      process.stdout.write(Buffer.from(args[0] === 'manifest'
        ? ${JSON.stringify(document.toString('base64'))}
        : ${JSON.stringify(config.toString('base64'))}, 'base64'))
    }
  `)
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    credentialResolver: envCredentialResolver,
    env: { ...process.env, REGISTRY_TOKEN: 'test-only-registry-token' },
    limits: { maxEntryBytes: document.length },
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-warning-')), 'ev')
  const written = await adapter.run(await adapter.plan({ ...REQUEST, image: reference }), { out })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.equal(written.profile.coverage_gaps.some(({ reason }) => /output|stdout.*cap/i.test(reason)), false)
  const counters = JSON.parse(await readFile(join(out, 'payload', 'impact-counters.json'), 'utf8'))
  assert.deepEqual(
    { commands: counters.commands, objects_touched: counters.objects_touched },
    { commands: 2, objects_touched: 2 },
  )
})

test('an oversized config descriptor is rejected before its registry object is dispatched', async () => {
  const configDigest = `sha256:${'c'.repeat(64)}`
  const document = Buffer.from(JSON.stringify({
    schemaVersion: 2,
    config: {
      mediaType: 'application/vnd.oci.image.config.v1+json',
      digest: configDigest,
      size: 1025,
    },
    layers: [],
  }))
  const digest = `sha256:${createHash('sha256').update(document).digest('hex')}`
  const reference = `registry.example.com/example/application@${digest}`
  const marker = join(await mkdtemp(join(tmpdir(), 'rta-registry-descriptor-cap-')), 'blob.txt')
  const stub = await stubCli('crane', `
    if (args[0] === 'version') process.stdout.write('0.19.1\\n')
    else if (args[0] === 'manifest') process.stdout.write(Buffer.from(${JSON.stringify(document.toString('base64'))}, 'base64'))
    else await (await import('node:fs/promises')).writeFile(${JSON.stringify(marker)}, 'blob dispatched')
  `)
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    credentialResolver: envCredentialResolver,
    env: { ...process.env, REGISTRY_TOKEN: 'test-only-registry-token' },
    limits: { maxEntryBytes: 1024 },
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-descriptor-cap-out-')), 'ev')
  const written = await adapter.run(await adapter.plan({ ...REQUEST, image: reference }), { out })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.match(written.profile.coverage_gaps[0].reason, /config.*1025.*bounded read limit.*1024/i)
  await assert.rejects(() => access(marker))
  const counters = JSON.parse(await readFile(join(out, 'payload', 'impact-counters.json'), 'utf8'))
  assert.deepEqual(
    { commands: counters.commands, objects_touched: counters.objects_touched },
    { commands: 1, objects_touched: 1 },
  )
})

test('a zero command budget stops before object accounting or target resolver dispatch', async () => {
  const stub = await craneStub()
  let targetResolverCalls = 0
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: (name, args, environment) => {
      if (args[0] !== 'version') targetResolverCalls += 1
      return stub.resolver(name, args, environment)
    },
    credentialResolver: envCredentialResolver,
    env: { ...process.env, REGISTRY_TOKEN: 'test-only-registry-token' },
    limits: { maxCommands: 0 },
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-command-cap-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.equal(targetResolverCalls, 0)
  const counters = JSON.parse(await readFile(join(out, 'payload', 'impact-counters.json'), 'utf8'))
  assert.deepEqual(
    { commands: counters.commands, objects_touched: counters.objects_touched },
    { commands: 0, objects_touched: 0 },
  )
})

test('registry archive construction refuses before allocating beyond its archive budget', async () => {
  const stub = await craneStub()
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    resolver: stub.resolver,
    credentialResolver: envCredentialResolver,
    env: { ...process.env, REGISTRY_TOKEN: 'test-only-registry-token' },
    limits: { maxArchiveBytes: 1024 },
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-archive-cap-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.match(written.profile.coverage_gaps[0].reason, /archive.*bounded limit.*1024 bytes/i)
})
