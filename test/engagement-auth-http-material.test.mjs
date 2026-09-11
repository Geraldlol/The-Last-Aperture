import assert from 'node:assert/strict'
import { mkdtemp, mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'
import { test } from 'node:test'

import {
  createEngagementAuthority,
  createEngagementManifest,
} from '../scripts/lib/engagement-authorization.mjs'
import { createEngagementIntake } from '../scripts/lib/engagement-contracts.mjs'
import {
  deriveEngagementAuthHttpMaterial,
} from '../scripts/lib/engagement-auth-http-material.mjs'
import { readAndVerifyHttpAuthedAuthorization } from '../scripts/lib/http-authed-contracts.mjs'
import { buildEngagementRouteInvocation } from '../scripts/lib/engagement-route-registry.mjs'

const DECLARED_AT = '2026-09-12T09:00:00.000Z'
const ISSUED_AT = new Date('2026-09-12T10:00:00.000Z')
const EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop'

async function fixture(t, {
  target = 'https://target.example/app',
  credentialReferences = ['browser-session:primary'],
} = {}) {
  const parent = await mkdtemp(join(tmpdir(), 'last-aperture-auth-http-material-'))
  t.after(() => rm(parent, { recursive: true, force: true }))
  const bundle = join(parent, 'engagement')
  await mkdir(join(bundle, 'routes', 'authenticated-http-browser'), { recursive: true })
  const intake = await createEngagementIntake({
    operatorId: 'operator:workspace-owner',
    declaredAt: DECLARED_AT,
    statement: 'I own or am authorized to perform the full assessment of this target.',
    objective: 'Assess the authenticated application surface.',
    target,
    authorizationProfile: 'full',
    credentialReferences,
    inputs: [],
  })
  const authority = createEngagementAuthority({
    engagementId: 'engagement:auth-http-material-test',
    operatorId: intake.operator_id,
    declaredAt: intake.declared_at,
    statement: intake.statement,
    objective: intake.objective,
    target: intake.target,
    authorizationProfile: intake.authorization_profile,
    credentialReferences: intake.credential_references,
  })
  const manifest = createEngagementManifest({
    platformVersion: '0.14.0',
    engagementId: authority.engagement_id,
    createdAt: '2026-09-12T09:00:00.001Z',
    objective: authority.objective,
    target: authority.target,
    intake,
    authority,
    routeRegistryVersion: '1.2.0',
  })
  return { parent, bundle, intake, authority, manifest }
}

function browserAdapter(extensionId = EXTENSION_ID) {
  return async ({ browserCredentialReferences, target }) => {
    assert.deepEqual(browserCredentialReferences, ['browser-session:primary'])
    assert.deepEqual(target, { kind: 'https', locator: 'https://target.example/app' })
    return { extensionId }
  }
}

test('derives target-bound browser campaign material accepted by the route registry', async (t) => {
  const { bundle, authority, manifest } = await fixture(t)
  const material = await deriveEngagementAuthHttpMaterial({ bundle, authority, manifest }, {
    resolveBrowserCredential: browserAdapter(),
    now: () => ISSUED_AT,
  })

  assert.equal(material.state, 'READY')
  assert.equal(material.route_id, 'authenticated-http-browser')
  assert.equal(material.material.operator_id, authority.operator_id)
  assert.equal(material.material.credential_transport, 'browser')
  assert.equal(material.material.ledger_directory, join(
    bundle, 'routes', 'authenticated-http-browser', 'campaign-ledger',
  ))
  assert.equal(material.material.materials_directory, join(
    bundle, 'routes', 'authenticated-http-browser', 'campaign-materials',
  ))
  assert.equal((await stat(material.material.ledger_directory)).isDirectory(), true)
  assert.equal((await stat(material.material.materials_directory)).isDirectory(), true)

  const verified = await readAndVerifyHttpAuthedAuthorization({
    scopePath: material.material.scope_path,
    requiredMode: 'OPERATOR_ATTESTED_AUTHED',
    now: ISSUED_AT,
  })
  assert.equal(material.material.campaign_grant_sha256, verified.campaignGrantSha256)
  assert.equal(
    basename(material.material.scope_path),
    `scope-${material.material.campaign_grant_sha256}.json`,
  )
  assert.equal(verified.scope.target.origin, 'https://target.example')
  assert.deepEqual(verified.scope.authorization.authorized_scope.path_prefixes, ['/app'])
  assert.equal(verified.scope.requests[0].url, 'https://target.example/app')
  assert.deepEqual(verified.scope.credential, {
    mode: 'CHROME_ACTIVE_TAB_SESSION',
    extension_id: EXTENSION_ID,
    origin: 'https://target.example',
  })
  assert.equal(verified.scope.evidence_handling.persist_credential_values, false)

  const persisted = await readFile(material.material.scope_path, 'utf8')
  assert.equal(persisted.includes('browser-session:primary'), false)
  assert.equal(persisted.includes('must-not-cross-this-boundary'), false)

  const invocation = buildEngagementRouteInvocation(
    'authenticated-http-browser',
    material.material,
  )
  assert.equal(invocation.shell, false)
  assert.equal(invocation.arguments.includes('--credential-browser'), true)
  assert.equal(invocation.arguments.includes(material.material.campaign_grant_sha256), true)

  const resumed = await deriveEngagementAuthHttpMaterial({ bundle, authority, manifest }, {
    resolveBrowserCredential: browserAdapter(),
    now: () => new Date(ISSUED_AT.getTime() + 1_000),
  })
  assert.deepEqual(resumed, material)
})

test('returns explicit adapter-required states without creating route material', async (t) => {
  const withoutReference = await fixture(t, { credentialReferences: [] })
  let called = false
  const referenceResult = await deriveEngagementAuthHttpMaterial({
    bundle: withoutReference.bundle,
    authority: withoutReference.authority,
    manifest: withoutReference.manifest,
  }, {
    resolveBrowserCredential: async () => {
      called = true
      return { extensionId: EXTENSION_ID }
    },
  })
  assert.deepEqual(referenceResult, {
    state: 'ADAPTER_REQUIRED',
    route_id: 'authenticated-http-browser',
    reason_code: 'BROWSER_CREDENTIAL_REFERENCE_REQUIRED',
  })
  assert.equal(called, false)

  const withReference = await fixture(t)
  const adapterResult = await deriveEngagementAuthHttpMaterial({
    bundle: withReference.bundle,
    authority: withReference.authority,
    manifest: withReference.manifest,
  })
  assert.deepEqual(adapterResult, {
    state: 'ADAPTER_REQUIRED',
    route_id: 'authenticated-http-browser',
    reason_code: 'BROWSER_CREDENTIAL_ADAPTER_REQUIRED',
  })

  const unavailable = await deriveEngagementAuthHttpMaterial({
    bundle: withReference.bundle,
    authority: withReference.authority,
    manifest: withReference.manifest,
  }, { resolveBrowserCredential: async () => null })
  assert.equal(unavailable.reason_code, 'BROWSER_CREDENTIAL_ADAPTER_UNAVAILABLE')
})

test('rejects manifest target drift before resolving a browser credential', async (t) => {
  const first = await fixture(t)
  const second = await fixture(t, { target: 'https://other.example/app' })
  let called = false

  await assert.rejects(
    deriveEngagementAuthHttpMaterial({
      bundle: first.bundle,
      authority: first.authority,
      manifest: second.manifest,
    }, {
      resolveBrowserCredential: async () => {
        called = true
        return { extensionId: EXTENSION_ID }
      },
      now: () => ISSUED_AT,
    }),
    (error) => error.code === 'ENGAGEMENT_AUTHORITY_TARGET_MISMATCH',
  )
  assert.equal(called, false)
})

test('rejects retained scope and named credential binding drift', async (t) => {
  const { bundle, authority, manifest } = await fixture(t)
  const first = await deriveEngagementAuthHttpMaterial({ bundle, authority, manifest }, {
    resolveBrowserCredential: browserAdapter(),
    now: () => ISSUED_AT,
  })

  await assert.rejects(
    deriveEngagementAuthHttpMaterial({ bundle, authority, manifest }, {
      resolveBrowserCredential: browserAdapter('b'.repeat(32)),
      now: () => new Date(ISSUED_AT.getTime() + 1_000),
    }),
    (error) => error.code === 'ENGAGEMENT_AUTH_HTTP_SCOPE_BINDING_DRIFT',
  )

  const scope = JSON.parse(await readFile(first.material.scope_path, 'utf8'))
  for (const target of [
    scope.target,
    scope.credential,
  ]) target.origin = 'https://drift.example'
  scope.authorization.authorized_scope.origins = ['https://drift.example']
  scope.liveness.credential_preflight.url = 'https://drift.example/app'
  scope.discovery.origin = 'https://drift.example'
  scope.requests[0].url = 'https://drift.example/app'
  await writeFile(first.material.scope_path, JSON.stringify(scope), 'utf8')

  await assert.rejects(
    deriveEngagementAuthHttpMaterial({ bundle, authority, manifest }, {
      resolveBrowserCredential: browserAdapter(),
      now: () => new Date(ISSUED_AT.getTime() + 2_000),
    }),
    (error) => error.code === 'ENGAGEMENT_AUTH_HTTP_SCOPE_BINDING_DRIFT',
  )
})

test('refuses adapter fields that could smuggle credential values', async (t) => {
  const { bundle, authority, manifest } = await fixture(t)
  await assert.rejects(
    deriveEngagementAuthHttpMaterial({ bundle, authority, manifest }, {
      resolveBrowserCredential: async () => ({
        extensionId: EXTENSION_ID,
        credentialValue: 'must-not-cross-this-boundary',
      }),
      now: () => ISSUED_AT,
    }),
    (error) => error.code === 'ENGAGEMENT_AUTH_HTTP_ADAPTER_RESULT_INVALID',
  )
})

test('refuses creation of a sixty-fifth create-only scope', async (t) => {
  const { bundle, authority, manifest } = await fixture(t)
  const lifetimeAndOneMillisecond = (60 * 60 * 1000) + 1
  for (let index = 0; index < 64; index += 1) {
    const result = await deriveEngagementAuthHttpMaterial({ bundle, authority, manifest }, {
      resolveBrowserCredential: browserAdapter(),
      now: () => new Date(ISSUED_AT.getTime() + (index * lifetimeAndOneMillisecond)),
    })
    assert.equal(result.state, 'READY')
  }

  await assert.rejects(
    deriveEngagementAuthHttpMaterial({ bundle, authority, manifest }, {
      resolveBrowserCredential: browserAdapter(),
      now: () => new Date(ISSUED_AT.getTime() + (64 * lifetimeAndOneMillisecond)),
    }),
    (error) => error.code === 'ENGAGEMENT_AUTH_HTTP_SCOPE_LIMIT',
  )
  assert.equal((await readdir(join(
    bundle, 'routes', 'authenticated-http-browser', 'scopes',
  ))).length, 64)
})
