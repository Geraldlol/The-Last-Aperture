import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { lstat, mkdtemp, mkdir, readFile, readdir, realpath, rename, rm, symlink, unlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'

import {
  canonicalEngagementJson,
  canonicalEngagementAuthority,
  canonicalEngagementManifest,
} from '../scripts/lib/engagement-contracts.mjs'
import { openHttpAuthedCampaignLedger } from '../scripts/lib/http-authed-campaign-ledger.mjs'
import {
  httpAuthedAuthorizationEvidence,
  readAndVerifyHistoricalHttpAuthedAuthorization,
} from '../scripts/lib/http-authed-contracts.mjs'
import { openEngagementLedger } from '../scripts/lib/engagement-ledger.mjs'
import { planHttpAuthedAttestedScope } from '../scripts/lib/http-authed-planner.mjs'
import {
  planOperatorAttestedHttpReconBundle,
} from '../scripts/lib/http-recon-controller.mjs'
import {
  canonicalWebSessionEvidence,
  importWebSessionEvidence,
  importWebHarEvidence,
} from '../scripts/lib/reverse-web-har.mjs'
import {
  importVerifiedHttpAuthedSessionEvidence,
  importVerifiedHttpReconSessionEvidence,
} from '../scripts/lib/reverse-web-live.mjs'
import {
  finalizeRepositoryWork,
  getRepositoryNextWork,
  getRepositoryWorkStatus,
  getEngagementStatus,
  resumeEngagement,
  startEngagement,
  stopEngagement,
  submitRepositoryWork,
  validateRepositoryWork,
} from '../scripts/lib/engagement-controller.mjs'

function clock(start = Date.parse('2026-09-11T12:00:00.000Z')) {
  let tick = start
  return () => new Date(tick++).toISOString()
}

async function fixture(t, name) {
  const parent = await mkdtemp(join(tmpdir(), `last-aperture-engagement-${name}-`))
  t.after(() => rm(parent, { recursive: true, force: true }))
  return { parent, bundle: join(parent, 'engagement') }
}

function dependencies(overrides = {}) {
  return {
    now: clock(),
    engagementId: 'engagement:controller-test',
    operatorId: 'operator:workspace-owner',
    executeRoute: async ({ routeId, bundle }) => {
      await writeSuccessfulRouteOutput({ routeId, bundle })
      return {
        status: 'SUCCEEDED',
        exitCode: 0,
        signal: null,
        timedOut: false,
        requestMayHaveBeenSent: true,
        stdout: '{"status":"SUCCEEDED"}',
        stderr: '',
      }
    },
    ...overrides,
  }
}

async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf8'))
}

async function writeSuccessfulRouteOutput({
  routeId,
  bundle,
  targetUrl = 'https://target.example/',
  har = { log: { entries: [] } },
}) {
  const route = join(bundle, 'routes', routeId)
  if (routeId === 'https-recon') {
    const declaredAt = '2026-09-11T12:00:00.000Z'
    const operatorAuthorization = {
      schema_version: '1.0.0',
      kind: 'red-team-audit/operator-authorization',
      status: 'OPERATOR_ASSERTED_AUTHORIZED',
      operator_id: 'operator:workspace-owner',
      declared_at: declaredAt,
      authorization_reference: 'engagement-controller-test',
      statement: 'I confirm I am authorized to test this exact HTTPS target.',
      target: { kind: 'https_url', url: targetUrl },
    }
    await planOperatorAttestedHttpReconBundle({
      targetUrl,
      operatorId: operatorAuthorization.operator_id,
      authorizedBy: operatorAuthorization.operator_id,
      authorizationReference: operatorAuthorization.authorization_reference,
      operatorAuthorization,
      out: join(route, 'http-recon'),
      now: () => new Date(declaredAt),
      randomBytesImpl: (size) => Buffer.alloc(size, 7),
    })
  } else if (routeId === 'repository-audit') {
    await mkdir(join(route, 'audit-bundle'))
    await mkdir(join(route, 'audit-bundle', 'audit-run-1'))
  } else if (routeId === 'web-capture-har-import') {
    const captureBytes = Buffer.from(JSON.stringify(har), 'utf8')
    const target = new URL(targetUrl)
    const pathLiterals = target.pathname.split('/').filter((value) => /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/u.test(value))
    const evidence = importWebHarEvidence(har, {
      sourceSha256: createHash('sha256').update(captureBytes).digest('hex'),
      targetOrigins: [target.origin],
      pathLiterals,
    })
    await writeFile(join(route, 'evidence.json'), canonicalWebSessionEvidence(evidence), 'utf8')
  }
}

function invocationValue(invocation, flag) {
  const index = invocation.arguments.indexOf(flag)
  return index === -1 ? undefined : invocation.arguments[index + 1]
}

function invocationValues(invocation, flag) {
  const values = []
  for (let index = 0; index < invocation.arguments.length; index += 1) {
    if (invocation.arguments[index] === flag) values.push(invocation.arguments[index + 1])
  }
  return values
}

async function initializeAuthenticatedCampaign(invocation) {
  const scopePath = invocationValue(invocation, '--scope')
  const ledgerDirectory = invocationValue(invocation, '--ledger')
  const verified = await readAndVerifyHistoricalHttpAuthedAuthorization({
    scopePath,
    requiredMode: 'OPERATOR_ATTESTED_AUTHED',
  })
  const assurance = httpAuthedAuthorizationEvidence(verified.scope)
  const ledger = await openHttpAuthedCampaignLedger({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: assurance.authorizationMode,
    independentlyVerified: assurance.independentlyVerified,
    operatorId: verified.scope.authorization.operator_id,
    initialize: true,
    now: () => new Date(verified.scope.authorization.attested_at),
  })
  try {
    for (const action of verified.scope.requests.filter(({ kind }) => kind === 'probe')) {
      await ledger.enqueueCandidate({ candidateDraft: action, provenance: 'SEALED_PLAN' })
    }
  } finally {
    await ledger.close()
  }
}

function liveProjectionOptions(invocation) {
  return {
    targetOrigins: invocationValues(invocation, '--origin'),
    targetPathPrefix: invocationValue(invocation, '--path-prefix'),
    pathLiterals: invocationValues(invocation, '--path-literal'),
  }
}

async function writeExactLiveEvidence(invocation, { omitAuth = false } = {}) {
  const output = invocationValue(invocation, '--out')
  await mkdir(output)
  const options = liveProjectionOptions(invocation)
  const recon = await importVerifiedHttpReconSessionEvidence({
    bundle: invocationValue(invocation, '--recon-bundle'),
    ...options,
  })
  await writeFile(join(output, 'http-recon.json'), canonicalWebSessionEvidence(recon), 'utf8')
  const scopePath = invocationValue(invocation, '--auth-scope')
  if (scopePath !== undefined && !omitAuth) {
    const auth = await importVerifiedHttpAuthedSessionEvidence({
      scopePath,
      ledgerDirectory: invocationValue(invocation, '--auth-ledger'),
      ...options,
    })
    await writeFile(join(output, 'authenticated-campaign.json'), canonicalWebSessionEvidence(auth), 'utf8')
  }
  return { output, options, recon }
}

async function runLiveEvidenceScenario(t, name, { withAuth = false, writeOutput }) {
  const { bundle } = await fixture(t, name)
  const result = await startEngagement({
    target: 'https://target.example/app',
    statement: 'I own this target and authorize its full authenticated assessment.',
    authorizationProfile: 'full',
    objective: 'Validate exact live metadata provenance.',
    ...(withAuth ? { credentialReferences: ['browser-session:primary'] } : {}),
    out: bundle,
  }, dependencies({
    ...(withAuth
      ? { resolveBrowserCredential: async () => ({ extensionId: TEST_EXTENSION_ID }) }
      : {}),
    executeRoute: async ({ routeId, invocation, bundle: activeBundle }) => {
      if (routeId === 'https-recon') {
        await writeSuccessfulRouteOutput({
          routeId,
          bundle: activeBundle,
          targetUrl: 'https://target.example/app',
        })
        return { status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false, requestMayHaveBeenSent: true, stdout: '', stderr: '' }
      }
      if (routeId === 'authenticated-http-browser') {
        await initializeAuthenticatedCampaign(invocation)
        return { status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false, requestMayHaveBeenSent: true, stdout: '', stderr: '' }
      }
      if (routeId === 'web-live-metadata-import') {
        await writeOutput(invocation)
        return { status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false, requestMayHaveBeenSent: false, stdout: '', stderr: '' }
      }
      return { status: 'FAILED', exitCode: 1, signal: null, timedOut: false, requestMayHaveBeenSent: false, stdout: '', stderr: 'fixture stop' }
    },
  }))
  return {
    bundle,
    result,
    routeResult: await readJson(join(bundle, 'routes', 'web-live-metadata-import', 'result.json')),
  }
}

function repositoryPacket() {
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'LENS',
    run_id: 'audit-run-1',
    job_id: 'lens:authorization:0001',
    lens: 'authorization',
    inputs: [],
  }
  return {
    ...unsigned,
    packet_sha256: createHash('sha256').update(`${canonicalEngagementJson(unsigned)}\n`, 'utf8').digest('hex'),
  }
}

function repositoryChildStatus(overrides = {}) {
  return {
    schema_version: '1.0.0',
    run_id: 'audit-run-1',
    state: 'RUNNING',
    phase: 'FANOUT',
    terminal: false,
    target: 'redacted',
    capability_mode: 'T0',
    source_sealed: false,
    jobs: {
      total: 1,
      by_state: { PENDING: 0, RUNNING: 0, SUCCEEDED: 1 },
      by_kind: { LENS: 1 },
      pending_current_phase: { total: 0, items: [], omitted: 0 },
      running: { total: 0, items: [], omitted: 0 },
      failed: { total: 0, items: [], omitted: 0 },
    },
    active_attempts: { total: 0, items: [], omitted: 0 },
    findings: { status: 'NO_FINDINGS_REPORTED', reported: 0, retained: 0, removed: 0 },
    coverage: { inventory_files: 1, examined_files: 1, unexamined_files: 0 },
    errors: { total: 0, items: [], omitted: 0 },
    next_step: { code: 'INSPECT_PENDING_WORK' },
    bundle_integrity: 'VERIFIED',
    root_authenticity: 'UNANCHORED',
    live_repository: 'NOT_CHECKED',
    ...overrides,
  }
}

const TEST_EXTENSION_ID = 'abcdefghijklmnopabcdefghijklmnop'

function pageSessionAdapter() {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/page-session-adapter',
    adapter_id: 'controller-test-session',
    source: {
      type: 'WEB_STORAGE',
      area: 'LOCAL',
      key: 'synthetic.session',
      extraction: { mode: 'RAW' },
    },
    carrier: {
      type: 'REQUEST_HEADER',
      name: 'authorization',
      prefix: 'Bearer ',
    },
    target_constraints: ['GET', 'HEAD', 'OPTIONS'].map((method) => ({
      origin: 'https://target.example',
      method,
      path_prefix: '/app',
    })),
    validity: {
      not_before: '2026-09-01T00:00:00.000Z',
      not_after: '2026-10-01T00:00:00.000Z',
    },
    limits: { max_value_bytes: 4096 },
  }
}

test('start persists one exact authority and canonical create-only engagement bundle', async (t) => {
  const { bundle } = await fixture(t, 'start')
  const statement = 'I own this target and authorize the full assessment.\nCodex and Claude may continue this engagement.'
  let dispatchSnapshot

  const result = await startEngagement({
    target: 'https://target.example/app',
    statement,
    authorizationProfile: 'full',
    objective: 'Assess and reconstruct every reachable application interaction.',
    out: bundle,
  }, dependencies({
    executeRoute: async ({ routeId, invocation, bundle: activeBundle, binding }) => {
      assert.equal(routeId, 'https-recon')
      assert.equal(invocation.public_entrypoint, process.execPath)
      assert.equal(invocation.shell, false)
      assert.equal(Array.isArray(invocation.arguments), true)
      assert.equal(invocation.arguments.includes('https://target.example/app'), true)
      const ledger = await openEngagementLedger({
        directory: join(activeBundle, 'ledger'),
        binding,
        initialize: false,
      })
      dispatchSnapshot = ledger.snapshot()
      await writeSuccessfulRouteOutput({ routeId, bundle: activeBundle })
      return {
        status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false,
        requestMayHaveBeenSent: true, stdout: '{"status":"SUCCEEDED"}', stderr: '',
      }
    },
  }))

  assert.equal(result.status, 'WAITING_FOR_MATERIAL')
  assert.deepEqual(result.completed_routes, ['https-recon'])
  assert.equal(result.waiting_routes.includes('authenticated-http-browser'), true)
  assert.equal(result.waiting_routes.includes('web-capture-har-import'), true)
  assert.deepEqual(
    result.unavailable_routes.find(({ route_id: routeId }) => routeId === 'bounty-recon'),
    { route_id: 'bounty-recon', reason_code: 'BOUNTY_RECON_LIVE_IO_DISABLED' },
  )

  const intakeBytes = await readFile(join(bundle, 'intake.json'), 'utf8')
  const authorityBytes = await readFile(join(bundle, 'authorization.json'), 'utf8')
  const manifestBytes = await readFile(join(bundle, 'engagement.json'), 'utf8')
  const intake = JSON.parse(intakeBytes)
  const authority = JSON.parse(authorityBytes)
  const manifest = JSON.parse(manifestBytes)
  assert.equal(intakeBytes, canonicalEngagementJson(intake))
  assert.equal(authorityBytes, canonicalEngagementAuthority(authority))
  assert.equal(manifestBytes, canonicalEngagementManifest(manifest))
  assert.equal(authority.statement, statement)
  assert.equal(authority.statement_sha256, createHash('sha256').update(statement, 'utf8').digest('hex'))
  assert.equal(result.authorization_sha256, manifest.authority_sha256)

  const dispatched = dispatchSnapshot.routes.find(({ route_id: routeId }) => routeId === 'https-recon')
  assert.equal(dispatched.state, 'DISPATCH_PERMITTED')
  assert.match(dispatched.permit_sha256, /^[a-f0-9]{64}$/)
  assert.equal(dispatchSnapshot.routes.length, 18, 'all applicable routes are planned before dispatch')

  await assert.rejects(
    startEngagement({
      target: 'https://target.example/app', statement, objective: authority.objective, out: bundle,
      authorizationProfile: 'full',
    }, dependencies()),
    (error) => error.code === 'ENGAGEMENT_BUNDLE_EXISTS',
  )
})

test('a trusted browser resolver makes authenticated HTTP ready and binds every child output', async (t) => {
  const { bundle } = await fixture(t, 'authenticated-http-resolver')
  let resolverCalls = 0
  let authenticatedInvocation
  const workDependencies = dependencies({
    resolveBrowserCredential: async (request) => {
      resolverCalls += 1
      assert.equal(Object.isFrozen(request), true)
      assert.deepEqual(request.browserCredentialReferences, ['browser-session:primary'])
      return {
        credentialReference: 'browser-session:primary',
        extensionId: TEST_EXTENSION_ID,
      }
    },
    executeRoute: async ({ routeId, invocation, bundle: activeBundle }) => {
      await writeSuccessfulRouteOutput({ routeId, bundle: activeBundle })
      if (routeId === 'authenticated-http-browser') authenticatedInvocation = invocation
      return {
        status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false,
        requestMayHaveBeenSent: true, stdout: '{"status":"SUCCEEDED"}', stderr: '',
      }
    },
  })

  const result = await startEngagement({
    target: 'https://target.example/app',
    statement: 'I own this target and authorize its full authenticated assessment.',
    authorizationProfile: 'full',
    objective: 'Map the authenticated application protocol.',
    credentialReferences: ['browser-session:primary'],
    out: bundle,
  }, workDependencies)

  assert.equal(resolverCalls, 1)
  assert.equal(result.completed_routes.includes('authenticated-http-browser'), true)
  assert.equal(authenticatedInvocation.shell, false)
  assert.equal(authenticatedInvocation.arguments.includes('--credential-browser'), true)
  const route = join(bundle, 'routes', 'authenticated-http-browser')
  const routeResult = await readJson(join(route, 'result.json'))
  assert.deepEqual(
    routeResult.output_bindings.map(({ root_relative_path }) => root_relative_path),
    ['campaign-ledger', 'campaign-materials', 'scopes'],
  )

  const ledgerTamper = join(route, 'campaign-ledger', 'rollback-or-tamper.json')
  await writeFile(ledgerTamper, '{}\n')
  await assert.rejects(
    getEngagementStatus({ bundle }, workDependencies),
    (error) => error.code === 'ENGAGEMENT_ROUTE_OUTPUT_DRIFT',
  )
  await unlink(ledgerTamper)
  await getEngagementStatus({ bundle }, workDependencies)

  const [scopeName] = await readdir(join(route, 'scopes'))
  await writeFile(join(route, 'scopes', scopeName), '{}\n')
  await assert.rejects(
    getEngagementStatus({ bundle }, workDependencies),
    (error) => error.code === 'ENGAGEMENT_ROUTE_OUTPUT_DRIFT',
  )
})

test('verified live metadata feeds protocol construction without a supplied capture', async (t) => {
  const { bundle } = await fixture(t, 'live-metadata-protocol')
  const called = []
  let stagedRecon
  let stagedEvidence
  const result = await startEngagement({
    target: 'https://target.example/app',
    statement: 'I own this target and authorize its full assessment.',
    authorizationProfile: 'full',
    objective: 'Construct a native interaction from live target metadata.',
    out: bundle,
  }, dependencies({
    executeRoute: async ({ routeId, invocation, bundle: activeBundle }) => {
      called.push(routeId)
      if (routeId === 'https-recon') {
        await writeSuccessfulRouteOutput({ routeId, bundle: activeBundle })
        return { status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false, requestMayHaveBeenSent: true, stdout: '', stderr: '' }
      }
      if (routeId === 'web-live-metadata-import') {
        const reconFlag = invocation.arguments.indexOf('--recon-bundle')
        stagedRecon = invocation.arguments[reconFlag + 1]
        assert.notEqual(stagedRecon, join(activeBundle, 'routes', 'https-recon', 'http-recon'))
        await writeExactLiveEvidence(invocation)
        return { status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false, requestMayHaveBeenSent: false, stdout: '', stderr: '' }
      }
      if (routeId === 'protocol-build') {
        const evidenceFlag = invocation.arguments.indexOf('--web-evidence')
        stagedEvidence = invocation.arguments[evidenceFlag + 1]
        assert.notEqual(stagedEvidence, join(activeBundle, 'routes', 'web-live-metadata-import', 'evidence', 'http-recon.json'))
      }
      return { status: 'FAILED', exitCode: 1, signal: null, timedOut: false, requestMayHaveBeenSent: false, stdout: '', stderr: 'fixture stop' }
    },
  }))

  assert.deepEqual(called, ['https-recon', 'web-live-metadata-import', 'protocol-build'])
  assert.equal(result.completed_routes.includes('web-live-metadata-import'), true)
  assert.equal(typeof stagedRecon, 'string')
  assert.equal(typeof stagedEvidence, 'string')
})

test('live metadata rejects a wrong reconnaissance source digest', async (t) => {
  const { routeResult } = await runLiveEvidenceScenario(t, 'live-wrong-recon-digest', {
    writeOutput: async (invocation) => {
      const { output, options } = await writeExactLiveEvidence(invocation)
      const forged = importWebSessionEvidence([], {
        sourceKind: 'HTTP_RECON',
        sourceSha256: 'f'.repeat(64),
        ...options,
        deriveHeaderValues: false,
      })
      await writeFile(join(output, 'http-recon.json'), canonicalWebSessionEvidence(forged), 'utf8')
    },
  })
  assert.equal(routeResult.error_code, 'ENGAGEMENT_ROUTE_SCOPE_INVALID')
})

test('live metadata rejects fabricated in-scope entries with the correct source digest', async (t) => {
  const { routeResult } = await runLiveEvidenceScenario(t, 'live-invented-recon-entry', {
    writeOutput: async (invocation) => {
      const { output, options, recon } = await writeExactLiveEvidence(invocation)
      const forged = importWebSessionEvidence([{
        startedDateTime: '2026-09-11T12:00:00.000Z',
        time: 1,
        request: {
          method: 'GET', url: 'https://target.example/app/invented', headers: [], cookies: [],
        },
        response: { status: 299, headers: [], cookies: [], content: {} },
      }], {
        sourceKind: 'HTTP_RECON',
        sourceSha256: recon.source.sha256,
        ...options,
        deriveHeaderValues: false,
      })
      await writeFile(join(output, 'http-recon.json'), canonicalWebSessionEvidence(forged), 'utf8')
    },
  })
  assert.equal(routeResult.error_code, 'ENGAGEMENT_ROUTE_SCOPE_INVALID')
})

test('recon-only live metadata rejects a forged authenticated evidence file', async (t) => {
  const { routeResult } = await runLiveEvidenceScenario(t, 'live-forged-auth-membership', {
    writeOutput: async (invocation) => {
      const { output, options } = await writeExactLiveEvidence(invocation)
      const forged = importWebSessionEvidence([], {
        sourceKind: 'HTTP_AUTHED_CAMPAIGN',
        sourceSha256: 'e'.repeat(64),
        ...options,
        deriveHeaderValues: false,
      })
      await writeFile(join(output, 'authenticated-campaign.json'), canonicalWebSessionEvidence(forged), 'utf8')
    },
  })
  assert.equal(routeResult.error_code, 'ENGAGEMENT_ROUTE_OUTPUT_INVALID')
})

test('authenticated live metadata requires both exact projected files', async (t) => {
  const { routeResult } = await runLiveEvidenceScenario(t, 'live-missing-auth-output', {
    withAuth: true,
    writeOutput: (invocation) => writeExactLiveEvidence(invocation, { omitAuth: true }),
  })
  assert.equal(routeResult.error_code, 'ENGAGEMENT_ROUTE_OUTPUT_INVALID')
})

test('authenticated live metadata rejects a wrong authenticated source digest', async (t) => {
  const { routeResult } = await runLiveEvidenceScenario(t, 'live-wrong-auth-digest', {
    withAuth: true,
    writeOutput: async (invocation) => {
      const { output, options } = await writeExactLiveEvidence(invocation)
      const forged = importWebSessionEvidence([], {
        sourceKind: 'HTTP_AUTHED_CAMPAIGN',
        sourceSha256: 'd'.repeat(64),
        ...options,
        deriveHeaderValues: false,
      })
      await writeFile(join(output, 'authenticated-campaign.json'), canonicalWebSessionEvidence(forged), 'utf8')
    },
  })
  assert.equal(routeResult.error_code, 'ENGAGEMENT_ROUTE_SCOPE_INVALID')
})

test('authenticated live metadata accepts the exact deterministic source projection', async (t) => {
  const { routeResult } = await runLiveEvidenceScenario(t, 'live-exact-auth-projection', {
    withAuth: true,
    writeOutput: writeExactLiveEvidence,
  })
  assert.equal(routeResult.status, 'SUCCEEDED')
})

test('resume selects the successful auth invocation scope from retained expired history', async (t) => {
  const { bundle } = await fixture(t, 'auth-scope-history-resume')
  const invocationPath = join(bundle, 'routes', 'authenticated-http-browser', 'invocation.json')
  let nowMs = Date.parse('2026-09-12T12:00:00.000Z')
  let blockFirstInvocation = true
  let successfulScopePath
  let importedScope
  const workDependencies = dependencies({
    now: () => new Date(nowMs++).toISOString(),
    resolveBrowserCredential: async () => ({ extensionId: TEST_EXTENSION_ID }),
    planAuthHttpScope: async (input, plannerDependencies) => {
      const planned = await planHttpAuthedAttestedScope(input, plannerDependencies)
      if (blockFirstInvocation) {
        blockFirstInvocation = false
        await mkdir(invocationPath)
      }
      return planned
    },
    executeRoute: async ({ routeId, invocation, bundle: activeBundle }) => {
      if (routeId === 'https-recon') await writeSuccessfulRouteOutput({ routeId, bundle: activeBundle })
      if (routeId === 'authenticated-http-browser') {
        successfulScopePath = invocation.arguments[invocation.arguments.indexOf('--scope') + 1]
      }
      if (routeId === 'web-live-metadata-import') {
        const stagedScope = invocation.arguments[invocation.arguments.indexOf('--auth-scope') + 1]
        importedScope = await readJson(stagedScope)
        return {
          status: 'FAILED', exitCode: 1, signal: null, timedOut: false,
          requestMayHaveBeenSent: false, stdout: '', stderr: 'fixture stop after material verification',
        }
      }
      return {
        status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false,
        requestMayHaveBeenSent: true, stdout: '', stderr: '',
      }
    },
  })

  await assert.rejects(startEngagement({
    target: 'https://target.example/app',
    statement: 'I own this target and authorize its full authenticated assessment.',
    authorizationProfile: 'full',
    objective: 'Retain exact authenticated protocol evidence across a controller restart.',
    credentialReferences: ['browser-session:primary'],
    out: bundle,
  }, workDependencies))
  const scopesDirectory = join(bundle, 'routes', 'authenticated-http-browser', 'scopes')
  assert.equal((await readdir(scopesDirectory)).length, 1)
  await rm(invocationPath, { recursive: true })
  nowMs += (60 * 60 * 1000) + 1

  await resumeEngagement({ bundle }, workDependencies)
  const scopeNames = await readdir(scopesDirectory)
  assert.equal(scopeNames.length, 2)
  assert.equal(typeof successfulScopePath, 'string')
  const successfulScope = await readJson(successfulScopePath)
  assert.deepEqual(importedScope, successfulScope)
})

test('an exact browser extension reference uses one bound page session adapter', async (t) => {
  const { parent, bundle } = await fixture(t, 'authenticated-http-default')
  const adapterPath = join(parent, 'page-session-adapter.json')
  await writeFile(adapterPath, JSON.stringify(pageSessionAdapter()), 'utf8')
  const called = []
  const workDependencies = dependencies({
    executeRoute: async ({ routeId, bundle: activeBundle }) => {
      called.push(routeId)
      await writeSuccessfulRouteOutput({ routeId, bundle: activeBundle })
      return {
        status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false,
        requestMayHaveBeenSent: true, stdout: '{"status":"SUCCEEDED"}', stderr: '',
      }
    },
  })

  const result = await startEngagement({
    target: 'https://target.example/app',
    statement: 'I own this target and authorize its full authenticated assessment.',
    authorizationProfile: 'full',
    objective: 'Map the authenticated application protocol.',
    credentialReferences: [`browser:${TEST_EXTENSION_ID}`],
    inputs: [{ kind: 'configuration', locator: adapterPath }],
    out: bundle,
  }, workDependencies)

  assert.equal(called.includes('authenticated-http-browser'), true)
  assert.equal(result.completed_routes.includes('authenticated-http-browser'), true)
  const scopes = join(bundle, 'routes', 'authenticated-http-browser', 'scopes')
  const entries = await readdir(scopes)
  assert.equal(entries.length, 1)
  const scope = await readJson(join(scopes, entries[0]))
  assert.equal(scope.credential.extension_id, TEST_EXTENSION_ID)
  assert.equal(scope.credential.session_adapter.adapter_id, 'controller-test-session')
})

test('direct browser credential resolution rejects ambiguous browser references', async (t) => {
  const { bundle } = await fixture(t, 'authenticated-http-ambiguous-reference')
  await assert.rejects(
    startEngagement({
      target: 'https://target.example/app',
      statement: 'I own this target and authorize its full authenticated assessment.',
      authorizationProfile: 'full',
      objective: 'Map the authenticated application protocol.',
      credentialReferences: [
        `browser:${TEST_EXTENSION_ID}`,
        'browser:pppppppppppppppppppppppppppppppp',
      ],
      out: bundle,
    }, dependencies()),
    (error) => error.code === 'ENGAGEMENT_AUTH_HTTP_CREDENTIAL_AMBIGUOUS',
  )
})

test('a failed route does not prevent an independent ready route from running', async (t) => {
  const { parent, bundle } = await fixture(t, 'independent')
  const harPath = join(parent, 'capture.har')
  await writeFile(harPath, '{"log":{"entries":[]}}', 'utf8')
  const called = []

  const result = await startEngagement({
    target: 'https://target.example/',
    statement: 'Authorized for a full assessment of this target and the supplied capture.',
    authorizationProfile: 'full',
    objective: 'Map the target protocol.',
    out: bundle,
    inputs: [{ kind: 'capture', locator: harPath }],
  }, dependencies({
    executeRoute: async ({ routeId, bundle: activeBundle }) => {
      called.push(routeId)
      const succeeded = routeId === 'web-capture-har-import'
      if (succeeded) await writeSuccessfulRouteOutput({ routeId, bundle: activeBundle })
      return {
        status: succeeded ? 'SUCCEEDED' : 'FAILED',
        exitCode: succeeded ? 0 : 1,
        signal: null,
        timedOut: false,
        requestMayHaveBeenSent: true,
        stdout: '',
        stderr: succeeded ? '' : 'recon failed',
      }
    },
  }))

  assert.deepEqual(called, ['https-recon', 'web-capture-har-import', 'protocol-build'])
  assert.deepEqual(result.completed_routes, ['web-capture-har-import'])
  assert.deepEqual(result.failed_routes, ['https-recon', 'protocol-build'])
  assert.equal(result.waiting_routes.includes('authenticated-http-browser'), true)
  const failedResult = await readJson(join(bundle, 'routes', 'https-recon', 'result.json'))
  assert.equal(failedResult.status, 'FAILED')
  const succeededResult = await readJson(join(bundle, 'routes', 'web-capture-har-import', 'result.json'))
  assert.equal(succeededResult.status, 'SUCCEEDED')
})

test('capture output outside the authorized HTTPS path prefix is rejected', async (t) => {
  const { parent, bundle } = await fixture(t, 'capture-prefix')
  const har = { log: { entries: [{
    startedDateTime: '2026-09-11T12:00:00.000Z',
    time: 5,
    request: { method: 'GET', url: 'https://target.example/admin', headers: [], cookies: [] },
    response: { status: 200, headers: [], cookies: [], content: { size: 0, text: '' } },
  }] } }
  const harPath = join(parent, 'capture.har')
  await writeFile(harPath, JSON.stringify(har), 'utf8')

  const result = await startEngagement({
    target: 'https://target.example/app',
    statement: 'Authorized for the full target application assessment.',
    authorizationProfile: 'full',
    objective: 'Map the application protocol.',
    out: bundle,
    inputs: [{ kind: 'capture', locator: harPath }],
  }, dependencies({
    executeRoute: async ({ routeId, bundle: activeBundle }) => {
      if (routeId === 'web-capture-har-import') {
        await writeSuccessfulRouteOutput({
          routeId,
          bundle: activeBundle,
          targetUrl: 'https://target.example/app',
          har,
        })
        return { status: 'SUCCEEDED', exitCode: 0, requestMayHaveBeenSent: false, stdout: '', stderr: '' }
      }
      return { status: 'FAILED', exitCode: 1, requestMayHaveBeenSent: true, stdout: '', stderr: 'recon failed' }
    },
  }))

  assert.equal(result.completed_routes.includes('web-capture-har-import'), false)
  const routeResult = await readJson(join(bundle, 'routes', 'web-capture-har-import', 'result.json'))
  assert.equal(routeResult.status, 'FAILED')
  assert.equal(routeResult.error_code, 'ENGAGEMENT_ROUTE_SCOPE_INVALID')
})

test('resume verifies canonical bindings and never requests or repeats the original statement', async (t) => {
  const { parent, bundle } = await fixture(t, 'resume')
  const repository = join(parent, 'repository')
  await mkdir(repository)
  await writeFile(join(repository, 'README.md'), 'fixture\n', 'utf8')
  let dispatches = 0
  const deps = dependencies({
    executeRoute: async ({ routeId, bundle: activeBundle }) => {
      dispatches += 1
      await writeSuccessfulRouteOutput({ routeId, bundle: activeBundle })
      return {
        status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false,
        requestMayHaveBeenSent: false, stdout: '', stderr: '',
      }
    },
  })

  const started = await startEngagement({
    target: repository,
    statement: 'Our organization owns this repository and authorizes its full assessment.',
    authorizationProfile: 'full',
    objective: 'Audit the repository.',
    out: bundle,
  }, deps)
  assert.equal(dispatches, 1)

  const resumed = await resumeEngagement({ bundle }, dependencies({
    executeRoute: async () => { dispatches += 1; throw new Error('must not redispatch') },
  }))
  assert.equal(resumed.engagement_id, started.engagement_id)
  assert.equal(resumed.authorization_sha256, started.authorization_sha256)
  assert.equal(dispatches, 1)
  assert.equal(resumed.ledger.resume_count, 1)

  const authorityPath = join(bundle, 'authorization.json')
  const authority = await readJson(authorityPath)
  authority.statement = `${authority.statement} changed`
  await writeFile(authorityPath, canonicalEngagementJson(authority), 'utf8')
  await assert.rejects(
    resumeEngagement({ bundle }, dependencies()),
    (error) => /AUTHORITY|STATEMENT|BUNDLE/.test(error.code),
  )
})

test('resume refuses a local target that has become a link or reparse alias', async (t) => {
  const { parent, bundle } = await fixture(t, 'resume-linked-target')
  const repository = join(parent, 'repository')
  await mkdir(repository)
  await writeFile(join(repository, 'README.md'), 'fixture\n', 'utf8')

  await startEngagement({
    target: repository,
    statement: 'Our organization owns this repository and authorizes its full assessment.',
    authorizationProfile: 'full',
    objective: 'Audit the repository.',
    out: bundle,
  }, dependencies())

  await assert.rejects(
    resumeEngagement({ bundle }, dependencies({
      lstatImpl: async (path) => path === repository
        ? { isSymbolicLink: () => true, isDirectory: () => false, isFile: () => false }
        : lstat(path),
      realpathImpl: realpath,
    })),
    (error) => error.code === 'ENGAGEMENT_TARGET_CHANGED',
  )
})

test('resume refuses repository and artifact objects replaced at the same canonical path', async (t) => {
  for (const kind of ['repository', 'artifact']) {
    const { parent, bundle } = await fixture(t, `resume-replaced-${kind}`)
    const target = join(parent, kind)
    const replacement = join(parent, `${kind}-replacement`)
    if (kind === 'repository') {
      await mkdir(target)
      await writeFile(join(target, 'README.md'), 'fixture\n', 'utf8')
      await mkdir(replacement)
      await writeFile(join(replacement, 'README.md'), 'fixture\n', 'utf8')
    } else {
      await writeFile(target, 'identical artifact bytes\n', 'utf8')
      await writeFile(replacement, 'identical artifact bytes\n', 'utf8')
    }

    await startEngagement({
      target,
      statement: `Our organization owns this ${kind} and authorizes its full assessment.`,
      authorizationProfile: 'full',
      objective: `Assess the ${kind}.`,
      out: bundle,
    }, dependencies())

    if (kind === 'repository') {
      await writeFile(join(target, 'new-work.txt'), 'repository contents may evolve\n', 'utf8')
      await assert.doesNotReject(resumeEngagement({ bundle }, dependencies()))
    }
    await rm(target, { recursive: true, force: true })
    await rename(replacement, target)
    await assert.rejects(
      resumeEngagement({ bundle }, dependencies()),
      (error) => error.code === 'ENGAGEMENT_TARGET_CHANGED',
      kind,
    )
  }
})

test('completed route outputs remain bound before status or downstream reuse', async (t) => {
  const { bundle } = await fixture(t, 'output-binding')
  await startEngagement({
    target: 'https://target.example/',
    statement: 'Authorized for the full target assessment.',
    authorizationProfile: 'full',
    objective: 'Assess the target.',
    out: bundle,
  }, dependencies())

  await writeFile(join(bundle, 'routes', 'https-recon', 'http-recon', 'injected.json'), '{}', 'utf8')
  await assert.rejects(
    getEngagementStatus({ bundle }),
    (error) => error.code === 'ENGAGEMENT_ROUTE_OUTPUT_DRIFT',
  )
})

test('downstream routes receive exact staged copies of producer output bytes', async (t) => {
  const { parent, bundle } = await fixture(t, 'staged-producer-output')
  const har = { log: { entries: [] } }
  const harPath = join(parent, 'capture.har')
  await writeFile(harPath, JSON.stringify(har), 'utf8')
  let inspected = false

  await startEngagement({
    target: 'https://target.example/app',
    statement: 'I own this target and authorize its full assessment.',
    authorizationProfile: 'full',
    objective: 'Build a target-bound protocol contract.',
    inputs: [{ kind: 'capture', locator: harPath }],
    out: bundle,
  }, dependencies({
    executeRoute: async ({ routeId, invocation, bundle: activeBundle }) => {
      if (routeId === 'web-capture-har-import') {
        await writeSuccessfulRouteOutput({ routeId, bundle: activeBundle, targetUrl: 'https://target.example/app', har })
        return { status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false, requestMayHaveBeenSent: false, stdout: '', stderr: '' }
      }
      if (routeId === 'protocol-build') {
        const flag = invocation.arguments.indexOf('--web-evidence')
        const stagedPath = invocation.arguments[flag + 1]
        const producerPath = join(activeBundle, 'routes', 'web-capture-har-import', 'evidence.json')
        assert.notEqual(stagedPath, producerPath)
        assert.equal(stagedPath.startsWith(join(activeBundle, 'routes', 'protocol-build', 'material')), true)
        const exactBytes = await readFile(producerPath)
        await writeFile(producerPath, '{}', 'utf8')
        assert.deepEqual(await readFile(stagedPath), exactBytes)
        await writeFile(producerPath, exactBytes)
        inspected = true
      }
      return { status: 'FAILED', exitCode: 1, signal: null, timedOut: false, requestMayHaveBeenSent: false, stdout: '', stderr: 'fixture stop' }
    },
  }))

  assert.equal(inspected, true)
})

test('connector verification receives an exact staged producer tree', async (t) => {
  const { parent, bundle } = await fixture(t, 'staged-producer-tree')
  const har = { log: { entries: [] } }
  const harPath = join(parent, 'capture.har')
  await writeFile(harPath, JSON.stringify(har), 'utf8')
  let inspected = false

  await startEngagement({
    target: 'https://target.example/app',
    statement: 'I own this target and authorize its full assessment.',
    authorizationProfile: 'full',
    objective: 'Generate and verify a target-bound connector.',
    inputs: [{ kind: 'capture', locator: harPath }],
    out: bundle,
  }, dependencies({
    executeRoute: async ({ routeId, invocation, bundle: activeBundle }) => {
      if (routeId === 'web-capture-har-import') {
        await writeSuccessfulRouteOutput({ routeId, bundle: activeBundle, targetUrl: 'https://target.example/app', har })
        return { status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false, requestMayHaveBeenSent: false, stdout: '', stderr: '' }
      }
      if (routeId === 'protocol-build') {
        await writeFile(join(activeBundle, 'routes', routeId, 'contract.json'), '{}\n', 'utf8')
        return { status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false, requestMayHaveBeenSent: false, stdout: '', stderr: '' }
      }
      if (routeId === 'connector-generate') {
        const contractFlag = invocation.arguments.indexOf('--contract')
        assert.notEqual(invocation.arguments[contractFlag + 1], join(activeBundle, 'routes', 'protocol-build', 'contract.json'))
        const output = join(activeBundle, 'routes', routeId, 'package')
        await mkdir(output)
        await writeFile(join(output, 'manifest.json'), '{"kind":"fixture"}\n', 'utf8')
        await writeFile(join(output, 'client.mjs'), 'export const fixture = true\n', 'utf8')
        return { status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false, requestMayHaveBeenSent: false, stdout: '', stderr: '' }
      }
      if (routeId === 'connector-verify') {
        const packageFlag = invocation.arguments.indexOf('--package')
        const stagedPackage = invocation.arguments[packageFlag + 1]
        const producerPackage = join(activeBundle, 'routes', 'connector-generate', 'package')
        assert.notEqual(stagedPackage, producerPackage)
        const producerClient = join(producerPackage, 'client.mjs')
        const exactBytes = await readFile(producerClient)
        await writeFile(producerClient, 'substituted\n', 'utf8')
        assert.deepEqual(await readFile(join(stagedPackage, 'client.mjs')), exactBytes)
        await writeFile(producerClient, exactBytes)
        inspected = true
        return { status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false, requestMayHaveBeenSent: false, stdout: '', stderr: '' }
      }
      return { status: 'FAILED', exitCode: 1, signal: null, timedOut: false, requestMayHaveBeenSent: false, stdout: '', stderr: 'fixture stop' }
    },
  }))

  assert.equal(inspected, true)
})

test('external controller heads reject a valid-prefix engagement ledger rollback', async (t) => {
  const { bundle } = await fixture(t, 'ledger-rollback')
  await startEngagement({
    target: 'https://target.example/',
    statement: 'Authorized for the full target assessment.',
    authorizationProfile: 'full',
    objective: 'Assess the target.',
    out: bundle,
  }, dependencies())
  const ledgerDirectory = join(bundle, 'ledger')
  const retained = await readdir(ledgerDirectory)
  await resumeEngagement({ bundle }, dependencies())
  const advanced = await readdir(ledgerDirectory)
  assert.equal(advanced.length > retained.length, true)
  for (const name of advanced.filter((entry) => !retained.includes(entry))) {
    await unlink(join(ledgerDirectory, name))
  }

  await assert.rejects(
    getEngagementStatus({ bundle }),
    (error) => error.code === 'ENGAGEMENT_LEDGER_ANCHOR_MISMATCH',
  )
})

test('status is read-only and stop is terminal, durable, and idempotent', async (t) => {
  const { bundle } = await fixture(t, 'stop')
  await startEngagement({
    target: 'https://target.example/',
    statement: 'Authorized for the full target.',
    authorizationProfile: 'full',
    objective: 'Assess the target.',
    out: bundle,
  }, dependencies())

  const before = await getEngagementStatus({ bundle })
  const again = await getEngagementStatus({ bundle })
  assert.equal(again.ledger.record_count, before.ledger.record_count)
  assert.equal(before.status, 'WAITING_FOR_MATERIAL')

  const stopped = await stopEngagement({ bundle, reason: 'operator requested stop' }, dependencies())
  assert.equal(stopped.status, 'STOPPED')
  const stoppedAgain = await stopEngagement({ bundle, reason: 'a later reason' }, dependencies())
  assert.equal(stoppedAgain.status, 'STOPPED')
  assert.equal(stoppedAgain.ledger.record_count, stopped.ledger.record_count)

  const resumed = await resumeEngagement({ bundle }, dependencies({
    executeRoute: async () => { throw new Error('stopped engagement must not dispatch') },
  }))
  assert.equal(resumed.status, 'STOPPED')
  assert.equal(resumed.ledger.record_count, stopped.ledger.record_count)
})

test('noncanonical bundle documents and oversized runner output fail closed', async (t) => {
  const canonicalFixture = await fixture(t, 'canonical')
  await startEngagement({
    target: 'https://target.example/', statement: 'Authorized for the full target.', objective: 'Assess.',
    authorizationProfile: 'full',
    out: canonicalFixture.bundle,
  }, dependencies())
  const manifestPath = join(canonicalFixture.bundle, 'engagement.json')
  await writeFile(manifestPath, `${await readFile(manifestPath, 'utf8')}\n`, 'utf8')
  await assert.rejects(
    getEngagementStatus({ bundle: canonicalFixture.bundle }),
    (error) => error.code === 'ENGAGEMENT_BUNDLE_NONCANONICAL',
  )

  const boundedFixture = await fixture(t, 'bounded')
  const result = await startEngagement({
    target: 'https://bounded.example/', statement: 'Authorized for the full target.', objective: 'Assess.',
    authorizationProfile: 'full',
    out: boundedFixture.bundle,
  }, dependencies({
    executeRoute: async () => ({
      status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false,
      requestMayHaveBeenSent: true, stdout: 'x'.repeat(2 * 1024 * 1024), stderr: '',
    }),
  }))
  assert.deepEqual(result.uncertain_routes, ['https-recon'])
  const routeResult = await readJson(join(boundedFixture.bundle, 'routes', 'https-recon', 'result.json'))
  assert.equal(routeResult.status, 'UNCERTAIN')
  assert.equal(routeResult.error_code, 'OUTPUT_LIMIT_EXCEEDED')
  assert.equal(Object.hasOwn(routeResult, 'stdout'), false)
  assert.equal(Object.hasOwn(routeResult, 'stderr'), false)
  assert.equal(routeResult.stdout_bytes, 2 * 1024 * 1024)
  assert.match(routeResult.stdout_sha256, /^[a-f0-9]{64}$/)
})

test('a durable stop marker wins the next dispatch boundary while an active route settles', async (t) => {
  const { bundle } = await fixture(t, 'stop-race')
  let enteredResolve
  let releaseResolve
  const entered = new Promise((resolvePromise) => { enteredResolve = resolvePromise })
  const release = new Promise((resolvePromise) => { releaseResolve = resolvePromise })
  const called = []
  const started = startEngagement({
    target: 'https://target.example/', statement: 'Authorized for the full target.', objective: 'Assess.', out: bundle,
    authorizationProfile: 'full',
  }, dependencies({
    executeRoute: async ({ routeId, bundle: activeBundle }) => {
      called.push(routeId)
      enteredResolve()
      await release
      await writeSuccessfulRouteOutput({ routeId, bundle: activeBundle })
      return {
        status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false,
        requestMayHaveBeenSent: true, stdout: '{"status":"SUCCEEDED"}', stderr: '',
      }
    },
  }))
  await entered

  let stopSettled = false
  const stopped = stopEngagement({ bundle, reason: 'operator requested stop' }, dependencies())
    .finally(() => { stopSettled = true })
  await new Promise((resolvePromise) => setTimeout(resolvePromise, 75))
  assert.equal(stopSettled, false, 'stop waits for the launched route outcome instead of fabricating one')
  releaseResolve()
  const [startResult, stopResult] = await Promise.all([started, stopped])
  assert.equal(stopResult.status, 'STOPPED')
  assert.equal(['STOP_REQUESTED', 'STOPPED'].includes(startResult.status), true)
  assert.deepEqual(called, ['https-recon'])
})

test('linked input ancestors and repository-contained bundles are refused', async (t) => {
  const { parent } = await fixture(t, 'linked')
  const repository = join(parent, 'repository')
  const inputDirectory = join(parent, 'inputs')
  const alias = join(parent, 'input-alias')
  await mkdir(repository)
  await mkdir(inputDirectory)
  await writeFile(join(inputDirectory, 'capture.har'), '{"log":{"entries":[]}}', 'utf8')
  try {
    await symlink(inputDirectory, alias, process.platform === 'win32' ? 'junction' : 'dir')
  } catch (error) {
    if (error?.code === 'EPERM') return t.skip('link creation is unavailable')
    throw error
  }
  await assert.rejects(
    startEngagement({
      target: 'https://target.example/', statement: 'Authorized for the full target.', objective: 'Assess.',
      authorizationProfile: 'full',
      out: join(parent, 'linked-bundle'),
      inputs: [{ kind: 'capture', locator: join(alias, 'capture.har') }],
    }, dependencies()),
    /link|junction|canonical|input/i,
  )
  await assert.rejects(
    startEngagement({
      target: repository, statement: 'Authorized for the full target.', objective: 'Assess.',
      authorizationProfile: 'full',
      out: join(repository, 'engagement'),
    }, dependencies()),
    (error) => error.code === 'ENGAGEMENT_BUNDLE_IN_TARGET',
  )
})

test('repository work runs next through validated finalization with outer child checkpoints', async (t) => {
  const { parent, bundle } = await fixture(t, 'repository-lifecycle')
  const repository = join(parent, 'repository')
  const resultPath = join(parent, 'job-result.json')
  await mkdir(repository)
  await writeFile(join(repository, 'README.md'), 'fixture\n')
  await writeFile(resultPath, JSON.stringify({
    schema_version: '1.0.0', run_id: 'audit-run-1',
    job_id: 'lens:authorization:0001', state: 'SUCCEEDED',
  }))
  const childBundle = join(bundle, 'routes', 'repository-audit', 'audit-bundle', 'audit-run-1')
  const actions = []
  let childState = 'RUNNING'
  let nextStep = 'REVIEW_FINALIZATION'
  const workDependencies = dependencies({
    executeRoute: async ({ routeId, bundle: activeBundle }) => {
      await writeSuccessfulRouteOutput({ routeId, bundle: activeBundle })
      await writeFile(join(childBundle, 'state.json'), '{"state":"PLANNED"}\n')
      return {
        status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false,
        requestMayHaveBeenSent: false,
        stdout: JSON.stringify({ status: 'PLANNED', bundle: childBundle }), stderr: '',
      }
    },
    executeRepositoryAction: async ({ action }) => {
      actions.push(action)
      if (action === 'next') {
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            run_id: 'audit-run-1', state: 'PLANNED', phase: 'RECON',
            pending_jobs: [repositoryPacket()],
          }),
          stderr: '',
        }
      }
      if (action === 'check-result') {
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            valid: true, applied: false, run_id: 'audit-run-1',
            job_id: 'lens:authorization:0001', result_state: 'SUCCEEDED',
          }),
          stderr: '',
        }
      }
      if (action === 'ingest') {
        await writeFile(join(childBundle, 'ingested.json'), '{"job":"lens:authorization:0001"}\n')
        return { exitCode: 0, stdout: 'Ingested result.\n', stderr: '' }
      }
      if (action === 'finalize') {
        childState = 'COMPLETED'
        nextStep = 'REVIEW_REPORT'
        await writeFile(join(childBundle, 'finalized.json'), '{"status":"COMPLETED"}\n')
        return { exitCode: 0, stdout: 'Finalized.\n', stderr: '' }
      }
      if (action === 'validate') {
        return { exitCode: 0, stdout: JSON.stringify({ status: 'VALID' }), stderr: '' }
      }
      if (action === 'status') {
        return {
          exitCode: 0,
          stdout: JSON.stringify(repositoryChildStatus({
            state: childState,
            terminal: childState === 'COMPLETED',
            next_step: { code: nextStep },
          })),
          stderr: '',
        }
      }
      throw new Error(`unexpected repository action ${action}`)
    },
  })

  const started = await startEngagement({
    target: repository,
    statement: 'Our organization owns this repository and authorizes its full assessment.',
    authorizationProfile: 'repository-read',
    objective: 'Audit the repository completely.',
    out: bundle,
  }, workDependencies)
  assert.equal(started.status, 'WAITING_FOR_AGENT_RESULT')

  const next = await getRepositoryNextWork({ bundle }, workDependencies)
  assert.equal(next.recovered, false)
  assert.match(next.work_envelope.work_id, /^repository-work:[a-f0-9]{64}$/u)
  const recovered = await getRepositoryNextWork({ bundle }, workDependencies)
  assert.equal(recovered.recovered, true)
  assert.equal(recovered.work_envelope.work_id, next.work_envelope.work_id)
  assert.deepEqual(actions, ['next'])

  const submitted = await submitRepositoryWork({
    bundle,
    workId: next.work_envelope.work_id,
    resultPath,
  }, workDependencies)
  assert.equal(submitted.status, 'READY_TO_FINALIZE')
  assert.equal(submitted.work_receipt.state, 'RESULT_INGESTED')

  const ingestedPath = join(childBundle, 'ingested.json')
  const ingestedBytes = await readFile(ingestedPath)
  await unlink(ingestedPath)
  await assert.rejects(
    getRepositoryWorkStatus({ bundle }, workDependencies),
    (error) => error.code === 'ENGAGEMENT_REPOSITORY_CHILD_CHANGED',
  )
  await writeFile(ingestedPath, ingestedBytes)

  const status = await getRepositoryWorkStatus({ bundle }, workDependencies)
  assert.equal(status.status, 'READY_TO_FINALIZE')
  const finalized = await finalizeRepositoryWork({ bundle }, workDependencies)
  assert.equal(finalized.status, 'COMPLETED')
  const validated = await validateRepositoryWork({ bundle }, workDependencies)
  assert.equal(validated.status, 'COMPLETED_WITH_GAPS')
  assert.equal(validated.validation.status, 'VALID')
  assert.equal(validated.child_status.child_state, 'COMPLETED')
  assert.deepEqual(actions, [
    'next', 'check-result', 'ingest', 'status', 'status',
    'finalize', 'status', 'validate', 'status',
  ])

  const outer = await getEngagementStatus({ bundle }, workDependencies)
  assert.equal(outer.repository.current_checkpoint.operation, 'VALIDATE')
  assert.equal(outer.repository.current_checkpoint.terminal, true)
  assert.equal(outer.repository.works[0].result.status, 'RESULT_INGESTED')
})

test('repository ingest ambiguity before mutation is reconciled and the exact work can retry', async (t) => {
  const { parent, bundle } = await fixture(t, 'repository-ambiguous-ingest')
  const repository = join(parent, 'repository')
  const resultPath = join(parent, 'job-result.json')
  await mkdir(repository)
  await writeFile(join(repository, 'README.md'), 'fixture\n')
  await writeFile(resultPath, JSON.stringify({
    schema_version: '1.0.0', run_id: 'audit-run-1',
    job_id: 'lens:authorization:0001', state: 'SUCCEEDED',
  }))
  const childBundle = join(bundle, 'routes', 'repository-audit', 'audit-bundle', 'audit-run-1')
  const actions = []
  const workDependencies = dependencies({
    executeRoute: async ({ routeId, bundle: activeBundle }) => {
      await writeSuccessfulRouteOutput({ routeId, bundle: activeBundle })
      await writeFile(join(childBundle, 'state.json'), '{"state":"PLANNED"}\n')
      return {
        status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false,
        requestMayHaveBeenSent: false,
        stdout: JSON.stringify({ status: 'PLANNED', bundle: childBundle }), stderr: '',
      }
    },
    executeRepositoryAction: async ({ action }) => {
      actions.push(action)
      if (action === 'next') {
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            run_id: 'audit-run-1', state: 'PLANNED', phase: 'RECON',
            pending_jobs: [repositoryPacket()],
          }),
          stderr: '',
        }
      }
      if (action === 'check-result') {
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            valid: true, applied: false, run_id: 'audit-run-1',
            job_id: 'lens:authorization:0001', result_state: 'SUCCEEDED',
          }),
          stderr: '',
        }
      }
      if (action === 'ingest') throw new Error('connection lost after dispatch')
      throw new Error(`unexpected repository action ${action}`)
    },
  })

  await startEngagement({
    target: repository,
    statement: 'Our organization owns this repository and authorizes its full assessment.',
    authorizationProfile: 'full',
    objective: 'Audit the repository completely.',
    out: bundle,
  }, workDependencies)
  const next = await getRepositoryNextWork({ bundle }, workDependencies)
  const ambiguous = await submitRepositoryWork({
    bundle,
    workId: next.work_envelope.work_id,
    resultPath,
  }, workDependencies)

  assert.equal(ambiguous.status, 'INGEST_RECOVERY_REQUIRED')
  assert.equal(ambiguous.recovery.next_step.code, 'RECONCILE_EXACT_STAGED_RESULT')
  assert.deepEqual(actions, ['next', 'check-result', 'ingest'])
  const retried = await submitRepositoryWork({
    bundle,
    workId: next.work_envelope.work_id,
    resultPath,
  }, workDependencies)
  assert.equal(retried.status, 'INGEST_RECOVERY_REQUIRED')
  assert.deepEqual(actions, [
    'next', 'check-result', 'ingest',
    'check-result', 'check-result', 'ingest',
  ])

  const outer = await getEngagementStatus({ bundle }, workDependencies)
  assert.equal(outer.repository.current_checkpoint.operation, 'NEXT')
  assert.equal(outer.repository.works[0].result, null)
  assert.equal(outer.repository.works[0].ingest_attempts.length, 2)
  assert.equal(outer.repository.works[0].ingest_attempts[0].reconciliation.outcome, 'NOT_APPLIED')
  assert.equal(outer.repository.works[0].ingest_attempts[1].reconciliation, null)
  const stopped = await stopEngagement({
    bundle,
    reason: 'Stop after exact not-applied reconciliation.',
  }, workDependencies)
  assert.equal(stopped.status, 'STOPPED')
  assert.deepEqual(actions.slice(-1), ['check-result'])
  const stoppedOuter = await getEngagementStatus({ bundle }, workDependencies)
  assert.equal(stoppedOuter.repository.works[0].ingest_attempts[1].reconciliation.outcome, 'NOT_APPLIED')
  assert.equal(stoppedOuter.repository.works[0].ingest, null)
})

test('a restarted controller reconciles an exact result applied before ingest transport loss', async (t) => {
  const { parent, bundle } = await fixture(t, 'repository-applied-ingest-recovery')
  const repository = join(parent, 'repository')
  const resultPath = join(parent, 'job-result.json')
  await mkdir(repository)
  await writeFile(join(repository, 'README.md'), 'fixture\n')
  await writeFile(resultPath, JSON.stringify({
    schema_version: '1.0.0', run_id: 'audit-run-1',
    job_id: 'lens:authorization:0001', state: 'SUCCEEDED',
  }))
  const childBundle = join(bundle, 'routes', 'repository-audit', 'audit-bundle', 'audit-run-1')
  const actions = []
  let applied = false
  const overrides = {
    executeRoute: async ({ routeId, bundle: activeBundle }) => {
      await writeSuccessfulRouteOutput({ routeId, bundle: activeBundle })
      await writeFile(join(childBundle, 'state.json'), '{"state":"PLANNED"}\n')
      return {
        status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false,
        requestMayHaveBeenSent: false,
        stdout: JSON.stringify({ status: 'PLANNED', bundle: childBundle }), stderr: '',
      }
    },
    executeRepositoryAction: async ({ action }) => {
      actions.push(action)
      if (action === 'next') {
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            run_id: 'audit-run-1', state: 'PLANNED', phase: 'RECON',
            pending_jobs: [repositoryPacket()],
          }),
          stderr: '',
        }
      }
      if (action === 'check-result') {
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            valid: true, applied, run_id: 'audit-run-1',
            job_id: 'lens:authorization:0001', result_state: 'SUCCEEDED',
          }),
          stderr: '',
        }
      }
      if (action === 'ingest') {
        applied = true
        await writeFile(join(childBundle, 'ingested.json'), '{"job":"lens:authorization:0001"}\n')
        throw new Error('transport lost after the child committed the exact result')
      }
      if (action === 'status') {
        return {
          exitCode: 0,
          stdout: JSON.stringify(repositoryChildStatus({
            next_step: { code: 'REVIEW_FINALIZATION' },
          })),
          stderr: '',
        }
      }
      throw new Error(`unexpected repository action ${action}`)
    },
  }
  const firstController = dependencies(overrides)
  await startEngagement({
    target: repository,
    statement: 'Our organization owns this repository and authorizes its full assessment.',
    authorizationProfile: 'full',
    objective: 'Audit the repository completely.',
    out: bundle,
  }, firstController)
  const next = await getRepositoryNextWork({ bundle }, firstController)
  const ambiguous = await submitRepositoryWork({
    bundle,
    workId: next.work_envelope.work_id,
    resultPath,
  }, firstController)
  assert.equal(ambiguous.status, 'INGEST_RECOVERY_REQUIRED')

  const restartedController = dependencies(overrides)
  const recovered = await stopEngagement({
    bundle,
    reason: 'Stop only after exact applied-result reconciliation.',
  }, restartedController)
  assert.equal(recovered.status, 'STOPPED')
  assert.deepEqual(actions, ['next', 'check-result', 'ingest', 'check-result', 'status'])

  const outer = await getEngagementStatus({ bundle }, restartedController)
  assert.equal(outer.repository.current_checkpoint.operation, 'INGEST')
  assert.equal(outer.repository.works[0].result.status, 'RESULT_INGESTED')
  assert.equal(outer.repository.works[0].ingest_attempts[0].reconciliation.outcome, 'APPLIED')
  assert.equal(outer.status, 'STOPPED')
})

test('stop remains nonterminal when ambiguous ingest changed the child without applying the exact result', async (t) => {
  const { parent, bundle } = await fixture(t, 'repository-ingest-conflict-stop')
  const repository = join(parent, 'repository')
  const resultPath = join(parent, 'job-result.json')
  await mkdir(repository)
  await writeFile(join(repository, 'README.md'), 'fixture\n')
  await writeFile(resultPath, JSON.stringify({
    schema_version: '1.0.0', run_id: 'audit-run-1',
    job_id: 'lens:authorization:0001', state: 'SUCCEEDED',
  }))
  const childBundle = join(bundle, 'routes', 'repository-audit', 'audit-bundle', 'audit-run-1')
  const workDependencies = dependencies({
    executeRoute: async ({ routeId, bundle: activeBundle }) => {
      await writeSuccessfulRouteOutput({ routeId, bundle: activeBundle })
      await writeFile(join(childBundle, 'state.json'), '{"state":"PLANNED"}\n')
      return {
        status: 'SUCCEEDED', exitCode: 0, signal: null, timedOut: false,
        requestMayHaveBeenSent: false,
        stdout: JSON.stringify({ status: 'PLANNED', bundle: childBundle }), stderr: '',
      }
    },
    executeRepositoryAction: async ({ action }) => {
      if (action === 'next') {
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            run_id: 'audit-run-1', state: 'PLANNED', phase: 'RECON',
            pending_jobs: [repositoryPacket()],
          }),
          stderr: '',
        }
      }
      if (action === 'check-result') {
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            valid: true, applied: false, run_id: 'audit-run-1',
            job_id: 'lens:authorization:0001', result_state: 'SUCCEEDED',
          }),
          stderr: '',
        }
      }
      if (action === 'ingest') {
        await writeFile(join(childBundle, 'unrelated-change.json'), '{"not_the_result":true}\n')
        throw new Error('transport lost after an unrelated child mutation')
      }
      throw new Error(`unexpected repository action ${action}`)
    },
  })
  await startEngagement({
    target: repository,
    statement: 'Our organization owns this repository and authorizes its full assessment.',
    authorizationProfile: 'full',
    objective: 'Audit the repository completely.',
    out: bundle,
  }, workDependencies)
  const next = await getRepositoryNextWork({ bundle }, workDependencies)
  const ambiguous = await submitRepositoryWork({
    bundle,
    workId: next.work_envelope.work_id,
    resultPath,
  }, workDependencies)
  assert.equal(ambiguous.status, 'INGEST_RECOVERY_REQUIRED')
  await assert.rejects(
    stopEngagement({ bundle, reason: 'Attempt a safe stop.' }, workDependencies),
    (error) => error.code === 'ENGAGEMENT_REPOSITORY_RECOVERY_REQUIRED',
  )
  const outer = await getEngagementStatus({ bundle }, workDependencies)
  assert.equal(outer.status, 'STOP_REQUESTED')
  assert.equal(outer.repository.works[0].result, null)
  assert.equal(outer.repository.works[0].ingest.reconciliation.outcome, 'CONFLICT')
})
