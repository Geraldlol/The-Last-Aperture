import assert from 'node:assert/strict'
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { main } from '../scripts/http-authed.mjs'
import { openHttpAuthedCampaignLedger } from '../scripts/lib/http-authed-campaign-ledger.mjs'
import { runHttpAuthedAttestedCampaign } from '../scripts/lib/http-authed-campaign-runtime.mjs'
import {
  OPERATOR_ATTESTED_AUTHED_STATEMENT,
  sha256Hex,
  verifyHttpAuthedAuthorization,
} from '../scripts/lib/http-authed-contracts.mjs'
import { planHttpAuthedAttestedScope } from '../scripts/lib/http-authed-planner.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'
import { attestedScope } from './helpers/http-authed-fixtures.mjs'

const NOW = new Date('2026-08-17T10:00:00.000Z')
const COOKIE = '__Host-rta=SYNTHETIC_ATTESTED_COOKIE_MUST_NOT_PERSIST'
const PHI_BODY_SENTINEL = 'SYNTHETIC_PHI_BODY_MUST_NOT_PERSIST'
const HEADER_VALUE_SENTINEL = 'SYNTHETIC_HEADER_SECRET_MUST_NOT_PERSIST'

async function fixture(t, name = 'base') {
  const directory = await mkdtemp(join(tmpdir(), `rta-http-authed-attested-${name}-`))
  t.after(() => rm(directory, { recursive: true, force: true }))
  return {
    directory,
    scopePath: join(directory, 'scope.json'),
    ledgerDirectory: join(directory, 'ledger'),
  }
}

function planArguments(scopePath) {
  return [
    'plan-attested',
    '--scope', scopePath,
    '--engagement-id', 'truthful-vendor-bounty-2026',
    '--authorization-id', 'operator-attestation-2026-08-17',
    '--operator-id', 'security-researcher',
    '--authorized-by', 'Vendor security program contact',
    '--authorization-reference', 'Operator-held vendor authorization reference 2026-08-17',
    '--not-before', '2026-08-17T09:00:00.000Z',
    '--not-after', '2026-08-17T11:00:00.000Z',
    '--target-origin', 'https://bounty.example.test',
    '--environment', 'production',
    '--data-class', 'phi',
    '--ownership', 'third_party_owned',
    '--credential-stdin',
    '--credential-kind', 'cookie',
    '--path-prefix', '/authorized',
    '--method', 'GET',
    '--test-category', 'api_security',
    '--seed-url', 'https://bounty.example.test/authorized/non-phi-seed',
    '--seed-test-category', 'api_security',
    '--min-interval-ms', '0',
    '--json',
  ]
}

function withoutOption(args, name) {
  const copy = [...args]
  const index = copy.indexOf(`--${name}`)
  assert.notEqual(index, -1, `test setup must include --${name}`)
  copy.splice(index, 2)
  return copy
}

async function planAttested(files, overrides = {}) {
  let output = ''
  let credentialReads = 0
  let transportCalls = 0
  await main(overrides.args ?? planArguments(files.scopePath), {
    clock: () => NOW,
    env: {},
    credentialInput: overrides.credentialInput ?? Symbol('sealed stdin credential'),
    credentialStdinReader: async () => {
      credentialReads += 1
      return Buffer.from(COOKIE, 'ascii')
    },
    transport: async () => {
      transportCalls += 1
      throw new Error('attested planning must remain offline')
    },
    write: (value) => { output += value },
  })
  return {
    summary: JSON.parse(output),
    output,
    credentialReads,
    transportCalls,
  }
}

async function assertUnsafeAttestedUrlRejected(t, name, updateArguments) {
  const files = await fixture(t, name)
  const args = planArguments(files.scopePath)
  updateArguments(args)
  assert.equal(args.includes('--enable-discovery'), false)
  let transportCalls = 0
  await assert.rejects(
    main(args, {
      clock: () => NOW,
      env: {},
      credentialStdinReader: async () => Buffer.from(COOKIE, 'ascii'),
      transport: async () => { transportCalls += 1 },
      write: () => {},
    }),
    /synthetic.*query|query.*synthetic|persistence.safe/i,
  )
  assert.equal(transportCalls, 0)
  await assert.rejects(access(files.scopePath), { code: 'ENOENT' })
}

async function attestedMutationPlannerInput(files) {
  const action = structuredClone(attestedScope({ actionCount: 1 }).requests[0])
  action.request_body.body_id = 'SYNTHETIC_MUTATION_BODY_0001'
  action.rollback.request_body.body_id = 'SYNTHETIC_ROLLBACK_BODY_0001'
  action.expected_mutation.resource_ref = 'SYNTHETIC_RESOURCE_0001'
  return {
    input: {
      outputPath: files.scopePath,
      engagementId: 'attested-synthetic-mutation-planner',
      classification: { environment: 'production', dataClass: 'phi' },
      authorization: {
        authorizationId: 'attested-synthetic-mutation-authorization',
        operatorId: 'security-researcher',
        authorizedBy: 'Vendor security program contact',
        authorizationReference: 'Operator-held vendor authorization reference 2026-08-17',
        attestAuthorized: true,
        permissions: {
          activeTesting: true,
          production: true,
          thirdParty: true,
          phi: true,
        },
      },
      credential: { ref: 'env:ATTESTED_MUTATION_CREDENTIAL', kind: 'cookie' },
      target: {
        origin: 'https://peerstar-test.example.test',
        ownership: 'third_party_owned',
        tls: { mode: 'PKIX_HOSTNAME' },
      },
      authorizedScope: {
        pathPrefixes: ['/'],
        methods: ['HEAD', 'GET', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'],
        testCategories: ['api_security'],
      },
      liveness: {
        credentialPreflightUrl: 'https://peerstar-test.example.test/whoami',
      },
      seedRequests: [action],
      validity: {
        notBefore: '2026-08-17T09:00:00.000Z',
        notAfter: '2026-08-17T11:00:00.000Z',
      },
      limits: { min_interval_ms: 0 },
      mutationAuthorized: true,
    },
    action,
  }
}

test('plan-attested truthfully seals exact production third-party PHI scope without a document', async (t) => {
  const files = await fixture(t, 'plan')
  const planned = await planAttested(files)

  assert.equal(planned.credentialReads, 1)
  assert.equal(planned.transportCalls, 0)
  assert.equal(planned.summary.kind, 'red-team-audit/http-authed-attested-plan')
  assert.equal(planned.summary.authorization_mode, 'OPERATOR_ATTESTED_AUTHED')
  assert.equal(planned.summary.independently_verified, false)
  assert.match(planned.summary.authorization_binding_sha256, /^[a-f0-9]{64}$/)
  assert.match(planned.summary.campaign_grant_sha256, /^[a-f0-9]{64}$/)

  const scopeText = await readFile(files.scopePath, 'utf8')
  const scope = JSON.parse(scopeText)
  assert.equal(scope.authorization.mode, 'OPERATOR_ATTESTED_AUTHED')
  assert.equal(scope.authorization.statement, OPERATOR_ATTESTED_AUTHED_STATEMENT)
  assert.equal(scope.authorization.attested_at, NOW.toISOString())
  assert.equal(scope.authorization.independently_verified, false)
  assert.deepEqual(scope.authorization.permissions, {
    active_testing: true,
    production: true,
    third_party: true,
    phi: true,
    mutation: false,
  })
  assert.deepEqual(scope.authorization.authorized_scope, {
    origins: ['https://bounty.example.test'],
    path_prefixes: ['/authorized'],
    methods: ['GET'],
    test_categories: ['api_security'],
  })
  assert.deepEqual(scope.validity, {
    not_before: '2026-08-17T09:00:00.000Z',
    not_after: '2026-08-17T11:00:00.000Z',
    cleanup_not_after: '2026-08-17T11:00:00.000Z',
  })
  assert.deepEqual(scope.requests, [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: 'https://bounty.example.test/authorized/non-phi-seed',
    expected_effect: 'none',
  }])
  assert.equal(scope.approver, undefined)
  assert.equal(scope.credential.ref, 'stdin:PIPE')
  assert.equal(scope.credential.kind, 'cookie')
  assert.equal(scope.credential.binding_sha256, sha256Hex(Buffer.from(COOKIE, 'ascii')))
  assert.equal(scopeText.includes(COOKIE), false)
  assert.equal(planned.output.includes(COOKIE), false)
})

test('plan-attested requires an explicit current attestation, validity window, and exact scope', async (t) => {
  const required = [
    'operator-id',
    'authorized-by',
    'authorization-reference',
    'not-before',
    'not-after',
    'target-origin',
    'path-prefix',
    'method',
    'test-category',
    'seed-url',
  ]

  for (const name of required) {
    const files = await fixture(t, `missing-${name}`)
    let transportCalls = 0
    let credentialReads = 0
    await assert.rejects(
      main(withoutOption(planArguments(files.scopePath), name), {
        clock: () => NOW,
        env: {},
        credentialStdinReader: async () => {
          credentialReads += 1
          return Buffer.from(COOKIE, 'ascii')
        },
        transport: async () => { transportCalls += 1 },
        write: () => {},
      }),
      new RegExp(`requires --${name}|${name.replaceAll('-', '[ -]')}`, 'i'),
    )
    assert.equal(transportCalls, 0)
    assert.equal(credentialReads, 0)
    await assert.rejects(access(files.scopePath), { code: 'ENOENT' })
  }
})

test('plan-attested refuses a validity window that is not current', async (t) => {
  const files = await fixture(t, 'expired-window')
  const args = planArguments(files.scopePath)
  args[args.indexOf('--not-before') + 1] = '2026-08-17T07:00:00.000Z'
  args[args.indexOf('--not-after') + 1] = '2026-08-17T08:00:00.000Z'
  let transportCalls = 0
  await assert.rejects(
    main(args, {
      clock: () => NOW,
      env: {},
      credentialStdinReader: async () => Buffer.from(COOKIE, 'ascii'),
      transport: async () => { transportCalls += 1 },
      write: () => {},
    }),
    /authorization.*expired|validity.*current|window/i,
  )
  assert.equal(transportCalls, 0)
  await assert.rejects(access(files.scopePath), { code: 'ENOENT' })
})

test('validate-attested rejects an attestation timestamp in the future', async (t) => {
  const files = await fixture(t, 'future-attestation')
  await planAttested(files)
  const scope = JSON.parse(await readFile(files.scopePath, 'utf8'))
  scope.authorization.attested_at = '2026-08-17T10:30:00.000Z'
  await writeFile(files.scopePath, stableJson(scope), 'utf8')
  let transportCalls = 0

  await assert.rejects(
    main(['validate-attested', '--scope', files.scopePath, '--json'], {
      clock: () => NOW,
      transport: async () => { transportCalls += 1 },
      write: () => {},
    }),
    /attest.*(?:future|current|verification time)|(?:future|current|verification time).*attest/i,
  )
  assert.equal(transportCalls, 0)
})

test('validate-attested requires attested_at to fall inside the sealed validity window', async (t) => {
  const files = await fixture(t, 'attestation-outside-window')
  await planAttested(files)
  const scope = JSON.parse(await readFile(files.scopePath, 'utf8'))
  scope.authorization.attested_at = '2026-08-17T08:59:59.999Z'
  await writeFile(files.scopePath, stableJson(scope), 'utf8')
  let transportCalls = 0

  await assert.rejects(
    main(['validate-attested', '--scope', files.scopePath, '--json'], {
      clock: () => NOW,
      transport: async () => { transportCalls += 1 },
      write: () => {},
    }),
    /attest(?:ation|ed).*(?:validity|window)|(?:validity|window).*attest/i,
  )
  assert.equal(transportCalls, 0)
})

test('plan-attested rejects a non-synthetic query in its first seed without discovery', async (t) => {
  await assertUnsafeAttestedUrlRejected(t, 'unsafe-first-seed-query', (args) => {
    args[args.indexOf('--seed-url') + 1] =
      'https://bounty.example.test/authorized/non-phi-seed?patient=REAL_PATIENT_123'
  })
})

test('plan-attested checks every seed for non-synthetic query values without discovery', async (t) => {
  await assertUnsafeAttestedUrlRejected(t, 'unsafe-later-seed-query', (args) => {
    args.splice(args.indexOf('--json'), 0,
      '--seed-url',
      'https://bounty.example.test/authorized/second?patient=REAL_PATIENT_456')
  })
})

test('plan-attested rejects a non-synthetic preflight query without discovery', async (t) => {
  await assertUnsafeAttestedUrlRejected(t, 'unsafe-preflight-query', (args) => {
    args.splice(args.indexOf('--json'), 0,
      '--preflight-url',
      'https://bounty.example.test/authorized/whoami?patient=REAL_PATIENT_789')
  })
})

test('plan-attested accepts explicit synthetic query values without enabling discovery', async (t) => {
  const files = await fixture(t, 'synthetic-query')
  const args = planArguments(files.scopePath)
  args[args.indexOf('--seed-url') + 1] =
    'https://bounty.example.test/authorized/non-phi-seed?patient=SYNTHETIC_PATIENT_0001'
  args.splice(args.indexOf('--json'), 0,
    '--preflight-url',
    'https://bounty.example.test/authorized/whoami?session=SYNTHETIC_SESSION_0001')
  const planned = await planAttested(files, { args })
  const scope = JSON.parse(await readFile(files.scopePath, 'utf8'))

  assert.equal(planned.transportCalls, 0)
  assert.equal(scope.discovery, undefined)
  assert.match(scope.requests[0].url, /patient=SYNTHETIC_PATIENT_0001$/)
  assert.match(
    scope.liveness.credential_preflight.url,
    /session=SYNTHETIC_SESSION_0001$/,
  )
})

test('attested commands reject every document-authority flag', async (t) => {
  const files = await fixture(t, 'document-flags')
  for (const [name, value] of [
    ['authorization-document', join(files.directory, 'not-used.txt')],
    ['document-issuer', 'Synthetic issuer'],
    ['document-issued-at', '2026-08-01T00:00:00.000Z'],
  ]) {
    const args = planArguments(files.scopePath)
    args.push(`--${name}`, value)
    await assert.rejects(
      main(args, { clock: () => NOW, write: () => {} }),
      new RegExp(`plan-attested does not support --${name}`),
    )
  }

  await assert.rejects(
    main([
      'validate-attested', '--scope', files.scopePath,
      '--authorization-document', 'not-used.txt',
    ], { clock: () => NOW, write: () => {} }),
    /validate-attested does not support --authorization-document/,
  )

  await assert.rejects(
    main(['campaign-attested', '--authorization-document', 'not-used.txt']),
    /campaign-attested does not support --authorization-document/,
  )
})

test('validate-attested verifies the sealed attestation offline without credential or document input', async (t) => {
  const files = await fixture(t, 'validate')
  const planned = await planAttested(files)
  let output = ''
  let transportCalls = 0
  let credentialReads = 0

  await main([
    'validate-attested',
    '--scope', files.scopePath,
    '--json',
  ], {
    clock: () => NOW,
    env: {},
    credentialStdinReader: async () => {
      credentialReads += 1
      throw new Error('attested validation must not read credentials')
    },
    transport: async () => {
      transportCalls += 1
      throw new Error('attested validation must remain offline')
    },
    write: (value) => { output += value },
  })

  const validation = JSON.parse(output)
  assert.equal(transportCalls, 0)
  assert.equal(credentialReads, 0)
  assert.equal(validation.kind, 'red-team-audit/http-authed-attested-validation')
  assert.equal(validation.authorization_mode, 'OPERATOR_ATTESTED_AUTHED')
  assert.equal(validation.independently_verified, false)
  assert.equal(
    validation.authorization_binding_sha256,
    planned.summary.authorization_binding_sha256,
  )
  assert.equal(validation.campaign_grant_sha256, planned.summary.campaign_grant_sha256)
})

test('attested-campaign runtime uses sealed stdin and persists no credential, PHI body, or header value', async (t) => {
  const files = await fixture(t, 'campaign')
  const planArgs = planArguments(files.scopePath)
  planArgs.splice(planArgs.indexOf('--json'), 0,
    '--enable-discovery',
    '--discovery-source', 'location_header')
  const planned = await planAttested(files, { args: planArgs })
  let credentialReads = 0
  let transportCalls = 0

  const result = await runHttpAuthedAttestedCampaign({
    scopePath: files.scopePath,
    expectedCampaignGrantSha256: planned.summary.campaign_grant_sha256,
    ledgerDirectory: files.ledgerDirectory,
    operatorId: 'security-researcher',
    authorizationConfirmed: true,
    clock: () => NOW,
    env: {},
    credentialInput: Symbol('sealed campaign stdin credential'),
    credentialStdinReader: async () => {
      credentialReads += 1
      return Buffer.from(COOKIE, 'ascii')
    },
    protectedTransport: async (request) => {
      transportCalls += 1
      assert.equal(request.headers.cookie, COOKIE)
      assert.equal(request.headers.authorization, undefined)
      await request.beforeSend()
      await request.responseObserver?.({
        status: 200,
        headers: [
          { name: 'set-cookie', value: HEADER_VALUE_SENTINEL },
          { name: 'content-type', value: 'text/plain' },
        ],
        bodyChunks: [Buffer.from(PHI_BODY_SENTINEL, 'utf8')],
      })
      return {
        status: 200,
        responseBytes: Buffer.byteLength(PHI_BODY_SENTINEL),
        responseHeaderNames: ['set-cookie', 'content-type'],
      }
    },
  })

  assert.equal(credentialReads, 1)
  assert.equal(transportCalls, 1)
  assert.equal(result.actions.completed, 1)
  assert.equal(result.authorization_mode, 'OPERATOR_ATTESTED_AUTHED')
  assert.equal(result.independently_verified, false)
  assert.match(result.authorization_binding_sha256, /^[a-f0-9]{64}$/)

  const entries = await readdir(files.ledgerDirectory, { withFileTypes: true })
  const ledgerRecordTexts = await Promise.all(entries
    .filter((entry) => entry.isFile())
    .map((entry) => readFile(join(files.ledgerDirectory, entry.name), 'utf8')))
  const ledgerRecords = ledgerRecordTexts.map((text) => JSON.parse(text))
  assert.ok(ledgerRecords.length > 0)
  const expectedRecordFields = [
    'schema_version',
    'kind',
    'record_sequence',
    'previous_record_sha256',
    'campaign_grant_sha256',
    'authorization_binding_sha256',
    'authorization_mode',
    'independently_verified',
    'authorization_assurance',
    'authorization_nonclaim',
    'at',
    'event',
  ].sort()
  for (const record of ledgerRecords) {
    assert.deepEqual(Object.keys(record).sort(), expectedRecordFields)
    assert.equal(record.schema_version, '1.2.0')
    assert.equal(record.authorization_mode, 'OPERATOR_ATTESTED_AUTHED')
    assert.equal(record.independently_verified, false)
    assert.equal(record.authorization_assurance, 'OPERATOR_DECLARATION_ONLY')
    assert.equal(record.authorization_nonclaim, 'NOT_INDEPENDENTLY_VERIFIED')
  }
  const genesis = ledgerRecords.find((record) => record.record_sequence === 0)
  assert.equal(genesis?.event?.type, 'CAMPAIGN_OPENED')
  const sessionConfirmations = ledgerRecords
    .filter((record) => record.event.type === 'CAMPAIGN_SESSION_CONFIRMED')
  assert.equal(sessionConfirmations.length, 1)
  assert.deepEqual(sessionConfirmations[0].event, {
    type: 'CAMPAIGN_SESSION_CONFIRMED',
    operator_id: 'security-researcher',
    authorization_mode: 'OPERATOR_ATTESTED_AUTHED',
    confirmation: 'CURRENT_AUTHORIZATION_CONFIRMED',
  })
  const firstLease = ledgerRecords.find((record) => record.event.type === 'ACTION_LEASED')
  assert.ok(firstLease)
  assert.ok(sessionConfirmations[0].record_sequence < firstLease.record_sequence)
  const ledgerText = ledgerRecordTexts.join('\n')
  const durableText = [
    await readFile(files.scopePath, 'utf8'),
    ledgerText,
    JSON.stringify(result),
  ].join('\n')
  assert.equal(durableText.includes(COOKIE), false)
  assert.equal(durableText.includes(PHI_BODY_SENTINEL), false)
  assert.equal(durableText.includes(HEADER_VALUE_SENTINEL), false)
  assert.match(ledgerText, /"authorization_binding_sha256"\s*:\s*"[a-f0-9]{64}"/)
})

test('attested-campaign runtime rejects missing launch confirmation and operator drift before ledger or network', async (t) => {
  const files = await fixture(t, 'pre-dispatch')
  const planned = await planAttested(files)
  let credentialReads = 0
  let transportCalls = 0
  const deps = {
    scopePath: files.scopePath,
    expectedCampaignGrantSha256: planned.summary.campaign_grant_sha256,
    ledgerDirectory: files.ledgerDirectory,
    clock: () => NOW,
    env: {},
    credentialInput: Symbol('sealed campaign stdin credential'),
    credentialStdinReader: async () => {
      credentialReads += 1
      return Buffer.from(COOKIE, 'ascii')
    },
    protectedTransport: async () => { transportCalls += 1 },
  }

  await assert.rejects(
    runHttpAuthedAttestedCampaign({
      ...deps,
      operatorId: 'security-researcher',
      authorizationConfirmed: false,
    }),
    /requires explicit controller launch confirmation/i,
  )
  assert.equal(credentialReads, 0)
  assert.equal(transportCalls, 0)
  await assert.rejects(access(files.ledgerDirectory), { code: 'ENOENT' })

  await assert.rejects(
    runHttpAuthedAttestedCampaign({
      ...deps,
      operatorId: 'different-security-researcher',
      authorizationConfirmed: true,
    }),
    /operator.*match|operator.*mismatch/i,
  )
  assert.equal(credentialReads, 0)
  assert.equal(transportCalls, 0)
  await assert.rejects(access(files.ledgerDirectory), { code: 'ENOENT' })
})

test('plan-attested uses the operator statement as explicit mutation authorization', async (t) => {
  const unsafeFiles = await fixture(t, 'mutation-permission')
  const unsafeArgs = planArguments(unsafeFiles.scopePath)
  unsafeArgs.splice(unsafeArgs.indexOf('--method'), 0, '--method', 'POST')
  unsafeArgs.splice(unsafeArgs.indexOf('--seed-url'), 0, '--seed-method', 'POST')
  await assert.rejects(
    main(unsafeArgs, {
      clock: () => NOW,
      env: {},
      credentialStdinReader: async () => Buffer.from(COOKIE, 'ascii'),
      write: () => {},
    }),
    /mutation authorization|--mutation-authorized/i,
  )
  await assert.rejects(access(unsafeFiles.scopePath), { code: 'ENOENT' })

  const authorizedFiles = await fixture(t, 'mutation-authorized')
  const authorizedArgs = planArguments(authorizedFiles.scopePath)
  authorizedArgs.splice(authorizedArgs.indexOf('--method'), 0, '--method', 'POST')
  authorizedArgs.splice(authorizedArgs.indexOf('--seed-url'), 0, '--seed-method', 'POST')
  authorizedArgs.splice(authorizedArgs.indexOf('--json'), 0, '--mutation-authorized')
  await main(authorizedArgs, {
    clock: () => NOW,
    env: {},
    credentialStdinReader: async () => Buffer.from(COOKIE, 'ascii'),
    write: () => {},
  })
  const authorizedScope = JSON.parse(await readFile(authorizedFiles.scopePath, 'utf8'))
  assert.equal(authorizedScope.authorization.permissions.mutation, true)
  assert.equal(authorizedScope.approver, undefined)
})

test('attested mutation planning refuses non-synthetic body and resource identifiers', async (t) => {
  for (const [name, makeUnsafe, expected] of [
    [
      'unsafe-body-id',
      (action) => { action.request_body.body_id = 'patient-record-body-12345' },
      /body(?:_id| identifier)?.*synthetic|synthetic.*body(?:_id| identifier)?/i,
    ],
    [
      'unsafe-rollback-body-id',
      (action) => { action.rollback.request_body.body_id = 'patient-rollback-body-12345' },
      /body(?:_id| identifier)?.*synthetic|synthetic.*body(?:_id| identifier)?/i,
    ],
    [
      'unsafe-resource-ref',
      (action) => { action.expected_mutation.resource_ref = 'real patient record 12345' },
      /resource(?:_ref| reference)?.*synthetic|synthetic.*resource(?:_ref| reference)?/i,
    ],
  ]) {
    await t.test(name, async (subtest) => {
      const files = await fixture(subtest, name)
      const { input, action } = await attestedMutationPlannerInput(files)
      makeUnsafe(action)
      await assert.rejects(
        planHttpAuthedAttestedScope(input, {
          clock: () => NOW,
          env: { ATTESTED_MUTATION_CREDENTIAL: COOKIE },
        }),
        expected,
      )
      await assert.rejects(access(files.scopePath), { code: 'ENOENT' })
    })
  }
})

test('attested mutation planning accepts explicit synthetic body and resource identifiers', async (t) => {
  const files = await fixture(t, 'synthetic-mutation-identifiers')
  const { input } = await attestedMutationPlannerInput(files)
  const summary = await planHttpAuthedAttestedScope(input, {
    clock: () => NOW,
    env: { ATTESTED_MUTATION_CREDENTIAL: COOKIE },
  })
  const scope = JSON.parse(await readFile(files.scopePath, 'utf8'))

  assert.equal(summary.authorization_mode, 'OPERATOR_ATTESTED_AUTHED')
  assert.equal(scope.requests[0].request_body.body_id, 'SYNTHETIC_MUTATION_BODY_0001')
  assert.equal(
    scope.requests[0].rollback.request_body.body_id,
    'SYNTHETIC_ROLLBACK_BODY_0001',
  )
  assert.equal(
    scope.requests[0].expected_mutation.resource_ref,
    'SYNTHETIC_RESOURCE_0001',
  )
})

test('campaign runtime rejects the retired authorization mode before credentials, ledger, or network', async (t) => {
  const files = await fixture(t, 'retired-authorization-mode')
  const legacyScope = attestedScope({ actionCount: 1 })
  legacyScope.authorization.mode = 'WRITTEN_AUTHORIZATION_AUTHED'
  await writeFile(files.scopePath, stableJson(legacyScope), 'utf8')
  let credentialReads = 0
  let transportCalls = 0

  await assert.rejects(
    runHttpAuthedAttestedCampaign({
      scopePath: files.scopePath,
      expectedCampaignGrantSha256: 'a'.repeat(64),
      ledgerDirectory: files.ledgerDirectory,
      operatorId: 'peerstar-security-operator',
      authorizationConfirmed: true,
      clock: () => NOW,
      env: {},
      credentialInput: Symbol('sealed campaign stdin credential'),
      credentialStdinReader: async () => {
        credentialReads += 1
        return Buffer.from(COOKIE, 'ascii')
      },
      protectedTransport: async () => { transportCalls += 1 },
    }),
    (error) => error.code === 'HTTP_AUTHED_AUTHORIZATION_MODE_MISMATCH',
  )
  assert.equal(credentialReads, 0)
  assert.equal(transportCalls, 0)
  await assert.rejects(access(files.ledgerDirectory), { code: 'ENOENT' })
})

test('attested-campaign runtime rechecks scope and candidate bytes immediately before send', async (t) => {
  const files = await fixture(t, 'immediate-reauthorization')
  const planned = await planAttested(files)
  let transportCalls = 0
  let wireSends = 0

  const result = await runHttpAuthedAttestedCampaign({
    scopePath: files.scopePath,
    expectedCampaignGrantSha256: planned.summary.campaign_grant_sha256,
    ledgerDirectory: files.ledgerDirectory,
    operatorId: 'security-researcher',
    authorizationConfirmed: true,
    clock: () => NOW,
    env: {},
    credentialInput: Symbol('sealed campaign stdin credential'),
    credentialStdinReader: async () => Buffer.from(COOKIE, 'ascii'),
    protectedTransport: async (request) => {
      transportCalls += 1
      assert.equal(
        request.url,
        'https://bounty.example.test/authorized/non-phi-seed',
      )
      const drifted = JSON.parse(await readFile(files.scopePath, 'utf8'))
      drifted.requests[0].url = 'https://bounty.example.test/authorized/drifted-candidate'
      await writeFile(files.scopePath, stableJson(drifted), 'utf8')
      await request.beforeSend()
      wireSends += 1
      return { status: 200, responseBytes: 0, responseHeaderNames: [] }
    },
  })

  assert.equal(transportCalls, 1)
  assert.equal(wireSends, 0)
  assert.equal(result.actions.completed, 0)
  assert.equal(result.actions.failed, 1)
  assert.equal(result.actions.uncertain, 0)
  assert.equal(result.ledger.terminal_actions, 1)
})

test('attested authorization binding refuses ledger records missing the binding field', async (t) => {
  const files = await fixture(t, 'missing-ledger-binding')
  const planned = await planAttested(files)
  const ledger = await openHttpAuthedCampaignLedger({
    directory: files.ledgerDirectory,
    campaignGrantSha256: planned.summary.campaign_grant_sha256,
    authorizationBindingSha256: planned.summary.authorization_binding_sha256,
    authorizationMode: 'OPERATOR_ATTESTED_AUTHED',
    operatorId: 'security-researcher',
    initialize: true,
    now: () => NOW,
  })
  await ledger.close()

  const recordPath = join(
    files.ledgerDirectory,
    '0000000000000000.http-authed-campaign.json',
  )
  const record = JSON.parse(await readFile(recordPath, 'utf8'))
  delete record.authorization_binding_sha256
  await writeFile(recordPath, stableJson(record), 'utf8')

  await assert.rejects(
    openHttpAuthedCampaignLedger({
      directory: files.ledgerDirectory,
      campaignGrantSha256: planned.summary.campaign_grant_sha256,
      authorizationBindingSha256: planned.summary.authorization_binding_sha256,
      authorizationMode: 'OPERATOR_ATTESTED_AUTHED',
      operatorId: 'security-researcher',
      initialize: false,
      now: () => NOW,
    }),
    (error) => error.code === 'HTTP_AUTHED_LEDGER_RECORD_INVALID',
  )
})

test('attested mutation campaign durably qualifies authorization, verification, and rollback', async (t) => {
  const files = await fixture(t, 'mutation-e2e')
  const materialsDirectory = join(files.directory, 'materials')
  await mkdir(materialsDirectory)
  const mutationCredential = 'SYNTHETIC_ATTESTED_MUTATION_CREDENTIAL'
  const mutationBody = Buffer.alloc(64, 0x6d)
  const rollbackBody = Buffer.alloc(64, 0x72)
  const scope = attestedScope({ actionCount: 1 })
  scope.authorization.mode = 'OPERATOR_ATTESTED_AUTHED'
  scope.authorization.statement = OPERATOR_ATTESTED_AUTHED_STATEMENT
  scope.authorization.attested_at = NOW.toISOString()
  scope.validity = {
    not_before: '2026-08-17T09:00:00.000Z',
    not_after: '2026-08-17T11:00:00.000Z',
    cleanup_not_after: '2026-08-17T11:00:00.000Z',
  }
  scope.limits.min_interval_ms = 0
  scope.credential.binding_sha256 = sha256Hex(Buffer.from(mutationCredential, 'utf8'))
  scope.requests[0].request_body.sha256 = sha256Hex(mutationBody)
  scope.requests[0].rollback.request_body.sha256 = sha256Hex(rollbackBody)
  const verified = verifyHttpAuthedAuthorization({ scope, now: NOW })
  const bodyPath = (metadata) => join(
    materialsDirectory,
    `body-${sha256Hex(Buffer.from(metadata.body_id, 'utf8'))}.bin`,
  )
  await Promise.all([
    writeFile(files.scopePath, stableJson(scope), 'utf8'),
    writeFile(bodyPath(scope.requests[0].request_body), mutationBody),
    writeFile(bodyPath(scope.requests[0].rollback.request_body), rollbackBody),
  ])

  const methods = []
  let wireSends = 0
  const result = await runHttpAuthedAttestedCampaign({
    scopePath: files.scopePath,
    expectedCampaignGrantSha256: verified.campaignGrantSha256,
    ledgerDirectory: files.ledgerDirectory,
    materialsDirectory,
    operatorId: scope.authorization.operator_id,
    authorizationConfirmed: true,
    env: { SYNTHETIC_TEST_CREDENTIAL: mutationCredential },
    clock: () => NOW,
    protectedTransport: async (request) => {
      await request.beforeSend()
      wireSends += 1
      methods.push(request.method)
      const body = Buffer.from('{}', 'utf8')
      await request.responseObserver?.({
        status: 200,
        headers: [{ name: 'content-type', value: 'application/json' }],
        bodyChunks: [body],
      })
      return {
        status: 200,
        responseBytes: body.length,
        responseHeaderNames: ['content-type'],
      }
    },
    mutationDependencies: {
      verifyObservation: async () => ({
        valueMatch: true,
        contextMatch: true,
        contextToken: 'synthetic-attested-context',
      }),
    },
  })

  assert.deepEqual(methods, ['GET', 'GET', 'POST', 'GET', 'PATCH', 'GET'])
  assert.equal(wireSends, 6)
  assert.equal(result.actions.completed, 1)
  assert.equal(result.actions.failed, 0)
  assert.equal(result.authorization_mode, 'OPERATOR_ATTESTED_AUTHED')
  assert.equal(result.independently_verified, false)
  assert.equal(result.authorization_binding_sha256, verified.authorizationBindingSha256)
  const ledgerText = (await Promise.all(
    (await readdir(files.ledgerDirectory))
      .filter((name) => name.endsWith('.json'))
      .map((name) => readFile(join(files.ledgerDirectory, name), 'utf8')),
  )).join('\n')
  assert.match(ledgerText, /AUTHORIZATION_CONSUMED/)
  assert.match(ledgerText, /dispatch_permit_sha256/)
  assert.doesNotMatch(ledgerText, /countersignature/i)
})
