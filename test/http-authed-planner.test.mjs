import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { main } from '../scripts/http-authed.mjs'
import {
  readAndVerifyHttpAuthedAuthorization,
  sha256Hex,
} from '../scripts/lib/http-authed-contracts.mjs'

const NOW = new Date('2026-08-17T10:00:00.000Z')
const CREDENTIAL = 'SYNTHETIC_CREDENTIAL_VALUE_MUST_NOT_PERSIST'

async function fixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'http-authed-planner-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const scopePath = join(directory, 'scope.json')
  return { directory, scopePath }
}

function planAttestedArguments({ scopePath }) {
  return [
    'plan-attested',
    '--scope', scopePath,
    '--engagement-id', 'generic-vendor-bounty-2026',
    '--authorization-id', 'vendor-program-2026',
    '--operator-id', 'security-researcher',
    '--authorized-by', 'Vendor security team',
    '--authorization-reference', 'Vendor bug bounty terms accepted 2026-08-01',
    '--not-before', '2026-08-17T09:00:00.000Z',
    '--not-after', '2026-08-18T09:00:00.000Z',
    '--target-origin', 'https://bounty.example.test',
    '--environment', 'production',
    '--data-class', 'unknown',
    '--ownership', 'third_party_owned',
    '--credential-env', 'GENERIC_BOUNTY_CREDENTIAL',
    '--credential-kind', 'bearer',
    '--path-prefix', '/',
    '--method', 'HEAD',
    '--method', 'GET',
    '--method', 'OPTIONS',
    '--test-category', 'authentication',
    '--test-category', 'api_security',
    '--seed-url', 'https://bounty.example.test/security/start',
    '--seed-test-category', 'api_security',
    '--enable-discovery',
    '--json',
  ]
}

function removeOption(args, name) {
  const option = `--${name}`
  for (let index = args.length - 1; index >= 0; index -= 1) {
    if (args[index] === option) {
      args.splice(index, ['enable-discovery', 'mutation-authorized'].includes(name)
        ? 1
        : 2)
    }
  }
}

function requestPlanArguments(files, requestsPath) {
  const args = planAttestedArguments(files)
  removeOption(args, 'seed-url')
  removeOption(args, 'seed-test-category')
  args.splice(args.indexOf('--json'), 0, '--requests', requestsPath)
  return args
}

function mutationRequestDraft(origin = 'https://bounty.example.test') {
  const url = `${origin}/security/synthetic-resource/1`
  return {
    kind: 'mutate',
    sequence: 97,
    test_category: 'api_security',
    method: 'POST',
    url,
    success_statuses: [200, 201, 204],
    request_body: {
      body_id: 'SYNTHETIC_SECURITY_TEST_PAYLOAD_1',
      sha256: '4'.repeat(64),
      byte_length: 64,
      content_type: 'application/json',
      data_class: 'synthetic_non_phi',
    },
    expected_mutation: {
      resource_ref: 'SYNTHETIC_SECURITY_TEST_RECORD_1',
      field: '/synthetic_marker',
      representation: 'CANONICAL_JSON_VALUE_SHA256',
      before_digest: '2'.repeat(64),
      after_digest: '3'.repeat(64),
    },
    before_read: {
      method: 'GET',
      url,
      expected_statuses: [200],
      observation: { format: 'JSON', json_pointer: '/synthetic_marker' },
    },
    after_read: {
      method: 'GET',
      url,
      expected_statuses: [200],
      observation: { format: 'JSON', json_pointer: '/synthetic_marker' },
    },
    rollback: {
      method: 'PATCH',
      url,
      expected_after_digest: '2'.repeat(64),
      idempotent_restore: true,
      success_statuses: [200],
      request_body: {
        body_id: 'SYNTHETIC_SECURITY_TEST_ROLLBACK_1',
        sha256: '5'.repeat(64),
        byte_length: 64,
        content_type: 'application/json',
        data_class: 'synthetic_non_phi',
      },
      verification_read: {
        method: 'GET',
        url,
        expected_statuses: [200],
        observation: { format: 'JSON', json_pointer: '/synthetic_marker' },
      },
    },
    rollback_policy: 'ALWAYS',
  }
}

function addMutationPlannerOptions(args) {
  args.splice(args.indexOf('--json'), 0,
    '--method', 'POST',
    '--method', 'PATCH',
    '--mutation-authorized',
  )
}

test('plan-attested creates and validates a generic offline campaign without persisting secrets', async (t) => {
  const files = await fixture(t)
  let output = ''
  let transportCalls = 0

  await main(planAttestedArguments(files), {
    clock: () => NOW,
    env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
    transport: async () => {
      transportCalls += 1
      throw new Error('planner must not use network transport')
    },
    write: (text) => { output += text },
  })

  assert.equal(transportCalls, 0)
  const summary = JSON.parse(output)
  assert.equal(summary.kind, 'red-team-audit/http-authed-attested-plan')
  assert.equal(summary.target_origin, 'https://bounty.example.test')
  assert.equal(summary.request_count, 1)
  assert.match(summary.campaign_grant_sha256, /^[a-f0-9]{64}$/)

  const scopeText = await readFile(files.scopePath, 'utf8')
  const plannedScope = JSON.parse(scopeText)
  assert.equal(plannedScope.schema_version, '1.0.0')
  assert.equal(plannedScope.response_observation, undefined)
  assert.equal(scopeText.includes(CREDENTIAL), false)
  assert.equal(output.includes(CREDENTIAL), false)

  const verified = await readAndVerifyHttpAuthedAuthorization({
    scopePath: files.scopePath,
    requiredMode: 'OPERATOR_ATTESTED_AUTHED',
    now: NOW,
  })
  assert.equal(verified.campaignGrantSha256, summary.campaign_grant_sha256)
  assert.deepEqual(verified.scope.authorization.permissions, {
    active_testing: true,
    production: true,
    third_party: true,
    phi: true,
    mutation: false,
  })
  assert.equal(verified.scope.credential.ref, 'env:GENERIC_BOUNTY_CREDENTIAL')
  assert.equal(
    verified.scope.credential.binding_sha256,
    sha256Hex(Buffer.from(CREDENTIAL, 'utf8')),
  )
  assert.equal(verified.scope.approver, undefined)
  assert.deepEqual(verified.scope.authorization.authorized_scope, {
    origins: ['https://bounty.example.test'],
    path_prefixes: ['/'],
    methods: ['HEAD', 'GET', 'OPTIONS'],
    test_categories: ['authentication', 'api_security'],
  })
  assert.deepEqual(verified.scope.requests, [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: 'https://bounty.example.test/security/start',
    expected_effect: 'none',
  }])
  assert.deepEqual(verified.scope.target, {
    origin: 'https://bounty.example.test',
    ownership: 'third_party_owned',
    tls: { mode: 'PKIX_HOSTNAME' },
  })
  assert.deepEqual(verified.scope.limits, {
    request_timeout_ms: 10000,
    max_response_bytes: 65536,
    min_interval_ms: 1000,
    concurrency: 1,
    max_actions: 10000,
  })
  assert.deepEqual(verified.scope.evidence_handling, {
    persist_request_bodies: false,
    persist_response_bodies: false,
    persist_credential_values: false,
    persist_header_values: false,
    stop_on_sensitive_data: true,
    test_data: 'synthetic_only',
  })
  assert.equal(verified.scope.stop_conditions.length, 9)
  assert.deepEqual(verified.scope.discovery.candidate_methods, ['HEAD', 'GET', 'OPTIONS'])
  assert.equal(verified.scope.discovery.test_category, 'api_security')
  assert.equal(verified.scope.requests[0].test_category, 'api_security')
})

test('plan-attested seals an explicitly opted-in JSON shape allowlist', async (t) => {
  const files = await fixture(t)
  const args = planAttestedArguments(files)
  args.splice(args.indexOf('--json'), 0,
    '--observe-json-shape',
    '--json-shape-key', 'records',
    '--json-shape-key', 'id',
    '--json-shape-max-depth', '3',
  )

  await main(args, {
    clock: () => NOW,
    env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
    transport: async () => { throw new Error('planner must remain offline') },
    write: () => {},
  })

  const scope = JSON.parse(await readFile(files.scopePath, 'utf8'))
  assert.equal(scope.schema_version, '1.1.0')
  assert.deepEqual(scope.response_observation, {
    mode: 'JSON_SHAPE_ONLY',
    max_depth: 3,
    safe_key_names: ['records', 'id'],
  })
  const verified = await readAndVerifyHttpAuthedAuthorization({
    scopePath: files.scopePath,
    requiredMode: 'OPERATOR_ATTESTED_AUTHED',
    now: NOW,
  })
  assert.deepEqual(verified.scope.response_observation, scope.response_observation)
})

test('plan-attested seals an explicitly opted-in ASP.NET d JSON projection', async (t) => {
  const files = await fixture(t)
  const args = planAttestedArguments(files)
  args.splice(args.indexOf('--json'), 0,
    '--observe-json-shape',
    '--json-shape-aspnet-d',
    '--json-shape-key', 'records',
    '--json-shape-key', 'id',
    '--json-shape-max-depth', '3',
  )

  await main(args, {
    clock: () => NOW,
    env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
    transport: async () => { throw new Error('planner must remain offline') },
    write: () => {},
  })

  const scope = JSON.parse(await readFile(files.scopePath, 'utf8'))
  assert.equal(scope.schema_version, '1.2.0')
  assert.deepEqual(scope.response_observation, {
    mode: 'ASPNET_D_JSON_SHAPE_ONLY',
    max_depth: 3,
    safe_key_names: ['records', 'id'],
  })
  const verified = await readAndVerifyHttpAuthedAuthorization({
    scopePath: files.scopePath,
    requiredMode: 'OPERATOR_ATTESTED_AUTHED',
    now: NOW,
  })
  assert.deepEqual(verified.scope.response_observation, scope.response_observation)
})

test('JSON shape planner options fail closed unless the allowlist is explicit and valid', async (t) => {
  const files = await fixture(t)
  const scenarios = [
    {
      name: 'key-without-opt-in',
      options: ['--json-shape-key', 'records'],
      pattern: /require --observe-json-shape/i,
    },
    {
      name: 'opt-in-without-key',
      options: ['--observe-json-shape'],
      pattern: /requires at least one --json-shape-key/i,
    },
    {
      name: 'invalid-key',
      options: ['--observe-json-shape', '--json-shape-key', 'unsafe key'],
      pattern: /schema|response observation|invalid/i,
    },
    {
      name: 'duplicate-key',
      options: [
        '--observe-json-shape',
        '--json-shape-key', 'records',
        '--json-shape-key', 'records',
      ],
      pattern: /duplicates/i,
    },
    {
      name: 'depth-out-of-range',
      options: [
        '--observe-json-shape',
        '--json-shape-key', 'records',
        '--json-shape-max-depth', '5',
      ],
      pattern: /depth.*1 through 4/i,
    },
    {
      name: 'aspnet-without-opt-in',
      options: ['--json-shape-aspnet-d'],
      pattern: /require --observe-json-shape/i,
    },
  ]

  for (const scenario of scenarios) {
    const scopePath = join(files.directory, `${scenario.name}-scope.json`)
    const args = planAttestedArguments({ ...files, scopePath })
    args.splice(args.indexOf('--json'), 0, ...scenario.options)
    await assert.rejects(
      main(args, {
        clock: () => NOW,
        env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
        write: () => {},
      }),
      scenario.pattern,
    )
    await assert.rejects(readFile(scopePath), { code: 'ENOENT' })
  }
})

test('plan-attested refuses to invent unavailable credentials and does not create output', async (t) => {
  const files = await fixture(t)
  await assert.rejects(
    main(planAttestedArguments(files), {
      clock: () => NOW,
      env: {},
      write: () => {},
    }),
    /credential.*unavailable/i,
  )
  await assert.rejects(readFile(files.scopePath), { code: 'ENOENT' })
})

test('plan-attested binds one redirected credential without persisting or printing it', async (t) => {
  const files = await fixture(t)
  const args = planAttestedArguments(files)
  const credentialOption = args.indexOf('--credential-env')
  args.splice(credentialOption, 2, '--credential-stdin')
  let reads = 0
  let output = ''

  await main(args, {
    clock: () => NOW,
    env: {},
    credentialStdinReader: async () => {
      reads += 1
      return Buffer.from(CREDENTIAL, 'utf8')
    },
    write: (text) => { output += text },
  })

  assert.equal(reads, 1)
  const scopeText = await readFile(files.scopePath, 'utf8')
  const scope = JSON.parse(scopeText)
  assert.equal(scope.credential.ref, 'stdin:PIPE')
  assert.equal(scope.credential.binding_sha256, sha256Hex(Buffer.from(CREDENTIAL, 'utf8')))
  assert.equal(scopeText.includes(CREDENTIAL), false)
  assert.equal(output.includes(CREDENTIAL), false)
})

test('plan-attested seals a Chrome-held active-tab session without exporting a credential', async (t) => {
  const files = await fixture(t)
  const args = planAttestedArguments(files)
  const credentialOption = args.indexOf('--credential-env')
  args.splice(
    credentialOption,
    4,
    '--credential-browser',
    '--browser-extension-id', 'abcdefghijklmnopabcdefghijklmnop',
  )
  let reads = 0
  let output = ''

  await main(args, {
    clock: () => NOW,
    env: {},
    credentialStdinReader: async () => {
      reads += 1
      throw new Error('browser-held planning must not read a credential')
    },
    write: (text) => { output += text },
  })

  assert.equal(reads, 0)
  const scopeText = await readFile(files.scopePath, 'utf8')
  const scope = JSON.parse(scopeText)
  assert.deepEqual(scope.credential, {
    mode: 'CHROME_ACTIVE_TAB_SESSION',
    extension_id: 'abcdefghijklmnopabcdefghijklmnop',
    origin: 'https://bounty.example.test',
  })
  assert.equal(scopeText.includes('binding_sha256'), false)
  assert.equal(scopeText.includes('cookie'), false)
  assert.equal(output.includes('cookie'), false)
  await readAndVerifyHttpAuthedAuthorization({
    scopePath: files.scopePath,
    requiredMode: 'OPERATOR_ATTESTED_AUTHED',
    now: NOW,
  })
})

test('plan-attested keeps browser-held and exported credential sources mutually exclusive', async (t) => {
  const files = await fixture(t)
  const mixed = planAttestedArguments(files)
  mixed.splice(mixed.indexOf('--json'), 0,
    '--credential-browser',
    '--browser-extension-id', 'abcdefghijklmnopabcdefghijklmnop',
  )
  await assert.rejects(
    main(mixed, {
      clock: () => NOW,
      env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
      write: () => {},
    }),
    /exactly one/i,
  )
  await assert.rejects(readFile(files.scopePath), { code: 'ENOENT' })
})

test('plan-attested uses exclusive output creation and never overwrites a scope', async (t) => {
  const files = await fixture(t)
  await writeFile(files.scopePath, 'SENTINEL_EXISTING_SCOPE')
  await assert.rejects(
    main(planAttestedArguments(files), {
      clock: () => NOW,
      env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
      write: () => {},
    }),
    /already exists|exclusive|refus/i,
  )
  assert.equal(await readFile(files.scopePath, 'utf8'), 'SENTINEL_EXISTING_SCOPE')
})

test('plan-attested uses the operator statement as mutation authority without approver material', async (t) => {
  const files = await fixture(t)
  const args = planAttestedArguments(files)
  args.splice(args.indexOf('--json'), 0, '--mutation-authorized')
  await main(args, {
    clock: () => NOW,
    env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
    write: () => {},
  })
  const scope = JSON.parse(await readFile(files.scopePath, 'utf8'))
  assert.equal(scope.authorization.permissions.mutation, true)
  assert.equal(scope.approver, undefined)
})

test('retired written commands and authority-file flags fail before planner I/O', async (t) => {
  const files = await fixture(t)
  const cases = [
    ...['plan-written', 'validate-written', 'campaign-written'].map((command) => ({
      name: command,
      args: [command, '--authorization-document', 'must-not-read-authorization.txt'],
      pattern: /supported http-authed command/i,
    })),
    ...[
      ['authorization-document', 'must-not-read-authorization.txt'],
      ['approver-public-key', 'must-not-read-approver.pem'],
      ['countersignature', 'must-not-read-countersignature.json'],
    ].map(([flag, value]) => {
      const scopePath = join(files.directory, `retired-${flag}.json`)
      return {
        name: flag,
        scopePath,
        args: [...planAttestedArguments({ scopePath }), `--${flag}`, value],
        pattern: new RegExp(`plan-attested does not support --${flag}`, 'i'),
      }
    }),
  ]

  for (const scenario of cases) {
    let credentialReads = 0
    let requestPlanReads = 0
    let transportCalls = 0
    await assert.rejects(
      main(scenario.args, {
        clock: () => NOW,
        env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
        credentialStdinReader: async () => {
          credentialReads += 1
          return Buffer.from(CREDENTIAL, 'utf8')
        },
        requestPlanLstat: async () => {
          requestPlanReads += 1
          throw new Error('retired command or flag must fail before request-plan I/O')
        },
        transport: async () => { transportCalls += 1 },
        write: () => {},
      }),
      scenario.pattern,
      scenario.name,
    )
    assert.equal(credentialReads, 0, scenario.name)
    assert.equal(requestPlanReads, 0, scenario.name)
    assert.equal(transportCalls, 0, scenario.name)
    if (scenario.scopePath) {
      await assert.rejects(readFile(scenario.scopePath), { code: 'ENOENT' })
    }
  }
})

test('plan-attested rejects a write-capable seed without explicit mutation authority', async (t) => {
  const files = await fixture(t)
  const writeSeed = planAttestedArguments({
    ...files,
    scopePath: join(files.directory, 'write-seed.json'),
  })
  const seedMethodIndex = writeSeed.indexOf('--seed-method')
  if (seedMethodIndex < 0) {
    writeSeed.splice(writeSeed.indexOf('--json'), 0, '--seed-method', 'POST')
  } else {
    writeSeed[seedMethodIndex + 1] = 'POST'
  }
  await assert.rejects(
    main(writeSeed, {
      clock: () => NOW,
      env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
      write: () => {},
    }),
    (error) => error.code === 'HTTP_AUTHED_PLAN_MUTATION_AUTHORIZATION_REQUIRED',
  )
  await assert.rejects(readFile(join(files.directory, 'write-seed.json')), { code: 'ENOENT' })
})

test('plan-attested rejects URL credentials and fragments even when discovery is disabled', async (t) => {
  const files = await fixture(t)
  for (const [name, seedUrl, code] of [
    [
      'credentials',
      'https://synthetic-user:synthetic-password@bounty.example.test/security/start',
      'HTTP_AUTHED_URL_CREDENTIALS_REFUSED',
    ],
    [
      'fragment',
      'https://bounty.example.test/security/start#fragment',
      'HTTP_AUTHED_URL_FRAGMENT_REFUSED',
    ],
  ]) {
    const caseFiles = { ...files, scopePath: join(files.directory, `${name}.json`) }
    const args = planAttestedArguments(caseFiles)
    args.splice(args.indexOf('--enable-discovery'), 1)
    args[args.indexOf('https://bounty.example.test/security/start')] = seedUrl
    await assert.rejects(
      main(args, {
        clock: () => NOW,
        env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
        write: () => {},
      }),
      (error) => error.code === 'HTTP_AUTHED_PLAN_SCOPE_INVALID'
        && error.message.includes(code),
    )
    await assert.rejects(readFile(caseFiles.scopePath), { code: 'ENOENT' })
  }
})

test('plan-attested creates a valid probe-only scope with discovery disabled', async (t) => {
  const files = await fixture(t)
  const args = planAttestedArguments(files)
  args.splice(args.indexOf('--enable-discovery'), 1)
  await main(args, {
    clock: () => NOW,
    env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
    write: () => {},
  })
  const verified = await readAndVerifyHttpAuthedAuthorization({
    scopePath: files.scopePath,
    requiredMode: 'OPERATOR_ATTESTED_AUTHED',
    now: NOW,
  })
  assert.equal(verified.scope.discovery, undefined)
  assert.equal(verified.scope.requests[0].kind, 'probe')
})

test('plan-attested rejects widening and contradictory discovery input before writing', async (t) => {
  const files = await fixture(t)
  const cases = [
    {
      name: 'off-origin seed',
      mutate(args) {
        args[args.indexOf('https://bounty.example.test/security/start')] =
          'https://other.example.test/security/start'
      },
    },
    {
      name: 'missing preflight GET authority',
      mutate(args) {
        for (let index = args.length - 1; index >= 0; index -= 1) {
          if (args[index] === '--method' && args[index + 1] === 'GET') args.splice(index, 2)
        }
      },
    },
    {
      name: 'discovery option without discovery',
      mutate(args) {
        args.splice(args.indexOf('--enable-discovery'), 1)
        args.splice(args.indexOf('--json'), 0, '--discovery-source', 'html_links')
      },
    },
  ]

  for (const scenario of cases) {
    const caseFiles = {
      ...files,
      scopePath: join(files.directory, `${scenario.name.replaceAll(' ', '-')}.json`),
    }
    const args = planAttestedArguments(caseFiles)
    scenario.mutate(args)
    await assert.rejects(
      main(args, {
        clock: () => NOW,
        env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
        write: () => {},
      }),
      scenario.name,
    )
    await assert.rejects(readFile(caseFiles.scopePath), { code: 'ENOENT' })
  }
})

test('plan-attested maps CLI limit overrides into the sealed contract fields', async (t) => {
  const files = await fixture(t)
  const args = planAttestedArguments(files)
  args.splice(args.indexOf('--json'), 0,
    '--request-timeout-ms', '12000',
    '--max-response-bytes', '32768',
    '--min-interval-ms', '250',
    '--concurrency', '2',
    '--max-actions', '250000',
    '--discovery-max-depth', '32',
    '--discovery-max-candidates', '50000',
  )
  await main(args, {
    clock: () => NOW,
    env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
    write: () => {},
  })
  const verified = await readAndVerifyHttpAuthedAuthorization({
    scopePath: files.scopePath,
    requiredMode: 'OPERATOR_ATTESTED_AUTHED',
    now: NOW,
  })
  assert.deepEqual(verified.scope.limits, {
    request_timeout_ms: 12000,
    max_response_bytes: 32768,
    min_interval_ms: 250,
    concurrency: 2,
    max_actions: 250000,
  })
  assert.equal(verified.scope.discovery.max_depth, 32)
  assert.equal(verified.scope.discovery.max_candidates, 50000)
})

test('plan-attested reports a safe actionable contract reason without echoing input bytes', async (t) => {
  const files = await fixture(t)
  const args = planAttestedArguments(files)
  args.splice(args.indexOf('--enable-discovery'), 1)
  args[args.indexOf('https://bounty.example.test/security/start')] =
    'https://other.example.test/security/start'
  await assert.rejects(
    main(args, {
      clock: () => NOW,
      env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
      write: () => {},
    }),
    (error) => {
      assert.equal(error.code, 'HTTP_AUTHED_PLAN_SCOPE_INVALID')
      assert.match(error.message, /outside the sealed authorization scope/i)
      assert.equal(error.message.includes(CREDENTIAL), false)
      return true
    },
  )
})

test('plan-attested accepts an absolute bounded JSON action plan and assigns contiguous sequences', async (t) => {
  const files = await fixture(t)
  const requestsPath = join(files.directory, 'requests.json')
  const actions = [
    {
      kind: 'probe',
      sequence: 41,
      test_category: 'authentication',
      method: 'HEAD',
      url: 'https://bounty.example.test/security/start',
      expected_effect: 'none',
    },
    mutationRequestDraft(),
  ]
  await writeFile(requestsPath, JSON.stringify(actions), 'utf8')
  const args = requestPlanArguments(files, requestsPath)
  removeOption(args, 'enable-discovery')
  addMutationPlannerOptions(args)
  let transportCalls = 0

  await main(args, {
    clock: () => NOW,
    env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
    transport: async () => { transportCalls += 1 },
    write: () => {},
  })

  assert.equal(transportCalls, 0)
  const scope = JSON.parse(await readFile(files.scopePath, 'utf8'))
  assert.deepEqual(scope.requests.map(({ sequence }) => sequence), [1, 2])
  assert.deepEqual(scope.requests.map(({ kind }) => kind), ['probe', 'mutate'])
  assert.equal(scope.requests[1].request_body.body_id, 'SYNTHETIC_SECURITY_TEST_PAYLOAD_1')
  assert.equal(scope.requests[1].rollback.request_body.body_id, 'SYNTHETIC_SECURITY_TEST_ROLLBACK_1')
  assert.equal(scope.requests[1].expected_mutation.resource_ref, 'SYNTHETIC_SECURITY_TEST_RECORD_1')
  assert.equal(scope.authorization.permissions.mutation, true)
  assert.equal(scope.approver, undefined)
})

test('plan-attested accepts full probe and mutate JSON drafts without a document', async (t) => {
  const files = await fixture(t)
  const requestsPath = join(files.directory, 'attested-requests.json')
  await writeFile(requestsPath, JSON.stringify([
    {
      kind: 'probe',
      sequence: 82,
      test_category: 'api_security',
      method: 'GET',
      url: 'https://bounty.example.test/security/start',
      expected_effect: 'none',
    },
    mutationRequestDraft(),
  ]), 'utf8')
  const args = requestPlanArguments(files, requestsPath)
  removeOption(args, 'enable-discovery')
  addMutationPlannerOptions(args)
  let output = ''

  await main(args, {
    clock: () => NOW,
    env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
    transport: async () => { throw new Error('planning must remain offline') },
    write: (text) => { output += text },
  })

  const summary = JSON.parse(output)
  const scope = JSON.parse(await readFile(files.scopePath, 'utf8'))
  assert.equal(summary.authorization_mode, 'OPERATOR_ATTESTED_AUTHED')
  assert.equal(summary.request_count, 2)
  assert.equal(scope.authorization.written_authorization_sha256, undefined)
  assert.deepEqual(scope.requests.map(({ sequence }) => sequence), [1, 2])
  assert.equal(scope.requests[1].kind, 'mutate')
  assert.equal(scope.authorization.permissions.mutation, true)
  assert.equal(scope.approver, undefined)
})

test('JSON action plans are mutually exclusive with every seed shortcut', async (t) => {
  const files = await fixture(t)
  const requestsPath = join(files.directory, 'exclusive-requests.json')
  await writeFile(requestsPath, JSON.stringify([{
    kind: 'probe',
    method: 'GET',
    url: 'https://bounty.example.test/security/start',
    test_category: 'api_security',
  }]), 'utf8')

  for (const [name, value] of [
    ['seed-url', 'https://bounty.example.test/security/other'],
    ['seed-method', 'HEAD'],
    ['seed-test-category', 'authentication'],
  ]) {
    const caseFiles = {
      ...files,
      scopePath: join(files.directory, `exclusive-${name}.json`),
    }
    const args = requestPlanArguments(caseFiles, requestsPath)
    args.splice(args.indexOf('--json'), 0, `--${name}`, value)
    await assert.rejects(
      main(args, {
        clock: () => NOW,
        env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
        write: () => {},
      }),
      new RegExp(`--requests.*--${name}|--${name}.*--requests`, 'i'),
    )
    await assert.rejects(readFile(caseFiles.scopePath), { code: 'ENOENT' })
  }
})

test('JSON action-plan input must be absolute, bounded, regular, and non-symlink', async (t) => {
  const files = await fixture(t)
  const oversizedPath = join(files.directory, 'oversized-requests.json')
  await writeFile(oversizedPath, Buffer.alloc((1024 * 1024) + 1, 0x20))
  const scenarios = [
    {
      name: 'relative',
      requestsPath: 'relative-requests.json',
      deps: {},
      pattern: /requests.*absolute|absolute.*requests/i,
    },
    {
      name: 'oversized',
      requestsPath: oversizedPath,
      deps: {},
      pattern: /requests.*bounded|bounded.*requests/i,
    },
    {
      name: 'symlink',
      requestsPath: join(files.directory, 'synthetic-link.json'),
      deps: {
        requestPlanLstat: async () => ({
          isFile: () => true,
          isSymbolicLink: () => true,
          size: 64,
        }),
        requestPlanOpen: async () => {
          throw new Error('a symlink must be rejected before open')
        },
      },
      pattern: /requests.*non-symlink|non-symlink.*requests/i,
    },
  ]

  for (const scenario of scenarios) {
    const caseFiles = {
      ...files,
      scopePath: join(files.directory, `unsafe-${scenario.name}.json`),
    }
    let credentialReads = 0
    await assert.rejects(
      main(requestPlanArguments(caseFiles, scenario.requestsPath), {
        clock: () => NOW,
        env: {},
        credentialStdinReader: async () => {
          credentialReads += 1
          return Buffer.from(CREDENTIAL, 'utf8')
        },
        write: () => {},
        ...scenario.deps,
      }),
      scenario.pattern,
    )
    assert.equal(credentialReads, 0)
    await assert.rejects(readFile(caseFiles.scopePath), { code: 'ENOENT' })
  }
})

test('JSON action-plan parsing rejects malformed or non-array content without echoing it', async (t) => {
  const files = await fixture(t)
  const sentinel = 'SYNTHETIC_REQUEST_PLAN_CONTENT_MUST_NOT_BE_ECHOED'
  for (const [name, content] of [
    ['malformed', `[${sentinel}`],
    ['object', JSON.stringify({ sentinel })],
  ]) {
    const requestsPath = join(files.directory, `${name}-requests.json`)
    const scopePath = join(files.directory, `${name}-scope.json`)
    await writeFile(requestsPath, content, 'utf8')
    await assert.rejects(
      main(requestPlanArguments({ ...files, scopePath }, requestsPath), {
        clock: () => NOW,
        env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
        write: () => {},
      }),
      (error) => {
        assert.match(error.message, /requests.*JSON|JSON.*requests|requests.*array|array.*requests/i)
        assert.equal(error.message.includes(sentinel), false)
        return true
      },
    )
    await assert.rejects(readFile(scopePath), { code: 'ENOENT' })
  }
})

test('human-readable plan, validate, and fixed campaign output preserve assurance', async (t) => {
  const files = await fixture(t)
  const args = planAttestedArguments(files)
  removeOption(args, 'enable-discovery')
  args.splice(args.indexOf('--json'), 1)
  let planOutput = ''

  await main(args, {
    clock: () => NOW,
    env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
    write: (text) => { planOutput += text },
  })

  const assurance = 'OPERATOR_DECLARATION_ONLY'
  const nonclaim = 'NOT_INDEPENDENTLY_VERIFIED'
  assert.match(planOutput, new RegExp(`authorization assurance: ${assurance}`))
  assert.match(planOutput, new RegExp(`authorization nonclaim: ${nonclaim}`))

  const verified = await readAndVerifyHttpAuthedAuthorization({
    scopePath: files.scopePath,
    requiredMode: 'OPERATOR_ATTESTED_AUTHED',
    now: NOW,
  })
  let validationOutput = ''
  await main([
    'validate-attested',
    '--scope', files.scopePath,
  ], {
    clock: () => NOW,
    write: (text) => { validationOutput += text },
  })
  assert.match(validationOutput, new RegExp(`authorization assurance: ${assurance}`))
  assert.match(validationOutput, new RegExp(`authorization nonclaim: ${nonclaim}`))

  let campaignOutput = ''
  let sends = 0
  await main([
    'campaign-attested',
    '--scope', files.scopePath,
    '--campaign-grant-sha256', verified.campaignGrantSha256,
    '--ledger', join(files.directory, 'human-output-ledger'),
    '--operator-id', 'security-researcher',
  ], {
    clock: () => NOW,
    env: { GENERIC_BOUNTY_CREDENTIAL: CREDENTIAL },
    transport: async (request) => {
      await request.beforeSend()
      sends += 1
      return { status: 200, responseBytes: 0, responseHeaderNames: [] }
    },
    write: (text) => { campaignOutput += text },
  })
  assert.equal(sends, 1)
  assert.match(campaignOutput, /completed actions: 1/)
  assert.match(campaignOutput, new RegExp(`authorization assurance: ${assurance}`))
  assert.match(campaignOutput, new RegExp(`authorization nonclaim: ${nonclaim}`))
})
