import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { once } from 'node:events'
import {
  link,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { main as runHttpReconCli } from '../scripts/http-recon.mjs'
import * as httpReconController from '../scripts/lib/http-recon-controller.mjs'
import {
  canonicalJson,
  sha256Hex,
} from '../scripts/lib/http-recon-contracts.mjs'
import {
  finalizeHttpReconBundle,
  goOperatorAttestedHttpRecon,
  nextHttpReconAction,
  planOperatorAttestedHttpReconBundle,
  requestHttpReconStop,
  runHttpReconAction,
  validateHttpReconBundle,
} from '../scripts/lib/http-recon-controller.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'
import {
  replaceFileDurably,
  syncDirectoryDurably,
} from '../scripts/lib/durable-file-publication.mjs'

const EMPTY_SHA256 = sha256Hex(Buffer.alloc(0))
const DNS_ANSWERS = [{ address: '93.184.216.34', family: 4 }]
const DNS_SHA256 = sha256Hex(Buffer.from(JSON.stringify({
  hostname: 'target.example',
  answers: DNS_ANSWERS,
})))

test('Win32 durable replacement uses a real write-through move instead of directory fsync', {
  skip: process.platform !== 'win32',
}, async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'rta-win32-durable-replace-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const source = join(directory, 'report.md.pending')
  const destination = join(directory, 'report.md')
  await writeFile(source, 'durable replacement')
  await writeFile(destination, 'old report')
  await assert.rejects(
    syncDirectoryDurably(directory),
    (error) => error.code === 'DIRECTORY_FSYNC_UNSUPPORTED',
  )
  await replaceFileDurably(source, destination)
  assert.equal(await readFile(destination, 'utf8'), 'durable replacement')
  await assert.rejects(readFile(source), (error) => error.code === 'ENOENT')
})

test('signed authorization controller entry points are absent', () => {
  assert.equal(Object.hasOwn(httpReconController, 'planHttpReconBundle'), false)
  assert.equal(
    Object.hasOwn(httpReconController.httpReconControllerConstants, 'ROE_FILE'),
    false,
  )
})

test('HTTP recon rejects hard-linked bundle artifacts before acting on them', async (t) => {
  const value = await attestedFixture(t)
  await link(join(value.out, 'run.json'), join(value.parent, 'run-alias.json'))
  await assert.rejects(
    nextHttpReconAction({ bundle: value.out, now: value.clock.now }),
    (error) => error.code === 'HTTP_RECON_ARTIFACT_NOT_REGULAR',
  )
})

test('public HTTP recon execution reaches the controller without a repeat confirmation flag', async () => {
  await assert.rejects(
    () => runHttpReconCli([
      'run',
      'missing-bundle-for-controller-validation',
      'action:controller-validation',
      '--operator-id',
      'operator:test',
      '--rationale',
      'exercise the authorized controller path',
    ]),
    (error) => error.code === 'ENOENT'
      && error.code !== 'HTTP_RECON_LIVE_IO_DISABLED',
  )
})

test('public HTTP recon retires signed routes and flags before artifact reads or target I/O', async (t) => {
  const legacyInputs = [
    [
      'plan-signed',
      '--roe', 'must-not-read-roe.json',
      '--authorization-document', 'must-not-read-authorization.txt',
      '--owner-public-key', 'must-not-read-key.pem',
      '--out', 'must-not-create-bundle',
    ],
    [
      'next',
      'must-not-read-bundle',
      '--authorization-document', 'must-not-read-authorization.txt',
      '--owner-public-key', 'must-not-read-key.pem',
    ],
    [
      'run',
      'must-not-read-bundle',
      'action:must-not-run',
      '--operator-id', 'operator:test',
      '--rationale', 'legacy signed route must remain retired',
      '--authorization-document', 'must-not-read-authorization.txt',
      '--owner-public-key', 'must-not-read-key.pem',
    ],
    [
      'finalize',
      'must-not-read-bundle',
      '--authorization-document', 'must-not-read-authorization.txt',
      '--owner-public-key', 'must-not-read-key.pem',
    ],
    [
      'validate',
      'must-not-read-bundle',
      '--authorization-document', 'must-not-read-authorization.txt',
      '--owner-public-key', 'must-not-read-key.pem',
    ],
  ]
  let controllerCalls = 0
  for (const args of legacyInputs) {
    await t.test(args[0], async () => {
      await assert.rejects(
        runHttpReconCli(args, {
          planAttested: async () => { controllerCalls += 1 },
          runAction: async () => { controllerCalls += 1 },
          finalize: async () => { controllerCalls += 1 },
        }),
        (error) => /unknown command|does not support/.test(error.message)
          && error.code !== 'ENOENT',
      )
    })
  }
  assert.equal(controllerCalls, 0)
})

test('go plans, executes, and finalizes one operator-attested target in one command', async () => {
  const calls = []
  let output = ''
  let progress = ''
  const plannedAction = {
    action_id: 'action:operator-attested:1',
    method: 'HEAD',
    url: 'https://target.example/health',
  }

  await runHttpReconCli([
    'go',
    plannedAction.url,
    '--out', 'operator-attested-go-bundle',
    '--json',
  ], {
    planAttested: async (input) => {
      calls.push(['plan', input])
      return {
        directory: 'operator-attested-go-bundle',
        run: {
          engagement_id: 'operator-attested-engagement',
          actions: [plannedAction],
        },
      }
    },
    runAction: async (input) => {
      calls.push(['run', input])
      return {
        run: { state: 'PROBE_PLAN_RUNNING' },
        action: { ...plannedAction, state: 'COMPLETED' },
      }
    },
    finalize: async (input) => {
      calls.push(['finalize', input])
      return {
        run: {
          engagement_id: 'operator-attested-engagement',
          state: 'PROBE_PLAN_COMPLETE',
        },
        reportPath: 'operator-attested-go-bundle/http-recon-report.md',
      }
    },
    write: (value) => { output += value },
    progressWrite: (value) => { progress += value },
  })

  assert.equal(calls.length, 3)
  assert.equal(calls[0][0], 'plan')
  assert.equal(calls[0][1].targetUrl, plannedAction.url)
  assert.equal('attestationConfirmed' in calls[0][1], false)
  assert.match(calls[0][1].operatorAuthorization.operator_id, /^local:/)
  assert.match(
    calls[0][1].operatorAuthorization.authorization_reference,
    /^operator-directive:/,
  )
  assert.deepEqual(calls[0][1].operatorAuthorization.target, {
    kind: 'https_url',
    url: plannedAction.url,
  })
  assert.equal(calls[1][0], 'run')
  assert.equal(calls[1][1].bundle, 'operator-attested-go-bundle')
  assert.equal(calls[1][1].actionId, plannedAction.action_id)
  assert.equal('authorizationConfirmed' in calls[1][1], false)
  assert.equal(
    calls[1][1].operatorId,
    calls[0][1].operatorAuthorization.operator_id,
  )
  assert.equal(calls[2][0], 'finalize')
  assert.equal(calls[2][1].bundle, 'operator-attested-go-bundle')
  assert.match(progress, /Bundle ready for stop control: operator-attested-go-bundle/)
  assert.deepEqual(JSON.parse(output), {
    action: { ...plannedAction, state: 'COMPLETED' },
    bundle: 'operator-attested-go-bundle',
    engagement_id: 'operator-attested-engagement',
    report: 'operator-attested-go-bundle/http-recon-report.md',
    state: 'PROBE_PLAN_COMPLETE',
  })
})

test('target-and-go controller refuses before planning without an operator authorization declaration', async () => {
  let plans = 0
  await assert.rejects(
    goOperatorAttestedHttpRecon({
      targetUrl: 'https://target.example/health',
      operatorId: 'operator:test',
      authorizedBy: 'Acme security owner',
      authorizationReference: 'ticket:SEC-1234',
      rationale: 'exercise the bounded target',
      out: 'must-not-be-created',
      planImpl: async () => { plans += 1 },
    }),
    (error) => error.code === 'HTTP_RECON_LIVE_EXECUTION_AUTHORIZATION_REQUIRED',
  )
  assert.equal(plans, 0)
})

test('target-and-go controller library does not infer authorization from omitted input', async () => {
  let plans = 0
  await assert.rejects(
    goOperatorAttestedHttpRecon({
      targetUrl: 'https://target.example/health',
      out: 'must-not-be-created',
      planImpl: async () => { plans += 1 },
    }),
    (error) => error.code === 'HTTP_RECON_LIVE_EXECUTION_AUTHORIZATION_REQUIRED',
  )
  assert.equal(plans, 0)
})
const CERTIFICATE_SHA256 = 'c'.repeat(64)
const SPKI_SHA256 = 'a'.repeat(64)

function mutableClock(initial = '2026-08-04T12:00:00.000Z') {
  let current = Date.parse(initial)
  return {
    now: () => new Date(current),
    advance: (milliseconds) => { current += milliseconds },
  }
}

function headerSummary(headers) {
  return {
    retained_bytes: Buffer.byteLength(
      headers.map(({ name, value }) => `${name}: ${value}\r\n`).join(''),
    ),
    omitted_count: 0,
    redacted_names: [],
    truncated: false,
  }
}

function baseTransport({
  url,
  method,
  headers,
  body,
  tlsVerification = 'PKIX_HOSTNAME_AND_SPKI_PIN',
  spkiSha256 = SPKI_SHA256,
}) {
  return {
    schema_version: '1.0.0',
    requested_url: url,
    url,
    method,
    status: 200,
    response_headers: headers,
    response_header_summary: headerSummary(headers),
    body,
    dns: {
      answer_sha256: DNS_SHA256,
      answer_count: 1,
      answers: structuredClone(DNS_ANSWERS),
      selected_ip: '93.184.216.34',
      selected_family: 4,
    },
    tls: {
      server_name: 'target.example',
      peer_ip: '93.184.216.34',
      peer_family: 4,
      spki_sha256: spkiSha256,
      certificate_sha256: CERTIFICATE_SHA256,
      valid_from: 'Aug  1 00:00:00 2026 GMT',
      valid_to: 'Sep  1 00:00:00 2026 GMT',
      protocol: 'TLSv1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      authorized: true,
      verification_mode: tlsVerification,
    },
    timing: {
      dns_ms: 1,
      tls_handshake_ms: 2,
      before_send_ms: 1,
      time_to_first_byte_ms: 3,
      total_ms: 7,
    },
    request_may_have_been_sent: true,
  }
}

function preDispatchMetadata({
  url,
  method,
  request_headers: requestHeaders,
  tlsVerification = 'PKIX_HOSTNAME_AND_SPKI_PIN',
  spkiSha256 = SPKI_SHA256,
}) {
  const hostname = new URL(url).hostname
  return {
    url,
    method,
    request_headers: requestHeaders ?? null,
    dns: {
      answer_sha256: DNS_SHA256,
      answer_count: 1,
      answers: structuredClone(DNS_ANSWERS),
      selected_ip: '93.184.216.34',
      selected_family: 4,
    },
    tls: {
      server_name: hostname,
      peer_ip: '93.184.216.34',
      peer_family: 4,
      spki_sha256: spkiSha256,
      certificate_sha256: CERTIFICATE_SHA256,
      valid_from: 'Aug  1 00:00:00 2026 GMT',
      valid_to: 'Sep  1 00:00:00 2026 GMT',
      protocol: 'TLSv1.3',
      cipher: 'TLS_AES_256_GCM_SHA384',
      authorized: true,
      verification_mode: tlsVerification,
    },
  }
}

function recordedTransportIdentity(metadata) {
  return {
    dns_sha256: metadata.dns.answer_sha256,
    dns_answer_count: metadata.dns.answer_count,
    dns_answers: structuredClone(metadata.dns.answers),
    resolved_ip: metadata.dns.selected_ip,
    resolved_family: metadata.dns.selected_family,
    tls_verification: metadata.tls.verification_mode,
    server_name: metadata.tls.server_name,
    peer_certificate_sha256: metadata.tls.certificate_sha256,
    peer_spki_sha256: metadata.tls.spki_sha256,
    tls_authorized: true,
  }
}

async function rewriteEventChain(bundle, mutate) {
  const eventPath = join(bundle, 'events.jsonl')
  const records = (await readFile(eventPath, 'utf8'))
    .trimEnd()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line))
  mutate(records)
  let previous = '0'.repeat(64)
  for (const record of records) {
    record.previous_sha256 = previous
    delete record.record_sha256
    record.record_sha256 = sha256Hex(canonicalJson(record))
    previous = record.record_sha256
  }
  await writeFile(
    eventPath,
    `${records.map((record) => JSON.stringify(record)).join('\n')}\n`,
  )
  const runPath = join(bundle, 'run.json')
  const run = JSON.parse(await readFile(runPath, 'utf8'))
  run.event_chain = {
    count: records.length,
    last_sha256: previous,
  }
  await writeFile(runPath, `${JSON.stringify(run, null, 2)}\n`)
}

async function rewriteObservationAndChain(bundle, mutate) {
  const runPath = join(bundle, 'run.json')
  const run = JSON.parse(await readFile(runPath, 'utf8'))
  const action = run.actions[0]
  const observationPath = join(bundle, ...action.observation_path.split('/'))
  const observation = JSON.parse(await readFile(observationPath, 'utf8'))
  mutate(observation)
  const observationBytes = Buffer.from(`${JSON.stringify(observation, null, 2)}\n`)
  await writeFile(observationPath, observationBytes)
  action.observation_sha256 = sha256Hex(observationBytes)

  const eventPath = join(bundle, 'events.jsonl')
  const records = (await readFile(eventPath, 'utf8'))
    .trimEnd()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line))
  const commit = records.find(({ type }) => type === 'ACTION_COMMITTED')
  commit.details.observation_sha256 = action.observation_sha256
  let previous = '0'.repeat(64)
  for (const record of records) {
    record.previous_sha256 = previous
    delete record.record_sha256
    record.record_sha256 = sha256Hex(canonicalJson(record))
    previous = record.record_sha256
  }
  await writeFile(
    eventPath,
    `${records.map((record) => JSON.stringify(record)).join('\n')}\n`,
  )
  run.event_chain = {
    count: records.length,
    last_sha256: previous,
  }
  await writeFile(runPath, `${JSON.stringify(run, null, 2)}\n`)
}

function appendSyntheticEvent(records, run, type, details, at) {
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-recon-event',
    run_id: run.run_id,
    engagement_id: run.engagement_id,
    sequence: records.length + 1,
    at,
    type,
    previous_sha256: records.at(-1).record_sha256,
    details,
  }
  records.push({
    ...unsigned,
    record_sha256: sha256Hex(canonicalJson(unsigned)),
  })
  return records.at(-1)
}

async function synthesizeStaleActionPreDispatch(bundle, at, { includePreDispatch = true } = {}) {
  const runPath = join(bundle, 'run.json')
  const eventPath = join(bundle, 'events.jsonl')
  const run = JSON.parse(await readFile(runPath, 'utf8'))
  const action = run.actions[0]
  run.state = 'ACTIVE'
  run.updated_at = at
  run.budget.started_at = at
  action.state = 'LEASED'
  action.attempt_count = 1
  action.leased_at = at
  const records = (await readFile(eventPath, 'utf8'))
    .trimEnd()
    .split('\n')
    .filter(Boolean)
    .map((line) => JSON.parse(line))
  const lease = appendSyntheticEvent(records, run, 'ACTION_LEASED', {
    action_id: action.action_id,
    method: action.method,
    url: action.url,
    operator_id: run.authorization.operator_id,
    rationale: 'authorized bounded response metadata observation',
    authorization_mode: 'OPERATOR_ATTESTED',
    tls_policy: structuredClone(run.target.tls),
    current_authorization_confirmed: true,
    budget_before: structuredClone(run.budget),
  }, at)
  action.state = 'SENT'
  action.sent_at = at
  const metadata = preDispatchMetadata({
    url: action.url,
    method: action.method,
    tlsVerification: run.target.tls.mode,
  })
  if (includePreDispatch) {
    appendSyntheticEvent(records, run, 'ACTION_REQUEST_PRE_DISPATCH', {
      action_id: action.action_id,
      method: action.method,
      url: action.url,
      transport_identity: recordedTransportIdentity(metadata),
    }, at)
  }
  run.event_chain = {
    count: lease.sequence,
    last_sha256: lease.record_sha256,
  }
  await writeFile(
    eventPath,
    `${records.map((record) => JSON.stringify(record)).join('\n')}\n`,
  )
  await writeFile(runPath, `${JSON.stringify(run, null, 2)}\n`)
}

async function attestedFixture(t, overrides = {}) {
  const parent = await mkdtemp(join(tmpdir(), 'rta-http-recon-attested-'))
  t.after(() => rm(parent, { recursive: true, force: true }))
  const clock = mutableClock()
  const out = join(parent, 'bundle')
  const targetUrl = overrides.targetUrl ?? 'https://target.example/'
  const declaredAt = clock.now().toISOString()
  const planned = await planOperatorAttestedHttpReconBundle({
    targetUrl,
    operatorId: 'operator-001',
    authorizedBy: 'A. Asset Owner',
    authorizationReference: 'operator authorization reference 2026-08-04',
    environment: 'production',
    operatorAuthorization: {
      schema_version: '1.0.0',
      kind: 'red-team-audit/operator-authorization',
      status: 'OPERATOR_ASSERTED_AUTHORIZED',
      operator_id: 'operator-001',
      declared_at: declaredAt,
      authorization_reference: 'operator authorization reference 2026-08-04',
      statement: 'I confirm I am authorized to test this exact HTTPS target.',
      target: { kind: 'https_url', url: targetUrl },
    },
    out,
    now: clock.now,
    randomBytesImpl: () => Buffer.from('abcdef123456', 'hex'),
    ...overrides,
  })
  return { parent, out, clock, planned }
}

function attestedTransports(
  counters = { proof: 0, probe: 0 },
  {
    expectedPin,
    tlsVerification = expectedPin === undefined
      ? 'PKIX_HOSTNAME'
      : 'PKIX_HOSTNAME_AND_SPKI_PIN',
    spkiSha256 = SPKI_SHA256,
  } = {},
) {
  return {
    counters,
    probeImpl: async (options) => {
      counters.probe += 1
      assert.equal(options.url, 'https://target.example/')
      assert.equal(options.method, 'HEAD')
      assert.equal(options.tlsVerificationMode, tlsVerification)
      assert.equal(options.tlsSpkiSha256, expectedPin)
      assert.equal(options.expectedDnsSha256, undefined)
      await options.beforeSend(preDispatchMetadata({
        url: options.url,
        method: options.method,
        tlsVerification,
        spkiSha256,
      }))
      const headers = [{ name: 'content-type', value: 'text/html' }]
      return baseTransport({
        url: options.url,
        method: options.method,
        headers,
        tlsVerification,
        spkiSha256,
        body: {
          bytes: null,
          sha256: EMPTY_SHA256,
          size: 0,
          retained_size: 0,
          retained: false,
          truncated: false,
          digest_scope: 'complete',
        },
      })
    },
  }
}

test('operator-attested mode needs no repeat authorization, authority files, or proof requests', async (t) => {
  const value = await attestedFixture(t)
  assert.equal(value.planned.run.authorization.mode, 'OPERATOR_ATTESTED')
  assert.equal(Object.hasOwn(value.planned.run.target, 'proof'), false)
  assert.deepEqual(value.planned.run.target.tls, { mode: 'PKIX_HOSTNAME' })
  assert.equal(value.planned.run.limits.max_target_proof_requests, 0)

  const next = await nextHttpReconAction({
    bundle: value.out,
    now: value.clock.now,
  })
  const transport = attestedTransports()
  await assert.rejects(
    runHttpReconAction({
      bundle: value.out,
      actionId: next.action_id,
      operatorId: 'operator-002',
      rationale: 'authorized bounded response metadata observation',
      now: value.clock.now,
      probeImpl: transport.probeImpl,
    }),
    /operator identity that created the sealed attestation/,
  )
  assert.deepEqual(transport.counters, { proof: 0, probe: 0 })

  const executed = await runHttpReconAction({
    bundle: value.out,
    actionId: next.action_id,
    operatorId: 'operator-001',
    rationale: 'authorized bounded response metadata observation',
    now: value.clock.now,
    probeImpl: transport.probeImpl,
  })
  assert.equal(executed.action.state, 'COMMITTED')
  assert.equal(executed.observation.authority.mode, 'OPERATOR_ATTESTED')
  assert.equal(
    Object.hasOwn(executed.observation.authority, 'target_proof_sha256'),
    false,
  )
  assert.equal(executed.observation.network.tls_verification, 'PKIX_HOSTNAME')
  assert.equal(executed.observation.network.peer_spki_sha256, SPKI_SHA256)
  assert.deepEqual(transport.counters, { proof: 0, probe: 1 })

  const finalized = await finalizeHttpReconBundle({
    bundle: value.out,
    now: value.clock.now,
  })
  assert.equal(finalized.run.state, 'PROBE_PLAN_COMPLETE')
  const report = await readFile(finalized.reportPath, 'utf8')
  assert.match(report, /Authorization source: operator declaration/i)
  assert.match(report, /without independently deciding legal authority/i)
  assert.match(report, /no advance SPKI pin/i)
  assert.match(report, /Observed TLS SPKI SHA-256/)
  assert.match(report, /code coverage are NOT APPLICABLE/)

  const validation = await validateHttpReconBundle({
    bundle: value.out,
    now: value.clock.now,
  })
  assert.equal(validation.valid, true)
  assert.deepEqual(validation.errors, [])
})

test('operator-attested diagnostic header profile is sealed, dispatched, and value-redacted', async (t) => {
  const value = await attestedFixture(t, {
    targetUrl: 'https://target.example/diagnostics/headers',
    method: 'GET',
    safeToGet: true,
    requestHeaderProfile: 'x-forwarded-for-loopback-v1',
  })
  assert.equal(value.planned.run.schema_version, '1.1.0')
  const action = value.planned.run.actions[0]
  assert.equal(action.request_headers.profile, 'x-forwarded-for-loopback-v1')

  const probeImpl = async (options) => {
    assert.deepEqual(options.requestHeaderProfile, action.request_headers)
    await options.beforeSend(preDispatchMetadata({
      url: options.url,
      method: options.method,
      tlsVerification: 'PKIX_HOSTNAME',
      spkiSha256: SPKI_SHA256,
      request_headers: action.request_headers,
    }))
    return baseTransport({
      url: options.url,
      method: options.method,
      headers: [{ name: 'content-type', value: 'application/json' }],
      tlsVerification: 'PKIX_HOSTNAME',
      spkiSha256: SPKI_SHA256,
      body: {
        bytes: null,
        sha256: EMPTY_SHA256,
        size: 0,
        retained_size: 0,
        retained: false,
        truncated: false,
        digest_scope: 'complete',
      },
    })
  }
  const result = await runHttpReconAction({
    bundle: value.out,
    actionId: action.action_id,
    operatorId: 'operator-001',
    rationale: 'authorized sealed proxy-routing differential',
    now: value.clock.now,
    probeImpl,
  })
  assert.equal(result.action.state, 'COMMITTED')

  const runText = await readFile(join(value.out, 'run.json'), 'utf8')
  const eventText = await readFile(join(value.out, 'events.jsonl'), 'utf8')
  assert.match(runText, /x-forwarded-for-loopback-v1/)
  assert.match(eventText, /x-forwarded-for-loopback-v1/)
  assert.doesNotMatch(runText, /127\.0\.0\.1/)
  assert.doesNotMatch(eventText, /127\.0\.0\.1/)

  await finalizeHttpReconBundle({ bundle: value.out, now: value.clock.now })
  const validation = await validateHttpReconBundle({ bundle: value.out, now: value.clock.now })
  assert.equal(validation.valid, true)
})

test('operator-attested mode may explicitly seal and enforce an advance SPKI pin', async (t) => {
  const value = await attestedFixture(t, { tlsSpkiSha256: SPKI_SHA256 })
  assert.deepEqual(value.planned.run.target.tls, {
    mode: 'PKIX_HOSTNAME_AND_SPKI_PIN',
    spki_sha256: SPKI_SHA256,
  })
  const next = await nextHttpReconAction({
    bundle: value.out,
    now: value.clock.now,
  })
  const transport = attestedTransports(
    { proof: 0, probe: 0 },
    { expectedPin: SPKI_SHA256 },
  )
  const executed = await runHttpReconAction({
    bundle: value.out,
    actionId: next.action_id,
    operatorId: 'operator-001',
    rationale: 'authorized pinned response metadata observation',
    now: value.clock.now,
    probeImpl: transport.probeImpl,
  })
  assert.equal(
    executed.observation.network.tls_verification,
    'PKIX_HOSTNAME_AND_SPKI_PIN',
  )
  assert.equal(executed.observation.network.peer_spki_sha256, SPKI_SHA256)
})

test('controller rejects transport TLS evidence that contradicts a sealed pin', async (t) => {
  const value = await attestedFixture(t, { tlsSpkiSha256: SPKI_SHA256 })
  const next = await nextHttpReconAction({
    bundle: value.out,
    now: value.clock.now,
  })
  const transport = attestedTransports(
    { proof: 0, probe: 0 },
    {
      expectedPin: SPKI_SHA256,
      spkiSha256: 'e'.repeat(64),
    },
  )
  await assert.rejects(
    runHttpReconAction({
      bundle: value.out,
      actionId: next.action_id,
      operatorId: 'operator-001',
      rationale: 'authorized pinned response metadata observation',
      now: value.clock.now,
      probeImpl: transport.probeImpl,
    }),
    (error) => {
      assert.equal(error.code, 'HTTP_RECON_PRE_DISPATCH_IDENTITY_INVALID')
      assert.equal(error.request_may_have_been_sent, undefined)
      return true
    },
  )
  const run = JSON.parse(await readFile(join(value.out, 'run.json'), 'utf8'))
  assert.equal(run.state, 'FAILED')
  assert.equal(run.actions[0].state, 'FAILED')
})

test('returned transport identity cannot differ from durable pre-dispatch evidence', async (t) => {
  const value = await attestedFixture(t)
  const next = await nextHttpReconAction({
    bundle: value.out,
    now: value.clock.now,
  })
  const probeImpl = async (options) => {
    await options.beforeSend(preDispatchMetadata({
      url: options.url,
      method: options.method,
      tlsVerification: 'PKIX_HOSTNAME',
    }))
    return baseTransport({
      url: options.url,
      method: options.method,
      headers: [{ name: 'content-type', value: 'text/html' }],
      tlsVerification: 'PKIX_HOSTNAME',
      spkiSha256: 'e'.repeat(64),
      body: {
        bytes: null,
        sha256: EMPTY_SHA256,
        size: 0,
        retained_size: 0,
        retained: false,
        truncated: false,
        digest_scope: 'complete',
      },
    })
  }
  await assert.rejects(
    runHttpReconAction({
      bundle: value.out,
      actionId: next.action_id,
      operatorId: 'operator-001',
      rationale: 'authorized bounded response metadata observation',
      now: value.clock.now,
      probeImpl,
    }),
    (error) => {
      assert.equal(error.code, 'HTTP_RECON_TRANSPORT_IDENTITY_CHANGED')
      return true
    },
  )
  const run = JSON.parse(await readFile(join(value.out, 'run.json'), 'utf8'))
  assert.equal(run.state, 'OUTCOME_UNCERTAIN')
  assert.equal(run.actions[0].state, 'DELIVERY_AMBIGUOUS')
})

test('pre-dispatch authorization requires the active phase exact method and URL', async (t) => {
  for (const field of ['url', 'method']) {
    await t.test(`action ${field}`, async (subtest) => {
        const value = await attestedFixture(subtest)
        const actionId = (await nextHttpReconAction({
          bundle: value.out,
          now: value.clock.now,
        })).action_id
        let adapterSent = false
        const wrongPhaseTransport = async (options) => {
          const attemptedUrl = field === 'url'
            ? 'https://target.example/unsealed'
            : options.url
          const attemptedMethod = field === 'method'
            ? (options.method === 'GET' ? 'HEAD' : 'GET')
            : options.method
          await options.beforeSend(preDispatchMetadata({
            url: attemptedUrl,
            method: attemptedMethod,
            tlsVerification: 'PKIX_HOSTNAME',
          }))
          adapterSent = true
          throw new Error('adapter should not receive pre-dispatch authorization')
        }
        await assert.rejects(
          runHttpReconAction({
            bundle: value.out,
            actionId,
            operatorId: 'operator-001',
            rationale: 'authorized bounded response metadata observation',
            now: value.clock.now,
            probeImpl: wrongPhaseTransport,
          }),
          (error) => {
            assert.equal(error.code, 'HTTP_RECON_PRE_DISPATCH_SCOPE_MISMATCH')
            return true
          },
        )
        assert.equal(adapterSent, false)
        const run = JSON.parse(await readFile(join(value.out, 'run.json'), 'utf8'))
        assert.equal(run.state, 'FAILED')
        assert.equal(run.actions[0].state, 'FAILED')
        const events = (await readFile(join(value.out, 'events.jsonl'), 'utf8'))
          .trimEnd()
          .split('\n')
          .map((line) => JSON.parse(line))
        assert.equal(
          events.some(({ type }) => type === 'ACTION_REQUEST_PRE_DISPATCH'),
          false,
        )
    })
  }
})

test('stop-condition results cannot contradict durable pre-dispatch identity', async (t) => {
  const value = await attestedFixture(t)
  const next = await nextHttpReconAction({
    bundle: value.out,
    now: value.clock.now,
  })
  const probeImpl = async (options) => {
    await options.beforeSend(preDispatchMetadata({
      url: options.url,
      method: options.method,
      tlsVerification: 'PKIX_HOSTNAME',
    }))
    const result = baseTransport({
      url: options.url,
      method: options.method,
      headers: [{ name: 'location', value: '[REDACTED]' }],
      tlsVerification: 'PKIX_HOSTNAME',
      spkiSha256: 'e'.repeat(64),
      body: {
        bytes: null,
        sha256: EMPTY_SHA256,
        size: 0,
        retained_size: 0,
        retained: false,
        truncated: true,
        digest_scope: 'captured-prefix',
      },
    })
    result.status = 302
    const error = new Error('synthetic redirect response')
    error.code = 'HTTP_RECON_REDIRECT'
    error.condition = 'REDIRECT'
    error.request_may_have_been_sent = true
    error.result = result
    throw error
  }
  await assert.rejects(
    runHttpReconAction({
      bundle: value.out,
      actionId: next.action_id,
      operatorId: 'operator-001',
      rationale: 'authorized bounded response metadata observation',
      now: value.clock.now,
      probeImpl,
    }),
    (error) => {
      assert.equal(error.code, 'HTTP_RECON_TRANSPORT_IDENTITY_CHANGED')
      return true
    },
  )
  const run = JSON.parse(await readFile(join(value.out, 'run.json'), 'utf8'))
  assert.equal(run.state, 'OUTCOME_UNCERTAIN')
  assert.equal(run.actions[0].state, 'DELIVERY_AMBIGUOUS')
  assert.equal(run.actions[0].observation_path, null)
  assert.equal(run.budget.probe_requests_used, 0)
  const events = await readFile(join(value.out, 'events.jsonl'), 'utf8')
  assert.doesNotMatch(events, /"type":"ACTION_COMMITTED"/)
})

test('operator-attested scope or mutable run drift blocks before transport', async (t) => {
  for (const mutate of [
    (directory, run) => {
      run.actions[0].url = 'https://target.example/admin'
      return writeFile(join(directory, 'run.json'), `${JSON.stringify(run, null, 2)}\n`)
    },
    (directory, run) => {
      run.authorization.operator_id = 'operator-002'
      return writeFile(join(directory, 'run.json'), `${JSON.stringify(run, null, 2)}\n`)
    },
    (directory, run) => {
      run.target.tls = {
        mode: 'PKIX_HOSTNAME_AND_SPKI_PIN',
        spki_sha256: 'e'.repeat(64),
      }
      return writeFile(join(directory, 'run.json'), `${JSON.stringify(run, null, 2)}\n`)
    },
    (directory, run) => {
      run.plan_sha256 = 'e'.repeat(64)
      return writeFile(join(directory, 'run.json'), `${JSON.stringify(run, null, 2)}\n`)
    },
    (directory, run) => {
      run.budget.proof_requests_used = 1
      return writeFile(join(directory, 'run.json'), `${JSON.stringify(run, null, 2)}\n`)
    },
    async (directory) => {
      const scopePath = join(directory, 'attested-scope.json')
      const scope = JSON.parse(await readFile(scopePath, 'utf8'))
      scope.target.tls = {
        mode: 'PKIX_HOSTNAME_AND_SPKI_PIN',
        spki_sha256: 'f'.repeat(64),
      }
      await writeFile(scopePath, `${JSON.stringify(scope, null, 2)}\n`)
    },
  ]) {
    const value = await attestedFixture(t)
    const run = JSON.parse(await readFile(join(value.out, 'run.json'), 'utf8'))
    await mutate(value.out, run)
    const transport = attestedTransports()
    await assert.rejects(
      nextHttpReconAction({ bundle: value.out, now: value.clock.now }),
      /sealed operator attestation|scope does not match|zero proof budget|PKIX TLS policy/,
    )
    assert.deepEqual(transport.counters, { proof: 0, probe: 0 })
  }
})

test('validation rejects a locally rehashed lease that drops current authorization', async (t) => {
  const value = await attestedFixture(t)
  const next = await nextHttpReconAction({
    bundle: value.out,
    now: value.clock.now,
  })
  const transport = attestedTransports()
  await runHttpReconAction({
    bundle: value.out,
    actionId: next.action_id,
    operatorId: 'operator-001',
    rationale: 'authorized bounded response metadata observation',
    now: value.clock.now,
    probeImpl: transport.probeImpl,
  })
  await rewriteEventChain(value.out, (records) => {
    const lease = records.find(({ type }) => type === 'ACTION_LEASED')
    lease.details.current_authorization_confirmed = false
  })
  const validation = await validateHttpReconBundle({
    bundle: value.out,
    now: value.clock.now,
  })
  assert.equal(validation.valid, false)
  assert.deepEqual(
    validation.errors.map(({ code }) => code),
    ['HTTP_RECON_ACTION_LEASE_INVALID'],
  )
})

test('validation re-correlates locally rehashed observations with action and TLS evidence', async (t) => {
  const mutations = [
    (observation) => { observation.url = 'https://target.example/other' },
    (observation) => {
      observation.network.tls_verification = 'PKIX_HOSTNAME_AND_SPKI_PIN'
    },
    (observation) => { observation.network.peer_spki_sha256 = 'e'.repeat(64) },
    (observation) => {
      observation.network.peer_certificate_sha256 = 'f'.repeat(64)
    },
  ]
  for (const mutate of mutations) {
    const value = await attestedFixture(t)
    const next = await nextHttpReconAction({
      bundle: value.out,
      now: value.clock.now,
    })
    const transport = attestedTransports()
    await runHttpReconAction({
      bundle: value.out,
      actionId: next.action_id,
      operatorId: 'operator-001',
      rationale: 'authorized bounded response metadata observation',
      now: value.clock.now,
      probeImpl: transport.probeImpl,
    })
    await rewriteObservationAndChain(value.out, mutate)
    const validation = await validateHttpReconBundle({
      bundle: value.out,
      now: value.clock.now,
    })
    assert.equal(validation.valid, false)
    assert.deepEqual(
      validation.errors.map(({ code }) => code),
      ['HTTP_RECON_COMMITTED_EVIDENCE_MISMATCH'],
    )
  }
})

test('validation rejects a rehashed pre-dispatch peer identity substitution', async (t) => {
  const value = await attestedFixture(t)
  const next = await nextHttpReconAction({
    bundle: value.out,
    now: value.clock.now,
  })
  const transport = attestedTransports()
  await runHttpReconAction({
    bundle: value.out,
    actionId: next.action_id,
    operatorId: 'operator-001',
    rationale: 'authorized bounded response metadata observation',
    now: value.clock.now,
    probeImpl: transport.probeImpl,
  })
  await rewriteEventChain(value.out, (records) => {
    const preDispatch = records.find(
      ({ type }) => type === 'ACTION_REQUEST_PRE_DISPATCH',
    )
    preDispatch.details.transport_identity.peer_spki_sha256 = 'e'.repeat(64)
  })
  const validation = await validateHttpReconBundle({
    bundle: value.out,
    now: value.clock.now,
  })
  assert.equal(validation.valid, false)
  assert.deepEqual(
    validation.errors.map(({ code }) => code),
    ['HTTP_RECON_COMMITTED_EVIDENCE_MISMATCH'],
  )
})

test('validation recomputes public DNS evidence instead of trusting correlated hashes', async (t) => {
  const value = await attestedFixture(t)
  const next = await nextHttpReconAction({
    bundle: value.out,
    now: value.clock.now,
  })
  const transport = attestedTransports()
  await runHttpReconAction({
    bundle: value.out,
    actionId: next.action_id,
    operatorId: 'operator-001',
    rationale: 'authorized bounded response metadata observation',
    now: value.clock.now,
    probeImpl: transport.probeImpl,
  })
  await rewriteObservationAndChain(value.out, (observation) => {
    observation.network.resolved_ip = 'deadbeef'
  })
  await rewriteEventChain(value.out, (records) => {
    const preDispatch = records.find(
      ({ type }) => type === 'ACTION_REQUEST_PRE_DISPATCH',
    )
    preDispatch.details.transport_identity.resolved_ip = 'deadbeef'
  })
  const validation = await validateHttpReconBundle({
    bundle: value.out,
    now: value.clock.now,
  })
  assert.equal(validation.valid, false)
  assert.deepEqual(
    validation.errors.map(({ code }) => code),
    ['HTTP_RECON_DNS_EVIDENCE_INVALID'],
  )
})

test('finalize adopts an action pre-dispatch fsynced past a stale run root', async (t) => {
  const value = await attestedFixture(t)
  await synthesizeStaleActionPreDispatch(
    value.out,
    value.clock.now().toISOString(),
  )
  const finalized = await finalizeHttpReconBundle({
    bundle: value.out,
    now: value.clock.now,
  })
  assert.equal(finalized.run.state, 'OUTCOME_UNCERTAIN')
  assert.equal(finalized.run.actions[0].state, 'DELIVERY_AMBIGUOUS')
  const validation = await validateHttpReconBundle({
    bundle: value.out,
    now: value.clock.now,
  })
  assert.equal(validation.valid, true)
})

test('finalize treats SENT without durable pre-dispatch as interrupted before send', async (t) => {
  const value = await attestedFixture(t)
  await synthesizeStaleActionPreDispatch(
    value.out,
    value.clock.now().toISOString(),
    { includePreDispatch: false },
  )
  const finalized = await finalizeHttpReconBundle({
    bundle: value.out,
    now: value.clock.now,
  })
  assert.equal(finalized.run.state, 'FAILED')
  assert.equal(finalized.run.actions[0].state, 'FAILED')
  assert.equal(
    finalized.run.actions[0].error.code,
    'INTERRUPTED_BEFORE_ACTION_SEND',
  )
})

test('finalize preserves a response stop recovered from an ACTION_COMMITTED crash tail', async (t) => {
  const value = await attestedFixture(t)
  const next = await nextHttpReconAction({
    bundle: value.out,
    now: value.clock.now,
  })
  const transport = attestedTransports()
  const originalProbe = transport.probeImpl
  transport.probeImpl = async (options) => {
    const error = new Error('synthetic response stop')
    error.code = 'HTTP_RECON_STOP_CONDITION'
    error.condition = 'TARGET_HEALTH_DEGRADED'
    error.request_may_have_been_sent = true
    error.result = {
      ...await originalProbe(options),
      status: 500,
    }
    throw error
  }
  const stopped = await runHttpReconAction({
    bundle: value.out,
    actionId: next.action_id,
    operatorId: 'operator-001',
    rationale: 'authorized bounded response metadata observation',
    now: value.clock.now,
    probeImpl: transport.probeImpl,
  })
  assert.equal(stopped.run.state, 'STOPPED')
  const normalStopReason = stopped.run.stop.reason

  const eventPath = join(value.out, 'events.jsonl')
  const runPath = join(value.out, 'run.json')
  const events = (await readFile(eventPath, 'utf8'))
    .trimEnd()
    .split('\n')
    .map((line) => JSON.parse(line))
  const commitIndex = events.findIndex(({ type }) => type === 'ACTION_COMMITTED')
  const commit = events[commitIndex]
  const predecessor = events[commitIndex - 1]
  const lease = events.find(({ type }) => type === 'ACTION_LEASED')
  assert.notEqual(commitIndex, -1)
  assert.notEqual(commit.details.stop_condition, null)
  assert.equal(
    normalStopReason,
    `${commit.details.stop_condition.code}: ${commit.details.stop_condition.message}`,
  )

  const staleRun = JSON.parse(await readFile(runPath, 'utf8'))
  staleRun.state = 'ACTIVE'
  staleRun.stop = null
  staleRun.report = null
  staleRun.budget = structuredClone(lease.details.budget_before)
  staleRun.actions[0].state = 'SENT'
  staleRun.actions[0].completed_at = null
  staleRun.actions[0].observation_path = null
  staleRun.actions[0].observation_sha256 = null
  staleRun.actions[0].error = null
  staleRun.event_chain = {
    count: predecessor.sequence,
    last_sha256: predecessor.record_sha256,
  }
  await writeFile(
    eventPath,
    `${events.slice(0, commitIndex + 1).map((record) => JSON.stringify(record)).join('\n')}\n`,
  )
  await writeFile(runPath, `${JSON.stringify(staleRun, null, 2)}\n`)

  const recovered = await finalizeHttpReconBundle({
    bundle: value.out,
    now: value.clock.now,
  })
  assert.equal(recovered.run.state, 'STOPPED')
  assert.equal(recovered.run.stop.reason, normalStopReason)
  const validation = await validateHttpReconBundle({
    bundle: value.out,
    now: value.clock.now,
  })
  assert.equal(validation.valid, true)
})

test('finalize adopts an exact fsynced finalization past an active run root', async (t) => {
  const value = await attestedFixture(t)
  const next = await nextHttpReconAction({
    bundle: value.out,
    now: value.clock.now,
  })
  const transport = attestedTransports()
  await runHttpReconAction({
    bundle: value.out,
    actionId: next.action_id,
    operatorId: 'operator-001',
    rationale: 'authorized bounded response metadata observation',
    now: value.clock.now,
    probeImpl: transport.probeImpl,
  })
  const firstFinalization = await finalizeHttpReconBundle({
    bundle: value.out,
    now: value.clock.now,
  })
  const eventPath = join(value.out, 'events.jsonl')
  const runPath = join(value.out, 'run.json')
  const events = (await readFile(eventPath, 'utf8'))
    .trimEnd()
    .split('\n')
    .map((line) => JSON.parse(line))
  assert.equal(events.at(-1).type, 'RUN_FINALIZED')
  const run = JSON.parse(await readFile(runPath, 'utf8'))
  run.state = 'ACTIVE'
  run.report = null
  run.event_chain = {
    count: events.length - 1,
    last_sha256: events.at(-2).record_sha256,
  }
  await writeFile(runPath, `${JSON.stringify(run, null, 2)}\n`)

  const recovered = await finalizeHttpReconBundle({
    bundle: value.out,
    now: value.clock.now,
  })
  assert.equal(recovered.run.state, 'PROBE_PLAN_COMPLETE')
  assert.equal(recovered.run.event_chain.count, events.length)
  assert.equal(recovered.run.report.sha256, firstFinalization.run.report.sha256)
  const validation = await validateHttpReconBundle({
    bundle: value.out,
    now: value.clock.now,
  })
  assert.equal(validation.valid, true)
})

test('finalize is idempotent after a rooted RUN_FINALIZED and ignores a late stop marker', async (t) => {
  const value = await attestedFixture(t)
  const next = await nextHttpReconAction({ bundle: value.out, now: value.clock.now })
  const transport = attestedTransports()
  await runHttpReconAction({
    bundle: value.out,
    actionId: next.action_id,
    operatorId: 'operator-001',
    rationale: 'authorized bounded response metadata observation',
    now: value.clock.now,
    probeImpl: transport.probeImpl,
  })
  const first = await finalizeHttpReconBundle({ bundle: value.out, now: value.clock.now })
  const eventPath = join(value.out, 'events.jsonl')
  const firstEvents = await readFile(eventPath, 'utf8')
  await requestHttpReconStop({
    bundle: value.out,
    operatorId: 'operator-001',
    reason: 'late operator stop after durable finalization',
    now: value.clock.now,
  })
  const second = await finalizeHttpReconBundle({ bundle: value.out, now: value.clock.now })
  assert.deepEqual(second.run, first.run)
  assert.equal(await readFile(eventPath, 'utf8'), firstEvents)
  assert.equal((firstEvents.match(/RUN_FINALIZED/g) ?? []).length, 1)
})

test('finalize atomically replaces an incomplete report left before its durable root', async (t) => {
  const value = await attestedFixture(t)
  const next = await nextHttpReconAction({ bundle: value.out, now: value.clock.now })
  const transport = attestedTransports()
  await runHttpReconAction({
    bundle: value.out,
    actionId: next.action_id,
    operatorId: 'operator-001',
    rationale: 'authorized bounded response metadata observation',
    now: value.clock.now,
    probeImpl: transport.probeImpl,
  })
  await writeFile(join(value.out, 'report.md'), 'incomplete report publication')
  const finalized = await finalizeHttpReconBundle({ bundle: value.out, now: value.clock.now })
  assert.equal(finalized.run.state, 'PROBE_PLAN_COMPLETE')
  const validation = await validateHttpReconBundle({ bundle: value.out, now: value.clock.now })
  assert.equal(validation.valid, true)
})

test('finalize does not root RUN_FINALIZED until report directory sync succeeds', async (t) => {
  const value = await attestedFixture(t)
  const next = await nextHttpReconAction({ bundle: value.out, now: value.clock.now })
  const transport = attestedTransports()
  await runHttpReconAction({
    bundle: value.out,
    actionId: next.action_id,
    operatorId: 'operator-001',
    rationale: 'authorized bounded response metadata observation',
    now: value.clock.now,
    probeImpl: transport.probeImpl,
  })
  const eventPath = join(value.out, 'events.jsonl')
  const before = await readFile(eventPath, 'utf8')
  await assert.rejects(
    finalizeHttpReconBundle({
      bundle: value.out,
      now: value.clock.now,
      directorySyncImpl: async () => { throw new Error('synthetic directory sync failure') },
    }),
    /synthetic directory sync failure/,
  )
  assert.equal(await readFile(eventPath, 'utf8'), before)
  const finalized = await finalizeHttpReconBundle({ bundle: value.out, now: value.clock.now })
  assert.equal(finalized.run.state, 'PROBE_PLAN_COMPLETE')
})

test('a dead recon lock owner is recovered before finalization', async (t) => {
  const value = await attestedFixture(t)
  await requestHttpReconStop({
    bundle: value.out,
    operatorId: 'operator-001',
    reason: 'finish the bounded fixture',
    now: value.clock.now,
  })
  const child = spawn(process.execPath, ['-e', ''])
  const deadPid = child.pid
  await once(child, 'exit')
  await writeFile(join(value.out, '.http-recon.lock'), stableJson({
    schema_version: '1.0.0',
    pid: deadPid,
    acquired_at: value.clock.now().toISOString(),
    nonce: 'a'.repeat(32),
  }))
  const finalized = await finalizeHttpReconBundle({ bundle: value.out, now: value.clock.now })
  assert.equal(finalized.run.state, 'STOPPED')
})

test('a dead two-name recon reclaim guard cannot permanently block stale-lock recovery', async (t) => {
  const value = await attestedFixture(t)
  await requestHttpReconStop({
    bundle: value.out,
    operatorId: 'operator-001',
    reason: 'finish after a crashed reclaim owner',
    now: value.clock.now,
  })
  const child = spawn(process.execPath, ['-e', ''])
  const deadPid = child.pid
  await once(child, 'exit')
  const owner = {
    schema_version: '1.0.0',
    pid: deadPid,
    acquired_at: value.clock.now().toISOString(),
  }
  await writeFile(join(value.out, '.http-recon.lock'), stableJson({
    ...owner,
    nonce: '1'.repeat(32),
  }))
  const reclaimTemporary = join(
    value.out,
    `.http-recon.lock-reclaim.tmp-${deadPid}-1111111111111111`,
  )
  const reclaimPath = join(value.out, '.http-recon.lock-reclaim')
  await writeFile(reclaimTemporary, stableJson({
    ...owner,
    nonce: '2'.repeat(32),
  }))
  await link(reclaimTemporary, reclaimPath)

  const finalized = await finalizeHttpReconBundle({ bundle: value.out, now: value.clock.now })
  assert.equal(finalized.run.state, 'STOPPED')
  await assert.rejects(
    readFile(reclaimPath),
    (error) => error.code === 'ENOENT',
  )
  assert.equal(JSON.parse(await readFile(reclaimTemporary, 'utf8')).nonce, '2'.repeat(32))
})

test('a live recon lock owner remains exclusive', async (t) => {
  const value = await attestedFixture(t)
  const lockPath = join(value.out, '.http-recon.lock')
  await writeFile(lockPath, stableJson({
    schema_version: '1.0.0',
    pid: process.pid,
    acquired_at: value.clock.now().toISOString(),
    nonce: 'b'.repeat(32),
  }))
  await assert.rejects(
    finalizeHttpReconBundle({ bundle: value.out, now: value.clock.now }),
    (error) => error.code === 'HTTP_RECON_RUN_LOCKED',
  )
  await rm(lockPath)
})

test('a lock released after create collision is retried instead of leaking ENOENT', async (t) => {
  const value = await attestedFixture(t)
  await requestHttpReconStop({
    bundle: value.out,
    operatorId: 'operator-001',
    reason: 'finish after the lock collision race',
    now: value.clock.now,
  })
  const lockPath = join(value.out, '.http-recon.lock')
  await writeFile(lockPath, stableJson({
    schema_version: '1.0.0',
    pid: process.pid,
    acquired_at: value.clock.now().toISOString(),
    nonce: 'c'.repeat(32),
  }))
  let collisionExercised = false
  const finalized = await finalizeHttpReconBundle({
    bundle: value.out,
    now: value.clock.now,
    lockFaultInjector: async (phase) => {
      if (phase !== 'after-run-lock-collision' || collisionExercised) return
      collisionExercised = true
      await rm(lockPath)
    },
  })
  assert.equal(collisionExercised, true)
  assert.equal(finalized.run.state, 'STOPPED')
})

test('serialized stale reclaim leaves a replacement live lock in place', async (t) => {
  const value = await attestedFixture(t)
  await requestHttpReconStop({
    bundle: value.out,
    operatorId: 'operator-001',
    reason: 'finish after replacement lock validation',
    now: value.clock.now,
  })
  const lockPath = join(value.out, '.http-recon.lock')
  const stale = stableJson({
    schema_version: '1.0.0',
    pid: 2_147_483_647,
    acquired_at: value.clock.now().toISOString(),
    nonce: 'd'.repeat(32),
  })
  const replacement = stableJson({
    schema_version: '1.0.0',
    pid: process.pid,
    acquired_at: value.clock.now().toISOString(),
    nonce: 'e'.repeat(32),
  })
  await writeFile(lockPath, stale)
  let replacementInstalled = false
  await assert.rejects(
    finalizeHttpReconBundle({
      bundle: value.out,
      now: value.clock.now,
      lockFaultInjector: async (phase) => {
        if (phase !== 'after-run-lock-reclaim-guard-acquired' || replacementInstalled) return
        replacementInstalled = true
        await rm(lockPath)
        await writeFile(lockPath, replacement)
      },
    }),
    (error) => error.code === 'HTTP_RECON_RUN_LOCKED',
  )
  assert.equal(replacementInstalled, true)
  assert.equal(await readFile(lockPath, 'utf8'), replacement)
  await rm(lockPath)
})

test('recon lock release never deletes a replacement live owner', async (t) => {
  const value = await attestedFixture(t)
  await requestHttpReconStop({
    bundle: value.out,
    operatorId: 'operator-001',
    reason: 'finish before the release replacement race',
    now: value.clock.now,
  })
  const lockPath = join(value.out, '.http-recon.lock')
  const replacement = stableJson({
    schema_version: '1.0.0',
    pid: process.pid,
    acquired_at: value.clock.now().toISOString(),
    nonce: '9'.repeat(32),
  })
  let replacementInstalled = false

  await assert.rejects(
    finalizeHttpReconBundle({
      bundle: value.out,
      now: value.clock.now,
      lockFaultInjector: async (phase) => {
        if (phase !== 'before-run-lock-release-quarantine' || replacementInstalled) return
        replacementInstalled = true
        await rm(lockPath)
        await writeFile(lockPath, replacement)
      },
    }),
    (error) => error.code === 'HTTP_RECON_RUN_LOCK_CHANGED',
  )
  assert.equal(replacementInstalled, true)
  assert.equal(await readFile(lockPath, 'utf8'), replacement)
  await rm(lockPath)
})

test('stale-lock inspection rejects an endpoint swapped after its bounded lstat', async (t) => {
  const value = await attestedFixture(t)
  await requestHttpReconStop({
    bundle: value.out,
    operatorId: 'operator-001',
    reason: 'finish after bounded stale-lock inspection',
    now: value.clock.now,
  })
  const lockPath = join(value.out, '.http-recon.lock')
  await writeFile(lockPath, stableJson({
    schema_version: '1.0.0',
    pid: 2_147_483_647,
    acquired_at: value.clock.now().toISOString(),
    nonce: 'f'.repeat(32),
  }))
  let swapped = false
  await assert.rejects(
    finalizeHttpReconBundle({
      bundle: value.out,
      now: value.clock.now,
      lockFaultInjector: async (phase, detail) => {
        if (phase !== 'after-run-lock-lstat' || detail?.path !== lockPath || swapped) return
        swapped = true
        await rm(lockPath)
        await writeFile(lockPath, 'x'.repeat(4097))
      },
    }),
    (error) => error.code === 'HTTP_RECON_ARTIFACT_CHANGED'
      || error.code === 'HTTP_RECON_ARTIFACT_TOO_LARGE',
  )
  assert.equal(swapped, true)
})

test('concurrent stale lock reclaim never leaks filesystem races', async (t) => {
  const value = await attestedFixture(t)
  await requestHttpReconStop({
    bundle: value.out,
    operatorId: 'operator-001',
    reason: 'finish after concurrent stale lock reclaim',
    now: value.clock.now,
  })
  await writeFile(join(value.out, '.http-recon.lock'), stableJson({
    schema_version: '1.0.0',
    pid: 2_147_483_647,
    acquired_at: value.clock.now().toISOString(),
    nonce: 'f'.repeat(32),
  }))
  const results = await Promise.allSettled(Array.from({ length: 24 }, () => (
    finalizeHttpReconBundle({ bundle: value.out, now: value.clock.now })
  )))
  assert.ok(results.some(({ status }) => status === 'fulfilled'))
  for (const result of results) {
    if (result.status === 'fulfilled') continue
    assert.ok(
      ['HTTP_RECON_RUN_LOCKED', 'HTTP_RECON_RUN_LOCK_RECLAIM_BUSY'].includes(result.reason?.code),
      `unexpected stale-reclaim error: ${result.reason?.stack ?? result.reason}`,
    )
  }
  const validation = await validateHttpReconBundle({ bundle: value.out, now: value.clock.now })
  assert.equal(validation.valid, true)
})

test('forged finalization tail is rejected before its stale run root is adopted', async (t) => {
  const value = await attestedFixture(t)
  const next = await nextHttpReconAction({
    bundle: value.out,
    now: value.clock.now,
  })
  const transport = attestedTransports()
  await runHttpReconAction({
    bundle: value.out,
    actionId: next.action_id,
    operatorId: 'operator-001',
    rationale: 'authorized bounded response metadata observation',
    now: value.clock.now,
    probeImpl: transport.probeImpl,
  })
  const finalized = await finalizeHttpReconBundle({
    bundle: value.out,
    now: value.clock.now,
  })
  const eventPath = join(value.out, 'events.jsonl')
  const runPath = join(value.out, 'run.json')
  const events = (await readFile(eventPath, 'utf8'))
    .trimEnd()
    .split('\n')
    .map((line) => JSON.parse(line))
  const finalEvent = events.at(-1)
  const run = JSON.parse(await readFile(runPath, 'utf8'))
  run.state = 'ACTIVE'
  run.report = null
  run.event_chain = {
    count: events.length - 1,
    last_sha256: events.at(-2).record_sha256,
  }
  const staleRoot = structuredClone(run.event_chain)
  await writeFile(runPath, `${JSON.stringify(run, null, 2)}\n`)

  const forgedReport = `${await readFile(finalized.reportPath, 'utf8')}forged\n`
  await writeFile(finalized.reportPath, forgedReport)
  finalEvent.details.report_sha256 = sha256Hex(Buffer.from(forgedReport, 'utf8'))
  delete finalEvent.record_sha256
  finalEvent.record_sha256 = sha256Hex(canonicalJson(finalEvent))
  await writeFile(
    eventPath,
    `${events.map((record) => JSON.stringify(record)).join('\n')}\n`,
  )

  await assert.rejects(
    finalizeHttpReconBundle({
      bundle: value.out,
      now: value.clock.now,
    }),
    (error) => {
      assert.equal(error.code, 'HTTP_RECON_REPORT_RENDER_MISMATCH')
      return true
    },
  )
  const unchanged = JSON.parse(await readFile(runPath, 'utf8'))
  assert.equal(unchanged.state, 'ACTIVE')
  assert.equal(unchanged.report, null)
  assert.deepEqual(unchanged.event_chain, staleRoot)
})

test('schema-valid mutable action, limits, or target edits fail before transport', async (t) => {
  const mutations = [
    (run) => { run.actions[0].url = 'https://target.example/admin' },
    (run) => { run.limits.min_interval_ms = 2_000 },
    (run) => {
      run.target.tls = {
        mode: 'PKIX_HOSTNAME_AND_SPKI_PIN',
        spki_sha256: SPKI_SHA256,
      }
    },
    (run) => { run.authorization.valid_until = '2026-08-04T12:05:00.000Z' },
  ]
  for (const mutate of mutations) {
    const value = await attestedFixture(t)
    const runPath = join(value.out, 'run.json')
    const run = JSON.parse(await readFile(runPath, 'utf8'))
    mutate(run)
    await writeFile(runPath, `${JSON.stringify(run, null, 2)}\n`)
    const transport = attestedTransports()
    await assert.rejects(
      nextHttpReconAction({
        bundle: value.out,
        now: value.clock.now,
      }),
      /sealed operator attestation|scope does not match/,
    )
    assert.deepEqual(transport.counters, { proof: 0, probe: 0 })
  }
})

test('CLI rejects untyped plan URLs and all post-plan target overrides', () => {
  const result = spawnSync(
    process.execPath,
    ['scripts/http-recon.mjs', 'plan', '--url', 'https://target.example/'],
    { encoding: 'utf8', shell: false, windowsHide: true },
  )
  assert.equal(result.status, 1)
  assert.match(result.stderr, /plan does not support --url/)

  const runResult = spawnSync(
    process.execPath,
    [
      'scripts/http-recon.mjs',
      'run',
      'missing-bundle',
      `http-recon-action:${'a'.repeat(64)}`,
      '--target-url',
      'https://target.example/',
    ],
    { encoding: 'utf8', shell: false, windowsHide: true },
  )
  assert.equal(runResult.status, 1)
  assert.match(runResult.stderr, /run does not support --target-url/)
})

test('CLI plans operator-attested scope without authority artifact paths', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'rta-http-recon-cli-attested-'))
  t.after(() => rm(parent, { recursive: true, force: true }))
  const out = join(parent, 'bundle')
  const planArgs = [
    'scripts/http-recon.mjs',
    'plan',
    '--target-url',
    'https://target.example/',
    '--operator-id',
    'operator-001',
    '--authorized-by',
    'A. Asset Owner',
    '--authorization-reference',
    'operator authorization reference 2026-08-04',
    '--out',
    out,
  ]
  const result = spawnSync(
    process.execPath,
    planArgs,
    { encoding: 'utf8', shell: false, windowsHide: true },
  )
  assert.equal(result.status, 0, result.stderr)
  assert.match(result.stdout, /not independently verified/)
  const run = JSON.parse(await readFile(join(out, 'run.json'), 'utf8'))
  assert.equal(run.authorization.mode, 'OPERATOR_ATTESTED')
  assert.equal(run.actions[0].method, 'HEAD')
  assert.deepEqual(run.target.tls, { mode: 'PKIX_HOSTNAME' })
  assert.equal(Object.hasOwn(run, 'target_proof'), false)
  assert.equal(run.budget.proof_requests_used, 0)
  const events = (await readFile(join(out, 'events.jsonl'), 'utf8'))
    .trimEnd()
    .split('\n')
    .map((line) => JSON.parse(line))
  assert.equal(
    events[0].details.operator_authorization_receipt.authority_basis,
    'OPERATOR_DECLARATION_ACCEPTED_AS_FACT',
  )
})

test('event-chain tampering blocks selection before any request', async (t) => {
  const value = await attestedFixture(t)
  await writeFile(join(value.out, 'events.jsonl'), '')
  await assert.rejects(
    nextHttpReconAction({
      bundle: value.out,
      now: value.clock.now,
    }),
    /event root|sealed plan commitment/,
  )
})

test('out-of-band stop is idempotent and prevents target dispatch', async (t) => {
  const value = await attestedFixture(t)
  const first = await requestHttpReconStop({
    bundle: value.out,
    operatorId: 'operator-001',
    reason: 'asset owner requested immediate stop',
    now: value.clock.now,
  })
  const second = await requestHttpReconStop({
    bundle: value.out,
    operatorId: 'operator-002',
    reason: 'confirm the existing emergency stop',
    now: value.clock.now,
  })
  assert.deepEqual(second, first)
  const transport = attestedTransports()
  const stopped = await runHttpReconAction({
    bundle: value.out,
    actionId: value.planned.run.actions[0].action_id,
    operatorId: 'operator-001',
    rationale: 'would have been authorized without stop',
    now: value.clock.now,
    probeImpl: transport.probeImpl,
  })
  assert.equal(stopped.run.state, 'STOPPED')
  assert.equal(stopped.action, null)
  assert.deepEqual(transport.counters, { proof: 0, probe: 0 })
})

test('a concurrent recon stop requester never observes a partially written final marker', async (t) => {
  const value = await attestedFixture(t)
  let entered
  let release
  const enteredPromise = new Promise((resolvePromise) => { entered = resolvePromise })
  const releasePromise = new Promise((resolvePromise) => { release = resolvePromise })
  const firstPromise = requestHttpReconStop({
    bundle: value.out,
    operatorId: 'operator-001',
    reason: 'first concurrent emergency stop',
    now: value.clock.now,
    stopPublicationFaultInjector: async () => {
      entered()
      await releasePromise
    },
  })
  await enteredPromise
  const secondOutcome = await requestHttpReconStop({
    bundle: value.out,
    operatorId: 'operator-002',
    reason: 'second concurrent emergency stop',
    now: value.clock.now,
  }).then(
    (value) => ({ status: 'fulfilled', value }),
    (reason) => ({ status: 'rejected', reason }),
  )
  release()
  const first = await firstPromise

  assert.equal(secondOutcome.status, 'fulfilled', secondOutcome.reason?.stack)
  assert.equal(secondOutcome.value.requested_at, first.requested_at)
})

test('out-of-band stop aborts an in-flight request and preserves uncertain delivery', async (t) => {
  const value = await attestedFixture(t)
  const transport = attestedTransports()
  let confirmSent
  const sent = new Promise((resolvePromise) => { confirmSent = resolvePromise })
  transport.probeImpl = async (options) => {
    transport.counters.probe += 1
    await options.beforeSend(preDispatchMetadata({
      url: options.url,
      method: options.method,
      tlsVerification: 'PKIX_HOSTNAME',
    }))
    confirmSent()
    return new Promise((resolvePromise, rejectPromise) => {
      options.signal.addEventListener('abort', () => {
        const error = new Error('request aborted by out-of-band stop')
        error.code = 'HTTP_RECON_ABORTED'
        error.request_may_have_been_sent = true
        rejectPromise(error)
      }, { once: true })
    })
  }
  const running = runHttpReconAction({
    bundle: value.out,
    actionId: value.planned.run.actions[0].action_id,
    operatorId: 'operator-001',
    rationale: 'approved bounded response metadata observation',
    now: value.clock.now,
    delayImpl: async (milliseconds) => value.clock.advance(milliseconds),
    stopPollIntervalMs: 5,
    probeImpl: transport.probeImpl,
  })
  await sent
  const inFlight = JSON.parse(
    await readFile(join(value.out, 'run.json'), 'utf8'),
  )
  assert.equal(inFlight.actions[0].state, 'SENT')
  assert.notEqual(inFlight.actions[0].sent_at, null)
  await requestHttpReconStop({
    bundle: value.out,
    operatorId: 'operator-002',
    reason: 'asset owner requested stop during request',
    now: value.clock.now,
  })
  const result = await running
  assert.equal(result.run.state, 'OUTCOME_UNCERTAIN')
  assert.equal(result.action.state, 'DELIVERY_AMBIGUOUS')
  assert.match(result.stop_reason, /owner requested stop/)
})

test('delivery after pre-dispatch without a response is terminal and never replayed', async (t) => {
  const value = await attestedFixture(t)
  const transport = attestedTransports()
  transport.probeImpl = async (options) => {
    transport.counters.probe += 1
    await options.beforeSend(preDispatchMetadata({
      url: options.url,
      method: options.method,
      tlsVerification: 'PKIX_HOSTNAME',
    }))
    const error = new Error('synthetic connection loss after send')
    error.code = 'HTTP_RECON_REQUEST_FAILED'
    error.request_may_have_been_sent = true
    throw error
  }
  await assert.rejects(
    runHttpReconAction({
      bundle: value.out,
      actionId: value.planned.run.actions[0].action_id,
      operatorId: 'operator-001',
      rationale: 'approved bounded response metadata observation',
      now: value.clock.now,
      delayImpl: async (milliseconds) => value.clock.advance(milliseconds),
      probeImpl: transport.probeImpl,
    }),
    /connection loss after send/,
  )
  const run = JSON.parse(await readFile(join(value.out, 'run.json'), 'utf8'))
  assert.equal(run.state, 'OUTCOME_UNCERTAIN')
  assert.equal(run.actions[0].state, 'DELIVERY_AMBIGUOUS')
  const events = (await readFile(join(value.out, 'events.jsonl'), 'utf8'))
    .trimEnd()
    .split('\n')
    .map((line) => JSON.parse(line))
  const preDispatch = events.find(
    ({ type }) => type === 'ACTION_REQUEST_PRE_DISPATCH',
  )
  assert.equal(
    preDispatch.details.transport_identity.peer_spki_sha256,
    SPKI_SHA256,
  )
  assert.equal(
    preDispatch.details.transport_identity.tls_verification,
    'PKIX_HOSTNAME',
  )
  await assert.rejects(
    nextHttpReconAction({
      bundle: value.out,
      now: value.clock.now,
    }),
    /terminal|uncertain/i,
  )
})

test('stop marker can still be written when run.json is damaged', async (t) => {
  const value = await attestedFixture(t)
  await writeFile(join(value.out, 'run.json'), '{damaged')
  const stopped = await requestHttpReconStop({
    bundle: value.out,
    operatorId: 'operator-001',
    reason: 'bundle integrity failed; stop all activity',
    now: value.clock.now,
  })
  assert.equal(stopped.engagement_id, null)
  const marker = JSON.parse(await readFile(stopped.path, 'utf8'))
  assert.equal(marker.reason, 'bundle integrity failed; stop all activity')
})
