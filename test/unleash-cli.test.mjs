import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import test from 'node:test'

import {
  identifyEngageManagementBundle,
  runEngageCli,
} from '../scripts/engage.mjs'
import { UnleashControllerError } from '../scripts/lib/unleash-controller.mjs'

const TARGET = 'https://Example.test'

function capture() {
  const stdout = []
  const stderr = []
  return {
    stdout: { write: (value) => { stdout.push(String(value)); return true } },
    stderr: { write: (value) => { stderr.push(String(value)); return true } },
    stdoutText: () => stdout.join(''),
    stderrText: () => stderr.join(''),
  }
}

function unleashResult(overrides = {}) {
  return {
    campaign_id: 'campaign:test-001',
    status: 'ACTIVE',
    run_directory: 'C:\\last-aperture\\runs\\campaign-test-001',
    plan_sha256: 'a'.repeat(64),
    target: {
      family: 'https',
      canonical_locator: 'https://example.test/',
      target_id: `target:sha256:${'b'.repeat(64)}`,
      supplied_sha256: 'c'.repeat(64),
    },
    completed_routes: ['https-recon'],
    route_counts: {
      total: 29,
      ready: 1,
      waiting: 3,
      unavailable: 4,
      not_applicable: 20,
      blocked: 1,
    },
    gap_count: 8,
    ...overrides,
  }
}

test('help advertises the target-only unleash command', async () => {
  const io = capture()
  let calls = 0

  assert.equal(await runEngageCli(
    ['unleash', '--help'],
    {
      unleashTarget: async () => { calls += 1 },
      ...io,
    },
  ), 0, io.stderrText())

  assert.equal(calls, 0)
  assert.match(io.stdoutText(), /engage unleash <target> \[--json\]/)
  assert.equal(io.stderrText(), '')
})

test('unleash accepts exactly one target and delegates exactly once with no other runtime input', async () => {
  const calls = []
  const io = capture()
  const result = unleashResult()

  const code = await runEngageCli(
    ['unleash', TARGET, '--json'],
    {
      unleashTarget: async (input) => {
        calls.push(input)
        return result
      },
      ...io,
    },
  )

  assert.equal(code, 0, io.stderrText())
  assert.deepEqual(calls, [{ target: TARGET }])
  assert.deepEqual(JSON.parse(io.stdoutText()), result)
  assert.equal(io.stderrText(), '')
})

test('unleash rejects missing and additional targets before invoking the controller', async () => {
  for (const args of [
    ['unleash'],
    ['unleash', TARGET, 'https://second.example/'],
  ]) {
    let calls = 0
    const io = capture()

    assert.equal(await runEngageCli(args, {
      unleashTarget: async () => { calls += 1 },
      ...io,
    }), 1)
    assert.equal(calls, 0)
    assert.match(io.stderrText(), /unleash.*exactly one target|usage/i)
  }
})

test('unleash accepts only presentation flags and never accepts controller material or credentials', async () => {
  for (const [option, value] of [
    ['--out', 'C:\\operator-chosen-run'],
    ['--profile', 'full'],
    ['--attestation-file', 'C:\\trusted\\statement.txt'],
    ['--input', 'artifact=C:\\trusted\\application.exe'],
    ['--credential-reference', 'browser:abcdefghijklmnopabcdefghijklmnop'],
    ['--objective', 'operator-supplied objective'],
  ]) {
    let calls = 0
    const io = capture()

    assert.equal(await runEngageCli(
      ['unleash', TARGET, option, value, '--json'],
      {
        unleashTarget: async () => { calls += 1 },
        ...io,
      },
    ), 1, `${option} was accepted`)
    assert.equal(calls, 0, `${option} reached unleashTarget`)
    const failure = JSON.parse(io.stderrText())
    assert.equal(failure.status, 'FAILED')
    assert.match(failure.error.code, /^ENGAGE_CLI_/)
    assert.match(failure.error.message, new RegExp(option.slice(2), 'i'))
    assert.equal(io.stdoutText(), '')
  }
})

test('unleash JSON output is terminal-safe and exposes the complete campaign summary', async () => {
  const io = capture()
  const result = unleashResult({
    campaign_id: 'campaign:test\u001b[31m\nFORGED',
    run_directory: 'C:\\runs\\test\u202eexe.txt',
  })

  assert.equal(await runEngageCli(
    ['unleash', TARGET, '--json'],
    { unleashTarget: async () => result, ...io },
  ), 0, io.stderrText())

  const raw = io.stdoutText()
  const output = JSON.parse(raw)
  assert.deepEqual(output, result)
  assert.equal(output.campaign_id, result.campaign_id)
  assert.equal(output.status, 'ACTIVE')
  assert.equal(output.run_directory, result.run_directory)
  assert.equal(output.plan_sha256, 'a'.repeat(64))
  assert.deepEqual(output.target, result.target)
  assert.deepEqual(output.completed_routes, ['https-recon'])
  assert.deepEqual(output.route_counts, {
    total: 29,
    ready: 1,
    waiting: 3,
    unavailable: 4,
    not_applicable: 20,
    blocked: 1,
  })
  assert.equal(output.gap_count, 8)
  assert.doesNotMatch(raw, /\u001b/u)
  assert.doesNotMatch(raw, /\u202e/u)
  assert.doesNotMatch(raw, /\nFORGED/u)
  assert.match(raw, /\\u001b\[31m\\nFORGED/u)
  assert.match(raw, /\\u202Eexe\.txt/u)
})

test('unleash human output is terminal-safe and shows target, plan digest, campaign state, routes, and gaps', async () => {
  const io = capture()
  const result = unleashResult({
    campaign_id: 'campaign:test\u001b[31m\nFORGED',
    run_directory: 'C:\\runs\\test\u202eexe.txt',
  })

  assert.equal(await runEngageCli(
    ['unleash', TARGET],
    { unleashTarget: async () => result, ...io },
  ), 0, io.stderrText())

  const output = io.stdoutText()
  assert.match(output, /Campaign: campaign:test\\u001B\[31m\\u000AFORGED/u)
  assert.match(output, /Status: ACTIVE/u)
  assert.match(output, /Target: https:\/\/example\.test\//u)
  assert.match(output, new RegExp(`Plan SHA-256: ${'a'.repeat(64)}`, 'u'))
  assert.match(output, /Run directory: C:\\runs\\test\\u202Eexe\.txt/u)
  assert.match(output, /Completed routes: 1/u)
  assert.match(output, /Routes: total=29 ready=1 waiting=3 unavailable=4 not_applicable=20 blocked=1/u)
  assert.match(output, /Gaps: 8/u)
  assert.doesNotMatch(output, /\u001b/u)
  assert.doesNotMatch(output, /\u202e/u)
  assert.doesNotMatch(output, /\nFORGED/u)
  assert.equal(io.stderrText(), '')
})

test('unleash failures use sanitized JSON and a stable fallback code', async () => {
  const io = capture()
  let calls = 0

  const code = await runEngageCli(
    ['unleash', TARGET, '--json'],
    {
      unleashTarget: async () => {
        calls += 1
        throw new Error('provider failed\u001b[31m\nFORGED')
      },
      ...io,
    },
  )

  assert.equal(code, 1)
  assert.equal(calls, 1)
  assert.equal(io.stdoutText(), '')
  assert.deepEqual(JSON.parse(io.stderrText()), {
    status: 'FAILED',
    error: {
      code: 'ENGAGE_CLI_FAILED',
      message: 'provider failed\\u001B[31m\\u000AFORGED',
    },
  })
  assert.doesNotMatch(io.stderrText(), /\u001b/u)
  assert.doesNotMatch(io.stderrText(), /\nFORGED/u)
  assert.doesNotMatch(io.stderrText(), /at file:|node:internal|\.mjs:\d+/u)
})

test('Unleash controller recovery errors preserve status and run directory in JSON and human output', async () => {
  const failure = new UnleashControllerError(
    'UNLEASH_CAMPAIGN_RECOVERY_FAILED',
    'campaign state needs reconciliation\u001b[31m',
    {
      status: 'RECONCILIATION_REQUIRED',
      runDirectory: 'C:\\runs\\campaign-0123456789abcdef01234567',
    },
  )

  const jsonIo = capture()
  assert.equal(await runEngageCli(
    ['unleash', TARGET, '--json'],
    { unleashTarget: async () => { throw failure }, ...jsonIo },
  ), 1)
  assert.deepEqual(JSON.parse(jsonIo.stderrText()), {
    status: 'RECONCILIATION_REQUIRED',
    run_directory: failure.run_directory,
    error: {
      code: 'UNLEASH_CAMPAIGN_RECOVERY_FAILED',
      message: 'campaign state needs reconciliation\\u001B[31m',
    },
  })

  const humanIo = capture()
  assert.equal(await runEngageCli(
    ['unleash', TARGET],
    { unleashTarget: async () => { throw failure }, ...humanIo },
  ), 1)
  assert.match(humanIo.stderrText(), /\[UNLEASH_CAMPAIGN_RECOVERY_FAILED\]/u)
  assert.match(humanIo.stderrText(), /Status: RECONCILIATION_REQUIRED/u)
  assert.match(humanIo.stderrText(), /Run directory: C:\\runs\\campaign-0123456789abcdef01234567/u)
  assert.doesNotMatch(humanIo.stderrText(), /\u001b/u)
})

test('existing engage run remains compatible after unleash is added', async () => {
  const calls = []
  const io = capture()
  const result = {
    status: 'WAITING_FOR_MATERIAL',
    engagement_id: 'engagement:legacy',
    bundle: 'C:\\engagements\\legacy',
    authorization_sha256: 'b'.repeat(64),
    target_sha256: 'c'.repeat(64),
    completed_routes: ['https-recon'],
    waiting_routes: ['authenticated-http-browser'],
  }

  const code = await runEngageCli([
    'run', TARGET,
    '--attestation-file', 'C:\\trusted\\statement.txt',
    '--profile', 'web',
    '--out', 'C:\\engagements\\legacy',
    '--credential-reference', 'browser:abcdefghijklmnopabcdefghijklmnop',
    '--input', 'configuration=C:\\trusted\\page-session-adapter.json',
    '--json',
  ], {
    readAttestation: async (path) => {
      calls.push(['read-attestation', path])
      return 'I have full authority to assess this target.'
    },
    startEngagement: async (input) => {
      calls.push(['run', input])
      return result
    },
    ...io,
  })

  assert.equal(code, 0, io.stderrText())
  assert.deepEqual(calls, [
    ['read-attestation', 'C:\\trusted\\statement.txt'],
    ['run', {
      target: TARGET,
      statement: 'I have full authority to assess this target.',
      authorizationProfile: 'web',
      out: 'C:\\engagements\\legacy',
      objective: 'Run the full authorized assessment and integration workflow for the named target.',
      credentialReferences: ['browser:abcdefghijklmnopabcdefghijklmnop'],
      inputs: [{
        kind: 'configuration',
        locator: 'C:\\trusted\\page-session-adapter.json',
      }],
    }],
  ])
  assert.deepEqual(JSON.parse(io.stdoutText()), result)
  assert.equal(io.stderrText(), '')
})

test('resume, status, and stop route validated Unleash bundle identities to Unleash management', async () => {
  const bundle = resolve('campaign-0123456789abcdef01234567')
  const result = unleashResult({ run_directory: bundle })
  const cases = [
    {
      argv: ['resume', bundle, '--json'],
      operation: 'resumeUnleashCampaign',
      expected: { bundle },
    },
    {
      argv: ['status', bundle, '--json'],
      operation: 'getUnleashCampaignStatus',
      expected: { bundle },
    },
    {
      argv: ['stop', bundle, '--reason', 'operator stop', '--json'],
      operation: 'stopUnleashCampaign',
      expected: { bundle, reason: 'operator stop' },
    },
  ]

  for (const { argv, operation, expected } of cases) {
    const io = capture()
    const calls = []
    const code = await runEngageCli(argv, {
      identifyManagementBundle: async (input) => ({
        kind: 'unleash',
        status: { ...result, run_directory: input.bundle },
      }),
      [operation]: async (input) => {
        calls.push(input)
        return result
      },
      ...io,
    })
    assert.equal(code, 0, io.stderrText())
    assert.deepEqual(calls, argv[0] === 'status' ? [] : [expected])
    assert.deepEqual(JSON.parse(io.stdoutText()), result)
  }
})

test('management keeps a validated legacy engagement on the legacy controller despite a campaign-shaped basename', async () => {
  const bundle = resolve('campaign-0123456789abcdef01234567')
  const io = capture()
  const calls = []
  const result = { engagement_id: 'engagement:legacy', status: 'RUNNING', bundle }

  const identifyManagementBundle = (input) => identifyEngageManagementBundle(input, {
    getUnleashCampaignStatus: async (candidate) => {
      calls.push(['unleash-validator', candidate])
      throw new Error('campaign marker absent')
    },
    getEngagementStatus: async (candidate) => {
      calls.push(['engagement-validator', candidate])
      return result
    },
  })

  assert.equal(await runEngageCli(['status', bundle, '--json'], {
    identifyManagementBundle,
    ...io,
  }), 0, io.stderrText())
  assert.deepEqual(calls, [
    ['unleash-validator', { bundle }],
    ['engagement-validator', { bundle }],
  ])
  assert.deepEqual(JSON.parse(io.stdoutText()), result)
})

test('management fails closed when both controllers validate the same bundle', async () => {
  const bundle = resolve('hybrid-bundle')
  await assert.rejects(
    () => identifyEngageManagementBundle(
      { bundle },
      {
        getUnleashCampaignStatus: async () => unleashResult({ run_directory: bundle }),
        getEngagementStatus: async () => ({ engagement_id: 'engagement:hybrid', status: 'RUNNING', bundle }),
      },
    ),
    (error) => error?.code === 'ENGAGE_BUNDLE_IDENTITY_AMBIGUOUS',
  )
})
