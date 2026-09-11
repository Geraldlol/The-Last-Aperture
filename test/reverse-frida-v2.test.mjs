import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'

import Ajv2020 from 'ajv/dist/2020.js'

import { traceFridaPlanFile } from '../scripts/lib/reverse-controller.mjs'
import {
  FRIDA_TRACE_PLAN_KIND,
  FRIDA_V2_PROFILE_ID,
  assertValidFridaTracePlan,
  buildFridaTracePlanArguments,
  digestFridaTracePlan,
  parseFridaTracePlanOutput,
  runFridaTracePlan,
} from '../scripts/lib/reverse-frida.mjs'

const AGENT = resolve('scripts/frida/native-call-trace-v2.js')
const FRIDA = resolve('tools/frida.exe')
const ARTIFACT = resolve('test/fixtures/reverse/demo executable.exe')
const CWD = resolve('test/fixtures/reverse/lab')
const PREFIX = '[last-aperture:frida] '
const NONCE = 'a'.repeat(64)
const ARTIFACT_SHA256 = 'b'.repeat(64)

function plan(target = { mode: 'local-spawn' }, artifact = {}) {
  return {
    schema_version: '1.0.0',
    kind: FRIDA_TRACE_PLAN_KIND,
    profile_id: FRIDA_V2_PROFILE_ID,
    artifact: {
      lab_root: CWD,
      path: 'bin/demo.exe',
      kind: 'native-executable',
      ...artifact,
    },
    target,
    hooks: [
      {
        hook_id: 'decoder.parse',
        resolver: { kind: 'export', module_name: '<main>', export_name: 'parse_packet' },
        capture: { arguments: [], return_value: null },
      },
      {
        hook_id: 'crypto.verify',
        resolver: { kind: 'export', module_name: 'crypto.dll', export_name: 'verify_token' },
        capture: { arguments: [], return_value: null },
      },
    ],
    limits: {
      duration_seconds: 5,
      max_events: 20,
      max_capture_records: 100,
      max_capture_bytes_total: 1024 * 1024,
      max_frame_capture_bytes: 65_536,
    },
  }
}

function parameters(args) {
  const index = args.indexOf('-P')
  assert.notEqual(index, -1)
  return JSON.parse(args[index + 1])
}

function v2Event(config, value, observedAt = 1000) {
  return `${PREFIX}${JSON.stringify({
    schema_version: '1.0.0',
    profile_id: FRIDA_V2_PROFILE_ID,
    frame_nonce: config.frameNonce,
    plan_sha256: config.planSha256,
    artifact_sha256: config.artifactSha256,
    target_mode: config.targetMode,
    observed_at_ms: observedAt,
    ...value,
  })}`
}

function successfulOutput(args) {
  const config = parameters(args)
  return [
    'untrusted target output is ignored',
    v2Event(config, { event: 'session-ready', hooks_expected: 2 }, 1000),
    v2Event(config, {
      event: 'hook-ready', hook_id: 'decoder.parse', resolver_kind: 'export',
      module_name: '<main>', symbol_name: 'parse_packet',
      module_relative_offset: '0x1000', resolved_address: '0x401000',
    }, 1001),
    v2Event(config, {
      event: 'hook-ready', hook_id: 'crypto.verify', resolver_kind: 'export',
      module_name: 'crypto.dll', symbol_name: 'verify_token',
      module_relative_offset: '0x2000', resolved_address: '0x702000',
    }, 1002),
    v2Event(config, {
      event: 'enter', hook_id: 'decoder.parse', call_id: 1, sequence: 1, thread_id: 7, captures: [],
    }, 1003),
    v2Event(config, {
      event: 'leave', hook_id: 'decoder.parse', call_id: 1, sequence: 2, thread_id: 7, captures: [],
    }, 1004),
    v2Event(config, {
      event: 'complete', hooks_ready: 2, hooks_detached: 2,
      events_emitted: 2, capture_attempts: 0, capture_failures: 0,
      capture_truncations: 0, captured_payload_bytes: 0, truncated: false,
    }, 1005),
  ].join('\n')
}

function capturePlan(target = { mode: 'local-spawn' }) {
  const value = plan(target)
  value.hooks = [{
    hook_id: 'http.send',
    resolver: { kind: 'export', module_name: '<main>', export_name: 'send_request' },
    capture: {
      arguments: [
        { capture_id: 'context.ptr', index: 0, codec: 'pointer', retention: 'metadata' },
        { capture_id: 'status.code', index: 1, codec: 'uint32', retention: 'raw' },
        { capture_id: 'headers.utf8', index: 2, codec: 'utf8', retention: 'raw', length: { kind: 'argument', index: 3, max_bytes: 16 } },
        { capture_id: 'path.utf16', index: 4, codec: 'utf16', retention: 'sha256', length: { kind: 'fixed', bytes: 8 } },
        { capture_id: 'body.bytes', index: 5, phase: 'leave', codec: 'bytes', retention: 'raw', length: { kind: 'fixed', bytes: 3 } },
      ],
      return_value: { capture_id: 'return.ok', codec: 'bool', retention: 'raw' },
    },
  }]
  return value
}

function pointer(retention, address = '0x501000') {
  return {
    is_null: false,
    address: retention === 'raw' ? address : null,
    module_name: 'demo.exe',
    module_relative_offset: '0x1000',
    protection: 'r-x',
  }
}

function outcome(value) {
  return {
    capture_id: value.capture_id,
    codec: value.codec,
    retention: value.retention,
    status: 'CAPTURED',
    pointer: value.pointer ?? null,
    requested_bytes: value.requested_bytes ?? null,
    captured_bytes: value.captured_bytes,
    truncated: value.truncated ?? false,
    truncation_reason: value.truncated === true ? (value.truncation_reason ?? 'DECLARED_MAX') : null,
    value_encoding: value.value_encoding,
    value: value.value,
    error_code: null,
  }
}

function capturedOutput(args) {
  const config = parameters(args)
  const rawHeaders = Buffer.from('Authorization: B', 'utf8')
  assert.equal(rawHeaders.length, 16)
  return [
    v2Event(config, { event: 'session-ready', hooks_expected: 1 }, 1000),
    v2Event(config, {
      event: 'hook-ready', hook_id: 'http.send', resolver_kind: 'export',
      module_name: '<main>', symbol_name: 'send_request', module_relative_offset: '0x1000',
      resolved_address: '0x401000',
    }, 1001),
    v2Event(config, {
      event: 'enter', hook_id: 'http.send', call_id: 1, sequence: 1, thread_id: 7,
      captures: [
        outcome({ capture_id: 'context.ptr', codec: 'pointer', retention: 'metadata', pointer: pointer('metadata'), captured_bytes: 0, value_encoding: 'none', value: null }),
        outcome({ capture_id: 'status.code', codec: 'uint32', retention: 'raw', captured_bytes: 4, value_encoding: 'number', value: 200 }),
        outcome({ capture_id: 'headers.utf8', codec: 'utf8', retention: 'raw', pointer: pointer('raw'), requested_bytes: 20, captured_bytes: 16, truncated: true, value_encoding: 'base64', value: rawHeaders.toString('base64') }),
        outcome({ capture_id: 'path.utf16', codec: 'utf16', retention: 'sha256', pointer: pointer('sha256'), requested_bytes: 8, captured_bytes: 8, value_encoding: 'sha256', value: 'c'.repeat(64) }),
      ],
    }, 1002),
    v2Event(config, {
      event: 'leave', hook_id: 'http.send', call_id: 1, sequence: 2, thread_id: 7,
      captures: [
        outcome({ capture_id: 'body.bytes', codec: 'bytes', retention: 'raw', pointer: pointer('raw', '0x502000'), requested_bytes: 3, captured_bytes: 3, value_encoding: 'base64', value: Buffer.from([1, 2, 3]).toString('base64') }),
        outcome({ capture_id: 'return.ok', codec: 'bool', retention: 'raw', captured_bytes: 1, value_encoding: 'boolean', value: true }),
      ],
    }, 1003),
    v2Event(config, {
      event: 'complete', hooks_ready: 1, hooks_detached: 1, events_emitted: 2,
      capture_attempts: 6, capture_failures: 0, capture_truncations: 1,
      captured_payload_bytes: 32, truncated: false,
    }, 1004),
  ].join('\n')
}

test('v2 plan maps every allowed target shape to exact official Frida selector flags', () => {
  const cases = [
    [{ mode: 'local-spawn' }, ['-f', ARTIFACT]],
    [{ mode: 'local-pid', pid: 1234 }, ['-p', '1234']],
    [{ mode: 'local-name', name: 'demo.exe' }, ['-n', 'demo.exe']],
    [{ mode: 'usb-pid', pid: 1234 }, ['-U', '-p', '1234']],
    [{ mode: 'usb-name', name: 'Demo' }, ['-U', '-n', 'Demo']],
    [{ mode: 'usb-app-identifier', app_identifier: 'com.example.demo' }, ['-U', '-N', 'com.example.demo']],
    [{ mode: 'device-pid', device_id: 'device-01', pid: 1234 }, ['-D', 'device-01', '-p', '1234']],
    [{ mode: 'device-name', device_id: 'device-01', name: 'Demo' }, ['-D', 'device-01', '-n', 'Demo']],
    [{ mode: 'device-app-identifier', device_id: 'device-01', app_identifier: 'com.example.demo' }, ['-D', 'device-01', '-N', 'com.example.demo']],
  ]

  for (const [target, selector] of cases) {
    const tracePlan = plan(target)
    const args = buildFridaTracePlanArguments({
      plan: tracePlan,
      artifactPath: ARTIFACT,
      artifactSha256: ARTIFACT_SHA256,
      agentPath: AGENT,
      frameNonce: NONCE,
    })
    assert.deepEqual(args.slice(-selector.length), selector)
    assert.deepEqual(args.slice(0, 3), ['-q', '--no-auto-reload', '--exit-on-error'])
    assert.equal(args.filter((value) => value === '--kill-on-exit').length, target.mode === 'local-spawn' ? 1 : 0)
    assert.equal(args.includes('-R'), false)
    assert.equal(args.includes('-H'), false)
    assert.equal(args.includes('-e'), false)
    assert.equal(args.filter((value) => value === '-l').length, 1)
    assert.equal(args[args.indexOf('-l') + 1], AGENT)
    const config = parameters(args)
    assert.equal(config.profileId, FRIDA_V2_PROFILE_ID)
    assert.equal(config.planSha256, digestFridaTracePlan(tracePlan))
    assert.equal(config.targetMode, target.mode)
    assert.equal(config.artifactSha256, ARTIFACT_SHA256)
    assert.deepEqual(config.hooks.map((hook) => hook[0]), ['decoder.parse', 'crypto.verify'])
  }
})

test('v2 plan validation rejects widening, malformed selectors, duplicate hooks, and excess work', () => {
  const valid = plan()
  assert.equal(assertValidFridaTracePlan(valid), valid)
  const invalid = [
    { ...plan(), raw_argv: ['-H', 'host'] },
    { ...plan(), script: 'caller.js' },
    { ...plan(), eval: 'send(1)' },
    { ...plan(), token: 'secret' },
    plan({ mode: 'remote-host', host: '127.0.0.1' }),
    plan({ mode: 'local-name', name: '-H' }),
    plan({ mode: 'device-pid', device_id: '-R', pid: 1 }),
    plan({ mode: 'usb-pid', pid: 0 }),
    { ...plan(), hooks: [plan().hooks[0], plan().hooks[0]] },
    { ...plan(), hooks: [{ ...plan().hooks[0], hook_id: 'one' }, { ...plan().hooks[0], hook_id: 'two' }] },
    { ...plan(), hooks: Array.from({ length: 257 }, (_, index) => ({
      hook_id: `hook.${index}`,
      resolver: { kind: 'export', module_name: '<main>', export_name: `symbol_${index}` },
      capture: { arguments: [], return_value: null },
    })) },
    { ...plan(), limits: { ...plan().limits, duration_seconds: 301 } },
    plan({ mode: 'local-spawn' }, { kind: 'shared-library' }),
    (() => {
      const value = capturePlan()
      value.hooks[0].capture.arguments[0].phase = 'after-return'
      return value
    })(),
  ]
  for (const value of invalid) assert.throws(() => assertValidFridaTracePlan(value), /plan|field|target|hook|limit|artifact|selector|identifier|duration|capture|phase/i)
})

test('v2 plan supports exact export, module-offset, absolute, and unambiguous module debug resolvers', () => {
  const resolvers = [
    [{ kind: 'export', module_name: '<main>', export_name: 'send_request' }, ['e', '<main>', 'send_request']],
    [{ kind: 'module-offset', module_name: '<main>', offset: '0x1000' }, ['o', '<main>', '0x1000']],
    [{ kind: 'absolute', address: '0x401000' }, ['a', '0x401000']],
    [{ kind: 'debug-symbol', module_name: '<main>', symbol_name: 'send_request' }, ['d', '<main>', 'send_request']],
  ]
  for (const [resolver, wire] of resolvers) {
    const value = plan()
    value.hooks = [{ hook_id: 'hook.one', resolver, capture: { arguments: [], return_value: null } }]
    assert.equal(assertValidFridaTracePlan(value), value)
    const args = buildFridaTracePlanArguments({
      plan: value, artifactPath: ARTIFACT, artifactSha256: ARTIFACT_SHA256,
      agentPath: AGENT, frameNonce: NONCE,
    })
    assert.deepEqual(parameters(args).hooks[0][1], wire)
  }
  for (const address of ['0x0', `0x1${'0'.repeat(16)}`]) {
    const value = plan()
    value.hooks = [{
      hook_id: 'hook.one', resolver: { kind: 'absolute', address },
      capture: { arguments: [], return_value: null },
    }]
    assert.throws(() => assertValidFridaTracePlan(value), /absolute|address|resolver/i)
  }
})

test('v2 debug-symbol hook readiness remains bound to the requested module', () => {
  const tracePlan = plan()
  tracePlan.hooks = [{
    hook_id: 'debug.parse',
    resolver: { kind: 'debug-symbol', module_name: 'expected.dll', symbol_name: 'parse_packet' },
    capture: { arguments: [], return_value: null },
  }]
  const args = buildFridaTracePlanArguments({
    plan: tracePlan,
    artifactPath: ARTIFACT,
    artifactSha256: ARTIFACT_SHA256,
    agentPath: AGENT,
    frameNonce: NONCE,
  })
  const config = parameters(args)
  const outputForModule = (moduleName) => [
    v2Event(config, { event: 'session-ready', hooks_expected: 1 }, 1000),
    v2Event(config, {
      event: 'hook-ready', hook_id: 'debug.parse', resolver_kind: 'debug-symbol',
      module_name: moduleName, symbol_name: 'parse_packet',
      module_relative_offset: '0x1000', resolved_address: '0x401000',
    }, 1001),
    v2Event(config, {
      event: 'complete', hooks_ready: 1, hooks_detached: 1,
      events_emitted: 0, capture_attempts: 0, capture_failures: 0,
      capture_truncations: 0, captured_payload_bytes: 0, truncated: false,
    }, 1002),
  ].join('\n')

  assert.equal(parseFridaTracePlanOutput(outputForModule('expected.dll'), {
    plan: tracePlan,
    artifactSha256: ARTIFACT_SHA256,
    expectedFrameNonce: NONCE,
    maxBytes: 16 * 1024,
  }).hooks_ready, 1)
  assert.throws(() => parseFridaTracePlanOutput(outputForModule('wrong.dll'), {
    plan: tracePlan,
    artifactSha256: ARTIFACT_SHA256,
    expectedFrameNonce: NONCE,
    maxBytes: 16 * 1024,
  }), /hook-ready|module|match/i)
})

test('v2 compact wire format admits 256 short hooks within the native command-line budget', () => {
  const value = plan()
  value.hooks = Array.from({ length: 256 }, (_, index) => ({
    hook_id: `h${index}`,
    resolver: { kind: 'export', module_name: 'm', export_name: `s${index}` },
    capture: { arguments: [], return_value: null },
  }))
  const args = buildFridaTracePlanArguments({
    plan: value, artifactPath: ARTIFACT, artifactSha256: ARTIFACT_SHA256,
    agentPath: AGENT, frameNonce: NONCE,
  })
  assert.equal(parameters(args).hooks.length, 256)
  assert.ok(args[args.indexOf('-P') + 1].length < 20_000)
})

test('v2 typed captures retain bounded raw values only as base64 and reconcile all counters', () => {
  const tracePlan = capturePlan()
  const args = buildFridaTracePlanArguments({
    plan: tracePlan, artifactPath: ARTIFACT, artifactSha256: ARTIFACT_SHA256,
    agentPath: AGENT, frameNonce: NONCE,
  })
  const output = capturedOutput(args)
  const bodyWire = parameters(args).hooks[0][2].find(([captureId]) => captureId === 'body.bytes')
  assert.equal(bodyWire.at(-1), 'l')
  assert.doesNotMatch(output, /Authorization: B/)
  const parsed = parseFridaTracePlanOutput(output, {
    plan: tracePlan, artifactSha256: ARTIFACT_SHA256,
    expectedFrameNonce: NONCE, maxBytes: 64 * 1024,
  })
  assert.equal(parsed.capture_attempts, 6)
  assert.equal(parsed.capture_failures, 0)
  assert.equal(parsed.capture_truncations, 1)
  assert.equal(parsed.captured_payload_bytes, 32)
  const captures = parsed.events.find(({ event }) => event === 'enter').captures
  assert.equal(captures.find(({ capture_id: id }) => id === 'headers.utf8').value_encoding, 'base64')
  assert.equal(captures.find(({ capture_id: id }) => id === 'path.utf16').value_encoding, 'sha256')
  assert.equal(captures.find(({ capture_id: id }) => id === 'context.ptr').pointer.address, null)
  const leaveCaptures = parsed.events.find(({ event }) => event === 'leave').captures
  assert.equal(leaveCaptures[0].capture_id, 'body.bytes')

  for (const changed of [
    output.replace('QXV0aG9yaXphdGlvbjogQg==', 'not-base64'),
    output.replace('"capture_attempts":6', '"capture_attempts":5'),
    output.replace('"captured_payload_bytes":32', '"captured_payload_bytes":31'),
    output.replace('"address":null,"module_name":"demo.exe"', '"address":"0x501000","module_name":"demo.exe"'),
    output.replace('"capture_id":"return.ok"', '"capture_id":"other.return"'),
    output.replace('"value_encoding":"number","value":200', '"value_encoding":"number","value":4294967296'),
    output.replace('"truncated":true,"truncation_reason":"DECLARED_MAX"', '"truncated":true,"truncation_reason":null'),
  ]) {
    assert.throws(() => parseFridaTracePlanOutput(changed, {
      plan: tracePlan, artifactSha256: ARTIFACT_SHA256,
      expectedFrameNonce: NONCE, maxBytes: 64 * 1024,
    }), /capture|base64|payload|complete|retention|descriptor/i)
  }
})

test('v2 framed output binds all hook frames, call pairs, hashes, and lifecycle order', () => {
  const tracePlan = plan()
  const args = buildFridaTracePlanArguments({
    plan: tracePlan, artifactPath: ARTIFACT, artifactSha256: ARTIFACT_SHA256,
    agentPath: AGENT, frameNonce: NONCE,
  })
  const parsed = parseFridaTracePlanOutput(successfulOutput(args), {
    plan: tracePlan,
    artifactSha256: ARTIFACT_SHA256,
    expectedFrameNonce: NONCE,
    maxBytes: 16 * 1024,
  })
  assert.equal(parsed.profile_id, FRIDA_V2_PROFILE_ID)
  assert.equal(parsed.session_ready, true)
  assert.equal(parsed.hooks_ready, 2)
  assert.equal(parsed.trace_events, 2)
  assert.equal(parsed.complete, true)
  assert.equal(parsed.ignored_lines, 1)
  assert.deepEqual(parsed.events.map(({ event }) => event), [
    'session-ready', 'hook-ready', 'hook-ready', 'enter', 'leave', 'complete',
  ])

  const config = parameters(args)
  const badOutputs = [
    successfulOutput(args).replace('crypto.verify', 'unknown.hook'),
    successfulOutput(args).replace(config.planSha256, 'c'.repeat(64)),
    successfulOutput(args).replace(config.artifactSha256, 'd'.repeat(64)),
    successfulOutput(args).replace('"call_id":1,"sequence":2', '"call_id":2,"sequence":2'),
    successfulOutput(args).replace('"hooks_detached":2', '"hooks_detached":1'),
    successfulOutput(args).replace('"hook_id":"decoder.parse","resolver_kind":"export"', '"hook_id":"crypto.verify","resolver_kind":"export"'),
  ]
  for (const output of badOutputs) {
    assert.throws(() => parseFridaTracePlanOutput(output, {
      plan: tracePlan, artifactSha256: ARTIFACT_SHA256,
      expectedFrameNonce: NONCE, maxBytes: 16 * 1024,
    }), /frida|hook|digest|hash|call|lifecycle|detach|match|order/i)
  }
})

test('v2 runner refuses altered argv and spawns with a sanitized environment and no shell', async () => {
  const tracePlan = plan({ mode: 'usb-app-identifier', app_identifier: 'com.example.demo' })
  const args = buildFridaTracePlanArguments({
    plan: tracePlan, artifactPath: ARTIFACT, artifactSha256: ARTIFACT_SHA256,
    agentPath: AGENT, frameNonce: NONCE,
  })
  const previous = process.env.LAST_APERTURE_TEST_SECRET
  process.env.LAST_APERTURE_TEST_SECRET = 'must-not-reach-frida'
  let invocation
  try {
    const result = await runFridaTracePlan({
      fridaPath: FRIDA, args, plan: tracePlan, artifactPath: ARTIFACT,
      artifactSha256: ARTIFACT_SHA256, cwd: CWD, timeoutMs: 8_000,
      maxOutputBytes: 16 * 1024,
      spawnImpl: async (file, childArgs, options) => {
        invocation = { file, childArgs, options }
        return { code: 0, stdout: successfulOutput(args), stderr: '', terminationConfirmed: true }
      },
    })
    assert.equal(result.complete, true)
  } finally {
    if (previous === undefined) delete process.env.LAST_APERTURE_TEST_SECRET
    else process.env.LAST_APERTURE_TEST_SECRET = previous
  }
  assert.equal(invocation.file, FRIDA)
  assert.deepEqual(invocation.childArgs, args)
  assert.equal(invocation.options.shell, false)
  assert.equal(invocation.options.env.LAST_APERTURE_TEST_SECRET, undefined)

  let spawns = 0
  for (const altered of [
    [...args, '-H', 'host'],
    args.with(args.indexOf('-U'), '-R'),
    args.with(args.indexOf('-l') + 1, resolve('caller-agent.js')),
    args.with(args.indexOf('-P') + 1, JSON.stringify({ ...parameters(args), rawArgv: ['-e', 'send(1)'] })),
  ]) {
    await assert.rejects(runFridaTracePlan({
      fridaPath: FRIDA, args: altered, plan: tracePlan, artifactPath: ARTIFACT,
      artifactSha256: ARTIFACT_SHA256, cwd: CWD, timeoutMs: 8_000,
      maxOutputBytes: 16 * 1024,
      spawnImpl: async () => { spawns += 1 },
    }), /exact|argument|profile|agent|widen|field/i)
  }
  assert.equal(spawns, 0)
})

test('v2 controller emits succeeded local-spawn evidence and partial attach evidence bound to a local copy', async () => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-frida-v2-'))
  const labRoot = join(root, 'lab')
  await mkdir(join(labRoot, 'bin'), { recursive: true })
  const artifactPath = join(labRoot, 'bin', 'demo.exe')
  const fridaPath = join(root, 'frida.exe')
  await writeFile(artifactPath, 'fixed artifact bytes', 'utf8')
  await writeFile(fridaPath, 'fixed Frida bytes', 'utf8')
  const artifactSha256 = createHash('sha256').update('fixed artifact bytes').digest('hex')
  const runFrida = async (options) => {
    const parsed = parseFridaTracePlanOutput(successfulOutput(options.args), {
      plan: options.plan,
      artifactSha256: options.artifactSha256,
      expectedFrameNonce: parameters(options.args).frameNonce,
      maxBytes: options.maxOutputBytes,
    })
    return { ...parsed, process_exit_code: 0, stderr_bytes: 0, termination_confirmed: true }
  }
  const reverseSchema = JSON.parse(await readFile('schemas/reverse-evidence.schema.json', 'utf8'))
  const validateEvidence = new Ajv2020({ allErrors: true, strict: false }).compile(reverseSchema)
  try {
    for (const [target, expectedStatus, execution] of [
      [{ mode: 'local-spawn' }, 'SUCCEEDED', 'LOCAL_LAB_SPAWN'],
      [{ mode: 'local-pid', pid: 1234 }, 'PARTIAL', 'LOCAL_PROCESS_ATTACH'],
      [{ mode: 'usb-app-identifier', app_identifier: 'com.example.demo' }, 'PARTIAL', 'USB_DEVICE_ATTACH'],
      [{ mode: 'device-name', device_id: 'device-01', name: 'Demo' }, 'PARTIAL', 'DEVICE_ID_ATTACH'],
    ]) {
      const tracePlan = plan(target)
      tracePlan.artifact.lab_root = labRoot
      const planPath = join(root, `${target.mode}.json`)
      const outPath = join(root, `${target.mode}-evidence`)
      await writeFile(planPath, JSON.stringify(tracePlan), 'utf8')
      const result = await traceFridaPlanFile({
        planPath, fridaPath, outPath,
        now: () => new Date('2026-09-11T12:00:00.000Z'),
        runFrida,
      })
      const evidence = JSON.parse(await readFile(join(outPath, 'evidence.json'), 'utf8'))
      assert.equal(result.status, expectedStatus)
      assert.equal(evidence.profile_id, FRIDA_V2_PROFILE_ID)
      assert.equal(evidence.target_execution, execution)
      assert.equal(evidence.artifact.sha256, artifactSha256)
      assert.equal(evidence.observations.length, 6)
      assert.equal(evidence.cleanup.verified, true)
      assert.equal(validateEvidence(evidence), true, JSON.stringify(validateEvidence.errors))
      assert.equal(
        evidence.gaps.some(({ code }) => code === 'RUNTIME_ARTIFACT_IDENTITY_UNVERIFIED'),
        target.mode !== 'local-spawn',
      )
    }

    const typedPlan = capturePlan()
    typedPlan.artifact.lab_root = labRoot
    const typedPlanPath = join(root, 'typed-captures.json')
    const typedOutPath = join(root, 'typed-captures-evidence')
    await writeFile(typedPlanPath, JSON.stringify(typedPlan), 'utf8')
    const typedResult = await traceFridaPlanFile({
      planPath: typedPlanPath,
      fridaPath,
      outPath: typedOutPath,
      now: () => new Date('2026-09-11T12:00:00.000Z'),
      runFrida: async (options) => {
        const parsed = parseFridaTracePlanOutput(capturedOutput(options.args), {
          plan: options.plan,
          artifactSha256: options.artifactSha256,
          expectedFrameNonce: parameters(options.args).frameNonce,
          maxBytes: options.maxOutputBytes,
        })
        return { ...parsed, process_exit_code: 0, stderr_bytes: 0, termination_confirmed: true }
      },
    })
    const typedEvidence = JSON.parse(await readFile(join(typedOutPath, 'evidence.json'), 'utf8'))
    assert.equal(typedResult.status, 'PARTIAL')
    assert.equal(validateEvidence(typedEvidence), true, JSON.stringify(validateEvidence.errors))
    assert.ok(typedEvidence.gaps.some(({ code }) => code === 'DECLARED_CAPTURE_SCOPE_ONLY'))
    assert.ok(typedEvidence.gaps.some(({ code }) => code === 'FRIDA_CAPTURE_TRUNCATED'))
    const rawHeader = typedEvidence.observations
      .find(({ event }) => event === 'enter').captures
      .find(({ capture_id: id }) => id === 'headers.utf8')
    assert.equal(rawHeader.value, Buffer.from('Authorization: B').toString('base64'))
    assert.doesNotMatch(JSON.stringify(typedEvidence), /Authorization: B/)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('published v2 plan schema and bundled agent match the strict runtime profile', async () => {
  const schema = JSON.parse(await readFile('schemas/frida-trace-plan.schema.json', 'utf8'))
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(schema)
  assert.equal(validate(plan()), true, JSON.stringify(validate.errors))
  assert.equal(validate({ ...plan(), raw_argv: [] }), false)
  assert.equal(validate(plan({ mode: 'remote-host', host: 'example.test' })), false)

  const source = await readFile(AGENT, 'utf8')
  assert.match(source, /configuration\.hooks/)
  assert.match(source, /Interceptor\.attach/)
  assert.match(source, /hookId/)
  assert.match(source, /hooksDetached/)
  assert.doesNotMatch(source, /\bargs\s*\[/)
  assert.doesNotMatch(source, /\bretval\b/)
  assert.match(source, /readVolatile/)
  assert.match(source, /Checksum\.compute/)
  assert.match(source, /arrayBufferToBase64/)
  assert.doesNotMatch(source, /\.write(?:U|S|Pointer|ByteArray|Utf|CString)/)
  assert.doesNotThrow(() => new Function(source))
})
