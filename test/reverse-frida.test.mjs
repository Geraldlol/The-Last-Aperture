import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { resolve } from 'node:path'

import {
  FRIDA_PROFILE_ID,
  buildFridaArguments,
  parseFridaOutput,
  runFridaTrace,
} from '../scripts/lib/reverse-frida.mjs'

const BINARY = resolve('test/fixtures/reverse/demo executable.exe')
const AGENT = resolve('scripts/frida/native-call-trace-v1.js')
const FRIDA = resolve('tools/frida.exe')
const CWD = resolve('test/fixtures/reverse/lab')
const PREFIX = '[last-aperture:frida] '
const FRAME_NONCE = 'a'.repeat(64)

function event(value, { frameNonce = FRAME_NONCE } = {}) {
  return `${PREFIX}${JSON.stringify({
    schema_version: '1.0.0',
    profile_id: FRIDA_PROFILE_ID,
    frame_nonce: frameNonce,
    observed_at_ms: 1000,
    ...value,
  })}`
}

function successfulOutput() {
  return [
    'untrusted target output that is ignored',
    event({
      event: 'ready',
      module_name: 'demo.exe',
      symbol_name: 'parse_packet',
      module_relative_offset: '0x1000',
      observed_at_ms: 1000,
    }),
    event({ event: 'enter', sequence: 1, thread_id: 7, observed_at_ms: 1001 }),
    event({ event: 'leave', sequence: 2, thread_id: 7, observed_at_ms: 1002 }),
    event({ event: 'complete', events_emitted: 2, truncated: false, observed_at_ms: 1003 }),
  ].join('\n')
}

test('buildFridaArguments produces one exact local-spawn command with a fixed agent profile', () => {
  const args = buildFridaArguments({
    binaryPath: BINARY,
    agentPath: AGENT,
    moduleName: 'demo.exe',
    symbolName: 'parse_packet',
    durationSeconds: 5,
    maxEvents: 20,
    frameNonce: FRAME_NONCE,
  })

  assert.deepEqual(args, [
    '-q',
    '--no-auto-reload',
    '--exit-on-error',
    '--kill-on-exit',
    '-t', '6',
    '-P', JSON.stringify({
      profileId: FRIDA_PROFILE_ID,
      moduleName: 'demo.exe',
      symbolName: 'parse_packet',
      durationSeconds: 5,
      maxEvents: 20,
      frameNonce: FRAME_NONCE,
    }),
    '-l', AGENT,
    '-f', BINARY,
  ])
  assert.equal(FRIDA_PROFILE_ID, 'native-call-trace-v1')
  for (const forbidden of [
    '-U', '--usb', '-R', '--remote', '-H', '--host', '-D', '--device',
    '-p', '--attach-pid', '-n', '--attach-name', '-N', '--attach-identifier',
    '-F', '--attach-frontmost', '-W', '--await', '-e', '--eval', '-c', '--codeshare',
    '-O', '--options-file', '--aux', '--eternalize', '--pause', '--stdio',
  ]) assert.equal(args.includes(forbidden), false, `${forbidden} must not be emitted`)
})

test('argument construction rejects ambiguous paths, selectors, and unbounded work', () => {
  const valid = {
    binaryPath: BINARY,
    agentPath: AGENT,
    moduleName: 'demo.exe',
    symbolName: 'parse_packet',
    durationSeconds: 5,
    maxEvents: 20,
    frameNonce: FRAME_NONCE,
  }
  for (const changed of [
    { binaryPath: 'relative.exe' },
    { binaryPath: '\\\\server\\share\\target.exe' },
    { agentPath: 'agent.js' },
    { agentPath: resolve('scripts/frida/caller-agent.txt') },
    { moduleName: '' },
    { moduleName: 'bad\nmodule' },
    { moduleName: 'bad\u202emodule' },
    { symbolName: '' },
    { symbolName: 'x'.repeat(513) },
    { symbolName: 'parse\u2066packet' },
    { durationSeconds: 0 },
    { durationSeconds: 301 },
    { maxEvents: 0 },
    { maxEvents: 10001 },
    { frameNonce: 'short' },
    { frameNonce: 'A'.repeat(64) },
  ]) {
    assert.throws(() => buildFridaArguments({ ...valid, ...changed }), /frida|absolute|local|module|symbol|duration|events|agent/i)
  }
})

test('parseFridaOutput accepts only the fixed framed event protocol', () => {
  const parsed = parseFridaOutput(successfulOutput(), {
    maxEvents: 20,
    maxBytes: 16 * 1024,
    expectedFrameNonce: FRAME_NONCE,
  })
  assert.equal(parsed.profile_id, FRIDA_PROFILE_ID)
  assert.equal(parsed.ready, true)
  assert.equal(parsed.complete, true)
  assert.equal(parsed.trace_events, 2)
  assert.equal(parsed.truncated, false)
  assert.equal(parsed.ignored_lines, 1)
  assert.deepEqual(parsed.observation_window_ms, { start: 1000, end: 1003 })
  assert.deepEqual(parsed.events.map(({ event: kind }) => kind), [
    'ready', 'enter', 'leave', 'complete',
  ])
})

test('parseFridaOutput rejects malformed, widened, spoofed, inconsistent, and oversized output', () => {
  const options = { maxEvents: 2, maxBytes: 4096, expectedFrameNonce: FRAME_NONCE }
  const cases = [
    `${PREFIX}{not-json}`,
    `untrusted target output with escape \u001b[31m`,
    event({ event: 'ready', module_name: 'demo.exe', symbol_name: 'x', module_relative_offset: '0x1', extra: true }),
    event({ event: 'ready', module_name: 'demo.exe', symbol_name: 'x', module_relative_offset: '0x1' }, { frameNonce: 'b'.repeat(64) }),
    event({ event: 'ready', module_name: 'demo\u202eexe', symbol_name: 'x', module_relative_offset: '0x1' }),
    event({ event: 'enter', sequence: 1, thread_id: 1, args: ['secret'] }),
    [
      event({ event: 'ready', module_name: 'demo.exe', symbol_name: 'x', module_relative_offset: '0x1' }),
      event({ event: 'enter', sequence: 2, thread_id: 1 }),
      event({ event: 'complete', events_emitted: 1, truncated: false }),
    ].join('\n'),
    [
      event({ event: 'ready', module_name: 'demo.exe', symbol_name: 'x', module_relative_offset: '0x1', observed_at_ms: 1001 }),
      event({ event: 'enter', sequence: 1, thread_id: 1, observed_at_ms: 1000 }),
      event({ event: 'complete', events_emitted: 1, truncated: false, observed_at_ms: 1002 }),
    ].join('\n'),
    [
      event({ event: 'ready', module_name: 'demo.exe', symbol_name: 'x', module_relative_offset: '0x1' }),
      event({ event: 'enter', sequence: 1, thread_id: 1 }),
      event({ event: 'leave', sequence: 2, thread_id: 1 }),
      event({ event: 'enter', sequence: 3, thread_id: 1 }),
      event({ event: 'complete', events_emitted: 3, truncated: false }),
    ].join('\n'),
    [
      event({ event: 'ready', module_name: 'demo.exe', symbol_name: 'x', module_relative_offset: '0x1' }),
      event({ event: 'complete', events_emitted: 1, truncated: false }),
    ].join('\n'),
  ]
  for (const value of cases) assert.throws(() => parseFridaOutput(value, options), /frida|event|sequence|field|complete|limit/i)
  assert.throws(
    () => parseFridaOutput(successfulOutput(), { maxEvents: 2, maxBytes: 4096 }),
    /nonce/i,
  )
  assert.throws(
    () => parseFridaOutput('x'.repeat(4097), options),
    /byte limit/i,
  )
})

test('runFridaTrace executes the exact validated vector without a shell or ambient secrets', async () => {
  const args = buildFridaArguments({
    binaryPath: BINARY,
    agentPath: AGENT,
    moduleName: 'demo.exe',
    symbolName: 'parse_packet',
    durationSeconds: 5,
    maxEvents: 20,
    frameNonce: FRAME_NONCE,
  })
  const previous = process.env.LAST_APERTURE_TEST_SECRET
  process.env.LAST_APERTURE_TEST_SECRET = 'must-not-reach-frida'
  let invocation
  try {
    const result = await runFridaTrace({
      fridaPath: FRIDA,
      args,
      cwd: CWD,
      timeoutMs: 8000,
      maxOutputBytes: 16 * 1024,
      spawnImpl: async (file, childArgs, options) => {
        invocation = { file, childArgs, options }
        return {
          code: 0,
          stdout: successfulOutput(),
          stderr: '',
          timedOut: false,
          terminationConfirmed: true,
        }
      },
    })
    assert.equal(result.complete, true)
    assert.equal(result.trace_events, 2)
  } finally {
    if (previous === undefined) delete process.env.LAST_APERTURE_TEST_SECRET
    else process.env.LAST_APERTURE_TEST_SECRET = previous
  }

  assert.equal(invocation.file, FRIDA)
  assert.deepEqual(invocation.childArgs, args)
  assert.equal(invocation.options.shell, false)
  assert.equal(invocation.options.windowsHide, true)
  assert.equal(invocation.options.timeout, 8000)
  assert.equal(invocation.options.maxBuffer, 16 * 1024)
  assert.equal(invocation.options.env.LAST_APERTURE_TEST_SECRET, undefined)
  for (const ambientProfile of ['APPDATA', 'HOME', 'LOCALAPPDATA', 'USERPROFILE']) {
    assert.equal(invocation.options.env[ambientProfile], undefined)
  }
  assert.equal(Object.keys(invocation.options.env).some((key) => /TOKEN|SECRET|PASSWORD|KEY/i.test(key)), false)
})

test('runFridaTrace refuses raw or widened argv before spawning', async () => {
  const base = buildFridaArguments({
    binaryPath: BINARY,
    agentPath: AGENT,
    moduleName: 'demo.exe',
    symbolName: 'parse_packet',
    durationSeconds: 5,
    maxEvents: 20,
    frameNonce: FRAME_NONCE,
  })
  let spawns = 0
  const spawnImpl = async () => {
    spawns += 1
    return {
      code: 0,
      stdout: successfulOutput(),
      stderr: '',
      terminationConfirmed: true,
    }
  }
  for (const args of [
    [...base, '--', '--target-argument'],
    [...base, '-U'],
    base.map((value) => value === '-f' ? '-p' : value),
    base.map((value) => value === AGENT ? resolve('caller-script.js') : value),
    base.with(7, JSON.stringify({ profileId: FRIDA_PROFILE_ID, moduleName: 'x', symbolName: 'y', durationSeconds: 5, maxEvents: 20, frameNonce: FRAME_NONCE, extra: true })),
  ]) {
    await assert.rejects(
      runFridaTrace({ fridaPath: FRIDA, args, cwd: CWD, timeoutMs: 8000, maxOutputBytes: 16384, spawnImpl }),
      /fixed|argument|profile|spawn|agent/i,
    )
  }
  assert.equal(spawns, 0)
})

test('runFridaTrace rejects unsafe runner configuration and surfaces timeout or process failure', async () => {
  const args = buildFridaArguments({
    binaryPath: BINARY,
    agentPath: AGENT,
    moduleName: 'demo.exe',
    symbolName: 'parse_packet',
    durationSeconds: 5,
    maxEvents: 20,
    frameNonce: FRAME_NONCE,
  })
  const base = { fridaPath: FRIDA, args, cwd: CWD, timeoutMs: 8000, maxOutputBytes: 16384 }
  for (const changed of [
    { fridaPath: 'frida' },
    { fridaPath: resolve('tools/frida.cmd') },
    { cwd: 'relative-lab' },
    { timeoutMs: 0 },
    { timeoutMs: 400_000 },
    { maxOutputBytes: 0 },
  ]) {
    await assert.rejects(runFridaTrace({ ...base, ...changed, spawnImpl: async () => { throw new Error('must not spawn') } }))
  }
  await assert.rejects(
    runFridaTrace({ ...base, spawnImpl: async () => ({ code: 124, stdout: '', stderr: '', timedOut: true }) }),
    /timed out/i,
  )
  await assert.rejects(
    runFridaTrace({ ...base, spawnImpl: async () => ({ code: 3, stdout: '', stderr: 'failure', timedOut: false, terminationConfirmed: true }) }),
    /exited with code 3/i,
  )
  await assert.rejects(
    runFridaTrace({
      ...base,
      spawnImpl: async () => ({
        code: 0,
        stdout: successfulOutput(),
        stderr: '',
        timedOut: false,
        terminationConfirmed: false,
      }),
    }),
    (error) => error?.code === 'FRIDA_TERMINATION_UNCONFIRMED',
  )
})

test('runFridaTrace enforces one exact combined stdout and stderr budget', async () => {
  const args = buildFridaArguments({
    binaryPath: BINARY,
    agentPath: AGENT,
    moduleName: 'demo.exe',
    symbolName: 'parse_packet',
    durationSeconds: 5,
    maxEvents: 20,
    frameNonce: FRAME_NONCE,
  })
  await assert.rejects(
    runFridaTrace({
      fridaPath: FRIDA,
      args,
      cwd: CWD,
      timeoutMs: 8000,
      maxOutputBytes: 4096,
      spawnImpl: async () => ({
        code: 0,
        stdout: Buffer.alloc(3000),
        stderr: Buffer.alloc(1097),
        timedOut: false,
        terminationConfirmed: true,
      }),
    }),
    (error) => error?.code === 'FRIDA_OUTPUT_TOO_LARGE' && /combined/i.test(error.message),
  )
})

test('runFridaTrace binds the ready frame to the exact validated module and symbol', async () => {
  const args = buildFridaArguments({
    binaryPath: BINARY,
    agentPath: AGENT,
    moduleName: 'demo.exe',
    symbolName: 'parse_packet',
    durationSeconds: 5,
    maxEvents: 20,
    frameNonce: FRAME_NONCE,
  })
  const base = {
    fridaPath: FRIDA,
    args,
    cwd: CWD,
    timeoutMs: 8000,
    maxOutputBytes: 16384,
  }
  for (const changed of [
    { module_name: 'other.exe', symbol_name: 'parse_packet' },
    { module_name: 'demo.exe', symbol_name: 'other_symbol' },
  ]) {
    const output = [
      event({
        event: 'ready',
        ...changed,
        module_relative_offset: '0x1000',
      }),
      event({ event: 'complete', events_emitted: 0, truncated: false, observed_at_ms: 1001 }),
    ].join('\n')
    await assert.rejects(
      runFridaTrace({
        ...base,
        spawnImpl: async () => ({
          code: 0,
          stdout: output,
          stderr: '',
          timedOut: false,
          terminationConfirmed: true,
        }),
      }),
      /ready.*module|ready.*symbol|requested/i,
    )
  }
})

test('the bundled agent uses fixed parameters and emits bounded metadata without reading arguments or memory', async () => {
  const source = await readFile(AGENT, 'utf8')
  assert.match(source, /parameters/)
  assert.match(source, /rpc\.exports\s*=\s*\{/)
  assert.match(source, /init\(_stage, parametersValue\)/)
  assert.match(source, /loadConfiguration\(parametersValue\)/)
  assert.doesNotMatch(source, /loadConfiguration\(\)/)
  assert.match(source, /Process\.mainModule/)
  assert.match(source, /Process\.getModuleByName/)
  assert.match(source, /findExportByName/)
  assert.match(source, /Interceptor\.attach/)
  assert.match(source, /onEnter\s*\(\s*\)/)
  assert.match(source, /onLeave\s*\(\s*\)/)
  assert.match(source, /maxEvents/)
  assert.match(source, /durationSeconds/)
  assert.match(source, /frameNonce/)
  assert.match(source, /targetAddress\.sub\(selectedModule\.base\)/)
  assert.doesNotMatch(source, /\bargs\s*\[/)
  assert.doesNotMatch(source, /\bretval\b/)
  assert.doesNotMatch(source, /\bMemory\s*\./)
  assert.doesNotMatch(source, /\.read(?:U|S|Pointer|ByteArray|Utf|CString)/)
  assert.doesNotMatch(source, /\.write(?:U|S|Pointer|ByteArray|Utf|CString)/)
  assert.doesNotThrow(() => new Function(source))
})
