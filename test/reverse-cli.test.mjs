import assert from 'node:assert/strict'
import { test } from 'node:test'

import { runReverseCli } from '../scripts/reverse.mjs'

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

function operations(calls) {
  return {
    importBurpFile: async (options) => { calls.push(['burp', options]); return { status: 'SUCCEEDED', output_path: options.outPath, digest: 'e'.repeat(64), entries: 1 } },
    importHarFile: async (options) => { calls.push(['web', options]); return { status: 'SUCCEEDED', output_path: options.outPath, digest: 'a'.repeat(64), entries: 1 } },
    importLiveMetadata: async (options) => { calls.push(['live', options]); return { status: 'SUCCEEDED', output_path: options.outPath, captures: 2, entries: 2 } },
    buildProtocolContractFile: async (options) => { calls.push(['protocol', options]); return { status: 'SUCCEEDED', output_path: options.outPath, digest: 'b'.repeat(64), endpoints: 1 } },
    generateNativeConnectorPackage: async (options) => { calls.push(['generate', options]); return { status: 'SUCCEEDED', output_path: options.outPath, digest: 'c'.repeat(64), endpoints: 1 } },
    verifyGeneratedConnectorPackage: async (options) => { calls.push(['verify', options]); return { status: 'SUCCEEDED', output_path: options.packagePath, manifest_sha256: options.expectedManifestSha256 } },
    analyzeGhidraArtifact: async (options) => { calls.push(['ghidra', options]); return { status: 'SUCCEEDED', output_path: options.outPath, evidence_path: `${options.outPath}/evidence.json` } },
    traceFridaArtifact: async (options) => { calls.push(['frida', options]); return { status: 'SUCCEEDED', output_path: options.outPath, evidence_path: `${options.outPath}/evidence.json` } },
    traceFridaPlanFile: async (options) => { calls.push(['frida-plan', options]); return { status: 'PARTIAL', output_path: options.outPath, evidence_path: `${options.outPath}/evidence.json` } },
  }
}

test('help describes every narrow reverse route', async () => {
  const io = capture()
  assert.equal(await runReverseCli(['--help'], { ...operations([]), ...io }), 0)
  assert.match(io.stdoutText(), /web import-har/)
  assert.match(io.stdoutText(), /web import-burp/)
  assert.match(io.stdoutText(), /web import-live-metadata/)
  assert.match(io.stdoutText(), /--path-prefix/)
  assert.match(io.stdoutText(), /protocol build/)
  assert.match(io.stdoutText(), /protocol generate/)
  assert.match(io.stdoutText(), /protocol verify/)
  assert.match(io.stdoutText(), /ghidra analyze/)
  assert.match(io.stdoutText(), /frida trace/)
  assert.match(io.stdoutText(), /frida trace-plan/)
})

test('CLI maps the fixed live metadata adapter without arbitrary arguments', async () => {
  const calls = []
  const io = capture()
  assert.equal(await runReverseCli([
    'web', 'import-live-metadata',
    '--recon-bundle', 'C:\\staged\\recon',
    '--auth-scope', 'C:\\staged\\scope.json',
    '--auth-ledger', 'C:\\staged\\ledger',
    '--origin', 'https://target.example',
    '--path-prefix', '/app',
    '--path-literal', 'app',
    '--out', 'C:\\out\\live',
    '--json',
  ], { ...operations(calls), ...io }), 0)
  assert.deepEqual(calls, [['live', {
    reconBundle: 'C:\\staged\\recon',
    authScopePath: 'C:\\staged\\scope.json',
    authLedgerDirectory: 'C:\\staged\\ledger',
    targetOrigins: ['https://target.example'],
    targetPathPrefix: '/app',
    pathLiterals: ['app'],
    outPath: 'C:\\out\\live',
  }]])
})

test('CLI preserves repeatable origins and evidence inputs and emits JSON', async () => {
  const calls = []
  const io = capture()
  const ops = operations(calls)
  assert.equal(await runReverseCli([
    'web', 'import-har',
    '--har', 'C:\\lab\\session.har',
    '--origin', 'https://app.example',
    '--origin', 'https://api.example',
    '--path-prefix', '/app',
    '--path-literal', 'resources',
    '--path-literal', 'records',
    '--out', 'C:\\out\\web.json',
    '--json',
  ], { ...ops, ...io }), 0)
  assert.deepEqual(calls[0], ['web', {
    harPath: 'C:\\lab\\session.har',
    targetOrigins: ['https://app.example', 'https://api.example'],
    targetPathPrefix: '/app',
    pathLiterals: ['resources', 'records'],
    outPath: 'C:\\out\\web.json',
  }])
  assert.equal(JSON.parse(io.stdoutText()).status, 'SUCCEEDED')

  assert.equal(await runReverseCli([
    'web', 'import-burp',
    '--burp', 'C:\\lab\\items.xml',
    '--origin', 'https://app.example',
    '--path-prefix', '/app/',
    '--path-literal', 'records',
    '--out', 'C:\\out\\burp-web.json',
  ], { ...ops, ...capture() }), 0)
  assert.deepEqual(calls[1], ['burp', {
    burpPath: 'C:\\lab\\items.xml',
    targetOrigins: ['https://app.example'],
    targetPathPrefix: '/app/',
    pathLiterals: ['records'],
    outPath: 'C:\\out\\burp-web.json',
  }])

  assert.equal(await runReverseCli([
    'protocol', 'build',
    '--web-evidence', 'C:\\out\\web-one.json',
    '--web-evidence', 'C:\\out\\web-two.json',
    '--reverse-evidence', 'C:\\out\\native.json',
    '--out', 'C:\\out\\contract.json',
  ], { ...ops, ...capture() }), 0)
  assert.deepEqual(calls[2][1], {
    webEvidencePaths: ['C:\\out\\web-one.json', 'C:\\out\\web-two.json'],
    reverseEvidencePaths: ['C:\\out\\native.json'],
    outPath: 'C:\\out\\contract.json',
  })
  assert.equal(await runReverseCli([
    'protocol', 'generate',
    '--contract', 'C:\\out\\contract.json',
    '--out', 'C:\\out\\connector',
    '--name', '@example/portal-native',
  ], { ...ops, ...capture() }), 0)
  assert.deepEqual(calls[3], ['generate', {
    contractPath: 'C:\\out\\contract.json',
    outPath: 'C:\\out\\connector',
    packageName: '@example/portal-native',
  }])
  assert.equal(await runReverseCli([
    'protocol', 'verify',
    '--package', 'C:\\out\\connector',
    '--manifest-sha256', 'd'.repeat(64),
  ], { ...ops, ...capture() }), 0)
  assert.deepEqual(calls[4], ['verify', {
    packagePath: 'C:\\out\\connector',
    expectedManifestSha256: 'd'.repeat(64),
  }])
})

test('protocol build accepts reverse evidence without web evidence', async () => {
  const calls = []
  const io = capture()
  assert.equal(await runReverseCli([
    'protocol', 'build',
    '--reverse-evidence', 'C:\\out\\native.json',
    '--out', 'C:\\out\\contract.json',
  ], { ...operations(calls), ...io }), 0)
  assert.deepEqual(calls, [['protocol', {
    webEvidencePaths: [],
    reverseEvidencePaths: ['C:\\out\\native.json'],
    outPath: 'C:\\out\\contract.json',
  }]])
})

test('protocol build refuses an empty evidence set before invoking the controller', async () => {
  const calls = []
  const io = capture()
  assert.equal(await runReverseCli([
    'protocol', 'build',
    '--out', 'C:\\out\\contract.json',
    '--json',
  ], { ...operations(calls), ...io }), 1)
  assert.deepEqual(calls, [])
  const failure = JSON.parse(io.stderrText())
  assert.equal(failure.error.code, 'REVERSE_CLI_OPTION_REQUIRED')
  assert.match(failure.error.message, /at least one.*web-evidence.*reverse-evidence/i)
})

test('CLI maps fixed Ghidra and Frida inputs without accepting raw target arguments', async () => {
  const calls = []
  const deps = { ...operations(calls), ...capture() }
  assert.equal(await runReverseCli([
    'ghidra', 'analyze', '--lab-root', 'C:\\lab', '--binary', 'bin/app.exe',
    '--artifact-kind', 'native-executable', '--ghidra', 'C:\\tools\\headless.exe',
    '--out', 'C:\\out\\ghidra',
  ], deps), 0)
  assert.equal(await runReverseCli([
    'frida', 'trace', '--lab-root', 'C:\\lab', '--binary', 'bin/app.exe',
    '--frida', 'C:\\tools\\frida.exe', '--module', '<main>', '--symbol', 'send_request',
    '--out', 'C:\\out\\frida',
  ], deps), 0)
  assert.deepEqual(calls[0][1], {
    labRoot: 'C:\\lab', binary: 'bin/app.exe', artifactKind: 'native-executable',
    ghidraPath: 'C:\\tools\\headless.exe', outPath: 'C:\\out\\ghidra',
  })
  assert.deepEqual(calls[1][1], {
    labRoot: 'C:\\lab', binary: 'bin/app.exe', fridaPath: 'C:\\tools\\frida.exe',
    moduleName: '<main>', symbolName: 'send_request', outPath: 'C:\\out\\frida',
  })
  assert.equal(await runReverseCli([
    'frida', 'trace-plan', '--plan', 'C:\\lab\\trace-plan.json',
    '--frida', 'C:\\tools\\frida.exe', '--out', 'C:\\out\\frida-v2',
  ], deps), 2)
  assert.deepEqual(calls[2], ['frida-plan', {
    planPath: 'C:\\lab\\trace-plan.json', fridaPath: 'C:\\tools\\frida.exe',
    outPath: 'C:\\out\\frida-v2',
  }])
})

test('CLI rejects unknown, missing, duplicate scalar, and widened options without dispatch', async () => {
  const cases = [
    ['unknown'],
    ['web', 'import-har', '--har', 'x', '--origin', 'https://x.example'],
    ['web', 'import-har', '--har', 'x', '--origin', 'https://x.example', '--out', 'z'],
    ['web', 'import-har', '--har', 'x', '--har', 'y', '--origin', 'https://x.example', '--out', 'z'],
    ['frida', 'trace', '--lab-root', 'x', '--binary', 'x', '--frida', 'x', '--module', 'x', '--symbol', 'x', '--out', 'x', '--target-arg', '--unsafe'],
    ['frida', 'trace-plan', '--plan', 'x', '--frida', 'x', '--out', 'x', '--script', 'caller.js'],
    ['frida', 'trace-plan', '--plan', 'x', '--frida', 'x', '--out', 'x', '--host', 'remote'],
    ['protocol', 'verify', '--package', 'x'],
    ['protocol', 'verify', '--package', 'x', '--manifest-sha256', 'x', '--contract', 'y'],
  ]
  for (const argv of cases) {
    const calls = []
    const io = capture()
    assert.equal(await runReverseCli(argv, { ...operations(calls), ...io }), 1)
    assert.equal(calls.length, 0)
    assert.match(io.stderrText(), /reverse|usage|unknown|required|duplicate|option/i)
  }
})
