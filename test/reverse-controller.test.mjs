import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import fsPromises from 'node:fs/promises'
import { mkdtemp, mkdir, readFile, rename, rm, symlink, truncate, writeFile } from 'node:fs/promises'
import { syncBuiltinESMExports } from 'node:module'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'

import {
  analyzeGhidraArtifact,
  buildProtocolContractFile,
  importBurpFile,
  importHarFile,
  traceFridaArtifact,
} from '../scripts/lib/reverse-controller.mjs'
import { compareCanonicalStrings } from '../scripts/lib/canonical-order.mjs'
import { GHIDRA_GENERIC_PATH_SEGMENTS } from '../scripts/lib/reverse-contracts.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-reverse-'))
  const labRoot = join(root, 'lab')
  await mkdir(join(labRoot, 'bin'), { recursive: true })
  const binaryPath = join(labRoot, 'bin', 'demo.exe')
  await writeFile(binaryPath, Buffer.from('fixed native fixture'))
  const ghidraPath = join(root, 'analyzeHeadless.exe')
  const fridaPath = join(root, 'frida.exe')
  await writeFile(ghidraPath, Buffer.from('fixture'))
  await writeFile(fridaPath, Buffer.from('fixture'))
  return { root, labRoot, binaryPath, ghidraPath, fridaPath }
}

function har() {
  return { log: { entries: [{
    startedDateTime: '2026-09-11T12:00:00.000Z',
    time: 5,
    request: {
      method: 'POST',
      url: 'https://portal.example/auth/login?connection=secret',
      headers: [{ name: 'Authorization', value: 'Bearer secret' }],
      cookies: [{ name: 'SessionCookie', value: 'secret' }],
      postData: {
        mimeType: 'application/x-www-form-urlencoded',
        params: [{ name: 'Password', value: 'secret' }],
      },
    },
    response: {
      status: 200,
      headers: [{ name: 'Set-Cookie', value: 'SessionToken=secret' }],
      cookies: [{ name: 'SessionToken', value: 'secret' }],
      content: { mimeType: 'application/json', size: 15, text: '{"Status":"OK"}' },
    },
  }] } }
}

function burpXml() {
  const request = Buffer.from([
    'POST /auth/login?connection=secret HTTP/1.1',
    'Host: portal.example',
    'Authorization: Bearer secret',
    'Content-Type: application/x-www-form-urlencoded',
    '',
    'password=secret',
  ].join('\r\n')).toString('base64')
  const response = Buffer.from([
    'HTTP/1.1 200 OK',
    'Set-Cookie: SessionToken=secret; Secure',
    'Content-Type: application/json',
    '',
    '{"Status":"OK"}',
  ].join('\r\n')).toString('base64')
  return `<?xml version="1.0" encoding="UTF-8"?><items burpVersion="2026.8"><item>
    <url>https://portal.example/auth/login?connection=secret</url>
    <host>portal.example</host><port>443</port><protocol>https</protocol>
    <method>POST</method><path>/auth/login?connection=secret</path>
    <request base64="true">${request}</request><status>200</status>
    <response base64="true">${response}</response>
  </item></items>`
}

function inconclusiveReverseEvidence() {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/reverse-evidence',
    protocol: 'reverse-evidence-v1',
    run_id: 'reverse:0123456789abcdef0123456789abcdef',
    engine: 'ghidra',
    profile_id: 'ghidra-headless-fixed-export-v1',
    started_at: '2026-09-11T12:00:00.000Z',
    finished_at: '2026-09-11T12:00:01.000Z',
    artifact: {
      kind: 'native-executable', path: 'bin/app.exe', sha256: 'c'.repeat(64), size_bytes: 4096,
    },
    tool: { name: 'Ghidra', version: '12.1.3', invocation_sha256: 'd'.repeat(64) },
    limits: { timeout_ms: 300000, max_output_bytes: 8192, max_observations: 100 },
    status: 'INCONCLUSIVE',
    target_execution: 'NOT_PERFORMED',
    security_verdict: 'NOT_ASSESSED',
    applied_to_audit_bundle: false,
    observations: [],
    gaps: [{ code: 'FIXTURE_INCONCLUSIVE', message: 'No native observations were retained.' }],
    cleanup: { attempted: true, verified: true },
  }
}

function ghidraExport(executableSha256, pathTemplate = '/api/session/{integer}') {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/ghidra-static-export',
    profile_id: 'ghidra-headless-fixed-export-v1',
    analysis_status: 'OBSERVATIONS_ONLY',
    target_execution: 'NOT_PERFORMED',
    program: {
      executable_format: 'Portable Executable (PE)',
      executable_sha256: executableSha256,
      language_id: 'x86:LE:64:default',
      compiler_spec_id: 'windows',
      image_base: '140000000',
      minimum_address: '140001000',
      maximum_address: '140001100',
    },
    functions: [{ entry_point: '140001000', name: 'main', external: false, thunk: false, body_address_count: 12 }],
    network_imports: [{
      api: 'WINHTTP_SEND_REQUEST',
      references: [{ from_offset: '0x1000', kind: 'CALL' }],
      callsite_offsets: ['0x1000'],
      references_scanned: 1,
      references_truncated: false,
    }],
    endpoint_observations: [{
      scheme: 'https', origin: 'https://portal.example', host: 'portal.example', port: 443,
      path_template: pathTemplate, query_names: ['view'], source_offsets: ['0x2000'],
      userinfo_present: false, candidate_truncated: false, path_truncated: false,
      path_values_redacted: true, query_names_truncated: false,
    }],
    auth_hints: [{ hint: 'SESSION_IDENTIFIER', source_offset: '0x2100' }],
    coverage: { function_limit: 20000, available_functions: 1, emitted_functions: 1, truncated: false },
    protocol_coverage: {
      network_import_limit: 512,
      references_per_import_limit: 128,
      external_functions_scanned: 1,
      matching_network_imports: 1,
      emitted_network_imports: 1,
      external_function_scan_truncated: false,
      network_imports_truncated: false,
      string_record_limit: 100000,
      string_records_scanned: 2,
      string_values_scanned: 2,
      truncated_string_values: 0,
      string_scan_truncated: false,
      endpoint_limit: 512,
      endpoint_candidates: 1,
      emitted_endpoints: 1,
      endpoints_truncated: false,
      auth_hint_limit: 512,
      auth_hint_candidates: 1,
      emitted_auth_hints: 1,
      auth_hints_truncated: false,
    },
  }
}

test('imports a bounded HAR to exclusive redacted web evidence', async () => {
  const files = await fixture()
  try {
    const harPath = join(files.root, 'session.har')
    const outPath = join(files.root, 'web-evidence.json')
    const captured = har()
    captured.log.entries.push({
      ...structuredClone(captured.log.entries[0]),
      request: { ...structuredClone(captured.log.entries[0].request), url: 'https://portal.example/admin' },
    })
    await writeFile(harPath, JSON.stringify(captured), 'utf8')
    const result = await importHarFile({
      harPath,
      targetOrigins: ['https://portal.example'],
      targetPathPrefix: '/auth',
      outPath,
    })
    const text = await readFile(outPath, 'utf8')
    const evidence = JSON.parse(text)
    assert.equal(result.status, 'SUCCEEDED')
    assert.equal(result.output_path, outPath)
    assert.equal(evidence.kind, 'red-team-audit/web-session-evidence')
    assert.equal(evidence.entries.length, 1)
    assert.equal(evidence.skipped.off_scope, 1)
    assert.equal(evidence.entries[0].request.path_template, '/auth/login')
    assert.equal(text.includes('Bearer secret'), false)
    assert.equal(text.includes('connection=secret'), false)
    assert.equal(text.includes('"secret"'), false)
    await assert.rejects(
      importHarFile({ harPath, targetOrigins: ['https://portal.example'], outPath }),
      /exist|overwrite|exclusive/i,
    )
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('imports bounded Burp HTTP-items XML to the shared redacted evidence contract', async () => {
  const files = await fixture()
  try {
    const burpPath = join(files.root, 'items.xml')
    const outPath = join(files.root, 'burp-web-evidence.json')
    await writeFile(burpPath, burpXml(), 'utf8')
    const result = await importBurpFile({
      burpPath,
      targetOrigins: ['https://portal.example'],
      targetPathPrefix: '/auth',
      outPath,
    })
    const text = await readFile(outPath, 'utf8')
    const evidence = JSON.parse(text)
    assert.equal(result.status, 'SUCCEEDED')
    assert.equal(evidence.source.kind, 'BURP_XML')
    assert.equal(evidence.entries[0].request.path_template, '/auth/login')
    assert.equal(evidence.entries[0].response.redirect, null)
    for (const value of ['Bearer secret', 'connection=secret', 'password=secret']) {
      assert.equal(text.includes(value), false)
    }
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('refuses linked input and protocol output replacement', async () => {
  const files = await fixture()
  try {
    const realDirectory = join(files.root, 'real-input')
    const linkedDirectory = join(files.root, 'linked-input')
    await mkdir(realDirectory)
    const realHar = join(realDirectory, 'session.har')
    await writeFile(realHar, JSON.stringify(har()), 'utf8')
    await symlink(realDirectory, linkedDirectory, process.platform === 'win32' ? 'junction' : 'dir')
    await assert.rejects(
      importHarFile({
        harPath: join(linkedDirectory, 'session.har'),
        targetOrigins: ['https://portal.example'],
        outPath: join(files.root, 'linked-result.json'),
      }),
      /link|regular|input/i,
    )
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('builds a native interaction contract from strict evidence files', async () => {
  const files = await fixture()
  try {
    const harPath = join(files.root, 'session.har')
    const webPath = join(files.root, 'web.json')
    const outPath = join(files.root, 'interaction.json')
    await writeFile(harPath, JSON.stringify(har()), 'utf8')
    await importHarFile({ harPath, targetOrigins: ['https://portal.example'], outPath: webPath })
    const result = await buildProtocolContractFile({
      webEvidencePaths: [webPath],
      reverseEvidencePaths: [],
      outPath,
      generatedAt: '2026-09-11T12:01:00.000Z',
    })
    const contract = JSON.parse(await readFile(outPath, 'utf8'))
    assert.equal(result.status, 'SUCCEEDED')
    assert.equal(contract.kind, 'red-team-audit/native-interaction-contract')
    assert.equal(contract.status, 'DRAFT_OBSERVED')
    assert.equal(contract.generated_client_status, 'CONTRACT_ONLY')
    assert.equal(contract.endpoints.length, 1)
    await assert.rejects(
      buildProtocolContractFile({
        webEvidencePaths: [webPath],
        reverseEvidencePaths: [],
        outPath,
      }),
      /exist|overwrite|exclusive/i,
    )
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('builds a native interaction contract from reverse evidence alone', async () => {
  const files = await fixture()
  try {
    const reversePath = join(files.root, 'reverse.json')
    const outPath = join(files.root, 'interaction.json')
    await writeFile(reversePath, JSON.stringify(inconclusiveReverseEvidence()), 'utf8')
    const result = await buildProtocolContractFile({
      reverseEvidencePaths: [reversePath],
      outPath,
      generatedAt: '2026-09-11T12:01:00.000Z',
    })
    const contract = JSON.parse(await readFile(outPath, 'utf8'))
    assert.equal(result.status, 'SUCCEEDED')
    assert.deepEqual(contract.basis.web_session_evidence_sha256, [])
    assert.equal(contract.basis.reverse_evidence_sha256.length, 1)
    assert.deepEqual(contract.subjects.artifact_sha256, ['c'.repeat(64)])
    assert.equal(contract.gaps.some(({ code }) => code === 'NO_WEB_ENDPOINTS'), true)
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('protocol contract file refuses an empty evidence set', async () => {
  const files = await fixture()
  try {
    await assert.rejects(
      buildProtocolContractFile({ outPath: join(files.root, 'interaction.json') }),
      (error) => error?.code === 'REVERSE_EVIDENCE_INPUT_INVALID'
        && /at least one.*web or reverse evidence/i.test(error.message),
    )
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('protocol build rejects more than 128 MiB of evidence before parsing it', async () => {
  const files = await fixture()
  try {
    const paths = [
      join(files.root, 'oversized-one.json'),
      join(files.root, 'oversized-two.json'),
      join(files.root, 'oversized-three.json'),
    ]
    for (const [index, path] of paths.entries()) {
      await writeFile(path, '{', 'utf8')
      await truncate(path, index < 2 ? 64 * 1024 * 1024 : 1)
    }
    await assert.rejects(
      buildProtocolContractFile({
        webEvidencePaths: paths,
        reverseEvidencePaths: [],
        outPath: join(files.root, 'oversized-contract.json'),
      }),
      (error) => error?.code === 'REVERSE_EVIDENCE_INPUT_SIZE_INVALID'
        && /128 MiB|combined|cumulative/i.test(error.message),
    )
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('output setup failure removes only the new owned directory and permits retry', async () => {
  const files = await fixture()
  const outPath = join(files.root, 'retryable-output')
  const intentPath = join(outPath, 'intent.json')
  const originalWriteFile = fsPromises.writeFile
  let setupFailureInjected = false
  let runnerCalls = 0
  try {
    fsPromises.writeFile = async (path, ...args) => {
      if (path === intentPath) {
        setupFailureInjected = true
        const error = new Error('injected output setup failure')
        error.code = 'EIO'
        throw error
      }
      return originalWriteFile(path, ...args)
    }
    syncBuiltinESMExports()
    try {
      await assert.rejects(
        traceFridaArtifact({
          labRoot: files.labRoot,
          binary: 'bin/demo.exe',
          fridaPath: files.fridaPath,
          moduleName: '<main>',
          symbolName: 'parse_packet',
          outPath,
          runFrida: async () => { runnerCalls += 1 },
        }),
        /injected output setup failure/,
      )
    } finally {
      fsPromises.writeFile = originalWriteFile
      syncBuiltinESMExports()
    }
    assert.equal(setupFailureInjected, true)
    assert.equal(runnerCalls, 0)
    await assert.rejects(readFile(intentPath), { code: 'ENOENT' })

    const result = await traceFridaArtifact({
      labRoot: files.labRoot,
      binary: 'bin/demo.exe',
      fridaPath: files.fridaPath,
      moduleName: '<main>',
      symbolName: 'parse_packet',
      outPath,
      runFrida: async (options) => {
        runnerCalls += 1
        const { frameNonce } = JSON.parse(options.args[7])
        return {
          profile_id: 'native-call-trace-v1',
          ready: true,
          complete: true,
          trace_events: 0,
          truncated: false,
          ignored_lines: 0,
          observation_window_ms: { start: 1, end: 2 },
          events: [
            { schema_version: '1.0.0', profile_id: 'native-call-trace-v1', frame_nonce: frameNonce, observed_at_ms: 1, event: 'ready', module_name: '<main>', symbol_name: 'parse_packet', module_relative_offset: '0x1000' },
            { schema_version: '1.0.0', profile_id: 'native-call-trace-v1', frame_nonce: frameNonce, observed_at_ms: 2, event: 'complete', events_emitted: 0, truncated: false },
          ],
          process_exit_code: 0,
          stderr_bytes: 0,
        }
      },
    })
    assert.equal(result.status, 'SUCCEEDED')
    assert.equal(runnerCalls, 1)
  } finally {
    if (fsPromises.writeFile !== originalWriteFile) {
      fsPromises.writeFile = originalWriteFile
      syncBuiltinESMExports()
    }
    await rm(files.root, { recursive: true, force: true })
  }
})

test('Ghidra orchestration stages a copy, emits strict evidence, and removes scratch state', async () => {
  const files = await fixture()
  try {
    const outPath = join(files.root, 'ghidra-evidence')
    let invocation
    const result = await analyzeGhidraArtifact({
      labRoot: files.labRoot,
      binary: 'bin/demo.exe',
      artifactKind: 'native-executable',
      ghidraPath: files.ghidraPath,
      outPath,
      now: () => new Date('2026-09-11T12:00:00.000Z'),
      runGhidra: async (options) => {
        invocation = options
        await writeFile(options.args[14], JSON.stringify(ghidraExport(resultHash('fixed native fixture'))), 'utf8')
        return {
          profile_id: 'ghidra-headless-fixed-export-v1',
          code: 0,
          signal: null,
          timed_out: false,
          output_limit_exceeded: false,
          spawn_error: false,
          termination_confirmed: true,
          duration_ms: 10,
          stdout: Buffer.alloc(0),
          stderr: Buffer.alloc(0),
        }
      },
    })
    const evidence = JSON.parse(await readFile(join(outPath, 'evidence.json'), 'utf8'))
    const intent = JSON.parse(await readFile(join(outPath, 'intent.json'), 'utf8'))
    assert.equal(result.status, 'SUCCEEDED')
    assert.equal(evidence.status, 'SUCCEEDED')
    assert.equal(evidence.target_execution, 'NOT_PERFORMED')
    assert.equal(evidence.observations[0].type, 'program-summary')
    assert.equal(evidence.observations[1].type, 'protocol-summary')
    assert.equal(evidence.observations.some(({ type }) => type === 'network-import'), true)
    assert.equal(evidence.observations.some(({ type }) => type === 'static-endpoint'), true)
    assert.equal(evidence.observations.some(({ type }) => type === 'auth-hint'), true)
    assert.equal(evidence.observations.some(({ type }) => type === 'function'), true)
    assert.equal(intent.tool_invocation_sha256, evidence.tool.invocation_sha256)
    assert.equal(
      evidence.tool.invocation_sha256,
      createHash('sha256').update(stableJson({
        profile_id: evidence.profile_id,
        args: invocation.args,
        components: evidence.tool.components,
      }, 0)).digest('hex'),
    )
    assert.deepEqual(
      evidence.tool.components.map(({ role }) => role),
      ['fixed-exporter', 'ghidra-launcher'],
    )
    assert.deepEqual(
      evidence.tool.components.map(({ role }) => role),
      evidence.tool.components.map(({ role }) => role).sort(compareCanonicalStrings),
    )
    for (const component of evidence.tool.components) {
      assert.match(component.sha256, /^[a-f0-9]{64}$/u)
      assert.equal(component.size_bytes > 0, true)
    }
    assert.equal(invocation.args.includes('-readOnly'), true)
    assert.equal(invocation.args.includes('-deleteProject'), true)
    assert.equal(Object.hasOwn(invocation, 'windowsCompatibilityAgent'), false)
    assert.equal(invocation.args[0], join(outPath, 'work', 'project'))
    assert.equal(invocation.args[0].split(/[\\/]/u).some((part) => part.startsWith('.')), false)
    await assert.rejects(readFile(join(outPath, 'work', 'target.exe')))
    assert.equal(await readFile(files.binaryPath, 'utf8'), 'fixed native fixture')
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('Ghidra export verification admits only the exporter generic route segments', async () => {
  const files = await fixture()
  const analyzePath = async (pathTemplate, outputName) => {
    const outPath = join(files.root, outputName)
    const result = await analyzeGhidraArtifact({
      labRoot: files.labRoot,
      binary: 'bin/demo.exe',
      artifactKind: 'native-executable',
      ghidraPath: files.ghidraPath,
      outPath,
      runGhidra: async (options) => {
        await writeFile(
          options.args[14],
          JSON.stringify(ghidraExport(resultHash('fixed native fixture'), pathTemplate)),
          'utf8',
        )
        return {
          profile_id: 'ghidra-headless-fixed-export-v1',
          code: 0,
          signal: null,
          timed_out: false,
          output_limit_exceeded: false,
          spawn_error: false,
          termination_confirmed: true,
          duration_ms: 10,
          stdout: Buffer.alloc(0),
          stderr: Buffer.alloc(0),
        }
      },
    })
    return {
      result,
      evidence: JSON.parse(await readFile(join(outPath, 'evidence.json'), 'utf8')),
    }
  }

  try {
    const genericPath = `/${GHIDRA_GENERIC_PATH_SEGMENTS.join('/')}/v1/{integer}`
    const accepted = await analyzePath(genericPath, 'generic-ghidra-route')
    assert.equal(accepted.result.status, 'SUCCEEDED')
    assert.equal(
      accepted.evidence.observations.find(({ type }) => type === 'static-endpoint').path_template,
      genericPath,
    )

    for (const segment of [
      'workspacealpha', 'workspacebeta', 'workspacegamma', 'workspacedelta', 'workspaceepsilon', 'workspacezeta',
    ]) {
      const rejected = await analyzePath(`/api/${segment}/{integer}`, `rejected-ghidra-${segment}`)
      assert.equal(rejected.result.status, 'FAILED')
      assert.deepEqual(rejected.evidence.observations, [])
      assert.equal(
        rejected.evidence.gaps.some(({ code }) => code === 'GHIDRA_EXECUTION_FAILED'),
        true,
      )
    }
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('Ghidra orchestration preserves scratch when process termination is unconfirmed', async () => {
  const files = await fixture()
  try {
    const outPath = join(files.root, 'ghidra-unconfirmed')
    const result = await analyzeGhidraArtifact({
      labRoot: files.labRoot,
      binary: 'bin/demo.exe',
      artifactKind: 'native-executable',
      ghidraPath: files.ghidraPath,
      outPath,
      now: () => new Date('2026-09-11T12:00:00.000Z'),
      runGhidra: async () => ({
        profile_id: 'ghidra-headless-fixed-export-v1',
        code: null,
        signal: 'SIGKILL',
        timed_out: true,
        output_limit_exceeded: false,
        spawn_error: false,
        termination_confirmed: false,
        duration_ms: 5_000,
        stdout: Buffer.alloc(0),
        stderr: Buffer.alloc(0),
      }),
    })
    const evidence = JSON.parse(await readFile(join(outPath, 'evidence.json'), 'utf8'))
    assert.equal(result.status, 'FAILED')
    assert.deepEqual(evidence.cleanup, { attempted: false, verified: false })
    assert.equal(evidence.gaps.some(({ code }) => code === 'GHIDRA_TERMINATION_UNCONFIRMED'), true)
    assert.equal(await readFile(join(outPath, 'work', 'target.exe'), 'utf8'), 'fixed native fixture')
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('Ghidra orchestration rejects output when diagnostic logs exceed their cap', async () => {
  const files = await fixture()
  try {
    const outPath = join(files.root, 'ghidra-log-limit')
    const result = await analyzeGhidraArtifact({
      labRoot: files.labRoot,
      binary: 'bin/demo.exe',
      artifactKind: 'native-executable',
      ghidraPath: files.ghidraPath,
      outPath,
      runGhidra: async (options) => {
        for (const logPath of [options.args[16], options.args[18]]) {
          await writeFile(logPath, '')
          await truncate(logPath, (8 * 1024 * 1024) + 1)
        }
        return {
          profile_id: 'ghidra-headless-fixed-export-v1',
          code: 0,
          signal: null,
          timed_out: false,
          output_limit_exceeded: false,
          spawn_error: false,
          termination_confirmed: true,
          duration_ms: 10,
          stdout: Buffer.alloc(0),
          stderr: Buffer.alloc(0),
        }
      },
    })
    const evidence = JSON.parse(await readFile(join(outPath, 'evidence.json'), 'utf8'))
    assert.equal(result.status, 'FAILED')
    assert.equal(evidence.gaps.some(({ code }) => code === 'GHIDRA_LOG_LIMIT_EXCEEDED'), true)
    assert.deepEqual(evidence.cleanup, { attempted: true, verified: true })
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('Ghidra orchestration reports missing owned scratch as cleanup uncertainty', async () => {
  const files = await fixture()
  try {
    const outPath = join(files.root, 'ghidra-missing-work')
    const result = await analyzeGhidraArtifact({
      labRoot: files.labRoot,
      binary: 'bin/demo.exe',
      artifactKind: 'native-executable',
      ghidraPath: files.ghidraPath,
      outPath,
      runGhidra: async (options) => {
        await rm(options.cwd, { recursive: true, force: false })
        return {
          profile_id: 'ghidra-headless-fixed-export-v1',
          code: 0,
          signal: null,
          timed_out: false,
          output_limit_exceeded: false,
          spawn_error: false,
          termination_confirmed: true,
          duration_ms: 10,
          stdout: Buffer.alloc(0),
          stderr: Buffer.alloc(0),
        }
      },
    })
    const evidence = JSON.parse(await readFile(join(outPath, 'evidence.json'), 'utf8'))
    assert.equal(result.status, 'FAILED')
    assert.deepEqual(evidence.cleanup, { attempted: true, verified: false })
    assert.equal(evidence.gaps.some(({ code }) => code === 'WORK_IDENTITY_CHANGED'), true)
    assert.equal(evidence.gaps.some(({ code }) => code === 'CLEANUP_UNVERIFIED'), true)
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('Ghidra orchestration never removes a replacement at the owned scratch path', async () => {
  const files = await fixture()
  try {
    const outPath = join(files.root, 'ghidra-replaced-work')
    const displacedPath = join(outPath, 'work-displaced')
    const result = await analyzeGhidraArtifact({
      labRoot: files.labRoot,
      binary: 'bin/demo.exe',
      artifactKind: 'native-executable',
      ghidraPath: files.ghidraPath,
      outPath,
      runGhidra: async (options) => {
        await rename(options.cwd, displacedPath)
        await mkdir(options.cwd)
        await writeFile(join(options.cwd, 'replacement-marker.txt'), 'preserve me', 'utf8')
        return {
          profile_id: 'ghidra-headless-fixed-export-v1',
          code: 0,
          signal: null,
          timed_out: false,
          output_limit_exceeded: false,
          spawn_error: false,
          termination_confirmed: true,
          duration_ms: 10,
          stdout: Buffer.alloc(0),
          stderr: Buffer.alloc(0),
        }
      },
    })
    const evidence = JSON.parse(await readFile(join(outPath, 'evidence.json'), 'utf8'))
    assert.equal(result.status, 'FAILED')
    assert.deepEqual(evidence.cleanup, { attempted: true, verified: false })
    assert.equal(evidence.gaps.some(({ code }) => code === 'WORK_IDENTITY_CHANGED'), true)
    assert.equal(evidence.gaps.some(({ code }) => code === 'CLEANUP_UNVERIFIED'), true)
    assert.equal(await readFile(join(outPath, 'work', 'replacement-marker.txt'), 'utf8'), 'preserve me')
    assert.equal(await readFile(join(displacedPath, 'target.exe'), 'utf8'), 'fixed native fixture')
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('Ghidra orchestration discards observations when the launcher changes during execution', async () => {
  const files = await fixture()
  try {
    const outPath = join(files.root, 'changed-ghidra-tool')
    const result = await analyzeGhidraArtifact({
      labRoot: files.labRoot,
      binary: 'bin/demo.exe',
      artifactKind: 'native-executable',
      ghidraPath: files.ghidraPath,
      outPath,
      now: () => new Date('2026-09-11T12:00:00.000Z'),
      runGhidra: async (options) => {
        await writeFile(options.args[14], JSON.stringify(ghidraExport(resultHash('fixed native fixture'))), 'utf8')
        await writeFile(files.ghidraPath, Buffer.from('changed launcher'))
        return {
          profile_id: 'ghidra-headless-fixed-export-v1',
          code: 0,
          signal: null,
          timed_out: false,
          output_limit_exceeded: false,
          spawn_error: false,
          termination_confirmed: true,
          duration_ms: 10,
          stdout: Buffer.alloc(0),
          stderr: Buffer.alloc(0),
        }
      },
    })
    const evidence = JSON.parse(await readFile(join(outPath, 'evidence.json'), 'utf8'))
    assert.equal(result.status, 'FAILED')
    assert.deepEqual(evidence.observations, [])
    assert.equal(evidence.gaps.some(({ code }) => code === 'TOOL_CHANGED'), true)
    await assert.rejects(readFile(join(outPath, 'work', 'target.exe')))
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('Frida orchestration uses only the fixed local spawn profile', async () => {
  const files = await fixture()
  try {
    const outPath = join(files.root, 'frida-evidence')
    let invocation
    const result = await traceFridaArtifact({
      labRoot: files.labRoot,
      binary: 'bin/demo.exe',
      fridaPath: files.fridaPath,
      moduleName: '<main>',
      symbolName: 'parse_packet',
      outPath,
      now: () => new Date('2026-09-11T12:00:00.000Z'),
      runFrida: async (options) => {
        invocation = options
        const { frameNonce } = JSON.parse(options.args[7])
        return {
          profile_id: 'native-call-trace-v1',
          ready: true,
          complete: true,
          trace_events: 2,
          truncated: false,
          ignored_lines: 0,
          observation_window_ms: { start: 1, end: 3 },
          events: [
            { schema_version: '1.0.0', profile_id: 'native-call-trace-v1', frame_nonce: frameNonce, observed_at_ms: 1, event: 'ready', module_name: '<main>', symbol_name: 'parse_packet', module_relative_offset: '0x1000' },
            { schema_version: '1.0.0', profile_id: 'native-call-trace-v1', frame_nonce: frameNonce, observed_at_ms: 2, event: 'enter', sequence: 1, thread_id: 7 },
            { schema_version: '1.0.0', profile_id: 'native-call-trace-v1', frame_nonce: frameNonce, observed_at_ms: 2, event: 'leave', sequence: 2, thread_id: 7 },
            { schema_version: '1.0.0', profile_id: 'native-call-trace-v1', frame_nonce: frameNonce, observed_at_ms: 3, event: 'complete', events_emitted: 2, truncated: false },
          ],
          process_exit_code: 0,
          stderr_bytes: 0,
        }
      },
    })
    const evidence = JSON.parse(await readFile(join(outPath, 'evidence.json'), 'utf8'))
    assert.equal(result.status, 'SUCCEEDED')
    assert.equal(evidence.engine, 'frida')
    assert.equal(evidence.target_execution, 'LOCAL_LAB_SPAWN')
    assert.equal(evidence.security_verdict, 'NOT_ASSESSED')
    assert.equal(invocation.args.includes('-f'), true)
    assert.equal(invocation.args.some((item) => ['-p', '-U', '-R', '-H', '-e'].includes(item)), false)
    assert.equal(await readFile(files.binaryPath, 'utf8'), 'fixed native fixture')
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('Frida orchestration reports unconfirmed process-tree termination explicitly', async () => {
  const files = await fixture()
  try {
    const outPath = join(files.root, 'frida-unconfirmed-termination')
    const result = await traceFridaArtifact({
      labRoot: files.labRoot,
      binary: 'bin/demo.exe',
      fridaPath: files.fridaPath,
      moduleName: '<main>',
      symbolName: 'parse_packet',
      outPath,
      runFrida: async () => {
        const error = new Error('tree state unavailable')
        error.code = 'FRIDA_TERMINATION_UNCONFIRMED'
        throw error
      },
    })
    const evidence = JSON.parse(await readFile(join(outPath, 'evidence.json'), 'utf8'))
    assert.equal(result.status, 'FAILED')
    assert.deepEqual(evidence.cleanup, { attempted: true, verified: false })
    assert.equal(evidence.gaps.some(({ code }) => code === 'FRIDA_TERMINATION_UNCONFIRMED'), true)
    assert.equal(evidence.gaps.some(({ code }) => code === 'CLEANUP_UNVERIFIED'), true)
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('Frida orchestration rejects a runner frame not bound to its nonce and requested symbol', async () => {
  const files = await fixture()
  try {
    const outPath = join(files.root, 'spoofed-frida-evidence')
    const result = await traceFridaArtifact({
      labRoot: files.labRoot,
      binary: 'bin/demo.exe',
      fridaPath: files.fridaPath,
      moduleName: '<main>',
      symbolName: 'parse_packet',
      outPath,
      now: () => new Date('2026-09-11T12:00:00.000Z'),
      runFrida: async () => {
        const frameNonce = '0'.repeat(64)
        return {
          profile_id: 'native-call-trace-v1', ready: true, complete: true,
          trace_events: 0, truncated: false, ignored_lines: 0,
          observation_window_ms: { start: 1, end: 2 },
          events: [
            { schema_version: '1.0.0', profile_id: 'native-call-trace-v1', frame_nonce: frameNonce, observed_at_ms: 1, event: 'ready', module_name: '<main>', symbol_name: 'other_symbol', module_relative_offset: '0x1000' },
            { schema_version: '1.0.0', profile_id: 'native-call-trace-v1', frame_nonce: frameNonce, observed_at_ms: 2, event: 'complete', events_emitted: 0, truncated: false },
          ],
          process_exit_code: 0,
          stderr_bytes: 0,
        }
      },
    })
    const evidence = JSON.parse(await readFile(join(outPath, 'evidence.json'), 'utf8'))
    assert.equal(result.status, 'FAILED')
    assert.deepEqual(evidence.observations, [])
    assert.equal(evidence.gaps.some(({ code }) => code === 'FRIDA_EXECUTION_FAILED'), true)
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('Frida evidence fails closed when the executable hash changes during the trace', async () => {
  const files = await fixture()
  try {
    const outPath = join(files.root, 'changed-frida-evidence')
    const result = await traceFridaArtifact({
      labRoot: files.labRoot,
      binary: 'bin/demo.exe',
      fridaPath: files.fridaPath,
      moduleName: '<main>',
      symbolName: 'parse_packet',
      outPath,
      now: () => new Date('2026-09-11T12:00:00.000Z'),
      runFrida: async (options) => {
        const { frameNonce } = JSON.parse(options.args[7])
        await writeFile(files.binaryPath, Buffer.from('changed native fixture'))
        return {
          profile_id: 'native-call-trace-v1',
          ready: true,
          complete: true,
          trace_events: 0,
          truncated: false,
          ignored_lines: 0,
          observation_window_ms: { start: 1, end: 2 },
          events: [
            { schema_version: '1.0.0', profile_id: 'native-call-trace-v1', frame_nonce: frameNonce, observed_at_ms: 1, event: 'ready', module_name: '<main>', symbol_name: 'parse_packet', module_relative_offset: '0x1000' },
            { schema_version: '1.0.0', profile_id: 'native-call-trace-v1', frame_nonce: frameNonce, observed_at_ms: 2, event: 'complete', events_emitted: 0, truncated: false },
          ],
          process_exit_code: 0,
          stderr_bytes: 0,
        }
      },
    })
    const evidence = JSON.parse(await readFile(join(outPath, 'evidence.json'), 'utf8'))
    assert.equal(result.status, 'FAILED')
    assert.equal(evidence.status, 'FAILED')
    assert.deepEqual(evidence.observations, [])
    assert.equal(evidence.gaps.some(({ code }) => code === 'TARGET_CHANGED'), true)
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('Frida orchestration discards observations when the executable changes during execution', async () => {
  const files = await fixture()
  try {
    const outPath = join(files.root, 'changed-frida-tool')
    const result = await traceFridaArtifact({
      labRoot: files.labRoot,
      binary: 'bin/demo.exe',
      fridaPath: files.fridaPath,
      moduleName: '<main>',
      symbolName: 'parse_packet',
      outPath,
      now: () => new Date('2026-09-11T12:00:00.000Z'),
      runFrida: async (options) => {
        const { frameNonce } = JSON.parse(options.args[7])
        await writeFile(files.fridaPath, Buffer.from('changed executable'))
        return {
          profile_id: 'native-call-trace-v1',
          ready: true,
          complete: true,
          trace_events: 0,
          truncated: false,
          ignored_lines: 0,
          observation_window_ms: { start: 1, end: 2 },
          events: [
            { schema_version: '1.0.0', profile_id: 'native-call-trace-v1', frame_nonce: frameNonce, observed_at_ms: 1, event: 'ready', module_name: '<main>', symbol_name: 'parse_packet', module_relative_offset: '0x1000' },
            { schema_version: '1.0.0', profile_id: 'native-call-trace-v1', frame_nonce: frameNonce, observed_at_ms: 2, event: 'complete', events_emitted: 0, truncated: false },
          ],
          process_exit_code: 0,
          stderr_bytes: 0,
        }
      },
    })
    const evidence = JSON.parse(await readFile(join(outPath, 'evidence.json'), 'utf8'))
    assert.equal(result.status, 'FAILED')
    assert.deepEqual(evidence.observations, [])
    assert.equal(evidence.gaps.some(({ code }) => code === 'TOOL_CHANGED'), true)
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

test('reverse execution rejects traversal and output beneath the executable lab before invoking a tool', async () => {
  const files = await fixture()
  let calls = 0
  try {
    await assert.rejects(
      traceFridaArtifact({
        labRoot: files.labRoot,
        binary: '../outside.exe',
        fridaPath: files.fridaPath,
        moduleName: '<main>',
        symbolName: 'x',
        outPath: join(files.root, 'bad-one'),
        runFrida: async () => { calls += 1 },
      }),
      /contained|relative|binary/i,
    )
    await assert.rejects(
      traceFridaArtifact({
        labRoot: files.labRoot,
        binary: 'bin/demo.exe',
        fridaPath: files.fridaPath,
        moduleName: '<main>',
        symbolName: 'x',
        outPath: join(files.labRoot, 'evidence'),
        runFrida: async () => { calls += 1 },
      }),
      /outside|lab|output/i,
    )
    assert.equal(calls, 0)
  } finally {
    await rm(files.root, { recursive: true, force: true })
  }
})

function resultHash(value) {
  return createHash('sha256').update(value).digest('hex')
}
