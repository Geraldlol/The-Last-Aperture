import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'

import {
  assertValidReverseEvidence,
  canonicalReverseEvidence,
  digestReverseEvidence,
  GHIDRA_GENERIC_PATH_SEGMENTS,
} from '../scripts/lib/reverse-contracts.mjs'

const HASH = 'a'.repeat(64)

function ghidraObservations() {
  return [
    {
      type: 'program-summary', executable_format: 'Portable Executable (PE)',
      executable_sha256: HASH, language_id: 'x86:LE:64:default', compiler_spec_id: 'windows',
      image_base: '140000000', minimum_address: '140001000', maximum_address: '140001100',
      available_functions: 1, emitted_functions: 1, truncated: false,
    },
    {
      type: 'protocol-summary', network_import_limit: 512, references_per_import_limit: 128,
      external_functions_scanned: 1, matching_network_imports: 1, emitted_network_imports: 1,
      external_function_scan_truncated: false, network_imports_truncated: false,
      string_record_limit: 100000, string_records_scanned: 2, string_values_scanned: 2,
      truncated_string_values: 0, string_scan_truncated: false, endpoint_limit: 512,
      endpoint_candidates: 1, emitted_endpoints: 1, endpoints_truncated: false,
      auth_hint_limit: 512, auth_hint_candidates: 1, emitted_auth_hints: 1,
      auth_hints_truncated: false,
    },
    {
      type: 'network-import', api: 'WINHTTP_SEND_REQUEST',
      references: [{ from_offset: '0x1000', kind: 'CALL' }], callsite_offsets: ['0x1000'],
      references_scanned: 1, references_truncated: false,
    },
    {
      type: 'static-endpoint', scheme: 'https', origin: 'https://portal.example',
      host: 'portal.example', port: 443, path_template: '/api/session/{integer}',
      query_names: ['view'], source_offsets: ['0x2000'], userinfo_present: false,
      candidate_truncated: false, path_truncated: false, path_values_redacted: true,
      query_names_truncated: false,
    },
    { type: 'auth-hint', hint: 'SESSION_IDENTIFIER', source_offset: '0x2100' },
    { type: 'function', entry_point: '140001000', name: 'main', external: false, thunk: false, body_address_count: 12 },
  ]
}

function fridaObservations({ truncated = false } = {}) {
  const common = { schema_version: '1.0.0', profile_id: 'native-call-trace-v1', frame_nonce: 'f'.repeat(64) }
  return [
    { ...common, observed_at_ms: 1, event: 'ready', module_name: 'demo.exe', symbol_name: 'send_request', module_relative_offset: '0x1000' },
    { ...common, observed_at_ms: 2, event: 'enter', sequence: 1, thread_id: 7 },
    { ...common, observed_at_ms: 3, event: 'leave', sequence: 2, thread_id: 7 },
    { ...common, observed_at_ms: 4, event: 'complete', events_emitted: 2, truncated },
  ]
}

function evidence(overrides = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/reverse-evidence',
    protocol: 'reverse-evidence-v1',
    run_id: 'reverse:0123456789abcdef0123456789abcdef',
    engine: 'ghidra',
    profile_id: 'ghidra-headless-fixed-export-v1',
    started_at: '2026-09-11T10:00:00.000Z',
    finished_at: '2026-09-11T10:00:01.000Z',
    artifact: {
      kind: 'native-executable',
      path: 'bin/sample.exe',
      sha256: HASH,
      size_bytes: 4096,
    },
    tool: {
      name: 'Ghidra',
      version: '12.1.3',
      invocation_sha256: 'b'.repeat(64),
    },
    limits: {
      timeout_ms: 300000,
      max_output_bytes: 8 * 1024 * 1024,
      max_observations: 10000,
    },
    status: 'SUCCEEDED',
    target_execution: 'NOT_PERFORMED',
    security_verdict: 'NOT_ASSESSED',
    applied_to_audit_bundle: false,
    observations: ghidraObservations(),
    gaps: [],
    cleanup: { attempted: true, verified: true },
    ...overrides,
  }
}

test('reverse evidence is strict, canonical, and digest stable', () => {
  const value = evidence()
  assert.equal(assertValidReverseEvidence(value), value)
  const parsed = JSON.parse(canonicalReverseEvidence(value))
  assert.deepEqual(parsed, value)
  assert.match(digestReverseEvidence(value), /^[a-f0-9]{64}$/)
  assert.equal(digestReverseEvidence(structuredClone(value)), digestReverseEvidence(value))
})

test('reverse evidence admits bounded content-addressed tool components', () => {
  const components = [
    { role: 'ghidra-launcher', name: 'Ghidra headless launcher', sha256: '1'.repeat(64), size_bytes: 4096 },
    { role: 'java-compiler', name: 'javac.exe', sha256: '2'.repeat(64), size_bytes: 8192 },
    { role: 'java-archive-builder', name: 'jar.exe', sha256: '3'.repeat(64), size_bytes: 8192 },
    { role: 'windows-compatibility-agent', name: 'last-aperture-ghidra-agent.jar', sha256: '4'.repeat(64), size_bytes: 16384 },
  ]
  const value = evidence({ schema_version: '1.1.0', tool: { ...evidence().tool, components } })
  assert.equal(assertValidReverseEvidence(value), value)
  assert.throws(
    () => assertValidReverseEvidence(evidence({ tool: { ...evidence().tool, components } })),
    /1\.0\.0.*component/i,
  )
  assert.throws(
    () => assertValidReverseEvidence(evidence({ schema_version: '1.1.0' })),
    /1\.1\.0.*component/i,
  )
  assert.throws(
    () => assertValidReverseEvidence(evidence({ schema_version: '1.1.0',
      tool: { ...evidence().tool, components: [...components, { ...components[0] }] },
    })),
    /component role/i,
  )
  assert.throws(
    () => assertValidReverseEvidence(evidence({ schema_version: '1.1.0',
      tool: { ...evidence().tool, components: [{ ...components[0], path: 'C:\\private\\javac.exe' }] },
    })),
    /component.*field/i,
  )
})

test('engine, profile, execution, and artifact kind stay coupled', () => {
  assert.throws(() => assertValidReverseEvidence(evidence({ profile_id: 'native-call-trace-v1' })), /profile/i)
  assert.throws(() => assertValidReverseEvidence(evidence({ target_execution: 'LOCAL_LAB_SPAWN' })), /execution/i)
  assert.throws(() => assertValidReverseEvidence(evidence({ artifact: { ...evidence().artifact, kind: 'apk' } })), /artifact/i)

  const frida = evidence({
    engine: 'frida',
    profile_id: 'native-call-trace-v1',
    target_execution: 'LOCAL_LAB_SPAWN',
    tool: { name: 'Frida', version: '17.18.0', invocation_sha256: 'c'.repeat(64) },
    observations: fridaObservations(),
  })
  assert.equal(assertValidReverseEvidence(frida), frida)
  assert.throws(() => assertValidReverseEvidence({
    ...frida,
    artifact: { ...frida.artifact, kind: 'shared-library' },
  }), /artifact/i)
})

test('reverse evidence cannot claim a verdict, audit ingestion, or unverified success', () => {
  assert.throws(() => assertValidReverseEvidence(evidence({ security_verdict: 'CONFIRMED' })), /verdict/i)
  assert.throws(() => assertValidReverseEvidence(evidence({ applied_to_audit_bundle: true })), /audit bundle/i)
  assert.throws(() => assertValidReverseEvidence(evidence({ cleanup: { attempted: true, verified: false } })), /cleanup/i)
  assert.throws(() => assertValidReverseEvidence(evidence({ made_up: true })), /field/i)
})

test('reverse evidence rejects malformed and unbounded caller data', () => {
  for (const value of [
    evidence({ artifact: { ...evidence().artifact, sha256: 'bad' } }),
    evidence({ artifact: { ...evidence().artifact, path: '../escape.exe' } }),
    evidence({ limits: { ...evidence().limits, timeout_ms: 0 } }),
    evidence({ limits: { ...evidence().limits, max_output_bytes: 1024 * 1024 * 1024 } }),
    evidence({ observations: Array(10001).fill({ type: 'x' }) }),
    evidence({ gaps: [{ code: 'BAD CODE', message: 'x' }] }),
    evidence({ finished_at: '2026-09-11T09:59:59.000Z' }),
  ]) assert.throws(() => assertValidReverseEvidence(value))
})

test('reverse evidence rejects arbitrary observations and forged Frida frames', () => {
  assert.throws(() => assertValidReverseEvidence(evidence({
    observations: [{ type: 'program-summary', secret: 'raw-value' }],
  })), /observation|field|summary/i)

  const forgedNonce = fridaObservations()
  forgedNonce[2].frame_nonce = 'e'.repeat(64)
  assert.throws(() => assertValidReverseEvidence(evidence({
    engine: 'frida', profile_id: 'native-call-trace-v1', target_execution: 'LOCAL_LAB_SPAWN',
    tool: { name: 'Frida', version: '17.18.0', invocation_sha256: 'c'.repeat(64) },
    observations: forgedNonce,
  })), /sequence|nonce|observation/i)
})

test('Ghidra endpoint evidence admits only the exporter generic route segments', async () => {
  assert.deepEqual(GHIDRA_GENERIC_PATH_SEGMENTS, [
    'api', 'auth', 'callback', 'login', 'logout', 'oauth', 'session', 'signin',
    'signout', 'sso', 'token',
  ])
  const exporter = await readFile(
    new URL('../scripts/ghidra/LastApertureExport.java', import.meta.url),
    'utf8',
  )
  const exporterSet = exporter.match(/STRUCTURAL_PATH_SEGMENTS\s*=\s*Set\.of\(([\s\S]*?)\s*\);/u)
  assert.ok(exporterSet, 'bundled Ghidra exporter must declare its structural path set')
  assert.deepEqual(
    [...exporterSet[1].matchAll(/"([a-z]+)"/gu)].map((match) => match[1]),
    GHIDRA_GENERIC_PATH_SEGMENTS,
  )

  const generic = evidence()
  generic.observations.find(({ type }) => type === 'static-endpoint').path_template = (
    `/${GHIDRA_GENERIC_PATH_SEGMENTS.join('/')}/v1/{integer}`
  )
  assert.equal(assertValidReverseEvidence(generic), generic)

  for (const segment of [
    'workspacealpha', 'workspacebeta', 'workspacegamma', 'workspacedelta', 'workspaceepsilon', 'workspacezeta',
  ]) {
    const applicationSpecific = evidence()
    applicationSpecific.observations.find(({ type }) => type === 'static-endpoint').path_template = (
      `/api/${segment}/{integer}`
    )
    assert.throws(
      () => assertValidReverseEvidence(applicationSpecific),
      /unredacted segment/i,
    )
  }
})
