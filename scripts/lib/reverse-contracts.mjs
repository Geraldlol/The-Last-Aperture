import { createHash } from 'node:crypto'

import { stableJson } from './run-engine.mjs'

export const REVERSE_EVIDENCE_KIND = 'red-team-audit/reverse-evidence'
export const REVERSE_EVIDENCE_PROTOCOL = 'reverse-evidence-v1'
export const GHIDRA_REVERSE_PROFILE = 'ghidra-headless-fixed-export-v1'
export const FRIDA_REVERSE_PROFILE = 'native-call-trace-v1'
export const FRIDA_V2_REVERSE_PROFILE = 'native-call-trace-v2'
export const GHIDRA_GENERIC_PATH_SEGMENTS = Object.freeze([
  'api', 'auth', 'callback', 'login', 'logout', 'oauth', 'session', 'signin',
  'signout', 'sso', 'token',
])

const TOP_LEVEL_FIELDS = Object.freeze([
  'applied_to_audit_bundle',
  'artifact',
  'cleanup',
  'engine',
  'finished_at',
  'gaps',
  'kind',
  'limits',
  'observations',
  'profile_id',
  'protocol',
  'run_id',
  'schema_version',
  'security_verdict',
  'started_at',
  'status',
  'target_execution',
  'tool',
])
const HASH_PATTERN = /^[a-f0-9]{64}$/
const RUN_ID_PATTERN = /^reverse:[a-f0-9]{32}$/
const GAP_CODE_PATTERN = /^[A-Z][A-Z0-9_]{2,95}$/
const CONTROL_PATTERN = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u
const ARTIFACT_KINDS = new Set(['firmware-image', 'native-executable', 'shared-library', 'application-package'])
const GHIDRA_ARTIFACT_KINDS = new Set(['firmware-image', 'native-executable', 'shared-library'])
const FRIDA_V2_TARGET_EXECUTIONS = new Set([
  'LOCAL_LAB_SPAWN', 'LOCAL_PROCESS_ATTACH', 'USB_DEVICE_ATTACH', 'DEVICE_ID_ATTACH',
])
const STATUS_VALUES = new Set(['SUCCEEDED', 'PARTIAL', 'INCONCLUSIVE', 'FAILED'])
const GHIDRA_OFFSET = /^0x(?:0|[1-9a-f][0-9a-f]*)$/u
const GHIDRA_QUERY_NAME = /^[A-Za-z][A-Za-z0-9._~-]{0,63}$/u
const GHIDRA_NETWORK_APIS = new Set([
  'POSIX_CONNECT', 'POSIX_GETADDRINFO', 'POSIX_RECV', 'POSIX_SEND', 'POSIX_SOCKET',
  'LIBCURL_EASY_GETINFO', 'LIBCURL_EASY_INIT', 'LIBCURL_EASY_PERFORM',
  'LIBCURL_EASY_SETOPT', 'LIBCURL_HEADER_APPEND', 'OPENSSL_CONNECT', 'OPENSSL_READ',
  'OPENSSL_SET_SERVER_NAME', 'OPENSSL_VERIFY_RESULT', 'OPENSSL_WRITE',
  'WINHTTP_CONNECT', 'WINHTTP_OPEN', 'WINHTTP_OPEN_REQUEST', 'WINHTTP_QUERY_HEADERS',
  'WINHTTP_RECEIVE_RESPONSE', 'WINHTTP_SEND_REQUEST', 'WINHTTP_SET_CREDENTIALS',
  'WINHTTP_SET_OPTION', 'WININET_CONNECT', 'WININET_GET_COOKIE', 'WININET_OPEN',
  'WININET_OPEN_REQUEST', 'WININET_QUERY_INFO', 'WININET_READ', 'WININET_SEND_REQUEST',
  'WININET_SET_COOKIE', 'WINDOWS_CREDENTIAL_READ',
  'WINDOWS_SSPI_ACQUIRE_CREDENTIALS', 'WINDOWS_SSPI_INITIALIZE_CONTEXT',
])
const GHIDRA_AUTH_HINTS = new Set([
  'API_KEY_IDENTIFIER', 'AUTHORIZATION_HEADER_NAME', 'BASIC_SCHEME', 'BEARER_SCHEME',
  'COOKIE_HEADER_NAME', 'CSRF_IDENTIFIER', 'OAUTH_ACCESS_TOKEN_PARAMETER',
  'OAUTH_CLIENT_CREDENTIALS', 'OAUTH_FLOW', 'OAUTH_PKCE',
  'OAUTH_REFRESH_TOKEN_PARAMETER', 'OPENID_CONNECT', 'PASSWORD_FIELD_IDENTIFIER',
  'SAML_FLOW', 'SESSION_IDENTIFIER', 'SET_COOKIE_HEADER_NAME',
  'URL_USERINFO_CREDENTIALS', 'USERNAME_FIELD_IDENTIFIER',
  'WWW_AUTHENTICATE_HEADER_NAME',
])
const GHIDRA_STRUCTURAL_SEGMENTS = new Set(GHIDRA_GENERIC_PATH_SEGMENTS)

function fail(message) {
  const error = new Error(message)
  error.name = 'ReverseEvidenceError'
  error.code = 'REVERSE_EVIDENCE_INVALID'
  throw error
}

function exactObject(value, fields, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) fail(`${label} must be an object`)
  const actual = Object.keys(value).sort()
  const expected = [...fields].sort()
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    fail(`${label} contains a missing or unknown field`)
  }
}

function boundedText(value, label, { min = 1, max = 4096 } = {}) {
  if (typeof value !== 'string' || value.length < min || value.length > max || value.trim() !== value || CONTROL_PATTERN.test(value)) {
    fail(`${label} must be bounded plain text`)
  }
  return value
}

function canonicalTimestamp(value, label) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) {
    fail(`${label} must be a canonical timestamp`)
  }
  return Date.parse(value)
}

function relativeArtifactPath(value) {
  boundedText(value, 'artifact path', { max: 2048 })
  const normalized = value.replaceAll('\\', '/')
  if (
    normalized.startsWith('/')
    || /^[A-Za-z]:/.test(normalized)
    || normalized.split('/').some((part) => part === '' || part === '.' || part === '..')
  ) fail('artifact path must be a contained relative path')
}

function nonNegativeInteger(value, maximum = Number.MAX_SAFE_INTEGER) {
  return Number.isSafeInteger(value) && value >= 0 && value <= maximum
}

function exactStringList(value, predicate, maximum, label) {
  if (!Array.isArray(value) || value.length > maximum || new Set(value).size !== value.length || !value.every(predicate)) {
    fail(`${label} is invalid`)
  }
}

function ghidraPath(value) {
  boundedText(value, 'Ghidra endpoint path', { max: 512 })
  if (!value.startsWith('/')) fail('Ghidra endpoint path is invalid')
  const segments = value.split('/')
  if (segments.length > 34) fail('Ghidra endpoint path is invalid')
  for (const [index, segment] of segments.entries()) {
    if (index === 0 || segment === '') continue
    if (segment === '{...}' && index === segments.length - 1) continue
    if (['{hex}', '{integer}', '{segment}', '{uuid}', '{value}'].includes(segment)) continue
    if (/^v[0-9]+$/iu.test(segment) || GHIDRA_STRUCTURAL_SEGMENTS.has(segment.toLowerCase())) continue
    fail('Ghidra endpoint path contains an unredacted segment')
  }
}

function ghidraOrigin(item) {
  if (!['http', 'https'].includes(item.scheme)) fail('Ghidra endpoint scheme is invalid')
  boundedText(item.origin, 'Ghidra endpoint origin', { max: 512 })
  boundedText(item.host, 'Ghidra endpoint host', { max: 253 })
  let parsed
  try { parsed = new URL(item.origin) } catch { fail('Ghidra endpoint origin is invalid') }
  const normalizedHost = parsed.hostname.replace(/^\[|\]$/gu, '').toLowerCase()
  const effectivePort = parsed.port === '' ? (item.scheme === 'https' ? 443 : 80) : Number(parsed.port)
  if (
    parsed.protocol !== `${item.scheme}:`
    || parsed.origin !== item.origin
    || parsed.pathname !== '/'
    || parsed.username
    || parsed.password
    || normalizedHost !== item.host.toLowerCase()
    || effectivePort !== item.port
  ) fail('Ghidra endpoint origin metadata is inconsistent')
}

function assertGhidraObservations(observations, artifactHash, status) {
  if (observations.length === 0) {
    if (status === 'SUCCEEDED') fail('successful Ghidra evidence requires observations')
    return
  }
  if (!['SUCCEEDED', 'PARTIAL'].includes(status)) fail('failed or inconclusive Ghidra evidence cannot retain observations')
  const programFields = [
    'available_functions', 'compiler_spec_id', 'emitted_functions', 'executable_format',
    'executable_sha256', 'image_base', 'language_id', 'maximum_address',
    'minimum_address', 'truncated', 'type',
  ]
  const protocolFields = [
    'auth_hint_candidates', 'auth_hint_limit', 'auth_hints_truncated',
    'emitted_auth_hints', 'emitted_endpoints', 'emitted_network_imports',
    'endpoint_candidates', 'endpoint_limit', 'endpoints_truncated',
    'external_function_scan_truncated', 'external_functions_scanned',
    'matching_network_imports', 'network_import_limit', 'network_imports_truncated',
    'references_per_import_limit', 'string_record_limit', 'string_records_scanned',
    'string_scan_truncated', 'string_values_scanned', 'truncated_string_values', 'type',
  ]
  const program = observations[0]
  const protocol = observations[1]
  exactObject(program, programFields, 'Ghidra program observation')
  exactObject(protocol, protocolFields, 'Ghidra protocol observation')
  if (program.type !== 'program-summary' || protocol.type !== 'protocol-summary') fail('Ghidra summaries must be the first observations')
  for (const field of ['compiler_spec_id', 'executable_format', 'image_base', 'language_id', 'maximum_address', 'minimum_address']) {
    boundedText(program[field], `Ghidra program ${field}`, { max: 512 })
  }
  if (
    program.executable_sha256 !== artifactHash
    || !nonNegativeInteger(program.available_functions, 20_000_000)
    || !nonNegativeInteger(program.emitted_functions, 20_000)
    || program.available_functions < program.emitted_functions
    || typeof program.truncated !== 'boolean'
  ) fail('Ghidra program summary is invalid')
  if (
    protocol.network_import_limit !== 512
    || protocol.references_per_import_limit !== 128
    || protocol.string_record_limit !== 100_000
    || protocol.endpoint_limit !== 512
    || protocol.auth_hint_limit !== 512
  ) fail('Ghidra protocol limits are invalid')
  for (const field of [
    'auth_hint_candidates', 'emitted_auth_hints', 'emitted_endpoints',
    'emitted_network_imports', 'endpoint_candidates', 'external_functions_scanned',
    'matching_network_imports', 'string_records_scanned', 'string_values_scanned',
    'truncated_string_values',
  ]) if (!nonNegativeInteger(protocol[field], 2_000_000)) fail('Ghidra protocol count is invalid')
  for (const field of ['auth_hints_truncated', 'endpoints_truncated', 'external_function_scan_truncated', 'network_imports_truncated', 'string_scan_truncated']) {
    if (typeof protocol[field] !== 'boolean') fail('Ghidra protocol truncation state is invalid')
  }
  const typeOrder = new Map([['network-import', 0], ['static-endpoint', 1], ['auth-hint', 2], ['function', 3]])
  let previousOrder = -1
  const counts = { 'network-import': 0, 'static-endpoint': 0, 'auth-hint': 0, function: 0 }
  for (const item of observations.slice(2)) {
    if (!typeOrder.has(item?.type) || typeOrder.get(item.type) < previousOrder) fail('Ghidra observations are out of profile order')
    previousOrder = typeOrder.get(item.type)
    counts[item.type] += 1
    if (item.type === 'function') {
      exactObject(item, ['body_address_count', 'entry_point', 'external', 'name', 'thunk', 'type'], 'Ghidra function observation')
      boundedText(item.entry_point, 'Ghidra function entry point', { max: 512 })
      boundedText(item.name, 'Ghidra function name', { max: 512 })
      if (!nonNegativeInteger(item.body_address_count) || typeof item.external !== 'boolean' || typeof item.thunk !== 'boolean') fail('Ghidra function observation is invalid')
    } else if (item.type === 'network-import') {
      exactObject(item, ['api', 'callsite_offsets', 'references', 'references_scanned', 'references_truncated', 'type'], 'Ghidra network observation')
      if (!GHIDRA_NETWORK_APIS.has(item.api) || !nonNegativeInteger(item.references_scanned, 4_096) || typeof item.references_truncated !== 'boolean') fail('Ghidra network observation is invalid')
      exactStringList(item.callsite_offsets, (offset) => GHIDRA_OFFSET.test(offset), 128, 'Ghidra call-site offsets')
      if (!Array.isArray(item.references) || item.references.length > 128 || item.references.length > item.references_scanned) fail('Ghidra network references are invalid')
      const keys = new Set()
      for (const reference of item.references) {
        exactObject(reference, ['from_offset', 'kind'], 'Ghidra network reference')
        const key = `${reference.kind}:${reference.from_offset}`
        if (!GHIDRA_OFFSET.test(reference.from_offset ?? '') || !['CALL', 'DATA', 'OTHER'].includes(reference.kind) || keys.has(key)) fail('Ghidra network reference is invalid')
        keys.add(key)
      }
      const callsites = item.references.filter(({ kind }) => kind === 'CALL').map(({ from_offset: offset }) => offset)
      if (JSON.stringify(callsites) !== JSON.stringify(item.callsite_offsets)) fail('Ghidra call-site offsets do not match references')
    } else if (item.type === 'static-endpoint') {
      exactObject(item, ['candidate_truncated', 'host', 'origin', 'path_template', 'path_truncated', 'path_values_redacted', 'port', 'query_names', 'query_names_truncated', 'scheme', 'source_offsets', 'type', 'userinfo_present'], 'Ghidra endpoint observation')
      ghidraOrigin(item)
      ghidraPath(item.path_template)
      exactStringList(item.query_names, (name) => GHIDRA_QUERY_NAME.test(name), 32, 'Ghidra query names')
      exactStringList(item.source_offsets, (offset) => GHIDRA_OFFSET.test(offset), 16, 'Ghidra endpoint source offsets')
      for (const field of ['candidate_truncated', 'path_truncated', 'path_values_redacted', 'query_names_truncated', 'userinfo_present']) if (typeof item[field] !== 'boolean') fail('Ghidra endpoint truncation state is invalid')
    } else {
      exactObject(item, ['hint', 'source_offset', 'type'], 'Ghidra authentication observation')
      if (!GHIDRA_AUTH_HINTS.has(item.hint) || !(item.source_offset === 'UNMAPPED' || GHIDRA_OFFSET.test(item.source_offset ?? ''))) fail('Ghidra authentication observation is invalid')
    }
  }
  if (
    counts['network-import'] !== protocol.emitted_network_imports
    || counts['static-endpoint'] !== protocol.emitted_endpoints
    || counts['auth-hint'] !== protocol.emitted_auth_hints
    || counts.function > program.emitted_functions
    || (status === 'SUCCEEDED' && (
      counts.function !== program.emitted_functions
      || program.truncated
      || protocol.auth_hints_truncated
      || protocol.endpoints_truncated
      || protocol.network_imports_truncated
      || protocol.string_scan_truncated
    ))
  ) fail('Ghidra observation counts do not match their summaries')
}

function assertFridaObservations(observations, status) {
  if (observations.length === 0) {
    if (status === 'SUCCEEDED' || status === 'PARTIAL') fail('completed Frida evidence requires observations')
    return
  }
  if (!['SUCCEEDED', 'PARTIAL'].includes(status)) fail('failed or inconclusive Frida evidence cannot retain observations')
  let nonce
  let previousTime = -1
  let traceCount = 0
  for (const [index, item] of observations.entries()) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) fail('Frida observation must be an object')
    const common = ['event', 'frame_nonce', 'observed_at_ms', 'profile_id', 'schema_version']
    if (item.schema_version !== '1.0.0' || item.profile_id !== FRIDA_REVERSE_PROFILE || !HASH_PATTERN.test(item.frame_nonce ?? '') || !nonNegativeInteger(item.observed_at_ms)) fail('Frida observation metadata is invalid')
    nonce ??= item.frame_nonce
    if (item.frame_nonce !== nonce || item.observed_at_ms < previousTime) fail('Frida observation sequence is invalid')
    previousTime = item.observed_at_ms
    if (item.event === 'ready') {
      exactObject(item, [...common, 'module_name', 'module_relative_offset', 'symbol_name'], 'Frida ready observation')
      if (index !== 0) fail('Frida ready observation must be first')
      boundedText(item.module_name, 'Frida module name', { max: 256 })
      boundedText(item.symbol_name, 'Frida symbol name', { max: 512 })
      if (!/^0x(?:0|[1-9a-f][0-9a-f]*)$/u.test(item.module_relative_offset ?? '')) fail('Frida module-relative offset is invalid')
    } else if (item.event === 'enter' || item.event === 'leave') {
      exactObject(item, [...common, 'sequence', 'thread_id'], 'Frida call observation')
      traceCount += 1
      if (item.sequence !== traceCount || !nonNegativeInteger(item.thread_id)) fail('Frida call sequence is invalid')
    } else if (item.event === 'complete') {
      exactObject(item, [...common, 'events_emitted', 'truncated'], 'Frida complete observation')
      if (index !== observations.length - 1 || item.events_emitted !== traceCount || typeof item.truncated !== 'boolean') fail('Frida completion observation is invalid')
      if ((status === 'SUCCEEDED') !== !item.truncated) fail('Frida status does not match trace truncation')
    } else {
      fail('Frida observation event is invalid')
    }
  }
  if (observations[0].event !== 'ready' || observations.at(-1).event !== 'complete') fail('Frida evidence is missing its framed lifecycle')
}

function fridaV2TargetExecution(mode) {
  if (mode === 'local-spawn') return 'LOCAL_LAB_SPAWN'
  if (mode === 'local-pid' || mode === 'local-name') return 'LOCAL_PROCESS_ATTACH'
  if (mode === 'usb-pid' || mode === 'usb-name' || mode === 'usb-app-identifier') {
    return 'USB_DEVICE_ATTACH'
  }
  if (mode === 'device-pid' || mode === 'device-name' || mode === 'device-app-identifier') {
    return 'DEVICE_ID_ATTACH'
  }
  fail('Frida v2 target mode is invalid')
}

function assertFridaV2Pointer(value, retention) {
  exactObject(value, ['address', 'is_null', 'module_name', 'module_relative_offset', 'protection'], 'Frida v2 pointer metadata')
  const addressPattern = /^0x(?:0|[1-9a-f][0-9a-f]{0,15})$/u
  if (typeof value.is_null !== 'boolean'
    || (value.address !== null && (typeof value.address !== 'string' || !addressPattern.test(value.address)))
    || (value.module_name !== null && (typeof value.module_name !== 'string' || value.module_name.length < 1 || value.module_name.length > 256 || CONTROL_PATTERN.test(value.module_name)))
    || (value.module_relative_offset !== null && (typeof value.module_relative_offset !== 'string' || !addressPattern.test(value.module_relative_offset)))
    || (value.protection !== null && (typeof value.protection !== 'string' || !/^[r-][w-][x-]$/u.test(value.protection)))
    || ((retention === 'raw') !== (value.address !== null))
    || (value.is_null && (value.module_name !== null || value.module_relative_offset !== null || value.protection !== null))) {
    fail('Frida v2 pointer metadata is invalid')
  }
}

function fridaV2ScalarWidth(codec, capturedBytes) {
  if (codec === 'pointer') return capturedBytes === 4 || capturedBytes === 8
  if (codec === 'int8' || codec === 'uint8' || codec === 'bool') return capturedBytes === 1
  if (codec === 'int16' || codec === 'uint16') return capturedBytes === 2
  if (codec === 'int32' || codec === 'uint32') return capturedBytes === 4
  return capturedBytes === 8
}

function fridaV2IntegerInRange(value, codec) {
  const ranges = {
    int8: [-128, 127], uint8: [0, 255], int16: [-32768, 32767],
    uint16: [0, 65535], int32: [-2147483648, 2147483647], uint32: [0, 4294967295],
  }
  const [minimum, maximum] = ranges[codec]
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum
}

function assertFridaV2Capture(value) {
  exactObject(value, [
    'capture_id', 'captured_bytes', 'codec', 'error_code', 'pointer',
    'requested_bytes', 'retention', 'status', 'truncated', 'truncation_reason',
    'value', 'value_encoding',
  ], 'Frida v2 capture')
  const scalarCodecs = new Set(['pointer', 'int8', 'uint8', 'int16', 'uint16', 'int32', 'uint32', 'int64', 'uint64', 'bool'])
  const memoryCodecs = new Set(['utf8', 'utf16', 'bytes'])
  if (!/^[A-Za-z][A-Za-z0-9._:-]{0,127}$/u.test(value.capture_id ?? '')
    || (!scalarCodecs.has(value.codec) && !memoryCodecs.has(value.codec))
    || !['raw', 'sha256', 'metadata'].includes(value.retention)
    || !['CAPTURED', 'READ_FAILED'].includes(value.status)
    || (value.pointer !== null && (typeof value.pointer !== 'object' || Array.isArray(value.pointer)))
    || (value.requested_bytes !== null && (!Number.isSafeInteger(value.requested_bytes) || value.requested_bytes < 0 || value.requested_bytes > 4_294_967_295))
    || !Number.isSafeInteger(value.captured_bytes) || value.captured_bytes < 0 || value.captured_bytes > 65_536
    || typeof value.truncated !== 'boolean'
    || (value.truncation_reason !== null && !['DECLARED_MAX', 'RANGE_BOUNDARY', 'SESSION_BUDGET', 'FRAME_BUDGET'].includes(value.truncation_reason))
    || (value.truncated !== (value.truncation_reason !== null))
    || !['none', 'base64', 'number', 'decimal', 'boolean', 'pointer', 'sha256'].includes(value.value_encoding)
    || (value.error_code !== null && !['NULL_POINTER', 'LENGTH_READ_FAILED', 'MEMORY_READ_FAILED', 'VALUE_CONVERSION_FAILED', 'CAPTURE_BUDGET_EXHAUSTED'].includes(value.error_code))) {
    fail('Frida v2 capture metadata is invalid')
  }
  if (value.pointer !== null) assertFridaV2Pointer(value.pointer, value.retention)
  const expectsPointer = memoryCodecs.has(value.codec) || value.codec === 'pointer'
  if (expectsPointer !== (value.pointer !== null)) fail('Frida v2 capture pointer metadata is inconsistent')
  if (value.status === 'READ_FAILED') {
    if (value.error_code === null || value.value !== null || value.value_encoding !== 'none' || value.captured_bytes !== 0) {
      fail('Frida v2 failed capture is inconsistent')
    }
    return
  }
  if (value.error_code !== null) fail('Frida v2 captured value has an error')
  if (value.retention === 'metadata') {
    if (value.value !== null || value.value_encoding !== 'none' || value.captured_bytes !== 0) fail('Frida v2 metadata capture retained a value')
  } else if (value.retention === 'sha256') {
    if (value.value_encoding !== 'sha256' || !HASH_PATTERN.test(value.value ?? '')
      || (scalarCodecs.has(value.codec) && !fridaV2ScalarWidth(value.codec, value.captured_bytes))) {
      fail('Frida v2 digest capture is invalid')
    }
  } else if (memoryCodecs.has(value.codec)) {
    if (value.value_encoding !== 'base64' || typeof value.value !== 'string'
      || Buffer.from(value.value, 'base64').toString('base64') !== value.value
      || Buffer.from(value.value, 'base64').length !== value.captured_bytes) {
      fail('Frida v2 memory capture is not canonical base64')
    }
  } else if (value.codec === 'pointer') {
    if (value.value_encoding !== 'pointer'
      || value.pointer?.address !== value.value
      || !fridaV2ScalarWidth(value.codec, value.captured_bytes)) {
      fail('Frida v2 pointer capture is invalid')
    }
  } else if (value.codec === 'bool') {
    if (value.value_encoding !== 'boolean' || typeof value.value !== 'boolean' || value.captured_bytes !== 1) fail('Frida v2 boolean capture is invalid')
  } else if (value.codec === 'int64' || value.codec === 'uint64') {
    let integer
    try { integer = BigInt(value.value) } catch { integer = null }
    const minimum = value.codec === 'int64' ? -(2n ** 63n) : 0n
    const maximum = value.codec === 'int64' ? (2n ** 63n) - 1n : (2n ** 64n) - 1n
    if (value.value_encoding !== 'decimal'
      || typeof value.value !== 'string'
      || !/^-?(?:0|[1-9][0-9]*)$/u.test(value.value)
      || integer === null || integer < minimum || integer > maximum
      || value.captured_bytes !== 8) {
      fail('Frida v2 64-bit capture is invalid')
    }
  } else if (value.value_encoding !== 'number'
    || !fridaV2IntegerInRange(value.value, value.codec)
    || !fridaV2ScalarWidth(value.codec, value.captured_bytes)) {
    fail('Frida v2 integer capture is invalid')
  }
  if (memoryCodecs.has(value.codec) && (value.pointer === null || value.requested_bytes === null)) fail('Frida v2 memory capture metadata is incomplete')
  if (!memoryCodecs.has(value.codec) && value.requested_bytes !== null) fail('Frida v2 scalar capture carries a memory length')
}

function assertFridaV2Observations(observations, status, targetExecution, expectedArtifactSha256) {
  if (observations.length === 0) {
    if (status === 'SUCCEEDED' || status === 'PARTIAL') {
      fail('completed Frida v2 evidence requires observations')
    }
    return
  }
  if (!['SUCCEEDED', 'PARTIAL'].includes(status)) {
    fail('failed or inconclusive Frida v2 evidence cannot retain observations')
  }
  let nonce
  let planSha256
  let artifactSha256
  let targetMode
  let previousTime = -1
  let hooksExpected
  let hooksReady = 0
  let traceCount = 0
  let nextCallId = 1
  let captureAttempts = 0
  let captureFailures = 0
  let captureTruncations = 0
  let capturedPayloadBytes = 0
  const hookIds = new Set()
  const hookTargets = new Set()
  const activeCalls = new Map()
  const common = [
    'artifact_sha256', 'event', 'frame_nonce', 'observed_at_ms', 'plan_sha256',
    'profile_id', 'schema_version', 'target_mode',
  ]
  for (const [index, item] of observations.entries()) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      fail('Frida v2 observation must be an object')
    }
    if (item.schema_version !== '1.0.0'
      || item.profile_id !== FRIDA_V2_REVERSE_PROFILE
      || !HASH_PATTERN.test(item.frame_nonce ?? '')
      || !HASH_PATTERN.test(item.plan_sha256 ?? '')
      || !HASH_PATTERN.test(item.artifact_sha256 ?? '')
      || !nonNegativeInteger(item.observed_at_ms)) {
      fail('Frida v2 observation metadata is invalid')
    }
    nonce ??= item.frame_nonce
    planSha256 ??= item.plan_sha256
    artifactSha256 ??= item.artifact_sha256
    targetMode ??= item.target_mode
    if (item.frame_nonce !== nonce
      || item.plan_sha256 !== planSha256
      || item.artifact_sha256 !== artifactSha256
      || item.artifact_sha256 !== expectedArtifactSha256
      || item.target_mode !== targetMode
      || item.observed_at_ms < previousTime) {
      fail('Frida v2 observation bindings or sequence are invalid')
    }
    previousTime = item.observed_at_ms
    if (item.event === 'session-ready') {
      exactObject(item, [...common, 'hooks_expected'], 'Frida v2 session-ready observation')
      if (index !== 0
        || !Number.isSafeInteger(item.hooks_expected)
        || item.hooks_expected < 1
        || item.hooks_expected > 256) {
        fail('Frida v2 session-ready observation is invalid')
      }
      hooksExpected = item.hooks_expected
    } else if (item.event === 'hook-ready') {
      exactObject(item, [
        ...common, 'hook_id', 'module_name', 'module_relative_offset', 'resolved_address',
        'resolver_kind', 'symbol_name',
      ], 'Frida v2 hook-ready observation')
      if (hooksExpected === undefined || hooksReady >= hooksExpected || traceCount > 0) {
        fail('Frida v2 hook-ready observation order is invalid')
      }
      boundedText(item.hook_id, 'Frida v2 hook id', { max: 128 })
      if (!/^[A-Za-z][A-Za-z0-9._:-]{0,127}$/u.test(item.hook_id)) {
        fail('Frida v2 hook id is invalid')
      }
      if (!['export', 'module-offset', 'absolute', 'debug-symbol'].includes(item.resolver_kind)
        || (item.module_name !== null && (typeof item.module_name !== 'string' || item.module_name.length < 1 || item.module_name.length > 256 || CONTROL_PATTERN.test(item.module_name)))
        || (item.symbol_name !== null && (typeof item.symbol_name !== 'string' || item.symbol_name.length < 1 || item.symbol_name.length > 512 || CONTROL_PATTERN.test(item.symbol_name)))
        || (item.module_relative_offset !== null && !/^0x(?:0|[1-9a-f][0-9a-f]{0,15})$/u.test(item.module_relative_offset))
        || !/^0x[1-9a-f][0-9a-f]{0,15}$/u.test(item.resolved_address ?? '')) {
        fail('Frida v2 resolved hook metadata is invalid')
      }
      const target = `${item.resolver_kind}\u0000${item.module_name}\u0000${item.symbol_name}\u0000${item.resolved_address}`
      if (hookIds.has(item.hook_id) || hookTargets.has(target)) {
        fail('Frida v2 hook-ready observations must be unique')
      }
      hookIds.add(item.hook_id)
      hookTargets.add(target)
      hooksReady += 1
    } else if (item.event === 'enter' || item.event === 'leave') {
      exactObject(item, [...common, 'call_id', 'captures', 'hook_id', 'sequence', 'thread_id'], 'Frida v2 call observation')
      if (hooksExpected === undefined || hooksReady !== hooksExpected || !hookIds.has(item.hook_id)) {
        fail('Frida v2 call observation names an unavailable hook')
      }
      traceCount += 1
      if (item.sequence !== traceCount
        || !Number.isSafeInteger(item.call_id) || item.call_id < 1
        || !nonNegativeInteger(item.thread_id)) {
        fail('Frida v2 call observation sequence is invalid')
      }
      if (!Array.isArray(item.captures) || item.captures.length > 33) fail('Frida v2 call captures are invalid')
      const captureIds = new Set()
      for (const capture of item.captures) {
        assertFridaV2Capture(capture)
        if (captureIds.has(capture.capture_id)) fail('Frida v2 call capture IDs must be unique')
        captureIds.add(capture.capture_id)
        captureAttempts += 1
        if (capture.status === 'READ_FAILED') captureFailures += 1
        if (capture.truncated) captureTruncations += 1
        capturedPayloadBytes += capture.captured_bytes
      }
      if (captureAttempts > 10_000 || capturedPayloadBytes > 8 * 1024 * 1024) fail('Frida v2 capture totals exceed their profile limits')
      if (item.event === 'enter') {
        if (item.call_id !== nextCallId || activeCalls.has(item.call_id)) {
          fail('Frida v2 enter call id is invalid')
        }
        nextCallId += 1
        activeCalls.set(item.call_id, { hookId: item.hook_id, threadId: item.thread_id })
      } else {
        const active = activeCalls.get(item.call_id)
        if (!active || active.hookId !== item.hook_id || active.threadId !== item.thread_id) {
          fail('Frida v2 leave call id is invalid')
        }
        activeCalls.delete(item.call_id)
      }
    } else if (item.event === 'complete') {
      exactObject(item, [
        ...common, 'capture_attempts', 'capture_failures', 'capture_truncations',
        'captured_payload_bytes', 'events_emitted', 'hooks_detached', 'hooks_ready', 'truncated',
      ], 'Frida v2 complete observation')
      if (index !== observations.length - 1
        || hooksExpected === undefined
        || item.hooks_ready !== hooksExpected
        || item.hooks_detached !== hooksExpected
        || item.events_emitted !== traceCount
        || item.capture_attempts !== captureAttempts
        || item.capture_failures !== captureFailures
        || item.capture_truncations !== captureTruncations
        || item.captured_payload_bytes !== capturedPayloadBytes
        || typeof item.truncated !== 'boolean'
        || (activeCalls.size > 0 && item.truncated !== true)) {
        fail('Frida v2 completion observation is invalid')
      }
      if (targetExecution === 'LOCAL_LAB_SPAWN') {
        const completeSuccess = !item.truncated && item.capture_failures === 0 && item.capture_truncations === 0
        if ((status === 'SUCCEEDED') !== completeSuccess) {
          fail('Frida v2 local-spawn status does not match trace truncation')
        }
      } else if (status !== 'PARTIAL') {
        fail('Frida v2 attach observations require partial status')
      }
    } else {
      fail('Frida v2 observation event is invalid')
    }
  }
  if (observations[0].event !== 'session-ready'
    || observations.at(-1).event !== 'complete'
    || hooksReady !== hooksExpected
    || fridaV2TargetExecution(targetMode) !== targetExecution) {
    fail('Frida v2 evidence is missing or mismatches its framed lifecycle')
  }
}

export function assertValidReverseEvidence(value) {
  exactObject(value, TOP_LEVEL_FIELDS, 'reverse evidence')
  if (value.schema_version !== '1.0.0' || value.kind !== REVERSE_EVIDENCE_KIND || value.protocol !== REVERSE_EVIDENCE_PROTOCOL) {
    fail('reverse evidence version or kind is invalid')
  }
  if (!RUN_ID_PATTERN.test(value.run_id ?? '')) fail('reverse evidence run id is invalid')
  if (!['ghidra', 'frida'].includes(value.engine)) fail('reverse evidence engine is invalid')
  const expectedProfiles = value.engine === 'ghidra'
    ? new Set([GHIDRA_REVERSE_PROFILE])
    : new Set([FRIDA_REVERSE_PROFILE, FRIDA_V2_REVERSE_PROFILE])
  if (!expectedProfiles.has(value.profile_id)) fail('reverse evidence profile does not match its engine')

  const started = canonicalTimestamp(value.started_at, 'started_at')
  const finished = canonicalTimestamp(value.finished_at, 'finished_at')
  if (finished < started) fail('finished_at cannot precede started_at')

  exactObject(value.artifact, ['kind', 'path', 'sha256', 'size_bytes'], 'artifact')
  if (!ARTIFACT_KINDS.has(value.artifact.kind)) fail('artifact kind is unsupported')
  if (value.engine === 'ghidra' && !GHIDRA_ARTIFACT_KINDS.has(value.artifact.kind)) {
    fail('Ghidra artifact kind is unsupported')
  }
  if (value.profile_id === FRIDA_REVERSE_PROFILE && value.artifact.kind !== 'native-executable') {
    fail('Frida trace requires a native-executable artifact')
  }
  relativeArtifactPath(value.artifact.path)
  if (!HASH_PATTERN.test(value.artifact.sha256 ?? '')) fail('artifact sha256 is invalid')
  if (!Number.isSafeInteger(value.artifact.size_bytes) || value.artifact.size_bytes < 1 || value.artifact.size_bytes > 2 * 1024 * 1024 * 1024) {
    fail('artifact size is invalid')
  }

  exactObject(value.tool, ['invocation_sha256', 'name', 'version'], 'tool')
  const expectedTool = value.engine === 'ghidra' ? 'Ghidra' : 'Frida'
  if (value.tool.name !== expectedTool) fail('tool name does not match engine')
  if (value.tool.version !== null) boundedText(value.tool.version, 'tool version', { max: 256 })
  if (!HASH_PATTERN.test(value.tool.invocation_sha256 ?? '')) fail('tool invocation digest is invalid')

  exactObject(value.limits, ['max_observations', 'max_output_bytes', 'timeout_ms'], 'limits')
  if (!Number.isSafeInteger(value.limits.timeout_ms) || value.limits.timeout_ms < 1000 || value.limits.timeout_ms > 30 * 60 * 1000) {
    fail('timeout limit is invalid')
  }
  if (!Number.isSafeInteger(value.limits.max_output_bytes) || value.limits.max_output_bytes < 4096 || value.limits.max_output_bytes > 64 * 1024 * 1024) {
    fail('output limit is invalid')
  }
  if (!Number.isSafeInteger(value.limits.max_observations) || value.limits.max_observations < 1 || value.limits.max_observations > 10000) {
    fail('observation limit is invalid')
  }

  if (!STATUS_VALUES.has(value.status)) fail('reverse evidence status is invalid')
  if (value.engine === 'ghidra' && value.target_execution !== 'NOT_PERFORMED') {
    fail('target execution does not match engine')
  }
  if (value.profile_id === FRIDA_REVERSE_PROFILE && value.target_execution !== 'LOCAL_LAB_SPAWN') {
    fail('target execution does not match Frida v1')
  }
  if (value.profile_id === FRIDA_V2_REVERSE_PROFILE
    && !FRIDA_V2_TARGET_EXECUTIONS.has(value.target_execution)) {
    fail('target execution does not match Frida v2')
  }
  if (value.profile_id === FRIDA_V2_REVERSE_PROFILE
    && value.target_execution === 'LOCAL_LAB_SPAWN'
    && value.artifact.kind !== 'native-executable') {
    fail('Frida v2 local spawn requires a native-executable artifact')
  }
  if (value.security_verdict !== 'NOT_ASSESSED') fail('reverse evidence cannot claim a security verdict')
  if (value.applied_to_audit_bundle !== false) fail('reverse evidence is not an audit bundle input')

  if (!Array.isArray(value.observations) || value.observations.length > value.limits.max_observations) {
    fail('observations exceed their limit')
  }
  if (value.engine === 'ghidra') {
    assertGhidraObservations(value.observations, value.artifact.sha256, value.status)
  } else if (value.profile_id === FRIDA_REVERSE_PROFILE) {
    assertFridaObservations(value.observations, value.status)
  } else {
    assertFridaV2Observations(
      value.observations,
      value.status,
      value.target_execution,
      value.artifact.sha256,
    )
  }
  if (Buffer.byteLength(JSON.stringify(value.observations), 'utf8') > value.limits.max_output_bytes) {
    fail('observations exceed their byte limit')
  }

  if (!Array.isArray(value.gaps) || value.gaps.length > 256) fail('gaps are invalid')
  for (const gap of value.gaps) {
    exactObject(gap, ['code', 'message'], 'gap')
    if (!GAP_CODE_PATTERN.test(gap.code ?? '')) fail('gap code is invalid')
    boundedText(gap.message, 'gap message', { max: 2048 })
  }
  if (value.profile_id === FRIDA_V2_REVERSE_PROFILE
    && value.target_execution !== 'LOCAL_LAB_SPAWN'
    && !value.gaps.some(({ code }) => code === 'RUNTIME_ARTIFACT_IDENTITY_UNVERIFIED')) {
    fail('Frida v2 attach evidence must disclose the runtime artifact identity gap')
  }

  exactObject(value.cleanup, ['attempted', 'verified'], 'cleanup')
  if (typeof value.cleanup.attempted !== 'boolean' || typeof value.cleanup.verified !== 'boolean') {
    fail('cleanup flags must be boolean')
  }
  if (value.cleanup.verified && !value.cleanup.attempted) fail('cleanup cannot be verified before it is attempted')
  if (value.status === 'SUCCEEDED' && !value.cleanup.verified) fail('successful reverse evidence requires verified cleanup')

  if (Buffer.byteLength(stableJson(value, 0), 'utf8') > 64 * 1024 * 1024) fail('reverse evidence exceeds its byte limit')
  return value
}

export function canonicalReverseEvidence(value) {
  assertValidReverseEvidence(value)
  return stableJson(value, 2)
}

export function digestReverseEvidence(value) {
  return createHash('sha256').update(canonicalReverseEvidence(value)).digest('hex')
}
