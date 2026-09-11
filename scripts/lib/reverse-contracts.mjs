import { createHash } from 'node:crypto'

import { stableJson } from './run-engine.mjs'

export const REVERSE_EVIDENCE_KIND = 'red-team-audit/reverse-evidence'
export const REVERSE_EVIDENCE_PROTOCOL = 'reverse-evidence-v1'
export const GHIDRA_REVERSE_PROFILE = 'ghidra-headless-static-v1'
export const FRIDA_REVERSE_PROFILE = 'frida-native-call-trace-v1'

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
const ARTIFACT_KINDS = new Set(['firmware-image', 'native-executable', 'shared-library'])
const STATUS_VALUES = new Set(['SUCCEEDED', 'PARTIAL', 'INCONCLUSIVE', 'FAILED'])

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

function safeJsonValue(value, depth = 0) {
  if (depth > 10) return false
  if (value === null || typeof value === 'boolean') return true
  if (typeof value === 'number') return Number.isFinite(value)
  if (typeof value === 'string') return value.length <= 65536 && !CONTROL_PATTERN.test(value)
  if (Array.isArray(value)) return value.length <= 10000 && value.every((child) => safeJsonValue(child, depth + 1))
  if (!value || typeof value !== 'object') return false
  const entries = Object.entries(value)
  return entries.length <= 256
    && entries.every(([key, child]) => /^[A-Za-z0-9_.:-]{1,128}$/.test(key) && safeJsonValue(child, depth + 1))
}

export function assertValidReverseEvidence(value) {
  exactObject(value, TOP_LEVEL_FIELDS, 'reverse evidence')
  if (value.schema_version !== '1.0.0' || value.kind !== REVERSE_EVIDENCE_KIND || value.protocol !== REVERSE_EVIDENCE_PROTOCOL) {
    fail('reverse evidence version or kind is invalid')
  }
  if (!RUN_ID_PATTERN.test(value.run_id ?? '')) fail('reverse evidence run id is invalid')
  if (!['ghidra', 'frida'].includes(value.engine)) fail('reverse evidence engine is invalid')
  const expectedProfile = value.engine === 'ghidra' ? GHIDRA_REVERSE_PROFILE : FRIDA_REVERSE_PROFILE
  if (value.profile_id !== expectedProfile) fail('reverse evidence profile does not match its engine')

  const started = canonicalTimestamp(value.started_at, 'started_at')
  const finished = canonicalTimestamp(value.finished_at, 'finished_at')
  if (finished < started) fail('finished_at cannot precede started_at')

  exactObject(value.artifact, ['kind', 'path', 'sha256', 'size_bytes'], 'artifact')
  if (!ARTIFACT_KINDS.has(value.artifact.kind)) fail('artifact kind is unsupported')
  if (value.engine === 'frida' && value.artifact.kind !== 'native-executable') {
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
  const expectedExecution = value.engine === 'ghidra' ? 'NOT_PERFORMED' : 'LOCAL_LAB_SPAWN'
  if (value.target_execution !== expectedExecution) fail('target execution does not match engine')
  if (value.security_verdict !== 'NOT_ASSESSED') fail('reverse evidence cannot claim a security verdict')
  if (value.applied_to_audit_bundle !== false) fail('reverse evidence is not an audit bundle input')

  if (!Array.isArray(value.observations) || value.observations.length > value.limits.max_observations) {
    fail('observations exceed their limit')
  }
  if (!value.observations.every((item) => safeJsonValue(item))) fail('observation data is invalid')
  if (Buffer.byteLength(JSON.stringify(value.observations), 'utf8') > value.limits.max_output_bytes) {
    fail('observations exceed their byte limit')
  }

  if (!Array.isArray(value.gaps) || value.gaps.length > 256) fail('gaps are invalid')
  for (const gap of value.gaps) {
    exactObject(gap, ['code', 'message'], 'gap')
    if (!GAP_CODE_PATTERN.test(gap.code ?? '')) fail('gap code is invalid')
    boundedText(gap.message, 'gap message', { max: 2048 })
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
