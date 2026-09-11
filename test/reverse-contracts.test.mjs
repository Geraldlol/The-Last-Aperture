import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  assertValidReverseEvidence,
  canonicalReverseEvidence,
  digestReverseEvidence,
} from '../scripts/lib/reverse-contracts.mjs'

const HASH = 'a'.repeat(64)

function evidence(overrides = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/reverse-evidence',
    protocol: 'reverse-evidence-v1',
    run_id: 'reverse:0123456789abcdef0123456789abcdef',
    engine: 'ghidra',
    profile_id: 'ghidra-headless-static-v1',
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
    observations: [{ type: 'program-summary', function_count: 42 }],
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

test('engine, profile, execution, and artifact kind stay coupled', () => {
  assert.throws(() => assertValidReverseEvidence(evidence({ profile_id: 'frida-native-call-trace-v1' })), /profile/i)
  assert.throws(() => assertValidReverseEvidence(evidence({ target_execution: 'LOCAL_LAB_SPAWN' })), /execution/i)
  assert.throws(() => assertValidReverseEvidence(evidence({ artifact: { ...evidence().artifact, kind: 'apk' } })), /artifact/i)

  const frida = evidence({
    engine: 'frida',
    profile_id: 'frida-native-call-trace-v1',
    target_execution: 'LOCAL_LAB_SPAWN',
    tool: { name: 'Frida', version: '17.18.0', invocation_sha256: 'c'.repeat(64) },
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
