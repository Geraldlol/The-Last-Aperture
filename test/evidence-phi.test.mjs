import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  PHI_RETENTION_DAYS,
  PHI_SCOPES,
  redactToMetadata,
  resolvePhiPolicy,
} from '../scripts/lib/evidence-phi.mjs'

test('an attested absence of PHI captures everything with no marking', () => {
  const policy = resolvePhiPolicy({ phiScope: 'none' })
  assert.equal(policy.capture_contents, true)
  assert.equal(policy.phi_bearing, false)
  assert.equal(policy.retention_days, null)
})

test('possible PHI is metadata-only until an explicit flag says otherwise', () => {
  const defaulted = resolvePhiPolicy({ phiScope: 'possible' })
  assert.equal(defaulted.capture_contents, false)
  assert.equal(defaulted.phi_bearing, false)

  const opted = resolvePhiPolicy({ phiScope: 'possible', captureContents: true })
  assert.equal(opted.capture_contents, true)
  assert.equal(opted.phi_bearing, true)
})

test('confirmed PHI needs the flag and an acknowledgment, and carries a retention limit', () => {
  assert.equal(resolvePhiPolicy({ phiScope: 'confirmed' }).capture_contents, false)
  assert.throws(
    () => resolvePhiPolicy({ phiScope: 'confirmed', captureContents: true }),
    /acknowledg/i,
  )
  const opted = resolvePhiPolicy({ phiScope: 'confirmed', captureContents: true, acknowledged: true })
  assert.equal(opted.capture_contents, true)
  assert.equal(opted.phi_bearing, true)
  assert.equal(opted.retention_days, PHI_RETENTION_DAYS)
})

test('an unknown scope is refused rather than defaulted to the permissive one', () => {
  assert.deepEqual(PHI_SCOPES, ['none', 'possible', 'confirmed'])
  assert.throws(() => resolvePhiPolicy({ phiScope: 'probably-fine' }), /phi_scope/i)
  assert.throws(() => resolvePhiPolicy({}), /phi_scope/i)
})

test('redaction keeps key names and shapes and drops every value', () => {
  const secret = {
    kind: 'Secret',
    metadata: { name: 'patient-db', namespace: 'clinical' },
    data: {
      DB_PASSWORD: 'aHVudGVyMg==',
      PATIENT_EXPORT: 'TXJzIFJvc2EgTGVl',
    },
  }
  const redacted = redactToMetadata(secret)
  assert.equal(redacted.kind, 'Secret')
  assert.deepEqual(Object.keys(redacted.data).sort(), ['DB_PASSWORD', 'PATIENT_EXPORT'])
  for (const value of Object.values(redacted.data)) {
    assert.equal(typeof value, 'object')
    assert.equal(typeof value.bytes, 'number')
    assert.match(value.sha256, /^[0-9a-f]{64}$/)
    assert.equal(Object.hasOwn(value, 'value'), false)
  }
  const serialized = JSON.stringify(redacted)
  assert.equal(serialized.includes('aHVudGVyMg=='), false)
  assert.equal(serialized.includes('TXJzIFJvc2EgTGVl'), false)
})

test('a value that merely looks structural is still redacted', () => {
  // Base64 PHI is frequently pure alphanumeric and indistinguishable from a
  // resource kind by inspection, so structure is decided by field name only.
  const redacted = redactToMetadata({
    kind: 'Secret',
    data: { PATIENT: 'TXJzIFJvc2EgTGVl', NOTE: 'Diagnosis' },
  })
  assert.equal(redacted.kind, 'Secret')
  assert.equal(typeof redacted.data.PATIENT, 'object')
  assert.equal(typeof redacted.data.NOTE, 'object')
  assert.equal(JSON.stringify(redacted).includes('Diagnosis'), false)
})

test('redaction preserves the structural facts an audit reasons about', () => {
  const redacted = redactToMetadata({
    spec: { replicas: 3, containers: [{ name: 'api' }, { name: 'sidecar' }] },
  })
  assert.equal(redacted.spec.containers.length, 2)
  assert.equal(typeof redacted.spec.replicas, 'object')
  assert.equal(redacted.spec.replicas.bytes, 1)
})

test('redaction is bounded and cannot be made to recurse forever', () => {
  const deep = {}
  let cursor = deep
  for (let index = 0; index < 200; index += 1) {
    cursor.next = {}
    cursor = cursor.next
  }
  assert.doesNotThrow(() => redactToMetadata(deep, { maxDepth: 8 }))
  assert.equal(JSON.stringify(redactToMetadata(deep, { maxDepth: 8 })).includes('[depth]'), true)
})
