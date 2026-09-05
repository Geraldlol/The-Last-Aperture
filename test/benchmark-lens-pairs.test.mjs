import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { parseLens } from '../scripts/lib/frontmatter.mjs'

const pairs = [
  ['ai-model-and-mlops-security', 0, 'training_dataset.py'],
  ['failure-semantics-and-resilience', 0, 'failure_policy.py'],
  ['native-and-memory-safety', 0, 'native_frame.c'],
  ['hipaa-and-phi', 4, 'patient_chart_audit.py'],
  ['privacy-and-data-protection', 2, 'privacy_consent.py'],
  ['security-observability-and-response', 0, 'security_grant.ts'],
  ['threat-modeling', 9, 'internal_identity.py'],
  ['embedded-iot-ot-security', 0, 'device_enrollment.py'],
  ['desktop-and-thick-client-security', 0, 'desktop_update.js'],
  ['smart-contract-and-web3-security', 0, 'AssetSweep.sol'],
]

test('each newly represented lens has a detector-aligned vulnerable and clean pair', () => {
  for (const [lensName, detectorIndex, fixtureName] of pairs) {
    const lensText = readFileSync(
      new URL(`../skills/red-team-audit/lenses/${lensName}.md`, import.meta.url),
      'utf8',
    )
    const lens = parseLens(lensText, `${lensName}.md`)
    const detector = lens.detectors[detectorIndex]
    assert.ok(detector, `${lensName} detector ${detectorIndex} must exist`)

    const vulnerable = readFileSync(
      new URL(`../fixtures/vulnerable/${fixtureName}`, import.meta.url),
      'utf8',
    )
    const clean = readFileSync(
      new URL(`../fixtures/clean/${fixtureName}`, import.meta.url),
      'utf8',
    )

    assert.ok(
      vulnerable.includes(detector.match.trim()),
      `${fixtureName} must contain ${lensName}'s detector match`,
    )
    assert.ok(
      clean.includes(detector.nomatch.trim()),
      `${fixtureName} must contain ${lensName}'s detector nomatch`,
    )
  }
})
