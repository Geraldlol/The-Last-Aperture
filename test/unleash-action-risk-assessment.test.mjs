import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { test } from 'node:test'

import Ajv2020 from 'ajv/dist/2020.js'

import {
  UNLEASH_ACTION_RISK_CATALOG,
  UNLEASH_ACTION_RISK_CONTROL_DOMAINS,
  UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL,
  UNLEASH_ACTION_RISK_OPERATIONAL_PROFILES,
  assessUnleashActionRisk,
  assertUnleashActionRiskConfirmation,
  assertValidUnleashActionRiskAssessment,
  assertValidUnleashActionRiskReceipt,
  createUnleashActionRiskReceipt,
  normalizeUnleashActionRiskProfile,
  selectUnleashActionRiskProfile,
} from '../scripts/lib/unleash-action-risk-assessment.mjs'

function actionFacts(overrides = {}) {
  return {
    tool_id: 'tool:https-recon',
    parameters: { method: 'HEAD' },
    target: 'https://example.test/',
    effect: 'OBSERVE',
    volume: {
      request_count: 1,
      max_parallel_requests: 1,
      max_requests_per_minute: 1,
      minimum_interval_ms: 0,
    },
    ...overrides,
  }
}

test('exports one reviewed, versioned catalog of bounded official source identifiers and URLs', () => {
  assert.equal(UNLEASH_ACTION_RISK_CATALOG.catalog_id, 'last-aperture/defender-action-risk')
  assert.equal(UNLEASH_ACTION_RISK_CATALOG.catalog_version, '1.0.0')
  assert.equal(UNLEASH_ACTION_RISK_CATALOG.reviewed_at, '2026-09-16')
  assert.equal(UNLEASH_ACTION_RISK_CATALOG.sources.length, 6)
  assert.equal(new Set(UNLEASH_ACTION_RISK_CATALOG.sources.map(({ source_id }) => source_id)).size, 6)
  assert.deepEqual(UNLEASH_ACTION_RISK_CATALOG.sources[0], {
    source_id: 'mitre-attack-detection-strategies',
    url: 'https://attack.mitre.org/detectionstrategies/',
  })
  for (const source of UNLEASH_ACTION_RISK_CATALOG.sources) {
    assert.match(source.source_id, /^[a-z0-9][a-z0-9-]{2,95}$/u)
    assert.match(source.url, /^https:\/\//u)
  }
  assert.doesNotMatch(JSON.stringify(UNLEASH_ACTION_RISK_CATALOG), /attack\.mitre\.org\/datasources/u)
  assert.equal(Object.isFrozen(UNLEASH_ACTION_RISK_CATALOG), true)
  assert.equal(Object.isFrozen(UNLEASH_ACTION_RISK_CATALOG.sources), true)
})

test('exports one frozen versioned model of generic defender detection patterns', () => {
  assert.equal(
    UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL.model_id,
    'last-aperture/generic-defender-detection-patterns',
  )
  assert.equal(UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL.model_version, '1.0.0')
  assert.deepEqual(
    UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL.patterns.map(({ pattern_id: patternId }) => patternId),
    [
      'pattern:single-request',
      'pattern:request-sequence',
      'pattern:high-rate-request-activity',
      'pattern:parallel-request-activity',
      'pattern:authenticated-access',
      'pattern:application-state-change',
      'pattern:workload-execution',
      'pattern:data-transfer',
    ],
  )
  const sourceIds = new Set(UNLEASH_ACTION_RISK_CATALOG.sources.map(({ source_id: sourceId }) => sourceId))
  const traits = new Set([
    'REQUEST_COUNT', 'REQUESTS_PER_MINUTE', 'MAX_PARALLEL_REQUESTS',
    'AUTHENTICATED_ACCESS', 'APPLICATION_STATE_CHANGE', 'WORKLOAD_EXECUTION', 'DATA_TRANSFER',
  ])
  for (const pattern of UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL.patterns) {
    assert.match(pattern.pattern_id, /^pattern:[a-z0-9]+(?:-[a-z0-9]+)*$/u)
    assert.ok(pattern.source_ids.every((sourceId) => sourceIds.has(sourceId)))
    assert.ok(pattern.control_domains.every(
      (control) => UNLEASH_ACTION_RISK_CONTROL_DOMAINS.includes(control),
    ))
    assert.ok(pattern.match_all.length > 0)
    for (const condition of pattern.match_all) {
      assert.equal(traits.has(condition.trait), true)
      assert.equal(['EQUALS', 'GREATER_THAN'].includes(condition.operator), true)
      assert.equal(Number.isSafeInteger(condition.value), true)
    }
    assert.equal(Object.isFrozen(pattern), true)
    assert.equal(Object.isFrozen(pattern.match_all), true)
  }
  assert.equal(Object.isFrozen(UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL), true)
  assert.equal(Object.isFrozen(UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL.patterns), true)
  assert.doesNotMatch(
    JSON.stringify(UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL),
    /evasion|bypass|stealth|vendor alert/iu,
  )
})

test('normalizes and selects only aggressive, balanced, and cautious profiles', () => {
  assert.deepEqual(UNLEASH_ACTION_RISK_OPERATIONAL_PROFILES, [
    'aggressive',
    'balanced',
    'cautious',
  ])
  assert.equal(normalizeUnleashActionRiskProfile('balanced'), 'balanced')
  assert.throws(
    () => selectUnleashActionRiskProfile(),
    (error) => error?.code === 'UNLEASH_ACTION_RISK_INPUT_INVALID',
  )
  assert.throws(
    () => selectUnleashActionRiskProfile(null),
    (error) => error?.code === 'UNLEASH_ACTION_RISK_INPUT_INVALID',
  )
  assert.equal(selectUnleashActionRiskProfile('cautious').operational_profile, 'cautious')
  assert.equal(
    selectUnleashActionRiskProfile({ operational_profile: 'aggressive' }).operational_profile,
    'aggressive',
  )
  const cautious = selectUnleashActionRiskProfile('cautious')
  assert.deepEqual(cautious.constraints, {
    max_parallel_requests: 1,
    max_requests_per_minute: 30,
    minimum_interval_ms: 2000,
    risk_confirmation_threshold: 25,
    noise_confirmation_threshold: 40,
  })
  assert.equal(Object.isFrozen(cautious.constraints), true)
})

test('classifies the exact inert HTTPS HEAD proposal across every defender control domain', () => {
  const assessment = assessUnleashActionRisk(actionFacts(), 'balanced')

  assert.deepEqual(
    assessment.control_signals.map(({ control }) => control),
    UNLEASH_ACTION_RISK_CONTROL_DOMAINS,
  )
  assert.equal(assessment.action_state, 'PROPOSED_INERT')
  assert.equal(assessment.executable, false)
  assert.equal(assessment.execution_authorized, false)
  assert.equal(assessment.scope, 'DEFENDER_OBSERVABILITY_ASSESSMENT')
  assert.equal(assessment.methodology, 'HEURISTIC_UNCALIBRATED')
  assert.equal(
    assessment.control_signal_score_semantics,
    'RELATIVE_EXPOSURE_NOT_ALERT_PROBABILITY',
  )
  assert.equal(assessment.telemetry_coverage, 'UNKNOWN')
  assert.equal(assessment.collection_precondition, 'UNKNOWN')
  assert.equal(assessment.catalog_id, UNLEASH_ACTION_RISK_CATALOG.catalog_id)
  assert.equal(assessment.catalog_version, UNLEASH_ACTION_RISK_CATALOG.catalog_version)
  assert.equal(assessment.reviewed_at, '2026-09-16')
  assert.deepEqual(assessment.sources, UNLEASH_ACTION_RISK_CATALOG.sources)
  assert.equal(
    assessment.detection_pattern_model_id,
    UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL.model_id,
  )
  assert.equal(
    assessment.detection_pattern_model_version,
    UNLEASH_ACTION_RISK_DETECTION_PATTERN_MODEL.model_version,
  )
  assert.deepEqual(assessment.matched_pattern_ids, ['pattern:single-request'])
  assert.equal(assessment.tool_id, 'tool:https-recon')
  assert.deepEqual(assessment.parameters, { method: 'HEAD' })
  assert.equal(assessment.target, 'https://example.test/')
  assert.equal(assessment.effect, 'OBSERVE')
  assert.match(assessment.action_fingerprint_sha256, /^[a-f0-9]{64}$/u)
  assert.equal(assessment.risk_score, 23)
  assert.equal(assessment.risk_level, 'LOW')
  assert.equal(assessment.noise_score, 43)
  assert.equal(assessment.noise_level, 'MODERATE')
  assert.equal(assessment.profile_constraints_met, true)
  assert.deepEqual(assessment.constraint_violations, [])
  assert.equal(assessment.controller_confirmation_required, false)
  assert.deepEqual(assessment.confirmation_reasons, [])
  assert.deepEqual(
    assessment.control_signals.find(({ control }) => control === 'NETWORK'),
    {
      control: 'NETWORK',
      relative_exposure_score: 45,
      relative_exposure_level: 'MEDIUM',
      potential_telemetry: ['NETWORK_CONNECTION_EVENT'],
      telemetry_coverage: 'UNKNOWN',
      collection_precondition: 'UNKNOWN',
      rationale: 'If relevant network telemetry collection is enabled at an observation point, one bounded request may be represented as connection or request telemetry; collection coverage has not been verified.',
    },
  )
  for (const control of assessment.control_signals) {
    assert.equal(control.telemetry_coverage, 'UNKNOWN')
    assert.equal(control.collection_precondition, 'UNKNOWN')
    assert.doesNotMatch(control.rationale, /\b(?:expected|likely|probability)\b/iu)
  }
  assert.equal(Object.isFrozen(assessment), true)
  assert.equal(Object.isFrozen(assessment.control_signals[0]), true)
  assert.doesNotThrow(() => assertValidUnleashActionRiskAssessment(assessment))
})

test('matches common action patterns deterministically without claiming an alert', () => {
  const sequence = assessUnleashActionRisk(actionFacts({
    tool_id: 'tool:bounded-observation',
    volume: {
      request_count: 120,
      max_parallel_requests: 4,
      max_requests_per_minute: 120,
      minimum_interval_ms: 500,
    },
  }), 'aggressive')
  assert.deepEqual(sequence.matched_pattern_ids, [
    'pattern:request-sequence',
    'pattern:high-rate-request-activity',
    'pattern:parallel-request-activity',
  ])

  const authenticated = assessUnleashActionRisk(actionFacts({
    tool_id: 'tool:authenticated-read',
    effect: 'AUTHENTICATED_REQUEST',
  }), 'aggressive')
  assert.deepEqual(authenticated.matched_pattern_ids, [
    'pattern:single-request',
    'pattern:authenticated-access',
  ])

  const stateChange = assessUnleashActionRisk(actionFacts({
    tool_id: 'tool:reversible-change',
    effect: 'MUTATE_REVERSIBLE',
  }), 'aggressive')
  assert.deepEqual(stateChange.matched_pattern_ids, [
    'pattern:single-request',
    'pattern:application-state-change',
  ])

  const execution = assessUnleashActionRisk(actionFacts({
    tool_id: 'tool:bounded-proof',
    effect: 'EXECUTE_PROOF',
  }), 'aggressive')
  assert.deepEqual(execution.matched_pattern_ids, [
    'pattern:single-request',
    'pattern:workload-execution',
  ])

  const transfer = assessUnleashActionRisk(actionFacts({
    tool_id: 'tool:canary-transfer',
    effect: 'EXFILTRATE_CANARY',
  }), 'aggressive')
  assert.deepEqual(transfer.matched_pattern_ids, [
    'pattern:single-request',
    'pattern:data-transfer',
  ])
  assert.equal(
    transfer.control_signals.find(({ control }) => control === 'IDENTITY').relative_exposure_score,
    0,
  )
  assert.equal(transfer.telemetry_coverage, 'UNKNOWN')
  assert.equal(transfer.collection_precondition, 'UNKNOWN')
})

test('request volume raises risk and noise monotonically', () => {
  const single = assessUnleashActionRisk(actionFacts({
    tool_id: 'tool:bounded-observation',
  }), 'aggressive')
  const bounded = assessUnleashActionRisk(actionFacts({
    tool_id: 'tool:bounded-observation',
    volume: {
      request_count: 12,
      max_parallel_requests: 2,
      max_requests_per_minute: 60,
      minimum_interval_ms: 1000,
    },
  }), 'aggressive')
  const larger = assessUnleashActionRisk(actionFacts({
    tool_id: 'tool:bounded-observation',
    volume: {
      request_count: 120,
      max_parallel_requests: 4,
      max_requests_per_minute: 120,
      minimum_interval_ms: 500,
    },
  }), 'aggressive')

  assert.ok(single.risk_score < bounded.risk_score)
  assert.ok(bounded.risk_score < larger.risk_score)
  assert.ok(single.noise_score < bounded.noise_score)
  assert.ok(bounded.noise_score < larger.noise_score)
})

test('rejects telemetry-coverage and relative-exposure tampering deterministically', () => {
  const claimedCoverage = structuredClone(assessUnleashActionRisk(actionFacts(), 'balanced'))
  claimedCoverage.telemetry_coverage = 'VERIFIED'
  assert.throws(
    () => assertValidUnleashActionRiskAssessment(claimedCoverage),
    (error) => error.code === 'UNLEASH_ACTION_RISK_ASSESSMENT_INVALID',
  )

  const changedExposure = structuredClone(assessUnleashActionRisk(actionFacts(), 'balanced'))
  changedExposure.control_signals[2].relative_exposure_score = 44
  assert.throws(
    () => assertValidUnleashActionRiskAssessment(changedExposure),
    (error) => error.code === 'UNLEASH_ACTION_RISK_ASSESSMENT_INVALID',
  )
})

test('profiles change confirmation tolerance without changing inherent scores', () => {
  const aggressive = assessUnleashActionRisk(actionFacts(), 'aggressive')
  const balanced = assessUnleashActionRisk(actionFacts(), 'balanced')
  const cautious = assessUnleashActionRisk(actionFacts(), 'cautious')

  assert.equal(aggressive.risk_score, balanced.risk_score)
  assert.equal(balanced.risk_score, cautious.risk_score)
  assert.equal(aggressive.noise_score, balanced.noise_score)
  assert.equal(balanced.noise_score, cautious.noise_score)
  assert.equal(aggressive.controller_confirmation_required, false)
  assert.equal(balanced.controller_confirmation_required, false)
  assert.equal(cautious.controller_confirmation_required, true)
  assert.deepEqual(cautious.confirmation_reasons, ['NOISE_THRESHOLD_MET'])
})

test('profile request constraints are visible and remain hard enforcement bounds', () => {
  const assessment = assessUnleashActionRisk(actionFacts({
    tool_id: 'tool:bounded-observation',
    volume: {
      request_count: 10,
      max_parallel_requests: 2,
      max_requests_per_minute: 60,
      minimum_interval_ms: 500,
    },
  }), 'cautious')

  assert.equal(assessment.profile_constraints_met, false)
  assert.deepEqual(assessment.constraint_violations, [
    'MAX_PARALLEL_REQUESTS_EXCEEDED',
    'MAX_REQUESTS_PER_MINUTE_EXCEEDED',
    'MINIMUM_INTERVAL_NOT_MET',
  ])
  assert.ok(assessment.confirmation_reasons.includes('PROFILE_CONSTRAINT_EXCEEDED'))
  const receipt = createUnleashActionRiskReceipt({
    action_id: 'http-recon-action:constraints',
    assessment,
  })
  const confirmation = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-action-risk-confirmation',
    action_id: receipt.action_id,
    assessment_sha256: receipt.assessment_sha256,
    receipt_sha256: receipt.receipt_sha256,
    confirmed: true,
  }
  assert.throws(
    () => assertUnleashActionRiskConfirmation({ receipt, confirmation }),
    (error) => error.code === 'UNLEASH_ACTION_RISK_PROFILE_CONSTRAINT_EXCEEDED',
  )
})

test('receipt is immutable and binds the exact action ID and assessment digest', () => {
  const assessment = assessUnleashActionRisk(actionFacts(), 'balanced')
  const receipt = createUnleashActionRiskReceipt({
    action_id: 'http-recon-action:planned-head',
    assessment,
  })

  assert.equal(receipt.kind, 'last-aperture/unleash-action-risk-receipt')
  assert.equal(receipt.action_id, 'http-recon-action:planned-head')
  assert.equal(receipt.action_fingerprint_sha256, assessment.action_fingerprint_sha256)
  assert.match(receipt.assessment_sha256, /^[a-f0-9]{64}$/u)
  assert.match(receipt.receipt_sha256, /^[a-f0-9]{64}$/u)
  assert.deepEqual(receipt.assessment, assessment)
  assert.equal(Object.isFrozen(receipt), true)
  assert.equal(Object.isFrozen(receipt.assessment), true)
  assert.doesNotThrow(() => assertValidUnleashActionRiskReceipt(
    receipt,
    { action_id: receipt.action_id },
  ))
  assert.throws(
    () => assertValidUnleashActionRiskReceipt(receipt, { action_id: 'http-recon-action:other' }),
    (error) => error.code === 'UNLEASH_ACTION_RISK_RECEIPT_BINDING_MISMATCH',
  )
})

test('confirmation enforcement requires an exact receipt-bound controller record', () => {
  const noConfirmation = createUnleashActionRiskReceipt({
    action_id: 'http-recon-action:balanced',
    assessment: assessUnleashActionRisk(actionFacts(), 'balanced'),
  })
  assert.equal(assertUnleashActionRiskConfirmation({
    receipt: noConfirmation,
    confirmation: null,
  }), noConfirmation)

  const required = createUnleashActionRiskReceipt({
    action_id: 'http-recon-action:cautious',
    assessment: assessUnleashActionRisk(actionFacts(), 'cautious'),
  })
  assert.throws(
    () => assertUnleashActionRiskConfirmation({ receipt: required, confirmation: null }),
    (error) => error.code === 'UNLEASH_ACTION_RISK_CONFIRMATION_REQUIRED',
  )
  const confirmation = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-action-risk-confirmation',
    action_id: required.action_id,
    assessment_sha256: required.assessment_sha256,
    receipt_sha256: required.receipt_sha256,
    confirmed: true,
  }
  assert.equal(assertUnleashActionRiskConfirmation({
    receipt: required,
    confirmation,
  }), required)

  const mismatched = { ...confirmation, action_id: 'http-recon-action:other' }
  assert.throws(
    () => assertUnleashActionRiskConfirmation({ receipt: required, confirmation: mismatched }),
    (error) => error.code === 'UNLEASH_ACTION_RISK_CONFIRMATION_MISMATCH',
  )
})

test('explicitly rejects prohibited profile names and rejects unknown names separately', () => {
  for (const name of ['evasive', 'bypass', 'stealth', 'stealthy', 'STEALTH']) {
    assert.throws(
      () => normalizeUnleashActionRiskProfile(name),
      (error) => error.code === 'UNLEASH_ACTION_RISK_PROFILE_FORBIDDEN',
    )
  }
  assert.throws(
    () => normalizeUnleashActionRiskProfile('fast'),
    (error) => error.code === 'UNLEASH_ACTION_RISK_PROFILE_INVALID',
  )
})

test('the shipped HTTPS action accepts only inert HEAD assessment semantics', () => {
  assert.throws(
    () => assessUnleashActionRisk(actionFacts({ parameters: { method: 'GET' } }), 'balanced'),
    (error) => error.code === 'UNLEASH_ACTION_RISK_ACTION_INVALID',
  )
  assert.throws(
    () => assessUnleashActionRisk(actionFacts({ effect: 'PROBE' }), 'balanced'),
    (error) => error.code === 'UNLEASH_ACTION_RISK_ACTION_INVALID',
  )
  assert.throws(
    () => assessUnleashActionRisk(actionFacts({
      volume: {
        request_count: 2,
        max_parallel_requests: 1,
        max_requests_per_minute: 2,
        minimum_interval_ms: 30000,
      },
    }), 'balanced'),
    (error) => error.code === 'UNLEASH_ACTION_RISK_ACTION_INVALID',
  )
})

test('rejects accessor-backed action parameters without invoking accessors', () => {
  let getterCalls = 0
  const parameters = {}
  Object.defineProperty(parameters, 'method', {
    enumerable: true,
    get() {
      getterCalls += 1
      return 'HEAD'
    },
  })
  assert.throws(
    () => assessUnleashActionRisk(actionFacts({ parameters }), 'balanced'),
    (error) => error.code === 'UNLEASH_ACTION_RISK_INPUT_INVALID',
  )
  assert.equal(getterCalls, 0)
})

test('assessment, receipt, and confirmation conform to one standalone schema', async () => {
  const schema = JSON.parse(await readFile(
    new URL('../schemas/unleash-action-risk-assessment.schema.json', import.meta.url),
    'utf8',
  ))
  const ajv = new Ajv2020({
    allErrors: true,
    strict: true,
    strictRequired: false,
    strictTypes: false,
    validateFormats: false,
  })
  const validate = ajv.compile(schema)
  const assessment = assessUnleashActionRisk(actionFacts(), 'cautious')
  const receipt = createUnleashActionRiskReceipt({
    action_id: 'http-recon-action:schema',
    assessment,
  })
  const confirmation = {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-action-risk-confirmation',
    action_id: receipt.action_id,
    assessment_sha256: receipt.assessment_sha256,
    receipt_sha256: receipt.receipt_sha256,
    confirmed: true,
  }

  for (const document of [assessment, receipt, confirmation]) {
    assert.equal(validate(document), true, JSON.stringify(validate.errors))
  }
  assert.doesNotMatch(
    JSON.stringify({ assessment, receipt }),
    /evasion|bypass|stealth|avoid.{0,24}(?:alert|detect|logging)/iu,
  )
  const executable = structuredClone(assessment)
  executable.executable = true
  assert.equal(validate(executable), false)
})
