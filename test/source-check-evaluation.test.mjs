import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  evaluateCommittedSourceChecks,
  scoreSourceCheckEvaluation,
} from '../scripts/evaluate-source-check.mjs'

const ENV_RULE = 'node-tls-env-disable'
const OPTION_RULE = 'node-tls-option-disable'
const SHA = 'a'.repeat(64)

function example(caseId, expectation, ruleId = ENV_RULE) {
  return {
    case_id: caseId,
    path: `${caseId}.js`,
    source: '// Inert evaluation input. Never executed.',
    expectation: expectation === 'observation'
      ? { outcome: expectation, rule_id: ruleId }
      : { outcome: expectation },
    rationale: 'Synthetic metric test, not a source-checker fixture.',
  }
}

function outcome(caseId, { status = 'CHECKED', rules = [], gaps = [] } = {}) {
  return {
    case_id: caseId,
    result: {
      path: `${caseId}.js`,
      source_sha256: SHA,
      status,
      observations: rules.map((rule_id) => ({ rule_id })),
      gaps: gaps.map((code) => ({ code, message: 'Synthetic gap.' })),
    },
  }
}

function score(cases, outcomes) {
  return scoreSourceCheckEvaluation({
    cases,
    outcomes,
    checkerVersion: '1.0.0',
    corpusSha256: SHA,
  })
}

test('source-check metrics expose deliberate misses, false positives, and abstention violations', () => {
  const result = score([
    example('positive', 'observation'),
    example('missed', 'observation'),
    example('negative', 'no_observation'),
    example('unsupported', 'abstain'),
    example('false-clearance', 'abstain'),
  ], [
    outcome('positive', { rules: [ENV_RULE] }),
    outcome('missed'),
    outcome('negative', { rules: [ENV_RULE] }),
    outcome('unsupported', { status: 'NOT_ASSESSED', gaps: ['UNSUPPORTED_LANGUAGE'] }),
    outcome('false-clearance'),
  ])

  assert.deepEqual(result.metrics.confusion_matrix, {
    true_positives: 1,
    false_positives: 1,
    true_negatives: 0,
    false_negatives: 1,
  })
  assert.equal(result.metrics.expected_assessable_cases, 3)
  assert.equal(result.metrics.assessed_expected_assessable_cases, 3)
  assert.equal(result.metrics.expected_abstentions, 2)
  assert.equal(result.metrics.actual_abstentions, 1)
  assert.equal(result.metrics.correct_expected_abstentions, 1)
  assert.equal(result.metrics.abstention_violations, 1)
  assert.equal(result.metrics.precision, 0.5)
  assert.equal(result.metrics.recall, 0.5)
  assert.equal(result.metrics.expectation_mismatches, 3)
})

test('an unexpected positive-case abstention remains a false negative in recall', () => {
  const result = score([example('missed', 'observation')], [
    outcome('missed', { status: 'PARTIAL', gaps: ['UNCERTAIN_BINDING'] }),
  ])
  assert.equal(result.metrics.confusion_matrix.false_negatives, 1)
  assert.equal(result.metrics.unexpected_abstentions, 1)
  assert.equal(result.metrics.assessed_expected_assessable_cases, 0)
  assert.equal(result.metrics.recall, 0)
  assert.equal(result.metrics.precision, null)
})

test('negative-case abstentions and unsupported cases never become true negatives', () => {
  const result = score([
    example('negative', 'no_observation'),
    example('unsupported', 'abstain'),
  ], [
    outcome('negative', { status: 'PARTIAL', gaps: ['UNCERTAIN_BINDING'] }),
    outcome('unsupported', { status: 'NOT_ASSESSED', gaps: ['UNSUPPORTED_LANGUAGE'] }),
  ])
  assert.equal(result.metrics.confusion_matrix.true_negatives, 0)
  assert.equal(result.metrics.unexpected_abstentions, 1)
  assert.equal(result.metrics.precision, null)
  assert.equal(result.metrics.recall, null)
  assert.equal(result.metrics.expectation_mismatches, 1)
})

test('wrong-rule observations do not satisfy a labeled positive', () => {
  const result = score([example('positive', 'observation')], [
    outcome('positive', { rules: [OPTION_RULE] }),
  ])
  assert.equal(result.metrics.confusion_matrix.true_positives, 0)
  assert.equal(result.metrics.confusion_matrix.false_positives, 1)
  assert.equal(result.metrics.confusion_matrix.false_negatives, 1)
  assert.equal(result.metrics.unexpected_rule_cases, 1)
  assert.equal(result.metrics.expectation_mismatches, 1)
  assert.equal(result.metrics.precision, 0)
})

test('extra observations are reported even when the expected rule is detected', () => {
  const result = score([example('positive', 'observation')], [
    outcome('positive', { rules: [ENV_RULE, OPTION_RULE] }),
  ])
  assert.equal(result.metrics.confusion_matrix.true_positives, 1)
  assert.equal(result.metrics.confusion_matrix.false_positives, 1)
  assert.equal(result.metrics.unexpected_rule_cases, 1)
  assert.equal(result.metrics.expectation_mismatches, 1)
  assert.equal(result.metrics.precision, 0.5)
})

test('source-check evaluation rejects incomplete, duplicate, or contradictory inputs', () => {
  const cases = [example('positive', 'observation')]
  assert.throws(() => score([], []), /non-empty/)
  assert.throws(() => score(cases, []), /same case IDs/)
  assert.throws(() => score(cases, [outcome('different')]), /same case IDs/)
  assert.throws(() => score([...cases, ...cases], [outcome('positive')]), /duplicate/)
  assert.throws(() => score(cases, [outcome('positive'), outcome('positive')]), /duplicate/)
  assert.throws(() => score(cases, [outcome('positive', { status: 'UNKNOWN' })]), /status/)
  assert.throws(() => score(cases, [outcome('positive', { gaps: ['UNSUPPORTED'] })]), /CHECKED/)
  assert.throws(() => score(cases, [outcome('positive', { status: 'PARTIAL' })]), /gap/)
  assert.throws(() => score(cases, [outcome('positive', { rules: ['unknown-rule'] })]), /rule/)
  const missingCaseId = structuredClone(cases)
  delete missingCaseId[0].case_id
  const missingOutcomeId = [outcome('positive')]
  delete missingOutcomeId[0].case_id
  assert.throws(() => score(missingCaseId, missingOutcomeId), /case ID/)
  const coercedHash = [outcome('positive')]
  coercedHash[0].result.source_sha256 = [SHA]
  assert.throws(() => score(cases, coercedHash), /source identity/)
  const malformed = structuredClone(cases)
  malformed[0].expectation = { outcome: 'no_observation', rule_id: ENV_RULE }
  assert.throws(() => score(malformed, [outcome('positive')]), /expectation/)
})

test('the committed corpus is explicit synthetic-development evidence with positive, negative, and abstention cases', async () => {
  const corpus = JSON.parse(await readFile(new URL('../benchmarks/source-check-cases.json', import.meta.url), 'utf8'))
  assert.equal(corpus.provenance.classification, 'synthetic-development')
  assert.equal(corpus.provenance.externally_validated, false)
  assert.equal(corpus.provenance.target_code_executed, false)
  assert.equal(corpus.cases.length, 24)
  for (const label of ['observation', 'no_observation', 'abstain']) {
    assert.equal(corpus.cases.filter((entry) => entry.expectation.outcome === label).length, 8)
  }
})

test('the fixed-corpus evaluation reports versioned provenance without claiming independent security validation', async () => {
  const result = await evaluateCommittedSourceChecks()
  assert.equal(result.provenance.classification, 'synthetic-development')
  assert.equal(result.provenance.externally_validated, false)
  assert.equal(result.provenance.target_code_executed, false)
  assert.equal(result.case_count, 24)
  assert.match(result.corpus_sha256, /^[a-f0-9]{64}$/)
  assert.match(result.checker_version, /^\d+\.\d+\.\d+$/)
  assert.equal(result.cases.length, 24)
  assert.equal(result.cases.some((entry) => 'source' in entry), false)
  assert.equal(result.nonclaims.includes('No real-world precision, recall, or security-clearance claim.'), true)
  assert.equal(result.metrics.expectation_mismatches, 0,
    'fixed labeled corpus expectations must not silently regress')
})

test('the evaluation CLI rejects arbitrary corpus locations without echoing them', () => {
  const script = fileURLToPath(new URL('../scripts/evaluate-source-check.mjs', import.meta.url))
  const child = spawnSync(process.execPath, [script, '--corpus', 'https://untrusted.example/private-marker'], {
    cwd: tmpdir(), encoding: 'utf8', windowsHide: true, timeout: 10_000,
  })
  assert.equal(child.error, undefined)
  assert.equal(child.status, 1)
  assert.equal(child.stdout, '')
  assert.match(child.stderr, /Use only the committed corpus/)
  assert.equal(child.stderr.includes('private-marker'), false)
})

test('the evaluation CLI locates its fixed corpus independently of the working directory', () => {
  const script = fileURLToPath(new URL('../scripts/evaluate-source-check.mjs', import.meta.url))
  const child = spawnSync(process.execPath, [script, '--json'], {
    cwd: tmpdir(), encoding: 'utf8', windowsHide: true, timeout: 10_000,
  })
  assert.equal(child.error, undefined)
  const result = JSON.parse(child.stdout)
  assert.equal(result.case_count, 24)
  assert.equal(child.status, result.metrics.expectation_mismatches > 0 ? 1 : 0)
  assert.equal(child.stderr, '')
})
