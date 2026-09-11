import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'
import { isMainModule } from './lib/main-module.mjs'

const CORPUS_URL = new URL('../benchmarks/source-check-cases.json', import.meta.url)
const RULES = new Set(['node-tls-env-disable', 'node-tls-option-disable'])
const OUTCOMES = new Set(['observation', 'no_observation', 'abstain'])
const STATUSES = new Set(['CHECKED', 'PARTIAL', 'NOT_ASSESSED'])
const SHA256 = /^[a-f0-9]{64}$/
const CASE_ID = /^[a-z0-9][a-z0-9-]{0,127}$/
const MAX_CASES = 256

function record(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function requireInput(condition, message) {
  if (!condition) throw new TypeError(`invalid source-check evaluation: ${message}`)
}

function validateCases(cases) {
  requireInput(Array.isArray(cases) && cases.length > 0 && cases.length <= MAX_CASES,
    `cases must be a non-empty array of at most ${MAX_CASES} entries`)
  const ids = new Set()
  for (const entry of cases) {
    requireInput(record(entry) && typeof entry.case_id === 'string' && CASE_ID.test(entry.case_id),
      'case ID is invalid')
    requireInput(!ids.has(entry.case_id), 'duplicate case ID')
    ids.add(entry.case_id)
    requireInput(typeof entry.path === 'string' && entry.path.length > 0 && entry.path.length <= 256,
      'case path is invalid')
    requireInput(typeof entry.source === 'string' && Buffer.byteLength(entry.source, 'utf8') <= 64 * 1024,
      'case source must be a bounded string')
    requireInput(record(entry.expectation) && OUTCOMES.has(entry.expectation.outcome),
      'case expectation is invalid')
    const expectedKeys = entry.expectation.outcome === 'observation'
      ? ['outcome', 'rule_id']
      : ['outcome']
    requireInput(Object.keys(entry.expectation).length === expectedKeys.length &&
      expectedKeys.every((key) => Object.hasOwn(entry.expectation, key)), 'case expectation fields are invalid')
    requireInput(entry.expectation.outcome !== 'observation' || RULES.has(entry.expectation.rule_id),
      'case expectation rule is invalid')
  }
  return ids
}

function validateOutcomes(outcomes, caseIds) {
  requireInput(Array.isArray(outcomes) && outcomes.length <= MAX_CASES, 'outcomes must be a bounded array')
  const byId = new Map()
  for (const entry of outcomes) {
    requireInput(record(entry) && typeof entry.case_id === 'string' && CASE_ID.test(entry.case_id),
      'outcome case ID is invalid')
    requireInput(!byId.has(entry.case_id), 'duplicate outcome case ID')
    const result = entry.result
    requireInput(record(result) && STATUSES.has(result.status), 'outcome status is invalid')
    requireInput(typeof result.path === 'string' && typeof result.source_sha256 === 'string' &&
      SHA256.test(result.source_sha256),
      'outcome source identity is invalid')
    requireInput(Array.isArray(result.observations) && result.observations.length <= 256,
      'outcome observations must be a bounded array')
    requireInput(result.observations.every((item) => record(item) && RULES.has(item.rule_id)),
      'outcome observation rule is invalid')
    requireInput(Array.isArray(result.gaps) && result.gaps.length <= 256 &&
      result.gaps.every((item) => record(item) && typeof item.code === 'string' &&
        /^[A-Z0-9_-]{1,128}$/.test(item.code)), 'outcome gaps are invalid')
    requireInput(result.status !== 'CHECKED' || result.gaps.length === 0,
      'CHECKED outcomes cannot contain gaps')
    requireInput(result.status === 'CHECKED' || result.gaps.length > 0,
      'unassessed or partial outcomes must report a gap')
    requireInput(result.status !== 'NOT_ASSESSED' || result.observations.length === 0,
      'NOT_ASSESSED outcomes cannot contain observations')
    byId.set(entry.case_id, result)
  }
  requireInput(byId.size === caseIds.size && [...caseIds].every((id) => byId.has(id)),
    'cases and outcomes must have the same case IDs')
  return byId
}

// Case-level expected-rule detection. A wrong/additional rule also contributes
// one false positive, so a case can contribute both TP + FP or FN + FP.
// Expected unsupported cases are never counted as true negatives.
// An unexpected abstention on an expected positive is still a false negative.
export function scoreSourceCheckEvaluation({ cases, outcomes, checkerVersion, corpusSha256 }) {
  const caseIds = validateCases(cases)
  const byId = validateOutcomes(outcomes, caseIds)
  requireInput(typeof checkerVersion === 'string' && /^\d+\.\d+\.\d+$/.test(checkerVersion),
    'checker version is invalid')
  requireInput(typeof corpusSha256 === 'string' && SHA256.test(corpusSha256), 'corpus digest is invalid')

  const confusion = { true_positives: 0, false_positives: 0, true_negatives: 0, false_negatives: 0 }
  const metrics = {
    confusion_matrix: confusion,
    expected_positive_cases: 0,
    expected_negative_cases: 0,
    expected_assessable_cases: 0,
    assessed_expected_assessable_cases: 0,
    expected_abstentions: 0,
    actual_abstentions: 0,
    correct_expected_abstentions: 0,
    unexpected_abstentions: 0,
    abstention_violations: 0,
    unexpected_rule_cases: 0,
    cases_with_gaps: 0,
    expectation_mismatches: 0,
  }
  const caseResults = cases.map((entry) => {
    const actual = byId.get(entry.case_id)
    requireInput(actual.path === entry.path, 'outcome path differs from its case')
    const observedRules = [...new Set(actual.observations.map(({ rule_id }) => rule_id))].sort()
    const actualOutcome = observedRules.length > 0
      ? 'observation'
      : actual.status === 'CHECKED' ? 'no_observation' : 'abstain'
    const expected = entry.expectation
    const abstained = actualOutcome === 'abstain'
    const unexpectedRules = observedRules.filter((rule) => rule !== expected.rule_id)
    let matched
    if (actual.gaps.length > 0) metrics.cases_with_gaps += 1
    if (abstained) metrics.actual_abstentions += 1

    if (expected.outcome === 'abstain') {
      metrics.expected_abstentions += 1
      matched = abstained
      if (matched) metrics.correct_expected_abstentions += 1
      else metrics.abstention_violations += 1
    } else {
      metrics.expected_assessable_cases += 1
      if (!abstained) metrics.assessed_expected_assessable_cases += 1
      else metrics.unexpected_abstentions += 1
      if (expected.outcome === 'observation') {
        metrics.expected_positive_cases += 1
        const detected = observedRules.includes(expected.rule_id)
        if (detected) confusion.true_positives += 1
        else confusion.false_negatives += 1
        if (unexpectedRules.length > 0) {
          metrics.unexpected_rule_cases += 1
          confusion.false_positives += 1
        }
        matched = detected && unexpectedRules.length === 0
      } else {
        metrics.expected_negative_cases += 1
        if (actualOutcome === 'observation') confusion.false_positives += 1
        if (actualOutcome === 'no_observation') confusion.true_negatives += 1
        matched = actualOutcome === 'no_observation'
      }
    }
    if (!matched) metrics.expectation_mismatches += 1
    return {
      case_id: entry.case_id,
      expected_outcome: expected.outcome,
      expected_rule_id: expected.rule_id ?? null,
      actual_outcome: actualOutcome,
      status: actual.status,
      observed_rules: observedRules,
      gap_codes: [...new Set(actual.gaps.map(({ code }) => code))].sort(),
      expectation_matched: matched,
    }
  })

  const precisionDenominator = confusion.true_positives + confusion.false_positives
  metrics.precision_denominator = precisionDenominator
  metrics.recall_denominator = metrics.expected_positive_cases
  metrics.precision = precisionDenominator === 0 ? null : confusion.true_positives / precisionDenominator
  metrics.recall = metrics.expected_positive_cases === 0
    ? null : confusion.true_positives / metrics.expected_positive_cases
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/source-check-evaluation',
    checker_version: checkerVersion,
    corpus_sha256: corpusSha256,
    case_count: cases.length,
    metric_unit: 'Case-level expected-rule detection. Wrong or additional rules contribute a false positive; a case may contribute both TP + FP or FN + FP. Expected abstentions are excluded from the confusion counts.',
    metrics,
    cases: caseResults,
  }
}

export async function evaluateCommittedSourceChecks() {
  const bytes = await readFile(CORPUS_URL)
  requireInput(bytes.length <= 256 * 1024, 'committed corpus exceeds the byte limit')
  const corpus = JSON.parse(bytes.toString('utf8'))
  requireInput(corpus.schema_version === '1.0.0' &&
    corpus.provenance?.classification === 'synthetic-development' &&
    corpus.provenance?.externally_validated === false &&
    corpus.provenance?.target_code_executed === false, 'committed corpus provenance is invalid')
  validateCases(corpus.cases)
  // Only this fixed, trusted checker module is imported. Corpus strings are data:
  // they are never imported, evaluated, launched, or resolved as target paths.
  const { checkJavaScriptSource, SOURCE_CHECK_VERSION } = await import('./lib/source-check.mjs')
  const outcomes = corpus.cases.map((entry) => {
    const result = checkJavaScriptSource({ path: entry.path, source: entry.source })
    requireInput(result.source_sha256 === createHash('sha256').update(entry.source, 'utf8').digest('hex'),
      'checker result does not bind to the case source bytes')
    return { case_id: entry.case_id, result }
  })
  return {
    ...scoreSourceCheckEvaluation({
      cases: corpus.cases,
      outcomes,
      checkerVersion: SOURCE_CHECK_VERSION,
      corpusSha256: createHash('sha256').update(bytes).digest('hex'),
    }),
    corpus_id: corpus.corpus_id,
    provenance: corpus.provenance,
    nonclaims: [
      'No real-world precision, recall, or security-clearance claim.',
      'Synthetic development examples are not an externally validated benchmark.',
      'Expected abstentions do not count as true negatives; missed positive abstentions remain false negatives.',
      'No target source was executed and no target services were contacted.',
    ],
  }
}

if (isMainModule(import.meta.url)) {
  try {
    const args = process.argv.slice(2)
    requireInput(args.length === 0 || (args.length === 1 && args[0] === '--json'),
      'usage: node scripts/evaluate-source-check.mjs [--json]')
    const result = await evaluateCommittedSourceChecks()
    if (args[0] === '--json') process.stdout.write(`${JSON.stringify(result, null, 2)}\n`)
    else {
      const { metrics } = result
      process.stdout.write(`Synthetic source-check evaluation: ${result.case_count} cases; ${metrics.expectation_mismatches} expectation mismatches.\n`)
      process.stdout.write(`Precision: ${metrics.precision ?? 'not defined'}; recall: ${metrics.recall ?? 'not defined'}.\n`)
      process.stdout.write(`Expected abstentions: ${metrics.expected_abstentions}; actual: ${metrics.actual_abstentions}; violations: ${metrics.abstention_violations}.\n`)
      process.stdout.write('Development corpus only; no real-world accuracy or security-clearance claim.\n')
    }
    if (result.metrics.expectation_mismatches > 0) process.exitCode = 1
  } catch {
    process.stderr.write('Source-check evaluation failed. Use only the committed corpus: node scripts/evaluate-source-check.mjs [--json].\n')
    process.exitCode = 1
  }
}
