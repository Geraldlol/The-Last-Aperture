import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import {
  EVALUATION_LIMITS,
  EvaluationInputError,
  evaluateThresholds,
  jaccardSimilarity,
  scoreEvaluation,
  scoreFingerprintStability,
  scoreRepeatedEvaluations,
} from '../scripts/lib/evaluation.mjs'

const EXPECTED = [
  {
    case_id: 'C-001',
    expectation: 'clean',
    topic: 'jwt-jws-and-jwks-verification',
  },
  {
    case_id: 'C-002',
    expectation: 'clean',
    topic: 'legacy-hash-and-cipher-primitives',
  },
  {
    case_id: 'V-001',
    expectation: 'vulnerable',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    expected_severity: 'High',
  },
  {
    case_id: 'V-002',
    expectation: 'vulnerable',
    lens: 'web-and-api',
    topic: 'injection-sql-nosql-orm',
    expected_severity: 'Critical',
    also_acceptable_topics: ['input-validation'],
    must_not_report_topics: ['csrf'],
  },
]

const finding = (
  caseId,
  candidateId,
  topic,
  severity,
  extra = {},
) => ({
  case_id: caseId,
  candidate_id: candidateId,
  topic,
  effective_severity: severity,
  ...extra,
})

test('perfect observations produce a complete case confusion matrix and exact severity', () => {
  const score = scoreEvaluation({
    expectedCases: EXPECTED,
    observedFindings: [
      finding('V-002', 'sql:2', 'injection-sql-nosql-orm', 'critical'),
      finding('C-001', 'info:1', 'jwt-jws-and-jwks-verification', 'Info'),
      finding('V-001', 'authz:1', 'authz-object-level', 'HIGH'),
    ],
    schemaInvalidCount: 0,
  })

  assert.deepEqual(
    {
      tp: score.counts.tp,
      fp: score.counts.fp,
      tn: score.counts.tn,
      fn: score.counts.fn,
    },
    { tp: 2, fp: 0, tn: 2, fn: 0 },
  )
  assert.equal(score.rates.precision, 1)
  assert.equal(score.rates.recall, 1)
  assert.equal(score.rates.tpr, 1)
  assert.equal(score.rates.fpr, 0)
  assert.equal(score.rates.severity_accuracy, 1)
  assert.equal(score.rates.minimum_vulnerable_topic_recall, 1)
  assert.equal(score.counts.reportable_findings, 2)
  assert.equal(score.counts.schema_invalid, 0)
})

test('misses, clean contamination, and explicit false clears remain distinct', () => {
  const score = scoreEvaluation({
    expectedCases: EXPECTED,
    observedFindings: [
      finding('V-001', 'authz:1', 'authz-object-level', 'High'),
      finding('C-001', 'false:1', 'jwt-jws-and-jwks-verification', 'Low'),
    ],
    caseOutcomes: [
      { case_id: 'V-002', verdict: 'clear' },
      { case_id: 'C-001', verdict: 'finding' },
    ],
    schemaInvalidCount: 2,
  })

  assert.deepEqual(
    {
      tp: score.counts.tp,
      fp: score.counts.fp,
      tn: score.counts.tn,
      fn: score.counts.fn,
    },
    { tp: 1, fp: 1, tn: 1, fn: 1 },
  )
  assert.equal(score.rates.precision, 0.5)
  assert.equal(score.rates.recall, 0.5)
  assert.equal(score.rates.minimum_vulnerable_topic_recall, 0)
  assert.equal(score.rates.fpr, 0.5)
  assert.equal(score.counts.false_clears, 1)
  assert.equal(score.counts.schema_invalid, 2)
  assert.equal(score.rates.schema_valid_rate, 0.5)
})

test('unlisted and duplicate findings are precision debt even on a true-positive case', () => {
  const score = scoreEvaluation({
    expectedCases: [EXPECTED[3]],
    observedFindings: [
      finding('V-002', 'sql:a', 'injection-sql-nosql-orm', 'Critical'),
      finding('V-002', 'sql:b', 'injection-sql-nosql-orm', 'High'),
      finding('V-002', 'allowed:1', 'input-validation', 'Low'),
      finding('V-002', 'wrong:1', 'csrf', 'Low'),
    ],
  })

  assert.equal(score.counts.tp, 1)
  assert.equal(score.counts.unexpected_findings, 2)
  assert.equal(score.counts.duplicate_findings, 1)
  assert.equal(score.rates.finding_precision, 1 / 3)
  assert.deepEqual(score.unexpected_by_topic, [
    { topic: 'csrf', count: 1 },
    { topic: 'injection-sql-nosql-orm', count: 1 },
  ])
})

test('Info is non-reportable but unauthenticated removal claims remain findings', () => {
  const expected = [EXPECTED[0]]
  const variants = [
    finding('C-001', 'info', expected[0].topic, 'Info'),
    finding('C-001', 'drop', expected[0].topic, 'High', { triage_disposition: 'dropped' }),
    finding('C-001', 'merge', expected[0].topic, 'High', { triage_disposition: 'merged' }),
    finding('C-001', 'disproved', expected[0].topic, 'High', { verification_status: 'DISPROVED' }),
    finding('C-001', 'absent', expected[0].topic, 'High', { verification_status: 'NOT_REPRODUCED' }),
  ]
  const score = scoreEvaluation({ expectedCases: expected, observedFindings: variants })
  assert.equal(score.counts.fp, 1)
  assert.equal(score.counts.reportable_findings, 4)
  assert.deepEqual(score.cases[0].unexpected_candidate_ids, [
    'absent',
    'disproved',
    'drop',
    'merge',
  ])
})

test('severity accuracy distinguishes exact, overclassified, and underclassified cases', () => {
  const expected = [
    { case_id: 'V-A', expectation: 'vulnerable', topic: 'a', expected_severity: 'High' },
    { case_id: 'V-B', expectation: 'vulnerable', topic: 'b', expected_severity: 'High' },
    { case_id: 'V-C', expectation: 'vulnerable', topic: 'c', expected_severity: 'High' },
  ]
  const score = scoreEvaluation({
    expectedCases: expected,
    observedFindings: [
      finding('V-A', 'a', 'a', 'High'),
      finding('V-B', 'b', 'b', 'Critical'),
      finding('V-C', 'c', 'c', 'Medium'),
    ],
  })
  assert.equal(score.counts.severity_exact, 1)
  assert.equal(score.counts.severity_over, 1)
  assert.equal(score.counts.severity_under, 1)
  assert.equal(score.rates.severity_accuracy, 1 / 3)
})

test('per-topic output is sorted and carries its own confusion metrics', () => {
  const score = scoreEvaluation({
    expectedCases: EXPECTED,
    observedFindings: [
      finding('V-001', 'authz:1', 'authz-object-level', 'High'),
      finding('C-001', 'jwt:1', 'jwt-jws-and-jwks-verification', 'Low'),
    ],
  })
  assert.deepEqual(
    score.per_topic.map((entry) => entry.topic),
    [
      'authz-object-level',
      'injection-sql-nosql-orm',
      'jwt-jws-and-jwks-verification',
      'legacy-hash-and-cipher-primitives',
    ],
  )
  const jwt = score.per_topic.find((entry) => entry.topic === 'jwt-jws-and-jwks-verification')
  assert.equal(jwt.counts.fp, 1)
  assert.equal(jwt.rates.fpr, 1)
})

test('per-lens output exposes the minimum recall and represented lens denominator', () => {
  const score = scoreEvaluation({
    expectedCases: [
      {
        case_id: 'V-WEB',
        expectation: 'vulnerable',
        lens: 'web-and-api',
        topic: 'authz-object-level',
        expected_severity: 'High',
      },
      {
        case_id: 'V-NATIVE',
        expectation: 'vulnerable',
        lens: 'native-and-memory-safety',
        topic: 'native-memory-bounds',
        expected_severity: 'Critical',
      },
    ],
    observedFindings: [
      finding('V-WEB', 'authz:1', 'authz-object-level', 'High', {
        lens: 'web-and-api',
      }),
    ],
  })

  assert.equal(score.counts.vulnerable_lenses, 2)
  assert.equal(score.rates.minimum_vulnerable_lens_recall, 0)
  assert.deepEqual(
    score.per_lens.map(({ lens, counts, rates }) => ({
      lens,
      vulnerable_cases: counts.vulnerable_cases,
      recall: rates.recall,
    })),
    [
      { lens: 'native-and-memory-safety', vulnerable_cases: 1, recall: 0 },
      { lens: 'web-and-api', vulnerable_cases: 1, recall: 1 },
    ],
  )
})

test('a cross-cutting detector cannot credit the expected domain authoring lens', () => {
  const score = scoreEvaluation({
    expectedCases: [{
      case_id: 'V-WEB',
      expectation: 'vulnerable',
      lens: 'web-and-api',
      topic: 'authz-object-level',
      expected_severity: 'High',
    }],
    observedFindings: [finding(
      'V-WEB',
      'ai-review:authz',
      'authz-object-level',
      'High',
      { lens: 'ai-generated-code', raised_by: 'ai-generated-code' },
    )],
  })

  assert.equal(score.counts.tp, 1, 'system/topic recall still sees the defect')
  assert.equal(score.per_lens[0].lens, 'web-and-api')
  assert.equal(score.per_lens[0].counts.tp, 0)
  assert.equal(score.per_lens[0].counts.fn, 1)
  assert.equal(score.rates.minimum_vulnerable_lens_recall, 0)
  assert.equal(score.cases[0].matched_lens_candidate_id, null)
  assert.equal(score.per_lens[0].counts.severity_assessed, 0)
})

test('per-lens severity is graded from the expected lens finding, not a cross-lens match', () => {
  const score = scoreEvaluation({
    expectedCases: [{
      case_id: 'V-WEB',
      expectation: 'vulnerable',
      lens: 'web-and-api',
      topic: 'authz-object-level',
      expected_severity: 'High',
    }],
    observedFindings: [
      finding('V-WEB', 'ai-review:authz', 'authz-object-level', 'Critical', {
        lens: 'ai-generated-code',
        raised_by: 'ai-generated-code',
      }),
      finding('V-WEB', 'web-review:authz', 'authz-object-level', 'Low', {
        lens: 'web-and-api',
      }),
    ],
  })

  assert.equal(score.cases[0].severity_result, 'over')
  assert.equal(score.cases[0].matched_lens_candidate_id, 'web-review:authz')
  assert.equal(score.cases[0].matched_lens_observed_severity, 'Low')
  assert.equal(score.cases[0].matched_lens_severity_result, 'under')
  assert.equal(score.per_lens[0].counts.severity_assessed, 1)
  assert.equal(score.per_lens[0].counts.severity_over, 0)
  assert.equal(score.per_lens[0].counts.severity_under, 1)
})

test('scoring is independent of expected-case and finding input order', () => {
  const observations = [
    finding('V-001', 'authz:1', 'authz-object-level', 'High'),
    finding('V-002', 'sql:1', 'injection-sql-nosql-orm', 'Critical'),
  ]
  const forward = scoreEvaluation({
    expectedCases: EXPECTED,
    observedFindings: observations,
  })
  const reverse = scoreEvaluation({
    expectedCases: [...EXPECTED].reverse(),
    observedFindings: [...observations].reverse(),
  })
  assert.deepEqual(reverse, forward)
})

test('malformed evaluation inputs fail closed', () => {
  const attempts = [
    () => scoreEvaluation({ expectedCases: [], observedFindings: [] }),
    () => scoreEvaluation({
      expectedCases: [EXPECTED[0], EXPECTED[0]],
      observedFindings: [],
    }),
    () => scoreEvaluation({
      expectedCases: EXPECTED,
      observedFindings: [finding('unknown', 'x', 'topic', 'High')],
    }),
    () => scoreEvaluation({
      expectedCases: EXPECTED,
      observedFindings: [finding('V-001', 'x', 'authz-object-level', 'Severe')],
    }),
    () => scoreEvaluation({
      expectedCases: EXPECTED,
      observedFindings: [],
      schemaInvalidCount: -1,
    }),
  ]
  for (const attempt of attempts) {
    assert.throws(attempt, EvaluationInputError)
  }
})

test('contradictory explicit verdicts fail closed', () => {
  assert.throws(
    () => scoreEvaluation({
      expectedCases: [EXPECTED[2]],
      observedFindings: [finding('V-001', 'authz:1', 'authz-object-level', 'High')],
      caseOutcomes: [{ case_id: 'V-001', verdict: 'clear' }],
    }),
    /says clear/,
  )
  assert.throws(
    () => scoreEvaluation({
      expectedCases: [EXPECTED[2]],
      observedFindings: [],
      caseOutcomes: [{ case_id: 'V-001', verdict: 'finding' }],
    }),
    /says finding/,
  )
})

test('Jaccard similarity handles overlap and the empty-set identity', () => {
  assert.equal(jaccardSimilarity(['a', 'b'], ['b', 'c']), 1 / 3)
  assert.equal(jaccardSimilarity([], []), 1)
})

test('repeated-run stability reports pairwise and all-run fingerprint overlap', () => {
  const runs = [
    {
      run_id: 'run-c',
      findings: [
        finding('V-001', 'candidate-a3', 'authz-object-level', 'High', { fingerprint: 'A' }),
        finding('V-002', 'candidate-c', 'injection-sql-nosql-orm', 'Critical', { fingerprint: 'C' }),
      ],
    },
    {
      run_id: 'run-a',
      findings: [
        finding('V-001', 'candidate-a1', 'authz-object-level', 'High', { fingerprint: 'A' }),
        finding('V-002', 'candidate-b1', 'injection-sql-nosql-orm', 'Critical', { fingerprint: 'B' }),
      ],
    },
    {
      run_id: 'run-b',
      findings: [
        finding('V-001', 'candidate-a2', 'authz-object-level', 'High', { fingerprint: 'A' }),
        finding('V-002', 'candidate-b2', 'injection-sql-nosql-orm', 'Critical', { fingerprint: 'B' }),
      ],
    },
  ]
  const stability = scoreFingerprintStability(runs, EXPECTED)
  assert.equal(stability.assessable, true)
  assert.equal(stability.run_count, 3)
  assert.equal(stability.pair_count, 3)
  assert.equal(stability.stable_fingerprint_count, 1)
  assert.equal(stability.union_fingerprint_count, 3)
  assert.equal(stability.fingerprint_stability, 1 / 3)
  assert.equal(stability.minimum_pairwise_jaccard, 1 / 3)
  assert.deepEqual(
    stability.pairs.map((pair) => [pair.left_run, pair.right_run]),
    [
      ['run-a', 'run-b'],
      ['run-a', 'run-c'],
      ['run-b', 'run-c'],
    ],
  )
})

test('one run or an all-empty repeated run is explicitly unassessable', () => {
  const one = scoreFingerprintStability([{ run_id: 'one', findings: [] }], EXPECTED)
  assert.equal(one.assessable, false)
  assert.equal(one.fingerprint_stability, null)

  const empty = scoreFingerprintStability([
    { run_id: 'one', findings: [] },
    { run_id: 'two', findings: [] },
  ], EXPECTED)
  assert.equal(empty.assessable, false)
  assert.equal(empty.mean_pairwise_jaccard, null)
})

test('stability runs are bound to the benchmark case manifest', () => {
  assert.throws(
    () => scoreFingerprintStability([
      {
        run_id: 'run-a',
        findings: [
          finding('NOT-IN-MANIFEST', 'candidate-a', 'authz-object-level', 'High'),
        ],
      },
      {
        run_id: 'run-b',
        findings: [
          finding('NOT-IN-MANIFEST', 'candidate-a', 'authz-object-level', 'High'),
        ],
      },
    ], EXPECTED),
    (error) => error instanceof EvaluationInputError
      && /unknown case "NOT-IN-MANIFEST"/.test(error.message),
  )
})

test('evaluation cardinality limits bound repeated-run pair materialization', () => {
  assert.throws(
    () => scoreFingerprintStability(
      Array.from(
        { length: EVALUATION_LIMITS.repeatedRuns + 1 },
        (_, index) => ({ run_id: `run-${index}`, findings: [] }),
      ),
      EXPECTED,
    ),
    new RegExp(`at most ${EVALUATION_LIMITS.repeatedRuns} items`),
  )
  assert.throws(
    () => scoreFingerprintStability([{
      run_id: 'run-over-findings',
      findings: Array(EVALUATION_LIMITS.findingsPerRepeatedRun + 1).fill(null),
    }], EXPECTED),
    new RegExp(`at most ${EVALUATION_LIMITS.findingsPerRepeatedRun} items`),
  )
  assert.throws(
    () => scoreEvaluation({
      expectedCases: EXPECTED,
      observedFindings: Array(EVALUATION_LIMITS.observedFindings + 1).fill(null),
    }),
    new RegExp(`at most ${EVALUATION_LIMITS.observedFindings} items`),
  )
})

test('threshold evaluation truncates over-limit configuration and fails closed', () => {
  const result = evaluateThresholds(
    { counts: { cases: 64 } },
    {
      schema_version: 1,
      profile: 'over-limit',
      requirements: Array.from(
        { length: EVALUATION_LIMITS.thresholdRequirements + 1 },
        (_, index) => ({
          id: `requirement-${index}`,
          metric: 'counts.cases',
          operator: '>=',
          value: 1,
        }),
      ),
    },
  )
  assert.equal(result.passed, false)
  assert.match(
    result.errors.join('\n'),
    new RegExp(`at most ${EVALUATION_LIMITS.thresholdRequirements} items`),
  )
  assert.equal(result.checks.length, EVALUATION_LIMITS.thresholdRequirements)
})

test('threshold evaluation passes and fails deterministic numeric requirements', () => {
  const thresholds = {
    schema_version: 1,
    profile: 'test',
    requirements: [
      { id: 'recall', metric: 'rates.recall', operator: '>=', value: 0.8 },
      { id: 'false-clears', metric: 'counts.false_clears', operator: '==', value: 0 },
    ],
  }
  const passed = evaluateThresholds(
    { rates: { recall: 0.9 }, counts: { false_clears: 0 } },
    thresholds,
  )
  assert.equal(passed.passed, true)
  assert.deepEqual(passed.errors, [])

  const failed = evaluateThresholds(
    { rates: { recall: 0.7 }, counts: { false_clears: 1 } },
    thresholds,
  )
  assert.equal(failed.passed, false)
  assert.deepEqual(failed.checks.map((check) => check.passed), [false, false])
  assert.deepEqual(failed.errors, [])
})

test('threshold configuration and missing metrics fail closed with errors', () => {
  const missing = evaluateThresholds(
    { rates: {} },
    {
      schema_version: 1,
      profile: 'missing',
      requirements: [
        { id: 'recall', metric: 'rates.recall', operator: '>=', value: 0.8 },
      ],
    },
  )
  assert.equal(missing.passed, false)
  assert.equal(missing.checks[0].actual, null)
  assert.match(missing.errors[0], /missing or not a finite number/)

  const malformed = evaluateThresholds({}, {
    schema_version: 2,
    profile: '',
    requirements: [
      { id: 'bad', metric: '__proto__.x', operator: '~=', value: Number.NaN },
    ],
  })
  assert.equal(malformed.passed, false)
  assert.ok(malformed.errors.length >= 4)

  const empty = evaluateThresholds({}, {
    schema_version: 1,
    profile: 'empty',
    requirements: [],
  })
  assert.equal(empty.passed, false)
})

test('the initial release threshold profile is valid and executable', () => {
  const thresholds = JSON.parse(readFileSync(
    new URL('../benchmarks/thresholds.json', import.meta.url),
    'utf8',
  ))
  const metrics = {
    counts: {
      cases: 64,
      vulnerable_cases: 22,
      vulnerable_lenses: 18,
      clean_cases: 42,
      false_clears: 0,
      schema_invalid: 0,
      unexpected_findings: 0,
      false_positive_findings: 0,
    },
    rates: {
      precision: 1,
      recall: 0.9,
      minimum_vulnerable_topic_recall: 0.9,
      minimum_vulnerable_lens_recall: 0.9,
      fpr: 0,
      finding_precision: 1,
      severity_accuracy: 0.9,
    },
    stability: {
      run_count: 3,
      fingerprint_stability: 0.8,
      mean_pairwise_jaccard: 0.85,
      minimum_pairwise_jaccard: 0.75,
    },
  }
  const result = evaluateThresholds(metrics, thresholds)
  assert.equal(result.passed, true, result.errors.join('\n'))
  assert.ok(result.checks.length >= 10)
})

test('assessment states partition the corpus without changing the case confusion matrix', () => {
  const score = scoreEvaluation({
    expectedCases: EXPECTED,
    observedFindings: [],
    caseOutcomes: [
      { case_id: 'C-001', verdict: 'clear' },
      { case_id: 'C-002', verdict: 'incomplete' },
      { case_id: 'V-001', verdict: 'not_assessed' },
    ],
  })
  assert.equal(score.counts.tn, 2, 'the existing matrix is still a finding-presence metric')
  assert.equal(score.counts.fn, 2)
  assert.equal(score.counts.assessed_cases, 1)
  assert.equal(score.counts.incomplete_cases, 1)
  assert.equal(score.counts.not_assessed_cases, 1)
  assert.equal(score.counts.unspecified_cases, 1)
  assert.equal(score.counts.abstentions, 2)
  assert.equal(score.rates.accuracy, 0.5)
  assert.equal(score.rates.assessed_accuracy, 1)
  assert.equal(score.rates.assessment_rate, 0.25)
  assert.equal(score.rates.abstention_rate, 0.5)
  assert.equal(score.rates.unspecified_rate, 0.25)
  assert.deepEqual(score.cases.map(({ assessment_status: status }) => status), [
    'assessed', 'incomplete', 'not_assessed', 'unspecified',
  ])
})

test('missing final outcomes remain unspecified even when a finding was observed', () => {
  const score = scoreEvaluation({
    expectedCases: EXPECTED,
    observedFindings: [finding('V-001', 'authz:1', 'authz-object-level', 'High')],
  })
  assert.equal(score.counts.tp, 1)
  assert.equal(score.counts.unspecified_cases, EXPECTED.length)
  assert.equal(score.counts.assessed_cases, 0)
  assert.equal(score.rates.assessed_accuracy, null)
  assert.equal(score.rates.abstention_rate, 0)
  assert.equal(score.rates.unspecified_rate, 1)
})

test('repeated accuracy includes each run severity, false clears, and abstentions independently', () => {
  const good = [
    finding('V-001', 'authz:1', 'authz-object-level', 'High'),
    finding('V-002', 'sql:1', 'injection-sql-nosql-orm', 'Critical'),
  ]
  const repeats = scoreRepeatedEvaluations([
    { run_id: 'silent', findings: [] },
    {
      run_id: 'good', findings: good,
      caseOutcomes: EXPECTED.map(({ case_id, expectation }) => ({
        case_id, verdict: expectation === 'clean' ? 'clear' : 'finding',
      })),
    },
    {
      run_id: 'mixed',
      findings: [finding('V-001', 'authz:2', 'authz-object-level', 'Low')],
      caseOutcomes: [
        { case_id: 'V-001', verdict: 'finding' },
        { case_id: 'V-002', verdict: 'clear' },
        { case_id: 'C-001', verdict: 'incomplete' },
        { case_id: 'C-002', verdict: 'not_assessed' },
      ],
      schemaInvalidCount: 2,
    },
  ], EXPECTED)
  assert.deepEqual(repeats.runs.map(({ run_id }) => run_id), ['good', 'mixed', 'silent'])
  const mixed = repeats.runs[1]
  assert.equal(mixed.counts.false_clears, 1)
  assert.equal(mixed.counts.abstentions, 2)
  assert.equal(mixed.counts.schema_invalid, 2)
  assert.equal(mixed.rates.severity_accuracy, 0)
  assert.equal(repeats.runs[2].counts.unspecified_cases, 4)
  assert.deepEqual(repeats.aggregate.rates.accuracy, {
    minimum: 0.5, maximum: 1, mean: 0.75, assessed_runs: 3, unassessed_runs: 0,
  })
  assert.deepEqual(repeats.aggregate.rates.severity_accuracy, {
    minimum: 0, maximum: 1, mean: 0.5, assessed_runs: 2, unassessed_runs: 1,
  })
  assert.deepEqual(repeats.aggregate.rates.assessed_accuracy, {
    minimum: 0.5, maximum: 1, mean: 0.75, assessed_runs: 2, unassessed_runs: 1,
  })
})

test('unmeasured repeated accuracy never becomes an aggregate perfect score', () => {
  const repeats = scoreRepeatedEvaluations([
    { run_id: 'a', findings: [] },
    { run_id: 'b', findings: [] },
  ], EXPECTED)
  assert.deepEqual(repeats.aggregate.rates.assessed_accuracy, {
    minimum: null, maximum: null, mean: null, assessed_runs: 0, unassessed_runs: 2,
  })
  assert.equal(repeats.aggregate.counts.unspecified_cases.minimum, 4)
})

test('repeat scoring rejects contradictory outcomes, duplicate runs, and invalid-record counts', () => {
  for (const runs of [
    [],
    [{ run_id: 'a', findings: [] }, { run_id: ' a ', findings: [] }],
    [{ run_id: 'a', findings: [], caseOutcomes: [{ case_id: 'C-001', verdict: 'finding' }] }],
    [{ run_id: 'a', findings: [], schemaInvalidCount: -1 }],
    [{ run_id: 'a', findings: [finding('unknown', 'x', 'topic', 'High')] }],
    Array.from({ length: 65 }, (_, index) => ({ run_id: `${index}`, findings: [] })),
  ]) {
    assert.throws(() => scoreRepeatedEvaluations(runs, EXPECTED), EvaluationInputError)
  }
})

test('repeat aggregates are deterministic across run, case, and finding ordering', () => {
  const observations = [
    finding('V-001', 'authz:1', 'authz-object-level', 'High'),
    finding('V-002', 'sql:1', 'injection-sql-nosql-orm', 'Critical'),
  ]
  const first = [{ run_id: 'b', findings: observations }, { run_id: 'a', findings: [] }]
  const second = [...first].reverse().map((run) => ({ ...run, findings: [...run.findings].reverse() }))
  assert.deepEqual(
    scoreRepeatedEvaluations(first, EXPECTED),
    scoreRepeatedEvaluations(second, [...EXPECTED].reverse()),
  )
})
