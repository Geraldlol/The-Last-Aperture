import { isSurvivingFinding } from './findings.mjs'
import { compareCanonicalStrings } from './canonical-order.mjs'

const SEVERITIES = ['Info', 'Low', 'Medium', 'High', 'Critical']
const SEVERITY_RANK = new Map(SEVERITIES.map((severity, index) => [severity, index]))
const EXPECTATIONS = new Set(['vulnerable', 'clean'])
const TRIAGE_DISPOSITIONS = new Set(['queued', 'merged', 'dropped', 'elevated'])
const VERIFICATION_STATUSES = new Set([
  'CONFIRMED',
  'NOT_REPRODUCED',
  'INCONCLUSIVE',
  'DISPROVED',
  'UNPROVEN',
])
const CASE_VERDICTS = new Set(['finding', 'clear', 'incomplete', 'not_assessed'])
const THRESHOLD_OPERATORS = new Set(['>=', '<=', '>', '<', '=='])
const UNSAFE_PATH_SEGMENTS = new Set(['__proto__', 'prototype', 'constructor'])

export const EVALUATION_LIMITS = Object.freeze({
  expectedCases: 4096,
  observedFindings: 4096,
  caseOutcomes: 4096,
  repeatedRuns: 64,
  findingsPerRepeatedRun: 4096,
  thresholdRequirements: 256,
})

export class EvaluationInputError extends TypeError {
  constructor(issues) {
    const normalized = Array.isArray(issues) ? issues : [String(issues)]
    super(`invalid evaluation input:\n- ${normalized.join('\n- ')}`)
    this.name = 'EvaluationInputError'
    this.issues = normalized
  }
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function nonEmptyString(value) {
  return typeof value === 'string' && value.trim() !== ''
}

function normalizeSeverity(value, field, issues) {
  if (!nonEmptyString(value)) {
    issues.push(`${field} must be a severity`)
    return null
  }
  const normalized = SEVERITIES.find(
    (severity) => severity.toLowerCase() === value.trim().toLowerCase(),
  )
  if (!normalized) {
    issues.push(`${field} must be one of ${SEVERITIES.join(', ')}`)
    return null
  }
  return normalized
}

function normalizeStringList(value, field, issues) {
  if (value === undefined) return []
  if (!Array.isArray(value)) {
    issues.push(`${field} must be an array`)
    return []
  }
  const output = []
  const seen = new Set()
  for (const [index, item] of value.entries()) {
    if (!nonEmptyString(item)) {
      issues.push(`${field}[${index}] must be a non-empty string`)
      continue
    }
    const normalized = item.trim()
    if (seen.has(normalized)) {
      issues.push(`${field} contains duplicate value ${JSON.stringify(normalized)}`)
      continue
    }
    seen.add(normalized)
    output.push(normalized)
  }
  return output
}

function normalizeExpectedCases(expectedCases) {
  const issues = []
  if (!Array.isArray(expectedCases) || expectedCases.length === 0) {
    throw new EvaluationInputError('expectedCases must be a non-empty array')
  }
  if (expectedCases.length > EVALUATION_LIMITS.expectedCases) {
    throw new EvaluationInputError(
      `expectedCases must contain at most ${EVALUATION_LIMITS.expectedCases} items`,
    )
  }

  const seen = new Set()
  const normalized = expectedCases.map((entry, index) => {
    const field = `expectedCases[${index}]`
    if (!isRecord(entry)) {
      issues.push(`${field} must be an object`)
      return null
    }

    const caseId = nonEmptyString(entry.case_id) ? entry.case_id.trim() : null
    if (!caseId) issues.push(`${field}.case_id must be a non-empty string`)
    else if (seen.has(caseId)) issues.push(`${field}.case_id duplicates ${JSON.stringify(caseId)}`)
    else seen.add(caseId)

    const expectation = nonEmptyString(entry.expectation)
      ? entry.expectation.trim().toLowerCase()
      : null
    if (!EXPECTATIONS.has(expectation)) {
      issues.push(`${field}.expectation must be "vulnerable" or "clean"`)
    }

    const topic = nonEmptyString(entry.topic) ? entry.topic.trim() : null
    if (!topic) issues.push(`${field}.topic must be a non-empty string`)

    const expectedSeverity = expectation === 'vulnerable'
      ? normalizeSeverity(entry.expected_severity, `${field}.expected_severity`, issues)
      : null
    if (expectation === 'vulnerable' && expectedSeverity === 'Info') {
      issues.push(`${field}.expected_severity cannot be Info for a vulnerable case`)
    }
    if (expectation === 'clean' && entry.expected_severity !== undefined) {
      issues.push(`${field}.expected_severity must be omitted for a clean case`)
    }

    const acceptable = normalizeStringList(
      entry.also_acceptable_topics,
      `${field}.also_acceptable_topics`,
      issues,
    )
    const mustNotReport = normalizeStringList(
      entry.must_not_report_topics,
      `${field}.must_not_report_topics`,
      issues,
    )

    if (expectation === 'clean' && acceptable.length > 0) {
      issues.push(`${field}.also_acceptable_topics must be empty for a clean case`)
    }
    if (topic && acceptable.includes(topic)) {
      issues.push(`${field}.also_acceptable_topics must not repeat the primary topic`)
    }
    const allowed = new Set([topic, ...acceptable].filter(Boolean))
    for (const denied of mustNotReport) {
      if (allowed.has(denied)) {
        issues.push(`${field}.must_not_report_topics conflicts with an allowed topic ${JSON.stringify(denied)}`)
      }
    }

    return {
      case_id: caseId,
      expectation,
      topic,
      expected_severity: expectedSeverity,
      also_acceptable_topics: acceptable,
      must_not_report_topics: mustNotReport,
    }
  }).filter(Boolean)

  if (issues.length) throw new EvaluationInputError(issues)
  return normalized.sort((left, right) => compareCanonicalStrings(left.case_id, right.case_id))
}

function normalizeFindings(observedFindings, expectedIds = null, fieldName = 'observedFindings') {
  const issues = []
  if (!Array.isArray(observedFindings)) {
    throw new EvaluationInputError(`${fieldName} must be an array`)
  }
  if (observedFindings.length > EVALUATION_LIMITS.observedFindings) {
    throw new EvaluationInputError(
      `${fieldName} must contain at most ${EVALUATION_LIMITS.observedFindings} items`,
    )
  }

  const seenCandidates = new Set()
  const normalized = observedFindings.map((entry, index) => {
    const field = `${fieldName}[${index}]`
    if (!isRecord(entry)) {
      issues.push(`${field} must be an object`)
      return null
    }

    const caseId = nonEmptyString(entry.case_id) ? entry.case_id.trim() : null
    const candidateId = nonEmptyString(entry.candidate_id) ? entry.candidate_id.trim() : null
    const topic = nonEmptyString(entry.topic) ? entry.topic.trim() : null
    if (!caseId) issues.push(`${field}.case_id must be a non-empty string`)
    else if (expectedIds && !expectedIds.has(caseId)) {
      issues.push(`${field}.case_id references unknown case ${JSON.stringify(caseId)}`)
    }
    if (!candidateId) issues.push(`${field}.candidate_id must be a non-empty string`)
    else if (seenCandidates.has(candidateId)) {
      issues.push(`${field}.candidate_id duplicates ${JSON.stringify(candidateId)}`)
    } else {
      seenCandidates.add(candidateId)
    }
    if (!topic) issues.push(`${field}.topic must be a non-empty string`)

    const severity = normalizeSeverity(entry.effective_severity, `${field}.effective_severity`, issues)
    const disposition = entry.triage_disposition
    if (disposition !== undefined && !TRIAGE_DISPOSITIONS.has(disposition)) {
      issues.push(
        `${field}.triage_disposition must be one of ${[...TRIAGE_DISPOSITIONS].join(', ')}`,
      )
    }
    const verification = entry.verification_status
    if (verification !== undefined && !VERIFICATION_STATUSES.has(verification)) {
      issues.push(
        `${field}.verification_status must be one of ${[...VERIFICATION_STATUSES].join(', ')}`,
      )
    }
    if (entry.fingerprint !== undefined && !nonEmptyString(entry.fingerprint)) {
      issues.push(`${field}.fingerprint must be a non-empty string when present`)
    }

    return {
      ...entry,
      case_id: caseId,
      candidate_id: candidateId,
      topic,
      effective_severity: severity,
      fingerprint: nonEmptyString(entry.fingerprint) ? entry.fingerprint.trim() : undefined,
    }
  }).filter(Boolean)

  if (issues.length) throw new EvaluationInputError(issues)
  return normalized.sort((left, right) => {
    const caseOrder = compareCanonicalStrings(left.case_id, right.case_id)
    return caseOrder || compareCanonicalStrings(left.candidate_id, right.candidate_id)
  })
}

function normalizeCaseOutcomes(caseOutcomes, expectedIds, findingsByCase) {
  const issues = []
  if (!Array.isArray(caseOutcomes)) {
    throw new EvaluationInputError('caseOutcomes must be an array')
  }
  if (
    caseOutcomes.length > EVALUATION_LIMITS.caseOutcomes
    || caseOutcomes.length > expectedIds.size
  ) {
    throw new EvaluationInputError(
      `caseOutcomes must contain at most ${Math.min(
        EVALUATION_LIMITS.caseOutcomes,
        expectedIds.size,
      )} items`,
    )
  }
  const seen = new Set()
  const normalized = new Map()

  for (const [index, entry] of caseOutcomes.entries()) {
    const field = `caseOutcomes[${index}]`
    if (!isRecord(entry)) {
      issues.push(`${field} must be an object`)
      continue
    }
    const caseId = nonEmptyString(entry.case_id) ? entry.case_id.trim() : null
    const verdict = nonEmptyString(entry.verdict) ? entry.verdict.trim().toLowerCase() : null
    if (!caseId) issues.push(`${field}.case_id must be a non-empty string`)
    else if (!expectedIds.has(caseId)) {
      issues.push(`${field}.case_id references unknown case ${JSON.stringify(caseId)}`)
    } else if (seen.has(caseId)) {
      issues.push(`${field}.case_id duplicates ${JSON.stringify(caseId)}`)
    } else {
      seen.add(caseId)
    }
    if (!CASE_VERDICTS.has(verdict)) {
      issues.push(`${field}.verdict must be one of ${[...CASE_VERDICTS].join(', ')}`)
    }
    if (caseId && CASE_VERDICTS.has(verdict)) normalized.set(caseId, verdict)
  }

  for (const [caseId, verdict] of normalized) {
    const reportable = (findingsByCase.get(caseId) ?? []).filter(isReportableFinding)
    if (verdict === 'clear' && reportable.length > 0) {
      issues.push(
        `caseOutcomes for ${JSON.stringify(caseId)} says clear but has ${reportable.length} reportable finding(s)`,
      )
    }
    if (verdict === 'finding' && reportable.length === 0) {
      issues.push(
        `caseOutcomes for ${JSON.stringify(caseId)} says finding but has no reportable finding`,
      )
    }
  }

  if (issues.length) throw new EvaluationInputError(issues)
  return normalized
}

function isActiveFinding(finding) {
  return isSurvivingFinding(finding)
}

function isReportableFinding(finding) {
  return isActiveFinding(finding) && SEVERITY_RANK.get(finding.effective_severity) >= 1
}

function ratio(numerator, denominator) {
  return denominator === 0 ? null : numerator / denominator
}

function compareSeverity(actual, expected) {
  const difference = SEVERITY_RANK.get(actual) - SEVERITY_RANK.get(expected)
  if (difference === 0) return 'exact'
  return difference > 0 ? 'over' : 'under'
}

function choosePrimaryFinding(findings) {
  return [...findings].sort((left, right) => {
    const severityOrder = SEVERITY_RANK.get(right.effective_severity)
      - SEVERITY_RANK.get(left.effective_severity)
    return severityOrder || compareCanonicalStrings(left.candidate_id, right.candidate_id)
  })[0]
}

function summarizeDetails(details) {
  const counts = {
    cases: details.length,
    vulnerable_cases: 0,
    clean_cases: 0,
    tp: 0,
    fp: 0,
    tn: 0,
    fn: 0,
    reportable_findings: 0,
    matched_findings: 0,
    false_positive_findings: 0,
    unexpected_findings: 0,
    duplicate_findings: 0,
    false_clears: 0,
    severity_assessed: 0,
    severity_exact: 0,
    severity_over: 0,
    severity_under: 0,
  }

  for (const detail of details) {
    counts[`${detail.expectation}_cases`] += 1
    counts[detail.classification.toLowerCase()] += 1
    counts.reportable_findings += detail.reportable_finding_count
    counts.matched_findings += detail.matched_candidate_id ? 1 : 0
    counts.false_positive_findings += detail.false_positive_finding_count
    counts.unexpected_findings += detail.unexpected_candidate_ids.length
    counts.duplicate_findings += detail.duplicate_candidate_ids.length
    if (detail.false_clear) counts.false_clears += 1
    if (detail.severity_result) {
      counts.severity_assessed += 1
      counts[`severity_${detail.severity_result}`] += 1
    }
  }

  const rates = {
    precision: ratio(counts.tp, counts.tp + counts.fp),
    recall: ratio(counts.tp, counts.tp + counts.fn),
    tpr: ratio(counts.tp, counts.tp + counts.fn),
    fpr: ratio(counts.fp, counts.fp + counts.tn),
    specificity: ratio(counts.tn, counts.tn + counts.fp),
    finding_precision: ratio(counts.tp, counts.tp + counts.unexpected_findings),
    false_clear_rate: ratio(counts.false_clears, counts.vulnerable_cases),
    severity_accuracy: ratio(counts.severity_exact, counts.severity_assessed),
  }

  return { counts, rates }
}

/**
 * Score one deterministic evaluation run.
 *
 * The confusion matrix is case-based: vulnerable cases are TP/FN and clean
 * cases are FP/TN. Extra or duplicate records are separately counted as
 * unexpected findings so a vulnerable case cannot hide noisy output behind a
 * true positive. Info observations and withdrawn records are not scored.
 */
export function scoreEvaluation({
  expectedCases,
  observedFindings,
  caseOutcomes = [],
  schemaInvalidCount = 0,
}) {
  if (!Number.isSafeInteger(schemaInvalidCount) || schemaInvalidCount < 0) {
    throw new EvaluationInputError('schemaInvalidCount must be a non-negative safe integer')
  }

  const expected = normalizeExpectedCases(expectedCases)
  const expectedIds = new Set(expected.map((entry) => entry.case_id))
  const findings = normalizeFindings(observedFindings, expectedIds)
  const findingsByCase = new Map(expected.map((entry) => [entry.case_id, []]))
  for (const finding of findings) findingsByCase.get(finding.case_id).push(finding)
  const outcomes = normalizeCaseOutcomes(caseOutcomes, expectedIds, findingsByCase)

  const details = expected.map((entry) => {
    const reportable = findingsByCase.get(entry.case_id).filter(isReportableFinding)
    const primary = entry.expectation === 'vulnerable'
      ? reportable.filter((finding) => finding.topic === entry.topic)
      : []
    const selected = primary.length > 0 ? choosePrimaryFinding(primary) : null
    const acceptedTopics = new Set(entry.also_acceptable_topics)
    const acceptedCandidateIds = new Set(
      reportable
        .filter((finding) => acceptedTopics.has(finding.topic))
        .map((finding) => finding.candidate_id),
    )
    if (selected) acceptedCandidateIds.add(selected.candidate_id)

    const duplicateCandidateIds = selected
      ? primary
        .filter((finding) => finding.candidate_id !== selected.candidate_id)
        .map((finding) => finding.candidate_id)
        .sort()
      : []
    const unexpectedCandidateIds = reportable
      .filter((finding) => !acceptedCandidateIds.has(finding.candidate_id))
      .map((finding) => finding.candidate_id)
      .sort()

    const classification = entry.expectation === 'vulnerable'
      ? (selected ? 'TP' : 'FN')
      : (reportable.length > 0 ? 'FP' : 'TN')
    const severityResult = selected
      ? compareSeverity(selected.effective_severity, entry.expected_severity)
      : null

    return {
      case_id: entry.case_id,
      expectation: entry.expectation,
      topic: entry.topic,
      classification,
      expected_severity: entry.expected_severity,
      observed_severity: selected?.effective_severity ?? null,
      severity_result: severityResult,
      matched_candidate_id: selected?.candidate_id ?? null,
      reportable_finding_count: reportable.length,
      false_positive_finding_count: entry.expectation === 'clean' ? reportable.length : 0,
      duplicate_candidate_ids: duplicateCandidateIds,
      unexpected_candidate_ids: unexpectedCandidateIds,
      explicit_verdict: outcomes.get(entry.case_id) ?? null,
      false_clear: entry.expectation === 'vulnerable' && outcomes.get(entry.case_id) === 'clear',
    }
  })

  const summary = summarizeDetails(details)
  summary.counts.schema_invalid = schemaInvalidCount
  summary.counts.observed_records = findings.length
  summary.rates.schema_valid_rate = ratio(
    findings.length,
    findings.length + schemaInvalidCount,
  )

  const perTopic = [...new Set(expected.map((entry) => entry.topic))]
    .sort()
    .map((topic) => ({
      topic,
      ...summarizeDetails(details.filter((detail) => detail.topic === topic)),
    }))
  const vulnerableTopicRecalls = perTopic
    .filter((entry) => entry.counts.vulnerable_cases > 0)
    .map((entry) => entry.rates.recall)
  summary.rates.minimum_vulnerable_topic_recall = vulnerableTopicRecalls.length > 0
    ? Math.min(...vulnerableTopicRecalls)
    : null

  const unexpectedByTopic = new Map()
  for (const detail of details) {
    const byId = new Map(findingsByCase.get(detail.case_id).map((finding) => [
      finding.candidate_id,
      finding,
    ]))
    for (const candidateId of detail.unexpected_candidate_ids) {
      const topic = byId.get(candidateId)?.topic ?? '__unknown__'
      unexpectedByTopic.set(topic, (unexpectedByTopic.get(topic) ?? 0) + 1)
    }
  }

  return {
    schema_version: 1,
    counts: summary.counts,
    rates: summary.rates,
    per_topic: perTopic,
    unexpected_by_topic: [...unexpectedByTopic]
      .sort(([left], [right]) => compareCanonicalStrings(left, right))
      .map(([topic, count]) => ({ topic, count })),
    cases: details,
  }
}

export function jaccardSimilarity(leftValues, rightValues) {
  const left = new Set(leftValues)
  const right = new Set(rightValues)
  const union = new Set([...left, ...right])
  if (union.size === 0) return 1
  let intersection = 0
  for (const value of left) if (right.has(value)) intersection += 1
  return intersection / union.size
}

/**
 * Measure repeatability using the explicit fingerprint on a finding, falling
 * back to candidate_id. The case id is part of the comparison key so identical
 * candidate ids in different benchmark cases cannot collapse together.
 */
export function scoreFingerprintStability(runs, expectedCases) {
  if (!Array.isArray(runs) || runs.length === 0) {
    throw new EvaluationInputError('runs must be a non-empty array')
  }
  if (runs.length > EVALUATION_LIMITS.repeatedRuns) {
    throw new EvaluationInputError(
      `runs must contain at most ${EVALUATION_LIMITS.repeatedRuns} items`,
    )
  }
  const expectedIds = new Set(
    normalizeExpectedCases(expectedCases).map(({ case_id: caseId }) => caseId),
  )

  const issues = []
  const seenRuns = new Set()
  const normalizedRuns = []

  for (const [index, run] of runs.entries()) {
    const field = `runs[${index}]`
    if (!isRecord(run)) {
      issues.push(`${field} must be an object`)
      continue
    }
    const runId = nonEmptyString(run.run_id) ? run.run_id.trim() : null
    if (!runId) issues.push(`${field}.run_id must be a non-empty string`)
    else if (seenRuns.has(runId)) issues.push(`${field}.run_id duplicates ${JSON.stringify(runId)}`)
    else seenRuns.add(runId)

    let findings
    try {
      if (
        Array.isArray(run.findings)
        && run.findings.length > EVALUATION_LIMITS.findingsPerRepeatedRun
      ) {
        issues.push(
          `${field}.findings must contain at most ` +
          `${EVALUATION_LIMITS.findingsPerRepeatedRun} items`,
        )
        continue
      }
      findings = normalizeFindings(run.findings, expectedIds, `${field}.findings`)
    } catch (error) {
      if (error instanceof EvaluationInputError) issues.push(...error.issues)
      else throw error
      continue
    }

    const fingerprints = new Set()
    let duplicateCount = 0
    for (const finding of findings.filter(isReportableFinding)) {
      const fingerprint = finding.fingerprint ?? finding.candidate_id
      const key = `${finding.case_id}\u0000${fingerprint}`
      if (fingerprints.has(key)) duplicateCount += 1
      fingerprints.add(key)
    }
    normalizedRuns.push({
      run_id: runId,
      fingerprints,
      duplicate_fingerprint_count: duplicateCount,
    })
  }

  if (issues.length) throw new EvaluationInputError(issues)
  normalizedRuns.sort((left, right) => compareCanonicalStrings(left.run_id, right.run_id))

  const pairs = []
  for (let leftIndex = 0; leftIndex < normalizedRuns.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < normalizedRuns.length; rightIndex += 1) {
      const left = normalizedRuns[leftIndex]
      const right = normalizedRuns[rightIndex]
      pairs.push({
        left_run: left.run_id,
        right_run: right.run_id,
        jaccard: jaccardSimilarity(left.fingerprints, right.fingerprints),
      })
    }
  }

  const union = new Set(normalizedRuns.flatMap((run) => [...run.fingerprints]))
  const intersection = new Set(normalizedRuns[0].fingerprints)
  for (const run of normalizedRuns.slice(1)) {
    for (const fingerprint of intersection) {
      if (!run.fingerprints.has(fingerprint)) intersection.delete(fingerprint)
    }
  }
  const assessable = normalizedRuns.length >= 2 && union.size > 0
  const pairScores = pairs.map((pair) => pair.jaccard)

  return {
    run_count: normalizedRuns.length,
    pair_count: pairs.length,
    assessable,
    fingerprint_stability: assessable ? intersection.size / union.size : null,
    mean_pairwise_jaccard: assessable
      ? pairScores.reduce((sum, value) => sum + value, 0) / pairScores.length
      : null,
    minimum_pairwise_jaccard: assessable ? Math.min(...pairScores) : null,
    stable_fingerprint_count: intersection.size,
    union_fingerprint_count: union.size,
    duplicate_fingerprint_count: normalizedRuns.reduce(
      (sum, run) => sum + run.duplicate_fingerprint_count,
      0,
    ),
    pairs,
  }
}

function metricAtPath(metrics, path) {
  const segments = path.split('.')
  if (
    segments.some((segment) => !segment || UNSAFE_PATH_SEGMENTS.has(segment))
  ) {
    return { found: false, value: undefined }
  }
  let cursor = metrics
  for (const segment of segments) {
    if (!isRecord(cursor) || !Object.hasOwn(cursor, segment)) {
      return { found: false, value: undefined }
    }
    cursor = cursor[segment]
  }
  return { found: true, value: cursor }
}

function compareThreshold(actual, operator, expected) {
  if (operator === '>=') return actual >= expected
  if (operator === '<=') return actual <= expected
  if (operator === '>') return actual > expected
  if (operator === '<') return actual < expected
  return actual === expected
}

/**
 * Evaluate a declarative threshold profile. Configuration or metric errors are
 * returned as failed checks and make `passed` false; missing data never passes.
 */
export function evaluateThresholds(metrics, thresholds) {
  const errors = []
  const checks = []

  if (!isRecord(metrics)) errors.push('metrics must be an object')
  if (!isRecord(thresholds)) {
    return {
      profile: null,
      passed: false,
      errors: ['thresholds must be an object'],
      checks,
    }
  }

  const profile = nonEmptyString(thresholds.profile) ? thresholds.profile.trim() : null
  if (!profile) errors.push('thresholds.profile must be a non-empty string')
  if (thresholds.schema_version !== 1) {
    errors.push('thresholds.schema_version must equal 1')
  }
  if (!Array.isArray(thresholds.requirements) || thresholds.requirements.length === 0) {
    errors.push('thresholds.requirements must be a non-empty array')
  }
  if (
    Array.isArray(thresholds.requirements)
    && thresholds.requirements.length > EVALUATION_LIMITS.thresholdRequirements
  ) {
    errors.push(
      `thresholds.requirements must contain at most ` +
      `${EVALUATION_LIMITS.thresholdRequirements} items`,
    )
  }

  const seenIds = new Set()
  const boundedRequirements = Array.isArray(thresholds.requirements)
    ? thresholds.requirements.slice(0, EVALUATION_LIMITS.thresholdRequirements)
    : []
  for (const [index, requirement] of boundedRequirements.entries()) {
    const field = `thresholds.requirements[${index}]`
    if (!isRecord(requirement)) {
      errors.push(`${field} must be an object`)
      continue
    }
    const id = nonEmptyString(requirement.id) ? requirement.id.trim() : null
    const metric = nonEmptyString(requirement.metric) ? requirement.metric.trim() : null
    const operator = requirement.operator
    const expected = requirement.value

    if (!id) errors.push(`${field}.id must be a non-empty string`)
    else if (seenIds.has(id)) errors.push(`${field}.id duplicates ${JSON.stringify(id)}`)
    else seenIds.add(id)
    if (!metric) errors.push(`${field}.metric must be a non-empty string`)
    if (!THRESHOLD_OPERATORS.has(operator)) {
      errors.push(`${field}.operator must be one of ${[...THRESHOLD_OPERATORS].join(', ')}`)
    }
    if (typeof expected !== 'number' || !Number.isFinite(expected)) {
      errors.push(`${field}.value must be a finite number`)
    }
    if (!id || !metric || !THRESHOLD_OPERATORS.has(operator)
      || typeof expected !== 'number' || !Number.isFinite(expected)) {
      continue
    }

    const resolved = isRecord(metrics)
      ? metricAtPath(metrics, metric)
      : { found: false, value: undefined }
    if (!resolved.found || typeof resolved.value !== 'number' || !Number.isFinite(resolved.value)) {
      const message = `${id}: metric ${JSON.stringify(metric)} is missing or not a finite number`
      errors.push(message)
      checks.push({
        id,
        metric,
        operator,
        expected,
        actual: resolved.found ? resolved.value : null,
        passed: false,
        error: message,
      })
      continue
    }

    checks.push({
      id,
      metric,
      operator,
      expected,
      actual: resolved.value,
      passed: compareThreshold(resolved.value, operator, expected),
    })
  }

  return {
    profile,
    passed: errors.length === 0 && checks.length > 0 && checks.every((check) => check.passed),
    errors,
    checks,
  }
}
