import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import { compareCanonicalStrings } from './canonical-order.mjs'

const BENCHMARK_INPUT_SCHEMA_URL = new URL(
  '../../schemas/benchmark-input.schema.json',
  import.meta.url,
)

export const benchmarkInputSchema = JSON.parse(
  readFileSync(fileURLToPath(BENCHMARK_INPUT_SCHEMA_URL), 'utf8'),
)

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
})
const validateInputSchema = ajv.compile(benchmarkInputSchema)
const validateCaseOutcomes = ajv.compile({
  $ref: `${benchmarkInputSchema.$id}#/$defs/caseOutcomes`,
})

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (value === null || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.keys(value)
      .sort(compareCanonicalStrings)
      .map((key) => [key, stableValue(value[key])]),
  )
}

function normalizedFindingSet(findings) {
  const records = findings
    .map((finding) => JSON.stringify(stableValue(finding)))
    .sort(compareCanonicalStrings)
  const canonical = JSON.stringify(records)
  return {
    canonical,
    count: records.length,
    sha256: createHash('sha256').update(canonical).digest('hex'),
  }
}

function schemaIssue(error) {
  const path = error.instancePath || '/'
  if (error.keyword === 'required') {
    return `${path} requires ${error.params.missingProperty}`
  }
  return `${path} ${error.message}`
}

export function assertValidBenchmarkInput(value) {
  if (!validateInputSchema(value)) {
    throw new TypeError(
      `benchmark input contract validation failed:\n- ` +
      validateInputSchema.errors.map(schemaIssue).join('\n- '),
    )
  }
  return value
}

export function bindBenchmarkPrimaryRun(primaryRunId, observedFindings, repeatedRuns) {
  const normalizedId = primaryRunId.trim()
  const matches = repeatedRuns.filter(({ run_id: runId }) => runId === normalizedId)
  if (matches.length !== 1) {
    throw new TypeError(
      `primary_run_id ${JSON.stringify(normalizedId)} must identify exactly one repeated run`,
    )
  }

  const observed = normalizedFindingSet(observedFindings)
  const primary = normalizedFindingSet(matches[0].findings)
  if (observed.canonical !== primary.canonical) {
    throw new TypeError(
      `observedFindings must exactly match repeated run ${JSON.stringify(normalizedId)} ` +
      'after canonical finding normalization',
    )
  }

  return {
    run_id: normalizedId,
    normalized_finding_count: observed.count,
    normalized_finding_set_sha256: observed.sha256,
    bound_to_repeated_run: true,
  }
}

function normalizedCaseOutcomes(outcomes) {
  if (!validateCaseOutcomes(outcomes)) {
    throw new TypeError(
      'benchmark case outcome validation failed:\n- ' +
      validateCaseOutcomes.errors.map(schemaIssue).join('\n- '),
    )
  }
  const seen = new Set()
  return outcomes.map(({ case_id: caseId, verdict }) => {
    const normalizedId = caseId.trim()
    if (seen.has(normalizedId)) {
      throw new TypeError(`benchmark case outcomes duplicate ${JSON.stringify(normalizedId)}`)
    }
    seen.add(normalizedId)
    return { case_id: normalizedId, verdict }
  }).sort((left, right) => compareCanonicalStrings(left.case_id, right.case_id))
}

/** Bind optional legacy top-level outcomes to the primary run only. A repeat
 * with no declared outcomes stays unspecified, even if the primary was clear.
 */
export function bindBenchmarkPrimaryOutcomes(primaryRunId, topLevelCaseOutcomes, repeatedRuns) {
  const normalizedId = primaryRunId.trim()
  const primaryRuns = repeatedRuns.filter(({ run_id: runId }) => runId === normalizedId)
  if (primaryRuns.length !== 1) {
    throw new TypeError(
      `primary_run_id ${JSON.stringify(normalizedId)} must identify exactly one repeated run`,
    )
  }
  const primaryOutcomes = primaryRuns[0].caseOutcomes
  const top = topLevelCaseOutcomes === undefined ? undefined : normalizedCaseOutcomes(topLevelCaseOutcomes)
  const primary = primaryOutcomes === undefined ? undefined : normalizedCaseOutcomes(primaryOutcomes)
  if (top !== undefined && primary !== undefined && JSON.stringify(top) !== JSON.stringify(primary)) {
    throw new TypeError(
      `caseOutcomes must exactly match repeated run ${JSON.stringify(normalizedId)} ` +
      'after canonical outcome normalization',
    )
  }
  const caseOutcomes = primary ?? top ?? []
  return {
    caseOutcomes,
    repeatedRuns: repeatedRuns.map((run) => run.run_id === normalizedId
      ? { ...run, caseOutcomes }
      : run),
  }
}
