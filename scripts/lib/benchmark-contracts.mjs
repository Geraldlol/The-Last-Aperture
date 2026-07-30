import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'

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

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (value === null || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.keys(value)
      .sort((left, right) => left.localeCompare(right, 'en'))
      .map((key) => [key, stableValue(value[key])]),
  )
}

function normalizedFindingSet(findings) {
  const records = findings
    .map((finding) => JSON.stringify(stableValue(finding)))
    .sort((left, right) => left.localeCompare(right, 'en'))
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
