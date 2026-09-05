import test from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const CLI = resolve('scripts/audit.mjs')
const CASES = {
  cases: [
    { case_id: 'C-SYNTHETIC', expectation: 'clean', topic: 'authz-object-level' },
    {
      case_id: 'V-SYNTHETIC', expectation: 'vulnerable',
      topic: 'authz-object-level', lens: 'web-and-api', expected_severity: 'Medium',
    },
  ],
}
const THRESHOLDS = {
  schema_version: 1,
  profile: 'synthetic-cli-contract',
  requirements: [{ id: 'valid-records', metric: 'counts.schema_invalid', operator: '==', value: 0 }],
}
const MEASUREMENT = {
  model: { name: 'synthetic-observations', version: '1', configuration_sha256: 'a'.repeat(64) },
  harness: { name: 'synthetic-cli-contract', version: '1', configuration_sha256: 'b'.repeat(64) },
  corpus: { name: 'two-synthetic-cases', version: '1' },
}

function syntheticRecord(severity = 'Medium') {
  return {
    case_id: 'V-SYNTHETIC',
    finding: {
      candidate_id: 'authz-object-level:synthetic-measurement',
      lens: 'web-and-api',
      topic: 'authz-object-level',
      title: 'Synthetic benchmark observation',
      claimed_impact_severity: severity,
      location: ['synthetic-fixture.txt:1'],
      evidence: 'Synthetic fixture observation; no target code was executed.',
      attack: 'Synthetic benchmark input, not an executable procedure.',
      impact: 'Synthetic expected finding used only to exercise scoring.',
      reachable_from: 'Synthetic scoring fixture only.',
      confidence: 'High',
      proof_plan: 'Compare normalized synthetic records with the test manifest.',
      effective_severity: severity,
      triage_disposition: 'queued',
      existence_check: { status: 'located', method: 'Synthetic fixture declaration.' },
      proof_tier: 'T3',
      verification_status: 'UNPROVEN',
      blocking_reason: 'Synthetic measurement test; no runtime proof is claimed.',
    },
  }
}

function findingOutcomes() {
  return [
    { case_id: 'C-SYNTHETIC', verdict: 'clear' },
    { case_id: 'V-SYNTHETIC', verdict: 'finding' },
  ]
}

async function withBenchmark(input, callback) {
  const directory = await mkdtemp(join(tmpdir(), 'red-team-measurement-cli-'))
  const documents = {
    evaluation_input: { path: join(directory, 'evaluation.json'), text: JSON.stringify(input) },
    case_manifest: { path: join(directory, 'cases.json'), text: JSON.stringify(CASES) },
    thresholds: { path: join(directory, 'thresholds.json'), text: JSON.stringify(THRESHOLDS) },
  }
  try {
    await Promise.all(Object.values(documents).map(({ path, text }) => writeFile(path, text)))
    const run = () => spawnSync(process.execPath, [
      CLI, 'benchmark', documents.evaluation_input.path,
      '--cases', documents.case_manifest.path,
      '--thresholds', documents.thresholds.path,
    ], { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024, timeout: 30_000 })
    await callback({ documents, run })
  } finally {
    await rm(directory, { recursive: true, force: true })
  }
}

function scorecardFrom(result, expectedStatus = 0) {
  assert.equal(result.error, undefined)
  assert.equal(result.status, expectedStatus, result.stderr)
  return JSON.parse(result.stdout)
}

test('benchmark CLI propagates declared versions and reproducible content bindings', async () => {
  const records = [syntheticRecord()]
  await withBenchmark({
    primary_run_id: 'primary', observedFindings: records,
    measurement: MEASUREMENT,
    repeatedRuns: [{ run_id: 'primary', findings: records, caseOutcomes: findingOutcomes() }],
  }, async ({ documents, run }) => {
    const first = scorecardFrom(run())
    const second = scorecardFrom(run())
    assert.deepEqual(first.provenance.measurement, MEASUREMENT)
    assert.equal(first.provenance.measurement_authority, 'CALLER_DECLARED')
    assert.match(first.provenance.observation_authority, /caller-supplied/)
    assert.ok(Number.isFinite(Date.parse(first.generated_at)))
    assert.equal(first.provenance.case_manifest.cases, 2)
    for (const [name, document] of Object.entries(documents)) {
      assert.equal(first.provenance[name].path, document.path)
      assert.equal(first.provenance[name].sha256, createHash('sha256').update(document.text).digest('hex'))
    }
    assert.equal(first.provenance.primary_run.run_id, 'primary')
    assert.equal(first.provenance.primary_run.bound_to_repeated_run, true)
    assert.equal(first.provenance.primary_run.normalized_finding_count, 1)
    assert.match(first.provenance.primary_run.normalized_finding_set_sha256, /^[a-f0-9]{64}$/)
    assert.deepEqual(second.provenance, first.provenance)
    assert.deepEqual(second.metrics, first.metrics)
    assert.equal(first.metrics.counts.assessed_cases, 2)
    assert.equal(first.metrics.repeated.runs[0].rates.assessed_accuracy, 1)
  })
})

test('benchmark CLI rejects conflicting top-level and primary repeat outcomes', async () => {
  await withBenchmark({
    primary_run_id: 'primary', observedFindings: [], caseOutcomes: [],
    repeatedRuns: [{
      run_id: 'primary', findings: [],
      caseOutcomes: [{ case_id: 'C-SYNTHETIC', verdict: 'clear' }],
    }],
  }, async ({ run }) => {
    const result = run()
    assert.equal(result.status, 1)
    assert.match(result.stderr, /caseOutcomes must exactly match repeated run "primary"/)
    assert.equal(result.stdout, '')
  })
})

test('benchmark CLI binds legacy outcomes only to primary and exposes silent repeat coverage', async () => {
  await withBenchmark({
    primary_run_id: 'primary', observedFindings: [],
    caseOutcomes: [
      { case_id: 'C-SYNTHETIC', verdict: 'clear' },
      { case_id: 'V-SYNTHETIC', verdict: 'incomplete' },
    ],
    repeatedRuns: [{ run_id: 'primary', findings: [] }, { run_id: 'silent', findings: [] }],
  }, async ({ run }) => {
    const scorecard = scorecardFrom(run())
    assert.equal(scorecard.provenance.measurement, null)
    const [primary, silent] = scorecard.metrics.repeated.runs
    assert.equal(primary.counts.assessed_cases, 1)
    assert.equal(primary.counts.incomplete_cases, 1)
    assert.equal(silent.counts.unspecified_cases, 2)
    assert.equal(silent.counts.assessed_cases, 0)
    assert.equal(silent.counts.abstentions, 0)
    assert.equal(silent.rates.assessed_accuracy, null)
    assert.equal(scorecard.metrics.counts.assessed_cases, primary.counts.assessed_cases)
    assert.equal(scorecard.metrics.repeated.aggregate.rates.assessed_accuracy.unassessed_runs, 1)
  })
})

test('benchmark CLI scores repeat severity, accuracy, false clears, and abstentions separately', async () => {
  const good = [syntheticRecord('Medium')]
  await withBenchmark({
    primary_run_id: 'a-good', observedFindings: good,
    repeatedRuns: [
      { run_id: 'a-good', findings: good, caseOutcomes: findingOutcomes() },
      { run_id: 'b-low', findings: [syntheticRecord('Low')], caseOutcomes: findingOutcomes() },
      {
        run_id: 'c-missed', findings: [], caseOutcomes: [
          { case_id: 'V-SYNTHETIC', verdict: 'clear' },
          { case_id: 'C-SYNTHETIC', verdict: 'not_assessed' },
        ],
      },
    ],
  }, async ({ run }) => {
    const { metrics } = scorecardFrom(run())
    assert.equal(metrics.repeated.run_count, 3)
    const [goodRun, lowRun, missedRun] = metrics.repeated.runs
    assert.equal(goodRun.rates.severity_accuracy, 1)
    assert.equal(lowRun.rates.severity_accuracy, 0)
    assert.equal(lowRun.counts.severity_under, 1)
    assert.equal(missedRun.counts.false_clears, 1)
    assert.equal(missedRun.counts.not_assessed_cases, 1)
    assert.equal(missedRun.counts.abstentions, 1)
    assert.equal(missedRun.rates.assessed_accuracy, 0)
    assert.deepEqual(metrics.repeated.aggregate.rates.accuracy, {
      minimum: 0.5, maximum: 1, mean: 5 / 6, assessed_runs: 3, unassessed_runs: 0,
    })
    assert.deepEqual(metrics.repeated.aggregate.rates.severity_accuracy, {
      minimum: 0, maximum: 1, mean: 0.5, assessed_runs: 2, unassessed_runs: 1,
    })
    assert.equal(metrics.counts.false_clears, 0, 'secondary verdicts do not rewrite primary results')
  })
})

test('benchmark CLI exposes malformed secondary record debt in both release and repeat scores', async () => {
  const good = [syntheticRecord()]
  await withBenchmark({
    primary_run_id: 'primary', observedFindings: good,
    repeatedRuns: [
      { run_id: 'primary', findings: good, caseOutcomes: findingOutcomes() },
      { run_id: 'secondary', findings: [{ case_id: 'V-SYNTHETIC', finding: { candidate_id: 'invalid' } }] },
    ],
  }, async ({ run }) => {
    const scorecard = scorecardFrom(run(), 2)
    assert.equal(scorecard.gate.passed, false)
    assert.equal(scorecard.invalid_records.length, 1)
    assert.equal(scorecard.invalid_records[0].record, 'repeatedRuns[1].findings[0]')
    assert.equal(scorecard.metrics.counts.schema_invalid, 1)
    assert.equal(scorecard.metrics.repeated.runs[0].counts.schema_invalid, 0)
    assert.equal(scorecard.metrics.repeated.runs[1].counts.schema_invalid, 1)
    assert.equal(scorecard.metrics.repeated.aggregate.counts.schema_invalid.maximum, 1)
    assert.equal(scorecard.metrics.repeated.runs[1].counts.unspecified_cases, 2)
  })
})

test('benchmark CLI validates secondary verdicts against the shared case denominator', async () => {
  await withBenchmark({
    primary_run_id: 'primary', observedFindings: [],
    repeatedRuns: [
      { run_id: 'primary', findings: [] },
      { run_id: 'secondary', findings: [], caseOutcomes: [{ case_id: 'C-UNKNOWN', verdict: 'clear' }] },
    ],
  }, async ({ run }) => {
    const result = run()
    assert.equal(result.status, 1)
    assert.match(result.stderr, /references unknown case "C-UNKNOWN"/)
    assert.equal(result.stdout, '')
  })
})
