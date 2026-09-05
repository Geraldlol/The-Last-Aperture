import { test } from 'node:test'
import assert from 'node:assert/strict'
import { renderRunStatus, summarizeRunStatus } from '../scripts/lib/run-status.mjs'
import { createLensFileCoverageGap, exactCoverageGapId } from '../scripts/lib/coverage-gaps.mjs'

const OBSERVED_AT = '2026-09-05T12:00:00.000Z'

function run(overrides = {}) {
  return {
    run_id: 'status:fixture', state: 'PLANNED', phase: 'RECON', capability_mode: 'STATIC',
    repository: { root: 'C:/fixtures/status-target' },
    jobs: [], findings: [], errors: [],
    coverage: { inventory: [], examined: [], unexamined: [], lenses: [], gaps: [] },
    ...overrides,
  }
}

function summary(value, options = {}) {
  return summarizeRunStatus(value, { observedAt: OBSERVED_AT, ...options })
}

test('status preserves no-findings as a non-clearance claim and never mutates its input', () => {
  const value = run()
  const before = structuredClone(value)
  const result = summary(value)
  assert.equal(result.findings.status, 'NO_FINDINGS_REPORTED')
  assert.equal(result.coverage.closure.status, 'NOT_RECORDED')
  assert.equal(result.terminal, false)
  assert.equal(result.next_step.code, 'REVIEW_PHASE')
  assert.match(renderRunStatus(result), /do not establish semantic coverage or security clearance/)
  assert.deepEqual(value, before)
})

test('status separates dormant, skipped, pending, running, failed, and successful work', () => {
  const jobs = ['DORMANT', 'SKIPPED', 'PENDING', 'RUNNING', 'FAILED', 'SUCCEEDED']
    .map((state, index) => ({ job_id: `lens:${index}`, kind: 'LENS', state, lens: 'web-and-api' }))
  const value = run({ jobs })
  const result = summary(value, { pendingJobs: [jobs[2]] })
  assert.equal(result.jobs.total, 6)
  assert.equal(result.jobs.by_state.DORMANT, 1)
  assert.equal(result.jobs.by_state.SKIPPED, 1)
  assert.equal(result.jobs.by_state.SUCCEEDED, 1)
  assert.equal(result.jobs.pending_current_phase.total, 1)
  assert.equal(result.jobs.running.total, 1)
  assert.equal(result.jobs.failed.total, 1)
  assert.equal(result.next_step.code, 'INSPECT_PENDING_WORK')
  assert.deepEqual(value.jobs, jobs)
})

test('terminal status never advertises pending dispatch and distinguishes failed audits', () => {
  const pending = { job_id: 'report:final', kind: 'REPORT', state: 'PENDING' }
  for (const state of ['COMPLETED', 'COMPLETE_WITH_GAPS', 'FAILED', 'ABORTED']) {
    const result = summary(run({ state, phase: 'FINALIZED', jobs: [pending] }), { pendingJobs: [pending] })
    assert.equal(result.terminal, true)
    assert.equal(result.jobs.pending_current_phase.total, 0)
    assert.equal(result.next_step.code,
      ['FAILED', 'ABORTED'].includes(state) ? 'REVIEW_FAILURE' : 'REVIEW_REPORT')
  }
})

test('status retains untrusted negative findings and does not promote confirmation or lower claimed impact', () => {
  const findings = [
    { candidate_id: 'finding:a', claimed_impact_severity: 'Critical', effective_severity: 'Medium', verification_status: 'CONFIRMED' },
    { candidate_id: 'finding:b', claimed_impact_severity: 'High', verification_status: 'DISPROVED', triage_disposition: 'dropped' },
    { candidate_id: 'finding:c', claimed_impact_severity: 'Low', verification_status: 'NOT_REPRODUCED', triage_disposition: 'merged' },
    { candidate_id: 'finding:d', claimed_impact_severity: 'Medium' },
  ]
  const result = summary(run({ findings })).findings
  assert.equal(result.reported, 4)
  assert.equal(result.retained, 4)
  assert.equal(result.removed, 0)
  assert.equal(result.by_claimed_severity.Critical, 1)
  assert.equal(result.by_verification.CLAIMED_CONFIRMED, 1)
  assert.equal(result.by_verification.CLAIMED_DISPROVED, 1)
  assert.equal(result.by_verification.CLAIMED_NOT_REPRODUCED, 1)
  assert.equal(result.by_verification.NOT_ASSESSED, 1)
  assert.equal(result.by_verification.CONFIRMED, undefined)
})

test('status separates examined files, topic obligations, exact gaps, and coverage closure', () => {
  const gapA = createLensFileCoverageGap({ lens: 'web-and-api', path: 'src/a.js', reason: 'Not assessed' })
  const gapB = createLensFileCoverageGap({ lens: 'web-and-api', path: 'src/b.js', reason: 'Not assessed' })
  const result = summary(run({
    jobs: [{ job_id: 'lens:1', kind: 'LENS', state: 'SUCCEEDED', lens: 'web-and-api',
      topic_obligations: ['topic-a', 'topic-b', 'topic-c'],
      topic_assessments: [
        { topic: 'topic-a', disposition: 'examined-clean' },
        { topic: 'topic-b', disposition: 'partial' },
      ],
    }],
    coverage: {
      inventory: ['src/a.js', 'src/b.js'], examined: ['src/a.js', 'src/b.js'], unexamined: [],
      lenses: [{ lens: 'web-and-api', status: 'PARTIAL' }],
      gaps: [gapA, { ...gapA, reason: 'Retry still missing' }, gapB],
      resolved_gap_ids: [exactCoverageGapId(gapB)],
      closure: { status: 'BUDGET_EXHAUSTED', required_source_closure: true, round: 3, max_rounds: 3 },
    },
  })).coverage
  assert.equal(result.examined_files, 2)
  assert.deepEqual(result.topics, { obligations: 3, closed: 1, partial: 1, not_assessed: 1, open: 2 })
  assert.equal(result.gaps.exact_open_gap_count, 1)
  assert.equal(result.gaps.unique_open_gap_count, 1)
  assert.equal(result.gaps.resolved_input_gap_count, 1)
  assert.equal(result.closure.status, 'BUDGET_EXHAUSTED')
  assert.equal(result.closure.uncovered_lens_file_pairs, null)
})

test('attempt expiry uses the observation boundary but captured results remain available', () => {
  const attempt = {
    attempt_id: 'attempt:1', job_id: 'proof:1', state: 'STARTED',
    lease: { backend: 'SERVICE_PROOF_CONTAINER', expires_at: OBSERVED_AT },
  }
  const value = run({ state: 'RUNNING', phase: 'PROOF' })
  const expired = summary(value, { activeAttempts: [attempt] })
  assert.equal(expired.active_attempts.items[0].status, 'LEASE_EXPIRED')
  assert.equal(expired.next_step.code, 'REVIEW_EXPIRED_ATTEMPT')
  assert.match(expired.next_step.message, /expiry alone does not prove it stopped/)
  const unexpired = summary(value, { activeAttempts: [attempt], observedAt: '2026-09-05T11:59:59.999Z' })
  assert.equal(unexpired.active_attempts.items[0].status, 'LEASE_UNEXPIRED')
  for (const state of ['RESULT_CAPTURED', 'VALIDATED']) {
    const captured = summary(value, { activeAttempts: [{ ...attempt, state }] })
    assert.equal(captured.active_attempts.items[0].status, 'RESULT_AVAILABLE')
    assert.equal(captured.next_step.code, 'REVIEW_CAPTURED_RESULT')
  }
})

test('status bounds detail samples without reducing totals and uses unsampled attempts for guidance', () => {
  const jobs = Array.from({ length: 25 }, (_, i) => ({
    job_id: `job:${i.toString().padStart(2, '0')}`, kind: 'LENS', state: 'FAILED', reason: 'x'.repeat(1000),
  }))
  const activeAttempts = jobs.map((job, i) => ({
    attempt_id: `attempt:${i.toString().padStart(2, '0')}`, job_id: job.job_id,
    state: i === 24 ? 'RESULT_CAPTURED' : 'STARTED',
    lease: { backend: 'SERVICE_PROOF_CONTAINER', expires_at: OBSERVED_AT },
  }))
  const errors = jobs.map((job) => ({ code: 'TEST_FAILURE', phase: 'FANOUT', message: job.reason, recoverable: false }))
  const value = summary(run({ jobs, errors }), { activeAttempts })
  assert.equal(value.jobs.failed.total, 25)
  assert.equal(value.jobs.failed.items.length, 20)
  assert.equal(value.jobs.failed.omitted, 5)
  assert.ok(value.jobs.failed.items.every((job) => job.reason.length < 420))
  assert.equal(value.errors.total, 25)
  assert.equal(value.errors.items.length, 20)
  assert.equal(value.active_attempts.omitted, 5)
  assert.equal(value.next_step.code, 'REVIEW_CAPTURED_RESULT')
})

test('status text neutralizes terminal controls and rejects invalid observation time', () => {
  const value = run({ errors: [{ code: 'FAIL', phase: 'FANOUT', message: '\u001b[2J\u202eoverwritten\nNext: all clear', recoverable: false }] })
  const output = renderRunStatus(summary(value))
  assert.doesNotMatch(output, /[\u001b\u202e]/u)
  assert.match(output, /\\u001B\[2J\\u202E/)
  assert.match(output, /\\u000ANext: all clear/)
  assert.throws(() => summary(value, { observedAt: 'invalid' }), /valid date/)
})

test('status bounds diagnostic identifiers as well as messages in JSON output', () => {
  const large = 'x'.repeat(100_000)
  const gap = createLensFileCoverageGap({ lens: large, path: 'app.js', reason: 'Not assessed' })
  const value = summary(run({
    repository: { root: large },
    jobs: [{ job_id: large, kind: 'LENS', lens: large, state: 'FAILED', reason: large }],
    errors: [{ code: large, job_id: large, phase: 'FANOUT', message: large, recoverable: false }],
    coverage: { ...run().coverage, gaps: [gap] },
  }))
  assert.ok(JSON.stringify(value).length < 10_000)
  assert.match(value.target, /\[truncated\]$/)
  assert.match(value.errors.items[0].code, /\[truncated\]$/)
  assert.match(value.errors.items[0].job_id, /\[truncated\]$/)
  assert.match(value.jobs.failed.items[0].lens, /\[truncated\]$/)
  assert.match(value.coverage.gaps.examples[0].lens, /\[truncated\]$/)
  assert.equal(value.coverage.gaps.examples[0].gap_id, gap.gap_id)
  assert.equal(value.coverage.gaps.exact_open_gap_count, 1)
})
