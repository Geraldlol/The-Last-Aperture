import { compareCanonicalStrings } from './canonical-order.mjs'
import { projectCoverageGaps } from './coverage-gaps.mjs'
import {
  displayVerificationStatus,
  isSurvivingFinding,
} from './findings.mjs'
import { terminalSafeLines } from './terminal-text.mjs'
import { topicAssessmentSummary } from './topic-assessments.mjs'

const SAMPLE_LIMIT = 20
const TERMINAL_STATES = new Set(['COMPLETED', 'COMPLETE_WITH_GAPS', 'FAILED', 'ABORTED'])

function counts(values, initial = []) {
  const entries = new Map(initial.map((key) => [key, 0]))
  for (const value of values) entries.set(value, (entries.get(value) ?? 0) + 1)
  return Object.fromEntries([...entries].sort(([a], [b]) => compareCanonicalStrings(a, b)))
}

function boundedText(value) {
  const text = String(value ?? '')
  return text.length > 400 ? `${text.slice(0, 400)}...[truncated]` : text
}

function sampled(items) {
  return {
    total: items.length,
    items: items.slice(0, SAMPLE_LIMIT),
    omitted: Math.max(0, items.length - SAMPLE_LIMIT),
  }
}

function jobSummary(job) {
  return {
    job_id: boundedText(job.job_id),
    kind: job.kind,
    state: job.state,
    ...(job.lens ? { lens: boundedText(job.lens) } : {}),
    ...(job.reason ? { reason: boundedText(job.reason) } : {}),
  }
}

function nextStep(run, pendingCount, runningCount, attempts) {
  if (TERMINAL_STATES.has(run.state)) {
    return {
      code: ['FAILED', 'ABORTED'].includes(run.state) ? 'REVIEW_FAILURE' : 'REVIEW_REPORT',
      message: 'Review the report, retained findings, errors, and coverage gaps for this terminal run.',
    }
  }
  if (attempts.some((attempt) => attempt.status === 'RESULT_AVAILABLE')) {
    return {
      code: 'REVIEW_CAPTURED_RESULT',
      message: 'An attempt has captured results awaiting validation or commit; inspect its recorded state before resuming.',
    }
  }
  if (attempts.some((attempt) => attempt.status === 'LEASE_EXPIRED')) {
    return {
      code: 'REVIEW_EXPIRED_ATTEMPT',
      message: 'An attempt lease expired. Check the original controller and cleanup evidence; expiry alone does not prove it stopped.',
    }
  }
  if (pendingCount > 0) {
    return { code: 'INSPECT_PENDING_WORK', message: 'Use next to inspect the pending job packets for the current phase.' }
  }
  if (runningCount > 0) {
    return { code: 'AWAIT_RESULTS', message: 'Work is recorded as running; inspect its result or attempt state.' }
  }
  if (run.phase === 'COMPLETENESS') {
    return {
      code: 'REVIEW_FINALIZATION',
      message: 'No current-phase work is pending. Finalize will check all remaining stage and coverage requirements.',
    }
  }
  return { code: 'REVIEW_PHASE', message: 'No job is dispatchable in this phase; review job failures, dependencies, and coverage.' }
}

/** Project a validated run without reading targets, advancing jobs, or claiming clearance. */
export function summarizeRunStatus(run, {
  pendingJobs = [],
  activeAttempts = [],
  observedAt = new Date(),
} = {}) {
  const observed = new Date(observedAt)
  if (!Number.isFinite(observed.getTime())) throw new TypeError('observedAt must be a valid date')
  const jobs = run.jobs ?? []
  const terminal = TERMINAL_STATES.has(run.state)
  const byId = (left, right) => compareCanonicalStrings(left.job_id, right.job_id)
  const pending = terminal ? [] : [...pendingJobs].sort(byId)
  const running = jobs.filter((job) => job.state === 'RUNNING').sort(byId)
  const failed = jobs.filter((job) => job.state === 'FAILED').sort(byId)
  const attempts = [...activeAttempts]
    .sort((left, right) => compareCanonicalStrings(left.attempt_id, right.attempt_id))
    .map((attempt) => ({
      attempt_id: boundedText(attempt.attempt_id),
      job_id: boundedText(attempt.job_id),
      state: attempt.state,
      backend: attempt.lease.backend,
      expires_at: boundedText(attempt.lease.expires_at),
      status: ['RESULT_CAPTURED', 'VALIDATED'].includes(attempt.state)
        ? 'RESULT_AVAILABLE'
        : observed.getTime() >= Date.parse(attempt.lease.expires_at)
          ? 'LEASE_EXPIRED'
          : 'LEASE_UNEXPIRED',
    }))
  const findings = run.findings ?? []
  const retained = findings.filter(isSurvivingFinding)
  const coverage = run.coverage ?? {}
  const topics = topicAssessmentSummary(run)
  const closure = coverage.closure
  const gaps = projectCoverageGaps(coverage.gaps ?? [], {
    resolvedGapIds: coverage.resolved_gap_ids ?? [],
  })
  return {
    schema_version: '1.0.0',
    run_id: run.run_id,
    state: run.state,
    phase: run.phase,
    terminal,
    observed_at: observed.toISOString(),
    target: boundedText(run.repository.root),
    capability_mode: run.capability_mode,
    source_sealed: Boolean(run.source_snapshot),
    jobs: {
      total: jobs.length,
      by_state: counts(jobs.map((job) => job.state), [
        'DORMANT', 'PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'SKIPPED',
      ]),
      by_kind: counts(jobs.map((job) => job.kind)),
      pending_current_phase: sampled(pending.map(jobSummary)),
      running: sampled(running.map(jobSummary)),
      failed: sampled(failed.map(jobSummary)),
    },
    active_attempts: sampled(attempts),
    findings: {
      status: retained.length > 0 ? 'FINDINGS_REPORTED' : 'NO_FINDINGS_REPORTED',
      reported: findings.length,
      retained: retained.length,
      removed: findings.length - retained.length,
      by_claimed_severity: counts(retained.map((finding) =>
        finding.claimed_impact_severity ?? finding.effective_severity ?? 'NOT_RECORDED'),
      ['Critical', 'High', 'Medium', 'Low', 'Info']),
      by_verification: counts(retained.map((finding) =>
        displayVerificationStatus(finding) ?? 'NOT_ASSESSED')),
    },
    coverage: {
      inventory_files: coverage.inventory?.length ?? 0,
      examined_files: coverage.examined?.length ?? 0,
      unexamined_files: coverage.unexamined?.length ?? 0,
      lenses_by_status: counts((coverage.lenses ?? []).map((lens) => lens.status)),
      topics: {
        obligations: topics.obligations,
        closed: topics.closed,
        partial: topics.partial,
        not_assessed: topics.not_assessed,
        open: topics.open,
      },
      gaps: {
        ...gaps,
        examples: gaps.examples.map((gap) => ({
          ...gap,
          ...(gap.lens ? { lens: boundedText(gap.lens) } : {}),
        })),
      },
      closure: closure ? {
        status: closure.status,
        required_source_closure: closure.required_source_closure,
        round: closure.round,
        max_rounds: closure.max_rounds,
        uncovered_lens_file_pairs: closure.uncovered_lens_file_pairs ?? null,
      } : { status: 'NOT_RECORDED' },
    },
    errors: sampled((run.errors ?? []).map((error) => ({
      code: boundedText(error.code),
      phase: error.phase,
      message: boundedText(error.message),
      recoverable: error.recoverable,
      ...(error.job_id ? { job_id: boundedText(error.job_id) } : {}),
    }))),
    next_step: nextStep(run, pending.length, running.length, attempts),
    nonclaims: [
      'Job completion and examined bytes do not establish semantic coverage or security clearance.',
      'Status inspects recorded bundle state; it does not check the current target or controller process liveness.',
    ],
  }
}

export function renderRunStatus(status) {
  const state = status.jobs.by_state
  const coverage = status.coverage
  const lines = [
    `Run: ${status.run_id}`,
    `State: ${status.state} / ${status.phase}`,
    `Target: ${status.target}`,
    `Capability: ${status.capability_mode}; sealed source: ${status.source_sealed ? 'yes' : 'no'}`,
    `Bundle integrity: ${status.bundle_integrity ?? 'NOT_CHECKED'}; root authenticity: ${status.root_authenticity ?? 'UNANCHORED'}`,
    `Jobs: ${state.SUCCEEDED} succeeded, ${state.RUNNING} running, ${state.PENDING} pending, ${state.FAILED} failed, ${state.SKIPPED} skipped, ${state.DORMANT} dormant`,
    `Current-phase pending jobs: ${status.jobs.pending_current_phase.total}`,
    `Findings: ${status.findings.status} (${status.findings.retained} retained)`,
    `Claimed severity: ${Object.entries(status.findings.by_claimed_severity).map(([key, value]) => `${key}=${value}`).join(', ')}`,
    `Verification: ${Object.entries(status.findings.by_verification).map(([key, value]) => `${key}=${value}`).join(', ') || 'none recorded'}`,
    `Files: ${coverage.examined_files}/${coverage.inventory_files} examined; ${coverage.unexamined_files} unexamined`,
    `Topic obligations: ${coverage.topics.closed}/${coverage.topics.obligations} closed; ${coverage.topics.open} open`,
    `Open gaps: ${coverage.gaps.unique_open_gap_count} distinct areas; ${coverage.gaps.exact_open_gap_count} exact obligations`,
    `Coverage closure: ${coverage.closure.status}`,
    `Recorded errors: ${status.errors.total}`,
  ]
  for (const job of status.jobs.failed.items) {
    lines.push(`Failed job: ${job.job_id} (${job.kind}): ${job.reason ?? 'reason not recorded'}`)
  }
  for (const attempt of status.active_attempts.items) {
    lines.push(`Attempt: ${attempt.attempt_id} / ${attempt.job_id}: ${attempt.state}, ${attempt.status}; expires ${attempt.expires_at}`)
  }
  for (const error of status.errors.items) lines.push(`Error: ${error.phase}/${error.code}: ${error.message}`)
  for (const gap of coverage.gaps.examples) lines.push(`Gap: ${gap.area}: ${gap.reason}`)
  const omitted = status.jobs.failed.omitted + status.active_attempts.omitted
    + status.errors.omitted + coverage.gaps.omitted_example_count
  if (omitted > 0) lines.push(`Additional detail entries omitted: ${omitted}; full records remain in the bundle.`)
  lines.push(`Next: ${status.next_step.message}`, ...status.nonclaims)
  return `${terminalSafeLines(lines)}\n`
}
