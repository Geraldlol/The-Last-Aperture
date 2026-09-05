import { compareCanonicalStrings } from './canonical-order.mjs'
import {
  displayTriageDisposition,
  displayVerificationStatus,
  hasAuthenticatedTriage,
  hasAuthenticatedVerification,
  isSurvivingFinding,
} from './findings.mjs'
import { findingFingerprint } from './lifecycle.mjs'
import { terminalSafeLines } from './terminal-text.mjs'

function bounded(value) {
  const text = String(value ?? '')
  return text.length > 400 ? `${text.slice(0, 400)}...[truncated]` : text
}

/** Describe recorded evidence requirements. It cannot register trust or promote a verdict. */
export function buildVerdictAssessment(run, { candidateId } = {}) {
  const all = run.findings ?? []
  if (candidateId !== undefined && !all.some((finding) => finding.candidate_id === candidateId)) {
    throw new Error('candidate not found in this run')
  }
  const selected = all.filter((finding) => candidateId === undefined || finding.candidate_id === candidateId)
    .sort((left, right) => compareCanonicalStrings(left.candidate_id, right.candidate_id))
  const records = selected.slice(0, 100).map((finding) => {
    const proofJobs = (run.jobs ?? []).filter((job) =>
      job.kind === 'PROOF' && (job.candidate_ids ?? []).includes(finding.candidate_id))
    const missing = []
    if (!hasAuthenticatedVerification(finding)) missing.push('AUTHENTICATED_SEMANTIC_VERIFIER_UNAVAILABLE')
    if (!hasAuthenticatedTriage(finding)) missing.push('TRIAGE_DECISION_UNAUTHENTICATED')
    if (!(finding.source_anchors?.length > 0) && !finding.evidence_context) {
      missing.push('SOURCE_ANCHOR_NOT_RECORDED')
    }
    if (!finding.verification_status) missing.push('VERIFICATION_NOT_ASSESSED')
    if (proofJobs.some((job) => job.state === 'FAILED')) missing.push('PROOF_JOB_FAILED')
    if (proofJobs.some((job) => ['PENDING', 'RUNNING'].includes(job.state))) missing.push('PROOF_WORK_INCOMPLETE')
    return {
      candidate_id: bounded(finding.candidate_id),
      fingerprint: findingFingerprint(finding),
      retained: isSurvivingFinding(finding),
      verification: displayVerificationStatus(finding) ?? 'NOT_ASSESSED',
      triage: displayTriageDisposition(finding) ?? 'NOT_ASSESSED',
      semantic_verification_authenticated: hasAuthenticatedVerification(finding),
      source_anchor_count: finding.source_anchors?.length ?? 0,
      evidence_context_recorded: Boolean(finding.evidence_context),
      proof_tier: finding.proof_tier ?? 'NOT_ASSESSED',
      proof_jobs: proofJobs.slice(0, 20).map((job) => ({
        job_id: bounded(job.job_id),
        state: job.state,
        receipt_reference_recorded: typeof job.receipt_sha256 === 'string',
      })),
      omitted_proof_jobs: Math.max(0, proofJobs.length - 20),
      remediation: finding.remediation?.status === 'FIX_VERIFIED' && !hasAuthenticatedVerification(finding)
        ? 'CLAIMED_FIX_VERIFIED'
        : finding.remediation?.status ?? 'NOT_RECORDED',
      unmet_requirements: missing,
    }
  })
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/verdict-assessment',
    run_id: run.run_id,
    semantic_verifier: 'NOT_AVAILABLE',
    findings_total: selected.length,
    findings: records,
    omitted_findings: Math.max(0, selected.length - records.length),
    limitations: [
      'This is a read-only evidence assessment, not a new verification authority.',
      'Recorded anchors, receipt references, and completed jobs do not independently establish a security conclusion.',
      'Provider claims and comparison absence cannot establish a verified fix; historical findings remain unchanged.',
      'Raw evidence, commands, and provider narrative are omitted from this projection.',
    ],
  }
}

export function renderVerdictAssessment(assessment) {
  const lines = [
    `Run: ${assessment.run_id}`,
    `Semantic verifier: ${assessment.semantic_verifier}`,
    `Findings: ${assessment.findings_total} (${assessment.omitted_findings} omitted)`,
  ]
  for (const finding of assessment.findings) {
    lines.push(
      `${finding.candidate_id}: ${finding.verification}; ${finding.proof_tier}; retained=${finding.retained}`,
      `Triage: ${finding.triage}; Remediation: ${finding.remediation}`,
      `Unmet requirements: ${finding.unmet_requirements.join(', ') || 'none recorded'}`,
    )
  }
  return `${terminalSafeLines([...lines, ...assessment.limitations])}\n`
}
