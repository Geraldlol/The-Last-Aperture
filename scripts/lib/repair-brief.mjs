import { compareCanonicalStrings } from './canonical-order.mjs'
import {
  displayTriageDisposition,
  displayVerificationStatus,
  hasAuthenticatedTriage,
  hasAuthenticatedVerification,
  isSurvivingFinding,
  triageAuthorityOf,
  verificationAuthorityOf,
} from './findings.mjs'
import { findingFingerprint } from './lifecycle.mjs'

const FINDING_LIMIT = 100
const DETAIL_LIMIT = 32
const TEXT_LIMIT = 1024
const LIFECYCLE_STATES = new Set([
  'new', 'updated', 'unchanged', 'not-observed', 'claimed-fixed', 'fixed',
])
const SENSITIVE_FIELDS = [
  'title', 'evidence', 'attack', 'impact', 'reachable_from', 'proof_plan',
  'command', 'quotes', 'artifact', 'pre_result', 'reason', 'blocking_reason',
  'remediation.detail', 'post_result.detail', 'post_result.regressions',
  'evidence_context.target_identity', 'evidence_context.detection_evidence',
]

function scalar(value, fallback = 'NOT_RECORDED') {
  if (typeof value !== 'string' || value.length === 0) return fallback
  return value.slice(0, TEXT_LIMIT)
    .replace(/[\u0000-\u001f\u007f-\u009f]/gu, ' ')
    .replace(/[\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/gu, '\uFFFD')
    .replace(/\s+/gu, ' ')
    .trim() || fallback
}

function sample(items, limit = DETAIL_LIMIT) {
  return { total: items.length, items: items.slice(0, limit), omitted: Math.max(0, items.length - limit) }
}

function repositoryPath(value) {
  if (typeof value !== 'string' || value.length === 0 || value.length > TEXT_LIMIT) return null
  const path = value.replaceAll('\\', '/')
  if (
    path.startsWith('/')
    || /[:\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u.test(path)
    || path.split('/').some((part) => part === '' || part === '.' || part === '..')
  ) return null
  return path
}

function sourceCoordinate(value, inventory) {
  if (typeof value !== 'string' || value.length > TEXT_LIMIT + 40) return null
  const match = /^(.*?):([1-9][0-9]*)(?::([1-9][0-9]*))?$/.exec(value)
  if (!match) return null
  const path = repositoryPath(match[1])
  const line = Number(match[2])
  const column = match[3] === undefined ? undefined : Number(match[3])
  if (
    !path || !inventory.has(path) || !Number.isSafeInteger(line)
    || (column !== undefined && !Number.isSafeInteger(column))
  ) return null
  return { path, line, ...(column === undefined ? {} : { column }) }
}

function locationsOf(finding, inventory) {
  const byPath = new Map()
  const evidenceReferences = []
  let unresolved = 0
  for (const [index, location] of (finding.location ?? []).entries()) {
    // Evidence locators are identifiers inside a separately acquired artifact.
    // Even a suffix resembling file:line does not make them repository files.
    if (finding.evidence_context) {
      evidenceReferences.push({
        field: 'location',
        index,
        evidence_id: scalar(finding.evidence_context.evidence_id),
        locator: 'WITHHELD',
      })
      continue
    }
    const coordinate = sourceCoordinate(location, inventory)
    if (!coordinate) {
      unresolved += 1
      continue
    }
    const { path, ...position } = coordinate
    const coordinates = byPath.get(path) ?? new Map()
    coordinates.set(`${position.line}:${position.column ?? ''}`, position)
    byPath.set(path, coordinates)
  }
  const files = [...byPath].sort(([left], [right]) => compareCanonicalStrings(left, right))
    .map(([path, positions]) => {
      const coordinates = [...positions.values()].sort((left, right) => (
        left.line - right.line || (left.column ?? 0) - (right.column ?? 0)
      ))
      return {
        path,
        coordinates: coordinates.slice(0, DETAIL_LIMIT),
        omitted_coordinates: Math.max(0, coordinates.length - DETAIL_LIMIT),
      }
    })
  return {
    affected_source_files: sample(files),
    evidence_references: sample(evidenceReferences),
    unresolved_location_count: unresolved,
    source_anchor_count: finding.source_anchors?.length ?? 0,
  }
}

function recordedFields(finding) {
  return {
    title: typeof finding.title === 'string',
    impact: typeof finding.impact === 'string',
    evidence: typeof finding.evidence === 'string',
    remediation_detail: typeof finding.remediation?.detail === 'string',
    post_result: finding.post_result !== undefined,
    source_anchors: (finding.source_anchors?.length ?? 0) > 0,
  }
}

function claimsOf(finding) {
  const remediationStatus = scalar(finding.remediation?.status)
  return {
    verification: {
      claimed_status: scalar(finding.verification_status),
      display_status: scalar(displayVerificationStatus(finding)),
      authority: scalar(verificationAuthorityOf(finding)),
      authenticated: hasAuthenticatedVerification(finding),
      proof_tier: scalar(finding.proof_tier),
    },
    triage: {
      claimed_status: scalar(finding.triage_disposition),
      display_status: scalar(displayTriageDisposition(finding)),
      authority: scalar(triageAuthorityOf(finding)),
      authenticated: hasAuthenticatedTriage(finding),
    },
    remediation: {
      claimed_status: remediationStatus,
      display_status: remediationStatus === 'FIX_VERIFIED' ? 'CLAIMED_FIX_VERIFIED' : remediationStatus,
      authority: 'NO_INDEPENDENT_REMEDIATION_VERIFICATION',
      fix_verified: false,
    },
    post_result: {
      claimed_status: scalar(finding.post_result?.status),
      authority: 'RECORDED_ASSERTION_ONLY',
      establishes_fix: false,
    },
  }
}

function acceptanceChecklist() {
  return [
    {
      id: 'REVIEW_PREMISE', status: 'REQUIRES_REVIEW',
      criterion: 'Review the saved source references and record the intended security invariant and observed deviation.',
      evidence_required: ['reviewer_summary', 'reviewed_source_revision'],
    },
    {
      id: 'RECORD_REPAIR', status: 'NOT_RECORDED',
      criterion: 'Record the reviewed change, affected files, patch revision, and why the change enforces the intended invariant.',
      evidence_required: ['recommended_change', 'patch_revision', 'affected_files'],
    },
    {
      id: 'CHECK_EXPECTED_BEHAVIOR', status: 'NOT_ASSESSED',
      criterion: 'Document regression checks for intended valid behavior using synthetic data and record their results.',
      evidence_required: ['test_reference', 'test_result', 'tested_revision'],
    },
    {
      id: 'CHECK_SECURITY_INVARIANT', status: 'NOT_ASSESSED',
      criterion: 'Document whether the reviewed security invariant holds after the change, with explicit pass and fail criteria.',
      evidence_required: ['acceptance_criteria', 'reviewed_result', 'result_authority'],
    },
    {
      id: 'LINK_RETEST', status: 'REQUIRES_REVIEW',
      criterion: 'Link the subsequent run and candidate fingerprint, compare applicable scope and coverage, and retain any unresolved gaps.',
      evidence_required: ['retest_run_id', 'candidate_fingerprint', 'coverage_comparison'],
    },
    {
      id: 'REVIEW_FIX_EVIDENCE', status: 'NOT_ASSESSED',
      criterion: 'Review patch and test evidence independently; a missing finding or a recorded passing test alone does not verify a fix.',
      evidence_required: ['independent_review', 'patch_and_test_evidence'],
    },
  ]
}

function lifecycleLinks(comparison, finding, sourceRunId) {
  if (!comparison) return sample([])
  const fingerprint = findingFingerprint(finding)
  const links = comparison.results.filter((entry) => {
    if (entry.fingerprint !== fingerprint) return false
    const sameCurrent = sourceRunId === comparison.current_run_id
      && entry.finding?.candidate_id === finding.candidate_id
    const sameBaseline = sourceRunId === comparison.baseline_run_id
      && entry.baseline_finding?.candidate_id === finding.candidate_id
    return sameCurrent || sameBaseline
  }).map((entry) => ({
    baseline_run_id: scalar(comparison.baseline_run_id),
    current_run_id: scalar(comparison.current_run_id),
    baseline_candidate_id: entry.baseline_finding ? scalar(entry.baseline_finding.candidate_id) : null,
    current_candidate_id: entry.finding ? scalar(entry.finding.candidate_id) : null,
    fingerprint: scalar(entry.fingerprint),
    state: LIFECYCLE_STATES.has(entry.state) ? entry.state : 'UNKNOWN',
    resolution_authority: scalar(entry.resolution_authority),
    semantic_resolution_authority: scalar(entry.semantic_resolution_authority, 'NO_RESOLUTION_CLAIM'),
    fix_verified: false,
  }))
  return sample(links)
}

function comparisonSummary(comparison) {
  if (!comparison) return { status: 'NOT_PROVIDED' }
  return {
    status: 'LINKED',
    baseline_run_id: scalar(comparison.baseline_run_id),
    current_run_id: scalar(comparison.current_run_id),
    comparable: comparison.comparable === true,
    partially_comparable: comparison.partially_comparable === true,
    fix_verified: false,
  }
}

/**
 * Inert handoff from a validated saved run and optional compareRuns output.
 * The caller owns bundle validation. This projection performs no reads, writes,
 * execution, patch generation, semantic verification, or claim promotion.
 * Free-text narratives are deliberately referenced rather than re-exported:
 * schema validation does not establish that they are free of PHI or payloads.
 */
export function buildRepairBrief(run, { candidateId, comparison } = {}) {
  if (!run || typeof run.run_id !== 'string' || !Array.isArray(run.findings)) {
    throw new TypeError('repair brief requires a validated saved run')
  }
  if (candidateId !== undefined && (typeof candidateId !== 'string' || candidateId.length === 0)) {
    throw new TypeError('candidateId must be a nonempty string')
  }
  if (comparison && (
    !Array.isArray(comparison.results)
    || ![comparison.baseline_run_id, comparison.current_run_id].includes(run.run_id)
  )) throw new TypeError('comparison does not include the requested run')

  const inventory = new Set((run.coverage?.inventory ?? []).map(repositoryPath).filter(Boolean))
  const records = run.findings.map((finding) => ({ finding, sourceRunId: run.run_id, present: true }))
  if (comparison?.current_run_id === run.run_id) {
    const known = new Set(records.map(({ finding, sourceRunId }) => (
      `${sourceRunId}\0${finding.candidate_id}\0${findingFingerprint(finding)}`
    )))
    for (const entry of comparison.results) {
      if (entry.finding || !entry.baseline_finding) continue
      const finding = entry.baseline_finding
      const sourceRunId = comparison.baseline_run_id
      const key = `${sourceRunId}\0${finding.candidate_id}\0${findingFingerprint(finding)}`
      if (known.has(key)) continue
      known.add(key)
      records.push({ finding, sourceRunId, present: false })
    }
  }
  const selected = records.filter(({ finding }) => candidateId === undefined || finding.candidate_id === candidateId)
    .sort((left, right) => (
      compareCanonicalStrings(left.finding.candidate_id, right.finding.candidate_id)
      || compareCanonicalStrings(left.sourceRunId, right.sourceRunId)
      || compareCanonicalStrings(findingFingerprint(left.finding), findingFingerprint(right.finding))
    ))
  if (candidateId !== undefined && selected.length === 0) throw new Error('candidate was not found in the run or comparison history')
  const sampledRecords = sample(selected, FINDING_LIMIT)
  return {
    schema_version: '1.0.0',
    kind: 'REPAIR_RETEST_HANDOFF',
    run_id: scalar(run.run_id),
    run_state: scalar(run.state),
    selected_candidate_id: candidateId === undefined ? null : scalar(candidateId),
    comparison: comparisonSummary(comparison),
    findings: {
      total: sampledRecords.total,
      items: sampledRecords.items.map(({ finding, sourceRunId, present }) => ({
        candidate_id: scalar(finding.candidate_id),
        fingerprint: scalar(findingFingerprint(finding)),
        source_run_id: scalar(sourceRunId),
        present_in_requested_run: present,
        lens: scalar(finding.lens),
        topic: scalar(finding.topic),
        retained_by_current_policy: isSurvivingFinding(finding),
        ...locationsOf(finding, inventory),
        observed_impact: {
          status: typeof finding.impact === 'string' ? 'RECORDED_CLAIM' : 'NOT_RECORDED',
          claimed_severity: scalar(finding.claimed_impact_severity),
          confidence: scalar(finding.confidence),
          narrative: 'WITHHELD_SENSITIVE_FREE_TEXT',
          source_field: 'impact',
        },
        recommended_change: {
          status: 'UNKNOWN',
          detail: 'No structured repair recommendation is recorded in this finding; maintainer review is required.',
        },
        claims: claimsOf(finding),
        recorded_fields: recordedFields(finding),
        acceptance_checklist: acceptanceChecklist(),
        lifecycle_links: lifecycleLinks(comparison, finding, sourceRunId),
        saved_record_reference: { run_id: scalar(sourceRunId), candidate_id: scalar(finding.candidate_id) },
      })),
      omitted: sampledRecords.omitted,
      present_candidates: selected.filter(({ present }) => present).length,
      absent_baseline_candidates: selected.filter(({ present }) => !present).length,
    },
    data_policy: {
      free_text: 'WITHHELD_BY_DEFAULT',
      withheld_fields: [...SENSITIVE_FIELDS],
      evidence_locator_values: 'WITHHELD_BY_DEFAULT',
      metadata_notice: 'Repository paths and candidate identifiers remain metadata; review before sharing.',
    },
    nonclaims: [
      'This handoff does not implement a fix, execute a test, or independently verify a finding or remediation claim.',
      'Checklist entries are review requirements, not recorded passing results.',
      'Missing findings and negative provider assertions do not establish a verified fix or target clearance.',
      'Full findings and evidence remain in their saved runs; this projection does not mutate or discard their history.',
    ],
  }
}

function markdown(value) {
  return scalar(value)
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replace(/[\\`*_{}[\]()#+.!|~-]/g, '\\$&')
}

export function renderRepairBriefMarkdown(brief) {
  const lines = [
    '# Repair and retest handoff',
    '',
    `Run: ${markdown(brief.run_id)} (${markdown(brief.run_state)})`,
    `Candidates: ${brief.findings.total}; displayed: ${brief.findings.items.length}; omitted: ${brief.findings.omitted}.`,
    '',
    'Finding narratives and evidence payloads are withheld. Use the saved run and candidate references for controlled review.',
    '',
  ]
  for (const item of brief.findings.items) {
    lines.push(
      `## ${markdown(item.candidate_id)}`,
      '',
      `Source run: ${markdown(item.source_run_id)}; fingerprint: ${markdown(item.fingerprint)}.`,
      `Topic: ${markdown(item.lens)} / ${markdown(item.topic)}.`,
      `Claimed impact: ${markdown(item.observed_impact.claimed_severity)}; confidence: ${markdown(item.observed_impact.confidence)}.`,
      `Verification: ${markdown(item.claims.verification.display_status)}; authority: ${markdown(item.claims.verification.authority)}.`,
      `Triage: ${markdown(item.claims.triage.display_status)}; authority: ${markdown(item.claims.triage.authority)}.`,
      `Remediation: ${markdown(item.claims.remediation.display_status)}; authority: ${markdown(item.claims.remediation.authority)}.`,
      `Recommended change: ${markdown(item.recommended_change.status)}. ${markdown(item.recommended_change.detail)}`,
      '',
      'Affected source files (recorded coordinates within the requested run inventory):',
      '',
    )
    for (const file of item.affected_source_files.items) {
      const coordinates = file.coordinates.map(({ line, column }) => `${line}${column === undefined ? '' : `:${column}`}`).join(', ')
      lines.push(`- ${markdown(file.path)}: ${markdown(coordinates)}${file.omitted_coordinates ? `; ${file.omitted_coordinates} additional coordinates omitted` : ''}`)
    }
    if (item.affected_source_files.total === 0) lines.push('UNKNOWN: no repository-inventory source file reference is available.')
    lines.push(
      '',
      `Evidence locator references: ${item.evidence_references.total} (values withheld); unresolved locations: ${item.unresolved_location_count}; additional source files omitted: ${item.affected_source_files.omitted}.`,
      '',
      'Acceptance and retest requirements:',
      '',
    )
    for (const check of item.acceptance_checklist) lines.push(`- [ ] ${markdown(check.criterion)} (${markdown(check.status)})`)
    if (item.lifecycle_links.total > 0) {
      lines.push('', 'Linked comparison records:', '')
      for (const link of item.lifecycle_links.items) {
        lines.push(`- ${markdown(link.baseline_run_id)} / ${markdown(link.baseline_candidate_id)} to ${markdown(link.current_run_id)} / ${markdown(link.current_candidate_id)}: ${markdown(link.state)}; semantic authority: ${markdown(link.semantic_resolution_authority)}; fix verified: no.`)
      }
    }
    lines.push('')
  }
  lines.push(...brief.nonclaims.map((text) => markdown(text)), '', markdown(brief.data_policy.metadata_notice), '')
  return lines.join('\n')
}
