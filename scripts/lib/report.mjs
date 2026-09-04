import { findingFingerprint } from './lifecycle.mjs'
import {
  displayTriageDisposition,
  displayVerificationStatus,
  hasAuthenticatedTriage,
  hasAuthenticatedVerification,
  isSurvivingFinding,
  triageAuthorityOf,
  verificationAuthorityOf,
} from './findings.mjs'
import { evidenceConflicts } from './contracts.mjs'
import {
  filterResolvedCoverageGaps,
  projectCoverageGaps,
} from './coverage-gaps.mjs'

const SEVERITY_RANK = new Map([
  ['Critical', 0],
  ['High', 1],
  ['Medium', 2],
  ['Low', 3],
  ['Info', 4],
])

const HIGH_IMPACT_SEVERITIES = new Set(['Critical', 'High'])
const COVERAGE_SAMPLE_LIMIT = 20
const COVERAGE_REASON_SAMPLE_LIMIT = 3
const COVERAGE_SAMPLE_TEXT_LIMIT = 240
const COVERAGE_CLOSURE_HISTORY_SAMPLE_LIMIT = 20
const COVERAGE_CLASS_ORDER = new Map([
  ['CANONICAL_SOURCE', 0],
  ['GENERATED_CODE', 1],
  ['TEST', 2],
  ['DOCUMENTATION', 3],
  ['BINARY', 4],
])
const MARKDOWN_PUNCTUATION = new Set([
  '\\',
  '`',
  '*',
  '{',
  '}',
  '[',
  ']',
  '(',
  ')',
  '#',
  '!',
  '|',
  '~',
])

// Severity and confidence are separate axes. `severityOf` is the confidence-
// gated priority — what to act on first. `claimedSeverityOf` is how bad the
// finding is if it is real. Reporting only the former tells a reader a claimed
// Critical is moderate, when what is actually true is that it is unproven.
function severityOf(finding) {
  return hasAuthenticatedTriage(finding)
    ? finding.effective_severity ?? finding.claimed_impact_severity ?? 'Info'
    : finding.claimed_impact_severity ?? finding.effective_severity ?? 'Info'
}

function claimedSeverityOf(finding) {
  return finding.claimed_impact_severity ?? finding.effective_severity ?? 'Info'
}

function sortedFindings(findings) {
  return [...findings].sort((left, right) =>
    (SEVERITY_RANK.get(claimedSeverityOf(left)) ?? 99) -
      (SEVERITY_RANK.get(claimedSeverityOf(right)) ?? 99) ||
    (SEVERITY_RANK.get(severityOf(left)) ?? 99) -
      (SEVERITY_RANK.get(severityOf(right)) ?? 99) ||
    left.candidate_id.localeCompare(right.candidate_id, 'en'))
}

function singleLine(value, fallback = '—') {
  const normalized = String(value ?? '')
    .replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ')
    .replace(/[\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/gu, '�')
    .replace(/\s+/gu, ' ')
    .trim()
  return normalized || fallback
}

function markdownText(value, fallback = '—') {
  const htmlSafe = singleLine(value, fallback)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
  const characters = [...htmlSafe]
  const escaped = characters
    .map((character, index) => {
      if (character === '_') {
        const previousIsWord = /[\p{L}\p{N}]/u.test(characters[index - 1] ?? '')
        const nextIsWord = /[\p{L}\p{N}]/u.test(characters[index + 1] ?? '')
        return previousIsWord && nextIsWord ? character : '\\_'
      }
      return MARKDOWN_PUNCTUATION.has(character) ? `\\${character}` : character
    })
    .join('')
  return escaped
    .replace(/^([+-])/, '\\$1')
    .replace(/^([0-9]+)([.)])(?=\s)/, '$1\\$2')
}

// A longer delimiter stops provider text closing the span early, but it is not
// sufficient on its own: CommonMark merges the delimiter with a backtick at the
// very start or end of the content, so `` `x `` emits ```` ```x`` ```` and the
// span never closes — leaving the rest of the line to render as live markup.
// The specified remedy is one space of padding, which the renderer strips.
//
// Angle brackets are deliberately not escaped. Code-span content is escaped by
// the renderer, and pre-escaping would print `&lt;img&gt;` to a reader looking
// at quoted evidence. codeBlock takes the same position for the same reason.
function inlineCode(value, fallback = '—') {
  const text = singleLine(value, fallback)
  const longestRun = Math.max(
    0,
    ...(text.match(/`+/g) ?? []).map((run) => run.length),
  )
  const delimiter = '`'.repeat(longestRun + 1)
  const padding = text.startsWith('`') || text.endsWith('`') ? ' ' : ''
  return `${delimiter}${padding}${text}${padding}${delimiter}`
}

function tableCell(value) {
  return markdownText(value)
}

function codeBlock(value) {
  return String(value ?? '')
    .replace(/\r\n?/g, '\n')
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/gu, '�')
    .split(/\r?\n/)
    .map((line) => `    ${line}`)
    .join('\n')
}

function proofStatusDetail(finding) {
  if (finding.triage_disposition === 'dropped') {
    return `${hasAuthenticatedTriage(finding) ? 'DROPPED' : 'CLAIMED DROPPED'} before proof: ${finding.drop_reason ?? 'reason not recorded'}`
  }
  if (finding.triage_disposition === 'merged') {
    return `${hasAuthenticatedTriage(finding) ? 'MERGED' : 'CLAIMED MERGED'} into ${finding.merged_into_candidate_id ?? 'candidate not recorded'}`
  }
  const authenticated = hasAuthenticatedVerification(finding)
  if (finding.verification_status === 'CONFIRMED') {
    return authenticated
      ? 'CONFIRMED'
      : 'CLAIMED CONFIRMED; semantic proof authority is not authenticated'
  }
  if (finding.verification_status === 'DISPROVED') {
    const basis = finding.disproof_basis
      ? ` (${finding.disproof_basis})`
      : ''
    return `${authenticated ? 'DISPROVED' : 'CLAIMED DISPROVED'}${basis}: ${finding.reason ?? 'reason not recorded'}`
  }
  if (finding.verification_status === 'NOT_REPRODUCED') {
    return `${authenticated ? 'NOT REPRODUCED' : 'CLAIMED NOT REPRODUCED'}: ${finding.reason ?? 'reason not recorded'}`
  }
  if (finding.verification_status === 'INCONCLUSIVE') {
    return `INCONCLUSIVE: ${finding.reason ?? 'reason not recorded'}`
  }
  if (finding.verification_status === 'UNPROVEN') {
    return `UNPROVEN; blocked: ${finding.blocking_reason ?? 'blocking reason not recorded'}`
  }
  return 'NOT ASSESSED'
}

function remediationDetail(finding) {
  if (
    finding.remediation
    && typeof finding.remediation.status === 'string'
    && typeof finding.remediation.detail === 'string'
  ) {
    return finding.remediation.status === 'FIX_VERIFIED'
      && !hasAuthenticatedVerification(finding)
      ? {
          status: 'CLAIMED_FIX_VERIFIED',
          detail: `${finding.remediation.detail}; semantic verification authority is not authenticated`,
        }
      : finding.remediation
  }
  if (finding.post_result?.status === 'passed') {
    return {
      status: hasAuthenticatedVerification(finding)
        ? 'FIX_VERIFIED'
        : 'CLAIMED_FIX_VERIFIED',
      detail: `legacy post-result passed; regressions: ${finding.post_result.regressions}; semantic verification authority ${hasAuthenticatedVerification(finding) ? 'authenticated' : 'not authenticated'}`,
    }
  }
  if (finding.post_result?.status === 'failed') {
    return {
      status: 'FIX_FAILED',
      detail: `legacy post-result failed; regressions: ${finding.post_result.regressions}`,
    }
  }
  return null
}

function isUnverifiedHighImpactClaim(finding) {
  return HIGH_IMPACT_SEVERITIES.has(finding.claimed_impact_severity)
    && !(
      finding.verification_status === 'CONFIRMED'
      && hasAuthenticatedVerification(finding)
    )
}

// Counted by claimed impact, so the summary states the risk profile. The
// confidence-gated view is served by the unverified-high-impact table below and
// by SARIF rank; collapsing both into one row reported three Criticals as zero.
function countBySeverity(findings) {
  return Object.fromEntries(
    [...SEVERITY_RANK.keys()].map((severity) => [
      severity,
      findings.filter((finding) => claimedSeverityOf(finding) === severity).length,
    ]),
  )
}

// "Critical (unproven)" is the whole point: how bad it is if real, and how well
// established that is, in the one line a reader scans.
//
// The qualifier is emitted unescaped, so it is resolved through a fixed map
// rather than derived from the record. A provider-supplied status that is not
// one of these is dropped instead of rendered.
const CONFIDENCE_LABEL = new Map([
  ['CONFIRMED', 'confirmed'],
  ['CLAIMED_CONFIRMED', 'claimed confirmed'],
  ['NOT_REPRODUCED', 'not reproduced'],
  ['CLAIMED_NOT_REPRODUCED', 'claimed not reproduced'],
  ['INCONCLUSIVE', 'inconclusive'],
  ['DISPROVED', 'disproved'],
  ['CLAIMED_DISPROVED', 'claimed disproved'],
  ['UNPROVEN', 'unproven'],
])

function headingSeverity(finding) {
  const claimed = markdownText(claimedSeverityOf(finding))
  const label = CONFIDENCE_LABEL.get(displayVerificationStatus(finding))
  return label === undefined ? claimed : `${claimed} (${label})`
}

function boundedCoverageText(value) {
  const normalized = singleLine(value)
  if (normalized.length <= COVERAGE_SAMPLE_TEXT_LIMIT) return normalized
  return `${normalized.slice(0, COVERAGE_SAMPLE_TEXT_LIMIT - 1)}…`
}

function sortedSet(values) {
  return [...new Set(values)].sort((left, right) =>
    left.localeCompare(right, 'en'))
}

function boundedReasonSamples(values) {
  const reasons = sortedSet(values)
  return {
    reasons: reasons
      .slice(0, COVERAGE_REASON_SAMPLE_LIMIT)
      .map(boundedCoverageText),
    omitted_reason_count: Math.max(
      0,
      reasons.length - COVERAGE_REASON_SAMPLE_LIMIT,
    ),
  }
}

function sampledReasonsLabel(entry, fallback = 'none') {
  const selected = entry.reasons.join('; ') || fallback
  return entry.omitted_reason_count > 0
    ? `${selected}; ${entry.omitted_reason_count} additional reason` +
      `${entry.omitted_reason_count === 1 ? '' : 's'} omitted`
    : selected
}

function coverageClassRank(value) {
  const normalized = String(value)
    .toUpperCase()
    .replaceAll('-', '_')
  return COVERAGE_CLASS_ORDER.get(normalized) ?? Number.MAX_SAFE_INTEGER
}

function denominatorProjection(row) {
  const category = row.category ?? row.class ?? 'unknown'
  const filesTotal = row.files_total ?? (row.files ?? row.paths ?? []).length
  const filesExamined = row.files_examined ?? 0
  const filesUnexamined = row.files_unexamined ?? Math.max(
    0,
    filesTotal - filesExamined,
  )
  const bytesTotal = row.bytes_total ?? 0
  const bytesExamined = row.bytes_examined ?? Math.max(
    0,
    bytesTotal - (row.bytes_unexamined ?? bytesTotal),
  )
  const bytesUnexamined = row.bytes_unexamined ?? Math.max(
    0,
    bytesTotal - bytesExamined,
  )
  return {
    category,
    files_total: filesTotal,
    files_examined: filesExamined,
    files_unexamined: filesUnexamined,
    bytes_total: bytesTotal,
    bytes_examined: bytesExamined,
    bytes_unexamined: bytesUnexamined,
  }
}

function closureMeasurementProjection(measurement) {
  return {
    round: measurement.round,
    status: measurement.status,
    applicable_lens_file_pairs:
      measurement.applicable_lens_file_pairs ?? null,
    examined_lens_file_pairs:
      measurement.examined_lens_file_pairs ?? null,
    uncovered_lens_file_pairs:
      measurement.uncovered_lens_file_pairs ?? null,
    uncovered_shard_count: Array.isArray(measurement.uncovered_shards)
      ? measurement.uncovered_shards.length
      : null,
  }
}

function closureProjection(closure) {
  if (closure === null || typeof closure !== 'object' || Array.isArray(closure)) {
    return null
  }
  const history = Array.isArray(closure.history) ? closure.history : []
  const historySamples = history
    .slice(-COVERAGE_CLOSURE_HISTORY_SAMPLE_LIMIT)
    .map(closureMeasurementProjection)
  return {
    required_source_closure: closure.required_source_closure === true,
    max_rounds: closure.max_rounds,
    round: closure.round,
    status: closure.status ?? 'UNKNOWN',
    applicable_lens_file_pairs:
      closure.applicable_lens_file_pairs ?? null,
    examined_lens_file_pairs:
      closure.examined_lens_file_pairs ?? null,
    uncovered_lens_file_pairs:
      closure.uncovered_lens_file_pairs ?? null,
    uncovered_shard_count: Array.isArray(closure.uncovered_shards)
      ? closure.uncovered_shards.length
      : null,
    history_count: history.length,
    history_samples: historySamples,
    omitted_history_count: Math.max(0, history.length - historySamples.length),
  }
}

function coverageMetric(value) {
  return Number.isSafeInteger(value) ? value : 'not measured'
}

function coverageProjection(coverage = {}) {
  const gaps = Array.isArray(coverage.gaps) ? coverage.gaps : []
  const resolvedGapIds = Array.isArray(coverage.resolved_gap_ids)
    ? coverage.resolved_gap_ids
    : []
  const gapProjection = projectCoverageGaps(gaps, {
    resolvedGapIds,
    maxExamples: COVERAGE_SAMPLE_LIMIT,
  })
  const openGaps = filterResolvedCoverageGaps(gaps, resolvedGapIds)
  const inventory = new Set(coverage.inventory ?? [])
  const openFiles = new Map()
  const lensFilePairs = new Map()
  const knownLenses = sortedSet(
    (coverage.lenses ?? [])
      .map(({ lens }) => lens)
      .filter((lens) => typeof lens === 'string'),
  ).sort((left, right) => right.length - left.length)

  const ensureOpenFile = (path) => {
    if (!openFiles.has(path)) {
      openFiles.set(path, {
        path,
        lenses: new Set(),
        reasons: new Set(),
      })
    }
    return openFiles.get(path)
  }

  for (const entry of coverage.unexamined ?? []) {
    if (typeof entry?.path !== 'string') continue
    const file = ensureOpenFile(entry.path)
    if (typeof entry.reason === 'string') file.reasons.add(entry.reason)
  }

  const lensRows = (coverage.lenses ?? []).map((row) => {
    const examined = new Set(row.examined_paths ?? [])
    const applicableKnown = Array.isArray(row.applicable_paths)
    const applicable = new Set(applicableKnown ? row.applicable_paths : [])
    const open = applicableKnown
      ? [...applicable].filter((path) => !examined.has(path))
      : []
    for (const path of open) {
      const key = `${row.lens}\0${path}`
      lensFilePairs.set(key, { lens: row.lens, path })
      ensureOpenFile(path).lenses.add(row.lens)
    }
    return {
      ...row,
      applicable_count: applicableKnown ? applicable.size : null,
      examined_count: applicableKnown
        ? [...applicable].filter((path) => examined.has(path)).length
        : examined.size,
      open_count: applicableKnown ? open.length : null,
    }
  })

  const nonFileGroups = new Map()
  for (const gap of openGaps) {
    let lensFile = null
    if (
      gap?.kind === 'LENS_FILE'
      && typeof gap.lens === 'string'
      && typeof gap.path === 'string'
    ) {
      lensFile = { lens: gap.lens, path: gap.path }
    } else if (typeof gap?.area === 'string') {
      for (const lens of knownLenses) {
        const prefix = `lens:${lens}:`
        if (!gap.area.startsWith(prefix)) continue
        const path = gap.area.slice(prefix.length)
        if (inventory.has(path)) {
          lensFile = { lens, path }
        }
        break
      }
    }
    if (lensFile) {
      const key = `${lensFile.lens}\0${lensFile.path}`
      lensFilePairs.set(key, lensFile)
      const file = ensureOpenFile(lensFile.path)
      file.lenses.add(lensFile.lens)
      if (typeof gap.reason === 'string') file.reasons.add(gap.reason)
      continue
    }

    if (typeof gap?.area !== 'string') continue
    let group = nonFileGroups.get(gap.area)
    if (!group) {
      group = {
        area: gap.area,
        reasons: new Set(),
        records: 0,
      }
      nonFileGroups.set(gap.area, group)
    }
    group.records += 1
    if (typeof gap.reason === 'string') group.reasons.add(gap.reason)
    if (inventory.has(gap.area)) {
      const file = ensureOpenFile(gap.area)
      if (typeof gap.reason === 'string') file.reasons.add(gap.reason)
    }
  }

  const openFileSamples = [...openFiles.values()]
    .sort((left, right) => left.path.localeCompare(right.path, 'en'))
    .slice(0, COVERAGE_SAMPLE_LIMIT)
    .map((entry) => ({
      path: boundedCoverageText(entry.path),
      lenses: sortedSet(entry.lenses),
      ...boundedReasonSamples(entry.reasons),
    }))
  const nonFileGapSamples = [...nonFileGroups.values()]
    .sort((left, right) => left.area.localeCompare(right.area, 'en'))
    .slice(0, COVERAGE_SAMPLE_LIMIT)
    .map((entry) => ({
      area: boundedCoverageText(entry.area),
      records: entry.records,
      ...boundedReasonSamples(entry.reasons),
    }))

  const denominators = (coverage.denominators ?? [])
    .map(denominatorProjection)
    .sort((left, right) =>
      coverageClassRank(left.category) - coverageClassRank(right.category)
      || String(left.category).localeCompare(String(right.category), 'en'))

  return {
    denominators,
    closure: closureProjection(coverage.closure),
    gapProjection,
    lensRows,
    unique_open_files: openFiles.size,
    open_lens_file_obligations: lensFilePairs.size,
    conceptual_unique_open_gaps: gapProjection.unique_open_gap_count,
    exact_open_gap_identities: gapProjection.exact_open_gap_count,
    exact_open_lens_file_gaps:
      gapProjection.exact_open_lens_file_gap_count,
    unique_non_file_gap_groups: nonFileGroups.size,
    raw_open_gap_records: gapProjection.open_input_gap_count,
    resolved_gap_records: gapProjection.resolved_input_gap_count,
    openFileSamples,
    omittedOpenFileSamples: Math.max(
      0,
      openFiles.size - openFileSamples.length,
    ),
    nonFileGapSamples,
    omittedNonFileGapSamples: Math.max(
      0,
      nonFileGroups.size - nonFileGapSamples.length,
    ),
  }
}

export function renderMarkdownReport(run) {
  const allFindings = run.findings ?? []
  const survivors = sortedFindings(allFindings.filter(isSurvivingFinding))
  const removed = sortedFindings(allFindings.filter(
    (finding) => !isSurvivingFinding(finding),
  ))
  const unverifiedHighImpact = sortedFindings(
    allFindings.filter(isUnverifiedHighImpactClaim),
  )
  const counts = countBySeverity(survivors)
  const coverage = run.coverage ?? {
    inventory: [],
    examined: [],
    unexamined: [],
    lenses: [],
    gaps: [],
  }
  const coverageSummary = coverageProjection(coverage)
  const producedJobs = (run.jobs ?? []).filter((job) => job.producer)
  const authorityCounts = {
    PROVIDER_DECLARED: producedJobs.filter(
      ({ coverage_authority: authority }) => authority === 'PROVIDER_DECLARED',
    ).length,
    CONTROLLER_OBSERVED_CONSUMPTION: producedJobs.filter(
      ({ coverage_authority: authority }) =>
        authority === 'CONTROLLER_OBSERVED_CONSUMPTION',
    ).length,
    REMOTE_REQUEST_ACCEPTED: producedJobs.filter(
      ({ coverage_authority: authority }) =>
        authority === 'REMOTE_REQUEST_ACCEPTED',
    ).length,
  }
  const lensAuthority = new Map()
  for (const job of producedJobs.filter(
    ({ kind, lens }) => kind === 'LENS' && lens,
  )) {
    if (!lensAuthority.has(job.lens)) lensAuthority.set(job.lens, new Set())
    lensAuthority.get(job.lens).add(
      job.coverage_authority ?? 'PROVIDER_DECLARED',
    )
  }
  const lensAuthorityLabel = (lens) => {
    const authorities = lensAuthority.get(lens)
    return authorities
      ? sortedSet(authorities).join(' + ')
      : 'NOT ASSESSED'
  }
  const lines = [
    '# Red Team Audit Report',
    '',
    `Run: ${inlineCode(run.run_id)}`,
    '',
    `Status: **${markdownText(run.state)}**`,
    '',
  ]

  if (!['COMPLETED', 'COMPLETE_WITH_GAPS'].includes(run.state)) {
    lines.push(
      '> This is not a clean audit result. The run did not complete every required stage.',
      '',
    )
  } else if (run.state === 'COMPLETE_WITH_GAPS') {
    lines.push(
      '> The audit completed with declared coverage gaps. Silence outside the measured surface is not a clearance.',
      '',
    )
  }
  if (['COMPLETED', 'COMPLETE_WITH_GAPS'].includes(run.state)) {
    lines.push(
      '> Coverage authority is recorded per job. CONTROLLER_OBSERVED_CONSUMPTION proves the local adapter completed a challenge over exact sealed bytes. REMOTE_REQUEST_ACCEPTED proves the pinned gateway accepted one exact signed request. Neither proves comprehension or correct analysis. PROVIDER_DECLARED remains an unauthenticated provider claim. None is an independent security clearance.',
      '',
    )
  }

  lines.push(
    '## Executive summary',
    '',
    '| Critical | High | Medium | Low | Info |',
    '|---:|---:|---:|---:|---:|',
    `| ${counts.Critical} | ${counts.High} | ${counts.Medium} | ${counts.Low} | ${counts.Info} |`,
    '',
    `Capability mode: ${inlineCode(run.capability_mode)}`,
    '',
    `Repository tree: ${inlineCode(run.repository?.tree_digest ?? 'unknown')}`,
    '',
    '### Unverified high-impact claims',
    '',
  )

  if (unverifiedHighImpact.length === 0) {
    lines.push(
      'No unverified Critical or High impact claims were recorded.',
      '',
    )
  } else {
    lines.push(
      'These are provider claims whose claimed impact is Critical or High but whose semantic proof is not authenticated by a controller-owned oracle receipt. They do not imply confirmed or effective severity.',
      '',
      '| Candidate | Claimed | Provider effective | Disposition | Verification | Proof tier | Status detail |',
      '|---|---|---|---|---|---|---|',
    )
    for (const finding of unverifiedHighImpact) {
      lines.push(
        `| ${tableCell(finding.candidate_id)} | ${tableCell(finding.claimed_impact_severity)} | ` +
        `${tableCell(finding.effective_severity ?? 'not assigned')} | ` +
        `${tableCell(displayTriageDisposition(finding) ?? 'not triaged')} | ` +
        `${tableCell(displayVerificationStatus(finding) ?? 'NOT ASSESSED')} | ` +
        `${tableCell(finding.proof_tier ?? 'NOT ASSESSED')} | ` +
        `${tableCell(proofStatusDetail(finding))} |`,
      )
    }
    lines.push('')
  }

  lines.push(
    '## Findings',
    '',
  )

  if (survivors.length === 0) {
    lines.push(
      `NO_FINDINGS_REPORTED: No surviving findings were recorded. ` +
      `This does not override run status, coverage gaps, or coverage authority, ` +
      `and it does not mean the repository is clean or safe.`,
      '',
    )
  }

  for (const finding of survivors) {
    const remediation = remediationDetail(finding)
    lines.push(
      `### ${headingSeverity(finding)} — ${markdownText(finding.title)}`,
      '',
      `Candidate: ${inlineCode(finding.candidate_id)}  `,
      `Lens/topic: ${inlineCode(finding.lens)} / ${inlineCode(finding.topic)}  `,
      `Location: ${(finding.location ?? []).map((location) => inlineCode(location)).join(', ')}  `,
      `Reachability: ${inlineCode(finding.reachable_from)}  `,
      `Claimed severity: ${inlineCode(finding.claimed_impact_severity)}  `,
      `Report priority (authenticated gates only): ${inlineCode(severityOf(finding))}  `,
      `Provider-claimed effective severity: ${inlineCode(finding.effective_severity ?? 'not assigned')}  `,
      `Triage disposition: ${inlineCode(displayTriageDisposition(finding) ?? 'not triaged')}  `,
      `Triage authority: ${inlineCode(triageAuthorityOf(finding))}  `,
      `Existence: ${inlineCode(finding.existence_check?.status ?? 'NOT ASSESSED')}  `,
      `Proof tier: ${inlineCode(finding.proof_tier ?? 'NOT ASSESSED')}  `,
      `Verification: ${inlineCode(displayVerificationStatus(finding) ?? 'NOT ASSESSED')}  `,
      `Verification authority: ${inlineCode(verificationAuthorityOf(finding))}  `,
      `Proof status: ${markdownText(proofStatusDetail(finding))}`,
      ...(remediation
        ? [`Remediation: ${inlineCode(remediation.status)} — ${markdownText(remediation.detail)}`]
        : []),
      '',
      markdownText(finding.impact),
      '',
      '**Evidence**',
      '',
      codeBlock(finding.evidence),
      '',
      '**Attack or failure path**',
      '',
      markdownText(finding.attack),
      '',
      '**Proof plan**',
      '',
      markdownText(finding.proof_plan),
      '',
    )
  }

  lines.push(
    '## Coverage',
    '',
    `Inventory: ${coverage.inventory.length} unique files  `,
    `Examined: ${coverage.examined.length} unique files  `,
    `Unique open files: ${coverageSummary.unique_open_files}  `,
    `Open lens/file obligations: ${coverageSummary.open_lens_file_obligations}  `,
    `Conceptual unique open gaps: ${coverageSummary.conceptual_unique_open_gaps}  `,
    `Exact open lens/file gaps: ${coverageSummary.exact_open_lens_file_gaps}  `,
    `Unique non-file gap groups: ${coverageSummary.unique_non_file_gap_groups}  `,
    `Raw open gap records: ${coverageSummary.raw_open_gap_records}  `,
    `Resolved historical gap records: ${coverageSummary.resolved_gap_records}  `,
    `Provider-declared jobs: ${authorityCounts.PROVIDER_DECLARED}  `,
    `Controller-observed consumption jobs: ${authorityCounts.CONTROLLER_OBSERVED_CONSUMPTION}  `,
    `Remote request accepted jobs: ${authorityCounts.REMOTE_REQUEST_ACCEPTED}`,
    '',
  )

  if (coverageSummary.denominators.length > 0) {
    lines.push(
      '### Inventory denominators',
      '',
      '| Class | Files total | Files examined | Files open | Bytes total | Bytes examined | Bytes open |',
      '|---|---:|---:|---:|---:|---:|---:|',
    )
    for (const row of coverageSummary.denominators) {
      lines.push(
        `| ${tableCell(row.category)} | ${row.files_total} | ` +
        `${row.files_examined} | ${row.files_unexamined} | ` +
        `${row.bytes_total} | ${row.bytes_examined} | ` +
        `${row.bytes_unexamined} |`,
      )
    }
    lines.push('')
  }

  if (coverageSummary.closure) {
    const closure = coverageSummary.closure
    lines.push(
      '### Recursive coverage closure',
      '',
      `Status: ${inlineCode(closure.status)}  `,
      `Round: ${coverageMetric(closure.round)} of ${coverageMetric(closure.max_rounds)}  `,
      `Source closure required: ${closure.required_source_closure ? 'yes' : 'no'}  `,
      `Applicable lens/file pairs: ${coverageMetric(closure.applicable_lens_file_pairs)}  `,
      `Examined lens/file pairs: ${coverageMetric(closure.examined_lens_file_pairs)}  `,
      `Open lens/file pairs: ${coverageMetric(closure.uncovered_lens_file_pairs)}  `,
      `Open shards: ${coverageMetric(closure.uncovered_shard_count)}`,
      '',
    )
    if (closure.history_samples.length > 0) {
      lines.push(
        '#### Measurement history',
        '',
        '| Round | Outcome | Applicable pairs | Examined pairs | Open pairs | Open shards |',
        '|---:|---|---:|---:|---:|---:|',
      )
      for (const measurement of closure.history_samples) {
        lines.push(
          `| ${coverageMetric(measurement.round)} | ` +
          `${tableCell(measurement.status)} | ` +
          `${coverageMetric(measurement.applicable_lens_file_pairs)} | ` +
          `${coverageMetric(measurement.examined_lens_file_pairs)} | ` +
          `${coverageMetric(measurement.uncovered_lens_file_pairs)} | ` +
          `${coverageMetric(measurement.uncovered_shard_count)} |`,
        )
      }
      if (closure.omitted_history_count > 0) {
        lines.push(
          '',
          `${closure.omitted_history_count} earlier closure measurement ` +
          `record${closure.omitted_history_count === 1 ? '' : 's'} omitted; ` +
          'the most recent measurements are shown.',
        )
      }
      lines.push('')
    }
  }

  lines.push(
    '### Lens/file obligations',
    '',
    '| Lens | Status | Applicable | Examined | Open | Coverage authority | Reason |',
    '|---|---|---:|---:|---:|---|---|',
  )
  for (const lens of coverageSummary.lensRows) {
    lines.push(
      `| ${tableCell(lens.lens)} | ${tableCell(lens.status)} | ` +
      `${lens.applicable_count ?? '—'} | ${lens.examined_count} | ` +
      `${lens.open_count ?? '—'} | ` +
      `${tableCell(lensAuthorityLabel(lens.lens))} | ` +
      `${tableCell(lens.reason)} |`,
    )
  }
  lines.push('')

  const databaseDiscovery = run.database_discovery
  if (
    databaseDiscovery
    && Array.isArray(databaseDiscovery.store_candidates)
    && Array.isArray(databaseDiscovery.path_scope)
  ) {
    const candidates = databaseDiscovery.store_candidates
    const candidateSamples = candidates.slice(0, COVERAGE_SAMPLE_LIMIT)
    const profiledStoreIds = new Set(
      (run.store_profiles ?? [])
        .map((profile) => profile.store_context?.store_id)
        .filter(Boolean),
    )
    lines.push(
      '### Controller database discovery',
      '',
      `Graph: ${inlineCode(databaseDiscovery.digest)}  `,
      `Discovered stores: ${candidates.length}  `,
      `Database-scoped paths: ${databaseDiscovery.path_scope
        .filter(({ state }) => state === 'in-scope').length}  `,
      `Unresolved observations: ${(databaseDiscovery.unresolved ?? []).length}  `,
      `Discovery limit gaps: ${(databaseDiscovery.gaps ?? []).length}`,
      '',
    )
    if (candidateSamples.length > 0) {
      lines.push(
        '| Store | Engine candidates | Version candidates | Confidence | Profile | Open discovery reasons |',
        '|---|---|---|---|---|---|',
      )
      for (const candidate of candidateSamples) {
        lines.push(
          `| ${tableCell(candidate.store_id)} | ` +
          `${tableCell((candidate.engine_candidates ?? []).join(', ') || 'unresolved')} | ` +
          `${tableCell((candidate.engine_version_candidates ?? []).join(', ') || 'unresolved')} | ` +
          `${tableCell(candidate.confidence)} | ` +
          `${profiledStoreIds.has(candidate.store_id) ? 'recorded' : 'NOT ASSESSED'} | ` +
          `${tableCell((candidate.open_reasons ?? []).join(', ') || 'none')} |`,
        )
      }
      if (candidates.length > candidateSamples.length) {
        lines.push(
          '',
          `${candidates.length - candidateSamples.length} additional discovered ` +
          `store${candidates.length - candidateSamples.length === 1 ? '' : 's'} ` +
          'omitted from Markdown; see database-discovery.json.',
        )
      }
      lines.push('')
    }
  }

  const databaseConformance = run.database_conformance
  if (databaseConformance) {
    lines.push(
      '### Reference database conformance',
      '',
      `Source run: ${inlineCode(databaseConformance.source.run_id)}  `,
      `Source root: ${inlineCode(databaseConformance.source.root_sha256)}  `,
      `Root authenticity: ${inlineCode(databaseConformance.root_authenticity)}  `,
      `Assurance: ${inlineCode(databaseConformance.assurance_scope)}  `,
      'Target deployment proven: **no**',
      '',
      '> These results describe digest-pinned disposable reference engines only. They do not elevate any target finding, proof tier, verification status, store profile, or deployment-coverage claim.',
      '',
      '| Engine | Product/version | Result | Passing scenarios | Image |',
      '|---|---|---|---:|---|',
    )
    for (const engine of databaseConformance.engines) {
      lines.push(
        `| ${tableCell(engine.engine_id)} | ` +
        `${tableCell(`${engine.product} ${engine.server_version}`)} | ` +
        `${tableCell(engine.state)} | ` +
        `${engine.scenarios.filter(({ state }) => state === 'PASSED').length}/` +
        `${engine.scenarios.length} | ${tableCell(engine.requested_image)} |`,
      )
    }
    lines.push('')
  }

  const storeProfiles = run.store_profiles ?? []
  if (
    storeProfiles.length > 0
    || (run.activated_lenses ?? []).includes('database-and-data-stores')
  ) {
    lines.push(
      '### Data-store coverage',
      '',
      '| Store | Engine | Deployment | Adapter | Coverage | Assessed topics | Effective principal |',
      '|---|---|---|---|---|---|---|',
    )
    if (storeProfiles.length === 0) {
      lines.push(
        '| No store profile recorded | — | — | — | NOT ASSESSED | — | — |',
      )
    }
    for (const profile of storeProfiles) {
      lines.push(
        `| ${tableCell(profile.store_context.store_id)} | ` +
        `${tableCell(profile.store_context.engine)} | ` +
        `${tableCell(profile.store_context.deployment_variant)} | ` +
        `${tableCell(profile.store_context.adapter_id)} | ` +
        `${tableCell(profile.coverage_state)} | ` +
        `${tableCell(profile.assessed_topics.join(', ') || 'none')} | ` +
        `${tableCell(profile.principal_path.effective_principal)} |`,
      )
    }
    lines.push('')
  }

  const evidenceCoverage = run.evidence_coverage
  if (evidenceCoverage) {
    const evidenceSummary = evidenceCoverage.summary ?? {}
    // NOT_APPLICABLE cells are the overwhelming majority — a lens that did not
    // activate, or a class it declares not-consumed — and printing them buries
    // the handful of cells that are the entire point under hundreds of rows of
    // nothing. They stay in run.json, where a machine reads them; the report
    // states their count and shows what a reader has to act on.
    const reportable = (evidenceCoverage.cells ?? [])
      .filter((cell) => cell.state !== 'NOT_APPLICABLE')
    const notApplicable = (evidenceCoverage.cells ?? []).length - reportable.length

    lines.push('### Evidence-class coverage', '')
    if (reportable.length > 0) {
      lines.push(
        '| Lens | Topic | Evidence class | Coverage | Basis |',
        '|---|---|---|---|---|',
      )
      for (const cell of reportable) {
        lines.push(
          `| ${tableCell(cell.lens)} | ${tableCell(cell.topic)} | ` +
          `${tableCell(cell.evidence_class)} | ${tableCell(cell.state)} | ` +
          `${tableCell(cell.reason)} |`,
        )
      }
      lines.push('')
    }
    if (notApplicable > 0) {
      lines.push(
        `${notApplicable} further lens/topic/class ` +
        `${notApplicable === 1 ? 'cell is' : 'cells are'} ` +
        'NOT_APPLICABLE — the lens did not activate, or declares that class ' +
        'not-consumed. They carry no obligation and are recorded in `run.json`.',
        '',
      )
    }
    // INVENTORY_ONLY and NOT_ASSESSED are never rendered as pass, clean, secure
    // or no findings. Stating the blind spot is the whole point: silence about
    // an unexamined class is what reads as clearance.
    if ((evidenceSummary.unreached_class_count ?? 0) > 0) {
      const classes = (evidenceSummary.unreached_classes ?? []).join(', ')
      lines.push(
        `${evidenceSummary.unreached_class_count} evidence ` +
        `class${evidenceSummary.unreached_class_count === 1 ? ' was' : 'es were'} not acquired ` +
        `for this run: ${classes}. Findings and clean results below cover the ` +
        'repository only. An unexamined evidence class is a coverage gap, not a clearance.',
        '',
      )
    }
    const phiBearing = (run.evidence_bundles ?? []).filter(({ phi_bearing: bearing }) => bearing)
    if (phiBearing.length > 0) {
      lines.push(
        '#### PHI-bearing evidence',
        '',
        'The following bundles were captured with contents under a declared PHI scope. ' +
        'Their contents are not reproduced here; the bundle is itself an auditable ' +
        'artifact and is subject to its retention limit.',
        '',
        '| Evidence | Class | Adapter | Bundle digest |',
        '|---|---|---|---|',
      )
      for (const bundle of phiBearing) {
        lines.push(
          `| ${tableCell(bundle.evidence_id)} | ${tableCell(bundle.evidence_class)} | ` +
          `${tableCell(bundle.adapter_id)} | ${inlineCode(bundle.root_sha256.slice(0, 12))} |`,
        )
      }
      lines.push('')
    }
    if ((evidenceSummary.inventory_only_cell_count ?? 0) > 0) {
      lines.push(
        `${evidenceSummary.inventory_only_cell_count} lens/topic obligation` +
        `${evidenceSummary.inventory_only_cell_count === 1 ? '' : 's'} received evidence no ` +
        'activated lens has a rule for; those are inventoried, not assessed.',
        '',
      )
    }
  }

  const conflicts = evidenceConflicts(run.findings ?? [])
  if (conflicts.length > 0) {
    lines.push(
      '### Precedence conflicts',
      '',
      'Where two evidence classes disagree about one topic the higher-precedence ' +
      'class prevails and the disagreement is recorded here. A lower-precedence ' +
      'signal never overrides a conflicting higher-precedence one.',
      '',
      '| Topic | Prevailing | Class | Superseded | Class |',
      '|---|---|---|---|---|',
    )
    for (const conflict of conflicts) {
      lines.push(
        `| ${tableCell(conflict.topic)} | ` +
        `${inlineCode(conflict.prevailing_candidate_id)} | ` +
        `${tableCell(conflict.prevailing_class)} | ` +
        `${inlineCode(conflict.superseded_candidate_id)} | ` +
        `${tableCell(conflict.superseded_class)} |`,
      )
    }
    lines.push('')
  }

  if (coverageSummary.openFileSamples.length > 0) {
    lines.push(
      '### Open file samples',
      '',
      '| Path | Open lenses | Reasons |',
      '|---|---|---|',
    )
    for (const entry of coverageSummary.openFileSamples) {
      lines.push(
        `| ${tableCell(entry.path)} | ` +
        `${tableCell(entry.lenses.join(', ') || 'none')} | ` +
        `${tableCell(sampledReasonsLabel(
          entry,
          'open lens/file obligation',
        ))} |`,
      )
    }
    if (coverageSummary.omittedOpenFileSamples > 0) {
      lines.push(
        '',
        `${coverageSummary.omittedOpenFileSamples} additional open file ` +
        `sample${coverageSummary.omittedOpenFileSamples === 1 ? '' : 's'} ` +
        'omitted from Markdown; see coverage.json for the complete record.',
      )
    }
    lines.push('')
  }

  if (coverageSummary.nonFileGapSamples.length > 0) {
    lines.push(
      '### Non-file coverage gap groups',
      '',
      '| Area | Open records | Reasons |',
      '|---|---:|---|',
    )
    for (const entry of coverageSummary.nonFileGapSamples) {
      lines.push(
        `| ${tableCell(entry.area)} | ${entry.records} | ` +
        `${tableCell(sampledReasonsLabel(entry))} |`,
      )
    }
    if (coverageSummary.omittedNonFileGapSamples > 0) {
      lines.push(
        '',
        `${coverageSummary.omittedNonFileGapSamples} additional non-file gap ` +
        `group${coverageSummary.omittedNonFileGapSamples === 1 ? '' : 's'} ` +
        'omitted from Markdown; see coverage.json for the complete record.',
      )
    }
    lines.push('')
  }

  if (removed.length > 0) {
    lines.push(
      '## Withdrawn candidates',
      '',
      '| Candidate | Claimed | Effective | Disposition | Verification | Proof tier | Status detail | Merged into |',
      '|---|---|---|---|---|---|---|---|',
    )
    for (const finding of removed) {
      lines.push(
        `| ${tableCell(finding.candidate_id)} | ${tableCell(finding.claimed_impact_severity)} | ` +
        `${tableCell(finding.effective_severity ?? 'not assigned')} | ` +
        `${tableCell(displayTriageDisposition(finding) ?? 'not triaged')} | ` +
        `${tableCell(displayVerificationStatus(finding))} | ` +
        `${tableCell(finding.proof_tier ?? 'NOT ASSESSED')} | ` +
        `${tableCell(proofStatusDetail(finding))} | ` +
        `${tableCell(finding.merged_into_candidate_id)} |`,
      )
    }
    lines.push('')
  }

  if ((run.errors ?? []).length > 0) {
    lines.push('## Run errors', '', '| Phase | Code | Message |', '|---|---|---|')
    for (const error of run.errors) {
      lines.push(`| ${tableCell(error.phase)} | ${tableCell(error.code)} | ${tableCell(error.message)} |`)
    }
    lines.push('')
  }

  if (producedJobs.length > 0) {
    lines.push(
      '## Provider and controller provenance',
      '',
      'Producer identity is supplied by the provider and is not an authenticated identity claim. Coverage authority and receipt fields are controller-owned.',
      '',
      '| Job | Declared producer | Version | Instance | Input packet | Coverage authority | Attempt | Receipt |',
      '|---|---|---|---|---|---|---|---|',
    )
    for (const job of producedJobs) {
      lines.push(
        `| ${tableCell(job.job_id)} | ${tableCell(job.producer.name)} | ` +
        `${tableCell(job.producer.version)} | ${tableCell(job.producer.instance_id)} | ` +
        `${tableCell(job.input_sha256)} | ${tableCell(job.coverage_authority)} | ` +
        `${tableCell(job.attempt_id)} | ${tableCell(job.receipt_sha256)} |`,
      )
    }
    lines.push('')
  }

  lines.push(
    '## Provenance',
    '',
    `Plan digest: ${inlineCode(run.plan_digest ?? 'not recorded')}  `,
    `Policy digest: ${inlineCode(run.policy_digest ?? 'not recorded')}  `,
    `Lens pack digest: ${inlineCode(run.lens_pack_digest ?? 'not recorded')}`,
    '',
  )
  return `${lines.join('\n').trimEnd()}\n`
}

function parseLocation(value) {
  // The path is lazy so a trailing `:line:column` binds to both groups. A
  // greedy path swallows the line and reports the column as the line.
  const match = /^(.*?):([1-9][0-9]*)(?::([1-9][0-9]*))?$/.exec(String(value))
  if (!match) return null
  return {
    path: match[1].replaceAll('\\', '/'),
    line: Number(match[2]),
    column: match[3] === undefined ? undefined : Number(match[3]),
  }
}

function sarifLevel(severity) {
  if (severity === 'Critical' || severity === 'High') return 'error'
  if (severity === 'Medium' || severity === 'Low') return 'warning'
  return 'note'
}

// SARIF 2.1.0 separates how bad a result is (`level`) from how urgent it is
// (`rank`, 0-100). That is exactly the severity/confidence split, so a consumer
// can gate on `level: error` to catch every claimed Critical, or on `rank` to
// catch only the demonstrated ones, without the report choosing for them.
const SARIF_RANK = new Map([
  ['Critical', 100],
  ['High', 80],
  ['Medium', 50],
  ['Low', 20],
  ['Info', 0],
])

function sarifRank(severity) {
  return SARIF_RANK.get(severity) ?? 0
}

export function renderSarif(run, options = {}) {
  const lifecycleByFinding = new Map(
    (options.lifecycle?.results ?? [])
      .filter((entry) => entry.finding !== null)
      .map((entry) => [`${entry.fingerprint}\0${entry.candidate_id}`, entry.state]),
  )
  const allFindings = run.findings ?? []
  const findings = sortedFindings(allFindings.filter(isSurvivingFinding))
  const withdrawn = sortedFindings(allFindings.filter(
    (finding) => !isSurvivingFinding(finding),
  ))
  const unverifiedHighImpact = allFindings.filter(isUnverifiedHighImpactClaim)
  const evidenceNotifications = (run.evidence_coverage?.summary?.unreached_classes ?? [])
    .map((evidenceClass) => ({
      level: 'warning',
      descriptor: { id: `evidence-class-not-assessed/${evidenceClass}` },
      message: {
        text: `No ${evidenceClass} evidence was acquired for this run. Results cover `
          + 'the repository only; an unexamined evidence class is a coverage gap, '
          + 'not a clearance.',
      },
    }))
  const producedJobs = (run.jobs ?? []).filter((job) => job.producer)
  const coverageSummary = coverageProjection(run.coverage ?? {})
  const rulesByTopic = new Map()
  for (const finding of [...findings, ...withdrawn]) {
    if (rulesByTopic.has(finding.topic)) continue
    rulesByTopic.set(finding.topic, {
      id: finding.topic,
      name: finding.topic,
      shortDescription: { text: `Red Team Audit: ${finding.topic}` },
      properties: {
        lens: finding.lens,
        ...(finding.cwe ? { tags: [finding.cwe] } : {}),
      },
    })
  }

  const sarifResult = (finding) => {
    const fingerprint = findingFingerprint(finding)
    const lifecycle = lifecycleByFinding.get(`${fingerprint}\0${finding.candidate_id}`)
    const remediation = remediationDetail(finding)
    const locations = (finding.location ?? [])
      .map(parseLocation)
      .filter(Boolean)
      .map(({ path, line, column }) => ({
        physicalLocation: {
          // Keep SARIF portable and avoid disclosing a developer's absolute
          // checkout path. Finding locations are repository-relative.
          artifactLocation: { uri: path },
          region: {
            startLine: line,
            ...(column === undefined ? {} : { startColumn: column }),
          },
        },
      }))
    return {
      ruleId: finding.topic,
      level: sarifLevel(claimedSeverityOf(finding)),
      rank: sarifRank(severityOf(finding)),
      message: { text: `${finding.title}: ${finding.impact}` },
      locations,
      partialFingerprints: {
        'redTeamAudit/semantic/v1': fingerprint,
      },
      ...(lifecycle ? {
        baselineState: lifecycle === 'new'
          ? 'new'
          : lifecycle === 'unchanged'
            ? 'unchanged'
            : 'updated',
      } : {}),
      properties: {
        candidate_id: finding.candidate_id,
        lens: finding.lens,
        claimed_impact_severity: finding.claimed_impact_severity,
        effective_severity: finding.effective_severity ?? null,
        report_priority_severity: severityOf(finding),
        triage_disposition: displayTriageDisposition(finding) ?? null,
        provider_claimed_triage_disposition: finding.triage_disposition ?? null,
        triage_authority: triageAuthorityOf(finding),
        merged_into_candidate_id: finding.merged_into_candidate_id ?? null,
        drop_reason: finding.drop_reason ?? null,
        verification_status: displayVerificationStatus(finding) ?? null,
        provider_claimed_verification_status: finding.verification_status ?? null,
        verification_authority: verificationAuthorityOf(finding),
        proof_tier: finding.proof_tier ?? null,
        ...(remediation
          ? {
              remediation_status: remediation.status,
              remediation_detail: remediation.detail,
            }
          : {}),
        reachability: finding.reachable_from,
        coverage_authority: [...new Set(
          producedJobs
            .filter((job) =>
              job.lens === finding.lens
              || (job.candidate_ids ?? []).includes(finding.candidate_id))
            .map(({ coverage_authority: authority }) =>
              authority ?? 'PROVIDER_DECLARED'),
        )].sort((left, right) => left.localeCompare(right, 'en')),
      },
    }
  }

  // A withdrawn candidate is a record, not an alert. SARIF suppressions are the
  // representation that keeps it in the machine artifact CI gates on without
  // counting it as an open result.
  const suppressedResult = (finding) => {
    const result = sarifResult(finding)
    return {
      ...result,
      suppressions: [{
        kind: 'external',
        status: 'accepted',
        justification: proofStatusDetail(finding),
      }],
      properties: {
        ...result.properties,
        triage_disposition: finding.triage_disposition ?? null,
        merged_into_candidate_id: finding.merged_into_candidate_id ?? null,
        drop_reason: finding.drop_reason ?? null,
      },
    }
  }

  const results = [
    ...findings.map(sarifResult),
    ...withdrawn.map(suppressedResult),
  ]

  return {
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    version: '2.1.0',
    runs: [{
      automationDetails: { id: run.run_id },
      tool: {
        driver: {
          name: 'red-team-audit',
          version: run.tool?.version ?? '0.4.0',
          rules: [...rulesByTopic.values()].sort((left, right) => left.id.localeCompare(right.id, 'en')),
        },
      },
      invocations: [{
        executionSuccessful: ['COMPLETED', 'COMPLETE_WITH_GAPS'].includes(run.state),
        exitCode: run.state === 'COMPLETED' ? 0 : 2,
        // A coverage cell is not a finding, so an unreached evidence class must
        // not become a result — that would inflate the finding count with
        // things nobody found. SARIF's notification channel is where "the tool
        // could not examine X" belongs.
        ...(evidenceNotifications.length > 0
          ? { toolExecutionNotifications: evidenceNotifications }
          : {}),
        properties: {
          run_state: run.state,
          capability_mode: run.capability_mode,
          coverage_inventory: run.coverage?.inventory?.length ?? 0,
          coverage_examined: run.coverage?.examined?.length ?? 0,
          coverage_unexamined: run.coverage?.unexamined?.length ?? 0,
          coverage_gaps: coverageSummary.raw_open_gap_records,
          coverage_gap_history_records:
            coverageSummary.gapProjection.input_gap_count,
          coverage_unique_open_files: coverageSummary.unique_open_files,
          coverage_open_lens_file_obligations:
            coverageSummary.open_lens_file_obligations,
          coverage_conceptual_unique_open_gaps:
            coverageSummary.conceptual_unique_open_gaps,
          coverage_exact_open_gap_identities:
            coverageSummary.exact_open_gap_identities,
          coverage_exact_open_lens_file_gaps:
            coverageSummary.exact_open_lens_file_gaps,
          coverage_unique_non_file_gap_groups:
            coverageSummary.unique_non_file_gap_groups,
          coverage_raw_open_gap_records:
            coverageSummary.raw_open_gap_records,
          coverage_resolved_gap_records:
            coverageSummary.resolved_gap_records,
          ...(coverageSummary.denominators.length > 0
            ? {
                coverage_denominators: coverageSummary.denominators.map(
                  (row) => ({ ...row }),
                ),
              }
            : {}),
          ...(coverageSummary.closure
            ? {
                coverage_closure_status: coverageSummary.closure.status,
                coverage_closure_round: coverageSummary.closure.round,
                coverage_closure_max_rounds:
                  coverageSummary.closure.max_rounds,
                coverage_closure_source_required:
                  coverageSummary.closure.required_source_closure,
                coverage_closure_applicable_lens_file_pairs:
                  coverageSummary.closure.applicable_lens_file_pairs,
                coverage_closure_examined_lens_file_pairs:
                  coverageSummary.closure.examined_lens_file_pairs,
                coverage_closure_open_lens_file_pairs:
                  coverageSummary.closure.uncovered_lens_file_pairs,
                coverage_closure_open_shards:
                  coverageSummary.closure.uncovered_shard_count,
                coverage_closure_history_records:
                  coverageSummary.closure.history_count,
                coverage_closure_history:
                  coverageSummary.closure.history_samples.map(
                    (measurement) => ({ ...measurement }),
                  ),
                coverage_closure_history_omitted_records:
                  coverageSummary.closure.omitted_history_count,
              }
            : {}),
          provider_declared_jobs: producedJobs.filter(
            ({ coverage_authority: authority }) => authority === 'PROVIDER_DECLARED',
          ).length,
          controller_observed_consumption_jobs: producedJobs.filter(
            ({ coverage_authority: authority }) =>
              authority === 'CONTROLLER_OBSERVED_CONSUMPTION',
          ).length,
          remote_request_accepted_jobs: producedJobs.filter(
            ({ coverage_authority: authority }) =>
              authority === 'REMOTE_REQUEST_ACCEPTED',
          ).length,
          findings_state: findings.length === 0
            ? 'NO_FINDINGS_REPORTED'
            : 'FINDINGS_REPORTED',
          withdrawn_candidates: withdrawn.length,
          withdrawn_high_impact_candidates: withdrawn.filter((finding) =>
            HIGH_IMPACT_SEVERITIES.has(finding.claimed_impact_severity)).length,
          unverified_high_impact_claims: unverifiedHighImpact.length,
          data_stores: run.store_profiles?.length ?? 0,
          data_stores_not_assessed: (run.store_profiles ?? []).filter(
            ({ coverage_state: state }) => state !== 'ASSESSED',
          ).length,
          database_discovery_digest: run.database_discovery?.digest,
          database_discovered_stores:
            run.database_discovery?.store_candidates?.length ?? 0,
          database_discovery_scoped_paths:
            run.database_discovery?.path_scope?.filter(
              ({ state }) => state === 'in-scope',
            ).length ?? 0,
          database_discovery_unresolved:
            run.database_discovery?.unresolved?.length ?? 0,
          database_discovery_limit_gaps:
            run.database_discovery?.gaps?.length ?? 0,
        },
      }],
      results,
    }],
  }
}
