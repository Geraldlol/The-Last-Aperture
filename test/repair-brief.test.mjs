import { test } from 'node:test'
import assert from 'node:assert/strict'
import { compareRuns, findingFingerprint } from '../scripts/lib/lifecycle.mjs'
import {
  buildRepairBrief,
  renderRepairBriefMarkdown,
} from '../scripts/lib/repair-brief.mjs'

function finding(overrides = {}) {
  return {
    candidate_id: 'cand:repair:001',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Recorded title',
    claimed_impact_severity: 'High',
    location: ['src/orders.js:42:7', 'src/orders.js:44', 'src/orders.js:42:7'],
    evidence: 'Synthetic evidence narrative',
    attack: 'Synthetic attack narrative',
    impact: 'Synthetic impact narrative',
    reachable_from: 'Synthetic entry point',
    confidence: 'High',
    proof_plan: 'Synthetic proof narrative',
    triage_disposition: 'queued',
    verification_status: 'UNPROVEN',
    proof_tier: 'T0',
    ...overrides,
  }
}

function run(overrides = {}) {
  return {
    run_id: 'run:repair:001',
    state: 'COMPLETED',
    repository: { root: 'C:\\private-repository', tree_digest: 'a'.repeat(64) },
    coverage: {
      inventory: ['src/orders.js'],
      examined: ['src/orders.js'],
      unexamined: [],
      lenses: [{ lens: 'web-and-api', status: 'RAN', examined_paths: ['src/orders.js'] }],
      gaps: [],
    },
    findings: [finding()],
    jobs: [{ kind: 'LENS', lens: 'web-and-api', state: 'SUCCEEDED', coverage_authority: 'PROVIDER_DECLARED' }],
    policy_digest: 'b'.repeat(64),
    lens_pack_digest: 'c'.repeat(64),
    ...overrides,
  }
}

test('repair brief preserves identity and source coordinates without inventing a repair', () => {
  const saved = run()
  const before = structuredClone(saved)
  const brief = buildRepairBrief(saved)
  const [item] = brief.findings.items
  assert.equal(brief.schema_version, '1.0.0')
  assert.equal(brief.kind, 'REPAIR_RETEST_HANDOFF')
  assert.equal(item.candidate_id, saved.findings[0].candidate_id)
  assert.equal(item.fingerprint, findingFingerprint(saved.findings[0]))
  assert.deepEqual(item.affected_source_files.items, [{
    path: 'src/orders.js',
    coordinates: [{ line: 42, column: 7 }, { line: 44 }],
    omitted_coordinates: 0,
  }])
  assert.equal(item.recommended_change.status, 'UNKNOWN')
  assert.equal(item.observed_impact.claimed_severity, 'High')
  assert.equal(item.observed_impact.narrative, 'WITHHELD_SENSITIVE_FREE_TEXT')
  assert.ok(item.acceptance_checklist.length >= 4)
  assert.ok(item.acceptance_checklist.every((entry) => entry.status !== 'PASSED'))
  assert.deepEqual(saved, before)
})

test('repair handoff does not export free-text evidence, PHI, credentials, or proof payloads', () => {
  const sensitive = 'PRIVATE_PATIENT_OR_CREDENTIAL_SENTINEL'
  const saved = run({ findings: [finding({
    title: sensitive,
    evidence: sensitive,
    attack: sensitive,
    impact: sensitive,
    proof_plan: sensitive,
    command: sensitive,
    reachable_from: sensitive,
    reason: sensitive,
    remediation: { status: 'FIX_FAILED', detail: sensitive },
    quotes: [{ path: 'src/orders.js', line: 42, text: sensitive }],
    artifact: { path: sensitive },
    pre_result: { detail: sensitive },
    post_result: { status: 'passed', regressions: sensitive },
    evidence_context: {
      evidence_id: 'synthetic', evidence_class: 'live-runtime', adapter_id: 'synthetic',
      target_identity: sensitive, detection_evidence: [sensitive],
    },
    location: [`synthetic:/${sensitive}:42`],
  })] })
  const brief = buildRepairBrief(saved)
  const serialized = JSON.stringify(brief)
  assert.ok(!serialized.includes(sensitive))
  assert.ok(!serialized.includes('C:\\private-repository'))
  assert.ok(!renderRepairBriefMarkdown(brief).includes(sensitive))
  assert.equal(brief.findings.items[0].evidence_references.total, 1)
  assert.equal(brief.findings.items[0].affected_source_files.total, 0)
  assert.equal(brief.findings.items[0].recorded_fields.impact, true)
  assert.equal(brief.findings.items[0].recorded_fields.remediation_detail, true)
})

test('unverified negative and remediation assertions remain visible as claims', () => {
  const saved = run({ findings: [finding({
    triage_disposition: 'dropped',
    verification_status: 'DISPROVED',
    verification_authority: 'UNAUTHENTICATED_PROVIDER_ASSERTION',
    remediation: { status: 'FIX_VERIFIED', detail: 'Provider claim only' },
    post_result: { status: 'passed', regressions: 'Provider claim only' },
  })] })
  const [item] = buildRepairBrief(saved).findings.items
  assert.equal(item.claims.verification.display_status, 'CLAIMED_DISPROVED')
  assert.equal(item.claims.verification.authenticated, false)
  assert.equal(item.claims.triage.display_status, 'CLAIMED_DROPPED')
  assert.equal(item.claims.remediation.claimed_status, 'FIX_VERIFIED')
  assert.equal(item.claims.remediation.display_status, 'CLAIMED_FIX_VERIFIED')
  assert.equal(item.claims.remediation.fix_verified, false)
  assert.equal(item.claims.post_result.establishes_fix, false)
  assert.equal(item.retained_by_current_policy, true)
  assert.equal(saved.findings[0].remediation.status, 'FIX_VERIFIED')
})

test('evidence locators never become affected source files even when they end in line numbers', () => {
  const saved = run({ findings: [finding({
    location: ['image:src/orders.js:42', 'src/orders.js:42'],
    evidence_context: { evidence_id: 'image', evidence_class: 'built-artifact' },
  })] })
  const [item] = buildRepairBrief(saved).findings.items
  assert.equal(item.affected_source_files.total, 0)
  assert.equal(item.evidence_references.total, 2)
  assert.ok(item.evidence_references.items.every((entry) => entry.locator === 'WITHHELD'))
})

test('only canonical repository-inventory paths are shown as source references', () => {
  const saved = run({ findings: [finding({ location: [
    'src\\orders.js:42:7', '../outside.js:12', '/tmp/private.js:3',
    'C:\\private\\patient.js:4', 'https://host/private.js:5',
    'src/unlisted.js:8', 'src/orders.js:9007199254740992',
  ] })] })
  const [item] = buildRepairBrief(saved).findings.items
  assert.deepEqual(item.affected_source_files.items, [{
    path: 'src/orders.js', coordinates: [{ line: 42, column: 7 }], omitted_coordinates: 0,
  }])
  assert.equal(item.unresolved_location_count, 6)
  assert.ok(!JSON.stringify(item).includes('patient.js'))
})

test('literal repository filenames retain hash and question-mark characters without becoming URI references', () => {
  const paths = ['src/name#fragment.js', 'src/name?version.js']
  const saved = run({
    coverage: { inventory: paths },
    findings: [finding({ location: paths.map((path) => `${path}:12`) })],
  })
  const brief = buildRepairBrief(saved)
  const [item] = brief.findings.items
  assert.deepEqual(item.affected_source_files.items.map(({ path }) => path), paths)
  assert.equal(item.unresolved_location_count, 0)
  const rendered = renderRepairBriefMarkdown(brief)
  assert.ok(rendered.includes('src/name\\#fragment\\.js'))
  assert.ok(rendered.includes('src/name?version\\.js'))
})

test('comparison retains missing baseline findings and never promotes absence to a verified fix', () => {
  const baseline = run()
  const current = run({ run_id: 'run:repair:002', findings: [] })
  const comparison = compareRuns(baseline, current)
  const brief = buildRepairBrief(current, { comparison })
  const [item] = brief.findings.items
  assert.equal(item.source_run_id, baseline.run_id)
  assert.equal(item.present_in_requested_run, false)
  assert.equal(item.lifecycle_links.items[0].state, 'claimed-fixed')
  assert.equal(item.lifecycle_links.items[0].semantic_resolution_authority, 'UNAUTHENTICATED_COVERAGE_ABSENCE')
  assert.equal(item.lifecycle_links.items[0].fix_verified, false)
  assert.equal(item.claims.remediation.fix_verified, false)
  assert.equal(brief.findings.absent_baseline_candidates, 1)
  assert.equal(comparison.results[0].state, 'claimed-fixed')
})

test('lifecycle links pair candidate IDs and fingerprints without merging collision members', () => {
  const baseline = run({ findings: [
    finding({ candidate_id: 'cand:repair:a' }),
    finding({ candidate_id: 'cand:repair:b', impact: 'Other recorded impact' }),
  ] })
  const current = run({ run_id: 'run:repair:002', findings: [
    finding({ candidate_id: 'cand:repair:c', impact: 'Other recorded impact' }),
  ] })
  const comparison = compareRuns(baseline, current)
  const brief = buildRepairBrief(current, { comparison })
  assert.equal(brief.findings.total, 2)
  const present = brief.findings.items.find((item) => item.present_in_requested_run)
  const absent = brief.findings.items.find((item) => !item.present_in_requested_run)
  assert.equal(present.lifecycle_links.items[0].baseline_candidate_id, 'cand:repair:b')
  assert.equal(present.lifecycle_links.items[0].current_candidate_id, 'cand:repair:c')
  assert.equal(absent.lifecycle_links.items[0].baseline_candidate_id, 'cand:repair:a')
  assert.equal(absent.lifecycle_links.items[0].current_candidate_id, null)
  assert.equal(present.fingerprint, absent.fingerprint)
})

test('candidate selection supports absent baseline records and rejects unrelated comparisons', () => {
  const baseline = run()
  const current = run({ run_id: 'run:repair:002', findings: [] })
  const comparison = compareRuns(baseline, current)
  assert.equal(buildRepairBrief(current, { comparison, candidateId: 'cand:repair:001' }).findings.total, 1)
  assert.throws(() => buildRepairBrief(current, { candidateId: 'cand:not:present' }), /candidate was not found/)
  assert.throws(() => buildRepairBrief(run({ run_id: 'run:unrelated:001' }), { comparison }), /comparison does not include/)
})

test('incomplete retest retains a not-observed baseline candidate and the baseline can link forward', () => {
  const baseline = run()
  const current = run({
    run_id: 'run:repair:incomplete', state: 'INCOMPLETE', findings: [],
    coverage: { inventory: ['src/orders.js'], examined: [], unexamined: [{ path: 'src/orders.js' }] },
  })
  const comparison = compareRuns(baseline, current)
  const currentItem = buildRepairBrief(current, { comparison }).findings.items[0]
  const baselineItem = buildRepairBrief(baseline, { comparison }).findings.items[0]
  assert.equal(currentItem.lifecycle_links.items[0].state, 'not-observed')
  assert.equal(currentItem.lifecycle_links.items[0].semantic_resolution_authority, 'NO_RESOLUTION_CLAIM')
  assert.equal(baselineItem.present_in_requested_run, true)
  assert.equal(baselineItem.lifecycle_links.items[0].current_run_id, current.run_id)
  assert.equal(baselineItem.lifecycle_links.items[0].fix_verified, false)
})

test('repair handoff samples explicitly and can select a candidate outside the first sample', () => {
  const saved = run({ findings: Array.from({ length: 105 }, (_, index) => finding({
    candidate_id: `cand:repair:${String(index).padStart(3, '0')}`,
  })) })
  const brief = buildRepairBrief(saved)
  assert.equal(brief.findings.total, 105)
  assert.equal(brief.findings.items.length, 100)
  assert.equal(brief.findings.omitted, 5)
  assert.equal(buildRepairBrief(saved, { candidateId: 'cand:repair:104' }).findings.items[0].candidate_id, 'cand:repair:104')
})

test('file and coordinate samples disclose omitted detail without losing aggregate counts', () => {
  const paths = Array.from({ length: 34 }, (_, index) => `src/file-${String(index).padStart(2, '0')}.js`)
  const saved = run({
    coverage: { inventory: paths },
    findings: [finding({ location: [
      ...paths.map((path) => `${path}:1`),
      ...Array.from({ length: 33 }, (_, index) => `${paths[0]}:${index + 2}`),
    ] })],
  })
  const files = buildRepairBrief(saved).findings.items[0].affected_source_files
  assert.equal(files.total, 34)
  assert.equal(files.items.length, 32)
  assert.equal(files.omitted, 2)
  assert.equal(files.items[0].coordinates.length, 32)
  assert.equal(files.items[0].omitted_coordinates, 2)
})

test('Markdown renders metadata inertly and makes UNKNOWN repair and unverified claims explicit', () => {
  const path = 'src/<img src=x onerror=alert(1)>_[text].js'
  const saved = run({
    coverage: { inventory: [path] },
    findings: [finding({ location: [`${path}:4`], verification_status: 'NOT_REPRODUCED' })],
  })
  const markdown = renderRepairBriefMarkdown(buildRepairBrief(saved))
  assert.ok(markdown.includes('&lt;img src=x onerror=alert\\(1\\)&gt;'))
  assert.ok(!markdown.includes('<img'))
  assert.ok(markdown.includes('UNKNOWN'))
  assert.ok(markdown.includes('CLAIMED\\_NOT\\_REPRODUCED'))
  assert.ok(markdown.includes('- [ ]'))
  assert.ok(!markdown.includes('Synthetic attack narrative'))
})
