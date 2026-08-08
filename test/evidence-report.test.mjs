import { test } from 'node:test'
import assert from 'node:assert/strict'
import { renderMarkdownReport, renderSarif } from '../scripts/lib/report.mjs'

function run(overrides = {}) {
  return {
    schema_version: '7.0.0',
    run_id: 'run-2026-08-08-aaaa',
    state: 'COMPLETE',
    phase: 'REPORT',
    created_at: '2026-08-08T14:00:00Z',
    capability_mode: 'STATIC',
    tool: { name: 'red-team-audit', version: '0.11.0', corpus_sha256: 'a'.repeat(64) },
    plan_digest: 'e'.repeat(64),
    policy_digest: 'f'.repeat(64),
    lens_pack_digest: 'a'.repeat(64),
    repository: { root: '/repo', tree_digest: 'b'.repeat(64), dirty: 'unknown' },
    scope: { included_paths: ['.'], excluded_paths: [] },
    activated_lenses: ['cloud-and-iac'],
    jobs: [],
    coverage: { inventory: [], examined: [], gaps: [], policy: {}, lenses: [], shards: [] },
    store_profiles: [],
    findings: [],
    errors: [],
    artifacts: {},
    attempt_events: [],
    evidence_bundles: [],
    evidence_coverage: {
      cells: [
        {
          lens: 'cloud-and-iac',
          topic: 'container-image-content',
          evidence_class: 'source',
          state: 'COVERED',
          reason: 'the repository under audit is the run evidence',
        },
        {
          lens: 'cloud-and-iac',
          topic: 'container-image-content',
          evidence_class: 'built-artifact',
          state: 'NOT_ASSESSED',
          reason: 'no built-artifact evidence was acquired for this run',
        },
      ],
      summary: {
        cell_count: 2,
        bundle_count: 0,
        unreached_class_count: 1,
        unreached_classes: ['built-artifact'],
        not_assessed_cell_count: 1,
        inventory_only_cell_count: 0,
      },
    },
    ...overrides,
  }
}

test('the report names every class the audit could not reach', () => {
  const report = renderMarkdownReport(run())
  assert.match(report, /### Evidence-class coverage/)
  assert.match(report, /built-artifact/)
  assert.match(report, /NOT_ASSESSED/)
  assert.match(report, /no built-artifact evidence was acquired for this run/)
})

test('an unreached class is stated as a blind spot, not omitted', () => {
  const report = renderMarkdownReport(run())
  const section = report.slice(report.indexOf('### Evidence-class coverage'))
  assert.match(
    section,
    /1 evidence class was not acquired[\s\S]*not a clearance/,
  )
})

test('a run with every class covered says so without the blind-spot notice', () => {
  const covered = run({
    evidence_bundles: [{
      evidence_id: 'peerstar-api-image',
      evidence_class: 'built-artifact',
      adapter_id: 'artifact',
      artifact_kind: 'oci-image',
      coverage_state: 'COVERED',
      root_sha256: 'c'.repeat(64),
    }],
    evidence_coverage: {
      cells: [{
        lens: 'cloud-and-iac',
        topic: 'container-image-content',
        evidence_class: 'built-artifact',
        state: 'COVERED',
        reason: 'peerstar-api-image (cccccccccccc)',
      }],
      summary: {
        cell_count: 1,
        bundle_count: 1,
        unreached_class_count: 0,
        unreached_classes: [],
        not_assessed_cell_count: 0,
        inventory_only_cell_count: 0,
      },
    },
  })
  const report = renderMarkdownReport(covered)
  assert.match(report, /peerstar-api-image/)
  assert.equal(/was not acquired/.test(report), false)
})

test('a precedence conflict is printed, never silently reconciled', () => {
  const conflicted = run({
    findings: [
      {
        candidate_id: 'container-image-content:aaaa1111',
        lens: 'cloud-and-iac',
        topic: 'container-image-content',
        title: 'Dockerfile removes the build secret',
        claimed_impact_severity: 'Info',
        effective_severity: 'Info',
        location: ['Dockerfile:14'],
      },
      {
        candidate_id: 'container-image-content:5c1a7f30',
        lens: 'cloud-and-iac',
        topic: 'container-image-content',
        title: 'Build secret is readable below the whiteout',
        claimed_impact_severity: 'High',
        effective_severity: 'High',
        location: ['peerstar-api-image:layer/02/secret.txt'],
        evidence_context: { evidence_class: 'built-artifact', evidence_id: 'peerstar-api-image' },
      },
    ],
  })
  const report = renderMarkdownReport(conflicted)
  assert.match(report, /Precedence conflicts/)
  assert.match(report, /container-image-content:5c1a7f30/)
  assert.match(report, /container-image-content:aaaa1111/)
  assert.match(report, /built-artifact/)
})

test('SARIF carries the unreached classes as notifications, not as results', () => {
  const sarif = renderSarif(run())
  const invocation = sarif.runs[0].invocations?.[0]
  const notifications = invocation?.toolExecutionNotifications ?? []
  assert.equal(notifications.length, 1)
  assert.equal(notifications[0].level, 'warning')
  assert.match(notifications[0].message.text, /built-artifact/)
  assert.match(notifications[0].message.text, /not a clearance/)
  assert.equal(sarif.runs[0].results.length, 0)
  // The existing invocation properties must survive the merge.
  assert.equal(typeof invocation.executionSuccessful, 'boolean')
  assert.ok(invocation.properties)
})

test('SARIF for a fully covered run raises no notification', () => {
  const covered = run({
    evidence_coverage: {
      cells: [],
      summary: {
        cell_count: 0,
        bundle_count: 1,
        unreached_class_count: 0,
        unreached_classes: [],
        not_assessed_cell_count: 0,
        inventory_only_cell_count: 0,
      },
    },
  })
  const notifications = renderSarif(covered).runs[0].invocations?.[0]?.toolExecutionNotifications ?? []
  assert.deepEqual(notifications, [])
})

test('a PHI-bearing bundle is named in the report without its contents', () => {
  const report = renderMarkdownReport(run({
    evidence_bundles: [{
      evidence_id: 'prod-cluster',
      evidence_class: 'deployed-state',
      adapter_id: 'deployed',
      coverage_state: 'COVERED',
      phi_bearing: true,
      root_sha256: 'd'.repeat(64),
    }],
  }))
  assert.match(report, /PHI-bearing/i)
  assert.match(report, /prod-cluster/)
  assert.match(report, /dddddddddddd/)
  assert.match(report, /contents are not reproduced/i)
})

test('a run with no PHI-bearing bundle raises no PHI notice', () => {
  assert.equal(/PHI-bearing/i.test(renderMarkdownReport(run())), false)
})

test('a run planned before this change still renders', () => {
  const legacy = run()
  delete legacy.evidence_coverage
  delete legacy.evidence_bundles
  assert.doesNotThrow(() => renderMarkdownReport(legacy))
})
