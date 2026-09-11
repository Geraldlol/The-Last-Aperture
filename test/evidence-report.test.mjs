import { test } from 'node:test'
import assert from 'node:assert/strict'
import { renderMarkdownReport, renderSarif } from '../scripts/lib/report.mjs'

function run(overrides = {}) {
  return {
    schema_version: '7.0.0',
    run_id: 'run-2026-08-08-aaaa',
    state: 'COMPLETED',
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

test('an acquired class with bounded coverage avoids the not-acquired notice', () => {
  const covered = run({
    evidence_bundles: [{
      evidence_id: 'sample-api-image',
      evidence_class: 'built-artifact',
      adapter_id: 'artifact',
      artifact_kind: 'oci-image',
      coverage_state: 'COVERED',
      root_sha256: 'c'.repeat(64),
    }],
    evidence_coverage: {
      bundle_coverage: [{
        evidence_id: 'sample-api-image',
        evidence_class: 'built-artifact',
        artifact_kind: 'oci-image',
        root_sha256: 'c'.repeat(64),
        state: 'PARTIAL',
        consumer_lenses: ['cloud-and-iac'],
        reason: 'controller OCI analysis is positive-only, not exhaustive',
      }],
      cells: [{
        lens: 'cloud-and-iac',
        topic: 'container-image-content',
        evidence_class: 'built-artifact',
        state: 'PARTIAL',
        reason: 'sample-api-image (cccccccccccc)',
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
  assert.match(report, /sample-api-image/)
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
        location: ['sample-api-image:layer/02/secret.txt'],
        evidence_context: { evidence_class: 'built-artifact', evidence_id: 'sample-api-image' },
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
        bundle_count: 0,
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

test('SARIF preserves evidence locators literally when source-path URIs need encoding', () => {
  const locator = 'sample-api-image:layer/naïve#part%20?.txt:42'
  const evidenceContext = {
    evidence_id: 'sample-api-image', evidence_class: 'built-artifact',
    adapter_id: 'artifact', target_identity: 'sha256:' + 'a'.repeat(64),
  }
  const sarif = renderSarif(run({ findings: [{
    candidate_id: 'container-image-content:locator', lens: 'cloud-and-iac',
    topic: 'container-image-content', title: 'Artifact content requires review',
    claimed_impact_severity: 'Medium', location: [locator],
    impact: 'The artifact contains unexpected content.',
    evidence_context: evidenceContext,
  }] }))
  const result = sarif.runs[0].results[0]
  assert.deepEqual(result.locations, [])
  assert.deepEqual(result.properties.evidence_locations, [{
    evidence_id: 'sample-api-image', locator: 'layer/naïve#part%20?.txt:42',
  }])
  assert.deepEqual(result.properties.evidence_context, evidenceContext)
})

test('unconsumed acquired bundles are explicit in Markdown and SARIF', () => {
  const uncovered = run({
    state: 'COMPLETE_WITH_GAPS',
    evidence_bundles: [{
      evidence_id: 'portable-model',
      evidence_class: 'built-artifact',
      adapter_id: 'artifact',
      artifact_kind: 'model-bundle',
      coverage_state: 'COVERED',
      root_sha256: 'd'.repeat(64),
    }],
    evidence_coverage: {
      cells: [],
      bundle_coverage: [{
        evidence_id: 'portable-model',
        evidence_class: 'built-artifact',
        artifact_kind: 'model-bundle',
        root_sha256: 'd'.repeat(64),
        state: 'INVENTORY_ONLY',
        consumer_lenses: [],
        reason: 'model-bundle was acquired; no lens declares it consumed',
      }],
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

  const markdown = renderMarkdownReport(uncovered)
  assert.match(markdown, /Acquired bundle coverage/)
  assert.match(markdown, /portable-model.*model-bundle.*INVENTORY_ONLY/s)
  assert.match(markdown, /no lens declares it consumed/)

  const invocation = renderSarif(uncovered).runs[0].invocations[0]
  const notifications = invocation.toolExecutionNotifications ?? []
  assert.ok(notifications.some(({ descriptor, message }) =>
    descriptor.id === 'evidence-bundle-not-assessed/portable-model'
    && /no lens declares it consumed/i.test(message.text)))
  assert.equal(invocation.properties.evidence_bundle_count, 1)
  assert.equal(invocation.properties.evidence_bundle_gap_count, 1)
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

test('NOT_APPLICABLE cells are counted, not printed as hundreds of rows', () => {
  const noisy = run({
    evidence_coverage: {
      cells: [
        ...Array.from({ length: 200 }, (_unused, index) => ({
          lens: 'llm-and-ai',
          topic: `topic-${index}`,
          evidence_class: 'built-artifact',
          state: 'NOT_APPLICABLE',
          reason: 'llm-and-ai did not activate in this run',
        })),
        {
          lens: 'cloud-and-iac',
          topic: 'container-image-content',
          evidence_class: 'built-artifact',
          state: 'NOT_ASSESSED',
          reason: 'no built-artifact evidence was acquired for this run',
        },
      ],
      summary: {
        cell_count: 201,
        bundle_count: 0,
        unreached_class_count: 1,
        unreached_classes: ['built-artifact'],
        not_assessed_cell_count: 1,
        inventory_only_cell_count: 0,
      },
    },
  })
  const report = renderMarkdownReport(noisy)
  const section = report.slice(report.indexOf('### Evidence-class coverage'))
  const rows = section.split('\n').filter((line) => line.startsWith('| '))
  // One header plus one actionable row (the |--- separator does not match).
  // The 200 inapplicable cells are a sentence, not 200 rows burying it.
  assert.equal(rows.length, 2)
  assert.match(section, /200 further lens\/topic\/class cells are NOT_APPLICABLE/)
  assert.match(section, /no built-artifact evidence was acquired/)
})

test('a fully inapplicable matrix prints no table at all', () => {
  const report = renderMarkdownReport(run({
    evidence_coverage: {
      cells: [{
        lens: 'llm-and-ai',
        topic: 't',
        evidence_class: 'built-artifact',
        state: 'NOT_APPLICABLE',
        reason: 'llm-and-ai did not activate in this run',
      }],
      summary: {
        cell_count: 1,
        bundle_count: 0,
        unreached_class_count: 0,
        unreached_classes: [],
        not_assessed_cell_count: 0,
        inventory_only_cell_count: 0,
      },
    },
  }))
  const section = report.slice(report.indexOf('### Evidence-class coverage'))
  assert.equal(section.split('\n').filter((line) => line.startsWith('| ')).length, 0)
  assert.match(section, /1 further lens\/topic\/class cell is NOT_APPLICABLE/)
})
