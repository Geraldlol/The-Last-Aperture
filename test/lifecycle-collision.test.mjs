import { test } from 'node:test'
import assert from 'node:assert/strict'
import { compareRuns } from '../scripts/lib/lifecycle.mjs'

function finding(candidateId, title) {
  return {
    candidate_id: candidateId,
    fingerprint: 'explicit:shared',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    location: ['src/orders.js:42'],
    title,
    effective_severity: 'High',
  }
}

function run(runId, findings, overrides = {}) {
  return {
    run_id: runId,
    state: 'COMPLETED',
    repository: { root: 'C:\\repo' },
    lens_pack_digest: 'a'.repeat(64),
    policy_digest: 'b'.repeat(64),
    findings,
    coverage: {
      inventory: ['src/orders.js'],
      examined: ['src/orders.js'],
      unexamined: [],
      lenses: [{
        lens: 'web-and-api',
        status: 'RAN',
        examined_paths: ['src/orders.js'],
      }],
      gaps: [],
    },
    jobs: [{
      kind: 'LENS',
      lens: 'web-and-api',
      state: 'SUCCEEDED',
      coverage_authority: 'PROVIDER_DECLARED',
    }],
    ...overrides,
  }
}

test('colliding changed findings cannot consume a later exact baseline match', () => {
  const comparison = compareRuns(
    run('baseline', [finding('a', 'Preserved'), finding('b', 'Old changed')]),
    run('current', [finding('a', 'New changed'), finding('z', 'Preserved')]),
  )

  assert.equal(comparison.counts.unchanged, 1)
  assert.equal(comparison.counts.updated, 1)
  const preserved = comparison.results.find(({ candidate_id: id }) => id === 'z')
  assert.equal(preserved.state, 'unchanged')
  assert.equal(preserved.baseline_finding.title, 'Preserved')
  const changed = comparison.results.find(({ candidate_id: id }) => id === 'a')
  assert.equal(changed.baseline_finding.title, 'Old changed')
})

test('exact collision matching survives reordered input and regenerated candidate identifiers', () => {
  for (const [changedId, preservedId] of [['a', 'z'], ['z', 'a']]) {
    const baselineFindings = [finding('a', 'Preserved'), finding('b', 'Old changed')]
    const currentFindings = [finding(changedId, 'New changed'), finding(preservedId, 'Preserved')]
    const forward = compareRuns(run('baseline', baselineFindings), run('current', currentFindings))
    const reversed = compareRuns(
      run('baseline', [...baselineFindings].reverse()),
      run('current', [...currentFindings].reverse()),
    )

    assert.deepEqual(reversed, forward)
    assert.equal(forward.counts.unchanged, 1)
    assert.equal(forward.counts.updated, 1)
    assert.equal(
      forward.results.find(({ finding: entry }) => entry?.title === 'Preserved').state,
      'unchanged',
    )
  }
})

test('surplus colliding findings remain new after exact matches are reserved', () => {
  const comparison = compareRuns(
    run('baseline', [finding('a', 'Preserved')]),
    run('current', [finding('a', 'New occurrence'), finding('z', 'Preserved')]),
  )

  assert.equal(comparison.counts.new, 1)
  assert.equal(comparison.counts.unchanged, 1)
  assert.equal(comparison.counts.updated, 0)
  assert.equal(comparison.results.find(({ state }) => state === 'new').finding.title, 'New occurrence')
})

test('exact matching preserves duplicate digest multiplicity within a collision', () => {
  const comparison = compareRuns(
    run('baseline', [
      finding('a', 'Preserved'),
      finding('b', 'Preserved'),
      finding('c', 'Old changed'),
    ]),
    run('current', [
      finding('a', 'New changed'),
      finding('y', 'Preserved'),
      finding('z', 'Preserved'),
    ]),
  )

  assert.equal(comparison.counts.unchanged, 2)
  assert.equal(comparison.counts.updated, 1)
  assert.equal(comparison.results.length, 3)
  assert.equal(new Set(comparison.results.map(({ baseline_finding: entry }) => entry.candidate_id)).size, 3)
})

test('unmatched collision members keep existing coverage-qualified absence semantics', () => {
  const baseline = run('baseline', [
    finding('a', 'Preserved'),
    finding('b', 'Old changed'),
    finding('c', 'Absent'),
  ])
  const currentFindings = [finding('a', 'New changed'), finding('z', 'Preserved')]
  for (const [overrides, absentState] of [
    [{}, 'claimed-fixed'],
    [{ state: 'INCOMPLETE' }, 'not-observed'],
  ]) {
    const comparison = compareRuns(baseline, run('current', currentFindings, overrides))
    const absent = comparison.results.find(({ finding: entry }) => entry === null)

    assert.equal(comparison.counts.unchanged, 1)
    assert.equal(comparison.counts.updated, 1)
    assert.equal(comparison.counts.fixed, 0)
    assert.equal(absent.state, absentState)
    assert.equal(absent.baseline_finding.title, 'Absent')
    assert.equal(comparison.results.length, 3)
  }
})

test('collision matching agrees with a multiset oracle across bounded finding permutations', () => {
  const titles = ['A', 'B', 'C']
  const sequences = [[]]
  let frontier = [[]]
  for (let length = 1; length <= 3; length += 1) {
    frontier = frontier.flatMap((sequence) => titles.map((title) => [...sequence, title]))
    sequences.push(...frontier)
  }

  for (const before of sequences) {
    for (const after of sequences) {
      const unchanged = titles.reduce((count, title) => count + Math.min(
        before.filter((value) => value === title).length,
        after.filter((value) => value === title).length,
      ), 0)
      const updated = Math.min(before.length, after.length) - unchanged
      const comparison = compareRuns(
        run('baseline', before.map((title, index) => finding(`baseline:${index}`, title))),
        run('current', after.map((title, index) => finding(`current:${index}`, title))),
      )

      assert.deepEqual(comparison.counts, {
        new: after.length - unchanged - updated,
        updated,
        unchanged,
        'claimed-fixed': before.length - unchanged - updated,
        fixed: 0,
        'not-observed': 0,
      }, JSON.stringify({ before, after }))
    }
  }
})
