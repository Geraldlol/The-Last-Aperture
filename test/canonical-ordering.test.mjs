import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { stableJson } from '../scripts/lib/run-engine.mjs'
import { compareRuns, coverageSupportsResolution } from '../scripts/lib/lifecycle.mjs'
import { bindBenchmarkPrimaryRun } from '../scripts/lib/benchmark-contracts.mjs'
import { serializeSealedSnapshotIndex } from '../scripts/lib/sealed-snapshot.mjs'

const localeOrder = (keys) => [...keys].sort((left, right) => left.localeCompare(right, 'en'))
const codeUnitOrder = (keys) => [...keys].sort((left, right) => (left < right ? -1 : left > right ? 1 : 0))

function keysOf(json) {
  return [...json.matchAll(/"([^"]*)":/g)].map((match) => match[1])
}

test('canonical serialization orders keys by UTF-16 code unit, not locale collation', () => {
  const value = { apple: 1, Zebra: 2, _under: 3, $dollar: 4, Apple: 5 }
  assert.deepEqual(
    keysOf(stableJson(value, 0)),
    ['$dollar', 'Apple', 'Zebra', '_under', 'apple'],
  )
  // The same key set under locale collation produces a different order, which is
  // exactly the ICU-build dependency this ordering removes.
  assert.notDeepEqual(
    localeOrder(Object.keys(value)),
    codeUnitOrder(Object.keys(value)),
  )
})

test('canonical serialization depends on content alone, never on insertion order', () => {
  const forward = { alpha: 1, beta: { gamma: 2, delta: [3, { epsilon: 4, digamma: 5 }] } }
  const reversed = { beta: { delta: [3, { digamma: 5, epsilon: 4 }], gamma: 2 }, alpha: 1 }
  assert.equal(stableJson(forward), stableJson(reversed))
})

test('keys that locale collation calls equal still order deterministically', () => {
  // localeCompare returns 0 for these pairs, so a stable sort previously left
  // canonical bytes decided by object insertion order rather than by content.
  for (const [left, right] of [['a‍b', 'ab'], ['a­b', 'ab'], ['ab', 'a︀b']]) {
    assert.equal(left.localeCompare(right, 'en'), 0)
    assert.equal(
      stableJson({ [left]: 1, [right]: 2 }, 0),
      stableJson({ [right]: 2, [left]: 1 }, 0),
    )
  }
})

test('run-engine and sealed-snapshot agree on one canonical ordering', () => {
  const index = { zeta: 1, Alpha: 2, _shard: 3, files: [{ size: 1, path: 'a', availability: 'AVAILABLE' }] }
  assert.equal(stableJson(index), serializeSealedSnapshotIndex(index))
})

test('lifecycle finding digests ignore key insertion order', () => {
  const base = {
    candidate_id: 'cand:web:001',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Tenant object is loaded without an ownership check',
    location: ['src/orders.js:42'],
    evidence: 'return Orders.findById(req.params.id)',
    reachable_from: 'GET /orders/:id',
    claimed_impact_severity: 'High',
  }
  const permuted = Object.fromEntries([...Object.entries(base)].reverse())
  const run = (findings, runId) => ({
    run_id: runId,
    state: 'COMPLETED',
    repository: { root: '/repo' },
    lens_pack_digest: 'a'.repeat(64),
    policy_digest: 'b'.repeat(64),
    jobs: [{
      job_id: 'lens:web-and-api',
      kind: 'LENS',
      lens: 'web-and-api',
      state: 'SUCCEEDED',
      coverage_authority: 'PROVIDER_DECLARED',
    }],
    coverage: { inventory: [], examined: [], unexamined: [], lenses: [], gaps: [] },
    findings,
  })
  const comparison = compareRuns(run([base], 'run:a'), run([permuted], 'run:b'))
  assert.equal(comparison.counts.unchanged, 1)
  assert.equal(comparison.counts.updated, 0)
  assert.equal(comparison.counts.new, 0)
})

test('benchmark normalized finding sets ignore key insertion order', () => {
  const finding = { case_id: 'V-001', candidate_id: 'candidate:first', topic: 'authz-object-level' }
  const permuted = Object.fromEntries([...Object.entries(finding)].reverse())
  const digestOf = (findings) => bindBenchmarkPrimaryRun(
    'repeat:primary',
    findings,
    [{ run_id: 'repeat:primary', findings }],
  ).normalized_finding_set_sha256
  assert.equal(digestOf([finding]), digestOf([permuted]))
})

test('a directory gap is attributable even when a case-variant sibling exists', () => {
  // The known-path lookup lower-bounds `SRC/` in a sorted path list. Locale
  // collation ranks case below the separator, so `src/x.js` sorts ahead of
  // `SRC/x.js` and the bound lands on a non-match: the gap is then read as
  // unattributable and vetoes a resolution the coverage does support.
  const paths = ['app/main.js', 'src/x.js', 'SRC/x.js']
  assert.deepEqual(localeOrder(paths), ['app/main.js', 'src/x.js', 'SRC/x.js'])
  assert.deepEqual(codeUnitOrder(paths), ['SRC/x.js', 'app/main.js', 'src/x.js'])

  const run = {
    run_id: 'run:a',
    state: 'COMPLETE_WITH_GAPS',
    jobs: [{ job_id: 'lens:web-and-api', kind: 'LENS', lens: 'web-and-api', state: 'SUCCEEDED' }],
    coverage: {
      inventory: paths,
      examined: paths,
      unexamined: [],
      lenses: [{ lens: 'web-and-api', status: 'RAN', examined_paths: paths }],
      gaps: [{ gap_id: 'gap:1', area: 'SRC', reason: 'not scanned' }],
      resolved_gap_ids: [],
    },
    findings: [],
  }
  const finding = { candidate_id: 'cand:1', lens: 'web-and-api', location: ['app/main.js:1'] }
  assert.equal(coverageSupportsResolution(run, finding), true)
})

test('only the rendering module may order by locale collation', () => {
  // Collation is an ICU-build and host-locale dependency. It is fine for text a
  // human reads and wrong for anything that is hashed, signed, or binary
  // searched, so it is confined to report rendering. canonical-order.mjs names
  // it only to forbid it.
  const allowed = new Set(['scripts/lib/report.mjs', 'scripts/lib/canonical-order.mjs'])
  const offenders = []
  const walk = (directory) => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = `${directory}/${entry.name}`
      if (entry.isDirectory()) {
        if (entry.name !== 'node_modules') walk(path)
      } else if (entry.name.endsWith('.mjs') && !allowed.has(path)) {
        if (readFileSync(path, 'utf8').includes('localeCompare')) offenders.push(path)
      }
    }
  }
  walk('scripts')
  walk('providers')
  assert.deepEqual(
    offenders,
    [],
    'these modules order by locale collation; use compareCanonicalStrings instead',
  )
})

test('no shipped schema reorders under code-unit key ordering', () => {
  // The canonical-order change is only byte-neutral while every declared key set
  // sorts identically both ways. This asserts that invariant instead of assuming it.
  const directory = 'schemas'
  let compared = 0
  for (const file of readdirSync(directory).filter((name) => name.endsWith('.json'))) {
    const schema = JSON.parse(readFileSync(join(directory, file), 'utf8'))
    const bags = []
    const collect = (node) => {
      if (Array.isArray(node)) {
        node.forEach(collect)
        return
      }
      if (node === null || typeof node !== 'object') return
      bags.push(Object.keys(node))
      for (const field of ['properties', '$defs', 'definitions', 'patternProperties']) {
        const bag = node[field]
        if (bag && typeof bag === 'object' && !Array.isArray(bag)) bags.push(Object.keys(bag))
      }
      for (const child of Object.values(node)) collect(child)
    }
    collect(schema)
    for (const keys of bags) {
      compared += 1
      assert.deepEqual(
        localeOrder(keys),
        codeUnitOrder(keys),
        `${file}: key set reorders between locale collation and code-unit ordering`,
      )
    }
  }
  assert.ok(compared > 100, `expected a meaningful schema key population, compared ${compared}`)
})
