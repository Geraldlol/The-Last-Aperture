import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  buildActivationPlan,
  lensSharedContractDigest,
} from '../scripts/lib/activation.mjs'

function lens(name, frontmatter = {}) {
  return {
    name,
    file: `${name}.md`,
    digest: 'a'.repeat(64),
    frontmatter: {
      name,
      runs_in: 'fanout',
      activates_on: { paths: [], signals: [] },
      owns: [],
      ...frontmatter,
    },
  }
}

function inventory(entries) {
  return {
    entries: entries.map((entry) => ({ examined: true, ...entry })),
    errors: [],
    excluded: [],
  }
}

test('fanout scope includes bounded dependencies and dependents of direct matches', () => {
  const plan = buildActivationPlan([
    lens('web', {
      activates_on: { paths: ['src/routes/**'], signals: [] },
      owns: ['web-topic'],
    }),
  ], inventory([
    { path: 'src/routes/orders.ts', kind: 'text', content: "import '../services/orders.js'\n" },
    { path: 'src/services/orders.ts', kind: 'text', content: "import '../security/tenant.js'\n" },
    { path: 'src/security/tenant.ts', kind: 'text', content: 'export const tenant = true\n' },
    { path: 'src/unrelated.ts', kind: 'text', content: 'export const unrelated = true\n' },
  ]))

  const job = plan.jobs.find(({ lens: name }) => name === 'web')
  assert.deepEqual(job.scoped_files, [
    'src/routes/orders.ts',
    'src/security/tenant.ts',
    'src/services/orders.ts',
  ])
  assert.deepEqual(
    job.matches.find(({ path }) => path === 'src/security/tenant.ts').scope_expansion,
    {
      direction: 'dependency',
      depth: 2,
      from_path: 'src/services/orders.ts',
    },
  )
  assert.ok(!job.scoped_files.includes('src/unrelated.ts'))
})

test('business-logic receives the active fanout source scope while other triage stays finding-only', () => {
  const plan = buildActivationPlan([
    lens('web', {
      activates_on: { paths: ['src/routes/**'], signals: [] },
      owns: ['web-topic'],
    }),
    lens('ai-generated-code', { always_active: true }),
    lens('business-logic', { runs_in: 'triage' }),
    lens('attack-chaining', { runs_in: 'triage' }),
  ], inventory([
    { path: 'src/routes/orders.ts', kind: 'text', content: "import '../services/orders.js'\n" },
    { path: 'src/services/orders.ts', kind: 'text', content: 'export const total = 1\n' },
    { path: 'docs/notes.md', kind: 'text', content: '# unrelated\n' },
  ]))

  assert.deepEqual(
    plan.jobs.find(({ lens: name }) => name === 'business-logic').scoped_files,
    ['src/routes/orders.ts', 'src/services/orders.ts'],
  )
  assert.deepEqual(
    plan.jobs.find(({ lens: name }) => name === 'attack-chaining').scoped_files,
    [],
  )
})

test('business-logic source delivery is bounded and records omitted domain scope', () => {
  const plan = buildActivationPlan([
    lens('web', {
      activates_on: { paths: ['src/**'], signals: [] },
      owns: ['web-topic'],
    }),
    lens('business-logic', { runs_in: 'triage' }),
  ], inventory([
    { path: 'src/a.js', kind: 'text', content: '' },
    { path: 'src/b.js', kind: 'text', content: '' },
    { path: 'src/c.js', kind: 'text', content: '' },
  ]), { shardPolicy: { maxFiles: 2, maxBytes: 1024 } })

  const job = plan.jobs.find(({ lens: name }) => name === 'business-logic')
  assert.deepEqual(job.scoped_files, ['src/a.js', 'src/b.js'])
  assert.deepEqual(job.triage_source_scope, {
    total_files: 3,
    max_files: 2,
    truncated: true,
  })
})

test('shared contract digest ignores additive topic registry drift but binds shared rules', () => {
  const pack = {
    files: [
      { path: '_schema.md', sha256: '1'.repeat(64), size: 10 },
      { path: '_topics.md', sha256: '2'.repeat(64), size: 20 },
      { path: 'web-and-api.md', sha256: '3'.repeat(64), size: 30 },
    ],
  }
  const initial = lensSharedContractDigest(pack)
  const additiveTopics = structuredClone(pack)
  additiveTopics.files[1] = { path: '_topics.md', sha256: '4'.repeat(64), size: 40 }
  assert.equal(lensSharedContractDigest(additiveTopics), initial)

  const changedRules = structuredClone(pack)
  changedRules.files[0] = { path: '_schema.md', sha256: '5'.repeat(64), size: 10 }
  assert.notEqual(lensSharedContractDigest(changedRules), initial)
})
