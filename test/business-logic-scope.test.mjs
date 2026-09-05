import assert from 'node:assert/strict'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { createRunPlan } from '../scripts/lib/run-engine.mjs'

test('run planning bounds business-logic domain source and records truncation', async () => {
  const repository = await mkdtemp(join(tmpdir(), 'rta-business-scope-'))
  try {
    const routes = join(repository, 'src', 'routes')
    await mkdir(routes, { recursive: true })
    await Promise.all(['a.js', 'b.js', 'c.js'].map((file) =>
      writeFile(join(routes, file), 'export const handler = true\n')))

    const plan = await createRunPlan({
      targetRoot: repository,
      createdAt: new Date('2026-09-04T12:00:00.000Z'),
      maxClosureRounds: 0,
      shardOptions: { maxFiles: 2, maxBytes: 1024 * 1024 },
    })
    const sidecar = plan.jobSidecars.find(({ lens }) => lens === 'business-logic')

    assert.deepEqual(sidecar.scoped_files, [
      'src/routes/a.js',
      'src/routes/b.js',
    ])
    assert.deepEqual(
      plan.run.coverage.gaps.filter(({ area }) => area === 'lens:business-logic'),
      [{
        area: 'lens:business-logic',
        reason: 'bounded triage source scope truncated at 2 of 3 domain files',
      }],
    )
  } finally {
    await rm(repository, { recursive: true, force: true })
  }
})
