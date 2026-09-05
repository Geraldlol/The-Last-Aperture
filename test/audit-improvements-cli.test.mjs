import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { mkdtemp, mkdir, readFile, readdir, rename, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

const CLI = resolve('scripts/audit.mjs')
const SOURCE_SENTINEL = 'SYNTHETIC_SOURCE_BYTES_NOT_FOR_DIAGNOSTICS'
const PRIVATE_SENTINEL = 'SYNTHETIC_PRIVATE_PROVIDER_VALUE'

function invoke(args, options = {}) {
  const result = spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8', timeout: 30_000, maxBuffer: 8 * 1024 * 1024, ...options,
  })
  assert.equal(result.error, undefined)
  return result
}

function json(args, status = 0, options = {}) {
  const result = invoke(args, options)
  assert.equal(result.status, status, result.stderr || result.stdout)
  assert.equal(result.stderr, '')
  return JSON.parse(result.stdout)
}

async function digestTree(directory) {
  const result = {}
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    result[entry.name] = entry.isDirectory() ? await digestTree(path)
      : createHash('sha256').update(await readFile(path)).digest('hex')
  }
  return result
}

async function withBundle(callback) {
  const workspace = await mkdtemp(join(tmpdir(), 'rta-assessment-cli-'))
  const target = join(workspace, 'target')
  const output = join(workspace, 'output')
  try {
    await mkdir(target)
    await writeFile(join(target, 'app.js'), `export const fixture = '${SOURCE_SENTINEL}'\n`)
    await writeFile(join(target, 'package.json'), JSON.stringify({ name: 'synthetic-metadata-fixture', private: true }))
    await writeFile(join(target, 'pyproject.toml'), '[project]\nname = "synthetic-metadata-fixture"\n')
    const planned = invoke(['plan', target, '--out', output])
    assert.equal(planned.status, 0, planned.stderr)
    const directories = await readdir(output)
    assert.equal(directories.length, 1)
    await callback({ workspace, target, output, bundle: join(output, directories[0]) })
  } finally {
    await rm(workspace, { recursive: true, force: true })
  }
}

test('review handoff and result preflight share the ingestion contract without persisting work', async () => {
  await withBundle(async ({ bundle, output }) => {
    const next = json(['next', bundle])
    const job = next.pending_jobs.find((entry) => entry.kind === 'LENS')
    assert.ok(job)
    const before = await digestTree(bundle)
    const handoff = json(['review-template', bundle, '--job', job.job_id])
    assert.equal(handoff.analysis_status, 'NOT_PERFORMED')
    assert.equal(handoff.input.packet_sha256, job.packet_sha256)
    assert.equal(handoff.result_template.input_sha256, job.packet_sha256)
    assert.equal(handoff.result_template.state, null)
    assert.doesNotMatch(JSON.stringify(handoff), new RegExp(SOURCE_SENTINEL))
    const resultPath = join(output, 'review.json')
    await writeFile(resultPath, JSON.stringify(handoff.result_template))
    const placeholder = json(['check-result', bundle, resultPath, '--json'], 1)
    assert.equal(placeholder.valid, false)
    assert.equal(placeholder.applied, false)
    assert.equal(placeholder.error, 'RESULT_VALIDATION_FAILED')
    assert.deepEqual(await digestTree(bundle), before)

    // This declares only a synthetic contract check; topic review remains absent.
    const completed = {
      ...handoff.result_template,
      producer: { name: 'synthetic-test', version: '1', instance_id: 'synthetic-contract-check' },
      state: 'SUCCEEDED',
      examined_files: job.scoped_files,
    }
    await writeFile(resultPath, JSON.stringify(completed))
    const checked = json(['check-result', bundle, resultPath, '--json'])
    assert.equal(checked.valid, true)
    assert.equal(checked.applied, false)
    assert.equal(checked.semantic_authority, 'PROVIDER_DECLARED')
    assert.equal(checked.job_id, job.job_id)
    assert.deepEqual(await digestTree(bundle), before)
    const ingested = invoke(['ingest', bundle, resultPath])
    assert.equal(ingested.status, 0, ingested.stderr)
    const run = JSON.parse(await readFile(join(bundle, 'run.json'), 'utf8'))
    assert.equal(run.jobs.find((entry) => entry.job_id === job.job_id).state, 'SUCCEEDED')
    assert.notEqual(run.state, 'COMPLETE_CLEAN')
    const stale = invoke(['review-template', bundle, '--job', job.job_id])
    assert.equal(stale.status, 1)
    assert.match(stale.stderr, /pending source-review/)
  })
})

test('result preflight rejects malformed, out-of-scope and stale inputs without exposing content or writing', async () => {
  await withBundle(async ({ bundle, output, target }) => {
    const job = json(['next', bundle]).pending_jobs[0]
    const template = json(['review-template', bundle, '--job', job.job_id]).result_template
    const valid = {
      ...template,
      producer: { name: 'synthetic-test', version: '1', instance_id: 'synthetic-contract-check' },
      state: 'SUCCEEDED', examined_files: job.scoped_files,
    }
    const resultPath = join(output, 'review.json')
    const before = await digestTree(bundle)
    for (const content of [
      PRIVATE_SENTINEL,
      JSON.stringify({ ...valid, examined_files: [PRIVATE_SENTINEL] }),
      JSON.stringify({ ...valid, input_sha256: '0'.repeat(64) }),
    ]) {
      await writeFile(resultPath, content)
      const failure = json(['check-result', bundle, resultPath, '--json'], 1)
      assert.equal(failure.error, 'RESULT_VALIDATION_FAILED')
      assert.equal(failure.applied, false)
      assert.doesNotMatch(JSON.stringify(failure), /SYNTHETIC_PRIVATE|SYNTHETIC_/)
      const human = invoke(['check-result', bundle, resultPath])
      assert.equal(human.status, 1)
      assert.match(human.stdout, /RESULT_VALIDATION_FAILED/)
      assert.doesNotMatch(human.stdout + human.stderr, /SYNTHETIC_PRIVATE|SYNTHETIC_/)
      assert.deepEqual(await digestTree(bundle), before)
    }
    await writeFile(resultPath, JSON.stringify(valid))
    await writeFile(join(target, 'app.js'), 'export const fixture = "changed"\n')
    const stale = json(['check-result', bundle, resultPath, '--json'], 1)
    assert.equal(stale.error, 'SNAPSHOT_VALIDATION_FAILED')
    assert.equal(stale.applied, false)
    assert.deepEqual(await digestTree(bundle), before)
    const missing = json(['check-result', join(output, 'missing'), resultPath, '--json'], 1)
    assert.equal(missing.error, 'BUNDLE_VALIDATION_FAILED')
  })
})

test('saved-bundle diagnostics stay read-only and do not imply analysis, fixes, or runtime readiness', async () => {
  await withBundle(async ({ workspace, bundle, target }) => {
    const before = await digestTree(bundle)
    await rename(target, join(workspace, 'moved-target'))
    const verdict = json(['verdict', bundle, '--json'])
    assert.equal(verdict.semantic_verifier, 'NOT_AVAILABLE')
    assert.equal(verdict.bundle_integrity, 'VERIFIED')
    assert.equal(verdict.root_authenticity, 'UNANCHORED')
    assert.equal(verdict.findings_total, 0)
    const brief = json(['repair-brief', bundle, '--json'])
    assert.equal(brief.kind, 'REPAIR_RETEST_HANDOFF')
    assert.equal(brief.findings.total, 0)
    const baselineBrief = json(['repair-brief', bundle, '--baseline', bundle, '--json'])
    assert.equal(baselineBrief.findings.total, 0)
    const doctor = json(['doctor', '--bundle', bundle, '--json'])
    assert.equal(doctor.assessment, 'STATIC_ONLY')
    assert.equal(doctor.environment_coverage.basis, 'RECORDED_FILENAMES_ONLY')
    assert.equal(doctor.environment_coverage.deployment_evidence, 'NOT_ASSESSED')
    assert.equal(doctor.environment_coverage.detected_profiles.find((profile) => profile.profile_id === 'python').execution_support, 'UNAVAILABLE')
    assert.ok(doctor.workflows.every((workflow) => workflow.status !== 'READY'))
    assert.doesNotMatch(JSON.stringify([verdict, brief, doctor]), new RegExp(SOURCE_SENTINEL))
    assert.deepEqual(await digestTree(bundle), before)
    const human = invoke(['doctor', '--bundle', bundle])
    assert.equal(human.status, 0, human.stderr)
    assert.match(human.stdout, /RECORDED_FILENAMES_ONLY/)
    for (const command of ['verdict', 'repair-brief']) {
      const unknown = invoke([command, bundle, '--candidate', 'missing-candidate'])
      assert.equal(unknown.status, 1)
      assert.match(unknown.stderr, /candidate.*not.*found|unknown candidate/i)
    }
  })
})

test('capability registry and diagnostic argument handling expose only supported command shapes', () => {
  const capabilities = json(['capabilities', '--json'])
  assert.equal(capabilities.capabilities.find((item) => item.id === 'semantic-oracle').status, 'UNAVAILABLE')
  assert.equal(capabilities.capabilities.find((item) => item.id === 'review-integration').status, 'AVAILABLE')
  for (const args of [
    ['capabilities', 'unexpected'], ['doctor', '--unknown'], ['verdict'],
    ['review-template', 'missing'], ['check-result', 'missing'],
    ['repair-brief', 'missing', '--json', '--json'],
  ]) {
    const failure = invoke(args)
    assert.equal(failure.status, 1)
    assert.doesNotMatch(failure.stderr, /ENOENT/)
  }
})
