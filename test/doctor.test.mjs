import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'node:fs/promises'
import { join, dirname, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { execFileSync } from 'node:child_process'
import { inspectReadiness, renderReadiness, controllerRuntimePaths, READINESS_INPUT_LIMITS } from '../scripts/lib/doctor.mjs'
import { assessEnvironmentCoverage } from '../scripts/lib/capabilities.mjs'

const schemaSource = new URL('../schemas/proof-worker.schema.json', import.meta.url)
const runtime = controllerRuntimePaths()

function worker(overrides = {}) {
  return {
    schema_version: '1.0.0', protocol: 'docker-proof-v1', runtime_path: runtime.docker,
    image: `sha256:${'a'.repeat(64)}`, dependency_manifest_sha256: 'b'.repeat(64),
    limits: { wall_time_ms: 1000, docker_command_timeout_ms: 1000, max_source_bytes: 1024,
      max_output_bytes: 1024, memory_bytes: 67108864, cpus: 1, pids: 8, nofile: 16, tmpfs_bytes: 1048576 },
    ...overrides,
  }
}

async function fixture(t) {
  const root = await fs.mkdtemp(join(tmpdir(), 'rta-doctor-'))
  t.after(() => fs.rm(root, { recursive: true, force: true }))
  const files = {
    'package.json': JSON.stringify({ name: 'last-aperture', dependencies: { acorn: '8.15.0' } }),
    'package-lock.json': '{}',
    'scripts/audit.mjs': 'throw new Error("controller must not execute during doctor")',
    'skills/last-aperture/SKILL.md': '# fixture',
    'schemas/proof-worker.schema.json': await fs.readFile(schemaSource, 'utf8'),
    'node_modules/acorn/package.json': JSON.stringify({ name: 'acorn', version: '8.15.0' }),
    'node_modules/acorn/index.js': 'throw new Error("dependency must not execute during doctor")',
    'worker.json': JSON.stringify(worker()),
    'credential-secret.txt': 'DO_NOT_READ_SECRET_MARKER',
  }
  for (const [name, content] of Object.entries(files)) {
    await fs.mkdir(dirname(join(root, name)), { recursive: true })
    await fs.writeFile(join(root, name), content)
  }
  return root
}

async function fakeRuntimes(root, overrides = {}) {
  const fileStat = await fs.lstat(join(root, 'worker.json'))
  const dirStat = await fs.lstat(root)
  return {
    ...fs,
    lstat: async (path) => {
      if (path === runtime.docker || path === runtime.archive) return fileStat
      if ([runtime.docker, runtime.archive].some((endpoint) => endpoint.startsWith(`${path}\\`) || endpoint.startsWith(`${path}/`))) return dirStat
      return fs.lstat(path)
    },
    realpath: async (path) => path === runtime.docker || path === runtime.archive ? path : fs.realpath(path),
    ...overrides,
  }
}

function find(report, id) { return report.checks.find((item) => item.id === id) }

test('doctor checks static prerequisites but never equates file presence with runtime readiness', async (t) => {
  const root = await fixture(t)
  const opened = []
  const fileSystem = await fakeRuntimes(root, {
    open: async (path, flags) => { opened.push(path); return fs.open(path, flags) },
  })
  const report = await inspectReadiness({ projectRoot: root, workerConfigPath: join(root, 'worker.json'), nodeVersion: 'v20.0.0', fileSystem })
  assert.equal(report.assessment, 'STATIC_ONLY')
  assert.equal(find(report, 'node-runtime').status, 'PASS')
  assert.equal(find(report, 'proof-worker-config').status, 'PASS')
  assert.equal(find(report, 'docker-executable').status, 'PASS')
  for (const id of ['docker-daemon', 'worker-image', 'runtime-identity', 'target-compatibility']) assert.equal(find(report, id).status, 'NOT_CHECKED')
  assert.equal(report.workflows.find((item) => item.id === 't2-service-proof').status, 'STATIC_CHECKS_PASSED')
  assert.deepEqual(report.workflows.find((item) => item.id === 't2-service-proof').unchecked_checks, ['docker-daemon', 'runtime-identity', 'worker-image', 'target-compatibility'])
  assert.ok(!opened.some((path) => path.endsWith('credential-secret.txt') || path.endsWith('index.js') || path.endsWith('audit.mjs') || path === runtime.docker))
  assert.doesNotMatch(JSON.stringify(report), /DO_NOT_READ_SECRET_MARKER|sha256:a{64}/)
  assert.match(renderReadiness(report), /runtime checks still pending/)
})

test('missing dependency metadata and worker config produce actionable blockers without failing inspection', async (t) => {
  const root = await fixture(t)
  await fs.unlink(join(root, 'node_modules/acorn/package.json'))
  const report = await inspectReadiness({ projectRoot: root, nodeVersion: 'v19.9.0', fileSystem: await fakeRuntimes(root) })
  assert.equal(find(report, 'node-runtime').status, 'BLOCKED')
  assert.equal(find(report, 'dependency:acorn').status, 'BLOCKED')
  assert.match(find(report, 'dependency:acorn').action, /lockfile/)
  assert.equal(find(report, 'proof-worker-config').status, 'NOT_CONFIGURED')
  assert.equal(report.workflows[0].status, 'PREREQUISITES_MISSING')
  assert.equal(find(report, 'docker-daemon').status, 'NOT_CHECKED')
})

test('worker config validation rejects malformed values, unknown fields, wrong runtime, and missing resource bounds without exposing contents', async (t) => {
  const root = await fixture(t)
  const fileSystem = await fakeRuntimes(root)
  for (const changed of [
    worker({ image: 'mutable:latest' }), worker({ runtime_path: 'DO_NOT_READ_SECRET_MARKER' }),
    worker({ credentials: 'DO_NOT_READ_SECRET_MARKER' }), worker({ limits: {} }),
    worker({ limits: { ...worker().limits, cpus: 100 } }),
    worker({ limits: { ...worker().limits, max_source_bytes: 1048577 } }),
    worker({ limits: { ...worker().limits, pids: '8' } }),
  ]) {
    await fs.writeFile(join(root, 'worker.json'), JSON.stringify(changed))
    const report = await inspectReadiness({ projectRoot: root, workerConfigPath: join(root, 'worker.json'), fileSystem })
    assert.equal(find(report, 'proof-worker-config').status, 'BLOCKED')
    assert.doesNotMatch(JSON.stringify(report), /DO_NOT_READ_SECRET_MARKER|mutable:latest/)
  }
})

test('unknown future worker-schema constraints cannot be silently treated as validated', async (t) => {
  const root = await fixture(t)
  const schema = JSON.parse(await fs.readFile(schemaSource, 'utf8'))
  schema.properties.image.enum = ['some-future-required-shape']
  await fs.writeFile(join(root, 'schemas/proof-worker.schema.json'), JSON.stringify(schema))
  const report = await inspectReadiness({ projectRoot: root, workerConfigPath: join(root, 'worker.json'), fileSystem: await fakeRuntimes(root) })
  assert.equal(find(report, 'proof-worker-config').status, 'BLOCKED')
})

test('doctor rejects remote and relative operator endpoints before filesystem access', async () => {
  let reads = 0
  const fileSystem = { lstat: async () => { reads += 1; throw new Error('must not touch filesystem') } }
  for (const projectRoot of ['relative/path', '\\\\server\\share', '//server/share', '\\\\?\\C:\\path', 'bad\0path']) {
    await assert.rejects(inspectReadiness({ projectRoot, fileSystem }), /local filesystem|absolute/)
  }
  await assert.rejects(inspectReadiness({ projectRoot: resolve('.'), workerConfigPath: '\\\\server\\share\\secret.json', fileSystem }), /local filesystem/)
  assert.equal(reads, 0)
})

test('oversized worker config is rejected before opening it', async (t) => {
  const root = await fixture(t)
  await fs.writeFile(join(root, 'worker.json'), ' '.repeat(READINESS_INPUT_LIMITS.worker_bytes + 1))
  const opened = []
  const fileSystem = await fakeRuntimes(root, { open: async (path, flags) => { opened.push(path); return fs.open(path, flags) } })
  const report = await inspectReadiness({ projectRoot: root, workerConfigPath: join(root, 'worker.json'), fileSystem })
  assert.equal(find(report, 'proof-worker-config').status, 'BLOCKED')
  assert.ok(!opened.includes(join(root, 'worker.json')))
})

test('linked worker config is rejected without reading its contents', async (t) => {
  const root = await fixture(t)
  const endpoint = join(root, 'worker.json')
  const base = await fakeRuntimes(root)
  let workerOpened = false
  const fileSystem = { ...base,
    lstat: async (path) => path === endpoint ? { ...(await fs.lstat(endpoint)), isSymbolicLink: () => true } : base.lstat(path),
    open: async (path, flags) => { if (path === endpoint) workerOpened = true; return fs.open(path, flags) },
  }
  const report = await inspectReadiness({ projectRoot: root, workerConfigPath: endpoint, fileSystem })
  assert.equal(find(report, 'proof-worker-config').status, 'BLOCKED')
  assert.equal(workerOpened, false)
})

test('standalone doctor runs with no installed npm dependencies and strict inert arguments', async (t) => {
  const root = await fixture(t)
  for (const path of ['scripts/doctor.mjs', 'scripts/lib/doctor.mjs', 'scripts/lib/capabilities.mjs', 'scripts/lib/canonical-order.mjs', 'scripts/lib/filesystem-endpoint.mjs', 'scripts/lib/main-module.mjs', 'scripts/lib/terminal-text.mjs']) {
    await fs.mkdir(dirname(join(root, path)), { recursive: true })
    await fs.copyFile(resolve(path), join(root, path))
  }
  await fs.unlink(join(root, 'node_modules/acorn/package.json'))
  const executable = join(root, 'scripts/doctor.mjs')
  const report = JSON.parse(execFileSync(process.execPath, [executable, '--json'], { encoding: 'utf8' }))
  assert.equal(find(report, 'dependency:acorn').status, 'BLOCKED')
  assert.equal(report.assessment, 'STATIC_ONLY')
  for (const args of [['--execute'], ['--worker'], ['--json', '--json'], ['--worker', '//remote/share.json']]) {
    assert.throws(() => execFileSync(process.execPath, [executable, ...args], { encoding: 'utf8', stdio: 'pipe' }))
  }
})

test('human readiness output includes recorded environment gaps without implying deployed or live evidence', async (t) => {
  const root = await fixture(t)
  const report = await inspectReadiness({ projectRoot: root, fileSystem: await fakeRuntimes(root) })
  report.environment_coverage = assessEnvironmentCoverage(['compose.yml', 'browser/playwright.config.ts', 'api/app.py'])
  report.run_id = 'saved-run\x1b[2J'
  report.bundle_integrity = 'VERIFIED'
  report.root_authenticity = 'UNANCHORED'
  const rendered = renderReadiness(report)
  assert.match(rendered, /python: source review AVAILABLE; execution UNAVAILABLE/)
  assert.match(rendered, /browser: source review AVAILABLE; execution AVAILABLE_NARROW/)
  assert.match(rendered, /database-stack: source review AVAILABLE; execution UNAVAILABLE/)
  assert.match(rendered, /deployment evidence: NOT_ASSESSED/)
  assert.match(rendered, /root authenticity: UNANCHORED/)
  assert.match(rendered, /\\u001B\[2J/)
  assert.doesNotMatch(rendered, /\x1b/)
})
