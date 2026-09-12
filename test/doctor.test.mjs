import { test } from 'node:test'
import assert from 'node:assert/strict'
import * as fs from 'node:fs/promises'
import { join, dirname, resolve } from 'node:path'
import { tmpdir } from 'node:os'
import { execFileSync, spawnSync } from 'node:child_process'
import { inspectReadiness, renderReadiness, controllerRuntimePaths, READINESS_INPUT_LIMITS } from '../scripts/lib/doctor.mjs'
import { assessEnvironmentCoverage } from '../scripts/lib/capabilities.mjs'

const schemaSource = new URL('../schemas/proof-worker.schema.json', import.meta.url)
const runtime = controllerRuntimePaths()
const fixtureManifest = Object.freeze({
  name: 'last-aperture',
  version: '0.14.0',
  dependencies: Object.freeze({ acorn: '8.15.0' }),
})

function fixtureLockfile() {
  return {
    name: fixtureManifest.name,
    version: fixtureManifest.version,
    lockfileVersion: 3,
    requires: true,
    packages: {
      '': {
        name: fixtureManifest.name,
        version: fixtureManifest.version,
        dependencies: { ...fixtureManifest.dependencies },
      },
      'node_modules/acorn': { version: fixtureManifest.dependencies.acorn },
    },
  }
}

function worker(overrides = {}) {
  return {
    schema_version: '1.0.0', protocol: 'docker-proof-v1', runtime_path: runtime.docker,
    image: `sha256:${'a'.repeat(64)}`, dependency_manifest_sha256: 'b'.repeat(64),
    limits: { wall_time_ms: 1000, docker_command_timeout_ms: 1000, max_source_bytes: 1024,
      max_output_bytes: 1024, memory_bytes: 67108864, cpus: 1, pids: 8, nofile: 16, tmpfs_bytes: 1048576 },
    ...overrides,
  }
}

async function fixture(t, { installed = false } = {}) {
  const fixtureRoot = await fs.mkdtemp(join(tmpdir(), 'rta-doctor-'))
  const root = installed ? join(fixtureRoot, 'host/node_modules/last-aperture') : fixtureRoot
  await fs.mkdir(root, { recursive: true })
  t.after(() => fs.rm(fixtureRoot, { recursive: true, force: true }))
  const files = {
    'package.json': JSON.stringify(fixtureManifest),
    'package-lock.json': JSON.stringify(fixtureLockfile()),
    'npm-shrinkwrap.json': JSON.stringify(fixtureLockfile()),
    'scripts/audit.mjs': 'throw new Error("controller must not execute during doctor")',
    'scripts/engage.mjs': 'throw new Error("engagement must not execute during doctor")',
    'scripts/http-recon.mjs': 'throw new Error("HTTP recon must not execute during doctor")',
    'scripts/http-authed.mjs': 'throw new Error("authenticated HTTP must not execute during doctor")',
    'scripts/reverse.mjs': 'throw new Error("reverse routes must not execute during doctor")',
    'scripts/acquire.mjs': 'throw new Error("acquisition must not execute during doctor")',
    'scripts/bounty.mjs': 'throw new Error("bounty routes must not execute during doctor")',
    'scripts/lib/engagement-route-registry.mjs': 'throw new Error("registry must not execute during doctor")',
    'scripts/ghidra/LastApertureExport.java': 'fixture',
    'scripts/ghidra/GhidraBundleLocationAgent.java.source': 'fixture',
    'scripts/ghidra/GhidraBundleLocationAgent.mf': 'fixture',
    'scripts/frida/native-call-trace-v1.js': 'fixture',
    'scripts/frida/native-call-trace-v2.js': 'fixture',
    'browser/http-authed-chrome/manifest.json': '{}',
    'integrations/burp-montoya/src/main/java/dev/lastaperture/burp/LastApertureBurpExtension.java': 'fixture',
    'skills/last-aperture/SKILL.md': '# fixture',
    'schemas/engagement-intake.schema.json': '{}',
    'schemas/engagement-authority.schema.json': '{}',
    'schemas/engagement-manifest.schema.json': '{}',
    'schemas/engagement-ledger-record.schema.json': '{}',
    'schemas/proof-worker.schema.json': await fs.readFile(schemaSource, 'utf8'),
    'node_modules/acorn/package.json': JSON.stringify({ name: 'acorn', version: '8.15.0' }),
    'node_modules/acorn/index.js': 'throw new Error("dependency must not execute during doctor")',
    'worker.json': JSON.stringify(worker()),
    'credential-secret.txt': 'DO_NOT_READ_SECRET_MARKER',
    'tools/analyzeHeadless.bat': '@echo off',
    'tools/analyzeHeadless': '#!/bin/sh\nexit 0\n',
    'tools/javac.exe': 'fixture',
    'tools/jar.exe': 'fixture',
    'tools/frida.exe': 'fixture',
    'tools/burpsuite.jar': 'fixture',
    'tools/last-aperture-burp.jar': 'fixture',
    'tools/crane.exe': 'fixture',
  }
  for (const [name, content] of Object.entries(files)) {
    await fs.mkdir(dirname(join(root, name)), { recursive: true })
    await fs.writeFile(join(root, name), content)
  }
  if (process.platform !== 'win32') {
    for (const name of ['analyzeHeadless', 'frida.exe', 'crane.exe']) {
      await fs.chmod(join(root, 'tools', name), 0o755)
    }
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
    access: async (path, mode) => path === runtime.docker || path === runtime.archive
      ? undefined
      : fs.access(path, mode),
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

test('doctor projects static readiness for every unified host-tool family without executing tools', async (t) => {
  const root = await fixture(t)
  const ghidraLauncher = process.platform === 'win32' ? 'analyzeHeadless.bat' : 'analyzeHeadless'
  const toolPaths = Object.fromEntries([
    ['ghidra', ghidraLauncher],
    ['javac', 'javac.exe'],
    ['jar', 'jar.exe'],
    ['frida', 'frida.exe'],
    ['burpDesktop', 'burpsuite.jar'],
    ['burpExtension', 'last-aperture-burp.jar'],
    ['crane', 'crane.exe'],
  ].map(([name, file]) => [name, join(root, 'tools', file)]))
  const report = await inspectReadiness({
    projectRoot: root,
    fileSystem: await fakeRuntimes(root),
    toolPaths,
    environment: { Path: join(root, 'tools') },
  })
  for (const id of ['ghidra-executable', 'frida-executable', 'burp-desktop', 'burp-extension', 'crane-executable']) {
    assert.equal(find(report, id).status, 'PASS', id)
  }
  for (const id of ['jdk-javac-executable', 'jdk-jar-executable']) {
    assert.equal(find(report, id).status, process.platform === 'win32' ? 'PASS' : 'NOT_APPLICABLE', id)
  }
  for (const id of [
    'engagement-orchestration', 'ghidra-static-reverse', 'frida-typed-reverse',
    'frida-local-reverse', 'web-protocol-reconstruction', 'burp-proxy-history-export',
  ]) assert.equal(report.workflows.find((item) => item.id === id).status, 'STATIC_CHECKS_PASSED', id)
  assert.equal(report.workflows.find((item) => item.id === 'oci-registry-acquisition').status, 'UNAVAILABLE')

  const unconfigured = await inspectReadiness({ projectRoot: root, fileSystem: await fakeRuntimes(root) })
  assert.equal(find(unconfigured, 'frida-executable').status, 'NOT_CONFIGURED')
  assert.equal(unconfigured.workflows.find((item) => item.id === 'frida-typed-reverse').status, 'PREREQUISITES_MISSING')
})

test('doctor does not report hard-linked route tools or assets as ready', async (t) => {
  const root = await fixture(t)
  const fridaPath = join(root, 'tools/frida.exe')
  await fs.link(fridaPath, join(root, 'tools/frida-alias.exe'))
  const exporterPath = join(root, 'scripts/ghidra/LastApertureExport.java')
  await fs.link(exporterPath, join(root, 'scripts/ghidra/LastApertureExport.alias'))

  const report = await inspectReadiness({
    projectRoot: root,
    fileSystem: await fakeRuntimes(root),
    toolPaths: { frida: fridaPath },
  })
  assert.equal(find(report, 'frida-executable').status, 'BLOCKED')
  assert.equal(find(report, 'ghidra-exporter-source').status, 'BLOCKED')
  assert.equal(report.workflows.find((item) => item.id === 'frida-typed-reverse').status, 'PREREQUISITES_MISSING')
})

test('doctor does not report an empty shipped route asset as ready', async (t) => {
  const root = await fixture(t)
  await fs.writeFile(join(root, 'scripts/frida/native-call-trace-v2.js'), '')
  const report = await inspectReadiness({
    projectRoot: root,
    fileSystem: await fakeRuntimes(root),
    toolPaths: { frida: join(root, 'tools/frida.exe') },
  })
  assert.equal(find(report, 'frida-v2-agent').status, 'BLOCKED')
  assert.equal(report.workflows.find((item) => item.id === 'frida-typed-reverse').status, 'PREREQUISITES_MISSING')
})

test('doctor requires the shipped assets that engagement and reverse routes open at runtime', async (t) => {
  const root = await fixture(t)
  const toolPaths = Object.fromEntries([
    ['ghidra', 'analyzeHeadless.bat'],
    ['javac', 'javac.exe'],
    ['jar', 'jar.exe'],
    ['frida', 'frida.exe'],
  ].map(([name, file]) => [name, join(root, 'tools', file)]))
  const cases = [
    ['scripts/http-recon.mjs', 'engagement-orchestration', 'http-recon-entrypoint'],
    ['scripts/http-authed.mjs', 'engagement-orchestration', 'http-authed-entrypoint'],
    ['schemas/engagement-intake.schema.json', 'engagement-orchestration', 'engagement-intake-schema'],
    ['schemas/engagement-authority.schema.json', 'engagement-orchestration', 'engagement-authority-schema'],
    ['schemas/engagement-manifest.schema.json', 'engagement-orchestration', 'engagement-manifest-schema'],
    ['schemas/engagement-ledger-record.schema.json', 'engagement-orchestration', 'engagement-ledger-record-schema'],
    ['scripts/ghidra/LastApertureExport.java', 'ghidra-static-reverse', 'ghidra-exporter-source'],
    ['scripts/ghidra/GhidraBundleLocationAgent.java.source', 'ghidra-static-reverse', 'ghidra-windows-agent-source'],
    ['scripts/ghidra/GhidraBundleLocationAgent.mf', 'ghidra-static-reverse', 'ghidra-windows-agent-manifest'],
    ['scripts/frida/native-call-trace-v1.js', 'frida-local-reverse', 'frida-v1-agent'],
    ['scripts/frida/native-call-trace-v2.js', 'frida-typed-reverse', 'frida-v2-agent'],
  ]
  for (const [relativePath, workflowId, checkId] of cases) {
    const path = join(root, relativePath)
    const bytes = await fs.readFile(path)
    await fs.unlink(path)
    const report = await inspectReadiness({ projectRoot: root, platform: 'win32', fileSystem: await fakeRuntimes(root), toolPaths })
    const workflow = report.workflows.find((item) => item.id === workflowId)
    assert.equal(workflow.status, 'PREREQUISITES_MISSING', relativePath)
    assert.ok(workflow.blocking_checks.includes(checkId), `${relativePath}: ${workflow.blocking_checks}`)
    await fs.writeFile(path, bytes)
  }
})

test('Ghidra JDK and compatibility-agent prerequisites apply only to Windows batch launchers', async (t) => {
  const root = await fixture(t)
  const fileSystem = await fakeRuntimes(root)
  const batch = join(root, 'tools/analyzeHeadless.bat')
  const native = join(root, 'tools/frida.exe')
  if (process.platform !== 'win32') await fs.chmod(batch, 0o755)

  const windowsBatch = await inspectReadiness({ projectRoot: root, platform: 'win32', fileSystem, toolPaths: { ghidra: batch } })
  assert.deepEqual(
    windowsBatch.workflows.find((item) => item.id === 'ghidra-static-reverse').blocking_checks,
    ['jdk-javac-executable', 'jdk-jar-executable'],
  )

  for (const [platform, ghidra] of [['win32', native], ['linux', batch], ['darwin', batch]]) {
    const report = await inspectReadiness({ projectRoot: root, platform, fileSystem, toolPaths: { ghidra } })
    assert.equal(find(report, 'ghidra-executable').status, 'PASS', `${platform}:${ghidra}:executable`)
    assert.equal(report.workflows.find((item) => item.id === 'ghidra-static-reverse').status, 'STATIC_CHECKS_PASSED', `${platform}:${ghidra}`)
    assert.equal(find(report, 'jdk-javac-executable').status, 'NOT_APPLICABLE', `${platform}:${ghidra}:javac`)
    assert.equal(find(report, 'jdk-jar-executable').status, 'NOT_APPLICABLE', `${platform}:${ghidra}:jar`)
    assert.equal(find(report, 'ghidra-windows-agent-source').status, 'NOT_APPLICABLE', `${platform}:${ghidra}:agent-source`)
    assert.equal(find(report, 'ghidra-windows-agent-manifest').status, 'NOT_APPLICABLE', `${platform}:${ghidra}:agent-manifest`)
  }
})

test('Windows batch Ghidra readiness binds Java tools to the paths runtime discovery will select', {
  skip: process.platform !== 'win32',
}, async (t) => {
  const root = await fixture(t)
  const runtimeTools = join(root, 'tools')
  const arbitraryTools = join(root, 'arbitrary-tools')
  await fs.mkdir(arbitraryTools)
  await fs.writeFile(join(arbitraryTools, 'javac.exe'), 'unselected compiler')
  await fs.writeFile(join(arbitraryTools, 'jar.exe'), 'unselected archive builder')
  const report = await inspectReadiness({
    projectRoot: root,
    platform: 'win32',
    fileSystem: await fakeRuntimes(root),
    environment: { Path: runtimeTools },
    toolPaths: {
      ghidra: join(runtimeTools, 'analyzeHeadless.bat'),
      javac: join(arbitraryTools, 'javac.exe'),
      jar: join(arbitraryTools, 'jar.exe'),
    },
  })
  assert.equal(find(report, 'jdk-javac-executable').status, 'BLOCKED')
  assert.equal(find(report, 'jdk-jar-executable').status, 'BLOCKED')
  assert.deepEqual(
    report.workflows.find((item) => item.id === 'ghidra-static-reverse').blocking_checks,
    ['jdk-javac-executable', 'jdk-jar-executable'],
  )
})

test('configured native executables require host execute permission', async (t) => {
  const root = await fixture(t)
  const fridaPath = join(root, 'tools/frida.exe')
  const base = await fakeRuntimes(root)
  const fileSystem = {
    ...base,
    access: async (path, mode) => {
      if (path === fridaPath) {
        const error = new Error('execute access denied')
        error.code = 'EACCES'
        throw error
      }
      return base.access(path, mode)
    },
  }
  const report = await inspectReadiness({
    projectRoot: root,
    platform: 'linux',
    fileSystem,
    toolPaths: { frida: fridaPath },
  })
  assert.equal(find(report, 'frida-executable').status, 'BLOCKED')
  assert.equal(report.workflows.find((item) => item.id === 'frida-local-reverse').status, 'PREREQUISITES_MISSING')
})

test('a publishable shrinkwrap satisfies the dependency-lock prerequisite', async (t) => {
  const root = await fixture(t)
  await fs.unlink(join(root, 'package-lock.json'))
  const report = await inspectReadiness({ projectRoot: root, fileSystem: await fakeRuntimes(root) })
  assert.equal(find(report, 'dependency-lockfile').status, 'PASS')
  assert.equal(report.workflows.find((item) => item.id === 'source-review').status, 'STATIC_CHECKS_PASSED')
})

test('an existing malformed shrinkwrap blocks readiness instead of falling through to a source lockfile', async (t) => {
  const root = await fixture(t)
  await fs.writeFile(join(root, 'npm-shrinkwrap.json'), '{}')
  const report = await inspectReadiness({ projectRoot: root, fileSystem: await fakeRuntimes(root) })
  assert.equal(find(report, 'dependency-lockfile').status, 'BLOCKED')
  assert.equal(report.workflows.find((item) => item.id === 'source-review').status, 'PREREQUISITES_MISSING')
})

test('doctor resolves dependency metadata from a normal hoisted package installation', async (t) => {
  const root = await fixture(t, { installed: true })
  const nested = join(root, 'node_modules/acorn/package.json')
  const hoisted = join(dirname(root), 'acorn/package.json')
  await fs.mkdir(dirname(hoisted), { recursive: true })
  await fs.rename(nested, hoisted)
  const report = await inspectReadiness({ projectRoot: root, fileSystem: await fakeRuntimes(root) })
  assert.equal(find(report, 'dependency:acorn').status, 'PASS')
  assert.equal(report.workflows.find((item) => item.id === 'source-review').status, 'STATIC_CHECKS_PASSED')
})

test('the installed root command forwards explicit host-tool paths to doctor', async (t) => {
  const root = await fixture(t)
  const report = JSON.parse(execFileSync(process.execPath, [
    'scripts/audit.mjs', 'doctor', '--json', '--frida', join(root, 'tools/frida.exe'),
  ], { encoding: 'utf8' }))
  assert.equal(find(report, 'frida-executable').status, 'PASS')
})

test('the installed root command validates every doctor path before bundle I/O', () => {
  const invalidToolPath = resolve(`${'a'.repeat(4096)}.exe`)
  const child = spawnSync(process.execPath, [
    'scripts/audit.mjs', 'doctor', '--bundle', 'missing-review-bundle', '--frida', invalidToolPath,
  ], { encoding: 'utf8', shell: false, windowsHide: true })
  assert.equal(child.status, 1)
  assert.match(child.stderr, /absolute local filesystem path is required/i)
  assert.doesNotMatch(child.stderr, /ENOENT|missing-review-bundle/)
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
  await assert.rejects(inspectReadiness({
    projectRoot: resolve('.'),
    toolPaths: { frida: '\\\\server\\share\\frida.exe' },
    fileSystem,
  }), /local filesystem/)
  await assert.rejects(inspectReadiness({
    projectRoot: resolve('.'),
    toolPaths: { undeclaredTool: resolve('tool.exe') },
    fileSystem,
  }), /declared local tool endpoints/)
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
  for (const path of ['scripts/doctor.mjs', 'scripts/lib/doctor.mjs', 'scripts/lib/capabilities.mjs', 'scripts/lib/canonical-order.mjs', 'scripts/lib/filesystem-endpoint.mjs', 'scripts/lib/main-module.mjs', 'scripts/lib/terminal-text.mjs', 'scripts/lib/windows-java-tool-candidates.mjs']) {
    await fs.mkdir(dirname(join(root, path)), { recursive: true })
    await fs.copyFile(resolve(path), join(root, path))
  }
  await fs.unlink(join(root, 'node_modules/acorn/package.json'))
  const executable = join(root, 'scripts/doctor.mjs')
  const report = JSON.parse(execFileSync(process.execPath, [executable, '--json'], { encoding: 'utf8' }))
  assert.equal(find(report, 'dependency:acorn').status, 'BLOCKED')
  assert.equal(report.assessment, 'STATIC_ONLY')
  const configured = JSON.parse(execFileSync(process.execPath, [
    executable, '--json', '--frida', join(root, 'tools/frida.exe'),
  ], { encoding: 'utf8' }))
  assert.equal(find(configured, 'frida-executable').status, 'PASS')
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
