import { test } from 'node:test'
import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { EventEmitter } from 'node:events'
import { PassThrough } from 'node:stream'
import { mkdir, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import {
  GHIDRA_PROFILE_ID,
  GHIDRA_WINDOWS_AGENT_MANIFEST_PATH,
  GHIDRA_WINDOWS_AGENT_SOURCE_PATH,
  assertSupportedGhidraLauncher,
  buildGhidraArguments,
  prepareWindowsGhidraCompatibilityAgent,
  runGhidraHeadless,
  windowsJavaDevelopmentToolCandidates,
} from '../scripts/lib/reverse-ghidra.mjs'
import { sanitizedProcessEnvironment } from '../scripts/lib/reverse-process.mjs'

const PATHS = process.platform === 'win32'
  ? {
      launcher: 'C:\\Tools\\ghidra\\analyzeHeadless.exe',
      projectDirectory: 'C:\\work\\project',
      stagedBinary: 'C:\\work\\input\\sample.exe',
      scriptDirectory: 'C:\\tool\\scripts\\ghidra',
      exportPath: 'C:\\work\\output\\export.json',
      logPath: 'C:\\work\\output\\ghidra.log',
      scriptLogPath: 'C:\\work\\output\\script.log',
      cwd: 'C:\\work',
    }
  : {
      launcher: '/opt/ghidra/support/analyzeHeadless',
      projectDirectory: '/work/project',
      stagedBinary: '/work/input/sample',
      scriptDirectory: '/opt/last-aperture/scripts/ghidra',
      exportPath: '/work/output/export.json',
      logPath: '/work/output/ghidra.log',
      scriptLogPath: '/work/output/script.log',
      cwd: '/work',
    }

function argumentsFor(overrides = {}) {
  return buildGhidraArguments({
    projectDirectory: PATHS.projectDirectory,
    projectName: 'last-aperture-analysis',
    stagedBinary: PATHS.stagedBinary,
    scriptDirectory: PATHS.scriptDirectory,
    exportPath: PATHS.exportPath,
    logPath: PATHS.logPath,
    scriptLogPath: PATHS.scriptLogPath,
    timeoutSeconds: 90,
    maxCpu: 2,
    ...overrides,
  })
}

function fakeProcess({ stdout = '', stderr = '', code = 0, signal = null, delay = 0 } = {}) {
  const child = new EventEmitter()
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  child.killedWith = []
  child.closed = false
  child.kill = (requestedSignal) => {
    child.killedWith.push(requestedSignal)
    return true
  }
  queueMicrotask(() => {
    child.stdout.write(stdout)
    child.stderr.write(stderr)
    child.stdout.end()
    child.stderr.end()
    setTimeout(() => {
      child.closed = true
      child.emit('close', code, signal)
    }, delay)
  })
  return child
}

test('the fixed profile builds one exact headless-analysis argument vector', () => {
  assert.equal(GHIDRA_PROFILE_ID, 'ghidra-headless-fixed-export-v1')
  assert.deepEqual(argumentsFor(), [
    PATHS.projectDirectory,
    'last-aperture-analysis',
    '-import',
    PATHS.stagedBinary,
    '-readOnly',
    '-deleteProject',
    '-analysisTimeoutPerFile',
    '90',
    '-max-cpu',
    '2',
    '-scriptPath',
    PATHS.scriptDirectory,
    '-postScript',
    'LastApertureExport.java',
    PATHS.exportPath,
    '-log',
    PATHS.logPath,
    '-scriptlog',
    PATHS.scriptLogPath,
  ])
})

test('argument construction rejects alternate scripts, raw argv, relative paths, and unsafe limits', () => {
  assert.throws(
    () => argumentsFor({ preScript: 'caller.java' }),
    /unknown Ghidra profile option/i,
  )
  assert.throws(
    () => argumentsFor({ rawArgs: ['-preScript', 'caller.java'] }),
    /unknown Ghidra profile option/i,
  )
  assert.throws(() => argumentsFor({ stagedBinary: 'relative.bin' }), /absolute local path/i)
  assert.throws(() => argumentsFor({ projectName: '../escape' }), /project name/i)
  assert.throws(() => argumentsFor({ timeoutSeconds: 0 }), /timeoutSeconds/i)
  assert.throws(() => argumentsFor({ timeoutSeconds: 3601 }), /timeoutSeconds/i)
  assert.throws(() => argumentsFor({ maxCpu: 0 }), /maxCpu/i)
  assert.throws(() => argumentsFor({ maxCpu: 65 }), /maxCpu/i)
})

test('Windows Java tool discovery preserves JAVA_HOME, JDK_HOME, then PATH order', () => {
  assert.deepEqual(
    windowsJavaDevelopmentToolCandidates({
      JAVA_HOME: 'C:\\jdk-stale',
      JDK_HOME: 'C:\\jdk-current',
      Path: 'C:\\path-jdk;C:\\jdk-current\\bin;relative-entry',
    }, 'javac.exe'),
    [
      'C:\\jdk-stale\\bin\\javac.exe',
      'C:\\jdk-current\\bin\\javac.exe',
      'C:\\path-jdk\\javac.exe',
    ],
  )
  assert.throws(
    () => windowsJavaDevelopmentToolCandidates({ JAVA_HOME: 'relative-jdk' }, 'javac.exe'),
    /absolute local path/i,
  )
})

test('Windows launcher policy admits native and batch launchers but rejects PowerShell scripts', () => {
  for (const launcher of ['C:\\ghidra\\support\\analyzeHeadless.bat', 'C:\\tools\\wrapper.CMD']) {
    assert.equal(assertSupportedGhidraLauncher(launcher, { platform: 'win32' }), launcher)
  }
  assert.throws(
    () => assertSupportedGhidraLauncher('C:\\tools\\wrapper.ps1', { platform: 'win32' }),
    (error) => error?.code === 'GHIDRA_WINDOWS_LAUNCHER_UNSUPPORTED',
  )
  assert.throws(
    () => assertSupportedGhidraLauncher('C:\\tools\\safe" & calc & "\\analyzeHeadless.bat', { platform: 'win32' }),
    (error) => error?.code === 'GHIDRA_PATH_INVALID',
  )
  assert.equal(
    assertSupportedGhidraLauncher('C:\\tools\\analyzeHeadless.exe', { platform: 'win32' }),
    'C:\\tools\\analyzeHeadless.exe',
  )
  assert.equal(
    assertSupportedGhidraLauncher('/opt/ghidra/support/analyzeHeadless', { platform: 'linux' }),
    '/opt/ghidra/support/analyzeHeadless',
  )
})

test('Windows batch launchers cannot bypass the Job Object adapter through an injected spawn', {
  skip: process.platform !== 'win32',
}, async () => {
  let spawned = false
  await assert.rejects(
    runGhidraHeadless({
      launcherPath: 'C:\\ghidra\\support\\analyzeHeadless.bat',
      args: argumentsFor(),
      cwd: PATHS.cwd,
      timeoutMs: 1_000,
      maxOutputBytes: 1_024,
      spawnImpl: () => { spawned = true; return fakeProcess() },
    }),
    (error) => error?.code === 'GHIDRA_WINDOWS_JOB_ADAPTER_REQUIRED',
  )
  assert.equal(spawned, false)
})

test('Windows native launchers run without building or injecting the batch compatibility agent', {
  skip: process.platform !== 'win32',
}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-ghidra-native-'))
  try {
    const result = await runGhidraHeadless({
      launcherPath: process.execPath,
      args: buildGhidraArguments({
        projectDirectory: join(root, 'project'),
        projectName: 'last-aperture-analysis',
        stagedBinary: join(root, 'target.exe'),
        scriptDirectory: join(root, 'scripts'),
        exportPath: join(root, 'export.json'),
        logPath: join(root, 'ghidra.log'),
        scriptLogPath: join(root, 'script.log'),
        timeoutSeconds: 90,
        maxCpu: 2,
      }),
      cwd: root,
      timeoutMs: 30_000,
      maxOutputBytes: 64 * 1024,
    })
    assert.deepEqual(result.tool_components, [])
    await assert.rejects(stat(join(root, '.ghidra-agent')), { code: 'ENOENT' })
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('Windows runs the official batch-launcher shape through confirmed Job Object supervision', {
  skip: process.platform !== 'win32',
}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-ghidra-batch-'))
  const fixtureDirectory = join(root, 'fixture & bang! %PATH%')
  const launcherPath = join(fixtureDirectory, 'analyzeHeadless.cmd')
  await mkdir(fixtureDirectory, { recursive: true })
  await writeFile(launcherPath, [
    '@echo off',
    'echo agent=%GHIDRA_HEADLESS_JAVA_OPTIONS%',
    'echo batch-job-ok',
    'exit /b 0',
    '',
  ].join('\r\n'), 'utf8')

  try {
    const paths = {
      projectDirectory: join(root, 'project & data!'),
      stagedBinary: join(root, 'input & data!', 'sample.exe'),
      scriptDirectory: join(root, 'scripts & data!'),
      exportPath: join(root, 'output & data!', 'export.json'),
      logPath: join(root, 'output & data!', 'ghidra.log'),
      scriptLogPath: join(root, 'output & data!', 'script.log'),
    }
    const javaEnvironment = sanitizedProcessEnvironment()
    const activeJavaHome = javaEnvironment.JAVA_HOME ?? javaEnvironment.JDK_HOME
    if (activeJavaHome !== undefined) {
      javaEnvironment.JAVA_HOME = join(root, 'missing-java-home')
      javaEnvironment.JDK_HOME = activeJavaHome
    }
    const preparedAgent = await prepareWindowsGhidraCompatibilityAgent({
      cwd: root,
      environment: javaEnvironment,
      deadline: Date.now() + 30_000,
      outputBudget: 4_096,
    })
    const result = await runGhidraHeadless({
      launcherPath,
      args: buildGhidraArguments({
        ...paths,
        projectName: 'last-aperture-analysis',
        timeoutSeconds: 90,
        maxCpu: 2,
      }),
      cwd: root,
      timeoutMs: 30_000,
      maxOutputBytes: 4_096,
      windowsCompatibilityAgent: preparedAgent,
    })

    assert.equal(result.code, 0)
    assert.equal(result.spawn_error, false)
    assert.equal(result.termination_confirmed, true)
    assert.equal(result.supervision, 'WINDOWS_JOB_OBJECT')
    assert.match(result.stdout.toString('utf8'), /batch-job-ok/)
    assert.match(result.stdout.toString('utf8'), /-javaagent:.*last-aperture-ghidra-agent\.jar/i)
    assert.deepEqual(
      result.tool_components.map(({ role }) => role),
      ['java-compiler', 'java-archive-builder', 'windows-compatibility-agent'],
    )
    for (const component of result.tool_components) {
      assert.match(component.sha256, /^[a-f0-9]{64}$/u)
      assert.equal(Number.isSafeInteger(component.size_bytes) && component.size_bytes > 0, true)
      assert.deepEqual(Object.keys(component).sort(), ['name', 'role', 'sha256', 'size_bytes'])
    }
    if (activeJavaHome !== undefined) {
      const activeJavac = await readFile(join(activeJavaHome, 'bin', 'javac.exe'))
      assert.equal(
        result.tool_components.find(({ role }) => role === 'java-compiler').sha256,
        createHash('sha256').update(activeJavac).digest('hex'),
      )
    }
    const agentJar = await readFile(join(root, '.ghidra-agent', 'last-aperture-ghidra-agent.jar'))
    assert.equal(
      result.tool_components.find(({ role }) => role === 'windows-compatibility-agent').sha256,
      createHash('sha256').update(agentJar).digest('hex'),
    )
    assert.equal(
      (await stat(join(root, '.ghidra-agent', 'last-aperture-ghidra-agent.jar'))).isFile(),
      true,
    )
    await writeFile(preparedAgent.jarPath, Buffer.from('changed agent'))
    await assert.rejects(
      runGhidraHeadless({
        launcherPath,
        args: buildGhidraArguments({
          ...paths,
          projectName: 'last-aperture-analysis',
          timeoutSeconds: 90,
          maxCpu: 2,
        }),
        cwd: root,
        timeoutMs: 30_000,
        maxOutputBytes: 4_096,
        windowsCompatibilityAgent: preparedAgent,
      }),
      (error) => error?.code === 'GHIDRA_SPAWN_FAILED'
        && error?.cause?.code === 'GHIDRA_WINDOWS_AGENT_CHANGED',
    )
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('Windows Java tool discovery does not fall through an existing unsafe home candidate', {
  skip: process.platform !== 'win32',
}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-ghidra-unsafe-jdk-'))
  const unsafeHome = join(root, 'unsafe-jdk')
  try {
    await mkdir(join(unsafeHome, 'bin', 'javac.exe'), { recursive: true })
    await mkdir(join(unsafeHome, 'bin', 'jar.exe'), { recursive: true })
    await assert.rejects(
      prepareWindowsGhidraCompatibilityAgent({
        cwd: root,
        environment: {
          ...sanitizedProcessEnvironment(),
          JAVA_HOME: unsafeHome,
        },
        deadline: Date.now() + 30_000,
        outputBudget: 4_096,
      }),
      (error) => error?.code === 'GHIDRA_JAVA_TOOL_INVALID',
    )
    await assert.rejects(stat(join(root, '.ghidra-agent')), { code: 'ENOENT' })
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('the Windows compatibility agent is a fixed narrowly scoped source build', async () => {
  const [source, manifest] = await Promise.all([
    readFile(GHIDRA_WINDOWS_AGENT_SOURCE_PATH, 'utf8'),
    readFile(GHIDRA_WINDOWS_AGENT_MANIFEST_PATH, 'utf8'),
  ])
  assert.match(source, /ghidra\/app\/plugin\/core\/osgi\/GhidraSourceBundle/)
  assert.match(source, /path\.toUri\(\)\.toASCIIString\(\)/)
  assert.match(source, /jdk\.nio\.zipfs\.ZipFileSystemProvider/)
  assert.match(source, /frame\.getMethodName\(\)\.equals\("removeFileSystem"\)/)
  assert.match(source, /endsWith\("\.jar"\)/)
  assert.doesNotMatch(source, /Runtime\.getRuntime|ProcessBuilder|java\.net|Socket/)
  assert.match(
    manifest,
    /Premain-Class: lastaperture\.ghidra\.GhidraBundleLocationAgent/,
  )
})

test('runner uses shell false and returns bounded raw process output without a verdict', async () => {
  let invocation
  const child = fakeProcess({ stdout: 'analysis complete\n', stderr: 'diagnostic\n' })
  const previous = process.env.LAST_APERTURE_TEST_SECRET
  process.env.LAST_APERTURE_TEST_SECRET = 'must-not-reach-ghidra'
  let result
  try {
    result = await runGhidraHeadless({
      launcherPath: PATHS.launcher,
      args: argumentsFor(),
      cwd: PATHS.cwd,
      timeoutMs: 1_000,
      maxOutputBytes: 1_024,
      spawnImpl: (file, args, options) => {
        invocation = { file, args, options }
        return child
      },
    })
  } finally {
    if (previous === undefined) delete process.env.LAST_APERTURE_TEST_SECRET
    else process.env.LAST_APERTURE_TEST_SECRET = previous
  }

  assert.equal(invocation.file, PATHS.launcher)
  assert.deepEqual(invocation.args, argumentsFor())
  assert.equal(invocation.options.shell, false)
  assert.equal(invocation.options.windowsHide, true)
  assert.equal(invocation.options.cwd, PATHS.cwd)
  assert.equal(invocation.options.detached, process.platform !== 'win32')
  assert.deepEqual(invocation.options.stdio, ['ignore', 'pipe', 'pipe'])
  assert.equal(invocation.options.env.LAST_APERTURE_TEST_SECRET, undefined)
  assert.equal(Object.keys(invocation.options.env).some((key) => /TOKEN|SECRET|PASSWORD|KEY/i.test(key)), false)
  assert.equal(invocation.options.env.XDG_CONFIG_HOME, join(PATHS.cwd, '.ghidra-config'))
  assert.equal(invocation.options.env.XDG_CACHE_HOME, join(PATHS.cwd, '.ghidra-cache'))
  assert.equal(result.profile_id, GHIDRA_PROFILE_ID)
  assert.equal(result.code, 0)
  assert.equal(result.timed_out, false)
  assert.equal(result.output_limit_exceeded, false)
  assert.equal(result.termination_confirmed, false)
  assert.equal(result.stdout.toString('utf8'), 'analysis complete\n')
  assert.equal(result.stderr.toString('utf8'), 'diagnostic\n')
  assert.equal(Object.hasOwn(result, 'security_verdict'), false)
})

test('runner rejects an argument vector that adds a caller script before spawn', async () => {
  let spawned = false
  await assert.rejects(
    runGhidraHeadless({
      launcherPath: PATHS.launcher,
      args: [...argumentsFor(), '-preScript', 'caller.java'],
      cwd: PATHS.cwd,
      timeoutMs: 1_000,
      maxOutputBytes: 1_024,
      spawnImpl: () => { spawned = true; return fakeProcess() },
    }),
    /fixed Ghidra argument profile/i,
  )
  assert.equal(spawned, false)
})

test('runner kills and marks a process that exceeds the output bound', async () => {
  const child = fakeProcess({ stdout: 'x'.repeat(2_048), delay: 20 })
  const result = await runGhidraHeadless({
    launcherPath: PATHS.launcher,
    args: argumentsFor(),
    cwd: PATHS.cwd,
    timeoutMs: 1_000,
    maxOutputBytes: 128,
    spawnImpl: () => child,
  })
  assert.equal(result.output_limit_exceeded, true)
  assert.equal(result.timed_out, false)
  assert.equal(result.stdout.length + result.stderr.length, 128)
  assert.deepEqual(child.killedWith, ['SIGKILL'])
  assert.equal(child.closed, true)
  assert.equal(result.termination_confirmed, false)
})

test('runner kills and marks a process that exceeds its time bound', async () => {
  const child = fakeProcess({ delay: 100 })
  const result = await runGhidraHeadless({
    launcherPath: PATHS.launcher,
    args: argumentsFor(),
    cwd: PATHS.cwd,
    timeoutMs: 10,
    maxOutputBytes: 1_024,
    spawnImpl: () => child,
  })
  assert.equal(result.timed_out, true)
  assert.equal(result.output_limit_exceeded, false)
  assert.deepEqual(child.killedWith, ['SIGKILL'])
  assert.equal(child.closed, true)
  assert.equal(result.termination_confirmed, false)
})

test('runner reports unconfirmed termination when the bounded post-kill wait expires', async () => {
  const child = new EventEmitter()
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  child.killedWith = []
  child.kill = (signal) => {
    child.killedWith.push(signal)
    return true
  }
  queueMicrotask(() => child.stdout.write('x'.repeat(256)))

  const originalSetTimeout = globalThis.setTimeout
  globalThis.setTimeout = (callback, delay, ...args) => originalSetTimeout(
    callback,
    delay === 5_000 ? 1 : delay,
    ...args,
  )
  try {
    const result = await runGhidraHeadless({
      launcherPath: PATHS.launcher,
      args: argumentsFor(),
      cwd: PATHS.cwd,
      timeoutMs: 1_000,
      maxOutputBytes: 16,
      spawnImpl: () => child,
    })
    assert.equal(result.output_limit_exceeded, true)
    assert.equal(result.termination_confirmed, false)
    assert.deepEqual(child.killedWith, ['SIGKILL'])
  } finally {
    globalThis.setTimeout = originalSetTimeout
  }
})

test('runner child errors never imply confirmed process-tree termination', async () => {
  const child = new EventEmitter()
  child.stdout = new PassThrough()
  child.stderr = new PassThrough()
  child.kill = () => true
  queueMicrotask(() => child.emit('error', new Error('spawn failed')))

  const result = await runGhidraHeadless({
    launcherPath: PATHS.launcher,
    args: argumentsFor(),
    cwd: PATHS.cwd,
    timeoutMs: 1_000,
    maxOutputBytes: 1_024,
    spawnImpl: () => child,
  })
  assert.equal(result.spawn_error, true)
  assert.equal(result.termination_confirmed, false)
})

test('runner monitors the two Ghidra logs under one combined byte cap', async () => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-ghidra-logs-'))
  try {
    const logPath = join(root, 'ghidra.log')
    const scriptLogPath = join(root, 'ghidra-script.log')
    await writeFile(logPath, Buffer.alloc(80))
    await writeFile(scriptLogPath, Buffer.alloc(80))
    const child = fakeProcess({ delay: 20 })
    const result = await runGhidraHeadless({
      launcherPath: PATHS.launcher,
      args: argumentsFor({ logPath, scriptLogPath }),
      cwd: PATHS.cwd,
      timeoutMs: 1_000,
      maxOutputBytes: 128,
      spawnImpl: () => child,
    })
    assert.equal(result.log_limit_exceeded, true)
    assert.equal(result.log_bytes, 160)
    assert.deepEqual(child.killedWith, ['SIGKILL'])
    assert.equal(result.termination_confirmed, false)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('the controller-owned exporter is bounded observations-only output', async () => {
  const source = await readFile(
    new URL('../scripts/ghidra/LastApertureExport.java', import.meta.url),
    'utf8',
  )
  assert.match(source, /ghidra-headless-fixed-export-v1/)
  assert.match(source, /MAX_FUNCTIONS\s*=\s*20_000/)
  assert.match(source, /MAX_NETWORK_IMPORTS\s*=\s*512/)
  assert.match(source, /MAX_REFERENCES_PER_IMPORT\s*=\s*128/)
  assert.match(source, /MAX_STRING_RECORDS_SCANNED\s*=\s*100_000/)
  assert.match(source, /MAX_STRING_CHARS_SCANNED\s*=\s*16_384/)
  assert.match(source, /MAX_ENDPOINTS\s*=\s*512/)
  assert.match(source, /MAX_AUTH_HINTS\s*=\s*512/)
  assert.match(source, /red-team-audit\/ghidra-static-export/)
  assert.match(source, /\\"network_imports\\"/)
  assert.match(source, /\\"endpoint_observations\\"/)
  assert.match(source, /\\"auth_hints\\"/)
  assert.match(source, /\\"callsite_offsets\\"/)
  assert.match(source, /"path_template"/)
  assert.match(source, /"query_names"/)
  assert.match(source, /redacted_name/)
  assert.match(source, /\\"protocol_coverage\\"/)
  assert.doesNotMatch(source, /security_verdict/i)
})

test('the fixed exporter derives protocol metadata without emitting raw strings or values', async () => {
  const source = await readFile(
    new URL('../scripts/ghidra/LastApertureExport.java', import.meta.url),
    'utf8',
  )

  assert.match(source, /enum AuthHint/)
  assert.match(source, /enum NetworkApi/)
  assert.match(source, /getExternalFunctions\(\)/)
  assert.match(source, /classifyNetworkApi\(function\.getName\(\)\)/)
  assert.match(source, /WINHTTP_SEND_REQUEST/)
  assert.match(source, /LIBCURL_EASY_PERFORM/)
  assert.match(source, /new URI\(candidate\)/)
  assert.match(source, /getRawQuery\(\)/)
  assert.match(source, /queryPart\.substring\(0, equalsIndex\)/)
  assert.match(source, /templatePath\(uri\.getRawPath\(\)\)/)
  assert.match(source, /getRawUserInfo\(\) != null/)

  for (const forbiddenField of [
    'raw_url',
    'raw_string',
    'query_value',
    'header_value',
    'credential_value',
    'request_body',
    'cookie_value',
    'token_value',
  ]) {
    assert.doesNotMatch(source, new RegExp(`\\\"${forbiddenField}\\\"`, 'i'))
  }

  assert.doesNotMatch(source, /writeJsonString\(writer,\s*(?:candidate|rawQuery|rawString|stringValue)\b/)
  assert.doesNotMatch(
    source,
    /writeStringField\([^;]*(?:candidate|rawQuery|rawString|stringValue)\b/s,
  )
})
