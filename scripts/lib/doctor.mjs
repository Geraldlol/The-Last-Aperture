import * as fs from 'node:fs/promises'
import { constants } from 'node:fs'
import { basename, dirname, isAbsolute, join, parse, relative, resolve, win32 } from 'node:path'

import { capabilityRegistry } from './capabilities.mjs'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { assertLocalFilesystemEndpoint } from './filesystem-endpoint.mjs'
import { terminalSafeText } from './terminal-text.mjs'
import { windowsJavaDevelopmentToolCandidates } from './windows-java-tool-candidates.mjs'

export const READINESS_INPUT_LIMITS = Object.freeze({
  json_bytes: 64 * 1024,
  lockfile_bytes: 4 * 1024 * 1024,
  worker_bytes: 64 * 1024,
})
const MAX_JAVA_TOOL_BYTES = 64 * 1024 * 1024

export function controllerRuntimePaths(platform = process.platform) {
  return platform === 'win32'
    ? { docker: 'C:\\Program Files\\Docker\\Docker\\resources\\bin\\docker.exe', archive: 'C:\\Windows\\System32\\tar.exe' }
    : { docker: '/usr/bin/docker', archive: '/usr/bin/tar' }
}

function localAbsolutePath(value) {
  assertLocalFilesystemEndpoint(value)
  if (typeof value !== 'string' || value.length > 4096 || /[\x00-\x1f\x7f]/.test(value) || !isAbsolute(value)) {
    throw new Error('an absolute local filesystem path is required')
  }
  // Reject alternate streams before touching a Windows path.
  if (process.platform === 'win32' && /:/.test(value.slice(2))) throw new Error('alternate data streams are not supported')
  return resolve(value)
}

const TOOL_PATH_KEYS = new Set([
  'ghidra', 'javac', 'jar', 'frida', 'burpDesktop', 'burpExtension', 'crane',
])

export function normalizeReadinessPaths({
  projectRoot,
  workerConfigPath,
  bundlePath,
  toolPaths = {},
} = {}) {
  const root = localAbsolutePath(projectRoot)
  const worker = workerConfigPath === undefined ? undefined : localAbsolutePath(workerConfigPath)
  const bundle = bundlePath === undefined ? undefined : localAbsolutePath(bundlePath)
  if (
    toolPaths === null
    || typeof toolPaths !== 'object'
    || Array.isArray(toolPaths)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(toolPaths))
    || Object.keys(toolPaths).some((name) => !TOOL_PATH_KEYS.has(name))
  ) throw new Error('toolPaths must contain only declared local tool endpoints')
  const tools = Object.fromEntries(Object.entries(toolPaths).map(([name, value]) => [
    name,
    localAbsolutePath(value),
  ]))
  return { projectRoot: root, workerConfigPath: worker, bundlePath: bundle, toolPaths: tools }
}

async function checkedEndpoint(value, fileSystem, kind = 'file') {
  const absolute = localAbsolutePath(value)
  const root = parse(absolute).root
  let current = root
  let metadata = await fileSystem.lstat(root)
  const parts = relative(root, absolute).split(/[\\/]/).filter(Boolean)
  for (const [index, part] of parts.entries()) {
    current = join(current, part)
    metadata = await fileSystem.lstat(current)
    if (metadata.isSymbolicLink()) throw new Error('linked filesystem endpoint is not supported')
    if (index < parts.length - 1 && !metadata.isDirectory()) throw new Error('parent endpoint is not a directory')
  }
  if (metadata.isSymbolicLink() || (kind === 'directory' ? !metadata.isDirectory() : !metadata.isFile())) {
    throw new Error(`endpoint is not a regular ${kind}`)
  }
  if (kind === 'file' && metadata.nlink !== 1 && metadata.nlink !== 1n) {
    throw new Error('endpoint is not one unlinked regular file')
  }
  if (kind === 'file' && (metadata.size === 0 || metadata.size === 0n)) {
    throw new Error('endpoint is an empty regular file')
  }
  const canonical = localAbsolutePath(await fileSystem.realpath(absolute))
  if ((process.platform === 'win32' ? canonical.toLowerCase() !== absolute.toLowerCase() : canonical !== absolute)) {
    throw new Error('endpoint changed during canonical path validation')
  }
  return { path: canonical, metadata }
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs && left.nlink === right.nlink
}

async function boundedJson(path, maxBytes, fileSystem) {
  const checked = await checkedEndpoint(path, fileSystem)
  if (!Number.isSafeInteger(checked.metadata.size) || checked.metadata.size > maxBytes || checked.metadata.size < 1) {
    throw new Error('JSON file exceeds its size limit or is empty')
  }
  let handle
  try {
    handle = await fileSystem.open(checked.path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
    const before = await handle.stat()
    if (!before.isFile() || !sameFile(before, checked.metadata)) throw new Error('JSON file changed before reading')
    const buffer = Buffer.alloc(checked.metadata.size + 1)
    let offset = 0
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset)
      if (!bytesRead) break
      offset += bytesRead
    }
    const after = await handle.stat()
    const endpointAfter = await checkedEndpoint(path, fileSystem)
    if (offset !== checked.metadata.size || !sameFile(before, after) || !sameFile(before, endpointAfter.metadata)) {
      throw new Error('JSON file changed while reading')
    }
    return JSON.parse(buffer.subarray(0, offset).toString('utf8'))
  } finally {
    await handle?.close()
  }
}

// The bundled proof-worker schema uses this small JSON-schema subset. Inspect
// it without loading Ajv, executing dependencies, or echoing config values.
function matchesWorkerSchema(value, schema, root = schema, depth = 0) {
  if (!schema || typeof schema !== 'object' || depth > 12) return false
  const supported = new Set(['$schema', '$id', '$defs', '$ref', 'title', 'description', 'type', 'required', 'properties', 'additionalProperties', 'const', 'minLength', 'maxLength', 'pattern', 'minimum', 'maximum'])
  if (Object.keys(schema).some((key) => !supported.has(key))) return false
  if (schema.$ref) {
    const match = /^#\/\$defs\/([A-Za-z][A-Za-z0-9]*)$/.exec(schema.$ref)
    return Boolean(match && matchesWorkerSchema(value, root.$defs?.[match[1]], root, depth + 1))
  }
  if (Object.hasOwn(schema, 'const') && value !== schema.const) return false
  if (schema.type === 'object') {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false
    if ((schema.required ?? []).some((name) => !Object.hasOwn(value, name))) return false
    for (const [name, child] of Object.entries(value)) {
      if (!Object.hasOwn(schema.properties ?? {}, name)) {
        if (schema.additionalProperties === false) return false
      } else if (!matchesWorkerSchema(child, schema.properties[name], root, depth + 1)) return false
    }
  } else if (schema.type === 'string') {
    if (typeof value !== 'string') return false
    if (value.length < (schema.minLength ?? 0) || value.length > (schema.maxLength ?? Infinity)) return false
    if (schema.pattern && !new RegExp(schema.pattern).test(value)) return false
  } else if (schema.type === 'integer' || schema.type === 'number') {
    if (typeof value !== 'number' || !Number.isFinite(value) || (schema.type === 'integer' && !Number.isSafeInteger(value))) return false
    if (value < (schema.minimum ?? -Infinity) || value > (schema.maximum ?? Infinity)) return false
  } else if (!Object.hasOwn(schema, 'const')) return false
  return true
}

function check(id, status, detail, action) {
  return { id, status, detail, ...(action ? { action } : {}) }
}

async function fileCheck(id, path, fileSystem, action) {
  try {
    await checkedEndpoint(path, fileSystem)
    return check(id, 'PASS', 'Required regular local file is present; its contents were not executed.', action)
  } catch {
    return check(id, 'BLOCKED', 'Required local file is missing, inaccessible, or not a regular unlinked endpoint.', action)
  }
}

async function executableFileCheck(id, path, fileSystem, platform, action) {
  try {
    const endpoint = await checkedEndpoint(path, fileSystem)
    if (platform !== 'win32') await fileSystem.access(endpoint.path, constants.X_OK)
    const endpointAfter = await checkedEndpoint(path, fileSystem)
    if (!sameFile(endpoint.metadata, endpointAfter.metadata)) throw new Error('executable changed during inspection')
    return check(id, 'PASS', 'Required non-empty executable is present; it was not executed.', action)
  } catch {
    return check(id, 'BLOCKED', 'Required executable is missing, inaccessible, empty, linked, or lacks host execute permission.', action)
  }
}

async function configuredFileCheck(id, path, fileSystem, action) {
  if (path === undefined) {
    return check(id, 'NOT_CONFIGURED', 'No local executable or artifact path was supplied for this workflow.', action)
  }
  return fileCheck(id, path, fileSystem, action)
}

async function configuredExecutableCheck(id, path, fileSystem, platform, action) {
  if (path === undefined) {
    return check(id, 'NOT_CONFIGURED', 'No local executable path was supplied for this workflow.', action)
  }
  return executableFileCheck(id, path, fileSystem, platform, action)
}

function plainRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function exactStringRecord(actual, expected) {
  if (!plainRecord(actual)) return false
  const actualNames = Object.keys(actual).sort(compareCanonicalStrings)
  const expectedNames = Object.keys(expected).sort(compareCanonicalStrings)
  return actualNames.length === expectedNames.length
    && actualNames.every((name, index) => name === expectedNames[index] && actual[name] === expected[name])
}

function validDependencyLock(lock, manifest) {
  if (!plainRecord(lock) || !plainRecord(manifest) || ![2, 3].includes(lock.lockfileVersion)) return false
  if (lock.name !== manifest.name || lock.version !== manifest.version || !plainRecord(lock.packages)) return false
  const root = lock.packages['']
  if (!plainRecord(root) || root.name !== manifest.name || root.version !== manifest.version) return false
  if (!exactStringRecord(root.dependencies, manifest.dependencies)) return false
  return Object.entries(manifest.dependencies).every(([name, version]) => {
    const installed = lock.packages[`node_modules/${name}`]
    return plainRecord(installed) && installed.version === version
  })
}

async function dependencyLockCheck(root, manifest, fileSystem) {
  for (const name of ['npm-shrinkwrap.json', 'package-lock.json']) {
    try {
      const lock = await boundedJson(join(root, name), READINESS_INPUT_LIMITS.lockfile_bytes, fileSystem)
      if (!validDependencyLock(lock, manifest)) throw new Error('release lockfile does not match the installation manifest')
      return check('dependency-lockfile', 'PASS', `${name} structurally pins every declared direct dependency for this package release.`)
    } catch (error) {
      if (error?.code === 'ENOENT') continue
      return check('dependency-lockfile', 'BLOCKED', `${name} exists but is inaccessible, unsafe, malformed, or does not match the installation manifest.`, 'Restore the matching generated release lockfile.')
    }
  }
  return check('dependency-lockfile', 'BLOCKED', 'Neither the publishable npm-shrinkwrap.json nor the source package-lock.json is present.', 'Restore the matching release lockfile.')
}

function sameWindowsPath(left, right) {
  return win32.normalize(left).toLowerCase() === win32.normalize(right).toLowerCase()
}

async function configuredRuntimeJavaCheck({
  id,
  path,
  executable,
  applicable,
  environment,
  fileSystem,
  action,
}) {
  if (!applicable) {
    return check(id, 'NOT_APPLICABLE', 'The configured Ghidra launcher does not require the Windows batch compatibility agent.')
  }
  if (path === undefined) {
    return check(id, 'NOT_CONFIGURED', 'No local executable path was supplied for this workflow.', action)
  }
  let candidates
  try {
    candidates = windowsJavaDevelopmentToolCandidates(environment, executable)
  } catch {
    return check(id, 'BLOCKED', 'The runtime Java discovery environment contains an invalid local path.', action)
  }
  let selected
  for (const candidate of candidates) {
    try {
      const endpoint = await checkedEndpoint(candidate, fileSystem)
      const size = typeof endpoint.metadata.size === 'bigint'
        ? endpoint.metadata.size
        : BigInt(endpoint.metadata.size)
      if (size < 1n || size > BigInt(MAX_JAVA_TOOL_BYTES)) {
        return check(id, 'BLOCKED', `The first runtime-discovered ${executable} candidate is empty or exceeds its fixed byte limit.`, action)
      }
      selected = endpoint.path
      break
    } catch (error) {
      if (error?.code === 'ENOENT') continue
      return check(id, 'BLOCKED', `The first existing runtime-discovered ${executable} candidate is unsafe or inaccessible.`, action)
    }
  }
  if (selected === undefined) {
    return check(id, 'BLOCKED', `${executable} is not discoverable from JAVA_HOME, JDK_HOME, or PATH.`, action)
  }
  if (!sameWindowsPath(selected, path)) {
    return check(id, 'BLOCKED', `The supplied path is not the ${executable} endpoint the reverse runtime will select.`, action)
  }
  return executableFileCheck(id, path, fileSystem, 'win32', action)
}

function dependencyMetadataCandidates(root, name) {
  const candidates = []
  const seen = new Set()
  let current = root
  for (let depth = 0; depth < 64; depth += 1) {
    const nodeModules = (process.platform === 'win32'
      ? basename(current).toLowerCase() === 'node_modules'
      : basename(current) === 'node_modules')
      ? current
      : join(current, 'node_modules')
    const candidate = join(nodeModules, name, 'package.json')
    const key = process.platform === 'win32' ? candidate.toLowerCase() : candidate
    if (!seen.has(key)) {
      candidates.push(candidate)
      seen.add(key)
    }
    const parent = dirname(current)
    if (parent === current) break
    current = parent
  }
  return candidates
}

async function installedDependencyMetadata(root, name, fileSystem) {
  for (const candidate of dependencyMetadataCandidates(root, name)) {
    try {
      return await boundedJson(candidate, READINESS_INPUT_LIMITS.json_bytes, fileSystem)
    } catch (error) {
      if (error?.code === 'ENOENT') continue
      throw error
    }
  }
  const error = new Error('installed dependency metadata is missing')
  error.code = 'ENOENT'
  throw error
}

export async function inspectReadiness({
  projectRoot,
  workerConfigPath,
  toolPaths = {},
  platform = process.platform,
  nodeVersion = process.version,
  fileSystem = fs,
  environment = process.env,
} = {}) {
  // Validate every operator-supplied endpoint before any filesystem operation.
  const normalized = normalizeReadinessPaths({ projectRoot, workerConfigPath, toolPaths })
  const root = normalized.projectRoot
  const workerPath = normalized.workerConfigPath
  const tools = normalized.toolPaths
  const runtimes = controllerRuntimePaths(platform)
  const windowsBatchGhidra = platform === 'win32'
    && tools.ghidra !== undefined
    && ['.bat', '.cmd'].includes(win32.extname(tools.ghidra).toLowerCase())
  const checks = []
  const version = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(nodeVersion)
  checks.push(check('node-runtime', version && Number(version[1]) >= 20 ? 'PASS' : 'BLOCKED',
    'The controller requires a stable Node.js version 20 or newer.', 'Use Node.js >=20 to run the controller.'))
  checks.push(check('host-platform', ['win32', 'linux', 'darwin'].includes(platform) ? 'PASS' : 'NOT_CHECKED',
    ['win32', 'linux', 'darwin'].includes(platform) ? `Static host platform observed: ${platform}.` : 'Host platform has no declared static readiness profile.',
    'Runtime compatibility still requires the existing controller checks.'))

  let manifest
  try {
    await checkedEndpoint(root, fileSystem, 'directory')
    manifest = await boundedJson(join(root, 'package.json'), READINESS_INPUT_LIMITS.json_bytes, fileSystem)
    if (
      manifest.name !== 'last-aperture'
      || typeof manifest.version !== 'string'
      || !/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(manifest.version)
      || !manifest.dependencies
      || typeof manifest.dependencies !== 'object'
      || Array.isArray(manifest.dependencies)
    ) {
      throw new Error('not a controller installation manifest')
    }
    const dependencies = Object.entries(manifest.dependencies)
    if (dependencies.length < 1 || dependencies.length > 128 || dependencies.some(([name, version]) =>
      !/^(?:@[a-z0-9][a-z0-9._-]*\/)?[a-z0-9][a-z0-9._-]*$/.test(name)
      || !/^\d+\.\d+\.\d+(?:[-+][A-Za-z0-9.-]+)?$/.test(version))) {
      throw new Error('dependency declarations are not bounded pinned package names')
    }
    checks.push(check('installation-manifest', 'PASS', 'Controller package manifest is structurally valid and declares pinned dependencies.'))
  } catch {
    manifest = null
    checks.push(check('installation-manifest', 'BLOCKED', 'Controller package manifest is missing, unsafe, oversized, or structurally invalid.', 'Use a complete local installation of The Last Aperture.'))
  }
  for (const [id, path] of [
    ['controller-entrypoint', 'scripts/audit.mjs'],
    ['engagement-entrypoint', 'scripts/engage.mjs'],
    ['engagement-route-registry', 'scripts/lib/engagement-route-registry.mjs'],
    ['http-recon-entrypoint', 'scripts/http-recon.mjs'],
    ['http-authed-entrypoint', 'scripts/http-authed.mjs'],
    ['engagement-intake-schema', 'schemas/engagement-intake.schema.json'],
    ['engagement-authority-schema', 'schemas/engagement-authority.schema.json'],
    ['engagement-manifest-schema', 'schemas/engagement-manifest.schema.json'],
    ['engagement-ledger-record-schema', 'schemas/engagement-ledger-record.schema.json'],
    ['reverse-entrypoint', 'scripts/reverse.mjs'],
    ['ghidra-exporter-source', 'scripts/ghidra/LastApertureExport.java'],
    ['frida-v1-agent', 'scripts/frida/native-call-trace-v1.js'],
    ['frida-v2-agent', 'scripts/frida/native-call-trace-v2.js'],
    ['acquisition-entrypoint', 'scripts/acquire.mjs'],
    ['bounty-entrypoint', 'scripts/bounty.mjs'],
    ['browser-bridge-manifest', 'browser/http-authed-chrome/manifest.json'],
    ['burp-extension-source', 'integrations/burp-montoya/src/main/java/dev/lastaperture/burp/LastApertureBurpExtension.java'],
    ['canonical-skill', 'skills/last-aperture/SKILL.md'],
    ['proof-worker-schema', 'schemas/proof-worker.schema.json'],
  ]) {
    checks.push(await fileCheck(id, join(root, path), fileSystem, 'Restore the required file from the matching tool release.'))
  }
  checks.push(await dependencyLockCheck(root, manifest, fileSystem))
  for (const [id, path] of [
    ['ghidra-windows-agent-source', 'scripts/ghidra/GhidraBundleLocationAgent.java.source'],
    ['ghidra-windows-agent-manifest', 'scripts/ghidra/GhidraBundleLocationAgent.mf'],
  ]) {
    checks.push(windowsBatchGhidra
      ? await fileCheck(id, join(root, path), fileSystem, 'Restore the required file from the matching tool release.')
      : check(id, 'NOT_APPLICABLE', 'The configured Ghidra launcher does not require the Windows batch compatibility agent.'))
  }
  if (manifest) {
    for (const [name, expectedVersion] of Object.entries(manifest.dependencies).sort(([left], [right]) => compareCanonicalStrings(left, right))) {
      try {
        const installed = await installedDependencyMetadata(root, name, fileSystem)
        if (installed.name !== name || installed.version !== expectedVersion) throw new Error('installed dependency mismatch')
        checks.push(check(`dependency:${name}`, 'PASS', 'Installed package metadata matches the declared pinned version; package code was not loaded.'))
      } catch {
        checks.push(check(`dependency:${name}`, 'BLOCKED', 'Installed package metadata is missing, unsafe, oversized, or does not match its pinned version.', 'Restore dependencies using the project lockfile; doctor does not install packages.'))
      }
    }
  }
  checks.push(await executableFileCheck('docker-executable', runtimes.docker, fileSystem, platform, `Install or repair the controller runtime at ${runtimes.docker}; file presence does not prove identity or daemon readiness.`))
  checks.push(await executableFileCheck('archive-executable', runtimes.archive, fileSystem, platform, `Make the controller archive utility available at ${runtimes.archive}; it is not executed by doctor.`))
  for (const [id, name, action] of [
    ['ghidra-executable', 'ghidra', 'Supply --ghidra with the exact analyzeHeadless launcher used by the reverse route.'],
    ['frida-executable', 'frida', 'Supply --frida with the exact Frida executable used by the reverse route.'],
    ['crane-executable', 'crane', 'Supply --crane with the exact Crane executable used for OCI registry acquisition.'],
  ]) checks.push(await configuredExecutableCheck(id, tools[name], fileSystem, platform, action))
  for (const [id, name, action] of [
    ['burp-desktop', 'burpDesktop', 'Supply --burp with the exact Burp desktop JAR.'],
    ['burp-extension', 'burpExtension', 'Supply --burp-extension with the compiled Last Aperture Montoya extension JAR.'],
  ]) checks.push(await configuredFileCheck(id, tools[name], fileSystem, action))
  checks.push(await configuredRuntimeJavaCheck({
    id: 'jdk-javac-executable',
    path: tools.javac,
    executable: 'javac.exe',
    applicable: windowsBatchGhidra,
    environment,
    fileSystem,
    action: 'Supply --javac with the exact JDK compiler selected from JAVA_HOME, JDK_HOME, or PATH by the Windows Ghidra compatibility agent.',
  }))
  checks.push(await configuredRuntimeJavaCheck({
    id: 'jdk-jar-executable',
    path: tools.jar,
    executable: 'jar.exe',
    applicable: windowsBatchGhidra,
    environment,
    fileSystem,
    action: 'Supply --jar with the exact JDK archive tool selected from JAVA_HOME, JDK_HOME, or PATH by the Windows Ghidra compatibility agent.',
  }))

  if (!workerPath) {
    checks.push(check('proof-worker-config', 'NOT_CONFIGURED', 'No external proof worker configuration was supplied.', 'Supply --worker <proof-worker.json> to inspect its structure without executing it.'))
  } else {
    try {
      const schema = await boundedJson(join(root, 'schemas/proof-worker.schema.json'), READINESS_INPUT_LIMITS.json_bytes, fileSystem)
      const worker = await boundedJson(workerPath, READINESS_INPUT_LIMITS.worker_bytes, fileSystem)
      if (!matchesWorkerSchema(worker, schema) || worker.runtime_path !== runtimes.docker || worker.limits.tmpfs_bytes < worker.limits.max_source_bytes) {
        throw new Error('worker configuration does not match the fixed worker contract')
      }
      checks.push(check('proof-worker-config', 'PASS', 'Worker configuration matches the static schema, fixed runtime path, image digest shape, and memory/source bounds. Values and referenced files are not disclosed.'))
    } catch {
      checks.push(check('proof-worker-config', 'BLOCKED', 'Worker configuration is missing, unsafe, oversized, malformed, or does not match the fixed worker contract.', 'Use schemas/proof-worker.schema.json, an immutable local image ID, and the controller runtime path for this host.'))
    }
  }
  for (const [id, detail, action] of [
    ['docker-daemon', 'Docker daemon availability and local context were not checked.', 'The existing proof controller verifies the local context when its route is invoked.'],
    ['runtime-identity', 'Runtime executable contents, identity, version, and behavior were not checked.', 'File presence is insufficient; the existing proof controller must verify its runtime.'],
    ['worker-image', 'Image availability, immutable identity, installed dependencies, and compatibility were not checked.', 'The existing proof controller verifies the selected local image against sealed inputs.'],
    ['target-compatibility', 'No target source, credentials, services, or deployment state were inspected.', 'Use a sealed repository inventory and its recorded environment indicators to identify unsupported shapes.'],
  ]) checks.push(check(id, 'NOT_CHECKED', detail, action))
  checks.push(check(
    'oci-registry-acquisition-controller',
    'UNAVAILABLE',
    'Public OCI registry acquisition remains disabled before argument or target access.',
    'Enable only after the acquisition route is migrated to the trusted controller.',
  ))

  const staticIds = checks.filter((item) => ['node-runtime', 'installation-manifest', 'controller-entrypoint', 'canonical-skill', 'dependency-lockfile'].includes(item.id) || item.id.startsWith('dependency:')).map((item) => item.id)
  const workflow = (id, prerequisiteIds, uncheckedIds = []) => {
    const blocking = checks.filter((item) => prerequisiteIds.includes(item.id) && item.status !== 'PASS').map((item) => item.id)
    return { id, status: blocking.length ? 'PREREQUISITES_MISSING' : 'STATIC_CHECKS_PASSED', blocking_checks: blocking, unchecked_checks: uncheckedIds }
  }
  const unavailableWorkflow = (id, blocker) => ({
    id,
    status: 'UNAVAILABLE',
    blocking_checks: [blocker],
    unchecked_checks: [],
  })
  const proofIds = [...staticIds, 'proof-worker-schema', 'docker-executable', 'archive-executable', 'proof-worker-config']
  const engagementIds = [
    ...staticIds,
    'engagement-entrypoint',
    'engagement-route-registry',
    'http-recon-entrypoint',
    'http-authed-entrypoint',
    'reverse-entrypoint',
    'engagement-intake-schema',
    'engagement-authority-schema',
    'engagement-manifest-schema',
    'engagement-ledger-record-schema',
  ]
  const ghidraIds = [
    ...staticIds,
    'reverse-entrypoint',
    'ghidra-executable',
    'ghidra-exporter-source',
    ...(windowsBatchGhidra ? [
      'jdk-javac-executable',
      'jdk-jar-executable',
      'ghidra-windows-agent-source',
      'ghidra-windows-agent-manifest',
    ] : []),
  ]
  return {
    schema_version: '1.0.0',
    assessment: 'STATIC_ONLY',
    checks,
    workflows: [
      workflow('source-review', staticIds),
      workflow('t1-proof', proofIds, ['docker-daemon', 'runtime-identity', 'worker-image', 'target-compatibility']),
      workflow('t2-service-proof', proofIds, ['docker-daemon', 'runtime-identity', 'worker-image', 'target-compatibility']),
      workflow('engagement-orchestration', engagementIds, ['target-compatibility']),
      workflow('ghidra-static-reverse', ghidraIds, ['runtime-identity', 'target-compatibility']),
      workflow('frida-local-reverse', [...staticIds, 'reverse-entrypoint', 'frida-executable', 'frida-v1-agent'], ['runtime-identity', 'target-compatibility']),
      workflow('frida-typed-reverse', [...staticIds, 'reverse-entrypoint', 'frida-executable', 'frida-v2-agent'], ['runtime-identity', 'target-compatibility']),
      workflow('web-protocol-reconstruction', [...staticIds, 'reverse-entrypoint', 'browser-bridge-manifest'], ['target-compatibility']),
      workflow('burp-proxy-history-export', [...staticIds, 'burp-extension-source', 'burp-desktop', 'burp-extension'], ['runtime-identity', 'target-compatibility']),
      unavailableWorkflow('oci-registry-acquisition', 'oci-registry-acquisition-controller'),
      workflow('bounty-controller', [...staticIds, 'bounty-entrypoint'], ['target-compatibility']),
    ],
    capabilities: capabilityRegistry(),
    limitations: [
      'Static checks never establish runtime readiness, analysis quality, authorization, or a security verdict.',
      'Doctor executes no Docker commands, target code, dependency code, network requests, or package installation.',
      'Credential files and worker-referenced files are not opened; configuration contents are not printed.',
    ],
  }
}

export function renderReadiness(report) {
  const environmentLines = report.environment_coverage ? [
    '', `Recorded environment coverage for run ${terminalSafeText(report.run_id, 256)}`,
    `  Bundle integrity: ${terminalSafeText(report.bundle_integrity, 64)}; root authenticity: ${terminalSafeText(report.root_authenticity, 64)}.`,
    `  Basis: ${terminalSafeText(report.environment_coverage.basis, 128)}; deployment evidence: ${terminalSafeText(report.environment_coverage.deployment_evidence, 64)}.`,
    ...report.environment_coverage.detected_profiles.flatMap((item) => [
      `  ${terminalSafeText(item.profile_id, 128)}: source review ${terminalSafeText(item.source_review, 64)}; execution ${terminalSafeText(item.execution_support, 64)}.`,
      `    ${terminalSafeText(item.limitation, 1024)}`,
      `    Recorded indicators (${item.matching_path_count}): ${item.matching_paths.map((path) => terminalSafeText(path, 1024)).join(', ')}`,
    ]),
    ...(report.environment_coverage.detected_profiles.length ? [] : ['  No recognized profile indicators; runtime coverage remains UNKNOWN.']),
    ...report.environment_coverage.limitations.map((item) => `  ${terminalSafeText(item, 2048)}`),
  ] : []
  return [
    'The Last Aperture doctor: static inspection only', '',
    ...report.checks.flatMap((item) => [
      `${item.status} ${item.id}: ${item.detail}`,
      ...(item.action && item.status !== 'PASS' ? [`  Next: ${item.action}`] : []),
    ]), '',
    ...report.workflows.map((item) => `${item.status} ${item.id}${item.unchecked_checks.length ? `; runtime checks still pending: ${item.unchecked_checks.join(', ')}` : ''}`),
    ...environmentLines, '',
    ...report.limitations, '',
  ].join('\n')
}
