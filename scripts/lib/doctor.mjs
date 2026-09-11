import * as fs from 'node:fs/promises'
import { constants } from 'node:fs'
import { isAbsolute, join, parse, relative, resolve } from 'node:path'

import { capabilityRegistry } from './capabilities.mjs'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { assertLocalFilesystemEndpoint } from './filesystem-endpoint.mjs'
import { terminalSafeText } from './terminal-text.mjs'

export const READINESS_INPUT_LIMITS = Object.freeze({ json_bytes: 64 * 1024, worker_bytes: 64 * 1024 })

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
  const canonical = localAbsolutePath(await fileSystem.realpath(absolute))
  if ((process.platform === 'win32' ? canonical.toLowerCase() !== absolute.toLowerCase() : canonical !== absolute)) {
    throw new Error('endpoint changed during canonical path validation')
  }
  return { path: canonical, metadata }
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs
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

export async function inspectReadiness({
  projectRoot,
  workerConfigPath,
  platform = process.platform,
  nodeVersion = process.version,
  fileSystem = fs,
} = {}) {
  // Validate every operator-supplied endpoint before any filesystem operation.
  const root = localAbsolutePath(projectRoot)
  const workerPath = workerConfigPath === undefined ? undefined : localAbsolutePath(workerConfigPath)
  const runtimes = controllerRuntimePaths(platform)
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
    if (manifest.name !== 'last-aperture' || !manifest.dependencies || typeof manifest.dependencies !== 'object' || Array.isArray(manifest.dependencies)) {
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
    ['canonical-skill', 'skills/last-aperture/SKILL.md'],
    ['dependency-lockfile', 'package-lock.json'],
    ['proof-worker-schema', 'schemas/proof-worker.schema.json'],
  ]) {
    checks.push(await fileCheck(id, join(root, path), fileSystem, 'Restore the required file from the matching tool release.'))
  }
  if (manifest) {
    for (const [name, expectedVersion] of Object.entries(manifest.dependencies).sort(([left], [right]) => compareCanonicalStrings(left, right))) {
      try {
        const installed = await boundedJson(join(root, 'node_modules', name, 'package.json'), READINESS_INPUT_LIMITS.json_bytes, fileSystem)
        if (installed.name !== name || installed.version !== expectedVersion) throw new Error('installed dependency mismatch')
        checks.push(check(`dependency:${name}`, 'PASS', 'Installed package metadata matches the declared pinned version; package code was not loaded.'))
      } catch {
        checks.push(check(`dependency:${name}`, 'BLOCKED', 'Installed package metadata is missing, unsafe, oversized, or does not match its pinned version.', 'Restore dependencies using the project lockfile; doctor does not install packages.'))
      }
    }
  }
  checks.push(await fileCheck('docker-executable', runtimes.docker, fileSystem, `Install or repair the controller runtime at ${runtimes.docker}; file presence does not prove identity or daemon readiness.`))
  checks.push(await fileCheck('archive-executable', runtimes.archive, fileSystem, `Make the controller archive utility available at ${runtimes.archive}; it is not executed by doctor.`))

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

  const staticIds = checks.filter((item) => ['node-runtime', 'installation-manifest', 'controller-entrypoint', 'canonical-skill', 'dependency-lockfile'].includes(item.id) || item.id.startsWith('dependency:')).map((item) => item.id)
  const workflow = (id, prerequisiteIds, uncheckedIds = []) => {
    const blocking = checks.filter((item) => prerequisiteIds.includes(item.id) && item.status !== 'PASS').map((item) => item.id)
    return { id, status: blocking.length ? 'PREREQUISITES_MISSING' : 'STATIC_CHECKS_PASSED', blocking_checks: blocking, unchecked_checks: uncheckedIds }
  }
  const proofIds = [...staticIds, 'proof-worker-schema', 'docker-executable', 'archive-executable', 'proof-worker-config']
  return {
    schema_version: '1.0.0',
    assessment: 'STATIC_ONLY',
    checks,
    workflows: [
      workflow('source-review', staticIds),
      workflow('t1-proof', proofIds, ['docker-daemon', 'runtime-identity', 'worker-image', 'target-compatibility']),
      workflow('t2-service-proof', proofIds, ['docker-daemon', 'runtime-identity', 'worker-image', 'target-compatibility']),
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
