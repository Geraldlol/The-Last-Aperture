import { createHash, randomUUID } from 'node:crypto'
import { constants as FS_CONSTANTS, existsSync } from 'node:fs'
import {
  lstat,
  mkdir,
  open,
  readdir,
  readFile,
  realpath,
  rmdir,
  unlink,
  writeFile,
} from 'node:fs/promises'
import { userInfo } from 'node:os'
import { basename, dirname, extname, isAbsolute, join, parse, relative, resolve } from 'node:path'
import { TextDecoder } from 'node:util'
import { fileURLToPath } from 'node:url'

import { assertLocalFilesystemEndpoint } from './filesystem-endpoint.mjs'
import { compareCanonicalStrings } from './canonical-order.mjs'
import {
  assertValidEngagementIntake,
  canonicalEngagementAuthority,
  canonicalEngagementIntake,
  canonicalEngagementJson,
  canonicalEngagementManifest,
  createEngagementIntake,
  digestEngagementIntake,
  digestEngagementManifest,
  digestEngagementValue,
  normalizeEngagementTarget,
} from './engagement-contracts.mjs'
import {
  canonicalEngagementRouteGrant,
  createEngagementAuthority,
  createEngagementManifest,
  deriveEngagementRouteGrant,
  digestEngagementAuthority,
  digestEngagementRouteGrant,
  verifyEngagementAuthority,
  verifyEngagementManifest,
  verifyEngagementRouteGrant,
} from './engagement-authorization.mjs'
import { deriveEngagementAuthHttpMaterial } from './engagement-auth-http-material.mjs'
import { openEngagementLedger } from './engagement-ledger.mjs'
import {
  bindEngagementOutput,
  digestEngagementOutputBinding,
  verifyEngagementOutputBinding,
} from './engagement-output-binding.mjs'
import {
  RepositoryWorkflowError,
  buildRepositoryAuditInvocation,
  prepareRepositoryNextWork,
  readRepositoryChildStatus,
  reconcileRepositoryWorkResult as reconcileBoundRepositoryWorkResult,
  submitRepositoryWorkResult as submitBoundRepositoryWorkResult,
  verifyRepositoryWorkEnvelope,
} from './engagement-repository-workflow.mjs'
import {
  buildEngagementRouteInvocation,
  ENGAGEMENT_ROUTE_REGISTRY_VERSION,
  getEngagementRouteRegistry,
  planEngagementRoutes,
} from './engagement-route-registry.mjs'
import { readAndVerifyHttpAuthedAuthorization } from './http-authed-contracts.mjs'
import {
  assertPageSessionAdapterCurrent,
  normalizePageSessionAdapter,
} from './page-session-adapter.mjs'
import { assertValidFridaTracePlan, canonicalFridaTracePlan } from './reverse-frida.mjs'
import { runSupervisedProcess, sanitizedProcessEnvironment } from './reverse-process.mjs'
import {
  assertValidWebSessionEvidence,
  canonicalWebSessionEvidence,
  webPathTemplate,
} from './reverse-web-har.mjs'
import {
  importVerifiedHttpAuthedSessionEvidence,
  importVerifiedHttpReconSessionEvidence,
} from './reverse-web-live.mjs'
import { PLATFORM_VERSION } from './version.mjs'

const PACKAGE_ROOT = fileURLToPath(new URL('../../', import.meta.url))
const MAX_BUNDLE_DOCUMENT_BYTES = 4 * 1024 * 1024
const MAX_WEB_EVIDENCE_BYTES = 64 * 1024 * 1024
const MAX_ROUTE_OUTPUT_BYTES = 1024 * 1024
const MAX_ROUTE_RESULT_BYTES = 64 * 1024 * 1024
const MAX_ROUTE_TIMEOUT_MS = 30 * 60 * 1000
const DEFAULT_ROUTE_TIMEOUT_MS = 15 * 60 * 1000
const MAX_INPUT_BYTES = 2 * 1024 * 1024 * 1024
const MAX_PAGE_SESSION_ADAPTER_BYTES = 128 * 1024
const ROUTE_OUTCOMES = new Set(['SUCCEEDED', 'PARTIAL', 'FAILED', 'CANCELLED_BEFORE_SEND', 'UNCERTAIN', 'STOPPED'])
const DEPENDENCY_COMPLETE = new Set(['SUCCEEDED', 'PARTIAL'])
const RESERVED_OUTPUT_MATERIAL = new Set([
  'output_directory',
  'output_path',
  'contract_path',
  'package_directory',
  'manifest_sha256',
  'web_evidence_paths',
  'reverse_evidence_paths',
  'audit_bundle_path',
])
const CONTROLLER_OWNED_MATERIAL = new Set([
  ...RESERVED_OUTPUT_MATERIAL,
  'repository_path', 'target_url', 'target_origins', 'target_path_prefix', 'operator_id',
  'lab_root', 'binary_relative_path', 'artifact_kind',
  'har_path', 'burp_path', 'trace_plan_path', 'scope_path', 'job_result_path',
  'ghidra_path', 'frida_path', 'credential_transport',
  'recon_bundle_path', 'auth_scope_path', 'auth_ledger_directory',
  'campaign_grant_sha256', 'ledger_directory', 'materials_directory',
  'trusted_ledger_record_count', 'trusted_ledger_head_sha256',
])
const AUTH_HTTP_ROUTE_ID = 'authenticated-http-browser'
const LIVE_WEB_ROUTE_ID = 'web-live-metadata-import'
const DIRECT_BROWSER_REFERENCE = /^browser:([a-p]{32})$/u

function stopMarkerPath(bundle) {
  return join(bundle, 'stop-request.json')
}

function ledgerAnchorDirectory(bundle) {
  return `${bundle}.last-aperture-heads`
}

export class EngagementControllerError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'EngagementControllerError'
    this.code = code
  }
}

function fail(code, message, options) {
  throw new EngagementControllerError(code, message, options)
}

function assertStopReason(value) {
  if (
    typeof value !== 'string'
    || value.trim() !== value
    || value.length === 0
    || Buffer.byteLength(value, 'utf8') > 16 * 1024
    || /[\u0000-\u001f\u007f]/u.test(value)
  ) fail('ENGAGEMENT_STOP_INVALID', 'stop reason must be bounded ordinary text')
  return value
}

function comparablePath(value) {
  const normalized = resolve(value)
  return process.platform === 'win32' ? normalized.toLowerCase() : normalized
}

function samePath(left, right) {
  return comparablePath(left) === comparablePath(right)
}

function inside(root, candidate) {
  const delta = relative(resolve(root), resolve(candidate))
  return delta !== '' && !delta.startsWith('..') && !isAbsolute(delta)
}

function exactFields(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const actual = Object.keys(value).sort()
  const expected = [...fields].sort()
  return actual.length === expected.length && actual.every((field, index) => field === expected[index])
}

function canonicalTimestamp(value) {
  const candidate = value instanceof Date ? value : new Date(value)
  if (Number.isNaN(candidate.valueOf())) fail('ENGAGEMENT_TIME_INVALID', 'controller clock returned an invalid time')
  return candidate.toISOString()
}

function currentTimestamp(dependencies) {
  const value = typeof dependencies.now === 'function' ? dependencies.now() : new Date()
  return canonicalTimestamp(value)
}

function currentLedgerTimestamp(ledger, dependencies) {
  const candidate = currentTimestamp(dependencies)
  const latest = ledger.snapshot().latest_at
  return latest !== null && candidate < latest ? latest : candidate
}

function controllerIdentity(dependencies) {
  const configured = typeof dependencies.operatorId === 'function'
    ? dependencies.operatorId()
    : dependencies.operatorId
  if (configured !== undefined) return configured
  let name = 'local-operator'
  try { name = userInfo().username || name } catch { /* hashed fallback remains non-secret */ }
  const digest = createHash('sha256').update(String(name), 'utf8').digest('hex').slice(0, 32)
  return `operator:${digest}`
}

function engagementIdentity(dependencies) {
  const configured = typeof dependencies.engagementId === 'function'
    ? dependencies.engagementId()
    : dependencies.engagementId
  return configured ?? `engagement:${randomUUID()}`
}

async function assertUnlinkedPath(path, { expect = 'file', maximumBytes = Number.MAX_SAFE_INTEGER } = {}) {
  const absolute = resolve(path)
  const filesystemRoot = parse(absolute).root
  let current = filesystemRoot
  let metadata
  try {
    metadata = await lstat(current, { bigint: true })
    if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
      fail('ENGAGEMENT_PATH_UNSAFE', 'filesystem root is linked or is not a directory')
    }
    const parts = relative(filesystemRoot, absolute).split(/[\\/]/u).filter(Boolean)
    for (const [index, part] of parts.entries()) {
      current = join(current, part)
      metadata = await lstat(current, { bigint: true })
      if (metadata.isSymbolicLink()) fail('ENGAGEMENT_PATH_UNSAFE', 'path crosses a symbolic link or junction')
      if (index < parts.length - 1 && !metadata.isDirectory()) {
        fail('ENGAGEMENT_PATH_UNSAFE', 'path contains a non-directory ancestor')
      }
    }
  } catch (cause) {
    if (cause instanceof EngagementControllerError) throw cause
    fail('ENGAGEMENT_PATH_UNSAFE', 'path cannot be inspected without following aliases', { cause })
  }
  if (expect === 'directory') {
    if (!metadata.isDirectory()) fail('ENGAGEMENT_PATH_UNSAFE', 'path must be a directory')
  } else if (
    !metadata.isFile()
    || metadata.isSymbolicLink()
    || metadata.nlink !== 1n
    || metadata.size < 0n
    || metadata.size > BigInt(maximumBytes)
  ) {
    fail('ENGAGEMENT_PATH_UNSAFE', 'path must be one bounded regular single-link file')
  }
  const canonical = await realpath(absolute)
  assertLocalFilesystemEndpoint(canonical, 'canonical engagement path')
  if (!samePath(canonical, absolute)) fail('ENGAGEMENT_PATH_UNSAFE', 'path is not canonical')
  return { path: absolute, metadata }
}

async function assertCanonicalDirectory(path, code) {
  assertLocalFilesystemEndpoint(path, 'engagement directory')
  const absolute = resolve(path)
  await assertUnlinkedPath(absolute, { expect: 'directory' })
  let metadata
  let canonical
  try {
    metadata = await lstat(absolute)
    canonical = await realpath(absolute)
  } catch (cause) {
    fail(code, 'engagement directory is unavailable', { cause })
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || !samePath(absolute, canonical)) {
    fail('ENGAGEMENT_BUNDLE_INVALID', 'engagement directory must be a canonical local non-link directory')
  }
  return absolute
}

async function createBundleDirectory(path) {
  assertLocalFilesystemEndpoint(path, 'engagement output directory')
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path) {
    fail('ENGAGEMENT_BUNDLE_INVALID', 'engagement output must be a canonical absolute local path')
  }
  const absolute = resolve(path)
  if (samePath(absolute, dirname(absolute))) {
    fail('ENGAGEMENT_BUNDLE_INVALID', 'engagement output cannot be a filesystem root')
  }
  await assertCanonicalDirectory(dirname(absolute), 'ENGAGEMENT_BUNDLE_PARENT_INVALID')
  try {
    await mkdir(absolute, { recursive: false, mode: 0o700 })
  } catch (cause) {
    if (cause?.code === 'EEXIST') fail('ENGAGEMENT_BUNDLE_EXISTS', 'engagement output already exists')
    fail('ENGAGEMENT_BUNDLE_CREATE_FAILED', 'engagement output could not be created', { cause })
  }
  return assertCanonicalDirectory(absolute, 'ENGAGEMENT_BUNDLE_CREATE_FAILED')
}

async function syncDirectoryEntry(path) {
  if (process.platform === 'win32') return
  const handle = await open(path, 'r')
  try {
    await handle.sync()
  } finally {
    await handle.close()
  }
}

async function writeCanonicalExclusive(path, value) {
  const bytes = typeof value === 'string' ? value : canonicalEngagementJson(value)
  try {
    const handle = await open(path, 'wx', 0o600)
    try {
      await handle.writeFile(bytes, 'utf8')
      await handle.sync()
    } finally {
      await handle.close()
    }
    await syncDirectoryEntry(dirname(path))
  } catch (cause) {
    if (cause?.code === 'EEXIST') fail('ENGAGEMENT_BUNDLE_IMMUTABLE', `refusing to overwrite ${basename(path)}`)
    if (cause instanceof EngagementControllerError) throw cause
    fail('ENGAGEMENT_BUNDLE_WRITE_FAILED', `could not write ${basename(path)}`, { cause })
  }
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
    && left.nlink === right.nlink
}

async function stableRead(path, { maximumBytes = MAX_BUNDLE_DOCUMENT_BYTES, binding } = {}) {
  assertLocalFilesystemEndpoint(path, 'engagement file')
  const absolute = resolve(path)
  let endpoint
  try { endpoint = (await assertUnlinkedPath(absolute, { maximumBytes })).metadata } catch (cause) {
    if (cause?.code === 'ENGAGEMENT_PATH_UNSAFE') {
      fail('ENGAGEMENT_BUNDLE_FILE_INVALID', `engagement file is unsafe: ${basename(path)}`, { cause })
    }
    throw cause
  }
  const flags = FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0)
  let handle
  try {
    handle = await open(absolute, flags)
    const heldBefore = await handle.stat({ bigint: true })
    if (!heldBefore.isFile() || heldBefore.nlink !== 1n || !sameFileIdentity(endpoint, heldBefore)) {
      fail('ENGAGEMENT_BUNDLE_FILE_CHANGED', `engagement file changed before read: ${basename(path)}`)
    }
    const length = Number(heldBefore.size)
    const bytes = Buffer.alloc(length + 1)
    let offset = 0
    while (offset < bytes.length) {
      const { bytesRead } = await handle.read(bytes, offset, bytes.length - offset, offset)
      if (bytesRead === 0) break
      offset += bytesRead
    }
    const heldAfter = await handle.stat({ bigint: true })
    const endpointAfter = (await assertUnlinkedPath(absolute, { maximumBytes })).metadata
    if (
      offset !== length
      || !sameFileIdentity(heldBefore, heldAfter)
      || !sameFileIdentity(heldBefore, endpointAfter)
    ) {
      fail('ENGAGEMENT_BUNDLE_FILE_CHANGED', `engagement file changed while read: ${basename(path)}`)
    }
    const result = bytes.subarray(0, length)
    if (binding !== undefined) {
      const sha256 = createHash('sha256').update(result).digest('hex')
      if (binding.size_bytes !== result.length || binding.sha256 !== sha256) {
        fail('ENGAGEMENT_INPUT_CHANGED', `bound engagement input changed: ${basename(path)}`)
      }
    }
    return result
  } finally {
    await handle?.close()
  }
}

async function stableFingerprint(path, maximumBytes = MAX_INPUT_BYTES) {
  const absolute = resolve(path)
  const endpoint = (await assertUnlinkedPath(absolute, { maximumBytes })).metadata
  const flags = FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0)
  let handle
  try {
    handle = await open(absolute, flags)
    const heldBefore = await handle.stat({ bigint: true })
    if (!heldBefore.isFile() || heldBefore.nlink !== 1n || !sameFileIdentity(endpoint, heldBefore)) {
      fail('ENGAGEMENT_INPUT_CHANGED', 'input identity changed before hashing')
    }
    const hash = createHash('sha256')
    const buffer = Buffer.allocUnsafe(1024 * 1024)
    let position = 0n
    while (position < heldBefore.size) {
      const wanted = Number(heldBefore.size - position > BigInt(buffer.length)
        ? BigInt(buffer.length)
        : heldBefore.size - position)
      const { bytesRead } = await handle.read(buffer, 0, wanted, Number(position))
      if (bytesRead === 0) break
      hash.update(buffer.subarray(0, bytesRead))
      position += BigInt(bytesRead)
    }
    const heldAfter = await handle.stat({ bigint: true })
    const endpointAfter = (await assertUnlinkedPath(absolute, { maximumBytes })).metadata
    if (position !== heldBefore.size
      || !sameFileIdentity(heldBefore, heldAfter)
      || !sameFileIdentity(heldBefore, endpointAfter)) {
      fail('ENGAGEMENT_INPUT_CHANGED', 'input identity or length changed while hashing')
    }
    return { sha256: hash.digest('hex'), size_bytes: Number(position) }
  } finally {
    await handle?.close()
  }
}

async function readCanonicalDocument(path, canonicalize, maximumBytes = MAX_BUNDLE_DOCUMENT_BYTES) {
  const bytes = await stableRead(path, { maximumBytes })
  let text
  let value
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    value = JSON.parse(text)
  } catch (cause) {
    fail('ENGAGEMENT_BUNDLE_DOCUMENT_INVALID', `${basename(path)} must contain valid UTF-8 JSON`, { cause })
  }
  let canonical
  try {
    canonical = canonicalize(value)
  } catch (cause) {
    if (cause?.code) throw cause
    fail('ENGAGEMENT_BUNDLE_DOCUMENT_INVALID', `${basename(path)} violates its contract`, { cause })
  }
  if (text !== canonical) {
    fail('ENGAGEMENT_BUNDLE_NONCANONICAL', `${basename(path)} does not contain exact canonical bytes`)
  }
  return value
}

async function readDurableStopRequest(bundle, engagementId) {
  const path = stopMarkerPath(bundle)
  if (!existsSync(path)) return null
  const value = await readCanonicalDocument(path, canonicalEngagementJson, 32 * 1024)
  if (
    !exactFields(value, ['engagement_id', 'kind', 'reason', 'requested_at', 'schema_version'])
    || value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/engagement-stop-request'
    || value.engagement_id !== engagementId
    || canonicalTimestamp(value.requested_at) !== value.requested_at
  ) fail('ENGAGEMENT_STOP_INVALID', 'durable stop request is invalid')
  assertStopReason(value.reason)
  return value
}

async function writeOrVerify(path, value, canonicalize = canonicalEngagementJson) {
  const expected = canonicalize(value)
  try {
    await writeCanonicalExclusive(path, expected)
  } catch (error) {
    if (error.code !== 'ENGAGEMENT_BUNDLE_IMMUTABLE') throw error
    const actual = await readCanonicalDocument(path, canonicalize)
    if (canonicalEngagementJson(actual) !== canonicalEngagementJson(value)) {
      fail('ENGAGEMENT_BUNDLE_BINDING_DRIFT', `${basename(path)} differs from its engagement binding`)
    }
  }
}

function intakeMatchesAuthority(intake, authority) {
  return intake.operator_id === authority.operator_id
    && intake.declared_at === authority.declared_at
    && intake.statement === authority.statement
    && intake.objective === authority.objective
    && intake.authorization_profile === authority.authorization_profile
    && canonicalEngagementJson(intake.capabilities) === canonicalEngagementJson(authority.capabilities)
    && canonicalEngagementJson(intake.effects) === canonicalEngagementJson(authority.effects)
    && canonicalEngagementJson(intake.target) === canonicalEngagementJson(authority.target)
    && canonicalEngagementJson(intake.credential_references)
      === canonicalEngagementJson(authority.credential_references)
}

function sameLocalTargetInstance(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.birthtimeNs === right.birthtimeNs
}

function digestLocalTargetInstance(metadata) {
  return createHash('sha256')
    .update(canonicalEngagementJson({
      birthtime_ns: metadata.birthtimeNs.toString(),
      device: metadata.dev.toString(),
      inode: metadata.ino.toString(),
    }), 'utf8')
    .digest('hex')
}

async function targetIntegrity(target) {
  if (target.kind !== 'repository' && target.kind !== 'artifact') return null
  const options = target.kind === 'repository'
    ? { expect: 'directory' }
    : { maximumBytes: MAX_INPUT_BYTES }
  const before = (await assertUnlinkedPath(target.locator, options)).metadata
  const fingerprint = target.kind === 'artifact'
    ? await stableFingerprint(target.locator)
    : {}
  const after = (await assertUnlinkedPath(target.locator, options)).metadata
  if (!sameLocalTargetInstance(before, after)) {
    fail('ENGAGEMENT_TARGET_CHANGED', 'local target identity changed while it was inspected')
  }
  return {
    ...fingerprint,
    instance_sha256: digestLocalTargetInstance(before),
  }
}

function buildRoutePlan({ descriptor, manifest, intake, targetIntegrity }) {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/engagement-route-plan',
    engagement_id: manifest.engagement_id,
    route_id: descriptor.id,
    route_registry_version: manifest.route_registry_version,
    target_sha256: manifest.target_sha256,
    intake_sha256: digestEngagementIntake(intake),
    target_integrity: targetIntegrity,
    order: descriptor.order,
    dependencies: [...descriptor.dependencies],
    required_material: [...descriptor.required_material],
    optional_material: [...descriptor.optional_material],
    recovery_mode: descriptor.recovery_mode,
    capability_id: descriptor.capability_id,
    availability: { ...descriptor.availability },
  }
}

function routeDirectory(bundle, routeId) {
  return join(bundle, 'routes', routeId)
}

async function ensureRouteDirectory(bundle, routeId) {
  const directory = routeDirectory(bundle, routeId)
  try {
    await mkdir(directory, { recursive: false, mode: 0o700 })
  } catch (cause) {
    if (cause?.code !== 'EEXIST') fail('ENGAGEMENT_ROUTE_DIRECTORY_FAILED', `could not create route directory ${routeId}`, { cause })
  }
  return assertCanonicalDirectory(directory, 'ENGAGEMENT_ROUTE_DIRECTORY_INVALID')
}

function routeOutputMaterial(bundle, routeId) {
  const directory = routeDirectory(bundle, routeId)
  switch (routeId) {
    case 'repository-audit': return { output_directory: join(directory, 'audit-bundle') }
    case 'https-recon': return { output_directory: join(directory, 'http-recon') }
    case 'web-live-metadata-import': return { output_directory: join(directory, 'evidence') }
    case 'web-capture-har-import': return { output_path: join(directory, 'evidence.json') }
    case 'web-capture-burp-import': return { output_path: join(directory, 'evidence.json') }
    case 'ghidra-analysis': return { output_directory: join(directory, 'reverse-evidence') }
    case 'frida-trace': return { output_directory: join(directory, 'reverse-evidence') }
    case 'protocol-build': return { output_path: join(directory, 'contract.json') }
    case 'connector-generate': return { output_directory: join(directory, 'package') }
    default: return {}
  }
}

function routeOutputSpecifications(bundle, routeId) {
  const directory = routeDirectory(bundle, routeId)
  const specifications = Object.entries(routeOutputMaterial(bundle, routeId))
    .map(([materialName, path]) => ({
      materialName,
      path,
      relativePath: relative(directory, path).replaceAll('\\', '/'),
      kind: materialName === 'output_directory' ? 'directory' : 'file',
    }))
  if (routeId === AUTH_HTTP_ROUTE_ID) {
    specifications.push(
      {
        materialName: 'scope_history',
        path: join(directory, 'scopes'),
        relativePath: 'scopes',
        kind: 'directory',
      },
      {
        materialName: 'campaign_ledger',
        path: join(directory, 'campaign-ledger'),
        relativePath: 'campaign-ledger',
        kind: 'directory',
      },
      {
        materialName: 'campaign_materials',
        path: join(directory, 'campaign-materials'),
        relativePath: 'campaign-materials',
        kind: 'directory',
      },
    )
  }
  return specifications.sort((left, right) => (
    compareCanonicalStrings(left.relativePath, right.relativePath)
  ))
}

function targetPathLiterals(target) {
  if (!['https', 'browser'].includes(target.kind)) return []
  const literals = []
  for (const rawSegment of new URL(target.locator).pathname.split('/').filter(Boolean)) {
    let segment
    try { segment = decodeURIComponent(rawSegment) } catch { continue }
    if (/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/u.test(segment)) literals.push(segment)
  }
  return [...new Set(literals)].sort()
}

function pathTemplateWithinPrefix(candidate, prefix) {
  if (prefix === '/' || candidate === prefix) return true
  return candidate.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`)
}

async function assertWebEvidenceMatchesTarget(path, target, expectedSourceSha256, expectedSourceKind) {
  let evidence
  try {
    const bytes = await stableRead(path, { maximumBytes: MAX_WEB_EVIDENCE_BYTES })
    evidence = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    assertValidWebSessionEvidence(evidence)
  } catch (cause) {
    fail('ENGAGEMENT_ROUTE_OUTPUT_INVALID', 'web capture output is not valid bounded session evidence', { cause })
  }
  const parsedTarget = new URL(target.locator)
  if (expectedSourceSha256 !== undefined && evidence.source.sha256 !== expectedSourceSha256) {
    fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'web evidence source differs from the bound engagement capture')
  }
  if (expectedSourceKind !== undefined && evidence.source.kind !== expectedSourceKind) {
    fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'web evidence provenance differs from its live engagement producer')
  }
  if (canonicalEngagementJson(evidence.origins) !== canonicalEngagementJson([parsedTarget.origin])) {
    fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'web evidence origins differ from the engagement target')
  }
  const requiredLiterals = targetPathLiterals(target)
  if (requiredLiterals.some((literal) => !evidence.path_literals.includes(literal))) {
    fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'web evidence omitted a target path literal')
  }
  const prefix = webPathTemplate(parsedTarget.pathname, { pathLiterals: evidence.path_literals })
  for (const entry of evidence.entries) {
    const scopedPaths = [entry.request]
    if (entry.response.redirect !== null) scopedPaths.push(entry.response.redirect)
    scopedPaths.push(...entry.response.destinations)
    if (scopedPaths.some((item) => (
      item.origin !== parsedTarget.origin
      || !pathTemplateWithinPrefix(item.path_template, prefix)
    ))) {
      fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'web evidence contains a path outside the engagement target prefix')
    }
  }
  return evidence
}

async function expectedLiveWebSources(context) {
  const reconDirectory = routeOutputMaterial(context.bundle, 'https-recon').output_directory
  await verifyProducedPath(context, 'https-recon', reconDirectory, 'directory')
  const target = new URL(context.manifest.target.locator)
  const projectionOptions = {
    targetOrigins: [target.origin],
    targetPathPrefix: target.pathname,
    pathLiterals: targetPathLiterals(context.manifest.target),
  }
  let reconEvidence
  try {
    reconEvidence = await importVerifiedHttpReconSessionEvidence({
      bundle: reconDirectory,
      ...projectionOptions,
    })
  } catch (cause) {
    fail('ENGAGEMENT_ROUTE_OUTPUT_INVALID', 'bound HTTP reconnaissance evidence cannot be reverified', { cause })
  }
  const expected = new Map([[
    'http-recon.json',
    {
      kind: 'HTTP_RECON',
      evidence: reconEvidence,
    },
  ]])

  const authResultPath = join(routeDirectory(context.bundle, AUTH_HTTP_ROUTE_ID), 'result.json')
  if (!existsSync(authResultPath)) return expected
  const result = await readCanonicalDocument(
    authResultPath,
    (value) => canonicalEngagementJson(assertRouteResult(value, context, AUTH_HTTP_ROUTE_ID)),
    MAX_ROUTE_RESULT_BYTES,
  )
  if (!DEPENDENCY_COMPLETE.has(result.status)) return expected
  const bindings = await verifyDeclaredRouteOutputs(context, AUTH_HTTP_ROUTE_ID, result)
  const scopeBinding = bindings.get('scopes')
  const ledgerBinding = bindings.get('campaign-ledger')
  if (
    scopeBinding === undefined
    || ledgerBinding?.root_kind !== 'directory'
    || ledgerBinding.root_relative_path !== 'campaign-ledger'
  ) {
    fail('ENGAGEMENT_ROUTE_OUTPUT_DRIFT', 'authenticated HTTP evidence bindings are incomplete')
  }
  const scopePath = await successfulAuthScopePath(context, scopeBinding)
  let authEvidence
  try {
    authEvidence = await importVerifiedHttpAuthedSessionEvidence({
      scopePath,
      ledgerDirectory: authHttpRoutePaths(context.bundle).ledger,
      ...projectionOptions,
    })
  } catch (cause) {
    fail('ENGAGEMENT_ROUTE_OUTPUT_INVALID', 'bound authenticated campaign evidence cannot be reverified', { cause })
  }
  expected.set('authenticated-campaign.json', {
    kind: 'HTTP_AUTHED_CAMPAIGN',
    evidence: authEvidence,
  })
  return expected
}

async function assertLiveWebEvidenceMatchesTarget(context, directory, binding, target) {
  const root = binding.root_relative_path
  const fileEntries = binding.entries.filter(({ entry_kind: kind }) => kind === 'file')
  const directoryEntries = binding.entries.filter(({ entry_kind: kind }) => kind === 'directory')
  const expectedSources = await expectedLiveWebSources(context)
  const expectedPaths = new Set([...expectedSources.keys()].map((name) => `${root}/${name}`))
  const descriptor = getEngagementRouteRegistry().find(({ id }) => id === LIVE_WEB_ROUTE_ID)
  const invocation = await readCanonicalDocument(
    join(routeDirectory(context.bundle, LIVE_WEB_ROUTE_ID), 'invocation.json'),
    canonicalEngagementJson,
  )
  assertFixedInvocation(descriptor, invocation)
  const authScope = optionalInvocationFlagValue(invocation, '--auth-scope')
  const authLedger = optionalInvocationFlagValue(invocation, '--auth-ledger')
  const invocationHasAuth = authScope !== undefined && authLedger !== undefined
  if (
    directoryEntries.length !== 1
    || directoryEntries[0].relative_path !== root
    || (authScope === undefined) !== (authLedger === undefined)
    || invocationHasAuth !== expectedSources.has('authenticated-campaign.json')
    || fileEntries.length !== expectedSources.size
    || fileEntries.some(({ relative_path: path }) => !expectedPaths.has(path))
    || [...expectedPaths].some((path) => !fileEntries.some(({ relative_path }) => relative_path === path))
  ) {
    fail('ENGAGEMENT_ROUTE_OUTPUT_INVALID', 'live web evidence output has an unexpected tree shape')
  }
  for (const entry of fileEntries) {
    const name = entry.relative_path.slice(root.length + 1)
    const expectedSource = expectedSources.get(name)
    const actual = await assertWebEvidenceMatchesTarget(
      join(directory, name), target, expectedSource.evidence.source.sha256, expectedSource.kind,
    )
    if (canonicalWebSessionEvidence(actual) !== canonicalWebSessionEvidence(expectedSource.evidence)) {
      fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'live web evidence differs from its verified source projection')
    }
  }
}

async function bindDeclaredRouteOutputs(context, routeId) {
  const directory = routeDirectory(context.bundle, routeId)
  const bindings = []
  for (const specification of routeOutputSpecifications(context.bundle, routeId)) {
    const binding = await bindEngagementOutput({
      routeDirectory: directory,
      relativePath: specification.relativePath,
    })
    if (binding.root_kind !== specification.kind) {
      fail('ENGAGEMENT_ROUTE_OUTPUT_INVALID', `${routeId} produced the wrong output kind`)
    }
    if (['web-capture-har-import', 'web-capture-burp-import'].includes(routeId)) {
      const extension = routeId === 'web-capture-har-import' ? ['.har'] : ['.xml']
      const source = selectInput(context.intake, 'capture', extension)
      if (source === undefined) fail('ENGAGEMENT_ROUTE_OUTPUT_INVALID', `${routeId} has no bound capture source`)
      await assertWebEvidenceMatchesTarget(specification.path, context.manifest.target, source.sha256)
      await verifyEngagementOutputBinding({ routeDirectory: directory, binding })
    }
    if (routeId === LIVE_WEB_ROUTE_ID) {
      await assertLiveWebEvidenceMatchesTarget(context, specification.path, binding, context.manifest.target)
      await verifyEngagementOutputBinding({ routeDirectory: directory, binding })
    }
    bindings.push(binding)
  }
  return bindings.sort((left, right) => compareCanonicalStrings(left.root_relative_path, right.root_relative_path))
}

async function verifyDeclaredRouteOutputs(
  context,
  routeId,
  result,
  { allowMutableRepository = false } = {},
) {
  const specifications = routeOutputSpecifications(context.bundle, routeId)
  if (!DEPENDENCY_COMPLETE.has(result.status)) {
    if (result.output_bindings.length !== 0) {
      fail('ENGAGEMENT_ROUTE_OUTPUT_DRIFT', `${routeId} has output bindings for a non-complete outcome`)
    }
    return new Map()
  }
  if (result.output_bindings.length !== specifications.length) {
    fail('ENGAGEMENT_ROUTE_OUTPUT_DRIFT', `${routeId} does not bind every declared output`)
  }
  const byRoot = new Map(result.output_bindings.map((binding) => [binding.root_relative_path, binding]))
  if (byRoot.size !== result.output_bindings.length) {
    fail('ENGAGEMENT_ROUTE_OUTPUT_DRIFT', `${routeId} contains duplicate output bindings`)
  }
  if (routeId === 'repository-audit' && allowMutableRepository) return byRoot
  for (const specification of specifications) {
    const binding = byRoot.get(specification.relativePath)
    if (binding === undefined || binding.root_kind !== specification.kind) {
      fail('ENGAGEMENT_ROUTE_OUTPUT_DRIFT', `${routeId} output binding differs from its route declaration`)
    }
    try {
      await verifyEngagementOutputBinding({
        routeDirectory: routeDirectory(context.bundle, routeId),
        binding,
      })
    } catch (cause) {
      fail('ENGAGEMENT_ROUTE_OUTPUT_DRIFT', `${routeId} output bytes changed after completion`, { cause })
    }
    if (['web-capture-har-import', 'web-capture-burp-import'].includes(routeId)) {
      const extension = routeId === 'web-capture-har-import' ? ['.har'] : ['.xml']
      const source = selectInput(context.intake, 'capture', extension)
      if (source === undefined) fail('ENGAGEMENT_ROUTE_OUTPUT_DRIFT', `${routeId} lost its bound capture source`)
      await assertWebEvidenceMatchesTarget(
        specification.path, context.manifest.target, source.sha256,
      )
    }
    if (routeId === LIVE_WEB_ROUTE_ID) {
      await assertLiveWebEvidenceMatchesTarget(context, specification.path, binding, context.manifest.target)
    }
  }
  return byRoot
}

function bindingContainsPath(binding, routeDirectoryPath, path, kind) {
  const relativePath = relative(routeDirectoryPath, path).replaceAll('\\', '/')
  return binding.entries.some((entry) => (
    entry.relative_path === relativePath && entry.entry_kind === kind
  ))
}

async function verifyProducedPath(context, routeId, path, kind) {
  const result = await readCanonicalDocument(
    join(routeDirectory(context.bundle, routeId), 'result.json'),
    (value) => canonicalEngagementJson(assertRouteResult(value, context, routeId)),
    MAX_ROUTE_RESULT_BYTES,
  )
  const bindings = await verifyDeclaredRouteOutputs(context, routeId, result)
  const binding = [...bindings.values()].find((candidate) => (
    bindingContainsPath(candidate, routeDirectory(context.bundle, routeId), path, kind)
  ))
  if (binding === undefined) {
    fail('ENGAGEMENT_ROUTE_OUTPUT_DRIFT', `${routeId} does not bind the requested downstream material`)
  }
  const relativePath = relative(routeDirectory(context.bundle, routeId), path).replaceAll('\\', '/')
  const entry = binding.entries.find((candidate) => (
    candidate.relative_path === relativePath && candidate.entry_kind === kind
  ))
  if (entry === undefined) {
    fail('ENGAGEMENT_ROUTE_OUTPUT_DRIFT', `${routeId} lost the requested downstream output entry`)
  }
  return { binding, entry, routeDirectory: routeDirectory(context.bundle, routeId) }
}

const REPOSITORY_ROUTE_ID = 'repository-audit'
const REPOSITORY_TERMINAL_STATES = new Set(['COMPLETED', 'COMPLETE_WITH_GAPS', 'FAILED', 'ABORTED'])

function repositoryWorkRoot(bundle) {
  return join(bundle, 'repository-work')
}

function repositoryWorkToken(workId) {
  if (typeof workId !== 'string' || !/^repository-work:[a-f0-9]{64}$/u.test(workId)) {
    fail('ENGAGEMENT_REPOSITORY_WORK_ID_INVALID', 'repository work identifier is invalid')
  }
  return workId.slice('repository-work:'.length)
}

async function ensureRepositoryWorkStorage(context) {
  const root = repositoryWorkRoot(context.bundle)
  for (const directory of [
    root,
    join(root, 'checkpoints'),
    join(root, 'envelopes'),
    join(root, 'receipts'),
    join(root, 'staging'),
  ]) {
    try {
      await mkdir(directory, { recursive: false, mode: 0o700 })
      await syncDirectoryEntry(dirname(directory))
    } catch (cause) {
      if (cause?.code !== 'EEXIST') {
        fail('ENGAGEMENT_REPOSITORY_STORAGE_FAILED', 'repository work storage could not be created', { cause })
      }
    }
    await assertCanonicalDirectory(directory, 'ENGAGEMENT_REPOSITORY_STORAGE_INVALID')
  }
  return {
    root,
    checkpoints: join(root, 'checkpoints'),
    envelopes: join(root, 'envelopes'),
    receipts: join(root, 'receipts'),
    staging: join(root, 'staging'),
  }
}

function repositoryEnvelopePath(storage, workId) {
  return join(storage.envelopes, `${repositoryWorkToken(workId)}.json`)
}

function repositoryReceiptPath(storage, workId) {
  return join(storage.receipts, `${repositoryWorkToken(workId)}.json`)
}

function repositoryChildBundleSha256(relativePath) {
  return createHash('sha256').update(relativePath, 'utf8').digest('hex')
}

async function discoverRepositoryChildBundle(context) {
  const outputParent = routeOutputMaterial(context.bundle, REPOSITORY_ROUTE_ID).output_directory
  await assertCanonicalDirectory(outputParent, 'ENGAGEMENT_REPOSITORY_CHILD_MISSING')
  let entries
  try {
    entries = await readdir(outputParent, { withFileTypes: true })
  } catch (cause) {
    fail('ENGAGEMENT_REPOSITORY_CHILD_MISSING', 'repository child bundle cannot be enumerated', { cause })
  }
  if (entries.length !== 1 || !entries[0].isDirectory() || entries[0].isSymbolicLink()) {
    fail('ENGAGEMENT_REPOSITORY_CHILD_AMBIGUOUS', 'repository route must contain exactly one child audit bundle')
  }
  const childBundle = await assertCanonicalDirectory(
    join(outputParent, entries[0].name),
    'ENGAGEMENT_REPOSITORY_CHILD_INVALID',
  )
  if (!inside(outputParent, childBundle)) {
    fail('ENGAGEMENT_REPOSITORY_CHILD_INVALID', 'repository child bundle escaped its controller output')
  }
  const relativePath = relative(routeDirectory(context.bundle, REPOSITORY_ROUTE_ID), childBundle).replaceAll('\\', '/')
  return {
    path: childBundle,
    relative_path: relativePath,
    sha256: repositoryChildBundleSha256(relativePath),
  }
}

function repositoryCheckpointDocument(context, operation, child, binding, status, checkpointedAt) {
  const statusSha256 = digestEngagementValue(status)
  const childTreeSha256 = digestEngagementOutputBinding(binding)
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/repository-child-checkpoint',
    engagement_id: context.manifest.engagement_id,
    route_id: REPOSITORY_ROUTE_ID,
    operation,
    child_bundle_relative_path: child.relative_path,
    child_bundle_sha256: child.sha256,
    child_tree_binding: structuredClone(binding),
    child_tree_sha256: childTreeSha256,
    child_status: structuredClone(status),
    status_sha256: statusSha256,
    child_state: status.child_state ?? status.state,
    terminal: status.terminal === true,
    checkpointed_at: checkpointedAt,
  }
}

function assertRepositoryCheckpointDocument(value, context, expected) {
  if (!exactFields(value, [
    'checkpointed_at', 'child_bundle_relative_path', 'child_bundle_sha256', 'child_state',
    'child_status', 'child_tree_binding', 'child_tree_sha256', 'engagement_id', 'kind',
    'operation', 'route_id', 'schema_version', 'status_sha256', 'terminal',
  ])
    || value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/repository-child-checkpoint'
    || value.engagement_id !== context.manifest.engagement_id
    || value.route_id !== REPOSITORY_ROUTE_ID
    || digestEngagementValue(value.child_status) !== value.status_sha256
    || digestEngagementOutputBinding(value.child_tree_binding) !== value.child_tree_sha256
    || (value.child_status.child_state ?? value.child_status.state) !== value.child_state
    || (value.child_status.terminal === true) !== value.terminal
    || (expected !== undefined && (
      value.operation !== expected.operation
      || value.child_bundle_sha256 !== expected.child_bundle_sha256
      || value.child_tree_sha256 !== expected.child_tree_sha256
      || value.status_sha256 !== expected.status_sha256
      || value.child_state !== expected.child_state
      || value.terminal !== expected.terminal
      || value.checkpointed_at !== expected.checkpointed_at
    ))) {
    fail('ENGAGEMENT_REPOSITORY_CHECKPOINT_INVALID', 'repository child checkpoint differs from its ledger binding')
  }
  const routeRoot = routeDirectory(context.bundle, REPOSITORY_ROUTE_ID)
  const childPath = resolve(routeRoot, value.child_bundle_relative_path)
  if (!inside(routeRoot, childPath) || repositoryChildBundleSha256(value.child_bundle_relative_path) !== value.child_bundle_sha256) {
    fail('ENGAGEMENT_REPOSITORY_CHECKPOINT_INVALID', 'repository child checkpoint path binding is invalid')
  }
  return { value, childPath }
}

async function readRepositoryCheckpoint(context, event) {
  const path = join(repositoryWorkRoot(context.bundle), 'checkpoints', `${event.checkpoint_sha256}.json`)
  const value = await readCanonicalDocument(path, canonicalEngagementJson, MAX_ROUTE_RESULT_BYTES)
  if (digestEngagementValue(value) !== event.checkpoint_sha256) {
    fail('ENGAGEMENT_REPOSITORY_CHECKPOINT_DRIFT', 'repository checkpoint bytes differ from the outer ledger')
  }
  return assertRepositoryCheckpointDocument(value, context, event)
}

async function verifyRepositoryCheckpointHistory(context, snapshot, { verifyCurrent = true } = {}) {
  let current = null
  for (const event of snapshot.repository.checkpoints) current = await readRepositoryCheckpoint(context, event)
  if (current !== null && verifyCurrent) {
    try {
      await verifyEngagementOutputBinding({
        routeDirectory: routeDirectory(context.bundle, REPOSITORY_ROUTE_ID),
        binding: current.value.child_tree_binding,
      })
    } catch (cause) {
      fail('ENGAGEMENT_REPOSITORY_CHILD_CHANGED', 'repository child bundle differs from its latest outer checkpoint', { cause })
    }
  }
  return current
}

async function recordRepositoryCheckpoint(context, ledger, operation, child, status, dependencies) {
  const binding = await bindEngagementOutput({
    routeDirectory: routeDirectory(context.bundle, REPOSITORY_ROUTE_ID),
    relativePath: child.relative_path,
  })
  const checkpointedAt = currentLedgerTimestamp(ledger, dependencies)
  const document = repositoryCheckpointDocument(
    context,
    operation,
    child,
    binding,
    status,
    checkpointedAt,
  )
  const checkpointSha256 = digestEngagementValue(document)
  const storage = await ensureRepositoryWorkStorage(context)
  await writeOrVerify(join(storage.checkpoints, `${checkpointSha256}.json`), document)
  await ledger.recordRepositoryChildCheckpoint({
    operation,
    childBundleSha256: child.sha256,
    childTreeSha256: document.child_tree_sha256,
    statusSha256: document.status_sha256,
    checkpointSha256,
    childState: document.child_state,
    terminal: document.terminal,
    checkpointedAt,
  })
  return { document, checkpointSha256 }
}

async function ensureInitialRepositoryCheckpoint(context, ledger, dependencies) {
  const snapshot = ledger.snapshot()
  if (snapshot.repository.current_checkpoint !== null) {
    const current = await verifyRepositoryCheckpointHistory(context, snapshot, {
      verifyCurrent: snapshot.repository.active_work?.ingest === null
        || snapshot.repository.active_work === null,
    })
    return {
      path: current.childPath,
      relative_path: current.value.child_bundle_relative_path,
      sha256: current.value.child_bundle_sha256,
    }
  }
  const route = snapshot.routes.find(({ route_id: id }) => id === REPOSITORY_ROUTE_ID)
  if (route?.outcome?.status !== 'PARTIAL') {
    fail('ENGAGEMENT_REPOSITORY_ROUTE_NOT_READY', 'repository plan route is not waiting for agent work')
  }
  const result = await readCanonicalDocument(
    join(routeDirectory(context.bundle, REPOSITORY_ROUTE_ID), 'result.json'),
    (value) => canonicalEngagementJson(assertRouteResult(value, context, REPOSITORY_ROUTE_ID)),
    MAX_ROUTE_RESULT_BYTES,
  )
  await verifyDeclaredRouteOutputs(context, REPOSITORY_ROUTE_ID, result)
  const child = await discoverRepositoryChildBundle(context)
  await recordRepositoryCheckpoint(context, ledger, 'INITIAL', child, {
    schema_version: '1.0.0',
    state: 'PLANNED',
    child_state: 'PLANNED',
    terminal: false,
  }, dependencies)
  return child
}

function artifactKind(path) {
  const extension = extname(path).toLowerCase()
  if (['.dll', '.so', '.dylib'].includes(extension)) return 'shared-library'
  if (['.bin', '.fw', '.img', '.rom'].includes(extension)) return 'firmware-image'
  return 'native-executable'
}

async function canonicalToolPath(value) {
  if (typeof value !== 'string' || value.length === 0 || !isAbsolute(value) || resolve(value) !== value) return undefined
  try {
    assertLocalFilesystemEndpoint(value, 'tool path')
    const absolute = resolve(value)
    await assertUnlinkedPath(absolute, { maximumBytes: MAX_INPUT_BYTES })
    return absolute
  } catch {
    return undefined
  }
}

async function discoverExecutable(names) {
  for (const directory of String(process.env.PATH ?? '').split(process.platform === 'win32' ? ';' : ':')) {
    if (!directory) continue
    for (const name of names) {
      const found = await canonicalToolPath(join(directory, name))
      if (found !== undefined) return found
    }
  }
  return undefined
}

async function discoverTools(dependencies) {
  const configured = dependencies.toolPaths ?? {}
  const ghidraCandidates = [
    configured.ghidra,
    process.env.GHIDRA_PATH,
    process.env.GHIDRA_HOME && join(process.env.GHIDRA_HOME, 'support', process.platform === 'win32' ? 'analyzeHeadless.bat' : 'analyzeHeadless'),
  ]
  let ghidra
  for (const candidate of ghidraCandidates) {
    ghidra = await canonicalToolPath(candidate)
    if (ghidra !== undefined) break
  }
  ghidra ??= await discoverExecutable(process.platform === 'win32'
    ? ['analyzeHeadless.bat', 'analyzeHeadless.exe']
    : ['analyzeHeadless'])

  let frida = await canonicalToolPath(configured.frida ?? process.env.FRIDA_PATH)
  frida ??= await discoverExecutable(process.platform === 'win32' ? ['frida.exe'] : ['frida'])
  return { ghidra, frida }
}

function selectInput(intake, kind, extensions = []) {
  return intake.inputs.find((input) => input.kind === kind
    && (extensions.length === 0 || extensions.includes(extname(input.locator).toLowerCase())))
}

function authHttpRoutePaths(bundle) {
  const directory = routeDirectory(bundle, AUTH_HTTP_ROUTE_ID)
  return {
    directory,
    scopes: join(directory, 'scopes'),
    ledger: join(directory, 'campaign-ledger'),
    materials: join(directory, 'campaign-materials'),
  }
}

async function configuredPageSessionAdapter(intake, now) {
  const candidates = []
  for (const input of intake.inputs.filter(({ kind }) => kind === 'configuration')) {
    if (input.size_bytes > MAX_PAGE_SESSION_ADAPTER_BYTES) continue
    let value
    try {
      const bytes = await stableRead(input.locator, {
        maximumBytes: MAX_PAGE_SESSION_ADAPTER_BYTES,
        binding: input,
      })
      value = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    } catch (cause) {
      if (cause instanceof EngagementControllerError) throw cause
      continue
    }
    if (value?.kind !== 'last-aperture/page-session-adapter') continue
    try {
      const adapter = normalizePageSessionAdapter(value)
      assertPageSessionAdapterCurrent(adapter, now)
      candidates.push(adapter)
    } catch (cause) {
      fail(
        'ENGAGEMENT_AUTH_HTTP_ADAPTER_INVALID',
        'content-bound page session adapter configuration is invalid or inactive',
        { cause },
      )
    }
  }
  if (candidates.length > 1) {
    fail(
      'ENGAGEMENT_AUTH_HTTP_ADAPTER_AMBIGUOUS',
      'engagement contains more than one valid page session adapter configuration',
    )
  }
  return candidates[0]
}

async function defaultBrowserCredentialResolver(context, now) {
  const browserReferences = context.authority.credential_references.filter((value) => (
    /^(?:browser|browser-session):/u.test(value)
  ))
  const direct = browserReferences
    .map((credentialReference) => ({
      credentialReference,
      match: DIRECT_BROWSER_REFERENCE.exec(credentialReference),
    }))
    .filter(({ match }) => match !== null)
  if (direct.length === 0) return undefined
  if (browserReferences.length !== 1 || direct.length !== 1) {
    fail(
      'ENGAGEMENT_AUTH_HTTP_CREDENTIAL_AMBIGUOUS',
      'direct browser credential resolution requires exactly one browser extension reference',
    )
  }
  const pageSessionAdapter = await configuredPageSessionAdapter(context.intake, now)
  const selected = direct[0]
  return async ({ browserCredentialReferences }) => {
    if (
      browserCredentialReferences.length !== 1
      || browserCredentialReferences[0] !== selected.credentialReference
    ) {
      fail(
        'ENGAGEMENT_AUTH_HTTP_CREDENTIAL_AMBIGUOUS',
        'browser credential references changed during material derivation',
      )
    }
    return {
      credentialReference: selected.credentialReference,
      extensionId: selected.match[1],
      ...(pageSessionAdapter === undefined ? {} : { pageSessionAdapter }),
    }
  }
}

function exactInvocationFlagValue(invocation, flag) {
  const indexes = invocation.arguments
    .map((value, index) => (value === flag ? index : -1))
    .filter((index) => index !== -1)
  if (indexes.length !== 1 || indexes[0] + 1 >= invocation.arguments.length) {
    fail(
      'ENGAGEMENT_ROUTE_OUTPUT_DRIFT',
      `authenticated HTTP invocation does not contain one ${flag} binding`,
    )
  }
  return invocation.arguments[indexes[0] + 1]
}

function optionalInvocationFlagValue(invocation, flag) {
  const indexes = invocation.arguments
    .map((value, index) => (value === flag ? index : -1))
    .filter((index) => index !== -1)
  if (indexes.length === 0) return undefined
  if (indexes.length !== 1 || indexes[0] + 1 >= invocation.arguments.length) {
    fail('ENGAGEMENT_ROUTE_OUTPUT_DRIFT', `route invocation has an invalid ${flag} binding`)
  }
  return invocation.arguments[indexes[0] + 1]
}

async function successfulAuthScopePath(context, scopeBinding) {
  const descriptor = getEngagementRouteRegistry().find(({ id }) => id === AUTH_HTTP_ROUTE_ID)
  if (descriptor === undefined) {
    fail('ENGAGEMENT_ROUTE_PLAN_DRIFT', 'authenticated HTTP route is absent from the registry')
  }
  const invocation = await readCanonicalDocument(
    join(routeDirectory(context.bundle, AUTH_HTTP_ROUTE_ID), 'invocation.json'),
    canonicalEngagementJson,
  )
  assertFixedInvocation(descriptor, invocation)
  const scopePath = exactInvocationFlagValue(invocation, '--scope')
  const grantSha256 = exactInvocationFlagValue(invocation, '--campaign-grant-sha256')
  const paths = authHttpRoutePaths(context.bundle)
  const expectedName = `scope-${grantSha256}.json`
  if (
    !/^[a-f0-9]{64}$/u.test(grantSha256)
    || !samePath(dirname(scopePath), paths.scopes)
    || basename(scopePath) !== expectedName
    || scopeBinding.root_kind !== 'directory'
    || scopeBinding.root_relative_path !== 'scopes'
    || !bindingContainsPath(
      scopeBinding,
      routeDirectory(context.bundle, AUTH_HTTP_ROUTE_ID),
      scopePath,
      'file',
    )
  ) {
    fail(
      'ENGAGEMENT_ROUTE_OUTPUT_DRIFT',
      'authenticated HTTP invocation scope is absent from its bound scope history',
    )
  }
  return scopePath
}

async function generatedMaterial(context, snapshot, dependencies) {
  const { bundle, intake, authority, manifest } = context
  const material = { operator_id: authority.operator_id }
  if (manifest.target.kind === 'repository') material.repository_path = manifest.target.locator
  if (manifest.target.kind === 'https' || manifest.target.kind === 'browser') {
    const targetUrl = new URL(manifest.target.locator)
    material.target_url = manifest.target.locator
    material.target_origins = [targetUrl.origin]
    material.target_path_prefix = targetUrl.pathname
    material.path_literals = targetPathLiterals(manifest.target)
  }
  if (manifest.target.kind === 'artifact') {
    material.lab_root = dirname(manifest.target.locator)
    material.binary_relative_path = basename(manifest.target.locator)
    material.artifact_kind = artifactKind(manifest.target.locator)
  }

  const har = selectInput(intake, 'capture', ['.har'])
  const burp = selectInput(intake, 'capture', ['.xml'])
  const tracePlan = selectInput(intake, 'plan', ['.json'])
  const configurations = intake.inputs.filter(({ kind }) => kind === 'configuration')
  const scope = configurations.find(({ locator }) => /scope/i.test(basename(locator)))
  const jobResult = configurations.find(({ locator }) => /(?:job|result)/i.test(basename(locator)))
  if (har) material.har_path = har.locator
  if (burp) material.burp_path = burp.locator
  if (tracePlan) material.trace_plan_path = tracePlan.locator
  if (scope) material.scope_path = scope.locator
  if (jobResult) material.job_result_path = jobResult.locator
  if (authority.credential_references.some((value) => value.startsWith('browser'))) {
    material.credential_transport = 'browser'
  }

  const tools = await discoverTools(dependencies)
  if (tools.ghidra) material.ghidra_path = tools.ghidra
  if (tools.frida) material.frida_path = tools.frida

  const successful = new Map(snapshot.routes
    .filter((route) => DEPENDENCY_COMPLETE.has(route.outcome?.status))
    .map((route) => [route.route_id, route]))
  const verifiedOutputs = new Map()
  for (const routeId of successful.keys()) {
    const result = await readCanonicalDocument(
      join(routeDirectory(bundle, routeId), 'result.json'),
      (value) => canonicalEngagementJson(assertRouteResult(value, context, routeId)),
      MAX_ROUTE_RESULT_BYTES,
    )
    verifiedOutputs.set(routeId, await verifyDeclaredRouteOutputs(context, routeId, result, {
      allowMutableRepository: routeId === REPOSITORY_ROUTE_ID
        && snapshot.repository.checkpoints.length > 0,
    }))
  }
  const authRoute = snapshot.routes.find(({ route_id: id }) => id === AUTH_HTTP_ROUTE_ID)
  if (
    !snapshot.stop_requested
    && !snapshot.terminal
    && context.stopMarker !== true
    && authRoute?.outcome === null
    && successful.has('https-recon')
  ) {
    const derivedAt = currentTimestamp(dependencies)
    const resolveBrowserCredential = typeof dependencies.resolveBrowserCredential === 'function'
      ? dependencies.resolveBrowserCredential
      : await defaultBrowserCredentialResolver(context, derivedAt)
    const deriveDependencies = {
      resolveBrowserCredential,
      now: () => derivedAt,
      ...(typeof dependencies.planAuthHttpScope === 'function'
        ? { planScope: dependencies.planAuthHttpScope }
        : {}),
    }
    const derived = await deriveEngagementAuthHttpMaterial({
      bundle,
      authority,
      manifest,
    }, deriveDependencies)
    if (derived.state === 'READY') Object.assign(material, derived.material)
  }
  const outputBinding = (routeId) => {
    const specification = routeOutputSpecifications(bundle, routeId)[0]
    return specification === undefined
      ? undefined
      : verifiedOutputs.get(routeId)?.get(specification.relativePath)
  }
  const browserCredentialRequested = authority.credential_references.some((value) => (
    value.startsWith('browser')
  ))
  const authRouteSettled = authRoute?.outcome !== null && authRoute?.outcome !== undefined
  if (
    successful.has('https-recon')
    && (!browserCredentialRequested || authRouteSettled)
  ) {
    material.recon_bundle_path = routeOutputMaterial(bundle, 'https-recon').output_directory
    if (successful.has(AUTH_HTTP_ROUTE_ID)) {
      const scopeBinding = verifiedOutputs.get(AUTH_HTTP_ROUTE_ID)?.get('scopes')
      const ledgerBinding = verifiedOutputs.get(AUTH_HTTP_ROUTE_ID)?.get('campaign-ledger')
      if (
        scopeBinding === undefined
        || ledgerBinding?.root_kind !== 'directory'
        || ledgerBinding.root_relative_path !== 'campaign-ledger'
      ) {
        fail(
          'ENGAGEMENT_ROUTE_OUTPUT_DRIFT',
          'authenticated HTTP outputs do not expose a bound scope history and campaign ledger',
        )
      }
      material.auth_scope_path = await successfulAuthScopePath(context, scopeBinding)
      material.auth_ledger_directory = authHttpRoutePaths(bundle).ledger
    }
  }
  const webEvidence = []
  const reverseEvidence = []
  for (const routeId of ['web-capture-har-import', 'web-capture-burp-import']) {
    const path = routeOutputMaterial(bundle, routeId).output_path
    const binding = outputBinding(routeId)
    if (binding && bindingContainsPath(binding, routeDirectory(bundle, routeId), path, 'file')) webEvidence.push(path)
  }
  const liveDirectory = routeOutputMaterial(bundle, LIVE_WEB_ROUTE_ID).output_directory
  const liveBinding = outputBinding(LIVE_WEB_ROUTE_ID)
  if (liveBinding && bindingContainsPath(
    liveBinding, routeDirectory(bundle, LIVE_WEB_ROUTE_ID), liveDirectory, 'directory',
  )) {
    for (const name of ['http-recon.json', 'authenticated-campaign.json']) {
      const path = join(liveDirectory, name)
      if (bindingContainsPath(
        liveBinding, routeDirectory(bundle, LIVE_WEB_ROUTE_ID), path, 'file',
      )) webEvidence.push(path)
    }
  }
  for (const routeId of ['ghidra-analysis', 'frida-trace']) {
    const directory = routeOutputMaterial(bundle, routeId).output_directory
    const path = join(directory, 'evidence.json')
    const binding = outputBinding(routeId)
    if (binding && bindingContainsPath(binding, routeDirectory(bundle, routeId), path, 'file')) reverseEvidence.push(path)
  }
  if (webEvidence.length > 0) material.web_evidence_paths = webEvidence
  if (reverseEvidence.length > 0) material.reverse_evidence_paths = reverseEvidence

  const contractPath = routeOutputMaterial(bundle, 'protocol-build').output_path
  const contractBinding = outputBinding('protocol-build')
  if (contractBinding && bindingContainsPath(
    contractBinding, routeDirectory(bundle, 'protocol-build'), contractPath, 'file',
  )) material.contract_path = contractPath
  const packageDirectory = routeOutputMaterial(bundle, 'connector-generate').output_directory
  const packageBinding = outputBinding('connector-generate')
  if (packageBinding && bindingContainsPath(
    packageBinding, routeDirectory(bundle, 'connector-generate'), packageDirectory, 'directory',
  )) {
    material.package_directory = packageDirectory
    const manifestPath = join(packageDirectory, 'manifest.json')
    const manifestEntry = packageBinding.entries.find((entry) => (
      entry.relative_path === relative(routeDirectory(bundle, 'connector-generate'), manifestPath).replaceAll('\\', '/')
      && entry.entry_kind === 'file'
    ))
    if (manifestEntry) material.manifest_sha256 = manifestEntry.sha256
  }
  const repositoryCheckpoint = snapshot.repository.current_checkpoint
  if (repositoryCheckpoint !== null) {
    const checkpoint = await readRepositoryCheckpoint(context, repositoryCheckpoint)
    material.audit_bundle_path = checkpoint.childPath
  } else if (successful.has(REPOSITORY_ROUTE_ID)) {
    const child = await discoverRepositoryChildBundle(context)
    material.audit_bundle_path = child.path
  }

  if (typeof dependencies.resolveMaterial === 'function') {
    const resolved = await dependencies.resolveMaterial({
      intake: structuredClone(intake),
      authority: structuredClone(authority),
      manifest: structuredClone(manifest),
      bundle,
      snapshot: structuredClone(snapshot),
    })
    if (resolved === null || typeof resolved !== 'object' || Array.isArray(resolved)) {
      fail('ENGAGEMENT_ROUTE_MATERIAL_INVALID', 'material resolver must return one plain object')
    }
    for (const [name, value] of Object.entries(resolved)) {
      if (CONTROLLER_OWNED_MATERIAL.has(name)) continue
      if (!['package_name', 'path_literals'].includes(name)) {
        fail('ENGAGEMENT_ROUTE_MATERIAL_INVALID', `material resolver cannot supply ${name}`)
      }
      if (name === 'path_literals') {
        if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
          fail('ENGAGEMENT_ROUTE_MATERIAL_INVALID', 'path_literals must be an array of strings')
        }
        material.path_literals = [...new Set([...(material.path_literals ?? []), ...value])].sort()
      } else {
        material[name] = value
      }
    }
  }
  return material
}

function materialForRoute(descriptor, allMaterial, bundle) {
  const selected = {}
  for (const name of [...descriptor.required_material, ...descriptor.optional_material]) {
    if (Object.hasOwn(allMaterial, name)) selected[name] = allMaterial[name]
  }
  Object.assign(selected, routeOutputMaterial(bundle, descriptor.id))
  return selected
}

function boundInputForPath(intake, path) {
  return intake.inputs.find((input) => samePath(input.locator, path))
}

async function verifyBoundPath(intake, path, label) {
  const binding = boundInputForPath(intake, path)
  if (binding === undefined) fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', `${label} is not a content-bound engagement input`)
  const current = await stableFingerprint(binding.locator, MAX_INPUT_BYTES)
  if (current.sha256 !== binding.sha256 || current.size_bytes !== binding.size_bytes) {
    fail('ENGAGEMENT_INPUT_CHANGED', `${label} changed after engagement intake`)
  }
  return binding
}

async function validateFridaTarget(context, planPath, dependencies = {}) {
  const binding = await verifyBoundPath(context.intake, planPath, 'Frida trace plan')
  const bytes = await stableRead(binding.locator, { maximumBytes: MAX_BUNDLE_DOCUMENT_BYTES, binding })
  let plan
  try {
    plan = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
    assertValidFridaTracePlan(plan)
  } catch (cause) {
    fail('ENGAGEMENT_FRIDA_PLAN_INVALID', 'Frida trace plan is invalid', { cause })
  }
  const artifactPath = resolve(plan.artifact.lab_root, plan.artifact.path)
  const target = context.manifest.target
  let artifactBinding
  if (target.kind === 'artifact') {
    if (!samePath(artifactPath, target.locator) || plan.target.mode !== 'local-spawn') {
      fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'Frida plan must spawn the exact artifact target')
    }
    artifactBinding = { kind: 'artifact', locator: target.locator, ...context.targetIntegrity }
  } else {
    const currentTarget = await normalizeEngagementTarget({ kind: target.kind, locator: target.locator }, dependencies)
    if (canonicalEngagementJson(currentTarget) !== canonicalEngagementJson(target)) {
      fail('ENGAGEMENT_TARGET_CHANGED', 'runtime target instance changed before Frida dispatch')
    }
    artifactBinding = await verifyBoundPath(context.intake, artifactPath, 'Frida plan artifact')
    if (target.kind === 'process') {
      const pid = /^pid:(\d+)$/.exec(target.locator)
      if (!(pid && plan.target.mode === 'local-pid' && plan.target.pid === Number(pid[1]))) {
        fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'Frida plan process selector differs from the engagement target')
      }
    } else if (target.kind === 'device') {
      const device = /^id:(.+)$/.exec(target.locator)
      if (!(device && plan.target.mode.startsWith('device-') && plan.target.device_id === device[1])) {
        fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'Frida plan device selector differs from the engagement target')
      }
    }
  }
  return { plan, artifactBinding }
}

async function ensureMaterialDirectory(context, routeId) {
  const directory = join(routeDirectory(context.bundle, routeId), 'material')
  try {
    await mkdir(directory, { recursive: false, mode: 0o700 })
  } catch (cause) {
    if (cause?.code !== 'EEXIST') fail('ENGAGEMENT_ROUTE_MATERIAL_INVALID', 'route material directory could not be created', { cause })
  }
  await assertCanonicalDirectory(directory, 'ENGAGEMENT_ROUTE_MATERIAL_INVALID')
  return directory
}

async function stageBoundInput(context, routeId, binding, name) {
  const materialDirectory = await ensureMaterialDirectory(context, routeId)
  const extension = extname(binding.locator).toLowerCase().replace(/[^.a-z0-9]/gu, '')
  const destination = join(materialDirectory, `${name}-${binding.sha256.slice(0, 24)}${extension}`)
  const source = resolve(binding.locator)
  const endpoint = (await assertUnlinkedPath(source, { maximumBytes: MAX_INPUT_BYTES })).metadata
  const readFlags = FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0)
  let input
  let output
  let created = false
  try {
    input = await open(source, readFlags)
    const heldBefore = await input.stat({ bigint: true })
    if (!heldBefore.isFile() || heldBefore.nlink !== 1n || !sameFileIdentity(endpoint, heldBefore)) {
      fail('ENGAGEMENT_INPUT_CHANGED', 'bound input changed before staging')
    }
    try {
      output = await open(destination, 'wx', 0o600)
      created = true
    } catch (cause) {
      if (cause?.code !== 'EEXIST') throw cause
    }
    if (created) {
      const hash = createHash('sha256')
      const buffer = Buffer.allocUnsafe(1024 * 1024)
      let position = 0n
      while (position < heldBefore.size) {
        const remaining = heldBefore.size - position
        const wanted = Number(remaining > BigInt(buffer.length) ? BigInt(buffer.length) : remaining)
        const { bytesRead } = await input.read(buffer, 0, wanted, Number(position))
        if (bytesRead === 0) break
        await output.write(buffer, 0, bytesRead, Number(position))
        hash.update(buffer.subarray(0, bytesRead))
        position += BigInt(bytesRead)
      }
      const heldAfter = await input.stat({ bigint: true })
      const endpointAfter = (await assertUnlinkedPath(source, { maximumBytes: MAX_INPUT_BYTES })).metadata
      if (position !== heldBefore.size
        || !sameFileIdentity(heldBefore, heldAfter)
        || !sameFileIdentity(heldBefore, endpointAfter)
        || Number(position) !== binding.size_bytes
        || hash.digest('hex') !== binding.sha256) {
        fail('ENGAGEMENT_INPUT_CHANGED', 'bound input changed while it was staged')
      }
      await output.sync()
    }
  } catch (cause) {
    if (cause instanceof EngagementControllerError) throw cause
    fail('ENGAGEMENT_ROUTE_MATERIAL_INVALID', 'bound input could not be staged', { cause })
  } finally {
    await input?.close()
    await output?.close()
  }
  const staged = await stableFingerprint(destination, MAX_INPUT_BYTES)
  if (staged.sha256 !== binding.sha256 || staged.size_bytes !== binding.size_bytes) {
    fail('ENGAGEMENT_ROUTE_MATERIAL_INVALID', 'staged input differs from its intake binding')
  }
  return destination
}

async function copyBoundFile(source, destination, expected, label) {
  const endpoint = (await assertUnlinkedPath(source, { maximumBytes: MAX_INPUT_BYTES })).metadata
  const flags = FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0)
  let input
  let output
  let created = false
  let failure
  try {
    input = await open(source, flags)
    const heldBefore = await input.stat({ bigint: true })
    if (
      !heldBefore.isFile()
      || heldBefore.nlink !== 1n
      || !sameFileIdentity(endpoint, heldBefore)
      || Number(heldBefore.size) !== expected.size_bytes
    ) {
      fail('ENGAGEMENT_ROUTE_OUTPUT_CHANGED', `${label} changed before downstream staging`)
    }
    output = await open(destination, 'wx', 0o600)
    created = true
    const hash = createHash('sha256')
    const buffer = Buffer.allocUnsafe(1024 * 1024)
    let position = 0n
    while (position < heldBefore.size) {
      const remaining = heldBefore.size - position
      const wanted = Number(remaining > BigInt(buffer.length) ? BigInt(buffer.length) : remaining)
      const { bytesRead } = await input.read(buffer, 0, wanted, Number(position))
      if (bytesRead === 0) break
      await output.write(buffer, 0, bytesRead, Number(position))
      hash.update(buffer.subarray(0, bytesRead))
      position += BigInt(bytesRead)
    }
    const heldAfter = await input.stat({ bigint: true })
    const endpointAfter = (await assertUnlinkedPath(source, { maximumBytes: MAX_INPUT_BYTES })).metadata
    if (
      position !== heldBefore.size
      || !sameFileIdentity(heldBefore, heldAfter)
      || !sameFileIdentity(heldBefore, endpointAfter)
      || Number(position) !== expected.size_bytes
      || hash.digest('hex') !== expected.sha256
    ) {
      fail('ENGAGEMENT_ROUTE_OUTPUT_CHANGED', `${label} changed while downstream bytes were staged`)
    }
    await output.sync()
  } catch (cause) {
    failure = cause
  } finally {
    await input?.close()
    await output?.close()
  }
  if (failure !== undefined) {
    if (created) {
      try { await unlink(destination) } catch {}
    }
    if (failure instanceof EngagementControllerError) throw failure
    fail('ENGAGEMENT_ROUTE_MATERIAL_INVALID', `${label} could not be staged for downstream use`, { cause: failure })
  }
  const staged = await stableFingerprint(destination, MAX_INPUT_BYTES)
  if (staged.sha256 !== expected.sha256 || staged.size_bytes !== expected.size_bytes) {
    fail('ENGAGEMENT_ROUTE_MATERIAL_INVALID', `${label} staged bytes differ from their producer binding`)
  }
  return destination
}

function bindingContent(binding) {
  const root = binding.root_relative_path
  return binding.entries.map((entry) => {
    const contentPath = entry.relative_path === root
      ? ''
      : entry.relative_path.slice(root.length + 1)
    return {
      path: contentPath,
      kind: entry.entry_kind,
      size_bytes: entry.size_bytes,
      sha256: entry.sha256,
    }
  }).sort((left, right) => compareCanonicalStrings(left.path, right.path))
}

async function stageProducedFile(context, routeId, producerRouteId, source, name) {
  const produced = await verifyProducedPath(context, producerRouteId, source, 'file')
  const directory = await ensureMaterialDirectory(context, routeId)
  const extension = extname(source).toLowerCase().replace(/[^.a-z0-9]/gu, '')
  const destination = join(directory, `${name}-${produced.entry.sha256.slice(0, 24)}${extension}`)
  return copyBoundFile(source, destination, produced.entry, `${producerRouteId} output`)
}

async function stageProducedDirectory(context, routeId, producerRouteId, source, name) {
  const produced = await verifyProducedPath(context, producerRouteId, source, 'directory')
  const materialDirectory = await ensureMaterialDirectory(context, routeId)
  const destination = join(materialDirectory, `${name}-${produced.entry.sha256.slice(0, 24)}`)
  try {
    await mkdir(destination, { recursive: false, mode: 0o700 })
    const root = produced.binding.root_relative_path
    const relativeEntries = produced.binding.entries.map((entry) => ({
      ...entry,
      content_path: entry.relative_path === root
        ? ''
        : entry.relative_path.slice(root.length + 1),
    }))
    const directories = relativeEntries
      .filter((entry) => entry.entry_kind === 'directory' && entry.content_path !== '')
      .sort((left, right) => {
        const depth = left.content_path.split('/').length - right.content_path.split('/').length
        return depth || compareCanonicalStrings(left.content_path, right.content_path)
      })
    for (const entry of directories) {
      await mkdir(join(destination, ...entry.content_path.split('/')), { recursive: false, mode: 0o700 })
    }
    const files = relativeEntries
      .filter((entry) => entry.entry_kind === 'file')
      .sort((left, right) => compareCanonicalStrings(left.content_path, right.content_path))
    for (const entry of files) {
      await copyBoundFile(
        join(source, ...entry.content_path.split('/')),
        join(destination, ...entry.content_path.split('/')),
        entry,
        `${producerRouteId} output file`,
      )
    }
    const stagedBinding = await bindEngagementOutput({
      routeDirectory: routeDirectory(context.bundle, routeId),
      relativePath: relative(routeDirectory(context.bundle, routeId), destination).replaceAll('\\', '/'),
    })
    if (
      stagedBinding.entry_count !== produced.binding.entry_count
      || stagedBinding.total_size_bytes !== produced.binding.total_size_bytes
      || canonicalEngagementJson(bindingContent(stagedBinding))
        !== canonicalEngagementJson(bindingContent(produced.binding))
    ) {
      fail('ENGAGEMENT_ROUTE_MATERIAL_INVALID', `${producerRouteId} staged tree differs from its producer binding`)
    }
    return destination
  } catch (cause) {
    try { await removeStagedEntry(materialDirectory, destination) } catch {}
    if (cause instanceof EngagementControllerError) throw cause
    fail('ENGAGEMENT_ROUTE_MATERIAL_INVALID', `${producerRouteId} output tree could not be staged`, { cause })
  }
}

async function prepareRouteMaterial(context, descriptor, material, dependencies) {
  await validateRouteMaterial(context, descriptor, material, dependencies)
  const prepared = structuredClone(material)
  const cleanup = []
  for (const [field, name] of [
    ['har_path', 'har'],
    ['burp_path', 'burp'],
    ['scope_path', 'scope'],
    ['job_result_path', 'job-result'],
  ]) {
    if (prepared[field] === undefined) continue
    if (descriptor.id === AUTH_HTTP_ROUTE_ID && field === 'scope_path') continue
    const binding = await verifyBoundPath(context.intake, prepared[field], field)
    prepared[field] = await stageBoundInput(context, descriptor.id, binding, name)
    cleanup.push(prepared[field])
  }
  if (descriptor.id === 'ghidra-analysis') {
    const binding = {
      kind: 'artifact', locator: context.manifest.target.locator, ...context.targetIntegrity,
    }
    const staged = await stageBoundInput(context, descriptor.id, binding, 'target')
    cleanup.push(staged)
    prepared.lab_root = dirname(staged)
    prepared.binary_relative_path = basename(staged)
  }
  if (descriptor.id === 'frida-trace') {
    const { plan, artifactBinding } = await validateFridaTarget(context, material.trace_plan_path, dependencies)
    const stagedArtifact = await stageBoundInput(context, descriptor.id, artifactBinding, 'target')
    cleanup.push(stagedArtifact)
    const stagedPlan = structuredClone(plan)
    stagedPlan.artifact.lab_root = dirname(stagedArtifact)
    stagedPlan.artifact.path = basename(stagedArtifact)
    const stagedPlanPath = join(await ensureMaterialDirectory(context, descriptor.id), 'trace-plan.json')
    await writeOrVerify(stagedPlanPath, stagedPlan, canonicalFridaTracePlan)
    prepared.trace_plan_path = stagedPlanPath
    cleanup.push(stagedPlanPath)
  }
  if (descriptor.id === LIVE_WEB_ROUTE_ID) {
    prepared.recon_bundle_path = await stageProducedDirectory(
      context, descriptor.id, 'https-recon', prepared.recon_bundle_path, 'http-recon',
    )
    cleanup.push(prepared.recon_bundle_path)
    if (prepared.auth_scope_path !== undefined) {
      prepared.auth_scope_path = await stageProducedFile(
        context, descriptor.id, AUTH_HTTP_ROUTE_ID, prepared.auth_scope_path, 'auth-scope',
      )
      cleanup.push(prepared.auth_scope_path)
      prepared.auth_ledger_directory = await stageProducedDirectory(
        context, descriptor.id, AUTH_HTTP_ROUTE_ID, prepared.auth_ledger_directory, 'auth-ledger',
      )
      cleanup.push(prepared.auth_ledger_directory)
    }
  }
  if (descriptor.id === 'protocol-build') {
    for (const [field, producers, prefix] of [
      ['web_evidence_paths', [LIVE_WEB_ROUTE_ID, 'web-capture-har-import', 'web-capture-burp-import'], 'web-evidence'],
      ['reverse_evidence_paths', ['ghidra-analysis', 'frida-trace'], 'reverse-evidence'],
    ]) {
      const stagedPaths = []
      for (const [index, source] of (prepared[field] ?? []).entries()) {
        const producer = producers.find((candidate) => {
          const output = routeOutputMaterial(context.bundle, candidate)
          return output.output_path !== undefined
            ? samePath(output.output_path, source)
            : inside(output.output_directory, source)
        })
        if (producer === undefined) {
          fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', `${field} has no declared producer`)
        }
        const staged = await stageProducedFile(
          context, descriptor.id, producer, source, `${prefix}-${index + 1}`,
        )
        stagedPaths.push(staged)
        cleanup.push(staged)
      }
      if (stagedPaths.length > 0) prepared[field] = stagedPaths
    }
  }
  if (descriptor.id === 'connector-generate') {
    prepared.contract_path = await stageProducedFile(
      context, descriptor.id, 'protocol-build', prepared.contract_path, 'contract',
    )
    cleanup.push(prepared.contract_path)
  }
  if (descriptor.id === 'connector-verify') {
    prepared.package_directory = await stageProducedDirectory(
      context, descriptor.id, 'connector-generate', prepared.package_directory, 'package',
    )
    cleanup.push(prepared.package_directory)
  }
  return { material: prepared, cleanup }
}

async function removeStagedEntry(materialDirectory, path) {
  if (!inside(materialDirectory, path)) {
    fail('ENGAGEMENT_ROUTE_CLEANUP_INVALID', 'staged cleanup path escaped its route material directory')
  }
  let metadata
  try { metadata = await lstat(path, { bigint: true }) } catch (cause) {
    if (cause?.code === 'ENOENT') return
    fail('ENGAGEMENT_ROUTE_CLEANUP_FAILED', 'staged route material could not be inspected', { cause })
  }
  if (metadata.isSymbolicLink()) {
    fail('ENGAGEMENT_ROUTE_CLEANUP_INVALID', 'staged route material became a link before cleanup')
  }
  if (metadata.isFile()) {
    if (metadata.nlink !== 1n) {
      fail('ENGAGEMENT_ROUTE_CLEANUP_INVALID', 'staged route material gained an unexpected hard link')
    }
    await unlink(path)
    return
  }
  if (!metadata.isDirectory()) {
    fail('ENGAGEMENT_ROUTE_CLEANUP_INVALID', 'staged route material became a special file before cleanup')
  }
  const canonical = await realpath(path)
  if (!samePath(canonical, path)) {
    fail('ENGAGEMENT_ROUTE_CLEANUP_INVALID', 'staged route material directory became an alias')
  }
  const names = await readdir(path)
  for (const name of names) {
    if (name === '.' || name === '..' || /[\\/]/u.test(name)) {
      fail('ENGAGEMENT_ROUTE_CLEANUP_INVALID', 'staged route material contains an invalid entry')
    }
    await removeStagedEntry(materialDirectory, join(path, name))
  }
  await rmdir(path)
}

async function cleanupStagedMaterial(context, routeId, paths) {
  const materialDirectory = join(routeDirectory(context.bundle, routeId), 'material')
  for (const path of [...paths].reverse()) {
    try {
      await removeStagedEntry(materialDirectory, path)
    } catch (cause) {
      if (cause?.code !== 'ENOENT') {
        if (cause instanceof EngagementControllerError) throw cause
        fail('ENGAGEMENT_ROUTE_CLEANUP_FAILED', 'staged route material could not be removed', { cause })
      }
    }
  }
  try { await rmdir(materialDirectory) } catch (cause) {
    if (cause?.code !== 'ENOENT') fail('ENGAGEMENT_ROUTE_CLEANUP_FAILED', 'route material directory is not empty after cleanup', { cause })
  }
}

async function cleanupAnyStagedMaterial(context, routeId) {
  const directory = join(routeDirectory(context.bundle, routeId), 'material')
  let names
  try { names = await readdir(directory) } catch (cause) {
    if (cause?.code === 'ENOENT') return
    throw cause
  }
  const paths = names.map((name) => {
    if (name === '.' || name === '..' || /[\\/]/u.test(name)) {
      fail('ENGAGEMENT_ROUTE_CLEANUP_INVALID', 'route material contains an invalid entry')
    }
    return join(directory, name)
  })
  await cleanupStagedMaterial(context, routeId, paths)
}

async function verifyAuthHttpRouteMaterial(context, material, dependencies) {
  const paths = authHttpRoutePaths(context.bundle)
  if (
    !samePath(material.ledger_directory, paths.ledger)
    || !samePath(material.materials_directory, paths.materials)
    || !samePath(dirname(material.scope_path), paths.scopes)
    || basename(material.scope_path) !== `scope-${material.campaign_grant_sha256}.json`
    || material.operator_id !== context.authority.operator_id
    || material.credential_transport !== 'browser'
  ) {
    fail(
      'ENGAGEMENT_ROUTE_SCOPE_INVALID',
      'authenticated HTTP material differs from its controller-owned route binding',
    )
  }
  await Promise.all([
    assertCanonicalDirectory(paths.scopes, 'ENGAGEMENT_ROUTE_SCOPE_INVALID'),
    assertCanonicalDirectory(paths.ledger, 'ENGAGEMENT_ROUTE_SCOPE_INVALID'),
    assertCanonicalDirectory(paths.materials, 'ENGAGEMENT_ROUTE_SCOPE_INVALID'),
  ])
  await assertUnlinkedPath(material.scope_path, {
    expect: 'file',
    maximumBytes: MAX_BUNDLE_DOCUMENT_BYTES,
  })
  let verified
  try {
    verified = await readAndVerifyHttpAuthedAuthorization({
      scopePath: material.scope_path,
      requiredMode: 'OPERATOR_ATTESTED_AUTHED',
      now: new Date(currentTimestamp(dependencies)),
    })
  } catch (cause) {
    fail(
      'ENGAGEMENT_ROUTE_SCOPE_INVALID',
      'authenticated HTTP scope is invalid or outside its authorization window',
      { cause },
    )
  }
  const target = new URL(context.manifest.target.locator)
  if (
    verified.campaignGrantSha256 !== material.campaign_grant_sha256
    || verified.scope.engagement_id !== context.manifest.engagement_id
    || verified.scope.authorization.operator_id !== context.authority.operator_id
    || verified.scope.target.origin !== target.origin
    || canonicalEngagementJson(verified.scope.authorization.authorized_scope.origins)
      !== canonicalEngagementJson([target.origin])
    || canonicalEngagementJson(verified.scope.authorization.authorized_scope.path_prefixes)
      !== canonicalEngagementJson([target.pathname])
  ) {
    fail(
      'ENGAGEMENT_ROUTE_SCOPE_INVALID',
      'authenticated HTTP scope grant differs from the engagement authority or target',
    )
  }
}

async function validateRouteMaterial(context, descriptor, material, dependencies = {}) {
  const { bundle, intake, manifest } = context
  const expectedOutput = routeOutputMaterial(bundle, descriptor.id)
  for (const [name, value] of Object.entries(expectedOutput)) {
    if (!samePath(material[name], value) || !(samePath(bundle, dirname(value)) || inside(bundle, value))) {
      fail('ENGAGEMENT_ROUTE_OUTPUT_INVALID', `${descriptor.id} output must stay inside its engagement route directory`)
    }
  }
  if (descriptor.id === 'repository-audit' && !samePath(material.repository_path, manifest.target.locator)) {
    fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'repository route differs from the engagement target')
  }
  if (descriptor.id === 'https-recon' && material.target_url !== manifest.target.locator) {
    fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'HTTPS route differs from the engagement target')
  }
  if (descriptor.id === LIVE_WEB_ROUTE_ID) {
    const target = new URL(manifest.target.locator)
    if (
      canonicalEngagementJson(material.target_origins) !== canonicalEngagementJson([target.origin])
      || material.target_path_prefix !== target.pathname
    ) {
      fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'live web metadata scope differs from the engagement target')
    }
    if ((material.auth_scope_path === undefined) !== (material.auth_ledger_directory === undefined)) {
      fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'live authenticated metadata requires both bound auth inputs')
    }
    await verifyProducedPath(context, 'https-recon', material.recon_bundle_path, 'directory')
    if (material.auth_scope_path !== undefined) {
      await verifyProducedPath(context, AUTH_HTTP_ROUTE_ID, material.auth_scope_path, 'file')
      await verifyProducedPath(context, AUTH_HTTP_ROUTE_ID, material.auth_ledger_directory, 'directory')
    }
  }
  if (['web-capture-har-import', 'web-capture-burp-import'].includes(descriptor.id)) {
    const inputPath = descriptor.id === 'web-capture-har-import' ? material.har_path : material.burp_path
    await verifyBoundPath(intake, inputPath, 'web capture')
    const expectedOrigins = [new URL(manifest.target.locator).origin]
    if (canonicalEngagementJson(material.target_origins) !== canonicalEngagementJson(expectedOrigins)) {
      fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'capture import origins differ from the engagement target')
    }
    if (material.target_path_prefix !== new URL(manifest.target.locator).pathname) {
      fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'capture import path prefix differs from the engagement target')
    }
  }
  if (descriptor.id === 'ghidra-analysis') {
    if (!samePath(resolve(material.lab_root, material.binary_relative_path), manifest.target.locator)) {
      fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'Ghidra artifact differs from the engagement target')
    }
    const expected = await targetIntegrity(manifest.target)
    if (canonicalEngagementJson(expected) !== canonicalEngagementJson(context.targetIntegrity)) {
      fail('ENGAGEMENT_TARGET_CHANGED', 'artifact target changed after engagement planning')
    }
  }
  if (descriptor.id === 'frida-trace') await validateFridaTarget(context, material.trace_plan_path, dependencies)
  if (descriptor.id === AUTH_HTTP_ROUTE_ID) {
    await verifyAuthHttpRouteMaterial(context, material, dependencies)
  } else if (material.scope_path !== undefined) {
    await verifyBoundPath(intake, material.scope_path, 'authenticated scope')
  }
  if (material.job_result_path !== undefined) await verifyBoundPath(intake, material.job_result_path, 'agent job result')
  if (material.audit_bundle_path !== undefined && !inside(bundle, material.audit_bundle_path)) {
    fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', 'agent-host audit bundle must be produced inside this engagement')
  }
  if (material.audit_bundle_path !== undefined) {
    await verifyProducedPath(context, 'repository-audit', material.audit_bundle_path, 'directory')
  }
  for (const name of ['web_evidence_paths', 'reverse_evidence_paths']) {
    for (const path of material[name] ?? []) {
      if (!inside(bundle, path)) fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', `${name} must come from this engagement`)
      const candidates = name === 'web_evidence_paths'
        ? [LIVE_WEB_ROUTE_ID, 'web-capture-har-import', 'web-capture-burp-import']
        : ['ghidra-analysis', 'frida-trace']
      const source = candidates.find((routeId) => {
        const output = routeOutputMaterial(bundle, routeId)
        return output.output_path !== undefined
          ? samePath(output.output_path, path)
          : inside(output.output_directory, path)
      })
      if (source === undefined) fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', `${name} has no declared producer`)
      await verifyProducedPath(context, source, path, 'file')
    }
  }
  for (const name of ['contract_path', 'package_directory']) {
    if (material[name] !== undefined && !inside(bundle, material[name])) {
      fail('ENGAGEMENT_ROUTE_SCOPE_INVALID', `${name} must come from this engagement`)
    }
  }
  if (material.contract_path !== undefined) {
    await verifyProducedPath(context, 'protocol-build', material.contract_path, 'file')
  }
  if (material.package_directory !== undefined) {
    await verifyProducedPath(context, 'connector-generate', material.package_directory, 'directory')
  }
}

function assertFixedInvocation(descriptor, invocation) {
  if (
    !exactFields(invocation, ['public_entrypoint', 'arguments', 'shell'])
    || invocation.public_entrypoint !== descriptor.invocation.public_entrypoint
    || invocation.public_entrypoint !== process.execPath
    || invocation.shell !== false
    || !Array.isArray(invocation.arguments)
    || invocation.arguments.length < 1
    || invocation.arguments.some((value) => typeof value !== 'string' || value.includes('\0'))
    || invocation.arguments[0] !== descriptor.invocation.argument_vector[0]
  ) {
    fail('ENGAGEMENT_INVOCATION_INVALID', 'route invocation does not match its fixed public entrypoint')
  }
  const script = resolve(invocation.arguments[0])
  if (!inside(PACKAGE_ROOT, script)) {
    fail('ENGAGEMENT_INVOCATION_INVALID', 'route invocation script is outside The Last Aperture package')
  }
  return invocation
}

async function executeFixedRoute({ invocation, timeoutMs = DEFAULT_ROUTE_TIMEOUT_MS, stopMarker }) {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_ROUTE_TIMEOUT_MS) {
    fail('ENGAGEMENT_ROUTE_LIMIT_INVALID', 'route timeout is outside controller bounds')
  }
  try {
    const result = await runSupervisedProcess({
      file: invocation.public_entrypoint,
      args: invocation.arguments,
      cwd: PACKAGE_ROOT,
      env: sanitizedProcessEnvironment(),
      timeoutMs,
      maxOutputBytes: MAX_ROUTE_OUTPUT_BYTES,
      stopMarkerPath: stopMarker,
    })
    const started = result.started === true
    const requestMayHaveBeenSent = started
    const terminationUnconfirmed = started && result.termination_confirmed !== true
    let status
    let errorCode
    if (result.stop_requested) {
      status = terminationUnconfirmed ? 'UNCERTAIN' : 'STOPPED'
      errorCode = terminationUnconfirmed ? 'ROUTE_TERMINATION_UNCONFIRMED' : 'OPERATOR_STOPPED'
    } else if (result.output_limit_exceeded || result.log_limit_exceeded) {
      status = requestMayHaveBeenSent ? 'UNCERTAIN' : 'FAILED'
      errorCode = 'OUTPUT_LIMIT_EXCEEDED'
    } else if (result.log_integrity_failed) {
      status = requestMayHaveBeenSent ? 'UNCERTAIN' : 'FAILED'
      errorCode = 'ROUTE_LOG_INTEGRITY_FAILED'
    } else if (result.timed_out) {
      status = requestMayHaveBeenSent ? 'UNCERTAIN' : 'CANCELLED_BEFORE_SEND'
      errorCode = 'ROUTE_TIMEOUT'
    } else if (result.spawn_error) {
      status = requestMayHaveBeenSent ? 'UNCERTAIN' : 'CANCELLED_BEFORE_SEND'
      errorCode = 'ROUTE_SPAWN_FAILED'
    } else if (terminationUnconfirmed) {
      status = 'UNCERTAIN'
      errorCode = 'ROUTE_TERMINATION_UNCONFIRMED'
    }
    return {
      status,
      started,
      termination_confirmed: result.termination_confirmed === true,
      exitCode: Number.isInteger(result.code) ? result.code : null,
      signal: typeof result.signal === 'string' ? result.signal : null,
      timedOut: result.timed_out === true,
      requestMayHaveBeenSent,
      stdout: result.stdout,
      stderr: result.stderr,
      ...(errorCode === undefined ? {} : { errorCode }),
    }
  } catch (error) {
    return {
      status: 'CANCELLED_BEFORE_SEND', exitCode: null, signal: null, timedOut: false,
      started: false, termination_confirmed: false,
      requestMayHaveBeenSent: false, stdout: '', stderr: error.message,
      errorCode: 'ROUTE_SPAWN_FAILED',
    }
  }
}

function assertFixedRepositoryInvocation(action, invocation) {
  const commands = new Set(['next', 'status', 'check-result', 'ingest', 'finalize', 'validate'])
  if (
    !commands.has(action)
    || !exactFields(invocation, ['public_entrypoint', 'arguments', 'shell'])
    || invocation.public_entrypoint !== process.execPath
    || invocation.shell !== false
    || !Array.isArray(invocation.arguments)
    || invocation.arguments.length < 3
    || invocation.arguments.some((value) => typeof value !== 'string' || value.includes('\0'))
    || invocation.arguments[1] !== action
    || !inside(PACKAGE_ROOT, resolve(invocation.arguments[0]))
    || basename(invocation.arguments[0]) !== 'audit.mjs'
  ) fail('ENGAGEMENT_REPOSITORY_INVOCATION_INVALID', 'repository work action is not a fixed audit CLI invocation')
  return invocation
}

function repositoryExecutor(context, dependencies, { allowStoppedReadOnly = false } = {}) {
  return async ({ action, invocation }) => {
    assertFixedRepositoryInvocation(action, invocation)
    const stoppedReadOnly = allowStoppedReadOnly && ['check-result', 'status'].includes(action)
    const stopRequest = await readDurableStopRequest(context.bundle, context.manifest.engagement_id)
    const live = (await openLedger(context)).snapshot()
    if ((stopRequest !== null || live.stop_requested || live.terminal) && !stoppedReadOnly) {
      const error = new Error('engagement is stopped before repository work action')
      error.code = 'ENGAGEMENT_STOP_BEFORE_SEND'
      error.requestMayHaveBeenSent = false
      throw error
    }
    const execute = dependencies.executeRepositoryAction ?? (async ({ invocation: fixed }) => (
      executeFixedRoute({
        invocation: fixed,
        timeoutMs: dependencies.routeTimeoutMs ?? DEFAULT_ROUTE_TIMEOUT_MS,
        stopMarker: stoppedReadOnly ? undefined : stopMarkerPath(context.bundle),
      })
    ))
    const result = await execute({
      action,
      invocation: structuredClone(invocation),
      bundle: context.bundle,
      binding: bindingFor(context),
    })
    const afterStop = await readDurableStopRequest(context.bundle, context.manifest.engagement_id)
    if (afterStop !== null && !stoppedReadOnly && result?.requestMayHaveBeenSent !== true) {
      const error = new Error('engagement stopped before repository work action sent')
      error.code = 'ENGAGEMENT_STOP_BEFORE_SEND'
      error.requestMayHaveBeenSent = false
      throw error
    }
    const stdout = boundedText(result?.stdout)
    const stderr = boundedText(result?.stderr)
    if (stdout.exceeded || stderr.exceeded) {
      const error = new Error('repository work action exceeded the controller output limit')
      error.code = 'ENGAGEMENT_REPOSITORY_OUTPUT_LIMIT'
      error.requestMayHaveBeenSent = result?.requestMayHaveBeenSent === true
      throw error
    }
    return { ...result, stdout: stdout.value, stderr: stderr.value }
  }
}

async function executeRepositoryAction(context, action, childBundle, dependencies) {
  const invocation = assertFixedRepositoryInvocation(
    action,
    buildRepositoryAuditInvocation(action, { childBundle }),
  )
  let result
  try {
    result = await repositoryExecutor(context, dependencies)({ action, invocation })
  } catch (cause) {
    fail('ENGAGEMENT_REPOSITORY_ACTION_FAILED', `repository ${action} action failed`, { cause })
  }
  const supervisorStatusRejected = typeof result?.status === 'string'
    && !['SUCCEEDED', 'PARTIAL'].includes(result.status)
  const supervisorError = typeof result?.errorCode === 'string' && result.errorCode.length > 0
  const terminationRejected = result?.termination_confirmed === false
    || result?.terminationConfirmed === false
    || (
      result?.started === true
      && result?.termination_confirmed !== true
      && result?.terminationConfirmed !== true
    )
  if (
    result === null
    || typeof result !== 'object'
    || !Number.isSafeInteger(result.exitCode)
    || result.exitCode !== 0
    || typeof result.stdout !== 'string'
    || typeof result.stderr !== 'string'
    || result.timedOut === true
    || (result.signal !== undefined && result.signal !== null)
    || supervisorStatusRejected
    || supervisorError
    || terminationRejected
  ) fail('ENGAGEMENT_REPOSITORY_ACTION_FAILED', `repository ${action} action did not complete successfully`)
  return result
}

function boundedText(value) {
  const bytes = Buffer.isBuffer(value)
    ? value
    : Buffer.from(typeof value === 'string' ? value : value == null ? '' : String(value), 'utf8')
  if (bytes.length <= MAX_ROUTE_OUTPUT_BYTES) return { value: bytes.toString('utf8'), exceeded: false }
  return { value: bytes.subarray(0, MAX_ROUTE_OUTPUT_BYTES).toString('utf8'), exceeded: true }
}

function semanticRouteStatus(routeId, value, stdout) {
  let declared = ROUTE_OUTCOMES.has(value.status) ? value.status : undefined
  if (declared === undefined && stdout.value.trim().length > 0) {
    try {
      const parsed = JSON.parse(stdout.value)
      if (ROUTE_OUTCOMES.has(parsed?.status)) declared = parsed.status
      else if (parsed?.status === 'PLANNED') declared = 'PARTIAL'
    } catch { /* unstructured child output is evidence, not a success assertion */ }
  }
  const exitCode = value.exitCode ?? value.code
  if (declared === undefined) declared = exitCode === 0 ? 'PARTIAL' : 'FAILED'
  if (routeId === 'repository-audit' && declared === 'SUCCEEDED') declared = 'PARTIAL'
  return declared
}

function normalizeRunnerResult(raw, completedAt, routeId) {
  const value = raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {}
  const stdout = boundedText(value.stdout)
  const stderr = boundedText(value.stderr)
  const stdoutBytes = Buffer.isBuffer(value.stdout)
    ? value.stdout
    : Buffer.from(typeof value.stdout === 'string' ? value.stdout : value.stdout == null ? '' : String(value.stdout), 'utf8')
  const stderrBytes = Buffer.isBuffer(value.stderr)
    ? value.stderr
    : Buffer.from(typeof value.stderr === 'string' ? value.stderr : value.stderr == null ? '' : String(value.stderr), 'utf8')
  const requestMayHaveBeenSent = value.requestMayHaveBeenSent === true || value.request_may_have_been_sent === true
  const timedOut = value.timedOut === true || value.timed_out === true
  let status = semanticRouteStatus(routeId, value, stdout)
  let errorCode = typeof value.errorCode === 'string' ? value.errorCode : null
  if (stdout.exceeded || stderr.exceeded) {
    status = requestMayHaveBeenSent ? 'UNCERTAIN' : 'FAILED'
    errorCode = 'OUTPUT_LIMIT_EXCEEDED'
  } else if (timedOut) {
    status = requestMayHaveBeenSent ? 'UNCERTAIN' : 'CANCELLED_BEFORE_SEND'
    errorCode ??= 'ROUTE_TIMEOUT'
  }
  if (status === 'PARTIAL' && errorCode === null) {
    errorCode = routeId === 'repository-audit' ? 'ROUTE_PLANNED_ONLY' : 'ROUTE_SEMANTICS_UNVERIFIED'
  }
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/engagement-route-result',
    engagement_id: value.engagementId,
    route_id: value.routeId,
    status,
    exit_code: Number.isInteger(value.exitCode) ? value.exitCode : Number.isInteger(value.code) ? value.code : null,
    signal: typeof value.signal === 'string' ? value.signal : null,
    timed_out: timedOut,
    request_may_have_been_sent: requestMayHaveBeenSent,
    error_code: errorCode,
    stdout_sha256: createHash('sha256').update(stdoutBytes).digest('hex'),
    stdout_bytes: stdoutBytes.length,
    stderr_sha256: createHash('sha256').update(stderrBytes).digest('hex'),
    stderr_bytes: stderrBytes.length,
    output_bindings: [],
    completed_at: completedAt,
  }
}

function assertRouteResult(value, context, routeId) {
  if (
    !exactFields(value, [
      'completed_at', 'engagement_id', 'error_code', 'exit_code', 'kind',
      'request_may_have_been_sent', 'route_id', 'schema_version', 'signal',
      'status', 'stderr_bytes', 'stderr_sha256', 'stdout_bytes', 'stdout_sha256', 'timed_out',
      'output_bindings',
    ])
    || value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/engagement-route-result'
    || value.engagement_id !== context.manifest.engagement_id
    || value.route_id !== routeId
    || !ROUTE_OUTCOMES.has(value.status)
    || typeof value.request_may_have_been_sent !== 'boolean'
    || typeof value.timed_out !== 'boolean'
    || ![null, 'string'].includes(value.signal === null ? null : typeof value.signal)
    || !(value.exit_code === null || Number.isInteger(value.exit_code))
    || !(value.error_code === null || typeof value.error_code === 'string')
    || !/^[a-f0-9]{64}$/.test(value.stdout_sha256 ?? '')
    || !/^[a-f0-9]{64}$/.test(value.stderr_sha256 ?? '')
    || !Number.isSafeInteger(value.stdout_bytes) || value.stdout_bytes < 0
    || !Number.isSafeInteger(value.stderr_bytes) || value.stderr_bytes < 0
    || !Array.isArray(value.output_bindings)
    || canonicalTimestamp(value.completed_at) !== value.completed_at
  ) {
    fail('ENGAGEMENT_ROUTE_RESULT_INVALID', `route result is invalid for ${routeId}`)
  }
  return value
}

function executionFailure(context, routeId, error, completedAt) {
  const requestMayHaveBeenSent = error?.requestMayHaveBeenSent === true || error?.request_may_have_been_sent === true
  const stderr = Buffer.from(error?.message ?? 'route execution failed', 'utf8')
  return assertRouteResult({
    schema_version: '1.0.0', kind: 'last-aperture/engagement-route-result',
    engagement_id: context.manifest.engagement_id, route_id: routeId,
    status: requestMayHaveBeenSent
      ? 'UNCERTAIN'
      : error?.code === 'ENGAGEMENT_STOP_BEFORE_SEND' ? 'CANCELLED_BEFORE_SEND' : 'FAILED',
    exit_code: null, signal: null, timed_out: false,
    request_may_have_been_sent: requestMayHaveBeenSent,
    error_code: typeof error?.code === 'string' ? error.code : 'ROUTE_EXECUTION_FAILED',
    stdout_sha256: createHash('sha256').update('').digest('hex'), stdout_bytes: 0,
    stderr_sha256: createHash('sha256').update(stderr).digest('hex'), stderr_bytes: stderr.length,
    output_bindings: [],
    completed_at: completedAt,
  }, context, routeId)
}

const engagementMutexes = new Map()

function delay(milliseconds) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds))
}

function processIsAlive(pid) {
  if (!Number.isSafeInteger(pid) || pid < 1) return null
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    if (error?.code === 'ESRCH') return false
    return true
  }
}

async function reclaimDeadDispatchLease(path) {
  let before
  let record
  try {
    before = await lstat(path, { bigint: true })
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size > 4096n) return false
    const bytes = await stableRead(path, { maximumBytes: 4096 })
    record = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes))
  } catch {
    return false
  }
  if (
    !exactFields(record, ['acquired_at', 'kind', 'nonce', 'owner_pid', 'schema_version'])
    || record.schema_version !== '1.0.0'
    || record.kind !== 'last-aperture/engagement-dispatch-lease'
    || processIsAlive(record.owner_pid) !== false
  ) return false
  const after = await lstat(path, { bigint: true })
  if (!sameFileIdentity(before, after)) return false
  await unlink(path)
  return true
}

async function acquireDispatchLease(bundle, dependencies) {
  const timeoutMs = dependencies.dispatchLeaseTimeoutMs ?? 10_000
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > MAX_ROUTE_TIMEOUT_MS + 10 * 60 * 1000) {
    fail('ENGAGEMENT_DISPATCH_LEASE_INVALID', 'dispatch lease wait is outside controller bounds')
  }
  const path = join(bundle, '.engagement-dispatch.lock')
  const deadline = Date.now() + timeoutMs
  for (;;) {
    let handle
    try {
      handle = await open(path, 'wx', 0o600)
      const record = canonicalEngagementJson({
        schema_version: '1.0.0',
        kind: 'last-aperture/engagement-dispatch-lease',
        owner_pid: process.pid,
        nonce: randomUUID(),
        acquired_at: new Date().toISOString(),
      })
      await handle.writeFile(record, 'utf8')
      await handle.sync()
      const identity = await handle.stat({ bigint: true })
      return async () => {
        await handle.close()
        const current = await lstat(path, { bigint: true })
        if (!sameFileIdentity(identity, current)) {
          fail('ENGAGEMENT_DISPATCH_LEASE_CHANGED', 'dispatch lease identity changed before release')
        }
        await unlink(path)
      }
    } catch (cause) {
      await handle?.close()
      if (cause?.code !== 'EEXIST') {
        if (cause instanceof EngagementControllerError) throw cause
        fail('ENGAGEMENT_DISPATCH_LEASE_FAILED', 'dispatch lease could not be acquired', { cause })
      }
      if (await reclaimDeadDispatchLease(path)) continue
      if (Date.now() >= deadline) {
        fail('ENGAGEMENT_DISPATCH_LEASE_BUSY', 'another controller still owns the engagement dispatch lease')
      }
      await delay(25)
    }
  }
}

async function withEngagementMutex(bundle, operation, dependencies = {}) {
  const key = comparablePath(bundle)
  const prior = engagementMutexes.get(key) ?? Promise.resolve()
  let release
  const current = new Promise((resolvePromise) => { release = resolvePromise })
  const tail = prior.then(() => current)
  engagementMutexes.set(key, tail)
  await prior
  let releaseLease
  try {
    releaseLease = await acquireDispatchLease(bundle, dependencies)
    return await operation()
  } finally {
    await releaseLease?.()
    release()
    if (engagementMutexes.get(key) === tail) engagementMutexes.delete(key)
  }
}

function bindingFor(context) {
  return {
    engagement_id: context.manifest.engagement_id,
    authority_sha256: context.manifest.authority_sha256,
    target_sha256: context.manifest.target_sha256,
  }
}

async function openLedger(context, expectedHead) {
  return openEngagementLedger({
    directory: join(context.bundle, 'ledger'),
    anchorDirectory: ledgerAnchorDirectory(context.bundle),
    binding: bindingFor(context),
    initialize: false,
    ...(expectedHead === undefined ? {} : { expectedHead }),
  })
}

async function reconcileInterruptedRoutes(context, ledger, dependencies) {
  for (const route of ledger.snapshot().routes) {
    if (route.permit_sha256 === null || route.outcome !== null) continue
    const resultPath = join(routeDirectory(context.bundle, route.route_id), 'result.json')
    let result
    try {
      result = await readCanonicalDocument(resultPath, (value) => canonicalEngagementJson(
        assertRouteResult(value, context, route.route_id),
      ), MAX_ROUTE_RESULT_BYTES)
    } catch (error) {
      if (error.code !== 'ENGAGEMENT_BUNDLE_FILE_INVALID') throw error
      result = assertRouteResult({
        schema_version: '1.0.0', kind: 'last-aperture/engagement-route-result',
        engagement_id: context.manifest.engagement_id, route_id: route.route_id,
        status: 'UNCERTAIN', exit_code: null, signal: null, timed_out: false,
        request_may_have_been_sent: true,
        error_code: 'INTERRUPTED_AFTER_DISPATCH_PERMIT',
        stdout_sha256: createHash('sha256').update('').digest('hex'), stdout_bytes: 0,
        stderr_sha256: createHash('sha256').update('').digest('hex'), stderr_bytes: 0,
        output_bindings: [],
        completed_at: currentLedgerTimestamp(ledger, dependencies),
      }, context, route.route_id)
      await writeCanonicalExclusive(resultPath, canonicalEngagementJson(result))
    }
    await verifyDeclaredRouteOutputs(context, route.route_id, result)
    await cleanupAnyStagedMaterial(context, route.route_id)
    await ledger.recordRouteOutcome({
      routeId: route.route_id,
      planSha256: route.plan_sha256,
      status: result.status,
      resultSha256: digestEngagementValue(result),
      requestMayHaveBeenSent: result.request_may_have_been_sent,
      completedAt: result.completed_at,
    })
  }
}

async function planAllRoutes(context, ledger, dependencies) {
  const descriptors = getEngagementRouteRegistry().filter((descriptor) => (
    descriptor.applicability.target_kinds.includes(context.manifest.target.kind)
    && context.authority.capabilities.includes(descriptor.id)
  ))
  let snapshot = ledger.snapshot()
  const recorded = new Map(snapshot.routes.map((route) => [route.route_id, route]))
  for (const descriptor of descriptors) {
    const directory = await ensureRouteDirectory(context.bundle, descriptor.id)
    const plan = buildRoutePlan({
      descriptor,
      manifest: context.manifest,
      intake: context.intake,
      targetIntegrity: context.targetIntegrity,
    })
    const planSha256 = digestEngagementValue(plan)
    await writeOrVerify(join(directory, 'plan.json'), plan)
    const existing = recorded.get(descriptor.id)
    if (existing === undefined) {
      snapshot = await ledger.recordRoutePlan({
        routeId: descriptor.id,
        planSha256,
        plannedAt: currentLedgerTimestamp(ledger, dependencies),
      })
      recorded.set(descriptor.id, snapshot.routes.find(({ route_id: id }) => id === descriptor.id))
    } else if (existing.plan_sha256 !== planSha256) {
      fail('ENGAGEMENT_ROUTE_PLAN_DRIFT', `route plan changed for ${descriptor.id}`)
    }
  }
  return descriptors
}

async function recordWaiting(ledger, route, reasonCode, dependencies) {
  if (route.state === 'WAITING' && route.waiting?.reason_code === reasonCode) return
  await ledger.recordRouteWaiting({
    routeId: route.route_id,
    planSha256: route.plan_sha256,
    reasonCode,
    waitingAt: currentLedgerTimestamp(ledger, dependencies),
  })
}

async function dispatchRoute(context, ledger, descriptor, material, dependencies) {
  return withEngagementMutex(context.bundle, async () => {
    let liveLedger = await openLedger(context)
    const trusted = liveLedger.snapshot()
    liveLedger = await openLedger(context, {
      recordCount: trusted.record_count,
      headSha256: trusted.head_sha256,
    })
    const live = liveLedger.snapshot()
    if (live.stop_requested || live.terminal || existsSync(stopMarkerPath(context.bundle))) return false
    const route = live.routes.find(({ route_id: id }) => id === descriptor.id)
    if (route === undefined || route.outcome !== null || route.permit_sha256 !== null) return false
    const prepared = await prepareRouteMaterial(context, descriptor, material, dependencies)
    const routeDirectoryPath = routeDirectory(context.bundle, descriptor.id)
    let result
    let permitRecorded = false
    try {
      const invocation = assertFixedInvocation(
        descriptor,
        buildEngagementRouteInvocation(descriptor.id, prepared.material),
      )
      const invocationSha256 = digestEngagementValue(invocation)
      await writeOrVerify(join(routeDirectoryPath, 'invocation.json'), invocation)
      const grant = deriveEngagementRouteGrant({
        manifest: context.manifest,
        authority: context.authority,
        routeId: descriptor.id,
        planSha256: route.plan_sha256,
        invocationSha256,
      })
      await writeOrVerify(
        join(routeDirectoryPath, 'grant.json'),
        grant,
        (value) => canonicalEngagementRouteGrant(value, {
          manifest: context.manifest,
          authority: context.authority,
          routeId: descriptor.id,
          planSha256: route.plan_sha256,
          invocationSha256,
        }),
      )
      liveLedger.assertDispatchAllowed({ routeId: descriptor.id, planSha256: route.plan_sha256 })
      if (existsSync(stopMarkerPath(context.bundle))) return false
      const permitSha256 = digestEngagementRouteGrant(grant, {
        manifest: context.manifest,
        authority: context.authority,
        routeId: descriptor.id,
        planSha256: route.plan_sha256,
        invocationSha256,
      })
      await liveLedger.recordDispatchPermit({
        routeId: descriptor.id,
        planSha256: route.plan_sha256,
        permitSha256,
        permittedAt: currentLedgerTimestamp(liveLedger, dependencies),
      })
      permitRecorded = true
      if (existsSync(stopMarkerPath(context.bundle))) {
        const stopped = new Error('operator stop was recorded before route launch')
        stopped.code = 'ENGAGEMENT_STOP_BEFORE_SEND'
        throw stopped
      }
      const executeRoute = dependencies.executeRoute ?? executeFixedRoute
      const raw = await executeRoute({
        routeId: descriptor.id,
        invocation: structuredClone(invocation),
        bundle: context.bundle,
        binding: bindingFor(context),
        plan: structuredClone(await readCanonicalDocument(
          join(routeDirectoryPath, 'plan.json'),
          canonicalEngagementJson,
        )),
        grant: structuredClone(grant),
        timeoutMs: dependencies.routeTimeoutMs ?? DEFAULT_ROUTE_TIMEOUT_MS,
        stopMarker: stopMarkerPath(context.bundle),
      })
      const completedAt = currentLedgerTimestamp(liveLedger, dependencies)
      result = normalizeRunnerResult({
        ...raw,
        engagementId: context.manifest.engagement_id,
        routeId: descriptor.id,
      }, completedAt, descriptor.id)
      if (DEPENDENCY_COMPLETE.has(result.status)) {
        result.output_bindings = await bindDeclaredRouteOutputs(context, descriptor.id)
      }
      assertRouteResult(result, context, descriptor.id)
    } catch (error) {
      if (!permitRecorded) throw error
      result = executionFailure(
        context,
        descriptor.id,
        error,
        currentLedgerTimestamp(liveLedger, dependencies),
      )
    } finally {
      try {
        await cleanupStagedMaterial(context, descriptor.id, prepared.cleanup)
      } catch (cleanupError) {
        if (!permitRecorded) throw cleanupError
        result = executionFailure(
          context,
          descriptor.id,
          cleanupError,
          currentLedgerTimestamp(liveLedger, dependencies),
        )
      }
    }
    const resultPath = join(routeDirectoryPath, 'result.json')
    await writeCanonicalExclusive(resultPath, canonicalEngagementJson(result))
    await liveLedger.recordRouteOutcome({
      routeId: descriptor.id,
      planSha256: route.plan_sha256,
      status: result.status,
      resultSha256: digestEngagementValue(result),
      requestMayHaveBeenSent: result.request_may_have_been_sent,
      completedAt: result.completed_at,
    })
    ledger._reload?.()
    return true
  }, dependencies)
}

async function schedule(context, ledger, dependencies) {
  await reconcileInterruptedRoutes(context, ledger, dependencies)
  const descriptors = await planAllRoutes(context, ledger, dependencies)
  const blocked = new Map()
  while (true) {
    let snapshot = ledger.snapshot()
    context.stopMarker = existsSync(stopMarkerPath(context.bundle))
    if (snapshot.stop_requested || snapshot.terminal || context.stopMarker) break
    const allMaterial = await generatedMaterial(context, snapshot, dependencies)
    const completedRoutes = snapshot.routes
      .filter((route) => DEPENDENCY_COMPLETE.has(route.outcome?.status))
      .map((route) => route.route_id)
    const availableMaterial = new Set(Object.keys(allMaterial))
    for (const descriptor of descriptors) {
      for (const name of Object.keys(routeOutputMaterial(context.bundle, descriptor.id))) {
        availableMaterial.add(name)
      }
    }
    const plan = planEngagementRoutes({
      targetKinds: [context.manifest.target.kind],
      availableMaterial,
      completedRoutes,
    })
    let dispatched = false
    for (const descriptor of descriptors) {
      snapshot = ledger.snapshot()
      context.stopMarker = existsSync(stopMarkerPath(context.bundle))
      if (snapshot.stop_requested || snapshot.terminal || context.stopMarker) break
      const route = snapshot.routes.find(({ route_id: id }) => id === descriptor.id)
      if (route?.outcome !== null || route?.permit_sha256 !== null || blocked.has(descriptor.id)) continue
      const planned = plan.find(({ route_id: id }) => id === descriptor.id)
      if (planned.status !== 'READY') continue
      const material = materialForRoute(descriptor, allMaterial, context.bundle)
      try {
        dispatched = await dispatchRoute(context, ledger, descriptor, material, dependencies) || dispatched
      } catch (error) {
        if (String(error?.code ?? '').startsWith('ENGAGEMENT_ROUTE_')
          || String(error?.code ?? '').startsWith('ENGAGEMENT_FRIDA_')) {
          blocked.set(descriptor.id, 'MATERIAL_INVALID')
          continue
        }
        throw error
      }
    }
    if (dispatched) continue

    snapshot = ledger.snapshot()
    const refreshedMaterial = await generatedMaterial(context, snapshot, dependencies)
    const refreshedCompleted = snapshot.routes
      .filter((route) => DEPENDENCY_COMPLETE.has(route.outcome?.status))
      .map((route) => route.route_id)
    const finalAvailableMaterial = new Set(Object.keys(refreshedMaterial))
    for (const descriptor of descriptors) {
      for (const name of Object.keys(routeOutputMaterial(context.bundle, descriptor.id))) {
        finalAvailableMaterial.add(name)
      }
    }
    const finalPlan = planEngagementRoutes({
      targetKinds: [context.manifest.target.kind],
      availableMaterial: finalAvailableMaterial,
      completedRoutes: refreshedCompleted,
    })
    for (const route of snapshot.routes) {
      const liveSnapshot = ledger.snapshot()
      if (liveSnapshot.terminal || liveSnapshot.stop_requested) break
      const liveRoute = liveSnapshot.routes.find(({ route_id: id }) => id === route.route_id)
      if (liveRoute === undefined || liveRoute.outcome !== null || liveRoute.permit_sha256 !== null) continue
      if (route.outcome !== null || route.permit_sha256 !== null) continue
      const state = finalPlan.find(({ route_id: id }) => id === route.route_id)
      const reason = blocked.get(route.route_id)
        ?? (state.status === 'UNAVAILABLE'
          ? state.unavailable_reason
          : state.status === 'WAITING_FOR_DEPENDENCY'
            ? 'DEPENDENCY_UNSETTLED'
            : 'MATERIAL_UNAVAILABLE')
      await recordWaiting(ledger, liveRoute, reason, dependencies)
    }
    break
  }
  let finalSnapshot = ledger.snapshot()
  if (
    !finalSnapshot.terminal
    && !finalSnapshot.stop_requested
    && finalSnapshot.routes.length > 0
    && finalSnapshot.routes.every((route) => route.outcome !== null)
    && !finalSnapshot.routes.some((route) => (
      route.route_id === 'repository-audit'
      && route.outcome?.status === 'PARTIAL'
      && finalSnapshot.repository.current_checkpoint?.terminal !== true
    ))
  ) {
    await withEngagementMutex(context.bundle, async () => {
      const liveLedger = await openLedger(context)
      const live = liveLedger.snapshot()
      if (live.terminal || live.stop_requested || live.routes.some((route) => route.outcome === null)) return
      const status = live.routes.every((route) => route.outcome.status === 'SUCCEEDED')
        ? 'COMPLETED'
        : 'COMPLETED_WITH_GAPS'
      const terminal = {
        schema_version: '1.0.0',
        kind: 'last-aperture/engagement-terminal-result',
        engagement_id: context.manifest.engagement_id,
        status,
        reason: 'all applicable registered routes settled',
        terminal_at: currentLedgerTimestamp(liveLedger, dependencies),
      }
      await writeOrVerify(join(context.bundle, 'terminal.json'), terminal)
      await liveLedger.recordTerminal({
        status,
        resultSha256: digestEngagementValue(terminal),
        terminalAt: terminal.terminal_at,
      })
    }, dependencies)
    finalSnapshot = ledger.snapshot()
  }
  return statusFromContext(context, finalSnapshot)
}

function statusFromContext(context, snapshot) {
  const completed = []
  const partial = []
  const failed = []
  const uncertain = []
  const waiting = []
  const unavailable = []
  const waitingDetails = []
  const waitingForAgent = []
  const registry = new Map(getEngagementRouteRegistry().map((route) => [route.id, route]))
  for (const route of snapshot.routes) {
    const status = route.outcome?.status
    if (status === 'SUCCEEDED') completed.push(route.route_id)
    else if (status === 'PARTIAL') {
      partial.push(route.route_id)
      if (route.route_id === 'repository-audit'
        && snapshot.repository.current_checkpoint?.terminal !== true) waitingForAgent.push(route.route_id)
    }
    else if (status === 'FAILED' || status === 'CANCELLED_BEFORE_SEND') failed.push(route.route_id)
    else if (status === 'UNCERTAIN') uncertain.push(route.route_id)
    else if (route.outcome === null) {
      waiting.push(route.route_id)
      const reasonCode = route.waiting?.reason_code ?? null
      waitingDetails.push({ route_id: route.route_id, reason_code: reasonCode })
      if (registry.get(route.route_id)?.availability.status === 'UNAVAILABLE') {
        unavailable.push({ route_id: route.route_id, reason_code: reasonCode })
      }
    }
  }
  const status = snapshot.terminal
    ? snapshot.terminal_result.status
      : snapshot.stop_requested
        || context.stopMarker === true
      ? 'STOP_REQUESTED'
      : waitingForAgent.length > 0
        ? 'WAITING_FOR_AGENT_RESULT'
      : waiting.length > 0
        ? 'WAITING_FOR_MATERIAL'
        : snapshot.routes.length === 0
          ? 'ACTIVE'
          : 'READY_TO_FINALIZE'
  return {
    status,
    engagement_id: context.manifest.engagement_id,
    bundle: context.bundle,
    authorization_sha256: context.manifest.authority_sha256,
    target_sha256: context.manifest.target_sha256,
    completed_routes: completed,
    partial_routes: partial,
    failed_routes: failed,
    uncertain_routes: uncertain,
    waiting_routes: waiting,
    unavailable_routes: unavailable,
    waiting_route_details: waitingDetails,
    waiting_for_agent_routes: waitingForAgent,
    repository: structuredClone(snapshot.repository),
    ledger: {
      record_count: snapshot.record_count,
      head_sha256: snapshot.head_sha256,
      resume_count: snapshot.resume_count,
    },
  }
}

async function loadEngagement(bundleValue, dependencies = {}) {
  const bundle = await assertCanonicalDirectory(bundleValue, 'ENGAGEMENT_BUNDLE_MISSING')
  const [intake, authority, manifest] = await Promise.all([
    readCanonicalDocument(join(bundle, 'intake.json'), canonicalEngagementIntake),
    readCanonicalDocument(join(bundle, 'authorization.json'), canonicalEngagementAuthority),
    readCanonicalDocument(join(bundle, 'engagement.json'), canonicalEngagementManifest),
  ])
  assertValidEngagementIntake(intake)
  verifyEngagementAuthority(authority, {
    expectedEngagementId: manifest.engagement_id,
    expectedTarget: intake.target,
  })
  if (!intakeMatchesAuthority(intake, authority)) {
    fail('ENGAGEMENT_BUNDLE_AUTHORITY_MISMATCH', 'engagement intake differs from durable authority')
  }
  verifyEngagementManifest(manifest, { authority, intake })
  if (['repository', 'artifact', 'process', 'device'].includes(manifest.target.kind)) {
    let currentTarget
    try {
      currentTarget = await normalizeEngagementTarget({
        kind: manifest.target.kind,
        locator: manifest.target.locator,
      }, dependencies)
    } catch (cause) {
      fail('ENGAGEMENT_TARGET_CHANGED', 'local or runtime target identity is no longer valid', { cause })
    }
    if (canonicalEngagementJson(currentTarget) !== canonicalEngagementJson(manifest.target)) {
      fail('ENGAGEMENT_TARGET_CHANGED', 'local or runtime target identity changed after engagement intake')
    }
  }
  for (const input of intake.inputs) {
    const current = await stableFingerprint(input.locator, MAX_INPUT_BYTES)
    if (current.sha256 !== input.sha256 || current.size_bytes !== input.size_bytes) {
      fail('ENGAGEMENT_INPUT_CHANGED', `engagement input changed after intake: ${basename(input.locator)}`)
    }
  }
  if (manifest.route_registry_version !== ENGAGEMENT_ROUTE_REGISTRY_VERSION) {
    fail('ENGAGEMENT_ROUTE_REGISTRY_DRIFT', 'engagement route registry version differs from this runtime')
  }
  let currentTargetIntegrity
  try {
    currentTargetIntegrity = await targetIntegrity(manifest.target)
  } catch (cause) {
    if (manifest.target.kind === 'repository' || manifest.target.kind === 'artifact') {
      fail('ENGAGEMENT_TARGET_CHANGED', 'local target identity is no longer valid', { cause })
    }
    throw cause
  }
  const context = {
    bundle,
    intake,
    authority,
    manifest,
    targetIntegrity: currentTargetIntegrity,
    stopRequest: await readDurableStopRequest(bundle, manifest.engagement_id),
  }
  context.stopMarker = context.stopRequest !== null
  const ledger = await openLedger(context)
  const snapshot = ledger.snapshot()
  if (!snapshot.started || snapshot.manifest_sha256 !== digestEngagementManifest(manifest)) {
    fail('ENGAGEMENT_BUNDLE_LEDGER_MISMATCH', 'engagement ledger does not bind the immutable manifest')
  }

  const descriptors = new Map(getEngagementRouteRegistry().map((value) => [value.id, value]))
  for (const route of snapshot.routes) {
    const descriptor = descriptors.get(route.route_id)
    if (
      !descriptor
      || !descriptor.applicability.target_kinds.includes(manifest.target.kind)
      || !authority.capabilities.includes(route.route_id)
    ) {
      fail('ENGAGEMENT_ROUTE_PLAN_DRIFT', `ledger contains an inapplicable route ${route.route_id}`)
    }
    const expectedPlan = buildRoutePlan({ descriptor, manifest, intake, targetIntegrity: context.targetIntegrity })
    const plan = await readCanonicalDocument(
      join(routeDirectory(bundle, route.route_id), 'plan.json'),
      canonicalEngagementJson,
    )
    if (digestEngagementValue(plan) !== route.plan_sha256) {
      fail('ENGAGEMENT_ROUTE_PLAN_DRIFT', `route plan binding changed for ${route.route_id}`)
    }
    if (canonicalEngagementJson(plan) !== canonicalEngagementJson(expectedPlan)) {
      const reboundPlan = { ...plan, target_integrity: expectedPlan.target_integrity }
      if (canonicalEngagementJson(reboundPlan) === canonicalEngagementJson(expectedPlan)) {
        fail('ENGAGEMENT_TARGET_CHANGED', 'local target identity changed after engagement intake')
      }
      fail('ENGAGEMENT_ROUTE_PLAN_DRIFT', `route plan binding changed for ${route.route_id}`)
    }
    if (route.permit_sha256 !== null) {
      const invocation = await readCanonicalDocument(
        join(routeDirectory(bundle, route.route_id), 'invocation.json'),
        canonicalEngagementJson,
      )
      assertFixedInvocation(descriptor, invocation)
      const invocationSha256 = digestEngagementValue(invocation)
      const grant = await readCanonicalDocument(
        join(routeDirectory(bundle, route.route_id), 'grant.json'),
        (value) => canonicalEngagementRouteGrant(value, {
          manifest, authority, routeId: route.route_id, planSha256: route.plan_sha256, invocationSha256,
        }),
      )
      verifyEngagementRouteGrant(grant, {
        manifest, authority, routeId: route.route_id, planSha256: route.plan_sha256, invocationSha256,
      })
      if (digestEngagementRouteGrant(grant, {
        manifest, authority, routeId: route.route_id, planSha256: route.plan_sha256, invocationSha256,
      }) !== route.permit_sha256) {
        fail('ENGAGEMENT_ROUTE_PERMIT_DRIFT', `route permit binding changed for ${route.route_id}`)
      }
    }
    if (route.outcome !== null) {
      const result = await readCanonicalDocument(
        join(routeDirectory(bundle, route.route_id), 'result.json'),
        (value) => canonicalEngagementJson(assertRouteResult(value, context, route.route_id)),
        MAX_ROUTE_RESULT_BYTES,
      )
      if (digestEngagementValue(result) !== route.outcome.result_sha256
        || result.status !== route.outcome.status
        || result.request_may_have_been_sent !== route.outcome.request_may_have_been_sent) {
        fail('ENGAGEMENT_ROUTE_RESULT_DRIFT', `route result binding changed for ${route.route_id}`)
      }
      await verifyDeclaredRouteOutputs(context, route.route_id, result, {
        allowMutableRepository: route.route_id === REPOSITORY_ROUTE_ID
          && snapshot.repository.checkpoints.length > 0,
      })
    }
  }
  if (snapshot.repository.checkpoints.length > 0) {
    await verifyRepositoryCheckpointHistory(context, snapshot, {
      verifyCurrent: snapshot.repository.active_work?.ingest === null
        || snapshot.repository.active_work === null,
    })
    for (const work of snapshot.repository.works) {
      const envelope = await readCanonicalDocument(
        join(repositoryWorkRoot(bundle), 'envelopes', `${repositoryWorkToken(work.work_id)}.json`),
        canonicalEngagementJson,
        MAX_ROUTE_RESULT_BYTES,
      )
      verifyRepositoryWorkEnvelope(envelope, work.envelope_sha256)
      if (work.result !== null) {
        const receipt = await readCanonicalDocument(
          join(repositoryWorkRoot(bundle), 'receipts', `${repositoryWorkToken(work.work_id)}.json`),
          canonicalEngagementJson,
          MAX_ROUTE_RESULT_BYTES,
        )
        if (digestEngagementValue(receipt) !== work.result.receipt_sha256) {
          fail('ENGAGEMENT_REPOSITORY_RECEIPT_DRIFT', 'repository work receipt differs from the outer ledger')
        }
      }
    }
  }
  if (snapshot.terminal) {
    const terminal = await readCanonicalDocument(
      join(bundle, 'terminal.json'),
      canonicalEngagementJson,
    )
    if (
      !exactFields(terminal, ['engagement_id', 'kind', 'reason', 'schema_version', 'status', 'terminal_at'])
      || terminal.schema_version !== '1.0.0'
      || terminal.kind !== 'last-aperture/engagement-terminal-result'
      || terminal.engagement_id !== manifest.engagement_id
      || terminal.status !== snapshot.terminal_result.status
      || terminal.terminal_at !== snapshot.terminal_result.terminal_at
      || digestEngagementValue(terminal) !== snapshot.terminal_result.result_sha256
    ) fail('ENGAGEMENT_TERMINAL_RESULT_DRIFT', 'terminal result differs from the engagement ledger')
  }
  return { context, ledger }
}

function assertRepositoryOperationAllowed(context, snapshot) {
  if (snapshot.stop_requested || snapshot.terminal || context.stopMarker) {
    fail('ENGAGEMENT_REPOSITORY_WORK_STOPPED', 'repository work cannot run after stop or terminal state')
  }
  const route = snapshot.routes.find(({ route_id: id }) => id === REPOSITORY_ROUTE_ID)
  if (route?.outcome?.status !== 'PARTIAL') {
    fail('ENGAGEMENT_REPOSITORY_ROUTE_NOT_READY', 'engagement has no planned repository child workflow')
  }
}

async function currentRepositoryChildTree(context, child) {
  const binding = await bindEngagementOutput({
    routeDirectory: routeDirectory(context.bundle, REPOSITORY_ROUTE_ID),
    relativePath: child.relative_path,
  })
  return {
    binding,
    sha256: digestEngagementOutputBinding(binding),
  }
}

function repositoryRecoveryRequired(context, ledger, work, reason) {
  return repositoryOperationResult(context, ledger, {
    schema_version: '1.0.0',
    state: 'INGEST_RECOVERY_REQUIRED',
    child_state: 'UNKNOWN',
    terminal: false,
  }, {
    recovery: {
      schema_version: '1.0.0',
      state: 'INGEST_RECOVERY_REQUIRED',
      work_id: work.work_id,
      attempt: work.ingest?.attempt ?? work.ingest_attempts.at(-1)?.attempt,
      reason,
      next_step: { code: 'RECONCILE_EXACT_STAGED_RESULT' },
    },
  })
}

async function reconcilePendingRepositoryIngest(
  context,
  ledger,
  child,
  storage,
  dependencies,
  { allowStoppedReadOnly = false } = {},
) {
  let snapshot = ledger.snapshot()
  const work = snapshot.repository.active_work
  if (work === null || work.ingest === null) return { state: 'NONE' }
  const envelope = await readPersistedRepositoryEnvelope(context, storage, work)
  let ingest = work.ingest

  if (ingest.reconciliation?.outcome === 'CONFLICT') {
    return {
      state: 'RECOVERY_REQUIRED',
      result: repositoryRecoveryRequired(context, ledger, work, 'CHILD_STATE_CONFLICT'),
    }
  }

  let observed = await currentRepositoryChildTree(context, child)
  if (ingest.reconciliation?.outcome === 'APPLIED') {
    if (observed.sha256 !== ingest.reconciliation.observed_child_tree_sha256) {
      return {
        state: 'RECOVERY_REQUIRED',
        result: repositoryRecoveryRequired(context, ledger, work, 'CHILD_CHANGED_AFTER_APPLIED_RECONCILIATION'),
      }
    }
  } else {
    let reconciled
    try {
      reconciled = await reconcileBoundRepositoryWorkResult({
        envelope,
        stagedResult: {
          relative_path: ingest.staged_relative_path,
          sha256: ingest.result_sha256,
          size_bytes: ingest.result_size_bytes,
        },
      }, {
        stagingDirectory: storage.staging,
        loadExpectedEnvelope: async ({ workId, workEnvelopeSha256 }) => {
          if (workId !== work.work_id || workEnvelopeSha256 !== work.envelope_sha256) {
            fail('ENGAGEMENT_REPOSITORY_WORK_ENVELOPE_DRIFT', 'repository recovery expectation differs from the ledger')
          }
          return envelope
        },
        execute: repositoryExecutor(context, dependencies, { allowStoppedReadOnly }),
      })
    } catch (cause) {
      observed = await currentRepositoryChildTree(context, child)
      if (observed.sha256 !== ingest.pre_child_tree_sha256) {
        await ledger.recordRepositoryIngestReconciliation({
          workId: work.work_id,
          envelopeSha256: work.envelope_sha256,
          attempt: ingest.attempt,
          outcome: 'CONFLICT',
          observedChildTreeSha256: observed.sha256,
          reconciledAt: currentLedgerTimestamp(ledger, dependencies),
        })
        snapshot = ledger.snapshot()
        return {
          state: 'RECOVERY_REQUIRED',
          result: repositoryRecoveryRequired(
            context,
            ledger,
            snapshot.repository.active_work,
            'CHILD_CHANGED_WITHOUT_EXACT_APPLIED_RESULT',
          ),
        }
      }
      return {
        state: 'RECOVERY_REQUIRED',
        result: repositoryRecoveryRequired(context, ledger, work, `EXACT_RESULT_CHECK_FAILED:${cause.code ?? 'ERROR'}`),
      }
    }

    observed = await currentRepositoryChildTree(context, child)
    if (!reconciled.applied) {
      if (observed.sha256 !== ingest.pre_child_tree_sha256) {
        await ledger.recordRepositoryIngestReconciliation({
          workId: work.work_id,
          envelopeSha256: work.envelope_sha256,
          attempt: ingest.attempt,
          outcome: 'CONFLICT',
          observedChildTreeSha256: observed.sha256,
          reconciledAt: currentLedgerTimestamp(ledger, dependencies),
        })
        snapshot = ledger.snapshot()
        return {
          state: 'RECOVERY_REQUIRED',
          result: repositoryRecoveryRequired(context, ledger, snapshot.repository.active_work, 'CHILD_CHANGED_BUT_RESULT_NOT_APPLIED'),
        }
      }
      await ledger.recordRepositoryIngestReconciliation({
        workId: work.work_id,
        envelopeSha256: work.envelope_sha256,
        attempt: ingest.attempt,
        outcome: 'NOT_APPLIED',
        observedChildTreeSha256: observed.sha256,
        reconciledAt: currentLedgerTimestamp(ledger, dependencies),
      })
      return { state: 'NOT_APPLIED' }
    }

    await ledger.recordRepositoryIngestReconciliation({
      workId: work.work_id,
      envelopeSha256: work.envelope_sha256,
      attempt: ingest.attempt,
      outcome: 'APPLIED',
      observedChildTreeSha256: observed.sha256,
      reconciledAt: currentLedgerTimestamp(ledger, dependencies),
    })
    snapshot = ledger.snapshot()
    ingest = snapshot.repository.active_work.ingest
  }

  let childStatus
  try {
    childStatus = await readRepositoryChildStatus(
      { childBundle: child.path },
      { execute: repositoryExecutor(context, dependencies, { allowStoppedReadOnly }) },
    )
  } catch (cause) {
    return {
      state: 'RECOVERY_REQUIRED',
      result: repositoryRecoveryRequired(context, ledger, ledger.snapshot().repository.active_work, `CHILD_STATUS_FAILED:${cause.code ?? 'ERROR'}`),
    }
  }
  const active = ledger.snapshot().repository.active_work
  const receipt = {
    schema_version: '1.0.0',
    state: 'RESULT_INGESTED',
    accepted: true,
    applied: true,
    work_id: active.work_id,
    child_bundle: envelope.binding.child_bundle,
    run_id: envelope.binding.child_run_id,
    job_id: envelope.binding.job_id,
    packet_sha256: envelope.binding.packet_sha256,
    result_state: active.ingest.result_state,
    staged_result: {
      relative_path: active.ingest.staged_relative_path,
      sha256: active.ingest.result_sha256,
      size_bytes: active.ingest.result_size_bytes,
    },
    next_step: { code: 'READ_CHILD_STATUS' },
  }
  await persistRepositoryWorkResult({
    context,
    ledger,
    child,
    storage,
    work: active,
    envelope,
    status: childStatus,
    receipt,
    operation: 'INGEST',
    dependencies,
  })
  return {
    state: 'APPLIED',
    workId: active.work_id,
    result: repositoryOperationResult(context, ledger, childStatus, { work_receipt: receipt, recovered: true }),
  }
}

async function withRepositoryOperation(bundleValue, dependencies, operation) {
  const bundle = await assertCanonicalDirectory(bundleValue, 'ENGAGEMENT_BUNDLE_MISSING')
  return withEngagementMutex(bundle, async () => {
    const loaded = await loadEngagement(bundle, dependencies)
    assertRepositoryOperationAllowed(loaded.context, loaded.ledger.snapshot())
    const storage = await ensureRepositoryWorkStorage(loaded.context)
    const child = await ensureInitialRepositoryCheckpoint(loaded.context, loaded.ledger, dependencies)
    const recovery = await reconcilePendingRepositoryIngest(
      loaded.context,
      loaded.ledger,
      child,
      storage,
      dependencies,
    )
    return operation({ ...loaded, child, storage, recovery })
  }, dependencies)
}

async function readPersistedRepositoryEnvelope(context, storage, work) {
  const envelope = await readCanonicalDocument(
    repositoryEnvelopePath(storage, work.work_id),
    canonicalEngagementJson,
    MAX_ROUTE_RESULT_BYTES,
  )
  verifyRepositoryWorkEnvelope(envelope, work.envelope_sha256)
  if (envelope.binding.child_bundle !== (
    await verifyRepositoryCheckpointHistory(context, (await openLedger(context)).snapshot(), {
      verifyCurrent: work.ingest === null,
    })
  ).childPath) {
    fail('ENGAGEMENT_REPOSITORY_WORK_ENVELOPE_DRIFT', 'repository work envelope child differs from its checkpoint')
  }
  return envelope
}

function repositoryOperationResult(context, ledger, childStatus, extra = {}) {
  return {
    status: childStatus.state,
    engagement_id: context.manifest.engagement_id,
    bundle: context.bundle,
    child_status: structuredClone(childStatus),
    ledger: {
      record_count: ledger.snapshot().record_count,
      head_sha256: ledger.snapshot().head_sha256,
    },
    ...extra,
  }
}

export async function getRepositoryNextWork({ bundle } = {}, dependencies = {}) {
  return withRepositoryOperation(bundle, dependencies, async ({ context, ledger, child, storage, recovery }) => {
    if (recovery.state === 'RECOVERY_REQUIRED') return recovery.result
    const before = ledger.snapshot()
    if (before.repository.active_work !== null) {
      const envelope = await readPersistedRepositoryEnvelope(
        context,
        storage,
        before.repository.active_work,
      )
      return repositoryOperationResult(context, ledger, {
        state: 'WAITING_FOR_AGENT_RESULT',
        child_state: before.repository.current_checkpoint.child_state,
        terminal: false,
      }, {
        recovered: true,
        work_envelope: envelope,
      })
    }
    const next = await prepareRepositoryNextWork({
      engagementId: context.manifest.engagement_id,
      authoritySha256: context.manifest.authority_sha256,
      targetSha256: context.manifest.target_sha256,
      childBundle: child.path,
    }, { execute: repositoryExecutor(context, dependencies) })
    const checkpoint = await recordRepositoryCheckpoint(
      context,
      ledger,
      'NEXT',
      child,
      {
        schema_version: '1.0.0',
        state: next.state,
        child_state: next.child_state,
        child_phase: next.child_phase,
        terminal: REPOSITORY_TERMINAL_STATES.has(next.child_state),
        run_id: next.run_id,
      },
      dependencies,
    )
    if (next.work_envelope === undefined) {
      return repositoryOperationResult(context, ledger, next)
    }
    verifyRepositoryWorkEnvelope(next.work_envelope)
    await writeOrVerify(repositoryEnvelopePath(storage, next.work_envelope.work_id), next.work_envelope)
    await ledger.recordRepositoryWorkIssued({
      workId: next.work_envelope.work_id,
      envelopeSha256: next.work_envelope.work_envelope_sha256,
      childTreeSha256: checkpoint.document.child_tree_sha256,
      issuedAt: currentLedgerTimestamp(ledger, dependencies),
    })
    return repositoryOperationResult(context, ledger, next, {
      recovered: false,
      work_envelope: next.work_envelope,
    })
  })
}

export async function getRepositoryWorkStatus({ bundle } = {}, dependencies = {}) {
  return withRepositoryOperation(bundle, dependencies, async ({ context, ledger, child, recovery }) => {
    if (recovery.state === 'RECOVERY_REQUIRED') return recovery.result
    const status = await readRepositoryChildStatus(
      { childBundle: child.path },
      { execute: repositoryExecutor(context, dependencies) },
    )
    await recordRepositoryCheckpoint(context, ledger, 'STATUS', child, status, dependencies)
    return repositoryOperationResult(context, ledger, status)
  })
}

async function persistRepositoryWorkResult({
  context,
  ledger,
  child,
  storage,
  work,
  envelope,
  status,
  receipt,
  operation,
  dependencies,
}) {
  const snapshot = ledger.snapshot()
  const currentEvent = snapshot.repository.current_checkpoint
  let checkpoint
  if (
    operation === 'INGEST'
    && currentEvent?.operation === 'INGEST'
    && snapshot.repository.active_work?.work_id === work.work_id
  ) {
    const current = await readRepositoryCheckpoint(context, currentEvent)
    const observed = await currentRepositoryChildTree(context, child)
    if (
      observed.sha256 !== current.value.child_tree_sha256
      || digestEngagementValue(status) !== current.value.status_sha256
    ) fail('ENGAGEMENT_REPOSITORY_CHILD_CHANGED', 'recovered ingest checkpoint differs from current child state')
    checkpoint = { document: current.value, checkpointSha256: currentEvent.checkpoint_sha256 }
  } else {
    checkpoint = await recordRepositoryCheckpoint(
      context,
      ledger,
      operation,
      child,
      status,
      dependencies,
    )
  }
  const receiptDocument = {
    schema_version: '1.0.0',
    kind: 'last-aperture/repository-work-receipt',
    engagement_id: context.manifest.engagement_id,
    work_id: work.work_id,
    envelope_sha256: envelope.work_envelope_sha256,
    status: receipt.state,
    receipt: structuredClone(receipt),
    checkpoint_sha256: checkpoint.checkpointSha256,
    child_tree_sha256: checkpoint.document.child_tree_sha256,
    recorded_at: checkpoint.document.checkpointed_at,
  }
  const receiptSha256 = digestEngagementValue(receiptDocument)
  await writeOrVerify(repositoryReceiptPath(storage, work.work_id), receiptDocument)
  await ledger.recordRepositoryWorkResult({
    workId: work.work_id,
    envelopeSha256: envelope.work_envelope_sha256,
    receiptSha256,
    childTreeSha256: checkpoint.document.child_tree_sha256,
    status: receipt.state,
    recordedAt: receiptDocument.recorded_at,
  })
  return { checkpoint, receiptDocument, receiptSha256 }
}

export async function submitRepositoryWork({ bundle, workId, resultPath } = {}, dependencies = {}) {
  repositoryWorkToken(workId)
  return withRepositoryOperation(bundle, dependencies, async ({ context, ledger, child, storage, recovery }) => {
    if (recovery.state === 'RECOVERY_REQUIRED') return recovery.result
    if (recovery.state === 'APPLIED' && recovery.workId === workId) return recovery.result
    const work = ledger.snapshot().repository.works.find(({ work_id: id }) => id === workId)
    if (work === undefined || work.result !== null
      || ledger.snapshot().repository.active_work?.work_id !== workId) {
      fail('ENGAGEMENT_REPOSITORY_WORK_NOT_ACTIVE', 'repository work is not the active unresolved lease')
    }
    const envelope = await readPersistedRepositoryEnvelope(context, storage, work)
    let receipt
    try {
      receipt = await submitBoundRepositoryWorkResult({ envelope, resultPath }, {
        stagingDirectory: storage.staging,
        loadExpectedEnvelope: async ({ workId: requested, workEnvelopeSha256 }) => {
          if (requested !== work.work_id || workEnvelopeSha256 !== work.envelope_sha256) {
            fail('ENGAGEMENT_REPOSITORY_WORK_ENVELOPE_DRIFT', 'repository work expectation differs from the ledger')
          }
          return envelope
        },
        beforeIngest: async (dispatch) => {
          if (
            dispatch.work_id !== work.work_id
            || dispatch.envelope_sha256 !== work.envelope_sha256
          ) fail('ENGAGEMENT_REPOSITORY_WORK_ENVELOPE_DRIFT', 'repository ingest dispatch differs from the active work')
          const live = ledger.snapshot()
          const active = live.repository.active_work
          if (active?.work_id !== work.work_id || active.ingest !== null) {
            fail('ENGAGEMENT_REPOSITORY_WORK_NOT_ACTIVE', 'repository work is not ready for an ingest dispatch')
          }
          const observed = await currentRepositoryChildTree(context, child)
          if (observed.sha256 !== live.repository.current_checkpoint.child_tree_sha256) {
            fail('ENGAGEMENT_REPOSITORY_CHILD_CHANGED', 'repository child changed before ingest dispatch')
          }
          await ledger.recordRepositoryIngestDispatch({
            workId: work.work_id,
            envelopeSha256: work.envelope_sha256,
            preChildTreeSha256: observed.sha256,
            stagedRelativePath: dispatch.staged_result.relative_path,
            resultSha256: dispatch.staged_result.sha256,
            resultSizeBytes: dispatch.staged_result.size_bytes,
            resultState: dispatch.result_state,
            dispatchedAt: currentLedgerTimestamp(ledger, dependencies),
          })
        },
        execute: repositoryExecutor(context, dependencies),
      })
      receipt = {
        ...receipt,
        staged_result: {
          relative_path: receipt.staged_result.relative_path,
          sha256: receipt.staged_result.sha256,
          size_bytes: receipt.staged_result.size_bytes,
        },
      }
    } catch (cause) {
      const active = ledger.snapshot().repository.active_work
      if (active?.work_id !== work.work_id || active.ingest === null) throw cause
      return repositoryRecoveryRequired(
        context,
        ledger,
        active,
        cause instanceof RepositoryWorkflowError
          ? cause.code
          : 'INGEST_EXECUTION_FAILED_AFTER_DISPATCH',
      )
    }
    const dispatched = ledger.snapshot().repository.active_work
    if (dispatched?.work_id !== work.work_id || dispatched.ingest === null) {
      fail('ENGAGEMENT_REPOSITORY_INGEST_RECORD_MISSING', 'successful repository ingest lacks its durable dispatch record')
    }
    const observed = await currentRepositoryChildTree(context, child)
    await ledger.recordRepositoryIngestReconciliation({
      workId: work.work_id,
      envelopeSha256: work.envelope_sha256,
      attempt: dispatched.ingest.attempt,
      outcome: 'APPLIED',
      observedChildTreeSha256: observed.sha256,
      reconciledAt: currentLedgerTimestamp(ledger, dependencies),
    })
    let childStatus
    try {
      childStatus = await readRepositoryChildStatus(
        { childBundle: child.path },
        { execute: repositoryExecutor(context, dependencies) },
      )
    } catch (cause) {
      return repositoryRecoveryRequired(
        context,
        ledger,
        ledger.snapshot().repository.active_work,
        `CHILD_STATUS_FAILED:${cause.code ?? 'ERROR'}`,
      )
    }
    await persistRepositoryWorkResult({
      context, ledger, child, storage,
      work: ledger.snapshot().repository.active_work,
      envelope, status: childStatus,
      receipt,
      operation: 'INGEST',
      dependencies,
    })
    return repositoryOperationResult(context, ledger, childStatus, {
      work_receipt: receipt,
    })
  })
}

async function repositoryTerminalAction(bundle, action, dependencies) {
  return withRepositoryOperation(bundle, dependencies, async ({ context, ledger, child }) => {
    if (ledger.snapshot().repository.active_work !== null) {
      fail('ENGAGEMENT_REPOSITORY_WORK_ACTIVE', `repository work must settle before ${action}`)
    }
    const result = await executeRepositoryAction(context, action, child.path, dependencies)
    let output = null
    if (action === 'validate') {
      try { output = JSON.parse(result.stdout) } catch (cause) {
        fail('ENGAGEMENT_REPOSITORY_ACTION_FAILED', 'repository validate did not return JSON', { cause })
      }
    }
    const status = await readRepositoryChildStatus(
      { childBundle: child.path },
      { execute: repositoryExecutor(context, dependencies) },
    )
    await recordRepositoryCheckpoint(context, ledger, action.toUpperCase(), child, status, dependencies)
    if (action === 'validate') {
      return repositoryOperationResult(context, ledger, status, { validation: output })
    }
    return repositoryOperationResult(context, ledger, status)
  })
}

export async function finalizeRepositoryWork({ bundle } = {}, dependencies = {}) {
  return repositoryTerminalAction(bundle, 'finalize', dependencies)
}

export async function validateRepositoryWork({ bundle } = {}, dependencies = {}) {
  const child = await repositoryTerminalAction(bundle, 'validate', dependencies)
  const engagement = await resumeEngagement({ bundle }, dependencies)
  return { ...engagement, child_status: child.child_status, validation: child.validation }
}

export async function startEngagement({
  target,
  statement,
  objective,
  out,
  authorizationProfile,
  credentialReferences = [],
  inputs = [],
} = {}, dependencies = {}) {
  const operatorId = controllerIdentity(dependencies)
  const declaredAt = currentTimestamp(dependencies)
  const intake = await createEngagementIntake({
    operatorId,
    declaredAt,
    statement,
    objective,
    target,
    authorizationProfile,
    credentialReferences,
    inputs,
  }, dependencies)
  const engagementId = engagementIdentity(dependencies)
  const authority = createEngagementAuthority({
    engagementId,
    operatorId,
    declaredAt,
    statement: intake.statement,
    objective: intake.objective,
    target: intake.target,
    authorizationProfile: intake.authorization_profile,
    credentialReferences: intake.credential_references,
  })
  const manifest = createEngagementManifest({
    platformVersion: PLATFORM_VERSION,
    engagementId,
    createdAt: currentTimestamp(dependencies),
    objective: intake.objective,
    target: intake.target,
    intake,
    authority,
    routeRegistryVersion: ENGAGEMENT_ROUTE_REGISTRY_VERSION,
  })
  if (intake.target.kind === 'repository') {
    const requestedBundle = resolve(out)
    if (samePath(intake.target.locator, requestedBundle) || inside(intake.target.locator, requestedBundle)) {
      fail('ENGAGEMENT_BUNDLE_IN_TARGET', 'engagement output must be outside the repository target')
    }
  }
  const bundle = await createBundleDirectory(out)
  await writeCanonicalExclusive(join(bundle, 'intake.json'), canonicalEngagementIntake(intake))
  await writeCanonicalExclusive(join(bundle, 'authorization.json'), canonicalEngagementAuthority(authority))
  await writeCanonicalExclusive(join(bundle, 'engagement.json'), canonicalEngagementManifest(manifest))
  await mkdir(join(bundle, 'routes'), { recursive: false, mode: 0o700 })
  const context = {
    bundle,
    intake,
    authority,
    manifest,
    targetIntegrity: await targetIntegrity(intake.target),
    stopMarker: false,
    stopRequest: null,
  }
  const ledger = await openEngagementLedger({
    directory: join(bundle, 'ledger'),
    anchorDirectory: ledgerAnchorDirectory(bundle),
    binding: bindingFor(context),
    initialize: true,
  })
  await ledger.start({
    manifestSha256: digestEngagementManifest(manifest),
    startedAt: currentLedgerTimestamp(ledger, dependencies),
  })
  return schedule(context, ledger, dependencies)
}

export async function resumeEngagement({ bundle } = {}, dependencies = {}) {
  const loaded = await loadEngagement(bundle, dependencies)
  const snapshot = loaded.ledger.snapshot()
  if (snapshot.terminal || snapshot.stop_requested) return statusFromContext(loaded.context, snapshot)
  if (loaded.context.stopRequest !== null) {
    return stopEngagement({ bundle: loaded.context.bundle, reason: loaded.context.stopRequest.reason }, dependencies)
  }
  await loaded.ledger.recordResume({ resumedAt: currentLedgerTimestamp(loaded.ledger, dependencies) })
  return schedule(loaded.context, loaded.ledger, dependencies)
}

export async function getEngagementStatus({ bundle } = {}, dependencies = {}) {
  const loaded = await loadEngagement(bundle, dependencies)
  return statusFromContext(loaded.context, loaded.ledger.snapshot())
}

export async function stopEngagement({ bundle, reason = 'operator requested stop' } = {}, dependencies = {}) {
  const loaded = await loadEngagement(bundle, dependencies)
  assertStopReason(reason)
  if (loaded.ledger.snapshot().terminal) {
    return statusFromContext(loaded.context, loaded.ledger.snapshot())
  }
  const requestedAt = currentLedgerTimestamp(loaded.ledger, dependencies)
  const requested = {
    schema_version: '1.0.0',
    kind: 'last-aperture/engagement-stop-request',
    engagement_id: loaded.context.manifest.engagement_id,
    reason,
    requested_at: requestedAt,
  }
  let durableRequest = requested
  try {
    await writeCanonicalExclusive(stopMarkerPath(loaded.context.bundle), canonicalEngagementJson(requested))
  } catch (error) {
    if (error.code !== 'ENGAGEMENT_BUNDLE_IMMUTABLE') throw error
    durableRequest = await readCanonicalDocument(stopMarkerPath(loaded.context.bundle), canonicalEngagementJson)
    if (
      !exactFields(durableRequest, ['engagement_id', 'kind', 'reason', 'requested_at', 'schema_version'])
      || durableRequest.schema_version !== '1.0.0'
      || durableRequest.kind !== 'last-aperture/engagement-stop-request'
      || durableRequest.engagement_id !== loaded.context.manifest.engagement_id
    ) fail('ENGAGEMENT_STOP_INVALID', 'existing durable stop request is invalid')
  }
  loaded.context.stopMarker = true
  loaded.context.stopRequest = durableRequest
  return withEngagementMutex(loaded.context.bundle, async () => {
    let ledger = await openLedger(loaded.context)
    const trusted = ledger.snapshot()
    ledger = await openLedger(loaded.context, {
      recordCount: trusted.record_count,
      headSha256: trusted.head_sha256,
    })
    let snapshot = ledger.snapshot()
    if (snapshot.terminal) return statusFromContext(loaded.context, snapshot)
    await ledger.requestStop({ reason: durableRequest.reason, requestedAt: durableRequest.requested_at })
    await reconcileInterruptedRoutes(loaded.context, ledger, dependencies)
    snapshot = ledger.snapshot()
    if (snapshot.repository.active_work?.ingest !== null
      && snapshot.repository.active_work !== null) {
      const current = await verifyRepositoryCheckpointHistory(loaded.context, snapshot, {
        verifyCurrent: false,
      })
      const child = {
        path: current.childPath,
        relative_path: current.value.child_bundle_relative_path,
        sha256: current.value.child_bundle_sha256,
      }
      const storage = await ensureRepositoryWorkStorage(loaded.context)
      const recovery = await reconcilePendingRepositoryIngest(
        loaded.context,
        ledger,
        child,
        storage,
        dependencies,
        { allowStoppedReadOnly: true },
      )
      if (recovery.state === 'RECOVERY_REQUIRED') {
        fail(
          'ENGAGEMENT_REPOSITORY_RECOVERY_REQUIRED',
          'repository ingest must be exactly reconciled before engagement terminalization',
        )
      }
    }
    if (ledger.snapshot().repository.active_work?.ingest !== null
      && ledger.snapshot().repository.active_work !== null) {
      fail(
        'ENGAGEMENT_REPOSITORY_RECOVERY_REQUIRED',
        'repository ingest remains unresolved before engagement terminalization',
      )
    }
    const terminal = {
      schema_version: '1.0.0',
      kind: 'last-aperture/engagement-terminal-result',
      engagement_id: loaded.context.manifest.engagement_id,
      status: 'STOPPED',
      reason: durableRequest.reason,
      terminal_at: currentLedgerTimestamp(ledger, dependencies),
    }
    await writeOrVerify(join(loaded.context.bundle, 'terminal.json'), terminal)
    await ledger.recordTerminal({
      status: 'STOPPED',
      resultSha256: digestEngagementValue(terminal),
      terminalAt: terminal.terminal_at,
    })
    return statusFromContext(loaded.context, ledger.snapshot())
  }, dependencies)
}
