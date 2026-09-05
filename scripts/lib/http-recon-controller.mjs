import { constants as fsConstants } from 'node:fs'
import {
  lstat,
  mkdir,
  open,
  readFile,
  realpath,
  rename,
  rm,
} from 'node:fs/promises'
import { randomBytes } from 'node:crypto'
import { isIP } from 'node:net'
import { tmpdir } from 'node:os'
import {
  basename,
  dirname,
  isAbsolute,
  join,
  relative,
  resolve,
} from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  assertValidHttpReconObservation,
  assertValidHttpReconRun,
  assertValidOperatorAttestedHttpReconScope,
  buildOperatorAttestedHttpReconPlan,
  canonicalJson,
  createOperatorAttestedHttpReconScope,
  sha256Hex,
} from './http-recon-contracts.mjs'
import {
  isPublicHttpReconAddress,
  probeHttps,
} from './http-recon-client.mjs'
import {
  bindPrePlanOperatorAuthorization,
  verifyOperatorAuthorizationReceipt,
  verifyPrePlanHttpsOperatorAuthorization,
} from './operator-authorization.mjs'
import { stableJson } from './run-engine.mjs'

const PROJECT_ROOT = resolve(fileURLToPath(new URL('../..', import.meta.url)))
const RUN_FILE = 'run.json'
const ATTESTED_SCOPE_FILE = 'attested-scope.json'
const EVENTS_FILE = 'events.jsonl'
const REPORT_FILE = 'report.md'
const OBSERVATIONS_DIRECTORY = 'observations'
const STOP_FILE = '.http-recon.stop'
const LOCK_FILE = '.http-recon.lock'
const MAX_RUN_BYTES = 4 * 1024 * 1024
const MAX_ATTESTED_SCOPE_BYTES = 1024 * 1024
const MAX_EVENT_BYTES = 16 * 1024 * 1024
const MAX_OBSERVATION_BYTES = 1024 * 1024
const MAX_REPORT_BYTES = 4 * 1024 * 1024
const OPEN_READ_ONLY_NO_FOLLOW = fsConstants.O_RDONLY
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)
const ZERO_SHA256 = '0'.repeat(64)

export class HttpReconControllerError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'HttpReconControllerError'
    this.code = code
    if (options.details) this.details = options.details
    if (options.bundle) this.bundle = options.bundle
  }
}

function controllerError(code, message, options) {
  return new HttpReconControllerError(code, message, options)
}

function tlsPolicyForRun(run) {
  return structuredClone(run.target.tls)
}

function tlsSpkiPinForRun(run) {
  const policy = tlsPolicyForRun(run)
  return policy.mode === 'PKIX_HOSTNAME_AND_SPKI_PIN'
    ? policy.spki_sha256
    : undefined
}

function compareDnsAnswers(left, right) {
  if (left.family !== right.family) return left.family - right.family
  if (left.address < right.address) return -1
  if (left.address > right.address) return 1
  return 0
}

function assertDnsEvidence(url, {
  answers,
  answerCount,
  answerSha256,
  selectedIp,
  selectedFamily,
}) {
  const hostname = new URL(url).hostname
  if (
    !Array.isArray(answers)
    || answers.length < 1
    || answers.length > 64
    || answerCount !== answers.length
    || ![4, 6].includes(selectedFamily)
    || isIP(selectedIp) !== selectedFamily
    || !isPublicHttpReconAddress(selectedIp)
  ) {
    throw controllerError(
      'HTTP_RECON_DNS_EVIDENCE_INVALID',
      'recorded DNS evidence is malformed or outside the public target boundary',
    )
  }
  const seen = new Set()
  for (const answer of answers) {
    const key = `${answer?.family}:${answer?.address}`
    if (
      ![4, 6].includes(answer?.family)
      || isIP(answer?.address) !== answer.family
      || !isPublicHttpReconAddress(answer.address)
      || seen.has(key)
    ) {
      throw controllerError(
        'HTTP_RECON_DNS_EVIDENCE_INVALID',
        'recorded DNS answers are malformed, duplicated, or non-public',
      )
    }
    seen.add(key)
  }
  const canonicalAnswers = answers.map((answer) => ({ ...answer }))
    .sort(compareDnsAnswers)
  if (
    canonicalJson(canonicalAnswers) !== canonicalJson(answers)
    || !answers.some(({ address, family }) =>
      address === selectedIp && family === selectedFamily)
    || answerSha256 !== sha256Hex(Buffer.from(JSON.stringify({
      hostname,
      answers: canonicalAnswers,
    }), 'utf8'))
  ) {
    throw controllerError(
      'HTTP_RECON_DNS_EVIDENCE_INVALID',
      'recorded DNS selection or digest does not match the canonical public answer set',
    )
  }
  return { hostname, canonicalAnswers }
}

function preDispatchTransportIdentity(run, url, dns, tls) {
  const policy = tlsPolicyForRun(run)
  const { hostname, canonicalAnswers } = assertDnsEvidence(url, {
    answers: dns?.answers,
    answerCount: dns?.answer_count,
    answerSha256: dns?.answer_sha256,
    selectedIp: dns?.selected_ip,
    selectedFamily: dns?.selected_family,
  })
  if (
    tls?.authorized !== true
    || tls.verification_mode !== policy.mode
    || tls.server_name !== hostname
    || tls.peer_ip !== dns?.selected_ip
    || tls.peer_family !== dns?.selected_family
    || typeof dns?.answer_sha256 !== 'string'
    || !/^[a-f0-9]{64}$/.test(dns.answer_sha256)
    || typeof tls?.certificate_sha256 !== 'string'
    || !/^[a-f0-9]{64}$/.test(tls.certificate_sha256)
    || typeof tls?.spki_sha256 !== 'string'
    || !/^[a-f0-9]{64}$/.test(tls.spki_sha256)
    || (
      policy.mode === 'PKIX_HOSTNAME_AND_SPKI_PIN'
      && tls.spki_sha256 !== policy.spki_sha256
    )
  ) {
    throw controllerError(
      'HTTP_RECON_PRE_DISPATCH_IDENTITY_INVALID',
      'pre-dispatch TLS and DNS evidence does not match the sealed verification policy',
    )
  }
  return {
    dns_sha256: dns.answer_sha256,
    dns_answer_count: canonicalAnswers.length,
    dns_answers: canonicalAnswers,
    resolved_ip: dns.selected_ip,
    resolved_family: dns.selected_family,
    tls_verification: tls.verification_mode,
    server_name: tls.server_name,
    peer_certificate_sha256: tls.certificate_sha256,
    peer_spki_sha256: tls.spki_sha256,
    tls_authorized: true,
  }
}

function assertRecordedTransportIdentity(run, url, identity) {
  const policy = tlsPolicyForRun(run)
  const { hostname } = assertDnsEvidence(url, {
    answers: identity?.dns_answers,
    answerCount: identity?.dns_answer_count,
    answerSha256: identity?.dns_sha256,
    selectedIp: identity?.resolved_ip,
    selectedFamily: identity?.resolved_family,
  })
  if (
    identity?.tls_authorized !== true
    || identity?.tls_verification !== policy.mode
    || identity?.server_name !== hostname
    || typeof identity?.peer_certificate_sha256 !== 'string'
    || !/^[a-f0-9]{64}$/.test(identity.peer_certificate_sha256)
    || typeof identity?.peer_spki_sha256 !== 'string'
    || !/^[a-f0-9]{64}$/.test(identity.peer_spki_sha256)
    || (
      policy.mode === 'PKIX_HOSTNAME_AND_SPKI_PIN'
      && identity.peer_spki_sha256 !== policy.spki_sha256
    )
  ) {
    throw controllerError(
      'HTTP_RECON_PRE_DISPATCH_IDENTITY_INVALID',
      'recorded pre-dispatch identity does not match the sealed TLS policy',
    )
  }
  return identity
}

function observationTransportIdentity(observation) {
  return {
    dns_sha256: observation.network.dns_sha256,
    dns_answer_count: observation.network.dns_answers.length,
    dns_answers: structuredClone(observation.network.dns_answers),
    resolved_ip: observation.network.resolved_ip,
    resolved_family: observation.network.resolved_family,
    tls_verification: observation.network.tls_verification,
    server_name: new URL(observation.url).hostname,
    peer_certificate_sha256: observation.network.peer_certificate_sha256,
    peer_spki_sha256: observation.network.peer_spki_sha256,
    tls_authorized: true,
  }
}

function assertReturnedTransportIdentity({
  run,
  url,
  transport,
  expectedIdentity,
  code,
  message,
}) {
  const returnedIdentity = preDispatchTransportIdentity(
    run,
    url,
    transport.dns,
    transport.tls,
  )
  if (
    expectedIdentity === null
    || canonicalJson(returnedIdentity) !== canonicalJson(expectedIdentity)
  ) {
    throw controllerError(code, message)
  }
  return returnedIdentity
}

function unsettledPreDispatchEvent(events, actionId) {
  return events.find((event) =>
    event.type === 'ACTION_REQUEST_PRE_DISPATCH'
    && event.details?.action_id === actionId) ?? null
}

function hasUnsettledPreDispatch(events, actionId) {
  return unsettledPreDispatchEvent(events, actionId) !== null
}

function normalizeOperatorId(value) {
  const normalized = typeof value === 'string' ? value.trim() : ''
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}$/.test(normalized)) {
    throw controllerError(
      'HTTP_RECON_OPERATOR_INVALID',
      'operator ID must be 3-160 characters using letters, digits, dot, underscore, colon, slash, or hyphen',
    )
  }
  return normalized
}

function normalizeHumanReason(value, label, minimum = 8) {
  const normalized = typeof value === 'string' ? value.trim() : ''
  if (
    normalized.length < minimum
    || normalized.length > 1024
    || /[\u0000-\u001f\u007f]/.test(normalized)
  ) {
    throw controllerError(
      `HTTP_RECON_${label.toUpperCase()}_INVALID`,
      `${label} must be ${minimum}-1024 printable characters`,
    )
  }
  return normalized
}

function timestamp(now) {
  const value = now()
  const date = value instanceof Date ? value : new Date(value)
  if (!Number.isFinite(date.getTime())) {
    throw controllerError(
      'HTTP_RECON_CLOCK_INVALID',
      'authorized HTTP-recon clock returned an invalid time',
    )
  }
  return date.toISOString()
}

function makeRunId(engagementId, now, randomBytesImpl) {
  const suffix = randomBytesImpl(6)
  if (!Buffer.isBuffer(suffix) || suffix.length !== 6) {
    throw controllerError(
      'HTTP_RECON_RANDOM_INVALID',
      'run ID source must return exactly six bytes',
    )
  }
  return `http-recon-run:${sha256Hex(
    `${engagementId}\u0000${timestamp(now)}\u0000${suffix.toString('hex')}`,
  )}`
}

function makeOperatorAttestedIds({ operatorId, targetUrl, at, randomBytesImpl }) {
  const suffix = randomBytesImpl(6)
  if (!Buffer.isBuffer(suffix) || suffix.length !== 6) {
    throw controllerError(
      'HTTP_RECON_RANDOM_INVALID',
      'attested engagement ID source must return exactly six bytes',
    )
  }
  const digest = sha256Hex(
    `${operatorId}\u0000${targetUrl}\u0000${at}\u0000${suffix.toString('hex')}`,
  )
  return {
    engagementId: `http-recon-attested:${digest}`,
    authorizationId: `operator-attested:${digest}`,
  }
}

function isInside(parent, child) {
  const path = relative(resolve(parent), resolve(child))
  return path !== '' && !path.startsWith('..') && !isAbsolute(path)
}

function safeArtifactPath(bundle, artifactPath) {
  if (
    typeof artifactPath !== 'string'
    || artifactPath.length === 0
    || artifactPath.includes('\\')
    || artifactPath.split('/').some((part) => !part || part === '.' || part === '..')
  ) {
    throw controllerError(
      'HTTP_RECON_ARTIFACT_PATH_INVALID',
      `invalid bundle artifact path ${JSON.stringify(artifactPath)}`,
    )
  }
  const target = resolve(bundle, ...artifactPath.split('/'))
  if (!isInside(bundle, target)) {
    throw controllerError(
      'HTTP_RECON_ARTIFACT_PATH_ESCAPE',
      `artifact path escapes the bundle: ${JSON.stringify(artifactPath)}`,
    )
  }
  return target
}

async function readBoundedNoFollow(path, maxBytes, label) {
  const info = await lstat(path)
  if (!info.isFile() || info.isSymbolicLink()) {
    throw controllerError(
      'HTTP_RECON_ARTIFACT_NOT_REGULAR',
      `${label} must be a regular non-symlink file`,
    )
  }
  if (info.size > maxBytes) {
    throw controllerError(
      'HTTP_RECON_ARTIFACT_TOO_LARGE',
      `${label} exceeds its ${maxBytes}-byte limit`,
    )
  }
  const handle = await open(path, OPEN_READ_ONLY_NO_FOLLOW)
  try {
    const before = await handle.stat()
    const content = await handle.readFile()
    const after = await handle.stat()
    if (
      before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || before.ino !== after.ino
      || content.length !== after.size
    ) {
      throw controllerError(
        'HTTP_RECON_ARTIFACT_CHANGED',
        `${label} changed while it was being read`,
      )
    }
    return content
  } finally {
    await handle.close()
  }
}

async function readJson(path, maxBytes, label) {
  const bytes = await readBoundedNoFollow(path, maxBytes, label)
  try {
    return { bytes, value: JSON.parse(bytes.toString('utf8')) }
  } catch (error) {
    throw controllerError(
      'HTTP_RECON_JSON_INVALID',
      `${label} is not valid JSON: ${error.message}`,
      { cause: error },
    )
  }
}

async function atomicReplace(path, content) {
  const target = resolve(path)
  const temporary = `${target}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`
  const handle = await open(temporary, 'wx', 0o600)
  let writeError
  try {
    await handle.writeFile(content, { encoding: 'utf8' })
    await handle.sync()
  } catch (error) {
    writeError = error
  } finally {
    await handle.close()
  }
  if (writeError) {
    await rm(temporary, { force: true })
    throw writeError
  }
  try {
    await rename(temporary, target)
  } catch (error) {
    await rm(temporary, { force: true })
    throw error
  }
}

async function exclusiveWrite(path, content) {
  const handle = await open(path, 'wx', 0o600)
  try {
    await handle.writeFile(content, { encoding: 'utf8' })
    await handle.sync()
  } finally {
    await handle.close()
  }
}

async function createStagingDirectory(destination) {
  const requestedTarget = resolve(destination)
  const requestedParent = dirname(requestedTarget)
  const requestedParentInfo = await lstat(requestedParent)
  if (!requestedParentInfo.isDirectory() || requestedParentInfo.isSymbolicLink()) {
    throw controllerError(
      'HTTP_RECON_PARENT_UNSAFE',
      'HTTP-recon destination parent must be a real directory',
    )
  }
  const parent = await realpath(requestedParent)
  const projectRoot = await realpath(PROJECT_ROOT)
  const target = join(parent, basename(requestedTarget))
  let targetInfo
  try {
    targetInfo = await lstat(target)
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
  if (targetInfo) {
    throw controllerError(
      'HTTP_RECON_DESTINATION_EXISTS',
      `HTTP-recon destination already exists: ${target}`,
    )
  }
  if (target === projectRoot || isInside(projectRoot, target)) {
    throw controllerError(
      'HTTP_RECON_DESTINATION_INSIDE_PROJECT',
      'mutable HTTP-recon bundles must be written outside the project tree',
    )
  }
  const staging = join(
    parent,
    `.${basename(target)}.staging-${process.pid}-${randomBytes(6).toString('hex')}`,
  )
  await mkdir(staging, { recursive: false, mode: 0o700 })
  return { target, staging }
}

function resolveBundle(argument) {
  const value = resolve(argument)
  return basename(value).toLowerCase() === RUN_FILE
    ? { directory: dirname(value), runPath: value }
    : { directory: value, runPath: join(value, RUN_FILE) }
}

async function loadRun(argument) {
  const bundle = resolveBundle(argument)
  const realDirectory = await realpath(bundle.directory)
  const directoryInfo = await lstat(realDirectory)
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
    throw controllerError(
      'HTTP_RECON_BUNDLE_UNSAFE',
      'HTTP-recon bundle must be a real directory',
    )
  }
  const loaded = await readJson(join(realDirectory, RUN_FILE), MAX_RUN_BYTES, RUN_FILE)
  assertValidHttpReconRun(loaded.value)
  return {
    directory: realDirectory,
    runPath: join(realDirectory, RUN_FILE),
    sourceDigest: sha256Hex(loaded.bytes),
    run: loaded.value,
  }
}

async function saveRun(loaded) {
  loaded.run.updated_at = new Date().toISOString()
  assertValidHttpReconRun(loaded.run)
  await atomicReplace(loaded.runPath, stableJson(loaded.run))
}

async function loadOperatorAttestedTrust({
  loaded,
  now,
  requireCurrentValidity = true,
}) {
  const artifact = await readJson(
    join(loaded.directory, ATTESTED_SCOPE_FILE),
    MAX_ATTESTED_SCOPE_BYTES,
    ATTESTED_SCOPE_FILE,
  )
  const scope = assertValidOperatorAttestedHttpReconScope(artifact.value, {
    now: now(),
    requireCurrentValidity,
  })
  const plan = buildOperatorAttestedHttpReconPlan(scope)
  if (
    plan.scope_sha256 !== loaded.run.authorization.scope_sha256
    || plan.plan_sha256 !== loaded.run.plan_sha256
  ) {
    throw controllerError(
      'HTTP_RECON_ATTESTED_SCOPE_MISMATCH',
      'operator-attested scope does not match the planned engagement digests',
    )
  }
  const runProjection = {
    engagement_id: loaded.run.engagement_id,
    authorization: {
      mode: loaded.run.authorization.mode,
      authorization_id: loaded.run.authorization.authorization_id,
      statement: loaded.run.authorization.statement,
      operator_id: loaded.run.authorization.operator_id,
      authorized_by: loaded.run.authorization.authorized_by,
      authorization_reference: loaded.run.authorization.authorization_reference,
      attested_at: loaded.run.authorization.attested_at,
      independently_verified: loaded.run.authorization.independently_verified,
    },
    validity: {
      not_before: loaded.run.authorization.valid_from,
      not_after: loaded.run.authorization.valid_until,
    },
    target: loaded.run.target,
    limits: loaded.run.limits,
    actions: loaded.run.actions.map((action) => ({
      action_id: action.action_id,
      sequence: action.sequence,
      method: action.method,
      url: action.url,
      ...(action.request_headers === undefined
        ? {}
        : { request_headers: structuredClone(action.request_headers) }),
      ...(action.response_observation === undefined
        ? {}
        : { response_observation: structuredClone(action.response_observation) }),
      safe_to_get: action.safe_to_get,
    })),
  }
  const sealedProjection = {
    engagement_id: scope.engagement_id,
    authorization: scope.authorization,
    validity: scope.validity,
    target: plan.plan.target,
    limits: scope.limits,
    actions: plan.actions,
  }
  if (canonicalJson(runProjection) !== canonicalJson(sealedProjection)) {
    throw controllerError(
      'HTTP_RECON_IMMUTABLE_SCOPE_MISMATCH',
      'mutable run scope, target, action, validity, or limits differ from the sealed operator attestation',
    )
  }
  return {
    mode: 'OPERATOR_ATTESTED',
    scope,
    plan,
  }
}

async function loadAuthorizationContext({
  loaded,
  now,
  requireCurrentValidity = true,
}) {
  return loadOperatorAttestedTrust({
    loaded,
    now,
    requireCurrentValidity,
  })
}

function eventRecord({ run, type, at, details }) {
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-recon-event',
    run_id: run.run_id,
    engagement_id: run.engagement_id,
    sequence: run.event_chain.count + 1,
    at,
    type,
    previous_sha256: run.event_chain.last_sha256,
    details,
  }
  return {
    ...unsigned,
    record_sha256: sha256Hex(canonicalJson(unsigned)),
  }
}

async function appendEvent(loaded, type, details, now) {
  const record = eventRecord({
    run: loaded.run,
    type,
    at: timestamp(now),
    details,
  })
  const handle = await open(join(loaded.directory, EVENTS_FILE), 'a', 0o600)
  try {
    await handle.writeFile(stableJson(record, 0), { encoding: 'utf8' })
    await handle.sync()
  } finally {
    await handle.close()
  }
  loaded.run.event_chain = {
    count: record.sequence,
    last_sha256: record.record_sha256,
  }
  return record
}

async function acquireRunLock(directory, now) {
  const path = join(directory, LOCK_FILE)
  const content = stableJson({
    schema_version: '1.0.0',
    pid: process.pid,
    acquired_at: timestamp(now),
    nonce: randomBytes(16).toString('hex'),
  })
  let handle
  try {
    handle = await open(path, 'wx', 0o600)
  } catch (error) {
    if (error.code === 'EEXIST') {
      throw controllerError(
        'HTTP_RECON_RUN_LOCKED',
        `HTTP-recon bundle is already locked: ${directory}`,
      )
    }
    throw error
  }
  try {
    await handle.writeFile(content, { encoding: 'utf8' })
    await handle.sync()
  } finally {
    await handle.close()
  }
  return { path, content }
}

async function releaseRunLock(lock) {
  const observed = await readBoundedNoFollow(lock.path, 4096, LOCK_FILE)
  if (observed.toString('utf8') !== lock.content) {
    throw controllerError(
      'HTTP_RECON_RUN_LOCK_CHANGED',
      'HTTP-recon run lock changed while the controller held it',
    )
  }
  await rm(lock.path)
}

async function withRunLock(loaded, now, operation) {
  const lock = await acquireRunLock(loaded.directory, now)
  try {
    return await operation()
  } finally {
    await releaseRunLock(lock)
  }
}

function initialOperatorAttestedRun({ scope, plan, now, randomBytesImpl }) {
  const createdAt = timestamp(now)
  return {
    schema_version: scope.schema_version,
    kind: 'red-team-audit/http-recon-run',
    capability_mode: 'AUTHORIZED_HTTP_RECON',
    run_id: makeRunId(scope.engagement_id, now, randomBytesImpl),
    engagement_id: scope.engagement_id,
    created_at: createdAt,
    updated_at: createdAt,
    state: 'PLANNED',
    authorization: {
      ...structuredClone(scope.authorization),
      scope_sha256: plan.scope_sha256,
      valid_from: scope.validity.not_before,
      valid_until: scope.validity.not_after,
    },
    target: structuredClone(plan.plan.target),
    plan_sha256: plan.plan_sha256,
    limits: structuredClone(scope.limits),
    budget: {
      proof_requests_used: 0,
      probe_requests_used: 0,
      response_bytes_used: 0,
      started_at: null,
      last_request_at: null,
    },
    actions: plan.actions.map((action) => ({
      ...structuredClone(action),
      state: 'PENDING',
      attempt_count: 0,
      leased_at: null,
      sent_at: null,
      completed_at: null,
      observation_path: null,
      observation_sha256: null,
      error: null,
    })),
    stop: null,
    report: null,
    event_chain: {
      count: 0,
      last_sha256: ZERO_SHA256,
    },
  }
}

export async function planOperatorAttestedHttpReconBundle({
  targetUrl,
  tlsSpkiSha256,
  method = 'HEAD',
  safeToGet = false,
  requestHeaderProfile,
  responseObservationProfile,
  operatorId,
  authorizedBy,
  authorizationReference,
  environment = 'production',
  operatorAuthorization,
  out,
  now = () => new Date(),
  randomBytesImpl = randomBytes,
}) {
  if (operatorAuthorization === undefined) {
    throw controllerError(
      'HTTP_RECON_AUTHORIZATION_ATTESTATION_REQUIRED',
      'operator-attested planning requires one operator authorization declaration',
    )
  }
  const ingressTime = timestamp(now)
  const declaration = verifyPrePlanHttpsOperatorAuthorization({
    value: operatorAuthorization,
    targetUrl,
    now: ingressTime,
    fail: (code, message) => {
      throw controllerError(`HTTP_RECON_OPERATOR_AUTHORIZATION_${code}`, message)
    },
  })
  if (operatorId !== undefined && operatorId !== declaration.operator_id) {
    throw controllerError(
      'HTTP_RECON_OPERATOR_AUTHORIZATION_IDENTITY_MISMATCH',
      'operator authorization identity differs from the planning identity',
    )
  }
  if (
    authorizationReference !== undefined
    && authorizationReference !== declaration.authorization_reference
  ) {
    throw controllerError(
      'HTTP_RECON_OPERATOR_AUTHORIZATION_REFERENCE_MISMATCH',
      'operator authorization reference differs from the planning reference',
    )
  }
  const normalizedOperatorId = normalizeOperatorId(declaration.operator_id)
  const normalizedAuthorizedBy = normalizeHumanReason(
    authorizedBy ?? declaration.operator_id,
    'authorized_by',
    3,
  )
  const normalizedReference = normalizeHumanReason(
    declaration.authorization_reference,
    'authorization_reference',
  )
  const attestedAt = declaration.declared_at
  const ids = makeOperatorAttestedIds({
    operatorId: normalizedOperatorId,
    targetUrl: declaration.target.url,
    at: attestedAt,
    randomBytesImpl,
  })
  const scope = createOperatorAttestedHttpReconScope({
    engagementId: ids.engagementId,
    authorizationId: ids.authorizationId,
    targetUrl: declaration.target.url,
    tlsSpkiSha256,
    method,
    safeToGet,
    requestHeaderProfile,
    responseObservationProfile,
    operatorId: normalizedOperatorId,
    authorizedBy: normalizedAuthorizedBy,
    authorizationReference: normalizedReference,
    environment,
    now: new Date(attestedAt),
  })
  const plan = buildOperatorAttestedHttpReconPlan(scope)
  const run = initialOperatorAttestedRun({
    scope,
    plan,
    now,
    randomBytesImpl,
  })
  const operatorAuthorizationReceipt = bindPrePlanOperatorAuthorization({
    value: declaration,
    planSha256: run.plan_sha256,
    scopeRevisionSha256: run.authorization.scope_sha256,
  })
  assertValidHttpReconRun(run)

  const { target, staging } = await createStagingDirectory(out)
  try {
    await mkdir(join(staging, OBSERVATIONS_DIRECTORY), {
      recursive: false,
      mode: 0o700,
    })
    await exclusiveWrite(join(staging, ATTESTED_SCOPE_FILE), stableJson(scope))
    await exclusiveWrite(join(staging, EVENTS_FILE), '')
    const staged = {
      directory: staging,
      runPath: join(staging, RUN_FILE),
      run,
    }
    await appendEvent(staged, 'PLAN_CREATED', {
      authorization_mode: 'OPERATOR_ATTESTED',
      plan_sha256: run.plan_sha256,
      scope_sha256: run.authorization.scope_sha256,
      tls_policy: tlsPolicyForRun(run),
      response_observation: run.actions[0].response_observation ?? null,
      action_count: 1,
      operator_id: run.authorization.operator_id,
      independently_verified: false,
      operator_authorization_receipt: operatorAuthorizationReceipt,
      network_activity: false,
    }, now)
    assertValidHttpReconRun(run)
    await exclusiveWrite(join(staging, RUN_FILE), stableJson(run))
    await rename(staging, target)
    return {
      directory: target,
      run,
      scope,
      operator_authorization_receipt: operatorAuthorizationReceipt,
    }
  } catch (error) {
    await rm(staging, { recursive: true, force: true })
    throw error
  }
}

export async function goOperatorAttestedHttpRecon({
  targetUrl,
  tlsSpkiSha256,
  method = 'HEAD',
  safeToGet = false,
  requestHeaderProfile,
  responseObservationProfile,
  operatorId,
  authorizedBy,
  authorizationReference,
  environment = 'production',
  operatorAuthorization,
  rationale,
  out,
  now = () => new Date(),
  randomBytesImpl = randomBytes,
  planImpl = planOperatorAttestedHttpReconBundle,
  runImpl = runHttpReconAction,
  finalizeImpl = finalizeHttpReconBundle,
  onPlanned,
}) {
  const directedAt = timestamp(now)
  if (operatorAuthorization === undefined) {
    throw controllerError(
      'HTTP_RECON_LIVE_EXECUTION_AUTHORIZATION_REQUIRED',
      'target-and-go requires one operator authorization declaration',
    )
  }
  const declaration = verifyPrePlanHttpsOperatorAuthorization({
    value: operatorAuthorization,
    targetUrl,
    now: directedAt,
    fail: (code, message) => {
      throw controllerError(`HTTP_RECON_OPERATOR_AUTHORIZATION_${code}`, message)
    },
  })
  if (operatorId !== undefined && operatorId !== declaration.operator_id) {
    throw controllerError(
      'HTTP_RECON_OPERATOR_AUTHORIZATION_IDENTITY_MISMATCH',
      'operator authorization identity differs from the execution identity',
    )
  }
  if (
    typeof planImpl !== 'function'
    || typeof runImpl !== 'function'
    || typeof finalizeImpl !== 'function'
    || (onPlanned !== undefined && typeof onPlanned !== 'function')
  ) {
    throw controllerError(
      'HTTP_RECON_GO_CONTROLLER_INVALID',
      'target-and-go requires controller-owned plan, execution, and finalization functions',
    )
  }
  const effectiveAuthorizedBy = authorizedBy ?? 'Local operator directive'
  const effectiveRationale = rationale ?? 'Operator directed target-and-go execution.'
  const output = typeof out === 'string' && out.trim() !== ''
    ? out
    : join(tmpdir(), `red-team-audit-http-recon-${randomBytesImpl(8).toString('hex')}`)
  const planned = await planImpl({
    targetUrl,
    tlsSpkiSha256,
    method,
    safeToGet,
    requestHeaderProfile,
    responseObservationProfile,
    operatorId: declaration.operator_id,
    authorizedBy: effectiveAuthorizedBy,
    authorizationReference: declaration.authorization_reference,
    environment,
    operatorAuthorization: declaration,
    out: output,
    now,
    randomBytesImpl,
  })
  if (!Array.isArray(planned?.run?.actions) || planned.run.actions.length !== 1) {
    throw controllerError(
      'HTTP_RECON_GO_PLAN_INVALID',
      'target-and-go requires exactly one controller-sealed action',
    )
  }
  await onPlanned?.(Object.freeze({
    bundle: planned.directory,
    operator_id: declaration.operator_id,
    action_id: planned.run.actions[0].action_id,
  }))
  const executed = await runImpl({
    bundle: planned.directory,
    actionId: planned.run.actions[0].action_id,
    operatorId: declaration.operator_id,
    rationale: effectiveRationale,
    now,
  })
  const finalized = await finalizeImpl({
    bundle: planned.directory,
    now,
  })
  return Object.freeze({
    action: executed.action,
    bundle: planned.directory,
    engagement_id: finalized.run.engagement_id,
    ...(planned.operator_authorization_receipt === undefined
      ? {}
      : { operator_authorization_receipt: planned.operator_authorization_receipt }),
    report: finalized.reportPath,
    state: finalized.run.state,
  })
}

function assertActionWindow(run, now) {
  const current = new Date(timestamp(now)).getTime()
  const validFrom = Date.parse(run.authorization.valid_from)
  const validUntil = Date.parse(run.authorization.valid_until)
  if (current < validFrom) {
    throw controllerError(
      'HTTP_RECON_AUTHORIZATION_NOT_YET_VALID',
      `authorization is not valid before ${run.authorization.valid_from}`,
    )
  }
  if (current >= validUntil) {
    throw controllerError(
      'HTTP_RECON_AUTHORIZATION_EXPIRED',
      `authorization expired at ${run.authorization.valid_until}`,
    )
  }
  if (run.budget.started_at) {
    const elapsed = current - Date.parse(run.budget.started_at)
    if (elapsed >= run.limits.max_wall_time_ms) {
      throw controllerError(
        'HTTP_RECON_WALL_TIME_EXHAUSTED',
        'authorized HTTP-recon wall-time budget is exhausted',
      )
    }
  }
}

async function loadStopMarker(directory) {
  const fallback = (message) => ({
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-recon-stop-request',
    engagement_id: null,
    run_id: null,
    requested_at: new Date().toISOString(),
    operator_id: 'controller',
    reason: `fail-closed stop: ${message}`.slice(0, 1024),
  })
  let bytes
  try {
    bytes = await readBoundedNoFollow(
      join(directory, STOP_FILE),
      64 * 1024,
      STOP_FILE,
    )
  } catch (error) {
    if (error.code === 'ENOENT') return null
    return fallback(error.code ?? error.message)
  }
  let marker
  try {
    marker = JSON.parse(bytes.toString('utf8'))
  } catch {
    return fallback('stop marker is not valid JSON')
  }
  if (
    marker?.schema_version !== '1.0.0'
    || marker?.kind !== 'red-team-audit/http-recon-stop-request'
    || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(marker.requested_at ?? '')
    || !/^[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}$/.test(marker.operator_id ?? '')
    || typeof marker.reason !== 'string'
    || marker.reason.length < 1
    || marker.reason.length > 1024
    || /[\u0000-\u001f\u007f]/.test(marker.reason)
  ) {
    return fallback('stop marker fields are invalid')
  }
  return marker
}

function assertRunnableState(run) {
  if (['STOPPED', 'FAILED', 'OUTCOME_UNCERTAIN', 'PROBE_PLAN_COMPLETE'].includes(run.state)) {
    throw controllerError(
      'HTTP_RECON_TERMINAL',
      `HTTP-recon engagement is terminal in state ${run.state}`,
    )
  }
  const uncertain = run.actions.find((action) =>
    ['LEASED', 'SENT', 'DELIVERY_AMBIGUOUS'].includes(action.state))
  if (uncertain) {
    throw controllerError(
      'HTTP_RECON_DELIVERY_UNCERTAIN',
      `action ${uncertain.action_id} has uncertain delivery and cannot be replayed`,
    )
  }
}

export async function nextHttpReconAction({
  bundle,
  now = () => new Date(),
}) {
  const loaded = await loadRun(bundle)
  assertRunnableState(loaded.run)
  assertActionWindow(loaded.run, now)
  const trust = await loadAuthorizationContext({
    loaded,
    now,
  })
  await verifyExistingEvidence({ loaded, trust })
  if (await loadStopMarker(loaded.directory)) {
    throw controllerError(
      'HTTP_RECON_STOP_REQUESTED',
      'a stop marker exists; no action can be selected',
    )
  }
  const action = loaded.run.actions.find(({ state }) => state === 'PENDING')
  return action ? structuredClone(action) : null
}

export async function requestHttpReconStop({
  bundle,
  operatorId,
  reason,
  now = () => new Date(),
}) {
  const normalizedOperatorId = normalizeOperatorId(operatorId)
  const normalizedReason = normalizeHumanReason(reason, 'stop_reason')
  const resolved = resolveBundle(bundle)
  const directory = await realpath(resolved.directory)
  const directoryInfo = await lstat(directory)
  if (!directoryInfo.isDirectory() || directoryInfo.isSymbolicLink()) {
    throw controllerError(
      'HTTP_RECON_BUNDLE_UNSAFE',
      'HTTP-recon stop target must be a real directory',
    )
  }
  let loaded = null
  try {
    loaded = await loadRun(directory)
  } catch {
    // The kill path intentionally remains available when run.json is damaged.
  }
  const marker = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-recon-stop-request',
    engagement_id: loaded?.run.engagement_id ?? null,
    run_id: loaded?.run.run_id ?? null,
    requested_at: timestamp(now),
    operator_id: normalizedOperatorId,
    reason: normalizedReason,
  }
  const path = join(directory, STOP_FILE)
  try {
    await exclusiveWrite(path, stableJson(marker))
  } catch (error) {
    if (error.code === 'EEXIST') {
      const existing = await loadStopMarker(directory)
      return {
        engagement_id: existing?.engagement_id ?? null,
        path,
        requested_at: existing?.requested_at ?? null,
      }
    }
    throw error
  }
  return {
    engagement_id: loaded?.run.engagement_id ?? null,
    path,
    requested_at: marker.requested_at,
  }
}

function startStopWatcher(directory, abortController, intervalMs = 100) {
  let checking = false
  const timer = setInterval(async () => {
    if (checking || abortController.signal.aborted) return
    checking = true
    try {
      if (await loadStopMarker(directory)) {
        abortController.abort(new Error('out-of-band HTTP-recon stop requested'))
      }
    } catch (error) {
      abortController.abort(error)
    } finally {
      checking = false
    }
  }, intervalMs)
  timer.unref?.()
  return () => clearInterval(timer)
}

function enforceRateAndBudgets(run, now) {
  if (run.budget.probe_requests_used >= run.limits.max_probe_requests) {
    throw controllerError(
      'HTTP_RECON_REQUEST_BUDGET_EXHAUSTED',
      'authorized probe-request budget is exhausted',
    )
  }
  if (run.budget.response_bytes_used >= run.limits.max_aggregate_response_bytes) {
    throw controllerError(
      'HTTP_RECON_BYTE_BUDGET_EXHAUSTED',
      'authorized aggregate response-byte budget is exhausted',
    )
  }
  if (run.budget.last_request_at) {
    const elapsed = new Date(timestamp(now)).getTime()
      - Date.parse(run.budget.last_request_at)
    if (elapsed < run.limits.min_interval_ms) {
      throw controllerError(
        'HTTP_RECON_RATE_LIMITED',
        `next request is allowed after ${run.limits.min_interval_ms - elapsed} ms`,
      )
    }
  }
}

function delayWithSignal(milliseconds, signal) {
  if (milliseconds <= 0) return Promise.resolve()
  return new Promise((resolvePromise, rejectPromise) => {
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort)
      resolvePromise()
    }, milliseconds)
    const onAbort = () => {
      clearTimeout(timer)
      signal?.removeEventListener('abort', onAbort)
      rejectPromise(controllerError(
        'HTTP_RECON_STOP_REQUESTED',
        'HTTP-recon stopped while waiting for its request interval',
      ))
    }
    signal?.addEventListener('abort', onAbort, { once: true })
  })
}

async function waitForRequestInterval(run, now, signal, delayImpl) {
  if (!run.budget.last_request_at) return
  const elapsed = new Date(timestamp(now)).getTime()
    - Date.parse(run.budget.last_request_at)
  const remaining = run.limits.min_interval_ms - elapsed
  if (remaining > 0) await delayImpl(remaining, signal)
  assertActionWindow(run, now)
}

function observationPath(actionId) {
  const match = /^http-recon-action:([a-f0-9]{64})$/.exec(actionId)
  if (!match) {
    throw controllerError(
      'HTTP_RECON_ACTION_ID_UNSAFE',
      `unsafe action ID ${JSON.stringify(actionId)}`,
    )
  }
  return `${OBSERVATIONS_DIRECTORY}/${match[1]}.json`
}

function responseObservationMatchesAction(observation, action) {
  const expected = action.response_observation ?? null
  if (expected === null) {
    return !Object.hasOwn(observation, 'response_observation')
  }
  if (!Object.hasOwn(observation, 'response_observation')) return false
  const observed = observation.response_observation
  return observed === null || (
    observed.profile === expected.profile
    && observed.profile_binding_sha256 === expected.profile_binding_sha256
  )
}

function normalizeTransportObservation({
  run,
  action,
  transport,
  startedAt,
  completedAt,
  stopCondition = null,
}) {
  const expectedTlsPolicy = tlsPolicyForRun(run)
  if (
    transport.tls.verification_mode !== expectedTlsPolicy.mode
    || (
      expectedTlsPolicy.mode === 'PKIX_HOSTNAME_AND_SPKI_PIN'
      && transport.tls.spki_sha256 !== expectedTlsPolicy.spki_sha256
    )
  ) {
    throw controllerError(
      'HTTP_RECON_TLS_EVIDENCE_MISMATCH',
      'transport TLS evidence does not match the sealed verification policy',
    )
  }
  const authority = {
    mode: 'OPERATOR_ATTESTED',
    authorization_id: run.authorization.authorization_id,
    operator_id: run.authorization.operator_id,
    scope_sha256: run.authorization.scope_sha256,
    plan_sha256: run.plan_sha256,
    independently_verified: false,
  }
  const expectedResponseObservation = action.response_observation ?? null
  const observedResponseObservation = transport.response_observation ?? null
  if (
    expectedResponseObservation === null
      ? Object.hasOwn(transport, 'response_observation')
      : (
          observedResponseObservation !== null
          && (
            observedResponseObservation.profile !== expectedResponseObservation.profile
            || observedResponseObservation.profile_binding_sha256
              !== expectedResponseObservation.profile_binding_sha256
          )
        )
  ) {
    throw controllerError(
      'HTTP_RECON_RESPONSE_OBSERVATION_MISMATCH',
      'transport response observation does not match the sealed action profile',
    )
  }
  if (
    expectedResponseObservation !== null
    && observedResponseObservation === null
    && stopCondition === null
    && transport.body.truncated !== true
  ) {
    throw controllerError(
      'HTTP_RECON_RESPONSE_OBSERVATION_MISSING',
      'successful transport omitted its sealed response observation',
    )
  }
  const observation = {
    schema_version: expectedResponseObservation === null ? '1.0.0' : '1.1.0',
    kind: 'red-team-audit/http-recon-observation',
    observed_at: completedAt,
    authority,
    run_id: run.run_id,
    engagement_id: run.engagement_id,
    action_id: action.action_id,
    sequence: action.sequence,
    method: action.method,
    url: action.url,
    status_code: transport.status,
    response_headers: structuredClone(transport.response_headers),
    response_header_summary: structuredClone(transport.response_header_summary),
    body: structuredClone(transport.body),
    ...(expectedResponseObservation === null
      ? {}
      : { response_observation: structuredClone(observedResponseObservation) }),
    network: {
      resolved_ip: transport.dns.selected_ip,
      resolved_family: transport.dns.selected_family,
      dns_sha256: transport.dns.answer_sha256,
      dns_answers: structuredClone(transport.dns.answers),
      tls_protocol: transport.tls.protocol,
      tls_cipher: transport.tls.cipher,
      tls_verification: transport.tls.verification_mode,
      peer_certificate_sha256: transport.tls.certificate_sha256,
      peer_spki_sha256: transport.tls.spki_sha256,
    },
    timing_ms: structuredClone(transport.timing),
    stop_condition: stopCondition === null && !transport.body.truncated
      ? null
      : {
          code: stopCondition ?? 'LIMIT_REACHED',
          message: stopCondition === null
            ? 'response body exceeded the authorized capture limit'
            : `transport stop condition: ${stopCondition}`,
        },
  }
  assertValidHttpReconObservation(observation)
  return observation
}

async function commitTransportObservation({
  loaded,
  action,
  transport,
  startedAt,
  completedAt,
  now,
  stopCondition = null,
}) {
  const observation = normalizeTransportObservation({
    run: loaded.run,
    action,
    transport,
    startedAt,
    completedAt,
    stopCondition,
  })
  const path = observationPath(action.action_id)
  const content = stableJson(observation)
  await exclusiveWrite(safeArtifactPath(loaded.directory, path), content)
  action.state = 'COMMITTED'
  action.completed_at = completedAt
  action.observation_path = path
  action.observation_sha256 = sha256Hex(Buffer.from(content, 'utf8'))
  action.error = null
  loaded.run.budget.probe_requests_used += 1
  loaded.run.budget.response_bytes_used += observation.body.size
  loaded.run.budget.last_request_at = completedAt
  await appendEvent(loaded, 'ACTION_COMMITTED', {
    action_id: action.action_id,
    observation_path: path,
    observation_sha256: action.observation_sha256,
    status_code: observation.status_code,
    response_bytes: observation.body.size,
    response_observation: action.response_observation ?? null,
    stop_condition: observation.stop_condition,
    budget_after: structuredClone(loaded.run.budget),
  }, now)
  return observation
}

function responseStopReason(stopCondition) {
  return stopCondition === null
    ? null
    : `${stopCondition.code}: ${stopCondition.message}`
}

async function markStopped(
  loaded,
  marker,
  reason,
  now,
  action = null,
  priorEvents = [],
) {
  loaded.run.state = 'STOPPED'
  loaded.run.stop = {
    requested_at: marker?.requested_at ?? timestamp(now),
    observed_at: timestamp(now),
    operator_id: marker?.operator_id ?? 'controller',
    reason: reason ?? marker?.reason ?? 'stop condition observed',
  }
  if (action && ['LEASED', 'SENT'].includes(action.state)) {
    const hasPreDispatch = hasUnsettledPreDispatch(
      priorEvents,
      action.action_id,
    )
    action.state = action.state === 'SENT' || hasPreDispatch
      ? 'DELIVERY_AMBIGUOUS'
      : 'FAILED'
    if (action.state === 'DELIVERY_AMBIGUOUS' && action.sent_at === null) {
      action.sent_at = unsettledPreDispatchEvent(
        priorEvents,
        action.action_id,
      )?.at ?? action.leased_at
    }
    action.completed_at = timestamp(now)
    action.error = {
      code: action.state === 'DELIVERY_AMBIGUOUS'
        ? 'DELIVERY_AMBIGUOUS'
        : 'STOPPED_BEFORE_SEND',
      message: loaded.run.stop.reason,
    }
    if (action.state === 'DELIVERY_AMBIGUOUS') loaded.run.state = 'OUTCOME_UNCERTAIN'
  }
  await appendEvent(loaded, 'STOP_CONFIRMED', {
    reason: loaded.run.stop.reason,
    action_id: action?.action_id ?? null,
    terminal_state: loaded.run.state,
  }, now)
  await saveRun(loaded)
}

async function terminalizeInterruptedAction(loaded, now, priorEvents = []) {
  const interrupted = loaded.run.actions.filter(({ state }) =>
    state === 'LEASED' || state === 'SENT')
  if (interrupted.length === 0) return null
  if (interrupted.length !== 1) {
    throw controllerError(
      'HTTP_RECON_MULTIPLE_IN_FLIGHT',
      'concurrency-one run contains multiple interrupted actions',
    )
  }
  const action = interrupted[0]
  const preDispatch = unsettledPreDispatchEvent(
    priorEvents,
    action.action_id,
  )
  const deliveryAmbiguous = action.state === 'SENT' || preDispatch !== null
  action.state = deliveryAmbiguous ? 'DELIVERY_AMBIGUOUS' : 'FAILED'
  if (deliveryAmbiguous && action.sent_at === null) {
    action.sent_at = preDispatch?.at ?? action.leased_at
  }
  action.completed_at = timestamp(now)
  action.error = {
    code: deliveryAmbiguous
      ? 'DELIVERY_AMBIGUOUS'
      : 'INTERRUPTED_BEFORE_ACTION_SEND',
    message: deliveryAmbiguous
      ? 'controller restart found durable pre-dispatch evidence without a settled network outcome'
      : 'controller restart found a leased action before target-action dispatch',
  }
  loaded.run.state = deliveryAmbiguous ? 'OUTCOME_UNCERTAIN' : 'FAILED'
  await appendEvent(
    loaded,
    deliveryAmbiguous ? 'ACTION_DELIVERY_AMBIGUOUS' : 'ACTION_FAILED',
    {
      action_id: action.action_id,
      phase: 'RESTART_RECOVERY',
      error: structuredClone(action.error),
      stop_requested: false,
    },
    now,
  )
  await saveRun(loaded)
  return action
}

export async function runHttpReconAction({
  bundle,
  actionId,
  operatorId,
  rationale,
  now = () => new Date(),
  probeImpl = probeHttps,
  clientDependencies,
  stopPollIntervalMs = 100,
  delayImpl = delayWithSignal,
}) {
  const loaded = await loadRun(bundle)
  return withRunLock(loaded, now, async () => {
    const refreshed = await loadRun(loaded.directory)
    loaded.run = refreshed.run
    loaded.sourceDigest = refreshed.sourceDigest
    assertRunnableState(loaded.run)
    assertActionWindow(loaded.run, now)
    enforceRateAndBudgets(loaded.run, now)
    const trust = await loadAuthorizationContext({
      loaded,
      now,
    })
    await verifyExistingEvidence({ loaded, trust })
    const normalizedOperatorId = normalizeOperatorId(operatorId)
    const normalizedRationale = normalizeHumanReason(rationale, 'rationale')
    if (normalizedOperatorId !== loaded.run.authorization.operator_id) {
      throw controllerError(
        'HTTP_RECON_ATTESTING_OPERATOR_MISMATCH',
        'operator-attested execution must use the operator identity that created the sealed attestation',
      )
    }
    const marker = await loadStopMarker(loaded.directory)
    if (marker) {
      await markStopped(loaded, marker, marker.reason, now)
      return {
        run: structuredClone(loaded.run),
        action: null,
        stop_reason: marker.reason,
      }
    }
    const action = loaded.run.actions.find((candidate) => candidate.action_id === actionId)
    if (!action) {
      throw controllerError(
        'HTTP_RECON_ACTION_UNKNOWN',
        `action ${JSON.stringify(actionId)} is not in the sealed plan`,
      )
    }
    const next = loaded.run.actions.find(({ state }) => state === 'PENDING')
    if (!next || next.action_id !== action.action_id || action.state !== 'PENDING') {
      throw controllerError(
        'HTTP_RECON_ACTION_NOT_NEXT',
        `action ${action.action_id} is not the next pending sealed action`,
      )
    }

    if (loaded.run.budget.started_at === null) {
      loaded.run.budget.started_at = timestamp(now)
    }
    loaded.run.state = 'ACTIVE'
    action.state = 'LEASED'
    action.attempt_count += 1
    action.leased_at = timestamp(now)
    await saveRun(loaded)
    await appendEvent(loaded, 'ACTION_LEASED', {
      action_id: action.action_id,
      method: action.method,
      url: action.url,
      request_headers: action.request_headers ?? null,
      response_observation: action.response_observation ?? null,
      operator_id: normalizedOperatorId,
      rationale: normalizedRationale,
      authorization_mode: trust.mode,
      tls_policy: tlsPolicyForRun(loaded.run),
      // This is derived from the controller's successful window, receipt,
      // event-chain, and identity checks above. It is not caller consent.
      current_authorization_confirmed: true,
      budget_before: structuredClone(loaded.run.budget),
    }, now)
    await saveRun(loaded)

    const abortController = new AbortController()
    const stopWatching = startStopWatcher(
      loaded.directory,
      abortController,
      stopPollIntervalMs,
    )
    const currentPhase = 'ACTION'
    let sentRecorded = false
    let actionPreDispatchIdentity = null
    let actionStartedAt = null
    const beforeSend = async ({ url, method, request_headers: requestHeaders, dns, tls }) => {
      assertActionWindow(loaded.run, now)
      const currentMarker = await loadStopMarker(loaded.directory)
      if (currentMarker) {
        abortController.abort(new Error(currentMarker.reason))
        throw controllerError('HTTP_RECON_STOP_REQUESTED', currentMarker.reason)
      }
      const expectedMethod = action.method
      const expectedUrl = action.url
      const expectedRequestHeaders = action.request_headers ?? null
      if (
        method !== expectedMethod
        || url !== expectedUrl
        || canonicalJson(requestHeaders ?? null) !== canonicalJson(expectedRequestHeaders)
      ) {
        throw controllerError(
          'HTTP_RECON_PRE_DISPATCH_SCOPE_MISMATCH',
          `${currentPhase.toLowerCase()} pre-dispatch request does not match its sealed method, URL, and diagnostic-header profile`,
        )
      }
      const transportIdentity = preDispatchTransportIdentity(
        loaded.run,
        url,
        dns,
        tls,
      )
      action.state = 'SENT'
      action.sent_at = timestamp(now)
      await saveRun(loaded)
      await appendEvent(loaded, 'ACTION_REQUEST_PRE_DISPATCH', {
        action_id: action.action_id,
        method,
        url,
        request_headers: requestHeaders ?? null,
        response_observation: action.response_observation ?? null,
        transport_identity: transportIdentity,
      }, now)
      actionPreDispatchIdentity = transportIdentity
      sentRecorded = true
      await saveRun(loaded)
    }

    try {
      await waitForRequestInterval(
        loaded.run,
        now,
        abortController.signal,
        delayImpl,
      )
      actionStartedAt = timestamp(now)
      const transport = await probeImpl({
        url: action.url,
        method: action.method,
        requestHeaderProfile: action.request_headers,
        responseObservationProfile: action.response_observation,
        tlsVerificationMode: tlsPolicyForRun(loaded.run).mode,
        tlsSpkiSha256: tlsSpkiPinForRun(loaded.run),
        timeoutMs: loaded.run.limits.request_timeout_ms,
        maxResponseBytes: Math.min(
          loaded.run.limits.max_response_bytes,
          loaded.run.limits.max_aggregate_response_bytes
            - loaded.run.budget.response_bytes_used,
        ),
        signal: abortController.signal,
        beforeSend,
        dependencies: clientDependencies,
      })
      assertReturnedTransportIdentity({
        run: loaded.run,
        url: action.url,
        transport,
        expectedIdentity: actionPreDispatchIdentity,
        code: 'HTTP_RECON_TRANSPORT_IDENTITY_CHANGED',
        message: 'target transport identity changed after durable pre-dispatch recording',
      })
      const completedAt = timestamp(now)
      const observation = await commitTransportObservation({
        loaded,
        action,
        transport,
        startedAt: actionStartedAt,
        completedAt,
        now,
      })
      const stopReason = responseStopReason(observation.stop_condition)
      if (stopReason) {
        await markStopped(loaded, null, stopReason, now)
      } else {
        await saveRun(loaded)
      }
      return {
        run: structuredClone(loaded.run),
        action: structuredClone(action),
        observation,
        stop_reason: stopReason,
      }
    } catch (error) {
      const currentMarker = await loadStopMarker(loaded.directory)
      if (currentPhase === 'ACTION' && error.result) {
        let resultIdentityValid = false
        try {
          assertReturnedTransportIdentity({
            run: loaded.run,
            url: action.url,
            transport: error.result,
            expectedIdentity: actionPreDispatchIdentity,
            code: 'HTTP_RECON_TRANSPORT_IDENTITY_CHANGED',
            message: 'target transport identity changed after durable pre-dispatch recording',
          })
          resultIdentityValid = true
        } catch (identityError) {
          error = identityError
        }
        if (resultIdentityValid) {
          const stopReason = error.condition ?? error.code ?? 'STOP_CONDITION'
          const completedAt = timestamp(now)
          const observation = await commitTransportObservation({
            loaded,
            action,
            transport: error.result,
            startedAt: actionStartedAt ?? action.sent_at ?? completedAt,
            completedAt,
            now,
            stopCondition: stopReason,
          })
          const committedStopReason = responseStopReason(observation.stop_condition)
          await markStopped(
            loaded,
            currentMarker,
            currentMarker?.reason ?? committedStopReason,
            now,
          )
          return {
            run: structuredClone(loaded.run),
            action: structuredClone(action),
            observation,
            stop_reason: loaded.run.stop.reason,
          }
        }
      }
      const requestMayHaveBeenSent = sentRecorded
        || error.request_may_have_been_sent === true
      action.state = requestMayHaveBeenSent ? 'DELIVERY_AMBIGUOUS' : 'FAILED'
      if (requestMayHaveBeenSent && action.sent_at === null) {
        action.sent_at = action.leased_at
      }
      action.completed_at = timestamp(now)
      action.error = {
        code: error.code ?? 'HTTP_RECON_EXECUTION_FAILED',
        message: String(error.message ?? error).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 1024),
      }
      loaded.run.state = requestMayHaveBeenSent ? 'OUTCOME_UNCERTAIN' : 'FAILED'
      if (currentMarker) {
        loaded.run.stop = {
          requested_at: currentMarker.requested_at,
          observed_at: timestamp(now),
          operator_id: currentMarker.operator_id,
          reason: currentMarker.reason,
        }
        if (!requestMayHaveBeenSent) loaded.run.state = 'STOPPED'
      }
      await appendEvent(loaded, requestMayHaveBeenSent
        ? 'ACTION_DELIVERY_AMBIGUOUS'
        : 'ACTION_FAILED', {
        action_id: action.action_id,
        phase: currentPhase,
        error: structuredClone(action.error),
        stop_requested: currentMarker !== null,
      }, now)
      await saveRun(loaded)
      if (currentMarker) {
        return {
          run: structuredClone(loaded.run),
          action: structuredClone(action),
          stop_reason: currentMarker.reason,
        }
      }
      error.bundle = loaded.directory
      throw error
    } finally {
      stopWatching()
    }
  })
}

function reportCoverage(run) {
  const committed = run.actions.filter(({ state }) => state === 'COMMITTED').length
  return {
    committed,
    total: run.actions.length,
    gaps: run.actions.filter(({ state }) => state !== 'COMMITTED'),
  }
}

async function loadObservations(loaded) {
  const observations = []
  for (const action of loaded.run.actions) {
    if (!action.observation_path) continue
    const path = safeArtifactPath(loaded.directory, action.observation_path)
    const artifact = await readJson(path, MAX_OBSERVATION_BYTES, action.observation_path)
    if (sha256Hex(artifact.bytes) !== action.observation_sha256) {
      throw controllerError(
        'HTTP_RECON_OBSERVATION_DIGEST_MISMATCH',
        `observation ${action.observation_path} does not match run.json`,
      )
    }
    assertValidHttpReconObservation(artifact.value)
    observations.push(artifact.value)
  }
  return observations
}

export function renderHttpReconReport({ run, observations }) {
  const coverage = reportCoverage(run)
  const authorityLines = [
    '- Authorization mode: `OPERATOR_ATTESTED`',
    `- Declaring operator: \`${run.authorization.operator_id}\``,
    `- Declared authorizer: ${run.authorization.authorized_by}`,
    `- Authorization reference: ${run.authorization.authorization_reference}`,
    `- Locally sealed scope SHA-256: \`${run.authorization.scope_sha256}\``,
    '- Authorization source: operator declaration',
  ]
  const completionBoundary = 'Completion means only that the locally hash-bound HTTP request denominator ran within the operator-attested scope.'
  const authorityBoundary = 'Authorization is an operator declaration; the controller records the statement and exact scope without independently deciding legal authority.'
  const boundaryLabel = 'Operator-attested external HTTP reconnaissance only.'
  const tlsPolicy = tlsPolicyForRun(run)
  const tlsPolicyLine = tlsPolicy.mode === 'PKIX_HOSTNAME'
    ? '- TLS verification policy: runtime-configured CA trust and hostname validation; no advance SPKI pin'
    : `- TLS verification policy: runtime-configured CA trust, hostname validation, and SPKI pin \`${tlsPolicy.spki_sha256}\``
  const lines = [
    '# Operator-attested external HTTP reconnaissance',
    '',
    `- Engagement: \`${run.engagement_id}\``,
    `- Run: \`${run.run_id}\``,
    `- State: **${run.state}**`,
    `- Exact probe denominator: **${coverage.committed}/${coverage.total}**`,
    ...authorityLines,
    `- Target origin: \`${run.target.origin}\``,
    tlsPolicyLine,
    '',
    '## Boundary and non-claims',
    '',
    `${boundaryLabel} No repository or source was supplied; repository inventory, lens activation, source closure, and code coverage are NOT APPLICABLE. ${completionBoundary}`,
    '',
    `This run did not perform exploitation, authenticated testing, form submission, browser execution, mutation, crawling, fuzzing, brute force, bulk access, or load testing. ${authorityBoundary} CDN, WAF, reverse-proxy, and cache behavior may mediate observations. Response observations do not establish root cause or that the target is secure.`,
    '',
    'Local event hashes are tamper-evident only when their terminal digest is retained independently. The controller makes no OWASP APTS or NIST SP 800-115 conformance or certification claim.',
    '',
    '## Exact sealed actions',
    '',
    '| # | Method | URL | State | HTTP |',
    '|---:|---|---|---|---:|',
  ]
  const byId = new Map(observations.map((item) => [item.action_id, item]))
  for (const action of run.actions) {
    const observation = byId.get(action.action_id)
    lines.push(
      `| ${action.sequence} | ${action.method} | \`${action.url}\` | ${action.state} | ${observation?.status_code ?? '—'} |`,
    )
  }
  lines.push('', '## Observations', '')
  if (observations.length === 0) {
    lines.push('No probe response was committed.')
  } else {
    for (const observation of observations) {
      lines.push(
        `### ${observation.action_id}`,
        '',
        `- HTTP status: ${observation.status_code}`,
        `- Response bytes hashed then discarded: ${observation.body.size}`,
        `- Response body SHA-256: \`${observation.body.sha256}\``,
        `- DNS-set SHA-256: \`${observation.network.dns_sha256}\``,
        `- TLS verification: \`${observation.network.tls_verification}\``,
        `- Observed TLS SPKI SHA-256: \`${observation.network.peer_spki_sha256}\``,
        `- Retained header names: ${observation.response_headers.map(({ name }) => `\`${name}\``).join(', ') || 'none'}`,
        '',
      )
    }
  }
  lines.push('## Gaps and stop state', '')
  if (coverage.gaps.length === 0) {
    lines.push('No planned-request gap remains. This is not a no-vulnerability claim.')
  } else {
    for (const gap of coverage.gaps) {
      lines.push(`- ${gap.action_id}: ${gap.state}${gap.error ? ` — ${gap.error.code}: ${gap.error.message}` : ''}`)
    }
  }
  if (run.stop) {
    lines.push('', `Stop reason: ${run.stop.reason}`)
  }
  lines.push(
    '',
    '## Outcome label',
    '',
    coverage.gaps.length === 0 && run.state === 'PROBE_PLAN_COMPLETE'
      ? '`NO_FINDINGS_OBSERVED_IN_AUTHORIZED_PROBED_SURFACE`'
      : '`AUTHORIZED_PROBED_SURFACE_INCOMPLETE`',
    '',
  )
  return `${lines.join('\n')}\n`
}

export async function finalizeHttpReconBundle({
  bundle,
  now = () => new Date(),
}) {
  const loaded = await loadRun(bundle)
  return withRunLock(loaded, now, async () => {
    const refreshed = await loadRun(loaded.directory)
    loaded.run = refreshed.run
    const trust = await loadAuthorizationContext({
      loaded,
      now,
      requireCurrentValidity: false,
    })
    const evidence = await verifyExistingEvidence({
      loaded,
      trust,
      forDispatch: false,
      recoverFsyncedTail: true,
    })
    if (evidence.recovered_finalized) {
      const report = await readBoundedNoFollow(
        join(loaded.directory, REPORT_FILE),
        MAX_REPORT_BYTES,
        REPORT_FILE,
      )
      const expected = renderHttpReconReport({
        run: loaded.run,
        observations: evidence.observations,
      })
      if (
        report.toString('utf8') !== expected
        || report.length !== loaded.run.report.size
        || sha256Hex(report) !== loaded.run.report.sha256
      ) {
        throw controllerError(
          'HTTP_RECON_REPORT_RENDER_MISMATCH',
          'recovered finalized report is not the deterministic run rendering',
        )
      }
      await saveRun(loaded)
      return {
        directory: loaded.directory,
        run: structuredClone(loaded.run),
        reportPath: join(loaded.directory, REPORT_FILE),
      }
    }
    if (evidence.recovered) await saveRun(loaded)
    const marker = await loadStopMarker(loaded.directory)
    if (marker && !['STOPPED', 'OUTCOME_UNCERTAIN'].includes(loaded.run.state)) {
      const inFlight = loaded.run.actions.find(({ state }) =>
        state === 'LEASED' || state === 'SENT')
      await markStopped(
        loaded,
        marker,
        marker.reason,
        now,
        inFlight,
        evidence.events,
      )
    }
    if (!marker) {
      await terminalizeInterruptedAction(loaded, now, evidence.events)
    }
    const coverage = reportCoverage(loaded.run)
    if (!['STOPPED', 'FAILED', 'OUTCOME_UNCERTAIN'].includes(loaded.run.state)) {
      if (coverage.gaps.length > 0) {
        throw controllerError(
          'HTTP_RECON_PLAN_INCOMPLETE',
          `${coverage.gaps.length} sealed action(s) remain incomplete`,
        )
      }
      loaded.run.state = 'PROBE_PLAN_COMPLETE'
    }
    if (
      loaded.run.state === 'PROBE_PLAN_COMPLETE'
      && evidence.observations.length !== loaded.run.actions.length
    ) {
      throw controllerError(
        'HTTP_RECON_COMPLETE_DENOMINATOR_MISMATCH',
        'complete state requires one observation per action',
      )
    }
    const observations = evidence.observations
    const report = renderHttpReconReport({ run: loaded.run, observations })
    const reportPath = join(loaded.directory, REPORT_FILE)
    let existing
    try {
      existing = await readBoundedNoFollow(reportPath, MAX_REPORT_BYTES, REPORT_FILE)
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }
    if (existing) {
      if (existing.toString('utf8') !== report) {
        throw controllerError(
          'HTTP_RECON_REPORT_CHANGED',
          'existing HTTP-recon report differs from deterministic rendering',
        )
      }
    } else {
      await exclusiveWrite(reportPath, report)
    }
    loaded.run.report = {
      path: REPORT_FILE,
      sha256: sha256Hex(Buffer.from(report, 'utf8')),
      size: Buffer.byteLength(report),
      generated_at: timestamp(now),
    }
    await appendEvent(loaded, 'RUN_FINALIZED', {
      state: loaded.run.state,
      completed_actions: coverage.committed,
      total_actions: coverage.total,
      report_sha256: loaded.run.report.sha256,
    }, now)
    await saveRun(loaded)
    return {
      directory: loaded.directory,
      run: structuredClone(loaded.run),
      reportPath,
    }
  })
}

function parseEventLines(bytes) {
  const text = bytes.toString('utf8')
  if (text.length === 0) return []
  const lines = text.split('\n')
  if (lines.at(-1) !== '') {
    throw controllerError(
      'HTTP_RECON_EVENT_LOG_TRUNCATED',
      'events.jsonl does not end on a complete record boundary',
    )
  }
  lines.pop()
  return lines.map((line, index) => {
    try {
      return JSON.parse(line)
    } catch (error) {
      throw controllerError(
        'HTTP_RECON_EVENT_JSON_INVALID',
        `events.jsonl record ${index + 1} is invalid JSON`,
        { cause: error },
      )
    }
  })
}

function verifyEventRecords(run, records) {
  let previous = ZERO_SHA256
  for (let index = 0; index < records.length; index += 1) {
    const record = records[index]
    const { record_sha256: digest, ...unsigned } = record
    if (
      record.sequence !== index + 1
      || record.run_id !== run.run_id
      || record.engagement_id !== run.engagement_id
      || record.previous_sha256 !== previous
      || digest !== sha256Hex(canonicalJson(unsigned))
    ) {
      throw controllerError(
        'HTTP_RECON_EVENT_CHAIN_INVALID',
        `events.jsonl record ${index + 1} breaks the hash chain`,
      )
    }
    previous = digest
  }
  return previous
}

function verifyEventChain(run, records) {
  const previous = verifyEventRecords(run, records)
  if (
    run.event_chain.count !== records.length
    || run.event_chain.last_sha256 !== previous
  ) {
    throw controllerError(
      'HTTP_RECON_EVENT_ROOT_MISMATCH',
      'run.json event root does not match events.jsonl',
    )
  }
}

function eventTailError(message) {
  return controllerError('HTTP_RECON_EVENT_TAIL_INVALID', message)
}

async function recoveredStop(event, directory) {
  const marker = await loadStopMarker(directory)
  return {
    requested_at: marker?.requested_at ?? event.at,
    observed_at: event.at,
    operator_id: marker?.operator_id ?? 'controller',
    reason: marker?.reason ?? event.details?.reason
      ?? event.details?.error?.message
      ?? 'recovered terminal event',
  }
}

async function replayFsyncedEventTail({ loaded, trust, events }) {
  const rootCount = loaded.run.event_chain.count
  if (rootCount > events.length) {
    throw controllerError(
      'HTTP_RECON_EVENT_ROOT_MISMATCH',
      'run.json event root is ahead of events.jsonl',
    )
  }
  const rootedDigest = rootCount === 0
    ? ZERO_SHA256
    : events[rootCount - 1].record_sha256
  if (rootedDigest !== loaded.run.event_chain.last_sha256) {
    throw controllerError(
      'HTTP_RECON_EVENT_ROOT_MISMATCH',
      'run.json event root is not a prefix of events.jsonl',
    )
  }
  const tail = events.slice(rootCount)
  if (tail.length === 0) {
    throw controllerError(
      'HTTP_RECON_EVENT_ROOT_MISMATCH',
      'run.json event root does not match events.jsonl',
    )
  }
  if (tail.length > 2) {
    throw eventTailError('fsynced event tail exceeds the bounded crash window')
  }

  const run = structuredClone(loaded.run)
  const rootedEvents = events.slice(0, rootCount)
  const applied = []
  for (const event of tail) {
    const action = run.actions.find(
      ({ action_id: actionId }) => actionId === event.details?.action_id,
    )
    if (event.type === 'ACTION_LEASED') {
      if (
        !action
        || action.state !== 'LEASED'
        || run.state !== 'ACTIVE'
        || event.details?.method !== action.method
        || event.details?.url !== action.url
        || canonicalJson(event.details?.request_headers ?? null)
          !== canonicalJson(action.request_headers ?? null)
        || canonicalJson(event.details?.response_observation ?? null)
          !== canonicalJson(action.response_observation ?? null)
        || event.details?.authorization_mode !== trust.mode
        || canonicalJson(event.details?.budget_before)
          !== canonicalJson(run.budget)
      ) {
        throw eventTailError('ACTION_LEASED tail does not match durable run state')
      }
    } else if (event.type === 'ACTION_REQUEST_PRE_DISPATCH') {
      if (
        !action
        || action.state !== 'SENT'
        || event.details?.method !== action.method
        || event.details?.url !== action.url
        || canonicalJson(event.details?.request_headers ?? null)
          !== canonicalJson(action.request_headers ?? null)
        || canonicalJson(event.details?.response_observation ?? null)
          !== canonicalJson(action.response_observation ?? null)
      ) {
        throw eventTailError('action pre-dispatch tail does not match durable SENT state')
      }
      assertRecordedTransportIdentity(
        run,
        action.url,
        event.details?.transport_identity,
      )
    } else if (event.type === 'ACTION_COMMITTED') {
      if (
        !action
        || action.state !== 'SENT'
        || typeof event.details?.observation_path !== 'string'
        || typeof event.details?.observation_sha256 !== 'string'
        || !Number.isSafeInteger(event.details?.response_bytes)
      ) {
        throw eventTailError('committed-action tail does not match durable SENT state')
      }
      const observationArtifact = await readJson(
        safeArtifactPath(loaded.directory, event.details.observation_path),
        MAX_OBSERVATION_BYTES,
        event.details.observation_path,
      )
      if (
        sha256Hex(observationArtifact.bytes) !== event.details.observation_sha256
        || observationArtifact.value?.action_id !== action.action_id
        || canonicalJson(event.details?.response_observation ?? null)
          !== canonicalJson(action.response_observation ?? null)
        || canonicalJson(event.details?.stop_condition ?? null)
          !== canonicalJson(observationArtifact.value?.stop_condition ?? null)
        || !responseObservationMatchesAction(observationArtifact.value, action)
      ) {
        throw eventTailError('committed-action tail lacks its exact observation')
      }
      const expectedBudget = {
        ...structuredClone(run.budget),
        probe_requests_used: run.budget.probe_requests_used + 1,
        response_bytes_used:
          run.budget.response_bytes_used + event.details.response_bytes,
        last_request_at: observationArtifact.value.observed_at,
      }
      if (
        canonicalJson(expectedBudget)
          !== canonicalJson(event.details?.budget_after)
      ) {
        throw eventTailError('committed-action tail budget is not derivable')
      }
      action.state = 'COMMITTED'
      action.completed_at = observationArtifact.value.observed_at
      action.observation_path = event.details.observation_path
      action.observation_sha256 = event.details.observation_sha256
      action.error = null
      run.budget = expectedBudget
      if (observationArtifact.value.stop_condition !== null) {
        run.state = 'STOPPED'
        run.stop = {
          requested_at: event.at,
          observed_at: event.at,
          operator_id: 'controller',
          reason: responseStopReason(observationArtifact.value.stop_condition),
        }
      }
    } else if (
      event.type === 'ACTION_DELIVERY_AMBIGUOUS'
      || event.type === 'ACTION_FAILED'
    ) {
      if (
        !action
        || !['LEASED', 'SENT'].includes(action.state)
        || !event.details?.error
      ) {
        throw eventTailError('terminal action tail does not match an in-flight action')
      }
      const ambiguous = event.type === 'ACTION_DELIVERY_AMBIGUOUS'
      action.state = ambiguous ? 'DELIVERY_AMBIGUOUS' : 'FAILED'
      if (ambiguous && action.sent_at === null) {
        const preDispatch = unsettledPreDispatchEvent(
          [...rootedEvents, ...applied],
          action.action_id,
        )
        action.sent_at = preDispatch?.at ?? action.leased_at
      }
      action.completed_at = event.at
      action.error = structuredClone(event.details.error)
      run.state = ambiguous
        ? 'OUTCOME_UNCERTAIN'
        : (event.details?.stop_requested === true ? 'STOPPED' : 'FAILED')
      if (event.details?.stop_requested === true) {
        run.stop = await recoveredStop(event, loaded.directory)
      }
    } else if (event.type === 'STOP_CONFIRMED') {
      if (
        !['STOPPED', 'OUTCOME_UNCERTAIN'].includes(
          event.details?.terminal_state,
        )
      ) {
        throw eventTailError('stop tail has an invalid terminal state')
      }
      if (action && ['LEASED', 'SENT'].includes(action.state)) {
        const ambiguous = event.details.terminal_state === 'OUTCOME_UNCERTAIN'
        action.state = ambiguous ? 'DELIVERY_AMBIGUOUS' : 'FAILED'
        if (ambiguous && action.sent_at === null) action.sent_at = event.at
        action.completed_at = event.at
        action.error = {
          code: ambiguous ? 'DELIVERY_AMBIGUOUS' : 'STOPPED_BEFORE_SEND',
          message: event.details?.reason,
        }
      } else if (event.details?.action_id !== null && !action) {
        throw eventTailError('stop tail names an unknown action')
      }
      run.state = event.details.terminal_state
      run.stop = await recoveredStop(event, loaded.directory)
    } else if (event.type === 'RUN_FINALIZED') {
      const committed = run.actions.filter(({ state }) => state === 'COMMITTED').length
      const recoveredFinalState = ['STOPPED', 'FAILED', 'OUTCOME_UNCERTAIN'].includes(
        run.state,
      )
        ? run.state
        : (committed === run.actions.length ? 'PROBE_PLAN_COMPLETE' : null)
      if (
        event !== tail.at(-1)
        || run.report !== null
        || recoveredFinalState === null
        || event.details?.state !== recoveredFinalState
        || event.details?.completed_actions !== committed
        || event.details?.total_actions !== run.actions.length
        || typeof event.details?.report_sha256 !== 'string'
      ) {
        throw eventTailError('finalization tail does not match terminal run state')
      }
      const report = await readBoundedNoFollow(
        join(loaded.directory, REPORT_FILE),
        MAX_REPORT_BYTES,
        REPORT_FILE,
      )
      if (sha256Hex(report) !== event.details.report_sha256) {
        throw eventTailError('finalization tail does not match report.md')
      }
      run.report = {
        path: REPORT_FILE,
        sha256: event.details.report_sha256,
        size: report.length,
        generated_at: event.at,
      }
      run.state = recoveredFinalState
    } else {
      throw eventTailError(`event ${event.type} is not a recoverable crash tail`)
    }
    applied.push(event)
  }

  run.event_chain = {
    count: events.length,
    last_sha256: events.at(-1).record_sha256,
  }
  assertValidHttpReconRun(run)
  loaded.run = run
  return {
    recovered: true,
    recovered_types: tail.map(({ type }) => type),
    recovered_finalized: tail.at(-1)?.type === 'RUN_FINALIZED',
  }
}

async function verifyExistingEvidence({
  loaded,
  trust,
  forDispatch = true,
  recoverFsyncedTail = false,
}) {
  const eventBytes = await readBoundedNoFollow(
    join(loaded.directory, EVENTS_FILE),
    MAX_EVENT_BYTES,
    EVENTS_FILE,
  )
  const events = parseEventLines(eventBytes)
  verifyEventRecords(loaded.run, events)
  let recovery = {
    recovered: false,
    recovered_types: [],
    recovered_finalized: false,
  }
  if (
    loaded.run.event_chain.count !== events.length
    || loaded.run.event_chain.last_sha256
      !== (events.at(-1)?.record_sha256 ?? ZERO_SHA256)
  ) {
    if (!recoverFsyncedTail) {
      throw controllerError(
        'HTTP_RECON_EVENT_ROOT_MISMATCH',
        'run.json event root does not match events.jsonl',
      )
    }
    recovery = await replayFsyncedEventTail({ loaded, trust, events })
  }
  verifyEventChain(loaded.run, events)
  if (
    events[0]?.type !== 'PLAN_CREATED'
    || events[0]?.details?.plan_sha256 !== loaded.run.plan_sha256
    || events[0]?.details?.authorization_mode !== loaded.run.authorization.mode
    || canonicalJson(events[0]?.details?.tls_policy)
      !== canonicalJson(tlsPolicyForRun(loaded.run))
  ) {
    throw controllerError(
      'HTTP_RECON_PLAN_EVENT_INVALID',
      'event history does not begin with the sealed plan commitment',
    )
  }
  if (loaded.run.authorization.mode === 'OPERATOR_ATTESTED') {
    const receipt = verifyOperatorAuthorizationReceipt({
      value: events[0]?.details?.operator_authorization_receipt,
      planSha256: loaded.run.plan_sha256,
      scopeRevisionSha256: loaded.run.authorization.scope_sha256,
      target: {
        kind: 'https_url',
        url: loaded.run.actions[0]?.url,
      },
      fail: (code, message) => {
        throw controllerError(`HTTP_RECON_OPERATOR_AUTHORIZATION_${code}`, message)
      },
    })
    if (
      receipt.operator_id !== loaded.run.authorization.operator_id
      || receipt.declared_at !== loaded.run.authorization.attested_at
      || receipt.authorization_reference
        !== loaded.run.authorization.authorization_reference
    ) {
      throw controllerError(
        'HTTP_RECON_OPERATOR_AUTHORIZATION_RECEIPT_INVALID',
        'operator authorization receipt does not bind the sealed authorization identity',
      )
    }
  }
  if (forDispatch && events.some(({ type }) => type === 'RUN_FINALIZED')) {
    throw controllerError(
      'HTTP_RECON_ALREADY_FINALIZED',
      'finalized HTTP-recon evidence cannot dispatch another action',
    )
  }
  if (forDispatch && events.some(({ type }) => type === 'STOP_CONFIRMED')) {
    throw controllerError(
      'HTTP_RECON_STOP_ALREADY_CONFIRMED',
      'stopped HTTP-recon evidence cannot dispatch another action',
    )
  }

  const planActionIds = new Set(loaded.run.actions.map(({ action_id: id }) => id))
  const actionById = new Map(
    loaded.run.actions.map((action) => [action.action_id, action]),
  )
  const leasedByAction = new Map()
  const preDispatchByAction = new Map()
  const committedByAction = new Map()
  const dispatchedActions = new Set()
  const allowedEventTypes = new Set([
    'PLAN_CREATED',
    'ACTION_LEASED',
    'ACTION_REQUEST_PRE_DISPATCH',
    'ACTION_COMMITTED',
    'ACTION_DELIVERY_AMBIGUOUS',
    'ACTION_FAILED',
    'STOP_CONFIRMED',
    'RUN_FINALIZED',
  ])
  for (const event of events) {
    if (!allowedEventTypes.has(event.type)) {
      throw controllerError(
        'HTTP_RECON_EVENT_TYPE_INVALID',
        `event ${event.sequence} has an unsupported type`,
      )
    }
    const eventActionId = event.details?.action_id
    if (eventActionId !== null && eventActionId !== undefined) {
      if (!planActionIds.has(eventActionId)) {
        throw controllerError(
          'HTTP_RECON_EVENT_ACTION_UNKNOWN',
          `event ${event.sequence} names an action outside the sealed plan`,
        )
      }
    }
    if (event.type === 'ACTION_LEASED') {
      const plannedAction = actionById.get(eventActionId)
      const attestedLeaseValid = event.details?.current_authorization_confirmed === true
        && event.details?.operator_id === loaded.run.authorization.operator_id
      if (
        leasedByAction.has(eventActionId)
        || event.details?.authorization_mode !== trust.mode
        || event.details?.method !== plannedAction?.method
        || event.details?.url !== plannedAction?.url
        || canonicalJson(event.details?.request_headers ?? null)
          !== canonicalJson(plannedAction?.request_headers ?? null)
        || canonicalJson(event.details?.response_observation ?? null)
          !== canonicalJson(plannedAction?.response_observation ?? null)
        || canonicalJson(event.details?.tls_policy)
          !== canonicalJson(tlsPolicyForRun(loaded.run))
        || !attestedLeaseValid
      ) {
        throw controllerError(
          'HTTP_RECON_ACTION_LEASE_INVALID',
          `action lease event ${event.sequence} is duplicated or does not preserve authorization and scope`,
        )
      }
      leasedByAction.set(eventActionId, event)
    }
    if (event.type === 'ACTION_REQUEST_PRE_DISPATCH') {
      const plannedAction = actionById.get(eventActionId)
      if (
        preDispatchByAction.has(eventActionId)
        || event.details?.method !== plannedAction?.method
        || event.details?.url !== plannedAction?.url
        || canonicalJson(event.details?.request_headers ?? null)
          !== canonicalJson(plannedAction?.request_headers ?? null)
        || canonicalJson(event.details?.response_observation ?? null)
          !== canonicalJson(plannedAction?.response_observation ?? null)
      ) {
        throw controllerError(
          'HTTP_RECON_ACTION_PRE_DISPATCH_INVALID',
          `action pre-dispatch event ${event.sequence} is duplicated or outside the sealed action`,
        )
      }
      assertRecordedTransportIdentity(
        loaded.run,
        plannedAction.url,
        event.details?.transport_identity,
      )
      preDispatchByAction.set(eventActionId, event)
      dispatchedActions.add(eventActionId)
    }
    if (event.type === 'ACTION_COMMITTED') {
      if (committedByAction.has(eventActionId)) {
        throw controllerError(
          'HTTP_RECON_ACTION_REPLAYED',
          `action ${eventActionId} has more than one commit event`,
        )
      }
      committedByAction.set(eventActionId, event)
    }
  }
  for (const actionId of dispatchedActions) {
    if (forDispatch && !committedByAction.has(actionId)) {
      throw controllerError(
        'HTTP_RECON_PRIOR_DELIVERY_UNCERTAIN',
        `action ${actionId} has pre-dispatch evidence without a committed response`,
      )
    }
  }
  const observations = await loadObservations(loaded)
  const observationByAction = new Map(
    observations.map((observation) => [observation.action_id, observation]),
  )
  for (const action of loaded.run.actions) {
    const observation = observationByAction.get(action.action_id)
    const commit = committedByAction.get(action.action_id)
    const lease = leasedByAction.get(action.action_id)
    const preDispatch = preDispatchByAction.get(action.action_id)
    const authorityMatches = observation?.authority?.mode === 'OPERATOR_ATTESTED'
      && observation.authority.authorization_id
        === loaded.run.authorization.authorization_id
      && observation.authority.operator_id
        === loaded.run.authorization.operator_id
      && observation.authority.scope_sha256
        === loaded.run.authorization.scope_sha256
      && observation.authority.plan_sha256 === loaded.run.plan_sha256
    const observationMatchesAction = observation !== undefined
      && observation.run_id === loaded.run.run_id
      && observation.engagement_id === loaded.run.engagement_id
      && observation.action_id === action.action_id
      && observation.sequence === action.sequence
      && observation.method === action.method
      && observation.url === action.url
    const identityMatches = observation !== undefined
      && preDispatch !== undefined
      && canonicalJson(observationTransportIdentity(observation))
        === canonicalJson(preDispatch.details.transport_identity)
    if (action.state === 'COMMITTED') {
      if (
        !observation
        || !commit
        || !lease
        || !preDispatch
        || lease.sequence >= commit.sequence
        || preDispatch.sequence >= commit.sequence
        || commit.details.observation_sha256 !== action.observation_sha256
        || commit.details.observation_path !== action.observation_path
        || commit.details.status_code !== observation.status_code
        || commit.details.response_bytes !== observation.body.size
        || canonicalJson(commit.details?.response_observation ?? null)
          !== canonicalJson(action.response_observation ?? null)
        || !responseObservationMatchesAction(observation, action)
        || !observationMatchesAction
        || !identityMatches
        || !authorityMatches
      ) {
        throw controllerError(
          'HTTP_RECON_COMMITTED_EVIDENCE_MISMATCH',
          `committed action ${action.action_id} lacks matching event or observation evidence`,
        )
      }
    } else if (observation || commit) {
      throw controllerError(
        'HTTP_RECON_ACTION_STATE_MISMATCH',
        `non-committed action ${action.action_id} has committed evidence`,
      )
    }
  }
  if (loaded.run.budget.probe_requests_used !== observations.length) {
    throw controllerError(
      'HTTP_RECON_PROBE_BUDGET_MISMATCH',
      'probe request counter does not match committed observations',
    )
  }
  if (loaded.run.budget.proof_requests_used !== 0) {
    throw controllerError(
      'HTTP_RECON_ATTESTED_PROOF_STATE_INVALID',
      'operator-attested evidence must not contain target-proof budget use',
    )
  }
  return { events, observations, ...recovery }
}

export async function validateHttpReconBundle({
  bundle,
  now = () => new Date(),
}) {
  const path = resolveBundle(bundle).directory
  const errors = []
  let loaded
  try {
    loaded = await loadRun(bundle)
    const trust = await loadAuthorizationContext({
      loaded,
      now,
      requireCurrentValidity: false,
    })
    const evidence = await verifyExistingEvidence({
      loaded,
      trust,
      forDispatch: false,
    })
    const observations = evidence.observations
    if (
      loaded.run.state === 'PROBE_PLAN_COMPLETE'
      && observations.length !== loaded.run.actions.length
    ) {
      throw controllerError(
        'HTTP_RECON_COMPLETE_DENOMINATOR_MISMATCH',
        'complete state requires one observation per action',
      )
    }
    if (loaded.run.report) {
      const report = await readBoundedNoFollow(
        safeArtifactPath(loaded.directory, loaded.run.report.path),
        MAX_REPORT_BYTES,
        loaded.run.report.path,
      )
      if (
        report.length !== loaded.run.report.size
        || sha256Hex(report) !== loaded.run.report.sha256
      ) {
        throw controllerError(
          'HTTP_RECON_REPORT_DIGEST_MISMATCH',
          'report does not match its committed size and SHA-256',
        )
      }
      const expected = renderHttpReconReport({ run: loaded.run, observations })
      if (report.toString('utf8') !== expected) {
        throw controllerError(
          'HTTP_RECON_REPORT_RENDER_MISMATCH',
          'report is not the deterministic rendering of run evidence',
        )
      }
    }
  } catch (error) {
    errors.push({
      code: error.code ?? 'HTTP_RECON_VALIDATION_FAILED',
      message: error.message,
    })
  }
  return {
    valid: errors.length === 0,
    path: loaded?.directory ?? path,
    state: loaded?.run?.state ?? null,
    errors,
  }
}

export async function httpReconReportPath(bundle) {
  const loaded = await loadRun(bundle)
  if (!loaded.run.report) {
    throw controllerError(
      'HTTP_RECON_REPORT_MISSING',
      'HTTP-recon report has not been finalized',
    )
  }
  const path = safeArtifactPath(loaded.directory, loaded.run.report.path)
  await readBoundedNoFollow(path, MAX_REPORT_BYTES, loaded.run.report.path)
  return path
}

export const httpReconControllerConstants = Object.freeze({
  RUN_FILE,
  ATTESTED_SCOPE_FILE,
  EVENTS_FILE,
  REPORT_FILE,
  STOP_FILE,
  LOCK_FILE,
})
