import { Buffer } from 'node:buffer'

import {
  buildActionCountersignaturePayload,
  canonicalJson,
  httpAuthedAuthorizationEvidence,
  httpAuthedAuthorizationBindingSha256,
  httpAuthedCampaignLedgerBindingSha256,
  isHttpAuthedBrowserSessionCredential,
  sha256Hex,
  verifyHttpAuthedActionCountersignature,
  verifyHttpAuthedCandidate,
  verifyHttpAuthedCleanupCandidate,
} from './http-authed-contracts.mjs'
import { sanitizeHttpAuthedHeaderNames } from './http-authed-response-metadata.mjs'
import { httpAuthedCandidateIdentity } from './http-authed-campaign-ledger.mjs'

const MAX_CREDENTIAL_BYTES = 64 * 1024
const MAX_BODY_BYTES = 16 * 1024 * 1024
const REQUIRED_LEDGER_METHODS = [
  'snapshot',
  'actionState',
  'enqueueCandidate',
  'leaseAction',
  'consumeApproval',
  'markPreDispatch',
  'markOutcome',
  'recordVerification',
  'terminalizeAction',
]

export class HttpAuthedMutationControllerError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause })
    this.name = 'HttpAuthedMutationControllerError'
    this.code = code
  }
}

function mutationError(code, message, options) {
  return new HttpAuthedMutationControllerError(code, message, options)
}

function exactBytes(value, label, { minimum = 1, maximum }) {
  if (!(typeof value === 'string' || Buffer.isBuffer(value) || value instanceof Uint8Array)) {
    throw mutationError('HTTP_AUTHED_MUTATION_BYTES_REQUIRED', `${label} must be supplied as bytes`)
  }
  const bytes = Buffer.from(value)
  if (bytes.length < minimum || bytes.length > maximum) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_BYTES_INVALID',
      `${label} is outside its permitted byte range`,
    )
  }
  return bytes
}

function boundBody(metadata, supplied, label) {
  if (metadata === undefined) {
    if (supplied !== undefined) {
      throw mutationError(
        'HTTP_AUTHED_MUTATION_BODY_UNEXPECTED',
        `${label} bytes were supplied without sealed body metadata`,
      )
    }
    return null
  }
  const bytes = exactBytes(supplied, `${label} body`, { minimum: 0, maximum: MAX_BODY_BYTES })
  if (bytes.length !== metadata.byte_length || sha256Hex(bytes) !== metadata.sha256) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_BODY_BINDING_MISMATCH',
      `${label} body does not match its sealed length and digest`,
    )
  }
  return bytes
}

function validateLedger(ledger, expectedCampaignGrantSha256, scope) {
  if (!ledger || REQUIRED_LEDGER_METHODS.some((method) => typeof ledger[method] !== 'function')) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_LEDGER_REQUIRED',
      'declared mutation execution requires an open campaign ledger',
    )
  }
  const evidence = httpAuthedAuthorizationEvidence(scope)
  if (
    ledger.campaignGrantSha256 !== expectedCampaignGrantSha256
    || ledger.authorizationBindingSha256 !== httpAuthedAuthorizationBindingSha256(scope)
    || ledger.authorizationMode !== evidence.authorizationMode
    || ledger.independentlyVerified !== evidence.independentlyVerified
  ) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_LEDGER_BINDING_MISMATCH',
      'campaign ledger does not match the sealed authorization grant',
    )
  }
}

function responseMetadata(response) {
  if (
    !response
    || !Number.isSafeInteger(response.status)
    || response.status < 100
    || response.status > 599
    || !Number.isSafeInteger(response.responseBytes)
    || response.responseBytes < 0
    || !Array.isArray(response.responseHeaderNames)
    || response.responseHeaderNames.length > 256
  ) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_TRANSPORT_RESULT_INVALID',
      'mutation transport returned invalid response metadata',
    )
  }
  let headerNames
  try {
    headerNames = sanitizeHttpAuthedHeaderNames(response.responseHeaderNames)
  } catch {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_TRANSPORT_RESULT_INVALID',
      'mutation transport returned an invalid response header name',
    )
  }
  return {
    status: response.status,
    bytes: response.responseBytes,
    header_names: headerNames,
  }
}

function requestBinding({ actionId, phase, method, url, body }) {
  return sha256Hex(Buffer.from(canonicalJson({
    action_id: actionId,
    phase,
    method,
    url,
    body_sha256: body === null ? null : sha256Hex(body),
  }), 'utf8'))
}

function assertCleanupWindowAvailable(scope, currentTime) {
  const nowMs = (currentTime instanceof Date ? currentTime : new Date(currentTime)).getTime()
  const cleanupNotAfterMs = new Date(scope.validity.cleanup_not_after).getTime()
  const cleanupBudgetMs = (scope.limits.request_timeout_ms * 4)
    + (scope.limits.min_interval_ms * 3)
  if (
    !Number.isFinite(nowMs)
    || !Number.isFinite(cleanupNotAfterMs)
    || cleanupNotAfterMs - nowMs < cleanupBudgetMs
  ) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_CLEANUP_WINDOW_INSUFFICIENT',
      'authorization window cannot cover mutation settlement and the full cleanup sequence',
    )
  }
}

function phaseRequest(action, phase, mutationBody, rollbackBody) {
  if (phase === 'CREDENTIAL_PREFLIGHT') {
    return { ...action.__credential_preflight, body: null }
  }
  if (phase === 'BEFORE_READ') {
    return { ...action.before_read, body: null }
  }
  if (phase === 'MUTATION') {
    return { method: action.method, url: action.url, body: mutationBody }
  }
  if (phase === 'AFTER_READ') {
    return { ...action.after_read, body: null }
  }
  if (phase === 'ROLLBACK') {
    return { method: action.rollback.method, url: action.rollback.url, body: rollbackBody }
  }
  if (phase === 'ROLLBACK_VERIFY') {
    return { ...action.rollback.verification_read, body: null }
  }
  throw mutationError('HTTP_AUTHED_MUTATION_PHASE_INVALID', 'mutation phase is invalid')
}

function defaultCountersignatureVerifier({
  scope,
  action,
  countersignature,
  expectedCampaignGrantSha256,
  campaignLedgerSha256,
  now,
}) {
  if (scope.approver.mechanism !== 'ed25519_file') {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_APPROVER_UNSUPPORTED',
      'declared mutation execution currently requires an Ed25519 file approver',
    )
  }
  const expected = buildActionCountersignaturePayload({
    action,
    planSha256: expectedCampaignGrantSha256,
    campaignLedgerSha256,
    nonce: countersignature?.nonce,
    at: countersignature?.at,
  })
  const identity = verifyHttpAuthedActionCountersignature({
    countersignature,
    approverPublicKeyBytes: Buffer.from(scope.approver.public_key.value_base64, 'base64'),
    expected,
    now,
  })
  if (identity.keyId !== scope.approver.key_id) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_APPROVER_MISMATCH',
      'mutation countersignature does not match the sealed approver key',
    )
  }
  return identity
}

function observationResult(value) {
  if (
    !value
    || typeof value.valueMatch !== 'boolean'
    || typeof value.contextMatch !== 'boolean'
  ) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_OBSERVATION_INVALID',
      'mutation observation verifier returned an invalid decision',
    )
  }
  return {
    valueMatch: value.valueMatch,
    contextMatch: value.contextMatch,
    contextToken: value.contextToken,
  }
}

function jsonPointerTokens(pointer) {
  if (
    typeof pointer !== 'string'
    || !/^(?:\/(?:[^~/\u0000-\u001f\u007f]|~[01])*)+$/.test(pointer)
  ) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_JSON_POINTER_INVALID',
      'mutation observation JSON pointer is invalid',
    )
  }
  return pointer.slice(1).split('/').map((token) => token
    .replaceAll('~1', '/')
    .replaceAll('~0', '~'))
}

function pointerLocation(document, tokens) {
  let current = document
  for (let index = 0; index < tokens.length; index += 1) {
    const token = tokens[index]
    if (Array.isArray(current)) {
      if (!/^(?:0|[1-9][0-9]*)$/.test(token)) {
        throw mutationError(
          'HTTP_AUTHED_MUTATION_OBSERVATION_MISSING',
          'mutation observation pointer does not identify a response value',
        )
      }
      const position = Number(token)
      if (!Number.isSafeInteger(position) || position >= current.length) {
        throw mutationError(
          'HTTP_AUTHED_MUTATION_OBSERVATION_MISSING',
          'mutation observation pointer does not identify a response value',
        )
      }
      if (index === tokens.length - 1) return { parent: current, key: position }
      current = current[position]
      continue
    }
    if (
      current === null
      || typeof current !== 'object'
      || !Object.hasOwn(current, token)
    ) {
      throw mutationError(
        'HTTP_AUTHED_MUTATION_OBSERVATION_MISSING',
        'mutation observation pointer does not identify a response value',
      )
    }
    if (index === tokens.length - 1) return { parent: current, key: token }
    current = current[token]
  }
  throw mutationError(
    'HTTP_AUTHED_MUTATION_OBSERVATION_MISSING',
    'mutation observation pointer does not identify a response value',
  )
}

/**
 * Compares a transient JSON response without projecting its values. The
 * context token is a digest of the representation with the declared field
 * replaced by a fixed sentinel; callers keep it in memory between reads.
 */
export function verifyTransientHttpAuthedJsonObservation({
  response,
  observation,
  expectedDigest,
  baselineContextToken,
}) {
  if (
    observation?.format !== 'JSON'
    || !/^[a-f0-9]{64}$/.test(expectedDigest ?? '')
    || (
      baselineContextToken !== undefined
      && !/^[a-f0-9]{64}$/.test(baselineContextToken)
    )
  ) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_OBSERVATION_INVALID',
      'mutation observation contract is invalid',
    )
  }
  const bytes = exactBytes(response?.body, 'transient response body', {
    minimum: 1,
    maximum: MAX_BODY_BYTES,
  })
  try {
    let document
    try {
      document = JSON.parse(bytes.toString('utf8'))
    } catch (cause) {
      throw mutationError(
        'HTTP_AUTHED_MUTATION_RESPONSE_JSON_INVALID',
        'mutation observation response is not valid JSON',
        { cause },
      )
    }
    const tokens = jsonPointerTokens(observation.json_pointer)
    const selected = pointerLocation(document, tokens)
    const valueDigest = sha256Hex(Buffer.from(canonicalJson(selected.parent[selected.key]), 'utf8'))
    const contextDocument = structuredClone(document)
    const context = pointerLocation(contextDocument, tokens)
    context.parent[context.key] = { '$red-team-audit-declared-mutation': true }
    const contextToken = sha256Hex(Buffer.from(canonicalJson(contextDocument), 'utf8'))
    return {
      valueMatch: valueDigest === expectedDigest,
      contextMatch: baselineContextToken === undefined
        || contextToken === baselineContextToken,
      contextToken,
    }
  } finally {
    bytes.fill(0)
  }
}

function observationForPhase(action, phase) {
  if (phase === 'BEFORE_READ') return action.before_read.observation
  if (phase === 'AFTER_READ') return action.after_read.observation
  if (phase === 'ROLLBACK_VERIFY') return action.rollback.verification_read.observation
  throw mutationError(
    'HTTP_AUTHED_MUTATION_PHASE_INVALID',
    'mutation phase does not define an observation',
  )
}

function expectedStatusesForPhase(action, phase) {
  if (phase === 'CREDENTIAL_PREFLIGHT') {
    return Array.from({ length: 100 }, (_unused, index) => 200 + index)
  }
  if (phase === 'BEFORE_READ') return action.before_read.expected_statuses
  if (phase === 'MUTATION') return action.success_statuses
  if (phase === 'AFTER_READ') return action.after_read.expected_statuses
  if (phase === 'ROLLBACK') return action.rollback.success_statuses
  if (phase === 'ROLLBACK_VERIFY') return action.rollback.verification_read.expected_statuses
  throw mutationError('HTTP_AUTHED_MUTATION_PHASE_INVALID', 'mutation phase is invalid')
}

function publicResult({ lease, action, outcome, verification, responses }) {
  return {
    kind: 'red-team-audit/http-authed-mutation-result',
    schema_version: '1.0.0',
    outcome,
    action: {
      action_id: lease.actionId,
      sequence: lease.actionSequence,
      test_category: action.test_category,
      method: action.method,
    },
    verification: {
      before: verification.before,
      after: verification.after,
      rollback: verification.rollback,
    },
    responses: structuredClone(responses),
  }
}

/**
 * Executes one fully declared mutation using injected network and observation
 * boundaries. The campaign ledger is authoritative for dispatch consumption;
 * raw response bodies and header values are never projected into its events or
 * the returned result.
 */
export async function runDeclaredHttpAuthedMutation({
  ledger,
  scope,
  action,
  documentBytes,
  expectedCampaignGrantSha256,
  operatorId,
  countersignature,
  credentialValue,
  requestBodyBytes,
  rollbackBodyBytes,
  now = () => new Date(),
  transport,
  verifyCandidate = verifyHttpAuthedCandidate,
  verifyCleanupCandidate = verifyHttpAuthedCleanupCandidate,
  verifyCountersignature = defaultCountersignatureVerifier,
  verifyObservation = verifyTransientHttpAuthedJsonObservation,
  existingLease,
  wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
}) {
  if (action?.kind !== 'mutate') {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_KIND_REQUIRED',
      'declared mutation controller requires a mutate action',
    )
  }
  if (
    typeof now !== 'function'
    || typeof transport !== 'function'
    || typeof verifyCandidate !== 'function'
    || typeof verifyCleanupCandidate !== 'function'
    || typeof verifyCountersignature !== 'function'
    || typeof verifyObservation !== 'function'
    || typeof wait !== 'function'
  ) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_DEPENDENCY_INVALID',
      'declared mutation execution dependencies are invalid',
    )
  }
  if (action.rollback_policy !== 'ALWAYS' || action.rollback?.idempotent_restore !== true) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_ROLLBACK_POLICY_REQUIRED',
      'declared reversible mutation execution requires an always-on idempotent restore',
    )
  }
  validateLedger(ledger, expectedCampaignGrantSha256, scope)
  const campaignLedgerSha256 = httpAuthedCampaignLedgerBindingSha256(ledger.directory)
  const browserSession = isHttpAuthedBrowserSessionCredential(scope.credential)
  if (browserSession && credentialValue !== undefined) {
    throw mutationError(
      'HTTP_AUTHED_BROWSER_CREDENTIAL_EXPORT_REFUSED',
      'Chrome active-tab mutation dispatch must not receive exported credential bytes',
    )
  }
  const credentialBytes = browserSession
    ? undefined
    : exactBytes(credentialValue, 'credential value', {
        maximum: MAX_CREDENTIAL_BYTES,
      })
  let mutationBody
  let rollbackBody
  try {
    if (!browserSession && sha256Hex(credentialBytes) !== scope.credential.binding_sha256) {
      throw mutationError(
        'HTTP_AUTHED_MUTATION_CREDENTIAL_BINDING_MISMATCH',
        'credential value does not match the sealed binding digest',
      )
    }
    mutationBody = boundBody(action.request_body, requestBodyBytes, 'mutation')
    rollbackBody = boundBody(action.rollback.request_body, rollbackBodyBytes, 'rollback')

  const verifyCandidateNow = async (candidate, { cleanup = false } = {}) => {
    try {
      const verifier = cleanup ? verifyCleanupCandidate : verifyCandidate
      return await verifier({
        scope,
        action: candidate,
        documentBytes,
        expectedCampaignGrantSha256,
        now: now(),
      })
    } catch (cause) {
      throw mutationError(
        'HTTP_AUTHED_MUTATION_AUTHORIZATION_REJECTED',
        'declared mutation campaign authorization verification failed',
        { cause },
      )
    }
  }
  const verifyCountersignatureNow = async (candidate) => {
    try {
      return await verifyCountersignature({
        scope,
        action: candidate,
        countersignature,
        expectedCampaignGrantSha256,
        campaignLedgerSha256,
        now: now(),
      })
    } catch (cause) {
      throw mutationError(
        'HTTP_AUTHED_MUTATION_COUNTERSIGNATURE_REJECTED',
        'declared mutation countersignature verification failed',
        { cause },
      )
    }
  }

  await verifyCandidateNow(action)
  await verifyCountersignatureNow(action)
  if (
    typeof countersignature?.nonce !== 'string'
    || countersignature.nonce.length < 16
    || countersignature.nonce.length > 128
    || !/^[A-Za-z0-9._~-]+$/.test(countersignature.nonce)
  ) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_APPROVAL_NONCE_INVALID',
      'declared mutation countersignature must carry a valid one-use nonce',
    )
  }
  let lease
  if (existingLease === undefined) {
    await ledger.enqueueCandidate({
      candidateDraft: action,
      provenance: 'OPERATOR_SUPPLIED',
    })
    lease = await ledger.leaseAction({ candidateDraft: action, operatorId })
  } else {
    const state = ledger.actionState(existingLease.actionId)
    if (
      !state
      || state.terminal
      || state.state !== 'LEASED'
      || state.lease_id !== existingLease.leaseId
      || existingLease.allocatedAction?.kind !== 'mutate'
    ) {
      throw mutationError(
        'HTTP_AUTHED_MUTATION_LEASE_INVALID',
        'campaign-supplied mutation lease is invalid or stale',
      )
    }
    lease = existingLease
  }
  const allocatedAction = lease.allocatedAction
  Object.defineProperty(allocatedAction, '__credential_preflight', {
    value: structuredClone(scope.liveness.credential_preflight),
    enumerable: false,
    configurable: false,
    writable: false,
  })
  const verification = { before: false, after: false, rollback: false }
  const responses = {}
  let dispatchAttempts = 0

  const terminal = async (outcome, reasonCode) => {
    await ledger.terminalizeAction({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      outcome,
      reasonCode,
    })
    const result = publicResult({
      lease,
      action: allocatedAction,
      outcome,
      verification,
      responses,
    })
    credentialBytes?.fill(0)
    mutationBody?.fill(0)
    rollbackBody?.fill(0)
    return result
  }

  const dispatch = async (phase) => {
    const request = phaseRequest(allocatedAction, phase, mutationBody, rollbackBody)
    if (dispatchAttempts > 0 && scope.limits.min_interval_ms > 0) {
      await wait(scope.limits.min_interval_ms)
    }
    dispatchAttempts += 1
    let preDispatched = false
    const beforeSend = async () => {
      if (preDispatched) {
        throw mutationError(
          'HTTP_AUTHED_MUTATION_PRE_DISPATCH_REPLAY',
          'mutation transport invoked its pre-dispatch permit more than once',
        )
      }
      await verifyCandidateNow(allocatedAction, {
        cleanup: ['AFTER_READ', 'ROLLBACK', 'ROLLBACK_VERIFY'].includes(phase),
      })
      if (phase === 'MUTATION') {
        assertCleanupWindowAvailable(scope, now())
        await verifyCountersignatureNow(allocatedAction)
        await ledger.consumeApproval({
          actionId: lease.actionId,
          leaseId: lease.leaseId,
          nonce: countersignature.nonce,
          countersignatureBindingSha256: sha256Hex(Buffer.from(
            canonicalJson(countersignature),
            'utf8',
          )),
        })
      }
      await ledger.markPreDispatch({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        phase,
        requestBindingSha256: requestBinding({
          actionId: lease.actionId,
          phase,
          method: request.method,
          url: request.url,
          body: request.body,
        }),
      })
      preDispatched = true
    }

    try {
      const rawResponse = await transport({
        phase,
        method: request.method,
        url: request.url,
        body: request.body === null ? null : Buffer.from(request.body),
        credentialValue: credentialBytes === undefined ? undefined : Buffer.from(credentialBytes),
        timeoutMs: scope.limits.request_timeout_ms,
        maxResponseBytes: scope.limits.max_response_bytes,
        tls: structuredClone(scope.target.tls),
        beforeSend,
      })
      if (!preDispatched) {
        return { ok: false, mayHaveBeenSent: false, response: null, metadata: null }
      }
      const metadata = responseMetadata(rawResponse)
      await ledger.markOutcome({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        phase,
        outcome: 'SETTLED',
        responseMetadata: {
          status: metadata.status,
          bytes: metadata.bytes,
          headerNames: metadata.header_names,
          requestMayHaveBeenSent: true,
        },
      })
      responses[phase] = metadata
      if (
        !['BEFORE_READ', 'AFTER_READ', 'ROLLBACK_VERIFY'].includes(phase)
        && (Buffer.isBuffer(rawResponse.body) || rawResponse.body instanceof Uint8Array)
      ) {
        rawResponse.body.fill(0)
      }
      return {
        ok: true,
        acceptedStatus: expectedStatusesForPhase(allocatedAction, phase)
          .includes(metadata.status),
        mayHaveBeenSent: true,
        response: rawResponse,
        metadata,
      }
    } catch (cause) {
      const mayHaveBeenSent = preDispatched || cause?.request_may_have_been_sent === true
      if (preDispatched) {
        await ledger.markOutcome({
          actionId: lease.actionId,
          leaseId: lease.leaseId,
          phase,
          outcome: 'FAILED',
          responseMetadata: {
            status: null,
            bytes: 0,
            headerNames: [],
            requestMayHaveBeenSent: mayHaveBeenSent,
          },
        })
      }
      return { ok: false, mayHaveBeenSent, response: null, metadata: null }
    }
  }

  const observe = async (phase, dispatched, expectedDigest, baselineContextToken) => {
    let decision
    try {
      decision = observationResult(await verifyObservation({
        phase,
        response: dispatched.response,
        observation: observationForPhase(allocatedAction, phase),
        expectedDigest,
        baselineContextToken,
      }))
    } catch {
      return { completed: false, matched: false, contextToken: undefined }
    } finally {
      if (Buffer.isBuffer(dispatched.response?.body)) dispatched.response.body.fill(0)
      else if (dispatched.response?.body instanceof Uint8Array) {
        dispatched.response.body.fill(0)
      }
    }
    await ledger.recordVerification({
      actionId: lease.actionId,
      leaseId: lease.leaseId,
      phase,
      valueMatch: decision.valueMatch,
      contextMatch: decision.contextMatch,
    })
    return {
      completed: true,
      matched: decision.valueMatch && decision.contextMatch,
      contextToken: decision.contextToken,
    }
  }

  const credentialPreflight = await dispatch('CREDENTIAL_PREFLIGHT')
  if (!credentialPreflight.ok || !credentialPreflight.acceptedStatus) {
    return terminal('FAILED_BEFORE_MUTATION', 'CREDENTIAL_PREFLIGHT_FAILED')
  }

  const before = await dispatch('BEFORE_READ')
  if (!before.ok || !before.acceptedStatus) {
    return terminal('FAILED_BEFORE_MUTATION', 'BEFORE_READ_FAILED')
  }
  const beforeDecision = await observe(
    'BEFORE_READ',
    before,
    allocatedAction.expected_mutation.before_digest,
    undefined,
  )
  verification.before = beforeDecision.matched
  if (!verification.before) {
    return terminal('FAILED_BEFORE_MUTATION', 'BEFORE_VERIFICATION_MISMATCH')
  }

  const mutation = await dispatch('MUTATION')
  if (!mutation.ok) {
    if (!mutation.mayHaveBeenSent) {
      return terminal('FAILED_BEFORE_SEND', 'MUTATION_FAILED_BEFORE_SEND')
    }
  }
  const mutationDeliveryAmbiguous = !mutation.ok

  const after = await dispatch('AFTER_READ')
  if (after.ok && after.acceptedStatus) {
    const afterDecision = await observe(
      'AFTER_READ',
      after,
      allocatedAction.expected_mutation.after_digest,
      beforeDecision.contextToken,
    )
    verification.after = afterDecision.matched
  }
  // Once a mutation may have crossed the send boundary, the sealed idempotent
  // restore is attempted exactly once even when the response or after-read is
  // ambiguous. The mutation itself is never replayed.
  const rollback = await dispatch('ROLLBACK')
  const rollbackDeliveryFailed = !rollback.ok

  const rollbackVerify = await dispatch('ROLLBACK_VERIFY')
  if (!rollbackVerify.ok || !rollbackVerify.acceptedStatus) {
    return terminal('MANUAL_INTERVENTION_REQUIRED', 'ROLLBACK_VERIFY_FAILED')
  }
  const rollbackDecision = await observe(
    'ROLLBACK_VERIFY',
    rollbackVerify,
    allocatedAction.rollback.expected_after_digest,
    beforeDecision.contextToken,
  )
  verification.rollback = rollbackDecision.matched
  if (!verification.rollback) {
    return terminal('MANUAL_INTERVENTION_REQUIRED', 'ROLLBACK_VERIFICATION_MISMATCH')
  }

  const completeSuccess = mutation.acceptedStatus
    && verification.after
    && rollback.acceptedStatus
    && !mutationDeliveryAmbiguous
    && !rollbackDeliveryFailed
    return terminal(
      completeSuccess
        ? 'MUTATION_VERIFIED_ROLLBACK_VERIFIED'
        : 'ROLLBACK_VERIFIED_AFTER_FAILURE',
      completeSuccess ? null : 'MUTATION_OR_VERIFICATION_MISMATCH',
    )
  } finally {
    credentialBytes?.fill(0)
    mutationBody?.fill(0)
    rollbackBody?.fill(0)
  }
}

/**
 * Resume only the cleanup half of an interrupted mutation. The durable ledger
 * determines whether the rollback request was already consumed; this function
 * never issues MUTATION and never repeats a pre-dispatched ROLLBACK.
 */
export async function recoverDeclaredHttpAuthedMutation({
  ledger,
  scope,
  action,
  existingLease,
  documentBytes,
  expectedCampaignGrantSha256,
  credentialValue,
  rollbackBodyBytes,
  now = () => new Date(),
  transport,
  verifyCandidate = verifyHttpAuthedCleanupCandidate,
  verifyObservation = verifyTransientHttpAuthedJsonObservation,
  wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
}) {
  if (
    action?.kind !== 'mutate'
    || action.rollback_policy !== 'ALWAYS'
    || action.rollback?.idempotent_restore !== true
  ) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_RECOVERY_ACTION_INVALID',
      'cleanup recovery requires a declared always-on idempotent restore action',
    )
  }
  if (
    typeof now !== 'function'
    || typeof transport !== 'function'
    || typeof verifyCandidate !== 'function'
    || typeof verifyObservation !== 'function'
    || typeof wait !== 'function'
  ) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_DEPENDENCY_INVALID',
      'mutation cleanup recovery dependencies are invalid',
    )
  }
  validateLedger(ledger, expectedCampaignGrantSha256, scope)
  const identity = httpAuthedCandidateIdentity({
    campaignGrantSha256: expectedCampaignGrantSha256,
    candidateDraft: action,
  })
  const state = ledger.actionState(existingLease?.actionId)
  if (
    !state
    || state.terminal
    || state.action_kind !== 'mutate'
    || state.approval_consumed !== true
    || state.action_id !== identity.actionId
    || state.lease_id !== existingLease?.leaseId
    || existingLease?.actionId !== identity.actionId
    || ledger.snapshot().stopped !== true
  ) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_RECOVERY_LEASE_INVALID',
      'mutation cleanup recovery requires the exact interrupted action lease',
    )
  }
  const rollbackRequiredStates = new Set([
    'MUTATION_SETTLED',
    'MUTATION_FAILED',
    'AFTER_READ_SETTLED',
    'AFTER_READ_FAILED',
    'AFTER_READ_VERIFIED',
  ])
  const verifyOnlyStates = new Set(['ROLLBACK_SETTLED', 'ROLLBACK_FAILED'])
  if (!rollbackRequiredStates.has(state.state) && !verifyOnlyStates.has(state.state)) {
    throw mutationError(
      'HTTP_AUTHED_MUTATION_RECOVERY_STATE_INVALID',
      'interrupted mutation is not at a cleanup-recoverable ledger state',
    )
  }

  const assertCurrentRecoveryState = (phase) => {
    const currentState = ledger.actionState(existingLease.actionId)
    const allowed = phase === 'ROLLBACK' ? rollbackRequiredStates : verifyOnlyStates
    if (
      !currentState
      || currentState.terminal
      || currentState.action_id !== identity.actionId
      || currentState.lease_id !== existingLease.leaseId
      || currentState.action_kind !== 'mutate'
      || currentState.approval_consumed !== true
      || ledger.snapshot().stopped !== true
      || !allowed.has(currentState.state)
    ) {
      throw mutationError(
        'HTTP_AUTHED_MUTATION_RECOVERY_STATE_INVALID',
        `interrupted mutation cannot dispatch cleanup phase ${phase} from its current ledger state`,
      )
    }
  }

  const verifyCandidateNow = async (phase) => {
    try {
      const verified = await verifyCandidate({
        scope,
        action,
        documentBytes,
        expectedCampaignGrantSha256,
        now: now(),
      })
      if (phase !== undefined) assertCurrentRecoveryState(phase)
      return verified
    } catch (cause) {
      throw mutationError(
        'HTTP_AUTHED_MUTATION_AUTHORIZATION_REJECTED',
        'mutation cleanup authorization verification failed',
        { cause },
      )
    }
  }
  await verifyCandidateNow()

  const browserSession = isHttpAuthedBrowserSessionCredential(scope.credential)
  if (browserSession && credentialValue !== undefined) {
    throw mutationError(
      'HTTP_AUTHED_BROWSER_CREDENTIAL_EXPORT_REFUSED',
      'Chrome active-tab mutation recovery must not receive exported credential bytes',
    )
  }
  const credentialBytes = browserSession
    ? undefined
    : exactBytes(credentialValue, 'credential value', {
        maximum: MAX_CREDENTIAL_BYTES,
      })
  const rollbackBody = boundBody(action.rollback.request_body, rollbackBodyBytes, 'rollback')
  const responses = {}
  let dispatchAttempts = 0
  const terminal = async (outcome, reasonCode) => {
    await ledger.terminalizeAction({
      actionId: existingLease.actionId,
      leaseId: existingLease.leaseId,
      outcome,
      reasonCode,
    })
    return {
      kind: 'red-team-audit/http-authed-mutation-recovery-result',
      schema_version: '1.0.0',
      outcome,
      action: {
        action_id: existingLease.actionId,
        sequence: state.action_sequence,
        test_category: action.test_category,
      },
      verification: {
        rollback_value: outcome === 'ROLLBACK_RECOVERED_CONTEXT_UNVERIFIED',
        sibling_context: false,
      },
      responses,
    }
  }
  const dispatch = async (phase) => {
    const request = phaseRequest(action, phase, null, rollbackBody)
    if (dispatchAttempts > 0 && scope.limits.min_interval_ms > 0) {
      await wait(scope.limits.min_interval_ms)
    }
    dispatchAttempts += 1
    let preDispatched = false
    const beforeSend = async () => {
      if (preDispatched) {
        throw mutationError(
          'HTTP_AUTHED_MUTATION_PRE_DISPATCH_REPLAY',
          'mutation cleanup transport invoked pre-dispatch more than once',
        )
      }
      await verifyCandidateNow(phase)
      await ledger.markPreDispatch({
        actionId: existingLease.actionId,
        leaseId: existingLease.leaseId,
        phase,
        requestBindingSha256: requestBinding({
          actionId: existingLease.actionId,
          phase,
          method: request.method,
          url: request.url,
          body: request.body,
        }),
      })
      preDispatched = true
    }
    try {
      const rawResponse = await transport({
        phase,
        method: request.method,
        url: request.url,
        body: request.body === null ? null : Buffer.from(request.body),
        credentialValue: credentialBytes === undefined ? undefined : Buffer.from(credentialBytes),
        timeoutMs: scope.limits.request_timeout_ms,
        maxResponseBytes: scope.limits.max_response_bytes,
        tls: structuredClone(scope.target.tls),
        beforeSend,
      })
      if (!preDispatched) return { ok: false, acceptedStatus: false, response: null }
      const metadata = responseMetadata(rawResponse)
      await ledger.markOutcome({
        actionId: existingLease.actionId,
        leaseId: existingLease.leaseId,
        phase,
        outcome: 'SETTLED',
        responseMetadata: {
          status: metadata.status,
          bytes: metadata.bytes,
          headerNames: metadata.header_names,
          requestMayHaveBeenSent: true,
        },
      })
      responses[phase] = metadata
      if (phase === 'ROLLBACK' && (Buffer.isBuffer(rawResponse.body)
        || rawResponse.body instanceof Uint8Array)) rawResponse.body.fill(0)
      return {
        ok: true,
        acceptedStatus: expectedStatusesForPhase(action, phase).includes(metadata.status),
        response: rawResponse,
      }
    } catch (cause) {
      if (preDispatched) {
        await ledger.markOutcome({
          actionId: existingLease.actionId,
          leaseId: existingLease.leaseId,
          phase,
          outcome: 'FAILED',
          responseMetadata: {
            status: null,
            bytes: 0,
            headerNames: [],
            requestMayHaveBeenSent: true,
          },
        })
      }
      return { ok: false, acceptedStatus: false, response: null }
    }
  }

  try {
    if (rollbackRequiredStates.has(state.state)) await dispatch('ROLLBACK')
    const verificationRead = await dispatch('ROLLBACK_VERIFY')
    if (!verificationRead.ok || !verificationRead.acceptedStatus) {
      return terminal('MANUAL_INTERVENTION_REQUIRED', 'RECOVERY_ROLLBACK_VERIFY_FAILED')
    }
    let decision
    try {
      decision = observationResult(await verifyObservation({
        phase: 'ROLLBACK_VERIFY',
        response: verificationRead.response,
        observation: action.rollback.verification_read.observation,
        expectedDigest: action.rollback.expected_after_digest,
        baselineContextToken: undefined,
      }))
    } catch {
      return terminal('MANUAL_INTERVENTION_REQUIRED', 'RECOVERY_OBSERVATION_FAILED')
    } finally {
      if (Buffer.isBuffer(verificationRead.response?.body)
        || verificationRead.response?.body instanceof Uint8Array) {
        verificationRead.response.body.fill(0)
      }
    }
    await ledger.recordVerification({
      actionId: existingLease.actionId,
      leaseId: existingLease.leaseId,
      phase: 'ROLLBACK_VERIFY',
      valueMatch: decision.valueMatch,
      contextMatch: false,
    })
    return decision.valueMatch
      ? terminal(
          'ROLLBACK_RECOVERED_CONTEXT_UNVERIFIED',
          'RECOVERY_FIELD_RESTORED_CONTEXT_UNAVAILABLE',
        )
      : terminal('MANUAL_INTERVENTION_REQUIRED', 'RECOVERY_ROLLBACK_VALUE_MISMATCH')
  } finally {
    credentialBytes?.fill(0)
    rollbackBody?.fill(0)
  }
}
