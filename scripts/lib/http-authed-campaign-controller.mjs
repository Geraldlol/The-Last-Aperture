import { discoverHttpAuthedCandidates } from './http-authed-discovery.mjs'
import {
  canonicalJson,
  httpAuthedAuthorizationEvidence,
  sha256Hex,
  verifyHttpAuthedAuthorization,
  verifyHttpAuthedCandidate,
  verifyHttpAuthedCleanupCandidate,
} from './http-authed-contracts.mjs'
import { httpAuthedCandidateIdentity } from './http-authed-campaign-ledger.mjs'
import { sanitizeHttpAuthedJsonShape } from './http-authed-json-shape.mjs'
import {
  HTTP_AUTHED_JSON_SHAPE_FAILURE_STAGE,
  assertHttpAuthedResponseByteBucket,
  sanitizeHttpAuthedHeaderNames,
} from './http-authed-response-metadata.mjs'

const CLEANUP_RECOVERY_STATES = new Set([
  'MUTATION_SETTLED',
  'MUTATION_FAILED',
  'AFTER_READ_SETTLED',
  'AFTER_READ_FAILED',
  'AFTER_READ_VERIFIED',
  'AFTER_READ_VERIFICATION_FAILED',
  'ROLLBACK_SETTLED',
  'ROLLBACK_FAILED',
])
const MUTATION_RESPONSE_STOP_REASONS = new Set([
  'CREDENTIAL_INVALID',
  'LIMIT_REACHED',
  'UNEXPECTED_REDIRECT',
  'TARGET_HEALTH_DEGRADED',
])

export class HttpAuthedCampaignControllerError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'HttpAuthedCampaignControllerError'
    this.code = code
    this.request_may_have_been_sent = options.requestMayHaveBeenSent === true
  }
}

function campaignError(code, message, options) {
  return new HttpAuthedCampaignControllerError(code, message, options)
}

function exactFunction(value, label) {
  if (typeof value !== 'function') {
    throw campaignError('HTTP_AUTHED_CAMPAIGN_CALLBACK_REQUIRED', `${label} callback is required`)
  }
  return value
}

function requestBindingSha256(action) {
  return sha256Hex(Buffer.from(
    `red-team-audit/http-authed-request-binding/v1\0${canonicalJson(action)}`,
    'utf8',
  ))
}

function publicLedger(snapshot) {
  return {
    record_count: snapshot.record_count,
    head_sha256: snapshot.head_sha256,
    queued_actions: snapshot.queued_actions,
    terminal_actions: snapshot.terminal_actions,
    stopped: snapshot.stopped,
    stop_reason: snapshot.stop_reason,
  }
}

function responseMetadata(response, requestMayHaveBeenSent = true, observation) {
  if (
    response === null
    || typeof response !== 'object'
    || !Number.isSafeInteger(response.status)
    || response.status < 100
    || response.status > 599
    || !Array.isArray(response.header_names)
  ) {
    throw campaignError(
      'HTTP_AUTHED_CAMPAIGN_RESPONSE_INVALID',
      'campaign executor returned invalid response metadata',
      { requestMayHaveBeenSent },
    )
  }
  let headerNames
  try {
    headerNames = sanitizeHttpAuthedHeaderNames(response.header_names)
  } catch (cause) {
    throw campaignError(
      'HTTP_AUTHED_CAMPAIGN_RESPONSE_INVALID',
      'campaign executor returned invalid response header-name metadata',
      { cause, requestMayHaveBeenSent },
    )
  }
  const hasFailureStage = Object.hasOwn(response, 'failure_stage_code')
  const hasResponseByteBucket = Object.hasOwn(response, 'response_byte_bucket')
  if (hasFailureStage || hasResponseByteBucket) {
    let responseByteBucket
    try {
      responseByteBucket = assertHttpAuthedResponseByteBucket(response.response_byte_bucket)
    } catch (cause) {
      throw campaignError(
        'HTTP_AUTHED_CAMPAIGN_RESPONSE_INVALID',
        'campaign executor returned invalid observation-failure metadata',
        { cause, requestMayHaveBeenSent },
      )
    }
    if (
      !hasFailureStage
      || !hasResponseByteBucket
      || observation === undefined
      || response.failure_stage_code !== HTTP_AUTHED_JSON_SHAPE_FAILURE_STAGE
      || response.bytes !== undefined
      || response.json_shape !== undefined
    ) {
      throw campaignError(
        'HTTP_AUTHED_CAMPAIGN_RESPONSE_INVALID',
        'campaign executor returned invalid observation-failure metadata',
        { requestMayHaveBeenSent },
      )
    }
    return {
      status: response.status,
      headerNames,
      responseByteBucket,
      failureStageCode: HTTP_AUTHED_JSON_SHAPE_FAILURE_STAGE,
      requestMayHaveBeenSent,
    }
  }
  if (!Number.isSafeInteger(response.bytes) || response.bytes < 0) {
    throw campaignError(
      'HTTP_AUTHED_CAMPAIGN_RESPONSE_INVALID',
      'campaign executor returned invalid response metadata',
      { requestMayHaveBeenSent },
    )
  }
  let jsonShape
  try {
    if (response.json_shape !== undefined && observation === undefined) {
      throw new TypeError('unsealed JSON shape metadata')
    }
    jsonShape = response.json_shape === undefined
      ? undefined
      : sanitizeHttpAuthedJsonShape(response.json_shape, {
          safeKeyNames: observation.safe_key_names,
          mode: observation.mode,
        })
  } catch (cause) {
    throw campaignError(
      'HTTP_AUTHED_CAMPAIGN_RESPONSE_INVALID',
      'campaign executor returned invalid JSON shape metadata',
      { cause, requestMayHaveBeenSent },
    )
  }
  return {
    status: response.status,
    bytes: response.bytes,
    headerNames,
    requestMayHaveBeenSent,
    ...(jsonShape === undefined ? {} : { jsonShape }),
  }
}

function responseStopReason(status) {
  if (status === 401 || status === 403) return 'CREDENTIAL_INVALID'
  if (status === 429) return 'LIMIT_REACHED'
  if (status >= 300 && status <= 399) return 'UNEXPECTED_REDIRECT'
  if (status >= 500) return 'TARGET_HEALTH_DEGRADED'
  return null
}

function durableMutationStopReason(state) {
  for (const phase of [
    'CREDENTIAL_PREFLIGHT',
    'BEFORE_READ',
    'MUTATION',
    'AFTER_READ',
    'ROLLBACK',
    'ROLLBACK_VERIFY',
  ]) {
    const reason = responseStopReason(state?.phase_outcomes?.[phase]?.status)
    if (reason !== null) return reason
  }
  return null
}

function expiredCleanupTarget({ scope, ledger, campaignGrantSha256 }) {
  if (
    typeof ledger?.actionState !== 'function'
    || typeof ledger?.snapshot !== 'function'
    || ledger.snapshot().stopped !== true
  ) return null
  const matches = []
  for (const action of scope.requests) {
    if (action.kind !== 'mutate') continue
    const identity = httpAuthedCandidateIdentity({
      campaignGrantSha256,
      candidateDraft: action,
    })
    const state = ledger.actionState(identity.actionId)
    if (
      state
      && !state.terminal
      && state.provenance === 'SEALED_PLAN'
      && state.action_kind === 'mutate'
      && state.authorization_consumed === true
      && typeof state.lease_id === 'string'
      && CLEANUP_RECOVERY_STATES.has(state.state)
    ) {
      matches.push({ action, state })
    }
  }
  return matches.length === 1 ? matches[0] : null
}

/**
 * Drain an operator-attested authenticated campaign sequentially. The ledger is the
 * authoritative exact-once history; candidate bytes live only in the sealed
 * scope or in this process for response-derived, synthetic-safe discoveries.
 */
export async function runHttpAuthedCampaign({
  scope,
  expectedCampaignGrantSha256,
  operatorId,
  authorizationConfirmed,
  ledger,
  executeProbe,
  executeMutation,
  executeMutationRecovery,
  reauthorize,
  now = () => new Date(),
  wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds)),
}) {
  if (authorizationConfirmed !== true) {
    throw campaignError(
      'HTTP_AUTHED_CURRENT_AUTHORIZATION_REQUIRED',
      'campaign execution requires current authorization confirmation',
    )
  }
  if (
    !ledger
    || typeof ledger.enqueueCandidate !== 'function'
    || typeof ledger.confirmCampaignSession !== 'function'
    || typeof ledger.snapshot !== 'function'
    || typeof ledger.actionState !== 'function'
    || typeof ledger.reconcileInterruptedDispatches !== 'function'
  ) {
    throw campaignError(
      'HTTP_AUTHED_CAMPAIGN_LEDGER_REQUIRED',
      'campaign execution requires an open durable campaign ledger',
    )
  }
  exactFunction(reauthorize, 'campaign reauthorization')
  exactFunction(executeProbe, 'campaign probe executor')
  exactFunction(wait, 'campaign interval wait')
  if (executeMutation !== undefined) exactFunction(executeMutation, 'campaign mutation executor')
  if (executeMutationRecovery !== undefined) {
    exactFunction(executeMutationRecovery, 'campaign mutation recovery executor')
  }
  if (typeof now !== 'function') {
    throw campaignError('HTTP_AUTHED_CAMPAIGN_CLOCK_INVALID', 'campaign clock must be a function')
  }

  let verified
  let entryCleanupTarget = null
  try {
    verified = verifyHttpAuthedAuthorization({
      scope,
      now: now(),
    })
  } catch (cause) {
    if (cause?.code !== 'HTTP_AUTHED_AUTHORIZATION_EXPIRED') throw cause
    const cleanupCandidate = scope.requests?.find((action) => action.kind === 'mutate')
    if (cleanupCandidate === undefined) throw cause
    const cleanupVerified = verifyHttpAuthedCleanupCandidate({
      scope,
      action: cleanupCandidate,
      expectedCampaignGrantSha256,
      now: now(),
    })
    entryCleanupTarget = expiredCleanupTarget({
      scope,
      ledger,
      campaignGrantSha256: cleanupVerified.campaignGrantSha256,
    })
    if (entryCleanupTarget === null) throw cause
    verified = cleanupVerified
  }
  if (verified.campaignGrantSha256 !== expectedCampaignGrantSha256) {
    throw campaignError(
      'HTTP_AUTHED_CAMPAIGN_GRANT_MISMATCH',
      'campaign scope does not match the controller-held campaign grant',
    )
  }
  if (operatorId !== scope.authorization.operator_id) {
    throw campaignError(
      'HTTP_AUTHED_OPERATOR_MISMATCH',
      'campaign operator does not match the sealed authorization',
    )
  }
  const initialLedger = ledger.snapshot()
  const authorizationEvidence = httpAuthedAuthorizationEvidence(scope)
  if (
    initialLedger.campaign_grant_sha256 !== expectedCampaignGrantSha256
    || initialLedger.authorization_binding_sha256 !== verified.authorizationBindingSha256
    || initialLedger.authorization_mode !== authorizationEvidence.authorizationMode
    || initialLedger.independently_verified !== authorizationEvidence.independentlyVerified
    || initialLedger.operator_id !== operatorId
  ) {
    throw campaignError(
      'HTTP_AUTHED_CAMPAIGN_LEDGER_BINDING_MISMATCH',
      'campaign ledger is bound to a different authorization grant',
    )
  }
  if (entryCleanupTarget === null) {
    await ledger.confirmCampaignSession({
      operatorId,
      authorizationMode: scope.authorization.mode,
    })
  } else {
    if (typeof ledger.confirmCleanupSession !== 'function') {
      throw campaignError(
        'HTTP_AUTHED_CAMPAIGN_CLEANUP_LEDGER_INVALID',
        'expired campaign cleanup requires a cleanup-only ledger confirmation API',
      )
    }
    await ledger.confirmCleanupSession({
      operatorId,
      authorizationMode: scope.authorization.mode,
    })
  }

  const counts = {
    completed: 0,
    discovered: 0,
    duplicates: 0,
    rejected: 0,
    failed: 0,
    uncertain: 0,
    already_terminal: 0,
  }
  const jsonShapes = []
  const observationFailures = []
  const queue = []
  const queuedIds = new Set()
  let executedActions = 0
  const observeOperatorStop = async () => {
    if (typeof ledger.observeStopRequest === 'function') {
      await ledger.observeStopRequest()
    }
    return ledger.snapshot().stopped === true
  }

  const enqueue = async (candidateDraft, provenance) => {
    const enqueued = await ledger.enqueueCandidate({ candidateDraft, provenance })
    const state = ledger.actionState(enqueued.actionId)
    if (!enqueued.created) counts.duplicates += 1
    if (state?.terminal) {
      counts.already_terminal += 1
      return enqueued
    }
    if (!queuedIds.has(enqueued.actionId)) {
      queuedIds.add(enqueued.actionId)
      queue.push({ candidateDraft, enqueued })
    }
    return enqueued
  }

  await observeOperatorStop()
  if (entryCleanupTarget === null) {
    if (!ledger.snapshot().stopped) {
      for (const action of scope.requests) await enqueue(action, 'SEALED_PLAN')
    }
  } else {
    const { action, state } = entryCleanupTarget
    queuedIds.add(state.action_id)
    queue.push({
      candidateDraft: structuredClone(action),
      enqueued: {
        created: false,
        actionId: state.action_id,
        candidateSha256: state.candidate_sha256,
        actionSequence: state.action_sequence,
        allocatedAction: {
          ...structuredClone(action),
          sequence: state.action_sequence,
        },
        headSha256: ledger.snapshot().head_sha256,
      },
    })
  }

  while (queue.length > 0) {
    const queued = queue.shift()
    queuedIds.delete(queued.enqueued.actionId)
    const currentState = ledger.actionState(queued.enqueued.actionId)
    if (currentState?.terminal) continue
    const cleanupRecovery = currentState?.action_kind === 'mutate'
      && currentState.state !== 'QUEUED'
    await observeOperatorStop()
    if (ledger.snapshot().stopped && !cleanupRecovery) break
    if (cleanupRecovery) {
      const recoveryLease = {
        actionId: currentState.action_id,
        candidateSha256: currentState.candidate_sha256,
        actionSequence: currentState.action_sequence,
        allocatedAction: queued.enqueued.allocatedAction,
        leaseId: currentState.lease_id,
        headSha256: ledger.snapshot().head_sha256,
      }
      if (executeMutationRecovery === undefined) {
        await ledger.terminalizeAction({
          actionId: recoveryLease.actionId,
          leaseId: recoveryLease.leaseId,
          outcome: 'MANUAL_INTERVENTION_REQUIRED',
          reasonCode: 'MUTATION_RECOVERY_EXECUTOR_UNAVAILABLE',
        })
        counts.uncertain += 1
        break
      }
      try {
        verifyHttpAuthedCleanupCandidate({
          scope,
          action: recoveryLease.allocatedAction,
          expectedCampaignGrantSha256,
          now: now(),
        })
        const recovery = await executeMutationRecovery({
          action: recoveryLease.allocatedAction,
          lease: recoveryLease,
          ledger,
          reauthorize,
        })
        if (recovery?.outcome === 'ROLLBACK_RECOVERED_CONTEXT_UNVERIFIED') {
          counts.uncertain += 1
        } else if (recovery?.outcome === 'MUTATION_VERIFIED_ROLLBACK_VERIFIED') {
          counts.completed += 1
        } else {
          counts.uncertain += 1
        }
      } catch {
        const recoveryState = ledger.actionState(recoveryLease.actionId)
        if (!recoveryState?.terminal) {
          await ledger.terminalizeAction({
            actionId: recoveryLease.actionId,
            leaseId: recoveryLease.leaseId,
            outcome: 'MANUAL_INTERVENTION_REQUIRED',
            reasonCode: 'MUTATION_RECOVERY_FAILED',
          })
        }
        counts.uncertain += 1
      }
      break
    }
    if (executedActions > 0 && scope.limits.min_interval_ms > 0) {
      await wait(scope.limits.min_interval_ms)
      if (await observeOperatorStop()) break
    }
    executedActions += 1
    const lease = await ledger.leaseAction({
      candidateDraft: queued.candidateDraft,
      operatorId,
    })
    const action = lease.allocatedAction
    verifyHttpAuthedCandidate({
      scope,
      action,
      expectedCampaignGrantSha256,
      now: now(),
    })
    if (await observeOperatorStop()) {
      await ledger.terminalizeAction({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        outcome: action.kind === 'mutate' ? 'FAILED_BEFORE_MUTATION' : 'FAILED_BEFORE_SEND',
        reasonCode: 'OPERATOR_REQUESTED',
      })
      counts.failed += 1
      break
    }

    if (action.kind === 'mutate') {
      if (executeMutation === undefined) {
        await ledger.terminalizeAction({
          actionId: lease.actionId,
          leaseId: lease.leaseId,
          outcome: 'FAILED_BEFORE_MUTATION',
          reasonCode: 'MUTATION_EXECUTOR_UNAVAILABLE',
        })
        counts.failed += 1
        continue
      }
      let stopReason = null
      let haltAfterMutation = false
      try {
        const outcome = await executeMutation({ action, lease, ledger, reauthorize })
        const terminalOutcome = outcome?.terminal_outcome ?? outcome?.outcome
        const preciseStopReason = MUTATION_RESPONSE_STOP_REASONS.has(outcome?.stop_reason)
          ? outcome.stop_reason
          : null
        if (terminalOutcome === 'MUTATION_VERIFIED_ROLLBACK_VERIFIED') {
          counts.completed += 1
        } else if ([
          'DELIVERY_UNCERTAIN',
          'MANUAL_INTERVENTION_REQUIRED',
        ].includes(terminalOutcome)) {
          counts.uncertain += 1
          stopReason = 'MUTATION_OUTCOME_UNCERTAIN'
        } else {
          counts.failed += 1
          stopReason = terminalOutcome === 'ROLLBACK_VERIFIED_AFTER_FAILURE'
            ? 'VERIFICATION_MISMATCH'
            : 'MUTATION_ACTION_FAILED'
        }
        if (preciseStopReason !== null) stopReason = preciseStopReason
      } catch (cause) {
        let state = ledger.actionState(lease.actionId)
        if (!state?.terminal) {
          const postWrite = state?.authorization_consumed === true && (
            state?.pending_phase !== null
            || state?.settled_phases?.some((phase) => [
              'MUTATION', 'AFTER_READ', 'ROLLBACK', 'ROLLBACK_VERIFY',
            ].includes(phase))
          )
          const deliveryUncertain = postWrite
            || cause?.request_may_have_been_sent === true
          if (postWrite) {
            // Never terminalize a possibly executed write merely because its
            // executor unwound. Reconcile any ambiguous append, durably stop
            // new work, and enter the cleanup-only path on the same lease.
            // The reconciliation state machine never reissues MUTATION.
            const preciseDurableStopReason = durableMutationStopReason(state)
            if (preciseDurableStopReason !== null && !ledger.snapshot().stopped) {
              await ledger.stopCampaign(preciseDurableStopReason)
            }
            await ledger.reconcileInterruptedDispatches()
            state = ledger.actionState(lease.actionId)
            if (!ledger.snapshot().stopped) {
              await ledger.stopCampaign('MUTATION_EXECUTOR_FAILED')
            }
            if (state?.terminal) {
              if (state.outcome === 'MUTATION_VERIFIED_ROLLBACK_VERIFIED') {
                counts.completed += 1
              } else if (state.outcome === 'ROLLBACK_VERIFIED_AFTER_FAILURE') {
                counts.failed += 1
              } else {
                counts.uncertain += 1
              }
            } else if (
              CLEANUP_RECOVERY_STATES.has(state?.state)
              && executeMutationRecovery !== undefined
            ) {
              try {
                verifyHttpAuthedCleanupCandidate({
                  scope,
                  action,
                  expectedCampaignGrantSha256,
                  now: now(),
                })
                const recovery = await executeMutationRecovery({
                  action,
                  lease,
                  ledger,
                  reauthorize,
                })
                if (recovery?.outcome === 'MUTATION_VERIFIED_ROLLBACK_VERIFIED') {
                  counts.completed += 1
                } else {
                  counts.uncertain += 1
                }
              } catch {
                const recoveryState = ledger.actionState(lease.actionId)
                if (!recoveryState?.terminal) {
                  await ledger.terminalizeAction({
                    actionId: lease.actionId,
                    leaseId: lease.leaseId,
                    outcome: 'MANUAL_INTERVENTION_REQUIRED',
                    reasonCode: 'MUTATION_RECOVERY_FAILED',
                  })
                }
                counts.uncertain += 1
              }
            } else {
              await ledger.terminalizeAction({
                actionId: lease.actionId,
                leaseId: lease.leaseId,
                outcome: 'MANUAL_INTERVENTION_REQUIRED',
                reasonCode: executeMutationRecovery === undefined
                  ? 'MUTATION_RECOVERY_EXECUTOR_UNAVAILABLE'
                  : 'MUTATION_RECOVERY_STATE_UNAVAILABLE',
              })
              counts.uncertain += 1
            }
            haltAfterMutation = true
          } else {
            await ledger.terminalizeAction({
              actionId: lease.actionId,
              leaseId: lease.leaseId,
              outcome: deliveryUncertain
                ? 'DELIVERY_UNCERTAIN'
                : state?.authorization_consumed
                  ? 'FAILED_BEFORE_SEND'
                  : 'FAILED_BEFORE_MUTATION',
              reasonCode: deliveryUncertain
                ? 'MUTATION_EXECUTOR_DELIVERY_UNCERTAIN'
                : 'MUTATION_EXECUTOR_REJECTED',
            })
            if (deliveryUncertain) counts.uncertain += 1
            else counts.failed += 1
          }
        }
        if (!haltAfterMutation) stopReason = 'MUTATION_EXECUTOR_FAILED'
      }
      if (haltAfterMutation) break
      if (stopReason !== null) {
        if (!ledger.snapshot().stopped) await ledger.stopCampaign(stopReason)
        break
      }
      continue
    }

    let preDispatchRecorded = false
    let preDispatchSettled = false
    const beforeSend = async () => {
      if (preDispatchRecorded) {
        throw campaignError(
          'HTTP_AUTHED_CAMPAIGN_PRE_DISPATCH_REPLAY',
          'campaign executor invoked pre-dispatch more than once',
        )
      }
      if (await observeOperatorStop()) {
        throw campaignError(
          'HTTP_AUTHED_CAMPAIGN_STOP_REQUESTED',
          'operator stop was requested before probe dispatch',
        )
      }
      await reauthorize({ action: structuredClone(action) })
      verifyHttpAuthedCandidate({
        scope,
        action,
        expectedCampaignGrantSha256,
        now: now(),
      })
      // Re-import the external stop after every asynchronous qualification
      // step. A stop committed while reauthorization was in flight must win
      // before this request receives a durable send permit.
      if (await observeOperatorStop()) {
        throw campaignError(
          'HTTP_AUTHED_CAMPAIGN_STOP_REQUESTED',
          'operator stop was requested while probe dispatch was being qualified',
        )
      }
      await ledger.markPreDispatch({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        phase: 'PROBE',
        requestBindingSha256: requestBindingSha256(action),
      })
      preDispatchRecorded = true
      // The pre-dispatch record and its immediate stop observation form the
      // controller's final permit boundary. If a stop landed with that record,
      // settle the qualified request as definitely unsent before returning to
      // the transport.
      if (await observeOperatorStop()) {
        try {
          await ledger.markOutcome({
            actionId: lease.actionId,
            leaseId: lease.leaseId,
            phase: 'PROBE',
            outcome: 'FAILED',
            responseMetadata: {
              status: null,
              bytes: 0,
              headerNames: [],
              requestMayHaveBeenSent: false,
            },
          })
        } finally {
          preDispatchSettled = ledger.actionState(lease.actionId)
            ?.phase_outcomes?.PROBE?.outcome === 'FAILED'
        }
        throw campaignError(
          'HTTP_AUTHED_CAMPAIGN_STOP_REQUESTED',
          'operator stop was committed with probe pre-dispatch; request was not sent',
        )
      }
    }

    try {
      const execution = await executeProbe({ action: structuredClone(action), beforeSend })
      if (!preDispatchRecorded) {
        throw campaignError(
          'HTTP_AUTHED_CAMPAIGN_PRE_DISPATCH_MISSING',
          'campaign executor returned without invoking durable pre-dispatch',
        )
      }
      const settledResponse = responseMetadata(
        execution?.response,
        true,
        scope.response_observation,
      )
      await ledger.markOutcome({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        phase: 'PROBE',
        outcome: 'SETTLED',
        responseMetadata: settledResponse,
      })
      const settledStopReason = responseStopReason(settledResponse.status)
      if (settledResponse.failureStageCode !== undefined) {
        observationFailures.push({
          action_sequence: action.sequence,
          method: action.method,
          status: settledResponse.status,
          header_names: [...settledResponse.headerNames],
          response_byte_bucket: settledResponse.responseByteBucket,
          failure_stage_code: settledResponse.failureStageCode,
        })
        await ledger.terminalizeAction({
          actionId: lease.actionId,
          leaseId: lease.leaseId,
          outcome: 'PROBE_OBSERVATION_FAILED',
          reasonCode: 'PROBE_JSON_SHAPE_OBSERVATION_FAILED',
        })
        counts.failed += 1
        if (settledStopReason !== null) {
          if (!ledger.snapshot().stopped) await ledger.stopCampaign(settledStopReason)
          break
        }
        continue
      }
      if (settledResponse.jsonShape !== undefined) {
        jsonShapes.push({
          action_sequence: action.sequence,
          method: action.method,
          json_shape: structuredClone(settledResponse.jsonShape),
        })
      }

      if (settledStopReason !== null) {
        await ledger.terminalizeAction({
          actionId: lease.actionId,
          leaseId: lease.leaseId,
          outcome: 'PROBE_COMPLETED',
        })
        counts.completed += 1
        if (!ledger.snapshot().stopped) await ledger.stopCampaign(settledStopReason)
        break
      }

      if (scope.discovery?.enabled === true) {
        const transientChunks = execution?.discoveryInput?.bodyChunks ?? []
        let discovered
        try {
          discovered = discoverHttpAuthedCandidates({
            policy: scope.discovery,
            sourceAction: action,
            headers: execution?.discoveryInput?.headers ?? [],
            bodyChunks: transientChunks,
          })
        } finally {
          for (const chunk of transientChunks) {
            if (Buffer.isBuffer(chunk) || chunk instanceof Uint8Array) chunk.fill(0)
          }
        }
        let createdCount = 0
        let duplicateCount = 0
        for (const candidateDraft of discovered.candidates) {
          const candidate = await enqueue(candidateDraft, 'DISCOVERED')
          if (candidate.created) {
            createdCount += 1
            counts.discovered += 1
          } else {
            duplicateCount += 1
          }
        }
        const rejectedCount = Object.values(discovered.summary.rejected_by_code)
          .reduce((sum, value) => sum + value, 0)
        counts.rejected += rejectedCount
        await ledger.recordDiscoverySummary({
          actionId: lease.actionId,
          leaseId: lease.leaseId,
          acceptedCount: createdCount,
          duplicateCount,
          rejectedCount,
        })
      }
      await ledger.terminalizeAction({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        outcome: 'PROBE_COMPLETED',
      })
      counts.completed += 1
    } catch (cause) {
      const requestMayHaveBeenSent = cause?.request_may_have_been_sent === true
      const durableState = ledger.actionState(lease.actionId)
      const durablePreDispatch = preDispatchRecorded
        || durableState?.pending_phase === 'PROBE'
        || durableState?.phase_outcomes?.PROBE !== undefined
      preDispatchSettled ||= durableState?.phase_outcomes?.PROBE !== undefined
      if (durablePreDispatch && !preDispatchSettled) {
        await ledger.markOutcome({
          actionId: lease.actionId,
          leaseId: lease.leaseId,
          phase: 'PROBE',
          outcome: 'FAILED',
          responseMetadata: {
            status: null,
            bytes: 0,
            headerNames: [],
            requestMayHaveBeenSent,
          },
        })
      }
      await ledger.terminalizeAction({
        actionId: lease.actionId,
        leaseId: lease.leaseId,
        outcome: requestMayHaveBeenSent ? 'DELIVERY_UNCERTAIN' : 'FAILED_BEFORE_SEND',
        reasonCode: requestMayHaveBeenSent
          ? 'PROBE_DELIVERY_UNCERTAIN'
          : 'PROBE_FAILED_BEFORE_SEND',
      })
      if (requestMayHaveBeenSent) {
        counts.uncertain += 1
        if (!ledger.snapshot().stopped) {
          await ledger.stopCampaign('PROBE_DELIVERY_UNCERTAIN')
        }
        break
      }
      counts.failed += 1
    }
  }

  // Close the final response/terminalization race: a stop requested while the
  // last request was in flight must still enter the ledger before the result is
  // projected, even though there is no next loop iteration to observe it.
  await observeOperatorStop()
  return {
    kind: 'red-team-audit/http-authed-campaign-result',
    schema_version: observationFailures.length > 0
      ? '1.3.0'
      : scope.response_observation === undefined
      ? '1.0.0'
      : scope.response_observation.mode === 'ASPNET_D_JSON_SHAPE_ONLY'
        ? '1.2.0'
        : '1.1.0',
    authorization_mode: scope.authorization.mode,
    independently_verified: scope.authorization.independently_verified,
    authorization_assurance: authorizationEvidence.authorizationAssurance,
    authorization_nonclaim: authorizationEvidence.authorizationNonclaim,
    authorization_binding_sha256: verified.authorizationBindingSha256,
    campaign_grant_sha256: verified.campaignGrantSha256,
    ...(entryCleanupTarget === null ? {} : { cleanup_only: true }),
    actions: counts,
    ...(scope.response_observation === undefined ? {} : { json_shapes: jsonShapes }),
    ...(observationFailures.length === 0
      ? {}
      : { observation_failures: observationFailures }),
    ledger: publicLedger(ledger.snapshot()),
  }
}
