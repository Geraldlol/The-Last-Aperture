import { constants as fsConstants } from 'node:fs'
import { lstat, open } from 'node:fs/promises'
import { isAbsolute, join } from 'node:path'

import {
  createHttpAuthedHttpsTransport,
  dispatchHttpAuthedProbe,
} from './http-authed-client.mjs'
import { createHttpAuthedBrowserBridgeServer } from './http-authed-browser-bridge.mjs'
import { runHttpAuthedCampaign } from './http-authed-campaign-controller.mjs'
import {
  httpAuthedCandidateIdentity,
  openHttpAuthedCampaignLedger,
} from './http-authed-campaign-ledger.mjs'
import {
  httpAuthedAuthorizationEvidence,
  sha256Hex,
  isHttpAuthedBrowserSessionCredential,
  verifyHttpAuthedAuthorization,
  verifyHttpAuthedCandidate,
  verifyHttpAuthedCleanupCandidate,
} from './http-authed-contracts.mjs'
import { resolveHttpAuthedCredential } from './http-authed-credential.mjs'
import {
  recoverDeclaredHttpAuthedMutation,
  runDeclaredHttpAuthedMutation,
} from './http-authed-mutation-controller.mjs'
import { PLATFORM_SERIES } from './version.mjs'

const OPEN_READ_ONLY_NO_FOLLOW = fsConstants.O_RDONLY
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)
const INPUT_LIMITS = Object.freeze({
  scope: 64 * 1024 * 1024,
  body: 16 * 1024 * 1024,
})
const MAX_PUBLIC_FIXED_CAMPAIGN_ACTIONS = 256
const STARTUP_STOP_POLL_MS = 20
const CLEANUP_ROLLBACK_STATES = new Set([
  'MUTATION_SETTLED',
  'MUTATION_FAILED',
  'AFTER_READ_SETTLED',
  'AFTER_READ_FAILED',
  'AFTER_READ_VERIFIED',
  'AFTER_READ_VERIFICATION_FAILED',
  'ROLLBACK_SETTLED',
  'ROLLBACK_FAILED',
])

export class HttpAuthedCampaignRuntimeError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'HttpAuthedCampaignRuntimeError'
    this.code = code
  }
}

function runtimeError(code, message, options) {
  return new HttpAuthedCampaignRuntimeError(code, message, options)
}

function waitForStartupPoll(signal) {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve()
      return
    }
    let timer
    const finish = () => {
      clearTimeout(timer)
      signal.removeEventListener('abort', finish)
      resolve()
    }
    timer = setTimeout(finish, STARTUP_STOP_POLL_MS)
    signal.addEventListener('abort', finish, { once: true })
  })
}

async function waitForStartupStop(ledger, signal) {
  while (!signal.aborted) {
    if (ledger.snapshot().stopped || await ledger.observeStopRequest()) return true
    await waitForStartupPoll(signal)
  }
  return false
}

async function raceStartupOperationWithStop({
  ledger,
  operation,
  disposeLateValue,
}) {
  if (ledger.snapshot().stopped || await ledger.observeStopRequest()) {
    return { stopped: true, value: undefined }
  }
  const polling = new AbortController()
  const operationPromise = Promise.resolve().then(() => operation(polling.signal))
  const completed = operationPromise.then(
    (value) => ({ kind: 'COMPLETED', value }),
    (error) => ({ kind: 'FAILED', error }),
  )
  const stopped = waitForStartupStop(ledger, polling.signal)
    .then((value) => ({ kind: 'STOPPED', value }))
  const winner = await Promise.race([completed, stopped])
  polling.abort()
  if (winner.kind === 'FAILED') throw winner.error
  if (winner.kind === 'COMPLETED') return { stopped: false, value: winner.value }
  if (winner.value !== true) {
    throw runtimeError(
      'HTTP_AUTHED_CAMPAIGN_STARTUP_MONITOR_FAILED',
      'campaign startup stop monitor ended without a stop request',
    )
  }
  // The underlying provider may not support cancellation. If it resolves
  // after the stop wins, destroy any returned secret/session immediately.
  if (typeof disposeLateValue === 'function') {
    operationPromise.then(
      async (value) => { await disposeLateValue(value) },
      () => {},
    ).catch(() => {})
  }
  return { stopped: true, value: undefined }
}

async function readStableBoundedFile(path, label, maximum, { minimum = 1 } = {}) {
  let info
  try {
    info = await lstat(path)
  } catch (cause) {
    throw runtimeError('HTTP_AUTHED_CAMPAIGN_INPUT_UNREADABLE', `${label} cannot be read`, { cause })
  }
  if (!info.isFile() || info.isSymbolicLink() || info.size < minimum || info.size > maximum) {
    throw runtimeError(
      'HTTP_AUTHED_CAMPAIGN_INPUT_UNSAFE',
      `${label} must be a regular non-symlink file within its byte limit`,
    )
  }
  let handle
  try {
    handle = await open(path, OPEN_READ_ONLY_NO_FOLLOW)
    const before = await handle.stat()
    const bytes = await handle.readFile()
    const after = await handle.stat()
    if (
      before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || before.ino !== after.ino
      || bytes.length !== after.size
    ) {
      throw runtimeError(
        'HTTP_AUTHED_CAMPAIGN_INPUT_CHANGED',
        `${label} changed while it was read`,
      )
    }
    return bytes
  } catch (cause) {
    if (cause instanceof HttpAuthedCampaignRuntimeError) throw cause
    throw runtimeError('HTTP_AUTHED_CAMPAIGN_INPUT_UNREADABLE', `${label} cannot be read`, { cause })
  } finally {
    await handle?.close()
  }
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'))
  } catch (cause) {
    throw runtimeError('HTTP_AUTHED_CAMPAIGN_JSON_INVALID', `${label} is not valid JSON`, { cause })
  }
}

function requireMaterialsDirectory(materialsDirectory) {
  if (!isAbsolute(materialsDirectory ?? '')) {
    throw runtimeError(
      'HTTP_AUTHED_CAMPAIGN_MATERIALS_REQUIRED',
      'synthetic bodies require an absolute materials directory',
    )
  }
  return materialsDirectory
}

async function resolveBody(materialsDirectory, metadata, label) {
  if (metadata === undefined) return undefined
  const directory = requireMaterialsDirectory(materialsDirectory)
  const name = `body-${sha256Hex(Buffer.from(metadata.body_id, 'utf8'))}.bin`
  return readStableBoundedFile(
    join(directory, name),
    `${label} synthetic body`,
    INPUT_LIMITS.body,
    { minimum: 0 },
  )
}

function credentialHeaders(scope, bytes) {
  const value = bytes.toString('utf8')
  return scope.credential.kind === 'bearer'
    ? { authorization: `Bearer ${value}` }
    : { cookie: value }
}

function mutationContentType(action, phase) {
  if (phase === 'MUTATION') return action.request_body?.content_type
  if (phase === 'ROLLBACK') return action.rollback.request_body?.content_type
  return undefined
}

function createProtectedMutationTransport({ scope, action, protectedTransport }) {
  return async (request) => {
    const observedChunks = []
    let observedHeaders = []
    const contentType = mutationContentType(action, request.phase)
    let headers
    try {
      headers = {
        accept: 'application/json',
        ...(isHttpAuthedBrowserSessionCredential(scope.credential)
          ? {}
          : {
              'user-agent': `red-team-audit-http-authed/${PLATFORM_SERIES}`,
              ...credentialHeaders(scope, request.credentialValue),
            }),
        ...(request.body === null
          ? {}
          : {
              'content-type': contentType ?? 'application/octet-stream',
              'content-length': String(request.body.length),
            }),
      }
    } finally {
      request.credentialValue?.fill?.(0)
    }
    try {
      const response = await protectedTransport({
        url: request.url,
        method: request.method,
        headers,
        body: request.body,
        timeoutMs: request.timeoutMs,
        maxResponseBytes: request.maxResponseBytes,
        tls: request.tls,
        beforeSend: request.beforeSend,
        responseObserver: async ({ headers: responseHeaders, bodyChunks }) => {
          observedHeaders = responseHeaders
          for (const chunk of bodyChunks) observedChunks.push(Buffer.from(chunk))
        },
      })
      if (['BEFORE_READ', 'AFTER_READ', 'ROLLBACK_VERIFY'].includes(request.phase)) {
        const encodings = observedHeaders
          .filter(({ name }) => name === 'content-encoding')
          .map(({ value }) => value.trim().toLowerCase())
        const contentTypes = observedHeaders
          .filter(({ name }) => name === 'content-type')
          .map(({ value }) => value.split(';', 1)[0].trim().toLowerCase())
        if (
          encodings.some((value) => value !== 'identity')
          || contentTypes.length !== 1
          || !(
            contentTypes[0] === 'application/json'
            || /^application\/[a-z0-9!#$&^_.+-]+\+json$/.test(contentTypes[0])
          )
        ) {
          throw runtimeError(
            'HTTP_AUTHED_MUTATION_JSON_RESPONSE_REQUIRED',
            'mutation verification reads require one unencoded JSON response',
          )
        }
      }
      const body = Buffer.concat(observedChunks)
      return {
        status: response.status,
        responseBytes: response.responseBytes,
        responseHeaderNames: response.responseHeaderNames,
        body,
      }
    } finally {
      for (const chunk of observedChunks) chunk.fill(0)
    }
  }
}

function recoverableSealedMutation({ scope, ledger, campaignGrantSha256 }) {
  const matches = []
  for (const sealedAction of scope.requests) {
    if (sealedAction.kind !== 'mutate') continue
    const identity = httpAuthedCandidateIdentity({
      campaignGrantSha256,
      candidateDraft: sealedAction,
    })
    const state = ledger.actionState(identity.actionId)
    if (
      state
      && !state.terminal
      && state.provenance === 'SEALED_PLAN'
      && state.action_kind === 'mutate'
      && state.authorization_consumed === true
      && typeof state.lease_id === 'string'
      && state.lease_id.length > 0
      && CLEANUP_ROLLBACK_STATES.has(state.state)
    ) {
      matches.push({
        action: structuredClone(sealedAction),
        lease: {
          actionId: state.action_id,
          candidateSha256: state.candidate_sha256,
          actionSequence: state.action_sequence,
          allocatedAction: {
            ...structuredClone(sealedAction),
            sequence: state.action_sequence,
          },
          leaseId: state.lease_id,
          headSha256: ledger.snapshot().head_sha256,
        },
      })
    }
  }
  if (matches.length !== 1 || ledger.snapshot().stopped !== true) {
    throw runtimeError(
      'HTTP_AUTHED_CAMPAIGN_CLEANUP_STATE_INVALID',
      'expired campaign cleanup requires exactly one stopped, ledger-proven, nonterminal sealed mutation',
    )
  }
  return matches[0]
}

function cleanupCampaignResult({ scope, verified, recovery, ledger }) {
  const evidence = httpAuthedAuthorizationEvidence(scope)
  const completed = recovery?.outcome === 'MUTATION_VERIFIED_ROLLBACK_VERIFIED' ? 1 : 0
  const failed = recovery?.outcome === 'ROLLBACK_VERIFIED_AFTER_FAILURE' ? 1 : 0
  const uncertain = completed === 0 && failed === 0 ? 1 : 0
  const snapshot = ledger.snapshot()
  return {
    kind: 'red-team-audit/http-authed-campaign-result',
    schema_version: '1.0.0',
    authorization_mode: scope.authorization.mode,
    independently_verified: scope.authorization.independently_verified,
    authorization_assurance: evidence.authorizationAssurance,
    authorization_nonclaim: evidence.authorizationNonclaim,
    authorization_binding_sha256: verified.authorizationBindingSha256,
    campaign_grant_sha256: verified.campaignGrantSha256,
    cleanup_only: true,
    actions: {
      completed,
      discovered: 0,
      duplicates: 0,
      rejected: 0,
      failed,
      uncertain,
      already_terminal: 0,
    },
    ledger: {
      record_count: snapshot.record_count,
      head_sha256: snapshot.head_sha256,
      queued_actions: snapshot.queued_actions,
      terminal_actions: snapshot.terminal_actions,
      stopped: snapshot.stopped,
      stop_reason: snapshot.stop_reason,
    },
  }
}

async function runHttpAuthedCampaignRuntime({
  scopePath,
  expectedCampaignGrantSha256,
  ledgerDirectory,
  materialsDirectory,
  operatorId,
  trustedLedgerHead,
  env = process.env,
  transientCredential,
  credentialInput,
  credentialStdinReader,
  browserSessionRequested = false,
  browserTransportFactory = createHttpAuthedBrowserBridgeServer,
  onBrowserPairing,
  clock = () => new Date(),
  protectedTransport,
  mutationDependencies = {},
  fixedCampaignOnly = false,
}) {
  const commandName = 'campaign-attested'
  if (!isAbsolute(ledgerDirectory ?? '')) {
    throw runtimeError(
      'HTTP_AUTHED_CAMPAIGN_LEDGER_DIRECTORY_INVALID',
      `${commandName} requires an absolute external ledger directory`,
    )
  }
  if (
    (protectedTransport !== undefined && typeof protectedTransport !== 'function')
    || (browserTransportFactory !== undefined && typeof browserTransportFactory !== 'function')
    || (onBrowserPairing !== undefined && typeof onBrowserPairing !== 'function')
    || typeof clock !== 'function'
    || typeof fixedCampaignOnly !== 'boolean'
  ) {
    throw runtimeError(
      'HTTP_AUTHED_CAMPAIGN_DEPENDENCY_INVALID',
      'campaign runtime dependency is invalid',
    )
  }
  const scopeBytes = await readStableBoundedFile(
    scopePath,
    'http-authed scope',
    INPUT_LIMITS.scope,
  )
  const scope = parseJson(scopeBytes, 'http-authed scope')
  if (scope.authorization?.mode !== 'OPERATOR_ATTESTED_AUTHED') {
    throw runtimeError(
      'HTTP_AUTHED_AUTHORIZATION_MODE_MISMATCH',
      `${commandName} requires OPERATOR_ATTESTED_AUTHED scope`,
    )
  }
  let verified
  let cleanupOnly = false
  try {
    verified = verifyHttpAuthedAuthorization({
      scope,
      now: clock(),
    })
  } catch (cause) {
    if (cause?.code !== 'HTTP_AUTHED_AUTHORIZATION_EXPIRED') throw cause
    const sealedMutation = scope.requests?.find((action) => action.kind === 'mutate')
    if (sealedMutation === undefined) throw cause
    verified = verifyHttpAuthedCleanupCandidate({
      scope,
      action: sealedMutation,
      expectedCampaignGrantSha256,
      now: clock(),
    })
    cleanupOnly = true
  }
  if (verified.campaignGrantSha256 !== expectedCampaignGrantSha256) {
    throw runtimeError(
      'HTTP_AUTHED_CAMPAIGN_GRANT_MISMATCH',
      'scope does not match the controller-held campaign grant',
    )
  }
  if (typeof operatorId !== 'string' || operatorId !== scope.authorization.operator_id) {
    throw runtimeError(
      'HTTP_AUTHED_OPERATOR_MISMATCH',
      `${commandName} operator must match the sealed campaign operator`,
    )
  }
  if (fixedCampaignOnly && !cleanupOnly && scope.discovery?.enabled === true) {
    throw runtimeError(
      'HTTP_AUTHED_PUBLIC_DISCOVERY_REQUIRES_ADAPTIVE_CONTROLLER',
      'public campaign execution accepts only its fixed sealed request list',
    )
  }
  if (fixedCampaignOnly && scope.requests.length > MAX_PUBLIC_FIXED_CAMPAIGN_ACTIONS) {
    throw runtimeError(
      'HTTP_AUTHED_PUBLIC_CAMPAIGN_ACTION_LIMIT',
      `public fixed campaigns may contain at most ${MAX_PUBLIC_FIXED_CAMPAIGN_ACTIONS} sealed actions`,
    )
  }

  const browserSession = isHttpAuthedBrowserSessionCredential(scope.credential)
  if (browserSession !== (browserSessionRequested === true)) {
    throw runtimeError(
      'HTTP_AUTHED_BROWSER_MODE_MISMATCH',
      browserSession
        ? 'a Chrome active-tab scope requires explicit --credential-browser execution'
        : '--credential-browser cannot execute a scope with an exported credential binding',
    )
  }

  if (cleanupOnly) {
    let cleanupLedger
    let cleanupCredential
    let cleanupBrowserTransportSession
    let cleanupTransport = protectedTransport
    try {
      cleanupLedger = await openHttpAuthedCampaignLedger({
        directory: ledgerDirectory,
        campaignGrantSha256: verified.campaignGrantSha256,
        authorizationBindingSha256: verified.authorizationBindingSha256,
        authorizationMode: scope.authorization.mode,
        independentlyVerified: scope.authorization.independently_verified,
        operatorId,
        initialize: false,
        trustedHead: trustedLedgerHead,
        now: clock,
      })
      const recoveryTarget = recoverableSealedMutation({
        scope,
        ledger: cleanupLedger,
        campaignGrantSha256: verified.campaignGrantSha256,
      })
      if (typeof cleanupLedger.confirmCleanupSession !== 'function') {
        throw runtimeError(
          'HTTP_AUTHED_CAMPAIGN_CLEANUP_LEDGER_INVALID',
          'expired campaign cleanup requires a cleanup-only ledger confirmation API',
        )
      }
      await cleanupLedger.confirmCleanupSession({
        operatorId,
        authorizationMode: scope.authorization.mode,
      })
      if (browserSession) {
        if (cleanupTransport === undefined) {
          if (typeof browserTransportFactory !== 'function') {
            throw runtimeError(
              'HTTP_AUTHED_BROWSER_COMPANION_REQUIRED',
              'Chrome active-tab cleanup execution requires the browser companion bridge',
            )
          }
          cleanupBrowserTransportSession = await browserTransportFactory({
            extensionId: scope.credential.extension_id,
            targetOrigin: scope.credential.origin,
            campaignGrantSha256: verified.campaignGrantSha256,
            timeoutMs: scope.limits.request_timeout_ms,
          })
          if (
            typeof cleanupBrowserTransportSession?.transport !== 'function'
            || typeof cleanupBrowserTransportSession?.waitForAttach !== 'function'
            || typeof cleanupBrowserTransportSession?.close !== 'function'
          ) {
            throw runtimeError(
              'HTTP_AUTHED_BROWSER_COMPANION_INVALID',
              'the browser companion bridge did not provide a valid cleanup transport session',
            )
          }
          await onBrowserPairing?.(structuredClone(cleanupBrowserTransportSession.pairing))
          await cleanupBrowserTransportSession.waitForAttach()
          cleanupTransport = cleanupBrowserTransportSession.transport
        }
      } else {
        cleanupTransport ??= createHttpAuthedHttpsTransport()
        cleanupCredential = await resolveHttpAuthedCredential({
          credential: scope.credential,
          env,
          transientCredential,
          credentialInput,
          readStdin: credentialStdinReader,
        })
      }

      const reauthorizeCleanup = async ({ action }) => {
        const currentScopeBytes = await readStableBoundedFile(
          scopePath,
          'http-authed scope',
          INPUT_LIMITS.scope,
        )
        const currentScope = parseJson(currentScopeBytes, 'http-authed scope')
        if (currentScope.authorization?.mode !== 'OPERATOR_ATTESTED_AUTHED') {
          throw runtimeError(
            'HTTP_AUTHED_AUTHORIZATION_MODE_MISMATCH',
            'campaign authorization mode changed before cleanup dispatch',
          )
        }
        if (currentScope.authorization.operator_id !== operatorId) {
          throw runtimeError(
            'HTTP_AUTHED_OPERATOR_MISMATCH',
            'campaign operator changed before cleanup dispatch',
          )
        }
        return verifyHttpAuthedCleanupCandidate({
          scope: currentScope,
          action,
          expectedCampaignGrantSha256,
          now: clock(),
        })
      }

      let cleanupCredentialValue
      let rollbackBodyBytes
      try {
        rollbackBodyBytes = await resolveBody(
          materialsDirectory,
          recoveryTarget.action.rollback.request_body,
          'rollback',
        )
        cleanupCredentialValue = cleanupCredential === undefined
          ? undefined
          : Buffer.from(cleanupCredential)
        const recovery = await recoverDeclaredHttpAuthedMutation({
          ledger: cleanupLedger,
          scope,
          action: recoveryTarget.action,
          existingLease: recoveryTarget.lease,
          expectedCampaignGrantSha256,
          credentialValue: cleanupCredentialValue,
          rollbackBodyBytes,
          now: clock,
          transport: createProtectedMutationTransport({
            scope,
            action: recoveryTarget.action,
            protectedTransport: cleanupTransport,
          }),
          ...mutationDependencies,
          verifyCandidate: async ({ action }) => reauthorizeCleanup({ action }),
        })
        return cleanupCampaignResult({
          scope,
          verified,
          recovery,
          ledger: cleanupLedger,
        })
      } finally {
        cleanupCredentialValue?.fill(0)
        rollbackBodyBytes?.fill(0)
      }
    } finally {
      try {
        await cleanupLedger?.close()
      } finally {
        try {
          cleanupCredential?.fill(0)
        } finally {
          await cleanupBrowserTransportSession?.close()
        }
      }
    }
  }

  let masterCredential
  let browserTransportSession
  let activeTransport = protectedTransport
  let ledger
  try {
    // Create and bind the durable control surface before credential input or a
    // browser attach can block. The operator can therefore request a stop for
    // the entire startup window, not only after target dispatch is ready.
    ledger = await openHttpAuthedCampaignLedger({
      directory: ledgerDirectory,
      campaignGrantSha256: verified.campaignGrantSha256,
      authorizationBindingSha256: verified.authorizationBindingSha256,
      authorizationMode: scope.authorization.mode,
      independentlyVerified: scope.authorization.independently_verified,
      operatorId,
      initialize: true,
      trustedHead: trustedLedgerHead,
      now: clock,
    })
    let startupStopped = ledger.snapshot().stopped
    if (browserSession) {
      if (activeTransport === undefined && !startupStopped) {
        if (typeof browserTransportFactory !== 'function') {
          throw runtimeError(
            'HTTP_AUTHED_BROWSER_COMPANION_REQUIRED',
            'Chrome active-tab campaign execution requires the browser companion bridge',
          )
        }
        const created = await raceStartupOperationWithStop({
          ledger,
          operation: () => browserTransportFactory({
            extensionId: scope.credential.extension_id,
            targetOrigin: scope.credential.origin,
            campaignGrantSha256: verified.campaignGrantSha256,
            timeoutMs: scope.limits.request_timeout_ms,
          }),
          disposeLateValue: async (session) => { await session?.close?.() },
        })
        startupStopped = created.stopped
        if (!startupStopped) {
          browserTransportSession = created.value
          if (
            typeof browserTransportSession?.transport !== 'function'
            || typeof browserTransportSession?.waitForAttach !== 'function'
            || typeof browserTransportSession?.close !== 'function'
          ) {
            throw runtimeError(
              'HTTP_AUTHED_BROWSER_COMPANION_INVALID',
              'the browser companion bridge did not provide a valid transport session',
            )
          }
          const paired = await raceStartupOperationWithStop({
            ledger,
            operation: async () => {
              await onBrowserPairing?.(structuredClone(browserTransportSession.pairing))
            },
          })
          startupStopped = paired.stopped
        }
        if (!startupStopped) {
          const attached = await raceStartupOperationWithStop({
            ledger,
            operation: () => browserTransportSession.waitForAttach(),
          })
          startupStopped = attached.stopped
        }
        if (!startupStopped) activeTransport = browserTransportSession.transport
      }
    } else if (!startupStopped) {
      activeTransport ??= createHttpAuthedHttpsTransport()
      const credential = await raceStartupOperationWithStop({
        ledger,
        operation: (signal) => resolveHttpAuthedCredential({
          credential: scope.credential,
          env,
          transientCredential,
          credentialInput,
          readStdin: credentialStdinReader,
          signal,
        }),
        disposeLateValue: (value) => { value?.fill?.(0) },
      })
      startupStopped = credential.stopped
      if (!startupStopped) masterCredential = credential.value
    }
    const reauthorizeForPurpose = async ({ action, cleanup }) => {
      const currentScopeBytes = await readStableBoundedFile(
        scopePath,
        'http-authed scope',
        INPUT_LIMITS.scope,
      )
      const currentScope = parseJson(currentScopeBytes, 'http-authed scope')
      if (currentScope.authorization?.mode !== 'OPERATOR_ATTESTED_AUTHED') {
        throw runtimeError(
          'HTTP_AUTHED_AUTHORIZATION_MODE_MISMATCH',
          `campaign authorization mode changed before ${cleanup ? 'cleanup' : 'request'} dispatch`,
        )
      }
      if (currentScope.authorization.operator_id !== operatorId) {
        throw runtimeError(
          'HTTP_AUTHED_OPERATOR_MISMATCH',
          `campaign operator changed before ${cleanup ? 'cleanup' : 'request'} dispatch`,
        )
      }
      const verifier = cleanup
        ? verifyHttpAuthedCleanupCandidate
        : verifyHttpAuthedCandidate
      return verifier({
        scope: currentScope,
        action,
        expectedCampaignGrantSha256,
        now: clock(),
      })
    }
    const reauthorize = ({ action }) => reauthorizeForPurpose({ action, cleanup: false })
    const reauthorizeCleanup = ({ action }) => reauthorizeForPurpose({ action, cleanup: true })

    return await runHttpAuthedCampaign({
      scope,
      expectedCampaignGrantSha256,
      operatorId,
      ledger,
      now: clock,
      reauthorize,
      executeProbe: async ({ action, beforeSend }) => {
        let credentialValue
        let requestBodyBytes
        let discoveryInput = { headers: [], bodyChunks: [] }
        try {
          requestBodyBytes = await resolveBody(
            materialsDirectory,
            action.request_body,
            'probe',
          )
          credentialValue = masterCredential === undefined
            ? undefined
            : Buffer.from(masterCredential)
          const result = await dispatchHttpAuthedProbe({
            scope,
            action,
            expectedCampaignGrantSha256,
            credentialValue,
            requestBodyBytes,
            now: clock(),
            transport: activeTransport,
            beforeSend,
            responseObserver: scope.discovery?.enabled === true
              ? async (input) => { discoveryInput = input }
              : undefined,
          })
          return { response: result.response, discoveryInput }
        } finally {
          credentialValue?.fill(0)
          requestBodyBytes?.fill(0)
        }
      },
      executeMutation: async ({ action, lease }) => {
        let credentialValue
        let requestBodyBytes
        let rollbackBodyBytes
        try {
          requestBodyBytes = await resolveBody(
            materialsDirectory,
            action.request_body,
            'mutation',
          )
          rollbackBodyBytes = await resolveBody(
            materialsDirectory,
            action.rollback.request_body,
            'rollback',
          )
          credentialValue = masterCredential === undefined
            ? undefined
            : Buffer.from(masterCredential)
          return await runDeclaredHttpAuthedMutation({
            ledger,
            scope,
            action,
            existingLease: lease,
            expectedCampaignGrantSha256,
            operatorId,
            credentialValue,
            requestBodyBytes,
            rollbackBodyBytes,
            now: clock,
            transport: createProtectedMutationTransport({
              scope,
              action,
              protectedTransport: activeTransport,
            }),
            ...mutationDependencies,
            verifyCandidate: async ({ action: candidate }) => reauthorize({ action: candidate }),
            verifyCleanupCandidate: async ({ action: candidate }) => (
              reauthorizeCleanup({ action: candidate })
            ),
          })
        } finally {
          credentialValue?.fill(0)
          requestBodyBytes?.fill(0)
          rollbackBodyBytes?.fill(0)
        }
      },
      executeMutationRecovery: async ({ action, lease }) => {
        let credentialValue
        let rollbackBodyBytes
        try {
          rollbackBodyBytes = await resolveBody(
            materialsDirectory,
            action.rollback.request_body,
            'rollback',
          )
          credentialValue = masterCredential === undefined
            ? undefined
            : Buffer.from(masterCredential)
          return await recoverDeclaredHttpAuthedMutation({
            ledger,
            scope,
            action,
            existingLease: lease,
            expectedCampaignGrantSha256,
            credentialValue,
            rollbackBodyBytes,
            now: clock,
            transport: createProtectedMutationTransport({
              scope,
              action,
              protectedTransport: activeTransport,
            }),
            ...mutationDependencies,
            verifyCandidate: async ({ action: candidate }) => reauthorizeCleanup({ action: candidate }),
          })
        } finally {
          credentialValue?.fill(0)
          rollbackBodyBytes?.fill(0)
        }
      },
    })
  } finally {
    try {
      await ledger?.close()
    } finally {
      try {
        masterCredential?.fill(0)
      } finally {
        await browserTransportSession?.close()
      }
    }
  }
}

export function runHttpAuthedAttestedCampaign(options) {
  return runHttpAuthedCampaignRuntime(options)
}
