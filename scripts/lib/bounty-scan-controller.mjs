import { readFile, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { assertScopeCurrent } from './bounty-contracts.mjs'
import { validateBountyBundle } from './bounty-controller.mjs'
import {
  digestAdversarialPlan,
} from './adversarial-validation-contracts.mjs'
import { verifyOperatorAuthorizationReceipt } from './operator-authorization.mjs'
import { sanitizeCapturedRequest } from './bounty-authz-request.mjs'
import {
  describeIntensity,
  resolveIntensityProfile,
  selectInsertionPoints,
  selectProbes,
  selectRequests,
} from './bounty-intensity.mjs'
import { replayAsRole } from './bounty-authz-replay.mjs'
import { ANONYMOUS_ROLE, findRole } from './bounty-authz-roles.mjs'
import { createRateLimiter } from './bounty-recon-ratelimit.mjs'
import {
  applyPayload,
  describeInsertion,
  findInsertionPoints,
  isSsrfCandidate,
} from './bounty-scan-insertion.mjs'
import {
  calibrateProbeBaseline,
  classifyOobProbe,
  classifyProbe,
  summarizeScan,
} from './bounty-scan-oracle.mjs'
import { scanResponse, summarizePassive } from './bounty-scan-passive.mjs'
import { assertValidOobSession } from './bounty-oob-controller.mjs'
import { buildPayloadHost } from './bounty-oob-payload.mjs'
import {
  authorizeBountyScanRequest,
  bountyScanStateChangingReason,
  bountyScanPayloadCatalog,
  buildBountyScanPlan,
  digestBountyScanScope,
  snapshotBountyScanRole,
} from './bounty-scan-plan.mjs'
import {
  BOUNTY_SCAN_LEDGER_DIRECTORY,
  digestBountyScanLedgerValue,
  openBountyScanLedger,
} from './bounty-scan-ledger.mjs'

const REQUESTS_FILE = 'authz-requests.json'
const FINDINGS_FILE = 'scan-findings.json'
const OOB_SESSION_FILE = 'oob-session.json'
const OPERATOR_AUTHORIZATION_START_GRACE_MS = 5 * 60 * 1000

// Deliberately narrow, per the design spec. No mass XSS or SQLi fuzzing and no
// CVE template sweep: nuclei does breadth better, and breadth on a picked-over
// program is a duplicate-and-N/A factory. Depth on a few classes with a real
// oracle is what pays.
export const SCAN_CLASSES = Object.freeze(['error-injection', 'ssrf-oob', 'passive'])

function verifyScanOperatorAuthorization({ receipt, plan, now }) {
  const planSha256 = digestAdversarialPlan(plan)
  const verified = verifyOperatorAuthorizationReceipt({
    value: receipt,
    planSha256,
    scopeRevisionSha256: plan.scope_revision_sha256,
    target: plan.target,
    fail(code, message) {
      throw new Error(`bounty scan operator authorization ${code}: ${message}`)
    },
  })
  const current = now instanceof Date ? now.valueOf() : Date.parse(now)
  const declaredAt = Date.parse(verified.declared_at)
  const expiresAt = declaredAt
    + OPERATOR_AUTHORIZATION_START_GRACE_MS
    + plan.limits.max_wall_time_ms
  if (!Number.isFinite(current) || declaredAt > current) {
    throw new Error('bounty scan operator authorization cannot be future-dated')
  }
  if (current >= expiresAt) {
    throw new Error('bounty scan operator authorization is outside its plan-derived execution window')
  }
  return Object.freeze({
    schema_version: '1.0.0',
    kind: 'red-team-audit/bounty-scan-authorization-receipt',
    status: 'CONTROLLER_VERIFIED',
    authorization_id: verified.authorization_reference,
    authorization_reference: verified.authorization_reference,
    authorization_sha256: verified.authorization_sha256,
    authority_basis: verified.authority_basis,
    operator_id: verified.operator_id,
    plan_sha256: verified.plan_sha256,
    engagement_id: plan.engagement_id,
    scope_revision_sha256: verified.scope_revision_sha256,
    target_sha256: verified.target_sha256,
    declared_at: verified.declared_at,
    expires_at: new Date(expiresAt).toISOString(),
  })
}

async function loadScope(bundlePath, { now }) {
  return (await validateBountyBundle(bundlePath, { now })).scope
}

export async function loadBountyScanOobBinding(bundlePath) {
  const session = JSON.parse(await readFile(join(bundlePath, OOB_SESSION_FILE), 'utf8'))
  assertValidOobSession(session)
  return {
    backend: session.backend,
    server: session.server,
    correlation_id: session.correlation_id,
    created_at: session.created_at,
  }
}

export async function runScan({
  bundlePath,
  requests,
  registry,
  now,
  classes = SCAN_CLASSES,
  roleId = null,
  // Supplied by the caller when ssrf-oob is active: mints a correlated host and
  // later reads back what the listener saw. P4 does not reach into P7 itself.
  oob = null,
  fetchImpl = fetch,
  env = process.env,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  clock = () => Date.now(),
  operatorAuthorizationReceipt = null,
  isAuthorizationRevoked = null,
  isOperatorStopRequested = null,
  // A synchronous, fail-before-transport crash seam used by recovery tests.
  // It is deliberately not exposed by the public CLI (whose scan run remains disabled).
  ledgerHooks = null,
}) {
  if (!Array.isArray(requests) || requests.length === 0) {
    throw new Error('no captured requests to scan; import a HAR first')
  }
  const scope = await loadScope(bundlePath, { now })
  assertScopeCurrent({ scope, now })
  if (scope.stop_conditions.operator_stop === true) {
    throw new Error('bounty scan stopped by the sealed operator stop condition')
  }
  const role = snapshotBountyScanRole(
    roleId === null ? ANONYMOUS_ROLE : findRole(registry, roleId),
  )

  // The sealed tier decides breadth. An explicit --classes still wins, so an
  // operator can narrow a HAM scope for one run without re-sealing it; what
  // they cannot do is widen beyond what the tier permits.
  const profile = resolveIntensityProfile(scope)
  const activeClasses = (classes ?? profile.classes).filter((entry) => profile.classes.includes(entry))
  if (activeClasses.length === 0) {
    throw new Error('bounty scan requires at least one class allowed by the sealed intensity profile')
  }
  const coverageNotes = []
  // Plan construction and execution share the same module-owned, deeply frozen
  // catalog snapshot. Exported oracle fixtures cannot drift it between awaits.
  const payloadCatalog = bountyScanPayloadCatalog()
  const controlProbes = payloadCatalog.error_controls
  const errorProbes = payloadCatalog.error_probes

  const requestPlan = selectRequests(
    requests.map((request) => sanitizeCapturedRequest(request)),
    profile,
  )
  if (requestPlan.note !== null) coverageNotes.push(requestPlan.note)
  const crafted = activeClasses.includes('error-injection')
    || activeClasses.includes('ssrf-oob')
  if (crafted) {
    const unsafeRequest = requestPlan.items.find((request) =>
      bountyScanStateChangingReason(request) !== null)
    if (unsafeRequest !== undefined) {
      const reason = bountyScanStateChangingReason(unsafeRequest)
      throw new Error(
        `bounty scan refuses state-changing captured ${reason}; use the mutation campaign`,
      )
    }
  }
  if (crafted && scope.authorization.permissions.active_testing !== true) {
    throw new Error(
      'scanning sends crafted payloads and requires active_testing in the sealed permissions',
    )
  }
  if (
    activeClasses.includes('ssrf-oob')
    && (typeof oob?.mint !== 'function' || typeof oob?.collect !== 'function')
  ) {
    throw new Error('ssrf-oob requires a concrete OOB adapter and bound session')
  }
  const oobBinding = activeClasses.includes('ssrf-oob') && oob !== null
    ? await loadBountyScanOobBinding(bundlePath)
    : null
  const exactPlan = crafted
    ? buildBountyScanPlan({
      scope,
      requests: requestPlan.items,
      classes: activeClasses,
      role,
      profile,
      oobBinding,
    })
    : null
  let adversarialValidation = null
  if (exactPlan !== null) {
    if (
      operatorAuthorizationReceipt === null
      || typeof isAuthorizationRevoked !== 'function'
      || typeof isOperatorStopRequested !== 'function'
    ) {
      throw new Error(
        'every crafted scan requires an exact controller-verified operator authorization receipt plus fail-closed revocation and operator-stop gates',
      )
    }
    adversarialValidation = verifyScanOperatorAuthorization({
      receipt: operatorAuthorizationReceipt,
      plan: exactPlan,
      now,
    })
  }

  const limiter = createRateLimiter({
    ratePerSecond: scope.authorization.permissions.rate_limit_rps,
    now: clock,
    sleep,
  })
  const startedAt = clock()
  if (!Number.isFinite(startedAt)) {
    throw new Error('crafted bounty scan clock returned a non-finite start time')
  }
  const authorityStartedAt = now.valueOf()
  let scanLedger = null
  let actionsUsed = 0
  if (exactPlan !== null) {
    scanLedger = openBountyScanLedger({
      directory: resolve(bundlePath, BOUNTY_SCAN_LEDGER_DIRECTORY),
      binding: {
        authorization_id: adversarialValidation.authorization_id,
        authorization_sha256: adversarialValidation.authorization_sha256,
        engagement_id: exactPlan.engagement_id,
        plan_sha256: adversarialValidation.plan_sha256,
        scope_revision_sha256: exactPlan.scope_revision_sha256,
        target_sha256: adversarialValidation.target_sha256,
      },
    })
    const ledgerStatus = scanLedger.assertDispatchable()
    actionsUsed = ledgerStatus.qualified_sends
    if (actionsUsed >= exactPlan.limits.max_actions) {
      throw new Error('crafted bounty scan exhausted its authorized action budget')
    }
  }

  const results = []
  const passive = []

  const ledgerTimestamp = (fallback = now.toISOString()) => {
    const currentClock = clock()
    if (!Number.isFinite(currentClock) || currentClock < startedAt) return fallback
    return new Date(authorityStartedAt + (currentClock - startedAt)).toISOString()
  }

  const finishScan = async () => {
    const passiveSummary = crafted
      ? summarizePassive(passive)
      : { total: 0, byKind: {}, status: 'NOT_ASSESSED' }
    const summaryCore = {
      ...summarizeScan(results),
      passive: passiveSummary,
      intensity: describeIntensity(profile),
      // Never silent: a truncated sweep must not read as a complete one.
      coverageNotes,
      coverage: !crafted
        ? 'NOT_ASSESSED_MISSING_RESPONSE_EVIDENCE'
        : coverageNotes.length === 0
          ? 'FULL_AT_THIS_INTENSITY'
          : 'CAPPED_BY_INTENSITY',
    }
    const scanLedgerStatus = scanLedger === null
      ? null
      : scanLedger.complete({
        summarySha256: digestBountyScanLedgerValue(summaryCore),
        completedAt: ledgerTimestamp(),
      })
    const summary = {
      ...summaryCore,
      scanLedger: scanLedgerStatus,
    }
    await writeFile(join(bundlePath, FINDINGS_FILE), `${JSON.stringify({
      schema_version: '1.0.0',
      kind: 'red-team-audit/bounty-scan-findings',
      engagement_id: scope.engagement_id,
      created_at: now.toISOString(),
      classes: activeClasses,
      intensity: profile.tier,
      adversarial_validation: adversarialValidation,
      scan_ledger: scanLedgerStatus,
      results,
      passive,
      summary,
    }, null, 2)}\n`, 'utf8')
    return {
      ...summary,
      paced: limiter.stats(),
      adversarialValidation,
    }
  }

  // Passive mode consumes only already-captured artifacts. The request capture
  // does not contain response bytes, so synthesizing a "passive observation"
  // by replaying it would actually be active reconnaissance. Preserve scope
  // qualification for the artifact, but make this path network-silent.
  if (!crafted) {
    coverageNotes.push(
      'passive response evidence was not captured; response analysis was not assessed',
    )
    for (const request of requestPlan.items) {
      const decision = authorizeBountyScanRequest({ scope, request })
      if (!decision.allowed) {
        results.push({
          url: request.url,
          method: request.method,
          insertion: null,
          probe: null,
          verdict: 'PROBE_FAILED',
          confidence: 'none',
          rationale: `captured artifact target refused by the scope kernel: ${decision.reason}`,
        })
      }
    }
    return finishScan()
  }

  for (const request of requestPlan.items) {
    const send = async (candidate) => {
      const scopeDecision = authorizeBountyScanRequest({ scope, request: candidate })
      if (!scopeDecision.allowed) {
        return {
          status: null,
          error: `out of scope: ${scopeDecision.reason}`,
          refusal: {
            host: null,
            reason: scopeDecision.reason,
            ruleId: scopeDecision.rule_id,
          },
          normalized: null,
          role: role.id,
        }
      }
      if (actionsUsed >= exactPlan.limits.max_actions) {
        throw new Error('crafted bounty scan exhausted its authorized action budget')
      }

      const currentAuthorityTime = () => {
        const currentClock = clock()
        if (!Number.isFinite(currentClock) || currentClock < startedAt) {
          throw new Error('crafted bounty scan clock moved backwards or became invalid')
        }
        const elapsedMs = currentClock - startedAt
        const authorityNow = new Date(authorityStartedAt + elapsedMs)
        if (elapsedMs >= exactPlan.limits.max_wall_time_ms) {
          throw new Error('crafted bounty scan exhausted its authorized wall-time budget')
        }
        if (authorityNow.valueOf() >= Date.parse(adversarialValidation.expires_at)) {
          throw new Error('crafted scan operator authorization expired before target dispatch')
        }
        return { authorityNow, elapsedMs }
      }

      let dispatchQualification = null
      const dispatchLimiter = {
        acquire: async () => {
          await limiter.acquire()
          currentAuthorityTime()
          const currentReceipt = Object.freeze({ ...adversarialValidation })
          let stopped
          try {
            stopped = await isOperatorStopRequested(currentReceipt)
          } catch {
            throw new Error('crafted scan operator-stop check failed before target dispatch')
          }
          if (typeof stopped !== 'boolean') {
            throw new Error('crafted scan operator-stop check returned an invalid result')
          }
          if (stopped) {
            throw new Error('crafted scan was stopped by the operator before target dispatch')
          }
          let revoked
          try {
            revoked = await isAuthorizationRevoked(currentReceipt)
          } catch {
            throw new Error('crafted scan authorization revocation check failed before target dispatch')
          }
          if (typeof revoked !== 'boolean') {
            throw new Error('crafted scan authorization revocation check returned an invalid result')
          }
          if (revoked) {
            throw new Error('crafted scan authorization was revoked before target dispatch')
          }

          // The callbacks and pacing above are asynchronous. Reload the sealed
          // bundle after they finish; a startup snapshot is not authorization
          // for a later send. From this successful check through qualification
          // and fetch, the remaining controller work is synchronous.
          const beforeLoad = currentAuthorityTime()
          const currentScope = await loadScope(bundlePath, { now: beforeLoad.authorityNow })
          const finalAuthority = currentAuthorityTime()
          assertScopeCurrent({ scope: currentScope, now: finalAuthority.authorityNow })
          if (currentScope.stop_conditions.operator_stop === true) {
            throw new Error('crafted scan stopped by the current sealed operator stop condition')
          }
          if (currentScope.authorization.permissions.active_testing !== true) {
            throw new Error('crafted scan lost active_testing permission before target dispatch')
          }
          const currentScopeSha256 = digestBountyScanScope(currentScope)
          if (currentScopeSha256 !== exactPlan.scope_revision_sha256) {
            throw new Error(
              'current scope revision drifted from the exact operator-authorized bounty scan plan',
            )
          }
          const currentScopeDecision = authorizeBountyScanRequest({
            scope: currentScope,
            request: candidate,
          })
          if (!currentScopeDecision.allowed) {
            throw new Error(
              `bounty scan request left the current scope before dispatch: ${currentScopeDecision.reason}`,
            )
          }
          dispatchQualification = Object.freeze({
            authorityNow: finalAuthority.authorityNow,
            request: currentScopeDecision.request,
            ruleId: currentScopeDecision.rule_id,
          })
        },
      }

      let ledgerFailure = null
      let pendingSettlement = null
      const auditedFetch = async (url, options) => {
        const qualification = dispatchQualification
        dispatchQualification = null
        if (qualification === null || url !== qualification.request.url) {
          const error = new Error('bounty scan transport reached dispatch without current scope qualification')
          ledgerFailure = error
          throw error
        }
        const actionIndex = actionsUsed + 1
        const requestSha256 = digestBountyScanLedgerValue(qualification.request)
        const actionSha256 = digestBountyScanLedgerValue({
          schema_version: '1.0.0',
          kind: 'red-team-audit/bounty-scan-ledger-action',
          action_index: actionIndex,
          plan_sha256: adversarialValidation.plan_sha256,
          authorization_sha256: adversarialValidation.authorization_sha256,
          scope_revision_sha256: exactPlan.scope_revision_sha256,
          request_sha256: requestSha256,
          role_id: role.id,
        })
        const qualifiedAt = qualification.authorityNow.toISOString()
        try {
          scanLedger.qualifySend({
            actionIndex,
            actionSha256,
            requestSha256,
            ruleId: qualification.ruleId,
            qualifiedAt,
          })
          actionsUsed = actionIndex
          if (ledgerHooks?.afterQualified !== undefined) {
            if (typeof ledgerHooks.afterQualified !== 'function') {
              throw new Error('bounty scan ledger afterQualified hook must be a function')
            }
            const hookResult = ledgerHooks.afterQualified(Object.freeze({
              action_index: actionIndex,
              action_sha256: actionSha256,
            }))
            if (hookResult !== undefined) {
              throw new Error('bounty scan ledger afterQualified hook must be synchronous')
            }
          }
        } catch (error) {
          ledgerFailure = error
          throw error
        }

        let response
        try {
          response = await fetchImpl(url, options)
        } catch (error) {
          try {
            scanLedger.settleSend({
              actionIndex,
              actionSha256,
              outcome: 'THREW',
              httpStatus: null,
              errorName: String(error?.name ?? 'Error').slice(0, 160),
              settledAt: ledgerTimestamp(qualifiedAt),
            })
          } catch (settlementError) {
            ledgerFailure = settlementError
          }
          throw error
        }
        pendingSettlement = { actionIndex, actionSha256, qualifiedAt }
        return response
      }

      const replay = await replayAsRole({
        request: scopeDecision.request,
        role,
        sealedScope: scope,
        limiter: dispatchLimiter,
        fetchImpl: auditedFetch,
        timeoutMs: exactPlan.limits.max_action_time_ms,
        env,
        onResponseSettled({ outcome, httpStatus, errorName }) {
          if (pendingSettlement === null) {
            const error = new Error('bounty scan response settled without a qualified transport result')
            ledgerFailure = error
            throw error
          }
          const settlement = pendingSettlement
          pendingSettlement = null
          try {
            scanLedger.settleSend({
              actionIndex: settlement.actionIndex,
              actionSha256: settlement.actionSha256,
              outcome,
              httpStatus,
              errorName,
              settledAt: ledgerTimestamp(settlement.qualifiedAt),
            })
          } catch (error) {
            ledgerFailure = error
            throw error
          }
        },
      })
      if (ledgerFailure !== null) throw ledgerFailure
      if (pendingSettlement !== null) {
        throw new Error('bounty scan response observation ended without durable settlement')
      }
      return replay
    }

    // Two untouched requests first. Same self-calibration as the authz grinder:
    // without knowing whether the endpoint is reproducible, no later diff means
    // anything.
    const first = await send(request)
    if (first.refusal !== null) {
      results.push({
        url: request.url,
        method: request.method,
        insertion: null,
        probe: null,
        verdict: 'PROBE_FAILED',
        confidence: 'none',
        rationale: `request target refused by the scope kernel: ${first.refusal.reason}`,
      })
      continue
    }
    const second = await send(request)
    const baseline = calibrateProbeBaseline({ first, second })
    const baselineBody = first.normalized?.normalizedBody ?? ''

    if (activeClasses.includes('passive')) {
      for (const observation of scanResponse({
        url: request.url,
        status: first.status,
        headers: { 'content-type': first.contentType ?? '' },
        body: baselineBody,
      })) {
        passive.push(observation)
      }
    }

    const pointPlan = selectInsertionPoints(findInsertionPoints(request), profile)
    if (pointPlan.note !== null) coverageNotes.push(`${request.url} ${pointPlan.note}`)
    const points = pointPlan.items

    for (const point of points) {
      if (activeClasses.includes('error-injection')) {
        // One control per insertion point, reused across that point's probes: the
        // control answers "does this endpoint react to any change at all", which
        // is a property of the point, not of each payload.
        const controlProbe = controlProbes[0]
        const control = await send(applyPayload(request, point, controlProbe.payload, { mode: controlProbe.mode }))

        const probePlan = selectProbes(errorProbes, profile)
        if (probePlan.note !== null) coverageNotes.push(`${request.url} ${probePlan.note}`)
        let signalFound = false
        for (const probeSpec of probePlan.items) {
          // normal tier stops at the first signal for a point; higher tiers
          // exhaust it, because a second signal on the same parameter is
          // often the one that characterises the bug.
          if (signalFound && profile.earlyExitOnSignal) break
          const probe = await send(applyPayload(request, point, probeSpec.payload, { mode: probeSpec.mode }))
          const outcome = classifyProbe({
            baseline: { ...baseline, normalizedBody: baselineBody },
            control,
            probe,
            insertionPoint: point,
            probeId: probeSpec.id,
          })
          if (outcome.verdict.endsWith('_CANDIDATE')) signalFound = true
          results.push({
            url: request.url,
            method: request.method,
            insertion: describeInsertion(point),
            probe: probeSpec.id,
            class: 'error-injection',
            status: probe.status,
            ...outcome,
          })
        }
      }

      // Narrow by construction: only points whose name or value shape says they
      // carry a URL. Spraying an SSRF payload at a numeric id burns requests
      // against the sealed rate limit and produces results nobody should read.
      if (activeClasses.includes('ssrf-oob') && oob !== null && isSsrfCandidate(point)) {
        const minted = await oob.mint({
          label: `ssrf ${describeInsertion(point)}`,
          bugClass: 'ssrf',
          requestId: request.request_id ?? request.url,
          insertionPoint: describeInsertion(point),
          role: role.id,
        })
        if (!/^[a-z0-9]{13}$/.test(minted?.nonce ?? '')) {
          throw new Error('OOB adapter returned an invalid nonce')
        }
        const expectedOobHost = buildPayloadHost({
          correlationId: oobBinding.correlation_id,
          nonce: minted.nonce,
          server: oobBinding.server,
        })
        if (minted.backend !== oobBinding.backend || minted.host !== expectedOobHost) {
          throw new Error(
            'OOB callback drifted from the exact session destination bound into the sealed plan',
          )
        }
        const payloadUrl = new URL(`http://${expectedOobHost}/`)
        if (
          payloadUrl.username !== ''
          || payloadUrl.password !== ''
          || payloadUrl.port !== ''
          || payloadUrl.hostname !== expectedOobHost
          || payloadUrl.pathname !== '/'
          || payloadUrl.search !== ''
          || payloadUrl.hash !== ''
        ) {
          throw new Error('OOB callback URL drifted from the sealed canonical hostname')
        }
        const probe = await send(applyPayload(request, point, payloadUrl.href))
        const interactions = await oob.collect()
        const outcome = classifyOobProbe({
          interactions,
          nonce: minted.nonce,
          insertionPoint: point,
          probeId: 'ssrf-oob',
        })
        results.push({
          url: request.url,
          method: request.method,
          insertion: describeInsertion(point),
          probe: 'ssrf-oob',
          class: 'ssrf-oob',
          status: probe.status,
          oob_host: minted.host,
          ...outcome,
        })
      }
    }
  }

  return finishScan()
}

export async function loadScanRequests(bundlePath) {
  const stored = JSON.parse(await readFile(join(bundlePath, REQUESTS_FILE), 'utf8'))
  if (!Array.isArray(stored.requests)) throw new Error('scan request bundle must contain a request array')
  return stored.requests.map((request) => sanitizeCapturedRequest(request))
}

export async function scanStatus({ bundlePath }) {
  const findings = JSON.parse(await readFile(join(bundlePath, FINDINGS_FILE), 'utf8'))
  return {
    ...findings.summary,
    adversarialValidation: findings.adversarial_validation ?? null,
    candidateDetail: findings.results
      .filter((result) => result.verdict.endsWith('_CANDIDATE'))
      .map((result) => `${result.verdict} ${result.method} ${result.url} at ${result.insertion} via ${result.probe}`),
  }
}
