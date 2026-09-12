import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { calibrateBaseline, classifyAuthzOutcome, summarizeMatrix } from './bounty-authz-classify.mjs'
import { assertScopeCurrent } from './bounty-contracts.mjs'
import { replayAsRole } from './bounty-authz-replay.mjs'
import { findRole, rolesToTest } from './bounty-authz-roles.mjs'
import {
  describeOccurrence,
  identifiersInRequest,
  mutationPlan,
  substituteIdentifier,
} from './bounty-authz-identifier.mjs'
import {
  importHarEntries,
  redactRequest,
  requestSignature,
  sanitizeCapturedRequest,
} from './bounty-authz-request.mjs'
import { createRateLimiter } from './bounty-recon-ratelimit.mjs'

const REQUESTS_FILE = 'authz-requests.json'
const FINDINGS_FILE = 'authz-findings.json'
const SCOPE_FILE = 'scope.json'

async function loadSealedScope(bundlePath) {
  return JSON.parse(await readFile(join(bundlePath, SCOPE_FILE), 'utf8'))
}

export async function importAuthzRequests({ bundlePath, harPath, ownerRole }) {
  const har = JSON.parse(await readFile(harPath, 'utf8'))
  const { requests, skipped } = importHarEntries(har, { ownerRole })
  // Deduped by signature so a browser session's repeated polling does not turn
  // into hundreds of identical replays.
  const bySignature = new Map()
  for (const request of requests) {
    bySignature.set(requestSignature(request), redactRequest(request))
  }
  const deduped = [...bySignature.values()]
  await writeFile(
    join(bundlePath, REQUESTS_FILE),
    `${JSON.stringify({ schema_version: '1.0.0', requests: deduped }, null, 2)}\n`,
    'utf8',
  )
  return { imported: deduped.length, skipped, rawEntries: requests.length }
}

export async function loadAuthzRequests(bundlePath) {
  const stored = JSON.parse(await readFile(join(bundlePath, REQUESTS_FILE), 'utf8'))
  if (!Array.isArray(stored.requests)) throw new Error('authz request bundle must contain a request array')
  return stored.requests.map((request) => sanitizeCapturedRequest(request))
}

export async function runAuthzMatrix({
  bundlePath,
  requests,
  registry,
  now,
  identifierMap = null,
  fetchImpl = fetch,
  env = process.env,
  sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
  clock = () => Date.now(),
}) {
  if (!Array.isArray(requests) || requests.length === 0) {
    throw new Error('no captured requests to grind; import a HAR first')
  }
  const safeRequests = requests.map((request) => sanitizeCapturedRequest(request))
  const scope = await loadSealedScope(bundlePath)
  // An expired grant makes every replay unauthorized, in scope or not.
  assertScopeCurrent({ scope, now })
  const limiter = createRateLimiter({
    ratePerSecond: scope.authorization.permissions.rate_limit_rps,
    now: clock,
    sleep,
  })

  const results = []
  for (const request of safeRequests) {
    const ownerRole = findRole(registry, request.owner_role)

    // Two owner replays first: anything that differs between them is volatile by
    // definition, and that is the noise floor every cross-role claim rests on.
    const first = await replayAsRole({ request, role: ownerRole, sealedScope: scope, limiter, fetchImpl, env })
    const second = await replayAsRole({ request, role: ownerRole, sealedScope: scope, limiter, fetchImpl, env })
    const baseline = calibrateBaseline({ first, second })

    if (first.refusal !== null) {
      results.push({
        request_id: request.request_id,
        url: request.url,
        method: request.method,
        owner_role: ownerRole.id,
        tester_role: ownerRole.id,
        verdict: 'REPLAY_FAILED',
        confidence: 'none',
        rationale: `request target refused by the scope kernel: ${first.refusal.reason}`,
        baseline_stable: false,
      })
      continue
    }

    for (const testerRole of rolesToTest(registry, ownerRole.id)) {
      const testerResponse = await replayAsRole({
        request, role: testerRole, sealedScope: scope, limiter, fetchImpl, env,
      })
      const outcome = classifyAuthzOutcome({ baseline, testerResponse, testerRole })
      results.push({
        request_id: request.request_id,
        url: request.url,
        method: request.method,
        owner_role: ownerRole.id,
        tester_role: testerRole.id,
        owner_status: first.status,
        tester_status: testerResponse.status,
        verdict: outcome.verdict,
        confidence: outcome.confidence,
        rationale: outcome.rationale,
        baseline_stable: baseline.stable,
        baseline_reason: baseline.reason,
      })
    }
  }

  // Horizontal IDOR. Where a captured request carries a declared identifier, swap
  // in each same-kind identifier owned by a DIFFERENT operator-controlled role,
  // then ask whether a role that should not own the object can read it.
  //
  // The mutated request is baselined against the identifier's own owner rather
  // than the capture's owner: after substitution the request targets a different
  // object, so the only meaningful "correct" response is the one its real owner
  // gets. Reusing the original baseline here would compare against the wrong
  // object entirely.
  if (identifierMap !== null) {
    for (const request of safeRequests) {
      for (const { identifier, occurrence } of identifiersInRequest({
        request,
        identifiers: identifierMap.identifiers,
      })) {
        for (const target of mutationPlan({ identifiers: identifierMap.identifiers, sourceIdentifier: identifier })) {
          const mutated = substituteIdentifier(request, occurrence, target.value)

          if (target.absent === true) {
            // Existence-oracle check: no baseline, because a declared-absent
            // object has no owner and no correct content. Only the status matters.
            const probeRole = findRole(registry, request.owner_role)
            const probe = await replayAsRole({
              request: mutated, role: probeRole, sealedScope: scope, limiter, fetchImpl, env,
            })
            results.push({
              request_id: request.request_id,
              url: mutated.url,
              method: mutated.method,
              owner_role: probeRole.id,
              tester_role: probeRole.id,
              mutation: `${describeOccurrence(occurrence)} ${identifier.id} -> ${target.id} (declared absent)`,
              tester_status: probe.status,
              verdict: 'ABSENT_PROBE',
              confidence: 'none',
              rationale: `status ${probe.status} for a declared-absent ${target.kind}; compare against the not-yours status to spot an enumeration oracle`,
              baseline_stable: false,
              baseline_reason: 'absent-object-has-no-owner',
            })
            continue
          }

          const targetOwner = findRole(registry, target.owner_role)
          const firstOwned = await replayAsRole({
            request: mutated, role: targetOwner, sealedScope: scope, limiter, fetchImpl, env,
          })
          const secondOwned = await replayAsRole({
            request: mutated, role: targetOwner, sealedScope: scope, limiter, fetchImpl, env,
          })
          const mutatedBaseline = calibrateBaseline({ first: firstOwned, second: secondOwned })

          if (firstOwned.refusal !== null) continue

          for (const testerRole of rolesToTest(registry, targetOwner.id)) {
            const testerResponse = await replayAsRole({
              request: mutated, role: testerRole, sealedScope: scope, limiter, fetchImpl, env,
            })
            const outcome = classifyAuthzOutcome({ baseline: mutatedBaseline, testerResponse, testerRole })
            results.push({
              request_id: request.request_id,
              url: mutated.url,
              method: mutated.method,
              owner_role: targetOwner.id,
              tester_role: testerRole.id,
              mutation: `${describeOccurrence(occurrence)} ${identifier.id} -> ${target.id}`,
              owner_status: firstOwned.status,
              tester_status: testerResponse.status,
              verdict: outcome.verdict,
              confidence: outcome.confidence,
              rationale: outcome.rationale,
              baseline_stable: mutatedBaseline.stable,
              baseline_reason: mutatedBaseline.reason,
            })
          }
        }
      }
    }
  }

  const summary = summarizeMatrix(results)
  const findings = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/bounty-authz-findings',
    engagement_id: scope.engagement_id,
    created_at: now.toISOString(),
    // Every verdict is retained, denials included: the shape of what was refused
    // is what makes a bypass elsewhere defensible.
    results,
    summary,
  }
  await writeFile(join(bundlePath, FINDINGS_FILE), `${JSON.stringify(findings, null, 2)}\n`, 'utf8')
  return { ...summary, requests: safeRequests.length, paced: limiter.stats() }
}

export async function authzStatus({ bundlePath }) {
  const findings = JSON.parse(await readFile(join(bundlePath, FINDINGS_FILE), 'utf8'))
  return {
    ...findings.summary,
    candidateDetail: findings.results
      .filter((result) => result.verdict === 'AUTHZ_BYPASS_CANDIDATE')
      .map((result) => `${result.method} ${result.url} as ${result.tester_role}`),
  }
}
