import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { assertScopeCurrent } from './bounty-contracts.mjs'
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
  CONTROL_PROBES,
  ERROR_PROBES,
  calibrateProbeBaseline,
  classifyOobProbe,
  classifyProbe,
  summarizeScan,
} from './bounty-scan-oracle.mjs'
import { scanResponse, summarizePassive } from './bounty-scan-passive.mjs'

const SCOPE_FILE = 'scope.json'
const REQUESTS_FILE = 'authz-requests.json'
const FINDINGS_FILE = 'scan-findings.json'

// Deliberately narrow, per the design spec. No mass XSS or SQLi fuzzing and no
// CVE template sweep: nuclei does breadth better, and breadth on a picked-over
// program is a duplicate-and-N/A factory. Depth on a few classes with a real
// oracle is what pays.
export const SCAN_CLASSES = Object.freeze(['error-injection', 'ssrf-oob', 'passive'])

async function loadScope(bundlePath) {
  return JSON.parse(await readFile(join(bundlePath, SCOPE_FILE), 'utf8'))
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
}) {
  if (!Array.isArray(requests) || requests.length === 0) {
    throw new Error('no captured requests to scan; import a HAR first')
  }
  const scope = await loadScope(bundlePath)
  assertScopeCurrent({ scope, now })
  if (scope.authorization.permissions.active_testing !== true) {
    throw new Error(
      'scanning sends crafted payloads and requires active_testing in the sealed permissions',
    )
  }
  const limiter = createRateLimiter({
    ratePerSecond: scope.authorization.permissions.rate_limit_rps,
    now: clock,
    sleep,
  })
  const role = roleId === null ? ANONYMOUS_ROLE : findRole(registry, roleId)

  const results = []
  const passive = []

  for (const request of requests) {
    const send = (candidate) => replayAsRole({
      request: candidate, role, sealedScope: scope, limiter, fetchImpl, env,
    })

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

    if (classes.includes('passive')) {
      for (const observation of scanResponse({
        url: request.url,
        status: first.status,
        headers: { 'content-type': first.contentType ?? '' },
        body: baselineBody,
      })) {
        passive.push(observation)
      }
    }

    const points = findInsertionPoints(request)

    for (const point of points) {
      if (classes.includes('error-injection')) {
        // One control per insertion point, reused across that point's probes: the
        // control answers "does this endpoint react to any change at all", which
        // is a property of the point, not of each payload.
        const controlProbe = CONTROL_PROBES[0]
        const control = await send(applyPayload(request, point, controlProbe.payload, { mode: controlProbe.mode }))

        for (const probeSpec of ERROR_PROBES) {
          const probe = await send(applyPayload(request, point, probeSpec.payload, { mode: probeSpec.mode }))
          const outcome = classifyProbe({
            baseline: { ...baseline, normalizedBody: baselineBody },
            control,
            probe,
            insertionPoint: point,
            probeId: probeSpec.id,
          })
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
      if (classes.includes('ssrf-oob') && oob !== null && isSsrfCandidate(point)) {
        const minted = await oob.mint({
          label: `ssrf ${describeInsertion(point)}`,
          bugClass: 'ssrf',
          requestId: request.request_id ?? request.url,
          insertionPoint: describeInsertion(point),
          role: role.id,
        })
        const probe = await send(applyPayload(request, point, `http://${minted.host}/`))
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

  const summary = { ...summarizeScan(results), passive: summarizePassive(passive) }
  await writeFile(join(bundlePath, FINDINGS_FILE), `${JSON.stringify({
    schema_version: '1.0.0',
    kind: 'red-team-audit/bounty-scan-findings',
    engagement_id: scope.engagement_id,
    created_at: now.toISOString(),
    classes,
    results,
    passive,
    summary,
  }, null, 2)}\n`, 'utf8')
  return { ...summary, paced: limiter.stats() }
}

export async function loadScanRequests(bundlePath) {
  const stored = JSON.parse(await readFile(join(bundlePath, REQUESTS_FILE), 'utf8'))
  return stored.requests
}

export async function scanStatus({ bundlePath }) {
  const findings = JSON.parse(await readFile(join(bundlePath, FINDINGS_FILE), 'utf8'))
  return {
    ...findings.summary,
    candidateDetail: findings.results
      .filter((result) => result.verdict.endsWith('_CANDIDATE'))
      .map((result) => `${result.verdict} ${result.method} ${result.url} at ${result.insertion} via ${result.probe}`),
  }
}
