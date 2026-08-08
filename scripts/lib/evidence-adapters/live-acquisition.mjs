import { compareCanonicalStrings } from '../canonical-order.mjs'
import { writeEvidenceBundle } from '../evidence-bundle.mjs'
import {
  DEFAULT_CLI_LIMITS,
  ImpactCapExceededError,
  ImpactCounters,
  probeCli,
  runBoundedCli,
} from '../evidence-cli-runner.mjs'
import { redactForLog } from '../evidence-image-reference.mjs'
import { resolvePhiPolicy } from '../evidence-phi.mjs'
import { buildReadOnlyCommand } from '../evidence-readonly-allowlist.mjs'

const CLI_BY_PREFIX = new Map([['k8s', 'kubectl'], ['sf', 'sf'], ['runtime', 'kubectl']])

export function requiredCli(operations) {
  return [...new Set(operations.map(({ operation_id: id }) => CLI_BY_PREFIX.get(id.split('.')[0])))]
    .filter(Boolean)
    .sort(compareCanonicalStrings)
}

/**
 * The authorization gate both live classes share. Attestation, target class and
 * a named operator are floors for deployed-state and live-runtime alike; the
 * runtime adapter adds a per-run confirmation on top at execution time.
 */
export function assertLivePlanAuthorization(request, label) {
  if (request.attest_authorized !== true) {
    throw new Error(`${label} acquisition requires --attest-authorized`)
  }
  if (request.target_class === 'PRODUCTION' && request.acknowledge_production !== true) {
    throw new Error('a PRODUCTION target requires --acknowledge-production')
  }
  if (request.target_class === 'THIRD_PARTY' && !request.signed_authorization) {
    throw new Error(
      'a THIRD_PARTY target routes through the existing higher-assurance signed-artifact '
      + 'mode; this adapter neither creates nor approves those artifacts',
    )
  }
  return resolvePhiPolicy({
    phiScope: request.phi_scope,
    captureContents: request.capture_contents === true,
    acknowledged: request.acknowledge_phi === true,
  })
}

export async function probeRequiredClis(operations, { env, resolver, label }) {
  const cliOptions = resolver ? { resolver } : {}
  for (const cli of requiredCli(operations)) {
    const probe = await probeCli(cli, { versionArgs: ['version'], env, ...cliOptions })
    if (!probe.present) {
      throw new Error(
        `${label} acquisition needs ${cli} on PATH and it is absent (${probe.reason})`,
      )
    }
  }
}

/**
 * One bounded, stoppable, counted acquisition loop, shared by both live
 * adapters. `capture` turns one command's stdout into payload entries; that is
 * the only thing the two classes actually do differently.
 */
export async function runLiveAcquisition({
  planned,
  out,
  env,
  resolver,
  limits,
  adapterVersion,
  capture,
  shouldStop,
}) {
  const cliLimits = { ...DEFAULT_CLI_LIMITS, ...limits }
  const cliOptions = resolver ? { resolver } : {}
  const counters = new ImpactCounters({
    maxCommands: cliLimits.maxCommands,
    maxObjects: cliLimits.maxObjects,
    maxBytes: cliLimits.maxStdoutBytes,
  })
  const payload = []
  const gaps = []
  const executed = []
  let acquired = 0

  for (const [index, operation] of planned.operations.entries()) {
    // The payload prefix is the operation's position, not its ID: two
    // `k8s.resource` reads of different objects are a legitimate plan and would
    // otherwise collide on one path.
    const prefix = String(index).padStart(2, '0')
    if (await shouldStop?.()) {
      gaps.push({ area: 'acquisition', reason: 'stopped by the operator before this operation' })
      break
    }

    let result
    try {
      result = await runBoundedCli({
        name: operation.cli,
        args: operation.args,
        limits: cliLimits,
        env,
        counters,
        ...cliOptions,
      })
      counters.record({ objects: operation.objects }).assertWithinCaps()
    } catch (error) {
      // A cap is a halt, not a crash: what was already acquired stays, and the
      // stopping point is named.
      gaps.push({
        area: operation.operation_id,
        reason: error instanceof ImpactCapExceededError
          ? `acquisition halted at an impact cap: ${error.message}`
          : `operation failed: ${redactForLog(String(error.message)).slice(0, 400)}`,
      })
      break
    }

    executed.push({
      index,
      operation_id: operation.operation_id,
      payload_prefix: prefix,
      exit_code: result.code,
      objects: operation.objects,
    })
    if (result.code !== 0) {
      gaps.push({
        area: operation.operation_id,
        reason: `exited ${result.code}: ${redactForLog(result.stderr).slice(0, 400)}`,
      })
      continue
    }

    const captured = capture(operation, result, planned.phi_policy, prefix)
    for (const gap of captured.gaps ?? []) gaps.push(gap)
    for (const entry of captured.payload ?? []) payload.push(entry)
    acquired += captured.acquired ?? 0
  }

  payload.push({
    path: 'operations.json',
    bytes: Buffer.from(JSON.stringify(executed, null, 2), 'utf8'),
  })
  payload.push({
    path: 'impact-counters.json',
    bytes: Buffer.from(JSON.stringify(counters.snapshot(), null, 2), 'utf8'),
  })
  payload.sort((left, right) => compareCanonicalStrings(left.path, right.path))

  return writeEvidenceBundle({
    directory: out,
    profile: {
      schema: 'evidence-bundle-v1',
      evidence_context: { ...planned.evidence_context_seed, acquired_on: planned.acquired_on },
      target_class: planned.target_class,
      phi_scope: planned.phi_scope,
      phi_bearing: planned.phi_policy.phi_bearing,
      adapter_version: adapterVersion,
      contract_version: 1,
      coverage_state: acquired === 0 ? 'NOT_ASSESSED' : gaps.length > 0 ? 'PARTIAL' : 'COVERED',
      attestation: planned.attestation,
      coverage_gaps: gaps.length > 0
        ? gaps
        : acquired === 0
          ? [{ area: 'acquisition', reason: 'no object was acquired' }]
          : [],
    },
    payload,
  })
}

export { buildReadOnlyCommand }
