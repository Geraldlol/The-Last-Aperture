import { compareCanonicalStrings } from '../canonical-order.mjs'
import { writeEvidenceBundle } from '../evidence-bundle.mjs'
import {
  ImpactCapExceededError,
  ImpactCounters,
  probeCli,
  runBoundedCli,
  validateCliLimits,
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
  if (
    request.target_class === 'THIRD_PARTY'
    && request.acknowledge_third_party !== true
  ) {
    throw new Error(
      'a THIRD_PARTY target requires --acknowledge-third-party while the '
      + 'higher-assurance signed-artifact controller is unavailable',
    )
  }
  return resolvePhiPolicy({
    phiScope: request.phi_scope,
    captureContents: request.capture_contents === true,
    acknowledged: request.acknowledge_phi === true,
  })
}

export function assertLivePlannedAuthorization(planned) {
  if (!planned?.attestation?.operator_id || planned?.authorization_gate?.attest_authorized !== true) {
    throw new Error('live acquisition plan is missing its sealed authorization attestation')
  }
  if (
    planned.target_class === 'PRODUCTION'
    && planned.authorization_gate.acknowledge_production !== true
  ) {
    throw new Error('live acquisition plan is missing its sealed PRODUCTION acknowledgment')
  }
  if (
    planned.target_class === 'THIRD_PARTY'
    && planned.authorization_gate.acknowledge_third_party !== true
  ) {
    throw new Error('live acquisition plan is missing its sealed THIRD_PARTY acknowledgment')
  }
  return planned
}

export async function probeRequiredClis(operations, { env, resolver, label }) {
  const cliOptions = resolver ? { resolver } : {}
  const dependencies = []
  for (const cli of requiredCli(operations)) {
    const probe = await probeCli(cli, { versionArgs: ['version'], env, ...cliOptions })
    if (!probe.present) {
      throw new Error(
        `${label} acquisition needs ${cli} on PATH and it is absent (${probe.reason})`,
      )
    }
    dependencies.push({
      name: cli,
      version: probe.version,
      invocation: probe.invocation,
    })
  }
  return dependencies
}

export function liveExecutionProfile({ adapterId, adapterVersion, operations, dependencies, limits }) {
  return {
    adapter_id: adapterId,
    adapter_version: adapterVersion,
    command_policy: 'readonly-allowlist-v1',
    process_supervision: process.platform === 'win32' ? 'WINDOWS_JOB_OBJECT' : 'POSIX_PROCESS_GROUP',
    dependencies,
    commands: operations.map(({ operation_id: operationId, cli, args, objects }) => ({
      operation_id: operationId,
      cli,
      args,
      estimated_objects: objects,
    })),
    limits: { ...limits },
  }
}

export function assertLiveExecutionProfile(planned, current) {
  if (JSON.stringify(planned?.execution_profile) !== JSON.stringify(current)) {
    throw new Error('live adapter execution profile or executable identity no longer matches the immutable plan')
  }
}

export function resolverForProbedDependencies(dependencies) {
  const byName = new Map(dependencies.map((dependency) => [dependency.name, dependency.invocation]))
  return (name, args) => {
    const invocation = byName.get(name)
    if (typeof invocation?.file !== 'string' || invocation.file === ''
      || !Array.isArray(invocation.argument_prefix)
      || invocation.argument_prefix.some((argument) => typeof argument !== 'string')) {
      throw new Error(`no validated executable invocation is bound for ${name}`)
    }
    return { file: invocation.file, args: [...invocation.argument_prefix, ...args] }
  }
}

export function createCollectionObjectObserver(maxObjects) {
  if (!Number.isSafeInteger(maxObjects) || maxObjects < 0) {
    throw new RangeError('collection object cap must be a non-negative safe integer')
  }
  let depth = 0
  let inString = false
  let escaped = false
  let stringValue = ''
  let lastString = null
  let pendingKey = null
  let targetDepth = null
  let expectingElement = false
  let count = 0

  const countElement = () => {
    if (targetDepth === null || depth !== targetDepth || !expectingElement) return
    count += 1
    expectingElement = false
    if (count > maxObjects) {
      throw new ImpactCapExceededError('objects_touched', count, maxObjects)
    }
  }

  return (chunk) => {
    for (const character of Buffer.from(chunk).toString('utf8')) {
      if (inString) {
        if (escaped) {
          escaped = false
          continue
        }
        if (character === '\\') {
          escaped = true
          continue
        }
        if (character === '"') {
          inString = false
          lastString = stringValue
        } else {
          stringValue += character
        }
        continue
      }
      if (/\s/.test(character)) continue
      if (character === '"') {
        countElement()
        inString = true
        escaped = false
        stringValue = ''
        continue
      }
      if (character === ':') {
        pendingKey = lastString
        lastString = null
        continue
      }
      if (character === '[') {
        countElement()
        depth += 1
        if (targetDepth === null && (pendingKey === 'items' || pendingKey === 'records')) {
          targetDepth = depth
          expectingElement = true
        }
        pendingKey = null
        continue
      }
      if (character === '{') {
        countElement()
        depth += 1
        pendingKey = null
        continue
      }
      if (character === ']') {
        if (targetDepth === depth) {
          targetDepth = null
          expectingElement = false
        }
        depth -= 1
        pendingKey = null
        continue
      }
      if (character === '}') {
        depth -= 1
        pendingKey = null
        continue
      }
      if (character === ',') {
        if (targetDepth === depth) expectingElement = true
        pendingKey = null
        lastString = null
        continue
      }
      countElement()
      pendingKey = null
      lastString = null
    }
    return count
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
  observeCollectionObjects = false,
}) {
  assertLivePlannedAuthorization(planned)
  const cliLimits = validateCliLimits(limits)
  const cliOptions = resolver ? { resolver } : {}
  const counters = new ImpactCounters({
    maxCommands: cliLimits.maxCommands,
    maxObjects: cliLimits.maxObjects,
    maxBytes: cliLimits.maxTotalOutputBytes,
  })
  const payload = []
  const gaps = []
  const executed = []
  let acquired = 0
  const verifiedIdentityByCli = new Map(
    (planned.execution_profile?.dependencies ?? [])
      .map((dependency) => [dependency.name, dependency.invocation?.identity]),
  )

  for (const [index, operation] of planned.operations.entries()) {
    // The payload prefix is the operation's position, not its ID: two
    // `k8s.resource` reads of different objects are a legitimate plan and would
    // otherwise collide on one path.
    const prefix = String(index).padStart(2, '0')
    if (await shouldStop?.()) {
      gaps.push({ area: 'acquisition', reason: 'stopped by the operator before this operation' })
      break
    }

    let approved
    try {
      approved = buildReadOnlyCommand(operation.operation_id, operation.params)
    } catch (error) {
      gaps.push({
        area: operation.operation_id,
        reason: `sealed operation is no longer allowlisted: ${redactForLog(String(error.message)).slice(0, 400)}`,
      })
      break
    }
    if (approved.cli !== operation.cli
      || approved.objects !== operation.objects
      || JSON.stringify(approved.args) !== JSON.stringify(operation.args)) {
      gaps.push({
        area: operation.operation_id,
        reason: 'sealed operation command does not match the immutable read-only allowlist',
      })
      break
    }

    try {
      counters.assertCanRecord({ objects: operation.objects })
    } catch (error) {
      gaps.push({
        area: operation.operation_id,
        reason: error instanceof ImpactCapExceededError
          ? `acquisition halted before an estimated-object impact cap: ${error.message}`
          : `operation accounting failed: ${redactForLog(String(error.message)).slice(0, 400)}`,
      })
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
        verifiedInvocationIdentity: verifiedIdentityByCli.get(operation.cli),
        ...(observeCollectionObjects
          ? {
              stdoutObserver: createCollectionObjectObserver(
                counters.caps.objects_touched - counters.counters.objects_touched,
              ),
            }
          : {}),
        ...cliOptions,
      })
    } catch (error) {
      // A cap is a halt, not a crash: what was already acquired stays, and the
      // stopping point is named.
      if (error instanceof ImpactCapExceededError && error.command_dispatched === true) {
        executed.push({
          index,
          operation_id: operation.operation_id,
          payload_prefix: prefix,
          exit_code: null,
          failure_code: 'IMPACT_CAP_EXCEEDED',
          outcome: 'IMPACT_CAP_EXCEEDED',
          supervision_mode: error.supervision_mode,
          termination_confirmed: error.termination_confirmed === true,
          estimated_objects: operation.objects,
          objects: error.dimension === 'objects_touched'
            ? error.value
            : 0,
          impact_dimension: error.dimension,
          operation_cap: error.cap,
          observed_value: error.value,
        })
      }
      gaps.push({
        area: operation.operation_id,
        reason: error instanceof ImpactCapExceededError
          ? `acquisition halted at an impact cap: ${error.message}`
          : `operation failed: ${redactForLog(String(error.message)).slice(0, 400)}`,
      })
      break
    }

    const execution = {
      index,
      operation_id: operation.operation_id,
      payload_prefix: prefix,
      exit_code: result.code,
      supervision_mode: result.supervision_mode,
      termination_confirmed: result.termination_confirmed,
      estimated_objects: operation.objects,
      objects: 0,
    }
    executed.push(execution)
    if (result.code !== 0) {
      gaps.push({
        area: operation.operation_id,
        reason: result.termination_confirmed === false
          ? `${result.supervision_mode} cleanup was not confirmed; provider stderr withheld from evidence`
          : `exited ${result.code}; provider stderr withheld from evidence`,
      })
      continue
    }

    const captured = capture(operation, result, planned.phi_policy, prefix)
    const observedObjects = captured.acquired ?? 0
    execution.objects = observedObjects
    try {
      counters.record({ objects: observedObjects }).assertWithinCaps()
    } catch (error) {
      gaps.push({
        area: operation.operation_id,
        reason: error instanceof ImpactCapExceededError
          ? `acquisition halted at an observed-object impact cap: ${error.message}`
          : `operation accounting failed: ${redactForLog(String(error.message)).slice(0, 400)}`,
      })
      break
    }
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
