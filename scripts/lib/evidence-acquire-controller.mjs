import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join, resolve } from 'node:path'
import { resolveEvidenceAdapter } from './evidence-adapters.mjs'
import { readEvidenceBundle, verifyEvidenceBundle } from './evidence-bundle.mjs'
import { createArtifactAdapter } from './evidence-adapters/artifact.mjs'
import { createRegistryAdapter } from './evidence-adapters/registry.mjs'
import { createDeployedAdapter } from './evidence-adapters/deployed.mjs'
import { createRuntimeAdapter } from './evidence-adapters/runtime.mjs'

const PLAN_FILE = 'acquisition-plan.json'

// One factory per canonical adapter. An adapter that is not registered cannot
// be planned, which is what keeps the routing table and the code from drifting.
const ADAPTER_FACTORIES = new Map([
  ['artifact', createArtifactAdapter],
  ['registry', createRegistryAdapter],
  ['deployed', createDeployedAdapter],
  ['runtime', createRuntimeAdapter],
])

export class AcquisitionError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'AcquisitionError'
    this.code = code
  }
}

async function readPlanFile(bundle) {
  const path = join(resolve(bundle), PLAN_FILE)
  try {
    return JSON.parse(await readFile(path, 'utf8'))
  } catch {
    throw new AcquisitionError('ACQUISITION_PLAN_MISSING', `no acquisition plan at ${path}`)
  }
}

async function writePlanFile(bundle, record) {
  await mkdir(resolve(bundle), { recursive: true })
  await writeFile(
    join(resolve(bundle), PLAN_FILE),
    `${JSON.stringify(record, null, 2)}\n`,
    'utf8',
  )
  return record
}

export async function isAcquisitionStopped(bundle) {
  try {
    return (await readPlanFile(bundle)).state === 'STOPPED'
  } catch {
    return false
  }
}

export async function planAcquisition({ adapterId, request, out, env = process.env, resolver }) {
  const routed = resolveEvidenceAdapter(adapterId)
  if (routed.selection_status !== 'SELECTED') {
    throw new AcquisitionError(
      'ACQUISITION_ADAPTER_UNKNOWN',
      `unknown adapter "${adapterId}"; an unlisted acquisition target selects `
      + 'inventory-only and cannot be planned',
    )
  }
  const factory = ADAPTER_FACTORIES.get(adapterId)
  if (!factory) {
    throw new AcquisitionError(
      'ACQUISITION_ADAPTER_UNIMPLEMENTED',
      `adapter "${adapterId}" is declared in the routing manifest but not implemented`,
    )
  }
  const adapter = factory({ env, resolver })
  const plan = await adapter.plan(request)
  const directory = resolve(out)
  await writePlanFile(directory, {
    schema: 'evidence-acquisition-plan-v1',
    adapter_id: adapterId,
    evidence_class: routed.evidence_class,
    state: 'PLANNED',
    plan,
  })
  return { directory, plan }
}

export async function runAcquisition({
  bundle,
  operatorId,
  authorizationConfirmed = false,
  env = process.env,
  resolver,
}) {
  const directory = resolve(bundle)
  const record = await readPlanFile(directory)
  if (record.state === 'STOPPED') {
    throw new AcquisitionError('ACQUISITION_STOPPED', 'this acquisition was stopped and cannot run')
  }
  if (record.state === 'ACQUIRED') {
    throw new AcquisitionError(
      'ACQUISITION_ALREADY_RUN',
      'this plan already produced a bundle; re-acquiring writes a new bundle, not this one',
    )
  }
  const routed = resolveEvidenceAdapter(record.adapter_id)
  if (routed.authorization.operator_identity && !operatorId) {
    throw new AcquisitionError('ACQUISITION_OPERATOR_REQUIRED', 'this class requires a named operator')
  }
  if (routed.authorization.attestation && authorizationConfirmed !== true) {
    throw new AcquisitionError(
      'ACQUISITION_AUTHORIZATION_REQUIRED',
      'this class requires --confirm-authorization-current at run time',
    )
  }
  if (record.plan.target_class === 'THIRD_PARTY') {
    const gate = record.plan.authorization_gate
    if (
      gate?.mode !== 'INTERIM_OPERATOR_ACKNOWLEDGED_THIRD_PARTY'
      || gate.acknowledge_third_party !== true
    ) {
      throw new AcquisitionError(
        'ACQUISITION_THIRD_PARTY_PLAN_ACKNOWLEDGMENT_MISSING',
        'THIRD_PARTY acquisition plan is missing its exact sealed interim acknowledgment',
      )
    }
  }

  const adapter = ADAPTER_FACTORIES.get(record.adapter_id)({ env, resolver })
  const written = await adapter.run(record.plan, {
    out: directory,
    authorizationConfirmed,
    shouldStop: () => isAcquisitionStopped(directory),
  })
  await writePlanFile(directory, {
    ...record,
    state: 'ACQUIRED',
    operator_id: operatorId ?? null,
    root_sha256: written.root_sha256,
    ...(record.plan.authorization_gate
      ? {
          run_authorization: {
            mode: record.plan.authorization_gate.mode,
            current_authorization_confirmed: authorizationConfirmed === true,
            third_party_acknowledged:
              record.plan.authorization_gate.acknowledge_third_party === true,
            confirmed_by: operatorId ?? null,
          },
        }
      : {}),
  })
  return written
}

export async function validateAcquisition(bundle) {
  const verification = await verifyEvidenceBundle(bundle)
  return { path: resolve(bundle), ...verification }
}

export async function finalizeAcquisition(bundle) {
  const verification = await verifyEvidenceBundle(bundle)
  if (!verification.valid) {
    throw new AcquisitionError(
      'ACQUISITION_INVALID',
      'the bundle did not verify; finalize refuses evidence of uncertain provenance',
    )
  }
  const record = await readPlanFile(bundle)
  const read = await readEvidenceBundle(bundle)
  return {
    directory: resolve(bundle),
    state: record.state,
    evidence_id: read.evidence_context.evidence_id,
    evidence_class: read.evidence_context.evidence_class,
    coverage_state: read.profile.coverage_state,
    root_sha256: read.root_sha256,
  }
}

// Idempotent, and deliberately requires no still-valid authority artifact:
// the one command an operator needs during an incident must not itself depend
// on the thing that may have gone wrong.
export async function requestAcquisitionStop({ bundle, operatorId, reason }) {
  const directory = resolve(bundle)
  let record
  try {
    record = await readPlanFile(directory)
  } catch {
    record = { schema: 'evidence-acquisition-plan-v1', adapter_id: null, plan: null }
  }
  return writePlanFile(directory, {
    ...record,
    state: 'STOPPED',
    stopped_by: operatorId,
    stop_reason: reason,
  })
}
