import { buildReadOnlyCommand } from '../evidence-readonly-allowlist.mjs'
import { validateCliLimits } from '../evidence-cli-runner.mjs'
import {
  assertLiveExecutionProfile,
  assertLivePlanAuthorization,
  liveExecutionProfile,
  probeRequiredClis,
  requiredCli,
  resolverForProbedDependencies,
  runLiveAcquisition,
} from './live-acquisition.mjs'

const ADAPTER_VERSION = '1.0.0'

const CAPABILITIES = Object.freeze({
  'target-identity': 'COMPOSABLE',
  'content-enumeration': 'COMPOSABLE',
  'content-retrieval': 'NATIVE',
  'layer-or-revision-history': 'UNSUPPORTED',
  'metadata-provenance': 'UNKNOWN',
  'deletion-recoverability': 'UNSUPPORTED',
  'effective-configuration': 'NATIVE',
  'principal-and-permission-state': 'COMPOSABLE',
  'secret-material-surface': 'NATIVE',
  'impact-accounting': 'NATIVE',
})

// Metadata-only for text output: the line shapes, with anything after the first
// `=` dropped. runtime.env-keys already returns key names only, so this is the
// second belt on the same trousers rather than the only one.
function summariseText(text) {
  return text
    .split(/\r?\n/)
    .filter((line) => line.trim() !== '')
    .map((line) => line.split('=')[0])
    .join('\n')
}

export function createRuntimeAdapter({
  clock = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
  env = process.env,
  resolver,
  limits = {},
} = {}) {
  const effectiveLimits = validateCliLimits(limits)
  return {
    describe: () => ({
      adapter_id: 'runtime',
      evidence_class: 'live-runtime',
      adapter_version: ADAPTER_VERSION,
      capabilities: { ...CAPABILITIES },
      external_dependency: 'kubectl',
    }),

    plan: async (request) => {
      const phi = assertLivePlanAuthorization(request, 'live-runtime')

      // Runtime inspection is bound to one named container. A cluster-wide
      // sweep is the deployed adapter's job and must not be reachable here.
      for (const { operation_id: id } of request.operations ?? []) {
        if (!String(id).startsWith('runtime.')) {
          throw new Error(`runtime acquisition accepts only runtime.* operations; received ${id}`)
        }
      }
      const operations = (request.operations ?? []).map(({ operation_id: id, params }) => {
        const boundParams = {
          ...params,
          namespace: request.namespace,
          pod: request.pod,
          container: request.container,
        }
        return {
          ...buildReadOnlyCommand(id, boundParams),
          params: boundParams,
        }
      })
      if (operations.length === 0) throw new Error('at least one read-only operation is required')

      const dependencies = await probeRequiredClis(operations, { env, resolver, label: 'live-runtime' })

      return {
        plan_id: `runtime:${request.namespace}/${request.pod}:${operations.length}`,
        context: request.context,
        operations,
        phi_policy: phi,
        acquired_on: clock(),
        evidence_context_seed: {
          evidence_id: request.evidence_id,
          evidence_class: 'live-runtime',
          adapter_id: 'runtime',
          target_identity: `${request.context}/${request.namespace}/${request.pod}/${request.container}`,
          acquisition_mode: 'read-only-inspection',
          detection_evidence: operations.map(({ operation_id: id, args }, index) =>
            `operation ${index}: ${id} ${args.join(' ')}`),
          confidence: 'high',
        },
        attestation: {
          operator_id: request.operator_id,
          authorized_by: request.authorized_by,
          authorization_reference: request.authorization_reference,
          attested_on: clock(),
        },
        authorization_gate: {
          mode: request.target_class === 'THIRD_PARTY'
            ? 'INTERIM_OPERATOR_ACKNOWLEDGED_THIRD_PARTY'
            : 'OPERATOR_ATTESTED',
          attest_authorized: true,
          acknowledge_production: request.acknowledge_production === true,
          acknowledge_third_party: request.acknowledge_third_party === true,
        },
        target_class: request.target_class,
        phi_scope: phi.scope,
        dependency: { name: requiredCli(operations).join('|'), present: true, version: null },
        execution_profile: liveExecutionProfile({
          adapterId: 'runtime',
          adapterVersion: ADAPTER_VERSION,
          operations,
          dependencies,
          limits: effectiveLimits,
        }),
      }
    },

    run: async (planned, { out, shouldStop, authorizationConfirmed = false }) => {
      // Attestation at plan time is not enough for this class: authorization can
      // lapse between planning and running, and this is the tier where that
      // difference has consequences.
      if (authorizationConfirmed !== true) {
        throw new Error(
          'live-runtime acquisition requires --confirm-authorization-current at run time',
        )
      }
      const dependencies = await probeRequiredClis(planned.operations, {
        env,
        resolver,
        label: 'live-runtime',
      })
      assertLiveExecutionProfile(planned, liveExecutionProfile({
        adapterId: 'runtime',
        adapterVersion: ADAPTER_VERSION,
        operations: planned.operations,
        dependencies,
        limits: effectiveLimits,
      }))
      return runLiveAcquisition({
        planned,
        out,
        env,
        resolver: resolverForProbedDependencies(dependencies),
        limits,
        adapterVersion: ADAPTER_VERSION,
        shouldStop,
        capture: (operation, result, phiPolicy, prefix) => {
          const text = result.stdout.toString('utf8')
          if (text.trim() === '') {
            return {
              gaps: [{
                area: operation.operation_id,
                reason: 'the command produced no output inside the container',
              }],
            }
          }
          return {
            acquired: 1,
            payload: [{
              path: `observations/${prefix}.txt`,
              bytes: Buffer.from(
                phiPolicy.capture_contents ? text : summariseText(text),
                'utf8',
              ),
            }],
          }
        },
      })
    },
  }
}
