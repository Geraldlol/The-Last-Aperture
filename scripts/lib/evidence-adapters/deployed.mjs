import { redactToMetadata } from '../evidence-phi.mjs'
import { buildReadOnlyCommand } from '../evidence-readonly-allowlist.mjs'
import {
  assertLivePlanAuthorization,
  probeRequiredClis,
  requiredCli,
  runLiveAcquisition,
} from './live-acquisition.mjs'

const ADAPTER_VERSION = '1.0.0'

const CAPABILITIES = Object.freeze({
  'target-identity': 'COMPOSABLE',
  'content-enumeration': 'NATIVE',
  'content-retrieval': 'NATIVE',
  'layer-or-revision-history': 'UNSUPPORTED',
  'metadata-provenance': 'COMPOSABLE',
  'deletion-recoverability': 'UNSUPPORTED',
  'effective-configuration': 'NATIVE',
  'principal-and-permission-state': 'NATIVE',
  'secret-material-surface': 'NATIVE',
  'impact-accounting': 'NATIVE',
})

export function createDeployedAdapter({
  clock = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
  env = process.env,
  resolver,
  limits = {},
} = {}) {
  return {
    describe: () => ({
      adapter_id: 'deployed',
      evidence_class: 'deployed-state',
      adapter_version: ADAPTER_VERSION,
      capabilities: { ...CAPABILITIES },
      external_dependency: 'kubectl|sf|cloud-cli',
    }),

    plan: async (request) => {
      const phi = assertLivePlanAuthorization(request, 'deployed-state')

      // The allowlist builds every vector. An operation the table does not name
      // cannot be planned, so a mutating command is unconstructible.
      const operations = (request.operations ?? []).map(({ operation_id: id, params }) => ({
        ...buildReadOnlyCommand(id, params),
        params,
      }))
      if (operations.length === 0) throw new Error('at least one read-only operation is required')

      await probeRequiredClis(operations, { env, resolver, label: 'deployed-state' })

      return {
        plan_id: `deployed:${request.context}:${operations.length}`,
        context: request.context,
        operations,
        phi_policy: phi,
        acquired_on: clock(),
        evidence_context_seed: {
          evidence_id: request.evidence_id,
          evidence_class: 'deployed-state',
          adapter_id: 'deployed',
          target_identity: request.context,
          acquisition_mode: 'read-only-query',
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
      }
    },

    run: async (planned, { out, shouldStop }) => runLiveAcquisition({
      planned,
      out,
      env,
      resolver,
      limits,
      adapterVersion: ADAPTER_VERSION,
      shouldStop,
      capture: (operation, result, phiPolicy, prefix) => {
        let parsed
        try {
          parsed = JSON.parse(result.stdout.toString('utf8'))
        } catch (error) {
          return {
            gaps: [{
              area: operation.operation_id,
              reason: `could not parse output as JSON: ${error.message}; `
                + 'the raw output was not captured',
            }],
          }
        }
        const objects = Array.isArray(parsed?.items) ? parsed.items : [parsed]
        return {
          acquired: objects.length,
          payload: objects.map((object, index) => ({
            path: `objects/${prefix}/${index}.json`,
            bytes: Buffer.from(JSON.stringify(
              phiPolicy.capture_contents ? object : redactToMetadata(object),
              null,
              2,
            ), 'utf8'),
          })),
        }
      },
    }),
  }
}
