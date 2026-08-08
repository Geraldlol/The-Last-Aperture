import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { writeEvidenceBundle } from '../evidence-bundle.mjs'
import {
  DEFAULT_CLI_LIMITS,
  ImpactCounters,
  probeCli,
  runBoundedCli,
} from '../evidence-cli-runner.mjs'
import {
  parsePinnedImageReference,
  redactForLog,
  sealCredentialRef,
} from '../evidence-image-reference.mjs'
import { DEFAULT_NORMALIZER_LIMITS, normalizeOciLayout } from '../oci-normalizer.mjs'
import { buildArtifactPayload, DEFAULT_ARTIFACT_LIMITS } from './artifact.mjs'

const ADAPTER_VERSION = '1.0.0'

const CAPABILITIES = Object.freeze({
  'target-identity': 'NATIVE',
  'content-enumeration': 'NATIVE',
  'content-retrieval': 'NATIVE',
  'layer-or-revision-history': 'NATIVE',
  'metadata-provenance': 'NATIVE',
  'deletion-recoverability': 'NATIVE',
  'effective-configuration': 'EXTERNAL_ONLY',
  'principal-and-permission-state': 'EXTERNAL_ONLY',
  'secret-material-surface': 'NATIVE',
  'impact-accounting': 'NATIVE',
})

export function createRegistryAdapter({
  clock = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
  env = process.env,
  resolver,
  limits = {},
} = {}) {
  const cliLimits = { ...DEFAULT_CLI_LIMITS, ...limits }
  const normalizerLimits = { ...DEFAULT_ARTIFACT_LIMITS, ...DEFAULT_NORMALIZER_LIMITS, ...limits }
  const cliOptions = resolver ? { resolver } : {}

  return {
    describe: () => ({
      adapter_id: 'registry',
      evidence_class: 'built-artifact',
      adapter_version: ADAPTER_VERSION,
      capabilities: { ...CAPABILITIES },
      external_dependency: 'crane|docker',
    }),

    plan: async (request) => {
      // built-artifact via registry sits above its class floor: the pull leaves
      // this machine, so attestation is required where the offline artifact
      // adapter needs none.
      if (request.attest_authorized !== true) {
        throw new Error('registry acquisition requires --attest-authorized')
      }
      const pinned = parsePinnedImageReference(request.image)
      const sealed = sealCredentialRef(request.credential_ref)

      // The probe happens at plan time, not run time. A missing CLI must fail
      // where an operator is watching, not later as an empty success.
      const probe = await probeCli('crane', { versionArgs: ['version'], env, ...cliOptions })
      if (!probe.present) {
        throw new Error(
          `registry acquisition needs crane on PATH and it is absent (${probe.reason}); `
          + 'install it or use the artifact adapter against a docker save export',
        )
      }

      return {
        plan_id: `registry:${pinned.digest.slice(7, 23)}`,
        image_reference: pinned.canonical,
        credential_ref: sealed.credential_ref,
        evidence_context_seed: {
          evidence_id: request.evidence_id,
          evidence_class: 'built-artifact',
          adapter_id: 'registry',
          target_identity: pinned.digest,
          acquisition_mode: 'registry-pull',
          detection_evidence: [`${pinned.registry}/${pinned.repository} pinned at ${pinned.digest}`],
          confidence: 'high',
        },
        attestation: {
          operator_id: request.operator_id,
          authorized_by: request.authorized_by,
          authorization_reference: request.authorization_reference,
          attested_on: clock(),
          credential_ref: sealed.credential_ref,
        },
        target_class: request.target_class ?? 'NONPROD',
        phi_scope: request.phi_scope ?? 'none',
        dependency: { name: 'crane', present: true, version: probe.version },
      }
    },

    run: async (planned, { out }) => {
      const counters = new ImpactCounters({
        maxCommands: cliLimits.maxCommands,
        maxObjects: cliLimits.maxObjects,
        maxBytes: cliLimits.maxStdoutBytes,
      })
      const scratch = await mkdtemp(join(tmpdir(), 'rta-registry-pull-'))
      const target = join(scratch, 'image.tar')

      const baseProfile = {
        schema: 'evidence-bundle-v1',
        evidence_context: { ...planned.evidence_context_seed, acquired_on: clock() },
        target_class: planned.target_class,
        phi_scope: planned.phi_scope,
        phi_bearing: false,
        adapter_version: ADAPTER_VERSION,
        contract_version: 1,
        attestation: planned.attestation,
      }

      try {
        const result = await runBoundedCli({
          name: 'crane',
          args: ['pull', '--format', 'oci', planned.image_reference, target],
          limits: cliLimits,
          env,
          counters,
          ...cliOptions,
        })
        if (result.code !== 0) {
          // A failed pull is NOT_ASSESSED with a named reason. It is never an
          // empty COVERED, and the reason is redacted before it is recorded.
          return await writeEvidenceBundle({
            directory: out,
            profile: {
              ...baseProfile,
              coverage_state: 'NOT_ASSESSED',
              artifact_kind: 'oci-image',
              coverage_gaps: [{
                area: 'registry pull',
                reason: `crane pull exited ${result.code}: ${redactForLog(result.stderr).slice(0, 480)}`,
              }],
            },
            payload: [],
          })
        }

        const bytes = await readFile(target)
        counters.record({ bytes: bytes.length, objects: 1 }).assertWithinCaps()
        const normalized = normalizeOciLayout(bytes, normalizerLimits)
        const { payload, gaps } = buildArtifactPayload(bytes, normalized, normalizerLimits)
        payload.push({
          path: 'impact-counters.json',
          bytes: Buffer.from(JSON.stringify(counters.snapshot(), null, 2), 'utf8'),
        })

        return await writeEvidenceBundle({
          directory: out,
          profile: {
            ...baseProfile,
            coverage_state: normalized.layers.length === 0
              ? 'NOT_ASSESSED'
              : gaps.length > 0 ? 'PARTIAL' : 'COVERED',
            artifact_kind: 'oci-image',
            coverage_gaps: normalized.layers.length === 0 && gaps.length === 0
              ? [{ area: 'image', reason: 'the pulled archive carried no readable layer' }]
              : gaps,
          },
          payload,
        })
      } finally {
        await rm(scratch, { recursive: true, force: true })
      }
    },
  }
}
