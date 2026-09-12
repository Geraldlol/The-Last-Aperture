import { createHash } from 'node:crypto'
import { compareCanonicalStrings } from '../canonical-order.mjs'
import { writeEvidenceBundle } from '../evidence-bundle.mjs'
import {
  ImpactCounters,
  probeCli,
  runBoundedCli,
  validateCliLimits,
} from '../evidence-cli-runner.mjs'
import {
  parsePinnedImageReference,
  redactForLog,
  resolveCredentialReference,
  sealCredentialRef,
} from '../evidence-image-reference.mjs'
import {
  createTarArchive,
  DEFAULT_NORMALIZER_LIMITS,
  normalizeOciArchive,
  validateNormalizerLimits,
} from '../oci-normalizer.mjs'
import { buildArtifactPayload, DEFAULT_ARTIFACT_LIMITS, validateArtifactLimits } from './artifact.mjs'

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

function resolvedCredential(value, fallbackEnv, { requireExplicitSecrets = false } = {}) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('credential resolver must return an object with an environment')
  }
  const environment = value.env
  if (environment === null || typeof environment !== 'object' || Array.isArray(environment)) {
    throw new Error('credential resolver returned an invalid environment')
  }
  const secrets = value.secret_values
  if (requireExplicitSecrets && (!Array.isArray(secrets) || secrets.length === 0)) {
    throw new Error('credential resolver must return non-empty secret_values for non-environment credentials')
  }
  if (!Array.isArray(secrets) || secrets.some((secret) => typeof secret !== 'string')) {
    throw new Error('credential resolver returned invalid secret_values')
  }
  const changedEnvironmentValues = Object.entries(environment)
    .filter(([key, value]) => typeof value === 'string' && value !== '' && fallbackEnv?.[key] !== value)
    .map(([, value]) => value)
  return {
    environment: { ...environment },
    secrets: [...new Set([...secrets, ...changedEnvironmentValues].filter((secret) => secret !== ''))],
  }
}

function redactCredentialValues(value, secrets) {
  let text = redactForLog(value)
  for (const secret of secrets) text = text.replaceAll(secret, '[REDACTED]')
  return text
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex')
}

function canonicalBlobReference(imageReference, digest) {
  return `${imageReference.slice(0, imageReference.lastIndexOf('@'))}@${digest}`
}

function assertDescriptorShape(descriptor, label) {
  const match = /^sha256:([0-9a-f]{64})$/.exec(String(descriptor?.digest ?? ''))
  if (!match) throw new Error(`${label} has no supported canonical sha256 digest`)
  if (!Number.isSafeInteger(descriptor.size) || descriptor.size < 0) {
    throw new Error(`${label} has no valid byte size`)
  }
  return match[1]
}

function assertDescriptorBytes(bytes, descriptor, label) {
  const digest = assertDescriptorShape(descriptor, label)
  if (bytes.length !== descriptor.size || sha256(bytes) !== digest) {
    throw new Error(`${label} bytes do not match their declared size and sha256 digest`)
  }
}

function manifestMediaType(document) {
  if (typeof document?.mediaType === 'string' && document.mediaType !== '') return document.mediaType
  return Array.isArray(document?.manifests)
    ? 'application/vnd.oci.image.index.v1+json'
    : 'application/vnd.oci.image.manifest.v1+json'
}

function registryExecutionProfile(pinned, probe, cliLimits, normalizerLimits) {
  return {
    adapter_id: 'registry',
    adapter_version: ADAPTER_VERSION,
    command_protocol: 'crane-content-addressed-read-v1',
    process_supervision: process.platform === 'win32' ? 'WINDOWS_JOB_OBJECT' : 'POSIX_PROCESS_GROUP',
    dependency: {
      name: 'crane',
      version: probe.version,
      invocation: probe.invocation,
    },
    initial_command: {
      cli: 'crane',
      args: ['manifest', pinned.canonical],
    },
    descriptor_commands: {
      manifest: {
        cli: 'crane',
        verb: 'manifest',
        reference: 'same-repository@descriptor-sha256',
        require_declared_size: true,
        require_sha256_match: true,
      },
      blob: {
        cli: 'crane',
        verb: 'blob',
        reference: 'same-repository@descriptor-sha256',
        require_declared_size: true,
        require_sha256_match: true,
      },
    },
    limits: {
      cli: { ...cliLimits },
      traversal: {
        maxEntries: normalizerLimits.maxEntries,
        maxProjectedBytes: normalizerLimits.maxProjectedBytes,
        maxManifests: normalizerLimits.maxManifests,
        maxLayers: normalizerLimits.maxLayers,
        maxEntryBytes: normalizerLimits.maxEntryBytes,
        maxTotalBytes: normalizerLimits.maxTotalBytes,
        maxArchiveBytes: normalizerLimits.maxArchiveBytes,
        maxInflatedBytes: normalizerLimits.maxInflatedBytes,
        maxMetadataItems: normalizerLimits.maxMetadataItems,
        maxMetadataBytes: normalizerLimits.maxMetadataBytes,
        maxCapturedEntryBytes: normalizerLimits.maxCapturedEntryBytes,
        maxCapturedBytes: normalizerLimits.maxCapturedBytes,
        maxCapturedFiles: normalizerLimits.maxCapturedFiles,
      },
    },
  }
}

export function createRegistryAdapter({
  clock = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
  env = process.env,
  resolver,
  credentialResolver,
  limits = {},
} = {}) {
  const cliLimits = validateCliLimits(limits)
  const normalizerLimits = validateArtifactLimits({
    ...DEFAULT_ARTIFACT_LIMITS,
    ...validateNormalizerLimits({ ...DEFAULT_NORMALIZER_LIMITS, ...limits }),
    ...limits,
  })
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
        execution_profile: registryExecutionProfile(pinned, probe, cliLimits, normalizerLimits),
      }
    },

    run: async (planned, { out, shouldStop }) => {
      const sealed = sealCredentialRef(planned.credential_ref)
      const pinned = parsePinnedImageReference(planned.image_reference)
      if (planned.evidence_context_seed?.target_identity !== pinned.digest) {
        throw new Error('registry plan target identity does not match its digest-pinned image reference')
      }
      const expectedInvocationIdentity = planned.execution_profile?.dependency?.invocation?.identity
      if (expectedInvocationIdentity === undefined) {
        throw new Error('registry plan has no bounded executable identity')
      }
      const currentProbe = await probeCli('crane', {
        versionArgs: ['version'],
        env,
        expectedInvocationIdentity,
        ...cliOptions,
      })
      if (!currentProbe.present
        || JSON.stringify(planned.execution_profile)
          !== JSON.stringify(registryExecutionProfile(pinned, currentProbe, cliLimits, normalizerLimits))) {
        throw new Error('registry executable identity or execution profile no longer matches the immutable plan')
      }
      const boundCraneResolver = (_name, args) => ({
        file: currentProbe.invocation.file,
        args: [...currentProbe.invocation.argument_prefix, ...args],
      })
      const counters = new ImpactCounters({
        maxCommands: cliLimits.maxCommands,
        maxObjects: cliLimits.maxObjects,
        maxBytes: cliLimits.maxTotalOutputBytes,
      })
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
      const failureBundle = (error, secrets = []) => {
        const impact = counters.snapshot()
        if (error?.dimension) {
          impact.halt = { dimension: error.dimension, value: error.value, cap: error.cap }
        }
        return writeEvidenceBundle({
          directory: out,
          profile: {
            ...baseProfile,
            coverage_state: 'NOT_ASSESSED',
            artifact_kind: 'oci-image',
            coverage_gaps: [{
              area: 'registry pull',
              reason: redactCredentialValues(error.message, secrets).slice(0, 480),
            }],
          },
          payload: [{
            path: 'impact-counters.json',
            bytes: Buffer.from(JSON.stringify(impact, null, 2), 'utf8'),
          }],
        })
      }
      let credentialResult
      try {
        credentialResult = await resolveCredentialReference(sealed.credential_ref, {
          env,
          resolver: credentialResolver === undefined
            ? undefined
            : (reference, context) => credentialResolver(reference, {
                ...context,
                imageReference: planned.image_reference,
              }),
        })
      } catch {
        return failureBundle(new Error(`credential reference ${sealed.credential_ref} could not be resolved`))
      }
      let credential
      try {
        credential = resolvedCredential(credentialResult, env, {
          requireExplicitSecrets: !sealed.credential_ref.startsWith('env:'),
        })
      } catch {
        return failureBundle(new Error(
          `credential reference ${sealed.credential_ref} returned no usable redaction material`,
        ))
      }

      const blobs = new Map()
      const runCraneRead = async (args, label, maxStdoutBytes) => {
        if (await shouldStop?.()) throw new Error('registry acquisition stopped by the operator')
        if (!Number.isSafeInteger(maxStdoutBytes) || maxStdoutBytes < 0) {
          throw new RangeError(`${label} has no valid bounded read limit`)
        }
        counters.assertCanRecord({ commands: 1, objects: 1 })
        const result = await runBoundedCli({
          name: 'crane',
          args,
          limits: {
            ...cliLimits,
            maxStdoutBytes: Math.min(cliLimits.maxStdoutBytes, maxStdoutBytes),
          },
          env: credential.environment,
          counters,
          resolver: boundCraneResolver,
          verifiedInvocationIdentity: currentProbe.invocation.identity,
          // Record the object at the same boundary where the runner records
          // its command, after resolver and identity checks but before spawn.
          beforeDispatch: () => counters.record({ objects: 1 }),
        })
        if (result.termination_confirmed === false) {
          throw new Error(`${label} ${result.supervision_mode} cleanup was not confirmed`)
        }
        if (result.code !== 0) {
          // CLI stderr is an untrusted exfiltration channel. Exact known
          // credential values can be redacted, but the child inherits other
          // environment values and may echo one whose secret status this
          // controller cannot classify. Persist only the structured failure.
          throw new Error(`${label} exited ${result.code}; provider stderr withheld from evidence`)
        }
        return result.stdout
      }

      let topDocument
      try {
        let manifestCount = 0
        let layerCount = 0
        const visitManifest = async (descriptor, reference) => {
          if (manifestCount >= normalizerLimits.maxManifests) return
          assertDescriptorShape(descriptor, 'manifest descriptor')
          if (descriptor.size > normalizerLimits.maxEntryBytes) {
            throw new RangeError(
              `manifest descriptor is ${descriptor.size} bytes, above the bounded JSON limit of `
              + `${normalizerLimits.maxEntryBytes} bytes`,
            )
          }
          manifestCount += 1
          let bytes = blobs.get(descriptor.digest)
          if (!bytes) {
            bytes = await runCraneRead(
              ['manifest', reference],
              'crane manifest',
              descriptor.size,
            )
            assertDescriptorBytes(bytes, descriptor, `manifest ${descriptor.digest}`)
            blobs.set(descriptor.digest, bytes)
          }
          let document
          try {
            document = JSON.parse(bytes.toString('utf8'))
          } catch {
            throw new Error(`manifest ${descriptor.digest} is not valid JSON`)
          }
          if (Array.isArray(document.manifests)) {
            for (const child of document.manifests) {
              if (manifestCount >= normalizerLimits.maxManifests) break
              await visitManifest(
                child,
                canonicalBlobReference(planned.image_reference, child.digest),
              )
            }
            return document
          }
          if (!Array.isArray(document.layers) || !document.config) {
            throw new Error(`manifest ${descriptor.digest} is neither an image manifest nor an index`)
          }
          const fetchBlob = async (child, label, maxBytes) => {
            assertDescriptorShape(child, label)
            if (child.size > maxBytes) {
              throw new RangeError(
                `${label} is ${child.size} bytes, above its bounded read limit of ${maxBytes} bytes`,
              )
            }
            if (blobs.has(child.digest)) return
            const childBytes = await runCraneRead(
              ['blob', canonicalBlobReference(planned.image_reference, child.digest)],
              `crane blob ${label}`,
              child.size,
            )
            assertDescriptorBytes(childBytes, child, label)
            blobs.set(child.digest, childBytes)
          }
          await fetchBlob(
            document.config,
            `image config ${document.config.digest}`,
            normalizerLimits.maxEntryBytes,
          )
          for (const layer of document.layers) {
            if (layerCount >= normalizerLimits.maxLayers) break
            layerCount += 1
            await fetchBlob(
              layer,
              `layer ${layer.digest}`,
              Math.min(normalizerLimits.maxArchiveBytes, normalizerLimits.maxTotalBytes),
            )
          }
          return document
        }

        const topBytes = await runCraneRead(
          ['manifest', planned.image_reference],
          'crane manifest',
          normalizerLimits.maxEntryBytes,
        )
        const topDescriptor = {
          digest: pinned.digest,
          size: topBytes.length,
        }
        assertDescriptorBytes(topBytes, topDescriptor, 'requested manifest')
        blobs.set(pinned.digest, topBytes)
        topDocument = await visitManifest(topDescriptor, planned.image_reference)
      } catch (error) {
        return failureBundle(error, credential.secrets)
      }

      const index = Buffer.from(JSON.stringify({
        schemaVersion: 2,
        manifests: [{
          mediaType: manifestMediaType(topDocument),
          digest: pinned.digest,
          size: blobs.get(pinned.digest).length,
        }],
      }), 'utf8')
      const archiveFiles = [
        {
          path: 'oci-layout',
          bytes: Buffer.from(JSON.stringify({ imageLayoutVersion: '1.0.0' }), 'utf8'),
        },
        { path: 'index.json', bytes: index },
        ...[...blobs]
          .sort(([left], [right]) => compareCanonicalStrings(left, right))
          .map(([digest, blob]) => ({ path: `blobs/sha256/${digest.slice(7)}`, bytes: blob })),
      ]
      let bytes
      try {
        bytes = createTarArchive(archiveFiles, { maxBytes: normalizerLimits.maxArchiveBytes })
      } catch (error) {
        return failureBundle(error, credential.secrets)
      }
      const { archive, normalized, resource_budget: resourceBudget } = normalizeOciArchive(bytes, normalizerLimits)
      const { payload, gaps } = buildArtifactPayload(
        archive ?? Buffer.alloc(0),
        normalized,
        normalizerLimits,
        resourceBudget,
      )
      payload.push({
        path: 'impact-counters.json',
        bytes: Buffer.from(JSON.stringify(counters.snapshot(), null, 2), 'utf8'),
      })

      return writeEvidenceBundle({
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
    },
  }
}
