#!/usr/bin/env node

import {
  createHash,
  createPrivateKey,
  createPublicKey,
  randomBytes,
  randomUUID,
  sign as signBytes,
  verify as verifyBytes,
} from 'node:crypto'
import { spawn } from 'node:child_process'
import { constants as fsConstants, existsSync } from 'node:fs'
import {
  lstat,
  link,
  mkdir,
  mkdtemp,
  open,
  realpath,
  rename,
  rm,
  unlink,
  writeFile,
} from 'node:fs/promises'
import { tmpdir } from 'node:os'
import {
  basename,
  dirname,
  isAbsolute,
  join,
  parse,
  relative,
  resolve,
  sep,
} from 'node:path'
import { fileURLToPath } from 'node:url'
import { TextDecoder } from 'node:util'
import {
  assertValidRun,
  assertValidRunTransition,
  finalizeFinding,
  parseContractTimestamp,
  validateRun,
} from './lib/contracts.mjs'
import { isMainModule } from './lib/main-module.mjs'
import {
  terminalSafeDocumentText,
  terminalSafeSerializedJson,
  terminalSafeText,
} from './lib/terminal-text.mjs'
import {
  assertLocalFilesystemEndpoint,
  assertNoRemoteFilesystemArguments,
} from './lib/filesystem-endpoint.mjs'
import { compareCanonicalStrings } from './lib/canonical-order.mjs'
import { sourcePathsForJob } from './lib/job-source-scope.mjs'
import { assertValidProofConfig, executeProof } from './lib/proof-execution.mjs'
import { materializeSealedFiles } from './lib/disposable-mirror.mjs'
import {
  cleanupDockerServiceProofContainers,
  normalizeProofWorkerConfig,
  proofSourceTreeDigest,
  proofWorkerConfigDigest,
  runDockerProofCommand,
  runDockerServiceProofCommand,
  serviceProofControllerBudget,
} from './lib/proof-docker-runner.mjs'
import { proofEvidence } from './lib/proof-evidence.mjs'
import {
  buildProofReceipt,
  findingWithProofEvidence,
  serviceProofAttemptReceiptBinding,
} from './lib/proof-receipt.mjs'
import {
  classifyProviderAttemptRecovery,
  classifyServiceProofAttemptRecovery,
  commitProviderAttempt,
  commitServiceProofAttempt,
  failProviderAttempt,
  failServiceProofAttempt,
  findActiveAttempt,
  findProviderAttempt,
  leaseProviderAttempt,
  leaseRemoteAttempt,
  leaseServiceProofAttempt,
  markProviderAttemptStarted,
  markServiceProofAttemptStarted,
  recordProviderResultCaptured,
  recordProviderResultValidated,
  recordServiceProofResultCaptured,
  recordServiceProofResultValidated,
  recoverExpiredServiceProofAttempt,
} from './lib/attempts.mjs'
import {
  EVALUATION_LIMITS,
  evaluateThresholds,
  scoreEvaluation,
  scoreFingerprintStability,
  scoreRepeatedEvaluations,
} from './lib/evaluation.mjs'
import {
  assertValidBenchmarkInput,
  bindBenchmarkPrimaryRun,
  bindBenchmarkPrimaryOutcomes,
} from './lib/benchmark-contracts.mjs'
import {
  databaseDiscoveryProjection,
  digestLensPack,
  lensSharedContractDigest,
  loadLenses,
} from './lib/activation.mjs'
import { artifactKeyToken, artifactToken } from './lib/artifact-names.mjs'
import {
  serializeDatabaseDiscovery,
  validateDatabaseDiscovery,
} from './lib/database-discovery.mjs'
import {
  buildCategoryDenominators,
  inventoryCoverageRecords,
} from './lib/coverage-model.mjs'
import { compareRuns, findingFingerprint } from './lib/lifecycle.mjs'
import {
  advanceRun,
  applyJobResult,
  assertValidJobResult,
  beginJob,
  buildFinalizedRun,
  compareTriageJobs,
} from './lib/job-protocol.mjs'
import {
  inventoryRepository,
  normalizeIncludedRoots,
  serializeInventory,
} from './lib/inventory.mjs'
import { authorizeAction, normalizePolicy } from './lib/policy.mjs'
import { renderMarkdownReport, renderSarif } from './lib/report.mjs'
import { renderRunStatus, summarizeRunStatus } from './lib/run-status.mjs'
import { buildReviewTemplate } from './lib/review-handoff.mjs'
import { buildVerdictAssessment, renderVerdictAssessment } from './lib/verdict-assessment.mjs'
import { buildRepairBrief, renderRepairBriefMarkdown } from './lib/repair-brief.mjs'
import { capabilityRegistry, renderCapabilities, assessEnvironmentCoverage } from './lib/capabilities.mjs'
import { inspectReadiness, normalizeReadinessPaths, renderReadiness } from './lib/doctor.mjs'
import {
  assertBundleArtifactSize,
  assertRunManifestSize,
  MAX_BUNDLE_ARTIFACT_BYTES,
  MAX_BUNDLE_ARTIFACTS,
  MAX_BUNDLE_VERIFICATION_BYTES,
  MAX_RUN_MANIFEST_BYTES,
  reserveBundleArtifactCapacity,
} from './lib/resource-limits.mjs'
import {
  createRunPlan,
  PLATFORM_VERSION,
  providerPolicyProjection,
  stableJson,
  summarizePlan,
  writeRunPlanBundle,
} from './lib/run-engine.mjs'
import {
  parseSealedSnapshotIndex,
  readSealedSnapshotFile,
  verifySealedSnapshot,
} from './lib/sealed-snapshot.mjs'
import {
  createRootAttestation,
  verifyRootAttestation,
} from './lib/root-attestation.mjs'
import {
  assertValidControllerFailureEnvelope,
  assertValidControllerExecutionEnvelope,
  assertValidProviderConfig,
  assertValidProviderExecution,
} from './lib/provider-contracts.mjs'
import {
  buildDockerCreateArgs,
  cleanupDockerProviderContainer,
  normalizeProviderArtifacts,
  runDockerProvider,
  sanitizeProviderPacket,
} from './lib/provider-runner.mjs'
import { buildRetryJobTemplate } from './lib/work-shards.mjs'
import { loadDatabaseConformanceEvidence } from './lib/database-conformance-controller.mjs'
import { loadEvidenceBundle } from './lib/evidence-bundle.mjs'
import {
  assertValidRemoteGatewayConfig,
  createRemoteRequestEnvelope,
  parseRemotePrivateKey,
  parseRemotePublicKey,
  verifyRemoteAcceptanceEnvelope,
  verifyRemoteRequestEnvelope,
} from './lib/remote-gateway-contracts.mjs'
import {
  submitRemoteGatewayRequest,
} from './lib/remote-gateway-client.mjs'
import {
  assertValidTransparencyLogConfig,
  createTransparencyConsistencyRequest,
  createTransparencyPublishRequest,
  parseTransparencyPublicKey,
  projectTransparencySignedCheckpoint,
  verifyTransparencyInclusion,
} from './lib/transparency-log-contracts.mjs'
import {
  submitTransparencyConsistencyRequest,
  submitTransparencyLogEntry,
} from './lib/transparency-log-client.mjs'
import {
  openTransparencyCheckpointJournal,
} from './lib/transparency-checkpoint-journal.mjs'

const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url))
const PROJECT_ROOT = resolve(SCRIPT_DIRECTORY, '..')
const DEFAULT_LENS_DIRECTORY = join(PROJECT_ROOT, 'skills', 'last-aperture', 'lenses')
const DEFAULT_THRESHOLDS = join(PROJECT_ROOT, 'benchmarks', 'thresholds.json')
const DEFAULT_BENCHMARK_CASES = join(PROJECT_ROOT, 'benchmarks', 'cases.json')
// context, version, image, create, profile inspect, attached start/exit,
// kill, remove, post-remove inspect, and exact-name absence listing.
const PROVIDER_DOCKER_COMMAND_BUDGET_SLOTS = 10
const PROVIDER_CAPTURE_GRACE_MS = 30_000
const NONRECOVERABLE_PROVIDER_CLEANUP_CODES = new Set([
  'PROVIDER_CLEANUP_FAILED',
  'PROVIDER_CLEANUP_UNVERIFIED',
  'PROVIDER_CREATE_OUTCOME_UNVERIFIED',
])
const MAX_PROVIDER_RESULT_BYTES = 8 * 1024 * 1024
const MAX_PROVIDER_CONFIG_BYTES = 1024 * 1024
const MAX_REMOTE_GATEWAY_CONFIG_BYTES = 1024 * 1024
const MAX_SIGNING_KEY_BYTES = 64 * 1024
const MAX_POLICY_BYTES = 1024 * 1024
const MAX_COMPLETENESS_INPUTS_BYTES = 4 * 1024 * 1024
const MAX_LOCK_BYTES = 16 * 1024
const MAX_BENCHMARK_INPUT_BYTES = 16 * 1024 * 1024
const MAX_BENCHMARK_CASES_BYTES = 8 * 1024 * 1024
const MAX_BENCHMARK_THRESHOLDS_BYTES = 1024 * 1024
const MAX_ROOT_ATTESTATION_BYTES = 64 * 1024
const MAX_TRANSPARENCY_LOG_CONFIG_BYTES = 64 * 1024
const MAX_TRANSPARENCY_RECEIPT_BYTES = 1024 * 1024
// Offline verification cannot read the log configuration, so it allows the
// largest skew any valid transparency-log-config.schema.json could configure.
const MAX_OFFLINE_TRANSPARENCY_CLOCK_SKEW_MS = 300_000
const OPEN_READ_ONLY_NO_FOLLOW = fsConstants.O_RDONLY
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)
const CREATE_EXCLUSIVE_NO_FOLLOW = fsConstants.O_WRONLY
  | fsConstants.O_CREAT
  | fsConstants.O_EXCL
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)

const HELP = `last-aperture ${PLATFORM_VERSION}

Usage:
  last-aperture engage unleash <target> [--json]
  last-aperture engage run <target> --attestation-file <file> --profile <full|repository-read|web|reverse|offline> --out <new-directory> [--target-kind <kind>] [--objective <text>] [--credential-reference <name> ...] [--input <kind=absolute-path> ...] [--json]
  last-aperture engage resume|status|stop <engagement-or-campaign-directory> [options]
  last-aperture engage work next|status|finalize|validate <engagement-directory> [--json]
  last-aperture engage work submit <engagement-directory> --work-id <repository-work:sha256> --result <absolute-json-path> [--json]
    Browser auth accepts --credential-reference browser:<32-character a-p Chrome-extension-id>
    and optional --input configuration=<absolute-page-session-adapter.json>.
  last-aperture http-recon <command> [options]
  last-aperture http-authed <command> [options]
  last-aperture reverse <command> [options]
  last-aperture adversarial <command> [options]
  last-aperture bounty <command> [options]
  last-aperture acquire <command> [options]
  last-aperture database-conformance <command> [options]
  last-aperture plan <repository> [--out <directory>] [--roe <policy.json>] [--completeness-inputs <inputs.json>] [--database-conformance <complete-bundle>] [--evidence-bundle <bundle>[,<bundle>...]  DISABLED] [--max-text-bytes <bytes>] [--max-shard-files <count>] [--max-shard-bytes <bytes>] [--max-closure-rounds <count>] [--require-source-closure] [--seal-source] [--json]
  last-aperture next <run.json|bundle-directory>
  last-aperture status <run.json|bundle-directory> [--json] [--receipt-public-key <ed25519-public.pem>]
  last-aperture capabilities [--json]
  last-aperture doctor [--worker <proof-worker.json>] [--bundle <bundle>] [--ghidra <file>] [--javac <file>] [--jar <file>] [--frida <file>] [--burp <jar>] [--burp-extension <jar>] [--crane <file>] [--json]
  last-aperture review-template <bundle> --job <job-id>
  last-aperture check-result <bundle> <job-result.json> [--expected-sha256 <sha256> --expected-size <bytes>] [--json]
  last-aperture verdict <bundle> [--candidate <candidate-id>] [--json]
  last-aperture repair-brief <bundle> [--candidate <candidate-id>] [--baseline <bundle>] [--json]
  last-aperture run-provider <run.json|bundle-directory> <provider-config.json>  [DISABLED]
  last-aperture run-remote <run.json|bundle-directory> <remote-gateway-config.json>  [DISABLED]
  last-aperture run-proof <run.json|bundle-directory> <proof-config.json> --worker <proof-worker.json>
  last-aperture run-service-proof <run.json|bundle-directory> <service-proof-config.json> --worker <proof-worker.json>
  last-aperture ingest <run.json|bundle-directory> <job-result.json> [--expected-sha256 <sha256> --expected-size <bytes>]
  last-aperture ingest-batch <run.json|bundle-directory> <job-result.json>...
  last-aperture finalize <run.json|bundle-directory>
  last-aperture abort <run.json|bundle-directory> --reason <text>
  last-aperture unlock <run.json|bundle-directory>
  last-aperture attest <run.json|bundle-directory> --signing-key <ed25519-private.pem> --out <external-attestation.json> [--receipt-public-key <ed25519-public.pem>]
  last-aperture publish <run.json|bundle-directory> <transparency-log-config.json> --root-attestation <external-attestation.json> --root-public-key <ed25519-public.pem> --out <external-inclusion-receipt.json> [--receipt-public-key <ed25519-public.pem>] [--transparency-checkpoint-journal <external-directory> [--initialize-transparency-checkpoint-journal]]  [DISABLED]
  last-aperture validate <run.json|bundle-directory> [--receipt-public-key <ed25519-public.pem>] [--root-attestation <external-attestation.json> --root-public-key <ed25519-public.pem>] [--transparency-receipt <external-inclusion-receipt.json> --transparency-log-public-key <ed25519-public.pem> --transparency-log-origin <origin> [--transparency-checkpoint-journal <external-directory>]]
  last-aperture report <run.json|bundle-directory> [--out <report.md>] [--sarif <results.sarif>] [--receipt-public-key <ed25519-public.pem>] [--root-attestation <external-attestation.json> --root-public-key <ed25519-public.pem>] [--transparency-receipt <external-inclusion-receipt.json> --transparency-log-public-key <ed25519-public.pem> --transparency-log-origin <origin> [--transparency-checkpoint-journal <external-directory>]]
  last-aperture compare <baseline-run> <current-run> [--out <comparison.json>] [--receipt-public-key <ed25519-public.pem>]
  last-aperture benchmark <evaluation.json> [--cases <cases.json>] [--thresholds <thresholds.json>] [--out <scorecard.json>]

Safety:
  Static/read-only planning is the default. Repository content is untrusted data.
  Planning never executes repository code, follows symlinks, or makes network calls.
  --seal-source requires an explicit local output directory outside the target.
  Public T1 proof execution uses a digest-pinned, network-denied Docker proof worker.
  It reconstructs verified sealed bytes, copies them into container tmpfs without a
  host mount, scrubs ambient credentials, bounds output/time/PIDs, and verifies teardown.
  Public T2 service proof execution uses that same worker with two fresh containers,
  a controller-owned TTL supervisor, and fixed in-container loopback readiness probes.
  Public run-remote execution is disabled before bundle/configuration access until
  gateway identity and outbound-data policy are enrolled outside caller-controlled
  files. A signed request does not make a caller-selected destination trusted.
  Public run-provider execution is disabled before bundle/configuration access until
  the container-runtime executable is controller-enrolled and identity-pinned.
  Public transparency publication is disabled before input/configuration access until
  the log endpoint is independently enrolled; a fixed POST is still target I/O.
  Public evidence-bundle import is disabled before repository or bundle access until
  one atomic verifier authenticates manifest semantics, payloads, and plan identity.

Exit codes:
  0  command succeeded
  1  invalid input, contract violation, or operational failure
  2  benchmark gate failed
`

function parseArguments(values) {
  const positionals = []
  const options = {}
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index]
    if (!value.startsWith('--')) {
      positionals.push(value)
      continue
    }
    const key = value.slice(2)
    if (!key) throw new Error('empty option name')
    if (Object.hasOwn(options, key)) {
      throw new Error(`duplicate option --${key}`)
    }
    const next = values[index + 1]
    if (next === undefined || next.startsWith('--')) {
      options[key] = true
    } else {
      options[key] = next
      index += 1
    }
  }
  return { positionals, options }
}

const COMMAND_ARGUMENTS = {
  plan: {
    positionals: 1,
    options: {
      out: 'value',
      roe: 'value',
      'completeness-inputs': 'value',
      'database-conformance': 'value',
      'evidence-bundle': 'value',
      'max-text-bytes': 'value',
      'max-shard-files': 'value',
      'max-shard-bytes': 'value',
      'max-closure-rounds': 'value',
      'require-source-closure': 'flag',
      'seal-source': 'flag',
      json: 'flag',
    },
  },
  next: { positionals: 1, options: {} },
  status: { positionals: 1, options: { json: 'flag', 'receipt-public-key': 'value' } },
  capabilities: { positionals: 0, options: { json: 'flag' } },
  doctor: { positionals: 0, options: {
    json: 'flag', worker: 'value', bundle: 'value', ghidra: 'value', javac: 'value',
    jar: 'value', frida: 'value', burp: 'value', 'burp-extension': 'value', crane: 'value',
  } },
  'review-template': { positionals: 1, options: { job: 'value' } },
  'check-result': {
    positionals: 2,
    options: { json: 'flag', 'expected-sha256': 'value', 'expected-size': 'value' },
  },
  verdict: { positionals: 1, options: { json: 'flag', candidate: 'value' } },
  'repair-brief': { positionals: 1, options: { json: 'flag', candidate: 'value', baseline: 'value' } },
  'run-provider': { positionals: 2, options: {} },
  'run-remote': { positionals: 2, options: {} },
  ingest: {
    positionals: 2,
    options: { 'expected-sha256': 'value', 'expected-size': 'value' },
  },
  'ingest-batch': { minPositionals: 2, options: {} },
  finalize: { positionals: 1, options: {} },
  abort: { positionals: 1, options: { reason: 'value' } },
  unlock: { positionals: 1, options: {} },
  attest: {
    positionals: 1,
    options: {
      'signing-key': 'value',
      out: 'value',
      'receipt-public-key': 'value',
    },
  },
  publish: {
    positionals: 2,
    options: {
      out: 'value',
      'receipt-public-key': 'value',
      'root-attestation': 'value',
      'root-public-key': 'value',
      'transparency-checkpoint-journal': 'value',
      'initialize-transparency-checkpoint-journal': 'flag',
    },
  },
  validate: {
    positionals: 1,
    options: {
      json: 'flag',
      'receipt-public-key': 'value',
      'root-attestation': 'value',
      'root-public-key': 'value',
      'transparency-receipt': 'value',
      'transparency-log-public-key': 'value',
      'transparency-log-origin': 'value',
      'transparency-checkpoint-journal': 'value',
    },
  },
  report: {
    positionals: 1,
    options: {
      out: 'value',
      sarif: 'value',
      'receipt-public-key': 'value',
      'root-attestation': 'value',
      'root-public-key': 'value',
      'transparency-receipt': 'value',
      'transparency-log-public-key': 'value',
      'transparency-log-origin': 'value',
      'transparency-checkpoint-journal': 'value',
    },
  },
  'run-proof': {
    positionals: 2,
    options: { worker: 'value' },
  },
  'run-service-proof': {
    positionals: 2,
    options: { worker: 'value' },
  },
  compare: {
    positionals: 2,
    options: { out: 'value', 'receipt-public-key': 'value' },
  },
  benchmark: {
    positionals: 1,
    options: { cases: 'value', thresholds: 'value', out: 'value' },
  },
}

function assertArgumentShape(command, positionals, options) {
  const spec = COMMAND_ARGUMENTS[command]
  if (!spec) return
  if (
    Number.isSafeInteger(spec.positionals)
    && positionals.length !== spec.positionals
  ) {
    throw new Error(
      `${command} expects exactly ${spec.positionals} positional ` +
      `argument${spec.positionals === 1 ? '' : 's'}; received ${positionals.length}`,
    )
  }
  if (
    Number.isSafeInteger(spec.minPositionals)
    && positionals.length < spec.minPositionals
  ) {
    throw new Error(
      `${command} expects at least ${spec.minPositionals} positional arguments; ` +
      `received ${positionals.length}`,
    )
  }
  for (const [key, value] of Object.entries(options)) {
    const kind = spec.options[key]
    if (!kind) throw new Error(`unknown option --${key} for ${command}`)
    if (kind === 'flag' && value !== true) {
      throw new Error(`--${key} is a flag and does not accept a value`)
    }
    if (kind === 'value' && typeof value !== 'string') {
      throw new Error(`--${key} requires a value`)
    }
  }
}

function requirePositional(positionals, index, name) {
  const value = positionals[index]
  if (!value) throw new Error(`${name} is required`)
  return value
}

function positiveInteger(value, name) {
  if (value === undefined) return undefined
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${name} must be a positive integer`)
  }
  return parsed
}

function nonNegativeInteger(value, name) {
  if (value === undefined) return undefined
  const parsed = Number(value)
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${name} must be a non-negative integer`)
  }
  return parsed
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

async function readJson(path, options = {}) {
  const absolutePath = resolve(path)
  if (!Number.isSafeInteger(options.maxBytes) || options.maxBytes < 0) {
    throw new Error('JSON input reads require a non-negative maxBytes limit')
  }
  const text = (await readBoundedFile(
    absolutePath,
    options.maxBytes,
    options.label ?? 'JSON input',
  )).toString('utf8')
  try {
    return JSON.parse(text)
  } catch (error) {
    throw new Error(`invalid JSON in ${absolutePath}: ${error.message}`)
  }
}

function exactResultSourceBinding(options) {
  const expectedSha256 = options?.['expected-sha256']
  const expectedSizeValue = options?.['expected-size']
  if ((expectedSha256 === undefined) !== (expectedSizeValue === undefined)) {
    throw new Error('--expected-sha256 and --expected-size must be provided together')
  }
  if (expectedSha256 === undefined) return undefined
  if (typeof expectedSha256 !== 'string' || !/^[a-f0-9]{64}$/u.test(expectedSha256)) {
    throw new Error('--expected-sha256 must be a lowercase SHA-256 digest')
  }
  const expectedSize = nonNegativeInteger(expectedSizeValue, '--expected-size')
  if (expectedSize > MAX_PROVIDER_RESULT_BYTES) {
    throw new Error(`--expected-size exceeds the ${MAX_PROVIDER_RESULT_BYTES}-byte provider result limit`)
  }
  return { sha256: expectedSha256, size: expectedSize }
}

async function readJobResultSource(resultPath, expectedSource) {
  const absolutePath = resolve(resultPath)
  const bytes = await readBoundedFile(
    absolutePath,
    MAX_PROVIDER_RESULT_BYTES,
    'provider result JSON',
  )
  if (
    expectedSource !== undefined
    && (
      bytes.length !== expectedSource.size
      || sha256(bytes) !== expectedSource.sha256
    )
  ) {
    throw new Error('provider result source differs from its controller-bound digest or size')
  }
  let jobResult
  try {
    jobResult = JSON.parse(bytes.toString('utf8'))
  } catch (error) {
    throw new Error(`invalid JSON in ${absolutePath}: ${error.message}`)
  }
  return { bytes, jobResult }
}

async function readBoundedFile(path, maxBytes, label) {
  const absolutePath = resolve(path)
  let handle
  try {
    handle = await open(absolutePath, OPEN_READ_ONLY_NO_FOLLOW)
    const metadata = await handle.stat()
    if (!metadata.isFile()) {
      throw new Error(`${label} is not a regular file`)
    }
    if (metadata.size > maxBytes) {
      throw new Error(`${label} exceeds the ${maxBytes}-byte input limit`)
    }
    const buffer = Buffer.allocUnsafe(metadata.size)
    let offset = 0
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(
        buffer,
        offset,
        Math.min(64 * 1024, buffer.length - offset),
        null,
      )
      if (bytesRead === 0) break
      offset += bytesRead
    }
    const probe = Buffer.allocUnsafe(1)
    const { bytesRead: growth } = await handle.read(probe, 0, 1, null)
    const finalMetadata = await handle.stat()
    if (
      offset !== buffer.length
      || growth !== 0
      || finalMetadata.size !== metadata.size
      || finalMetadata.mtimeMs !== metadata.mtimeMs
      || finalMetadata.ctimeMs !== metadata.ctimeMs
    ) {
      if (metadata.size >= maxBytes || finalMetadata.size > maxBytes) {
        throw new Error(`${label} exceeds the ${maxBytes}-byte input limit`)
      }
      throw new Error(`${label} changed while it was being read`)
    }
    if (offset > maxBytes) {
      throw new Error(`${label} exceeds the ${maxBytes}-byte input limit`)
    }
    return buffer
  } catch (error) {
    throw new Error(
      `cannot read ${absolutePath}: ${error.message}`,
      { cause: error },
    )
  } finally {
    await handle?.close()
  }
}

async function canonicalUnlinkedFile(path, label) {
  const absolutePath = resolve(path)
  const filesystemRoot = parse(absolutePath).root
  const segments = relative(filesystemRoot, absolutePath)
    .split(/[\\/]/)
    .filter(Boolean)
  let current = filesystemRoot
  let metadata
  for (const [index, segment] of segments.entries()) {
    current = join(current, segment)
    metadata = await lstat(current)
    if (metadata.isSymbolicLink()) {
      throw new Error(`${label} contains a symbolic link or reparse point: ${current}`)
    }
    if (index < segments.length - 1 && !metadata.isDirectory()) {
      throw new Error(`${label} parent is not a directory: ${current}`)
    }
  }
  if (!metadata?.isFile()) throw new Error(`${label} is not a regular file: ${absolutePath}`)
  return realpath(absolutePath)
}

function pathWithin(root, candidate) {
  const fromRoot = relative(root, candidate)
  return fromRoot === ''
    || (
      fromRoot !== '..'
      && !fromRoot.startsWith(`..${sep}`)
      && !isAbsolute(fromRoot)
    )
}

async function runJsonPath(value) {
  const path = resolve(value)
  const metadata = await lstat(path)
  if (metadata.isSymbolicLink()) {
    throw new Error(`run path must not be a symbolic link or reparse point: ${path}`)
  }
  const runPath = metadata.isDirectory() ? join(path, 'run.json') : path
  await assertSafeExistingBundlePath(
    dirname(runPath),
    basename(runPath),
    { expectedType: 'file' },
  )
  return runPath
}

async function loadRun(value) {
  const path = await runJsonPath(value)
  const { content } = await readSafeBundleFile(
    dirname(path),
    basename(path),
    {
      maxBytes: MAX_RUN_MANIFEST_BYTES,
      label: 'run manifest',
    },
  )
  let text
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(content)
  } catch {
    throw new Error(`run manifest is not valid UTF-8: ${path}`)
  }
  let run
  try {
    run = JSON.parse(text)
  } catch (error) {
    throw new Error(`invalid JSON in ${path}: ${error.message}`)
  }
  assertLocalFilesystemEndpoint(run?.repository?.root, 'run repository root')
  return {
    path,
    directory: dirname(path),
    run,
    sourceDigest: sha256(content),
  }
}

async function writeJson(path, value) {
  await writeFile(resolve(path), stableJson(value), { encoding: 'utf8', flag: 'wx' })
}

async function preflightReportOutputs(options) {
  const targets = [
    ...(typeof options.out === 'string'
      ? [{ option: '--out', path: resolve(options.out) }]
      : []),
    ...(typeof options.sarif === 'string'
      ? [{ option: '--sarif', path: resolve(options.sarif) }]
      : []),
  ]
  const identities = new Map()
  for (const target of targets) {
    let canonicalParent
    try {
      canonicalParent = await realpath(dirname(target.path))
    } catch (error) {
      throw new Error(
        `cannot prepare ${target.option} output ${target.path}: ${error.message}`,
      )
    }
    const canonicalTarget = join(canonicalParent, basename(target.path))
    const identity = process.platform === 'win32'
      ? canonicalTarget.toLowerCase()
      : canonicalTarget
    const prior = identities.get(identity)
    if (prior) {
      throw new Error(
        `${prior.option} and ${target.option} resolve to the same output path: ` +
        `${canonicalTarget}`,
      )
    }
    identities.set(identity, target)
  }
  for (const target of targets) {
    try {
      await lstat(target.path)
    } catch (error) {
      if (error.code === 'ENOENT') continue
      throw new Error(
        `cannot inspect ${target.option} output ${target.path}: ${error.message}`,
      )
    }
    throw new Error(`${target.option} output already exists: ${target.path}`)
  }
  return {
    markdownPath: targets.find(({ option }) => option === '--out')?.path,
    sarifPath: targets.find(({ option }) => option === '--sarif')?.path,
  }
}

async function durableCreate(path, content) {
  const handle = await open(path, CREATE_EXCLUSIVE_NO_FOLLOW, 0o600)
  try {
    const metadata = await handle.stat()
    if (!metadata.isFile()) {
      throw new Error(`refusing to write a non-regular file: ${path}`)
    }
    await handle.writeFile(content, { encoding: 'utf8' })
    await handle.sync()
  } finally {
    await handle.close()
  }
}

async function exclusiveAtomicCreate(path, content) {
  const temporary = `${path}.${process.pid}.${randomUUID()}.create`
  await durableCreate(temporary, content)
  try {
    await link(temporary, path)
  } finally {
    await unlink(temporary).catch((error) => {
      if (error.code !== 'ENOENT') throw error
    })
  }
}

async function atomicReplace(path, content) {
  const temporary = `${path}.${process.pid}.${randomUUID()}.tmp`
  await durableCreate(temporary, content)
  try {
    await rename(temporary, path)
  } finally {
    await unlink(temporary).catch((error) => {
      if (error.code !== 'ENOENT') throw error
    })
  }
}

async function writeOnceBundleArtifact(directory, artifactPath, content) {
  assertBundleArtifactSize(content, `bundle artifact ${artifactPath}`)
  const expectedBytes = Buffer.isBuffer(content)
    ? content
    : Buffer.from(String(content), 'utf8')
  const normalized = String(artifactPath).replaceAll('\\', '/')
  const parentPath = normalized.includes('/')
    ? normalized.slice(0, normalized.lastIndexOf('/'))
    : null
  if (parentPath) await ensureSafeBundleSubdirectory(directory, parentPath)
  const { absolutePath } = await assertSafeBundleWriteParent(directory, normalized)
  try {
    await exclusiveAtomicCreate(absolutePath, content)
    await assertSafeExistingBundlePath(directory, normalized, { expectedType: 'file' })
  } catch (error) {
    if (error.code !== 'EEXIST') throw error
  }
  const { content: committedBytes } = await readSafeBundleFile(directory, normalized)
  if (!committedBytes.equals(expectedBytes)) {
    throw new Error(`refusing to overwrite conflicting artifact ${absolutePath}`)
  }
}

async function assertSafeBundleWriteParent(directory, artifactPath) {
  const root = await canonicalBundleRoot(directory)
  const resolved = resolveBundleArtifactPath(root.lexicalRoot, artifactPath)
  const normalizedParent = resolved.normalized.includes('/')
    ? resolved.normalized.slice(0, resolved.normalized.lastIndexOf('/'))
    : null
  if (normalizedParent) {
    await assertSafeExistingBundlePath(
      root.lexicalRoot,
      normalizedParent,
      { expectedType: 'directory' },
    )
  }
  const canonicalParent = await realpath(dirname(resolved.absolutePath))
  if (!isContainedPath(root.canonicalRoot, canonicalParent, { allowRoot: true })) {
    throw new Error(`bundle write parent escapes its canonical root: ${artifactPath}`)
  }
  return resolved
}

function lockRecord(token = randomUUID()) {
  return {
    pid: process.pid,
    created_at: new Date().toISOString(),
    token,
  }
}

function parseLockRecord(text, path) {
  let record
  try {
    record = JSON.parse(text)
  } catch {
    const legacy = /^([1-9][0-9]*)\s+(\S+)\s*$/.exec(text)
    if (legacy) {
      record = {
        pid: Number(legacy[1]),
        created_at: legacy[2],
        token: null,
      }
    }
  }
  if (
    record === null
    || typeof record !== 'object'
    || Array.isArray(record)
    || !Number.isSafeInteger(record.pid)
    || record.pid <= 0
    || typeof record.created_at !== 'string'
    || Number.isNaN(Date.parse(record.created_at))
    || !(
      record.token === null
      || (typeof record.token === 'string' && record.token.length >= 16)
    )
  ) {
    throw new Error(`invalid run lock record: ${path}`)
  }
  return record
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0)
    return true
  } catch (error) {
    if (error.code === 'ESRCH') return false
    if (error.code === 'EPERM') return true
    throw new Error(`cannot determine whether lock owner PID ${pid} is alive: ${error.message}`)
  }
}

async function readLock(path) {
  const bytes = await readBoundedFile(path, MAX_LOCK_BYTES, 'run lock')
  const text = bytes.toString('utf8')
  return {
    record: parseLockRecord(text, path),
    text,
    digest: sha256(bytes),
  }
}

async function readLockCandidate(directory, path) {
  await assertSafeExistingBundlePath(
    directory,
    basename(path),
    { expectedType: 'file' },
  )
  const metadata = await lstat(path)
  if (metadata.size > MAX_LOCK_BYTES) {
    return {
      record: null,
      signature: [
        'oversized',
        metadata.dev,
        metadata.ino,
        metadata.size,
        metadata.mtimeMs,
        metadata.ctimeMs,
      ].join(':'),
    }
  }
  const bytes = await readBoundedFile(path, MAX_LOCK_BYTES, 'run lock')
  let record = null
  try {
    record = parseLockRecord(bytes.toString('utf8'), path)
  } catch {
    // Explicit unlock may recover a stable malformed legacy marker while its
    // scoped recovery lock excludes normal mutations.
  }
  await assertSafeExistingBundlePath(
    directory,
    basename(path),
    { expectedType: 'file' },
  )
  return {
    record,
    signature: `sha256:${sha256(bytes)}`,
  }
}

async function assertRecoveryNotInProgress(recoveryPath) {
  try {
    const metadata = await lstat(recoveryPath)
    if (metadata.isSymbolicLink()) {
      throw new Error(
        `run lock recovery marker is a symbolic link or reparse point: ${recoveryPath}`,
      )
    }
    throw new Error(`run lock recovery is already in progress: ${recoveryPath}`)
  } catch (error) {
    if (error.code === 'ENOENT') return
    throw error
  }
}

async function clearStaleRecoveryMarker(directory, recoveryPath) {
  try {
    await assertSafeExistingBundlePath(
      directory,
      basename(recoveryPath),
      { expectedType: 'file' },
    )
  } catch (error) {
    if (error.code === 'ENOENT') return
    throw error
  }
  const before = await readLock(recoveryPath)
  if (processIsAlive(before.record.pid)) {
    throw new Error(
      `run lock recovery is owned by live PID ${before.record.pid}: ${recoveryPath}`,
    )
  }
  const after = await readLock(recoveryPath)
  if (after.digest !== before.digest) {
    throw new Error(`run lock recovery marker changed while being checked: ${recoveryPath}`)
  }
  await unlink(recoveryPath)
}

async function releaseOwnedLock(path, token) {
  let current
  try {
    current = await readLock(path)
  } catch (error) {
    if (error.cause?.code === 'ENOENT') return
    throw error
  }
  if (current.record.pid !== process.pid || current.record.token !== token) {
    throw new Error(`refusing to remove a run lock whose ownership changed: ${path}`)
  }
  await unlink(path)
}

async function acquireServiceProofCommandLock(runPath, options = {}) {
  const processAlive = options.processIsAlive ?? processIsAlive
  if (typeof processAlive !== 'function') {
    throw new TypeError('service-proof processIsAlive must be a function')
  }
  const directory = dirname(runPath)
  const lockPath = `${runPath}.service-proof.lock`
  const recoveryPath = `${lockPath}.recovery`
  const record = lockRecord()
  await assertRecoveryNotInProgress(recoveryPath)
  try {
    await exclusiveAtomicCreate(lockPath, stableJson(record))
    return { path: lockPath, token: record.token }
  } catch (error) {
    if (error.code !== 'EEXIST') throw error
  }

  const observed = await readLockCandidate(directory, lockPath)
  if (!observed.record) {
    throw new Error(`invalid service-proof command lock: ${lockPath}`)
  }
  if (processAlive(observed.record.pid)) {
    const error = new Error(
      `service-proof controller PID ${observed.record.pid} is active; `
      + 'refusing concurrent or expired-lease takeover',
    )
    error.code = 'SERVICE_PROOF_CONTROLLER_ACTIVE'
    throw error
  }

  const recoveryRecord = lockRecord()
  try {
    await exclusiveAtomicCreate(recoveryPath, stableJson(recoveryRecord))
  } catch (error) {
    if (error.code === 'EEXIST') {
      throw new Error(`service-proof command-lock recovery is already active: ${recoveryPath}`)
    }
    throw error
  }
  try {
    const current = await readLockCandidate(directory, lockPath)
    if (
      !current.record
      || current.signature !== observed.signature
      || processAlive(current.record.pid)
    ) {
      throw new Error('service-proof command lock changed or became live during recovery')
    }
    await unlink(lockPath)
  } finally {
    await releaseOwnedLock(recoveryPath, recoveryRecord.token)
  }

  await assertRecoveryNotInProgress(recoveryPath)
  await exclusiveAtomicCreate(lockPath, stableJson(record))
  return { path: lockPath, token: record.token }
}

async function persistRun(path, run, expectedDigest, hooks = {}) {
  const { beforeCommit, afterCommit } = hooks
  if (beforeCommit !== undefined && typeof beforeCommit !== 'function') {
    throw new TypeError('beforeCommit must be a function')
  }
  if (afterCommit !== undefined && typeof afterCommit !== 'function') {
    throw new TypeError('afterCommit must be a function')
  }
  assertValidRun(run)
  const serializedRun = stableJson(run)
  assertRunManifestSize(serializedRun)
  const directory = dirname(path)
  await assertSafeExistingBundlePath(directory, basename(path), { expectedType: 'file' })
  const lockPath = `${path}.lock`
  const recoveryPath = `${lockPath}.recovery`
  const record = lockRecord()
  await assertRecoveryNotInProgress(recoveryPath)
  try {
    await exclusiveAtomicCreate(lockPath, stableJson(record))
  } catch (error) {
    if (error.code === 'EEXIST') {
      throw new Error(
        `run is locked by another update: ${lockPath}; ` +
        `if its owner exited, run last-aperture unlock ${JSON.stringify(directory)}`,
      )
    }
    throw error
  }
  try {
    await assertRecoveryNotInProgress(recoveryPath)
    const { content: currentBytes } = await readSafeBundleFile(
      directory,
      basename(path),
    )
    if (expectedDigest && sha256(currentBytes) !== expectedDigest) {
      throw new Error('run changed concurrently; reload it and retry the operation')
    }
    if (beforeCommit) await beforeCommit()
    await atomicReplace(path, serializedRun)
    if (afterCommit) await afterCommit()
  } finally {
    await releaseOwnedLock(lockPath, record.token)
  }
}

function lensSidecarArtifact(job) {
  const filename = `${artifactToken(job.job_id)}.json`
  return {
    key: `job_${artifactKeyToken(job.job_id).toLowerCase()}`,
    path: `jobs/${filename}`,
    absolutePath: join('jobs', filename),
  }
}

function immutableDenominatorProjection(row) {
  return {
    class: row?.class,
    files_total: row?.files_total,
    bytes_total: row?.bytes_total,
    paths: row?.paths,
    files: row?.files,
  }
}

function immutableCoveragePlanProjection(coverage, schemaVersion) {
  const projection = {
    inventory: coverage?.inventory,
  }
  if (!['3.0.0', '4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(schemaVersion)) return projection
  return {
    model_version: coverage?.model_version,
    policy: coverage?.policy,
    inventory: coverage?.inventory,
    inventory_records: coverage?.inventory_records,
    denominators: Array.isArray(coverage?.denominators)
      ? coverage.denominators.map(immutableDenominatorProjection)
      : coverage?.denominators,
    completeness_inputs: coverage?.completeness_inputs,
    lenses: Array.isArray(coverage?.lenses)
      ? coverage.lenses.map(({ lens, applicable_paths: applicablePaths }) => ({
          lens,
          applicable_paths: applicablePaths,
        }))
      : coverage?.lenses,
    shards: coverage?.shards,
    closure_policy: coverage?.closure === undefined
      ? undefined
      : {
          required_source_closure:
            coverage.closure?.required_source_closure,
          max_rounds: coverage.closure?.max_rounds,
        },
  }
}

function assertImmutableCoveragePlan(
  run,
  plannedCoverage,
  snapshot,
  expectedInventory,
) {
  if (
    stableJson(plannedCoverage?.inventory) !== stableJson(expectedInventory)
    || (plannedCoverage?.examined ?? []).length !== 0
  ) {
    throw new Error(
      'planned coverage artifact is not the immutable initial coverage snapshot',
    )
  }
  if (!['3.0.0', '4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(run.schema_version)) return

  const expectedRecords = inventoryCoverageRecords(snapshot.entries)
  const expectedDenominators = buildCategoryDenominators(expectedRecords)
  const closure = plannedCoverage.closure
  if (
    !Array.isArray(plannedCoverage.examined)
    || stableJson(plannedCoverage.inventory_records)
      !== stableJson(expectedRecords)
    || stableJson(plannedCoverage.denominators)
      !== stableJson(expectedDenominators)
    || !Array.isArray(plannedCoverage.lenses)
    || plannedCoverage.lenses.some(
      ({ examined_paths: examinedPaths }) =>
        !Array.isArray(examinedPaths) || examinedPaths.length !== 0,
    )
    || !Array.isArray(plannedCoverage.resolved_gap_ids)
    || plannedCoverage.resolved_gap_ids.length !== 0
    || closure?.round !== 0
    || closure?.status !== 'PENDING'
    || !Array.isArray(closure?.history)
    || closure.history.length !== 0
    || closure.required_source_closure
      !== plannedCoverage.policy?.require_source_closure
    || closure.max_rounds
      !== plannedCoverage.policy?.max_requeue_rounds
  ) {
    throw new Error(
      'planned coverage artifact is not the immutable initial coverage snapshot',
    )
  }

  if (
    stableJson(immutableCoveragePlanProjection(run.coverage, run.schema_version))
    !== stableJson(
      immutableCoveragePlanProjection(plannedCoverage, run.schema_version),
    )
  ) {
    throw new Error(
      'run coverage immutable plan fields do not match coverage-plan.json',
    )
  }
}

function hasOwn(value, field) {
  return Object.prototype.hasOwnProperty.call(value, field)
}

function plannedShardForJob(plannedCoverage, job) {
  if (job.kind !== 'LENS' || job.shard === undefined) return undefined
  const plannedJobId = job.closure_round === undefined
    ? job.job_id
    : job.parent_job_id
  return plannedCoverage.shards?.find(
    ({ job_id: jobId }) => jobId === plannedJobId,
  )
}

function expectedV3SidecarScope(plannedCoverage, job, run) {
  if (job.kind === 'TRIAGE' && job.lens === 'business-logic') {
    const lensJobs = (run?.jobs ?? []).filter(({ kind }) => kind === 'LENS')
    const hasOwnedTopicProvenance = lensJobs.some((lensJob) =>
      hasOwn(lensJob, 'owned_topics'))
    const domainLenses = hasOwnedTopicProvenance
      ? new Set(lensJobs
          .filter((lensJob) => (lensJob.owned_topics?.length ?? 0) > 0)
          .map(({ lens }) => lens))
      : undefined
    const sourceFiles = [...new Set((plannedCoverage?.shards ?? [])
      .filter((shard) => domainLenses === undefined || domainLenses.has(shard.lens))
      .flatMap((shard) => shard.scoped_files ?? []))]
      .sort(compareCanonicalStrings)
    return hasOwnedTopicProvenance
      ? sourceFiles.slice(0, plannedCoverage?.policy?.max_shard_files)
      : sourceFiles
  }
  if (job.kind !== 'LENS') return []
  if (job.shard === undefined) return []
  const plannedShard = plannedShardForJob(plannedCoverage, job)
  if (
    !plannedShard
    || plannedShard.lens !== job.lens
    || stableJson(plannedShard.shard, 0) !== stableJson(job.shard, 0)
  ) {
    throw new Error(`job identity does not match coverage-plan.json for ${job.job_id}`)
  }
  if (job.closure_round !== undefined) {
    const retry = buildRetryJobTemplate(
      {
        scoped_files: plannedShard.scoped_files,
        shard: plannedShard.shard,
      },
      {
        parentJobId: plannedShard.job_id,
        lens: plannedShard.lens,
        closureRound: job.closure_round,
      },
    )
    if (retry.job_id !== job.job_id) {
      throw new Error(`job identity does not match coverage-plan.json for ${job.job_id}`)
    }
  }
  return plannedShard.scoped_files
}

function assertSidecarJobIdentity(
  run,
  job,
  sidecar,
  plannedCoverage = run.coverage,
  { requireProtocolFields = false } = {},
) {
  const expectedFields = {
    job_id: job.job_id,
    kind: job.kind,
    lens: job.lens,
    repository_root: run.repository.root,
    ...(
      ['3.0.0', '4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(run.schema_version) || requireProtocolFields
        ? {
            schema_version: run.schema_version,
            phase: job.closure_round !== undefined
              ? 'COMPLETENESS'
              : {
                  LENS: 'FANOUT',
                  TRIAGE: 'TRIAGE',
                  COMPLETENESS: 'COMPLETENESS',
                }[job.kind],
          }
        : {}
    ),
  }
  for (const [field, value] of Object.entries(expectedFields)) {
    if (sidecar[field] !== value) {
      throw new Error(`sidecar ${field} mismatch for ${job.job_id}`)
    }
  }
  for (const field of ['shard', 'closure_round', 'parent_job_id']) {
    if (
      hasOwn(sidecar, field) !== hasOwn(job, field)
      || (
        hasOwn(job, field)
        && stableJson(sidecar[field], 0) !== stableJson(job[field], 0)
      )
    ) {
      throw new Error(`sidecar ${field} mismatch for ${job.job_id}`)
    }
  }
  for (const field of [
    'database_store_ids',
    'profile_authority_store_ids',
  ]) {
    const expected = job[field] ?? []
    const actual = sidecar[field] ?? []
    if (stableJson(actual) !== stableJson(expected)) {
      throw new Error(`sidecar ${field} mismatch for ${job.job_id}`)
    }
  }
  for (const field of ['lens_digest', 'owned_topics']) {
    if (
      hasOwn(job, field)
      && stableJson(sidecar[field]) !== stableJson(job[field])
    ) {
      throw new Error(`sidecar ${field} mismatch for ${job.job_id}`)
    }
  }
  if (
    hasOwn(sidecar, 'topic_obligations') !== hasOwn(job, 'topic_obligations')
    || (
      hasOwn(job, 'topic_obligations')
      && stableJson(sidecar.topic_obligations) !== stableJson(job.topic_obligations)
    )
  ) {
    throw new Error(`sidecar topic_obligations mismatch for ${job.job_id}`)
  }
  const expectedCompletenessInputs =
    job.kind === 'COMPLETENESS' && plannedCoverage?.completeness_inputs !== undefined
      ? plannedCoverage.completeness_inputs
      : undefined
  if (
    hasOwn(sidecar, 'completeness_inputs')
      !== (expectedCompletenessInputs !== undefined)
    || (
      expectedCompletenessInputs !== undefined
      && stableJson(sidecar.completeness_inputs, 0)
        !== stableJson(expectedCompletenessInputs, 0)
    )
  ) {
    throw new Error(`sidecar completeness_inputs mismatch for ${job.job_id}`)
  }
  if (!Array.isArray(sidecar.scoped_files)) {
    throw new Error(`sidecar scoped_files must be an array for ${job.job_id}`)
  }
  if (['3.0.0', '4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(run.schema_version)) {
    const expectedScope = expectedV3SidecarScope(plannedCoverage, job, run)
    if (stableJson(sidecar.scoped_files) !== stableJson(expectedScope)) {
      throw new Error(`sidecar scoped_files mismatch for ${job.job_id}`)
    }
    const expectedDatabaseProjection =
      job.lens === 'database-and-data-stores'
        ? databaseDiscoveryProjection(
            run.database_discovery,
            sidecar.scoped_files,
          )
        : undefined
    if (
      hasOwn(sidecar, 'database_discovery')
        !== (expectedDatabaseProjection !== undefined)
      || (
        expectedDatabaseProjection !== undefined
        && stableJson(sidecar.database_discovery, 0)
          !== stableJson(expectedDatabaseProjection, 0)
      )
    ) {
      throw new Error(
        `sidecar database_discovery mismatch for ${job.job_id}`,
      )
    }
  }
}

async function readVerifiedArtifact(directory, run, key, expectedPath) {
  const artifact = run.artifacts?.[key]
  if (!artifact) throw new Error(`run is missing the hashed ${key} artifact`)
  if (artifact.path.replaceAll('\\', '/') !== expectedPath) {
    throw new Error(`${key} artifact path mismatch`)
  }
  const { absolutePath, content } = await readSafeBundleFile(directory, expectedPath)
  if (sha256(content).toLowerCase() !== artifact.sha256.toLowerCase()) {
    throw new Error(`${key} artifact digest mismatch`)
  }
  return { absolutePath, content }
}

function verifiedArtifactUtf8(committed) {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(committed.content)
  } catch (error) {
    throw new Error(`${committed.absolutePath} is not valid UTF-8: ${error.message}`)
  }
}

function resolveBundleArtifactPath(directory, artifactPath) {
  const normalized = String(artifactPath).replaceAll('\\', '/')
  const segments = normalized.split('/')
  if (
    normalized.length === 0
    || normalized.startsWith('/')
    || /^[A-Za-z]:/.test(normalized)
    || segments.some((segment) => segment === '' || segment === '.' || segment === '..')
  ) {
    throw new Error(`unsafe artifact path ${JSON.stringify(artifactPath)}`)
  }
  const bundleRoot = resolve(directory)
  const absolutePath = resolve(bundleRoot, ...segments)
  const fromBundle = relative(bundleRoot, absolutePath)
  if (
    fromBundle === ''
    || fromBundle.startsWith('..')
    || isAbsolute(fromBundle)
  ) {
    throw new Error(`artifact escapes the run bundle: ${artifactPath}`)
  }
  return { absolutePath, normalized }
}

function isContainedPath(root, candidate, { allowRoot = false } = {}) {
  const fromRoot = relative(root, candidate)
  return (
    (allowRoot && fromRoot === '')
    || (
      fromRoot !== ''
      && !fromRoot.startsWith('..')
      && !isAbsolute(fromRoot)
    )
  )
}

async function canonicalBundleRoot(directory) {
  const lexicalRoot = resolve(directory)
  const metadata = await lstat(lexicalRoot)
  if (metadata.isSymbolicLink()) {
    throw new Error(
      `run bundle must not be a symbolic link or reparse point: ${lexicalRoot}`,
    )
  }
  if (!metadata.isDirectory()) {
    throw new Error(`run bundle is not a directory: ${lexicalRoot}`)
  }
  return {
    lexicalRoot,
    canonicalRoot: await realpath(lexicalRoot),
  }
}

async function assertSafeExistingBundlePath(
  directory,
  artifactPath,
  { expectedType = 'file' } = {},
) {
  const root = await canonicalBundleRoot(directory)
  const resolved = resolveBundleArtifactPath(root.lexicalRoot, artifactPath)
  const segments = resolved.normalized.split('/')
  let current = root.lexicalRoot
  let metadata
  for (const [index, segment] of segments.entries()) {
    current = join(current, segment)
    metadata = await lstat(current)
    if (metadata.isSymbolicLink()) {
      throw new Error(
        `bundle path contains a symbolic link or reparse point: ${resolved.normalized}`,
      )
    }
    if (index < segments.length - 1 && !metadata.isDirectory()) {
      throw new Error(`bundle path parent is not a directory: ${resolved.normalized}`)
    }
  }
  if (expectedType === 'file' && !metadata.isFile()) {
    throw new Error(`bundle artifact is not a regular file: ${resolved.normalized}`)
  }
  if (expectedType === 'directory' && !metadata.isDirectory()) {
    throw new Error(`bundle path is not a directory: ${resolved.normalized}`)
  }
  const canonicalPath = await realpath(resolved.absolutePath)
  if (!isContainedPath(root.canonicalRoot, canonicalPath)) {
    throw new Error(`bundle path escapes its canonical root: ${resolved.normalized}`)
  }
  return {
    ...resolved,
    canonicalPath,
    canonicalRoot: root.canonicalRoot,
  }
}

async function readSafeBundleFile(directory, artifactPath, options = {}) {
  const resolved = await assertSafeExistingBundlePath(
    directory,
    artifactPath,
    { expectedType: 'file' },
  )
  const content = await readBoundedFile(
    resolved.absolutePath,
    options.maxBytes ?? MAX_BUNDLE_ARTIFACT_BYTES,
    options.label ?? `bundle artifact ${resolved.normalized}`,
  )
  await assertSafeExistingBundlePath(directory, artifactPath, { expectedType: 'file' })
  return { ...resolved, content }
}

async function digestSafeBundleFile(directory, artifactPath, maxBytes) {
  const resolved = await assertSafeExistingBundlePath(
    directory,
    artifactPath,
    { expectedType: 'file' },
  )
  let handle
  try {
    handle = await open(resolved.absolutePath, OPEN_READ_ONLY_NO_FOLLOW)
    const metadata = await handle.stat()
    if (!metadata.isFile()) {
      throw new Error(`bundle artifact is not a regular file: ${resolved.normalized}`)
    }
    if (metadata.size > maxBytes) {
      throw new Error(
        `bundle artifact ${resolved.normalized} exceeds the ${maxBytes}-byte ` +
        'remaining verification limit',
      )
    }
    const digest = createHash('sha256')
    const buffer = Buffer.allocUnsafe(64 * 1024)
    let bytes = 0
    while (true) {
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null)
      if (bytesRead === 0) break
      bytes += bytesRead
      if (bytes > maxBytes) {
        throw new Error(
          `bundle artifact ${resolved.normalized} exceeds the ${maxBytes}-byte ` +
          'remaining verification limit',
        )
      }
      digest.update(buffer.subarray(0, bytesRead))
    }
    return { ...resolved, bytes, sha256: digest.digest('hex') }
  } finally {
    await handle?.close()
    await assertSafeExistingBundlePath(
      directory,
      artifactPath,
      { expectedType: 'file' },
    )
  }
}

async function ensureSafeBundleSubdirectory(directory, artifactPath) {
  const root = await canonicalBundleRoot(directory)
  const resolved = resolveBundleArtifactPath(root.lexicalRoot, artifactPath)
  const segments = resolved.normalized.split('/')
  let current = root.lexicalRoot
  for (const segment of segments) {
    current = join(current, segment)
    let metadata
    try {
      metadata = await lstat(current)
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
      await mkdir(current)
      metadata = await lstat(current)
    }
    if (metadata.isSymbolicLink()) {
      throw new Error(
        `bundle path contains a symbolic link or reparse point: ${resolved.normalized}`,
      )
    }
    if (!metadata.isDirectory()) {
      throw new Error(`bundle path is not a directory: ${resolved.normalized}`)
    }
    const canonicalPath = await realpath(current)
    if (!isContainedPath(root.canonicalRoot, canonicalPath)) {
      throw new Error(`bundle path escapes its canonical root: ${resolved.normalized}`)
    }
  }
  return resolved.absolutePath
}

async function verifyAllBundleArtifacts(directory, run) {
  const paths = new Map()
  const artifacts = Object.entries(run.artifacts ?? {})
  if (artifacts.length > MAX_BUNDLE_ARTIFACTS) {
    throw new Error(
      `run declares ${artifacts.length} artifacts; limit is ${MAX_BUNDLE_ARTIFACTS}`,
    )
  }
  let verifiedBytes = 0
  for (const [key, artifact] of artifacts) {
    const { absolutePath, normalized } = resolveBundleArtifactPath(
      directory,
      artifact.path,
    )
    const priorKey = paths.get(normalized)
    if (priorKey !== undefined) {
      throw new Error(
        `artifact keys ${priorKey} and ${key} alias the same bundle path`,
      )
    }
    paths.set(normalized, key)
    let verified
    try {
      verified = await digestSafeBundleFile(
        directory,
        normalized,
        Math.min(
          MAX_BUNDLE_ARTIFACT_BYTES,
          MAX_BUNDLE_VERIFICATION_BYTES - verifiedBytes,
        ),
      )
    } catch (error) {
      throw new Error(`cannot read artifact ${key} at ${normalized}: ${error.message}`)
    }
    verifiedBytes += verified.bytes
    if (verified.sha256.toLowerCase() !== artifact.sha256.toLowerCase()) {
      throw new Error(`artifact digest mismatch for ${key} at ${normalized}`)
    }
  }
  return {
    artifactCount: artifacts.length,
    artifactBytes: verifiedBytes,
  }
}

function parseVerifiedJson(committed) {
  try {
    return JSON.parse(verifiedArtifactUtf8(committed))
  } catch (error) {
    throw new Error(`invalid JSON in ${committed.absolutePath}: ${error.message}`)
  }
}

async function verifyDeclaredSealedSnapshot(directory, run, field, name) {
  const descriptor = run[field]
  if (!descriptor) return null
  const expectedKind = name === 'source' ? 'source' : 'control'
  const indexPath = `snapshots/${name}/index.json`
  const committed = await readVerifiedArtifact(
    directory,
    run,
    descriptor.index_artifact_key,
    indexPath,
  )
  if (sha256(committed.content) !== descriptor.root_sha256) {
    throw new Error(`${name} snapshot root digest does not match its canonical index`)
  }
  const index = parseSealedSnapshotIndex(committed.content)
  if (index.snapshot_kind !== expectedKind) {
    throw new Error(`${name} snapshot index has kind ${index.snapshot_kind}`)
  }
  const verification = await verifySealedSnapshot(
    index,
    async (shardId) => {
      const key = `${name}_snapshot_${shardId}`
      const path = `snapshots/${name}/${shardId}.bin`
      const shard = await readVerifiedArtifact(directory, run, key, path)
      return shard.content
    },
  )
  const availableBytes = index.files
    .filter(({ availability }) => availability === 'AVAILABLE')
    .reduce((total, { size }) => total + size, 0)
  if (
    verification.available_files !== descriptor.available_files
    || availableBytes !== descriptor.available_bytes
  ) {
    throw new Error(`${name} snapshot availability does not match the run descriptor`)
  }
  return index
}

function assertSignedFindingReflectedInRun(run, job, signedFinding) {
  const current = run.findings.find(
    ({ candidate_id: candidateId }) =>
      candidateId === signedFinding.candidate_id,
  )
  if (!current) {
    throw new Error(
      `observed execution ${job.job_id} finding ${signedFinding.candidate_id} is absent from the run`,
    )
  }
  for (const [field, signedValue] of Object.entries(signedFinding)) {
    if (field === 'location') {
      const currentLocations = new Set(current.location ?? [])
      if (signedValue.some((location) => !currentLocations.has(location))) {
        throw new Error(
          `observed execution ${job.job_id} finding ${signedFinding.candidate_id} lost a signed location`,
        )
      }
      continue
    }
    if (stableJson(current[field], 0) !== stableJson(signedValue, 0)) {
      throw new Error(
        `observed execution ${job.job_id} finding ${signedFinding.candidate_id} ` +
        `does not retain signed field ${field}`,
      )
    }
  }
}

function assertObservedResultReflectedInRun(run, job, result) {
  for (const finding of result.findings) {
    assertSignedFindingReflectedInRun(run, job, finding)
  }

  const runGapKeys = new Set(
    run.coverage.gaps.map((gap) => stableJson(gap, 0)),
  )
  for (const gap of result.coverage_gaps) {
    if (!runGapKeys.has(stableJson(gap, 0))) {
      throw new Error(
        `observed execution ${job.job_id} signed coverage gap is absent from the run`,
      )
    }
  }

  if (job.kind === 'LENS') {
    const row = run.coverage.lenses.find(({ lens }) => lens === job.lens)
    const expectedPaths = result.state === 'SUCCEEDED'
      ? [...result.examined_files]
        .sort((left, right) => compareCanonicalStrings(left, right))
      : []
    const aggregatePaths = new Set(row?.examined_paths ?? [])
    if (!row || expectedPaths.some((path) => !aggregatePaths.has(path))) {
      throw new Error(
        `observed execution ${job.job_id} examined-file coverage is absent from its lens aggregate`,
      )
    }
  }

  const profilesById = new Map(
    (run.store_profiles ?? []).map((profile) => [
      profile.store_context.store_id,
      profile,
    ]),
  )
  for (const profile of result.store_profiles ?? []) {
    const storeId = profile.store_context.store_id
    if (
      stableJson(profilesById.get(storeId), 0)
      !== stableJson(profile, 0)
    ) {
      throw new Error(
        `observed execution ${job.job_id} store profile ${storeId} diverges from its signed result`,
      )
    }
  }

  if (result.state === 'FAILED') {
    const matchingError = run.errors.some((entry) => (
      entry.job_id === job.job_id
      && entry.code === result.error.code
      && entry.message === result.error.message
      && entry.recoverable === result.error.recoverable
    ))
    if (job.reason !== result.error.message || !matchingError) {
      throw new Error(
        `observed execution ${job.job_id} failure state diverges from its signed result`,
      )
    }
  }
}

export async function verifyControlBundle(
  directory,
  run,
  {
    requireCurrentLensPack = false,
    pinnedReceiptKeyId = undefined,
  } = {},
) {
  const artifactCapacity = await verifyAllBundleArtifacts(directory, run)
  const committed = await readVerifiedArtifact(
    directory,
    run,
    'inventory',
    'inventory.json',
  )
  const snapshot = parseVerifiedJson(committed)
  if (
    snapshot.root !== run.repository.root ||
    snapshot.tree_digest !== run.repository.tree_digest
  ) {
    throw new Error('inventory artifact does not match the run repository provenance')
  }

  const expectedInventory = snapshot.entries.map(({ path }) => path)
  const expectedIncluded = expectedInventory.length > 0 ? expectedInventory : ['.']
  if (stableJson(run.coverage.inventory) !== stableJson(expectedInventory)) {
    throw new Error('run coverage denominator does not match the hashed inventory artifact')
  }
  if (stableJson(run.scope.included_paths) !== stableJson(expectedIncluded)) {
    throw new Error('run included scope does not match the hashed inventory artifact')
  }
  if (stableJson(run.scope.excluded_paths) !== stableJson(snapshot.excluded)) {
    throw new Error('run excluded scope does not match the hashed inventory artifact')
  }

  const policyCommitted = await readVerifiedArtifact(
    directory,
    run,
    'policy',
    'policy.json',
  )
  const policy = parseVerifiedJson(policyCommitted)
  if (
    policy.workspace_root !== run.repository.root
    || sha256(stableJson(policy, 0)) !== run.policy_digest
  ) {
    throw new Error('policy artifact does not match the run provenance')
  }
  if (
    !['static', 'remote_static', 'test', 'local_dynamic'].includes(policy.mode)
    || !['STATIC', 'TEST_EXECUTION', 'LOCAL_DYNAMIC'].includes(run.capability_mode)
  ) {
    throw new Error(
      `${PLATFORM_VERSION} can dispatch and ingest only STATIC, TEST_EXECUTION, and LOCAL_DYNAMIC runs`,
    )
  }
  const policyRoots = policy.capabilities?.read_file?.enabled
    ? policy.capabilities.read_file.roots
    : []
  if (
    stableJson(normalizeIncludedRoots(snapshot.limits?.includedRoots ?? ['.']))
    !== stableJson(normalizeIncludedRoots(policyRoots))
  ) {
    throw new Error('inventory read roots do not match the Rules of Engagement')
  }

  const plannedCoverageCommitted = await readVerifiedArtifact(
    directory,
    run,
    'coverage_plan',
    'coverage-plan.json',
  )
  const plannedCoverage = parseVerifiedJson(plannedCoverageCommitted)
  assertImmutableCoveragePlan(
    run,
    plannedCoverage,
    snapshot,
    expectedInventory,
  )
  let databaseDiscoveryCommitted
  let databaseConformanceCommitted
  if (['3.0.0', '4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(run.schema_version)) {
    databaseDiscoveryCommitted = await readVerifiedArtifact(
      directory,
      run,
      'database_discovery',
      'database-discovery.json',
    )
    const databaseDiscovery = parseVerifiedJson(databaseDiscoveryCommitted)
    const discoveryValidation = validateDatabaseDiscovery(databaseDiscovery)
    if (!discoveryValidation.valid) {
      throw new Error(
        `database discovery artifact is invalid: ${discoveryValidation.errors.join('; ')}`,
      )
    }
    if (
      serializeDatabaseDiscovery(databaseDiscovery)
      !== serializeDatabaseDiscovery(run.database_discovery)
    ) {
      throw new Error('database discovery artifact does not match the canonical run graph')
    }
  }
  if (run.database_conformance) {
    databaseConformanceCommitted = await readVerifiedArtifact(
      directory,
      run,
      'database_conformance',
      'database-conformance.json',
    )
    const databaseConformance = parseVerifiedJson(databaseConformanceCommitted)
    if (stableJson(databaseConformance) !== stableJson(run.database_conformance)) {
      throw new Error(
        'database conformance artifact does not match the canonical run evidence',
      )
    }
  } else if (run.artifacts?.database_conformance) {
    throw new Error(
      'database conformance artifact exists without canonical run evidence',
    )
  }
  if (run.artifacts?.coverage) {
    const finalCoverageCommitted = await readVerifiedArtifact(
      directory,
      run,
      'coverage',
      'coverage.json',
    )
    const finalCoverage = parseVerifiedJson(finalCoverageCommitted)
    if (stableJson(finalCoverage) !== stableJson(run.coverage)) {
      throw new Error('final coverage artifact does not match canonical run coverage')
    }
  }
  const lensPackCommitted = await readVerifiedArtifact(
    directory,
    run,
    'lens_pack',
    'lens-pack.json',
  )
  const lensPack = parseVerifiedJson(lensPackCommitted)
  if (
    lensPack === null
    || typeof lensPack !== 'object'
    || Array.isArray(lensPack)
    || lensPack.schema_version !== 1
    || !Array.isArray(lensPack.files)
    || typeof lensPack.digest !== 'string'
  ) {
    throw new Error('hashed lens-pack manifest has an invalid shape')
  }
  const bundledLensFiles = new Map()
  for (const entry of lensPack.files) {
    if (
      entry === null
      || typeof entry !== 'object'
      || Array.isArray(entry)
      || typeof entry.path !== 'string'
      || !/^[a-fA-F0-9]{64}$/.test(entry.sha256)
      || !Number.isSafeInteger(entry.size)
      || entry.size < 0
      || bundledLensFiles.has(entry.path)
    ) {
      throw new Error('hashed lens-pack manifest contains an invalid or duplicate file entry')
    }
    bundledLensFiles.set(entry.path, entry)
  }
  const bundledDigest = sha256(JSON.stringify(lensPack.files.map(
    ({ path, sha256: digest, size }) => [path, digest, size],
  )))
  if (
    lensPack.digest !== run.lens_pack_digest
    || run.tool?.corpus_sha256 !== run.lens_pack_digest
    || bundledDigest !== lensPack.digest
  ) {
    throw new Error('lens-pack manifest does not match the run provenance')
  }
  if (
    run.lens_shared_contract_digest !== undefined
    && lensSharedContractDigest(lensPack) !== run.lens_shared_contract_digest
  ) {
    throw new Error('shared lens contract digest does not match the run provenance')
  }
  const controlSnapshot = await verifyDeclaredSealedSnapshot(
    directory,
    run,
    'control_snapshot',
    'control',
  )
  const sourceSnapshot = await verifyDeclaredSealedSnapshot(
    directory,
    run,
    'source_snapshot',
    'source',
  )
  if (sourceSnapshot) {
    if (sourceSnapshot.source_tree_digest !== run.repository.tree_digest) {
      throw new Error('source snapshot is not bound to the planned repository tree')
    }
    const sourceRecords = sourceSnapshot.files.map(
      ({ path, kind, size, sha256: digest }) => ({
        path,
        kind,
        size,
        sha256: digest,
      }),
    )
    const inventoryRecords = snapshot.entries.map(
      ({ path, kind, size, sha256: digest }) => ({
        path,
        kind,
        size,
        sha256: digest,
      }),
    )
    if (stableJson(sourceRecords) !== stableJson(inventoryRecords)) {
      throw new Error('source snapshot file manifest differs from the planned inventory')
    }
  }
  if (controlSnapshot) {
    const controlFiles = new Map(
      controlSnapshot.files.map((file) => [file.path, file]),
    )
    const providerPolicyContent = Buffer.from(stableJson(
      providerPolicyProjection(policy, run.policy_digest),
    ), 'utf8')
    const completenessInputsContent = run.coverage?.completeness_inputs === undefined
      ? undefined
      : Buffer.from(stableJson(run.coverage.completeness_inputs), 'utf8')
    for (const [path, expected] of [
      ['controls/policy.json', run.artifacts.policy],
      ['controls/provider-policy.json', {
        sha256: sha256(providerPolicyContent),
        size: providerPolicyContent.length,
      }],
      ['controls/lens-pack.json', run.artifacts.lens_pack],
      ...(completenessInputsContent
        ? [['controls/completeness-inputs.json', {
            sha256: sha256(completenessInputsContent),
            size: completenessInputsContent.length,
          }]]
        : []),
      ...(['3.0.0', '4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(run.schema_version)
        ? [['controls/database-discovery.json', run.artifacts.database_discovery]]
        : []),
      ...(run.database_conformance
        ? [['controls/database-conformance.json', run.artifacts.database_conformance]]
        : []),
      ...lensPack.files
        .filter(({ path }) =>
          !path.includes('/')
          && path.endsWith('.md')
          && !path.startsWith('_'))
        .map((entry) => [`lenses/${entry.path}`, entry]),
    ]) {
      const actual = controlFiles.get(path)
      if (
        !actual
        || actual.availability !== 'AVAILABLE'
        || actual.sha256 !== expected.sha256.toLowerCase()
        || actual.size !== (
          path === 'controls/policy.json'
            ? policyCommitted.content.length
            : path === 'controls/provider-policy.json'
              ? providerPolicyContent.length
            : path === 'controls/lens-pack.json'
              ? lensPackCommitted.content.length
              : path === 'controls/database-discovery.json'
                ? databaseDiscoveryCommitted.content.length
              : path === 'controls/database-conformance.json'
                ? databaseConformanceCommitted.content.length
              : expected.size
        )
      ) {
        throw new Error(`control snapshot does not bind trusted input ${path}`)
      }
    }
  }

  const sidecars = []
  let bundledKnownTopics
  const plannedJobs = run.jobs.filter(
    ({ kind, lens }) =>
      lens && ['LENS', 'TRIAGE', 'COMPLETENESS'].includes(kind),
  )
  for (const job of plannedJobs) {
    const expected = lensSidecarArtifact(job)
    const sidecarCommitted = await readVerifiedArtifact(
      directory,
      run,
      expected.key,
      expected.path,
    )
    const sidecar = parseVerifiedJson(sidecarCommitted)
    assertSidecarJobIdentity(run, job, sidecar, plannedCoverage)
    const bundledLens = bundledLensFiles.get(sidecar.lens_file)
    if (
      bundledLens === undefined
      || sidecar.lens_digest !== bundledLens.sha256
      || !Array.isArray(sidecar.owned_topics)
      || !Array.isArray(sidecar.known_topics)
      || sidecar.owned_topics.some((topic) => !sidecar.known_topics.includes(topic))
      || (
        Array.isArray(sidecar.topic_obligations)
        && stableJson(sidecar.topic_obligations) !== stableJson(sidecar.owned_topics)
      )
    ) {
      throw new Error(`sidecar authority does not match its bundled lens manifest for ${job.job_id}`)
    }
    if (bundledKnownTopics === undefined) {
      bundledKnownTopics = sidecar.known_topics
    } else if (stableJson(sidecar.known_topics) !== stableJson(bundledKnownTopics)) {
      throw new Error(`sidecar known-topic denominator differs for ${job.job_id}`)
    }
    if (!sidecar.activated && job.state !== 'SKIPPED') {
      throw new Error(`inactive planned job ${job.job_id} must remain SKIPPED`)
    }
    sidecars.push(sidecar)
  }

  const expectedActivated = [...new Set(
    sidecars
      .filter(({ activated }) => activated)
      .map(({ lens }) => lens),
  )]
  if (stableJson(run.activated_lenses) !== stableJson(expectedActivated)) {
    throw new Error('activated lens set does not match the hashed job plan')
  }
  const verifiedExecutionEnvelopes = new Map()
  const verifiedRemoteAcceptances = new Map()
  const verifiedServiceProofReceipts = new Map()
  let evidenceKeyId = pinnedReceiptKeyId
  const attempts = (run.attempt_events ?? [])
    .filter(({ event }) => event === 'LEASED')
    .map(({ attempt_id: attemptId }) =>
      findProviderAttempt(run, attemptId))
  for (const attempt of attempts) {
    const job = run.jobs.find(({ job_id: jobId }) => jobId === attempt.job_id)
    if (!job) {
      throw new Error(
        `provider attempt ${attempt.attempt_id} references an unknown job`,
      )
    }
    const serviceProofAttempt = attempt.lease.backend === 'SERVICE_PROOF_CONTAINER'
    const sidecar = sidecars.find(({ job_id: jobId }) => jobId === job.job_id)
    const expectedArtifacts = serviceProofAttempt
      ? null
      : observedProviderArtifactDescriptors(
          run,
          job,
          sidecar,
          {
            sealedSnapshots: {
              control: controlSnapshot,
              source: sourceSnapshot,
            },
          },
        )
    if (attempt.lease.backend === 'REMOTE_GATEWAY') {
      const request = await readRemoteRequestArtifact(
        { directory, run },
        attempt,
      )
      const actualArtifacts = new Map(request.envelope.artifacts.map(
        (artifact) => [artifact.artifact_id, artifact],
      ))
      if (actualArtifacts.size !== expectedArtifacts.size) {
        throw new Error(
          `remote request ${attempt.lease.request_id} does not contain the exact planned artifact set`,
        )
      }
      for (const [artifactId, expected] of expectedArtifacts) {
        const actual = actualArtifacts.get(artifactId)
        if (
          !actual
          || actual.kind !== expected.artifact_kind
          || actual.logical_name !== expected.logical_name
          || actual.sha256 !== expected.expected_sha256
          || actual.size !== expected.size
        ) {
          throw new Error(
            `remote request ${attempt.lease.request_id} artifact ${artifactId} differs from the sealed plan`,
          )
        }
      }
    }
    if (attempt.execution_artifact_key !== undefined) {
      if (attempt.lease.backend === 'REMOTE_GATEWAY') {
        const acceptance = await readRemoteAcceptanceArtifact(
          { directory, run },
          attempt,
        )
        verifiedRemoteAcceptances.set(attempt.attempt_id, acceptance)
      } else if (serviceProofAttempt) {
        const receipt = await readServiceProofAttemptReceipt(
          { directory, run },
          attempt,
        )
        verifiedServiceProofReceipts.set(attempt.attempt_id, receipt)
      } else {
        const envelope = await readAttemptEnvelope(
          { directory, run },
          attempt,
          evidenceKeyId,
        )
        evidenceKeyId ??= envelope.controller.key_id
        verifiedExecutionEnvelopes.set(attempt.attempt_id, envelope)
      }
    }
    if (attempt.failure_artifact_key !== undefined) {
      if (attempt.lease.backend === 'REMOTE_GATEWAY') {
        throw new Error('remote gateway attempts cannot use container failure envelopes')
      }
      if (serviceProofAttempt) {
        throw new Error('service-proof attempts cannot use provider failure envelopes')
      }
      const envelope = await readAttemptFailureEnvelope(
        { directory, run },
        attempt,
        {
          expectedArtifacts,
          pinnedKeyId: evidenceKeyId,
        },
      )
      evidenceKeyId ??= envelope.controller.key_id
    }
  }
  for (const job of run.jobs.filter(
    ({ coverage_authority: authority }) =>
      authority === 'CONTROLLER_OBSERVED_CONSUMPTION',
  )) {
    const attempt = findProviderAttempt(run, job.attempt_id)
    if (attempt.lease.backend === 'SERVICE_PROOF_CONTAINER') continue
    const envelope = verifiedExecutionEnvelopes.get(attempt.attempt_id)
    if (!envelope) {
      throw new Error(
        `observed job ${job.job_id} has no verified execution envelope`,
      )
    }
    const execution = envelope.provider_execution
    const result = execution.job_result
    if (
      result.job_id !== job.job_id
      || result.state !== job.state
      || result.input_sha256.toLowerCase() !== job.input_sha256.toLowerCase()
      || stableJson(result.producer) !== stableJson(job.producer)
      || envelope.controller.receipt_sha256 !== job.receipt_sha256
    ) {
      throw new Error(`observed execution envelope does not match job ${job.job_id}`)
    }
    const resultCandidateIds = result.findings
      .map(({ candidate_id: candidateId }) => candidateId)
      .sort((left, right) => compareCanonicalStrings(left, right))
    const jobCandidateIds = [...(job.candidate_ids ?? [])]
      .sort((left, right) => compareCanonicalStrings(left, right))
    if (stableJson(resultCandidateIds) !== stableJson(jobCandidateIds)) {
      throw new Error(`observed execution findings do not match job ${job.job_id}`)
    }
    assertObservedResultReflectedInRun(run, job, result)
    const observedSidecar = sidecars.find(({ job_id: jobId }) => jobId === job.job_id)
    const consumedControls = new Set(
      execution.receipt.deliveries
        .filter((delivery) =>
          delivery.artifact_kind === 'CONTROL'
          && delivery.events?.[1]?.state === 'CONSUMED')
        .map(({ logical_name: logicalName }) => logicalName),
    )
    for (const requiredControl of [
      'controls/provider-policy.json',
      'controls/lens-pack.json',
      ...(observedSidecar?.lens === 'database-and-data-stores'
        ? ['controls/database-discovery.json']
        : []),
      ...(
        observedSidecar?.kind === 'COMPLETENESS'
        && observedSidecar?.completeness_inputs !== undefined
          ? ['controls/completeness-inputs.json']
          : []
      ),
      ...(
        observedSidecar?.lens === 'database-and-data-stores'
        && run.database_conformance
          ? ['controls/database-conformance.json']
          : []
      ),
      ...(observedSidecar?.lens_file
        ? [`lenses/${observedSidecar.lens_file}`]
        : []),
    ]) {
      if (!consumedControls.has(requiredControl)) {
        throw new Error(
          `observed execution ${job.job_id} did not consume ${requiredControl}`,
        )
      }
    }
    if (sourceSnapshot) {
      await assertObservedSourceAnchors(
        directory,
        run,
        job,
        execution,
        sourceSnapshot,
      )
    }
  }
  for (const job of run.jobs.filter(
    ({ coverage_authority: authority }) =>
      authority === 'CONTROLLER_OBSERVED_CONSUMPTION',
  )) {
    const attempt = findProviderAttempt(run, job.attempt_id)
    if (attempt.lease.backend !== 'SERVICE_PROOF_CONTAINER') continue
    const receipt = verifiedServiceProofReceipts.get(attempt.attempt_id)
    if (!receipt) {
      throw new Error(
        `service-proof job ${job.job_id} has no verified controller receipt`,
      )
    }
    assertServiceProofReceiptMatchesCommittedJob(run, job, attempt, receipt)
  }
  for (const job of run.jobs.filter(
    ({ coverage_authority: authority }) =>
      authority === 'REMOTE_REQUEST_ACCEPTED',
  )) {
    const attempt = findProviderAttempt(run, job.attempt_id)
    const acceptance = verifiedRemoteAcceptances.get(attempt.attempt_id)
    if (!acceptance) {
      throw new Error(
        `remote job ${job.job_id} has no verified gateway acceptance`,
      )
    }
    const result = acceptance.envelope.job_result
    if (
      result.job_id !== job.job_id
      || result.state !== job.state
      || result.input_sha256.toLowerCase() !== job.input_sha256.toLowerCase()
      || stableJson(result.producer) !== stableJson(job.producer)
      || attempt.execution_artifact_sha256 !== job.receipt_sha256
    ) {
      throw new Error(`remote acceptance does not match job ${job.job_id}`)
    }
    const resultCandidateIds = result.findings
      .map(({ candidate_id: candidateId }) => candidateId)
      .sort((left, right) => compareCanonicalStrings(left, right))
    const jobCandidateIds = [...(job.candidate_ids ?? [])]
      .sort((left, right) => compareCanonicalStrings(left, right))
    if (stableJson(resultCandidateIds) !== stableJson(jobCandidateIds)) {
      throw new Error(`remote acceptance findings do not match job ${job.job_id}`)
    }
    assertObservedResultReflectedInRun(run, job, result)
    if (sourceSnapshot) {
      await assertRemoteSourceAnchors(
        directory,
        run,
        job,
        acceptance.request,
        result,
        sourceSnapshot,
      )
    }
  }
  const planMaterial = {
    schema_version: run.schema_version,
    capability_mode: run.capability_mode,
    repository: { tree_digest: run.repository.tree_digest },
    policy_digest: run.policy_digest,
    lens_pack_digest: run.lens_pack_digest,
    ...(run.lens_shared_contract_digest
      ? { lens_shared_contract_digest: run.lens_shared_contract_digest }
      : {}),
    ...(['3.0.0', '4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(run.schema_version)
      ? {
          coverage_policy: run.coverage.policy,
          database_discovery_digest: run.database_discovery.digest,
          ...(run.coverage?.completeness_inputs
            ? {
                completeness_inputs_sha256: sha256(
                  stableJson(run.coverage.completeness_inputs, 0),
                ),
              }
            : {}),
          // Pinned so the evidence-class matrix cannot be edited after
          // planning. Conditional because a run planned before the matrix
          // existed carries none and must still validate.
          ...(run.evidence_coverage
            ? {
                evidence_coverage_sha256: sha256(
                  stableJson(run.evidence_coverage, 0),
                ),
              }
            : {}),
          ...(run.database_conformance
            ? {
                database_conformance_sha256: sha256(
                  stableJson(run.database_conformance, 0),
                ),
              }
            : {}),
        }
      : {}),
    control_snapshot_sha256: run.control_snapshot?.root_sha256,
    ...(run.source_snapshot
      ? { source_snapshot_sha256: run.source_snapshot.root_sha256 }
      : {}),
    jobs: sidecars,
  }
  if (sha256(stableJson(planMaterial, 0)) !== run.plan_digest) {
    throw new Error('plan digest does not match the hashed control-plane inputs')
  }
  if (requireCurrentLensPack) {
    const [currentLensPack, currentLenses] = await Promise.all([
      digestLensPack(DEFAULT_LENS_DIRECTORY),
      loadLenses(DEFAULT_LENS_DIRECTORY),
    ])
    if (stableJson(lensPack) !== stableJson(currentLensPack)) {
      throw new Error('trusted lens pack changed after planning')
    }
    const currentLensByName = new Map(currentLenses.map((lens) => [lens.name, lens]))
    const currentKnownTopics = [...new Set(currentLenses.flatMap(
      (lens) => lens.frontmatter.owns ?? [],
    ))].sort((left, right) => compareCanonicalStrings(left, right))
    for (const sidecar of sidecars) {
      const currentLens = currentLensByName.get(sidecar.lens)
      const expectedOwnedTopics = [...(currentLens?.frontmatter.owns ?? [])]
        .sort((left, right) => compareCanonicalStrings(left, right))
      if (
        currentLens === undefined
        || sidecar.lens_file !== currentLens.file
        || sidecar.lens_digest !== currentLens.digest
        || stableJson(sidecar.owned_topics) !== stableJson(expectedOwnedTopics)
        || (
          Array.isArray(sidecar.topic_obligations)
          && stableJson(sidecar.topic_obligations) !== stableJson(expectedOwnedTopics)
        )
        || stableJson(sidecar.known_topics) !== stableJson(currentKnownTopics)
      ) {
        throw new Error(`sidecar topic or lens authority mismatch for ${sidecar.job_id}`)
      }
    }
  }
  return {
    snapshot,
    policy,
    lensPack,
    sidecars,
    artifactCapacity,
    evidenceKeyId,
    sealedSnapshots: {
      control: controlSnapshot,
      source: sourceSnapshot,
    },
  }
}

export async function verifyRepositorySnapshot(directory, run) {
  const control = await verifyControlBundle(
    directory,
    run,
    { requireCurrentLensPack: true },
  )
  const { snapshot } = control
  const current = await inventoryRepository(run.repository.root, {
    maxTextBytes: snapshot.limits?.maxTextBytes,
    includedRoots: snapshot.limits?.includedRoots,
  })
  const currentSecurityView = {
    tree_digest: current.treeDigest,
    entries: serializeInventory(current).entries,
    errors: current.errors,
    limits: current.limits,
  }
  const committedSecurityView = {
    tree_digest: snapshot.tree_digest,
    entries: snapshot.entries,
    errors: snapshot.errors,
    limits: snapshot.limits,
  }
  if (stableJson(currentSecurityView) !== stableJson(committedSecurityView)) {
    throw new Error(
      'repository snapshot changed after planning; create a new run before dispatching or ingesting work',
    )
  }
  return { ...control, inventoryEntries: current.entries }
}

async function loadJobSidecar(directory, run, job) {
  if (!['LENS', 'TRIAGE', 'COMPLETENESS'].includes(job.kind)) return undefined
  const expected = lensSidecarArtifact(job)
  const committed = await readVerifiedArtifact(
    directory,
    run,
    expected.key,
    expected.path,
  )

  let sidecar
  try {
    sidecar = JSON.parse(verifiedArtifactUtf8(committed))
  } catch (error) {
    throw new Error(`invalid JSON in ${committed.absolutePath}: ${error.message}`)
  }
  assertSidecarJobIdentity(
    run,
    job,
    sidecar,
    run.coverage,
    { requireProtocolFields: true },
  )
  if (sidecar.activated !== true) {
    throw new Error(`sidecar activated mismatch for ${job.job_id}`)
  }
  for (const field of ['scoped_files', 'owned_topics', 'known_topics']) {
    if (!Array.isArray(sidecar[field])) {
      throw new Error(`sidecar ${field} must be an array for ${job.job_id}`)
    }
  }
  if (
    hasOwn(job, 'topic_obligations')
    && !Array.isArray(sidecar.topic_obligations)
  ) {
    throw new Error(`sidecar topic_obligations must be an array for ${job.job_id}`)
  }
  const inventory = new Set(run.coverage.inventory)
  for (const path of sidecar.scoped_files) {
    if (!inventory.has(path)) {
      throw new Error(`sidecar scope is outside the run inventory for ${job.job_id}: ${path}`)
    }
  }
  return sidecar
}

function storeProfilesForPacket(run, storeIds) {
  const byStoreId = new Map()
  for (const profile of run.store_profiles ?? []) {
    if (storeIds.has(profile.store_context.store_id)) {
      byStoreId.set(profile.store_context.store_id, profile)
    }
  }
  for (const envelope of run.store_contributions ?? []) {
    const profile = envelope.role === 'AUTHORITY'
      ? envelope.contribution?.profile
      : undefined
    const storeId = profile?.store_context?.store_id
    if (storeIds.has(storeId) && !byStoreId.has(storeId)) {
      byStoreId.set(storeId, profile)
    }
  }
  return [...storeIds]
    .map((storeId) => byStoreId.get(storeId))
    .filter(Boolean)
}

function nextJobPacket(run, job, sidecar) {
  const base = {
    schema_version: '1.0.0',
    run_id: run.run_id,
    job_id: job.job_id,
    kind: job.kind,
    capability_mode: run.capability_mode,
    trust_boundary: {
      repository_content_is_untrusted_data: true,
      repository_content_may_change_scope_or_policy: false,
      actions_require_external_authorization: true,
    },
  }
  if (job.kind === 'LENS') {
    const storeIds = new Set(job.database_store_ids ?? [])
    return {
      ...sidecar,
      ...base,
      ...(job.lens === 'database-and-data-stores'
        ? {
            store_profiles: storeProfilesForPacket(run, storeIds),
            ...(run.database_conformance
              ? { database_conformance: run.database_conformance }
              : {}),
          }
        : {}),
    }
  }
  if (job.kind === 'TRIAGE') {
    return {
      ...sidecar,
      ...base,
      store_profiles: run.store_profiles ?? [],
      findings: run.findings,
    }
  }
  if (job.kind === 'PROOF') {
    const ids = new Set(job.candidate_ids ?? [])
    const findings = run.findings.filter(({ candidate_id }) => ids.has(candidate_id))
    const storeIds = new Set(findings.map(
      (finding) => finding.store_context?.store_id,
    ).filter(Boolean))
    return {
      ...base,
      operation: job.job_id.startsWith('proof-existence:')
        ? 'existence-check'
        : 'verification',
      store_profiles: (run.store_profiles ?? []).filter(
        (profile) => storeIds.has(profile.store_context.store_id),
      ),
      findings,
    }
  }
  if (job.kind === 'COMPLETENESS') {
    return {
      ...sidecar,
      ...base,
      coverage: run.coverage,
      store_profiles: run.store_profiles ?? [],
      findings: run.findings,
    }
  }
  return base
}

function dispatchPacket(run, job, sidecar) {
  const packet = nextJobPacket(run, job, sidecar)
  return {
    ...packet,
    packet_sha256: sha256(stableJson(packet, 0)),
  }
}

function observedDispatchPacket(run, job, sidecar) {
  if (!run.source_snapshot) {
    throw new Error(
      'controller-observed execution requires a runner-ready plan created with --seal-source',
    )
  }
  const candidate = {
    ...nextJobPacket(run, job, sidecar),
    schema_version: '2.0.0',
    snapshot_id: run.source_snapshot.root_sha256,
    packet_sha256: '0'.repeat(64),
  }
  const portable = sanitizeProviderPacket(candidate)
  delete portable.packet_sha256
  return {
    ...portable,
    packet_sha256: sha256(stableJson(portable, 0)),
  }
}

function sourcePathsForObservedJob(run, job, sidecar, sourceIndex) {
  return sourcePathsForJob(run, job, sidecar, sourceIndex)
}

function observedProviderArtifactDescriptors(run, job, sidecar, control) {
  const sourceIndex = control.sealedSnapshots.source
  const controlIndex = control.sealedSnapshots.control
  if (!sourceIndex || !controlIndex) {
    throw new Error('observed execution requires verified source and control snapshots')
  }
  const descriptors = new Map()
  const sourceByPath = new Map(sourceIndex.files.map((file) => [file.path, file]))
  for (const path of sourcePathsForObservedJob(run, job, sidecar, sourceIndex)) {
    const file = sourceByPath.get(path)
    if (!file || file.availability !== 'AVAILABLE') {
      throw new Error(`job ${job.job_id} requires unavailable sealed source ${path}`)
    }
    descriptors.set(file.file_id, {
      artifact_id: file.file_id,
      artifact_kind: 'FILE',
      logical_name: file.path,
      expected_sha256: file.sha256,
      size: file.size,
    })
  }
  const controlByPath = new Map(controlIndex.files.map((file) => [file.path, file]))
  const sharedLensControlPaths = controlIndex.files
    .map(({ path }) => path)
    .filter((path) => path.startsWith('lenses/_'))
  const ownerLensControlPaths = (
    Array.isArray(sidecar?.owned_topics)
    && sidecar.owned_topics.length === 0
  )
    ? controlIndex.files
        .map(({ path }) => path)
        .filter((path) => /^lenses\/(?!_)[^/]+\.md$/.test(path))
    : []
  const selectedControlPaths = new Set([
    'controls/provider-policy.json',
    'controls/lens-pack.json',
    ...(sidecar?.lens === 'database-and-data-stores'
      ? ['controls/database-discovery.json']
      : []),
    ...(
      sidecar?.kind === 'COMPLETENESS'
      && sidecar?.completeness_inputs !== undefined
        ? ['controls/completeness-inputs.json']
        : []
    ),
    ...(
      sidecar?.lens === 'database-and-data-stores'
      && run.database_conformance
        ? ['controls/database-conformance.json']
        : []
    ),
    ...(sidecar?.lens_file ? [`lenses/${sidecar.lens_file}`] : []),
    ...sharedLensControlPaths,
    // A zero-owner cross-cutting lens routes findings through registered domain
    // topics and must apply the owner's discriminator/severity rules. The
    // generated topic index names that owner but does not contain its rules,
    // so deliver the bounded sealed lens corpus rather than asking the provider
    // to guess or consult mutable external text.
    ...ownerLensControlPaths,
  ])
  for (const path of [...selectedControlPaths].sort(
    (left, right) => compareCanonicalStrings(left, right),
  )) {
    const file = controlByPath.get(path)
    if (!file || file.availability !== 'AVAILABLE') {
      throw new Error(`job ${job.job_id} requires unavailable sealed control ${path}`)
    }
    descriptors.set(file.file_id, {
      artifact_id: file.file_id,
      artifact_kind: 'CONTROL',
      logical_name: file.path,
      expected_sha256: file.sha256,
      size: file.size,
    })
  }
  return descriptors
}

async function readIndexedSnapshotFile(
  directory,
  run,
  name,
  index,
  file,
  shardCache = new Map(),
) {
  return readSealedSnapshotFile(index, file.file_id, async (shardId) => {
    if (shardCache.has(shardId)) return shardCache.get(shardId)
    const committed = await readVerifiedArtifact(
      directory,
      run,
      `${name}_snapshot_${shardId}`,
      `snapshots/${name}/${shardId}.bin`,
    )
    shardCache.set(shardId, committed.content)
    return committed.content
  })
}

async function observedProviderArtifacts(directory, run, job, sidecar, control, config) {
  const sourceIndex = control.sealedSnapshots.source
  const controlIndex = control.sealedSnapshots.control
  if (!sourceIndex || !controlIndex) {
    throw new Error('observed execution requires verified source and control snapshots')
  }
  const descriptors = observedProviderArtifactDescriptors(
    run,
    job,
    sidecar,
    control,
  )
  const sourceById = new Map(sourceIndex.files.map((file) => [file.file_id, file]))
  const controlById = new Map(controlIndex.files.map((file) => [file.file_id, file]))
  const artifacts = []
  const sourceShardCache = new Map()
  const controlShardCache = new Map()
  for (const descriptor of descriptors.values()) {
    const isSource = descriptor.artifact_kind === 'FILE'
    const file = (isSource ? sourceById : controlById).get(descriptor.artifact_id)
    const snapshotName = isSource ? 'source' : 'control'
    const index = isSource ? sourceIndex : controlIndex
    const shardCache = isSource ? sourceShardCache : controlShardCache
    artifacts.push({
      artifact_id: file.file_id,
      kind: descriptor.artifact_kind,
      logical_name: file.path,
      bytes: await readIndexedSnapshotFile(
        directory,
        run,
        snapshotName,
        index,
        file,
        shardCache,
      ),
      sha256: file.sha256,
    })
  }
  return normalizeProviderArtifacts(artifacts, config.limits)
}

function controllerSigningKey(keyBytes) {
  let privateKey
  try {
    privateKey = createPrivateKey(keyBytes)
  } catch (error) {
    throw new Error(`cannot parse controller receipt signing key: ${error.message}`)
  }
  if (privateKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('controller receipt signing key must be Ed25519')
  }
  const publicKey = createPublicKey(privateKey)
  const spki = publicKey.export({ type: 'spki', format: 'der' })
  return {
    privateKey,
    publicKey,
    publicSpkiBase64: spki.toString('base64'),
    keyId: `ed25519:${sha256(spki)}`,
  }
}

function controllerPublicKeyId(keyBytes) {
  let publicKey
  try {
    publicKey = createPublicKey(keyBytes)
  } catch (error) {
    throw new Error(`cannot parse controller receipt public key: ${error.message}`)
  }
  if (publicKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('controller receipt public key must be Ed25519')
  }
  const spki = publicKey.export({ type: 'spki', format: 'der' })
  return `ed25519:${sha256(spki)}`
}

async function loadPinnedReceiptPublicKeyId(pathValue, bundleDirectory, repositoryRoot) {
  const keyPath = await canonicalUnlinkedFile(
    pathValue,
    'controller receipt public key path',
  )
  if (
    pathWithin(resolve(bundleDirectory), keyPath)
    || pathWithin(resolve(repositoryRoot), keyPath)
  ) {
    throw new Error(
      'controller receipt public key must be pinned outside the run bundle and target repository',
    )
  }
  const keyBytes = await readBoundedFile(
    keyPath,
    MAX_SIGNING_KEY_BYTES,
    'controller receipt public key',
  )
  const keyPathAfterRead = await canonicalUnlinkedFile(
    pathValue,
    'controller receipt public key path',
  )
  if (keyPathAfterRead !== keyPath) {
    throw new Error('controller receipt public key path changed while it was being read')
  }
  return controllerPublicKeyId(keyBytes)
}

async function loadExternalTrustFile(
  pathValue,
  label,
  loaded,
  maxBytes,
) {
  const externalPath = await canonicalUnlinkedFile(pathValue, `${label} path`)
  if (
    pathWithin(resolve(loaded.directory), externalPath)
    || pathWithin(resolve(loaded.run.repository.root), externalPath)
  ) {
    throw new Error(
      `${label} must be pinned outside the run bundle and target repository`,
    )
  }
  const bytes = await readBoundedFile(externalPath, maxBytes, label)
  const pathAfterRead = await canonicalUnlinkedFile(pathValue, `${label} path`)
  if (pathAfterRead !== externalPath) {
    throw new Error(`${label} path changed while it was being read`)
  }
  return {
    bytes,
    path: externalPath,
  }
}

async function openExternalCheckpointJournal({
  pathValue,
  loaded,
  publicKeyBytes,
  expectedOrigin,
  maxClockSkewMs,
  mustExist = false,
  dependencies = {},
}) {
  if (typeof pathValue !== 'string' || !isAbsolute(pathValue)) {
    throw new Error(
      '--transparency-checkpoint-journal must name an absolute external directory',
    )
  }
  const requested = resolve(pathValue)
  if (mustExist) {
    try {
      await realpath(requested)
    } catch (error) {
      throw new Error(
        `cannot open transparency checkpoint journal ${requested}: ${error.message}`,
      )
    }
  }
  const openJournal = dependencies.openTransparencyCheckpointJournal
    ?? openTransparencyCheckpointJournal
  return openJournal({
    directory: requested,
    expectedOrigin,
    publicKeyBytes,
    maxClockSkewMs,
    readOnly: mustExist,
    now: () => new Date(),
    targetDirectory: resolve(loaded.run.repository.root),
    auditBundleDirectory: resolve(loaded.directory),
  })
}

async function loadPinnedRootAttestation(
  loaded,
  options,
  { required = false } = {},
) {
  const attestationPath = options['root-attestation']
  const publicKeyPath = options['root-public-key']
  const hasAttestation = typeof attestationPath === 'string'
  const hasPublicKey = typeof publicKeyPath === 'string'
  if (hasAttestation !== hasPublicKey) {
    throw new Error(
      '--root-attestation and --root-public-key must be supplied together',
    )
  }
  if (!hasAttestation) {
    if (required) {
      throw new Error(
        '--root-attestation and --root-public-key are required for transparency publication or verification',
      )
    }
    return {
      verification: {
        status: 'UNANCHORED',
        message:
          'run.json is valid only relative to its own unsigned artifact manifest',
      },
    }
  }
  const [attestationFile, publicKeyFile] = await Promise.all([
    loadExternalTrustFile(
      attestationPath,
      'root manifest attestation',
      loaded,
      MAX_ROOT_ATTESTATION_BYTES,
    ),
    loadExternalTrustFile(
      publicKeyPath,
      'root manifest public key',
      loaded,
      MAX_SIGNING_KEY_BYTES,
    ),
  ])
  let attestation
  try {
    attestation = JSON.parse(attestationFile.bytes.toString('utf8'))
  } catch (error) {
    throw new Error(
      `invalid JSON in ${attestationFile.path}: ${error.message}`,
    )
  }
  const verification = verifyRootAttestation({
    attestation,
    run: loaded.run,
    runSha256: loaded.sourceDigest,
    publicKeyBytes: publicKeyFile.bytes,
  })
  return {
    attestation,
    attestationFile,
    publicKeyFile,
    verification,
  }
}

async function verifyPinnedRootAttestation(loaded, options) {
  const result = await loadPinnedRootAttestation(loaded, options)
  return result.verification
}

async function verifyPinnedTransparencyReceipt(
  loaded,
  options,
  rootAttestationRecord,
  dependencies = {},
) {
  const receiptPath = options['transparency-receipt']
  const publicKeyPath = options['transparency-log-public-key']
  const expectedOrigin = options['transparency-log-origin']
  const hasReceipt = typeof receiptPath === 'string'
  const hasPublicKey = typeof publicKeyPath === 'string'
  const hasOrigin = typeof expectedOrigin === 'string'
  const hasJournal = typeof options['transparency-checkpoint-journal'] === 'string'
  if (new Set([hasReceipt, hasPublicKey, hasOrigin]).size !== 1) {
    throw new Error(
      '--transparency-receipt, --transparency-log-public-key, and --transparency-log-origin must be supplied together',
    )
  }
  if (!hasReceipt) {
    if (hasJournal) {
      throw new Error(
        '--transparency-checkpoint-journal requires the transparency receipt, log public key, and origin options',
      )
    }
    return {
      status: 'NOT_SUPPLIED',
      claim: 'NO_TRANSPARENCY_INCLUSION_CLAIM',
    }
  }
  if (!rootAttestationRecord?.attestation) {
    throw new Error(
      'transparency verification requires --root-attestation and --root-public-key',
    )
  }
  const [receiptFile, logPublicKeyFile] = await Promise.all([
    loadExternalTrustFile(
      receiptPath,
      'transparency inclusion receipt',
      loaded,
      MAX_TRANSPARENCY_RECEIPT_BYTES,
    ),
    loadExternalTrustFile(
      publicKeyPath,
      'transparency log public key',
      loaded,
      MAX_SIGNING_KEY_BYTES,
    ),
  ])
  let receipt
  try {
    receipt = JSON.parse(receiptFile.bytes.toString('utf8'))
  } catch (error) {
    throw new Error(
      `invalid JSON in ${receiptFile.path}: ${error.message}`,
    )
  }
  const inclusion = verifyTransparencyInclusion({
    receipt,
    attestation: rootAttestationRecord.attestation,
    publicKeyBytes: logPublicKeyFile.bytes,
    expectedOrigin,
    maxClockSkewMs: MAX_OFFLINE_TRANSPARENCY_CLOCK_SKEW_MS,
  })
  const journalPath = options['transparency-checkpoint-journal']
  if (journalPath === undefined) return inclusion
  const journal = await openExternalCheckpointJournal({
    pathValue: journalPath,
    loaded,
    publicKeyBytes: logPublicKeyFile.bytes,
    expectedOrigin,
    maxClockSkewMs: MAX_OFFLINE_TRANSPARENCY_CLOCK_SKEW_MS,
    mustExist: true,
    dependencies,
  })
  try {
    const continuity = await journal.continuityForCheckpoint(
      projectTransparencySignedCheckpoint(receipt),
    )
    return {
      ...inclusion,
      consistency: continuity.consistency,
      continuity,
    }
  } finally {
    await journal.close()
  }
}

async function externalTrustOutputPath(pathValue, loaded, label) {
  if (typeof pathValue !== 'string') {
    throw new Error(`--out is required to write ${label}`)
  }
  const absolutePath = resolve(pathValue)
  let canonicalParent
  try {
    canonicalParent = await realpath(dirname(absolutePath))
  } catch (error) {
    throw new Error(
      `cannot prepare ${label} output ${absolutePath}: ${error.message}`,
    )
  }
  const outputPath = join(canonicalParent, basename(absolutePath))
  if (
    pathWithin(resolve(loaded.directory), outputPath)
    || pathWithin(resolve(loaded.run.repository.root), outputPath)
  ) {
    throw new Error(
      `${label} output must be outside the run bundle and target repository`,
    )
  }
  try {
    await lstat(outputPath)
  } catch (error) {
    if (error.code === 'ENOENT') return outputPath
    throw new Error(
      `cannot inspect ${label} output ${outputPath}: ${error.message}`,
    )
  }
  throw new Error(`${label} output already exists: ${outputPath}`)
}

async function rootAttestationOutputPath(pathValue, loaded) {
  return externalTrustOutputPath(
    pathValue,
    loaded,
    'root manifest attestation',
  )
}

function createControllerExecutionEnvelope(execution, attempt, signingKey) {
  assertValidProviderExecution(execution)
  const unsigned = {
    schema_version: '1.0.0',
    authority: 'CONTROLLER_OBSERVED_CONSUMPTION',
    controller: {
      attempt_id: attempt.attempt_id,
      attempt_nonce: attempt.lease.nonce,
      lease_event_sha256: attempt.lease.event_sha256,
      packet_sha256: attempt.lease.packet_sha256,
      source_snapshot_sha256: attempt.lease.source_snapshot_sha256,
      control_snapshot_sha256: attempt.lease.control_snapshot_sha256,
      signed_at: new Date().toISOString(),
      key_id: signingKey.keyId,
      public_key_spki_base64: signingKey.publicSpkiBase64,
      provider_execution_sha256: sha256(stableJson(execution, 0)),
      receipt_sha256: sha256(stableJson(execution.receipt, 0)),
    },
    provider_execution: execution,
  }
  const signature = signBytes(
    null,
    Buffer.from(stableJson(unsigned, 0), 'utf8'),
    signingKey.privateKey,
  )
  return {
    ...unsigned,
    signature: {
      algorithm: 'Ed25519',
      value_base64: signature.toString('base64'),
    },
  }
}

function providerCleanupFailure(error) {
  if (error?.cleanup_error !== undefined) return error.cleanup_error
  return NONRECOVERABLE_PROVIDER_CLEANUP_CODES.has(error?.code)
    ? error
    : undefined
}

function createControllerFailureEnvelope(
  error,
  attempt,
  signingKey,
  partialReceipt = error?.partial_receipt,
) {
  const cleanupCandidate = providerCleanupFailure(error)
  let cleanupError
  if (cleanupCandidate !== undefined) {
    const candidateCleanupCode = String(
      cleanupCandidate?.code ?? 'PROVIDER_CLEANUP_UNVERIFIED',
    )
    cleanupError = {
      code: /^[A-Z][A-Z0-9_:-]{2,159}$/.test(candidateCleanupCode)
        ? candidateCleanupCode
        : 'PROVIDER_CLEANUP_UNVERIFIED',
      message: String(
        cleanupCandidate?.message
          ?? 'provider container absence could not be verified',
      ).slice(0, 16_000),
      ...(typeof cleanupCandidate?.stderr === 'string'
        && cleanupCandidate.stderr.length > 0
        ? { stderr: cleanupCandidate.stderr.slice(0, 65_536) }
        : {}),
    }
  }
  const recoverable = cleanupError === undefined
  const candidateCode = String(error?.code ?? 'CONTROLLER_PROVIDER_FAILURE')
  const code = /^[A-Z][A-Z0-9_:-]{2,159}$/.test(candidateCode)
    ? candidateCode
    : 'CONTROLLER_PROVIDER_FAILURE'
  const failure = {
    code,
    message: String(error?.message ?? error ?? 'provider execution failed')
      .slice(0, 16_000),
    recoverable,
    ...(typeof error?.stderr === 'string' && error.stderr.length > 0
      ? { stderr: error.stderr.slice(0, 16_777_216) }
      : {}),
    ...(cleanupError === undefined ? {} : { cleanup_error: cleanupError }),
    ...(partialReceipt === undefined
      ? {}
      : { partial_receipt: structuredClone(partialReceipt) }),
  }
  const unsigned = {
    schema_version: '1.0.0',
    authority: 'CONTROLLER_OBSERVED_FAILURE',
    controller: {
      attempt_id: attempt.attempt_id,
      attempt_nonce: attempt.lease.nonce,
      lease_event_sha256: attempt.lease.event_sha256,
      packet_sha256: attempt.lease.packet_sha256,
      source_snapshot_sha256: attempt.lease.source_snapshot_sha256,
      control_snapshot_sha256: attempt.lease.control_snapshot_sha256,
      signed_at: new Date().toISOString(),
      key_id: signingKey.keyId,
      public_key_spki_base64: signingKey.publicSpkiBase64,
      failure_sha256: sha256(stableJson(failure, 0)),
      ...(partialReceipt === undefined
        ? {}
        : {
            partial_receipt_sha256: sha256(
              stableJson(partialReceipt, 0),
            ),
          }),
    },
    failure,
  }
  const envelope = {
    ...unsigned,
    signature: {
      algorithm: 'Ed25519',
      value_base64: signBytes(
        null,
        Buffer.from(stableJson(unsigned, 0), 'utf8'),
        signingKey.privateKey,
      ).toString('base64'),
    },
  }
  assertValidControllerFailureEnvelope(envelope)
  return envelope
}

function assertControllerEnvelopeSignature(envelope, pinnedKeyId, label) {
  const controller = envelope.controller
  let publicKey
  let spki
  try {
    spki = Buffer.from(controller.public_key_spki_base64, 'base64')
    publicKey = createPublicKey({ key: spki, type: 'spki', format: 'der' })
  } catch (error) {
    throw new Error(`${label} public key is invalid: ${error.message}`)
  }
  const keyId = `ed25519:${sha256(spki)}`
  if (
    publicKey.asymmetricKeyType !== 'ed25519'
    || controller.key_id !== keyId
    || (pinnedKeyId !== undefined && pinnedKeyId !== keyId)
  ) {
    throw new Error(`${label} signing key identity is not trusted`)
  }
  const { signature, ...unsigned } = envelope
  const signatureBytes = Buffer.from(signature.value_base64, 'base64')
  if (!verifyBytes(
    null,
    Buffer.from(stableJson(unsigned, 0), 'utf8'),
    publicKey,
    signatureBytes,
  )) {
    throw new Error(`${label} signature verification failed`)
  }
}

function assertControllerExecutionEnvelope(
  envelope,
  attempt,
  run,
  pinnedKeyId = undefined,
) {
  assertValidControllerExecutionEnvelope(envelope)
  if (
    envelope === null
    || typeof envelope !== 'object'
    || Array.isArray(envelope)
    || envelope.schema_version !== '1.0.0'
    || envelope.authority !== 'CONTROLLER_OBSERVED_CONSUMPTION'
    || envelope.signature?.algorithm !== 'Ed25519'
  ) {
    throw new Error('controller execution envelope has an invalid shape')
  }
  const controller = envelope.controller
  if (
    controller?.attempt_id !== attempt.attempt_id
    || controller?.attempt_nonce !== attempt.lease.nonce
    || controller?.lease_event_sha256 !== attempt.lease.event_sha256
    || controller?.packet_sha256 !== attempt.lease.packet_sha256
    || controller?.source_snapshot_sha256 !== attempt.lease.source_snapshot_sha256
    || controller?.control_snapshot_sha256 !== attempt.lease.control_snapshot_sha256
  ) {
    throw new Error('controller execution envelope does not bind the active attempt')
  }
  assertValidProviderExecution(envelope.provider_execution)
  const result = envelope.provider_execution.job_result
  const receipt = envelope.provider_execution.receipt
  if (
    result.run_id !== run.run_id
    || receipt.run_id !== run.run_id
    || result.job_id !== attempt.job_id
    || receipt.job_id !== attempt.job_id
    || result.input_sha256 !== attempt.lease.packet_sha256
    || receipt.packet_sha256 !== attempt.lease.packet_sha256
    || receipt.backend.container_name !== attempt.lease.container_name
  ) {
    throw new Error(
      'controller execution envelope provider payload does not bind its run and attempt',
    )
  }
  if (
    controller.provider_execution_sha256
      !== sha256(stableJson(envelope.provider_execution, 0))
    || controller.receipt_sha256
      !== sha256(stableJson(envelope.provider_execution.receipt, 0))
    || (
      attempt.receipt_sha256 !== undefined
      && controller.receipt_sha256 !== attempt.receipt_sha256
    )
  ) {
    throw new Error('controller execution envelope digest binding failed')
  }
  assertControllerEnvelopeSignature(
    envelope,
    pinnedKeyId,
    'controller execution',
  )
  return envelope
}

function assertPartialReceiptBoundToAttempt(
  receipt,
  attempt,
  run,
  expectedArtifacts,
) {
  if (
    receipt.run_id !== run.run_id
    || receipt.job_id !== attempt.job_id
    || receipt.packet_sha256 !== attempt.lease.packet_sha256
    || receipt.backend.container_name !== attempt.lease.container_name
  ) {
    throw new Error('controller failure partial receipt does not bind its attempt')
  }
  const startedAt = parseContractTimestamp(receipt.started_at)
  const completedAt = parseContractTimestamp(receipt.completed_at)
  if (
    !Number.isFinite(startedAt)
    || !Number.isFinite(completedAt)
    || completedAt < startedAt
  ) {
    throw new Error('controller failure partial receipt has invalid execution times')
  }
  const deliveryIds = new Set()
  const artifactIds = new Set()
  for (const [index, delivery] of receipt.deliveries.entries()) {
    if (
      deliveryIds.has(delivery.delivery_id)
      || artifactIds.has(delivery.artifact_id)
    ) {
      throw new Error(
        `controller failure partial receipt has duplicate delivery identity at index ${index}`,
      )
    }
    deliveryIds.add(delivery.delivery_id)
    artifactIds.add(delivery.artifact_id)
    const expected = expectedArtifacts.get(delivery.artifact_id)
    if (
      !expected
      || expected.artifact_kind !== delivery.artifact_kind
      || expected.logical_name !== delivery.logical_name
      || expected.expected_sha256 !== delivery.expected_sha256
      || expected.size !== delivery.size
    ) {
      throw new Error(
        `controller failure partial receipt delivery ${delivery.artifact_id} was not offered to the attempt`,
      )
    }
    const delivered = delivery.events[0]
    const deliveredAt = parseContractTimestamp(delivered.observed_at)
    if (
      !Number.isFinite(deliveredAt)
      || delivered.bytes_sent !== delivery.size
      || delivered.transport_sha256 !== delivery.expected_sha256
    ) {
      throw new Error(
        `controller failure partial receipt delivery ${delivery.artifact_id} has invalid byte evidence`,
      )
    }
    if (delivery.events.length === 2) {
      const consumedAt = parseContractTimestamp(delivery.events[1].observed_at)
      if (!Number.isFinite(consumedAt) || consumedAt < deliveredAt) {
        throw new Error(
          `controller failure partial receipt delivery ${delivery.artifact_id} has invalid event order`,
        )
      }
    }
  }
}

function assertControllerFailureEnvelope(
  envelope,
  attempt,
  {
    run,
    expectedArtifacts,
    pinnedKeyId = undefined,
  },
) {
  assertValidControllerFailureEnvelope(envelope)
  const controller = envelope.controller
  if (
    controller.attempt_id !== attempt.attempt_id
    || controller.attempt_nonce !== attempt.lease.nonce
    || controller.lease_event_sha256 !== attempt.lease.event_sha256
    || controller.packet_sha256 !== attempt.lease.packet_sha256
    || controller.source_snapshot_sha256 !== attempt.lease.source_snapshot_sha256
    || controller.control_snapshot_sha256 !== attempt.lease.control_snapshot_sha256
  ) {
    throw new Error('controller failure envelope does not bind its attempt')
  }
  if (
    controller.failure_sha256 !== sha256(stableJson(envelope.failure, 0))
    || (
      envelope.failure.partial_receipt !== undefined
      && controller.partial_receipt_sha256 !== sha256(
        stableJson(envelope.failure.partial_receipt, 0),
      )
    )
  ) {
    throw new Error('controller failure envelope digest binding failed')
  }
  if (envelope.failure.partial_receipt !== undefined) {
    assertPartialReceiptBoundToAttempt(
      envelope.failure.partial_receipt,
      attempt,
      run,
      expectedArtifacts,
    )
  }
  assertControllerEnvelopeSignature(
    envelope,
    pinnedKeyId,
    'controller failure',
  )
  return envelope
}

async function assertBoundSourceAnchors(
  directory,
  run,
  job,
  result,
  sourceIndex,
  authorizedFileIds,
  authorityLabel,
) {
  const examinedPaths = new Set(result.examined_files)
  const sourceById = new Map(sourceIndex.files.map((file) => [file.file_id, file]))
  const cachedBytes = new Map()
  const shardCache = new Map()
  for (const finding of result.findings) {
    if (
      job.kind === 'LENS'
      && (
        !Array.isArray(finding.source_anchors)
        || finding.source_anchors.length === 0
      )
    ) {
      throw new Error(
        `${authorityLabel} finding ${finding.candidate_id} requires a controller-verifiable source anchor`,
      )
    }
    for (const anchor of finding.source_anchors ?? []) {
      const file = sourceById.get(anchor.file_id)
      if (
        !file
        || file.availability !== 'AVAILABLE'
        || anchor.snapshot_sha256 !== run.source_snapshot.root_sha256
        || !authorizedFileIds.has(anchor.file_id)
        || !examinedPaths.has(file.path)
        || !Number.isSafeInteger(anchor.start_byte)
        || !Number.isSafeInteger(anchor.end_byte)
        || anchor.start_byte < 0
        || anchor.end_byte <= anchor.start_byte
        || anchor.end_byte > file.size
      ) {
        throw new Error(
          `finding ${finding.candidate_id} has an unbound source anchor`,
        )
      }
      let bytes = cachedBytes.get(file.file_id)
      if (!bytes) {
        bytes = await readIndexedSnapshotFile(
          directory,
          run,
          'source',
          sourceIndex,
          file,
          shardCache,
        )
        cachedBytes.set(file.file_id, bytes)
      }
      const excerpt = bytes.subarray(anchor.start_byte, anchor.end_byte)
      if (sha256(excerpt) !== anchor.excerpt_sha256.toLowerCase()) {
        throw new Error(
          `finding ${finding.candidate_id} source anchor excerpt digest does not match`,
        )
      }
    }
  }
}

async function assertObservedSourceAnchors(
  directory,
  run,
  job,
  execution,
  sourceIndex,
) {
  const consumedIds = new Set(
    execution.receipt.deliveries
      .filter((delivery) =>
        delivery.artifact_kind === 'FILE'
        && delivery.events?.[1]?.state === 'CONSUMED')
      .map(({ artifact_id: artifactId }) => artifactId),
  )
  return assertBoundSourceAnchors(
    directory,
    run,
    job,
    execution.job_result,
    sourceIndex,
    consumedIds,
    'observed',
  )
}

async function assertRemoteSourceAnchors(
  directory,
  run,
  job,
  requestEnvelope,
  result,
  sourceIndex,
) {
  const suppliedIds = new Set(
    requestEnvelope.artifacts
      .filter(({ kind }) => kind === 'FILE')
      .map(({ artifact_id: artifactId }) => artifactId),
  )
  return assertBoundSourceAnchors(
    directory,
    run,
    job,
    result,
    sourceIndex,
    suppliedIds,
    'remote',
  )
}

function assertRequiredControlConsumption(execution, artifacts) {
  const consumed = new Set(
    execution.receipt.deliveries
      .filter((delivery) =>
        delivery.artifact_kind === 'CONTROL'
        && delivery.events?.[1]?.state === 'CONSUMED')
      .map(({ artifact_id: artifactId }) => artifactId),
  )
  const missing = artifacts
    .filter(({ kind }) => kind === 'CONTROL')
    .filter(({ artifact_id: artifactId }) => !consumed.has(artifactId))
    .map(({ logical_name: logicalName }) => logicalName)
  if (missing.length > 0) {
    throw new Error(
      `provider did not consume required sealed controls: ${missing.join(', ')}`,
    )
  }
}

function advanceUntilBlocked(run) {
  let current = run
  while (true) {
    const result = advanceRun(current)
    if (!result.advanced) return current
    current = result.run
  }
}

async function planCommand(positionals, options) {
  const targetRoot = await realpath(resolve(requirePositional(positionals, 0, 'repository')))
  const customOutput = typeof options.out === 'string'
  const sealSource = options['seal-source'] === true
  const outputParent = resolve(
    customOutput ? options.out : join(process.cwd(), '.audit-runs'),
  )
  if (sealSource && pathWithin(targetRoot, outputParent)) {
    throw new Error(
      '--seal-source creates a sensitive exact-byte archive; its output ' +
      'directory must be outside the audited repository',
    )
  }
  if (customOutput && pathWithin(targetRoot, outputParent)) {
    throw new Error(
      'a custom --out directory must be outside the audited repository; ' +
      'omit --out to use the excluded .audit-runs default',
    )
  }
  let policy
  if (typeof options.roe === 'string') {
    const policyPath = await canonicalUnlinkedFile(options.roe, 'Rules of Engagement path')
    if (pathWithin(targetRoot, policyPath)) {
      throw new Error(
        'Rules of Engagement must be supplied from outside the untrusted target repository',
      )
    }
    const policyDocument = await readJson(policyPath, {
      maxBytes: MAX_POLICY_BYTES,
      label: 'Rules of Engagement JSON',
    })
    const policyPathAfterRead = await canonicalUnlinkedFile(
      options.roe,
      'Rules of Engagement path',
    )
    if (policyPathAfterRead !== policyPath || pathWithin(targetRoot, policyPathAfterRead)) {
      throw new Error('Rules of Engagement path changed while it was being read')
    }
    policy = normalizePolicy(policyDocument, {
      workspaceRoot: targetRoot,
      policySource: 'external',
    })
    if (policy.mode === 'remote_static' && !sealSource) {
      throw new Error(
        'remote_static Rules of Engagement require --seal-source so the controller can bind exact outbound bytes',
      )
    }
    if (policy.mode === 'local_dynamic' && !sealSource) {
      throw new Error(
        'local_dynamic Rules of Engagement require --seal-source so T2 executes exact planned bytes',
      )
    }
  }
  let completenessInputs
  if (typeof options['completeness-inputs'] === 'string') {
    const inputsPath = await canonicalUnlinkedFile(
      options['completeness-inputs'],
      'completeness inputs path',
    )
    if (pathWithin(targetRoot, inputsPath)) {
      throw new Error(
        'completeness inputs must be supplied from outside the untrusted target repository',
      )
    }
    completenessInputs = await readJson(inputsPath, {
      maxBytes: MAX_COMPLETENESS_INPUTS_BYTES,
      label: 'completeness inputs JSON',
    })
    const inputsPathAfterRead = await canonicalUnlinkedFile(
      options['completeness-inputs'],
      'completeness inputs path',
    )
    if (
      inputsPathAfterRead !== inputsPath
      || pathWithin(targetRoot, inputsPathAfterRead)
    ) {
      throw new Error('completeness inputs path changed while it was being read')
    }
  }
  let databaseConformanceEvidence
  if (typeof options['database-conformance'] === 'string') {
    const conformanceArgument = resolve(options['database-conformance'])
    const conformanceBefore = await realpath(conformanceArgument)
    if (pathWithin(targetRoot, conformanceBefore)) {
      throw new Error(
        'database conformance evidence must be supplied from outside the untrusted target repository',
      )
    }
    databaseConformanceEvidence = await loadDatabaseConformanceEvidence(
      conformanceBefore,
    )
    const conformanceAfter = await realpath(conformanceArgument)
    if (
      conformanceAfter !== conformanceBefore
      || pathWithin(targetRoot, conformanceAfter)
    ) {
      throw new Error('database conformance evidence path changed while it was read')
    }
  }
  // Evidence of uncertain provenance is worse than absent evidence because it
  // launders into findings, so loadEvidenceBundle refuses rather than warning.
  const evidenceBundles = []
  if (typeof options['evidence-bundle'] === 'string') {
    for (const argument of options['evidence-bundle'].split(',')) {
      const bundleArgument = resolve(argument.trim())
      const before = await realpath(bundleArgument)
      if (pathWithin(targetRoot, before)) {
        throw new Error(
          'evidence bundles must be supplied from outside the untrusted target repository',
        )
      }
      const loaded = await loadEvidenceBundle(before)
      const after = await realpath(bundleArgument)
      if (after !== before || pathWithin(targetRoot, after)) {
        throw new Error('evidence bundle path changed while it was read')
      }
      evidenceBundles.push({
        evidence_id: loaded.evidence_context.evidence_id,
        evidence_class: loaded.evidence_context.evidence_class,
        adapter_id: loaded.evidence_context.adapter_id,
        evidence_context: loaded.evidence_context,
        ...(loaded.profile.artifact_kind
          ? { artifact_kind: loaded.profile.artifact_kind }
          : {}),
        coverage_state: loaded.profile.coverage_state,
        phi_bearing: loaded.profile.phi_bearing,
        root_sha256: loaded.root_sha256,
        // Internal planning authority only. createRunPlan verifies it again,
        // builds the bounded locator index, and strips this host path from
        // run.json and every portable report artifact.
        directory: loaded.directory,
      })
    }
    const ids = evidenceBundles.map(({ evidence_id: id }) => id)
    if (new Set(ids).size !== ids.length) {
      throw new Error('each evidence_id must be unique within a run')
    }
  }
  const maxTextBytes = positiveInteger(options['max-text-bytes'], '--max-text-bytes')
  const maxShardFiles = positiveInteger(
    options['max-shard-files'],
    '--max-shard-files',
  )
  const maxShardBytes = positiveInteger(
    options['max-shard-bytes'],
    '--max-shard-bytes',
  )
  const maxClosureRounds = nonNegativeInteger(
    options['max-closure-rounds'],
    '--max-closure-rounds',
  )
  const plan = await createRunPlan({
    targetRoot,
    lensDirectory: DEFAULT_LENS_DIRECTORY,
    policy,
    databaseConformanceEvidence,
    evidenceBundles,
    completenessInputs,
    sealSource,
    ...(maxTextBytes === undefined ? {} : { inventoryOptions: { maxTextBytes } }),
    shardOptions: {
      ...(maxShardFiles === undefined ? {} : { maxFiles: maxShardFiles }),
      ...(maxShardBytes === undefined ? {} : { maxBytes: maxShardBytes }),
    },
    closureOptions: {
      ...(maxClosureRounds === undefined ? {} : { maxRounds: maxClosureRounds }),
      requireSourceClosure: options['require-source-closure'] === true,
    },
  })
  assertValidRun(plan.run)
  const written = await writeRunPlanBundle(plan, outputParent)
  assertValidRun(plan.run)
  const summary = summarizePlan(plan)

  if (options.json) {
    process.stdout.write(terminalSafeSerializedJson(
      stableJson({ ...summary, bundle: written.directory }),
    ))
  } else {
    console.log(terminalSafeText(`Planned ${summary.run_id}`))
    console.log(terminalSafeText(`Bundle: ${written.directory}`))
    console.log(terminalSafeText(`Files: ${summary.files}`))
    console.log(terminalSafeText(`Active fan-out lenses: ${summary.active_fanout_lenses}`))
    console.log(terminalSafeText(`Bounded fan-out shards: ${summary.fanout_shards}`))
    console.log(terminalSafeText(
      `Database discovery: ${summary.database_stores_discovered} stores, ` +
      `${summary.database_paths_in_scope} scoped paths`,
    ))
    console.log(terminalSafeText(`Coverage: ${summary.coverage_status}`))
    console.log(terminalSafeText(
      `Source snapshot: ${summary.source_sealed ? 'SEALED (sensitive)' : 'not sealed; observed runner unavailable'}`,
    ))
    if (summary.unassigned_text_files || summary.unexamined_files || summary.inventory_errors) {
      console.log(terminalSafeText(
        `Gaps: ${summary.unassigned_text_files} unassigned text, ` +
        `${summary.unexamined_files} unexamined, ${summary.inventory_errors} inventory errors`,
      ))
    }
    console.log('State: PLANNED — no audit provider has run; this is not a clean result.')
  }
}

async function attestCommand(positionals, options) {
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  assertValidRun(loaded.run)
  if (
    !['COMPLETED', 'COMPLETE_WITH_GAPS', 'ABORTED', 'FAILED']
      .includes(loaded.run.state)
    || loaded.run.phase !== 'FINALIZED'
  ) {
    throw new Error(
      'only a terminal FINALIZED run can receive a root manifest attestation',
    )
  }
  const pinnedReceiptKeyId = typeof options['receipt-public-key'] === 'string'
    ? await loadPinnedReceiptPublicKeyId(
        options['receipt-public-key'],
        loaded.directory,
        loaded.run.repository.root,
      )
    : undefined
  await verifyControlBundle(loaded.directory, loaded.run, { pinnedReceiptKeyId })
  if (typeof options['signing-key'] !== 'string') {
    throw new Error('--signing-key is required to attest a run manifest')
  }
  const signingKey = await loadExternalTrustFile(
    options['signing-key'],
    'root manifest signing key',
    loaded,
    MAX_SIGNING_KEY_BYTES,
  )
  const outputPath = await rootAttestationOutputPath(options.out, loaded)
  const attestation = createRootAttestation({
    run: loaded.run,
    runSha256: loaded.sourceDigest,
    privateKeyBytes: signingKey.bytes,
  })
  await durableCreate(outputPath, stableJson(attestation))
  console.log(terminalSafeText(`Attested ${loaded.run.run_id}`))
  console.log(terminalSafeText(`Root SHA-256: ${loaded.sourceDigest}`))
  console.log(terminalSafeText(`Signing key: ${attestation.signing.key_id}`))
  console.log(terminalSafeText(`Attestation: ${outputPath}`))
}

function sameTransparencyCheckpointHead(left, right) {
  return left?.checkpoint?.origin === right?.checkpoint?.origin
    && left?.checkpoint?.tree_size === right?.checkpoint?.tree_size
    && left?.checkpoint?.root_hash === right?.checkpoint?.root_hash
    && left?.checkpoint?.signing?.key_id
      === right?.checkpoint?.signing?.key_id
}

async function requestPublishedCheckpointConsistency({
  trusted,
  firstCheckpoint,
  secondCheckpoint,
  dependencies,
}) {
  const requestDocument = createTransparencyConsistencyRequest({
    firstSize: firstCheckpoint.checkpoint.tree_size,
    secondSize: secondCheckpoint.checkpoint.tree_size,
  })
  const submitConsistency = dependencies.submitTransparencyConsistencyRequest
    ?? submitTransparencyConsistencyRequest
  return submitConsistency({
    config: trusted.config,
    requestDocument,
    logPublicKeyBytes: trusted.logPublicKeyBytes,
    expectedFirstCheckpoint: firstCheckpoint,
    expectedSecondCheckpoint: secondCheckpoint,
    ...(typeof dependencies.transparencyConsistencyTransport === 'function'
      ? { transport: dependencies.transparencyConsistencyTransport }
      : (
          typeof dependencies.transparencyTransport === 'function'
            ? { transport: dependencies.transparencyTransport }
            : {}
        )),
  })
}

async function establishPublishedCheckpointContinuity({
  journal,
  trusted,
  receipt,
  initializeJournal,
  dependencies,
  republish,
}) {
  let currentReceipt = receipt
  let publishedCheckpoint = projectTransparencySignedCheckpoint(currentReceipt)
  for (let attempt = 0; attempt < 3; attempt += 1) {
    const snapshot = await journal.load()
    const retainedCheckpoint = snapshot.head
    if (retainedCheckpoint === null) {
      if (!initializeJournal) {
        throw new Error(
          'checkpoint journal became empty before continuity could be established',
        )
      }
      await journal.advance({ checkpoint: publishedCheckpoint })
      return {
        receipt: currentReceipt,
        continuity: await journal.continuityForCheckpoint(publishedCheckpoint),
      }
    }
    const retainedSize = retainedCheckpoint.checkpoint.tree_size
    const publishedSize = publishedCheckpoint.checkpoint.tree_size
    if (retainedSize === publishedSize) {
      if (!sameTransparencyCheckpointHead(
        retainedCheckpoint,
        publishedCheckpoint,
      )) {
        throw new Error(
          'published checkpoint conflicts with the externally retained root at the same tree size',
        )
      }
      return {
        receipt: currentReceipt,
        continuity: await journal.continuityForCheckpoint(publishedCheckpoint),
      }
    }
    if (retainedSize < publishedSize) {
      const result = await requestPublishedCheckpointConsistency({
        trusted,
        firstCheckpoint: retainedCheckpoint,
        secondCheckpoint: publishedCheckpoint,
        dependencies,
      })
      try {
        await journal.advance({
          expectedHead: retainedCheckpoint,
          checkpoint: publishedCheckpoint,
          consistencyProof: result.proof,
        })
        return {
          receipt: currentReceipt,
          continuity: await journal.continuityForCheckpoint(publishedCheckpoint),
        }
      } catch (error) {
        if (
          error?.code === 'TRANSPARENCY_CHECKPOINT_JOURNAL_CAS_CONFLICT'
          && attempt < 2
        ) {
          continue
        }
        throw error
      }
    }

    try {
      return {
        receipt: currentReceipt,
        continuity: await journal.continuityForCheckpoint(publishedCheckpoint),
      }
    } catch (error) {
      if (
        error?.code !== 'TRANSPARENCY_CHECKPOINT_JOURNAL_CHECKPOINT_ABSENT'
      ) {
        throw error
      }
      if (typeof republish !== 'function' || attempt >= 2) {
        throw new Error(
          'checkpoint journal is ahead of the publication receipt and no retained offline proof binds that receipt; retry publication',
          { cause: error },
        )
      }
      const replacement = await republish()
      currentReceipt = replacement.receipt
      publishedCheckpoint = projectTransparencySignedCheckpoint(currentReceipt)
    }
  }
  throw new Error(
    'checkpoint journal changed repeatedly while continuity was being established',
  )
}

export async function publishTransparencyCommand(
  positionals,
  options,
  dependencies = {},
) {
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  assertValidRun(loaded.run)
  const rootRecord = await loadPinnedRootAttestation(
    loaded,
    options,
    { required: true },
  )
  const pinnedReceiptKeyId = typeof options['receipt-public-key'] === 'string'
    ? await loadPinnedReceiptPublicKeyId(
        options['receipt-public-key'],
        loaded.directory,
        loaded.run.repository.root,
      )
    : undefined
  await verifyControlBundle(loaded.directory, loaded.run, { pinnedReceiptKeyId })
  const trusted = await loadTrustedTransparencyLogConfiguration(
    requirePositional(positionals, 1, 'transparency log configuration'),
    loaded,
  )
  const outputPath = await externalTrustOutputPath(
    options.out,
    loaded,
    'transparency inclusion receipt',
  )
  const journalPath = options['transparency-checkpoint-journal']
  const initializeJournal = options['initialize-transparency-checkpoint-journal'] === true
  if (initializeJournal && typeof journalPath !== 'string') {
    throw new Error(
      '--initialize-transparency-checkpoint-journal requires --transparency-checkpoint-journal',
    )
  }
  if (
    typeof journalPath === 'string'
    && typeof trusted.config.consistency_url !== 'string'
  ) {
    throw new Error(
      'checkpoint-journal publication requires a version 1.1 transparency configuration with consistency_url',
    )
  }
  if (
    typeof journalPath === 'string'
    && pathWithin(resolve(journalPath), outputPath)
  ) {
    throw new Error(
      'transparency inclusion receipt output must be outside the checkpoint journal directory',
    )
  }
  const journal = typeof journalPath === 'string'
    ? await openExternalCheckpointJournal({
        pathValue: journalPath,
        loaded,
        publicKeyBytes: trusted.logPublicKeyBytes,
        expectedOrigin: trusted.config.log_origin,
        maxClockSkewMs: trusted.config.limits.max_clock_skew_ms,
        dependencies,
      })
    : null
  if (journal !== null) {
    const before = await journal.load()
    if (before.head === null && !initializeJournal) {
      await journal.close()
      throw new Error(
        'checkpoint journal is empty; repeat with --initialize-transparency-checkpoint-journal to establish an explicit baseline',
      )
    }
    if (before.head !== null && initializeJournal) {
      await journal.close()
      throw new Error(
        '--initialize-transparency-checkpoint-journal is valid only for an empty journal',
      )
    }
  }
  const requestDocument = createTransparencyPublishRequest(
    rootRecord.attestation,
  )
  const submit = dependencies.submitTransparencyLogEntry
    ?? submitTransparencyLogEntry
  const submitPublication = () => submit({
      config: trusted.config,
      requestDocument,
      attestation: rootRecord.attestation,
      logPublicKeyBytes: trusted.logPublicKeyBytes,
      ...(typeof dependencies.transparencyTransport === 'function'
        ? { transport: dependencies.transparencyTransport }
        : {}),
    })
  let publicationAttempted = false
  try {
    publicationAttempted = true
    let publication = await submitPublication()
    let continuity = null
    if (journal !== null) {
      const established = await establishPublishedCheckpointContinuity({
        journal,
        trusted,
        receipt: publication.receipt,
        initializeJournal,
        dependencies,
        republish: submitPublication,
      })
      publication = {
        ...publication,
        receipt: established.receipt,
      }
      continuity = established.continuity
    }
    const verification = verifyTransparencyInclusion({
      receipt: publication.receipt,
      attestation: rootRecord.attestation,
      publicKeyBytes: trusted.logPublicKeyBytes,
      expectedOrigin: trusted.config.log_origin,
      maxClockSkewMs: trusted.config.limits.max_clock_skew_ms,
    })
    await durableCreate(outputPath, stableJson(publication.receipt))
    console.log(`Published ${loaded.run.run_id}`)
    console.log(`Transparency log: ${verification.origin}`)
    console.log(
      `Checkpoint: tree ${verification.tree_size}, leaf ${verification.leaf_index}, ${verification.root_hash}`,
    )
    if (continuity !== null) {
      console.log(`Checkpoint continuity: ${continuity.consistency}`)
    }
    console.log(`Inclusion receipt: ${outputPath}`)
    return {
      outputPath,
      receipt: publication.receipt,
      verification,
      ...(continuity === null ? {} : { continuity }),
    }
  } catch (error) {
    if (!publicationAttempted) throw error
    const wrapped = new Error(
      `transparency publication may already be durable, but no verified receipt output was written: ${error.message}`,
      { cause: error },
    )
    wrapped.code = error.code ?? 'TRANSPARENCY_PUBLICATION_OUTCOME_UNCERTAIN'
    if (error.details !== undefined) wrapped.details = error.details
    throw wrapped
  } finally {
    await journal?.close()
  }
}

async function validateCommand(positionals, options) {
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  const {
    path,
    directory,
    run,
  } = loaded
  const result = validateRun(run)
  let rootAuthenticity
  let transparencyInclusion
  if (result.valid) {
    try {
      const rootRecord = await loadPinnedRootAttestation(loaded, options)
      rootAuthenticity = rootRecord.verification
      transparencyInclusion = await verifyPinnedTransparencyReceipt(
        loaded,
        options,
        rootRecord,
      )
      const pinnedReceiptKeyId = typeof options['receipt-public-key'] === 'string'
        ? await loadPinnedReceiptPublicKeyId(
            options['receipt-public-key'],
            directory,
            run.repository.root,
          )
        : undefined
      await verifyControlBundle(directory, run, { pinnedReceiptKeyId })
    } catch (error) {
      result.valid = false
      result.errors.push({
        code: 'BUNDLE_INTEGRITY',
        instancePath: '/artifacts',
        message: error.message,
      })
    }
  }
  if (options.json) {
    process.stdout.write(terminalSafeSerializedJson(stableJson({
      path,
      ...result,
      ...(rootAuthenticity ? { root_authenticity: rootAuthenticity } : {}),
      ...(transparencyInclusion
        ? { transparency_inclusion: transparencyInclusion }
        : {}),
    })))
  } else if (result.valid) {
    console.log(terminalSafeText(`VALID: ${path}`))
    if (rootAuthenticity.status === 'SIGNATURE_VERIFIED_WITH_SUPPLIED_KEY') {
      console.log(terminalSafeText(
        `Root signature: VERIFIED WITH SUPPLIED KEY (${rootAuthenticity.key_id})`,
      ))
    } else {
      console.log('Root authenticity: UNANCHORED')
    }
    if (transparencyInclusion.status === 'VERIFIED') {
      console.log(terminalSafeText(
        `Transparency inclusion: VERIFIED (${transparencyInclusion.origin}, tree ${transparencyInclusion.tree_size}, leaf ${transparencyInclusion.leaf_index})`,
      ))
      if (transparencyInclusion.continuity) {
        console.log(terminalSafeText(
          `Checkpoint continuity: ${transparencyInclusion.continuity.consistency}`,
        ))
      }
    } else {
      console.log('Transparency inclusion: NOT SUPPLIED')
    }
  }
  else {
    console.error(`INVALID: ${terminalSafeText(path)}`)
    for (const error of result.errors) {
      console.error(terminalSafeText(
        `- ${error.code ?? error.keyword}: ${error.instancePath || '/'} ${error.message}`,
      ))
    }
  }
  if (!result.valid) process.exitCode = 1
}

function databaseContextJobBlocked(run, job) {
  if (
    job.kind !== 'LENS'
    || job.lens !== 'database-and-data-stores'
    || (job.profile_authority_store_ids?.length ?? 0) > 0
  ) {
    return false
  }
  const profiled = new Set(
    (run.store_profiles ?? []).map(
      (profile) => profile.store_context.store_id,
    ),
  )
  const missing = (job.database_store_ids ?? [])
    .filter((storeId) => !profiled.has(storeId))
  if (missing.length === 0) return false
  const missingSet = new Set(missing)
  return run.jobs.some((candidate) =>
    candidate.kind === 'LENS'
    && candidate.lens === 'database-and-data-stores'
    && candidate.closure_round === undefined
    && ['PENDING', 'RUNNING'].includes(candidate.state)
    && (candidate.profile_authority_store_ids ?? [])
      .some((storeId) => missingSet.has(storeId)))
}

export function pendingJobsForCurrentPhase(run) {
  const effectivePhase = run.state === 'PLANNED' && run.phase === 'RECON'
    ? 'FANOUT'
    : run.phase
  const kindForPhase = {
    FANOUT: 'LENS',
    TRIAGE: 'TRIAGE',
    PROOF: 'PROOF',
    PATCH: 'PATCH',
    REPORT: 'REPORT',
    COMPLETENESS: 'COMPLETENESS',
  }[effectivePhase]
  let pending = run.jobs.filter((job) => (
    job.state === 'PENDING'
    && !databaseContextJobBlocked(run, job)
    && (
      job.kind === kindForPhase
      || (
        effectivePhase === 'COMPLETENESS'
        && job.closure_round !== undefined
      )
    )
  ))
  if (effectivePhase === 'COMPLETENESS') {
    const lensJobs = pending.filter(({ kind }) => kind === 'LENS')
    if (lensJobs.length > 0) return lensJobs
    const triageJobs = pending.filter(({ kind }) => kind === 'TRIAGE')
    if (triageJobs.length > 0) {
      return [triageJobs.sort(compareTriageJobs)[0]]
    }
    const proofJobs = pending.filter(({ kind }) => kind === 'PROOF')
    if (proofJobs.length > 0) {
      return proofJobs
    }
    const completenessJobs = pending.filter(
      ({ kind }) => kind === 'COMPLETENESS',
    )
    return completenessJobs.slice(0, 1)
  }
  if (kindForPhase === 'TRIAGE' && pending.length > 1) {
    pending = [pending.sort(compareTriageJobs)[0]]
  }
  return pending
}

async function loadInspectionBundle(value) {
  const loaded = await loadRun(value)
  assertValidRun(loaded.run)
  await verifyControlBundle(loaded.directory, loaded.run)
  return loaded
}

async function assertInspectionUnchanged(loaded) {
  if ((await loadRun(loaded.path)).sourceDigest !== loaded.sourceDigest) {
    throw new Error('run changed during inspection; repeat the read for the current snapshot')
  }
}

async function capabilitiesCommand(options) {
  const capabilities = capabilityRegistry()
  process.stdout.write(options.json
    ? terminalSafeSerializedJson(stableJson(capabilities))
    : renderCapabilities(capabilities))
}

async function doctorCommand(options) {
  const toolPaths = {}
  for (const [option, name] of [
    ['ghidra', 'ghidra'], ['javac', 'javac'], ['jar', 'jar'], ['frida', 'frida'],
    ['burp', 'burpDesktop'], ['burp-extension', 'burpExtension'], ['crane', 'crane'],
  ]) {
    if (options[option] === undefined) continue
    toolPaths[name] = resolve(options[option])
  }
  const normalized = normalizeReadinessPaths({
    projectRoot: PROJECT_ROOT,
    bundlePath: options.bundle === undefined ? undefined : resolve(options.bundle),
    workerConfigPath: options.worker === undefined ? undefined : resolve(options.worker),
    toolPaths,
  })
  const loaded = normalized.bundlePath ? await loadInspectionBundle(normalized.bundlePath) : null
  const report = await inspectReadiness({
    projectRoot: normalized.projectRoot,
    workerConfigPath: normalized.workerConfigPath,
    toolPaths: normalized.toolPaths,
  })
  if (loaded) {
    report.environment_coverage = assessEnvironmentCoverage(loaded.run.coverage.inventory)
    report.run_id = loaded.run.run_id
    report.bundle_integrity = 'VERIFIED'
    report.root_authenticity = 'UNANCHORED'
    await assertInspectionUnchanged(loaded)
  }
  process.stdout.write(options.json
    ? terminalSafeSerializedJson(stableJson(report))
    : renderReadiness(report))
}

async function reviewTemplateCommand(positionals, options) {
  if (typeof options.job !== 'string') throw new Error('review-template requires --job <job-id>')
  const loaded = await loadInspectionBundle(positionals[0])
  const job = pendingJobsForCurrentPhase(loaded.run).find((entry) => entry.job_id === options.job)
  if (!job || job.kind !== 'LENS') throw new Error('review-template requires a pending source-review LENS job in the current phase')
  const sidecar = await loadJobSidecar(loaded.directory, loaded.run, job)
  const handoff = buildReviewTemplate(dispatchPacket(loaded.run, job, sidecar))
  await assertInspectionUnchanged(loaded)
  const serialized = stableJson(handoff)
  assertBundleArtifactSize(serialized, 'review handoff')
  process.stdout.write(terminalSafeSerializedJson(serialized))
}

async function checkResultCommand(positionals, options) {
  let runId
  let stage = 'BUNDLE_VALIDATION'
  try {
    const loaded = await loadRun(positionals[0])
    assertValidRun(loaded.run)
    runId = loaded.run.run_id
    stage = 'SNAPSHOT_VALIDATION'
    const control = await verifyRepositorySnapshot(loaded.directory, loaded.run)
    stage = 'RESULT_VALIDATION'
    const expectedSource = exactResultSourceBinding(options)
    const resultPath = resolve(positionals[1])
    const source = await readJobResultSource(resultPath, expectedSource)
    const applied = await verifyAlreadyAppliedResult(loaded, source)
    const prepared = applied ?? await prepareOneResult(
      loaded,
      resultPath,
      control.artifactCapacity,
      control.inventoryEntries,
      { source },
    )
    stage = 'SNAPSHOT_RECHECK'
    await assertInspectionUnchanged(loaded)
    const result = {
      valid: true,
      applied: applied !== null,
      run_id: loaded.run.run_id,
      job_id: prepared.jobId,
      result_state: prepared.jobState,
      semantic_authority: 'PROVIDER_DECLARED',
      note: applied === null
        ? 'This checks the ingestion contract only. No result was committed and no security conclusion was authenticated.'
        : 'The exact result is already committed in this bundle. No additional mutation was performed.',
    }
    process.stdout.write(options.json
      ? terminalSafeSerializedJson(stableJson(result))
      : `VALID RESULT (${applied === null ? 'not ingested' : 'already ingested'}): ${terminalSafeText(prepared.jobId)}\n${result.note}\n`)
  } catch {
    // Parser and scope-validation errors can contain provider-controlled text.
    // Project only a fixed stage/code, never raw evidence, messages, or Ajv params.
    const rejected = {
      valid: false,
      applied: false,
      ...(runId === undefined ? {} : { run_id: runId }),
      error: `${stage}_FAILED`,
      stage,
      note: 'The result was not accepted or committed. Inspect the matching bundle and result contract locally; raw rejection details are withheld.',
    }
    process.stdout.write(options.json
      ? terminalSafeSerializedJson(stableJson(rejected))
      : `INVALID RESULT (not ingested): ${rejected.error}\n${rejected.note}\n`)
    process.exitCode = 1
  }
}

async function verdictCommand(positionals, options) {
  const loaded = await loadInspectionBundle(positionals[0])
  const assessment = buildVerdictAssessment(loaded.run, { candidateId: options.candidate })
  assessment.bundle_integrity = 'VERIFIED'
  assessment.root_authenticity = 'UNANCHORED'
  await assertInspectionUnchanged(loaded)
  process.stdout.write(options.json
    ? terminalSafeSerializedJson(stableJson(assessment))
    : renderVerdictAssessment(assessment))
}

async function repairBriefCommand(positionals, options) {
  const loaded = await loadInspectionBundle(positionals[0])
  const baseline = options.baseline ? await loadInspectionBundle(options.baseline) : null
  const brief = buildRepairBrief(loaded.run, {
    candidateId: options.candidate,
    ...(baseline ? { comparison: compareRuns(baseline.run, loaded.run) } : {}),
  })
  await assertInspectionUnchanged(loaded)
  if (baseline) await assertInspectionUnchanged(baseline)
  process.stdout.write(options.json
    ? terminalSafeSerializedJson(stableJson(brief))
    : terminalSafeDocumentText(renderRepairBriefMarkdown(brief)))
}

async function statusCommand(positionals, options) {
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  assertValidRun(loaded.run)
  const pinnedReceiptKeyId = typeof options['receipt-public-key'] === 'string'
    ? await loadPinnedReceiptPublicKeyId(
        options['receipt-public-key'], loaded.directory, loaded.run.repository.root,
      )
    : undefined
  await verifyControlBundle(loaded.directory, loaded.run, { pinnedReceiptKeyId })
  const after = await loadRun(loaded.path)
  if (after.sourceDigest !== loaded.sourceDigest) {
    throw new Error('run changed while status was being read; repeat status for the current snapshot')
  }
  const status = {
    ...summarizeRunStatus(loaded.run, {
      pendingJobs: pendingJobsForCurrentPhase(loaded.run),
      activeAttempts: findActiveAttempt(loaded.run) ?? [],
    }),
    bundle_integrity: 'VERIFIED',
    root_authenticity: 'UNANCHORED',
    live_repository: 'NOT_CHECKED',
  }
  process.stdout.write(options.json
    ? terminalSafeSerializedJson(stableJson(status))
    : renderRunStatus(status))
}

async function nextCommand(positionals) {
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  assertValidRun(loaded.run)
  await verifyRepositorySnapshot(loaded.directory, loaded.run)
  const pending = pendingJobsForCurrentPhase(loaded.run)
  if (pending.length === 0) {
    process.stdout.write(terminalSafeSerializedJson(stableJson({
      run_id: loaded.run.run_id,
      state: loaded.run.state,
      phase: loaded.run.phase,
      pending_jobs: [],
    })))
    return
  }
  const packets = []
  for (const job of pending) {
    const sidecar = await loadJobSidecar(loaded.directory, loaded.run, job)
    packets.push(dispatchPacket(loaded.run, job, sidecar))
  }
  process.stdout.write(terminalSafeSerializedJson(stableJson({
    run_id: loaded.run.run_id,
    state: loaded.run.state,
    phase: loaded.run.phase,
    pending_jobs: packets,
  })))
}

async function loadTrustedProviderConfiguration(pathValue, loaded) {
  const major = Number(process.versions.node.split('.')[0])
  if (!Number.isSafeInteger(major) || major < 24) {
    throw new Error(
      'controller-observed provider execution requires Node.js 24 or newer; manual next/ingest remains available',
    )
  }
  const configPath = await canonicalUnlinkedFile(
    pathValue,
    'provider configuration path',
  )
  if (
    pathWithin(loaded.run.repository.root, configPath)
    || pathWithin(loaded.directory, configPath)
  ) {
    throw new Error(
      'provider configuration must be external to both the target repository and run bundle',
    )
  }
  const document = await readJson(configPath, {
    maxBytes: MAX_PROVIDER_CONFIG_BYTES,
    label: 'provider configuration JSON',
  })
  const configPathAfterRead = await canonicalUnlinkedFile(
    pathValue,
    'provider configuration path',
  )
  if (configPathAfterRead !== configPath) {
    throw new Error('provider configuration path changed while it was being read')
  }
  assertValidProviderConfig(document)
  if (typeof document.receipt_signing_private_key_path !== 'string') {
    throw new Error(
      'observed execution requires receipt_signing_private_key_path outside the bundle',
    )
  }
  const runtimePath = await canonicalUnlinkedFile(
    document.runtime_path,
    'trusted provider runtime path',
  )
  const signingKeyPath = await canonicalUnlinkedFile(
    document.receipt_signing_private_key_path,
    'controller receipt signing key path',
  )
  for (const [label, path] of [
    ['trusted provider runtime', runtimePath],
    ['controller receipt signing key', signingKeyPath],
  ]) {
    if (
      pathWithin(loaded.run.repository.root, path)
      || pathWithin(loaded.directory, path)
    ) {
      throw new Error(`${label} must be external to the target and run bundle`)
    }
  }
  const keyBytes = await readBoundedFile(
    signingKeyPath,
    MAX_SIGNING_KEY_BYTES,
    'controller receipt signing key',
  )
  const signingKeyPathAfterRead = await canonicalUnlinkedFile(
    document.receipt_signing_private_key_path,
    'controller receipt signing key path',
  )
  if (signingKeyPathAfterRead !== signingKeyPath) {
    throw new Error('controller receipt signing key path changed while it was being read')
  }
  const config = {
    ...structuredClone(document),
    runtime_path: runtimePath,
    receipt_signing_private_key_path: signingKeyPath,
  }
  assertValidProviderConfig(config)
  const signingKey = controllerSigningKey(keyBytes)
  return {
    config,
    signingKey,
    configSha256: sha256(stableJson({
      provider_config: config,
      receipt_signing_key_id: signingKey.keyId,
    }, 0)),
  }
}

async function loadTrustedRemoteGatewayConfiguration(pathValue, loaded) {
  const configFile = await loadExternalTrustFile(
    pathValue,
    'remote gateway configuration',
    loaded,
    MAX_REMOTE_GATEWAY_CONFIG_BYTES,
  )
  let document
  try {
    document = JSON.parse(configFile.bytes.toString('utf8'))
  } catch (error) {
    throw new Error(
      `invalid JSON in remote gateway configuration ${configFile.path}: ${error.message}`,
    )
  }
  assertValidRemoteGatewayConfig(document)
  const config = structuredClone(document)
  const controllerKeyFile = await loadExternalTrustFile(
    config.controller_signing_private_key_path,
    'remote controller signing key',
    loaded,
    MAX_SIGNING_KEY_BYTES,
  )
  const gatewayKeyFile = await loadExternalTrustFile(
    config.gateway_public_key_path,
    'remote gateway public key',
    loaded,
    MAX_SIGNING_KEY_BYTES,
  )
  config.controller_signing_private_key_path = controllerKeyFile.path
  config.gateway_public_key_path = gatewayKeyFile.path
  const controllerKey = parseRemotePrivateKey(controllerKeyFile.bytes)
  const gatewayKey = parseRemotePublicKey(gatewayKeyFile.bytes)
  assertValidRemoteGatewayConfig(config)
  return {
    config,
    controllerKeyBytes: controllerKeyFile.bytes,
    gatewayKeyBytes: gatewayKeyFile.bytes,
    controllerKey,
    gatewayKey,
    configSha256: sha256(stableJson({
      remote_gateway_config: config,
      controller_key_id: controllerKey.keyId,
      gateway_key_id: gatewayKey.keyId,
    }, 0)),
  }
}

async function loadTrustedTransparencyLogConfiguration(pathValue, loaded) {
  const configFile = await loadExternalTrustFile(
    pathValue,
    'transparency log configuration',
    loaded,
    MAX_TRANSPARENCY_LOG_CONFIG_BYTES,
  )
  let document
  try {
    document = JSON.parse(configFile.bytes.toString('utf8'))
  } catch (error) {
    throw new Error(
      `invalid JSON in transparency log configuration ${configFile.path}: ${error.message}`,
    )
  }
  assertValidTransparencyLogConfig(document)
  const config = structuredClone(document)
  const logPublicKeyFile = await loadExternalTrustFile(
    config.log_public_key_path,
    'transparency log public key',
    loaded,
    MAX_SIGNING_KEY_BYTES,
  )
  config.log_public_key_path = logPublicKeyFile.path
  const logKey = parseTransparencyPublicKey(logPublicKeyFile.bytes)
  assertValidTransparencyLogConfig(config)
  return {
    config,
    logPublicKeyBytes: logPublicKeyFile.bytes,
    logKey,
  }
}

async function persistLoadedRun(loaded, next) {
  await persistRun(loaded.path, next, loaded.sourceDigest)
  loaded.run = next
  loaded.sourceDigest = sha256(Buffer.from(stableJson(next), 'utf8'))
  return next
}

function assertServiceProofReceiptMatchesLease(run, attempt, receipt) {
  const lease = attempt.lease
  if (
    receipt?.schema_version !== '1.0.0'
    || receipt?.kind !== 'red-team-audit/proof-receipt'
    || receipt?.run_id !== run.run_id
    || receipt?.job_id !== attempt.job_id
    || receipt?.input_sha256 !== lease.packet_sha256
    || receipt?.repository_snapshot?.tree_digest !== run.repository.tree_digest
    || receipt?.repository_snapshot?.source_snapshot_sha256
      !== run.source_snapshot?.root_sha256
    || receipt?.repository_snapshot?.plan_digest !== run.plan_digest
    || receipt?.repository_snapshot?.policy_digest !== run.policy_digest
    || receipt?.repository_snapshot?.lens_pack_digest !== run.lens_pack_digest
    || receipt?.proof_configuration?.sha256 !== lease.proof_config_sha256
    || receipt?.proof_worker?.config_sha256 !== lease.proof_worker_config_sha256
    || stableJson(receipt?.execution_attempt, 0)
      !== stableJson(serviceProofAttemptReceiptBinding(attempt), 0)
  ) {
    throw new Error('service-proof receipt does not bind its exact attempt lease')
  }
  const sessionBudget = lease.service_session_budget
  if (
    receipt.proof_worker.controller_session_budget_ms
      !== sessionBudget.attack_controller_wall_clock_ms
    || receipt.proof_worker.controller_session_budget_ms
      !== sessionBudget.control_controller_wall_clock_ms
  ) {
    throw new Error('service-proof receipt controller budget differs from its lease')
  }
}

async function readServiceProofAttemptReceipt(loaded, attempt) {
  const artifact = loaded.run.artifacts?.[attempt.execution_artifact_key]
  if (!artifact) {
    throw new Error(`service-proof attempt ${attempt.attempt_id} receipt is missing`)
  }
  if (
    artifact.sha256 !== attempt.execution_artifact_sha256
    || artifact.sha256 !== attempt.receipt_sha256
  ) {
    throw new Error('service-proof receipt digest differs from its captured attempt')
  }
  const committed = await readVerifiedArtifact(
    loaded.directory,
    loaded.run,
    attempt.execution_artifact_key,
    artifact.path.replaceAll('\\', '/'),
  )
  const receipt = parseVerifiedJson(committed)
  assertServiceProofReceiptMatchesLease(loaded.run, attempt, receipt)
  return receipt
}

function assertServiceProofReceiptMatchesCommittedJob(run, job, attempt, receipt) {
  if (
    job.state !== 'SUCCEEDED'
    || job.input_sha256 !== attempt.lease.packet_sha256
    || job.receipt_sha256 !== attempt.receipt_sha256
    || job.execution_artifact_key !== attempt.execution_artifact_key
    || receipt.job_id !== job.job_id
    || receipt.candidate_id !== job.candidate_ids?.[0]
    || job.producer?.name !== 'red-team-audit-service-proof-controller'
    || job.producer?.version !== PLATFORM_VERSION
    || job.producer?.instance_id !== 'run-service-proof:controller'
  ) {
    throw new Error(`service-proof receipt does not match committed job ${job.job_id}`)
  }
  const finding = run.findings.find(
    ({ candidate_id: candidateId }) => candidateId === receipt.candidate_id,
  )
  if (!finding || receipt.evidence === null || typeof receipt.evidence !== 'object') {
    throw new Error(`service-proof receipt evidence is missing for ${job.job_id}`)
  }
  for (const [key, value] of Object.entries(receipt.evidence)) {
    if (stableJson(finding[key], 0) !== stableJson(value, 0)) {
      throw new Error(`service-proof receipt evidence differs from job ${job.job_id}`)
    }
  }
  const artifact = run.artifacts?.[attempt.execution_artifact_key]
  if (stableJson(finding.artifact, 0) !== stableJson(artifact, 0)) {
    throw new Error(`service-proof finding artifact differs from job ${job.job_id}`)
  }
}

async function readAttemptEnvelope(loaded, attempt, pinnedKeyId) {
  const artifact = loaded.run.artifacts?.[attempt.execution_artifact_key]
  if (!artifact) {
    throw new Error(`attempt ${attempt.attempt_id} execution artifact is missing`)
  }
  const committed = await readVerifiedArtifact(
    loaded.directory,
    loaded.run,
    attempt.execution_artifact_key,
    artifact.path.replaceAll('\\', '/'),
  )
  let envelope
  try {
    envelope = JSON.parse(verifiedArtifactUtf8(committed))
  } catch (error) {
    throw new Error(`execution envelope JSON is invalid: ${error.message}`)
  }
  assertControllerExecutionEnvelope(
    envelope,
    attempt,
    loaded.run,
    pinnedKeyId,
  )
  if (sha256(committed.content) !== attempt.execution_artifact_sha256) {
    throw new Error('execution envelope digest differs from its captured attempt')
  }
  return envelope
}

function embeddedRemotePublicKey(spkiBase64, label) {
  try {
    const spki = Buffer.from(spkiBase64, 'base64')
    if (spki.toString('base64') !== spkiBase64) {
      throw new Error('non-canonical base64')
    }
    return createPublicKey({ key: spki, type: 'spki', format: 'der' })
  } catch (error) {
    throw new Error(`${label} embedded public key is invalid: ${error.message}`)
  }
}

async function readRemoteRequestArtifact(loaded, attempt) {
  const artifact = loaded.run.artifacts?.[attempt.lease.request_artifact_key]
  if (!artifact) {
    throw new Error(`remote attempt ${attempt.attempt_id} request artifact is missing`)
  }
  const committed = await readVerifiedArtifact(
    loaded.directory,
    loaded.run,
    attempt.lease.request_artifact_key,
    artifact.path.replaceAll('\\', '/'),
  )
  if (
    sha256(committed.content) !== attempt.lease.request_artifact_sha256
    || artifact.sha256 !== attempt.lease.request_artifact_sha256
  ) {
    throw new Error('remote request artifact digest differs from its lease')
  }
  let envelope
  try {
    envelope = JSON.parse(verifiedArtifactUtf8(committed))
  } catch (error) {
    throw new Error(`remote request envelope JSON is invalid: ${error.message}`)
  }
  if (!committed.content.equals(Buffer.from(stableJson(envelope, 0), 'utf8'))) {
    throw new Error('remote request artifact must retain exact canonical JSON bytes')
  }
  const controllerKey = embeddedRemotePublicKey(
    envelope.controller?.public_key_spki_base64,
    'remote request',
  )
  const verified = verifyRemoteRequestEnvelope({
    envelope,
    publicKeyBytes: controllerKey,
    expectedPromptTransform: envelope.controller?.prompt_transform,
    now: envelope.controller?.created_at,
  })
  if (
    verified.key_id !== attempt.lease.controller_key_id
    || envelope.controller.request_id !== attempt.lease.request_id
    || envelope.controller.attempt_id !== attempt.attempt_id
    || envelope.controller.attempt_nonce !== attempt.lease.nonce
    || envelope.controller.run_id !== loaded.run.run_id
    || envelope.controller.job_id !== attempt.job_id
    || envelope.controller.packet_sha256 !== attempt.lease.packet_sha256
  ) {
    throw new Error('remote request artifact does not bind its attempt lease')
  }
  return {
    envelope,
    bytes: committed.content,
  }
}

async function readRemoteAcceptanceArtifact(
  loaded,
  attempt,
  {
    gatewayPublicKeyBytes = undefined,
    expectedPromptTransform = undefined,
  } = {},
) {
  const request = await readRemoteRequestArtifact(loaded, attempt)
  const artifact = loaded.run.artifacts?.[attempt.execution_artifact_key]
  if (!artifact) {
    throw new Error(`remote attempt ${attempt.attempt_id} acceptance artifact is missing`)
  }
  const committed = await readVerifiedArtifact(
    loaded.directory,
    loaded.run,
    attempt.execution_artifact_key,
    artifact.path.replaceAll('\\', '/'),
  )
  if (
    sha256(committed.content) !== attempt.execution_artifact_sha256
    || attempt.receipt_sha256 !== attempt.execution_artifact_sha256
  ) {
    throw new Error('remote acceptance artifact digest differs from its captured attempt')
  }
  let envelope
  try {
    envelope = JSON.parse(verifiedArtifactUtf8(committed))
  } catch (error) {
    throw new Error(`remote acceptance envelope JSON is invalid: ${error.message}`)
  }
  if (!committed.content.equals(Buffer.from(stableJson(envelope, 0), 'utf8'))) {
    throw new Error('remote acceptance artifact must retain exact canonical JSON bytes')
  }
  const pinnedGatewayKey = gatewayPublicKeyBytes ?? embeddedRemotePublicKey(
    envelope.gateway?.public_key_spki_base64,
    'remote acceptance',
  )
  const verified = verifyRemoteAcceptanceEnvelope({
    envelope,
    requestEnvelope: request.envelope,
    requestBytes: request.bytes,
    gatewayPublicKeyBytes: pinnedGatewayKey,
    expectedPromptTransform:
      expectedPromptTransform ?? request.envelope.controller.prompt_transform,
    now: envelope.gateway?.accepted_at,
  })
  if (verified.gateway_key_id !== attempt.lease.gateway_key_id) {
    throw new Error('remote acceptance key differs from its pinned attempt lease')
  }
  return {
    request: request.envelope,
    envelope,
    verified,
  }
}

async function readAttemptFailureEnvelope(
  loaded,
  attempt,
  {
    expectedArtifacts,
    pinnedKeyId,
  },
) {
  const artifact = loaded.run.artifacts?.[attempt.failure_artifact_key]
  if (!artifact) {
    throw new Error(`attempt ${attempt.attempt_id} failure artifact is missing`)
  }
  const committed = await readVerifiedArtifact(
    loaded.directory,
    loaded.run,
    attempt.failure_artifact_key,
    artifact.path.replaceAll('\\', '/'),
  )
  let envelope
  try {
    envelope = JSON.parse(verifiedArtifactUtf8(committed))
  } catch (error) {
    throw new Error(`failure envelope JSON is invalid: ${error.message}`)
  }
  assertControllerFailureEnvelope(envelope, attempt, {
    run: loaded.run,
    expectedArtifacts,
    pinnedKeyId,
  })
  if (sha256(committed.content) !== attempt.failure_artifact_sha256) {
    throw new Error('failure envelope digest differs from its FAILED event')
  }
  if (envelope.failure.recoverable !== attempt.last_event?.recoverable) {
    throw new Error(
      'failure envelope recoverability differs from its FAILED event',
    )
  }
  if (
    attempt.partial_receipt_sha256 !== undefined
    && envelope.controller.partial_receipt_sha256
      !== attempt.partial_receipt_sha256
  ) {
    throw new Error('failure envelope partial receipt differs from its FAILED event')
  }
  return envelope
}

function tripProviderCleanupCircuitBreaker(previous, failed, attempt, reason) {
  const next = structuredClone(failed)
  const message = (
    'provider container absence could not be verified; ' +
    'the run is terminal and no further provider execution is permitted'
  )
  next.state = 'FAILED'
  next.phase = 'FINALIZED'
  next.completed_at = new Date().toISOString()
  next.jobs = next.jobs.map((job) => {
    if (['DORMANT', 'PENDING'].includes(job.state)) {
      return { ...job, state: 'SKIPPED', reason: message }
    }
    if (job.state === 'RUNNING') {
      return { ...job, state: 'FAILED', reason: message }
    }
    return job
  })
  let errorOrdinal = next.errors.length + 1
  while (
    next.errors.some(
      ({ error_id: errorId }) => errorId === `provider-cleanup:${errorOrdinal}`,
    )
  ) {
    errorOrdinal += 1
  }
  next.errors.push({
    error_id: `provider-cleanup:${errorOrdinal}`,
    phase: 'FINALIZED',
    code: 'PROVIDER_CLEANUP_UNVERIFIED',
    message: reason,
    recoverable: false,
    job_id: attempt.job_id,
  })
  assertValidRunTransition(previous, next)
  return next
}

async function failObservedAttemptWithEvidence({
  loaded,
  control,
  attemptId,
  signingKey,
  error,
  reasonPrefix,
  partialReceipt = error?.partial_receipt,
  occurredAt = undefined,
}) {
  const message = error?.message ?? String(error)
  const reason = `${reasonPrefix}: ${message}`.slice(0, 16_000)
  const attempt = findProviderAttempt(loaded.run, attemptId)
  const recoverable = providerCleanupFailure(error) === undefined
  let failed
  try {
    const envelope = createControllerFailureEnvelope(
      error,
      attempt,
      signingKey,
      partialReceipt,
    )
    const content = stableJson(envelope)
    assertBundleArtifactSize(content, 'provider failure envelope')
    reserveBundleArtifactCapacity(
      control.artifactCapacity,
      content,
      'provider failure envelope',
    )
    const artifactKey = `failure_${artifactKeyToken(attemptId).toLowerCase()}`
    const artifactPath = `failures/${artifactToken(attemptId)}.json`
    await writeOnceBundleArtifact(loaded.directory, artifactPath, content)
    failed = failProviderAttempt(loaded.run, attemptId, {
      reason,
      recoverable,
      ...(occurredAt === undefined ? {} : { occurred_at: occurredAt }),
      failure_artifact_key: artifactKey,
      failure_artifact: {
        path: artifactPath,
        sha256: sha256(content),
      },
      ...(envelope.controller.partial_receipt_sha256 === undefined
        ? {}
        : {
            partial_receipt_sha256:
              envelope.controller.partial_receipt_sha256,
          }),
    })
  } catch (evidenceError) {
    const stillActive = findActiveAttempt(loaded.run, attempt.job_id)
    if (stillActive?.attempt_id !== attemptId) throw evidenceError
    failed = failProviderAttempt(loaded.run, attemptId, {
      reason: (
        `${reason}; signed failure evidence could not be captured: ` +
        `${evidenceError.message}`
      ).slice(0, 16_000),
      recoverable,
      ...(occurredAt === undefined ? {} : { occurred_at: occurredAt }),
    })
  }
  if (!recoverable) {
    failed = tripProviderCleanupCircuitBreaker(
      loaded.run,
      failed,
      attempt,
      reason,
    )
  }
  await persistLoadedRun(loaded, failed)
  return failed
}

async function completeObservedAttempt(loaded, control, attempt, signingKey) {
  const job = loaded.run.jobs.find(({ job_id: jobId }) => jobId === attempt.job_id)
  if (!job) throw new Error(`attempt job ${attempt.job_id} no longer exists`)
  const sidecar = await loadJobSidecar(loaded.directory, loaded.run, job)
  const packet = observedDispatchPacket(loaded.run, job, sidecar)
  if (packet.packet_sha256 !== attempt.lease.packet_sha256) {
    throw new Error('active attempt packet no longer matches the controller plan')
  }
  let active = attempt
  let envelope = await readAttemptEnvelope(loaded, active, signingKey.keyId)
  const execution = envelope.provider_execution
  await assertObservedSourceAnchors(
    loaded.directory,
    loaded.run,
    job,
    execution,
    control.sealedSnapshots.source,
  )
  if (active.state === 'RESULT_CAPTURED') {
    const validated = recordProviderResultValidated(
      loaded.run,
      active.attempt_id,
    )
    await persistLoadedRun(loaded, validated)
    active = findActiveAttempt(loaded.run, job.job_id)
    envelope = await readAttemptEnvelope(loaded, active, signingKey.keyId)
  }
  if (active.state !== 'VALIDATED') {
    throw new Error(`attempt ${active.attempt_id} cannot commit from ${active.state}`)
  }
  const applied = applyJobResult(
    loaded.run,
    envelope.provider_execution.job_result,
    {
      expectedPacketSha256: packet.packet_sha256,
      sidecar,
      commitObservedAttempt: (previous, candidate) =>
        commitProviderAttempt(previous, candidate, active.attempt_id),
    },
  )
  const advanced = advanceUntilBlocked(applied)
  await persistLoadedRun(loaded, advanced)
  console.log(`Observed ${job.job_id}: ${execution.job_result.state}`)
  console.log(`Attempt: ${active.attempt_id}`)
  console.log(`Coverage authority: CONTROLLER_OBSERVED_CONSUMPTION`)
  console.log(`Run: ${advanced.state}/${advanced.phase}`)
  return advanced
}

function remoteProviderLimits(config) {
  return {
    limits: {
      max_deliveries: config.limits.max_artifacts,
      max_file_bytes: config.limits.max_file_bytes,
      max_total_delivery_bytes: config.limits.max_total_artifact_bytes,
    },
  }
}

function remoteDispatchPacket(run, job, sidecar, artifacts) {
  const base = observedDispatchPacket(run, job, sidecar)
  const { packet_sha256: _packetSha256, ...unsigned } = base
  unsigned.scoped_files = artifacts
    .filter(({ kind }) => kind === 'FILE')
    .map(({ logical_name: logicalName }) => logicalName)
    .sort((left, right) => compareCanonicalStrings(left, right))
  return {
    ...unsigned,
    packet_sha256: sha256(stableJson(unsigned, 0)),
  }
}

function assertRemoteGatewayAuthorized(control, trusted) {
  if (control.policy.mode !== 'remote_static') {
    throw new Error(
      'run-remote requires an externally supplied remote_static Rules of Engagement policy',
    )
  }
  const policy = normalizePolicy(control.policy, {
    workspaceRoot: control.policy.workspace_root,
    policySource: 'external',
  })
  const decision = authorizeAction(policy, {
    type: 'network',
    url: trusted.config.gateway_url,
    redirects: [],
  })
  if (!decision.allowed) {
    const message = decision.reasons
      .map(({ code, message: reason }) => `${code}: ${reason}`)
      .join('; ')
    throw new Error(`remote gateway is not authorized by the run policy: ${message}`)
  }
  const configuredUrl = new URL(trusted.config.gateway_url).href
  if (
    decision.normalized_action?.url !== configuredUrl
    || decision.normalized_action?.redirects?.length !== 0
  ) {
    throw new Error('remote gateway policy decision does not bind the exact configured endpoint')
  }
}

function assertAttemptUsesTrustedRemoteConfiguration(attempt, trusted) {
  if (
    attempt.lease.backend !== 'REMOTE_GATEWAY'
    || attempt.lease.remote_gateway_config_sha256 !== trusted.configSha256
    || attempt.lease.controller_key_id !== trusted.controllerKey.keyId
    || attempt.lease.gateway_key_id !== trusted.gatewayKey.keyId
  ) {
    throw new Error(
      `attempt ${attempt.attempt_id} was leased with different remote gateway trust material`,
    )
  }
}

async function failRemoteAttempt({
  loaded,
  attemptId,
  error,
  reasonPrefix,
  occurredAt = undefined,
}) {
  const message = error?.message ?? String(error)
  const failed = failProviderAttempt(loaded.run, attemptId, {
    reason: `${reasonPrefix}: ${message}`.slice(0, 16_000),
    recoverable: true,
    ...(occurredAt === undefined ? {} : { occurred_at: occurredAt }),
  })
  await persistLoadedRun(loaded, failed)
  return failed
}

async function completeRemoteAttempt(loaded, control, attempt, trusted) {
  assertAttemptUsesTrustedRemoteConfiguration(attempt, trusted)
  const job = loaded.run.jobs.find(({ job_id: jobId }) => jobId === attempt.job_id)
  if (!job) throw new Error(`remote attempt job ${attempt.job_id} no longer exists`)
  const sidecar = await loadJobSidecar(loaded.directory, loaded.run, job)
  const requestArtifact = await readRemoteRequestArtifact(loaded, attempt)
  const packet = remoteDispatchPacket(
    loaded.run,
    job,
    sidecar,
    requestArtifact.envelope.artifacts.map((artifact) => ({
      kind: artifact.kind,
      logical_name: artifact.logical_name,
    })),
  )
  if (packet.packet_sha256 !== attempt.lease.packet_sha256) {
    throw new Error('active remote attempt packet no longer matches the controller plan')
  }
  let active = attempt
  let acceptance = await readRemoteAcceptanceArtifact(
    loaded,
    active,
    {
      gatewayPublicKeyBytes: trusted.gatewayKeyBytes,
      expectedPromptTransform: trusted.config.prompt_transform,
    },
  )
  await assertRemoteSourceAnchors(
    loaded.directory,
    loaded.run,
    job,
    acceptance.request,
    acceptance.envelope.job_result,
    control.sealedSnapshots.source,
  )
  if (active.state === 'RESULT_CAPTURED') {
    const validated = recordProviderResultValidated(
      loaded.run,
      active.attempt_id,
    )
    await persistLoadedRun(loaded, validated)
    active = findActiveAttempt(loaded.run, job.job_id)
    acceptance = await readRemoteAcceptanceArtifact(
      loaded,
      active,
      {
        gatewayPublicKeyBytes: trusted.gatewayKeyBytes,
        expectedPromptTransform: trusted.config.prompt_transform,
      },
    )
  }
  if (active.state !== 'VALIDATED') {
    throw new Error(`remote attempt ${active.attempt_id} cannot commit from ${active.state}`)
  }
  const applied = applyJobResult(
    loaded.run,
    acceptance.envelope.job_result,
    {
      expectedPacketSha256: packet.packet_sha256,
      sidecar,
      commitObservedAttempt: (previous, candidate) =>
        commitProviderAttempt(previous, candidate, active.attempt_id),
    },
  )
  const advanced = advanceUntilBlocked(applied)
  await persistLoadedRun(loaded, advanced)
  console.log(`Remote ${job.job_id}: ${acceptance.envelope.job_result.state}`)
  console.log(`Attempt: ${active.attempt_id}`)
  console.log('Coverage authority: REMOTE_REQUEST_ACCEPTED')
  console.log(`Run: ${advanced.state}/${advanced.phase}`)
  return advanced
}

export async function runRemoteCommand(positionals, _options = {}, dependencies = {}) {
  const currentInstant = () => {
    const value = dependencies.now?.() ?? new Date()
    const date = value instanceof Date ? value : new Date(value)
    if (!Number.isFinite(date.getTime())) {
      throw new Error('run-remote clock returned an invalid instant')
    }
    return date
  }
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  assertValidRun(loaded.run)
  if (!['6.0.0', '7.0.0'].includes(loaded.run.schema_version) || !loaded.run.source_snapshot) {
    throw new Error(
      'run-remote requires a runner-ready v6 or v7 bundle created with remote_static Rules of Engagement and --seal-source',
    )
  }
  const trusted = await loadTrustedRemoteGatewayConfiguration(
    requirePositional(positionals, 1, 'remote gateway configuration'),
    loaded,
  )
  const control = await verifyControlBundle(
    loaded.directory,
    loaded.run,
    { requireCurrentLensPack: true },
  )
  assertRemoteGatewayAuthorized(control, trusted)
  for (const event of loaded.run.attempt_events ?? []) {
    if (event.event !== 'LEASED' || event.backend !== 'REMOTE_GATEWAY') continue
    if (
      event.remote_gateway_config_sha256 !== trusted.configSha256
      || event.controller_key_id !== trusted.controllerKey.keyId
      || event.gateway_key_id !== trusted.gatewayKey.keyId
    ) {
      throw new Error(
        'remote gateway configuration or key identity differs from existing run evidence; key and endpoint rotation require a new run',
      )
    }
  }

  const activeValue = findActiveAttempt(loaded.run)
  const activeAttempts = activeValue === null ? [] : activeValue
  if (activeAttempts.length > 1) {
    throw new Error('run-remote refuses a run with more than one active attempt')
  }
  if (activeAttempts.length === 1) {
    const active = activeAttempts[0]
    if (active.lease.backend === 'SERVICE_PROOF_CONTAINER') {
      throw new Error(
        `active attempt ${active.attempt_id} belongs to the service-proof backend; `
        + 'use run-service-proof',
      )
    }
    if (active.lease.backend !== 'REMOTE_GATEWAY') {
      throw new Error(
        `active attempt ${active.attempt_id} belongs to the sealed-container backend; use run-provider`,
      )
    }
    assertAttemptUsesTrustedRemoteConfiguration(active, trusted)
    const recovery = classifyProviderAttemptRecovery(
      loaded.run,
      active.attempt_id,
      { now: currentInstant() },
    )
    if (['RESULT_CAPTURED', 'VALIDATED'].includes(active.state)) {
      try {
        return await completeRemoteAttempt(loaded, control, active, trusted)
      } catch (error) {
        await failRemoteAttempt({
          loaded,
          attemptId: active.attempt_id,
          error,
          reasonPrefix: 'captured remote result could not commit',
          occurredAt: currentInstant().toISOString(),
        })
        throw error
      }
    }
    if (recovery.status === 'ACTIVE_UNEXPIRED') {
      throw new Error(
        `remote attempt ${active.attempt_id} is active until ${recovery.expires_at}; refusing to replay its one-use request`,
      )
    }
    if (recovery.status !== 'ACTIVE_EXPIRED') {
      throw new Error(
        `remote attempt ${active.attempt_id} cannot be recovered from ${recovery.status}`,
      )
    }
    const expiryError = new Error(
      `attempt lease expired at ${recovery.expires_at}; the prior remote outcome is ambiguous and request ${active.lease.request_id} will not be reused`,
    )
    expiryError.code = 'REMOTE_ATTEMPT_EXPIRED'
    await failRemoteAttempt({
      loaded,
      attemptId: active.attempt_id,
      error: expiryError,
      reasonPrefix: 'remote attempt expired',
      occurredAt: recovery.observed_at,
    })
  }

  const [job] = pendingJobsForCurrentPhase(loaded.run)
  if (!job) throw new Error('run has no provider job ready for remote execution')
  if (job.kind === 'REPORT' || job.kind === 'PATCH') {
    throw new Error(`job ${job.job_id} is controller-owned and cannot run remotely`)
  }
  const sidecar = await loadJobSidecar(loaded.directory, loaded.run, job)
  const artifacts = await observedProviderArtifacts(
    loaded.directory,
    loaded.run,
    job,
    sidecar,
    control,
    remoteProviderLimits(trusted.config),
  )
  const packet = remoteDispatchPacket(loaded.run, job, sidecar, artifacts)
  const attemptId = `attempt:${randomUUID()}`
  const requestId = `remote:${randomUUID()}`
  const nonce = randomBytes(32).toString('hex')
  const createdAt = currentInstant()
  const requestEnvelope = createRemoteRequestEnvelope({
    provenance: {
      run_id: loaded.run.run_id,
      job_id: job.job_id,
      plan_sha256: loaded.run.plan_digest,
      repository_tree_sha256: loaded.run.repository.tree_digest,
      lens_pack_sha256: loaded.run.lens_pack_digest,
      policy_sha256: loaded.run.policy_digest,
      source_snapshot_sha256: loaded.run.source_snapshot.root_sha256,
      control_snapshot_sha256: loaded.run.control_snapshot.root_sha256,
    },
    packet,
    artifacts,
    promptTransform: trusted.config.prompt_transform,
    privateKeyBytes: trusted.controllerKeyBytes,
    attemptId,
    requestId,
    nonce,
    createdAt,
    ttlMs: trusted.config.limits.request_ttl_ms,
  })
  const requestContent = stableJson(requestEnvelope, 0)
  assertBundleArtifactSize(requestContent, 'remote request envelope')
  reserveBundleArtifactCapacity(
    control.artifactCapacity,
    requestContent,
    'remote request envelope',
  )
  const requestArtifactKey = `request_${artifactKeyToken(attemptId).toLowerCase()}`
  const requestArtifactPath = `requests/${artifactToken(attemptId)}.json`
  await writeOnceBundleArtifact(
    loaded.directory,
    requestArtifactPath,
    requestContent,
  )
  const leased = leaseRemoteAttempt(loaded.run, job.job_id, {
    attempt_id: attemptId,
    nonce,
    packet_sha256: packet.packet_sha256,
    remote_gateway_config_sha256: trusted.configSha256,
    controller_key_id: trusted.controllerKey.keyId,
    gateway_key_id: trusted.gatewayKey.keyId,
    request_id: requestId,
    request_artifact_key: requestArtifactKey,
    request_artifact: {
      path: requestArtifactPath,
      sha256: sha256(requestContent),
    },
    occurred_at: requestEnvelope.controller.created_at,
    expires_at: requestEnvelope.controller.expires_at,
    budgets: {
      wall_clock_ms: trusted.config.limits.request_timeout_ms,
      max_requests: 1,
      max_bytes: (
        trusted.config.limits.max_request_bytes
        + trusted.config.limits.max_response_bytes
      ),
    },
  })
  if (typeof dependencies.beforeLeasePersist === 'function') {
    await dependencies.beforeLeasePersist({
      attempt_id: attemptId,
      job_id: job.job_id,
    })
  }
  await persistLoadedRun(loaded, leased)
  if (typeof dependencies.afterLeasePersist === 'function') {
    await dependencies.afterLeasePersist({
      attempt_id: attemptId,
      job_id: job.job_id,
    })
  }
  const started = markProviderAttemptStarted(loaded.run, attemptId, {
    occurred_at: requestEnvelope.controller.created_at,
  })
  await persistLoadedRun(loaded, started)

  let accepted
  try {
    const submit = dependencies.submitRemoteGatewayRequest
      ?? submitRemoteGatewayRequest
    accepted = await submit({
      config: trusted.config,
      requestEnvelope,
      gatewayPublicKeyBytes: trusted.gatewayKeyBytes,
      ...(dependencies.transport === undefined
        ? {}
        : { transport: dependencies.transport }),
      now: currentInstant(),
    })
  } catch (error) {
    await failRemoteAttempt({
      loaded,
      attemptId,
      error,
      reasonPrefix: 'remote gateway request failed',
      occurredAt: currentInstant().toISOString(),
    })
    throw error
  }

  try {
    const acceptanceContent = stableJson(accepted.acceptance_envelope, 0)
    assertBundleArtifactSize(acceptanceContent, 'remote acceptance envelope')
    reserveBundleArtifactCapacity(
      control.artifactCapacity,
      acceptanceContent,
      'remote acceptance envelope',
    )
    const artifactKey = `execution_${artifactKeyToken(attemptId).toLowerCase()}`
    const artifactPath = `executions/${artifactToken(attemptId)}.json`
    await writeOnceBundleArtifact(
      loaded.directory,
      artifactPath,
      acceptanceContent,
    )
    const acceptanceSha256 = sha256(acceptanceContent)
    const captured = recordProviderResultCaptured(loaded.run, attemptId, {
      execution_artifact_key: artifactKey,
      execution_artifact: {
        path: artifactPath,
        sha256: acceptanceSha256,
      },
      receipt_sha256: acceptanceSha256,
    })
    await persistLoadedRun(loaded, captured)
    return await completeRemoteAttempt(
      loaded,
      control,
      findActiveAttempt(loaded.run, job.job_id),
      trusted,
    )
  } catch (error) {
    const active = findActiveAttempt(loaded.run, job.job_id)
    if (active?.attempt_id === attemptId) {
      await failRemoteAttempt({
        loaded,
        attemptId,
        error,
        reasonPrefix: 'remote result capture or commit failed',
        occurredAt: currentInstant().toISOString(),
      })
    }
    throw error
  }
}

function providerSandboxPolicySha256(config, containerName) {
  return sha256(stableJson({
    backend: 'OCI_DOCKER',
    argv: buildDockerCreateArgs(config, containerName),
  }, 0))
}

function assertAttemptUsesTrustedProviderConfiguration(attempt, trusted) {
  if (attempt.lease.provider_config_sha256 !== trusted.configSha256) {
    throw new Error(
      `attempt ${attempt.attempt_id} was leased with a different provider configuration; ` +
      'retry with the original trusted configuration',
    )
  }
  const sandboxPolicySha256 = providerSandboxPolicySha256(
    trusted.config,
    attempt.lease.container_name,
  )
  if (attempt.lease.sandbox_policy_sha256 !== sandboxPolicySha256) {
    throw new Error(
      `attempt ${attempt.attempt_id} sandbox policy does not match the trusted configuration`,
    )
  }
}

// shell:false is load-bearing. The RoE allowlist matches program and argv
// exactly, and a shell would let an argument smuggle `;` or `&&` past it.
export function spawnProofCommand(program, args, cwd, limits = {}) {
  const timeoutMs = Number.isInteger(limits.timeout_ms) ? limits.timeout_ms : 120_000
  const killGraceMs = Number.isInteger(limits.kill_grace_ms) ? limits.kill_grace_ms : 1_000
  const maxOutputBytes = Number.isInteger(limits.max_output_bytes)
    ? limits.max_output_bytes
    : 65_536
  return new Promise((settle) => {
    const child = spawn(program, args, {
      cwd,
      shell: false,
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    const started = Date.now()
    const output = {
      stdout: [],
      stderr: [],
      stdoutBytes: 0,
      stderrBytes: 0,
      stdoutTruncated: false,
      stderrTruncated: false,
    }
    let timedOut = false
    let settled = false
    let forceTimer = null

    const capture = (name, chunk) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)
      const bytesKey = `${name}Bytes`
      const truncatedKey = `${name}Truncated`
      const remaining = Math.max(0, maxOutputBytes - output[bytesKey])
      if (remaining > 0) output[name].push(buffer.subarray(0, remaining))
      output[bytesKey] += Math.min(buffer.length, remaining)
      if (buffer.length > remaining) output[truncatedKey] = true
    }
    child.stdout.on('data', (chunk) => capture('stdout', chunk))
    child.stderr.on('data', (chunk) => capture('stderr', chunk))

    const finish = (code, signal, error = null) => {
      if (settled) return
      settled = true
      clearTimeout(timeout)
      if (forceTimer !== null) clearTimeout(forceTimer)
      const stdout = Buffer.concat(output.stdout).toString('utf8')
      let stderr = Buffer.concat(output.stderr).toString('utf8')
      if (error && stderr.length === 0) stderr = String(error.message)
      settle({
        code: timedOut ? 124 : (code ?? (error ? 127 : 1)),
        signal: signal ?? null,
        stdout,
        stderr,
        stdout_truncated: output.stdoutTruncated,
        stderr_truncated: output.stderrTruncated,
        timed_out: timedOut,
        spawn_error: error !== null,
        duration_ms: Date.now() - started,
      })
    }
    const timeout = setTimeout(() => {
      timedOut = true
      child.kill('SIGTERM')
      forceTimer = setTimeout(() => child.kill('SIGKILL'), killGraceMs)
    }, timeoutMs)
    child.on('close', (code, signal) => finish(code, signal))
    child.on('error', (error) => finish(null, null, error))
  })
}

function currentProofVerificationJob(run, jobId) {
  const job = pendingJobsForCurrentPhase(run).find((candidate) => (
    candidate.job_id === jobId
    && candidate.kind === 'PROOF'
    && candidate.job_id.startsWith('proof-verification:')
  ))
  if (!job) {
    throw new Error(
      `${jobId} is not a current pending proof-verification job for this run`,
    )
  }
  if (!Array.isArray(job.candidate_ids) || job.candidate_ids.length !== 1) {
    throw new Error(`proof-verification job ${jobId} must name exactly one candidate`)
  }
  const finding = run.findings.find(
    ({ candidate_id: candidateId }) => candidateId === job.candidate_ids[0],
  )
  if (!finding) {
    throw new Error(
      `proof-verification job ${jobId} references an unknown candidate`,
    )
  }
  return { finding, job }
}

function serviceProofVerificationJob(run, jobId) {
  const candidate = run.jobs.find((job) => job.job_id === jobId)
  if (candidate?.state === 'PENDING') {
    return currentProofVerificationJob(run, jobId)
  }
  if (
    candidate?.state !== 'RUNNING'
    || candidate.kind !== 'PROOF'
    || !candidate.job_id.startsWith('proof-verification:')
    || !Array.isArray(candidate.candidate_ids)
    || candidate.candidate_ids.length !== 1
  ) {
    throw new Error(
      `${jobId} is not a pending or recoverable RUNNING proof-verification job`,
    )
  }
  const finding = run.findings.find(
    ({ candidate_id: candidateId }) => candidateId === candidate.candidate_ids[0],
  )
  if (!finding) {
    throw new Error(`proof-verification job ${jobId} references an unknown candidate`)
  }
  return { finding, job: candidate }
}

async function readExternalProofDocument(
  value,
  label,
  targetRoot,
  bundleRoot,
  maxBytes,
) {
  const before = await canonicalUnlinkedFile(value, `${label} path`)
  if (pathWithin(targetRoot, before) || pathWithin(bundleRoot, before)) {
    throw new Error(`${label} must be supplied from outside the target and run bundle`)
  }
  const document = await readJson(before, { maxBytes, label })
  const after = await canonicalUnlinkedFile(value, `${label} path`)
  if (after !== before || pathWithin(targetRoot, after) || pathWithin(bundleRoot, after)) {
    throw new Error(`${label} path changed while it was being read`)
  }
  return document
}

function assertPublicProofWritesAuthorized(policy, config, route = 'run-proof') {
  for (const file of config.proof_files) {
    const decision = authorizeAction(policy, { type: 'write_file', path: file.path })
    if (!decision.allowed) {
      const detail = decision.reasons
        .map(({ code, message }) => `${code}: ${message}`)
        .join('; ')
      throw new Error(`proof file ${file.path} is not authorized by the run policy: ${detail}`)
    }
  }
  if ((config.patch_files?.length ?? 0) > 0) {
    throw new Error(
      `public ${route} does not apply candidate patches; remediation is a separate directive`,
    )
  }
}

function assertPublicServiceLoopbackAuthorized(policy, service) {
  const decision = authorizeAction(policy, {
    type: 'network',
    url: `http://127.0.0.1:${service.port}/`,
    redirects: [],
  })
  if (decision.allowed) return
  const detail = decision.reasons
    .map(({ code, message }) => `${code}: ${message}`)
    .join('; ')
  throw new Error(
    `service loopback port 127.0.0.1:${service.port} is not authorized by the run policy: ${detail}`,
  )
}

function serviceProofContainerName(role) {
  return `rta-proof-service-${role}-${randomUUID().replaceAll('-', '').toLowerCase()}`
}

function normalizedServiceProofFailure(error) {
  const code = typeof error?.code === 'string' ? error.code : ''
  const cleanupVerified = error?.evidence?.cleanup_verified === true
  if (!/^SERVICE_PROOF_[A-Z0-9_]+$/.test(code)) return null
  if (!cleanupVerified) return null
  let lifecyclePhase
  let blockingReason
  if (code.startsWith('SERVICE_PROOF_PRE_BOOT_')) {
    lifecyclePhase = 'pre-boot'
    blockingReason = 'the controller could not prove the loopback service port closed before boot'
  } else if (code.startsWith('SERVICE_PROOF_STARTUP_')) {
    lifecyclePhase = 'startup'
    blockingReason = 'the fixed loopback TCP readiness probe did not succeed before startup timeout'
  } else if (code.startsWith('SERVICE_PROOF_POST_PROBE_')) {
    lifecyclePhase = 'post-probe'
    blockingReason = 'the fixed loopback TCP readiness probe did not remain valid after the target probe'
  } else {
    lifecyclePhase = 'execution'
    blockingReason = 'the controller stopped the local service lifecycle before trusted T2 proof completed'
  }
  return {
    code,
    lifecycle_phase: lifecyclePhase,
    cleanup_verified: true,
    blocking_reason: blockingReason,
  }
}

function serviceProofErrorCauses(error) {
  return error instanceof AggregateError && Array.isArray(error.errors)
    ? [...error.errors]
    : [error]
}

async function removeServiceProofHostTemporaryDirectories(remove, paths) {
  const outcomes = await Promise.allSettled(paths.map((path) => (
    Promise.resolve().then(() => remove(path, { recursive: true, force: true }))
  )))
  return outcomes
    .filter(({ status }) => status === 'rejected')
    .map(({ reason }) => (
      reason instanceof Error ? reason : new Error(String(reason))
    ))
}

function serviceProofHostTemporaryCleanupError(primaryError, cleanupErrors) {
  const error = new AggregateError(
    [
      ...(primaryError === undefined ? [] : serviceProofErrorCauses(primaryError)),
      ...cleanupErrors,
    ],
    'service-proof host temporary directory cleanup failed',
  )
  error.code = 'SERVICE_PROOF_HOST_TEMP_CLEANUP_FAILED'
  return error
}

async function materializeCompleteProofSource({
  directory,
  run,
  sourceIndex,
  maxSourceBytes,
  inventoryOptions,
}) {
  const unavailable = sourceIndex.files.filter(
    ({ availability }) => availability !== 'AVAILABLE',
  )
  if (unavailable.length > 0) {
    const sample = unavailable.slice(0, 3).map(({ path, kind }) => `${path} (${kind})`)
    throw new Error(
      'PROOF_SOURCE_INCOMPLETE: sealed execution source contains unavailable files: '
      + sample.join(', '),
    )
  }
  const totalBytes = sourceIndex.files.reduce((total, file) => total + file.size, 0)
  if (totalBytes > maxSourceBytes) {
    throw new Error(
      `PROOF_SOURCE_LIMIT: sealed source is ${totalBytes} bytes; worker permits ${maxSourceBytes}`,
    )
  }
  const parent = await mkdtemp(join(tmpdir(), 'red-team-audit-sealed-proof-'))
  const root = join(parent, 'source')
  await mkdir(root, { mode: 0o700 })
  try {
    const shardCache = new Map()
    const files = []
    for (const file of sourceIndex.files) {
      files.push({
        path: file.path,
        bytes: await readIndexedSnapshotFile(
          directory,
          run,
          'source',
          sourceIndex,
          file,
          shardCache,
        ),
      })
    }
    await materializeSealedFiles(root, files)
    const staged = await inventoryRepository(root, inventoryOptions)
    if (staged.treeDigest !== run.repository.tree_digest) {
      throw new Error(
        'PROOF_SOURCE_DIGEST_MISMATCH: reconstructed sealed source does not match the planned tree',
      )
    }
    return { parent, root, totalBytes }
  } catch (error) {
    await rm(parent, { recursive: true, force: true })
    throw error
  }
}

export async function runProofCommand(positionals, options = {}, dependencies = {}) {
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  assertValidRun(loaded.run)
  if (loaded.run.capability_mode !== 'TEST_EXECUTION') {
    throw new Error(
      'run-proof requires a TEST_EXECUTION run; plan with a test-mode Rules of Engagement',
    )
  }
  if (!loaded.run.source_snapshot) {
    throw new Error('run-proof requires a bundle created with plan --seal-source')
  }
  const proofConfigPath = requirePositional(positionals, 1, 'proof configuration')
  const internalSpawn = dependencies.spawn
  const publicRoute = typeof internalSpawn !== 'function'
  const config = assertValidProofConfig(await readExternalProofDocument(
    proofConfigPath,
    'proof configuration JSON',
    loaded.run.repository.root,
    loaded.directory,
    8 * 1024 * 1024,
  ))
  if (publicRoute && config.schema_version !== '2.0.0') {
    throw new Error('public run-proof requires a v2 proof configuration')
  }

  const { finding, job } = currentProofVerificationJob(loaded.run, config.job_id)
  // This is deliberately the final repository read before the controller
  // creates the disposable mirror and starts the authored proof commands.
  const control = await verifyRepositorySnapshot(loaded.directory, loaded.run)
  const policy = normalizePolicy(control.policy, {
    workspaceRoot: control.policy.workspace_root,
    policySource: 'external',
  })
  let worker = null
  if (publicRoute) {
    assertPublicProofWritesAuthorized(policy, config)
    if (typeof options.worker !== 'string') {
      throw new Error('public run-proof requires --worker <proof-worker.json>')
    }
    worker = normalizeProofWorkerConfig(await readExternalProofDocument(
      options.worker,
      'proof worker configuration JSON',
      loaded.run.repository.root,
      loaded.directory,
      1024 * 1024,
    ))
  }
  const expectedPacket = dispatchPacket(loaded.run, job, undefined)
  const started = beginJob(loaded.run, job.job_id)

  const inventoryOptions = {
    maxTextBytes: loaded.run.coverage?.policy?.max_shard_bytes,
    includedRoots: policy.capabilities?.read_file?.enabled
      ? policy.capabilities.read_file.roots
      : [],
  }
  let sealedSource = null
  const targetRoot = publicRoute
    ? (sealedSource = await materializeCompleteProofSource({
        directory: loaded.directory,
        run: loaded.run,
        sourceIndex: control.sealedSnapshots.source,
        maxSourceBytes: worker.limits.max_source_bytes,
        inventoryOptions,
      })).root
    : loaded.run.repository.root
  const mirrorRoot = join(await mkdtemp(join(tmpdir(), 'red-team-audit-proof-')), 'mirror')
  // The non-mutation check must measure the target exactly as plan did, or it
  // reports every real run as mutated. Both inputs are recorded in the bundle.
  let outcome
  try {
    const dockerProof = dependencies.dockerProof ?? runDockerProofCommand
    outcome = await executeProof({
      targetRoot,
      mirrorRoot,
      expectedTreeDigest: loaded.run.repository.tree_digest,
      inventoryOptions,
      policy,
      config,
      spawn: publicRoute
        ? (program, args, sourceRoot, limits) => dockerProof({
            config: worker,
            sourceRoot,
            program,
            args,
            limits,
          })
        : internalSpawn,
    })
  } finally {
    if (sealedSource) {
      await rm(sealedSource.parent, { recursive: true, force: true })
    }
  }

  // The pair runner's sixth rule replays against the previous revision, which a
  // target with no history cannot supply. Recorded, never silently skipped.
  const ruleSixApplicable = existsSync(join(targetRoot, '.git'))
  const provisionalEvidence = proofEvidence({
    ...outcome,
    // executeProof uses null for an absent optional control; proofEvidence's
    // legacy migration branch distinguishes absence from an observed result.
    control: outcome.control ?? undefined,
  }, config, { ruleSixApplicable })
  const { artifact: _ephemeralProofArtifact, ...receiptEvidence } = provisionalEvidence
  const receipt = buildProofReceipt({
    run: loaded.run,
    job,
    config,
    packetSha256: expectedPacket.packet_sha256,
    outcome,
    evidence: receiptEvidence,
    ruleSixApplicable,
    ...(worker
      ? {
          proofWorker: {
            protocol: worker.protocol,
            config_sha256: proofWorkerConfigDigest(worker),
            image: worker.image,
            dependency_manifest_sha256: worker.dependency_manifest_sha256,
          },
        }
      : {}),
  })
  const receiptContent = stableJson(receipt)
  const receiptSha256 = sha256(receiptContent)
  const receiptArtifact = {
    path: `proofs/${artifactToken(job.job_id)}/receipt-${receiptSha256}.json`,
    sha256: receiptSha256,
  }
  const evidence = {
    ...receiptEvidence,
    artifact: receiptArtifact,
  }
  const jobResult = {
    schema_version: '1.0.0',
    run_id: loaded.run.run_id,
    job_id: job.job_id,
    input_sha256: expectedPacket.packet_sha256,
    producer: {
      name: 'red-team-audit-proof-controller',
      version: PLATFORM_VERSION,
      instance_id: 'run-proof:controller',
    },
    state: 'SUCCEEDED',
    examined_files: [],
    findings: [findingWithProofEvidence(finding, evidence)],
    coverage_gaps: [],
  }
  const applied = applyJobResult(started, jobResult, {
    expectedPacketSha256: expectedPacket.packet_sha256,
    artifact: receiptArtifact,
    inventoryEntries: control.inventoryEntries,
  })
  const advanced = advanceUntilBlocked(applied)
  assertRunManifestSize(stableJson(advanced))
  reserveBundleArtifactCapacity(
    control.artifactCapacity,
    receiptContent,
    'proof receipt artifact',
  )
  await writeOnceBundleArtifact(
    loaded.directory,
    receiptArtifact.path,
    receiptContent,
  )
  await persistLoadedRun(loaded, advanced)

  const rendered = stableJson({
    job_id: config.job_id,
    owned_paths: outcome.ownedPaths,
    evidence,
    receipt: receiptArtifact,
  })
  if (typeof dependencies.output === 'function') dependencies.output(rendered)
  else process.stdout.write(terminalSafeSerializedJson(rendered))
}

function serviceProofConfigurationDigest(config) {
  return sha256(stableJson(config, 0))
}

function serviceProofSessionBudget(controllerBudget) {
  const captureGraceMs = 60_000
  const sessionMs = controllerBudget.controller_session_budget_ms
  return {
    attack_controller_wall_clock_ms: sessionMs,
    control_controller_wall_clock_ms: sessionMs,
    capture_grace_ms: captureGraceMs,
    controller_wall_clock_ms: (2 * sessionMs) + captureGraceMs,
  }
}

function assertServiceProofAttemptConfiguration(
  attempt,
  { packetSha256, proofConfigSha256, proofWorkerConfigSha256, serviceSessionBudget },
) {
  if (
    attempt.lease.backend !== 'SERVICE_PROOF_CONTAINER'
    || attempt.lease.packet_sha256 !== packetSha256
    || attempt.lease.proof_config_sha256 !== proofConfigSha256
    || attempt.lease.proof_worker_config_sha256 !== proofWorkerConfigSha256
    || stableJson(attempt.lease.service_session_budget, 0)
      !== stableJson(serviceSessionBudget, 0)
  ) {
    throw new Error(
      `service-proof attempt ${attempt.attempt_id} is bound to different trusted inputs`,
    )
  }
}

function assertServiceProofRecoveryCleanupResult(result, expectedNames) {
  if (
    result === null
    || typeof result !== 'object'
    || Array.isArray(result)
    || result.cleanup_verified !== true
    || result.service_container_names === null
    || typeof result.service_container_names !== 'object'
    || Array.isArray(result.service_container_names)
    || stableJson(result.service_container_names, 0) !== stableJson(expectedNames, 0)
  ) {
    const error = new Error(
      'service-proof recovery cleanup did not attest both exact leased container names',
    )
    error.code = 'SERVICE_PROOF_RECOVERY_CLEANUP_UNVERIFIED'
    error.cleanup_verified = false
    error.evidence = {
      verification_status: 'UNPROVEN',
      cleanup_verified: false,
    }
    throw error
  }
  return result
}

async function assertServiceProofDispatchLeaseCurrent(loaded, attempt, now) {
  const current = await loadRun(loaded.directory)
  const currentAttempt = findActiveAttempt(current.run, attempt.job_id)
  const recovery = classifyServiceProofAttemptRecovery(
    current.run,
    attempt.attempt_id,
    { now },
  )
  if (
    current.sourceDigest !== loaded.sourceDigest
    || currentAttempt?.attempt_id !== attempt.attempt_id
    || recovery.status !== 'ACTIVE_UNEXPIRED'
    || recovery.state !== 'STARTED'
  ) {
    const error = new Error(
      `service-proof attempt ${attempt.attempt_id} is no longer dispatchable`,
    )
    error.code = 'SERVICE_PROOF_ATTEMPT_EXPIRED_BEFORE_DISPATCH'
    error.evidence = {
      verification_status: 'UNPROVEN',
      cleanup_verified: false,
    }
    throw error
  }
}

function serviceProofPersistedFailureCode(error) {
  return typeof error?.code === 'string' && /^[A-Z][A-Z0-9_]+$/.test(error.code)
    ? error.code
    : 'SERVICE_PROOF_CONTROLLER_FAILED'
}

function appendServiceProofRunError(previous, candidate, job, error) {
  const code = serviceProofPersistedFailureCode(error)
  const message = code === 'SERVICE_PROOF_RECOVERY_CLEANUP_UNVERIFIED'
    ? 'expired service-proof container cleanup could not be verified'
    : 'service-proof controller failed before trusted proof evidence committed'
  candidate.errors.push({
    error_id: `${job.job_id}:error:${candidate.errors.length + 1}`,
    phase: candidate.phase,
    code,
    message,
    recoverable: false,
    job_id: job.job_id,
  })
  assertValidRunTransition(previous, candidate)
  return candidate
}

async function failActiveServiceProofAttempt(loaded, job, attempt, error) {
  const code = serviceProofPersistedFailureCode(error)
  const previous = loaded.run
  const failed = failServiceProofAttempt(previous, attempt.attempt_id, {
    reason: code === 'SERVICE_PROOF_RECOVERY_CLEANUP_UNVERIFIED'
      ? 'expired service-proof container cleanup could not be verified'
      : 'service-proof controller failed before trusted proof evidence committed',
    recoverable: false,
  })
  await persistLoadedRun(
    loaded,
    advanceUntilBlocked(appendServiceProofRunError(previous, failed, job, error)),
  )
}

async function completeServiceProofAttempt({
  loaded,
  control,
  finding,
  job,
  attempt,
  output,
  resumed = false,
}) {
  let active = attempt
  let receipt = await readServiceProofAttemptReceipt(loaded, active)
  if (active.state === 'RESULT_CAPTURED') {
    const validated = recordServiceProofResultValidated(
      loaded.run,
      active.attempt_id,
    )
    await persistLoadedRun(loaded, validated)
    active = findProviderAttempt(loaded.run, active.attempt_id)
  }
  if (active.state !== 'VALIDATED') {
    throw new Error(
      `service-proof attempt ${active.attempt_id} cannot commit from ${active.state}`,
    )
  }
  receipt = await readServiceProofAttemptReceipt(loaded, active)
  const receiptArtifact = structuredClone(
    loaded.run.artifacts[active.execution_artifact_key],
  )
  const evidence = {
    ...structuredClone(receipt.evidence),
    artifact: receiptArtifact,
  }
  const jobResult = {
    schema_version: '1.0.0',
    run_id: loaded.run.run_id,
    job_id: job.job_id,
    input_sha256: active.lease.packet_sha256,
    producer: {
      name: 'red-team-audit-service-proof-controller',
      version: PLATFORM_VERSION,
      instance_id: 'run-service-proof:controller',
    },
    state: 'SUCCEEDED',
    examined_files: [],
    findings: [findingWithProofEvidence(finding, evidence)],
    coverage_gaps: [],
  }
  const applied = applyJobResult(loaded.run, jobResult, {
    expectedPacketSha256: active.lease.packet_sha256,
    inventoryEntries: control.inventoryEntries,
    commitObservedAttempt: (previous, candidate) => commitServiceProofAttempt(
      previous,
      candidate,
      active.attempt_id,
    ),
  })
  const advanced = advanceUntilBlocked(applied)
  await persistLoadedRun(loaded, advanced)

  const rendered = stableJson({
    job_id: job.job_id,
    owned_paths: receipt.outcome.owned_paths,
    evidence,
    receipt: receiptArtifact,
    attempt_id: active.attempt_id,
    resumed,
  })
  if (typeof output === 'function') output(rendered)
  else process.stdout.write(terminalSafeSerializedJson(rendered))
}

async function runServiceProofCommandWithLockHeld(
  positionals,
  options,
  dependencies,
  loaded,
) {
  const completeServiceProof = dependencies.completeServiceProofAttempt
    ?? completeServiceProofAttempt
  if (typeof completeServiceProof !== 'function') {
    throw new TypeError('completeServiceProofAttempt must be a function')
  }
  assertValidRun(loaded.run)
  if (loaded.run.capability_mode !== 'LOCAL_DYNAMIC') {
    throw new Error(
      'run-service-proof requires a LOCAL_DYNAMIC run; plan with local_dynamic Rules of Engagement',
    )
  }
  if (!loaded.run.source_snapshot) {
    throw new Error('run-service-proof requires a bundle created with plan --seal-source')
  }
  if (loaded.run.schema_version !== '7.0.0') {
    throw new Error('run-service-proof durable service-container attempts require a v7 run')
  }

  const config = assertValidProofConfig(await readExternalProofDocument(
    requirePositional(positionals, 1, 'service proof configuration'),
    'service proof configuration JSON',
    loaded.run.repository.root,
    loaded.directory,
    8 * 1024 * 1024,
  ))
  if (config.schema_version !== '3.0.0') {
    throw new Error('public run-service-proof requires a v3 service proof configuration')
  }
  if (typeof options.worker !== 'string') {
    throw new Error('public run-service-proof requires --worker <proof-worker.json>')
  }

  let { finding, job } = serviceProofVerificationJob(loaded.run, config.job_id)
  // This remains the final read of the named target. All execution below uses
  // only the separately reconstructed and verified source snapshot.
  const control = await verifyRepositorySnapshot(loaded.directory, loaded.run)
  const policy = normalizePolicy(control.policy, {
    workspaceRoot: control.policy.workspace_root,
    policySource: 'external',
  })
  assertPublicProofWritesAuthorized(policy, config, 'T2 run-service-proof')
  assertPublicServiceLoopbackAuthorized(policy, config.service)
  const worker = normalizeProofWorkerConfig(await readExternalProofDocument(
    options.worker,
    'proof worker configuration JSON',
    loaded.run.repository.root,
    loaded.directory,
    1024 * 1024,
  ))
  const controllerBudget = serviceProofControllerBudget(worker)
  const serviceSessionBudget = serviceProofSessionBudget(controllerBudget)
  const proofConfigSha256 = serviceProofConfigurationDigest(config)
  const proofWorkerConfigSha256 = proofWorkerConfigDigest(worker)
  const proofWorkerReceipt = {
    protocol: worker.protocol,
    config_sha256: proofWorkerConfigSha256,
    image: worker.image,
    dependency_manifest_sha256: worker.dependency_manifest_sha256,
    wall_time_ms: worker.limits.wall_time_ms,
    ...controllerBudget,
  }

  let expectedPacket = dispatchPacket(loaded.run, job, undefined)
  let activeAttempt = findActiveAttempt(loaded.run, job.job_id)
  if (job.state === 'RUNNING' && activeAttempt === null) {
    throw new Error(
      `LEGACY_SERVICE_PROOF_RUNNING_UNRECOVERABLE: ${job.job_id} was started before `
      + 'durable two-container leases existed; its container identities are unknown',
    )
  }
  if (activeAttempt !== null) {
    if (activeAttempt.lease.backend !== 'SERVICE_PROOF_CONTAINER') {
      throw new Error(
        `active attempt ${activeAttempt.attempt_id} belongs to ${activeAttempt.lease.backend}; `
        + 'run-service-proof will not take over another backend',
      )
    }
    assertServiceProofAttemptConfiguration(activeAttempt, {
      packetSha256: expectedPacket.packet_sha256,
      proofConfigSha256,
      proofWorkerConfigSha256,
      serviceSessionBudget,
    })
    const recoveryOccurredAt = typeof dependencies.serviceProofNow === 'function'
      ? dependencies.serviceProofNow()
      : new Date().toISOString()
    const recovery = classifyServiceProofAttemptRecovery(
      loaded.run,
      activeAttempt.attempt_id,
      { now: recoveryOccurredAt },
    )
    if (recovery.status === 'ACTIVE_UNEXPIRED') {
      throw new Error(
        `service-proof attempt ${activeAttempt.attempt_id} is active until `
        + `${recovery.expires_at}; refusing concurrent or premature replay`,
      )
    }
    if (recovery.status === 'RESUMABLE') {
      await completeServiceProof({
        loaded,
        control,
        finding,
        job,
        attempt: activeAttempt,
        output: dependencies.output,
        resumed: true,
      })
      return
    }
    if (recovery.status === 'EXPIRED_STARTED') {
      const cleanupServiceProofContainers = dependencies.cleanupServiceProofContainers
        ?? cleanupDockerServiceProofContainers
      try {
        const cleanupResult = await cleanupServiceProofContainers({
          config: worker,
          service: config.service,
          limits: config.limits,
          serviceContainerNames: recovery.service_container_names,
        })
        assertServiceProofRecoveryCleanupResult(
          cleanupResult,
          recovery.service_container_names,
        )
      } catch (error) {
        const cleanupError = error?.code === 'SERVICE_PROOF_RECOVERY_CLEANUP_UNVERIFIED'
          ? error
          : Object.assign(new AggregateError(
              [error],
              'expired service-proof container cleanup could not be verified',
            ), {
              code: 'SERVICE_PROOF_RECOVERY_CLEANUP_UNVERIFIED',
              cleanup_verified: false,
            })
        const previous = loaded.run
        const terminal = recoverExpiredServiceProofAttempt(
          previous,
          activeAttempt.attempt_id,
          {
            occurred_at: recoveryOccurredAt,
            cleanup_verified: false,
            service_container_names: recovery.service_container_names,
          },
        )
        await persistLoadedRun(
          loaded,
          advanceUntilBlocked(
            appendServiceProofRunError(previous, terminal, job, cleanupError),
          ),
        )
        throw cleanupError
      }
    } else if (recovery.status !== 'EXPIRED_LEASED') {
      throw new Error(
        `service-proof attempt ${activeAttempt.attempt_id} cannot recover from `
        + recovery.status,
      )
    }
    const recovered = recoverExpiredServiceProofAttempt(
      loaded.run,
      activeAttempt.attempt_id,
      {
        occurred_at: recoveryOccurredAt,
        ...(recovery.status === 'EXPIRED_STARTED'
          ? {
              cleanup_verified: true,
              service_container_names: recovery.service_container_names,
            }
          : {}),
      },
    )
    await persistLoadedRun(loaded, recovered)
    ;({ finding, job } = serviceProofVerificationJob(loaded.run, config.job_id))
    expectedPacket = dispatchPacket(loaded.run, job, undefined)
    activeAttempt = null
  }
  const inventoryOptions = {
    maxTextBytes: loaded.run.coverage?.policy?.max_shard_bytes,
    includedRoots: policy.capabilities?.read_file?.enabled
      ? policy.capabilities.read_file.roots
      : [],
  }
  const removeHostTemporaryDirectory = dependencies.removeHostTemporaryDirectory ?? rm
  const sealedSource = await materializeCompleteProofSource({
    directory: loaded.directory,
    run: loaded.run,
    sourceIndex: control.sealedSnapshots.source,
    maxSourceBytes: worker.limits.max_source_bytes,
    inventoryOptions,
  })
  let ruleSixApplicable
  let mirrorParent
  try {
    ruleSixApplicable = existsSync(join(sealedSource.root, '.git'))
    mirrorParent = await (
      dependencies.createServiceProofMirrorTemporaryDirectory ?? mkdtemp
    )(join(tmpdir(), 'red-team-audit-service-proof-'))
  } catch (error) {
    const cleanupErrors = await removeServiceProofHostTemporaryDirectories(
      removeHostTemporaryDirectory,
      [sealedSource.parent],
    )
    if (cleanupErrors.length > 0) {
      throw serviceProofHostTemporaryCleanupError(error, cleanupErrors)
    }
    throw error
  }
  const mirrorRoot = join(mirrorParent, 'mirror')
  let outcome
  let proofWorktreeSha256
  let executionError
  try {
    const serviceContainerNames = {
      attack: serviceProofContainerName('attack'),
      control: serviceProofContainerName('control'),
    }
    const leased = leaseServiceProofAttempt(loaded.run, job.job_id, {
      packet_sha256: expectedPacket.packet_sha256,
      proof_config_sha256: proofConfigSha256,
      proof_worker_config_sha256: proofWorkerConfigSha256,
      service_container_names: serviceContainerNames,
      service_session_budget: serviceSessionBudget,
    })
    // LEASED is the single-winner CAS. STARTED is durable before Docker can be
    // reached, so a later controller can clean these two exact names.
    await persistLoadedRun(loaded, leased)
    activeAttempt = findActiveAttempt(loaded.run, job.job_id)
    const attemptStarted = markServiceProofAttemptStarted(
      loaded.run,
      activeAttempt.attempt_id,
    )
    await persistLoadedRun(loaded, attemptStarted)
    activeAttempt = findProviderAttempt(loaded.run, activeAttempt.attempt_id)
    const dockerServiceProof = dependencies.dockerServiceProof
      ?? runDockerServiceProofCommand
    let invocation = 0
    try {
      outcome = await executeProof({
        targetRoot: sealedSource.root,
        mirrorRoot,
        expectedTreeDigest: loaded.run.repository.tree_digest,
        inventoryOptions,
        policy,
        config,
        spawn: async (program, args, sourceRoot, limits) => {
          const role = invocation === 0 ? 'attack' : invocation === 1 ? 'control' : null
          invocation += 1
          if (role === null) {
            throw new Error('public service proof attempted an unexpected third service session')
          }
          const observedProofWorktreeSha256 = await proofSourceTreeDigest(
            sourceRoot,
            worker.limits.max_source_bytes,
          )
          if (proofWorktreeSha256 === undefined) {
            proofWorktreeSha256 = observedProofWorktreeSha256
          } else if (proofWorktreeSha256 !== observedProofWorktreeSha256) {
            throw new Error('proof worktree changed between isolated service sessions')
          }
          const dispatchNow = typeof dependencies.serviceProofDispatchNow === 'function'
            ? dependencies.serviceProofDispatchNow()
            : new Date().toISOString()
          await assertServiceProofDispatchLeaseCurrent(
            loaded,
            activeAttempt,
            dispatchNow,
          )
          return await dockerServiceProof({
            config: worker,
            sourceRoot,
            service: config.service,
            program,
            args,
            limits,
            containerName: activeAttempt.lease.service_container_names[role],
          })
        },
      })
    } catch (error) {
      const failure = normalizedServiceProofFailure(error)
      if (!failure) throw error
      const partial = error?.proof_outcome
      outcome = {
        demonstration: partial?.demonstration ?? null,
        control: partial?.control ?? null,
        remediation: partial?.remediation ?? null,
        ownedPaths: partial?.ownedPaths ?? config.proof_files
          .map(({ path }) => path)
          .sort(compareCanonicalStrings),
        mirrorRoot,
        mirrorRetained: false,
        failure,
      }
    }
  } catch (error) {
    executionError = error
  }

  const cleanupErrors = await removeServiceProofHostTemporaryDirectories(
    removeHostTemporaryDirectory,
    [mirrorParent, sealedSource.parent],
  )
  if (cleanupErrors.length > 0) {
    executionError = serviceProofHostTemporaryCleanupError(
      executionError,
      cleanupErrors,
    )
  }
  if (executionError !== undefined) {
    if (activeAttempt?.state === 'STARTED') {
      try {
        await failActiveServiceProofAttempt(
          loaded,
          job,
          activeAttempt,
          executionError,
        )
      } catch (persistenceError) {
        throw new AggregateError(
          [...serviceProofErrorCauses(executionError), persistenceError],
          `service-proof attempt ${activeAttempt.attempt_id} failed and its FAILED event could not be persisted`,
        )
      }
    }
    throw executionError
  }

  try {
    const provisionalEvidence = proofEvidence({
      ...outcome,
      control: outcome.control ?? undefined,
    }, config, {
      ruleSixApplicable,
      proofWorker: proofWorkerReceipt,
      proofWorktreeSha256,
    })
    const { artifact: _ephemeralProofArtifact, ...receiptEvidence } = provisionalEvidence
    const receipt = buildProofReceipt({
      run: loaded.run,
      job,
      config,
      packetSha256: expectedPacket.packet_sha256,
      outcome,
      evidence: receiptEvidence,
      ruleSixApplicable,
      proofWorker: proofWorkerReceipt,
      proofWorktreeSha256,
      serviceProofAttempt: activeAttempt,
    })
    const receiptContent = stableJson(receipt)
    const receiptSha256 = sha256(receiptContent)
    const receiptArtifact = {
      path: `proofs/${artifactToken(job.job_id)}/receipt-${receiptSha256}.json`,
      sha256: receiptSha256,
    }
    reserveBundleArtifactCapacity(
      control.artifactCapacity,
      receiptContent,
      'service proof receipt artifact',
    )
    await writeOnceBundleArtifact(
      loaded.directory,
      receiptArtifact.path,
      receiptContent,
    )
    const captured = recordServiceProofResultCaptured(
      loaded.run,
      activeAttempt.attempt_id,
      {
        execution_artifact_key:
          `service_proof_${artifactKeyToken(job.job_id).toLowerCase()}`,
        execution_artifact: receiptArtifact,
        receipt_sha256: receiptSha256,
      },
    )
    assertRunManifestSize(stableJson(captured))
    await persistLoadedRun(loaded, captured)
    activeAttempt = findProviderAttempt(loaded.run, activeAttempt.attempt_id)
    await completeServiceProof({
      loaded,
      control,
      finding,
      job,
      attempt: activeAttempt,
      output: dependencies.output,
      resumed: false,
    })
  } catch (error) {
    const stillActive = findActiveAttempt(loaded.run, job.job_id)
    if (
      stillActive?.lease.backend === 'SERVICE_PROOF_CONTAINER'
      && stillActive.state === 'STARTED'
    ) {
      try {
        await failActiveServiceProofAttempt(loaded, job, stillActive, error)
      } catch (persistenceError) {
        throw new AggregateError(
          [error, persistenceError],
          `service-proof attempt ${stillActive.attempt_id} could not capture evidence or persist failure`,
        )
      }
    }
    throw error
  }
}

export async function runServiceProofCommand(positionals, options = {}, dependencies = {}) {
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  const commandLock = await acquireServiceProofCommandLock(loaded.path, {
    processIsAlive: dependencies.serviceProofProcessIsAlive,
  })
  try {
    return await runServiceProofCommandWithLockHeld(
      positionals,
      options,
      dependencies,
      loaded,
    )
  } finally {
    await releaseOwnedLock(commandLock.path, commandLock.token)
  }
}

export async function runProviderCommand(positionals, _options = {}, dependencies = {}) {
  const providerRunner = dependencies.providerRunner ?? runDockerProvider
  const cleanupProviderContainer = dependencies.cleanupProviderContainer
    ?? cleanupDockerProviderContainer
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  assertValidRun(loaded.run)
  if (!['2.0.0', '3.0.0', '4.0.0', '5.0.0', '6.0.0', '7.0.0'].includes(loaded.run.schema_version)
    || !loaded.run.source_snapshot) {
    throw new Error(
      'run-provider requires a runner-ready v2 bundle created with plan --seal-source',
    )
  }
  const trusted = await loadTrustedProviderConfiguration(
    requirePositional(positionals, 1, 'provider configuration'),
    loaded,
  )
  const control = await verifyControlBundle(
    loaded.directory,
    loaded.run,
    {
      requireCurrentLensPack: true,
      pinnedReceiptKeyId: trusted.signingKey.keyId,
    },
  )
  if (control.policy.mode !== 'static') {
    throw new Error('run-provider accepts only static Rules of Engagement; use run-remote for remote_static runs')
  }
  if (
    control.evidenceKeyId !== undefined
    && control.evidenceKeyId !== trusted.signingKey.keyId
  ) {
    throw new Error(
      'controller receipt signing key differs from the existing run evidence key; ' +
      'key rotation within one run is not permitted',
    )
  }

  const activeValue = findActiveAttempt(loaded.run)
  const activeAttempts = activeValue === null ? [] : activeValue
  if (activeAttempts.length > 1) {
    throw new Error('run-provider refuses a run with more than one active attempt')
  }
  if (activeAttempts.length === 1) {
    const active = activeAttempts[0]
    if (active.lease.backend === 'SERVICE_PROOF_CONTAINER') {
      throw new Error(
        `active attempt ${active.attempt_id} belongs to the service-proof backend; `
        + 'use run-service-proof',
      )
    }
    if (active.lease.backend === 'REMOTE_GATEWAY') {
      throw new Error(
        `active attempt ${active.attempt_id} belongs to the remote gateway backend; use run-remote`,
      )
    }
    if (active.lease.backend !== 'SEALED_CONTAINER') {
      throw new Error(
        `active attempt ${active.attempt_id} uses an unsupported backend`,
      )
    }
    const recovery = classifyProviderAttemptRecovery(
      loaded.run,
      active.attempt_id,
      { now: new Date() },
    )
    if (['RESULT_CAPTURED', 'VALIDATED'].includes(active.state)) {
      assertAttemptUsesTrustedProviderConfiguration(active, trusted)
      try {
        return await completeObservedAttempt(
          loaded,
          control,
          active,
          trusted.signingKey,
        )
      } catch (error) {
        let partialReceipt
        const currentAttempt = findProviderAttempt(
          loaded.run,
          active.attempt_id,
        )
        if (currentAttempt.execution_artifact_key !== undefined) {
          try {
            const envelope = await readAttemptEnvelope(
              loaded,
              currentAttempt,
              trusted.signingKey.keyId,
            )
            partialReceipt = envelope.provider_execution.receipt
          } catch {
            // The original completion error remains the primary failure. Bundle
            // validation will independently reject an invalid captured envelope.
          }
        }
        try {
          await failObservedAttemptWithEvidence({
            loaded,
            control,
            attemptId: active.attempt_id,
            signingKey: trusted.signingKey,
            error,
            reasonPrefix: 'captured result could not commit',
            partialReceipt,
          })
        } catch (failurePersistenceError) {
          throw new AggregateError(
            [error, failurePersistenceError],
            `provider attempt ${active.attempt_id} failed and its FAILED event could not be persisted`,
          )
        }
        throw error
      }
    }
    if (recovery.status === 'ACTIVE_UNEXPIRED') {
      throw new Error(
        `provider attempt ${active.attempt_id} is active until ${recovery.expires_at}; ` +
        'refusing to steal its lease or clean its container',
      )
    }
    if (recovery.status !== 'ACTIVE_EXPIRED') {
      throw new Error(
        `provider attempt ${active.attempt_id} cannot be recovered from ${recovery.status}`,
      )
    }
    assertAttemptUsesTrustedProviderConfiguration(active, trusted)
    if (active.state === 'STARTED') {
      try {
        await cleanupProviderContainer({
          config: trusted.config,
          containerName: active.lease.container_name,
        })
      } catch (error) {
        try {
          await failObservedAttemptWithEvidence({
            loaded,
            control,
            attemptId: active.attempt_id,
            signingKey: trusted.signingKey,
            error,
            reasonPrefix:
              'expired provider attempt cleanup could not verify container absence',
          })
        } catch (failurePersistenceError) {
          throw new AggregateError(
            [error, failurePersistenceError],
            `provider attempt ${active.attempt_id} cleanup failed and its FAILED event could not be persisted`,
          )
        }
        throw error
      }
    }
    const expiryError = new Error(
      `attempt lease expired at ${recovery.expires_at} before the prior ` +
      'controller captured a result',
    )
    expiryError.code = 'PROVIDER_ATTEMPT_EXPIRED'
    await failObservedAttemptWithEvidence({
      loaded,
      control,
      attemptId: active.attempt_id,
      signingKey: trusted.signingKey,
      error: expiryError,
      reasonPrefix: 'provider attempt expired',
      occurredAt: recovery.observed_at,
    })
  }

  const [job] = pendingJobsForCurrentPhase(loaded.run)
  if (!job) {
    throw new Error('run has no provider job ready for observed execution')
  }
  if (job.kind === 'REPORT' || job.kind === 'PATCH') {
    throw new Error(`job ${job.job_id} is controller-owned and cannot run in a provider`)
  }
  const sidecar = await loadJobSidecar(loaded.directory, loaded.run, job)
  const packet = observedDispatchPacket(loaded.run, job, sidecar)
  const artifacts = await observedProviderArtifacts(
    loaded.directory,
    loaded.run,
    job,
    sidecar,
    control,
    trusted.config,
  )
  const attemptId = `attempt:${randomUUID()}`
  const containerName = `rta-provider-${randomUUID().replaceAll('-', '').toLowerCase()}`
  const leaseOccurredAt = new Date()
  const totalAttemptBudgetMs = (
    trusted.config.limits.wall_time_ms
    + (
      PROVIDER_DOCKER_COMMAND_BUDGET_SLOTS
      * trusted.config.limits.docker_command_timeout_ms
    )
    + PROVIDER_CAPTURE_GRACE_MS
  )
  const sandboxPolicySha256 = providerSandboxPolicySha256(
    trusted.config,
    containerName,
  )
  const leased = leaseProviderAttempt(loaded.run, job.job_id, {
    attempt_id: attemptId,
    packet_sha256: packet.packet_sha256,
    provider_config_sha256: trusted.configSha256,
    sandbox_policy_sha256: sandboxPolicySha256,
    container_name: containerName,
    occurred_at: leaseOccurredAt.toISOString(),
    expires_at: new Date(
      leaseOccurredAt.getTime() + totalAttemptBudgetMs,
    ).toISOString(),
    budgets: {
      wall_clock_ms: trusted.config.limits.wall_time_ms,
      max_requests: trusted.config.limits.max_deliveries,
      max_bytes: trusted.config.limits.max_total_delivery_bytes,
    },
  })
  if (typeof dependencies.beforeLeasePersist === 'function') {
    await dependencies.beforeLeasePersist({
      attempt_id: attemptId,
      job_id: job.job_id,
    })
  }
  await persistLoadedRun(loaded, leased)
  if (typeof dependencies.afterLeasePersist === 'function') {
    await dependencies.afterLeasePersist({
      attempt_id: attemptId,
      job_id: job.job_id,
    })
  }
  const started = markProviderAttemptStarted(loaded.run, attemptId)
  await persistLoadedRun(loaded, started)

  let execution
  try {
    execution = await providerRunner({
      config: trusted.config,
      packet,
      artifacts,
      containerName,
    })
    assertValidProviderExecution(execution)
    assertRequiredControlConsumption(execution, artifacts)
  } catch (error) {
    try {
      await failObservedAttemptWithEvidence({
        loaded,
        control,
        attemptId,
        signingKey: trusted.signingKey,
        error,
        reasonPrefix: 'provider execution failed',
        partialReceipt: error?.partial_receipt ?? execution?.receipt,
      })
    } catch (failurePersistenceError) {
      throw new AggregateError(
        [error, failurePersistenceError],
        `provider attempt ${attemptId} failed and its FAILED event could not be persisted`,
      )
    }
    throw error
  }
  try {
    const active = findActiveAttempt(loaded.run, job.job_id)
    const envelope = createControllerExecutionEnvelope(
      execution,
      active,
      trusted.signingKey,
    )
    const envelopeContent = stableJson(envelope)
    assertBundleArtifactSize(envelopeContent, 'provider execution envelope')
    reserveBundleArtifactCapacity(
      control.artifactCapacity,
      envelopeContent,
      'provider execution envelope',
    )
    const artifactKey = `execution_${artifactKeyToken(attemptId).toLowerCase()}`
    const artifactPath = `executions/${artifactToken(attemptId)}.json`
    await writeOnceBundleArtifact(
      loaded.directory,
      artifactPath,
      envelopeContent,
    )
    const captured = recordProviderResultCaptured(loaded.run, attemptId, {
      execution_artifact_key: artifactKey,
      execution_artifact: {
        path: artifactPath,
        sha256: sha256(envelopeContent),
      },
      receipt_sha256: envelope.controller.receipt_sha256,
    })
    await persistLoadedRun(loaded, captured)
    return await completeObservedAttempt(
      loaded,
      control,
      findActiveAttempt(loaded.run, job.job_id),
      trusted.signingKey,
    )
  } catch (error) {
    const active = findActiveAttempt(loaded.run, job.job_id)
    if (active?.attempt_id === attemptId) {
      try {
        await failObservedAttemptWithEvidence({
          loaded,
          control,
          attemptId,
          signingKey: trusted.signingKey,
          error,
          reasonPrefix: 'provider result capture or commit failed',
          partialReceipt: execution?.receipt,
        })
      } catch (failurePersistenceError) {
        throw new AggregateError(
          [error, failurePersistenceError],
          `provider attempt ${attemptId} failed and its FAILED event could not be persisted`,
        )
      }
    }
    throw error
  }
}

async function prepareOneResult(
  loaded,
  resultPath,
  artifactCapacity,
  inventoryEntries,
  options = {},
) {
  const source = options.source
    ?? await readJobResultSource(resultPath, options.expectedSource)
  const jobResult = source.jobResult
  assertValidJobResult(jobResult)
  const job = loaded.run.jobs.find(({ job_id }) => job_id === jobResult.job_id)
  if (!job) throw new Error(`unknown job ${jobResult.job_id}`)
  const sidecar = await loadJobSidecar(loaded.directory, loaded.run, job)
  const expectedPacket = dispatchPacket(loaded.run, job, sidecar)
  if (
    typeof jobResult.input_sha256 !== 'string'
    || jobResult.input_sha256.toLowerCase() !== expectedPacket.packet_sha256
  ) {
    throw new Error(
      `job result ${job.job_id} is not bound to the current dispatch packet`,
    )
  }
  if (
    jobResult.producer === null
    || typeof jobResult.producer !== 'object'
    || Array.isArray(jobResult.producer)
  ) {
    throw new Error(`job result ${job.job_id} must identify its producer`)
  }
  const started = job.state === 'PENDING'
    ? beginJob(loaded.run, job.job_id)
    : loaded.run
  const canonicalResult = stableJson(jobResult)
  const resultDigest = sha256(canonicalResult)
  const resultRelativePath = (
    `results/${artifactToken(job.job_id)}.${resultDigest}.json`
  )
  const applied = applyJobResult(started, jobResult, {
    expectedPacketSha256: expectedPacket.packet_sha256,
    sidecar,
    artifact: {
      path: resultRelativePath,
      sha256: sha256(canonicalResult),
    },
    inventoryEntries,
  })
  const advanced = advanceUntilBlocked(applied)
  const serializedRun = stableJson(advanced)
  assertRunManifestSize(serializedRun)
  const nextArtifactCapacity = reserveBundleArtifactCapacity(
    artifactCapacity,
    canonicalResult,
    'provider result artifact',
  )

  return {
    advanced,
    canonicalResult,
    jobId: job.job_id,
    jobState: jobResult.state,
    nextArtifactCapacity,
    pendingCount: advanced.jobs.filter(({ state }) => state === 'PENDING').length,
    resultRelativePath,
    runPhase: advanced.phase,
    runState: advanced.state,
    serializedRun,
  }
}

async function verifyAlreadyAppliedResult(loaded, source) {
  const jobResult = source.jobResult
  assertValidJobResult(jobResult)
  const job = loaded.run.jobs.find(({ job_id: jobId }) => jobId === jobResult.job_id)
  if (job === undefined || !['SUCCEEDED', 'FAILED'].includes(job.state)) return null
  if (
    loaded.run.run_id !== jobResult.run_id
    || job.state !== jobResult.state
    || typeof job.input_sha256 !== 'string'
    || job.input_sha256.toLowerCase() !== jobResult.input_sha256.toLowerCase()
    || stableJson(job.producer, 0) !== stableJson(jobResult.producer, 0)
  ) return null

  const sidecar = await loadJobSidecar(loaded.directory, loaded.run, job)
  const expectedPacket = dispatchPacket(loaded.run, job, sidecar)
  if (jobResult.input_sha256.toLowerCase() !== expectedPacket.packet_sha256) return null

  const canonicalResult = stableJson(jobResult)
  const resultDigest = sha256(canonicalResult)
  const artifactKey = `result_${artifactKeyToken(job.job_id).toLowerCase()}`
  const artifact = loaded.run.artifacts?.[artifactKey]
  const expectedPath = `results/${artifactToken(job.job_id)}.${resultDigest}.json`
  if (
    artifact === undefined
    || artifact.path !== expectedPath
    || artifact.sha256 !== resultDigest
  ) return null
  const committed = await readSafeBundleFile(loaded.directory, expectedPath, {
    maxBytes: MAX_PROVIDER_RESULT_BYTES,
    label: 'committed provider result artifact',
  })
  if (!committed.content.equals(Buffer.from(canonicalResult, 'utf8'))) return null
  return {
    jobId: job.job_id,
    jobState: jobResult.state,
  }
}

function logAcceptedResult(prepared) {
  console.log(`Accepted ${prepared.jobId}: ${prepared.jobState}`)
  console.log(`Run: ${prepared.runState}/${prepared.runPhase}`)
  console.log(`Pending jobs: ${prepared.pendingCount}`)
}

async function ingestOneResult(
  loaded,
  resultPath,
  artifactCapacity,
  inventoryEntries,
  options = {},
) {
  const prepared = await prepareOneResult(
    loaded,
    resultPath,
    artifactCapacity,
    inventoryEntries,
    options,
  )
  await persistRun(loaded.path, prepared.advanced, loaded.sourceDigest, {
    beforeCommit: () => writeOnceBundleArtifact(
      loaded.directory,
      prepared.resultRelativePath,
      prepared.canonicalResult,
    ),
  })
  loaded.run = prepared.advanced
  loaded.sourceDigest = sha256(Buffer.from(prepared.serializedRun, 'utf8'))
  logAcceptedResult(prepared)
  return prepared.nextArtifactCapacity
}

async function ingestCommand(positionals, options) {
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  const resultPath = resolve(requirePositional(positionals, 1, 'job result'))
  const expectedSource = exactResultSourceBinding(options)
  assertValidRun(loaded.run)
  const control = await verifyRepositorySnapshot(loaded.directory, loaded.run)
  await ingestOneResult(
    loaded,
    resultPath,
    control.artifactCapacity,
    control.inventoryEntries,
    { expectedSource },
  )
}

async function ingestBatchCommand(positionals) {
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  assertValidRun(loaded.run)
  const control = await verifyRepositorySnapshot(loaded.directory, loaded.run)
  const resultPaths = positionals.slice(1).map((path) => resolve(path))
  let artifactCapacity = control.artifactCapacity
  let accepted = 0

  for (const [index, resultPath] of resultPaths.entries()) {
    try {
      artifactCapacity = await ingestOneResult(
        loaded,
        resultPath,
        artifactCapacity,
        control.inventoryEntries,
      )
      accepted += 1
    } catch (error) {
      const wrapped = new Error(
        `ingest-batch stopped at result ${index + 1} ` +
        `(${resultPath}) after accepting ${accepted}: ${error.message}`,
        { cause: error },
      )
      const details = error.errors ?? error.details
      if (details) wrapped.details = details
      throw wrapped
    }
  }

  console.log(`Batch accepted ${accepted} result${accepted === 1 ? '' : 's'}`)
}

function finalizedArtifactPayloads(run) {
  const payloads = {
    coverage: stableJson(run.coverage),
    report: renderMarkdownReport(run),
    sarif: stableJson(renderSarif(run)),
  }
  for (const [key, content] of Object.entries(payloads)) {
    const artifact = run.artifacts?.[key]
    if (!artifact || typeof artifact.path !== 'string') {
      throw new Error(`finalized run is missing its ${key} artifact commitment`)
    }
    if (sha256(content) !== artifact.sha256) {
      throw new Error(
        `finalized run ${key} content does not match its committed digest`,
      )
    }
  }
  return payloads
}

async function writeFinalizedArtifacts(directory, run, payloads) {
  for (const key of ['coverage', 'report', 'sarif']) {
    await writeOnceBundleArtifact(
      directory,
      run.artifacts[key].path,
      payloads[key],
    )
  }
}

async function assertFinalizedArtifactsCompatible(directory, run, payloads) {
  for (const key of ['coverage', 'report', 'sarif']) {
    const artifactPath = run.artifacts[key].path
    let existing
    try {
      existing = await readSafeBundleFile(directory, artifactPath, {
        maxBytes: MAX_BUNDLE_ARTIFACT_BYTES,
        label: `existing ${key} artifact`,
      })
    } catch (error) {
      if (error.code === 'ENOENT') continue
      throw error
    }
    if (!existing.content.equals(Buffer.from(payloads[key], 'utf8'))) {
      throw new Error(
        `refusing to finalize over conflicting artifact ${artifactPath}`,
      )
    }
  }
}

async function finalizeCommand(positionals) {
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  assertValidRun(loaded.run)
  if (
    loaded.run.phase === 'FINALIZED'
    && ['COMPLETED', 'COMPLETE_WITH_GAPS'].includes(loaded.run.state)
  ) {
    const payloads = finalizedArtifactPayloads(loaded.run)
    await persistRun(loaded.path, loaded.run, loaded.sourceDigest, {
      afterCommit: () => writeFinalizedArtifacts(
        loaded.directory,
        loaded.run,
        payloads,
      ),
    })
    await verifyControlBundle(loaded.directory, loaded.run)
    console.log(terminalSafeText(
      `Verified final artifacts for ${loaded.run.run_id}: ${loaded.run.state}`,
    ))
    console.log(terminalSafeText(
      `Report: ${join(loaded.directory, loaded.run.artifacts.report.path)}`,
    ))
    return
  }
  const control = await verifyRepositorySnapshot(loaded.directory, loaded.run)
  const finalized = buildFinalizedRun(loaded.run)
  assertRunManifestSize(stableJson(finalized.run))
  reserveBundleArtifactCapacity(
    control.artifactCapacity,
    [finalized.coverage, finalized.report, finalized.sarif],
    'final report artifacts',
  )
  const payloads = {
    coverage: finalized.coverage,
    report: finalized.report,
    sarif: finalized.sarif,
  }
  await persistRun(loaded.path, finalized.run, loaded.sourceDigest, {
    beforeCommit: () => assertFinalizedArtifactsCompatible(
      loaded.directory,
      finalized.run,
      payloads,
    ),
    afterCommit: () => writeFinalizedArtifacts(
      loaded.directory,
      finalized.run,
      payloads,
    ),
  })
  await verifyControlBundle(loaded.directory, finalized.run)
  console.log(terminalSafeText(
    `Finalized ${finalized.run.run_id}: ${finalized.run.state}`,
  ))
  console.log(terminalSafeText(
    `Report: ${join(loaded.directory, finalized.run.artifacts.report.path)}`,
  ))
}

async function abortCommand(positionals, options) {
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  const reason = typeof options.reason === 'string' ? options.reason.trim() : ''
  if (!reason) throw new Error('--reason is required to abort a run')
  assertValidRun(loaded.run)
  if (!['PLANNED', 'RUNNING'].includes(loaded.run.state)) {
    throw new Error(`cannot abort terminal run ${loaded.run.state}`)
  }
  const next = structuredClone(loaded.run)
  next.state = 'ABORTED'
  next.phase = 'FINALIZED'
  next.completed_at = new Date().toISOString()
  next.jobs = next.jobs.map((job) => {
    if (['DORMANT', 'PENDING'].includes(job.state)) {
      return { ...job, state: 'SKIPPED', reason: `run aborted: ${reason}` }
    }
    if (job.state === 'RUNNING') {
      return { ...job, state: 'FAILED', reason: `run aborted: ${reason}` }
    }
    return job
  })
  next.errors.push({
    error_id: `abort:${next.errors.length + 1}`,
    phase: 'FINALIZED',
    code: 'OPERATOR_ABORT',
    message: reason,
    recoverable: false,
  })
  assertValidRunTransition(loaded.run, next)
  await persistRun(loaded.path, next, loaded.sourceDigest)
  console.log(`Aborted ${next.run_id}`)
}

async function unlockCommand(positionals) {
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  const lockPath = `${loaded.path}.lock`
  const recoveryPath = `${lockPath}.recovery`
  const recovery = lockRecord()
  await clearStaleRecoveryMarker(loaded.directory, recoveryPath)
  try {
    await exclusiveAtomicCreate(recoveryPath, stableJson(recovery))
  } catch (error) {
    if (error.code === 'EEXIST') {
      throw new Error(`run lock recovery is already in progress: ${recoveryPath}`)
    }
    throw error
  }

  try {
    await assertSafeExistingBundlePath(
      loaded.directory,
      basename(lockPath),
      { expectedType: 'file' },
    )
    const before = await readLockCandidate(loaded.directory, lockPath)
    if (before.record && processIsAlive(before.record.pid)) {
      throw new Error(
        `refusing to unlock a run owned by live PID ${before.record.pid}: ${lockPath}`,
      )
    }
    const after = await readLockCandidate(loaded.directory, lockPath)
    if (after.signature !== before.signature) {
      throw new Error(`run lock changed during recovery: ${lockPath}`)
    }
    await unlink(lockPath)
    if (before.record) {
      console.log(terminalSafeText(`Removed stale run lock for PID ${before.record.pid}: ${lockPath}`))
    } else {
      console.log(terminalSafeText(`Removed stable malformed run lock: ${lockPath}`))
    }
  } finally {
    await releaseOwnedLock(recoveryPath, recovery.token)
  }
}

async function reportCommand(positionals, options) {
  const outputs = await preflightReportOutputs(options)
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  const { directory, run } = loaded
  assertValidRun(run)
  const rootRecord = await loadPinnedRootAttestation(loaded, options)
  const rootAuthenticity = rootRecord.verification
  const transparencyInclusion = await verifyPinnedTransparencyReceipt(
    loaded,
    options,
    rootRecord,
  )
  const pinnedReceiptKeyId = typeof options['receipt-public-key'] === 'string'
    ? await loadPinnedReceiptPublicKeyId(
        options['receipt-public-key'],
        directory,
        run.repository.root,
      )
    : undefined
  await verifyControlBundle(directory, run, { pinnedReceiptKeyId })
  if (rootAuthenticity.status === 'SIGNATURE_VERIFIED_WITH_SUPPLIED_KEY') {
    console.error(terminalSafeText(
      `Root signature: VERIFIED WITH SUPPLIED KEY (${rootAuthenticity.key_id})`,
    ))
  } else {
    console.error('Root authenticity: UNANCHORED')
  }
  if (transparencyInclusion.status === 'VERIFIED') {
    console.error(terminalSafeText(
      `Transparency inclusion: VERIFIED (${transparencyInclusion.origin}, tree ${transparencyInclusion.tree_size}, leaf ${transparencyInclusion.leaf_index})`,
    ))
    if (transparencyInclusion.continuity) {
      console.error(terminalSafeText(
        `Checkpoint continuity: ${transparencyInclusion.continuity.consistency}`,
      ))
    }
  } else {
    console.error('Transparency inclusion: NOT SUPPLIED')
  }
  const markdown = renderMarkdownReport(run)
  if (outputs.markdownPath) {
    await writeFile(outputs.markdownPath, markdown, { encoding: 'utf8', flag: 'wx' })
    console.log(terminalSafeText(`Wrote ${outputs.markdownPath}`))
  } else {
    process.stdout.write(terminalSafeDocumentText(markdown))
  }
  if (outputs.sarifPath) {
    await writeJson(outputs.sarifPath, renderSarif(run))
    const status = `Wrote ${outputs.sarifPath}`
    if (outputs.markdownPath) console.log(terminalSafeText(status))
    else console.error(terminalSafeText(status))
  }
}

async function compareCommand(positionals, options) {
  const baseline = await loadRun(requirePositional(positionals, 0, 'baseline run'))
  const current = await loadRun(requirePositional(positionals, 1, 'current run'))
  assertValidRun(baseline.run)
  assertValidRun(current.run)
  for (const loaded of [baseline, current]) {
    const pinnedReceiptKeyId = typeof options['receipt-public-key'] === 'string'
      ? await loadPinnedReceiptPublicKeyId(
          options['receipt-public-key'],
          loaded.directory,
          loaded.run.repository.root,
        )
      : undefined
    await verifyControlBundle(loaded.directory, loaded.run, { pinnedReceiptKeyId })
  }
  const comparison = compareRuns(baseline.run, current.run)
  if (typeof options.out === 'string') {
    await writeJson(options.out, comparison)
    console.log(terminalSafeText(`Wrote ${resolve(options.out)}`))
  } else {
    process.stdout.write(terminalSafeSerializedJson(stableJson(comparison)))
  }
}

function normalizeBenchmarkFindingRecords(records, field, expectedCaseIds) {
  if (!Array.isArray(records)) {
    throw new Error(`${field} must be an array of { case_id, finding } records`)
  }
  const findings = []
  const invalid = []
  for (const [index, record] of records.entries()) {
    const location = `${field}[${index}]`
    try {
      if (
        record === null
        || typeof record !== 'object'
        || Array.isArray(record)
        || typeof record.case_id !== 'string'
        || !record.case_id.trim()
        || record.finding === null
        || typeof record.finding !== 'object'
        || Array.isArray(record.finding)
      ) {
        throw new Error('must contain a non-empty case_id and a finding object')
      }
      if (expectedCaseIds && !expectedCaseIds.has(record.case_id.trim())) {
        throw new Error(
          `references unknown benchmark case ${JSON.stringify(record.case_id.trim())}`,
        )
      }
      const finding = finalizeFinding(record.finding)
      findings.push({
        ...finding,
        case_id: record.case_id.trim(),
        fingerprint: findingFingerprint(finding),
      })
    } catch (error) {
      invalid.push({
        record: location,
        message: error.message,
      })
    }
  }
  return { findings, invalid }
}

async function benchmarkCommand(positionals, options) {
  const inputPath = resolve(requirePositional(positionals, 0, 'evaluation input'))
  const casesPath = resolve(
    typeof options.cases === 'string' ? options.cases : DEFAULT_BENCHMARK_CASES,
  )
  const thresholdsPath = resolve(
    typeof options.thresholds === 'string' ? options.thresholds : DEFAULT_THRESHOLDS,
  )
  const [inputBytes, casesBytes, thresholdsBytes] = await Promise.all([
    readBoundedFile(
      inputPath,
      MAX_BENCHMARK_INPUT_BYTES,
      'benchmark evaluation JSON',
    ),
    readBoundedFile(
      casesPath,
      MAX_BENCHMARK_CASES_BYTES,
      'benchmark case manifest JSON',
    ),
    readBoundedFile(
      thresholdsPath,
      MAX_BENCHMARK_THRESHOLDS_BYTES,
      'benchmark thresholds JSON',
    ),
  ])
  const inputText = inputBytes.toString('utf8')
  const casesText = casesBytes.toString('utf8')
  const thresholdsText = thresholdsBytes.toString('utf8')
  let input
  let caseManifest
  let thresholds
  try {
    input = JSON.parse(inputText)
    caseManifest = JSON.parse(casesText)
    thresholds = JSON.parse(thresholdsText)
  } catch (error) {
    throw new Error(`invalid benchmark JSON: ${error.message}`)
  }
  if (
    input !== null
    && typeof input === 'object'
    && !Array.isArray(input)
    && (
      Object.hasOwn(input, 'expectedCases')
      || Object.hasOwn(input, 'schemaInvalidCount')
    )
  ) {
    throw new Error(
      'benchmark denominators and schema-invalid counts are controller-derived; ' +
      'remove expectedCases and schemaInvalidCount from the evaluation input',
    )
  }
  assertValidBenchmarkInput(input)
  if (
    caseManifest === null
    || typeof caseManifest !== 'object'
    || Array.isArray(caseManifest)
    || !Array.isArray(caseManifest.cases)
    || caseManifest.cases.length === 0
  ) {
    throw new Error('benchmark case manifest must contain a non-empty cases array')
  }
  if (caseManifest.cases.length > EVALUATION_LIMITS.expectedCases) {
    throw new Error(
      `benchmark case manifest must contain at most ` +
      `${EVALUATION_LIMITS.expectedCases} cases`,
    )
  }
  const expectedCaseIds = new Set(
    caseManifest.cases.map(({ case_id: caseId }) => caseId),
  )

  const observed = normalizeBenchmarkFindingRecords(
    input.observedFindings,
    'observedFindings',
    expectedCaseIds,
  )
  const normalizedRepeats = (input.repeatedRuns ?? []).map((run, index) => {
    if (
      run === null
      || typeof run !== 'object'
      || Array.isArray(run)
      || typeof run.run_id !== 'string'
      || !run.run_id.trim()
    ) {
      throw new Error(`repeatedRuns[${index}].run_id must be a non-empty string`)
    }
    const normalized = normalizeBenchmarkFindingRecords(
      run.findings,
      `repeatedRuns[${index}].findings`,
      expectedCaseIds,
    )
    observed.invalid.push(...normalized.invalid)
    return {
      run_id: run.run_id.trim(),
      findings: normalized.findings,
      schemaInvalidCount: normalized.invalid.length,
      ...(run.caseOutcomes === undefined ? {} : { caseOutcomes: run.caseOutcomes }),
    }
  })
  const { caseOutcomes, repeatedRuns } = bindBenchmarkPrimaryOutcomes(
    input.primary_run_id, input.caseOutcomes, normalizedRepeats,
  )
  const primaryRunBinding = bindBenchmarkPrimaryRun(
    input.primary_run_id,
    observed.findings,
    repeatedRuns,
  )
  const metrics = scoreEvaluation({
    expectedCases: caseManifest.cases,
    observedFindings: observed.findings,
    caseOutcomes,
    schemaInvalidCount: observed.invalid.length,
  })
  metrics.stability = scoreFingerprintStability(repeatedRuns, caseManifest.cases)
  metrics.repeated = scoreRepeatedEvaluations(repeatedRuns, caseManifest.cases)
  const gate = evaluateThresholds(metrics, thresholds)
  const scorecard = {
    schema_version: 1,
    generated_at: new Date().toISOString(),
    provenance: {
      evaluation_input: {
        path: inputPath,
        sha256: sha256(inputText),
      },
      case_manifest: {
        path: casesPath,
        sha256: sha256(casesText),
        cases: caseManifest.cases.length,
      },
      thresholds: {
        path: thresholdsPath,
        sha256: sha256(thresholdsText),
      },
      primary_run: primaryRunBinding,
      measurement: input.measurement ?? null,
      measurement_authority: 'CALLER_DECLARED',
      observation_authority: 'caller-supplied; canonical finding contracts enforced',
    },
    invalid_records: observed.invalid,
    metrics,
    gate,
  }
  if (typeof options.out === 'string') {
    await writeJson(options.out, scorecard)
    console.log(terminalSafeText(`Wrote ${resolve(options.out)}`))
  } else {
    process.stdout.write(terminalSafeSerializedJson(stableJson(scorecard)))
  }
  if (!gate.passed) process.exitCode = 2
}

export async function main(argv = process.argv.slice(2)) {
  const command = argv[0]
  if (!command || command === 'help' || command === '--help' || command === '-h') {
    process.stdout.write(HELP)
    return
  }
  if (command === 'engage') {
    const { runEngageCli } = await import('./engage.mjs')
    const exitCode = await runEngageCli(argv.slice(1))
    if (exitCode !== 0) process.exitCode = exitCode
    return
  }
  if (command === 'http-recon') {
    const { main: runHttpReconCli } = await import('./http-recon.mjs')
    await runHttpReconCli(argv.slice(1))
    return
  }
  if (command === 'http-authed') {
    const { main: runHttpAuthedCli } = await import('./http-authed.mjs')
    await runHttpAuthedCli(argv.slice(1))
    return
  }
  if (command === 'reverse') {
    const { runReverseCli } = await import('./reverse.mjs')
    const exitCode = await runReverseCli(argv.slice(1))
    if (exitCode !== 0) process.exitCode = exitCode
    return
  }
  if (command === 'adversarial') {
    const { main: runAdversarialCli } = await import('./adversarial.mjs')
    const exitCode = await runAdversarialCli(argv.slice(1))
    if (exitCode !== 0) process.exitCode = exitCode
    return
  }
  if (command === 'bounty') {
    const { runBountyCli } = await import('./bounty.mjs')
    const exitCode = await runBountyCli(argv.slice(1))
    if (exitCode !== 0) process.exitCode = exitCode
    return
  }
  if (command === 'acquire') {
    const { main: runAcquireCli } = await import('./acquire.mjs')
    await runAcquireCli(argv.slice(1))
    return
  }
  if (command === 'database-conformance') {
    const { main: runDatabaseConformanceCli } = await import('./database-conformance.mjs')
    await runDatabaseConformanceCli(argv.slice(1))
    return
  }
  assertLocalFilesystemEndpoint(process.cwd(), 'working directory')
  assertNoRemoteFilesystemArguments(argv)
  const { positionals, options } = parseArguments(argv.slice(1))
  assertArgumentShape(command, positionals, options)
  if (command === 'run-provider') {
    const error = new Error(
      'run-provider is disabled before bundle or configuration access pending controller-enrolled, identity-pinned container runtime execution',
    )
    error.code = 'PROVIDER_RUNTIME_ENROLLMENT_REQUIRED'
    throw error
  }
  if (command === 'run-remote') {
    const error = new Error(
      'run-remote is disabled before bundle or configuration access pending independently enrolled gateway identity and outbound-data authorization',
    )
    error.code = 'REMOTE_GATEWAY_ENROLLMENT_REQUIRED'
    throw error
  }
  if (command === 'publish') {
    const error = new Error(
      'publish is disabled before run, attestation, key, output, or configuration access pending independently enrolled transparency-log identity',
    )
    error.code = 'TRANSPARENCY_LOG_ENROLLMENT_REQUIRED'
    throw error
  }
  if (command === 'plan' && typeof options['evidence-bundle'] === 'string') {
    const error = new Error(
      'evidence-bundle import is disabled before repository or bundle access pending controller-authenticated manifest semantics and atomic verification',
    )
    error.code = 'EVIDENCE_BUNDLE_TRUST_ENROLLMENT_REQUIRED'
    throw error
  }
  if (command === 'plan') return planCommand(positionals, options)
  if (command === 'next') return nextCommand(positionals, options)
  if (command === 'status') return statusCommand(positionals, options)
  if (command === 'capabilities') return capabilitiesCommand(options)
  if (command === 'doctor') return doctorCommand(options)
  if (command === 'review-template') return reviewTemplateCommand(positionals, options)
  if (command === 'check-result') return checkResultCommand(positionals, options)
  if (command === 'verdict') return verdictCommand(positionals, options)
  if (command === 'repair-brief') return repairBriefCommand(positionals, options)
  if (command === 'run-provider') return runProviderCommand(positionals, options)
  if (command === 'run-remote') return runRemoteCommand(positionals, options)
  if (command === 'run-proof') return runProofCommand(positionals, options)
  if (command === 'run-service-proof') return runServiceProofCommand(positionals, options)
  if (command === 'ingest') return ingestCommand(positionals, options)
  if (command === 'ingest-batch') return ingestBatchCommand(positionals, options)
  if (command === 'finalize') return finalizeCommand(positionals, options)
  if (command === 'abort') return abortCommand(positionals, options)
  if (command === 'unlock') return unlockCommand(positionals, options)
  if (command === 'attest') return attestCommand(positionals, options)
  if (command === 'publish') return publishTransparencyCommand(positionals, options)
  if (command === 'validate') return validateCommand(positionals, options)
  if (command === 'report') return reportCommand(positionals, options)
  if (command === 'compare') return compareCommand(positionals, options)
  if (command === 'benchmark') return benchmarkCommand(positionals, options)
  throw new Error(`unknown command ${JSON.stringify(command)}\n\n${HELP}`)
}

const isDirectRun = isMainModule(import.meta.url)

if (isDirectRun) {
  main().catch((error) => {
    console.error(`ERROR: ${terminalSafeText(error.message)}`)
    const details = error.errors ?? error.details
    if (Array.isArray(details)) {
      for (const issue of details) {
        console.error(terminalSafeText(
          `- ${issue.code ?? issue.keyword}: ${issue.instancePath || '/'} ${issue.message}`,
        ))
      }
    }
    process.exitCode = 1
  })
}
