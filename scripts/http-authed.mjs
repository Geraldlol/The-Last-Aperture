#!/usr/bin/env node

import { constants as fsConstants } from 'node:fs'
import { lstat, open } from 'node:fs/promises'
import { isAbsolute } from 'node:path'
import { TextDecoder } from 'node:util'

import {
  httpAuthedAuthorizationEvidence,
  readAndVerifyHttpAuthedAuthorization,
} from './lib/http-authed-contracts.mjs'
import {
  runHttpAuthedAttestedCampaign,
} from './lib/http-authed-campaign-runtime.mjs'
import { requestHttpAuthedCampaignStop } from './lib/http-authed-campaign-ledger.mjs'
import {
  HTTP_AUTHED_STDIN_CREDENTIAL_REF,
  readHttpAuthedCredentialFromStdin,
} from './lib/http-authed-credential.mjs'
import {
  planHttpAuthedAttestedScope,
} from './lib/http-authed-planner.mjs'
import { isMainModule } from './lib/main-module.mjs'
import {
  assertLocalFilesystemEndpoint,
  assertNoRemoteFilesystemArguments,
} from './lib/filesystem-endpoint.mjs'
import { PLATFORM_VERSION, stableJson } from './lib/run-engine.mjs'
import {
  terminalSafeLines,
  terminalSafeSerializedJson,
  terminalSafeText,
} from './lib/terminal-text.mjs'

const HELP = `last-aperture authenticated HTTP campaigns ${PLATFORM_VERSION}

Usage:
  http-authed plan-attested --scope <absolute-new-scope.json> --engagement-id <id> --authorization-id <id> --operator-id <id> --authorized-by <declared-authorizer> --authorization-reference <reference> --not-before <timestamp> --not-after <timestamp> [--cleanup-not-after <timestamp>] --target-origin <https-origin> --environment <production|non_production> --data-class <phi|non_phi|unknown> --ownership <operator_owned|third_party_owned> ((--credential-env <ENV_NAME>|--credential-stdin) --credential-kind <bearer|cookie>|--credential-browser --browser-extension-id <id>) --path-prefix <prefix> --method <METHOD> --test-category <category> (--seed-url <https-url>|--requests <absolute-requests.json>) [--enable-discovery] [--observe-json-shape [--json-shape-aspnet-d] --json-shape-key <safe-key> [--json-shape-max-depth <1-4>]] [--response-observation-profile <controller-profile>] [--json]
  http-authed validate-attested --scope <scope.json> [--json]
  http-authed campaign-attested --scope <scope.json> --campaign-grant-sha256 <hex> --ledger <absolute-external-directory> --operator-id <id> [--credential-stdin|--credential-browser] [--materials <absolute-directory>] [--trusted-ledger-record-count <integer> --trusted-ledger-head-sha256 <hex>] [--json]
  http-authed campaign-stop --ledger <absolute-external-directory> --campaign-grant-sha256 <hex> --operator-id <id> [--json]
Boundary:
  Both planners and validators perform no network activity. Invoking plan-attested
  is the explicit operator statement; the controller accepts it as the authorization
  fact for the named target and scope without another flag or legal-proof artifact.
  It does not independently prove the operator's underlying legal authority.
  Invoking a live command is the operator's campaign launch directive; no repeated
  legal-attestation flag is required. Campaign execution supports sealed adaptive
  response-derived discovery inside the declared origin, path, method, and test-category
  perimeter. The runtime revalidates scope and authorization before each send and uses a locally append-only,
  hash-chained campaign ledger. Across restarts, rollback or valid-prefix truncation
  detection requires the separately retained trusted record count and head digest to
  be supplied with --trusted-ledger-record-count and --trusted-ledger-head-sha256.
  Standalone probes are not public: use a single-action campaign so every active
  authenticated request receives a durable lease and campaign ledger record.
  campaign-stop writes an out-of-band request bound to that grant and operator;
  the runner consumes it into the ledger before dispatching another action.
  Commands never print credential references/values, full
  request URLs, request/response bodies, or header values.
  --credential-stdin reads one opaque value from redirected stdin, strips one pipe
  line ending, refuses terminal or multiline input, and never persists or prints it.
  The packaged Chrome companion pairs through an operator-entered loopback capability
  and attaches only to the active tab whose origin matches the sealed target.
  --credential-browser uses that browser-held session without exporting cookies or
  authorization values; this route uses browser-managed DNS rather than
  the native transport's all-answer validation and socket IP pinning.
  JSON response shape observation is disabled unless --observe-json-shape is sealed
  at plan time with repeatable --json-shape-key values. It retains only allowed key
  names, structural types, and bounded counts; scalar values and raw bodies remain
  transient and are never emitted. --json-shape-aspnet-d selects one strict JSON
  parse of an exact ASP.NET {d: JSON-string} envelope; it never parses XML or HTML.
  --response-observation-profile credible-bundle-src-v1 is exclusive with discovery
  and JSON shape observation. It admits one exact Credible GET, transiently parses
  one complete identity UTF-8 HTML response, emits at most four fixed-format bundle
  paths, and discards all response bytes and other HTML data.

Materials:
  A synthetic body is read from body-SHA256.bin, where SHA256 is the lowercase
  SHA-256 of body_id UTF-8. Each action receives a ledger-bound one-use dispatch
  permit derived from the sealed operator-authorized campaign.

Planner options:
  Repeat --path-prefix, --method, and --test-category to express the sealed boundary.
  Use repeatable --seed-url for simple probes, or one bounded non-symlink JSON array
  via --requests for full probe/mutate drafts. --requests is exclusive with
  --seed-url, --seed-method, and --seed-test-category. --preflight-url can refine
  either route. --cleanup-not-after defaults to --not-after and extends only
  ledger-proven rollback/verification, never new work. --enable-discovery accepts repeatable --discovery-source,
  --synthetic-query NAME=SYNTHETIC_VALUE, and --synthetic-path NAME=SYNTHETIC_VALUE.
  Include --mutation-authorized in the explicit plan command to authorize the
  exact sealed mutation and rollback sequence. Optional transport controls are --tls-spki-sha256,
  --request-timeout-ms, --max-response-bytes, --min-interval-ms, --concurrency,
  and --max-actions. Discovery also accepts --discovery-max-depth and
  --discovery-max-candidates; these are sealed operational budgets rather than
  public-tier feature gates.
`

const OPEN_READ_ONLY_NO_FOLLOW = fsConstants.O_RDONLY
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)
const REQUEST_PLAN_MAX_BYTES = 1024 * 1024

const FLAG_OPTIONS = new Set([
  'json',
  'enable-discovery',
  'mutation-authorized',
  'credential-stdin',
  'credential-browser',
  'observe-json-shape',
  'json-shape-aspnet-d',
])
const REPEATABLE_OPTIONS = new Set([
  'path-prefix',
  'method',
  'test-category',
  'seed-url',
  'discovery-source',
  'synthetic-query',
  'synthetic-path',
  'json-shape-key',
])

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
    if (!key || (Object.hasOwn(options, key) && !REPEATABLE_OPTIONS.has(key))) {
      throw new Error(`invalid or duplicate option ${JSON.stringify(value)}`)
    }
    if (FLAG_OPTIONS.has(key)) {
      options[key] = true
      continue
    }
    const next = values[index + 1]
    if (next === undefined || next.startsWith('--')) {
      throw new Error(`--${key} requires a value`)
    }
    if (REPEATABLE_OPTIONS.has(key)) {
      options[key] ??= []
      options[key].push(next)
    } else {
      options[key] = next
    }
    index += 1
  }
  return { positionals, options }
}

const COMMANDS = {
  'plan-attested': {
    required: [
      'scope',
      'engagement-id',
      'authorization-id',
      'operator-id',
      'authorized-by',
      'authorization-reference',
      'not-before',
      'not-after',
      'target-origin',
      'environment',
      'data-class',
      'ownership',
      'path-prefix',
      'method',
      'test-category',
    ],
    optional: [
      'requests',
      'seed-url',
      'preflight-url',
      'cleanup-not-after',
      'credential-env',
      'credential-stdin',
      'credential-browser',
      'browser-extension-id',
      'credential-kind',
      'seed-method',
      'seed-test-category',
      'enable-discovery',
      'observe-json-shape',
      'json-shape-aspnet-d',
      'json-shape-key',
      'json-shape-max-depth',
      'response-observation-profile',
      'discovery-source',
      'synthetic-query',
      'synthetic-path',
      'mutation-authorized',
      'tls-spki-sha256',
      'request-timeout-ms',
      'max-response-bytes',
      'min-interval-ms',
      'concurrency',
      'max-actions',
      'discovery-max-depth',
      'discovery-max-candidates',
      'json',
    ],
  },
  'validate-attested': {
    required: ['scope'],
    optional: ['json'],
  },
  'campaign-stop': {
    required: ['ledger', 'campaign-grant-sha256', 'operator-id'],
    optional: ['json'],
  },
  'campaign-attested': {
    required: [
      'scope',
      'campaign-grant-sha256',
      'ledger',
      'operator-id',
    ],
    optional: [
      'materials',
      'credential-stdin',
      'credential-browser',
      'trusted-ledger-record-count',
      'trusted-ledger-head-sha256',
      'json',
    ],
  },
}

function assertCommandShape(positionals, options) {
  if (positionals.length !== 1 || !COMMANDS[positionals[0]]) {
    throw new Error(`expected a supported http-authed command\n\n${HELP}`)
  }
  const command = positionals[0]
  const shape = COMMANDS[command]
  const allowed = new Set([...shape.required, ...shape.optional])
  for (const key of Object.keys(options)) {
    if (!allowed.has(key)) throw new Error(`${command} does not support --${key}`)
  }
  for (const key of shape.required) {
    if (FLAG_OPTIONS.has(key)) {
      if (options[key] !== true) throw new Error(`${command} requires --${key}`)
    } else if (REPEATABLE_OPTIONS.has(key)) {
      if (!Array.isArray(options[key]) || options[key].length === 0) {
        throw new Error(`${command} requires --${key}`)
      }
    } else if (typeof options[key] !== 'string' || options[key].length === 0) {
      throw new Error(`${command} requires --${key}`)
    }
  }
  return command
}

function optionalInteger(options, key) {
  const value = options[key]
  if (value === undefined) return undefined
  if (!/^(?:0|[1-9][0-9]*)$/.test(value) || !Number.isSafeInteger(Number(value))) {
    throw new Error(`--${key} must be a non-negative safe integer`)
  }
  return Number(value)
}

function keyValueMap(values, option) {
  const result = {}
  for (const value of values ?? []) {
    const separator = value.indexOf('=')
    const key = separator < 0 ? '' : value.slice(0, separator)
    const mapped = separator < 0 ? '' : value.slice(separator + 1)
    if (!key || !mapped || Object.hasOwn(result, key)) {
      throw new Error(`--${option} requires unique NAME=VALUE entries`)
    }
    result[key] = mapped
  }
  return result
}

function requestPlanError(code, message) {
  const error = new Error(message)
  error.code = code
  return error
}

function sameRequestPlanFile(left, right) {
  return left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ino === right.ino
    && left.dev === right.dev
}

async function readRequestPlanFile(
  path,
  { lstatImpl = lstat, openImpl = open } = {},
) {
  if (typeof path !== 'string' || !isAbsolute(path)) {
    throw requestPlanError(
      'HTTP_AUTHED_REQUESTS_ABSOLUTE_REQUIRED',
      '--requests must name an absolute JSON file',
    )
  }

  let info
  try {
    info = await lstatImpl(path)
  } catch {
    throw requestPlanError(
      'HTTP_AUTHED_REQUESTS_UNREADABLE',
      'the --requests JSON file cannot be read',
    )
  }
  if (
    !info.isFile()
    || info.isSymbolicLink()
    || info.size < 1
    || info.size > REQUEST_PLAN_MAX_BYTES
  ) {
    throw requestPlanError(
      'HTTP_AUTHED_REQUESTS_UNSAFE',
      'the --requests input must be a bounded regular non-symlink JSON file',
    )
  }

  let handle
  let bytes
  try {
    handle = await openImpl(path, OPEN_READ_ONLY_NO_FOLLOW)
    const before = await handle.stat()
    if (!before.isFile() || !sameRequestPlanFile(info, before)) {
      throw requestPlanError(
        'HTTP_AUTHED_REQUESTS_CHANGED',
        'the --requests JSON file changed before it was read',
      )
    }
    bytes = await handle.readFile()
    const after = await handle.stat()
    const pathAfter = await lstatImpl(path)
    if (
      !sameRequestPlanFile(before, after)
      || !pathAfter.isFile()
      || pathAfter.isSymbolicLink()
      || !sameRequestPlanFile(info, pathAfter)
      || bytes.length !== after.size
      || bytes.length < 1
      || bytes.length > REQUEST_PLAN_MAX_BYTES
    ) {
      throw requestPlanError(
        'HTTP_AUTHED_REQUESTS_CHANGED',
        'the --requests JSON file changed while it was read',
      )
    }
  } catch (error) {
    if (error?.code?.startsWith('HTTP_AUTHED_REQUESTS_')) throw error
    throw requestPlanError(
      'HTTP_AUTHED_REQUESTS_UNREADABLE',
      'the --requests JSON file cannot be read safely',
    )
  } finally {
    try {
      await handle?.close()
    } catch {
      // The bounded bytes were already captured through the no-follow handle.
    }
  }

  try {
    let parsed
    try {
      const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
      parsed = JSON.parse(text)
    } catch {
      throw requestPlanError(
        'HTTP_AUTHED_REQUESTS_JSON_INVALID',
        'the --requests input must contain valid UTF-8 JSON',
      )
    }
    if (!Array.isArray(parsed)) {
      throw requestPlanError(
        'HTTP_AUTHED_REQUESTS_ARRAY_REQUIRED',
        'the --requests JSON value must be an array of action drafts',
      )
    }
    return parsed
  } finally {
    bytes?.fill(0)
  }
}

async function planInput(options, requestPlanIo = {}) {
  const command = 'plan-attested'
  const testCategories = options['test-category']
  const usesRequestPlan = options.requests !== undefined
  const usesSeedUrls = Array.isArray(options['seed-url'])
    && options['seed-url'].length > 0
  if (usesRequestPlan && (
    usesSeedUrls
    || options['seed-method'] !== undefined
    || options['seed-test-category'] !== undefined
  )) {
    throw new Error(
      '--requests cannot be combined with --seed-url, --seed-method, or --seed-test-category',
    )
  }
  if (usesRequestPlan === usesSeedUrls) {
    throw new Error(`${command} requires exactly one of --seed-url or --requests`)
  }
  const seedRequests = usesRequestPlan
    ? await readRequestPlanFile(options.requests, requestPlanIo)
    : options['seed-url'].map((url) => ({
        method: options['seed-method'] ?? 'GET',
        url,
        testCategory: options['seed-test-category'] ?? testCategories[0],
      }))
  const seedTestCategory = options['seed-test-category'] ?? testCategories[0]
  const discoveryOptionsPresent = [
    'discovery-source',
    'synthetic-query',
    'synthetic-path',
  ].some((key) => options[key] !== undefined)
  if (discoveryOptionsPresent && options['enable-discovery'] !== true) {
    throw new Error('discovery options require --enable-discovery')
  }
  const jsonShapeOptionsPresent = [
    'json-shape-key',
    'json-shape-max-depth',
    'json-shape-aspnet-d',
  ].some((key) => options[key] !== undefined)
  if (jsonShapeOptionsPresent && options['observe-json-shape'] !== true) {
    throw new Error('JSON shape options require --observe-json-shape')
  }
  if (
    options['observe-json-shape'] === true
    && (!Array.isArray(options['json-shape-key']) || options['json-shape-key'].length === 0)
  ) {
    throw new Error('--observe-json-shape requires at least one --json-shape-key')
  }
  if (
    options['response-observation-profile'] !== undefined
    && (
      options['observe-json-shape'] === true
      || options['enable-discovery'] === true
      || seedRequests.length !== 1
    )
  ) {
    throw new Error(
      '--response-observation-profile requires one exact seed and is exclusive with discovery and JSON shape observation',
    )
  }
  const usesEnvironmentCredential = typeof options['credential-env'] === 'string'
  const usesStdinCredential = options['credential-stdin'] === true
  const usesBrowserCredential = options['credential-browser'] === true
  if ([usesEnvironmentCredential, usesStdinCredential, usesBrowserCredential].filter(Boolean).length !== 1) {
    throw new Error(`${command} requires exactly one of --credential-env, --credential-stdin, or --credential-browser`)
  }
  if (usesBrowserCredential) {
    if (options['credential-kind'] !== undefined) {
      throw new Error('--credential-kind cannot be used with --credential-browser')
    }
    if (!/^[a-p]{32}$/.test(options['browser-extension-id'] ?? '')) {
      throw new Error('--credential-browser requires a 32-character --browser-extension-id')
    }
  } else {
    if (!['bearer', 'cookie'].includes(options['credential-kind'])) {
      throw new Error('exported credentials require --credential-kind bearer or cookie')
    }
    if (options['browser-extension-id'] !== undefined) {
      throw new Error('--browser-extension-id requires --credential-browser')
    }
  }
  return {
    outputPath: options.scope,
    engagementId: options['engagement-id'],
    classification: {
      environment: options.environment,
      dataClass: options['data-class'],
    },
    authorization: {
      authorizationId: options['authorization-id'],
      operatorId: options['operator-id'],
      authorizedBy: options['authorized-by'],
      authorizationReference: options['authorization-reference'],
      attestAuthorized: true,
      permissions: {
        activeTesting: true,
        production: options.environment === 'production',
        thirdParty: options.ownership === 'third_party_owned',
        phi: ['phi', 'unknown'].includes(options['data-class']),
      },
    },
    credential: usesBrowserCredential
      ? {
          mode: 'CHROME_ACTIVE_TAB_SESSION',
          extensionId: options['browser-extension-id'],
          origin: options['target-origin'],
        }
      : {
          ref: usesStdinCredential
            ? HTTP_AUTHED_STDIN_CREDENTIAL_REF
            : `env:${options['credential-env']}`,
          kind: options['credential-kind'],
        },
    target: {
      origin: options['target-origin'],
      ownership: options.ownership,
      tls: options['tls-spki-sha256'] === undefined
        ? { mode: 'PKIX_HOSTNAME' }
        : {
            mode: 'PKIX_HOSTNAME_AND_SPKI_PIN',
            spki_sha256: options['tls-spki-sha256'],
          },
    },
    authorizedScope: {
      pathPrefixes: options['path-prefix'],
      methods: options.method,
      testCategories,
    },
    liveness: {
      credentialPreflightUrl: options['preflight-url'] ?? seedRequests[0]?.url,
    },
    seedRequests,
    responseObservation: options['observe-json-shape'] === true
      ? {
          safeKeyNames: options['json-shape-key'],
          maxDepth: optionalInteger(options, 'json-shape-max-depth') ?? 4,
          aspNetD: options['json-shape-aspnet-d'] === true,
        }
      : undefined,
    responseObservationProfile: options['response-observation-profile'],
    validity: {
      notBefore: options['not-before'],
      notAfter: options['not-after'],
      cleanupNotAfter: options['cleanup-not-after'],
    },
    limits: {
      request_timeout_ms: optionalInteger(options, 'request-timeout-ms'),
      max_response_bytes: optionalInteger(options, 'max-response-bytes'),
      min_interval_ms: optionalInteger(options, 'min-interval-ms'),
      concurrency: optionalInteger(options, 'concurrency'),
      max_actions: optionalInteger(options, 'max-actions'),
    },
    mutationAuthorized: options['mutation-authorized'] === true,
    discovery: options['enable-discovery'] === true
      ? {
          enabled: true,
          sources: options['discovery-source'],
          testCategory: seedTestCategory,
          syntheticQueryValues: keyValueMap(options['synthetic-query'], 'synthetic-query'),
          syntheticPathValues: keyValueMap(options['synthetic-path'], 'synthetic-path'),
          maxDepth: optionalInteger(options, 'discovery-max-depth'),
          maxCandidates: optionalInteger(options, 'discovery-max-candidates'),
        }
      : undefined,
  }
}

function publicValidationSummary(verified) {
  const {
    scope,
    authorizationBindingSha256,
    campaignGrantSha256,
  } = verified
  const evidence = httpAuthedAuthorizationEvidence(scope)
  return {
    kind: 'red-team-audit/http-authed-attested-validation',
    schema_version: scope.schema_version,
    engagement_id: scope.engagement_id,
    authorization_mode: scope.authorization.mode,
    authorization_id: scope.authorization.authorization_id,
    authorization_reference: scope.authorization.authorization_reference,
    independently_verified: scope.authorization.independently_verified,
    authorization_assurance: evidence.authorizationAssurance,
    authorization_nonclaim: evidence.authorizationNonclaim,
    authorization_binding_sha256: authorizationBindingSha256,
    campaign_grant_sha256: campaignGrantSha256,
    target_origin: scope.target.origin,
    authorized_methods: scope.authorization.authorized_scope.methods,
    request_count: scope.requests.length,
    validity: scope.validity,
    limits: scope.limits,
    evidence_handling: scope.evidence_handling,
  }
}

function trustedLedgerHead(options) {
  const count = options['trusted-ledger-record-count']
  const digest = options['trusted-ledger-head-sha256']
  if (count === undefined && digest === undefined) return undefined
  if (
    !/^[1-9][0-9]*$/.test(count ?? '')
    || !/^[a-f0-9]{64}$/.test(digest ?? '')
    || !Number.isSafeInteger(Number(count))
  ) {
    throw new Error(
      'trusted ledger checkpoint requires a positive record count and SHA-256 head digest',
    )
  }
  return { recordCount: Number(count), headSha256: digest }
}

function renderBrowserPairing(pairing) {
  if (
    pairing === null
    || typeof pairing !== 'object'
    || typeof pairing.bridge_origin !== 'string'
    || typeof pairing.pairing_code !== 'string'
    || typeof pairing.target_origin !== 'string'
    || typeof pairing.campaign_grant_sha256 !== 'string'
  ) {
    throw new Error('the Chrome companion returned an invalid pairing invitation')
  }
  let port
  try {
    const bridge = new URL(pairing.bridge_origin)
    if (bridge.protocol !== 'http:' || bridge.hostname !== '127.0.0.1' || bridge.pathname !== '/') {
      throw new Error('invalid bridge origin')
    }
    port = bridge.port
  } catch {
    throw new Error('the Chrome companion returned an invalid loopback origin')
  }
  return terminalSafeLines([
    'Chrome active-tab campaign is waiting for one attachment.',
    `target origin: ${pairing.target_origin}`,
    `campaign grant sha256: ${pairing.campaign_grant_sha256}`,
    `controller port: ${port}`,
    `one-time pairing capability: ${pairing.pairing_code}`,
    'In the logged-in target tab, open The Last Aperture Browser Bridge, enter the controller port and one-time capability, review the origin and grant, then attach.',
    'Chrome will apply its current session to every sealed action; do not export or paste a cookie.',
    '',
  ])
}

export async function main(
  argv = process.argv.slice(2),
  {
    clock = () => new Date(),
    env = process.env,
    credentialInput = process.stdin,
    credentialStdinReader = readHttpAuthedCredentialFromStdin,
    transport,
    browserTransportFactory,
    requestCampaignStop = requestHttpAuthedCampaignStop,
    browserPairingWrite = (text) => process.stderr.write(text),
    requestPlanLstat = lstat,
    requestPlanOpen = open,
    write = (text) => process.stdout.write(text),
  } = {},
) {
  if (argv.length === 0 || argv[0] === '--help' || argv[0] === '-h') {
    write(HELP)
    return
  }
  assertLocalFilesystemEndpoint(process.cwd(), 'working directory')
  assertNoRemoteFilesystemArguments(argv)
  const { positionals, options } = parseArguments(argv)
  const command = assertCommandShape(positionals, options)
  if (command === 'campaign-stop') {
    const result = await requestCampaignStop({
      directory: options.ledger,
      campaignGrantSha256: options['campaign-grant-sha256'],
      operatorId: options['operator-id'],
      now: clock,
    })
    if (options.json) {
      write(terminalSafeSerializedJson(stableJson(result)))
      return
    }
    write(terminalSafeLines([
      `campaign stop: ${result.status}`,
      `ledger: ${result.ledger}`,
      `campaign grant sha256: ${result.campaign_grant_sha256}`,
      '',
    ]))
    return
  }
  if (command === 'plan-attested') {
    const input = await planInput(
      options,
      { lstatImpl: requestPlanLstat, openImpl: requestPlanOpen },
    )
    const result = await planHttpAuthedAttestedScope(input, {
      env,
      clock,
      credentialInput: options['credential-stdin'] === true ? credentialInput : undefined,
      credentialStdinReader,
    })
    if (options.json) {
      write(terminalSafeSerializedJson(stableJson(result)))
      return
    }
    write(terminalSafeLines([
      `engagement: ${result.engagement_id}`,
      `target: ${result.target_origin}`,
      `scope: ${result.output_path}`,
      `planned actions: ${result.request_count}`,
      `authorization mode: ${result.authorization_mode}`,
      `independently verified: ${result.independently_verified}`,
      `authorization assurance: ${result.authorization_assurance}`,
      `authorization nonclaim: ${result.authorization_nonclaim}`,
      `authorization binding sha256: ${result.authorization_binding_sha256}`,
      `campaign grant sha256: ${result.campaign_grant_sha256}`,
      '',
    ]))
    return
  }
  if (command === 'campaign-attested') {
    if (options['credential-browser'] === true && options['credential-stdin'] === true) {
      throw new Error(`${command} accepts only one explicit credential transport mode`)
    }
    const result = await runHttpAuthedAttestedCampaign({
      scopePath: options.scope,
      expectedCampaignGrantSha256: options['campaign-grant-sha256'],
      ledgerDirectory: options.ledger,
      materialsDirectory: options.materials,
      operatorId: options['operator-id'],
      fixedCampaignOnly: false,
      trustedLedgerHead: trustedLedgerHead(options),
      env,
      credentialInput: options['credential-stdin'] === true ? credentialInput : undefined,
      credentialStdinReader,
      browserSessionRequested: options['credential-browser'] === true,
      browserTransportFactory,
      onBrowserPairing: async (pairing) => browserPairingWrite(renderBrowserPairing(pairing)),
      clock,
      protectedTransport: transport,
    })
    if (options.json) {
      write(terminalSafeSerializedJson(stableJson(result)))
      return
    }
    write(terminalSafeLines([
      `completed actions: ${result.actions.completed}`,
      `discovered actions: ${result.actions.discovered}`,
      `failed actions: ${result.actions.failed}`,
      `uncertain actions: ${result.actions.uncertain}`,
      `authorization mode: ${result.authorization_mode}`,
      `independently verified: ${result.independently_verified}`,
      `authorization assurance: ${result.authorization_assurance}`,
      `authorization nonclaim: ${result.authorization_nonclaim}`,
      ...(result.cleanup_only === true ? ['cleanup only: true'] : []),
      `authorization binding sha256: ${result.authorization_binding_sha256}`,
      `ledger records: ${result.ledger.record_count}`,
      `ledger head sha256: ${result.ledger.head_sha256}`,
      `campaign stopped: ${result.ledger.stopped}`,
      `campaign stop reason: ${result.ledger.stop_reason ?? 'none'}`,
      `campaign grant sha256: ${result.campaign_grant_sha256}`,
      '',
    ]))
    return
  }
  const verified = await readAndVerifyHttpAuthedAuthorization({
    scopePath: options.scope,
    requiredMode: 'OPERATOR_ATTESTED_AUTHED',
    now: clock(),
  })
  const summary = publicValidationSummary(verified)
  if (options.json) {
    write(terminalSafeSerializedJson(stableJson(summary)))
    return
  }
  write(terminalSafeLines([
    `engagement: ${summary.engagement_id}`,
    `authorization: ${summary.authorization_mode}`,
    `independently verified: ${summary.independently_verified}`,
    `authorization assurance: ${summary.authorization_assurance}`,
    `authorization nonclaim: ${summary.authorization_nonclaim}`,
    `target: ${summary.target_origin}`,
    `planned actions: ${summary.request_count}`,
    `authorization binding sha256: ${summary.authorization_binding_sha256}`,
    `campaign grant sha256: ${summary.campaign_grant_sha256}`,
    '',
  ]))
}

if (isMainModule(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${terminalSafeText(error.message)}\n`)
    process.exitCode = 1
  })
}
