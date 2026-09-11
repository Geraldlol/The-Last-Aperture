#!/usr/bin/env node

import {
  closeSync,
  fsyncSync,
  lstatSync,
  openSync,
  readFileSync,
  writeFileSync,
} from 'node:fs'
import { createHash } from 'node:crypto'
import { userInfo } from 'node:os'
import { join, resolve } from 'node:path'
import { TextDecoder } from 'node:util'
import {
  assertValidAdversarialCurrentScope,
  canonicalAdversarialCurrentScope,
  inspectAdversarialPlan,
  sealAdversarialPlan,
} from './lib/adversarial-cli-contracts.mjs'
import {
  executeEnrolledAdversarialCampaign,
  inspectControllerEnrollment,
} from './lib/adversarial-cli-controller.mjs'
import { goOperatorAttestedHttpRecon } from './lib/http-recon-controller.mjs'
import {
  OPERATOR_CAMPAIGN_AUTHORIZATION_STATEMENT,
  OPERATOR_HTTPS_AUTHORIZATION_STATEMENT,
} from './lib/operator-authorization.mjs'
import {
  assertValidAdversarialPlan,
  canonicalAdversarialPlan,
  digestAdversarialPlan,
} from './lib/adversarial-validation-contracts.mjs'
import { isMainModule } from './lib/main-module.mjs'
import {
  assertLocalFilesystemEndpoint,
  assertNoRemoteFilesystemArguments,
} from './lib/filesystem-endpoint.mjs'
import { PLATFORM_VERSION } from './lib/run-engine.mjs'
import { terminalSafeJson, terminalSafeText } from './lib/terminal-text.mjs'
import { main as repositoryAuditMain } from './audit.mjs'

const MAX_JSON_FILE_BYTES = 1024 * 1024
const TRUSTED_CONTROLLER_ROOT = join(
  userInfo().homedir,
  '.red-team-audit-controller',
  'adversarial-v1',
)

const HELP = `last-aperture adversarial validation ${PLATFORM_VERSION}

Usage:
  adversarial go <target> [--out <directory>] [--method <HEAD|GET|OPTIONS>] [--safe-to-get] [--request-header-profile <controller-profile>] [--tls-spki-sha256 <hex>] [--json]
  adversarial scope validate <scope.json> [--json]
  adversarial plan seal <draft.json> --scope <scope.json> --out <new-plan.json> [--json]
  adversarial plan validate <plan.json> [--scope <scope.json>] [--json]
  adversarial plan inspect <plan.json> [--scope <scope.json>] [--json]
  adversarial enrollment status <enrollment-id> [--json]
  adversarial execute <canonical-plan.json> --enrollment <enrollment-id> [--json]

Trust boundary:
  The operator-attested target-and-go command treats the invocation itself as the
  operator directive. An HTTPS target immediately runs one bounded reconnaissance
  action and returns its evidence report. A local directory enters the static
  repository-audit controller. No repeated certification or attestation flags are
  required. The controller still enforces exact scope, TLS/DNS policy, budgets,
  no redirects, durable pre-dispatch evidence, and stop semantics.

  Offline scope validation, plan sealing, validation, and inspection perform no
  target I/O. Plan sealing derives the exact current-scope digest and creates a
  new canonical file; it never overwrites an existing plan.

  Invoking execute is one operator statement authorizing the exact canonical plan
  and target. The controller accepts that statement as its authorization fact and
  returns a target/plan/scope-bound receipt; it does not independently prove
  underlying legal authority. Fixed controller-owned enrollment still fixes current
  scope and the adapter allowlist. Transports and modules cannot be replaced from
  the CLI.
  No command enrolls or mutates controller trust.

  The built-in structured-fuzz/v1 adapter is a synthetic, offline property oracle.
  It generates bounded integer/JSON values for three fixed pure properties and does
  not read a repository, connect to a loopback service, or exercise a target.
  This CLI dispatches its built-in routes and controller-enrolled adapters.
  An agent may compose other available browser, process, network, Burp, Ghidra,
  Frida, and connector tools under the same operator attestation while preserving
  the target, scope, evidence, cleanup, and stop bindings. The absence of one
  general-purpose CLI adapter is not another authorization decision.

Exit codes:
  0  command succeeded
  1  invalid input, refused execution, or failed technical controller check
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
    const name = value.slice(2)
    if (FLAG_OPTIONS.has(name)) {
      options[name] = true
      continue
    }
    const next = values[index + 1]
    if (next === undefined || next.startsWith('--')) {
      throw cliError('ADVERSARIAL_CLI_OPTION_VALUE_REQUIRED', `--${name} requires a value`)
    }
    if (Object.hasOwn(options, name)) {
      throw cliError('ADVERSARIAL_CLI_OPTION_DUPLICATE', `--${name} may be provided only once`)
    }
    options[name] = next
    index += 1
  }
  return { positionals, options }
}

const FLAG_OPTIONS = new Set([
  'json',
  'safe-to-get',
])

function cliError(code, message, details = []) {
  const error = new Error(message)
  error.name = 'AdversarialCliError'
  error.code = code
  error.details = details
  return error
}

function assertOptions(options, allowed) {
  for (const name of Object.keys(options)) {
    if (!allowed.includes(name)) {
      throw cliError('ADVERSARIAL_CLI_OPTION_UNKNOWN', `unknown option --${name}`)
    }
  }
}

function requireOption(options, name) {
  const value = options[name]
  if (typeof value !== 'string' || value.length === 0) {
    throw cliError('ADVERSARIAL_CLI_OPTION_REQUIRED', `--${name} is required`)
  }
  return value
}

function requirePositionals(positionals, expected, usage) {
  if (positionals.length !== expected) {
    throw cliError('ADVERSARIAL_CLI_USAGE', `expected ${usage}`)
  }
}

function readJsonFile(path, label, { canonical = false, maxBytes = MAX_JSON_FILE_BYTES } = {}) {
  let stat
  let rawBytes
  let value
  try {
    stat = lstatSync(path)
    if (!stat.isFile() || stat.isSymbolicLink()) {
      throw new Error('not a regular non-symlink file')
    }
    if (stat.size > maxBytes) throw new Error(`exceeds ${maxBytes} bytes`)
    rawBytes = readFileSync(path)
    const rawText = new TextDecoder('utf-8', { fatal: true }).decode(rawBytes)
    value = JSON.parse(rawText)
  } catch (cause) {
    throw cliError('ADVERSARIAL_CLI_FILE_INVALID', `${label} could not be read as bounded JSON`, [cause.message])
  }
  const canonicalBytes = canonical
    ? Buffer.from(canonicalAdversarialPlan(value), 'utf8')
    : null
  if (canonical && !rawBytes.equals(canonicalBytes)) {
    throw cliError(
      'ADVERSARIAL_PLAN_NOT_CANONICAL',
      'execution requires exact canonical plan bytes; use plan seal to create them',
    )
  }
  return value
}

function writeExclusive(path, content) {
  const destination = resolve(path)
  let descriptor = null
  try {
    descriptor = openSync(destination, 'wx', 0o600)
    writeFileSync(descriptor, content, 'utf8')
    fsyncSync(descriptor)
    closeSync(descriptor)
    descriptor = null
  } catch (cause) {
    if (cause?.code === 'EEXIST') {
      throw cliError('ADVERSARIAL_CLI_OUTPUT_EXISTS', 'output already exists; plan writes are exclusive')
    }
    throw cliError('ADVERSARIAL_CLI_OUTPUT_FAILED', 'could not write the exclusive output file', [cause.message])
  } finally {
    if (descriptor !== null) closeSync(descriptor)
  }
  return destination
}

function emit(payload, asJson) {
  if (asJson) {
    process.stdout.write(`${terminalSafeJson(payload)}\n`)
  } else {
    process.stdout.write(`${terminalSafeText(payload.summary)}\n`)
  }
}

function planWithOptionalScope(planPath, options, { canonical = false } = {}) {
  const plan = readJsonFile(planPath, 'adversarial plan', { canonical })
  assertValidAdversarialPlan(plan)
  const currentScope = typeof options.scope === 'string'
    ? readJsonFile(options.scope, 'current scope')
    : undefined
  return { plan, currentScope }
}

async function commandScope(positionals, options) {
  assertOptions(options, ['json'])
  requirePositionals(positionals, 3, 'scope validate <scope.json>')
  if (positionals[1] !== 'validate') {
    throw cliError('ADVERSARIAL_CLI_USAGE', `unknown scope action ${positionals[1]}`)
  }
  const scope = readJsonFile(positionals[2], 'current scope')
  assertValidAdversarialCurrentScope(scope)
  emit({
    ok: true,
    command: 'scope validate',
    canonical_scope: canonicalAdversarialCurrentScope(scope),
    summary: `VALID ${scope.scope_id}`,
  }, options.json === true)
  return 0
}

async function commandPlan(positionals, options) {
  const action = positionals[1]
  if (action === 'seal') {
    assertOptions(options, ['json', 'out', 'scope'])
    requirePositionals(positionals, 3, 'plan seal <draft.json>')
    const draft = readJsonFile(positionals[2], 'adversarial plan draft')
    const currentScope = readJsonFile(requireOption(options, 'scope'), 'current scope')
    const plan = sealAdversarialPlan({ draft, currentScope })
    const output = writeExclusive(requireOption(options, 'out'), canonicalAdversarialPlan(plan))
    const inspection = inspectAdversarialPlan({ plan, currentScope })
    emit({
      ok: true,
      command: 'plan seal',
      output,
      ...inspection,
      summary: `SEALED ${output} sha256=${inspection.plan_sha256}`,
    }, options.json === true)
    return 0
  }
  if (action === 'validate' || action === 'inspect') {
    assertOptions(options, ['json', 'scope'])
    requirePositionals(positionals, 3, `plan ${action} <plan.json>`)
    const { plan, currentScope } = planWithOptionalScope(positionals[2], options)
    const inspection = inspectAdversarialPlan({ plan, currentScope })
    if (
      action === 'validate'
      && currentScope !== undefined
      && (
        inspection.scope_binding !== 'CURRENT_SCOPE_MATCH'
        || inspection.scope_authority !== 'WITHIN_CURRENT_SCOPE'
      )
    ) {
      throw cliError(
        'ADVERSARIAL_PLAN_OUTSIDE_CURRENT_SCOPE',
        'plan is outside the supplied current scope or does not bind its exact digest',
      )
    }
    emit({
      ok: true,
      command: `plan ${action}`,
      ...inspection,
      summary: `VALID ${inspection.plan_id} sha256=${inspection.plan_sha256}`,
    }, options.json === true)
    return 0
  }
  throw cliError('ADVERSARIAL_CLI_USAGE', `unknown plan action ${action ?? '(none)'}`)
}

async function commandEnrollment(positionals, options) {
  assertOptions(options, ['json'])
  requirePositionals(positionals, 3, 'enrollment status <enrollment-id>')
  if (positionals[1] !== 'status') {
    throw cliError('ADVERSARIAL_CLI_USAGE', `unknown enrollment action ${positionals[1]}`)
  }
  const status = inspectControllerEnrollment({
    trustedControllerRoot: TRUSTED_CONTROLLER_ROOT,
    enrollmentId: positionals[2],
    now: new Date(),
  })
  emit({
    ok: true,
    command: 'enrollment status',
    ...status,
    summary: `${status.status} ${status.enrollment_id} scope=${status.scope_status} adapters=${status.allowed_adapters.length}`,
  }, options.json === true)
  return 0
}

async function commandExecute(
  positionals,
  options,
  {
    executeCampaign = executeEnrolledAdversarialCampaign,
    now = () => new Date(),
  } = {},
) {
  assertOptions(options, ['enrollment', 'json'])
  requirePositionals(positionals, 2, 'execute <canonical-plan.json>')
  const plan = readJsonFile(positionals[1], 'canonical adversarial plan', { canonical: true })
  const directedAt = now()
  const directedAtIso = directedAt instanceof Date
    ? directedAt.toISOString()
    : new Date(directedAt).toISOString()
  const operatorAuthorization = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/operator-authorization',
    status: 'OPERATOR_ASSERTED_AUTHORIZED',
    operator_id: localOperatorId(),
    declared_at: directedAtIso,
    authorization_reference: operatorDirectiveReference(
      `${plan.plan_id}\u0000${plan.target.locator}`,
      directedAt,
    ),
    statement: OPERATOR_CAMPAIGN_AUTHORIZATION_STATEMENT,
    plan_sha256: digestAdversarialPlan(plan),
    scope_revision_sha256: plan.scope_revision_sha256,
    target: structuredClone(plan.target),
  }
  const enrollmentId = requireOption(options, 'enrollment')
  const result = await executeCampaign({
    trustedControllerRoot: TRUSTED_CONTROLLER_ROOT,
    enrollmentId,
    plan,
    operatorAuthorization,
    now: new Date(directedAtIso),
  })
  emit({
    ok: true,
    command: 'execute',
    ...result,
    summary: `${result.status} plan=${result.plan_sha256} dispatched=${result.dispatched_actions}`,
  }, options.json === true)
  return 0
}

function localOperatorId() {
  const username = userInfo().username ?? 'unknown'
  return `local:${createHash('sha256').update(username).digest('hex').slice(0, 24)}`
}

function operatorDirectiveReference(target, now) {
  const at = now instanceof Date ? now.toISOString() : new Date(now).toISOString()
  const digest = createHash('sha256').update(`${target}\u0000${at}`).digest('hex').slice(0, 24)
  return `operator-directive:${digest}`
}

function isHttpsTarget(target) {
  try {
    return new URL(target).protocol === 'https:'
  } catch {
    return false
  }
}

async function commandGo(
  positionals,
  options,
  {
    goTarget = goOperatorAttestedHttpRecon,
    repositoryGo = repositoryAuditMain,
    now = () => new Date(),
    progressWrite = (value) => process.stderr.write(value),
  } = {},
) {
  assertOptions(options, [
    'out',
    'environment',
    'method',
    'safe-to-get',
    'request-header-profile',
    'tls-spki-sha256',
    'json',
  ])
  requirePositionals(positionals, 2, 'go <target>')
  const target = positionals[1]
  if (!isHttpsTarget(target)) {
    if (/^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(target)) {
      throw cliError(
        'ADVERSARIAL_GO_TARGET_UNSUPPORTED',
        'network target-and-go currently requires an exact HTTPS URL',
      )
    }
    assertOptions(options, ['out', 'json'])
    const repositoryArguments = ['plan', target]
    if (typeof options.out === 'string') repositoryArguments.push('--out', options.out)
    if (options.json === true) repositoryArguments.push('--json')
    await repositoryGo(repositoryArguments)
    return 0
  }
  const directedAt = now()
  const canonicalTarget = new URL(target).href
  const operatorId = localOperatorId()
  const result = await goTarget({
    targetUrl: canonicalTarget,
    operatorAuthorization: {
      schema_version: '1.0.0',
      kind: 'red-team-audit/operator-authorization',
      status: 'OPERATOR_ASSERTED_AUTHORIZED',
      operator_id: operatorId,
      declared_at: directedAt instanceof Date
        ? directedAt.toISOString()
        : new Date(directedAt).toISOString(),
      authorization_reference: operatorDirectiveReference(canonicalTarget, directedAt),
      statement: OPERATOR_HTTPS_AUTHORIZATION_STATEMENT,
      target: { kind: 'https_url', url: canonicalTarget },
    },
    rationale: 'Operator directed target-and-go execution.',
    out: options.out,
    environment: options.environment ?? 'production',
    method: options.method ?? 'HEAD',
    safeToGet: options['safe-to-get'] === true,
    requestHeaderProfile: options['request-header-profile'],
    tlsSpkiSha256: options['tls-spki-sha256'],
    onPlanned: ({ bundle }) => {
      progressWrite(`${terminalSafeText(`Bundle ready for stop control: ${bundle}`)}\n`)
    },
  })
  emit({
    ok: result.state === 'PROBE_PLAN_COMPLETE',
    command: 'go',
    phase: 'INITIAL_RECONNAISSANCE_COMPLETE',
    ...result,
    authorization_status: 'OPERATOR_DIRECTIVE_ACCEPTED',
    active_testing: 'USE_SCOPE_MATCHED_CONTROLLER',
    summary: `${result.state} target=${target} report=${result.report}`,
  }, options.json === true)
  return result.state === 'PROBE_PLAN_COMPLETE' ? 0 : 1
}

export async function main(
  values,
  {
    goTarget = goOperatorAttestedHttpRecon,
    repositoryGo = repositoryAuditMain,
    executeCampaign = executeEnrolledAdversarialCampaign,
    now = () => new Date(),
    progressWrite = (value) => process.stderr.write(value),
  } = {},
) {
  if (values.length === 0 || values.includes('--help') || values.includes('-h')) {
    process.stdout.write(HELP)
    return 0
  }
  assertLocalFilesystemEndpoint(process.cwd(), 'working directory')
  assertNoRemoteFilesystemArguments(values)
  const { positionals, options } = parseArguments(values)
  const command = positionals[0]
  if (command === 'go') {
    return commandGo(positionals, options, { goTarget, repositoryGo, now, progressWrite })
  }
  assertLocalFilesystemEndpoint(TRUSTED_CONTROLLER_ROOT, 'trusted controller root')
  if (command === 'scope') return commandScope(positionals, options)
  if (command === 'plan') return commandPlan(positionals, options)
  if (command === 'enrollment') return commandEnrollment(positionals, options)
  if (command === 'execute') {
    return commandExecute(positionals, options, { executeCampaign, now })
  }
  throw cliError('ADVERSARIAL_CLI_USAGE', `unknown command ${command ?? '(none)'}`)
}

function sanitizedError(error) {
  return {
    ok: false,
    code: typeof error?.code === 'string' && error.code.startsWith('ADVERSARIAL_')
      ? error.code
      : 'ADVERSARIAL_CLI_FAILED',
    message: typeof error?.message === 'string' ? error.message : 'adversarial command failed',
    ...(Array.isArray(error?.details) && error.details.length > 0
      ? { details: error.details }
      : {}),
  }
}

if (isMainModule(import.meta.url)) {
  const asJson = process.argv.slice(2).includes('--json')
  main(process.argv.slice(2)).then(
    (code) => { process.exitCode = code },
    (error) => {
      const payload = sanitizedError(error)
      process.stderr.write(asJson
        ? `${terminalSafeJson(payload)}\n`
        : `${terminalSafeText(payload.code, 256)}: ${terminalSafeText(payload.message)}\n`)
      process.exitCode = 1
    },
  )
}
