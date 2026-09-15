#!/usr/bin/env node

import { constants as fsConstants } from 'node:fs'
import { lstat, open, realpath } from 'node:fs/promises'
import { isAbsolute, join, parse, relative, resolve } from 'node:path'
import { TextDecoder } from 'node:util'

import { assertLocalFilesystemEndpoint } from './lib/filesystem-endpoint.mjs'
import { isMainModule } from './lib/main-module.mjs'
import { terminalSafeJson, terminalSafeText } from './lib/terminal-text.mjs'
import { PLATFORM_VERSION } from './lib/version.mjs'

const MAX_ATTESTATION_BYTES = 8 * 1024
const OPEN_READ_FLAGS = fsConstants.O_RDONLY
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)
  | (typeof fsConstants.O_NONBLOCK === 'number' ? fsConstants.O_NONBLOCK : 0)
const DEFAULT_OBJECTIVE = 'Run the full authorized assessment and integration workflow for the named target.'

export const ENGAGE_HELP = `The Last Aperture unified engagement ${PLATFORM_VERSION}

Usage:
  last-aperture engage unleash <target> [--json]
  last-aperture engage run <target> --attestation-file <file> --profile <full|repository-read|web|reverse|offline> --out <new-directory> [--target-kind <kind>] [--objective <text>] [--credential-reference <name> ...] [--input <kind=absolute-path> ...] [--json]
  last-aperture engage resume <campaign-or-engagement-directory> [--json]
  last-aperture engage status <campaign-or-engagement-directory> [--json]
  last-aperture engage stop <campaign-or-engagement-directory> [--reason <text>] [--json]
  last-aperture engage work next <engagement-directory> [--json]
  last-aperture engage work status <engagement-directory> [--json]
  last-aperture engage work submit <engagement-directory> --work-id <repository-work:sha256> --result <absolute-json-path> [--json]
  last-aperture engage work finalize <engagement-directory> [--json]
  last-aperture engage work validate <engagement-directory> [--json]

Authenticated browser sessions:
  --credential-reference browser:<32-character a-p Chrome-extension-id>
  [--input configuration=<absolute-page-session-adapter.json>]

Unleash is the target-only Point-Click-Shoot path. Controller-owned deployment
policy, storage, provider configuration, and credentials remain outside runtime
input. The legacy run command stores one bounded ordinary-language operator
statement and remains available for explicit engagement intake.
`

const BOOLEAN_OPTIONS = new Set(['help', 'json'])
const REPEATABLE_OPTIONS = new Set(['credential-reference', 'input'])
const TARGET_KINDS = new Set(['https', 'repository', 'artifact', 'process', 'device', 'browser'])
const INPUT_KINDS = new Set(['artifact', 'capture', 'configuration', 'plan'])
const AUTHORIZATION_PROFILES = new Set(['full', 'repository-read', 'web', 'reverse', 'offline'])

function cliError(code, message) {
  const error = new Error(message)
  error.name = 'EngageCliError'
  error.code = code
  return error
}

function comparablePath(path) {
  return process.platform === 'win32' ? path.toLowerCase() : path
}

async function inspectAttestationPath(path) {
  const filesystemRoot = parse(path).root
  let current = filesystemRoot
  let metadata = await lstat(current, { bigint: true })
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw cliError('ENGAGE_ATTESTATION_FILE_INVALID', 'attestation path has an unsafe filesystem root')
  }
  const parts = relative(filesystemRoot, path).split(/[\\/]/u).filter(Boolean)
  for (const [index, part] of parts.entries()) {
    current = join(current, part)
    metadata = await lstat(current, { bigint: true })
    if (metadata.isSymbolicLink()) {
      throw cliError('ENGAGE_ATTESTATION_FILE_INVALID', 'attestation path cannot traverse a symbolic link or junction')
    }
    if (index < parts.length - 1 && !metadata.isDirectory()) {
      throw cliError('ENGAGE_ATTESTATION_FILE_INVALID', 'attestation path contains a non-directory ancestor')
    }
  }
  const canonical = await realpath(path)
  assertLocalFilesystemEndpoint(canonical, 'engagement attestation file')
  if (comparablePath(canonical) !== comparablePath(path)) {
    throw cliError('ENGAGE_ATTESTATION_FILE_INVALID', 'attestation file path must be canonical and alias-free')
  }
  return metadata
}

function parseArguments(argv) {
  if (!Array.isArray(argv) || argv.some((value) => typeof value !== 'string')) {
    throw cliError('ENGAGE_CLI_INVALID', 'engage arguments must be strings')
  }
  const positionals = []
  const options = new Map()
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index]
    if (!token.startsWith('--')) {
      positionals.push(token)
      continue
    }
    const name = token.slice(2)
    if (name.length === 0 || name.includes('=')) {
      throw cliError('ENGAGE_CLI_OPTION_INVALID', `unknown engage option syntax: ${token}`)
    }
    if (BOOLEAN_OPTIONS.has(name)) {
      if (options.has(name)) throw cliError('ENGAGE_CLI_OPTION_DUPLICATE', `duplicate engage option: --${name}`)
      options.set(name, true)
      continue
    }
    const value = argv[index + 1]
    if (value === undefined || value.startsWith('--')) {
      throw cliError('ENGAGE_CLI_OPTION_VALUE_REQUIRED', `engage option requires one value: --${name}`)
    }
    index += 1
    if (REPEATABLE_OPTIONS.has(name)) {
      options.set(name, [...(options.get(name) ?? []), value])
    } else if (options.has(name)) {
      throw cliError('ENGAGE_CLI_OPTION_DUPLICATE', `duplicate engage option: --${name}`)
    } else {
      options.set(name, value)
    }
  }
  return { positionals, options }
}

function assertCommand(parsed) {
  const [topLevel, ...positionals] = parsed.positionals
  let command = topLevel
  let rest = positionals
  if (topLevel === 'work') {
    const [workAction, ...workRest] = positionals
    if (!['next', 'status', 'submit', 'finalize', 'validate'].includes(workAction ?? '')) {
      throw cliError('ENGAGE_CLI_COMMAND_INVALID', `unknown engage work command: ${workAction ?? '(none)'}`)
    }
    command = `work-${workAction}`
    rest = workRest
  }
  if (!['unleash', 'run', 'resume', 'status', 'stop', 'work-next', 'work-status', 'work-submit', 'work-finalize', 'work-validate'].includes(command ?? '')) {
    throw cliError('ENGAGE_CLI_COMMAND_INVALID', `unknown engage command: ${command ?? '(none)'}`)
  }
  if (rest.length !== 1) {
    throw cliError(
      'ENGAGE_CLI_USAGE',
      command === 'unleash'
        ? 'engage unleash requires exactly one target'
        : `engage ${command} requires exactly one target or engagement directory`,
    )
  }
  const allowed = command === 'unleash'
    ? new Set(['json', 'help'])
    : command === 'run'
    ? new Set(['attestation-file', 'profile', 'out', 'target-kind', 'objective', 'credential-reference', 'input', 'json', 'help'])
    : command === 'stop'
      ? new Set(['reason', 'json', 'help'])
      : command === 'work-submit'
        ? new Set(['work-id', 'result', 'json', 'help'])
      : new Set(['json', 'help'])
  for (const name of parsed.options.keys()) {
    if (!allowed.has(name)) {
      throw cliError('ENGAGE_CLI_OPTION_UNKNOWN', `engage ${command} does not support --${name}`)
    }
  }
  if (command === 'run') {
    for (const required of ['attestation-file', 'profile', 'out']) {
      if (typeof parsed.options.get(required) !== 'string') {
        throw cliError('ENGAGE_CLI_OPTION_REQUIRED', `engage run requires --${required} <value>`)
      }
    }
    if (!AUTHORIZATION_PROFILES.has(parsed.options.get('profile'))) {
      throw cliError('ENGAGE_CLI_PROFILE_INVALID', 'engage run requires a supported explicit authorization profile')
    }
  } else if (command === 'work-submit') {
    for (const required of ['work-id', 'result']) {
      if (typeof parsed.options.get(required) !== 'string') {
        throw cliError('ENGAGE_CLI_OPTION_REQUIRED', `engage work submit requires --${required} <value>`)
      }
    }
  }
  return { command, operand: rest[0] }
}

function parseTarget(operand, kind) {
  if (kind === undefined) return operand
  if (!TARGET_KINDS.has(kind)) {
    throw cliError('ENGAGE_CLI_TARGET_KIND_INVALID', `unsupported engagement target kind: ${kind}`)
  }
  return { kind, locator: operand }
}

function parseInputs(values = []) {
  return values.map((value) => {
    const separator = value.indexOf('=')
    const kind = separator === -1 ? '' : value.slice(0, separator)
    const locator = separator === -1 ? '' : value.slice(separator + 1)
    if (!INPUT_KINDS.has(kind) || locator.length === 0) {
      throw cliError(
        'ENGAGE_CLI_INPUT_INVALID',
        'engagement input must use artifact, capture, configuration, or plan followed by =absolute-path',
      )
    }
    return { kind, locator }
  })
}

export async function readBoundedAttestation(path) {
  try {
    assertLocalFilesystemEndpoint(path, 'engagement attestation file')
  } catch {
    throw cliError('ENGAGE_ATTESTATION_FILE_INVALID', 'attestation file must use an absolute local filesystem path')
  }
  if (typeof path !== 'string' || !isAbsolute(path) || resolve(path) !== path) {
    throw cliError('ENGAGE_ATTESTATION_FILE_INVALID', 'attestation file must use an absolute local filesystem path')
  }
  const sameIdentity = (left, right) => left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
  let before
  let handle
  let bytes
  try {
    before = await inspectAttestationPath(path)
    if (
      !before.isFile()
      || before.isSymbolicLink()
      || before.nlink !== 1n
      || before.size < 1n
      || before.size > BigInt(MAX_ATTESTATION_BYTES)
    ) {
      throw cliError('ENGAGE_ATTESTATION_FILE_INVALID', 'attestation file must be one bounded regular non-link file')
    }
    handle = await open(path, OPEN_READ_FLAGS)
    const opened = await handle.stat({ bigint: true })
    if (!opened.isFile() || opened.nlink !== 1n || !sameIdentity(before, opened)) {
      throw cliError('ENGAGE_ATTESTATION_FILE_CHANGED', 'attestation file identity changed while opening')
    }
    const buffer = Buffer.alloc(MAX_ATTESTATION_BYTES + 1)
    let offset = 0
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset)
      if (bytesRead === 0) break
      offset += bytesRead
    }
    const heldAfter = await handle.stat({ bigint: true })
    const pathAfter = await inspectAttestationPath(path)
    if (
      offset < 1
      || offset > MAX_ATTESTATION_BYTES
      || !sameIdentity(opened, heldAfter)
      || !sameIdentity(opened, pathAfter)
      || pathAfter.isSymbolicLink()
    ) {
      throw cliError('ENGAGE_ATTESTATION_FILE_CHANGED', 'attestation file changed while it was read')
    }
    bytes = buffer.subarray(0, offset)
  } catch (error) {
    if (error?.name === 'EngageCliError') throw error
    throw cliError('ENGAGE_ATTESTATION_FILE_INVALID', 'attestation file could not be read as one stable local file')
  } finally {
    await handle?.close()
  }
  let value
  try {
    value = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    throw cliError('ENGAGE_ATTESTATION_FILE_INVALID', 'attestation file must contain valid UTF-8')
  }
  return value
}

async function defaultOperations() {
  const controller = await import('./lib/engagement-controller.mjs')
  const unleash = await import('./lib/unleash-controller.mjs')
  const operations = {
    unleashTarget: unleash.unleashTarget,
    resumeUnleashCampaign: unleash.resumeUnleashCampaign,
    getUnleashCampaignStatus: unleash.getUnleashCampaignStatus,
    stopUnleashCampaign: unleash.stopUnleashCampaign,
    readAttestation: readBoundedAttestation,
    startEngagement: controller.startEngagement,
    resumeEngagement: controller.resumeEngagement,
    getEngagementStatus: controller.getEngagementStatus,
    stopEngagement: controller.stopEngagement,
    getRepositoryNextWork: controller.getRepositoryNextWork,
    getRepositoryWorkStatus: controller.getRepositoryWorkStatus,
    submitRepositoryWork: controller.submitRepositoryWork,
    finalizeRepositoryWork: controller.finalizeRepositoryWork,
    validateRepositoryWork: controller.validateRepositoryWork,
  }
  operations.identifyManagementBundle = (input) => identifyEngageManagementBundle(input, {
    getUnleashCampaignStatus: operations.getUnleashCampaignStatus,
    getEngagementStatus: operations.getEngagementStatus,
  })
  return operations
}

export async function identifyEngageManagementBundle(
  input,
  { getUnleashCampaignStatus, getEngagementStatus } = {},
) {
  if (
    input === null
    || typeof input !== 'object'
    || Array.isArray(input)
    || Object.keys(input).length !== 1
    || typeof input.bundle !== 'string'
    || typeof getUnleashCampaignStatus !== 'function'
    || typeof getEngagementStatus !== 'function'
  ) {
    throw cliError('ENGAGE_BUNDLE_IDENTITY_INVALID', 'management requires one bundle and both validating controllers')
  }

  const candidates = []
  let unleashFailure
  try {
    candidates.push({
      kind: 'unleash',
      status: await getUnleashCampaignStatus({ bundle: input.bundle }),
    })
  } catch (error) {
    unleashFailure = error
  }

  try {
    candidates.push({
      kind: 'engagement',
      status: await getEngagementStatus({ bundle: input.bundle }),
    })
  } catch {}

  if (candidates.length === 1) return Object.freeze(candidates[0])
  if (candidates.length > 1) {
    throw cliError('ENGAGE_BUNDLE_IDENTITY_AMBIGUOUS', 'bundle validates as both an Unleash campaign and a legacy engagement')
  }
  if (
    unleashFailure !== null
    && typeof unleashFailure === 'object'
    && (
      typeof unleashFailure.run_directory === 'string'
      || typeof unleashFailure.status === 'string'
    )
  ) throw unleashFailure
  throw cliError('ENGAGE_BUNDLE_IDENTITY_INVALID', 'bundle does not validate as an Unleash campaign or a legacy engagement')
}

function assertManagementIdentity(value) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || !['unleash', 'engagement'].includes(value.kind)
    || value.status === null
    || typeof value.status !== 'object'
    || Array.isArray(value.status)
  ) throw cliError('ENGAGE_BUNDLE_IDENTITY_INVALID', 'bundle identity validator returned an invalid result')
  return value
}

function render(result, asJson, stdout) {
  if (asJson) {
    stdout.write(`${terminalSafeJson(result, 2)}\n`)
    return
  }
  if (typeof result?.campaign_id === 'string') {
    const counts = result.route_counts ?? {}
    const target = typeof result.target === 'string'
      ? result.target
      : result.target?.canonical_locator ?? '(unavailable)'
    const lines = [
      `Campaign: ${result.campaign_id}`,
      `Status: ${result.status}`,
      `Target: ${target}`,
      `Plan SHA-256: ${result.plan_sha256}`,
      `Run directory: ${result.run_directory}`,
      `Completed routes: ${Array.isArray(result.completed_routes) ? result.completed_routes.length : 0}`,
      `Routes: total=${counts.total ?? 0} ready=${counts.ready ?? 0} waiting=${counts.waiting ?? 0} unavailable=${counts.unavailable ?? 0} not_applicable=${counts.not_applicable ?? 0} blocked=${counts.blocked ?? 0}`,
      `Gaps: ${result.gap_count ?? 0}`,
    ]
    stdout.write(`${lines.map((line) => terminalSafeText(line)).join('\n')}\n`)
    return
  }
  const lines = [
    `Engagement: ${result.engagement_id}`,
    `Status: ${result.status}`,
    `Bundle: ${result.bundle}`,
  ]
  if (Array.isArray(result.completed_routes)) {
    lines.push(`Completed routes: ${result.completed_routes.length}`)
  }
  if (Array.isArray(result.waiting_routes)) {
    lines.push(`Waiting routes: ${result.waiting_routes.length}`)
  }
  stdout.write(`${lines.map((line) => terminalSafeText(line)).join('\n')}\n`)
}

export async function runEngageCli(argv, dependencies = {}) {
  const stdout = dependencies.stdout ?? process.stdout
  const stderr = dependencies.stderr ?? process.stderr
  let asJson = Array.isArray(argv) && argv.includes('--json')
  try {
    assertLocalFilesystemEndpoint(process.cwd(), 'working directory')
    const parsed = parseArguments(argv)
    asJson = parsed.options.get('json') === true
    if (parsed.options.get('help') === true || parsed.positionals.length === 0) {
      stdout.write(ENGAGE_HELP)
      return 0
    }
    const { command, operand } = assertCommand(parsed)
    const defaults = Object.keys(dependencies).some((key) => [
      'unleashTarget',
      'resumeUnleashCampaign',
      'getUnleashCampaignStatus',
      'stopUnleashCampaign',
      'identifyManagementBundle',
      'readAttestation',
      'startEngagement',
      'resumeEngagement',
      'getEngagementStatus',
      'stopEngagement',
      'getRepositoryNextWork',
      'getRepositoryWorkStatus',
      'submitRepositoryWork',
      'finalizeRepositoryWork',
      'validateRepositoryWork',
    ].includes(key)) ? {} : await defaultOperations()
    const operations = { ...defaults, ...dependencies }
    let result
    if (command === 'unleash') {
      result = await operations.unleashTarget({ target: operand })
    } else if (command === 'run') {
      const target = parseTarget(operand, parsed.options.get('target-kind'))
      const inputs = parseInputs(parsed.options.get('input') ?? [])
      const statement = await operations.readAttestation(parsed.options.get('attestation-file'))
      result = await operations.startEngagement({
        target,
        statement,
        authorizationProfile: parsed.options.get('profile'),
        out: parsed.options.get('out'),
        objective: parsed.options.get('objective') ?? DEFAULT_OBJECTIVE,
        credentialReferences: parsed.options.get('credential-reference') ?? [],
        inputs,
      })
    } else if (command === 'resume') {
      const identity = assertManagementIdentity(await operations.identifyManagementBundle({ bundle: operand }))
      const operation = identity.kind === 'unleash'
        ? operations.resumeUnleashCampaign
        : operations.resumeEngagement
      if (typeof operation !== 'function') throw cliError('ENGAGE_CLI_OPERATION_UNAVAILABLE', 'resume controller is unavailable')
      result = await operation({ bundle: operand })
    } else if (command === 'status') {
      const identity = assertManagementIdentity(await operations.identifyManagementBundle({ bundle: operand }))
      result = identity.status
    } else if (command === 'stop') {
      const identity = assertManagementIdentity(await operations.identifyManagementBundle({ bundle: operand }))
      const operation = identity.kind === 'unleash'
        ? operations.stopUnleashCampaign
        : operations.stopEngagement
      if (typeof operation !== 'function') throw cliError('ENGAGE_CLI_OPERATION_UNAVAILABLE', 'stop controller is unavailable')
      result = await operation({
        bundle: operand,
        reason: parsed.options.get('reason') ?? 'operator requested stop',
      })
    } else if (command === 'work-next') {
      result = await operations.getRepositoryNextWork({ bundle: operand })
    } else if (command === 'work-status') {
      result = await operations.getRepositoryWorkStatus({ bundle: operand })
    } else if (command === 'work-submit') {
      result = await operations.submitRepositoryWork({
        bundle: operand,
        workId: parsed.options.get('work-id'),
        resultPath: parsed.options.get('result'),
      })
    } else if (command === 'work-finalize') {
      result = await operations.finalizeRepositoryWork({ bundle: operand })
    } else {
      result = await operations.validateRepositoryWork({ bundle: operand })
    }
    render(result, asJson, stdout)
    return 0
  } catch (error) {
    const code = typeof error?.code === 'string' ? error.code : 'ENGAGE_CLI_FAILED'
    const message = terminalSafeText(error?.message ?? 'engage command failed')
    const status = typeof error?.status === 'string' ? terminalSafeText(error.status) : 'FAILED'
    const runDirectory = typeof error?.run_directory === 'string'
      ? terminalSafeText(error.run_directory)
      : undefined
    if (asJson) {
      const failure = { status, error: { code, message } }
      if (runDirectory !== undefined) failure.run_directory = runDirectory
      stderr.write(`${terminalSafeJson(failure, 2)}\n`)
    } else {
      const lines = [`last-aperture engage [${code}]: ${message}`]
      if (typeof error?.status === 'string') lines.push(`Status: ${status}`)
      if (runDirectory !== undefined) lines.push(`Run directory: ${runDirectory}`)
      stderr.write(`${lines.map((line) => terminalSafeText(line)).join('\n')}\n`)
    }
    return 1
  }
}

if (isMainModule(import.meta.url)) {
  process.exitCode = await runEngageCli(process.argv.slice(2))
}
