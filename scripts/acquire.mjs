#!/usr/bin/env node

import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { compareCanonicalStrings } from './lib/canonical-order.mjs'
import { terminalSafeJson, terminalSafeText } from './lib/terminal-text.mjs'
import { PLATFORM_VERSION } from './lib/version.mjs'

const HELP = `last-aperture evidence acquisition ${PLATFORM_VERSION}

Usage:
  audit:acquire artifact plan --source <path> --evidence-id <id> --out <bundle> [--target-class <class>] [--phi-scope <scope>] [--json] [DISABLED]
  audit:acquire registry plan --image <ref@sha256:...> --credential-ref <env:NAME> --evidence-id <id> --operator-id <id> --out <bundle> [--target-class <class>] [--phi-scope <scope>] [--json] [DISABLED]
  audit:acquire deployed plan --context <ctx> --evidence-id <id> --operation "<id>:<k>=<v>;<k>=<v>[,...]" --target-class <class> --phi-scope <scope> --operator-id <id> --out <bundle> [--capture-contents --acknowledge-phi] [--json] [DISABLED]
  audit:acquire runtime  plan --context <ctx> --namespace <ns> --pod <pod> --container <c> --evidence-id <id> --operation "<id>[:<k>=<v>][,...]" --target-class <class> --phi-scope <scope> --operator-id <id> --out <bundle> [--capture-contents --acknowledge-phi] [--json] [DISABLED]
  audit:acquire <artifact|registry|deployed|runtime> run <bundle> --operator-id <id> [--json] [DISABLED]
  audit:acquire <adapter> finalize <bundle> [--json] [DISABLED]
  audit:acquire <adapter> validate <bundle> [--json] [DISABLED]
  audit:acquire <adapter> stop <bundle> --operator-id <id> --reason <text> [--json] [DISABLED]

Boundary:
  The entire public acquisition CLI is disabled before argument parsing or
  acquisition-controller loading. This prevents caller-selected adapter names,
  bundle and source paths (including UNC, device, pipe, and linked paths),
  credentials, ambient CLI contexts, crafted acquisition plans, or legacy
  verification reads from causing filesystem, process, or network I/O.
  Re-enabling a command requires bounded no-follow I/O and an exact detached
  signed plan enforced by the trusted adversarial controller. That signature
  protects technical plan integrity; it does not establish engagement authority.
  Re-enabled ingress must accept the authenticated operator target/scope statement
  as its sole authorization primitive. Caller-supplied authorization documents,
  owner keys, approver signatures, countersignatures, and legacy repeat-attestation
  flags cannot unlock acquisition. Retained internal acquisition kernels are
  test-only and are not public execution authority.

Exit codes:
  0  command succeeded
  1  invalid input, stopped acquisition, failed validation, or operational failure
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
    if (!key || Object.hasOwn(options, key)) {
      throw new Error(`invalid or duplicate option ${JSON.stringify(value)}`)
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

const VALUE_OPTIONS = new Set([
  'source',
  'image',
  'credential-ref',
  'authorized-by',
  'authorization-reference',
  'evidence-id',
  'out',
  'target-class',
  'phi-scope',
  'operator-id',
  'reason',
  'context',
  'namespace',
  'pod',
  'container',
  'operation',
])

const FLAG_OPTIONS = new Set([
  'json',
  'confirm-authorization-current',
  'attest-authorized',
  'acknowledge-production',
  'acknowledge-third-party',
  'acknowledge-phi',
  'capture-contents',
])

// Per-adapter plan shapes. Registered adapters keep their own required set, so
// an adapter with no authorization floor is not made to carry one it does not need.
const PLAN_SHAPES = {
  artifact: {
    required: ['source', 'evidence-id', 'out'],
    requiredFlags: [],
    optional: ['target-class', 'phi-scope', 'json'],
  },
  registry: {
    required: [
      'image',
      'credential-ref',
      'evidence-id',
      'operator-id',
      'authorized-by',
      'authorization-reference',
      'out',
    ],
    requiredFlags: ['attest-authorized'],
    optional: ['target-class', 'phi-scope', 'json'],
  },
  deployed: {
    required: ['evidence-id', 'context', 'operation', 'target-class', 'phi-scope', 'operator-id', 'authorized-by', 'authorization-reference', 'out'],
    requiredFlags: ['attest-authorized'],
    optional: ['acknowledge-production', 'acknowledge-third-party', 'acknowledge-phi', 'capture-contents', 'json'],
  },
  runtime: {
    required: ['evidence-id', 'context', 'operation', 'target-class', 'phi-scope', 'operator-id', 'authorized-by', 'authorization-reference', 'out', 'namespace', 'pod', 'container'],
    requiredFlags: ['attest-authorized'],
    optional: ['acknowledge-production', 'acknowledge-third-party', 'acknowledge-phi', 'capture-contents', 'json'],
  },
}

const COMMANDS = {
  plan: { positionals: 0 },
  run: { positionals: 1, required: ['operator-id'], optional: ['confirm-authorization-current', 'json'] },
  finalize: { positionals: 1, required: [], optional: ['json'] },
  validate: { positionals: 1, required: [], optional: ['json'] },
  stop: { positionals: 1, required: ['operator-id', 'reason'], optional: ['json'] },
}

function refuseDisabledPublicAcquisition(adapter, command) {
  const error = new Error(
    `${adapter} ${command ?? '(missing command)'} is disabled before argument parsing, controller loading, acquisition-plan, filesystem, credential, stop-state, target, process, or network I/O pending exact detached signed-plan migration through the trusted adversarial controller`,
  )
  error.code = 'ACQUIRE_LIVE_IO_DISABLED'
  throw error
}

function assertShape(adapter, command, positionals, options) {
  const base = COMMANDS[command]
  if (!base) throw new Error(`unknown command ${JSON.stringify(command)}\n\n${HELP}`)
  const shape = command === 'plan'
    ? { ...base, ...(PLAN_SHAPES[adapter] ?? {}) }
    : base
  if (command === 'plan' && !PLAN_SHAPES[adapter]) {
    throw new Error(`adapter ${JSON.stringify(adapter)} has no plan shape in this release`)
  }
  if (positionals.length !== shape.positionals) {
    throw new Error(
      `${adapter} ${command} expects ${shape.positionals} positional arguments; received `
      + `${positionals.length}`,
    )
  }
  const allowed = new Set([
    ...(shape.required ?? []),
    ...(shape.requiredFlags ?? []),
    ...(shape.optional ?? []),
  ])
  for (const [key, value] of Object.entries(options)) {
    if (!allowed.has(key)) throw new Error(`${adapter} ${command} does not support --${key}`)
    if (FLAG_OPTIONS.has(key) && value !== true) {
      throw new Error(`--${key} is a flag and does not accept a value`)
    }
    if (VALUE_OPTIONS.has(key) && typeof value !== 'string') {
      throw new Error(`--${key} requires a value`)
    }
  }
  for (const key of shape.required ?? []) {
    if (typeof options[key] !== 'string' || options[key].trim() === '') {
      throw new Error(`${adapter} ${command} requires --${key} <value>`)
    }
  }
  for (const key of shape.requiredFlags ?? []) {
    if (options[key] !== true) throw new Error(`${adapter} ${command} requires --${key}`)
  }
}

// --operation takes a compact id:key=value,key=value form, repeated as a
// comma-separated list, because parseArguments rejects a duplicated option.
function parseOperations(value) {
  if (typeof value !== 'string') return undefined
  return value.split(',').map((entry) => {
    const [id, ...pairs] = entry.split(':')
    const params = Object.fromEntries(
      pairs.join(':').split(';').filter(Boolean).map((pair) => {
        const index = pair.indexOf('=')
        if (index === -1) throw new Error(`--operation parameter must be key=value: ${pair}`)
        return [pair.slice(0, index).trim(), pair.slice(index + 1).trim()]
      }),
    )
    return { operation_id: id.trim(), params }
  })
}

function printJson(value) {
  process.stdout.write(`${terminalSafeJson(stableValue(value))}\n`)
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (value === null || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.keys(value)
      .sort(compareCanonicalStrings)
      .map((key) => [key, stableValue(value[key])]),
  )
}

async function controllerFunction(overrides, overrideName, exportName) {
  if (typeof overrides[overrideName] === 'function') return overrides[overrideName]
  const controller = await import('./lib/evidence-acquire-controller.mjs')
  return controller[exportName]
}

function isDirectInvocation(moduleUrl, argvPath = process.argv[1]) {
  if (!argvPath) return false
  return pathToFileURL(resolve(argvPath)).href === moduleUrl
}

export async function main(
  argv = process.argv.slice(2),
  dependencies = {},
) {
  const adapter = argv[0]
  if (!adapter || ['help', '--help', '-h'].includes(adapter)) {
    process.stdout.write(HELP)
    return
  }
  const command = argv[1]
  refuseDisabledPublicAcquisition(adapter, command)
  const { positionals, options } = parseArguments(argv.slice(2))
  assertShape(adapter, command, positionals, options)

  if (command === 'plan') {
    const planAcquisitionImpl = await controllerFunction(
      dependencies,
      'planAcquisitionImpl',
      'planAcquisition',
    )
    const planned = await planAcquisitionImpl({
      adapterId: adapter,
      out: options.out,
      request: {
        evidence_id: options['evidence-id'],
        source_path: options.source,
        image: options.image,
        credential_ref: options['credential-ref'],
        operator_id: options['operator-id'],
        authorized_by: options['authorized-by'],
        authorization_reference: options['authorization-reference'],
        attest_authorized: options['attest-authorized'] === true,
        context: options.context,
        namespace: options.namespace,
        pod: options.pod,
        container: options.container,
        operations: parseOperations(options.operation),
        acknowledge_production: options['acknowledge-production'] === true,
        acknowledge_third_party: options['acknowledge-third-party'] === true,
        acknowledge_phi: options['acknowledge-phi'] === true,
        capture_contents: options['capture-contents'] === true,
        target_class: options['target-class'] ?? (adapter === 'registry' ? 'NONPROD' : 'LAB'),
        phi_scope: options['phi-scope'] ?? 'none',
      },
    })
    const summary = {
      bundle: planned.directory,
      adapter_id: adapter,
      evidence_id: planned.plan.evidence_context_seed.evidence_id,
      target_identity: planned.plan.evidence_context_seed.target_identity,
      target_class: planned.plan.target_class,
      phi_scope: planned.plan.phi_scope,
    }
    if (options.json) printJson(summary)
    else {
      console.log(terminalSafeText(`Planned ${adapter} acquisition ${summary.evidence_id}`))
      console.log(terminalSafeText(`Bundle: ${summary.bundle}`))
      console.log(terminalSafeText(`Sealed target: ${summary.target_identity}`))
      console.log(terminalSafeText(`Target class: ${summary.target_class}   PHI scope: ${summary.phi_scope}`))
      console.log('No acquisition was performed during planning.')
    }
    return
  }

  if (command === 'run') {
    const runAcquisitionImpl = await controllerFunction(
      dependencies,
      'runAcquisitionImpl',
      'runAcquisition',
    )
    const written = await runAcquisitionImpl({
      bundle: positionals[0],
      expectedAdapterId: adapter,
      operatorId: options['operator-id'],
      authorizationConfirmed: options['confirm-authorization-current'] === true,
    })
    const summary = {
      bundle: written.directory,
      coverage_state: written.profile.coverage_state,
      root_sha256: written.root_sha256,
      coverage_gaps: written.profile.coverage_gaps.length,
    }
    if (options.json) printJson(summary)
    else {
      console.log(terminalSafeText(`Acquired: ${summary.coverage_state}`))
      console.log(terminalSafeText(`Bundle: ${summary.bundle}`))
      console.log(terminalSafeText(`Root: ${summary.root_sha256}`))
      if (summary.coverage_gaps > 0) {
        console.log(terminalSafeText(`Coverage gaps: ${summary.coverage_gaps}`))
        for (const gap of written.profile.coverage_gaps) {
          console.log(terminalSafeText(`  - ${gap.area}: ${gap.reason}`))
        }
      }
    }
    if (written.profile.coverage_state === 'NOT_ASSESSED') process.exitCode = 1
    return
  }

  if (command === 'finalize') {
    const finalizeAcquisitionImpl = await controllerFunction(
      dependencies,
      'finalizeAcquisitionImpl',
      'finalizeAcquisition',
    )
    const finalized = await finalizeAcquisitionImpl(positionals[0])
    if (options.json) printJson(finalized)
    else {
      console.log(terminalSafeText(`${finalized.evidence_id} (${finalized.evidence_class}): ${finalized.coverage_state}`))
      console.log(terminalSafeText(`Bundle: ${finalized.directory}`))
      console.log(terminalSafeText(`Root: ${finalized.root_sha256}`))
    }
    return
  }

  if (command === 'validate') {
    const validateAcquisitionImpl = await controllerFunction(
      dependencies,
      'validateAcquisitionImpl',
      'validateAcquisition',
    )
    const validation = await validateAcquisitionImpl(positionals[0])
    if (options.json) printJson(validation)
    else if (validation.valid) {
      console.log(terminalSafeText(`Valid: ${validation.path}`))
      console.log(terminalSafeText(`Root: ${validation.root_sha256}`))
    } else {
      console.error(terminalSafeText(`Invalid: ${validation.path}`))
      for (const error of validation.errors) {
        console.error(terminalSafeText(`- ${error.code}: ${error.message}`))
      }
    }
    if (!validation.valid) process.exitCode = 1
    return
  }

  if (command === 'stop') {
    const requestAcquisitionStopImpl = await controllerFunction(
      dependencies,
      'requestAcquisitionStopImpl',
      'requestAcquisitionStop',
    )
    const stopped = await requestAcquisitionStopImpl({
      bundle: positionals[0],
      operatorId: options['operator-id'],
      reason: options.reason,
    })
    if (options.json) printJson(stopped)
    else {
      console.log(terminalSafeText(`Stop recorded for ${positionals[0]}`))
      console.log(terminalSafeText(`Reason: ${stopped.stop_reason}`))
    }
  }
}

if (isDirectInvocation(import.meta.url)) {
  main().catch((error) => {
    console.error(terminalSafeText(`ERROR: ${error.message}`))
    for (const detail of error.details ?? []) {
      console.error(terminalSafeText(`- ${detail.code ?? detail.keyword}: ${detail.message}`))
    }
    process.exitCode = 1
  })
}
