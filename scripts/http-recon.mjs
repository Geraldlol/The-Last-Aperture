#!/usr/bin/env node

import {
  finalizeHttpReconBundle,
  httpReconReportPath,
  nextHttpReconAction,
  planHttpReconBundle,
  planOperatorAttestedHttpReconBundle,
  requestHttpReconStop,
  runHttpReconAction,
  validateHttpReconBundle,
} from './lib/http-recon-controller.mjs'
import { isMainModule } from './lib/main-module.mjs'
import { PLATFORM_VERSION, stableJson } from './lib/run-engine.mjs'

const HELP = `red-team-audit authorized HTTP reconnaissance ${PLATFORM_VERSION}

Usage:
  http-recon plan --target-url <exact-https-url> --operator-id <id> --authorized-by <name-or-role> --authorization-reference <reference> --attest-authorized --out <bundle> [--method <HEAD|GET|OPTIONS>] [--safe-to-get] [--request-header-profile <controller-profile>] [--response-observation-profile <controller-profile>] [--tls-spki-sha256 <hex>] [--json]
  http-recon plan-signed --roe <signed-roe.json> --authorization-document <document> --owner-public-key <ed25519-public.pem> --out <bundle> [--json]
  http-recon next <bundle> [--authorization-document <document> --owner-public-key <ed25519-public.pem>] [--json]
  http-recon run <bundle> <action-id> --operator-id <id> --rationale <text> [--confirm-authorization-current] [--authorization-document <document> --owner-public-key <ed25519-public.pem>] [--json]
  http-recon stop <bundle> --operator-id <id> --reason <text> [--json]
  http-recon finalize <bundle> [--authorization-document <document> --owner-public-key <ed25519-public.pem>] [--json]
  http-recon validate <bundle> [--authorization-document <document> --owner-public-key <ed25519-public.pem>] [--json]
  http-recon report <bundle>

Boundary:
  The default plan seals one exact operator-attested HTTPS HEAD, GET, or OPTIONS
  action without requiring authorization files or an owner public-key file.
  Signed RoE mode remains available through plan-signed. Operator-attested planning
  may seal one controller-owned diagnostic request-header profile or narrow response-
  observation profile; arbitrary names and values remain refused. Neither mode accepts
  a target, URL, method, TLS policy, profile, credential, or payload after planning.

  Planning performs no network activity. Operator-attested authorization is a
  recorded declaration, not independently verified owner permission. Every run
  rechecks the sealed action, validity window, hard budgets, and stop state.
  The default TLS policy uses the runtime-configured CA trust and hostname validation,
  then records the observed certificate and SPKI hashes. An advance SPKI pin is
  optional for operator-attested plans and mandatory only in signed RoE mode.

Exit codes:
  0  command succeeded
  1  invalid input, stopped engagement, failed validation, or operational failure
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
  'roe',
  'authorization-document',
  'owner-public-key',
  'target-url',
  'tls-spki-sha256',
  'method',
  'request-header-profile',
  'response-observation-profile',
  'authorized-by',
  'authorization-reference',
  'environment',
  'out',
  'operator-id',
  'rationale',
  'reason',
])

const FLAG_OPTIONS = new Set([
  'json',
  'attest-authorized',
  'safe-to-get',
  'confirm-authorization-current',
])

const COMMANDS = {
  plan: {
    positionals: 0,
    required: [
      'target-url',
      'operator-id',
      'authorized-by',
      'authorization-reference',
      'out',
    ],
    requiredFlags: ['attest-authorized'],
    optional: [
      'environment',
      'method',
      'safe-to-get',
      'request-header-profile',
      'response-observation-profile',
      'tls-spki-sha256',
      'json',
    ],
  },
  'plan-signed': {
    positionals: 0,
    required: ['roe', 'authorization-document', 'owner-public-key', 'out'],
    optional: ['json'],
  },
  next: {
    positionals: 1,
    required: [],
    optional: ['authorization-document', 'owner-public-key', 'json'],
  },
  run: {
    positionals: 2,
    required: [
      'operator-id',
      'rationale',
    ],
    optional: [
      'authorization-document',
      'owner-public-key',
      'confirm-authorization-current',
      'json',
    ],
  },
  stop: {
    positionals: 1,
    required: ['operator-id', 'reason'],
    optional: ['json'],
  },
  finalize: {
    positionals: 1,
    required: [],
    optional: ['authorization-document', 'owner-public-key', 'json'],
  },
  validate: {
    positionals: 1,
    required: [],
    optional: ['authorization-document', 'owner-public-key', 'json'],
  },
  report: {
    positionals: 1,
    required: [],
    optional: [],
  },
}

function assertShape(command, positionals, options) {
  const shape = COMMANDS[command]
  if (!shape) throw new Error(`unknown command ${JSON.stringify(command)}\n\n${HELP}`)
  if (positionals.length !== shape.positionals) {
    throw new Error(
      `${command} expects ${shape.positionals} positional arguments; received `
      + `${positionals.length}`,
    )
  }
  const allowed = new Set([
    ...shape.required,
    ...(shape.requiredFlags ?? []),
    ...shape.optional,
  ])
  for (const [key, value] of Object.entries(options)) {
    if (!allowed.has(key)) throw new Error(`${command} does not support --${key}`)
    if (FLAG_OPTIONS.has(key) && value !== true) {
      throw new Error(`--${key} is a flag and does not accept a value`)
    }
    if (VALUE_OPTIONS.has(key) && typeof value !== 'string') {
      throw new Error(`--${key} requires a value`)
    }
  }
  for (const key of shape.required) {
    if (typeof options[key] !== 'string' || options[key].trim() === '') {
      throw new Error(`${command} requires --${key} <value>`)
    }
  }
  for (const key of shape.requiredFlags ?? []) {
    if (options[key] !== true) {
      throw new Error(`${command} requires --${key}`)
    }
  }
}

function trustOptions(options) {
  return {
    authorizationDocumentPath: options['authorization-document'],
    ownerPublicKeyPath: options['owner-public-key'],
  }
}

function printJson(value) {
  process.stdout.write(stableJson(value))
}

export async function main(argv = process.argv.slice(2)) {
  const command = argv[0]
  if (!command || ['help', '--help', '-h'].includes(command)) {
    process.stdout.write(HELP)
    return
  }
  const { positionals, options } = parseArguments(argv.slice(1))
  assertShape(command, positionals, options)

  if (command === 'plan') {
    const planned = await planOperatorAttestedHttpReconBundle({
      targetUrl: options['target-url'],
      tlsSpkiSha256: options['tls-spki-sha256'],
      method: options.method ?? 'HEAD',
      safeToGet: options['safe-to-get'] === true,
      requestHeaderProfile: options['request-header-profile'],
      responseObservationProfile: options['response-observation-profile'],
      operatorId: options['operator-id'],
      authorizedBy: options['authorized-by'],
      authorizationReference: options['authorization-reference'],
      environment: options.environment ?? 'production',
      attestationConfirmed: options['attest-authorized'] === true,
      out: options.out,
    })
    const summary = {
      bundle: planned.directory,
      engagement_id: planned.run.engagement_id,
      authorization_mode: planned.run.authorization.mode,
      state: planned.run.state,
      action_count: planned.run.actions.length,
      action: planned.run.actions[0],
      tls_policy: planned.run.target.tls,
      limits: planned.run.limits,
      valid_until: planned.run.authorization.valid_until,
    }
    if (options.json) printJson(summary)
    else {
      console.log(`Planned operator-attested HTTP reconnaissance ${summary.engagement_id}`)
      console.log(`Bundle: ${summary.bundle}`)
      console.log(`Actions: ${summary.action_count}`)
      console.log(`Sealed action: ${summary.action.method} ${summary.action.url}`)
      console.log(`TLS policy: ${summary.tls_policy.mode}`)
      if (summary.tls_policy.spki_sha256) {
        console.log(`Advance TLS SPKI SHA-256: ${summary.tls_policy.spki_sha256}`)
      } else {
        console.log('Advance TLS SPKI pin: none; the observed SPKI will be recorded at execution.')
      }
      console.log(`Request timeout: ${summary.limits.request_timeout_ms} ms`)
      console.log(`Response byte cap: ${summary.limits.max_response_bytes}`)
      console.log(`Valid until: ${summary.valid_until}`)
      console.log('Authorization was declared by the operator and was not independently verified.')
      console.log('No network request was made during planning.')
    }
    return
  }

  if (command === 'plan-signed') {
    const planned = await planHttpReconBundle({
      roePath: options.roe,
      out: options.out,
      ...trustOptions(options),
    })
    const summary = {
      bundle: planned.directory,
      engagement_id: planned.run.engagement_id,
      authorization_mode: planned.run.authorization.mode,
      state: planned.run.state,
      action_count: planned.run.actions.length,
      valid_until: planned.run.authorization.valid_until,
    }
    if (options.json) printJson(summary)
    else {
      console.log(`Planned externally signed HTTP reconnaissance ${summary.engagement_id}`)
      console.log(`Bundle: ${summary.bundle}`)
      console.log(`Actions: ${summary.action_count}`)
      console.log(`Valid until: ${summary.valid_until}`)
      console.log('No network request was made during planning.')
    }
    return
  }

  if (command === 'next') {
    const action = await nextHttpReconAction({
      bundle: positionals[0],
      ...trustOptions(options),
    })
    if (options.json) printJson(action)
    else if (action === null) console.log('No pending authorized action.')
    else {
      console.log(`Next action: ${action.action_id}`)
      console.log(`${action.method} ${action.url}`)
      console.log('The sealed authorization mode is revalidated before this action.')
    }
    return
  }

  if (command === 'run') {
    const result = await runHttpReconAction({
      bundle: positionals[0],
      actionId: positionals[1],
      operatorId: options['operator-id'],
      rationale: options.rationale,
      authorizationConfirmed: options['confirm-authorization-current'] === true,
      ...trustOptions(options),
    })
    if (options.json) printJson(result)
    else if (result.action === null) {
      console.log(`No action dispatched: ${result.run.state}`)
      if (result.stop_reason) console.log(`Stopped: ${result.stop_reason}`)
    }
    else {
      console.log(`Action ${result.action.action_id}: ${result.action.state}`)
      console.log(`Run state: ${result.run.state}`)
      if (result.stop_reason) console.log(`Stopped: ${result.stop_reason}`)
    }
    if (['FAILED', 'STOPPED', 'OUTCOME_UNCERTAIN'].includes(result.run.state)) {
      process.exitCode = 1
    }
    return
  }

  if (command === 'stop') {
    const stopped = await requestHttpReconStop({
      bundle: positionals[0],
      operatorId: options['operator-id'],
      reason: options.reason,
    })
    if (options.json) printJson(stopped)
    else {
      console.log(`Stop requested for ${stopped.engagement_id}`)
      console.log(`Marker: ${stopped.path}`)
    }
    return
  }

  if (command === 'finalize') {
    const finalized = await finalizeHttpReconBundle({
      bundle: positionals[0],
      ...trustOptions(options),
    })
    const summary = {
      engagement_id: finalized.run.engagement_id,
      state: finalized.run.state,
      report: finalized.reportPath,
    }
    if (options.json) printJson(summary)
    else {
      console.log(`Authorized HTTP reconnaissance: ${summary.state}`)
      console.log(`Report: ${summary.report}`)
    }
    if (summary.state !== 'PROBE_PLAN_COMPLETE') process.exitCode = 1
    return
  }

  if (command === 'validate') {
    const validation = await validateHttpReconBundle({
      bundle: positionals[0],
      ...trustOptions(options),
    })
    if (options.json) printJson(validation)
    else if (validation.valid) {
      console.log(`Valid: ${validation.path}`)
      console.log(`State: ${validation.state}`)
    } else {
      console.error(`Invalid: ${validation.path}`)
      for (const error of validation.errors) {
        console.error(`- ${error.code}: ${error.message}`)
      }
    }
    if (!validation.valid) process.exitCode = 1
    return
  }

  if (command === 'report') {
    console.log(await httpReconReportPath(positionals[0]))
  }
}

if (isMainModule(import.meta.url)) {
  main().catch((error) => {
    console.error(`ERROR: ${error.message}`)
    for (const detail of error.details ?? []) {
      console.error(
        `- ${detail.code ?? detail.keyword}: `
        + `${detail.instancePath ?? '/'} ${detail.message}`,
      )
    }
    if (error.bundle) console.error(`Bundle: ${error.bundle}`)
    process.exitCode = 1
  })
}
