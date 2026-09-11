#!/usr/bin/env node

import { createHash } from 'node:crypto'
import { userInfo } from 'node:os'

import {
  finalizeHttpReconBundle,
  goOperatorAttestedHttpRecon,
  httpReconReportPath,
  nextHttpReconAction,
  planOperatorAttestedHttpReconBundle,
  requestHttpReconStop,
  runHttpReconAction,
  validateHttpReconBundle,
} from './lib/http-recon-controller.mjs'
import { isMainModule } from './lib/main-module.mjs'
import { OPERATOR_HTTPS_AUTHORIZATION_STATEMENT } from './lib/operator-authorization.mjs'
import {
  assertLocalFilesystemEndpoint,
  assertNoRemoteFilesystemArguments,
} from './lib/filesystem-endpoint.mjs'
import { PLATFORM_VERSION, stableJson } from './lib/run-engine.mjs'
import { terminalSafeSerializedJson, terminalSafeText } from './lib/terminal-text.mjs'

const HELP = `last-aperture authorized HTTP reconnaissance ${PLATFORM_VERSION}

Usage:
  http-recon go <exact-https-url> [--out <bundle>] [--method <HEAD|GET|OPTIONS>] [--safe-to-get] [--request-header-profile <controller-profile>] [--tls-spki-sha256 <hex>] [--json]
  http-recon plan --target-url <exact-https-url> --operator-id <id> --authorized-by <name-or-role> --authorization-reference <reference> --out <bundle> [--method <HEAD|GET|OPTIONS>] [--safe-to-get] [--request-header-profile <controller-profile>] [--tls-spki-sha256 <hex>] [--json]
  http-recon next <bundle> [--json]
  http-recon run <bundle> <action-id> --operator-id <id> --rationale <text> [--json]
  http-recon stop <bundle> --operator-id <id> --reason <text> [--json]
  http-recon finalize <bundle> [--json]
  http-recon validate <bundle> [--json]
  http-recon report <bundle>

Boundary:
  The plan command seals one exact operator-attested HTTPS HEAD, GET, or OPTIONS
  action. Planning may seal one controller-owned diagnostic request-header profile;
  arbitrary names and values remain refused.
  No command accepts a target, URL, method, TLS policy, profile, credential, or
  payload after planning.

  go treats the invocation itself as the operator directive: it plans, executes,
  and finalizes one exact bounded action without repeated attestation flags.
  Planning by itself performs no network activity.
  Operator-attested authorization is accepted as the controller authorization
  fact and recorded, but is not independent proof of underlying legal authority.
  plan, go, and run treat their invocation as the operator directive; they do not
  ask for a repeat confirmation flag. Dispatch remains limited to the same operator
  identity and the exact sealed controller-owned action.
  The default TLS policy uses the runtime-configured CA trust and hostname validation,
  then records the observed certificate and SPKI hashes. An advance SPKI pin is
  optional for operator-attested plans.

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
  'target-url',
  'tls-spki-sha256',
  'method',
  'request-header-profile',
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
  'safe-to-get',
])

const COMMANDS = {
  go: {
    positionals: 1,
    required: [],
    optional: [
      'out',
      'environment',
      'method',
      'safe-to-get',
      'request-header-profile',
      'tls-spki-sha256',
      'json',
    ],
  },
  plan: {
    positionals: 0,
    required: [
      'target-url',
      'operator-id',
      'authorized-by',
      'authorization-reference',
      'out',
    ],
    optional: [
      'environment',
      'method',
      'safe-to-get',
      'request-header-profile',
      'tls-spki-sha256',
      'json',
    ],
  },
  next: {
    positionals: 1,
    required: [],
    optional: ['json'],
  },
  run: {
    positionals: 2,
    required: [
      'operator-id',
      'rationale',
    ],
    optional: ['json'],
  },
  stop: {
    positionals: 1,
    required: ['operator-id', 'reason'],
    optional: ['json'],
  },
  finalize: {
    positionals: 1,
    required: [],
    optional: ['json'],
  },
  validate: {
    positionals: 1,
    required: [],
    optional: ['json'],
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

function printJson(value) {
  process.stdout.write(terminalSafeSerializedJson(stableJson(value)))
}

function operatorAttestedPlanInput(options, directedAt) {
  const targetUrl = new URL(options['target-url']).href
  const declaredAt = directedAt instanceof Date
    ? directedAt.toISOString()
    : new Date(directedAt).toISOString()
  return {
    targetUrl,
    tlsSpkiSha256: options['tls-spki-sha256'],
    method: options.method ?? 'HEAD',
    safeToGet: options['safe-to-get'] === true,
    requestHeaderProfile: options['request-header-profile'],
    operatorId: options['operator-id'],
    authorizedBy: options['authorized-by'],
    authorizationReference: options['authorization-reference'],
    environment: options.environment ?? 'production',
    operatorAuthorization: {
      schema_version: '1.0.0',
      kind: 'red-team-audit/operator-authorization',
      status: 'OPERATOR_ASSERTED_AUTHORIZED',
      operator_id: options['operator-id'],
      declared_at: declaredAt,
      authorization_reference: options['authorization-reference'],
      statement: OPERATOR_HTTPS_AUTHORIZATION_STATEMENT,
      target: { kind: 'https_url', url: targetUrl },
    },
    out: options.out,
  }
}

export async function main(
  argv = process.argv.slice(2),
  {
    goTarget = goOperatorAttestedHttpRecon,
    planAttested = planOperatorAttestedHttpReconBundle,
    runAction = runHttpReconAction,
    finalize = finalizeHttpReconBundle,
    now = () => new Date(),
    write = (value) => process.stdout.write(value),
    progressWrite = (value) => process.stderr.write(value),
  } = {},
) {
  const command = argv[0]
  if (!command || ['help', '--help', '-h'].includes(command)) {
    process.stdout.write(HELP)
    return
  }
  assertLocalFilesystemEndpoint(process.cwd(), 'working directory')
  assertNoRemoteFilesystemArguments(argv)
  const { positionals, options } = parseArguments(argv.slice(1))
  assertShape(command, positionals, options)
  if (command === 'go') {
    const targetUrl = new URL(positionals[0]).href
    const directedAt = now()
    const declaredAt = directedAt instanceof Date
      ? directedAt.toISOString()
      : new Date(directedAt).toISOString()
    const operatorId = `local:${createHash('sha256')
      .update(userInfo().username ?? 'unknown')
      .digest('hex')
      .slice(0, 24)}`
    const authorizationReference = `operator-directive:${createHash('sha256')
      .update(`${targetUrl}\u0000${declaredAt}`)
      .digest('hex')
      .slice(0, 24)}`
    const summary = await goTarget({
      targetUrl,
      tlsSpkiSha256: options['tls-spki-sha256'],
      method: options.method ?? 'HEAD',
      safeToGet: options['safe-to-get'] === true,
      requestHeaderProfile: options['request-header-profile'],
      environment: options.environment ?? 'production',
      out: options.out,
      operatorAuthorization: {
        schema_version: '1.0.0',
        kind: 'red-team-audit/operator-authorization',
        status: 'OPERATOR_ASSERTED_AUTHORIZED',
        operator_id: operatorId,
        declared_at: declaredAt,
        authorization_reference: authorizationReference,
        statement: OPERATOR_HTTPS_AUTHORIZATION_STATEMENT,
        target: { kind: 'https_url', url: targetUrl },
      },
      planImpl: planAttested,
      runImpl: runAction,
      finalizeImpl: finalize,
      onPlanned: ({ bundle }) => {
        progressWrite(`${terminalSafeText(`Bundle ready for stop control: ${bundle}`)}\n`)
      },
    })
    if (options.json) write(terminalSafeSerializedJson(stableJson(summary)))
    else {
      write([
        `Authorized HTTP reconnaissance: ${summary.state}`,
        `Bundle: ${summary.bundle}`,
        `Action: ${summary.action?.action_id ?? 'none'} (${summary.action?.state ?? 'not dispatched'})`,
        `Report: ${summary.report}`,
        '',
      ].map(terminalSafeText).join('\n'))
    }
    if (summary.state !== 'PROBE_PLAN_COMPLETE') process.exitCode = 1
    return
  }
  if (command === 'plan') {
    const input = operatorAttestedPlanInput(options, now())
    const planned = await planAttested({ ...input, now })
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
      console.log(terminalSafeText(`Planned operator-attested HTTP reconnaissance ${summary.engagement_id}`))
      console.log(terminalSafeText(`Bundle: ${summary.bundle}`))
      console.log(terminalSafeText(`Actions: ${summary.action_count}`))
      console.log(terminalSafeText(`Sealed action: ${summary.action.method} ${summary.action.url}`))
      console.log(terminalSafeText(`TLS policy: ${summary.tls_policy.mode}`))
      if (summary.tls_policy.spki_sha256) {
        console.log(terminalSafeText(`Advance TLS SPKI SHA-256: ${summary.tls_policy.spki_sha256}`))
      } else {
        console.log('Advance TLS SPKI pin: none; the observed SPKI will be recorded at execution.')
      }
      console.log(terminalSafeText(`Request timeout: ${summary.limits.request_timeout_ms} ms`))
      console.log(terminalSafeText(`Response byte cap: ${summary.limits.max_response_bytes}`))
      console.log(terminalSafeText(`Valid until: ${summary.valid_until}`))
      console.log('Authorization was declared by the operator and was not independently verified.')
      console.log('No network request was made during planning.')
    }
    return
  }

  if (command === 'next') {
    const action = await nextHttpReconAction({
      bundle: positionals[0],
    })
    if (options.json) printJson(action)
    else if (action === null) console.log('No pending authorized action.')
    else {
      console.log(terminalSafeText(`Next action: ${action.action_id}`))
      console.log(terminalSafeText(`${action.method} ${action.url}`))
      console.log('The sealed authorization mode is revalidated before this action.')
    }
    return
  }

  if (command === 'run') {
    const result = await runAction({
      bundle: positionals[0],
      actionId: positionals[1],
      operatorId: options['operator-id'],
      rationale: options.rationale,
      now,
    })
    if (options.json) printJson(result)
    else if (result.action === null) {
      console.log(terminalSafeText(`No action dispatched: ${result.run.state}`))
      if (result.stop_reason) console.log(terminalSafeText(`Stopped: ${result.stop_reason}`))
    }
    else {
      console.log(terminalSafeText(`Action ${result.action.action_id}: ${result.action.state}`))
      console.log(terminalSafeText(`Run state: ${result.run.state}`))
      if (result.stop_reason) console.log(terminalSafeText(`Stopped: ${result.stop_reason}`))
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
      console.log(terminalSafeText(`Stop requested for ${stopped.engagement_id}`))
      console.log(terminalSafeText(`Marker: ${stopped.path}`))
    }
    return
  }

  if (command === 'finalize') {
    const finalized = await finalizeHttpReconBundle({
      bundle: positionals[0],
    })
    const summary = {
      engagement_id: finalized.run.engagement_id,
      state: finalized.run.state,
      report: finalized.reportPath,
    }
    if (options.json) printJson(summary)
    else {
      console.log(terminalSafeText(`Authorized HTTP reconnaissance: ${summary.state}`))
      console.log(terminalSafeText(`Report: ${summary.report}`))
    }
    if (summary.state !== 'PROBE_PLAN_COMPLETE') process.exitCode = 1
    return
  }

  if (command === 'validate') {
    const validation = await validateHttpReconBundle({
      bundle: positionals[0],
    })
    if (options.json) printJson(validation)
    else if (validation.valid) {
      console.log(terminalSafeText(`Valid: ${validation.path}`))
      console.log(terminalSafeText(`State: ${validation.state}`))
    } else {
      console.error(terminalSafeText(`Invalid: ${validation.path}`))
      for (const error of validation.errors) {
        console.error(terminalSafeText(`- ${error.code}: ${error.message}`))
      }
    }
    if (!validation.valid) process.exitCode = 1
    return
  }

  if (command === 'report') {
    console.log(terminalSafeText(await httpReconReportPath(positionals[0])))
  }
}

if (isMainModule(import.meta.url)) {
  main().catch((error) => {
    console.error(terminalSafeText(`ERROR: ${error.message}`))
    for (const detail of error.details ?? []) {
      console.error(terminalSafeText(
        `- ${detail.code ?? detail.keyword}: `
        + `${detail.instancePath ?? '/'} ${detail.message}`,
      ))
    }
    if (error.bundle) console.error(terminalSafeText(`Bundle: ${error.bundle}`))
    process.exitCode = 1
  })
}
