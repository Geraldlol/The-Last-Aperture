#!/usr/bin/env node

import {
  checkBountyScope,
  planBountyBundle,
  revalidateBountyBundle,
  validateBountyBundle,
} from './lib/bounty-controller.mjs'
import { isMainModule } from './lib/main-module.mjs'
import { PLATFORM_VERSION } from './lib/run-engine.mjs'

const HELP = `red-team-audit bounty-v1 program perimeter ${PLATFORM_VERSION}

Usage:
  bounty plan --platform <yeswehack|hackerone|intigriti|direct> --program <handle> --engagement-id <id> --policy-url <https-url> --policy-file <snapshot> --operator-id <id> --authorized-by <text> --allow <spec> [--allow <spec>...] [--deny <spec>...] --rate-limit-rps <n> --not-before <iso8601> --not-after <iso8601> --attest-enrolled --out <parent> [--active-testing] [--mutation] [--automation] [--intensity <normal|aggressive|ham>] [--desync] [--non-production] [--json]
  bounty validate <bundle> [--json]
  bounty revalidate <bundle> --policy-file <fresh-snapshot> [--json]
  bounty scope <bundle> --check <url> [--json]

Scope rule specs:
  *.example.com         all subdomains, NOT the apex
  example.com           the apex only
  example.com:8443      apex on a sealed non-default port
  *.example.com/api     subdomains, path-scoped to /api
  203.0.113.7           an exact IP literal

Intensity (design spec section 20):
  normal      narrow and sampled; the daily driver
  aggressive  exhaustive within each bug class; requires --active-testing
  ham         every class in parallel, recursive to convergence, compound attacks,
              no early exit, auto-escalation on any anomaly; requires
              --active-testing and --automation
  --desync    request smuggling and desync probes; requires --intensity ham, and
              only where the program policy permits them, because desync can
              affect other users of the target

  Intensity changes how hard we hunt inside the sealed perimeter. It never moves
  the perimeter. There is no flag that widens scope_rules after sealing.

Boundary:
  Planning performs no network activity. bounty-v1 seals one bounty program
  perimeter from a policy snapshot digest. The authorization records the
  operator's declaration of program enrollment; it does not verify enrollment,
  asset ownership, scope currency, or revocation. Re-run revalidate before every
  session: programs narrow scope without notice, and a drifted policy means the
  sealed perimeter no longer matches the granted one.

  This protocol never produces repository coverage, an audit clearance, or an
  attestation. It never handles PHI.

Exit codes:
  0  command succeeded, or scope check returned ALLOW
  1  invalid input, failed validation, or policy drift
  2  scope check returned DENY
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
    const next = values[index + 1]
    if (next === undefined || next.startsWith('--')) {
      options[name] = true
      continue
    }
    if (options[name] === undefined) {
      options[name] = next
    } else if (Array.isArray(options[name])) {
      options[name].push(next)
    } else {
      options[name] = [options[name], next]
    }
    index += 1
  }
  return { positionals, options }
}

function list(value) {
  if (value === undefined) return []
  return Array.isArray(value) ? value : [value]
}

function requireOption(options, name) {
  const value = options[name]
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`--${name} is required`)
  }
  return value
}

function emit(payload, asJson) {
  process.stdout.write(asJson ? `${JSON.stringify(payload, null, 2)}\n` : `${payload.summary}\n`)
}

async function commandPlan(options) {
  if (options['attest-enrolled'] !== true) {
    throw new Error('--attest-enrolled is required; bounty-v1 will not seal an unattested perimeter')
  }
  const rateLimit = Number.parseInt(requireOption(options, 'rate-limit-rps'), 10)
  if (!Number.isInteger(rateLimit) || rateLimit < 1) {
    throw new Error('--rate-limit-rps must be a positive integer')
  }
  const planned = await planBountyBundle({
    outParent: requireOption(options, 'out'),
    policyPath: requireOption(options, 'policy-file'),
    engagementId: requireOption(options, 'engagement-id'),
    platform: requireOption(options, 'platform'),
    programHandle: requireOption(options, 'program'),
    policyUrl: requireOption(options, 'policy-url'),
    operatorId: requireOption(options, 'operator-id'),
    authorizedBy: requireOption(options, 'authorized-by'),
    allowSpecs: list(options.allow),
    denySpecs: list(options.deny),
    permissions: {
      active_testing: options['active-testing'] === true,
      production: options['non-production'] !== true,
      third_party: false,
      mutation: options.mutation === true,
      automation_allowed: options.automation === true,
      intensity: typeof options.intensity === 'string' ? options.intensity : 'normal',
      desync_probes: options.desync === true,
      rate_limit_rps: rateLimit,
    },
    validity: {
      notBefore: requireOption(options, 'not-before'),
      notAfter: requireOption(options, 'not-after'),
    },
    now: new Date(),
  })
  emit({
    command: 'plan',
    bundle_path: planned.bundlePath,
    policy_snapshot_sha256: planned.scope.program.policy_snapshot_sha256,
    intensity: planned.scope.authorization.permissions.intensity,
    allow_rules: planned.scope.scope_rules.allow.length,
    deny_rules: planned.scope.scope_rules.deny.length,
    summary: `SEALED ${planned.bundlePath} intensity=${planned.scope.authorization.permissions.intensity} (${planned.scope.scope_rules.allow.length} allow, ${planned.scope.scope_rules.deny.length} deny)`,
  }, options.json === true)
  return 0
}

export async function runBountyCli(argv) {
  const { positionals, options } = parseArguments(argv)
  const command = positionals[0]
  if (options.help === true || command === undefined) {
    process.stdout.write(HELP)
    return 0
  }
  try {
    if (command === 'plan') return await commandPlan(options)
    if (command === 'validate') {
      const result = await validateBountyBundle(positionals[1])
      emit({
        command: 'validate',
        status: result.status,
        summary: `VALID ${positionals[1]}`,
      }, options.json === true)
      return 0
    }
    if (command === 'revalidate') {
      const result = await revalidateBountyBundle(positionals[1], requireOption(options, 'policy-file'))
      emit({
        command: 'revalidate',
        status: result.status,
        sealed: result.sealed,
        observed: result.observed,
        summary: `${result.status} sealed=${result.sealed} observed=${result.observed}`,
      }, options.json === true)
      return result.status === 'UNCHANGED' ? 0 : 1
    }
    if (command === 'scope') {
      const result = await checkBountyScope(positionals[1], requireOption(options, 'check'))
      emit({
        command: 'scope',
        ...result,
        summary: `${result.decision} rule=${result.rule_id} reason=${result.reason}`,
      }, options.json === true)
      return result.decision === 'ALLOW' ? 0 : 2
    }
    process.stderr.write(`unknown command: ${command}\n\n${HELP}`)
    return 1
  } catch (error) {
    process.stderr.write(`bounty: ${error.message}\n`)
    return 1
  }
}

if (isMainModule(import.meta.url)) {
  process.exitCode = await runBountyCli(process.argv.slice(2))
}
