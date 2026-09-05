#!/usr/bin/env node

import {
  checkBountyScope,
  planBountyBundle,
  revalidateBountyBundle,
  validateBountyBundle,
} from './lib/bounty-controller.mjs'
import {
  authzStatus,
  importAuthzRequests,
} from './lib/bounty-authz-controller.mjs'
import { draftAuthzReports } from './lib/bounty-report-controller.mjs'
import { scanStatus } from './lib/bounty-scan-controller.mjs'
import { loadRoleRegistry } from './lib/bounty-authz-roles.mjs'
import { reconStatus } from './lib/bounty-recon-controller.mjs'
import { isMainModule } from './lib/main-module.mjs'
import {
  assertLocalFilesystemEndpoint,
  assertNoRemoteFilesystemArguments,
} from './lib/filesystem-endpoint.mjs'
import { PLATFORM_VERSION } from './lib/run-engine.mjs'
import { terminalSafeJson, terminalSafeText } from './lib/terminal-text.mjs'

const HELP = `red-team-audit bounty-v1 program perimeter ${PLATFORM_VERSION}

Usage:
  bounty plan --platform <yeswehack|hackerone|intigriti|direct> --program <handle> --engagement-id <id> --policy-url <https-url> --policy-file <snapshot> --operator-id <id> --authorized-by <text> --user-agent <program-mandated-marker> --allow <spec> [--allow <spec>...] [--deny <spec>...] --rate-limit-rps <n> --not-before <iso8601> --not-after <iso8601> --attest-enrolled --out <parent> [--active-testing] [--mutation] [--automation] [--intensity <normal|aggressive|ham>] [--desync] [--non-production] [--json]
  bounty validate <bundle> [--json]
  bounty revalidate <bundle> --policy-file <fresh-snapshot> [--json]
  bounty scope <bundle> --check <url> [--json]
  bounty oob open <bundle> --backend <hosted|self-hosted> [--server <domain>] [--json]  (disabled pending trusted-session migration)
  bounty oob mint <bundle> --label <text> --bug-class <class> [--request-id <id>] [--insertion-point <text>] [--role <name>] [--json]  (disabled pending trusted-session migration)
  bounty oob poll <bundle> [--json]  (disabled pending trusted-session migration)
  bounty oob status <bundle> [--json]  (disabled pending trusted-session migration)
  bounty oob close <bundle> [--json]  (disabled pending trusted-session migration)
  bounty recon run <bundle> --seed <host> [--seed <host>...] [--sources tls,ctlog] [--json]  (disabled pending trusted-scope and pinned-transport migration)
  bounty recon status <bundle> [--json]
  bounty authz import <bundle> --har <file> --owner-role <id> [--json]
  bounty authz run <bundle> --roles <registry.json> [--identifiers <ids.json>] [--json]  (disabled pending controller-authorization migration)
  bounty authz status <bundle> [--json]
  bounty report draft <bundle> --roles <registry.json> [--out <dir>] [--json]
  bounty scan run <bundle> --roles <registry.json> --as <role-id> [--classes error-injection,ssrf-oob,passive] [--json]  (disabled pending controller-authorization migration)
  bounty scan status <bundle> [--json]
  bounty proxy ingest <bundle> [--json]  (disabled pending trusted-capture migration)
  bounty proxy flows <bundle> [--limit <n>] [--json]  (disabled pending trusted-capture migration)
  bounty proxy to-authz <bundle> --owner-role <id> [--json]  (disabled pending trusted-capture migration)

Proxy capture (design spec section 8):
  Live forwarding is disabled and no loadable mitmproxy addon ships. A URL-only
  bounty perimeter cannot approve an arbitrary browser method/body. A future
  proxy must consume an exact controller-issued prepared-request lease
  and prove process-level startup/termination behavior before it may listen.

  The pure Python fixture helper, scope kernel, and JSONL ingestion remain for
  offline conformance and historical captures; none is an active capture path.

  proxy to-authz feeds captured traffic into the grinder and skips anything the
  perimeter blocked: a blocked request is evidence about the perimeter, not
  something to replay.

Scanner (design spec section 10):
  The public live scan command is disabled. It must be wired to an exact operator
  authorization receipt, controller-attested target identity, and qualified action
  ledger before it can send crafted probes. A literal loopback URL is not proof
  that a service is disposable; it may be a tunnel or port-forward to production.

  Deliberately narrow. No mass XSS or SQLi fuzzing and no CVE template sweep --
  nuclei does breadth better, and breadth on a picked-over program is a
  duplicate-and-N/A factory. Depth on a few classes with a real oracle pays.

  Classes:
    error-injection  probes that provoke a parser error, judged against an
                     INERT CONTROL payload. If the control also changes the
                     response the endpoint reacts to any input and the result
                     is UNPROVEN_VOLATILE, not a finding.
    ssrf-oob         only for insertion points whose name or value shape says
                     they carry a URL. Mints a correlated OOB host, so a
                     callback names the exact parameter that fetched it.
    passive          reads responses already collected. Secrets are matched on
                     high-confidence shapes only and NEVER recorded verbatim.

  Requires active_testing in the sealed permissions, because this sends
  crafted payloads. Absence of a callback is inconclusive, never a clearance.

Report drafting (design spec section 14):
  Turns reportable findings into YesWeHack-shaped markdown with a runnable
  repro. Credentials appear as shell variable references, never values -- a
  report is a document you hand to someone else.

  Only AUTHZ_BYPASS_CANDIDATE is drafted. UNPROVEN_VOLATILE, ACCESS_DENIED,
  NOT_FOUND, DIFFERENT_CONTENT, SERVER_ERROR and ABSENT_PROBE are declined
  with a stated reason, because submitting those is how a researcher destroys
  the signal that earns private invites.

  Severity is a SUGGESTION with a stated rationale per metric, never an
  assertion. Nothing is submitted automatically.

Authorization grinder (design spec section 9):
  Import and historical-status/report functions remain available, but the public
  live replay command is disabled. It must be migrated to an exact operator
  authorization receipt and canonical prepared-request gate before it can
  contact a target again. A legacy sealed-scope permission is not action authorization.

  The internal test harness models replaying captured requests as other roles and
  unauthenticated. Import a HAR straight from Chrome DevTools (Network, then
  Export HAR) -- no proxy needed.

  Each request is first replayed TWICE as its owning role to establish a noise
  floor. Differences between two identical-role runs are volatile by definition,
  so only differences beyond that floor mean anything. If the two baseline runs
  disagree, the endpoint is volatile and every comparison for it is reported
  UNPROVEN_VOLATILE rather than guessed at.

  Verdicts: AUTHZ_BYPASS_CANDIDATE, UNPROVEN_VOLATILE, ACCESS_DENIED, NOT_FOUND,
  DIFFERENT_CONTENT, SERVER_ERROR, REPLAY_FAILED. The strongest is a CANDIDATE
  needing human proof; nothing here asserts a vulnerability, and a denial is
  never a clearance. DIFFERENT_CONTENT is not a finding: on /api/me another role
  correctly sees its own data.

  Role credentials are read from environment variables named in the registry and
  are never stored in it, so a registry is safe to commit. A missing variable is
  a hard error rather than a silent unauthenticated replay.

  --identifiers adds horizontal IDOR testing. You declare object ids and which of
  YOUR OWN roles owns each, and the grinder substitutes same-kind ids between
  them: swap your second account's order id into your first account's request and
  see whose order comes back. This reaches bugs role replay structurally cannot --
  proving alice can read bob's object needs bob's id in alice's request.

  A mutated request is baselined against the id's OWN owner, since after
  substitution it targets a different object and only that object's owner defines
  a correct response.

  There is no range, wildcard, or increment form, and there never will be:
  enumerating undeclared ids means reading a stranger's data to prove a bug. That
  is out of bounds on every program and makes a weaker report than "I accessed my
  own second account's object". Mark an id "absent": true to compare its status
  against the not-yours status -- a difference between them is an enumeration
  oracle.

Recon (design spec section 11):
  Public recon execution is disabled before bundle or target access. The legacy
  controller trusted a mutable scope.json without binding bundle.json, resolved
  DNS after its lexical scope check, and lacked uniform byte/rate/redirect/stop
  enforcement across every socket. Re-enable only through a trusted current-scope
  lease and a public-address-pinned bounded transport.

  Request pacing comes from the sealed rate_limit_rps and cannot be overridden
  by a flag: the program's stated limit is the authorization, not a setting.

  Sources:
    tls    peer certificate SANs. No third party involved. The primary source.
    ctlog  crt.sh certificate transparency search. High yield when reachable and
           frequently returns 502; failure is recorded as a gap, never hidden.

  Wildcard SANs are recorded as zone hints and never probed -- a wildcard proves
  a zone exists but names no host. Redirects are recorded, never followed; the
  target becomes a new candidate that must pass the gate on its own.

  Inventory status is OBSERVED or PARTIAL. There is no COMPLETE: any source that
  failed leaves a gap, and gaps force PARTIAL permanently, so a large haul never
  launders an incomplete sweep into a clean one.

Out-of-band interaction (design spec section 17):
  Blind SSRF, blind XXE, blind RCE, out-of-band SQLi and most blind SSTI are
  invisible without a callback channel. Every minted payload carries a nonce, so
  a callback names the exact request, parameter, and role that produced it.

  Every public OOB session command is disabled. The retained self-hosted and
  hosted kernels are internal conformance surfaces until a controller-owned
  local session root, atomic backend check/effect, exact action authorization, and
  enrolled transport exist. A caller-selected bundle path is not a safe place
  to generate session secrets, and a hosted allowlist is not disclosure authority.

  An absent callback is NO_INTERACTION_OBSERVED. A blind vector that produced no
  interaction is inconclusive and is never proof that a target is sound.

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
  process.stdout.write(
    asJson
      ? `${terminalSafeJson(payload)}\n`
      : `${terminalSafeText(payload.summary)}\n`,
  )
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
    requiredUserAgent: requireOption(options, 'user-agent'),
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

async function commandOob(positionals, options) {
  const action = positionals[1]
  if (['open', 'mint', 'poll', 'status', 'close'].includes(action)) {
    const error = new Error(
      `OOB ${action} is disabled before bundle, session, secret, or network access pending a controller-owned local session root and atomic authenticated backend/transport lease`,
    )
    error.code = 'BOUNTY_OOB_SESSION_ENROLLMENT_REQUIRED'
    throw error
  }
  throw new Error(`unknown oob action: ${action ?? '(none)'}`)
}

async function commandRecon(positionals, options) {
  const action = positionals[1]
  const bundle = positionals[2]
  const asJson = options.json === true
  if (action === 'run') {
    const error = new Error(
      'recon run is disabled before bundle or target access pending trusted current-scope binding, DNS pinning, and uniform transport bounds',
    )
    error.code = 'BOUNTY_RECON_LIVE_IO_DISABLED'
    throw error
  }
  if (action === 'status') {
    const status = await reconStatus({ bundlePath: bundle })
    emit({
      command: 'recon status',
      ...status,
      summary: `${status.status} hosts=${status.hosts} zoneHints=${status.zoneHints} refused=${status.refused} gaps=${status.gaps}${
        status.gaps > 0 ? ` [${status.gapDetail.map((g) => `${g.source}:${g.reason}`).join(', ')}]` : ''
      }`,
    }, asJson)
    return 0
  }
  throw new Error(`unknown recon action: ${action ?? '(none)'}`)
}

async function commandAuthz(positionals, options) {
  const action = positionals[1]
  const bundle = positionals[2]
  const asJson = options.json === true
  if (action === 'import') {
    const result = await importAuthzRequests({
      bundlePath: bundle,
      harPath: requireOption(options, 'har'),
      ownerRole: requireOption(options, 'owner-role'),
    })
    emit({
      command: 'authz import',
      ...result,
      summary: `IMPORTED ${result.imported} unique requests from ${result.rawEntries} entries (${result.skipped.length} skipped)`,
    }, asJson)
    return 0
  }
  if (action === 'run') {
    throw new Error(
      'authz run is disabled before target I/O until it is migrated to an exact operator authorization receipt and canonical prepared-request gate',
    )
  }
  if (action === 'status') {
    const status = await authzStatus({ bundlePath: bundle })
    const detail = status.candidateDetail.length > 0
      ? `\n  ${status.candidateDetail.join('\n  ')}`
      : ''
    emit({
      command: 'authz status',
      ...status,
      summary: `candidates=${status.candidates} unproven=${status.unproven}${detail}`,
    }, asJson)
    return 0
  }
  throw new Error(`unknown authz action: ${action ?? '(none)'}`)
}

async function commandReport(positionals, options) {
  const action = positionals[1]
  const bundle = positionals[2]
  const asJson = options.json === true
  if (action === 'draft') {
    const registry = await loadRoleRegistry(requireOption(options, 'roles'))
    const result = await draftAuthzReports({
      bundlePath: bundle,
      registry,
      now: new Date(),
      ...(typeof options.out === 'string' ? { outDir: options.out } : {}),
    })
    const declinedNote = result.declined.length === 0
      ? ''
      : ` (${result.declined.length} findings declined as unreportable)`
    emit({
      command: 'report draft',
      ...result,
      summary: `${result.status} drafted=${result.drafted}${declinedNote} authorization=${result.authorization}`,
    }, asJson)
    return 0
  }
  throw new Error(`unknown report action: ${action ?? '(none)'}`)
}

async function commandScan(positionals, options) {
  const action = positionals[1]
  const bundle = positionals[2]
  const asJson = options.json === true
  if (action === 'run') {
    throw new Error(
      'scan run is disabled before target I/O until it is wired to an exact operator authorization receipt, controller-attested target identity, and qualified action ledger',
    )
  }
  if (action === 'status') {
    const status = await scanStatus({ bundlePath: bundle })
    const indent = '\n  '
    const detail = status.candidateDetail.length > 0
      ? `${indent}${status.candidateDetail.join(indent)}`
      : ''
    emit({
      command: 'scan status',
      ...status,
      summary: `candidates=${status.candidates} unproven=${status.unproven}${detail}`,
    }, asJson)
    return 0
  }
  throw new Error(`unknown scan action: ${action ?? '(none)'}`)
}

async function commandProxy(positionals, options) {
  const action = positionals[1]
  if (['ingest', 'flows', 'to-authz'].includes(action)) {
    const error = new Error(
      `proxy ${action} is disabled before bundle or capture access pending bounded no-follow ingestion, structured queries, terminal-safe rendering, and trusted capture provenance`,
    )
    error.code = 'BOUNTY_PROXY_CAPTURE_DISABLED'
    throw error
  }
  throw new Error(`unknown proxy action: ${action ?? '(none)'}`)
}

export async function runBountyCli(argv) {
  const { positionals, options } = parseArguments(argv)
  const command = positionals[0]
  if (options.help === true || command === undefined) {
    process.stdout.write(HELP)
    return 0
  }
  try {
    assertLocalFilesystemEndpoint(process.cwd(), 'working directory')
    assertNoRemoteFilesystemArguments(argv)
    if (command === 'plan') return await commandPlan(options)
    if (command === 'oob') return await commandOob(positionals, options)
    if (command === 'recon') return await commandRecon(positionals, options)
    if (command === 'authz') return await commandAuthz(positionals, options)
    if (command === 'report') return await commandReport(positionals, options)
    if (command === 'scan') return await commandScan(positionals, options)
    if (command === 'proxy') return await commandProxy(positionals, options)
    if (command === 'validate') {
      const result = await validateBountyBundle(positionals[1])
      // Currency is reported, not enforced: an expired bundle must stay readable
      // so past evidence can be inspected. Enforcement lives on the commands
      // that contact a target.
      emit({
        command: 'validate',
        status: result.status,
        currency: result.currency,
        ...(result.preMandate ? { sealed_before_user_agent_mandate: true } : {}),
        // Reported the same way a lapsed window is: the bundle opens, and the
        // line says which commands will refuse until it is resealed.
        summary: `VALID ${positionals[1]} authorization=${result.currency.status}${
          result.currency.status === 'CURRENT'
            ? ''
            : ` (window ${result.currency.notBefore} to ${result.currency.notAfter}) -- recon and authz will refuse to run`
        }${
          result.preMandate
            ? ' -- sealed before the program user-agent mandate: recon, authz and the proxy will refuse every request until you reseal with --user-agent'
            : ''
        }`,
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
    process.stderr.write(`unknown command: ${terminalSafeText(command)}\n\n${HELP}`)
    return 1
  } catch (error) {
    process.stderr.write(`bounty: ${terminalSafeText(error.message)}\n`)
    return 1
  }
}

if (isMainModule(import.meta.url)) {
  process.exitCode = await runBountyCli(process.argv.slice(2))
}
