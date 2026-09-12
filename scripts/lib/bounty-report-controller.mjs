import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { assertNoSecretLeak } from './bounty-report-curl.mjs'
import { explainUnreportable, isReportable, renderAuthzReport } from './bounty-report.mjs'
import { ANONYMOUS_ROLE, findRole } from './bounty-authz-roles.mjs'
import { describeScopeCurrency } from './bounty-contracts.mjs'
import { sanitizeCapturedRequest } from './bounty-authz-request.mjs'

const SCOPE_FILE = 'scope.json'
const FINDINGS_FILE = 'authz-findings.json'
const REQUESTS_FILE = 'authz-requests.json'
const REPORTS_DIR = 'reports'

function slugFor(result, index) {
  const path = (() => {
    try {
      return new URL(result.url).pathname
    } catch {
      return 'endpoint'
    }
  })()
  const cleaned = path.replace(/[^a-zA-Z0-9]+/g, '-').replace(/^-|-$/g, '').toLowerCase()
  const role = String(result.tester_role ?? 'unknown')
    .replace(/[^a-zA-Z0-9]+/g, '-')
    .replace(/^-|-$/g, '')
    .toLowerCase()
  return `${String(index + 1).padStart(2, '0')}-${role || 'unknown'}-${cleaned || 'endpoint'}`.slice(0, 96)
}

function roleOrAnonymous(registry, roleId) {
  if (roleId === ANONYMOUS_ROLE.id) return ANONYMOUS_ROLE
  try {
    return findRole(registry, roleId)
  } catch {
    return null
  }
}

// Matches a finding back to the captured request it came from, so the repro shows
// the actual request rather than one reconstructed from a url.
function matchRequest(requests, result) {
  const byId = requests.find((request) => request.request_id === result.request_id)
  if (byId !== undefined && result.mutation === undefined) return byId
  // A mutated finding's url is the substituted one, which is what should be
  // reproduced; carry the original's method, headers and body.
  const base = byId ?? requests.find((request) => request.url === result.url)
  if (base === undefined) {
    return { method: result.method, url: result.url, headers: {}, body: null }
  }
  return { ...base, url: result.url, method: result.method }
}

export async function draftAuthzReports({
  bundlePath,
  registry,
  now,
  env = process.env,
  outDir = REPORTS_DIR,
}) {
  const scope = JSON.parse(await readFile(join(bundlePath, SCOPE_FILE), 'utf8'))
  const findings = JSON.parse(await readFile(join(bundlePath, FINDINGS_FILE), 'utf8'))
  let requests = []
  try {
    const stored = JSON.parse(await readFile(join(bundlePath, REQUESTS_FILE), 'utf8'))
    if (!Array.isArray(stored.requests)) throw new Error('authz request bundle must contain a request array')
    requests = stored.requests.map((request) => sanitizeCapturedRequest(request))
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }

  // Every credential value the registry can resolve, so the leak check has
  // something concrete to look for rather than trusting the renderer.
  const secrets = []
  for (const role of registry.roles) {
    if (role.auth?.kind === 'none') continue
    const value = env[role.auth?.value_env]
    if (typeof value === 'string' && value.length > 0) secrets.push(value)
  }

  const safeResults = findings.results.map((result) => ({
    ...result,
    url: sanitizeCapturedRequest({
      method: result.method,
      url: result.url,
      headers: {},
      body: null,
    }).url,
  }))
  const reportable = safeResults.filter(isReportable)
  const declined = safeResults
    .filter((result) => !isReportable(result))
    .map((result) => ({ url: result.url, verdict: result.verdict, why: explainUnreportable(result) }))

  const directory = join(bundlePath, outDir)
  if (reportable.length > 0) await mkdir(directory, { recursive: true })

  const written = []
  for (const [index, result] of reportable.entries()) {
    const ownerRole = roleOrAnonymous(registry, result.owner_role)
    const testerRole = roleOrAnonymous(registry, result.tester_role)
    const markdown = renderAuthzReport({
      result,
      scope,
      ownerRole,
      testerRole,
      request: matchRequest(requests, result),
      generatedAt: now.toISOString(),
    })
    // Last gate before anything is written to disk.
    assertNoSecretLeak(markdown, secrets)
    const file = join(directory, `${slugFor(result, index)}.md`)
    await writeFile(file, `${markdown}\n`, 'utf8')
    written.push({ file, url: result.url, testerRole: result.tester_role })
  }

  return {
    drafted: written.length,
    declined,
    files: written,
    // Reported so a stale bundle cannot be mistaken for a live one at submission
    // time; a report drafted under a lapsed grant is worth knowing about.
    authorization: describeScopeCurrency({ scope, now }).status,
    status: written.length === 0 ? 'NO_REPORTABLE_FINDINGS' : 'DRAFTED_PENDING_REVIEW',
  }
}
