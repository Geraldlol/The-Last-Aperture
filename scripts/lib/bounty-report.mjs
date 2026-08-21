import { assertNoSecretLeak, buildReproCurl, reproPreamble } from './bounty-report-curl.mjs'
import { suggestAuthzVector } from './bounty-report-cvss.mjs'

// Only these verdicts justify a submission. Everything else the grinder produces
// is either correct behaviour or an unproven observation, and submitting those
// is how a researcher's signal-to-noise -- the thing that earns private invites --
// gets destroyed.
export const REPORTABLE_VERDICTS = Object.freeze(['AUTHZ_BYPASS_CANDIDATE'])

export const UNREPORTABLE_REASONS = Object.freeze({
  UNPROVEN_VOLATILE: 'the endpoint was not reproducible, so the comparison cannot support a claim',
  ACCESS_DENIED: 'the request was correctly refused for this role',
  NOT_FOUND: 'a 404 is ambiguous and proves nothing on its own',
  DIFFERENT_CONTENT: 'the role received its own data, which is correct behaviour',
  SERVER_ERROR: 'a 5xx is worth investigating but is not itself an authorization finding',
  REPLAY_FAILED: 'the replay did not complete, so nothing was observed',
  ABSENT_PROBE: 'a status observation for a declared-absent object, not a finding on its own',
})

export function isReportable(result) {
  return REPORTABLE_VERDICTS.includes(result.verdict)
}

export function explainUnreportable(result) {
  return UNREPORTABLE_REASONS[result.verdict] ?? 'not a reportable verdict'
}

function titleFor(result) {
  const path = (() => {
    try {
      return new URL(result.url).pathname
    } catch {
      return result.url
    }
  })()
  const actor = result.tester_role === 'anonymous'
    ? 'Unauthenticated access'
    : `Cross-account access as ${result.tester_role}`
  const via = result.mutation === undefined
    ? ''
    : ' via object identifier substitution'
  return `${actor} to ${result.owner_role}'s data at ${path}${via}`
}

function evidenceTable(result) {
  const rows = [
    ['Endpoint', `\`${result.method} ${result.url}\``],
    ['Baseline account', `\`${result.owner_role}\``],
    ['Requested as', `\`${result.tester_role}\``],
    ['Owner response', `\`${result.owner_status}\``],
    ['Tester response', `\`${result.tester_status}\``],
    ['Baseline reproducible', result.baseline_stable ? 'yes' : 'no'],
  ]
  if (result.mutation !== undefined) {
    rows.push(['Identifier substitution', `\`${result.mutation}\``])
  }
  return [
    '| | |',
    '|---|---|',
    ...rows.map(([key, value]) => `| ${key} | ${value} |`),
  ].join('\n')
}

export function renderAuthzReport({ result, scope, ownerRole, testerRole, request, generatedAt }) {
  if (!isReportable(result)) {
    throw new Error(
      `refusing to draft a report for ${result.verdict}: ${explainUnreportable(result)}`,
    )
  }
  const severity = suggestAuthzVector({
    testerRole: result.tester_role,
    method: result.method,
    ownerStatus: result.owner_status,
  })

  const preamble = reproPreamble([ownerRole, testerRole].filter(Boolean))
  const ownerCurl = buildReproCurl({ request, role: ownerRole })
  const testerCurl = buildReproCurl({ request, role: testerRole })

  const sections = [
    `# ${titleFor(result)}`,
    '',
    `**Severity (suggested):** ${severity.band} ${severity.score} — \`${severity.vector}\``,
    '',
    '> This severity is a suggestion derived from the observed evidence and has not',
    '> been reviewed. Confirm it before submitting; you are the one signing it.',
    '',
    '## Summary',
    '',
    // Describes what was measured rather than asserting ownership semantics the
    // tool cannot know. The grinder observed response equivalence; whether the
    // endpoint is object-scoped or a collection is not something it can tell, and
    // "returns alice's data" reads wrong on an admin user list.
    result.tester_role === 'anonymous'
      ? `An unauthenticated request to \`${result.method} ${result.url}\` returns the same response as the authenticated account \`${result.owner_role}\`. No credential is required to obtain it.`
      : `An authenticated request as \`${result.tester_role}\` returns the same response as \`${result.owner_role}\`, an account it has no entitlement to act for.`,
    '',
    '## Impact',
    '',
    result.tester_role === 'anonymous'
      ? 'Any caller on the internet obtains data that the application only serves to an authenticated session. Review the response body to confirm the sensitivity and breadth of what is exposed — if it is a collection rather than a single object, the exposure is correspondingly wider.'
      : 'Any authenticated user obtains data scoped to a different account at this endpoint. Account creation is typically self-service, so the practical population of attackers is anyone willing to register. Review the response body to confirm the breadth of what is reachable.',
    '',
    '## Evidence',
    '',
    evidenceTable(result),
    '',
    `The tester's response was byte-equivalent to the owner's after normalisation of volatile content (timestamps, request identifiers, CSRF tokens). Equivalence was only accepted as meaningful because the owner's own response was **reproducible across two consecutive requests** — an endpoint whose output varies between identical requests is reported as unproven rather than as a finding.`,
    '',
    `Basis recorded by the grinder: ${result.rationale}`,
    '',
    '## Steps to reproduce',
    '',
    ...(preamble === null ? [] : ['```bash', preamble, '```', '']),
    `**1. As the owner (\`${result.owner_role}\`), confirm the object and its content:**`,
    '',
    '```bash',
    ownerCurl,
    '```',
    '',
    `**2. As \`${result.tester_role}\`, issue the same request:**`,
    '',
    '```bash',
    testerCurl,
    '```',
    '',
    `**3.** The second response returns \`${result.tester_status}\` with the owner's data. Expected behaviour is \`403\`.`,
    '',
    '## Suggested severity rationale',
    '',
    ...severity.rationale.map((line) => `- ${line}`),
    ...(severity.caveats.length === 0
      ? []
      : ['', '**Caveats:**', ...severity.caveats.map((line) => `- ${line}`)]),
    '',
    '## Remediation',
    '',
    'Enforce an ownership or entitlement check on this endpoint server-side, deriving the acting principal from the session rather than from any client-supplied identifier. Apply it before the object is loaded, and return the same status for "does not exist" and "not yours" so the endpoint does not double as an existence oracle.',
    '',
    '## Testing scope and authorisation',
    '',
    `Testing was performed under the ${scope.platform} program \`${scope.program.program_handle}\`, against the sealed perimeter recorded in this engagement (\`${scope.engagement_id}\`). Program policy digest: \`${scope.program.policy_snapshot_sha256}\`. Authorisation window: ${scope.validity.not_before} to ${scope.validity.not_after}.`,
    '',
    'All accounts used are researcher-controlled test accounts. No third-party user data was accessed.',
    '',
    '---',
    '',
    `Drafted ${generatedAt} by red-team-audit bounty-v1. Not submitted automatically; review before sending.`,
  ]

  return sections.join('\n')
}
