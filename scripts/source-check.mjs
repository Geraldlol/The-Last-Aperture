// Standalone passive checker. Do not load the campaign runtime or target modules.
import { isAbsolute } from 'node:path'
import { checkJavaScriptSource, SOURCE_CHECK_VERSION } from './lib/source-check.mjs'
import { readSourceCheckInputs } from './lib/source-check-input.mjs'
import { assertNoRemoteFilesystemArguments } from './lib/filesystem-endpoint.mjs'
import { compareCanonicalStrings } from './lib/canonical-order.mjs'
import { isMainModule } from './lib/main-module.mjs'
import { terminalSafeText } from './lib/terminal-text.mjs'

const USAGE = 'node scripts/source-check.mjs --root <absolute-local-directory> --file <relative.js> [--file <relative.js> ...] [--json]'

export function parseSourceCheckArguments(args) {
  if (!Array.isArray(args) || args.length > 203 || args.some((arg) => typeof arg !== 'string' || arg.length > 4096)) {
    throw new Error('invalid source-check arguments')
  }
  assertNoRemoteFilesystemArguments(args)
  let root
  let json = false
  const files = []
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]
    if (arg === '--json' && !json) json = true
    else if (arg === '--root' && root === undefined && args[index + 1] && !args[index + 1].startsWith('--')) {
      root = args[++index]
    } else if (arg === '--file' && args[index + 1] && !args[index + 1].startsWith('--')) {
      files.push(args[++index])
    } else throw new Error('invalid source-check arguments')
  }
  if (!root || !isAbsolute(root) || files.length === 0) throw new Error('explicit source-check scope required')
  return { root, files, json }
}

export async function inspectSourcePatterns({ root, files }) {
  const inputs = await readSourceCheckInputs({ root, files })
  const results = inputs.map((input) => input.gap ? {
    path: input.path, source_sha256: null, status: 'NOT_ASSESSED', observations: [], gaps: [input.gap],
  } : checkJavaScriptSource(input)).sort((left, right) => compareCanonicalStrings(left.path, right.path))
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/source-check',
    checker: { name: 'builtin-node-tls-patterns', version: SOURCE_CHECK_VERSION },
    analysis_status: 'NARROW_STATIC_CHECK',
    security_verdict: 'NOT_ASSESSED',
    target_execution: 'NOT_PERFORMED',
    applied_to_audit_bundle: false,
    counts: {
      requested_files: results.length,
      checked_files: results.filter((file) => file.status === 'CHECKED').length,
      partial_files: results.filter((file) => file.status === 'PARTIAL').length,
      not_assessed_files: results.filter((file) => file.status === 'NOT_ASSESSED').length,
      observations: results.reduce((total, file) => total + file.observations.length, 0),
      gaps: results.reduce((total, file) => total + file.gaps.length, 0),
    },
    files: results,
    limitations: [
      'Only two literal Node TLS configuration patterns are checked in the explicitly requested JavaScript files.',
      'CHECKED means these narrow syntax checks completed, not that a file or repository is secure. Runtime reachability and exploitability are not assessed.',
      'No target imports, execution, dependency resolution, network requests, patches, retests, or audit-bundle mutations are performed.',
      'Repair guidance is a review requirement, not an applied change or independently verified fix.',
      'File checks assume a stable local checkout. They are not an OS sandbox or a repository-wide atomic snapshot; remotely mounted filesystems cannot be identified reliably.',
      'Relative paths and content digests are metadata to review before sharing. Source text and parser diagnostics are omitted.',
    ],
  }
}

export function sourceCheckExitCode(report) {
  if (report.counts.gaps > 0) return 3
  return report.counts.observations > 0 ? 2 : 0
}

export function renderSourceCheck(report) {
  const lines = [
    'Passive source checks: Node TLS configuration',
    `Security verdict: ${report.security_verdict}; target execution: ${report.target_execution}`,
    `Files: ${report.counts.requested_files}; observations: ${report.counts.observations}; gaps: ${report.counts.gaps}`, '',
  ]
  for (const file of report.files) {
    lines.push(`${file.status} ${terminalSafeText(file.path)}`)
    for (const observation of file.observations) {
      lines.push(`  ${observation.line}:${observation.column} ${observation.rule_id} [${observation.verification}]`,
        `  ${observation.message}`, `  Review change: ${observation.repair.recommendation}`)
      for (const check of observation.repair.acceptance_checks) lines.push(`  Acceptance requirement: ${check}`)
    }
    for (const gap of file.gaps) lines.push(`  Gap ${gap.code}: ${gap.message}`)
  }
  lines.push('', ...report.limitations, '')
  return lines.join('\n')
}

export async function main(args = process.argv.slice(2)) {
  const options = parseSourceCheckArguments(args)
  const report = await inspectSourcePatterns(options)
  process.stdout.write(options.json ? `${JSON.stringify(report, null, 2)}\n` : renderSourceCheck(report))
  return sourceCheckExitCode(report)
}

if (isMainModule(import.meta.url)) {
  main().then((code) => { process.exitCode = code }).catch(() => {
    // Never echo an untrusted path, parser diagnostic, or source excerpt.
    process.stderr.write(`ERROR: source-check could not inspect the requested scope. Check local paths, permissions, and limits.\nUsage: ${USAGE}\n`)
    process.exitCode = 1
  })
}
