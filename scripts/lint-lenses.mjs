import { existsSync, readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'
import { parseLens } from './lib/frontmatter.mjs'
import { isMainModule } from './lib/main-module.mjs'
import { buildRegistry, diffRegistry, checkShapes, checkDetectors, checkBodyClaims, checkEvidenceClasses, detectorCoverage } from './lib/registry.mjs'
import { checkOrthography } from './lib/orthography.mjs'
import { parseLedger } from './lib/ledger.mjs'
import { checkSkill, MAX_SKILL_BYTES } from './lib/skill.mjs'

const DEFAULTS = {
  lensDir: 'skills/red-team-audit/lenses',
  topicsFile: 'skills/red-team-audit/lenses/_topics.md',
  ledgerFile: 'docs/migration-ledger.tsv',
  skillFile: 'skills/red-team-audit/SKILL.md',
}

// Underscore-prefixed files are contracts and generated artifacts, not lenses.
// _topics.md living inside the lens directory is exactly why this filter exists.
// A missing lens directory is a violation, not a crash — CI must be able to
// report "no lenses found" instead of dying with a stack trace.
function loadLenses(lensDir, violations) {
  if (!existsSync(lensDir)) {
    violations.push({ rule: 'FATAL', slug: null, lenses: [], message: `lens directory not found: ${lensDir}` })
    return []
  }
  return readdirSync(lensDir)
    .filter((f) => f.endsWith('.md') && !f.startsWith('_'))
    .sort()
    .map((f) => parseLens(readFileSync(join(lensDir, f), 'utf8'), f))
}

export function parseTopicsFile(text) {
  const committed = new Map()
  let owner = null
  for (const line of text.split(/\r?\n/)) {
    const heading = /^##\s+(\S+)\s*$/.exec(line)
    if (heading) { owner = heading[1]; continue }
    const item = /^[-*]\s+(\S+)\s*$/.exec(line)
    if (item && owner) committed.set(item[1], owner)
  }
  return committed
}

function readTopics(topicsFile, violations) {
  if (!existsSync(topicsFile)) {
    violations.push({ rule: 'FATAL', slug: null, lenses: [], message: `topics file not found: ${topicsFile}` })
    return new Map()
  }
  return parseTopicsFile(readFileSync(topicsFile, 'utf8'))
}

function readLedgerViolations(ledgerFile) {
  if (!existsSync(ledgerFile)) {
    return [{ rule: 'LEDGER', slug: null, lenses: [], message: `migration ledger file not found: ${ledgerFile}` }]
  }
  return parseLedger(readFileSync(ledgerFile, 'utf8')).violations
}

// The skill entry point is not a lens, so nothing above reads it. A missing file
// is a violation rather than a crash, for the same reason a missing lens directory
// is: CI must report it, not die on it.
function readSkill(skillFile, violations) {
  if (!existsSync(skillFile)) {
    violations.push({ rule: 'SKILL', slug: null, lenses: [], message: `skill file not found: ${skillFile}` })
    return { bytes: 0 }
  }
  const { violations: skillViolations, bytes } = checkSkill(readFileSync(skillFile, 'utf8'), skillFile)
  violations.push(...skillViolations)
  return { bytes }
}

export function runLint(opts = {}) {
  const { lensDir, topicsFile, ledgerFile, skillFile } = { ...DEFAULTS, ...opts }
  const violations = []
  const lenses = loadLenses(lensDir, violations)

  for (const l of lenses) {
    for (const message of l.errors) violations.push({ rule: 'PARSE', slug: null, lenses: [l.name], message })
  }

  const { slugs, violations: registryViolations } = buildRegistry(lenses)
  violations.push(...registryViolations)
  violations.push(...checkShapes(lenses))
  violations.push(...checkDetectors(lenses))
  violations.push(...checkBodyClaims(lenses, slugs))
  violations.push(...checkEvidenceClasses(lenses))
  violations.push(...checkOrthography([...slugs.keys()]))

  const committed = readTopics(topicsFile, violations)
  violations.push(...diffRegistry(slugs, committed))
  violations.push(...readLedgerViolations(ledgerFile))
  const skill = readSkill(skillFile, violations)

  // Observations never gate the build: R7 (checkDetectors) can be satisfied by
  // one trivial example while a Checklist's other search instructions stay
  // undemonstrated. detectorCoverage reports the literal-vs-detector ratio per
  // lens so that gap is visible to a reviewer without failing CI on a heuristic.
  const observations = detectorCoverage(lenses)

  return { violations, observations, counts: { lenses: lenses.length, slugs: slugs.size, skillBytes: skill.bytes } }
}

if (isMainModule(import.meta.url)) {
  const { violations, observations, counts } = runLint()
  const byRule = violations.reduce((acc, v) => ((acc[v.rule] = (acc[v.rule] ?? 0) + 1), acc), {})

  for (const v of violations) console.error(`[${v.rule}] ${v.message}`)

  console.log(`\n${counts.lenses} lenses, ${counts.slugs} slugs owned.`)
  console.log(`SKILL.md: ${counts.skillBytes} bytes of the ${MAX_SKILL_BYTES}-byte budget (${MAX_SKILL_BYTES - counts.skillBytes} to spare).`)

  console.log('\n--- Detector coverage (observation only — never affects the exit code) ---')
  if (observations.length) {
    for (const o of observations) {
      console.log(`  [OBSERVATION] ${o.lens}: ${o.detectors} detector(s) demonstrating ${o.literals} distinct literal(s) named in its Checklist`)
    }
  } else {
    console.log('  (no lenses with a Checklist section)')
  }

  if (violations.length) {
    console.error(`\nFAIL: ${violations.length} violation(s) — ${JSON.stringify(byRule)}`)
    process.exit(1)
  }
  console.log('\nPASS: R1-R9, SKILL and ledger gate clean.')
}
