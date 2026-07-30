import { existsSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { isAbsolute, relative, resolve } from 'node:path'
import { isMainModule } from './lib/main-module.mjs'

const MANIFEST = 'fixtures/EXPECTED.md'
const OWNERSHIP = 'fixtures/OWNERSHIP.tsv'
const OUTPUT = 'benchmarks/cases.json'

function cells(line) {
  return line
    .slice(1, line.lastIndexOf('|'))
    .split('|')
    .map((cell) => cell.trim())
}

function unquoteCode(value) {
  return value.replace(/^`|`$/g, '')
}

function parseOwnership(value, caseId) {
  const tokens = [...value.matchAll(/`([^`]+)`/g)].map((match) => match[1])
  if (tokens.length < 2) {
    throw new Error(`${caseId} has no owning lens/topic pair`)
  }
  return {
    lens: tokens[0],
    topic: tokens[1],
    also_acceptable_topics: tokens.slice(2),
  }
}

function parseSeverity(value, caseId) {
  const severities = [...value.matchAll(/\b(Critical|High|Medium|Low)\b/g)]
    .map((match) => match[1])
  if (severities.length === 0) {
    throw new Error(`${caseId} has no benchmark severity`)
  }
  return severities[0]
}

function parseOwnershipManifest(ownership) {
  const selectorsById = new Map()
  for (const [index, line] of ownership.split(/\r?\n/).entries()) {
    if (!line || line.startsWith('#')) continue
    const fields = line.split('\t')
    if (fields.length < 2 || fields.length > 3) {
      throw new Error(`OWNERSHIP.tsv:${index + 1} has an invalid column count`)
    }
    const ids = [
      fields[0],
      ...(fields[2] ?? '').split(',').map((value) => value.trim()).filter(Boolean),
    ]
    for (const id of ids) {
      if (!/^[VC]-\d{3}$/.test(id)) {
        throw new Error(`OWNERSHIP.tsv:${index + 1} has invalid case ID ${id}`)
      }
      const selectors = selectorsById.get(id) ?? []
      selectors.push(fields[1])
      selectorsById.set(id, selectors)
    }
  }
  for (const [id, selectors] of selectorsById) {
    selectorsById.set(id, [...new Set(selectors)].sort())
  }
  return selectorsById
}

export function extractBenchmarkCases(manifest, ownership) {
  if (typeof ownership !== 'string' || !ownership.trim()) {
    throw new Error('fixture ownership manifest is required')
  }
  const selectorsById = parseOwnershipManifest(ownership)
  const cases = []
  for (const line of manifest.split(/\r?\n/)) {
    if (/^\|\s*V-\d{3}\s*\|/.test(line)) {
      const row = cells(line)
      const owner = parseOwnership(row[6], row[0])
      const fixtureSelectors = selectorsById.get(row[0])
      if (!fixtureSelectors?.length) {
        throw new Error(`${row[0]} has no fixture ownership selector`)
      }
      cases.push({
        case_id: row[0],
        expectation: 'vulnerable',
        topic: owner.topic,
        expected_severity: parseSeverity(row[4], row[0]),
        fixture_selectors: fixtureSelectors,
        manifest_fixture_label: unquoteCode(row[1]),
        lens: owner.lens,
        ...(owner.also_acceptable_topics.length > 0
          ? { also_acceptable_topics: owner.also_acceptable_topics }
          : {}),
        description: row[3],
      })
    } else if (/^\|\s*C-\d{3}\s*\|/.test(line)) {
      const row = cells(line)
      const fixtureSelectors = selectorsById.get(row[0])
      if (!fixtureSelectors?.length) {
        throw new Error(`${row[0]} has no fixture ownership selector`)
      }
      cases.push({
        case_id: row[0],
        expectation: 'clean',
        topic: 'clean-canary',
        fixture_selectors: fixtureSelectors,
        manifest_fixture_label: unquoteCode(row[1]),
        description: row[3],
      })
    }
  }

  cases.sort((left, right) => left.case_id.localeCompare(right.case_id, 'en'))
  const ids = cases.map(({ case_id }) => case_id)
  if (new Set(ids).size !== ids.length) throw new Error('benchmark manifest contains duplicate case IDs')
  const vulnerable = cases.filter(({ expectation }) => expectation === 'vulnerable')
  const clean = cases.filter(({ expectation }) => expectation === 'clean')
  if (vulnerable.length !== 22 || clean.length !== 42) {
    throw new Error(
      `benchmark manifest must contain 22 vulnerable and 42 clean cases; got ${vulnerable.length}/${clean.length}`,
    )
  }
  return cases
}

export function assertFixtureSelectorsExist(cases, root = 'fixtures') {
  const fixtureRoot = resolve(root)
  for (const entry of cases) {
    if (!Array.isArray(entry.fixture_selectors) || entry.fixture_selectors.length === 0) {
      throw new Error(`${entry.case_id} has no fixture selectors`)
    }
    for (const selector of entry.fixture_selectors) {
      const baseSelector = selector.endsWith('/**') ? selector.slice(0, -3) : selector
      const target = resolve(fixtureRoot, baseSelector)
      const fromRoot = relative(fixtureRoot, target)
      if (
        isAbsolute(fromRoot)
        || fromRoot === '..'
        || fromRoot.startsWith(`..\\`)
        || fromRoot.startsWith('../')
      ) {
        throw new Error(`${entry.case_id} fixture selector escapes fixtures: ${selector}`)
      }
      if (!existsSync(target)) {
        throw new Error(`${entry.case_id} fixture selector matches no path: ${selector}`)
      }
      if (selector.endsWith('/**') && !statSync(target).isDirectory()) {
        throw new Error(`${entry.case_id} fixture selector is not a directory: ${selector}`)
      }
    }
  }
  return cases
}

export function renderBenchmarkCases(cases) {
  return `${JSON.stringify({
    schema_version: 1,
    generated_from: [MANIFEST, OWNERSHIP],
    cases,
  }, null, 2)}\n`
}

const isDirectRun = isMainModule(import.meta.url)

if (isDirectRun) {
  const cases = extractBenchmarkCases(
    readFileSync(MANIFEST, 'utf8'),
    readFileSync(OWNERSHIP, 'utf8'),
  )
  assertFixtureSelectorsExist(cases)
  const expected = renderBenchmarkCases(cases)
  if (process.argv.includes('--check')) {
    const actual = readFileSync(OUTPUT, 'utf8')
    if (actual !== expected) {
      console.error(`DRIFT: ${OUTPUT} does not match ${MANIFEST}`)
      process.exit(1)
    }
    console.log('PASS: benchmark cases match the fixture manifest (22 vulnerable, 42 clean).')
  } else {
    writeFileSync(OUTPUT, expected)
    console.log(`wrote ${OUTPUT}`)
  }
}
