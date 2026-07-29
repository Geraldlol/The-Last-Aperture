import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

const ROOT = new URL('../', import.meta.url)
const OWNERSHIP = new URL('../fixtures/OWNERSHIP.tsv', import.meta.url)
const EXPECTED = new URL('../fixtures/EXPECTED.md', import.meta.url)
const FIXTURE_ID = /\b[VC]-\d{3}\b/g
const FIXTURE_ID_ON_LINE = /\b[VC]-\d{3}\b/

function trackedPayloads() {
  const gitPaths = (args) => execFileSync(
    'git',
    [...args, 'fixtures/vulnerable', 'fixtures/clean'],
    { cwd: ROOT, encoding: 'utf8' },
  )
    .trim()
    .split(/\r?\n/)
    .filter(Boolean)
    .map((path) => path.replace(/^fixtures\//, '').replaceAll('\\', '/'))

  const tracked = gitPaths(['ls-files'])
  const selectors = ownershipRows().map((row) => row.selector)
  const declaredPending = gitPaths(['ls-files', '--others', '--exclude-standard'])
    .filter((path) => selectors.some((selector) => selected(selector, path)))

  return [...new Set([...tracked, ...declaredPending])]
}

function ownershipRows() {
  return readFileSync(OWNERSHIP, 'utf8')
    .split(/\r?\n/)
    .flatMap((line, index) => {
      if (!line || line.startsWith('#')) return []

      const fields = line.split('\t')
      assert.ok(
        fields.length === 2 || fields.length === 3,
        `OWNERSHIP.tsv:${index + 1}: expected <owner><TAB><selector>[<TAB><support IDs>]`,
      )

      const supports = fields[2]
        ? fields[2].split(',').map((id) => id.trim())
        : []
      assert.equal(
        new Set(supports).size,
        supports.length,
        `OWNERSHIP.tsv:${index + 1}: duplicate support ID`,
      )

      return [{
        id: fields[0],
        selector: fields[1],
        supports,
        line: index + 1,
      }]
    })
}

function expectedManifestRows() {
  return readFileSync(EXPECTED, 'utf8')
    .split(/\r?\n/)
    .flatMap((line, index) => {
      const match = line.match(/^\|\s*([VC]-\d{3})\s*\|/)
      return match ? [{ id: match[1], line: index + 1 }] : []
    })
}

function selected(selector, path) {
  return selector.endsWith('/**')
    ? path.startsWith(selector.slice(0, -2))
    : path === selector
}

function primaryFixtureDeclaration(path, text) {
  if (path.endsWith('.json')) {
    let parsed
    assert.doesNotThrow(
      () => { parsed = JSON.parse(text) },
      `${path}: JSON fixture must remain parseable`,
    )
    assert.equal(
      typeof parsed._fixture,
      'string',
      `${path}: JSON fixture must declare its primary ID in the _fixture string`,
    )
    return parsed._fixture
  }

  const prologue = text.split(/\r?\n/).slice(0, 12)
  const declaration = prologue.find((line) => FIXTURE_ID_ON_LINE.test(line))
  assert.ok(
    declaration,
    `${path}: no fixture ID declaration in the first 12 lines`,
  )
  return declaration
}

function fixtureIds(text) {
  return [...text.matchAll(FIXTURE_ID)].map((match) => match[0])
}

test('every tracked fixture payload has exactly one logical owner', () => {
  const payloads = trackedPayloads()
  const rows = ownershipRows()

  assert.ok(payloads.length > 0, 'git returned no tracked fixture payloads')
  assert.ok(rows.length > 0, 'OWNERSHIP.tsv contains no ownership rows')

  for (const row of rows) {
    assert.match(row.id, /^[VC]-\d{3}$/, `OWNERSHIP.tsv:${row.line}: malformed fixture id`)
    for (const support of row.supports) {
      assert.match(
        support,
        /^[VC]-\d{3}$/,
        `OWNERSHIP.tsv:${row.line}: malformed support fixture id`,
      )
      assert.notEqual(
        support,
        row.id,
        `OWNERSHIP.tsv:${row.line}: owner cannot also be its own support ID`,
      )
    }
    assert.ok(
      payloads.some((path) => selected(row.selector, path)),
      `OWNERSHIP.tsv:${row.line}: selector matches no tracked payload: ${row.selector}`,
    )
    assert.equal(
      row.id[0],
      row.selector.startsWith('vulnerable/') ? 'V' : 'C',
      `OWNERSHIP.tsv:${row.line}: id and fixture half disagree`,
    )
  }

  for (const path of payloads) {
    const owners = rows.filter((row) => selected(row.selector, path))
    assert.equal(
      owners.length,
      1,
      `${path}: expected one logical owner, got ${owners.map((row) => row.id).join(', ') || 'none'}`,
    )

    const text = readFileSync(new URL(`../fixtures/${path}`, import.meta.url), 'utf8')
    const declaration = primaryFixtureDeclaration(path, text)
    const declaredIds = [...new Set(fixtureIds(declaration))].sort()
    const expectedIds = [owners[0].id, ...owners[0].supports].sort()
    assert.deepEqual(
      declaredIds,
      expectedIds,
      `${path}: primary declaration must name owner/support IDs ${expectedIds.join(', ')}`,
    )
  }

  const ids = new Set(rows.map((row) => row.id))
  for (const row of rows) {
    for (const support of row.supports) {
      assert.ok(
        ids.has(support),
        `OWNERSHIP.tsv:${row.line}: support ID has no logical owner row: ${support}`,
      )
    }
  }

  assert.deepEqual(
    [...ids].filter((id) => id.startsWith('V-')).sort(),
    Array.from({ length: 22 }, (_, index) => `V-${String(index + 1).padStart(3, '0')}`),
  )
  assert.deepEqual(
    [...ids].filter((id) => id.startsWith('C-')).sort(),
    Array.from({ length: 42 }, (_, index) => `C-${String(index + 1).padStart(3, '0')}`),
  )
})

test('EXPECTED manifest rows stay in lockstep with logical ownership IDs', () => {
  const ownerIds = new Set(ownershipRows().map((row) => row.id))
  const manifestRows = expectedManifestRows()
  const manifestCounts = new Map()

  for (const row of manifestRows) {
    manifestCounts.set(row.id, (manifestCounts.get(row.id) ?? 0) + 1)
    assert.ok(
      ownerIds.has(row.id),
      `EXPECTED.md:${row.line}: manifest ID has no OWNERSHIP.tsv row: ${row.id}`,
    )
  }

  for (const id of ownerIds) {
    assert.equal(
      manifestCounts.get(id),
      1,
      `EXPECTED.md: expected exactly one manifest row for ${id}`,
    )
  }

  assert.deepEqual(
    [...manifestCounts.keys()].sort(),
    [...ownerIds].sort(),
    'EXPECTED.md manifest IDs and OWNERSHIP.tsv logical IDs diverged',
  )
})
