import { readFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { isMainModule } from './lib/main-module.mjs'
import { terminalSafeText } from './lib/terminal-text.mjs'

// The banned term list is supplied at the shell via RESIDUE_TERMS and is
// deliberately absent from this file and from every other tracked file.
// Committing the words being scanned for would put them inside the thing being
// scanned: the scan would then either flag its own term list forever or have to
// exempt a file, and either way the strings would be in history permanently.

export function parseTerms(raw) {
  const seen = new Set()
  const terms = []
  for (const cell of String(raw ?? '').split(',')) {
    const term = cell.trim()
    if (!term) continue
    const key = term.toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    terms.push(term)
  }
  return terms
}

// One hit per line per term. Two occurrences of the same term on one line are a
// single fix, so reporting them twice only pads the count; two DIFFERENT terms
// on one line are two separate fixes and both are reported.
export function scanResidue(text, terms) {
  // A blank term is a substring of every line. Dropping blanks here is what
  // stops a stray comma in RESIDUE_TERMS from matching the entire corpus.
  const needles = []
  for (const term of terms) {
    const lower = String(term).trim().toLowerCase()
    if (lower) needles.push({ term, lower })
  }
  if (!needles.length) return []

  const hits = []
  text.split(/\r?\n/).forEach((line, i) => {
    const lower = line.toLowerCase()
    for (const needle of needles) {
      if (lower.includes(needle.lower)) hits.push({ term: needle.term, line: i + 1 })
    }
  })
  return hits
}

function git(args) {
  return execFileSync('git', args, { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 })
}

const GIT_SOURCES = [
  { where: 'git authorship (git log --all --format=%ae%n%an%n%ce%n%cn)', args: ['log', '--all', '--format=%ae%n%an%n%ce%n%cn'] },
  { where: 'git commit messages (git log --all --format=%B)', args: ['log', '--all', '--format=%B'] },
]

// Canonical-path comparison keeps the scan executable through a linked skill
// installation while imports remain side-effect free.
if (isMainModule(import.meta.url)) {
  const terms = parseTerms(process.env.RESIDUE_TERMS)
  if (!terms.length) {
    console.error('scan-residue: RESIDUE_TERMS is unset or contains no non-empty term.')
    console.error('Supply the banned terms at the shell — employer, tenant, product and person names plus any')
    console.error('email domain — and never write them into a tracked file:')
    console.error('  RESIDUE_TERMS="term1,term2,term3" node scripts/scan-residue.mjs')
    process.exit(2)
  }

  const hits = []
  // Sources that could not be read at all. These are tracked separately from
  // hits because "scanned and found nothing" and "never got looked at" are
  // different facts, and only the first one licenses a PASS.
  const unscanned = []
  const add = (where, text) => {
    for (const hit of scanResidue(text, terms)) hits.push({ where: `${where}:${hit.line}`, term: hit.term })
  }

  // Untracked-but-not-ignored files are included: a release candidate is
  // scanned before its new work is committed, and that work is exactly where
  // fresh residue lives.
  let tracked
  try {
    tracked = git(['ls-files', '-z', '--cached', '--others', '--exclude-standard'])
      .split('\0')
      .filter(Boolean)
  } catch (err) {
    console.error(`scan-residue: could not list candidate files — ${terminalSafeText(String(err.message).trim().split('\n')[0])}`)
    console.error('INCOMPLETE: nothing was scanned. This is not a clean result.')
    process.exit(3)
  }

  for (const file of tracked) {
    // A filename can carry residue just as a line of prose can.
    for (const hit of scanResidue(file, terms)) hits.push({ where: `path of tracked file ${file}`, term: hit.term })

    let buf
    try {
      buf = readFileSync(file)
    } catch (err) {
      unscanned.push(`${file} — unreadable (${err.code ?? String(err.message).trim()})`)
      continue
    }
    // utf8-decoding a binary can hide a matching byte sequence, so a binary is
    // reported as unscanned rather than silently counted as clean.
    if (buf.includes(0)) {
      unscanned.push(`${file} — binary (contains NUL); not text-scanned`)
      continue
    }
    add(file, buf.toString('utf8'))
  }

  for (const source of GIT_SOURCES) {
    try {
      add(source.where, git(source.args))
    } catch (err) {
      unscanned.push(`${source.where} — git failed (${String(err.stderr || err.message).trim().split('\n')[0]})`)
    }
  }

  for (const hit of hits) {
    console.error(
      `RESIDUE ${terminalSafeText(hit.where)}: contains "${terminalSafeText(hit.term)}"`,
    )
  }
  for (const source of unscanned) {
    console.error(`UNSCANNED ${terminalSafeText(source)}`)
  }

  console.log(`\nscanned ${tracked.length} candidate file(s) and ${GIT_SOURCES.length} git source(s) against ${terms.length} term(s).`)

  if (hits.length) {
    console.error(`FAIL: ${hits.length} residue hit(s). Phase A cannot close.`)
    process.exit(1)
  }
  if (unscanned.length) {
    console.error(`INCOMPLETE: ${unscanned.length} source(s) could not be scanned, so no clean verdict is available.`)
    process.exit(3)
  }
  console.log('PASS: no residue in tracked file contents, tracked file paths, commit authorship or commit messages.')
}
