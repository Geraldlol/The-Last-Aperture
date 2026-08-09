import { test } from 'node:test'
import assert from 'node:assert/strict'
import { existsSync, readFileSync } from 'node:fs'

const LEDGER = 'docs/migration-ledger.tsv'

function referenceCitations() {
  return readFileSync(LEDGER, 'utf8')
    .split(/\r?\n/)
    .slice(1)
    .filter((row) => row.startsWith('references/'))
    .map((row) => /^(references\/[^#]+)#L(\d+)/.exec(row.split('\t')[0]))
    .filter(Boolean)
    .map(([, file, line]) => ({ file, line: Number(line) }))
}

// `references/` is the unscrubbed pre-migration corpus. It is gitignored on
// purpose — .gitignore records that those files still carry private-product
// residue and named-vendor content and "must never enter history" — so a clone
// does not have them and CI cannot check them.
//
// That is a deliberate trade, not an oversight, and this file exists to keep it
// legible: the ledger cites those files as the origin of migrated lens content,
// so its provenance is verifiable only where a local copy survives. A test that
// *required* them would fail on every clone and would pressure someone into
// committing the residue to make it green, which is the one outcome the ignore
// rule exists to prevent.
const REFERENCES_SKIP = existsSync('references')
  ? false
  : 'references/ is gitignored by design (unscrubbed residue) and absent from '
    + 'this checkout; ledger provenance into it cannot be verified here'

test('the ledger cites the pre-migration corpus, whether or not it is present', () => {
  // Checkable everywhere: the citations exist and are well-formed. Only
  // resolving them against the files needs the local corpus.
  const citations = referenceCitations()
  assert.ok(
    citations.length > 700,
    `expected the ledger to cite references/; got ${citations.length}`,
  )
  for (const { file, line } of citations.slice(0, 50)) {
    assert.match(file, /^references\/[a-z0-9-]+\.md$/)
    assert.ok(Number.isInteger(line) && line > 0)
  }
})

test('every cited file resolves, where the corpus is present', { skip: REFERENCES_SKIP }, () => {
  const missing = [...new Set(referenceCitations().map(({ file }) => file))]
    .filter((file) => !existsSync(file))
  assert.deepEqual(
    missing,
    [],
    'the ledger cites these as the origin of migrated lens content; a local '
    + 'copy that loses them loses the last verifiable provenance',
  )
})

test('the cited line numbers resolve inside those files', { skip: REFERENCES_SKIP }, () => {
  const lineCounts = new Map()
  const unresolvable = referenceCitations().filter(({ file, line }) => {
    if (!lineCounts.has(file)) {
      lineCounts.set(file, readFileSync(file, 'utf8').split(/\r?\n/).length)
    }
    return line > lineCounts.get(file)
  })
  // Two rows cite a line past the end of their file. Pinned rather than
  // tolerated: a bound that drifts is a bound nobody is holding.
  assert.equal(
    unresolvable.length,
    2,
    `citations past end of file: ${JSON.stringify(unresolvable)}`,
  )
})
