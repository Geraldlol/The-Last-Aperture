import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { parseLens } from '../scripts/lib/frontmatter.mjs'

const text = readFileSync('test/samples/minimal-lens.md', 'utf8')

test('parses frontmatter into an object', () => {
  const lens = parseLens(text, 'minimal-lens.md')
  assert.equal(lens.errors.length, 0)
  assert.equal(lens.name, 'sample-domain')
  assert.equal(lens.frontmatter.runs_in, 'fanout')
  assert.deepEqual(lens.frontmatter.owns, ['csrf'])
  assert.equal(
    lens.frontmatter.defers['jwt-jws-and-jwks-verification'],
    'crypto-and-key-management'
  )
  assert.deepEqual(lens.frontmatter.activates_on.paths, ['**/routes/**'])
  assert.deepEqual(lens.frontmatter.activates_on.signals, ['express'])
})

test('collects every h2 section by title', () => {
  const lens = parseLens(text, 'minimal-lens.md')
  assert.deepEqual(Object.keys(lens.sections), [
    'Scope',
    'Checklist',
    'Severity calibration',
    'Known false positives',
    'Proof recipes',
  ])
  assert.match(lens.sections['Scope'], /Does not own JWT verification/)
})

test('extracts detector blocks with both directions', () => {
  const lens = parseLens(text, 'minimal-lens.md')
  assert.equal(lens.detectors.length, 1)
  assert.match(lens.detectors[0].match, /app\.post\('\/transfer'/)
  assert.match(lens.detectors[0].nomatch, /csrfProtection/)
  // Line number should match the file-relative line of the fence (grep -n '```detector')
  assert.equal(lens.detectors[0].line, 23)
})

test('reports an error instead of throwing on missing frontmatter', () => {
  const lens = parseLens('# no frontmatter here\n', 'broken.md')
  assert.ok(lens.errors.some((e) => /frontmatter/i.test(e)))
})

test('reports an error instead of throwing on malformed yaml', () => {
  const lens = parseLens('---\nname: [unclosed\n---\n', 'broken.md')
  assert.equal(lens.errors.length, 1)
  assert.match(lens.errors[0], /yaml/i)
})

const fencedText = `---
name: x
---

## Scope

real section

## Proof recipes

Here is a template:

\`\`\`
## Summary
## Findings
## Coverage
\`\`\`

end of real section
`

test('a `## ` line inside a fenced code block does not become a section', () => {
  const lens = parseLens(fencedText, 'fenced.md')
  assert.deepEqual(Object.keys(lens.sections), ['Scope', 'Proof recipes'])
  assert.equal(lens.sections['Summary'], undefined)
  assert.equal(lens.sections['Findings'], undefined)
  assert.equal(lens.sections['Coverage'], undefined)
})

test('a real section after a fenced block containing `## ` lines is still found, with its content intact', () => {
  const lens = parseLens(fencedText, 'fenced.md')
  assert.match(lens.sections['Proof recipes'], /Here is a template:/)
  // The fenced example itself is preserved as part of the section's content.
  assert.match(lens.sections['Proof recipes'], /## Summary\n## Findings\n## Coverage/)
  assert.match(lens.sections['Proof recipes'], /end of real section/)
})

test('a fenced markdown example between two detector blocks does not fracture section splitting', () => {
  const text = `---
name: x
---

## Checklist

- First check.

\`\`\`detector
match: |
  first-match-example
nomatch: |
  first-nomatch-example
\`\`\`

Here is what the report looks like:

\`\`\`
## Summary
Some \`inline-code\` in the example.
\`\`\`

- Second check.

\`\`\`detector
match: |
  second-match-example
nomatch: |
  second-nomatch-example
\`\`\`
`
  const lens = parseLens(text, 'fenced-detectors.md')
  // The primary claim: the fenced markdown example's `## Summary` line does not
  // split the Checklist section in two, or spin off a phantom section.
  assert.deepEqual(Object.keys(lens.sections), ['Checklist'])
  // Incidental confirmation that detector-block parsing (unaffected by this
  // change, since it runs its own regex over the raw body) still finds both.
  assert.equal(lens.detectors.length, 2)
  assert.match(lens.detectors[0].match, /first-match-example/)
  assert.match(lens.detectors[1].match, /second-match-example/)
})

test('an unterminated fence extends to end of file: no crash, no data loss, no further headings, but a reported error naming the opening line', () => {
  const text = `---
name: x
---

## Scope

before the fence

\`\`\`
inside the unterminated fence
## This looks like a heading but the fence never closed
still inside
`
  const lens = parseLens(text, 'unterminated.md')
  assert.deepEqual(Object.keys(lens.sections), ['Scope'])
  assert.match(lens.sections['Scope'], /before the fence/)
  assert.match(lens.sections['Scope'], /still inside/)
  // No longer silent: exactly one error, naming the file, the opening line
  // (9 — the ``` that never finds a closer), and calling it unterminated.
  assert.equal(lens.errors.length, 1)
  assert.match(lens.errors[0], /unterminated/i)
  assert.match(lens.errors[0], /unterminated\.md:9:/)
})

test('a closing fence with trailing content does not close the block — only a bare backtick run does', () => {
  const text = `---
name: x
---

## Scope

\`\`\`
line one
\`\`\` note: this is still example text
## Findings
\`\`\`

end of scope
`
  const lens = parseLens(text, 'trailing-closer.md')
  // The candidate closer carries trailing content, so per CommonMark it is not
  // a closer; the fence — and the "## Findings" line inside it — stays open
  // until the bare ``` two lines later. No phantom "Findings" section.
  assert.deepEqual(Object.keys(lens.sections), ['Scope'])
  assert.equal(lens.sections['Findings'], undefined)
  assert.match(lens.sections['Scope'], /end of scope/)
  // This fence does close (on the bare ``` at the end), so no unterminated error.
  assert.equal(lens.errors.length, 0)
})
