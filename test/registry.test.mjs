import { test } from 'node:test'
import assert from 'node:assert/strict'
import { buildRegistry, checkBodyClaims, checkShapes } from '../scripts/lib/registry.mjs'

const lens = (name, owns, defers = {}, extra = {}) => ({
  name,
  frontmatter: { name, runs_in: 'fanout', owns, defers, ...extra },
  sections: {},
  detectors: [],
  errors: [],
})

test('a clean partition produces no violations', () => {
  const { slugs, violations } = buildRegistry([
    lens('web', ['csrf', 'xss'], { 'jwt-verify': 'crypto' }),
    lens('crypto', ['jwt-verify']),
  ])
  assert.deepEqual(violations, [])
  assert.equal(slugs.get('csrf'), 'web')
  assert.equal(slugs.get('jwt-verify'), 'crypto')
  assert.equal(slugs.size, 3)
})

test('R1 flags a slug owned by two lenses', () => {
  const { violations } = buildRegistry([lens('web', ['csrf']), lens('mobile', ['csrf'])])
  const r1 = violations.filter((v) => v.rule === 'R1')
  assert.equal(r1.length, 1)
  assert.equal(r1[0].slug, 'csrf')
  assert.deepEqual(r1[0].lenses.sort(), ['mobile', 'web'])
})

test('R1 flags a lens that both owns and defers the same slug', () => {
  const { violations } = buildRegistry([lens('web', ['csrf'], { csrf: 'mobile' }), lens('mobile', [])])
  assert.ok(violations.some((v) => v.rule === 'R1' && v.slug === 'csrf'))
})

test('R1 flags a duplicate slug inside one owns list', () => {
  const { violations } = buildRegistry([lens('web', ['csrf', 'csrf'])])
  assert.ok(violations.some((v) => v.rule === 'R1' && v.slug === 'csrf'))
})

test('R3 flags a deferral whose target does not own the slug', () => {
  const { violations } = buildRegistry([
    lens('web', ['csrf'], { 'jwt-verify': 'crypto' }),
    lens('crypto', ['aes-nonce']),
  ])
  const r3 = violations.filter((v) => v.rule === 'R3')
  assert.equal(r3.length, 1)
  assert.equal(r3[0].slug, 'jwt-verify')
})

test('R3 flags a deferral naming a lens that does not exist', () => {
  const { violations } = buildRegistry([lens('web', ['csrf'], { 'jwt-verify': 'nope' })])
  assert.ok(violations.some((v) => v.rule === 'R3' && /unknown lens/i.test(v.message)))
})

test('R3 flags a self-deferral', () => {
  const { violations } = buildRegistry([lens('web', ['csrf'], { csrf: 'web' })])
  assert.ok(violations.some((v) => v.rule === 'R3' || v.rule === 'R1'))
})

test('R3 isolates self-deferral without R1 co-firing', () => {
  const { violations } = buildRegistry([lens('web', [], { 'jwt-verify': 'web' })])
  assert.equal(violations.length, 1)
  assert.equal(violations[0].rule, 'R3')
  assert.ok(/self/i.test(violations[0].message))
})

test('non-owning lenses are exempt rather than violations', () => {
  const { violations } = buildRegistry([
    lens('web', ['csrf']),
    lens('completeness', [], {}, { runs_in: 'triage' }),
    lens('ai-generated-code', [], {}, { always_active: true }),
  ])
  assert.deepEqual(violations, [])
})

// R8 — body-aware ownership. Every body below is written in the shapes the real
// lenses use, because the predicate is about position and a paraphrase would test
// a different rule.
const bodied = (name, owns, defers, sections, extra = {}) => ({ ...lens(name, owns, defers, extra), sections })
const r8 = (lenses) => checkBodyClaims(lenses, buildRegistry(lenses).slugs)

// The owner claims `csrf` twice over, the way every real lens does: an `### Owns`
// table row in Scope, and a Checklist item heading that names the slug it files
// under.
const OWNER = {
  Scope: [
    '### Owns',
    '',
    '| Topic | What that means here |',
    '|---|---|',
    '| `csrf` | State-changing requests reachable with no token check. |',
    '',
    '### Does not own',
    '',
    '- **crypto** — `jwt-jws-and-jwks-verification`.',
  ].join('\n'),
  Checklist: '### 4. Cross-site request forgery (`csrf`)\n\nGrep for state-changing POST handlers with no token check.',
}

// A second lens working the same topic under its own heading: no `defers` entry,
// so two lenses will file the same finding.
const CLAIMS_IT_TOO = {
  Checklist: '### 9. Cross-site request forgery through the bridge (`csrf`)\n\nGrep the webview bridge for state-changing calls with no token.',
}

test('R8 fires on two lenses whose bodies both claim a slug with no deferral between them', () => {
  const v = r8([bodied('web', ['csrf'], {}, OWNER), bodied('mobile', ['webview-bridge-trust'], {}, CLAIMS_IT_TOO)])
  assert.equal(v.length, 1)
  assert.equal(v[0].rule, 'R8')
  assert.equal(v[0].slug, 'csrf')
  assert.deepEqual(v[0].lenses, ['mobile', 'web'])
  assert.match(v[0].message, /no defers entry/)
  assert.match(v[0].message, /also claimed by web/)
})

test('R8 stays silent when the shared mention is a "does not own" declaration, in either shape', () => {
  // Both shapes of the hand-off: the bullet list the lenses use today, and the
  // same list as a table, which puts the slug in first-cell position — the one
  // reformatting that would fool a position-only predicate.
  const handoff = {
    Scope: [
      '### Does not own',
      '',
      '- **web** — `csrf`. The generic cross-site request forgery class is web-and-api\'s; the platform shape stays here.',
      '',
      '| Topic | Owner |',
      '|---|---|',
      '| `csrf` | web |',
    ].join('\n'),
  }
  assert.deepEqual(r8([bodied('web', ['csrf'], {}, OWNER), bodied('mobile', ['webview-bridge-trust'], {}, handoff)]), [])
})

test('R8 stays silent when a hand-off is written in prose or a later table cell', () => {
  // The three shapes the real corpus hands a topic over in. None is a claim, and
  // all three would be reported by a predicate that read prose.
  const prose = {
    Checklist: '- Scope the impact by what the request reaches. The generic token check is `csrf` in `web` — file the platform shape here and hand that lens the request context.',
    'Severity calibration': [
      '| Finding | Severity | The artifact that establishes it |',
      '|---|---|---|',
      '| Bridge call performing a state change | High | The finding is filed by `web` under `csrf`; this row exists so the grade is identical wherever it is filed. |',
    ].join('\n'),
    'Known false positives': '- **"A POST with no token."** Real, but deduplicated to `web`, which owns `csrf`.',
  }
  assert.deepEqual(r8([bodied('web', ['csrf'], {}, OWNER), bodied('mobile', ['webview-bridge-trust'], {}, prose)]), [])
})

test('R8 keeps a "does not own" list excluded when it is grouped under sub-headings', () => {
  const handoff = {
    Scope: [
      '### Does not own',
      '',
      '#### web',
      '',
      '| Topic | Owner |',
      '|---|---|',
      '| `csrf` | web |',
      '',
      '### What cannot be determined from a repository',
      '',
      '- Whether the deployed proxy strips the header.',
    ].join('\n'),
  }
  assert.deepEqual(r8([bodied('web', ['csrf'], {}, OWNER), bodied('mobile', ['webview-bridge-trust'], {}, handoff)]), [])
})

test('R8 stays silent when a claim position sits inside a fenced example', () => {
  const fenced = {
    Checklist: ['```', '| `csrf` | a row quoted from an example report |', '#### 9. (`csrf`)', '```'].join('\n'),
  }
  assert.deepEqual(r8([bodied('web', ['csrf'], {}, OWNER), bodied('mobile', ['webview-bridge-trust'], {}, fenced)]), [])
})

test('R8 accepts a body claim that carries the declared deferral', () => {
  const claimant = bodied('mobile', ['webview-bridge-trust'], { csrf: 'web' }, CLAIMS_IT_TOO)
  assert.deepEqual(r8([bodied('web', ['csrf'], {}, OWNER), claimant]), [])
})

test('R8 does not report a lens for claiming a slug it owns', () => {
  assert.deepEqual(r8([bodied('web', ['csrf'], {}, OWNER), bodied('mobile', ['webview-bridge-trust'], {}, {})]), [])
})

test('R8 requires a pair: one lens claiming a slug alone is not a duplicate', () => {
  // The owner's body says nothing about `csrf`, so there is no second filer and
  // no duplicate. Stated as a test because it is the rule's deliberate gap:
  // `completeness` resolves a finding's topic to its owner at run time.
  const v = r8([bodied('web', ['csrf'], {}, {}), bodied('mobile', ['webview-bridge-trust'], {}, CLAIMS_IT_TOO)])
  assert.deepEqual(v, [])
})

test('R8 reports both lenses when two non-owners claim a slug its owner never mentions', () => {
  const v = r8([
    bodied('web', ['csrf'], {}, {}),
    bodied('mobile', ['webview-bridge-trust'], {}, CLAIMS_IT_TOO),
    bodied('salesforce', ['apex-sharing-declaration'], {}, CLAIMS_IT_TOO),
  ])
  assert.equal(v.length, 2)
  assert.deepEqual(v.map((x) => x.lenses[0]).sort(), ['mobile', 'salesforce'])
  assert.match(v[0].message, /also claimed by salesforce/)
})

test('R8 fires when a body Owns table lists a slug the frontmatter does not own', () => {
  const drift = {
    Scope: ['### Owns', '', '| Topic | What that means here |', '|---|---|', '| `csrf` | Token checks on bridge calls. |'].join('\n'),
  }
  const v = r8([bodied('web', ['csrf'], {}, OWNER), bodied('mobile', ['webview-bridge-trust'], {}, drift)])
  assert.equal(v.length, 1)
  assert.equal(v[0].slug, 'csrf')
  assert.deepEqual(v[0].lenses, ['mobile', 'web'])
})

test('R8 asks for no deferral from a lens R6 forbids to declare one', () => {
  const triage = { runs_in: 'triage', activates_on: { paths: [], signals: [] } }
  assert.deepEqual(r8([bodied('web', ['csrf'], {}, OWNER), bodied('completeness', [], {}, CLAIMS_IT_TOO, triage)]), [])
  // Why the exemption is forced rather than chosen: the only edit that would
  // satisfy a pairwise demand against a lens owning nothing is itself an R6
  // violation, so R8 and R6 could not both be satisfied.
  const withDeferral = bodied('completeness', [], { csrf: 'web' }, CLAIMS_IT_TOO, triage)
  assert.ok(checkShapes([withDeferral]).some((x) => /nothing to defer from/.test(x.message)))
})
