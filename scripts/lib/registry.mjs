import { stripFencedBlocks } from './frontmatter.mjs'
import { compareCanonicalStrings } from './canonical-order.mjs'
import {
  EVIDENCE_ARTIFACT_KINDS,
  EVIDENCE_CLASSES,
  EVIDENCE_CLASS_ORDER,
  isEvidenceArtifactKind,
  isEvidenceClaimKind,
} from './evidence-classes.mjs'

// Ownership model. Pure functions over parsed lenses — no file I/O, so the
// rules are testable against synthetic lens sets rather than the real corpus.
export function buildRegistry(lenses) {
  const violations = []
  const slugs = new Map()
  const names = new Set(lenses.map((l) => l.frontmatter.name))

  // R1: ownership is a partition.
  for (const l of lenses) {
    const owns = l.frontmatter.owns ?? []
    const seen = new Set()
    for (const slug of owns) {
      if (seen.has(slug)) {
        violations.push({ rule: 'R1', slug, lenses: [l.frontmatter.name], message: `${l.frontmatter.name}: slug "${slug}" listed twice in owns` })
        continue
      }
      seen.add(slug)
      const existing = slugs.get(slug)
      if (existing !== undefined) {
        violations.push({ rule: 'R1', slug, lenses: [existing, l.frontmatter.name], message: `slug "${slug}" owned by both ${existing} and ${l.frontmatter.name}` })
        continue
      }
      slugs.set(slug, l.frontmatter.name)
    }
    for (const slug of Object.keys(l.frontmatter.defers ?? {})) {
      if (seen.has(slug)) {
        violations.push({ rule: 'R1', slug, lenses: [l.frontmatter.name], message: `${l.frontmatter.name}: owns and defers the same slug "${slug}"` })
      }
    }
  }

  // R3: every deferral resolves to the actual owner.
  for (const l of lenses) {
    for (const [slug, target] of Object.entries(l.frontmatter.defers ?? {})) {
      if (target === l.frontmatter.name) {
        violations.push({ rule: 'R3', slug, lenses: [l.frontmatter.name], message: `${l.frontmatter.name}: defers "${slug}" to itself` })
        continue
      }
      if (!names.has(target)) {
        violations.push({ rule: 'R3', slug, lenses: [l.frontmatter.name, target], message: `${l.frontmatter.name}: defers "${slug}" to unknown lens "${target}"` })
        continue
      }
      const owner = slugs.get(slug)
      if (owner !== target) {
        violations.push({ rule: 'R3', slug, lenses: [l.frontmatter.name, target], message: `${l.frontmatter.name}: defers "${slug}" to ${target}, but it is owned by ${owner ?? 'nobody'}` })
      }
    }
  }

  return { slugs, violations }
}

// R2 compares the generated registry against a committed one. Kept separate
// from buildRegistry because R2 is about drift between files, not about the model.
export function diffRegistry(generated, committed) {
  const violations = []
  for (const [slug, owner] of generated) {
    if (!committed.has(slug)) {
      violations.push({ rule: 'R2', slug, lenses: [owner], message: `slug "${slug}" owned by ${owner} is missing from _topics.md` })
    } else if (committed.get(slug) !== owner) {
      violations.push({ rule: 'R2', slug, lenses: [owner, committed.get(slug)], message: `slug "${slug}": frontmatter says ${owner}, _topics.md says ${committed.get(slug)}` })
    }
  }
  for (const [slug, owner] of committed) {
    if (!generated.has(slug)) {
      violations.push({ rule: 'R2', slug, lenses: [owner], message: `slug "${slug}" in _topics.md is owned by no lens` })
    }
  }
  return violations
}

const REQUIRED_KEYS = ['name', 'title', 'runs_in', 'activates_on', 'owns', 'defers', 'frameworks', 'severity_floor']

// Three legal shapes. runs_in replaced an earlier cross_cutting boolean because
// one flag was carrying two facts: when a lens runs, and whether it owns territory.
export function checkShapes(lenses) {
  const violations = []
  const seen = new Set()
  for (const l of lenses) {
    const fm = l.frontmatter
    const name = fm.name ?? l.name ?? '<unnamed>'
    const push = (message) => violations.push({ rule: 'R6', slug: null, lenses: [name], message })

    // Two lenses sharing a name collapse into one identity: R1 reports a slug
    // "owned by both foo and foo", R3 deferral targets stop resolving to one
    // lens, and checkBodyClaims' byName map keeps only the last of them.
    if (seen.has(name)) push(`${name}: duplicate lens name; lens names must be unique`)
    seen.add(name)

    for (const key of REQUIRED_KEYS) {
      if (fm[key] === undefined) push(`${name}: missing required frontmatter key "${key}"`)
    }
    if (fm.runs_in !== 'fanout' && fm.runs_in !== 'triage') {
      push(`${name}: runs_in must be "fanout" or "triage", got "${fm.runs_in}"`)
      continue
    }

    const owns = fm.owns ?? []
    const paths = fm.activates_on?.paths ?? []
    const signals = fm.activates_on?.signals ?? []
    const matches = paths.length + signals.length

    if (fm.runs_in === 'triage') {
      if (fm.always_active) push(`${name}: always_active is only valid with runs_in: fanout`)
      if (owns.length) push(`${name}: runs_in triage but owns ${owns.length} slug(s); triage lenses reason over findings and own nothing`)
      if (matches) push(`${name}: runs_in triage but activates_on is non-empty; triage lenses activate on findings, not paths`)
      if (Object.keys(fm.defers ?? {}).length) push(`${name}: runs_in triage but declares defers; it owns nothing to defer from`)
    } else if (fm.always_active) {
      if (owns.length) push(`${name}: always_active but owns ${owns.length} slug(s); it reports against other lenses' topics`)
      if (matches) push(`${name}: always_active but activates_on is non-empty; it runs on every audit and must not be matched`)
    } else {
      if (!owns.length) push(`${name}: a domain lens must own at least one slug`)
      if (!matches) push(`${name}: activates_on must match something, or the lens never runs`)
    }
  }
  return violations
}

// R7 realizes spec gate A2. A search instruction nobody demonstrated firing is
// worse than a missing check: it runs, matches nothing, and reports clean.
export function checkDetectors(lenses) {
  const violations = []
  for (const l of lenses) {
    const name = l.frontmatter.name ?? l.name ?? '<unnamed>'
    const push = (message) => violations.push({ rule: 'R7', slug: null, lenses: [name], message })

    if (l.sections.Checklist === undefined) continue
    if (!l.detectors.length) {
      push(`${name}: has a Checklist but no detector blocks; at least one search instruction must be demonstrated firing`)
      continue
    }
    for (const d of l.detectors) {
      if (!d.match) push(`${name}:${d.line}: detector has no "match" example, so nothing shows the check fires`)
      if (!d.nomatch) push(`${name}:${d.line}: detector has no "nomatch" example, so nothing shows the check discriminates`)
      if (d.match && d.nomatch && d.match.trim() === d.nomatch.trim()) {
        push(`${name}:${d.line}: match and nomatch are identical, so the detector proves nothing`)
      }
    }
  }
  return violations
}

// R8 is the body-aware companion to R1-R3. Those three read frontmatter only, so
// two lenses can both work the same topic in their bodies with no `defers` entry
// between them and the linter stays silent — which is how a duplicate finding
// reaches a report despite a clean partition on paper. It bites hardest on the
// slugs with no inbound `defers` reference at all, where nothing else constrains
// anything. The spec deferred this rule until the lens bodies existed; they do.
//
// "Substantively discusses" decides the whole rule and is wrong in both
// directions if it is guessed, so the predicate is POSITIONAL rather than
// textual: a lens claims a topic where it puts the slug in the subject position
// of a structural element it authored — a `###`-or-deeper heading, or the first
// cell of a table row. Those are the two positions this corpus uses to say "this
// topic is mine": the `### Owns` table declares it, and a Checklist item heading
// ("### 6. Pivot feasibility (`pivot-feasibility`)") heads the check that files
// under it. Every one of the 164 owned slugs is named by its owner in one of
// those two positions, so the predicate tracks how the corpus actually works
// rather than a shape that happens to be rare.
//
// A slug named anywhere else — mid-sentence in prose, in a later table cell,
// inside a fenced example — is read as discussion *about* a topic, not a claim on
// it, and that asymmetry is the point. Prose is where this corpus hands a topic
// OVER: "an unvalidated user-supplied URL is web-and-api's
// `ssrf-application-path`", "the control is cited, not filed", "owned
// elsewhere". Nineteen (lens, slug) pairs across twenty-four mentions sit in that
// population today; every one was read by hand and every one is a hand-off, so a
// predicate that counted prose would report nineteen findings on topics the
// sentences explicitly disclaim. `### Does not own` is excluded as a whole region
// on top of that: its bullets already sit outside a claim position, but it is the
// one region where rewriting the list as a table would put a slug in first-cell
// position, and it is definitionally where a lens gives topics away.
//
// The limit, stated because a silent rule must not read as a clean bill of
// health: a claim made only in prose ("...and file it under `X`") is not
// detected here. Nothing in the frontmatter rules sees it either; the
// `completeness` lens, which resolves every finding's `topic` to its owner at run
// time, is what covers that case.
const CLAIM_FREE_SUBSECTION = /^does not own\b/i

// Slugs are read as whole backticked literals compared for equality against the
// registry, so no slug can be matched as a fragment of a longer literal and no
// prose word can be mistaken for a slug.
function bodyClaims(lens, slugs) {
  const claimed = new Set()
  const add = (text) => {
    for (const span of text.match(/`[^`]+`/g) ?? []) {
      const literal = span.slice(1, -1).trim()
      if (slugs.has(literal)) claimed.add(literal)
    }
  }
  for (const section of Object.values(lens.sections ?? {})) {
    // The claim-free region runs to the next heading at its own depth or
    // shallower, so grouping a "does not own" list under `####` sub-headings
    // keeps the whole list excluded instead of reopening it as claim territory.
    let claimFreeDepth = 0
    for (const line of stripFencedBlocks(section).split('\n')) {
      const heading = /^(#{3,})\s+(.+?)\s*$/.exec(line)
      if (heading) {
        const depth = heading[1].length
        if (claimFreeDepth && depth <= claimFreeDepth) claimFreeDepth = 0
        if (claimFreeDepth) continue
        if (CLAIM_FREE_SUBSECTION.test(heading[2].trim())) claimFreeDepth = depth
        else add(heading[2])
        continue
      }
      if (claimFreeDepth) continue
      if (!/^\s*\|/.test(line)) continue
      add(line.replace(/^\s*\|/, '').split('|')[0])
    }
  }
  return claimed
}

export function checkBodyClaims(lenses, slugs) {
  const violations = []

  // Only lenses that own territory participate, and that is forced rather than
  // chosen: R6 rejects a triage lens that declares `defers` at all ("it owns
  // nothing to defer from"), so demanding a deferral from one would make R8 and
  // R6 unsatisfiable together. The always-active lens is the same case — its body
  // names other lenses' slugs deliberately, routes each to its owner in
  // `### Routing`, and files under `raised_by`, which is the schema's mechanism
  // for exactly that rather than a gap in this one.
  const participants = lenses.filter((l) => (l.frontmatter.owns ?? []).length > 0)
  const byName = new Map(participants.map((l) => [l.frontmatter.name, l]))

  const claimants = new Map()
  for (const l of participants) {
    for (const slug of bodyClaims(l, slugs)) {
      if (!claimants.has(slug)) claimants.set(slug, [])
      claimants.get(slug).push(l.frontmatter.name)
    }
  }

  for (const [slug, names] of claimants) {
    // The pair is the unit the rule is stated in, and it is the unit the harm
    // needs: one lens claiming a topic alone files one finding, not a duplicate.
    if (names.length < 2) continue
    const owner = slugs.get(slug)
    for (const name of names) {
      if (name === owner) continue
      // Presence of the entry is all R8 asks. R3 already checks that a `defers`
      // target resolves to the actual owner; firing both would print two
      // violations for the one edit that fixes them.
      if ((byName.get(name).frontmatter.defers ?? {})[slug] !== undefined) continue
      const others = names.filter((n) => n !== name)
      violations.push({
        rule: 'R8',
        slug,
        lenses: [name, owner],
        message: `${name}: body claims "${slug}" — owned by ${owner}, also claimed by ${others.join(', ')} — with no defers entry`,
      })
    }
  }
  return violations
}

const EVIDENCE_STATES = new Set(['consumed', 'not-consumed'])

// R9. A lens that never says which evidence classes it can speak to makes
// "we read the Dockerfile but never the image" inexpressible, and an audit
// that cannot express a blind spot reports it as silence. Silence reads as
// clearance, which is the failure this rule exists to make impossible.
export function checkEvidenceClasses(lenses) {
  const violations = []
  for (const l of lenses) {
    const name = l.frontmatter?.name ?? l.name ?? '<unnamed>'
    const push = (message) => violations.push({ rule: 'R9', slug: null, lenses: [name], message })
    const declared = l.frontmatter?.activates_on?.evidence_classes

    if (declared === null || typeof declared !== 'object' || Array.isArray(declared)) {
      push(`${name}: activates_on.evidence_classes is missing; every lens declares all four classes`)
      continue
    }

    for (const key of Object.keys(declared)) {
      if (!EVIDENCE_CLASS_ORDER.includes(key)) {
        push(`${name}: unknown evidence class "${key}"`)
      }
    }

    for (const evidenceClass of EVIDENCE_CLASS_ORDER) {
      const entry = declared[evidenceClass]
      if (entry === undefined) {
        push(`${name}: evidence class "${evidenceClass}" is not declared`)
        continue
      }
      if (entry === null || typeof entry !== 'object' || Array.isArray(entry)) {
        push(`${name}: evidence class "${evidenceClass}" must be a mapping with a state`)
        continue
      }
      if (!EVIDENCE_STATES.has(entry.state)) {
        push(
          `${name}: evidence class "${evidenceClass}" state must be consumed or not-consumed, `
          + `got "${entry.state}"`,
        )
        continue
      }

      const consumed = entry.state === 'consumed'
      const kinds = entry.artifact_kinds
      const claims = entry.may_conclude

      if (!consumed) {
        for (const key of ['artifact_kinds', 'may_conclude']) {
          if (entry[key] !== undefined) {
            push(`${name}: "${evidenceClass}" is not-consumed and must not declare ${key}`)
          }
        }
        continue
      }

      if (evidenceClass === EVIDENCE_CLASSES.BUILT_ARTIFACT) {
        if (!Array.isArray(kinds) || kinds.length === 0) {
          push(
            `${name}: "built-artifact" is consumed and must declare a non-empty artifact_kinds `
            + `from ${EVIDENCE_ARTIFACT_KINDS.join(', ')}`,
          )
        } else {
          for (const kind of kinds) {
            if (!isEvidenceArtifactKind(kind)) {
              push(`${name}: unknown artifact kind "${kind}" in "built-artifact"`)
            }
          }
        }
      } else if (kinds !== undefined) {
        push(`${name}: artifact_kinds is only meaningful for "built-artifact", not "${evidenceClass}"`)
      }

      // source is exempt: it is what every lens in this registry already does,
      // and bounding it now would re-litigate all 174 owned topics.
      if (evidenceClass === EVIDENCE_CLASSES.SOURCE) {
        if (claims !== undefined) {
          push(`${name}: "source" needs no may_conclude; its claims are bounded by topic ownership`)
        }
        continue
      }
      if (!Array.isArray(claims) || claims.length === 0) {
        push(`${name}: "${evidenceClass}" is consumed and must declare a non-empty may_conclude`)
        continue
      }
      for (const claim of claims) {
        if (!isEvidenceClaimKind(claim)) {
          push(`${name}: unknown claim kind "${claim}" in "${evidenceClass}"`)
        }
      }
    }
  }
  return violations
}

// The corpus as a lookup, for the coverage matrix and the finding validator.
export function lensEvidenceDeclarations(lenses) {
  return new Map(lenses.map((l) => [
    l.frontmatter?.name ?? l.name,
    l.frontmatter?.activates_on?.evidence_classes ?? {},
  ]))
}

// Coverage observation channel. Reports detector-to-literal ratios for lenses
// with Checklist sections. An observation, not a violation — helps identify
// which lenses may have undemonstrated search instructions.
export function detectorCoverage(lenses) {
  const results = []
  for (const l of lenses) {
    const name = l.frontmatter.name ?? l.name ?? '<unnamed>'

    if (l.sections.Checklist === undefined) continue

    // Count distinct backticked literals in the Checklist section, ignoring
    // any fenced example embedded in it — those show usage, not search targets.
    const text = stripFencedBlocks(l.sections.Checklist)
    const matches = text.match(/`[^`]+`/g) || []
    const literals = new Set(matches.map(m => m.slice(1, -1))) // Remove backticks

    results.push({
      lens: name,
      literals: literals.size,
      detectors: l.detectors.length
    })
  }

  // Sort by lens name for deterministic output
  results.sort((a, b) => compareCanonicalStrings(a.lens, b.lens))
  return results
}
