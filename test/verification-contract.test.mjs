import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

// The two contract documents are not lenses: `lint-lenses.mjs` filters out every
// underscore-prefixed file, so nothing else in this repository reads them. These
// checks exist because two rules in them were bought with a shipped false
// Critical, and a rule that nothing asserts is a rule the next editor deletes
// without noticing.
//
// Both directions, as everywhere else in this corpus: each rule is asserted
// present on the real file AND asserted to fail on a doctored copy with the rule
// removed. A checker that only passes on the good input proves it runs, not that
// it fires.

const SCHEMA = 'skills/last-aperture/lenses/_schema.md'
const HARNESS = 'skills/last-aperture/lenses/_harness.md'
const SKILL = 'skills/last-aperture/SKILL.md'
const CHAINING = 'skills/last-aperture/lenses/attack-chaining.md'
const THREAT_MODEL = 'skills/last-aperture/lenses/threat-modeling.md'
const DATABASE = 'skills/last-aperture/lenses/database-and-data-stores.md'

const read = (p) => readFileSync(p, 'utf8')

/**
 * The existence-first ordering rule, in the four places it has to be stated to
 * be live: the rule itself, the disposition it forces, the field that records
 * it, and the invariant that authorizes a grade.
 *
 * Returns [] when the contract states the rule. Each violation names the rule
 * that is missing, not the line, because the rule may legitimately move.
 */
export function checkExistenceFirst(schema, harness) {
  const out = []
  const wants = [
    ['ordering-rule', schema, /existence first[^.]*ordering rule/i,
      '_schema.md must state existence-first as an ordering rule, not as one more condition'],
    ['before-the-argument', schema, /before any argument about reachability, severity or impact/i,
      '_schema.md must order the existence check ahead of the reachability, severity and impact arguments'],
    ['not-located-is-not-reproduced', schema, /cannot be located[\s\S]{0,400}?NOT_REPRODUCED/,
      '_schema.md must grade an unlocatable artifact NOT_REPRODUCED'],
    ['plausibility-is-not-evidence', schema, /however plausible the reasoning/i,
      '_schema.md must say the grade holds however plausible the reasoning was'],
    ['not-inconclusive', schema, /not `INCONCLUSIVE`/,
      '_schema.md must distinguish an unlocatable artifact from an INCONCLUSIVE harness failure'],
    ['recorded-field', schema, /`existence_check`/,
      '_schema.md must carry a field recording the outcome of the check'],
    ['state-table', schema, /\|\s*`NOT_REPRODUCED`\s*\|[^|]*could not be located/,
      "the NOT_REPRODUCED row of _schema.md's state table must carry the unlocatable-artifact case"],
    ['invariant', schema, /No `verification_status` is assigned without `existence_check`/,
      '_schema.md must carry the invariant that no status is assigned without the check'],
    ['harness-ordering', harness, /existence precedes tier/i,
      '_harness.md must order the existence check ahead of tier assignment'],
    ['harness-disposition', harness, /cannot be located is `NOT_REPRODUCED`/,
      '_harness.md must grade an unlocatable artifact NOT_REPRODUCED, consistently with _schema.md'],
  ]
  for (const [rule, text, pattern, message] of wants) {
    if (!pattern.test(text)) out.push({ rule, message })
  }
  return out
}

/**
 * The `contingent:` reachability value. Asserted for the same reason: the value
 * is worth nothing if a later edit keeps the prose and drops the cap, or keeps
 * the cap and drops the two fields that make the finding resolvable.
 *
 * The two lens consumers are checked here too, and that is the point rather than
 * thoroughness for its own sake. This project's recurring defect is a rule fixed
 * where it is stated and left stale where it is used, so a value declared in the
 * schema and asserted only in the schema is exactly the shape that decays: the
 * schema keeps the rule, the lens that grades on it loses it, and the grading
 * site is what authorizes the severity.
 */
export function checkContingentReachability(schema, skill, chaining, threatModel) {
  const out = []
  const wants = [
    // Anchored to the `reachable_from` row itself, not to the word pair anywhere
    // on a line. The unanchored form was satisfied by the `contingent_fact` and
    // `contingent_query` rows below it, both of which quote "`reachable_from`
    // carries a `contingent:` value" — so it could only fire after fact-required
    // and query-required had already fired, and the schema could stop declaring
    // the value on the field that carries it with the suite green.
    ['value-declared', schema, /\|\s*`reachable_from`\s*\|[^|]*`contingent:/,
      "_schema.md's Stage 1 table must declare the contingent: form on the `reachable_from` row itself"],
    ['fact-required', schema, /`contingent_fact`/,
      '_schema.md must require the one runtime fact to be named'],
    ['query-required', schema, /`contingent_query`/,
      '_schema.md must require the query that resolves the fact to be named'],
    ['still-caps', schema, /`contingent:` value implies `effective_severity` is at most Medium/,
      'the invariant that authorizes the grade must cap the contingent form at Medium'],
    ['not-normalized', schema, /not\*{0,2} normalized to `unknown`/,
      '_schema.md must forbid a consumer collapsing the contingent form to unknown'],
    ['queue-position', schema, /`contingent:` records precede `unknown` ones/,
      '_schema.md must state how the contingent form is queued relative to unknown'],
    ['gate-covers-it', skill, /`reachable_from: unknown` or `contingent:` caps/,
      "SKILL.md's reachability gate must cap the contingent form too, or the gate leaks"],
    ['queue-keeps-capped-findings', skill, /including those capped to Medium by the gate/,
      'SKILL.md must keep gate-capped findings in the proof queue, or the cap becomes a silent drop'],
    ['chain-cap', chaining, /`contingent:` value caps the composition at Medium/,
      'attack-chaining.md must cap a chain carrying a contingent: component, or a chain launders the uncapped grade'],
    ['entry-point-table', threatModel, /`contingent:<entry point>` form with `contingent_fact` and `contingent_query`/,
      "threat-modeling.md's entry-point mapping must offer the contingent: form"],
    ['critical-row', threatModel, /that caveat has a home in the record/,
      "threat-modeling.md's Critical row must not still claim the reachability caveat has nowhere in the record to go"],
  ]
  for (const [rule, text, pattern, message] of wants) {
    if (!pattern.test(text)) out.push({ rule, message })
  }
  return out
}

/**
 * Database semantic claims require an engine/deployment profile and an adapter.
 * Without this gate a generic SQL detector can silently clear a store whose
 * role, policy, transaction or copy semantics are different from the engine the
 * detector author had in mind.
 */
export function checkDatabaseContext(schema, database) {
  const out = []
  const wants = [
    ['store-context-field', schema, /\|\s*`store_context`\s*\|[^\n]*database-and-data-stores/,
      '_schema.md must require store_context on database findings'],
    ['store-context-shape', schema, /`store_id`, `family`, `engine`, `deployment_variant`, `adapter_id`,[\s\S]{0,120}`detection_evidence\[\]` and `confidence` are required/,
      '_schema.md must require every field in the immutable Stage-1 store context'],
    ['principal-path-field', schema, /\|\s*`principal_path`\s*\|[^\n]*database-and-data-stores/,
      '_schema.md must require the authenticated-to-effective principal path'],
    ['enforcement-plane-field', schema, /\|\s*`enforcement_plane`\s*\|[^\n]*database-and-data-stores/,
      '_schema.md must say where the database invariant is enforced'],
    ['adapter-rule-source', schema, /`adapter_rule_id`[\s\S]{0,500}?`semantic_source`/,
      '_schema.md must bind version-sensitive claims to an adapter rule and primary source'],
    ['inventory-cannot-clear', schema, /inventory-only[\s\S]{0,300}?cannot (?:produce a )?clearance/i,
      '_schema.md must forbid an ambiguous/inventory-only adapter from clearing a candidate'],
    ['unknown-version-cap', schema, /engine_version: unknown[\s\S]{0,500}?capped at Medium/,
      '_schema.md must cap an unresolved engine/version semantic premise'],
    ['sql-does-not-select', database, /`\.sql` alone never selects\s+an adapter/,
      'the database lens must forbid dialect selection from a .sql filename alone'],
    ['evidence-isolated-per-store', database, /treat each `store_id` as an[\s\S]{0,300}?never merge clearance evidence\s+between stores/,
      'the database lens must isolate evidence and coverage per store'],
    ['adapter-contract', database, /_database-adapters\/contract\.md/,
      'the database lens must load the adapter contract before a selected adapter'],
    ['not-assessed-not-clean', database, /NOT ASSESSED[\s\S]{0,200}?never receives a clean result/,
      'an unsupported store must render NOT ASSESSED rather than a generic clean result'],
  ]
  for (const [rule, text, pattern, message] of wants) {
    if (!pattern.test(text)) out.push({ rule, message })
  }
  return out
}

// --- direction 1: the shipped contract states both rules ---

test('the shipped contract states the existence-first ordering rule at every site', () => {
  const found = checkExistenceFirst(read(SCHEMA), read(HARNESS))
  assert.deepEqual(found.map((v) => `${v.rule}: ${v.message}`), [])
})

test('the shipped contract states the contingent: reachability value at every site', () => {
  const found = checkContingentReachability(read(SCHEMA), read(SKILL), read(CHAINING), read(THREAT_MODEL))
  assert.deepEqual(found.map((v) => `${v.rule}: ${v.message}`), [])
})

test('the shipped contract binds database findings to one profiled store and adapter', () => {
  const found = checkDatabaseContext(read(SCHEMA), read(DATABASE))
  assert.deepEqual(found.map((v) => `${v.rule}: ${v.message}`), [])
})

test('_schema.md and _harness.md agree on what an unlocatable artifact grades as', () => {
  // The two documents state the same rule in two voices. The failure this guards
  // against is one of them being softened to INCONCLUSIVE, which would report at
  // Medium what has to be withdrawn.
  //
  // Asserted as an explicit rejection rather than as the absence of the word:
  // _schema.md names INCONCLUSIVE in this passage on purpose, to say what the
  // grade is not, and an absence check would forbid the sentence that carries the
  // distinction.
  for (const [name, text] of [[SCHEMA, read(SCHEMA)], [HARNESS, read(HARNESS)]]) {
    const window = /cannot be located[\s\S]{0,400}/.exec(text)
    assert.ok(window, `${name}: no statement about an artifact that cannot be located`)
    assert.match(window[0], /NOT_REPRODUCED/, `${name}: the unlocatable case must grade NOT_REPRODUCED`)
  }
  assert.match(
    read(SCHEMA),
    /deliberately not `INCONCLUSIVE`/,
    `${SCHEMA}: the unlocatable case must reject INCONCLUSIVE in as many words, or a reader will reach for it`,
  )
})

// --- direction 2: each rule fails when it is removed ---

test('every existence-first rule fires when its statement is deleted', () => {
  const schema = read(SCHEMA)
  const harness = read(HARNESS)
  const removals = [
    ['ordering-rule', () => [schema.replace(/Existence first — an ordering rule/, 'Existence, one more thing'), harness]],
    ['before-the-argument', () => [schema.replace(/before any argument about reachability, severity or impact/i, 'at some point'), harness]],
    ['not-located-is-not-reproduced', () => [schema.replace(/NOT_REPRODUCED/g, 'INCONCLUSIVE'), harness]],
    ['recorded-field', () => [schema.replace(/`existence_check`/g, '`checked`'), harness]],
    ['invariant', () => [schema.replace(/No `verification_status` is assigned without `existence_check`/, 'Statuses are assigned carefully'), harness]],
    ['harness-ordering', () => [schema, harness.replace(/Existence precedes tier/, 'Tier first')]],
    ['harness-disposition', () => [schema, harness.replace(/cannot be located is `NOT_REPRODUCED`/, 'cannot be located is awkward')]],
  ]
  for (const [rule, doctor] of removals) {
    const [s, h] = doctor()
    const found = checkExistenceFirst(s, h)
    assert.ok(
      found.some((v) => v.rule === rule),
      `deleting the "${rule}" statement produced no violation — the check does not fire on the input it exists for`,
    )
  }
})

test('every contingent-reachability rule fires when its statement is deleted', () => {
  const schema = read(SCHEMA)
  const skill = read(SKILL)
  const chaining = read(CHAINING)
  const threatModel = read(THREAT_MODEL)
  const removals = [
    // The row that declares the value, doctored on its own cell. The previous
    // pattern survived this edit because two rows below quote the same field name
    // beside the same value; this one must not.
    ['value-declared', () => [schema.replace(/entry point name, `contingent:<entry point name>`, or the literal/, 'entry point name or the literal'), skill, chaining, threatModel]],
    ['fact-required', () => [schema.replace(/`contingent_fact`/g, '`notes`'), skill, chaining, threatModel]],
    ['query-required', () => [schema.replace(/`contingent_query`/g, '`notes`'), skill, chaining, threatModel]],
    ['still-caps', () => [schema.replace(/`contingent:` value implies `effective_severity` is at most Medium/, '`contingent:` is graded on its merits'), skill, chaining, threatModel]],
    ['queue-position', () => [schema.replace(/`contingent:` records precede `unknown` ones/g, 'order is left to the reader'), skill, chaining, threatModel]],
    ['gate-covers-it', () => [schema, skill.replace(/`reachable_from: unknown` or `contingent:` caps/, '`reachable_from: unknown` caps'), chaining, threatModel]],
    ['queue-keeps-capped-findings', () => [schema, skill.replace(/including those capped to Medium by the gate/, 'except those the gate capped'), chaining, threatModel]],
    ['chain-cap', () => [schema, skill, chaining.replace(/`contingent:` value caps the composition at Medium/, '`contingent:` value is composed on its merits'), threatModel]],
    ['entry-point-table', () => [schema, skill, chaining, threatModel.replace(/`contingent:<entry point>` form with `contingent_fact` and `contingent_query`/, '`unknown`')]],
    ['critical-row', () => [schema, skill, chaining, threatModel.replace(/that caveat has a home in the record/, 'that caveat goes nowhere')]],
  ]
  for (const [rule, doctor] of removals) {
    const [s, k, c, t] = doctor()
    const found = checkContingentReachability(s, k, c, t)
    assert.ok(
      found.some((v) => v.rule === rule),
      `deleting the "${rule}" statement produced no violation — the check does not fire on the input it exists for`,
    )
  }
})

test('every database-context rule fires when its statement is deleted', () => {
  const schema = read(SCHEMA)
  const database = read(DATABASE)
  const removals = [
    ['store-context-field', () => [schema.replace(/`store_context`/g, '`store_notes`'), database]],
    ['store-context-shape', () => [schema.replace(/`store_id`, `family`, `engine`/, '`store_id`, `engine`'), database]],
    ['principal-path-field', () => [schema.replace(/`principal_path`/g, '`identity_notes`'), database]],
    ['enforcement-plane-field', () => [schema.replace(/`enforcement_plane`/g, '`control_notes`'), database]],
    ['adapter-rule-source', () => [schema.replace(/`adapter_rule_id`/g, '`rule_notes`'), database]],
    ['inventory-cannot-clear', () => [schema.replace(/cannot produce a clearance/, 'may clear a candidate'), database]],
    ['unknown-version-cap', () => [schema.replace(/engine_version: unknown/, 'engine_version: resolved'), database]],
    ['sql-does-not-select', () => [schema, database.replace(/`\.sql` alone never selects\s+an adapter/, 'a SQL file selects the SQL adapter')]],
    ['evidence-isolated-per-store', () => [schema, database.replace(/never merge clearance evidence\s+between stores/, 'merge clearance evidence between stores')]],
    ['adapter-contract', () => [schema, database.replace(/_database-adapters\/contract\.md/g, '_database-adapters')]],
    ['not-assessed-not-clean', () => [schema, database.replace(/never receives a clean result/, 'may receive a clean result')]],
  ]
  for (const [rule, doctor] of removals) {
    const [s, d] = doctor()
    const found = checkDatabaseContext(s, d)
    assert.ok(
      found.some((v) => v.rule === rule),
      `deleting the "${rule}" statement produced no violation - the check does not fire on the input it exists for`,
    )
  }
})

test('a document with no contingent: rule at all reports every one of them', () => {
  // The zero-row companion to the existence-first case below. A doctored copy
  // proves a rule fires; this proves the checker is reading the file it thinks it
  // is, which is the failure mode that made correct work look broken in this
  // project more than once.
  const found = checkContingentReachability('# not the contract\n', '# not the skill\n', '# not a lens\n', '# not a lens\n')
  assert.equal(found.length, 11)
})

test('a contract document with neither rule reports every one of them', () => {
  // The zero-row case the corpus warns about everywhere: a checker pointed at the
  // wrong text must report loudly rather than pass.
  const found = checkExistenceFirst('# not the contract\n', '# not the harness\n')
  assert.equal(found.length, 10)
  assert.deepEqual(found.map((v) => v.rule).slice(0, 3), ['ordering-rule', 'before-the-argument', 'not-located-is-not-reproduced'])
})

test('documents with no database context report every database contract rule', () => {
  const found = checkDatabaseContext('# not the schema\n', '# not the database lens\n')
  assert.equal(found.length, 11)
})
