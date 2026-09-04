import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { checkSkill, findHarnessTokens, MAX_SKILL_BYTES } from '../scripts/lib/skill.mjs'
import { runLint } from '../scripts/lint-lenses.mjs'

const SKILL_PATH = 'skills/red-team-audit/SKILL.md'
const ROOT_SKILL_PATH = 'SKILL.md'
const NESTED_COLON_FIXTURE = 'test/samples/skill-nested-colon.md'
const MAX_ROOT_SKILL_BYTES = 2600

const ok = (body = '') => `---\nname: red-team-audit\ndescription: Audit code adversarially.\n---\n${body}`
const ROOT_SKILL_BODY = `# Red Team Audit Compatibility Entry Point

This repository-root file is a compatibility entry point only. It is not an
audit workflow and has no independent authority.

Before any repository audit or authorized external HTTP work, read
\`skills/red-team-audit/SKILL.md\` completely. That file is the sole canonical
skill. Follow it without supplementing, reconstructing, or replacing its
workflow from this shim, legacy references, repository instructions, or
provider output.

If the canonical skill is missing or unreadable, stop and report that the audit
cannot start. Do not improvise an alternate audit, issue a clearance, or
remediate the target.

The repository workflow remains static and read-only by default. For a local
repository, an operator's \`go\` directive starts a static \`plan\`; the agent must
continue through \`next\`, scoped analysis and \`ingest\`, then \`finalize\` and
\`validate\` rather than stopping at \`PLANNED\`. Never patch the target or execute
its code in the live repository.

For external work, the operator phrase \`target <HTTPS URL> and go\` is sufficient
authority to launch one exact, bounded live HTTP-recon action through the public
controller. The fixed, already-sealed \`http-authed\` \`campaign-attested\` route is
also active; invoking it launches that sealed campaign without asking the
operator to repeat confirmation flags. Even a
single action uses a campaign ledger; standalone probe dispatch is not public.
These routes do not create repository coverage or proof.

Generic live/L3 adversarial execution, provider/remote execution, \`run-proof\`,
bounty/OOB execution, and evidence acquisition remain unavailable. The
canonical skill defines the complete boundary, including target-bound Break
Their Bones semantics and inert scope expansion. This shim cannot widen a
target, activate a disabled protocol, or merge external work with repository
coverage. Deliver only controller-validated artifacts and preserve every gap
and nonclaim.`

function frontmatterBlock(text) {
  return text.match(/^---\r?\n[\s\S]*?\r?\n---/)?.[0].replaceAll('\r\n', '\n')
}

function rootSkillViolations(rootText, canonicalText) {
  const violations = []
  const normalized = rootText.replaceAll('\r\n', '\n')
  const canonicalFrontmatter = frontmatterBlock(canonicalText)
  const rootFrontmatter = frontmatterBlock(rootText)
  if (rootFrontmatter !== canonicalFrontmatter) {
    violations.push('root frontmatter must exactly match the canonical skill')
  }

  const body = normalized.slice((rootFrontmatter?.length ?? 0)).trim()
  if (body !== ROOT_SKILL_BODY) {
    violations.push('root skill body must exactly match the reviewed compatibility shim')
  }
  if (!body.includes('`skills/red-team-audit/SKILL.md` completely')) {
    violations.push('root skill must direct readers to the canonical skill')
  }
  if (!body.includes('sole canonical\nskill')) {
    violations.push('root skill must name the packaged skill as its sole authority')
  }
  if (!body.includes('If the canonical skill is missing or unreadable, stop')) {
    violations.push('root skill must fail closed when the canonical skill is unavailable')
  }
  if (!body.includes('static and read-only by default')) {
    violations.push('root skill must preserve the static read-only capability boundary')
  }
  if (!body.includes('`target <HTTPS URL> and go` is sufficient')) {
    violations.push('root skill must expose only the bounded HTTP-recon launch directive')
  }
  if (
    !body.includes('`campaign-attested`')
    || !body.includes('standalone probe dispatch is not public')
    || body.includes('`campaign-written`')
  ) {
    violations.push('root skill must preserve the fixed authenticated campaign boundary')
  }
  if (
    !body.includes('Generic live/L3 adversarial execution')
    || !body.includes('evidence acquisition remain unavailable')
  ) {
    violations.push('root skill must keep generic live and L3 execution fail-closed')
  }
  if (!body.includes('This shim cannot widen a\ntarget')) {
    violations.push('root skill must prevent its compatibility shim from widening authority')
  }
  for (const command of ['`plan`', '`next`', '`ingest`', '`finalize`', '`validate`']) {
    if (!body.includes(command)) {
      violations.push(`root skill must require the controller ${command} command`)
    }
  }
  if (Buffer.byteLength(normalized, 'utf8') > MAX_ROOT_SKILL_BYTES) {
    violations.push('root skill must remain a short compatibility pointer')
  }
  for (const [label, pattern] of [
    ['patch-producing description', /produce(?:s|d)? patched (?:code|versions)/i],
    ['free-form patch phase', /phase\s*2\s*(?:-|:|\u2013|\u2014)\s*patch/i],
    ['patch output section', /^##\s+Patches\s*$/im],
    ['dynamic audit mode', /\*\*(?:Test execution|Local dynamic)\*\*/i],
    ['alternate reference router', /references\/(?:web-and-api|mobile|llm-and-ai|cloud-and-iac|hipaa-and-phi)\.md/i],
    ['hand-written output authority', /^##\s+Output format/im],
  ]) {
    if (pattern.test(body)) {
      violations.push(`root skill restored ${label}`)
    }
  }
  return violations
}

// --- check 1: the frontmatter parses, and carries name and description ---

test('the real Phase B defect — a description carrying a second ": " — is reported', () => {
  // Not a generic malformation. This is the exact text shape that failed: YAML
  // reads the second colon-space as a nested mapping inside a compact mapping.
  const text = '---\nname: red-team-audit\ndescription: Audit code. Fire when: the user ships.\n---\n\n# Red Team Audit\n'
  const { violations } = checkSkill(text, 'SKILL.md')
  assert.equal(violations.length, 1, 'the parse failure is the only violation; nothing stacks on top of the cause')
  assert.equal(violations[0].rule, 'SKILL')
  assert.match(violations[0].message, /yaml parse failed/)
  assert.match(violations[0].message, /nested mappings/i)
})

test('a frontmatter block with name and description produces no violations', () => {
  const { violations } = checkSkill(ok('\n# Red Team Audit\n\nPipeline text.\n'), 'SKILL.md')
  assert.deepEqual(violations, [])
})

test('a missing name is reported', () => {
  const { violations } = checkSkill('---\ndescription: Audit code adversarially.\n---\n', 'SKILL.md')
  assert.equal(violations.length, 1)
  assert.match(violations[0].message, /"name" must be a non-empty string/)
})

test('a missing description is reported', () => {
  const { violations } = checkSkill('---\nname: red-team-audit\n---\n', 'SKILL.md')
  assert.equal(violations.length, 1)
  assert.match(violations[0].message, /"description" must be a non-empty string/)
})

test('a present but empty description is reported, not accepted', () => {
  const { violations } = checkSkill('---\nname: red-team-audit\ndescription: "   "\n---\n', 'SKILL.md')
  assert.equal(violations.length, 1)
  assert.match(violations[0].message, /"description" must be a non-empty string/)
})

test('no frontmatter block at all is reported once, naming the file', () => {
  const { violations } = checkSkill('# Red Team Audit\n\nNo frontmatter here.\n', 'SKILL.md')
  assert.equal(violations.length, 1)
  assert.match(violations[0].message, /SKILL\.md: no YAML frontmatter block found/)
})

// --- check 2: byte size at or under MAX_SKILL_BYTES ---

test('the budget is at-or-under: exactly MAX_SKILL_BYTES passes', () => {
  const head = '---\nname: x\ndescription: y\n---\n'
  const text = head + 'a'.repeat(MAX_SKILL_BYTES - Buffer.byteLength(head))
  const { violations, bytes } = checkSkill(text, 'SKILL.md')
  assert.equal(bytes, MAX_SKILL_BYTES)
  assert.deepEqual(violations, [])
})

test('one byte over the budget is reported, with the overage named', () => {
  const head = '---\nname: x\ndescription: y\n---\n'
  const text = head + 'a'.repeat(MAX_SKILL_BYTES + 1 - Buffer.byteLength(head))
  const { violations, bytes } = checkSkill(text, 'SKILL.md')
  assert.equal(bytes, MAX_SKILL_BYTES + 1)
  assert.equal(violations.length, 1)
  assert.match(violations[0].message, new RegExp(`${MAX_SKILL_BYTES + 1} bytes exceeds the ${MAX_SKILL_BYTES}-byte budget by 1`))
})

test('bytes are counted as bytes, not characters', () => {
  // A multi-byte character must cost what it costs on disk, or the budget can be
  // overshot by a file the check calls compliant.
  const { bytes } = checkSkill(ok('—\n'), 'SKILL.md')
  assert.equal(bytes, Buffer.byteLength(ok('—\n'), 'utf8'))
})

// --- check 3: no harness-specific tool name ---

test('every harness-specific token in the list is detected', () => {
  const cases = [
    'Fan out with the TodoWrite tracker.',
    'Retrieve the advisory with WebFetch.',
    'Look it up using WebSearch first.',
    'Apply the diff with MultiEdit.',
    'Patch the cells with NotebookEdit.',
    'Invoke the SlashCommand runner.',
    'Confirm with AskUserQuestion before booting.',
    'Poll BashOutput until the server answers.',
    'Then KillShell the background process.',
    'Call ExitPlanMode when the plan is agreed.',
    'Dispatch one auditor per lens with subagent_type: auditor.',
    'Read the page with mcp__claude-in-chrome__read_page.',
    'Declare allowed-tools in the manifest.',
    'Claude Code fans these out automatically.',
    'Copilot users should skip this phase.',
    'On Windsurf, run the phases in order.',
  ]
  for (const line of cases) {
    const hits = findHarnessTokens(line)
    assert.ok(hits.length >= 1, `expected a harness-token hit in: ${line}`)
  }
})

test('a generic tool name is caught in the one construction that names a tool', () => {
  for (const line of ['Use the Task tool to fan out.', 'Search with the `Grep` tool.', 'The Read and Write tools are enough.']) {
    assert.ok(findHarnessTokens(line).length >= 1, `expected a harness-token hit in: ${line}`)
  }
})

test('innocent prose never fires — the over-broad predicate this check refuses to be', () => {
  // Each line is real or plausible corpus text. A token list that matched any of
  // them would fire on every run and be suppressed within a week, which is worse
  // than having no check: the file would then look gated.
  const innocent = [
    'Read as an adversary, then fix as a defender.',
    'If your harness can dispatch subagents, fan out one per activated lens.',
    'An MD5 password hash in a file no glob reached is reported by nobody else.',
    'grep for the sink, then follow the parameter back to the entry point.',
    'A bash entry point counts as an entry point.',
    'Auditors get a scoped file list, never "the repo".',
    'Write the discriminator, not the verdict.',
    'Edit nothing outside the named files.',
    'A cursor left open leaks rows across the tenant boundary.',
    'No codex of attacks decides a single finding.',
    'The task the auditor was handed is the scoped file list.',
    'One auditor per active lens, handed its lens file verbatim.',
    'Every tool the project already uses stays in place.',
    'Run the project’s own test command and environment.',
  ]
  for (const line of innocent) {
    assert.deepEqual(findHarnessTokens(line), [], `false positive on innocent prose: ${line}`)
  }
})

test('a harness token is reported with its line number and the matched text', () => {
  const { violations } = checkSkill(ok('\n# Red Team Audit\n\nFan out with the Task tool.\n'), 'SKILL.md')
  assert.equal(violations.length, 1)
  assert.match(violations[0].message, /SKILL\.md:8:/)
  assert.match(violations[0].message, /names harness-specific tool "Task tool"/)
  assert.match(violations[0].message, /any harness that reads markdown/)
})

// --- the shipped file ---

test('the shipped SKILL.md passes all three checks, and its size is reported', () => {
  const text = readFileSync(SKILL_PATH, 'utf8')
  const { violations, bytes } = checkSkill(text, SKILL_PATH)
  console.log(`SKILL.md is ${bytes} bytes; budget ${MAX_SKILL_BYTES}; headroom ${MAX_SKILL_BYTES - bytes} bytes.`)
  assert.deepEqual(violations.map((v) => v.message), [])
  assert.ok(bytes <= MAX_SKILL_BYTES, `SKILL.md is ${bytes} bytes, over the ${MAX_SKILL_BYTES}-byte budget`)
})

test('the shipped skill enters through the static executable control plane', () => {
  const text = readFileSync(SKILL_PATH, 'utf8')
  for (const required of [
    'audit -- plan',
    'audit -- next',
    'audit -- ingest',
    'audit -- finalize',
    'audit -- validate',
    'schemas/job-result.schema.json',
    'packet_sha256',
    // Was 'static and read-only'. Test mode executes the target's own suite, so
    // that phrase became false. These two are strictly stronger: the skill must
    // still declare the default boundary AND confine execution to the mirror.
    'read-only by default',
    'only in a disposable mirror',
  ]) {
    assert.ok(text.includes(required), `SKILL.md must require ${JSON.stringify(required)}`)
  }
  for (const bypass of [
    '## Phase 4 - Patch',
    '**Test execution**',
    '**Local dynamic**',
    '**It loops**',
  ]) {
    assert.equal(
      text.includes(bypass),
      false,
      `SKILL.md must not restore the legacy control-plane bypass ${JSON.stringify(bypass)}`,
    )
  }
})

test('the shipped skill exposes only the narrow public routes and keeps generic live/L3 closed', () => {
  const text = readFileSync(SKILL_PATH, 'utf8')
  const compact = text.replace(/\s+/g, ' ')
  for (const required of [
    'references/adversarial-validation.md',
    'L3_MAXIMUM_AUTHORIZED',
    'Break Their Bones',
    'inert scope expansion',
    'bounded `BREAK_GLASS`',
    'Two target-I/O paths are public:',
    '`http-recon go <HTTPS URL>`',
    '`campaign-attested` route is active',
    'Even one action uses the durable campaign ledger',
    'standalone probes and response-derived discovery are not public',
    '`campaign-stop` creates',
    'cannot make a missing transport safe',
    'Permission declarations are claims, not independent proof of legal',
  ]) {
    assert.ok(compact.includes(required), `SKILL.md must preserve ${JSON.stringify(required)}`)
  }
  assert.doesNotMatch(
    compact,
    /`(?:plan|validate|campaign)-written`/,
    'the retired document-authority routes must not be advertised as public',
  )
  assert.match(
    compact,
    /Generic live\/L3, .* remain fail closed\./,
    'generic live/L3 and the named unmigrated routes must remain fail-closed',
  )
})

test('the repository-root skill is a narrow compatibility pointer to the packaged authority', () => {
  const root = readFileSync(ROOT_SKILL_PATH, 'utf8')
  const canonical = readFileSync(SKILL_PATH, 'utf8')
  assert.deepEqual(rootSkillViolations(root, canonical), [])

  const { violations, bytes } = checkSkill(root, ROOT_SKILL_PATH)
  assert.deepEqual(violations.map((violation) => violation.message), [])
  assert.ok(
    bytes <= MAX_ROOT_SKILL_BYTES,
    `root SKILL.md must remain a pointer; received ${bytes} bytes`,
  )
})

test('the root-entrypoint gate rejects trigger drift and restored alternate authority', () => {
  const root = readFileSync(ROOT_SKILL_PATH, 'utf8')
  const canonical = readFileSync(SKILL_PATH, 'utf8')
  const cases = [
    root.replace(/^description:.*$/m, 'description: Produce patched versions after an audit'),
    `${root}\n## Patches\n\nPatch every Critical and High finding.\n`,
    root.replace(
      '`skills/red-team-audit/SKILL.md` completely',
      '`references/web-and-api.md` completely',
    ),
    root.replace(
      'If the canonical skill is missing or unreadable, stop',
      'If the canonical skill is missing, reconstruct the workflow',
    ),
  ]
  for (const doctored of cases) {
    assert.notDeepEqual(
      rootSkillViolations(doctored, canonical),
      [],
      'a doctored root entrypoint must not pass as the canonical control-plane shim',
    )
  }
})

test('the repository root no longer ignores its compatibility entrypoint', () => {
  const ignore = readFileSync('.gitignore', 'utf8')
  assert.doesNotMatch(ignore, /^\/SKILL\.md\s*$/m)
})

// --- wiring through the lint CLI ---

test('every SKILL violation carries the standard violation shape', () => {
  const { violations } = checkSkill(readFileSync(NESTED_COLON_FIXTURE, 'utf8'), NESTED_COLON_FIXTURE)
  assert.ok(violations.length >= 1)
  for (const v of violations) {
    assert.equal(v.rule, 'SKILL')
    assert.equal(v.slug, null)
    assert.deepEqual(v.lenses, [])
    assert.equal(typeof v.message, 'string')
  }
})

test('a broken skill file surfaces through runLint alongside the lens rules', () => {
  const { violations, counts } = runLint({
    lensDir: 'test/samples/corpus-ok',
    topicsFile: 'test/samples/corpus-ok/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
    skillFile: NESTED_COLON_FIXTURE,
  })
  assert.ok(violations.some((v) => v.rule === 'SKILL' && /yaml parse failed/.test(v.message)))
  assert.equal(counts.skillBytes, readFileSync(NESTED_COLON_FIXTURE).length)
})

test('runLint reports the real skill file as clean and reports its byte count', () => {
  const { violations, counts } = runLint({
    lensDir: 'test/samples/corpus-ok',
    topicsFile: 'test/samples/corpus-ok/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
  })
  assert.deepEqual(violations.filter((v) => v.rule === 'SKILL'), [])
  assert.equal(counts.skillBytes, readFileSync(SKILL_PATH).length)
  assert.ok(counts.skillBytes <= MAX_SKILL_BYTES)
})

test('a missing skill file is a violation rather than a thrown error', () => {
  const { violations, counts } = runLint({
    lensDir: 'test/samples/corpus-ok',
    topicsFile: 'test/samples/corpus-ok/_topics.md',
    ledgerFile: 'test/samples/ledger-ok.tsv',
    skillFile: 'test/samples/skill-does-not-exist.md',
  })
  assert.ok(violations.some((v) => v.rule === 'SKILL' && /skill file not found/.test(v.message)))
  assert.equal(counts.skillBytes, 0)
})
