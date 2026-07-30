import { parseLens } from './frontmatter.mjs'

// SKILL.md is the entry point, and until this rule existed it was the one tracked
// file no gate read: the lint walks `lenses/*.md`, so a defect here shipped green.
// The failure that motivated the rule is not hypothetical. A drafted `description`
// carried a second `": "` inside its value, YAML read that as a nested mapping,
// the repo's own parser rejected the block — and the skill would not have loaded
// at all. Three checks, each one a way this file can be broken without any lens
// changing: the frontmatter parses and carries its two keys, the file fits the
// budget, and its text names no tool that only one harness has.

export const MAX_SKILL_BYTES = 8000

// Harness-specific identifiers. The portability claim being enforced is narrow
// and checkable: the orchestrator's text names no tool belonging to a particular
// harness, so the skill runs anywhere markdown is read and only wall-clock time
// differs when subagents are unavailable.
//
// THE SELECTION RULE IS THE WHOLE DESIGN. A token qualifies only if its spelling
// has no ordinary-English, ordinary-Unix or ordinary-security-prose reading. An
// over-broad token fires on innocent text, fires on every run, and gets
// suppressed — at which point the check is worse than absent, because the file
// now looks gated. Every entry below is either a compound identifier no prose
// produces by accident, a namespace prefix, or a product name.
const HARNESS_IDENTIFIERS = [
  // Tool names. CamelCase compounds: no sentence produces these accidentally.
  'TodoWrite',
  'WebFetch',
  'WebSearch',
  'MultiEdit',
  'NotebookEdit',
  'SlashCommand',
  'AskUserQuestion',
  'BashOutput',
  'KillShell',
  'ExitPlanMode',
  // Dispatch and manifest plumbing. `subagent_type` is the parameter that names a
  // harness's agent registry; `mcp__` prefixes every tool a server exposes;
  // `allowed-tools` is a manifest key. The hyphenated and underscored spellings
  // are what make them safe to match — the corresponding prose ("subagents",
  // "allowed tools") is portable and must not fire. See the rejected list below.
  'subagent_type',
  'mcp__',
  'allowed-tools',
  // Products. Naming the runner in normative text is the defect this check is
  // about, whichever runner it is.
  'Claude Code',
  'Copilot',
  'Windsurf',
]

// Deliberately NOT tokens, because each has an innocent reading this corpus
// actually uses, and a check that fires on them fires forever:
//
//   Read, Write, Edit, Task, Agent   — "Read as an adversary", "the task the
//                                      auditor was handed", plain English
//   Bash, Grep, Glob                 — real Unix tools and real prose: "a bash
//                                      entry point", "grep for the sink", "a
//                                      file no glob reached"
//   subagent                         — the portable sentence "if your harness can
//                                      dispatch subagents" is exactly what makes
//                                      the skill harness-independent; banning the
//                                      word would fire on the fix
//   Cursor, Codex                    — a database cursor and an ordinary noun
//   Skill, Tool, Plugin              — generic
//
// The generic names are still reachable in the one construction that unambiguously
// names a harness tool: the bare name immediately followed by the word "tool".
// "use the Task tool to fan out" is caught; "Read as an adversary" is not.
const GENERIC_TOOL_NAMES = ['Agent', 'Bash', 'Edit', 'Glob', 'Grep', 'Read', 'Task', 'Write']

function identifierPattern(token) {
  const escaped = token.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  // A token ending in `_` or `-` is a namespace prefix (`mcp__browser_batch`), so
  // it must be allowed to run into what follows. Every other token is a whole
  // identifier and gets a trailing boundary, which is what keeps `Task` out of
  // "Tasks" territory and `mcp__` matching at all.
  const trailing = /[_-]$/.test(token) ? '' : '(?![A-Za-z0-9_])'
  return new RegExp(`(?<![A-Za-z0-9_])${escaped}${trailing}`, 'i')
}

const HARNESS_PATTERNS = [
  ...HARNESS_IDENTIFIERS.map((token) => ({ label: token, pattern: identifierPattern(token) })),
  {
    label: '<generic tool name> followed by "tool"',
    // Optional backticks on either side, because the reference usually arrives as
    // "the `Task` tool".
    pattern: new RegExp(`(?<![A-Za-z0-9_])(?:${GENERIC_TOOL_NAMES.join('|')})\`?\\s+\`?tools?(?![A-Za-z0-9_])`, 'i'),
  },
]

// One hit per line per pattern, with the matched text quoted so the fix is
// obvious from the message alone. The whole file is scanned, fenced blocks
// included: an example telling the auditor which tool to call is an instruction,
// and a non-portable instruction inside a fence is still non-portable.
export function findHarnessTokens(text) {
  const hits = []
  text.split(/\r?\n/).forEach((line, i) => {
    for (const { label, pattern } of HARNESS_PATTERNS) {
      const m = pattern.exec(line)
      if (m) hits.push({ match: m[0], label, line: i + 1 })
    }
  })
  return hits
}

const REQUIRED_FRONTMATTER = ['name', 'description']

// Pure over the file's text: the caller does the I/O, the same way the registry
// and ledger rules take parsed input. `bytes` is returned rather than only
// asserted, so the CLI can print the number and the remaining headroom instead of
// reporting a budget nobody can see the distance to.
export function checkSkill(text, filename = 'SKILL.md') {
  const violations = []
  const push = (message) => violations.push({ rule: 'SKILL', slug: null, lenses: [], message })
  const bytes = Buffer.byteLength(text, 'utf8')

  // Reuses the parser every lens goes through, which is the parser that rejected
  // the real defect. A second YAML reader here could disagree with it, and then a
  // file could pass lint and still fail to load.
  const parsed = parseLens(text, filename)
  for (const message of parsed.errors) push(message)

  // parseLens returns early with a single error and an empty frontmatter when the
  // block is missing or will not parse. Stacking "missing name" on top of that
  // buries the cause, so the key checks run only when a mapping came back.
  const gotMapping = Object.keys(parsed.frontmatter).length > 0
  if (gotMapping || !parsed.errors.length) {
    for (const key of REQUIRED_FRONTMATTER) {
      const value = parsed.frontmatter[key]
      if (typeof value !== 'string' || !value.trim()) {
        push(`${filename}: frontmatter "${key}" must be a non-empty string`)
      }
    }
  }

  if (bytes > MAX_SKILL_BYTES) {
    push(`${filename}: ${bytes} bytes exceeds the ${MAX_SKILL_BYTES}-byte budget by ${bytes - MAX_SKILL_BYTES}`)
  }

  for (const hit of findHarnessTokens(text)) {
    push(`${filename}:${hit.line}: names harness-specific tool "${hit.match}" (${hit.label}); the skill must run on any harness that reads markdown`)
  }

  return { violations, bytes }
}
