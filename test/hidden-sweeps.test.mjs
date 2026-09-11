import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync, readdirSync } from 'node:fs'
import { join } from 'node:path'

const LENS_DIR = 'skills/last-aperture/lenses'
const CICD = join(LENS_DIR, 'cicd-and-supply-chain.md')

const CONTROL_OPERATORS = new Set(['|', '|&', '&&', '||', ';', '(', ')', '{', '}', '$(', '<('])
const COMMAND_PREFIXES = new Set([
  'if',
  'elif',
  'then',
  'while',
  'until',
  'do',
  'time',
  'command',
  'builtin',
  'exec',
  'noglob',
])
const LONG_VALUE_OPTIONS = new Set([
  '--after-context',
  '--before-context',
  '--color',
  '--colors',
  '--context',
  '--context-separator',
  '--encoding',
  '--engine',
  '--field-context-separator',
  '--field-match-separator',
  '--file',
  '--glob',
  '--hostname-bin',
  '--hyperlink-format',
  '--iglob',
  '--max-columns',
  '--max-count',
  '--max-depth',
  '--path-separator',
  '--pre',
  '--pre-glob',
  '--regexp',
  '--replace',
  '--sort',
  '--sortr',
  '--threads',
  '--type',
  '--type-add',
  '--type-not',
])
const SHORT_VALUE_OPTIONS = new Set(['A', 'B', 'C', 'E', 'M', 'e', 'f', 'g', 'j', 'm', 'r', 't', 'T'])

/**
 * Yield executable shell statements from shell fences plus standalone inline
 * command spans. Embedded prose such as "run `rg --version` first" is not a
 * runnable statement; a line whose whole payload is a code span is.
 */
function runnableShellSnippets(source) {
  const lines = source.split(/\r?\n/)
  const snippets = []
  let inShellFence = false

  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index]
    if (/^```(?:bash|sh|shell)\s*$/i.test(line)) {
      inShellFence = true
      continue
    }
    if (inShellFence && /^```\s*$/.test(line)) {
      inShellFence = false
      continue
    }

    if (inShellFence) {
      let logical = line
      let end = index
      while (/\\\s*$/.test(logical) && end + 1 < lines.length) {
        end += 1
        logical = `${logical.replace(/\\\s*$/, '')} ${lines[end]}`
      }
      snippets.push({ line: index + 1, source: logical })
      index = end
      continue
    }

    const inline = /^\s*`([^`\r\n]+)`[.!?]?\s*$/.exec(line)
    if (inline && /(?:^|[\s;&|!()])rg(?:\s|$)/.test(inline[1])) {
      snippets.push({ line: index + 1, source: inline[1] })
    }
  }

  return snippets
}

/**
 * A small shell lexer: enough to identify command position without treating
 * pipes and alternation inside quoted rg patterns as control operators.
 */
function shellTokens(source) {
  const tokens = []

  for (let index = 0; index < source.length;) {
    const char = source[index]
    if (/\s/.test(char)) {
      index += 1
      continue
    }
    if (char === '#') break

    const two = source.slice(index, index + 2)
    if (CONTROL_OPERATORS.has(two)) {
      tokens.push({ type: 'operator', value: two, raw: two })
      index += 2
      continue
    }
    if (CONTROL_OPERATORS.has(char) || char === '!') {
      tokens.push({ type: 'operator', value: char, raw: char })
      index += 1
      continue
    }
    const redirection = /^(?:\d+)?(?:<<<|<<|>>|<>|<|>)/.exec(source.slice(index))
    if (redirection) {
      tokens.push({ type: 'redirection', value: redirection[0], raw: redirection[0] })
      index += redirection[0].length
      continue
    }

    const start = index
    let value = ''
    let quote = null
    while (index < source.length) {
      const current = source[index]
      const pair = source.slice(index, index + 2)
      if (
        !quote
        && (/\s/.test(current)
          || CONTROL_OPERATORS.has(current)
          || CONTROL_OPERATORS.has(pair)
          || current === '!'
          || current === '<'
          || current === '>')
      ) {
        break
      }
      if (!quote && (current === "'" || current === '"')) {
        quote = current
        index += 1
        continue
      }
      if (quote && current === quote) {
        quote = null
        index += 1
        continue
      }
      if (current === '\\' && quote !== "'" && index + 1 < source.length) {
        value += source[index + 1]
        index += 2
        continue
      }
      value += current
      index += 1
    }
    tokens.push({ type: 'word', value, raw: source.slice(start, index) })
  }

  return tokens
}

function commandWordIndex(stage) {
  let index = 0
  while (index < stage.length) {
    const token = stage[index]
    if (token.type === 'operator' && token.value === '!') {
      index += 1
      continue
    }
    if (token.type !== 'word') return -1
    if (COMMAND_PREFIXES.has(token.value) || token.value === '[' || token.value === '[[' || token.value === ':') {
      index += 1
      continue
    }
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token.value)) {
      index += 1
      continue
    }
    break
  }

  if (stage[index]?.value === 'env') {
    index += 1
    while (
      stage[index]?.type === 'word'
      && (stage[index].value.startsWith('-') || /^[A-Za-z_][A-Za-z0-9_]*=/.test(stage[index].value))
    ) {
      index += 1
    }
  }
  return index
}

function rgInvocations(source) {
  const tokens = shellTokens(source)
  const invocations = []
  let stage = []
  let readsPipe = false

  const flush = (operator = null) => {
    if (stage.length > 0) {
      const commandIndex = commandWordIndex(stage)
      if (stage[commandIndex]?.type === 'word' && stage[commandIndex].value === 'rg') {
        const commandTokens = stage.slice(commandIndex)
        const args = []
        let skipRedirectTarget = false
        let readsRedirect = false
        for (const token of commandTokens.slice(1)) {
          if (token.type === 'redirection') {
            readsRedirect ||= token.value.includes('<')
            skipRedirectTarget = true
            continue
          }
          if (skipRedirectTarget) {
            skipRedirectTarget = false
            continue
          }
          if (token.type === 'word') args.push(token)
        }
        invocations.push({
          args,
          command: commandTokens.map((token) => token.raw).join(' '),
          readsPipe: readsPipe || readsRedirect,
        })
      }
    }
    stage = []
    readsPipe = operator === '|' || operator === '|&'
  }

  for (const token of tokens) {
    if (token.type === 'operator' && CONTROL_OPERATORS.has(token.value)) {
      flush(token.value)
    } else {
      stage.push(token)
    }
  }
  flush()
  return invocations
}

function analyzeRgArgs(args) {
  const positionals = []
  let endOfOptions = false
  let filesMode = false
  let patternFromOption = false
  let informationalOnly = false

  for (let index = 0; index < args.length; index += 1) {
    const value = args[index].value
    if (endOfOptions) {
      positionals.push(value)
      continue
    }
    if (value === '--') {
      endOfOptions = true
      continue
    }
    if (value === '--files') {
      filesMode = true
      continue
    }
    if (value === '--help' || value === '--version' || value === '--pcre2-version' || value === '--type-list') {
      informationalOnly = true
      continue
    }
    if (value.startsWith('--')) {
      const equals = value.indexOf('=')
      const name = equals === -1 ? value : value.slice(0, equals)
      if (name === '--regexp' || name === '--file') patternFromOption = true
      if (LONG_VALUE_OPTIONS.has(name) && equals === -1) index += 1
      continue
    }
    if (value.startsWith('-') && value !== '-') {
      const flags = value.slice(1)
      for (let offset = 0; offset < flags.length; offset += 1) {
        const flag = flags[offset]
        if (flag === 'e' || flag === 'f') patternFromOption = true
        if (SHORT_VALUE_OPTIONS.has(flag)) {
          if (offset === flags.length - 1) index += 1
          break
        }
      }
      continue
    }
    positionals.push(value)
  }

  const paths = filesMode || patternFromOption ? positionals : positionals.slice(1)
  return {
    filesMode,
    hasHidden: args.some((token) => token.value === '--hidden'),
    hasPath: paths.length > 0,
    informationalOnly,
    paths,
  }
}

function explicitFileOperand(value) {
  if (value === '-') return true
  const variable = /^\$\{?([A-Za-z_][A-Za-z0-9_]*)(?:\[@])?\}?$/.exec(value)
  // Shell syntax cannot prove whether a literal such as `config.d` or
  // `README.md` is a file or a directory. Treat literal operands as potential
  // traversals; adding --hidden is harmless for a single explicit file.
  return Boolean(
    variable
    && /^(?:f|file|files|filename|filenames|candidate|candidates|input|inputs)$/i.test(variable[1]),
  )
}

/**
 * Inspect repository-traversing rg commands in runnable shell statements.
 * Pipe-right filters, xargs consumers, and explicit-file reads are excluded.
 * Every traversal must opt into hidden entries and name its search root.
 */
export function hiddenSweepViolations(file, source) {
  const violations = []

  for (const snippet of runnableShellSnippets(source)) {
    for (const invocation of rgInvocations(snippet.source)) {
      const analysis = analyzeRgArgs(invocation.args)
      // An rg on the right side of a pipe is a stdin filter only when it has no
      // path operand. `producer | rg pattern .` ignores stdin for traversal
      // purposes and must still opt into hidden entries.
      if (invocation.readsPipe && !analysis.hasPath) continue
      if (analysis.informationalOnly) continue
      const explicitFileRead = analysis.hasPath && analysis.paths.every(explicitFileOperand)
      if (explicitFileRead) continue

      const missing = []
      if (!analysis.hasHidden) missing.push('--hidden')
      if (!analysis.hasPath) missing.push('an explicit path operand')
      if (missing.length > 0) {
        violations.push({
          file,
          line: snippet.line,
          command: invocation.command.replace(/\s+/g, ' '),
          missing,
        })
      }
    }
  }
  return violations
}

function braceGlobArgs(args) {
  const globs = []
  for (let index = 0; index < args.length; index += 1) {
    const value = args[index].value
    if (value === '--glob' || value === '--iglob' || value === '-g') {
      if (args[index + 1]?.value.includes('{') && args[index + 1].value.includes('}')) {
        globs.push(`${args[index].raw} ${args[index + 1].raw}`)
      }
      index += 1
      continue
    }
    if (/^(?:--glob|--iglob)=/.test(value) || /^-g.+/.test(value)) {
      if (value.includes('{') && value.includes('}')) globs.push(args[index].raw)
    }
  }
  return globs
}

export function braceGlobViolations(file, source) {
  const violations = []
  for (const snippet of runnableShellSnippets(source)) {
    for (const invocation of rgInvocations(snippet.source)) {
      for (const glob of braceGlobArgs(invocation.args)) {
        violations.push({ file, line: snippet.line, glob })
      }
    }
  }
  return violations
}

const format = ({ file, line, command, missing }) =>
  `${file}:${line}: repository-traversing rg command lacks ${missing.join(' and ')}\n  ${command}`
const formatBrace = ({ file, line, glob }) =>
  `${file}:${line}: rg glob uses a brace alternate that the grep fallback cannot expand\n  ${glob}`

test('the gate fires on a doctored shipped sweep with --hidden removed', () => {
  const source = readFileSync(CICD, 'utf8')
  const good = "rg -n --hidden --glob '**/.github/workflows/*.y*ml'"
  assert.ok(source.includes(good), 'the cicd control sweep changed; update the doctoring target')

  const doctored = source.replace(good, good.replace(' --hidden', ''))
  const violations = hiddenSweepViolations(CICD, doctored)

  assert.equal(violations.length, 1, violations.map(format).join('\n'))
  assert.match(violations[0].command, /pull_request_target/)
})

test('stdin filters and explicit-file checks are not classified as traversals', () => {
  const sample = [
    '```bash',
    "printf '%s\\n' input | rg -v ignored",
    'rg -v ignored < "$f"',
    'rg -q "$PATTERN" "$f"',
    "rg -n --hidden needle . | rg -v ignored",
    '```',
  ].join('\n')
  assert.deepEqual(hiddenSweepViolations('classification-sample.md', sample), [])
})

test('a pipe cannot hide an explicit repository traversal', () => {
  const doctored = [
    '```bash',
    "printf '%s\\n' input | rg -n needle .",
    "printf '%s\\n' input | rg -n --hidden needle .",
    '```',
  ].join('\n')
  const violations = hiddenSweepViolations('pipe-traversal-doctored.md', doctored)

  assert.deepEqual(violations.map(({ line }) => line), [2], violations.map(format).join('\n'))
  assert.deepEqual(violations[0].missing, ['--hidden'])
})

test('control prefixes and chained commands cannot hide a repository traversal', () => {
  const doctored = [
    '```bash',
    'if rg -n needle .; then :; fi',
    '! rg -n --hidden needle',
    'true && rg -n needle .',
    '```',
  ].join('\n')
  const violations = hiddenSweepViolations('control-doctored.md', doctored)

  assert.deepEqual(violations.map(({ line }) => line), [2, 3, 4], violations.map(format).join('\n'))
  assert.deepEqual(violations[0].missing, ['--hidden'])
  assert.deepEqual(violations[1].missing, ['an explicit path operand'])
  assert.deepEqual(violations[2].missing, ['--hidden'])
})

test('a pattern variable is not mistaken for an explicit-file operand', () => {
  const doctored = [
    '```bash',
    'rg --hidden "$PATTERN"',
    'rg -q "$PATTERN" "$f"',
    '```',
  ].join('\n')
  const violations = hiddenSweepViolations('variable-doctored.md', doctored)

  assert.equal(violations.length, 1, violations.map(format).join('\n'))
  assert.equal(violations[0].line, 2)
  assert.deepEqual(violations[0].missing, ['an explicit path operand'])
})

test('hidden directory operands are traversals, not extension-looking files', () => {
  const doctored = [
    '```bash',
    'rg -n needle .github',
    'rg -n needle .sfdx',
    'rg -n needle .sf',
    'rg -n needle config.d',
    'rg -n needle src.v2',
    'rg -n --hidden needle .github',
    '```',
  ].join('\n')
  const violations = hiddenSweepViolations('hidden-directory-doctored.md', doctored)

  assert.deepEqual(violations.map(({ line }) => line), [2, 3, 4, 5, 6], violations.map(format).join('\n'))
  assert.ok(violations.every(({ missing }) => missing.length === 1 && missing[0] === '--hidden'))
})

test('standalone inline commands are gated for hidden traversal and path operands', () => {
  const doctored = [
    'The prose example `rg -n needle .` is not a runnable standalone command.',
    '  `rg -n needle .`',
    '  `rg -n --hidden needle`',
  ].join('\n')
  const violations = hiddenSweepViolations('inline-doctored.md', doctored)

  assert.deepEqual(violations.map(({ line }) => line), [2, 3], violations.map(format).join('\n'))
  assert.deepEqual(violations[0].missing, ['--hidden'])
  assert.deepEqual(violations[1].missing, ['an explicit path operand'])
})

test('the brace-glob gate fires on an engine-dependent shell sweep', () => {
  const doctored = [
    '```bash',
    "rg -n --hidden --glob '**/*.{ts,js}' needle .",
    "rg --hidden --iglob '*.{pem,key}' --files .",
    '```',
  ].join('\n')
  const violations = braceGlobViolations('brace-doctored.md', doctored)
  assert.equal(violations.length, 2, violations.map(formatBrace).join('\n'))
  assert.equal(violations[0].line, 2)
  assert.equal(violations[1].line, 3)
})

test('every shipped repository-traversing rg sweep includes --hidden and an explicit path', () => {
  const violations = readdirSync(LENS_DIR)
    .filter((name) => name.endsWith('.md') && !name.startsWith('_'))
    .flatMap((name) => {
      const file = join(LENS_DIR, name)
      return hiddenSweepViolations(file, readFileSync(file, 'utf8'))
    })

  assert.equal(
    violations.length,
    0,
    `repository sweeps without --hidden or an explicit path:\n${violations.map(format).join('\n')}`,
  )
})

test('no shipped runnable rg sweep uses a brace-alternate glob', () => {
  const violations = readdirSync(LENS_DIR)
    .filter((name) => name.endsWith('.md') && !name.startsWith('_'))
    .flatMap((name) => {
      const file = join(LENS_DIR, name)
      return braceGlobViolations(file, readFileSync(file, 'utf8'))
    })

  assert.equal(
    violations.length,
    0,
    `engine-dependent brace globs:\n${violations.map(formatBrace).join('\n')}`,
  )
})
