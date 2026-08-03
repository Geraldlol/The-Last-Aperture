import { compareCanonicalStrings } from './canonical-order.mjs'

const HORIZONTAL_WHITESPACE = /^[ \t]+|[ \t]+$/g

function trimHorizontal(line) {
  return line.replace(HORIZONTAL_WHITESPACE, '')
}

export function normalizeQuote(text) {
  const lines = String(text).split(/\r\n|\n|\r/).map(trimHorizontal)
  let start = 0
  let end = lines.length
  while (start < end && lines[start] === '') start += 1
  while (end > start && lines[end - 1] === '') end -= 1
  return lines.slice(start, end)
}

export function indexFileLines(content) {
  const text = String(content)
  const lines = []
  const byteStarts = []
  const byteEnds = []
  let byteCursor = 0
  let index = 0
  while (index <= text.length) {
    let breakAt = text.length
    let terminator = 0
    for (let scan = index; scan < text.length; scan += 1) {
      const ch = text[scan]
      if (ch === '\n') {
        breakAt = scan
        terminator = 1
        break
      }
      if (ch === '\r') {
        breakAt = scan
        terminator = text[scan + 1] === '\n' ? 2 : 1
        break
      }
    }
    const line = text.slice(index, breakAt)
    const lineBytes = Buffer.byteLength(line, 'utf8')
    lines.push(line)
    byteStarts.push(byteCursor)
    byteEnds.push(byteCursor + lineBytes)
    byteCursor += lineBytes + (
      terminator === 0
        ? 0
        : Buffer.byteLength(text.slice(breakAt, breakAt + terminator), 'utf8')
    )
    if (terminator === 0) break
    index = breakAt + terminator
  }
  return {
    lines,
    normalized: lines.map(trimHorizontal),
    byteStarts,
    byteEnds,
  }
}

function leadingWhitespaceBytes(line) {
  const trimmedStart = line.length - line.replace(/^[ \t]+/, '').length
  return Buffer.byteLength(line.slice(0, trimmedStart), 'utf8')
}

function trailingWhitespaceBytes(line) {
  const trimmedEnd = line.length - line.replace(/[ \t]+$/, '').length
  return Buffer.byteLength(line.slice(line.length - trimmedEnd), 'utf8')
}

export function matchQuote(content, quoteText, claimedLine) {
  const miss = {
    outcome: 'NOT_LOCATED',
    foundLine: null,
    matchCount: 0,
    startByte: null,
    endByte: null,
  }
  const needle = normalizeQuote(quoteText)
  if (needle.length === 0) return miss

  const file = indexFileLines(content)
  const starts = []
  const limit = file.normalized.length - needle.length
  for (let offset = 0; offset <= limit; offset += 1) {
    let matched = true
    for (let step = 0; step < needle.length; step += 1) {
      if (file.normalized[offset + step] !== needle[step]) {
        matched = false
        break
      }
    }
    if (matched) starts.push(offset)
  }
  if (starts.length === 0) return miss

  const target = Number.isInteger(claimedLine) ? claimedLine - 1 : 0
  let best = starts[0]
  for (const candidate of starts) {
    if (Math.abs(candidate - target) < Math.abs(best - target)) best = candidate
  }

  const lastIndex = best + needle.length - 1
  const startByte = file.byteStarts[best]
    + leadingWhitespaceBytes(file.lines[best])
  const endByte = file.byteEnds[lastIndex]
    - trailingWhitespaceBytes(file.lines[lastIndex])

  return {
    outcome: best === target ? 'LOCATED' : 'LOCATED_OFF_LINE',
    foundLine: best + 1,
    matchCount: starts.length,
    startByte,
    endByte,
  }
}

const MAX_RECORDED_HITS = 16

function inScope(path, scope) {
  return scope.some((prefix) => path === prefix || path.startsWith(`${prefix}/`))
}

export function searchAbsence(entries, claim) {
  const scope = [...claim.scope]
  const fold = claim.kind === 'literal_ci'
  const needle = fold ? claim.pattern.toLowerCase() : claim.pattern

  const searchable = entries
    .filter((entry) =>
      entry.kind === 'text'
      && typeof entry.content === 'string'
      && inScope(entry.path, scope))
    .sort((left, right) => compareCanonicalStrings(left.path, right.path))

  if (searchable.length === 0) {
    return {
      outcome: 'ABSENCE_UNCHECKABLE',
      matchCount: 0,
      searchedFiles: 0,
      hits: [],
    }
  }

  let matchCount = 0
  const hits = []
  for (const entry of searchable) {
    const lines = String(entry.content).split(/\r\n|\n|\r/)
    for (let index = 0; index < lines.length; index += 1) {
      const haystack = fold ? lines[index].toLowerCase() : lines[index]
      if (!haystack.includes(needle)) continue
      matchCount += 1
      if (hits.length < MAX_RECORDED_HITS) {
        hits.push({ path: entry.path, line: index + 1 })
      }
    }
  }

  return {
    outcome: matchCount > 0 ? 'ABSENCE_CONTRADICTED' : 'ABSENCE_HOLDS',
    matchCount,
    searchedFiles: searchable.length,
    hits,
  }
}
