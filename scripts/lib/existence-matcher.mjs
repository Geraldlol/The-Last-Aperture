import { createHash } from 'node:crypto'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { parseEvidenceLocation } from './evidence-locator.mjs'

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

// Building a fresh Map/array from the full inventory on every call is the right default
// for a single lookup, but applyFindings verifies many candidates against the same
// inventory in one pass. Both helpers below let a caller compute the shared view once
// and thread it through verifyFindingExistence's optional parameters instead of paying
// an O(inventory size) rebuild per candidate.
export function indexEntriesByPath(entries) {
  return new Map(entries.map((entry) => [entry.path, entry]))
}

// searchAbsence itself still filters by kind/content/scope and sorts on every call — its
// signature and semantics are unchanged. Pre-reducing entries to just the text-bearing
// ones, sorted once by canonical path, means that per-claim work now runs over a much
// smaller, already-ordered array instead of the raw (possibly huge, mostly non-text)
// inventory, without altering searchAbsence's output for any given claim.
export function sortedTextEntries(entries) {
  return entries
    .filter((entry) => entry.kind === 'text' && typeof entry.content === 'string')
    .sort((left, right) => compareCanonicalStrings(left.path, right.path))
}

function sha256Hex(buffer) {
  return createHash('sha256').update(buffer).digest('hex')
}

export function verifyFindingExistence(
  finding,
  entries,
  byPath = indexEntriesByPath(entries),
  textEntries = sortedTextEntries(entries),
) {
  // An evidence-qualified finding is graded by evidence-locator.mjs against a
  // sealed bundle, not against the repository inventory. Running it through the
  // repository matcher would report it as an unavailable anchor, double-counting
  // a bundle finding as a repository failure.
  if ((finding.location ?? []).some((value) => parseEvidenceLocation(value))) {
    return {
      candidate_id: finding.candidate_id,
      quote_results: [],
      absence_results: [],
      outcome: 'NOT_APPLICABLE',
    }
  }

  const quotes = Array.isArray(finding.quotes) ? finding.quotes : []
  const claims = Array.isArray(finding.absence_claims) ? finding.absence_claims : []

  const quoteResults = quotes.map((quote, index) => {
    const entry = byPath.get(quote.path)
    if (!entry || entry.kind !== 'text' || typeof entry.content !== 'string') {
      return {
        index,
        outcome: 'NOT_LOCATED',
        path: quote.path,
        claimed_line: quote.line,
        found_line: null,
        match_count: 0,
        start_byte: null,
        end_byte: null,
        excerpt_sha256: null,
        anchor_state: 'ANCHOR_UNAVAILABLE',
      }
    }
    const match = matchQuote(entry.content, quote.text, quote.line)
    const base = {
      index,
      outcome: match.outcome,
      path: quote.path,
      claimed_line: quote.line,
      found_line: match.foundLine,
      match_count: match.matchCount,
    }
    if (match.outcome === 'NOT_LOCATED') {
      return {
        ...base,
        start_byte: null,
        end_byte: null,
        excerpt_sha256: null,
        anchor_state: 'ANCHOR_UNAVAILABLE',
      }
    }
    // Byte anchors come from re-encoding the decoded content as UTF-8. That only
    // round-trips to the original bytes if those bytes were valid UTF-8 to begin with;
    // otherwise content already has U+FFFD in place of the invalid bytes and any byte
    // offset computed from it would be wrong. The inventory's sha256 of the original
    // bytes is the oracle: if re-encoding doesn't reproduce it, withhold the anchor
    // rather than report a byte range that cannot be trusted.
    const bytes = Buffer.from(entry.content, 'utf8')
    const roundTrips = typeof entry.sha256 !== 'string'
      || sha256Hex(bytes) === entry.sha256.toLowerCase()
    if (!roundTrips) {
      return {
        ...base,
        start_byte: null,
        end_byte: null,
        excerpt_sha256: null,
        anchor_state: 'ANCHOR_UNAVAILABLE',
      }
    }
    const excerpt = bytes.subarray(match.startByte, match.endByte)
    return {
      ...base,
      start_byte: match.startByte,
      end_byte: match.endByte,
      excerpt_sha256: sha256Hex(excerpt),
      anchor_state: 'ANCHORED',
    }
  })

  const absenceResults = claims.map((claim, index) => ({
    index,
    ...searchAbsence(textEntries, claim),
  })).map(({ matchCount, searchedFiles, ...rest }) => ({
    ...rest,
    match_count: matchCount,
    searched_files: searchedFiles,
  }))

  let outcome = 'NOT_APPLICABLE'
  if (quotes.length > 0 || claims.length > 0) {
    const failed = quoteResults.some((r) => r.outcome === 'NOT_LOCATED')
      || absenceResults.some((r) => r.outcome !== 'ABSENCE_HOLDS')
    const drifted = quoteResults.some((r) => r.outcome === 'LOCATED_OFF_LINE')
    outcome = failed ? 'UNVERIFIED' : (drifted ? 'DRIFTED' : 'VERIFIED')
  }

  return {
    candidate_id: finding.candidate_id,
    quote_results: quoteResults,
    absence_results: absenceResults,
    outcome,
  }
}
