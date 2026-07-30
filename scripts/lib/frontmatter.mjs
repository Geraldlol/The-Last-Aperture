import { parse as parseYaml } from 'yaml'

const FM = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/

// One lens file in, structured lens out. Parsing only — no rules live here,
// so a rule change never means touching the parser.
export function parseLens(text, filename) {
  const errors = []
  const match = FM.exec(text)
  if (!match) {
    return { name: null, frontmatter: {}, sections: {}, detectors: [], errors: [`${filename}: no YAML frontmatter block found`] }
  }

  let frontmatter = {}
  try {
    frontmatter = parseYaml(match[1]) ?? {}
  } catch (err) {
    return { name: null, frontmatter: {}, sections: {}, detectors: [], errors: [`${filename}: yaml parse failed — ${err.message}`] }
  }

  const body = text.slice(match[0].length)
  const fmLineOffset = match[0].split(/\r?\n/).length - 1
  return {
    name: frontmatter.name ?? null,
    frontmatter,
    sections: splitSections(body, filename, errors, fmLineOffset),
    detectors: parseDetectors(body, filename, errors, fmLineOffset),
    errors,
  }
}

// Tags each line of `body` with whether it lies inside a fenced code block,
// so callers can ignore fence content when looking for structure (headings,
// backtick literals) without losing it from the surrounding text.
//
// A fence opens on a line starting (after up to 3 spaces of indent) with a
// run of 3+ backticks, optionally followed by an info string. It is closed
// only by a later line whose backtick run is at least as long AND which
// carries nothing but that run (plus trailing whitespace) — a closing fence
// may not carry an info string, only an opening one may. A candidate closer
// line with other trailing content is ordinary content inside the fence,
// not a closer. An unterminated fence is treated as extending to the end of
// the text — every line from the opener onward is reported as fenced, so
// nothing past it is mistaken for a heading; `openFenceLine` reports the
// body-relative (1-based) line the still-open fence began on, or null if
// every fence closed. (Tilde fences are valid Markdown but unused in this
// project's lenses, so they are not handled here.)
function markFences(body) {
  let fenceLen = 0
  let openFenceLine = null
  const lines = body.split(/\r?\n/).map((line, i) => {
    const run = /^ {0,3}(`{3,})/.exec(line)
    if (fenceLen > 0) {
      const isCloser = run && run[1].length >= fenceLen && /^ {0,3}`{3,}\s*$/.test(line)
      if (isCloser) {
        fenceLen = 0
        openFenceLine = null
      }
      return { line, fenced: true }
    }
    if (run) {
      fenceLen = run[1].length
      openFenceLine = i + 1
      return { line, fenced: true }
    }
    return { line, fenced: false }
  })
  return { lines, openFenceLine }
}

// Removes fenced code blocks (marker lines and their contents) from `body`,
// leaving the surrounding prose. Used where fenced examples must not
// contribute to counts taken over the remaining text.
export function stripFencedBlocks(body) {
  return markFences(body)
    .lines.filter(({ fenced }) => !fenced)
    .map(({ line }) => line)
    .join('\n')
}

function splitSections(body, filename, errors, fmLineOffset) {
  const sections = {}
  let current = null
  const buffer = []
  const flush = () => {
    if (current !== null) sections[current] = buffer.join('\n').trim()
    buffer.length = 0
  }
  const { lines, openFenceLine } = markFences(body)
  for (const { line, fenced } of lines) {
    if (!fenced) {
      const heading = /^##\s+(.+?)\s*$/.exec(line)
      if (heading) {
        flush()
        current = heading[1]
        continue
      }
    }
    if (current !== null) buffer.push(line)
  }
  flush()
  if (openFenceLine !== null) {
    errors.push(`${filename}:${fmLineOffset + openFenceLine}: unterminated fenced code block (opened here and never closed before end of file)`)
  }
  return sections
}

// A detector block proves a search instruction can actually fire. Both
// directions are required: match shows it fires, nomatch shows it discriminates.
function parseDetectors(body, filename, errors, fmLineOffset) {
  const detectors = []
  const re = /```detector\r?\n([\s\S]*?)```/g
  let m
  while ((m = re.exec(body)) !== null) {
    const bodyRelativeLine = body.slice(0, m.index).split(/\r?\n/).length
    const line = fmLineOffset + bodyRelativeLine
    let parsed
    try {
      parsed = parseYaml(m[1]) ?? {}
    } catch (err) {
      errors.push(`${filename}:${line}: detector block yaml parse failed — ${err.message}`)
      continue
    }
    detectors.push({
      match: typeof parsed.match === 'string' ? parsed.match : null,
      nomatch: typeof parsed.nomatch === 'string' ? parsed.nomatch : null,
      line,
    })
  }
  return detectors
}
