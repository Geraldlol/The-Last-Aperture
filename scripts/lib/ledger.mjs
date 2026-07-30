// The ledger is what proves content survived migration. Metadata lint cannot
// see a deleted checklist item; a ledger row with a disposition can.
const DISPOSITIONS = new Set(['preserved', 'corrected', 'moved', 'intentionally_removed'])
const HEADER = ['source', 'destination', 'disposition', 'evidence']

export function parseLedger(text) {
  const violations = []
  const rows = []
  // Carry each line's PHYSICAL number alongside its text. Filtering blanks out
  // before indexing makes every reported line number drift upward by the count
  // of blank lines above it, which sends a contributor to the wrong row.
  const lines = text
    .split(/\r?\n/)
    .map((text, i) => ({ text, lineNo: i + 1 }))
    .filter((l) => l.text.trim() !== '')

  if (!lines.length) {
    return { rows, violations: [{ rule: 'LEDGER', message: 'migration ledger is empty' }] }
  }
  const header = lines[0].text.split('\t').map((h) => h.trim())
  if (header.join(',') !== HEADER.join(',')) {
    violations.push({ rule: 'LEDGER', message: `ledger header must be exactly ${HEADER.join(' / ')}, got ${header.join(' / ')}` })
  }
  if (lines.length === 1) {
    violations.push({ rule: 'LEDGER', message: 'migration ledger has no rows; Phase A cannot close' })
  }

  lines.slice(1).forEach(({ text: line, lineNo }) => {
    const cells = line.split('\t')
    if (cells.length !== HEADER.length) {
      violations.push({ rule: 'LEDGER', message: `ledger line ${lineNo}: expected ${HEADER.length} columns, got ${cells.length}` })
      return
    }
    const [source, destination, disposition, evidence] = cells.map((c) => c.trim())
    if (!DISPOSITIONS.has(disposition)) {
      violations.push({ rule: 'LEDGER', message: `ledger line ${lineNo}: disposition "${disposition}" is not one of ${[...DISPOSITIONS].join(', ')}` })
    }
    if (!evidence) {
      violations.push({ rule: 'LEDGER', message: `ledger line ${lineNo}: no evidence reference for "${source}"` })
    }
    if (!source) {
      violations.push({ rule: 'LEDGER', message: `ledger line ${lineNo}: no source location` })
    }
    rows.push({ source, destination, disposition, evidence })
  })

  // rows includes rows that also produced violations — a row with an unknown
  // disposition still appears in rows unchanged. Task 7 consumes both arrays.
  return { rows, violations }
}
