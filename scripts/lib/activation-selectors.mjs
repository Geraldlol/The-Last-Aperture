export const MAX_SIGNAL_SELECTOR_LITERALS = 32
export const MAX_SIGNAL_LITERAL_CHARACTERS = 256

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
}

function literalViolation(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.trim() !== value) {
    return `${label} must be a non-empty trimmed string`
  }
  if (value.length > MAX_SIGNAL_LITERAL_CHARACTERS) {
    return `${label} must be at most ${MAX_SIGNAL_LITERAL_CHARACTERS} characters`
  }
  if (value.includes(' / ')) {
    return `${label} must use any_of instead of slash-separated prose`
  }
  return null
}

// Signal selectors deliberately support literals only. In particular, regex is
// not an accepted selector key: repository contents are untrusted and a lens
// pack must not be able to introduce an unbounded backtracking program into the
// controller. `any_of` captures the compound inventories the corpus needs while
// retaining the same bounded literal matcher used by legacy scalar entries.
export function validateSignalSelector(selector) {
  if (typeof selector === 'string') {
    const violation = literalViolation(selector, 'signal selector')
    return violation ? [violation] : []
  }

  if (!isRecord(selector)) {
    return ['signal selector must be a literal string or an any_of mapping']
  }

  const keys = Object.keys(selector)
  if (keys.length !== 1 || keys[0] !== 'any_of') {
    if (keys.length === 1) return [`unknown signal selector key "${keys[0]}"; only "any_of" is supported`]
    return ['signal selector mapping must contain exactly one "any_of" key']
  }

  const literals = selector.any_of
  if (!Array.isArray(literals)) {
    return ['signal selector any_of must be an array']
  }
  if (literals.length < 2 || literals.length > MAX_SIGNAL_SELECTOR_LITERALS) {
    return [`signal selector any_of must contain between 2 and ${MAX_SIGNAL_SELECTOR_LITERALS} atomic literals`]
  }

  const violations = []
  for (const [index, literal] of literals.entries()) {
    const violation = literalViolation(literal, `signal selector any_of[${index}] atomic literal`)
    if (violation) violations.push(violation)
  }
  if (literals.every((literal) => typeof literal === 'string') &&
      new Set(literals).size !== literals.length) {
    violations.push('signal selector any_of must not contain duplicates')
  }
  return violations
}

export function signalSelectorLiterals(selector) {
  const violations = validateSignalSelector(selector)
  if (violations.length > 0) {
    throw new TypeError(`invalid signal selector: ${violations.join('; ')}`)
  }
  return typeof selector === 'string' ? [selector] : selector.any_of
}
