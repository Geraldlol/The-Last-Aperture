import { readFileSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import Ajv2020 from 'ajv/dist/2020.js'

const SCHEMA_URL = new URL('../../schemas/bounty-authz-identifiers.schema.json', import.meta.url)

let compiledValidator = null

export function assertValidIdentifierMap(value) {
  if (compiledValidator === null) {
    const ajv = new Ajv2020({ allErrors: true, strict: false })
    compiledValidator = ajv.compile(JSON.parse(readFileSync(SCHEMA_URL, 'utf8')))
  }
  if (compiledValidator(value)) return
  const detail = (compiledValidator.errors ?? [])
    .map((error) => `${error.instancePath || '/'} ${error.message}`)
    .join('; ')
  throw new Error(`identifier map failed schema validation: ${detail}`)
}

export async function loadIdentifierMap(path) {
  const map = JSON.parse(await readFile(path, 'utf8'))
  assertValidIdentifierMap(map)
  return map
}

// Occurrences are located by matching a WHOLE token against a declared value:
// a path segment, a complete query value, a scalar JSON value, or a full header
// value. Substring matching is deliberately absent -- an identifier of "2" would
// otherwise rewrite a page number, an API version, or a digit inside an unrelated
// word, and a mangled request produces a meaningless verdict.
function walkJson(value, pointer, visit) {
  if (Array.isArray(value)) {
    value.forEach((entry, index) => walkJson(entry, `${pointer}/${index}`, visit))
    return
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, entry] of Object.entries(value)) {
      walkJson(entry, `${pointer}/${key}`, visit)
    }
    return
  }
  visit(value, pointer)
}

export function findIdentifierOccurrences(request, identifierValue) {
  const wanted = String(identifierValue)
  const occurrences = []

  let parsed = null
  try {
    parsed = new URL(request.url)
  } catch {
    parsed = null
  }

  if (parsed !== null) {
    const segments = parsed.pathname.split('/')
    segments.forEach((segment, index) => {
      if (segment === wanted) {
        occurrences.push({ location: 'path', pointer: String(index), original: segment })
      }
    })
    for (const [name, value] of parsed.searchParams.entries()) {
      if (value === wanted) {
        occurrences.push({ location: 'query', pointer: name, original: value })
      }
    }
  }

  for (const [name, value] of Object.entries(request.headers ?? {})) {
    if (value === wanted) {
      occurrences.push({ location: 'header', pointer: name, original: value })
    }
  }

  if (typeof request.body === 'string' && request.body.length > 0) {
    try {
      const body = JSON.parse(request.body)
      walkJson(body, '', (value, pointer) => {
        if (value !== null && typeof value !== 'object' && String(value) === wanted) {
          occurrences.push({
            location: 'json',
            pointer: pointer === '' ? '/' : pointer,
            original: value,
          })
        }
      })
    } catch {
      // A non-JSON body is not searched: blind string replacement in an opaque
      // payload is how a request gets corrupted into a meaningless result.
    }
  }

  return occurrences
}

function setJsonPointer(root, pointer, nextValue) {
  if (pointer === '/' || pointer === '') return nextValue
  const parts = pointer.split('/').slice(1)
  const clone = structuredClone(root)
  let cursor = clone
  for (let index = 0; index < parts.length - 1; index += 1) {
    cursor = cursor[Array.isArray(cursor) ? Number.parseInt(parts[index], 10) : parts[index]]
  }
  const last = parts[parts.length - 1]
  const key = Array.isArray(cursor) ? Number.parseInt(last, 10) : last
  cursor[key] = nextValue
  return clone
}

export function substituteIdentifier(request, occurrence, newValue) {
  const replacement = String(newValue)

  if (occurrence.location === 'path' || occurrence.location === 'query') {
    const parsed = new URL(request.url)
    if (occurrence.location === 'path') {
      const segments = parsed.pathname.split('/')
      segments[Number.parseInt(occurrence.pointer, 10)] = replacement
      parsed.pathname = segments.join('/')
    } else {
      parsed.searchParams.set(occurrence.pointer, replacement)
    }
    return { ...request, url: parsed.toString() }
  }

  if (occurrence.location === 'header') {
    return { ...request, headers: { ...request.headers, [occurrence.pointer]: replacement } }
  }

  if (occurrence.location === 'json') {
    const body = JSON.parse(request.body)
    // Preserve the original JSON type: turning a number into a string can trip
    // strict server-side validation and produce a 400 that looks like a denial.
    const typed = typeof occurrence.original === 'number' && /^-?\d+(\.\d+)?$/.test(replacement)
      ? Number(replacement)
      : replacement
    return { ...request, body: JSON.stringify(setJsonPointer(body, occurrence.pointer, typed)) }
  }

  throw new Error(`unknown occurrence location: ${occurrence.location}`)
}

export function describeOccurrence(occurrence) {
  return `${occurrence.location}:${occurrence.pointer}`
}

// Only identifiers the operator declared, and only ones owned by a role the
// operator controls, are ever substituted. There is no increment-the-integer or
// guess-a-uuid path: enumerating unknown ids means reading a stranger's data to
// prove a bug, which is both out of bounds and makes a worse report than
// "I accessed my own second account's object".
export function mutationPlan({ identifiers, sourceIdentifier }) {
  return identifiers.filter((candidate) => (
    candidate.id !== sourceIdentifier.id
    && candidate.kind === sourceIdentifier.kind
  ))
}

export function identifiersInRequest({ request, identifiers }) {
  const found = []
  for (const identifier of identifiers) {
    const occurrences = findIdentifierOccurrences(request, identifier.value)
    for (const occurrence of occurrences) {
      found.push({ identifier, occurrence })
    }
  }
  return found
}
