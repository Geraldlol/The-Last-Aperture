// Sources emit names, not URLs. A source handing us "https://x/y" is a bug in
// that source, so it is rejected rather than coerced -- silent coercion would
// hide the defect and could smuggle a path or port past later checks.

const NAME_PATTERN = /^[a-z0-9_-]+(\.[a-z0-9_-]+)*$/

export function normalizeCandidateName(raw) {
  if (typeof raw !== 'string') return null
  let name = raw.trim().toLowerCase()
  if (name.startsWith('dns:')) name = name.slice(4).trim()
  if (name.endsWith('.')) name = name.slice(0, -1)
  if (name.length === 0) return null
  if (!NAME_PATTERN.test(name)) return null
  return name
}

export function classifyCandidate(raw) {
  if (typeof raw !== 'string') return null
  let text = raw.trim().toLowerCase()
  if (text.startsWith('dns:')) text = text.slice(4).trim()

  // A wildcard SAN proves a zone exists but names no host, so it can never be a
  // probe target. Strip every leading wildcard label and keep what it covers.
  let sawWildcard = false
  while (text.startsWith('*.')) {
    sawWildcard = true
    text = text.slice(2)
  }
  if (text === '*') return null

  const value = normalizeCandidateName(text)
  if (value === null) return null
  return { kind: sawWildcard ? 'zone_hint' : 'host', value }
}

export function expandZoneHint(hint) {
  return hint.value
}

export function dedupeCandidates(candidates) {
  const seen = new Set()
  const out = []
  for (const candidate of candidates) {
    if (candidate === null || typeof candidate !== 'object') continue
    const key = `${candidate.kind}:${candidate.value}`
    if (seen.has(key)) continue
    seen.add(key)
    out.push(candidate)
  }
  return out
}
