// crt.sh is high-yield when it works and returns 502 often enough that the
// degradation path is the common path, not the edge case (verified 2026-08-21:
// three consecutive 502s). So this source never throws into the pipeline. It
// returns a gap, the gap forces the inventory to PARTIAL, and the sweep
// continues on whatever other sources are alive.

const DEFAULT_TIMEOUT_MS = 45000
const DEFAULT_ATTEMPTS = 2
const MAX_ROWS = 50000

export function parseCtLogRows(rows) {
  if (!Array.isArray(rows)) return []
  const names = []
  for (const row of rows.slice(0, MAX_ROWS)) {
    // name_value is newline-separated and may carry wildcards; classification is
    // the candidate module's job, so everything is passed through verbatim.
    for (const field of ['name_value', 'common_name']) {
      const value = row?.[field]
      if (typeof value !== 'string') continue
      for (const line of value.split('\n')) {
        const name = line.trim()
        if (name.length > 0) names.push(name)
      }
    }
  }
  return names
}

export async function fetchCtLogNames({
  apex,
  fetchImpl = fetch,
  timeoutMs = DEFAULT_TIMEOUT_MS,
  attempts = DEFAULT_ATTEMPTS,
}) {
  if (typeof apex !== 'string' || apex.length === 0) {
    return { names: [], gap: { source: 'crt.sh', reason: 'no-apex-supplied' } }
  }
  const url = `https://crt.sh/?q=${encodeURIComponent(`%.${apex}`)}&output=json`
  let lastDetail = 'unknown'
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetchImpl(url, {
        headers: { 'User-Agent': 'red-team-audit-bounty-recon/1.0' },
        signal: AbortSignal.timeout(timeoutMs),
      })
      if (!response.ok) {
        lastDetail = `HTTP ${response.status} on attempt ${attempt}`
        continue
      }
      const rows = await response.json()
      return { names: parseCtLogNames(rows), gap: null }
    } catch (error) {
      lastDetail = `${error.name} on attempt ${attempt}: ${error.message}`.slice(0, 200)
    }
  }
  return {
    names: [],
    gap: { source: 'crt.sh', reason: 'source-unavailable', detail: lastDetail },
  }
}

// Named export kept separate so the parser is testable without the transport.
function parseCtLogNames(rows) {
  return parseCtLogRows(rows)
}
