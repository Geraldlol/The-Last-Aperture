import { readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { normalizeCapturedRequest, redactRequest, requestSignature } from './bounty-authz-request.mjs'

const FLOWS_FILE = 'flows.jsonl'
const REQUESTS_FILE = 'authz-requests.json'
const FLOW_DB = 'flows.sqlite'

export const FLOW_KIND = 'red-team-audit/bounty-flow'

// The proxy appends JSONL and only Node touches SQLite. That boundary is
// deliberate: no cross-language database locking, and the raw capture stays
// replayable if the schema changes.
export function parseFlowLines(text) {
  const flows = []
  const skipped = []
  for (const [index, line] of text.split('\n').entries()) {
    const trimmed = line.trim()
    if (trimmed.length === 0) continue
    let record
    try {
      record = JSON.parse(trimmed)
    } catch {
      skipped.push({ line: index + 1, reason: 'not-json' })
      continue
    }
    if (record?.kind !== FLOW_KIND) {
      skipped.push({ line: index + 1, reason: 'not-a-bounty-flow' })
      continue
    }
    if (typeof record.request?.url !== 'string' || typeof record.request?.method !== 'string') {
      skipped.push({ line: index + 1, reason: 'flow-missing-request' })
      continue
    }
    flows.push(record)
  }
  return { flows, skipped }
}

const SCHEMA = `
CREATE TABLE IF NOT EXISTS flows (
  signature TEXT NOT NULL,
  observed_at TEXT,
  forwarded INTEGER NOT NULL,
  scope_decision TEXT NOT NULL,
  scope_reason TEXT,
  method TEXT NOT NULL,
  url TEXT NOT NULL,
  host TEXT,
  path TEXT,
  request_headers TEXT NOT NULL,
  request_body TEXT,
  status INTEGER,
  response_headers TEXT,
  response_body TEXT,
  PRIMARY KEY (signature, observed_at)
);
CREATE INDEX IF NOT EXISTS flows_host ON flows (host);
CREATE INDEX IF NOT EXISTS flows_status ON flows (status);
CREATE INDEX IF NOT EXISTS flows_decision ON flows (scope_decision);
`

function urlParts(url) {
  try {
    const parsed = new URL(url)
    return { host: parsed.hostname, path: parsed.pathname }
  } catch {
    return { host: null, path: null }
  }
}

export function openFlowStore(bundlePath) {
  const database = new DatabaseSync(join(bundlePath, FLOW_DB))
  database.exec(SCHEMA)
  return database
}

export async function ingestFlows({ bundlePath, flowsFile = FLOWS_FILE }) {
  let text = ''
  try {
    text = await readFile(join(bundlePath, flowsFile), 'utf8')
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
    return { ingested: 0, skipped: [], blocked: 0, status: 'NO_CAPTURE_FILE' }
  }
  const { flows, skipped } = parseFlowLines(text)
  const database = openFlowStore(bundlePath)
  const insert = database.prepare(`
    INSERT OR REPLACE INTO flows (
      signature, observed_at, forwarded, scope_decision, scope_reason,
      method, url, host, path, request_headers, request_body,
      status, response_headers, response_body
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `)

  let blocked = 0
  try {
    for (const flow of flows) {
      if (flow.scope_decision !== 'ALLOW') blocked += 1
      const { host, path } = urlParts(flow.request.url)
      const signature = requestSignature(normalizeCapturedRequest({
        method: flow.request.method,
        url: flow.request.url,
        headers: flow.request.headers ?? {},
        body: flow.request.body ?? null,
      }))
      insert.run(
        signature,
        flow.observed_at ?? null,
        flow.forwarded === true ? 1 : 0,
        flow.scope_decision,
        flow.scope_reason ?? null,
        flow.request.method,
        flow.request.url,
        host,
        path,
        JSON.stringify(flow.request.headers ?? {}),
        flow.request.body ?? null,
        flow.response?.status ?? null,
        flow.response === null || flow.response === undefined ? null : JSON.stringify(flow.response.headers ?? {}),
        flow.response?.body ?? null,
      )
    }
  } finally {
    database.close()
  }

  return {
    ingested: flows.length,
    skipped,
    blocked,
    status: flows.length === 0 ? 'NO_FLOWS' : 'INGESTED',
  }
}

export function queryFlows({ bundlePath, where = '1=1', limit = 100 }) {
  const database = openFlowStore(bundlePath)
  try {
    // Read-only by construction: the caller supplies a filter, never a statement.
    return database.prepare(
      `SELECT method, url, status, scope_decision, forwarded FROM flows WHERE ${where} LIMIT ?`,
    ).all(limit)
  } finally {
    database.close()
  }
}

// Turns captured traffic into the shape the authz grinder already consumes, so
// the proxy feeds P3 without either side knowing about the other.
export async function flowsToAuthzRequests({ bundlePath, ownerRole, flowsFile = FLOWS_FILE }) {
  let text = ''
  try {
    text = await readFile(join(bundlePath, flowsFile), 'utf8')
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
    return { imported: 0, status: 'NO_CAPTURE_FILE' }
  }
  const { flows } = parseFlowLines(text)
  const bySignature = new Map()
  for (const flow of flows) {
    // Only what actually reached the target. A blocked request is evidence about
    // the perimeter, not a request the grinder should replay.
    if (flow.forwarded !== true || flow.scope_decision !== 'ALLOW') continue
    const request = redactRequest(normalizeCapturedRequest({
      method: flow.request.method,
      url: flow.request.url,
      headers: flow.request.headers ?? {},
      body: flow.request.body ?? null,
      owner_role: ownerRole,
    }))
    bySignature.set(requestSignature(request), { ...request, request_id: `flow-${bySignature.size + 1}` })
  }
  const requests = [...bySignature.values()]
  await writeFile(
    join(bundlePath, REQUESTS_FILE),
    `${JSON.stringify({ schema_version: '1.0.0', requests }, null, 2)}\n`,
    'utf8',
  )
  return { imported: requests.length, status: requests.length === 0 ? 'NO_FORWARDED_FLOWS' : 'IMPORTED' }
}
