import { randomBytes as cryptoRandomBytes, randomUUID } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { appendFile, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import Ajv2020 from 'ajv/dist/2020.js'
import {
  correlateInteraction,
  normalizeInteraction,
  summarizeCorrelation,
} from './bounty-oob-correlator.mjs'
import { generateSessionKeypair } from './bounty-oob-crypto.mjs'
import {
  deregisterHostedSession,
  pollHostedSession,
  registerHostedSession,
} from './bounty-oob-hosted.mjs'
import {
  buildPayloadHost,
  createCorrelationId,
  createMintLedger,
  mintNonce,
  recordMint,
} from './bounty-oob-payload.mjs'

const SESSION_FILE = 'oob-session.json'
const INTERACTIONS_FILE = 'oob-interactions.jsonl'
const SESSION_SCHEMA_URL = new URL('../../schemas/bounty-oob-session.schema.json', import.meta.url)

export const OOB_BACKENDS = ['hosted', 'self_hosted']

let compiledValidator = null

export function assertValidOobSession(value) {
  if (compiledValidator === null) {
    const ajv = new Ajv2020({ allErrors: true, strict: false })
    compiledValidator = ajv.compile(JSON.parse(readFileSync(SESSION_SCHEMA_URL, 'utf8')))
  }
  if (compiledValidator(value)) return
  const detail = (compiledValidator.errors ?? [])
    .map((error) => `${error.instancePath || '/'} ${error.message}`)
    .join('; ')
  throw new Error(`oob session failed schema validation: ${detail}`)
}

function sessionPath(bundlePath) {
  return join(bundlePath, SESSION_FILE)
}

async function loadSession(bundlePath) {
  const session = JSON.parse(await readFile(sessionPath(bundlePath), 'utf8'))
  assertValidOobSession(session)
  return session
}

async function saveSession(bundlePath, session) {
  assertValidOobSession(session)
  await writeFile(sessionPath(bundlePath), `${JSON.stringify(session, null, 2)}\n`, 'utf8')
}

async function appendResults(bundlePath, results) {
  if (results.length === 0) return
  const lines = results.map((result) => JSON.stringify({
    matched: result.matched,
    reason: result.reason ?? null,
    nonce: result.nonce ?? null,
    mint: result.mint ?? null,
    interaction: result.interaction,
  })).join('\n')
  await appendFile(join(bundlePath, INTERACTIONS_FILE), `${lines}\n`, 'utf8')
}

export async function openOobSession({
  bundlePath,
  backend,
  server,
  randomBytes = cryptoRandomBytes,
  now,
  fetchImpl = fetch,
}) {
  if (!OOB_BACKENDS.includes(backend)) {
    throw new Error(`unknown oob backend: ${backend}`)
  }
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) {
    throw new Error('now must be a valid Date')
  }
  const keys = generateSessionKeypair()
  const correlationId = createCorrelationId(randomBytes)
  const secret = randomUUID()
  // A self-hosted session is entirely local: no registration call exists to make.
  if (backend === 'hosted') {
    await registerHostedSession({
      server,
      correlationId,
      secret,
      publicKeyBase64: keys.publicKeyBase64,
      fetchImpl,
    })
  }
  const session = {
    schema_version: '1.0.0',
    kind: 'red-team-audit/bounty-oob-session',
    backend,
    server,
    correlation_id: correlationId,
    secret,
    private_key_pem: keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    created_at: now.toISOString(),
    ledger: createMintLedger(),
  }
  await saveSession(bundlePath, session)
  return session
}

export async function mintOobPayload({
  bundlePath,
  label,
  requestId = '',
  insertionPoint = '',
  role = '',
  bugClass,
  randomBytes = cryptoRandomBytes,
  now,
}) {
  const session = await loadSession(bundlePath)
  const nonce = mintNonce(randomBytes)
  const host = buildPayloadHost({
    correlationId: session.correlation_id,
    nonce,
    server: session.server,
  })
  session.ledger = recordMint(session.ledger, {
    nonce,
    label,
    requestId,
    insertionPoint,
    role,
    bugClass,
    mintedAt: now.toISOString(),
  })
  await saveSession(bundlePath, session)
  return { host, nonce, url: `http://${host}/`, backend: session.backend }
}

export async function pollOobSession({ bundlePath, fetchImpl = fetch }) {
  const session = await loadSession(bundlePath)
  if (session.backend !== 'hosted') {
    throw new Error(
      'poll applies to the hosted backend; a self-hosted listener feeds ingestSelfHostedEvent directly',
    )
  }
  const raw = await pollHostedSession({
    server: session.server,
    correlationId: session.correlation_id,
    secret: session.secret,
    privateKey: session.private_key_pem,
    fetchImpl,
  })
  const results = raw.map((item) => correlateInteraction({
    ledger: session.ledger,
    correlationId: session.correlation_id,
    server: session.server,
    interaction: normalizeInteraction(item),
  }))
  await appendResults(bundlePath, results)
  return { results, summary: summarizeCorrelation(results) }
}

function selfHostedEventToRaw(event, now) {
  const timestamp = now.toISOString()
  if (event.protocol === 'dns') {
    return {
      protocol: 'dns',
      'full-id': event.name,
      'q-type': event.qType,
      'remote-address': event.remoteAddress,
      'raw-request': event.rawRequest,
      timestamp,
    }
  }
  const headerLines = Object.entries(event.headers ?? {})
    .map(([name, value]) => `${name}: ${value}`)
    .join('\n')
  const body = event.body ? `\n\n${event.body}` : ''
  return {
    protocol: 'http',
    'full-id': event.host,
    'remote-address': event.remoteAddress,
    'raw-request': `${event.method} ${event.path}\n${headerLines}${body}`,
    timestamp,
  }
}

export async function ingestSelfHostedEvent({ bundlePath, event, now }) {
  const session = await loadSession(bundlePath)
  const result = correlateInteraction({
    ledger: session.ledger,
    correlationId: session.correlation_id,
    server: session.server,
    interaction: normalizeInteraction(selfHostedEventToRaw(event, now)),
  })
  await appendResults(bundlePath, [result])
  return result
}

export async function oobSessionStatus({ bundlePath }) {
  const session = await loadSession(bundlePath)
  let observed = 0
  let matched = 0
  try {
    const text = await readFile(join(bundlePath, INTERACTIONS_FILE), 'utf8')
    for (const line of text.split('\n')) {
      if (line.trim().length === 0) continue
      observed += 1
      if (JSON.parse(line).matched === true) matched += 1
    }
  } catch (error) {
    if (error.code !== 'ENOENT') throw error
  }
  return {
    backend: session.backend,
    server: session.server,
    correlationId: session.correlation_id,
    mints: Object.keys(session.ledger.mints).length,
    observed,
    matched,
    // Never phrase this as a negative result about the target.
    status: observed === 0 ? 'NO_INTERACTION_OBSERVED' : 'INTERACTIONS_OBSERVED',
  }
}

export async function closeOobSession({ bundlePath, fetchImpl = fetch }) {
  const session = await loadSession(bundlePath)
  if (session.backend !== 'hosted') return { deregistered: false, backend: session.backend }
  await deregisterHostedSession({
    server: session.server,
    correlationId: session.correlation_id,
    secret: session.secret,
    fetchImpl,
  })
  return { deregistered: true, backend: session.backend }
}
