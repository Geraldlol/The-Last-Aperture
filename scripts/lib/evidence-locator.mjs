import { readEvidencePayloadFile } from './evidence-bundle.mjs'

const EVIDENCE_LOCATION = /^([a-z0-9][a-z0-9-]{0,63}):(?!\d+$)(.+)$/
const LAYER_LOCATOR = /^layer\/(\d{2,})\/(.+)$/
const HISTORY_LOCATOR = /^config\/history\[(\d+)\]$/
const ORPHAN_LOCATOR = /^orphan\/(sha256:[0-9a-f]{64})$/
const OBJECT_LOCATOR = /^([a-z0-9][a-z0-9./-]*)\/([A-Z][A-Za-z0-9]*)\/([a-z0-9-]+)\/([a-z0-9.-]+)$/
const MAX_OBSERVED_BYTES = 512
// Bounded for the same reason every other loop in this subsystem is.
const MAX_OBJECT_SCAN = 4096

export function parseEvidenceLocation(value) {
  const match = EVIDENCE_LOCATION.exec(String(value))
  if (!match) return null
  return { evidence_id: match[1], locator: match[2] }
}

async function readJsonPayload(directory, path) {
  try {
    return JSON.parse((await readEvidencePayloadFile(directory, path)).toString('utf8'))
  } catch {
    return null
  }
}

/**
 * Three locator forms and no more. An unrecognised form resolves to nothing
 * rather than being interpreted generously: a locator nobody can resolve is a
 * statement about the claim, and guessing at one would let a typo find bytes
 * it was never pointed at.
 */
export async function resolveEvidenceLocator(directory, locator) {
  const layer = LAYER_LOCATOR.exec(locator)
  if (layer) {
    const path = `payload/layers/${layer[1]}/content/${layer[2]}`
    try {
      return { kind: 'entry', payload_path: path, bytes: await readEvidencePayloadFile(directory, path) }
    } catch {
      return { kind: 'entry', payload_path: path, bytes: null }
    }
  }

  const history = HISTORY_LOCATOR.exec(locator)
  if (history) {
    const entries = await readJsonPayload(directory, 'payload/config/history.json')
    const element = Array.isArray(entries) ? entries[Number(history[1])] : undefined
    return {
      kind: 'history',
      payload_path: 'payload/config/history.json',
      bytes: element === undefined ? null : Buffer.from(JSON.stringify(element), 'utf8'),
    }
  }

  const orphan = ORPHAN_LOCATOR.exec(locator)
  if (orphan) {
    const blobs = await readJsonPayload(directory, 'payload/orphan-blobs.json')
    const element = (blobs ?? []).find(({ digest }) => digest === orphan[1])
    return {
      kind: 'orphan',
      payload_path: 'payload/orphan-blobs.json',
      bytes: element === undefined ? null : Buffer.from(JSON.stringify(element), 'utf8'),
    }
  }

  // A deployed-state object, cited as <apiVersion>/<Kind>/<namespace>/<name>.
  // The payload prefix is the operation's position, so the scan walks
  // operations.json rather than reconstructing a directory from the locator.
  const object = OBJECT_LOCATOR.exec(locator)
  if (object) {
    const [, apiVersion, kind, namespace, name] = object
    const executed = await readJsonPayload(directory, 'payload/operations.json')
    for (const { payload_prefix: prefix } of executed ?? []) {
      if (typeof prefix !== 'string') continue
      for (let index = 0; index < MAX_OBJECT_SCAN; index += 1) {
        const path = `payload/objects/${prefix}/${index}.json`
        let parsed
        try {
          parsed = JSON.parse((await readEvidencePayloadFile(directory, path)).toString('utf8'))
        } catch {
          break
        }
        if (
          parsed?.apiVersion === apiVersion
          && parsed?.kind === kind
          && parsed?.metadata?.namespace === namespace
          && parsed?.metadata?.name === name
        ) {
          return {
            kind: 'object',
            payload_path: path,
            bytes: Buffer.from(JSON.stringify(parsed), 'utf8'),
          }
        }
      }
    }
    return { kind: 'object', payload_path: null, bytes: null }
  }

  return { kind: 'unknown', payload_path: null, bytes: null }
}

/**
 * The existence-first rule, for evidence that is not the repository. The three
 * outcomes are _schema.md's, unchanged: an unresolvable locator or an absent
 * bundle is a statement about the claim (not_located -> NOT_REPRODUCED); a
 * resolved locator whose quoted evidence is absent is a falsified premise
 * (located with a contradicting observation -> DISPROVED).
 */
export async function verifyEvidenceExistence(finding, bundlesById) {
  const parsed = (finding.location ?? [])
    .map(parseEvidenceLocation)
    .find(Boolean)
  if (!parsed) {
    return { status: 'not_located', method: 'the record carries no evidence-qualified location' }
  }

  const directory = bundlesById.get(parsed.evidence_id)
  if (!directory) {
    return {
      status: 'not_located',
      method: `evidence bundle "${parsed.evidence_id}" is not present in this run`,
    }
  }

  const resolved = await resolveEvidenceLocator(directory, parsed.locator)
  if (resolved.bytes === null) {
    return {
      status: 'not_located',
      method: `locator "${parsed.locator}" does not resolve inside bundle `
        + `"${parsed.evidence_id}"`,
    }
  }

  const text = resolved.bytes.toString('utf8')
  const quoted = String(finding.evidence ?? '')
  const method = `read ${parsed.evidence_id}:${parsed.locator} `
    + `(${resolved.payload_path}) from the sealed bundle`
  if (quoted !== '' && text.includes(quoted)) {
    return { status: 'located', method }
  }
  return {
    status: 'located',
    method,
    observed: text.slice(0, MAX_OBSERVED_BYTES),
  }
}
