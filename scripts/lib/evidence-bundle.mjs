import { createHash } from 'node:crypto'
import { mkdir, readFile, readdir, writeFile } from 'node:fs/promises'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { assertValidEvidenceProfile, validateEvidenceProfile } from './evidence-contracts.mjs'

export const EVIDENCE_MANIFEST_FILE = 'manifest.json'
const PAYLOAD_DIRECTORY = 'payload'
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024

export class EvidenceBundleError extends Error {
  constructor(code, message, { bundle, details } = {}) {
    super(message)
    this.name = 'EvidenceBundleError'
    this.code = code
    this.bundle = bundle
    this.details = details ?? []
  }
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function canonicalPayloadPath(value) {
  const normalized = String(value).replaceAll('\\', '/').replace(/^(?:\.\/)+/, '')
  const segments = normalized.split('/')
  if (
    normalized === ''
    || normalized.startsWith('/')
    || /^[A-Za-z]:/.test(normalized)
    || segments.some((segment) => segment === '' || segment === '.' || segment === '..')
  ) {
    throw new EvidenceBundleError(
      'EVIDENCE_PAYLOAD_PATH_INVALID',
      `payload path must stay inside the bundle: ${String(value)}`,
    )
  }
  return normalized
}

/**
 * The bundle's root digest. Content-addressed over exactly the three facts a
 * later reader can re-derive from disk, so re-verification months later is
 * exact rather than approximate.
 */
export function evidenceBundleRootDigest(files) {
  const material = [...files]
    .map(({ path, sha256: digest, size }) => [path, digest, size])
    .sort((left, right) => compareCanonicalStrings(left[0], right[0]))
  return sha256(JSON.stringify(material))
}

export async function writeEvidenceBundle({ directory, profile, payload = [] }) {
  const root = resolve(directory)
  const entries = payload.map(({ path, bytes }) => {
    const relativePath = canonicalPayloadPath(path)
    const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes), 'utf8')
    return {
      relativePath,
      buffer,
      file: {
        path: `${PAYLOAD_DIRECTORY}/${relativePath}`,
        sha256: sha256(buffer),
        size: buffer.length,
      },
    }
  })
  entries.sort((left, right) =>
    compareCanonicalStrings(left.file.path, right.file.path))

  const sealed = assertValidEvidenceProfile({
    ...profile,
    files: entries.map(({ file }) => file),
  })
  const rootDigest = evidenceBundleRootDigest(sealed.files)

  await mkdir(root, { recursive: true })
  for (const entry of entries) {
    const target = join(root, PAYLOAD_DIRECTORY, ...entry.relativePath.split('/'))
    await mkdir(dirname(target), { recursive: true })
    await writeFile(target, entry.buffer)
  }
  await writeFile(
    join(root, EVIDENCE_MANIFEST_FILE),
    `${JSON.stringify({ profile: sealed, root_sha256: rootDigest }, null, 2)}\n`,
    'utf8',
  )
  return { directory: root, root_sha256: rootDigest, profile: sealed }
}

async function readManifest(root) {
  const manifestPath = join(root, EVIDENCE_MANIFEST_FILE)
  let text
  try {
    text = await readFile(manifestPath, 'utf8')
  } catch {
    throw new EvidenceBundleError(
      'EVIDENCE_BUNDLE_MANIFEST_UNREADABLE',
      `evidence bundle manifest not found: ${manifestPath}`,
      { bundle: root },
    )
  }
  if (Buffer.byteLength(text, 'utf8') > MAX_MANIFEST_BYTES) {
    throw new EvidenceBundleError(
      'EVIDENCE_BUNDLE_MANIFEST_TOO_LARGE',
      `evidence bundle manifest exceeds ${MAX_MANIFEST_BYTES} bytes`,
      { bundle: root },
    )
  }
  try {
    return JSON.parse(text)
  } catch (error) {
    throw new EvidenceBundleError(
      'EVIDENCE_BUNDLE_MANIFEST_UNPARSEABLE',
      `evidence bundle manifest is not JSON: ${error.message}`,
      { bundle: root },
    )
  }
}

async function listPayloadFiles(root) {
  const payloadRoot = join(root, PAYLOAD_DIRECTORY)
  const found = []
  async function visit(directory) {
    let dirEntries
    try {
      dirEntries = await readdir(directory, { withFileTypes: true })
    } catch {
      return
    }
    for (const entry of dirEntries) {
      const path = join(directory, entry.name)
      if (entry.isSymbolicLink()) {
        throw new EvidenceBundleError(
          'EVIDENCE_BUNDLE_SYMLINK',
          `an evidence bundle cannot contain a symlink: ${path}`,
          { bundle: root },
        )
      }
      if (entry.isDirectory()) await visit(path)
      else if (entry.isFile()) {
        found.push(`${PAYLOAD_DIRECTORY}/${relative(payloadRoot, path).split(sep).join('/')}`)
      }
    }
  }
  await visit(payloadRoot)
  return found.sort(compareCanonicalStrings)
}

export async function verifyEvidenceBundle(directory) {
  const root = resolve(directory)
  const errors = []
  let manifest
  try {
    manifest = await readManifest(root)
  } catch (error) {
    return { valid: false, root_sha256: null, errors: [{ code: error.code, message: error.message }] }
  }

  const profileValidation = validateEvidenceProfile(manifest?.profile)
  for (const error of profileValidation.errors) {
    errors.push({ code: error.code, message: `${error.instancePath || '/'} ${error.message}` })
  }
  const files = Array.isArray(manifest?.profile?.files) ? manifest.profile.files : []
  const expectedRoot = evidenceBundleRootDigest(files)
  if (manifest?.root_sha256 !== expectedRoot) {
    errors.push({
      code: 'ROOT_DIGEST_MISMATCH',
      message: `manifest root digest ${String(manifest?.root_sha256)} does not cover its own file list`,
    })
  }

  const declared = new Set(files.map(({ path }) => path))
  for (const file of files) {
    let bytes
    try {
      bytes = await readFile(join(root, ...String(file.path).split('/')))
    } catch {
      errors.push({ code: 'PAYLOAD_FILE_MISSING', message: `declared payload file is absent: ${file.path}` })
      continue
    }
    if (sha256(bytes) !== file.sha256 || bytes.length !== file.size) {
      errors.push({
        code: 'PAYLOAD_DIGEST_MISMATCH',
        message: `payload file does not match its declared digest: ${file.path}`,
      })
    }
  }

  try {
    for (const path of await listPayloadFiles(root)) {
      if (!declared.has(path)) {
        errors.push({
          code: 'UNDECLARED_PAYLOAD_FILE',
          message: `payload file is present but not declared in the manifest: ${path}`,
        })
      }
    }
  } catch (error) {
    errors.push({ code: error.code, message: error.message })
  }

  return { valid: errors.length === 0, root_sha256: expectedRoot, errors }
}

export async function readEvidenceBundle(directory) {
  const root = resolve(directory)
  const manifest = await readManifest(root)
  const profile = manifest?.profile
  return {
    directory: root,
    profile,
    evidence_context: Object.freeze({ ...profile?.evidence_context }),
    root_sha256: manifest?.root_sha256,
  }
}

export async function readEvidencePayloadFile(directory, payloadPath) {
  const root = resolve(directory)
  const normalized = canonicalPayloadPath(payloadPath)
  if (!normalized.startsWith(`${PAYLOAD_DIRECTORY}/`)) {
    throw new EvidenceBundleError(
      'EVIDENCE_PAYLOAD_PATH_INVALID',
      `payload path must begin with ${PAYLOAD_DIRECTORY}/: ${payloadPath}`,
      { bundle: root },
    )
  }
  return readFile(join(root, ...normalized.split('/')))
}

/**
 * The audit-side entry point. Evidence of uncertain provenance is worse than
 * absent evidence because it launders into findings, so this refuses rather
 * than warning and continuing.
 */
export async function loadEvidenceBundle(argument) {
  const verification = await verifyEvidenceBundle(argument)
  if (!verification.valid) {
    throw new EvidenceBundleError(
      'EVIDENCE_BUNDLE_INVALID',
      'evidence bundle did not verify; planning refuses unverified evidence',
      { bundle: resolve(argument), details: verification.errors },
    )
  }
  return readEvidenceBundle(argument)
}
