import { createHash, randomUUID } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import { lstat, mkdir, open, readdir, realpath, rename, rm } from 'node:fs/promises'
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { assertValidEvidenceProfile, validateEvidenceProfile } from './evidence-contracts.mjs'
import { publishFileCreateOnlyDurably } from './durable-file-publication.mjs'

export const EVIDENCE_MANIFEST_FILE = 'manifest.json'
const PAYLOAD_DIRECTORY = 'payload'
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024
const MAX_PAYLOAD_FILE_BYTES = 128 * 1024 * 1024
const MAX_PAYLOAD_TOTAL_BYTES = 1024 * 1024 * 1024
export const EVIDENCE_ROOT_ALGORITHM_V1 = 'sha256-file-tuples-v1'
export const EVIDENCE_ROOT_ALGORITHM_V2 = 'sha256-canonical-profile-v2'
export const EVIDENCE_MANIFEST_SCHEMA_V2 = 'evidence-bundle-manifest-v2'
const OPEN_READ_FLAGS = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0)
const OPEN_WRITE_FLAGS = fsConstants.O_WRONLY
  | fsConstants.O_CREAT
  | fsConstants.O_EXCL
  | (fsConstants.O_NOFOLLOW ?? 0)
const VERIFIED_BUNDLE_SNAPSHOT = Symbol('verifiedEvidenceBundleSnapshot')

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

export function canonicalEvidencePayloadPath(value) {
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
  for (const segment of segments) {
    const stem = segment.split('.')[0]
    if (
      /[<>:"|?*\u0000-\u001f]/.test(segment)
      || /[. ]$/.test(segment)
      || /^(?:con|prn|aux|nul|clock\$|com[1-9]|lpt[1-9])$/i.test(stem)
    ) {
      throw new EvidenceBundleError(
        'EVIDENCE_PAYLOAD_PATH_INVALID',
        `payload path is not portable across supported filesystems: ${String(value)}`,
      )
    }
  }
  return normalized
}

/**
 * The bundle's root digest covers the complete canonical profile: provenance,
 * coverage, attestation, evidence identity, and the ordered payload records.
 * Object keys are canonicalized while array order remains evidentiary.
 */
function canonicalValue(value) {
  if (Array.isArray(value)) return value.map(canonicalValue)
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(
      Object.keys(value)
        .sort(compareCanonicalStrings)
        .map((key) => [key, canonicalValue(value[key])]),
    )
  }
  return value
}

export function evidenceBundleRootDigest(value, {
  algorithm = EVIDENCE_ROOT_ALGORITHM_V2,
} = {}) {
  if (algorithm === EVIDENCE_ROOT_ALGORITHM_V1) {
    const files = Array.isArray(value) ? value : value?.files
    if (!Array.isArray(files)) throw new TypeError('legacy evidence root requires a file list')
    const material = files
      .map(({ path, sha256: digest, size }) => [path, digest, size])
      .sort((left, right) => compareCanonicalStrings(left[0], right[0]))
    return sha256(JSON.stringify(material))
  }
  if (algorithm !== EVIDENCE_ROOT_ALGORITHM_V2) {
    throw new TypeError(`unsupported evidence bundle root algorithm: ${String(algorithm)}`)
  }
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new TypeError('evidence bundle root requires the complete sealed profile')
  }
  return sha256(JSON.stringify(canonicalValue(value)))
}

function samePath(left, right) {
  return process.platform === 'win32'
    ? left.toLowerCase() === right.toLowerCase()
    : left === right
}

function sameFile(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
    && left.nlink === right.nlink
}

async function createSafeDirectoryTree(path, code, message) {
  const missing = []
  let current = resolve(path)
  while (true) {
    let metadata
    try {
      metadata = await lstat(current, { bigint: true })
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        throw new EvidenceBundleError(code, `${message}: ${error.code ?? error.message}`)
      }
      missing.push(current)
      const parent = dirname(current)
      if (parent === current) {
        throw new EvidenceBundleError(code, `${message}: no existing safe ancestor`)
      }
      current = parent
      continue
    }
    let canonical
    try {
      canonical = await realpath(current)
    } catch (error) {
      throw new EvidenceBundleError(code, `${message}: ${error.code ?? error.message}`)
    }
    if (!metadata.isDirectory() || metadata.isSymbolicLink() || !samePath(canonical, current)) {
      throw new EvidenceBundleError(code, message)
    }
    break
  }
  for (const directory of missing.reverse()) {
    try {
      await mkdir(directory, { recursive: false, mode: 0o700 })
    } catch (error) {
      if (error?.code !== 'EEXIST') throw error
    }
    await assertSafeDirectory(directory, code, message)
  }
}

async function assertSafeDirectory(path, code, message) {
  let metadata
  let canonical
  try {
    metadata = await lstat(path, { bigint: true })
    canonical = await realpath(path)
  } catch (error) {
    throw new EvidenceBundleError(code, `${message}: ${error.code ?? error.message}`)
  }
  if (!metadata.isDirectory() || metadata.isSymbolicLink() || !samePath(canonical, resolve(path))) {
    throw new EvidenceBundleError(code, message)
  }
  return metadata
}

async function snapshotDirectoryAncestors(root, file, code, message) {
  const canonicalRoot = resolve(root)
  const parent = dirname(resolve(file))
  const suffix = relative(canonicalRoot, parent)
  if (suffix === '..' || suffix.startsWith(`..${sep}`) || isAbsolute(suffix)) {
    throw new EvidenceBundleError(code, `${message}: file is outside its bundle root`, { bundle: canonicalRoot })
  }
  const paths = [canonicalRoot]
  if (suffix !== '') {
    let current = canonicalRoot
    for (const segment of suffix.split(sep)) {
      current = join(current, segment)
      paths.push(current)
    }
  }
  const snapshot = []
  for (const path of paths) snapshot.push(await assertSafeDirectory(path, code, message))
  return snapshot
}

function sameDirectorySnapshot(left, right) {
  return left.length === right.length && left.every((metadata, index) => sameFile(metadata, right[index]))
}

async function boundedRegularFile(path, maximumBytes, {
  missingCode,
  unsafeCode,
  tooLargeCode,
  changedCode,
  label,
  expectedSize,
  bundle,
}) {
  const ancestorsBefore = await snapshotDirectoryAncestors(
    bundle,
    path,
    unsafeCode,
    `${label} ancestor is linked or non-canonical`,
  )
  let before
  try {
    before = await lstat(path, { bigint: true })
  } catch (error) {
    throw new EvidenceBundleError(missingCode, `${label} is absent or unreadable: ${path}`, { bundle })
  }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) {
    throw new EvidenceBundleError(unsafeCode, `${label} must be one regular, unlinked file: ${path}`, { bundle })
  }
  if (before.size > BigInt(maximumBytes)) {
    throw new EvidenceBundleError(tooLargeCode, `${label} exceeds ${maximumBytes} bytes: ${path}`, { bundle })
  }
  if (expectedSize !== undefined && before.size !== BigInt(expectedSize)) {
    throw new EvidenceBundleError(changedCode, `${label} size does not match its declaration: ${path}`, { bundle })
  }

  let handle
  try {
    handle = await open(path, OPEN_READ_FLAGS)
    const heldBefore = await handle.stat({ bigint: true })
    if (!heldBefore.isFile() || heldBefore.nlink !== 1n || !sameFile(before, heldBefore)) {
      throw new EvidenceBundleError(changedCode, `${label} identity changed before reading: ${path}`, { bundle })
    }
    const size = Number(heldBefore.size)
    const bytes = Buffer.alloc(size)
    let offset = 0
    while (offset < size) {
      const { bytesRead } = await handle.read(bytes, offset, size - offset, offset)
      if (bytesRead === 0) break
      offset += bytesRead
    }
    const heldAfter = await handle.stat({ bigint: true })
    const ancestorsAfter = await snapshotDirectoryAncestors(
      bundle,
      path,
      changedCode,
      `${label} ancestor changed while reading`,
    )
    if (offset !== size || !sameFile(heldBefore, heldAfter)
      || !sameDirectorySnapshot(ancestorsBefore, ancestorsAfter)) {
      throw new EvidenceBundleError(changedCode, `${label} changed while reading: ${path}`, { bundle })
    }
    return bytes
  } catch (error) {
    if (error instanceof EvidenceBundleError) throw error
    throw new EvidenceBundleError(unsafeCode, `${label} could not be opened safely: ${path}`, { bundle })
  } finally {
    await handle?.close()
  }
}

async function exclusiveWrite(path, bytes, bundle) {
  let handle
  try {
    handle = await open(path, OPEN_WRITE_FLAGS, 0o600)
    let offset = 0
    while (offset < bytes.length) {
      const { bytesWritten } = await handle.write(bytes, offset, bytes.length - offset, offset)
      if (bytesWritten < 1) throw new Error('write made no progress')
      offset += bytesWritten
    }
    await handle.sync()
    const metadata = await handle.stat({ bigint: true })
    if (!metadata.isFile() || metadata.nlink !== 1n || metadata.size !== BigInt(bytes.length)) {
      throw new Error('published file identity is unsafe')
    }
  } catch (error) {
    throw new EvidenceBundleError(
      'EVIDENCE_BUNDLE_OUTPUT_UNSAFE',
      `refusing to overwrite or follow an existing bundle path: ${path}`,
      { bundle },
    )
  } finally {
    await handle?.close()
  }
}

function assertPortableEntrySet(entries) {
  const seen = new Map()
  const leaves = new Set()
  const directories = new Set()
  for (const { relativePath } of entries) {
    const segments = relativePath.split('/')
    for (let length = 1; length <= segments.length; length += 1) {
      const prefix = segments.slice(0, length).join('/')
      const folded = prefix.normalize('NFC').toLowerCase()
      const prior = seen.get(folded)
      if (prior !== undefined && (prior !== prefix || length === segments.length)) {
        throw new EvidenceBundleError(
          'EVIDENCE_PAYLOAD_PATH_INVALID',
          `payload paths collide or repeat on a supported filesystem: ${prior} and ${prefix}`,
        )
      }
      if ((length === segments.length && directories.has(folded))
        || (length < segments.length && leaves.has(folded))) {
        throw new EvidenceBundleError(
          'EVIDENCE_PAYLOAD_PATH_INVALID',
          `payload path is both a file and a directory prefix: ${prefix}`,
        )
      }
      if (length === segments.length) leaves.add(folded)
      else directories.add(folded)
      seen.set(folded, prefix)
    }
  }
}

async function syncDirectory(path) {
  let handle
  try {
    handle = await open(path, fsConstants.O_RDONLY)
    await handle.sync()
  } catch (error) {
    // Windows does not expose directory FlushFileBuffers through Node. Files
    // are synced before rename; directory sync remains mandatory where the
    // platform implements it.
    if (process.platform !== 'win32' || !['EISDIR', 'EPERM', 'EINVAL', 'EBADF'].includes(error?.code)) {
      throw error
    }
  } finally {
    await handle?.close()
  }
}

async function syncDirectoryTree(path) {
  for (const entry of await readdir(path, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue
    const child = join(path, entry.name)
    await assertSafeDirectory(
      child,
      'EVIDENCE_BUNDLE_OUTPUT_UNSAFE',
      'staged payload directory is linked or non-canonical',
    )
    await syncDirectoryTree(child)
  }
  await syncDirectory(path)
}

async function publishCreateOnly(source, destination, {
  directory = false,
  afterVisible,
} = {}) {
  if (!directory || process.platform === 'win32') {
    await publishFileCreateOnlyDurably(source, destination, { afterVisible })
    return
  }
  await rename(source, destination)
  await afterVisible?.()
  await syncDirectory(dirname(destination))
}

async function pathMetadata(path) {
  try {
    return await lstat(path, { bigint: true })
  } catch (error) {
    if (error?.code === 'ENOENT') return null
    throw error
  }
}

async function assertPublishableExistingRoot(root) {
  const allowed = new Set([
    'acquisition-plan.json',
    'acquisition-state.json',
    'acquisition-stop.json',
    '.acquisition-lock',
    '.acquisition-lock-reclaim',
  ])
  for (const entry of await readdir(root, { withFileTypes: true })) {
    if (!allowed.has(entry.name)) {
      throw new EvidenceBundleError(
        'EVIDENCE_BUNDLE_OUTPUT_UNSAFE',
        `bundle root already contains non-controller output: ${join(root, entry.name)}`,
        { bundle: root },
      )
    }
    const path = join(root, entry.name)
    if (entry.name === '.acquisition-lock' || entry.name === '.acquisition-lock-reclaim') {
      const metadata = await lstat(path, { bigint: true })
      if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1n
        || metadata.size < 1n || metadata.size > 4096n) {
        throw new EvidenceBundleError(
          'EVIDENCE_BUNDLE_OUTPUT_UNSAFE',
          'acquisition lock owner is not one bounded regular file',
          { bundle: root },
        )
      }
      continue
    }
    const metadata = await lstat(path, { bigint: true })
    if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.nlink !== 1n) {
      throw new EvidenceBundleError(
        'EVIDENCE_BUNDLE_OUTPUT_UNSAFE',
        `controller metadata must be one regular, unlinked file: ${path}`,
        { bundle: root },
      )
    }
  }
}

export async function writeEvidenceBundle({ directory, profile, payload = [] }) {
  const root = resolve(directory)
  const entries = payload.map(({ path, bytes }) => {
    const relativePath = canonicalEvidencePayloadPath(path)
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
  assertPortableEntrySet(entries)

  const sealed = assertValidEvidenceProfile({
    ...profile,
    files: entries.map(({ file }) => file),
  })
  const totalBytes = entries.reduce((sum, entry) => sum + entry.buffer.length, 0)
  if (entries.some((entry) => entry.buffer.length > MAX_PAYLOAD_FILE_BYTES)
    || totalBytes > MAX_PAYLOAD_TOTAL_BYTES) {
    throw new EvidenceBundleError(
      'EVIDENCE_BUNDLE_PAYLOAD_TOO_LARGE',
      'evidence payload exceeds its bounded file or bundle byte limit',
      { bundle: root },
    )
  }
  const rootDigest = evidenceBundleRootDigest(sealed, { algorithm: EVIDENCE_ROOT_ALGORITHM_V2 })
  const manifestBytes = Buffer.from(`${JSON.stringify({
    schema: EVIDENCE_MANIFEST_SCHEMA_V2,
    root_algorithm: EVIDENCE_ROOT_ALGORITHM_V2,
    profile: sealed,
    root_sha256: rootDigest,
  }, null, 2)}\n`, 'utf8')
  if (manifestBytes.length > MAX_MANIFEST_BYTES) {
    throw new EvidenceBundleError(
      'EVIDENCE_BUNDLE_MANIFEST_TOO_LARGE',
      `evidence bundle manifest exceeds ${MAX_MANIFEST_BYTES} bytes`,
      { bundle: root },
    )
  }
  const parent = dirname(root)
  await createSafeDirectoryTree(
    parent,
    'EVIDENCE_BUNDLE_OUTPUT_UNSAFE',
    'bundle ancestor is linked or non-canonical',
  )
  const stage = join(parent, `.${basename(root)}.evidence-${randomUUID()}.tmp`)
  let movedPayload = false
  let movedManifest = false
  let movedRoot = false
  try {
    await mkdir(stage, { recursive: false, mode: 0o700 })
    await assertSafeDirectory(stage, 'EVIDENCE_BUNDLE_OUTPUT_UNSAFE', 'staged bundle root is unsafe')
    await mkdir(join(stage, PAYLOAD_DIRECTORY), { recursive: false, mode: 0o700 })
    for (const entry of entries) {
      const target = join(stage, PAYLOAD_DIRECTORY, ...entry.relativePath.split('/'))
      await mkdir(dirname(target), { recursive: true })
      await assertSafeDirectory(dirname(target), 'EVIDENCE_BUNDLE_OUTPUT_UNSAFE', 'staged payload parent is unsafe')
      await exclusiveWrite(target, entry.buffer, root)
    }
    await exclusiveWrite(
      join(stage, EVIDENCE_MANIFEST_FILE),
      manifestBytes,
      root,
    )
    await syncDirectoryTree(join(stage, PAYLOAD_DIRECTORY))
    await syncDirectory(stage)

    const existingRoot = await pathMetadata(root)
    if (existingRoot === null) {
      await publishCreateOnly(stage, root, {
        directory: true,
        afterVisible: () => { movedRoot = true },
      })
    } else {
      await assertSafeDirectory(root, 'EVIDENCE_BUNDLE_OUTPUT_UNSAFE', 'bundle root is linked or non-canonical')
      await assertPublishableExistingRoot(root)
      await publishCreateOnly(
        join(stage, PAYLOAD_DIRECTORY),
        join(root, PAYLOAD_DIRECTORY),
        {
          directory: true,
          afterVisible: () => { movedPayload = true },
        },
      )
      await publishCreateOnly(
        join(stage, EVIDENCE_MANIFEST_FILE),
        join(root, EVIDENCE_MANIFEST_FILE),
        { afterVisible: () => { movedManifest = true } },
      )
      await syncDirectory(root)
      await rm(stage, { recursive: true, force: true })
    }
  } catch (error) {
    if (movedRoot) await rm(root, { recursive: true, force: true })
    else {
      if (movedPayload) {
        await rm(join(root, PAYLOAD_DIRECTORY), { recursive: true, force: true })
      }
      if (movedManifest) await rm(join(root, EVIDENCE_MANIFEST_FILE), { force: true })
      await rm(stage, { recursive: true, force: true })
    }
    if (error instanceof EvidenceBundleError) throw error
    throw new EvidenceBundleError(
      'EVIDENCE_BUNDLE_OUTPUT_UNSAFE',
      `staged evidence bundle publication failed: ${error?.code ?? error?.message ?? String(error)}`,
      { bundle: root },
    )
  }
  return { directory: root, root_sha256: rootDigest, profile: sealed }
}

async function readManifest(root) {
  const manifestPath = join(root, EVIDENCE_MANIFEST_FILE)
  let text
  try {
    text = (await boundedRegularFile(manifestPath, MAX_MANIFEST_BYTES, {
      missingCode: 'EVIDENCE_BUNDLE_MANIFEST_UNREADABLE',
      unsafeCode: 'EVIDENCE_BUNDLE_MANIFEST_UNSAFE',
      tooLargeCode: 'EVIDENCE_BUNDLE_MANIFEST_TOO_LARGE',
      changedCode: 'EVIDENCE_BUNDLE_MANIFEST_CHANGED',
      label: 'evidence bundle manifest',
      bundle: root,
    })).toString('utf8')
  } catch (error) {
    if (error instanceof EvidenceBundleError) throw error
    throw new EvidenceBundleError(
      'EVIDENCE_BUNDLE_MANIFEST_UNREADABLE',
      `evidence bundle manifest not found: ${manifestPath}`,
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
  await assertSafeDirectory(
    payloadRoot,
    'EVIDENCE_BUNDLE_SYMLINK',
    'an evidence bundle cannot contain a linked payload root',
  )
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
      if (entry.isDirectory()) {
        await assertSafeDirectory(path, 'EVIDENCE_BUNDLE_SYMLINK', 'an evidence bundle cannot contain a linked directory')
        await visit(path)
      }
      else if (entry.isFile()) {
        const metadata = await lstat(path, { bigint: true })
        if (metadata.nlink !== 1n) {
          throw new EvidenceBundleError(
            'EVIDENCE_BUNDLE_HARDLINK',
            `an evidence bundle cannot contain a hard link: ${path}`,
            { bundle: root },
          )
        }
        found.push(`${PAYLOAD_DIRECTORY}/${relative(payloadRoot, path).split(sep).join('/')}`)
      }
    }
  }
  await visit(payloadRoot)
  return found.sort(compareCanonicalStrings)
}

function immutableJsonSnapshot(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(immutableJsonSnapshot))
  if (value !== null && typeof value === 'object') {
    return Object.freeze(Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, immutableJsonSnapshot(entry)]),
    ))
  }
  return value
}

function evidenceBundleProjection(root, manifest) {
  const profile = immutableJsonSnapshot(manifest?.profile)
  return Object.freeze({
    directory: root,
    profile,
    evidence_context: profile?.evidence_context,
    root_sha256: manifest?.root_sha256,
    root_algorithm: manifest?.root_algorithm ?? EVIDENCE_ROOT_ALGORITHM_V1,
  })
}

export async function verifyEvidenceBundle(directory) {
  const root = resolve(directory)
  const errors = []
  let rootBefore
  try {
    rootBefore = await assertSafeDirectory(
      root,
      'EVIDENCE_BUNDLE_ROOT_UNSAFE',
      'evidence bundle root is linked or non-canonical',
    )
  } catch (error) {
    return { valid: false, root_sha256: null, errors: [{ code: error.code, message: error.message }] }
  }
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
  const isLegacy = manifest?.schema === undefined && manifest?.root_algorithm === undefined
  const rootAlgorithm = isLegacy ? EVIDENCE_ROOT_ALGORITHM_V1 : manifest?.root_algorithm
  if (!isLegacy && (
    manifest?.schema !== EVIDENCE_MANIFEST_SCHEMA_V2
    || rootAlgorithm !== EVIDENCE_ROOT_ALGORITHM_V2
  )) {
    errors.push({
      code: 'ROOT_ALGORITHM_UNSUPPORTED',
      message: 'evidence bundle manifest names an unsupported schema or root algorithm',
    })
  }
  let expectedRoot = null
  try {
    expectedRoot = evidenceBundleRootDigest(
      isLegacy ? files : manifest?.profile,
      { algorithm: rootAlgorithm },
    )
  } catch (error) {
    errors.push({ code: 'ROOT_MATERIAL_INVALID', message: error.message })
  }
  if (expectedRoot === null || manifest?.root_sha256 !== expectedRoot) {
    errors.push({
      code: 'ROOT_DIGEST_MISMATCH',
      message: `manifest root digest ${String(manifest?.root_sha256)} does not cover its own file list`,
    })
  }

  const declared = new Set()
  const declaredTotal = files.reduce((sum, file) => (
    Number.isSafeInteger(file?.size) && file.size >= 0 ? sum + file.size : sum
  ), 0)
  if (declaredTotal > MAX_PAYLOAD_TOTAL_BYTES) {
    errors.push({
      code: 'PAYLOAD_TOTAL_TOO_LARGE',
      message: `declared payload exceeds ${MAX_PAYLOAD_TOTAL_BYTES} bytes`,
    })
  }
  for (const file of files) {
    let safePath
    try {
      safePath = canonicalEvidencePayloadPath(file?.path)
      if (safePath !== file.path || !safePath.startsWith(`${PAYLOAD_DIRECTORY}/`)) {
        throw new EvidenceBundleError('EVIDENCE_PAYLOAD_PATH_INVALID', 'declared payload path is not canonical')
      }
      declared.add(safePath)
    } catch (error) {
      errors.push({ code: 'EVIDENCE_PAYLOAD_PATH_INVALID', message: error.message })
      continue
    }
    if (!Number.isSafeInteger(file?.size) || file.size < 0 || file.size > MAX_PAYLOAD_FILE_BYTES) {
      errors.push({
        code: 'PAYLOAD_FILE_TOO_LARGE',
        message: `declared payload file exceeds ${MAX_PAYLOAD_FILE_BYTES} bytes: ${file?.path}`,
      })
      continue
    }
    let bytes
    try {
      bytes = await boundedRegularFile(
        join(root, ...safePath.split('/')),
        MAX_PAYLOAD_FILE_BYTES,
        {
          missingCode: 'PAYLOAD_FILE_MISSING',
          unsafeCode: 'PAYLOAD_FILE_UNSAFE',
          tooLargeCode: 'PAYLOAD_FILE_TOO_LARGE',
          changedCode: 'PAYLOAD_DIGEST_MISMATCH',
          label: 'declared payload file',
          expectedSize: file.size,
          bundle: root,
        },
      )
    } catch (error) {
      errors.push({ code: error.code, message: error.message })
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

  try {
    const rootAfter = await assertSafeDirectory(
      root,
      'EVIDENCE_BUNDLE_ROOT_UNSAFE',
      'evidence bundle root changed or became linked during verification',
    )
    if (!sameFile(rootBefore, rootAfter)) {
      errors.push({
        code: 'EVIDENCE_BUNDLE_ROOT_CHANGED',
        message: 'evidence bundle root identity changed during verification',
      })
    }
  } catch (error) {
    errors.push({ code: error.code, message: error.message })
  }

  const verification = {
    valid: errors.length === 0,
    root_sha256: expectedRoot,
    root_algorithm: rootAlgorithm,
    errors,
  }
  if (verification.valid) {
    Object.defineProperty(verification, VERIFIED_BUNDLE_SNAPSHOT, {
      value: evidenceBundleProjection(root, manifest),
    })
  }
  return verification
}

export async function readEvidenceBundle(directory) {
  const root = resolve(directory)
  const manifest = await readManifest(root)
  return evidenceBundleProjection(root, manifest)
}

export async function readEvidencePayloadFile(directory, payloadPath) {
  const root = resolve(directory)
  const normalized = canonicalEvidencePayloadPath(payloadPath)
  if (!normalized.startsWith(`${PAYLOAD_DIRECTORY}/`)) {
    throw new EvidenceBundleError(
      'EVIDENCE_PAYLOAD_PATH_INVALID',
      `payload path must begin with ${PAYLOAD_DIRECTORY}/: ${payloadPath}`,
      { bundle: root },
    )
  }
  const rootBefore = await assertSafeDirectory(
    root,
    'EVIDENCE_BUNDLE_ROOT_UNSAFE',
    'evidence bundle root is linked or non-canonical',
  )
  const payloadBefore = await assertSafeDirectory(
    join(root, PAYLOAD_DIRECTORY),
    'EVIDENCE_BUNDLE_SYMLINK',
    'an evidence bundle cannot contain a linked payload root',
  )
  const bytes = await boundedRegularFile(join(root, ...normalized.split('/')), MAX_PAYLOAD_FILE_BYTES, {
    missingCode: 'PAYLOAD_FILE_MISSING',
    unsafeCode: 'PAYLOAD_FILE_UNSAFE',
    tooLargeCode: 'PAYLOAD_FILE_TOO_LARGE',
    changedCode: 'PAYLOAD_FILE_CHANGED',
    label: 'evidence payload file',
    bundle: root,
  })
  const rootAfter = await assertSafeDirectory(
    root,
    'EVIDENCE_BUNDLE_ROOT_UNSAFE',
    'evidence bundle root changed during payload read',
  )
  const payloadAfter = await assertSafeDirectory(
    join(root, PAYLOAD_DIRECTORY),
    'EVIDENCE_BUNDLE_SYMLINK',
    'evidence payload root changed during payload read',
  )
  if (!sameFile(rootBefore, rootAfter) || !sameFile(payloadBefore, payloadAfter)) {
    throw new EvidenceBundleError(
      'PAYLOAD_FILE_CHANGED',
      'evidence bundle ancestor identity changed during payload read',
      { bundle: root },
    )
  }
  return bytes
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
  if (verification.root_algorithm !== EVIDENCE_ROOT_ALGORITHM_V2) {
    throw new EvidenceBundleError(
      'EVIDENCE_BUNDLE_MIGRATION_REQUIRED',
      'legacy evidence verifies for migration only; its file-tuple root does not bind metadata required for planning',
      { bundle: resolve(argument) },
    )
  }
  return verification[VERIFIED_BUNDLE_SNAPSHOT]
}
