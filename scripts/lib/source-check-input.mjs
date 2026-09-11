import * as fs from 'node:fs/promises'
import { constants } from 'node:fs'
import { extname, isAbsolute, join, parse, relative, resolve } from 'node:path'

import { assertLocalFilesystemEndpoint } from './filesystem-endpoint.mjs'
import { isSourceCheckPathText, isSourceCheckRelativePath, SOURCE_CHECK_PATH_MAX_CHARACTERS } from './source-check-path.mjs'

export const SOURCE_CHECK_INPUT_LIMITS = Object.freeze({
  max_files: 100,
  max_path_characters: SOURCE_CHECK_PATH_MAX_CHARACTERS,
  max_file_bytes: 256 * 1024,
  max_total_bytes: 8 * 1024 * 1024,
})

const SUPPORTED_EXTENSIONS = new Set(['.js', '.mjs', '.cjs'])
const OPEN_FLAGS = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0)
const GAP_MESSAGES = Object.freeze({
  UNSUPPORTED_LANGUAGE: 'Only JavaScript, MJS, and CJS source files are supported',
  SOURCE_UNREADABLE: 'Source is missing, unsafe, inaccessible, or changed while reading',
  SOURCE_TOO_LARGE: 'Source exceeds the per-file byte limit',
  SOURCE_TOTAL_LIMIT: 'Source exceeds the remaining total byte budget',
  SOURCE_INVALID_UTF8: 'Source does not contain valid UTF-8 text',
})

function fixedError(code) {
  const error = new Error(code === 'SOURCE_CHECK_INPUT_INVALID'
    ? 'Invalid source-check input batch'
    : 'Source-check root is not a readable unlinked local directory')
  error.code = code
  return error
}

function gap(path, code) {
  return { path, gap: { code, message: GAP_MESSAGES[code] } }
}

function validateInputs(root, files) {
  try {
    // This must precede resolve, stat, realpath, or open: Windows network and
    // namespace paths can otherwise trigger remote filesystem activity.
    assertLocalFilesystemEndpoint(root)
    if (!isSourceCheckPathText(root) || !isAbsolute(root)
      || (process.platform === 'win32' && !/^[a-z]:[\\/]/iu.test(root))) throw new Error()
    const absolute = resolve(root)
    assertLocalFilesystemEndpoint(absolute)
    const rootParts = relative(parse(absolute).root, absolute).split(/[\\/]/u).filter(Boolean)
    if (rootParts.some((part) => !isSourceCheckRelativePath(part))) throw new Error()
    if (!Array.isArray(files) || files.length < 1 || files.length > SOURCE_CHECK_INPUT_LIMITS.max_files) throw new Error()
    const seen = new Set()
    for (const path of files) {
      assertLocalFilesystemEndpoint(path)
      if (!isSourceCheckRelativePath(path)) throw new Error()
      const key = process.platform === 'win32' ? path.toLowerCase() : path
      if (seen.has(key)) throw new Error()
      seen.add(key)
    }
    return { root: absolute, files: [...files] }
  } catch {
    throw fixedError('SOURCE_CHECK_INPUT_INVALID')
  }
}

function equalPath(left, right) {
  return process.platform === 'win32' ? left.toLowerCase() === right.toLowerCase() : left === right
}

function sameFile(left, right) {
  return left.dev === right.dev && left.ino === right.ino && left.size === right.size
    && left.mtimeMs === right.mtimeMs && left.ctimeMs === right.ctimeMs
    && left.mtimeNs === right.mtimeNs && left.ctimeNs === right.ctimeNs
    && left.nlink === right.nlink
}

function regularSingleLink(metadata) {
  return metadata.isFile() && !metadata.isSymbolicLink()
    && (metadata.nlink === 1 || metadata.nlink === 1n)
    && (typeof metadata.size === 'bigint'
      ? metadata.size >= 0n && metadata.size <= BigInt(Number.MAX_SAFE_INTEGER)
      : Number.isSafeInteger(metadata.size) && metadata.size >= 0)
}

async function checkedEndpoint(path, fileSystem, kind) {
  const filesystemRoot = parse(path).root
  let current = filesystemRoot
  let metadata = await fileSystem.lstat(current, { bigint: true })
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) throw new Error()
  const parts = relative(filesystemRoot, path).split(/[\\/]/u).filter(Boolean)
  for (const [index, part] of parts.entries()) {
    current = join(current, part)
    metadata = await fileSystem.lstat(current, { bigint: true })
    if (metadata.isSymbolicLink() || (index < parts.length - 1 && !metadata.isDirectory())) throw new Error()
  }
  if (kind === 'directory' ? !metadata.isDirectory() : !regularSingleLink(metadata)) throw new Error()
  const canonical = await fileSystem.realpath(path)
  assertLocalFilesystemEndpoint(canonical)
  if (!equalPath(canonical, path)) throw new Error()
  return metadata
}

function assertContained(root, path) {
  const inside = relative(root, path)
  if (inside === '' || inside === '..' || inside.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) || isAbsolute(inside)) throw new Error()
}

async function readOne(path, root, rootMetadata, fileSystem, budget) {
  let handle
  try {
    const absolute = resolve(root, ...path.split('/'))
    assertContained(root, absolute)
    const metadata = await checkedEndpoint(absolute, fileSystem, 'file')
    const size = Number(metadata.size)
    if (size > SOURCE_CHECK_INPUT_LIMITS.max_file_bytes) return gap(path, 'SOURCE_TOO_LARGE')
    if (size > budget.remaining) return gap(path, 'SOURCE_TOTAL_LIMIT')
    // Charge attempted reads too: invalid UTF-8 and changing inputs must not
    // bypass the batch's bounded consumption budget.
    budget.remaining -= size
    handle = await fileSystem.open(absolute, OPEN_FLAGS)
    const before = await handle.stat({ bigint: true })
    if (!regularSingleLink(before) || !sameFile(metadata, before)) throw new Error()
    const buffer = Buffer.alloc(size + 1)
    let offset = 0
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset)
      if (!Number.isSafeInteger(bytesRead) || bytesRead < 0 || bytesRead > buffer.length - offset) throw new Error()
      if (bytesRead === 0) break
      offset += bytesRead
    }
    const after = await handle.stat({ bigint: true })
    const endpointAfter = await checkedEndpoint(absolute, fileSystem, 'file')
    const rootAfter = await checkedEndpoint(root, fileSystem, 'directory')
    if (offset !== size || !regularSingleLink(after) || !sameFile(before, after)
      || !sameFile(before, endpointAfter) || rootAfter.dev !== rootMetadata.dev || rootAfter.ino !== rootMetadata.ino) throw new Error()
    let source
    try {
      // Preserve a leading BOM so re-encoding valid input preserves its bytes.
      source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(buffer.subarray(0, offset))
    } catch {
      return gap(path, 'SOURCE_INVALID_UTF8')
    }
    return { path, source }
  } catch {
    return gap(path, 'SOURCE_UNREADABLE')
  } finally {
    if (handle) {
      try { await handle.close() } catch { /* Closing must not disclose filesystem error text. */ }
    }
  }
}

/**
 * Read only operator-listed local source files; never traverse directories,
 * import targets, interpret target configuration, or perform network requests.
 * Endpoint and metadata checks detect common link/change hazards, but are not
 * OS confinement against a hostile concurrently-mutating filesystem. Use a
 * quiescent trusted local snapshot; mounted remote filesystems cannot be
 * identified reliably by this portable reader.
 */
export async function readSourceCheckInputs({ root, files, fileSystem = fs } = {}) {
  const validated = validateInputs(root, files)
  let rootMetadata
  try {
    rootMetadata = await checkedEndpoint(validated.root, fileSystem, 'directory')
  } catch {
    throw fixedError('SOURCE_CHECK_ROOT_UNREADABLE')
  }
  const budget = { remaining: SOURCE_CHECK_INPUT_LIMITS.max_total_bytes }
  const results = []
  for (const path of validated.files) {
    if (!SUPPORTED_EXTENSIONS.has(extname(path).toLowerCase())) results.push(gap(path, 'UNSUPPORTED_LANGUAGE'))
    else results.push(await readOne(path, validated.root, rootMetadata, fileSystem, budget))
  }
  return results
}
