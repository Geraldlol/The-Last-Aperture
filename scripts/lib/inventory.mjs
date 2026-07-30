import { createHash } from 'node:crypto'
import { constants as fsConstants } from 'node:fs'
import { lstat, open, opendir, realpath } from 'node:fs/promises'
import { isAbsolute, relative, resolve, sep } from 'node:path'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { classifyCoverageEntry } from './coverage-model.mjs'

const DEFAULT_EXCLUDED_DIRECTORIES = Object.freeze([
  '.git',
  '.audit-runs',
  'node_modules',
])

const DEFAULT_INVENTORY_LIMITS = Object.freeze({
  maxTextBytes: 2 * 1024 * 1024,
  maxInventoryFiles: 100_000,
  maxInventoryBytes: 256 * 1024 * 1024,
  maxTraversalEntries: 200_000,
  maxDirectoryDepth: 64,
})

export const INVENTORY_CATEGORIES = Object.freeze([
  'canonical-source',
  'generated-code',
  'tests',
  'docs',
  'binaries',
])

const CATEGORY_BY_COVERAGE_CLASS = Object.freeze({
  CANONICAL_SOURCE: 'canonical-source',
  GENERATED_CODE: 'generated-code',
  TEST: 'tests',
  DOCUMENTATION: 'docs',
  BINARY: 'binaries',
})

export function classifyInventoryEntry(entry) {
  const { coverage_class: coverageClass } = classifyCoverageEntry(entry)
  return CATEGORY_BY_COVERAGE_CLASS[coverageClass] ?? 'canonical-source'
}

const OPEN_READ_ONLY_NO_FOLLOW = fsConstants.O_RDONLY
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)

function toPosix(path) {
  return path.split(sep).join('/')
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function isInside(root, candidate) {
  const rel = relative(root, candidate)
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel))
}

function sameResolvedPath(left, right) {
  const normalizedLeft = resolve(left)
  const normalizedRight = resolve(right)
  return process.platform === 'win32'
    ? normalizedLeft.toLowerCase() === normalizedRight.toLowerCase()
    : normalizedLeft === normalizedRight
}

function looksBinary(buffer) {
  if (buffer.length === 0) return false
  const sample = buffer.subarray(0, Math.min(buffer.length, 8192))
  if (sample.includes(0)) return true
  let suspicious = 0
  for (const byte of sample) {
    if (byte < 7 || (byte > 13 && byte < 32)) suspicious += 1
  }
  return suspicious / sample.length > 0.1
}

function normalizedExclusions(values) {
  return new Set(values.map((value) => String(value).replaceAll('\\', '/').replace(/^\.?\//, '').replace(/\/$/, '')))
}

export function normalizeIncludedRoots(values) {
  const normalized = values.map((value) =>
    String(value).replaceAll('\\', '/').replace(/^\.?\//, '').replace(/\/$/, '') || '.')
  for (const value of normalized) {
    if (
      value.startsWith('/')
      || /^[A-Za-z]:/.test(value)
      || value === '..'
      || value.startsWith('../')
      || value.includes('/../')
    ) {
      throw new Error(`inventory include root must be workspace-relative: ${value}`)
    }
  }
  if (normalized.includes('.')) return ['.']
  const sorted = [...new Set(normalized)].sort((left, right) =>
    left.split('/').length - right.split('/').length
    || compareCanonicalStrings(left, right))
  return sorted.filter((value, index) =>
    !sorted.slice(0, index).some((parent) => value.startsWith(`${parent}/`)))
}

function directoryIsExcluded(relativePath, name, exclusions) {
  const normalized = toPosix(relativePath)
  return exclusions.has(name) || exclusions.has(normalized)
}

function boundedInteger(name, value, fallback) {
  const resolvedValue = value ?? fallback
  if (!Number.isSafeInteger(resolvedValue) || resolvedValue < 0) {
    throw new Error(`${name} must be a non-negative safe integer`)
  }
  return resolvedValue
}

function numericSize(metadata) {
  return Number(metadata.size)
}

function sameStatSnapshot(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.nlink === right.nlink
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
    && left.birthtimeNs === right.birthtimeNs
}

async function readExact(handle, size) {
  const bytes = Buffer.alloc(size)
  let offset = 0
  while (offset < size) {
    const { bytesRead } = await handle.read(
      bytes,
      offset,
      Math.min(64 * 1024, size - offset),
      offset,
    )
    if (bytesRead === 0) break
    offset += bytesRead
  }
  return offset === size ? bytes : bytes.subarray(0, offset)
}

async function readPrefix(handle, size) {
  const bytes = Buffer.alloc(Math.min(size, 8192))
  let offset = 0
  while (offset < bytes.length) {
    const { bytesRead } = await handle.read(
      bytes,
      offset,
      bytes.length - offset,
      offset,
    )
    if (bytesRead === 0) break
    offset += bytesRead
  }
  return offset === bytes.length ? bytes : bytes.subarray(0, offset)
}

/**
 * Deterministically inventories a repository without invoking repository code,
 * following symlinks, or relying on gitignore semantics. Hidden paths are
 * included unless explicitly excluded.
 */
export async function inventoryRepository(targetRoot, options = {}) {
  const configuredRoot = resolve(targetRoot)
  const root = await realpath(configuredRoot)
  const exclusions = normalizedExclusions(
    options.excludedDirectories ?? DEFAULT_EXCLUDED_DIRECTORIES,
  )
  const includedRoots = normalizeIncludedRoots(options.includedRoots ?? ['.'])
  const maxTextBytes = boundedInteger(
    'maxTextBytes',
    options.maxTextBytes,
    DEFAULT_INVENTORY_LIMITS.maxTextBytes,
  )
  const maxInventoryFiles = boundedInteger(
    'maxInventoryFiles',
    options.maxInventoryFiles,
    DEFAULT_INVENTORY_LIMITS.maxInventoryFiles,
  )
  const maxInventoryBytes = boundedInteger(
    'maxInventoryBytes',
    options.maxInventoryBytes,
    DEFAULT_INVENTORY_LIMITS.maxInventoryBytes,
  )
  const maxTraversalEntries = boundedInteger(
    'maxTraversalEntries',
    options.maxTraversalEntries,
    DEFAULT_INVENTORY_LIMITS.maxTraversalEntries,
  )
  const maxDirectoryDepth = boundedInteger(
    'maxDirectoryDepth',
    options.maxDirectoryDepth,
    DEFAULT_INVENTORY_LIMITS.maxDirectoryDepth,
  )
  const entries = []
  const excluded = []
  const errors = []
  let inventoriedFiles = 0
  let reservedInventoryBytes = 0n
  let traversedEntries = 0
  let fileLimitReached = false
  let traversalLimitReached = false

  function pushError(path, operation, code, message) {
    errors.push({ path, operation, code, message })
  }

  function pushUnreadable(relativePath, size, reason, operation, code, message) {
    entries.push({
      path: relativePath,
      kind: 'unreadable',
      size,
      examined: false,
      reason,
    })
    pushError(relativePath, operation, code, message)
  }

  function pushTargetChanged(relativePath, metadata, operation, message) {
    pushUnreadable(
      relativePath,
      numericSize(metadata),
      'inventory-target-changed',
      operation,
      'TARGET_CHANGED',
      message,
    )
  }

  async function pathStillCanonical(absolutePath) {
    const canonicalPath = await realpath(absolutePath)
    return isInside(root, canonicalPath) && sameResolvedPath(absolutePath, canonicalPath)
  }

  async function recordPath(absolutePath, relativePath, metadataHint) {
    if (inventoriedFiles >= maxInventoryFiles) {
      if (!fileLimitReached) {
        fileLimitReached = true
        pushError(
          relativePath,
          'quota',
          'MAX_FILES_EXCEEDED',
          `inventory stopped before this path because the ${maxInventoryFiles}-file limit was reached`,
        )
      }
      return false
    }
    inventoriedFiles += 1

    let metadata = metadataHint
    if (!metadata) {
      try {
        metadata = await lstat(absolutePath, { bigint: true })
      } catch (error) {
        pushError(relativePath, 'lstat', error.code ?? 'UNKNOWN', error.message)
        return true
      }
    }

    if (metadata.isSymbolicLink()) {
      entries.push({
        path: relativePath,
        kind: 'symlink',
        size: numericSize(metadata),
        examined: false,
        reason: 'symlink-not-followed',
      })
      return true
    }
    if (!metadata.isFile()) {
      entries.push({
        path: relativePath,
        kind: 'special',
        size: numericSize(metadata),
        examined: false,
        reason: 'non-regular-file',
      })
      return true
    }

    try {
      if (!await pathStillCanonical(absolutePath)) {
        pushTargetChanged(
          relativePath,
          metadata,
          'verify-path',
          'inventory path resolved through a symlink, reparse point, or outside the repository',
        )
        return true
      }
    } catch (error) {
      pushTargetChanged(
        relativePath,
        metadata,
        'verify-path',
        `inventory path changed before it could be opened: ${error.code ?? 'UNKNOWN'}`,
      )
      return true
    }

    let handle
    try {
      handle = await open(absolutePath, OPEN_READ_ONLY_NO_FOLLOW)
    } catch (error) {
      if (error.code === 'ELOOP' || error.code === 'EMLINK') {
        pushTargetChanged(
          relativePath,
          metadata,
          'open-no-follow',
          'inventory target became a symlink or reparse point before it could be opened',
        )
      } else {
        pushUnreadable(
          relativePath,
          numericSize(metadata),
          error.code ?? 'open-failed',
          'open',
          error.code ?? 'UNKNOWN',
          error.message,
        )
      }
      return true
    }

    try {
      let openedMetadata
      try {
        openedMetadata = await handle.stat({ bigint: true })
      } catch (error) {
        pushUnreadable(
          relativePath,
          numericSize(metadata),
          error.code ?? 'fstat-failed',
          'fstat',
          error.code ?? 'UNKNOWN',
          error.message,
        )
        return true
      }

      if (!openedMetadata.isFile() || !sameStatSnapshot(metadata, openedMetadata)) {
        pushTargetChanged(
          relativePath,
          openedMetadata,
          'verify-open-file',
          'inventory target identity or metadata changed between lstat and open',
        )
        return true
      }

      try {
        if (!await pathStillCanonical(absolutePath)) {
          pushTargetChanged(
            relativePath,
            openedMetadata,
            'verify-open-file',
            'inventory path became a symlink, reparse point, or escaped the repository after open',
          )
          return true
        }
      } catch (error) {
        pushTargetChanged(
          relativePath,
          openedMetadata,
          'verify-open-file',
          `inventory path changed after open: ${error.code ?? 'UNKNOWN'}`,
        )
        return true
      }

      if (openedMetadata.size > BigInt(maxTextBytes)) {
        let prefix
        try {
          prefix = await readPrefix(handle, numericSize(openedMetadata))
        } catch (error) {
          pushUnreadable(
            relativePath,
            numericSize(openedMetadata),
            error.code ?? 'read-failed',
            'read-prefix',
            error.code ?? 'UNKNOWN',
            error.message,
          )
          return true
        }

        let finalMetadata
        try {
          finalMetadata = await handle.stat({ bigint: true })
        } catch (error) {
          pushUnreadable(
            relativePath,
            numericSize(openedMetadata),
            error.code ?? 'fstat-failed',
            'fstat-after-prefix',
            error.code ?? 'UNKNOWN',
            error.message,
          )
          return true
        }

        let canonicalAfterRead = false
        try {
          canonicalAfterRead = await pathStillCanonical(absolutePath)
        } catch {
          canonicalAfterRead = false
        }
        if (
          !canonicalAfterRead
          || !sameStatSnapshot(openedMetadata, finalMetadata)
          || prefix.length !== Math.min(numericSize(openedMetadata), 8192)
        ) {
          pushTargetChanged(
            relativePath,
            finalMetadata,
            'verify-after-prefix',
            'inventory target identity, metadata, or path changed while its prefix was being read',
          )
          return true
        }

        if (looksBinary(prefix)) {
          entries.push({
            path: relativePath,
            absolutePath,
            kind: 'binary',
            size: numericSize(openedMetadata),
            examined: false,
            reason: 'binary-content-not-decoded',
            content: null,
          })
          return true
        }

        entries.push({
          path: relativePath,
          kind: 'too-large',
          size: numericSize(openedMetadata),
          examined: false,
          reason: `larger-than-${maxTextBytes}-byte-static-limit`,
        })
        return true
      }

      if (reservedInventoryBytes + openedMetadata.size > BigInt(maxInventoryBytes)) {
        entries.push({
          path: relativePath,
          kind: 'quota-exceeded',
          size: numericSize(openedMetadata),
          examined: false,
          reason: `total-inventory-byte-limit-${maxInventoryBytes}-bytes-exceeded`,
        })
        pushError(
          relativePath,
          'quota',
          'MAX_TOTAL_BYTES_EXCEEDED',
          `reading this file would exceed the ${maxInventoryBytes}-byte total inventory limit`,
        )
        return true
      }

      reservedInventoryBytes += openedMetadata.size

      let bytes
      try {
        bytes = await readExact(handle, numericSize(openedMetadata))
      } catch (error) {
        pushUnreadable(
          relativePath,
          numericSize(openedMetadata),
          error.code ?? 'read-failed',
          'read',
          error.code ?? 'UNKNOWN',
          error.message,
        )
        return true
      }

      let finalMetadata
      try {
        finalMetadata = await handle.stat({ bigint: true })
      } catch (error) {
        pushUnreadable(
          relativePath,
          numericSize(openedMetadata),
          error.code ?? 'fstat-failed',
          'fstat-after-read',
          error.code ?? 'UNKNOWN',
          error.message,
        )
        return true
      }

      let canonicalAfterRead = false
      try {
        canonicalAfterRead = await pathStillCanonical(absolutePath)
      } catch {
        canonicalAfterRead = false
      }
      if (
        !canonicalAfterRead
        || !sameStatSnapshot(openedMetadata, finalMetadata)
        || bytes.length !== numericSize(openedMetadata)
      ) {
        pushTargetChanged(
          relativePath,
          finalMetadata,
          'verify-after-read',
          'inventory target identity, metadata, or path changed while it was being read',
        )
        return true
      }

      const binary = looksBinary(bytes)
      const content = binary ? null : bytes.toString('utf8')
      const kind = binary ? 'binary' : 'text'
      entries.push({
        path: relativePath,
        absolutePath,
        kind,
        size: bytes.length,
        sha256: sha256(bytes),
        examined: !binary,
        reason: binary ? 'binary-content-not-decoded' : null,
        content,
      })
    } finally {
      try {
        await handle.close()
      } catch (error) {
        pushError(relativePath, 'close', error.code ?? 'UNKNOWN', error.message)
      }
    }
    return true
  }

  async function visit(directory, depth) {
    if (depth > maxDirectoryDepth) {
      pushError(
        `${toPosix(relative(root, directory)) || '.'}/`,
        'depth',
        'MAX_DEPTH_EXCEEDED',
        `inventory did not descend beyond the ${maxDirectoryDepth}-directory depth limit`,
      )
      return
    }

    const directoryPath = `${toPosix(relative(root, directory)) || '.'}/`
    const children = []
    let directoryHandle
    try {
      directoryHandle = await opendir(directory)
    } catch (error) {
      pushError(
        toPosix(relative(root, directory)) || '.',
        'opendir',
        error.code ?? 'UNKNOWN',
        error.message,
      )
      return
    }

    const remainingEntries = maxTraversalEntries - traversedEntries
    let enumerationError = null
    try {
      while (true) {
        const child = await directoryHandle.read()
        if (child === null) break
        if (children.length >= remainingEntries) {
          traversalLimitReached = true
          break
        }
        children.push(child)
      }
    } catch (error) {
      enumerationError = error
    } finally {
      try {
        await directoryHandle.close()
      } catch (error) {
        if (!enumerationError) enumerationError = error
      }
    }

    if (enumerationError) {
      pushError(
        toPosix(relative(root, directory)) || '.',
        'readdir',
        enumerationError.code ?? 'UNKNOWN',
        enumerationError.message,
      )
      return
    }
    if (traversalLimitReached) {
      pushError(
        directoryPath,
        'quota',
        'MAX_TRAVERSAL_ENTRIES_EXCEEDED',
        `inventory stopped at this directory because the ${maxTraversalEntries}-traversal-entry limit was exceeded`,
      )
      return
    }

    traversedEntries += children.length
    children.sort((left, right) =>
      compareCanonicalStrings(left.name, right.name))
    for (const child of children) {
      if (fileLimitReached || traversalLimitReached) break
      const absolutePath = resolve(directory, child.name)
      const relativePath = toPosix(relative(root, absolutePath))
      if (!isInside(root, absolutePath)) {
        pushError(
          relativePath,
          'boundary',
          'OUTSIDE_ROOT',
          'resolved inventory path escaped the repository root',
        )
        continue
      }

      if (child.isDirectory()) {
        if (directoryIsExcluded(relativePath, child.name, exclusions)) {
          excluded.push({ path: `${relativePath}/`, reason: 'configured-directory-exclusion' })
        } else {
          await visit(absolutePath, depth + 1)
        }
        continue
      }

      const shouldContinue = await recordPath(absolutePath, relativePath)
      if (!shouldContinue) break
    }
  }

  if (includedRoots.length === 0) {
    excluded.push({
      path: '<workspace>/',
      reason: 'policy-read-capability-disabled',
    })
  } else {
    if (!includedRoots.includes('.')) {
      excluded.push({
        path: '<outside-read-allowlist>/',
        reason: `policy-read-roots:${includedRoots.join(',')}`,
      })
    }
    for (const includedRoot of includedRoots) {
      if (fileLimitReached || traversalLimitReached) break
      const absolutePath = includedRoot === '.'
        ? root
        : resolve(root, ...includedRoot.split('/'))
      if (!isInside(root, absolutePath)) {
        throw new Error(`inventory include root escaped repository boundary: ${includedRoot}`)
      }
      let metadata
      try {
        metadata = await lstat(absolutePath, { bigint: true })
      } catch (error) {
        pushError(
          includedRoot,
          'include-root',
          error.code ?? 'UNKNOWN',
          error.message,
        )
        continue
      }
      if (metadata.isDirectory()) {
        if (
          includedRoot !== '.'
          && directoryIsExcluded(includedRoot, includedRoot.split('/').at(-1), exclusions)
        ) {
          excluded.push({
            path: `${includedRoot}/`,
            reason: 'configured-directory-exclusion',
          })
        } else {
          const depth = includedRoot === '.' ? 0 : includedRoot.split('/').length
          await visit(absolutePath, depth)
        }
      } else {
        await recordPath(absolutePath, includedRoot, metadata)
      }
    }
  }
  for (const entry of entries) {
    Object.assign(entry, classifyCoverageEntry(entry))
    entry.category = classifyInventoryEntry(entry)
  }
  entries.sort((left, right) =>
    compareCanonicalStrings(left.path, right.path))
  excluded.sort((left, right) =>
    compareCanonicalStrings(left.path, right.path))
  errors.sort((left, right) => compareCanonicalStrings(
    `${left.path}\0${left.operation}\0${left.code}`,
    `${right.path}\0${right.operation}\0${right.code}`,
  ))

  const digestInput = entries.map((entry) => [
    entry.path,
    entry.kind,
    entry.size,
    entry.sha256 ?? '',
    entry.reason ?? '',
    entry.category,
    entry.coverage_class,
    entry.classification_reason,
  ])
  for (const error of errors) {
    digestInput.push([
      `!inventory-error:${error.path}`,
      error.operation,
      0,
      '',
      error.code,
    ])
  }
  const treeDigest = sha256(JSON.stringify(digestInput))

  return {
    root,
    treeDigest,
    complete: errors.length === 0,
    entries,
    excluded,
    errors,
    limits: {
      maxTextBytes,
      maxInventoryFiles,
      maxInventoryBytes,
      maxTraversalEntries,
      maxDirectoryDepth,
      includedRoots,
    },
  }
}

export function serializeInventory(inventory) {
  return {
    root: inventory.root,
    tree_digest: inventory.treeDigest,
    complete: inventory.complete,
    limits: inventory.limits,
    entries: inventory.entries.map(({ absolutePath, content, ...entry }) => entry),
    excluded: inventory.excluded,
    errors: inventory.errors,
  }
}

export { DEFAULT_EXCLUDED_DIRECTORIES, DEFAULT_INVENTORY_LIMITS }
