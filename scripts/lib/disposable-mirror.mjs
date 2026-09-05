/**
 * Proof work happens in a disposable copy so the target is never written to.
 *
 * A copy rather than a git worktree: nothing in the audit path uses git, a
 * de-gitted target inventories to an identical tree digest, and one code path
 * serves repositories and plain directories alike.
 *
 * This is not a sandbox. The copy prevents accidental mutation of the target;
 * it does not contain what an executed command does to the rest of the machine.
 */
import { cp, lstat, mkdir, realpath, rm, writeFile } from 'node:fs/promises'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { inventoryRepository } from './inventory.mjs'

export class MirrorMutationError extends Error {
  constructor(expected, actual) {
    super(
      'target tree digest changed during proof execution; '
      + `expected ${expected}, observed ${actual}`,
    )
    this.name = 'MirrorMutationError'
    this.expected = expected
    this.actual = actual
  }
}

/**
 * The whole mirror is disposable, so enumerating the copy would answer the
 * wrong question. Rail 3 asks for a manifest of what the audit *owns* — the
 * files it introduced — which is what materializeFiles returns. Walking the
 * copy also costs real time: this repository alone is 1,649 paths, 764 of them
 * node_modules, and a run creates one mirror per proof job.
 *
 * `.git` is copied deliberately. The detector-pair discipline's sixth rule runs
 * the tightened rule against the previous revision, which needs history.
 */
export async function createMirror(targetRoot, mirrorRoot) {
  await mkdir(dirname(mirrorRoot), { recursive: true })
  await cp(targetRoot, mirrorRoot, { recursive: true, dereference: false })
  return { root: mirrorRoot }
}

function proofFileCollision(path) {
  const error = new Error(
    `proof file path already exists in the sealed target mirror: ${path}`,
  )
  error.code = 'PROOF_FILE_PATH_COLLISION'
  return error
}

function assertInsideCanonicalRoot(canonicalRoot, canonicalPath, path) {
  if (
    canonicalPath !== canonicalRoot
    && !canonicalPath.startsWith(canonicalRoot + sep)
  ) {
    throw new Error(
      `proof file path escapes through a symbolic link or reparse point: ${path}`,
    )
  }
}

async function inspectMaterializationPath(root, canonicalRoot, path, requireAbsent) {
  const absolute = resolve(root, path)
  if (absolute !== root && !absolute.startsWith(root + sep)) {
    throw new Error(`proof file path escapes the mirror: ${path}`)
  }
  const parent = dirname(absolute)
  const parentRelative = relative(root, parent)
  let cursor = root
  let missingParent = false
  for (const segment of parentRelative.split(sep).filter(Boolean)) {
    cursor = join(cursor, segment)
    try {
      const stat = await lstat(cursor)
      if (stat.isSymbolicLink()) {
        throw new Error(`proof file path crosses a symbolic link or reparse point: ${path}`)
      }
      if (!stat.isDirectory()) {
        throw new Error(`proof file parent is not a directory: ${path}`)
      }
      assertInsideCanonicalRoot(canonicalRoot, await realpath(cursor), path)
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
      missingParent = true
      break
    }
  }
  if (!missingParent) {
    assertInsideCanonicalRoot(canonicalRoot, await realpath(parent), path)
    try {
      const stat = await lstat(absolute)
      if (requireAbsent) throw proofFileCollision(path)
      if (stat.isSymbolicLink()) {
        throw new Error(`proof file is a symbolic link or reparse point: ${path}`)
      }
      if (!stat.isFile()) {
        throw new Error(`proof file target is not a regular file: ${path}`)
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }
  }
  return {
    absolute,
    canonical: relative(root, absolute).split(sep).join('/'),
    contents: undefined,
  }
}

export async function materializeFiles(
  mirrorRoot,
  files,
  { requireAbsent = false } = {},
) {
  const root = resolve(mirrorRoot)
  const canonicalRoot = await realpath(root)
  const inspected = []
  for (const { path, contents } of files) {
    inspected.push({
      ...await inspectMaterializationPath(root, canonicalRoot, path, requireAbsent),
      contents,
    })
  }
  const canonicalPaths = inspected
    .map(({ canonical }) => canonical)
    .map((canonical) => ({
      canonical,
      collisionKey: process.platform === 'win32' ? canonical.toLowerCase() : canonical,
    }))
    .sort((left, right) => compareCanonicalStrings(left.collisionKey, right.collisionKey))
  for (let index = 1; index < canonicalPaths.length; index += 1) {
    const previous = canonicalPaths[index - 1]
    const current = canonicalPaths[index]
    if (
      current.collisionKey === previous.collisionKey
      || current.collisionKey.startsWith(`${previous.collisionKey}/`)
    ) {
      throw new Error(
        'proof file paths contain an internal file/directory collision: '
        + `${previous.canonical} and ${current.canonical}`,
      )
    }
  }

  const written = []
  for (const { absolute, canonical, contents } of inspected) {
    const path = canonical
    const parent = dirname(absolute)
    const parentRelative = relative(root, parent)
    let cursor = root
    for (const segment of parentRelative.split(sep).filter(Boolean)) {
      cursor = join(cursor, segment)
      try {
        const stat = await lstat(cursor)
        if (stat.isSymbolicLink()) {
          throw new Error(`proof file path crosses a symbolic link or reparse point: ${path}`)
        }
        if (!stat.isDirectory()) {
          throw new Error(`proof file parent is not a directory: ${path}`)
        }
      } catch (error) {
        if (error.code !== 'ENOENT') throw error
        await mkdir(cursor)
      }
    }
    assertInsideCanonicalRoot(canonicalRoot, await realpath(parent), path)
    try {
      const stat = await lstat(absolute)
      if (requireAbsent) throw proofFileCollision(path)
      if (stat.isSymbolicLink()) {
        throw new Error(`proof file is a symbolic link or reparse point: ${path}`)
      }
      if (!stat.isFile()) {
        throw new Error(`proof file target is not a regular file: ${path}`)
      }
    } catch (error) {
      if (error.code !== 'ENOENT') throw error
    }
    try {
      await writeFile(absolute, contents, requireAbsent ? { flag: 'wx' } : undefined)
    } catch (error) {
      if (requireAbsent && error.code === 'EEXIST') throw proofFileCollision(path)
      throw error
    }
    written.push(canonical)
  }
  return written.sort(compareCanonicalStrings)
}

/**
 * Materialize bytes already authenticated by a sealed-snapshot verifier.
 * Validate the complete batch before touching disk so a malformed caller
 * cannot leave a partially reconstructed execution tree.
 */
export async function materializeSealedFiles(mirrorRoot, files) {
  for (const [index, file] of files.entries()) {
    if (!Buffer.isBuffer(file?.bytes)) {
      throw new TypeError(`sealed file ${index} bytes must be a verified Buffer`)
    }
  }
  return materializeFiles(
    mirrorRoot,
    files.map(({ path, bytes }) => ({ path, contents: bytes })),
  )
}

/**
 * The options are not optional in practice. `plan` inventories with
 * maxTextBytes from the coverage policy and includedRoots from the Rules of
 * Engagement, so recomputing with defaults measures a different thing and
 * reports an untouched target as mutated. Callers must pass the same options
 * the plan used; they are recoverable from the bundle.
 */
export async function assertTargetUnchanged(
  targetRoot,
  expectedTreeDigest,
  inventoryOptions = {},
) {
  const { treeDigest } = await inventoryRepository(targetRoot, inventoryOptions)
  if (treeDigest !== expectedTreeDigest) {
    throw new MirrorMutationError(expectedTreeDigest, treeDigest)
  }
}

export async function destroyMirror(mirrorRoot) {
  await rm(mirrorRoot, { recursive: true, force: true })
}
