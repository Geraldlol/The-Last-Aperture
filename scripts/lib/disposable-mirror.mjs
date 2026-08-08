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
import { cp, mkdir, rm, writeFile } from 'node:fs/promises'
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

export async function materializeFiles(mirrorRoot, files) {
  const root = resolve(mirrorRoot)
  const written = []
  for (const { path, contents } of files) {
    const absolute = resolve(root, path)
    if (absolute !== root && !absolute.startsWith(root + sep)) {
      throw new Error(`proof file path escapes the mirror: ${path}`)
    }
    await mkdir(dirname(absolute), { recursive: true })
    await writeFile(absolute, contents)
    written.push(relative(root, absolute).split(sep).join('/'))
  }
  return written.sort(compareCanonicalStrings)
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
