import { createHash } from 'node:crypto'
import { lstat, readFile, readdir } from 'node:fs/promises'
import { join, relative, resolve, sep } from 'node:path'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { evidenceForLens } from './evidence-packet.mjs'
import { parseLens } from './frontmatter.mjs'
import { signalSelectorLiterals } from './activation-selectors.mjs'
import { expandDependencyScope } from './scope-expansion.mjs'
import {
  DEFAULT_WORK_SHARD_LIMITS,
  packWorkShards,
} from './work-shards.mjs'

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function expandBraceAlternations(pattern) {
  // A one-alternative brace must expand like every other brace. Leaving `{ts}`
  // literal made the lens match nothing and report as legitimately inapplicable.
  const match = /\{([^{}]*)\}/.exec(pattern)
  if (!match) return [pattern]
  return match[1].split(',').flatMap((alternative) => expandBraceAlternations(
    `${pattern.slice(0, match.index)}${alternative}${pattern.slice(match.index + match[0].length)}`,
  ))
}

function globRegex(pattern) {
  let source = '^'
  for (let index = 0; index < pattern.length; index += 1) {
    const character = pattern[index]
    if (character === '*') {
      if (pattern[index + 1] === '*') {
        while (pattern[index + 1] === '*') index += 1
        if (pattern[index + 1] === '/') {
          source += '(?:.*/)?'
          index += 1
        } else {
          source += '.*'
        }
      } else {
        source += '[^/]*'
      }
      continue
    }
    if (character === '?') {
      source += '[^/]'
      continue
    }
    source += /[\\^$+.[\]()|{}]/.test(character) ? `\\${character}` : character
  }
  return new RegExp(`${source}$`)
}

export function pathActivatorMatches(pattern, path) {
  const normalizedPattern = String(pattern).replaceAll('\\', '/')
  const normalizedPath = String(path).replaceAll('\\', '/').replace(/^\.\//, '')
  return expandBraceAlternations(normalizedPattern)
    .some((expanded) => globRegex(expanded).test(normalizedPath))
}

const IDENTIFIER_CHARACTER = /[\p{L}\p{N}_$]/u
const LETTER_CHARACTER = /\p{L}/u
const NUMBER_CHARACTER = /\p{N}/u

function hasBoundedNumericSuffix(needle, haystack, end) {
  if (
    !LETTER_CHARACTER.test(needle.at(-1)) ||
    !NUMBER_CHARACTER.test(haystack[end] ?? '')
  ) {
    return false
  }
  let suffixEnd = end
  while (NUMBER_CHARACTER.test(haystack[suffixEnd] ?? '')) suffixEnd += 1
  return suffixEnd === haystack.length ||
    !IDENTIFIER_CHARACTER.test(haystack[suffixEnd])
}

function signalLiteralMatches(signal, content) {
  const needle = String(signal)
  const haystack = String(content)
  if (!needle) return false

  const requiresLeftBoundary = IDENTIFIER_CHARACTER.test(needle[0])
  const requiresRightBoundary = IDENTIFIER_CHARACTER.test(needle.at(-1))
  let offset = 0

  while (offset <= haystack.length - needle.length) {
    const index = haystack.indexOf(needle, offset)
    if (index === -1) return false
    const end = index + needle.length
    const leftMatches = !requiresLeftBoundary ||
      index === 0 ||
      !IDENTIFIER_CHARACTER.test(haystack[index - 1])
    const rightMatches = !requiresRightBoundary ||
      end === haystack.length ||
      !IDENTIFIER_CHARACTER.test(haystack[end]) ||
      hasBoundedNumericSuffix(needle, haystack, end)
    if (leftMatches && rightMatches) return true
    offset = index + 1
  }

  return false
}

export function signalActivatorMatches(selector, content) {
  return signalSelectorLiterals(selector)
    .some((signal) => signalLiteralMatches(signal, content))
}

export async function loadLenses(lensDirectory) {
  const files = (await readdir(lensDirectory))
    .filter((file) => file.endsWith('.md') && !file.startsWith('_'))
    .sort(compareCanonicalStrings)
  const lenses = []

  for (const file of files) {
    const path = join(lensDirectory, file)
    const text = await readFile(path, 'utf8')
    const parsed = parseLens(text, file)
    if (parsed.errors.length > 0) {
      throw new Error(`cannot activate malformed lens ${file}: ${parsed.errors.join('; ')}`)
    }
    lenses.push({
      file,
      path,
      digest: sha256(text),
      text,
      ...parsed,
    })
  }
  return lenses
}

export async function digestLensPack(lensDirectory) {
  const root = resolve(lensDirectory)
  const files = []
  async function visit(directory) {
    const entries = (await readdir(directory, { withFileTypes: true }))
      .sort((left, right) => compareCanonicalStrings(left.name, right.name))
    for (const entry of entries) {
      const path = join(directory, entry.name)
      if (entry.isSymbolicLink() || (await lstat(path)).isSymbolicLink()) {
        throw new Error(`trusted lens pack cannot contain a symlink: ${path}`)
      }
      if (entry.isDirectory()) {
        await visit(path)
      } else if (entry.isFile()) {
        const bytes = await readFile(path)
        files.push({
          path: relative(root, path).split(sep).join('/'),
          sha256: sha256(bytes),
          size: bytes.length,
        })
      }
    }
  }
  await visit(root)
  files.sort((left, right) => compareCanonicalStrings(left.path, right.path))
  return {
    schema_version: 1,
    files,
    digest: sha256(JSON.stringify(files.map(({ path, sha256: digest, size }) => [
      path,
      digest,
      size,
    ]))),
  }
}

export function lensSharedContractDigest(lensPack) {
  const sharedFiles = (lensPack?.files ?? [])
    .filter(({ path }) => path.startsWith('_') && path !== '_topics.md')
    .sort((left, right) => compareCanonicalStrings(left.path, right.path))
  return sha256(JSON.stringify(sharedFiles.map(({ path, sha256: digest, size }) => [
    path,
    digest,
    size,
  ])))
}

function matchLens(lens, inventory) {
  const pathPatterns = lens.frontmatter.activates_on?.paths ?? []
  const signals = lens.frontmatter.activates_on?.signals ?? []
  const matches = new Map()

  for (const entry of inventory.entries) {
    const pathMatches = pathPatterns.filter((pattern) => pathActivatorMatches(pattern, entry.path))
    const signalMatches = entry.kind === 'text'
      ? signals.filter((signal) => signalActivatorMatches(signal, entry.content))
      : []
    if (pathMatches.length === 0 && signalMatches.length === 0) continue
    matches.set(entry.path, {
      path: entry.path,
      kind: entry.kind,
      path_activators: pathMatches,
      signal_activators: signalMatches,
    })
  }

  return [...matches.values()].sort((left, right) => compareCanonicalStrings(left.path, right.path))
}

function augmentDatabaseMatches(matches, inventory, databaseDiscovery) {
  if (!databaseDiscovery || !Array.isArray(databaseDiscovery.path_scope)) return matches
  const byPath = new Map(inventory.entries.map((entry) => [entry.path, entry]))
  const augmented = new Map(matches.map((match) => [match.path, match]))
  for (const scope of databaseDiscovery.path_scope) {
    if (scope.state !== 'in-scope' || augmented.has(scope.path)) continue
    const entry = byPath.get(scope.path)
    if (!entry) continue
    augmented.set(scope.path, {
      path: scope.path,
      kind: entry.kind,
      path_activators: [],
      signal_activators: [],
      database_discovery_reasons: scope.reasons ?? [],
    })
  }
  return [...augmented.values()]
    .sort((left, right) => compareCanonicalStrings(left.path, right.path))
}

export function databaseDiscoveryProjection(databaseDiscovery, scopedFiles) {
  if (!databaseDiscovery) return undefined
  const scope = new Set(scopedFiles)
  const relatedCandidates = (databaseDiscovery.store_candidates ?? [])
    .filter((candidate) =>
      (candidate.scope_paths ?? candidate.evidence_paths ?? [])
        .some((path) => scope.has(path)))
  const storeCandidates = relatedCandidates.filter((candidate) => {
    const [homePath] = candidate.evidence_paths ?? candidate.scope_paths ?? []
    return typeof homePath === 'string' && scope.has(homePath)
  })
  return {
    schema_version: databaseDiscovery.schema_version,
    kind: 'red-team-audit/database-discovery-projection',
    graph_digest: databaseDiscovery.digest,
    scoped_paths: (databaseDiscovery.path_scope ?? [])
      .filter(({ path, state }) => scope.has(path) && state === 'in-scope'),
    store_candidates: storeCandidates,
    related_store_ids: relatedCandidates.map(({ store_id: storeId }) => storeId),
    unresolved: (databaseDiscovery.unresolved ?? [])
      .filter(({ path }) => typeof path === 'string' && scope.has(path)),
  }
}

function boundedFanoutJobs(job, inventory, shardPolicy) {
  if (!job.activated || job.scoped_files.length === 0) {
    const { database_discovery: fullDatabaseDiscovery, ...baseJob } = job
    const projection = job.lens === 'database-and-data-stores'
      ? databaseDiscoveryProjection(fullDatabaseDiscovery, job.scoped_files)
      : undefined
    return [{
      ...baseJob,
      ...(projection ? { database_discovery: projection } : {}),
    }]
  }
  const byPath = new Map(inventory.entries.map((entry) => [entry.path, entry]))
  const shards = packWorkShards(
    job.scoped_files.map((path) => {
      const entry = byPath.get(path)
      const size = entry.size ?? (
        typeof entry.content === 'string'
          ? Buffer.byteLength(entry.content, 'utf8')
          : 0
      )
      return { path, size, sha256: entry.sha256 }
    }),
    shardPolicy,
  )
  return shards.map((packed, shardIndex) => {
    const scope = new Set(packed.scoped_files)
    const databaseDiscovery = job.lens === 'database-and-data-stores'
      ? databaseDiscoveryProjection(job.database_discovery, packed.scoped_files)
      : undefined
    const {
      database_discovery: _fullDatabaseDiscovery,
      evidence,
      ...baseJob
    } = job
    return {
      ...baseJob,
      // Evidence matches are bundle-global obligations. Deliver them once per
      // lens, not once per source shard, or each shard would be required to
      // duplicate the same finding.
      ...(shardIndex === 0 && evidence ? { evidence } : {}),
      scoped_files: [...packed.scoped_files],
      matches: job.matches.filter(({ path }) => scope.has(path)),
      shard: packed.shard,
      ...(databaseDiscovery ? { database_discovery: databaseDiscovery } : {}),
    }
  })
}

export function buildActivationPlan(lenses, inventory, options = {}) {
  const jobs = []
  // Acquired evidence a lens may reason over, resolved once from its own
  // declaration. A lens is handed a bundle only where it declares that class
  // consumed and, for built-artifact, that artifact kind.
  const evidenceBundles = options.evidenceBundles ?? []
  const evidenceDeclarations = new Map(lenses.map((lens) => [
    lens.frontmatter?.name ?? lens.name,
    lens.frontmatter?.activates_on?.evidence_classes ?? {},
  ]))
  const domainAssignments = new Map()
  const shardPolicy = {
    maxFiles: options.shardPolicy?.maxFiles ?? DEFAULT_WORK_SHARD_LIMITS.maxFiles,
    maxBytes: options.shardPolicy?.maxBytes ?? DEFAULT_WORK_SHARD_LIMITS.maxBytes,
  }
  const knownTopics = [...new Set(lenses.flatMap(
    (lens) => lens.frontmatter.owns ?? [],
  ))].sort(compareCanonicalStrings)

  for (const lens of lenses) {
    const frontmatter = lens.frontmatter
    const topicAuthority = {
      owned_topics: [...(frontmatter.owns ?? [])]
        .sort(compareCanonicalStrings),
      known_topics: knownTopics,
    }
    if (frontmatter.runs_in === 'triage') {
      const phase = lens.name === 'completeness' ? 'completeness' : 'triage'
      jobs.push({
        lens: lens.name,
        lens_file: lens.file,
        lens_digest: lens.digest,
        phase,
        activation: 'finding-set',
        activated: true,
        scoped_files: [],
        matches: [],
        status: 'pending',
        ...topicAuthority,
      })
      continue
    }

    if (frontmatter.always_active) {
      jobs.push(...boundedFanoutJobs({
        lens: lens.name,
        lens_file: lens.file,
        lens_digest: lens.digest,
        phase: 'fanout',
        activation: 'always',
        activated: true,
        scoped_files: inventory.entries
          .filter((entry) => entry.kind === 'text')
          .map((entry) => entry.path),
        matches: [],
        status: 'pending',
        ...topicAuthority,
      }, inventory, shardPolicy))
      continue
    }

    const rawMatches = matchLens(lens, inventory)
    const directMatches = lens.name === 'database-and-data-stores'
      ? augmentDatabaseMatches(
          rawMatches,
          inventory,
          options.databaseDiscovery,
        )
      : rawMatches
    const directTextMatches = directMatches.filter(({ kind }) => kind === 'text')
    const scopeLimit = Math.min(100000, directTextMatches.length + 256)
    const expandedScope = directTextMatches.length > 0
      ? expandDependencyScope(directTextMatches, inventory, {
          maxDepth: 2,
          maxFiles: scopeLimit,
        })
      : { matches: [], truncated: false }
    const matches = [
      ...directMatches.filter(({ kind }) => kind !== 'text'),
      ...expandedScope.matches,
    ].sort((left, right) => compareCanonicalStrings(left.path, right.path))
    for (const match of matches) {
      if (!domainAssignments.has(match.path)) domainAssignments.set(match.path, [])
      domainAssignments.get(match.path).push(lens.name)
    }
    const lensEvidence = evidenceForLens(lens.name, evidenceDeclarations, evidenceBundles)
    jobs.push(...boundedFanoutJobs({
      lens: lens.name,
      lens_file: lens.file,
      lens_digest: lens.digest,
      phase: 'fanout',
      activation: 'repository',
      // A lens can be activated by acquired evidence alone: an image was
      // pulled for a lens whose repository globs matched nothing is still
      // evidence that lens owns, and dropping it would recreate the silence
      // this whole dimension exists to remove.
      activated: matches.length > 0 || lensEvidence.length > 0,
      ...(lensEvidence.length > 0 ? { evidence: lensEvidence } : {}),
      scoped_files: matches
        .filter(({ kind }) => kind === 'text')
        .map(({ path }) => path),
      matches,
      scope_expansion: {
        max_depth: 2,
        max_files: scopeLimit,
        added_files: Math.max(0, expandedScope.matches.length - directTextMatches.length),
        truncated: expandedScope.truncated,
      },
      status: matches.length > 0 || lensEvidence.length > 0 ? 'pending' : 'not-activated',
      ...(lens.name === 'database-and-data-stores'
        ? { database_discovery: options.databaseDiscovery }
        : {}),
      ...topicAuthority,
    }, inventory, shardPolicy))
  }

  // Business-logic is the one triage pass that may originate code-backed
  // findings. Give it a bounded union of active domain-lens source scope so it
  // can inspect product invariants after seeing the merged candidate set.
  // Cross-cutting lenses deliberately own no topics and can be always-active;
  // including their repository-wide scope here would silently defeat provider
  // packet bounds. Other triage passes remain finding-set-only unless their
  // dispatch derives source directly from component locations.
  const businessLogic = jobs.find((job) =>
    job.phase === 'triage' && job.lens === 'business-logic')
  if (businessLogic) {
    const domainScope = [...new Set(jobs
      .filter((job) =>
        job.phase === 'fanout'
        && job.activated
        && (job.owned_topics?.length ?? 0) > 0)
      .flatMap((job) => job.scoped_files))]
      .sort(compareCanonicalStrings)
    businessLogic.scoped_files = domainScope.slice(0, shardPolicy.maxFiles)
    businessLogic.triage_source_scope = {
      total_files: domainScope.length,
      max_files: shardPolicy.maxFiles,
      truncated: domainScope.length > shardPolicy.maxFiles,
    }
  }

  jobs.sort((left, right) => {
    const phase = compareCanonicalStrings(left.phase, right.phase)
    return phase
      || compareCanonicalStrings(left.lens, right.lens)
      || (left.shard?.index ?? 0) - (right.shard?.index ?? 0)
  })

  const unassignedTextFiles = inventory.entries
    .filter((entry) => entry.kind === 'text' && !domainAssignments.has(entry.path))
    .map((entry) => entry.path)
  const unexamined = inventory.entries
    .filter((entry) => !entry.examined)
    .map(({ path, kind, reason }) => ({ path, kind, reason }))

  let status = 'complete'
  if (inventory.errors.length > 0 || unassignedTextFiles.length > 0 ||
      unexamined.some(({ kind }) => ['too-large', 'unreadable'].includes(kind))) {
    status = 'incomplete'
  } else if (unexamined.length > 0 || inventory.excluded.length > 0) {
    status = 'partial'
  }

  const coverage = {
    status,
    files_total: inventory.entries.length,
    text_files_total: inventory.entries.filter((entry) => entry.kind === 'text').length,
    assigned_text_files: inventory.entries.filter(
      (entry) => entry.kind === 'text' && domainAssignments.has(entry.path),
    ).length,
    unassigned_text_files: unassignedTextFiles,
    unexamined,
    configured_exclusions: inventory.excluded,
    inventory_errors: inventory.errors,
    assignments: [...domainAssignments.entries()]
      .sort(([left], [right]) => compareCanonicalStrings(left, right))
      .map(([path, assignedLenses]) => ({
        path,
        lenses: assignedLenses.sort(compareCanonicalStrings),
      })),
  }

  return {
    jobs,
    coverage,
    active_lenses: [...new Set(
      jobs.filter((job) => job.activated).map((job) => job.lens),
    )],
    inactive_lenses: [...new Set(
      jobs.filter((job) => !job.activated).map((job) => job.lens),
    )],
  }
}
