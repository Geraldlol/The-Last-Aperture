import { posix } from 'node:path'
import { compareCanonicalStrings } from './canonical-order.mjs'

const SOURCE_EXTENSIONS = Object.freeze([
  '.c', '.cc', '.cpp', '.cxx', '.go', '.h', '.hpp', '.java', '.js', '.jsx',
  '.kt', '.kts', '.mjs', '.cjs', '.py', '.rb', '.rs', '.sol', '.ts', '.tsx',
  '.vy',
])

function normalizedRepositoryPath(value) {
  return String(value).replaceAll('\\', '/').replace(/^\.\//, '')
}

function localSpecifiers(content) {
  const text = String(content ?? '')
  const values = new Set()
  const patterns = [
    /\b(?:import|export)\s+(?:[^'"\n]+?\s+from\s+)?['"]([^'"]+)['"]/g,
    /\b(?:import|require)\s*\(\s*['"]([^'"]+)['"]\s*\)/g,
    /^\s*#\s*include\s*"([^"]+)"/gm,
  ]
  for (const pattern of patterns) {
    for (const match of text.matchAll(pattern)) {
      const specifier = match[1].split(/[?#]/, 1)[0]
      if (specifier.startsWith('.')) values.add(specifier)
    }
  }
  for (const match of text.matchAll(/^\s*from\s+(\.+)([A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*)\s+import\b/gm)) {
    const parentPrefix = '../'.repeat(Math.max(0, match[1].length - 1)) || './'
    values.add(`${parentPrefix}${match[2].replaceAll('.', '/')}`)
  }
  for (const match of text.matchAll(/\brequire_relative\s*(?:\(\s*)?['"]([^'"]+)['"]/g)) {
    const specifier = match[1].startsWith('.') ? match[1] : `./${match[1]}`
    values.add(specifier)
  }
  for (const match of text.matchAll(/^\s*(?:pub\s+)?mod\s+([A-Za-z_]\w*)\s*;/gm)) {
    values.add(`./${match[1]}`)
  }
  return [...values].sort(compareCanonicalStrings)
}

function resolutionCandidates(importer, specifier) {
  const base = posix.normalize(posix.join(posix.dirname(importer), specifier))
  if (base === '..' || base.startsWith('../') || posix.isAbsolute(base)) return []
  const extension = posix.extname(base)
  const candidates = new Set([base])
  if (extension) {
    const stem = base.slice(0, -extension.length)
    for (const replacement of SOURCE_EXTENSIONS) candidates.add(`${stem}${replacement}`)
  } else {
    for (const replacement of SOURCE_EXTENSIONS) {
      candidates.add(`${base}${replacement}`)
      candidates.add(`${base}/index${replacement}`)
    }
  }
  return [...candidates]
}

function dependencyGraph(inventory) {
  const entries = (inventory?.entries ?? [])
    .filter(({ kind, content }) => kind === 'text' && typeof content === 'string')
  const byPath = new Map(entries.map((entry) => [
    normalizedRepositoryPath(entry.path),
    entry,
  ]))
  const outgoing = new Map([...byPath.keys()].map((path) => [path, new Set()]))
  const incoming = new Map([...byPath.keys()].map((path) => [path, new Set()]))

  for (const [path, entry] of byPath) {
    for (const specifier of localSpecifiers(entry.content)) {
      const target = resolutionCandidates(path, specifier).find((candidate) => byPath.has(candidate))
      if (!target || target === path) continue
      outgoing.get(path).add(target)
      incoming.get(target).add(path)
    }
  }
  return { byPath, outgoing, incoming }
}

export function expandDependencyScope(directMatches, inventory, options = {}) {
  const maxDepth = options.maxDepth ?? 2
  const maxFiles = options.maxFiles ?? 256
  if (!Number.isSafeInteger(maxDepth) || maxDepth < 0 || maxDepth > 8) {
    throw new TypeError('dependency scope maxDepth must be an integer from 0 through 8')
  }
  if (!Number.isSafeInteger(maxFiles) || maxFiles < 1 || maxFiles > 100000) {
    throw new TypeError('dependency scope maxFiles must be an integer from 1 through 100000')
  }

  const graph = dependencyGraph(inventory)
  const selected = new Map()
  const queue = []
  for (const match of directMatches ?? []) {
    const path = normalizedRepositoryPath(match.path)
    if (!graph.byPath.has(path) || selected.has(path)) continue
    selected.set(path, { ...match, path })
    queue.push({ path, depth: 0 })
  }
  queue.sort((left, right) => compareCanonicalStrings(left.path, right.path))

  let truncated = selected.size > maxFiles
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const current = queue[cursor]
    if (current.depth >= maxDepth) {
      const beyondDepth = [
        ...(graph.outgoing.get(current.path) ?? []),
        ...(graph.incoming.get(current.path) ?? []),
      ].some((path) => !selected.has(path))
      if (beyondDepth) truncated = true
      continue
    }
    const neighbors = [
      ...[...(graph.outgoing.get(current.path) ?? [])].map((path) => ({
        path,
        direction: 'dependency',
      })),
      ...[...(graph.incoming.get(current.path) ?? [])].map((path) => ({
        path,
        direction: 'dependent',
      })),
    ].sort((left, right) =>
      compareCanonicalStrings(left.path, right.path)
      || compareCanonicalStrings(left.direction, right.direction))

    for (const neighbor of neighbors) {
      if (selected.has(neighbor.path)) continue
      if (selected.size >= maxFiles) {
        truncated = true
        continue
      }
      const entry = graph.byPath.get(neighbor.path)
      selected.set(neighbor.path, {
        path: neighbor.path,
        kind: entry.kind,
        path_activators: [],
        signal_activators: [],
        scope_expansion: {
          direction: neighbor.direction,
          depth: current.depth + 1,
          from_path: current.path,
        },
      })
      queue.push({ path: neighbor.path, depth: current.depth + 1 })
    }
  }

  return {
    matches: [...selected.values()].sort((left, right) =>
      compareCanonicalStrings(left.path, right.path)),
    truncated,
  }
}
