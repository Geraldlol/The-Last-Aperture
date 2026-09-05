import { compareCanonicalStrings } from './canonical-order.mjs'

function findingSourcePaths(run, sourceIndex, candidateIds) {
  const knownPaths = new Set((sourceIndex?.files ?? []).map(({ path }) => path))
  const selectedIds = candidateIds === undefined ? null : new Set(candidateIds)
  const paths = new Set()
  for (const finding of run?.findings ?? []) {
    if (selectedIds && !selectedIds.has(finding.candidate_id)) continue
    for (const location of finding.location ?? []) {
      const match = /^(.*?):[1-9][0-9]*(?::[1-9][0-9]*)?$/.exec(location)
      if (match && knownPaths.has(match[1])) paths.add(match[1])
    }
  }
  return [...paths].sort(compareCanonicalStrings)
}

export function sourcePathsForJob(run, job, sidecar, sourceIndex) {
  if (job.kind === 'LENS') return [...(sidecar.scoped_files ?? [])]
  if (job.kind === 'COMPLETENESS') return []
  if (job.kind === 'TRIAGE') {
    if (job.lens === 'business-logic') {
      return [...new Set(sidecar.scoped_files ?? [])].sort(compareCanonicalStrings)
    }
    if (job.lens === 'attack-chaining') {
      return findingSourcePaths(run, sourceIndex)
    }
    return []
  }
  if (job.kind === 'PROOF') {
    return findingSourcePaths(run, sourceIndex, job.candidate_ids ?? [])
  }
  return []
}
