import { createHash } from 'node:crypto'
import { isSurvivingFinding } from './findings.mjs'
import { filterResolvedCoverageGaps } from './coverage-gaps.mjs'

const ACTIVE_DISPOSITIONS = new Set(['queued', 'elevated'])

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (value === null || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.keys(value)
      .sort((left, right) => left.localeCompare(right, 'en'))
      .map((key) => [key, stableValue(value[key])]),
  )
}

function activeFindings(run) {
  return (run.findings ?? []).filter((finding) =>
    isSurvivingFinding(finding)
    && (
      finding.triage_disposition === undefined
      || ACTIVE_DISPOSITIONS.has(finding.triage_disposition)
    ))
}

function locationPath(location) {
  return String(location).replace(/:[1-9][0-9]*(?::[1-9][0-9]*)?$/, '').replaceAll('\\', '/')
}

function normalizedCoverageArea(value) {
  return String(value ?? '')
    .trim()
    .replaceAll('\\', '/')
    .replace(/^\.\/+/, '')
    .replace(/\/+/g, '/')
}

function pathIsWithin(path, area) {
  return path === area || path.startsWith(`${area}/`)
}

function namedCoverageOwner(area, prefix, namesByLength) {
  if (!area.startsWith(prefix)) return null
  return namesByLength.find(
    (name) => area === `${prefix}${name}` || area.startsWith(`${prefix}${name}:`),
  )
}

function hasKnownPathRelation(area, knownPaths, sortedKnownPaths) {
  if (knownPaths.has(area)) return true

  let parent = area
  while (parent.includes('/')) {
    parent = parent.slice(0, parent.lastIndexOf('/'))
    if (knownPaths.has(parent)) return true
  }

  const prefix = `${area}/`
  let low = 0
  let high = sortedKnownPaths.length
  while (low < high) {
    const middle = Math.floor((low + high) / 2)
    if (sortedKnownPaths[middle].localeCompare(prefix, 'en') < 0) low = middle + 1
    else high = middle
  }
  return sortedKnownPaths[low]?.startsWith(prefix) ?? false
}

function gapAffectsFinding(run, finding, locationPaths) {
  const coverage = run.coverage ?? {}
  const lenses = [...new Set((coverage.lenses ?? []).map(({ lens }) => lens))]
    .sort((left, right) => right.length - left.length)
  const stores = [...new Set(
    (run.store_profiles ?? []).map(({ store_context: context }) => context?.store_id)
      .filter((storeId) => typeof storeId === 'string' && storeId.length > 0),
  )].sort((left, right) => right.length - left.length)
  const knownPaths = new Set([
    ...(coverage.inventory ?? []),
    ...(coverage.examined ?? []),
    ...(coverage.unexamined ?? []).map(({ path }) => path),
    ...(run.scope?.excluded_paths ?? []).map(({ path }) => path),
  ].map(normalizedCoverageArea).filter(Boolean))
  const sortedKnownPaths = [...knownPaths].sort((left, right) =>
    left.localeCompare(right, 'en'))

  const openGaps = filterResolvedCoverageGaps(
    coverage.gaps ?? [],
    coverage.resolved_gap_ids ?? [],
  )
  for (const gap of openGaps) {
    const area = normalizedCoverageArea(gap?.area)
    // Schema-valid runs cannot contain an empty area. Treat malformed historical
    // input as global rather than letting it authorize a false resolution.
    if (!area) return true

    if (area.startsWith('store:')) {
      const owner = namedCoverageOwner(area, 'store:', stores)
      if (owner === undefined) return true
      if (owner === finding.store_context?.store_id) return true
      continue
    }

    if (area.startsWith('lens:')) {
      const owner = namedCoverageOwner(area, 'lens:', lenses)
      if (owner === undefined) return true
      if (owner === finding.lens) return true
      continue
    }

    if (area === finding.lens || area.startsWith(`${finding.lens}:`)) return true
    if (lenses.some((lens) => area === lens || area.startsWith(`${lens}:`))) {
      continue
    }

    if (
      locationPaths.some(
        (path) => pathIsWithin(path, area) || area.endsWith(`:${path}`),
      )
    ) {
      return true
    }

    // Exact or directory-scoped gaps elsewhere in the declared repository are
    // attributable and do not veto this finding. Free-form, unattributable gaps
    // fail closed because their relationship to the finding cannot be proved.
    if (hasKnownPathRelation(area, knownPaths, sortedKnownPaths)) {
      continue
    }
    return true
  }
  return false
}

function findingDigest(finding) {
  const lifecycleNeutral = { ...finding }
  delete lifecycleNeutral.baseline_state
  delete lifecycleNeutral.candidate_id
  delete lifecycleNeutral.fingerprint
  return sha256(JSON.stringify(stableValue(lifecycleNeutral)))
}

function normalizedText(value) {
  return String(value ?? '').replace(/\s+/g, ' ').trim()
}

export function findingFingerprint(finding) {
  if (typeof finding.fingerprint === 'string' && finding.fingerprint.trim()) {
    return finding.fingerprint.trim()
  }
  // Line and column numbers drift under harmless edits. Keep repository paths
  // in semantic identity, but let changed coordinates classify as `updated`
  // through findingDigest instead of manufacturing a `fixed` + `new` pair.
  const locations = [...new Set(
    (finding.location ?? []).map(locationPath),
  )].sort()
  return `sha256:${sha256(JSON.stringify([
    finding.topic ?? '',
    locations,
    finding.store_context?.store_id ?? '',
    finding.store_context?.family ?? '',
    finding.store_context?.engine ?? '',
    finding.store_context?.engine_version ?? '',
    finding.store_context?.deployment_variant ?? '',
    finding.store_context?.adapter_id ?? '',
    finding.principal_path?.effective_principal ?? '',
    finding.enforcement_plane ?? '',
    normalizedText(finding.reachable_from),
    normalizedText(finding.evidence),
  ]))}`
}

export function comparisonCompatibility(baseline, current) {
  const reasons = []
  if (!['COMPLETED', 'COMPLETE_WITH_GAPS'].includes(baseline.state)) {
    reasons.push('baseline run is not reportable')
  }
  if (!['COMPLETED', 'COMPLETE_WITH_GAPS'].includes(current.state)) {
    reasons.push('current run is not reportable')
  }
  if (baseline.repository?.root !== current.repository?.root) {
    reasons.push('repository roots differ')
  }
  if (baseline.lens_pack_digest !== current.lens_pack_digest) {
    reasons.push('lens packs differ')
  }
  if (baseline.policy_digest !== current.policy_digest) {
    reasons.push('Rules of Engagement differ')
  }
  return { comparable: reasons.length === 0, reasons }
}

export function coverageSupportsResolution(run, finding) {
  if (!['COMPLETED', 'COMPLETE_WITH_GAPS'].includes(run.state)) return false
  const successfulLensJob = (run.jobs ?? []).some(
    ({ kind, lens, state }) => (
      kind === 'LENS'
      && lens === finding.lens
      && state === 'SUCCEEDED'
    ),
  )
  if (!successfulLensJob) return false

  const coverage = run.coverage ?? {}
  const examined = new Set(coverage.examined ?? [])
  const unexamined = new Set((coverage.unexamined ?? []).map(({ path }) => path))
  const lens = (coverage.lenses ?? []).find((entry) => entry.lens === finding.lens)
  if (!lens || lens.status !== 'RAN') return false
  const examinedByLens = new Set(lens.examined_paths ?? [])
  const locationsCovered = (finding.location ?? []).every((location) => {
    const path = locationPath(location)
    return examined.has(path) && examinedByLens.has(path) && !unexamined.has(path)
  })
  if (!locationsCovered) return false
  if (gapAffectsFinding(run, finding, [...new Set(
    (finding.location ?? []).map(locationPath).map(normalizedCoverageArea),
  )])) {
    return false
  }

  const databaseFinding = finding.lens === 'database-and-data-stores'
    || /^(?:database(?:-|$)|db\.)/.test(finding.topic ?? '')
  if (!databaseFinding) return true

  const storeId = finding.store_context?.store_id
  if (!storeId) return false
  const profile = (run.store_profiles ?? []).find(
    (entry) => entry.store_context?.store_id === storeId,
  )
  if (
    !profile
    || profile.coverage_state !== 'ASSESSED'
    || profile.store_context?.adapter_id === 'inventory-only'
    || !(profile.assessed_topics ?? []).includes(finding.topic)
    || (profile.coverage_gaps ?? []).length > 0
  ) {
    return false
  }
  for (
    const field of [
      'family',
      'engine',
      'engine_version',
      'deployment_variant',
      'adapter_id',
    ]
  ) {
    if (
      finding.store_context?.[field] !== undefined
      && profile.store_context?.[field] !== finding.store_context[field]
    ) {
      return false
    }
  }
  if (
    finding.principal_path !== undefined
    && JSON.stringify(stableValue(profile.principal_path))
      !== JSON.stringify(stableValue(finding.principal_path))
  ) {
    return false
  }
  return (profile.evidence_paths ?? []).every(
    (path) => examined.has(path) && examinedByLens.has(path) && !unexamined.has(path),
  )
}

function coverageAuthorityForFinding(run, finding) {
  const job = (run.jobs ?? []).find(
    ({ kind, lens }) =>
      kind === 'LENS'
      && lens === finding.lens,
  )
  if (job?.state !== 'SUCCEEDED') return 'NO_CURRENT_COVERAGE_AUTHORITY'
  if (job?.coverage_authority === 'CONTROLLER_OBSERVED_CONSUMPTION') {
    return 'CONTROLLER_OBSERVED_CONSUMPTION'
  }
  return 'PROVIDER_DECLARED'
}

function groupedFindings(run) {
  const groups = new Map()
  for (const finding of activeFindings(run)) {
    const fingerprint = findingFingerprint(finding)
    const group = groups.get(fingerprint) ?? []
    group.push(finding)
    groups.set(fingerprint, group)
  }
  for (const group of groups.values()) {
    group.sort((left, right) =>
      String(left.candidate_id).localeCompare(String(right.candidate_id), 'en'))
  }
  return groups
}

export function compareRuns(baseline, current) {
  const compatibility = comparisonCompatibility(baseline, current)
  const baselineByFingerprint = groupedFindings(baseline)
  const currentByFingerprint = groupedFindings(current)
  const results = []

  const fingerprints = new Set([
    ...baselineByFingerprint.keys(),
    ...currentByFingerprint.keys(),
  ])
  for (const fingerprint of fingerprints) {
    const previous = (baselineByFingerprint.get(fingerprint) ?? [])
      .map((finding) => ({
        digest: findingDigest(finding),
        finding,
        matched: false,
      }))
    const present = currentByFingerprint.get(fingerprint) ?? []
    const previousByDigest = new Map()
    for (const entry of previous) {
      const bucket = previousByDigest.get(entry.digest) ?? { entries: [], cursor: 0 }
      bucket.entries.push(entry)
      previousByDigest.set(entry.digest, bucket)
    }
    let fallbackCursor = 0
    for (const finding of present) {
      const digest = findingDigest(finding)
      const bucket = previousByDigest.get(digest)
      while (
        bucket
        && bucket.cursor < bucket.entries.length
        && bucket.entries[bucket.cursor].matched
      ) {
        bucket.cursor += 1
      }
      let match = bucket?.entries[bucket.cursor] ?? null
      if (match) {
        match.matched = true
        bucket.cursor += 1
      } else {
        while (fallbackCursor < previous.length && previous[fallbackCursor].matched) {
          fallbackCursor += 1
        }
        match = previous[fallbackCursor] ?? null
        if (match) {
          match.matched = true
          fallbackCursor += 1
        }
      }
      const baselineFinding = match?.finding ?? null
      results.push({
        fingerprint,
        candidate_id: finding.candidate_id,
        state: baselineFinding === null
          ? 'new'
          : findingDigest(baselineFinding) === digest
            ? 'unchanged'
            : 'updated',
        finding,
        baseline_finding: baselineFinding,
        resolution_authority: coverageAuthorityForFinding(current, finding),
      })
    }
    for (const { finding, matched } of previous) {
      if (matched) continue
      results.push({
        fingerprint,
        candidate_id: finding.candidate_id,
        state: compatibility.comparable && coverageSupportsResolution(current, finding)
          ? 'fixed'
          : 'not-observed',
        finding: null,
        baseline_finding: finding,
        resolution_authority: coverageAuthorityForFinding(current, finding),
      })
    }
  }

  const order = new Map([
    ['new', 0],
    ['updated', 1],
    ['unchanged', 2],
    ['not-observed', 3],
    ['fixed', 4],
  ])
  results.sort((left, right) =>
    order.get(left.state) - order.get(right.state) ||
    left.fingerprint.localeCompare(right.fingerprint, 'en') ||
    String(left.candidate_id).localeCompare(String(right.candidate_id), 'en'))

  const resolutionAuthorities = [...new Set(
    results
      .map(({ resolution_authority: authority }) => authority),
  )].sort((left, right) => left.localeCompare(right, 'en'))
  const resolutionAuthority = resolutionAuthorities.length === 0
    ? 'NO_RESOLUTION_CLAIMS'
    : resolutionAuthorities.length === 1
      && resolutionAuthorities[0] === 'CONTROLLER_OBSERVED_CONSUMPTION'
      ? 'controller-observed byte consumption; not comprehension or independent proof'
      : resolutionAuthorities.length === 1
        && resolutionAuthorities[0] === 'PROVIDER_DECLARED'
        ? 'provider-declared lens, file, and store coverage; not an independent controller read receipt'
        : resolutionAuthorities.length === 1
          ? 'no current successful lens coverage authority; no resolution claim is supported'
          : resolutionAuthorities.includes('NO_CURRENT_COVERAGE_AUTHORITY')
            ? 'mixed current coverage authority with at least one finding lacking successful lens coverage; no unsupported resolution claim is implied'
            : 'mixed provider-declared and controller-observed byte consumption; neither is independent proof'
  return {
    baseline_run_id: baseline.run_id,
    current_run_id: current.run_id,
    comparable: compatibility.comparable,
    comparability_reasons: compatibility.reasons,
    resolution_authority: resolutionAuthority,
    counts: Object.fromEntries(
      ['new', 'updated', 'unchanged', 'fixed', 'not-observed']
        .map((state) => [state, results.filter((entry) => entry.state === state).length]),
    ),
    results,
  }
}
