import { createHash } from 'node:crypto'
import { isSurvivingFinding } from './findings.mjs'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { filterResolvedCoverageGaps } from './coverage-gaps.mjs'

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function stableValue(value) {
  if (Array.isArray(value)) return value.map(stableValue)
  if (value === null || typeof value !== 'object') return value
  return Object.fromEntries(
    Object.keys(value)
      .sort(compareCanonicalStrings)
      .map((key) => [key, stableValue(value[key])]),
  )
}

function activeFindings(run) {
  return (run.findings ?? []).filter(isSurvivingFinding)
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
    if (compareCanonicalStrings(sortedKnownPaths[middle], prefix) < 0) low = middle + 1
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
  // The lower-bound search below is only valid in a prefix-preserving order.
  // Locale collation is not one: it ranks case below the separator, so `src/x`
  // sorts ahead of `SRC/x` and the bound for `SRC/` lands on a non-match.
  const sortedKnownPaths = [...knownPaths].sort(compareCanonicalStrings)

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

function normalizedLensContract(run, lens) {
  const jobs = (run.jobs ?? []).filter(
    ({ kind, lens: jobLens }) => kind === 'LENS' && jobLens === lens,
  )
  if (
    jobs.length === 0
    || jobs.some(({ lens_digest: digest, owned_topics: topics }) => (
      typeof digest !== 'string'
      || digest.length === 0
      || !Array.isArray(topics)
    ))
  ) {
    return null
  }
  const digests = [...new Set(jobs
    .map(({ lens_digest: digest }) => digest))]
  const topicContracts = [...new Set(jobs
    .map(({ owned_topics: topics }) => JSON.stringify([...topics].sort(compareCanonicalStrings))))]
  if (digests.length !== 1 || topicContracts.length !== 1) return null
  return {
    digest: digests[0],
    topics: JSON.parse(topicContracts[0]),
  }
}

function compareLensContracts(baseline, current, lens, compatibility) {
  const nonPackReasons = compatibility.reasons.filter((reason) => reason !== 'lens packs differ')
  if (nonPackReasons.length > 0) {
    return { lens, comparable: false, reason: nonPackReasons.join('; ') }
  }
  if (baseline.lens_pack_digest === current.lens_pack_digest) {
    return { lens, comparable: true, reason: 'lens pack unchanged' }
  }

  if (
    typeof baseline.lens_shared_contract_digest !== 'string'
    || typeof current.lens_shared_contract_digest !== 'string'
  ) {
    return { lens, comparable: false, reason: 'shared lens contract digest is unavailable' }
  }
  if (baseline.lens_shared_contract_digest !== current.lens_shared_contract_digest) {
    return { lens, comparable: false, reason: 'shared lens contract differs' }
  }

  const before = normalizedLensContract(baseline, lens)
  const after = normalizedLensContract(current, lens)
  if (!before || !after) {
    return { lens, comparable: false, reason: 'semantic lens contract is unavailable' }
  }
  if (before.digest !== after.digest) {
    return { lens, comparable: false, reason: 'lens implementation differs' }
  }
  if (JSON.stringify(before.topics) !== JSON.stringify(after.topics)) {
    return { lens, comparable: false, reason: 'owner topic contract differs' }
  }
  return { lens, comparable: true, reason: 'semantic lens contract unchanged' }
}

function normalizedTopicOwners(run, topic) {
  const lensJobs = (run.jobs ?? []).filter(({ kind }) => kind === 'LENS')
  if (
    lensJobs.length === 0
    || lensJobs.some(({ lens }) => typeof lens !== 'string' || lens.length === 0)
  ) {
    return null
  }

  const owners = []
  const lenses = [...new Set(lensJobs.map(({ lens }) => lens))]
    .sort(compareCanonicalStrings)
  for (const lens of lenses) {
    const contract = normalizedLensContract(run, lens)
    if (!contract) return null
    if (contract.topics.includes(topic)) owners.push(lens)
  }
  return owners
}

function topicContractSupportsResolution(baseline, current, finding, compatibility) {
  if (baseline.lens_pack_digest === current.lens_pack_digest) return true

  // Zero-owner lenses may raise a finding under a topic owned elsewhere in the
  // registry. Their own empty owned_topics contract cannot prove that reused
  // topic survived a pack change, so reconstruct both sealed registries from
  // every LENS job. The owner set must be identical, and each owner lens must
  // retain the same semantic contract. Any legacy/malformed omission makes a
  // registry incomplete and therefore unable to authorize an absence claim.
  const baselineOwners = normalizedTopicOwners(baseline, finding.topic)
  const currentOwners = normalizedTopicOwners(current, finding.topic)
  if (
    !baselineOwners
    || baselineOwners.length === 0
    || !currentOwners
    || JSON.stringify(baselineOwners) !== JSON.stringify(currentOwners)
  ) {
    return false
  }
  return baselineOwners.every(
    (owner) => compareLensContracts(baseline, current, owner, compatibility).comparable,
  )
}

// A lens fans out into many LENS jobs (one per shard, plus closure retries), so
// a lens-wide claim is only supported when every shard that carried a coverage
// obligation succeeded. DORMANT and SKIPPED jobs never carried one.
function obligatedLensJobs(run, lens) {
  return (run.jobs ?? []).filter(
    ({ kind, lens: jobLens, state }) => (
      kind === 'LENS'
      && jobLens === lens
      && state !== 'DORMANT'
      && state !== 'SKIPPED'
    ),
  )
}

function lensCoverageIsComplete(jobs) {
  return jobs.length > 0 && jobs.every(({ state }) => state === 'SUCCEEDED')
}

function uniqueMatchingEvidenceBundle(run, context) {
  const matches = (run.evidence_bundles ?? []).filter(
    ({ evidence_id: evidenceId }) => evidenceId === context.evidence_id,
  )
  if (matches.length !== 1) return null
  const [bundle] = matches
  return bundle.evidence_class === context.evidence_class
    && bundle.adapter_id === context.adapter_id
    ? bundle
    : null
}

function evidenceCoverageSupportsResolution(run, finding, baselineRun) {
  const context = finding.evidence_context
  // Repository-source findings predate the evidence matrix and remain governed
  // by lens/file coverage below. A source-class evidence_context is invalid,
  // so malformed historical input must not authorize an absence claim.
  if (context === undefined) return true
  if (context?.evidence_class === 'source') return false

  const cells = (run.evidence_coverage?.cells ?? []).filter((cell) => (
    cell.lens === finding.lens
    && cell.topic === finding.topic
    && cell.evidence_class === context?.evidence_class
  ))
  if (cells.length !== 1 || cells[0].state !== 'COVERED') return false

  const currentBundle = uniqueMatchingEvidenceBundle(run, context ?? {})
  if (!currentBundle || currentBundle.coverage_state !== 'COVERED') return false

  if (context.evidence_class !== 'built-artifact') return true
  if (typeof currentBundle.artifact_kind !== 'string') return false

  // evidence_id is the stable acquisition name, while the bundle root is
  // expected to change when a rebuilt artifact removes a finding. Artifact
  // kind therefore comes from the baseline bundle and must remain the same;
  // otherwise a covered firmware image could falsely clear an OCI finding.
  if (baselineRun === undefined) return false
  const baselineBundle = uniqueMatchingEvidenceBundle(baselineRun, context)
  if (
    !baselineBundle
    || typeof baselineBundle.artifact_kind !== 'string'
    || baselineBundle.artifact_kind !== currentBundle.artifact_kind
  ) {
    return false
  }
  return true
}

export function coverageSupportsResolution(run, finding, baselineRun) {
  if (!['COMPLETED', 'COMPLETE_WITH_GAPS'].includes(run.state)) return false
  if (!lensCoverageIsComplete(obligatedLensJobs(run, finding.lens))) return false

  const coverage = run.coverage ?? {}
  const lens = (coverage.lenses ?? []).find((entry) => entry.lens === finding.lens)
  if (!lens || lens.status !== 'RAN') return false
  const evidenceQualified = finding.evidence_context !== undefined
  if (!evidenceQualified) {
    const examined = new Set(coverage.examined ?? [])
    const unexamined = new Set((coverage.unexamined ?? []).map(({ path }) => path))
    const examinedByLens = new Set(lens.examined_paths ?? [])
    const locationsCovered = (finding.location ?? []).every((location) => {
      const path = locationPath(location)
      return examined.has(path) && examinedByLens.has(path) && !unexamined.has(path)
    })
    if (!locationsCovered) return false
  }
  if (gapAffectsFinding(run, finding, [...new Set(
    (finding.location ?? []).map(locationPath).map(normalizedCoverageArea),
  )])) {
    return false
  }
  if (evidenceQualified && !evidenceCoverageSupportsResolution(run, finding, baselineRun)) {
    return false
  }

  const databaseFinding = finding.lens === 'database-and-data-stores'
    || /^(?:database(?:-|$)|db\.)/.test(finding.topic ?? '')
  if (!databaseFinding) return true

  const examined = new Set(coverage.examined ?? [])
  const unexamined = new Set((coverage.unexamined ?? []).map(({ path }) => path))
  const examinedByLens = new Set(lens.examined_paths ?? [])

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
  const jobs = obligatedLensJobs(run, finding.lens)
  if (!lensCoverageIsComplete(jobs)) return 'NO_CURRENT_COVERAGE_AUTHORITY'
  const authorities = new Set(
    jobs.map(({ coverage_authority: authority }) => authority),
  )
  if (authorities.size > 1) return 'PROVIDER_DECLARED'
  if (authorities.has('CONTROLLER_OBSERVED_CONSUMPTION')) {
    return 'CONTROLLER_OBSERVED_CONSUMPTION'
  }
  if (authorities.has('REMOTE_REQUEST_ACCEPTED')) {
    return 'REMOTE_REQUEST_ACCEPTED'
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
      compareCanonicalStrings(String(left.candidate_id), String(right.candidate_id)))
  }
  return groups
}

export function compareRuns(baseline, current) {
  const compatibility = comparisonCompatibility(baseline, current)
  const baselineByFingerprint = groupedFindings(baseline)
  const currentByFingerprint = groupedFindings(current)
  const comparedLenses = [...new Set([
    ...activeFindings(baseline).map(({ lens }) => lens),
    ...activeFindings(current).map(({ lens }) => lens),
  ])].sort(compareCanonicalStrings)
  const lensComparability = comparedLenses.map((lens) =>
    compareLensContracts(baseline, current, lens, compatibility))
  const lensComparabilityByName = new Map(
    lensComparability.map((entry) => [entry.lens, entry]),
  )
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
    const present = (currentByFingerprint.get(fingerprint) ?? [])
      .map((finding) => ({
        digest: findingDigest(finding),
        finding,
        match: null,
      }))
    const previousByDigest = new Map()
    for (const entry of previous) {
      const bucket = previousByDigest.get(entry.digest) ?? { entries: [], cursor: 0 }
      bucket.entries.push(entry)
      previousByDigest.set(entry.digest, bucket)
    }
    // Reserve every exact match before pairing changed collision members. A
    // fallback in this pass could consume the only baseline record matching a
    // later current finding, making unchanged counts depend on candidate IDs.
    for (const entry of present) {
      const bucket = previousByDigest.get(entry.digest)
      const match = bucket?.entries[bucket.cursor] ?? null
      if (match) {
        match.matched = true
        bucket.cursor += 1
        entry.match = match
      }
    }

    let fallbackCursor = 0
    for (const { finding, digest, match: exactMatch } of present) {
      let match = exactMatch
      if (!match) {
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
          : match.digest === digest
            ? 'unchanged'
            : 'updated',
        finding,
        baseline_finding: baselineFinding,
        resolution_authority: coverageAuthorityForFinding(current, finding),
      })
    }
    for (const { finding, matched } of previous) {
      if (matched) continue
      const comparableCoverage = (
        (compatibility.comparable || lensComparabilityByName.get(finding.lens)?.comparable === true)
        && topicContractSupportsResolution(baseline, current, finding, compatibility)
        && coverageSupportsResolution(current, finding, baseline)
      )
      results.push({
        fingerprint,
        candidate_id: finding.candidate_id,
        // Comparable coverage can establish only that the current provider did
        // not return the prior semantic finding. None of the currently enrolled
        // coverage authorities authenticates that the vulnerability is fixed.
        state: comparableCoverage
          ? 'claimed-fixed'
          : 'not-observed',
        finding: null,
        baseline_finding: finding,
        resolution_authority: coverageAuthorityForFinding(current, finding),
        semantic_resolution_authority: comparableCoverage
          ? 'UNAUTHENTICATED_COVERAGE_ABSENCE'
          : 'NO_RESOLUTION_CLAIM',
      })
    }
  }

  const order = new Map([
    ['new', 0],
    ['updated', 1],
    ['unchanged', 2],
    ['not-observed', 3],
    ['claimed-fixed', 4],
    ['fixed', 5],
  ])
  results.sort((left, right) =>
    order.get(left.state) - order.get(right.state) ||
    compareCanonicalStrings(left.fingerprint, right.fingerprint) ||
    compareCanonicalStrings(String(left.candidate_id), String(right.candidate_id)))

  const resolutionAuthorities = [...new Set(
    results
      .map(({ resolution_authority: authority }) => authority),
  )].sort((left, right) => compareCanonicalStrings(left, right))
  const resolutionAuthority = resolutionAuthorities.length === 0
    ? 'NO_RESOLUTION_CLAIMS'
    : resolutionAuthorities.length === 1
      && resolutionAuthorities[0] === 'CONTROLLER_OBSERVED_CONSUMPTION'
      ? 'controller-observed byte consumption; not comprehension or independent proof'
      : resolutionAuthorities.length === 1
        && resolutionAuthorities[0] === 'REMOTE_REQUEST_ACCEPTED'
        ? 'pinned remote gateway request acceptance; not comprehension or independent proof'
      : resolutionAuthorities.length === 1
        && resolutionAuthorities[0] === 'PROVIDER_DECLARED'
        ? 'provider-declared lens, file, and store coverage; not an independent controller read receipt'
        : resolutionAuthorities.length === 1
          ? 'no current successful lens coverage authority; no resolution claim is supported'
          : resolutionAuthorities.includes('NO_CURRENT_COVERAGE_AUTHORITY')
            ? 'mixed current coverage authority with at least one finding lacking successful lens coverage; no unsupported resolution claim is implied'
            : 'mixed provider-declared and authenticated execution authorities; none is independent proof'
  return {
    baseline_run_id: baseline.run_id,
    current_run_id: current.run_id,
    comparable: compatibility.comparable,
    partially_comparable: !compatibility.comparable
      && lensComparability.some(({ comparable }) => comparable),
    comparability_reasons: compatibility.reasons,
    lens_comparability: lensComparability,
    resolution_authority: resolutionAuthority,
    counts: Object.fromEntries(
      ['new', 'updated', 'unchanged', 'claimed-fixed', 'fixed', 'not-observed']
        .map((state) => [state, results.filter((entry) => entry.state === state).length]),
    ),
    results,
  }
}
