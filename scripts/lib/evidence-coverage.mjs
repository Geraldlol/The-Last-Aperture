import { compareCanonicalStrings } from './canonical-order.mjs'
import { EVIDENCE_CLASSES, EVIDENCE_CLASS_ORDER } from './evidence-classes.mjs'
import { OCI_EVIDENCE_RULE_SUPPORT } from './evidence-oci-rules.mjs'

const COVERAGE_RANK = ['NOT_ASSESSED', 'INVENTORY_ONLY', 'PARTIAL', 'COVERED']
const NON_CLEAR_STATES = new Set(['PARTIAL', 'INVENTORY_ONLY', 'NOT_ASSESSED'])

function normalizedAcquiredState(state) {
  // NOT_APPLICABLE is meaningful for an empty lens/class matrix cell. It is
  // never meaningful for bytes the controller actually acquired: those bytes
  // were either analyzed or they were not. Treat a profile that claims N/A as
  // not assessed so acquisition cannot become implicit clearance.
  return COVERAGE_RANK.includes(state) ? state : 'NOT_ASSESSED'
}

function bundleMatchesDeclaration(bundle, declaration) {
  const entry = declaration?.[bundle.evidence_class]
  if (entry?.state !== 'consumed') return false
  if (bundle.evidence_class !== EVIDENCE_CLASSES.BUILT_ARTIFACT) return true
  return (entry.artifact_kinds ?? []).includes(bundle.artifact_kind)
}

function deliveredEvidenceIds(job) {
  return [
    ...(Array.isArray(job?.evidence_ids) ? job.evidence_ids : []),
    ...(job?.evidence ?? [])
    .map(({ evidence_context: context }) => context?.evidence_id)
    .filter((evidenceId) => typeof evidenceId === 'string'),
  ]
}

function bundleDeliveredToLens(bundle, lens, jobs) {
  if (!Array.isArray(jobs)) return true
  return jobs.some((job) =>
    job?.lens === lens
    && deliveredEvidenceIds(job).includes(bundle.evidence_id))
}

function bundleCoverageState(bundle, deliveredConsumers) {
  if (deliveredConsumers.length === 0) return 'NOT_ASSESSED'
  const acquiredState = normalizedAcquiredState(bundle.coverage_state)
  if (bundle.analysis_state === 'NOT_ASSESSED') return 'NOT_ASSESSED'
  if (
    bundle.analysis_state === 'PARTIAL'
    && COVERAGE_RANK.indexOf(acquiredState) > COVERAGE_RANK.indexOf('PARTIAL')
  ) {
    return 'PARTIAL'
  }
  // The shipped OCI controller rules are finite positive-match detectors.
  // Completing them establishes that their checks ran, not that the acquired
  // bytes were exhaustively assessed. No current analyzer contract authorizes
  // bundle-level clearance.
  if (acquiredState === 'COVERED') return 'PARTIAL'
  return acquiredState
}

function buildBundleCoverage({ lenses, active, bundles, jobs }) {
  const useDispatchedJobs = Array.isArray(jobs)
  const records = bundles.map((bundle) => {
    const declaredConsumers = lenses
      .filter((lens) => bundleMatchesDeclaration(
        bundle,
        lens.frontmatter?.activates_on?.evidence_classes ?? {},
      ))
      .map((lens) => lens.frontmatter?.name ?? lens.name)
      .filter((name) => typeof name === 'string')
      .sort(compareCanonicalStrings)
    const eligibleConsumers = declaredConsumers.filter((name) => active.has(name))
    const deliveredConsumers = useDispatchedJobs
      ? [...new Set(jobs
          .filter((job) =>
            eligibleConsumers.includes(job.lens)
            && deliveredEvidenceIds(job).includes(bundle.evidence_id))
          .map(({ lens }) => lens))]
          .sort(compareCanonicalStrings)
      : eligibleConsumers
    const missingConsumers = eligibleConsumers.filter(
      (name) => !deliveredConsumers.includes(name),
    )

    let state
    let reason
    if (declaredConsumers.length === 0) {
      state = 'INVENTORY_ONLY'
      reason = `${bundle.artifact_kind ?? bundle.evidence_class} was acquired; `
        + 'no lens declares it consumed'
    } else if (eligibleConsumers.length === 0) {
      state = 'NOT_ASSESSED'
      reason = `${bundle.artifact_kind ?? bundle.evidence_class} was acquired, but its declared `
        + `consumer${declaredConsumers.length === 1 ? '' : 's'} did not activate: `
        + declaredConsumers.join(', ')
    } else if (missingConsumers.length > 0) {
      state = 'NOT_ASSESSED'
      reason = `${bundle.artifact_kind ?? bundle.evidence_class} was not delivered to every `
        + `active declared consumer; missing ${missingConsumers.join(', ')}`
        + (deliveredConsumers.length > 0
          ? `; delivered to ${deliveredConsumers.join(', ')}`
          : '; delivered to none')
    } else {
      state = bundleCoverageState(bundle, deliveredConsumers)
      const basis = bundle.coverage_state === 'NOT_APPLICABLE'
        ? 'an acquired bundle cannot have NOT_APPLICABLE analysis coverage'
        : bundle.analysis_reason
          ?? `the acquired bundle reports ${normalizedAcquiredState(bundle.coverage_state)} coverage`
      const completeness = (
        state === 'PARTIAL'
        && normalizedAcquiredState(bundle.coverage_state) === 'COVERED'
        && bundle.analysis_state !== 'PARTIAL'
      )
        ? '; current controller analysis is positive-only, not exhaustive'
        : ''
      reason = `${basis}${completeness}; delivered to ${deliveredConsumers.join(', ')}`
    }

    return {
      evidence_id: bundle.evidence_id,
      evidence_class: bundle.evidence_class,
      ...(bundle.artifact_kind ? { artifact_kind: bundle.artifact_kind } : {}),
      root_sha256: bundle.root_sha256,
      state,
      consumer_lenses: deliveredConsumers,
      reason,
    }
  })
  records.sort((left, right) =>
    compareCanonicalStrings(left.evidence_id, right.evidence_id))
  return records
}

function analysisBoundBundle(bundle, lens, topic, declaration) {
  if (bundle.coverage_state === 'NOT_APPLICABLE') {
    return {
      ...bundle,
      coverage_state: 'NOT_ASSESSED',
      analysis_reason: 'an acquired bundle cannot have NOT_APPLICABLE analysis coverage',
    }
  }
  if (bundle.analysis_state === undefined) {
    if (
      bundle.evidence_class !== EVIDENCE_CLASSES.SOURCE
      && bundle.coverage_state === 'COVERED'
    ) {
      return {
        ...bundle,
        coverage_state: 'PARTIAL',
        analysis_reason: `${bundle.analysis_reason ?? 'controller analysis state is missing'}; `
          + 'acquired evidence cannot establish exhaustive coverage',
      }
    }
    return bundle
  }
  if (bundle.analysis_state === 'NOT_ASSESSED') {
    return { ...bundle, coverage_state: 'NOT_ASSESSED' }
  }
  if (
    bundle.evidence_class === EVIDENCE_CLASSES.BUILT_ARTIFACT
    && bundle.artifact_kind === 'oci-image'
    && bundle.index?.rule_analysis?.controller_evaluated === true
  ) {
    const evaluated = new Set(
      bundle.index.rule_analysis.evaluated_rule_ids ?? [],
    )
    const declaredClaims = new Set(declaration.may_conclude ?? [])
    const supportedRules = Object.entries(OCI_EVIDENCE_RULE_SUPPORT)
      .filter(([ruleId, support]) =>
        support.lens === lens
        && support.topic === topic
        && evaluated.has(ruleId)
        && declaredClaims.has(support.claim))
      .map(([ruleId]) => ruleId)
      .sort(compareCanonicalStrings)
    if (supportedRules.length === 0) {
      return {
        ...bundle,
        coverage_state: 'NOT_ASSESSED',
        analysis_reason: `controller OCI analysis has no rule owned by ${lens}/${topic}`,
      }
    }
    const coverageState = COVERAGE_RANK.indexOf(bundle.coverage_state)
      < COVERAGE_RANK.indexOf('PARTIAL')
      ? bundle.coverage_state
      : 'PARTIAL'
    return {
      ...bundle,
      coverage_state: coverageState,
      analysis_reason: `${bundle.analysis_reason}; ${supportedRules.join(', ')} `
        + 'is positive-match coverage and cannot clear the whole topic',
    }
  }
  if (
    bundle.analysis_state === 'PARTIAL'
    && COVERAGE_RANK.indexOf(bundle.coverage_state)
      > COVERAGE_RANK.indexOf('PARTIAL')
  ) {
    return { ...bundle, coverage_state: 'PARTIAL' }
  }
  if (
    bundle.evidence_class !== EVIDENCE_CLASSES.SOURCE
    && bundle.coverage_state === 'COVERED'
  ) {
    return {
      ...bundle,
      coverage_state: 'PARTIAL',
      analysis_reason: `${bundle.analysis_reason ?? 'controller analysis completed'}; `
        + 'current acquired-evidence analysis is positive-only, not exhaustive',
    }
  }
  return bundle
}

/**
 * Coverage becomes lens x topic x evidence class, where it is currently
 * lens x topic. No new state is introduced: the five states are the database
 * contract's, and the existing rule that INVENTORY_ONLY and NOT_ASSESSED never
 * render as clean is what does the work.
 *
 * The load-bearing cell is the one nobody writes today: a lens that consumes
 * built-artifact in a run where no image was acquired. Without it, "we examined
 * the Dockerfile but never the image" is not expressible, and an audit that
 * cannot express its blind spot reports silence — which reads as clearance.
 */
export function buildEvidenceCoverage({
  lenses = [],
  activatedLenses = [],
  bundles = [],
  jobs,
}) {
  const active = new Set(activatedLenses)
  const bundlesByClass = new Map(EVIDENCE_CLASS_ORDER.map((c) => [c, []]))
  for (const bundle of bundles) {
    bundlesByClass.get(bundle.evidence_class)?.push(bundle)
  }

  const cells = []
  const unreached = new Set()

  for (const lens of lenses) {
    const name = lens.frontmatter?.name ?? lens.name
    const declared = lens.frontmatter?.activates_on?.evidence_classes ?? {}
    const topics = [...(lens.frontmatter?.owns ?? [])].sort(compareCanonicalStrings)
    const activated = active.has(name)

    for (const topic of topics) {
      for (const evidenceClass of EVIDENCE_CLASS_ORDER) {
        const entry = declared[evidenceClass]
        if (entry?.state !== 'consumed') {
          cells.push({
            lens: name,
            topic,
            evidence_class: evidenceClass,
            state: 'NOT_APPLICABLE',
            reason: `${name} declares "${evidenceClass}" not-consumed; it has nothing to say`,
          })
          continue
        }
        if (!activated) {
          cells.push({
            lens: name,
            topic,
            evidence_class: evidenceClass,
            state: 'NOT_APPLICABLE',
            reason: `${name} did not activate in this run`,
          })
          continue
        }
        if (evidenceClass === EVIDENCE_CLASSES.SOURCE) {
          cells.push({
            lens: name,
            topic,
            evidence_class: evidenceClass,
            state: 'COVERED',
            reason: 'the repository under audit is the run evidence',
          })
          continue
        }

        const available = bundlesByClass.get(evidenceClass) ?? []
        if (available.length === 0) {
          unreached.add(evidenceClass)
          cells.push({
            lens: name,
            topic,
            evidence_class: evidenceClass,
            state: 'NOT_ASSESSED',
            reason: `no ${evidenceClass} evidence was acquired for this run`,
          })
          continue
        }

        const kinds = entry.artifact_kinds ?? null
        const usable = kinds === null
          ? available
          : available.filter((bundle) => kinds.includes(bundle.artifact_kind))
        if (usable.length === 0) {
          const acquired = [...new Set(available.map(({ artifact_kind: kind }) => kind))]
            .sort(compareCanonicalStrings)
          cells.push({
            lens: name,
            topic,
            evidence_class: evidenceClass,
            state: 'INVENTORY_ONLY',
            reason: `${acquired.join(', ')} was acquired; ${name} declares no rule for it`,
          })
          continue
        }
        const undelivered = usable.filter(
          (bundle) => !bundleDeliveredToLens(bundle, name, jobs),
        )
        if (undelivered.length > 0) {
          unreached.add(evidenceClass)
          cells.push({
            lens: name,
            topic,
            evidence_class: evidenceClass,
            state: 'NOT_ASSESSED',
            reason: `${undelivered.map(({ evidence_id: evidenceId }) => evidenceId)
              .sort(compareCanonicalStrings)
              .join(', ')} was acquired but not delivered to ${name}`,
          })
          continue
        }

        // Where several bundles cover one class, the run is only as covered as
        // its weakest — the same reason PARTIAL exists at all.
        const analysisBound = usable.map((bundle) =>
          analysisBoundBundle(bundle, name, topic, entry))
        const weakest = analysisBound.reduce((worst, bundle) =>
          COVERAGE_RANK.indexOf(bundle.coverage_state)
            < COVERAGE_RANK.indexOf(worst.coverage_state)
            ? bundle
            : worst)
        if (weakest.coverage_state === 'NOT_ASSESSED') {
          unreached.add(evidenceClass)
        }
        cells.push({
          lens: name,
          topic,
          evidence_class: evidenceClass,
          state: weakest.coverage_state,
          reason: `${weakest.evidence_id} (${weakest.root_sha256.slice(0, 12)})`
            + (weakest.analysis_reason
              ? `; ${weakest.analysis_reason}`
              : ''),
        })
      }
    }
  }

  cells.sort((left, right) =>
    compareCanonicalStrings(left.lens, right.lens)
    || compareCanonicalStrings(left.topic, right.topic)
    || EVIDENCE_CLASS_ORDER.indexOf(left.evidence_class)
      - EVIDENCE_CLASS_ORDER.indexOf(right.evidence_class))

  const unreachedClasses = [...unreached]
    .sort((left, right) =>
      EVIDENCE_CLASS_ORDER.indexOf(left) - EVIDENCE_CLASS_ORDER.indexOf(right))
  const bundleCoverage = buildBundleCoverage({
    lenses,
    active,
    bundles,
    jobs,
  })

  return {
    cells,
    bundle_coverage: bundleCoverage,
    summary: {
      cell_count: cells.length,
      bundle_count: bundles.length,
      unreached_class_count: unreachedClasses.length,
      unreached_classes: unreachedClasses,
      not_assessed_cell_count: cells.filter(({ state }) => state === 'NOT_ASSESSED').length,
      inventory_only_cell_count: cells.filter(({ state }) => state === 'INVENTORY_ONLY').length,
    },
  }
}

export function evidenceCoverageIndex(coverage) {
  return new Map((coverage?.cells ?? []).map((cell) => [
    `${cell.lens}\0${cell.topic}\0${cell.evidence_class}`,
    cell.state,
  ]))
}

export function acquiredEvidenceCoverageGaps(run) {
  const bundleCoverageGaps = (run?.evidence_coverage?.bundle_coverage ?? [])
    .filter(({ state }) => NON_CLEAR_STATES.has(state))
  const acquiredClasses = new Set(
    (run?.evidence_bundles ?? []).map(
      ({ evidence_class: evidenceClass }) => evidenceClass,
    ),
  )
  const cellGaps = (run?.evidence_coverage?.cells ?? []).filter(
    ({ evidence_class: evidenceClass, state }) =>
      acquiredClasses.has(evidenceClass)
      && NON_CLEAR_STATES.has(state),
  )
  return [...bundleCoverageGaps, ...cellGaps]
}

export function acquiredEvidenceHasGaps(run) {
  return acquiredEvidenceCoverageGaps(run).length > 0
}
