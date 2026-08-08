import { compareCanonicalStrings } from './canonical-order.mjs'
import { EVIDENCE_CLASSES, EVIDENCE_CLASS_ORDER } from './evidence-classes.mjs'

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
export function buildEvidenceCoverage({ lenses = [], activatedLenses = [], bundles = [] }) {
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

        // Where several bundles cover one class, the run is only as covered as
        // its weakest — the same reason PARTIAL exists at all.
        const ranked = ['NOT_ASSESSED', 'INVENTORY_ONLY', 'PARTIAL', 'COVERED']
        const weakest = usable.reduce((worst, bundle) =>
          ranked.indexOf(bundle.coverage_state) < ranked.indexOf(worst.coverage_state)
            ? bundle
            : worst)
        cells.push({
          lens: name,
          topic,
          evidence_class: evidenceClass,
          state: weakest.coverage_state,
          reason: `${weakest.evidence_id} (${weakest.root_sha256.slice(0, 12)})`,
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

  return {
    cells,
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
