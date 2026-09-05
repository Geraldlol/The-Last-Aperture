import { compareCanonicalStrings } from './canonical-order.mjs'

export const CLOSED_TOPIC_DISPOSITIONS = new Set([
  'finding',
  'examined-clean',
  'not-applicable',
])

function assessedByTopic(job) {
  return new Map(
    (job.topic_assessments ?? []).map((assessment) => [assessment.topic, assessment]),
  )
}

export function topicAssessmentStatsForJob(job) {
  const obligations = job.topic_obligations ?? []
  const assessments = assessedByTopic(job)
  let closed = 0
  let partial = 0
  let notAssessed = 0
  for (const topic of obligations) {
    const disposition = assessments.get(topic)?.disposition
    if (CLOSED_TOPIC_DISPOSITIONS.has(disposition)) closed += 1
    else if (disposition === 'partial') partial += 1
    else notAssessed += 1
  }
  return {
    obligations: obligations.length,
    closed,
    partial,
    not_assessed: notAssessed,
    open: partial + notAssessed,
  }
}

export function topicAssessmentSummary(run) {
  const rowsByLens = new Map()
  const jobs = (run?.jobs ?? []).filter((job) =>
    job.kind === 'LENS'
    && typeof job.lens === 'string'
    && !['SKIPPED', 'DORMANT'].includes(job.state))
  for (const job of jobs) {
    const stats = topicAssessmentStatsForJob(job)
    const row = rowsByLens.get(job.lens) ?? {
      lens: job.lens,
      obligations: 0,
      closed: 0,
      partial: 0,
      not_assessed: 0,
      open: 0,
    }
    for (const field of ['obligations', 'closed', 'partial', 'not_assessed', 'open']) {
      row[field] += stats[field]
    }
    rowsByLens.set(job.lens, row)
  }
  const rows = [...rowsByLens.values()]
    .sort((left, right) => compareCanonicalStrings(left.lens, right.lens))
  return {
    obligations: rows.reduce((total, row) => total + row.obligations, 0),
    closed: rows.reduce((total, row) => total + row.closed, 0),
    partial: rows.reduce((total, row) => total + row.partial, 0),
    not_assessed: rows.reduce((total, row) => total + row.not_assessed, 0),
    open: rows.reduce((total, row) => total + row.open, 0),
    rows,
  }
}
