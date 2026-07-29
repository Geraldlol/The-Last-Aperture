const REMOVED_DISPOSITIONS = new Set(['dropped', 'merged'])
const NEGATIVE_VERIFICATION_STATUSES = new Set(['DISPROVED', 'NOT_REPRODUCED'])

export function isSurvivingFinding(finding) {
  return !REMOVED_DISPOSITIONS.has(finding?.triage_disposition)
    && !NEGATIVE_VERIFICATION_STATUSES.has(finding?.verification_status)
}
