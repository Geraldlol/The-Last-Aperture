const REMOVED_DISPOSITIONS = new Set(['dropped', 'merged'])
const NEGATIVE_VERIFICATION_STATUSES = new Set(['DISPROVED', 'NOT_REPRODUCED'])
const DEFINITIVE_VERIFICATION_STATUSES = new Set([
  'CONFIRMED',
  'DISPROVED',
  'NOT_REPRODUCED',
])

// No public or internal release path currently binds a semantic oracle to a
// separately pinned controller receipt. Keep the trusted set empty until that
// contract exists; a provenance label alone must never manufacture authority.
const TRUSTED_VERIFICATION_AUTHORITIES = new Set()
const TRUSTED_TRIAGE_AUTHORITIES = new Set()

export function hasAuthenticatedVerification(finding) {
  return TRUSTED_VERIFICATION_AUTHORITIES.has(finding?.verification_authority)
}

export function verificationAuthorityOf(finding) {
  return finding?.verification_authority ?? 'UNAUTHENTICATED_LEGACY_ASSERTION'
}

export function hasAuthenticatedTriage(finding) {
  return TRUSTED_TRIAGE_AUTHORITIES.has(finding?.triage_authority)
}

export function triageAuthorityOf(finding) {
  return finding?.triage_authority ?? 'UNAUTHENTICATED_LEGACY_ASSERTION'
}

export function displayTriageDisposition(finding) {
  const disposition = finding?.triage_disposition
  if (
    REMOVED_DISPOSITIONS.has(disposition)
    && !hasAuthenticatedTriage(finding)
  ) {
    return `CLAIMED_${disposition.toUpperCase()}`
  }
  return disposition
}

export function displayVerificationStatus(finding) {
  const status = finding?.verification_status
  if (
    DEFINITIVE_VERIFICATION_STATUSES.has(status)
    && !hasAuthenticatedVerification(finding)
  ) {
    return `CLAIMED_${status}`
  }
  return status
}

export function isSurvivingFinding(finding) {
  return !(
    REMOVED_DISPOSITIONS.has(finding?.triage_disposition)
    && hasAuthenticatedTriage(finding)
  )
    && !(
      NEGATIVE_VERIFICATION_STATUSES.has(finding?.verification_status)
      && hasAuthenticatedVerification(finding)
    )
}
