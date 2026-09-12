const NON_FOLLOWABLE_3XX_STATUSES = new Set([304, 305, 306])

export function httpAuthedResponseStopReason(status) {
  if (status === 401 || status === 403) return 'CREDENTIAL_INVALID'
  if (status === 429) return 'LIMIT_REACHED'
  if (
    Number.isSafeInteger(status)
    && status >= 300
    && status <= 399
    && !NON_FOLLOWABLE_3XX_STATUSES.has(status)
  ) {
    return 'UNEXPECTED_REDIRECT'
  }
  if (Number.isSafeInteger(status) && status >= 500) return 'TARGET_HEALTH_DEGRADED'
  return null
}
