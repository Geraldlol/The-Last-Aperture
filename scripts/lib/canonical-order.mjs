/**
 * Locale-independent ordering for controller-owned identities.
 *
 * Do not replace this with localeCompare: path, job, and digest material must
 * sort identically across hosts regardless of OS locale or ICU version.
 */
export function compareCanonicalStrings(left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}
