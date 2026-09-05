/**
 * Reject Windows network and object-manager path syntax without touching the
 * filesystem. `path.resolve()` preserves UNC paths, so treating the result as
 * an ordinary local file can perform SMB/WebDAV I/O and disclose ambient
 * credentials. Device and pipe namespaces have the same problem. Run this
 * lexical check before stat, realpath, or open.
 */
export function assertLocalFilesystemEndpoint(value, label = 'filesystem path') {
  if (typeof value !== 'string') return value
  const windows = value.replaceAll('/', '\\')
  if (windows.startsWith('\\\\') || /^\\\?\?\\/.test(windows)) {
    const error = new Error(
      `${label} must be a local filesystem path; UNC/WebDAV and Windows namespace-prefixed device, object-manager, or pipe paths are refused`,
    )
    error.code = 'FILESYSTEM_ENDPOINT_NOT_LOCAL'
    throw error
  }
  return value
}

export function assertNoRemoteFilesystemArguments(values, label = 'command-line argument') {
  for (const value of values) assertLocalFilesystemEndpoint(value, label)
}
