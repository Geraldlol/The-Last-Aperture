export const MAX_RUN_MANIFEST_BYTES = 128 * 1024 * 1024
export const MAX_BUNDLE_ARTIFACT_BYTES = 128 * 1024 * 1024
export const MAX_BUNDLE_ARTIFACTS = 16_384
export const MAX_BUNDLE_VERIFICATION_BYTES = 512 * 1024 * 1024

export function contentByteLength(content) {
  return Buffer.isBuffer(content)
    ? content.length
    : Buffer.byteLength(String(content), 'utf8')
}

export function assertBundleArtifactSize(content, label = 'bundle artifact') {
  const bytes = contentByteLength(content)
  if (bytes > MAX_BUNDLE_ARTIFACT_BYTES) {
    throw new Error(
      `${label} exceeds the ${MAX_BUNDLE_ARTIFACT_BYTES}-byte bundle artifact limit`,
    )
  }
  return bytes
}

export function assertRunManifestSize(content) {
  const bytes = contentByteLength(content)
  if (bytes > MAX_RUN_MANIFEST_BYTES) {
    throw new Error(
      `run manifest exceeds the ${MAX_RUN_MANIFEST_BYTES}-byte input limit`,
    )
  }
  return bytes
}

export function reserveBundleArtifactCapacity(
  current,
  contents,
  label = 'bundle artifacts',
) {
  const additions = Array.isArray(contents) ? contents : [contents]
  if (
    !Number.isSafeInteger(current.artifactCount)
    || current.artifactCount < 0
    || !Number.isSafeInteger(current.artifactBytes)
    || current.artifactBytes < 0
  ) {
    throw new Error(`${label} requires non-negative integer capacity counters`)
  }
  const artifactCount = current.artifactCount + additions.length
  if (artifactCount > MAX_BUNDLE_ARTIFACTS) {
    throw new Error(
      `${label} would declare ${artifactCount} artifacts; ` +
      `limit is ${MAX_BUNDLE_ARTIFACTS}`,
    )
  }
  const next = {
    artifactCount,
    artifactBytes: current.artifactBytes + additions.reduce(
      (total, content) => total + assertBundleArtifactSize(content, label),
      0,
    ),
  }
  if (next.artifactBytes > MAX_BUNDLE_VERIFICATION_BYTES) {
    throw new Error(
      `${label} would require ${next.artifactBytes} verification bytes; ` +
      `limit is ${MAX_BUNDLE_VERIFICATION_BYTES}`,
    )
  }
  return next
}
