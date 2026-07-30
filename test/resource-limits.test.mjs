import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  MAX_BUNDLE_ARTIFACTS,
  MAX_BUNDLE_VERIFICATION_BYTES,
  reserveBundleArtifactCapacity,
} from '../scripts/lib/resource-limits.mjs'

test('bundle append reservation accepts the exact boundary and rejects either overflow', () => {
  const exact = reserveBundleArtifactCapacity(
    {
      artifactCount: MAX_BUNDLE_ARTIFACTS - 1,
      artifactBytes: MAX_BUNDLE_VERIFICATION_BYTES - 1,
    },
    Buffer.alloc(1),
  )
  assert.deepEqual(exact, {
    artifactCount: MAX_BUNDLE_ARTIFACTS,
    artifactBytes: MAX_BUNDLE_VERIFICATION_BYTES,
  })

  assert.throws(
    () => reserveBundleArtifactCapacity(
      {
        artifactCount: MAX_BUNDLE_ARTIFACTS,
        artifactBytes: 0,
      },
      Buffer.alloc(0),
    ),
    /would declare.*limit/i,
  )
  assert.throws(
    () => reserveBundleArtifactCapacity(
      {
        artifactCount: 0,
        artifactBytes: MAX_BUNDLE_VERIFICATION_BYTES,
      },
      Buffer.alloc(1),
    ),
    /verification bytes.*limit/i,
  )
})
