import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import { assertValidBountyScope, digestPolicySnapshot } from './bounty-contracts.mjs'
import { createProgramSealedScope } from './bounty-planner.mjs'
import { decideScope } from './bounty-scope-kernel.mjs'

const BUNDLE_KIND = 'red-team-audit/bounty-bundle'
const BUNDLE_SCHEMA_VERSION = '1.0.0'
const MAX_POLICY_BYTES = 4 * 1024 * 1024

function serialize(value) {
  return `${JSON.stringify(value, null, 2)}\n`
}

async function readPolicyBytes(policyPath) {
  const bytes = await readFile(policyPath)
  if (bytes.byteLength === 0) {
    throw new Error(`policy snapshot is empty: ${policyPath}`)
  }
  if (bytes.byteLength > MAX_POLICY_BYTES) {
    throw new Error(`policy snapshot exceeds ${MAX_POLICY_BYTES} bytes: ${policyPath}`)
  }
  return bytes
}

export async function planBountyBundle(options) {
  const { outParent, policyPath, ...rest } = options
  const bundlePath = join(outParent, rest.engagementId)
  try {
    await mkdir(bundlePath, { recursive: false })
  } catch (error) {
    if (error.code === 'EEXIST') {
      throw new Error(`bundle path already exists, refusing to overwrite: ${bundlePath}`)
    }
    throw error
  }
  const policySnapshotBytes = await readPolicyBytes(policyPath)
  const scope = createProgramSealedScope({ ...rest, policySnapshotBytes })
  const scopeText = serialize(scope)
  await writeFile(join(bundlePath, 'scope.json'), scopeText, 'utf8')
  await writeFile(join(bundlePath, 'bundle.json'), serialize({
    kind: BUNDLE_KIND,
    schema_version: BUNDLE_SCHEMA_VERSION,
    engagement_id: scope.engagement_id,
    scope_sha256: digestPolicySnapshot(scopeText),
    created_at: scope.authorization.attested_at,
  }), 'utf8')
  return { bundlePath, scope }
}

async function readBundle(bundlePath) {
  const manifest = JSON.parse(await readFile(join(bundlePath, 'bundle.json'), 'utf8'))
  if (manifest.kind !== BUNDLE_KIND) {
    throw new Error(`not a bounty-v1 bundle: ${bundlePath}`)
  }
  const scopeText = await readFile(join(bundlePath, 'scope.json'), 'utf8')
  const observed = digestPolicySnapshot(scopeText)
  if (observed !== manifest.scope_sha256) {
    throw new Error(
      `sealed scope digest mismatch; bundle was modified after sealing (sealed ${manifest.scope_sha256}, observed ${observed})`,
    )
  }
  const scope = JSON.parse(scopeText)
  assertValidBountyScope(scope)
  return { manifest, scope }
}

export async function validateBountyBundle(bundlePath) {
  const { scope } = await readBundle(bundlePath)
  return { status: 'VALID', scope }
}

export async function revalidateBountyBundle(bundlePath, policyPath) {
  const { scope } = await readBundle(bundlePath)
  const observed = digestPolicySnapshot(await readPolicyBytes(policyPath))
  const sealed = scope.program.policy_snapshot_sha256
  return { status: observed === sealed ? 'UNCHANGED' : 'DRIFTED', sealed, observed }
}

export async function checkBountyScope(bundlePath, candidate) {
  const { scope } = await readBundle(bundlePath)
  return decideScope(scope, candidate)
}
