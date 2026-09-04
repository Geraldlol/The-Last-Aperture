import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { join } from 'node:path'
import {
  assertValidBountyScope,
  describeScopeCurrency,
  digestPolicySnapshot,
  sealedBeforeUserAgentMandate,
} from './bounty-contracts.mjs'
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
  // A bundle sealed before the marker was mandated stays readable, for the same
  // reason a lapsed one does: the evidence outlives the authorization. Every
  // other schema defect still throws, and recon/authz refuse on their own.
  const preMandate = sealedBeforeUserAgentMandate(scope)
  if (!preMandate) assertValidBountyScope(scope)
  return { manifest, scope, preMandate }
}

export async function validateBountyBundle(bundlePath, { now = new Date() } = {}) {
  const { scope, preMandate } = await readBundle(bundlePath)
  // Reports currency rather than enforcing it. Inspecting an old bundle must stay
  // possible after the grant lapses -- the evidence outlives the authorization,
  // and refusing to open it would make past findings unreadable. Enforcement
  // belongs on the commands that contact a target.
  const currency = describeScopeCurrency({ scope, now })
  return { status: 'VALID', scope, currency, preMandate }
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
