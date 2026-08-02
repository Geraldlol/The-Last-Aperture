/**
 * Executes an authored proof in a disposable mirror of the target.
 *
 * The provider authors the proof and the candidate patch; the controller runs
 * them. The split is deliberate: the party claiming the bug never produces the
 * observation that proves it.
 *
 * The mirror is not a sandbox. The executed command is the project's own, run
 * with the project's own environment, and does whatever that does.
 */
import { readFileSync } from 'node:fs'
import Ajv2020 from 'ajv/dist/2020.js'
import { authorizeAction } from './policy.mjs'
import {
  assertTargetUnchanged,
  createMirror,
  destroyMirror,
  materializeFiles,
  MirrorMutationError,
} from './disposable-mirror.mjs'
import { compareCanonicalStrings } from './canonical-order.mjs'

const PROOF_CONFIG_SCHEMA_URL = new URL(
  '../../schemas/proof-config.schema.json',
  import.meta.url,
)
const validateProofConfigSchema = new Ajv2020({ strict: true, allErrors: true })
  .compile(JSON.parse(readFileSync(PROOF_CONFIG_SCHEMA_URL, 'utf8')))

export function assertValidProofConfig(config) {
  if (validateProofConfigSchema(config)) return config
  const detail = validateProofConfigSchema.errors
    .map((error) => `${error.instancePath || '/'} ${error.message}`)
    .join('; ')
  throw new Error(`proof configuration is invalid: ${detail}`)
}

export async function executeProof({
  targetRoot,
  mirrorRoot,
  expectedTreeDigest,
  policy,
  config,
  spawn,
}) {
  // Authorize before anything is copied, so a refused command leaves no trace.
  const decision = authorizeAction(policy, {
    type: 'execute',
    program: config.command.program,
    args: config.command.args,
  })
  if (!decision.allowed) {
    const detail = decision.reasons
      .map(({ code, message }) => `${code}: ${message}`)
      .join('; ')
    throw new Error(`proof command is not authorized by the run policy: ${detail}`)
  }

  await createMirror(targetRoot, mirrorRoot)
  const owned = new Set()
  let mirrorRetained = false
  try {
    for (const path of await materializeFiles(mirrorRoot, config.proof_files)) {
      owned.add(path)
    }
    // The demonstration runs against the unmodified mirror. It must fail here,
    // or the proof did not reproduce the bug it claims.
    const demonstration = await spawn(
      config.command.program,
      config.command.args,
      mirrorRoot,
    )

    let remediation = null
    if (Array.isArray(config.patch_files) && config.patch_files.length > 0) {
      for (const path of await materializeFiles(mirrorRoot, config.patch_files)) {
        owned.add(path)
      }
      remediation = await spawn(
        config.command.program,
        config.command.args,
        mirrorRoot,
      )
    }

    await assertTargetUnchanged(targetRoot, expectedTreeDigest)

    return {
      demonstration,
      remediation,
      ownedPaths: [...owned].sort(compareCanonicalStrings),
      mirrorRoot,
      mirrorRetained,
    }
  } catch (error) {
    // A mutated target is the one failure where the evidence of what happened
    // matters more than tidiness, so the mirror survives for inspection.
    if (error instanceof MirrorMutationError) mirrorRetained = true
    throw error
  } finally {
    if (!mirrorRetained) await destroyMirror(mirrorRoot)
  }
}
