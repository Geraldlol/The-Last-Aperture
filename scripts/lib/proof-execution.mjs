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
  if (validateProofConfigSchema(config)) {
    const proofPaths = config.proof_files.map(({ path }) => path)
    const patchPaths = (config.patch_files ?? []).map(({ path }) => path)
    if (new Set(proofPaths).size !== proofPaths.length) {
      throw new Error('proof configuration is invalid: proof file paths must be unique')
    }
    if (new Set(patchPaths).size !== patchPaths.length) {
      throw new Error('proof configuration is invalid: patch file paths must be unique')
    }
    const proofSet = new Set(proofPaths)
    if (patchPaths.some((path) => proofSet.has(path))) {
      throw new Error('proof configuration is invalid: proof and patch paths must be disjoint')
    }
    if (
      config.schema_version === '2.0.0'
      && !proofSet.has(config.reproducer.path)
    ) {
      throw new Error(
        'proof configuration is invalid: reproducer path must name a declared proof file',
      )
    }
    if (config.schema_version === '2.0.0') {
      const attackCodes = new Set(config.oracle.attack_exit_codes)
      if (config.oracle.control_exit_codes.some((code) => attackCodes.has(code))) {
        throw new Error(
          'proof configuration is invalid: attack and control oracle exit codes must be disjoint',
        )
      }
    }
    return config
  }
  const detail = validateProofConfigSchema.errors
    .map((error) => `${error.instancePath || '/'} ${error.message}`)
    .join('; ')
  throw new Error(`proof configuration is invalid: ${detail}`)
}

export async function executeProof({
  targetRoot,
  mirrorRoot,
  expectedTreeDigest,
  inventoryOptions = {},
  policy,
  config,
  spawn,
}) {
  // Authorize every command before anything is copied, so a refused attack or
  // control leaves no trace. Version 1 has no separate control command.
  const authorizeCommand = (command, label) => {
    const decision = authorizeAction(policy, {
      type: 'execute',
      program: command.program,
      args: command.args,
    })
    if (decision.allowed) return
    const detail = decision.reasons
      .map(({ code, message }) => `${code}: ${message}`)
      .join('; ')
    throw new Error(`${label} is not authorized by the run policy: ${detail}`)
  }
  authorizeCommand(config.command, 'proof command')
  if (config.control_command) authorizeCommand(config.control_command, 'control command')

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
      config.limits,
    )

    const control = config.control_command
      ? await spawn(
          config.control_command.program,
          config.control_command.args,
          mirrorRoot,
          config.limits,
        )
      : null

    let remediation = null
    if (Array.isArray(config.patch_files) && config.patch_files.length > 0) {
      for (const path of await materializeFiles(mirrorRoot, config.patch_files)) {
        owned.add(path)
      }
      remediation = await spawn(
        config.command.program,
        config.command.args,
        mirrorRoot,
        config.limits,
      )
    }

    await assertTargetUnchanged(targetRoot, expectedTreeDigest, inventoryOptions)

    return {
      demonstration,
      control,
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
