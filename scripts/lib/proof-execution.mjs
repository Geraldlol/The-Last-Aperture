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

const WINDOWS_RESERVED_BASENAME = /^(?:con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i

function assertCanonicalProofPath(path, label) {
  const segments = path.split('/')
  if (
    segments.some((segment) => (
      segment.length === 0
      || segment === '.'
      || segment === '..'
      || segment.includes(':')
      || /[. ]$/.test(segment)
      || WINDOWS_RESERVED_BASENAME.test(segment)
    ))
  ) {
    throw new Error(
      `proof configuration is invalid: ${label} must be a canonical portable path`,
    )
  }
}

export function assertValidProofConfig(config) {
  if (validateProofConfigSchema(config)) {
    for (const [index, file] of config.proof_files.entries()) {
      assertCanonicalProofPath(file.path, `proof_files[${index}].path`)
    }
    for (const [index, file] of (config.patch_files ?? []).entries()) {
      assertCanonicalProofPath(file.path, `patch_files[${index}].path`)
    }
    if (config.destination_guard?.path) {
      assertCanonicalProofPath(config.destination_guard.path, 'destination_guard.path')
    }
    if (config.reproducer?.path) {
      assertCanonicalProofPath(config.reproducer.path, 'reproducer.path')
    }
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
      ['2.0.0', '3.0.0'].includes(config.schema_version)
      && !proofSet.has(config.reproducer.path)
    ) {
      throw new Error(
        'proof configuration is invalid: reproducer path must name a declared proof file',
      )
    }
    if (['2.0.0', '3.0.0'].includes(config.schema_version)) {
      const attackCodes = new Set(config.oracle.attack_exit_codes)
      if (config.oracle.control_exit_codes.some((code) => attackCodes.has(code))) {
        throw new Error(
          'proof configuration is invalid: attack and control oracle exit codes must be disjoint',
        )
      }
    }
    if (
      config.schema_version === '3.0.0'
      && config.service.probe_interval_ms > config.service.startup_timeout_ms
    ) {
      throw new Error(
        'proof configuration is invalid: service probe_interval_ms must not exceed startup_timeout_ms',
      )
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
  if (config.schema_version === '3.0.0') {
    authorizeCommand(config.service.command, 'service boot command')
  }
  authorizeCommand(config.command, 'proof command')
  if (config.control_command) authorizeCommand(config.control_command, 'control command')

  await createMirror(targetRoot, mirrorRoot)
  const owned = new Set()
  let mirrorRetained = false
  let activePhase = null
  let demonstration = null
  let control = null
  let remediation = null
  try {
    for (const path of await materializeFiles(
      mirrorRoot,
      config.proof_files,
      { requireAbsent: true },
    )) {
      owned.add(path)
    }
    // The demonstration runs against the unmodified mirror. It must fail here,
    // or the proof did not reproduce the bug it claims.
    activePhase = 'demonstration'
    demonstration = await spawn(
      config.command.program,
      config.command.args,
      mirrorRoot,
      config.limits,
    )

    activePhase = 'control'
    control = config.control_command
      ? await spawn(
          config.control_command.program,
          config.control_command.args,
          mirrorRoot,
          config.limits,
        )
      : null

    if (Array.isArray(config.patch_files) && config.patch_files.length > 0) {
      for (const path of await materializeFiles(mirrorRoot, config.patch_files)) {
        owned.add(path)
      }
      activePhase = 'remediation'
      remediation = await spawn(
        config.command.program,
        config.command.args,
        mirrorRoot,
        config.limits,
      )
    }

    activePhase = null
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
    if (config.schema_version === '3.0.0' && error instanceof Error) {
      if (error.partial_result !== undefined) {
        if (activePhase === 'demonstration') demonstration = error.partial_result
        if (activePhase === 'control') control = error.partial_result
        if (activePhase === 'remediation') remediation = error.partial_result
      }
      error.proof_outcome = {
        demonstration,
        control,
        remediation,
        ownedPaths: [...owned].sort(compareCanonicalStrings),
        mirrorRoot,
        mirrorRetained,
      }
    }
    // A mutated target is the one failure where the evidence of what happened
    // matters more than tidiness, so the mirror survives for inspection.
    if (error instanceof MirrorMutationError) mirrorRetained = true
    throw error
  } finally {
    if (!mirrorRetained) await destroyMirror(mirrorRoot)
  }
}
