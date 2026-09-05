#!/usr/bin/env node

import { constants as fsConstants } from 'node:fs'
import { lstat, open } from 'node:fs/promises'
import { resolve } from 'node:path'
import {
  databaseConformanceReportPath,
  planDatabaseConformance,
  runDatabaseConformanceBundle,
  unlockDatabaseConformanceBundle,
  validateDatabaseConformanceBundle,
} from './lib/database-conformance-controller.mjs'
import { assertValidDatabaseConformanceConfig } from './lib/database-conformance-contracts.mjs'
import { isMainModule } from './lib/main-module.mjs'
import {
  assertLocalFilesystemEndpoint,
  assertNoRemoteFilesystemArguments,
} from './lib/filesystem-endpoint.mjs'
import { stableJson } from './lib/run-engine.mjs'
import { terminalSafeSerializedJson, terminalSafeText } from './lib/terminal-text.mjs'

const HELP = `red-team-audit database conformance 0.7.0

Usage:
  database-conformance plan <outside-target-directory> [--engines <comma-separated-engine-ids>] [--json]
  database-conformance run <bundle> <trusted-config.json>  [DISABLED]
  database-conformance unlock <bundle>
  database-conformance validate <bundle> [--json]
  database-conformance report <bundle>

Safety:
  The LOCAL_DYNAMIC protocol uses controller-owned synthetic SQL and never reads
  or executes an audited repository. Public run is disabled before argument,
  bundle, or config access because a caller-selected absolute runtime path is not
  authenticated Docker identity. Reference-engine behavior is not target proof.

Exit codes:
  0  command succeeded
  1  invalid input, failed conformance, or operational failure
`
const MAX_CONFIG_BYTES = 1024 * 1024
const OPEN_READ_ONLY_NO_FOLLOW = fsConstants.O_RDONLY
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)

function parseArguments(values) {
  const positionals = []
  const options = {}
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index]
    if (!value.startsWith('--')) {
      positionals.push(value)
      continue
    }
    const key = value.slice(2)
    if (!key || Object.hasOwn(options, key)) {
      throw new Error(`invalid or duplicate option ${JSON.stringify(value)}`)
    }
    const next = values[index + 1]
    if (next === undefined || next.startsWith('--')) {
      options[key] = true
    } else {
      options[key] = next
      index += 1
    }
  }
  return { positionals, options }
}

function assertShape(command, positionals, options) {
  const shapes = {
    plan: {
      count: 1,
      options: new Map([['engines', 'value'], ['json', 'flag']]),
    },
    run: {
      count: 2,
      options: new Map(),
    },
    validate: {
      count: 1,
      options: new Map([['json', 'flag']]),
    },
    unlock: {
      count: 1,
      options: new Map(),
    },
    report: {
      count: 1,
      options: new Map(),
    },
  }
  const shape = shapes[command]
  if (!shape) throw new Error(`unknown command ${JSON.stringify(command)}\n\n${HELP}`)
  if (positionals.length !== shape.count) {
    throw new Error(
      `${command} expects ${shape.count} positional arguments; received ` +
      `${positionals.length}`,
    )
  }
  for (const [key, value] of Object.entries(options)) {
    const kind = shape.options.get(key)
    if (!kind) throw new Error(`${command} does not support --${key}`)
    if (kind === 'flag' && value !== true) {
      throw new Error(`--${key} is a flag and does not accept a value`)
    }
    if (kind === 'value' && typeof value !== 'string') {
      throw new Error(`--${key} requires a value`)
    }
  }
}

function parseEngineIds(value) {
  if (value === undefined) return undefined
  const values = value.split(',').map((item) => item.trim()).filter(Boolean)
  if (values.length === 0) throw new Error('--engines must name at least one engine')
  return values
}

async function loadConfig(path) {
  const resolved = resolve(path)
  let config
  const info = await lstat(resolved)
  if (!info.isFile() || info.isSymbolicLink() || info.size > MAX_CONFIG_BYTES) {
    throw new Error(
      `trusted configuration must be a regular non-symlink file no larger than ${MAX_CONFIG_BYTES} bytes`,
    )
  }
  const handle = await open(resolved, OPEN_READ_ONLY_NO_FOLLOW)
  try {
    const before = await handle.stat()
    const bytes = await handle.readFile()
    const after = await handle.stat()
    if (
      before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || before.ino !== after.ino
      || bytes.length !== after.size
    ) {
      throw new Error('trusted configuration changed while it was read')
    }
    config = JSON.parse(bytes.toString('utf8'))
  } catch (error) {
    throw new Error(`could not parse trusted configuration ${resolved}: ${error.message}`)
  } finally {
    await handle.close()
  }
  return assertValidDatabaseConformanceConfig(config)
}

export async function main(argv = process.argv.slice(2)) {
  const command = argv[0]
  if (!command || ['help', '--help', '-h'].includes(command)) {
    process.stdout.write(HELP)
    return
  }
  if (command === 'run') {
    const error = new Error(
      'database-conformance run is disabled before argument, bundle, or configuration access pending controller-enrolled, identity-pinned container runtime execution',
    )
    error.code = 'DATABASE_RUNTIME_ENROLLMENT_REQUIRED'
    throw error
  }
  assertLocalFilesystemEndpoint(process.cwd(), 'working directory')
  assertNoRemoteFilesystemArguments(argv)
  const { positionals, options } = parseArguments(argv.slice(1))
  assertShape(command, positionals, options)

  if (command === 'plan') {
    const planned = await planDatabaseConformance({
      out: positionals[0],
      engineIds: parseEngineIds(options.engines),
    })
    if (options.json) {
      process.stdout.write(terminalSafeSerializedJson(stableJson({
        bundle: planned.directory,
        run_id: planned.run.run_id,
        state: planned.run.state,
        engine_ids: planned.run.requested_engine_ids,
        gaps: planned.run.gaps,
      })))
    } else {
      console.log(terminalSafeText(`Planned ${planned.run.run_id}`))
      console.log(terminalSafeText(`Bundle: ${planned.directory}`))
      console.log(terminalSafeText(`Engines: ${planned.run.requested_engine_ids.join(', ')}`))
    }
    return
  }

  if (command === 'run') {
    const config = await loadConfig(positionals[1])
    const run = await runDatabaseConformanceBundle({
      bundle: positionals[0],
      config,
    })
    console.log(terminalSafeText(`Database conformance: ${run.state}`))
    console.log(terminalSafeText(`Report: ${await databaseConformanceReportPath(positionals[0])}`))
    if (run.state !== 'COMPLETE') process.exitCode = 1
    return
  }

  if (command === 'validate') {
    const validation = await validateDatabaseConformanceBundle(positionals[0])
    if (options.json) {
      process.stdout.write(terminalSafeSerializedJson(stableJson(validation)))
    } else if (validation.valid) {
      console.log(terminalSafeText(`Valid: ${validation.path}`))
      console.log(terminalSafeText(`Root authenticity: ${validation.root_authenticity.status}`))
    } else {
      console.error(terminalSafeText(`Invalid: ${validation.path}`))
      for (const error of validation.errors) {
        console.error(terminalSafeText(`- ${error.code}: ${error.message}`))
      }
    }
    if (!validation.valid) process.exitCode = 1
    return
  }

  if (command === 'unlock') {
    const unlocked = await unlockDatabaseConformanceBundle(positionals[0])
    console.log(terminalSafeText(`Removed stale lock for PID ${unlocked.removed_pid}`))
    console.log(terminalSafeText(unlocked.warning))
    return
  }

  if (command === 'report') {
    console.log(terminalSafeText(await databaseConformanceReportPath(positionals[0])))
  }
}

if (isMainModule(import.meta.url)) {
  main().catch((error) => {
    console.error(terminalSafeText(`ERROR: ${error.message}`))
    for (const detail of error.details ?? []) {
      console.error(terminalSafeText(
        `- ${detail.code ?? detail.keyword}: ` +
        `${detail.instancePath ?? '/'} ${detail.message}`,
      ))
    }
    if (error.bundle) console.error(terminalSafeText(`Bundle: ${error.bundle}`))
    process.exitCode = 1
  })
}
