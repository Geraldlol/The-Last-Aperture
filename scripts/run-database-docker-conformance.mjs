#!/usr/bin/env node

import { mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import {
  databaseConformanceReportPath,
  planDatabaseConformance,
  runDatabaseConformanceBundle,
  validateDatabaseConformanceBundle,
} from './lib/database-conformance-controller.mjs'

const runtimePath = process.env.RTA_DOCKER_RUNTIME

if (!runtimePath) {
  console.error(
    'real database conformance requires RTA_DOCKER_RUNTIME and both manifest images pre-pulled',
  )
  process.exitCode = 1
} else {
  const parent = await mkdtemp(join(tmpdir(), 'rta-database-docker-conformance-'))
  const bundle = join(parent, 'bundle')
  let succeeded = false
  try {
    await planDatabaseConformance({ out: bundle })
    const run = await runDatabaseConformanceBundle({
      bundle,
      config: {
        schema_version: '1.0.0',
        protocol: 'docker-database-lab-v1',
        runtime_path: resolve(runtimePath),
        acknowledge_local_dynamic: true,
        limits: {
          wall_time_ms: 900_000,
          docker_command_timeout_ms: 60_000,
          startup_timeout_ms: 180_000,
          memory_bytes: 1_073_741_824,
          cpus: 2,
          pids: 256,
          nofile: 1024,
          tmpfs_bytes: 536_870_912,
          max_output_bytes: 8_388_608,
        },
      },
    })
    const validation = await validateDatabaseConformanceBundle(bundle)
    if (run.state !== 'COMPLETE' || !validation.valid) {
      throw new Error(
        `database conformance gate ended ${run.state}: ` +
        validation.errors.map(({ code, message }) => `${code}: ${message}`).join('; '),
      )
    }
    console.log(`Database conformance: ${run.state}`)
    console.log(`Root: ${run.root_sha256}`)
    await databaseConformanceReportPath(bundle)
    console.log('Report artifact verified before temporary bundle cleanup')
    succeeded = true
  } finally {
    if (succeeded) {
      await rm(parent, { recursive: true, force: true })
    } else {
      console.error(`Failed database conformance bundle retained at ${bundle}`)
    }
  }
}
