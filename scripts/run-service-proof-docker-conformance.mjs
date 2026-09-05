#!/usr/bin/env node

import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'

const runtimePath = process.env.RTA_DOCKER_RUNTIME
const image = process.env.RTA_PROOF_WORKER_IMAGE

if (!runtimePath || !image) {
  console.error(
    'real service-proof conformance requires RTA_DOCKER_RUNTIME and RTA_PROOF_WORKER_IMAGE',
  )
  process.exitCode = 1
} else {
  const result = spawnSync(
    process.execPath,
    [
      '--test',
      resolve('conformance/service-proof-docker.conformance.mjs'),
    ],
    {
      shell: false,
      windowsHide: true,
      stdio: 'inherit',
      env: process.env,
    },
  )
  if (result.error) throw result.error
  process.exitCode = result.status ?? 1
}
