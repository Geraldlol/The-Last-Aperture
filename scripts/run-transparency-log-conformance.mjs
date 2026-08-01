#!/usr/bin/env node

import { spawnSync } from 'node:child_process'
import { resolve } from 'node:path'

const result = spawnSync(
  process.execPath,
  ['--test', resolve('test/reference-transparency-log-conformance.test.mjs')],
  {
    shell: false,
    windowsHide: true,
    stdio: 'inherit',
    env: process.env,
  },
)
if (result.error) throw result.error
process.exitCode = result.status ?? 1
