import assert from 'node:assert/strict'
import { copyFile, mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'

import {
  CONTROLLER_DOCKER_RUNTIME,
  proofDependencyManifestDigest,
  runDockerServiceProofCommand,
} from '../scripts/lib/proof-docker-runner.mjs'

const runtimePath = process.env.RTA_DOCKER_RUNTIME
const image = process.env.RTA_PROOF_WORKER_IMAGE
const enabled = runtimePath !== undefined && image !== undefined
const HOST_SECRET_CANARY = 'RTA_SERVICE_PROOF_HOST_SECRET'
const PORT = 31_947

const SERVICE_SOURCE = String.raw`
import net from 'node:net'

if (process.env.RTA_SERVICE_PROOF_HOST_SECRET !== undefined) process.exit(90)
const host = process.env.RTA_SERVICE_HOST
const port = Number(process.env.RTA_SERVICE_PORT)
if (host !== '127.0.0.1' || !Number.isInteger(port)) process.exit(91)

const server = net.createServer((socket) => socket.end('rta-service-proof-ready'))
server.on('error', () => process.exit(92))
server.listen({ host, port, exclusive: true })
const stop = () => server.close(() => process.exit(0))
process.once('SIGTERM', stop)
process.once('SIGINT', stop)
`

const PROBE_SOURCE = String.raw`
import net from 'node:net'
import { appendFileSync, chmodSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'

if (process.env.RTA_SERVICE_PROOF_HOST_SECRET !== undefined) process.exit(90)
const role = process.argv[2]
const host = process.env.RTA_SERVICE_HOST
const port = Number(process.env.RTA_SERVICE_PORT)
if (!['attack', 'control'].includes(role) || host !== '127.0.0.1') process.exit(91)

const sealedService = new URL('./service.mjs', import.meta.url)
try {
  chmodSync(sealedService, 0o644)
  process.exit(94)
} catch (error) {
  if (!['EACCES', 'EPERM', 'EROFS'].includes(error?.code)) process.exit(95)
}
try {
  appendFileSync(sealedService, '// mutation must fail\n')
  process.exit(96)
} catch (error) {
  if (!['EACCES', 'EPERM', 'EROFS'].includes(error?.code)) process.exit(97)
}
writeFileSync(join(process.env.TMPDIR, role + '.state'), 'runtime scratch remains writable\n')

let body = ''
const socket = net.createConnection({ host, port })
socket.setEncoding('utf8')
socket.setTimeout(2_000, () => socket.destroy(new Error('timeout')))
socket.on('data', (chunk) => { body += chunk })
socket.on('error', () => process.exit(92))
socket.on('end', () => {
  if (body !== 'rta-service-proof-ready') process.exit(93)
  process.exit(role === 'control' ? 0 : 7)
})
`

async function fixtureSourceRoot() {
  const sourceRoot = await mkdtemp(join(tmpdir(), 'rta-service-proof-source-'))
  await mkdir(join(sourceRoot, 'fixture'))
  await Promise.all([
    copyFile(resolve('package.json'), join(sourceRoot, 'package.json')),
    copyFile(resolve('package-lock.json'), join(sourceRoot, 'package-lock.json')),
    writeFile(join(sourceRoot, 'fixture', 'service.mjs'), SERVICE_SOURCE, 'utf8'),
    writeFile(join(sourceRoot, 'fixture', 'probe.mjs'), PROBE_SOURCE, 'utf8'),
  ])
  return sourceRoot
}

test('real Docker boots two fresh loopback-only services and cleans both proof sessions', {
  skip: enabled
    ? false
    : 'use the explicit service-proof conformance launcher with an enrolled worker image',
  timeout: 180_000,
}, async () => {
  assert.equal(resolve(runtimePath), CONTROLLER_DOCKER_RUNTIME)
  const packageJson = await readFile(resolve('package.json'))
  const packageLock = await readFile(resolve('package-lock.json'))
  const sourceRoot = await fixtureSourceRoot()
  const worker = {
    schema_version: '1.0.0',
    protocol: 'docker-proof-v1',
    runtime_path: resolve(runtimePath),
    image,
    dependency_manifest_sha256: proofDependencyManifestDigest(packageJson, packageLock),
    limits: {
      wall_time_ms: 30_000,
      docker_command_timeout_ms: 30_000,
      max_source_bytes: 8_388_608,
      max_output_bytes: 8_192,
      memory_bytes: 268_435_456,
      cpus: 1,
      pids: 64,
      nofile: 256,
      tmpfs_bytes: 67_108_864,
    },
  }
  const service = {
    protocol: 'loopback-tcp-v1',
    command: { program: 'node', args: ['fixture/service.mjs'] },
    port: PORT,
    startup_timeout_ms: 10_000,
    probe_interval_ms: 100,
  }
  const limits = { timeout_ms: 5_000, max_output_bytes: 8_192 }
  const priorCanary = process.env[HOST_SECRET_CANARY]
  process.env[HOST_SECRET_CANARY] = 'must-not-cross-the-container-boundary'
  let control
  let attack
  try {
    control = await runDockerServiceProofCommand({
      config: worker,
      sourceRoot,
      service,
      program: 'node',
      args: ['fixture/probe.mjs', 'control'],
      limits,
      containerName: 'rta-proof-service-conformance-control',
    })
    attack = await runDockerServiceProofCommand({
      config: worker,
      sourceRoot,
      service,
      program: 'node',
      args: ['fixture/probe.mjs', 'attack'],
      limits,
      containerName: 'rta-proof-service-conformance-attack',
    })
  } finally {
    if (priorCanary === undefined) delete process.env[HOST_SECRET_CANARY]
    else process.env[HOST_SECRET_CANARY] = priorCanary
    await rm(sourceRoot, { recursive: true, force: true })
  }

  assert.equal(control.code, 0)
  assert.equal(attack.code, 7)
  assert.notEqual(control.sandbox.container_id, attack.sandbox.container_id)
  for (const result of [control, attack]) {
    assert.equal(result.output_omitted, true)
    assert.equal(result.sandbox.image, image)
    assert.equal(result.sandbox.network_mode, 'none')
    assert.deepEqual(result.sandbox.mounts, [])
    assert.equal(result.sandbox.cleanup_verified, true)
    assert.equal(result.sandbox.service.source_immutable, true)
    assert.match(result.sandbox.service.source_tree_sha256, /^[a-f0-9]{64}$/)
    assert.equal(result.sandbox.service.runtime_root, '/work/runtime')
    assert.deepEqual(
      {
        protocol: result.sandbox.service.protocol,
        host: result.sandbox.service.host,
        port: result.sandbox.service.port,
        pre_boot_closed: result.sandbox.service.pre_boot_closed,
        pre_probe_ready: result.sandbox.service.pre_probe_ready,
        post_probe_ready: result.sandbox.service.post_probe_ready,
        output_omitted: result.sandbox.service.output_omitted,
      },
      {
        protocol: 'loopback-tcp-v1',
        host: '127.0.0.1',
        port: PORT,
        pre_boot_closed: true,
        pre_probe_ready: true,
        post_probe_ready: true,
        output_omitted: true,
      },
    )
  }
})
