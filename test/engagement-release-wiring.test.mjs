import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { test } from 'node:test'

import { CAPABILITY_REGISTRY, renderCapabilityDocumentation } from '../scripts/lib/capabilities.mjs'
import { PLATFORM_VERSION } from '../scripts/lib/version.mjs'

const RELEASE_VERSION = '0.14.1'

test('unified engagement command ships through the package and root CLI', () => {
  for (const path of [
    'scripts/engage.mjs',
    'schemas/engagement-authority.schema.json',
    'schemas/engagement-intake.schema.json',
    'schemas/engagement-ledger-record.schema.json',
    'schemas/engagement-manifest.schema.json',
  ]) {
    assert.equal(existsSync(path), true, `${path} must ship`)
    assert.ok(readFileSync(path).length > 0, `${path} must not be empty`)
  }

  const packageDocument = JSON.parse(readFileSync('package.json', 'utf8'))
  const lockDocument = JSON.parse(readFileSync('package-lock.json', 'utf8'))
  const shrinkwrapDocument = JSON.parse(readFileSync('npm-shrinkwrap.json', 'utf8'))
  assert.equal(packageDocument.version, RELEASE_VERSION)
  assert.equal(lockDocument.version, RELEASE_VERSION)
  assert.equal(lockDocument.packages[''].version, RELEASE_VERSION)
  assert.deepEqual(shrinkwrapDocument, lockDocument)
  assert.ok(packageDocument.files.includes('npm-shrinkwrap.json'))
  assert.equal(PLATFORM_VERSION, RELEASE_VERSION)
  assert.equal(packageDocument.bin['last-aperture-engage'], './scripts/engage.mjs')
  assert.equal(packageDocument.scripts['audit:engage'], 'node scripts/engage.mjs')
  assert.match(packageDocument.scripts['test:engagement'], /test\/engage-\*\.test\.mjs/)
  assert.match(packageDocument.scripts['test:engagement'], /test\/engagement-\*\.test\.mjs/)

  const help = spawnSync(process.execPath, ['scripts/audit.mjs', 'engage', '--help'], {
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  })
  assert.equal(help.status, 0, help.stderr)
  assert.match(help.stdout, /unified engagement 0\.14\.1/i)
  assert.match(help.stdout, /engage run <target>/)
  assert.match(help.stdout, /engage resume <engagement-directory>/)

  const rootHelp = spawnSync(process.execPath, ['scripts/audit.mjs', '--help'], {
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  })
  assert.equal(rootHelp.status, 0, rootHelp.stderr)
  assert.match(rootHelp.stdout, /last-aperture engage run <target>/)
})

test('the installed root CLI exposes every controller family used by unified engagements', () => {
  const commands = [
    ['http-recon', /authorized HTTP reconnaissance/i],
    ['http-authed', /authenticated HTTP campaigns/i],
    ['reverse', /reverse engineering/i],
    ['adversarial', /adversarial validation/i],
    ['bounty', /bounty-v1 program perimeter/i],
    ['acquire', /evidence acquisition/i],
    ['database-conformance', /database conformance/i],
  ]
  for (const [command, expected] of commands) {
    const help = spawnSync(process.execPath, ['scripts/audit.mjs', command, '--help'], {
      encoding: 'utf8',
      shell: false,
      windowsHide: true,
    })
    assert.equal(help.status, 0, `${command}: ${help.stderr}`)
    assert.match(help.stdout, expected, command)
  }
})

test('capability registry declares bounded engagement orchestration exactly', () => {
  const byId = new Map(CAPABILITY_REGISTRY.capabilities.map((item) => [item.id, item]))
  const engagement = byId.get('engagement-orchestration')
  assert.equal(engagement?.status, 'AVAILABLE_NARROW')
  assert.deepEqual(engagement?.commands, [
    'engage run',
    'engage resume',
    'engage status',
    'engage stop',
    'engage work next',
    'engage work status',
    'engage work submit',
    'engage work finalize',
    'engage work validate',
  ])
  assert.match(engagement.description, /durable.*target-neutral.*registered routes/i)
  assert.match(engagement.limitation, /shipped registered routes/i)

  const generic = byId.get('generic-live')
  assert.equal(generic?.status, 'UNAVAILABLE')
  assert.deepEqual(generic?.commands, [])
  assert.match(generic.description, /unbounded|arbitrary/i)
  assert.deepEqual(byId.get('https-recon')?.commands, ['last-aperture http-recon go'])
  assert.deepEqual(byId.get('authenticated-http')?.commands, [
    'last-aperture http-authed campaign-attested',
    'last-aperture http-authed campaign-stop',
  ])
  assert.deepEqual(byId.get('browser-execution')?.commands, [
    'last-aperture http-authed campaign-attested',
  ])
  assert.equal(readFileSync('docs/capabilities.md', 'utf8'), renderCapabilityDocumentation())
})
