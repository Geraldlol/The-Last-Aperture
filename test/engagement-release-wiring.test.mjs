import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { test } from 'node:test'

import { CAPABILITY_REGISTRY, renderCapabilityDocumentation } from '../scripts/lib/capabilities.mjs'
import { PLATFORM_VERSION } from '../scripts/lib/version.mjs'

const RELEASE_VERSION = '0.15.0'

test('unified engagement command ships through the package and root CLI', () => {
  for (const path of [
    'scripts/engage.mjs',
    'scripts/lib/unleash-contracts.mjs',
    'scripts/lib/unleash-campaign-state.mjs',
    'scripts/lib/unleash-campaign-storage.mjs',
    'scripts/lib/unleash-controller.mjs',
    'scripts/lib/unleash-evidence-packet.mjs',
    'scripts/lib/unleash-policy-loader.mjs',
    'scripts/lib/unleash-policy.mjs',
    'scripts/lib/unleash-recon-evidence.mjs',
    'scripts/lib/unleash-registry.mjs',
    'scripts/lib/unleash-vulnerability.mjs',
    'docs/unleash-setup.md',
    'schemas/engagement-authority.schema.json',
    'schemas/engagement-intake.schema.json',
    'schemas/engagement-ledger-record.schema.json',
    'schemas/engagement-manifest.schema.json',
    'schemas/unleash-deployment-policy.schema.json',
    'schemas/unleash-evidence-packet.schema.json',
    'schemas/unleash-intent.schema.json',
    'schemas/unleash-plan.schema.json',
    'schemas/unleash-proposal.schema.json',
    'schemas/unleash-recon-completion-receipt.schema.json',
    'schemas/unleash-revocations.schema.json',
    'schemas/unleash-vulnerability.schema.json',
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
  assert.ok(packageDocument.files.includes('agents/'))
  assert.ok(packageDocument.files.includes('skills/'))
  assert.equal(PLATFORM_VERSION, RELEASE_VERSION)
  assert.equal(packageDocument.bin['last-aperture-engage'], './scripts/engage.mjs')
  assert.equal(packageDocument.scripts['audit:engage'], 'node scripts/engage.mjs')
  assert.match(packageDocument.scripts['test:engagement'], /test\/engage-\*\.test\.mjs/)
  assert.match(packageDocument.scripts['test:engagement'], /test\/engagement-\*\.test\.mjs/)
  assert.match(packageDocument.scripts['test:engagement'], /test\/unleash-\*\.test\.mjs/)

  const help = spawnSync(process.execPath, ['scripts/audit.mjs', 'engage', '--help'], {
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  })
  assert.equal(help.status, 0, help.stderr)
  assert.match(help.stdout, /unified engagement 0\.15\.0/i)
  assert.match(help.stdout, /engage unleash <target> \[--json\]/)
  assert.match(help.stdout, /engage run <target>/)
  assert.match(help.stdout, /engage resume <campaign-or-engagement-directory>/)

  const rootHelp = spawnSync(process.execPath, ['scripts/audit.mjs', '--help'], {
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  })
  assert.equal(rootHelp.status, 0, rootHelp.stderr)
  assert.match(rootHelp.stdout, /last-aperture engage unleash <target> \[--json\]/)
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
    'engage unleash',
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
  const generatedCapabilities = readFileSync('docs/capabilities.md', 'utf8')
  assert.match(generatedCapabilities, /`engage unleash`/)
  assert.equal(generatedCapabilities, renderCapabilityDocumentation())
})

test('public guidance exposes the target-only unleash command without intake knobs', () => {
  const readme = readFileSync('README.md', 'utf8')
  const agent = readFileSync('agents/openai.yaml', 'utf8')
  const setup = readFileSync('docs/unleash-setup.md', 'utf8')
  const skill = readFileSync('skills/last-aperture/SKILL.md', 'utf8')

  assert.match(readme, /engage unleash https:\/\/target\.example\/app/)
  assert.match(readme, /target-only/i)
  assert.match(readme, /unleash setup/i)
  assert.match(agent, /engage unleash <target>/)
  assert.match(agent, /target-only/i)
  assert.match(skill, /npm\.cmd run audit -- engage unleash <target>/)
  assert.match(
    skill,
    /controller-owned deployment policy, run storage, provider configuration, and credentials/i,
  )
  assert.match(setup, /%LOCALAPPDATA%\\LastAperture\\controller\\deployment-policy\.json/)
  assert.match(setup, /~\/\.config\/last-aperture\/controller\/deployment-policy\.json/)
  assert.match(setup, /unleash-deployment-policy\.schema\.json/)
  assert.match(setup, /unleash-revocations\.schema\.json/)
  assert.match(setup, /max_duration_ms[^\n]*900000/i)
  assert.match(setup, /max_response_bytes[^\n]*1048576/i)
})
