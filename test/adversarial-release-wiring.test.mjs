import { readFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { test } from 'node:test'
import assert from 'node:assert/strict'

test('generic adversarial validation CLI is release-wired with its trust contracts', () => {
  for (const path of [
    'schemas/adversarial-current-scope.schema.json',
    'schemas/adversarial-controller-enrollment.schema.json',
    'scripts/adversarial.mjs',
    'scripts/lib/adversarial-campaign-ledger.mjs',
    'scripts/lib/adversarial-cli-contracts.mjs',
    'scripts/lib/adversarial-cli-controller.mjs',
    'scripts/lib/operator-authorization.mjs',
    'scripts/lib/adversarial-runtime.mjs',
    'test/adversarial-campaign-ledger.test.mjs',
    'test/adversarial-cli-contracts.test.mjs',
    'test/adversarial-cli-controller.test.mjs',
    'test/adversarial-cli.test.mjs',
    'test/operator-authorization-ingress.test.mjs',
    'test/adversarial-runtime.test.mjs',
  ]) {
    assert.ok(readFileSync(path).length > 0, `${path} must ship with the adversarial CLI`)
  }

  const packageDocument = JSON.parse(readFileSync('package.json', 'utf8'))
  assert.equal(packageDocument.bin['last-aperture-adversarial'], './scripts/adversarial.mjs')
  assert.equal(packageDocument.scripts['audit:adversarial'], 'node scripts/adversarial.mjs')
  const focusedGateEntries = new Set(packageDocument.scripts['test:adversarial'].split(/\s+/))
  for (const path of [
    'test/adversarial-campaign-ledger.test.mjs',
    'test/adversarial-cli.test.mjs',
    'test/operator-authorization-ingress.test.mjs',
    'test/adversarial-runtime.test.mjs',
  ]) {
    assert.ok(focusedGateEntries.has(path), `${path} must run in test:adversarial`)
  }

  const cli = readFileSync('scripts/adversarial.mjs', 'utf8')
  const controller = readFileSync('scripts/lib/adversarial-cli-controller.mjs', 'utf8')
  const skill = readFileSync('skills/last-aperture/SKILL.md', 'utf8')
  assert.doesNotMatch(cli, /eval\s*\(|execSync|spawnSync|child_process/)
  assert.doesNotMatch(cli, /process\.env.*CONTROLLER|--controller-root/)
  assert.match(controller, /trusted append-only campaign ledger/i)
  assert.match(skill, /public\s+L3 controller[\s\S]*append-only ledger/i)

  const help = spawnSync(process.execPath, ['scripts/adversarial.mjs', '--help'], {
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  })
  assert.equal(help.status, 0)
  assert.doesNotMatch(help.stdout, /--approval|signed approval/i)
  assert.match(help.stdout, /fixed.*controller/i)
  assert.match(help.stdout, /no command.*enroll/i)

  const enrollmentSchema = JSON.parse(
    readFileSync('schemas/adversarial-controller-enrollment.schema.json', 'utf8'),
  )
  assert.deepEqual(enrollmentSchema.required, [
    'schema_version',
    'kind',
    'enrollment_id',
    'engagement_id',
    'status',
    'scope_sha256',
    'allowed_adapters',
  ])
  assert.equal('authority_sha256' in enrollmentSchema.properties, false)
})
