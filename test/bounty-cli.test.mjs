import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { runBountyCli } from '../scripts/bounty.mjs'

async function workspace() {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-cli-'))
  const policyPath = join(dir, 'policy.txt')
  await writeFile(policyPath, 'ACME policy. Scope: *.acme.example\n', 'utf8')
  return { dir, policyPath }
}

// The CLI stamps attested_at from the ambient clock and now refuses to seal a
// window that does not contain it, so this window must follow real time. A fixed
// window would pass until its end date and then fail forever -- exactly the time
// bomb removed from http-authed-credential.
function relativeWindow(reference = new Date()) {
  const HOUR = 60 * 60 * 1000
  const at = (offsetMs) => new Date(reference.getTime() + offsetMs).toISOString()
  return { notBefore: at(-HOUR), notAfter: at(90 * 24 * HOUR) }
}

function planArgv(dir, policyPath, window = relativeWindow()) {
  return [
    'plan',
    '--platform', 'yeswehack',
    '--program', 'acme-public',
    '--engagement-id', 'ywh-acme-2026-08',
    '--policy-url', 'https://yeswehack.com/programs/acme-public',
    '--policy-file', policyPath,
    '--operator-id', 'operator-1',
    '--authorized-by', 'ACME via YesWeHack program policy',
    '--allow', '*.acme.example',
    '--deny', 'legacy.acme.example',
    '--rate-limit-rps', '5',
    '--not-before', window.notBefore,
    '--not-after', window.notAfter,
    '--attest-enrolled',
    '--out', dir,
  ]
}

test('plan then validate then scope check via the cli', async () => {
  const { dir, policyPath } = await workspace()
  try {
    assert.equal(await runBountyCli(planArgv(dir, policyPath)), 0)
    const bundle = join(dir, 'ywh-acme-2026-08')
    assert.equal(await runBountyCli(['validate', bundle]), 0)
    assert.equal(await runBountyCli(['scope', bundle, '--check', 'https://www.acme.example/']), 0)
    assert.equal(await runBountyCli(['scope', bundle, '--check', 'https://evil.example/']), 2)
    assert.equal(await runBountyCli(['revalidate', bundle, '--policy-file', policyPath]), 0)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('plan without the attestation flag is refused', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const argv = planArgv(dir, policyPath).filter((token) => token !== '--attest-enrolled')
    assert.equal(await runBountyCli(argv), 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('seals ham intensity when active testing and automation are granted', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const argv = [
      ...planArgv(dir, policyPath),
      '--active-testing',
      '--automation',
      '--intensity', 'ham',
    ]
    assert.equal(await runBountyCli(argv), 0)
    const scope = JSON.parse(
      await readFile(join(dir, 'ywh-acme-2026-08', 'scope.json'), 'utf8'),
    )
    assert.equal(scope.authorization.permissions.intensity, 'ham')
    assert.equal(scope.authorization.permissions.automation_allowed, true)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('refuses ham intensity without automation', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const argv = [...planArgv(dir, policyPath), '--active-testing', '--intensity', 'ham']
    assert.equal(await runBountyCli(argv), 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('ham intensity does not widen the sealed perimeter', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const argv = [
      ...planArgv(dir, policyPath),
      '--active-testing',
      '--automation',
      '--intensity', 'ham',
    ]
    assert.equal(await runBountyCli(argv), 0)
    const bundle = join(dir, 'ywh-acme-2026-08')
    assert.equal(await runBountyCli(['scope', bundle, '--check', 'https://evil.example/']), 2)
    assert.equal(await runBountyCli(['scope', bundle, '--check', 'http://127.0.0.1/']), 2)
    assert.equal(await runBountyCli(['scope', bundle, '--check', 'https://legacy.acme.example/']), 2)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('an unknown command is refused', async () => {
  assert.equal(await runBountyCli(['definitely-not-a-command']), 1)
})

test('help exits zero', async () => {
  assert.equal(await runBountyCli(['--help']), 0)
})

test('revalidate exits nonzero on policy drift', async () => {
  const { dir, policyPath } = await workspace()
  try {
    await runBountyCli(planArgv(dir, policyPath))
    await writeFile(policyPath, 'ACME policy. Scope: acme.example only\n', 'utf8')
    const bundle = join(dir, 'ywh-acme-2026-08')
    assert.equal(await runBountyCli(['revalidate', bundle, '--policy-file', policyPath]), 1)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
