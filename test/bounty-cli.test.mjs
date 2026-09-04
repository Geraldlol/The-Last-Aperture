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
    '--user-agent', 'BugBounty-acme',
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

test('legacy authz live replay is disabled before loading caller artifacts', async () => {
  assert.equal(await runBountyCli([
    'authz',
    'run',
    'missing-bundle-that-must-not-be-opened',
    '--roles',
    'missing-registry-that-must-not-be-opened.json',
  ]), 1)
})

test('legacy crafted scan is disabled before loading caller artifacts', async () => {
  assert.equal(await runBountyCli([
    'scan',
    'run',
    'missing-bundle-that-must-not-be-opened',
    '--roles',
    'missing-roles-that-must-not-be-opened.json',
    '--as',
    'operator',
  ]), 1)
})

test('legacy passive recon is disabled before loading mutable scope artifacts', async () => {
  assert.equal(await runBountyCli([
    'recon',
    'run',
    'missing-bundle-that-must-not-be-opened',
    '--seed',
    'allowed.example',
  ]), 1)
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

// --- the cli must carry the program marker from flag to sealed bundle ---

function withoutOption(argv, name) {
  const at = argv.indexOf(name)
  if (at === -1) throw new Error(`${name} not present in argv`)
  return [...argv.slice(0, at), ...argv.slice(at + 2)]
}

test('plan seals the user agent given on the command line', async () => {
  const { dir, policyPath } = await workspace()
  try {
    assert.equal(await runBountyCli(planArgv(dir, policyPath)), 0)
    const scope = JSON.parse(await readFile(join(dir, 'ywh-acme-2026-08', 'scope.json'), 'utf8'))
    assert.equal(scope.program.required_user_agent, 'BugBounty-acme')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

// The marker is what lets the program attribute the traffic to a researcher, so
// an omitted flag is refused rather than filled in with our own tool string.
test('plan without a user agent is refused', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const argv = withoutOption(planArgv(dir, policyPath), '--user-agent')
    assert.notEqual(await runBountyCli(argv), 0)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

// --- out-of-band callbacks default to infrastructure we control ---

// The YesWeHack GCU forbids disclosing anything about a Program, System, or
// Vulnerability to a third party. A hosted interactsh server receives callback
// data straight from the target, so it cannot be the path taken by default:
// reaching a third party has to be a decision the operator types out.
test('oob open is disabled before bundle, secret, and network access', async () => {
  assert.equal(await runBountyCli([
    'oob',
    'open',
    'missing-bundle-that-must-not-be-opened',
    '--server',
    'oob.acme.example',
  ]), 1)
})

// Self-hosted needs a domain with wildcard DNS, and there is no sane default for
// that, so an operator who names no server gets a refusal rather than a silent
// fallback to somebody else's server.
test('oob open refuses before validating a server option', async () => {
  assert.equal(await runBountyCli([
    'oob',
    'open',
    'missing-bundle-that-must-not-be-opened',
  ]), 1)
})

test('hosted oob open is disabled before bundle and network access', async () => {
  assert.equal(await runBountyCli([
    'oob',
    'open',
    'missing-bundle-that-must-not-be-opened',
    '--backend',
    'hosted',
  ]), 1)
})

test('oob mint and poll are disabled before mutable session state is read', async () => {
  assert.equal(await runBountyCli([
    'oob',
    'mint',
    'missing-bundle-that-must-not-be-opened',
    '--label',
    'proof',
    '--bug-class',
    'ssrf-oob',
  ]), 1)
  assert.equal(await runBountyCli([
    'oob',
    'poll',
    'missing-bundle-that-must-not-be-opened',
  ]), 1)
  assert.equal(await runBountyCli([
    'oob',
    'status',
    'missing-bundle-that-must-not-be-opened',
  ]), 1)
  assert.equal(await runBountyCli([
    'oob',
    'close',
    'missing-bundle-that-must-not-be-opened',
  ]), 1)
})

test('every proxy capture command is disabled before bundle or query access', async () => {
  for (const action of ['ingest', 'flows', 'to-authz']) {
    assert.equal(await runBountyCli([
      'proxy',
      action,
      'missing-bundle-that-must-not-be-opened',
      ...(action === 'flows' ? ['--where', "1 UNION SELECT 'escape'"] : []),
      ...(action === 'to-authz' ? ['--owner-role', 'owner'] : []),
    ]), 1, action)
  }
})

// A bundle sealed before the marker was mandated must stay inspectable. The
// design already says so for a lapsed grant -- "the evidence outlives the
// authorization, and refusing to open it would make past findings unreadable" --
// and a schema field added later is the same situation: enforcement belongs on
// the commands that contact a target, which now refuse on their own.
async function legacyBundle() {
  const { dir, policyPath } = await workspace()
  assert.equal(await runBountyCli(planArgv(dir, policyPath)), 0)
  const bundle = join(dir, 'ywh-acme-2026-08')
  const scopePath = join(bundle, 'scope.json')
  const scope = JSON.parse(await readFile(scopePath, 'utf8'))
  delete scope.program.required_user_agent
  const scopeText = `${JSON.stringify(scope, null, 2)}\n`
  await writeFile(scopePath, scopeText, 'utf8')
  // Reseal the manifest digest: this is an old bundle, not a tampered one.
  const { createHash } = await import('node:crypto')
  const manifestPath = join(bundle, 'bundle.json')
  const manifest = JSON.parse(await readFile(manifestPath, 'utf8'))
  manifest.scope_sha256 = createHash('sha256').update(Buffer.from(scopeText, 'utf8')).digest('hex')
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
  return { dir, bundle, policyPath }
}

test('a bundle sealed before the user-agent mandate stays inspectable', async () => {
  const { dir, bundle, policyPath } = await legacyBundle()
  try {
    assert.equal(
      await runBountyCli(['validate', bundle]),
      0,
      'validate must open a pre-mandate bundle rather than refusing to read it',
    )
    assert.equal(
      await runBountyCli(['revalidate', bundle, '--policy-file', policyPath]),
      0,
      'revalidate must still compare the policy snapshot',
    )
    assert.equal(
      await runBountyCli(['scope', bundle, '--check', 'https://api.acme.example/']),
      0,
      'the perimeter must stay inspectable',
    )
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('validate names the remedy for a pre-mandate bundle instead of an ajv dump', async () => {
  const { dir, bundle } = await legacyBundle()
  const lines = []
  const write = process.stdout.write.bind(process.stdout)
  process.stdout.write = (chunk, ...rest) => { lines.push(String(chunk)); return write(chunk, ...rest) }
  try {
    await runBountyCli(['validate', bundle])
  } finally {
    process.stdout.write = write
    await rm(dir, { recursive: true, force: true })
  }
  const output = lines.join('')
  assert.match(output, /--user-agent/, 'the operator is told how to fix it')
  assert.equal(
    /failed schema validation/.test(output),
    false,
    'not a raw schema dump',
  )
})
