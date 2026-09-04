import assert from 'node:assert/strict'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import {
  checkBountyScope,
  planBountyBundle,
  revalidateBountyBundle,
  validateBountyBundle,
} from '../scripts/lib/bounty-controller.mjs'

const NOW = new Date('2026-08-20T12:00:00.000Z')
const POLICY = 'ACME program policy. Scope: *.acme.example\n'

async function workspace() {
  const dir = await mkdtemp(join(tmpdir(), 'bounty-controller-'))
  const policyPath = join(dir, 'policy.txt')
  await writeFile(policyPath, POLICY, 'utf8')
  return { dir, policyPath }
}

function planOptions(dir, policyPath) {
  return {
    outParent: dir,
    policyPath,
    engagementId: 'ywh-acme-2026-08',
    platform: 'yeswehack',
    programHandle: 'acme-public',
    policyUrl: 'https://yeswehack.com/programs/acme-public',
    operatorId: 'operator-1',
    authorizedBy: 'ACME via YesWeHack program policy',
    requiredUserAgent: 'BugBounty-acme',
    allowSpecs: ['*.acme.example'],
    denySpecs: ['legacy.acme.example'],
    permissions: {
      active_testing: true,
      production: true,
      third_party: false,
      mutation: false,
      automation_allowed: true,
      intensity: 'normal',
      desync_probes: false,
      rate_limit_rps: 5,
    },
    validity: { notBefore: '2026-08-20T00:00:00.000Z', notAfter: '2026-11-20T00:00:00.000Z' },
    now: NOW,
  }
}

test('plan writes a bundle that validates', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const planned = await planBountyBundle(planOptions(dir, policyPath))
    const validated = await validateBountyBundle(planned.bundlePath)
    assert.equal(validated.status, 'VALID')
    assert.equal(validated.scope.program.program_handle, 'acme-public')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('validate detects a tampered scope file', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const planned = await planBountyBundle(planOptions(dir, policyPath))
    const scopePath = join(planned.bundlePath, 'scope.json')
    const scope = JSON.parse(await readFile(scopePath, 'utf8'))
    scope.scope_rules.allow.push({ rule_id: 'injected', host_kind: 'wildcard', host: 'evil.example' })
    await writeFile(scopePath, JSON.stringify(scope, null, 2), 'utf8')
    await assert.rejects(() => validateBountyBundle(planned.bundlePath), /digest/)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('revalidate reports UNCHANGED for the sealed policy', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const planned = await planBountyBundle(planOptions(dir, policyPath))
    const result = await revalidateBountyBundle(planned.bundlePath, policyPath)
    assert.equal(result.status, 'UNCHANGED')
    assert.equal(result.sealed, result.observed)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('revalidate reports DRIFTED when the program changes its policy', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const planned = await planBountyBundle(planOptions(dir, policyPath))
    await writeFile(policyPath, 'ACME policy. Scope: acme.example only\n', 'utf8')
    const result = await revalidateBountyBundle(planned.bundlePath, policyPath)
    assert.equal(result.status, 'DRIFTED')
    assert.notEqual(result.sealed, result.observed)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('scope check answers from the sealed bundle', async () => {
  const { dir, policyPath } = await workspace()
  try {
    const planned = await planBountyBundle(planOptions(dir, policyPath))
    const allowed = await checkBountyScope(planned.bundlePath, 'https://www.acme.example/x')
    assert.equal(allowed.decision, 'ALLOW')
    const denied = await checkBountyScope(planned.bundlePath, 'https://legacy.acme.example/')
    assert.equal(denied.decision, 'DENY')
    assert.equal(denied.rule_id, 'deny-1')
    const unlisted = await checkBountyScope(planned.bundlePath, 'https://other.example/')
    assert.equal(unlisted.reason, 'candidate-unlisted')
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})

test('plan refuses to overwrite an existing bundle', async () => {
  const { dir, policyPath } = await workspace()
  try {
    await planBountyBundle(planOptions(dir, policyPath))
    await assert.rejects(() => planBountyBundle(planOptions(dir, policyPath)), /exists/)
  } finally {
    await rm(dir, { recursive: true, force: true })
  }
})
