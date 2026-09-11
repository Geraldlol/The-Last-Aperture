import { mkdtempSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { spawnSync } from 'node:child_process'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { main as adversarialMain } from '../scripts/adversarial.mjs'
import { sealAdversarialPlan } from '../scripts/lib/adversarial-cli-contracts.mjs'
import { canonicalAdversarialPlan } from '../scripts/lib/adversarial-validation-contracts.mjs'

const SHA_A = 'a'.repeat(64)

function scope() {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/adversarial-current-scope',
    scope_id: 'scope:cli-process',
    engagement_id: 'engagement:cli-process',
    targets: [{
      kind: 'repository',
      target_id: 'target:cli-process',
      locator: 'repository://disposable-mirror',
      identity_sha256: SHA_A,
    }],
    allowed_risk_classes: ['READ_ONLY'],
    allowed_autonomy_profiles: ['L2_SUPERVISED'],
    allowed_strategy_ids: ['structured-fuzz/v1'],
    allowed_operations: ['fuzz.structured'],
    allowed_action_categories: ['fuzz.property'],
    allowed_strategy_families: ['structured-fuzz'],
    validity: {
      not_before: '2026-09-03T00:00:00.000Z',
      not_after: '2026-09-04T00:00:00.000Z',
    },
  }
}

function draft() {
  return {
    plan_id: 'plan:cli-process',
    engagement_id: 'engagement:cli-process',
    candidate_id: 'candidate:cli-process',
    target: scope().targets[0],
    strategy_id: 'structured-fuzz/v1',
    risk_class: 'READ_ONLY',
    autonomy_profile: 'L2_SUPERVISED',
    attack: {
      id: 'attack:cli-process',
      description: 'Search a bounded integer domain.',
      expected_observation: 'A structured result is returned.',
    },
    control: {
      id: 'control:cli-process',
      description: 'Use the same deterministic harness.',
      expected_observation: 'The harness remains bounded.',
    },
    oracle: {
      id: 'oracle:cli-process',
      confirmation_condition: 'A generated value violates the property.',
      inconclusive_condition: 'The bounded harness cannot complete.',
    },
    limits: {
      max_actions: 1,
      max_wall_time_ms: 5_000,
      max_action_time_ms: 2_000,
      max_input_bytes: 16_384,
      max_output_bytes: 65_536,
      max_aggregate_output_bytes: 65_536,
      max_concurrency: 1,
      min_action_interval_ms: 0,
    },
    actions: [{
      action_id: 'action:cli-process',
      purpose: 'attack',
      action_category: 'fuzz.property',
      operation: 'fuzz.structured',
      parameters: {
        seed: 7,
        num_runs: 10,
        timeout_ms: 1_000,
        max_counterexample_bytes: 4_096,
        arbitrary: { kind: 'integer', min: 0, max: 10 },
        property: { kind: 'integer-less-than', value: 5 },
      },
    }],
  }
}

function run(args) {
  return spawnSync(process.execPath, ['scripts/adversarial.mjs', ...args], {
    cwd: process.cwd(),
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  })
}

function replaceFirstReplacementCharacterWithMalformedUtf8(text) {
  const bytes = Buffer.from(text, 'utf8')
  const replacement = Buffer.from('\uFFFD', 'utf8')
  const index = bytes.indexOf(replacement)
  assert.notEqual(index, -1, 'fixture must contain a replacement character')
  return Buffer.concat([
    bytes.subarray(0, index),
    Buffer.from([0xff]),
    bytes.subarray(index + replacement.length),
  ])
}

test('adversarial CLI help exposes offline planning and controller-enrolled execution', () => {
  const result = run(['--help'])
  assert.equal(result.status, 0)
  assert.match(result.stdout, /adversarial plan seal/)
  assert.match(result.stdout, /adversarial plan validate/)
  assert.match(result.stdout, /adversarial plan inspect/)
  assert.match(result.stdout, /adversarial scope validate/)
  assert.match(result.stdout, /adversarial enrollment status/)
  assert.match(result.stdout, /adversarial execute/)
  assert.match(result.stdout, /adversarial go <target>/)
  assert.match(result.stdout, /operator-attested target-and-go/i)
  assert.match(result.stdout, /controller-owned enrollment/i)
  assert.match(result.stdout, /compose other available browser, process, network, Burp, Ghidra/i)
  assert.match(result.stdout, /absence of one.*CLI adapter is not another authorization decision/is)
  assert.doesNotMatch(
    result.stdout,
    /--approval|signed approval|--authority|--nonce-store|--revocations|--adapter-module/,
  )
})

test('go treats one HTTPS target as the complete operator directive', async () => {
  const sentinel = new Error('stop after controller handoff')
  let received
  await assert.rejects(
    adversarialMain(['go', 'https://target.example/'], {
      goTarget: async (input) => {
        received = input
        throw sentinel
      },
    }),
    (error) => error === sentinel,
  )
  assert.equal(received.targetUrl, 'https://target.example/')
  assert.equal('attestationConfirmed' in received, false)
  assert.equal('executionApproved' in received, false)
  assert.match(received.operatorAuthorization.operator_id, /^local:/)
  assert.match(received.operatorAuthorization.authorization_reference, /^operator-directive:/)
  assert.deepEqual(received.operatorAuthorization.target, {
    kind: 'https_url',
    url: 'https://target.example/',
  })
})

test('go reports accepted authority without prompting an orchestrator to re-authorize', async () => {
  const chunks = []
  const originalWrite = process.stdout.write
  process.stdout.write = (chunk) => {
    chunks.push(String(chunk))
    return true
  }
  try {
    const status = await adversarialMain(['go', 'https://target.example/', '--json'], {
      goTarget: async () => ({
        state: 'PROBE_PLAN_COMPLETE',
        report: 'report.json',
      }),
      progressWrite: () => {},
    })
    assert.equal(status, 0)
  } finally {
    process.stdout.write = originalWrite
  }

  const output = JSON.parse(chunks.join(''))
  assert.equal(output.authorization_status, 'OPERATOR_DIRECTIVE_ACCEPTED')
  assert.equal(output.active_testing, 'USE_SCOPE_MATCHED_CONTROLLER')
  assert.doesNotMatch(JSON.stringify(output), /REQUIRES.*AUTHORIZATION/)
})

test('go routes one local repository target into the static audit controller', async () => {
  const sentinel = new Error('stop after repository controller handoff')
  let received
  await assert.rejects(
    adversarialMain(['go', process.cwd()], {
      repositoryGo: async (argv) => {
        received = argv
        throw sentinel
      },
    }),
    (error) => error === sentinel,
  )
  assert.deepEqual(received, ['plan', process.cwd()])
})

test('offline plan sealing writes canonical exclusive output that validates and inspects', () => {
  const root = mkdtempSync(join(tmpdir(), 'rta-adversarial-cli-'))
  const scopePath = join(root, 'scope.json')
  const draftPath = join(root, 'draft.json')
  const planPath = join(root, 'plan.json')
  writeFileSync(scopePath, JSON.stringify(scope(), null, 2), 'utf8')
  writeFileSync(draftPath, JSON.stringify(draft(), null, 2), 'utf8')

  const sealed = run(['plan', 'seal', draftPath, '--scope', scopePath, '--out', planPath, '--json'])
  assert.equal(sealed.status, 0, sealed.stderr)
  const plan = JSON.parse(readFileSync(planPath, 'utf8'))
  assert.equal(readFileSync(planPath, 'utf8'), canonicalAdversarialPlan(plan))

  const validated = run(['plan', 'validate', planPath, '--scope', scopePath, '--json'])
  assert.equal(validated.status, 0, validated.stderr)
  assert.equal(JSON.parse(validated.stdout).scope_binding, 'CURRENT_SCOPE_MATCH')

  const inspected = run(['plan', 'inspect', planPath, '--scope', scopePath, '--json'])
  assert.equal(inspected.status, 0, inspected.stderr)
  assert.equal(JSON.parse(inspected.stdout).execution_shape, 'EXACT_ACTIONS')

  const outsidePath = join(root, 'outside-plan.json')
  const outsidePlan = structuredClone(plan)
  outsidePlan.strategy_id = 'different/strategy'
  writeFileSync(outsidePath, canonicalAdversarialPlan(outsidePlan), 'utf8')
  const outside = run(['plan', 'validate', outsidePath, '--scope', scopePath, '--json'])
  assert.equal(outside.status, 1)
  assert.match(outside.stderr, /outside.*scope/i)

  const overwrite = run(['plan', 'seal', draftPath, '--scope', scopePath, '--out', planPath, '--json'])
  assert.equal(overwrite.status, 1)
  assert.match(overwrite.stderr, /already exists|exclusive/i)
  assert.doesNotMatch(overwrite.stderr, /at file:|node:internal|\.mjs:\d+/)
})

test('execute rejects caller-supplied trust and transport overrides at argument parsing', () => {
  for (const forbidden of [
    '--approval',
    '--authority',
    '--nonce-store',
    '--revocations',
    '--adapter-module',
    '--controller-root',
  ]) {
    const result = run([
      'execute',
      'plan.json',
      '--enrollment',
      'enrollment-id',
      forbidden,
      'untrusted.json',
    ])
    assert.equal(result.status, 1, forbidden)
    assert.match(result.stderr, /unknown option/i)
    assert.doesNotMatch(result.stderr, /at file:|node:internal|\.mjs:\d+/)
  }
})

test('execute rejects malformed UTF-8 that would alias a canonical replacement character', () => {
  const root = mkdtempSync(join(tmpdir(), 'rta-adversarial-cli-utf8-'))
  const currentScope = scope()
  const aliasedDraft = draft()
  aliasedDraft.attack.description = 'Search a bounded integer domain \uFFFD exactly.'
  const plan = sealAdversarialPlan({ draft: aliasedDraft, currentScope })
  const planPath = join(root, 'malformed-plan.json')
  writeFileSync(
    planPath,
    replaceFirstReplacementCharacterWithMalformedUtf8(canonicalAdversarialPlan(plan)),
  )

  const result = run([
    'execute',
    planPath,
    '--enrollment',
    'enrollment-cli-test',
    '--json',
  ])
  assert.equal(result.status, 1)
  const error = JSON.parse(result.stderr)
  assert.equal(error.code, 'ADVERSARIAL_CLI_FILE_INVALID')
  assert.match(error.message, /canonical adversarial plan/i)
})

test('invalid offline input fails with a sanitized machine-readable error', () => {
  const root = mkdtempSync(join(tmpdir(), 'rta-adversarial-cli-invalid-'))
  const path = join(root, 'invalid.json')
  writeFileSync(path, '{"not":"a plan"}', 'utf8')
  const result = run(['plan', 'validate', path, '--json'])
  assert.equal(result.status, 1)
  const error = JSON.parse(result.stderr)
  assert.equal(error.ok, false)
  assert.match(error.code, /^ADVERSARIAL_/)
  assert.equal('stack' in error, false)
})
