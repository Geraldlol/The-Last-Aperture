import assert from 'node:assert/strict'
import { access, mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'
import { digestAdversarialPlan } from '../scripts/lib/adversarial-validation-contracts.mjs'
import { digestPolicySnapshot } from '../scripts/lib/bounty-contracts.mjs'
import { normalizeCapturedRequest } from '../scripts/lib/bounty-authz-request.mjs'
import { ANONYMOUS_ROLE } from '../scripts/lib/bounty-authz-roles.mjs'
import { resolveIntensityProfile } from '../scripts/lib/bounty-intensity.mjs'
import {
  buildBountyScanPlan,
  classifyBountyScanTarget,
} from '../scripts/lib/bounty-scan-plan.mjs'
import { runScan, scanStatus } from '../scripts/lib/bounty-scan-controller.mjs'
import { openOobSession } from '../scripts/lib/bounty-oob-controller.mjs'
import {
  OPERATOR_AUTHORIZATION_KIND,
  OPERATOR_AUTHORIZATION_STATUS,
  OPERATOR_CAMPAIGN_AUTHORIZATION_STATEMENT,
  verifyBoundOperatorAuthorization,
} from '../scripts/lib/operator-authorization.mjs'

const NOW = new Date('2026-08-21T12:00:00.000Z')
const REGISTRY = { roles: [] }

function scope({ activeTesting = true, intensity = 'normal', mutation = false } = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/bounty-scope',
    engagement_id: 'engagement-live-scan-001',
    platform: 'direct',
    environment: 'non_production',
    data_class: 'non_phi',
    authorization: {
      mode: 'PROGRAM_POLICY_SEALED',
      authorization_id: 'engagement-live-scan-001-auth',
      statement: 'Synthetic live-scan authorization for controller tests.',
      operator_id: 'operator-test',
      authorized_by: 'test engagement owner',
      authorization_reference: 'https://policy.example.test/scope',
      attested_at: '2026-08-21T00:00:00.000Z',
      independently_verified: false,
      permissions: {
        rate_limit_rps: 100,
        active_testing: activeTesting,
        production: false,
        third_party: false,
        phi: false,
        mutation,
        automation_allowed: true,
        intensity,
        desync_probes: false,
      },
    },
    validity: {
      not_before: '2026-08-21T00:00:00.000Z',
      not_after: '2026-08-22T00:00:00.000Z',
    },
    program: {
      program_handle: 'test-program',
      policy_url: 'https://policy.example.test/scope',
      policy_snapshot_sha256: 'a'.repeat(64),
      required_user_agent: 'BugBounty-acme',
    },
    scope_rules: {
      allow: [{
        rule_id: 'allow-live-scan',
        host_kind: 'exact',
        host: 'api.example.test',
        ports: [443],
      }],
      deny: [],
      private_targets_sealed: false,
    },
    stop_conditions: { max_findings: 10, operator_stop: false },
  }
}

function request(query = 'widget') {
  return normalizeCapturedRequest({
    request_id: 'request:search-001',
    method: 'GET',
    url: `https://api.example.test/search?q=${query}`,
    headers: { accept: 'application/json' },
    owner_role: 'alice',
  })
}

async function workspace(t, sealedScope = scope()) {
  const directory = await mkdtemp(join(tmpdir(), 'bounty-scan-authorization-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  await sealScope(directory, sealedScope)
  return directory
}

async function sealScope(directory, sealedScope) {
  const scopeText = `${JSON.stringify(sealedScope, null, 2)}\n`
  await writeFile(join(directory, 'scope.json'), scopeText)
  await writeFile(join(directory, 'bundle.json'), `${JSON.stringify({
    kind: 'red-team-audit/bounty-bundle',
    schema_version: '1.0.0',
    engagement_id: sealedScope.engagement_id,
    scope_sha256: digestPolicySnapshot(scopeText),
    created_at: sealedScope.authorization.attested_at,
  }, null, 2)}\n`)
}

function authorizationReceiptFor(plan) {
  return verifyBoundOperatorAuthorization({
    value: {
      schema_version: '1.0.0',
      kind: OPERATOR_AUTHORIZATION_KIND,
      status: OPERATOR_AUTHORIZATION_STATUS,
      operator_id: 'operator:scan-owner',
      authorization_reference: 'authorization:live-bounty-scan-001',
      statement: OPERATOR_CAMPAIGN_AUTHORIZATION_STATEMENT,
      declared_at: '2026-08-21T11:59:00.000Z',
      target: structuredClone(plan.target),
      plan_sha256: digestAdversarialPlan(plan),
      scope_revision_sha256: plan.scope_revision_sha256,
    },
    planSha256: digestAdversarialPlan(plan),
    scopeRevisionSha256: plan.scope_revision_sha256,
    target: plan.target,
    now: NOW,
    fail(code, message) {
      const error = new Error(message)
      error.code = code
      throw error
    },
  })
}

function fakeResponse() {
  return new Response('{"ok":true}', {
    status: 200,
    headers: { 'content-type': 'application/json' },
  })
}

test('a live crafted scan without an exact operator authorization receipt performs zero target I/O', async (t) => {
  const directory = await workspace(t)
  let sends = 0

  await assert.rejects(
    () => runScan({
      bundlePath: directory,
      requests: [request()],
      registry: REGISTRY,
      now: NOW,
      classes: ['error-injection'],
      fetchImpl: async () => { sends += 1; return fakeResponse() },
      sleep: async () => {},
      clock: () => 0,
    }),
    /operator authorization receipt|authorization.*required/i,
  )

  assert.equal(sends, 0)
  await assert.rejects(() => access(join(directory, 'scan-findings.json')))
})

test('a live crafted scan requires the exact operator authorization statement', async (t) => {
  const sealedScope = scope()
  const directory = await workspace(t, sealedScope)
  const requests = [request()]
  const plan = buildBountyScanPlan({
    scope: sealedScope,
    requests,
    classes: ['error-injection'],
    role: ANONYMOUS_ROLE,
    profile: resolveIntensityProfile(sealedScope),
  })
  const operatorAuthorizationReceipt = {
    ...authorizationReceiptFor(plan),
    statement: 'I generally authorize security testing.',
  }
  let sends = 0

  await assert.rejects(
    () => runScan({
      bundlePath: directory,
      requests,
      registry: REGISTRY,
      now: NOW,
      classes: ['error-injection'],
      operatorAuthorizationReceipt,
      isAuthorizationRevoked: async () => false,
      isOperatorStopRequested: async () => false,
      fetchImpl: async () => { sends += 1; return fakeResponse() },
      sleep: async () => {},
      clock: () => 0,
    }),
    /operator authorization.*statement/i,
  )

  assert.equal(sends, 0)
})

test('operator authorization bound to a different exact plan refuses before target I/O', async (t) => {
  const sealedScope = scope()
  const directory = await workspace(t, sealedScope)
  const approvedRequest = request('approved')
  const approvedPlan = buildBountyScanPlan({
    scope: sealedScope,
    requests: [approvedRequest],
    classes: ['error-injection'],
    role: ANONYMOUS_ROLE,
    profile: resolveIntensityProfile(sealedScope),
  })
  const operatorAuthorizationReceipt = authorizationReceiptFor(approvedPlan)
  let sends = 0

  await assert.rejects(
    () => runScan({
      bundlePath: directory,
      requests: [request('drifted')],
      registry: REGISTRY,
      now: NOW,
      classes: ['error-injection'],
      operatorAuthorizationReceipt,
      isAuthorizationRevoked: async () => false,
      isOperatorStopRequested: async () => false,
      fetchImpl: async () => { sends += 1; return fakeResponse() },
      sleep: async () => {},
      clock: () => 0,
    }),
    /plan.*drift|exact.*plan/i,
  )

  assert.equal(sends, 0)
})

test('operator authorization bound to an earlier scope revision refuses before target I/O', async (t) => {
  const approvedScope = scope()
  const currentScope = structuredClone(approvedScope)
  currentScope.authorization.permissions.rate_limit_rps = 99
  const directory = await workspace(t, currentScope)
  const requests = [request()]
  const approvedPlan = buildBountyScanPlan({
    scope: approvedScope,
    requests,
    classes: ['error-injection'],
    role: ANONYMOUS_ROLE,
    profile: resolveIntensityProfile(approvedScope),
  })
  const operatorAuthorizationReceipt = authorizationReceiptFor(approvedPlan)
  let sends = 0

  await assert.rejects(
    () => runScan({
      bundlePath: directory,
      requests,
      registry: REGISTRY,
      now: NOW,
      classes: ['error-injection'],
      operatorAuthorizationReceipt,
      isAuthorizationRevoked: async () => false,
      isOperatorStopRequested: async () => false,
      fetchImpl: async () => { sends += 1; return fakeResponse() },
      sleep: async () => {},
      clock: () => 0,
    }),
    /plan.*drift|exact.*plan/i,
  )

  assert.equal(sends, 0)
})

test('an exact operator statement is normalized and rechecked before every live send', async (t) => {
  const sealedScope = scope()
  const directory = await workspace(t, sealedScope)
  const requests = [request()]
  const plan = buildBountyScanPlan({
    scope: sealedScope,
    requests,
    classes: ['error-injection'],
    role: ANONYMOUS_ROLE,
    profile: resolveIntensityProfile(sealedScope),
  })
  const operatorAuthorizationReceipt = authorizationReceiptFor(plan)
  let stopChecks = 0
  let revocationChecks = 0
  let sends = 0

  const summary = await runScan({
    bundlePath: directory,
    requests,
    registry: REGISTRY,
    now: NOW,
    classes: ['error-injection'],
    operatorAuthorizationReceipt,
    isOperatorStopRequested: async (receipt) => {
      stopChecks += 1
      assert.equal(receipt.status, 'CONTROLLER_VERIFIED')
      assert.equal(receipt.plan_sha256, digestAdversarialPlan(plan))
      return false
    },
    isAuthorizationRevoked: async (receipt) => {
      revocationChecks += 1
      assert.equal(receipt.authorization_id, operatorAuthorizationReceipt.authorization_reference)
      assert.equal(receipt.authorization_sha256, operatorAuthorizationReceipt.authorization_sha256)
      return false
    },
    fetchImpl: async () => {
      assert.ok(stopChecks > sends, 'operator stop must be checked before transport dispatch')
      assert.ok(revocationChecks > sends, 'revocation must be checked before transport dispatch')
      sends += 1
      return fakeResponse()
    },
    sleep: async () => {},
    clock: () => 0,
  })

  assert.ok(sends > 0)
  assert.equal(stopChecks, sends)
  assert.equal(revocationChecks, sends)
  assert.equal(summary.adversarialValidation.status, 'CONTROLLER_VERIFIED')
  const findings = JSON.parse(await readFile(join(directory, 'scan-findings.json'), 'utf8'))
  assert.equal(findings.adversarial_validation.plan_sha256, digestAdversarialPlan(plan))
  assert.equal(
    findings.adversarial_validation.authorization_id,
    operatorAuthorizationReceipt.authorization_reference,
  )
  assert.equal(
    findings.adversarial_validation.authorization_sha256,
    operatorAuthorizationReceipt.authorization_sha256,
  )
  assert.equal(
    findings.adversarial_validation.authority_basis,
    'OPERATOR_DECLARATION_ACCEPTED_AS_FACT',
  )
  assert.doesNotMatch(
    JSON.stringify(findings.adversarial_validation),
    /signature|nonce|public_key|approval/i,
  )
  const status = await scanStatus({ bundlePath: directory })
  assert.equal(status.adversarialValidation.plan_sha256, digestAdversarialPlan(plan))
})

test('passive-only analysis is operator-authorization-free and performs zero network I/O', async (t) => {
  const directory = await workspace(t)
  let sends = 0
  const summary = await runScan({
    bundlePath: directory,
    requests: [request()],
    registry: REGISTRY,
    now: NOW,
    classes: ['passive'],
    fetchImpl: async () => { sends += 1; return fakeResponse() },
    sleep: async () => {},
    clock: () => 0,
  })

  assert.equal(sends, 0)
  assert.equal(summary.adversarialValidation, null)
  assert.equal(summary.passive.status, 'NOTHING_OBSERVED')
  await assert.rejects(() => access(join(directory, 'scan-ledger')))
})

test('live scan preserves the mutation proof and cleanup boundary before target I/O', async (t) => {
  const directory = await workspace(t, scope({ mutation: true }))
  const stateChanging = request()
  stateChanging.method = 'POST'
  let sends = 0

  await assert.rejects(
    () => runScan({
      bundlePath: directory,
      requests: [stateChanging],
      registry: REGISTRY,
      now: NOW,
      classes: ['passive'],
      fetchImpl: async () => { sends += 1; return fakeResponse() },
      sleep: async () => {},
      clock: () => 0,
    }),
    /state-changing.*mutation campaign|use the mutation campaign/i,
  )
  assert.equal(sends, 0)
})

test('a live scan refuses a modified sealed scope before target I/O', async (t) => {
  const sealedScope = scope()
  const directory = await workspace(t, sealedScope)
  const modified = structuredClone(sealedScope)
  modified.authorization.permissions.rate_limit_rps = 99
  await writeFile(join(directory, 'scope.json'), `${JSON.stringify(modified, null, 2)}\n`)
  let sends = 0

  await assert.rejects(
    () => runScan({
      bundlePath: directory,
      requests: [request()],
      registry: REGISTRY,
      now: NOW,
      classes: ['error-injection'],
      fetchImpl: async () => { sends += 1; return fakeResponse() },
      sleep: async () => {},
      clock: () => 0,
    }),
    /sealed scope digest mismatch|modified after sealing/i,
  )
  assert.equal(sends, 0)
})

test('literal loopback is local_service but still requires exact operator authorization before I/O', async (t) => {
  const sealedScope = scope()
  sealedScope.scope_rules.allow = [{
    rule_id: 'allow-loopback',
    host_kind: 'ip',
    host: '127.0.0.1',
    ports: [8080],
  }]
  sealedScope.scope_rules.private_targets_sealed = true
  const directory = await workspace(t, sealedScope)
  const requests = [normalizeCapturedRequest({
    request_id: 'request:loopback-001',
    method: 'GET',
    url: 'http://127.0.0.1:8080/search?q=x',
    headers: { accept: 'application/json' },
  })]
  assert.equal(classifyBountyScanTarget(requests), 'local_service')
  let sends = 0

  await assert.rejects(
    () => runScan({
      bundlePath: directory,
      requests,
      registry: REGISTRY,
      now: NOW,
      classes: ['error-injection'],
      fetchImpl: async () => { sends += 1; return fakeResponse() },
      sleep: async () => {},
      clock: () => 0,
    }),
    /operator authorization receipt|authorization.*required/i,
  )
  assert.equal(sends, 0)
})

test('a production tunnel hostname is live and requires exact operator authorization before I/O', async (t) => {
  const sealedScope = scope()
  sealedScope.scope_rules.allow = [{
    rule_id: 'allow-production-tunnel',
    host_kind: 'exact',
    host: 'audit-edge.example.test',
    ports: [443],
  }]
  const directory = await workspace(t, sealedScope)
  const requests = [normalizeCapturedRequest({
    request_id: 'request:tunnel-001',
    method: 'GET',
    url: 'https://audit-edge.example.test/search?q=x',
    headers: { accept: 'application/json' },
  })]
  assert.equal(classifyBountyScanTarget(requests), 'live')
  let sends = 0

  await assert.rejects(
    () => runScan({
      bundlePath: directory,
      requests,
      registry: REGISTRY,
      now: NOW,
      classes: ['error-injection'],
      fetchImpl: async () => { sends += 1; return fakeResponse() },
      sleep: async () => {},
      clock: () => 0,
    }),
    /operator authorization receipt|authorization.*required/i,
  )
  assert.equal(sends, 0)
})

test('a newly sealed scope revision is loaded and rejected immediately before the next send', async (t) => {
  const sealedScope = scope()
  const directory = await workspace(t, sealedScope)
  const requests = [request()]
  const plan = buildBountyScanPlan({
    scope: sealedScope,
    requests,
    classes: ['error-injection'],
    role: ANONYMOUS_ROLE,
    profile: resolveIntensityProfile(sealedScope),
  })
  const operatorAuthorizationReceipt = authorizationReceiptFor(plan)
  let revocationChecks = 0
  let sends = 0

  await assert.rejects(
    () => runScan({
      bundlePath: directory,
      requests,
      registry: REGISTRY,
      now: NOW,
      classes: ['error-injection'],
      operatorAuthorizationReceipt,
      isOperatorStopRequested: async () => false,
      isAuthorizationRevoked: async () => {
        revocationChecks += 1
        if (revocationChecks === 2) {
          const successor = structuredClone(sealedScope)
          successor.authorization.permissions.rate_limit_rps = 99
          await sealScope(directory, successor)
        }
        return false
      },
      fetchImpl: async () => { sends += 1; return fakeResponse() },
      sleep: async () => {},
      clock: () => 0,
    }),
    /current scope.*plan|scope revision.*drift|exact.*scope/i,
  )

  assert.equal(sends, 1)
})

test('every authorized send is durably qualified and settled in a hash-linked ledger', async (t) => {
  const sealedScope = scope()
  const directory = await workspace(t, sealedScope)
  const requests = [request()]
  const plan = buildBountyScanPlan({
    scope: sealedScope,
    requests,
    classes: ['error-injection'],
    role: ANONYMOUS_ROLE,
    profile: resolveIntensityProfile(sealedScope),
  })
  const operatorAuthorizationReceipt = authorizationReceiptFor(plan)
  let sends = 0

  const summary = await runScan({
    bundlePath: directory,
    requests,
    registry: REGISTRY,
    now: NOW,
    classes: ['error-injection'],
    operatorAuthorizationReceipt,
    isOperatorStopRequested: async () => false,
    isAuthorizationRevoked: async () => false,
    fetchImpl: async () => { sends += 1; return fakeResponse() },
    sleep: async () => {},
    clock: () => 0,
  })

  const recordNames = (await readdir(join(directory, 'scan-ledger'))).sort()
  const records = await Promise.all(recordNames.map(async (name) =>
    JSON.parse(await readFile(join(directory, 'scan-ledger', name), 'utf8'))))
  const qualifications = records.filter(({ event }) => event.type === 'SEND_QUALIFIED')
  const settlements = records.filter(({ event }) => event.type === 'SEND_SETTLED')
  assert.equal(qualifications.length, sends)
  assert.equal(settlements.length, sends)
  assert.ok(sends > 0)
  assert.equal(records[0].previous_sha256, '0'.repeat(64))
  assert.ok(records.slice(1).every((record) => /^[a-f0-9]{64}$/.test(record.previous_sha256)))
  assert.deepEqual(
    settlements.map(({ event }) => event.action_sha256),
    qualifications.map(({ event }) => event.action_sha256),
  )
  assert.equal(summary.scanLedger.status, 'SETTLED')
  assert.equal(summary.scanLedger.qualified_sends, sends)
  assert.equal(summary.scanLedger.settled_sends, sends)
})

test('an unmatched durable send qualification is outcome-uncertain and cannot be replayed', async (t) => {
  const sealedScope = scope()
  const directory = await workspace(t, sealedScope)
  const requests = [request()]
  const plan = buildBountyScanPlan({
    scope: sealedScope,
    requests,
    classes: ['error-injection'],
    role: ANONYMOUS_ROLE,
    profile: resolveIntensityProfile(sealedScope),
  })
  const operatorAuthorizationReceipt = authorizationReceiptFor(plan)
  let sends = 0
  const common = {
    bundlePath: directory,
    requests,
    registry: REGISTRY,
    now: NOW,
    classes: ['error-injection'],
    operatorAuthorizationReceipt,
    isOperatorStopRequested: async () => false,
    isAuthorizationRevoked: async () => false,
    fetchImpl: async () => { sends += 1; return fakeResponse() },
    sleep: async () => {},
    clock: () => 0,
  }

  await assert.rejects(
    () => runScan({
      ...common,
      ledgerHooks: {
        afterQualified() {
          throw new Error('simulated process loss after durable qualification')
        },
      },
    }),
    /simulated process loss/i,
  )
  assert.equal(sends, 0)
  const recordsAfterCrash = await readdir(join(directory, 'scan-ledger'))
  assert.equal(recordsAfterCrash.length, 1)

  await assert.rejects(
    () => runScan(common),
    /outcome is uncertain|unsettled.*cannot be replayed/i,
  )
  assert.equal(sends, 0)
})

test('a settled prefix without terminal completion requires reconciliation and is never replayed', async (t) => {
  const sealedScope = scope()
  const directory = await workspace(t, sealedScope)
  const requests = [request()]
  const plan = buildBountyScanPlan({
    scope: sealedScope,
    requests,
    classes: ['error-injection'],
    role: ANONYMOUS_ROLE,
    profile: resolveIntensityProfile(sealedScope),
  })
  const operatorAuthorizationReceipt = authorizationReceiptFor(plan)
  let stopChecks = 0
  let sends = 0
  const common = {
    bundlePath: directory,
    requests,
    registry: REGISTRY,
    now: NOW,
    classes: ['error-injection'],
    operatorAuthorizationReceipt,
    isOperatorStopRequested: async () => {
      stopChecks += 1
      return stopChecks > 1
    },
    isAuthorizationRevoked: async () => false,
    fetchImpl: async () => { sends += 1; return fakeResponse() },
    sleep: async () => {},
    clock: () => 0,
  }

  await assert.rejects(() => runScan(common), /stopped by the operator/i)
  assert.equal(sends, 1)
  const checksAfterInterruptedRun = stopChecks

  await assert.rejects(
    () => runScan(common),
    /settled sends.*new operator-authorized plan|partial.*reconciliation/i,
  )
  assert.equal(sends, 1)
  assert.equal(stopChecks, checksAfterInterruptedRun, 'partial-ledger refusal must precede live gates')
})

test('a live operator authorization receipt stops authorizing sends when its window expires', async (t) => {
  const sealedScope = scope()
  sealedScope.validity.not_after = '2026-08-23T12:00:00.000Z'
  const directory = await workspace(t, sealedScope)
  const requests = [request()]
  const plan = buildBountyScanPlan({
    scope: sealedScope,
    requests,
    classes: ['error-injection'],
    role: ANONYMOUS_ROLE,
    profile: resolveIntensityProfile(sealedScope),
  })
  const operatorAuthorizationReceipt = authorizationReceiptFor(plan)
  let sends = 0

  await assert.rejects(
    () => runScan({
      bundlePath: directory,
      requests,
      registry: REGISTRY,
      now: new Date('2026-08-22T12:05:00.000Z'),
      classes: ['error-injection'],
      operatorAuthorizationReceipt,
      isAuthorizationRevoked: async () => false,
      isOperatorStopRequested: async () => false,
      fetchImpl: async () => { sends += 1; return fakeResponse() },
      sleep: async () => {},
      clock: () => 0,
    }),
    /authorization.*outside.*execution window/i,
  )
  assert.equal(sends, 0)
})

test('plan wall-time is rechecked after pacing and before operator-authorized dispatch', async (t) => {
  const sealedScope = scope()
  sealedScope.validity.not_after = '2026-08-23T12:00:00.000Z'
  const directory = await workspace(t, sealedScope)
  const requests = [request()]
  const plan = buildBountyScanPlan({
    scope: sealedScope,
    requests,
    classes: ['error-injection'],
    role: ANONYMOUS_ROLE,
    profile: resolveIntensityProfile(sealedScope),
  })
  const operatorAuthorizationReceipt = authorizationReceiptFor(plan)
  let elapsed = 0
  let sends = 0

  await assert.rejects(
    () => runScan({
      bundlePath: directory,
      requests,
      registry: REGISTRY,
      now: NOW,
      classes: ['error-injection'],
      operatorAuthorizationReceipt,
      isAuthorizationRevoked: async () => false,
      isOperatorStopRequested: async () => false,
      fetchImpl: async () => { sends += 1; return fakeResponse() },
      sleep: async () => { elapsed = (24 * 60 * 60 * 1000) + (5 * 60 * 1000) },
      clock: () => elapsed,
    }),
    /authorized wall-time budget/i,
  )
  assert.equal(sends, 1, 'pacing cannot carry an authorized action past its plan budget')
})

test('the current operator authorization is rechecked for revocation before every send', async (t) => {
  const sealedScope = scope()
  const directory = await workspace(t, sealedScope)
  const requests = [request()]
  const plan = buildBountyScanPlan({
    scope: sealedScope,
    requests,
    classes: ['error-injection'],
    role: ANONYMOUS_ROLE,
    profile: resolveIntensityProfile(sealedScope),
  })
  const operatorAuthorizationReceipt = authorizationReceiptFor(plan)
  let checks = 0
  let sends = 0

  await assert.rejects(
    () => runScan({
      bundlePath: directory,
      requests,
      registry: REGISTRY,
      now: NOW,
      classes: ['error-injection'],
      operatorAuthorizationReceipt,
      isOperatorStopRequested: async () => false,
      isAuthorizationRevoked: async () => {
        checks += 1
        return checks > 1
      },
      fetchImpl: async () => { sends += 1; return fakeResponse() },
      sleep: async () => {},
      clock: () => 0,
    }),
    /authorization.*revoked|revoked.*authorization/i,
  )
  assert.equal(checks, 2)
  assert.equal(sends, 1)
})

test('the current operator-stop callback can halt a live scan before its next send', async (t) => {
  const sealedScope = scope()
  const directory = await workspace(t, sealedScope)
  const requests = [request()]
  const plan = buildBountyScanPlan({
    scope: sealedScope,
    requests,
    classes: ['error-injection'],
    role: ANONYMOUS_ROLE,
    profile: resolveIntensityProfile(sealedScope),
  })
  const operatorAuthorizationReceipt = authorizationReceiptFor(plan)
  let stopChecks = 0
  let revocationChecks = 0
  let sends = 0

  await assert.rejects(
    () => runScan({
      bundlePath: directory,
      requests,
      registry: REGISTRY,
      now: NOW,
      classes: ['error-injection'],
      operatorAuthorizationReceipt,
      isOperatorStopRequested: async () => {
        stopChecks += 1
        return stopChecks > 1
      },
      isAuthorizationRevoked: async () => {
        revocationChecks += 1
        return false
      },
      fetchImpl: async () => { sends += 1; return fakeResponse() },
      sleep: async () => {},
      clock: () => 0,
    }),
    /stopped by the operator/i,
  )

  assert.equal(stopChecks, 2)
  assert.equal(revocationChecks, 1)
  assert.equal(sends, 1)
})

test('an SSRF adapter cannot substitute an unapproved runtime callback host', async (t) => {
  const sealedScope = scope({ intensity: 'aggressive' })
  const directory = await workspace(t, sealedScope)
  const session = await openOobSession({
    bundlePath: directory,
    backend: 'self_hosted',
    server: 'oob.test.example',
    now: NOW,
    fetchImpl: async () => { throw new Error('self-hosted setup must not use network') },
  })
  const oobBinding = {
    backend: session.backend,
    server: session.server,
    correlation_id: session.correlation_id,
    created_at: session.created_at,
  }
  const requests = [normalizeCapturedRequest({
    request_id: 'request:ssrf-001',
    method: 'GET',
    url: 'https://api.example.test/fetch?url=https://cdn.example.test/a.png',
    headers: { accept: 'application/json' },
    owner_role: 'alice',
  })]
  const plan = buildBountyScanPlan({
    scope: sealedScope,
    requests,
    classes: ['ssrf-oob'],
    role: ANONYMOUS_ROLE,
    profile: resolveIntensityProfile(sealedScope),
    oobBinding,
  })
  const operatorAuthorizationReceipt = authorizationReceiptFor(plan)
  let sends = 0

  await assert.rejects(
    () => runScan({
      bundlePath: directory,
      requests,
      registry: REGISTRY,
      now: NOW,
      classes: ['ssrf-oob'],
      operatorAuthorizationReceipt,
      isAuthorizationRevoked: async () => false,
      isOperatorStopRequested: async () => false,
      oob: {
        mint: async () => ({
          host: 'unapproved-callback.example',
          nonce: 'a'.repeat(13),
          backend: 'self_hosted',
        }),
        collect: async () => [],
      },
      fetchImpl: async () => { sends += 1; return fakeResponse() },
      sleep: async () => {},
      clock: () => 0,
    }),
    /OOB.*plan|callback.*drift|unapproved.*callback/i,
  )
  assert.equal(sends, 2, 'only the two approved baselines may precede OOB host validation')
})

test('an SSRF adapter cannot smuggle URL authority syntax through its nonce', async (t) => {
  const sealedScope = scope({ intensity: 'aggressive' })
  const directory = await workspace(t, sealedScope)
  const session = await openOobSession({
    bundlePath: directory,
    backend: 'self_hosted',
    server: 'oob.test.example',
    now: NOW,
    fetchImpl: async () => { throw new Error('self-hosted setup must not use network') },
  })
  const oobBinding = {
    backend: session.backend,
    server: session.server,
    correlation_id: session.correlation_id,
    created_at: session.created_at,
  }
  const requests = [normalizeCapturedRequest({
    request_id: 'request:ssrf-001',
    method: 'GET',
    url: 'https://api.example.test/fetch?url=https://cdn.example.test/a.png',
    headers: { accept: 'application/json' },
    owner_role: 'alice',
  })]
  const plan = buildBountyScanPlan({
    scope: sealedScope,
    requests,
    classes: ['ssrf-oob'],
    role: ANONYMOUS_ROLE,
    profile: resolveIntensityProfile(sealedScope),
    oobBinding,
  })
  const operatorAuthorizationReceipt = authorizationReceiptFor(plan)
  const maliciousNonce = '@2130706433/x'
  let sends = 0

  await assert.rejects(
    () => runScan({
      bundlePath: directory,
      requests,
      registry: REGISTRY,
      now: NOW,
      classes: ['ssrf-oob'],
      operatorAuthorizationReceipt,
      isAuthorizationRevoked: async () => false,
      isOperatorStopRequested: async () => false,
      oob: {
        mint: async () => ({
          host: `${session.correlation_id}${maliciousNonce}.${session.server}`,
          nonce: maliciousNonce,
          backend: 'self_hosted',
        }),
        collect: async () => [],
      },
      fetchImpl: async () => { sends += 1; return fakeResponse() },
      sleep: async () => {},
      clock: () => 0,
    }),
    /OOB.*nonce|nonce.*invalid/i,
  )
  assert.equal(sends, 2)
})
