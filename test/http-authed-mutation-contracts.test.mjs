import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { test } from 'node:test'

import * as httpAuthedContracts from '../scripts/lib/http-authed-contracts.mjs'
import { attestedScope } from './helpers/http-authed-fixtures.mjs'

const {
  actionId,
  assertValidHttpAuthedScope,
  httpAuthedCampaignLedgerBindingSha256,
} = httpAuthedContracts

function mutationAction() {
  return structuredClone(attestedScope({ actionCount: 1 }).requests[0])
}

test('mutation identity binds every behavior-bearing action field', () => {
  const original = mutationAction()
  const variants = [
    (action) => { action.test_category = 'business_logic' },
    (action) => { action.request_body.sha256 = '5'.repeat(64) },
    (action) => { action.before_read.url += '?synthetic=before' },
    (action) => { action.after_read.url += '?synthetic=after' },
    (action) => { action.expected_mutation.after_digest = '6'.repeat(64) },
    (action) => { action.rollback.method = 'DELETE' },
    (action) => { action.rollback.request_body.sha256 = '7'.repeat(64) },
    (action) => { action.rollback.verification_read.url += '?synthetic=verify' },
  ]
  const originalId = actionId(original)
  for (const mutate of variants) {
    const changed = structuredClone(original)
    mutate(changed)
    assert.notEqual(actionId(changed), originalId)
  }

  const resequenced = structuredClone(original)
  resequenced.sequence = 999_999
  assert.equal(actionId(resequenced), originalId)
})

test('mutation contracts expose no countersigning surface and keep ledger identity directory-bound', () => {
  assert.equal(Object.hasOwn(httpAuthedContracts, 'buildActionCountersignaturePayload'), false)
  assert.equal(Object.hasOwn(httpAuthedContracts, 'signHttpAuthedActionCountersignature'), false)
  assert.equal(Object.hasOwn(httpAuthedContracts, 'verifyHttpAuthedActionCountersignature'), false)

  const campaignLedgerSha256 = httpAuthedCampaignLedgerBindingSha256(
    resolve('synthetic-campaign-ledger'),
  )
  assert.match(campaignLedgerSha256, /^[a-f0-9]{64}$/)
  assert.notEqual(
    httpAuthedCampaignLedgerBindingSha256(resolve('synthetic-other-campaign-ledger')),
    campaignLedgerSha256,
  )

  const scopeWithLegacyApprover = attestedScope({ actionCount: 1 })
  scopeWithLegacyApprover.approver = { mechanism: 'ed25519_file' }
  assert.throws(() => assertValidHttpAuthedScope(scopeWithLegacyApprover))

  const actionWithLegacyRequirement = attestedScope({ actionCount: 1 })
  actionWithLegacyRequirement.requests[0].requires_countersignature = true
  assert.throws(() => assertValidHttpAuthedScope(actionWithLegacyRequirement))
})

test('declared mutation requires exact JSON observation and always rollback', () => {
  const scope = attestedScope({ actionCount: 1 })
  assert.doesNotThrow(() => assertValidHttpAuthedScope(scope))

  for (const alter of [
    (action) => { action.expected_mutation.field = 'synthetic_marker' },
    (action) => { delete action.rollback_policy },
    (action) => { delete action.rollback.idempotent_restore },
    (action) => { delete action.success_statuses },
    (action) => { delete action.before_read.expected_statuses },
    (action) => { delete action.after_read.observation },
    (action) => { delete action.rollback.success_statuses },
    (action) => { delete action.rollback.verification_read },
    (action) => { action.rollback.expected_after_digest = 'a'.repeat(64) },
    (action) => { action.after_read.observation.json_pointer = '/different' },
  ]) {
    const changed = attestedScope({ actionCount: 1 })
    alter(changed.requests[0])
    assert.throws(() => assertValidHttpAuthedScope(changed))
  }
})
