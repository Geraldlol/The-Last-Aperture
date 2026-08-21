import assert from 'node:assert/strict'
import { resolve } from 'node:path'
import { test } from 'node:test'

import {
  actionId,
  assertValidHttpAuthedScope,
  buildActionCountersignaturePayload,
  httpAuthedCampaignLedgerBindingSha256,
} from '../scripts/lib/http-authed-contracts.mjs'
import { writtenScope } from './helpers/http-authed-fixtures.mjs'

function mutationAction() {
  return structuredClone(writtenScope({ actionCount: 1 }).requests[0])
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

test('countersignature payload binds the full candidate and campaign grant', () => {
  const action = mutationAction()
  const campaignGrantSha256 = '8'.repeat(64)
  const campaignLedgerSha256 = httpAuthedCampaignLedgerBindingSha256(
    resolve('synthetic-campaign-ledger'),
  )
  const payload = buildActionCountersignaturePayload({
    action,
    planSha256: campaignGrantSha256,
    campaignLedgerSha256,
    nonce: 'synthetic-nonce-0001',
    at: '2026-08-16T12:00:00.000Z',
  })
  assert.match(payload.candidate_sha256, /^[a-f0-9]{64}$/)
  assert.equal(payload.plan_sha256, campaignGrantSha256)
  assert.equal(payload.campaign_ledger_sha256, campaignLedgerSha256)
  const changed = structuredClone(action)
  changed.request_body.sha256 = '9'.repeat(64)
  const changedPayload = buildActionCountersignaturePayload({
    action: changed,
    planSha256: campaignGrantSha256,
    campaignLedgerSha256,
    nonce: 'synthetic-nonce-0001',
    at: '2026-08-16T12:00:00.000Z',
  })
  assert.notEqual(changedPayload.candidate_sha256, payload.candidate_sha256)
  assert.notEqual(
    httpAuthedCampaignLedgerBindingSha256(resolve('synthetic-other-campaign-ledger')),
    campaignLedgerSha256,
  )
})

test('declared mutation requires exact JSON observation and always rollback', () => {
  const scope = writtenScope({ actionCount: 1 })
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
    const changed = writtenScope({ actionCount: 1 })
    alter(changed.requests[0])
    assert.throws(() => assertValidHttpAuthedScope(changed))
  }
})
