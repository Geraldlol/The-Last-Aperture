import { readFileSync } from 'node:fs'
import { test } from 'node:test'
import assert from 'node:assert/strict'

test('release wiring exposes adaptive authenticated campaigns through the controller', () => {
  const source = readFileSync('scripts/http-authed.mjs', 'utf8')
  const regression = readFileSync('test/http-authed-live-cli-disabled.test.mjs', 'utf8')
  const runtime = readFileSync('scripts/lib/http-authed-campaign-runtime.mjs', 'utf8')
  assert.doesNotMatch(source, /HTTP_AUTHED_LIVE_IO_DISABLED/)
  for (const command of ['campaign-attested']) {
    assert.match(source, new RegExp(`['"]${command}['"]`), command)
    assert.match(regression, new RegExp(`['"]${command}['"]`), command)
  }
  assert.match(source, /fixedCampaignOnly: false/)
  assert.doesNotMatch(source, /campaign-written|authorization-document|approver-public-key|countersignature/i)
  assert.match(source, /sealed adaptive[\s\S]*response-derived discovery/i)
  assert.match(runtime, /HTTP_AUTHED_PUBLIC_DISCOVERY_REQUIRES_ADAPTIVE_CONTROLLER/)
  assert.match(runtime, /MAX_PUBLIC_FIXED_CAMPAIGN_ACTIONS/)
})
