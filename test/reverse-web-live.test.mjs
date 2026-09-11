import assert from 'node:assert/strict'
import { test } from 'node:test'

import { httpAuthedCandidateIdentity } from '../scripts/lib/http-authed-campaign-ledger.mjs'
import {
  importVerifiedHttpAuthedSessionEvidence,
  importVerifiedHttpReconSessionEvidence,
} from '../scripts/lib/reverse-web-live.mjs'
import { importWebSessionEvidence } from '../scripts/lib/reverse-web-har.mjs'
import { buildNativeInteractionContract } from '../scripts/lib/reverse-protocol.mjs'

const GRANT = 'a'.repeat(64)
const BINDING = 'b'.repeat(64)

async function importReconObservation(observation) {
  return importVerifiedHttpReconSessionEvidence({
    bundle: 'C:\\staged\\recon',
    targetOrigins: ['https://target.example'],
    targetPathPrefix: '/app',
    pathLiterals: ['app', 'users'],
    dependencies: {
      readVerifiedHttpReconEvidence: async () => ({
        schema_version: '1.0.0',
        kind: 'last-aperture/verified-http-recon-evidence',
        run: { run_id: 'recon:fixture' },
        observations: [observation],
      }),
    },
  })
}

test('verified reconnaissance becomes value-free HTTP_RECON session evidence', async () => {
  const evidence = await importReconObservation({
    observed_at: '2026-09-12T12:00:00.000Z',
    method: 'GET',
    url: 'https://target.example/app/users/123?view=full',
    status_code: 200,
    response_headers: [
      { name: 'content-type', value: 'application/json' },
      { name: 'location', value: 'https://target.example/app/private-value' },
    ],
    body: { size: 128, truncated: false, digest_scope: 'complete' },
    timing_ms: { total_ms: 12.4 },
  })

  assert.equal(evidence.schema_version, '1.2.0')
  assert.equal(evidence.source.kind, 'HTTP_RECON')
  assert.equal(evidence.entries.length, 1)
  assert.equal(evidence.entries[0].request.path_template, '/app/users/{integer}')
  assert.deepEqual(evidence.entries[0].response.header_names, ['content-type', 'location'])
  assert.equal(evidence.entries[0].response.redirect, null, 'header values are not propagated')
  assert.equal(evidence.entries[0].response.body.byte_bucket, 'LE_1_KIB')
  assert.equal(evidence.entries[0].response.body.shape_status, 'NOT_OBSERVED')
  assert.deepEqual(evidence.gaps.map(({ code }) => code), ['HTTP_RECON_METADATA_ONLY'])
})

test('stop-condition truncated reconnaissance keeps response size unknown', async () => {
  const evidence = await importReconObservation({
    observed_at: '2026-09-12T12:00:00.000Z',
    method: 'GET',
    url: 'https://target.example/app/users/123',
    status_code: 302,
    response_headers: [{ name: 'location', value: '[REDACTED]' }],
    body: { size: 0, truncated: true, digest_scope: 'captured-prefix' },
    timing_ms: { total_ms: 12.4 },
    stop_condition: {
      code: 'REDIRECT',
      message: 'transport stop condition: REDIRECT',
    },
  })

  assert.equal(evidence.entries[0].response.body.byte_bucket, 'UNKNOWN')
})

test('a max-byte captured prefix does not claim the complete response size', async () => {
  const evidence = await importReconObservation({
    observed_at: '2026-09-12T12:00:00.000Z',
    method: 'GET',
    url: 'https://target.example/app/users/123',
    status_code: 200,
    response_headers: [],
    body: {
      size: 1_048_576,
      truncated: true,
      digest_scope: 'captured-prefix',
    },
    timing_ms: { total_ms: 12.4 },
    stop_condition: {
      code: 'LIMIT_REACHED',
      message: 'response body exceeded the authorized capture limit',
    },
  })

  assert.equal(evidence.entries[0].response.body.byte_bucket, 'UNKNOWN')
})

test('a complete max-byte response retains its observed size bucket', async () => {
  const evidence = await importReconObservation({
    observed_at: '2026-09-12T12:00:00.000Z',
    method: 'GET',
    url: 'https://target.example/app/users/123',
    status_code: 200,
    response_headers: [],
    body: {
      size: 1_048_576,
      truncated: false,
      digest_scope: 'complete',
    },
    timing_ms: { total_ms: 12.4 },
    stop_condition: null,
  })

  assert.equal(evidence.entries[0].response.body.byte_bucket, 'LE_1_MIB')
})

test('authenticated evidence correlates only the settled sealed-plan seed', async () => {
  const action = {
    kind: 'probe',
    sequence: 1,
    test_category: 'authenticated_surface',
    method: 'GET',
    url: 'https://target.example/app/api/items?limit=SYNTHETIC_LIMIT',
    expected_effect: 'none',
  }
  const identity = httpAuthedCandidateIdentity({
    campaignGrantSha256: GRANT,
    candidateDraft: action,
  })
  const scope = {
    authorization: { mode: 'OPERATOR_ATTESTED_AUTHED', operator_id: 'operator:fixture' },
    credential: {
      session_adapter: { carrier: { type: 'REQUEST_HEADER', name: 'authorization', prefix: 'Bearer ' } },
    },
    requests: [action],
  }
  const evidence = await importVerifiedHttpAuthedSessionEvidence({
    scopePath: 'C:\\staged\\scope.json',
    ledgerDirectory: 'C:\\staged\\ledger',
    targetOrigins: ['https://target.example'],
    targetPathPrefix: '/app',
    pathLiterals: ['app', 'api', 'items'],
    dependencies: {
      readAndVerifyHistoricalHttpAuthedAuthorization: async () => ({
        scope,
        campaignGrantSha256: GRANT,
        authorizationBindingSha256: BINDING,
      }),
      readHttpAuthedCampaignProjection: async () => ({
        schema_version: '1.0.0',
        kind: 'last-aperture/http-authed-campaign-projection',
        record_count: 8,
        head_sha256: 'c'.repeat(64),
        stopped: false,
        stop_reason: null,
        actions: [
          {
            action_id: identity.actionId,
            action_sequence: 1,
            provenance: 'SEALED_PLAN',
            phase_outcomes: { PROBE: { status: 200, request_may_have_been_sent: true } },
          },
          {
            action_id: `http-authed-action:${'d'.repeat(64)}`,
            action_sequence: 2,
            provenance: 'RESPONSE_DISCOVERY',
            phase_outcomes: { PROBE: { status: 200, request_may_have_been_sent: true } },
          },
        ],
      }),
    },
  })

  assert.equal(evidence.schema_version, '1.2.0')
  assert.equal(evidence.source.kind, 'HTTP_AUTHED_CAMPAIGN')
  assert.equal(evidence.entries.length, 1)
  assert.equal(evidence.entries[0].request.path_template, '/app/api/items')
  assert.deepEqual(evidence.entries[0].request.credential_carriers, ['header:authorization'])
  assert.equal(evidence.entries[0].response.status, 200)
  assert.deepEqual(
    evidence.gaps.map(({ code }) => code),
    ['HTTP_AUTHED_CAMPAIGN_METADATA_ONLY'],
  )
})

test('native contracts retain live source provenance without calling it HAR', () => {
  const evidence = importWebSessionEvidence([{
    request: { method: 'GET', url: 'https://target.example/app/api', headers: [], cookies: [] },
    response: { status: 200, headers: [], cookies: [], content: {} },
  }], {
    sourceKind: 'HTTP_RECON',
    sourceSha256: 'e'.repeat(64),
    targetOrigins: ['https://target.example'],
    targetPathPrefix: '/app',
    pathLiterals: ['app', 'api'],
    deriveHeaderValues: false,
  })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [evidence],
    generatedAt: '2026-09-12T12:00:00.000Z',
  })
  assert.equal(contract.schema_version, '1.2.0')
  assert.deepEqual(contract.endpoints[0].discovered_via, ['HTTP_RECON'])
  assert.equal(contract.endpoints[0].exchanges[0].provenance, 'HTTP_RECON')
  assert.equal(contract.status, 'DRAFT_OBSERVED')
  assert.equal(contract.generated_client_status, 'CONTRACT_ONLY')
})
