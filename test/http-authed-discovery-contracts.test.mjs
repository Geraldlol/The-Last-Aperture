import assert from 'node:assert/strict'
import { test } from 'node:test'

import { assertValidHttpAuthedScope } from '../scripts/lib/http-authed-contracts.mjs'
import { attestedScope } from './helpers/http-authed-fixtures.mjs'

function discoveryScope() {
  const scope = attestedScope({ actionCount: 1 })
  const actionUrl = 'https://peerstar-test.example.test/approved/seed'
  scope.authorization.authorized_scope.path_prefixes = ['/approved']
  scope.liveness.credential_preflight.url = 'https://peerstar-test.example.test/approved/whoami'
  scope.requests[0].url = actionUrl
  scope.requests[0].before_read.url = actionUrl
  scope.requests[0].after_read.url = actionUrl
  scope.requests[0].rollback.url = actionUrl
  scope.requests[0].rollback.verification_read.url = actionUrl
  scope.discovery = {
    enabled: true,
    origin: scope.target.origin,
    path_prefixes: ['/approved'],
    sources: [
      'link_header',
      'location_header',
      'allow_header',
      'html_links',
      'html_forms',
      'json_links',
      'openapi_paths',
      'sitemap_xml',
    ],
    candidate_methods: ['GET', 'HEAD', 'OPTIONS'],
    test_category: 'api_security',
    synthetic_query_values: {
      page: 'SYNTHETIC_PAGE_001',
      subject: 'SYNTHETIC_SUBJECT_001',
    },
    synthetic_path_values: {
      subject_id: 'SYNTHETIC_SUBJECT_001',
    },
    max_response_bytes: scope.limits.max_response_bytes,
  }
  return scope
}

test('sealed automated discovery is a subset of the operator-attested campaign scope', () => {
  const scope = discoveryScope()
  assert.doesNotThrow(() => assertValidHttpAuthedScope(scope))
  assert.equal('max_candidates' in scope.discovery, false)

  for (const alter of [
    (value) => { value.discovery.origin = 'https://outside.example.test' },
    (value) => { value.discovery.path_prefixes = ['/outside'] },
    (value) => { value.discovery.candidate_methods = ['SEARCH'] },
    (value) => { value.discovery.test_category = 'unwritten_category' },
    (value) => { value.discovery.max_response_bytes = value.limits.max_response_bytes + 1 },
    (value) => { value.discovery.synthetic_query_values.subject = 'real-value' },
    (value) => { value.discovery.synthetic_path_values.subject_id = 'real-value' },
  ]) {
    const changed = discoveryScope()
    alter(changed)
    assert.throws(() => assertValidHttpAuthedScope(changed))
  }
})
