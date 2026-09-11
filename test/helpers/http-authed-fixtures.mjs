import {
  OPERATOR_ATTESTED_AUTHED_STATEMENT,
} from '../../scripts/lib/http-authed-contracts.mjs'

export function attestedScope({ actionCount = 128 } = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-authed-scope',
    engagement_id: 'example-authorized-assessment',
    environment: 'production',
    data_class: 'phi',
    authorization: {
      mode: 'OPERATOR_ATTESTED_AUTHED',
      authorization_id: 'operator-attestation-2026-08-16',
      statement: OPERATOR_ATTESTED_AUTHED_STATEMENT,
      operator_id: 'example-security-operator',
      authorized_by: 'engagement operator',
      authorization_reference: 'Operator-held engagement authorization reference 2026-08-16',
      attested_at: '2026-08-16T12:00:00.000Z',
      independently_verified: false,
      permissions: {
        active_testing: true,
        production: true,
        third_party: true,
        phi: true,
        mutation: true,
      },
      authorized_scope: {
        origins: ['https://app.example.test'],
        path_prefixes: ['/'],
        methods: ['HEAD', 'GET', 'OPTIONS', 'POST', 'PUT', 'PATCH', 'DELETE'],
        test_categories: [
          'authentication',
          'authorization',
          'session_management',
          'input_validation',
          'business_logic',
          'api_security',
        ],
      },
    },
    credential: {
      ref: 'env:SYNTHETIC_TEST_CREDENTIAL',
      kind: 'bearer',
      binding_sha256: '1'.repeat(64),
    },
    evidence_handling: {
      persist_request_bodies: false,
      persist_response_bodies: false,
      persist_credential_values: false,
      persist_header_values: false,
      stop_on_sensitive_data: true,
      test_data: 'synthetic_only',
    },
    liveness: {
      credential_preflight: {
        method: 'GET',
        url: 'https://app.example.test/whoami',
      },
    },
    target: {
      origin: 'https://app.example.test',
      ownership: 'third_party_owned',
      tls: { mode: 'PKIX_HOSTNAME' },
    },
    validity: {
      not_before: '2026-08-16T11:59:00.000Z',
      not_after: '2026-08-16T12:04:00.000Z',
      cleanup_not_after: '2026-08-16T12:04:00.000Z',
    },
    limits: {
      request_timeout_ms: 10_000,
      max_response_bytes: 65_536,
      min_interval_ms: 1_000,
      concurrency: 1,
    },
    stop_conditions: [
      'AUTHORIZATION_WITHDRAWN',
      'EMERGENCY_STOP_REQUESTED',
      'AUTHORIZATION_WINDOW_CLOSED',
      'TARGET_IDENTITY_CHANGED',
      'LIMIT_REACHED',
      'UNEXPECTED_SIDE_EFFECT',
      'VERIFICATION_MISMATCH',
      'ROLLBACK_REQUIRED',
      'CREDENTIAL_INVALID',
    ],
    requests: Array.from({ length: actionCount }, (_unused, index) => {
      const sequence = index + 1
      const url = `https://app.example.test/security-test-resource/${sequence}`
      return {
        kind: 'mutate',
        sequence,
        test_category: 'api_security',
        method: 'POST',
        url,
        success_statuses: [200, 201, 204],
        request_body: {
          body_id: `SYNTHETIC_SECURITY_TEST_PAYLOAD_${sequence}`,
          sha256: '4'.repeat(64),
          byte_length: 64,
          content_type: 'application/json',
          data_class: 'synthetic_non_phi',
        },
        expected_mutation: {
          resource_ref: `SYNTHETIC_SECURITY_TEST_RECORD_${sequence}`,
          field: '/synthetic_marker',
          representation: 'CANONICAL_JSON_VALUE_SHA256',
          before_digest: '2'.repeat(64),
          after_digest: '3'.repeat(64),
        },
        before_read: {
          method: 'GET',
          url,
          expected_statuses: [200],
          observation: { format: 'JSON', json_pointer: '/synthetic_marker' },
        },
        after_read: {
          method: 'GET',
          url,
          expected_statuses: [200],
          observation: { format: 'JSON', json_pointer: '/synthetic_marker' },
        },
        rollback: {
          method: 'PATCH',
          url,
          expected_after_digest: '2'.repeat(64),
          idempotent_restore: true,
          success_statuses: [200],
          request_body: {
            body_id: `SYNTHETIC_SECURITY_TEST_ROLLBACK_${sequence}`,
            sha256: '5'.repeat(64),
            byte_length: 64,
            content_type: 'application/json',
            data_class: 'synthetic_non_phi',
          },
          verification_read: {
            method: 'GET',
            url,
            expected_statuses: [200],
            observation: { format: 'JSON', json_pointer: '/synthetic_marker' },
          },
        },
        rollback_policy: 'ALWAYS',
      }
    }),
  }
}
