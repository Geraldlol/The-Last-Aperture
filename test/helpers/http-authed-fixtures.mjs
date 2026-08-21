import { generateKeyPairSync } from 'node:crypto'
import {
  sha256Hex,
  WRITTEN_AUTHORIZATION_AUTHED_STATEMENT,
} from '../../scripts/lib/http-authed-contracts.mjs'

export const AUTHORIZATION_DOCUMENT = Buffer.from('synthetic authorization fixture')

function approver() {
  const { publicKey } = generateKeyPairSync('ed25519')
  const der = publicKey.export({ type: 'spki', format: 'der' })
  return {
    mechanism: 'ed25519_file',
    key_id: `ed25519:${sha256Hex(der)}`,
    public_key: {
      format: 'spki_der_b64',
      value_base64: der.toString('base64'),
    },
    enrollment: {
      enrolled_by: 'Peerstar security lead',
      enrolled_at: '2026-04-15T12:00:00.000Z',
      provenance: 'Peerstar internal approver enrollment for the written vendor authorization',
    },
  }
}

export function writtenScope({ actionCount = 128 } = {}) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/http-authed-scope',
    engagement_id: 'peerstar-credible-authorized-assessment',
    environment: 'production',
    data_class: 'phi',
    authorization: {
      mode: 'WRITTEN_AUTHORIZATION_AUTHED',
      authorization_id: 'credible-april-2026-authorization',
      statement: WRITTEN_AUTHORIZATION_AUTHED_STATEMENT,
      operator_id: 'peerstar-security-operator',
      authorized_by: 'Credible/Qualifacts security',
      authorization_reference: 'Credible/Qualifacts written authorization, April 2026',
      attested_at: '2026-08-16T12:00:00.000Z',
      independently_verified: false,
      written_authorization_sha256: sha256Hex(AUTHORIZATION_DOCUMENT),
      document_issuer: 'Credible/Qualifacts security',
      document_issued_at: '2026-04-15T12:00:00.000Z',
      permissions: {
        active_testing: true,
        production: true,
        third_party: true,
        phi: true,
        mutation: true,
      },
      authorized_scope: {
        origins: ['https://peerstar-test.example.test'],
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
    approver: approver(),
    liveness: {
      credential_preflight: {
        method: 'GET',
        url: 'https://peerstar-test.example.test/whoami',
      },
    },
    target: {
      origin: 'https://peerstar-test.example.test',
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
      const url = `https://peerstar-test.example.test/security-test-resource/${sequence}`
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
        requires_countersignature: true,
      }
    }),
  }
}
