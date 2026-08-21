import assert from 'node:assert/strict'
import test from 'node:test'
import {
  analyzeCrossOriginJavaScriptAst,
  createHttpReconResponseObservationDescriptor,
  observeCredibleBundleSources,
  observeCredibleCrossOriginJavaScript,
  resolveHttpReconResponseObservation,
  validateHttpReconResponseObservationHeaders,
} from '../scripts/lib/http-recon-response-observations.mjs'

const URL = 'https://www.cbh3.crediblebh.com/secure/index.aspx'
const MAX = 1024 * 1024

function descriptor(overrides = {}) {
  return createHttpReconResponseObservationDescriptor({
    profile: 'credible-bundle-src-v1',
    method: 'GET',
    url: URL,
    maxResponseBytes: MAX,
    ...overrides,
  })
}

function observe(html, overrides = {}) {
  const sealed = overrides.descriptor ?? descriptor()
  return observeCredibleBundleSources({
    descriptor: sealed,
    method: 'GET',
    url: URL,
    maxResponseBytes: MAX,
    body: Buffer.from(html, 'utf8'),
    ...overrides,
    descriptor: sealed,
  })
}

test('credible bundle-src descriptor seals the exact method, origin, and byte ceiling', () => {
  const sealed = descriptor()
  assert.deepEqual(Object.keys(sealed).sort(), [
    'profile',
    'profile_binding_sha256',
  ])
  assert.match(sealed.profile_binding_sha256, /^[a-f0-9]{64}$/u)
  assert.equal(
    resolveHttpReconResponseObservation({
      descriptor: sealed,
      method: 'GET',
      url: URL,
      maxResponseBytes: MAX,
    }).origin,
    'https://www.cbh3.crediblebh.com',
  )

  for (const input of [
    { method: 'HEAD' },
    { url: 'https://assets.cbh3.crediblebh.com/index.html' },
    { url: 'https://www.cbh3.crediblebh.com.evil.invalid/index.html' },
    { maxResponseBytes: MAX + 1 },
  ]) {
    assert.throws(() => descriptor(input), /method, origin, or byte boundary/iu)
  }

  const forged = { ...sealed, profile_binding_sha256: '0'.repeat(64) }
  assert.throws(
    () => resolveHttpReconResponseObservation({
      descriptor: forged,
      method: 'GET',
      url: URL,
      maxResponseBytes: MAX,
    }),
    /does not match/iu,
  )
})

test('credible bundle-src headers require complete identity-encoded HTTP 200 HTML', () => {
  const sealed = descriptor()
  assert.equal(validateHttpReconResponseObservationHeaders({
    descriptor: sealed,
    method: 'GET',
    url: URL,
    maxResponseBytes: MAX,
    status: 200,
    contentTypes: ['text/html; charset=UTF-8'],
    contentEncodings: [],
  }), true)
  assert.equal(validateHttpReconResponseObservationHeaders({
    descriptor: sealed,
    method: 'GET',
    url: URL,
    maxResponseBytes: MAX,
    status: 200,
    contentTypes: ['text/html'],
    contentEncodings: ['identity'],
  }), true)

  for (const input of [
    { status: 204, contentTypes: ['text/html'], contentEncodings: [] },
    { status: 200, contentTypes: [], contentEncodings: [] },
    { status: 200, contentTypes: ['application/xhtml+xml'], contentEncodings: [] },
    { status: 200, contentTypes: ['text/html; charset=windows-1252'], contentEncodings: [] },
    { status: 200, contentTypes: ['text/html'], contentEncodings: ['gzip'] },
    { status: 200, contentTypes: ['text/html'], contentEncodings: ['identity', 'identity'] },
  ]) {
    assert.throws(() => validateHttpReconResponseObservationHeaders({
      descriptor: sealed,
      method: 'GET',
      url: URL,
      maxResponseBytes: MAX,
      ...input,
    }), /response-observation profile/iu)
  }
})

test('credible bundle-src observer emits only sorted unique same-origin paths', () => {
  const result = observe(`<!doctype html>
    <!-- <script src="/assets/bundle-19990101_0000.js"></script> -->
    <script nonce="never-persist" src="/assets/bundle-20260513_1516.js"></script>
    <script src='https://www.cbh3.crediblebh.com/assets/bundle-20260818_0915.js'
      data-secret="never-persist"></script>
    <script src="/assets/bundle-20260513_1516.js"></script>
    <script src="/assets/ordinary.js">const secret = 'never-persist';</script>`)

  assert.deepEqual(result, {
    profile: 'credible-bundle-src-v1',
    profile_binding_sha256: descriptor().profile_binding_sha256,
    bundle_paths: [
      '/assets/bundle-20260513_1516.js',
      '/assets/bundle-20260818_0915.js',
    ],
  })
  const durable = JSON.stringify(result)
  assert.doesNotMatch(durable, /nonce|data-secret|ordinary|never-persist/iu)
})

test('credible bundle-src observer rejects malformed, encoded, and ambiguous candidates without echoing values', () => {
  const unsafe = [
    '<script src="/assets/bundle-20260513_1516.js?token=never-persist"></script>',
    '<script src="https://evil.invalid/assets/bundle-20260513_1516.js"></script>',
    '<script src="/assets/bundle-20260513_1516.js" src="/assets/bundle-20260818_0915.js"></script>',
    '<script src="/assets/bundle-20260513_1516.js">',
    [1, 2, 3, 4, 5]
      .map((value) => `<script src="/assets/bundle-20260818_000${value}.js"></script>`)
      .join(''),
  ]
  for (const html of unsafe) {
    assert.throws(
      () => observe(html),
      (error) => {
        assert.match(error.code, /^HTTP_RECON_RESPONSE_OBSERVATION_/u)
        assert.doesNotMatch(String(error.message), /never-persist|evil\.invalid|20260513/iu)
        return true
      },
    )
  }

  assert.throws(
    () => observeCredibleBundleSources({
      descriptor: descriptor(),
      method: 'GET',
      url: URL,
      maxResponseBytes: MAX,
      body: Buffer.from([0xc3, 0x28]),
    }),
    /valid UTF-8/iu,
  )
})

const CROSS_ORIGIN_MESSAGING_URL =
  'https://assets.cbh3.crediblebh.com/js/cross-origin-messaging.js'
const GLOBAL_CROSS_ORIGIN_HELPERS_URL =
  'https://assets.cbh3.crediblebh.com/js/global-cross-origin-helpers.js'

function crossOriginDescriptor(url = CROSS_ORIGIN_MESSAGING_URL) {
  return createHttpReconResponseObservationDescriptor({
    profile: 'credible-cross-origin-js-ast-v1',
    method: 'GET',
    url,
    maxResponseBytes: MAX,
  })
}

test('cross-origin AST descriptor is restricted to two digest-pinned asset URLs', () => {
  const first = crossOriginDescriptor()
  const second = crossOriginDescriptor(GLOBAL_CROSS_ORIGIN_HELPERS_URL)
  assert.deepEqual(first, second)
  assert.equal(
    resolveHttpReconResponseObservation({
      descriptor: first,
      method: 'GET',
      url: CROSS_ORIGIN_MESSAGING_URL,
      maxResponseBytes: MAX,
    }).artifacts.length,
    2,
  )

  for (const input of [
    { method: 'HEAD' },
    { url: 'https://assets.cbh3.crediblebh.com/js/other.js' },
    { url: `${CROSS_ORIGIN_MESSAGING_URL}?cache=1` },
    { url: 'https://assets.cbh3.crediblebh.com.evil.invalid/js/cross-origin-messaging.js' },
    { maxResponseBytes: 10_331 },
  ]) {
    assert.throws(
      () => createHttpReconResponseObservationDescriptor({
        profile: 'credible-cross-origin-js-ast-v1',
        method: 'GET',
        url: CROSS_ORIGIN_MESSAGING_URL,
        maxResponseBytes: MAX,
        ...input,
      }),
      /method, origin, or byte boundary/iu,
    )
  }
})

test('cross-origin AST headers require complete identity-encoded JavaScript', () => {
  const sealed = crossOriginDescriptor()
  assert.equal(validateHttpReconResponseObservationHeaders({
    descriptor: sealed,
    method: 'GET',
    url: CROSS_ORIGIN_MESSAGING_URL,
    maxResponseBytes: MAX,
    status: 200,
    contentTypes: ['application/javascript'],
    contentEncodings: [],
  }), true)
  for (const input of [
    { status: 204, contentTypes: ['application/javascript'], contentEncodings: [] },
    { status: 200, contentTypes: ['text/javascript'], contentEncodings: [] },
    { status: 200, contentTypes: ['application/javascript'], contentEncodings: ['gzip'] },
  ]) {
    assert.throws(() => validateHttpReconResponseObservationHeaders({
      descriptor: sealed,
      method: 'GET',
      url: CROSS_ORIGIN_MESSAGING_URL,
      maxResponseBytes: MAX,
      ...input,
    }), /response-observation profile/iu)
  }
})

test('Acorn AST analysis emits only bounded structural counts and booleans', () => {
  const analysis = analyzeCrossOriginJavaScriptAst(`
    function guarded(messageEvent) {
      if (messageEvent.origin !== allowedOrigin || messageEvent.source !== parent) return;
      const accessTokenValue = messageEvent.data.tokenValue;
      parent.postMessage({ accessTokenValue, marker: 'super-secret-literal' }, '*');
    }
    addEventListener('message', guarded);
    window.addEventListener('message', function (incomingEvent) {
      sessionTokenValue = incomingEvent.data;
      top.postMessage({ type: 'ready-value' }, window.location.origin);
    });
    window.onmessage = externalHandlerName;
    other.postMessage({ tokenValue: 'not-retained' }, 'https://trusted.example');
    postMessage({}, dynamicOriginName);
    postMessage({});
  `)

  assert.deepEqual(analysis.message_listeners, {
    count: 3,
    inline_handler_count: 1,
    resolved_handler_count: 2,
    unresolved_handler_count: 1,
    origin_guard_candidate_count: 1,
    source_guard_candidate_count: 1,
    both_guard_candidate_count: 1,
    without_origin_guard_candidate_count: 1,
    without_source_guard_candidate_count: 1,
    has_resolved_handler_without_origin_guard_candidate: true,
    has_resolved_handler_without_source_guard_candidate: true,
  })
  assert.deepEqual(analysis.post_message_calls, {
    count: 5,
    targets: {
      wildcard_literal_count: 1,
      same_origin_expression_count: 1,
      static_origin_literal_count: 1,
      opaque_or_null_literal_count: 0,
      other_static_literal_count: 0,
      dynamic_expression_count: 1,
      missing_count: 1,
    },
    has_wildcard_target: true,
    has_dynamic_target: true,
  })
  assert.equal(analysis.analysis_complete, true)
  assert.equal(analysis.token_like_flows.message_listener_candidate_count, 2)
  assert.equal(
    analysis.token_like_flows.message_input_to_token_sink_candidate_count,
    2,
  )
  assert.equal(analysis.token_like_flows.post_message_payload_candidate_count, 2)
  assert.equal(analysis.token_like_flows.candidate_count, 6)
  assert.equal(analysis.token_like_flows.present, true)
  assert.ok(analysis.token_like_flows.reference_count > 0)

  const durable = JSON.stringify(analysis)
  assert.doesNotMatch(
    durable,
    /messageEvent|allowedOrigin|accessTokenValue|super-secret-literal|ready-value|externalHandlerName|trusted\.example|dynamicOriginName|not-retained/u,
  )
  const leafValues = []
  const collect = (value) => {
    if (value !== null && typeof value === 'object') {
      for (const child of Object.values(value)) collect(child)
    } else leafValues.push(value)
  }
  collect(analysis)
  assert.ok(leafValues.every((value) => (
    typeof value === 'number' || typeof value === 'boolean'
  )))
})

test('cross-origin AST observer rejects nonmatching artifact identity before parsing', () => {
  const body = Buffer.alloc(10_332, 0x61)
  assert.throws(
    () => observeCredibleCrossOriginJavaScript({
      descriptor: crossOriginDescriptor(),
      method: 'GET',
      url: CROSS_ORIGIN_MESSAGING_URL,
      maxResponseBytes: MAX,
      body,
    }),
    (error) => {
      assert.equal(error.code, 'HTTP_RECON_RESPONSE_OBSERVATION_ARTIFACT_MISMATCH')
      assert.doesNotMatch(
        error.message,
        /a4abd910|1029bd62|cross-origin-messaging|global-cross-origin/iu,
      )
      return true
    },
  )
  assert.throws(
    () => analyzeCrossOriginJavaScriptAst('function { secret-source-value'),
    (error) => {
      assert.equal(error.code, 'HTTP_RECON_RESPONSE_OBSERVATION_JAVASCRIPT_PARSE_INVALID')
      assert.doesNotMatch(error.message, /secret-source-value/iu)
      return true
    },
  )
})
