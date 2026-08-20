import assert from 'node:assert/strict'
import { test } from 'node:test'
import { decideScope, SCOPE_ALLOW, SCOPE_DENY } from '../scripts/lib/bounty-scope-kernel.mjs'

function scope(overrides = {}) {
  return {
    scope_rules: {
      allow: [
        { rule_id: 'allow-wildcard', host_kind: 'wildcard', host: 'example.com' },
        { rule_id: 'allow-apex', host_kind: 'exact', host: 'example.com' },
      ],
      deny: [
        { rule_id: 'deny-internal', host_kind: 'exact', host: 'internal.example.com' },
      ],
      ...overrides,
    },
  }
}

test('allows a subdomain matched by a wildcard rule', () => {
  const result = decideScope(scope(), 'https://api.example.com/v1')
  assert.equal(result.decision, SCOPE_ALLOW)
  assert.equal(result.rule_id, 'allow-wildcard')
})

test('allows a deeply nested subdomain', () => {
  assert.equal(decideScope(scope(), 'https://a.b.example.com/').decision, SCOPE_ALLOW)
})

test('a wildcard rule alone does not match the apex', () => {
  const apexOnlyWildcard = {
    scope_rules: {
      allow: [{ rule_id: 'allow-wildcard', host_kind: 'wildcard', host: 'example.com' }],
      deny: [],
    },
  }
  const result = decideScope(apexOnlyWildcard, 'https://example.com/')
  assert.equal(result.decision, SCOPE_DENY)
  assert.equal(result.reason, 'candidate-unlisted')
})

test('deny takes precedence over a matching wildcard allow', () => {
  const result = decideScope(scope(), 'https://internal.example.com/')
  assert.equal(result.decision, SCOPE_DENY)
  assert.equal(result.rule_id, 'deny-internal')
  assert.equal(result.reason, 'explicit-deny-rule')
})

test('an unlisted host is denied', () => {
  const result = decideScope(scope(), 'https://notexample.com/')
  assert.equal(result.decision, SCOPE_DENY)
  assert.equal(result.reason, 'candidate-unlisted')
})

test('a suffix-confusable host is denied', () => {
  assert.equal(decideScope(scope(), 'https://evilexample.com/').decision, SCOPE_DENY)
  assert.equal(decideScope(scope(), 'https://example.com.evil.net/').decision, SCOPE_DENY)
})

test('an ip literal never matches a domain rule', () => {
  const result = decideScope(scope(), 'https://203.0.113.7/')
  assert.equal(result.decision, SCOPE_DENY)
})

test('a domain never matches an ip rule', () => {
  const ipScope = {
    scope_rules: {
      allow: [{ rule_id: 'allow-ip', host_kind: 'ip', host: '203.0.113.7' }],
      deny: [],
    },
  }
  assert.equal(decideScope(ipScope, 'https://203.0.113.7/').decision, SCOPE_ALLOW)
  assert.equal(decideScope(ipScope, 'https://example.com/').decision, SCOPE_DENY)
})

test('private and metadata targets are denied even when listed', () => {
  const privateScope = {
    scope_rules: {
      allow: [
        { rule_id: 'allow-meta', host_kind: 'ip', host: '169.254.169.254' },
        { rule_id: 'allow-rfc1918', host_kind: 'ip', host: '10.0.0.5' },
        { rule_id: 'allow-loopback', host_kind: 'ip', host: '127.0.0.1' },
      ],
      deny: [],
    },
  }
  for (const url of ['http://169.254.169.254/', 'http://10.0.0.5/', 'http://127.0.0.1/']) {
    const result = decideScope(privateScope, url)
    assert.equal(result.decision, SCOPE_DENY, url)
    assert.equal(result.reason, 'private-target-not-sealed')
  }
})

test('private targets are permitted only when explicitly sealed', () => {
  const sealed = {
    scope_rules: {
      allow: [{ rule_id: 'allow-loopback', host_kind: 'ip', host: '127.0.0.1' }],
      deny: [],
      private_targets_sealed: true,
    },
  }
  assert.equal(decideScope(sealed, 'http://127.0.0.1/').decision, SCOPE_ALLOW)
})

test('non-default ports are denied unless the rule seals them', () => {
  assert.equal(decideScope(scope(), 'https://api.example.com:8443/').decision, SCOPE_DENY)
  const ported = {
    scope_rules: {
      allow: [
        { rule_id: 'allow-8443', host_kind: 'wildcard', host: 'example.com', ports: [443, 8443] },
      ],
      deny: [],
    },
  }
  assert.equal(decideScope(ported, 'https://api.example.com:8443/').decision, SCOPE_ALLOW)
})

test('path scope matches on segment boundaries only', () => {
  const pathScoped = {
    scope_rules: {
      allow: [
        { rule_id: 'allow-api', host_kind: 'exact', host: 'example.com', path_prefix: '/api' },
      ],
      deny: [],
    },
  }
  assert.equal(decideScope(pathScoped, 'https://example.com/api').decision, SCOPE_ALLOW)
  assert.equal(decideScope(pathScoped, 'https://example.com/api/v1').decision, SCOPE_ALLOW)
  assert.equal(decideScope(pathScoped, 'https://example.com/apifoo').decision, SCOPE_DENY)
  assert.equal(decideScope(pathScoped, 'https://example.com/').decision, SCOPE_DENY)
})

test('an uncanonicalizable candidate is denied with its refusal reason', () => {
  const result = decideScope(scope(), 'https://allowed.example.com@evil.example/')
  assert.equal(result.decision, SCOPE_DENY)
  assert.equal(result.reason, 'candidate-carries-userinfo')
})

test('a malformed sealed scope is denied, not thrown', () => {
  for (const bad of [null, undefined, {}, { scope_rules: null }, { scope_rules: { allow: 'x' } }]) {
    const result = decideScope(bad, 'https://api.example.com/')
    assert.equal(result.decision, SCOPE_DENY)
    assert.equal(result.reason, 'sealed-scope-not-usable')
  }
})

test('a rule that throws during matching denies the candidate', () => {
  const hostile = {
    scope_rules: {
      allow: [{
        rule_id: 'hostile',
        host_kind: 'exact',
        get host() { throw new Error('boom') },
      }],
      deny: [],
    },
  }
  const result = decideScope(hostile, 'https://api.example.com/')
  assert.equal(result.decision, SCOPE_DENY)
  assert.equal(result.reason, 'kernel-error')
})
