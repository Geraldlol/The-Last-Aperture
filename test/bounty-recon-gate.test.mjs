import assert from 'node:assert/strict'
import { test } from 'node:test'
import { assertApproved, gateCandidates } from '../scripts/lib/bounty-recon-gate.mjs'

function sealedScope() {
  return {
    program: { required_user_agent: 'BugBounty-acme' },
    scope_rules: {
      allow: [
        { rule_id: 'allow-wildcard', host_kind: 'wildcard', host: 'target.example' },
        { rule_id: 'allow-apex', host_kind: 'exact', host: 'target.example' },
      ],
      deny: [{ rule_id: 'deny-legacy', host_kind: 'exact', host: 'legacy.target.example' }],
    },
  }
}

const host = (value) => ({ kind: 'host', value })
const zone = (value) => ({ kind: 'zone_hint', value })

test('approves an in-scope host and names the rule that allowed it', () => {
  const { approved, refused } = gateCandidates({
    sealedScope: sealedScope(),
    candidates: [host('api.target.example')],
  })
  assert.equal(refused.length, 0)
  assert.equal(approved.length, 1)
  assert.equal(approved[0].host, 'api.target.example')
  assert.equal(approved[0].port, 443)
  assert.equal(approved[0].url, 'https://api.target.example/')
  assert.equal(approved[0].ruleId, 'allow-wildcard')
  assert.equal(approved[0].__scopeApproved, true)
})

test('refuses an out-of-scope host with the kernel reason verbatim', () => {
  const { approved, refused } = gateCandidates({
    sealedScope: sealedScope(),
    candidates: [host('other.example')],
  })
  assert.equal(approved.length, 0)
  assert.equal(refused[0].host, 'other.example')
  assert.equal(refused[0].reason, 'candidate-unlisted')
})

test('an explicit deny beats the wildcard allow, and the deny rule is named', () => {
  const { approved, refused } = gateCandidates({
    sealedScope: sealedScope(),
    candidates: [host('legacy.target.example')],
  })
  assert.equal(approved.length, 0)
  assert.equal(refused[0].reason, 'explicit-deny-rule')
  assert.equal(refused[0].ruleId, 'deny-legacy')
})

test('a zone hint is never probeable even when its zone is in scope', () => {
  const { approved, refused } = gateCandidates({
    sealedScope: sealedScope(),
    candidates: [zone('target.example')],
  })
  assert.equal(approved.length, 0)
  assert.equal(refused[0].reason, 'zone-hint-not-probeable')
})

test('honours a non-default port only when the scope seals it', () => {
  const ported = {
    program: { required_user_agent: 'BugBounty-acme' },
    scope_rules: {
      allow: [{ rule_id: 'allow-8443', host_kind: 'wildcard', host: 'target.example', ports: [8443] }],
      deny: [],
    },
  }
  const allowed = gateCandidates({ sealedScope: ported, candidates: [host('api.target.example')], port: 8443 })
  assert.equal(allowed.approved.length, 1)
  assert.equal(allowed.approved[0].url, 'https://api.target.example:8443/')
  const denied = gateCandidates({ sealedScope: ported, candidates: [host('api.target.example')], port: 443 })
  assert.equal(denied.approved.length, 0)
})

test('a private or metadata target is refused even if a source suggested it', () => {
  const { refused } = gateCandidates({
    sealedScope: sealedScope(),
    candidates: [host('localhost'), host('169.254.169.254')],
  })
  assert.equal(refused.length, 2)
  assert.equal(refused.every((r) => r.reason === 'private-target-not-sealed'), true)
})

test('assertApproved accepts only an object the gate produced', () => {
  const { approved } = gateCandidates({
    sealedScope: sealedScope(),
    candidates: [host('api.target.example')],
  })
  assert.doesNotThrow(() => assertApproved(approved[0]))
  // Hand-forged shapes must not pass: this is the whole point of the brand.
  for (const forged of [
    { host: 'evil.example', port: 443, url: 'https://evil.example/' },
    { host: 'evil.example', __scopeApproved: 'true' },
    { __scopeApproved: false },
    null,
    undefined,
    'https://evil.example/',
  ]) {
    assert.throws(() => assertApproved(forged), /scope-approved/, JSON.stringify(forged))
  }
})

test('a malformed sealed scope refuses everything rather than approving it', () => {
  const { approved, refused } = gateCandidates({
    sealedScope: {},
    candidates: [host('api.target.example')],
  })
  assert.equal(approved.length, 0)
  assert.equal(refused[0].reason, 'sealed-scope-not-usable')
})

test('gates a mixed batch and keeps both sides', () => {
  const { approved, refused } = gateCandidates({
    sealedScope: sealedScope(),
    candidates: [
      host('api.target.example'),
      host('target.example'),
      host('legacy.target.example'),
      zone('target.example'),
      host('unrelated.example'),
    ],
  })
  assert.equal(approved.length, 2)
  assert.equal(refused.length, 3)
})
