import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  parsePinnedImageReference,
  redactForLog,
  sealCredentialRef,
} from '../scripts/lib/evidence-image-reference.mjs'

const DIGEST = 'sha256:9f2c1d0e4b6a8c3f5e7d9b1a3c5e7f9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c'

test('a digest-pinned reference parses into its parts', () => {
  const parsed = parsePinnedImageReference(`registry.example.com/peerstar/api@${DIGEST}`)
  assert.equal(parsed.registry, 'registry.example.com')
  assert.equal(parsed.repository, 'peerstar/api')
  assert.equal(parsed.digest, DIGEST)
  assert.equal(parsed.canonical, `registry.example.com/peerstar/api@${DIGEST}`)
})

test('a registry port survives while a tag does not', () => {
  const parsed = parsePinnedImageReference(`registry.example.com:5000/peerstar/api@${DIGEST}`)
  assert.equal(parsed.registry, 'registry.example.com:5000')
  assert.equal(parsed.repository, 'peerstar/api')
})

test('a tag is not an identity and is refused', () => {
  for (const reference of [
    'registry.example.com/peerstar/api:latest',
    'registry.example.com/peerstar/api',
    'peerstar/api:v2.1.0',
    `registry.example.com/peerstar/api:v2@${DIGEST.slice(0, 20)}`,
  ]) {
    assert.throws(() => parsePinnedImageReference(reference), /digest|pinned|tag/i, reference)
  }
})

test('a reference carrying shell metacharacters is refused before it reaches a CLI', () => {
  assert.throws(
    () => parsePinnedImageReference(`registry.example.com/a;rm -rf /@${DIGEST}`),
    /invalid/i,
  )
})

test('a credential reference is sealed; a credential value is refused', () => {
  assert.deepEqual(sealCredentialRef('env:REGISTRY_TOKEN'), { credential_ref: 'env:REGISTRY_TOKEN' })
  assert.deepEqual(sealCredentialRef('keychain:peerstar-registry'), {
    credential_ref: 'keychain:peerstar-registry',
  })
  for (const value of [
    'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'password=hunter2',
    'https://ci:hunter2@registry.example.com',
    '-----BEGIN OPENSSH PRIVATE KEY-----',
  ]) {
    assert.throws(() => sealCredentialRef(value), /credential value|reference/i, value)
  }
})

test('a credential reference must name a resolver, not float free', () => {
  assert.throws(() => sealCredentialRef('REGISTRY_TOKEN'), /env:|file:|keychain:/)
})

test('redaction is applied to anything that reaches a log or an error', () => {
  assert.equal(
    redactForLog('failed: https://ci:hunter2@registry.example.com/v2/'),
    'failed: https://[REDACTED]@registry.example.com/v2/',
  )
  assert.match(redactForLog('Authorization: Bearer eyJhbGciOi'), /Bearer \[REDACTED\]/)
})

test('a redacted string does not itself read as a credential value', () => {
  // Leaving `user:[REDACTED]@` behind would still match a credential-in-URL
  // shape, so the bundle contract would refuse a correctly redacted reason.
  const redacted = redactForLog('UNAUTHORIZED for https://ci:hunter2@registry.example.com')
  assert.equal(redacted.includes('hunter2'), false)
  assert.throws(() => sealCredentialRef(redacted), /reference/i)
  assert.equal(/[a-z]+:\/\/[^/\s:@]+:[^/\s@]+@/i.test(redacted), false)
})
