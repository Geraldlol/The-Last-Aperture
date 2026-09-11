import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFile } from 'node:fs/promises'

import {
  assertValidWebSessionEvidence,
  importWebHarEvidence,
} from '../../../scripts/lib/reverse-web-har.mjs'

const [capturePath] = process.argv.slice(2)
if (!capturePath) throw new Error('usage: node verify-har.mjs <capture.har>')

const bytes = await readFile(capturePath)
const har = JSON.parse(bytes.toString('utf8'))
assert.equal(har.log.version, '1.2')
assert.equal(har.log._lastAperture.core_evidence_provenance, 'WEB_HAR')
assert.equal(har.log._lastAperture.source.edition, 'COMMUNITY_EDITION')
assert.equal(har.log._lastAperture.capabilities.active_scanner, 'NOT_USED')
assert.equal(har.log._lastAperture.capabilities.traffic_modification, 'DISABLED')

const evidence = importWebHarEvidence(har, {
  sourceSha256: createHash('sha256').update(bytes).digest('hex'),
  targetOrigins: ['https://service.invalid'],
  pathLiterals: ['api', 'users', 'v1'],
})
assert.equal(assertValidWebSessionEvidence(evidence), evidence)
assert.equal(evidence.source.kind, 'HAR')
assert.equal(evidence.security_verdict, 'NOT_ASSESSED')
assert.equal(evidence.entries.length, 3)
assert.equal(evidence.entries[0].request.path_template, '/api/v1/users/{integer}')
assert.deepEqual(evidence.entries[0].request.header_names, ['authorization', 'content-type', 'cookie'])
assert.deepEqual(evidence.entries[0].request.cookie_names, ['SessionId'])
assert.deepEqual(evidence.entries[0].request.query_parameters.map(({ name }) => name), ['tenant'])
assert.deepEqual(evidence.entries[0].request.body.fields.map(({ name }) => name), ['password', 'username'])
assert.ok(evidence.entries[0].request.body.fields.every(({ types }) => types.includes('string')))
assert.deepEqual(evidence.entries[0].request.credential_carriers, [
  'body:password',
  'body:username',
  'cookie:SessionId',
  'header:authorization',
])
const bodies = Object.fromEntries(evidence.entries.map(({ request }) => [
  request.body.content_type,
  request.body,
]))
assert.equal(bodies['application/json'].format, 'JSON')
assert.equal(bodies['application/json'].byte_bucket, 'LE_1_KIB')
assert.equal(bodies['application/x-www-form-urlencoded'].format, 'FORM')
assert.equal(bodies['application/x-www-form-urlencoded'].byte_bucket, 'LE_4_KIB')
assert.deepEqual(bodies['application/x-www-form-urlencoded'].fields.map(({ name }) => name), ['email'])
assert.equal(bodies['application/octet-stream'].format, 'OPAQUE')
assert.equal(bodies['application/octet-stream'].byte_bucket, 'LE_64_KIB')

process.stdout.write(JSON.stringify({
  capture_protocol: har.log._lastAperture.capture_protocol,
  core_evidence_source: evidence.source.kind,
  entries: evidence.entries.length,
  path_template: evidence.entries[0].request.path_template,
}) + '\n')
