import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

const LENS_PATH = 'skills/red-team-audit/lenses/crypto-and-key-management.md'
const EXPECTED_PATH = 'fixtures/EXPECTED.md'
const CLEAN_APEX_PATH = 'fixtures/clean/ApexWebhookVerifier.cls'
const VULNERABLE_APEX_PATH = 'fixtures/vulnerable/WebhookSignatureEquals.cls'
const lens = readFileSync(LENS_PATH, 'utf8')
const expected = readFileSync(EXPECTED_PATH, 'utf8')
const cleanApex = readFileSync(CLEAN_APEX_PATH, 'utf8')
const vulnerableApex = readFileSync(VULNERABLE_APEX_PATH, 'utf8')

function occurrenceCount(source, token) {
  return source.split(token).length - 1
}

test('CommonCrypto construction inventories cover mode and streaming entry points', () => {
  const cryptorToken = String.raw`CCCryptorCreate(?:FromData)?(?:WithMode)?\(`
  const hmacToken = String.raw`CCHmac(?:Init)?\(`

  assert.ok(
    occurrenceCount(lens, cryptorToken) >= 3,
    'general, CBC/CTR and Swift inventories must share the expanded CCCryptorCreate family'
  )
  assert.ok(
    occurrenceCount(lens, hmacToken) >= 4,
    'positive, absence and Swift HMAC inventories must include CCHmacInit'
  )

  const cryptorPattern = /CCCryptorCreate(?:FromData)?(?:WithMode)?\(/
  for (const call of [
    'CCCryptorCreate(',
    'CCCryptorCreateFromData(',
    'CCCryptorCreateWithMode(',
    'CCCryptorCreateFromDataWithMode(',
  ]) {
    assert.match(call, cryptorPattern)
  }

  const hmacPattern = /CCHmac(?:Init)?\(/
  assert.match('CCHmac(', hmacPattern)
  assert.match('CCHmacInit(', hmacPattern)
})

test('Apex inventory uses real APIs and CBC absence triage exempts GCM', () => {
  const nonexistentApexApi = 'generateDigest' + 'WithKey'
  assert.ok(!lens.includes(nonexistentApexApi))
  assert.ok(!expected.includes(nonexistentApexApi))

  const absenceLine = lens
    .split(/\r?\n/)
    .find((line) => line.startsWith("rg -i --hidden --files-with-matches 'modes\\.CBC"))

  assert.ok(absenceLine, 'CBC/CTR absence sweep must exist')
  assert.ok(
    absenceLine.includes(String.raw`Crypto\.(encrypt|decrypt)(WithManagedIV)?\(`),
    'Apex arm must bind the mode decision to the algorithm argument'
  )
  assert.ok(absenceLine.includes('AES(128|192|256)'))
  assert.doesNotMatch(
    absenceLine,
    /Crypto\\\.encrypt\\\(\|Crypto\\\.encryptWithManagedIV\\\(/
  )

  const apexCbcLiteral = /Crypto\.(?:encrypt|decrypt)(?:WithManagedIV)?\(\s*["']AES(?:128|192|256)["']/
  assert.match("Crypto.encryptWithManagedIV('AES256', key, body)", apexCbcLiteral)
  assert.match('Crypto.decrypt("AES128", key, iv, body)', apexCbcLiteral)
  assert.doesNotMatch("Crypto.encryptWithManagedIV('AES256-GCM', key, aad, body)", apexCbcLiteral)

  assert.match(lens, /Summer '25 \(API 64\.0\)/)
  assert.match(lens, /Shield or Shield Platform Encryption license/)
  assert.match(lens, /supported Apex `AES\*-GCM`/)
  assert.doesNotMatch(
    lens,
    /Apex has no AEAD|Apex has no authenticated mode|platform's only mode is CBC|there is no AEAD to switch to/
  )
})

test('constant-time inventories use exact platform APIs and preserve Apex helper triage', () => {
  const safeLine = lens
    .split(/\r?\n/)
    .find((line) => line.includes("rg -q 'timingSafeEqual|compare_digest"))

  assert.ok(safeLine, 'general constant-time clearing list must exist')
  assert.ok(
    safeLine.includes(String.raw`ActiveSupport::SecurityUtils\.(fixed_length_secure_compare|secure_compare)`),
    'Rails clearances must use the full ActiveSupport::SecurityUtils namespace'
  )
  assert.ok(
    safeLine.includes(String.raw`subtle\.ConstantTimeCompare`),
    'Go clearance must include its package qualifier'
  )
  assert.ok(
    safeLine.includes(String.raw`Crypto\.areEqualConstantTime`),
    'Apex clearance must include the native Blob comparator'
  )
  assert.doesNotMatch(safeLine, /\|fixed_length_secure_compare\|secure_compare\|/)
  assert.doesNotMatch(safeLine, /\|SecurityUtils\\\./)
  assert.doesNotMatch(
    safeLine,
    /\|ConstantTimeCompare\|/,
    'a bare Go method name collides with project-local symbols and fixture names'
  )
  const safePatternText = /^.*?rg -q '([^']+)' "\$f" && continue$/.exec(safeLine)?.[1]
  assert.ok(safePatternText, 'constant-time clearing regex must remain extractable')
  const safePattern = new RegExp(safePatternText)
  assert.doesNotMatch(
    cleanApex,
    safePattern,
    'C-033 must reach the documented manual read-to-clear path, not an incidental safe token'
  )
  assert.doesNotMatch(
    vulnerableApex,
    safePattern,
    'V-014 must not be cleared by an incidental safe token in code or fixture prose'
  )
  assert.match(
    'Crypto.areEqualConstantTime(given, expected)',
    safePattern,
    'the exact Apex platform API must clear the extracted stage-2 regex'
  )
  assert.ok(
    occurrenceCount(lens, 'Crypto.areEqualConstantTime') >= 4,
    'the Apex built-in must appear in the inventory, detector, guidance, and severity contract'
  )

  const apexBuiltin = 'Crypto.' + 'areEqualConstantTime'
  assert.ok(!cleanApex.includes(apexBuiltin))
  assert.ok(!vulnerableApex.includes(apexBuiltin))
  assert.match(cleanApex, /equalsConstantTime\(String given, String expected\)/)
  assert.match(
    cleanApex,
    /return equalsConstantTime\(givenSignature, EncodingUtil\.base64Encode\(mac\)\);/
  )
  assert.doesNotMatch(
    [lens, expected, cleanApex, vulnerableApex].join('\n'),
    /Apex ships no constant-time|Apex has no platform constant-time|safe list has no Apex member|APEX HAS NO MEMBER|platform gives the auditor nothing/i
  )

  assert.match(lens, /Go's `os\.Getenv` has no default argument/)
  assert.match(lens, /empty-string check and a literal assignment/)
})
