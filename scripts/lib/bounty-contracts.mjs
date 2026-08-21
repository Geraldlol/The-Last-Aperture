import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import Ajv2020 from 'ajv/dist/2020.js'

const SCOPE_SCHEMA_URL = new URL('../../schemas/bounty-scope.schema.json', import.meta.url)

export const BOUNTY_SCOPE_SCHEMA_VERSION = '1.0.0'

export const PROGRAM_POLICY_SEALED_STATEMENT =
  'I declare that I am an enrolled researcher on the named bounty program and that the sealed scope reflects that program policy as published at seal time.'

let compiledScopeValidator = null

function scopeValidator() {
  if (compiledScopeValidator !== null) return compiledScopeValidator
  const ajv = new Ajv2020({ allErrors: true, strict: false })
  const schema = JSON.parse(readFileSync(SCOPE_SCHEMA_URL, 'utf8'))
  compiledScopeValidator = ajv.compile(schema)
  return compiledScopeValidator
}

export function assertValidBountyScope(value) {
  const validate = scopeValidator()
  if (validate(value)) return
  const detail = (validate.errors ?? [])
    .map((error) => `${error.instancePath || '/'} ${error.message}${
      error.params?.additionalProperty ? ` (${error.params.additionalProperty})` : ''
    }`)
    .join('; ')
  throw new Error(`bounty scope failed schema validation: ${detail}`)
}

export function digestPolicySnapshot(bytes) {
  const buffer = Buffer.isBuffer(bytes) ? bytes : Buffer.from(String(bytes), 'utf8')
  return createHash('sha256').update(buffer).digest('hex')
}

export const SCOPE_CURRENCY_STATES = Object.freeze([
  'CURRENT',
  'NOT_YET_VALID',
  'EXPIRED',
  'VALIDITY_MISSING',
])

// A program's authorization has a validity period, and testing outside it is
// unauthorized testing however in-scope the host is. Sealing the window and never
// checking it made the window decorative.
//
// Non-throwing, so `validate` can report on an expired bundle rather than refuse
// to open it: inspecting old evidence must stay possible after the grant lapses.
export function describeScopeCurrency({ scope, now }) {
  const at = now instanceof Date && !Number.isNaN(now.getTime()) ? now : null
  if (at === null) {
    throw new Error('describeScopeCurrency requires a valid Date for now')
  }
  const validity = scope?.validity
  const missing = {
    status: 'VALIDITY_MISSING',
    notBefore: null,
    notAfter: null,
    now: at.toISOString(),
  }
  if (validity === null || typeof validity !== 'object') return missing
  if (typeof validity.not_before !== 'string' || typeof validity.not_after !== 'string') return missing
  const notBefore = new Date(validity.not_before)
  const notAfter = new Date(validity.not_after)
  if (Number.isNaN(notBefore.getTime()) || Number.isNaN(notAfter.getTime())) return missing
  const shape = {
    notBefore: notBefore.toISOString(),
    notAfter: notAfter.toISOString(),
    now: at.toISOString(),
  }
  if (at.getTime() < notBefore.getTime()) return { status: 'NOT_YET_VALID', ...shape }
  // Exclusive upper bound, matching http-authed: at exactly not_after the grant
  // has run out.
  if (at.getTime() >= notAfter.getTime()) return { status: 'EXPIRED', ...shape }
  return { status: 'CURRENT', ...shape }
}

// Fails closed, including on a scope with no window at all: an unsealed validity
// period is not a permissive one, it is an invalid scope.
export function assertScopeCurrent({ scope, now }) {
  const currency = describeScopeCurrency({ scope, now })
  if (currency.status === 'CURRENT') return currency
  if (currency.status === 'VALIDITY_MISSING') {
    throw new Error(
      'sealed scope carries no usable validity window; refusing to contact a target under an unbounded authorization',
    )
  }
  throw new Error(
    `sealed authorization is ${currency.status}: window ${currency.notBefore} to ${currency.notAfter}, now ${currency.now}. Re-seal the program policy before testing.`,
  )
}
