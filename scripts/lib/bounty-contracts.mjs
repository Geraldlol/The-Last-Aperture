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
