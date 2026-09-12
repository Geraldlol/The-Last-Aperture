import { createHash } from 'node:crypto'
import { constants as FS_CONSTANTS } from 'node:fs'
import { lstat, open, realpath } from 'node:fs/promises'
import { isAbsolute, join, parse, relative, resolve } from 'node:path'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'

import { assertLocalFilesystemEndpoint } from './filesystem-endpoint.mjs'
import { engagementAuthorizationProfile } from './engagement-authority-profiles.mjs'
import { ENGAGEMENT_ROUTE_REGISTRY } from './engagement-route-registry.mjs'
import { stableJson } from './run-engine.mjs'

const INTAKE_SCHEMA_URL = new URL('../../schemas/engagement-intake.schema.json', import.meta.url)
const AUTHORITY_SCHEMA_URL = new URL('../../schemas/engagement-authority.schema.json', import.meta.url)
const MANIFEST_SCHEMA_URL = new URL('../../schemas/engagement-manifest.schema.json', import.meta.url)

export const engagementIntakeSchema = JSON.parse(readFileSync(fileURLToPath(INTAKE_SCHEMA_URL), 'utf8'))
export const engagementAuthoritySchema = JSON.parse(readFileSync(fileURLToPath(AUTHORITY_SCHEMA_URL), 'utf8'))
export const engagementManifestSchema = JSON.parse(readFileSync(fileURLToPath(MANIFEST_SCHEMA_URL), 'utf8'))

const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
for (const schema of [engagementIntakeSchema, engagementAuthoritySchema, engagementManifestSchema]) {
  ajv.addSchema(schema)
}
const validateIntakeSchema = ajv.getSchema(engagementIntakeSchema.$id)
const validateAuthoritySchema = ajv.getSchema(engagementAuthoritySchema.$id)
const validateManifestSchema = ajv.getSchema(engagementManifestSchema.$id)

const TARGET_KINDS = new Set(['https', 'repository', 'artifact', 'process', 'device', 'browser'])
const URI_SCHEME = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//
const SHA256 = /^[a-f0-9]{64}$/
const REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}$/
const MAX_STATEMENT_BYTES = 8 * 1024
const MAX_OBJECTIVE_BYTES = 4 * 1024
const MAX_INPUT_BYTES = 2 * 1024 * 1024 * 1024
const AFFIRMATIVE_AUTHORITY = /(?:\b(?:i|we)\b[^.!?\n]{0,40}\b(?:am|are)\s+(?:(?:explicitly|fully)\s+)?(?:allowed|authori[sz]ed|permitted)\b|\b(?:i|we)\s+(?:currently\s+)?have\s+(?:(?:complete|explicit|full|unrestricted)\s+)?(?:authori[sz]ation|authority|permission)\b|\b(?:i|we|my\s+team|our\s+(?:company|organization|team))\b[^.!?\n]{0,64}\bauthori[sz](?:e|es)\b|\bauthori[sz]ed\s+for\b|\b(?:authori[sz]ation|permission)\s+(?:is|has\s+been)\s+granted\b|\b(?:you|claude|codex)\s+(?:are|is)\s+(?:allowed|authori[sz]ed|permitted)\b|дозволяю|(?:маю|маємо)\s+дозвіл|уповноваж(?:ений|ена|ені))/iu
const NEGATED_AUTHORITY = /(?:\b(?:not|never|without|no|lack(?:ing|s|ed)?)\b[^.!?\n]{0,64}\b(?:authori[sz](?:e|ed|ation)|authority|permission|allowed|permitted)\b|\b(?:denied|refused|revoked|withdrew|withdrawn)\b[^.!?\n]{0,32}\b(?:authori[sz](?:e|ed|ation)|authority|permission)\b|\b(?:authori[sz]ation|authority|permission)\b[^.!?\n]{0,32}\b(?:denied|revoked|withdrawn|not\s+(?:been\s+)?(?:approved|confirmed|granted))\b|не\s+маю\s+дозволу)/iu
const NON_AFFIRMATIVE_AUTHORITY = /(?:\b(?:await(?:ing)?|need(?:ing|s|ed)?|request(?:ing|s|ed)?|seek(?:ing|s|ed)?)\b[^.!?\n]{0,48}\b(?:authori[sz](?:e|ation)|authority|permission|approval)\b|\b(?:authori[sz]ation|authority|permission|approval)\b[^.!?\n]{0,32}\b(?:absent|awaited|missing|needed|pending|required|requested)\b|\bplease\s+authori[sz]e\b|\b(?:am|are|can|may)\s+(?:i|we)\b[^.!?\n]{0,48}\b(?:allowed|authori[sz]ed|permitted)\b|\bdo\s+(?:i|we)\s+have\b[^.!?\n]{0,32}\b(?:authority|permission)\b)/iu
const REPORTED_OR_DISAVOWED_AUTHORITY = /(?:\b(?:says?|said|states?|stated|mentions?|mentioned|claims?|claimed|quotes?|quoted)\b[^.!?\n]{0,80}\b(?:i|we)\b[^.!?\n]{0,40}\b(?:allowed|authori[sz]ed|permitted)\b|\b(?:(?:the\s+)?(?:administrator|client|contract|customer|document(?:ation)?|owner|policy)|he|it|she|someone|they)\b[^.!?\n]{0,40}\b(?:confirms?|confirmed|indicates?|indicated|reads?|reports?|reported|tells?|told)\b[^.!?\n]{0,80}\b(?:i|we)\b[^.!?\n]{0,40}\b(?:allowed|authori[sz]ed|permitted)\b|\b(?:i|we)\s+(?:was|were)\s+(?:assured|informed|told)\b[^.!?\n]{0,80}\b(?:i|we)\b[^.!?\n]{0,40}\b(?:allowed|authori[sz]ed|permitted)\b|\baccording\s+to\b[^.!?\n]{0,96}\b(?:i|we)\b[^.!?\n]{0,40}\b(?:allowed|authori[sz]ed|permitted)\b|\b(?:i|we)\b[^.!?\n]{0,40}\b(?:allowed|authori[sz]ed|permitted)\b[^.!?\n]{0,64}\baccording\s+to\b|\b(?:deny|denies|denied|dispute|doubt|reject|refute|repudiate)\b[^.!?\n]{0,80}\b(?:allowed|authori[sz]ed|permitted|authori[sz]ation|authority|permission)\b|\b(?:false|untrue)\s+that\b[^.!?\n]{0,80}\b(?:allowed|authori[sz]ed|permitted|authori[sz]ation|authority|permission)\b)/iu
const CONDITIONAL_AUTHORITY = /(?:\b(?:allowed|authori[sz]ed|permitted|authori[sz]ation|authority|permission)\b[^.!?\n]{0,64}\b(?:if|provided(?:\s+that)?|assuming|subject\s+to|contingent\s+on|unless|pending)\b|\b(?:if|provided(?:\s+that)?|assuming|subject\s+to|contingent\s+on|unless|pending)\b[^.!?\n]{0,96}\b(?:i|we)\b[^.!?\n]{0,40}\b(?:allowed|authori[sz]ed|permitted)\b|\b(?:allowed|authori[sz]ed|permitted|authori[sz]ation|authority|permission)\b[^.!?\n]{0,48}\b(?:after|as\s+long\s+as|once|upon|when)\b[^.!?\n]{0,32}\b(?:approv\w*|authori[sz]\w*|client|consent|customer|owner|permission)\b|\b(?:after|as\s+long\s+as|once|upon|when)\b[^.!?\n]{0,48}\b(?:approv\w*|authori[sz]\w*|client|consent|customer|owner|permission)\b[^.!?\n]{0,64}\b(?:i|we)\b[^.!?\n]{0,40}\b(?:allowed|authori[sz]ed|permitted)\b)/iu
const QUESTIONED_AUTHORITY = /(?:\b(?:allowed|authori[sz]ed|permitted|authori[sz]ation|authority|permission)\b[^.;!?\n]{0,96}\?|\b(?:ask|question|wonder)\b[^.!?\n]{0,96}\b(?:allowed|authori[sz]ed|permitted|authori[sz]ation|authority|permission)\b|\b(?:can|could|will|would)\s+you\b[^.!?\n]{0,80}\b(?:i|we)\b[^.!?\n]{0,40}\b(?:allowed|authori[sz]ed|permitted)\b)/iu
const RESTRICTED_AUTHORITY = /\b(?:read[- ]only|no\s+(?:access|attach(?:ment)?|network|requests?|runtime|writes?|changes?)|without\s+(?:access|network|runtime|writes?))\b/iu
const FULL_SCOPE_RESTRICTION = /(?:\bnot\s+(?:a\s+)?(?:full|complete|maximum|unrestricted)\b|\bnot\s+[/\\]|\b(?:limited|restricted|partial)\s+(?:scope|assessment|access|authori[sz]ation)\b|\b(?:limited|restricted)\s+to\b|\b(?:except|exception\s+(?:of|for)|excluding|other\s+than)\b|\b(?:scope|access)\b[^.!?\n]{0,32}\b(?:excludes?|omits?)\b|\b(?:avoid|exclude|omit|skip)\b[^.!?\n]{0,64}\b(?:access|attach|attack|change|connect|execute|exploit|fuzz|hit|modif\w*|probe|request|scan|send|test|touch|write)\w*\b|\b(?:do\s+not|don't|must\s+not|may\s+not|cannot|can't)\b[^.!?\n]{0,64}\b(?:access|attach|attack|change|connect|execute|exploit|fuzz|hit|modify|probe|request|scan|send|test|touch|write)\w*\b|\bno\b[^.!?\n]{0,32}\b(?:DELETE|PATCH|POST|PUT)\b|\bonly\b[^.!?\n]{0,48}\b(?:access|attach|change|connect|execute|modify|passive|probe|read|recon|request|send|static|test|write)\w*\b|\b(?:passive\s+recon(?:naissance)?|read[- ]only\s+(?:access|review)|(?:API|endpoint)\s+(?:access|testing)|testing\s+(?:of\s+)?(?:the\s+)?API)\b[^.!?\n]{0,24}\bonly\b)/iu
const TARGET_ONLY_SCOPE = /\b(?:(?:full\s+)?(?:(?:this|that)(?:\s+named)?|the\s+(?:named|specified)|named|specified)?\s*target\s+only|only\s+(?:(?:this|that)(?:\s+named)?|the\s+(?:named|specified)|named|specified)\s+target)\b/giu
const SCOPE_CONTINUITY_NOTE = /(^|[.;]\s*)no\s+changes?\s+to\s+(?:the\s+)?scope(?=$|[.;])/giu
const NETWORK_RESTRICTION = /\b(?:no\s+(?:network|requests?)|without\s+network)\b/iu
const RUNTIME_RESTRICTION = /\b(?:no\s+(?:attach(?:ment)?|runtime)|without\s+runtime)\b/iu
const SUPPORTED_CREDENTIAL_REFERENCE = /^(?:browser:[a-p]{32}|browser-session:[A-Za-z0-9][A-Za-z0-9._:/-]{2,143})$/u

export class EngagementContractError extends Error {
  constructor(code, message, details = [], options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'EngagementContractError'
    this.code = code
    this.details = details
  }
}

function fail(code, message, details = [], options = {}) {
  throw new EngagementContractError(code, message, details, options)
}

function normalizedAjvErrors(errors = []) {
  return errors.map((error) => ({
    code: `SCHEMA_${String(error.keyword).toUpperCase()}`,
    instancePath: error.instancePath || '/',
    message: error.message ?? 'schema validation failed',
    params: error.params,
  }))
}

function assertSchema(validate, value, label) {
  if (!validate(value)) {
    fail('ENGAGEMENT_SCHEMA_INVALID', `${label} violates its JSON schema`, normalizedAjvErrors(validate.errors))
  }
  return value
}

function exactObject(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  if (prototype !== Object.prototype && prototype !== null) return false
  const actual = Object.keys(value).sort()
  const expected = [...fields].sort()
  return actual.length === expected.length && actual.every((field, index) => field === expected[index])
}

function deeplyFrozenCopy(value) {
  const copy = structuredClone(value)
  const stack = [copy]
  while (stack.length > 0) {
    const current = stack.pop()
    if (current === null || typeof current !== 'object' || Object.isFrozen(current)) continue
    for (const nested of Object.values(current)) stack.push(nested)
    Object.freeze(current)
  }
  return copy
}

function containsUnpairedSurrogate(value) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index)
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1)
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true
      index += 1
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return true
    }
  }
  return false
}

function assertBoundedText(value, label, maximumBytes, { naturalLanguage = false } = {}) {
  if (
    typeof value !== 'string'
    || value.trim().length === 0
    || Buffer.byteLength(value, 'utf8') > maximumBytes
    || containsUnpairedSurrogate(value)
    || /[\u0000\u0001-\u0008\u000b\u000c\u000e-\u001f\u007f]/u.test(value)
  ) {
    fail(
      naturalLanguage ? 'ENGAGEMENT_STATEMENT_INVALID' : 'ENGAGEMENT_TEXT_INVALID',
      `${label} must be non-empty bounded UTF-8 natural-language text`,
    )
  }
  return value
}

function assertAffirmativeAuthority(value) {
  if (
    !AFFIRMATIVE_AUTHORITY.test(value)
    || NEGATED_AUTHORITY.test(value)
    || NON_AFFIRMATIVE_AUTHORITY.test(value)
    || REPORTED_OR_DISAVOWED_AUTHORITY.test(value)
    || CONDITIONAL_AUTHORITY.test(value)
    || QUESTIONED_AUTHORITY.test(value)
  ) {
    fail(
      'ENGAGEMENT_AUTHORITY_NOT_ASSERTED',
      'engagement statement must affirm that the operator is authorized or has permission for the named target',
    )
  }
  return value
}

function assertAuthorizationProfileBinding(value, { authority = false } = {}) {
  const profile = engagementAuthorizationProfile(value.authorization_profile)
  if (profile === undefined) {
    fail('ENGAGEMENT_AUTHORIZATION_PROFILE_INVALID', 'engagement authorization profile is unknown')
  }
  if (
    canonicalEngagementJson(value.capabilities) !== canonicalEngagementJson(profile.capabilities)
    || canonicalEngagementJson(value.effects) !== canonicalEngagementJson(profile.effects)
    || (authority && (
      value.scope_mode !== profile.scope_mode
      || value.autonomy_profile !== profile.autonomy_profile
    ))
  ) {
    fail(
      'ENGAGEMENT_AUTHORIZATION_PROFILE_DRIFT',
      'engagement capabilities or effects differ from the selected authorization profile',
    )
  }
  const profileSends = profile.effects.some((effect) => effect.startsWith('SEND_'))
  const profileAttaches = profile.effects.includes('ATTACH_AUTHORIZED_RUNTIME')
  const statementWithoutTargetOnlyScope = value.statement
    .replace(TARGET_ONLY_SCOPE, '')
    .replace(SCOPE_CONTINUITY_NOTE, '$1')
  const contradicted = value.authorization_profile === 'full'
    ? RESTRICTED_AUTHORITY.test(statementWithoutTargetOnlyScope)
      || FULL_SCOPE_RESTRICTION.test(statementWithoutTargetOnlyScope)
      || /\bonly\b/iu.test(statementWithoutTargetOnlyScope)
    : (NETWORK_RESTRICTION.test(value.statement) && profileSends)
      || (RUNTIME_RESTRICTION.test(value.statement) && profileAttaches)
  if (contradicted) {
    fail(
      'ENGAGEMENT_AUTHORIZATION_PROFILE_CONTRADICTED',
      'the selected authorization profile conflicts with a network, runtime, or full-scope restriction in the statement',
    )
  }
  return profile
}

function assertAuthorizationProfileTargetBinding(value) {
  const applicable = ENGAGEMENT_ROUTE_REGISTRY.some((route) => (
    value.capabilities.includes(route.id)
    && route.applicability.target_kinds.includes(value.target.kind)
  ))
  if (!applicable) {
    fail(
      'ENGAGEMENT_AUTHORIZATION_PROFILE_TARGET_MISMATCH',
      'the selected authorization profile has no registered route for the target kind',
    )
  }
}

function assertTimestamp(value, label) {
  const parsed = Date.parse(value)
  if (!Number.isFinite(parsed) || new Date(parsed).toISOString() !== value) {
    fail('ENGAGEMENT_TIME_INVALID', `${label} must be a real canonical UTC millisecond timestamp`)
  }
  return value
}

function ambiguousEncodedPath(value) {
  let current = value
  for (let pass = 0; pass < 8; pass += 1) {
    if (/%(?:2e|2f|5c)/iu.test(current)) return true
    if (!current.includes('%')) return false
    let decoded
    try { decoded = decodeURIComponent(current) } catch { return true }
    if (decoded === current) return false
    current = decoded
  }
  return current.includes('%')
}

function canonicalHttpsLocator(value, label) {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096) {
    fail('ENGAGEMENT_TARGET_INVALID', `${label} must be a bounded HTTPS URL`)
  }
  if (value.includes('\\')) {
    fail('ENGAGEMENT_TARGET_AMBIGUOUS', `${label} contains an ambiguous URL path encoding`)
  }
  let parsed
  try {
    parsed = new URL(value)
  } catch (cause) {
    fail('ENGAGEMENT_TARGET_INVALID', `${label} is not a valid HTTPS URL`, [], { cause })
  }
  if (
    parsed.protocol !== 'https:'
    || parsed.username !== ''
    || parsed.password !== ''
    || parsed.search !== ''
    || parsed.hash !== ''
  ) {
    fail(
      'ENGAGEMENT_TARGET_INVALID',
      `${label} must be one credential-free HTTPS origin/path without a query or fragment`,
    )
  }
  if (parsed.hostname.endsWith('.') || parsed.hostname.includes('*')) {
    fail('ENGAGEMENT_TARGET_INVALID', `${label} contains a non-canonical host`)
  }
  const afterScheme = value.slice(value.indexOf('://') + 3)
  const suffixOffset = afterScheme.search(/[/?#]/u)
  const suffix = suffixOffset === -1 ? '' : afterScheme.slice(suffixOffset)
  const rawPath = suffix.startsWith('/') ? suffix.split(/[?#]/u, 1)[0] : ''
  if (ambiguousEncodedPath(rawPath)) {
    fail('ENGAGEMENT_TARGET_AMBIGUOUS', `${label} contains an ambiguous URL path encoding`)
  }
  return parsed.href
}

function assertCanonicalLocalLocator(value, label) {
  assertLocalFilesystemEndpoint(value, label)
  if (
    typeof value !== 'string'
    || value.length === 0
    || value.length > 4096
    || !isAbsolute(value)
    || resolve(value) !== value
  ) {
    fail('ENGAGEMENT_TARGET_NOT_CANONICAL', `${label} must be a canonical absolute local path`)
  }
  return value
}

function normalizeProcessLocator(value) {
  if (typeof value !== 'string') fail('ENGAGEMENT_TARGET_INVALID', 'process selector must be a string')
  const pid = /^pid:(\d+)$/u.exec(value)
  if (pid) {
    const parsed = Number(pid[1])
    if (!Number.isSafeInteger(parsed) || parsed < 1) {
      fail('ENGAGEMENT_TARGET_INVALID', 'process PID selector must name a positive safe integer')
    }
    return `pid:${parsed}`
  }
  fail('ENGAGEMENT_TARGET_INVALID', 'process selector must be exactly pid:<positive-integer>')
}

function normalizeDeviceLocator(value) {
  if (typeof value !== 'string' || !/^id:[A-Za-z0-9][A-Za-z0-9._-]{0,255}$/u.test(value)) {
    fail('ENGAGEMENT_TARGET_INVALID', 'device selector must be exactly id:<concrete-device-id>')
  }
  return value
}

async function bindRuntimeIdentity(kind, locator, resolveRuntimeIdentity) {
  if (typeof resolveRuntimeIdentity !== 'function') {
    fail(
      'ENGAGEMENT_RUNTIME_IDENTITY_ADAPTER_REQUIRED',
      `${kind} targets require a trusted resolveRuntimeIdentity adapter`,
    )
  }
  const selector = Object.freeze({ kind, locator })
  let instanceSha256
  try {
    instanceSha256 = await resolveRuntimeIdentity(selector)
  } catch (cause) {
    fail(
      'ENGAGEMENT_RUNTIME_IDENTITY_UNAVAILABLE',
      `the trusted runtime identity adapter could not resolve the ${kind} target instance`,
      [],
      { cause },
    )
  }
  if (typeof instanceSha256 !== 'string' || !SHA256.test(instanceSha256)) {
    fail(
      'ENGAGEMENT_RUNTIME_IDENTITY_INVALID',
      'resolveRuntimeIdentity must return one lowercase SHA-256 instance digest',
    )
  }
  return Object.freeze({ kind, locator, instance_sha256: instanceSha256 })
}

function assertCanonicalTargetSemantics(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value) || !TARGET_KINDS.has(value.kind)) {
    fail('ENGAGEMENT_TARGET_INVALID', 'engagement target must contain a supported kind and canonical fields')
  }
  const runtimeTarget = value.kind === 'process' || value.kind === 'device'
  const expectedFields = runtimeTarget ? ['kind', 'locator', 'instance_sha256'] : ['kind', 'locator']
  if (!exactObject(value, expectedFields)) {
    fail(
      'ENGAGEMENT_TARGET_INVALID',
      runtimeTarget
        ? 'process and device targets must contain only kind, locator, and instance_sha256'
        : 'engagement target must contain only kind and locator',
    )
  }
  if (value.kind === 'https' || value.kind === 'browser') {
    const canonical = canonicalHttpsLocator(value.locator, 'target locator')
    if (canonical !== value.locator) {
      fail('ENGAGEMENT_TARGET_NOT_CANONICAL', 'target HTTPS locator is not canonical')
    }
  } else if (value.kind === 'repository' || value.kind === 'artifact') {
    assertCanonicalLocalLocator(value.locator, 'target locator')
  } else if (value.kind === 'process') {
    if (normalizeProcessLocator(value.locator) !== value.locator) {
      fail('ENGAGEMENT_TARGET_NOT_CANONICAL', 'process target selector is not canonical')
    }
  } else if (normalizeDeviceLocator(value.locator) !== value.locator) {
    fail('ENGAGEMENT_TARGET_NOT_CANONICAL', 'device target selector is not canonical')
  }
  if (runtimeTarget && !SHA256.test(value.instance_sha256)) {
    fail(
      'ENGAGEMENT_RUNTIME_IDENTITY_INVALID',
      'process and device targets require a lowercase SHA-256 instance digest',
    )
  }
  return value
}

async function normalizeLocalTarget(rawLocator, requestedKind, { lstatImpl, realpathImpl }) {
  assertLocalFilesystemEndpoint(rawLocator, 'engagement target')
  if (typeof rawLocator !== 'string' || rawLocator.length === 0 || rawLocator.length > 4096) {
    fail('ENGAGEMENT_TARGET_INVALID', 'local target must be a bounded filesystem path')
  }
  const requestedPath = resolve(rawLocator)
  let requestedStat
  try {
    requestedStat = await lstatImpl(requestedPath)
  } catch (cause) {
    fail('ENGAGEMENT_TARGET_UNAVAILABLE', 'local target does not exist or cannot be inspected', [], { cause })
  }
  if (requestedStat.isSymbolicLink()) {
    fail('ENGAGEMENT_TARGET_LINK_REFUSED', 'local target cannot be a symbolic link or reparse-point alias')
  }
  let canonicalPath
  let canonicalStat
  try {
    canonicalPath = await realpathImpl(requestedPath)
    assertLocalFilesystemEndpoint(canonicalPath, 'canonical engagement target')
    canonicalStat = await lstatImpl(canonicalPath)
  } catch (cause) {
    if (cause instanceof EngagementContractError) throw cause
    fail('ENGAGEMENT_TARGET_UNAVAILABLE', 'local target could not be resolved and inspected', [], { cause })
  }
  if (canonicalStat.isSymbolicLink()) {
    fail('ENGAGEMENT_TARGET_LINK_REFUSED', 'canonical local target cannot be a symbolic link or reparse point')
  }
  const actualKind = canonicalStat.isDirectory()
    ? 'repository'
    : canonicalStat.isFile()
      ? 'artifact'
      : null
  if (actualKind === null) {
    fail('ENGAGEMENT_TARGET_INVALID', 'local target must be one regular file or directory')
  }
  if (requestedKind !== undefined && requestedKind !== actualKind) {
    fail('ENGAGEMENT_TARGET_KIND_MISMATCH', `declared ${requestedKind} target does not match the local filesystem object`)
  }
  const target = { kind: actualKind, locator: canonicalPath }
  assertCanonicalTargetSemantics(target)
  return Object.freeze(target)
}

export async function normalizeEngagementTarget(value, {
  lstatImpl = lstat,
  realpathImpl = realpath,
  resolveRuntimeIdentity,
} = {}) {
  if (typeof value === 'string') {
    if (URI_SCHEME.test(value)) {
      if (!value.toLowerCase().startsWith('https://')) {
        fail('ENGAGEMENT_TARGET_INVALID', 'network engagement targets require HTTPS')
      }
      return Object.freeze({ kind: 'https', locator: canonicalHttpsLocator(value, 'engagement target') })
    }
    return normalizeLocalTarget(value, undefined, { lstatImpl, realpathImpl })
  }
  if (!exactObject(value, ['kind', 'locator']) || !TARGET_KINDS.has(value.kind)) {
    fail('ENGAGEMENT_TARGET_INVALID', 'engagement target must be a locator string or exact supported target record')
  }
  if (value.kind === 'repository' || value.kind === 'artifact') {
    return normalizeLocalTarget(value.locator, value.kind, { lstatImpl, realpathImpl })
  }
  if (value.kind === 'https' || value.kind === 'browser') {
    return Object.freeze({ kind: value.kind, locator: canonicalHttpsLocator(value.locator, 'engagement target') })
  }
  if (value.kind === 'process') {
    return bindRuntimeIdentity(value.kind, normalizeProcessLocator(value.locator), resolveRuntimeIdentity)
  }
  return bindRuntimeIdentity(value.kind, normalizeDeviceLocator(value.locator), resolveRuntimeIdentity)
}

export function canonicalEngagementJson(value) {
  const rendered = stableJson(value, 0)
  return rendered.endsWith('\n') ? rendered.slice(0, -1) : rendered
}

export function digestEngagementValue(value) {
  return createHash('sha256').update(canonicalEngagementJson(value), 'utf8').digest('hex')
}

export function canonicalEngagementTarget(value) {
  assertCanonicalTargetSemantics(value)
  return canonicalEngagementJson(value)
}

export function digestEngagementTarget(value) {
  return createHash('sha256').update(canonicalEngagementTarget(value), 'utf8').digest('hex')
}

function assertSortedReferences(values, label) {
  if (
    !Array.isArray(values)
    || values.some((value) => typeof value !== 'string' || !REFERENCE.test(value))
    || values.some((value, index) => index > 0 && values[index - 1] >= value)
  ) {
    fail('ENGAGEMENT_REFERENCE_INVALID', `${label} must be unique bounded references in canonical order`)
  }
}

export function assertSupportedEngagementCredentialReferences(values) {
  if (
    !Array.isArray(values)
    || values.some((value) => typeof value !== 'string' || !SUPPORTED_CREDENTIAL_REFERENCE.test(value))
  ) {
    fail(
      'ENGAGEMENT_REFERENCE_SCHEME_UNSUPPORTED',
      'new engagements require a browser or browser-session credential reference with an executable adapter',
    )
  }
  return values
}

export function assertValidEngagementIntake(value) {
  assertSchema(validateIntakeSchema, value, 'engagement intake')
  assertTimestamp(value.declared_at, 'engagement intake declared_at')
  assertBoundedText(value.statement, 'engagement statement', MAX_STATEMENT_BYTES, { naturalLanguage: true })
  assertAffirmativeAuthority(value.statement)
  assertAuthorizationProfileBinding(value)
  assertBoundedText(value.objective, 'engagement objective', MAX_OBJECTIVE_BYTES)
  assertCanonicalTargetSemantics(value.target)
  assertAuthorizationProfileTargetBinding(value)
  assertSortedReferences(value.credential_references, 'credential_references')
  assertSupportedEngagementCredentialReferences(value.credential_references)
  for (const input of value.inputs) {
    assertLocalFilesystemEndpoint(input.locator, 'engagement input locator')
    if (!isAbsolute(input.locator) || resolve(input.locator) !== input.locator) {
      fail('ENGAGEMENT_INPUT_INVALID', 'engagement input locators must be canonical absolute local paths')
    }
    assertSha256(input.sha256, 'engagement input sha256')
    if (!Number.isSafeInteger(input.size_bytes) || input.size_bytes < 0 || input.size_bytes > MAX_INPUT_BYTES) {
      fail('ENGAGEMENT_INPUT_INVALID', 'engagement input size_bytes is invalid')
    }
  }
  return value
}

export function assertValidEngagementAuthority(value) {
  assertSchema(validateAuthoritySchema, value, 'engagement authority')
  assertTimestamp(value.declared_at, 'engagement authority declared_at')
  assertBoundedText(value.statement, 'engagement statement', MAX_STATEMENT_BYTES, { naturalLanguage: true })
  assertAffirmativeAuthority(value.statement)
  assertAuthorizationProfileBinding(value, { authority: true })
  assertBoundedText(value.objective, 'engagement objective', MAX_OBJECTIVE_BYTES)
  assertCanonicalTargetSemantics(value.target)
  assertAuthorizationProfileTargetBinding(value)
  assertSortedReferences(value.credential_references, 'credential_references')
  assertSupportedEngagementCredentialReferences(value.credential_references)
  return value
}

export function assertValidEngagementManifest(value) {
  assertSchema(validateManifestSchema, value, 'engagement manifest')
  assertTimestamp(value.created_at, 'engagement manifest created_at')
  assertBoundedText(value.objective, 'engagement objective', MAX_OBJECTIVE_BYTES)
  assertCanonicalTargetSemantics(value.target)
  return value
}

export function canonicalEngagementAuthority(value) {
  assertValidEngagementAuthority(value)
  return canonicalEngagementJson(value)
}

export function canonicalEngagementIntake(value) {
  assertValidEngagementIntake(value)
  return canonicalEngagementJson(value)
}

export function digestEngagementIntake(value) {
  return createHash('sha256').update(canonicalEngagementIntake(value), 'utf8').digest('hex')
}

export function canonicalEngagementManifest(value) {
  assertValidEngagementManifest(value)
  return canonicalEngagementJson(value)
}

export function digestEngagementManifest(value) {
  return createHash('sha256').update(canonicalEngagementManifest(value), 'utf8').digest('hex')
}

function normalizeCredentialReferences(values) {
  if (!Array.isArray(values)) fail('ENGAGEMENT_REFERENCE_INVALID', 'credentialReferences must be an array')
  const references = [...values]
  if (new Set(references).size !== references.length) {
    fail('ENGAGEMENT_REFERENCE_INVALID', 'credentialReferences cannot contain duplicates')
  }
  references.sort()
  assertSortedReferences(references, 'credentialReferences')
  assertSupportedEngagementCredentialReferences(references)
  return references
}

function sameFileIdentity(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
    && left.nlink === right.nlink
}

async function inspectUnlinkedInput(path) {
  const filesystemRoot = parse(path).root
  let current = filesystemRoot
  let metadata = await lstat(current, { bigint: true })
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    fail('ENGAGEMENT_INPUT_INVALID', 'engagement input has a linked or non-directory filesystem root')
  }
  const parts = relative(filesystemRoot, path).split(/[\\/]/u).filter(Boolean)
  for (const [index, part] of parts.entries()) {
    current = join(current, part)
    metadata = await lstat(current, { bigint: true })
    if (metadata.isSymbolicLink()) {
      fail('ENGAGEMENT_INPUT_INVALID', 'engagement input crosses a symbolic link or junction')
    }
    if (index < parts.length - 1 && !metadata.isDirectory()) {
      fail('ENGAGEMENT_INPUT_INVALID', 'engagement input has a non-directory ancestor')
    }
  }
  if (!metadata.isFile() || metadata.nlink !== 1n || metadata.size < 0n || metadata.size > BigInt(MAX_INPUT_BYTES)) {
    fail('ENGAGEMENT_INPUT_INVALID', 'engagement input must be one bounded regular single-link file')
  }
  const canonical = await realpath(path)
  assertLocalFilesystemEndpoint(canonical, 'canonical engagement input locator')
  const equal = process.platform === 'win32'
    ? canonical.toLowerCase() === path.toLowerCase()
    : canonical === path
  if (!equal) fail('ENGAGEMENT_INPUT_INVALID', 'engagement input path is not canonical')
  return metadata
}

async function bindInput(locator) {
  const requested = resolve(locator)
  let before
  let canonical
  try {
    before = await inspectUnlinkedInput(requested)
    canonical = await realpath(requested)
  } catch (cause) {
    fail('ENGAGEMENT_INPUT_UNAVAILABLE', 'engagement input does not exist or cannot be inspected', [], { cause })
  }
  assertLocalFilesystemEndpoint(canonical, 'canonical engagement input locator')
  if (
    canonical !== requested
    || !before.isFile()
    || before.isSymbolicLink()
    || before.nlink !== 1n
    || before.size < 0n
    || before.size > BigInt(MAX_INPUT_BYTES)
  ) {
    fail('ENGAGEMENT_INPUT_INVALID', 'engagement input must be one canonical bounded regular single-link file')
  }

  const flags = FS_CONSTANTS.O_RDONLY | (FS_CONSTANTS.O_NOFOLLOW ?? 0)
  let handle
  try {
    handle = await open(canonical, flags)
    const heldBefore = await handle.stat({ bigint: true })
    if (!heldBefore.isFile() || heldBefore.nlink !== 1n || !sameFileIdentity(before, heldBefore)) {
      fail('ENGAGEMENT_INPUT_CHANGED', 'engagement input identity changed before it was read')
    }
    const hash = createHash('sha256')
    const buffer = Buffer.allocUnsafe(1024 * 1024)
    let position = 0n
    while (position < heldBefore.size) {
      const remaining = heldBefore.size - position
      const wanted = Number(remaining > BigInt(buffer.length) ? BigInt(buffer.length) : remaining)
      const { bytesRead } = await handle.read(buffer, 0, wanted, Number(position))
      if (bytesRead === 0) break
      hash.update(buffer.subarray(0, bytesRead))
      position += BigInt(bytesRead)
    }
    const heldAfter = await handle.stat({ bigint: true })
    const after = await inspectUnlinkedInput(canonical)
    if (
      position !== heldBefore.size
      || !sameFileIdentity(heldBefore, heldAfter)
      || !sameFileIdentity(heldBefore, after)
      || await realpath(canonical) !== canonical
    ) {
      fail('ENGAGEMENT_INPUT_CHANGED', 'engagement input identity or length changed while it was read')
    }
    return { locator: canonical, sha256: hash.digest('hex'), size_bytes: Number(position) }
  } finally {
    await handle?.close()
  }
}

async function normalizeInputs(values) {
  if (!Array.isArray(values)) fail('ENGAGEMENT_INPUT_INVALID', 'inputs must be an array')
  const normalized = []
  for (const value of values) {
    if (!exactObject(value, ['kind', 'locator'])) {
      fail('ENGAGEMENT_INPUT_INVALID', 'each intake input must contain only kind and locator')
    }
    assertLocalFilesystemEndpoint(value.locator, 'engagement input locator')
    if (typeof value.locator !== 'string' || !isAbsolute(value.locator) || resolve(value.locator) !== value.locator) {
      fail('ENGAGEMENT_INPUT_INVALID', 'engagement input locator must be a canonical absolute local path')
    }
    normalized.push({ kind: value.kind, ...await bindInput(value.locator) })
  }
  const locators = normalized.map(({ locator }) => process.platform === 'win32' ? locator.toLowerCase() : locator)
  if (new Set(locators).size !== locators.length) {
    fail('ENGAGEMENT_INPUT_INVALID', 'engagement inputs cannot contain duplicate files')
  }
  return normalized
}

export async function createEngagementIntake({
  operatorId,
  declaredAt,
  statement,
  objective,
  target,
  authorizationProfile,
  credentialReferences = [],
  inputs = [],
}, dependencies = {}) {
  const profile = engagementAuthorizationProfile(authorizationProfile)
  if (profile === undefined) {
    fail('ENGAGEMENT_AUTHORIZATION_PROFILE_INVALID', 'engagement authorization profile is unknown')
  }
  const intake = {
    schema_version: '1.0.0',
    kind: 'last-aperture/engagement-intake',
    operator_id: operatorId,
    declared_at: declaredAt,
    statement,
    objective,
    authorization_profile: authorizationProfile,
    capabilities: [...profile.capabilities],
    effects: [...profile.effects],
    target: await normalizeEngagementTarget(target, dependencies),
    credential_references: normalizeCredentialReferences(credentialReferences),
    inputs: await normalizeInputs(inputs),
  }
  assertValidEngagementIntake(intake)
  return deeplyFrozenCopy(intake)
}

export function assertSha256(value, label) {
  if (!SHA256.test(value ?? '')) fail('ENGAGEMENT_DIGEST_INVALID', `${label} must be a lowercase SHA-256 digest`)
  return value
}
