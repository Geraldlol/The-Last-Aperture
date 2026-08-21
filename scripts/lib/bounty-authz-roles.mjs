import { readFileSync } from 'node:fs'
import { readFile } from 'node:fs/promises'
import Ajv2020 from 'ajv/dist/2020.js'

const SCHEMA_URL = new URL('../../schemas/bounty-authz-roles.schema.json', import.meta.url)

export const ANONYMOUS_ROLE = Object.freeze({
  id: 'anonymous',
  label: 'unauthenticated',
  auth: { kind: 'none' },
})

let compiledValidator = null

export function assertValidRoleRegistry(value) {
  if (compiledValidator === null) {
    const ajv = new Ajv2020({ allErrors: true, strict: false })
    compiledValidator = ajv.compile(JSON.parse(readFileSync(SCHEMA_URL, 'utf8')))
  }
  if (compiledValidator(value)) return
  const detail = (compiledValidator.errors ?? [])
    .map((error) => `${error.instancePath || '/'} ${error.message}`)
    .join('; ')
  throw new Error(`role registry failed schema validation: ${detail}`)
}

// Credentials live in the environment, never in the registry file, so a registry
// can be committed and a bundle shared without leaking a session. A missing
// variable is a hard error: replaying without the credential would silently turn
// every result into a false ACCESS_DENIED and read as "no bugs here".
export function resolveRoleCredential(role, env = process.env) {
  if (role.auth.kind === 'none') return null
  const name = role.auth.value_env
  const value = env[name]
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(
      `role ${role.id} needs credential from environment variable ${name}, which is unset; refusing to replay unauthenticated and report a false denial`,
    )
  }
  return value
}

export function applyRole(request, role, env = process.env) {
  const headers = { ...request.headers }
  // Strip whatever session the capture carried before applying this role's.
  delete headers.authorization
  delete headers.cookie
  delete headers['x-api-key']
  delete headers['x-auth-token']

  if (role.auth.kind === 'none') {
    return { ...request, headers, applied_role: role.id }
  }
  const value = resolveRoleCredential(role, env)
  if (role.auth.kind === 'header') {
    headers[role.auth.name.toLowerCase()] = value
  } else if (role.auth.kind === 'cookie') {
    headers.cookie = `${role.auth.name}=${value}`
  }
  return { ...request, headers, applied_role: role.id }
}

export function rolesToTest(registry, ownerRoleId) {
  const others = registry.roles.filter((role) => role.id !== ownerRoleId)
  // Anonymous is always tested: "can an unauthenticated caller reach this" is the
  // highest-severity question and the cheapest to answer.
  const hasAnonymous = others.some((role) => role.id === ANONYMOUS_ROLE.id)
  return hasAnonymous ? others : [...others, ANONYMOUS_ROLE]
}

export function findRole(registry, roleId) {
  if (roleId === ANONYMOUS_ROLE.id) return ANONYMOUS_ROLE
  const role = registry.roles.find((entry) => entry.id === roleId)
  if (role === undefined) throw new Error(`unknown role: ${roleId}`)
  return role
}

export async function loadRoleRegistry(path) {
  const registry = JSON.parse(await readFile(path, 'utf8'))
  assertValidRoleRegistry(registry)
  return registry
}
