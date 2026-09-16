import {
  UNLEASH_SWARM_DEFAULT_LIMITS,
  UNLEASH_SWARM_PROTOCOL_VERSION,
  UNLEASH_SWARM_ROLE_SET,
} from './unleash-swarm-contracts.mjs'
import { assertValidUnleashReasoningAdapterIdentity } from './unleash-reasoning-adapter.mjs'

const INPUT_FIELDS = ['assignments']
const ASSIGNMENT_FIELDS = ['roleId', 'adapterIdentity']

function exactDataRecord(value, fields) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return null
  let prototype
  let descriptors
  try {
    prototype = Object.getPrototypeOf(value)
    descriptors = Object.getOwnPropertyDescriptors(value)
  } catch {
    return null
  }
  if (![Object.prototype, null].includes(prototype)) return null
  const keys = Reflect.ownKeys(descriptors)
  if (
    keys.length !== fields.length
    || keys.some((key) => typeof key !== 'string'
      || !fields.includes(key)
      || descriptors[key].enumerable !== true
      || !Object.hasOwn(descriptors[key], 'value'))
  ) return null
  return Object.fromEntries(fields.map((field) => [field, descriptors[field].value]))
}

function deeplyFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deeplyFreeze(child)
  return Object.freeze(value)
}

function normalizeAssignments(value) {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype) {
    throw new TypeError('provider assignments must be one plain dense array')
  }
  const descriptors = Object.getOwnPropertyDescriptors(value)
  const keys = Reflect.ownKeys(descriptors).filter((key) => key !== 'length')
  if (
    keys.length !== value.length
    || keys.some((key, index) => key !== String(index)
      || descriptors[key].enumerable !== true
      || !Object.hasOwn(descriptors[key], 'value'))
  ) throw new TypeError('provider assignments must be one plain dense array')
  const byRole = new Map()
  for (const key of keys) {
    const item = exactDataRecord(descriptors[key].value, ASSIGNMENT_FIELDS)
    if (item === null || typeof item.roleId !== 'string' || byRole.has(item.roleId)) {
      throw new TypeError('provider assignment contains missing, unknown, or duplicate role data')
    }
    assertValidUnleashReasoningAdapterIdentity(item.adapterIdentity)
    byRole.set(item.roleId, structuredClone(item.adapterIdentity))
  }
  const knownRoles = new Set(UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => roleId))
  if ([...byRole.keys()].some((roleId) => !knownRoles.has(roleId))) {
    throw new TypeError('provider assignment names a role outside the sealed role set')
  }
  return byRole
}

export function createUnleashProviderProfile(input = { assignments: [] }) {
  const retained = exactDataRecord(input, INPUT_FIELDS)
  if (retained === null) throw new TypeError('provider profile input requires exactly one assignments field')
  const byRole = normalizeAssignments(retained.assignments)
  const assignments = UNLEASH_SWARM_ROLE_SET.roles.map(({ role_id: roleId }) => {
    const identity = byRole.get(roleId)
    return identity === undefined
      ? {
          role_id: roleId,
          adapter_id: null,
          adapter_version: null,
          adapter_config_sha256: null,
          availability: 'UNAVAILABLE',
          reason_code: 'REASONING_ADAPTER_UNAVAILABLE',
        }
      : {
          role_id: roleId,
          adapter_id: identity.adapter_id,
          adapter_version: identity.adapter_version,
          adapter_config_sha256: identity.adapter_config_sha256,
          availability: 'AVAILABLE',
          reason_code: null,
        }
  })
  return deeplyFreeze({
    schema_version: '1.0.0',
    protocol_version: UNLEASH_SWARM_PROTOCOL_VERSION,
    proposal_kind: 'last-aperture/unleash-proposal',
    role_set_id: UNLEASH_SWARM_ROLE_SET.role_set_id,
    role_set_sha256: UNLEASH_SWARM_ROLE_SET.role_set_sha256,
    roles: structuredClone(UNLEASH_SWARM_ROLE_SET.roles),
    limits: structuredClone(UNLEASH_SWARM_DEFAULT_LIMITS),
    assignments,
    trust: {
      provider_has_target_authority: false,
      provider_has_execution_authority: false,
      provider_output_is_proposal_only: true,
      provider_may_declare_proof: false,
    },
  })
}

export const UNLEASH_PROVIDER_PROTOCOL = createUnleashProviderProfile()
