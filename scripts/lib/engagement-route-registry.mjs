import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'

export const ENGAGEMENT_ROUTE_REGISTRY_VERSION = '2.0.0'

const NODE_ENTRYPOINT = process.execPath
const AUDIT_CLI = fileURLToPath(new URL('../audit.mjs', import.meta.url))
const HTTP_RECON_CLI = fileURLToPath(new URL('../http-recon.mjs', import.meta.url))
const HTTP_AUTHED_CLI = fileURLToPath(new URL('../http-authed.mjs', import.meta.url))
const REVERSE_CLI = fileURLToPath(new URL('../reverse.mjs', import.meta.url))

const TARGET_KINDS = new Set([
  'https',
  'repository',
  'artifact',
  'process',
  'device',
  'browser',
])

const ROUTE_CAPABILITY_IDS = Object.freeze({
  'repository-audit': 'source-review',
  'repository-t1-proof': 't1-proof',
  'repository-t2-service-proof': 't2-service-proof',
  'https-recon': 'https-recon',
  'authenticated-http-browser': 'authenticated-http',
  'adversarial-validation': 'adversarial-validation',
  'bounty-perimeter': 'bounty-perimeter',
  'bounty-recon': 'bounty-live-work',
  'bounty-authorization': 'bounty-live-work',
  'bounty-scan': 'bounty-live-work',
  'bounty-oob': 'bounty-live-work',
  'bounty-proxy': 'bounty-proxy-capture',
  'web-live-metadata-import': 'web-protocol-reconstruction',
  'web-capture-har-import': 'web-protocol-reconstruction',
  'web-capture-burp-import': 'web-protocol-reconstruction',
  'ghidra-analysis': 'ghidra-static-reverse',
  'frida-trace': 'frida-typed-reverse',
  'evidence-artifact-acquisition': 'deployed-evidence-acquisition',
  'evidence-registry-acquisition': 'deployed-evidence-acquisition',
  'evidence-deployed-acquisition': 'deployed-evidence-acquisition',
  'evidence-runtime-acquisition': 'deployed-evidence-acquisition',
  'evidence-bundle-import': 'evidence-bundle-import',
  'protocol-build': 'web-protocol-reconstruction',
  'connector-generate': 'web-protocol-reconstruction',
  'connector-verify': 'web-protocol-reconstruction',
  'provider-execution': 'remote-provider-and-publication',
  'remote-provider-execution': 'remote-provider-and-publication',
  'transparency-publication': 'remote-provider-and-publication',
  'database-conformance': 'database-stack-execution',
})

function routeError(code, message) {
  const error = new Error(message)
  error.name = 'EngagementRouteRegistryError'
  error.code = code
  return error
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const nested of Object.values(value)) deepFreeze(nested)
  return Object.freeze(value)
}

function route({
  id,
  order,
  dependencies = [],
  targetKinds,
  requiredMaterial,
  optionalMaterial = [],
  recoveryMode,
  cli,
  argumentVector,
  availability = Object.freeze({ status: 'AVAILABLE', reason_code: null }),
}) {
  const executable = availability.status === 'AVAILABLE'
  return {
    id,
    capability_id: ROUTE_CAPABILITY_IDS[id],
    order,
    dependencies,
    applicability: { target_kinds: targetKinds },
    required_material: requiredMaterial,
    optional_material: optionalMaterial,
    recovery_mode: recoveryMode,
    availability,
    invocation: executable
      ? {
          public_entrypoint: NODE_ENTRYPOINT,
          argument_vector: [cli, ...argumentVector],
          shell: false,
        }
      : null,
  }
}

function unavailableRoute({ reasonCode, ...options }) {
  return route({
    ...options,
    cli: null,
    argumentVector: [],
    availability: Object.freeze({ status: 'UNAVAILABLE', reason_code: reasonCode }),
  })
}

const ROUTES = [
  route({
    id: 'repository-audit',
    order: 10,
    targetKinds: ['repository'],
    requiredMaterial: ['repository_path', 'output_directory'],
    recoveryMode: 'RESUME_FROM_BUNDLE',
    cli: AUDIT_CLI,
    argumentVector: ['plan', '{repository_path}', '--out', '{output_directory}', '--seal-source', '--json'],
  }),
  unavailableRoute({
    id: 'repository-t1-proof',
    order: 11,
    dependencies: ['repository-audit'],
    targetKinds: ['repository'],
    requiredMaterial: ['audit_bundle_path', 'proof_config_path', 'proof_worker_path'],
    recoveryMode: 'RECONCILE_CONTROLLER_ATTEMPT',
    reasonCode: 'ENGAGEMENT_PROOF_PROFILE_UNAVAILABLE',
  }),
  unavailableRoute({
    id: 'repository-t2-service-proof',
    order: 12,
    dependencies: ['repository-audit'],
    targetKinds: ['repository'],
    requiredMaterial: ['audit_bundle_path', 'service_proof_config_path', 'proof_worker_path'],
    recoveryMode: 'RECONCILE_CONTROLLER_ATTEMPT',
    reasonCode: 'ENGAGEMENT_SERVICE_PROOF_PROFILE_UNAVAILABLE',
  }),
  route({
    id: 'https-recon',
    order: 20,
    targetKinds: ['https', 'browser'],
    requiredMaterial: ['target_url', 'output_directory'],
    recoveryMode: 'RECONCILE_APPEND_ONLY_BUNDLE',
    cli: HTTP_RECON_CLI,
    argumentVector: ['go', '{target_url}', '--out', '{output_directory}', '--json'],
  }),
  route({
    id: 'authenticated-http-browser',
    order: 30,
    dependencies: ['https-recon'],
    targetKinds: ['https', 'browser'],
    requiredMaterial: [
      'scope_path',
      'campaign_grant_sha256',
      'ledger_directory',
      'operator_id',
      'credential_transport',
    ],
    optionalMaterial: [
      'materials_directory',
      'trusted_ledger_record_count',
      'trusted_ledger_head_sha256',
    ],
    recoveryMode: 'REOPEN_APPEND_ONLY_LEDGER',
    cli: HTTP_AUTHED_CLI,
    argumentVector: [
      'campaign-attested',
      '--scope', '{scope_path}',
      '--campaign-grant-sha256', '{campaign_grant_sha256}',
      '--ledger', '{ledger_directory}',
      '--operator-id', '{operator_id}',
      '{credential_transport_flag}',
      '--json',
    ],
  }),
  unavailableRoute({
    id: 'adversarial-validation',
    order: 31,
    targetKinds: ['https', 'browser', 'repository'],
    requiredMaterial: ['adversarial_plan_path', 'enrollment_id'],
    recoveryMode: 'RECONCILE_APPEND_ONLY_LEDGER',
    reasonCode: 'ENGAGEMENT_ADVERSARIAL_GRANT_ADAPTER_UNAVAILABLE',
  }),
  unavailableRoute({
    id: 'bounty-perimeter',
    order: 32,
    targetKinds: ['https', 'browser'],
    requiredMaterial: ['bounty_policy_path', 'bounty_program_configuration'],
    recoveryMode: 'RESUME_FROM_BUNDLE',
    reasonCode: 'ENGAGEMENT_BOUNTY_PERIMETER_ADAPTER_UNAVAILABLE',
  }),
  unavailableRoute({
    id: 'bounty-recon',
    order: 33,
    dependencies: ['bounty-perimeter'],
    targetKinds: ['https', 'browser'],
    requiredMaterial: ['bounty_bundle_path'],
    recoveryMode: 'RECONCILE_APPEND_ONLY_BUNDLE',
    reasonCode: 'BOUNTY_RECON_LIVE_IO_DISABLED',
  }),
  unavailableRoute({
    id: 'bounty-authorization',
    order: 34,
    dependencies: ['bounty-perimeter'],
    targetKinds: ['https', 'browser'],
    requiredMaterial: ['bounty_bundle_path', 'role_registry_path'],
    recoveryMode: 'RECONCILE_APPEND_ONLY_BUNDLE',
    reasonCode: 'BOUNTY_AUTHZ_LIVE_IO_DISABLED',
  }),
  unavailableRoute({
    id: 'bounty-scan',
    order: 35,
    dependencies: ['bounty-perimeter'],
    targetKinds: ['https', 'browser'],
    requiredMaterial: ['bounty_bundle_path', 'role_registry_path'],
    recoveryMode: 'RECONCILE_APPEND_ONLY_LEDGER',
    reasonCode: 'BOUNTY_SCAN_LIVE_IO_DISABLED',
  }),
  unavailableRoute({
    id: 'bounty-oob',
    order: 36,
    dependencies: ['bounty-perimeter'],
    targetKinds: ['https', 'browser'],
    requiredMaterial: ['bounty_bundle_path', 'oob_backend_configuration'],
    recoveryMode: 'RECONCILE_APPEND_ONLY_LEDGER',
    reasonCode: 'BOUNTY_OOB_SESSION_ENROLLMENT_REQUIRED',
  }),
  unavailableRoute({
    id: 'bounty-proxy',
    order: 37,
    dependencies: ['bounty-perimeter'],
    targetKinds: ['https', 'browser'],
    requiredMaterial: ['bounty_bundle_path', 'proxy_capture_path'],
    recoveryMode: 'RESTART_CREATE_ONLY',
    reasonCode: 'BOUNTY_PROXY_CAPTURE_DISABLED',
  }),
  route({
    id: 'web-live-metadata-import',
    order: 40,
    dependencies: ['https-recon'],
    targetKinds: ['https', 'browser'],
    requiredMaterial: [
      'recon_bundle_path',
      'target_origins',
      'target_path_prefix',
      'output_directory',
    ],
    optionalMaterial: [
      'auth_scope_path',
      'auth_ledger_directory',
      'path_literals',
    ],
    recoveryMode: 'RESTART_CREATE_ONLY',
    cli: REVERSE_CLI,
    argumentVector: [
      'web', 'import-live-metadata',
      '--recon-bundle', '{recon_bundle_path}',
      '--auth-scope', '{auth_scope_path?}',
      '--auth-ledger', '{auth_ledger_directory?}',
      '--origin', '{target_origins...}',
      '--path-prefix', '{target_path_prefix}',
      '--path-literal', '{path_literals...}',
      '--out', '{output_directory}', '--json',
    ],
  }),
  route({
    id: 'web-capture-har-import',
    order: 50,
    targetKinds: ['https', 'browser'],
    requiredMaterial: ['har_path', 'target_origins', 'target_path_prefix', 'output_path'],
    optionalMaterial: ['path_literals'],
    recoveryMode: 'RESTART_CREATE_ONLY',
    cli: REVERSE_CLI,
    argumentVector: [
      'web', 'import-har', '--har', '{har_path}',
      '--origin', '{target_origins...}',
      '--path-prefix', '{target_path_prefix}',
      '--path-literal', '{path_literals...}',
      '--out', '{output_path}', '--json',
    ],
  }),
  route({
    id: 'web-capture-burp-import',
    order: 60,
    targetKinds: ['https', 'browser'],
    requiredMaterial: ['burp_path', 'target_origins', 'target_path_prefix', 'output_path'],
    optionalMaterial: ['path_literals'],
    recoveryMode: 'RESTART_CREATE_ONLY',
    cli: REVERSE_CLI,
    argumentVector: [
      'web', 'import-burp', '--burp', '{burp_path}',
      '--origin', '{target_origins...}',
      '--path-prefix', '{target_path_prefix}',
      '--path-literal', '{path_literals...}',
      '--out', '{output_path}', '--json',
    ],
  }),
  route({
    id: 'ghidra-analysis',
    order: 70,
    targetKinds: ['artifact'],
    requiredMaterial: [
      'lab_root',
      'binary_relative_path',
      'artifact_kind',
      'ghidra_path',
      'output_directory',
    ],
    recoveryMode: 'RESTART_CREATE_ONLY',
    cli: REVERSE_CLI,
    argumentVector: [
      'ghidra', 'analyze',
      '--lab-root', '{lab_root}',
      '--binary', '{binary_relative_path}',
      '--artifact-kind', '{artifact_kind}',
      '--ghidra', '{ghidra_path}',
      '--out', '{output_directory}', '--json',
    ],
  }),
  route({
    id: 'frida-trace',
    order: 80,
    targetKinds: ['artifact', 'process', 'device'],
    requiredMaterial: ['trace_plan_path', 'frida_path', 'output_directory'],
    recoveryMode: 'RESTART_CREATE_ONLY',
    cli: REVERSE_CLI,
    argumentVector: [
      'frida', 'trace-plan',
      '--plan', '{trace_plan_path}',
      '--frida', '{frida_path}',
      '--out', '{output_directory}', '--json',
    ],
  }),
  unavailableRoute({
    id: 'evidence-artifact-acquisition',
    order: 81,
    targetKinds: ['repository', 'artifact'],
    requiredMaterial: ['evidence_acquisition_plan_path'],
    recoveryMode: 'RECONCILE_ACQUISITION_PLAN',
    reasonCode: 'ACQUIRE_LIVE_IO_DISABLED',
  }),
  unavailableRoute({
    id: 'evidence-registry-acquisition',
    order: 82,
    targetKinds: ['repository', 'https', 'browser', 'artifact'],
    requiredMaterial: ['evidence_acquisition_plan_path'],
    recoveryMode: 'RECONCILE_ACQUISITION_PLAN',
    reasonCode: 'ACQUIRE_LIVE_IO_DISABLED',
  }),
  unavailableRoute({
    id: 'evidence-deployed-acquisition',
    order: 83,
    targetKinds: ['repository', 'https', 'browser'],
    requiredMaterial: ['evidence_acquisition_plan_path'],
    recoveryMode: 'RECONCILE_ACQUISITION_PLAN',
    reasonCode: 'ACQUIRE_LIVE_IO_DISABLED',
  }),
  unavailableRoute({
    id: 'evidence-runtime-acquisition',
    order: 84,
    targetKinds: ['repository', 'https', 'browser', 'process', 'device'],
    requiredMaterial: ['evidence_acquisition_plan_path'],
    recoveryMode: 'RECONCILE_ACQUISITION_PLAN',
    reasonCode: 'ACQUIRE_LIVE_IO_DISABLED',
  }),
  unavailableRoute({
    id: 'evidence-bundle-import',
    order: 85,
    targetKinds: ['repository'],
    requiredMaterial: ['evidence_bundle_path'],
    recoveryMode: 'RESTART_CREATE_ONLY',
    reasonCode: 'EVIDENCE_BUNDLE_IMPORT_DISABLED',
  }),
  route({
    id: 'protocol-build',
    order: 90,
    targetKinds: ['https', 'browser', 'artifact', 'process', 'device'],
    requiredMaterial: ['output_path'],
    optionalMaterial: ['web_evidence_paths', 'reverse_evidence_paths'],
    recoveryMode: 'RESTART_CREATE_ONLY',
    cli: REVERSE_CLI,
    argumentVector: [
      'protocol', 'build',
      '--web-evidence', '{web_evidence_paths...}',
      '--reverse-evidence', '{reverse_evidence_paths...}',
      '--out', '{output_path}', '--json',
    ],
  }),
  route({
    id: 'connector-generate',
    order: 100,
    dependencies: ['protocol-build'],
    targetKinds: ['https', 'browser', 'artifact', 'process', 'device'],
    requiredMaterial: ['contract_path', 'output_directory'],
    optionalMaterial: ['package_name'],
    recoveryMode: 'RESTART_CREATE_ONLY',
    cli: REVERSE_CLI,
    argumentVector: [
      'protocol', 'generate',
      '--contract', '{contract_path}',
      '--out', '{output_directory}',
      '--name', '{package_name?}', '--json',
    ],
  }),
  route({
    id: 'connector-verify',
    order: 110,
    dependencies: ['connector-generate'],
    targetKinds: ['https', 'browser', 'artifact', 'process', 'device'],
    requiredMaterial: ['package_directory', 'manifest_sha256'],
    recoveryMode: 'REPEAT_READ_ONLY',
    cli: REVERSE_CLI,
    argumentVector: [
      'protocol', 'verify',
      '--package', '{package_directory}',
      '--manifest-sha256', '{manifest_sha256}', '--json',
    ],
  }),
  unavailableRoute({
    id: 'provider-execution',
    order: 120,
    dependencies: ['repository-audit'],
    targetKinds: ['repository'],
    requiredMaterial: ['audit_bundle_path', 'provider_configuration_path'],
    recoveryMode: 'RECONCILE_CONTROLLER_ATTEMPT',
    reasonCode: 'PROVIDER_EXECUTION_DISABLED',
  }),
  unavailableRoute({
    id: 'remote-provider-execution',
    order: 130,
    dependencies: ['repository-audit'],
    targetKinds: ['repository'],
    requiredMaterial: ['audit_bundle_path', 'remote_gateway_configuration_path'],
    recoveryMode: 'RECONCILE_CONTROLLER_ATTEMPT',
    reasonCode: 'REMOTE_EXECUTION_DISABLED',
  }),
  unavailableRoute({
    id: 'transparency-publication',
    order: 140,
    dependencies: ['repository-audit'],
    targetKinds: ['repository'],
    requiredMaterial: ['audit_bundle_path', 'transparency_configuration_path'],
    recoveryMode: 'RECONCILE_PUBLICATION_RECEIPT',
    reasonCode: 'TRANSPARENCY_PUBLICATION_DISABLED',
  }),
  unavailableRoute({
    id: 'database-conformance',
    order: 150,
    targetKinds: ['repository'],
    requiredMaterial: ['database_configuration_path'],
    recoveryMode: 'RECONCILE_CONTROLLER_ATTEMPT',
    reasonCode: 'DATABASE_EXECUTION_DISABLED',
  }),
]

function assertRegistry(routes) {
  const ids = new Set()
  let priorOrder = -1
  for (const descriptor of routes) {
    if (ids.has(descriptor.id) || descriptor.order <= priorOrder) {
      throw routeError('ENGAGEMENT_ROUTE_REGISTRY_INVALID', 'route ids and order must be unique and increasing')
    }
    if (typeof descriptor.capability_id !== 'string' || descriptor.capability_id.length === 0) {
      throw routeError('ENGAGEMENT_ROUTE_REGISTRY_INVALID', `route ${descriptor.id} has no release capability binding`)
    }
    if (
      !['AVAILABLE', 'UNAVAILABLE'].includes(descriptor.availability?.status)
      || (descriptor.availability.status === 'AVAILABLE' && (
        descriptor.availability.reason_code !== null
        || descriptor.invocation === null
      ))
      || (descriptor.availability.status === 'UNAVAILABLE' && (
        !/^[A-Z][A-Z0-9_]{2,127}$/u.test(descriptor.availability.reason_code ?? '')
        || descriptor.invocation !== null
      ))
    ) {
      throw routeError('ENGAGEMENT_ROUTE_REGISTRY_INVALID', `route ${descriptor.id} has an invalid availability declaration`)
    }
    for (const dependency of descriptor.dependencies) {
      if (!ids.has(dependency)) {
        throw routeError(
          'ENGAGEMENT_ROUTE_REGISTRY_INVALID',
          `route ${descriptor.id} dependency ${dependency} must precede it`,
        )
      }
    }
    ids.add(descriptor.id)
    priorOrder = descriptor.order
  }
}

assertRegistry(ROUTES)

export const ENGAGEMENT_ROUTE_REGISTRY = deepFreeze(ROUTES)

const ROUTES_BY_ID = new Map(ENGAGEMENT_ROUTE_REGISTRY.map((descriptor) => [descriptor.id, descriptor]))

function cloneDescriptor(descriptor) {
  return {
    ...descriptor,
    dependencies: [...descriptor.dependencies],
    applicability: { target_kinds: [...descriptor.applicability.target_kinds] },
    required_material: [...descriptor.required_material],
    optional_material: [...descriptor.optional_material],
    availability: { ...descriptor.availability },
    invocation: descriptor.invocation === null
      ? null
      : {
          ...descriptor.invocation,
          argument_vector: [...descriptor.invocation.argument_vector],
        },
  }
}

export function getEngagementRouteRegistry() {
  return ENGAGEMENT_ROUTE_REGISTRY.map(cloneDescriptor)
}

function stringSet(values, label, errorCode) {
  if (!Array.isArray(values) && !(values instanceof Set)) {
    throw routeError(errorCode, `${label} must be an array or Set of strings`)
  }
  const result = new Set()
  for (const value of values) {
    if (typeof value !== 'string' || value.length === 0) {
      throw routeError(errorCode, `${label} must contain non-empty strings`)
    }
    result.add(value)
  }
  return result
}

export function planEngagementRoutes({
  targetKinds = [],
  availableMaterial = [],
  completedRoutes = [],
} = {}) {
  const kinds = stringSet(targetKinds, 'targetKinds', 'ENGAGEMENT_ROUTE_TARGET_KIND_INVALID')
  if (kinds.size === 0 || [...kinds].some((kind) => !TARGET_KINDS.has(kind))) {
    throw routeError(
      'ENGAGEMENT_ROUTE_TARGET_KIND_INVALID',
      `targetKinds must use declared capability kinds: ${[...TARGET_KINDS].join(', ')}`,
    )
  }
  const available = stringSet(
    availableMaterial,
    'availableMaterial',
    'ENGAGEMENT_ROUTE_MATERIAL_INVALID',
  )
  const completed = stringSet(
    completedRoutes,
    'completedRoutes',
    'ENGAGEMENT_ROUTE_COMPLETION_INVALID',
  )
  for (const routeId of completed) {
    const descriptor = ROUTES_BY_ID.get(routeId)
    if (descriptor === undefined || descriptor.availability.status !== 'AVAILABLE') {
      throw routeError('ENGAGEMENT_ROUTE_COMPLETION_INVALID', `unknown completed route: ${routeId}`)
    }
  }

  return ENGAGEMENT_ROUTE_REGISTRY.map((descriptor) => {
    const applicable = descriptor.applicability.target_kinds.some((kind) => kinds.has(kind))
    const base = {
      route_id: descriptor.id,
      order: descriptor.order,
      dependencies: [...descriptor.dependencies],
      required_material: [...descriptor.required_material],
      recovery_mode: descriptor.recovery_mode,
      availability: { ...descriptor.availability },
      missing_material: [],
      waiting_for_routes: [],
      unavailable_reason: null,
    }
    if (!applicable) return { ...base, status: 'NOT_APPLICABLE' }
    if (completed.has(descriptor.id)) return { ...base, status: 'COMPLETED' }
    if (descriptor.availability.status === 'UNAVAILABLE') {
      return {
        ...base,
        status: 'UNAVAILABLE',
        unavailable_reason: descriptor.availability.reason_code,
      }
    }

    const missingMaterial = descriptor.required_material.filter((name) => !available.has(name))
    if (
      descriptor.id === 'protocol-build'
      && !available.has('web_evidence_paths')
      && !available.has('reverse_evidence_paths')
    ) {
      missingMaterial.push('web_evidence_paths', 'reverse_evidence_paths')
    }
    if (missingMaterial.length > 0) {
      return { ...base, status: 'WAITING_FOR_MATERIAL', missing_material: missingMaterial }
    }

    const waitingForRoutes = descriptor.dependencies.filter((routeId) => !completed.has(routeId))
    if (waitingForRoutes.length > 0) {
      return { ...base, status: 'WAITING_FOR_DEPENDENCY', waiting_for_routes: waitingForRoutes }
    }
    return { ...base, status: 'READY' }
  })
}

function assertMaterialObject(material) {
  if (
    material === null
    || typeof material !== 'object'
    || Array.isArray(material)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(material))
  ) {
    throw routeError('ENGAGEMENT_ROUTE_MATERIAL_INVALID', 'route material must be a plain object')
  }
}

function validateMaterialKeys(descriptor, material) {
  const allowed = new Set([...descriptor.required_material, ...descriptor.optional_material])
  const unknown = Object.keys(material).filter((name) => !allowed.has(name)).sort()
  if (unknown.length > 0) {
    throw routeError('ENGAGEMENT_ROUTE_MATERIAL_UNKNOWN', `unknown material for ${descriptor.id}: ${unknown[0]}`)
  }
  const missing = descriptor.required_material.filter((name) => !Object.hasOwn(material, name))
  if (missing.length > 0) {
    throw routeError('ENGAGEMENT_ROUTE_MATERIAL_REQUIRED', `missing material for ${descriptor.id}: ${missing[0]}`)
  }
}

function scalar(material, name) {
  const value = material[name]
  if (typeof value !== 'string' || value.length === 0 || value.includes('\0')) {
    throw routeError('ENGAGEMENT_ROUTE_MATERIAL_INVALID', `${name} must be a non-empty string without NUL`)
  }
  return value
}

function optionalScalar(material, name) {
  if (!Object.hasOwn(material, name)) return undefined
  return scalar(material, name)
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

function targetPathPrefix(material) {
  const value = scalar(material, 'target_path_prefix')
  if (
    value.length > 2048
    || !value.startsWith('/')
    || /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u.test(value)
    || ambiguousEncodedPath(value)
    || /%(?![0-9a-f]{2})/iu.test(value)
  ) {
    throw routeError('ENGAGEMENT_ROUTE_MATERIAL_INVALID', 'target_path_prefix must be a canonical raw URL pathname')
  }
  let parsed
  try { parsed = new URL(value, 'https://last-aperture.invalid/') } catch {
    throw routeError('ENGAGEMENT_ROUTE_MATERIAL_INVALID', 'target_path_prefix must be a canonical raw URL pathname')
  }
  if (
    parsed.origin !== 'https://last-aperture.invalid'
    || parsed.pathname !== value
    || parsed.search
    || parsed.hash
  ) {
    throw routeError('ENGAGEMENT_ROUTE_MATERIAL_INVALID', 'target_path_prefix must be a canonical raw URL pathname')
  }
  return value
}

function compareStrings(left, right) {
  if (left < right) return -1
  if (left > right) return 1
  return 0
}

function list(material, name, { required = true } = {}) {
  if (!Object.hasOwn(material, name) && !required) return []
  const value = material[name]
  if (!Array.isArray(value) || (required && value.length === 0)) {
    throw routeError(
      'ENGAGEMENT_ROUTE_MATERIAL_INVALID',
      `${name} must be ${required ? 'a non-empty' : 'an'} array of strings`,
    )
  }
  const values = value.map((entry) => {
    if (typeof entry !== 'string' || entry.length === 0 || entry.includes('\0')) {
      throw routeError('ENGAGEMENT_ROUTE_MATERIAL_INVALID', `${name} must contain non-empty strings without NUL`)
    }
    return entry
  })
  return [...new Set(values)].sort(compareStrings)
}

function repeatArguments(flag, values) {
  return values.flatMap((value) => [flag, value])
}

function assertSha256(value, name) {
  if (!/^[a-f0-9]{64}$/.test(value)) {
    throw routeError('ENGAGEMENT_ROUTE_MATERIAL_INVALID', `${name} must be a lowercase SHA-256 digest`)
  }
  return value
}

function invocation(cli, arguments_) {
  return {
    public_entrypoint: NODE_ENTRYPOINT,
    arguments: [cli, ...arguments_],
    shell: false,
  }
}

const BUILDERS = new Map([
  ['repository-audit', (material) => invocation(AUDIT_CLI, [
    'plan', scalar(material, 'repository_path'),
    '--out', scalar(material, 'output_directory'),
    '--seal-source',
    '--json',
  ])],
  ['https-recon', (material) => invocation(HTTP_RECON_CLI, [
    'go', scalar(material, 'target_url'),
    '--out', scalar(material, 'output_directory'),
    '--json',
  ])],
  ['authenticated-http-browser', (material) => {
    const transport = scalar(material, 'credential_transport')
    if (!['browser', 'stdin'].includes(transport)) {
      throw routeError(
        'ENGAGEMENT_ROUTE_MATERIAL_INVALID',
        'credential_transport must be browser or stdin',
      )
    }
    const trustedCount = optionalScalar(material, 'trusted_ledger_record_count')
    const trustedHead = optionalScalar(material, 'trusted_ledger_head_sha256')
    if ((trustedCount === undefined) !== (trustedHead === undefined)) {
      throw routeError(
        'ENGAGEMENT_ROUTE_MATERIAL_INVALID',
        'trusted ledger record count and head SHA-256 must be supplied together',
      )
    }
    if (trustedCount !== undefined && !/^(0|[1-9][0-9]*)$/.test(trustedCount)) {
      throw routeError('ENGAGEMENT_ROUTE_MATERIAL_INVALID', 'trusted_ledger_record_count must be an integer')
    }
    if (trustedHead !== undefined) assertSha256(trustedHead, 'trusted_ledger_head_sha256')

    const arguments_ = [
      'campaign-attested',
      '--scope', scalar(material, 'scope_path'),
      '--campaign-grant-sha256', assertSha256(
        scalar(material, 'campaign_grant_sha256'),
        'campaign_grant_sha256',
      ),
      '--ledger', scalar(material, 'ledger_directory'),
      '--operator-id', scalar(material, 'operator_id'),
      transport === 'browser' ? '--credential-browser' : '--credential-stdin',
    ]
    const materialsDirectory = optionalScalar(material, 'materials_directory')
    if (materialsDirectory !== undefined) arguments_.push('--materials', materialsDirectory)
    if (trustedCount !== undefined) {
      arguments_.push(
        '--trusted-ledger-record-count', trustedCount,
        '--trusted-ledger-head-sha256', trustedHead,
      )
    }
    arguments_.push('--json')
    return invocation(HTTP_AUTHED_CLI, arguments_)
  }],
  ['web-live-metadata-import', (material) => {
    const authScopePath = optionalScalar(material, 'auth_scope_path')
    const authLedgerDirectory = optionalScalar(material, 'auth_ledger_directory')
    if ((authScopePath === undefined) !== (authLedgerDirectory === undefined)) {
      throw routeError(
        'ENGAGEMENT_ROUTE_MATERIAL_INVALID',
        'live authenticated metadata requires both scope and ledger paths',
      )
    }
    const arguments_ = [
      'web', 'import-live-metadata',
      '--recon-bundle', scalar(material, 'recon_bundle_path'),
    ]
    if (authScopePath !== undefined) {
      arguments_.push('--auth-scope', authScopePath, '--auth-ledger', authLedgerDirectory)
    }
    arguments_.push(
      ...repeatArguments('--origin', list(material, 'target_origins')),
      '--path-prefix', targetPathPrefix(material),
      ...repeatArguments('--path-literal', list(material, 'path_literals', { required: false })),
      '--out', scalar(material, 'output_directory'),
      '--json',
    )
    return invocation(REVERSE_CLI, arguments_)
  }],
  ['web-capture-har-import', (material) => invocation(REVERSE_CLI, [
    'web', 'import-har',
    '--har', scalar(material, 'har_path'),
    ...repeatArguments('--origin', list(material, 'target_origins')),
    '--path-prefix', targetPathPrefix(material),
    ...repeatArguments('--path-literal', list(material, 'path_literals', { required: false })),
    '--out', scalar(material, 'output_path'),
    '--json',
  ])],
  ['web-capture-burp-import', (material) => invocation(REVERSE_CLI, [
    'web', 'import-burp',
    '--burp', scalar(material, 'burp_path'),
    ...repeatArguments('--origin', list(material, 'target_origins')),
    '--path-prefix', targetPathPrefix(material),
    ...repeatArguments('--path-literal', list(material, 'path_literals', { required: false })),
    '--out', scalar(material, 'output_path'),
    '--json',
  ])],
  ['ghidra-analysis', (material) => invocation(REVERSE_CLI, [
    'ghidra', 'analyze',
    '--lab-root', scalar(material, 'lab_root'),
    '--binary', scalar(material, 'binary_relative_path'),
    '--artifact-kind', scalar(material, 'artifact_kind'),
    '--ghidra', scalar(material, 'ghidra_path'),
    '--out', scalar(material, 'output_directory'),
    '--json',
  ])],
  ['frida-trace', (material) => invocation(REVERSE_CLI, [
    'frida', 'trace-plan',
    '--plan', scalar(material, 'trace_plan_path'),
    '--frida', scalar(material, 'frida_path'),
    '--out', scalar(material, 'output_directory'),
    '--json',
  ])],
  ['protocol-build', (material) => {
    const webEvidence = list(material, 'web_evidence_paths', { required: false })
    const reverseEvidence = list(material, 'reverse_evidence_paths', { required: false })
    if (webEvidence.length + reverseEvidence.length === 0) {
      throw routeError(
        'ENGAGEMENT_ROUTE_MATERIAL_REQUIRED',
        'protocol-build requires at least one web or reverse evidence path',
      )
    }
    return invocation(REVERSE_CLI, [
      'protocol', 'build',
      ...repeatArguments('--web-evidence', webEvidence),
      ...repeatArguments('--reverse-evidence', reverseEvidence),
      '--out', scalar(material, 'output_path'),
      '--json',
    ])
  }],
  ['connector-generate', (material) => {
    const arguments_ = [
      'protocol', 'generate',
      '--contract', scalar(material, 'contract_path'),
      '--out', scalar(material, 'output_directory'),
    ]
    const packageName = optionalScalar(material, 'package_name')
    if (packageName !== undefined) arguments_.push('--name', packageName)
    arguments_.push('--json')
    return invocation(REVERSE_CLI, arguments_)
  }],
  ['connector-verify', (material) => invocation(REVERSE_CLI, [
    'protocol', 'verify',
    '--package', scalar(material, 'package_directory'),
    '--manifest-sha256', assertSha256(scalar(material, 'manifest_sha256'), 'manifest_sha256'),
    '--json',
  ])],
])

export function buildEngagementRouteInvocation(routeId, material) {
  if (typeof routeId !== 'string' || !ROUTES_BY_ID.has(routeId)) {
    throw routeError('ENGAGEMENT_ROUTE_UNKNOWN', `unknown engagement route: ${String(routeId)}`)
  }
  const descriptor = ROUTES_BY_ID.get(routeId)
  if (descriptor.availability.status !== 'AVAILABLE') {
    throw routeError(
      'ENGAGEMENT_ROUTE_UNAVAILABLE',
      `engagement route ${routeId} is unavailable: ${descriptor.availability.reason_code}`,
    )
  }
  assertMaterialObject(material)
  validateMaterialKeys(descriptor, material)
  return BUILDERS.get(routeId)(material)
}

export function renderEngagementSkillRouteInventory(capabilityRegistry) {
  const releaseCapabilities = new Map(
    (capabilityRegistry?.capabilities ?? []).map((capability) => [capability.id, capability]),
  )
  const inventory = ENGAGEMENT_ROUTE_REGISTRY.map((descriptor) => {
    const release = releaseCapabilities.get(descriptor.capability_id)
    if (release === undefined) {
      throw routeError(
        'ENGAGEMENT_ROUTE_CAPABILITY_UNKNOWN',
        `route ${descriptor.id} references unknown capability ${descriptor.capability_id}`,
      )
    }
    return {
      route_id: descriptor.id,
      capability_id: descriptor.capability_id,
      capability_status: release.status,
      unified_status: descriptor.availability.status,
      unavailable_reason: descriptor.availability.reason_code,
    }
  })
  const digest = createHash('sha256').update(JSON.stringify(inventory), 'utf8').digest('hex')
  return `<!-- ENGAGEMENT_ROUTE_INVENTORY_SHA256: ${digest} -->`
}
