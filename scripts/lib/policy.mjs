import {
  isAbsolute,
  posix,
  relative,
  resolve,
  win32,
} from 'node:path'

/**
 * External policy kernel for proposed actions. It performs no I/O and dispatches
 * nothing. The caller is responsible for enforcing an allowed decision at a
 * layer the model and repository under audit cannot modify.
 *
 * Design correspondence only (not an OWASP APTS conformance claim):
 * - APTS-SE-001: machine-readable Rules of Engagement validation.
 * - APTS-SE-006: authorization immediately before each proposed action.
 * - APTS-SC-020: an action allowlist external to the model.
 * - APTS-MR-001/MR-010/MR-012/MR-023: repository content and the agent runtime
 *   are untrusted and cannot widen the immutable external policy.
 * - APTS-MR-007: every redirect hop is independently authorized.
 */

export const ACTION_TYPES = Object.freeze([
  'read_file',
  'write_file',
  'execute',
  'network',
])

export const POLICY_MODES = Object.freeze([
  'static',
  'remote_static',
  'test',
  'local_dynamic',
])

const ACTION_TYPE_SET = new Set(ACTION_TYPES)
const POLICY_MODE_SET = new Set(POLICY_MODES)
const NORMALIZED_POLICIES = new WeakSet()
const CONTROL_CHARACTERS = /[\u0000-\u001f\u007f]/
const SHELL_CONTROL = /(?:&&|\|\||[;&|<>`]|\$\()/
const SAFE_PROGRAM = /^[A-Za-z0-9._-]+$/
const POLICY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/
const SHELL_PROGRAMS = new Set([
  'bash',
  'cmd',
  'cmd.exe',
  'fish',
  'powershell',
  'powershell.exe',
  'pwsh',
  'sh',
  'wsl',
  'zsh',
])

export class PolicyValidationError extends Error {
  constructor(issues) {
    const normalized = Array.isArray(issues) ? issues : [issues]
    super(normalized.map((issue) => `${issue.path}: ${issue.message}`).join('; '))
    this.name = 'PolicyValidationError'
    this.code = 'POLICY_INVALID'
    this.issues = deepFreeze(normalized.map((issue) => ({ ...issue })))
  }
}

function issue(path, code, message) {
  throw new PolicyValidationError([{ path, code, message }])
}

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false
  const prototype = Object.getPrototypeOf(value)
  return prototype === Object.prototype || prototype === null
}

function requirePlainObject(value, path) {
  if (!isPlainObject(value)) issue(path, 'TYPE_OBJECT_REQUIRED', 'must be a plain object')
}

function requireExactKeys(value, allowed, required, path) {
  const keys = Object.keys(value)
  for (const key of keys) {
    if (!allowed.includes(key)) {
      issue(`${path}.${key}`, 'UNKNOWN_FIELD', 'is not an allowed policy field')
    }
  }
  for (const key of required) {
    if (!Object.hasOwn(value, key)) {
      issue(`${path}.${key}`, 'REQUIRED_FIELD_MISSING', 'is required')
    }
  }
}

function requireBoolean(value, path) {
  if (typeof value !== 'boolean') issue(path, 'TYPE_BOOLEAN_REQUIRED', 'must be a boolean')
}

function requireString(value, path, { min = 1, max = 4096 } = {}) {
  if (typeof value !== 'string') issue(path, 'TYPE_STRING_REQUIRED', 'must be a string')
  if (value.length < min || value.length > max) {
    issue(path, 'STRING_LENGTH_INVALID', `must contain between ${min} and ${max} characters`)
  }
  if (CONTROL_CHARACTERS.test(value)) {
    issue(path, 'CONTROL_CHARACTER_FORBIDDEN', 'must not contain control characters')
  }
}

function requireArray(value, path, { max = 1024 } = {}) {
  if (!Array.isArray(value)) issue(path, 'TYPE_ARRAY_REQUIRED', 'must be an array')
  if (value.length > max) issue(path, 'ARRAY_TOO_LARGE', `must contain no more than ${max} entries`)
}

function hasForeignAbsoluteSyntax(value) {
  return isAbsolute(value)
    || posix.isAbsolute(value)
    || win32.isAbsolute(value)
    || /^[A-Za-z]:/.test(value)
    || /^\\\\/.test(value)
}

function relativeSegments(value, path) {
  requireString(value, path)
  if (hasForeignAbsoluteSyntax(value)) {
    issue(path, 'ABSOLUTE_PATH_FORBIDDEN', 'must be workspace-relative')
  }

  const segments = value.split(/[\\/]+/).filter((segment) => segment !== '' && segment !== '.')
  if (segments.includes('..')) {
    issue(path, 'PATH_TRAVERSAL_FORBIDDEN', 'must not contain a parent traversal segment')
  }
  if (segments.some((segment) => CONTROL_CHARACTERS.test(segment))) {
    issue(path, 'CONTROL_CHARACTER_FORBIDDEN', 'must not contain control characters')
  }

  return segments
}

function canonicalRelativePath(value, path) {
  const segments = relativeSegments(value, path)
  return segments.length === 0 ? '.' : segments.join('/')
}

function pathIsWithin(child, parent) {
  const relation = relative(parent, child)
  return relation === ''
    || (!relation.startsWith('..') && !isAbsolute(relation))
}

function normalizeWorkspaceRoot(value) {
  requireString(value, 'workspace_root')
  if (!hasForeignAbsoluteSyntax(value)) {
    issue('workspace_root', 'WORKSPACE_ROOT_NOT_ABSOLUTE', 'must be an absolute path')
  }
  return resolve(value)
}

function normalizeFileCapability(value, path) {
  requirePlainObject(value, path)
  requireExactKeys(value, ['enabled', 'roots'], ['enabled', 'roots'], path)
  requireBoolean(value.enabled, `${path}.enabled`)
  requireArray(value.roots, `${path}.roots`)

  const roots = value.roots.map((root, index) =>
    canonicalRelativePath(root, `${path}.roots[${index}]`))
  if (new Set(roots).size !== roots.length) {
    issue(`${path}.roots`, 'DUPLICATE_ENTRY', 'must not contain duplicate roots')
  }
  if (value.enabled && roots.length === 0) {
    issue(`${path}.roots`, 'ALLOWLIST_EMPTY', 'must name at least one root when enabled')
  }
  if (!value.enabled && roots.length !== 0) {
    issue(`${path}.roots`, 'DORMANT_AUTHORITY_FORBIDDEN', 'must be empty when the capability is disabled')
  }

  return { enabled: value.enabled, roots }
}

function validateCommandToken(value, path) {
  requireString(value, path)
  if (SHELL_CONTROL.test(value)) {
    issue(path, 'SHELL_CONTROL_FORBIDDEN', 'must not contain shell or command-control syntax')
  }
}

function normalizeCommandRule(value, path) {
  requirePlainObject(value, path)
  requireExactKeys(value, ['program', 'args'], ['program', 'args'], path)
  requireString(value.program, `${path}.program`, { max: 128 })
  if (!SAFE_PROGRAM.test(value.program)) {
    issue(`${path}.program`, 'PROGRAM_TOKEN_INVALID', 'must be a bare executable token')
  }
  if (SHELL_PROGRAMS.has(value.program.toLowerCase())) {
    issue(`${path}.program`, 'SHELL_PROGRAM_FORBIDDEN', 'shell interpreters are outside this foundation policy')
  }

  requireArray(value.args, `${path}.args`, { max: 64 })
  const args = value.args.map((argument, index) => {
    validateCommandToken(argument, `${path}.args[${index}]`)
    return argument
  })
  return { program: value.program, args }
}

function normalizeExecuteCapability(value, path) {
  requirePlainObject(value, path)
  requireExactKeys(value, ['enabled', 'commands'], ['enabled', 'commands'], path)
  requireBoolean(value.enabled, `${path}.enabled`)
  requireArray(value.commands, `${path}.commands`, { max: 128 })
  const commands = value.commands.map((command, index) =>
    normalizeCommandRule(command, `${path}.commands[${index}]`))
  const identities = commands.map((command) => JSON.stringify(command))
  if (new Set(identities).size !== identities.length) {
    issue(`${path}.commands`, 'DUPLICATE_ENTRY', 'must not contain duplicate command rules')
  }
  if (value.enabled && commands.length === 0) {
    issue(`${path}.commands`, 'ALLOWLIST_EMPTY', 'must name at least one command when enabled')
  }
  if (!value.enabled && commands.length !== 0) {
    issue(`${path}.commands`, 'DORMANT_AUTHORITY_FORBIDDEN', 'must be empty when the capability is disabled')
  }
  return { enabled: value.enabled, commands }
}

function normalizeHost(value, path, scheme) {
  requireString(value, path, { max: 253 })
  if (value.includes('*')) issue(path, 'NETWORK_WILDCARD_FORBIDDEN', 'must be an exact host')
  if (value.includes('/') || value.includes('@')) {
    issue(path, 'NETWORK_HOST_INVALID', 'must contain a host only')
  }

  let parsed
  try {
    parsed = new URL(`${scheme}://${value}`)
  } catch {
    issue(path, 'NETWORK_HOST_INVALID', 'must be a valid host')
  }
  if (!parsed.hostname || parsed.username || parsed.password || parsed.pathname !== '/') {
    issue(path, 'NETWORK_HOST_INVALID', 'must contain a host only')
  }
  return parsed.hostname.toLowerCase()
}

function normalizePathPrefix(value, path) {
  const prefix = value ?? '/'
  requireString(prefix, path)
  if (!prefix.startsWith('/') || prefix.includes('?') || prefix.includes('#')) {
    issue(path, 'NETWORK_PATH_PREFIX_INVALID', 'must be an absolute URL path without query or fragment')
  }
  let parsed
  try {
    parsed = new URL(prefix, 'https://policy.invalid')
  } catch {
    issue(path, 'NETWORK_PATH_PREFIX_INVALID', 'must be a valid URL path')
  }
  if (parsed.pathname !== prefix) {
    issue(path, 'NETWORK_PATH_PREFIX_INVALID', 'must already be URL-normalized')
  }
  return prefix
}

function normalizeDestination(value, path) {
  requirePlainObject(value, path)
  requireExactKeys(
    value,
    ['scheme', 'host', 'ports', 'path_prefix'],
    ['scheme', 'host', 'ports'],
    path,
  )
  if (!['http', 'https'].includes(value.scheme)) {
    issue(`${path}.scheme`, 'NETWORK_SCHEME_FORBIDDEN', 'must be http or https')
  }
  const host = normalizeHost(value.host, `${path}.host`, value.scheme)
  requireArray(value.ports, `${path}.ports`, { max: 128 })
  if (value.ports.length === 0) {
    issue(`${path}.ports`, 'ALLOWLIST_EMPTY', 'must name at least one port')
  }
  const ports = value.ports.map((port, index) => {
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      issue(`${path}.ports[${index}]`, 'NETWORK_PORT_INVALID', 'must be an integer from 1 through 65535')
    }
    return port
  })
  if (new Set(ports).size !== ports.length) {
    issue(`${path}.ports`, 'DUPLICATE_ENTRY', 'must not contain duplicate ports')
  }
  return {
    scheme: value.scheme,
    host,
    ports,
    path_prefix: normalizePathPrefix(value.path_prefix, `${path}.path_prefix`),
  }
}

function normalizeNetworkCapability(value, path) {
  requirePlainObject(value, path)
  requireExactKeys(value, ['enabled', 'destinations'], ['enabled', 'destinations'], path)
  requireBoolean(value.enabled, `${path}.enabled`)
  requireArray(value.destinations, `${path}.destinations`, { max: 256 })
  const destinations = value.destinations.map((destination, index) =>
    normalizeDestination(destination, `${path}.destinations[${index}]`))
  const identities = destinations.map((destination) => JSON.stringify(destination))
  if (new Set(identities).size !== identities.length) {
    issue(`${path}.destinations`, 'DUPLICATE_ENTRY', 'must not contain duplicate destinations')
  }
  if (value.enabled && destinations.length === 0) {
    issue(`${path}.destinations`, 'ALLOWLIST_EMPTY', 'must name at least one destination when enabled')
  }
  if (!value.enabled && destinations.length !== 0) {
    issue(`${path}.destinations`, 'DORMANT_AUTHORITY_FORBIDDEN', 'must be empty when the capability is disabled')
  }
  return { enabled: value.enabled, destinations }
}

function defaultRawPolicy(workspaceRoot) {
  return {
    schema_version: '1.0',
    policy_id: 'default-static',
    mode: 'static',
    workspace_root: workspaceRoot,
    capabilities: {
      read_file: { enabled: true, roots: ['.'] },
      write_file: { enabled: false, roots: [] },
      execute: { enabled: false, commands: [] },
      network: { enabled: false, destinations: [] },
    },
  }
}

function buildNormalizedPolicy(rawPolicy, options) {
  const explicit = rawPolicy !== undefined && rawPolicy !== null
  const policySource = options.policySource ?? (explicit ? null : 'default')
  if (explicit && policySource !== 'external') {
    issue(
      'policy_source',
      'POLICY_SOURCE_UNTRUSTED',
      'explicit policy must be marked external by the trusted orchestrator',
    )
  }

  const trustedRoot = options.workspaceRoot === undefined
    ? undefined
    : normalizeWorkspaceRoot(options.workspaceRoot)
  const raw = explicit
    ? rawPolicy
    : defaultRawPolicy(trustedRoot ?? resolve(process.cwd()))

  requirePlainObject(raw, '$')
  requireExactKeys(
    raw,
    ['schema_version', 'policy_id', 'policy_source', 'mode', 'workspace_root', 'capabilities'],
    ['schema_version', 'policy_id', 'mode', 'workspace_root', 'capabilities'],
    '$',
  )
  if (
    Object.prototype.hasOwnProperty.call(raw, 'policy_source')
    && raw.policy_source !== (explicit ? 'external' : 'default')
  ) {
    issue(
      'policy_source',
      'POLICY_SOURCE_MISMATCH',
      'does not match provenance supplied by the trusted orchestrator',
    )
  }
  if (raw.schema_version !== '1.0') {
    issue('schema_version', 'SCHEMA_VERSION_UNSUPPORTED', 'must equal "1.0"')
  }
  requireString(raw.policy_id, 'policy_id', { max: 128 })
  if (!POLICY_ID.test(raw.policy_id)) {
    issue('policy_id', 'POLICY_ID_INVALID', 'contains unsupported characters')
  }
  if (!POLICY_MODE_SET.has(raw.mode)) {
    issue('mode', 'POLICY_MODE_UNKNOWN', `must be one of ${POLICY_MODES.join(', ')}`)
  }

  const workspaceRoot = normalizeWorkspaceRoot(raw.workspace_root)
  if (trustedRoot !== undefined && workspaceRoot !== trustedRoot) {
    issue(
      'workspace_root',
      'WORKSPACE_ROOT_MISMATCH',
      'does not match the workspace root supplied by the trusted orchestrator',
    )
  }

  requirePlainObject(raw.capabilities, 'capabilities')
  requireExactKeys(
    raw.capabilities,
    ACTION_TYPES,
    ACTION_TYPES,
    'capabilities',
  )
  const capabilities = {
    read_file: normalizeFileCapability(raw.capabilities.read_file, 'capabilities.read_file'),
    write_file: normalizeFileCapability(raw.capabilities.write_file, 'capabilities.write_file'),
    execute: normalizeExecuteCapability(raw.capabilities.execute, 'capabilities.execute'),
    network: normalizeNetworkCapability(raw.capabilities.network, 'capabilities.network'),
  }

  if (
    raw.mode === 'static'
    && (capabilities.write_file.enabled
      || capabilities.execute.enabled
      || capabilities.network.enabled)
  ) {
    issue(
      'capabilities',
      'STATIC_MODE_CONTRADICTION',
      'static mode permits read_file only',
    )
  }
  if (
    raw.mode === 'remote_static'
    && (
      capabilities.write_file.enabled
      || capabilities.execute.enabled
      || !capabilities.network.enabled
    )
  ) {
    issue(
      'capabilities',
      'REMOTE_STATIC_MODE_CONTRADICTION',
      'remote_static mode requires network and permits neither write_file nor execute',
    )
  }
  // Rail 1 confines targets to the tree and localhost, and rail 3 confines
  // proof writes to a security leaf. Both are enforced here rather than left to
  // prose, because test mode is the first mode that can write and execute.
  if (raw.mode === 'test') {
    const rootsAreSecurityLeaves = capabilities.write_file.roots.every(
      (root) => root.split('/').includes('security'),
    )
    if (
      !capabilities.execute.enabled
      || !capabilities.write_file.enabled
      || capabilities.network.enabled
      || !rootsAreSecurityLeaves
    ) {
      issue(
        'capabilities',
        'TEST_MODE_CONTRADICTION',
        'test mode requires execute and write_file under a security leaf, and forbids network',
      )
    }
  }

  return {
    schema_version: '1.0',
    policy_id: raw.policy_id,
    policy_source: explicit ? 'external' : 'default',
    mode: raw.mode,
    workspace_root: workspaceRoot,
    capabilities,
  }
}

function deepFreeze(value) {
  if (value === null || typeof value !== 'object' || Object.isFrozen(value)) return value
  for (const child of Object.values(value)) deepFreeze(child)
  return Object.freeze(value)
}

export function validatePolicy(rawPolicy, options = {}) {
  try {
    buildNormalizedPolicy(rawPolicy, options)
    return deepFreeze({ valid: true, errors: [] })
  } catch (error) {
    if (!(error instanceof PolicyValidationError)) throw error
    return deepFreeze({ valid: false, errors: error.issues.map((entry) => ({ ...entry })) })
  }
}

export function normalizePolicy(rawPolicy, options = {}) {
  const policy = deepFreeze(buildNormalizedPolicy(rawPolicy, options))
  NORMALIZED_POLICIES.add(policy)
  return policy
}

export function createStaticPolicy({ workspaceRoot = process.cwd() } = {}) {
  return normalizePolicy(undefined, { workspaceRoot })
}

function reason(code, message, details = {}) {
  return { code, message, details }
}

function decision(allowed, actionType, reasons, extras = {}) {
  return deepFreeze({
    allowed,
    action_type: actionType ?? 'unknown',
    reasons,
    ...extras,
  })
}

function deny(actionType, code, message, details = {}) {
  return decision(false, actionType, [reason(code, message, details)])
}

function allow(actionType, code, message, extras = {}) {
  return decision(true, actionType, [reason(code, message)], extras)
}

function actionKeys(action, allowed, required) {
  requirePlainObject(action, 'action')
  requireExactKeys(action, allowed, required, 'action')
}

function normalizeActionPath(policy, value) {
  const canonical = canonicalRelativePath(value, 'action.path')
  const absolute = resolve(policy.workspace_root, ...canonical.split('/'))
  if (!pathIsWithin(absolute, policy.workspace_root)) {
    issue('action.path', 'PATH_OUTSIDE_WORKSPACE', 'resolves outside the workspace')
  }
  return { canonical, absolute }
}

function authorizeFile(policy, action, actionType) {
  actionKeys(action, ['type', 'path'], ['type', 'path'])
  const capability = policy.capabilities[actionType]
  if (!capability.enabled) {
    return deny(actionType, 'CAPABILITY_DISABLED', `${actionType} is disabled by policy`)
  }

  let target
  try {
    target = normalizeActionPath(policy, action.path)
  } catch (error) {
    if (!(error instanceof PolicyValidationError)) throw error
    return deny(actionType, error.issues[0].code, error.issues[0].message, {
      field: error.issues[0].path,
    })
  }

  const matchedRoot = capability.roots.find((root) => {
    const absoluteRoot = resolve(policy.workspace_root, ...root.split('/'))
    return pathIsWithin(target.absolute, absoluteRoot)
  })
  if (matchedRoot === undefined) {
    return deny(actionType, 'PATH_NOT_ALLOWED', 'path is outside the capability root allowlist', {
      path: target.canonical,
    })
  }

  return allow(actionType, 'ACTION_ALLOWED', `${actionType} is explicitly allowed`, {
    normalized_action: {
      type: actionType,
      path: target.absolute,
    },
    matched_rule: {
      root: matchedRoot,
    },
    enforcement: {
      realpath_containment_required: true,
      note: 'The dispatcher must resolve symlinks and re-check containment immediately before I/O.',
    },
  })
}

function authorizeExecute(policy, action) {
  actionKeys(action, ['type', 'program', 'args'], ['type', 'program', 'args'])
  const capability = policy.capabilities.execute
  if (!capability.enabled) {
    return deny('execute', 'CAPABILITY_DISABLED', 'execute is disabled by policy')
  }

  let normalized
  try {
    normalized = normalizeCommandRule(
      { program: action.program, args: action.args },
      'action',
    )
  } catch (error) {
    if (!(error instanceof PolicyValidationError)) throw error
    return deny('execute', error.issues[0].code, error.issues[0].message, {
      field: error.issues[0].path,
    })
  }

  const matched = capability.commands.find((command) =>
    command.program === normalized.program
      && command.args.length === normalized.args.length
      && command.args.every((argument, index) => argument === normalized.args[index]))
  if (matched === undefined) {
    return deny('execute', 'COMMAND_NOT_ALLOWED', 'command is not an exact allowlist entry', {
      program: normalized.program,
    })
  }

  return allow('execute', 'ACTION_ALLOWED', 'command is explicitly allowed', {
    normalized_action: {
      type: 'execute',
      program: normalized.program,
      args: [...normalized.args],
    },
    matched_rule: {
      program: matched.program,
      args: [...matched.args],
    },
    enforcement: {
      shell_must_be_false: true,
      exact_argv_required: true,
    },
  })
}

function parseNetworkUrl(value, path) {
  requireString(value, path, { max: 8192 })
  let parsed
  try {
    parsed = new URL(value)
  } catch {
    issue(path, 'NETWORK_URL_INVALID', 'must be an absolute URL')
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    issue(path, 'NETWORK_SCHEME_FORBIDDEN', 'must use http or https')
  }
  if (parsed.username || parsed.password) {
    issue(path, 'NETWORK_CREDENTIALS_FORBIDDEN', 'must not contain URL credentials')
  }
  return parsed
}

function effectivePort(url) {
  if (url.port !== '') return Number(url.port)
  return url.protocol === 'https:' ? 443 : 80
}

function pathPrefixMatches(pathname, prefix) {
  if (prefix === '/') return true
  return pathname === prefix || pathname.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`)
}

function matchingDestination(policy, url) {
  return policy.capabilities.network.destinations.find((destination) =>
    destination.scheme === url.protocol.slice(0, -1)
      && destination.host === url.hostname.toLowerCase()
      && destination.ports.includes(effectivePort(url))
      && pathPrefixMatches(url.pathname, destination.path_prefix))
}

function authorizeNetwork(policy, action) {
  actionKeys(action, ['type', 'url', 'redirects'], ['type', 'url'])
  const capability = policy.capabilities.network
  if (!capability.enabled) {
    return deny('network', 'CAPABILITY_DISABLED', 'network is disabled by policy')
  }
  if (action.redirects !== undefined && !Array.isArray(action.redirects)) {
    return deny('network', 'ACTION_FIELD_INVALID', 'redirects must be an array')
  }
  const redirects = action.redirects ?? []
  if (redirects.length > 10) {
    return deny('network', 'NETWORK_REDIRECT_LIMIT', 'redirect chain exceeds 10 hops')
  }

  const values = [action.url, ...redirects]
  const parsed = []
  for (const [index, value] of values.entries()) {
    let url
    try {
      url = parseNetworkUrl(value, index === 0 ? 'action.url' : `action.redirects[${index - 1}]`)
    } catch (error) {
      if (!(error instanceof PolicyValidationError)) throw error
      return deny('network', error.issues[0].code, error.issues[0].message, {
        field: error.issues[0].path,
      })
    }

    if (parsed.some((previous) => previous.href === url.href)) {
      return deny('network', 'NETWORK_REDIRECT_LOOP', 'redirect chain repeats a URL', {
        redirect_index: index - 1,
      })
    }
    const matched = matchingDestination(policy, url)
    if (matched === undefined) {
      return deny(
        'network',
        index === 0 ? 'NETWORK_DESTINATION_NOT_ALLOWED' : 'NETWORK_REDIRECT_OUT_OF_SCOPE',
        index === 0
          ? 'network destination is outside the allowlist'
          : 'redirect destination is outside the allowlist',
        {
          url: url.href,
          redirect_index: index === 0 ? null : index - 1,
        },
      )
    }
    parsed.push(url)
  }

  return allow('network', 'ACTION_ALLOWED', 'destination and every declared redirect are explicitly allowed', {
    normalized_action: {
      type: 'network',
      url: parsed[0].href,
      redirects: parsed.slice(1).map((url) => url.href),
    },
    enforcement: {
      reauthorize_each_redirect: true,
      dns_resolution_scope_check_required: true,
      note: 'The dispatcher must re-authorize resolved addresses; this pure kernel performs no DNS.',
    },
  })
}

export function authorizeAction(policy, action) {
  if (!NORMALIZED_POLICIES.has(policy)) {
    return deny(
      action?.type,
      'POLICY_NOT_NORMALIZED',
      'authorizeAction accepts only an immutable policy returned by normalizePolicy',
    )
  }
  if (!isPlainObject(action)) {
    return deny(undefined, 'ACTION_INVALID', 'action must be a plain object')
  }
  if (!ACTION_TYPE_SET.has(action.type)) {
    return deny(action.type, 'ACTION_TYPE_UNKNOWN', 'unknown action types are denied fail-closed')
  }

  if (policy.mode === 'static' && action.type !== 'read_file') {
    return deny(
      action.type,
      'STATIC_MODE_READ_ONLY',
      'static mode permits read_file actions only',
    )
  }
  if (
    policy.mode === 'remote_static'
    && !['read_file', 'network'].includes(action.type)
  ) {
    return deny(
      action.type,
      'REMOTE_STATIC_MODE_READ_NETWORK_ONLY',
      'remote_static mode permits only read_file and network actions',
    )
  }

  try {
    if (action.type === 'read_file' || action.type === 'write_file') {
      return authorizeFile(policy, action, action.type)
    }
    if (action.type === 'execute') return authorizeExecute(policy, action)
    if (action.type === 'network') return authorizeNetwork(policy, action)
  } catch (error) {
    if (!(error instanceof PolicyValidationError)) throw error
    return deny(action.type, error.issues[0].code, error.issues[0].message, {
      field: error.issues[0].path,
    })
  }

  return deny(action.type, 'ACTION_TYPE_UNKNOWN', 'unknown action types are denied fail-closed')
}
