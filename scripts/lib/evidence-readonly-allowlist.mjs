// The adapter never receives a command. It names an operation and this table
// builds the vector, so a mutating command is unconstructible rather than
// merely unwritten. assertReadOnlyArgv is the second gate, for the day someone
// adds an operation here that smuggles one in.
export const MUTATING_VERBS = Object.freeze(new Set([
  'annotate', 'apply', 'attach', 'autoscale', 'cordon', 'cp', 'create',
  'debug', 'delete', 'deploy', 'drain', 'edit', 'expose', 'label', 'patch',
  'port-forward', 'proxy', 'replace', 'rollout', 'run', 'scale', 'set',
  'taint', 'uncordon', 'update', 'upsert', 'import', 'purge', 'reset',
]))

const NAME = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/
const KIND = /^[a-z][a-z0-9.-]{0,62}$/
const ALIAS = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$/
const ABSOLUTE_PATH = /^\/[A-Za-z0-9._/-]{0,1023}$/
const SELECT_ONLY = /^SELECT\s+[A-Za-z0-9_ ,.()*]+\s+FROM\s+[A-Za-z0-9_]+(?:\s+[A-Za-z0-9_ ,.'=<>!()%-]+)?$/i
const STATEFUL_SOQL = /\b(?:FOR\s+(?:UPDATE|VIEW|REFERENCE)|UPDATE\s+(?:TRACKING|VIEWSTAT))\b/i

function checked(value, pattern, label) {
  const text = String(value ?? '')
  if (!pattern.test(text)) {
    throw new Error(`invalid ${label}: ${JSON.stringify(value)}`)
  }
  return text
}

function checkedReadOnlySoql(value) {
  const soql = checked(value, SELECT_ONLY, 'SOQL query; only a single SELECT is permitted')
  if (STATEFUL_SOQL.test(soql)) {
    throw new Error('invalid SOQL query: stateful SELECT clauses are not read-only')
  }
  return soql
}

// The read commands a runtime inspection may execute inside a container, and
// nothing else. `sh -c` appears once, for the env-key projection, and its
// script is a constant rather than a parameter.
const ALLOWED_EXEC_COMMANDS = Object.freeze([
  ['cat'],
  ['ls', '-la'],
  ['ps', 'ax'],
  ['sh', '-c', 'env | cut -d= -f1'],
])

export const READ_ONLY_OPERATIONS = Object.freeze(new Map([
  ['k8s.namespaces', {
    cli: 'kubectl',
    verb: 'get',
    objects: 16,
    argv: () => ['get', 'namespaces', '-o', 'json'],
  }],
  ['k8s.resources', {
    cli: 'kubectl',
    verb: 'get',
    objects: 64,
    argv: ({ kind, namespace }) => [
      'get', checked(kind, KIND, 'kind'),
      '-n', checked(namespace, NAME, 'namespace'),
      '-o', 'json',
    ],
  }],
  ['k8s.resource', {
    cli: 'kubectl',
    verb: 'get',
    objects: 1,
    argv: ({ kind, name, namespace }) => [
      'get', checked(kind, KIND, 'kind'), checked(name, NAME, 'name'),
      '-n', checked(namespace, NAME, 'namespace'),
      '-o', 'json',
    ],
  }],
  ['k8s.api-resources', {
    cli: 'kubectl',
    verb: 'api-resources',
    objects: 1,
    argv: () => ['api-resources', '-o', 'wide'],
  }],
  ['k8s.auth-can-i', {
    cli: 'kubectl',
    verb: 'auth',
    objects: 1,
    argv: ({ namespace }) => ['auth', 'can-i', '--list', '-n', checked(namespace, NAME, 'namespace')],
  }],
  ['sf.org-display', {
    cli: 'sf',
    verb: 'org',
    objects: 1,
    argv: ({ alias }) => ['org', 'display', '--json', '-o', checked(alias, ALIAS, 'alias')],
  }],
  ['sf.query', {
    cli: 'sf',
    verb: 'data',
    objects: 64,
    argv: ({ alias, soql }) => [
      'data', 'query', '--json',
      '-o', checked(alias, ALIAS, 'alias'),
      '-q', checkedReadOnlySoql(soql),
    ],
  }],
  ['runtime.read-file', {
    cli: 'kubectl',
    verb: 'exec',
    objects: 1,
    argv: ({ namespace, pod, container, path }) => [
      'exec', '-n', checked(namespace, NAME, 'namespace'),
      checked(pod, NAME, 'pod'), '-c', checked(container, NAME, 'container'),
      '--', 'cat', checked(path, ABSOLUTE_PATH, 'path'),
    ],
  }],
  ['runtime.list-directory', {
    cli: 'kubectl',
    verb: 'exec',
    objects: 1,
    argv: ({ namespace, pod, container, path }) => [
      'exec', '-n', checked(namespace, NAME, 'namespace'),
      checked(pod, NAME, 'pod'), '-c', checked(container, NAME, 'container'),
      '--', 'ls', '-la', checked(path, ABSOLUTE_PATH, 'path'),
    ],
  }],
  ['runtime.process-list', {
    cli: 'kubectl',
    verb: 'exec',
    objects: 1,
    argv: ({ namespace, pod, container }) => [
      'exec', '-n', checked(namespace, NAME, 'namespace'),
      checked(pod, NAME, 'pod'), '-c', checked(container, NAME, 'container'),
      '--', 'ps', 'ax',
    ],
  }],
  ['runtime.env-keys', {
    cli: 'kubectl',
    verb: 'exec',
    objects: 1,
    // Key names only. Metadata-only is applied at acquisition rather than
    // trusted to a redaction pass that runs after the values are already local.
    argv: ({ namespace, pod, container }) => [
      'exec', '-n', checked(namespace, NAME, 'namespace'),
      checked(pod, NAME, 'pod'), '-c', checked(container, NAME, 'container'),
      '--', 'sh', '-c', 'env | cut -d= -f1',
    ],
  }],
]))

export function buildReadOnlyCommand(operationId, params = {}) {
  const operation = READ_ONLY_OPERATIONS.get(operationId)
  if (!operation) {
    throw new Error(`operation "${operationId}" is not allowlisted for read-only acquisition`)
  }
  const args = operation.argv(params)
  assertReadOnlyArgv(operation.cli, args)
  return { cli: operation.cli, args, operation_id: operationId, objects: operation.objects }
}

const IMPERSONATION_FLAGS = new Set(['--as', '--as-group', '--as-uid', '--token'])

export function assertReadOnlyArgv(cli, args) {
  const vector = args.map(String)
  const separator = vector.indexOf('--')
  const head = separator === -1 ? vector : vector.slice(0, separator)

  for (const token of head) {
    if (MUTATING_VERBS.has(token) || IMPERSONATION_FLAGS.has(token)) {
      throw new Error(`refusing a command that is not read-only: ${cli} ${vector.join(' ')}`)
    }
  }

  if (separator !== -1) {
    const inner = vector.slice(separator + 1)
    const allowed = ALLOWED_EXEC_COMMANDS.some((template) =>
      template.length <= inner.length
      && template.every((token, index) => inner[index] === token))
    if (!allowed) {
      throw new Error(
        `refusing a command that is not read-only inside the container: ${inner.join(' ')}`,
      )
    }
  }
}
