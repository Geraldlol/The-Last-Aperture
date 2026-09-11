# `deployed` and `runtime` Adapters Implementation Plan (Plan 5 of 5)

> **Superseded security notice (2026-09-03):** Do not execute this historical
> implementation plan as current guidance. Public deployed/runtime acquisition
> `plan` and `run` commands are disabled before argument, bundle, credential,
> stop-state, process, or target access. Review found that planning itself ran a
> PATH-resolved `kubectl version` probe against the ambient context, a hand-edited plan could inject an arbitrary
> executable and arguments, the recorded Kubernetes context did not bind the
> actual cluster, stop-state errors failed open, and metadata-only
> `runtime.read-file` output could persist secrets. The old allowlist,
> attestation, PHI-redaction, and “mutates nothing” claims below are therefore not
> sufficient. Re-enablement requires controller-sealed canonical plans, execution-time
> reconstruction of allowlisted commands, attested target identity, fail-closed
> stop state, and protected/redacted evidence custody plus independent review.
> ADR 0021 separately supersedes every signed-authorization and third-party-
> artifact requirement below: only an authenticated operator target/scope
> statement creates authority; controller permits provide technical binding.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Read live systems — cluster and org configuration as it actually stands, and the contents of a running container — read-only, under attestation, with PHI redaction on by default where PHI is possible, bounded by impact counters and stoppable at any moment.

**Architecture:** Two adapters over one shared safety layer. A controller-side allowlist decides what commands may run: an argument vector is matched against an explicit read-only verb table and refused if it does not match — the adapter cannot construct a mutating command even in principle, because the allowlist is what builds the vector. PHI redaction is a separate module applied to every acquired object before it reaches a bundle, driven by the declared `--phi-scope` and independent of target class, so a non-PHI production system pays no PHI friction. Impact counters and the CLI runner come from Plan 4 unchanged. Every test injects stub `kubectl` and `sf` binaries on `PATH` replaying canned JSON.

**Tech Stack:** Node.js 20+, ESM (`.mjs`), `node:child_process` via Plan 4's runner, `node:test` + `node:assert/strict`.

**Depends on:** Plans 1-4, all committed.

**This is the last plan of Phase 0.** It deliberately does not mutate anything, does not exploit anything, and does not relax a hard rail. Exploitation is Phase 3 and requires the amendment recorded at the end of the design spec, which is out of scope here and must not be implemented from this plan.

## Global Constraints

- Branch: `agent/red-team-audit-v11-existence`. This plan touches no in-flight file.
- Baseline: 2 permanently failing `cloud-iac-fixtures.test.mjs` tests (ripgrep absent). Environmental, not regressions.
- `npm.cmd run lint` → `PASS: R1-R9, SKILL and ledger gate clean.` `npm.cmd run gen -- --check` → `PASS ... (174 slugs)`.
- **Read-only, enforced structurally, not by convention.** The adapter never accepts a command from a caller. It names an operation from a fixed table and the allowlist builds the argument vector. There is no code path that can produce `kubectl delete`.
- **Never `exec` a shell.** Plan 4's `runBoundedCli` refuses a command string.
- **PHI redaction defaults on where PHI is possible.** `--phi-scope possible` and `confirmed` capture metadata only — names, shapes, sizes, hashes and key names, never values or record contents. Capturing contents requires an explicit flag, and `confirmed` requires an acknowledgment on top of it.
- **Impact counters are mandatory for both adapters** and halt acquisition when a cap is exceeded, because an unbounded read against production is an availability risk regardless of intent.
- **`stop` is idempotent and requires no still-valid authority artifact**, matching `http-recon`. The one command an operator needs during an incident must not depend on the thing that may have gone wrong.
- **`PRODUCTION` and `THIRD_PARTY` require explicit acknowledgment.** `THIRD_PARTY` routes through the existing higher-assurance signed-artifact mode; this plan neither creates nor approves those artifacts and refuses to plan without one.
- Locale-independent ordering only: `compareCanonicalStrings`.

---

### Task 1: The read-only operation allowlist

**Files:**
- Create: `scripts/lib/evidence-readonly-allowlist.mjs`
- Test: `test/evidence-readonly-allowlist.test.mjs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `READ_ONLY_OPERATIONS: ReadonlyMap<operationId, {cli, verb, argv(params), objects}>`
  - `buildReadOnlyCommand(operationId, params): {cli, args: string[], operation_id, objects}` — throws on an unknown operation or a parameter that fails its own pattern
  - `assertReadOnlyArgv(cli, args): void` — the second gate, asserting the built vector contains no mutating verb and no flag that could write
  - `MUTATING_VERBS: ReadonlySet<string>`

Two gates rather than one is deliberate. The first makes a mutating command
unconstructible; the second catches a future operation added to the table that
smuggles one in. A safety property with one check is a safety property with one
typo between it and nothing.

The initial operation table:

| `operation_id` | CLI | Argument vector |
|---|---|---|
| `k8s.namespaces` | `kubectl` | `get namespaces -o json` |
| `k8s.resources` | `kubectl` | `get <kind> -n <namespace> -o json` |
| `k8s.resource` | `kubectl` | `get <kind> <name> -n <namespace> -o json` |
| `k8s.api-resources` | `kubectl` | `api-resources -o wide` |
| `k8s.auth-can-i` | `kubectl` | `auth can-i --list -n <namespace>` |
| `sf.org-display` | `sf` | `org display --json -o <alias>` |
| `sf.query` | `sf` | `data query --json -o <alias> -q <soql>` |
| `runtime.read-file` | `kubectl` | `exec -n <namespace> <pod> -c <container> -- cat <path>` |
| `runtime.list-directory` | `kubectl` | `exec -n <namespace> <pod> -c <container> -- ls -la <path>` |
| `runtime.process-list` | `kubectl` | `exec -n <namespace> <pod> -c <container> -- ps ax` |
| `runtime.env-keys` | `kubectl` | `exec -n <namespace> <pod> -c <container> -- sh -c "env \| cut -d= -f1"` |

`runtime.env-keys` returns key names only, never values — the metadata-only
rule applied at the point of acquisition rather than trusted to redaction
afterwards. `sf.query` accepts only a `SELECT`; anything else fails its pattern.

- [ ] **Step 1: Write the failing test**

Create `test/evidence-readonly-allowlist.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  MUTATING_VERBS,
  READ_ONLY_OPERATIONS,
  assertReadOnlyArgv,
  buildReadOnlyCommand,
} from '../scripts/lib/evidence-readonly-allowlist.mjs'

test('an allowlisted operation builds an exact argument vector', () => {
  const built = buildReadOnlyCommand('k8s.resources', { kind: 'pods', namespace: 'sidecars' })
  assert.equal(built.cli, 'kubectl')
  assert.deepEqual(built.args, ['get', 'pods', '-n', 'sidecars', '-o', 'json'])
  assert.equal(built.operation_id, 'k8s.resources')
})

test('an operation outside the table cannot be built', () => {
  assert.throws(() => buildReadOnlyCommand('k8s.delete', { kind: 'pods' }), /not allowlisted/i)
  assert.throws(() => buildReadOnlyCommand('anything', {}), /not allowlisted/i)
})

test('every declared operation is genuinely read-only', () => {
  for (const [id, operation] of READ_ONLY_OPERATIONS) {
    assert.equal(
      MUTATING_VERBS.has(operation.verb),
      false,
      `${id} declares mutating verb ${operation.verb}`,
    )
  }
})

test('a parameter that fails its pattern is refused, never interpolated', () => {
  assert.throws(
    () => buildReadOnlyCommand('k8s.resources', { kind: 'pods; kubectl delete ns prod', namespace: 'x' }),
    /invalid/i,
  )
  assert.throws(
    () => buildReadOnlyCommand('k8s.resource', { kind: 'pods', name: '../../etc', namespace: 'x' }),
    /invalid/i,
  )
  assert.throws(
    () => buildReadOnlyCommand('runtime.read-file', {
      namespace: 'x', pod: 'p', container: 'c', path: '/etc/passwd; rm -rf /',
    }),
    /invalid/i,
  )
})

test('sf.query accepts a SELECT and nothing else', () => {
  const built = buildReadOnlyCommand('sf.query', {
    alias: 'peerstar-prod',
    soql: 'SELECT Id, Name FROM PermissionSet LIMIT 50',
  })
  assert.deepEqual(built.args.slice(0, 4), ['data', 'query', '--json', '-o'])
  for (const soql of [
    'DELETE FROM Account',
    'UPDATE Account SET Name = 1',
    "SELECT Id FROM Account; DELETE FROM Account",
  ]) {
    assert.throws(() => buildReadOnlyCommand('sf.query', { alias: 'a', soql }), /SELECT|invalid/i)
  }
})

test('runtime.env-keys returns key names, never values', () => {
  const built = buildReadOnlyCommand('runtime.env-keys', {
    namespace: 'sidecars', pod: 'api-0', container: 'api',
  })
  const command = built.args.join(' ')
  assert.match(command, /cut -d= -f1/)
  assert.equal(/printenv\b(?!.*cut)/.test(command), false)
})

test('the second gate refuses a mutating vector even if the table were wrong', () => {
  assert.throws(() => assertReadOnlyArgv('kubectl', ['delete', 'ns', 'prod']), /read-only/i)
  assert.throws(() => assertReadOnlyArgv('kubectl', ['get', 'pods', '--as', 'admin']), /read-only/i)
  assert.throws(() => assertReadOnlyArgv('kubectl', ['apply', '-f', 'x.yaml']), /read-only/i)
  assert.throws(() => assertReadOnlyArgv('sf', ['data', 'delete', 'record']), /read-only/i)
  assert.doesNotThrow(() => assertReadOnlyArgv('kubectl', ['get', 'pods', '-o', 'json']))
})

test('kubectl exec is allowed only for the read commands the table names', () => {
  assert.doesNotThrow(() =>
    assertReadOnlyArgv('kubectl', ['exec', '-n', 'x', 'p', '-c', 'c', '--', 'cat', '/etc/os-release']))
  assert.throws(
    () => assertReadOnlyArgv('kubectl', ['exec', '-n', 'x', 'p', '-c', 'c', '--', 'rm', '-rf', '/']),
    /read-only/i,
  )
  assert.throws(
    () => assertReadOnlyArgv('kubectl', ['exec', '-n', 'x', 'p', '-c', 'c', '--', 'sh', '-c', 'curl evil.example.com']),
    /read-only/i,
  )
})

test('each operation declares how many objects it touches, for the counters', () => {
  assert.equal(buildReadOnlyCommand('k8s.resource', { kind: 'pods', name: 'api-0', namespace: 'x' }).objects, 1)
  assert.ok(buildReadOnlyCommand('k8s.resources', { kind: 'pods', namespace: 'x' }).objects >= 1)
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-readonly-allowlist.test.mjs`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/evidence-readonly-allowlist.mjs`:

```js
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

function checked(value, pattern, label) {
  const text = String(value ?? '')
  if (!pattern.test(text)) {
    throw new Error(`invalid ${label}: ${JSON.stringify(value)}`)
  }
  return text
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
      '-q', checked(soql, SELECT_ONLY, 'SOQL query; only a single SELECT is permitted'),
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
    if (MUTATING_VERBS.has(token)) {
      throw new Error(`refusing a command that is not read-only: ${cli} ${vector.join(' ')}`)
    }
    if (IMPERSONATION_FLAGS.has(token)) {
      throw new Error(`refusing a command that is not read-only: ${cli} ${vector.join(' ')}`)
    }
  }

  if (separator !== -1) {
    const inner = vector.slice(separator + 1)
    const allowed = ALLOWED_EXEC_COMMANDS.some((template) =>
      template.every((token, index) => inner[index] === token))
    if (!allowed) {
      throw new Error(
        `refusing a command that is not read-only inside the container: ${inner.join(' ')}`,
      )
    }
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm.cmd test -- test/evidence-readonly-allowlist.test.mjs`
Expected: PASS, 9 tests

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/evidence-readonly-allowlist.mjs test/evidence-readonly-allowlist.test.mjs
git commit -m "feat: controller-side read-only operation allowlist with a second refusal gate"
```

---

### Task 2: PHI scope and redaction

**Files:**
- Create: `scripts/lib/evidence-phi.mjs`
- Test: `test/evidence-phi.test.mjs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `PHI_SCOPES = ['none', 'possible', 'confirmed']`
  - `resolvePhiPolicy({phiScope, captureContents, acknowledged}): {scope, capture_contents, phi_bearing, retention_days: number|null}` — throws when the flags do not satisfy the scope
  - `redactToMetadata(value, {maxDepth}): object` — names, shapes, sizes, hashes and key names; never values or record contents
  - `PHI_RETENTION_DAYS = 30`

The rationale, because it is easy to read this as friction: `deployed-state`
and `live-runtime` against production can pull real PHI into a local bundle —
Secrets, ConfigMaps, log lines, database rows, a container's merged filesystem.
Writing unencrypted PHI-bearing bundles would create a new breach surface using
the audit tool itself. Redaction is the default where PHI is possible, and
freely disabled where it is attested absent, so a non-PHI system pays nothing.

- [ ] **Step 1: Write the failing test**

Create `test/evidence-phi.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  PHI_RETENTION_DAYS,
  PHI_SCOPES,
  redactToMetadata,
  resolvePhiPolicy,
} from '../scripts/lib/evidence-phi.mjs'

test('an attested absence of PHI captures everything with no marking', () => {
  const policy = resolvePhiPolicy({ phiScope: 'none' })
  assert.equal(policy.capture_contents, true)
  assert.equal(policy.phi_bearing, false)
  assert.equal(policy.retention_days, null)
})

test('possible PHI is metadata-only until an explicit flag says otherwise', () => {
  const defaulted = resolvePhiPolicy({ phiScope: 'possible' })
  assert.equal(defaulted.capture_contents, false)
  assert.equal(defaulted.phi_bearing, false)

  const opted = resolvePhiPolicy({ phiScope: 'possible', captureContents: true })
  assert.equal(opted.capture_contents, true)
  assert.equal(opted.phi_bearing, true)
})

test('confirmed PHI needs the flag and an acknowledgment, and carries a retention limit', () => {
  assert.equal(resolvePhiPolicy({ phiScope: 'confirmed' }).capture_contents, false)
  assert.throws(
    () => resolvePhiPolicy({ phiScope: 'confirmed', captureContents: true }),
    /acknowledg/i,
  )
  const opted = resolvePhiPolicy({ phiScope: 'confirmed', captureContents: true, acknowledged: true })
  assert.equal(opted.capture_contents, true)
  assert.equal(opted.phi_bearing, true)
  assert.equal(opted.retention_days, PHI_RETENTION_DAYS)
})

test('an unknown scope is refused rather than defaulted to the permissive one', () => {
  assert.deepEqual(PHI_SCOPES, ['none', 'possible', 'confirmed'])
  assert.throws(() => resolvePhiPolicy({ phiScope: 'probably-fine' }), /phi_scope/i)
  assert.throws(() => resolvePhiPolicy({}), /phi_scope/i)
})

test('redaction keeps key names and shapes and drops every value', () => {
  const secret = {
    kind: 'Secret',
    metadata: { name: 'patient-db', namespace: 'clinical' },
    data: {
      DB_PASSWORD: 'aHVudGVyMg==',
      PATIENT_EXPORT: 'TXJzIFJvc2EgTGVl',
    },
  }
  const redacted = redactToMetadata(secret)
  assert.equal(redacted.kind, 'Secret')
  assert.deepEqual(Object.keys(redacted.data).sort(), ['DB_PASSWORD', 'PATIENT_EXPORT'])
  for (const value of Object.values(redacted.data)) {
    assert.equal(typeof value, 'object')
    assert.equal(typeof value.bytes, 'number')
    assert.match(value.sha256, /^[0-9a-f]{64}$/)
    assert.equal(Object.hasOwn(value, 'value'), false)
  }
  const serialized = JSON.stringify(redacted)
  assert.equal(serialized.includes('aHVudGVyMg=='), false)
  assert.equal(serialized.includes('Rosa'), false)
})

test('redaction preserves the structural facts an audit reasons about', () => {
  const redacted = redactToMetadata({
    spec: { replicas: 3, containers: [{ name: 'api' }, { name: 'sidecar' }] },
  })
  assert.equal(redacted.spec.containers.length, 2)
  assert.equal(typeof redacted.spec.replicas, 'object')
  assert.equal(redacted.spec.containers[0].name.bytes, 3)
})

test('redaction is bounded and cannot be made to recurse forever', () => {
  const deep = {}
  let cursor = deep
  for (let index = 0; index < 200; index += 1) {
    cursor.next = {}
    cursor = cursor.next
  }
  assert.doesNotThrow(() => redactToMetadata(deep, { maxDepth: 8 }))
  assert.equal(JSON.stringify(redactToMetadata(deep, { maxDepth: 8 })).includes('[depth]'), true)
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-phi.test.mjs`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/evidence-phi.mjs`:

```js
import { createHash } from 'node:crypto'

export const PHI_SCOPES = Object.freeze(['none', 'possible', 'confirmed'])
export const PHI_RETENTION_DAYS = 30
const DEFAULT_MAX_DEPTH = 12

/**
 * Gated on declared PHI scope, independent of target class, so a non-PHI
 * production system pays no PHI friction while a PHI-bearing lab still does.
 *
 * The default matters more than the option: a deployed-state or live-runtime
 * read against production can pull real PHI into a local bundle, and writing
 * an unencrypted PHI-bearing bundle would create a new breach surface using
 * the audit tool itself.
 */
export function resolvePhiPolicy({ phiScope, captureContents = false, acknowledged = false } = {}) {
  if (!PHI_SCOPES.includes(phiScope)) {
    throw new Error(
      `phi_scope must be one of ${PHI_SCOPES.join(', ')}; received ${JSON.stringify(phiScope)}`,
    )
  }
  if (phiScope === 'none') {
    return { scope: phiScope, capture_contents: true, phi_bearing: false, retention_days: null }
  }
  if (!captureContents) {
    return { scope: phiScope, capture_contents: false, phi_bearing: false, retention_days: null }
  }
  if (phiScope === 'confirmed' && !acknowledged) {
    throw new Error(
      'capturing contents under phi_scope confirmed requires an explicit acknowledgment',
    )
  }
  return {
    scope: phiScope,
    capture_contents: true,
    phi_bearing: true,
    retention_days: phiScope === 'confirmed' ? PHI_RETENTION_DAYS : null,
  }
}

function scalarMetadata(value) {
  const text = typeof value === 'string' ? value : JSON.stringify(value) ?? String(value)
  return {
    type: typeof value,
    bytes: Buffer.byteLength(text, 'utf8'),
    sha256: createHash('sha256').update(text, 'utf8').digest('hex'),
  }
}

/**
 * Metadata-only means names, shapes, sizes, hashes and key names — never
 * values or record contents. Key names survive because "there is a key called
 * PATIENT_EXPORT here" is exactly the finding; its bytes are not.
 */
export function redactToMetadata(value, { maxDepth = DEFAULT_MAX_DEPTH, depth = 0 } = {}) {
  if (depth >= maxDepth) return '[depth]'
  if (value === null || value === undefined) return value ?? null
  if (Array.isArray(value)) {
    return value.map((item) => redactToMetadata(item, { maxDepth, depth: depth + 1 }))
  }
  if (typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value).map(([key, item]) => [
        key,
        redactToMetadata(item, { maxDepth, depth: depth + 1 }),
      ]),
    )
  }
  // A resource kind is structure, not content, and an audit that cannot see
  // "kind: Secret" cannot reason at all.
  if (typeof value === 'string' && /^[A-Za-z][A-Za-z0-9]{0,31}$/.test(value) && depth <= 2) {
    return value
  }
  return scalarMetadata(value)
}
```

Note the `kind` case in the test: `redactToMetadata({kind: 'Secret', …}).kind`
returns the literal `'Secret'` because it is a short identifier at depth 1.
`metadata.name` sits at depth 2 and also survives; `data.DB_PASSWORD`'s
base64 value does not match the identifier pattern and is reduced to its
metadata. Confirm this against the test's assertions while implementing — if
the depth cutoff needs to move, move it and update the test's reasoning, not
just its number.

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm.cmd test -- test/evidence-phi.test.mjs`
Expected: PASS, 7 tests

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/evidence-phi.mjs test/evidence-phi.test.mjs
git commit -m "feat: declared PHI scope with metadata-only redaction on by default"
```

---

### Task 3: The `deployed` adapter

**Files:**
- Create: `scripts/lib/evidence-adapters/deployed.mjs`
- Test: `test/evidence-deployed-adapter.test.mjs`

**Interfaces:**
- Consumes: `buildReadOnlyCommand` (Task 1); `resolvePhiPolicy`/`redactToMetadata` (Task 2); `probeCli`/`runBoundedCli`/`ImpactCounters` (Plan 4); `writeEvidenceBundle` (Plan 1).
- Produces: `createDeployedAdapter({clock, env, limits}): {describe, plan, run}`

Bundle payload:

```text
payload/operations.json                     # every operation run, its exit code and object count
payload/objects/<operation-id>/<index>.json # the acquired object, redacted per policy
payload/impact-counters.json
```

Locator form, consistent with Plan 3's: `prod-cluster:v1/Namespace/sidecars/Pod/sidecars/spec.volumes[0]`
resolves through `payload/objects/`. Plan 3's `resolveEvidenceLocator` gains a
fourth form for it in Task 5 of this plan.

- [ ] **Step 1: Write the failing test**

Create `test/evidence-deployed-adapter.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createDeployedAdapter } from '../scripts/lib/evidence-adapters/deployed.mjs'
import { verifyEvidenceBundle } from '../scripts/lib/evidence-bundle.mjs'
import { runEvidenceAdapterConformance } from './helpers/evidence-adapter-conformance.mjs'
import { stubCliOnPath } from './helpers/stub-cli.mjs'

const SECRET_JSON = JSON.stringify({
  apiVersion: 'v1',
  kind: 'List',
  items: [{
    apiVersion: 'v1',
    kind: 'Secret',
    metadata: { name: 'patient-db', namespace: 'clinical' },
    data: { DB_PASSWORD: 'aHVudGVyMg==', PATIENT_EXPORT: 'TXJzIFJvc2EgTGVl' },
  }],
})

async function kubectlStub(body = SECRET_JSON) {
  const escaped = body.replaceAll('"', '\\"')
  return stubCliOnPath('kubectl', {
    sh: `if [ "$1" = "version" ]; then echo "v1.29.4"; else echo "${escaped}"; fi`,
    cmd: `if "%1"=="version" (echo v1.29.4) else (echo ${body.replaceAll('"', '""')})`,
  })
}

async function adapterWithStub(body) {
  const stub = await kubectlStub(body)
  return createDeployedAdapter({ clock: () => '2026-08-08T14:22:10Z', env: stub.env })
}

const REQUEST = {
  evidence_id: 'prod-cluster',
  context: 'peerstar-prod',
  operations: [{ operation_id: 'k8s.resources', params: { kind: 'secrets', namespace: 'clinical' } }],
  target_class: 'PRODUCTION',
  acknowledge_production: true,
  phi_scope: 'possible',
  attest_authorized: true,
  operator_id: 'gmaida',
  authorized_by: 'security-lead',
  authorization_reference: 'JIRA-4418',
}

runEvidenceAdapterConformance(await adapterWithStub(), { validPlanRequest: REQUEST })

test('plan seals the operation list and probes kubectl without running anything', async () => {
  const adapter = await adapterWithStub()
  const planned = await adapter.plan(REQUEST)
  assert.equal(planned.evidence_context_seed.evidence_class, 'deployed-state')
  assert.equal(planned.evidence_context_seed.acquisition_mode, 'read-only-query')
  assert.equal(planned.operations.length, 1)
  assert.deepEqual(planned.operations[0].args, ['get', 'secrets', '-n', 'clinical', '-o', 'json'])
  assert.equal(planned.dependency.present, true)
})

test('plan refuses an operation outside the allowlist', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(
    () => adapter.plan({
      ...REQUEST,
      operations: [{ operation_id: 'k8s.delete', params: { kind: 'ns' } }],
    }),
    /not allowlisted/i,
  )
})

test('plan refuses PRODUCTION without an explicit acknowledgment', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, acknowledge_production: false }),
    /PRODUCTION|acknowledg/i,
  )
})

test('plan refuses THIRD_PARTY without a signed authorization artifact', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, target_class: 'THIRD_PARTY' }),
    /signed|higher-assurance/i,
  )
})

test('plan refuses without attestation, because deployed-state floors it', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(() => adapter.plan({ ...REQUEST, attest_authorized: false }), /attest/i)
})

test('an absent kubectl is NOT_ASSESSED with a named reason, never an empty success', async () => {
  const adapter = createDeployedAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    env: { ...process.env, PATH: '' },
  })
  await assert.rejects(() => adapter.plan(REQUEST), /kubectl|not found/i)
})

test('run acquires the objects and the bundle verifies', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-deployed-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.deepEqual((await verifyEvidenceBundle(written.directory)).errors, [])
  assert.equal(written.profile.evidence_context.evidence_class, 'deployed-state')
  assert.equal(written.profile.coverage_state, 'COVERED')
  assert.equal(Object.hasOwn(written.profile, 'artifact_kind'), false)
})

test('phi_scope possible captures key names and shapes but no values', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-deployed-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.equal(written.profile.phi_bearing, false)

  const bytes = await readFile(join(written.directory, 'payload', 'objects', 'k8s.resources', '0.json'))
  const text = bytes.toString('utf8')
  assert.match(text, /PATIENT_EXPORT/)
  assert.equal(text.includes('TXJzIFJvc2EgTGVl'), false)
  assert.equal(text.includes('aHVudGVyMg=='), false)
})

test('phi_scope none captures contents in full and marks nothing', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-deployed-')), 'ev')
  const written = await adapter.run(
    await adapter.plan({ ...REQUEST, phi_scope: 'none' }),
    { out },
  )
  const text = (await readFile(
    join(written.directory, 'payload', 'objects', 'k8s.resources', '0.json'),
  )).toString('utf8')
  assert.match(text, /TXJzIFJvc2EgTGVl/)
  assert.equal(written.profile.phi_bearing, false)
})

test('unparsed output is PARTIAL with the unparsed portion named', async () => {
  const adapter = await adapterWithStub('not json at all')
  const out = join(await mkdtemp(join(tmpdir(), 'rta-deployed-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.equal(written.profile.coverage_state, 'PARTIAL')
  assert.ok(written.profile.coverage_gaps.some(({ reason }) => /pars/i.test(reason)))
})

test('impact counters halt acquisition when a cap is exceeded', async () => {
  const stub = await kubectlStub()
  const adapter = createDeployedAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    env: stub.env,
    limits: { maxCommands: 1, maxObjects: 1 },
  })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-deployed-')), 'ev')
  const planned = await adapter.plan({
    ...REQUEST,
    operations: [
      { operation_id: 'k8s.resources', params: { kind: 'secrets', namespace: 'clinical' } },
      { operation_id: 'k8s.resources', params: { kind: 'configmaps', namespace: 'clinical' } },
    ],
  })
  const written = await adapter.run(planned, { out })
  assert.equal(written.profile.coverage_state, 'PARTIAL')
  assert.ok(written.profile.coverage_gaps.some(({ reason }) => /cap/i.test(reason)))
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-deployed-adapter.test.mjs`
Expected: FAIL — module not found

- [ ] **Step 3: Write the adapter**

Create `scripts/lib/evidence-adapters/deployed.mjs`:

```js
import { compareCanonicalStrings } from '../canonical-order.mjs'
import { writeEvidenceBundle } from '../evidence-bundle.mjs'
import {
  DEFAULT_CLI_LIMITS,
  ImpactCapExceededError,
  ImpactCounters,
  probeCli,
  runBoundedCli,
} from '../evidence-cli-runner.mjs'
import { redactForLog } from '../evidence-image-reference.mjs'
import { redactToMetadata, resolvePhiPolicy } from '../evidence-phi.mjs'
import { buildReadOnlyCommand } from '../evidence-readonly-allowlist.mjs'

const ADAPTER_VERSION = '1.0.0'

const CAPABILITIES = Object.freeze({
  'target-identity': 'COMPOSABLE',
  'content-enumeration': 'NATIVE',
  'content-retrieval': 'NATIVE',
  'layer-or-revision-history': 'UNSUPPORTED',
  'metadata-provenance': 'COMPOSABLE',
  'deletion-recoverability': 'UNSUPPORTED',
  'effective-configuration': 'NATIVE',
  'principal-and-permission-state': 'NATIVE',
  'secret-material-surface': 'NATIVE',
  'impact-accounting': 'NATIVE',
})

const CLI_BY_PREFIX = new Map([['k8s', 'kubectl'], ['sf', 'sf'], ['runtime', 'kubectl']])

function requiredCli(operations) {
  return [...new Set(operations.map(({ operation_id: id }) => CLI_BY_PREFIX.get(id.split('.')[0])))]
    .filter(Boolean)
    .sort(compareCanonicalStrings)
}

export function createDeployedAdapter({
  clock = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
  env = process.env,
  limits = {},
} = {}) {
  const cliLimits = { ...DEFAULT_CLI_LIMITS, ...limits }

  return {
    describe: () => ({
      adapter_id: 'deployed',
      evidence_class: 'deployed-state',
      adapter_version: ADAPTER_VERSION,
      capabilities: { ...CAPABILITIES },
      external_dependency: 'kubectl|sf|cloud-cli',
    }),

    plan: async (request) => {
      if (request.attest_authorized !== true) {
        throw new Error('deployed-state acquisition requires --attest-authorized')
      }
      if (request.target_class === 'PRODUCTION' && request.acknowledge_production !== true) {
        throw new Error('a PRODUCTION target requires --acknowledge-production')
      }
      if (request.target_class === 'THIRD_PARTY' && !request.signed_authorization) {
        throw new Error(
          'a THIRD_PARTY target routes through the existing higher-assurance signed-artifact '
          + 'mode; this adapter neither creates nor approves those artifacts',
        )
      }
      const phi = resolvePhiPolicy({
        phiScope: request.phi_scope,
        captureContents: request.capture_contents === true,
        acknowledged: request.acknowledge_phi === true,
      })

      // The allowlist builds every vector. An operation the table does not
      // name cannot be planned, so a mutating command is unconstructible.
      const operations = (request.operations ?? []).map(({ operation_id: id, params }) => ({
        ...buildReadOnlyCommand(id, params),
        params,
      }))
      if (operations.length === 0) throw new Error('at least one read-only operation is required')

      for (const cli of requiredCli(operations)) {
        const probe = await probeCli(cli, { versionArgs: ['version'], env })
        if (!probe.present) {
          throw new Error(
            `deployed-state acquisition needs ${cli} on PATH and it is absent (${probe.reason})`,
          )
        }
      }

      return {
        plan_id: `deployed:${request.context}:${operations.length}`,
        context: request.context,
        operations,
        phi_policy: phi,
        evidence_context_seed: {
          evidence_id: request.evidence_id,
          evidence_class: 'deployed-state',
          adapter_id: 'deployed',
          target_identity: request.context,
          acquisition_mode: 'read-only-query',
          detection_evidence: operations.map(({ operation_id: id }) => `operation ${id}`),
          confidence: 'high',
        },
        attestation: {
          operator_id: request.operator_id,
          authorized_by: request.authorized_by,
          authorization_reference: request.authorization_reference,
          attested_on: clock(),
        },
        target_class: request.target_class,
        phi_scope: phi.scope,
        dependency: { name: requiredCli(operations).join('|'), present: true, version: null },
      }
    },

    run: async (planned, { out }) => {
      const counters = new ImpactCounters({
        maxCommands: cliLimits.maxCommands,
        maxObjects: cliLimits.maxObjects,
        maxBytes: cliLimits.maxStdoutBytes,
      })
      const payload = []
      const gaps = []
      const executed = []
      let acquired = 0

      for (const operation of planned.operations) {
        let result
        try {
          result = await runBoundedCli({
            name: operation.cli,
            args: operation.args,
            limits: cliLimits,
            env,
            counters,
          })
          counters.record({ objects: operation.objects }).assertWithinCaps()
        } catch (error) {
          // A cap is a halt, not a crash: what was already acquired stays, and
          // the stopping point is named.
          gaps.push({
            area: operation.operation_id,
            reason: error instanceof ImpactCapExceededError
              ? `acquisition halted at an impact cap: ${error.message}`
              : `operation failed: ${redactForLog(String(error.message)).slice(0, 400)}`,
          })
          break
        }

        executed.push({
          operation_id: operation.operation_id,
          exit_code: result.code,
          objects: operation.objects,
        })
        if (result.code !== 0) {
          gaps.push({
            area: operation.operation_id,
            reason: `exited ${result.code}: ${redactForLog(result.stderr).slice(0, 400)}`,
          })
          continue
        }

        let parsed
        try {
          parsed = JSON.parse(result.stdout.toString('utf8'))
        } catch (error) {
          gaps.push({
            area: operation.operation_id,
            reason: `could not parse output as JSON: ${error.message}; the raw output was not captured`,
          })
          continue
        }

        const objects = Array.isArray(parsed?.items) ? parsed.items : [parsed]
        for (const [index, object] of objects.entries()) {
          payload.push({
            path: `objects/${operation.operation_id}/${index}.json`,
            bytes: Buffer.from(JSON.stringify(
              planned.phi_policy.capture_contents ? object : redactToMetadata(object),
              null,
              2,
            ), 'utf8'),
          })
          acquired += 1
        }
      }

      payload.push({
        path: 'operations.json',
        bytes: Buffer.from(JSON.stringify(executed, null, 2), 'utf8'),
      })
      payload.push({
        path: 'impact-counters.json',
        bytes: Buffer.from(JSON.stringify(counters.snapshot(), null, 2), 'utf8'),
      })
      payload.sort((left, right) => compareCanonicalStrings(left.path, right.path))

      return writeEvidenceBundle({
        directory: out,
        profile: {
          schema: 'evidence-bundle-v1',
          evidence_context: { ...planned.evidence_context_seed, acquired_on: clock() },
          target_class: planned.target_class,
          phi_scope: planned.phi_scope,
          phi_bearing: planned.phi_policy.phi_bearing,
          adapter_version: ADAPTER_VERSION,
          contract_version: 1,
          coverage_state: acquired === 0 ? 'NOT_ASSESSED' : gaps.length > 0 ? 'PARTIAL' : 'COVERED',
          attestation: planned.attestation,
          coverage_gaps: gaps.length > 0
            ? gaps
            : acquired === 0
              ? [{ area: 'acquisition', reason: 'no object was acquired' }]
              : [],
        },
        payload,
      })
    },
  }
}
```

- [ ] **Step 4: Run the tests**

Run: `npm.cmd test -- test/evidence-deployed-adapter.test.mjs`
Expected: PASS — the 10 shared conformance cases plus 11 adapter cases

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/evidence-adapters/deployed.mjs test/evidence-deployed-adapter.test.mjs
git commit -m "feat: read-only deployed-state acquisition with PHI redaction and impact caps"
```

---

### Task 4: The `runtime` adapter

**Files:**
- Create: `scripts/lib/evidence-adapters/runtime.mjs`
- Test: `test/evidence-runtime-adapter.test.mjs`

**Interfaces:**
- Consumes: everything Task 3 consumes, plus Task 3's own structure.
- Produces: `createRuntimeAdapter({clock, env, limits}): {describe, plan, run}`

`runtime` differs from `deployed` in exactly four ways, and nothing else:

1. Its class is `live-runtime`, the highest precedence.
2. Its operations are the four `runtime.*` entries — inspection inside one named container, never a cluster-wide sweep.
3. `run` requires `--confirm-authorization-current` at execution time, not only attestation at plan time. Authorization can lapse between planning and running, and this is the class where that matters.
4. Its output is text, not JSON, so parsing failures are `PARTIAL` differently: an unreadable file is a named gap, and the raw bytes are captured only when the PHI policy permits contents.

- [ ] **Step 1: Write the failing test**

Create `test/evidence-runtime-adapter.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRuntimeAdapter } from '../scripts/lib/evidence-adapters/runtime.mjs'
import { verifyEvidenceBundle } from '../scripts/lib/evidence-bundle.mjs'
import { runEvidenceAdapterConformance } from './helpers/evidence-adapter-conformance.mjs'
import { stubCliOnPath } from './helpers/stub-cli.mjs'

async function kubectlStub(body = 'DB_PASSWORD\nPATIENT_EXPORT\nPATH\n') {
  return stubCliOnPath('kubectl', {
    sh: `if [ "$1" = "version" ]; then echo "v1.29.4"; else printf '${body.replaceAll("'", "")}'; fi`,
    cmd: `if "%1"=="version" (echo v1.29.4) else (echo ${body.replaceAll('\n', ' & echo ')})`,
  })
}

async function adapterWithStub(body) {
  const stub = await kubectlStub(body)
  return createRuntimeAdapter({ clock: () => '2026-08-08T14:22:10Z', env: stub.env })
}

const REQUEST = {
  evidence_id: 'prod-api-pod',
  context: 'peerstar-prod',
  namespace: 'clinical',
  pod: 'api-0',
  container: 'api',
  operations: [{ operation_id: 'runtime.env-keys', params: {} }],
  target_class: 'PRODUCTION',
  acknowledge_production: true,
  phi_scope: 'possible',
  attest_authorized: true,
  operator_id: 'gmaida',
  authorized_by: 'security-lead',
  authorization_reference: 'JIRA-4419',
}

runEvidenceAdapterConformance(await adapterWithStub(), { validPlanRequest: REQUEST })

test('the adapter declares the highest-precedence class', async () => {
  const adapter = await adapterWithStub()
  assert.equal(adapter.describe().evidence_class, 'live-runtime')
})

test('plan binds one named container and refuses a cluster-wide operation', async () => {
  const adapter = await adapterWithStub()
  const planned = await adapter.plan(REQUEST)
  assert.deepEqual(planned.operations[0].args.slice(0, 6), [
    'exec', '-n', 'clinical', 'api-0', '-c', 'api',
  ])
  await assert.rejects(
    () => adapter.plan({
      ...REQUEST,
      operations: [{ operation_id: 'k8s.resources', params: { kind: 'pods', namespace: 'clinical' } }],
    }),
    /runtime\./i,
  )
})

test('run refuses without a current authorization confirmation', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-runtime-')), 'ev')
  await assert.rejects(
    () => adapter.run(await adapter.plan(REQUEST), { out }),
    /confirm-authorization-current|authorization/i,
  )
})

test('run with a current confirmation produces a verifiable bundle', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-runtime-')), 'ev')
  const written = await adapter.run(
    await adapter.plan(REQUEST),
    { out, authorizationConfirmed: true },
  )
  assert.deepEqual((await verifyEvidenceBundle(written.directory)).errors, [])
  assert.equal(written.profile.evidence_context.evidence_class, 'live-runtime')
  assert.equal(written.profile.coverage_state, 'COVERED')
})

test('env-keys acquires key names and never a value', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-runtime-')), 'ev')
  const written = await adapter.run(
    await adapter.plan(REQUEST),
    { out, authorizationConfirmed: true },
  )
  const text = (await readFile(
    join(written.directory, 'payload', 'observations', 'runtime.env-keys', '0.txt'),
  )).toString('utf8')
  assert.match(text, /PATIENT_EXPORT/)
  assert.equal(/=/.test(text), false)
})

test('a read that fails inside the container is a named gap', async () => {
  const stub = await stubCliOnPath('kubectl', {
    sh: 'if [ "$1" = "version" ]; then echo "v1.29.4"; else echo "cat: /etc/shadow: Permission denied" >&2; exit 1; fi',
    cmd: 'if "%1"=="version" (echo v1.29.4) else (echo cat: /etc/shadow: Permission denied 1>&2 & exit /b 1)',
  })
  const adapter = createRuntimeAdapter({ clock: () => '2026-08-08T14:22:10Z', env: stub.env })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-runtime-')), 'ev')
  const written = await adapter.run(
    await adapter.plan({
      ...REQUEST,
      operations: [{ operation_id: 'runtime.read-file', params: { path: '/etc/shadow' } }],
    }),
    { out, authorizationConfirmed: true },
  )
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.ok(written.profile.coverage_gaps.some(({ reason }) => /Permission denied/.test(reason)))
})

test('phi_scope confirmed without acknowledgment cannot capture contents', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, phi_scope: 'confirmed', capture_contents: true }),
    /acknowledg/i,
  )
})

test('a phi_bearing acquisition marks the bundle and carries a retention limit', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-runtime-')), 'ev')
  const written = await adapter.run(
    await adapter.plan({
      ...REQUEST,
      phi_scope: 'confirmed',
      capture_contents: true,
      acknowledge_phi: true,
    }),
    { out, authorizationConfirmed: true },
  )
  assert.equal(written.profile.phi_bearing, true)
  assert.equal(written.profile.phi_scope, 'confirmed')
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-runtime-adapter.test.mjs`
Expected: FAIL — module not found

- [ ] **Step 3: Write the adapter**

Create `scripts/lib/evidence-adapters/runtime.mjs`, structured exactly like
Task 3's `deployed.mjs` with the four differences above. The parts that differ:

```js
const CAPABILITIES = Object.freeze({
  'target-identity': 'COMPOSABLE',
  'content-enumeration': 'COMPOSABLE',
  'content-retrieval': 'NATIVE',
  'layer-or-revision-history': 'UNSUPPORTED',
  'metadata-provenance': 'UNKNOWN',
  'deletion-recoverability': 'UNSUPPORTED',
  'effective-configuration': 'NATIVE',
  'principal-and-permission-state': 'COMPOSABLE',
  'secret-material-surface': 'NATIVE',
  'impact-accounting': 'NATIVE',
})
```

```js
      // Runtime inspection is bound to one named container. A cluster-wide
      // sweep is the deployed adapter's job and must not be reachable here.
      for (const { operation_id: id } of request.operations ?? []) {
        if (!id.startsWith('runtime.')) {
          throw new Error(`runtime acquisition accepts only runtime.* operations; received ${id}`)
        }
      }
      const operations = (request.operations ?? []).map(({ operation_id: id, params }) => ({
        ...buildReadOnlyCommand(id, {
          ...params,
          namespace: request.namespace,
          pod: request.pod,
          container: request.container,
        }),
        params,
      }))
```

```js
    run: async (planned, { out, authorizationConfirmed = false }) => {
      // Attestation at plan time is not enough for this class: authorization
      // can lapse between planning and running, and this is the tier where
      // that difference has consequences.
      if (!authorizationConfirmed) {
        throw new Error(
          'live-runtime acquisition requires --confirm-authorization-current at run time',
        )
      }
```

and, because the output is text rather than JSON, the per-operation capture:

```js
        const text = result.stdout.toString('utf8')
        payload.push({
          path: `observations/${operation.operation_id}/0.txt`,
          bytes: Buffer.from(
            planned.phi_policy.capture_contents ? text : summariseText(text),
            'utf8',
          ),
        })
```

with:

```js
// Metadata-only for text output: line count, byte count, and the line shapes
// that carry no value. env-keys already returns key names only, so this is
// the second belt on the same trousers rather than the only one.
function summariseText(text) {
  const lines = text.split(/\r?\n/).filter((line) => line.trim() !== '')
  return lines.map((line) => line.split('=')[0]).join('\n')
}
```

The rest — attestation checks, `PRODUCTION`/`THIRD_PARTY` gates, PHI policy
resolution, the impact-counter loop with its cap-halt behaviour, the coverage
state derivation, and the bundle write — is byte-for-byte the shape of
`deployed.mjs`. If the two diverge beyond the four differences above during
implementation, extract the shared body into
`scripts/lib/evidence-adapters/live-acquisition.mjs` and have both call it.

- [ ] **Step 4: Run the tests**

Run: `npm.cmd test -- test/evidence-runtime-adapter.test.mjs test/evidence-deployed-adapter.test.mjs`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/evidence-adapters/runtime.mjs test/evidence-runtime-adapter.test.mjs
git commit -m "feat: read-only live-runtime inspection bound to one named container"
```

---

### Task 5: Controller wiring, kill switch and the fourth locator form

**Files:**
- Modify: `scripts/lib/evidence-acquire-controller.mjs`
- Modify: `scripts/acquire.mjs`
- Modify: `scripts/lib/evidence-locator.mjs`
- Test: `test/evidence-live-acquisition.test.mjs` (create)

**Interfaces:**
- Consumes: both adapters.
- Produces:
  - `ADAPTER_FACTORIES` carrying all four adapters
  - `runAcquisition` honouring the per-class authorization requirements the routing manifest declares
  - A `stop` that halts an in-flight acquisition, not only a planned one
  - `resolveEvidenceLocator` gaining the `<apiVersion>/<Kind>/<namespace>/<name>` form the deployed adapter's locators use

The kill switch is the one piece here that is not simply wiring. `stop` writing
a marker is enough for a planned acquisition, but a `deployed` run iterating
over sixty operations must notice it mid-loop. The acquisition loop re-reads
the stop marker before each operation — polling rather than signalling, because
polling a file needs no IPC and works identically on Windows.

- [ ] **Step 1: Write the failing test**

Create `test/evidence-live-acquisition.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  planAcquisition,
  requestAcquisitionStop,
  runAcquisition,
} from '../scripts/lib/evidence-acquire-controller.mjs'
import { resolveEvidenceLocator } from '../scripts/lib/evidence-locator.mjs'
import { stubCliOnPath } from './helpers/stub-cli.mjs'

const OBJECT_JSON = JSON.stringify({
  apiVersion: 'v1',
  kind: 'Pod',
  metadata: { name: 'api-0', namespace: 'clinical' },
  spec: { volumes: [{ name: 'config' }] },
})

async function kubectlStub() {
  return stubCliOnPath('kubectl', {
    sh: `if [ "$1" = "version" ]; then echo "v1.29.4"; else echo '${OBJECT_JSON}'; fi`,
    cmd: `if "%1"=="version" (echo v1.29.4) else (echo ${OBJECT_JSON.replaceAll('"', '""')})`,
  })
}

const request = {
  evidence_id: 'prod-cluster',
  context: 'peerstar-prod',
  operations: [
    { operation_id: 'k8s.resource', params: { kind: 'pods', name: 'api-0', namespace: 'clinical' } },
  ],
  target_class: 'NONPROD',
  phi_scope: 'none',
  attest_authorized: true,
  operator_id: 'gmaida',
  authorized_by: 'security-lead',
  authorization_reference: 'JIRA-4418',
}

async function scratch() {
  return join(await mkdtemp(join(tmpdir(), 'rta-live-')), 'ev')
}

test('all four adapters are reachable through the controller', async () => {
  const stub = await kubectlStub()
  const out = await scratch()
  const planned = await planAcquisition({
    adapterId: 'deployed',
    request,
    out,
    env: stub.env,
  })
  assert.equal(planned.plan.evidence_context_seed.evidence_class, 'deployed-state')
})

test('a class requiring attestation refuses to run without the confirmation', async () => {
  const stub = await kubectlStub()
  const out = await scratch()
  await planAcquisition({ adapterId: 'deployed', request, out, env: stub.env })
  await assert.rejects(
    () => runAcquisition({ bundle: out, operatorId: 'gmaida', env: stub.env }),
    /authorization/i,
  )
})

test('stop halts an acquisition that is already running, not only a planned one', async () => {
  const stub = await kubectlStub()
  const out = await scratch()
  await planAcquisition({
    adapterId: 'deployed',
    request: {
      ...request,
      operations: Array.from({ length: 8 }, (_unused, index) => ({
        operation_id: 'k8s.resource',
        params: { kind: 'pods', name: `api-${index}`, namespace: 'clinical' },
      })),
    },
    out,
    env: stub.env,
  })
  // The marker is written before the run begins, which is the same code path
  // an operator hits mid-run; the loop must notice it and stop.
  await requestAcquisitionStop({ bundle: out, operatorId: 'gmaida', reason: 'scope change' })
  await assert.rejects(
    () => runAcquisition({
      bundle: out,
      operatorId: 'gmaida',
      authorizationConfirmed: true,
      env: stub.env,
    }),
    /stopped/i,
  )
})

test('stop is idempotent and needs no still-valid authority artifact', async () => {
  const out = await scratch()
  const first = await requestAcquisitionStop({ bundle: out, operatorId: 'gmaida', reason: 'incident' })
  const second = await requestAcquisitionStop({ bundle: out, operatorId: 'gmaida', reason: 'incident' })
  assert.equal(first.state, 'STOPPED')
  assert.equal(second.state, 'STOPPED')
})

test('a deployed-state locator resolves to its acquired object', async () => {
  const stub = await kubectlStub()
  const out = await scratch()
  await planAcquisition({ adapterId: 'deployed', request, out, env: stub.env })
  await runAcquisition({
    bundle: out,
    operatorId: 'gmaida',
    authorizationConfirmed: true,
    env: stub.env,
  })
  const resolved = await resolveEvidenceLocator(out, 'v1/Pod/clinical/api-0')
  assert.equal(resolved.kind, 'object')
  assert.match(resolved.bytes.toString('utf8'), /"api-0"/)
})

test('an unresolvable object locator resolves to nothing rather than guessing', async () => {
  const stub = await kubectlStub()
  const out = await scratch()
  await planAcquisition({ adapterId: 'deployed', request, out, env: stub.env })
  await runAcquisition({
    bundle: out,
    operatorId: 'gmaida',
    authorizationConfirmed: true,
    env: stub.env,
  })
  const resolved = await resolveEvidenceLocator(out, 'v1/Pod/clinical/no-such-pod')
  assert.equal(resolved.bytes, null)
})

test('the acquisition plan records what was executed for the report', async () => {
  const stub = await kubectlStub()
  const out = await scratch()
  await planAcquisition({ adapterId: 'deployed', request, out, env: stub.env })
  await runAcquisition({
    bundle: out,
    operatorId: 'gmaida',
    authorizationConfirmed: true,
    env: stub.env,
  })
  const executed = JSON.parse(
    (await readFile(join(out, 'payload', 'operations.json'))).toString('utf8'),
  )
  assert.equal(executed.length, 1)
  assert.equal(executed[0].operation_id, 'k8s.resource')
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-live-acquisition.test.mjs`
Expected: FAIL — `deployed` is not a registered adapter factory

- [ ] **Step 3: Wire the controller**

In `scripts/lib/evidence-acquire-controller.mjs`:

```js
import { createDeployedAdapter } from './evidence-adapters/deployed.mjs'
import { createRuntimeAdapter } from './evidence-adapters/runtime.mjs'

const ADAPTER_FACTORIES = new Map([
  ['artifact', createArtifactAdapter],
  ['registry', createRegistryAdapter],
  ['deployed', createDeployedAdapter],
  ['runtime', createRuntimeAdapter],
])
```

Thread `env` through `planAcquisition` and `runAcquisition` into the factory,
so tests can inject a stub `PATH` and production passes `process.env`. Pass
`authorizationConfirmed` into `adapter.run`. Add a stop check the acquisition
loop can call:

```js
export async function isAcquisitionStopped(bundle) {
  try {
    return (await readPlanFile(bundle)).state === 'STOPPED'
  } catch {
    return false
  }
}
```

and give both live adapters a `shouldStop` callback in their `run` options,
checked before each operation:

```js
        if (await shouldStop?.()) {
          gaps.push({ area: 'acquisition', reason: 'stopped by the operator before this operation' })
          break
        }
```

`runAcquisition` supplies `shouldStop: () => isAcquisitionStopped(directory)`.
The controller additionally refuses to start at all when the marker is already
present, which is what the third test above exercises.

- [ ] **Step 4: Add the fourth locator form**

In `scripts/lib/evidence-locator.mjs`, add beside the three existing forms:

```js
const OBJECT_LOCATOR = /^([a-z0-9][a-z0-9./-]*)\/([A-Z][A-Za-z0-9]*)\/([a-z0-9-]+)\/([a-z0-9.-]+)$/
```

```js
  const object = OBJECT_LOCATOR.exec(locator)
  if (object) {
    const [, apiVersion, kind, namespace, name] = object
    const manifest = await readJsonPayload(directory, 'payload/operations.json')
    for (const { operation_id: operationId } of manifest ?? []) {
      for (let index = 0; index < MAX_OBJECT_SCAN; index += 1) {
        const path = `payload/objects/${operationId}/${index}.json`
        let parsed
        try {
          parsed = JSON.parse((await readEvidencePayloadFile(directory, path)).toString('utf8'))
        } catch {
          break
        }
        if (
          parsed?.apiVersion === apiVersion
          && parsed?.kind === kind
          && parsed?.metadata?.namespace === namespace
          && parsed?.metadata?.name === name
        ) {
          return { kind: 'object', payload_path: path, bytes: Buffer.from(JSON.stringify(parsed), 'utf8') }
        }
      }
    }
    return { kind: 'object', payload_path: null, bytes: null }
  }
```

with `const MAX_OBJECT_SCAN = 4096` beside the other constants — the scan is
bounded for the same reason every other loop in this subsystem is.

- [ ] **Step 5: Extend the CLI**

In `scripts/acquire.mjs`, add the two adapters' `plan` shapes. `deployed`:
`required: ['context', 'evidence-id', 'operation', 'target-class', 'phi-scope', 'operator-id', 'authorized-by', 'authorization-reference', 'out']`,
`requiredFlags: ['attest-authorized']`,
`optional: ['acknowledge-production', 'acknowledge-phi', 'capture-contents', 'json']`.
`runtime` adds `required: ['namespace', 'pod', 'container']` on top. `run` for
both gains `requiredFlags: ['confirm-authorization-current']`.

`--operation` takes a compact `id:key=value,key=value` form, repeated as a
comma-separated list for the same reason `--evidence-bundle` does — one option
value, no parser change:

```text
--operation "k8s.resources:kind=secrets,namespace=clinical"
```

Update the help text's `Boundary:` block to state, in `http-recon`'s voice:

```text
Boundary:
  Planning performs no acquisition. Every command is built from a controller-side
  read-only allowlist; the adapter cannot construct a mutating command. Attestation
  is a recorded declaration, not independently verified permission. Impact counters
  halt acquisition at their caps. `stop` is idempotent and needs no valid authority.
  This control plane mutates nothing. Exploitation is a separate tier that does not
  exist in this release.
```

- [ ] **Step 6: Run the tests**

Run: `npm.cmd test -- test/evidence-live-acquisition.test.mjs test/evidence-acquire-controller.test.mjs test/evidence-locator.test.mjs`
Expected: PASS

- [ ] **Step 7: Commit**

```bash
git add scripts/lib/evidence-acquire-controller.mjs scripts/acquire.mjs scripts/lib/evidence-locator.mjs scripts/lib/evidence-adapters test/evidence-live-acquisition.test.mjs
git commit -m "feat: wire the live adapters, a mid-run kill switch and deployed-state locators"
```

---

### Task 6: Adapter documents, PHI reporting and suite registration

**Files:**
- Create: `skills/last-aperture/lenses/_evidence-adapters/deployed.md`
- Create: `skills/last-aperture/lenses/_evidence-adapters/runtime.md`
- Modify: `scripts/lib/report.mjs`
- Modify: `package.json` — `test:platform`
- Test: `test/evidence-adapters.test.mjs` and `test/evidence-report.test.mjs` (extend)

**Interfaces:**
- Consumes: `run.evidence_bundles[].phi_bearing` (Plan 2, Task 5).
- Produces: the two adapter documents, and a report line naming any PHI-bearing bundle's existence and location without inlining its contents.

- [ ] **Step 1: Write the failing tests**

Append to `test/evidence-adapters.test.mjs`:

```js
for (const [adapterId, file] of [['deployed', 'deployed.md'], ['runtime', 'runtime.md']]) {
  test(`the ${adapterId} adapter document states its safety envelope`, () => {
    const doc = readFileSync(
      fileURLToPath(new URL(`../skills/last-aperture/lenses/_evidence-adapters/${file}`, import.meta.url)),
      'utf8',
    )
    assert.match(doc, /read-only/i)
    assert.match(doc, /impact counter/i)
    assert.match(doc, /kill switch|stop/i)
    assert.match(doc, /phi_scope/)
    assert.match(doc, /attestation/i)
    assert.match(doc, /mutat/i)
    assert.deepEqual([...declaredEvidenceRuleAnchors(doc)].every((id) => id.startsWith('ev.')), true)
  })
}

test('the runtime document states it is not an exploitation tier', () => {
  const doc = readFileSync(
    fileURLToPath(new URL('../skills/last-aperture/lenses/_evidence-adapters/runtime.md', import.meta.url)),
    'utf8',
  )
  assert.match(doc, /Phase 3|exploitation/i)
  assert.match(doc, /mutates nothing|no mutation/i)
})
```

Append to `test/evidence-report.test.mjs`:

```js
test('a PHI-bearing bundle is named in the report without its contents', () => {
  const report = renderMarkdownReport(run({
    evidence_bundles: [{
      evidence_id: 'prod-cluster',
      evidence_class: 'deployed-state',
      adapter_id: 'deployed',
      coverage_state: 'COVERED',
      phi_bearing: true,
      root_sha256: 'd'.repeat(64),
    }],
  }))
  assert.match(report, /PHI-bearing/i)
  assert.match(report, /prod-cluster/)
  assert.match(report, /dddddddddddd/)
  assert.match(report, /contents are not reproduced/i)
})

test('a run with no PHI-bearing bundle raises no PHI notice', () => {
  assert.equal(/PHI-bearing/i.test(renderMarkdownReport(run())), false)
})
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npm.cmd test -- test/evidence-adapters.test.mjs test/evidence-report.test.mjs`
Expected: FAIL on the four new cases.

- [ ] **Step 3: Write the two adapter documents**

Each states: canonical `adapter_id`, `verified_on`, the ten capabilities with
the values `describe()` returns, the exact read-only operation table it may
use, the authorization floor and what it adds above it, the impact counters and
their caps, the PHI scope table and the metadata-only rule, the kill switch's
idempotence, and the bundle payload layout. `runtime.md` additionally states,
plainly:

```markdown
## What this tier is not

This adapter mutates nothing. It runs a fixed set of read commands inside one
named container and records what they returned. It is not an exploitation
tier, and it must not be treated as a precedent for one: exploitation is
Phase 3, it requires an explicit amendment to two hard rails, and that
amendment does not exist. A report from this adapter carries the recon path's
sealed-scope language honestly, because the action set here really is sealed.
```

- [ ] **Step 4: Add the PHI notice to the report**

In `scripts/lib/report.mjs`, inside the `### Evidence-class coverage` block
added by Plan 2, after the table:

```js
    const phiBearing = (run.evidence_bundles ?? []).filter(({ phi_bearing: bearing }) => bearing)
    if (phiBearing.length > 0) {
      lines.push(
        '#### PHI-bearing evidence',
        '',
        'The following bundles were captured with contents under a declared PHI scope. ' +
        'Their contents are not reproduced here; the bundle is itself an auditable ' +
        'artifact and is subject to its retention limit.',
        '',
        '| Evidence | Class | Adapter | Bundle digest |',
        '|---|---|---|---|',
      )
      for (const bundle of phiBearing) {
        lines.push(
          `| ${tableCell(bundle.evidence_id)} | ${tableCell(bundle.evidence_class)} | ` +
          `${tableCell(bundle.adapter_id)} | ${inlineCode(bundle.root_sha256.slice(0, 12))} |`,
        )
      }
      lines.push('')
    }
```

- [ ] **Step 5: Register the tests**

Append to `package.json`'s `test:platform`:

```text
test/evidence-readonly-allowlist.test.mjs test/evidence-phi.test.mjs test/evidence-deployed-adapter.test.mjs test/evidence-runtime-adapter.test.mjs test/evidence-live-acquisition.test.mjs
```

- [ ] **Step 6: Run everything**

Run: `npm.cmd test`
Expected: the 2 known ripgrep failures only.

Run: `npm.cmd run test:platform` → PASS
Run: `npm.cmd run lint` → `PASS: R1-R9, SKILL and ledger gate clean.`
Run: `npm.cmd run gen -- --check` → `PASS ... (174 slugs).`

Run the end-to-end path once, against the stub-free local environment, to
confirm the honest failure mode on a machine with no cluster tooling:

```bash
npm.cmd run audit:acquire -- deployed plan --context peerstar-prod --evidence-id prod-cluster --operation "k8s.namespaces:" --target-class NONPROD --phi-scope none --operator-id gmaida --authorized-by security-lead --authorization-reference JIRA-4418 --attest-authorized --out ../rta-evidence/prod-cluster
```

Expected on a machine with no `kubectl`: a non-zero exit and
`deployed-state acquisition needs kubectl on PATH and it is absent`. That is
the correct behaviour and the reason the probe is at plan time — a missing
dependency is a failure, never an empty success.

- [ ] **Step 7: Commit**

```bash
git add skills/last-aperture/lenses/_evidence-adapters scripts/lib/report.mjs package.json test/evidence-adapters.test.mjs test/evidence-report.test.mjs
git commit -m "docs: deployed and runtime adapter documents, and PHI-bearing evidence in the report"
```

---

## Self-review

**Spec coverage.** `## Components` → "Acquisition adapters" rows `deployed` and
`runtime` (Tasks 3 and 4); `## Authorization model` → the read-only verb
allowlist enforced controller-side (Task 1), attestation, target class, named
operator, `--confirm-authorization-current`, kill switch and impact counters
(Tasks 3, 4, 5); `## Authorization model` → `### PHI scope` in full, including
the three-row table, the metadata-only definition, and the interaction with
`hipaa-and-phi` (Tasks 2 and 6); `## Error handling` → probe at plan time,
`NOT_ASSESSED` with a named reason, no `COVERED` with an empty payload,
`PARTIAL` for unparsed output (Tasks 3 and 4); `## Testing` → "Hermetic CI" and
"PHI redaction tests" (Tasks 2, 3, 4, 5).

**What Phase 0 does not do, stated because the boundary is the point.** No
mutation, no exploitation, no relaxed hard rail. The design's
`## Phase 3 prerequisite: hard-rail amendment` records five consequences that a
future spec must address before any of that is possible, and this plan
implements none of them. Task 6's `runtime.md` says so in the document itself,
so the next reader of that file does not have to reconstruct the boundary from
a plan they may never see.

**One deliberate structural choice.** `deployed.mjs` and `runtime.mjs` share
most of their body, and Task 4 says to extract
`live-acquisition.mjs` if they diverge beyond the four named differences during
implementation. Writing the extraction into the plan up front would have been a
guess about a shape neither adapter has yet; naming the condition under which
to extract is the honest version.

**Type consistency.** Both adapters' `describe`/`plan`/`run` shapes match
Plan 1's conformance suite, which Tasks 3 and 4 run unmodified. The `run`
options object gains `authorizationConfirmed` and `shouldStop`, both optional,
so `artifact` and `registry` remain conforming without change.
`ImpactCounters.snapshot()` writes the same `impact-counters.json` shape as
Plan 4. `resolvePhiPolicy`'s return shape is written once in Task 2 and read in
Tasks 3 and 4. The fourth locator form added in Task 5 uses the same
`resolveEvidenceLocator` contract as Plan 3's three — `{kind, payload_path,
bytes}`, with `bytes: null` for the unresolvable case in every form.
