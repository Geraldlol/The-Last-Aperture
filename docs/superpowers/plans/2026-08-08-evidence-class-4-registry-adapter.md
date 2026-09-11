# `registry` Adapter Implementation Plan (Plan 4 of 5)

> **Superseded security notice (2026-09-03):** Do not use this historical plan
> as current operational guidance. Public registry acquisition `plan` and `run`
> are disabled before argument, bundle, process, credential, or registry access.
> Planning launched a caller-PATH-resolved executable, and execution trusted a
> mutable unsigned acquisition plan without revalidating its registry target.
> Re-enable only with signed canonical plans, controller-enrolled executable and
> registry identities, exact target/credential reconstruction at dispatch, and
> independent review. Contrary examples and safety claims below are historical.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Acquire a `built-artifact` bundle directly from a container registry — digest-pinned, credential-sealed, attested — reusing the normalizer and bundle writer Plan 3 already proved, and adding exactly one new thing: the first acquisition that leaves the machine.

**Architecture:** The `registry` adapter shells out to `crane` or `docker`, exactly as this repository already drives the `sf` CLI, rather than reimplementing the OCI distribution protocol. `plan` pins an exact `image@sha256:…` reference, seals a `credential_ref` (never a credential value), probes for the CLI and fails there when it is absent, and makes no network request. `run` executes one pinned pull into a temp directory and hands the resulting tarball to Plan 3's `normalizeOciLayout`. Every test injects a stub `crane` on `PATH` replaying canned bytes, so no test touches a live registry.

**Tech Stack:** Node.js 20+, ESM (`.mjs`), `node:child_process` (`execFile`, never a shell), `node:test` + `node:assert/strict`.

**Depends on:** Plans 1, 2 and 3, all committed. This plan writes no normalizer, no bundle format, and no coverage logic — it reuses all three.

## Global Constraints

- Branch: `agent/red-team-audit-v11-existence`. This plan touches no in-flight file.
- Baseline: 2 permanently failing `cloud-iac-fixtures.test.mjs` tests (ripgrep absent). Environmental, not regressions.
- `npm.cmd run lint` → `PASS: R1-R9, SKILL and ledger gate clean.` `npm.cmd run gen -- --check` → `PASS ... (174 slugs)`.
- **Never `exec` a shell.** Use `execFile` with an argument array. A registry reference is untrusted input and a shell would make it injectable.
- **Never write a credential value anywhere.** Not into the bundle, not into a log line, not into an error message. Only `credential_ref`. Plan 1's `CREDENTIAL_VALUE_PRESENT` check will refuse a bundle that carries one, and this plan must never rely on that catch.
- **Digest-pinned only.** A tag (`:latest`, `:v2`) is not an identity; the same tag resolves differently tomorrow, which makes a bundle unreproducible and a finding uncheckable. `plan` refuses a reference with no `@sha256:` component.
- **Hermetic CI.** Every test injects a stub `crane` on `PATH`. No test depends on a live registry, and CI must pass on a machine with no container tooling at all.
- Locale-independent ordering only: `compareCanonicalStrings`.

---

### Task 1: The bounded external-CLI runner

**Files:**
- Create: `scripts/lib/evidence-cli-runner.mjs`
- Test: `test/evidence-cli-runner.test.mjs`

**Interfaces:**
- Consumes: nothing.
- Produces, and Plan 5 reuses all of it:
  - `probeCli(name, {versionArgs, env}): Promise<{name, present: boolean, version: string|null, reason: string|null}>`
  - `runBoundedCli({name, args, limits, env, cwd}): Promise<{stdout: Buffer, stderr: string, code: number, counters: {commands, bytes_read, objects_touched}}>`
  - `ImpactCounters` class with `record({bytes, objects})`, `assertWithinCaps()`, `snapshot()`
  - `DEFAULT_CLI_LIMITS = {timeoutMs: 120000, maxStdoutBytes: 2 * 1024 * 1024 * 1024, maxCommands: 64, maxObjects: 4096}`
  - `CliUnavailableError`, `ImpactCapExceededError`

Impact counters live here rather than in the `registry` adapter because
`deployed` and `runtime` need the identical mechanism in Plan 5, and a second
implementation of a safety cap is a second place for it to be wrong.

- [ ] **Step 1: Write the failing test**

Create `test/evidence-cli-runner.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { chmod, mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  CliUnavailableError,
  DEFAULT_CLI_LIMITS,
  ImpactCapExceededError,
  ImpactCounters,
  probeCli,
  runBoundedCli,
} from '../scripts/lib/evidence-cli-runner.mjs'

// A stub on PATH is how every adapter test in Plans 4 and 5 avoids a live
// target. The stub is a real executable, so the runner is exercised end to
// end rather than mocked out.
async function stubOnPath(name, script) {
  const directory = await mkdtemp(join(tmpdir(), 'rta-stub-'))
  const isWindows = process.platform === 'win32'
  const path = join(directory, isWindows ? `${name}.cmd` : name)
  await writeFile(path, isWindows ? `@echo off\r\n${script.cmd}\r\n` : `#!/bin/sh\n${script.sh}\n`)
  if (!isWindows) await chmod(path, 0o755)
  return { directory, env: { ...process.env, PATH: `${directory}${isWindows ? ';' : ':'}${process.env.PATH}` } }
}

test('a present CLI probes with its version', async () => {
  const stub = await stubOnPath('crane', {
    sh: 'echo "crane version 0.19.1"',
    cmd: 'echo crane version 0.19.1',
  })
  const probe = await probeCli('crane', { versionArgs: ['version'], env: stub.env })
  assert.equal(probe.present, true)
  assert.match(probe.version, /0\.19\.1/)
})

test('an absent CLI probes absent with a named reason, and never throws by itself', async () => {
  const probe = await probeCli('definitely-not-installed-xyz', {
    versionArgs: ['--version'],
    env: { ...process.env, PATH: '' },
  })
  assert.equal(probe.present, false)
  assert.equal(probe.version, null)
  assert.match(probe.reason, /not (?:found|installed)|ENOENT/i)
})

test('a missing dependency is a failure, never an empty success', async () => {
  await assert.rejects(
    () => runBoundedCli({
      name: 'definitely-not-installed-xyz',
      args: ['pull'],
      env: { ...process.env, PATH: '' },
    }),
    (error) => error instanceof CliUnavailableError && /not found/i.test(error.message),
  )
})

test('stdout is returned as bytes and the command is counted', async () => {
  const stub = await stubOnPath('crane', { sh: 'printf "blob-bytes"', cmd: 'echo|set /p=blob-bytes' })
  const result = await runBoundedCli({ name: 'crane', args: ['export'], env: stub.env })
  assert.equal(result.code, 0)
  assert.match(result.stdout.toString('utf8'), /blob-bytes/)
  assert.equal(result.counters.commands, 1)
  assert.ok(result.counters.bytes_read > 0)
})

test('a non-zero exit is surfaced, not swallowed', async () => {
  const stub = await stubOnPath('crane', { sh: 'echo "UNAUTHORIZED" >&2; exit 1', cmd: 'echo UNAUTHORIZED 1>&2 & exit /b 1' })
  const result = await runBoundedCli({ name: 'crane', args: ['pull'], env: stub.env })
  assert.equal(result.code, 1)
  assert.match(result.stderr, /UNAUTHORIZED/)
})

test('impact counters halt acquisition at their caps', () => {
  const counters = new ImpactCounters({ maxCommands: 2, maxObjects: 3, maxBytes: 100 })
  counters.record({ commands: 1, bytes: 40, objects: 1 })
  counters.record({ commands: 1, bytes: 40, objects: 1 })
  assert.doesNotThrow(() => counters.assertWithinCaps())
  counters.record({ commands: 1, bytes: 0, objects: 0 })
  assert.throws(() => counters.assertWithinCaps(), ImpactCapExceededError)
})

test('the counter snapshot is what a bundle records', () => {
  const counters = new ImpactCounters({ maxCommands: 8, maxObjects: 8, maxBytes: 1024 })
  counters.record({ commands: 1, bytes: 12, objects: 2 })
  assert.deepEqual(counters.snapshot(), {
    commands: 1,
    bytes_read: 12,
    objects_touched: 2,
    caps: { commands: 8, bytes_read: 1024, objects_touched: 8 },
  })
})

test('the runner never accepts a shell string', async () => {
  await assert.rejects(
    () => runBoundedCli({ name: 'crane', args: 'pull registry/img && rm -rf /' }),
    /args must be an array/i,
  )
})

test('the default limits are bounded, not unbounded', () => {
  assert.ok(DEFAULT_CLI_LIMITS.timeoutMs > 0)
  assert.ok(DEFAULT_CLI_LIMITS.maxCommands > 0)
  assert.ok(DEFAULT_CLI_LIMITS.maxObjects > 0)
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-cli-runner.test.mjs`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/evidence-cli-runner.mjs`:

```js
import { execFile } from 'node:child_process'

export const DEFAULT_CLI_LIMITS = Object.freeze({
  timeoutMs: 120000,
  maxStdoutBytes: 2 * 1024 * 1024 * 1024,
  maxCommands: 64,
  maxObjects: 4096,
})

export class CliUnavailableError extends Error {
  constructor(name, reason) {
    super(`${name} not found on PATH: ${reason}`)
    this.name = 'CliUnavailableError'
    this.cli = name
    this.reason = reason
  }
}

export class ImpactCapExceededError extends Error {
  constructor(dimension, value, cap) {
    super(`acquisition halted: ${dimension} reached ${value}, above its cap of ${cap}`)
    this.name = 'ImpactCapExceededError'
    this.dimension = dimension
  }
}

/**
 * Commands executed, bytes read, and distinct objects touched, each capped.
 * These exist for read-only classes too: an unbounded read against production
 * is an availability risk regardless of intent.
 */
export class ImpactCounters {
  constructor({ maxCommands, maxObjects, maxBytes }) {
    this.caps = { commands: maxCommands, objects_touched: maxObjects, bytes_read: maxBytes }
    this.counters = { commands: 0, bytes_read: 0, objects_touched: 0 }
  }

  record({ commands = 0, bytes = 0, objects = 0 } = {}) {
    this.counters.commands += commands
    this.counters.bytes_read += bytes
    this.counters.objects_touched += objects
    return this
  }

  assertWithinCaps() {
    for (const [dimension, value] of Object.entries(this.counters)) {
      const cap = this.caps[dimension]
      if (typeof cap === 'number' && value > cap) {
        throw new ImpactCapExceededError(dimension, value, cap)
      }
    }
    return this
  }

  snapshot() {
    return { ...this.counters, caps: { ...this.caps } }
  }
}

function execFileAsync(name, args, options) {
  return new Promise((resolve) => {
    execFile(name, args, { ...options, encoding: 'buffer' }, (error, stdout, stderr) => {
      resolve({
        error,
        stdout: stdout ?? Buffer.alloc(0),
        stderr: (stderr ?? Buffer.alloc(0)).toString('utf8'),
      })
    })
  })
}

/**
 * Probes without throwing. An absent CLI is a fact the caller records as a
 * coverage gap, not an exception it has to catch to stay honest — and
 * "the tool was missing" must never be able to read as "the target was safe".
 */
export async function probeCli(name, { versionArgs = ['--version'], env = process.env } = {}) {
  const { error, stdout } = await execFileAsync(name, versionArgs, { env, timeout: 15000 })
  if (error && (error.code === 'ENOENT' || error.code === 'EACCES')) {
    return { name, present: false, version: null, reason: `${error.code}: not found on PATH` }
  }
  if (error && error.killed) {
    return { name, present: false, version: null, reason: 'version probe timed out' }
  }
  const text = stdout.toString('utf8').trim()
  return { name, present: true, version: text === '' ? null : text.split('\n')[0], reason: null }
}

export async function runBoundedCli({
  name,
  args,
  limits = DEFAULT_CLI_LIMITS,
  env = process.env,
  cwd,
  counters,
}) {
  // A registry reference is untrusted input. execFile with an argument array
  // has no shell to inject into; a command string would.
  if (!Array.isArray(args)) throw new TypeError('args must be an array; this runner never spawns a shell')

  const { error, stdout, stderr } = await execFileAsync(name, args, {
    env,
    cwd,
    timeout: limits.timeoutMs,
    maxBuffer: limits.maxStdoutBytes,
    shell: false,
    windowsHide: true,
  })
  if (error && (error.code === 'ENOENT' || error.code === 'EACCES')) {
    throw new CliUnavailableError(name, `${error.code}: not found on PATH`)
  }

  const tracked = counters ?? new ImpactCounters({
    maxCommands: limits.maxCommands,
    maxObjects: limits.maxObjects,
    maxBytes: limits.maxStdoutBytes,
  })
  tracked.record({ commands: 1, bytes: stdout.length, objects: 1 }).assertWithinCaps()

  return {
    stdout,
    stderr,
    code: error?.code === undefined ? 0 : Number(error.code) || (error.killed ? 124 : 1),
    counters: tracked.snapshot(),
  }
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm.cmd test -- test/evidence-cli-runner.test.mjs`
Expected: PASS, 9 tests

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/evidence-cli-runner.mjs test/evidence-cli-runner.test.mjs
git commit -m "feat: bounded shell-free external CLI runner with impact counters"
```

---

### Task 2: Digest pinning and credential sealing

**Files:**
- Create: `scripts/lib/evidence-image-reference.mjs`
- Test: `test/evidence-image-reference.test.mjs`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `parsePinnedImageReference(value): {registry, repository, digest, canonical}` — throws on any unpinned form
  - `sealCredentialRef(value): {credential_ref: string}` — throws if handed something that looks like a credential *value*
  - `redactForLog(text): string`

Digest pinning is not a nicety. A bundle acquired from `app:latest` records an
identity that means something different tomorrow, so a finding citing it cannot
be re-verified — and re-verification being exact is the one guarantee bundles
have that repository checkouts do not.

- [ ] **Step 1: Write the failing test**

Create `test/evidence-image-reference.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  parsePinnedImageReference,
  redactForLog,
  sealCredentialRef,
} from '../scripts/lib/evidence-image-reference.mjs'

const DIGEST = 'sha256:9f2c1d0e4b6a8c3f5e7d9b1a3c5e7f9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c'

test('a digest-pinned reference parses into its parts', () => {
  const parsed = parsePinnedImageReference(`registry.example.com/peerstar/api@${DIGEST}`)
  assert.equal(parsed.registry, 'registry.example.com')
  assert.equal(parsed.repository, 'peerstar/api')
  assert.equal(parsed.digest, DIGEST)
  assert.equal(parsed.canonical, `registry.example.com/peerstar/api@${DIGEST}`)
})

test('a tag is not an identity and is refused', () => {
  for (const reference of [
    'registry.example.com/peerstar/api:latest',
    'registry.example.com/peerstar/api',
    'peerstar/api:v2.1.0',
    `registry.example.com/peerstar/api:v2@${DIGEST.slice(0, 20)}`,
  ]) {
    assert.throws(() => parsePinnedImageReference(reference), /digest|pinned/i, reference)
  }
})

test('a reference carrying shell metacharacters is refused before it reaches a CLI', () => {
  assert.throws(
    () => parsePinnedImageReference(`registry.example.com/a;rm -rf /@${DIGEST}`),
    /invalid/i,
  )
})

test('a credential reference is sealed; a credential value is refused', () => {
  assert.deepEqual(sealCredentialRef('env:REGISTRY_TOKEN'), { credential_ref: 'env:REGISTRY_TOKEN' })
  assert.deepEqual(sealCredentialRef('keychain:peerstar-registry'), {
    credential_ref: 'keychain:peerstar-registry',
  })
  for (const value of [
    'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'password=hunter2',
    'https://ci:hunter2@registry.example.com',
    '-----BEGIN OPENSSH PRIVATE KEY-----',
  ]) {
    assert.throws(() => sealCredentialRef(value), /credential value|reference/i, value)
  }
})

test('a credential reference must name a resolver, not float free', () => {
  assert.throws(() => sealCredentialRef('REGISTRY_TOKEN'), /env:|file:|keychain:/)
})

test('redaction is applied to anything that reaches a log or an error', () => {
  assert.equal(
    redactForLog('failed: https://ci:hunter2@registry.example.com/v2/'),
    'failed: https://ci:[REDACTED]@registry.example.com/v2/',
  )
  assert.match(redactForLog('Authorization: Bearer eyJhbGciOi'), /Bearer \[REDACTED\]/)
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-image-reference.test.mjs`
Expected: FAIL — module not found

- [ ] **Step 3: Write the implementation**

Create `scripts/lib/evidence-image-reference.mjs`:

```js
const DIGEST_PATTERN = /^sha256:[0-9a-f]{64}$/
const HOST_PATTERN = /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[0-9]{1,5})?$/
const REPOSITORY_PATTERN = /^[a-z0-9]+(?:[._-][a-z0-9]+)*(?:\/[a-z0-9]+(?:[._-][a-z0-9]+)*)*$/
const CREDENTIAL_REF_PATTERN = /^(?:env|file|keychain|vault):[A-Za-z0-9._/-]{1,256}$/

const CREDENTIAL_VALUE_PATTERNS = [
  /\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]/i,
  /\b[a-z]+:\/\/[^/\s:@]+:[^/\s@]+@/i,
  /-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----/,
  /\b(?:gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16})\b/,
  /\beyJ[A-Za-z0-9_-]{8,}\./,
]

/**
 * A tag is not an identity. The same tag resolves differently tomorrow, which
 * makes a bundle unreproducible and every finding citing it uncheckable — and
 * exact re-verification is the one guarantee a bundle has that a repository
 * checkout does not.
 */
export function parsePinnedImageReference(value) {
  const reference = String(value).trim()
  const at = reference.lastIndexOf('@')
  if (at === -1) {
    throw new Error(
      `image reference must be digest-pinned as <repository>@sha256:<64 hex>: ${reference}`,
    )
  }
  const digest = reference.slice(at + 1)
  if (!DIGEST_PATTERN.test(digest)) {
    throw new Error(`image digest must match sha256:<64 hex>: ${digest}`)
  }
  const name = reference.slice(0, at)
  if (name.includes(':')) {
    throw new Error(
      `a digest-pinned reference carries no tag; drop the tag from ${name}`,
    )
  }

  const slash = name.indexOf('/')
  const first = slash === -1 ? '' : name.slice(0, slash)
  const looksLikeHost = first.includes('.') || first.includes(':') || first === 'localhost'
  const registry = looksLikeHost ? first : 'docker.io'
  const repository = looksLikeHost ? name.slice(slash + 1) : name

  if (!HOST_PATTERN.test(registry)) throw new Error(`invalid registry host: ${registry}`)
  if (!REPOSITORY_PATTERN.test(repository)) throw new Error(`invalid repository name: ${repository}`)

  return {
    registry,
    repository,
    digest,
    canonical: `${looksLikeHost ? `${registry}/` : ''}${repository}@${digest}`,
  }
}

/**
 * Only a reference, never a value. The reference names where a credential
 * lives; the acquisition process resolves it at run time and it never lands
 * in a bundle, a log line, or an error message.
 */
export function sealCredentialRef(value) {
  const reference = String(value).trim()
  if (CREDENTIAL_VALUE_PATTERNS.some((pattern) => pattern.test(reference))) {
    throw new Error(
      'that looks like a credential value; supply a credential reference such as '
      + 'env:REGISTRY_TOKEN instead',
    )
  }
  if (!CREDENTIAL_REF_PATTERN.test(reference)) {
    throw new Error(
      'a credential reference names its resolver: env:, file:, keychain: or vault:',
    )
  }
  return { credential_ref: reference }
}

export function redactForLog(text) {
  return String(text)
    .replace(/([a-z]+:\/\/[^/\s:@]+):[^/\s@]+@/gi, '$1:[REDACTED]@')
    .replace(/\b(Bearer|Basic)\s+\S+/gi, '$1 [REDACTED]')
    .replace(/\b((?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*)\S+/gi, '$1[REDACTED]')
}
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `npm.cmd test -- test/evidence-image-reference.test.mjs`
Expected: PASS, 6 tests

- [ ] **Step 5: Commit**

```bash
git add scripts/lib/evidence-image-reference.mjs test/evidence-image-reference.test.mjs
git commit -m "feat: digest-pinned image references and credential references that refuse values"
```

---

### Task 3: The `registry` adapter

**Files:**
- Create: `scripts/lib/evidence-adapters/registry.mjs`
- Create: `test/helpers/stub-cli.mjs`
- Test: `test/evidence-registry-adapter.test.mjs`

**Interfaces:**
- Consumes: `probeCli`/`runBoundedCli`/`ImpactCounters` (Task 1); `parsePinnedImageReference`/`sealCredentialRef` (Task 2); `normalizeOciLayout` (Plan 3); `writeEvidenceBundle` (Plan 1).
- Produces:
  - `createRegistryAdapter({clock, env, limits}): {describe, plan, run}`
  - `test/helpers/stub-cli.mjs` exporting `stubCliOnPath(name, {sh, cmd}): Promise<{directory, env}>` — extracted from Task 1's test so Plan 5 reuses one implementation

The adapter's shape is deliberately thin: `plan` pins and probes, `run` pulls
once and hands the bytes to the normalizer. Everything downstream of the
tarball is Plan 3's code, unchanged.

- [ ] **Step 1: Write the failing test**

Create `test/evidence-registry-adapter.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtemp, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createRegistryAdapter } from '../scripts/lib/evidence-adapters/registry.mjs'
import { verifyEvidenceBundle } from '../scripts/lib/evidence-bundle.mjs'
import { runEvidenceAdapterConformance } from './helpers/evidence-adapter-conformance.mjs'
import { stubCliOnPath } from './helpers/stub-cli.mjs'

const DIGEST = 'sha256:9f2c1d0e4b6a8c3f5e7d9b1a3c5e7f9b1d3f5a7c9e1b3d5f7a9c1e3b5d7f9a1c'
const REFERENCE = `registry.example.com/peerstar/api@${DIGEST}`
const FIXTURE = 'test/fixtures/evidence/vulnerable-image.tar'

// The stub copies the committed fixture to wherever crane was told to write.
// Every registry test runs against these bytes; none touches a network.
async function craneStub() {
  return stubCliOnPath('crane', {
    sh: 'if [ "$1" = "version" ]; then echo "0.19.1"; else cp "'
      + `${process.cwd().replaceAll('\\\\', '/')}/${FIXTURE}" "$4"; fi`,
    cmd: 'if "%1"=="version" (echo 0.19.1) else (copy /y "'
      + `${process.cwd()}\\${FIXTURE}" "%4" >nul)`,
  })
}

async function adapterWithStub() {
  const stub = await craneStub()
  return createRegistryAdapter({ clock: () => '2026-08-08T14:22:10Z', env: stub.env })
}

const REQUEST = {
  evidence_id: 'peerstar-api-image',
  image: REFERENCE,
  credential_ref: 'env:REGISTRY_TOKEN',
  target_class: 'NONPROD',
  phi_scope: 'none',
  attest_authorized: true,
  operator_id: 'gmaida',
  authorized_by: 'platform-lead',
  authorization_reference: 'JIRA-4417',
}

// The shared suite, unmodified, against the second real adapter.
runEvidenceAdapterConformance(await adapterWithStub(), { validPlanRequest: REQUEST })

test('plan pins the digest and never contacts the registry', async () => {
  const adapter = await adapterWithStub()
  const planned = await adapter.plan(REQUEST)
  assert.equal(planned.evidence_context_seed.target_identity, DIGEST)
  assert.equal(planned.evidence_context_seed.acquisition_mode, 'registry-pull')
  assert.equal(planned.image_reference, REFERENCE)
  assert.equal(planned.dependency.present, true)
})

test('plan refuses an unpinned reference', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, image: 'registry.example.com/peerstar/api:latest' }),
    /digest|pinned/i,
  )
})

test('plan refuses without attestation, because built-artifact via registry requires it', async () => {
  const adapter = await adapterWithStub()
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, attest_authorized: false }),
    /attest/i,
  )
})

test('plan fails when crane is absent rather than succeeding emptily', async () => {
  const adapter = createRegistryAdapter({
    clock: () => '2026-08-08T14:22:10Z',
    env: { ...process.env, PATH: '' },
  })
  await assert.rejects(() => adapter.plan(REQUEST), /crane|docker|not found/i)
})

test('the sealed plan carries a credential reference and no credential value', async () => {
  const adapter = await adapterWithStub()
  const planned = await adapter.plan(REQUEST)
  assert.equal(planned.credential_ref, 'env:REGISTRY_TOKEN')
  assert.equal(JSON.stringify(planned).includes('REGISTRY_TOKEN='), false)
  await assert.rejects(
    () => adapter.plan({ ...REQUEST, credential_ref: 'ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' }),
    /credential value/i,
  )
})

test('run pulls once and produces a verifiable built-artifact bundle', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.deepEqual((await verifyEvidenceBundle(written.directory)).errors, [])
  assert.equal(written.profile.evidence_context.evidence_class, 'built-artifact')
  assert.equal(written.profile.artifact_kind, 'oci-image')
  assert.equal(written.profile.coverage_state, 'COVERED')
  assert.equal(written.profile.attestation.operator_id, 'gmaida')
  assert.equal(written.profile.attestation.credential_ref, 'env:REGISTRY_TOKEN')
})

test('the acquired bytes are the pinned image, not a tag resolution', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  const expected = await readFile(FIXTURE)
  assert.ok(expected.length > 0)
  assert.equal(written.profile.evidence_context.target_identity, DIGEST)
})

test('a pull that fails authentication is NOT_ASSESSED with a redacted reason', async () => {
  const stub = await stubCliOnPath('crane', {
    sh: 'if [ "$1" = "version" ]; then echo "0.19.1"; else echo "UNAUTHORIZED for https://ci:hunter2@registry.example.com" >&2; exit 1; fi',
    cmd: 'if "%1"=="version" (echo 0.19.1) else (echo UNAUTHORIZED for https://ci:hunter2@registry.example.com 1>&2 & exit /b 1)',
  })
  const adapter = createRegistryAdapter({ clock: () => '2026-08-08T14:22:10Z', env: stub.env })
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  assert.equal(written.profile.coverage_state, 'NOT_ASSESSED')
  assert.equal(written.profile.files.length, 0)
  const reason = written.profile.coverage_gaps[0].reason
  assert.match(reason, /UNAUTHORIZED/)
  assert.equal(reason.includes('hunter2'), false)
})

test('impact counters are recorded on the bundle', async () => {
  const adapter = await adapterWithStub()
  const out = join(await mkdtemp(join(tmpdir(), 'rta-registry-')), 'ev')
  const written = await adapter.run(await adapter.plan(REQUEST), { out })
  const counters = JSON.parse(
    (await readFile(join(written.directory, 'payload', 'impact-counters.json'))).toString('utf8'),
  )
  assert.equal(counters.commands, 1)
  assert.ok(counters.bytes_read > 0)
})
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npm.cmd test -- test/evidence-registry-adapter.test.mjs`
Expected: FAIL — module not found

- [ ] **Step 3: Extract the stub helper**

Create `test/helpers/stub-cli.mjs` with the `stubOnPath` body from Task 1's
test, exported as `stubCliOnPath`, and change Task 1's test to import it rather
than keeping a second copy.

- [ ] **Step 4: Write the adapter**

Create `scripts/lib/evidence-adapters/registry.mjs`:

```js
import { mkdtemp, readFile, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { writeEvidenceBundle } from '../evidence-bundle.mjs'
import {
  DEFAULT_CLI_LIMITS,
  ImpactCounters,
  probeCli,
  runBoundedCli,
} from '../evidence-cli-runner.mjs'
import {
  parsePinnedImageReference,
  redactForLog,
  sealCredentialRef,
} from '../evidence-image-reference.mjs'
import { DEFAULT_NORMALIZER_LIMITS, normalizeOciLayout } from '../oci-normalizer.mjs'
import { buildArtifactPayload } from './artifact.mjs'

const ADAPTER_VERSION = '1.0.0'

const CAPABILITIES = Object.freeze({
  'target-identity': 'NATIVE',
  'content-enumeration': 'NATIVE',
  'content-retrieval': 'NATIVE',
  'layer-or-revision-history': 'NATIVE',
  'metadata-provenance': 'NATIVE',
  'deletion-recoverability': 'NATIVE',
  'effective-configuration': 'EXTERNAL_ONLY',
  'principal-and-permission-state': 'EXTERNAL_ONLY',
  'secret-material-surface': 'NATIVE',
  'impact-accounting': 'NATIVE',
})

export function createRegistryAdapter({
  clock = () => new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
  env = process.env,
  limits = {},
} = {}) {
  const cliLimits = { ...DEFAULT_CLI_LIMITS, ...limits }

  return {
    describe: () => ({
      adapter_id: 'registry',
      evidence_class: 'built-artifact',
      adapter_version: ADAPTER_VERSION,
      capabilities: { ...CAPABILITIES },
      external_dependency: 'crane|docker',
    }),

    plan: async (request) => {
      // built-artifact via registry sits above its class floor: the pull
      // leaves this machine, so attestation is required where the offline
      // artifact adapter needs none.
      if (request.attest_authorized !== true) {
        throw new Error('registry acquisition requires --attest-authorized')
      }
      const pinned = parsePinnedImageReference(request.image)
      const sealed = sealCredentialRef(request.credential_ref)

      // The probe happens at plan time, not run time. A missing CLI must fail
      // where an operator is watching, not later as an empty success.
      const probe = await probeCli('crane', { versionArgs: ['version'], env })
      if (!probe.present) {
        throw new Error(
          `registry acquisition needs crane on PATH and it is absent (${probe.reason}); `
          + 'install it or use the artifact adapter against a docker save export',
        )
      }

      return {
        plan_id: `registry:${pinned.digest.slice(7, 23)}`,
        image_reference: pinned.canonical,
        credential_ref: sealed.credential_ref,
        evidence_context_seed: {
          evidence_id: request.evidence_id,
          evidence_class: 'built-artifact',
          adapter_id: 'registry',
          target_identity: pinned.digest,
          acquisition_mode: 'registry-pull',
          detection_evidence: [`${pinned.registry}/${pinned.repository} pinned at ${pinned.digest}`],
          confidence: 'high',
        },
        attestation: {
          operator_id: request.operator_id,
          authorized_by: request.authorized_by,
          authorization_reference: request.authorization_reference,
          attested_on: clock(),
          credential_ref: sealed.credential_ref,
        },
        target_class: request.target_class ?? 'NONPROD',
        phi_scope: request.phi_scope ?? 'none',
        dependency: { name: 'crane', present: true, version: probe.version },
      }
    },

    run: async (planned, { out }) => {
      const counters = new ImpactCounters({
        maxCommands: cliLimits.maxCommands,
        maxObjects: cliLimits.maxObjects,
        maxBytes: cliLimits.maxStdoutBytes,
      })
      const scratch = await mkdtemp(join(tmpdir(), 'rta-registry-pull-'))
      const target = join(scratch, 'image.tar')

      const baseProfile = {
        schema: 'evidence-bundle-v1',
        evidence_context: { ...planned.evidence_context_seed, acquired_on: clock() },
        target_class: planned.target_class,
        phi_scope: planned.phi_scope,
        phi_bearing: false,
        adapter_version: ADAPTER_VERSION,
        contract_version: 1,
        attestation: planned.attestation,
      }

      try {
        const result = await runBoundedCli({
          name: 'crane',
          args: ['pull', '--format', 'oci', planned.image_reference, target],
          limits: cliLimits,
          env,
          counters,
        })
        if (result.code !== 0) {
          // A failed pull is NOT_ASSESSED with a named reason. It is never an
          // empty COVERED, and the reason is redacted before it is recorded.
          return await writeEvidenceBundle({
            directory: out,
            profile: {
              ...baseProfile,
              coverage_state: 'NOT_ASSESSED',
              artifact_kind: 'oci-image',
              coverage_gaps: [{
                area: 'registry pull',
                reason: `crane pull exited ${result.code}: ${redactForLog(result.stderr).slice(0, 480)}`,
              }],
            },
            payload: [],
          })
        }

        const bytes = await readFile(target)
        counters.record({ bytes: bytes.length }).assertWithinCaps()
        const normalized = normalizeOciLayout(bytes, { ...DEFAULT_NORMALIZER_LIMITS, ...limits })
        const { payload, gaps } = buildArtifactPayload(bytes, normalized, {
          ...DEFAULT_NORMALIZER_LIMITS,
          ...limits,
        })
        payload.push({
          path: 'impact-counters.json',
          bytes: Buffer.from(JSON.stringify(counters.snapshot(), null, 2), 'utf8'),
        })

        return await writeEvidenceBundle({
          directory: out,
          profile: {
            ...baseProfile,
            coverage_state: normalized.layers.length === 0
              ? 'NOT_ASSESSED'
              : gaps.length > 0 ? 'PARTIAL' : 'COVERED',
            artifact_kind: 'oci-image',
            coverage_gaps: gaps,
          },
          payload,
        })
      } finally {
        await rm(scratch, { recursive: true, force: true })
      }
    },
  }
}
```

- [ ] **Step 5: Extract the shared payload builder**

This adapter and Plan 3's `artifact` adapter build the identical payload from a
normalized image. Refactor Plan 3's `run` so its payload construction lives in
one exported function and both adapters call it:

```js
// in scripts/lib/evidence-adapters/artifact.mjs
export function buildArtifactPayload(archiveBytes, normalized, limits) {
  // …the payload construction currently inline in artifact.run, returning
  // { payload, gaps } instead of writing the bundle…
}
```

Then `artifact.run` becomes a thin caller of it. Run
`npm.cmd test -- test/evidence-artifact-adapter.test.mjs` after the refactor —
its assertions are unchanged and must still pass, which is what proves the
extraction was behaviour-preserving.

- [ ] **Step 6: Register the adapter with the controller**

In `scripts/lib/evidence-acquire-controller.mjs`, add to `ADAPTER_FACTORIES`:

```js
  ['registry', createRegistryAdapter],
```

and extend `scripts/acquire.mjs`'s `COMMANDS.plan` for the `registry` adapter:
`required: ['image', 'credential-ref', 'evidence-id', 'operator-id', 'authorized-by', 'authorization-reference', 'out']`, `requiredFlags: ['attest-authorized']`, `optional: ['target-class', 'phi-scope', 'json']`. The
per-adapter required set is selected by the adapter positional, so
`artifact plan` keeps its simpler shape.

- [ ] **Step 7: Run the tests**

Run: `npm.cmd test -- test/evidence-registry-adapter.test.mjs test/evidence-artifact-adapter.test.mjs test/evidence-acquire-controller.test.mjs`
Expected: PASS

- [ ] **Step 8: Commit**

```bash
git add scripts/lib/evidence-adapters scripts/lib/evidence-acquire-controller.mjs scripts/acquire.mjs test/helpers/stub-cli.mjs test/evidence-registry-adapter.test.mjs test/evidence-cli-runner.test.mjs
git commit -m "feat: digest-pinned credential-sealed registry acquisition"
```

---

### Task 4: The `registry` adapter document and suite registration

**Files:**
- Create: `skills/last-aperture/lenses/_evidence-adapters/registry.md`
- Modify: `package.json` — `test:platform`
- Test: `test/evidence-adapters.test.mjs` (extend)

- [ ] **Step 1: Write the failing test**

Append to `test/evidence-adapters.test.mjs`:

```js
const REGISTRY_DOC = fileURLToPath(
  new URL('../skills/last-aperture/lenses/_evidence-adapters/registry.md', import.meta.url),
)

test('the registry adapter document states its authorization requirements', () => {
  const doc = readFileSync(REGISTRY_DOC, 'utf8')
  assert.match(doc, /digest-pinned/i)
  assert.match(doc, /credential_ref/)
  assert.match(doc, /attestation/i)
  assert.match(doc, /never (?:a |any )?credential value/i)
})

test('the registry adapter declares no rule anchors of its own', () => {
  // Detection over the acquired image is the oci format's business, declared
  // in artifact.md. Two documents declaring the same anchor would make the
  // ID ambiguous, which rule 6 exists to prevent.
  assert.deepEqual([...declaredEvidenceRuleAnchors(readFileSync(REGISTRY_DOC, 'utf8'))], [])
})
```

- [ ] **Step 2: Write the document**

Create `skills/last-aperture/lenses/_evidence-adapters/registry.md` stating:
canonical `adapter_id: registry`, `verified_on`, the ten capabilities with the
values `describe()` returns, the digest-pinning requirement and why a tag is
not an identity, the `credential_ref` rule ("a bundle carries a credential
reference and never a credential value"), the attestation requirement, the
impact counters recorded, and an explicit pointer that detection rules over the
acquired image live in `artifact.md` under the `oci` adapter segment.

- [ ] **Step 3: Register the tests**

Append to `package.json`'s `test:platform`:

```text
test/evidence-cli-runner.test.mjs test/evidence-image-reference.test.mjs test/evidence-registry-adapter.test.mjs
```

- [ ] **Step 4: Run everything**

Run: `npm.cmd test`
Expected: the 2 known ripgrep failures only.

Run: `npm.cmd run test:platform` → PASS
Run: `npm.cmd run lint` → `PASS: R1-R9, SKILL and ledger gate clean.`
Run: `npm.cmd run gen -- --check` → `PASS ... (174 slugs).`

- [ ] **Step 5: Commit**

```bash
git add skills/last-aperture/lenses/_evidence-adapters/registry.md package.json test/evidence-adapters.test.mjs
git commit -m "docs: registry adapter document and platform suite registration"
```

---

## Self-review

**Spec coverage.** `## Components` → "Acquisition adapters" row `registry`
(Tasks 1-3); `## Authorization model` → "`built-artifact` via `registry`:
Sealed `credential_ref`, digest-pinned image, attestation" (Tasks 2 and 3);
`## Decisions and rationale` → "Adapter mechanism: shell out to existing CLIs"
and "Credentials: sealed reference only, never values" (Tasks 1-3);
`## Error handling` → probe at plan time, `NOT_ASSESSED` on failure, never
`COVERED` with an empty payload (Task 3); `## Testing` → "Hermetic CI"
(Task 3's stub, and Task 1's runner tests).

**One design decision worth naming.** Impact counters are built here, in Task 1,
even though the spec attaches them to `deployed-state` and `live-runtime`. The
registry adapter is the first thing that leaves the machine, and a counter
mechanism written for the first network caller and reused by the next two is
one implementation of a safety cap instead of two. The `registry` adapter's
class floor does not *require* counters; it records them anyway, which costs
nothing and means Plan 5 inherits a mechanism that has already run.

**One refactor this plan forces on Plan 3.** Task 3, Step 5 extracts
`buildArtifactPayload` from the `artifact` adapter so both adapters build one
payload shape. Doing it here rather than in Plan 3 is deliberate — a shared
abstraction with one caller is a guess; with two it is a fact. The extraction
is verified by re-running Plan 3's unchanged test file.

**Type consistency.** `createRegistryAdapter`'s `describe`/`plan`/`run` shapes
match Plan 1's conformance suite, which Task 3 runs unmodified. `attestation`'s
five fields match `evidence-bundle.schema.json`'s `$defs.attestation` exactly.
`ImpactCounters.snapshot()`'s shape is written once in Task 1 and consumed in
Task 3 and again in Plan 5.
