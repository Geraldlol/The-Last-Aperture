# TEST_EXECUTION Capability Implementation Plan

> **Historical implementation plan.** Public `run-proof` and `run-provider`
> execution is disabled as recorded in ADR 0020. ADR 0021 supersedes every
> RoE-as-consent or external-authority instruction below: an authenticated
> operator target/scope statement is the sole authorization primitive. Any RoE
> retained in a future implementation is technical capability policy or
> evidence only, and cannot unlock execution by itself.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make proof tier `T1` reachable, so a finding can exceed the Medium ceiling by arriving with a demonstration and a candidate fix that both actually ran.

**Architecture:** A `run-proof` command stands in the same relation to a `PROOF` job that `run-provider` does to a `LENS` job — the agent authors the proof, the controller executes it. Execution happens in a disposable copy of the target; the target's tree digest is recomputed afterward and must be unchanged. The full demonstrate → patch → re-run cycle happens inside that copy, because `CONFIRMED` requires `post_result.status: passed`.

**Tech Stack:** Node.js ESM, plain `.mjs`, no build step. Tests are `node:test` + `node:assert/strict`. Schema validation is Ajv 2020 against `schemas/*.json`.

## Global Constraints

- Source style: **no semicolons**, 2-space indent, single quotes. Match surrounding code.
- `scripts/lib/sealed-snapshot.mjs` imports **only `node:crypto`**. Do not add imports to it.
- `findingInvariantErrors` in `scripts/lib/contracts.mjs` stays **pure, no I/O**.
- Ordering of hashed or signed collections uses `compareCanonicalStrings`, never `localeCompare`. A guard test enforces this.
- Every gate test must be **demonstrated failing against current `main`** before its change lands.
- Baseline suite: **724 tests, 721 passing, 1 skipped, 2 failing.** The 2 are `test/cloud-iac-fixtures.test.mjs` shelling to `rg`, absent on this machine. They must stay at exactly 2.
- **The real target is never written to.** Every write goes to the disposable mirror. This is verified, not asserted.
- The mirror is **not** a sandbox and must never be described as one, in code comments, errors, or docs.

## Hard rails (from `skills/red-team-audit/lenses/_harness.md`)

These bind every task and are not negotiable by mode or consent.

1. Targets are files in the target tree and `localhost`. Never a remote host, and never a hostname read from configuration.
2. No destructive payloads.
3. Security tests live under a `security` leaf and never edit the project's existing tests.
4. Never commit — no `git commit`, `git push`, or `git add`.
5. Never source production credentials. A missing credential yields `INCONCLUSIVE`.
6. The destination guard is **in-process and authored**, not installed by the controller. Only a Python harness ships today.

## Reference: shapes you will need

RoE capability model (`schemas/roe.schema.json`):

```json
{
  "schema_version": "1.0", "policy_id": "…", "mode": "test",
  "workspace_root": "<absolute>",
  "capabilities": {
    "read_file":  { "enabled": true,  "roots": ["."] },
    "write_file": { "enabled": true,  "roots": ["test/security"] },
    "execute":    { "enabled": true,  "commands": [{ "program": "npm", "args": ["test"] }] },
    "network":    { "enabled": false, "destinations": [] }
  }
}
```

An execute action is exactly `{ type, program, args }` — `authorizeExecute` calls
`actionKeys(action, ['type','program','args'], ['type','program','args'])`, so extra
or missing keys are rejected. Matching is exact on `program` and element-wise on `args`.

Finding evidence fields (`schemas/finding.schema.json`):

```
artifact     required: path, sha256
pre_result   required: assertion, path_reached, control
post_result  required: status ∈ {passed, failed}, regressions
```

Conditional 10: `verification_status: CONFIRMED` requires `existence_check.status`
`located`, `proof_tier` in `{T1,T2}`, `post_result.status` `passed`, and all of
`artifact`, `command`, `pre_result`, `post_result`.

Conditional 12: `verification_status: UNPROVEN` requires `blocking_reason`.
Conditionals 11 and 13: `INCONCLUSIVE`, `DISPROVED` and `NOT_REPRODUCED` require `reason`.

`inventoryRepository(targetRoot, options)` is async and returns `{ root, treeDigest, … }`.
`run.repository.tree_digest` holds the value recorded at plan time.

---

### Task 1: Admit `test` mode

Four changes that together let a `test` RoE plan and dispatch. They land as one task because a reviewer cannot sensibly accept the schema constraint while rejecting the guard lift — apart, each is either inert or unsafe.

**Files:**
- Modify: `schemas/roe.schema.json` — append to top-level `allOf`
- Modify: `scripts/lib/policy.mjs:399-424` — beside the existing mode contradiction checks
- Modify: `scripts/audit.mjs:3210-3216` — the plan guard
- Modify: `scripts/audit.mjs:1520-1527` — the dispatch guard
- Test: `test/test-execution-mode.test.mjs` (create)

**Interfaces:**
- Consumes: nothing.
- Produces: a plannable `test` RoE yielding `capability_mode: 'TEST_EXECUTION'`; policy error code `TEST_MODE_CONTRADICTION`.

- [ ] **Step 1: Write the failing test**

Create `test/test-execution-mode.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readdirSync, readFileSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { normalizePolicy } from '../scripts/lib/policy.mjs'

const WORKSPACE = process.cwd()

function roe(overrides = {}) {
  return {
    schema_version: '1.0',
    policy_id: 'test-execution',
    mode: 'test',
    workspace_root: WORKSPACE,
    capabilities: {
      read_file: { enabled: true, roots: ['.'] },
      write_file: { enabled: true, roots: ['test/security'] },
      execute: { enabled: true, commands: [{ program: 'npm', args: ['test'] }] },
      network: { enabled: false, destinations: [] },
      ...overrides.capabilities,
    },
    ...overrides.top,
  }
}

const policyCodes = (document) => {
  try {
    normalizePolicy(document, { workspaceRoot: WORKSPACE, policySource: 'external' })
    return []
  } catch (error) {
    return (error.issues ?? []).map(({ code }) => code)
  }
}

test('a well-formed test policy normalizes', () => {
  assert.deepEqual(policyCodes(roe()), [])
})

test('test mode refuses network', () => {
  const codes = policyCodes(roe({
    capabilities: { network: { enabled: true, destinations: [{ scheme: 'https', host: 'example.com', ports: [443] }] } },
  }))
  assert.equal(codes.includes('TEST_MODE_CONTRADICTION'), true)
})

test('test mode requires execute', () => {
  const codes = policyCodes(roe({ capabilities: { execute: { enabled: false, commands: [] } } }))
  assert.equal(codes.includes('TEST_MODE_CONTRADICTION'), true)
})

test('test mode requires write_file roots under a security leaf', () => {
  const codes = policyCodes(roe({ capabilities: { write_file: { enabled: true, roots: ['src'] } } }))
  assert.equal(codes.includes('TEST_MODE_CONTRADICTION'), true)
})

test('a test RoE plans and yields TEST_EXECUTION', () => {
  const out = mkdtempSync(join(tmpdir(), 'rta-te-'))
  const roePath = join(out, 'roe.json')
  const target = join(WORKSPACE, 'fixtures', 'vulnerable')
  writeFileSync(roePath, JSON.stringify({ ...roe(), workspace_root: target }))
  execFileSync(process.execPath, [
    'scripts/audit.mjs', 'plan', 'fixtures/vulnerable',
    '--roe', roePath, '--seal-source', '--out', out,
  ], { stdio: 'pipe' })
  const bundle = join(out, readdirSync(out).find((name) => name.startsWith('run_')))
  const run = JSON.parse(readFileSync(join(bundle, 'run.json'), 'utf8'))
  assert.equal(run.capability_mode, 'TEST_EXECUTION')
})
```

`normalizePolicy` throws `PolicyValidationError` carrying `issues[]`, each with a
`code` — see `policy.mjs:57`. If it reports issues by another shape, read
`validatePolicy` at `policy.mjs:442` and use whichever surface returns them
without throwing.

- [ ] **Step 2: Run the test and confirm it fails**

```bash
node --test test/test-execution-mode.test.mjs
```

Expected: the three `TEST_MODE_CONTRADICTION` tests FAIL (no such code), and the
plan test FAILS with *"test and local_dynamic Rules of Engagement require the
proof broker"*. The first test may pass already.

- [ ] **Step 3: Add the schema conditional**

Append one entry to the top-level `allOf` in `schemas/roe.schema.json`, matching
the two conditionals already there:

```json
{
  "if": { "properties": { "mode": { "const": "test" } }, "required": ["mode"] },
  "then": {
    "properties": {
      "capabilities": {
        "type": "object",
        "properties": {
          "execute": { "type": "object", "properties": { "enabled": { "const": true } } },
          "write_file": { "type": "object", "properties": { "enabled": { "const": true } } },
          "network": { "type": "object", "properties": { "enabled": { "const": false } } }
        }
      }
    }
  }
}
```

The `security`-leaf constraint on roots is not expressible cleanly in JSON Schema
and lives in `normalizePolicy` instead.

- [ ] **Step 4: Add the contradiction check**

In `scripts/lib/policy.mjs`, immediately after the `remote_static` block that
ends near line 424:

```js
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
```

- [ ] **Step 5: Lift the plan guard**

In `scripts/audit.mjs`, replace the guard at 3210:

```js
    if (!['static', 'remote_static', 'test'].includes(policy.mode)) {
      throw new Error(
        'local_dynamic Rules of Engagement require the T2 boot broker, which is not available in 0.10.0',
      )
    }
```

- [ ] **Step 6: Lift the dispatch guard**

In `scripts/audit.mjs`, the guard near 1520 currently reads
`|| run.capability_mode !== 'STATIC'`. Replace that clause with:

```js
    || !['STATIC', 'TEST_EXECUTION'].includes(run.capability_mode)
```

and update the thrown message to
`'0.10.0 can dispatch and ingest only STATIC and TEST_EXECUTION runs'`.

- [ ] **Step 7: Run the tests and confirm they pass**

```bash
node --test test/test-execution-mode.test.mjs
```

Expected: 5 passing.

- [ ] **Step 8: Run the full suite**

```bash
node --test 2>&1 | tail -20
```

Expected: 729 tests, 726 passing, 1 skipped, 2 failing. A third failure means an
existing fixture relied on `test` mode being refused — read it before changing it.

- [ ] **Step 9: Commit**

```bash
git add schemas/roe.schema.json scripts/lib/policy.mjs scripts/audit.mjs test/test-execution-mode.test.mjs
git commit -m "feat: admit test-mode Rules of Engagement and TEST_EXECUTION runs"
```

---

### Task 2: Disposable mirror

Rail 3 requires proof work happen in a disposable mirror with the target unmutated and an owned-paths manifest returned. Rail 3's "index preserved byte-for-byte" is git phrasing; the git-free equivalent is recomputing the target's content digest, which is stronger and works on any directory.

**Files:**
- Create: `scripts/lib/disposable-mirror.mjs`
- Test: `test/disposable-mirror.test.mjs` (create)

**Interfaces:**
- Consumes: `inventoryRepository(targetRoot, options)` from `scripts/lib/inventory.mjs`, async, returns `{ root, treeDigest, … }`.
- Produces, relied on by Task 4:
  - `createMirror(targetRoot, mirrorRoot) -> Promise<{ root, ownedPaths }>` — `ownedPaths` is a sorted array of mirror-relative paths written by the copy
  - `materializeFiles(mirrorRoot, files) -> Promise<string[]>` — `files` is `[{ path, contents }]` with `path` mirror-relative; returns the sorted paths written
  - `assertTargetUnchanged(targetRoot, expectedTreeDigest) -> Promise<void>` — throws `MirrorMutationError` on mismatch
  - `destroyMirror(mirrorRoot) -> Promise<void>`
  - `class MirrorMutationError extends Error` with `.expected` and `.actual`

- [ ] **Step 1: Write the failing test**

Create `test/disposable-mirror.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  createMirror,
  materializeFiles,
  assertTargetUnchanged,
  destroyMirror,
  MirrorMutationError,
} from '../scripts/lib/disposable-mirror.mjs'
import { inventoryRepository } from '../scripts/lib/inventory.mjs'

function makeTarget() {
  const root = mkdtempSync(join(tmpdir(), 'rta-target-'))
  mkdirSync(join(root, 'src'), { recursive: true })
  writeFileSync(join(root, 'src', 'app.js'), 'export const x = 1\n')
  writeFileSync(join(root, 'package.json'), '{"name":"t","version":"1.0.0"}\n')
  return root
}

test('the mirror reproduces the target and reports owned paths', async () => {
  const target = makeTarget()
  const mirror = join(mkdtempSync(join(tmpdir(), 'rta-mirror-')), 'work')
  const { root, ownedPaths } = await createMirror(target, mirror)
  assert.equal(root, mirror)
  assert.equal(readFileSync(join(mirror, 'src', 'app.js'), 'utf8'), 'export const x = 1\n')
  assert.deepEqual(ownedPaths, ['package.json', 'src/app.js'])
})

test('materializeFiles writes into the mirror and returns sorted paths', async () => {
  const target = makeTarget()
  const mirror = join(mkdtempSync(join(tmpdir(), 'rta-mirror-')), 'work')
  await createMirror(target, mirror)
  const written = await materializeFiles(mirror, [
    { path: 'test/security/b.test.mjs', contents: 'b\n' },
    { path: 'test/security/a.test.mjs', contents: 'a\n' },
  ])
  assert.deepEqual(written, ['test/security/a.test.mjs', 'test/security/b.test.mjs'])
  assert.equal(readFileSync(join(mirror, 'test', 'security', 'a.test.mjs'), 'utf8'), 'a\n')
  assert.equal(existsSync(join(target, 'test')), false)
})

test('materializeFiles refuses a path escaping the mirror', async () => {
  const target = makeTarget()
  const mirror = join(mkdtempSync(join(tmpdir(), 'rta-mirror-')), 'work')
  await createMirror(target, mirror)
  await assert.rejects(
    () => materializeFiles(mirror, [{ path: '../escape.js', contents: 'x' }]),
    /escapes the mirror/,
  )
})

test('an unchanged target passes the digest re-check', async () => {
  const target = makeTarget()
  const { treeDigest } = await inventoryRepository(target)
  await assertTargetUnchanged(target, treeDigest)
})

test('a mutated target fails the digest re-check with both digests', async () => {
  const target = makeTarget()
  const { treeDigest } = await inventoryRepository(target)
  writeFileSync(join(target, 'src', 'app.js'), 'export const x = 2\n')
  await assert.rejects(
    () => assertTargetUnchanged(target, treeDigest),
    (error) => {
      assert.ok(error instanceof MirrorMutationError)
      assert.equal(error.expected, treeDigest)
      assert.notEqual(error.actual, treeDigest)
      return true
    },
  )
})

test('destroyMirror removes the tree', async () => {
  const target = makeTarget()
  const mirror = join(mkdtempSync(join(tmpdir(), 'rta-mirror-')), 'work')
  await createMirror(target, mirror)
  await destroyMirror(mirror)
  assert.equal(existsSync(mirror), false)
})
```

- [ ] **Step 2: Run the test and confirm it fails**

```bash
node --test test/disposable-mirror.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement the module**

Create `scripts/lib/disposable-mirror.mjs`:

```js
/**
 * Proof work happens in a disposable copy so the target is never written to.
 *
 * A copy rather than a git worktree: nothing in the audit path uses git, a
 * de-gitted target inventories to an identical tree digest, and one code path
 * serves repositories and plain directories alike.
 *
 * This is not a sandbox. The copy prevents accidental mutation of the target;
 * it does not contain what the executed command does to the rest of the machine.
 */
import { cp, mkdir, readdir, rm, writeFile } from 'node:fs/promises'
import { dirname, join, relative, resolve, sep } from 'node:path'
import { compareCanonicalStrings } from './canonical-order.mjs'
import { inventoryRepository } from './inventory.mjs'

export class MirrorMutationError extends Error {
  constructor(expected, actual) {
    super(
      'target tree digest changed during proof execution; '
      + `expected ${expected}, observed ${actual}`,
    )
    this.name = 'MirrorMutationError'
    this.expected = expected
    this.actual = actual
  }
}

async function walkRelative(root, prefix = '') {
  const paths = []
  for (const entry of await readdir(join(root, prefix), { withFileTypes: true })) {
    const child = prefix ? `${prefix}/${entry.name}` : entry.name
    if (entry.isDirectory()) paths.push(...await walkRelative(root, child))
    else paths.push(child)
  }
  return paths
}

export async function createMirror(targetRoot, mirrorRoot) {
  await mkdir(dirname(mirrorRoot), { recursive: true })
  await cp(targetRoot, mirrorRoot, { recursive: true, dereference: false })
  const ownedPaths = (await walkRelative(mirrorRoot)).sort(compareCanonicalStrings)
  return { root: mirrorRoot, ownedPaths }
}

export async function materializeFiles(mirrorRoot, files) {
  const root = resolve(mirrorRoot)
  const written = []
  for (const { path, contents } of files) {
    const absolute = resolve(root, path)
    if (absolute !== root && !absolute.startsWith(root + sep)) {
      throw new Error(`proof file path escapes the mirror: ${path}`)
    }
    await mkdir(dirname(absolute), { recursive: true })
    await writeFile(absolute, contents)
    written.push(relative(root, absolute).split(sep).join('/'))
  }
  return written.sort(compareCanonicalStrings)
}

export async function assertTargetUnchanged(targetRoot, expectedTreeDigest) {
  const { treeDigest } = await inventoryRepository(targetRoot)
  if (treeDigest !== expectedTreeDigest) {
    throw new MirrorMutationError(expectedTreeDigest, treeDigest)
  }
}

export async function destroyMirror(mirrorRoot) {
  await rm(mirrorRoot, { recursive: true, force: true })
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
node --test test/disposable-mirror.test.mjs
```

Expected: 6 passing.

- [ ] **Step 5: Confirm the ordering guard still holds**

```bash
node --test test/canonical-ordering.test.mjs
```

Expected: all passing — the new module uses `compareCanonicalStrings`, not `localeCompare`.

- [ ] **Step 6: Commit**

```bash
git add scripts/lib/disposable-mirror.mjs test/disposable-mirror.test.mjs
git commit -m "feat: disposable mirror with target non-mutation proof"
```

---

### Task 3: Proof configuration schema

`run-proof` needs a validated input naming the job, the authored files, the candidate patch, the command, and whether a destination guard is installed. Modelled on `schemas/provider-config.schema.json`.

**Files:**
- Create: `schemas/proof-config.schema.json`
- Test: `test/proof-config.test.mjs` (create)

**Interfaces:**
- Consumes: nothing.
- Produces, relied on by Task 4: a validated document of this shape.

```json
{
  "schema_version": "1.0.0",
  "job_id": "proof-verification:cand:web:001",
  "proof_files":  [{ "path": "test/security/authz.test.mjs", "contents": "…" }],
  "patch_files":  [{ "path": "src/routes/invoices.ts", "contents": "…" }],
  "command": { "program": "npm", "args": ["test"] },
  "destination_guard": { "installed": true, "path": "test/security/harness/destinations.py" }
}
```

`patch_files` are whole-file replacements rather than a diff format — no patch
parser, and the mirror is discarded either way. Omitting `patch_files` is legal
and yields `UNPROVEN`, because no fix was demonstrated.

- [ ] **Step 1: Write the failing test**

Create `test/proof-config.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import Ajv2020 from 'ajv/dist/2020.js'

const schema = JSON.parse(readFileSync('schemas/proof-config.schema.json', 'utf8'))
const validate = new Ajv2020({ strict: true, allErrors: true }).compile(schema)

const config = (overrides = {}) => ({
  schema_version: '1.0.0',
  job_id: 'proof-verification:cand:web:001',
  proof_files: [{ path: 'test/security/authz.test.mjs', contents: 'x\n' }],
  command: { program: 'npm', args: ['test'] },
  destination_guard: { installed: false },
  ...overrides,
})

test('a minimal proof config validates', () => {
  assert.equal(validate(config()), true, JSON.stringify(validate.errors))
})

test('patch_files is optional', () => {
  assert.equal(validate(config({ patch_files: [{ path: 'src/a.js', contents: 'y\n' }] })), true)
})

test('proof_files must be non-empty', () => {
  assert.equal(validate(config({ proof_files: [] })), false)
})

test('the job id must name a proof job', () => {
  assert.equal(validate(config({ job_id: 'lens:web-and-api' })), false)
})

test('unknown properties are rejected', () => {
  assert.equal(validate(config({ shell: 'bash -c whoami' })), false)
})

test('an absolute or escaping proof path is rejected', () => {
  assert.equal(validate(config({ proof_files: [{ path: '/etc/passwd', contents: 'x' }] })), false)
  assert.equal(validate(config({ proof_files: [{ path: '../x.js', contents: 'x' }] })), false)
})
```

- [ ] **Step 2: Run the test and confirm it fails**

```bash
node --test test/proof-config.test.mjs
```

Expected: FAIL — the schema file does not exist.

- [ ] **Step 3: Write the schema**

Create `schemas/proof-config.schema.json`:

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://red-team-audit.invalid/schemas/proof-config.schema.json",
  "title": "Proof execution configuration",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "job_id", "proof_files", "command", "destination_guard"],
  "properties": {
    "schema_version": { "const": "1.0.0" },
    "job_id": { "type": "string", "pattern": "^proof-(existence|verification):", "maxLength": 256 },
    "proof_files": { "type": "array", "minItems": 1, "maxItems": 64, "items": { "$ref": "#/$defs/file" } },
    "patch_files": { "type": "array", "minItems": 1, "maxItems": 64, "items": { "$ref": "#/$defs/file" } },
    "command": {
      "type": "object",
      "additionalProperties": false,
      "required": ["program", "args"],
      "properties": {
        "program": { "type": "string", "pattern": "^[A-Za-z0-9._-]+$", "maxLength": 128 },
        "args": { "type": "array", "maxItems": 64, "items": { "type": "string", "maxLength": 4096 } }
      }
    },
    "destination_guard": {
      "type": "object",
      "additionalProperties": false,
      "required": ["installed"],
      "properties": {
        "installed": { "type": "boolean" },
        "path": { "$ref": "#/$defs/relativePath" }
      }
    }
  },
  "$defs": {
    "relativePath": {
      "type": "string",
      "minLength": 1,
      "maxLength": 4096,
      "pattern": "^(?!/)(?!.*(^|/)\\.\\.(/|$)).+$"
    },
    "file": {
      "type": "object",
      "additionalProperties": false,
      "required": ["path", "contents"],
      "properties": {
        "path": { "$ref": "#/$defs/relativePath" },
        "contents": { "type": "string", "maxLength": 1048576 }
      }
    }
  }
}
```

Ajv 2020 supports lookahead in `pattern` via the default RegExp engine. If
`strict: true` rejects the negative lookahead on this Ajv version, replace the
`relativePath` pattern with `"^[^/].*$"` and enforce the `..` rejection in
`materializeFiles`, which already rejects escapes — then delete the two
escaping-path assertions from the test and note the move in the commit message.

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
node --test test/proof-config.test.mjs
```

Expected: 6 passing.

- [ ] **Step 5: Commit**

```bash
git add schemas/proof-config.schema.json test/proof-config.test.mjs
git commit -m "feat: proof execution configuration schema"
```

---

### Task 4: Proof execution

Runs the authorised command in the mirror, twice when a candidate patch is supplied. Returns raw outcomes; the mapping to finding fields is Task 5, so this stays testable without a bundle.

**Files:**
- Create: `scripts/lib/proof-execution.mjs`
- Test: `test/proof-execution.test.mjs` (create)

**Interfaces:**
- Consumes: `createMirror`, `materializeFiles`, `assertTargetUnchanged`, `destroyMirror`, `MirrorMutationError` (Task 2); `authorizeAction` from `scripts/lib/policy.mjs`.
- Produces, relied on by Task 5:
  - `executeProof(options) -> Promise<ProofOutcome>` where `options` is
    `{ targetRoot, mirrorRoot, expectedTreeDigest, policy, config, spawn }`
  - `spawn(program, args, cwd) -> Promise<{ code, stdout, stderr }>` is injected so tests need no child process
  - `ProofOutcome` is
    `{ demonstration: RunOutcome, remediation: RunOutcome | null, ownedPaths: string[], mirrorRoot: string, mirrorRetained: boolean }`
  - `RunOutcome` is `{ code, stdout, stderr }`

- [ ] **Step 1: Write the failing test**

Create `test/proof-execution.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, mkdirSync, writeFileSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { executeProof } from '../scripts/lib/proof-execution.mjs'
import { normalizePolicy } from '../scripts/lib/policy.mjs'
import { inventoryRepository } from '../scripts/lib/inventory.mjs'

function makeTarget() {
  const root = mkdtempSync(join(tmpdir(), 'rta-pe-target-'))
  mkdirSync(join(root, 'src'), { recursive: true })
  writeFileSync(join(root, 'src', 'app.js'), 'export const x = 1\n')
  return root
}

const policyFor = (root) => normalizePolicy({
  schema_version: '1.0',
  policy_id: 'proof',
  mode: 'test',
  workspace_root: root,
  capabilities: {
    read_file: { enabled: true, roots: ['.'] },
    write_file: { enabled: true, roots: ['test/security'] },
    execute: { enabled: true, commands: [{ program: 'npm', args: ['test'] }] },
    network: { enabled: false, destinations: [] },
  },
}, { workspaceRoot: root, policySource: 'external' })

const baseConfig = {
  schema_version: '1.0.0',
  job_id: 'proof-verification:cand:1',
  proof_files: [{ path: 'test/security/a.test.mjs', contents: 'a\n' }],
  command: { program: 'npm', args: ['test'] },
  destination_guard: { installed: false },
}

async function run(config, spawn, overrides = {}) {
  const targetRoot = overrides.targetRoot ?? makeTarget()
  const { treeDigest } = await inventoryRepository(targetRoot)
  return executeProof({
    targetRoot,
    mirrorRoot: join(mkdtempSync(join(tmpdir(), 'rta-pe-mirror-')), 'work'),
    expectedTreeDigest: overrides.digest ?? treeDigest,
    policy: policyFor(targetRoot),
    config,
    spawn,
    ...overrides.extra,
  })
}

test('a demonstration-only proof runs the command once', async () => {
  const calls = []
  const spawn = async (program, args, cwd) => {
    calls.push({ program, args, cwd })
    return { code: 1, stdout: 'assertion failed', stderr: '' }
  }
  const outcome = await run(baseConfig, spawn)
  assert.equal(calls.length, 1)
  assert.equal(calls[0].program, 'npm')
  assert.equal(outcome.demonstration.code, 1)
  assert.equal(outcome.remediation, null)
})

test('a proof with a patch runs the command twice', async () => {
  const codes = [1, 0]
  const spawn = async () => ({ code: codes.shift(), stdout: '', stderr: '' })
  const outcome = await run({ ...baseConfig, patch_files: [{ path: 'src/app.js', contents: 'export const x = 2\n' }] }, spawn)
  assert.equal(outcome.demonstration.code, 1)
  assert.equal(outcome.remediation.code, 0)
})

test('a command absent from the allowlist is refused and no mirror is created', async () => {
  const target = makeTarget()
  let spawned = false
  const spawn = async () => { spawned = true; return { code: 0, stdout: '', stderr: '' } }
  await assert.rejects(
    () => run({ ...baseConfig, command: { program: 'curl', args: ['http://x'] } }, spawn, { targetRoot: target }),
    /not authorized|CAPABILITY|command/i,
  )
  assert.equal(spawned, false)
})

test('a mutated target fails the digest re-check and retains the mirror', async () => {
  const target = makeTarget()
  const mirrorRoot = join(mkdtempSync(join(tmpdir(), 'rta-pe-mirror-')), 'work')
  const { treeDigest } = await inventoryRepository(target)
  const spawn = async () => {
    writeFileSync(join(target, 'src', 'app.js'), 'export const x = 99\n')
    return { code: 0, stdout: '', stderr: '' }
  }
  await assert.rejects(
    () => executeProof({
      targetRoot: target,
      mirrorRoot,
      expectedTreeDigest: treeDigest,
      policy: policyFor(target),
      config: baseConfig,
      spawn,
    }),
    /tree digest changed/,
  )
  // The mirror survives a mutation failure: what happened matters more than tidiness.
  assert.equal(existsSync(mirrorRoot), true)
})

test('owned paths include the materialized proof file', async () => {
  const spawn = async () => ({ code: 0, stdout: '', stderr: '' })
  const outcome = await run(baseConfig, spawn)
  assert.ok(outcome.ownedPaths.includes('test/security/a.test.mjs'))
})

test('the mirror is destroyed on success', async () => {
  const spawn = async () => ({ code: 0, stdout: '', stderr: '' })
  const outcome = await run(baseConfig, spawn)
  assert.equal(existsSync(outcome.mirrorRoot), false)
  assert.equal(outcome.mirrorRetained, false)
})
```

- [ ] **Step 2: Run the test and confirm it fails**

```bash
node --test test/proof-execution.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement the module**

Create `scripts/lib/proof-execution.mjs`:

```js
/**
 * Executes an authored proof in a disposable mirror of the target.
 *
 * The agent authors the proof and the candidate patch; this module runs them.
 * The split is deliberate: the party claiming the bug never produces the
 * observation that proves it.
 *
 * The mirror is not a sandbox. The executed command is the project's own, run
 * with the project's own environment, and does whatever that does.
 */
import { authorizeAction } from './policy.mjs'
import {
  assertTargetUnchanged,
  createMirror,
  destroyMirror,
  materializeFiles,
  MirrorMutationError,
} from './disposable-mirror.mjs'

export async function executeProof({
  targetRoot,
  mirrorRoot,
  expectedTreeDigest,
  policy,
  config,
  spawn,
}) {
  // Authorize before anything is copied, so a refused command leaves no trace.
  const decision = authorizeAction(policy, {
    type: 'execute',
    program: config.command.program,
    args: config.command.args,
  })
  if (!decision.allowed) {
    const detail = decision.reasons
      .map(({ code, message }) => `${code}: ${message}`)
      .join('; ')
    throw new Error(`proof command is not authorized by the run policy: ${detail}`)
  }

  const { ownedPaths: copied } = await createMirror(targetRoot, mirrorRoot)
  const owned = new Set(copied)
  let mirrorRetained = false
  try {
    for (const path of await materializeFiles(mirrorRoot, config.proof_files)) {
      owned.add(path)
    }
    const demonstration = await spawn(
      config.command.program,
      config.command.args,
      mirrorRoot,
    )

    let remediation = null
    if (Array.isArray(config.patch_files) && config.patch_files.length > 0) {
      for (const path of await materializeFiles(mirrorRoot, config.patch_files)) {
        owned.add(path)
      }
      remediation = await spawn(
        config.command.program,
        config.command.args,
        mirrorRoot,
      )
    }

    await assertTargetUnchanged(targetRoot, expectedTreeDigest)

    return {
      demonstration,
      remediation,
      ownedPaths: [...owned].sort(),
      mirrorRoot,
      mirrorRetained,
    }
  } catch (error) {
    // A mutated target is the one failure where the evidence of what happened
    // matters more than cleanliness, so the mirror survives for inspection.
    if (error instanceof MirrorMutationError) mirrorRetained = true
    throw error
  } finally {
    if (!mirrorRetained) await destroyMirror(mirrorRoot)
  }
}
```

`ownedPaths` is sorted with the default comparator rather than
`compareCanonicalStrings` because it is diagnostic output, not hashed material.
If it later enters a digest, switch it and add a case to the ordering guard test.

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
node --test test/proof-execution.test.mjs
```

Expected: 6 passing. The mutated-target test asserts the rejection; the mirror
retention is asserted through `mirrorRetained` on the success path.

- [ ] **Step 5: Run the full suite and commit**

```bash
node --test 2>&1 | tail -20
git add scripts/lib/proof-execution.mjs test/proof-execution.test.mjs
git commit -m "feat: execute authored proofs in a disposable mirror"
```

Expected before committing: 741 tests, 738 passing, 1 skipped, 2 failing.

---

### Task 5: Map outcomes to finding evidence

`CONFIRMED` requires `artifact`, `command`, `pre_result` and `post_result` with `post_result.status: passed`. A demonstration alone therefore cannot confirm; it rests at `UNPROVEN` with a `blocking_reason`, which caps at Medium. That is the honest state for a bug proven and not yet fixed.

**Files:**
- Create: `scripts/lib/proof-evidence.mjs`
- Test: `test/proof-evidence.test.mjs` (create)

**Interfaces:**
- Consumes: `ProofOutcome` from Task 4.
- Produces, relied on by Task 6:
  - `proofEvidence(outcome, config, context) -> { proof_tier, verification_status, command, artifact, pre_result?, post_result?, reason?, blocking_reason? }`
  - `context` is `{ ruleSixApplicable: boolean }`

- [ ] **Step 1: Write the failing test**

Create `test/proof-evidence.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { proofEvidence } from '../scripts/lib/proof-evidence.mjs'

const config = {
  job_id: 'proof-verification:cand:1',
  proof_files: [{ path: 'test/security/a.test.mjs', contents: 'a\n' }],
  command: { program: 'npm', args: ['test'] },
  destination_guard: { installed: true, path: 'test/security/harness/destinations.py' },
}
const context = { ruleSixApplicable: true }
const fail = { code: 1, stdout: 'expected 403, received 200 containing CANARY-A', stderr: '' }
const pass = { code: 0, stdout: 'all tests passed', stderr: '' }

test('demonstration plus a passing remediation confirms at T1', () => {
  const e = proofEvidence({ demonstration: fail, remediation: pass, ownedPaths: [] }, config, context)
  assert.equal(e.proof_tier, 'T1')
  assert.equal(e.verification_status, 'CONFIRMED')
  assert.equal(e.post_result.status, 'passed')
  assert.ok(e.pre_result.assertion)
  assert.ok(e.pre_result.path_reached)
  assert.ok(e.pre_result.control)
  assert.ok(e.artifact.sha256.match(/^[a-f0-9]{64}$/))
})

test('a demonstration with no patch rests at UNPROVEN with a blocking reason', () => {
  const e = proofEvidence({ demonstration: fail, remediation: null, ownedPaths: [] }, config, context)
  assert.equal(e.verification_status, 'UNPROVEN')
  assert.ok(e.blocking_reason)
  assert.equal(e.post_result, undefined)
})

test('a demonstration that does not fire is NOT_REPRODUCED with a reason', () => {
  const e = proofEvidence({ demonstration: pass, remediation: null, ownedPaths: [] }, config, context)
  assert.equal(e.verification_status, 'NOT_REPRODUCED')
  assert.ok(e.reason)
})

test('a patch that leaves the suite red does not confirm', () => {
  const e = proofEvidence({ demonstration: fail, remediation: fail, ownedPaths: [] }, config, context)
  assert.notEqual(e.verification_status, 'CONFIRMED')
  assert.equal(e.post_result.status, 'failed')
  assert.ok(e.reason)
})

test('an unmonitored run is recorded in the evidence', () => {
  const e = proofEvidence(
    { demonstration: fail, remediation: pass, ownedPaths: [] },
    { ...config, destination_guard: { installed: false } },
    context,
  )
  assert.match(JSON.stringify(e), /unmonitored/i)
})

test('rule six not applicable is recorded', () => {
  const e = proofEvidence(
    { demonstration: fail, remediation: pass, ownedPaths: [] },
    config,
    { ruleSixApplicable: false },
  )
  assert.match(JSON.stringify(e), /previous revision/i)
})
```

- [ ] **Step 2: Run the test and confirm it fails**

```bash
node --test test/proof-evidence.test.mjs
```

Expected: FAIL with `ERR_MODULE_NOT_FOUND`.

- [ ] **Step 3: Implement the module**

Create `scripts/lib/proof-evidence.mjs`:

```js
/**
 * Maps a proof outcome onto the finding's evidence fields.
 *
 * CONFIRMED is not "the bug is real". finding.schema.json requires artifact,
 * command, pre_result and post_result with post_result.status 'passed', so a
 * finding confirms only when a candidate fix ran green. A bug demonstrated and
 * unfixed rests at UNPROVEN, which caps at Medium — the honest state.
 */
import { createHash } from 'node:crypto'

const MAX_DETAIL = 2000

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function truncated(text) {
  const value = String(text ?? '').trim()
  if (value.length === 0) return 'no output'
  return value.length > MAX_DETAIL ? `${value.slice(0, MAX_DETAIL)}…` : value
}

function notes(config, context) {
  const entries = []
  if (!config.destination_guard?.installed) {
    entries.push('execution was unmonitored: no destination guard was installed')
  }
  if (!context.ruleSixApplicable) {
    entries.push('previous-revision check not applied: the target has no revision history')
  }
  return entries
}

export function proofEvidence(outcome, config, context) {
  const { demonstration, remediation } = outcome
  const manifest = config.proof_files
    .map(({ path, contents }) => `${path}\0${sha256(contents)}`)
    .join('\n')
  const artifact = {
    path: config.proof_files[0].path,
    sha256: sha256(manifest),
  }
  const command = `${config.command.program} ${config.command.args.join(' ')}`.trim()
  const caveats = notes(config, context)
  const withNotes = (text) => [text, ...caveats].join('; ')

  const base = { proof_tier: 'T1', command, artifact }

  // The demonstration must fail against the unmodified mirror. A demonstration
  // that passes there did not reproduce the bug it claims.
  if (demonstration.code === 0) {
    return {
      ...base,
      verification_status: 'NOT_REPRODUCED',
      reason: withNotes(
        `the demonstration passed against the unmodified target: ${truncated(demonstration.stdout)}`,
      ),
    }
  }

  const pre_result = {
    assertion: truncated(demonstration.stdout || demonstration.stderr),
    path_reached: config.proof_files[0].path,
    control: config.proof_files.length > 1
      ? config.proof_files[1].path
      : 'unmodified target',
    ...(caveats.length > 0 ? { detail: caveats.join('; ') } : {}),
  }

  if (remediation === null) {
    return {
      ...base,
      verification_status: 'UNPROVEN',
      pre_result,
      blocking_reason: withNotes(
        'the bug was demonstrated but no candidate patch was supplied, so no post-fix result exists',
      ),
    }
  }

  const post_result = {
    status: remediation.code === 0 ? 'passed' : 'failed',
    regressions: remediation.code === 0
      ? 'none observed in the project suite'
      : truncated(remediation.stdout || remediation.stderr),
    ...(caveats.length > 0 ? { detail: caveats.join('; ') } : {}),
  }

  if (post_result.status === 'failed') {
    return {
      ...base,
      verification_status: 'INCONCLUSIVE',
      pre_result,
      post_result,
      reason: withNotes('the candidate patch did not leave the project suite green'),
    }
  }

  return { ...base, verification_status: 'CONFIRMED', pre_result, post_result }
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
node --test test/proof-evidence.test.mjs
```

Expected: 6 passing.

- [ ] **Step 5: Prove the schema agrees**

Add to `test/proof-evidence.test.mjs`:

```js
import { validateFinding } from '../scripts/lib/contracts.mjs'

test('a confirmed evidence block satisfies the finding contract', () => {
  const e = proofEvidence({ demonstration: fail, remediation: pass, ownedPaths: [] }, config, context)
  const finding = {
    candidate_id: 'cand:web:001',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Tenant object loads without an ownership check',
    claimed_impact_severity: 'Critical',
    effective_severity: 'Critical',
    location: ['src/orders.js:42'],
    evidence: 'return Orders.findById(req.params.id)',
    reachable_from: 'GET /orders/:id',
    triage_disposition: 'queued',
    existence_check: { status: 'located', method: 'read src/orders.js:42' },
    ...e,
  }
  const result = validateFinding(finding)
  assert.equal(result.valid, true, JSON.stringify(result.errors))
})
```

Run it. If it fails, the errors name exactly which required field the evidence
block is missing — add it to `proofEvidence` rather than relaxing the test. This
is the assertion that proves the whole task, so do not skip it.

- [ ] **Step 6: Run the full suite and commit**

```bash
node --test 2>&1 | tail -20
git add scripts/lib/proof-evidence.mjs test/proof-evidence.test.mjs
git commit -m "feat: map proof outcomes onto finding evidence"
```

Expected before committing: 748 tests, 745 passing, 1 skipped, 2 failing.

---

### Task 6: The `run-proof` command

Wires Tasks 2–5 to the bundle: loads the run and policy, resolves the job, executes, writes the job result through the existing write-once path.

**Files:**
- Modify: `scripts/audit.mjs` — `HELP` (line 198), `COMMAND_ARGUMENTS` (line 253), `main` dispatch (line 5556)
- Test: `test/run-proof-command.test.mjs` (create)

**Interfaces:**
- Consumes: `executeProof` (Task 4), `proofEvidence` (Task 5), the proof-config schema (Task 3), and `loadRun`, `requirePositional`, `readJson`, `verifyControlBundle` already in `audit.mjs`.
- Produces: a `PROOF` job result ingested through the existing write-once boundary.

- [ ] **Step 1: Write the failing test**

Create `test/run-proof-command.test.mjs`:

```js
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, readdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

test('run-proof refuses a bundle whose run is STATIC', () => {
  const out = mkdtempSync(join(tmpdir(), 'rta-rp-'))
  execFileSync(process.execPath, [
    'scripts/audit.mjs', 'plan', 'fixtures/vulnerable', '--seal-source', '--out', out,
  ], { stdio: 'pipe' })
  const bundle = join(out, readdirSync(out).find((name) => name.startsWith('run_')))
  const configPath = join(out, 'proof.json')
  writeFileSync(configPath, JSON.stringify({
    schema_version: '1.0.0',
    job_id: 'proof-verification:cand:1',
    proof_files: [{ path: 'test/security/a.test.mjs', contents: 'a\n' }],
    command: { program: 'npm', args: ['test'] },
    destination_guard: { installed: false },
  }))
  assert.throws(
    () => execFileSync(process.execPath, ['scripts/audit.mjs', 'run-proof', bundle, configPath], { stdio: 'pipe' }),
    /TEST_EXECUTION/,
  )
})

test('run-proof is registered and reports its arguments', () => {
  const help = execFileSync(process.execPath, ['scripts/audit.mjs', '--help'], { encoding: 'utf8' })
  assert.match(help, /run-proof <run\.json\|bundle-directory> <proof-config\.json>/)
})

test('run-proof rejects an unknown option', () => {
  assert.throws(
    () => execFileSync(process.execPath, ['scripts/audit.mjs', 'run-proof', 'x', 'y', '--shell', 'sh'], { stdio: 'pipe' }),
    /unknown option --shell/,
  )
})
```

- [ ] **Step 2: Run the test and confirm it fails**

```bash
node --test test/run-proof-command.test.mjs
```

Expected: FAIL with `unknown command "run-proof"`.

- [ ] **Step 3: Add the command**

In `scripts/audit.mjs`, import the new modules beside the existing lib imports:

```js
import { executeProof } from './lib/proof-execution.mjs'
import { proofEvidence } from './lib/proof-evidence.mjs'
```

Add the command, modelled on `runProviderCommand` at the same nesting level:

```js
export async function runProofCommand(positionals, _options = {}, dependencies = {}) {
  const loaded = await loadRun(requirePositional(positionals, 0, 'run'))
  assertValidRun(loaded.run)
  if (loaded.run.capability_mode !== 'TEST_EXECUTION') {
    throw new Error(
      'run-proof requires a TEST_EXECUTION run; plan with a test-mode Rules of Engagement',
    )
  }
  if (!loaded.run.source_snapshot) {
    throw new Error('run-proof requires a bundle created with plan --seal-source')
  }
  const config = await readJson(
    requirePositional(positionals, 1, 'proof configuration'),
    { maxBytes: 8 * 1024 * 1024, label: 'proof configuration JSON' },
  )
  assertValidProofConfig(config)

  const control = await verifyControlBundle(loaded.directory, loaded.run, {
    requireCurrentLensPack: true,
  })
  const policy = normalizePolicy(control.policy, {
    workspaceRoot: control.policy.workspace_root,
    policySource: 'external',
  })

  const targetRoot = loaded.run.repository.root
  const mirrorRoot = join(
    await mkdtemp(join(tmpdir(), 'red-team-audit-proof-')),
    'mirror',
  )
  const outcome = await executeProof({
    targetRoot,
    mirrorRoot,
    expectedTreeDigest: loaded.run.repository.tree_digest,
    policy,
    config,
    spawn: dependencies.spawn ?? spawnProofCommand,
  })

  const ruleSixApplicable = existsSync(join(targetRoot, '.git'))
  const evidence = proofEvidence(outcome, config, { ruleSixApplicable })
  process.stdout.write(`${stableJson({
    job_id: config.job_id,
    owned_paths: outcome.ownedPaths,
    evidence,
  })}\n`)
}
```

Add `spawnProofCommand`, the only place a child process is created:

```js
function spawnProofCommand(program, args, cwd) {
  return new Promise((resolve) => {
    const child = spawn(program, args, { cwd, shell: false, stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.on('close', (code) => resolve({ code: code ?? 1, stdout, stderr }))
    child.on('error', (error) => resolve({ code: 127, stdout, stderr: String(error.message) }))
  })
}
```

`shell: false` is required — rail 2 and the RoE's exact-match allowlist are both
defeated by a shell, which would let `args` carry `;` or `&&`.

Add `assertValidProofConfig` beside the other Ajv validators in `audit.mjs`,
compiling `schemas/proof-config.schema.json` the way the file already compiles
its other schemas, and throwing on invalid input with the Ajv errors in the
message.

Register the argument shape in `COMMAND_ARGUMENTS`:

```js
  'run-proof': {
    positionals: 2,
    options: {},
  },
```

Dispatch it in `main`, after `run-remote`:

```js
  if (command === 'run-proof') return runProofCommand(positionals, options)
```

Add the `HELP` line after the `run-remote` line:

```
  red-team-audit run-proof <run.json|bundle-directory> <proof-config.json>
```

Add `spawn` from `node:child_process`, `mkdtemp` from `node:fs/promises`, and
`tmpdir` from `node:os` to the imports if they are not already present.

- [ ] **Step 4: Run the tests and confirm they pass**

```bash
node --test test/run-proof-command.test.mjs
```

Expected: 3 passing.

- [ ] **Step 5: Prove the happy path end to end by hand**

```bash
node --test test/test-execution-mode.test.mjs
```

Then build a `TEST_EXECUTION` bundle against a scratch target with a trivial
`npm test` that exits 1, run `run-proof`, and confirm the emitted evidence is
`UNPROVEN` with a `blocking_reason`. Add `patch_files` that make the command exit
0 and confirm it becomes `CONFIRMED` with `post_result.status: passed`. Record
both outputs in the commit message.

- [ ] **Step 6: Run the full suite and commit**

```bash
node --test 2>&1 | tail -20
git add scripts/audit.mjs test/run-proof-command.test.mjs
git commit -m "feat: add the run-proof command"
```

Expected before committing: 751 tests, 748 passing, 1 skipped, 2 failing.

---

### Task 7: Document the workflow

`SKILL.md` drives the agent. Without a rule there nothing will author a proof and the feature stays dormant.

**Files:**
- Modify: `skills/red-team-audit/SKILL.md`
- Test: `node scripts/lint-lenses.mjs`

**Interfaces:**
- Consumes: the `run-proof` command from Task 6.
- Produces: nothing.

- [ ] **Step 1: Check the byte budget first**

```bash
wc -c skills/red-team-audit/SKILL.md
grep -n "MAX_SKILL_BYTES" scripts/lint-lenses.mjs
```

The cap is 8000 bytes and the file was last measured at 7991 — about 9 bytes of
headroom. Adding the text below requires compressing existing prose by roughly
as much as you add. Tighten wordy sentences; do not delete a rule.

- [ ] **Step 2: Add the rule**

In the proof-phase instructions:

```
For a `test`-mode run, author the proof and any candidate fix, then let the
controller run them: `audit -- run-proof <bundle> <proof-config.json>`. Never
run the target's suite yourself — a result you produced is not proof. No patch
means `UNPROVEN`, capped at Medium, which is a legitimate outcome.
```

- [ ] **Step 3: Verify the budget and lint gate**

```bash
wc -c skills/red-team-audit/SKILL.md
node scripts/lint-lenses.mjs
```

Expected: under 8000 bytes, and `PASS: R1-R8, SKILL and ledger gate clean.`

- [ ] **Step 4: Run the full suite and commit**

```bash
node --test 2>&1 | tail -20
git add skills/red-team-audit/SKILL.md
git commit -m "docs: require controller-run proofs for test-mode audits"
```

Expected: 751 tests, 748 passing, 1 skipped, 2 failing.

---

## Acceptance

The change is complete when a `TEST_EXECUTION` run of a scratch target can carry
a finding at `T1`/`CONFIRMED` with a demonstration that failed before a patch
and a suite that passed after it, reporting `effective_severity: Critical` —
while the same finding reports Medium when no patch is supplied, when the
demonstration does not fire, or when the patch leaves the suite red. Throughout,
the target's tree digest is unchanged.

Final expected suite state: **751 tests, 748 passing, 1 skipped, 2 failing**,
where the 2 remain the pre-existing ripgrep pair.

## Not in this plan

`T2` and `LOCAL_DYNAMIC` — booting the application and issuing loopback
requests. Every component here is reused; only the boot and its per-run consent
prompt are new.

Artifact unpacking for `.apk` and other distributables.

Applying a patch to the real target. The `PATCH` phase stays stubbed as
`patch:read-only / SKIPPED`. This plan validates candidate fixes in a mirror and
never writes to the target.

Test counts assume the tasks run in order. If you reorder them, recompute rather
than trusting the stated numbers.
