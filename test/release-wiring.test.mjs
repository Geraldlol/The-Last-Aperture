import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'

const WORKFLOW_PATH = '.github/workflows/lint-lenses.yml'
const CHECKOUT_SHA = '08eba0b27e820071cde6df949e0beb9ba4906955'
const SETUP_NODE_SHA = '49933ea5288caeca8642d1e84afbd3f7d6820020'

test('CI pins third-party actions and exercises the advertised Node floor', () => {
  const workflow = readFileSync(WORKFLOW_PATH, 'utf8')

  assert.match(workflow, new RegExp(`actions/checkout@${CHECKOUT_SHA} # v4\\.3\\.0`))
  assert.match(workflow, new RegExp(`actions/setup-node@${SETUP_NODE_SHA} # v4\\.4\\.0`))
  assert.doesNotMatch(workflow, /actions\/(?:checkout|setup-node)@v\d+/)
  assert.match(workflow, /node:\s*\['20', '24'\]/)
  assert.match(workflow, /node-version:\s*\$\{\{\s*matrix\.node\s*\}\}/)
  assert.match(workflow, /- run: npm test/)
  const ripgrepInstall = workflow.indexOf('sudo apt-get install --yes ripgrep')
  const testRun = workflow.indexOf('- run: npm test')
  assert.notEqual(ripgrepInstall, -1, 'CI must install ripgrep for executable shell fixtures')
  assert.ok(ripgrepInstall < testRun, 'CI must install ripgrep before running the test suite')
  assert.match(workflow, /^\s+rg --version$/m)
})

test('CI runs the hostile real-Docker gate with immutable image input', () => {
  const workflow = readFileSync(WORKFLOW_PATH, 'utf8')

  assert.match(workflow, /^\s{2}provider-docker-conformance:$/m)
  assert.match(
    workflow,
    /--file providers\/reference-byte-consumer\/Dockerfile\.conformance/,
  )
  assert.match(
    workflow,
    /NODE_IMAGE=node:22-bookworm@sha256:[a-f0-9]{64}/,
  )
  assert.match(workflow, /RTA_DOCKER_RUNTIME: \$\{\{ steps\.docker\.outputs\.runtime \}\}/)
  assert.match(workflow, /RTA_PROVIDER_IMAGE: \$\{\{ steps\.docker\.outputs\.image \}\}/)
  assert.match(workflow, /run: npm run test:provider:docker/)
  assert.doesNotMatch(workflow, /continue-on-error:\s*true/)
})

test('the dedicated Docker gate refuses to skip when runtime inputs are absent', () => {
  const env = { ...process.env }
  delete env.RTA_DOCKER_RUNTIME
  delete env.RTA_PROVIDER_IMAGE
  const result = spawnSync(
    process.execPath,
    ['scripts/run-provider-docker-conformance.mjs'],
    {
      encoding: 'utf8',
      env,
      shell: false,
      windowsHide: true,
    },
  )

  assert.equal(result.status, 1)
  assert.match(
    result.stderr,
    /real-Docker conformance requires RTA_DOCKER_RUNTIME and RTA_PROVIDER_IMAGE/,
  )
})

test('CI runs the digest-pinned multi-engine database conformance gate', () => {
  const workflow = readFileSync(WORKFLOW_PATH, 'utf8')

  assert.match(workflow, /^\s{2}database-docker-conformance:$/m)
  assert.match(
    workflow,
    /docker pull postgres@sha256:[a-f0-9]{64}/,
  )
  assert.match(
    workflow,
    /docker pull mysql@sha256:[a-f0-9]{64}/,
  )
  assert.match(
    workflow,
    /RTA_DOCKER_RUNTIME: \$\{\{ steps\.database-docker\.outputs\.runtime \}\}/,
  )
  assert.match(workflow, /run: npm run test:database:docker/)
})

test('the database Docker gate refuses to skip without its trusted runtime', () => {
  const env = { ...process.env }
  delete env.RTA_DOCKER_RUNTIME
  const result = spawnSync(
    process.execPath,
    ['scripts/run-database-docker-conformance.mjs'],
    {
      encoding: 'utf8',
      env,
      shell: false,
      windowsHide: true,
    },
  )

  assert.equal(result.status, 1)
  assert.match(
    result.stderr,
    /real database conformance requires RTA_DOCKER_RUNTIME/,
  )
})

test('release metadata exposes the 0.7 database conformance commands', () => {
  const packageDocument = JSON.parse(readFileSync('package.json', 'utf8'))
  const lockDocument = JSON.parse(readFileSync('package-lock.json', 'utf8'))

  assert.equal(packageDocument.version, '0.7.0')
  assert.equal(lockDocument.version, '0.7.0')
  assert.equal(lockDocument.packages[''].version, '0.7.0')
  assert.equal(
    packageDocument.scripts['conformance:database'],
    'node scripts/database-conformance.mjs',
  )
  assert.equal(
    packageDocument.scripts['test:database:docker'],
    'node scripts/run-database-docker-conformance.mjs',
  )
})

test('the v0.8 remote gateway protocol foundation is release-wired', () => {
  for (const path of [
    'docs/adr/0007-signed-remote-request-acceptance.md',
    'providers/reference-remote-gateway/README.md',
    'providers/reference-remote-gateway/gateway.mjs',
    'schemas/remote-gateway-config.schema.json',
    'schemas/remote-request-envelope.schema.json',
    'schemas/remote-acceptance-envelope.schema.json',
    'scripts/lib/remote-gateway-contracts.mjs',
    'scripts/lib/remote-gateway-client.mjs',
    'test/remote-gateway-contracts.test.mjs',
  ]) {
    assert.ok(
      readFileSync(path).length > 0,
      `${path} must ship with the remote gateway protocol slice`,
    )
  }
})
