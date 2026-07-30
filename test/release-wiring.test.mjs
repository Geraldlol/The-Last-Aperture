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
