import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import { PLATFORM_VERSION } from '../scripts/lib/version.mjs'

const WORKFLOW_PATH = '.github/workflows/lint-lenses.yml'
const CHECKOUT_SHA = '08eba0b27e820071cde6df949e0beb9ba4906955'
const SETUP_NODE_SHA = '49933ea5288caeca8642d1e84afbd3f7d6820020'
const RELEASE_VERSION = '0.13.0'

function workflowJobBlock(workflow, name) {
  const marker = `  ${name}:\n`
  const start = workflow.indexOf(marker)
  assert.notEqual(start, -1, `workflow must contain job ${name}`)
  const bodyStart = start + marker.length
  const remainder = workflow.slice(bodyStart)
  const next = remainder.search(/^  [a-z0-9-]+:\s*$/m)
  return next === -1 ? remainder : remainder.slice(0, next)
}

test('shared proof recipes expose sealed public T1 and narrow loopback T2 controller routes', () => {
  const harness = readFileSync('skills/last-aperture/lenses/_harness.md', 'utf8')
  const publicT1Decision = readFileSync(
    'docs/adr/0022-public-sealed-t1-proof.md',
    'utf8',
  )
  const publicT2Decision = readFileSync(
    'docs/adr/0024-public-sealed-t2-loopback-service-proof.md',
    'utf8',
  )
  const prose = harness.replace(/^>\s?/gm, '')
  assert.match(harness, /CURRENT RELEASE EXECUTION ROUTES/)
  assert.match(prose, /Public T1 uses `audit run-proof`; narrow\s+loopback T2 uses `audit run-service-proof`/)
  assert.match(
    prose,
    /sealed source\s+snapshot and external digest-pinned, dependency-manifest-bound Docker worker/,
  )
  assert.match(
    prose,
    /operator statement is the sole authorization fact for every named\s+capability[\s\S]*ask once only when it is\s+missing, and never re-ask/i,
  )
  assert.match(
    prose,
    /Other T2 shapes, live credentials, and\s+external services need separate controllers; otherwise retain authority and\s+emit an authorized-but-unavailable gap/i,
  )
  assert.match(publicT1Decision, /Replaces as current capability statement:[\s\S]*disabled release status/i)
  assert.match(publicT1Decision, /Public repository T1 proof is active under these rules/i)
  assert.match(publicT2Decision, /Add public `audit run-service-proof` for one constrained local-service shape/i)
  assert.match(publicT2Decision, /other supporting infrastructure[\s\S]*authorized-but-unavailable/i)
})

test('internal audit command exports are documented as privileged non-API kernels', () => {
  const security = readFileSync('SECURITY.md', 'utf8')
  const skill = readFileSync('skills/last-aperture/SKILL.md', 'utf8')
  const design = readFileSync('docs/design/2026-09-03-adversarial-validation-engine.md', 'utf8')
  assert.match(security, /command\/package-interface boundary, not an in-process JavaScript[\s\S]*sandbox/i)
  assert.match(security, /Directly importing those exports is privileged maintainer code/i)
  assert.match(skill, /Never deep-import or call retained internal audit command exports/i)
  assert.match(design, /same-process deep import is privileged[\s\S]*not a sandboxed or supported product API/i)
})

test('CI pins third-party actions and exercises the advertised Node floor', () => {
  const workflow = readFileSync(WORKFLOW_PATH, 'utf8')

  assert.match(workflow, new RegExp(`actions/checkout@${CHECKOUT_SHA} # v4\\.3\\.0`))
  assert.match(workflow, new RegExp(`actions/setup-node@${SETUP_NODE_SHA} # v4\\.4\\.0`))
  assert.doesNotMatch(workflow, /actions\/(?:checkout|setup-node)@v\d+/)
  assert.match(workflow, /node:\s*\['20', '24'\]/)
  assert.match(workflow, /node-version:\s*\$\{\{\s*matrix\.node\s*\}\}/)
  assert.doesNotMatch(workflow, /^\s{2}pull_request:/m)
  assert.match(workflow, /^\s{2}workflow_dispatch:/m)
  assert.match(workflow, /^\s{4}if: github\.ref == 'refs\/heads\/main'$/m)
  assert.match(workflow, /- run: npm ci --ignore-scripts/)
  assert.match(workflow, /- run: npm test/)
  assert.doesNotMatch(workflow, /sudo apt-get install --yes ripgrep/)
  assert.match(
    readFileSync('package.json', 'utf8'),
    /test:cloud-iac:conformance.*conformance\/cloud-iac-fixtures\.conformance\.mjs/,
  )
})

test('CI runs the hostile real-Docker gate with immutable image input', () => {
  const workflow = readFileSync(WORKFLOW_PATH, 'utf8')
  const providerJob = workflowJobBlock(workflow, 'provider-docker-conformance')

  assert.match(workflow, /^\s{2}provider-docker-conformance:$/m)
  assert.match(
    providerJob,
    /--file providers\/reference-byte-consumer\/Dockerfile\.conformance/,
  )
  assert.match(
    providerJob,
    /NODE_IMAGE=node:22-bookworm@sha256:[a-f0-9]{64}/,
  )
  assert.match(providerJob, /RTA_DOCKER_RUNTIME: \$\{\{ steps\.docker\.outputs\.runtime \}\}/)
  assert.match(providerJob, /RTA_PROVIDER_IMAGE: \$\{\{ steps\.docker\.outputs\.image \}\}/)
  assert.match(providerJob, /run: npm ci --ignore-scripts/)
  assert.match(providerJob, /run: npm run test:provider:docker/)
  assert.match(providerJob, /github\.event_name == 'workflow_dispatch'.*refs\/heads\/main/)
  assert.match(providerJob, /environment: release-conformance/)
  assert.doesNotMatch(providerJob, /continue-on-error:\s*true/)
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

test('CI runs the protected service-proof Docker gate with immutable image input', () => {
  const workflow = readFileSync(WORKFLOW_PATH, 'utf8')
  const serviceProofJob = workflowJobBlock(workflow, 'service-proof-docker-conformance')

  assert.match(workflow, /^\s{2}service-proof-docker-conformance:$/m)
  assert.match(serviceProofJob, /--file containers\/node-proof-worker\.Dockerfile/)
  assert.match(
    readFileSync('containers/node-proof-worker.Dockerfile', 'utf8'),
    /^FROM node@sha256:[a-f0-9]{64}$/m,
  )
  assert.match(
    serviceProofJob,
    /RTA_DOCKER_RUNTIME: \$\{\{ steps\.service-proof-docker\.outputs\.runtime \}\}/,
  )
  assert.match(
    serviceProofJob,
    /RTA_PROOF_WORKER_IMAGE: \$\{\{ steps\.service-proof-docker\.outputs\.image \}\}/,
  )
  assert.match(serviceProofJob, /docker image inspect --format '\{\{\.Id\}\}'/)
  assert.match(serviceProofJob, /run: npm ci --ignore-scripts/)
  assert.match(serviceProofJob, /run: npm run test:service-proof:docker/)
  assert.match(serviceProofJob, /github\.event_name == 'workflow_dispatch'.*refs\/heads\/main/)
  assert.match(serviceProofJob, /environment: release-conformance/)
  assert.doesNotMatch(serviceProofJob, /continue-on-error:\s*true/)
})

test('the service-proof Docker gate refuses to skip when runtime inputs are absent', () => {
  const env = { ...process.env }
  delete env.RTA_DOCKER_RUNTIME
  delete env.RTA_PROOF_WORKER_IMAGE
  const result = spawnSync(
    process.execPath,
    ['scripts/run-service-proof-docker-conformance.mjs'],
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
    /real service-proof conformance requires RTA_DOCKER_RUNTIME and RTA_PROOF_WORKER_IMAGE/,
  )
})

test('CI runs the digest-pinned multi-engine database conformance gate', () => {
  const workflow = readFileSync(WORKFLOW_PATH, 'utf8')
  const databaseJob = workflowJobBlock(workflow, 'database-docker-conformance')

  assert.match(workflow, /^\s{2}database-docker-conformance:$/m)
  assert.match(
    databaseJob,
    /docker pull postgres@sha256:[a-f0-9]{64}/,
  )
  assert.match(
    databaseJob,
    /docker pull mysql@sha256:[a-f0-9]{64}/,
  )
  assert.match(
    databaseJob,
    /RTA_DOCKER_RUNTIME: \$\{\{ steps\.database-docker\.outputs\.runtime \}\}/,
  )
  assert.match(databaseJob, /run: npm ci --ignore-scripts/)
  assert.match(databaseJob, /run: npm run test:database:docker/)
  assert.match(databaseJob, /github\.event_name == 'workflow_dispatch'.*refs\/heads\/main/)
  assert.match(databaseJob, /environment: release-conformance/)
  assert.doesNotMatch(databaseJob, /continue-on-error:\s*true/)
})

test('the Chrome companion has selected-tab, ephemeral recovery, and optional loopback authority', () => {
  const manifest = JSON.parse(readFileSync('browser/http-authed-chrome/manifest.json', 'utf8'))
  assert.equal(manifest.version, '0.13.0')
  assert.deepEqual(manifest.permissions, ['activeTab', 'scripting', 'storage'])
  assert.deepEqual(manifest.host_permissions, [])
  assert.deepEqual(manifest.optional_host_permissions, ['http://127.0.0.1/*'])
  assert.equal(manifest.background.service_worker, 'service-worker.js')
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

test('release metadata exposes the 0.13 controller and conformance commands', () => {
  const packageDocument = JSON.parse(readFileSync('package.json', 'utf8'))
  const lockDocument = JSON.parse(readFileSync('package-lock.json', 'utf8'))

  assert.equal(packageDocument.version, RELEASE_VERSION)
  assert.equal(lockDocument.version, RELEASE_VERSION)
  assert.equal(lockDocument.packages[''].version, RELEASE_VERSION)
  assert.equal(PLATFORM_VERSION, RELEASE_VERSION)
  assert.match(readFileSync('scripts/lib/run-engine.mjs', 'utf8'), /export \{ PLATFORM_VERSION \}/)
  for (const cli of [
    'scripts/audit.mjs',
    'scripts/http-recon.mjs',
    'scripts/http-authed.mjs',
    'scripts/acquire.mjs',
  ]) {
    const help = spawnSync(process.execPath, [cli, '--help'], {
      encoding: 'utf8',
      shell: false,
      windowsHide: true,
    })
    assert.equal(help.status, 0, `${cli} --help must succeed`)
    assert.match(help.stdout, /0\.13\.0/, `${cli} must expose the release version`)
    assert.doesNotMatch(readFileSync(cli, 'utf8'), /0\.11\.0/)
  }
  assert.equal(
    packageDocument.scripts['conformance:database'],
    'node scripts/database-conformance.mjs',
  )
  assert.equal(
    packageDocument.scripts['test:database:docker'],
    'node scripts/run-database-docker-conformance.mjs',
  )
  assert.equal(
    packageDocument.scripts['test:transparency:https'],
    'node scripts/run-transparency-log-conformance.mjs',
  )
  assert.equal(
    packageDocument.scripts['test:service-proof:docker'],
    'node scripts/run-service-proof-docker-conformance.mjs',
  )
  assert.match(
    readFileSync('scripts/audit.mjs', 'utf8'),
    /last-aperture run-remote <run\.json\|bundle-directory> <remote-gateway-config\.json>\s+\[DISABLED\]/,
  )
  assert.match(
    readFileSync('scripts/audit.mjs', 'utf8'),
    /REMOTE_GATEWAY_ENROLLMENT_REQUIRED/,
  )
  assert.match(
    readFileSync('scripts/audit.mjs', 'utf8'),
    /PROVIDER_RUNTIME_ENROLLMENT_REQUIRED/,
  )
  assert.match(
    readFileSync('scripts/audit.mjs', 'utf8'),
    /TRANSPARENCY_LOG_ENROLLMENT_REQUIRED/,
  )
  assert.match(
    readFileSync('scripts/audit.mjs', 'utf8'),
    /EVIDENCE_BUNDLE_TRUST_ENROLLMENT_REQUIRED/,
  )
  const auditSource = readFileSync('scripts/audit.mjs', 'utf8')
  assert.doesNotMatch(auditSource, /SOURCE_SNAPSHOT_ENROLLMENT_REQUIRED/)
  assert.doesNotMatch(auditSource, /RUN_PROOF_SANDBOX_REQUIRED/)
  assert.match(auditSource, /run-proof[^\n]+--worker <proof-worker\.json>/)
  assert.match(auditSource, /runDockerProofCommand/)
  assert.equal(existsSync('schemas/proof-worker.schema.json'), true)
  assert.equal(existsSync('scripts/lib/proof-docker-runner.mjs'), true)
  const refusedEvidenceImport = spawnSync(
    process.execPath,
    [
      'scripts/audit.mjs',
      'plan',
      'C:\\definitely-missing\\repository',
      '--evidence-bundle',
      'C:\\definitely-missing\\caller-bundle',
    ],
    { encoding: 'utf8', shell: false, windowsHide: true },
  )
  assert.equal(refusedEvidenceImport.status, 1)
  assert.match(refusedEvidenceImport.stderr, /disabled before repository or bundle access/i)
  assert.doesNotMatch(refusedEvidenceImport.stderr, /ENOENT|not found/i)
  const refusedSourceSeal = spawnSync(
    process.execPath,
    [
      'scripts/audit.mjs',
      'plan',
      'C:\\definitely-missing\\repository',
      '--seal-source',
      '--out',
      'C:\\definitely-missing\\source-export',
    ],
    { encoding: 'utf8', shell: false, windowsHide: true },
  )
  assert.equal(refusedSourceSeal.status, 1)
  assert.doesNotMatch(refusedSourceSeal.stderr, /disabled before repository or output access/i)
  assert.match(refusedSourceSeal.stderr, /ENOENT|not found/i)
  const databaseCli = readFileSync('scripts/database-conformance.mjs', 'utf8')
  assert.match(databaseCli, /database-conformance run[^\r\n]*\[DISABLED\]/)
  assert.match(databaseCli, /DATABASE_RUNTIME_ENROLLMENT_REQUIRED/)
  const refusedDatabaseRun = spawnSync(
    process.execPath,
    ['scripts/database-conformance.mjs', 'run'],
    { encoding: 'utf8', shell: false, windowsHide: true },
  )
  assert.equal(refusedDatabaseRun.status, 1)
  assert.match(refusedDatabaseRun.stderr, /disabled before argument, bundle, or configuration access/i)
  assert.doesNotMatch(refusedDatabaseRun.stderr, /expects 2 positional|ENOENT/i)
})

test('release wiring keeps the entire public acquisition CLI fail closed', () => {
  const source = readFileSync('scripts/acquire.mjs', 'utf8')
  const regression = readFileSync('test/evidence-live-acquisition.test.mjs', 'utf8')
  const help = spawnSync(process.execPath, ['scripts/acquire.mjs', '--help'], {
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  })

  assert.equal(help.status, 0)
  assert.match(help.stdout, /<artifact\|registry\|deployed\|runtime> run[^\r\n]*\[DISABLED\]/i)
  for (const command of ['plan', 'run', 'finalize', 'validate', 'stop']) {
    assert.match(help.stdout, new RegExp(`${command}[^\\r\\n]*\\[DISABLED\\]`, 'i'), command)
    assert.match(regression, new RegExp(`['"]${command}['"]`), command)
  }
  assert.match(help.stdout, /entire public acquisition CLI is disabled[\s\S]*signed plan/i)
  assert.match(source, /ACQUIRE_LIVE_IO_DISABLED/)
  const mainSource = source.slice(source.indexOf('export async function main'))
  const mainGate = mainSource.indexOf('refuseDisabledPublicAcquisition(adapter, command)')
  const firstControllerUse = mainSource.indexOf('await controllerFunction(')
  assert.ok(mainGate >= 0 && firstControllerUse > mainGate)
  for (const adapter of ['artifact', 'registry', 'deployed', 'runtime']) {
    assert.match(regression, new RegExp(`['"]${adapter}['"]`), adapter)
  }
  assert.match(regression, /spoofed-live-adapter/)
  assert.match(regression, /controllers are touched/i)
  assert.match(regression, /forged/)
  assert.match(regression, /confirm-authorization-current/)
})

test('the v0.11 authorized external HTTP-recon slice is release-wired', () => {
  for (const path of [
    'docs/adr/0013-authorized-external-http-recon.md',
    'docs/adr/0014-operator-attested-http-recon.md',
    'docs/adr/0015-url-first-pkix-http-recon.md',
    'docs/adr/0018-controller-governed-diagnostic-http-recon-headers.md',
    'docs/http-recon-protocol.md',
    'schemas/http-recon-attested-scope.schema.json',
    'schemas/http-recon-run.schema.json',
    'schemas/http-recon-observation.schema.json',
    'scripts/http-recon.mjs',
    'scripts/lib/http-recon-contracts.mjs',
    'scripts/lib/http-recon-client.mjs',
    'scripts/lib/http-recon-request-headers.mjs',
    'scripts/lib/http-recon-controller.mjs',
    'test/http-recon-contracts.test.mjs',
    'test/http-recon-client.test.mjs',
    'test/http-recon-request-headers.test.mjs',
    'test/http-recon-controller.test.mjs',
  ]) {
    assert.ok(
      readFileSync(path).length > 0,
      `${path} must ship with the authorized HTTP-recon slice`,
    )
  }
  for (const retiredPath of [
    'schemas/http-recon-roe.schema.json',
    'schemas/http-recon-target-proof.schema.json',
  ]) {
    assert.equal(existsSync(retiredPath), false, `${retiredPath} must remain retired`)
  }
  const packageDocument = JSON.parse(readFileSync('package.json', 'utf8'))
  assert.equal(
    packageDocument.scripts['audit:http-recon'],
    'node scripts/http-recon.mjs',
  )
  for (const testPath of [
    'test/http-recon-contracts.test.mjs',
    'test/http-recon-client.test.mjs',
    'test/http-recon-request-headers.test.mjs',
    'test/http-recon-controller.test.mjs',
  ]) {
    assert.match(packageDocument.scripts['test:platform'], new RegExp(testPath.replace('.', '\\.')))
  }
  const cli = readFileSync('scripts/http-recon.mjs', 'utf8')
  const protocol = readFileSync('docs/http-recon-protocol.md', 'utf8')
  for (const adrPath of [
    'docs/adr/0013-authorized-external-http-recon.md',
    'docs/adr/0014-operator-attested-http-recon.md',
    'docs/adr/0015-url-first-pkix-http-recon.md',
    'docs/adr/0018-controller-governed-diagnostic-http-recon-headers.md',
  ]) {
    const adr = readFileSync(adrPath, 'utf8')
    assert.match(adr, /Current 0\.13\.0 execution status: active/i, adrPath)
    assert.doesNotMatch(adr, /HTTP_RECON_LIVE_IO_DISABLED/, adrPath)
  }
  assert.match(cli, /Planning by itself performs no network activity/i)
  assert.match(cli, /http-recon go <exact-https-url>/)
  assert.match(cli, /http-recon plan --target-url/)
  assert.doesNotMatch(
    cli,
    /plan-signed|--roe|--authorization-document|--owner-public-key/,
  )
  assert.doesNotMatch(cli, /HTTP_RECON_LIVE_IO_DISABLED/)
  assert.match(protocol, /Current 0\.13\.0 execution status: active/i)
  assert.doesNotMatch(protocol, /HTTP_RECON_LIVE_IO_DISABLED/)
  assert.match(protocol, /go <exact-https-url>/i)
  assert.match(protocol, /plans one exact action, executes it, finalizes the bundle/i)
  assert.doesNotMatch(protocol, /Current platform release: 0\.12\.0/)
  assert.match(cli, /Operator-attested authorization is a/)
  assert.match(cli, /runtime-configured CA trust and hostname validation/)
  const attestedPlanShape = cli.slice(
    cli.indexOf('  plan: {'),
    cli.indexOf('  next: {'),
  )
  assert.doesNotMatch(
    attestedPlanShape.match(/required:\s*\[[\s\S]*?\]/)?.[0] ?? '',
    /tls-spki-sha256/,
  )
  assert.match(attestedPlanShape, /optional:[\s\S]*tls-spki-sha256/)
  assert.doesNotMatch(cli, /--(?:header|payload|credential|body)/)
})

test('the v0.12 authenticated campaign is release-wired through the governing skill', () => {
  const sourcePaths = [
    'docs/adr/0016-authenticated-mutation-actions.md',
    'docs/adr/0017-operator-attested-authenticated-campaigns.md',
    'schemas/http-authed-scope.schema.json',
    'scripts/http-authed.mjs',
    'scripts/lib/version.mjs',
    'scripts/lib/http-authed-contracts.mjs',
    'scripts/lib/http-authed-planner.mjs',
    'scripts/lib/http-authed-credential.mjs',
    'scripts/lib/http-authed-client.mjs',
    'scripts/lib/http-authed-response-metadata.mjs',
    'scripts/lib/http-authed-campaign-ledger.mjs',
    'scripts/lib/http-authed-discovery.mjs',
    'scripts/lib/http-authed-mutation-controller.mjs',
    'scripts/lib/http-authed-campaign-controller.mjs',
    'scripts/lib/http-authed-campaign-runtime.mjs',
    'scripts/lib/http-authed-browser-bridge-core.mjs',
    'scripts/lib/http-authed-browser-bridge-server.mjs',
    'scripts/lib/http-authed-browser-bridge.mjs',
    'browser/http-authed-chrome/manifest.json',
    'browser/http-authed-chrome/injected-fetch.mjs',
    'browser/http-authed-chrome/service-worker.js',
    'browser/http-authed-chrome/popup.html',
    'browser/http-authed-chrome/popup.js',
    'browser/http-authed-chrome/popup.css',
    'test/helpers/http-authed-fixtures.mjs',
  ]
  const httpAuthedTests = [
    'test/http-authed-planner.test.mjs',
    'test/http-authed-credential.test.mjs',
    'test/http-authed-attested.test.mjs',
    'test/http-authed-written-authorization.test.mjs',
    'test/http-authed-client.test.mjs',
    'test/http-authed-transport-boundary.test.mjs',
    'test/http-authed-mutation-contracts.test.mjs',
    'test/http-authed-discovery-contracts.test.mjs',
    'test/http-authed-campaign-ledger.test.mjs',
    'test/http-authed-discovery.test.mjs',
    'test/http-authed-mutation-controller.test.mjs',
    'test/http-authed-campaign-controller.test.mjs',
    'test/http-authed-campaign-runtime.test.mjs',
    'test/http-authed-browser-bridge.test.mjs',
    'test/http-authed-browser-extension.test.mjs',
    'test/http-authed-browser-injected.test.mjs',
  ]
  for (const path of [...sourcePaths, ...httpAuthedTests]) {
    assert.ok(readFileSync(path).length > 0, `${path} must ship with http-authed`)
  }
  const packageDocument = JSON.parse(readFileSync('package.json', 'utf8'))
  assert.equal(packageDocument.scripts['audit:http-authed'], 'node scripts/http-authed.mjs')
  const platformTests = new Set(packageDocument.scripts['test:platform'].split(/\s+/))
  for (const path of httpAuthedTests) {
    assert.ok(platformTests.has(path), `${path} must run in test:platform`)
  }
  const cli = readFileSync('scripts/http-authed.mjs', 'utf8')
  assert.match(cli, /plan-attested/)
  assert.match(cli, /campaign-attested/)
  assert.doesNotMatch(
    cli,
    /plan-written|validate-written|campaign-written|--authorization-document|--approver-public-key|countersignature/i,
  )
  assert.match(cli, /authorization_binding_sha256/)
  assert.match(cli, /locally append-only,[\s\S]*hash-chained campaign ledger/)
  const help = spawnSync(process.execPath, ['scripts/http-authed.mjs', '--help'], {
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  })
  assert.equal(help.status, 0)
  assert.match(help.stdout, /last-aperture authenticated HTTP campaigns 0\.13\.0/)
  assert.doesNotMatch(help.stdout, /campaign-attested.*DISABLED/i)
  assert.doesNotMatch(
    help.stdout,
    /plan-written|validate-written|campaign-written|probe-written|authorization-document|approver-public-key|countersignature/i,
  )
  assert.match(help.stdout, /standalone probes are not public/i)
  assert.match(help.stdout, /sealed adaptive[\s\S]*response-derived discovery/i)
  assert.match(help.stdout, /http-authed campaign-stop/i)
  assert.match(
    help.stdout,
    /Across restarts,[\s\S]*requires the separately retained trusted record count and head digest/i,
  )
  assert.doesNotMatch(
    readFileSync('scripts/http-authed.mjs', 'utf8'),
    /HTTP_AUTHED_LIVE_IO_DISABLED/,
  )
  assert.ok(
    readFileSync('test/http-authed-live-cli-disabled.test.mjs').length > 0,
    'the live-I/O controller regression test must ship',
  )
  assert.match(help.stdout, /plan-attested --scope <absolute-new-scope\.json>/)
  assert.match(help.stdout, /validate-attested --scope <scope\.json>/)
  assert.match(help.stdout, /campaign-attested --scope <scope\.json>/)
  assert.match(help.stdout, /Both planners and validators perform no network activity/)
  assert.match(help.stdout, /explicit operator statement/i)
  assert.match(help.stdout, /accepts it as the authorization\s+fact/i)
  assert.match(help.stdout, /does not independently prove.*legal authority/is)
  assert.match(help.stdout, /--credential-stdin/)
  assert.match(help.stdout, /--credential-browser/)
  assert.match(help.stdout, /--browser-extension-id/)
  assert.match(help.stdout, /packaged Chrome companion pairs[\s\S]*active tab/i)
  assert.match(help.stdout, /without exporting cookies or[\s\S]*authorization values/i)
  assert.match(help.stdout, /browser-managed DNS/i)
  assert.match(help.stdout, /--requests/)
  assert.match(help.stdout, /--cleanup-not-after defaults to --not-after/i)
  assert.match(help.stdout, /ledger-proven rollback\/verification, never new work/i)

  const helpLines = help.stdout.split(/\r?\n/)
  for (const command of ['plan-attested', 'validate-attested', 'campaign-attested']) {
    const line = helpLines.find((value) => value.includes(`http-authed ${command}`)) ?? ''
    assert.notEqual(line, '', `${command} must have a usage line`)
    assert.doesNotMatch(line, /authorization-document|document-issuer|document-issued-at/)
  }
  assert.doesNotMatch(
    helpLines.find((value) => value.includes('http-authed plan-attested')) ?? '',
    /--attest-authorized/,
  )

  const adr = readFileSync('docs/adr/0016-authenticated-mutation-actions.md', 'utf8')
  assert.match(adr, /Status: Accepted - implemented in v0\.12\.0/)
  assert.match(adr, /plan-written/)
  assert.match(adr, /--credential-stdin/)
  assert.match(adr, /CHROME_ACTIVE_TAB_SESSION/)
  assert.match(adr, /--credential-browser/)
  assert.match(adr, /Chrome applies its current session/i)
  assert.match(adr, /validity\.not_after/)
  assert.match(adr, /validity\.cleanup_not_after/)
  assert.match(adr, /Native transport refuses `CONNECT`/)
  assert.match(adr, /browser transport also refuses `TRACE` and `TRACK`/)
  assert.doesNotMatch(adr, /credential rotation requires a new binding/i)
  assert.match(adr, /Amended: ADR 0017/)
  assert.match(adr, /Superseded by ADR 0017/)

  const attestedAdr = readFileSync(
    'docs/adr/0017-operator-attested-authenticated-campaigns.md',
    'utf8',
  )
  assert.match(attestedAdr, /Status: Accepted - implemented in v0\.12\.0/)
  assert.match(attestedAdr, /plan-attested/)
  assert.match(attestedAdr, /validate-attested/)
  assert.match(attestedAdr, /campaign-attested/)
  assert.match(attestedAdr, /authorization_binding_sha256/)
  assert.match(attestedAdr, /independently_verified: false/)
  assert.match(attestedAdr, /accepts[\s\S]*authorization fact/i)
  assert.match(attestedAdr, /not independent proof[\s\S]*legal authority/i)
  assert.match(attestedAdr, /does not\s+verify the approver's identity or independence/i)
  assert.match(attestedAdr, /--requests <absolute-requests\.json>/)
  assert.match(attestedAdr, /--cleanup-not-after/)
  assert.match(attestedAdr, /CLEANUP_SESSION_CONFIRMED/)
  assert.doesNotMatch(attestedAdr, /pinned independent approver/i)

  const schema = JSON.parse(readFileSync('schemas/http-authed-scope.schema.json', 'utf8'))
  assert.match(schema.title, /http-authed-v1/)
  assert.doesNotMatch(schema.description, /draft/i)

  const skill = readFileSync('skills/last-aperture/SKILL.md', 'utf8')
  assert.match(skill, /Packaged target-I\/O paths include/i)
  assert.match(
    skill,
    /Adaptive authenticated HTTP work[\s\S]*campaign-attested[\s\S]*scope-valid discovered[\s\S]*without reconfirmation/i,
  )
  assert.match(skill, /campaign-stop[\s\S]*consumed before another send/i)
  assert.match(skill, /Reverse engineering and protocol reconstruction[\s\S]*Ghidra[\s\S]*Frida/i)
  assert.match(skill, /L3_MAXIMUM_AUTHORIZED/)
  assert.match(skill, /natural-language operator statement[\s\S]*sole authorization step/i)
  assert.match(skill, /without ownership proof[\s\S]*per-action confirmation/i)
  assert.match(skill, /Compose available[\s\S]*host tools under the same attestation/i)
  assert.match(skill, /Offline validation/)
  assert.match(
    skill,
    /sealed Docker implements T1 and narrow[\s\S]*loopback T2[\s\S]*Unsupported T2 stays `UNPROVEN`/i,
  )
  assert.match(skill, /standard browser\/process\/network tool/i)
  assert.doesNotMatch(skill, /Copy value/)

  const readme = readFileSync('README.md', 'utf8')
  assert.match(readme, /browser\/http-authed-chrome/)
  assert.match(readme, /plan-attested/)
  assert.match(readme, /validate-attested/)
  assert.match(readme, /campaign-attested/)
  assert.match(readme, /authorization_binding_sha256/)
  assert.match(readme, /independently_verified: false/)
  assert.match(readme, /declared authorizer and reference are audit fields, not proof/i)
  assert.match(readme, /Version 0\.13\.0[\s\S]*activeTab[\s\S]*scripting/i)
  assert.match(readme, /storage[^\n]*extension-owned ephemeral recovery marker/i)
  assert.match(readme, /no\s+persistent target-host, cookie, debugger, tabs, or web-request access/i)
  assert.match(readme, /--credential-stdin/)
  assert.doesNotMatch(readme, /automatically prepares and executes/i)
  assert.match(readme, /--requests C:\\trusted\\requests\.json/)
  assert.match(readme, /validity\.cleanup_not_after/)
  assert.match(readme, /CLEANUP_SESSION_CONFIRMED/)
  assert.doesNotMatch(readme, /prepare and commit each/i)
  assert.doesNotMatch(readme, /Get-Clipboard -Raw/)
  assert.doesNotMatch(readme, /Copy value/)
  const security = readFileSync('SECURITY.md', 'utf8')
  assert.match(security, /--credential-stdin/)
  assert.match(security, /--credential-browser/)
  assert.match(security, /one-time pairing capability/i)
  assert.match(security, /browser-managed DNS/i)
  assert.match(security, /activeTab[\s\S]*scripting/i)
  assert.match(security, /OPERATOR_ATTESTED_AUTHED/)
  assert.match(security, /authorization_binding_sha256/)
  assert.match(
    security,
    /operator's target\/scope statement at agent\/controller ingress is its sole\s+authorization primitive/i,
  )
  assert.match(
    security,
    /controller does not fetch program terms or independently verify[\s\S]*legal authority/i,
  )
  assert.match(security, /validity\.cleanup_not_after/)
  assert.match(security, /CLEANUP_SESSION_CONFIRMED/)
  assert.match(security, /exact origin\s+and rejects redirects/i)
  const rootSkill = readFileSync('SKILL.md', 'utf8')
  assert.match(rootSkill, /target <HTTPS URL> and go` authorizes the exact bounded\s+HTTP-recon action/i)
  assert.match(rootSkill, /Even one\s+action uses a campaign ledger/i)
  assert.match(
    rootSkill,
    /Use available controllers and standard browser, process, network, Burp, Ghidra,[\s\S]*Frida tooling/i,
  )
  assert.match(rootSkill, /missing dedicated wrapper[\s\S]*not create another authorization gate/i)
})

test('the v0.8 remote gateway protocol foundation is release-wired', () => {
  for (const path of [
    'docs/adr/0007-signed-remote-request-acceptance.md',
    'docs/adr/0008-remote-attempt-ledger-integration.md',
    'providers/reference-remote-gateway/README.md',
    'providers/reference-remote-gateway/gateway.mjs',
    'schemas/remote-gateway-config.schema.json',
    'schemas/remote-request-envelope.schema.json',
    'schemas/remote-acceptance-envelope.schema.json',
    'scripts/lib/remote-gateway-contracts.mjs',
    'scripts/lib/remote-gateway-client.mjs',
    'test/remote-gateway-contracts.test.mjs',
    'test/remote-cli-integration.test.mjs',
  ]) {
    assert.ok(
      readFileSync(path).length > 0,
      `${path} must ship with the remote gateway protocol slice`,
    )
  }
})

test('the v0.9 transparency publication protocol is release-wired', () => {
  for (const path of [
    'docs/adr/0009-external-transparency-inclusion.md',
    'docs/adr/0010-reference-transparency-log.md',
    'docs/transparency-protocol.md',
    'schemas/transparency-log-config.schema.json',
    'schemas/transparency-publish-request.schema.json',
    'schemas/transparency-inclusion-receipt.schema.json',
    'scripts/lib/transparency-log-contracts.mjs',
    'scripts/lib/transparency-log-client.mjs',
    'scripts/run-transparency-log-conformance.mjs',
    'providers/reference-transparency-log/store.mjs',
    'providers/reference-transparency-log/handler.mjs',
    'providers/reference-transparency-log/server.mjs',
    'providers/reference-transparency-log/README.md',
    'test/transparency-log-contracts.test.mjs',
    'test/transparency-log-client.test.mjs',
    'test/reference-transparency-log-store.test.mjs',
    'test/reference-transparency-log-handler.test.mjs',
    'test/reference-transparency-log-conformance.test.mjs',
    'test/fixtures/reference-transparency-tls.mjs',
  ]) {
    assert.ok(
      readFileSync(path).length > 0,
      `${path} must ship with the transparency publication slice`,
    )
  }
  assert.match(
    readFileSync('scripts/audit.mjs', 'utf8'),
    /last-aperture publish <run\.json\|bundle-directory> <transparency-log-config\.json>/,
  )
  const workflow = readFileSync(WORKFLOW_PATH, 'utf8')
  assert.match(workflow, /^\s{2}transparency-https-conformance:$/m)
  assert.match(workflow, /Run stateful HTTPS transparency-log conformance/)
  assert.match(workflow, /run: npm run test:transparency:https/)
  const jobStart = workflow.indexOf('\n  transparency-https-conformance:')
  const jobEnd = workflow.indexOf('\n  provider-docker-conformance:', jobStart)
  assert.notEqual(jobStart, -1)
  assert.notEqual(jobEnd, -1)
  const transparencyJob = workflow.slice(jobStart, jobEnd)
  assert.doesNotMatch(transparencyJob, /continue-on-error:\s*true/)
  assert.match(transparencyJob, /github\.event_name == 'workflow_dispatch'.*refs\/heads\/main/)
  assert.match(transparencyJob, /environment: release-conformance/)
  assert.doesNotMatch(transparencyJob, /sudo apt-get install --yes ripgrep/)
  const packageDocument = JSON.parse(readFileSync('package.json', 'utf8'))
  assert.match(
    packageDocument.scripts['test:platform'],
    /test\/reference-transparency-log-store\.test\.mjs/,
  )
  assert.match(
    packageDocument.scripts['test:platform'],
    /test\/reference-transparency-log-handler\.test\.mjs/,
  )
})

test('the v0.10 externally anchored checkpoint-continuity slice is release-wired', () => {
  for (const path of [
    'docs/adr/0011-externally-anchored-checkpoint-continuity.md',
    'schemas/transparency-signed-checkpoint.schema.json',
    'schemas/transparency-consistency-request.schema.json',
    'schemas/transparency-consistency-proof.schema.json',
    'schemas/transparency-checkpoint-journal-record.schema.json',
    'scripts/lib/transparency-checkpoint-journal.mjs',
    'test/transparency-checkpoint-journal.test.mjs',
  ]) {
    assert.ok(
      readFileSync(path).length > 0,
      `${path} must ship with the checkpoint-continuity slice`,
    )
  }
  const audit = readFileSync('scripts/audit.mjs', 'utf8')
  assert.match(audit, /--transparency-checkpoint-journal/)
  assert.match(audit, /--initialize-transparency-checkpoint-journal/)
  const packageDocument = JSON.parse(readFileSync('package.json', 'utf8'))
  assert.match(
    packageDocument.scripts['test:platform'],
    /test\/transparency-checkpoint-journal\.test\.mjs/,
  )
})

test('bounty-v1 is release-wired: files, npm scripts, and boundary language ship together', () => {
  const sourcePaths = [
    'docs/adr/0019-bounty-program-perimeter-protocol.md',
    'docs/superpowers/specs/2026-08-20-bounty-v1-design.md',
    'schemas/bounty-scope.schema.json',
    'schemas/bounty-surface-inventory.schema.json',
    'schemas/bounty-authz-roles.schema.json',
    'schemas/bounty-authz-identifiers.schema.json',
    'schemas/bounty-oob-session.schema.json',
    'fixtures/bounty/scope-kernel-cases.json',
    'scripts/bounty.mjs',
    'scripts/lib/bounty-target.mjs',
    'scripts/lib/bounty-scope-kernel.mjs',
    'scripts/lib/bounty-contracts.mjs',
    'scripts/lib/bounty-planner.mjs',
    'scripts/lib/bounty-controller.mjs',
    'scripts/lib/bounty-recon-ratelimit.mjs',
    'scripts/lib/bounty-recon-candidate.mjs',
    'scripts/lib/bounty-recon-gate.mjs',
    'scripts/lib/bounty-recon-tls.mjs',
    'scripts/lib/bounty-recon-ctlog.mjs',
    'scripts/lib/bounty-recon-probe.mjs',
    'scripts/lib/bounty-recon-inventory.mjs',
    'scripts/lib/bounty-recon-controller.mjs',
    'scripts/lib/bounty-authz-request.mjs',
    'scripts/lib/bounty-authz-normalize.mjs',
    'scripts/lib/bounty-authz-classify.mjs',
    'scripts/lib/bounty-authz-roles.mjs',
    'scripts/lib/bounty-authz-replay.mjs',
    'scripts/lib/bounty-authz-identifier.mjs',
    'scripts/lib/bounty-authz-controller.mjs',
    'scripts/lib/bounty-scan-insertion.mjs',
    'scripts/lib/bounty-scan-oracle.mjs',
    'scripts/lib/bounty-scan-passive.mjs',
    'scripts/lib/bounty-scan-controller.mjs',
    'scripts/lib/bounty-intensity.mjs',
    'scripts/lib/bounty-report-cvss.mjs',
    'scripts/lib/bounty-report-curl.mjs',
    'scripts/lib/bounty-report.mjs',
    'scripts/lib/bounty-report-controller.mjs',
    'scripts/lib/bounty-oob-payload.mjs',
    'scripts/lib/bounty-oob-correlator.mjs',
    'scripts/lib/bounty-oob-crypto.mjs',
    'scripts/lib/bounty-oob-hosted.mjs',
    'scripts/lib/bounty-oob-dns.mjs',
    'scripts/lib/bounty-oob-http.mjs',
    'scripts/lib/bounty-oob-controller.mjs',
    'scripts/lib/bounty-proxy-ingest.mjs',
    'proxy/bounty_scope_kernel.py',
    'proxy/bounty_helpers.py',
    'proxy/conformance.py',
    'test/fixtures/authz-testbed.mjs',
  ]
  const bountyTests = [
    'test/bounty-target.test.mjs',
    'test/bounty-scope-kernel.test.mjs',
    'test/bounty-scope-kernel-adversarial.test.mjs',
    'test/bounty-contracts.test.mjs',
    'test/bounty-planner.test.mjs',
    'test/bounty-controller.test.mjs',
    'test/bounty-cli.test.mjs',
    'test/bounty-scope-currency.test.mjs',
    'test/bounty-recon-ratelimit.test.mjs',
    'test/bounty-recon-candidate.test.mjs',
    'test/bounty-recon-gate.test.mjs',
    'test/bounty-recon-inventory.test.mjs',
    'test/bounty-recon-tls.test.mjs',
    'test/bounty-recon-probe.test.mjs',
    'test/bounty-recon-controller.test.mjs',
    'test/bounty-authz-request.test.mjs',
    'test/bounty-authz-normalize.test.mjs',
    'test/bounty-authz-classify.test.mjs',
    'test/bounty-authz-roles.test.mjs',
    'test/bounty-authz-replay.test.mjs',
    'test/bounty-authz-identifier.test.mjs',
    'test/bounty-authz-controller.test.mjs',
    'test/bounty-authz-mutation.test.mjs',
    'test/bounty-scan-passive.test.mjs',
    'test/bounty-scan-oracle.test.mjs',
    'test/bounty-scan-controller.test.mjs',
    'test/bounty-intensity.test.mjs',
    'test/bounty-report-cvss.test.mjs',
    'test/bounty-report.test.mjs',
    'test/bounty-report-controller.test.mjs',
    'test/bounty-oob-payload.test.mjs',
    'test/bounty-oob-correlator.test.mjs',
    'test/bounty-oob-crypto.test.mjs',
    'test/bounty-oob-hosted.test.mjs',
    'test/bounty-oob-dns.test.mjs',
    'test/bounty-oob-http.test.mjs',
    'test/bounty-oob-controller.test.mjs',
    'test/bounty-proxy-ingest.test.mjs',
  ]
  for (const path of [...sourcePaths, ...bountyTests]) {
    assert.ok(readFileSync(path).length > 0, `${path} must ship with bounty-v1`)
  }

  const packageDocument = JSON.parse(readFileSync('package.json', 'utf8'))
  assert.equal(packageDocument.scripts['audit:bounty'], 'node scripts/bounty.mjs')
  assert.equal(packageDocument.scripts['conformance:bounty-kernel'], 'py -I -B proxy/conformance.py')
  const platformTests = new Set(packageDocument.scripts['test:platform'].split(/\s+/))
  for (const path of bountyTests) {
    assert.ok(platformTests.has(path), `${path} must run in test:platform`)
  }
  // Structured fuzzing deliberately adds one exact-pinned dependency.
  assert.deepEqual(Object.keys(packageDocument.dependencies).sort(), ['acorn', 'ajv', 'fast-check', 'yaml'])
  assert.equal(packageDocument.dependencies['fast-check'], '4.9.0')

  const help = spawnSync(process.execPath, ['scripts/bounty.mjs', '--help'], {
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  })
  assert.equal(help.status, 0)

  // The boundary language is part of the release, not decoration. Each of these is
  // a nonclaim or a refusal a reader must not be able to miss.
  for (const required of [
    // Fragments rather than whole sentences: the help text is hard-wrapped, and a
    // test that breaks when a paragraph is re-flowed tests formatting, not substance.
    /it does not verify enrollment/i,
    /never produces repository coverage/i,
    /audit clearance/i,
    /It never handles PHI/,
    /Intensity changes how hard we hunt inside the sealed perimeter/,
    /There is no flag that widens scope_rules after sealing/,
    /the program.s stated limit is the authorization/i,
    /There is no COMPLETE/,
    /is inconclusive and is never proof that a target is sound/i,
    /nothing here asserts a vulnerability/i,
    /live replay command is disabled/i,
    /legacy sealed-scope permission is not action authorization/i,
    /enumerating undeclared ids means reading a stranger.s data/i,
    /Severity is a SUGGESTION/,
    /Nothing is submitted automatically/,
    /Live forwarding is disabled/i,
    /no loadable mitmproxy addon ships/i,
    /Every public OOB session command is disabled/i,
  ]) {
    assert.match(help.stdout, required, `--help must carry: ${required}`)
  }

  // Every command group reachable from the one entry point.
  for (const usage of [
    /bounty plan --platform/,
    /bounty validate <bundle>/,
    /bounty revalidate <bundle>/,
    /bounty scope <bundle> --check/,
    /bounty recon run <bundle>/,
    /bounty authz import <bundle>/,
    /bounty authz run <bundle>/,
    /bounty scan run <bundle>/,
    /literal loopback URL is not proof/i,
    /bounty report draft <bundle>/,
    /bounty oob open <bundle>/,
    /bounty proxy ingest <bundle>/,
  ]) {
    assert.match(help.stdout, usage, `--help must document: ${usage}`)
  }
  assert.match(readFileSync('scripts/bounty.mjs', 'utf8'), /BOUNTY_RECON_LIVE_IO_DISABLED/)

  // The perimeter is enforced by two implementations, so the fixture suite they
  // both answer to must ship, and the Python side must keep its explicit ranges.
  const fixtures = JSON.parse(readFileSync('fixtures/bounty/scope-kernel-cases.json', 'utf8'))
  assert.equal(fixtures.kind, 'red-team-audit/bounty-scope-kernel-cases')
  assert.ok(fixtures.cases.length >= 35, 'the shared kernel fixture suite must ship')
  const pythonKernel = readFileSync('proxy/bounty_scope_kernel.py', 'utf8')
  assert.match(pythonKernel, /deliberately NOT ipaddress\.is_private/)
})
