import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { PLATFORM_VERSION } from '../scripts/lib/version.mjs'

const WORKFLOW_PATH = '.github/workflows/lint-lenses.yml'
const CHECKOUT_SHA = '08eba0b27e820071cde6df949e0beb9ba4906955'
const SETUP_NODE_SHA = '49933ea5288caeca8642d1e84afbd3f7d6820020'
const RELEASE_VERSION = '0.12.0'

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

test('release metadata exposes the 0.12 controller and conformance commands', () => {
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
    assert.match(help.stdout, /0\.12\.0/, `${cli} must expose the release version`)
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
  assert.match(
    readFileSync('scripts/audit.mjs', 'utf8'),
    /red-team-audit run-remote <run\.json\|bundle-directory> <remote-gateway-config\.json>/,
  )
})

test('the v0.11 authorized external HTTP-recon slice is release-wired', () => {
  for (const path of [
    'docs/adr/0013-authorized-external-http-recon.md',
    'docs/adr/0014-operator-attested-http-recon.md',
    'docs/adr/0015-url-first-pkix-http-recon.md',
    'docs/adr/0018-controller-governed-diagnostic-http-recon-headers.md',
    'docs/http-recon-protocol.md',
    'schemas/http-recon-roe.schema.json',
    'schemas/http-recon-target-proof.schema.json',
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
  assert.match(cli, /Planning performs no network activity/)
  assert.match(cli, /http-recon plan --target-url/)
  assert.match(cli, /http-recon plan-signed --roe/)
  assert.match(cli, /Operator-attested authorization is a/)
  assert.match(cli, /runtime-configured CA trust and hostname validation/)
  const attestedPlanShape = cli.slice(
    cli.indexOf('  plan: {'),
    cli.indexOf("  'plan-signed': {"),
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
    'scripts/lib/http-authed-controller.mjs',
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
  assert.match(cli, /plan-written/)
  assert.match(cli, /campaign-written/)
  assert.match(cli, /authorization_binding_sha256/)
  assert.match(cli, /immutable campaign ledger/)
  assert.match(cli, /countersignature-N\.json/)
  const help = spawnSync(process.execPath, ['scripts/http-authed.mjs', '--help'], {
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  })
  assert.equal(help.status, 0)
  assert.match(help.stdout, /red-team-audit authenticated HTTP campaigns 0\.12\.0/)
  assert.match(help.stdout, /plan-attested --scope <absolute-new-scope\.json>/)
  assert.match(help.stdout, /validate-attested --scope <scope\.json>/)
  assert.match(help.stdout, /campaign-attested --scope <scope\.json>/)
  assert.match(help.stdout, /--attest-authorized/)
  assert.match(help.stdout, /plan-written --scope <absolute-new-scope\.json>/)
  assert.match(help.stdout, /Both planners and validators perform no network activity/)
  assert.match(help.stdout, /operator declaration only/i)
  assert.match(help.stdout, /does not independently verify vendor\/program/i)
  assert.match(help.stdout, /--credential-stdin/)
  assert.match(help.stdout, /--credential-browser/)
  assert.match(help.stdout, /--browser-extension-id/)
  assert.match(help.stdout, /one explicit attach gesture per campaign/i)
  assert.match(help.stdout, /--requests/)
  assert.match(help.stdout, /--cleanup-not-after defaults to --not-after/i)
  assert.match(help.stdout, /ledger-proven rollback\/verification, never new work/i)

  const helpLines = help.stdout.split(/\r?\n/)
  for (const command of ['plan-attested', 'validate-attested', 'campaign-attested']) {
    const line = helpLines.find((value) => value.includes(`http-authed ${command}`)) ?? ''
    assert.notEqual(line, '', `${command} must have a usage line`)
    assert.doesNotMatch(line, /authorization-document|document-issuer|document-issued-at/)
  }
  assert.match(
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
  assert.match(attestedAdr, /plan-attested --attest-authorized/)
  assert.match(attestedAdr, /validate-attested/)
  assert.match(attestedAdr, /campaign-attested/)
  assert.match(attestedAdr, /authorization_binding_sha256/)
  assert.match(attestedAdr, /independently_verified: false/)
  assert.match(attestedAdr, /does not prove that the declaration is true/i)
  assert.match(attestedAdr, /does not\s+verify the approver's identity or independence/i)
  assert.match(attestedAdr, /--requests <absolute-requests\.json>/)
  assert.match(attestedAdr, /--cleanup-not-after/)
  assert.match(attestedAdr, /CLEANUP_SESSION_CONFIRMED/)
  assert.doesNotMatch(attestedAdr, /pinned independent approver/i)

  const schema = JSON.parse(readFileSync('schemas/http-authed-scope.schema.json', 'utf8'))
  assert.match(schema.title, /http-authed-v1/)
  assert.doesNotMatch(schema.description, /draft/i)

  const skill = readFileSync('skills/red-team-audit/SKILL.md', 'utf8')
  assert.match(skill, /plan-written/)
  assert.match(skill, /plan-attested --attest-authorized/)
  assert.match(skill, /validate-attested/)
  assert.match(skill, /campaign-attested/)
  assert.match(skill, /validate-written/)
  assert.match(skill, /campaign-written/)
  assert.match(skill, /OPERATOR_ATTESTED_AUTHED/)
  assert.match(skill, /WRITTEN_AUTHORIZATION_AUTHED/)
  assert.match(skill, /http-authed-v1/)
  assert.match(skill, /--credential-stdin/)
  assert.match(skill, /--credential-browser/)
  assert.match(skill, /CHROME_ACTIVE_TAB_SESSION/)
  assert.match(skill, /one attach per campaign/i)
  assert.match(skill, /--requests <absolute-json>/)
  assert.match(skill, /cleanup_not_after/)
  assert.match(skill, /Native refuses `CONNECT`\/upgrades; browser also refuses `TRACE`\/`TRACK`/)
  assert.match(skill, /vendor\/program permission[\s\S]*not independently verified/i)
  assert.doesNotMatch(skill, /Copy value/)

  const readme = readFileSync('README.md', 'utf8')
  assert.match(readme, /browser\/http-authed-chrome/)
  assert.match(readme, /plan-attested/)
  assert.match(readme, /validate-attested/)
  assert.match(readme, /campaign-attested/)
  assert.match(readme, /authorization_binding_sha256/)
  assert.match(readme, /independently_verified: false/)
  assert.match(readme, /declared authorizer and reference are audit fields, not proof/i)
  assert.match(readme, /--credential-browser/)
  assert.match(readme, /--credential-stdin/)
  assert.match(readme, /automatically prepares and executes/i)
  assert.match(readme, /--requests C:\\trusted\\requests\.json/)
  assert.match(readme, /validity\.cleanup_not_after/)
  assert.match(readme, /CLEANUP_SESSION_CONFIRMED/)
  assert.doesNotMatch(readme, /prepare and commit each/i)
  assert.doesNotMatch(readme, /Get-Clipboard -Raw/)
  assert.doesNotMatch(readme, /Copy value/)
  const security = readFileSync('SECURITY.md', 'utf8')
  assert.match(security, /--credential-stdin/)
  assert.match(security, /--credential-browser/)
  assert.match(security, /activeTab/)
  assert.match(security, /never (?:reads|receives).*cookie/i)
  assert.match(security, /OPERATOR_ATTESTED_AUTHED/)
  assert.match(security, /authorization_binding_sha256/)
  assert.match(security, /CLI attestation records a\s+claim and does not create permission/i)
  assert.match(security, /validity\.cleanup_not_after/)
  assert.match(security, /CLEANUP_SESSION_CONFIRMED/)
  assert.match(security, /browser\s+transport also refuses `TRACE` and `TRACK`/i)
  const rootSkill = readFileSync('SKILL.md', 'utf8')
  assert.match(rootSkill, /audit:http-authed/)
  assert.match(rootSkill, /OPERATOR_ATTESTED_AUTHED/)
  assert.match(rootSkill, /WRITTEN_AUTHORIZATION_AUTHED/)
  assert.match(rootSkill, /does not verify vendor or\s+program permission/i)
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
    /red-team-audit publish <run\.json\|bundle-directory> <transparency-log-config\.json>/,
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
  assert.match(transparencyJob, /sudo apt-get install --yes ripgrep/)
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
