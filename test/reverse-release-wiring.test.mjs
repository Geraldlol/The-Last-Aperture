import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { test } from 'node:test'

import Ajv2020 from 'ajv/dist/2020.js'

import { CAPABILITY_REGISTRY } from '../scripts/lib/capabilities.mjs'
import {
  analyzeGhidraArtifact,
  traceFridaArtifact,
} from '../scripts/lib/reverse-controller.mjs'
import {
  buildNativeInteractionContract,
} from '../scripts/lib/reverse-protocol.mjs'
import { importWebHarEvidence } from '../scripts/lib/reverse-web-har.mjs'

const WEB_SCHEMA_PATH = 'schemas/web-session-evidence.schema.json'
const CONTRACT_SCHEMA_PATH = 'schemas/native-interaction-contract.schema.json'
const REVERSE_SCHEMA_PATH = 'schemas/reverse-evidence.schema.json'

function schemaValidator(path) {
  const schema = JSON.parse(readFileSync(path, 'utf8'))
  const ajv = new Ajv2020({
    strict: true,
    strictTuples: false,
    allErrors: true,
    allowUnionTypes: true,
  })
  return { schema, validate: ajv.compile(schema), ajv }
}

function observedDocuments() {
  const har = {
    log: {
      entries: [
        {
          startedDateTime: '2026-09-11T12:00:00.000Z',
          time: 10,
          request: {
            method: 'POST',
            url: 'https://portal.example/auth/login',
            headers: [{ name: 'Content-Type', value: 'application/x-www-form-urlencoded' }],
            cookies: [],
            postData: {
              mimeType: 'application/x-www-form-urlencoded',
              params: [
                { name: 'UserName', value: 'synthetic-user' },
                { name: 'Password', value: 'synthetic-password' },
              ],
            },
          },
          response: {
            status: 200,
            headers: [{ name: 'Set-Cookie', value: 'SessionCookie=synthetic-cookie' }],
            cookies: [{ name: 'SessionCookie', value: 'synthetic-cookie' }],
            content: {
              mimeType: 'application/json',
              size: 64,
              text: '{"status":"ok","nextUrl":"https://portal.example/home"}',
            },
          },
        },
      ],
    },
  }
  const webEvidence = importWebHarEvidence(har, {
    sourceSha256: 'a'.repeat(64),
    targetOrigins: ['https://portal.example'],
  })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [webEvidence],
    reverseEvidence: [],
    generatedAt: '2026-09-11T12:01:00.000Z',
  })
  return { webEvidence, contract }
}

test('reverse engineering ships its consumer contracts and public entry points together', () => {
  for (const path of [
    'scripts/reverse.mjs',
    'scripts/lib/reverse-controller.mjs',
    'scripts/lib/reverse-contracts.mjs',
    'scripts/lib/reverse-ghidra.mjs',
    'scripts/lib/reverse-frida.mjs',
    'scripts/lib/reverse-frida-v2.mjs',
    'scripts/lib/reverse-web-burp.mjs',
    'scripts/lib/reverse-web-har.mjs',
    'scripts/lib/reverse-protocol.mjs',
    'scripts/lib/reverse-connector-generator.mjs',
    'scripts/templates/native-connector-runtime.mjs',
    'scripts/ghidra/LastApertureExport.java',
    'scripts/ghidra/GhidraBundleLocationAgent.java.source',
    'scripts/ghidra/GhidraBundleLocationAgent.mf',
    'scripts/frida/native-call-trace-v1.js',
    'scripts/frida/native-call-trace-v2.js',
    'scripts/lib/page-session-adapter.mjs',
    'scripts/windows/job-supervisor.ps1',
    'scripts/windows/launch-ghidra-fixed.cmd',
    WEB_SCHEMA_PATH,
    'schemas/page-session-adapter.schema.json',
    'schemas/frida-trace-plan.schema.json',
    CONTRACT_SCHEMA_PATH,
    'schemas/generated-native-connector.schema.json',
    'schemas/generated-connector-manifest.schema.json',
    REVERSE_SCHEMA_PATH,
    'docs/reverse-engineering.md',
    'docs/adr/0026-reverse-engineering-and-protocol-reconstruction.md',
    'browser/http-authed-chrome/README.md',
    'integrations/burp-montoya/README.md',
    'integrations/burp-montoya/MANIFEST.MF',
    'integrations/burp-montoya/build.ps1',
    'integrations/burp-montoya/verify.ps1',
    'integrations/burp-montoya/src/main/java/dev/lastaperture/burp/LastApertureBurpExtension.java',
    'integrations/burp-montoya/test/extension.test.mjs',
    'skills/last-aperture/references/reverse-engineering.md',
  ]) {
    assert.equal(existsSync(path), true, `${path} must ship`)
    assert.ok(readFileSync(path).length > 0, `${path} must not be empty`)
  }

  const packageDocument = JSON.parse(readFileSync('package.json', 'utf8'))
  assert.equal(packageDocument.bin['last-aperture-reverse'], './scripts/reverse.mjs')
  assert.equal(packageDocument.version, '0.13.0')
  assert.ok(packageDocument.files.includes('integrations/'))
  assert.ok(packageDocument.files.includes('!docs/superpowers/'))
  assert.ok(packageDocument.files.includes('!**/.gradle/'))
  assert.ok(packageDocument.files.includes('!scripts/audit.mjs.bak_diag'))
  assert.equal(packageDocument.scripts['audit:reverse'], 'node scripts/reverse.mjs')
  assert.match(packageDocument.scripts['test:reverse'], /page-session-adapter\.test\.mjs/)
  assert.match(packageDocument.scripts['test:reverse'], /burp-montoya\/test\/extension\.test\.mjs/)

  const help = spawnSync(process.execPath, ['scripts/reverse.mjs', '--help'], {
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  })
  assert.equal(help.status, 0, help.stderr)
  for (const route of ['web import-har', 'web import-burp', 'protocol build', 'protocol generate', 'protocol verify', 'ghidra analyze', 'frida trace', 'frida trace-plan']) {
    assert.match(help.stdout, new RegExp(route.replace(' ', '\\s+')))
  }
  assert.match(help.stdout, /accept local artifacts and captures/i)
  assert.match(help.stdout, /never accept raw tool arguments/i)
})

test('release pack excludes local and nested build artifacts and retains compatibility fixtures', async () => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-pack-'))
  try {
    const configuredNpm = process.env.npm_execpath
    const windowsNpm = join(
      dirname(process.execPath),
      'node_modules',
      'npm',
      'bin',
      'npm-cli.js',
    )
    const npmCli = typeof configuredNpm === 'string' && existsSync(configuredNpm)
      ? configuredNpm
      : (process.platform === 'win32' ? windowsNpm : null)
    const packArguments = ['pack', '--dry-run', '--json', '--cache', join(root, 'npm-cache')]
    const packed = spawnSync(
      npmCli === null ? 'npm' : process.execPath,
      npmCli === null ? packArguments : [npmCli, ...packArguments],
      {
        encoding: 'utf8',
        shell: false,
        windowsHide: true,
        maxBuffer: 4 * 1024 * 1024,
      },
    )
    assert.equal(packed.error, undefined, packed.error?.stack)
    assert.equal(packed.status, 0, packed.stderr)
    const report = JSON.parse(packed.stdout)
    assert.equal(Array.isArray(report), true)
    assert.equal(report.length, 1)
    const paths = report[0].files.map((item) => item.path.replaceAll('\\', '/'))
    for (const forbidden of [
      /^docs\/superpowers(?:\/|$)/u,
      /(?:^|\/)\.gradle(?:\/|$)/u,
      /(?:^|\/)\.audit-runs(?:\/|$)/u,
      /(?:^|\/)scratchpad(?:\/|$)/u,
      /(?:^|\/)_tmp_[^/]*$/u,
      /(?:^|\/)validate_tmp\.mjs$/u,
      /\.bak_diag$/u,
    ]) {
      assert.equal(paths.some((path) => forbidden.test(path)), false, forbidden.source)
    }
    for (const required of [
      'SECURITY.md',
      'browser/http-authed-chrome/README.md',
      'integrations/burp-montoya/README.md',
      'schemas/page-session-adapter.schema.json',
      'scripts/ghidra/GhidraBundleLocationAgent.java.source',
      'scripts/lib/reverse-v1-compat-semantics.mjs',
      'scripts/lib/reverse-web-burp.mjs',
      'test/fixtures/compat/0.12/native-interaction-contract-1.0.0-retired-auth-semantics.json',
      'test/fixtures/compat/0.12/web-session-evidence-1.0.0-expanded-cookie-carrier.json',
      'test/fixtures/compat/0.12/web-session-evidence-1.0.0-retired-cookie-carrier.json',
    ]) {
      assert.equal(paths.includes(required), true, `${required} must be packed`)
    }
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('reverse capabilities and the canonical skill expose only the implemented narrow routes', () => {
  const byId = new Map(CAPABILITY_REGISTRY.capabilities.map((item) => [item.id, item]))
  assert.deepEqual(byId.get('ghidra-static-reverse')?.commands, ['last-aperture-reverse ghidra analyze'])
  assert.deepEqual(byId.get('frida-local-reverse')?.commands, ['last-aperture-reverse frida trace'])
  assert.deepEqual(byId.get('frida-typed-reverse')?.commands, ['last-aperture-reverse frida trace-plan'])
  assert.deepEqual(byId.get('web-protocol-reconstruction')?.commands, [
    'last-aperture-reverse web import-har',
    'last-aperture-reverse web import-burp',
    'last-aperture-reverse protocol build',
    'last-aperture-reverse protocol generate',
    'last-aperture-reverse protocol verify',
  ])
  assert.deepEqual(byId.get('burp-proxy-history-export')?.commands, ['integrations/burp-montoya/build.ps1'])
  for (const id of ['ghidra-static-reverse', 'frida-local-reverse', 'frida-typed-reverse', 'web-protocol-reconstruction', 'burp-proxy-history-export']) {
    assert.equal(byId.get(id)?.status, 'AVAILABLE_NARROW')
  }
  assert.match(byId.get('web-protocol-reconstruction').limitation, /GENERATED_REVIEWABLE/i)
  assert.match(byId.get('web-protocol-reconstruction').limitation, /externally retained manifest digest/i)
  assert.equal(byId.get('browser-execution')?.status, 'AVAILABLE_NARROW')
  assert.match(byId.get('browser-execution').description, /Web Storage session-to-header adapter/i)
  assert.match(byId.get('frida-typed-reverse').limitation, /PARTIAL.*local artifact copy/i)

  const skill = readFileSync('skills/last-aperture/SKILL.md', 'utf8')
  assert.ok(Buffer.byteLength(skill, 'utf8') <= 8000)
  assert.match(skill, /references\/reverse-engineering\.md/)
  const reference = readFileSync('skills/last-aperture/references/reverse-engineering.md', 'utf8')
  assert.match(reference, /DRAFT_OBSERVED/)
  assert.match(reference, /GENERATED_REVIEWABLE/)
  assert.match(reference, /security_verdict: NOT_ASSESSED/)
  assert.match(reference, /remain outside the\s+repository audit evidence bundle/i)
})

test('published web and native contract schemas validate generated documents and refuse widened claims', () => {
  const { webEvidence, contract } = observedDocuments()
  const web = schemaValidator(WEB_SCHEMA_PATH)
  const native = schemaValidator(CONTRACT_SCHEMA_PATH)

  assert.equal(web.validate(webEvidence), true, web.ajv.errorsText(web.validate.errors))
  assert.equal(native.validate(contract), true, native.ajv.errorsText(native.validate.errors))

  for (const [validator, value, mutate] of [
    [web.validate, webEvidence, (copy) => { copy.security_verdict = 'PASSED' }],
    [web.validate, webEvidence, (copy) => { copy.applied_to_audit_bundle = true }],
    [web.validate, webEvidence, (copy) => { copy.entries[0].request.body.fields[0].value = 'secret' }],
    [native.validate, contract, (copy) => { copy.status = 'READY' }],
    [native.validate, contract, (copy) => { copy.generated_client_status = 'GENERATED' }],
    [native.validate, contract, (copy) => { copy.security_verdict = 'PASSED' }],
    [native.validate, contract, (copy) => { copy.endpoints[0].request.extra = true }],
    [native.validate, contract, (copy) => { copy.endpoints[0].exchanges[0].response.extra = true }],
  ]) {
    const changed = structuredClone(value)
    mutate(changed)
    assert.equal(validator(changed), false)
  }

  assert.equal(web.schema.properties.security_verdict.const, 'NOT_ASSESSED')
  assert.equal(web.schema.properties.applied_to_audit_bundle.const, false)
  assert.equal(native.schema.properties.status.const, 'DRAFT_OBSERVED')
  assert.equal(native.schema.properties.generated_client_status.const, 'CONTRACT_ONLY')
  assert.equal(native.schema.properties.security_verdict.const, 'NOT_ASSESSED')
})

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function minimalGhidraExport(executableSha256) {
  return {
    schema_version: '1.0.0',
    kind: 'red-team-audit/ghidra-static-export',
    profile_id: 'ghidra-headless-fixed-export-v1',
    analysis_status: 'OBSERVATIONS_ONLY',
    target_execution: 'NOT_PERFORMED',
    program: {
      executable_format: 'Portable Executable (PE)',
      executable_sha256: executableSha256,
      language_id: 'x86:LE:64:default',
      compiler_spec_id: 'windows',
      image_base: '140000000',
      minimum_address: '140001000',
      maximum_address: '140001000',
    },
    functions: [],
    network_imports: [],
    endpoint_observations: [],
    auth_hints: [],
    coverage: {
      function_limit: 20000,
      available_functions: 0,
      emitted_functions: 0,
      truncated: false,
    },
    protocol_coverage: {
      network_import_limit: 512,
      references_per_import_limit: 128,
      external_functions_scanned: 0,
      matching_network_imports: 0,
      emitted_network_imports: 0,
      external_function_scan_truncated: false,
      network_imports_truncated: false,
      string_record_limit: 100000,
      string_records_scanned: 0,
      string_values_scanned: 0,
      truncated_string_values: 0,
      string_scan_truncated: false,
      endpoint_limit: 512,
      endpoint_candidates: 0,
      emitted_endpoints: 0,
      endpoints_truncated: false,
      auth_hint_limit: 512,
      auth_hint_candidates: 0,
      emitted_auth_hints: 0,
      auth_hints_truncated: false,
    },
  }
}

test('published reverse schema validates representative Ghidra and Frida controller evidence', async () => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-schema-'))
  const labRoot = join(root, 'lab')
  const binaryBytes = Buffer.from('fixed schema fixture')
  await mkdir(join(labRoot, 'bin'), { recursive: true })
  await writeFile(join(labRoot, 'bin', 'demo.exe'), binaryBytes)
  const ghidraPath = join(root, 'analyzeHeadless.exe')
  const fridaPath = join(root, 'frida.exe')
  await writeFile(ghidraPath, 'fixture')
  await writeFile(fridaPath, 'fixture')

  try {
    const ghidraOut = join(root, 'ghidra-evidence')
    await analyzeGhidraArtifact({
      labRoot,
      binary: 'bin/demo.exe',
      artifactKind: 'native-executable',
      ghidraPath,
      outPath: ghidraOut,
      now: () => new Date('2026-09-11T12:00:00.000Z'),
      runGhidra: async (options) => {
        const scriptIndex = options.args.indexOf('LastApertureExport.java')
        await writeFile(
          options.args[scriptIndex + 1],
          JSON.stringify(minimalGhidraExport(sha256(binaryBytes))),
          'utf8',
        )
        return {
          profile_id: 'ghidra-headless-fixed-export-v1',
          code: 0,
          signal: null,
          timed_out: false,
          output_limit_exceeded: false,
          spawn_error: false,
          termination_confirmed: true,
          duration_ms: 1,
          stdout: Buffer.alloc(0),
          stderr: Buffer.alloc(0),
        }
      },
    })

    const fridaOut = join(root, 'frida-evidence')
    await traceFridaArtifact({
      labRoot,
      binary: 'bin/demo.exe',
      fridaPath,
      moduleName: '<main>',
      symbolName: 'parse_packet',
      outPath: fridaOut,
      now: () => new Date('2026-09-11T12:00:00.000Z'),
      runFrida: async (options) => {
        const parameterIndex = options.args.indexOf('-P')
        const { frameNonce } = JSON.parse(options.args[parameterIndex + 1])
        return {
          profile_id: 'native-call-trace-v1',
          ready: true,
          complete: true,
          trace_events: 0,
          truncated: false,
          ignored_lines: 0,
          observation_window_ms: { start: 1, end: 2 },
          events: [
            {
              schema_version: '1.0.0',
              profile_id: 'native-call-trace-v1',
              frame_nonce: frameNonce,
              observed_at_ms: 1,
              event: 'ready',
              module_name: '<main>',
              symbol_name: 'parse_packet',
              module_relative_offset: '0x1000',
            },
            {
              schema_version: '1.0.0',
              profile_id: 'native-call-trace-v1',
              frame_nonce: frameNonce,
              observed_at_ms: 2,
              event: 'complete',
              events_emitted: 0,
              truncated: false,
            },
          ],
          process_exit_code: 0,
          stderr_bytes: 0,
        }
      },
    })

    const documents = [
      JSON.parse(await readFile(join(ghidraOut, 'evidence.json'), 'utf8')),
      JSON.parse(await readFile(join(fridaOut, 'evidence.json'), 'utf8')),
    ]
    const reverse = schemaValidator(REVERSE_SCHEMA_PATH)
    for (const document of documents) {
      assert.equal(reverse.validate(document), true, reverse.ajv.errorsText(reverse.validate.errors))
      const widened = structuredClone(document)
      widened.observations[0].raw_values = ['secret']
      assert.equal(reverse.validate(widened), false)
    }
    assert.equal(reverse.schema.properties.security_verdict.const, 'NOT_ASSESSED')
    assert.equal(reverse.schema.properties.applied_to_audit_bundle.const, false)
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})
