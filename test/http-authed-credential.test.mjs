import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import { mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { test } from 'node:test'

import { main } from '../scripts/http-authed.mjs'
import {
  HTTP_AUTHED_STDIN_CREDENTIAL_REF,
  MAX_HTTP_AUTHED_CREDENTIAL_BYTES,
  readHttpAuthedCredentialFromStdin,
  resolveHttpAuthedCredential,
} from '../scripts/lib/http-authed-credential.mjs'
import {
  readAndVerifyHttpAuthedWrittenAuthorization,
  sha256Hex,
  verifyHttpAuthedWrittenAuthorization,
} from '../scripts/lib/http-authed-contracts.mjs'
import {
  AUTHORIZATION_DOCUMENT,
  writtenScope,
} from './helpers/http-authed-fixtures.mjs'

const NOW = new Date('2026-08-17T10:00:00.000Z')
const EXECUTION_NOW = new Date('2026-08-16T12:00:00.000Z')
const COOKIE = ' session=SYNTHETIC_SECRET_COOKIE; tenant=bug-bounty '

function redirectedInput(chunks) {
  const stream = Readable.from(chunks.map((chunk) => Buffer.from(chunk)))
  Object.defineProperty(stream, 'isTTY', { value: false })
  return stream
}

function terminalInput() {
  const stream = Readable.from([])
  Object.defineProperty(stream, 'isTTY', { value: true })
  return stream
}

async function rejectsSafely(promise, code, secret = COOKIE) {
  await assert.rejects(promise, (error) => {
    assert.equal(error.code, code)
    assert.equal(error.message.includes(secret), false)
    return true
  })
}

async function plannerFixture(t) {
  const directory = await mkdtemp(join(tmpdir(), 'http-authed-credential-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const authorizationDocumentPath = join(directory, 'authorization.txt')
  const scopePath = join(directory, 'scope.json')
  await writeFile(authorizationDocumentPath, AUTHORIZATION_DOCUMENT)
  return { directory, authorizationDocumentPath, scopePath }
}

async function executionFixture(t, scope, name) {
  const directory = await mkdtemp(join(tmpdir(), `http-authed-${name}-`))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const scopePath = join(directory, 'scope.json')
  const authorizationDocumentPath = join(directory, 'authorization.txt')
  const candidatePath = join(directory, 'candidate.json')
  const candidate = scope.requests[0]
  const verified = verifyHttpAuthedWrittenAuthorization({
    scope,
    documentBytes: AUTHORIZATION_DOCUMENT,
    now: EXECUTION_NOW,
  })
  await writeFile(scopePath, JSON.stringify(scope), 'utf8')
  await writeFile(authorizationDocumentPath, AUTHORIZATION_DOCUMENT)
  await writeFile(candidatePath, JSON.stringify(candidate), 'utf8')
  return {
    directory,
    scopePath,
    authorizationDocumentPath,
    candidatePath,
    campaignGrantSha256: verified.campaignGrantSha256,
  }
}

function executableCookieScope({
  ref = HTTP_AUTHED_STDIN_CREDENTIAL_REF,
  binding = sha256Hex(Buffer.from(COOKIE, 'ascii')),
  discovery = false,
} = {}) {
  const scope = writtenScope({ actionCount: 1 })
  scope.limits.min_interval_ms = 0
  scope.credential = { ref, kind: 'cookie', binding_sha256: binding }
  scope.authorization.authorized_scope.path_prefixes = ['/approved']
  scope.liveness.credential_preflight.url = `${scope.target.origin}/approved/whoami`
  scope.requests = [{
    kind: 'probe',
    sequence: 1,
    test_category: 'api_security',
    method: 'GET',
    url: `${scope.target.origin}/approved/seed`,
    expected_effect: 'none',
  }]
  if (discovery) {
    scope.discovery = {
      enabled: true,
      origin: scope.target.origin,
      path_prefixes: ['/approved'],
      sources: ['location_header'],
      candidate_methods: ['GET'],
      test_category: 'api_security',
      synthetic_query_values: {},
      synthetic_path_values: {},
      max_response_bytes: scope.limits.max_response_bytes,
    }
  }
  return scope
}

function probeArguments(files, scope, { credentialStdin = true } = {}) {
  return [
    'probe-written',
    '--scope', files.scopePath,
    '--authorization-document', files.authorizationDocumentPath,
    '--candidate', files.candidatePath,
    '--campaign-grant-sha256', files.campaignGrantSha256,
    '--operator-id', scope.authorization.operator_id,
    '--confirm-authorization-current',
    ...(credentialStdin ? ['--credential-stdin'] : []),
    '--json',
  ]
}

// Used wherever the test injects its own clock. Fixed on purpose: a
// deterministic test is worth more than a uniform one.
const SEALED_WINDOW = {
  documentIssuedAt: '2026-08-01T00:00:00.000Z',
  notBefore: '2026-08-17T09:00:00.000Z',
  notAfter: '2026-08-18T09:00:00.000Z',
}

// For the one test that spawns the real CLI. That process reads the ambient
// clock, so it cannot be pointed at a fixed window -- the sealed window has to
// contain whenever the test happens to run, which a fixed one stops doing the
// day after it was written. The contract requires only
// not_before <= attested_at < not_after, so a window straddling the present
// satisfies it on any day.
function relativeValidityWindow(reference = new Date()) {
  const HOUR = 60 * 60 * 1000
  const at = (offsetMs) => new Date(reference.getTime() + offsetMs).toISOString()
  return {
    documentIssuedAt: at(-30 * 24 * HOUR),
    notBefore: at(-HOUR),
    notAfter: at(22 * HOUR),
  }
}

function stdinPlannerArguments({ authorizationDocumentPath, scopePath }, window = SEALED_WINDOW) {
  return [
    'plan-written',
    '--scope', scopePath,
    '--authorization-document', authorizationDocumentPath,
    '--engagement-id', 'generic-vendor-cookie-campaign',
    '--authorization-id', 'vendor-program-2026',
    '--operator-id', 'security-researcher',
    '--authorized-by', 'Vendor security team',
    '--authorization-reference', 'Vendor bug bounty authorization 2026',
    '--document-issuer', 'Vendor security team',
    '--document-issued-at', window.documentIssuedAt,
    '--not-before', window.notBefore,
    '--not-after', window.notAfter,
    '--target-origin', 'https://bounty.example.test',
    '--environment', 'production',
    '--data-class', 'unknown',
    '--ownership', 'third_party_owned',
    '--credential-stdin',
    '--credential-kind', 'cookie',
    '--path-prefix', '/',
    '--method', 'GET',
    '--test-category', 'api_security',
    '--seed-url', 'https://bounty.example.test/security/start',
    '--json',
  ]
}

test('redirected credential stdin removes one line ending and otherwise preserves exact bytes', async () => {
  const expected = Buffer.from(COOKIE, 'ascii')
  const actual = await readHttpAuthedCredentialFromStdin(redirectedInput([
    expected.subarray(0, 11),
    expected.subarray(11),
    Buffer.from('\r\n'),
  ]))

  assert.deepEqual(actual, expected)
  assert.equal(actual.toString('ascii').startsWith(' '), true)
  assert.equal(actual.toString('ascii').endsWith(' '), true)

  await rejectsSafely(
    readHttpAuthedCredentialFromStdin(redirectedInput([`${COOKIE}\r\n\r\n`])),
    'HTTP_AUTHED_CREDENTIAL_CHARACTERS_INVALID',
  )
})

test('redirected credential stdin accepts the byte limit and refuses TTY, empty, and oversized input', async () => {
  const maximum = Buffer.alloc(MAX_HTTP_AUTHED_CREDENTIAL_BYTES, 0x41)
  const accepted = await readHttpAuthedCredentialFromStdin(redirectedInput([
    maximum,
    Buffer.from('\r\n'),
  ]))
  assert.equal(accepted.length, MAX_HTTP_AUTHED_CREDENTIAL_BYTES)
  assert.deepEqual(accepted, maximum)

  await rejectsSafely(
    readHttpAuthedCredentialFromStdin(terminalInput()),
    'HTTP_AUTHED_CREDENTIAL_STDIN_TTY_REFUSED',
  )
  await rejectsSafely(
    readHttpAuthedCredentialFromStdin(redirectedInput([Buffer.from('\r\n')])),
    'HTTP_AUTHED_CREDENTIAL_LENGTH_INVALID',
  )
  await rejectsSafely(
    readHttpAuthedCredentialFromStdin(redirectedInput([
      Buffer.alloc(MAX_HTTP_AUTHED_CREDENTIAL_BYTES + 1, 0x41),
      Buffer.from('\r\n'),
    ])),
    'HTTP_AUTHED_CREDENTIAL_LENGTH_INVALID',
  )
})

test('redirected credential stdin refuses controls and a copied Cookie header name without echoing it', async () => {
  for (const input of [
    `session=SYNTHETIC_SECRET_COOKIE\u0000; tenant=x\r\n`,
    `session=SYNTHETIC_SECRET_COOKIE\t; tenant=x\r\n`,
    `session=SYNTHETIC_SECRET_COOKIE\r\ntenant=x\r\n`,
  ]) {
    await rejectsSafely(
      readHttpAuthedCredentialFromStdin(redirectedInput([input])),
      'HTTP_AUTHED_CREDENTIAL_CHARACTERS_INVALID',
      'SYNTHETIC_SECRET_COOKIE',
    )
  }

  for (const prefix of ['Cookie:', ' cookie :']) {
    await rejectsSafely(
      readHttpAuthedCredentialFromStdin(redirectedInput([
        `${prefix} SYNTHETIC_SECRET_COOKIE\r\n`,
      ])),
      'HTTP_AUTHED_CREDENTIAL_HEADER_PREFIX_REFUSED',
      'SYNTHETIC_SECRET_COOKIE',
    )
  }
})

test('shared credential resolver returns exact env and redirected-stdin bytes', async () => {
  const binding = sha256Hex(Buffer.from(COOKIE, 'ascii'))
  const fromEnvironment = await resolveHttpAuthedCredential({
    credential: {
      ref: 'env:VENDOR_COOKIE',
      kind: 'cookie',
      binding_sha256: binding,
    },
    env: { VENDOR_COOKIE: COOKIE },
  })
  assert.deepEqual(fromEnvironment, Buffer.from(COOKIE, 'ascii'))

  const fromStdin = await resolveHttpAuthedCredential({
    credential: {
      ref: HTTP_AUTHED_STDIN_CREDENTIAL_REF,
      kind: 'cookie',
      binding_sha256: binding,
    },
    credentialInput: redirectedInput([COOKIE, '\r\n']),
  })
  assert.deepEqual(fromStdin, Buffer.from(COOKIE, 'ascii'))
})

test('shared credential resolver refuses unavailable, mixed, and reference-mismatched sources', async () => {
  const binding = sha256Hex(Buffer.from(COOKIE, 'ascii'))
  const envCredential = {
    ref: 'env:VENDOR_COOKIE',
    kind: 'cookie',
    binding_sha256: binding,
  }
  const stdinCredential = {
    ref: HTTP_AUTHED_STDIN_CREDENTIAL_REF,
    kind: 'cookie',
    binding_sha256: binding,
  }

  await rejectsSafely(
    resolveHttpAuthedCredential({ credential: envCredential, env: {} }),
    'HTTP_AUTHED_CREDENTIAL_UNAVAILABLE',
  )
  await rejectsSafely(
    resolveHttpAuthedCredential({ credential: stdinCredential }),
    'HTTP_AUTHED_CREDENTIAL_UNAVAILABLE',
  )
  await rejectsSafely(
    resolveHttpAuthedCredential({
      credential: envCredential,
      env: { VENDOR_COOKIE: COOKIE },
      transientCredential: Buffer.from(COOKIE),
    }),
    'HTTP_AUTHED_CREDENTIAL_SOURCE_MISMATCH',
  )
  await rejectsSafely(
    resolveHttpAuthedCredential({
      credential: stdinCredential,
      transientCredential: Buffer.from(COOKIE),
      credentialInput: redirectedInput([COOKIE]),
    }),
    'HTTP_AUTHED_CREDENTIAL_SOURCE_AMBIGUOUS',
  )
})

test('credential binding drift is rejected before a caller can dispatch network traffic', async () => {
  let transportCalls = 0
  const supplied = 'session=SYNTHETIC_DRIFTED_COOKIE'

  async function resolveThenDispatch() {
    const bytes = await resolveHttpAuthedCredential({
      credential: {
        ref: HTTP_AUTHED_STDIN_CREDENTIAL_REF,
        kind: 'cookie',
        binding_sha256: sha256Hex(Buffer.from(COOKIE, 'ascii')),
      },
      transientCredential: Buffer.from(supplied, 'ascii'),
    })
    transportCalls += 1
    bytes.fill(0)
  }

  await rejectsSafely(
    resolveThenDispatch(),
    'HTTP_AUTHED_CREDENTIAL_BINDING_MISMATCH',
    supplied,
  )
  assert.equal(transportCalls, 0)
})

test('plan-written binds one explicitly piped cookie without network or secret persistence', async (t) => {
  const files = await plannerFixture(t)
  let output = ''
  let transportCalls = 0

  await main(stdinPlannerArguments(files), {
    clock: () => NOW,
    env: {},
    credentialInput: redirectedInput([COOKIE, '\r\n']),
    transport: async () => {
      transportCalls += 1
      throw new Error('offline planning must not dispatch network traffic')
    },
    write: (text) => { output += text },
  })

  assert.equal(transportCalls, 0)
  const scopeText = await readFile(files.scopePath, 'utf8')
  const scope = JSON.parse(scopeText)
  assert.deepEqual(Object.keys(scope.credential).sort(), [
    'binding_sha256',
    'kind',
    'ref',
  ])
  assert.deepEqual(scope.credential, {
    ref: HTTP_AUTHED_STDIN_CREDENTIAL_REF,
    kind: 'cookie',
    binding_sha256: sha256Hex(Buffer.from(COOKIE, 'ascii')),
  })
  assert.equal(scopeText.includes(COOKIE), false)
  assert.equal(output.includes(COOKIE), false)
  assert.equal(scopeText.includes(AUTHORIZATION_DOCUMENT.toString('utf8')), false)

  const verified = await readAndVerifyHttpAuthedWrittenAuthorization({
    scopePath: files.scopePath,
    authorizationDocumentPath: files.authorizationDocumentPath,
    now: NOW,
  })
  assert.deepEqual(verified.scope.credential, scope.credential)
})

test('the real CLI consumes redirected credential stdin without exposing it', async (t) => {
  const files = await plannerFixture(t)
  const execution = spawnSync(
    process.execPath,
    [
      join(process.cwd(), 'scripts', 'http-authed.mjs'),
      // The spawned CLI stamps attested_at from its own clock, so the window
      // must be relative to now rather than to the day this test was written.
      ...stdinPlannerArguments(files, relativeValidityWindow()),
    ],
    {
      cwd: process.cwd(),
      input: `${COOKIE}\r\n`,
      encoding: 'utf8',
      shell: false,
      windowsHide: true,
    },
  )

  assert.equal(execution.status, 0, execution.stderr)
  assert.equal(execution.stdout.includes('SYNTHETIC_SECRET_COOKIE'), false)
  assert.equal(execution.stderr.includes('SYNTHETIC_SECRET_COOKIE'), false)
  const scopeText = await readFile(files.scopePath, 'utf8')
  assert.equal(scopeText.includes('SYNTHETIC_SECRET_COOKIE'), false)
  assert.equal(JSON.parse(scopeText).credential.ref, HTTP_AUTHED_STDIN_CREDENTIAL_REF)
})

test('plan-written requires exactly one environment or stdin credential source', async (t) => {
  const files = await plannerFixture(t)
  let credentialReads = 0
  const both = stdinPlannerArguments(files)
  both.splice(both.indexOf('--credential-stdin'), 0, '--credential-env', 'VENDOR_COOKIE')

  await assert.rejects(
    main(both, {
      clock: () => NOW,
      env: { VENDOR_COOKIE: COOKIE },
      credentialInput: redirectedInput([COOKIE, '\r\n']),
      credentialStdinReader: async () => {
        credentialReads += 1
        return Buffer.from(COOKIE, 'ascii')
      },
      write: () => {},
    }),
    /exactly one.*credential-env.*credential-stdin/i,
  )
  await assert.rejects(readFile(files.scopePath), { code: 'ENOENT' })

  const neitherFiles = {
    ...files,
    scopePath: join(files.directory, 'neither-scope.json'),
  }
  const neither = stdinPlannerArguments(neitherFiles)
    .filter((value) => value !== '--credential-stdin')
  await assert.rejects(
    main(neither, {
      clock: () => NOW,
      env: {},
      write: () => {},
    }),
    /exactly one.*credential-env.*credential-stdin/i,
  )
  await assert.rejects(readFile(neitherFiles.scopePath), { code: 'ENOENT' })
  assert.equal(credentialReads, 0)
})

test('probe-written sends the exact stdin-bound Cookie value through one injected reader', async (t) => {
  const scope = executableCookieScope()
  const files = await executionFixture(t, scope, 'stdin-probe')
  const credentialInput = Symbol('synthetic redirected credential input')
  let credentialReads = 0
  let transportCalls = 0
  let output = ''

  await main(probeArguments(files, scope), {
    clock: () => EXECUTION_NOW,
    env: {},
    credentialInput,
    credentialStdinReader: async (input) => {
      assert.equal(input, credentialInput)
      credentialReads += 1
      return Buffer.from(COOKIE, 'ascii')
    },
    transport: async (request) => {
      await request.beforeSend()
      transportCalls += 1
      assert.equal(request.headers.cookie, COOKIE)
      assert.equal(request.headers.authorization, undefined)
      return { status: 200, responseBytes: 0, responseHeaderNames: ['set-cookie'] }
    },
    write: (text) => { output += text },
  })

  assert.equal(credentialReads, 1)
  assert.equal(transportCalls, 1)
  assert.equal(JSON.parse(output).response.status, 200)
  assert.equal(output.includes('SYNTHETIC_SECRET_COOKIE'), false)
})

test('probe-written rejects a drifted stdin credential binding before transport', async (t) => {
  const scope = executableCookieScope({
    binding: sha256Hex(Buffer.from('session=SEALED_DIFFERENT_COOKIE', 'ascii')),
  })
  const files = await executionFixture(t, scope, 'stdin-probe-drift')
  let credentialReads = 0
  let transportCalls = 0
  let output = ''

  await rejectsSafely(
    main(probeArguments(files, scope), {
      clock: () => EXECUTION_NOW,
      env: {},
      credentialInput: Symbol('synthetic redirected credential input'),
      credentialStdinReader: async () => {
        credentialReads += 1
        return Buffer.from(COOKIE, 'ascii')
      },
      transport: async () => { transportCalls += 1 },
      write: (text) => { output += text },
    }),
    'HTTP_AUTHED_CREDENTIAL_BINDING_MISMATCH',
    'SYNTHETIC_SECRET_COOKIE',
  )

  assert.equal(credentialReads, 1)
  assert.equal(transportCalls, 0)
  assert.equal(output.includes('SYNTHETIC_SECRET_COOKIE'), false)
})

test('probe-written refuses CLI credential input that does not match the sealed scope reference', async (t) => {
  let credentialReads = 0
  let transportCalls = 0

  const stdinScope = executableCookieScope()
  const stdinFiles = await executionFixture(t, stdinScope, 'missing-stdin-flag')
  await rejectsSafely(
    main(probeArguments(stdinFiles, stdinScope, { credentialStdin: false }), {
      clock: () => EXECUTION_NOW,
      env: {},
      credentialInput: Symbol('must not be forwarded without the CLI flag'),
      credentialStdinReader: async () => {
        credentialReads += 1
        return Buffer.from(COOKIE, 'ascii')
      },
      transport: async () => { transportCalls += 1 },
      write: () => {},
    }),
    'HTTP_AUTHED_CREDENTIAL_UNAVAILABLE',
  )

  const envScope = executableCookieScope({ ref: 'env:VENDOR_COOKIE' })
  const envFiles = await executionFixture(t, envScope, 'stdin-flag-env-scope')
  await rejectsSafely(
    main(probeArguments(envFiles, envScope), {
      clock: () => EXECUTION_NOW,
      env: { VENDOR_COOKIE: COOKIE },
      credentialInput: Symbol('stdin must conflict with an env-bound scope'),
      credentialStdinReader: async () => {
        credentialReads += 1
        return Buffer.from(COOKIE, 'ascii')
      },
      transport: async () => { transportCalls += 1 },
      write: () => {},
    }),
    'HTTP_AUTHED_CREDENTIAL_SOURCE_MISMATCH',
  )

  assert.equal(credentialReads, 0)
  assert.equal(transportCalls, 0)
})

test('campaign-written reads stdin once for seed and discovery and never journals the credential', async (t) => {
  const scope = executableCookieScope({ discovery: true })
  const files = await executionFixture(t, scope, 'stdin-campaign')
  const ledgerDirectory = join(files.directory, 'ledger')
  const credentialInput = Symbol('single redirected campaign credential')
  const responseSentinel = 'SYNTHETIC_TRANSIENT_RESPONSE_SENTINEL'
  let credentialReads = 0
  const sentCookies = []
  let output = ''

  await main([
    'campaign-written',
    '--scope', files.scopePath,
    '--authorization-document', files.authorizationDocumentPath,
    '--campaign-grant-sha256', files.campaignGrantSha256,
    '--ledger', ledgerDirectory,
    '--operator-id', scope.authorization.operator_id,
    '--confirm-authorization-current',
    '--credential-stdin',
    '--json',
  ], {
    clock: () => EXECUTION_NOW,
    env: {},
    credentialInput,
    credentialStdinReader: async (input) => {
      assert.equal(input, credentialInput)
      credentialReads += 1
      return Buffer.from(COOKIE, 'ascii')
    },
    transport: async (request) => {
      await request.beforeSend()
      sentCookies.push(request.headers.cookie)
      assert.equal(request.headers.authorization, undefined)
      if (sentCookies.length === 1) {
        await request.responseObserver?.({
          status: 200,
          headers: [{ name: 'location', value: '/approved/discovered' }],
          bodyChunks: [Buffer.from(responseSentinel)],
        })
      } else {
        await request.responseObserver?.({ status: 200, headers: [], bodyChunks: [] })
      }
      return {
        status: 200,
        responseBytes: 0,
        responseHeaderNames: ['location', 'set-cookie'],
      }
    },
    write: (text) => { output += text },
  })

  assert.equal(credentialReads, 1)
  assert.deepEqual(sentCookies, [COOKIE, COOKIE])
  const result = JSON.parse(output)
  assert.equal(result.actions.completed, 2)
  assert.equal(result.actions.discovered, 1)
  assert.equal(output.includes('SYNTHETIC_SECRET_COOKIE'), false)
  assert.equal(output.includes(responseSentinel), false)

  const ledgerEntries = await readdir(ledgerDirectory, { withFileTypes: true })
  const ledgerText = (await Promise.all(
    ledgerEntries
      .filter((entry) => entry.isFile())
      .map((entry) => readFile(join(ledgerDirectory, entry.name), 'utf8')),
  )).join('\n')
  assert.equal(ledgerText.includes('SYNTHETIC_SECRET_COOKIE'), false)
  assert.equal(ledgerText.includes(responseSentinel), false)
})

test('stdin bearer and cookie campaigns retain only bounded JSON shape metadata', async (t) => {
  const responseValue = 'SYNTHETIC_CLINICAL_RESPONSE_VALUE_MUST_NOT_PERSIST'
  for (const kind of ['bearer', 'cookie']) {
    const credential = kind === 'bearer'
      ? 'SYNTHETIC_BEARER_TOKEN'
      : 'session=SYNTHETIC_COOKIE_TOKEN'
    const scope = executableCookieScope({
      binding: sha256Hex(Buffer.from(credential, 'ascii')),
    })
    scope.credential.kind = kind
    scope.schema_version = '1.1.0'
    scope.response_observation = {
      mode: 'JSON_SHAPE_ONLY',
      max_depth: 4,
      safe_key_names: ['client_id', 'display_name', 'records'],
    }
    const files = await executionFixture(t, scope, `stdin-json-shape-${kind}`)
    const ledgerDirectory = join(files.directory, 'ledger')
    let credentialReads = 0
    let output = ''

    await main([
      'campaign-written',
      '--scope', files.scopePath,
      '--authorization-document', files.authorizationDocumentPath,
      '--campaign-grant-sha256', files.campaignGrantSha256,
      '--ledger', ledgerDirectory,
      '--operator-id', scope.authorization.operator_id,
      '--confirm-authorization-current',
      '--credential-stdin',
      '--json',
    ], {
      clock: () => EXECUTION_NOW,
      env: {},
      credentialInput: Symbol(`redirected-${kind}-credential`),
      credentialStdinReader: async () => {
        credentialReads += 1
        return Buffer.from(credential, 'ascii')
      },
      transport: async (request) => {
        await request.beforeSend()
        assert.equal(
          kind === 'bearer' ? request.headers.authorization : request.headers.cookie,
          kind === 'bearer' ? `Bearer ${credential}` : credential,
        )
        await request.responseObserver({
          status: 200,
          headers: [{ name: 'content-type', value: 'application/json' }],
          bodyChunks: [Buffer.from(JSON.stringify({
            records: [{ client_id: 8675309, display_name: responseValue }],
          }))],
        })
        return {
          status: 200,
          responseBytes: 128,
          responseHeaderNames: ['content-type', 'set-cookie'],
        }
      },
      write: (text) => { output += text },
    })

    assert.equal(credentialReads, 1)
    const result = JSON.parse(output)
    assert.equal(result.json_shapes.length, 1)
    assert.deepEqual(result.json_shapes[0].json_shape.key_names, [
      'client_id',
      'display_name',
      'records',
    ])
    assert.equal(output.includes(responseValue), false)
    assert.equal(output.includes('8675309'), false)
    assert.equal(output.includes(credential), false)

    const ledgerEntries = await readdir(ledgerDirectory, { withFileTypes: true })
    const ledgerText = (await Promise.all(
      ledgerEntries
        .filter((entry) => entry.isFile())
        .map((entry) => readFile(join(ledgerDirectory, entry.name), 'utf8')),
    )).join('\n')
    assert.match(ledgerText, /http-authed-json-shape/)
    assert.match(ledgerText, /client_id/)
    assert.equal(ledgerText.includes(responseValue), false)
    assert.equal(ledgerText.includes('8675309'), false)
    assert.equal(ledgerText.includes(credential), false)
  }
})

test('stdin campaign persists only projected ASP.NET d shape metadata', async (t) => {
  const responseValue = 'SYNTHETIC_ASMX_CLINICAL_VALUE_MUST_NOT_PERSIST'
  const scope = executableCookieScope()
  scope.schema_version = '1.2.0'
  scope.response_observation = {
    mode: 'ASPNET_D_JSON_SHAPE_ONLY',
    max_depth: 4,
    safe_key_names: ['client_id', 'display_name', 'records'],
  }
  const files = await executionFixture(t, scope, 'stdin-aspnet-d-json-shape')
  const ledgerDirectory = join(files.directory, 'ledger')
  let output = ''

  await main([
    'campaign-written',
    '--scope', files.scopePath,
    '--authorization-document', files.authorizationDocumentPath,
    '--campaign-grant-sha256', files.campaignGrantSha256,
    '--ledger', ledgerDirectory,
    '--operator-id', scope.authorization.operator_id,
    '--confirm-authorization-current',
    '--credential-stdin',
    '--json',
  ], {
    clock: () => EXECUTION_NOW,
    env: {},
    credentialInput: Symbol('redirected-aspnet-d-credential'),
    credentialStdinReader: async () => Buffer.from(COOKIE, 'ascii'),
    transport: async (request) => {
      await request.beforeSend()
      await request.responseObserver({
        status: 200,
        headers: [{ name: 'content-type', value: 'application/json' }],
        bodyChunks: [Buffer.from(JSON.stringify({
          d: JSON.stringify({
            records: [{ client_id: 8675309, display_name: responseValue }],
          }),
        }))],
      })
      return {
        status: 200,
        responseBytes: 160,
        responseHeaderNames: ['content-type'],
      }
    },
    write: (text) => { output += text },
  })

  const result = JSON.parse(output)
  assert.equal(result.schema_version, '1.2.0')
  assert.equal(result.json_shapes.length, 1)
  assert.equal(
    result.json_shapes[0].json_shape.projection,
    'ASPNET_D_JSON_STRING',
  )
  assert.equal(output.includes(responseValue), false)
  assert.equal(output.includes('8675309'), false)

  const ledgerEntries = await readdir(ledgerDirectory, { withFileTypes: true })
  const ledgerText = (await Promise.all(
    ledgerEntries
      .filter((entry) => entry.isFile())
      .map((entry) => readFile(join(ledgerDirectory, entry.name), 'utf8')),
  )).join('\n')
  assert.match(ledgerText, /ASPNET_D_JSON_STRING/)
  assert.equal(ledgerText.includes(responseValue), false)
  assert.equal(ledgerText.includes('8675309'), false)
})

test('malformed claimed JSON settles an stdin campaign as a bounded observation failure', async (t) => {
  const marker = 'SYNTHETIC_MALFORMED_JSON_MUST_NOT_PERSIST'
  const scope = executableCookieScope()
  scope.schema_version = '1.1.0'
  scope.response_observation = {
    mode: 'JSON_SHAPE_ONLY',
    max_depth: 4,
    safe_key_names: ['value'],
  }
  const files = await executionFixture(t, scope, 'stdin-json-shape-malformed')
  const ledgerDirectory = join(files.directory, 'ledger')
  let output = ''

  await main([
    'campaign-written',
    '--scope', files.scopePath,
    '--authorization-document', files.authorizationDocumentPath,
    '--campaign-grant-sha256', files.campaignGrantSha256,
    '--ledger', ledgerDirectory,
    '--operator-id', scope.authorization.operator_id,
    '--confirm-authorization-current',
    '--credential-stdin',
    '--json',
  ], {
    clock: () => EXECUTION_NOW,
    env: {},
    credentialInput: Symbol('redirected-malformed-json-credential'),
    credentialStdinReader: async () => Buffer.from(COOKIE, 'ascii'),
    transport: async (request) => {
      await request.beforeSend()
      await request.responseObserver({
        status: 200,
        headers: [{ name: 'content-type', value: 'application/json' }],
        bodyChunks: [Buffer.from(`{"value":"${marker}"`)],
      })
      return {
        status: 200,
        responseBytes: 700,
        responseHeaderNames: ['content-type', 'x-synthetic-subject-8675309'],
      }
    },
    write: (text) => { output += text },
  })

  const result = JSON.parse(output)
  assert.equal(result.schema_version, '1.3.0')
  assert.equal(result.actions.failed, 1)
  assert.equal(result.actions.uncertain, 0)
  assert.equal(result.ledger.stopped, false)
  assert.equal(result.json_shapes.length, 0)
  assert.deepEqual(result.observation_failures, [{
    action_sequence: 1,
    method: 'GET',
    status: 200,
    header_names: ['content-type', 'other'],
    response_byte_bucket: 'LE_1_KIB',
    failure_stage_code: 'JSON_SHAPE_OBSERVATION',
  }])
  assert.equal(output.includes(marker), false)
  assert.equal(output.includes('8675309'), false)
  const ledgerEntries = await readdir(ledgerDirectory, { withFileTypes: true })
  const ledgerTexts = await Promise.all(
    ledgerEntries
      .filter((entry) => entry.isFile())
      .map((entry) => readFile(join(ledgerDirectory, entry.name), 'utf8')),
  )
  const ledgerText = ledgerTexts.join('\n')
  assert.equal(ledgerText.includes(marker), false)
  assert.equal(ledgerText.includes('8675309'), false)
  assert.match(ledgerText, /PROBE_OBSERVATION_FAILED/)
  const failureRecord = ledgerTexts
    .map((text) => JSON.parse(text))
    .find(({ event }) => event.failure_stage_code === 'JSON_SHAPE_OBSERVATION')
  assert.equal(Object.hasOwn(failureRecord.event, 'bytes'), false)
})
