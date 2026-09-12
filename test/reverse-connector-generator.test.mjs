import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { createServer } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { test } from 'node:test'

import Ajv2020 from 'ajv/dist/2020.js'

import { SENSITIVE_HEADERS } from '../scripts/lib/bounty-authz-request.mjs'
import {
  assertValidGeneratedConnectorManifest,
  buildGeneratedConnectorDescriptor,
  generateNativeConnectorPackage,
  verifyGeneratedConnectorPackage,
} from '../scripts/lib/reverse-connector-generator.mjs'
import { buildNativeInteractionContract } from '../scripts/lib/reverse-protocol.mjs'
import { importWebHarEvidence } from '../scripts/lib/reverse-web-har.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'

function rebindContractId(contract) {
  const { contract_id: ignored, ...material } = contract
  contract.contract_id = `interaction:${createHash('sha256').update(stableJson(material, 0)).digest('hex').slice(0, 32)}`
}

function entry({ method, url, requestHeaders = [], requestCookies = [], postData, status, responseHeaders = [], responseCookies = [], content }) {
  return {
    startedDateTime: '2026-09-11T12:00:00.000Z',
    time: 5,
    request: { method, url, headers: requestHeaders, cookies: requestCookies, ...(postData ? { postData } : {}) },
    response: { status, headers: responseHeaders, cookies: responseCookies, content: content ?? { mimeType: 'application/json', text: '{}' } },
  }
}

function observedContract(origin = 'https://portal.example', { redirectQuery = false } = {}) {
  const homeSuffix = redirectQuery ? '/Home?token=synthetic-transition' : '/Home'
  const har = {
    log: {
      entries: [
        entry({
          method: 'POST',
          url: `${origin}/login`,
          requestHeaders: [
            { name: 'Content-Type', value: 'application/x-www-form-urlencoded' },
            { name: 'X-Client-Mode', value: 'native' },
          ],
          postData: {
            mimeType: 'application/x-www-form-urlencoded',
            params: [
              { name: 'UserName', value: 'synthetic-user' },
              { name: 'Password', value: 'synthetic-password' },
            ],
          },
          status: 302,
          responseHeaders: [
            { name: 'Location', value: homeSuffix },
            { name: 'Set-Cookie', value: 'SessionCookie=synthetic-cookie; Path=/; HttpOnly' },
          ],
          responseCookies: [{ name: 'SessionCookie', value: 'synthetic-cookie' }],
        }),
        entry({
          method: 'GET',
          url: `${origin}${homeSuffix}`,
          requestCookies: [{ name: 'SessionCookie', value: 'synthetic-cookie' }],
          status: 200,
          responseHeaders: [{ name: 'Authorization', value: 'Bearer synthetic-response' }],
          content: { mimeType: 'application/json', text: '{"ready":true}' },
        }),
        entry({
          method: 'GET',
          url: `${origin}/api/items/123?limit=1&view=read`,
          requestHeaders: [{ name: 'Authorization', value: 'Bearer synthetic' }],
          requestCookies: [{ name: 'SessionCookie', value: 'synthetic-cookie' }],
          status: 500,
          content: { mimeType: 'application/json', text: '{"error":"busy"}' },
        }),
        entry({
          method: 'GET',
          url: `${origin}/api/items/123?limit=1&view=read`,
          requestHeaders: [{ name: 'Authorization', value: 'Bearer synthetic' }],
          requestCookies: [{ name: 'SessionCookie', value: 'synthetic-cookie' }],
          status: 200,
          content: { mimeType: 'application/json', text: '{"items":[]}' },
        }),
      ],
    },
  }
  const evidence = importWebHarEvidence(har, {
    sourceSha256: 'a'.repeat(64),
    targetOrigins: [origin],
    pathLiterals: ['api', 'Home', 'items', 'login'],
  })
  return buildNativeInteractionContract({
    webSessionEvidence: [evidence],
    reverseEvidence: [],
    generatedAt: '2026-09-11T12:01:00.000Z',
  })
}

function redirectContract({
  origin = 'https://portal.example',
  observedStatus = 302,
  destinationSource = 'LOCATION_HEADER',
  destination = '/next',
} = {}) {
  const absoluteDestination = new URL(destination, origin).href
  const responseHeaders = destinationSource === 'LOCATION_HEADER'
    ? [{ name: 'Location', value: destination }]
    : []
  const content = destinationSource === 'RESPONSE_BODY_FIELD'
    ? { mimeType: 'application/json', text: JSON.stringify({ redirectUrl: absoluteDestination }) }
    : { mimeType: 'application/json', text: '{}' }
  const evidence = importWebHarEvidence({ log: { entries: [
    entry({ method: 'GET', url: `${origin}/start`, status: observedStatus, responseHeaders, content }),
    entry({ method: 'GET', url: absoluteDestination, status: 200 }),
  ] } }, {
    sourceSha256: 'd'.repeat(64),
    targetOrigins: [origin],
    pathLiterals: ['next', 'start'],
  })
  return buildNativeInteractionContract({
    webSessionEvidence: [evidence],
    reverseEvidence: [],
    generatedAt: '2026-09-11T12:01:00.000Z',
  })
}

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-connector-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const contract = observedContract()
  const contractPath = join(root, 'contract.json')
  await writeFile(contractPath, JSON.stringify(contract), 'utf8')
  return { root, contract, contractPath }
}

async function observeZeroedByteCopies(source, operation) {
  const expected = [...source]
  const clearedCopies = []
  const originalFill = Uint8Array.prototype.fill
  const originalApply = Reflect.apply
  try {
    Reflect.apply = function trackedApply(target, receiver, args) {
      const matches = target === originalFill
        && args?.[0] === 0
        && receiver?.length === expected.length
        && expected.every((byte, index) => receiver[index] === byte)
      const result = originalApply(target, receiver, args)
      if (matches) clearedCopies.push(receiver)
      return result
    }
    await operation()
  } finally {
    Reflect.apply = originalApply
  }
  return clearedCopies
}

test('generator emits a deterministic, schema-valid, digest-bound connector without network I/O', async (t) => {
  const { root, contract, contractPath } = await fixture(t)
  const first = join(root, 'one')
  const second = join(root, 'two')
  const originalFetch = globalThis.fetch
  globalThis.fetch = async () => { throw new Error('generation attempted network I/O') }
  let firstResult
  try {
    firstResult = await generateNativeConnectorPackage({ contractPath, outPath: first, packageName: '@example/portal-native' })
    await generateNativeConnectorPackage({ contractPath, outPath: second, packageName: '@example/portal-native' })
  } finally {
    globalThis.fetch = originalFetch
  }

  assert.equal(firstResult.status, 'SUCCEEDED')
  assert.equal(firstResult.contract_id, contract.contract_id)
  assert.equal(firstResult.endpoints, contract.endpoints.length)
  const manifest = JSON.parse(await readFile(join(first, 'manifest.json'), 'utf8'))
  assert.equal(assertValidGeneratedConnectorManifest(manifest), manifest)
  assert.equal(manifest.generation_status, 'GENERATED_REVIEWABLE')
  assert.equal(manifest.runtime_mode, 'CONTRACT_BOUND')
  assert.equal(manifest.network_during_generation, 'NONE')
  const verification = await verifyGeneratedConnectorPackage({
    packagePath: first,
    expectedManifestSha256: firstResult.digest,
  })
  assert.equal(verification.status, 'SUCCEEDED')
  assert.equal(verification.files_verified, 5)
  assert.equal(verification.contract_id, contract.contract_id)
  const descriptor = JSON.parse(await readFile(join(first, 'connector.json'), 'utf8'))
  assert.equal(descriptor.status, 'GENERATED_REVIEWABLE')
  assert.equal(descriptor.source_contract.contract_id, contract.contract_id)
  assert.equal(descriptor.source_contract.schema_version, '1.1.0')
  assert.equal(JSON.stringify(descriptor).includes('CONTRACT_ONLY'), false)

  for (const path of ['README.md', 'connector.json', 'index.mjs', 'manifest.json', 'package.json']) {
    assert.deepEqual(await readFile(join(first, path)), await readFile(join(second, path)))
  }

  const ajv = new Ajv2020({ strict: true, strictTuples: false, allErrors: true, allowUnionTypes: true })
  ajv.addSchema(JSON.parse(readFileSync('schemas/native-interaction-contract.schema.json', 'utf8')))
  const validateDescriptor = ajv.compile(JSON.parse(readFileSync('schemas/generated-native-connector.schema.json', 'utf8')))
  const validateManifest = ajv.compile(JSON.parse(readFileSync('schemas/generated-connector-manifest.schema.json', 'utf8')))
  assert.equal(validateDescriptor(descriptor), true, ajv.errorsText(validateDescriptor.errors))
  assert.equal(validateManifest(manifest), true, ajv.errorsText(validateManifest.errors))

  const incompleteCurrent = structuredClone(descriptor)
  delete incompleteCurrent.endpoints[0].discovered_via
  delete incompleteCurrent.endpoints[0].exchanges[0].provenance
  assert.equal(validateDescriptor(incompleteCurrent), false)

  const legacyDescriptor = structuredClone(descriptor)
  legacyDescriptor.source_contract.schema_version = '1.0.0'
  for (const endpoint of legacyDescriptor.endpoints) {
    for (const exchange of endpoint.exchanges) delete exchange.provenance
    assert.deepEqual(endpoint.discovered_via, ['WEB_HAR'])
  }
  assert.equal(validateDescriptor(legacyDescriptor), true, ajv.errorsText(validateDescriptor.errors))

  await assert.rejects(
    generateNativeConnectorPackage({ contractPath, outPath: first }),
    (error) => error?.code === 'CONNECTOR_OUTPUT_EXISTS',
  )
})

test('generator accepts and imports an authentic 1.0 contract with historical auth classification', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-legacy-connector-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const contract = JSON.parse(readFileSync(new URL(
    './fixtures/compat/0.12/native-interaction-contract-1.0.0-retired-auth-semantics.json',
    import.meta.url,
  ), 'utf8'))
  const contractPath = join(root, 'contract.json')
  const out = join(root, 'generated')
  await writeFile(contractPath, JSON.stringify(contract), 'utf8')

  const generated = await generateNativeConnectorPackage({
    contractPath,
    outPath: out,
    packageName: 'legacy-auth-connector',
  })
  assert.equal(generated.status, 'SUCCEEDED')
  assert.equal(generated.contract_id, contract.contract_id)

  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=legacy-auth`)
  assert.equal(runtime.metadata.source_contract.schema_version, '1.0.0')
  assert.equal(runtime.metadata.source_contract.contract_id, contract.contract_id)
  assert.equal(runtime.metadata.endpoints[0].protocol_role, 'AUTH')
  assert.equal(runtime.authFlows[0].steps[0].request_action, 'AUTH_REQUEST')
  assert.deepEqual(runtime.endpointIds, [contract.endpoints[0].endpoint_id])

  const generic = JSON.parse(readFileSync(new URL(
    './fixtures/compat/0.12/native-interaction-contract-1.0.0.json',
    import.meta.url,
  ), 'utf8'))
  const semanticForgeries = [
    (changed) => {
      changed.endpoints[0].exchanges[0].request.action = 'AUTH_REQUEST'
      changed.endpoints[0].exchanges[0].request.action_basis = 'INFERRED_PATH'
    },
    (changed) => {
      changed.endpoints[0].protocol_role = 'AUTH'
      changed.endpoints[0].side_effect = { basis: 'AUTH_FLOW', classification: 'UNKNOWN' }
    },
    (changed) => {
      changed.endpoints[0].protocol_role = 'AUTH'
      changed.endpoints[0].side_effect = { basis: 'AUTH_FLOW', classification: 'UNKNOWN' }
      changed.endpoints[0].exchanges[0].request.action = 'AUTH_REQUEST'
      changed.endpoints[0].exchanges[0].request.action_basis = 'INFERRED_PATH'
    },
  ]
  for (const [index, forge] of semanticForgeries.entries()) {
    const changed = structuredClone(generic)
    forge(changed)
    rebindContractId(changed)
    const changedPath = join(root, `forged-${index}.json`)
    await writeFile(changedPath, JSON.stringify(changed), 'utf8')
    await assert.rejects(
      generateNativeConnectorPackage({
        contractPath: changedPath,
        outPath: join(root, `forged-${index}`),
        packageName: `forged-${index}`,
      }),
      (error) => error?.code === 'CONNECTOR_CONTRACT_INVALID',
    )
  }
})

test('generated connector executes only contract endpoints with auth metadata, volatile credentials, cookies, redirects, and observed retries', async (t) => {
  const { root, contractPath } = await fixture(t)
  const out = join(root, 'generated')
  await generateNativeConnectorPackage({ contractPath, outPath: out, packageName: 'portal-native' })
  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=runtime`)
  const endpoints = runtime.metadata.endpoints
  const login = endpoints.find((item) => item.path_template === '/login')
  const home = endpoints.find((item) => item.path_template === '/Home')
  const items = endpoints.find((item) => item.path_template.includes('/api/items/'))
  assert.ok(login && home && items)
  assert.equal(items.retry, 'RETRY_SEQUENCE_OBSERVED')
  assert.ok(runtime.authFlows.length > 0)

  const calls = []
  let itemAttempts = 0
  const credentialContexts = []
  const connector = runtime.createConnector({
    credentialProvider: async (context) => {
      credentialContexts.push(context)
      if (context.endpointId === login.endpoint_id) {
        return { body: { UserName: 'alice@example.test', Password: 'do-not-persist' } }
      }
      if (context.endpointId === items.endpoint_id) {
        return { headers: { authorization: 'Bearer do-not-persist' } }
      }
      return {}
    },
    fetchImpl: async (url, init) => {
      calls.push({ url: url.toString(), method: init.method, headers: { ...init.headers }, body: init.body })
      if (url.pathname === '/login') {
        assert.equal(init.method, 'POST')
        assert.match(String(init.body), /UserName=alice%40example\.test/)
        return new Response(null, {
          status: 302,
          headers: { location: '/Home', 'set-cookie': 'SessionCookie=runtime-only; Path=/; HttpOnly' },
        })
      }
      if (url.pathname === '/Home') {
        assert.match(init.headers.cookie, /SessionCookie=runtime-only/)
        return new Response('{"ready":true}', {
          status: 200,
          headers: { authorization: 'Bearer response-do-not-return', 'content-type': 'application/json' },
        })
      }
      if (url.pathname.startsWith('/api/items/')) {
        itemAttempts += 1
        assert.equal(url.pathname, '/api/items/456')
        assert.equal(url.search, '?limit=2&view=read')
        assert.equal(init.headers.authorization, 'Bearer do-not-persist')
        assert.match(init.headers.cookie, /SessionCookie=runtime-only/)
        return new Response(itemAttempts === 1 ? '{"error":"busy"}' : '{"items":[{"id":456}]}', {
          status: itemAttempts === 1 ? 500 : 200,
          headers: { 'content-type': 'application/json' },
        })
      }
      throw new Error('unexpected target')
    },
  })

  const loginResult = await connector.request(login.endpoint_id, { headers: { 'x-client-mode': 'native' } })
  assert.equal(loginResult.endpointId, home.endpoint_id)
  assert.equal(loginResult.redirects, 1)
  assert.deepEqual(loginResult.data, { ready: true })
  assert.equal(Object.hasOwn(loginResult, 'url'), false)
  assert.equal(loginResult.origin, 'https://portal.example')
  assert.equal(loginResult.pathTemplate, '/Home')
  assert.equal(loginResult.headers.authorization, undefined)
  const itemsResult = await connector.request(items.endpoint_id, { path: { integer: 456 }, query: { limit: 2, view: 'read' } })
  assert.equal(itemsResult.status, 200)
  assert.equal(itemsResult.retries, 1)
  assert.equal(itemsResult.attempts, 2)
  assert.deepEqual(itemsResult.data, { items: [{ id: 456 }] })
  assert.equal(calls.length, 4)
  assert.equal(credentialContexts.every((item) => Object.isFrozen(item)), true)

  const generatedText = (await Promise.all(
    ['README.md', 'connector.json', 'index.mjs', 'manifest.json', 'package.json'].map((path) => readFile(join(out, path), 'utf8')),
  )).join('\n')
  assert.doesNotMatch(generatedText, /do-not-persist|alice@example\.test|runtime-only/)
  connector.clearCookies()

  const before = calls.length
  await assert.rejects(
    connector.request('endpoint:00000000000000000000000000000000'),
    (error) => error?.code === 'CONNECTOR_ENDPOINT_REFUSED',
  )
  await assert.rejects(
    connector.request(items.endpoint_id, { path: { integer: 1 }, query: { arbitrary: 'value' } }),
    (error) => error?.code === 'CONNECTOR_INPUT_INVALID',
  )
  assert.equal(calls.length, before)
})

test('generated runtime detects file drift relative to its bundled manifest', async (t) => {
  const { root, contractPath } = await fixture(t)
  const out = join(root, 'tampered')
  await generateNativeConnectorPackage({ contractPath, outPath: out })
  const descriptorPath = join(out, 'connector.json')
  await writeFile(descriptorPath, `${await readFile(descriptorPath, 'utf8')} `, 'utf8')
  await assert.rejects(
    import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=tampered`),
    (error) => error?.code === 'CONNECTOR_PACKAGE_INVALID',
  )
})

test('trusted verifier requires the external manifest anchor and exact generated inventory', async (t) => {
  const { root, contractPath } = await fixture(t)
  const out = join(root, 'externally-anchored')
  const generated = await generateNativeConnectorPackage({ contractPath, outPath: out })

  await assert.rejects(
    verifyGeneratedConnectorPackage({ packagePath: out, expectedManifestSha256: 'not-a-digest' }),
    (error) => error?.code === 'CONNECTOR_MANIFEST_DIGEST_INVALID',
  )
  const extra = join(out, 'unexpected.js')
  await writeFile(extra, 'export default true\n', 'utf8')
  await assert.rejects(
    verifyGeneratedConnectorPackage({ packagePath: out, expectedManifestSha256: generated.digest }),
    (error) => error?.code === 'CONNECTOR_PACKAGE_INVALID',
  )
  await rm(extra)
  await writeFile(join(out, 'connector.json'), '{}', 'utf8')
  await assert.rejects(
    verifyGeneratedConnectorPackage({ packagePath: out, expectedManifestSha256: generated.digest }),
    (error) => error?.code === 'CONNECTOR_PACKAGE_DIGEST_MISMATCH',
  )

  const second = join(root, 'rewritten-manifest')
  const secondGenerated = await generateNativeConnectorPackage({ contractPath, outPath: second })
  await writeFile(join(second, 'manifest.json'), `${await readFile(join(second, 'manifest.json'), 'utf8')} `, 'utf8')
  await assert.rejects(
    verifyGeneratedConnectorPackage({ packagePath: second, expectedManifestSha256: secondGenerated.digest }),
    (error) => error?.code === 'CONNECTOR_MANIFEST_DIGEST_MISMATCH',
  )
})

test('generated runtime enforces observed path, query, body, header, and cookie shapes', async (t) => {
  const { root, contractPath } = await fixture(t)
  const out = join(root, 'shape-enforcement')
  await generateNativeConnectorPackage({ contractPath, outPath: out, packageName: 'shape-enforcement' })
  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=shape-enforcement`)
  const login = runtime.metadata.endpoints.find((item) => item.path_template === '/login')
  const items = runtime.metadata.endpoints.find((item) => item.path_template.includes('/api/items/'))
  const noFetch = async () => { throw new Error('invalid input reached transport') }
  const connector = runtime.createConnector({ fetchImpl: noFetch })

  await assert.rejects(
    connector.request(items.endpoint_id, { path: { integer: 'delete-all' }, query: { limit: 1, view: 'read' } }),
    (error) => error?.code === 'CONNECTOR_INPUT_INVALID' && /observed type/.test(error.message),
  )
  await assert.rejects(
    connector.request(items.endpoint_id, { path: { integer: 123 }, query: { limit: 'many', view: 'read' } }),
    (error) => error?.code === 'CONNECTOR_INPUT_INVALID' && /observed type/.test(error.message),
  )
  await assert.rejects(
    connector.request(login.endpoint_id, { body: { UserName: 7 } }),
    (error) => error?.code === 'CONNECTOR_INPUT_INVALID' && /observed type/.test(error.message),
  )
  await assert.rejects(
    connector.request(login.endpoint_id, { headers: { authorization: 'Bearer bypass' } }),
    (error) => error?.code === 'CONNECTOR_INPUT_INVALID',
  )
  await assert.rejects(
    connector.request(login.endpoint_id, { headers: { 'x-http-method-override': 'DELETE' } }),
    (error) => error?.code === 'CONNECTOR_INPUT_INVALID',
  )

  const injectedCookie = runtime.createConnector({
    credentialProvider: async () => ({ cookies: { SessionCookie: 'safe; Injected=1' } }),
    fetchImpl: noFetch,
  })
  await assert.rejects(
    injectedCookie.request(items.endpoint_id, { path: { integer: 123 }, query: { limit: 1, view: 'read' } }),
    (error) => error?.code === 'CONNECTOR_INPUT_INVALID',
  )

  for (const emptyCredentialBody of [[], ['secret'], {}]) {
    const emptyCarrierBypass = runtime.createConnector({
      credentialProvider: async () => ({ body: emptyCredentialBody }),
      fetchImpl: noFetch,
    })
    await assert.rejects(
      emptyCarrierBypass.request(login.endpoint_id),
      (error) => error?.code === 'CONNECTOR_CREDENTIAL_INVALID',
    )
  }

  const undeclaredCredentialBody = runtime.createConnector({
    credentialProvider: async () => ({ body: { Password: 'secret' } }),
    fetchImpl: noFetch,
  })
  await assert.rejects(
    undeclaredCredentialBody.request(items.endpoint_id, { path: { integer: 123 }, query: { limit: 1, view: 'read' } }),
    (error) => error?.code === 'CONNECTOR_CREDENTIAL_INVALID',
  )
})

test('generated runtime erases nested credential byte clones when a later nested byte value is invalid', async (t) => {
  const { root, contractPath } = await fixture(t)
  const out = join(root, 'invalid-nested-credential-bytes')
  await generateNativeConnectorPackage({
    contractPath,
    outPath: out,
    packageName: 'invalid-nested-credential-bytes',
  })
  const runtime = await import(
    `${pathToFileURL(join(out, 'index.mjs')).href}?case=invalid-nested-credential-bytes`,
  )
  const login = runtime.metadata.endpoints.find((item) => item.path_template === '/login')
  const credentialBytes = new TextEncoder().encode('nested-credential-secret')
  const expectedBytes = [...credentialBytes]
  const oversizedBytes = new Uint8Array((1024 * 1024) + 1)
  let fetchCalls = 0
  const connector = runtime.createConnector({
    credentialProvider: async () => ({
      body: { Password: [credentialBytes, oversizedBytes] },
    }),
    fetchImpl: async () => {
      fetchCalls += 1
      return new Response(null, { status: 204 })
    },
  })

  const clearedCopies = await observeZeroedByteCopies(credentialBytes, async () => {
    await assert.rejects(
      connector.request(login.endpoint_id),
      (error) => error?.code === 'CONNECTOR_INPUT_INVALID'
        && error.request_may_have_been_sent === false,
    )
  })
  assert.equal(fetchCalls, 0)
  assert.deepEqual([...credentialBytes], expectedBytes)
  assert.equal(clearedCopies.some((bytes) => bytes !== credentialBytes
    && bytes.every((byte) => byte === 0)), true)
})

test('generated runtime erases partial nested caller byte clones when later cloning fails', async (t) => {
  const { root, contractPath } = await fixture(t)
  const out = join(root, 'partial-nested-caller-clone')
  await generateNativeConnectorPackage({
    contractPath,
    outPath: out,
    packageName: 'partial-nested-caller-clone',
  })
  const runtime = await import(
    `${pathToFileURL(join(out, 'index.mjs')).href}?case=partial-nested-caller-clone`,
  )
  const login = runtime.metadata.endpoints.find((item) => item.path_template === '/login')
  const callerBytes = new TextEncoder().encode('nested-caller-secret')
  const expectedBytes = [...callerBytes]
  let fetchCalls = 0
  const connector = runtime.createConnector({
    fetchImpl: async () => {
      fetchCalls += 1
      return new Response(null, { status: 204 })
    },
  })

  const clearedCopies = await observeZeroedByteCopies(callerBytes, async () => {
    await assert.rejects(
      connector.request(login.endpoint_id, {
        body: {
          UserName: callerBytes,
          Password: new Date('2026-09-12T00:00:00.000Z'),
        },
      }),
      (error) => error?.code === 'CONNECTOR_INPUT_INVALID'
        && error.request_may_have_been_sent === false,
    )
  })
  assert.equal(fetchCalls, 0)
  assert.deepEqual([...callerBytes], expectedBytes)
  assert.equal(clearedCopies.some((bytes) => bytes !== callerBytes
    && bytes.every((byte) => byte === 0)), true)
})

test('generated runtime keeps the timeout active while reading the response body', async (t) => {
  const { root, contractPath } = await fixture(t)
  const out = join(root, 'response-timeout')
  await generateNativeConnectorPackage({ contractPath, outPath: out, packageName: 'response-timeout' })
  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=response-timeout`)
  const home = runtime.metadata.endpoints.find((item) => item.path_template === '/Home')
  const connector = runtime.createConnector({
    fetchImpl: async (_url, init) => new Response(new ReadableStream({
      start(controller) {
        init.signal.addEventListener('abort', () => controller.error(init.signal.reason), { once: true })
      },
    }), { status: 200, headers: { 'content-type': 'application/json' } }),
  })
  const originalClearTimeout = globalThis.clearTimeout
  globalThis.clearTimeout = () => { throw new Error('synthetic timer cleanup failure') }
  try {
    await assert.rejects(
      connector.request(home.endpoint_id, { timeoutMs: 20 }),
      (error) => error?.code === 'CONNECTOR_TIMEOUT'
        && error.request_may_have_been_sent === true,
    )
  } finally {
    globalThis.clearTimeout = originalClearTimeout
  }
})

test('generated runtime clears its internal outgoing byte body after transport settles', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-request-bytes-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const origin = 'https://portal.example'
  const evidence = importWebHarEvidence({ log: { entries: [entry({
    method: 'POST',
    url: `${origin}/upload`,
    postData: {
      mimeType: 'application/octet-stream',
      text: 'synthetic-request-body',
    },
    status: 204,
    content: { mimeType: 'application/octet-stream', text: '' },
  })] } }, {
    sourceSha256: '9'.repeat(64),
    targetOrigins: [origin],
    pathLiterals: ['upload'],
  })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [evidence],
    reverseEvidence: [],
    generatedAt: '2026-09-11T12:01:00.000Z',
  })
  const contractPath = join(root, 'contract.json')
  const out = join(root, 'request-byte-zeroization')
  await writeFile(contractPath, JSON.stringify(contract), 'utf8')
  await generateNativeConnectorPackage({
    contractPath,
    outPath: out,
    packageName: 'request-byte-zeroization',
  })
  const runtime = await import(
    `${pathToFileURL(join(out, 'index.mjs')).href}?case=request-byte-zeroization`,
  )
  const upload = runtime.metadata.endpoints.find((item) => item.path_template === '/upload')
  const callerBytes = new TextEncoder().encode('caller-request-secret')
  const expectedBytes = [...callerBytes]
  let transportBytes
  const connector = runtime.createConnector({
    fetchImpl: async (_url, init) => {
      transportBytes = init.body
      assert.ok(transportBytes instanceof Uint8Array)
      assert.notEqual(transportBytes, callerBytes)
      assert.deepEqual([...transportBytes], expectedBytes)
      return new Response(null, { status: 204 })
    },
  })

  const originalSetTimeout = globalThis.setTimeout
  const originalClearTimeout = globalThis.clearTimeout
  globalThis.setTimeout = () => Symbol('synthetic-timer')
  globalThis.clearTimeout = () => { throw new Error('synthetic timer cleanup failure') }
  try {
    const result = await connector.request(upload.endpoint_id, {
      body: callerBytes,
      contentType: 'application/octet-stream',
    })
    assert.equal(result.status, 204)
  } finally {
    globalThis.setTimeout = originalSetTimeout
    globalThis.clearTimeout = originalClearTimeout
  }
  assert.deepEqual([...callerBytes], expectedBytes)
  assert.deepEqual([...transportBytes], Array(transportBytes.length).fill(0))
})

test('generated runtime clears its internal outgoing byte body when timer setup fails', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-request-timer-setup-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const origin = 'https://portal.example'
  const evidence = importWebHarEvidence({ log: { entries: [entry({
    method: 'POST',
    url: `${origin}/upload`,
    postData: {
      mimeType: 'application/octet-stream',
      text: 'synthetic-request-body',
    },
    status: 204,
    content: { mimeType: 'application/octet-stream', text: '' },
  })] } }, {
    sourceSha256: '9'.repeat(64),
    targetOrigins: [origin],
    pathLiterals: ['upload'],
  })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [evidence],
    reverseEvidence: [],
    generatedAt: '2026-09-11T12:01:00.000Z',
  })
  const contractPath = join(root, 'contract.json')
  const out = join(root, 'generated')
  await writeFile(contractPath, JSON.stringify(contract), 'utf8')
  await generateNativeConnectorPackage({ contractPath, outPath: out, packageName: 'timer-setup-failure' })
  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=timer-setup-failure`)
  const upload = runtime.metadata.endpoints.find((item) => item.path_template === '/upload')
  const callerBytes = new TextEncoder().encode('caller-request-secret')
  const expectedBytes = [...callerBytes]
  const clearedCopies = []
  let fetchCalls = 0
  const connector = runtime.createConnector({
    fetchImpl: async () => {
      fetchCalls += 1
      return new Response(null, { status: 204 })
    },
  })

  const originalFill = Uint8Array.prototype.fill
  const originalApply = Reflect.apply
  const originalSetTimeout = globalThis.setTimeout
  let requestPromise
  try {
    Reflect.apply = function trackedApply(target, receiver, args) {
      const before = receiver instanceof Uint8Array ? [...receiver] : []
      const result = originalApply(target, receiver, args)
      if (target === originalFill && args?.[0] === 0 && before.length === expectedBytes.length
        && before.every((byte, index) => byte === expectedBytes[index])) {
        clearedCopies.push(receiver)
      }
      return result
    }
    globalThis.setTimeout = () => { throw new Error('synthetic timer setup failure') }
    requestPromise = connector.request(upload.endpoint_id, {
      body: callerBytes,
      contentType: 'application/octet-stream',
    })
  } finally {
    globalThis.setTimeout = originalSetTimeout
    Reflect.apply = originalApply
  }

  await assert.rejects(
    requestPromise,
    (error) => error?.code === 'CONNECTOR_TIMER_FAILED'
      && error.request_may_have_been_sent === false
      && !String(error.message).includes('synthetic'),
  )
  assert.equal(fetchCalls, 0)
  assert.deepEqual([...callerBytes], expectedBytes)
  assert.equal(clearedCopies.some((bytes) => bytes !== callerBytes
    && bytes.every((byte) => byte === 0)), true)
})

test('generated runtime types a pre-dispatch clock failure and erases its raw body clone', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-request-clock-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const origin = 'https://portal.example'
  const evidence = importWebHarEvidence({ log: { entries: [entry({
    method: 'POST',
    url: `${origin}/upload`,
    postData: {
      mimeType: 'application/octet-stream',
      text: 'synthetic-request-body',
    },
    status: 204,
    content: { mimeType: 'application/octet-stream', text: '' },
  })] } }, {
    sourceSha256: '9'.repeat(64),
    targetOrigins: [origin],
    pathLiterals: ['upload'],
  })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [evidence],
    reverseEvidence: [],
    generatedAt: '2026-09-11T12:01:00.000Z',
  })
  const contractPath = join(root, 'contract.json')
  const out = join(root, 'generated')
  await writeFile(contractPath, JSON.stringify(contract), 'utf8')
  await generateNativeConnectorPackage({
    contractPath,
    outPath: out,
    packageName: 'clock-failure-cleanup',
  })
  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=clock-failure-cleanup`)
  const upload = runtime.metadata.endpoints.find((item) => item.path_template === '/upload')
  const callerBytes = new TextEncoder().encode('caller-clock-secret')
  const expectedBytes = [...callerBytes]
  let fetchCalls = 0
  const connector = runtime.createConnector({
    fetchImpl: async () => {
      fetchCalls += 1
      return new Response(null, { status: 204 })
    },
  })
  t.mock.method(globalThis.performance, 'now', () => {
    throw new Error('synthetic monotonic clock failure')
  })

  const clearedCopies = await observeZeroedByteCopies(callerBytes, async () => {
    await assert.rejects(
      connector.request(upload.endpoint_id, {
        body: callerBytes,
        contentType: 'application/octet-stream',
      }),
      (error) => error?.code === 'CONNECTOR_PREPARATION_FAILED'
        && error.request_may_have_been_sent === false
        && !String(error.message).includes('synthetic'),
    )
  })
  assert.equal(fetchCalls, 0)
  assert.deepEqual([...callerBytes], expectedBytes)
  assert.equal(clearedCopies.some((bytes) => bytes !== callerBytes
    && bytes.every((byte) => byte === 0)), true)
})

test('generated runtime cancels a hostile response reader and clears retained bytes on timeout', async (t) => {
  const { root, contractPath } = await fixture(t)
  const out = join(root, 'hostile-response-timeout')
  await generateNativeConnectorPackage({ contractPath, outPath: out, packageName: 'hostile-response-timeout' })
  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=hostile-response-timeout`)
  const home = runtime.metadata.endpoints.find((item) => item.path_template === '/Home')
  const observedChunk = new Uint8Array(Buffer.from('transient-response-secret'))
  let reads = 0
  let cancelCalls = 0
  const connector = runtime.createConnector({
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers({ 'content-type': 'text/plain' }),
      body: {
        getReader() {
          return {
            read() {
              reads += 1
              return reads === 1
                ? Promise.resolve({ done: false, value: observedChunk })
                : new Promise(() => {})
            },
            cancel() {
              cancelCalls += 1
              return new Promise(() => {})
            },
          }
        },
      },
    }),
  })

  await assert.rejects(
    connector.request(home.endpoint_id, { timeoutMs: 20 }),
    (error) => error?.code === 'CONNECTOR_TIMEOUT'
      && error.request_may_have_been_sent === true,
  )
  assert.equal(cancelCalls, 1)
  assert.deepEqual([...observedChunk], Array(observedChunk.length).fill(0))
})

test('generated runtime preserves a response when producer byte cleanup is overridden', async (t) => {
  const { root, contractPath } = await fixture(t)
  const out = join(root, 'overridden-response-byte-cleanup')
  await generateNativeConnectorPackage({
    contractPath,
    outPath: out,
    packageName: 'overridden-response-byte-cleanup',
  })
  const runtime = await import(
    `${pathToFileURL(join(out, 'index.mjs')).href}?case=overridden-response-byte-cleanup`,
  )
  const home = runtime.metadata.endpoints.find((item) => item.path_template === '/Home')
  const sourceChunk = new Uint8Array(Buffer.from('transient-generated-response'))
  const retainedCopies = []
  const originalFrom = Buffer.from
  t.mock.method(Buffer, 'from', function (value, ...args) {
    const copy = originalFrom.call(Buffer, value, ...args)
    if (value === sourceChunk) retainedCopies.push(copy)
    return copy
  })
  sourceChunk.fill = () => { throw new Error('synthetic hostile producer fill') }
  let reads = 0
  const connector = runtime.createConnector({
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers({ 'content-type': 'text/plain' }),
      body: {
        getReader() {
          return {
            read() {
              reads += 1
              return Promise.resolve(reads === 1
                ? { done: false, value: sourceChunk }
                : { done: true })
            },
            cancel() {},
          }
        },
      },
    }),
  })

  const result = await connector.request(home.endpoint_id)
  assert.equal(result.data, 'transient-generated-response')
  assert.equal(sourceChunk.every((byte) => byte === 0), true)
  assert.equal(retainedCopies.length, 1)
  assert.equal(retainedCopies[0].every((byte) => byte === 0), true)
})

test('generated runtime late detached response cleanup cannot reject unhandled', async (t) => {
  const { root, contractPath } = await fixture(t)
  const out = join(root, 'late-detached-array-buffer')
  await generateNativeConnectorPackage({
    contractPath,
    outPath: out,
    packageName: 'late-detached-array-buffer',
  })
  const runtime = await import(
    `${pathToFileURL(join(out, 'index.mjs')).href}?case=late-detached-array-buffer`,
  )
  const home = runtime.metadata.endpoints.find((item) => item.path_template === '/Home')
  let resolveArrayBuffer
  const lateArrayBuffer = new Promise((resolve) => { resolveArrayBuffer = resolve })
  const connector = runtime.createConnector({
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers({ 'content-type': 'text/plain' }),
      arrayBuffer: () => lateArrayBuffer,
    }),
  })
  const unhandled = []
  const onUnhandled = (error) => { unhandled.push(error) }
  process.on('unhandledRejection', onUnhandled)
  try {
    await assert.rejects(
      connector.request(home.endpoint_id, { timeoutMs: 10 }),
      (error) => error?.code === 'CONNECTOR_TIMEOUT'
        && error.request_may_have_been_sent === true,
    )
    const detached = new ArrayBuffer(16 * 1024)
    structuredClone(detached, { transfer: [detached] })
    resolveArrayBuffer(detached)
    await new Promise((resolve) => setImmediate(resolve))
    await new Promise((resolve) => setImmediate(resolve))
    assert.deepEqual(unhandled, [])
  } finally {
    process.off('unhandledRejection', onUnhandled)
  }
})

test('generated runtime clears a fallback response buffer that resolves after timeout', async (t) => {
  const { root, contractPath } = await fixture(t)
  const out = join(root, 'late-array-buffer-timeout')
  await generateNativeConnectorPackage({
    contractPath,
    outPath: out,
    packageName: 'late-array-buffer-timeout',
  })
  const runtime = await import(
    `${pathToFileURL(join(out, 'index.mjs')).href}?case=late-array-buffer-timeout`,
  )
  const home = runtime.metadata.endpoints.find((item) => item.path_template === '/Home')
  const lateBytes = new TextEncoder().encode('late-fallback-response-secret')
  const connector = runtime.createConnector({
    fetchImpl: async () => ({
      status: 200,
      headers: new Headers({ 'content-type': 'text/plain' }),
      arrayBuffer: async () => new Promise((resolve) => {
        setTimeout(() => resolve(lateBytes.buffer), 40)
      }),
    }),
  })

  await assert.rejects(
    connector.request(home.endpoint_id, { timeoutMs: 10 }),
    (error) => error?.code === 'CONNECTOR_TIMEOUT'
      && error.request_may_have_been_sent === true,
  )
  await new Promise((resolve) => setTimeout(resolve, 60))
  assert.deepEqual([...lateBytes], Array(lateBytes.length).fill(0))
})

test('generated runtime rechecks the monotonic deadline after a synchronous credential provider', async (t) => {
  const { root, contractPath } = await fixture(t)
  const out = join(root, 'synchronous-provider-timeout')
  await generateNativeConnectorPackage({ contractPath, outPath: out, packageName: 'synchronous-provider-timeout' })
  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=synchronous-provider-timeout`)
  const home = runtime.metadata.endpoints.find((item) => item.path_template === '/Home')
  let fetchCalls = 0
  const connector = runtime.createConnector({
    credentialProvider: () => {
      const until = performance.now() + 40
      while (performance.now() < until) {}
      return {}
    },
    fetchImpl: async () => {
      fetchCalls += 1
      return new Response('{}', { status: 200, headers: { 'content-type': 'application/json' } })
    },
  })

  await assert.rejects(
    connector.request(home.endpoint_id, { timeoutMs: 5 }),
    (error) => error?.code === 'CONNECTOR_TIMEOUT'
      && error.request_may_have_been_sent === false,
  )
  assert.equal(fetchCalls, 0)
})

test('generated runtime rechecks the deadline after synchronous response-header processing', async (t) => {
  const { root, contractPath } = await fixture(t)
  const out = join(root, 'synchronous-response-header-timeout')
  await generateNativeConnectorPackage({
    contractPath,
    outPath: out,
    packageName: 'synchronous-response-header-timeout',
  })
  const runtime = await import(
    `${pathToFileURL(join(out, 'index.mjs')).href}?case=synchronous-response-header-timeout`,
  )
  const home = runtime.metadata.endpoints.find((item) => item.path_template === '/Home')
  const headers = {
    get(name) {
      return name.toLowerCase() === 'content-type' ? 'application/json' : null
    },
    entries() {
      const until = performance.now() + 40
      while (performance.now() < until) {}
      return [['content-type', 'application/json']][Symbol.iterator]()
    },
  }
  const connector = runtime.createConnector({
    fetchImpl: async () => ({
      status: 200,
      headers,
      arrayBuffer: async () => new TextEncoder().encode('{}').buffer,
    }),
  })

  await assert.rejects(
    connector.request(home.endpoint_id, { timeoutMs: 5 }),
    (error) => error?.code === 'CONNECTOR_TIMEOUT'
      && error.request_may_have_been_sent === true,
  )
})

test('generated runtime deadline includes credential providers and receivers', async (t) => {
  const { root, contractPath } = await fixture(t)
  const providerOut = join(root, 'provider-timeout')
  await generateNativeConnectorPackage({ contractPath, outPath: providerOut, packageName: 'provider-timeout' })
  const providerRuntime = await import(`${pathToFileURL(join(providerOut, 'index.mjs')).href}?case=provider-timeout`)
  const home = providerRuntime.metadata.endpoints.find((item) => item.path_template === '/Home')
  let fetchCalls = 0
  const providerConnector = providerRuntime.createConnector({
    credentialProvider: async () => new Promise(() => {}),
    fetchImpl: async () => { fetchCalls += 1; return new Response('{}') },
  })

  let providerWatchdog
  try {
    await assert.rejects(
      Promise.race([
        providerConnector.request(home.endpoint_id, { timeoutMs: 20 }),
        new Promise((_, reject) => {
          providerWatchdog = setTimeout(() => reject(new Error('credential provider exceeded deadline')), 300)
        }),
      ]),
      (error) => error?.code === 'CONNECTOR_TIMEOUT'
        && error.request_may_have_been_sent === false,
    )
  } finally {
    clearTimeout(providerWatchdog)
  }
  assert.equal(fetchCalls, 0)

  const origin = 'https://portal.example'
  const evidence = importWebHarEvidence({ log: { entries: [entry({
    method: 'GET',
    url: `${origin}/token`,
    status: 200,
    content: { mimeType: 'application/json', text: '{"access_token":"synthetic-token"}' },
  })] } }, {
    sourceSha256: 'e'.repeat(64),
    targetOrigins: [origin],
    pathLiterals: ['token'],
  })
  const receiverContract = buildNativeInteractionContract({
    webSessionEvidence: [evidence], reverseEvidence: [], generatedAt: '2026-09-11T12:01:00.000Z',
  })
  const receiverContractPath = join(root, 'receiver-contract.json')
  const receiverOut = join(root, 'receiver-timeout')
  await writeFile(receiverContractPath, JSON.stringify(receiverContract), 'utf8')
  await generateNativeConnectorPackage({
    contractPath: receiverContractPath,
    outPath: receiverOut,
    packageName: 'receiver-timeout',
  })
  const receiverRuntime = await import(`${pathToFileURL(join(receiverOut, 'index.mjs')).href}?case=receiver-timeout`)
  const token = receiverRuntime.metadata.endpoints[0]
  const receiverConnector = receiverRuntime.createConnector({
    credentialReceiver: async () => new Promise(() => {}),
    fetchImpl: async () => new Response('{"access_token":"runtime-secret"}', {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  })

  let receiverWatchdog
  try {
    await assert.rejects(
      Promise.race([
        receiverConnector.request(token.endpoint_id, { timeoutMs: 20 }),
        new Promise((_, reject) => {
          receiverWatchdog = setTimeout(() => reject(new Error('credential receiver exceeded deadline')), 300)
        }),
      ]),
      (error) => error?.code === 'CONNECTOR_TIMEOUT'
        && error.request_may_have_been_sent === true,
    )
  } finally {
    clearTimeout(receiverWatchdog)
  }
})

test('generated runtime marks a credential-provider failure after a retryable send as ambiguous', async (t) => {
  const { root, contractPath } = await fixture(t)
  const out = join(root, 'provider-after-send')
  await generateNativeConnectorPackage({ contractPath, outPath: out, packageName: 'provider-after-send' })
  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=provider-after-send`)
  const items = runtime.metadata.endpoints.find((item) => item.path_template.includes('/api/items/'))
  let providerCalls = 0
  let fetchCalls = 0
  const connector = runtime.createConnector({
    credentialProvider: async () => {
      providerCalls += 1
      if (providerCalls === 1) return { headers: { authorization: 'Bearer transient-value' } }
      const forged = new Error('provider detail that must not escape')
      forged.name = 'GeneratedConnectorError'
      forged.code = 'CONNECTOR_TIMEOUT'
      forged.request_may_have_been_sent = false
      throw forged
    },
    fetchImpl: async () => {
      fetchCalls += 1
      return new Response('{"error":"busy"}', {
        status: 500,
        headers: { 'content-type': 'application/json' },
      })
    },
  })

  await assert.rejects(
    connector.request(items.endpoint_id, { path: { integer: 456 }, query: { limit: 2, view: 'read' } }),
    (error) => error?.code === 'CONNECTOR_TRANSPORT_FAILED'
      && error.request_may_have_been_sent === true
      && !String(error.message).includes('provider detail'),
  )
  assert.equal(fetchCalls, 1)
})

test('generated runtime never automatically retries an observed write sequence', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-connector-write-retry-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const origin = 'https://portal.example'
  const har = { log: { entries: [500, 200].map((status) => entry({
    method: 'POST',
    url: `${origin}/api/update`,
    requestHeaders: [{ name: 'Content-Type', value: 'application/json' }],
    postData: { mimeType: 'application/json', text: '{"id":1}' },
    status,
    content: { mimeType: 'application/json', text: status === 500 ? '{"error":"busy"}' : '{"ok":true}' },
  })) } }
  const evidence = importWebHarEvidence(har, {
    sourceSha256: 'b'.repeat(64),
    targetOrigins: [origin],
    pathLiterals: ['api', 'update'],
  })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [evidence], reverseEvidence: [], generatedAt: '2026-09-11T12:01:00.000Z',
  })
  const contractPath = join(root, 'contract.json')
  const out = join(root, 'generated')
  await writeFile(contractPath, JSON.stringify(contract), 'utf8')
  await generateNativeConnectorPackage({ contractPath, outPath: out, packageName: 'write-retry' })
  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=write-retry`)
  const update = runtime.metadata.endpoints[0]
  assert.equal(update.retry, 'RETRY_SEQUENCE_OBSERVED')
  assert.equal(update.side_effect.classification, 'WRITE_CANDIDATE')
  let calls = 0
  const connector = runtime.createConnector({
    fetchImpl: async () => {
      calls += 1
      return new Response('{"error":"busy"}', { status: 500, headers: { 'content-type': 'application/json' } })
    },
  })
  const result = await connector.request(update.endpoint_id, { body: { id: 2 }, maxRetries: 3 })
  assert.equal(result.status, 500)
  assert.equal(result.attempts, 1)
  assert.equal(result.retries, 0)
  assert.equal(calls, 1)

  let failedCalls = 0
  const ambiguous = runtime.createConnector({
    fetchImpl: async () => {
      failedCalls += 1
      throw new Error('synthetic transport failure')
    },
  })
  await assert.rejects(
    ambiguous.request(update.endpoint_id, { body: { id: 2 }, maxRetries: 3 }),
    (error) => error?.code === 'CONNECTOR_TRANSPORT_FAILED'
      && error.request_may_have_been_sent === true,
  )
  assert.equal(failedCalls, 1)
})

test('generated runtime never retries a GET carrying an observed method override', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-connector-method-override-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const origin = 'https://portal.example'
  const har = { log: { entries: [500, 200].map((status) => entry({
    method: 'GET',
    url: `${origin}/read?_method=DELETE`,
    requestHeaders: [{ name: 'X-Forwarded-Prefix', value: '/internal' }],
    status,
    content: { mimeType: 'application/json', text: status === 500 ? '{"error":"busy"}' : '{"ok":true}' },
  })) } }
  const evidence = importWebHarEvidence(har, {
    sourceSha256: '9'.repeat(64),
    targetOrigins: [origin],
    pathLiterals: ['read'],
  })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [evidence], reverseEvidence: [], generatedAt: '2026-09-11T12:01:00.000Z',
  })
  const contractPath = join(root, 'contract.json')
  const out = join(root, 'generated')
  await writeFile(contractPath, JSON.stringify(contract), 'utf8')
  await generateNativeConnectorPackage({ contractPath, outPath: out, packageName: 'method-override' })
  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=method-override`)
  const overridden = runtime.metadata.endpoints[0]
  assert.equal(overridden.retry, 'RETRY_SEQUENCE_OBSERVED')
  assert.equal(overridden.side_effect.classification, 'WRITE_CANDIDATE')
  let calls = 0
  const connector = runtime.createConnector({
    fetchImpl: async () => {
      calls += 1
      return new Response('{"error":"busy"}', { status: 500, headers: { 'content-type': 'application/json' } })
    },
  })

  await assert.rejects(
    connector.request(overridden.endpoint_id, {
      headers: { 'x-forwarded-prefix': '/internal' },
      query: { _method: 'DELETE' },
      maxRetries: 3,
    }),
    (error) => error?.code === 'CONNECTOR_INPUT_INVALID',
  )
  assert.equal(calls, 0)

  const result = await connector.request(overridden.endpoint_id, {
    query: { _method: 'DELETE' },
    maxRetries: 3,
  })
  assert.equal(result.status, 500)
  assert.equal(result.attempts, 1)
  assert.equal(result.retries, 0)
  assert.equal(calls, 1)
})

test('generated runtime refuses layered path traversal and state-changing action substitution', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-connector-semantic-input-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const origin = 'https://portal.example'
  const har = { log: { entries: [
    ...[500, 200].map((status) => entry({
      method: 'GET',
      url: `${origin}/files/example?action=read`,
      status,
      content: { mimeType: 'application/json', text: status === 500 ? '{"error":"busy"}' : '{"ok":true}' },
    })),
    entry({
      method: 'GET',
      url: `${origin}/jobs/example?action=custom`,
      status: 200,
      content: { mimeType: 'application/json', text: '{"ok":true}' },
    }),
    entry({
      method: 'POST',
      url: `${origin}/array-actions/example`,
      postData: { mimeType: 'application/json', text: '{"action":["read"]}' },
      status: 200,
      content: { mimeType: 'application/json', text: '{"ok":true}' },
    }),
  ] } }
  const evidence = importWebHarEvidence(har, {
    sourceSha256: '8'.repeat(64),
    targetOrigins: [origin],
    pathLiterals: ['array-actions', 'files', 'jobs'],
  })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [evidence], reverseEvidence: [], generatedAt: '2026-09-11T12:01:00.000Z',
  })
  const contractPath = join(root, 'contract.json')
  const out = join(root, 'generated')
  await writeFile(contractPath, JSON.stringify(contract), 'utf8')
  await generateNativeConnectorPackage({ contractPath, outPath: out, packageName: 'semantic-input' })
  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=semantic-input`)
  const endpoint = runtime.metadata.endpoints.find((item) => item.path_template === '/files/{segment}')
  const unknownEndpoint = runtime.metadata.endpoints.find((item) => item.path_template === '/jobs/{segment}')
  const arrayEndpoint = runtime.metadata.endpoints.find((item) => item.path_template === '/array-actions/{segment}')
  assert.equal(endpoint.path_template, '/files/{segment}')
  assert.deepEqual(endpoint.request.query_parameters[0].semantic_classes, ['READ_ACTION'])
  assert.deepEqual(unknownEndpoint.request.query_parameters[0].semantic_classes, ['OTHER_ACTION'])
  assert.deepEqual(arrayEndpoint.request.fields.find(({ path }) => path === 'action').semantic_classes, ['READ_ACTION'])
  let calls = 0
  const connector = runtime.createConnector({
    fetchImpl: async () => {
      calls += 1
      return new Response('{"error":"busy"}', {
        status: 500,
        headers: { 'content-type': 'application/json' },
      })
    },
  })
  let layeredDelete = '%64elete'
  for (let index = 0; index < 16; index += 1) layeredDelete = encodeURIComponent(layeredDelete)

  for (const options of [
    { path: { segment: '../admin' }, query: { action: 'read' } },
    { path: { segment: '%252e%252e%252fadmin' }, query: { action: 'read' } },
    { path: { segment: 'delete' }, query: { action: 'read' } },
    { path: { segment: 'report' }, query: { action: 'delete' } },
    { path: { segment: 'report' }, query: { action: 'delete_status' } },
    { path: { segment: 'report' }, query: { action: layeredDelete } },
  ]) {
    await assert.rejects(
      connector.request(endpoint.endpoint_id, options),
      (error) => error?.code === 'CONNECTOR_INPUT_INVALID',
    )
  }
  await assert.rejects(
    connector.request(endpoint.endpoint_id, { path: { segment: 'example' } }),
    (error) => error?.code === 'CONNECTOR_INPUT_INVALID'
      && /action semantics/u.test(error.message),
  )
  await assert.rejects(
    connector.request(unknownEndpoint.endpoint_id, {
      path: { segment: 'report' },
      query: { action: 'another-custom' },
    }),
    (error) => error?.code === 'CONNECTOR_INPUT_INVALID'
      && /unclassified/u.test(error.message),
  )
  await assert.rejects(
    connector.request(arrayEndpoint.endpoint_id, {
      path: { segment: 'report' },
      body: { action: ['delete'] },
    }),
    (error) => error?.code === 'CONNECTOR_INPUT_INVALID',
  )
  await assert.rejects(
    connector.request(arrayEndpoint.endpoint_id, {
      path: { segment: 'example' },
      body: { action: [] },
    }),
    (error) => error?.code === 'CONNECTOR_INPUT_INVALID'
      && /action semantics/u.test(error.message),
  )
  await assert.rejects(
    connector.request(arrayEndpoint.endpoint_id, { path: { segment: 'example' } }),
    (error) => error?.code === 'CONNECTOR_INPUT_INVALID'
      && /action semantics/u.test(error.message),
  )
  assert.equal(calls, 0)
})

test('generated runtime follows only exact observed Location exchanges and typed redirect queries', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-redirect-contract-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const cases = [
    {
      name: 'response-body-destination',
      contract: redirectContract({ destinationSource: 'RESPONSE_BODY_FIELD' }),
      liveStatus: 302,
      liveLocation: '/next',
    },
    {
      name: 'status-mismatch',
      contract: redirectContract({ observedStatus: 307 }),
      liveStatus: 302,
      liveLocation: '/next',
    },
    {
      name: 'query-type-mismatch',
      contract: redirectContract({ destination: '/next?limit=1' }),
      liveStatus: 302,
      liveLocation: '/next?limit=delete-all',
    },
    {
      name: 'unclassified-action-substitution',
      contract: redirectContract({ destination: '/next?action=custom' }),
      liveStatus: 302,
      liveLocation: '/next?action=another-custom',
    },
    {
      name: 'nonclassifiable-action-substitution',
      contract: redirectContract({ destination: '/next?action=1' }),
      liveStatus: 302,
      liveLocation: '/next?action=2',
    },
    {
      name: 'missing-observed-action',
      contract: redirectContract({ destination: '/next?action=read' }),
      liveStatus: 302,
      liveLocation: '/next',
    },
    {
      name: 'state-changing-redirect-path',
      contract: redirectContract({ destination: '/unrecognized-next' }),
      liveStatus: 302,
      liveLocation: '/delete',
    },
  ]

  for (const scenario of cases) {
    const contractPath = join(root, `${scenario.name}.json`)
    const out = join(root, scenario.name)
    await writeFile(contractPath, JSON.stringify(scenario.contract), 'utf8')
    await generateNativeConnectorPackage({ contractPath, outPath: out, packageName: scenario.name })
    const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=${scenario.name}`)
    const start = runtime.metadata.endpoints.find((item) => item.path_template === '/start')
    let calls = 0
    const connector = runtime.createConnector({
      fetchImpl: async () => {
        calls += 1
        return new Response(null, { status: scenario.liveStatus, headers: { location: scenario.liveLocation } })
      },
    })
    await assert.rejects(
      connector.request(start.endpoint_id),
      (error) => error?.code === 'CONNECTOR_REDIRECT_REFUSED'
        && error.request_may_have_been_sent === true,
      scenario.name,
    )
    assert.equal(calls, 1, scenario.name)
  }
})

test('runtime result metadata omits concrete redirect queries and credential response headers', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-private-result-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const contractPath = join(root, 'contract.json')
  await writeFile(contractPath, JSON.stringify(observedContract('https://portal.example', { redirectQuery: true })), 'utf8')
  const out = join(root, 'generated')
  await generateNativeConnectorPackage({ contractPath, outPath: out })
  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=private-result`)
  const login = runtime.metadata.endpoints.find((item) => item.path_template === '/login')
  let unresolvedTokenHeader = 'x-%74oken'
  for (let pass = 0; pass < 8; pass += 1) unresolvedTokenHeader = encodeURIComponent(unresolvedTokenHeader)
  const canonicalSensitiveHeaders = Object.fromEntries(
    [...SENSITIVE_HEADERS].map((name) => [name, `canonical-${name}-response-secret`]),
  )
  const connector = runtime.createConnector({
    credentialProvider: async ({ endpointId }) => endpointId === login.endpoint_id
      ? { body: { UserName: 'private-user', Password: 'private-password' } }
      : {},
    fetchImpl: async (url) => url.pathname === '/login'
      ? new Response(null, { status: 302, headers: { location: '/Home?token=redirect-secret' } })
      : new Response('{"ready":true}', {
        status: 200,
        headers: {
          ...canonicalSensitiveHeaders,
          authorization: 'Bearer response-secret',
          'content-type': 'application/json',
          location: '/Home?token=response-location-secret',
          'x-access-token': 'secondary-response-secret',
          'x-hub-signature-256': 'dynamic-versioned-signature-secret',
          'x-service-signature': 'dynamic-signature-secret',
          'x-service-token': 'dynamic-token-secret',
          'x-%2574oken': 'encoded-header-secret',
          [unresolvedTokenHeader]: 'unresolved-encoded-header-secret',
          'x-%zz-token': 'malformed-encoded-header-secret',
          'x-relay-state': 'sso-relay-secret',
          'x-saml-request': 'sso-request-secret',
          'x-saml-response': 'sso-response-secret',
          'x-state': 'sso-state-secret',
          'x-oauth-state': 'vendor-oauth-state-secret',
          'x-okta-saml-response': 'vendor-saml-response-secret',
          'x-auth-relay-state': 'vendor-relay-state-secret',
          'x-auth-code': 'vendor-authorization-code-secret',
          'x-%2561uth-code-v2': 'layered-authorization-code-secret',
          'x-vendor-saml-request-v12': 'versioned-saml-request-secret',
          'x-okta-%2573aml-response-v3': 'layered-saml-response-secret',
          'x-status-code': '200',
          'x-response-code': 'accepted',
          'x-error-code': 'none',
          'x-verification-code': 'otp-response-secret',
          'x-public-shape': 'visible',
        },
      }),
  })
  const result = await connector.request(login.endpoint_id)
  assert.equal(result.origin, 'https://portal.example')
  assert.equal(result.pathTemplate, '/Home')
  assert.equal(result.headers.authorization, undefined)
  assert.equal(result.headers.location, undefined)
  for (const name of SENSITIVE_HEADERS) assert.equal(result.headers[name], undefined, name)
  assert.equal(result.headers['x-access-token'], undefined)
  assert.equal(result.headers['x-hub-signature-256'], undefined)
  assert.equal(result.headers['x-service-signature'], undefined)
  assert.equal(result.headers['x-service-token'], undefined)
  for (const name of [
    'x-%2574oken',
    'x-relay-state',
    'x-saml-request',
    'x-saml-response',
    'x-state',
    'x-oauth-state',
    'x-okta-saml-response',
    'x-auth-relay-state',
    'x-auth-code',
    'x-%2561uth-code-v2',
    'x-vendor-saml-request-v12',
    'x-okta-%2573aml-response-v3',
  ]) {
    assert.equal(result.headers[name], undefined, name)
  }
  assert.equal(result.headers[unresolvedTokenHeader], undefined)
  assert.equal(result.headers['x-%zz-token'], undefined)
  assert.equal(result.headers['x-verification-code'], undefined)
  assert.equal(result.headers['x-status-code'], '200')
  assert.equal(result.headers['x-response-code'], 'accepted')
  assert.equal(result.headers['x-error-code'], 'none')
  assert.equal(result.headers['x-public-shape'], 'visible')
  assert.equal(Object.hasOwn(result, 'url'), false)
  assert.doesNotMatch(JSON.stringify(result), /redirect-secret|response-secret|response-location-secret|secondary-response-secret|dynamic-versioned-signature-secret|dynamic-signature-secret|dynamic-token-secret|unresolved-encoded-header-secret|malformed-encoded-header-secret|vendor-oauth-state-secret|vendor-saml-response-secret|vendor-relay-state-secret|vendor-authorization-code-secret|layered-authorization-code-secret|versioned-saml-request-secret|layered-saml-response-secret|otp-response-secret|private-password|private-user/)
})

test('generated runtime bounds response header count and values', async (t) => {
  const { root, contractPath } = await fixture(t)
  const out = join(root, 'response-header-bounds')
  await generateNativeConnectorPackage({ contractPath, outPath: out, packageName: 'response-header-bounds' })
  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=response-header-bounds`)
  const home = runtime.metadata.endpoints.find((item) => item.path_template === '/Home')
  const headers = new Headers({ 'content-type': 'application/json' })
  for (let index = 0; index < 129; index += 1) headers.set(`x-field-${index}`, 'value')
  const connector = runtime.createConnector({
    fetchImpl: async () => new Response('{}', { status: 200, headers }),
  })

  await assert.rejects(
    connector.request(home.endpoint_id),
    (error) => error?.code === 'CONNECTOR_RESPONSE_INVALID'
      && error.request_may_have_been_sent === true,
  )
})

test('response body credentials use an explicit transient receiver and stay out of ordinary result data', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-response-credentials-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const origin = 'https://portal.example'
  const evidence = importWebHarEvidence({ log: { entries: [entry({
    method: 'GET',
    url: `${origin}/token`,
    status: 200,
    content: { mimeType: 'application/json', text: '{"access_token":"synthetic-token","profile":{"name":"Synthetic User"}}' },
  })] } }, {
    sourceSha256: 'c'.repeat(64),
    targetOrigins: [origin],
    pathLiterals: ['token'],
  })
  const contract = buildNativeInteractionContract({
    webSessionEvidence: [evidence], reverseEvidence: [], generatedAt: '2026-09-11T12:01:00.000Z',
  })
  const contractPath = join(root, 'contract.json')
  const out = join(root, 'generated')
  await writeFile(contractPath, JSON.stringify(contract), 'utf8')
  await generateNativeConnectorPackage({ contractPath, outPath: out, packageName: 'response-credentials' })
  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=response-credentials`)
  const tokenEndpoint = runtime.metadata.endpoints[0]
  assert.deepEqual(tokenEndpoint.auth.response_carriers, ['body:access_token'])
  const received = []
  const connector = runtime.createConnector({
    credentialReceiver: async (context) => received.push(context),
    fetchImpl: async () => new Response('{"access_token":"runtime-secret","profile":{"name":"Safe Name"}}', {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  })
  const result = await connector.request(tokenEndpoint.endpoint_id)

  assert.deepEqual(result.data, { access_token: null, profile: { name: 'Safe Name' } })
  assert.equal(received.length, 1)
  assert.equal(Object.isFrozen(received[0]), true)
  assert.deepEqual(received[0].credentials, [{ carrier: 'body:access_token', value: 'runtime-secret' }])
  assert.doesNotMatch(JSON.stringify(result), /runtime-secret/)
  assert.throws(
    () => runtime.createConnector({ credentialReceiver: true }),
    (error) => error?.code === 'CONNECTOR_OPTION_INVALID',
  )
})

test('generated connector performs a real loopback login, redirect, cookie transition, and JSON read', async (t) => {
  const requests = []
  const server = createServer(async (request, response) => {
    const chunks = []
    for await (const chunk of request) chunks.push(chunk)
    requests.push({ url: request.url, method: request.method, headers: request.headers, body: Buffer.concat(chunks).toString('utf8') })
    if (request.url === '/login' && request.method === 'POST') {
      response.writeHead(302, {
        location: '/Home',
        'set-cookie': 'SessionCookie=loopback-session; Path=/; HttpOnly',
      })
      response.end()
      return
    }
    if (request.url === '/Home' && request.method === 'GET') {
      response.writeHead(200, { 'content-type': 'application/json' })
      response.end('{"source":"loopback"}')
      return
    }
    response.writeHead(404, { 'content-type': 'application/json' })
    response.end('{"error":"not found"}')
  })
  await new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, '127.0.0.1', resolve)
  })
  t.after(() => new Promise((resolve) => server.close(resolve)))
  const address = server.address()
  const origin = `http://127.0.0.1:${address.port}`
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-loopback-connector-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const contractPath = join(root, 'contract.json')
  await writeFile(contractPath, JSON.stringify(observedContract(origin)), 'utf8')
  const out = join(root, 'generated')
  await generateNativeConnectorPackage({ contractPath, outPath: out, packageName: 'loopback-native' })
  const runtime = await import(`${pathToFileURL(join(out, 'index.mjs')).href}?case=loopback`)
  const login = runtime.metadata.endpoints.find((item) => item.path_template === '/login')
  const connector = runtime.createConnector({
    credentialProvider: async ({ endpointId }) => endpointId === login.endpoint_id
      ? { body: { UserName: 'loopback-user', Password: 'loopback-secret' } }
      : {},
  })
  const result = await connector.request(login.endpoint_id)
  assert.equal(result.status, 200)
  assert.equal(result.redirects, 1)
  assert.deepEqual(result.data, { source: 'loopback' })
  assert.equal(requests.length, 2)
  assert.match(requests[0].body, /UserName=loopback-user/)
  assert.match(requests[1].headers.cookie, /SessionCookie=loopback-session/)
})

test('generator refuses invalid contracts, package names, relative paths, links, and partial replacement', async (t) => {
  const { root, contractPath } = await fixture(t)
  await assert.rejects(
    generateNativeConnectorPackage({ contractPath: 'contract.json', outPath: join(root, 'relative') }),
    (error) => error?.code === 'CONNECTOR_PATH_INVALID',
  )
  await assert.rejects(
    generateNativeConnectorPackage({ contractPath, outPath: join(root, 'bad-name'), packageName: 'Bad Name' }),
    (error) => error?.code === 'CONNECTOR_NAME_INVALID',
  )
  const invalid = join(root, 'invalid.json')
  await writeFile(invalid, '{"kind":"forged"}', 'utf8')
  await assert.rejects(
    generateNativeConnectorPackage({ contractPath: invalid, outPath: join(root, 'invalid-out') }),
    (error) => error?.code === 'CONNECTOR_CONTRACT_INVALID',
  )
})

test('descriptor projection is generated and reviewable while retaining exact source digest bindings', () => {
  const contract = observedContract()
  const descriptor = buildGeneratedConnectorDescriptor(contract)
  assert.equal(descriptor.status, 'GENERATED_REVIEWABLE')
  assert.equal(descriptor.runtime_mode, 'CONTRACT_BOUND')
  assert.equal(descriptor.source_contract.contract_id, contract.contract_id)
  assert.deepEqual(descriptor.source_contract.basis, contract.basis)
  assert.deepEqual(descriptor.endpoints, contract.endpoints)
  assert.deepEqual(descriptor.auth_flows, contract.auth_flows)
})
