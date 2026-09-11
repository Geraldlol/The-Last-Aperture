import { createHash, randomBytes } from 'node:crypto'
import {
  lstat,
  mkdir,
  readFile,
  readdir,
  realpath,
  rm,
  unlink,
  writeFile,
} from 'node:fs/promises'
import { dirname, isAbsolute, join, parse, resolve } from 'node:path'

import {
  assertValidNativeInteractionContract,
  digestNativeInteractionContract,
} from './reverse-protocol.mjs'
import { stableJson } from './run-engine.mjs'

export const GENERATED_CONNECTOR_KIND = 'last-aperture/generated-native-connector'
export const GENERATED_CONNECTOR_PROTOCOL = 'native-interaction-connector-v1'
export const GENERATED_CONNECTOR_MANIFEST_KIND = 'last-aperture/generated-connector-manifest'
export const GENERATED_CONNECTOR_GENERATOR_PROTOCOL = 'native-interaction-connector-generator-v1'
export const GENERATED_CONNECTOR_STATUS = 'GENERATED_REVIEWABLE'

const MAX_CONTRACT_BYTES = 64 * 1024 * 1024
const MAX_GENERATED_FILE_BYTES = 64 * 1024 * 1024
const SHA256 = /^[a-f0-9]{64}$/u
const PACKAGE_NAME = /^(?:@[a-z0-9](?:[a-z0-9._-]{0,212})\/[a-z0-9](?:[a-z0-9._-]{0,212})|[a-z0-9](?:[a-z0-9._-]{0,212}))$/u
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/u
const TEMPLATE_PATH = new URL('../templates/native-connector-runtime.mjs', import.meta.url)
const OUTPUT_FILES = Object.freeze(['README.md', 'connector.json', 'index.mjs', 'package.json'])
const PACKAGE_FILES = Object.freeze([...OUTPUT_FILES, 'manifest.json'].sort())

function fail(code, message) {
  const error = new Error(message)
  error.name = 'NativeConnectorGeneratorError'
  error.code = code
  throw error
}

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
}

function exact(value, fields, label) {
  if (!plain(value)) fail('CONNECTOR_MANIFEST_INVALID', `${label} must be an object`)
  const actual = Object.keys(value).sort()
  const expected = [...fields].sort()
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) {
    fail('CONNECTOR_MANIFEST_INVALID', `${label} contains a missing or unknown field`)
  }
}

function normalizedPath(value, label) {
  if (typeof value !== 'string' || !isAbsolute(value) || value.length > 4096 || CONTROL.test(value)) {
    fail('CONNECTOR_PATH_INVALID', `${label} must be an absolute local path`)
  }
  if (value.startsWith('\\\\') || value.startsWith('//') || /^(?:\\\\[.?]\\|\\\\?\\)/u.test(value)) {
    fail('CONNECTOR_PATH_INVALID', `${label} cannot use a network, device, or extended path`)
  }
  const normalized = resolve(value)
  if (normalized === parse(normalized).root) fail('CONNECTOR_PATH_INVALID', `${label} cannot be a filesystem root`)
  return normalized
}

function pathEqual(left, right) {
  return process.platform === 'win32'
    ? left.toLowerCase() === right.toLowerCase()
    : left === right
}

async function assertDirectLocalPath(path, label, expectedType) {
  let stats
  try { stats = await lstat(path) } catch (error) {
    if (error?.code === 'ENOENT') fail('CONNECTOR_PATH_MISSING', `${label} does not exist`)
    throw error
  }
  if (stats.isSymbolicLink() || (expectedType === 'file' && !stats.isFile()) || (expectedType === 'directory' && !stats.isDirectory())) {
    fail('CONNECTOR_PATH_INVALID', `${label} must be a direct local ${expectedType}`)
  }
  const actual = await realpath(path)
  if (!pathEqual(actual, path)) fail('CONNECTOR_PATH_INVALID', `${label} cannot traverse a link or reparse path`)
  return stats
}

async function readContract(path) {
  const stats = await assertDirectLocalPath(path, 'contract', 'file')
  if (stats.size < 2 || stats.size > MAX_CONTRACT_BYTES) fail('CONNECTOR_CONTRACT_INVALID', 'contract size is invalid')
  const bytes = await readFile(path)
  if (bytes.byteLength !== stats.size) fail('CONNECTOR_CONTRACT_CHANGED', 'contract changed while it was read')
  let value
  try { value = JSON.parse(bytes.toString('utf8')) } catch {
    fail('CONNECTOR_CONTRACT_INVALID', 'contract is not valid JSON')
  }
  try { assertValidNativeInteractionContract(value) } catch (error) {
    const wrapped = new Error('contract failed native-interaction-contract-v1 validation', { cause: error })
    wrapped.name = 'NativeConnectorGeneratorError'
    wrapped.code = 'CONNECTOR_CONTRACT_INVALID'
    throw wrapped
  }
  const after = await lstat(path)
  if (!after.isFile() || after.isSymbolicLink() || after.size !== stats.size || after.mtimeMs !== stats.mtimeMs) {
    fail('CONNECTOR_CONTRACT_CHANGED', 'contract changed while it was validated')
  }
  return value
}

async function readStablePackageFile(path, label) {
  const before = await assertDirectLocalPath(path, label, 'file')
  if (before.size < 1 || before.size > MAX_GENERATED_FILE_BYTES) {
    fail('CONNECTOR_PACKAGE_INVALID', `${label} size is invalid`)
  }
  const bytes = await readFile(path)
  const after = await lstat(path)
  if (
    !after.isFile()
    || after.isSymbolicLink()
    || bytes.byteLength !== before.size
    || after.size !== before.size
    || after.dev !== before.dev
    || after.ino !== before.ino
    || after.mtimeMs !== before.mtimeMs
  ) fail('CONNECTOR_PACKAGE_CHANGED', `${label} changed while it was verified`)
  return bytes
}

function validatePackageName(value) {
  if (typeof value !== 'string' || value.length > 214 || !PACKAGE_NAME.test(value)) {
    fail('CONNECTOR_NAME_INVALID', 'connector package name is invalid')
  }
  return value
}

function clone(value) {
  return JSON.parse(stableJson(value, 0))
}

export function buildGeneratedConnectorDescriptor(contract) {
  assertValidNativeInteractionContract(contract)
  return {
    schema_version: '1.0.0',
    kind: GENERATED_CONNECTOR_KIND,
    protocol: GENERATED_CONNECTOR_PROTOCOL,
    status: GENERATED_CONNECTOR_STATUS,
    runtime_mode: 'CONTRACT_BOUND',
    source_contract: {
      contract_id: contract.contract_id,
      sha256: digestNativeInteractionContract(contract),
      schema_version: contract.schema_version,
      protocol: contract.protocol,
      generated_at: contract.generated_at,
      basis: clone(contract.basis),
    },
    subjects: clone(contract.subjects),
    auth_flows: clone(contract.auth_flows),
    endpoints: clone(contract.endpoints),
  }
}

function contentDigest(files) {
  return sha256(files.map((item) => `${item.path}\u0000${item.sha256}`).join('\n'))
}

export function assertValidGeneratedConnectorManifest(value) {
  exact(value, [
    'schema_version', 'kind', 'generator_protocol', 'package_name', 'contract_id',
    'contract_sha256', 'generation_status', 'runtime_mode', 'network_during_generation',
    'content_sha256', 'files',
  ], 'generated connector manifest')
  if (
    value.schema_version !== '1.0.0'
    || value.kind !== GENERATED_CONNECTOR_MANIFEST_KIND
    || value.generator_protocol !== GENERATED_CONNECTOR_GENERATOR_PROTOCOL
    || value.generation_status !== GENERATED_CONNECTOR_STATUS
    || value.runtime_mode !== 'CONTRACT_BOUND'
    || value.network_during_generation !== 'NONE'
    || !/^interaction:[a-f0-9]{32}$/u.test(value.contract_id ?? '')
    || !SHA256.test(value.contract_sha256 ?? '')
    || !SHA256.test(value.content_sha256 ?? '')
  ) fail('CONNECTOR_MANIFEST_INVALID', 'generated connector manifest metadata is invalid')
  validatePackageName(value.package_name)
  if (!Array.isArray(value.files) || value.files.length !== OUTPUT_FILES.length) {
    fail('CONNECTOR_MANIFEST_INVALID', 'generated connector manifest file inventory is invalid')
  }
  for (const [index, item] of value.files.entries()) {
    exact(item, ['path', 'sha256'], 'generated connector file')
    if (item.path !== OUTPUT_FILES[index] || !SHA256.test(item.sha256 ?? '')) {
      fail('CONNECTOR_MANIFEST_INVALID', 'generated connector file record is invalid')
    }
  }
  if (value.content_sha256 !== contentDigest(value.files)) {
    fail('CONNECTOR_MANIFEST_INVALID', 'generated connector content digest is invalid')
  }
  return value
}

function escapeMarkdown(value) {
  return String(value).replaceAll('\\', '\\\\').replaceAll('|', '\\|').replaceAll('`', '\\`')
}

function connectorReadme(descriptor, packageName) {
  const first = descriptor.endpoints[0]
  const endpointRows = descriptor.endpoints.map((endpoint) => (
    `| \`${escapeMarkdown(endpoint.endpoint_id)}\` | ${escapeMarkdown(endpoint.method)} | \`${escapeMarkdown(endpoint.origin + endpoint.path_template)}\` | ${escapeMarkdown(endpoint.protocol_role)} |`
  ))
  const example = first
    ? `const result = await connector.request(${JSON.stringify(first.endpoint_id)}, {\n  path: {},\n  query: {},\n  headers: {},\n  body: undefined,\n})`
    : '// This observed contract contains no endpoints.'
  return `# ${packageName}\n\n`
    + `Generated by The Last Aperture from observed contract \`${descriptor.source_contract.contract_id}\`. `
    + 'The package is reviewable, self-contained, and bound to the endpoint IDs, origins, methods, request shapes, redirects, and retry evidence in that contract.\n\n'
    + `Source contract SHA-256: \`${descriptor.source_contract.sha256}\`\n\n`
    + '```js\n'
    + `import { createConnector, endpointIds, authFlows } from ${JSON.stringify(packageName)}\n\n`
    + 'const connector = createConnector({\n'
    + '  credentialReceiver: async ({ credentials }) => retainTokensInMemory(credentials),\n'
    + '  credentialProvider: async ({ endpointId, requestCarriers }) => {\n'
    + "    if (!requestCarriers.includes('header:authorization')) return {}\n"
    + '    return { headers: { authorization: await acquireToken(endpointId) } }\n'
    + '  },\n'
    + '})\n\n'
    + `${example}\n`
    + 'console.log(result.status, result.data)\n'
    + '```\n\n'
    + 'The credential provider is called for each attempt. Response body fields identified by the contract as credential carriers are removed from ordinary result data and delivered only to the optional credential receiver. Those values stay in memory and are never written by the connector. '
    + 'Response cookies use isolated in-memory jars per origin; call `clearCookies()` to erase them. Redirects resolve only to observed destination shapes and contract endpoints. Retries occur only where retry behavior was observed. Every error raised after transport invocation sets `request_may_have_been_sent: true`; never replay a write or unknown operation after that ambiguous outcome.\n\n'
    + '## Contract endpoints\n\n'
    + '| Endpoint ID | Method | URL template | Role |\n'
    + '| --- | --- | --- | --- |\n'
    + `${endpointRows.join('\n')}\n\n`
    + 'Exported metadata includes `manifest`, `metadata`, `contractId`, `endpointIds`, and `authFlows`.\n'
}

function packageDocument(packageName) {
  return {
    name: packageName,
    version: '0.1.0',
    private: true,
    description: 'A contract-bound Node connector generated by The Last Aperture.',
    type: 'module',
    engines: { node: '>=20.0.0' },
    exports: './index.mjs',
    files: ['README.md', 'connector.json', 'index.mjs', 'manifest.json'],
  }
}

async function assertNewOutput(path) {
  const parent = dirname(path)
  await assertDirectLocalPath(parent, 'output parent', 'directory')
  try {
    await lstat(path)
    fail('CONNECTOR_OUTPUT_EXISTS', 'output directory already exists')
  } catch (error) {
    if (error?.code !== 'ENOENT') throw error
  }
}

async function cleanupOwnedOutput(path, markerPath, nonce, identity) {
  try {
    const stats = await lstat(path)
    if (
      !stats.isDirectory()
      || stats.isSymbolicLink()
      || stats.dev !== identity.dev
      || stats.ino !== identity.ino
      || !pathEqual(await realpath(path), path)
    ) return
    const marker = await readFile(markerPath, 'utf8')
    if (marker !== nonce) return
    await rm(path, { recursive: true, force: false })
  } catch {
    // Keep the original generation failure. Cleanup is attempted only for the
    // new directory carrying this invocation's unpredictable ownership marker.
  }
}

export async function generateNativeConnectorPackage({ contractPath, outPath, packageName } = {}) {
  const contractFile = normalizedPath(contractPath, 'contract')
  const outputDirectory = normalizedPath(outPath, 'output directory')
  const contract = await readContract(contractFile)
  const selectedName = validatePackageName(packageName ?? `last-aperture-connector-${contract.contract_id.slice(-16)}`)
  await assertNewOutput(outputDirectory)

  const descriptor = buildGeneratedConnectorDescriptor(contract)
  const runtime = await readFile(TEMPLATE_PATH)
  if (runtime.byteLength < 1 || runtime.byteLength > MAX_GENERATED_FILE_BYTES) {
    fail('CONNECTOR_TEMPLATE_INVALID', 'connector runtime template size is invalid')
  }
  const sources = new Map([
    ['README.md', Buffer.from(connectorReadme(descriptor, selectedName), 'utf8')],
    ['connector.json', Buffer.from(stableJson(descriptor, 2), 'utf8')],
    ['index.mjs', runtime],
    ['package.json', Buffer.from(stableJson(packageDocument(selectedName), 2), 'utf8')],
  ])
  for (const [name, bytes] of sources) {
    if (bytes.byteLength < 1 || bytes.byteLength > MAX_GENERATED_FILE_BYTES) {
      fail('CONNECTOR_OUTPUT_INVALID', `generated ${name} size is invalid`)
    }
  }
  const files = OUTPUT_FILES.map((path) => ({ path, sha256: sha256(sources.get(path)) }))
  const manifest = assertValidGeneratedConnectorManifest({
    schema_version: '1.0.0',
    kind: GENERATED_CONNECTOR_MANIFEST_KIND,
    generator_protocol: GENERATED_CONNECTOR_GENERATOR_PROTOCOL,
    package_name: selectedName,
    contract_id: contract.contract_id,
    contract_sha256: descriptor.source_contract.sha256,
    generation_status: GENERATED_CONNECTOR_STATUS,
    runtime_mode: 'CONTRACT_BOUND',
    network_during_generation: 'NONE',
    content_sha256: contentDigest(files),
    files,
  })
  const manifestBytes = Buffer.from(stableJson(manifest, 2), 'utf8')

  const nonce = randomBytes(32).toString('hex')
  const markerPath = join(outputDirectory, '.last-aperture-generation-lock')
  let owned = false
  let outputIdentity = null
  try {
    await mkdir(outputDirectory, { recursive: false, mode: 0o700 })
    owned = true
    const outputStats = await lstat(outputDirectory)
    if (!outputStats.isDirectory() || outputStats.isSymbolicLink() || !pathEqual(await realpath(outputDirectory), outputDirectory)) {
      fail('CONNECTOR_OUTPUT_CHANGED', 'new output directory identity is invalid')
    }
    outputIdentity = { dev: outputStats.dev, ino: outputStats.ino }
    await writeFile(markerPath, nonce, { flag: 'wx', mode: 0o600 })
    for (const path of OUTPUT_FILES) await writeFile(join(outputDirectory, path), sources.get(path), { flag: 'wx', mode: 0o600 })
    await writeFile(join(outputDirectory, 'manifest.json'), manifestBytes, { flag: 'wx', mode: 0o600 })
    for (const item of files) {
      const actual = await readFile(join(outputDirectory, item.path))
      if (sha256(actual) !== item.sha256) fail('CONNECTOR_OUTPUT_CHANGED', 'generated connector changed while it was written')
    }
    assertValidGeneratedConnectorManifest(JSON.parse((await readFile(join(outputDirectory, 'manifest.json'))).toString('utf8')))
    await unlink(markerPath)
    return {
      status: 'SUCCEEDED',
      output_path: outputDirectory,
      manifest_path: join(outputDirectory, 'manifest.json'),
      package_name: selectedName,
      contract_id: contract.contract_id,
      contract_sha256: descriptor.source_contract.sha256,
      content_sha256: manifest.content_sha256,
      digest: sha256(manifestBytes),
      endpoints: descriptor.endpoints.length,
    }
  } catch (error) {
    if (owned && outputIdentity !== null) await cleanupOwnedOutput(outputDirectory, markerPath, nonce, outputIdentity)
    throw error
  }
}

export async function verifyGeneratedConnectorPackage({ packagePath, expectedManifestSha256 } = {}) {
  const packageDirectory = normalizedPath(packagePath, 'connector package')
  if (typeof expectedManifestSha256 !== 'string' || !SHA256.test(expectedManifestSha256)) {
    fail('CONNECTOR_MANIFEST_DIGEST_INVALID', 'expected manifest digest must be one lowercase SHA-256 value')
  }
  const directoryBefore = await assertDirectLocalPath(packageDirectory, 'connector package', 'directory')
  const names = (await readdir(packageDirectory)).sort()
  if (names.length !== PACKAGE_FILES.length || names.some((name, index) => name !== PACKAGE_FILES[index])) {
    fail('CONNECTOR_PACKAGE_INVALID', 'connector package file inventory does not match the generated package')
  }
  const manifestPath = join(packageDirectory, 'manifest.json')
  const manifestBytes = await readStablePackageFile(manifestPath, 'connector manifest')
  if (sha256(manifestBytes) !== expectedManifestSha256) {
    fail('CONNECTOR_MANIFEST_DIGEST_MISMATCH', 'connector manifest does not match the externally retained digest')
  }
  let manifest
  try { manifest = JSON.parse(manifestBytes.toString('utf8')) } catch {
    fail('CONNECTOR_MANIFEST_INVALID', 'connector manifest is not valid JSON')
  }
  assertValidGeneratedConnectorManifest(manifest)
  for (const item of manifest.files) {
    const bytes = await readStablePackageFile(join(packageDirectory, item.path), `connector file ${item.path}`)
    if (sha256(bytes) !== item.sha256) {
      fail('CONNECTOR_PACKAGE_DIGEST_MISMATCH', 'connector file does not match the externally anchored manifest')
    }
  }
  const directoryAfter = await lstat(packageDirectory)
  if (
    !directoryAfter.isDirectory()
    || directoryAfter.isSymbolicLink()
    || directoryAfter.dev !== directoryBefore.dev
    || directoryAfter.ino !== directoryBefore.ino
    || !pathEqual(await realpath(packageDirectory), packageDirectory)
  ) fail('CONNECTOR_PACKAGE_CHANGED', 'connector package changed while it was verified')
  return {
    status: 'SUCCEEDED',
    output_path: packageDirectory,
    manifest_path: manifestPath,
    manifest_sha256: expectedManifestSha256,
    content_sha256: manifest.content_sha256,
    contract_id: manifest.contract_id,
    contract_sha256: manifest.contract_sha256,
    package_name: manifest.package_name,
    files_verified: manifest.files.length + 1,
  }
}
