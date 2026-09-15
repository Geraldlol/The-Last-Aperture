import {
  closeSync,
  constants as fsConstants,
  fstatSync,
  fsyncSync,
  lstatSync,
  linkSync,
  openSync,
  readdirSync,
  readSync,
  realpathSync,
  renameSync,
  unlinkSync,
  writeSync,
} from 'node:fs'
import { randomBytes } from 'node:crypto'
import { chmod, lstat, open, readFile, realpath } from 'node:fs/promises'
import { spawnSync } from 'node:child_process'
import { homedir } from 'node:os'
import {
  isAbsolute,
  dirname,
  join,
  parse,
  posix,
  relative,
  resolve,
  win32,
} from 'node:path'
import { fileURLToPath } from 'node:url'

import Ajv2020 from 'ajv/dist/2020.js'

import { assertLocalFilesystemEndpoint } from './filesystem-endpoint.mjs'
import { digestUnleashValue } from './unleash-contracts.mjs'
import { createUnleashDeploymentPolicy } from './unleash-policy.mjs'

const MAX_CONTROLLER_JSON_BYTES = 64 * 1024
const READ_FLAGS = fsConstants.O_RDONLY
  | (fsConstants.O_NOFOLLOW ?? 0)
  | (fsConstants.O_NONBLOCK ?? 0)
const CREATE_FLAGS = fsConstants.O_WRONLY
  | fsConstants.O_CREAT
  | fsConstants.O_EXCL
  | (fsConstants.O_NOFOLLOW ?? 0)
const POLICY_FILE = 'deployment-policy.json'
const REVOCATIONS_FILE = 'revocations.json'
const HIGH_WATER_FILE = '.revocation-high-water.json'
const HIGH_WATER_LOCK_FILE = '.revocation-high-water.lock'
const HIGH_WATER_TEMP_FILE = '.revocation-high-water.tmp'
const HIGH_WATER_LOCK_TEMP_PATTERN = /^\.revocation-high-water\.lock\.tmp-(\d+)-([a-f0-9]{32})$/u
const HIGH_WATER_LOCK_FIELDS = ['schema_version', 'kind', 'pid', 'acquired_at', 'nonce']
const REVOCATION_FIELDS = [
  'schema_version', 'kind', 'check_id', 'policy_sha256', 'generation',
  'updated_at', 'revoked_policy_ids',
]
const HIGH_WATER_FIELDS = ['schema_version', 'kind', 'entries']
const HIGH_WATER_ENTRY_FIELDS = [
  'policy_id', 'policy_sha256', 'check_id', 'high_generation',
  'high_updated_at', 'snapshot_sha256', 'revoked_policy_ids',
]
const CHECK_FIELDS = ['check_id', 'policy_id', 'target_id', 'checked_at']
const SHA256_PATTERN = /^[a-f0-9]{64}$/u
const ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:/-]{2,159}$/u
const MAX_HIGH_WATER_ENTRIES = 128
const REVOCATIONS_SCHEMA_URL = new URL('../../schemas/unleash-revocations.schema.json', import.meta.url)
const WIN32_DURABLE_MOVE_WORKER = fileURLToPath(
  new URL('./win32-durable-move-worker.ps1', import.meta.url),
)
const revocationsSchema = JSON.parse(await readFile(fileURLToPath(REVOCATIONS_SCHEMA_URL), 'utf8'))
const ajv = new Ajv2020({
  allErrors: true,
  strict: true,
  strictRequired: false,
  strictTypes: false,
  validateFormats: false,
})
const validateRevocationsSchema = ajv.compile(revocationsSchema)

const WINDOWS_ACL_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
$path = $env:LAST_APERTURE_ACL_PATH
if ([string]::IsNullOrWhiteSpace($path)) { exit 20 }
$current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$allowed = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::Ordinal)
[void]$allowed.Add($current.Value)
[void]$allowed.Add('S-1-5-18')
[void]$allowed.Add('S-1-5-32-544')
$attributes = [System.IO.File]::GetAttributes($path)
$sections = [System.Security.AccessControl.AccessControlSections]::Owner -bor [System.Security.AccessControl.AccessControlSections]::Access
if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
  $acl = [System.IO.Directory]::GetAccessControl($path, $sections)
} else {
  $acl = [System.IO.File]::GetAccessControl($path, $sections)
}
if (-not $acl.AreAccessRulesCanonical) { exit 21 }
$owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier])
if (-not $allowed.Contains($owner.Value)) { exit 22 }
$binary = $acl.GetSecurityDescriptorBinaryForm()
$raw = New-Object System.Security.AccessControl.RawSecurityDescriptor($binary, 0)
if ($null -eq $raw.DiscretionaryAcl) { exit 23 }
$writeMask = [int64]0
$writeMask = $writeMask -bor [int64][System.Security.AccessControl.FileSystemRights]::WriteData
$writeMask = $writeMask -bor [int64][System.Security.AccessControl.FileSystemRights]::AppendData
$writeMask = $writeMask -bor [int64][System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes
$writeMask = $writeMask -bor [int64][System.Security.AccessControl.FileSystemRights]::WriteAttributes
$writeMask = $writeMask -bor [int64][System.Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles
$writeMask = $writeMask -bor [int64][System.Security.AccessControl.FileSystemRights]::Delete
$writeMask = $writeMask -bor [int64][System.Security.AccessControl.FileSystemRights]::ChangePermissions
$writeMask = $writeMask -bor [int64][System.Security.AccessControl.FileSystemRights]::TakeOwnership
$writeMask = $writeMask -bor [int64]0x40000000 # GENERIC_WRITE
$writeMask = $writeMask -bor [int64]0x10000000 # GENERIC_ALL
foreach ($ace in $raw.DiscretionaryAcl) {
  if ($ace -isnot [System.Security.AccessControl.QualifiedAce]) { exit 24 }
  if ($ace.AceQualifier -ne [System.Security.AccessControl.AceQualifier]::AccessAllowed) { continue }
  if (([int64]$ace.AccessMask -band $writeMask) -eq 0) { continue }
  $sid = $ace.SecurityIdentifier.Value
  if ($allowed.Contains($sid)) { continue }
  $creatorOwnerIsInheritOnly = $sid -eq 'S-1-3-0' -and
    ([int]$ace.AceFlags -band [int][System.Security.AccessControl.AceFlags]::InheritOnly) -ne 0 -and
    ([int]$ace.AceFlags -band (
      [int][System.Security.AccessControl.AceFlags]::ObjectInherit -bor
      [int][System.Security.AccessControl.AceFlags]::ContainerInherit
    )) -ne 0
  if ($creatorOwnerIsInheritOnly) { continue }
  exit 25
}
[Console]::Out.Write('OK')
`
const WINDOWS_ACL_ENCODED = Buffer.from(WINDOWS_ACL_SCRIPT, 'utf16le').toString('base64')
const windowsAclCache = new Map()

export class UnleashPolicyLoaderError extends Error {
  constructor(code, message, { cause } = {}) {
    super(message, cause === undefined ? undefined : { cause })
    this.name = 'UnleashPolicyLoaderError'
    this.code = code
  }
}

function fail(code, message, cause) {
  throw new UnleashPolicyLoaderError(code, message, { cause })
}

function hasExactKeys(value, fields) {
  return value !== null
    && typeof value === 'object'
    && !Array.isArray(value)
    && Object.keys(value).toSorted().join(',') === [...fields].toSorted().join(',')
}

function sameFile(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.size === right.size
    && left.mtimeNs === right.mtimeNs
    && left.ctimeNs === right.ctimeNs
    && left.nlink === right.nlink
}

function windowsPowerShellExecutable() {
  const systemRoot = process.env.SystemRoot
  if (
    typeof systemRoot !== 'string'
    || !win32.isAbsolute(systemRoot)
    || systemRoot.length > 4096
    || /[\u0000-\u001f\u007f]/u.test(systemRoot)
  ) fail('UNLEASH_CONTROL_ACL_UNAVAILABLE', 'Windows controller verification helpers are unavailable')
  return {
    executable: win32.join(systemRoot, 'System32', 'WindowsPowerShell', 'v1.0', 'powershell.exe'),
    systemRoot,
  }
}

function windowsAuthorityCacheKey(path, metadata) {
  return [
    comparablePath(path),
    metadata.dev,
    metadata.ino,
    metadata.ctimeNs,
    metadata.mode,
    metadata.uid,
  ].join(':')
}

function assertWindowsEndpointAuthority(path, metadata) {
  const cacheKey = windowsAuthorityCacheKey(path, metadata)
  if (windowsAclCache.has(cacheKey)) return
  const { executable, systemRoot } = windowsPowerShellExecutable()
  const result = spawnSync(executable, [
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-EncodedCommand',
    WINDOWS_ACL_ENCODED,
  ], {
    encoding: 'utf8',
    env: {
      SystemRoot: systemRoot,
      WINDIR: systemRoot,
      TEMP: process.env.TEMP ?? '',
      TMP: process.env.TMP ?? '',
      LAST_APERTURE_ACL_PATH: path,
    },
    maxBuffer: 4096,
    timeout: 10_000,
    windowsHide: true,
  })
  if (
    result.error !== undefined
    || result.signal !== null
    || result.status !== 0
    || result.stdout !== 'OK'
  ) fail('UNLEASH_CONTROL_ACL_UNSAFE', 'controller authority ACL is unavailable or permits an untrusted writer')
  if (windowsAclCache.size >= 256) windowsAclCache.clear()
  windowsAclCache.set(cacheKey, true)
}

function assertPosixEndpointAuthority(metadata) {
  if (typeof process.getuid !== 'function') {
    fail('UNLEASH_CONTROL_OWNER_UNAVAILABLE', 'controller authority owner verification is unavailable')
  }
  if (
    metadata.uid !== BigInt(process.getuid())
    || (metadata.mode & 0o077n) !== 0n
  ) fail('UNLEASH_CONTROL_PERMISSIONS_UNSAFE', 'controller authority must be owned by the current account with no group or other access')
}

function assertEndpointAuthority(path, metadata) {
  if (process.platform === 'win32') assertWindowsEndpointAuthority(path, metadata)
  else assertPosixEndpointAuthority(metadata)
}

function comparablePath(value) {
  return process.platform === 'win32' ? value.toLowerCase() : value
}

function assertControlRoot(value) {
  if (
    typeof value !== 'string'
    || value.length < 1
    || value.length > 4096
    || /[\u0000-\u001f\u007f]/u.test(value)
    || !isAbsolute(value)
  ) fail('UNLEASH_CONTROL_ROOT_INVALID', 'controller root must be one absolute local path')
  try {
    assertLocalFilesystemEndpoint(value, 'controller root')
  } catch (cause) {
    fail(
      'UNLEASH_CONTROL_ROOT_INVALID',
      'controller root must be one absolute local path',
      cause,
    )
  }
  if (process.platform === 'win32' && /:/u.test(value.slice(2))) {
    fail('UNLEASH_CONTROL_ROOT_INVALID', 'controller root cannot use an alternate data stream')
  }
  return resolve(value)
}

function canonicalTimestamp(value) {
  const milliseconds = Date.parse(value)
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value
}

async function inspectEndpoint(path, expectedKind, { allowedFileLinks = [1n] } = {}) {
  const root = parse(path).root
  let current = root
  let metadata = await lstat(current, { bigint: true })
  for (const part of relative(root, path).split(/[\\/]/u).filter(Boolean)) {
    current = join(current, part)
    metadata = await lstat(current, { bigint: true })
    if (metadata.isSymbolicLink()) fail('UNLEASH_CONTROL_ENDPOINT_UNSAFE', 'controller state cannot traverse a link or junction')
  }
  const validKind = expectedKind === 'directory' ? metadata.isDirectory() : metadata.isFile()
  if (!validKind || metadata.isSymbolicLink()) {
    fail('UNLEASH_CONTROL_ENDPOINT_UNSAFE', `controller state endpoint is not a regular ${expectedKind}`)
  }
  if (expectedKind === 'file' && !allowedFileLinks.includes(metadata.nlink)) {
    fail('UNLEASH_CONTROL_ENDPOINT_UNSAFE', 'controller state must be one unlinked regular file')
  }
  const canonical = await realpath(path)
  if (comparablePath(canonical) !== comparablePath(path)) {
    fail('UNLEASH_CONTROL_ENDPOINT_UNSAFE', 'controller state path is not canonical and alias-free')
  }
  assertEndpointAuthority(canonical, metadata)
  return { metadata, path: canonical }
}

function inspectEndpointSync(path, expectedKind, { allowedFileLinks = [1n] } = {}) {
  const root = parse(path).root
  let current = root
  let metadata = lstatSync(current, { bigint: true })
  for (const part of relative(root, path).split(/[\\/]/u).filter(Boolean)) {
    current = join(current, part)
    metadata = lstatSync(current, { bigint: true })
    if (metadata.isSymbolicLink()) fail('UNLEASH_CONTROL_ENDPOINT_UNSAFE', 'controller state cannot traverse a link or junction')
  }
  const validKind = expectedKind === 'directory' ? metadata.isDirectory() : metadata.isFile()
  if (!validKind || metadata.isSymbolicLink()) {
    fail('UNLEASH_CONTROL_ENDPOINT_UNSAFE', `controller state endpoint is not a regular ${expectedKind}`)
  }
  if (expectedKind === 'file' && !allowedFileLinks.includes(metadata.nlink)) {
    fail('UNLEASH_CONTROL_ENDPOINT_UNSAFE', 'controller state must be one unlinked regular file')
  }
  const canonical = realpathSync(path)
  if (comparablePath(canonical) !== comparablePath(path)) {
    fail('UNLEASH_CONTROL_ENDPOINT_UNSAFE', 'controller state path is not canonical and alias-free')
  }
  assertEndpointAuthority(canonical, metadata)
  return { metadata, path: canonical }
}

function normalizedAllowedFileLinks(value) {
  if (
    value === undefined
    || !Array.isArray(value)
    || value.length < 1
    || value.some((item) => !Number.isSafeInteger(item) || item < 1 || item > 2)
  ) {
    return value === undefined ? [1n] : null
  }
  return [...new Set(value)].map((item) => BigInt(item))
}

export async function assertUnleashPrivateEndpoint(path, expectedKind, options = {}) {
  if (!['directory', 'file'].includes(expectedKind)) {
    fail('UNLEASH_CONTROL_ENDPOINT_KIND_INVALID', 'private endpoint kind must be directory or file')
  }
  if (
    options === null
    || typeof options !== 'object'
    || Array.isArray(options)
    || Object.keys(options).some((key) => key !== 'allowedFileLinks')
  ) fail('UNLEASH_CONTROL_ENDPOINT_OPTIONS_INVALID', 'private endpoint options are invalid')
  const allowedFileLinks = normalizedAllowedFileLinks(options.allowedFileLinks)
  if (allowedFileLinks === null) {
    fail('UNLEASH_CONTROL_ENDPOINT_OPTIONS_INVALID', 'private endpoint link bounds are invalid')
  }
  const absolute = assertControlRoot(path)
  try {
    return (await inspectEndpoint(absolute, expectedKind, { allowedFileLinks })).path
  } catch (cause) {
    if (cause instanceof UnleashPolicyLoaderError) throw cause
    fail('UNLEASH_CONTROL_ENDPOINT_UNSAFE', 'private endpoint is unavailable or unsafe', cause)
  }
}

export async function hardenUnleashPrivateEndpoint(path, expectedKind) {
  if (!['directory', 'file'].includes(expectedKind)) {
    fail('UNLEASH_CONTROL_ENDPOINT_KIND_INVALID', 'private endpoint kind must be directory or file')
  }
  const absolute = assertControlRoot(path)
  try {
    const metadata = await lstat(absolute, { bigint: true })
    const validKind = expectedKind === 'directory' ? metadata.isDirectory() : metadata.isFile()
    if (!validKind || metadata.isSymbolicLink() || (expectedKind === 'file' && metadata.nlink !== 1n)) {
      fail('UNLEASH_CONTROL_ENDPOINT_UNSAFE', `private endpoint is not a regular ${expectedKind}`)
    }
    if (process.platform === 'win32') {
      const { systemRoot } = windowsPowerShellExecutable()
      const whoami = spawnSync(
        win32.join(systemRoot, 'System32', 'whoami.exe'),
        ['/user', '/fo', 'csv', '/nh'],
        {
          encoding: 'utf8',
          env: { SystemRoot: systemRoot, WINDIR: systemRoot },
          maxBuffer: 4096,
          timeout: 10_000,
          windowsHide: true,
        },
      )
      const currentSid = whoami.stdout?.match(/S-[0-9]+(?:-[0-9]+)+/u)?.[0]
      if (
        whoami.error !== undefined
        || whoami.signal !== null
        || whoami.status !== 0
        || currentSid === undefined
      ) fail('UNLEASH_CONTROL_ACL_UNAVAILABLE', 'current Windows security identity is unavailable')
      const inheritance = expectedKind === 'directory' ? '(OI)(CI)' : ''
      const result = spawnSync(
        win32.join(systemRoot, 'System32', 'icacls.exe'),
        [
          absolute,
          '/inheritance:r',
          '/grant:r',
          `*${currentSid}:${inheritance}F`,
          `*S-1-5-18:${inheritance}F`,
          `*S-1-5-32-544:${inheritance}F`,
        ],
        {
        encoding: 'utf8',
        env: {
          SystemRoot: systemRoot,
          WINDIR: systemRoot,
        },
        maxBuffer: 4096,
        timeout: 10_000,
        windowsHide: true,
        },
      )
      if (
        result.error !== undefined
        || result.signal !== null
        || result.status !== 0
      ) fail(
        'UNLEASH_CONTROL_ACL_UNSAFE',
        'private endpoint ACL could not be restricted to trusted principals',
        new Error(`ACL helper exited ${String(result.status)}: ${String(result.stderr ?? '').slice(0, 1024)}`),
      )
      windowsAclCache.clear()
    } else {
      await chmod(absolute, expectedKind === 'directory' ? 0o700 : 0o600)
    }
    return await assertUnleashPrivateEndpoint(absolute, expectedKind)
  } catch (cause) {
    if (cause instanceof UnleashPolicyLoaderError) throw cause
    fail('UNLEASH_CONTROL_ENDPOINT_UNSAFE', 'private endpoint could not be hardened safely', cause)
  }
}

function assertBounded(metadata) {
  if (metadata.size < 1n || metadata.size > BigInt(MAX_CONTROLLER_JSON_BYTES)) {
    fail('UNLEASH_CONTROL_STATE_BOUNDS', 'controller JSON state is empty or exceeds 64 KiB')
  }
  return Number(metadata.size)
}

async function readControllerJson(path) {
  let handle
  try {
    const checked = await inspectEndpoint(path, 'file')
    const size = assertBounded(checked.metadata)
    handle = await open(checked.path, READ_FLAGS)
    const before = await handle.stat({ bigint: true })
    if (!before.isFile() || !sameFile(before, checked.metadata)) {
      fail('UNLEASH_CONTROL_STATE_CHANGED', 'controller state changed before it was read')
    }
    const buffer = Buffer.alloc(size + 1)
    let offset = 0
    while (offset < buffer.length) {
      const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset)
      if (bytesRead === 0) break
      offset += bytesRead
    }
    const after = await handle.stat({ bigint: true })
    const endpointAfter = await inspectEndpoint(path, 'file')
    if (offset !== size || !sameFile(before, after) || !sameFile(after, endpointAfter.metadata)) {
      fail('UNLEASH_CONTROL_STATE_CHANGED', 'controller state changed while it was read')
    }
    return JSON.parse(buffer.subarray(0, offset).toString('utf8'))
  } catch (cause) {
    if (cause instanceof UnleashPolicyLoaderError) throw cause
    fail('UNLEASH_CONTROL_STATE_INVALID', 'controller JSON state is unavailable or invalid', cause)
  } finally {
    await handle?.close()
  }
}

function readControllerJsonSync(path) {
  let descriptor
  try {
    const checked = inspectEndpointSync(path, 'file')
    const size = assertBounded(checked.metadata)
    descriptor = openSync(checked.path, READ_FLAGS)
    const before = fstatSync(descriptor, { bigint: true })
    if (!before.isFile() || !sameFile(before, checked.metadata)) {
      fail('UNLEASH_CONTROL_STATE_CHANGED', 'controller state changed before it was read')
    }
    const buffer = Buffer.alloc(size + 1)
    let offset = 0
    while (offset < buffer.length) {
      const bytesRead = readSync(descriptor, buffer, offset, buffer.length - offset, offset)
      if (bytesRead === 0) break
      offset += bytesRead
    }
    const after = fstatSync(descriptor, { bigint: true })
    const endpointAfter = inspectEndpointSync(path, 'file')
    if (offset !== size || !sameFile(before, after) || !sameFile(after, endpointAfter.metadata)) {
      fail('UNLEASH_CONTROL_STATE_CHANGED', 'controller state changed while it was read')
    }
    return JSON.parse(buffer.subarray(0, offset).toString('utf8'))
  } catch (cause) {
    if (cause instanceof UnleashPolicyLoaderError) throw cause
    fail('UNLEASH_CONTROL_STATE_INVALID', 'controller JSON state is unavailable or invalid', cause)
  } finally {
    if (descriptor !== undefined) closeSync(descriptor)
  }
}

function endpointExistsSync(path) {
  try {
    lstatSync(path, { bigint: true })
    return true
  } catch (cause) {
    if (cause?.code === 'ENOENT') return false
    fail('UNLEASH_CONTROL_STATE_INVALID', 'controller authority endpoint cannot be inspected', cause)
  }
}

function canonicalJsonBytes(value) {
  const bytes = Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8')
  if (bytes.length < 1 || bytes.length > MAX_CONTROLLER_JSON_BYTES) {
    fail('UNLEASH_CONTROL_STATE_BOUNDS', 'controller JSON state is empty or exceeds 64 KiB')
  }
  return bytes
}

function writeAllSync(descriptor, bytes) {
  let offset = 0
  while (offset < bytes.length) {
    const written = writeSync(descriptor, bytes, offset, bytes.length - offset, offset)
    if (written < 1) fail('UNLEASH_CONTROL_STATE_WRITE_FAILED', 'controller durable state could not be written completely')
    offset += written
  }
}

function createPrivateFileSync(path, bytes) {
  let descriptor
  try {
    descriptor = openSync(path, CREATE_FLAGS, 0o600)
    writeAllSync(descriptor, bytes)
    fsyncSync(descriptor)
    const before = fstatSync(descriptor, { bigint: true })
    const endpoint = inspectEndpointSync(path, 'file')
    if (!before.isFile() || before.size !== BigInt(bytes.length) || !sameFile(before, endpoint.metadata)) {
      fail('UNLEASH_CONTROL_STATE_CHANGED', 'controller durable state changed while it was written')
    }
    return { descriptor, metadata: before, path: endpoint.path }
  } catch (cause) {
    if (descriptor !== undefined) {
      try { closeSync(descriptor) } catch {}
    }
    if (cause instanceof UnleashPolicyLoaderError) throw cause
    fail('UNLEASH_CONTROL_STATE_WRITE_FAILED', 'controller durable state could not be created safely', cause)
  }
}

function fsyncDirectorySync(path) {
  if (process.platform === 'win32') return
  let descriptor
  try {
    descriptor = openSync(path, fsConstants.O_RDONLY | (fsConstants.O_DIRECTORY ?? 0))
    fsyncSync(descriptor)
  } catch (cause) {
    fail('UNLEASH_CONTROL_STATE_WRITE_FAILED', 'controller durable directory could not be synchronized', cause)
  } finally {
    if (descriptor !== undefined) closeSync(descriptor)
  }
}

function replaceFileDurablySync(source, destination) {
  if (process.platform !== 'win32') {
    try {
      renameSync(source, destination)
      fsyncDirectorySync(dirname(destination))
      return
    } catch (cause) {
      if (cause instanceof UnleashPolicyLoaderError) throw cause
      fail('UNLEASH_CONTROL_STATE_WRITE_FAILED', 'revocation high-water state could not be installed durably', cause)
    }
  }
  const { executable, systemRoot } = windowsPowerShellExecutable()
  const requestId = 1
  const result = spawnSync(executable, [
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-ExecutionPolicy',
    'Bypass',
    '-File',
    WIN32_DURABLE_MOVE_WORKER,
  ], {
    encoding: 'utf8',
    env: {
      SystemRoot: systemRoot,
      WINDIR: systemRoot,
      TEMP: process.env.TEMP ?? '',
      TMP: process.env.TMP ?? '',
    },
    input: `${JSON.stringify({
      id: requestId,
      source: resolve(source),
      destination: resolve(destination),
      replace: true,
    })}\n`,
    maxBuffer: 16 * 1024,
    timeout: 15_000,
    windowsHide: true,
  })
  let response
  const lines = (result.stdout ?? '').split(/\r?\n/u).filter((line) => line.trim() !== '')
  try {
    if (lines.length === 1) response = JSON.parse(lines[0])
  } catch {
    response = undefined
  }
  if (
    result.error !== undefined
    || result.signal !== null
    || result.status !== 0
    || response?.id !== requestId
    || response?.ok !== true
  ) fail('UNLEASH_CONTROL_STATE_PUBLICATION_AMBIGUOUS', 'Win32 revocation state publication was not durably acknowledged')
}

function processIsAlive(pid) {
  try {
    process.kill(pid, 0)
    return true
  } catch (cause) {
    return cause?.code !== 'ESRCH'
  }
}

function normalizeHighWaterLockOwner(value) {
  if (
    !hasExactKeys(value, HIGH_WATER_LOCK_FIELDS)
    || value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/unleash-revocation-high-water-lock'
    || !Number.isSafeInteger(value.pid)
    || value.pid < 1
    || !canonicalTimestamp(value.acquired_at)
    || !/^[a-f0-9]{32}$/u.test(value.nonce ?? '')
  ) fail('UNLEASH_REVOCATION_LOCK_INVALID', 'revocation durability lock owner record is invalid')
  return value
}

function readHighWaterLockSnapshot(root, path) {
  let descriptor
  try {
    const checked = inspectEndpointSync(path, 'file', { allowedFileLinks: [1n, 2n] })
    const size = assertBounded(checked.metadata)
    const aliasPaths = []
    if (checked.metadata.nlink === 2n) {
      let matchingAlias = false
      const entries = readdirSync(root)
      if (entries.length > 256) {
        fail('UNLEASH_REVOCATION_LOCK_INVALID', 'revocation lock alias inspection exceeded its entry bound')
      }
      for (const entry of entries) {
        if (!HIGH_WATER_LOCK_TEMP_PATTERN.test(entry)) continue
        const alias = lstatSync(join(root, entry), { bigint: true })
        if (
          alias.isFile()
          && !alias.isSymbolicLink()
          && alias.nlink === 2n
          && alias.dev === checked.metadata.dev
          && alias.ino === checked.metadata.ino
        ) {
          matchingAlias = true
          aliasPaths.push(join(root, entry))
        }
      }
      if (!matchingAlias) {
        fail('UNLEASH_REVOCATION_LOCK_INVALID', 'revocation lock has an unexplained hard-link alias')
      }
    }
    descriptor = openSync(checked.path, READ_FLAGS)
    const before = fstatSync(descriptor, { bigint: true })
    if (!sameFile(before, checked.metadata)) {
      fail('UNLEASH_CONTROL_STATE_CHANGED', 'revocation lock changed before it was read')
    }
    const bytes = Buffer.alloc(size)
    let offset = 0
    while (offset < bytes.length) {
      const read = readSync(descriptor, bytes, offset, bytes.length - offset, offset)
      if (read === 0) break
      offset += read
    }
    const after = fstatSync(descriptor, { bigint: true })
    const endpointAfter = inspectEndpointSync(path, 'file', { allowedFileLinks: [1n, 2n] })
    if (offset !== size || !sameFile(before, after) || !sameFile(after, endpointAfter.metadata)) {
      fail('UNLEASH_CONTROL_STATE_CHANGED', 'revocation lock changed while it was read')
    }
    let value
    try {
      value = normalizeHighWaterLockOwner(JSON.parse(bytes.toString('utf8')))
    } catch (cause) {
      if (cause instanceof UnleashPolicyLoaderError) throw cause
      fail('UNLEASH_REVOCATION_LOCK_INVALID', 'revocation durability lock owner record is invalid', cause)
    }
    return { aliasPaths, bytes, metadata: endpointAfter.metadata, value }
  } finally {
    if (descriptor !== undefined) closeSync(descriptor)
  }
}

function reclaimStaleHighWaterLock(root, path) {
  const snapshot = readHighWaterLockSnapshot(root, path)
  if (processIsAlive(snapshot.value.pid)) {
    fail('UNLEASH_REVOCATION_STATE_BUSY', 'revocation durability lock is already held')
  }
  const quarantine = join(
    root,
    `${HIGH_WATER_LOCK_FILE}.quarantine-${process.pid}-${randomBytes(16).toString('hex')}`,
  )
  try {
    renameSync(path, quarantine)
    const quarantined = readHighWaterLockSnapshot(root, quarantine)
    if (
      quarantined.metadata.dev !== snapshot.metadata.dev
      || quarantined.metadata.ino !== snapshot.metadata.ino
      || quarantined.metadata.size !== snapshot.metadata.size
      || !quarantined.bytes.equals(snapshot.bytes)
    ) fail('UNLEASH_CONTROL_STATE_CHANGED', 'stale revocation lock changed during identity-bound quarantine')
    unlinkSync(quarantine)
    for (const aliasPath of snapshot.aliasPaths) {
      const alias = inspectEndpointSync(aliasPath, 'file')
      if (
        alias.metadata.dev !== snapshot.metadata.dev
        || alias.metadata.ino !== snapshot.metadata.ino
      ) fail('UNLEASH_CONTROL_STATE_CHANGED', 'stale revocation lock alias changed during quarantine')
      unlinkSync(aliasPath)
    }
    fsyncDirectorySync(root)
  } catch (cause) {
    if (cause instanceof UnleashPolicyLoaderError) throw cause
    fail('UNLEASH_CONTROL_STATE_CHANGED', 'stale revocation lock could not be reclaimed safely', cause)
  }
}

function cleanupOrphanedHighWaterLockTemps(root, lockPath) {
  if (endpointExistsSync(lockPath)) return
  const entries = readdirSync(root)
  if (entries.length > 256) {
    fail('UNLEASH_REVOCATION_LOCK_INVALID', 'revocation lock recovery exceeded its entry bound')
  }
  for (const entry of entries) {
    const match = entry.match(HIGH_WATER_LOCK_TEMP_PATTERN)
    if (match === null) continue
    const ownerPid = Number(match[1])
    if (!Number.isSafeInteger(ownerPid) || ownerPid < 1 || processIsAlive(ownerPid)) {
      fail('UNLEASH_REVOCATION_STATE_BUSY', 'revocation lock publication is still in progress')
    }
    const path = join(root, entry)
    inspectEndpointSync(path, 'file')
    try {
      const snapshot = readHighWaterLockSnapshot(root, path)
      if (snapshot.value.pid !== ownerPid || snapshot.value.nonce !== match[2]) {
        fail('UNLEASH_REVOCATION_LOCK_INVALID', 'orphaned revocation lock identity does not match its filename')
      }
    } catch (cause) {
      if (!(cause instanceof UnleashPolicyLoaderError)) throw cause
      if (![
        'UNLEASH_CONTROL_STATE_BOUNDS',
        'UNLEASH_REVOCATION_LOCK_INVALID',
      ].includes(cause.code)) throw cause
    }
    quarantineAndRemovePrivateResidue(root, path, entry)
  }
}

function acquireHighWaterLock(root) {
  const path = join(root, HIGH_WATER_LOCK_FILE)
  cleanupOrphanedHighWaterLockTemps(root, path)
  for (let attempt = 0; attempt < 4; attempt += 1) {
    const nonce = randomBytes(16).toString('hex')
    const temporaryPath = join(root, `${HIGH_WATER_LOCK_FILE}.tmp-${process.pid}-${nonce}`)
    const bytes = canonicalJsonBytes({
      schema_version: '1.0.0',
      kind: 'last-aperture/unleash-revocation-high-water-lock',
      pid: process.pid,
      acquired_at: new Date().toISOString(),
      nonce,
    })
    const temporary = createPrivateFileSync(temporaryPath, bytes)
    closeSync(temporary.descriptor)
    try {
      linkSync(temporaryPath, path)
    } catch (cause) {
      try { unlinkSync(temporaryPath) } catch {}
      if (cause?.code !== 'EEXIST') throw cause
      reclaimStaleHighWaterLock(root, path)
      continue
    }
    try {
      const published = inspectEndpointSync(path, 'file', { allowedFileLinks: [2n] })
      const alias = inspectEndpointSync(temporaryPath, 'file', { allowedFileLinks: [2n] })
      if (
        published.metadata.dev !== alias.metadata.dev
        || published.metadata.ino !== alias.metadata.ino
        || published.metadata.size !== BigInt(bytes.length)
      ) fail('UNLEASH_CONTROL_STATE_CHANGED', 'revocation lock publication identity is inconsistent')
      unlinkSync(temporaryPath)
      fsyncDirectorySync(root)
      const endpoint = inspectEndpointSync(path, 'file')
      const descriptor = openSync(path, READ_FLAGS)
      const metadata = fstatSync(descriptor, { bigint: true })
      if (!sameFile(metadata, endpoint.metadata)) {
        closeSync(descriptor)
        fail('UNLEASH_CONTROL_STATE_CHANGED', 'revocation lock changed after publication')
      }
      return { descriptor, metadata, path }
    } catch (cause) {
      try { unlinkSync(temporaryPath) } catch {}
      throw cause
    }
  }
  fail('UNLEASH_REVOCATION_STATE_BUSY', 'revocation durability lock remained contended')
}

function releaseHighWaterLock(root, lock) {
  closeSync(lock.descriptor)
  const endpoint = inspectEndpointSync(lock.path, 'file')
  if (!sameFile(lock.metadata, endpoint.metadata)) {
    fail('UNLEASH_CONTROL_STATE_CHANGED', 'revocation durability lock changed while it was held')
  }
  try {
    unlinkSync(lock.path)
    fsyncDirectorySync(root)
  } catch (cause) {
    if (cause instanceof UnleashPolicyLoaderError) throw cause
    fail('UNLEASH_CONTROL_STATE_WRITE_FAILED', 'revocation durability lock could not be released safely', cause)
  }
}

function persistHighWaterSync(root, value) {
  const temporaryPath = join(root, HIGH_WATER_TEMP_FILE)
  const finalPath = join(root, HIGH_WATER_FILE)
  const expectedSha256 = digestUnleashValue(value)
  const created = createPrivateFileSync(temporaryPath, canonicalJsonBytes(value))
  closeSync(created.descriptor)
  replaceFileDurablySync(temporaryPath, finalPath)
  const persisted = readControllerJsonSync(finalPath)
  if (digestUnleashValue(persisted) !== expectedSha256) {
    fail('UNLEASH_CONTROL_STATE_CHANGED', 'revocation high-water state changed after durable installation')
  }
}

function quarantineAndRemovePrivateResidue(root, path, label) {
  const before = inspectEndpointSync(path, 'file')
  const quarantine = join(
    root,
    `${label}.quarantine-${process.pid}-${randomBytes(16).toString('hex')}`,
  )
  try {
    renameSync(path, quarantine)
    const after = inspectEndpointSync(quarantine, 'file')
    if (
      before.metadata.dev !== after.metadata.dev
      || before.metadata.ino !== after.metadata.ino
      || before.metadata.size !== after.metadata.size
    ) fail('UNLEASH_CONTROL_STATE_CHANGED', `${label} changed during identity-bound quarantine`)
    unlinkSync(quarantine)
    fsyncDirectorySync(root)
  } catch (cause) {
    if (cause instanceof UnleashPolicyLoaderError) throw cause
    fail('UNLEASH_CONTROL_STATE_CHANGED', `${label} could not be removed safely`, cause)
  }
}

function assertHighWaterCandidateDominates(candidate, stored) {
  for (const previous of stored.entries) {
    const next = candidate.entries.find((entry) => entry.policy_sha256 === previous.policy_sha256)
    if (
      next === undefined
      || next.policy_id !== previous.policy_id
      || next.check_id !== previous.check_id
      || next.high_generation < previous.high_generation
      || (
        next.high_generation === previous.high_generation
        && (
          next.snapshot_sha256 !== previous.snapshot_sha256
          || next.high_updated_at !== previous.high_updated_at
        )
      )
      || (
        next.high_generation > previous.high_generation
        && Date.parse(next.high_updated_at) <= Date.parse(previous.high_updated_at)
      )
      || previous.revoked_policy_ids.some((policyId) => !next.revoked_policy_ids.includes(policyId))
    ) fail('UNLEASH_REVOCATION_DURABILITY_INVALID', 'staged revocation high-water state does not dominate durable state')
  }
}

function recoverStagedHighWaterSync(root) {
  const temporaryPath = join(root, HIGH_WATER_TEMP_FILE)
  if (!endpointExistsSync(temporaryPath)) return
  inspectEndpointSync(temporaryPath, 'file')
  let candidate
  try {
    candidate = normalizeHighWater(readControllerJsonSync(temporaryPath))
  } catch (cause) {
    if (
      cause instanceof UnleashPolicyLoaderError
      && [
        'UNLEASH_CONTROL_STATE_INVALID',
        'UNLEASH_CONTROL_STATE_BOUNDS',
        'UNLEASH_REVOCATION_DURABILITY_INVALID',
      ].includes(cause.code)
    ) {
      quarantineAndRemovePrivateResidue(root, temporaryPath, HIGH_WATER_TEMP_FILE)
      return
    }
    throw cause
  }
  const finalPath = join(root, HIGH_WATER_FILE)
  const stored = endpointExistsSync(finalPath)
    ? normalizeHighWater(readControllerJsonSync(finalPath))
    : defaultHighWater()
  assertHighWaterCandidateDominates(candidate, stored)
  const expectedSha256 = digestUnleashValue(candidate)
  replaceFileDurablySync(temporaryPath, finalPath)
  const persisted = normalizeHighWater(readControllerJsonSync(finalPath))
  if (digestUnleashValue(persisted) !== expectedSha256) {
    fail('UNLEASH_CONTROL_STATE_CHANGED', 'recovered revocation high-water state changed during installation')
  }
}

function canonicalIdentifiers(value) {
  return Array.isArray(value)
    && value.length <= 10_000
    && value.every((item) => typeof item === 'string' && ID_PATTERN.test(item))
    && new Set(value).size === value.length
    && JSON.stringify(value) === JSON.stringify([...value].toSorted())
}

function normalizeHighWater(value) {
  if (
    !hasExactKeys(value, HIGH_WATER_FIELDS)
    || value.schema_version !== '1.0.0'
    || value.kind !== 'last-aperture/unleash-revocation-high-water'
    || !Array.isArray(value.entries)
    || value.entries.length < 1
    || value.entries.length > MAX_HIGH_WATER_ENTRIES
  ) fail('UNLEASH_REVOCATION_DURABILITY_INVALID', 'revocation high-water state violates its exact contract')
  const policyDigests = []
  for (const entry of value.entries) {
    if (
      !hasExactKeys(entry, HIGH_WATER_ENTRY_FIELDS)
      || !ID_PATTERN.test(entry.policy_id ?? '')
      || !SHA256_PATTERN.test(entry.policy_sha256 ?? '')
      || !ID_PATTERN.test(entry.check_id ?? '')
      || !Number.isSafeInteger(entry.high_generation)
      || entry.high_generation < 1
      || !canonicalTimestamp(entry.high_updated_at)
      || !SHA256_PATTERN.test(entry.snapshot_sha256 ?? '')
      || !canonicalIdentifiers(entry.revoked_policy_ids)
    ) fail('UNLEASH_REVOCATION_DURABILITY_INVALID', 'revocation high-water entry violates its exact contract')
    policyDigests.push(entry.policy_sha256)
  }
  if (
    new Set(policyDigests).size !== policyDigests.length
    || JSON.stringify(policyDigests) !== JSON.stringify([...policyDigests].toSorted())
  ) fail('UNLEASH_REVOCATION_DURABILITY_INVALID', 'revocation high-water entries must use unique canonical policy order')
  return value
}

function normalizeRevocations(value, expectedCheckId, expectedPolicySha256) {
  if (!hasExactKeys(value, REVOCATION_FIELDS) || !validateRevocationsSchema(value)) {
    fail('UNLEASH_REVOCATION_STATE_INVALID', 'revocation state violates its exact schema')
  }
  if (
    !canonicalTimestamp(value.updated_at)
    || value.check_id !== expectedCheckId
    || value.policy_sha256 !== expectedPolicySha256
  ) {
    fail('UNLEASH_REVOCATION_STATE_INVALID', 'revocation state does not match the loaded policy')
  }
  if (JSON.stringify(value.revoked_policy_ids) !== JSON.stringify([...value.revoked_policy_ids].toSorted())) {
    fail('UNLEASH_REVOCATION_STATE_INVALID', 'revoked policy identifiers must use canonical order')
  }
  return value
}

function defaultHighWater() {
  return {
    schema_version: '1.0.0',
    kind: 'last-aperture/unleash-revocation-high-water',
    entries: [],
  }
}

function reconcileHighWater(root, policy, policySha256, snapshot) {
  inspectEndpointSync(root, 'directory')
  const lock = acquireHighWaterLock(root)
  try {
    recoverStagedHighWaterSync(root)
    const statePath = join(root, HIGH_WATER_FILE)
    const stored = endpointExistsSync(statePath)
      ? normalizeHighWater(readControllerJsonSync(statePath))
      : defaultHighWater()
    const snapshotSha256 = digestUnleashValue(snapshot)
    const previous = stored.entries.find((entry) => entry.policy_sha256 === policySha256)
    if (previous !== undefined) {
      if (previous.policy_id !== policy.policy_id || previous.check_id !== policy.revocation.check_id) {
        fail('UNLEASH_REVOCATION_DURABILITY_INVALID', 'revocation high-water identity conflicts with the loaded policy')
      }
      if (
        snapshot.generation < previous.high_generation
        || (snapshot.generation === previous.high_generation && snapshotSha256 !== previous.snapshot_sha256)
        || (
          snapshot.generation > previous.high_generation
          && Date.parse(snapshot.updated_at) <= Date.parse(previous.high_updated_at)
        )
      ) fail('UNLEASH_REVOCATION_STATE_ROLLBACK', 'revocation snapshot is older than or conflicts with durable high-water state')
    }

    const durableRevokedPolicyIds = stored.entries.flatMap((entry) => entry.revoked_policy_ids)
    const revokedPolicyIds = [...new Set([
      ...durableRevokedPolicyIds,
      ...snapshot.revoked_policy_ids,
    ])].toSorted()
    const nextEntry = {
      policy_id: policy.policy_id,
      policy_sha256: policySha256,
      check_id: policy.revocation.check_id,
      high_generation: snapshot.generation,
      high_updated_at: snapshot.updated_at,
      snapshot_sha256: snapshotSha256,
      revoked_policy_ids: revokedPolicyIds,
    }
    const entries = stored.entries
      .filter((entry) => entry.policy_sha256 !== policySha256)
      .concat(nextEntry)
      .toSorted((left, right) => left.policy_sha256 === right.policy_sha256
        ? 0
        : left.policy_sha256 < right.policy_sha256 ? -1 : 1)
    const next = normalizeHighWater({ ...defaultHighWater(), entries })
    if (!endpointExistsSync(statePath) || digestUnleashValue(stored) !== digestUnleashValue(next)) {
      persistHighWaterSync(root, next)
    }
    return revokedPolicyIds.includes(policy.policy_id)
  } finally {
    releaseHighWaterLock(root, lock)
  }
}

function assertCheckRequest(value, policy) {
  if (
    !hasExactKeys(value, CHECK_FIELDS)
    || value.check_id !== policy.revocation.check_id
    || value.policy_id !== policy.policy_id
    || !/^target:sha256:[a-f0-9]{64}$/u.test(value.target_id ?? '')
    || !canonicalTimestamp(value.checked_at)
  ) fail('UNLEASH_REVOCATION_REQUEST_INVALID', 'revocation request does not match the loaded policy')
}

export function defaultUnleashControllerRoot({
  platform = process.platform,
  localAppData = process.env.LOCALAPPDATA,
  home = homedir(),
} = {}) {
  const paths = platform === 'win32' ? win32 : posix
  const base = platform === 'win32'
    ? (typeof localAppData === 'string' && paths.isAbsolute(localAppData)
        ? localAppData
        : paths.join(home, 'AppData', 'Local'))
    : paths.join(home, '.config')
  return paths.resolve(base, platform === 'win32' ? 'LastAperture' : 'last-aperture', 'controller')
}

export async function loadUnleashControllerPolicy({
  controlRoot = defaultUnleashControllerRoot(),
} = {}) {
  const root = assertControlRoot(controlRoot)
  await inspectEndpoint(root, 'directory')
  const policy = createUnleashDeploymentPolicy(await readControllerJson(join(root, POLICY_FILE)))
  const policySha256 = digestUnleashValue(policy)
  const initialRevocations = normalizeRevocations(
    await readControllerJson(join(root, REVOCATIONS_FILE)),
    policy.revocation.check_id,
    policySha256,
  )
  const initialUpdatedAt = Date.parse(initialRevocations.updated_at)
  if (
    initialUpdatedAt < Date.parse(policy.valid_from)
    || initialUpdatedAt > Date.parse(policy.valid_until)
    || initialUpdatedAt > Date.now()
  ) {
    fail('UNLEASH_REVOCATION_STATE_INVALID', 'revocation state falls outside the policy validity window or is future-dated')
  }
  const revocationsPath = join(root, REVOCATIONS_FILE)
  reconcileHighWater(root, policy, policySha256, initialRevocations)
  const isRevoked = (request) => {
    assertCheckRequest(request, policy)
    inspectEndpointSync(root, 'directory')
    const state = normalizeRevocations(
      readControllerJsonSync(revocationsPath),
      policy.revocation.check_id,
      policySha256,
    )
    const updatedAt = Date.parse(state.updated_at)
    const checkedAt = Date.parse(request.checked_at)
    if (
      updatedAt < Date.parse(policy.valid_from)
      || updatedAt > Date.parse(policy.valid_until)
      || updatedAt > Date.now()
      || updatedAt > checkedAt
    ) fail('UNLEASH_REVOCATION_STATE_ROLLBACK', 'revocation state is stale or future-dated')
    return reconcileHighWater(root, policy, policySha256, state)
  }
  return Object.freeze({ policy, isRevoked, control_root: root })
}
