import { constants as fsConstants } from 'node:fs'
import { lstat, open } from 'node:fs/promises'
import { dispatchHttpAuthedProbe } from './http-authed-client.mjs'
import {
  canonicalJson,
  verifyHttpAuthedWrittenCandidate,
} from './http-authed-contracts.mjs'
import { resolveHttpAuthedCredential } from './http-authed-credential.mjs'

const OPEN_READ_ONLY_NO_FOLLOW = fsConstants.O_RDONLY
  | (typeof fsConstants.O_NOFOLLOW === 'number' ? fsConstants.O_NOFOLLOW : 0)
const INPUT_LIMITS = Object.freeze({
  scope: 64 * 1024 * 1024,
  authorization: 16 * 1024 * 1024,
  candidate: 4 * 1024 * 1024,
  body: 16 * 1024 * 1024,
})

export class HttpAuthedControllerError extends Error {
  constructor(code, message, options = {}) {
    super(message, options.cause ? { cause: options.cause } : undefined)
    this.name = 'HttpAuthedControllerError'
    this.code = code
  }
}

function controllerError(code, message, options) {
  return new HttpAuthedControllerError(code, message, options)
}

async function readStableBoundedFile(path, label, maxBytes, { minimum = 1 } = {}) {
  let info
  try {
    info = await lstat(path)
  } catch (cause) {
    throw controllerError('HTTP_AUTHED_INPUT_UNREADABLE', `${label} cannot be read`, { cause })
  }
  if (
    !info.isFile()
    || info.isSymbolicLink()
    || info.size < minimum
    || info.size > maxBytes
  ) {
    throw controllerError(
      'HTTP_AUTHED_INPUT_UNSAFE',
      `${label} must be a regular non-symlink file containing ${minimum} to ${maxBytes} bytes`,
    )
  }
  let handle
  try {
    handle = await open(path, OPEN_READ_ONLY_NO_FOLLOW)
    const before = await handle.stat()
    const bytes = await handle.readFile()
    const after = await handle.stat()
    if (
      before.size !== after.size
      || before.mtimeMs !== after.mtimeMs
      || before.ino !== after.ino
      || bytes.length !== after.size
    ) {
      throw controllerError('HTTP_AUTHED_INPUT_CHANGED', `${label} changed while it was read`)
    }
    return bytes
  } catch (cause) {
    if (cause instanceof HttpAuthedControllerError) throw cause
    throw controllerError('HTTP_AUTHED_INPUT_UNREADABLE', `${label} cannot be read`, { cause })
  } finally {
    await handle?.close()
  }
}

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'))
  } catch (cause) {
    throw controllerError('HTTP_AUTHED_JSON_INVALID', `${label} is not valid JSON`, { cause })
  }
}

export async function runHttpAuthedWrittenProbe({
  scopePath,
  authorizationDocumentPath,
  candidatePath,
  requestBodyPath,
  expectedCampaignGrantSha256,
  operatorId,
  authorizationConfirmed,
  env = process.env,
  transientCredential,
  credentialInput,
  credentialStdinReader,
  clock = () => new Date(),
  transport,
}) {
  if (authorizationConfirmed !== true) {
    throw controllerError(
      'HTTP_AUTHED_CURRENT_AUTHORIZATION_REQUIRED',
      'probe-written requires --confirm-authorization-current',
    )
  }
  const [scopeBytes, documentBytes, candidateBytes] = await Promise.all([
    readStableBoundedFile(scopePath, 'http-authed scope', INPUT_LIMITS.scope),
    readStableBoundedFile(
      authorizationDocumentPath,
      'written authorization document',
      INPUT_LIMITS.authorization,
    ),
    readStableBoundedFile(candidatePath, 'http-authed candidate', INPUT_LIMITS.candidate),
  ])
  const scope = parseJson(scopeBytes, 'http-authed scope')
  const action = parseJson(candidateBytes, 'http-authed candidate')
  const candidateBinding = canonicalJson(action)
  if (typeof operatorId !== 'string' || operatorId !== scope?.authorization?.operator_id) {
    throw controllerError(
      'HTTP_AUTHED_OPERATOR_MISMATCH',
      'probe-written operator must match the written campaign operator',
    )
  }
  let requestBodyBytes
  if (requestBodyPath !== undefined) {
    requestBodyBytes = await readStableBoundedFile(
      requestBodyPath,
      'synthetic request body',
      INPUT_LIMITS.body,
      { minimum: 0 },
    )
  }
  let credentialValue
  try {
    verifyHttpAuthedWrittenCandidate({
      scope,
      action,
      documentBytes,
      expectedCampaignGrantSha256,
      now: clock(),
    })
    credentialValue = await resolveHttpAuthedCredential({
      credential: scope.credential,
      env,
      transientCredential,
      credentialInput,
      readStdin: credentialStdinReader,
    })
  } catch (error) {
    requestBodyBytes?.fill(0)
    throw error
  }
  const beforeSend = async () => {
    const [currentScopeBytes, currentDocumentBytes, currentCandidateBytes] = await Promise.all([
      readStableBoundedFile(scopePath, 'http-authed scope', INPUT_LIMITS.scope),
      readStableBoundedFile(
        authorizationDocumentPath,
        'written authorization document',
        INPUT_LIMITS.authorization,
      ),
      readStableBoundedFile(candidatePath, 'http-authed candidate', INPUT_LIMITS.candidate),
    ])
    const currentScope = parseJson(currentScopeBytes, 'http-authed scope')
    const currentAction = parseJson(currentCandidateBytes, 'http-authed candidate')
    if (canonicalJson(currentAction) !== candidateBinding) {
      throw controllerError(
        'HTTP_AUTHED_CANDIDATE_CHANGED',
        'probe-written candidate changed before transport send',
      )
    }
    if (currentScope?.authorization?.operator_id !== operatorId) {
      throw controllerError(
        'HTTP_AUTHED_OPERATOR_MISMATCH',
        'probe-written operator changed before transport send',
      )
    }
    verifyHttpAuthedWrittenCandidate({
      scope: currentScope,
      action: currentAction,
      documentBytes: currentDocumentBytes,
      expectedCampaignGrantSha256,
      now: clock(),
    })
  }
  try {
    return await dispatchHttpAuthedProbe({
      scope,
      action,
      documentBytes,
      expectedCampaignGrantSha256,
      credentialValue,
      requestBodyBytes,
      now: clock(),
      transport,
      beforeSend,
    })
  } finally {
    credentialValue.fill(0)
    requestBodyBytes?.fill(0)
  }
}
