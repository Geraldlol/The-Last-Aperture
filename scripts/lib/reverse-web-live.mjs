import { createHash } from 'node:crypto'

import { readHttpAuthedCampaignProjection, httpAuthedCandidateIdentity } from './http-authed-campaign-ledger.mjs'
import {
  httpAuthedAuthorizationEvidence,
  readAndVerifyHistoricalHttpAuthedAuthorization,
} from './http-authed-contracts.mjs'
import { readVerifiedHttpReconEvidence } from './http-recon-controller.mjs'
import { stableJson } from './run-engine.mjs'
import { importWebSessionEvidence } from './reverse-web-har.mjs'

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

export function digestVerifiedHttpReconSessionSource(verified) {
  return sha256(Buffer.from(stableJson(verified, 0), 'utf8'))
}

export function digestVerifiedHttpAuthedSessionSource({ scope, projection }) {
  return sha256(Buffer.from(stableJson({ scope, projection }, 0), 'utf8'))
}

function headerItems(items) {
  if (!Array.isArray(items)) return []
  return items.map((item) => ({
    name: typeof item === 'string' ? item : item.name,
    value: '',
  }))
}

function contentType(headers) {
  return headers.find(({ name }) => name === 'content-type')?.value
}

function reconRawEntry(observation) {
  const responseHeaders = headerItems(observation.response_headers)
  return {
    startedDateTime: observation.observed_at,
    time: observation.timing_ms.total_ms,
    request: {
      method: observation.method,
      url: observation.url,
      headers: [],
      cookies: [],
    },
    response: {
      status: observation.status_code,
      headers: responseHeaders,
      cookies: [],
      content: {
        ...(observation.body.truncated === false
          && observation.body.digest_scope === 'complete'
          ? { size: observation.body.size }
          : {}),
        ...(contentType(responseHeaders) === undefined
          ? {}
          : { mimeType: contentType(responseHeaders) }),
      },
    },
  }
}

function authenticatedRawEntry(action, state, scope) {
  const outcome = state?.phase_outcomes?.PROBE
  if (!Number.isSafeInteger(outcome?.status)) return null
  const carrierName = scope.credential?.session_adapter?.carrier?.name
  const requestHeaders = carrierName === undefined
    ? []
    : [{ name: carrierName, value: 'REDACTED' }]
  return {
    time: null,
    request: {
      method: action.method,
      url: action.url,
      headers: requestHeaders,
      cookies: [],
    },
    response: {
      status: outcome.status,
      headers: headerItems(outcome.header_names),
      cookies: [],
      content: {},
    },
  }
}

export async function importVerifiedHttpReconSessionEvidence({
  bundle,
  targetOrigins,
  targetPathPrefix = '/',
  pathLiterals = [],
  now,
  dependencies = {},
} = {}) {
  const readReconEvidence = dependencies.readVerifiedHttpReconEvidence
    ?? readVerifiedHttpReconEvidence
  const verified = await readReconEvidence({
    bundle,
    ...(now === undefined ? {} : { now }),
  })
  const sourceSha256 = digestVerifiedHttpReconSessionSource(verified)
  return importWebSessionEvidence(verified.observations.map(reconRawEntry), {
    sourceKind: 'HTTP_RECON',
    sourceSha256,
    targetOrigins,
    targetPathPrefix,
    pathLiterals,
    deriveHeaderValues: false,
  })
}

export async function importVerifiedHttpAuthedSessionEvidence({
  scopePath,
  ledgerDirectory,
  targetOrigins,
  targetPathPrefix = '/',
  pathLiterals = [],
  dependencies = {},
} = {}) {
  const readAuthorization = dependencies.readAndVerifyHistoricalHttpAuthedAuthorization
    ?? readAndVerifyHistoricalHttpAuthedAuthorization
  const readProjection = dependencies.readHttpAuthedCampaignProjection
    ?? readHttpAuthedCampaignProjection
  const verified = await readAuthorization({
    scopePath,
    requiredMode: 'OPERATOR_ATTESTED_AUTHED',
  })
  const assurance = httpAuthedAuthorizationEvidence(verified.scope)
  const projection = await readProjection({
    directory: ledgerDirectory,
    campaignGrantSha256: verified.campaignGrantSha256,
    authorizationBindingSha256: verified.authorizationBindingSha256,
    authorizationMode: assurance.authorizationMode,
    independentlyVerified: assurance.independentlyVerified,
    operatorId: verified.scope.authorization.operator_id,
  })
  const states = new Map(projection.actions.map((action) => [action.action_id, action]))
  const rawEntries = []
  for (const action of verified.scope.requests) {
    if (action.kind !== 'probe') continue
    const identity = httpAuthedCandidateIdentity({
      campaignGrantSha256: verified.campaignGrantSha256,
      candidateDraft: action,
    })
    const state = states.get(identity.actionId)
    if (state?.provenance !== 'SEALED_PLAN') continue
    const entry = authenticatedRawEntry(action, state, verified.scope)
    if (entry !== null) rawEntries.push(entry)
  }
  const sourceSha256 = digestVerifiedHttpAuthedSessionSource({
    scope: verified.scope,
    projection,
  })
  return importWebSessionEvidence(rawEntries, {
    sourceKind: 'HTTP_AUTHED_CAMPAIGN',
    sourceSha256,
    targetOrigins,
    targetPathPrefix,
    pathLiterals,
    deriveHeaderValues: false,
  })
}
