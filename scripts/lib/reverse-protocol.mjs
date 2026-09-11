import { createHash } from 'node:crypto'

import { assertValidReverseEvidence, digestReverseEvidence } from './reverse-contracts.mjs'
import { legacyV1AuthPath } from './reverse-v1-compat-semantics.mjs'
import { assertValidWebSessionEvidence, digestWebSessionEvidence, webPathTemplate } from './reverse-web-har.mjs'
import { stableJson } from './run-engine.mjs'

export const NATIVE_INTERACTION_CONTRACT_KIND = 'red-team-audit/native-interaction-contract'
export const NATIVE_INTERACTION_CONTRACT_PROTOCOL = 'native-interaction-contract-v1'

const HASH = /^[a-f0-9]{64}$/u
const ID = /^[a-z]+:[a-f0-9]{32}$/u
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069]/u
const WRITE_METHODS = new Set(['DELETE', 'PATCH', 'POST', 'PUT'])
const AUTH_PATH = /(?:^|\/)(?:auth|callback|login|logon|oauth|session|signin|signout|sso|token)(?:\/|$)/iu
const LOGOUT_PATH = /(?:^|\/)(?:logout|signout)(?:\/|$)/iu
const PAGINATION_PAGE = new Set(['limit', 'offset', 'page', 'pagesize', 'page_size', 'skip', 'take'])
const PAGINATION_CURSOR = new Set(['after', 'before', 'cursor', 'next', 'page_token'])
const REQUEST_ACTIONS = new Set(['APPLICATION_REQUEST', 'AUTH_REQUEST', 'AUTHENTICATED_REQUEST', 'CREDENTIAL_SUBMIT', 'SESSION_TERMINATION', 'TOKEN_EXCHANGE'])
const REQUEST_ACTION_BASES = new Set(['INFERRED_PATH', 'OBSERVED_CARRIERS', 'OBSERVED_SHAPE', 'UNCLASSIFIED'])
const RESPONSE_TRANSITIONS = new Set(['AUTH_CHALLENGE_OBSERVED', 'CREDENTIAL_CARRIER_OBSERVED', 'REDIRECT_DESTINATION_OBSERVED'])
const DESTINATION_CORRELATIONS = new Set(['AMBIGUOUS', 'NOT_OBSERVED', 'OBSERVED_NOT_LINKED', 'UNIQUE_WITHIN_3_STEPS'])
const FIELD_TYPES = new Set(['array', 'boolean', 'integer', 'null', 'number', 'object', 'string', 'unknown'])
const CARRIER = /^(?:body:[A-Za-z0-9_$@.:[\]-]{1,1024}|cookie:[A-Za-z0-9_$@.:[\]-]{1,128}|header:[!#$%&'*+.^_`|~0-9a-z-]{1,128})$/u
const FIELD_NAME = /^[A-Za-z0-9_$@.:[\]-]{1,128}$/u
const HEADER_NAME = /^[!#$%&'*+.^_`|~0-9a-z-]{1,128}$/u
const SENSITIVE_NAME = /(?:api[_-]?key|auth|bearer|client[_-]?secret|connection|credential|csrf|jwt|login|pass(?:word|wd)?|secret|session|ssn|token|user(?:name)?|xsrf)/iu
const SEMANTIC_NAME = /^(?:action|command|event|method|mode|op|operation|submit|task|view)$/iu
const ENDPOINT_PROVENANCE = new Set([
  'BURP_XML',
  'HTTP_AUTHED_CAMPAIGN',
  'HTTP_RECON',
  'WEB_HAR',
])
const NATIVE_SCHEMA_VERSIONS = new Set(['1.0.0', '1.1.0', '1.2.0'])
const MAX_AGGREGATE_WEB_ENTRIES = 20_000
const MAX_AGGREGATE_REVERSE_OBSERVATIONS = 20_000
const MAX_AGGREGATE_FIELDS = 100_000
const MAX_ENDPOINT_EXCHANGES = 10_000
const TEMPLATE_PATH_SEGMENT = /(?:^|\/)\{(?:hex|integer|segment|uuid|value|\.\.\.)\}(?:\/|$)/u
const REDACTION = Object.freeze({
  protocol_values_removed: true,
  credentials_removed: true,
  bodies_removed: true,
  value_like_names_masked: true,
})

function fail(message) {
  const error = new Error(message)
  error.name = 'NativeInteractionContractError'
  error.code = 'NATIVE_INTERACTION_CONTRACT_INVALID'
  throw error
}

function plain(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype
}

function exact(value, fields, label) {
  if (!plain(value)) fail(`${label} must be an object`)
  const actual = Object.keys(value).sort()
  const expected = [...fields].sort()
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) fail(`${label} contains a missing or unknown field`)
}

function text(value, label, maximum = 2048) {
  if (typeof value !== 'string' || value.length < 1 || value.length > maximum || value.trim() !== value || CONTROL.test(value)) fail(`${label} is invalid`)
}

function lexical(left, right) {
  return left < right ? -1 : left > right ? 1 : 0
}

function valueLikeName(value) {
  return /^[^@]+@[^@]+$/u.test(value)
    || /^\d{3}-\d{2}-\d{4}$/u.test(value)
    || /^\d{4}-\d{2}-\d{2}$/u.test(value)
    || /^\d+(?:[.-]\d+){2,}$/u.test(value)
    || /^\d+$/u.test(value)
    || /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/iu.test(value)
    || /^[0-9a-f]{16,}$/iu.test(value)
    || /^(?=.{24,}$)(?=.*(?:\d|[_-]))[A-Za-z0-9_-]+={0,2}$/u.test(value)
    || /^(?:[A-Za-z0-9_-]{6,}\.){2}[A-Za-z0-9_-]{6,}$/u.test(value)
}

function pathContainsValueLikeName(value) {
  return value.split('.').some((part) => valueLikeName(part.replaceAll('[]', '')))
}

function carrierContainsValueLikeName(value) {
  const separator = value.indexOf(':')
  return separator >= 0 && pathContainsValueLikeName(value.slice(separator + 1))
}

function unique(values) {
  return [...new Set(values)].sort(lexical)
}

function canonicalList(values, predicate = () => true) {
  return Array.isArray(values)
    && values.every(predicate)
    && values.every((value, index) => index === 0 || lexical(values[index - 1], value) < 0)
}

function endpointIdentity(origin, method, pathTemplate) {
  return `endpoint:${createHash('sha256').update(`${origin}\n${method}\n${pathTemplate}`).digest('hex').slice(0, 32)}`
}

function cloneField(item) {
  return {
    name: item.name,
    path: item.path,
    types: [...item.types],
    sensitive: item.sensitive,
    semantic_classes: [...item.semantic_classes],
  }
}

function mergeField(map, item) {
  const path = item.path ?? item.name
  const current = map.get(path) ?? {
    name: item.name,
    path,
    types: new Set(),
    sensitive: false,
    semantic_classes: new Set(),
  }
  item.types.forEach((value) => current.types.add(value))
  ;(item.semantic_classes ?? []).forEach((value) => current.semantic_classes.add(value))
  current.sensitive ||= item.sensitive
  map.set(path, current)
}

function finishFields(map) {
  return [...map.values()].map((item) => ({
    name: item.name,
    path: item.path,
    types: [...item.types].sort(lexical),
    sensitive: item.sensitive,
    semantic_classes: [...item.semantic_classes].sort(lexical),
  })).sort((a, b) => lexical(a.path, b.path))
}

function queryAsFields(parameters) {
  return parameters.map((item) => cloneField({ ...item, path: item.name }))
}

function sideEffect(entry) {
  if (AUTH_PATH.test(entry.request.path_template)) return { classification: 'UNKNOWN', basis: 'AUTH_FLOW' }
  const semantic = [...entry.request.query_parameters, ...entry.request.body.fields]
    .flatMap((item) => item.semantic_classes ?? [])
  if (entry.request.path_action_class === 'WRITE_ACTION' || semantic.includes('WRITE_ACTION')) return { classification: 'WRITE_CANDIDATE', basis: 'SEMANTIC_ACTION_CLASS' }
  if (entry.request.path_action_class === 'READ_ACTION' || semantic.includes('READ_ACTION')) return { classification: 'READ_CANDIDATE', basis: 'SEMANTIC_ACTION_CLASS' }
  if (entry.request.path_action_class === 'OTHER_ACTION') return { classification: 'UNKNOWN', basis: 'SEMANTIC_ACTION_CLASS' }
  if (WRITE_METHODS.has(entry.request.method)) return { classification: 'WRITE_CANDIDATE', basis: 'HTTP_METHOD_ONLY' }
  return { classification: 'UNKNOWN', basis: 'UNCLASSIFIED' }
}

function pagination(parameters) {
  const names = parameters.map((item) => item.name.toLowerCase())
  if (names.some((item) => PAGINATION_CURSOR.has(item))) return 'CURSOR_PARAMETER_OBSERVED'
  if (names.some((item) => PAGINATION_PAGE.has(item))) return 'OFFSET_OR_PAGE_PARAMETERS_OBSERVED'
  return 'NOT_OBSERVED'
}

function classifyAuthRequest(entry) {
  if (LOGOUT_PATH.test(entry.request.path_template)) return ['SESSION_TERMINATION', 'INFERRED_PATH']
  if (entry.request.body.fields.some((field) => /pass(?:word|wd)?/iu.test(field.name))) return ['CREDENTIAL_SUBMIT', 'OBSERVED_SHAPE']
  if (/token/iu.test(entry.request.path_template)) return ['TOKEN_EXCHANGE', 'INFERRED_PATH']
  if (AUTH_PATH.test(entry.request.path_template)) return ['AUTH_REQUEST', 'INFERRED_PATH']
  if (entry.request.credential_carriers.length > 0) return ['AUTHENTICATED_REQUEST', 'OBSERVED_CARRIERS']
  return ['APPLICATION_REQUEST', 'UNCLASSIFIED']
}

function responseTransitions(entry, candidates) {
  return unique([
    ...([401, 403].includes(entry.response.status) ? ['AUTH_CHALLENGE_OBSERVED'] : []),
    ...(entry.response.credential_carriers.length > 0 ? ['CREDENTIAL_CARRIER_OBSERVED'] : []),
    ...(candidates.length > 0 ? ['REDIRECT_DESTINATION_OBSERVED'] : []),
  ])
}

function mergeRedirect(map, key, item) {
  const current = map.get(key) ?? {
    source: item.source,
    field_path: item.field_path,
    origin: item.origin,
    path_template: item.path_template,
    queryParameters: new Map(),
  }
  item.query_parameters.forEach((field) => mergeField(current.queryParameters, field))
  map.set(key, current)
}

function aggregateEndpoints(entries) {
  const map = new Map()
  for (const entry of entries) {
    const id = endpointIdentity(entry.request.origin, entry.request.method, entry.request.path_template)
    const current = map.get(id) ?? {
      endpoint_id: id,
      origin: entry.request.origin,
      path_template: entry.request.path_template,
      method: entry.request.method,
      protocol_role: AUTH_PATH.test(entry.request.path_template) ? 'AUTH' : 'APPLICATION',
      sideEffect: sideEffect(entry),
      observations: 0,
      requestQuery: new Map(),
      requestFields: new Map(),
      requestTypes: new Set(),
      requestHeaders: new Set(),
      pathActionClasses: new Set(),
      statuses: new Set(),
      responseFields: new Map(),
      responseTypes: new Set(),
      requestCarriers: new Set(),
      responseCarriers: new Set(),
      requestCookies: new Set(),
      responseCookies: new Set(),
      redirects: new Map(),
      evidenceRefs: [],
      discoveredVia: new Set(),
      exchanges: [],
      pagination: 'NOT_OBSERVED',
      sequences: [],
    }
    if (current.exchanges.length >= MAX_ENDPOINT_EXCHANGES) fail('native endpoint exchange limit exceeded')
    current.observations += 1
    current.sequences.push({ capture_id: entry.capture_id, sequence: entry.sequence })
    current.exchanges.push(exchangeForEntry(entry))
    queryAsFields(entry.request.query_parameters).forEach((item) => mergeField(current.requestQuery, item))
    entry.request.body.fields.forEach((item) => mergeField(current.requestFields, item))
    if (entry.request.body.content_type) current.requestTypes.add(entry.request.body.content_type)
    entry.request.header_names.forEach((item) => current.requestHeaders.add(item))
    current.pathActionClasses.add(entry.request.path_action_class)
    current.statuses.add(entry.response.status)
    entry.response.body.fields.forEach((item) => mergeField(current.responseFields, item))
    if (entry.response.body.content_type) current.responseTypes.add(entry.response.body.content_type)
    entry.request.credential_carriers.forEach((item) => current.requestCarriers.add(item))
    entry.response.credential_carriers.forEach((item) => current.responseCarriers.add(item))
    entry.request.cookie_names.forEach((item) => current.requestCookies.add(item))
    entry.response.cookie_names.forEach((item) => current.responseCookies.add(item))
    if (entry.response.redirect) mergeRedirect(current.redirects, `LOCATION_HEADER\n${entry.response.redirect.origin}${entry.response.redirect.path_template}`, {
      source: 'LOCATION_HEADER', field_path: null, origin: entry.response.redirect.origin,
      path_template: entry.response.redirect.path_template,
      query_parameters: queryAsFields(entry.response.redirect.query_parameters),
    })
    for (const destination of entry.response.destinations) mergeRedirect(current.redirects, `RESPONSE_BODY_FIELD\n${destination.field_path}\n${destination.origin}${destination.path_template}`, {
      source: 'RESPONSE_BODY_FIELD', field_path: destination.field_path, origin: destination.origin,
      path_template: destination.path_template,
      query_parameters: queryAsFields(destination.query_parameters),
    })
    current.evidenceRefs.push(entry.observation_id)
    current.discoveredVia.add(entry.source_provenance)
    const observedSideEffect = sideEffect(entry)
    if (
      observedSideEffect.classification === 'WRITE_CANDIDATE'
      || (observedSideEffect.classification === 'READ_CANDIDATE' && current.sideEffect.classification === 'UNKNOWN')
    ) current.sideEffect = observedSideEffect
    const observedPagination = pagination(entry.request.query_parameters)
    if (
      observedPagination === 'CURSOR_PARAMETER_OBSERVED'
      || (observedPagination === 'OFFSET_OR_PAGE_PARAMETERS_OBSERVED' && current.pagination === 'NOT_OBSERVED')
    ) current.pagination = observedPagination
    map.set(id, current)
  }
  return map
}

function finishEndpoints(map, entries) {
  const entryBySequence = new Map()
  const latestReadByPath = new Map()
  for (const entry of entries) {
    entryBySequence.set(`${entry.capture_id}\n${entry.sequence}`, entry)
    if (entry.request.method === 'GET' || entry.request.method === 'HEAD') {
      const key = `${entry.capture_id}\n${entry.request.origin}\n${entry.request.path_template}`
      latestReadByPath.set(key, Math.max(latestReadByPath.get(key) ?? 0, entry.sequence))
    }
  }
  return [...map.values()].map((item) => {
    const fieldSemantics = [...item.requestFields.values(), ...item.requestQuery.values()]
      .flatMap((field) => [...field.semantic_classes])
    const aggregateSideEffect = item.protocol_role === 'AUTH'
      ? { classification: 'UNKNOWN', basis: 'AUTH_FLOW' }
      : item.pathActionClasses.has('WRITE_ACTION') || fieldSemantics.includes('WRITE_ACTION')
        ? { classification: 'WRITE_CANDIDATE', basis: 'SEMANTIC_ACTION_CLASS' }
        : item.pathActionClasses.has('READ_ACTION') || fieldSemantics.includes('READ_ACTION')
          ? { classification: 'READ_CANDIDATE', basis: 'SEMANTIC_ACTION_CLASS' }
          : item.pathActionClasses.has('OTHER_ACTION')
            ? { classification: 'UNKNOWN', basis: 'SEMANTIC_ACTION_CLASS' }
            : WRITE_METHODS.has(item.method)
              ? { classification: 'WRITE_CANDIDATE', basis: 'HTTP_METHOD_ONLY' }
              : { classification: 'UNKNOWN', basis: 'UNCLASSIFIED' }
    let retry = 'NOT_OBSERVED'
    for (const reference of item.sequences) {
      const observation = entryBySequence.get(`${reference.capture_id}\n${reference.sequence}`)
      const next = entryBySequence.get(`${reference.capture_id}\n${reference.sequence + 1}`)
      if (
        next
        && endpointIdentity(next.request.origin, next.request.method, next.request.path_template) === item.endpoint_id
        && (observation.response.status === 429 || observation.response.status >= 500)
      ) retry = 'RETRY_SEQUENCE_OBSERVED'
    }
    let verification = 'NOT_APPLICABLE'
    if (aggregateSideEffect.classification === 'WRITE_CANDIDATE') {
      verification = item.sequences.some((reference) => (
        (latestReadByPath.get(`${reference.capture_id}\n${item.origin}\n${item.path_template}`) ?? 0) > reference.sequence
      )) ? 'FOLLOWUP_READ_SAME_TEMPLATE_OBSERVED' : 'NOT_OBSERVED'
    }
    return {
      endpoint_id: item.endpoint_id,
      origin: item.origin,
      path_template: item.path_template,
      method: item.method,
      protocol_role: item.protocol_role,
      side_effect: aggregateSideEffect,
      observations: item.observations,
      request: {
        query_parameters: finishFields(item.requestQuery),
        fields: finishFields(item.requestFields),
        content_types: [...item.requestTypes].sort(lexical),
        header_names: [...item.requestHeaders].sort(lexical),
        path_action_classes: [...item.pathActionClasses].sort(lexical),
      },
      response: {
        statuses: [...item.statuses].sort((a, b) => a - b),
        fields: finishFields(item.responseFields),
        content_types: [...item.responseTypes].sort(lexical),
      },
      auth: {
        request_carriers: [...item.requestCarriers].sort(lexical),
        response_carriers: [...item.responseCarriers].sort(lexical),
        request_cookie_names: [...item.requestCookies].sort(lexical),
        response_cookie_names: [...item.responseCookies].sort(lexical),
      },
      redirects: [...item.redirects.values()].map(({ queryParameters, ...redirect }) => ({
        ...redirect,
        query_parameters: finishFields(queryParameters),
      })).sort((a, b) => lexical(`${a.source}${a.field_path ?? ''}${a.origin}${a.path_template}`, `${b.source}${b.field_path ?? ''}${b.origin}${b.path_template}`)),
      pagination: item.pagination,
      retry,
      write_verification: verification,
      discovered_via: [...item.discoveredVia].sort(lexical),
      evidence_refs: unique(item.evidenceRefs),
      exchanges: [...item.exchanges].sort(compareExchanges),
    }
  }).sort((a, b) => lexical(`${a.origin}\n${a.path_template}\n${a.method}`, `${b.origin}\n${b.path_template}\n${b.method}`))
}

function cloneDestination(item, source, fieldPath = null) {
  return {
    source,
    field_path: fieldPath,
    origin: item.origin,
    path_template: item.path_template,
    query_parameters: queryAsFields(item.query_parameters),
  }
}

function destinationKey(destination) {
  return stableJson(destination, 0)
}

function observedDestinations(entry) {
  const items = [
    ...(entry.response.redirect === null ? [] : [cloneDestination(entry.response.redirect, 'LOCATION_HEADER')]),
    ...entry.response.destinations.map((item) => cloneDestination(item, 'RESPONSE_BODY_FIELD', item.field_path)),
  ]
  const byKey = new Map(items.map((item) => [destinationKey(item), item]))
  return [...byKey.values()].sort((left, right) => lexical(destinationKey(left), destinationKey(right)))
}

function exchangeForEntry(entry) {
  const [action, actionBasis] = classifyAuthRequest(entry)
  return {
    evidence_ref: entry.observation_id,
    capture_id: entry.capture_id,
    provenance: entry.source_provenance,
    sequence: entry.sequence,
    request: {
      action,
      action_basis: actionBasis,
      credential_carriers: [...entry.request.credential_carriers],
    },
    response: {
      status: entry.response.status,
      credential_carriers: [...entry.response.credential_carriers],
      destinations: observedDestinations(entry),
    },
  }
}

function compareExchanges(left, right) {
  return lexical(left.capture_id, right.capture_id)
    || left.sequence - right.sequence
    || lexical(left.evidence_ref, right.evidence_ref)
}

function pathHasTemplateSegment(pathTemplate) {
  return TEMPLATE_PATH_SEGMENT.test(pathTemplate)
}

function destinationMatchesOperation(destination, origin, pathTemplate) {
  return !pathHasTemplateSegment(destination.path_template)
    && !pathHasTemplateSegment(pathTemplate)
    && origin === destination.origin
    && pathTemplate === destination.path_template
}

function destinationMatchesEntry(destination, entry) {
  return destinationMatchesOperation(destination, entry.request.origin, entry.request.path_template)
}

function correlateDestination(capture, index, candidates) {
  if (candidates.length === 0) return { correlation: 'NOT_OBSERVED', destination: null, next: null }
  const forward = capture.entries.slice(index + 1, index + 4)
  const matches = []
  for (const candidate of candidates) for (const entry of forward) {
    if (destinationMatchesEntry(candidate, entry)) matches.push({ candidate, entry })
  }
  if (matches.length === 1) return { correlation: 'UNIQUE_WITHIN_3_STEPS', destination: matches[0].candidate, next: matches[0].entry }
  if (candidates.length === 1 && matches.length === 0) return { correlation: 'OBSERVED_NOT_LINKED', destination: candidates[0], next: null }
  return { correlation: 'AMBIGUOUS', destination: null, next: null }
}

function authRelevant(entry) {
  return AUTH_PATH.test(entry.request.path_template)
    || entry.request.body.fields.some((field) => /pass(?:word|wd)?/iu.test(field.name))
    || entry.request.credential_carriers.length > 0
    || entry.response.credential_carriers.length > 0
    || [401, 403].includes(entry.response.status)
}

function authFlows(webEvidence, endpoints) {
  const exchangeByEvidence = new Map(endpoints.flatMap((endpoint) => endpoint.exchanges.map((exchange) => [exchange.evidence_ref, exchange])))
  return webEvidence
    .filter((capture) => capture.entries.length > 0 && capture.entries.some(authRelevant))
    .map((capture) => ({
      flow_id: `authflow:${createHash('sha256').update(capture.capture_id).digest('hex').slice(0, 32)}`,
      capture_id: capture.capture_id,
      origins: [...capture.origins],
      steps: capture.entries.map((entry, index) => {
        const exchange = exchangeByEvidence.get(entry.observation_id)
        if (exchange === undefined) fail('auth flow entry is missing its endpoint exchange')
        const destinationCandidates = exchange.response.destinations
        const correlated = correlateDestination(capture, index, destinationCandidates)
        return {
          sequence: entry.sequence,
          endpoint_id: endpointIdentity(entry.request.origin, entry.request.method, entry.request.path_template),
          request_action: exchange.request.action,
          request_action_basis: exchange.request.action_basis,
          response_transitions: responseTransitions(entry, destinationCandidates),
          inputs: [...exchange.request.credential_carriers],
          outputs: unique([
            ...exchange.response.credential_carriers,
            ...destinationCandidates.map((item) => `destination:${item.source.toLowerCase()}`),
          ]),
          response_status: exchange.response.status,
          redirect_endpoint_id: correlated.next === null
            ? null
            : endpointIdentity(correlated.next.request.origin, correlated.next.request.method, correlated.next.request.path_template),
          destination: correlated.destination,
          destination_candidates: destinationCandidates,
          destination_correlation: correlated.correlation,
          next_observation_id: correlated.next?.observation_id ?? null,
          evidence_ref: entry.observation_id,
        }
      }),
    }))
    .sort((left, right) => lexical(left.flow_id, right.flow_id))
}

function canonicalTime(value) {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value)) || new Date(value).toISOString() !== value) fail('generated_at must be a canonical timestamp')
  return value
}

function contractIdentity(value) {
  const { contract_id: ignored, ...material } = value
  return createHash('sha256').update(stableJson(material, 0)).digest('hex').slice(0, 32)
}

function aggregateFieldCount(webSessionEvidence) {
  let count = 0
  for (const capture of webSessionEvidence) for (const entry of capture.entries) {
    count += entry.request.query_parameters.length
      + entry.request.body.fields.length
      + entry.response.body.fields.length
      + (entry.response.redirect?.query_parameters.length ?? 0)
      + entry.response.destinations.reduce((sum, item) => sum + item.query_parameters.length, 0)
    if (count > MAX_AGGREGATE_FIELDS) fail('web session evidence aggregate field limit exceeded')
  }
  return count
}

export function buildNativeInteractionContract({ webSessionEvidence = [], reverseEvidence = [], generatedAt = new Date().toISOString() } = {}) {
  if (!Array.isArray(webSessionEvidence) || webSessionEvidence.length > 32) fail('web session evidence list is invalid')
  if (!Array.isArray(reverseEvidence) || reverseEvidence.length > 64) fail('reverse evidence list is invalid')
  const aggregateEntries = webSessionEvidence.reduce((sum, capture) => sum + (Array.isArray(capture?.entries) ? capture.entries.length : 0), 0)
  const aggregateReverseObservations = reverseEvidence.reduce((sum, evidence) => sum + (Array.isArray(evidence?.observations) ? evidence.observations.length : 0), 0)
  if (aggregateEntries > MAX_AGGREGATE_WEB_ENTRIES) fail('web session evidence aggregate entry limit exceeded')
  if (aggregateReverseObservations > MAX_AGGREGATE_REVERSE_OBSERVATIONS) fail('reverse evidence aggregate observation limit exceeded')
  webSessionEvidence.forEach(assertValidWebSessionEvidence)
  reverseEvidence.forEach(assertValidReverseEvidence)
  if (new Set(webSessionEvidence.map(({ capture_id: id }) => id)).size !== webSessionEvidence.length) fail('web session evidence captures must be distinct')
  if (new Set(reverseEvidence.map(digestReverseEvidence)).size !== reverseEvidence.length) fail('reverse evidence inputs must be distinct')
  canonicalTime(generatedAt)
  aggregateFieldCount(webSessionEvidence)
  const sourceProvenance = (kind) => ({
    BURP_XML: 'BURP_XML',
    HAR: 'WEB_HAR',
    HTTP_AUTHED_CAMPAIGN: 'HTTP_AUTHED_CAMPAIGN',
    HTTP_RECON: 'HTTP_RECON',
  })[kind]
  const allEntries = webSessionEvidence.flatMap((capture) => capture.entries.map((entry) => ({
    ...entry,
    capture_id: capture.capture_id,
    source_provenance: sourceProvenance(capture.source.kind),
  })))
  if (new Set(allEntries.map(({ observation_id: id }) => id)).size !== allEntries.length) fail('web session observations must be distinct across captures')
  const endpointMap = aggregateEndpoints(allEntries)
  const endpoints = finishEndpoints(endpointMap, allEntries)
  const webDigests = unique(webSessionEvidence.map(digestWebSessionEvidence))
  const reverseDigests = unique(reverseEvidence.map(digestReverseEvidence))
  const origins = unique(webSessionEvidence.flatMap((capture) => capture.origins))
  const artifacts = unique(reverseEvidence.map((evidence) => evidence.artifact.sha256))
  const pathLiterals = unique(webSessionEvidence.flatMap((capture) => capture.path_literals))
  const flows = authFlows(webSessionEvidence, endpoints)
  const gaps = [
    { code: 'CONTRACT_REQUIRES_OPERATOR_REVIEW', message: 'Observed shapes and inferred auth stages require review before implementing or replaying a connector.' },
    { code: 'WRITE_SUCCESS_PREDICATES_UNPROVEN', message: 'A status code or read-back sequence alone does not prove a write succeeded; define record-specific success, failure, and rollback predicates.' },
  ]
  const webEvidenceGapCodes = new Set(webSessionEvidence.flatMap((capture) => capture.gaps.map(({ code }) => code)))
  const propagatedWebGaps = [
    ['BODY_FIELDS_TRUNCATED', 'WEB_EVIDENCE_BODY_FIELDS_TRUNCATED', 'At least one source capture omitted body fields at its structural traversal or field cap.'],
    ['BODY_SHAPE_OMITTED_SIZE_LIMIT', 'WEB_EVIDENCE_BODY_SHAPE_OMITTED_SIZE_LIMIT', 'At least one source capture omitted a structured body shape because it exceeded the capture byte limit.'],
    ['BODY_SHAPE_MALFORMED', 'WEB_EVIDENCE_BODY_SHAPE_MALFORMED', 'At least one source capture declared JSON whose field shape could not be parsed.'],
    ['RESPONSE_DESTINATIONS_TRUNCATED', 'WEB_EVIDENCE_RESPONSE_DESTINATIONS_TRUNCATED', 'At least one source capture omitted response destinations at its traversal or destination cap.'],
  ]
  for (const [sourceCode, code, message] of propagatedWebGaps) {
    if (webEvidenceGapCodes.has(sourceCode)) gaps.push({ code, message })
  }
  if (webSessionEvidence.length < 2) gaps.push({ code: 'TEMPLATE_VARIANCE_UNCONFIRMED', message: 'Capture at least two synthetic sessions before treating path placeholders, cardinality, or optional fields as stable.' })
  if (reverseEvidence.length > 0) gaps.push({ code: 'NATIVE_OBSERVATIONS_REQUIRE_CORRELATION', message: 'Native observations are digest-linked only until an operator correlates call sites and time windows with protocol events.' })
  if (endpoints.length === 0) gaps.push({ code: 'NO_WEB_ENDPOINTS', message: 'No in-scope web endpoint observations were available.' })
  if (flows.some((flow) => flow.steps.some((step) => step.destination_correlation === 'AMBIGUOUS'))) gaps.push({ code: 'MULTIPLE_RESPONSE_DESTINATIONS_REQUIRE_REVIEW', message: 'At least one response exposed multiple destinations without one unique forward match; no transition link was inferred for that step.' })
  if (flows.some((flow) => flow.steps.some((step) => step.destination_candidates.some((destination) => pathHasTemplateSegment(destination.path_template))))) gaps.push({ code: 'REDACTED_DESTINATION_CORRELATION_UNPROVEN', message: 'At least one response destination contains a redacted path segment, so no transition link is inferred from path-template equality.' })
  const contract = {
    schema_version: webSessionEvidence.some((capture) => (
      ['HTTP_AUTHED_CAMPAIGN', 'HTTP_RECON'].includes(capture.source.kind)
    )) ? '1.2.0' : '1.1.0',
    kind: NATIVE_INTERACTION_CONTRACT_KIND,
    protocol: NATIVE_INTERACTION_CONTRACT_PROTOCOL,
    contract_id: `interaction:${'0'.repeat(32)}`,
    generated_at: generatedAt,
    basis: { web_session_evidence_sha256: webDigests, reverse_evidence_sha256: reverseDigests },
    subjects: { origins, artifact_sha256: artifacts, path_literals: pathLiterals },
    auth_flows: flows,
    endpoints,
    redaction: { ...REDACTION },
    status: 'DRAFT_OBSERVED',
    generated_client_status: 'CONTRACT_ONLY',
    security_verdict: 'NOT_ASSESSED',
    gaps,
  }
  contract.contract_id = `interaction:${contractIdentity(contract)}`
  return assertValidNativeInteractionContract(contract)
}

function assertHashList(values, label, maximum = 64) {
  if (!canonicalList(values, (value) => HASH.test(value)) || values.length > maximum) fail(`${label} is invalid`)
}

function assertTextList(values, label, maximum = 1024) {
  if (!canonicalList(values) || values.length > maximum) fail(`${label} is invalid`)
  values.forEach((value) => text(value, label, 1024))
}

function assertOrigin(value) {
  text(value, 'contract origin')
  let parsed
  try { parsed = new URL(value) } catch { fail('contract origin is invalid') }
  if (!['http:', 'https:'].includes(parsed.protocol) || parsed.origin !== value || parsed.pathname !== '/' || parsed.search || parsed.hash || parsed.username || parsed.password) fail('contract origin is invalid')
}

function assertField(field, label) {
  exact(field, ['name', 'path', 'semantic_classes', 'sensitive', 'types'], label)
  text(field.name, `${label} name`, 128)
  text(field.path, `${label} path`, 1024)
  if (!FIELD_NAME.test(field.name) || valueLikeName(field.name) || pathContainsValueLikeName(field.path) || field.sensitive !== SENSITIVE_NAME.test(field.name)) fail(`${label} sensitivity is invalid`)
  if (!canonicalList(field.types, (value) => FIELD_TYPES.has(value)) || field.types.length < 1) fail(`${label} types are invalid`)
  if (!canonicalList(field.semantic_classes, (value) => ['OTHER_ACTION', 'READ_ACTION', 'WRITE_ACTION'].includes(value)) || (!SEMANTIC_NAME.test(field.name) && field.semantic_classes.length > 0)) fail(`${label} semantic classes are invalid`)
}

function assertDestination(destination, pathLiterals, label = 'native endpoint destination') {
  exact(destination, ['field_path', 'origin', 'path_template', 'query_parameters', 'source'], label)
  if (!['LOCATION_HEADER', 'RESPONSE_BODY_FIELD'].includes(destination.source)) fail(`${label} source is invalid`)
  if (!(destination.field_path === null || (destination.source === 'RESPONSE_BODY_FIELD' && typeof destination.field_path === 'string'))) fail(`${label} field is invalid`)
  if (destination.source === 'LOCATION_HEADER' && destination.field_path !== null) fail(`${label} field is invalid`)
  if (destination.field_path !== null) text(destination.field_path, `${label} field`, 1024)
  if (destination.field_path !== null && pathContainsValueLikeName(destination.field_path)) fail(`${label} contains a value-like field path`)
  assertOrigin(destination.origin)
  if (webPathTemplateForContract(destination.path_template, pathLiterals) !== destination.path_template) fail(`${label} path is not canonical`)
  if (!Array.isArray(destination.query_parameters)) fail(`${label} query parameters are invalid`)
  destination.query_parameters.forEach((field) => assertField(field, `${label} query parameter`))
  if (!destination.query_parameters.every((field, index) => field.path === field.name && (index === 0 || lexical(destination.query_parameters[index - 1].path, field.path) < 0))) fail(`${label} query parameters are not canonical`)
}

function webPathTemplateForContract(path, pathLiterals) {
  return webPathTemplate(path, { pathLiterals })
}

function assertExchange(exchange, pathLiterals, schemaVersion) {
  const legacy = schemaVersion === '1.0.0'
  const fields = ['capture_id', 'evidence_ref', 'request', 'response', 'sequence']
  exact(exchange, legacy ? fields : [...fields, 'provenance'], 'native endpoint exchange')
  if (!/^web:[a-f0-9]{32}$/u.test(exchange.capture_id ?? '') || !/^webobs:[a-f0-9]{32}$/u.test(exchange.evidence_ref ?? '')) fail('native endpoint exchange identity is invalid')
  if (!legacy && !ENDPOINT_PROVENANCE.has(exchange.provenance)) fail('native endpoint exchange provenance is invalid')
  if (!Number.isSafeInteger(exchange.sequence) || exchange.sequence < 1 || exchange.sequence > 10_000) fail('native endpoint exchange sequence is invalid')
  exact(exchange.request, ['action', 'action_basis', 'credential_carriers'], 'native endpoint exchange request')
  if (!REQUEST_ACTIONS.has(exchange.request.action) || !REQUEST_ACTION_BASES.has(exchange.request.action_basis)) fail('native endpoint exchange request action is invalid')
  assertTextList(exchange.request.credential_carriers, 'native endpoint exchange request carriers')
  if (exchange.request.credential_carriers.some((value) => !CARRIER.test(value) || carrierContainsValueLikeName(value))) fail('native endpoint exchange request carrier is invalid')
  exact(exchange.response, ['credential_carriers', 'destinations', 'status'], 'native endpoint exchange response')
  if (!Number.isSafeInteger(exchange.response.status) || exchange.response.status < 0 || exchange.response.status > 999) fail('native endpoint exchange response status is invalid')
  assertTextList(exchange.response.credential_carriers, 'native endpoint exchange response carriers')
  if (exchange.response.credential_carriers.some((value) => !CARRIER.test(value) || carrierContainsValueLikeName(value))) fail('native endpoint exchange response carrier is invalid')
  if (!Array.isArray(exchange.response.destinations) || exchange.response.destinations.length > 64) fail('native endpoint exchange response destinations are invalid')
  exchange.response.destinations.forEach((destination) => assertDestination(destination, pathLiterals, 'native endpoint exchange response destination'))
  if (!exchange.response.destinations.every((destination, index) => index === 0 || lexical(destinationKey(exchange.response.destinations[index - 1]), destinationKey(destination)) < 0)) fail('native endpoint exchange response destinations are not canonical or distinct')
}

function expectedExchangeRequestAction(endpoint, exchange, schemaVersion) {
  const carriers = exchange.request.credential_carriers
  if (LOGOUT_PATH.test(endpoint.path_template)) return ['SESSION_TERMINATION', 'INFERRED_PATH']
  if (carriers.some((carrier) => carrier.startsWith('body:') && /pass(?:word|wd)?/iu.test(carrier.slice('body:'.length)))) return ['CREDENTIAL_SUBMIT', 'OBSERVED_SHAPE']
  if (/token/iu.test(endpoint.path_template)) return ['TOKEN_EXCHANGE', 'INFERRED_PATH']
  if ((schemaVersion === '1.0.0' ? legacyV1AuthPath(endpoint.path_template) : AUTH_PATH.test(endpoint.path_template))) return ['AUTH_REQUEST', 'INFERRED_PATH']
  if (carriers.length > 0) return ['AUTHENTICATED_REQUEST', 'OBSERVED_CARRIERS']
  return ['APPLICATION_REQUEST', 'UNCLASSIFIED']
}

function aggregateExchangeDestinations(exchanges) {
  const redirects = new Map()
  for (const exchange of exchanges) for (const destination of exchange.response.destinations) {
    mergeRedirect(redirects, `${destination.source}\n${destination.field_path ?? ''}\n${destination.origin}${destination.path_template}`, destination)
  }
  return [...redirects.values()].map(({ queryParameters, ...redirect }) => ({
    ...redirect,
    query_parameters: finishFields(queryParameters),
  })).sort((left, right) => lexical(`${left.source}${left.field_path ?? ''}${left.origin}${left.path_template}`, `${right.source}${right.field_path ?? ''}${right.origin}${right.path_template}`))
}

function assertEndpoint(endpoint, pathLiterals, schemaVersion) {
  const legacy = schemaVersion === '1.0.0'
  const fields = ['auth', 'endpoint_id', 'evidence_refs', 'exchanges', 'method', 'observations', 'origin', 'pagination', 'path_template', 'protocol_role', 'redirects', 'request', 'response', 'retry', 'side_effect', 'write_verification']
  exact(endpoint, [...fields, 'discovered_via'], 'native endpoint')
  if (!/^endpoint:[a-f0-9]{32}$/u.test(endpoint.endpoint_id ?? '')) fail('native endpoint id is invalid')
  assertOrigin(endpoint.origin)
  if (webPathTemplateForContract(endpoint.path_template, pathLiterals) !== endpoint.path_template) fail('native endpoint path is not canonical')
  if (!/^[!#$%&'*+.^_`|~0-9A-Z-]{1,32}$/u.test(endpoint.method ?? '')) fail('native endpoint method is invalid')
  if (endpoint.endpoint_id !== endpointIdentity(endpoint.origin, endpoint.method, endpoint.path_template)) fail('native endpoint id does not match its operation')
  if (!['APPLICATION', 'AUTH'].includes(endpoint.protocol_role)) fail('native endpoint protocol role is invalid')
  exact(endpoint.side_effect, ['basis', 'classification'], 'native endpoint side effect')
  if (!['READ_CANDIDATE', 'UNKNOWN', 'WRITE_CANDIDATE'].includes(endpoint.side_effect.classification) || !['AUTH_FLOW', 'HTTP_METHOD_ONLY', 'SEMANTIC_ACTION_CLASS', 'UNCLASSIFIED'].includes(endpoint.side_effect.basis)) fail('native endpoint side-effect class is invalid')
  if (!Number.isSafeInteger(endpoint.observations) || endpoint.observations < 1 || endpoint.observations > 10_000) fail('native endpoint observation count is invalid')
  exact(endpoint.request, ['content_types', 'fields', 'header_names', 'path_action_classes', 'query_parameters'], 'native endpoint request')
  if (!Array.isArray(endpoint.request.fields) || !Array.isArray(endpoint.request.query_parameters)) fail('native endpoint request fields are invalid')
  endpoint.request.fields.forEach((field) => assertField(field, 'native request field'))
  endpoint.request.query_parameters.forEach((field) => assertField(field, 'native query parameter'))
  if (!endpoint.request.fields.every((field, index) => index === 0 || lexical(endpoint.request.fields[index - 1].path, field.path) < 0)) fail('native request fields are not canonical')
  if (!endpoint.request.query_parameters.every((field, index) => field.path === field.name && (index === 0 || lexical(endpoint.request.query_parameters[index - 1].path, field.path) < 0))) fail('native query parameters are not canonical')
  if (!canonicalList(endpoint.request.path_action_classes, (value) => ['NONE', 'OTHER_ACTION', 'READ_ACTION', 'WRITE_ACTION'].includes(value)) || endpoint.request.path_action_classes.length < 1) fail('native request path action classes are invalid')
  assertTextList(endpoint.request.content_types, 'native request content types', 64)
  if (endpoint.request.content_types.some((value) => !/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/u.test(value))) fail('native request content type is invalid')
  assertTextList(endpoint.request.header_names, 'native request header names', 256)
  if (endpoint.request.header_names.some((value) => !HEADER_NAME.test(value))) fail('native request header name is invalid')
  exact(endpoint.response, ['content_types', 'fields', 'statuses'], 'native endpoint response')
  if (!Array.isArray(endpoint.response.fields) || !Array.isArray(endpoint.response.statuses) || endpoint.response.statuses.some((status) => !Number.isSafeInteger(status) || status < 0 || status > 999)) fail('native endpoint response is invalid')
  endpoint.response.fields.forEach((field) => assertField(field, 'native response field'))
  if (!endpoint.response.fields.every((field, index) => index === 0 || lexical(endpoint.response.fields[index - 1].path, field.path) < 0)) fail('native response fields are not canonical')
  if (!endpoint.response.statuses.every((status, index) => index === 0 || endpoint.response.statuses[index - 1] < status)) fail('native endpoint statuses are not canonical')
  assertTextList(endpoint.response.content_types, 'native response content types', 64)
  if (endpoint.response.content_types.some((value) => !/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/u.test(value))) fail('native response content type is invalid')
  exact(endpoint.auth, ['request_carriers', 'request_cookie_names', 'response_carriers', 'response_cookie_names'], 'native endpoint auth')
  assertTextList(endpoint.auth.request_carriers, 'native endpoint auth carriers')
  if (endpoint.auth.request_carriers.some((value) => !CARRIER.test(value) || carrierContainsValueLikeName(value))) fail('native endpoint auth carrier is invalid')
  assertTextList(endpoint.auth.response_carriers, 'native endpoint response auth carriers')
  if (endpoint.auth.response_carriers.some((value) => !CARRIER.test(value) || carrierContainsValueLikeName(value))) fail('native endpoint response auth carrier is invalid')
  assertTextList(endpoint.auth.request_cookie_names, 'native endpoint request cookies')
  assertTextList(endpoint.auth.response_cookie_names, 'native endpoint response cookies')
  if (endpoint.auth.request_cookie_names.some((value) => !FIELD_NAME.test(value) || valueLikeName(value)) || endpoint.auth.response_cookie_names.some((value) => !FIELD_NAME.test(value) || valueLikeName(value))) fail('native endpoint cookie name is invalid')
  if (!Array.isArray(endpoint.redirects) || endpoint.redirects.length > 64) fail('native endpoint redirects are invalid')
  endpoint.redirects.forEach((redirect) => assertDestination(redirect, pathLiterals))
  if (!endpoint.redirects.every((redirect, index) => index === 0 || lexical(`${endpoint.redirects[index - 1].source}${endpoint.redirects[index - 1].field_path ?? ''}${endpoint.redirects[index - 1].origin}${endpoint.redirects[index - 1].path_template}`, `${redirect.source}${redirect.field_path ?? ''}${redirect.origin}${redirect.path_template}`) < 0)) fail('native endpoint redirects are not canonical')
  if (!['CURSOR_PARAMETER_OBSERVED', 'NOT_OBSERVED', 'OFFSET_OR_PAGE_PARAMETERS_OBSERVED'].includes(endpoint.pagination)) fail('native endpoint pagination is invalid')
  if (!['NOT_OBSERVED', 'RETRY_SEQUENCE_OBSERVED'].includes(endpoint.retry)) fail('native endpoint retry is invalid')
  if (!['FOLLOWUP_READ_SAME_TEMPLATE_OBSERVED', 'NOT_APPLICABLE', 'NOT_OBSERVED'].includes(endpoint.write_verification)) fail('native endpoint write verification is invalid')
  if (!canonicalList(endpoint.discovered_via, (value) => ENDPOINT_PROVENANCE.has(value)) || endpoint.discovered_via.length < 1 || endpoint.discovered_via.length > ENDPOINT_PROVENANCE.size) fail('native endpoint provenance is invalid')
  if (legacy && (endpoint.discovered_via.length !== 1 || endpoint.discovered_via[0] !== 'WEB_HAR')) fail('native interaction contract 1.0.0 supports HAR provenance only')
  if (!Array.isArray(endpoint.evidence_refs) || new Set(endpoint.evidence_refs).size !== endpoint.evidence_refs.length || endpoint.evidence_refs.some((value) => !/^webobs:[a-f0-9]{32}$/u.test(value))) fail('native endpoint evidence references are invalid')
  if (!canonicalList(endpoint.evidence_refs) || endpoint.observations !== endpoint.evidence_refs.length) fail('native endpoint observation references are inconsistent')
  if (!Array.isArray(endpoint.exchanges) || endpoint.exchanges.length < 1 || endpoint.exchanges.length > MAX_ENDPOINT_EXCHANGES) fail('native endpoint exchanges are invalid')
  endpoint.exchanges.forEach((exchange) => assertExchange(exchange, pathLiterals, schemaVersion))
  if (!endpoint.exchanges.every((exchange, index) => index === 0 || compareExchanges(endpoint.exchanges[index - 1], exchange) < 0)) fail('native endpoint exchanges are not canonical or distinct')
  if (new Set(endpoint.exchanges.map((exchange) => exchange.evidence_ref)).size !== endpoint.exchanges.length || new Set(endpoint.exchanges.map((exchange) => `${exchange.capture_id}\n${exchange.sequence}`)).size !== endpoint.exchanges.length) fail('native endpoint exchange identities are not distinct')
  if (stableJson(endpoint.evidence_refs, 0) !== stableJson(unique(endpoint.exchanges.map((exchange) => exchange.evidence_ref)), 0) || endpoint.observations !== endpoint.exchanges.length) fail('native endpoint exchanges do not match observation references')
  if (!legacy && stableJson(endpoint.discovered_via, 0) !== stableJson(unique(endpoint.exchanges.map((exchange) => exchange.provenance)), 0)) fail('native endpoint provenance does not match its exchanges')
  for (const exchange of endpoint.exchanges) {
    const [expectedAction, expectedBasis] = expectedExchangeRequestAction(endpoint, exchange, schemaVersion)
    if (exchange.request.action !== expectedAction || exchange.request.action_basis !== expectedBasis) fail('native endpoint exchange request action does not match its exact observation')
  }
  if (stableJson(endpoint.auth.request_carriers, 0) !== stableJson(unique(endpoint.exchanges.flatMap((exchange) => exchange.request.credential_carriers)), 0)) fail('native endpoint request carriers do not match its exchanges')
  if (stableJson(endpoint.auth.response_carriers, 0) !== stableJson(unique(endpoint.exchanges.flatMap((exchange) => exchange.response.credential_carriers)), 0)) fail('native endpoint response carriers do not match its exchanges')
  const exchangeStatuses = [...new Set(endpoint.exchanges.map((exchange) => exchange.response.status))].sort((left, right) => left - right)
  if (stableJson(endpoint.response.statuses, 0) !== stableJson(exchangeStatuses, 0)) fail('native endpoint response statuses do not match its exchanges')
  if (stableJson(endpoint.redirects, 0) !== stableJson(aggregateExchangeDestinations(endpoint.exchanges), 0)) fail('native endpoint redirects do not match its exchanges')
  const expectedRole = (legacy ? legacyV1AuthPath(endpoint.path_template) : AUTH_PATH.test(endpoint.path_template)) ? 'AUTH' : 'APPLICATION'
  if (endpoint.protocol_role !== expectedRole) fail('native endpoint protocol role does not match its path')
  const semanticClasses = [...endpoint.request.fields, ...endpoint.request.query_parameters].flatMap((field) => field.semantic_classes)
  const hasWriteClass = endpoint.request.path_action_classes.includes('WRITE_ACTION') || semanticClasses.includes('WRITE_ACTION')
  const hasReadClass = endpoint.request.path_action_classes.includes('READ_ACTION') || semanticClasses.includes('READ_ACTION')
  const hasOtherPathAction = endpoint.request.path_action_classes.includes('OTHER_ACTION')
  const expectedSideEffect = expectedRole === 'AUTH'
    ? { classification: 'UNKNOWN', basis: 'AUTH_FLOW' }
    : hasWriteClass
      ? { classification: 'WRITE_CANDIDATE', basis: 'SEMANTIC_ACTION_CLASS' }
      : hasReadClass
        ? { classification: 'READ_CANDIDATE', basis: 'SEMANTIC_ACTION_CLASS' }
        : hasOtherPathAction
          ? { classification: 'UNKNOWN', basis: 'SEMANTIC_ACTION_CLASS' }
          : WRITE_METHODS.has(endpoint.method)
            ? { classification: 'WRITE_CANDIDATE', basis: 'HTTP_METHOD_ONLY' }
            : { classification: 'UNKNOWN', basis: 'UNCLASSIFIED' }
  if (endpoint.side_effect.classification !== expectedSideEffect.classification || endpoint.side_effect.basis !== expectedSideEffect.basis) fail('native endpoint side effect does not match its observed shape')
  const expectedPagination = pagination(endpoint.request.query_parameters)
  if (endpoint.pagination !== expectedPagination) fail('native endpoint pagination does not match its query shape')
  if (
    (endpoint.side_effect.classification === 'WRITE_CANDIDATE' && endpoint.write_verification === 'NOT_APPLICABLE')
    || (endpoint.side_effect.classification !== 'WRITE_CANDIDATE' && endpoint.write_verification !== 'NOT_APPLICABLE')
  ) fail('native endpoint write verification does not match its side-effect class')
}

function assertAuthFlow(flow, pathLiterals) {
  exact(flow, ['capture_id', 'flow_id', 'origins', 'steps'], 'auth flow')
  if (!/^authflow:[a-f0-9]{32}$/u.test(flow.flow_id ?? '') || !/^web:[a-f0-9]{32}$/u.test(flow.capture_id ?? '')) fail('auth flow identity is invalid')
  const expectedFlowId = `authflow:${createHash('sha256').update(flow.capture_id).digest('hex').slice(0, 32)}`
  if (flow.flow_id !== expectedFlowId) fail('auth flow identity does not match its capture')
  if (!canonicalList(flow.origins) || flow.origins.length < 1) fail('auth flow origins are invalid')
  flow.origins.forEach(assertOrigin)
  if (!Array.isArray(flow.steps) || flow.steps.length > 10_000) fail('auth flow steps are invalid')
  let previousSequence = 0
  for (const step of flow.steps) {
    exact(step, ['destination', 'destination_candidates', 'destination_correlation', 'endpoint_id', 'evidence_ref', 'inputs', 'next_observation_id', 'outputs', 'redirect_endpoint_id', 'request_action', 'request_action_basis', 'response_status', 'response_transitions', 'sequence'], 'auth flow step')
    if (!Number.isSafeInteger(step.sequence) || step.sequence <= previousSequence || !/^endpoint:[a-f0-9]{32}$/u.test(step.endpoint_id ?? '') || !/^webobs:[a-f0-9]{32}$/u.test(step.evidence_ref ?? '')) fail('auth flow step identity is invalid')
    previousSequence = step.sequence
    if (!REQUEST_ACTIONS.has(step.request_action) || !REQUEST_ACTION_BASES.has(step.request_action_basis)) fail('auth flow request action is invalid')
    if (!canonicalList(step.response_transitions, (value) => RESPONSE_TRANSITIONS.has(value))) fail('auth flow response transitions are invalid')
    assertTextList(step.inputs, 'auth flow inputs')
    assertTextList(step.outputs, 'auth flow outputs')
    if (step.inputs.some((value) => !CARRIER.test(value) || carrierContainsValueLikeName(value)) || step.outputs.some((value) => !((CARRIER.test(value) && !carrierContainsValueLikeName(value)) || /^destination:(?:location_header|response_body_field)$/u.test(value)))) fail('auth flow carrier metadata is invalid')
    if (!Number.isSafeInteger(step.response_status) || step.response_status < 0 || step.response_status > 999) fail('auth flow response status is invalid')
    if (!(step.redirect_endpoint_id === null || /^endpoint:[a-f0-9]{32}$/u.test(step.redirect_endpoint_id))) fail('auth flow redirect is invalid')
    if (!(step.next_observation_id === null || /^webobs:[a-f0-9]{32}$/u.test(step.next_observation_id))) fail('auth flow next observation is invalid')
    if (step.destination !== null) assertDestination(step.destination, pathLiterals, 'auth flow destination')
    if (!Array.isArray(step.destination_candidates) || step.destination_candidates.length > 64) fail('auth flow destination candidates are invalid')
    step.destination_candidates.forEach((candidate) => assertDestination(candidate, pathLiterals, 'auth flow destination candidate'))
    if (!step.destination_candidates.every((candidate, index) => index === 0 || lexical(destinationKey(step.destination_candidates[index - 1]), destinationKey(candidate)) < 0)) fail('auth flow destination candidates are not canonical or distinct')
    if (!DESTINATION_CORRELATIONS.has(step.destination_correlation)) fail('auth flow destination correlation is invalid')
    const expectedDestinationOutputs = unique(step.destination_candidates.map((item) => `destination:${item.source.toLowerCase()}`))
    const observedDestinationOutputs = step.outputs.filter((item) => item.startsWith('destination:'))
    if (stableJson(expectedDestinationOutputs, 0) !== stableJson(observedDestinationOutputs, 0)) fail('auth flow destination outputs do not match its candidates')
    if (step.request_action === 'CREDENTIAL_SUBMIT' && step.request_action_basis !== 'OBSERVED_SHAPE') fail('credential submission basis is invalid')
    if (step.request_action === 'AUTHENTICATED_REQUEST' && (step.request_action_basis !== 'OBSERVED_CARRIERS' || step.inputs.length === 0)) fail('authenticated request basis is invalid')
    if (['AUTH_REQUEST', 'SESSION_TERMINATION', 'TOKEN_EXCHANGE'].includes(step.request_action) && step.request_action_basis !== 'INFERRED_PATH') fail('auth path request basis is invalid')
    if (step.request_action === 'APPLICATION_REQUEST' && step.request_action_basis !== 'UNCLASSIFIED') fail('application request basis is invalid')
    const expectedTransitions = unique([
      ...([401, 403].includes(step.response_status) ? ['AUTH_CHALLENGE_OBSERVED'] : []),
      ...(step.outputs.some((item) => CARRIER.test(item)) ? ['CREDENTIAL_CARRIER_OBSERVED'] : []),
      ...(step.destination_candidates.length > 0 ? ['REDIRECT_DESTINATION_OBSERVED'] : []),
    ])
    if (stableJson(step.response_transitions, 0) !== stableJson(expectedTransitions, 0)) fail('auth flow response transitions do not match its observed metadata')
    if (step.destination !== null && !step.destination_candidates.some((candidate) => destinationKey(candidate) === destinationKey(step.destination))) fail('auth flow selected destination is not one of its candidates')
    if (step.destination_correlation === 'NOT_OBSERVED' && (step.destination_candidates.length !== 0 || step.destination !== null || step.next_observation_id !== null || step.redirect_endpoint_id !== null)) fail('auth flow empty destination correlation is inconsistent')
    if (step.destination_correlation === 'OBSERVED_NOT_LINKED' && (step.destination_candidates.length !== 1 || destinationKey(step.destination) !== destinationKey(step.destination_candidates[0]) || step.next_observation_id !== null || step.redirect_endpoint_id !== null)) fail('auth flow unlinked destination correlation is inconsistent')
    if (step.destination_correlation === 'AMBIGUOUS' && (step.destination_candidates.length < 1 || step.destination !== null || step.next_observation_id !== null || step.redirect_endpoint_id !== null)) fail('auth flow ambiguous destination correlation is inconsistent')
    if (step.destination_correlation === 'UNIQUE_WITHIN_3_STEPS' && (step.destination === null || step.next_observation_id === null || step.redirect_endpoint_id === null)) fail('auth flow linked destination correlation is incomplete')
  }
}

export function assertValidNativeInteractionContract(value) {
  exact(value, ['auth_flows', 'basis', 'contract_id', 'endpoints', 'gaps', 'generated_at', 'generated_client_status', 'kind', 'protocol', 'redaction', 'schema_version', 'security_verdict', 'status', 'subjects'], 'native interaction contract')
  if (!NATIVE_SCHEMA_VERSIONS.has(value.schema_version) || value.kind !== NATIVE_INTERACTION_CONTRACT_KIND || value.protocol !== NATIVE_INTERACTION_CONTRACT_PROTOCOL || !/^interaction:[a-f0-9]{32}$/u.test(value.contract_id ?? '')) fail('native interaction contract identity is invalid')
  canonicalTime(value.generated_at)
  exact(value.basis, ['reverse_evidence_sha256', 'web_session_evidence_sha256'], 'native interaction basis')
  assertHashList(value.basis.web_session_evidence_sha256, 'web session evidence digests', 32)
  assertHashList(value.basis.reverse_evidence_sha256, 'reverse evidence digests')
  exact(value.subjects, ['artifact_sha256', 'origins', 'path_literals'], 'native interaction subjects')
  assertHashList(value.subjects.artifact_sha256, 'native artifact digests')
  if (!canonicalList(value.subjects.origins) || value.subjects.origins.length > 32) fail('native interaction origins are invalid')
  value.subjects.origins.forEach(assertOrigin)
  if (!canonicalList(value.subjects.path_literals, (item) => typeof item === 'string' && /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/u.test(item)) || value.subjects.path_literals.length > 128) fail('native interaction path literals are invalid')
  if (!Array.isArray(value.auth_flows) || value.auth_flows.length > 32) fail('native interaction auth flows are invalid')
  value.auth_flows.forEach((flow) => assertAuthFlow(flow, value.subjects.path_literals))
  if (!value.auth_flows.every((flow, index) => index === 0 || lexical(value.auth_flows[index - 1].flow_id, flow.flow_id) < 0)) fail('auth flows are not canonical or distinct')
  if (new Set(value.auth_flows.map(({ capture_id: id }) => id)).size !== value.auth_flows.length) fail('auth flow captures must be distinct')
  if (!Array.isArray(value.endpoints) || value.endpoints.length > 10_000) fail('native interaction endpoints are invalid')
  value.endpoints.forEach((endpoint) => assertEndpoint(endpoint, value.subjects.path_literals, value.schema_version))
  if (new Set(value.endpoints.map((endpoint) => endpoint.endpoint_id)).size !== value.endpoints.length) fail('native interaction endpoint ids must be unique')
  if (value.endpoints.some((endpoint) => !value.subjects.origins.includes(endpoint.origin))) fail('native endpoint origin is outside the contract subjects')
  if (value.endpoints.some((endpoint) => endpoint.redirects.some((redirect) => !value.subjects.origins.includes(redirect.origin)))) fail('native endpoint redirect is outside the contract subjects')
  if (value.auth_flows.some((flow) => flow.origins.some((origin) => !value.subjects.origins.includes(origin)))) fail('auth flow origin is outside the contract subjects')
  if (value.auth_flows.some((flow) => flow.steps.some((step) => step.destination !== null && !value.subjects.origins.includes(step.destination.origin)))) fail('auth flow destination is outside the contract subjects')
  exact(value.redaction, ['bodies_removed', 'credentials_removed', 'protocol_values_removed', 'value_like_names_masked'], 'native interaction redaction')
  if (Object.values(value.redaction).some((flag) => flag !== true)) fail('native interaction contract must remove values')
  if (value.status !== 'DRAFT_OBSERVED') fail('native interaction contract status is invalid')
  if (value.generated_client_status !== 'CONTRACT_ONLY') fail('generated client status is invalid')
  if (value.security_verdict !== 'NOT_ASSESSED') fail('native interaction contract cannot claim a security verdict')
  const expectedContractId = `interaction:${contractIdentity(value)}`
  if (value.contract_id !== expectedContractId) fail('native interaction contract id does not match its content')
  const endpointById = new Map(value.endpoints.map((endpoint) => [endpoint.endpoint_id, endpoint]))
  const evidenceToEndpoint = new Map()
  const exchangeByEvidence = new Map()
  const exchangeByCaptureSequence = new Map()
  let exchangeCount = 0
  for (const endpoint of value.endpoints) for (const exchange of endpoint.exchanges) {
    if (evidenceToEndpoint.has(exchange.evidence_ref)) fail('web observation cannot support multiple endpoint identities')
    const captureSequence = `${exchange.capture_id}\n${exchange.sequence}`
    if (exchangeByCaptureSequence.has(captureSequence)) fail('web observation capture sequence cannot support multiple exchanges')
    evidenceToEndpoint.set(exchange.evidence_ref, endpoint.endpoint_id)
    exchangeByEvidence.set(exchange.evidence_ref, exchange)
    exchangeByCaptureSequence.set(captureSequence, exchange)
    exchangeCount += 1
  }
  if (exchangeCount > MAX_AGGREGATE_WEB_ENTRIES) fail('native interaction aggregate exchange limit exceeded')
  const evidenceRefs = new Set(evidenceToEndpoint.keys())
  for (const flow of value.auth_flows) for (let index = 0; index < flow.steps.length; index += 1) {
    const step = flow.steps[index]
    const endpoint = endpointById.get(step.endpoint_id)
    const exchange = exchangeByEvidence.get(step.evidence_ref)
    if (!endpoint || !exchange || !evidenceRefs.has(step.evidence_ref)) fail('auth flow step is not linked to the endpoint exchange graph')
    if (evidenceToEndpoint.get(step.evidence_ref) !== step.endpoint_id) fail('auth flow evidence does not match its endpoint')
    if (exchange.capture_id !== flow.capture_id || exchange.sequence !== step.sequence) fail('auth flow step does not match its exact capture exchange')
    if (step.request_action !== exchange.request.action || step.request_action_basis !== exchange.request.action_basis || stableJson(step.inputs, 0) !== stableJson(exchange.request.credential_carriers, 0)) fail('auth flow request metadata does not match its exact exchange')
    const expectedOutputs = unique([
      ...exchange.response.credential_carriers,
      ...exchange.response.destinations.map((destination) => `destination:${destination.source.toLowerCase()}`),
    ])
    if (stableJson(step.outputs, 0) !== stableJson(expectedOutputs, 0) || step.response_status !== exchange.response.status) fail('auth flow response metadata does not match its exact exchange')
    if (stableJson(step.destination_candidates, 0) !== stableJson(exchange.response.destinations, 0)) fail('auth flow destinations do not match their exact exchange')
    if (step.request_action === 'CREDENTIAL_SUBMIT' && !endpoint.request.fields.some((field) => /pass(?:word|wd)?/iu.test(field.name))) fail('credential submission is not supported by its endpoint shape')
    if (step.request_action === 'AUTH_REQUEST' && endpoint.protocol_role !== 'AUTH') fail('auth request is not supported by its endpoint role')
    if (step.request_action === 'SESSION_TERMINATION' && !LOGOUT_PATH.test(endpoint.path_template)) fail('session termination is not supported by its endpoint path')
    if (step.request_action === 'TOKEN_EXCHANGE' && !/token/iu.test(endpoint.path_template)) fail('token exchange is not supported by its endpoint path')
    const future = flow.steps.slice(index + 1, index + 4)
    const matches = []
    for (const candidate of step.destination_candidates) for (const futureStep of future) {
      const futureEndpoint = endpointById.get(futureStep.endpoint_id)
      if (futureEndpoint && destinationMatchesOperation(candidate, futureEndpoint.origin, futureEndpoint.path_template)) matches.push({ candidate, futureStep })
    }
    const expectedCorrelation = step.destination_candidates.length === 0
      ? { correlation: 'NOT_OBSERVED', destination: null, futureStep: null }
      : matches.length === 1
        ? { correlation: 'UNIQUE_WITHIN_3_STEPS', destination: matches[0].candidate, futureStep: matches[0].futureStep }
        : step.destination_candidates.length === 1 && matches.length === 0
          ? { correlation: 'OBSERVED_NOT_LINKED', destination: step.destination_candidates[0], futureStep: null }
          : { correlation: 'AMBIGUOUS', destination: null, futureStep: null }
    if (step.destination_correlation !== expectedCorrelation.correlation || destinationKey(step.destination) !== destinationKey(expectedCorrelation.destination)) fail('auth flow destination correlation does not match its forward evidence window')
    if (expectedCorrelation.futureStep === null) {
      if (step.next_observation_id !== null || step.redirect_endpoint_id !== null) fail('auth flow transition link is unsupported')
    } else if (step.next_observation_id !== expectedCorrelation.futureStep.evidence_ref || step.redirect_endpoint_id !== expectedCorrelation.futureStep.endpoint_id) {
      fail('auth flow transition link does not match its forward evidence window')
    }
  }
  for (const flow of value.auth_flows) {
    const captureExchanges = [...exchangeByEvidence.values()]
      .filter((exchange) => exchange.capture_id === flow.capture_id)
      .sort((left, right) => left.sequence - right.sequence || lexical(left.evidence_ref, right.evidence_ref))
    if (
      captureExchanges.length !== flow.steps.length
      || flow.steps.some((step, index) => step.evidence_ref !== captureExchanges[index].evidence_ref || step.sequence !== captureExchanges[index].sequence)
    ) fail('auth flow steps do not cover their exact capture exchanges')
  }
  if (!Array.isArray(value.gaps) || value.gaps.length > 256) fail('native interaction gaps are invalid')
  for (const gap of value.gaps) {
    exact(gap, ['code', 'message'], 'native interaction gap')
    if (!/^[A-Z][A-Z0-9_]{2,95}$/u.test(gap.code ?? '')) fail('native interaction gap code is invalid')
    text(gap.message, 'native interaction gap message')
  }
  if (Buffer.byteLength(stableJson(value, 0), 'utf8') > 64 * 1024 * 1024) fail('native interaction contract exceeds its byte limit')
  return value
}

export function canonicalNativeInteractionContract(value) {
  assertValidNativeInteractionContract(value)
  return stableJson(value, 2)
}

export function digestNativeInteractionContract(value) {
  return createHash('sha256').update(canonicalNativeInteractionContract(value)).digest('hex')
}
