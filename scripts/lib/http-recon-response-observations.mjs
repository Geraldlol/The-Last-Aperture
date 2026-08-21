import { createHash } from 'node:crypto'
import { parse as parseJavaScript } from 'acorn'
import { compareCanonicalStrings } from './canonical-order.mjs'

const MAX_RESPONSE_BYTES = 1024 * 1024
const MAX_BUNDLE_PATHS = 4
const MAX_SCRIPT_TAGS = 256
const MAX_TAG_CHARACTERS = 8192
const CREDIBLE_ORIGIN = 'https://www.cbh3.crediblebh.com'
const CREDIBLE_ASSETS_ORIGIN = 'https://assets.cbh3.crediblebh.com'
const BUNDLE_PATH = /^\/assets\/bundle-[0-9]{8}_[0-9]{4}\.js$/u
const CROSS_ORIGIN_ANALYSIS_PROFILE = 'credible-cross-origin-js-ast-v1'
const MAX_AST_NODES = 16_384
const MAX_MESSAGE_LISTENERS = 256
const MAX_POST_MESSAGE_CALLS = 512
const MAX_TOKEN_LIKE_REFERENCES = 4096

const CROSS_ORIGIN_ARTIFACTS = Object.freeze([
  Object.freeze({
    url: `${CREDIBLE_ASSETS_ORIGIN}/js/cross-origin-messaging.js`,
    size: 10_332,
    sha256: 'a4abd91000f5d7d58c1c8d2dd378b7a5f1024b8c1579240c71c2a1819f903035',
  }),
  Object.freeze({
    url: `${CREDIBLE_ASSETS_ORIGIN}/js/global-cross-origin-helpers.js`,
    size: 20_524,
    sha256: '1029bd6288905eae865296a9a85ed1fd5c5b3c8d88fefa743caa6fe456deb412',
  }),
])

const PROFILE_DEFINITIONS = Object.freeze({
  'credible-bundle-src-v1': Object.freeze({
    method: 'GET',
    origin: CREDIBLE_ORIGIN,
    max_response_bytes: MAX_RESPONSE_BYTES,
    content_type: 'text/html',
    max_bundle_paths: MAX_BUNDLE_PATHS,
    path_pattern: BUNDLE_PATH.source,
  }),
  [CROSS_ORIGIN_ANALYSIS_PROFILE]: Object.freeze({
    method: 'GET',
    origin: CREDIBLE_ASSETS_ORIGIN,
    max_response_bytes: MAX_RESPONSE_BYTES,
    content_type: 'application/javascript',
    parser: 'acorn-8.15.0',
    artifacts: CROSS_ORIGIN_ARTIFACTS,
    max_ast_nodes: MAX_AST_NODES,
    max_message_listeners: MAX_MESSAGE_LISTENERS,
    max_post_message_calls: MAX_POST_MESSAGE_CALLS,
    max_token_like_references: MAX_TOKEN_LIKE_REFERENCES,
  }),
})

export const HTTP_RECON_RESPONSE_OBSERVATION_PROFILES = Object.freeze(
  Object.keys(PROFILE_DEFINITIONS).sort(compareCanonicalStrings),
)

function observationError(code, message) {
  const error = new Error(message)
  error.name = 'HttpReconResponseObservationError'
  error.code = code
  return error
}

function exactObject(value, label) {
  if (
    value === null
    || typeof value !== 'object'
    || Array.isArray(value)
    || Object.getPrototypeOf(value) !== Object.prototype
  ) {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_INVALID',
      `${label} must be an object`,
    )
  }
  return value
}

function definitionFor(profile) {
  const definition = PROFILE_DEFINITIONS[profile]
  if (definition === undefined) {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_PROFILE_UNKNOWN',
      'response-observation profile is not controller-defined',
    )
  }
  return definition
}

function exactUrl(value) {
  try {
    const parsed = new URL(value)
    if (
      parsed.protocol !== 'https:'
      || parsed.username !== ''
      || parsed.password !== ''
      || parsed.hash !== ''
    ) return null
    return parsed
  } catch {
    return null
  }
}

function bindingSha256(profile, definition) {
  return createHash('sha256')
    .update('red-team-audit/http-recon-response-observation/v1\0', 'utf8')
    .update(JSON.stringify([profile, definition]), 'utf8')
    .digest('hex')
}

function pinnedArtifactFor(definition, parsedUrl) {
  if (!Array.isArray(definition.artifacts)) return null
  return definition.artifacts.find(({ url }) => url === parsedUrl.href) ?? null
}

export function createHttpReconResponseObservationDescriptor({
  profile,
  method,
  url,
  maxResponseBytes,
}) {
  const definition = definitionFor(profile)
  const parsed = exactUrl(url)
  const pinnedArtifact = parsed === null ? null : pinnedArtifactFor(definition, parsed)
  if (
    method !== definition.method
    || parsed === null
    || parsed.origin !== definition.origin
    || (Array.isArray(definition.artifacts) && pinnedArtifact === null)
    || !Number.isSafeInteger(maxResponseBytes)
    || maxResponseBytes < 1
    || maxResponseBytes > definition.max_response_bytes
    || (pinnedArtifact !== null && maxResponseBytes < pinnedArtifact.size)
  ) {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_SCOPE_MISMATCH',
      'response-observation profile is outside its controller-owned method, origin, or byte boundary',
    )
  }
  return {
    profile,
    profile_binding_sha256: bindingSha256(profile, definition),
  }
}

export function resolveHttpReconResponseObservation({
  descriptor,
  method,
  url,
  maxResponseBytes,
}) {
  exactObject(descriptor, 'response-observation descriptor')
  const keys = Object.keys(descriptor).sort(compareCanonicalStrings)
  if (JSON.stringify(keys) !== JSON.stringify(['profile', 'profile_binding_sha256'])) {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_DESCRIPTOR_INVALID',
      'response-observation descriptor has unexpected fields',
    )
  }
  const expected = createHttpReconResponseObservationDescriptor({
    profile: descriptor.profile,
    method,
    url,
    maxResponseBytes,
  })
  if (
    descriptor.profile !== expected.profile
    || descriptor.profile_binding_sha256 !== expected.profile_binding_sha256
  ) {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_DESCRIPTOR_MISMATCH',
      'response-observation descriptor does not match its controller-owned profile',
    )
  }
  return Object.freeze({ ...PROFILE_DEFINITIONS[descriptor.profile] })
}

function parseContentType(value, expectedMediaType) {
  if (typeof value !== 'string' || /[\r\n\u0000]/u.test(value)) return false
  const parts = value.split(';').map((part) => part.trim().toLowerCase())
  if (parts.shift() !== expectedMediaType) return false
  let charsetSeen = false
  for (const parameter of parts) {
    if (parameter === '') continue
    const match = /^charset=(?:"?utf-8"?)$/u.exec(parameter)
    if (match === null || charsetSeen) return false
    charsetSeen = true
  }
  return true
}

export function validateHttpReconResponseObservationHeaders({
  descriptor,
  method,
  url,
  maxResponseBytes,
  status,
  contentTypes,
  contentEncodings,
}) {
  const definition = resolveHttpReconResponseObservation({
    descriptor,
    method,
    url,
    maxResponseBytes,
  })
  if (status !== 200) {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_STATUS_INVALID',
      'response-observation profile requires one complete HTTP 200 response',
    )
  }
  if (
    !Array.isArray(contentTypes)
    || contentTypes.length !== 1
    || !parseContentType(contentTypes[0], definition.content_type)
  ) {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_CONTENT_TYPE_INVALID',
      'response-observation profile requires one text/html Content-Type with no unsupported charset',
    )
  }
  if (
    !Array.isArray(contentEncodings)
    || contentEncodings.length > 1
    || contentEncodings.some((value) => String(value).trim().toLowerCase() !== 'identity')
  ) {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_ENCODING_DENIED',
      'response-observation profile rejects encoded response bodies',
    )
  }
  return true
}

function isSpace(character) {
  return /[\t\n\f\r ]/u.test(character)
}

function scriptBoundary(character) {
  return character === undefined || isSpace(character) || character === '>' || character === '/'
}

function findTagEnd(html, start) {
  let quote = null
  for (let index = start; index < html.length; index += 1) {
    const character = html[index]
    if (quote !== null) {
      if (character === quote) quote = null
      continue
    }
    if (character === '"' || character === "'") quote = character
    else if (character === '>') return index
  }
  return -1
}

function parseScriptAttributes(tag) {
  let index = 7
  let src
  while (index < tag.length - 1) {
    while (isSpace(tag[index])) index += 1
    if (tag[index] === '/' && index === tag.length - 2) break
    if (index >= tag.length - 1) break
    const nameStart = index
    while (
      index < tag.length - 1
      && !isSpace(tag[index])
      && !['"', "'", '<', '>', '/', '='].includes(tag[index])
    ) index += 1
    if (index === nameStart) {
      throw observationError(
        'HTTP_RECON_RESPONSE_OBSERVATION_HTML_MALFORMED',
        'response-observation profile encountered malformed script markup',
      )
    }
    const name = tag.slice(nameStart, index).toLowerCase()
    while (isSpace(tag[index])) index += 1
    let value = null
    if (tag[index] === '=') {
      index += 1
      while (isSpace(tag[index])) index += 1
      if (index >= tag.length - 1) {
        throw observationError(
          'HTTP_RECON_RESPONSE_OBSERVATION_HTML_MALFORMED',
          'response-observation profile encountered malformed script markup',
        )
      }
      const quote = tag[index] === '"' || tag[index] === "'" ? tag[index] : null
      if (quote !== null) {
        index += 1
        const valueStart = index
        while (index < tag.length - 1 && tag[index] !== quote) index += 1
        if (index >= tag.length - 1) {
          throw observationError(
            'HTTP_RECON_RESPONSE_OBSERVATION_HTML_MALFORMED',
            'response-observation profile encountered malformed script markup',
          )
        }
        value = tag.slice(valueStart, index)
        index += 1
      } else {
        const valueStart = index
        while (
          index < tag.length - 1
          && !isSpace(tag[index])
          && tag[index] !== '>'
        ) index += 1
        value = tag.slice(valueStart, index)
      }
    }
    if (name === 'src') {
      if (value === null || src !== undefined) {
        throw observationError(
          'HTTP_RECON_RESPONSE_OBSERVATION_HTML_AMBIGUOUS',
          'response-observation profile encountered an ambiguous script src',
        )
      }
      src = value
    }
  }
  return src
}

function candidatePath(src, targetUrl) {
  if (src === undefined || src !== src.trim() || /[\u0000-\u001f\u007f]/u.test(src)) {
    return null
  }
  let parsed
  try {
    parsed = new URL(src, targetUrl)
  } catch {
    if (/bundle-/iu.test(src)) {
      throw observationError(
        'HTTP_RECON_RESPONSE_OBSERVATION_SRC_INVALID',
        'response-observation profile encountered an invalid bundle src',
      )
    }
    return null
  }
  const looksLikeBundle = /(?:^|\/)bundle-/iu.test(parsed.pathname)
  if (!looksLikeBundle) return null
  if (
    parsed.origin !== CREDIBLE_ORIGIN
    || parsed.username !== ''
    || parsed.password !== ''
    || parsed.search !== ''
    || parsed.hash !== ''
    || !BUNDLE_PATH.test(parsed.pathname)
  ) {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_SRC_INVALID',
      'response-observation profile encountered an out-of-profile bundle src',
    )
  }
  return parsed.pathname
}

export function observeCredibleBundleSources({
  descriptor,
  method,
  url,
  maxResponseBytes,
  body,
}) {
  if (descriptor?.profile !== 'credible-bundle-src-v1') {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_PROFILE_MISMATCH',
      'response-observation implementation does not match the sealed profile',
    )
  }
  resolveHttpReconResponseObservation({ descriptor, method, url, maxResponseBytes })
  if (!Buffer.isBuffer(body) || body.length > maxResponseBytes) {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_BODY_INVALID',
      'response-observation profile received an invalid bounded body',
    )
  }
  let html
  try {
    html = new TextDecoder('utf-8', { fatal: true }).decode(body)
  } catch {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_UTF8_INVALID',
      'response-observation profile requires valid UTF-8 HTML',
    )
  }
  const lower = html.toLowerCase()
  const paths = new Set()
  let cursor = 0
  let scriptTags = 0
  while (cursor < html.length) {
    const comment = lower.indexOf('<!--', cursor)
    const script = lower.indexOf('<script', cursor)
    if (comment >= 0 && (script < 0 || comment < script)) {
      const end = lower.indexOf('-->', comment + 4)
      if (end < 0) {
        throw observationError(
          'HTTP_RECON_RESPONSE_OBSERVATION_HTML_MALFORMED',
          'response-observation profile encountered malformed HTML',
        )
      }
      cursor = end + 3
      continue
    }
    if (script < 0) break
    if (!scriptBoundary(html[script + 7])) {
      cursor = script + 7
      continue
    }
    scriptTags += 1
    if (scriptTags > MAX_SCRIPT_TAGS) {
      throw observationError(
        'HTTP_RECON_RESPONSE_OBSERVATION_HTML_AMBIGUOUS',
        'response-observation profile exceeded its script-tag bound',
      )
    }
    const tagEnd = findTagEnd(html, script + 7)
    if (tagEnd < 0 || tagEnd - script + 1 > MAX_TAG_CHARACTERS) {
      throw observationError(
        'HTTP_RECON_RESPONSE_OBSERVATION_HTML_MALFORMED',
        'response-observation profile encountered malformed script markup',
      )
    }
    const src = parseScriptAttributes(html.slice(script, tagEnd + 1))
    const path = candidatePath(src, url)
    if (path !== null) {
      paths.add(path)
      if (paths.size > MAX_BUNDLE_PATHS) {
        throw observationError(
          'HTTP_RECON_RESPONSE_OBSERVATION_HTML_AMBIGUOUS',
          'response-observation profile exceeded its unique bundle-src bound',
        )
      }
    }
    const closing = lower.indexOf('</script', tagEnd + 1)
    if (closing < 0 || !scriptBoundary(html[closing + 8])) {
      throw observationError(
        'HTTP_RECON_RESPONSE_OBSERVATION_HTML_MALFORMED',
        'response-observation profile encountered an unterminated script element',
      )
    }
    const closingEnd = findTagEnd(html, closing + 8)
    if (closingEnd < 0 || closingEnd - closing > MAX_TAG_CHARACTERS) {
      throw observationError(
        'HTTP_RECON_RESPONSE_OBSERVATION_HTML_MALFORMED',
        'response-observation profile encountered malformed script markup',
      )
    }
    cursor = closingEnd + 1
  }
  return {
    profile: descriptor.profile,
    profile_binding_sha256: descriptor.profile_binding_sha256,
    bundle_paths: [...paths].sort(compareCanonicalStrings),
  }
}

function isAstNode(value) {
  return value !== null
    && typeof value === 'object'
    && typeof value.type === 'string'
}

function isFunctionNode(node) {
  return [
    'ArrowFunctionExpression',
    'FunctionDeclaration',
    'FunctionExpression',
  ].includes(node?.type)
}

function astChildren(node) {
  const children = []
  for (const [key, value] of Object.entries(node)) {
    if (['end', 'loc', 'range', 'start', 'type'].includes(key)) continue
    if (isAstNode(value)) children.push(value)
    else if (Array.isArray(value)) {
      for (const item of value) {
        if (isAstNode(item)) children.push(item)
      }
    }
  }
  return children
}

function walkAst(root, visitor, {
  skipNestedFunctions = false,
  rootFunction = null,
} = {}) {
  const stack = [{ node: root, parent: null }]
  let visited = 0
  while (stack.length > 0) {
    const current = stack.pop()
    visited += 1
    if (visited > MAX_AST_NODES) {
      throw observationError(
        'HTTP_RECON_RESPONSE_OBSERVATION_AST_COMPLEXITY_EXCEEDED',
        'response-observation JavaScript exceeded the fixed AST bound',
      )
    }
    if (
      skipNestedFunctions
      && current.node !== rootFunction
      && isFunctionNode(current.node)
    ) continue
    visitor(current.node, current.parent)
    const children = astChildren(current.node)
    for (let index = children.length - 1; index >= 0; index -= 1) {
      stack.push({ node: children[index], parent: current.node })
    }
  }
  return visited
}

function astSome(root, predicate, options = {}) {
  const stack = [{ node: root, parent: null }]
  let visited = 0
  while (stack.length > 0) {
    const current = stack.pop()
    visited += 1
    if (visited > MAX_AST_NODES) {
      throw observationError(
        'HTTP_RECON_RESPONSE_OBSERVATION_AST_COMPLEXITY_EXCEEDED',
        'response-observation JavaScript exceeded the fixed AST bound',
      )
    }
    if (
      options.skipNestedFunctions
      && current.node !== options.rootFunction
      && isFunctionNode(current.node)
    ) continue
    if (predicate(current.node, current.parent)) return true
    const children = astChildren(current.node)
    for (let index = children.length - 1; index >= 0; index -= 1) {
      stack.push({ node: children[index], parent: current.node })
    }
  }
  return false
}

function staticText(node) {
  if (node?.type === 'Literal' && typeof node.value === 'string') {
    return node.value
  }
  if (
    node?.type === 'TemplateLiteral'
    && node.expressions.length === 0
    && node.quasis.length === 1
  ) return node.quasis[0].value.cooked
  return null
}

function staticPropertyName(node) {
  if (node?.type === 'MemberExpression') {
    return node.computed ? staticText(node.property) : node.property?.name ?? null
  }
  if (node?.type === 'Property' || node?.type === 'PropertyDefinition') {
    return node.computed ? staticText(node.key) : node.key?.name ?? staticText(node.key)
  }
  return null
}

function isTokenLikeText(value) {
  return typeof value === 'string'
    && /(?:access.?token|auth(?:entication|orization)?|bearer|credential|jwt|refresh.?token|session(?:id)?|token)/iu.test(value)
}

function isTokenLikeReference(node, parent) {
  if (node.type === 'Identifier') {
    if (
      (parent?.type === 'MemberExpression' && parent.property === node && !parent.computed)
      || (parent?.type === 'Property' && parent.key === node && !parent.computed)
      || (parent?.type === 'PropertyDefinition' && parent.key === node && !parent.computed)
    ) return false
    return isTokenLikeText(node.name)
  }
  if (node.type === 'MemberExpression') {
    return isTokenLikeText(staticPropertyName(node))
  }
  if (node.type === 'Property' || node.type === 'PropertyDefinition') {
    return isTokenLikeText(staticPropertyName(node))
  }
  return node.type === 'Literal' && isTokenLikeText(node.value)
}

function tokenLikeTarget(node) {
  if (node?.type === 'Identifier') return isTokenLikeText(node.name)
  if (node?.type === 'MemberExpression') {
    return isTokenLikeText(staticPropertyName(node))
  }
  if (node?.type === 'AssignmentPattern') return tokenLikeTarget(node.left)
  if (node?.type === 'RestElement') return tokenLikeTarget(node.argument)
  if (node?.type === 'ArrayPattern') return node.elements.some(tokenLikeTarget)
  if (node?.type === 'ObjectPattern') {
    return node.properties.some((property) => (
      isTokenLikeText(staticPropertyName(property))
      || tokenLikeTarget(property.value ?? property.argument)
    ))
  }
  return false
}

function handlerBindings(ast) {
  const bindings = new Map()
  walkAst(ast, (node) => {
    if (
      node.type === 'FunctionDeclaration'
      && node.id?.type === 'Identifier'
    ) bindings.set(node.id.name, node)
    if (
      node.type === 'VariableDeclarator'
      && node.id?.type === 'Identifier'
      && isFunctionNode(node.init)
    ) bindings.set(node.id.name, node.init)
    if (
      node.type === 'AssignmentExpression'
      && node.left?.type === 'Identifier'
      && isFunctionNode(node.right)
    ) bindings.set(node.left.name, node.right)
  })
  return bindings
}

function resolveHandler(node, bindings) {
  if (isFunctionNode(node)) return node
  if (node?.type === 'Identifier') return bindings.get(node.name) ?? null
  return null
}

function callableName(node) {
  if (node?.type === 'Identifier') return node.name
  return staticPropertyName(node)
}

function isMessageListenerCall(node) {
  if (node.type !== 'CallExpression') return false
  const calleeName = callableName(node.callee)
  if (calleeName === 'addEventListener' || calleeName === 'on') {
    return staticText(node.arguments[0]) === 'message'
  }
  return calleeName === 'attachEvent'
    && staticText(node.arguments[0]) === 'onmessage'
}

function collectMessageListeners(ast, bindings) {
  const listeners = []
  walkAst(ast, (node) => {
    let rawHandler = null
    if (isMessageListenerCall(node)) rawHandler = node.arguments[1] ?? null
    else if (
      node.type === 'AssignmentExpression'
      && staticPropertyName(node.left) === 'onmessage'
    ) rawHandler = node.right
    if (rawHandler === null) return
    listeners.push({
      handler: resolveHandler(rawHandler, bindings),
      inline: isFunctionNode(rawHandler),
    })
    if (listeners.length > MAX_MESSAGE_LISTENERS) {
      throw observationError(
        'HTTP_RECON_RESPONSE_OBSERVATION_AST_COMPLEXITY_EXCEEDED',
        'response-observation JavaScript exceeded the fixed message-listener bound',
      )
    }
  })
  return listeners
}

function destructuredEventAliases(pattern, propertyName) {
  const aliases = new Set()
  if (pattern?.type !== 'ObjectPattern') return aliases
  for (const property of pattern.properties) {
    if (staticPropertyName(property) !== propertyName) continue
    const value = property.value ?? property.argument
    if (value?.type === 'Identifier') aliases.add(value.name)
    else if (value?.type === 'AssignmentPattern' && value.left?.type === 'Identifier') {
      aliases.add(value.left.name)
    }
  }
  return aliases
}

function eventParameterState(handler) {
  const parameter = handler.params[0]
  return {
    objects: new Set(parameter?.type === 'Identifier' ? [parameter.name] : []),
    origin: destructuredEventAliases(parameter, 'origin'),
    source: destructuredEventAliases(parameter, 'source'),
  }
}

function expressionRootedAtEvent(node, eventObjects) {
  if (node?.type === 'Identifier') return eventObjects.has(node.name)
  if (node?.type === 'ChainExpression') {
    return expressionRootedAtEvent(node.expression, eventObjects)
  }
  if (node?.type === 'MemberExpression') {
    return expressionRootedAtEvent(node.object, eventObjects)
  }
  return false
}

function addIdentifierTarget(targetSet, target) {
  if (target?.type === 'Identifier') {
    const before = targetSet.size
    targetSet.add(target.name)
    return targetSet.size !== before
  }
  return false
}

function deriveEventAliases(handler, state) {
  const assignments = []
  walkAst(handler.body, (node) => {
    if (node.type === 'VariableDeclarator' && node.init !== null) {
      assignments.push({ target: node.id, source: node.init })
    } else if (node.type === 'AssignmentExpression') {
      assignments.push({ target: node.left, source: node.right })
    }
  }, { skipNestedFunctions: true, rootFunction: handler })

  let changed = true
  let passes = 0
  while (changed && passes <= assignments.length + 1) {
    changed = false
    passes += 1
    for (const { target, source } of assignments) {
      if (source?.type === 'Identifier' && state.objects.has(source.name)) {
        changed ||= addIdentifierTarget(state.objects, target)
      }
      if (source?.type === 'MemberExpression') {
        const propertyName = staticPropertyName(source)
        if (expressionRootedAtEvent(source.object, state.objects)) {
          if (propertyName === 'origin') changed ||= addIdentifierTarget(state.origin, target)
          if (propertyName === 'source') changed ||= addIdentifierTarget(state.source, target)
        }
      }
      if (target?.type === 'ObjectPattern' && expressionRootedAtEvent(source, state.objects)) {
        for (const propertyName of ['origin', 'source']) {
          const targetSet = state[propertyName]
          for (const alias of destructuredEventAliases(target, propertyName)) {
            const before = targetSet.size
            targetSet.add(alias)
            changed ||= targetSet.size !== before
          }
        }
      }
    }
  }
  return state
}

function referencesEventProperty(node, state, propertyName) {
  const aliases = state[propertyName]
  return astSome(node, (candidate, parent) => {
    if (candidate.type === 'Identifier' && aliases.has(candidate.name)) {
      if (
        (parent?.type === 'MemberExpression' && parent.property === candidate && !parent.computed)
        || (parent?.type === 'Property' && parent.key === candidate && !parent.computed)
      ) return false
      return true
    }
    return candidate.type === 'MemberExpression'
      && staticPropertyName(candidate) === propertyName
      && expressionRootedAtEvent(candidate.object, state.objects)
  })
}

function handlerGuardCandidates(handler, state) {
  const result = { origin: false, source: false }
  walkAst(handler.body, (node) => {
    let test = null
    if ([
      'ConditionalExpression',
      'DoWhileStatement',
      'IfStatement',
      'WhileStatement',
    ].includes(node.type)) test = node.test
    else if (node.type === 'ForStatement') test = node.test
    else if (node.type === 'SwitchStatement') test = node.discriminant
    if (test === null) return
    result.origin ||= referencesEventProperty(test, state, 'origin')
    result.source ||= referencesEventProperty(test, state, 'source')
  }, { skipNestedFunctions: true, rootFunction: handler })
  return result
}

function expressionDerivedFromEvent(node, state) {
  return astSome(node, (candidate, parent) => {
    if (candidate.type !== 'Identifier' || !state.objects.has(candidate.name)) return false
    return !(
      (parent?.type === 'MemberExpression' && parent.property === candidate && !parent.computed)
      || (parent?.type === 'Property' && parent.key === candidate && !parent.computed)
    )
  })
}

function tokenInputSinkCandidates(handler, state) {
  let count = 0
  walkAst(handler.body, (node) => {
    if (
      node.type === 'VariableDeclarator'
      && node.init !== null
      && tokenLikeTarget(node.id)
      && expressionDerivedFromEvent(node.init, state)
    ) count += 1
    else if (
      node.type === 'AssignmentExpression'
      && tokenLikeTarget(node.left)
      && expressionDerivedFromEvent(node.right, state)
    ) count += 1
    else if (
      node.type === 'CallExpression'
      && tokenLikeTarget(node.callee)
      && node.arguments.some((argument) => expressionDerivedFromEvent(argument, state))
    ) count += 1
    if (count > MAX_TOKEN_LIKE_REFERENCES) {
      throw observationError(
        'HTTP_RECON_RESPONSE_OBSERVATION_AST_COMPLEXITY_EXCEEDED',
        'response-observation JavaScript exceeded the fixed token-flow bound',
      )
    }
  }, { skipNestedFunctions: true, rootFunction: handler })
  return count
}

function isPostMessageCall(node) {
  return node.type === 'CallExpression'
    && callableName(node.callee) === 'postMessage'
}

function isSameOriginExpression(node) {
  if (staticText(node) === '/') return true
  if (node?.type === 'ChainExpression') return isSameOriginExpression(node.expression)
  if (node?.type !== 'MemberExpression' || staticPropertyName(node) !== 'origin') {
    return false
  }
  if (node.object?.type === 'Identifier' && node.object.name === 'location') return true
  return node.object?.type === 'MemberExpression'
    && staticPropertyName(node.object) === 'location'
}

function targetOriginArgument(rawTarget) {
  if (rawTarget?.type !== 'ObjectExpression') return rawTarget
  for (const property of rawTarget.properties) {
    if (staticPropertyName(property) === 'targetOrigin') return property.value
  }
  return undefined
}

function postMessageTargetCategory(rawTarget) {
  const target = targetOriginArgument(rawTarget)
  if (target === undefined) return 'missing'
  const text = staticText(target)
  if (text === '*') return 'wildcard_literal'
  if (text === 'null' || (target.type === 'Literal' && target.value === null)) {
    return 'opaque_or_null_literal'
  }
  if (isSameOriginExpression(target)) return 'same_origin_expression'
  if (text !== null) {
    try {
      const parsed = new URL(text)
      if (
        ['http:', 'https:'].includes(parsed.protocol)
        && parsed.username === ''
        && parsed.password === ''
        && parsed.pathname === '/'
        && parsed.search === ''
        && parsed.hash === ''
      ) {
        return 'static_origin_literal'
      }
    } catch {
      // A non-URL literal remains a fixed category; the value is never emitted.
    }
    return 'other_static_literal'
  }
  return 'dynamic_expression'
}

function boundedIncrement(object, key, maximum, label) {
  object[key] += 1
  if (object[key] > maximum) {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_AST_COMPLEXITY_EXCEEDED',
      `response-observation JavaScript exceeded the fixed ${label} bound`,
    )
  }
}

export function analyzeCrossOriginJavaScriptAst(source) {
  if (typeof source !== 'string' || source.length > MAX_RESPONSE_BYTES) {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_JAVASCRIPT_INVALID',
      'response-observation profile received invalid bounded JavaScript',
    )
  }
  let ast
  try {
    ast = parseJavaScript(source, {
      allowAwaitOutsideFunction: false,
      allowHashBang: false,
      allowImportExportEverywhere: false,
      allowReturnOutsideFunction: false,
      ecmaVersion: 'latest',
      sourceType: 'script',
    })
  } catch {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_JAVASCRIPT_PARSE_INVALID',
      'response-observation profile could not parse the pinned JavaScript artifact',
    )
  }
  walkAst(ast, () => {})

  const bindings = handlerBindings(ast)
  const listeners = collectMessageListeners(ast, bindings)
  const messageListeners = {
    count: listeners.length,
    inline_handler_count: 0,
    resolved_handler_count: 0,
    unresolved_handler_count: 0,
    origin_guard_candidate_count: 0,
    source_guard_candidate_count: 0,
    both_guard_candidate_count: 0,
    without_origin_guard_candidate_count: 0,
    without_source_guard_candidate_count: 0,
    has_resolved_handler_without_origin_guard_candidate: false,
    has_resolved_handler_without_source_guard_candidate: false,
  }
  let tokenMessageListenerCandidates = 0
  let tokenInputSinkCount = 0
  for (const listener of listeners) {
    if (listener.inline) messageListeners.inline_handler_count += 1
    if (listener.handler === null) {
      messageListeners.unresolved_handler_count += 1
      continue
    }
    messageListeners.resolved_handler_count += 1
    const state = deriveEventAliases(listener.handler, eventParameterState(listener.handler))
    const guards = handlerGuardCandidates(listener.handler, state)
    if (guards.origin) messageListeners.origin_guard_candidate_count += 1
    else messageListeners.without_origin_guard_candidate_count += 1
    if (guards.source) messageListeners.source_guard_candidate_count += 1
    else messageListeners.without_source_guard_candidate_count += 1
    if (guards.origin && guards.source) messageListeners.both_guard_candidate_count += 1
    if (astSome(
      listener.handler.body,
      isTokenLikeReference,
      { skipNestedFunctions: true, rootFunction: listener.handler },
    )) tokenMessageListenerCandidates += 1
    tokenInputSinkCount += tokenInputSinkCandidates(listener.handler, state)
  }
  messageListeners.has_resolved_handler_without_origin_guard_candidate =
    messageListeners.without_origin_guard_candidate_count > 0
  messageListeners.has_resolved_handler_without_source_guard_candidate =
    messageListeners.without_source_guard_candidate_count > 0

  const postMessageTargets = {
    wildcard_literal_count: 0,
    same_origin_expression_count: 0,
    static_origin_literal_count: 0,
    opaque_or_null_literal_count: 0,
    other_static_literal_count: 0,
    dynamic_expression_count: 0,
    missing_count: 0,
  }
  let postMessageCount = 0
  let tokenPostMessagePayloadCount = 0
  let tokenReferenceCount = 0
  walkAst(ast, (node, parent) => {
    if (isTokenLikeReference(node, parent)) {
      tokenReferenceCount += 1
      if (tokenReferenceCount > MAX_TOKEN_LIKE_REFERENCES) {
        throw observationError(
          'HTTP_RECON_RESPONSE_OBSERVATION_AST_COMPLEXITY_EXCEEDED',
          'response-observation JavaScript exceeded the fixed token-reference bound',
        )
      }
    }
    if (!isPostMessageCall(node)) return
    postMessageCount += 1
    if (postMessageCount > MAX_POST_MESSAGE_CALLS) {
      throw observationError(
        'HTTP_RECON_RESPONSE_OBSERVATION_AST_COMPLEXITY_EXCEEDED',
        'response-observation JavaScript exceeded the fixed postMessage bound',
      )
    }
    const category = postMessageTargetCategory(node.arguments[1])
    boundedIncrement(postMessageTargets, `${category}_count`, MAX_POST_MESSAGE_CALLS, 'postMessage')
    if (node.arguments[0] !== undefined && astSome(node.arguments[0], isTokenLikeReference)) {
      tokenPostMessagePayloadCount += 1
    }
  })

  const tokenCandidateCount = tokenMessageListenerCandidates
    + tokenInputSinkCount
    + tokenPostMessagePayloadCount
  return {
    analysis_complete: true,
    message_listeners: messageListeners,
    post_message_calls: {
      count: postMessageCount,
      targets: postMessageTargets,
      has_wildcard_target: postMessageTargets.wildcard_literal_count > 0,
      has_dynamic_target: postMessageTargets.dynamic_expression_count > 0,
    },
    token_like_flows: {
      reference_count: tokenReferenceCount,
      message_listener_candidate_count: tokenMessageListenerCandidates,
      message_input_to_token_sink_candidate_count: tokenInputSinkCount,
      post_message_payload_candidate_count: tokenPostMessagePayloadCount,
      candidate_count: tokenCandidateCount,
      present: tokenCandidateCount > 0,
    },
  }
}

export function observeCredibleCrossOriginJavaScript({
  descriptor,
  method,
  url,
  maxResponseBytes,
  body,
}) {
  if (descriptor?.profile !== CROSS_ORIGIN_ANALYSIS_PROFILE) {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_PROFILE_MISMATCH',
      'response-observation implementation does not match the sealed profile',
    )
  }
  const definition = resolveHttpReconResponseObservation({
    descriptor,
    method,
    url,
    maxResponseBytes,
  })
  const parsed = exactUrl(url)
  const artifact = parsed === null ? null : pinnedArtifactFor(definition, parsed)
  if (
    artifact === null
    || !Buffer.isBuffer(body)
    || body.length !== artifact.size
    || body.length > maxResponseBytes
    || createHash('sha256').update(body).digest('hex') !== artifact.sha256
  ) {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_ARTIFACT_MISMATCH',
      'response-observation body did not match the sealed artifact identity',
    )
  }
  let source
  try {
    source = new TextDecoder('utf-8', { fatal: true }).decode(body)
  } catch {
    throw observationError(
      'HTTP_RECON_RESPONSE_OBSERVATION_UTF8_INVALID',
      'response-observation profile requires valid UTF-8 JavaScript',
    )
  }
  return {
    profile: descriptor.profile,
    profile_binding_sha256: descriptor.profile_binding_sha256,
    analysis: analyzeCrossOriginJavaScriptAst(source),
  }
}

export function observeHttpReconResponse(input) {
  if (input?.descriptor?.profile === 'credible-bundle-src-v1') {
    return observeCredibleBundleSources(input)
  }
  if (input?.descriptor?.profile === CROSS_ORIGIN_ANALYSIS_PROFILE) {
    return observeCredibleCrossOriginJavaScript(input)
  }
  throw observationError(
    'HTTP_RECON_RESPONSE_OBSERVATION_PROFILE_UNKNOWN',
    'response-observation profile is not controller-defined',
  )
}
