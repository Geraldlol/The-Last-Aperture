import { createHash } from 'node:crypto'
import { parse } from 'acorn'
import { isSourceCheckRelativePath } from './source-check-path.mjs'

export const SOURCE_CHECK_VERSION = '1.0.0'
export const SOURCE_CHECK_LIMITS = Object.freeze({ max_file_bytes: 262144, max_observations: 100, max_ast_nodes: 50000 })

const GAP_MESSAGES = Object.freeze({
  INVALID_PATH: 'A printable relative JavaScript file path is required.',
  INVALID_SOURCE: 'Source must be a string.',
  SOURCE_SIZE_LIMIT: 'Source exceeds the file byte limit.',
  UNSUPPORTED_LANGUAGE: 'Only JavaScript, MJS, and CJS source is supported.',
  PARSE_ERROR: 'Source could not be parsed as supported ECMAScript.',
  AST_SIZE_LIMIT: 'Source exceeds the syntax node limit.',
  OBSERVATION_LIMIT: 'Additional observations were omitted at the result limit.',
  AMBIGUOUS_BINDING: 'A relevant binding is shadowed, reassigned, or otherwise ambiguous.',
  DYNAMIC_TLS_VALUE: 'A TLS setting uses an unsupported value or assignment form.',
  DYNAMIC_OPTIONS: 'A TLS options argument cannot be assessed as a direct static object.',
  AMBIGUOUS_OPTIONS: 'Duplicate, spread, computed, or accessor properties prevent assessment of TLS options.',
  UNSUPPORTED_ALIAS: 'A relevant import or alias is outside the supported direct-binding forms.',
})

function memberParts(node) {
  const parts = []
  while (node?.type === 'MemberExpression' && !node.optional) {
    const key = node.computed ? node.property.type === 'Literal' ? node.property.value : null : node.property.name
    if (typeof key !== 'string') return null
    parts.unshift(key)
    node = node.object
  }
  return node?.type === 'Identifier' ? [node.name, ...parts] : null
}

const isProcessEnvironment = (parts) => parts?.length === 2 && parts[0] === 'process' && parts[1] === 'env'
const isEnvironmentSetting = (parts) => parts?.length === 3 && isProcessEnvironment(parts.slice(0, 2)) && parts[2] === 'NODE_TLS_REJECT_UNAUTHORIZED'

function collectNodes(ast) {
  const entries = []
  const pending = [{ node: ast, parent: null }]
  while (pending.length > 0) {
    const entry = pending.pop()
    entries.push(entry)
    if (entries.length > SOURCE_CHECK_LIMITS.max_ast_nodes) return null
    for (const value of Object.values(entry.node)) {
      for (const child of Array.isArray(value) ? value : [value]) {
        if (child && typeof child === 'object' && typeof child.type === 'string') pending.push({ node: child, parent: entry.node })
      }
    }
  }
  return entries.sort((a, b) => a.node.start - b.node.start || a.node.end - b.node.end)
}

function observation(node, rule) {
  const environment = rule === 'node-tls-env-disable'
  return {
    rule_id: rule,
    line: node.loc.start.line, column: node.loc.start.column + 1,
    end_line: node.loc.end.line, end_column: node.loc.end.column + 1,
    message: environment ? 'A literal assignment sets the Node.js TLS certificate verification override to "0".' : 'A direct Node.js TLS options object contains rejectUnauthorized: false.',
    evidence_kind: 'STATIC_SYNTAX', verification: 'UNPROVEN',
    repair: {
      recommendation: environment ? 'Remove the TLS verification override and configure trusted certificate authorities for required connections.' : 'Remove the false TLS verification option or set it to true, and configure trusted certificate authorities as needed.',
      acceptance_checks: ['Confirm certificate verification remains enabled in the relevant configuration.', 'Review the affected connection configuration and add a regression test using synthetic certificate fixtures.'],
    },
  }
}

function patternTargets(pattern) {
  const targets = []
  const pending = [pattern]
  while (pending.length > 0) {
    const node = pending.pop()
    if (!node) continue
    if (node.type === 'Identifier' || node.type === 'MemberExpression') targets.push(node)
    else if (node.type === 'ObjectPattern') pending.push(...node.properties.map((property) => property.type === 'RestElement' ? property.argument : property.value))
    else if (node.type === 'ArrayPattern') pending.push(...node.elements)
    else if (node.type === 'AssignmentPattern') pending.push(node.left)
    else if (node.type === 'RestElement') pending.push(node.argument)
  }
  return targets
}

const boundNames = (pattern) => patternTargets(pattern).filter((node) => node.type === 'Identifier').map((node) => node.name)

function rootName(node) {
  while (node?.type === 'MemberExpression') node = node.object
  return node?.type === 'Identifier' ? node.name : null
}

const builtinModule = (value) => ['https', 'node:https'].includes(value) ? 'https' : ['tls', 'node:tls'].includes(value) ? 'tls' : null
const builtinMethod = (module, name) => module === 'https' ? ['request', 'get', 'Agent'].includes(name) : name === 'connect'
const propertyName = (property) => property.computed ? property.key?.type === 'Literal' ? property.key.value : null : property.key?.name ?? property.key?.value

function analyzeBindings(ast, entries, gap) {
  const counts = new Map()
  const writes = new Set()
  const bindings = new Map()
  const unsafe = new Set()
  const topDeclarations = new Set(ast.body.map((node) => node.type === 'ExportNamedDeclaration' ? node.declaration : node))
  let dynamicScope = false
  for (const { node } of entries) {
    const patterns = []
    if (node.type === 'VariableDeclarator' || /^(Function|Class)(Declaration|Expression)$/.test(node.type)) patterns.push(node.id)
    if (['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(node.type)) patterns.push(...node.params)
    if (node.type === 'CatchClause') patterns.push(node.param)
    if (/^Import.*Specifier$/.test(node.type)) patterns.push(node.local)
    for (const pattern of patterns) for (const name of boundNames(pattern)) counts.set(name, (counts.get(name) ?? 0) + 1)
    const assignmentTarget = ['AssignmentExpression', 'ForInStatement', 'ForOfStatement'].includes(node.type) ? node.left
      : node.type === 'UpdateExpression' || (node.type === 'UnaryExpression' && node.operator === 'delete') ? node.argument : null
    for (const target of patternTargets(assignmentTarget)) {
      const parts = memberParts(target)
      if (isEnvironmentSetting(parts)) {
        if (node.type !== 'AssignmentExpression' || node.left !== target) gap('DYNAMIC_TLS_VALUE')
      } else {
        if (rootName(target)) writes.add(rootName(target))
        if (parts?.[0] === 'globalThis' && parts[1] === 'process') writes.add('process')
      }
    }
    if (node.type === 'WithStatement' || (node.type === 'CallExpression' && node.callee.type === 'Identifier' && node.callee.name === 'eval')) dynamicScope = true
  }
  if (dynamicScope) gap('AMBIGUOUS_BINDING')
  const addBinding = (name, module, method = null, permitted = true) => {
    bindings.set(name, { module, method })
    if (!permitted || counts.get(name) !== 1 || writes.has(name) || dynamicScope) unsafe.add(name)
  }
  for (const { node, parent } of entries) {
    if (node.type === 'ImportDeclaration') {
      const module = builtinModule(node.source.value)
      if (!module) continue
      for (const specifier of node.specifiers) {
        const method = specifier.type === 'ImportSpecifier' ? specifier.imported.name ?? specifier.imported.value : null
        if (method !== null && !builtinMethod(module, method)) { gap('UNSUPPORTED_ALIAS'); continue }
        addBinding(specifier.local.name, module, method)
      }
    }
    if (node.type !== 'VariableDeclarator' || node.init?.type !== 'CallExpression' || node.init.callee.type !== 'Identifier' || node.init.callee.name !== 'require') continue
    const module = node.init.arguments.length === 1 && node.init.arguments[0].type === 'Literal' ? builtinModule(node.init.arguments[0].value) : null
    if (!module) continue
    const permitted = topDeclarations.has(parent) && parent.kind === 'const' && !counts.has('require') && !writes.has('require')
    if (node.id.type === 'Identifier') addBinding(node.id.name, module, null, permitted)
    else if (node.id.type === 'ObjectPattern') {
      for (const property of node.id.properties) {
        const method = propertyName(property)
        if (property.type !== 'Property' || property.value.type !== 'Identifier' || !builtinMethod(module, method)) { gap('UNSUPPORTED_ALIAS'); continue }
        addBinding(property.value.name, module, method, permitted)
      }
    } else gap('UNSUPPORTED_ALIAS')
  }
  for (const { node } of entries) {
    const values = node.type === 'VariableDeclarator' ? [node.init] : node.type === 'AssignmentExpression' ? [node.right] : node.type === 'CallExpression' ? node.arguments : []
    for (const value of values) {
      const parts = memberParts(value)
      const root = parts?.[0]
      if ((bindings.has(root) && parts.length === 1) || root === 'process' && (parts.length === 1 || isProcessEnvironment(parts))) {
        gap('UNSUPPORTED_ALIAS')
        if (root === 'process') writes.add(root)
        else unsafe.add(root)
      }
    }
  }
  if (unsafe.size > 0) gap('AMBIGUOUS_BINDING')
  return { counts, writes, bindings, unsafe, dynamicScope }
}

function checkOptions(node, method, gap, addObservation) {
  if (node.optional || node.arguments.some((argument) => argument.type === 'SpreadElement')) { gap('DYNAMIC_OPTIONS'); return }
  const objects = node.arguments.map((argument, index) => ({ argument, index })).filter(({ argument }) => argument.type === 'ObjectExpression')
  const maximumPosition = method === 'Agent' ? 0 : method === 'connect' ? 2 : 1
  if (objects.length > 1 || objects.some(({ index }) => index > maximumPosition)) { gap('DYNAMIC_OPTIONS'); return }
  if (objects.length === 0) {
    if (node.arguments.some((argument) => !['Literal', 'FunctionExpression', 'ArrowFunctionExpression'].includes(argument.type))) gap('DYNAMIC_OPTIONS')
    return
  }
  if (node.arguments.some((argument) => argument !== objects[0].argument && !['Literal', 'FunctionExpression', 'ArrowFunctionExpression'].includes(argument.type))) { gap('DYNAMIC_OPTIONS'); return }
  const properties = objects[0].argument.properties
  const setting = properties.filter((property) => propertyName(property) === 'rejectUnauthorized')
  if (properties.some((property) => property.type !== 'Property' || propertyName(property) === null || property.kind !== 'init' || property.method)
    || setting.length > 1) { gap('AMBIGUOUS_OPTIONS'); return }
  if (setting.length === 0) return
  if (setting[0].value.type !== 'Literal' || typeof setting[0].value.value !== 'boolean') gap('DYNAMIC_TLS_VALUE')
  else if (setting[0].value.value === false) addObservation(setting[0], 'node-tls-option-disable')
}

function checkBuiltinCalls(entries, bindings, unsafe, gap, addObservation) {
  for (const { node, parent } of entries) {
    if (node.type === 'VariableDeclarator' || node.type === 'AssignmentExpression') {
      const value = node.type === 'VariableDeclarator' ? node.init : node.right
      const root = rootName(value)
      const parts = memberParts(value)
      if (bindings.has(root) || root === 'process' && (parts?.length === 1 || isProcessEnvironment(parts))) gap('UNSUPPORTED_ALIAS')
    }
    if (node.type === 'ImportExpression' && (node.source.type !== 'Literal' || builtinModule(node.source.value))) gap('UNSUPPORTED_ALIAS')
    if (!['CallExpression', 'NewExpression'].includes(node.type)) continue
    if (node.callee.type === 'Identifier' && node.callee.name === 'require'
      && (node.arguments[0]?.type !== 'Literal' || builtinModule(node.arguments[0].value))
      && (node.arguments.length !== 1 || node.arguments[0]?.type !== 'Literal' || parent.type !== 'VariableDeclarator' || parent.init !== node)) gap('UNSUPPORTED_ALIAS')
    const parts = memberParts(node.callee)
    const root = rootName(node.callee)
    const binding = bindings.get(root)
    if (!binding) continue
    if (unsafe.has(root)) { gap('AMBIGUOUS_BINDING'); continue }
    const method = parts?.length === 1 ? binding.method : parts?.length === 2 && binding.method === null ? parts[1] : null
    if (!method || !builtinMethod(binding.module, method)) { gap('UNSUPPORTED_ALIAS'); continue }
    checkOptions(node, method, gap, addObservation)
  }
}

export function checkJavaScriptSource({ path, source } = {}) {
  const validPath = isSourceCheckRelativePath(path)
  const result = { path: validPath ? path : null, source_sha256: null, status: 'NOT_ASSESSED', observations: [], gaps: [] }
  const gap = (code) => { if (!result.gaps.some((entry) => entry.code === code)) result.gaps.push({ code, message: GAP_MESSAGES[code] }) }
  if (!validPath) { gap('INVALID_PATH'); return result }
  if (typeof source !== 'string') { gap('INVALID_SOURCE'); return result }
  if (Buffer.byteLength(source, 'utf8') > SOURCE_CHECK_LIMITS.max_file_bytes) { gap('SOURCE_SIZE_LIMIT'); return result }
  result.source_sha256 = createHash('sha256').update(source, 'utf8').digest('hex')
  const extension = path.slice(path.lastIndexOf('.') + 1).toLowerCase()
  if (!['js', 'mjs', 'cjs'].includes(extension)) { gap('UNSUPPORTED_LANGUAGE'); return result }
  let ast
  try { ast = parse(source, { ecmaVersion: 2025, sourceType: extension === 'cjs' ? 'script' : 'module', locations: true }) } catch {
    if (extension === 'js') {
      try { ast = parse(source, { ecmaVersion: 2025, sourceType: 'script', locations: true }) } catch { /* Fixed parser failure below. */ }
    }
  }
  if (!ast) { gap('PARSE_ERROR'); return result }
  const entries = collectNodes(ast)
  if (!entries) { gap('AST_SIZE_LIMIT'); return result }
  const { counts, writes, bindings, unsafe, dynamicScope } = analyzeBindings(ast, entries, gap)
  const addObservation = (node, rule) => {
    if (result.observations.length >= SOURCE_CHECK_LIMITS.max_observations) gap('OBSERVATION_LIMIT')
    else result.observations.push(observation(node, rule))
  }
  checkBuiltinCalls(entries, bindings, unsafe, gap, addObservation)
  for (const { node } of entries) {
    if (node.type !== 'AssignmentExpression') continue
    const parts = memberParts(node.left)
    if (node.left.type === 'MemberExpression' && isProcessEnvironment(memberParts(node.left.object)) && parts === null) { gap('DYNAMIC_TLS_VALUE'); continue }
    if (!isEnvironmentSetting(parts)) continue
    if (counts.has('process') || writes.has('process') || dynamicScope) gap('AMBIGUOUS_BINDING')
    else if (node.operator !== '=' || node.right.type !== 'Literal' || typeof node.right.value !== 'string') gap('DYNAMIC_TLS_VALUE')
    else if (node.right.value === '0') addObservation(node, 'node-tls-env-disable')
  }
  result.observations.sort((a, b) => a.line - b.line || a.column - b.column)
  result.status = result.gaps.length > 0 ? 'PARTIAL' : 'CHECKED'
  return result
}
