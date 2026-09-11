import assert from 'node:assert/strict'
import { test } from 'node:test'
import { checkJavaScriptSource, SOURCE_CHECK_LIMITS, SOURCE_CHECK_VERSION } from '../scripts/lib/source-check.mjs'

test('the passive checker identifies a literal global TLS override without executing source', () => {
  const result = checkJavaScriptSource({
    path: 'src/config.js',
    source: 'throw new Error("must not execute");\nprocess.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
  })
  assert.equal(SOURCE_CHECK_VERSION, '1.0.0')
  assert.equal(SOURCE_CHECK_LIMITS.max_file_bytes, 262144)
  assert.equal(result.status, 'CHECKED')
  assert.equal(result.observations.length, 1)
  assert.equal(result.observations[0].rule_id, 'node-tls-env-disable')
  assert.equal(result.observations[0].line, 2)
  assert.equal(result.observations[0].column, 1)
  assert.equal(result.observations[0].verification, 'UNPROVEN')
  assert.equal(result.observations[0].evidence_kind, 'STATIC_SYNTAX')
  assert.match(result.source_sha256, /^[a-f0-9]{64}$/)
  assert.ok(result.observations[0].repair.acceptance_checks.length > 0)
})

const check = (source, path = 'source.js') => checkJavaScriptSource({ path, source })

test('comments, strings, custom objects and enabled literal settings do not become observations', () => {
  for (const source of [
    '// process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
    'const text = "process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0";',
    'const custom = { request() {} }; custom.request({ rejectUnauthorized: false });',
    'process.env.NODE_TLS_REJECT_UNAUTHORIZED = "1";',
    'import https from "node:https"; https.request({ rejectUnauthorized: true });',
  ]) assert.equal(check(source).observations.length, 0)
})

test('static bracket access identifies the literal environment override', () => {
  assert.equal(check('process["env"]["NODE_TLS_REJECT_UNAUTHORIZED"] = "0";').observations.length, 1)
})

test('reading a scalar environment setting is not an object alias or an observation', () => {
  const result = check('const previousSetting = process.env.NODE_TLS_REJECT_UNAUTHORIZED;')
  assert.equal(result.status, 'CHECKED')
  assert.deepEqual(result.observations, [])
  assert.deepEqual(result.gaps, [])
})

test('shadowed or replaced process bindings and dynamic assignments are explicit gaps', () => {
  for (const source of [
    'function configure(process) { process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0"; }',
    'const { process } = local; process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
    'process = custom; process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
    'process.env = {}; process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
    'globalThis.process = custom; process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
    'process.env.NODE_TLS_REJECT_UNAUTHORIZED = setting;',
    'process.env.NODE_TLS_REJECT_UNAUTHORIZED ||= "0";',
    'process.env[key] = "0";',
  ]) {
    const result = check(source)
    assert.equal(result.observations.length, 0, source)
    assert.equal(result.status, 'PARTIAL', source)
    assert.ok(result.gaps.length > 0)
  }
})

test('direct built-in namespace and named imports identify TLS options', () => {
  for (const source of [
    'import https from "node:https"; https.request({ rejectUnauthorized: false });',
    'import * as web from "https"; web["get"]("https://example.test", { rejectUnauthorized: false });',
    'import { request as req } from "https"; req({ rejectUnauthorized: false });',
    'import { Agent } from "node:https"; new Agent({ rejectUnauthorized: false });',
    'import tls from "tls"; tls.connect(443, { rejectUnauthorized: false });',
    'const web = require("node:https"); web.get({ rejectUnauthorized: false });',
    'const { connect: conn } = require("tls"); conn({ rejectUnauthorized: false });',
  ]) {
    const result = check(source)
    assert.equal(result.status, 'CHECKED', source)
    assert.deepEqual(result.observations.map(({ rule_id }) => rule_id), ['node-tls-option-disable'], source)
  }
})

test('shadowing, reassignment, custom require, and aliases cannot impersonate a known TLS binding', () => {
  for (const source of [
    'import web from "https"; function f(web) { web.get({ rejectUnauthorized: false }); }',
    'let web = require("https"); web = custom; web.get({ rejectUnauthorized: false });',
    'const web = require("https"); web.get = custom; web.get({ rejectUnauthorized: false });',
    'function require() { return custom; } const web = require("https"); web.get({ rejectUnauthorized: false });',
    'import web from "https"; const req = web.request; req({ rejectUnauthorized: false });',
  ]) {
    const result = check(source)
    assert.equal(result.observations.length, 0, source)
    assert.equal(result.status, 'PARTIAL', source)
  }
})

test('dynamic options and override order become gaps instead of confident configuration observations', () => {
  for (const argument of ['options', '{ rejectUnauthorized: false, ...options }', '{ ...options, rejectUnauthorized: false }', '{ rejectUnauthorized: false, rejectUnauthorized: true }', '{ rejectUnauthorized: false, [key]: true }', '{ get rejectUnauthorized() { return false; } }']) {
    const result = check(`import web from "https"; web.request(${argument});`)
    assert.equal(result.observations.length, 0, argument)
    assert.equal(result.status, 'PARTIAL', argument)
  }
  for (const args of ['{ rejectUnauthorized: false }, options', 'url, { rejectUnauthorized: false }']) {
    const result = check(`import web from "https"; web.request(${args});`)
    assert.equal(result.observations.length, 0)
    assert.equal(result.status, 'PARTIAL')
  }
})

test('input errors are bounded fixed messages and unsupported languages are not assessed', () => {
  for (const path of ['../x.js', '/x.js', 'C:/x.js', 'x\\y.js', '//host/x.js', 'x\ny.js', 'x'.repeat(4097)]) {
    assert.equal(check('', path).gaps[0].code, 'INVALID_PATH')
  }
  assert.equal(check('', 'source.ts').gaps[0].code, 'UNSUPPORTED_LANGUAGE')
  assert.equal(check('', 'source.jsx').status, 'NOT_ASSESSED')
  assert.equal(check('const value: PRIVATE_DATA = ???;').gaps[0].code, 'PARSE_ERROR')
  assert.equal(JSON.stringify(check('const value: PRIVATE_DATA = ???;')).includes('PRIVATE_DATA'), false)
  assert.equal(check(' '.repeat(SOURCE_CHECK_LIMITS.max_file_bytes + 1)).gaps[0].code, 'SOURCE_SIZE_LIMIT')
})

test('node and observation limits are explicit and do not return clean status', () => {
  assert.equal(check(';'.repeat(SOURCE_CHECK_LIMITS.max_ast_nodes)).gaps[0].code, 'AST_SIZE_LIMIT')
  const result = check('process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";\n'.repeat(101))
  assert.equal(result.observations.length, SOURCE_CHECK_LIMITS.max_observations)
  assert.equal(result.status, 'PARTIAL')
  assert.ok(result.gaps.some(({ code }) => code === 'OBSERVATION_LIMIT'))
})

test('a dotted string property does not impersonate nested environment members', () => {
  assert.equal(check('process["env.NODE_TLS_REJECT_UNAUTHORIZED"] = "0";').observations.length, 0)
})

test('unsupported direct imports, aliases, escaping namespaces and dynamic calls remain gaps', () => {
  for (const source of [
    'require("https").request({ rejectUnauthorized: false });',
    'const req = require("https").request; req({ rejectUnauthorized: false });',
    'const web = await import("https"); web.request({ rejectUnauthorized: false });',
    'import web from "https"; const alias = web; alias.request = custom; web.request({ rejectUnauthorized: false });',
    'import web from "https"; mutate(web); web.request({ rejectUnauthorized: false });',
    'const env = process.env; env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
    'import web from "https"; web[method]({ rejectUnauthorized: false });',
    'import web from "https"; web.request.call(null, { rejectUnauthorized: false });',
    'import web from "https"; web.request?.({ rejectUnauthorized: false });',
    'import web from "https"; web?.request({ rejectUnauthorized: false });',
    'import web from "https"; let request; request = web.request; request({ rejectUnauthorized: false });',
    'const web = require("https", extra); web.request({ rejectUnauthorized: false });',
  ]) {
    const result = check(source)
    assert.equal(result.observations.length, 0, source)
    assert.equal(result.status, 'PARTIAL', source)
  }
})

test('printable Unicode paths retain their identity without relaxing traversal protection', () => {
  const result = check('process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";', 'src/certificats-é.js')
  assert.equal(result.path, 'src/certificats-é.js')
  assert.equal(result.status, 'CHECKED')
})

test('extension selects module or script parsing and syntax errors stay unassessed', () => {
  assert.equal(check('import https from "https";', 'test.cjs').status, 'NOT_ASSESSED')
  assert.equal(check('with (options) {}', 'test.js').status, 'PARTIAL')
  assert.equal(check('with (options) {}', 'test.mjs').status, 'NOT_ASSESSED')
  assert.equal(check('('.repeat(10000) + '0' + ')'.repeat(10000)).status, 'NOT_ASSESSED')
})

test('loop assignment targets invalidate affected built-in bindings', () => {
  for (const source of [
    'import web from "https"; for (web.request of replacements) {} web.request({ rejectUnauthorized: false });',
    'import web from "https"; for (web.request in replacements) {} web.request({ rejectUnauthorized: false });',
    'for (process of replacements) {} process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
    'for (process in replacements) {} process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";',
  ]) {
    const result = check(source)
    assert.equal(result.observations.length, 0, source)
    assert.equal(result.status, 'PARTIAL', source)
    assert.ok(result.gaps.some(({ code }) => code === 'AMBIGUOUS_BINDING'))
  }
})

test('assignment-based namespace escape suppresses configuration observations', () => {
  const result = check('import web from "https"; let alias; alias = web; alias.request = custom; web.request({ rejectUnauthorized: false });')
  assert.equal(result.observations.length, 0)
  assert.equal(result.status, 'PARTIAL')
  assert.ok(result.gaps.some(({ code }) => code === 'UNSUPPORTED_ALIAS'))
})

test('nested destructuring member writes and indirect environment writes are explicit gaps', () => {
  for (const source of [
    'import web from "https"; ({ replacement: web.request } = replacements); web.request({ rejectUnauthorized: false });',
    'import web from "https"; [web.request] = replacements; web.request({ rejectUnauthorized: false });',
    'import web from "https"; ({ nested: [web.request = custom] } = replacements); web.request({ rejectUnauthorized: false });',
    '({ replacement: process.env.NODE_TLS_REJECT_UNAUTHORIZED } = settings);',
    'for (process.env.NODE_TLS_REJECT_UNAUTHORIZED of settings) {}',
  ]) {
    const result = check(source)
    assert.equal(result.observations.length, 0, source)
    assert.equal(result.status, 'PARTIAL', source)
    assert.ok(result.gaps.length > 0)
  }
})
