import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import Ajv2020 from 'ajv/dist/2020.js'
import {
  PolicyValidationError,
  authorizeAction,
  createStaticPolicy,
  normalizePolicy,
  validatePolicy,
} from '../scripts/lib/policy.mjs'

/**
 * These tests map individual behaviors to relevant OWASP APTS requirement IDs
 * as design anchors only. Passing them is not an APTS conformance claim.
 */

const ROOT = fileURLToPath(new URL('../', import.meta.url))
const FIXTURES = new URL('../fixtures/adversarial-policy/', import.meta.url)

function fixture(name) {
  return readFileSync(new URL(name, FIXTURES), 'utf8')
}

function jsonFixture(name) {
  return JSON.parse(fixture(name))
}

function explicitPolicy() {
  return {
    schema_version: '1.0',
    policy_id: 'test-policy',
    mode: 'test',
    workspace_root: ROOT,
    capabilities: {
      read_file: {
        enabled: true,
        roots: ['fixtures/adversarial-policy'],
      },
      write_file: {
        enabled: true,
        roots: ['test/security'],
      },
      execute: {
        enabled: true,
        commands: [
          {
            program: 'node',
            args: ['--test'],
          },
        ],
      },
      network: {
        enabled: true,
        destinations: [
          {
            scheme: 'https',
            host: 'api.example.test',
            ports: [443],
            path_prefix: '/v1',
          },
        ],
      },
    },
  }
}

function external(raw = explicitPolicy()) {
  return normalizePolicy(raw, {
    workspaceRoot: ROOT,
    policySource: 'external',
  })
}

function remoteStaticPolicy() {
  const raw = explicitPolicy()
  raw.mode = 'remote_static'
  raw.capabilities.write_file = { enabled: false, roots: [] }
  raw.capabilities.execute = { enabled: false, commands: [] }
  return raw
}

function codeOf(result) {
  return result.reasons[0].code
}

test('RoE schema is strict and declares all four explicit capabilities', () => {
  // APTS-SE-001 correspondence: machine-readable RoE validation.
  const schema = JSON.parse(readFileSync(new URL('../schemas/roe.schema.json', import.meta.url), 'utf8'))
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema')
  assert.equal(schema.additionalProperties, false)
  assert.deepEqual(
    schema.properties.capabilities.required,
    ['read_file', 'write_file', 'execute', 'network'],
  )
  assert.equal(
    schema.allOf[0].then.properties.capabilities.properties.write_file
      .properties.enabled.const,
    false,
  )
})

test('normalized policy artifacts satisfy the published RoE schema', () => {
  const schema = JSON.parse(readFileSync(
    new URL('../schemas/roe.schema.json', import.meta.url),
    'utf8',
  ))
  const ajv = new Ajv2020({ strict: true, allErrors: true })
  const validate = ajv.compile(schema)
  const policy = createStaticPolicy({ workspaceRoot: ROOT })
  assert.equal(validate(policy), true, JSON.stringify(validate.errors))
  assert.equal(policy.policy_source, 'default')
})

test('default policy is deeply immutable, static, and read-only', () => {
  // APTS-SC-020 / APTS-MR-012 correspondence: immutable external action boundary.
  const policy = createStaticPolicy({ workspaceRoot: ROOT })
  assert.equal(policy.policy_source, 'default')
  assert.equal(policy.mode, 'static')
  assert.equal(policy.capabilities.read_file.enabled, true)
  assert.equal(policy.capabilities.write_file.enabled, false)
  assert.equal(policy.capabilities.execute.enabled, false)
  assert.equal(policy.capabilities.network.enabled, false)
  assert.ok(Object.isFrozen(policy))
  assert.ok(Object.isFrozen(policy.capabilities))
  assert.ok(Object.isFrozen(policy.capabilities.read_file.roots))
  assert.throws(() => {
    policy.capabilities.read_file.roots.push('outside')
  }, TypeError)
})

test('normalization copies caller input before freezing it', () => {
  const raw = explicitPolicy()
  const policy = external(raw)
  raw.capabilities.read_file.roots[0] = '.'
  raw.capabilities.execute.commands[0].args.push('injected')

  assert.deepEqual(policy.capabilities.read_file.roots, ['fixtures/adversarial-policy'])
  assert.deepEqual(policy.capabilities.execute.commands[0].args, ['--test'])
})

test('explicit policy is rejected unless the trusted orchestrator marks it external', () => {
  // APTS-MR-001/MR-004/MR-010 correspondence: target-controlled files are data,
  // not configuration or authority. This validates provenance signaling only;
  // the caller still owns the actual trust boundary.
  assert.throws(
    () => normalizePolicy(explicitPolicy(), {
      workspaceRoot: ROOT,
      policySource: 'repository',
    }),
    (error) =>
      error instanceof PolicyValidationError
      && error.issues[0].code === 'POLICY_SOURCE_UNTRUSTED',
  )

  const validation = validatePolicy(explicitPolicy(), { workspaceRoot: ROOT })
  assert.equal(validation.valid, false)
  assert.equal(validation.errors[0].code, 'POLICY_SOURCE_UNTRUSTED')
  assert.ok(Object.isFrozen(validation))
})

test('repository instructions cannot change default scope or mode', () => {
  // APTS-MR-001/MR-010/MR-023 correspondence: the agent and repository are
  // untrusted relative to the external policy kernel.
  const repositoryContent = fixture('repository-instructions.txt')
  const policy = createStaticPolicy({
    workspaceRoot: ROOT,
    repositoryContent,
  })

  assert.equal(policy.mode, 'static')
  assert.equal(policy.capabilities.write_file.enabled, false)
  assert.equal(policy.capabilities.network.enabled, false)

  const smuggled = authorizeAction(policy, jsonFixture('scope-widening-action.json'))
  assert.equal(smuggled.allowed, false)
  assert.equal(codeOf(smuggled), 'UNKNOWN_FIELD')
})

test('unknown actions and non-normalized policies fail closed', () => {
  // APTS-SC-020 correspondence: only declared external allowlist actions exist.
  const policy = createStaticPolicy({ workspaceRoot: ROOT })
  const unknown = authorizeAction(policy, { type: 'delete_repository' })
  assert.equal(unknown.allowed, false)
  assert.equal(codeOf(unknown), 'ACTION_TYPE_UNKNOWN')

  const rawPolicy = explicitPolicy()
  const rawDecision = authorizeAction(rawPolicy, {
    type: 'read_file',
    path: 'fixtures/adversarial-policy/repository-instructions.txt',
  })
  assert.equal(rawDecision.allowed, false)
  assert.equal(codeOf(rawDecision), 'POLICY_NOT_NORMALIZED')
})

test('read access is root-bounded and carries a realpath enforcement requirement', () => {
  // Pure lexical validation cannot inspect symlinks. The allow decision makes
  // the required dispatcher-side realpath containment check explicit rather
  // than implying this module provides a filesystem sandbox (APTS-SC-019).
  const policy = external()
  const allowed = authorizeAction(policy, {
    type: 'read_file',
    path: 'fixtures/adversarial-policy/repository-instructions.txt',
  })
  assert.equal(allowed.allowed, true)
  assert.equal(allowed.enforcement.realpath_containment_required, true)
  assert.ok(allowed.normalized_action.path.startsWith(ROOT))
  assert.ok(Object.isFrozen(allowed))

  const outsideRoot = authorizeAction(policy, {
    type: 'read_file',
    path: 'skills/red-team-audit/SKILL.md',
  })
  assert.equal(outsideRoot.allowed, false)
  assert.equal(codeOf(outsideRoot), 'PATH_NOT_ALLOWED')
})

test('absolute, foreign, traversal, UNC, and control-character paths are denied', () => {
  // APTS-SE-006 correspondence: validate scope immediately before an action.
  const policy = external()
  for (const path of jsonFixture('external-paths.json')) {
    const result = authorizeAction(policy, { type: 'read_file', path })
    assert.equal(result.allowed, false, `unexpectedly allowed ${JSON.stringify(path)}`)
    assert.ok(
      [
        'ABSOLUTE_PATH_FORBIDDEN',
        'PATH_TRAVERSAL_FORBIDDEN',
        'CONTROL_CHARACTER_FORBIDDEN',
      ].includes(codeOf(result)),
      `${JSON.stringify(path)} produced unexpected ${codeOf(result)}`,
    )
  }
})

test('write access is limited to its explicit root', () => {
  const policy = external()
  const allowed = authorizeAction(policy, {
    type: 'write_file',
    path: 'test/security/proof.mjs',
  })
  assert.equal(allowed.allowed, true)
  assert.equal(allowed.matched_rule.root, 'test/security')

  const denied = authorizeAction(policy, {
    type: 'write_file',
    path: 'src/app.mjs',
  })
  assert.equal(denied.allowed, false)
  assert.equal(codeOf(denied), 'PATH_NOT_ALLOWED')
})

test('execute requires an exact argv allowlist entry and no shell interpretation', () => {
  // APTS-SC-020 correspondence: program and parameter bounds are enforced
  // outside the model. This module authorizes only; it does not spawn anything.
  const policy = external()
  const allowed = authorizeAction(policy, {
    type: 'execute',
    program: 'node',
    args: ['--test'],
  })
  assert.equal(allowed.allowed, true)
  assert.equal(allowed.enforcement.shell_must_be_false, true)
  assert.equal(allowed.enforcement.exact_argv_required, true)

  const widened = authorizeAction(policy, {
    type: 'execute',
    program: 'node',
    args: ['--test', 'test/other.test.mjs'],
  })
  assert.equal(widened.allowed, false)
  assert.equal(codeOf(widened), 'COMMAND_NOT_ALLOWED')
})

test('shell and control-character command payloads are denied before matching', () => {
  const policy = external()
  for (const command of jsonFixture('shell-commands.json')) {
    const result = authorizeAction(policy, {
      type: 'execute',
      program: command.program,
      args: command.args,
    })
    assert.equal(result.allowed, false, `unexpectedly allowed ${JSON.stringify(command)}`)
    assert.ok(
      [
        'CONTROL_CHARACTER_FORBIDDEN',
        'SHELL_CONTROL_FORBIDDEN',
        'SHELL_PROGRAM_FORBIDDEN',
      ].includes(codeOf(result)),
      `${JSON.stringify(command)} produced unexpected ${codeOf(result)}`,
    )
  }
})

test('network authorization validates every redirect hop independently', () => {
  // APTS-SE-006/APTS-MR-007 correspondence: a redirect is a new proposed
  // destination, not inherited authority from the first URL.
  const policy = external()
  const urls = jsonFixture('network-redirects.json')
  const allowed = authorizeAction(policy, {
    type: 'network',
    url: urls.allowed,
    redirects: [urls.allowed_redirect],
  })
  assert.equal(allowed.allowed, true)
  assert.equal(allowed.enforcement.reauthorize_each_redirect, true)
  assert.equal(allowed.enforcement.dns_resolution_scope_check_required, true)

  const redirected = authorizeAction(policy, {
    type: 'network',
    url: urls.allowed,
    redirects: [urls.external_redirect],
  })
  assert.equal(redirected.allowed, false)
  assert.equal(codeOf(redirected), 'NETWORK_REDIRECT_OUT_OF_SCOPE')
  assert.equal(redirected.reasons[0].details.redirect_index, 0)
})

test('network credentials, forbidden schemes, and redirect loops are denied', () => {
  const policy = external()
  const urls = jsonFixture('network-redirects.json')
  const credentials = authorizeAction(policy, {
    type: 'network',
    url: urls.credential_url,
  })
  assert.equal(credentials.allowed, false)
  assert.equal(codeOf(credentials), 'NETWORK_CREDENTIALS_FORBIDDEN')

  const scheme = authorizeAction(policy, {
    type: 'network',
    url: urls.forbidden_scheme,
  })
  assert.equal(scheme.allowed, false)
  assert.equal(codeOf(scheme), 'NETWORK_SCHEME_FORBIDDEN')

  const loop = authorizeAction(policy, {
    type: 'network',
    url: urls.allowed,
    redirects: [urls.allowed],
  })
  assert.equal(loop.allowed, false)
  assert.equal(codeOf(loop), 'NETWORK_REDIRECT_LOOP')
})

test('static mode denies every mutation, command, and network action', () => {
  // Read-only is a mode invariant, not merely the default capability values.
  const policy = createStaticPolicy({ workspaceRoot: ROOT })
  for (const action of jsonFixture('static-mutations.json')) {
    const result = authorizeAction(policy, action)
    assert.equal(result.allowed, false)
    assert.equal(codeOf(result), 'STATIC_MODE_READ_ONLY')
  }
})

test('remote_static permits only externally allowlisted reads and network', () => {
  const policy = external(remoteStaticPolicy())
  assert.equal(authorizeAction(policy, {
    type: 'read_file',
    path: 'fixtures/adversarial-policy/prompt-injection.txt',
  }).allowed, true)
  assert.equal(authorizeAction(policy, {
    type: 'network',
    url: 'https://api.example.test/v1/audit',
    redirects: [],
  }).allowed, true)
  assert.equal(
    codeOf(authorizeAction(policy, {
      type: 'write_file',
      path: 'test/security/result.json',
    })),
    'REMOTE_STATIC_MODE_READ_NETWORK_ONLY',
  )
  assert.equal(
    codeOf(authorizeAction(policy, {
      type: 'execute',
      program: 'node',
      args: ['--test'],
    })),
    'REMOTE_STATIC_MODE_READ_NETWORK_ONLY',
  )

  const dormantNetwork = remoteStaticPolicy()
  dormantNetwork.capabilities.network = { enabled: false, destinations: [] }
  assert.equal(validatePolicy(dormantNetwork, {
    workspaceRoot: ROOT,
    policySource: 'external',
  }).valid, false)
})

test('contradictory static policy and dormant authority are rejected', () => {
  const staticWrite = explicitPolicy()
  staticWrite.mode = 'static'
  assert.throws(
    () => external(staticWrite),
    (error) =>
      error instanceof PolicyValidationError
      && error.issues[0].code === 'STATIC_MODE_CONTRADICTION',
  )

  const dormant = explicitPolicy()
  dormant.capabilities.execute.enabled = false
  assert.throws(
    () => external(dormant),
    (error) =>
      error instanceof PolicyValidationError
      && error.issues[0].code === 'DORMANT_AUTHORITY_FORBIDDEN',
  )
})
