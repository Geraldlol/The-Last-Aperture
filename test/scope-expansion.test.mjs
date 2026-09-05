import test from 'node:test'
import assert from 'node:assert/strict'
import { expandDependencyScope } from '../scripts/lib/scope-expansion.mjs'

function text(path, content) {
  return { path, kind: 'text', content }
}

test('dependency scope follows bounded repository-local imports in both directions', () => {
  const inventory = {
    entries: [
      text('src/routes/orders.ts', "import { loadOrder } from '../services/orders.js'\n"),
      text('src/services/orders.ts', "import { enforceTenant } from '../security/tenant'\n"),
      text('src/security/tenant.ts', 'export function enforceTenant() {}\n'),
      text('src/unrelated.ts', 'export const unrelated = true\n'),
    ],
  }
  const direct = [{
    path: 'src/routes/orders.ts',
    kind: 'text',
    path_activators: ['**/routes/**'],
    signal_activators: [],
  }]

  const expanded = expandDependencyScope(direct, inventory, { maxDepth: 2, maxFiles: 8 })
  assert.equal(expanded.truncated, false)
  assert.deepEqual(expanded.matches.map(({ path }) => path), [
    'src/routes/orders.ts',
    'src/security/tenant.ts',
    'src/services/orders.ts',
  ])
  assert.deepEqual(
    expanded.matches.find(({ path }) => path === 'src/security/tenant.ts').scope_expansion,
    {
      direction: 'dependency',
      depth: 2,
      from_path: 'src/services/orders.ts',
    },
  )

  const reverse = expandDependencyScope([{
    path: 'src/security/tenant.ts',
    kind: 'text',
    path_activators: [],
    signal_activators: ['enforceTenant'],
  }], inventory, { maxDepth: 2, maxFiles: 8 })
  assert.ok(reverse.matches.some(({ path, scope_expansion: scope }) =>
    path === 'src/routes/orders.ts' && scope?.direction === 'dependent'))
})

test('dependency expansion is deterministic and reports a hard file cap', () => {
  const inventory = {
    entries: [
      text('src/a.js', "import './b.js'\nimport './c.js'\n"),
      text('src/b.js', "import './d.js'\n"),
      text('src/c.js', "import './e.js'\n"),
      text('src/d.js', ''),
      text('src/e.js', ''),
    ],
  }
  const direct = [{
    path: 'src/a.js',
    kind: 'text',
    path_activators: ['src/a.js'],
    signal_activators: [],
  }]

  const expanded = expandDependencyScope(direct, inventory, { maxDepth: 4, maxFiles: 3 })
  assert.equal(expanded.truncated, true)
  assert.deepEqual(expanded.matches.map(({ path }) => path), [
    'src/a.js',
    'src/b.js',
    'src/c.js',
  ])
})

test('dependency depth limits are reported as truncation rather than silent closure', () => {
  const inventory = {
    entries: [
      text('src/a.js', "import './b.js'\n"),
      text('src/b.js', "import './c.js'\n"),
      text('src/c.js', "import './d.js'\n"),
      text('src/d.js', ''),
    ],
  }
  const expanded = expandDependencyScope([{
    path: 'src/a.js',
    kind: 'text',
    path_activators: ['src/a.js'],
    signal_activators: [],
  }], inventory, { maxDepth: 2, maxFiles: 8 })

  assert.equal(expanded.truncated, true)
  assert.deepEqual(expanded.matches.map(({ path }) => path), [
    'src/a.js',
    'src/b.js',
    'src/c.js',
  ])
})

test('dependency scope recognizes common repository-local module syntaxes', () => {
  const inventory = {
    entries: [
      text('app/routes/orders.py', 'from ..security.tenant import enforce_tenant\n'),
      text('app/security/tenant.py', 'def enforce_tenant(): pass\n'),
      text('lib/controllers/orders.rb', "require_relative '../services/orders'\n"),
      text('lib/services/orders.rb', 'class Orders; end\n'),
      text('src/lib.rs', 'mod policy;\n'),
      text('src/policy.rs', 'pub fn authorize() {}\n'),
    ],
  }

  for (const [start, expected] of [
    ['app/routes/orders.py', 'app/security/tenant.py'],
    ['lib/controllers/orders.rb', 'lib/services/orders.rb'],
    ['src/lib.rs', 'src/policy.rs'],
  ]) {
    const expanded = expandDependencyScope([{
      path: start,
      kind: 'text',
      path_activators: [start],
      signal_activators: [],
    }], inventory, { maxDepth: 1, maxFiles: 8 })
    assert.ok(expanded.matches.some(({ path }) => path === expected), `${start} -> ${expected}`)
  }
})
