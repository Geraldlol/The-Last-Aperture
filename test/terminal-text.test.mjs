import assert from 'node:assert/strict'
import { test } from 'node:test'
import {
  terminalSafeDocumentText,
  terminalSafeJson,
  terminalSafeLines,
  terminalSafeSerializedJson,
  terminalSafeText,
} from '../scripts/lib/terminal-text.mjs'

test('terminal-safe text makes control, OSC, newline, and bidi state visible', () => {
  const rendered = terminalSafeText(
    `before\n\u001b]8;;https://attacker.invalid\u0007link\u001b]8;;\u0007\u2028\u2029\u202Eafter`,
  )
  assert.equal(
    rendered,
    'before\\u000A\\u001B]8;;https://attacker.invalid\\u0007link\\u001B]8;;\\u0007\\u2028\\u2029\\u202Eafter',
  )
  assert.doesNotMatch(rendered, /[\u0000-\u001f\u007f-\u009f\u202a-\u202e]/u)
})

test('terminal-safe text bounds adversarial output', () => {
  assert.equal(terminalSafeText('abcdef', 3), 'abc...[truncated]')
})

test('terminal-safe JSON stays parseable while neutralizing bidi and C1 state', () => {
  const rendered = terminalSafeJson({ message: `left\u2028\u2029\u202Eright\u0085`, nested: ['ok\nnext'] })
  assert.doesNotMatch(rendered, /[\u0080-\u009f\u202a-\u202e]/u)
  assert.deepEqual(JSON.parse(rendered), {
    message: `left\u2028\u2029\u202Eright\u0085`,
    nested: ['ok\nnext'],
  })
})

test('stable serialized JSON and deliberate line structure can be preserved safely', () => {
  const serialized = terminalSafeSerializedJson('{"message":"left\u202Eright"}\n')
  assert.equal(serialized, '{"message":"left\\u202Eright"}\n')
  assert.deepEqual(JSON.parse(serialized), { message: `left\u202Eright` })

  assert.equal(
    terminalSafeLines([`first\u001Bline`, 'second']),
    'first\\u001Bline\nsecond',
  )
  assert.equal(
    terminalSafeDocumentText(`heading\nbody\u001B[2J\n`),
    'heading\nbody\\u001B[2J\n',
  )
})
