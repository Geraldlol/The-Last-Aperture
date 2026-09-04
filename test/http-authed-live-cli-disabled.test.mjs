import { spawnSync } from 'node:child_process'
import { join } from 'node:path'
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { main } from '../scripts/http-authed.mjs'

const LIVE_COMMANDS = [
  'campaign-attested',
]

test('controller-governed live commands reach ordinary argument validation', async () => {
  for (const command of LIVE_COMMANDS) {
    await assert.rejects(
      () => main([command], { write: () => {} }),
      (error) => error?.code !== 'HTTP_AUTHED_LIVE_IO_DISABLED'
        && /requires --scope/i.test(error.message),
      command,
    )
  }
})

test('unimplemented probe-attested remains unavailable without touching I/O', async () => {
  let transports = 0
  await assert.rejects(
    () => main(['probe-attested'], {
      transport: async () => { transports += 1 },
      write: () => {},
    }),
    /expected a supported http-authed command/i,
  )
  assert.equal(transports, 0)
})

test('retired written-authority live routes are unavailable before transport I/O', async () => {
  let transports = 0
  for (const command of ['probe-written', 'campaign-written']) {
    await assert.rejects(
      () => main([command], {
        transport: async () => { transports += 1 },
        write: () => {},
      }),
      /expected a supported http-authed command/i,
      command,
    )
  }
  assert.equal(transports, 0)
})

test('campaign-stop writes a grant-bound stop request without target transport', async () => {
  const grant = 'a'.repeat(64)
  const ledger = join(process.cwd(), 'synthetic-stop-ledger')
  let received
  let output = ''
  let transports = 0
  await main([
    'campaign-stop',
    '--ledger', ledger,
    '--campaign-grant-sha256', grant,
    '--operator-id', 'operator:test',
    '--json',
  ], {
    requestCampaignStop: async (input) => {
      received = input
      return {
        status: 'STOP_REQUESTED',
        ledger,
        campaign_grant_sha256: grant,
        operator_id: 'operator:test',
      }
    },
    transport: async () => { transports += 1 },
    write: (value) => { output += value },
  })
  assert.equal(received.directory, ledger)
  assert.equal(received.campaignGrantSha256, grant)
  assert.equal(received.operatorId, 'operator:test')
  assert.equal(transports, 0)
  assert.equal(JSON.parse(output).status, 'STOP_REQUESTED')
})

test('public help exposes fixed controller-governed live campaigns', () => {
  const help = spawnSync(process.execPath, ['scripts/http-authed.mjs', '--help'], {
    encoding: 'utf8',
    shell: false,
    windowsHide: true,
  })
  assert.equal(help.status, 0)
  assert.doesNotMatch(help.stdout, /campaign-attested.*DISABLED/i)
  assert.doesNotMatch(help.stdout, /http-authed probe-written/i)
  assert.doesNotMatch(help.stdout, /campaign-written/i)
  assert.match(help.stdout, /http-authed campaign-stop/)
  assert.match(help.stdout, /invoking a live command is the operator's campaign launch directive/i)
  assert.match(help.stdout, /fixed sealed request list/i)
  assert.match(help.stdout, /single-action campaign[\s\S]*campaign ledger/i)
  assert.match(help.stdout, /standalone probes are not public/i)
})
