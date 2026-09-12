import assert from 'node:assert/strict'
import { link, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { test } from 'node:test'

import { readBoundedAttestation, runEngageCli } from '../scripts/engage.mjs'

function capture() {
  const stdout = []
  const stderr = []
  return {
    stdout: { write: (value) => { stdout.push(String(value)); return true } },
    stderr: { write: (value) => { stderr.push(String(value)); return true } },
    stdoutText: () => stdout.join(''),
    stderrText: () => stderr.join(''),
  }
}

function operations(calls) {
  return {
    readAttestation: async (path) => {
      calls.push(['read-attestation', path])
      return 'I have full authority to assess this target.'
    },
    startEngagement: async (input) => {
      calls.push(['run', input])
      return {
        status: 'WAITING_FOR_MATERIAL',
        engagement_id: 'engagement:test',
        bundle: input.out,
        authorization_sha256: 'a'.repeat(64),
        target_sha256: 'b'.repeat(64),
        completed_routes: ['https-recon'],
        waiting_routes: ['authenticated-http-browser'],
      }
    },
    resumeEngagement: async (input) => {
      calls.push(['resume', input])
      return { status: 'ACTIVE', engagement_id: 'engagement:test', bundle: input.bundle }
    },
    getEngagementStatus: async (input) => {
      calls.push(['status', input])
      return { status: 'ACTIVE', engagement_id: 'engagement:test', bundle: input.bundle }
    },
    stopEngagement: async (input) => {
      calls.push(['stop', input])
      return { status: 'STOPPED', engagement_id: 'engagement:test', bundle: input.bundle }
    },
    getRepositoryNextWork: async (input) => {
      calls.push(['work-next', input])
      return { status: 'WAITING_FOR_AGENT_RESULT', engagement_id: 'engagement:test', bundle: input.bundle }
    },
    getRepositoryWorkStatus: async (input) => {
      calls.push(['work-status', input])
      return { status: 'RUNNING', engagement_id: 'engagement:test', bundle: input.bundle }
    },
    submitRepositoryWork: async (input) => {
      calls.push(['work-submit', input])
      return { status: 'READY_TO_FINALIZE', engagement_id: 'engagement:test', bundle: input.bundle }
    },
    finalizeRepositoryWork: async (input) => {
      calls.push(['work-finalize', input])
      return { status: 'COMPLETED', engagement_id: 'engagement:test', bundle: input.bundle }
    },
    validateRepositoryWork: async (input) => {
      calls.push(['work-validate', input])
      return { status: 'COMPLETED_WITH_GAPS', engagement_id: 'engagement:test', bundle: input.bundle }
    },
  }
}

test('help exposes one target-and-run engagement surface', async () => {
  const io = capture()
  assert.equal(await runEngageCli(['--help'], { ...operations([]), ...io }), 0)
  assert.match(io.stdoutText(), /engage run <target>/)
  assert.match(io.stdoutText(), /engage resume <engagement-directory>/)
  assert.match(io.stdoutText(), /engage status <engagement-directory>/)
  assert.match(io.stdoutText(), /engage stop <engagement-directory>/)
  assert.match(io.stdoutText(), /engage work next <engagement-directory>/)
  assert.match(io.stdoutText(), /engage work submit <engagement-directory>/)
  assert.match(io.stdoutText(), /browser:<32-character a-p Chrome-extension-id>/)
  assert.match(io.stdoutText(), /configuration=<absolute-page-session-adapter\.json>/)
  assert.match(io.stdoutText(), /one.*ordinary-language.*statement/is)
  assert.doesNotMatch(io.stdoutText(), /confirm-authorization|attest-authorized|approval/i)
})

test('run accepts one attestation file and starts the full target engagement', async () => {
  const calls = []
  const io = capture()
  const code = await runEngageCli([
    'run', 'https://target.example/app',
    '--attestation-file', 'C:\\trusted\\statement.txt',
    '--profile', 'full',
    '--out', 'C:\\engagements\\target',
    '--objective', 'Assess and integrate every reachable application surface.',
    '--credential-reference', 'browser:abcdefghijklmnopabcdefghijklmnop',
    '--json',
  ], { ...operations(calls), ...io })

  assert.equal(code, 0, io.stderrText())
  assert.deepEqual(calls[0], ['read-attestation', 'C:\\trusted\\statement.txt'])
  assert.deepEqual(calls[1], ['run', {
    target: 'https://target.example/app',
    statement: 'I have full authority to assess this target.',
    authorizationProfile: 'full',
    out: 'C:\\engagements\\target',
    objective: 'Assess and integrate every reachable application surface.',
    credentialReferences: ['browser:abcdefghijklmnopabcdefghijklmnop'],
    inputs: [],
  }])
  const output = JSON.parse(io.stdoutText())
  assert.equal(output.authorization_sha256, 'a'.repeat(64))
  assert.equal(output.status, 'WAITING_FOR_MATERIAL')
})

test('run accepts explicit process/device/browser kinds and typed local material', async () => {
  const calls = []
  const io = capture()
  assert.equal(await runEngageCli([
    'run', 'pid:42', '--target-kind', 'process',
    '--attestation-file', 'C:\\trusted\\statement.txt',
    '--profile', 'full',
    '--out', 'C:\\engagements\\process-42',
    '--input', 'plan=C:\\trusted\\trace-plan.json',
    '--input', 'artifact=C:\\trusted\\application.exe',
  ], { ...operations(calls), ...io }), 0, io.stderrText())

  assert.deepEqual(calls[1][1].target, { kind: 'process', locator: 'pid:42' })
  assert.deepEqual(calls[1][1].inputs, [
    { kind: 'plan', locator: 'C:\\trusted\\trace-plan.json' },
    { kind: 'artifact', locator: 'C:\\trusted\\application.exe' },
  ])
})

test('attestation reader preserves the exact bounded UTF-8 statement bytes', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'last-aperture-attestation-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const path = join(directory, 'statement.txt')
  const statement = 'I authorize the named target.\nContinue every applicable route.\n'
  await writeFile(path, statement, 'utf8')

  assert.equal(await readBoundedAttestation(path), statement)
})

test('attestation reader rejects oversized, invalid UTF-8, and multiply-linked files', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'last-aperture-attestation-invalid-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const path = join(directory, 'statement.txt')

  await writeFile(path, Buffer.alloc(8 * 1024 + 1, 0x61))
  await assert.rejects(() => readBoundedAttestation(path), /bounded|stable|read/i)

  await writeFile(path, Buffer.from([0xc3, 0x28]))
  await assert.rejects(() => readBoundedAttestation(path), /UTF-8/i)

  const alias = join(directory, 'statement-hardlink.txt')
  await writeFile(path, 'I authorize this target.', 'utf8')
  await link(path, alias)
  await assert.rejects(() => readBoundedAttestation(path), /regular non-link/i)
})

test('attestation reader refuses relative and remote filesystem endpoints before opening them', async () => {
  await assert.rejects(() => readBoundedAttestation('statement.txt'), /absolute local filesystem/i)
  await assert.rejects(
    () => readBoundedAttestation('\\\\server\\share\\statement.txt'),
    /absolute local filesystem/i,
  )
})

test('attestation reader refuses a linked ancestor before opening the statement', async (t) => {
  const directory = await mkdtemp(join(tmpdir(), 'last-aperture-attestation-link-'))
  t.after(() => rm(directory, { recursive: true, force: true }))
  const source = join(directory, 'source')
  const alias = join(directory, 'alias')
  await mkdir(source)
  await writeFile(join(source, 'statement.txt'), 'Authorized.', 'utf8')
  try {
    await symlink(source, alias, process.platform === 'win32' ? 'junction' : 'dir')
  } catch (error) {
    if (['EPERM', 'EACCES'].includes(error?.code)) {
      t.skip('creating a directory link is unavailable in this environment')
      return
    }
    throw error
  }
  await assert.rejects(
    () => readBoundedAttestation(join(alias, 'statement.txt')),
    /symbolic link|junction|canonical|alias/i,
  )
})

test('resume, status, and stop reuse the engagement without another attestation', async () => {
  for (const [command, expected] of [
    ['resume', 'resume'],
    ['status', 'status'],
    ['stop', 'stop'],
  ]) {
    const calls = []
    const io = capture()
    const args = [command, 'C:\\engagements\\target', '--json']
    if (command === 'stop') args.push('--reason', 'operator requested stop')
    assert.equal(await runEngageCli(args, { ...operations(calls), ...io }), 0)
    assert.equal(calls.length, 1)
    assert.equal(calls[0][0], expected)
    assert.equal(calls[0][1].bundle, 'C:\\engagements\\target')
    assert.equal('statement' in calls[0][1], false)
    assert.equal('authorization' in calls[0][1], false)
  }
})

test('repository work commands route through the existing engagement without a new attestation', async () => {
  for (const [args, expected, expectedInput] of [
    [['work', 'next', 'C:\\engagements\\target', '--json'], 'work-next', { bundle: 'C:\\engagements\\target' }],
    [['work', 'status', 'C:\\engagements\\target', '--json'], 'work-status', { bundle: 'C:\\engagements\\target' }],
    [[
      'work', 'submit', 'C:\\engagements\\target',
      '--work-id', `repository-work:${'a'.repeat(64)}`,
      '--result', 'C:\\results\\job.json', '--json',
    ], 'work-submit', {
      bundle: 'C:\\engagements\\target',
      workId: `repository-work:${'a'.repeat(64)}`,
      resultPath: 'C:\\results\\job.json',
    }],
    [['work', 'finalize', 'C:\\engagements\\target', '--json'], 'work-finalize', { bundle: 'C:\\engagements\\target' }],
    [['work', 'validate', 'C:\\engagements\\target', '--json'], 'work-validate', { bundle: 'C:\\engagements\\target' }],
  ]) {
    const calls = []
    const io = capture()
    assert.equal(await runEngageCli(args, { ...operations(calls), ...io }), 0, io.stderrText())
    assert.deepEqual(calls, [[expected, expectedInput]])
  }
})

test('CLI rejects repeat authorization switches, duplicate scalar options, and unknown commands', async () => {
  const cases = [
    ['resume', 'bundle', '--attestation-file', 'again.txt'],
    ['status', 'bundle', '--confirm-authorization'],
    ['run', 'https://target.example/', '--attestation-file', 'one', '--attestation-file', 'two', '--out', 'out'],
    ['run', 'https://target.example/', '--attestation-file', 'one', '--out', 'out', '--raw-command', 'anything'],
    ['run', 'pid:42', '--target-kind', 'unknown', '--attestation-file', 'one', '--out', 'out'],
    ['run', 'pid:42', '--target-kind', 'process', '--attestation-file', 'one', '--out', 'out', '--input', 'unknown=C:\\x'],
    ['work', 'submit', 'bundle', '--work-id', `repository-work:${'a'.repeat(64)}`],
    ['work', 'shell', 'bundle'],
    ['unknown'],
  ]
  for (const args of cases) {
    const calls = []
    const io = capture()
    assert.equal(await runEngageCli(args, { ...operations(calls), ...io }), 1)
    assert.equal(calls.length, 0)
    assert.match(io.stderrText(), /engage|unknown|duplicate|option|usage/i)
    assert.doesNotMatch(io.stderrText(), /at file:|node:internal|\.mjs:\d+/)
  }
})
