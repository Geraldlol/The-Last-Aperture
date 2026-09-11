import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'

import {
  RepositoryWorkflowError,
  buildRepositoryAuditInvocation,
  createRepositoryWorkEnvelope,
  planRepositoryWorkflow,
  prepareRepositoryNextWork,
  projectRepositoryChildStatus,
  submitRepositoryWorkResult,
  verifyRepositoryWorkEnvelope,
} from '../scripts/lib/engagement-repository-workflow.mjs'
import { stableJson } from '../scripts/lib/run-engine.mjs'

const AUDIT_CLI = fileURLToPath(new URL('../scripts/audit.mjs', import.meta.url))
const SHA_A = 'a'.repeat(64)
const SHA_B = 'b'.repeat(64)
const REPOSITORY_PATH = resolve('synthetic-repository')
const ENGAGEMENT_OUTPUT = resolve('synthetic-engagement', 'routes', 'repository-audit')
const CHILD_BUNDLE = join(ENGAGEMENT_OUTPUT, 'audit-run-1')
const AUDIT_BUNDLE = resolve('synthetic-audit', 'run')
const RESULT_PATH = resolve('synthetic-results', 'job.json')

function sha256(value) {
  return createHash('sha256').update(value, 'utf8').digest('hex')
}

function packet(overrides = {}) {
  const unsigned = {
    schema_version: '1.0.0',
    kind: 'LENS',
    run_id: 'audit-run-1',
    job_id: 'lens:authorization:0001',
    lens: 'authorization',
    inputs: [{ path: 'src/index.mjs', sha256: 'c'.repeat(64) }],
    ...overrides,
  }
  return {
    ...unsigned,
    packet_sha256: sha256(stableJson(unsigned, 0)),
  }
}

function childStatus(overrides = {}) {
  return {
    schema_version: '1.0.0',
    run_id: 'audit-run-1',
    state: 'RUNNING',
    phase: 'FANOUT',
    terminal: false,
    target: 'C:\\sensitive\\repository',
    capability_mode: 'T0',
    source_sealed: false,
    jobs: {
      total: 4,
      by_state: { DORMANT: 1, PENDING: 2, RUNNING: 0, SUCCEEDED: 1, FAILED: 0, SKIPPED: 0 },
      by_kind: { LENS: 4 },
      pending_current_phase: { total: 2, items: [], omitted: 2 },
      running: { total: 0, items: [], omitted: 0 },
      failed: { total: 0, items: [], omitted: 0 },
    },
    active_attempts: { total: 0, items: [], omitted: 0 },
    findings: {
      status: 'NO_FINDINGS_REPORTED',
      reported: 0,
      retained: 0,
      removed: 0,
      by_claimed_severity: {},
      by_verification: {},
    },
    coverage: {
      inventory_files: 3,
      examined_files: 1,
      unexamined_files: 2,
      topics: { obligations: 4, closed: 1, partial: 0, not_assessed: 3, open: 3 },
      gaps: { unique_open_gap_count: 2, exact_open_gap_count: 2, examples: [], omitted_example_count: 0 },
      closure: { status: 'OPEN' },
    },
    errors: { total: 0, items: [], omitted: 0 },
    next_step: { code: 'INSPECT_PENDING_WORK', message: 'provider-controlled detail is excluded' },
    bundle_integrity: 'VERIFIED',
    root_authenticity: 'UNANCHORED',
    live_repository: 'NOT_CHECKED',
    ...overrides,
  }
}

function binding(overrides = {}) {
  return {
    engagementId: 'engagement:repository-test',
    authoritySha256: SHA_A,
    targetSha256: SHA_B,
    childBundle: CHILD_BUNDLE,
    ...overrides,
  }
}

async function submissionFixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-repository-work-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const childBundle = join(root, 'child', 'audit-run-1')
  const stagingDirectory = join(root, 'controller-staging')
  const resultDirectory = join(root, 'agent-results')
  const resultPath = join(resultDirectory, 'result.json')
  await mkdir(childBundle, { recursive: true })
  await mkdir(stagingDirectory)
  await mkdir(resultDirectory)
  const resultBytes = Buffer.from(JSON.stringify({
    schema_version: '1.0.0',
    run_id: 'audit-run-1',
    job_id: 'lens:authorization:0001',
    state: 'SUCCEEDED',
  }))
  await writeFile(resultPath, resultBytes)
  const envelope = createRepositoryWorkEnvelope({
    ...binding({ childBundle }),
    childState: 'PLANNED',
    childPhase: 'RECON',
    packet: packet(),
  })
  return { root, childBundle, stagingDirectory, resultPath, resultBytes, envelope }
}

async function planningFixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'last-aperture-repository-plan-'))
  t.after(() => rm(root, { recursive: true, force: true }))
  const repositoryPath = join(root, 'repository')
  const outputDirectory = join(root, 'controller-output')
  const childBundle = join(outputDirectory, 'audit-run-1')
  await mkdir(repositoryPath)
  await mkdir(outputDirectory)
  await mkdir(childBundle)
  return { root, repositoryPath, outputDirectory, childBundle }
}

test('audit invocation builder exposes only fixed shell-free workflow commands', () => {
  assert.deepEqual(buildRepositoryAuditInvocation('plan', {
    repositoryPath: REPOSITORY_PATH,
    outputDirectory: ENGAGEMENT_OUTPUT,
  }), {
    public_entrypoint: process.execPath,
    arguments: [
      AUDIT_CLI,
      'plan', REPOSITORY_PATH,
      '--out', ENGAGEMENT_OUTPUT,
      '--seal-source',
      '--json',
    ],
    shell: false,
  })

  assert.deepEqual(buildRepositoryAuditInvocation('check-result', {
    childBundle: AUDIT_BUNDLE,
    resultPath: RESULT_PATH,
    resultSha256: SHA_A,
    resultSize: 1,
  }).arguments, [
    AUDIT_CLI, 'check-result', AUDIT_BUNDLE, RESULT_PATH,
    '--expected-sha256', SHA_A, '--expected-size', '1', '--json',
  ])
  assert.deepEqual(buildRepositoryAuditInvocation('ingest', {
    childBundle: AUDIT_BUNDLE,
    resultPath: RESULT_PATH,
    resultSha256: SHA_A,
    resultSize: 1,
  }).arguments, [
    AUDIT_CLI, 'ingest', AUDIT_BUNDLE, RESULT_PATH,
    '--expected-sha256', SHA_A, '--expected-size', '1',
  ])
  assert.deepEqual(buildRepositoryAuditInvocation('next', {
    childBundle: AUDIT_BUNDLE,
  }).arguments, [AUDIT_CLI, 'next', AUDIT_BUNDLE])
  assert.deepEqual(buildRepositoryAuditInvocation('status', {
    childBundle: AUDIT_BUNDLE,
  }).arguments, [AUDIT_CLI, 'status', AUDIT_BUNDLE, '--json'])
  assert.deepEqual(buildRepositoryAuditInvocation('finalize', {
    childBundle: AUDIT_BUNDLE,
  }).arguments, [AUDIT_CLI, 'finalize', AUDIT_BUNDLE])
  assert.deepEqual(buildRepositoryAuditInvocation('validate', {
    childBundle: AUDIT_BUNDLE,
  }).arguments, [AUDIT_CLI, 'validate', AUDIT_BUNDLE, '--json'])

  assert.throws(
    () => buildRepositoryAuditInvocation('shell', { argv: ['whoami'] }),
    (error) => error instanceof RepositoryWorkflowError && error.code === 'REPOSITORY_WORKFLOW_ACTION_UNKNOWN',
  )
  assert.throws(
    () => buildRepositoryAuditInvocation('next', { childBundle: AUDIT_BUNDLE, argv: ['whoami'] }),
    (error) => error.code === 'REPOSITORY_WORKFLOW_MATERIAL_INVALID',
  )
  assert.throws(
    () => buildRepositoryAuditInvocation('next', { childBundle: 'bad\0path' }),
    (error) => error.code === 'REPOSITORY_WORKFLOW_MATERIAL_INVALID',
  )
  assert.throws(
    () => buildRepositoryAuditInvocation('next', { childBundle: 'relative/audit-run' }),
    (error) => error.code === 'REPOSITORY_WORKFLOW_MATERIAL_INVALID',
  )
  assert.throws(
    () => buildRepositoryAuditInvocation('plan', {
      repositoryPath: REPOSITORY_PATH,
      outputDirectory: join(REPOSITORY_PATH, '.audit-runs'),
    }),
    (error) => error.code === 'REPOSITORY_WORKFLOW_MATERIAL_INVALID',
  )
})

test('planning reports waiting for agent work and never implies audit completion', async (t) => {
  const fixture = await planningFixture(t)
  const calls = []
  const result = await planRepositoryWorkflow({
    repositoryPath: fixture.repositoryPath,
    outputDirectory: fixture.outputDirectory,
  }, {
    execute: async (request) => {
      calls.push(request)
      return {
        exitCode: 0,
        stdout: JSON.stringify({
          run_id: 'audit-run-1',
          bundle: fixture.childBundle,
          capability_mode: 'T0',
          source_sealed: true,
          coverage_status: 'PLANNED',
        }),
        stderr: '',
      }
    },
  })

  assert.equal(calls.length, 1)
  assert.equal(calls[0].action, 'plan')
  assert.equal(calls[0].invocation.shell, false)
  assert.deepEqual(result, {
    schema_version: '1.0.0',
    state: 'WAITING_FOR_AGENT_RESULT',
    child_bundle: fixture.childBundle,
    run_id: 'audit-run-1',
    child_state: 'PLANNED',
    child_phase: 'RECON',
    capability_mode: 'T0',
    source_sealed: true,
    next_step: { code: 'INSPECT_PENDING_WORK' },
  })
  assert.notEqual(result.state, 'SUCCEEDED')
})

test('child status projection is read-only, detached, bounded, and truthful', () => {
  const source = childStatus()
  const before = structuredClone(source)
  const projected = projectRepositoryChildStatus(source)

  assert.deepEqual(source, before)
  assert.equal(projected.state, 'WAITING_FOR_AGENT_RESULT')
  assert.equal(projected.pending_job_count, 2)
  assert.equal(projected.child_state, 'RUNNING')
  assert.equal(projected.child_phase, 'FANOUT')
  assert.equal(projected.target, undefined)
  assert.equal(projected.next_step.message, undefined)
  projected.findings.reported = 99
  assert.equal(source.findings.reported, 0)

  assert.equal(projectRepositoryChildStatus(childStatus({
    state: 'COMPLETED', terminal: true,
    next_step: { code: 'REVIEW_REPORT', message: 'review' },
  })).state, 'COMPLETED')
  assert.equal(projectRepositoryChildStatus(childStatus({
    state: 'COMPLETE_WITH_GAPS', terminal: true,
    next_step: { code: 'REVIEW_REPORT', message: 'review' },
  })).state, 'COMPLETE_WITH_GAPS')
  assert.equal(projectRepositoryChildStatus(childStatus({
    state: 'FAILED', terminal: true,
    next_step: { code: 'REVIEW_FAILURE', message: 'review' },
  })).state, 'FAILED')
  assert.equal(projectRepositoryChildStatus(childStatus({
    phase: 'COMPLETENESS',
    jobs: {
      ...childStatus().jobs,
      pending_current_phase: { total: 0, items: [], omitted: 0 },
    },
    next_step: { code: 'REVIEW_FINALIZATION', message: 'finalize' },
  })).state, 'READY_TO_FINALIZE')
})

test('work envelopes deterministically bind authority, target, child bundle, and current packet', () => {
  const currentPacket = packet()
  const input = {
    ...binding(),
    childState: 'PLANNED',
    childPhase: 'RECON',
    packet: currentPacket,
  }
  const first = createRepositoryWorkEnvelope(input)
  const second = createRepositoryWorkEnvelope(structuredClone(input))

  assert.deepEqual(first, second)
  assert.match(first.work_id, /^repository-work:[a-f0-9]{64}$/)
  assert.match(first.work_envelope_sha256, /^[a-f0-9]{64}$/)
  assert.deepEqual(first.binding, {
    engagement_id: 'engagement:repository-test',
    authority_sha256: SHA_A,
    target_sha256: SHA_B,
    child_bundle: CHILD_BUNDLE,
    child_run_id: 'audit-run-1',
    child_state: 'PLANNED',
    child_phase: 'RECON',
    job_id: 'lens:authorization:0001',
    job_kind: 'LENS',
    packet_sha256: currentPacket.packet_sha256,
  })
  assert.equal(verifyRepositoryWorkEnvelope(first), true)

  const alteredEnvelope = structuredClone(first)
  alteredEnvelope.binding.target_sha256 = 'd'.repeat(64)
  assert.throws(
    () => verifyRepositoryWorkEnvelope(alteredEnvelope),
    (error) => error.code === 'REPOSITORY_WORK_ENVELOPE_INVALID',
  )

  const alteredPacket = packet()
  alteredPacket.job_id = 'lens:changed'
  assert.throws(
    () => createRepositoryWorkEnvelope({ ...input, packet: alteredPacket }),
    (error) => error.code === 'REPOSITORY_PACKET_INVALID',
  )
})

test('next work selects the child current packet and exposes one bound agent envelope', async (t) => {
  const fixture = await submissionFixture(t)
  const currentBinding = binding({ childBundle: fixture.childBundle })
  const firstPacket = packet()
  const secondPacket = packet({ job_id: 'lens:secrets:0001', lens: 'secrets' })
  const result = await prepareRepositoryNextWork(currentBinding, {
    execute: async ({ action, invocation }) => {
      assert.equal(action, 'next')
      assert.deepEqual(invocation.arguments, [AUDIT_CLI, 'next', currentBinding.childBundle])
      return {
        exitCode: 0,
        stdout: JSON.stringify({
          run_id: 'audit-run-1',
          state: 'PLANNED',
          phase: 'RECON',
          pending_jobs: [firstPacket, secondPacket],
        }),
        stderr: '',
      }
    },
  })

  assert.equal(result.state, 'WAITING_FOR_AGENT_RESULT')
  assert.equal(result.pending_packet_count, 2)
  assert.equal(result.work_envelope.packet.job_id, firstPacket.job_id)
  assert.equal(result.work_envelope.binding.authority_sha256, SHA_A)
  assert.equal(result.work_envelope.binding.target_sha256, SHA_B)
})

test('submitting a result checks and ingests one controller-staged exact byte file', async (t) => {
  const fixture = await submissionFixture(t)
  const { envelope } = fixture
  const actions = []
  const result = await submitRepositoryWorkResult({
    envelope,
    resultPath: fixture.resultPath,
  }, {
    stagingDirectory: fixture.stagingDirectory,
    loadExpectedEnvelope: async ({ workId, workEnvelopeSha256 }) => {
      assert.equal(workId, envelope.work_id)
      assert.equal(workEnvelopeSha256, envelope.work_envelope_sha256)
      return envelope
    },
    beforeIngest: async () => {},
    execute: async ({ action, invocation }) => {
      actions.push(action)
      const stagedPath = invocation.arguments[3]
      assert.equal(relative(fixture.stagingDirectory, stagedPath).startsWith('..'), false)
      assert.deepEqual(await readFile(stagedPath), fixture.resultBytes)
      if (action === 'check-result') {
        assert.deepEqual(invocation.arguments, [
          AUDIT_CLI, 'check-result', fixture.childBundle,
          stagedPath,
          '--expected-sha256', createHash('sha256').update(fixture.resultBytes).digest('hex'),
          '--expected-size', String(fixture.resultBytes.length), '--json',
        ])
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            valid: true,
            applied: false,
            run_id: 'audit-run-1',
            job_id: 'lens:authorization:0001',
            result_state: 'SUCCEEDED',
          }),
          stderr: '',
        }
      }
      assert.deepEqual(invocation.arguments, [
        AUDIT_CLI, 'ingest', fixture.childBundle,
        stagedPath,
        '--expected-sha256', createHash('sha256').update(fixture.resultBytes).digest('hex'),
        '--expected-size', String(fixture.resultBytes.length),
      ])
      return { exitCode: 0, stdout: 'Ingested result.\n', stderr: '' }
    },
  })

  assert.deepEqual(actions, ['check-result', 'ingest'])
  assert.deepEqual(result, {
    schema_version: '1.0.0',
    state: 'RESULT_INGESTED',
    accepted: true,
    applied: true,
    work_id: envelope.work_id,
    child_bundle: fixture.childBundle,
    run_id: 'audit-run-1',
    job_id: 'lens:authorization:0001',
    packet_sha256: envelope.binding.packet_sha256,
    result_state: 'SUCCEEDED',
    staged_result: {
      relative_path: `${envelope.work_envelope_sha256}-${createHash('sha256').update(fixture.resultBytes).digest('hex')}.json`,
      sha256: createHash('sha256').update(fixture.resultBytes).digest('hex'),
      size_bytes: fixture.resultBytes.length,
      recovered: false,
    },
    next_step: { code: 'READ_CHILD_STATUS' },
  })
})

test('an invalid or mismatched check result can never reach ingest', async (t) => {
  const fixture = await submissionFixture(t)
  const { envelope } = fixture

  for (const check of [
    { exitCode: 1, stdout: JSON.stringify({ valid: false, applied: false }), stderr: '' },
    {
      exitCode: 0,
      stdout: JSON.stringify({
        valid: true, applied: false, run_id: 'audit-run-1', job_id: 'lens:different:0001', result_state: 'SUCCEEDED',
      }),
      stderr: '',
    },
  ]) {
    const actions = []
    await assert.rejects(
      submitRepositoryWorkResult({ envelope, resultPath: fixture.resultPath }, {
        stagingDirectory: fixture.stagingDirectory,
        loadExpectedEnvelope: async () => envelope,
        execute: async ({ action }) => {
          actions.push(action)
          return check
        },
      }),
      (error) => error instanceof RepositoryWorkflowError
        && ['REPOSITORY_RESULT_CHECK_FAILED', 'REPOSITORY_RESULT_BINDING_MISMATCH'].includes(error.code),
    )
    assert.deepEqual(actions, ['check-result'])
  }
})

test('caller-recomputed self hashes cannot replace the controller-persisted work envelope', async (t) => {
  const fixture = await submissionFixture(t)
  const forged = createRepositoryWorkEnvelope({
    ...binding({ childBundle: fixture.childBundle, targetSha256: 'd'.repeat(64) }),
    childState: 'PLANNED',
    childPhase: 'RECON',
    packet: packet(),
  })
  assert.equal(verifyRepositoryWorkEnvelope(forged), true)
  assert.throws(
    () => verifyRepositoryWorkEnvelope(forged, fixture.envelope),
    (error) => error.code === 'REPOSITORY_WORK_ENVELOPE_NOT_PERSISTED',
  )

  let executed = false
  await assert.rejects(
    submitRepositoryWorkResult({ envelope: forged, resultPath: fixture.resultPath }, {
      stagingDirectory: fixture.stagingDirectory,
      loadExpectedEnvelope: async () => fixture.envelope,
      execute: async () => { executed = true },
    }),
    (error) => error.code === 'REPOSITORY_WORK_ENVELOPE_NOT_PERSISTED',
  )
  assert.equal(executed, false)

  await assert.rejects(
    submitRepositoryWorkResult({ envelope: fixture.envelope, resultPath: fixture.resultPath }, {
      stagingDirectory: fixture.stagingDirectory,
      execute: async () => { executed = true },
    }),
    (error) => error.code === 'REPOSITORY_WORK_ENVELOPE_EXPECTATION_REQUIRED',
  )
  assert.equal(executed, false)
})

test('source pathname replacement after validation cannot change the staged ingest bytes', async (t) => {
  const fixture = await submissionFixture(t)
  let checkedPath
  const result = await submitRepositoryWorkResult({
    envelope: fixture.envelope,
    resultPath: fixture.resultPath,
  }, {
    stagingDirectory: fixture.stagingDirectory,
    loadExpectedEnvelope: async () => fixture.envelope,
    beforeIngest: async () => {},
    execute: async ({ action, invocation }) => {
      const stagedPath = invocation.arguments[3]
      if (action === 'check-result') {
        checkedPath = stagedPath
        await writeFile(fixture.resultPath, '{"forged":true}')
        return {
          exitCode: 0,
          stdout: JSON.stringify({
            valid: true, applied: false, run_id: 'audit-run-1',
            job_id: 'lens:authorization:0001', result_state: 'SUCCEEDED',
          }),
          stderr: '',
        }
      }
      assert.equal(stagedPath, checkedPath)
      assert.deepEqual(await readFile(stagedPath), fixture.resultBytes)
      return { exitCode: 0, stdout: 'Ingested result.\n', stderr: '' }
    },
  })
  assert.equal(result.state, 'RESULT_INGESTED')
})

test('staged result mutation is denied by the host or detected before ingest', async (t) => {
  const fixture = await submissionFixture(t)
  const actions = []
  let mutationDenied = false
  let outcome
  let failure
  try {
    outcome = await submitRepositoryWorkResult({ envelope: fixture.envelope, resultPath: fixture.resultPath }, {
      stagingDirectory: fixture.stagingDirectory,
      loadExpectedEnvelope: async () => fixture.envelope,
      beforeIngest: async () => {},
      execute: async ({ action, invocation }) => {
        actions.push(action)
        if (action === 'check-result') {
          try {
            await writeFile(invocation.arguments[3], '{"changed":true}')
          } catch (error) {
            assert.match(error.code, /^(?:EACCES|EBUSY|EPERM)$/u)
            mutationDenied = true
          }
          return {
            exitCode: 0,
            stdout: JSON.stringify({
              valid: true, applied: false, run_id: 'audit-run-1',
              job_id: 'lens:authorization:0001', result_state: 'SUCCEEDED',
            }),
            stderr: '',
          }
        }
        assert.equal(mutationDenied, true)
        assert.deepEqual(await readFile(invocation.arguments[3]), fixture.resultBytes)
        return { exitCode: 0, stdout: 'Ingested result.\n', stderr: '' }
      },
    })
  } catch (error) {
    failure = error
  }
  if (mutationDenied) {
    assert.equal(failure, undefined)
    assert.equal(outcome.state, 'RESULT_INGESTED')
    assert.deepEqual(actions, ['check-result', 'ingest'])
  } else {
    assert.equal(failure?.code, 'REPOSITORY_RESULT_STAGING_CHANGED')
    assert.deepEqual(actions, ['check-result'])
  }
})

test('an uncertain ingest failure exposes durable reconciliation state', async (t) => {
  const fixture = await submissionFixture(t)
  await assert.rejects(
    submitRepositoryWorkResult({ envelope: fixture.envelope, resultPath: fixture.resultPath }, {
      stagingDirectory: fixture.stagingDirectory,
      loadExpectedEnvelope: async () => fixture.envelope,
      beforeIngest: async () => {},
      execute: async ({ action }) => {
        if (action === 'check-result') {
          return {
            exitCode: 0,
            stdout: JSON.stringify({
              valid: true, applied: false, run_id: 'audit-run-1',
              job_id: 'lens:authorization:0001', result_state: 'SUCCEEDED',
            }),
            stderr: '',
          }
        }
        throw new Error('controller connection dropped')
      },
    }),
    (error) => {
      assert.equal(error.code, 'REPOSITORY_INGEST_OUTCOME_AMBIGUOUS')
      assert.equal(error.recovery.state, 'INGEST_OUTCOME_AMBIGUOUS')
      assert.equal(error.recovery.work_id, fixture.envelope.work_id)
      assert.equal(error.recovery.next_step.code, 'RECONCILE_CHILD_STATUS_BEFORE_RETRY')
      assert.match(error.recovery.staged_result.sha256, /^[a-f0-9]{64}$/u)
      return true
    },
  )
})

test('supervisor uncertainty, errors, and unconfirmed termination can never count as ingest success', async (t) => {
  const fixture = await submissionFixture(t)
  const unsafeOutcomes = [
    { status: 'UNCERTAIN' },
    { errorCode: 'ROUTE_LOG_INTEGRITY_FAILED' },
    { started: true, termination_confirmed: false },
  ]
  for (const unsafe of unsafeOutcomes) {
    await assert.rejects(
      submitRepositoryWorkResult({
        envelope: fixture.envelope,
        resultPath: fixture.resultPath,
      }, {
        stagingDirectory: fixture.stagingDirectory,
        loadExpectedEnvelope: async () => fixture.envelope,
        beforeIngest: async () => {},
        execute: async ({ action }) => {
          if (action === 'check-result') {
            return {
              exitCode: 0,
              stdout: JSON.stringify({
                valid: true, applied: false, run_id: 'audit-run-1',
                job_id: 'lens:authorization:0001', result_state: 'SUCCEEDED',
              }),
              stderr: '',
            }
          }
          return {
            exitCode: 0,
            stdout: 'untrusted supervisor success\n',
            stderr: '',
            requestMayHaveBeenSent: true,
            ...unsafe,
          }
        },
      }),
      (error) => error.code === 'REPOSITORY_INGEST_OUTCOME_AMBIGUOUS',
    )
  }
})

test('planned child bundle must remain under the declared controller output directory', async (t) => {
  const fixture = await planningFixture(t)
  const outside = join(fixture.root, 'outside-controller-output', 'audit-run-1')
  await mkdir(outside, { recursive: true })
  await assert.rejects(
    planRepositoryWorkflow({
      repositoryPath: fixture.repositoryPath,
      outputDirectory: fixture.outputDirectory,
    }, {
      execute: async () => ({
        exitCode: 0,
        stdout: JSON.stringify({
          run_id: 'audit-run-1',
          bundle: outside,
          capability_mode: 'T0',
          source_sealed: false,
        }),
        stderr: '',
      }),
    }),
    (error) => error.code === 'REPOSITORY_PLAN_FAILED',
  )
})
