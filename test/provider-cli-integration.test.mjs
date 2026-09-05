import {
  createHash,
  generateKeyPairSync,
  sign as signBytes,
} from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import assert from 'node:assert/strict'

import {
  main,
  runProviderCommand,
  verifyControlBundle,
} from '../scripts/audit.mjs'
import {
  createRunPlan,
  stableJson,
  writeRunPlanBundle,
} from '../scripts/lib/run-engine.mjs'
import { hashAttemptEvent } from '../scripts/lib/attempts.mjs'
import {
  renderMarkdownReport,
  renderSarif,
} from '../scripts/lib/report.mjs'

const SHA_A = 'a'.repeat(64)
const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)

test('public run-provider refuses before reading caller-selected bundle or runtime config', async () => {
  await assert.rejects(
    () => main(['run-provider', 'missing-bundle', 'missing-provider-config.json']),
    (error) => {
      assert.equal(error.code, 'PROVIDER_RUNTIME_ENROLLMENT_REQUIRED')
      assert.match(error.message, /disabled before bundle or configuration access/i)
      return true
    },
  )
})

function sha256(value) {
  return createHash('sha256').update(value).digest('hex')
}

function rehashForgedPlan(plan) {
  const { run } = plan
  const material = {
    schema_version: run.schema_version,
    capability_mode: run.capability_mode,
    repository: { tree_digest: run.repository.tree_digest },
    policy_digest: run.policy_digest,
    lens_pack_digest: run.lens_pack_digest,
    ...(run.lens_shared_contract_digest
      ? { lens_shared_contract_digest: run.lens_shared_contract_digest }
      : {}),
    coverage_policy: run.coverage.policy,
    database_discovery_digest: run.database_discovery.digest,
    control_snapshot_sha256: run.control_snapshot.root_sha256,
    ...(run.source_snapshot
      ? { source_snapshot_sha256: run.source_snapshot.root_sha256 }
      : {}),
    jobs: plan.jobSidecars,
  }
  run.plan_digest = sha256(stableJson(material, 0))
}

function providerConfig(runtimePath, signingKeyPath) {
  return {
    schema_version: '1.0.0',
    protocol: 'docker-stdio-v1',
    runtime_path: runtimePath,
    image: `sha256:${SHA_A}`,
    receipt_signing_private_key_path: signingKeyPath,
    limits: {
      wall_time_ms: 30_000,
      docker_command_timeout_ms: 10_000,
      idle_timeout_ms: 10_000,
      delivery_timeout_ms: 10_000,
      max_deliveries: 100,
      max_file_bytes: 1024 * 1024,
      max_total_delivery_bytes: 16 * 1024 * 1024,
      max_stdout_bytes: 4 * 1024 * 1024,
      max_stderr_bytes: 1024 * 1024,
      max_frame_bytes: 2 * 1024 * 1024,
      memory_bytes: 128 * 1024 * 1024,
      cpus: 0.5,
      pids: 32,
      nofile: 64,
      tmpfs_bytes: 16 * 1024 * 1024,
    },
  }
}

function fakeExecution({
  config,
  packet,
  artifacts,
  containerName,
}, resultOverrides = {}) {
  const state = resultOverrides.state ?? 'SUCCEEDED'
  const findings = resultOverrides.findings ?? []
  const topicAssessments = resultOverrides.topic_assessments ?? (
    state === 'SUCCEEDED' && Array.isArray(packet.topic_obligations)
      ? packet.topic_obligations.map((topic) => {
          const topicFindings = findings.filter((finding) => finding.topic === topic)
          return topicFindings.length > 0
            ? {
                topic,
                disposition: 'finding',
                reason: 'The integration fixture reported a finding for this topic.',
                finding_ids: topicFindings.map(
                  ({ candidate_id: candidateId }) => candidateId,
                ),
              }
            : {
                topic,
                disposition: 'examined-clean',
                reason: 'The integration fixture assessed this bounded topic.',
                evidence: ['The fixture provider completed its bounded topic check.'],
              }
        })
      : []
  )
  const deliveries = artifacts.map((artifact, index) => ({
    delivery_id: `deliveryopaqueidentifier${String(index).padStart(4, '0')}`,
    artifact_id: artifact.artifact_id,
    artifact_kind: artifact.kind,
    logical_name: artifact.logical_name,
    expected_sha256: artifact.sha256,
    size: artifact.size,
    events: [
      {
        state: 'DELIVERED',
        observed_at: '2026-07-29T10:00:01.000Z',
        bytes_sent: artifact.size,
        transport_sha256: artifact.sha256,
      },
      {
        state: 'CONSUMED',
        observed_at: '2026-07-29T10:00:02.000Z',
        challenge_base64: Buffer.alloc(32, index).toString('base64'),
        hmac_algorithm: 'HMAC-SHA256',
        hmac_domain: 'red-team-audit/provider-delivery/v1',
        challenge_hmac_sha256: SHA_C,
      },
    ],
  }))
  return {
    schema_version: '1.0.0',
    protocol: 'docker-stdio-v1',
    job_result: {
      schema_version: '1.0.0',
      run_id: packet.run_id,
      job_id: packet.job_id,
      input_sha256: packet.packet_sha256,
      producer: {
        name: 'integration-fixture-provider',
        version: '1.0.0',
        instance_id: 'fixture:provider-1',
      },
      state,
      examined_files: artifacts
        .filter(({ kind }) => kind === 'FILE')
        .map(({ logical_name: logicalName }) => logicalName),
      findings,
      coverage_gaps: resultOverrides.coverage_gaps ?? [],
      ...(Array.isArray(packet.topic_obligations)
        ? { topic_assessments: topicAssessments }
        : {}),
      ...(resultOverrides.error ? { error: resultOverrides.error } : {}),
      ...(resultOverrides.store_contributions
        ? { store_contributions: resultOverrides.store_contributions }
        : {}),
    },
    receipt: {
      schema_version: '1.0.0',
      observer: 'red-team-audit-controller',
      receipt_scope: 'BYTE_DELIVERY_AND_CHALLENGE_CONSUMPTION_ONLY',
      semantic_analysis_proven: false,
      run_id: packet.run_id,
      job_id: packet.job_id,
      packet_sha256: packet.packet_sha256,
      session_id: 'sessionopaqueidentifier01',
      started_at: '2026-07-29T10:00:00.000Z',
      completed_at: '2026-07-29T10:00:03.000Z',
      backend: {
        type: 'OCI_DOCKER',
        runtime_path: config.runtime_path,
        runtime_version: 'fixture-1.0',
        context: 'default',
        image: config.image,
        container_name: containerName,
        container_id: SHA_B,
        security_profile: 'builtin',
      },
      deliveries,
      transcript_sha256: SHA_C,
    },
  }
}

test('run-provider uses sealed bytes, commits observed coverage, and signs one envelope', {
  skip: Number(process.versions.node.split('.')[0]) < 24
    ? 'observed runner requires Node.js 24+'
    : false,
}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-provider-target-'))
  const output = await mkdtemp(join(tmpdir(), 'rta-provider-output-'))
  try {
    await mkdir(join(root, 'src'))
    await writeFile(
      join(root, 'src', 'app.js'),
      'export const sealedMarker = "ORIGINAL_SEALED_BYTES"\n',
    )
    await writeFile(
      join(root, 'package.json'),
      '{"name":"provider-integration-fixture","type":"module"}\n',
    )
    const plan = await createRunPlan({
      targetRoot: root,
      lensDirectory: resolve('skills/red-team-audit/lenses'),
      sealSource: true,
      createdAt: new Date('2026-07-29T09:59:00.000Z'),
    })
    const written = await writeRunPlanBundle(plan, join(output, 'bundles'))

    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const signingKeyPath = join(output, 'receipt-signing-key.pem')
    const publicKeyPath = join(output, 'receipt-public-key.pem')
    const configPath = join(output, 'provider-config.json')
    await writeFile(
      signingKeyPath,
      privateKey.export({ type: 'pkcs8', format: 'pem' }),
      { mode: 0o600 },
    )
    await writeFile(
      publicKeyPath,
      publicKey.export({ type: 'spki', format: 'pem' }),
    )
    await writeFile(
      configPath,
      `${JSON.stringify(providerConfig(process.execPath, signingKeyPath), null, 2)}\n`,
    )

    await writeFile(
      join(root, 'src', 'app.js'),
      'export const sealedMarker = "MUTATED_LIVE_REPOSITORY"\n',
    )
    let observedSource
    let observedControls
    await runProviderCommand(
      [written.directory, configPath],
      {},
      {
        providerRunner: async (options) => {
          observedSource = options.artifacts
            .find(({ logical_name: path }) => path === 'src/app.js')
            ?.bytes.toString('utf8')
          observedControls = options.artifacts
            .filter(({ kind }) => kind === 'CONTROL')
            .map(({ logical_name: logicalName, bytes }) => ({
              logicalName,
              text: bytes.toString('utf8'),
            }))
          const source = options.artifacts
            .find(({ logical_name: path }) => path === 'src/app.js')
          const topic = options.packet.owned_topics[0]
            ?? options.packet.known_topics[0]
          const raisedBy = options.packet.owned_topics.length === 0
            ? options.packet.lens
            : undefined
          return fakeExecution(options, {
            findings: [{
              candidate_id: `${topic}:signed-envelope-fixture`,
              lens: options.packet.lens,
              topic,
              title: 'Signed provider finding survives controller replay',
              claimed_impact_severity: 'Medium',
              location: ['src/app.js:1'],
              evidence: 'export const sealedMarker = "ORIGINAL_SEALED_BYTES"',
              source_anchors: [{
                file_id: source.artifact_id,
                snapshot_sha256: options.packet.snapshot_id,
                start_byte: 0,
                end_byte: source.bytes.length,
                excerpt_sha256: sha256(source.bytes),
              }],
              attack: 'A caller reaches the fixture behavior through its exported value',
              impact: 'The fixture demonstrates a signed provider-authored security claim',
              reachable_from: 'src/app.js exported module',
              confidence: 'High',
              proof_plan: 'Verify the sealed first-line bytes and independently assess the claim',
              ...(raisedBy ? { raised_by: raisedBy } : {}),
            }],
          })
        },
      },
    )

    const run = JSON.parse(await readFile(written.runPath, 'utf8'))
    const completedJob = run.jobs.find(
      ({ coverage_authority: authority }) =>
        authority === 'CONTROLLER_OBSERVED_CONSUMPTION',
    )
    assert.match(observedSource, /ORIGINAL_SEALED_BYTES/)
    assert.doesNotMatch(observedSource, /MUTATED_LIVE_REPOSITORY/)
    assert.equal(
      observedControls.some(
        ({ logicalName }) => logicalName === 'controls/provider-policy.json',
      ),
      true,
    )
    assert.equal(
      observedControls.some(
        ({ logicalName }) => logicalName === 'controls/policy.json',
      ),
      false,
    )
    assert.equal(completedJob?.lens, 'ai-generated-code')
    for (const ownerLensPath of [
      'lenses/web-and-api.md',
      'lenses/embedded-iot-ot-security.md',
    ]) {
      const delivered = observedControls.find(
        ({ logicalName }) => logicalName === ownerLensPath,
      )
      assert.ok(delivered, `${ownerLensPath} owner contract was not delivered`)
      assert.match(delivered.text, /## Severity calibration/)
    }
    const encodedRoot = JSON.stringify(root).slice(1, -1)
    for (const { text } of observedControls) {
      assert.equal(text.includes(root), false)
      assert.equal(text.includes(encodedRoot), false)
    }
    assert.ok(completedJob)
    assert.match(completedJob.receipt_sha256, /^[a-f0-9]{64}$/)
    assert.equal(run.attempt_events.at(-1).event, 'COMMITTED')
    assert.deepEqual(
      run.attempt_events.map(({ event }) => event),
      ['LEASED', 'STARTED', 'RESULT_CAPTURED', 'VALIDATED', 'COMMITTED'],
    )
    const lease = run.attempt_events[0]
    assert.equal(
      Date.parse(lease.expires_at) - Date.parse(lease.occurred_at),
      30_000
        + providerConfig(process.execPath, signingKeyPath).limits.wall_time_ms
        + (
          10
          * providerConfig(process.execPath, signingKeyPath)
            .limits.docker_command_timeout_ms
        ),
    )
    const executionArtifacts = Object.keys(run.artifacts)
      .filter((key) => key.startsWith('execution_'))
    assert.equal(executionArtifacts.length, 1)
    const markdown = renderMarkdownReport(run)
    const sarif = renderSarif(run)
    assert.match(markdown, /CONTROLLER_OBSERVED_CONSUMPTION/)
    assert.match(markdown, new RegExp(completedJob.receipt_sha256))
    assert.equal(
      sarif.runs[0].invocations[0].properties
        .controller_observed_consumption_jobs,
      1,
    )

    const changedFinding = structuredClone(run)
    changedFinding.findings[0].title = 'Unsigned replacement title'
    await assert.rejects(
      verifyControlBundle(written.directory, changedFinding),
      /does not retain signed field title/,
    )

    const changedCoverage = structuredClone(run)
    changedCoverage.coverage.lenses
      .find(({ lens }) => lens === completedJob.lens)
      .examined_paths = []
    await assert.rejects(
      verifyControlBundle(written.directory, changedCoverage),
      /examined-file coverage is absent from its lens aggregate/,
    )

    const executionArtifact = run.artifacts[completedJob.execution_artifact_key]
    const executionPath = join(written.directory, executionArtifact.path)
    const originalEnvelopeContent = await readFile(executionPath, 'utf8')
    const rewriteEnvelope = async (mutate, resign, reflectFinding = false) => {
      const envelope = JSON.parse(originalEnvelopeContent)
      mutate(envelope)
      envelope.controller.provider_execution_sha256 = sha256(
        stableJson(envelope.provider_execution, 0),
      )
      if (resign) {
        const { signature: _discarded, ...unsigned } = envelope
        envelope.signature.value_base64 = signBytes(
          null,
          Buffer.from(stableJson(unsigned, 0), 'utf8'),
          privateKey,
        ).toString('base64')
      }
      const content = stableJson(envelope)
      const digest = sha256(content)
      const candidate = structuredClone(run)
      if (reflectFinding) {
        candidate.findings[0] = structuredClone(
          envelope.provider_execution.job_result.findings[0],
        )
      }
      candidate.artifacts[completedJob.execution_artifact_key].sha256 = digest
      let previousEventSha256 = null
      for (const event of candidate.attempt_events) {
        if (event.execution_artifact_sha256 !== undefined) {
          event.execution_artifact_sha256 = digest
        }
        event.previous_event_sha256 = previousEventSha256
        event.event_sha256 = hashAttemptEvent(event)
        previousEventSha256 = event.event_sha256
      }
      await writeFile(executionPath, content)
      return candidate
    }

    try {
      const invalidAnchorMutations = [
        (anchor) => {
          anchor.snapshot_sha256 = 'f'.repeat(64)
        },
        (anchor) => {
          anchor.end_byte += 1
        },
        (anchor) => {
          anchor.excerpt_sha256 = 'f'.repeat(64)
        },
        (anchor) => {
          anchor.file_id = `file_${'f'.repeat(64)}`
        },
      ]
      for (const mutateAnchor of invalidAnchorMutations) {
        const invalidAnchorRun = await rewriteEnvelope((envelope) => {
          mutateAnchor(
            envelope.provider_execution.job_result
              .findings[0].source_anchors[0],
          )
        }, true, true)
        await assert.rejects(
          verifyControlBundle(written.directory, invalidAnchorRun),
          /unbound source anchor|source anchor excerpt digest does not match/,
        )
        await writeFile(executionPath, originalEnvelopeContent)
      }

      const invalidSignatureRun = await rewriteEnvelope((envelope) => {
        envelope.provider_execution.job_result.findings[0].title =
          'Envelope body changed without the external signing key'
      }, false)
      await assert.rejects(
        verifyControlBundle(written.directory, invalidSignatureRun),
        /signature verification failed/,
      )
    } finally {
      await writeFile(executionPath, originalEnvelopeContent)
    }

    const pinnedValidation = execFileSync(
      process.execPath,
      [
        resolve('scripts/audit.mjs'),
        'validate',
        written.directory,
        '--receipt-public-key',
        publicKeyPath,
      ],
      { encoding: 'utf8' },
    )
    assert.match(pinnedValidation, /^VALID:/)
  } finally {
    await rm(root, { recursive: true, force: true })
    await rm(output, { recursive: true, force: true })
  }
})

test('bundle verification rejects scope and closure-round sidecar forgeries', async (t) => {
  const cases = [
    {
      name: 'scoped file removal',
      mutate(plan) {
        const sidecar = plan.jobSidecars.find(
          ({ kind, scoped_files: scopedFiles }) =>
            kind === 'LENS' && scopedFiles.length > 0,
        )
        assert.ok(sidecar)
        sidecar.scoped_files = []
      },
      pattern: /sidecar scoped_files mismatch/,
    },
    {
      name: 'closure round rewrite',
      mutate(plan) {
        const sidecar = plan.jobSidecars.find(
          ({ kind, closure_round: closureRound }) =>
            kind === 'LENS' && closureRound === 1,
        )
        assert.ok(sidecar)
        sidecar.closure_round = 2
      },
      pattern: /sidecar closure_round mismatch/,
    },
    {
      name: 'database discovery projection rewrite',
      mutate(plan) {
        const sidecar = plan.jobSidecars.find(
          ({ lens, database_discovery: discovery }) =>
            lens === 'database-and-data-stores' && discovery,
        )
        assert.ok(sidecar)
        sidecar.database_discovery.graph_digest = 'f'.repeat(64)
      },
      pattern: /sidecar database_discovery mismatch/,
    },
  ]

  for (const fixture of cases) {
    await t.test(fixture.name, async () => {
      const root = await mkdtemp(join(tmpdir(), 'rta-sidecar-target-'))
      const output = await mkdtemp(join(tmpdir(), 'rta-sidecar-output-'))
      try {
        await mkdir(join(root, 'src'))
        await writeFile(join(root, 'src', 'app.js'), 'export const app = true\n')
        await writeFile(join(root, 'package.json'), '{"name":"sidecar-fixture"}\n')
        const plan = await createRunPlan({
          targetRoot: root,
          lensDirectory: resolve('skills/red-team-audit/lenses'),
          maxClosureRounds: 2,
          createdAt: new Date('2026-07-29T12:30:00.000Z'),
        })
        fixture.mutate(plan)
        rehashForgedPlan(plan)
        const written = await writeRunPlanBundle(plan, join(output, 'bundles'))

        await assert.rejects(
          verifyControlBundle(written.directory, plan.run),
          fixture.pattern,
        )
      } finally {
        await rm(root, { recursive: true, force: true })
        await rm(output, { recursive: true, force: true })
      }
    })
  }
})

test('observed database work cannot omit the sealed discovery control', {
  skip: Number(process.versions.node.split('.')[0]) < 24
    ? 'observed runner requires Node.js 24+'
    : false,
}, async () => {
  const root = await mkdtemp(join(tmpdir(), 'rta-provider-database-target-'))
  const output = await mkdtemp(join(tmpdir(), 'rta-provider-database-output-'))
  try {
    await mkdir(join(root, 'src'))
    await writeFile(
      join(root, 'package.json'),
      '{"name":"provider-database-fixture","dependencies":{"pg":"8.16.3"}}\n',
    )
    await writeFile(
      join(root, 'src', 'database.js'),
      [
        "import pg from 'pg'",
        'export const pool = new pg.Pool({',
        '  connectionString: process.env.DATABASE_URL,',
        '})',
        '',
      ].join('\n'),
    )
    const plan = await createRunPlan({
      targetRoot: root,
      lensDirectory: resolve('skills/red-team-audit/lenses'),
      sealSource: true,
      createdAt: new Date('2026-07-29T11:59:00.000Z'),
    })
    assert.ok(plan.run.database_discovery.store_candidates.length > 0)
    const written = await writeRunPlanBundle(plan, join(output, 'bundles'))

    const { privateKey, publicKey } = generateKeyPairSync('ed25519')
    const signingKeyPath = join(output, 'receipt-signing-key.pem')
    const publicKeyPath = join(output, 'receipt-public-key.pem')
    const configPath = join(output, 'provider-config.json')
    await writeFile(
      signingKeyPath,
      privateKey.export({ type: 'pkcs8', format: 'pem' }),
      { mode: 0o600 },
    )
    await writeFile(
      publicKeyPath,
      publicKey.export({ type: 'spki', format: 'pem' }),
    )
    await writeFile(
      configPath,
      `${JSON.stringify(providerConfig(process.execPath, signingKeyPath), null, 2)}\n`,
    )

    let observedDatabase = false
    for (let invocation = 0; invocation < 10 && !observedDatabase; invocation += 1) {
      await runProviderCommand(
        [written.directory, configPath],
        {},
        {
          providerRunner: async (options) => {
            observedDatabase =
              options.packet.lens === 'database-and-data-stores'
            return fakeExecution(
              options,
              observedDatabase
                ? {
                    state: 'FAILED',
                    error: {
                      code: 'FIXTURE_SEMANTIC_REVIEW_UNAVAILABLE',
                      message: 'This control-consumption fixture does not assess database semantics.',
                      recoverable: false,
                    },
                  }
                : {},
            )
          },
        },
      )
    }
    assert.equal(observedDatabase, true)

    const run = JSON.parse(await readFile(written.runPath, 'utf8'))
    const databaseJob = run.jobs.find((job) =>
      job.lens === 'database-and-data-stores'
      && job.coverage_authority === 'CONTROLLER_OBSERVED_CONSUMPTION')
    assert.ok(databaseJob)
    const artifact = run.artifacts[databaseJob.execution_artifact_key]
    const executionPath = join(written.directory, artifact.path)
    const envelope = JSON.parse(await readFile(executionPath, 'utf8'))
    const receipt = envelope.provider_execution.receipt
    const deliveryCount = receipt.deliveries.length
    receipt.deliveries = receipt.deliveries.filter(
      ({ logical_name: logicalName }) =>
        logicalName !== 'controls/database-discovery.json',
    )
    assert.equal(receipt.deliveries.length, deliveryCount - 1)

    const receiptSha256 = sha256(stableJson(receipt, 0))
    envelope.controller.receipt_sha256 = receiptSha256
    envelope.controller.provider_execution_sha256 = sha256(
      stableJson(envelope.provider_execution, 0),
    )
    const { signature: _discarded, ...unsigned } = envelope
    envelope.signature.value_base64 = signBytes(
      null,
      Buffer.from(stableJson(unsigned, 0), 'utf8'),
      privateKey,
    ).toString('base64')

    const content = stableJson(envelope)
    const executionSha256 = sha256(content)
    const candidate = structuredClone(run)
    candidate.jobs
      .find(({ job_id: jobId }) => jobId === databaseJob.job_id)
      .receipt_sha256 = receiptSha256
    candidate.artifacts[databaseJob.execution_artifact_key].sha256 =
      executionSha256
    let previousEventSha256 = null
    for (const event of candidate.attempt_events) {
      if (event.attempt_id === databaseJob.attempt_id) {
        if (event.execution_artifact_sha256 !== undefined) {
          event.execution_artifact_sha256 = executionSha256
        }
        if (event.receipt_sha256 !== undefined) {
          event.receipt_sha256 = receiptSha256
        }
      }
      event.previous_event_sha256 = previousEventSha256
      event.event_sha256 = hashAttemptEvent(event)
      previousEventSha256 = event.event_sha256
    }
    await writeFile(executionPath, content)

    await assert.rejects(
      verifyControlBundle(written.directory, candidate),
      /did not consume controls\/database-discovery\.json/,
    )
  } finally {
    await rm(root, { recursive: true, force: true })
    await rm(output, { recursive: true, force: true })
  }
})
