import assert from 'node:assert/strict'
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import {
  applyJobResult,
  beginJob,
  validateJobResult,
} from '../scripts/lib/job-protocol.mjs'
import { validateRun } from '../scripts/lib/contracts.mjs'
import { renderMarkdownReport, renderSarif } from '../scripts/lib/report.mjs'
import { createRunPlan } from '../scripts/lib/run-engine.mjs'

const SHA_A = 'a'.repeat(64)
const SHA_B = 'b'.repeat(64)
const SHA_C = 'c'.repeat(64)

function plannedRun() {
  return {
    schema_version: '1.0.0',
    run_id: 'run:topic-assessment:test',
    state: 'PLANNED',
    phase: 'RECON',
    capability_mode: 'STATIC',
    created_at: '2026-09-04T12:00:00Z',
    tool: {
      name: 'red-team-audit',
      version: '0.12.0',
      corpus_sha256: SHA_C,
    },
    plan_digest: SHA_A,
    policy_digest: SHA_B,
    lens_pack_digest: SHA_C,
    repository: {
      root: 'C:/workspace/example',
      tree_digest: SHA_A,
      dirty: 'unknown',
    },
    scope: {
      included_paths: ['src/app.js'],
      excluded_paths: [],
    },
    activated_lenses: ['web-and-api'],
    jobs: [{
      job_id: 'lens:web-and-api',
      kind: 'LENS',
      lens: 'web-and-api',
      state: 'PENDING',
      topic_obligations: ['authn-session', 'authz-object-level'],
      topic_assessments: [],
    }],
    coverage: {
      inventory: ['src/app.js'],
      examined: [],
      unexamined: [{ path: 'src/app.js', reason: 'audit job has not run' }],
      lenses: [{
        lens: 'web-and-api',
        status: 'NOT_ASSESSED',
        applicable_paths: ['src/app.js'],
        examined_paths: [],
        reason: 'audit job has not run',
      }],
      gaps: [],
    },
    store_profiles: [],
    findings: [],
    errors: [],
    artifacts: {},
  }
}

const sidecar = {
  job_id: 'lens:web-and-api',
  scoped_files: ['src/app.js'],
  owned_topics: ['authn-session', 'authz-object-level'],
  known_topics: ['authn-session', 'authz-object-level'],
  topic_obligations: ['authn-session', 'authz-object-level'],
}

function finding() {
  return {
    candidate_id: 'authz-object-level:assessment',
    lens: 'web-and-api',
    topic: 'authz-object-level',
    title: 'Object lookup omits tenant authorization',
    claimed_impact_severity: 'High',
    location: ['src/app.js:1'],
    evidence: 'loadObject(request.params.id)',
    attack: 'Request another tenant object identifier.',
    impact: 'Reads another tenant object.',
    reachable_from: 'GET /objects/:id',
    confidence: 'High',
    proof_plan: 'Replay the request with two tenant identities.',
  }
}

function result(run, overrides = {}) {
  return {
    schema_version: '1.0.0',
    run_id: run.run_id,
    job_id: 'lens:web-and-api',
    input_sha256: SHA_A,
    producer: {
      name: 'assessment-test-provider',
      version: '1.0.0',
      instance_id: 'assessment-test-provider:1',
    },
    state: 'SUCCEEDED',
    examined_files: ['src/app.js'],
    findings: [],
    coverage_gaps: [],
    topic_assessments: [],
    ...overrides,
  }
}

function accept(run, value, packetSidecar = sidecar) {
  return applyJobResult(beginJob(run, 'lens:web-and-api'), value, {
    expectedPacketSha256: SHA_A,
    sidecar: packetSidecar,
  })
}

test('job-result topic assessments are sealed records with disposition-specific evidence', () => {
  const run = plannedRun()
  const valid = result(run, {
    findings: [finding()],
    topic_assessments: [
      {
        topic: 'authn-session',
        disposition: 'examined-clean',
        reason: 'The bounded route uses the centralized session guard.',
        evidence: ['Session middleware runs before the route handler.'],
        evidence_paths: ['src/app.js'],
      },
      {
        topic: 'authz-object-level',
        disposition: 'finding',
        reason: 'The route trusts an object identifier without tenant authorization.',
        finding_ids: ['authz-object-level:assessment'],
      },
    ],
  })
  assert.equal(validateJobResult(valid).valid, true)

  const missingCleanEvidence = structuredClone(valid)
  delete missingCleanEvidence.topic_assessments[0].evidence
  assert.equal(validateJobResult(missingCleanEvidence).valid, false)

  const unsupportedDisposition = structuredClone(valid)
  unsupportedDisposition.topic_assessments[0].disposition = 'clear'
  assert.equal(validateJobResult(unsupportedDisposition).valid, false)
})

test('ingest requires every sealed owned-topic obligation and persists accepted assessments', () => {
  const run = plannedRun()
  assert.throws(
    () => accept(run, result(run, {
      topic_assessments: [{
        topic: 'authz-object-level',
        disposition: 'not-assessed',
        reason: 'The provider could not resolve the authorization flow.',
        coverage_gap_areas: ['topic:authz-object-level'],
      }],
      coverage_gaps: [{
        area: 'topic:authz-object-level',
        reason: 'Authorization flow could not be resolved.',
      }],
    })),
    /missing topic assessment.*authn-session/i,
  )

  const accepted = accept(run, result(run, {
    findings: [finding()],
    topic_assessments: [
      {
        topic: 'authn-session',
        disposition: 'examined-clean',
        reason: 'The bounded route uses the centralized session guard.',
        evidence: ['Session middleware runs before the route handler.'],
        evidence_paths: ['src/app.js'],
      },
      {
        topic: 'authz-object-level',
        disposition: 'finding',
        reason: 'The route trusts an object identifier without tenant authorization.',
        finding_ids: ['authz-object-level:assessment'],
      },
    ],
  }))

  assert.deepEqual(
    accepted.jobs[0].topic_assessments.map(({ topic, disposition }) => ({ topic, disposition })),
    [
      { topic: 'authn-session', disposition: 'examined-clean' },
      { topic: 'authz-object-level', disposition: 'finding' },
    ],
  )
  assert.equal(accepted.coverage.lenses[0].status, 'RAN')
})

test('topic authority, scoped evidence, finding links, and gap links fail closed', () => {
  const base = plannedRun()
  const clean = {
    topic: 'authn-session',
    disposition: 'examined-clean',
    reason: 'The bounded route uses the centralized session guard.',
    evidence: ['Session middleware runs before the route handler.'],
    evidence_paths: ['src/app.js'],
  }
  const notApplicable = {
    topic: 'authz-object-level',
    disposition: 'not-applicable',
    reason: 'No object identifier crosses the route boundary.',
    evidence: ['The route accepts no object identifier.'],
  }

  assert.throws(
    () => accept(base, result(base, {
      topic_assessments: [clean, { ...notApplicable, topic: 'csrf' }],
    })),
    /does not own topic csrf/i,
  )
  assert.throws(
    () => accept(base, result(base, {
      topic_assessments: [
        { ...clean, evidence_paths: ['src/unexamined.js'] },
        notApplicable,
      ],
    })),
    /evidence path.*without reporting it examined/i,
  )
  assert.throws(
    () => accept(base, result(base, {
      findings: [finding()],
      topic_assessments: [
        clean,
        {
          topic: 'authz-object-level',
          disposition: 'finding',
          reason: 'A finding exists.',
          finding_ids: ['authz-object-level:not-in-result'],
        },
      ],
    })),
    /unknown finding authz-object-level:not-in-result/i,
  )
  assert.throws(
    () => accept(base, result(base, {
      topic_assessments: [
        clean,
        {
          topic: 'authz-object-level',
          disposition: 'partial',
          reason: 'Only one authorization branch was resolved.',
          evidence: ['The primary branch was inspected.'],
          coverage_gap_areas: ['topic:missing-gap'],
        },
      ],
    })),
    /unknown coverage gap area topic:missing-gap/i,
  )
})

test('partial and not-assessed topic dispositions keep a fully read lens PARTIAL', () => {
  const run = plannedRun()
  const accepted = accept(run, result(run, {
    coverage_gaps: [
      { area: 'topic:authn-session', reason: 'Session configuration is generated externally.' },
      { area: 'topic:authz-object-level', reason: 'A secondary route branch is unresolved.' },
    ],
    topic_assessments: [
      {
        topic: 'authn-session',
        disposition: 'not-assessed',
        reason: 'Session configuration is generated externally.',
        coverage_gap_areas: ['topic:authn-session'],
      },
      {
        topic: 'authz-object-level',
        disposition: 'partial',
        reason: 'The primary branch was inspected; a secondary branch is unresolved.',
        evidence: ['The primary route branch uses a tenant predicate.'],
        evidence_paths: ['src/app.js'],
        coverage_gap_areas: ['topic:authz-object-level'],
      },
    ],
  }))

  assert.equal(accepted.coverage.lenses[0].status, 'PARTIAL')
  assert.match(accepted.coverage.lenses[0].reason, /2 topic assessment obligations remain open/i)
})

test('zero-owner cross-cutting lenses have no mandatory topic denominator', () => {
  const run = plannedRun()
  run.activated_lenses = ['ai-generated-code']
  run.jobs[0] = {
    job_id: 'lens:ai-generated-code',
    kind: 'LENS',
    lens: 'ai-generated-code',
    state: 'PENDING',
    topic_obligations: [],
    topic_assessments: [],
  }
  run.coverage.lenses[0].lens = 'ai-generated-code'
  const packetSidecar = {
    job_id: 'lens:ai-generated-code',
    scoped_files: ['src/app.js'],
    owned_topics: [],
    known_topics: ['authz-object-level'],
    topic_obligations: [],
  }
  const value = {
    ...result(run),
    job_id: 'lens:ai-generated-code',
  }
  const accepted = applyJobResult(beginJob(run, 'lens:ai-generated-code'), value, {
    expectedPacketSha256: SHA_A,
    sidecar: packetSidecar,
  })
  assert.equal(accepted.coverage.lenses[0].status, 'RAN')
})

test('new plans seal topic obligations into both run jobs and provider sidecars', async () => {
  const root = await mkdtemp(join(tmpdir(), 'red-team-topic-assessments-'))
  try {
    const repository = join(root, 'repository')
    await mkdir(join(repository, 'routes'), { recursive: true })
    await writeFile(join(repository, 'routes', 'transfer.js'), "import express from 'express'\n")
    const plan = await createRunPlan({
      targetRoot: repository,
      lensDirectory: resolve('test/samples/corpus-ok'),
      createdAt: new Date('2026-09-04T12:00:00Z'),
    })
    const job = plan.run.jobs.find(({ lens }) => lens === 'web-sample')
    const packet = plan.jobSidecars.find(({ lens }) => lens === 'web-sample')
    assert.equal(job.lens_digest, packet.lens_digest)
    assert.match(job.lens_digest, /^[a-f0-9]{64}$/)
    assert.deepEqual(job.owned_topics, ['csrf'])
    assert.deepEqual(job.topic_obligations, ['csrf'])
    assert.deepEqual(job.topic_assessments, [])
    assert.deepEqual(packet.topic_obligations, ['csrf'])
    assert.equal(validateRun(plan.run).valid, true)
    for (const field of [
      'lens_digest',
      'owned_topics',
      'topic_obligations',
      'topic_assessments',
    ]) {
      const incomplete = structuredClone(plan.run)
      delete incomplete.jobs.find(({ job_id: jobId }) => jobId === job.job_id)[field]
      assert.equal(
        validateRun(incomplete).valid,
        false,
        `schema 7 LENS job must require ${field}`,
      )
    }
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('Markdown and SARIF expose topic-assessment coverage without inventing findings', () => {
  const run = plannedRun()
  run.state = 'COMPLETE_WITH_GAPS'
  run.phase = 'FINALIZED'
  run.jobs[0].state = 'SUCCEEDED'
  run.jobs[0].topic_assessments = [
    {
      topic: 'authn-session',
      disposition: 'examined-clean',
      reason: 'Session middleware is present.',
      evidence: ['The session guard dominates the route.'],
      evidence_paths: ['src/app.js'],
    },
    {
      topic: 'authz-object-level',
      disposition: 'not-assessed',
      reason: 'Authorization flow is unresolved.',
      coverage_gap_areas: ['topic:authz-object-level'],
    },
  ]
  run.coverage.examined = ['src/app.js']
  run.coverage.unexamined = []
  run.coverage.lenses[0] = {
    ...run.coverage.lenses[0],
    status: 'PARTIAL',
    examined_paths: ['src/app.js'],
    reason: '1 topic assessment obligation remains open',
  }
  run.coverage.gaps = [{
    area: 'topic:authz-object-level',
    reason: 'Authorization flow is unresolved.',
  }]

  const markdown = renderMarkdownReport(run)
  assert.match(markdown, /Topic assessment obligations/)
  assert.match(markdown, /\| web-and-api \| 2 \| 1 \| 0 \| 1 \| PARTIAL \|/)

  const sarif = renderSarif(run)
  assert.equal(sarif.runs[0].results.length, 0)
  assert.equal(
    sarif.runs[0].invocations[0].properties.topic_assessment_obligations,
    2,
  )
  assert.equal(
    sarif.runs[0].invocations[0].properties.topic_assessment_open,
    1,
  )
})
