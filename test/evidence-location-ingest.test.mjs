import assert from 'node:assert/strict'
import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test, { before } from 'node:test'
import { validateRun } from '../scripts/lib/contracts.mjs'
import { createArtifactAdapter } from '../scripts/lib/evidence-adapters/artifact.mjs'
import { acquiredEvidenceHasGaps } from '../scripts/lib/evidence-coverage.mjs'
import { evidenceForLens, readEvidenceIndex } from '../scripts/lib/evidence-packet.mjs'
import {
  advanceRun,
  applyJobResult,
  beginJob,
} from '../scripts/lib/job-protocol.mjs'
import { createRunPlan } from '../scripts/lib/run-engine.mjs'

const INPUT_SHA256 = 'a'.repeat(64)
const adapter = createArtifactAdapter({ clock: () => '2026-08-08T14:22:10Z' })

let planned
let acquiredEvidenceContext
let acquiredBundle

async function acquiredImage(evidenceId = 'peerstar-api-image') {
  const out = join(await mkdtemp(join(tmpdir(), 'rta-ingest-evidence-')), 'bundle')
  const request = await adapter.plan({
    evidence_id: evidenceId,
    source_path: 'test/fixtures/evidence/vulnerable-image.tar',
    target_class: 'LAB',
    phi_scope: 'none',
  })
  const written = await adapter.run(request, { out })
  acquiredEvidenceContext = structuredClone(written.profile.evidence_context)
  return {
    evidence_id: evidenceId,
    evidence_class: 'built-artifact',
    adapter_id: 'artifact',
    artifact_kind: 'oci-image',
    coverage_state: 'COVERED',
    phi_bearing: false,
    root_sha256: written.root_sha256,
    directory: written.directory,
    evidence_context: acquiredEvidenceContext,
  }
}

function evidenceFinding(overrides = {}) {
  return {
    candidate_id: 'dockerfile-and-image-content:evidence-ingest',
    lens: 'cloud-and-iac',
    topic: 'dockerfile-and-image-content',
    title: 'A whiteout-shaped entry contains unexpected data',
    claimed_impact_severity: 'High',
    location: ['peerstar-api-image:layer/01/.wh.audit-log.txt'],
    evidence: 'not actually a whiteout',
    attack: 'Pull the image and inspect the upper layer entry.',
    impact: 'Content represented as deleted remains readable.',
    reachable_from: 'Anyone permitted to pull the image.',
    confidence: 'High',
    proof_plan: 'Resolve the cited locator in the sealed evidence bundle.',
    evidence_claim: 'unexpected-artifact-content',
    adapter_rule_id: 'ev.built-artifact.oci.whiteout-named-file-with-content',
    evidence_context: structuredClone(acquiredEvidenceContext),
    ...overrides,
  }
}

function resultFor(run, job, findingsInput) {
  const findings = Array.isArray(findingsInput) ? findingsInput : [findingsInput]
  return {
    schema_version: '1.0.0',
    run_id: run.run_id,
    job_id: job.job_id,
    input_sha256: INPUT_SHA256,
    producer: {
      name: 'evidence-location-test-provider',
      version: '1.0.0',
      instance_id: 'evidence-location-test-provider:1',
    },
    state: 'SUCCEEDED',
    examined_files: [],
    findings,
    coverage_gaps: [],
    topic_assessments: job.topic_obligations.map((topic) => {
      const topicFindingIds = findings
        .filter((finding) => finding.topic === topic)
        .map(({ candidate_id: candidateId }) => candidateId)
      return topicFindingIds.length > 0
        ? {
          topic,
          disposition: 'finding',
          reason: 'The sealed evidence index exposes the unexpected entry.',
          finding_ids: topicFindingIds,
        }
        : {
          topic,
          disposition: 'examined-clean',
          reason: 'The bounded evidence did not support a finding for this topic.',
          evidence: ['The provider completed the bounded evidence check.'],
        }
    }),
  }
}

function lensDispatch(lens, plan = planned) {
  const run = structuredClone(plan.run)
  const job = run.jobs.find((candidate) =>
    candidate.lens === lens
    && (candidate.evidence_ids ?? []).includes('peerstar-api-image'))
  const sidecar = structuredClone(plan.jobSidecars.find(
    (candidate) => candidate.job_id === job.job_id,
  ))
  return { run: beginJob(run, job.job_id), job, sidecar }
}

function cloudDispatch(plan = planned) {
  return lensDispatch('cloud-and-iac', plan)
}

function locationMatchedBy(ruleId, lens = 'cloud-and-iac') {
  const authority = lensDispatch(lens).sidecar.evidence.find(
    ({ evidence_context: context }) => context.evidence_id === 'peerstar-api-image',
  )
  const entry = authority.entries.find(({ matched_rule_ids: ruleIds = [] }) =>
    ruleIds.includes(ruleId))
  assert.ok(entry, `fixture carries no controller match for ${ruleId}`)
  return `peerstar-api-image:${entry.locator}`
}

function controllerRequiredFindings({ job, sidecar }, existing = []) {
  const existingKeys = new Set(existing.map((finding) =>
    `${finding.adapter_rule_id}\0${finding.location[0]}`))
  let sequence = 0
  return sidecar.evidence.flatMap((authority) =>
    authority.required_matches
      .filter((required) => !existingKeys.has(
        `${required.adapter_rule_id}\0${required.evidence_id}:${required.locator}`,
      ))
      .map((required) => {
        sequence += 1
        return {
          candidate_id: `${required.topic}:controller-match-${sequence}`,
          lens: job.lens,
          topic: required.topic,
          title: `Controller evidence rule matched ${required.locator}`,
          claimed_impact_severity: 'High',
          location: [`${required.evidence_id}:${required.locator}`],
          evidence: 'The sealed controller analysis matched this locator.',
          attack: 'Inspect the acquired image evidence at the cited locator.',
          impact: 'The acquired artifact contains the matched unexpected material.',
          reachable_from: 'Anyone able to obtain the affected artifact.',
          confidence: 'High',
          proof_plan: 'Re-run the controller rule against the sealed evidence bundle.',
          evidence_claim: required.evidence_claim,
          adapter_rule_id: required.adapter_rule_id,
          evidence_context: structuredClone(authority.evidence_context),
        }
      }))
}

function acceptFinding(dispatch, finding, { complete = true } = {}) {
  const { run, job, sidecar } = dispatch
  const findings = [finding]
  if (complete) findings.push(...controllerRequiredFindings(dispatch, findings))
  return applyJobResult(run, resultFor(run, job, findings), {
    expectedPacketSha256: INPUT_SHA256,
    sidecar,
  })
}

function completedEvidenceOrigins(run, evidenceId) {
  return run.jobs
    .filter((job) =>
      job.kind === 'LENS'
      && job.closure_round === undefined
      && (job.evidence_ids ?? []).includes(evidenceId))
    .map((job) => ({
      job_id: job.job_id,
      kind: job.kind,
      lens: job.lens,
      state: 'SUCCEEDED',
      evidence_ids: [...job.evidence_ids],
      producer: {
        name: 'evidence-location-test-provider',
        version: '1.0.0',
        instance_id: `evidence-location-test-provider:${job.lens}`,
      },
      coverage_authority: 'PROVIDER_DECLARED',
    }))
}

before(async () => {
  const repository = await mkdtemp(join(tmpdir(), 'rta-ingest-repository-'))
  await writeFile(
    join(repository, 'Dockerfile'),
    'FROM node:20-alpine\nCOPY secret.txt /secret.txt\nRUN rm /secret.txt\n',
    'utf8',
  )
  acquiredBundle = await acquiredImage()
  planned = await createRunPlan({
    targetRoot: repository,
    evidenceBundles: [acquiredBundle],
  })
})

test('a valid current OCI plan remains non-clear without exhaustive analysis', () => {
  const record = planned.run.evidence_coverage.bundle_coverage.find(
    ({ evidence_id: evidenceId }) => evidenceId === 'peerstar-api-image',
  )

  assert.equal(record.state, 'PARTIAL')
  assert.equal(acquiredEvidenceHasGaps(planned.run), true)
  assert.equal(validateRun(planned.run).valid, true)
})

test('a real lens dispatch may originate a finding at an authorized evidence locator', () => {
  const accepted = acceptFinding(cloudDispatch(), evidenceFinding())
  const acceptedFinding = accepted.findings.find(
    ({ candidate_id: candidateId }) => candidateId === evidenceFinding().candidate_id,
  )
  assert.deepEqual(acceptedFinding.location, [
    'peerstar-api-image:layer/01/.wh.audit-log.txt',
  ])
})

test('orphan-blob and config-history origins use their exact controller-matched locators', () => {
  const orphanRule = 'ev.built-artifact.oci.blob-unreferenced-by-manifest'
  const orphan = evidenceFinding({
    candidate_id: 'dockerfile-and-image-content:evidence-orphan-blob',
    location: [locationMatchedBy(orphanRule)],
    adapter_rule_id: orphanRule,
    title: 'Controller analysis matched the orphan-blob evidence rule',
  })
  const acceptedOrphan = acceptFinding(cloudDispatch(), orphan)
  assert.ok(acceptedOrphan.findings.some(({ candidate_id: candidateId }) =>
    candidateId === orphan.candidate_id))

  const historyRule = 'ev.built-artifact.oci.secret-in-config-history'
  const history = evidenceFinding({
    candidate_id: 'hardcoded-credentials-and-key-material:evidence-config-history',
    lens: 'crypto-and-key-management',
    topic: 'hardcoded-credentials-and-key-material',
    location: [locationMatchedBy(historyRule, 'crypto-and-key-management')],
    adapter_rule_id: historyRule,
    evidence_claim: 'secret-present-in-artifact',
    title: 'Controller analysis matched the config-history evidence rule',
  })
  const acceptedHistory = acceptFinding(
    lensDispatch('crypto-and-key-management'),
    history,
  )
  assert.ok(acceptedHistory.findings.some(({ candidate_id: candidateId }) =>
    candidateId === history.candidate_id))
})

test('a successful lens result cannot suppress controller-matched evidence', () => {
  const dispatch = cloudDispatch()
  assert.throws(
    () => applyJobResult(
      dispatch.run,
      resultFor(dispatch.run, dispatch.job, []),
      {
        expectedPacketSha256: INPUT_SHA256,
        sidecar: dispatch.sidecar,
      },
    ),
    /must report exactly one finding for required controller match/i,
  )
})

test('more than 4096 mandatory locator matches can be reported in bounded aggregate findings', () => {
  const dispatch = cloudDispatch()
  const authority = dispatch.sidecar.evidence[0]
  const ruleId = 'ev.built-artifact.oci.whiteout-named-file-with-content'
  const required = Array.from({ length: 4097 }, (_, index) => {
    const locator = `layer/00/.wh.bulk-${String(index).padStart(4, '0')}`
    return {
      evidence_id: authority.evidence_context.evidence_id,
      locator,
      adapter_rule_id: ruleId,
      topic: 'dockerfile-and-image-content',
      evidence_claim: 'unexpected-artifact-content',
    }
  })
  authority.entries = required.map(({ locator }) => ({
    locator,
    kind: 'layer-entry',
    path: locator.slice('layer/00/'.length),
    layer: 0,
    mode: 0o644,
    size: 1,
    mtime: 1,
    type: 'file',
    whiteout: false,
    content_captured: false,
    matched_rule_ids: [ruleId],
  }))
  authority.required_matches = required
  authority.truncated_entry_count = 0
  authority.entry_index_unreadable = false

  const findings = []
  for (let offset = 0; offset < required.length; offset += 128) {
    const group = required.slice(offset, offset + 128)
    findings.push(evidenceFinding({
      candidate_id: `dockerfile-and-image-content:bulk-${String(offset).padStart(4, '0')}`,
      title: `Controller evidence rule matched ${group.length} bounded locators`,
      location: group.map(({ evidence_id: evidenceId, locator }) =>
        `${evidenceId}:${locator}`),
      adapter_rule_id: ruleId,
      evidence_claim: 'unexpected-artifact-content',
      evidence_context: structuredClone(authority.evidence_context),
    }))
  }
  assert.equal(findings.length, 33)
  assert.ok(findings.every(({ location }) => location.length <= 128))

  const accepted = applyJobResult(
    dispatch.run,
    resultFor(dispatch.run, dispatch.job, findings),
    {
      expectedPacketSha256: INPUT_SHA256,
      sidecar: dispatch.sidecar,
    },
  )
  assert.equal(accepted.findings.length, 33)

  const regrouped = structuredClone(findings)
  const firstTail = regrouped[0].location.at(-1)
  const secondTail = regrouped[1].location.at(-1)
  regrouped[0].location[regrouped[0].location.length - 1] = secondTail
  regrouped[1].location[regrouped[1].location.length - 1] = firstTail
  assert.throws(
    () => applyJobResult(
      dispatch.run,
      resultFor(dispatch.run, dispatch.job, regrouped),
      {
        expectedPacketSha256: INPUT_SHA256,
        sidecar: dispatch.sidecar,
      },
    ),
    /canonical sorted groups/i,
  )
})

test('an indexed locator cannot be paired with a controller rule that did not match it', () => {
  assert.throws(
    () => acceptFinding(cloudDispatch(), evidenceFinding({
      adapter_rule_id: 'ev.built-artifact.oci.recursive-encoded-payload',
    })),
    /rule .*recursive-encoded-payload did not match .*sealed controller analysis/i,
  )
})

test('a controller rule cannot be reassigned to a different lens or topic', () => {
  const historyRule = 'ev.built-artifact.oci.secret-in-config-history'
  assert.throws(
    () => acceptFinding(cloudDispatch(), evidenceFinding({
      location: [locationMatchedBy(historyRule)],
      adapter_rule_id: historyRule,
      evidence_claim: 'secret-present-in-artifact',
    })),
    /controller rule belongs to crypto-and-key-management\/hardcoded-credentials-and-key-material/i,
  )
})

test('evidence ingest rejects an absent bundle and an id-prefix mismatch', () => {
  const absent = evidenceFinding({
    location: ['forged-image:layer/01/.wh.audit-log.txt'],
    evidence_context: {
      ...evidenceFinding().evidence_context,
      evidence_id: 'forged-image',
    },
  })
  assert.throws(
    () => acceptFinding(cloudDispatch(), absent),
    /evidence bundle "forged-image" is not present in this run/i,
  )

  assert.throws(
    () => acceptFinding(cloudDispatch(), evidenceFinding({
      location: ['forged-image:layer/01/.wh.audit-log.txt'],
    })),
    /EVIDENCE_ID_MISMATCH/,
  )
})

test('evidence ingest rejects forged packet authority and locators outside its index', () => {
  const forgedBundle = cloudDispatch()
  forgedBundle.sidecar.evidence[0].root_sha256 = 'f'.repeat(64)
  assert.throws(
    () => acceptFinding(forgedBundle, evidenceFinding()),
    /evidence authority.*does not match.*run bundle/i,
  )

  assert.throws(
    () => acceptFinding(cloudDispatch(), evidenceFinding({
      location: ['peerstar-api-image:layer/99/not-in-the-index.txt'],
    })),
    /locator.*outside.*sealed evidence index/i,
  )
})

test('unsupported provider evidence delivery cannot originate a qualified finding', () => {
  const dispatch = cloudDispatch()
  dispatch.sidecar.evidence[0].locator_index_kind = 'unsupported'
  dispatch.sidecar.evidence[0].unsupported_reason =
    'provider evidence-byte delivery is not implemented'
  assert.throws(
    () => acceptFinding(dispatch, evidenceFinding()),
    /does not support evidence-qualified findings.*provider evidence-byte delivery/is,
  )
})

test('evidence ingest rejects provider-forged acquisition context fields', () => {
  const forgeries = [
    { target_identity: `sha256:${'f'.repeat(64)}` },
    { acquired_on: '2026-08-08T14:22:11Z' },
    { detection_evidence: ['provider-authored provenance'] },
  ]
  for (const forgery of forgeries) {
    assert.throws(
      () => acceptFinding(cloudDispatch(), evidenceFinding({
        evidence_context: {
          ...structuredClone(acquiredEvidenceContext),
          ...forgery,
        },
      })),
      /evidence_context does not match .* immutable packet authority/i,
    )
  }
})

test('a run-level bundle that was not delivered in the immutable packet cannot authorize a finding', () => {
  const dispatch = cloudDispatch()
  dispatch.run.evidence_bundles.push({
    ...dispatch.run.evidence_bundles[0],
    evidence_id: 'out-of-packet-image',
  })
  const finding = evidenceFinding({
    location: ['out-of-packet-image:layer/01/.wh.audit-log.txt'],
    evidence_context: {
      ...evidenceFinding().evidence_context,
      evidence_id: 'out-of-packet-image',
    },
  })
  assert.throws(
    () => acceptFinding(dispatch, finding),
    /immutable packet carries no authority for evidence "out-of-packet-image"/i,
  )
})

test('missing and unreadable evidence indexes fail closed at ingest', () => {
  const missing = cloudDispatch()
  delete missing.sidecar.evidence[0].entries
  delete missing.sidecar.evidence[0].layers
  delete missing.sidecar.evidence[0].truncated_entry_count
  delete missing.sidecar.evidence[0].entry_index_unreadable
  assert.throws(
    () => acceptFinding(missing, evidenceFinding()),
    /no (?:supported )?complete evidence index/i,
  )

  const unreadable = cloudDispatch()
  unreadable.sidecar.evidence[0].entry_index_unreadable = true
  assert.throws(
    () => acceptFinding(unreadable, evidenceFinding()),
    /evidence index.*unreadable/i,
  )
})

test('truncation preserves retained positive matches without claiming a full denominator', () => {
  const truncated = cloudDispatch()
  truncated.sidecar.evidence[0].truncated_entry_count = 1
  const accepted = acceptFinding(truncated, evidenceFinding())
  assert.ok(accepted.findings.some(({ candidate_id: candidateId }) =>
    candidateId === evidenceFinding().candidate_id))
  assert.equal(
    accepted.evidence_coverage.cells.find((cell) =>
      cell.lens === 'cloud-and-iac'
      && cell.topic === 'dockerfile-and-image-content'
      && cell.evidence_class === 'built-artifact').state,
    'PARTIAL',
  )
})

test('a real truncated index requires and accepts retained matches but rejects omitted locators', async () => {
  const index = await readEvidenceIndex(acquiredBundle.directory, {
    maxEntriesPerBundle: 8,
  })
  assert.ok(index.truncated > 0)
  const [projection] = evidenceForLens(
    'cloud-and-iac',
    new Map(Object.entries(planned.run.evidence_declarations)),
    [{ ...acquiredBundle, index }],
  )
  assert.ok(projection.required_matches.length > 0)
  const dispatch = cloudDispatch()
  dispatch.sidecar.evidence = [projection]
  const retained = projection.required_matches[0]
  const finding = evidenceFinding({
    candidate_id: 'dockerfile-and-image-content:truncated-retained-match',
    location: [`${retained.evidence_id}:${retained.locator}`],
    adapter_rule_id: retained.adapter_rule_id,
    evidence_claim: retained.evidence_claim,
    title: 'A retained controller match survives index truncation',
  })
  const accepted = acceptFinding(dispatch, finding)
  assert.ok(accepted.findings.some(({ candidate_id: candidateId }) =>
    candidateId === finding.candidate_id))
  assert.equal(
    accepted.evidence_coverage.cells.find((cell) =>
      cell.lens === 'cloud-and-iac'
      && cell.topic === 'dockerfile-and-image-content'
      && cell.evidence_class === 'built-artifact').state,
    'PARTIAL',
  )

  const omitted = cloudDispatch()
  omitted.sidecar.evidence = [projection]
  assert.throws(
    () => acceptFinding(omitted, evidenceFinding({
      location: ['peerstar-api-image:layer/99/omitted.txt'],
      adapter_rule_id: retained.adapter_rule_id,
      evidence_claim: retained.evidence_claim,
    })),
    /locator outside .* sealed evidence index/i,
  )
})

test('planning a portable bundle without an index cannot authorize an invented locator', async () => {
  const portableBundle = {
    ...structuredClone(planned.run.evidence_bundles[0]),
    evidence_context: structuredClone(acquiredEvidenceContext),
  }
  const unindexedPlan = await createRunPlan({
    targetRoot: planned.run.repository.root,
    evidenceBundles: [portableBundle],
  })
  assert.equal(
    Object.hasOwn(unindexedPlan.jobSidecars
      .find(({ lens, evidence }) =>
        lens === 'cloud-and-iac' && evidence?.length > 0)
      .evidence[0], 'entries'),
    false,
  )
  assert.throws(
    () => acceptFinding(cloudDispatch(unindexedPlan), evidenceFinding()),
    /no (?:supported )?complete evidence index/i,
  )

  assert.equal(validateRun(unindexedPlan.run).valid, true)
  const forgedClearance = structuredClone(unindexedPlan.run)
  forgedClearance.evidence_coverage.bundle_coverage[0].state = 'COVERED'
  for (const cell of forgedClearance.evidence_coverage.cells) {
    if (
      cell.evidence_class === 'built-artifact'
      && cell.state !== 'NOT_APPLICABLE'
    ) {
      cell.state = 'COVERED'
      cell.reason = 'forged portable OCI clearance without an index'
    }
  }
  const forgedCodes = new Set(
    validateRun(forgedClearance).errors.map(({ code }) => code),
  )
  assert.ok(forgedCodes.has('EVIDENCE_BUNDLE_EXHAUSTIVE_AUTHORITY_REQUIRED'))
  assert.ok(forgedCodes.has('ACQUIRED_EVIDENCE_CELL_FALSE_CLEARANCE'))
})

test('triage preserves an existing evidence location but cannot append one without packet authority', () => {
  let run = structuredClone(planned.run)
  const evidenceOrigins = completedEvidenceOrigins(run, 'peerstar-api-image')
  const business = run.jobs.find(
    (job) => job.job_id === 'triage:business-logic',
  )
  // A legacy-shaped coverage block keeps this transition focused on location
  // authority rather than the independent v7 closure denominator.
  run.schema_version = '1.0.0'
  run.jobs = [...evidenceOrigins, {
    job_id: business.job_id,
    kind: business.kind,
    lens: business.lens,
    state: 'PENDING',
  }]
  run.activated_lenses = [
    ...new Set([...evidenceOrigins.map(({ lens }) => lens), 'business-logic']),
  ]
  run.state = 'RUNNING'
  run.phase = 'TRIAGE'
  run.coverage = {
    inventory: ['Dockerfile'],
    examined: [],
    unexamined: [{ path: 'Dockerfile', reason: 'audit job has not run' }],
    lenses: [{
      lens: 'business-logic',
      status: 'NOT_ASSESSED',
      examined_paths: [],
      reason: 'audit job has not run',
    }],
    gaps: [],
  }
  run.findings = [evidenceFinding()]
  run.errors = []
  run.artifacts = {}
  delete run.control_snapshot
  delete run.source_snapshot
  run = beginJob(run, business.job_id)
  const sidecar = structuredClone(planned.jobSidecars.find(
    ({ job_id: jobId }) => jobId === business.job_id,
  ))
  const prior = run.findings[0]
  const triaged = {
    ...prior,
    effective_severity: 'High',
    triage_disposition: 'queued',
  }
  const triageResult = {
    ...resultFor(run, { ...business, topic_obligations: [] }, triaged),
    topic_assessments: [],
  }

  const accepted = applyJobResult(run, triageResult, {
    expectedPacketSha256: INPUT_SHA256,
    sidecar,
  })
  assert.deepEqual(accepted.findings[0].location, prior.location)

  const appended = structuredClone(triageResult)
  appended.findings[0].location.push(
    'peerstar-api-image:layer/00/build-secret.txt',
  )
  assert.throws(
    () => applyJobResult(run, appended, {
      expectedPacketSha256: INPUT_SHA256,
      sidecar,
    }),
    /immutable packet carries no authority for evidence "peerstar-api-image"/i,
  )
})

test('proof preserves an existing evidence location without treating it as repository scope', () => {
  let run = structuredClone(planned.run)
  const evidenceOrigins = completedEvidenceOrigins(run, 'peerstar-api-image')
  const prior = {
    ...evidenceFinding(),
    effective_severity: 'High',
    triage_disposition: 'queued',
  }
  const proofJob = {
    job_id: `proof-existence:${prior.candidate_id}`,
    kind: 'PROOF',
    state: 'PENDING',
    candidate_ids: [prior.candidate_id],
  }
  run.schema_version = '1.0.0'
  run.jobs = [...evidenceOrigins, proofJob]
  run.state = 'RUNNING'
  run.phase = 'PROOF'
  run.coverage = {
    inventory: ['Dockerfile'],
    examined: ['Dockerfile'],
    unexamined: [],
    lenses: [],
    gaps: [],
  }
  run.findings = [prior]
  run.errors = []
  run.artifacts = {}
  delete run.control_snapshot
  delete run.source_snapshot
  run = beginJob(run, proofJob.job_id)

  const proved = {
    ...prior,
    existence_check: {
      status: 'located',
      method: 'resolved the unchanged locator in the sealed evidence bundle',
    },
  }
  const proofResult = {
    schema_version: '1.0.0',
    run_id: run.run_id,
    job_id: proofJob.job_id,
    input_sha256: INPUT_SHA256,
    producer: {
      name: 'evidence-location-test-provider',
      version: '1.0.0',
      instance_id: 'evidence-location-test-provider:proof',
    },
    state: 'SUCCEEDED',
    examined_files: [],
    findings: [proved],
    coverage_gaps: [],
  }
  const accepted = applyJobResult(run, proofResult, {
    expectedPacketSha256: INPUT_SHA256,
  })
  assert.deepEqual(accepted.findings[0].location, prior.location)

  const appended = structuredClone(proofResult)
  appended.findings[0].location.push(
    'peerstar-api-image:layer/00/build-secret.txt',
  )
  assert.throws(
    () => applyJobResult(run, appended, {
      expectedPacketSha256: INPUT_SHA256,
    }),
    /immutable packet carries no authority for evidence "peerstar-api-image"/i,
  )
})
