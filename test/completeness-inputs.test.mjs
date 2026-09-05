import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { mkdtemp, mkdir, readFile, readdir, rm, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import {
  assertValidRun,
  runSchema,
  validateCompletenessInputs,
  validateRunTransition,
} from '../scripts/lib/contracts.mjs'
import {
  createRunPlan,
} from '../scripts/lib/run-engine.mjs'
import { sanitizeProviderPacket } from '../scripts/lib/provider-runner.mjs'

const CREATED_AT = new Date('2026-09-03T12:00:00.000Z')
const CLI = resolve('scripts/audit.mjs')

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), 'red-team-completeness-inputs-'))
  const repository = join(root, 'repository')
  const lenses = join(root, 'lenses')
  await mkdir(join(repository, 'src'), { recursive: true })
  await mkdir(lenses, { recursive: true })
  await Promise.all([
    writeFile(join(repository, 'src', 'app.js'), 'export const app = true\n'),
    writeFile(join(lenses, 'domain.md'), `---
name: domain
title: Domain
runs_in: fanout
activates_on:
  paths: ["src/**"]
  signals: []
owns: [domain-topic]
defers: {}
---

## Scope

Audit the fixture domain.
`),
    writeFile(join(lenses, 'completeness.md'), `---
name: completeness
title: Completeness
runs_in: triage
activates_on:
  paths: []
  signals: []
owns: []
defers: {}
---

## Scope

Measure the fixture run.
`),
  ])
  return { root, repository, lenses }
}

function completenessSidecars(plan) {
  return plan.jobSidecars.filter(({ kind }) => kind === 'COMPLETENESS')
}

test('completeness denominators distinguish unavailable, empty, and populated trusted inputs', async () => {
  const { root, repository, lenses } = await fixture()
  try {
    const common = {
      targetRoot: repository,
      lensDirectory: lenses,
      createdAt: CREATED_AT,
      maxClosureRounds: 1,
    }
    const unavailable = await createRunPlan(common)
    const explicitlyEmpty = await createRunPlan({
      ...common,
      completenessInputs: {
        schema_version: '1.0.0',
        high_value_flows: [],
        selected_framework_requirements: [],
      },
    })
    const populated = await createRunPlan({
      ...common,
      completenessInputs: {
        schema_version: '1.0.0',
        high_value_flows: [
          {
            flow_id: 'wire-transfer',
            title: 'Approve and settle a wire transfer',
            entry_points: ['POST /wires/:id/settle', 'POST /wires'],
            authoritative_invariant: 'The approver and creator are different principals.',
            disposition: 'executed-proof',
            evidence: 'proof:wire-transfer-maker-checker',
          },
        ],
        selected_framework_requirements: [
          {
            framework_id: 'owasp-asvs',
            version: '5.0.0',
            profile: 'L2',
            requirement_id: '2.3.5',
            disposition: 'mapped-and-tested',
            evidence: 'proof:wire-transfer-maker-checker',
          },
        ],
      },
    })

    assert.deepEqual(unavailable.run.coverage.completeness_inputs, {
      schema_version: '1.0.0',
      high_value_flows: null,
      selected_framework_requirements: null,
    })
    assert.deepEqual(explicitlyEmpty.run.coverage.completeness_inputs, {
      schema_version: '1.0.0',
      high_value_flows: [],
      selected_framework_requirements: [],
    })
    assert.notEqual(unavailable.run.plan_digest, explicitlyEmpty.run.plan_digest)
    const rewritten = structuredClone(unavailable.run)
    rewritten.coverage.completeness_inputs.high_value_flows = []
    const transition = validateRunTransition(unavailable.run, rewritten)
    assert.equal(transition.valid, false)
    assert.ok(transition.errors.some(({ code, instancePath }) =>
      code === 'COVERAGE_DENOMINATOR_CHANGED'
      && instancePath === '/coverage/completeness_inputs'))
    assert.deepEqual(
      populated.run.coverage.completeness_inputs.high_value_flows[0].entry_points,
      ['POST /wires', 'POST /wires/:id/settle'],
    )
    for (const plan of [unavailable, explicitlyEmpty, populated]) {
      assertValidRun(plan.run)
      assert.ok(completenessSidecars(plan).length > 0)
      assert.ok(completenessSidecars(plan).every((sidecar) =>
        assert.deepEqual(
          sidecar.completeness_inputs,
          plan.run.coverage.completeness_inputs,
        ) === undefined))
      assert.ok(plan.jobSidecars
        .filter(({ kind }) => kind !== 'COMPLETENESS')
        .every((sidecar) => !Object.hasOwn(sidecar, 'completeness_inputs')))
      assert.ok(plan.sealedSnapshots.control.index.files.some(
        ({ path }) => path === 'controls/completeness-inputs.json',
      ))
    }

    const completeness = completenessSidecars(populated)[0]
    const providerPacket = sanitizeProviderPacket({
      ...completeness,
      run_id: populated.run.run_id,
      packet_sha256: 'a'.repeat(64),
    })
    assert.deepEqual(
      providerPacket.completeness_inputs,
      populated.run.coverage.completeness_inputs,
    )
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

test('completeness input schema rejects malformed dispositions and duplicate denominator identities', () => {
  const missingApplicabilityEvidence = validateCompletenessInputs({
    schema_version: '1.0.0',
    high_value_flows: null,
    selected_framework_requirements: [{
      framework_id: 'owasp-asvs',
      version: '5.0.0',
      profile: 'L2',
      requirement_id: '1.1.1',
      disposition: 'not-applicable',
    }],
  })
  assert.equal(missingApplicabilityEvidence.valid, false)
  assert.ok(missingApplicabilityEvidence.errors.some(
    ({ instancePath }) => instancePath.includes('selected_framework_requirements/0'),
  ))

  const duplicateFlows = validateCompletenessInputs({
    schema_version: '1.0.0',
    high_value_flows: [
      { flow_id: 'recovery', title: 'Recovery A', entry_points: ['POST /recover'] },
      { flow_id: 'recovery', title: 'Recovery B', entry_points: ['POST /recovery'] },
    ],
    selected_framework_requirements: null,
  })
  assert.equal(duplicateFlows.valid, false)
  assert.ok(duplicateFlows.errors.some(
    ({ code }) => code === 'DUPLICATE_HIGH_VALUE_FLOW',
  ))
})

test('large completeness ledgers use linear identity checks instead of quadratic schema uniqueness', () => {
  const highValueFlowArray = runSchema.$defs.completenessInputs
    .properties.high_value_flows.oneOf.find(({ type }) => type === 'array')
  const requirementArray = runSchema.$defs.completenessInputs
    .properties.selected_framework_requirements.oneOf.find(({ type }) => type === 'array')
  assert.equal(Object.hasOwn(highValueFlowArray, 'uniqueItems'), false)
  assert.equal(Object.hasOwn(requirementArray, 'uniqueItems'), false)

  const selectedFrameworkRequirements = Array.from({ length: 8192 }, (_, index) => ({
    framework_id: 'owasp-asvs',
    version: '5.0.0',
    profile: 'L2',
    requirement_id: `requirement-${String(index).padStart(5, '0')}`,
  }))
  const validation = validateCompletenessInputs({
    schema_version: '1.0.0',
    high_value_flows: null,
    selected_framework_requirements: selectedFrameworkRequirements,
  })
  assert.equal(validation.valid, true)

  selectedFrameworkRequirements.push({ ...selectedFrameworkRequirements[0] })
  const duplicate = validateCompletenessInputs({
    schema_version: '1.0.0',
    high_value_flows: null,
    selected_framework_requirements: selectedFrameworkRequirements,
  })
  assert.equal(duplicate.valid, false)
  assert.ok(duplicate.errors.some(
    ({ code }) => code === 'DUPLICATE_SELECTED_FRAMEWORK_REQUIREMENT',
  ))
})

test('CLI accepts only an external schema-valid completeness input file', async () => {
  const { root, repository } = await fixture()
  const output = join(root, 'output')
  const inputs = join(root, 'completeness-inputs.json')
  try {
    await mkdir(output)
    await writeFile(inputs, JSON.stringify({
      schema_version: '1.0.0',
      high_value_flows: [],
      selected_framework_requirements: [],
    }))
    execFileSync(process.execPath, [
      CLI,
      'plan',
      repository,
      '--out',
      output,
      '--completeness-inputs',
      inputs,
      '--json',
    ], { encoding: 'utf8' })
    const bundles = (await readdir(output, { withFileTypes: true }))
      .filter((entry) => entry.isDirectory())
    assert.equal(bundles.length, 1)
    const run = JSON.parse(await readFile(
      join(output, bundles[0].name, 'run.json'),
      'utf8',
    ))
    assert.deepEqual(run.coverage.completeness_inputs.high_value_flows, [])
    assert.deepEqual(
      run.coverage.completeness_inputs.selected_framework_requirements,
      [],
    )
  } finally {
    await rm(root, { recursive: true, force: true })
  }
})

// The two denominators make the same shape of claim and must carry the same
// burden. `examined-and-clean` and `unresolved-invariant` are the two flow
// dispositions that point at nothing else in the run -- `finding` and
// `executed-proof` resolve to a record -- yet all four subtract the flow from
// the completeness gap set. So those two must say what was examined or what is
// open, exactly as `not-applicable` must carry its applicability evidence.
test('a high-value flow cannot be cleared or parked without evidence', () => {
  const flow = (disposition, extra = {}) => validateCompletenessInputs({
    schema_version: '1.0.0',
    high_value_flows: [{
      flow_id: 'checkout-refund',
      title: 'Refund issued against a completed order',
      entry_points: ['POST /api/refunds'],
      authoritative_invariant: 'refund total never exceeds captured total',
      disposition,
      ...extra,
    }],
    selected_framework_requirements: null,
  })

  for (const disposition of ['examined-and-clean', 'unresolved-invariant']) {
    const bare = flow(disposition)
    assert.equal(
      bare.valid,
      false,
      `${disposition} must not close a flow with no evidence`,
    )
    assert.ok(
      bare.errors.some(({ instancePath }) => instancePath.includes('high_value_flows/0')),
      `${disposition} rejection must name the offending flow`,
    )
    assert.equal(
      flow(disposition, { evidence: 'reviewed refund handler; invariant enforced at line 42' }).valid,
      true,
      `${disposition} is accepted once it carries its evidence`,
    )
  }

  // A disposition that resolves to a record elsewhere in the run keeps evidence
  // optional: the record is the evidence, and requiring both would double-file.
  for (const disposition of ['finding', 'executed-proof']) {
    assert.equal(flow(disposition).valid, true, `${disposition} resolves to a record`)
  }
})
