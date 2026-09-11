import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { mkdtemp } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createArtifactAdapter } from '../scripts/lib/evidence-adapters/artifact.mjs'
import { readEvidenceIndex } from '../scripts/lib/evidence-packet.mjs'
import {
  OCI_EVIDENCE_RULE,
  historyContainsCredentialMaterial,
  markOciSiblingOutliers,
} from '../scripts/lib/evidence-oci-rules.mjs'
import { declaredEvidenceRuleAnchors } from '../scripts/lib/evidence-adapters.mjs'
import { parseLens } from '../scripts/lib/frontmatter.mjs'

const ARTIFACT_DOC = fileURLToPath(
  new URL('../skills/last-aperture/lenses/_evidence-adapters/artifact.md', import.meta.url),
)

const adapter = createArtifactAdapter({ clock: () => '2026-08-08T14:22:10Z' })

async function acquire(fixture) {
  const out = join(await mkdtemp(join(tmpdir(), 'rta-rules-')), 'ev')
  const planned = await adapter.plan({
    evidence_id: 'image-under-test',
    source_path: `test/fixtures/evidence/${fixture}`,
    target_class: 'LAB',
    phi_scope: 'none',
  })
  const written = await adapter.run(planned, { out })
  return {
    index: await readEvidenceIndex(written.directory),
  }
}

// One predicate per declared anchor. These encode the oracles stated in
// artifact.md; the assertions below run each in both directions, because a
// rule that fires on everything discriminates nothing.
const ORACLES = {
  'ev.built-artifact.oci.whiteout-named-file-with-content': (image) =>
    image.index.entries.filter(({ matched_rule_ids: ruleIds = [] }) =>
      ruleIds.includes('ev.built-artifact.oci.whiteout-named-file-with-content')),

  'ev.built-artifact.oci.blob-unreferenced-by-manifest': (image) =>
    image.index.entries.filter(({ matched_rule_ids: ruleIds = [] }) =>
      ruleIds.includes('ev.built-artifact.oci.blob-unreferenced-by-manifest')),

  'ev.built-artifact.oci.sibling-size-mtime-outlier': (image) =>
    image.index.entries.filter(({ matched_rule_ids: ruleIds = [] }) =>
      ruleIds.includes('ev.built-artifact.oci.sibling-size-mtime-outlier')),

  'ev.built-artifact.oci.recursive-encoded-payload': (image) =>
    image.index.entries.filter(({ matched_rule_ids: ruleIds = [] }) =>
      ruleIds.includes('ev.built-artifact.oci.recursive-encoded-payload')),

  'ev.built-artifact.oci.secret-in-config-history': (image) =>
    image.index.entries.filter(({ matched_rule_ids: ruleIds = [] }) =>
      ruleIds.includes('ev.built-artifact.oci.secret-in-config-history')),
}

test('every anchor artifact.md declares has an oracle demonstrated here', () => {
  const declared = [...declaredEvidenceRuleAnchors(readFileSync(ARTIFACT_DOC, 'utf8'))].sort()
  // R7's discipline for acquired evidence: an anchor nobody showed firing is
  // worse than a missing rule, because it reports clean.
  assert.deepEqual(declared, Object.keys(ORACLES).sort())
})

test('every oracle fires on the vulnerable image', async () => {
  const image = await acquire('vulnerable-image.tar')
  for (const [anchor, oracle] of Object.entries(ORACLES)) {
    const hits = await oracle(image)
    assert.ok(hits.length > 0, `${anchor} did not fire on the vulnerable fixture`)
  }
})

test('no oracle fires on the clean image', async () => {
  const image = await acquire('clean-image.tar')
  for (const [anchor, oracle] of Object.entries(ORACLES)) {
    const hits = await oracle(image)
    assert.deepEqual(hits, [], `${anchor} fired on the clean fixture`)
  }
})

test('the whiteout rule discriminates a real marker from an impostor', async () => {
  const image = await acquire('vulnerable-image.tar')
  const hits = ORACLES['ev.built-artifact.oci.whiteout-named-file-with-content'](image)
  assert.deepEqual(hits.map(({ path }) => path), ['.wh.audit-log.txt'])
  // The genuine 0-byte marker sits beside it and must not be reported.
  assert.ok(image.index.entries.some(({ kind, path, whiteout }) =>
    kind === 'layer-entry' && path === '.wh.build-secret.txt' && whiteout === true))
})

test('each rule asserts a claim the citing lens is permitted to make', () => {
  const claims = {
    'ev.built-artifact.oci.whiteout-named-file-with-content': 'unexpected-artifact-content',
    'ev.built-artifact.oci.blob-unreferenced-by-manifest': 'unexpected-artifact-content',
    'ev.built-artifact.oci.sibling-size-mtime-outlier': 'unexpected-artifact-content',
    'ev.built-artifact.oci.recursive-encoded-payload': 'unexpected-artifact-content',
    'ev.built-artifact.oci.secret-in-config-history': 'secret-present-in-artifact',
  }
  assert.deepEqual(Object.keys(claims).sort(), Object.keys(ORACLES).sort())

  const lens = parseLens(
    readFileSync('skills/last-aperture/lenses/cloud-and-iac.md', 'utf8'),
    'cloud-and-iac.md',
  )
  const permitted = lens.frontmatter.activates_on.evidence_classes['built-artifact'].may_conclude
  for (const [anchor, claim] of Object.entries(claims)) {
    // Invariant 16: a finding asserting outside its class's may_conclude is
    // malformed, so a rule that could only produce one is a dead rule.
    assert.ok(permitted.includes(claim), `${anchor} asserts ${claim}, which cloud-and-iac may not`)
  }
})

function layerEntry(path, size, mtime) {
  return {
    kind: 'layer-entry',
    type: 'file',
    layer: 0,
    path: `app/${path}`,
    size,
    mtime,
    matched_rule_ids: [],
  }
}

test('the sibling rule uses a four-file joint baseline with multiple unrelated entries', () => {
  const entries = [
    layerEntry('base-a', 100, 1),
    layerEntry('base-b', 100, 1),
    layerEntry('base-c', 100, 1),
    layerEntry('base-d', 100, 1),
    layerEntry('outlier-a', 200, 2),
    layerEntry('outlier-b', 300, 3),
    layerEntry('size-only', 100, 4),
    layerEntry('mtime-only', 400, 1),
  ]
  markOciSiblingOutliers(entries)
  assert.deepEqual(
    entries
      .filter(({ matched_rule_ids: ids }) => ids.includes(OCI_EVIDENCE_RULE.sibling))
      .map(({ path }) => path),
    ['app/outlier-a', 'app/outlier-b'],
  )
})

test('equal-sized candidate sibling baselines are ambiguous and match nothing', () => {
  const entries = [
    ...['a', 'b', 'c', 'd'].map((name) => layerEntry(`first-${name}`, 100, 1)),
    ...['a', 'b', 'c', 'd'].map((name) => layerEntry(`second-${name}`, 200, 2)),
    layerEntry('unrelated', 300, 3),
  ]
  markOciSiblingOutliers(entries)
  assert.ok(entries.every(({ matched_rule_ids: ids }) => ids.length === 0))
})

test('config history requires concrete credential material, not a security keyword', () => {
  for (const command of [
    'RUN export DEPLOY_TOKEN=FIXTURE-NOT-A-REAL-SECRET-config-history && ./deploy.sh',
    'ENV PASSWORD=hunter2',
    'ENV PRIVATE_KEY=fixture-private-key-material',
    'ENV DB_PASS=fixture-db-password',
    'ENV DB_PASS=${DB_PASS:-fixture-db-password}',
    'RUN publish AKIAIOSFODNN7EXAMPLE',
    `RUN publish ghp_${'a'.repeat(36)}`,
  ]) {
    assert.equal(historyContainsCredentialMaterial(command), true, command)
  }

  for (const command of [
    'RUN echo password policy',
    'ARG PASSWORD',
    'ENV PASSWORD=$PASSWORD',
    'ENV API_KEY=changeme',
    'LABEL password_policy=required',
    'RUN --mount=type=secret,id=npm_token npm ci',
    'RUN PASSWORD="$(cat /run/secrets/db)" app',
    'ENV API_KEY=${API_KEY:-changeme}',
    'ENV TOKEN_URL=https://issuer.example/token',
    'ENV API_KEY_ID=client-identifier-12345',
    'ENV SECRET_ARN=arn:aws:secretsmanager:us-east-1:123456789012:secret:example',
    'RUN curl https://user:${TOKEN}@registry.example/v2',
    'RUN PASSWORD=`cat /run/secrets/db` app',
  ]) {
    assert.equal(historyContainsCredentialMaterial(command), false, command)
  }
})
