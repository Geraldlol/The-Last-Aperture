import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

const SURFACE_PATHS = Object.freeze({
  rootSkill: 'SKILL.md',
  canonicalSkill: 'skills/red-team-audit/SKILL.md',
  harness: 'skills/red-team-audit/lenses/_harness.md',
  readme: 'README.md',
  security: 'SECURITY.md',
  adr21: 'docs/adr/0021-operator-statement-authorization.md',
  adr22: 'docs/adr/0022-public-sealed-t1-proof.md',
  adr23: 'docs/adr/0023-operator-authority-governs-named-capabilities.md',
})

const ACTIVE_PUBLIC_SOURCE_PATHS = Object.freeze([
  'scripts/http-recon.mjs',
  'scripts/http-authed.mjs',
  'scripts/lib/http-recon-controller.mjs',
  'scripts/lib/http-authed-campaign-runtime.mjs',
  'scripts/lib/http-authed-campaign-controller.mjs',
])

function read(path) {
  return readFileSync(path, 'utf8')
}

function prose(path) {
  return read(path)
    .replace(/^>\s?/gm, '')
    .replace(/\s+/g, ' ')
    .trim()
}

function assertMatches(path, text, pattern, concept) {
  assert.match(text, pattern, `${path} must preserve ${concept}`)
}

test('current governing surfaces ask once only for missing target or scope', () => {
  const ingressSurfaces = [
    SURFACE_PATHS.rootSkill,
    SURFACE_PATHS.canonicalSkill,
    SURFACE_PATHS.harness,
    SURFACE_PATHS.readme,
    SURFACE_PATHS.security,
    SURFACE_PATHS.adr21,
    SURFACE_PATHS.adr23,
  ]

  for (const path of ingressSurfaces) {
    const text = prose(path)
    assertMatches(path, text, /operator statement/i, 'operator-statement ingress')
    assertMatches(
      path,
      text,
      /sole authorization (?:fact|primitive|source)/i,
      'the operator statement as the sole authorization source',
    )
    assertMatches(
      path,
      text,
      /(?:target\/scope|target and scope|target or scope)/i,
      'a target-and-scope envelope',
    )
    assertMatches(
      path,
      text,
      /(?:target\/scope is (?:already )?(?:supplied|present), proceed|if it is already present, the agent proceeds)/i,
      'proceeding when target and scope are present',
    )
    assertMatches(
      path,
      text,
      /(?:ask once only when it is missing|target or scope is missing, the agent asks the operator once)/i,
      'one question only when target or scope is missing',
    )
    assertMatches(
      path,
      text,
      /(?:never (?:re-ask|demand another|require another)|do not require another|no additional authorization|without another prompt)/i,
      'no repeated authorization decision',
    )
  }

  for (const path of [
    SURFACE_PATHS.canonicalSkill,
    SURFACE_PATHS.readme,
    SURFACE_PATHS.security,
    SURFACE_PATHS.adr21,
    SURFACE_PATHS.adr23,
  ]) {
    assertMatches(
      path,
      prose(path),
      /operator (?:is|remains) accountable/i,
      'operator accountability without product-side legal adjudication',
    )
  }
})

test('the same named authority covers T2, service boots, credentials, and external services', () => {
  for (const path of Object.values(SURFACE_PATHS)) {
    const text = prose(path)
    assertMatches(path, text, /sole authorization (?:fact|primitive|source)/i, 'one authorization source')
    assertMatches(path, text, /\bT2\b/i, 'named T2 authority')
    assertMatches(path, text, /service boots?/i, 'named service-boot authority')
    assertMatches(
      path,
      text,
      /(?:controller-referenced(?: live)?|live) credentials/i,
      'named credential use',
    )
    assertMatches(path, text, /(?:named )?external (?:services|systems)/i, 'named external-service authority')
  }

  for (const path of [
    SURFACE_PATHS.rootSkill,
    SURFACE_PATHS.canonicalSkill,
    SURFACE_PATHS.readme,
    SURFACE_PATHS.adr21,
    SURFACE_PATHS.adr22,
  ]) {
    assertMatches(path, prose(path), /T1-only statement (?:stays|remains) narrow/i, 'narrow T1-only scope')
  }
})

test('missing transports preserve authority as a technical unavailable result without re-prompting', () => {
  const documents = Object.fromEntries(
    Object.entries(SURFACE_PATHS).map(([name, path]) => [name, prose(path)]),
  )

  assertMatches(
    SURFACE_PATHS.canonicalSkill,
    documents.canonicalSkill,
    /technically unavailable[^.]*\. This is not an authorization denial[^.]*authorized-but-unavailable gap/i,
    'authorized-but-technically-unavailable route handling',
  )
  assertMatches(
    SURFACE_PATHS.rootSkill,
    documents.rootSkill,
    /Other service boots, live credentials, and external systems need their own routes; record them authorized-but-unavailable[\s\S]*technical capability fact, not a second authorization boundary/i,
    'route availability as distinct from authority',
  )
  assertMatches(
    SURFACE_PATHS.harness,
    documents.harness,
    /Other T2 shapes, live credentials, and external services need separate controllers; otherwise retain authority and emit an authorized-but-unavailable gap/i,
    'unsupported T2 remains authorized without an invented controller',
  )
  assertMatches(
    SURFACE_PATHS.readme,
    documents.readme,
    /narrow loopback T2 is enabled only[\s\S]{0,80}through `run-service-proof`[\s\S]{0,500}Other T2 shapes retain their authority but remain unavailable without a matching route/i,
    'implemented narrow T2 and retained authority for unsupported T2 shapes',
  )
  assertMatches(
    SURFACE_PATHS.security,
    documents.security,
    /missing transport is a technical unavailable result, not an authorization denial; never invent one/i,
    'a missing transport as a technical result',
  )
  assertMatches(
    SURFACE_PATHS.adr21,
    documents.adr21,
    /no matching route, authority is retained and execution is reported authorized-but-unavailable without another prompt/i,
    'retained authority without another prompt',
  )
  assertMatches(
    SURFACE_PATHS.adr22,
    documents.adr22,
    /statement named T2, service boots, controller-referenced credentials, or external services, retain that authority and report the missing matching route as an authorized-but-unavailable gap/i,
    'broader authority retained outside the T1 route',
  )
  assertMatches(
    SURFACE_PATHS.adr23,
    documents.adr23,
    /required controller, transport, credential material, or platform capability is absent[^.]*authorized-but-unavailable[\s\S]*Never ask the operator to authorize the same thing again/i,
    'authorized-but-unavailable execution without reauthorization',
  )
})

test('the sealed public T1 route remains network denied alongside narrow network-none T2', () => {
  assertMatches(
    SURFACE_PATHS.canonicalSkill,
    prose(SURFACE_PATHS.canonicalSkill),
    /Repository T1 proof[\s\S]{0,300}immutable-image worker[\s\S]{0,60}network-denied/i,
    'network-denied sealed T1',
  )
  assertMatches(
    SURFACE_PATHS.rootSkill,
    prose(SURFACE_PATHS.rootSkill),
    /Public T1 uses `test`, sealed source, and `run-proof`[\s\S]{0,180}Public T2 uses `LOCAL_DYNAMIC`, sealed source, v3, and `run-service-proof`/i,
    'delegation to the sealed T1 worker',
  )
  assertMatches(
    SURFACE_PATHS.harness,
    prose(SURFACE_PATHS.harness),
    /Public T1 uses `audit run-proof`[\s\S]{0,400}worker enforces no network/i,
    'no T1 network namespace connectivity',
  )
  assertMatches(
    SURFACE_PATHS.readme,
    prose(SURFACE_PATHS.readme),
    /Public T1 proof through a v2 proof config[\s\S]{0,260}with no network or host mounts/i,
    'the release T1 network boundary',
  )
  assertMatches(SURFACE_PATHS.adr22, prose(SURFACE_PATHS.adr22), /`--network=none`/i, 'Docker network denial')
  assertMatches(
    SURFACE_PATHS.harness,
    prose(SURFACE_PATHS.harness),
    /Public T2 also uses `--network=none`; its sole socket scope is literal loopback/i,
    'network-none T2 with only in-container loopback',
  )
  assertMatches(
    SURFACE_PATHS.adr23,
    prose(SURFACE_PATHS.adr23),
    /public T1 worker remains network-denied/i,
    'T1 network denial despite broader authority',
  )
})

test('only newly added scope needs a predecessor-bound successor statement', () => {
  assertMatches(
    SURFACE_PATHS.canonicalSkill,
    prose(SURFACE_PATHS.canonicalSkill),
    /New scope needs an inert request and explicit statement creating a predecessor-bound successor; authority never carries over/i,
    'a predecessor-bound successor for new scope',
  )
  assertMatches(
    SURFACE_PATHS.rootSkill,
    prose(SURFACE_PATHS.rootSkill),
    /cannot widen a target[\s\S]*Follow the canonical skill's Break Their Bones and scope-expansion rules/i,
    'non-widening delegation to canonical scope expansion',
  )
  assertMatches(
    SURFACE_PATHS.readme,
    prose(SURFACE_PATHS.readme),
    /accepts that statement as its authorization fact without requesting an external legal-proof artifact or later recertification/i,
    'no recertification of unchanged authority',
  )
  assertMatches(
    SURFACE_PATHS.security,
    prose(SURFACE_PATHS.security),
    /existing operator statement is sufficient if it already names the authenticated target and work; only a scope addition needs a successor statement/i,
    'a successor only for a scope addition',
  )
  assertMatches(
    SURFACE_PATHS.adr21,
    prose(SURFACE_PATHS.adr21),
    /new operator statement[\s\S]*predecessor-bound successor scope[\s\S]*existing campaign authority never carries across automatically/i,
    'predecessor-bound scope expansion',
  )
  assertMatches(
    SURFACE_PATHS.adr23,
    prose(SURFACE_PATHS.adr23),
    /successor statement may add it without recertifying unchanged authority/i,
    'unchanged authority surviving a scope addition',
  )
})

test('active public recon and authenticated sources derive authority without a caller confirmation predicate', () => {
  for (const path of ACTIVE_PUBLIC_SOURCE_PATHS) {
    const source = read(path)
    // `current_authorization_confirmed` remains valid as controller-derived
    // evidence. The forbidden camel-case identifier was a caller-controlled
    // parameter, predicate, and injection that duplicated operator authority.
    assert.doesNotMatch(
      source,
      /\bauthorizationConfirmed\b/,
      `${path} must not accept, check, or inject a repeat authorization predicate`,
    )
  }

  const reconCli = prose('scripts/http-recon.mjs')
  const authedCli = prose('scripts/http-authed.mjs')
  const reconController = read('scripts/lib/http-recon-controller.mjs')
  const campaignRuntime = read('scripts/lib/http-authed-campaign-runtime.mjs')
  const campaignController = read('scripts/lib/http-authed-campaign-controller.mjs')

  assert.match(
    reconCli,
    /go treats the invocation itself as the operator directive[^.]*without repeated attestation flags/i,
  )
  assert.match(
    authedCli,
    /plan-attested is the explicit operator statement[^.]*without another flag[\s\S]*live command is the operator's campaign launch directive; no repeated legal-attestation flag is required/i,
  )

  for (const verifier of [
    'verifyPrePlanHttpsOperatorAuthorization',
    'verifyOperatorAuthorizationReceipt',
  ]) {
    assert.match(
      reconController,
      new RegExp(`\\b${verifier}\\b`),
      `http-recon must retain ${verifier}`,
    )
  }

  for (const [path, source] of [
    ['scripts/lib/http-authed-campaign-runtime.mjs', campaignRuntime],
    ['scripts/lib/http-authed-campaign-controller.mjs', campaignController],
  ]) {
    for (const verifier of ['verifyHttpAuthedAuthorization', 'verifyHttpAuthedCandidate']) {
      assert.match(source, new RegExp(`\\b${verifier}\\b`), `${path} must retain ${verifier}`)
    }
    assert.match(source, /expectedCampaignGrantSha256/, `${path} must remain campaign-grant bound`)
    assert.match(source, /operatorId/, `${path} must remain operator bound`)
    assert.match(source, /ledger/, `${path} must retain ledger enforcement`)
    assert.match(source, /stop/i, `${path} must retain stop enforcement`)
  }
})
