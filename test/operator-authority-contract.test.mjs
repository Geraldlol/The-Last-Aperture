import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { test } from 'node:test'

const SURFACE_PATHS = Object.freeze({
  rootSkill: 'SKILL.md',
  canonicalSkill: 'skills/last-aperture/SKILL.md',
  harness: 'skills/last-aperture/lenses/_harness.md',
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

test('current skill entry points accept one ordinary-language target statement', () => {
  for (const path of [SURFACE_PATHS.rootSkill, SURFACE_PATHS.canonicalSkill]) {
    const text = prose(path)
    assertMatches(path, text, /natural-language (?:operator )?statement naming the target/i, 'ordinary-language target ingress')
    assertMatches(path, text, /start immediately/i, 'immediate execution after ingress')
    assertMatches(path, text, /Ask once only[^.]*missing/i, 'one question only for missing scope facts')
    assertMatches(path, text, /per-action confirmation/i, 'no per-action confirmation')
    assertMatches(path, text, /Codex\/Claude handoffs/i, 'authority carried across model handoffs')
  }

  assertMatches(
    SURFACE_PATHS.rootSkill,
    prose(SURFACE_PATHS.rootSkill),
    /authorization is sufficient for the entire named objective/i,
    'one statement for the entire named objective',
  )
  assertMatches(
    SURFACE_PATHS.canonicalSkill,
    prose(SURFACE_PATHS.canonicalSkill),
    /sole authorization step/i,
    'one authorization step',
  )
  for (const path of [SURFACE_PATHS.readme, SURFACE_PATHS.security, SURFACE_PATHS.adr21, SURFACE_PATHS.adr23]) {
    assertMatches(path, prose(path), /sole authorization (?:fact|primitive)/i, 'one authorization source')
  }
  for (const path of [SURFACE_PATHS.readme, SURFACE_PATHS.security, SURFACE_PATHS.adr21, SURFACE_PATHS.adr23]) {
    assertMatches(path, prose(path), /operator (?:is|remains) accountable/i, 'operator accountability')
  }
})

test('the accepted statement covers autonomous target-neutral methods', () => {
  const root = prose(SURFACE_PATHS.rootSkill)
  const canonical = prose(SURFACE_PATHS.canonicalSkill)
  for (const [path, text] of [
    [SURFACE_PATHS.rootSkill, root],
    [SURFACE_PATHS.canonicalSkill, canonical],
  ]) {
    assertMatches(path, text, /browser[\s\S]*Burp[\s\S]*Ghidra[\s\S]*Frida/i, 'target-neutral browser and reverse tooling')
    assertMatches(path, text, /\bT1\b[\s\S]*\bT2\b/i, 'implemented proof routes')
  }
  assertMatches(SURFACE_PATHS.canonicalSkill, canonical, /Choose tactics autonomously/i, 'autonomous tactic selection')
  assertMatches(
    SURFACE_PATHS.canonicalSkill,
    canonical,
    /covers the methods needed for the objective[\s\S]*fuzzing, proof, and connectors/i,
    'method coverage inherited from the objective',
  )
  for (const path of [SURFACE_PATHS.readme, SURFACE_PATHS.security]) {
    assertMatches(path, prose(path), /browser[\s\S]*Burp[\s\S]*Ghidra[\s\S]*Frida/i, 'shipped target-neutral tooling')
  }
})

test('a missing wrapper is a technical gap rather than another authorization prompt', () => {
  const root = prose(SURFACE_PATHS.rootSkill)
  const canonical = prose(SURFACE_PATHS.canonicalSkill)
  assertMatches(SURFACE_PATHS.rootSkill, root, /missing dedicated wrapper[\s\S]{0,80}(?:does not create|is not) another authorization gate/i, 'no wrapper-specific authorization gate')
  assertMatches(SURFACE_PATHS.rootSkill, root, /technical gap/i, 'technical unavailability reporting')
  assertMatches(SURFACE_PATHS.canonicalSkill, canonical, /Active target I\/O needs[\s\S]{0,100}matching dispatch route/i, 'target-bound dispatch requirement')
  assertMatches(SURFACE_PATHS.canonicalSkill, canonical, /without[\s\S]{0,100}per-action confirmation/i, 'no route-specific authorization prompt')
  assertMatches(
    SURFACE_PATHS.harness,
    prose(SURFACE_PATHS.harness),
    /retain authority and emit an authorized-but-unavailable gap/i,
    'authority retained when a controller is absent',
  )
  for (const path of [SURFACE_PATHS.readme, SURFACE_PATHS.security]) {
    assertMatches(path, prose(path), /technically unavailable/i, 'explicit technical unavailability')
  }
  for (const path of [SURFACE_PATHS.adr21, SURFACE_PATHS.adr22, SURFACE_PATHS.adr23]) {
    const text = prose(path)
    assertMatches(path, text, /authorized-but-unavailable|reported? (?:it )?unavailable/i, 'unavailable route result')
    assertMatches(path, text, /without (?:another|a second) (?:permission )?(?:prompt|confirmation)|without re-asking|never ask the operator to authorize the same thing again/i, 'no repeat authorization')
  }
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
    /T1 uses `test`, sealed source, and `run-proof`[\s\S]{0,180}T2 uses `LOCAL_DYNAMIC`, sealed source, v3, and `run-service-proof`/i,
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

test('only a new target, added scope, or effect needs a successor statement', () => {
  for (const path of [SURFACE_PATHS.rootSkill, SURFACE_PATHS.canonicalSkill]) {
    const text = prose(path)
    assertMatches(path, text, /(?:Only a )?new target, added scope, or unlisted publish\/deploy effect needs a successor/i, 'successor scope boundary')
    assertMatches(path, text, /unchanged scope never needs recertification/i, 'unchanged authority continuity')
  }
  assertMatches(
    SURFACE_PATHS.canonicalSkill,
    prose(SURFACE_PATHS.canonicalSkill),
    /New target scope needs an explicit predecessor-bound successor statement/i,
    'predecessor-bound scope expansion',
  )
  assertMatches(
    SURFACE_PATHS.security,
    prose(SURFACE_PATHS.security),
    /only a scope addition needs a successor statement/i,
    'successor only for added scope',
  )
  assertMatches(
    SURFACE_PATHS.adr21,
    prose(SURFACE_PATHS.adr21),
    /predecessor-bound successor scope/i,
    'predecessor-bound recorded successor',
  )
  assertMatches(
    SURFACE_PATHS.adr23,
    prose(SURFACE_PATHS.adr23),
    /successor statement may add it without recertifying unchanged authority/i,
    'unchanged authority continuity across a scope addition',
  )
  assertMatches(
    SURFACE_PATHS.readme,
    prose(SURFACE_PATHS.readme),
    /without requesting an external legal-proof artifact or later recertification/i,
    'no later recertification of the accepted scope',
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
