import { test } from 'node:test'
import assert from 'node:assert/strict'
import {
  loadLenses,
  pathActivatorMatches,
  signalActivatorMatches,
} from '../scripts/lib/activation.mjs'
import {
  buildRegistry,
  checkEvidenceClasses,
  checkShapes,
} from '../scripts/lib/registry.mjs'

const LENS_DIR = 'skills/last-aperture/lenses'

const EXPECTED_TOPICS = {
  'embedded-iot-ot-security': [
    'cyberphysical-safety-interlocks-and-fail-safe-control',
    'device-identity-and-secure-onboarding',
    'device-lifecycle-reset-and-decommissioning',
    'device-service-and-local-protocol-hardening',
    'embedded-debug-test-and-recovery-interface-exposure',
    'firmware-boot-integrity-and-hardware-root-of-trust',
    'firmware-update-authenticity-and-rollback-protection',
    'iot-command-and-telemetry-boundary',
    'ot-network-segmentation-and-remote-maintenance',
    'physical-access-tamper-and-secret-extraction',
    'wireless-pairing-and-provisioning',
  ],
  'desktop-and-thick-client-security': [
    'desktop-debug-diagnostic-and-developer-surface',
    'desktop-installation-and-package-trust',
    'desktop-local-data-and-secret-storage',
    'desktop-local-ipc-and-process-boundaries',
    'desktop-os-integration-and-shell-invocation',
    'desktop-plugin-extension-and-scripting-trust',
    'desktop-privilege-elevation-and-broker-boundaries',
    'desktop-update-authenticity-and-rollback',
    'desktop-uri-file-association-and-launch-handling',
    'desktop-webview-and-native-bridge-trust',
  ],
  'smart-contract-and-web3-security': [
    'block-context-randomness-and-time-dependence',
    'contract-access-control-and-privileged-roles',
    'contract-initialization-and-deployment-state',
    'contract-upgradeability-and-storage-layout',
    'cross-chain-bridge-and-message-integrity',
    'delegatecall-proxy-and-target-trust',
    'emergency-governance-pause-and-recovery',
    'flash-loan-and-economic-invariant-abuse',
    'gas-griefing-and-unbounded-onchain-execution',
    'onchain-arithmetic-precision-and-share-accounting',
    'onchain-signature-replay-and-domain-separation',
    'oracle-data-and-price-manipulation',
    'reentrancy-and-external-call-ordering',
    'token-accounting-and-standard-conformance',
    'transaction-ordering-front-running-and-mev',
  ],
}

function activationMatches(lens, path, content = '') {
  const activation = lens.frontmatter.activates_on
  return activation.paths.some((selector) => pathActivatorMatches(selector, path))
    || activation.signals.some((selector) => signalActivatorMatches(selector, content))
}

test('the target-driven lenses own a disjoint, explicit topic partition', async () => {
  const lenses = await loadLenses(LENS_DIR)
  const byName = new Map(lenses.map((lens) => [lens.frontmatter.name, lens]))
  const { slugs, violations } = buildRegistry(lenses)

  assert.deepEqual(violations, [])
  assert.deepEqual(checkShapes(lenses), [])
  for (const [name, topics] of Object.entries(EXPECTED_TOPICS)) {
    const lens = byName.get(name)
    assert.ok(lens, `${name} must exist`)
    assert.deepEqual([...lens.frontmatter.owns].sort(), topics)
    for (const topic of topics) assert.equal(slugs.get(topic), name)
  }
})

test('the target-driven lenses consume only their bounded artifact kinds and claims', async () => {
  const lenses = await loadLenses(LENS_DIR)
  const selected = lenses.filter((lens) => EXPECTED_TOPICS[lens.frontmatter.name])

  const expectedBuiltArtifacts = {
    'embedded-iot-ot-security': {
      state: 'consumed',
      artifact_kinds: ['firmware-image'],
      may_conclude: [
        'artifact-signature-invalid',
        'firmware-trust-gap',
        'secret-present-in-artifact',
        'unexpected-artifact-content',
      ],
    },
    'desktop-and-thick-client-security': {
      state: 'consumed',
      artifact_kinds: ['desktop-package', 'native-executable', 'shared-library'],
      may_conclude: [
        'artifact-signature-invalid',
        'binary-hardening-missing',
        'secret-present-in-artifact',
        'unexpected-artifact-content',
        'vulnerable-component-present',
      ],
    },
    'smart-contract-and-web3-security': {
      state: 'consumed',
      artifact_kinds: ['smart-contract-build'],
      may_conclude: [
        'smart-contract-deployment-drift',
        'unexpected-artifact-content',
        'secret-present-in-artifact',
      ],
    },
  }

  assert.equal(selected.length, 3)
  assert.deepEqual(checkEvidenceClasses(selected), [])
  for (const lens of selected) {
    assert.deepEqual(lens.frontmatter.activates_on.evidence_classes, {
      source: { state: 'consumed' },
      'built-artifact': expectedBuiltArtifacts[lens.frontmatter.name],
      'deployed-state': { state: 'not-consumed' },
      'live-runtime': { state: 'not-consumed' },
    })
  }
})

test('embedded activation is specific to firmware, RTOS, device and OT surfaces', async () => {
  const lens = (await loadLenses(LENS_DIR))
    .find(({ frontmatter }) => frontmatter.name === 'embedded-iot-ot-security')

  assert.equal(activationMatches(lens, 'devices/thermostat/platformio.ini'), true)
  assert.equal(activationMatches(lens, 'src/update.c', 'esp_ota_begin(partition, image_size)'), true)
  assert.equal(activationMatches(lens, 'src/main.c', 'int main(void) { return 0; }'), false)
  assert.equal(activationMatches(lens, 'mobile/AndroidManifest.xml', '<manifest />'), false)
  assert.equal(activationMatches(lens, 'web/mqtt-help.md', 'MQTT is documented here'), false)
})

test('desktop activation excludes ordinary web, mobile and native-library projects', async () => {
  const lens = (await loadLenses(LENS_DIR))
    .find(({ frontmatter }) => frontmatter.name === 'desktop-and-thick-client-security')

  assert.equal(activationMatches(lens, 'desktop/electron-builder.yml'), true)
  assert.equal(activationMatches(lens, 'src/main.ts', 'const window = new BrowserWindow(options)'), true)
  assert.equal(activationMatches(lens, 'web/vite.config.ts', 'export default defineConfig({})'), false)
  assert.equal(activationMatches(lens, 'mobile/AndroidManifest.xml', '<manifest />'), false)
  assert.equal(activationMatches(lens, 'src/library.cpp', 'int library_init();'), false)
})

test('smart-contract activation is limited to contract sources and toolchain signals', async () => {
  const lens = (await loadLenses(LENS_DIR))
    .find(({ frontmatter }) => frontmatter.name === 'smart-contract-and-web3-security')

  assert.equal(activationMatches(lens, 'contracts/Vault.sol'), true)
  assert.equal(activationMatches(lens, 'src/vault.txt', 'pragma solidity ^0.8.24;'), true)
  assert.equal(activationMatches(lens, 'src/contracts.ts', 'export const contracts = []'), false)
  assert.equal(activationMatches(lens, 'src/lib.rs', 'pub fn transfer() {}'), false)
  assert.equal(activationMatches(lens, 'docs/solidity.md', 'solidity language notes'), false)
})
