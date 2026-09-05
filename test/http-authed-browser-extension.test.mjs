import assert from 'node:assert/strict'
import { readFile } from 'node:fs/promises'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'

const EXTENSION_DIRECTORY = fileURLToPath(
  new URL('../browser/http-authed-chrome/', import.meta.url),
)

test('Chrome bridge manifest grants no executable or target-contacting authority', async () => {
  const manifest = JSON.parse(await readFile(
    join(EXTENSION_DIRECTORY, 'manifest.json'),
    'utf8',
  ))

  assert.equal(manifest.manifest_version, 3)
  assert.deepEqual(manifest.permissions, [])
  assert.deepEqual(manifest.host_permissions, [])
  assert.equal(manifest.background, undefined)
  assert.equal(manifest.optional_permissions, undefined)
  assert.equal(manifest.optional_host_permissions, undefined)
  assert.equal(manifest.externally_connectable, undefined)
  assert.equal(manifest.content_scripts, undefined)
  assert.equal(manifest.web_accessible_resources, undefined)
  assert.equal(manifest.action?.default_popup, 'popup.html')

  const extensionCsp = manifest.content_security_policy?.extension_pages ?? ''
  assert.match(extensionCsp, /(?:^|;)\s*script-src\s+'self'\s*(?:;|$)/)
  assert.doesNotMatch(extensionCsp, /unsafe-|https?:|\*/i)
})

test('Chrome bridge popup is a static refusal with no attach or script surface', async () => {
  const popup = await readFile(join(EXTENSION_DIRECTORY, 'popup.html'), 'utf8')

  assert.match(popup, /HTTP_AUTHED_BROWSER_BRIDGE_DISABLED/)
  assert.match(popup, /cannot attach to a tab or execute target requests/i)
  assert.doesNotMatch(popup, /<form|<input|<button|<script/i)
  assert.doesNotMatch(popup, /Attach and start campaign|Load controller binding/i)
})

test('orphaned compatibility scripts cannot attach, inject, poll, or fetch', async () => {
  const source = (await Promise.all([
    'popup.js',
    'service-worker.js',
  ].map((name) => readFile(join(EXTENSION_DIRECTORY, name), 'utf8')))).join('\n')

  assert.match(source, /HTTP_AUTHED_BROWSER_BRIDGE_DISABLED/)
  assert.doesNotMatch(source, /chrome\.(?:runtime|tabs|scripting)/)
  assert.doesNotMatch(source, /fetch\s*\(|setInterval\s*\(|addListener\s*\(/)
  assert.doesNotMatch(source, /^\s*import\s/m)
})
