import assert from 'node:assert/strict'
import { readFile, readdir } from 'node:fs/promises'
import { extname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { test } from 'node:test'

const EXTENSION_DIRECTORY = fileURLToPath(
  new URL('../browser/http-authed-chrome/', import.meta.url),
)
const MANIFEST_PATH = join(EXTENSION_DIRECTORY, 'manifest.json')

async function extensionSources(directory = EXTENSION_DIRECTORY) {
  const files = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) files.push(...await extensionSources(path))
    else if (['.html', '.js', '.json', '.mjs'].includes(extname(entry.name))) files.push(path)
  }
  return files
}

test('Chrome bridge manifest grants only active-tab scripting and loopback access', async () => {
  const manifest = JSON.parse(await readFile(MANIFEST_PATH, 'utf8'))

  assert.equal(manifest.manifest_version, 3)
  assert.deepEqual([...manifest.permissions].sort(), ['activeTab', 'scripting'])
  assert.deepEqual(manifest.host_permissions, ['http://127.0.0.1/*'])
  assert.equal(manifest.optional_permissions, undefined)
  assert.equal(manifest.optional_host_permissions, undefined)
  assert.equal(manifest.externally_connectable, undefined)
  assert.equal(manifest.content_scripts, undefined)
  assert.equal(manifest.web_accessible_resources, undefined)
  assert.equal(typeof manifest.background?.service_worker, 'string')
  assert.equal(manifest.background?.type, 'module')
  assert.equal(typeof manifest.action, 'object')

  const extensionCsp = manifest.content_security_policy?.extension_pages ?? ''
  assert.match(extensionCsp, /(?:^|;)\s*script-src\s+'self'\s*(?:;|$)/)
  assert.doesNotMatch(extensionCsp, /unsafe-|https?:|\*/i)
})

test('Chrome bridge sources contain no browser secret extraction or persistence channel', async () => {
  const paths = await extensionSources()
  assert.ok(paths.length >= 4, 'expected a manifest, control page, service worker, and injected code')
  const source = (await Promise.all(paths.map(async (path) => (
    `\n/* ${path} */\n${await readFile(path, 'utf8')}`
  )))).join('\n')

  for (const forbidden of [
    /\bdocument\s*\.\s*cookie\b/i,
    /\bchrome\s*\.\s*cookies\b/i,
    /\bcookieStore\b/i,
    /\bchrome\s*\.\s*(?:webRequest|declarativeNetRequest|debugger)\b/i,
    /\bchrome\s*\.\s*storage\b/i,
    /\b(?:localStorage|sessionStorage|indexedDB)\b/i,
    /\bcaches\s*\.\s*open\b/i,
    /["'](?:cookie|set-cookie)["']/i,
    /\b(?:user data dir|profile path|cookies sqlite|devtools protocol|cdp session)\b/i,
    /\bconsole\s*\.\s*(?:log|debug|info|warn|error)\s*\(/i,
    /<script[^>]+src\s*=\s*["']https?:/i,
    /\bwindow\s*\.\s*postMessage\b/i,
  ]) {
    assert.doesNotMatch(source, forbidden)
  }

  assert.match(source, /127\.0\.0\.1/)
  assert.match(source, /credentials\s*:\s*["']omit["']/)
  assert.match(source, /credentials\s*:\s*["']same-origin["']/)
  assert.match(source, /redirect\s*:\s*["']error["']/)
  assert.doesNotMatch(source, /credentials\s*:\s*["']include["']/)
})

test('one reviewed attach drives the continuous two-phase campaign loop', async () => {
  const [popup, worker] = await Promise.all([
    readFile(join(EXTENSION_DIRECTORY, 'popup.html'), 'utf8'),
    readFile(join(EXTENSION_DIRECTORY, 'service-worker.js'), 'utf8'),
  ])

  assert.match(popup, /Load controller binding/)
  assert.match(popup, /Attach and start campaign/)
  assert.match(popup, /Campaign grant SHA-256/)
  assert.match(popup, /Emergency stop and detach/)
  assert.doesNotMatch(popup, /id=["'](?:prepare|commit|deliver)["']/i)

  assert.match(worker, /preview:\s*["']\/v1\/preview["']/)
  assert.match(worker, /path:\s*ROUTES\.prepare,\s*\n\s*method:\s*["']POST["']/)
  assert.match(worker, /session\.capability\s*=\s*responseCapability/)
  assert.match(worker, /async function campaignLoop\(/)
  assert.match(worker, /bindingEnvelope\(prepared,\s*["']READY["']\)/)
  assert.match(worker, /bindingEnvelope\(prepared,\s*["']RESULT["']\)/)
  assert.match(worker, /executeHttpAuthedInjectedFetch/)
})
