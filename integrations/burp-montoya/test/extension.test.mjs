import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFile, readdir } from 'node:fs/promises'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const integration = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const sourceRoot = path.join(integration, 'src', 'main', 'java')

async function javaSources(directory = sourceRoot) {
  const files = []
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name)
    if (entry.isDirectory()) files.push(...await javaSources(full))
    else if (entry.isFile() && entry.name.endsWith('.java')) files.push(full)
  }
  return files.sort()
}

async function allSource() {
  const files = await javaSources()
  return (await Promise.all(files.map((file) => readFile(file, 'utf8')))).join('\n')
}

test('Montoya bridge uses read-only Community-safe proxy history APIs', async () => {
  const source = await allSource()
  assert.match(source, /api\.proxy\(\)\.history\(\)/)
  assert.match(source, /item\.finalRequest\(\)/)
  assert.doesNotMatch(source, /\.scanner\s*\(/)
  assert.doesNotMatch(source, /sendRequest\s*\(/)
  assert.doesNotMatch(source, /register(?:Request|Response|Http)Handler\s*\(/)
  assert.doesNotMatch(source, /with(?:Added|Body|Header|Method|Path|Removed|Service|Status|Updated)/)
})

test('sanitized HAR contract reports runtime edition and refuses stronger claims', async () => {
  const exporter = await readFile(path.join(sourceRoot, 'dev', 'lastaperture', 'burp', 'ProxyHistoryExporter.java'), 'utf8')
  const runtime = await readFile(path.join(sourceRoot, 'dev', 'lastaperture', 'burp', 'BurpRuntime.java'), 'utf8')
  assert.match(runtime, /version\.edition\(\)\.name\(\)/)
  assert.match(runtime, /version\.buildNumber\(\)/)
  assert.match(exporter, /"active_scanner", "NOT_USED"/)
  assert.match(exporter, /"traffic_modification", "DISABLED"/)
  assert.match(exporter, /"network_dispatch", "DISABLED"/)
  assert.match(exporter, /"security_verdict", "NOT_ASSESSED"/)
  assert.match(exporter, /"applied_to_audit_bundle", false/)
  assert.match(exporter, /"core_evidence_provenance", "WEB_HAR"/)
  assert.match(exporter, /log\.put\("version", "1\.2"\)/)
  assert.match(exporter, /log\.put\("_lastAperture", provenance\)/)
})

test('capture output is value-free, bounded, deterministic, and create-only', async () => {
  const source = await allSource()
  const exporter = await readFile(path.join(sourceRoot, 'dev', 'lastaperture', 'burp', 'ProxyHistoryExporter.java'), 'utf8')
  const canonical = await readFile(path.join(sourceRoot, 'dev', 'lastaperture', 'burp', 'CanonicalJson.java'), 'utf8')
  assert.doesNotMatch(exporter, /(?:ParsedHttpParameter|HttpHeader|Cookie)::value/)
  assert.doesNotMatch(exporter, /(?:parameter|header|cookie)\.value\(\)/)
  assert.doesNotMatch(exporter, /bodyToString\s*\(/)
  assert.doesNotMatch(exporter, /\.url\(\)/)
  assert.match(exporter, /header_values_removed_except_content_type", true/)
  assert.match(exporter, /structural_content_type_retained", true/)
  assert.match(exporter, /query_values_removed", true/)
  assert.match(exporter, /body_values_removed", true/)
  assert.match(exporter, /CREATE_NEW/)
  assert.doesNotMatch(exporter, /REPLACE_EXISTING/)
  assert.match(exporter, /item\.put\("value", ""\)/)
  assert.match(exporter, /shape\.put\(String\.valueOf\(field\.get\("name"\)\), ""\)/)
  assert.match(exporter, /pathTemplate\.replace\("\{value\}", "0"\)/)
  assert.match(exporter, /result\.put\("httpVersion", CaptureSanitizer\.httpVersion/)
  assert.match(exporter, /result\.put\("method", CaptureSanitizer\.httpMethod/)
  assert.match(exporter, /representativeBodySize/)
  assert.match(exporter, /postData\.put\("size", representativeBodySize\)/)
  assert.match(canonical, /entries\.sort\(Comparator\.comparing/)
  assert.match(exporter, /historyRecordsExamined = Math\.min\(historyRecordsAvailable, configuration\.maxItems\(\)\)/)
  assert.match(exporter, /index < historyRecordsExamined/)
  assert.match(exporter, /selected\.sort\(Comparator/)
  assert.doesNotMatch(exporter, /new ArrayList<>\(api\.proxy\(\)\.history\(\)\)/)
  assert.match(exporter, /FileChannel\.open\([\s\S]*StandardOpenOption\.CREATE_NEW/)
  assert.doesNotMatch(exporter, /Files\.move|ATOMIC_MOVE/)
  assert.match(source, /maxItems > 10_000/)
  assert.match(source, /MAX_AGGREGATE_METADATA_WEIGHT = 90_000/)
  assert.match(source, /MAX_QUERY_NAMES = 512/)
  assert.match(source, /MAX_BODY_FIELDS = 1024/)
  assert.match(source, /sanitized request path exceeds 2048 characters/)
  assert.match(source, /metadata_truncated/)
  assert.match(source, /path literals must be short ASCII route segments/)
})

test('unload closes the worker and deregisters the suite tab', async () => {
  const source = await allSource()
  assert.match(source, /registerUnloadingHandler\(this::close\)/)
  assert.match(source, /worker\.shutdownNow\(\)/)
  assert.match(source, /RejectedExecutionException/)
  assert.match(source, /Thread\.currentThread\(\)\.isInterrupted\(\)/)
  assert.match(source, /suiteTabRegistration\.deregister\(\)/)
})

test('local-path build helper compiles with the supplied API and excludes it from the result', async () => {
  const build = await readFile(path.join(integration, 'build.ps1'), 'utf8')
  const verify = await readFile(path.join(integration, 'verify.ps1'), 'utf8')
  const manifest = await readFile(path.join(integration, 'MANIFEST.MF'), 'utf8')
  assert.match(build, /Parameter\(Mandatory = \$true\)/)
  assert.match(build, /--release 17/)
  assert.match(build, /-proc:none/)
  assert.match(build, /-implicit:none --source-path \$emptySourceRoot/)
  assert.match(build, /-classpath \$apiJar/)
  assert.match(build, /classpath leaked Burp API classes/)
  assert.match(build, /LastApertureBurpExtension\.class/)
  assert.doesNotMatch(build, /Invoke-WebRequest|Start-BitsTransfer|curl|maven|gradle/i)
  assert.doesNotMatch(build, /REPLACE|\[switch\]\$Force/)
  assert.match(build, /\.partial\./)
  assert.match(build, /\[System\.IO\.File\]::Move\(\$candidateJar, \$outputJar\)/)
  assert.match(verify, /ExporterSelfTest/)
  assert.match(verify, /verify-har\.mjs/)
  assert.match(verify, /-proc:none/)
  assert.match(build, /An exception has occurred in the compiler/)
  assert.match(verify, /An exception has occurred in the compiler/)
  assert.doesNotMatch(verify, /Invoke-WebRequest|Start-BitsTransfer|curl|maven|gradle/i)
  assert.match(manifest, /Main-Class: dev\.lastaperture\.burp\.LastApertureBurpExtension/)
})
