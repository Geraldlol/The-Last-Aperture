import { test } from 'node:test'
import assert from 'node:assert/strict'
import { spawnSync } from 'node:child_process'
import {
  copyFileSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, join } from 'node:path'

const LENS_PATH = new URL('../skills/red-team-audit/lenses/cloud-and-iac.md', import.meta.url)
const LENS_LINES = readFileSync(LENS_PATH, 'utf8').split(/\r?\n/)

function extractFunction(name) {
  const start = LENS_LINES.findIndex((line) => line === `${name}() {`)
  assert.notEqual(start, -1, `cloud-and-iac.md: missing ${name} function`)

  const end = LENS_LINES.findIndex((line, index) => index > start && line === '}')
  assert.notEqual(end, -1, `cloud-and-iac.md: unterminated ${name} function`)
  return LENS_LINES.slice(start, end + 1).join('\n')
}

function extractSingleLine(startsWith, label) {
  const matches = LENS_LINES.filter((line) => line.startsWith(startsWith))
  assert.equal(matches.length, 1, `cloud-and-iac.md: expected one ${label} command`)
  return matches[0]
}

function extractContinuedCommand(startsWith, label) {
  const start = LENS_LINES.findIndex((line) => line.startsWith(startsWith))
  assert.notEqual(start, -1, `cloud-and-iac.md: missing ${label} command`)

  let end = start
  while (LENS_LINES[end].endsWith('\\')) end += 1
  return LENS_LINES.slice(start, end + 1).join('\n')
}

function resolveBash() {
  const candidates = [
    process.env.GIT_BASH,
    process.platform === 'win32' ? String.raw`C:\Program Files\Git\bin\bash.exe` : undefined,
    process.env.BASH,
    'bash',
    process.platform === 'win32' ? undefined : '/bin/bash',
  ].filter(Boolean)

  for (const candidate of new Set(candidates)) {
    const probe = spawnSync(candidate, ['--version'], {
      encoding: 'utf8',
      windowsHide: true,
    })
    if (!probe.error && probe.status === 0) return candidate
  }
  return null
}

const BICEP_ABSENT = extractFunction('bicep_absent')
const BICEP_COUNT = extractFunction('bicep_count')
const TF_ABSENT = extractFunction('tf_absent')
const TF_COUNT = extractFunction('tf_count')
const TF_META = extractFunction('tf_meta')
const BICEP_ABSENT_COMMAND = extractSingleLine(
  "bicep_absent 'Microsoft[.](KeyVault/vaults|Storage/storageAccounts|",
  'Bicep absence',
)
const BICEP_COUNT_COMMAND = extractContinuedCommand(
  'echo "stores: $(bicep_count ',
  'Bicep count',
)
const FIREWALL_SENTINEL_COMMAND = extractSingleLine(
  'rg -n --hidden -U "startIpAddress',
  'Azure firewall sentinel',
)
const TERRAFORM_ENCRYPTION_COMMAND = extractSingleLine(
  "rg -n --hidden 'storage_encrypted",
  'Terraform explicit-encryption',
)
const BASH = resolveBash()
const BASH_SKIP = BASH
  ? false
  : 'Bash with find/xargs/awk is unavailable; cloud lens shell snippets cannot run'

function runBash(command, cwd) {
  const result = spawnSync(BASH, ['-c', command], {
    cwd,
    encoding: 'utf8',
    windowsHide: true,
  })
  assert.ifError(result.error)
  return {
    status: result.status,
    stdout: result.stdout.replaceAll('\r\n', '\n'),
    stderr: result.stderr.replaceAll('\r\n', '\n'),
  }
}

function runAgainstFixture(path, command) {
  const directory = mkdtempSync(join(tmpdir(), 'red-team-cloud-iac-'))
  try {
    copyFileSync(new URL(`../${path}`, import.meta.url), join(directory, basename(path)))
    return runBash(command, directory)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
}

function runAgainstSource(filename, source, command) {
  const directory = mkdtempSync(join(tmpdir(), 'red-team-cloud-iac-'))
  try {
    writeFileSync(join(directory, filename), source, 'utf8')
    return runBash(command, directory)
  } finally {
    rmSync(directory, { recursive: true, force: true })
  }
}

function assertExit(result, status, label) {
  assert.equal(
    result.status,
    status,
    `${label}: exit ${result.status}; stderr: ${result.stderr.trim() || '(empty)'}`,
  )
}

function bicepCandidateLines(output) {
  return [...output.matchAll(/:(\d+): resource /g)].map((match) => Number(match[1]))
}

function bicepCounts(output) {
  const match = output.match(
    /stores:\s*(\d+)\s+diag:\s*(\d+)\s+pe:\s*(\d+)\s+bicep-files:\s*(\d+)/,
  )
  assert.ok(match, `unexpected Bicep count output: ${output.trim() || '(empty)'}`)
  return {
    stores: Number(match[1]),
    diag: Number(match[2]),
    pe: Number(match[3]),
    files: Number(match[4]),
  }
}

test('cloud fixture tests extract the authoritative lens snippets', () => {
  assert.match(TF_ABSENT, /^tf_absent\(\) \{/)
  assert.match(TF_COUNT, /^tf_count\(\) \{/)
  assert.match(TF_META, /^tf_meta\(\) \{/)
  assert.match(BICEP_ABSENT, /^bicep_absent\(\) \{/)
  assert.match(BICEP_COUNT, /^bicep_count\(\) \{/)
  assert.match(BICEP_ABSENT_COMMAND, /^bicep_absent /)
  assert.match(BICEP_COUNT_COMMAND, /^echo "stores: /)
  assert.match(FIREWALL_SENTINEL_COMMAND, /^rg -n --hidden -U /)
  assert.match(TERRAFORM_ENCRYPTION_COMMAND, /^rg -n --hidden /)
})

test(
  'actual Terraform helpers retain HCL absence, count and metadata behavior',
  { skip: BASH_SKIP },
  () => {
    const construct = String.raw`resource +"aws_db_instance"`
    const helperScript = [
      TF_ABSENT,
      TF_COUNT,
      TF_META,
      `tf_absent '${construct}' 'storage_encrypted[ \\t]*=[ \\t]*true'`,
      `printf 'summary count=%s meta=%s\\n' "$(tf_count '${construct}')" "$(tf_meta '${construct}')"`,
    ].join('\n')
    const vulnerable = runAgainstFixture(
      'fixtures/vulnerable/reporting_database.tf',
      helperScript,
    )
    const clean = runAgainstFixture(
      'fixtures/clean/network_public_alb.tf',
      helperScript,
    )

    assertExit(vulnerable, 0, 'vulnerable Terraform helpers')
    assertExit(clean, 0, 'clean Terraform helpers')
    assert.equal(
      (vulnerable.stdout.match(/resource "aws_db_instance"/g) ?? []).length,
      2,
      `vulnerable Terraform absence candidates: ${vulnerable.stdout}`,
    )
    assert.match(vulnerable.stdout, /summary count=2 meta=0/)
    assert.equal(
      (clean.stdout.match(/resource "aws_db_instance"/g) ?? []).length,
      0,
      `clean Terraform fixture produced an encryption absence candidate: ${clean.stdout}`,
    )
    assert.match(clean.stdout, /summary count=1 meta=0/)

    const metaSource = [
      'resource "aws_db_instance" "fleet" {',
      '  for_each = var.instances',
      '  storage_encrypted = true',
      '}',
      '',
    ].join('\n')
    const meta = runAgainstSource(
      'fleet.tf',
      metaSource,
      `${TF_META}\ntf_meta '${construct}'`,
    )
    assertExit(meta, 0, 'Terraform metadata helper')
    assert.equal(meta.stdout.trim(), '1')
  },
)

test(
  'actual Bicep helpers discriminate vulnerable and clean fixtures',
  { skip: BASH_SKIP },
  () => {
    const absentScript = `${BICEP_ABSENT}\n${BICEP_ABSENT_COMMAND}`
    const vulnerableAbsent = runAgainstFixture(
      'fixtures/vulnerable/azure_public_data_plane.bicep',
      absentScript,
    )
    const cleanAbsent = runAgainstFixture(
      'fixtures/clean/azure_private_endpoint.bicep',
      absentScript,
    )

    assertExit(vulnerableAbsent, 0, 'vulnerable Bicep absence helper')
    assertExit(cleanAbsent, 0, 'clean Bicep absence helper')
    assert.deepEqual(bicepCandidateLines(vulnerableAbsent.stdout), [61, 108])
    assert.equal(cleanAbsent.stdout.trim(), '', 'clean Bicep fixture produced an absence candidate')

    const countScript = `${BICEP_COUNT}\n${BICEP_COUNT_COMMAND}`
    const vulnerableCounts = runAgainstFixture(
      'fixtures/vulnerable/azure_public_data_plane.bicep',
      countScript,
    )
    const cleanCounts = runAgainstFixture(
      'fixtures/clean/azure_private_endpoint.bicep',
      countScript,
    )

    assertExit(vulnerableCounts, 0, 'vulnerable Bicep count helper')
    assertExit(cleanCounts, 0, 'clean Bicep count helper')
    assert.deepEqual(
      bicepCounts(vulnerableCounts.stdout),
      { stores: 2, diag: 0, pe: 0, files: 1 },
    )
    assert.deepEqual(
      bicepCounts(cleanCounts.stdout),
      { stores: 3, diag: 3, pe: 2, files: 1 },
    )
  },
)

test(
  'actual Azure firewall sentinel requires executable vulnerable properties',
  { skip: BASH_SKIP },
  () => {
    const vulnerable = runAgainstFixture(
      'fixtures/vulnerable/azure_public_data_plane.bicep',
      FIREWALL_SENTINEL_COMMAND,
    )
    const clean = runAgainstFixture(
      'fixtures/clean/azure_private_endpoint.bicep',
      FIREWALL_SENTINEL_COMMAND,
    )

    assertExit(vulnerable, 0, 'vulnerable Azure sentinel')
    assertExit(clean, 1, 'clean Azure sentinel')
    assert.match(vulnerable.stdout, /:21[:-].*startIpAddress/)
    assert.match(vulnerable.stdout, /:98[:-].*startIpAddress/)
    assert.match(vulnerable.stdout, /:99[:-].*endIpAddress/)
    assert.equal(clean.stdout.trim(), '', 'clean Bicep fixture matched the firewall sentinel')
  },
)

test(
  'actual Terraform encryption sweep discriminates vulnerable and clean fixtures',
  { skip: BASH_SKIP },
  () => {
    const vulnerable = runAgainstFixture(
      'fixtures/vulnerable/reporting_database.tf',
      TERRAFORM_ENCRYPTION_COMMAND,
    )
    const clean = runAgainstFixture(
      'fixtures/clean/network_public_alb.tf',
      TERRAFORM_ENCRYPTION_COMMAND,
    )

    assertExit(vulnerable, 0, 'vulnerable Terraform encryption sweep')
    assertExit(clean, 1, 'clean Terraform encryption sweep')
    assert.match(vulnerable.stdout, /:8:.*storage_encrypted/)
    assert.match(vulnerable.stdout, /:46:.*storage_encrypted/)
    assert.match(vulnerable.stdout, /:65:.*storage_encrypted/)
    assert.equal(clean.stdout.trim(), '', 'clean Terraform fixture matched explicit disabled encryption')
  },
)
