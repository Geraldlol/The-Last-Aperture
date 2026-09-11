#!/usr/bin/env node

import {
  analyzeGhidraArtifact as defaultAnalyzeGhidraArtifact,
  buildProtocolContractFile as defaultBuildProtocolContractFile,
  importHarFile as defaultImportHarFile,
  traceFridaArtifact as defaultTraceFridaArtifact,
  traceFridaPlanFile as defaultTraceFridaPlanFile,
} from './lib/reverse-controller.mjs'
import {
  generateNativeConnectorPackage as defaultGenerateNativeConnectorPackage,
  verifyGeneratedConnectorPackage as defaultVerifyGeneratedConnectorPackage,
} from './lib/reverse-connector-generator.mjs'
import { isMainModule } from './lib/main-module.mjs'
import { terminalSafeJson, terminalSafeText } from './lib/terminal-text.mjs'
import { PLATFORM_VERSION } from './lib/version.mjs'

export const REVERSE_HELP = `The Last Aperture reverse engineering ${PLATFORM_VERSION}

Usage:
  last-aperture-reverse web import-har --har <absolute.har> --origin <canonical-origin> [--origin <canonical-origin> ...] [--path-literal <segment> ...] --out <absolute-new.json> [--json]
  last-aperture-reverse protocol build --web-evidence <absolute.json> [--web-evidence <absolute.json> ...] [--reverse-evidence <absolute.json> ...] --out <absolute-new.json> [--json]
  last-aperture-reverse protocol generate --contract <absolute.json> --out <absolute-new-directory> [--name <npm-package-name>] [--json]
  last-aperture-reverse protocol verify --package <absolute-generated-directory> --manifest-sha256 <externally-retained-sha256> [--json]
  last-aperture-reverse ghidra analyze --lab-root <absolute-directory> --binary <contained-relative-path> --artifact-kind <native-executable|shared-library|firmware-image> --ghidra <absolute-launcher> --out <absolute-new-directory> [--json]
  last-aperture-reverse frida trace --lab-root <absolute-directory> --binary <contained-relative-path> --frida <absolute-native-executable> --module <module-or-<main>> --symbol <exported-symbol> --out <absolute-new-directory> [--json]
  last-aperture-reverse frida trace-plan --plan <absolute.json> --frida <absolute-native-executable> --out <absolute-new-directory> [--json]

The reverse routes accept local artifacts and captures. Frida v1 executes one
named local-lab executable; the typed v2 plan also supports bounded local, USB,
and explicit-device attachment. The routes never accept raw tool arguments,
caller scripts, remote host/token configuration, or evaluated code. HAR values are removed;
--path-literal declares a route segment safe to retain in the protocol shape.
Protocol generation is offline and emits a contract-bound Node connector;
protocol verify checks it against the externally retained manifest digest.
`

const BOOLEAN_OPTIONS = new Set(['help', 'json'])
const REPEATABLE_OPTIONS = new Set(['origin', 'path-literal', 'web-evidence', 'reverse-evidence'])

function cliError(code, message) {
  const error = new Error(message)
  error.name = 'ReverseCliError'
  error.code = code
  return error
}

function parseArguments(argv) {
  if (!Array.isArray(argv) || argv.some((value) => typeof value !== 'string')) {
    throw cliError('REVERSE_CLI_INVALID', 'arguments must be strings')
  }
  const positionals = []
  const options = new Map()
  for (let index = 0; index < argv.length; index += 1) {
    const token = argv[index]
    if (!token.startsWith('--')) {
      positionals.push(token)
      continue
    }
    const name = token.slice(2)
    if (name.length === 0 || name.includes('=')) {
      throw cliError('REVERSE_CLI_OPTION_INVALID', `unknown option syntax: ${token}`)
    }
    if (BOOLEAN_OPTIONS.has(name)) {
      if (options.has(name)) throw cliError('REVERSE_CLI_OPTION_DUPLICATE', `duplicate option: --${name}`)
      options.set(name, true)
      continue
    }
    const value = argv[index + 1]
    if (value === undefined || value.startsWith('--')) {
      throw cliError('REVERSE_CLI_OPTION_VALUE_REQUIRED', `option requires one value: --${name}`)
    }
    index += 1
    if (REPEATABLE_OPTIONS.has(name)) {
      options.set(name, [...(options.get(name) ?? []), value])
    } else if (options.has(name)) {
      throw cliError('REVERSE_CLI_OPTION_DUPLICATE', `duplicate option: --${name}`)
    } else {
      options.set(name, value)
    }
  }
  return { positionals, options }
}

function requireScalar(options, name) {
  const value = options.get(name)
  if (typeof value !== 'string') throw cliError('REVERSE_CLI_OPTION_REQUIRED', `required option is missing: --${name}`)
  return value
}

function requireList(options, name) {
  const value = options.get(name)
  if (!Array.isArray(value) || value.length === 0) {
    throw cliError('REVERSE_CLI_OPTION_REQUIRED', `at least one --${name} option is required`)
  }
  return value
}

function optionalList(options, name) {
  return options.get(name) ?? []
}

function assertRoute(parsed, command, action, allowed) {
  if (parsed.positionals.length !== 2 || parsed.positionals[0] !== command || parsed.positionals[1] !== action) {
    throw cliError('REVERSE_CLI_COMMAND_INVALID', `unknown reverse command: ${parsed.positionals.join(' ') || '(none)'}`)
  }
  const accepted = new Set([...allowed, 'help', 'json'])
  const unknown = [...parsed.options.keys()].filter((name) => !accepted.has(name))
  if (unknown.length > 0) throw cliError('REVERSE_CLI_OPTION_UNKNOWN', `unknown option: --${unknown[0]}`)
}

function renderResult(result, asJson, stdout) {
  if (asJson) stdout.write(`${terminalSafeJson(result, 2)}\n`)
  else {
    const details = [
      result.status,
      result.output_path,
      result.engine ? `engine=${result.engine}` : null,
      Number.isSafeInteger(result.entries) ? `entries=${result.entries}` : null,
      Number.isSafeInteger(result.endpoints) ? `endpoints=${result.endpoints}` : null,
      Number.isSafeInteger(result.observations) ? `observations=${result.observations}` : null,
    ].filter(Boolean)
    stdout.write(`${details.map((value) => terminalSafeText(value)).join(' ')}\n`)
  }
}

export async function runReverseCli(argv, {
  importHarFile = defaultImportHarFile,
  buildProtocolContractFile = defaultBuildProtocolContractFile,
  generateNativeConnectorPackage = defaultGenerateNativeConnectorPackage,
  verifyGeneratedConnectorPackage = defaultVerifyGeneratedConnectorPackage,
  analyzeGhidraArtifact = defaultAnalyzeGhidraArtifact,
  traceFridaArtifact = defaultTraceFridaArtifact,
  traceFridaPlanFile = defaultTraceFridaPlanFile,
  stdout = process.stdout,
  stderr = process.stderr,
} = {}) {
  let asJson = Array.isArray(argv) && argv.includes('--json')
  try {
    const parsed = parseArguments(argv)
    asJson = parsed.options.get('json') === true
    if (parsed.options.get('help') === true || parsed.positionals.length === 0) {
      stdout.write(REVERSE_HELP)
      return 0
    }

    const [command, action] = parsed.positionals
    let result
    if (command === 'web' && action === 'import-har') {
      assertRoute(parsed, 'web', 'import-har', ['har', 'origin', 'path-literal', 'out'])
      result = await importHarFile({
        harPath: requireScalar(parsed.options, 'har'),
        targetOrigins: requireList(parsed.options, 'origin'),
        pathLiterals: optionalList(parsed.options, 'path-literal'),
        outPath: requireScalar(parsed.options, 'out'),
      })
    } else if (command === 'protocol' && action === 'build') {
      assertRoute(parsed, 'protocol', 'build', ['web-evidence', 'reverse-evidence', 'out'])
      result = await buildProtocolContractFile({
        webEvidencePaths: requireList(parsed.options, 'web-evidence'),
        reverseEvidencePaths: optionalList(parsed.options, 'reverse-evidence'),
        outPath: requireScalar(parsed.options, 'out'),
      })
    } else if (command === 'protocol' && action === 'generate') {
      assertRoute(parsed, 'protocol', 'generate', ['contract', 'out', 'name'])
      result = await generateNativeConnectorPackage({
        contractPath: requireScalar(parsed.options, 'contract'),
        outPath: requireScalar(parsed.options, 'out'),
        packageName: parsed.options.get('name'),
      })
    } else if (command === 'protocol' && action === 'verify') {
      assertRoute(parsed, 'protocol', 'verify', ['package', 'manifest-sha256'])
      result = await verifyGeneratedConnectorPackage({
        packagePath: requireScalar(parsed.options, 'package'),
        expectedManifestSha256: requireScalar(parsed.options, 'manifest-sha256'),
      })
    } else if (command === 'ghidra' && action === 'analyze') {
      assertRoute(parsed, 'ghidra', 'analyze', ['lab-root', 'binary', 'artifact-kind', 'ghidra', 'out'])
      result = await analyzeGhidraArtifact({
        labRoot: requireScalar(parsed.options, 'lab-root'),
        binary: requireScalar(parsed.options, 'binary'),
        artifactKind: requireScalar(parsed.options, 'artifact-kind'),
        ghidraPath: requireScalar(parsed.options, 'ghidra'),
        outPath: requireScalar(parsed.options, 'out'),
      })
    } else if (command === 'frida' && action === 'trace') {
      assertRoute(parsed, 'frida', 'trace', ['lab-root', 'binary', 'frida', 'module', 'symbol', 'out'])
      result = await traceFridaArtifact({
        labRoot: requireScalar(parsed.options, 'lab-root'),
        binary: requireScalar(parsed.options, 'binary'),
        fridaPath: requireScalar(parsed.options, 'frida'),
        moduleName: requireScalar(parsed.options, 'module'),
        symbolName: requireScalar(parsed.options, 'symbol'),
        outPath: requireScalar(parsed.options, 'out'),
      })
    } else if (command === 'frida' && action === 'trace-plan') {
      assertRoute(parsed, 'frida', 'trace-plan', ['plan', 'frida', 'out'])
      result = await traceFridaPlanFile({
        planPath: requireScalar(parsed.options, 'plan'),
        fridaPath: requireScalar(parsed.options, 'frida'),
        outPath: requireScalar(parsed.options, 'out'),
      })
    } else {
      throw cliError('REVERSE_CLI_COMMAND_INVALID', `unknown reverse command: ${parsed.positionals.join(' ')}`)
    }
    renderResult(result, asJson, stdout)
    return result.status === 'SUCCEEDED' ? 0 : 2
  } catch (error) {
    const code = typeof error?.code === 'string' ? error.code : 'REVERSE_CLI_FAILED'
    const message = terminalSafeText(error?.message ?? 'reverse command failed')
    if (asJson) stderr.write(`${terminalSafeJson({ status: 'FAILED', error: { code, message } }, 2)}\n`)
    else stderr.write(`last-aperture-reverse: ${message}\n`)
    return 1
  }
}

if (isMainModule(import.meta.url)) {
  process.exitCode = await runReverseCli(process.argv.slice(2))
}
