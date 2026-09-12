// Standalone, dependency-free readiness entry point, including before npm ci.
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { inspectReadiness, renderReadiness } from './lib/doctor.mjs'
import { assertLocalFilesystemEndpoint } from './lib/filesystem-endpoint.mjs'
import { isMainModule } from './lib/main-module.mjs'
import { terminalSafeText } from './lib/terminal-text.mjs'

export async function main(args = process.argv.slice(2)) {
  let workerConfigPath
  let json = false
  const toolPaths = {}
  const toolFlags = {
    '--ghidra': 'ghidra',
    '--javac': 'javac',
    '--jar': 'jar',
    '--frida': 'frida',
    '--burp': 'burpDesktop',
    '--burp-extension': 'burpExtension',
    '--crane': 'crane',
  }
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '--json' && !json) json = true
    else if (args[index] === '--worker' && workerConfigPath === undefined && args[index + 1] && !args[index + 1].startsWith('--')) {
      const input = args[++index]
      assertLocalFilesystemEndpoint(input, 'worker configuration')
      workerConfigPath = resolve(input)
    } else if (Object.hasOwn(toolFlags, args[index]) && toolPaths[toolFlags[args[index]]] === undefined && args[index + 1] && !args[index + 1].startsWith('--')) {
      const input = args[++index]
      assertLocalFilesystemEndpoint(input, `${args[index - 1]} tool`)
      toolPaths[toolFlags[args[index - 1]]] = resolve(input)
    } else throw new Error('usage: node scripts/doctor.mjs [--json] [--worker <proof-worker.json>] [--ghidra <file>] [--javac <file>] [--jar <file>] [--frida <file>] [--burp <jar>] [--burp-extension <jar>] [--crane <file>]')
  }
  const report = await inspectReadiness({ projectRoot: resolve(dirname(fileURLToPath(import.meta.url)), '..'), workerConfigPath, toolPaths })
  process.stdout.write(json ? `${JSON.stringify(report, null, 2)}\n` : renderReadiness(report))
  return report
}

if (isMainModule(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`ERROR: ${terminalSafeText(error.message)}\n`)
    process.exitCode = 1
  })
}
