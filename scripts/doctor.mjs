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
  for (let index = 0; index < args.length; index += 1) {
    if (args[index] === '--json' && !json) json = true
    else if (args[index] === '--worker' && workerConfigPath === undefined && args[index + 1] && !args[index + 1].startsWith('--')) {
      const input = args[++index]
      assertLocalFilesystemEndpoint(input, 'worker configuration')
      workerConfigPath = resolve(input)
    } else throw new Error('usage: node scripts/doctor.mjs [--json] [--worker <proof-worker.json>]')
  }
  const report = await inspectReadiness({ projectRoot: resolve(dirname(fileURLToPath(import.meta.url)), '..'), workerConfigPath })
  process.stdout.write(json ? `${JSON.stringify(report, null, 2)}\n` : renderReadiness(report))
  return report
}

if (isMainModule(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`ERROR: ${terminalSafeText(error.message)}\n`)
    process.exitCode = 1
  })
}
