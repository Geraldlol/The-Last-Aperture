import { mkdtemp, writeFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

/**
 * A stub external CLI, as a real spawned process.
 *
 * The obvious approach — drop a shell script on PATH — cannot work here: on
 * Windows the shim must be a .cmd, and execFile refuses .cmd without
 * `shell: true`, which is exactly what the runner will not do. So the stub is
 * a Node script and the test injects a resolver that maps the CLI name to it.
 * Everything downstream is still a real child process: real argv, real stdout
 * bytes, real exit code.
 *
 * `script` is the body of a Node module receiving `args` (the argv the adapter
 * built, minus the script path) and writing to stdout/stderr.
 */
export async function stubCli(name, script) {
  const directory = await mkdtemp(join(tmpdir(), 'rta-stub-'))
  const path = join(directory, `${name}.mjs`)
  await writeFile(
    path,
    `const args = process.argv.slice(2)\n${script}\n`,
    'utf8',
  )
  return {
    directory,
    path,
    // Maps the adapter's chosen CLI name onto the stub, leaving every other
    // name unresolved so an unexpected command still fails as absent.
    resolver: (cli, args) => (cli === name
      ? { file: process.execPath, args: [path, ...args] }
      : { file: cli, args }),
  }
}

/** A resolver under which no external CLI exists at all. */
export const absentCliResolver = () => ({ file: 'rta-definitely-absent-binary', args: [] })
