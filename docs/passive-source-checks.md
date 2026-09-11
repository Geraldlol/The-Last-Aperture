# Passive source checks

This is the first bundled automated **pattern-checking** slice, not a general
semantic source analyzer. It checks two literal Node TLS configuration patterns
in `.js`, `.mjs`, and `.cjs` files using the pinned Acorn parser. Results contain
source coordinates, a content SHA-256, fixed-text repair guidance, and explicit
gaps. Source text and parser diagnostics are not included.

```text
node scripts/source-check.mjs --root C:\projects\example --file src/client.js --file src/config.mjs --json
npm run audit:source-check -- --root /absolute/local/project --file src/client.js
npm run evaluate:source-check -- --json
npm run test:source-check
```

On PowerShell installations that block `npm.ps1`, use `npm.cmd`.
The checker is a standalone entry point; it is not a subcommand of `audit.mjs`.

## Scope and input limits

Supply one absolute local root and one or more explicit relative file paths.
There is no recursive discovery, glob expansion, URL target, target import,
dependency resolution, process execution, or network transport. All file paths
are validated before filesystem access. Remote Windows namespaces, traversal,
linked endpoints, and non-regular files are refused. Unsupported extensions
are reported without reading their contents.

Limits are 100 files, 256 KiB per file, and 8 MiB in aggregate. Parsing and
observation counts are also bounded. The aggregate read budget is consumed in
the supplied file order; later files can be gapped when it is exhausted.
Sources must be valid UTF-8. The reader
checks file identity and metadata around each read, assuming a stable local
checkout. This is not atomic OS confinement, an atomic multi-file snapshot, or
a guarantee that a local path is not on a remotely mounted filesystem.

Relative paths and content digests can still be sensitive metadata. Review the
report before sharing it.

## Rules and evidence

- `node-tls-env-disable`: a literal assignment disabling certificate validation
  through unshadowed `process.env.NODE_TLS_REJECT_UNAUTHORIZED`.
- `node-tls-option-disable`: a literal `rejectUnauthorized: false` option on a
  directly identified Node `https` or `tls` call supported by the checker.

The review premise follows Node's documentation for the
[TLS environment setting](https://nodejs.org/api/cli.html#node_tls_reject_unauthorizedvalue)
and [TLS client certificate verification](https://nodejs.org/api/tls.html#tlsconnectoptions-callback).

These rules identify syntax, not runtime behavior. Shadowed or reassigned
bindings, dynamic options, spreads, unsupported syntax, and parse failures can
produce gaps. They do not silently become clean assessments. Comments and
string contents are not executable syntax matches. Alias and data-flow support
is deliberately narrow; follow the individual gap messages.

`CHECKED` means only these two patterns were checked. `PARTIAL` means parsing
completed but some relevant forms could not be assessed. `NOT_ASSESSED` means
the file could not be checked. Every observation remains `UNPROVEN`; the report
always declares `security_verdict: NOT_ASSESSED`. No observation is proof of
reachability, exploitability, impact, or a verified vulnerability.

Repair recommendations and acceptance checks are review requirements. They
are not patches, executed tests, or evidence of a verified fix. The command
does not change source files, saved findings, or sealed audit coverage.

| Exit code | Meaning |
|---|---|
| 0 | Narrow checks completed without observations or explicit gaps; not security clearance. |
| 1 | Invalid scope or command failure. Rejected input values are not echoed. |
| 2 | One or more observations, with no explicit gaps. |
| 3 | One or more coverage gaps, including when observations also exist. |

## Evaluation and remaining work

`evaluate:source-check` runs the checker on fixed committed source strings,
never executes them, and emits corpus/checker identities and explicit metric
denominators. Cases were authored separately from the checker implementation
but remain a small synthetic development corpus, not an externally vetted
benchmark or a real-world detection-accuracy claim. Unexpected abstentions
must remain visible and cannot turn into true negatives or perfect scores.

The first run on 2026-09-05 exposed one unexpected abstention: a read-only
scalar environment access was mistaken for a namespace alias. That checker
bug was corrected without changing the 24 case labels. The initial result was
8 true positives, 7 true negatives, no false positives or false negatives, and
9 abstentions against 8 expected. After the correction all 24 expectations
match, including the 8 deliberately unsupported cases. Because this feedback
informed development, these cases are now regression data, not held-out data.
The unchanged corpus SHA-256 is
`a1e13dd2510198615800af65aa844e1cde19af32964d8bdbf42c1bcd5bda7160`.

Scoring penalizes wrong or additional rule predictions as false positives even
on a positive case. Consequently a case may contribute TP plus FP, or FN plus
FP; confusion counts are not an exclusive partition of the case count.
Unexpected negative-case abstentions do not count as true negatives, and
unexpected positive-case abstentions remain false negatives.

The semantic provider and semantic oracle remain unavailable. TypeScript/JSX,
broader rules, integration into sealed packets, structured repair records for
existing findings, externally reviewed evaluation, and dependency-aware reuse
remain future work. See [ADR 0025](adr/0025-passive-source-pattern-checks.md).
