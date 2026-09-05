# ADR 0025: Bounded passive source-pattern checks

Date: 2026-09-05
Status: Accepted for this implementation slice

## Context

The source-review controller supplies sealed packets but no bundled semantic
analyzer. We need a usable first automated check without equating narrow syntax
matches with vulnerabilities, expanding target execution, or implying complete
language coverage. This slice is separate from existing campaign-runtime work.

## Decision

Add a standalone `source-check.mjs` entry point with explicit local root and
relative-file arguments. Use the already-pinned Acorn parser for two literal
Node TLS configuration checks in JavaScript. Target files are data: never
import them, resolve their dependencies, execute them, or send their contents
to a service. Do not integrate results automatically into sealed audit runs.

Return bounded source coordinates, content digests, fixed-text observations,
and repair acceptance requirements. All observations remain `UNPROVEN` and the
security verdict remains `NOT_ASSESSED`. Unsupported languages, uncertain
bindings, failed reads, parse errors, and resource caps are explicit gaps.
`CHECKED` describes only the declared pattern checks, not security clearance.

The reader rejects remote Windows path syntax before I/O, checks local path
components and regular-file identity around bounded reads, refuses linked
files, and decodes UTF-8 strictly. These are defensive consistency checks on a
stable checkout, not atomic filesystem confinement or a multi-file snapshot.

Keep syntactic observation evaluation separate from the existing benchmark's
vulnerability/finding-authority semantics. Label the separately authored
synthetic corpus as development coverage, preserve unexpected abstentions, and
publish its digest and denominators. It is not externally reviewed or evidence
of real-world detection quality.

## Alternatives considered

- Continue manual-only review: preserves existing behavior but supplies no
  runnable passive analysis baseline.
- Add a broad semantic or remote-model provider: requires a substantially
  larger analysis, privacy, evidence, and evaluation contract.
- Regex matching: cannot reliably distinguish comments, strings, and syntax.
- Add a TypeScript parser now: expands dependency and language claims before
  the small analysis contract has been validated. Report this gap explicitly.

## Consequences and validation

No new dependency, execution route, credential, network integration, source
modification, or security-verdict authority is introduced. The capability
registry adds narrow pattern checking without enabling the unavailable
semantic-provider capability. Unit tests cover syntax and ambiguity; reader
tests cover scope and resource boundaries; CLI tests verify unchanged target
bytes, omitted source content, and distinct failure/gap exit codes. Remove the
standalone entry point and its registry entry to withdraw this additive slice;
there is no stored-run migration.

The implementation uses the repository's Acorn 8.15.0 parser contract
([upstream documentation](https://github.com/acornjs/acorn/blob/8.15.0/acorn/README.md)).
No claim is made that this is a complete semantic analyzer.
