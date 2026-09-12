# Changelog

## 0.14.1 - 2026-09-12

### Added

- A complete, deterministic full-engagement route inventory with explicit
  dispatchable and unavailable outcomes.
- Installed-package readiness checks for Ghidra, Frida, Burp/Montoya, Java,
  OCI tooling, and the required browser-bridge assets.
- Pull-request validation on the supported Node 20 and Node 24 runtimes.

### Fixed

- Bound evidence metadata, acquisition plans, adapters, roots, executable
  identities, and registry image identities to verified durable state.
- Enforced evidence, command, registry, archive, and decompression limits with
  bounded preflight and streaming enforcement; normalized supported GNU, PAX,
  gzip, repeated-layer,
  directory, and large OCI archive forms without uncaught failures.
- Made HTTP recon and authenticated campaign locks, stop markers, reports,
  finalization, reopen timing, redirect handling, and delivery classification
  crash-safe and deterministic.
- Erased transient HTTP, browser, mutation, observer, credential, and connector
  buffers across success, rejection, timeout, cancellation, and recovery paths.
- Redacted credential carriers in HAR, Burp, browser-session, and generated
  connector flows while preserving exact credential-free request bytes.
- Preserved passive capture behavior, bounded browser observations, mutation
  settlement, response-read failures, and connector callback deadlines.
- Rejected repeatedly encoded traversal and ambiguous authority statements, and
  bound resumed repository and artifact targets to their original identities.
- Pinned the patched `fast-uri` 3.1.7 release for clean artifact installs; the
  prior 3.1.6 override was ignored downstream and is affected by
  `GHSA-qw65-cvwx-89v3` and `GHSA-58mr-gqgx-xq4g`.

### Packaging

- Added a publishable shrinkwrap, a packaged changelog, deterministic installed
  doctor checks, and a uniquely versioned upload artifact workflow.
