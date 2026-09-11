# Implementation Plan: Unified Engagement Control Plane

## Objective

Make one operator statement and one target the complete user-facing ingress for
an authorized assessment. Codex or Claude creates a durable engagement, selects
and chains every applicable Last Aperture route, preserves one authority binding
across restarts and handoffs, and continues until work is complete, stopped, or
waiting for material that is technically absent.

The engagement controller unifies orchestration and evidence. Existing route
controllers retain their protocol-specific validation, cleanup, and child
ledgers; their outputs are anchored into the engagement ledger rather than
becoming separate authorization prompts.

## Public workflow

```text
last-aperture engage run <target> --attestation-file <file> --out <new-directory>
last-aperture engage resume <engagement-directory>
last-aperture engage status <engagement-directory> [--json]
last-aperture engage stop <engagement-directory> [--reason <text>] [--json]
```

Agents may add reviewed material and record composed host-tool work through the
same controller. These are implementation operations, not new authorization
steps.

## Architecture

```text
ordinary-language statement + target
                 |
      immutable engagement authority
                 |
     append-only engagement ledger
                 |
       deterministic route registry
       /       |        |         \
 repository  HTTP   browser/Burp  reverse/connector
```

- `engagement.json` stores the normalized target, objective, scope mode, and the
  digest of the accepted authority record.
- `authorization.json` stores the exact bounded statement once. Resume derives
  short-lived route grants from its digest and never synthesizes a new operator
  statement.
- `ledger/` stores canonical, create-only, hash-chained records. A dispatch
  permit is durable before route I/O. Stop is durable and checked before every
  later dispatch.
- A frozen route registry orders repository, reconnaissance, authenticated
  browser/HTTP, capture import, Ghidra, Frida, protocol build, connector
  generation, and verification work. Missing tools or material produce
  `WAITING_FOR_MATERIAL`; independent work continues.
- Existing child bundles remain authoritative for their own protocol. The
  engagement ledger records their relative path and digest without upgrading
  observations into unsupported security verdicts.

## Implementation order

1. Authority, target, and manifest contracts.
2. Append-only engagement ledger and stop semantics.
3. Deterministic route registry and fixed public-entrypoint adapters.
4. Start/resume/status/stop controller and CLI.
5. Root CLI, capability registry, skill, documentation, and package wiring.
6. Focused, full-suite, packed-artifact, and live synthetic validation.

## Success criteria

- Any bounded ordinary-language affirmative statement is accepted; no canned
  phrase, signature, RoE file, or repeat confirmation is required.
- Equivalent targets canonicalize identically; target drift and local artifact
  replacement are rejected before route I/O.
- Every route grant binds the same engagement, authority, and target digests.
- Resume works after the old five-minute ingress window without producing a new
  operator authorization.
- Route selection is deterministic and covers every applicable shipped route.
- A durable permit precedes each route dispatch and a normalized outcome follows
  it, including technical unavailability and cleanup uncertainty.
- Stop is idempotent and prevents later dispatch.
- One status response reports authority, target, route progress, evidence,
  waiting material, failures, and terminal state.
- Root help, both installed skills, capabilities, schemas, tests, and npm package
  expose the unified workflow.
- Existing route CLIs remain compatible.

## Validation

- Focused engagement contract, ledger, route, controller, CLI, and release tests.
- Existing adversarial and reverse suites.
- Full `npm.cmd test` and lens lint.
- `npm pack` inventory and extracted-package engagement test.
- Synthetic restart test proving one authority and at-most-once route dispatch.

## Migration and rollback

The engagement layer is additive. Existing repository, HTTP, authenticated
campaign, adversarial, and reverse commands remain available as route adapters.
Rollback removes the engagement entrypoint and its new files without changing
historical child bundles or their validators.
