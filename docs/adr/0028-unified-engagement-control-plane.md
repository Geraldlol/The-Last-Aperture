# ADR 0028: Unified engagement control plane

- Status: Accepted
- Date: 2026-09-11
- Owners: The Last Aperture platform
- Extends: ADR 0023

## Context

The platform accepts one operator statement as authority for a named target, but
its repository, HTTP, browser, Burp, Ghidra, Frida, and connector workflows use
separate entrypoints and state. Agents can compose them, yet there is no durable
engagement object that preserves the original statement, selects routes, reports
combined progress, or stops all later work. Authorization friction was removed;
execution friction remained.

## Decision

Add one outer engagement controller as the normal operator-facing entrypoint.
It accepts a target and one bounded ordinary-language authorization statement,
persists that statement once, and binds it to a canonical target and objective.
The engagement remains authoritative across Codex/Claude handoffs and resumes.
It never asks the operator to repeat unchanged authority.

The controller owns a canonical append-only ledger. It selects applicable routes
from a frozen registry, records a durable dispatch permit before target I/O, and
records every result, gap, child-ledger anchor, cleanup state, stop, and terminal
outcome. Existing route controllers retain their own validation and evidence
contracts. Their ledgers become child evidence; they are not competing authority
sources.

A technically missing tool, credential reference, browser session, capture, or
runtime produces `WAITING_FOR_MATERIAL` or `AUTHORIZED_BUT_UNAVAILABLE`. It does
not trigger another authorization question and does not stop independent routes.

The controller may derive short-lived route grants from the durable engagement
authority. Those grants bind the engagement, authority, target, route, and
invocation digests. They are controller implementation records, not new operator
statements.

The public workflow is `engage run`, `engage resume`, `engage status`, and
`engage stop`. Compatibility entrypoints remain available and are invoked only
through fixed public adapters without a shell. Agent-composed browser, process,
network, or analyst-tool work is recorded in the same engagement before and
after execution.

## Consequences

The user can name a target once and let the agent run the complete applicable
toolchain. Status and stop are unified. The original statement survives process
restart, while target or scope changes still require a successor engagement.

The outer controller does not turn reverse observations into vulnerability
verdicts, manufacture unavailable credentials or runtimes, or override operating
system and hosting-platform capability controls. It records those conditions
honestly and continues other work.

## Rejected alternatives

### Keep orchestration only in prompt text

Rejected because prompt continuity alone cannot provide durable target binding,
at-most-once dispatch, combined status, or a shared stop state.

### Merge every child protocol into one schema and ledger

Rejected because route-specific recovery and evidence semantics would be lost.
The engagement ledger anchors child state while preserving each protocol.

### Synthesize a fresh operator statement on every route

Rejected because it recreates the permission friction the platform is designed
to remove and obscures the actual original authority.

## Validation

- One varied natural-language statement drives multiple routes and resumes.
- Every route grant references the original authority digest.
- Tampered authority, target, ledger, or route binding is rejected before I/O.
- Missing material is recorded and independent work continues.
- Stop is durable and prevents all subsequent dispatch.
- Existing route compatibility tests remain green.

