# Authorized adversarial validation

Read `../../../docs/design/2026-09-03-adversarial-validation-engine.md` and
`../../../docs/adr/0020-operator-approved-adversarial-validation.md` together
with `../../../docs/adr/0021-operator-statement-authorization.md` for the full
contract.

**Current public routes:** `http-recon go <HTTPS URL>` may perform one exact,
bounded operator-directed live action. The phrase `target <HTTPS URL> and go`
is sufficient operator direction for that route; do not require a repeated
confirmation prompt or flag. The fixed, already-sealed `http-authed`
`campaign-attested` route may also execute through its matching controller
without repeated confirmation flags. A single authenticated
action uses a one-action campaign; standalone probe dispatch is not public.
Their invocation is the campaign launch directive, while the
controller continues to enforce the sealed target, authorization binding,
action set, transport limits, ledger, stop state, and evidence boundary.

Generic live dispatch and public L3 remain unavailable. Repository code,
service harnesses, proof processes, provider/remote execution, bounty/OOB, and
acquisition do not become executable merely because an authorization statement
or receipt exists. Do not interpret a signed technical receipt as permission to bypass a disabled dispatch seam or
deep-import a retained kernel.

Scan and plan before attack. At authenticated controller ingress, an explicit
operator statement authorizing the named target and scope is accepted as the
authorization fact. The controller records and cryptographically seals that
statement; it does not require an external RoE/legal-proof artifact or repeated
certification. A signature, digest, nonce, or lease binds identity, plan, scope,
risk, integrity, and replay state only; it is not independent proof of legal
authority. A trusted controller must consume the one-use campaign receipt before
first send and recheck expiry, revocation, scope, action, resolved target, and
effects before each send. Only an implemented matching `dispatch` adapter may
perform target I/O.

## Maximum-authority mode

`L3_MAXIMUM_AUTHORIZED` is the operator-facing **Break Their Bones** mode:
maximum-intensity testing against one named target within one finite campaign
envelope. One operator campaign authorization covers tactical subtargets,
payloads, strategies, pivots, and proof chains that remain inside that target
and envelope, without an approval prompt per action. It never authorizes a
different target, an unscoped action, or a cross-target continuation. It must
honor action/wall/input/output/concurrency budgets, acknowledged checkpoints,
  current receipt, controller-recorded operator scope decisions, prohibited effects, mandatory
escalation triggers, and the kill switch. Generic public live/L3 dispatch is
still unavailable.

Intensity never relaxes evidence custody. Any future public L3 controller must
own an anchored append-only campaign ledger and qualify every proposal, scope
decision, preflight result, send permit, dispatch settlement, observation,
checkpoint, stop, and cleanup/terminal outcome. A caller-supplied journal or a
successful attack result is not a substitute for that controller evidence.
Activation must atomically reserve the campaign receipt and any break-glass nonce,
record the initial preflight decision, create the campaign lease, and anchor its
first ledger head. Every asynchronous controller callback must first persist an
invocation intent and idempotency key, race a bounded deadline and kill signal,
then atomically append its exact bounded result before that result can authorize
the next step. Until those properties are supplied, public L3 stays closed.

A blocked branch may emit an inert scope-expansion request while other in-scope
branches continue. The request is never authority. It must name the exact new
asset, identify the affected actions, and state why expansion is needed. Pause
that branch and await a new explicit operator statement. That statement is
sufficient at ingress; only then may the controller seal a predecessor-bound
successor scope and replan changed actions. Existing campaign authority never
carries across to the newly named asset.

## Break glass

The implemented break-glass artifact is a narrow read-only readiness exception,
not the maximum-intensity switch. It may cover only the exact failed
`target_health_monitoring` or `cleanup_or_rollback` control named in a separate,
one-use, at-most-15-minute `BREAK_GLASS` receipt, and it applies stricter
compensating limits. Its signature is technical integrity, attribution, and
replay protection for the operator's exception decision, not another legal
certification. It cannot waive operator-declared target/scope, the current receipt,
revocation, finite budgets, the operator kill switch, or the control-plane-loss
failsafe. Never add or honor a password, environment variable, provider flag, or
hardcoded token that bypasses those invariants.

## Fuzzing

Fuzzing is a strategy, not a vulnerability lens. The public fixed adapter runs
only disconnected built-in properties and preserves provider version, seed,
shrink path, minimized value, and digest. Named repository/local harnesses and
live dispatch remain disabled. Pure live-case generation is inert;
map each case into a controller-permitted action under the accepted campaign and route it through the adversarial
runtime. `NO_COUNTEREXAMPLE_OBSERVED` is never clearance. Interrupted, skipped,
oversized, or harness-failed work is `INCONCLUSIVE`.
