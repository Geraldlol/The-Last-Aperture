---
name: failure-semantics-and-resilience
title: Exceptional states, failure semantics, and resilience
runs_in: fanout
activates_on:
  paths:
    - '**/{errors,error,exceptions,exception,resilience}/**'
    - '**/*{error,Error,exception,Exception,failure,Failure}*.{py,js,ts,tsx,mjs,go,java,kt,rb,cs,php,rs,swift}'
    - '**/*{handler,Handler,middleware,Middleware}*.{py,js,ts,tsx,mjs,go,java,kt,rb,cs,php,rs,swift}'
    - '**/{commands,cmd,cli}/**'
    - '**/{workers,jobs,queues,consumers,schedulers}/**'
    - '**/*{worker,Worker,job,Job,consumer,Consumer,scheduler,Scheduler}*.{py,js,ts,tsx,mjs,go,java,kt,rb,cs,php,rs}'
    - '**/*{retry,Retry,backoff,Backoff,circuit,Circuit}*.{py,js,ts,tsx,mjs,go,java,kt,rb,cs,php,rs,yaml,yml,json}'
    - '**/{celeryconfig.py,sidekiq.yml,bullmq*.{js,ts},resilience4j*.{yaml,yml},polly*.json}'
    - '**/{transactions,unitofwork,uow}/**'
    - '**/*{transaction,Transaction,unitofwork,UnitOfWork}*.{py,js,ts,go,java,kt,rb,cs,php,rs}'
    - '**/*{pool,Pool,limiter,Limiter,semaphore,Semaphore}*.{py,js,ts,go,java,kt,rb,cs,php,rs}'
    - '**/{supervisord.conf,systemd,supervisor,healthchecks}/**'
    - '**/*{health,Health,readiness,Readiness,liveness,Liveness}*.{py,js,ts,go,java,kt,rb,cs,php,rs,yaml,yml}'
    - '**/*.{service,timer}'
    - '**/*.{py,js,jsx,ts,tsx,mjs,cjs,go,java,kt,kts,rb,cs,php,rs,swift,scala,cls}'
  signals:
    - 'except Exception'
    - 'except BaseException'
    - 'catch (Exception'
    - 'catch (Throwable'
    - 'recover()'
    - 'panic('
    - 'try {'
    - 'finally'
    - 'defer '
    - 'retry'
    - 'backoff'
    - 'dead-letter'
    - 'dead_letter'
    - 'DLQ'
    - 'Celery'
    - 'Sidekiq'
    - 'BullMQ'
    - 'bullmq'
    - 'Resilience4j'
    - 'Polly'
    - 'transaction.atomic'
    - 'BEGIN'
    - 'COMMIT'
    - 'ROLLBACK'
    - 'UnitOfWork'
    - 'unit_of_work'
    - 'commit()'
    - 'rollback()'
    - 'compensate'
    - 'compensation'
    - 'saga'
    - 'idempotency_key'
    - 'deduplication_id'
    - 'timeout'
    - 'deadline'
    - 'CircuitBreaker'
    - 'circuit_breaker'
    - 'Semaphore'
    - 'thread pool'
    - 'connection pool'
    - 'max_retries'
    - 'retry_count'
    - 'max_attempts'
    - 'graceful degradation'
    - 'degraded mode'
    - 'uncaughtException'
    - 'unhandledRejection'
    - 'set_exception_handler'
    - 'excepthook'
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
owns:
  - security-control-failure-mode
  - partial-operation-and-rollback
  - retry-backoff-and-redelivery-safety
  - resource-exhaustion-and-bounded-work
  - null-default-and-unknown-state-handling
  - cleanup-and-resource-release
  - safe-degradation-and-last-resort-handling
defers:
  error-handling-and-verbose-responses: web-and-api
  rate-limiting-and-request-quotas: web-and-api
  race-conditions-and-toctou: web-and-api
  webhook-handler-integrity: web-and-api
  client-trusted-business-rules: web-and-api
  denial-of-wallet-controls: llm-and-ai
  pipeline-scanner-gating: cicd-and-supply-chain
  runner-and-build-environment-trust: cicd-and-supply-chain
  control-plane-audit-logging: cloud-and-iac
  backup-and-replica-configuration: cloud-and-iac
  database-integrity-transactions-and-concurrency: database-and-data-stores
  symmetric-encryption-and-nonce-handling: crypto-and-key-management
  threat-detectability-gap: threat-modeling
  control-failure-observability: security-observability-and-response
frameworks:
  - owasp-top-10-2025
  - owasp-asvs-5.0.0
  - cwe
severity_floor: low
---

## Scope

This lens audits what code does when an expected assumption stops being true: a dependency times out, validation throws, one write succeeds and the next fails, a queue redelivers, a pool is exhausted, a value is absent, or the last handler in the process receives an error nobody anticipated. It is the repository-wide companion to **OWASP A10:2025 Mishandling of Exceptional Conditions**. The web lens still owns what an HTTP response reveals; this lens owns whether the operation remains secure and internally consistent.

An exception is not a finding. The finding is a named security decision or side effect that changes because of the exception. Every candidate therefore identifies all four of these before it is queued:

1. the operation or security control that failed;
2. the branch that handled, defaulted, retried, or discarded the failure;
3. the protected decision or persisted side effect reached afterward; and
4. the invariant that should have held, established from code, schema, tests, or documented intent.

The source can establish that a failure path is missing, fail-open, partial, or unbounded. It cannot establish production retry counts, pool sizes after environment overrides, supervisor behavior, downstream recovery, or whether an external circuit breaker exists. Those are verification steps, never assumed mitigations and never repository clearances.

### Owns

| Topic | What that means here |
|---|---|
| `security-control-failure-mode` | Authentication, authorization, validation, signature, policy, quota, or audit dependencies that error and let the guarded operation continue. The underlying control's correctness remains with its domain owner. |
| `partial-operation-and-rollback` | Multi-step state changes whose failure path commits an unauthorized, contradictory, or unrecoverable subset instead of restoring the previous valid state. |
| `retry-backoff-and-redelivery-safety` | Bounded attempts, backoff and jitter, retry classification, duplicate delivery, poison-message handling, and amplification across nested retries. |
| `resource-exhaustion-and-bounded-work` | Per-operation bounds on time, memory, threads, connections, queue depth, decompression, parsing, and fan-out outside the model-specific and generic HTTP quota topics. |
| `null-default-and-unknown-state-handling` | Missing, unknown, stale, or impossible values that select a permissive default or skip a security-relevant branch. |
| `cleanup-and-resource-release` | Locks, temporary privileges, files, handles, transactions, leases, and sensitive buffers not released or restored on every exit path. |
| `safe-degradation-and-last-resort-handling` | Degraded modes and process-level handlers that preserve security invariants, record the failure, and stop or isolate unsafe work instead of continuing blindly. |

### Does not own

- **web-and-api** owns response verbosity, generic route quotas, webhook replay, application races, and client-trusted workflow rules. A 500 response containing a stack trace is `error-handling-and-verbose-responses`; a validation service throwing and the transaction continuing is `security-control-failure-mode` here.
- **business-logic** establishes product-specific sequence and money invariants. This lens supplies the failure path that violates one; triage merges the two rather than filing a second defect.
- **database-and-data-stores** owns database-native transaction, isolation, and integrity semantics. This lens owns an application workflow that fails to use or correctly unwind those mechanisms.
- **cicd-and-supply-chain** owns scanner fail-open and runner failures inside pipelines. **cloud-and-iac** owns backup configuration and control-plane logging. **llm-and-ai** owns model spend and agent loop budgets. **crypto-and-key-management** owns padding-oracle and primitive-specific failure behavior.
- **security-observability-and-response** owns whether a control failure becomes a useful security event and alert. This lens owns whether the protected action continued.

### Framework boundaries

- `A10:2025` is a risk category, not proof that every exception path was tested. Its CWE set ranges from missing parameters and nulls through fail-open behavior, rollback, resource exhaustion, concurrency, and overflow.
- ASVS identifiers are version-pinned. `v5.0.0-16.5.2` requires secure behavior when external resources fail; `v5.0.0-16.5.3` requires graceful, secure failure without fail-open processing; `v5.0.0-16.5.4` requires a last-resort handler. Resource documentation and enforcement map to `v5.0.0-13.1.2`, `v5.0.0-13.1.3`, `v5.0.0-13.2.6`, `v5.0.0-15.1.3`, and `v5.0.0-15.2.2`. Transaction rollback maps to `v5.0.0-2.3.3`.
- These mappings support individual findings only. They do not establish ASVS level conformance; level selection and a requirement-by-requirement applicability ledger are separate work.

### What cannot be determined from a repository

- Runtime values for timeouts, attempts, queue visibility windows, pool limits, circuit thresholds, and feature flags when deployment overrides them.
- Whether a managed queue supplies a dead-letter policy, a mesh supplies retries, or a supervisor restarts a crashed process.
- Whether downstream APIs are idempotent, atomic, or compensating unless their implementation or a binding contract is in scope.
- Whether a production load shape can exhaust a resource. Static evidence can show attacker-controlled work with no bound; a production capacity verdict requires measured behavior.
- Whether alerts arrive or operators recover successfully. That belongs in external operational evidence and the observability lens.

## Activation coverage

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| General exception and handler surfaces | PARTIAL | `security-control-failure-mode` | Cross-language candidate checks exist, but framework exception propagation and middleware ordering require local reading |
| Workers, queues, schedulers, retries, and redelivery | PARTIAL | `retry-backoff-and-redelivery-safety` | Attempt, delay, duplicate, and poison-message checks exist; broker-side delivery policy is not repository evidence unless exported |
| Transactions, compensation, and resource pools | PARTIAL | `partial-operation-and-rollback` | Application boundaries and cleanup paths are assessed; database and provider atomicity remain domain-specific or external |
| Supervisors, health paths, and degraded modes | PARTIAL | `safe-degradation-and-last-resort-handling` | Source handlers and health decisions are assessed; deployed restart policy and operational recovery are not consumed |
| Cross-cutting application source and absence-shaped failure paths | PARTIAL | `security-control-failure-mode` | Broad source assignment prevents neutral filenames from escaping review; every candidate still needs a traced failure branch, protected decision or side effect, and violated invariant |

## Checklist

### 0. Highest-yield sweep

Search broadly, then trace each hit to a decision or side effect. A swallowed exception, `return true` in a catch, retry without an attempt counter, and a commit before the final security-sensitive step are candidates, not findings.

```bash
rg -nU --hidden '(except\s+(Exception|BaseException)|catch\s*\([^)]*(Exception|Throwable)[^)]*\))[^\n]*\n(?:[^\n]*\n){0,8}?\s*(pass|return\s+(true|null|None)|continue\b)' .
rg -n --hidden -i '(max[_-]?(retries|attempts)|retry[_-]?count|backoff|dead[_-]?letter|visibility[_-]?timeout|circuit[_-]?breaker|rollback|compensat)' .
rg -nU --hidden '(commit\(|\.save\(|INSERT\b|UPDATE\b)[\s\S]{0,500}(authorize|validate|verify|publish|send|charge)' .
rg -n --hidden -i '(while\s*\(?(true|1)\)?|for\s*\(;;\)|read_to_end|readAllBytes|unbounded|parallelStream|Promise\.all\()' .
```

The sweep is valid only if the traversal opened a non-zero file set and errors are distinguished from zero matches. Never convert `rg` exit status 2 into “clean.”

### 1. Security controls that fail open (`security-control-failure-mode`)

Trace every exception boundary around a security decision. The safe result of “the authorizer is unavailable,” “the signature service errored,” or “the policy document could not be parsed” is refusal or isolation. A permissive default is a finding only where the guarded operation still occurs.

Check for:

- a catch returning `true`, an allow decision, an empty policy, or an administrator/default role;
- an exception converted to `None`/`null` and a caller that treats absence as “no restriction”;
- validation, malware scanning, certificate verification, quota, or audit dependencies wrapped in “best effort” while the write continues;
- a timeout caught separately and treated more permissively than an explicit denial; and
- fallback from a stronger control to an unverified or unauthenticated path.

```detector
match: |
  def may_export(actor, record):
      try:
          return policy.authorize(actor, "export", record)
      except Exception:
          return True
nomatch: |
  def may_export(actor, record):
      try:
          return policy.authorize(actor, "export", record)
      except PolicyUnavailable as exc:
          security_events.control_failure("export_policy", actor.id, exc)
          return False
```

The event in the clean example does not make it safe; `return False` does. Event quality is assessed separately.

### 2. Partial state and rollback (`partial-operation-and-rollback`)

Write the operation as ordered side effects: reserve, authorize, charge, persist, publish, notify. Identify the first externally visible or irreversible step and every failure after it. Then find the transaction, compensation, or idempotent recovery covering the entire business invariant.

Red flags include a commit inside a loop; a provider call between two local commits; a transaction caught and suppressed; compensation that is not itself durable and retryable; or an error response returned after a state-changing call already ran. A transaction keyword is not a clearance: confirm the relevant statements use the same connection/session and that the caught exception reaches the rollback boundary.

```detector
match: |
  async function transfer(input) {
    await db.debits.insert({ account: input.from, amount: input.amount })
    try {
      await ledger.credit(input.to, input.amount)
    } catch (err) {
      return { ok: false }
    }
  }
nomatch: |
  async function transfer(input) {
    return db.transaction(async (tx) => {
      await tx.debits.insert({ account: input.from, amount: input.amount })
      await tx.credits.insert({ account: input.to, amount: input.amount })
      await tx.outbox.insert({ type: "ledger.transfer", payload: input })
    })
  }
```

Where the remote side cannot participate in the transaction, require a durable state machine or outbox and prove replay converges. Do not demand distributed transactions by default.

### 3. Retry, backoff, and redelivery (`retry-backoff-and-redelivery-safety`)

Inventory retries at every layer: SDK, application helper, queue, proxy, job runner, and caller. Multiply the maxima. Three attempts in four layers can produce 81 calls, and each layer looking bounded does not bound the composition.

Verify:

- a constant maximum attempt count and overall deadline;
- exponential or otherwise justified backoff with jitter for coordinated clients;
- retry classification that excludes authentication/authorization failures and permanent validation errors;
- an idempotency identity derived from the original intent, preserved across attempts and redeliveries;
- a poison-message terminal path that does not loop forever; and
- a per-principal or per-work-item budget so one actor cannot consume the whole worker fleet.

```detector
match: |
  async function deliver(message) {
    for (;;) {
      try { return await downstream.send(message) }
      catch { await sleep(1000) }
    }
  }
nomatch: |
  async function deliver(message, deadline) {
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      try { return await downstream.send(message, { idempotencyKey: message.id }) }
      catch (err) {
        if (!isTransient(err) || Date.now() >= deadline || attempt === 5) throw err
        await sleep(jitteredBackoff(attempt))
      }
    }
  }
```

### 4. Resource bounds (`resource-exhaustion-and-bounded-work`)

Start at attacker- or tenant-influenced sizes and follow them to allocation, decompression, parsing, concurrency, recursion, fan-out, and downstream calls. Require bounds before expensive work, not after it. One global pool may still allow a single principal to monopolize it.

Cover archive expansion ratio and member count, image dimensions, regex worst cases, parser nesting, response/body sizes, thread and connection pools, queue depth, subprocess time and output, and collection-wide `Promise.all`/parallel loops. File format-specific injection stays with its owner; this topic is the bounded-work property.

```detector
match: |
  const body = await response.arrayBuffer()
  const results = await Promise.all(request.items.map((item) => enrich(item)))
nomatch: |
  if (!response.headers.has("content-length") || Number(response.headers.get("content-length")) > MAX_BYTES) {
    throw new PayloadTooLarge()
  }
  const body = await readAtMost(response.body, MAX_BYTES)
  if (request.items.length > MAX_ITEMS) throw new TooManyItems()
  const results = await mapWithConcurrency(request.items, 8, enrich)
```

Header checks alone do not clear a streaming body because the header can be absent or false; the bounded reader is the control.

### 5. Null, default, and unknown states (`null-default-and-unknown-state-handling`)

Enumerations, policy decisions, parsing results, and lookup results need an explicit unknown branch. The risky forms are a `default` that allows, a missing tenant resolving to an unscoped query, an unknown role inheriting a privileged default, or a parse failure retaining the previous trusted value.

```detector
match: |
  switch (decision) {
    case "deny": return false
    case "allow": return true
    default: return true
  }
nomatch: |
  switch (decision) {
    case "allow": return true
    case "deny": return false
    case "not_applicable": return false
    default: throw new UnknownPolicyDecision(decision)
  }
```

Exhaustive compiler checks are strong only when the type cannot be widened at a deserialization or FFI boundary. Trace the value's origin.

### 6. Cleanup and release (`cleanup-and-resource-release`)

For every acquired capability, identify the release on success, expected failure, cancellation, timeout, and process shutdown: locks, leases, elevated roles, temporary files, database sessions, sockets, subprocesses, and decrypted buffers. Prefer structured lifetime constructs (`with`, `using`, RAII, `defer`, `try/finally`) and inspect the release call they actually invoke.

The security consequence must be named. A leaked handle with no reachable exhaustion is reliability debt. A lock never released that blocks authorization updates, a temporary admin grant that survives failure, a plaintext temp file left world-readable, or a pool an unauthenticated request can exhaust is a security finding.

### 7. Degraded mode and the last handler (`safe-degradation-and-last-resort-handling`)

A degraded mode declares which functions remain safe, which stop, and how recovery is observed. “Use cached policy,” “skip scanning,” or “run locally without the identity provider” are not graceful degradation unless cache age, scope, revocation, and safe operations are explicitly bounded.

Inspect process-level handlers (`uncaughtException`, `unhandledRejection`, thread exception hooks, panic recovery) for three independent properties:

- the failure is recorded without secrets;
- in-flight protected work is failed, rolled back, or quarantined; and
- the process either reaches a known safe state or terminates for a supervisor to replace it.

```detector
match: |
  process.on("uncaughtException", (err) => {
    logger.error(err)
    // keep serving; the process may now hold partial state
  })
nomatch: |
  process.on("uncaughtException", (err) => {
    logger.fatal({ err: safeError(err) }, "unrecoverable process failure")
    readiness.markUnready()
    server.close(() => process.exit(1))
    setTimeout(() => process.exit(1), SHUTDOWN_DEADLINE_MS).unref()
  })
```

Termination is not automatically correct: prove the supervisor/restart assumption before calling it resilient, and keep the repository result limited to the handler's local behavior.

## Severity calibration

`claimed_impact_severity` describes the state reached if the path is real. Static T0 and unexecuted T3 evidence still cap `effective_severity` at Medium.

| Finding | Claimed impact | Required evidence |
|---|---|---|
| Security-control error permits an unauthorized high-impact action | High; Critical only when unauthenticated, broadly reachable, and the impact itself is Critical | The forced failure, the allow branch, and the protected side effect; not the catch alone |
| Partial money, authority, or integrity operation persists an invalid state | High | The committed first side effect, the later failure, and absence or failure of rollback/compensation |
| Nested or infinite retries can exhaust a shared worker, connection, or paid dependency | High where one actor can exhaust shared availability; Medium when locally bounded | The composed attempt count or an executed counter, plus the shared resource |
| Attacker-sized input reaches unbounded allocation, expansion, concurrency, or parsing | High where a single request can exhaust a shared service; Medium for sustained volume | The untrusted size, missing pre-work bound, and reached allocation/work |
| Unknown or null state selects a permissive authorization/security default | High | The value origin, default branch, and authorized operation |
| Cleanup failure leaves a temporary privilege, plaintext secret, or security lock behind | High for authority/secret exposure; Medium for bounded denial of service | The acquisition and every exit path, plus the surviving capability |
| Missing generic handler with no demonstrated security or availability consequence | Info | Coverage gap only; ASVS mapping is not impact |

## Known false positives

1. **A broad catch that translates an error and then fails closed.** The type breadth may be maintainability debt, but refusal plus unchanged state is the security property. Keep the observability question separate.
2. **No application rollback around a database transaction.** Frameworks often roll back automatically when an exception escapes. Confirm whether the exception is swallowed inside the boundary and whether all writes share that boundary before filing.
3. **Retries in a mature SDK.** The SDK may cap attempts, honor `Retry-After`, and avoid non-idempotent methods. Read the pinned version and constructed client; an import is not evidence either way.
4. **A process that exits on an unrecoverable error.** Crash-only recovery can be safer than continuing. The remaining questions are whether readiness is withdrawn, work is durable, and a supervisor exists; the repository may establish only the first two.
5. **An unbounded in-memory operation over a trusted, build-time collection.** Establish who controls the cardinality and whether it runs in a shared service. “No limit” without an attacker-controlled or tenant-amplified source is not a security finding.
6. **Cleanup delegated to RAII, `with`, `using`, or `defer`.** Inspect the lifetime and destructor/finalizer semantics. Structured cleanup is normally the clearance, not a missing explicit `close()`.
7. **A fallback that deliberately removes privilege.** Anonymous/read-only/offline mode may be safe. Prove what remains callable and what identity the fallback uses rather than flagging the word `fallback`.

## Proof recipes

All proofs obey `_harness.md`: repository tests run only in a disposable mirror, external destinations are denied, and assertions target decisions and side effects rather than log text.

### F1 — Forced dependency failure, decision and side-effect oracle (T1)

Replace the security dependency at its injection seam with a fake that throws each documented failure class: timeout, malformed response, explicit deny, connection error. Exercise the protected path and assert refusal **and** zero protected side effects. Include an allow control and a deny control so “refuse everything” and “the fake never ran” cannot pass.

Where the error should become a security event, attach the **capturing log handler**, but keep the safety assertion independent: a perfect log after an unauthorized write is still a confirmed finding.

### F2 — Transaction checkpoint fault table (T1)

Enumerate each side-effect boundary in the operation. Inject a failure immediately before and after it, then assert the persisted state equals either the complete intended state or the original state—never a prefix. For remote effects, use a counting fake and assert the durable state machine converges after replay. Never call a payment, mail, or hosted queue.

### F3 — Retry and redelivery counter (T1)

Use the **counting fake client** with a scripted sequence of transient and permanent errors. Assert the exact attempt count, delay schedule under **clock control**, overall deadline, stable idempotency key, and terminal poison-message decision. Run nested wrappers together; testing each retry layer alone misses multiplicative amplification.

### F4 — Bounded-work hostile corpus (T1)

Feed a size table through the repository's parser or worker: just below the bound, at it, just above it, declared length absent, compressed-small/expanded-large, deep nesting, and a large fan-out list. Assert rejection occurs before the expensive allocation or downstream call by spying on that boundary. Keep payloads small enough to be nondestructive; the test validates the bound, not machine capacity.

### F5 — Last-resort handler state transition (T1)

Invoke the handler directly with a synthetic exception under the repository runner. Assert readiness becomes false, new protected work is refused, in-flight state is rolled back or left recoverable, and the supervisor-exit callback is requested. Do not crash the test process; inject the exit function. Deployed restart success remains unverified.

### Not provable here, and reported as such every run

- Production saturation, latency, failover, retry storms, and recovery time objectives.
- Broker, mesh, gateway, database, and supervisor settings not exported into the checkout.
- Whether a downstream provider honored an idempotency key or compensation in production.
- Alert delivery and operator response. Source can prove emission and routing configuration, not receipt or action.
