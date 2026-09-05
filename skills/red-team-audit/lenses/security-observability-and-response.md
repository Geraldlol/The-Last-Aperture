---
name: security-observability-and-response
title: Security observability and response
runs_in: fanout
activates_on:
  paths:
    - '**/{logging,audit}/**'
    - '**/*{audit,security-event,security_event,securityEvent}*.{ts,js,mjs,cjs,py,go,java,kt,cs,rb,php}'
    - '**/{logback,log4j2}*.xml'
    - '**/{alerts,alerting,detection,detectors,siem}/**'
    - '**/*{alert,detection,sigma}*.{yaml,yml,json,hcl,tf}'
    - '**/*{runbook,playbook}*.md'
    - '**/{observability,telemetry,otel,collectors}/**'
    - '**/*{otel,opentelemetry,telemetry,collector}*.{yaml,yml,json,toml,conf,ts,js,py,go,java,cs}'
    - '**/{fluent-bit,fluentd,filebeat,logstash,vector}*.{yaml,yml,json,toml,conf}'
    - '**/*.{js,jsx,ts,tsx,mjs,cjs,py,go,java,kt,kts,cs,rb,php,rs,swift,scala,cls}'
  signals:
    - 'pino'
    - 'winston'
    - 'structlog'
    - 'loguru'
    - 'Serilog'
    - 'NLog'
    - 'logback'
    - 'log4j'
    - 'audit.emit'
    - 'security_event'
    - 'securityEvent'
    - 'PrometheusRule'
    - 'alert:'
    - 'Alertmanager'
    - 'Sigma'
    - 'detection rule'
    - 'PagerDuty'
    - 'Opsgenie'
    - '@opentelemetry'
    - 'opentelemetry'
    - 'OpenTelemetry'
    - 'OTLP'
    - 'fluent-bit'
    - 'Fluentd'
    - 'Filebeat'
    - 'Logstash'
    - 'Sentry'
    - 'Datadog'
    - 'Splunk'
    - 'Elastic APM'
    - 'Honeycomb'
    - 'New Relic'
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
  - security-event-coverage
  - audit-log-integrity-and-access
  - detection-alerting-and-escalation
  - security-telemetry-pipeline-resilience
  - control-failure-observability
defers:
  application-log-and-url-content: web-and-api
  control-plane-audit-logging: cloud-and-iac
  phi-access-audit-controls: hipaa-and-phi
  cross-boundary-attribution-logging: threat-modeling
  threat-detectability-gap: threat-modeling
  security-control-failure-mode: failure-semantics-and-resilience
  partial-operation-and-rollback: failure-semantics-and-resilience
  retry-backoff-and-redelivery-safety: failure-semantics-and-resilience
  resource-exhaustion-and-bounded-work: failure-semantics-and-resilience
  null-default-and-unknown-state-handling: failure-semantics-and-resilience
  cleanup-and-resource-release: failure-semantics-and-resilience
  safe-degradation-and-last-resort-handling: failure-semantics-and-resilience
  hardcoded-credentials-and-key-material: crypto-and-key-management
  pii-inventory-and-data-map: privacy-and-data-protection
  third-party-destination-inventory: privacy-and-data-protection
  processor-contracts-and-dpa: privacy-and-data-protection
  retention-lawfulness-and-deletion-completeness: privacy-and-data-protection
  personal-data-severity-uplift: privacy-and-data-protection
  pci-scope-and-cardholder-data: privacy-and-data-protection
  phi-classification: hipaa-and-phi
  phi-severity-uplift: hipaa-and-phi
frameworks:
  - owasp-top-10-2025
  - owasp-asvs-5.0.0
  - nist-csf-2.0
  - cis-controls-8.1
  - cwe
severity_floor: low
---

## Scope

This lens reviews repository source and source-controlled configuration for the security signal chain: a security-relevant decision occurs, an application event represents it, a source-managed rule can recognize it, and a source-managed route has an accountable escalation target. It also reviews whether failures and losses inside that chain are visible and accounted for.

The unit of review is not "uses a logger." It is a security-event obligation tied to a reachable decision or control. A debug message can coexist with a missing security event; a well-formed audit event can coexist with no detection rule; and a complete-looking rule file can coexist with a production pipeline that drops every event.

Only `source` evidence is consumed. A candidate must cite the decision, emitter, rule, route, queue, retry, or failure branch at `file:line` and trace the relevant source path. Built artifacts, deployed state, and live runtime are outside this lens. Their absence is an explicit verification gap, not evidence of a vulnerability and never evidence of safety.

### Owns

| Topic | What this lens decides |
|---|---|
| `security-event-coverage` | Whether security-relevant application decisions have intentional, structured, outcome-bearing events across the enumerated source paths. |
| `audit-log-integrity-and-access` | Whether application audit records derive trustworthy identity and time, resist ordinary mutation through application code, and have source-visible read/write boundaries. |
| `detection-alerting-and-escalation` | Whether source-controlled detection rules, thresholds, severity, ownership, routing, and escalation references cover emitted security events without obvious blind routes. |
| `security-telemetry-pipeline-resilience` | Whether application-owned exporters, queues, collectors, and shippers preserve or explicitly account for security-event loss and expose their own failure through an independent source-visible path. |
| `control-failure-observability` | Whether security controls distinguish an attacker-caused rejection from unavailable, errored, stale, or misconfigured enforcement machinery and emit an actionable failure signal. |

### Does not own

The same logging surface can raise concerns owned elsewhere. File those under the owner below; do not duplicate them here.

- **web-and-api** owns `application-log-and-url-content`: secrets or personal data in logs or URLs, unsafe log interpolation, delimiter injection, and log-viewer rendering. This lens may require stable event fields, but it never recommends logging raw credentials, tokens, request bodies, or personal data.
- **cloud-and-iac** owns `control-plane-audit-logging`: CloudTrail, Azure Activity Log, Google Cloud audit logs, Kubernetes audit policy, platform diagnostic settings, and their infrastructure sinks.
- **hipaa-and-phi** owns `phi-access-audit-controls`, `phi-classification`, and `phi-severity-uplift`. Whether PHI access must be logged or changes severity is a regulatory decision, not a generic observability decision.
- **threat-modeling** owns `cross-boundary-attribution-logging` and `threat-detectability-gap`. This lens inventories application event obligations and source signal plumbing; threat modeling decides whether a particular attack path remains attributable or detectable across architectural boundaries.
- **failure-semantics-and-resilience** owns `security-control-failure-mode`, `partial-operation-and-rollback`, `retry-backoff-and-redelivery-safety`, `resource-exhaustion-and-bounded-work`, `null-default-and-unknown-state-handling`, `cleanup-and-resource-release`, and `safe-degradation-and-last-resort-handling`. It decides whether an operation stays secure, bounded, and internally consistent when something fails. This lens decides whether the failure or resulting security-telemetry loss is represented as an actionable security signal. One failure branch can inform both reviews, but the retry, exhaustion, rollback, or fail-open mechanism is filed only there.
- **crypto-and-key-management** owns `hardcoded-credentials-and-key-material`. A credential found in an exporter, receiver, or alert configuration is its finding.
- **privacy-and-data-protection** owns `pii-inventory-and-data-map`, `third-party-destination-inventory`, `processor-contracts-and-dpa`, `retention-lawfulness-and-deletion-completeness`, `personal-data-severity-uplift`, and `pci-scope-and-cardholder-data`. Telemetry destinations, contracts, lawful retention, and privacy impact stay there.

This lens also does not re-file the underlying control defect or its failure semantics. A fail-open authorization dependency is `security-control-failure-mode`; a disabled signature check belongs to its verification owner. This lens can independently file the fact that the control's unavailable/error state is indistinguishable from an ordinary denial or is silently discarded.

### What source evidence can establish

Source can establish:

- a reachable security-relevant decision and the branches it takes;
- whether an event call occurs on each branch and which fields are derived server-side;
- whether application code exposes update, delete, truncate, or unguarded read paths over audit records;
- the committed semantics of a detection rule, threshold, route, receiver reference, retry policy, buffer, or dead-letter path;
- whether a local, deterministic proof exercises those branches and observes the expected application behavior.

Every negative result needs a denominator. "No audit calls found" is not enough. Enumerate the relevant routes, jobs, consumers, commands, control adapters, and privileged mutations, then show which obligation lacks an event, rule, or failure signal. Record enumerator counts so a zero-row sweep cannot pass vacuously.

### Runtime nonclaims

Repository evidence does **not** establish any of the following:

- that production logging is enabled at the required level;
- that a deployed formatter preserves fields, timestamps, or event identifiers;
- that clocks are synchronized;
- that a SIEM, collector, shipper, or managed service receives, parses, indexes, correlates, retains, or protects an event;
- that a deployed rule evaluates, that its threshold is suitable for production volume, or that it avoids unacceptable false positives;
- that a receiver address is current, an alert is delivered, a page is acknowledged, an on-call engineer is available, or a playbook is executed effectively;
- that out-of-repository infrastructure or managed-service controls are absent;
- that production users cannot alter records through privileges granted outside the application.

Never turn source intent into "the attack will be detected," "the SIEM alerts," "on-call responds," or "the audit trail is immutable." The strongest source-only phrasing is specific: "the application emits event X on branch Y," "rule R maps X to receiver reference Z," or "application code exposes no mutation path found within the enumerated scope." Runtime delivery and response remain `UNVERIFIED`.

## Framework boundary and mapping

These frameworks guide the questions and classifications in this lens. They are not runtime evidence.

- [OWASP Top 10:2025 A09 — Security Logging & Alerting Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/) is the precise web-risk category used here. It calls out insufficient logging of logins, failed logins, high-value transactions, warnings and errors; unclear messages; local-only logs; missing monitoring; absent alert thresholds and escalation; and penetration tests that do not trigger alerts. Its prevention guidance covers audit trails for high-value transactions, tamper protection, central consumption, monitoring/alerting, escalation, and response playbooks. The stable routing key is `A09:2025`; punctuation in a rendered title must not create a second mapping.
- [OWASP ASVS 5.0.0](https://owasp.org/www-project-application-security-verification-standard/) supplies version-pinned verification requirements. Use `v5.0.0-16.1.1` for the security-event inventory; `v5.0.0-16.2.1` through `v5.0.0-16.2.5` for event metadata, synchronized/UTC time intent, documented sinks, correlation, and sensitive-data exclusion; `v5.0.0-16.3.1` through `v5.0.0-16.3.4` for authentication, authorization, defined security events, bypass attempts, and unexpected or security-control failures; and `v5.0.0-16.4.2` / `v5.0.0-16.4.3` for protection from modification and delivery to a logically separate system. Log-injection requirement `v5.0.0-16.4.1` routes to `application-log-and-url-content`. Repository evidence can map an individual requirement and show committed intent; it cannot prove clock synchronization, deployed sink separation, or whole-profile ASVS conformance.
- [The NIST Cybersecurity Framework (CSF) 2.0, NIST CSWP 29, published February 26, 2024](https://www.nist.gov/publications/nist-cybersecurity-framework-csf-20) supplies high-level outcomes, notably DE.CM-09, DE.AE-02, DE.AE-03, DE.AE-06, and DE.AE-08. NIST explicitly describes CSF outcomes rather than prescribing one implementation. A repository can show code intended to contribute to those outcomes; it cannot prove the organization achieves them.
- [CIS Critical Security Controls v8.1, released June 25, 2024](https://www.cisecurity.org/controls/v8-1) and [CIS Control 8: Audit Log Management](https://www.cisecurity.org/controls/audit-log-management) frame collection, alerting, review, retention, time synchronization, detail, centralization, and service-provider logs. Those are organizational safeguards. Source configuration is evidence of intent only, not proof that collection, review, retention, or response operates.
- [CWE](https://cwe.mitre.org/) classifies implementation mechanisms. OWASP A09:2025 maps CWE-117, CWE-221, CWE-223, CWE-532, and CWE-778. This lens uses CWE-221, CWE-223, and CWE-778 for omitted or insufficient security information. CWE-117 and CWE-532 concerns belong to `application-log-and-url-content` and are deferred to `web-and-api`.

The crosswalk below controls how A09:2025 is applied; it is not five independent OWASP findings.

| Lens topic | A09:2025 application |
|---|---|
| `security-event-coverage` | Security-relevant logins, failures, warnings, errors, high-value transactions, and other enumerated application decisions are represented with enough context to investigate. |
| `audit-log-integrity-and-access` | High-value audit trails have source-visible protection against ordinary tampering and unauthorized application access. |
| `detection-alerting-and-escalation` | Emitted events have source-controlled monitoring logic, thresholds, accountable routing, escalation references, and testable alert use cases where those artifacts are in scope. |
| `security-telemetry-pipeline-resilience` | Source-owned logging and shipping do not silently reduce security events to local-only or unaccounted-for loss when the repository contains that pipeline. |
| `control-failure-observability` | Warnings, errors, and exceptional security-control states are distinguishable from normal operation and ordinary attacker rejection. |

## Activation coverage

The activators seed review; they do not establish a finding or complete a denominator. Signal indexes below are the one-based order in `activates_on.signals`, and path indexes are the one-based order in `activates_on.paths`.

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| Application security events and logging frameworks — paths 1–3; signals 1–11 | PARTIAL | `security-event-coverage` | Source emitters and application audit stores can be traced, but generic logger presence neither enumerates security obligations nor proves delivery. |
| Detection, alert routing, escalation, and playbooks — paths 4–6; signals 12–18 | PARTIAL | `detection-alerting-and-escalation` | Committed rules and routing graphs can be parsed and fixture-tested; deployed evaluation, delivery, acknowledgement, and response remain unverified. |
| Telemetry SDKs, exporters, collectors, and shippers — paths 7–9; signals 19–32 | PARTIAL | `security-telemetry-pipeline-resilience` | Source retry, queue, loss-accounting, and failure branches can be reviewed; production capacity, connectivity, ingestion, retention, and noise cannot. |
| Application source security-decision denominator — path 10 | PARTIAL | `security-event-coverage` | Broad source assignment is required to discover absent events; security relevance and a complete entry-point denominator still require recon and branch tracing. |

## Checklist

Work from obligations to emitters, then from emitters to source-managed detection and transport. Do not start with a repository-wide search for `logger` and treat its hit count as coverage.

### 0. Establish the security-event obligation denominator

Enumerate source-visible operations whose outcome a defender would need to reconstruct or recognize. Tailor the set to the product, but begin with:

- authentication success, failure, recovery, and lockout;
- authorization denials and privileged access decisions;
- creation, removal, or use of elevated roles and service identities;
- administrator actions, impersonation, security-setting changes, and approval overrides;
- sensitive exports, bulk downloads, destructive actions, and high-value transactions;
- signature, CSRF, schema/input-validation, anti-automation, and rate-limit rejection;
- security-control dependency unavailable, timeout, stale-data, parse-error, or configuration-error states;
- telemetry queue, exporter, collector, shipper, and rule-loading failures.

Use a registry-driven enumerator over routes, jobs, message consumers, command handlers, policy adapters, and privileged mutation registries. For each obligation, record:

| Obligation | Decision site | Outcome branches | Event ID/schema | Source sink | Detection/routing reference | Runtime status |
|---|---|---|---|---|---|---|
| concrete operation | `file:line` | success / rejection / control error | event or gap | local source reference | rule/route or gap | `UNVERIFIED` |

Keep a committed-count or expected-minimum assertion for every enumerator. If the repository contains no authoritative registry, document the searched entry-point families and downgrade completeness; do not replace the denominator with logger-call count.

### 1. Security-event coverage (`security-event-coverage`)

For each obligation, follow every material outcome branch. An event should have a stable event identifier and enough server-derived context to answer who or which service acted, what operation was attempted, which object or scope was affected, the outcome, when it occurred, and which request or job ties related records together. Use opaque identifiers and minimum necessary fields; content safety and privacy classification remain with the deferred owners.

Look specifically for:

- success-only logging that omits denials, or failure-only logging that omits privileged success;
- early returns and exception handlers that bypass an otherwise central emitter;
- asynchronous or batch paths that perform the same operation without the interactive path's event;
- events written before the outcome is known, then never corrected or paired with a final outcome;
- free-form messages where the detection rule expects a stable identifier or typed field;
- sampling or rate suppression applied to security audit events without an unsampled security channel;
- a generic error event used for both adversarial rejection and enforcement-service failure.

Absence is a finding only after the denominator and the reachable branch are cited. A pattern match can locate candidates; it cannot prove that an event is absent from middleware, a domain-event subscriber, or a shared adapter.

```detector
match: |
  async function grantAdmin(req, userId) {
    await roles.add(userId, "admin")
    return { ok: true }
  }
nomatch: |
  async function grantAdmin(req, userId) {
    await db.transaction(async (tx) => {
      await roles.add(tx, userId, "admin")
      await securityOutbox.append(tx, "identity.admin_role_granted", {
        actorId: req.auth.subject,
        subjectId: userId,
        outcome: "success",
        requestId: req.id
      })
    })
    return { ok: true }
  }
```

The `match` is only a candidate until enumeration shows no shared event layer and the mutation is reachable. The `nomatch` proves that the privileged mutation and its durable outbox event commit atomically on this source path; it does not prove downstream dispatch, ingestion, or alerting. A direct network emit after the mutation is only partial evidence unless failure rolls the mutation back or an equally durable recovery path closes the gap.

### 2. Application audit integrity and access (`audit-log-integrity-and-access`)

Trace how application audit records obtain actor, subject, action, outcome, time, request/job identifier, and target identifiers. Security-relevant identity and time should come from authenticated server context and a controlled clock, not request fields. If impersonation is supported, preserve both the initiating and effective principal; whether identity survives another service or queue hop belongs to `cross-boundary-attribution-logging`.

Review application code for:

- request-controlled actor, role, timestamp, source address, outcome, or event type;
- ordinary update, delete, bulk-delete, truncate, or overwrite paths over audit records;
- an audit table sharing generic CRUD handlers, repositories, serializers, or admin endpoints;
- unguarded query/export access to audit data;
- failure of the audit write being swallowed while the protected action reports success;
- application-side sequence, chaining, signing, or append-only mechanisms that can be bypassed by a second writer.

Do not call a table "immutable" because the application exposes no mutation method. Database administrators, infrastructure identities, retention jobs, and deployed access policy are not consumed here. The defensible conclusion is bounded to the enumerated application paths.

```detector
match: |
  await audit.append({
    actorId: req.body.actorId,
    occurredAt: req.body.occurredAt,
    action: "invoice.exported",
    outcome: "success"
  })
nomatch: |
  await audit.append({
    actorId: req.auth.subject,
    occurredAt: clock.now(),
    action: "invoice.exported",
    outcome: "success",
    requestId: req.id
  })
```

Client-controlled context is a source-level integrity defect when it is stored as authoritative audit metadata. The `nomatch` still does not prove deployed time synchronization or storage immutability.

### 3. Detection, alerting, and escalation (`detection-alerting-and-escalation`)

Where rules or routing configuration are in the repository, map stable event identifiers to concrete abuse cases. Review:

- the event fields and values the rule actually receives, not a design-document schema;
- threshold count, unit, window, grouping dimension, exclusions, and reset behavior;
- both per-actor or per-target concentration and system-wide bursts where each matters;
- low-and-slow behavior, rule-disablement, parser failure, and telemetry-loss signals;
- severity, owner, receiver reference, escalation policy reference, runbook/playbook link, and deduplication key;
- default routes, inhibit rules, silence matchers, maintenance modes, and "null" receivers that can capture security alerts;
- a positive fixture that fires and a near-neighbor negative fixture that does not.

A committed receiver name is not evidence a human receives anything. A runbook link is not evidence the document is current or responders execute it. State only what the source-controlled rule and route express.

```detector
match: |
  route:
    routes:
      - matchers:
          - severity="critical"
        receiver: discard
  receivers:
    - name: discard
nomatch: |
  route:
    routes:
      - matchers:
          - severity="critical"
        receiver: security-primary
  receivers:
    - name: security-primary
      pagerduty_configs:
        - routing_key_file: /run/secrets/security-routing-key
```

The `match` requires graph resolution: prove that the discard route captures the relevant security alert and no later route continues. The `nomatch` establishes a source routing reference only; it does not establish that the secret exists, PagerDuty accepts the event, or on-call responds.

### 4. Security telemetry pipeline resilience (`security-telemetry-pipeline-resilience`)

Review only application-owned or source-controlled pipeline components in the repository. For synchronous exporters, asynchronous queues, collectors, and shippers, inspect:

- finite connect and operation timeouts;
- bounded retry count or deadline, backoff, jitter, and retryable-error classification;
- bounded memory and disk queues with explicit overflow behavior;
- durable buffering, dead-letter, replay, and idempotence where loss has material security impact;
- counters or structured events for dropped, rejected, expired, malformed, or permanently failed records;
- health or readiness that distinguishes the application from its telemetry dependency;
- startup behavior when configuration or rule loading fails;
- recursion protection so reporting a logging failure does not depend solely on the failed path.

Timeout, retry, backpressure, and queue bounds are traced here to determine the terminal fate of a security event. If the defect is the bound itself — an unbounded wait, retry storm, pool exhaustion, unsafe degradation, or redelivery amplification — file it under `failure-semantics-and-resilience`. This topic files the distinct outcome in which a security event is discarded, expired, corrupted, or made unrecoverable with no trustworthy loss signal or replay path.

```detector
match: |
  try {
    await telemetry.send(event)
  } catch (_) {
    // best effort
  }
nomatch: |
  try {
    await telemetryOutbox.enqueue(event, { deadlineMs: 250 })
  } catch (error) {
    telemetryHealth.increment("security_event_enqueue_failure")
    localEmergencySink.write({
      eventId: "telemetry.security_event_enqueue_failure",
      originalEventId: event.eventId
    })
  }
```

The `nomatch` is not automatically sufficient: prove the fallback is independent of the failed exporter, bounded, and safe for the data it receives. Whether either record leaves the host is a runtime question.

### 5. Security-control failure observability (`control-failure-observability`)

For each security-control adapter, enumerate at least three states:

1. the subject is evaluated and rejected;
2. the subject is evaluated and accepted;
3. the control cannot evaluate reliably because a dependency is unavailable, stale, malformed, timed out, misconfigured, or returns an unexpected result.

The third state needs a distinct event identifier, outcome, control name, safe error class, and correlation context. It must not be collapsed into an ordinary denial that teaches defenders nothing, nor into a generic application error that cannot be connected to enforcement degradation. Whether the application then fails open or closed is graded by the owning control lens; this topic grades the missing or misleading security signal.

Pay special attention to authorization policy stores, JWKS/signature material, certificate validation, session stores, rate limiters, fraud engines, revocation checks, secret managers, schema validators, and policy/rule loaders. Do not log the secret, token, raw credential, or sensitive payload that caused the failure.

```detector
match: |
  try {
    return await policyClient.isAllowed(subject, action, resource)
  } catch (_) {
    return false
  }
nomatch: |
  try {
    return await policyClient.isAllowed(subject, action, resource)
  } catch (error) {
    await securityEvents.emit("authorization.control_error", {
      subjectId: subject.id,
      action,
      resourceId: resource.id,
      errorClass: classifyPolicyError(error),
      outcome: "indeterminate"
    })
    return false
  }
```

Both examples fail closed; only one distinguishes control failure from a policy denial. The source event does not prove an operator sees or acts on it.

## Severity calibration

`severity_floor: low` suppresses no substantiated security defect at Low or above. Runtime unknowns and external-control questions are assumptions at Info, not findings promoted to meet the floor.

First grade the direct consequence of the observability defect, not the severity of an attack that merely becomes quieter. Authentication bypass, data theft, or privilege escalation remains the underlying owner's finding. `attack-chaining` may compose a proven suppression primitive with that finding; this lens does not borrow its impact.

| Condition | Claimed impact | Required evidence |
|---|---|---|
| A reachable, attacker-influenced application path can forge, rewrite, or selectively erase audit records for privileged or high-value actions, or can disable the source-visible security signal path while preserving the protected action | **High** after T1/T2 proof; otherwise **Medium** under the T0/T3 cap | The mutation/suppression path, attacker influence, affected event set, durable state or captured calls, and a sensitivity control |
| A source-controlled route provably discards the complete class of critical security alerts, or a pipeline failure deterministically and silently loses that complete class | **High** only with T1/T2 proof of the routing/loss semantics and a source-established reliance on that class; otherwise **Medium** | Parsed routing graph or failure injection, nonzero rule/event denominator, positive and negative controls; no claim of deployed delivery |
| A reachable privileged, destructive, high-value, or security-control branch lacks its required event; a control-error state is silent or indistinguishable from ordinary rejection; a security event reaches terminal drop or corruption with no trustworthy accounting or replay path | **Medium** | Denominator, reachable branch, traced absence or concrete failure branch, and the direct investigation/detection consequence |
| A covered event loses one useful but nonessential context field, a rule or escalation reference is fragile, or only a narrow low-impact event family is incomplete | **Low** | Concrete event/rule and why the remaining fields cannot reliably answer the stated investigation question |
| SIEM ingestion, production thresholds, retention, delivery, acknowledgement, on-call readiness, or playbook effectiveness cannot be verified from the repository | **Info assumption, not a finding** | State the missing evidence class and the exact artifact or owner needed to verify it |

**Critical is not a standalone source-only result from this lens.** Catastrophic business or safety impact requires a separately proven component finding and chain composition. Even then, the missing signal does not become the root cause. A source-only read is T0 and cannot exceed Medium; a High requires an executable T1/T2 oracle that proves the application behavior without claiming deployed SIEM or response behavior.

## Known false positives

1. **No event at the mutation call site.** Middleware, an ORM hook, a domain-event subscriber, a queue wrapper, or a transaction outbox may emit it elsewhere.
   **Resolve it:** trace the executed positive and negative branches through the shared layer. Do not clear it because the framework supports hooks; cite the registered hook and event.

2. **No SIEM, receiver, or retention configuration in this repository.** A separate infrastructure repository or managed service may own it.
   **Resolve it:** record a runtime/external-control assumption and the owner or artifact needed. Absence outside the source denominator is not a finding.

3. **Production filters suppress ordinary debug or info logs.** A dedicated audit sink or marker can bypass application log levels.
   **Resolve it:** trace the actual appender/filter graph for the security marker or event identifier. Generic root-level configuration neither proves nor disproves security coverage.

4. **An asynchronous SDK call appears to swallow failure.** The SDK or sidecar may durably spool, retry, and account for loss.
   **Resolve it:** follow the concrete adapter boundary and committed configuration. If resilience moves outside the repository, stop at `UNVERIFIED`.

5. **Audit records have delete or update code.** Retention expiry, legal deletion, fixture teardown, migration repair, and tightly controlled correction workflows can be legitimate.
   **Resolve it:** establish reachability, authority, selector scope, and whether the correction itself creates an attributable record. A method name alone is not an integrity finding.

6. **An alert has no runbook annotation or local receiver.** A downstream router can enrich and route it.
   **Resolve it:** treat the local gap as an assumption unless source establishes that this repository is the authoritative final route.

7. **Trace or metric sampling is enabled.** That does not prove security audit events are sampled; they may use a separate unsampled signal.
   **Resolve it:** trace the security event through sampler selection and exporter routing. Do not infer from global-looking defaults without resolving overrides.

8. **A duplicate event or noisy rule looks operationally harmful.** Production cardinality, volume, cost, false-positive rate, and responder fatigue are runtime properties.
   **Resolve it:** file only deterministic source behavior such as an unbounded loop or obviously duplicated emission on one execution. Otherwise request runtime evidence.

9. **A source rule and event schema appear to match.** Parser transformations, field dropping, index mappings, and version skew may still break them.
   **Resolve it:** source fixture tests can validate the committed transformation chain; they still do not clear deployed ingestion.

## Proof recipes

Use the repository's own test runner only through the sealed, network-denied T1 route in `_harness.md`. An accepted authenticated operator statement naming the repository and dynamic tests is launch authority without another prompt; the operator is accountable for it, and the auditor does not independently adjudicate legal authority. These repository-proof recipes consume source and controlled local execution; they do not query remote destinations, use live credentials, or infer deployed/live state. A named external observation requires a matching destination-bound controller and explicitly supplied or controller-referenced credential material, remains external evidence, and is `UNPROVEN` with a technical gap when that route or material is absent. Never infer a destination from repository configuration. Preserve exact commands, exit codes, enumerator counts, relevant output, and changed paths in the evidence ledger.

### O1 — Security-event obligation matrix (T1)

Use the shared **registry-driven enumerator** to enumerate the concrete routes, commands, consumers, policy adapters, or privileged mutations that form the denominator. Keep its committed-count assertion. For each obligation, drive at least one success, one adversarial rejection, and one control-error branch where applicable.

Attach the shared **capturing log handler** or an in-memory event-sink fake at the application's structured emitter boundary. Assert:

- exact event identifier;
- exactly-once or explicitly documented multiplicity;
- outcome and server-derived actor/subject identifiers;
- request/job correlation identifier;
- absence of the event on a near-neighbor operation that is not an obligation.

The negative control prevents "the test logger captured something" from satisfying the oracle. This recipe proves local application emission only.

### O2 — Audit provenance and application-mutation test (T1)

Use the **two-subject fixture** so the request body supplies subject A while authentication context is subject B. Execute the audited operation and assert that the stored/captured actor is B, the controlled server time is used, and request-provided actor/time fields are ignored or rejected.

Then enumerate application mutation entry points over the audit store. If a correction or deletion workflow exists, test an unauthorized subject, an authorized subject, selector scope, and creation of a correction/deletion audit record. Assert durable application state, not only an HTTP response. This does not test database-administrator or infrastructure access.

### O3 — Detection rule and routing fixture pair (T1)

Use the shared **detector-and-fixture-pair runner** against the repository's real rule parser or renderer. Supply:

- a positive security event that must match;
- a near-neighbor negative event that must not;
- a vulnerable routing fixture in which the matched alert resolves to a discard, missing, or unintended receiver;
- a clean routing fixture in which it resolves to the intended source reference.

Assert that the enumerated rule/event count is nonzero, the positive and negative fixtures discriminate, and the final source routing graph resolves as expected. This proves committed parsing and routing semantics, not production rule loading, delivery, acknowledgement, or response.

### O4 — Telemetry terminal-failure and loss-accounting proof (T1)

Replace the exporter with the shared **Counting fake provider client** and use **clock control**. Make the fake time out, return a retryable error N times, then return a permanent error. Use the repository's retry/deadline behavior to reach a terminal outcome without real sleeping, then assert that the security event is durably queued for replay or that a trustworthy, independent loss counter/event identifies the dropped event class. A broken retry bound, backoff, queue limit, or protected-operation failure mode is handed to `failure-semantics-and-resilience`; it is not a second finding here.

Capture the fallback health counter or local emergency event through a dependency independent from the failed exporter. Include a sensitivity control in which the exporter succeeds and no failure signal appears. Do not open sockets or contact a configured remote endpoint.

### O5 — Security-control error discrimination (T1)

Use a fake control dependency with three deterministic results: allow, deny, and unavailable/malformed. Attach the **capturing log handler** or event-sink fake and assert that deny and unavailable produce different stable event identifiers or typed outcomes, while both preserve the repository's intended enforcement result.

The assertion must name the control, safe error class, correlation context, and event count. A generic exception log does not satisfy the oracle if a defender cannot distinguish control degradation from an application error. This recipe proves the distinction locally; it does not prove an alert exists or anyone responds.

### O6 — Source-only audit-chain tamper oracle (T1, conditional)

Use this recipe only where the application explicitly implements sequence numbers, hashes, signatures, append-only commands, or another audit-integrity mechanism. With a disposable store, modify, remove, reorder, and duplicate one record at a time and run the repository's verifier. Include an unchanged-chain control and assert deterministic rejection of each supported tamper case.

Do not invent a universal requirement for cryptographic chaining, and do not call the result storage immutability. The proof is limited to the committed verifier and the tamper cases exercised.

### Not provable by these recipes

No local recipe proves deployed collection, time synchronization, production retention, tamper resistance against infrastructure administrators, live rule evaluation, real alert delivery, acceptable false-positive rates, page acknowledgement, on-call availability, incident declaration, escalation, containment, recovery, or playbook effectiveness. Those require the evidence class and authorization this lens explicitly does not consume.
