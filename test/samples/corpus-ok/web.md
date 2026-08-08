---
name: web-sample
title: Sample domain
runs_in: fanout
activates_on:
  paths: ["**/routes/**"]
  signals: ["express"]
  evidence_classes:
    source:
      state: not-consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
owns: [csrf]
defers:
  jwt-jws-and-jwks-verification: crypto-and-key-management
frameworks: [owasp-top-10]
severity_floor: low
---

## Scope

Owns CSRF. Does not own JWT verification.

## Checklist

- Look for state-changing POST handlers with no token check.

```detector
match: |
  app.post('/transfer', (req, res) => doTransfer(req.body))
nomatch: |
  app.post('/transfer', csrfProtection, (req, res) => doTransfer(req.body))
```

## Severity calibration

Missing CSRF on a state-changing endpoint is High.

## Known false positives

1. A POST endpoint that only reads. Not state-changing, so no CSRF exposure.

## Proof recipes

Two-subject request replay. See `_harness.md` → `route-table-enumerator`.
