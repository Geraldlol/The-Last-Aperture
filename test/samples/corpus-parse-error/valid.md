---
name: parse-error-sample
title: Parse error sample domain
runs_in: fanout
activates_on:
  paths: ["**/parse-sample/**"]
  signals: ["parse-sample"]
  evidence_classes:
    source:
      state: not-consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
owns: [parse-sample-slug]
defers: {}
frameworks: [owasp-top-10]
severity_floor: low
---

## Scope

Owns a single sample slug used to prove that one malformed sibling file does
not abort the rest of the lint run.

## Checklist

- Look for the sample unsafe call.

```detector
match: |
  doSomethingUnsafe()
nomatch: |
  doSomethingSafe()
```
