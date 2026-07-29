---
name: crypto-and-key-management
title: Cryptography and key management
runs_in: fanout
activates_on:
  paths: ["**/crypto/**"]
  signals: ["cryptography"]
owns: [jwt-jws-and-jwks-verification]
defers: {}
frameworks: [cwe-top-25]
severity_floor: low
---

## Scope

Owns JWT verification.

## Checklist

- Look for tokens decoded without signature verification.

```detector
match: |
  jwt.decode(token, options={"verify_signature": False})
nomatch: |
  jwt.decode(token, key, algorithms=["RS256"])
```
