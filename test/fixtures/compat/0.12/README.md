# 0.12 compatibility fixtures

`native-interaction-contract-1.0.0.json` was emitted by
`buildNativeInteractionContract` at commit `c2a2903` from a generic sanitized
HAR fixture. It preserves the released 1.0 wire shape and is not a current
contract with its version changed after generation.

`native-interaction-contract-1.0.0-retired-auth-semantics.json` was emitted by
the same builder from a sanitized HAR observation that exercises a historical
application-specific authentication route. It verifies read compatibility for
the released 1.0 semantic classifications without restoring that route to the
current target-neutral classifier. It ships only as regression input; current
classification never consumes it.

The two `web-session-evidence-1.0.0-*-cookie-carrier.json` files were emitted
by the `c2a2903` builder from sanitized, single-cookie HAR observations. They
cover both directions in which the target-neutral cookie heuristic later
changed. They verify exact read compatibility through the frozen 1.0 carrier
classifier. Those historical rules are selected only while validating schema
1.0 evidence and contracts. New imports and contracts emit schema 1.1 and use
the current target-neutral rules. These regression fixtures ship with the test
suite.
