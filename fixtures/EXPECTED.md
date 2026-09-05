# EXPECTED.md — the fixture manifest

This is what makes `fixtures/` an evaluation rather than a wish list. Every
vulnerable fixture names the lens that should catch it **and the specific severity
row or checklist item that should fire**, and every row records what happened when
that lens's own sweep was actually run against the file.

**The rule that governs this file: a fixture the lens misses is recorded as a
known gap, not tuned until it matches.** A corpus adjusted to make a lens look
good measures the corpus. Two unresolved gaps are recorded below; the two closed
entries remain as history, and neither was closed by editing a fixture.

Measured 2026-07-27 against `HEAD = bcd066b` (Phase B core). Re-run with the
commands quoted per fixture; each one is copied from its owning lens's §0 sweep
block or from the named artifact in its severity row.

V-016 and C-034 (the Bicep pair) were measured the same day against the **working
tree**, not against that commit: they exist because `cloud-and-iac` had named Bicep
in `activates_on.paths` while every detector and all four absence helpers read only
`*.tf` and `*.y*ml`, and they were added in the same change as the `bicep_absent` /
`bicep_count` helpers they exercise.

Re-measured 2026-07-28 against pre-edit `HEAD = 09eb0a7`: the Bicep helpers and
the lens's Terraform positive encryption sweep discriminate in both directions.
The exact results are recorded under V-016 below. The sentinel grep's first
vulnerable hit is an explanatory comment, so an exit code alone is insufficient;
the re-run also asserted the executable property lines at `:98-99`.

---

## Environment facts every re-run has to get right

All three were measured while running the sweeps, and each one makes an empty
result mean something other than "clean".

1. **`rg` here is a shell function, not a binary on `PATH`.** The first run of the
   vulnerable half returned **exit 127 on every line** — "command not found" — and all
   sixteen `ai-generated-code` sweeps reported `rc=127 NO VERDICT` on the clean half,
   which is that lens's own §0 environment note reproducing itself verbatim. A sweep run
   in a child shell (`bash sweep.sh`) exits 127 and finds nothing. An unguarded
   `|| echo clean` would have read all of those as clean results. Branch on the exit
   status explicitly: **0 = matched, 1 = ran and matched nothing, anything else = the
   sweep did not run and its silence means nothing.** The self-check that caught it — a
   string known to be in the corpus, which *must* match — is the first thing to run.

2. **A glob containing `/` is anchored to the search root.** `--glob 'force-app/**/*.cls'`
   and `--glob '.github/workflows/*.y*ml'` returned **exit 1, no stderr** against a corpus
   nested under `fixtures/` — indistinguishable from "this repository has no Apex and no
   workflows". Measured: 0 hits on a tree provably containing 6.

   **This is now fixed in the lenses, not worked around here.** All 20 `force-app` globs in
   `salesforce-platform` — 13 when this was first measured, and every glob added since has
   kept the prefix — and all 15 workflow globs in `cicd-and-supply-chain` are
   `**/`-prefixed, which matches at the root *and* nested (both verified). Re-count with
   `grep -o -- "--glob '\*\*/force-app[^']*'" … | wc -l` against
   `grep -o -- "--glob 'force-app[^']*'" … | wc -l`, which must be zero. The fix matters
   well beyond the corpus: the old form silently cleared any real repository whose Salesforce
   project or checkout is not at the scan root. V-009 and V-012 remain laid out under a
   simulated repository root, which is how both lenses say to run them.

3. **A brace-alternate glob survives `rg` and dies silently under `grep`.** Fact 1 forces
   `grep` as the fallback; `grep --include` has no brace expansion, so an
   `--include='{profiles,permissionsets}/*'` searches **zero files** and exits 1 with nothing
   on stderr. Measured on V-013 in both spellings: exit 1 against a directory provably
   containing two matching permission sets, while the same run under `rg` exits 0 with four
   hits. Any sweep in any lens written with a `{a,b}` glob is therefore engine-dependent, and
   the failure is in the clearing direction. **Fixed in `salesforce-platform`, not worked
   around here** — both of its permission-grant sweeps now use a repeated `--glob` per
   metadata suffix, which transliterates to repeated `--include` one-for-one, and the lens
   states why so the shorter form is not restored. **Not fixed elsewhere, and counted so it is
   not lost:** `grep -c -o -- "--glob '[^']*{" *.md` over the lens directory reports 4 brace
   globs in `mobile-app-security` and 4 in `web-and-api`. Those files were not touched by the
   task that produced this note. Each needs the same treatment or the same check.

## Manifest

| ID | Fixture | Language | Bug class (one per file) | Expected severity | CWE | Owning lens / topic | The row or item that should fire | Detection |
|---|---|---|---|---|---|---|---|---|
| V-001 | `vulnerable/order_notes_route.ts` | TypeScript (Express) | Object-level authorization missing on a mutating route (BOLA) | Critical | CWE-639 | `web-and-api` / `authz-object-level` | Severity table `:2474` "Object-level authorization missing on a mutating or exporting route → Critical"; item 1's "check the write, bulk and export paths separately from the read path" | **CAUGHT** |
| V-002 | `vulnerable/LedgerReportDao.java` | Java (JDBC) | SQL injection — caller text concatenated into a query string | Critical | CWE-89 | `web-and-api` / `injection-sql-nosql-orm` | Severity table `:2478` "Injection with caller-controlled input reaching the query → Critical"; item 13's "String building into a driver call" | **CAUGHT** (known gap 1 closed 2026-07-27) |
| V-003 | `vulnerable/jwt_session_middleware.go` | Go (golang-jwt v5) | JWT verification with no algorithm constraint | Critical | CWE-347 | `crypto-and-key-management` / `jwt-jws-and-jwks-verification` | Severity row "`alg: none` accepted, or an algorithm list mixing symmetric and asymmetric → Critical", the Go clause: "a `jwt.Parse` / `jwt.ParseWithClaims` whose keyfunc hands back key material without inspecting the token's method and with no `WithValidMethods`" | **CAUGHT** (positive + absence sweep) |
| V-004 | `vulnerable/support_triage_agent.py` | Python (agent framework) | Indirect prompt injection into a context holding an outbound-transmit tool | Critical | CWE-1427 | `llm-and-ai` / `prompt-injection` | Severity row "A tool can transmit to a model-selected external recipient with no server-side approval record read before execution → Critical"; item 3's three-question sequence and its first `match` detector | **CAUGHT** |
| V-005 | `vulnerable/SessionSealer.cs` | C# (.NET) | Unauthenticated ciphertext — nothing authenticates the encrypt/decrypt path | Critical | CWE-353 | `crypto-and-key-management` / `symmetric-encryption-and-nonce-handling` | Severity row "Unauthenticated ciphertext — no MAC anywhere on the encrypt/decrypt path → Critical", the `.NET bare Aes.Create()` clause; item 3's first bullet | **CAUGHT** (absence sweep) |
| V-006 | `vulnerable/settings_signing.py` | Python | Hardcoded credential — literal default applied when the variable is unset | High | CWE-798 | `crypto-and-key-management` / `hardcoded-credentials-and-key-material` | Severity row "Secret literal as an environment-variable fallback → High"; item 14's two-argument `os.environ.get` candidate (with Go separately described as `os.Getenv` followed by a nearby empty check and literal assignment) | **CAUGHT** (§0 sweep added 2026-07-28; known gap 2 closed) |
| V-007 | `vulnerable/link_preview_service.js` | JavaScript (Node) | SSRF whose destination reaches the instance-metadata service | Critical | CWE-918 | `web-and-api` / `ssrf-application-path` | Severity table `:2480` "SSRF where the destination reaches a metadata endpoint or an internal service → Critical", on three of its listed conditions: hand-written deny-list omitting the metadata addresses, validate-then-reresolve gap, redirects followed | **CAUGHT** (as a candidate) |
| V-008 | `vulnerable/session_restore.rb` | Ruby (Rack-shaped) | Unsafe deserialization of request-controlled bytes | Critical | CWE-502 | `web-and-api` / `deserialization-and-xxe` | Severity table `:2479` "Remote code execution through deserialization of request-controlled bytes → Critical", `Marshal.load` on its unconditional-sink list | **CAUGHT** |
| V-009 | `vulnerable/.github/workflows/pr-preview.yml` | YAML (GitHub Actions) | Privileged trigger executing pull-request-controlled content | Critical | CWE-829 | `cicd-and-supply-chain` / `workflow-trigger-and-script-injection` | Severity row "Privileged trigger executing pull-request-controlled content → Critical"; item 1a's two legs, and its rule that no `secrets.*` reference is required | **CAUGHT** (both legs) |
| V-010 | `vulnerable/reporting_database.tf` | HCL (Terraform) | Encryption at rest explicitly disabled | High | CWE-311 | `cloud-and-iac` / `encryption-at-rest-configuration` | Severity row "Explicitly disabled encryption on a store that supports disabling it → High", establishing artifact `storage_encrypted = false` | **CAUGHT** |
| V-011 | `vulnerable/TokenStore.kt` | Kotlin (Android) | Refresh token in an unencrypted local store | High | CWE-312 | `mobile-app-security` / `mobile-local-data-storage` | Severity row "Session token, refresh token, encryption key, or regulated data in an unencrypted local store → High"; false-positive entry 2's discriminator — the store is fine, the value is not | **CAUGHT** (and the safe-store list correctly does not clear it) |
| V-012 | `vulnerable/force-app/main/default/classes/InvoiceExportController.cls` | Apex | Record-level sharing bypass at an `@AuraEnabled` entry point | High | CWE-862 | `salesforce-platform` / `apex-sharing-declaration` | Severity row "`@AuraEnabled` on a `without sharing` class returning SObjects → High", plus its OWD condition, satisfied by the `<sharingModel>Private</sharingModel>` in the supporting object metadata | **CAUGHT** |

| V-013 | `vulnerable/sf_permset_view_all_fields/force-app/main/default/permissionsets/Care_Coordination_Team.permissionset-meta.xml` | Salesforce metadata (permission set) | FLS bypass through an over-broad declarative grant — `viewAllFields` on the object | High | CWE-732 | `salesforce-platform` / `permission-set-and-profile-grants` | Severity row "`viewAllFields` granted on an object → High", which carries **no** OWD condition; §0's system-permission sweep, whose pattern now names `viewAllFields` alongside the two sharing elements. The adjacent row's `ReadWrite` downgrade must not reach it, and the supporting `<sharingModel>ReadWrite</sharingModel>` is what proves it does not | **CAUGHT** (and would have been graded **Low** by the row as it stood — see the block below) |

| V-014 | `vulnerable/WebhookSignatureEquals.cls` | Apex | Timing-unsafe comparison of an attacker-supplied webhook signature | High | CWE-208 | `crypto-and-key-management` / `hmac-and-constant-time-comparison` | Severity row "Timing-unsafe comparison of an attacker-supplied MAC, signature, API key, TOTP code or reset token → High", on the **Apex clause added 2026-07-27**: a `.cls` comparing a request signature with `!=` and calling neither `Crypto.areEqualConstantTime` nor a verified project-local constant-time helper whose body has been read. All four re-grade conditions are in file — header-supplied operand, comparison against a server-computed MAC, no attempt cap in the class or in front of it, attacker-steerable operand | **CAUGHT** three independent ways — see the block below |

| V-015 | `vulnerable/agent_autopush_runner.py` | Python (agent CLI runner) | An autonomous agent's write-out gate is bound to one flag while a different flag combination reaches the same commit-and-push path | Critical | CWE-863 | `llm-and-ai` / `tool-call-authority-and-mediation` | Severity row "An autonomous coding agent bearing an Edit/Write/Bash/git tool set runs unattended over a checkout that is the deployed tree, holds a push-capable remote, or exposes the calling process's credentials to its shell, and its only gate is a permission mode or auto-approve flag … → Critical", with the mechanism row "The gate … is bound to one flag, mode or variable while a different flag combination reaches the same write, commit, push or deploy path → High"; item 16 and both of its detectors | **CAUGHT by the §0 arm (b) added 2026-07-27; every sweep in the block that predates it is blind to the file — see the block below** |

| V-016 | `vulnerable/azure_public_data_plane.bicep` | Bicep (Azure) | **Chain fixture, declared as one.** A managed data plane reachable from the public internet — `publicNetworkAccess: 'Enabled'` plus the `0.0.0.0`–`0.0.0.0` firewall sentinel — in a deployment that contains no diagnostic setting of any kind, so nothing records who used it | Critical (leg 1) + High (leg 2) | CWE-1327 (leg 1), CWE-778 (leg 2) | `cloud-and-iac` / `network-exposure-and-segmentation` + `control-plane-audit-logging` | Severity row "Managed database reachable from the internet → Critical", on the **Bicep clause added 2026-07-27** (`properties.network.publicNetworkAccess: 'Enabled'` paired with a `…/firewallRules` child whose `startIpAddress` and `endIpAddress` are both `'0.0.0.0'`); the new "Azure PaaS data plane reachable from the internet → High, Critical on a vault" row for the Key Vault; and "No control-plane audit trail → High" on its Bicep clause, `diag: 0` beside a non-zero `stores:` | **CAUGHT after the lens edit; every sweep that predates it reported the file clean — measured both ways in the block below** |

| V-017 | `vulnerable/database/sqlserver_rls_cdc_export.sql` | T-SQL (SQL Server) | A row-filtered source is copied into an unfiltered CDC view granted to the bulk-export principal | High | CWE-639 | `database-and-data-stores` / `database-native-authorization-and-tenant-isolation` + `database-replication-cdc-history-and-sharing` | Severity row "CDC, stream, history, replica, backup or export identity has unnecessary bulk-read authority"; checklist 7's requirement to test copy paths independently of the source policy | **CAUGHT** by the syntax-aware pair assertion in `test/database-fixtures.test.mjs` |
| V-018 | `vulnerable/database/mysql_definer_updatable_view.sql` | SQL (MySQL) | A writable `SQL SECURITY DEFINER` tenant view omits `CHECK OPTION`, permitting writes outside its read predicate | High | CWE-269 | `database-and-data-stores` / `database-privileged-code-and-execution-context` | Checklist 3's separate evaluation of definer context, write behavior, direct base-object authority, and view check options | **CAUGHT** by the syntax-aware pair assertion in `test/database-fixtures.test.mjs` |
| V-019 | `vulnerable/database/mongodb_additive_roles.json` | JSON (MongoDB role model) | A restricted tenant-view role is combined with a role that can read the source collection directly | High | CWE-863 | `database-and-data-stores` / `database-native-authorization-and-tenant-isolation` | Checklist 1–2's effective-role expansion and alternate native read-path matrix | **CAUGHT** by the parsed-role pair assertion in `test/database-fixtures.test.mjs` |
| V-020 | `vulnerable/database/redis_broad_acl.acl` | Redis ACL | The unauthenticated default user and application user can access every key, channel, and command, including administration | Critical | CWE-732 | `database-and-data-stores` / `database-native-authorization-and-tenant-isolation` + `database-resource-governance-and-availability` | Checklist 1–2's effective command/key/channel scope and checklist 5's administrative resource-control boundary | **CAUGHT** by the parsed-ACL pair assertion in `test/database-fixtures.test.mjs` |
| V-021 | `vulnerable/database/firestore_auth_only.rules` | Firestore rules | Authentication alone grants get, list, create, and update while `tenantId` and `admin` remain caller-mutable | High | CWE-639 | `database-and-data-stores` / `database-native-authorization-and-tenant-isolation` | Checklist 2's requirement to test get/list/write separately and preserve immutable tenant and privilege-bearing fields | **CAUGHT** by the operation-aware rules pair assertion in `test/database-fixtures.test.mjs` |
| V-022 | `vulnerable/database/elastic_role_union.json` | JSON (Elasticsearch security model) | An unrestricted secondary role defeats DLS/FLS on the same index while a filtered alias creates a false boundary | High | CWE-863 | `database-and-data-stores` / `database-native-authorization-and-tenant-isolation` | Checklist 1–2's effective-policy expansion across every assigned role and direct backing-index path | **CAUGHT** by the parsed effective-role pair assertion in `test/database-fixtures.test.mjs` |

| V-023 | `vulnerable/training_dataset.py` | Python (model training) | A moving training-data URI reaches the trainer without immutable identity or integrity admission | Medium | CWE-345 | `ai-model-and-mlops-security` / `training-data-provenance-and-integrity` | Checklist 1's detector requires a signed manifest, immutable URI, digest verification, and a fail-closed poisoning-policy result before the trainer boundary | **CAUGHT** by the owning detector's exact match fixture in `test/benchmark-lens-pairs.test.mjs` |
| V-024 | `vulnerable/failure_policy.py` | Python | Authorization-service failure returns an allow decision | High | CWE-636 | `failure-semantics-and-resilience` / `security-control-failure-mode` | Checklist 1's fail-open detector and severity row for a security-control error permitting an unauthorized high-impact action | **CAUGHT** by the owning detector's exact match fixture in `test/benchmark-lens-pairs.test.mjs` |
| V-025 | `vulnerable/native_frame.c` | C | A narrowed allocation length is followed by a copy using the original wider length | High | CWE-681 | `native-and-memory-safety` / `memory-bounds-and-integer-conversion` | Checklist 1's canonical-length detector; allocation and access do not share one representable, validated size | **CAUGHT** by the owning detector's exact match fixture in `test/benchmark-lens-pairs.test.mjs` |
| V-026 | `vulnerable/patient_chart_audit.py` | Python | A pooled service identity makes the acting human unrecoverable from ePHI-read audit records | High | CWE-778 | `hipaa-and-phi` / `phi-access-audit-controls` | Checklist 2's unique-user-identification detector and the High severity row for acting-human identity unrecoverable from every ePHI-access record | **CAUGHT** by the owning detector's exact match fixture in `test/benchmark-lens-pairs.test.mjs` |
| V-027 | `vulnerable/privacy_consent.py` | Python (Django forms) | Marketing consent is pre-selected rather than obtained by affirmative action | Medium | CWE-359 | `privacy-and-data-protection` / `lawful-basis-and-consent-capture` | Checklist 2's pre-ticked-control detector and the Medium severity row for default-on consent | **CAUGHT** by the owning detector's exact match fixture in `test/benchmark-lens-pairs.test.mjs` |
| V-028 | `vulnerable/security_grant.ts` | TypeScript | A privileged role grant commits with no durable attributed security event | Medium | CWE-778 | `security-observability-and-response` / `security-event-coverage` | Checklist 1's privileged-mutation detector and the Medium severity row for a reachable privileged branch lacking its required event | **CAUGHT** by the owning detector's exact match fixture in `test/benchmark-lens-pairs.test.mjs` |
| V-029 | `vulnerable/internal_identity.py` | Python (ASGI middleware) | Network position is promoted to service identity at a trust crossing | High | CWE-290 | `threat-modeling` / `architecture-trust-design-gaps` | Checklist 8's network-position trust detector and the High claimed-impact row for trust derived from position at a crossing | **CAUGHT** by the owning detector's exact match fixture in `test/benchmark-lens-pairs.test.mjs` |
| V-030 | `vulnerable/device_enrollment.py` | Python (device gateway) | A shared default credential and public serial number authorize device owner binding | Medium | CWE-1392 | `embedded-iot-ot-security` / `device-identity-and-secure-onboarding` | Checklist 1's shared-default enrollment detector and the Medium source-only boundary row | **CAUGHT** by the owning detector's exact match fixture in `test/benchmark-lens-pairs.test.mjs` |
| V-031 | `vulnerable/desktop_update.js` | JavaScript (Electron updater) | A settings-controlled feed reaches the updater without signed metadata, a version floor, or an expected payload digest | Medium | CWE-494 | `desktop-and-thick-client-security` / `desktop-update-authenticity-and-rollback` | Checklist 2's update-admission detector and the Medium row for a source-visible but artifact-unverified update boundary | **CAUGHT** by the owning detector's exact match fixture in `test/benchmark-lens-pairs.test.mjs` |
| V-032 | `vulnerable/AssetSweep.sol` | Solidity | `tx.origin` authorizes a complete token sweep to a caller-selected destination | Medium | CWE-346 | `smart-contract-and-web3-security` / `contract-access-control-and-privileged-roles` | Checklist 1's on-chain authorization detector and the Medium row where code is clear but deployment and asset state are unknown | **CAUGHT** by the owning detector's exact match fixture in `test/benchmark-lens-pairs.test.mjs` |

**All 32 vulnerable fixtures have an executable local discrimination assertion or are found by their owning lens's sweep machinery.**

`vulnerable/force-app/main/default/objects/Invoice__c/Invoice__c.object-meta.xml`
is a supporting artifact for V-012, not a fixture: it exists only so V-012's
severity row can be graded on its stated condition rather than on a missing file.
It carries no defect of its own.

`vulnerable/sf_permset_view_all_fields/` holds three files in the same position
relative to V-013, and none of the three is counted as a fixture:
`objects/Care_Episode__c/Care_Episode__c.object-meta.xml` supplies the
`<sharingModel>ReadWrite</sharingModel>` the grade turns on,
`objects/Care_Episode__c/fields/Clinical_Note__c.field-meta.xml` is the field no
`<fieldPermissions>` entry grants, and
`permissionsets/Care_Episode_Reporting.permissionset-meta.xml` is the **clean
counterpart** — the same grant with `<viewAllFields>false</viewAllFields>`, where
the OWD downgrade applies legitimately.

**Why the counterpart is not in `clean/`, stated rather than fudged.** The rule for
that directory is zero findings at Low or above, and this file's *correct* grade is
exactly Low: an over-broad `viewAllRecords`/`modifyAllRecords` grant on a
`ReadWrite` object, reported as hardening. Putting it in `clean/` would either
break that rule or require pretending the grant is invisible. It is therefore kept
beside the fixture it discriminates against, which is where it is useful anyway —
the pair is the measurement, and a rule that grades both files alike is either the
old wrong clearance (both Low) or a new false positive (both High). This is the
same incompatibility already recorded for `salesforce-platform`'s false-positive
entry 1 at the bottom of this file, and it is the second instance of it.

---

## Per-fixture detection detail

Each block quotes the command as run and the result. `exit` is the raw status.

### V-001 — CAUGHT

```
rg -n 'findByPk\(|findById\(|\.get\(pk=|objects\.get\(id=|getById\(|findOne\(\{ ?_?id' fixtures/vulnerable/order_notes_route.ts
  → exit 0, hits at :21 :53 :69
rg -n 'req\.params\.|req\.query\.|request\.args\.|request\.GET\.|params\[:' fixtures/vulnerable/order_notes_route.ts
  → exit 0, hits at :39 :53
```

Both halves of item 0's "the BOLA shape" pair fire, on the unscoped `findByPk`
lines and on the request source. The topic is detected.

**Secondary observation, not a gap in the topic detector.** The route-inventory
sweep in the same block —
`rg -n --glob '**/*.{ts,js,mjs}' 'app\.(use|get|post|put|patch|delete)\(|router\.(get|post|put|patch|delete)\('`
— returned **exit 1** on this fixture, because its router is bound to
`const orders = Router()` and the pattern is keyed to the identifiers `app.` and
`router.`. Verified in both directions: the same three routes renamed to `router.`
match at once. Multi-router Express applications routinely name a router after its
resource, so this sweep under-reports route inventory in exactly those codebases.
It does not affect V-001's grade — the BOLA sweep found the defect — and it is
recorded because a route table the auditor never enumerated is where a missing
guard hides.

### V-002 — CAUGHT (was known gap 1; sweep added 2026-07-27)

```
rg -n 'execute\(f"|execute\("[^"]*"\s*[%+]|query\(`[^`]*\$\{|\.raw\(|createQuery\("[^"]*"\s*\+|cursor\.execute\(.*%\s*\(' fixtures/vulnerable/LedgerReportDao.java
  → exit 1  (ran, matched nothing)
rg -n --glob '**/*.{java,kt}' '@(Get|Post|Put|Patch|Delete|Request)Mapping|SecurityFilterChain' fixtures/vulnerable
  → exit 1
rg -n 'String\.format|createQuery|\$queryRawUnsafe|\$executeRawUnsafe|\.extra\(where|\.raw\(|RawSQL|text\(|find_by_sql|Arel\.sql|sequelize\.query|Sequelize\.literal|whereRaw|orderByRaw|FromSqlRaw|FromSqlInterpolated' fixtures/vulnerable/LedgerReportDao.java
  → exit 1   ← every literal item 13 names, and none of them matches
rg -n 'createStatement|executeQuery|String sql' fixtures/vulnerable/LedgerReportDao.java
  → exit 0, hits at :54 :61 :62 :79 :81 :82
```

See **Known gap 1** below.

### V-003 — CAUGHT

```
rg -n 'jwt\.decode\(|jwt\.verify\(|jwt\.Parse|…|decodeJwt\(' fixtures/vulnerable/jwt_session_middleware.go
  → exit 0, hit at :62 (jwt.ParseWithClaims)
rg --files-with-matches 'jwt\.Parse|jwt\.NewParser\(|ParseFromRequest\(' fixtures/vulnerable   → exit 0
  then, per the lens's own loop:
  rg -q 'WithValidMethods|SigningMethodHMAC|SigningMethodRSA|SigningMethodECDSA|SigningMethodEd|token\.Method|\.Method\.\(' "$f" || printf '%s\n' "$f"
  → FLAGGED fixtures/vulnerable/jwt_session_middleware.go
```

The absence sweep is the one that matters here and it fires. Note the parser
spelling: `jwt\.Parse` with no closing paren is what reaches `ParseWithClaims`, and
the lens says so explicitly — a pattern written `jwt\.Parse\(` would have missed
this fixture entirely.

### V-004 — CAUGHT

```
rg -n 'AgentExecutor\(|create_react_agent\(|createReactAgent\(|…|StateGraph\(' fixtures/vulnerable
  → exit 0, hits at :34 :84
rg -n '@tool\b|@mcp\.tool|…|(server|mcp)\.registerTool\(' fixtures/vulnerable/support_triage_agent.py
  → exit 0, hits at :49 :55 :66 :86  (all three tools enumerated, plus the tools= list)
rg -n 'max_iterations|recursion_limit|max_execution_time|maxSteps|stopWhen' fixtures/vulnerable/support_triage_agent.py
  → exit 1  ← the ABSENCE the lens says to read: no iteration bound on the turn
```

The tool sweep enumerates all three tools, which is what item 5 needs to grade the
capability, and the bounds sweep correctly reports the absence rather than a hit.

### V-005 — CAUGHT

```
rg -n 'createCipheriv\(|…|Aes\.Create\(|…' fixtures/vulnerable/SessionSealer.cs
  → exit 0, hits at :50 :71
rg -i --files-with-matches 'modes\.CBC\(|…|Aes\.Create\(' fixtures/vulnerable   → exit 0
  then, per the lens's own loop:
  rg -i -q 'hmac|poly1305|(?-i:GCM|Gcm|gcm)|aead|fernet|\bSIV\b|AESSIV|[-_]SIV\b|encrypt_then|MessageEncryptor' "$f" || printf '%s\n' "$f"
  → FLAGGED fixtures/vulnerable/SessionSealer.cs
```

The `-sive` defect the Phase A punch list flagged at crypto `:176` is fixed in the
lens at `HEAD`: the safe list now carries `\bSIV\b|AESSIV|[-_]SIV\b` rather than a
bare case-insensitive `siv`, so a file containing *responsive* or *massive* is no
longer cleared. This fixture does not exercise that specific regression; the
clean-half corpus is where an `-sive` word belongs.

### V-006 — CAUGHT (§0 sweep added 2026-07-28; known gap 2 closed)

```
rg -n 'BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY' fixtures/vulnerable/settings_signing.py   → exit 1
rg -n 'sk-ant-|sk-[A-Za-z0-9]{20,}|A(KIA|SIA)[0-9A-Z]{16}|gh[oprsu]_|github_pat_|xox[abpr]-|…service_account' fixtures/vulnerable/settings_signing.py   → exit 1
rg -n --hidden '(?i)os\.(environ\.get|getenv)\([^,\n]+,\s*[\x22\x27][^\x22\x27\n]+[\x22\x27]|process\.env\.[A-Za-z_][A-Za-z0-9_]*\s*(\|\||\?\?)\s*[\x22\x27][^\x22\x27\n]+[\x22\x27]|…' fixtures/vulnerable/settings_signing.py
  → exit 0, hits at :31 :36 :40
```

The two §0 key-material sweeps return nothing, **and that is correct** — this
fixture contains no PEM block and no provider-shaped token, because the corpus
rule forbids shipping one. The new §0 fallback inventory fires on all three
deployed defaults. It also returns candidate lines in the clean corpus where
environment fallbacks configure a checkout path or a read-only agent command;
those are correctly cleared by reading the non-secret binding and deployed
capability, rather than by treating every fallback as a credential. See
**Closed gap 2** and **Lens observation B**.

### V-007 — CAUGHT (as a candidate)

```
rg -n 'fetch\(|axios\.(get|post)\(|requests\.(get|post)\(|httpx\.|http\.Get\(|HttpClient|urlopen\(' fixtures/vulnerable/link_preview_service.js
  → exit 0, hit at :62
```

This sweep finds the outbound call, not the defect — which is what item 0 says it
is for ("every hit is a candidate to trace, not a finding"). The grade then comes
from reading the validation, which is in the same function and quotable. Recorded
as CAUGHT with that qualification: the lens gets the auditor to the line, and the
severity row's conditions are all satisfiable from what is there.

### V-008 — CAUGHT

```
rg -n 'pickle\.loads?\(|yaml\.load\(|readObject\(|BinaryFormatter|Marshal\.load|unserialize\(|JsonConvert\.DeserializeObject<object>' fixtures/vulnerable/session_restore.rb
  → exit 0, hit at :46 (plus two header-comment lines)
```

`Marshal.load` is on the severity row's unconditional list, so no manifest read is
needed — which is the property this fixture was chosen to exercise. The
version-conditional siblings (`yaml.load`, `BinaryFormatter`) are deliberately not
in this corpus: grading them needs a `Gemfile.lock` or a `<TargetFramework>`, and a
fixture that cannot supply one tests the auditor's guesswork instead of the lens.

### V-009 — CAUGHT (run from `fixtures/vulnerable/`)

```
file-set self-check (mandatory per cicd §0):
  .github/workflows/**   1 file
  .github/**             1 file
rg -n --hidden --glob '.github/workflows/*.y*ml' 'pull_request_target|pull_request_review|workflow_run|issue_comment|discussion_comment|^\s*issues:' .
  → exit 0, hit at :31   (leg 1)
rg -n --hidden --glob '.github/workflows/*.y*ml' -e 'ref:\s*\$\{\{' -e 'head\.sha|head\.ref|head_sha|head_branch' -e 'refs/pull/' -e 'gh pr checkout' -e … .
  → exit 0, hit at :42   (leg 2)
mutable-ref sweep, stage 2:  → exit 1   (every ref is digest-pinned, as intended)
```

Both legs fire and nothing else does. The fixture carries **no** `secrets.*`, no
`permissions:` block and no `persist-credentials: true`, so it also confirms the
rule item 1a states in as many words: the finding does not need a third leg. A
detector that required one would clear this file.

### V-010 — CAUGHT

```
rg -n 'storage_encrypted\s*=\s*false|\bencrypted\s*=\s*false|at_rest_encryption_enabled\s*=\s*false|transit_encryption_enabled\s*=\s*false|StorageEncrypted:\s*false' fixtures/vulnerable/reporting_database.tf
  → exit 0, hits at :46 :65
rg -n '0\.0\.0\.0/0|::/0|publicly_accessible\s*=\s*true|PubliclyAccessible' fixtures/vulnerable/reporting_database.tf
  → exit 1   ← confirms the fixture carries one bug class and not two
```

The `tf_absent` / `tf_count` helpers are not the right instrument here and were not
run: this defect is a written-out `false`, not an absent block, so the positive
sweep is the lens's own named discovery step for it.

### V-011 — CAUGHT

```
rg -ni --glob '!**/node_modules/**' -e 'AsyncStorage\.(setItem|…)' -e 'new MMKV\(' -e 'UserDefaults|…' -e 'getSharedPreferences\(|: *SharedPreferences|\.edit\s*[({]|putString\(' -e 'openDatabase|…' fixtures/vulnerable/TokenStore.kt
  → exit 0, hits at :39 :40 :51 :52 :53 :65
rg -ni -e 'SecureStore\.setItemAsync|…' -e 'EncryptedSharedPreferences|MasterKey\.Builder|KeyGenParameterSpec|EncryptedFile' -e 'kSecAttrAccessible|…|encryptionKey' fixtures/vulnerable/TokenStore.kt
  → exit 1   ← the safe-store list correctly does not clear this file
```

Both directions behave: the store sweep finds the write, and the secure-store
sweep — which exists so the auditor can see what was *not* used — stays silent.

### V-012 — CAUGHT (run from `fixtures/vulnerable/`)

```
rg -n --glob 'force-app/**/*.cls' '@AuraEnabled|@RestResource|@InvocableMethod|webservice static' .
  → exit 0, hits at :29 :46
rg -n --glob 'force-app/**/*.cls' 'without sharing' .
  → exit 0, hit at :25
rg -n --glob 'force-app/**/objects/**' '<sharingModel>|<externalSharingModel>' .
  → exit 0, hits at :22 :23   (the OWD condition the severity row requires)
rg -n --glob 'force-app/**/*.cls' 'Database\.query\(|Database\.getQueryLocator\(|Search\.query\(' .     → exit 1
rg -n --glob 'force-app/**/*.cls' "\.put\('|OwnerId\s*=|RecordTypeId\s*=|JSON\.deserialize\(|…" .        → exit 1
```

Entry point, declaration and OWD all establish from the corpus, so the row grades
at its stated High rather than at a fallback. The two "must not hit" sweeps confirm
the fixture carries no injection and no write-side escalation.

### V-013 — CAUGHT after the lens edit; measured BEFORE and AFTER, and the before is the point

Measured 2026-07-27. `rg` on this machine is a **shell function**, re-verified here
by `type rg` before any result was trusted, and every run below was preceded by a
self-check on a string read by eye out of the fixture (`rg -n 'viewAllFields'` →
exit 0, 9 hits). Paths are relative to the repository root.

**BEFORE — the two §0 sweeps as they stood, both with `{profiles,permissionsets}`
brace globs.**

```
rg -n --glob '**/force-app/**/{profiles,permissionsets}/*' '<(viewAllRecords|modifyAllRecords)>true</' .
  → exit 0, hits at Care_Coordination_Team :44 :47 and Care_Episode_Reporting :40 :43
    ← NOTE WHAT IS NOT IN THAT OUTPUT: no viewAllFields line, on either file.
      An auditor grading from the sweep sees two identical-looking permission sets
      whose object OWD is ReadWrite, applies the downgrade, and files both at Low.
      That is the wrong clearance, produced by a sweep that ran correctly.
grep -rnE --include='{profiles,permissionsets}/*' '<(viewAllRecords|modifyAllRecords)>true</' .
  → exit 1, no stderr   ← grep --include has no brace expansion. Zero files were
    searched and the result is indistinguishable from a clean org.
grep -rnE --include='*{profile,permissionset}*' '…' .
  → exit 1   (second brace spelling, same silence)
rg -n --glob '**/force-app/**/{profiles,permissionsets,permissionsetgroups}/*' '<name>(ViewAllData|…)</name>' .
  → exit 1   (correct — there is no system permission in this fixture)
```

**AFTER — the same two sweeps, repeated `--glob` on the metadata suffix.**

```
rg -n --glob '**/force-app/**/*.profile-meta.xml' --glob '**/force-app/**/*.permissionset-meta.xml' '<(viewAllFields|viewAllRecords|modifyAllRecords)>true</' fixtures/vulnerable/sf_permset_view_all_fields
  → exit 0, hits at Care_Coordination_Team :10 :44 :46 :47 and
    Care_Episode_Reporting :40 :43
    ← :46 is <viewAllFields>true</viewAllFields> and it is now in the output, so
      the discriminator between the two files is visible without opening them.
grep -rnE --include='*.profile-meta.xml' --include='*.permissionset-meta.xml' '<(viewAllFields|viewAllRecords|modifyAllRecords)>true</' fixtures/vulnerable/sf_permset_view_all_fields
  → exit 0, same six lines   ← the transliteration the lens now quotes, verified
    against the engine it exists for
rg -n --glob '**/force-app/**/*.profile-meta.xml' --glob '**/force-app/**/*.permissionset-meta.xml' --glob '**/force-app/**/*.permissionsetgroup-meta.xml' '<name>(ViewAllData|ModifyAllData|AuthorApex|ApiEnabled|CustomizeApplication|ManageUsers)</name>' fixtures/vulnerable/sf_permset_view_all_fields
  → exit 1   ← negative control: one bug class in this fixture, not two
rg -n --glob '**/force-app/**/objects/**' '<sharingModel>|<externalSharingModel>' fixtures/vulnerable/sf_permset_view_all_fields
  → exit 0, hits at :29 :30 (ReadWrite / Private) — the OWD both halves are graded
    against, and the value that used to produce the downgrade
```

**False-positive checks on the corpus, both directions.**

```
rg -n --glob '**/force-app/**/*.profile-meta.xml' --glob '**/force-app/**/*.permissionset-meta.xml' '<(viewAllFields|viewAllRecords|modifyAllRecords)>true</' fixtures/clean
  → exit 1   ← the new pattern raises nothing on the clean half
rg … same … fixtures/vulnerable/force-app
  → exit 1   ← and nothing on V-012's tree, so no fixture's recorded grade moves
```

V-012's own recorded commands are unaffected for a mechanical reason worth stating:
they are run from `fixtures/vulnerable/` with root-anchored `force-app/**` globs,
and V-013 sits one directory deeper at `sf_permset_view_all_fields/force-app/**`,
which those globs do not reach. The lens's own globs are `**/`-prefixed and do.

**Two honest notes on the measurement.**

- Both engines match the header comment line (`:10`, the sentence naming the
  defect) as well as the real element at `:46`. That is Observation C in this file
  reproducing itself: fixture headers inflate hit counts. Over-reporting is the
  safe direction and no grade moves, but a reader comparing counts against a real
  org should subtract it.
- The sweep is what makes the finding *visible*; it is not what grades it. Whether
  the auditor then applies the `ReadWrite` downgrade is decided by the severity
  row, which is why the row was edited in the same pass and why the pair of files
  is the only thing that can tell the two outcomes apart.

### V-014 — CAUGHT, and its clean pair C-033 is the measurement that matters

Measured 2026-07-27. `rg` here is a **shell function** (`type rg` re-verified), so
every result below was preceded by a self-check on a string read by eye out of the
fixture — `rg -n 'THE DEFECT' fixtures/vulnerable/WebhookSignatureEquals.cls` → exit
0 at `:63`; and a negative control on a string that is in no fixture → exit 1.

**The three sweeps that find it.** The first is unchanged by this pass; the second
and third were added to §0 in the same pass as the row.

```
rg -n -i '(signature|\bsigs?\b|\bmac\b|digest|hmac|\btokens?\b|\bsecrets?\b)[^=!<>\n]{0,40}(===?|!==?)|…' fixtures/vulnerable/WebhookSignatureEquals.cls
  → exit 0, hits at :15 (header) and :71 (the defect)
rg -n --glob '**/*.cls' -i '(signature|\bsigs?\b|\bmac\b|digest|hmac)[^=!<>\n]{0,40}(==|!=)|…' fixtures
  → exit 0, V-014 only — :15 and :71.  exit 1 on C-033.
rg -n --glob '**/*.cls' 'Crypto\.(encrypt|encryptWithManagedIV|decrypt|…)\(|Crypto\.generate(Mac|Digest|AesKey)\(|…' fixtures
  → exit 0, one hit in each of the two new fixtures (both compute the MAC correctly)
```

**The MAC absence sweep, before and after the construction-list edit.** Apex's
keyed primitive is `Crypto.generateMac(`, which was in neither copy of the
construction list, so stage 1 never opened an Apex file:

```
stage 1, PRE-EDIT list, on both new fixtures
  → exit 1     ← the whole Apex stack read clean, silently
stage 1, POST-EDIT list (…|Crypto\.generateMac\()
  → exit 0, both files
full loop (stage 1 → stage 2 → stage 3), POST-EDIT, over all of fixtures/
  → FLAGGED fixtures/vulnerable/WebhookSignatureEquals.cls
    FLAGGED fixtures/vulnerable/settings_signing.py     (pre-existing)
    FLAGGED fixtures/clean/ApexWebhookVerifier.cls      (C-033 — BY DESIGN, below)
    FLAGGED fixtures/clean/retention_purge.py           (pre-existing, Observation B)
same loop with the PRE-EDIT list
  → the two pre-existing lines only
```

So the edit adds **two** flags across the corpus, and one of them is on the clean
half. That is the designed result and not noise: C-033 intentionally exercises the
legacy local-helper path and therefore contains no exact platform comparator call.
The general safe list now recognizes Apex code that calls the built-in Blob
comparator, while project-local names remain excluded until the auditor reads the
helper body. C-033 appearing in this list is the property being measured. A re-run
that sees three flags instead of four has lost that property — do not read the
C-033 line as a regression, and do not silence it by adding a helper name to the
safe list (the lens records that shortcut as rejected). The symmetric CBC/CTR
absence sweep, whose Apex arm now admits only calls with literal unhyphenated
`AES128`/`AES192`/`AES256` algorithm names (and therefore excludes `AES*-GCM`),
still flags only V-005 across the whole corpus (exit 0, one line).

**Stage 2 recognizes the built-in and intentionally does not clear this local
helper pair.** The platform safe list, run verbatim:

```
rg -q '…|subtle\.ConstantTimeCompare|MessageDigest\.isEqual|FixedTimeEquals|ActiveSupport::SecurityUtils\.(fixed_length_secure_compare|secure_compare)|Crypto\.areEqualConstantTime|…' fixtures/vulnerable/WebhookSignatureEquals.cls
  → exit 1     (correct: no exact platform comparator call)
… same list … fixtures/clean/ApexWebhookVerifier.cls
  → exit 1     (correct: no exact platform comparator call)
… same list … the PRE-COMMIT DRAFT of that same file, when it was named
  ConstantTimeCompare.cls with a class of the same name
  → exit 1 under the current qualified Go token
```

The draft used to clear stage 2 because the list contained a bare
`ConstantTimeCompare` alternative. That incidental-name collision is now fixed at
the source: the Go API is matched as `subtle\.ConstantTimeCompare`, so neither an
Apex file name nor a local class of the old name can clear the sweep. The committed
name is still `ApexWebhookVerifier`, its helper is `equalsConstantTime`, and stage
2 is **exit 1 on both fixtures**. The current rule embodies two distinct decisions:

- **Exact, qualified platform calls are safe-list material.** Apex's built-in call
  and Go's namespace-qualified call can clear stage 2 when executable code uses
  them.
- **Project-local helper names are reading-list material.** A helper named
  `constantTimeEquals`, `secureCompare` or similar cannot clear a candidate until
  its body and call site satisfy the manual contract. This remains the measured
  basis of the lens's rejected-candidate entry.

**The discriminator that does work, measured in both directions.** §0's new Apex
helper-enumeration arm against its operator arm:

```
rg -q --glob '**/*.cls' -i 'constantTime[A-Za-z]*|secureCompare|safeEquals|timingSafe|slowEquals'
  C-033 → exit 0  (declaration at :55, call at :92)      V-014 → exit 1
rg -q --glob '**/*.cls' -i '(signature|…)[^=!<>\n]{0,40}(==|!=)|…'
  C-033 → exit 1                                          V-014 → exit 0
```

Neither arm raises anything on the three pre-existing clean Apex fixtures (C-005,
C-015, C-031) or on V-012. A hit on the first arm is a **reading list**, not a
clearance — the lens says so in as many words, because a drifted private copy of a
helper matches that pattern exactly as a correct one does.

**BEFORE and AFTER on the grade, which no grep can show.** The original text
incorrectly assumed Apex lacked a built-in constant-time comparison API. The
platform list now includes the exact built-in and recommends it for production
code. C-033 deliberately contains no such call so the legacy manual path remains
tested: its project-local helper clears only after the auditor confirms all four
conditions (helper at `:55`–`:67`, length check at `:59`, branch-free loop at
`:63`–`:65`, called on the request value at `:92`). V-014 calls neither the
built-in nor a verified helper and stays High.

### V-015 — CAUGHT after the lens edit; the BEFORE is the point

Every sweep in `llm-and-ai` §0 that predates this run is blind to this file. `rg`
was confirmed live first, per environment fact 1 — `rg -n 'TICKET_TRIAGE_COMMAND'`
on the fixture returned exit 0 with the line printed, and a string known to be
absent returned exit 1.

```
BEFORE — pre-existing sweeps, whole file:
  provider call sites   'messages\.create\(|…|Runner\.run\('               → exit 1
  agent construction    'AgentExecutor\(|create_react_agent\(|…'           → exit 1
  tool enumeration      '@tool\b|…|zodFunction\('                          → exit 1
  system-prompt boundary 'system_prompt|SYSTEM_PROMPT|systemPrompt|…'      → exit 1

AFTER — arms added to §0 this run:
  arm (b) line 1  'claude\s+(-p|--print)|codex\s+exec|…|acceptEdits|bypassPermissions'
                  → exit 0, hits at :64 :66 :69 :73 :77
  arm (b) line 2  '(os\.environ(\.get)?[\[(]|…)…(COMMAND|CMD|AGENT|CLI|RUNNER)|shlex\.split\('
                  → exit 0, hits at :69 :70
  sinks (pre-existing, and it does fire)  'subprocess\.(run|Popen|…)\('
                  → exit 0, hits at :82 :93 :115 :116 :117
  bounds (extended this run)  '…|--max-turns|max_turns|maxTurns|timeout\s*=\s*[\dA-Z]'
                  → exit 1   ← the ABSENCE item 16 says to read: no cap, no clock
```

Four sweeps at exit 1, and a tool inventory of **zero** on a file whose entire
subject is a tool-bearing agent. That is the §0 reach gap this fixture was written
for: the agent's authority is a set of command-line flags, and a flag has no symbol
for a symbol grep. The subprocess sink sweep does fire, which is worth stating
plainly — an auditor who traced those five lines would arrive at the defect — but it
fires on `git` and on the spawn indifferently and produces no model call site, so
item 1's table is still empty and every grade below it is still ungraded.

Two measured details, both kept because they are corrections to this run's own work:

- **Arm (b) line 2 was wrong when first written and the measurement caught it.** As
  drafted it read `os\.environ(\.get)?\[?` — an optional bracket, no paren — so it
  matched `shlex.split(` at `:70` and **missed** `os.environ.get("TICKET_TRIAGE_COMMAND"`
  at `:69`, which is the line the arm exists for. A sweep that hits the right file
  for the wrong reason reads identically to one that works. Corrected to `[\[(]`
  and re-measured: both lines hit.
- **The bounds sweep was extended because of C-036, not because of V-015.** The
  pre-existing pattern is framework-keyed (`max_iterations`, `recursion_limit`,
  `maxSteps`), and a spawned agent has none of them: its turn cap is `--max-turns`
  and its wall clock is the spawn's own `timeout=`. Measured before the extension:
  **exit 1 on both fixtures**, so the correctly bounded clean runner read exactly
  like the unbounded vulnerable one, and item 16's bound requirement had no
  discovery step. After: exit 1 on V-015 (genuinely unbounded) and exit 0 on C-036
  at `:120` and `:137`. Re-measured on V-004 and across the whole vulnerable half:
  exit 1, so no previously recorded grade moved.

**One header literal was removed from the fixture to keep the measurement honest.**
The header first described the missing tool definitions using the decorator's own
spelling, and the tool-enumeration sweep matched that comment — Observation C, on a
file written this run. The sentence now names the decorator instead of spelling it,
and the sweep returns exit 1, which is the true result.

### V-016 — CAUGHT; Bicep helpers and the Terraform positive sweep re-measured in both directions

The Bicep absence/count commands, the Azure firewall-sentinel sweep and the
Terraform explicit-disable sweep were run from `cloud-and-iac` on 2026-07-28.

```text
fixtures/vulnerable/azure_public_data_plane.bicep
  bicep_absent  → PostgreSQL and Key Vault reported
  bicep_count   → stores: 2  diag: 0  pe: 0  bicep-files: 1
  firewall sentinel → exit 0; executable hits at :98-99

fixtures/clean/azure_private_endpoint.bicep
  bicep_absent  → no output
  bicep_count   → stores: 3  diag: 3  pe: 2  bicep-files: 1
  firewall sentinel → exit 1

Terraform regression pair
  vulnerable: storage_encrypted = false → executable hits at :46 and :65
  clean:      storage_encrypted = false → exit 1
```

The vulnerable sentinel command also matches the explanatory comment at `:21`
before it reaches the resource. That comment hit is not proof. The recorded
positive therefore requires the two non-comment property lines at `:98-99`;
the clean fixture supplies the opposite control. A future re-run that records
only `exit 0` has **NO VERDICT**, because deleting the resource while retaining
the comment would otherwise leave the fixture falsely green.

---

## Known and closed gaps

These are findings about the lenses, obtained by running the lenses' own machinery.
Closed entries remain as the measurement record for the sweep that now exists.
The unresolved entries are corpus coverage limits, not silent lens clearances.
None was closed by editing a fixture.

### Known gap 1 — CLOSED 2026-07-27 — `web-and-api` §0 could not see a JDBC concatenation built in a local variable

> **[RESOLVED 2026-07-27]** A two-stage sweep was added to `web-and-api` §0 for the two-step form
> (SQL literal concatenated into a variable, variable then executed). Verified in both
> directions: it catches V-002, which nothing in the corpus caught before, and returns nothing
> across all 32 clean fixtures. The finding below is kept as the record of why the sweep exists.

**Fixture:** V-002. **Topic:** `injection-sql-nosql-orm`. **Direction: missed
finding.**

Every injection literal in web-and-api §0 requires the concatenation to be *inside
the driver call*: `execute(f"`, `execute("…" %`, `query(`…${`,
`createQuery("…" +`, `cursor.execute(… % (`. V-002 builds the SQL into a
`String sql` local across four lines and then calls `statement.executeQuery(sql)`.
That is the dominant shape in Java, C#, PHP and Go — arguably the dominant shape
in *any* language once the query is long enough to need formatting — and no sweep
in the lens matches it. Measured: exit 1 on the §0 sweep, and exit 1 again on a
grep assembled from every literal item 13's prose names.

Item 13's prose *does* describe the class correctly ("String building into a driver
call"). So this is a §0 reach gap, not a lens blind spot — which is precisely the
"fix where the claim is USED, not only where it is STATED" failure the project's
method rules put at number two. An auditor who works the sweeps first, as item 0
instructs, never opens this file.

**Suggested edit** (for whoever owns `web-and-api`): add a two-stage sweep that
finds the *assembly* rather than the call —
enumerate `(String|StringBuilder|var)\s+\w*(sql|query)\w*\s*=` and
`\.append\(` near a driver symbol, then read each hit; or add
`(executeQuery|executeUpdate|execute)\(\s*[a-z_]\w*\s*\)` — the driver call taking
a *bare identifier* — as a candidate line, since a parameterised call never passes
a lone variable where the SQL goes.

### Known gap 2 — CLOSED 2026-07-28 — `crypto-and-key-management` §0 had no line for the shape item 14 calls the sharpest form of the finding

> **[RESOLVED 2026-07-28]** A §0 inventory now covers literal environment
> fallbacks in Python, Node, Ruby, PHP, Spring, .NET, shell expansion, and Go's
> nearby empty-check form. It catches all three fallback bindings in V-006.
> Clean-corpus hits are non-secret configuration defaults and clear on the read;
> the sweep is explicitly a candidate inventory, not an automatic finding.

The remainder of this subsection records the pre-fix diagnosis for provenance.

**Fixture:** V-006. **Topic:** `hardcoded-credentials-and-key-material`.
**Direction: missed finding.**

Item 14 said, in bold, that a default applied when the variable is unset is *the
sharpest form of this finding*, and then named the two-argument
`os.environ.get`, `process.env.X ||`, Go's `os.Getenv` followed by a nearby empty
check and literal assignment, and `@Value("${x:default}")`. At the time, the §0
sweep block contained no such line. Its
key-material sweeps look for PEM headers, provider prefixes and key file
extensions — all three of which correctly return nothing on V-006.

So the finding is reachable only by an auditor who reads item 14 in full and
writes the grep themselves. Given that §0 is described as "the highest-yield
sweeps" and is where an agent starts, the High-severity row most likely to appear
in a real repository has no discovery step.

**Suggested edit:** promote item 14's own sentence into §0 as a sweep line. The
pattern used for the measurement above is
`os\.environ\.get\([^)]*,|process\.env\.[A-Za-z_]+\s*\|\||os\.Getenv\([^)]*\)\s*;?\s*if|@Value\("\$\{[^}]*:[^}]*\}"\)`,
which found all three fallbacks in V-006. It has no Ruby or PHP arm — `ENV.fetch(x,
default)` and `$_ENV['X'] ?? 'literal'` are the same defect and match nothing in
the list item 14 names — so a lens edit should add those two spellings rather than
copying the pattern as-is.

### Known gap 3 — the corpus rule against realistic credentials makes one detection path structurally untestable

**Fixture:** V-006. **Direction: not a lens defect. A limit on what this corpus can
measure, recorded so nobody mistakes it for a pass.**

Crypto's §0 provider-prefix sweep (`sk-ant-`, `AKIA`+16, `ghp_`, `xoxb-`, service
account JSON) and its severity row "Private key, keystore or provider secret
committed → Critical" can only be exercised by a file containing a
provider-shaped string. This corpus is forbidden from shipping one, and correctly
so: a scanner-shaped literal in a repository generates alerts forever, each
costing a human a triage cycle to close as test data — which is also exactly how a
real leaked key gets dismissed.

That path is therefore **untested**, not passing. It should be verified by a unit
test over the pattern with a synthetic string constructed in memory at test time
and never written to disk, not by a fixture.

Two further consequences of the same rule, both worth stating:

- **`fixtures/` is explicitly exempted by the row itself.** The Critical row reads
  "…outside `test/`, `fixtures/`, `__snapshots__/` or `.env.example`", and item 14
  repeats it. Every file in this corpus is inside `fixtures/`, so **that row can
  never fire on anything here by construction.** The exemption is right for real
  repositories and it means this directory cannot evaluate the row at all.
- **A placeholder default invites a downgrade.** V-006's literals announce their
  own invalidity (`placeholder-not-a-key`). A reviewer may reasonably argue that a
  self-evident placeholder is a hygiene note. Item 14 is unambiguous that the
  *fallback mechanism* is the finding regardless of the value, so V-006 is
  expected at High — but the fixture cannot settle the argument the way a live-
  looking value would, and it is not allowed to try.

### Known gap 4 — no fixture exercises `llm-and-ai` §0 arm (a), the assembled-URL provider call

**Fixture: none. Topic:** `llm-data-flow-inventory`. **Direction: a corpus gap, not
a lens defect.**

Arm (a) was added to §0 this run for the shape that produces an inventory with *no*
rows: a raw `httpx.post` to a URL built from a base constant and a path, with no
vendor symbol anywhere in the file. Nothing in this corpus has that shape, and V-015
must not acquire it — one bug class per file, and stapling a second model call shape
onto an agent-runner fixture would make the file measure two things and settle
neither.

So the arm was measured against a file written **outside** the corpus, in a
scratch directory, and that measurement is recorded here rather than dressed up as a
fixture result:

```
scratch file: os.environ["MODEL_API_BASE"] + httpx.post(f"{MODEL_API_BASE}/v1/chat/completions", …)
  pre-existing provider sweep  'messages\.create\(|…|Runner\.run\('   → exit 1   ← the gap
  arm (a) line 1  '/v1/(chat/)?completions|…|(BASE_URL|API_BASE|…)\s*[:=]'
                  → exit 0, hits at :4 :10
  arm (a) line 2  'httpx\.(post|stream|Client|AsyncClient)|requests\.post\(|…'
                  → exit 0, hit at :9
```

Both arms hit the same file, which is the candidate the lens says to read; the
pre-existing sweep is silent on it. Also measured across the whole corpus: arm (a)
line 1 returns **exit 1** on every fixture in both halves while line 2 returns exit 0
on five clean files and one vulnerable file, so the intersection the lens requires is
empty and the broad arm raises nothing on its own. That is the two-arm design
working, and it is the reason line 2 is allowed to be broad.

The arm is demonstrated inside the lens by a detector pair in item 1. **A detector is
not a fixture** — it is a two-directional example, not a measured run over a file on
disk — so this stays a recorded gap until the corpus grows a `llm_http_client` fixture.

---

## Lens observations

Not gaps against a specific fixture, but properties measured while building the
corpus. Each one is a recommended lens edit, reported rather than applied.

### Observation A — both crypto absence sweeps are comment-blind in the clearing direction

> **[MITIGATED 2026-07-27, not closed]** A grep cannot tell code from a comment, so this cannot be
> fixed in the sweep. An explicit COMMENT BLINDNESS warning was added above both sweeps
> requiring the reader to confirm the safe call appears in executable code on the request path
> before clearing any file the sweep did not print.

**Measured, and this is the dangerous direction.** Two byte-identical copies of
V-003 differing only by one appended comment line naming a safe-list token:

```
cp fixtures/vulnerable/jwt_session_middleware.go /tmp/a.go
cp fixtures/vulnerable/jwt_session_middleware.go /tmp/b.go
printf '\n// note: the parser also has SigningMethodHMAC available.\n' >> /tmp/b.go
for f in /tmp/a.go /tmp/b.go; do
  rg -q 'WithValidMethods|SigningMethodHMAC|…|\.Method\.\(' "$f" || echo "FLAGGED: $f"
done
→ FLAGGED: /tmp/a.go      (b.go silently cleared)
```

The same experiment on V-005 with `// TODO: migrate this to an authenticated mode
such as AES-GCM.` appended clears the C# fixture identically. **A TODO comment
naming the fix suppresses the finding**, on code that is unchanged and still
vulnerable.

This is the over-broad-predicate failure the project's method rules put at number
six, one layer further in than the `siv` instance the Phase A punch list caught:
the safe list is not matching an `-sive` word, it is matching a sentence that
*repudiates* the claim. It is also why both fixtures carry an explicit editing
warning in their headers — without it, a future contributor adding a helpful
comment would silently disarm two Critical fixtures.

**Suggested edit:** the safe lists are clearing lists, so they should be read from
code rather than from comments. A cheap improvement short of parsing: require the
token to appear on a line that is not comment-only, e.g. pipe the file through a
`rg -v '^\s*(//|#|\*|--)'` stage before the safe-pattern test. That does not reach
a trailing comment on a code line, and the residual should be stated rather than
implied.

### Observation B — §0 and the severity rows can disagree about what is findable

> **[PARTLY CLOSED 2026-07-27]** The crypto instance is fixed: the MAC sweep now requires an equality
> operator to be present, matching the severity row it feeds, and `hmac.Equal` was added to
> both lists at once. A residual remains by design — `retention_purge.py` still surfaces on an
> unrelated `rule.action == "delete"`, which the row then clears, because the row grades on a
> comparison against a *request* value and grep cannot see provenance.

Known gap 2 is one instance; the pattern is worth naming on its own. `web-and-api`
and `crypto-and-key-management` both carry severity rows whose establishing
artifact is named nowhere in §0. The project's own method rule 3 — "a High/Critical
condition must be **findable** — name the glob, key, element or symbol" — is
satisfied at the row and not at the sweep, and an agent that starts at §0 is the
consumer that loses. A lint rule that checked every backticked literal in a
severity row against the §0 block would find these mechanically; the existing
`detectorCoverage` observation counts literals against detectors, not against
sweeps.

### Observation C — header comments in a fixture corpus produce false hits as well as false clearances

Several sweeps matched this corpus's own header comments — the cicd trigger sweep
hit the line explaining `pull_request_target`, and the "aggravators deliberately
absent" sweep hit the sentence saying they are absent. Over-reporting is the safe
direction and no grade was affected. It is recorded for two reasons: a reader
comparing hit *counts* between fixture and real code will see inflated numbers,
and the same mechanism running in the clearing direction is Observation A.

---

## The clean half

**A clean fixture's expected result is zero findings at Low severity or above.** An
`Info` observation is acceptable, because Info is explicitly not a vulnerability claim.
Anything at Low or above on any file below is a false positive against the lens that
raised it.
**The expected result for every file below is zero findings at Low severity or
above.** An `Info` observation is acceptable, because Info is explicitly not a
vulnerability claim. Anything at Low or above on any of these files is a false
positive against the lens that raised it.

**Why this half matters more than the vulnerable half.** A tool that misses a bug
is disappointing. A tool that cries wolf on correct code gets switched off inside a
day, and then it misses every bug. Each entry in a lens's `## Known false
positives` section is an untested assertion until a clean fixture exercises it; the
coverage table at the bottom records how many are exercised and how many are not.

---

### Manifest

| # | fixture | language / stack | reads as | the sweep or detector that fires, and why the finding does not stand |
|---|---|---|---|---|
| C-001 | `jwt_kid_static_jwks.py` | Python, PyJWT | kid-injection / key-source injection | `jwt.decode(`, `get_unverified_header` and a `kid` used as a key selector all hit. The kid is a subscript over a closed in-file dict of three PEM **public** keys; an unknown kid raises before `decode`; no `jku`/`x5u`/`jwks_uri` and no HTTP client anywhere; `algorithms=["RS256"]`, `audience` and `issuer` all pinned |
| C-002 | `crypto_util.go` | Go | CWE-327 MD5 + CWE-208 timing | `md5.Sum` twice and an `==` against a request header. Both digests derive a cache key and an ETag over build-time asset paths and bytes — no secret, no authorization downstream. The one secret-bearing path uses HMAC-SHA256 and `hmac.Equal` |
| C-003 | `reset_token.ts` | TypeScript, node:crypto | predictable reset token | `Math.random()` hits every CSPRNG sweep. It produces mailer retry **jitter**; the token is `randomBytes(32)` and redemption compares SHA-256 digests with `timingSafeEqual` behind an explicit length check |
| C-004 | `.github/workflows/pr_label_comment.yml` | GitHub Actions | pwn-request Critical | `pull_request_target` plus a secret-bearing job. No `actions/checkout`, no `gh pr checkout`, no `refs/pull/`, no local `uses: ./`, nothing installs or executes PR content. Untrusted strings are step-scoped `env:` dereferenced as `"$VAR"`; the one `${{ }}` in a shell is `github.run_id`; actions are 40-hex pinned; `permissions:` is explicit |
| C-005 | `force-app/.../ReportColumnQuery.cls` | Apex | SOQL injection | `Database.queryWithBinds` with `+` concatenation and an `@AuraEnabled` parameter in the string. The interpolated token is a **field API name** resolved through `Schema.getGlobalDescribe()` (absent name raises); every value is a named bind; `AccessLevel.USER_MODE` enforces CRUD/FLS/sharing. A field name cannot be bound in SOQL, so the allowlist is the fix rather than a shortcut |
| C-006 | `android/**` (7 files) | Gradle + XML | trust-all TLS in a shipped app | `usesCleartextTraffic="true"` and `<debug-overrides><certificates src="user">`. Both are in `app/src/debug/`, which never merges into a release variant; `usesCleartextTraffic` is ignored beside a declared `networkSecurityConfig`; and `build.gradle` sets `debuggable false` on `release`, which is the precondition the entry demands rather than assumes. `babel.config.js` and `metro.config.js` establish the `dev: false` half |
| C-007 | `network_public_alb.tf` | Terraform | SSH open to the world + exposed DB | Three `0.0.0.0/0` lines, one eleven lines above `from_port = 22`. Every ingress `0.0.0.0/0` is 443/80 on a group attached in-file to an internet-facing ALB; the SSH rule takes `security_groups` and no CIDR; `::/0` is declared beside each `0.0.0.0/0`; the RDS instance sets `publicly_accessible = false` and `storage_encrypted = true` |
| C-008 | `IconMessage.tsx` | React TSX | XSS via model output | `dangerouslySetInnerHTML` fed a value derived from model output. The model supplies an icon **name**; `Object.hasOwn` gates a frozen record of five hand-written SVG literals; unknown names render nothing. Deliberately not the DOMPurify variant, which `web-and-api` rejects as a suppression |
| C-009 | `cloud_iam_kms_s3_oac.tf` | Terraform | four separate IAM Criticals | `Resource = "*"` on actions that cannot be resource-scoped, with condition-key least privilege; `kms:*` to this account's own `:root` (the AWS default key policy, account id from `aws_caller_identity`); a bucket with no SSE block but BPA on all four flags; a bucket policy granting only `cloudfront.amazonaws.com` with `AWS:SourceArn`; `Principal = "*"` with `aws:PrincipalOrgID` `StringEquals` in the same statement |
| C-010 | `report_export.py` | Python, Django | f-string SQL injection | `f"SELECT {projection} …"` with `", ".join` handed to `cursor.execute`. Identifiers come from a frozenset of nine literals; values are `%s` placeholders passed as the second argument. Also carries `except ValueError: pass`, `contextlib.suppress(FileNotFoundError)`, `md5(..., usedforsecurity=False)`, a lazy queryset evaluated after the guard, a raising guard called as a bare statement, and a doubly-anchored allowlist regex |
| C-011 | `PrefsParser.java` | Java | swallowed exceptions + weakened SecureRandom | A comment-only `catch (JsonParseException e)`, a log-and-rethrow, an interrupt restore, `new SecureRandom(); setSeed(pid)` (which supplements on the default provider), and `Arrays.equals` on two locally computed CRC32 values |
| C-012 | `CbcThenHmac.java` | Java | hand-rolled AES-CBC | `Cipher.getInstance("AES/CBC/PKCS5Padding")`. Encrypt-then-MAC in the correct order: HKDF-separated enc/MAC keys, a fresh IV drawn inside the per-message method, a tag over VERSION‖IV‖CIPHERTEXT, verified with `MessageDigest.isEqual` and returning **before** `doFinal` on mismatch |
| C-013 | `tests/test_local_emulator_tls.py` | Python, pytest | `verify=False` Critical | Three `verify=False` calls. The host literal is at every call site — `https://127.0.0.1:4443` — against an emulator this module starts with a per-run throwaway certificate. Nothing is read from configuration. The last test is the control: it asserts the shipped client leaves `verify` True and `trust_env` False |
| C-014 | `egress_confined_pod.yaml` | Kubernetes | SSRF deny-list omitting loopback; container as root | The deny-list is a pre-check, not the boundary: a default-deny egress NetworkPolicy allows only DNS and the egress gateway, `hostNetwork` is absent, the pod has one container so its loopback has one listener, and the gateway's config is an allow-list. `runAsUser` unset is answered by `runAsNonRoot: true` plus a digest-pinned distroless-nonroot image |
| C-015 | `force-app/.../ShippingRuleRollup.cls` + `objects/Shipping_Zone__c/…` | Apex + object metadata | `without sharing` bypass | Three independent reasons, two of which the entry insists be established: `Shipping_Rule__mdt` is a custom metadata type and has no sharing model at all; `Shipping_Zone__c.object-meta.xml` declares `<sharingModel>ReadWrite</sharingModel>` and `<externalSharingModel>ReadWrite</externalSharingModel>`; and no user-supplied Id or filter crosses the boundary — the single caller is enumerated in the file |
| C-016 | `replay_and_consent.tsx` | React TSX | three replay SDKs + a pre-consent tag | Masking is read per vendor against documented defaults: `rrweb` records input by default so `maskAllInputs` and `maskTextSelector` are set; `logrocket` records by default so `inputSanitizer` is set; Sentry masks by default and is pinned anyway. FullStory and smartlook are deliberately absent because the lens records their defaults as unverified. Nothing initialises before a stored affirmative consent, Consent Mode defaults to denied before the container loads, and GPC is honoured |
| C-017 | `tests/checkout.spec.ts` | Playwright | PCI breach — three PANs | `4242…`, `4111…`, `5555…` are published processor test numbers that cannot authorize a transaction. Brand plus last four is permitted display; the negative control asserts the API returns no CVC, no track data and no thirteen-plus digit run |
| C-018 | `chart_view.py` | Python, DRF | minimum-necessary + PHI-in-URL Critical | `fields = "__all__"` on a chart endpoint whose callers are the patient's treating clinicians, which §164.502(b)(2)(i) exempts from minimum necessary entirely; the billing surface beside it is projected to four fields because the exemption stops there. The path identifier is an opaque UUID with `Referrer-Policy: no-referrer` and no tracker, and the audit write records the **acting user** and is not wrapped in try/except |
| C-019 | `seeds/synthetic_patients.json` | JSON | production ePHI in dev | Realistic demographics with a provenance block: generator, invocation, seed, `derived_from_production: false`, no crosswalk, no postal code at all. The finding requires provenance evidence, not resemblance |
| C-020 | `invoice_api.ts` | Express + Prisma + Zod | seven separate web reflexes | No CSRF token (bearer-only, and cookie auth is refused in code with a 401); `ACAO: *` on two unauthenticated fixed-content routes mounted above the guard; `findById(id, orgId)` with the scope in the signature and PATCH/DELETE/bulk/export each checked separately; the guard is `app.use("/api", requireBearer)` in this file; no login handler to rate-limit (OIDC redirect, no password comparison); ten-minute tokens plus refresh revocation; no `integrity` on the first-party content-hashed bundle and `integrity` present on the CDN tag |
| C-021 | `llm_support_agent.py` | Python, FastAPI + LangChain | prompt injection, filterless RAG, unapproved destructive tool | The capability inventory is written out and is empty of privilege: one read-only tool closed over the session, no interpreter, no outbound channel, `text/plain` responses, an enforcing CSP with explicit `img-src`, bounded iterations. Retrieval has no tenant filter because the **ingestion path in the same file** asserts every document is public. Approval is a server-side pending record whose resume path re-checks a digest of the exact arguments |
| C-022 | `ledger_refund.py` | Python, Django | five business-logic defects | Negative ledger rows are double-entry and are clamped at the availability boundary; negative stock is the backorder the product sells and the non-backorderable path is an atomic `UPDATE … WHERE` with a checked row count; the idempotency key is derived from the intent and the local ledger has a unique index on it; the seat table uses a unique index because uniqueness is the product there; the float exists only inside `format_amount` |
| C-023 | `lib_manifest/{package.json,.npmrc}` | npm manifest | no lockfile, not using `npm ci` | The manifest is evidence of a **library**: published name, `files`, `main`, `types`, `exports`, no `private`. A consumer never reads a library's lockfile. `packageManager` is pnpm, so `npm ci` is the wrong equivalent; `prefer-frozen-lockfile=true` is the right one. `ignore-scripts=true` is a value read, not a key-presence check |
| C-024 | `settings_dev.py` | Python, Django | `DEBUG = True`, `ALLOWED_HOSTS = ["*"]`, hardcoded key | The deployment chain is quoted in the docstring: the image's `CMD`, `wsgi.py`'s **assignment** (not `setdefault`) of the production settings module, and the absence of a `raw_env` override. Every boolean is a literal, so the inverse trap — `environ.get("DEBUG", True)` — is absent. `strict: False` is a CSV parser option |
| C-025 | `gen/api_client.gen.ts` + `gen/.gitattributes` | TypeScript, generated | five tells in ninety lines | Empty `catch {}`, a `_` discard, `strict: false`, `token === undefined`, a `fetch` with no timeout — all generator template. Establishable three ways: the header banner names the generator and its input, the `gen/` path and `.gen.ts` suffix, and `git check-attr linguist-generated -- fixtures/clean/gen/api_client.gen.ts` returns **true**. A real finding here belongs against `openapi/notes-api.v3.yaml` |
| C-026 | `hs256_service_token.py` | Python, cryptography | HS256, ECB, no-nonce API, counter nonce | HS256 with one party issuing and verifying, algorithm pinned, 256-bit managed key, no verify-only holder. `aes_key_wrap` is the ECB primitive wrapping one high-entropy key. `Fernet.encrypt` draws its own IV and the wrapper does not undo it. The GCM counter nonce is SP 800-38D §8.2.1 with both failure conditions closed — a durable counter store and a store-allocated fixed field asserted unique per writer |
| C-027 | `phi_logging.py` | Python | PHI in logs, telemetry capturing bodies | The record is traced call-site → processor → renderer → vendor. The processor is **allow**-list shaped, so a new ePHI column is dropped by default rather than leaking until someone edits a denylist. `send_default_pii: False`, `max_request_body_size: "never"`, `max_breadcrumbs: 0`, `before_breadcrumb` returns None. A negative control feeds fourteen ePHI-shaped keys and asserts none survives |
| C-028 | `marketing_landing.tsx` | Next.js TSX | tracking pixel in a healthcare app | Post-*AHA v. Becerra* the unauthenticated-public-page theory is vacated, so the four conditions that keep it Critical are each answered in file: `force-static` with no session read; no form, input or intake step; the tag receives a coarse page-group constant and never `pathname` or `search`; the route slug carries no identifier or condition parameter |
| C-029 | `retention_purge.py` | Python, Django | soft delete, no erasure | `deleted_at` with no `DELETE`. The purge path exists and walks a declared `ERASURE_PLAN` covering every store; `assert_schedule_meets_deadline` makes the grace-plus-interval arithmetic a runtime check against the one-month deadline; retained tax/audit rows are pseudonymised with a pepper held outside the database; `marketing_audience` excludes soft-deleted subjects at the query; restores re-apply erasures through a post-restore hook |
| C-030 | `mobile_prefs.tsx` | React Native TSX | `__DEV__` block, AsyncStorage, a key in config | The Gradle, Metro and Babel support artifacts expose no release-path override that keeps the literal `__DEV__` guard live (and no EAS profile exists); nothing inside the guarded branch is a string worth extracting. Every AsyncStorage key is classified at the call site and **both** tokens are in `expo-secure-store`. The Maps key and Sentry DSN are public client identifiers whose scope is recorded, and no `service_role`, service-account JSON or client secret appears |
| C-031 | `force-app/.../lwc/noteRecordPanel/*` | LWC | no FLS check anywhere | The data path is `lightning/uiRecordApi` and `lightning-record-edit-form` end to end, so object permissions, FLS and sharing are enforced server-side and there is no Apex to add a check to. The one real finding on this pattern is guarded: the field the author intends hidden is bound nowhere, and an assertion fails if it ever is |
| C-032 | `share_link.py` | Python, FastAPI | "anyone with the link can access it" | All five survivors the entry names are closed: 256-bit `secrets.token_urlsafe`; only the token in the URL and lookup by digest; the permission lives server-side so nothing needs signing; expiry is mandatory and shortened for a labelled-sensitive document; and the leak trio — access logs (token in the **fragment**), unfurling (POST plus a `Sec-Fetch-Mode` check), analytics (`capture_pageview: False` plus a property denylist) |
| C-033 | `ApexWebhookVerifier.cls` | Apex | CWE-208 timing-unsafe signature comparison — the fixture intentionally omits the built-in safe-list member | Apex provides a built-in Blob comparator and the lens recommends it for production code. C-033 deliberately uses the legacy local-helper path so that manual read-to-clear remains tested: length check first at `:59` (a fixed-width base64 digest, so the width is public), one pass over every character at `:63`–`:65` accumulating into a single Integer with no `break`, `return` or branch inside the loop, and the verifier calling it at `:92` on the header value that arrived in the request. The MAC is `Crypto.generateMac` over the raw body with the timestamp bound in and compared, so no second row fires either. **Recorded artifact:** stage 2 is **exit 1** on this file — the exact built-in token appears nowhere in code or comments — so the full absence loop FLAGS it by design and the row clears it on the read. An old pre-commit draft exposed a bare-name collision with Go's comparator; qualifying that safe token as `subtle.ConstantTimeCompare` fixed the collision, so the old draft would no longer clear stage 2. The committed helper remains `equalsConstantTime`. See the V-014 block |
| C-034 | `azure_private_endpoint.bicep` | Azure Bicep | public data plane and missing diagnostic settings | All three stores declare `publicNetworkAccess: 'Disabled'`; each diagnostic setting scopes a distinct store; two private endpoints name the resources that use them; the PostgreSQL server uses delegated-subnet injection. The same `bicep_absent`, count, denominator and firewall-sentinel checks exercised by V-016 return no missing-private-plane output, `stores: 3 diag: 3 pe: 2 bicep-files: 1`, and no sentinel |
| C-035 | `telemetry_vendor_bundle/**` (5 files) | TypeScript + generated bundle metadata | tracker strings on an ePHI-shaped portal | Tracker tokens exist only in a generated, vendored minified bundle. The first-party component imports no telemetry SDK; `package.json` declares none; the directory-scoped `.gitattributes` proves the minified asset is generated and vendored; and the test asserts no first-party telemetry import or initializer appears |
| C-036 | `agent_gated_runner.py` | Python, agent CLI runner | an autonomous coding agent with Edit/Write/Bash authority, untrusted ticket text interpolated into its prompt, and a `git push` in the file — the mirror of V-015 | Both arms of §0's new agent sweep fire: arm (b) line 1 at `:72`–`:77` and `:113` (`codex exec`, and `--full-auto`/`--yolo`/`--dangerously-skip-permissions`/`--auto-approve`/`bypassPermissions`/`acceptEdits`), arm (b) line 2 at `:113`–`:114` (`os.environ.get("AGENT_COMMAND")` + `shlex.split`), and the subprocess sink sweep at `:99` and `:131`. **The bypass-flag hits are a rejection list, not a configuration** — `_agent_argv` raises if any of them is in the value read back from the environment, so the sweep is matching executable code that refuses the finding rather than a comment that repudiates it (Observation A's mechanism, in the safe direction). The finding does not stand on item 16's four questions: the only write-out is `publish_reviewed_patch` at `:142`, whose first three statements are the approval read, the exact-argument-and-branch digest comparison and the single-use consume; `_git` at `:95` refuses every subcommand outside a four-member read-only set, so no caller can assemble a commit or a push around the gate; the two flags the module does have (`verbose`, `queue`) are read nowhere in the write path; the workspace is a per-run `mkdtemp` worktree removed in a `finally`; the environment is a three-key dict built from scratch rather than `os.environ.copy()`; and all three bounds plus a per-tenant budget are present (`:64`, `:65`, `:120`, `:137`, `:163`). Info is the correct grade — injection into a context whose capability is a read-only sandbox, per item 3 |
| C-037 | `database/sqlserver_rls_cdc_export.sql` | T-SQL (SQL Server) | RLS on the source beside a CDC export | The CDC schema is denied to the export principal and the granted view reapplies an immutable `ORIGINAL_LOGIN()`-to-tenant mapping; the parsed pair assertion rejects the vulnerable sibling and clears this file |
| C-038 | `database/mysql_definer_updatable_view.sql` | SQL (MySQL) | A writable `SQL SECURITY DEFINER` tenant view | The dedicated definer view has `WITH CASCADED CHECK OPTION`, the caller's base-table privileges are revoked, and only the checked view is granted; the parsed pair assertion clears it |
| C-039 | `database/mongodb_additive_roles.json` | JSON (MongoDB role model) | A tenant-filtered view and custom role | Effective roles for `tenant_api` grant `find` only on the view, never its source collection; the parsed pair assertion resolves assignments rather than treating any role declaration as effective |
| C-040 | `database/redis_broad_acl.acl` | Redis ACL | A Redis application principal with read/write commands | The default user is off, key scope is one tenant prefix, channels are reset, all commands are denied before five data commands are added, and no administrative category survives |
| C-041 | `database/firestore_auth_only.rules` | Firestore rules | Authenticated get/list/create/update rules | Each operation has an explicit tenant condition, create fixes `admin` to false, and update's field diff can change only two presentation fields; the operation-aware pair assertion clears it |
| C-042 | `database/elastic_role_union.json` | JSON (Elasticsearch security model) | DLS/FLS plus a filtered alias and a second role | The second role reads a disjoint health index; every role that reaches `orders-*` retains DLS/FLS, so neither role union nor direct backing-index access widens the tenant boundary |
| C-043 | `training_dataset.py` | Python (model training) | moving training data with no integrity admission | A signed manifest binds an immutable URI and digest, and a fail-closed poisoning-policy result precedes the trainer boundary |
| C-044 | `failure_policy.py` | Python | authorization dependency failure that permits export | The named dependency error emits a control-failure event and returns `False`; refusal, rather than the event alone, preserves the security property |
| C-045 | `native_frame.c` | C | narrowed allocation followed by a wider copy | The frame length is checked for availability and representability once, converted to `size_t`, and reused for allocation and copy |
| C-046 | `patient_chart_audit.py` | Python | ePHI access logged only as a pooled service identity | The audit record preserves the acting user's identifier and any impersonating principal alongside the accessed record |
| C-047 | `privacy_consent.py` | Python (Django forms) | a pre-selected marketing consent control | The optional consent field starts `False`, so only an affirmative user action can select it |
| C-048 | `security_grant.ts` | TypeScript | a privileged role mutation with no security event | The role grant and an attributed, stable security event are committed through the same transaction outbox |
| C-049 | `internal_identity.py` | Python (ASGI middleware) | network position used as workload identity | The receiver verifies a workload credential and never derives service authority from the source address |
| C-050 | `device_enrollment.py` | Python (device gateway) | serial-number and default-password device enrollment | A secure element consumes a one-time bootstrap, the cloud binds its attested key, and current user presence precedes authenticated owner binding |
| C-051 | `desktop_update.js` | JavaScript (Electron updater) | settings-controlled update feed | Approved channel policy, signed metadata, a monotonic security floor, and an exact package digest gate the updater |
| C-052 | `AssetSweep.sol` | Solidity | caller-selectable asset sweep guarded only by transaction origin | An operation-specific role and approved rescue destination constrain the transfer, which uses the safe token operation |

---

### Known-false-positive coverage

Counted by numbered entry in each lens's `## Known false positives` section.

| lens | entries | exercised | not exercised |
|---|---|---|---|
| ai-generated-code | 13 | 11 | 6 (partial), 13 (partial) |
| attack-chaining | 6 | 0 | all — not code-shaped |
| business-logic | 7 | 5 | 5, 7 |
| cicd-and-supply-chain | 6 | 5 | 3 |
| cloud-and-iac | 7 | 7 | — |
| completeness | 7 | 2 | 3, 4, 5, 6, 7 — not code-shaped |
| crypto-and-key-management | 10 | 10 | — |
| database-and-data-stores | 16 | 5 | 1, 3, 7, 8, 9, 10, 11, 13, 14, 15, 16 |
| hipaa-and-phi | 6 | 6 | — |
| llm-and-ai | 6 | 4 | 2, 6 |
| mobile-app-security | 6 | 6 | — |
| privacy-and-data-protection | 6 | 5 | 6 |
| salesforce-platform | 6 | 5 | 1 — incompatible with a zero-Low fixture by the entry's own text |
| threat-modeling | 6 | 3 | 2, 3, 4 — not code-shaped |
| web-and-api | 7 | 7 | — |
| **total** | **115** | **81** | **34** |

Five of the fifteen lenses are at full coverage: `cloud-and-iac`,
`crypto-and-key-management`, `hipaa-and-phi`, `mobile-app-security`, `web-and-api`.

#### Why the thirty-four are not covered, and which of them matter

**Structurally not code-shaped — 14 entries.** `attack-chaining` (all six),
`completeness` (3–7) and `threat-modeling` (2–4) are about how *findings* compose,
how coverage is measured, and what a threat-model document asserts. Their subject is
a set of Stage-1/Stage-2 records and a file map, not source text, so a source
fixture is the wrong instrument. Exercising them needs a **records fixture** — a
committed set of candidate-finding JSON objects per `_schema.md` plus an expected
triage disposition — which is a different corpus and a Phase B decision.

**Incompatible with the zero-Low rule — 1 entry.** `salesforce-platform` (1) clears
an Apex class with *no* sharing declaration, but its own text ends "the finding is
at most **Low**". A fixture exercising it therefore cannot produce zero findings at
Low or above. Recorded rather than fudged.

**Not establishable from a self-contained file — 5 entries.** `cicd` (3) turns on
two repository settings that are not in a checkout; `privacy` (6) turns on a
vendor's DPF certification scope on an external list; `llm` (2) needs the sandbox
runtime, network namespace and credential surface; `llm` (6) needs proof that a
construction is bound to *no* reachable handler anywhere; `business-logic` (7) needs
a guard in a second entry point.

**Database adapter remainder - 11 entries.** C-037 through C-042 exercise five
clearing mechanisms in the new lens: a complete read/write policy beside CDC
(2), a deliberately elevated object with a bounded contract (4), effective-role
expansion (5), a correctly scoped deny (6), and a filtered alias backed by native
security (12). The remaining entries require different engine/deployment
profiles or operational proofs: absence of a native row-policy feature, intended
administrator bypass, encryption, backup, replica, Redis logical databases,
Firestore query behavior, SQLite, migration convergence, connection identity,
and generated/vendor execution paths. Counting those as covered by the six
nearby pairs would recreate the cross-engine false clearance this lens forbids.

**Highest-risk uncovered, in order.** `llm-and-ai` (2) — the entry clears `exec()`
on model output when the isolation is correct, so a wrong clearance is remote code
execution reported clean. `llm-and-ai` (6) — the lens itself records this as the
false clearance it "came closest to shipping". `cicd-and-supply-chain` (3) — a wrong
clearance is a full CI compromise, and the discriminator is a repository setting.
All three want a multi-file fixture whose extra files are the discriminator, which is
what C-006, C-015 and C-023 already do for `mobile`, `salesforce` and `cicd`.

**Two partials.** `ai-generated-code` (6) wants a regex beside a context-aware
*encoder*; C-008 has a validator beside a closed literal set, which is adjacent and
not the same shape. `ai-generated-code` (13) wants a **hostile** fixture under an
anchored test path; this half is clean by definition, so the vulnerable half is
where that entry belongs.
