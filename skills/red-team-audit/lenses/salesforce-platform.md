---
name: salesforce-platform
title: Salesforce platform security
runs_in: fanout
activates_on:
  paths:
    - '**/force-app/**'
    - '**/classes/*.cls'
    - '**/*.cls'
    - '**/*.trigger'
    - '**/*.cls-meta.xml'
    - '**/lwc/**/*.js'
    - '**/lwc/**/*.html'
    - '**/aura/**/*.cmp'
    - '**/aura/**/*.js'
    - '**/pages/*.page'
    - '**/components/*.component'
    - '**/flows/*.flow-meta.xml'
    - '**/objects/**/*.field-meta.xml'
    - '**/permissionsets/*.permissionset-meta.xml'
    - '**/permissionsetgroups/*.permissionsetgroup-meta.xml'
    - '**/profiles/*.profile-meta.xml'
    - '**/sharingRules/*.sharingRules-meta.xml'
    - '**/namedCredentials/*.namedCredential-meta.xml'
    - '**/externalCredentials/*.externalCredential-meta.xml'
    - '**/remoteSiteSettings/*.remoteSite-meta.xml'
    - '**/cspTrustedSites/*.cspTrustedSite-meta.xml'
    - '**/connectedApps/*.connectedApp-meta.xml'
    - '**/customMetadata/*.md-meta.xml'
    - '**/settings/*.settings-meta.xml'
    - '**/sites/*.site-meta.xml'
    - '**/networks/*.network-meta.xml'
    - '**/staticresources/**'
    - '**/scripts/apex/*.apex'
    - 'sfdx-project.json'
    - '**/package.xml'
    - '.forceignore'
  signals:
    - '@AuraEnabled'
    - '@AuraEnabled(cacheable=true)'
    - 'with sharing'
    - 'without sharing'
    - 'inherited sharing'
    - 'Database.query('
    - 'Database.queryWithBinds('
    - 'String.escapeSingleQuotes('
    - 'Security.stripInaccessible('
    - 'WITH USER_MODE'
    - 'WITH SECURITY_ENFORCED'
    - 'AccessLevel.USER_MODE'
    - 'Schema.SObjectType'
    - 'FeatureManagement.checkPermission('
    - '@RestResource'
    - 'RestContext.request'
    - '@InvocableMethod'
    - 'webservice static'
    - 'System.runAs('
    - 'Test.startTest()'
    - 'System.debug('
    - 'Crypto.generateAesKey('
    - 'Database.DMLOptions'
    - 'lwc:dom="manual"'
    - 'aura:unescapedHtml'
    - 'apex:outputText escape="false"'
    - '{!$CurrentPage.parameters'
    - "import { LightningElement } from 'lwc'"
    - '@salesforce/apex/'
    - '@salesforce/schema/'
    - 'lightning/uiRecordApi'
    - 'sfdx-project.json'
    - '@salesforce/sfdx-lwc-jest'
    - '@salesforce/eslint-config-lwc'
    - '@salesforce/eslint-plugin-lwc'
    - '@salesforce/core'
    - '@salesforce/cli'
    - 'jsforce'
    - 'simple-salesforce'
    - 'sf project deploy'
    - 'force:source:deploy'
    - 'SFDX_AUTH_URL'
    - '.sfdx/'
    - '.sf/'
    - 'sfdx-scanner'
    - 'apiVersion in *-meta.xml'
owns:
  - apex-sharing-declaration
  - apex-crud-fls-enforcement
  - soql-sosl-injection
  - apex-entry-point-exposure
  - flow-run-context-and-authz
  - lwc-aura-vf-output-sinks
  - salesforce-redirect-and-trusted-sites
  - named-and-external-credentials
  - connected-app-configuration
  - permission-set-and-profile-grants
  - guest-user-and-site-exposure
  - salesforce-platform-logging-surface
  - shield-encryption-caveats
  - sfdx-deploy-exposure
  - agentforce-action-authorization
  - lwc-client-state-exposure
defers:
  injection-sql-nosql-orm: web-and-api
  injection-command-and-template: web-and-api
  deserialization-and-xxe: web-and-api
  xss-and-output-encoding: web-and-api
  security-headers-and-csp: web-and-api
  cors-policy: web-and-api
  session-and-cookie-management: web-and-api
  open-redirect: web-and-api
  mass-assignment-and-parameter-binding: web-and-api
  tls-and-certificate-validation: crypto-and-key-management
  oauth-oidc-flow-correctness: crypto-and-key-management
  jwt-jws-and-jwks-verification: crypto-and-key-management
  saml-assertion-validation: crypto-and-key-management
  symmetric-encryption-and-nonce-handling: crypto-and-key-management
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  ci-secret-and-token-handling: cicd-and-supply-chain
  artifact-signing-and-provenance-emission: cicd-and-supply-chain
  pipeline-scanner-gating: cicd-and-supply-chain
  iam-policy-and-privilege-scope: cloud-and-iac
  managed-secret-service-configuration: cloud-and-iac
  kms-key-lifecycle-and-policy: cloud-and-iac
  prompt-injection: llm-and-ai
  rag-retrieval-authorization: llm-and-ai
  tool-call-authority-and-mediation: llm-and-ai
  secrets-in-mobile-binary: mobile-app-security
  platform-keystore-key-custody: mobile-app-security
  phi-classification: hipaa-and-phi
  phi-access-audit-controls: hipaa-and-phi
  hipaa-policy-documentation-retention: hipaa-and-phi
  phi-severity-uplift: hipaa-and-phi
  lawful-basis-and-consent-capture: privacy-and-data-protection
  dsr-fulfillment-mechanics: privacy-and-data-protection
  pci-scope-and-cardholder-data: privacy-and-data-protection
  personal-data-severity-uplift: privacy-and-data-protection
  stride-decomposition: threat-modeling
  trust-boundary-inventory: threat-modeling
frameworks:
  - salesforce-secure-coding-guide
  - salesforce-lightning-web-security
  - appexchange-security-review
  - owasp-api-top-10
  - cwe
severity_floor: low
---

## Scope

This lens audits code and metadata that runs on the Salesforce platform: Apex classes and triggers, Lightning Web Components, Aura components, Visualforce pages, Flows, and the declarative metadata that governs access — profiles, permission sets, sharing rules, sites and networks, connected apps, named and external credentials, trusted sites and remote site settings.

The platform's security model does not map onto the generic web model, and the mismatch is where the bugs live. Three facts drive everything below:

- **Sharing, object permissions (CRUD) and field-level security (FLS) are three separate controls.** `with sharing` enforces only the first. A class can be `with sharing` and still hand a user every field on a record they were never meant to read.
- **Apex runs in system mode by default.** Object permissions, FLS and sharing are all off unless the code opts in — via user mode, `Security.stripInaccessible`, `WITH SECURITY_ENFORCED`, or explicit describe checks. `with sharing` opts into one third of that.
- **The client is not a boundary.** An `@AuraEnabled` method, a `@RestResource`, an `@InvocableMethod` and a Visualforce controller action are all callable without the component that was written to call them.

### Owns

| Topic | What that means here |
|---|---|
| `apex-sharing-declaration` | `with` / `without` / `inherited sharing`, the entry-point default, and which objects sharing reaches at all. |
| `apex-crud-fls-enforcement` | User mode, `Security.stripInaccessible`, `WITH SECURITY_ENFORCED`, describe checks, and the write side where a missing check becomes privilege escalation. |
| `soql-sosl-injection` | The platform variant of query injection: `Database.query`, `Database.getQueryLocator`, `Search.query`, bind variables, and what `String.escapeSingleQuotes` does and does not cover. |
| `apex-entry-point-exposure` | `@AuraEnabled`, `@RestResource`, `@InvocableMethod`, `webservice static`, Visualforce controller actions — reachability, the identity that reaches them, and what leaks out of them on error. |
| `flow-run-context-and-authz` | Which context a Flow actually runs in, what "with sharing" does and does not enforce there, and unfiltered Get Records elements. |
| `lwc-aura-vf-output-sinks` | `lwc:dom="manual"` plus `innerHTML`, `aura:unescapedHtml`, `apex:outputText escape="false"`, `{!$CurrentPage.parameters}`. |
| `salesforce-redirect-and-trusted-sites` | Platform redirect parameters (`retURL`, `startURL`), CSP Trusted Sites, Remote Site Settings breadth. |
| `named-and-external-credentials` | Callout credentials: hardcoded endpoints and tokens, and where secrets are stored on-platform (custom settings, custom metadata, static resources). |
| `connected-app-configuration` | OAuth scopes, IP relaxation, refresh-token policy, and the certificate behind a JWT bearer flow. |
| `permission-set-and-profile-grants` | Platform privilege scope: object and field permissions, View All Fields (an FLS bypass, not a sharing one), View All / Modify All, system permissions, permission-set assignment from code. |
| `guest-user-and-site-exposure` | Experience Cloud and Salesforce Sites: what the unauthenticated guest user can reach. |
| `salesforce-platform-logging-surface` | `System.debug`, exception content returned to a caller, and whether record-level read auditing exists on this org at all. |
| `shield-encryption-caveats` | What Shield Platform Encryption and classic Encrypted Text do and do not protect against. |
| `sfdx-deploy-exposure` | Auth URLs, `.sfdx`/`.sf` directories, retrieved metadata and deploy commands in the repository. |
| `agentforce-action-authorization` | Which identity an agent action runs as, and whether the Apex or Flow behind it enforces anything. |
| `lwc-client-state-exposure` | Sensitive values the platform puts in the browser: tracked component state, `cacheable=true` wire results, and client storage written from a component. |

### Does not own

Do not raise findings on these. Where the code shows one, note it in the candidate's `impact` as an aggravator and hand it to the owning lens with the file and line.

- **web-and-api** — `injection-sql-nosql-orm`, `injection-command-and-template`, `deserialization-and-xxe`, `xss-and-output-encoding`, `security-headers-and-csp`, `cors-policy`, `session-and-cookie-management`, `open-redirect`, `mass-assignment-and-parameter-binding`. Two of these are easy to file here by accident, so they are called out:
  - **`mass-assignment-and-parameter-binding` is web-and-api's.** The generic finding — "a caller-supplied payload set a field the caller was not entitled to set" — belongs there. What stays here is the platform half: DML executed in **system mode** over a caller-supplied SObject, so FLS never runs at all. That is `apex-crud-fls-enforcement`. One defect, one finding: do not file both.
  - **`application-log-and-url-content` is web-and-api's** — what ends up in a log line or a URL. This lens owns the platform-specific surface instead (`salesforce-platform-logging-surface`): debug logs, exception payloads returned to a client, and whether the org has any record-level read auditing.
- **crypto-and-key-management** — `tls-and-certificate-validation`, `oauth-oidc-flow-correctness`, `jwt-jws-and-jwks-verification`, `saml-assertion-validation`, `symmetric-encryption-and-nonce-handling`. Cipher mode and nonce handling in `Crypto.*` calls, TLS validation, and the correctness of an OAuth or SAML flow. This lens owns where the *credential* lives and how the connected app is *configured*.
- **cicd-and-supply-chain** — `dependency-pinning-and-lockfiles`, `ci-secret-and-token-handling`, `artifact-signing-and-provenance-emission`, `pipeline-scanner-gating`. Including how a CI secret is injected, and whether `sfdx-scanner` gates the pipeline. This lens owns what the *repository* exposes (`sfdx-deploy-exposure`).
- **cloud-and-iac** — `iam-policy-and-privilege-scope`, `managed-secret-service-configuration`, `kms-key-lifecycle-and-policy`. Cloud IAM is not platform permissions; the two are graded differently and must not be merged.
- **llm-and-ai** — `prompt-injection`, `rag-retrieval-authorization`, `tool-call-authority-and-mediation`. For an agent action, that lens owns whether the instruction can be subverted and whether retrieval is filtered; this lens owns which identity the action executes as and what the Apex behind it enforces.
- **mobile-app-security** — `secrets-in-mobile-binary`, `platform-keystore-key-custody`. Including a connected app's consumer secret embedded in a mobile build.
- **hipaa-and-phi** — `phi-classification`, `phi-access-audit-controls`, `hipaa-policy-documentation-retention`, `phi-severity-uplift`. Whether a field is PHI, and the uplift that follows, are decided there. This lens reports whether the platform can produce a record-level read audit at all.
- **privacy-and-data-protection** — `lawful-basis-and-consent-capture`, `dsr-fulfillment-mechanics`, `pci-scope-and-cardholder-data`, `personal-data-severity-uplift`.
- **threat-modeling** — `stride-decomposition`, `trust-boundary-inventory`.

One boundary with no defers entry, stated so it is not double-filed: the generic cross-site request forgery class is `csrf` in web-and-api. What stays here is the platform shape — a state-changing controller action bound to page load via `<apex:page action="...">`, which is a GET-triggered write. File it as `apex-entry-point-exposure`.

### What cannot be determined from a repository

State these as assumptions with a verification step, never as findings.

- **Org-wide defaults for *standard* objects.** Whether an object's OWD is Private or Public Read/Write decides whether `without sharing` means anything at all. For **custom objects this is repo-visible and you must read it** — `<sharingModel>` and `<externalSharingModel>` sit in `objects/X__c/X__c.object-meta.xml`, and "OWD unknown" is not an available answer there. For standard objects the OWD is Sharing Settings configuration and is not reliably present in a retrieved project. Either way the retrieved value is evidence, not proof: an administrator can change it in Setup and the repository goes stale without a diff.
- **Who actually holds a permission set or profile.** The repository shows what a permission set *grants*; assignment is runtime data.
- **The org's API version.** `sfdx-project.json` `sourceApiVersion` and each `*-meta.xml` `<apiVersion>` are what the code is compiled against and are the best available evidence, but the org can be ahead.
- **Whether Event Monitoring or Field Audit Trail is licensed.** Both are add-ons. Their absence is not visible in source, and their presence changes whether a read-audit finding stands.
- **The live guest-user posture.** Whether guest record access hardening is in force, and which permission sets are assigned to the guest user, are org settings.
- **Whether a `without sharing` declaration is justified.** A comment is evidence of intent, not a control. Say which it is.

## Activation coverage

Salesforce source and metadata families are not interchangeable. Coverage below
states which ones have measured positive and clean paths.

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| force-app repository umbrella | PARTIAL | `sfdx-deploy-exposure` | The umbrella activates all Salesforce source and metadata; the narrower rows below determine actual coverage |
| Apex classes, triggers and scripts | COVERED | `apex-entry-point-exposure` | fixture:V-012 |
| LWC source and UI API signals | COVERED | `lwc-aura-vf-output-sinks` | detector:lwc-aura-vf-output-sinks |
| Aura and Visualforce source | PARTIAL | `lwc-aura-vf-output-sinks` | Dedicated output and parameter checks exist; component semantics and fixture coverage are incomplete |
| Flow metadata | PARTIAL | `flow-run-context-and-authz` | Run-context and authorization checks exist; Flow graph and invoked-action coverage remain manual |
| Object, permission-set, permission-group, profile and sharing metadata | COVERED | `permission-set-and-profile-grants` | fixture:V-013 |
| Credential, trusted-site, connected-app, custom metadata and settings surfaces | PARTIAL | `named-and-external-credentials` | Dedicated credential, redirect and connected-app checks exist; deployed secret values remain external |
| Sites and Experience Cloud network metadata | PARTIAL | `guest-user-and-site-exposure` | Guest-access and sharing checks exist; org-side membership and publication remain external |
| Static resources | PARTIAL | `lwc-aura-vf-output-sinks` | Bundle and output-sink checks exist; generated and vendored content needs provenance-aware reading |
| SFDX project, deployment tooling and local auth artifacts | PARTIAL | `sfdx-deploy-exposure` | Repository and secret-artifact checks exist; org-side deployment behavior remains external |
| package.xml and .forceignore | NOT ASSESSED | — | Activation or repository inventory only; no dedicated security semantics |

## Checklist

### 0. Highest-yield sweeps

Run these first, scoped to the source directory, and treat every hit as a candidate to trace rather than as a finding. Every repository traversal carries `--hidden`: ripgrep prunes hidden directories before applying globs, and the auth artifacts named by the final sweep live under `.sfdx/` and `.sf/`. `--hidden` still excludes `.git`, so it needs no companion exclusion.

```bash
# entry points — the public API surface of the org
rg -n --hidden --glob '**/force-app/**/*.cls' '@AuraEnabled|@RestResource|@InvocableMethod|webservice static' .

# dynamic query construction
rg -n --hidden --glob '**/force-app/**/*.cls' 'Database\.query\(|Database\.getQueryLocator\(|Search\.query\(' .

# sharing: declared without, and declared not at all
rg -n --hidden --glob '**/force-app/**/*.cls' 'without sharing' .
rg --hidden --files-without-match --glob '**/force-app/**/*.cls' 'with sharing|without sharing|inherited sharing' .

# write-side escalation sinks
rg -n --hidden --glob '**/force-app/**/*.cls' "\.put\('|OwnerId\s*=|RecordTypeId\s*=|JSON\.deserialize\(|insert new \w+Share\b|insert new PermissionSetAssignment" .

# system permissions and object-level grants, granted declaratively.
# One --glob per metadata suffix, repeated. NOT a '{profiles,permissionsets}'
# brace alternate — see the note below the block before shortening these.
rg -n --hidden --glob '**/force-app/**/*.profile-meta.xml' --glob '**/force-app/**/*.permissionset-meta.xml' --glob '**/force-app/**/*.permissionsetgroup-meta.xml' '<name>(ViewAllData|ModifyAllData|AuthorApex|ApiEnabled|CustomizeApplication|ManageUsers)</name>' .
rg -n --hidden --glob '**/force-app/**/*.profile-meta.xml' --glob '**/force-app/**/*.permissionset-meta.xml' '<(viewAllFields|viewAllRecords|modifyAllRecords)>true</' .

# output sinks and platform redirect parameters
rg -n --hidden --glob '**/force-app/**' 'lwc:dom="manual"|aura:unescapedHtml|escape="false"|\{!\$CurrentPage\.parameters' .
rg -n --hidden --glob '**/force-app/**' "getParameters\(\)\.get\('(retURL|startURL)'\)" .

# credentials and deploy exposure
rg -n --hidden --glob '**/force-app/**/*.cls' "setHeader\('Authorization'" .

# ...and the shape a literal-only credential sweep reads as clean: the endpoint is
# a correct Named Credential and the secret is read at runtime out of the data
# model. Run all three and read them together with the sweep above.
rg -n --hidden --glob '**/force-app/**/*.cls' "setEndpoint\('callout:" .
rg -n --hidden --glob '**/force-app/**/*.cls' 'getOrgDefaults\(\)|getInstance\(|getValues\(|__mdt\b' .
rg -n --hidden --glob '**/force-app/**/objects/**/*.object-meta.xml' '<customSettingsType>|<visibility>' .

rg -n --hidden 'force://|SFDX_AUTH_URL|\.sfdx/|\.sf/' .
```

**Two of these sweeps must not be tidied, and this is why.** The permission-grant pair uses a repeated `--glob` rather than a `{profiles,permissionsets}` brace alternate because **`grep --include` does not support brace expansion**, and `grep` is the fallback the moment `rg` turns out to be a shell function rather than a binary on `PATH` — which is a live condition, not a hypothetical. Under `grep` a brace glob matches zero files, exits 1, prints nothing to stderr, and is indistinguishable from an org with no over-broad grants. These two sweeps are what this lens's two highest declarative findings rest on, so a silent zero here clears a real permission set. The repeated form transliterates one-for-one — `grep -rnE --include='*.profile-meta.xml' --include='*.permissionset-meta.xml' '<(viewAllFields|viewAllRecords|modifyAllRecords)>true</' force-app/` — with the directory scoping moving to `grep`'s path argument and only the suffix staying in the glob. Verify the engine before trusting either result: run one pattern you have read with your own eyes and require exit 0, then read exit 1 as "ran, found nothing" and anything else as no verdict.

`viewAllFields` is in that second pattern deliberately and is the element most often missing from a hand-written version of it. It is also the newest of the three, so a project retrieved at an older API version may not carry the element at all — its absence from the files is not evidence the permission is ungranted in the org.

The credential sweeps are four lines because the finding is rarely on one line. A `setHeader('Authorization'` hit whose second argument is **not** a literal is not cleared by that fact: pivot from it to the expression's source, and if that source is a custom setting or custom metadata field, to the field's container object metadata and its `<visibility>`. Item 10 states the pivot in full; §0's job is to produce all four hit lists so the auditor has the container to pivot *to*.

The sink list in the fifth sweep replaces a grep for a private setter name. Java-style accessor names are not a Salesforce convention, so a grep for one fires in exactly one codebase and reports clean everywhere else. The platform sinks are direct field assignment, `SObject.put`, deserialization onto an SObject, and the two records that grant access outright — a `__Share` row and a `PermissionSetAssignment`.

### 1. Sharing declaration (`apex-sharing-declaration`)

**The default is inheritance, not `without sharing`.** A class with no declaration runs in the sharing context of whatever called it. It defaults to *without* sharing only when it is the **entry point** — when nothing above it on the stack set a context. Entry points are `@AuraEnabled`, `@RestResource`, `@InvocableMethod`, `webservice static`, a Visualforce controller or extension, a trigger, `execute()` on a Queueable, Batchable or Schedulable, a `@future` method, an email service, and anonymous Apex.

- `with sharing` — enforces record-level sharing: org-wide defaults, sharing rules, manual and Apex shares, the role hierarchy, and territory. **It does not enforce object permissions or FLS.** Treat "the class is `with sharing`" as answering one question out of three.
- `without sharing` — legitimate for system-level work: rollups and denormalization in trigger handlers, sharing recalculation, batch and queueable jobs, approval automation, integration paths. It is a finding when a user-supplied Id or filter crosses into it.
- `inherited sharing` — runs with the caller's context, and **when the class is itself the entry point it defaults to `with sharing`**. That is the reason the keyword exists, and it is the correct declaration for a shared selector or service layer.
- The trigger *itself* runs in system context, but the declaration on the handler it calls is **not** a no-op: code inside a `with sharing` handler invoked from a trigger does enforce sharing, and a handler with no declaration inherits the trigger's system context. So "the trigger handler lacks `with sharing`" is usually low-value — trigger work is normally system-level by design — but never treat it as unreachable. The question is whether the handler is *also* called from an entry point.

```detector
match: |
  public class CaseSearchController {
      @AuraEnabled(cacheable=true)
      public static List<Case> recentForAccount(Id accountId) {
          return [SELECT Id, CaseNumber, Subject, Description
                  FROM Case WHERE AccountId = :accountId];
      }
  }
nomatch: |
  public with sharing class CaseSearchController {
      @AuraEnabled(cacheable=true)
      public static List<Case> recentForAccount(Id accountId) {
          return [SELECT Id, CaseNumber, Subject, Description
                  FROM Case WHERE AccountId = :accountId WITH USER_MODE];
      }
  }
```

```detector
match: |
  public without sharing class OpportunityService {
      @AuraEnabled
      public static List<Opportunity> forAccount(Id accountId) {
          return [SELECT Id, Name, Amount, StageName
                  FROM Opportunity WHERE AccountId = :accountId];
      }
  }
nomatch: |
  public with sharing class OpportunityService {
      @AuraEnabled
      public static List<Opportunity> forAccount(Id accountId) {
          return [SELECT Id, Name, Amount, StageName
                  FROM Opportunity WHERE AccountId = :accountId WITH USER_MODE];
      }
  }
```

**Sharing does not exist for every object.** It has no effect on custom metadata types, custom settings, or platform events, and it has nothing to enforce on an object whose OWD is Public Read/Write.

**Establish the OWD from the repository before grading, because for custom objects it is there.** `objects/X__c/X__c.object-meta.xml` carries `<sharingModel>` — for a custom object the values you will see are `Private`, `Read`, `ReadWrite`, and `ControlledByParent` on a master-detail child — and `<externalSharingModel>`. Read both. "The OWD could not be established" is a legitimate answer only for a standard object, or where the object's metadata is not in the checkout — and in either case it is an assumption to write down, not a reason to drop to the fallback grade by default.

**`<externalSharingModel>` and the guest user are two different questions, and conflating them will make this lens contradict itself.** The external OWD governs **authenticated external** users — Experience Cloud and portal license holders: Customer Community, Customer Community Plus, Partner Community, and legacy portal users. The **guest** user is not one of them for grading purposes: the guest floor in item 7 forces guest record access to Private and caps it at Read through criteria-based rules, and that floor overrides the external OWD. So a permissive `<externalSharingModel>` widens access for *logged-in community members*, not for anonymous visitors. It still matters to a guest-facing audit for a different reason: it is the value that tells you the object is exposed outside the internal org at all, and any site that serves authenticated community users as well as anonymous ones is graded on it directly.

```detector
match: |
  <!-- objects/Invoice__c/Invoice__c.object-meta.xml -->
  <CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">
      <label>Invoice</label>
      <sharingModel>ReadWrite</sharingModel>
      <externalSharingModel>Read</externalSharingModel>
  </CustomObject>
nomatch: |
  <!-- objects/Invoice__c/Invoice__c.object-meta.xml -->
  <CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">
      <label>Invoice</label>
      <sharingModel>Private</sharingModel>
      <externalSharingModel>Private</externalSharingModel>
  </CustomObject>
```

### 2. Testing sharing-sensitive code (`apex-sharing-declaration`)

**`System.runAs` is test-context only.** The compiler rejects it outside a test method, so code containing it in a non-test class cannot deploy. A "found `System.runAs` in production code" finding is not reachable: what you are looking at is a test class, a comment, or a string. Do not file it.

The real bug class is the inverse — privileged paths that are only ever exercised as the admin who runs the test suite:

- Tests of an entry point that never wrap the call in `System.runAs(someRestrictedUser)`, so the sharing and FLS behavior the class depends on is never exercised.
- `@isTest(SeeAllData=true)` on a test covering sharing-sensitive code. It hands the test the org's real data under the test-running user's access and destroys the test's value as evidence.
- Note the limit before relying on it: `System.runAs` changes the record-sharing context. Do not assume it reproduces every permission check; assert on the *observable result* — records absent, fields unset — rather than on the fact that the block ran.

```detector
match: |
  @isTest(SeeAllData=true)
  private class OpportunityServiceTest {
      @isTest
      static void returnsOpportunities() {
          Account a = [SELECT Id FROM Account LIMIT 1];
          Test.startTest();
          List<Opportunity> result = OpportunityService.forAccount(a.Id);
          Test.stopTest();
          Assert.isFalse(result.isEmpty());
      }
  }
nomatch: |
  @isTest
  private class OpportunityServiceTest {
      @isTest
      static void hidesOpportunitiesTheRunningUserCannotSee() {
          User minimal;
          // User is a setup object. Inserting one in the same transaction as
          // non-setup DML raises MIXED_DML_OPERATION, so the setup-object DML
          // is isolated inside a runAs of the current user. This is the
          // canonical pattern and its absence is why so many sharing tests
          // were never written.
          System.runAs(new User(Id = UserInfo.getUserId())) {
              Profile p = [SELECT Id FROM Profile
                           WHERE Name = 'Minimum Access - Salesforce' LIMIT 1];
              minimal = new User(
                  ProfileId = p.Id, LastName = 'Minimal', Alias = 'min',
                  Username = 'minimal.user@example.com.invalid',
                  Email = 'minimal.user@example.com',
                  TimeZoneSidKey = 'America/New_York', LocaleSidKey = 'en_US',
                  EmailEncodingKey = 'UTF-8', LanguageLocaleKey = 'en_US');
              insert minimal;
          }

          Account a = TestFixtures.accountOwnedByAnotherUser();
          System.runAs(minimal) {
              Test.startTest();
              List<Opportunity> result = OpportunityService.forAccount(a.Id);
              Test.stopTest();
              Assert.isTrue(result.isEmpty(), 'sharing was not enforced');
          }
      }
  }
```

A test that creates the user and then touches a business object in one transaction fails with `MIXED_DML_OPERATION` before it can assert anything. That failure mode is worth naming, because the usual reaction to it is to delete the `runAs` rather than to isolate the setup DML — which converts a sharing test back into an admin-context test that proves nothing.

### 3. CRUD and FLS enforcement (`apex-crud-fls-enforcement`)

Four mechanisms, and they are not interchangeable. State which one the code uses and what it actually covers.

| Mechanism | Object permissions | FLS | Sharing | Failure mode |
|---|---|---|---|---|
| `WITH USER_MODE` in SOQL | yes | yes | yes | throws |
| `AccessLevel.USER_MODE` on a `Database` DML call, or `insert as user records;` | yes | yes | yes | throws |
| `WITH SECURITY_ENFORCED` in SOQL | yes | yes | **no** | throws, all-or-nothing |
| `Security.stripInaccessible(...)` | yes | yes | no | strips silently |
| Describe checks (`isAccessible()` and siblings) | manual | manual | no | whatever the author wrote |

**User mode is SOQL-only as a query clause; DML has a different mechanism.** `WITH USER_MODE` and `WITH SYSTEM_MODE` are SOQL clauses. For DML the equivalents are the `AccessLevel` argument — `Database.insert(records, AccessLevel.USER_MODE)`, `Database.update`, `Database.upsert`, `Database.delete`, `Database.merge`, `Database.undelete` — and the statement form `insert as user records;` / `insert as system records;`. There is no `WITH USER_MODE` for DML, and an auditor who asks for one is asking for something that does not compile.

**Version.** User mode and the `AccessLevel` enum arrived in **API 56.0 (Winter '23)** and reached GA in **57.0 (Spring '23)**. It is emphatically not API 48.0. Recommending it to a team whose `sourceApiVersion` is below 56.0 recommends a clause that will not compile — read `sfdx-project.json` before prescribing it, and fall back to `Security.stripInaccessible` plus `with sharing` for older projects.

**What each one misses:**

- `WITH SECURITY_ENFORCED` enforces object and field permissions on fields in the `SELECT` and `WHERE` clauses and in subqueries, but **not sharing**, and it throws rather than stripping. It also does not reach polymorphic lookups or `TYPEOF`. A class that is `without sharing` and uses `WITH SECURITY_ENFORCED` still bypasses record access.
- `Security.stripInaccessible` removes inaccessible fields from the returned `SObjectAccessDecision`; check `getRemovedFields()` rather than assuming it removed nothing. Note that it nulls fields **out of the collection you read from the decision** — code that keeps using the original list gets no protection.
- Describe checks are only as good as their coverage. One `isAccessible()` on the object does not cover the fields.
- User mode **overrides the class's sharing declaration**. A `without sharing` class running a `WITH USER_MODE` query enforces sharing for that query.

```detector
match: |
  @AuraEnabled
  public static void applyStageChange(List<Opportunity> opps) {
      update opps;
  }
nomatch: |
  @AuraEnabled
  public static void applyStageChange(List<Opportunity> opps) {
      Database.update(opps, AccessLevel.USER_MODE);
  }
```

```detector
match: |
  @AuraEnabled(cacheable=true)
  public static List<Contact> forAccount(Id accountId) {
      return [SELECT Id, Name, Email, Phone, SSN__c
              FROM Contact WHERE AccountId = :accountId];
  }
nomatch: |
  @AuraEnabled(cacheable=true)
  public static List<Contact> forAccount(Id accountId) {
      List<Contact> rows = [SELECT Id, Name, Email, Phone, SSN__c
                            FROM Contact WHERE AccountId = :accountId];
      SObjectAccessDecision decision =
          Security.stripInaccessible(AccessType.READABLE, rows);
      return (List<Contact>) decision.getRecords();
  }
```

**The write side is where a missing check becomes escalation.** Write-side FLS bypass is worse than read-side because it lets a caller set a field they could never set through the UI. The field classes that matter:

- **Fields that gate a decision** — an approval or status flag, `Case.Status`, `Opportunity.StageName`, a stage or state field consumed by automation.
- **Fields that determine record access** — `OwnerId`, `RecordTypeId`, and any field a criteria-based sharing rule reads, because writing it silently widens who can see the record.
- **Monetary fields** — `Opportunity.Amount`, a discount or rate field.

`Profile` is **not** one of them. There is no writable `Profile` field on a record. Profile assignment is `User.ProfileId`, and DML on `User` is gated by the **"Manage Users"** permission, not by FLS — so escalation by reassigning a profile is a `permission-set-and-profile-grants` finding, not an FLS finding. Profile still matters here for what it does govern: object permissions, field permissions, Apex class access, page-layout and record-type assignment, and login IP ranges.

```detector
match: |
  @AuraEnabled
  public static void saveCase(Case record, Map<String, Object> extraFields) {
      for (String fieldName : extraFields.keySet()) {
          record.put(fieldName, extraFields.get(fieldName));
      }
      update record;
  }
nomatch: |
  @AuraEnabled
  public static void saveCase(Id caseId, String subject, String description) {
      Case record = new Case(Id = caseId, Subject = subject, Description = description);
      Database.update(record, AccessLevel.USER_MODE);
  }
```

```detector
match: |
  @RestResource(urlMapping='/case/*')
  global with sharing class CaseIntake {
      @HttpPost
      global static void create() {
          Case c = (Case) JSON.deserialize(
              RestContext.request.requestBody.toString(), Case.class);
          insert c;
      }
  }
nomatch: |
  @RestResource(urlMapping='/case/*')
  global with sharing class CaseIntake {
      global class Payload {
          public String subject;
          public String description;
      }

      @HttpPost
      global static void create() {
          Payload p = (Payload) JSON.deserialize(
              RestContext.request.requestBody.toString(), Payload.class);
          Database.insert(new Case(Subject = p.subject, Description = p.description),
                          AccessLevel.USER_MODE);
      }
  }
```

Where a manual describe check is the chosen mechanism, it must name the object and the field:

```detector
match: |
  if (Schema.SObjectType.Account.isUpdateable()) {
      acct.AnnualRevenue = newRevenue;
      update acct;
  }
nomatch: |
  if (Schema.SObjectType.Account.fields.AnnualRevenue.isUpdateable()) {
      acct.AnnualRevenue = newRevenue;
      Database.update(acct, AccessLevel.USER_MODE);
  }
```

### 4. SOQL and SOSL injection (`soql-sosl-injection`)

Dynamic queries built by concatenation are injectable. The safe constructions, in preference order — four alternative fragments, each complete on its own, not one block:

```apex
// 1. Static SOQL with a bind — always safe, and takes a user-mode clause.
List<Account> rows = [SELECT Id, Name FROM Account WHERE Name = :searchTerm WITH USER_MODE];

// 2. Dynamic SOQL with a bind map.
String q = 'SELECT Id, Name FROM Account WHERE Name = :searchTerm';
List<Account> rows = Database.queryWithBinds(
    q, new Map<String, Object>{ 'searchTerm' => searchTerm }, AccessLevel.USER_MODE);

// 3. Dynamic SOQL binding an in-scope variable.
String searchTerm = normalize(input);
List<Account> rows = Database.query(
    'SELECT Id, Name FROM Account WHERE Name = :searchTerm', AccessLevel.USER_MODE);

// 4. Last resort — escaping. The escaped value must be the one interpolated.
String safeTerm = String.escapeSingleQuotes(searchTerm);
String q = 'SELECT Id, Name FROM Account WHERE Name = \'' + safeTerm + '\'';
List<Account> rows = Database.query(q, AccessLevel.USER_MODE);
```

`Database.queryWithBinds` and its `getQueryLocatorWithBinds` / `countQueryWithBinds` siblings arrived in **API 57.0 (Spring '23)** — one release after the `WITH USER_MODE` clause, so a project pinned at 56.0 has user mode but not the bind-map methods and must use a static SOQL bind or an in-scope variable bind instead.

**Four things `String.escapeSingleQuotes` does not do**, and each is a place auditors wave a real bug through:

1. **It does nothing outside a quoted literal.** An `ORDER BY` field, a field list, an object name, a `LIMIT` value or an unquoted numeric, boolean, date or Id comparison is not protected by escaping quotes. Those need an allowlist, or coercion through `Integer.valueOf` / `Id.valueOf` / `Decimal.valueOf`, which cannot carry query syntax.
2. **It does not escape `%` or `_`.** In a `LIKE` clause the caller can still wildcard the whole predicate.
3. **It is not applied by being called.** The single highest-value grep in this section is a call to `String.escapeSingleQuotes` whose result is assigned to a variable that the query string then does not use. This looks correct on a skim and is fully vulnerable.
4. **A colon inside a quoted literal is not a bind.** `'... WHERE Name = \':' + x + '\''` contains a colon and binds nothing.

SOSL has the same shape: `Search.query(...)` with a concatenated `FIND` term, where the escaping helper is `String.escapeSingleQuotes` for the quoted form and the `FIND :term` bind for the safe one.

```detector
match: |
  String safeTerm = String.escapeSingleQuotes(searchTerm);
  String q = 'SELECT Id, Name FROM Account WHERE Name = \'' + searchTerm + '\'';
  List<Account> rows = Database.query(q);
nomatch: |
  String q = 'SELECT Id, Name FROM Account WHERE Name = :searchTerm';
  List<Account> rows = Database.queryWithBinds(
      q, new Map<String, Object>{ 'searchTerm' => searchTerm }, AccessLevel.USER_MODE);
```

```detector
match: |
  String sortField = ApexPages.currentPage().getParameters().get('sort');
  String q = 'SELECT Id, Name FROM Account ORDER BY '
      + String.escapeSingleQuotes(sortField);
  List<Account> rows = Database.query(q);
nomatch: |
  Set<String> sortable = new Set<String>{ 'Name', 'CreatedDate', 'AnnualRevenue' };
  String sortField = ApexPages.currentPage().getParameters().get('sort');
  if (!sortable.contains(sortField)) {
      sortField = 'Name';
  }
  List<Account> rows = Database.query(
      'SELECT Id, Name FROM Account WITH USER_MODE ORDER BY ' + sortField);
```

### 5. Entry-point exposure (`apex-entry-point-exposure`)

**Get the `@AuraEnabled` reachability story right, because the wrong version is checkable and a Salesforce developer will check it.**

- `@AuraEnabled` methods are **not** exposed on the REST API or the Tooling API. Only `@RestResource` is on `/services/apexrest/`, and that additionally requires the caller to have "API Enabled".
- The real path is the **Aura endpoint**: a `POST` to `/aura` — `/s/sfsites/aura` on an Experience Cloud site — carrying a message whose action descriptor is the literal `aura://ApexActionController/ACTION$execute`, plus a session cookie and the page's CSRF token. Both LWC imperative and `@wire` calls and Aura component controllers travel this route. Any authenticated user can lift the token from a Lightning page and call the method directly with arbitrary arguments; the component that was written to call it is not in the path.
- Anonymous Apex is a third route, but it requires **"Author Apex"** — a permission this lens separately treats as a privilege-escalation grant, so it is not the interesting case.
- **The platform does check Apex Class Access** for entry-point classes. So "any authenticated user can call this" holds where class access is granted broadly — via a widely assigned permission set, or on the profile — and not otherwise. Confirm the grant before writing the claim; the grep for it is `<classAccesses>` in the profile and permission-set metadata.
- `@AuraEnabled(cacheable=true)` is read-only — the platform refuses DML — and its result is cached client-side. It is still an endpoint.

**Authorization is the method's job.** Callability alone is not the finding: a `with sharing` method in user mode that takes no Id and returns the caller's own records is correctly scoped by the platform. Write the finding when the method accepts an Id or filter that widens scope beyond the caller's own records, runs in system mode, performs a privileged action (ownership change, approval, share insert, permission-set assignment), or is reachable by the site guest user.

```detector
match: |
  @AuraEnabled
  public static void reassign(Id recordId, Id newOwnerId) {
      update new Case(Id = recordId, OwnerId = newOwnerId);
  }
nomatch: |
  @AuraEnabled
  public static void reassign(Id recordId, Id newOwnerId) {
      if (!FeatureManagement.checkPermission('Your_Custom_Permission_API_Name')) {
          throw new AuraHandledException('You cannot reassign this record.');
      }
      Database.update(new Case(Id = recordId, OwnerId = newOwnerId),
                      AccessLevel.USER_MODE);
  }
```

**What comes back out on the error path.** Throwing a raw exception out of an `@AuraEnabled` method returns the exception type, the message, the failing SOQL and often field values to the caller's browser. `AuraHandledException` returns only the message you set.

```detector
match: |
  @AuraEnabled
  public static List<Account> search(String term) {
      try {
          return Database.query(buildQuery(term), AccessLevel.USER_MODE);
      } catch (Exception e) {
          throw e;
      }
  }
nomatch: |
  @AuraEnabled
  public static List<Account> search(String term) {
      try {
          return Database.queryWithBinds(NAME_QUERY,
              new Map<String, Object>{ 'term' => term }, AccessLevel.USER_MODE);
      } catch (Exception e) {
          System.debug(LoggingLevel.ERROR, e.getStackTraceString());
          throw new AuraHandledException('Search is unavailable.');
      }
  }
```

**Visualforce controller actions fire on page load.** `<apex:page action="{!doSomething}">` runs the controller method on a GET, which makes any state change in it reachable by a link. This is the platform's shape of the CSRF class; the generic slug is web-and-api's, so file it here as an entry-point defect and do not file it twice.

```detector
match: |
  <apex:page controller="ApprovalController" action="{!approve}">
      <apex:outputText value="Approved." />
  </apex:page>
nomatch: |
  <apex:page controller="ApprovalController">
      <apex:form>
          <apex:commandButton action="{!approve}" value="Approve" />
      </apex:form>
  </apex:page>
```

Also enumerate `webservice static` methods (SOAP, and reachable with "API Enabled"), `@InvocableMethod` (reachable from Flow, the REST Actions API and agent actions — see item 12), and `@HttpGet` / `@HttpPost` handlers whose `urlMapping` contains a wildcard. A wildcard mapping means the path segment is caller-controlled, and code that parses an Id out of `RestContext.request.requestURI` is taking input from the URL whether or not it looks like a parameter.

```detector
match: |
  @RestResource(urlMapping='/account/*')
  global without sharing class AccountApi {
      @HttpGet
      global static Account read() {
          String id = RestContext.request.requestURI.substringAfterLast('/');
          return [SELECT Id, Name, AnnualRevenue FROM Account WHERE Id = :id];
      }

      webservice static void purge(Id accountId) {
          delete [SELECT Id FROM Account WHERE Id = :accountId];
      }
  }
nomatch: |
  @RestResource(urlMapping='/account/*')
  global with sharing class AccountApi {
      @HttpGet
      global static Account read() {
          Id accountId = Id.valueOf(
              RestContext.request.requestURI.substringAfterLast('/'));
          return [SELECT Id, Name, AnnualRevenue
                  FROM Account WHERE Id = :accountId WITH USER_MODE];
      }
  }
```

### 6. Flow run context (`flow-run-context-and-authz`)

**Record-triggered, scheduled and other autolaunched flows always run in system context.** User context is not selectable for them; it is the default for screen flows only. So "check whether the Flow runs in user context" is not a check that can be performed on a record-triggered flow, and an auditor who asks for it will be told the setting does not exist.

The lever that *does* exist is `runInMode` in the flow metadata:

- `SystemModeWithoutSharing` — access all data.
- `SystemModeWithSharing` — **enforces record-level access only.** It does **not** enforce object permissions or FLS. Choosing it does not close a field-level hole, and this is the single most common misreading of the setting.
- `DefaultMode` — context depends on how the flow was launched. For a **record-triggered, scheduled or autolaunched** flow that resolves to system context **without** sharing.

**Three metadata shapes, one runtime effect — and only one of them is the literal an auditor thinks to grep for.** A record-triggered flow runs system-context-without-sharing when `<runInMode>` says `SystemModeWithoutSharing`, when it says `DefaultMode`, **and** when the element is absent entirely. The absent case is what Flow Builder produces when nobody opens the advanced settings, so it is the most common of the three; the explicit `DefaultMode` case is written out by some tooling and by round-tripped retrieves. A detector keyed only to `SystemModeWithoutSharing` reads both of the other two as clean, which is the silent all-clear this lens exists to avoid.

Two sweeps are needed, because one cannot express both — plus a third that is not optional:

```bash
# absent element — the default, and the most likely shape
rg --hidden --files-without-match --glob '**/force-app/**/flows/*.flow-meta.xml' '<runInMode>' .

# explicit DefaultMode — same effect, but a files-without-match sweep cannot see it
rg -n --hidden --glob '**/force-app/**/flows/*.flow-meta.xml' '<runInMode>DefaultMode</runInMode>' .

# MANDATORY: partition the output of both sweeps above on process type before
# grading a single hit. Neither sweep can tell a screen flow from an autolaunched
# one, and for a screen flow the absent element means the OPPOSITE.
rg -n --hidden --glob '**/force-app/**/flows/*.flow-meta.xml' '<processType>' .
```

**`<processType>` decides what the absent element *means*, and grading the raw sweep output inflates the count.** The three-shapes rule above is a rule about autolaunched flows, and both sweeps return every flow in the project:

- `<processType>AutoLaunchedFlow</processType>` — record-triggered, scheduled and autolaunched. Absent `<runInMode>` or `DefaultMode` resolves to system context **without** sharing. This is the finding.
- `<processType>Flow</processType>` — a **screen flow**. User context is the platform default here, so absent `<runInMode>` or `DefaultMode` resolves to the *running user's* context, with sharing and with FLS. That is the safe shape, and it is not a finding at any severity. What still is one on a screen flow is an **explicit** `SystemModeWithoutSharing` or `SystemModeWithSharing`, because somebody chose it: a screen flow naming `SystemModeWithoutSharing` grades exactly like an autolaunched one.
- Legacy `Workflow` and `InvocableProcess` process types are Process Builder and run in system context. Treat them as `AutoLaunchedFlow`.

Measured on a real org, 3 of 15 hits from the absent-element sweep were screen flows, so grading the unpartitioned list would have inflated the finding count by 20% — and every one of those three would have been a High that a Salesforce developer could refute from the setting's own documentation, which costs the rest of the report.

Any flow field write that must respect FLS needs an Apex action running in user mode, or an explicit permission check in the flow. A Get Records element filtered only by a flow input variable is the platform's IDOR: in system context it returns whatever the filter matches, regardless of who triggered it.

```detector
match: |
  <!-- flows/Case_Escalation.flow-meta.xml — no runInMode element at all,
       which is DefaultMode, which for a record-triggered flow is
       system context WITHOUT sharing -->
  <Flow xmlns="http://soap.sforce.com/2006/04/metadata">
      <processType>AutoLaunchedFlow</processType>
      <start>
          <object>Case</object>
          <recordTriggerType>CreateAndUpdate</recordTriggerType>
          <triggerType>RecordAfterSave</triggerType>
      </start>
  </Flow>
nomatch: |
  <!-- flows/Case_Escalation.flow-meta.xml -->
  <Flow xmlns="http://soap.sforce.com/2006/04/metadata">
      <processType>AutoLaunchedFlow</processType>
      <runInMode>SystemModeWithSharing</runInMode>
      <start>
          <object>Case</object>
          <recordTriggerType>CreateAndUpdate</recordTriggerType>
          <triggerType>RecordAfterSave</triggerType>
      </start>
  </Flow>
```

Explicit `DefaultMode` is a third shape and needs its own detector, because the files-without-match sweep above cannot see it — the element is present, it just names the permissive default.

```detector
match: |
  <!-- flows/Case_Escalation.flow-meta.xml -->
  <Flow xmlns="http://soap.sforce.com/2006/04/metadata">
      <processType>AutoLaunchedFlow</processType>
      <runInMode>DefaultMode</runInMode>
      <start>
          <object>Case</object>
          <recordTriggerType>CreateAndUpdate</recordTriggerType>
          <triggerType>RecordAfterSave</triggerType>
      </start>
  </Flow>
nomatch: |
  <!-- flows/Case_Escalation.flow-meta.xml -->
  <Flow xmlns="http://soap.sforce.com/2006/04/metadata">
      <processType>AutoLaunchedFlow</processType>
      <runInMode>SystemModeWithSharing</runInMode>
      <start>
          <object>Case</object>
          <recordTriggerType>CreateAndUpdate</recordTriggerType>
          <triggerType>RecordAfterSave</triggerType>
      </start>
  </Flow>
```

The explicit permissive form is worth its own detector too, because a flow that names `SystemModeWithoutSharing` was configured that way on purpose and the finding is different — it needs the documented reason, not a default nobody chose.

```detector
match: |
  <!-- flows/Bulk_Reassign.flow-meta.xml -->
  <Flow xmlns="http://soap.sforce.com/2006/04/metadata">
      <processType>AutoLaunchedFlow</processType>
      <runInMode>SystemModeWithoutSharing</runInMode>
      <start>
          <object>Case</object>
          <recordTriggerType>CreateAndUpdate</recordTriggerType>
          <triggerType>RecordAfterSave</triggerType>
      </start>
  </Flow>
nomatch: |
  <Flow xmlns="http://soap.sforce.com/2006/04/metadata">
      <processType>AutoLaunchedFlow</processType>
      <runInMode>SystemModeWithSharing</runInMode>
      <start>
          <object>Case</object>
          <recordTriggerType>CreateAndUpdate</recordTriggerType>
          <triggerType>RecordAfterSave</triggerType>
      </start>
  </Flow>
```

And the screen-flow arm, which is the one the sweeps cannot express: here the discriminator is the process type, not the mode, and the absent element is the **nomatch**.

```detector
match: |
  <!-- flows/Member_Lookup.flow-meta.xml — a screen flow that names the
       permissive mode explicitly, so it was chosen rather than defaulted -->
  <Flow xmlns="http://soap.sforce.com/2006/04/metadata">
      <processType>Flow</processType>
      <runInMode>SystemModeWithoutSharing</runInMode>
      <screens>
          <name>Lookup</name>
      </screens>
  </Flow>
nomatch: |
  <!-- flows/Member_Lookup.flow-meta.xml — no runInMode element at all, which on
       a SCREEN flow is the running user's context, with sharing and with FLS.
       The identical absence on an AutoLaunchedFlow is the finding above. -->
  <Flow xmlns="http://soap.sforce.com/2006/04/metadata">
      <processType>Flow</processType>
      <screens>
          <name>Lookup</name>
      </screens>
  </Flow>
```

Also check: Update Records elements that write ownership, approval or role fields with no validation that the triggering user was entitled to; and HTTP Callout actions, which take the same named-credential guidance as Apex (item 9).

### 7. Experience Cloud and Site guest access (`guest-user-and-site-exposure`)

This is the platform's largest real-world exposure and the one an Apex-only review misses entirely. An Experience Cloud site or a Salesforce Site serves unauthenticated visitors as a single **guest user** with its own profile. Everything that profile can reach, the internet can reach — with no login, no rate limit worth the name, and no attribution beyond an IP address.

**First, find the guest profile.** None of this is auditable until you can point at the file, and the guest profile is not labelled "guest" by any rule you can rely on.

- **The reliable marker is the license.** A guest profile carries `<userLicense>Guest User License</userLicense>` in `profiles/*.profile-meta.xml`. Sweep for that before anything else:
  `rg -l --hidden --glob '**/force-app/**/profiles/*.profile-meta.xml' '<userLicense>Guest User License</userLicense>' .`
- **The naming convention corroborates it.** The default guest profile name is `<Site Name> Profile`, so `profiles/Customer Portal Profile.profile-meta.xml` pairs with a site named "Customer Portal". It is only a convention — it can be renamed — so use it to cross-check, never as the test.
- **The sites themselves are the other end, and which file exists depends on the site type.** `sites/*.site-meta.xml` enumerates what is published for **both** kinds of site; `<urlPathPrefix>` and `<siteGuestRecordDefaultOwner>` tell you the path and where guest-created records land. **`networks/*.network-meta.xml` exists only for an Experience Cloud site** — `<siteType>` in the site file names one of the community types, `ChatterNetworkPicasso` or `ChatterNetwork`. A classic Salesforce Site declares `<siteType>Visualforce</siteType>`, has no network file and never had one, so its absence is **not** a retrieve gap and must not be recorded as one. Read `<siteType>` first and ask for the network file only where the type says there is one; recording a missing file that cannot exist spends a finding on nothing and puts a wrong claim next to the real ones. A site in the checkout with no identifiable guest **profile** is a different matter and is a genuine retrieve gap — that is an assumption to record, not an absence of exposure.

**The platform baseline, and precisely what it does not cover.** Salesforce enforces a guest-access floor on current orgs: guest org-wide defaults are Private and cannot be relaxed, guest users can be granted at most **Read** access to records and only through **criteria-based** sharing rules, guest users cannot own records, and "View All Data" / "Modify All Data" cannot be granted to a guest profile.

**That floor is a *sharing* floor, and this is the load-bearing consequence.** Sharing is the control it strengthens, so wherever sharing does not apply, the floor does not reach. Item 1 already establishes where that is: custom metadata types, custom settings and platform events have no sharing model at all. A guest profile with read on a **custom metadata type** therefore reads every record of it, floor or no floor — and public custom settings are exempt from sharing *and* FLS by design (item 10), which is what turns "a secret in a custom setting" from an internal-exposure finding into a public one on any org with a live site. Check those object types first; they are the ones the floor silently does not cover.

The floor also does not bound:

- **Object and field permissions on the guest profile.** Read on an object plus a `without sharing` Apex class that queries it returns everything, and no sharing rule was involved.
- **Apex class access granted to the guest profile.** Every `@AuraEnabled` method on an enabled class is reachable over the site's Aura endpoint by an anonymous visitor.
- **Anything running in system mode.** A trigger, a `@future` or queueable path — and a Flow, but read `<processType>` before counting one, because the absent element means opposite things on the two types (item 6). An `AutoLaunchedFlow` with `<runInMode>` absent, at `DefaultMode`, or at `SystemModeWithoutSharing` escapes the floor and belongs here — including one fired by a record a guest just created through a site form. A **screen flow** (`<processType>Flow</processType>`) belongs here **only** where it names `SystemModeWithoutSharing` explicitly; with the element absent it runs as the guest user, with sharing and with FLS. A flow embedded on a site page is normally a screen flow, so that is the common case here rather than the corner. `SystemModeWithSharing` stays inside the sharing floor and is an FLS finding instead.
- **Enumeration.** A method that takes an email address, a case number or a record Id and returns matches is an oracle even when each individual response is "legitimate".

**The mechanism behind the publicized Experience Cloud leaks needs no custom Apex at all.** The guest user can invoke the platform's own built-in Aura controllers at `/s/sfsites/aura` — the standard list, record-UI and data-provider controllers that back stock Lightning components — using the same `aura://…/ACTION$…` descriptor shape as item 5. Those controllers ship with the platform, are always present, and are never in the repository. The only thing standing between an anonymous visitor and the records they return is the guest profile's object and field permissions plus the sharing floor.

Two audit consequences follow, and both invert the usual approach:

1. **A repository containing zero custom Apex can still leak an entire object.** "There is no guest-facing controller in this codebase" is not a clearance. Do not write one.
2. **The guest profile's object and field permissions *are* the control**, not a supporting detail. Every `objectPermissions` and `fieldPermissions` entry on that profile is a decision to publish, and must be read as one — line by line, against what the site actually needs to render.

The incident shape to hunt: an unauthenticated visitor reads records nobody intended to expose, because an object permission was granted on the guest profile to make one page work — and either a `without sharing` controller was enabled alongside it, or a stock controller needed nothing further.

The detector below holds the guest license constant in both arms, so what discriminates is the grant, not the profile. A `classAccesses` grant to a `without sharing` controller over a customer-data object is the finding; the same shape over published content is the site working as designed.

```detector
match: |
  <!-- profiles/Customer Portal Profile.profile-meta.xml -->
  <Profile xmlns="http://soap.sforce.com/2006/04/metadata">
      <userLicense>Guest User License</userLicense>
      <classAccesses>
          <apexClass>PortalCaseController</apexClass>
          <enabled>true</enabled>
      </classAccesses>
      <objectPermissions>
          <allowCreate>false</allowCreate>
          <allowDelete>false</allowDelete>
          <allowEdit>false</allowEdit>
          <allowRead>true</allowRead>
          <modifyAllRecords>false</modifyAllRecords>
          <object>Case</object>
          <viewAllRecords>false</viewAllRecords>
      </objectPermissions>
      <fieldPermissions>
          <editable>false</editable>
          <field>Contact.SSN__c</field>
          <readable>true</readable>
      </fieldPermissions>
  </Profile>
nomatch: |
  <!-- profiles/Customer Portal Profile.profile-meta.xml -->
  <Profile xmlns="http://soap.sforce.com/2006/04/metadata">
      <userLicense>Guest User License</userLicense>
      <classAccesses>
          <apexClass>PublicFaqController</apexClass>
          <enabled>true</enabled>
      </classAccesses>
      <objectPermissions>
          <allowCreate>false</allowCreate>
          <allowDelete>false</allowDelete>
          <allowEdit>false</allowEdit>
          <allowRead>true</allowRead>
          <modifyAllRecords>false</modifyAllRecords>
          <object>Knowledge__kav</object>
          <viewAllRecords>false</viewAllRecords>
      </objectPermissions>
  </Profile>
```

```detector
match: |
  public without sharing class PortalCaseController {
      @AuraEnabled(cacheable=true)
      public static List<Case> byContactEmail(String email) {
          return [SELECT Id, CaseNumber, Subject, Description, ContactId
                  FROM Case WHERE Contact.Email = :email];
      }
  }
nomatch: |
  public with sharing class PortalCaseController {
      @AuraEnabled(cacheable=true)
      public static List<Case> forCurrentUser() {
          if (UserInfo.getUserType() == 'Guest') {
              throw new AuraHandledException('Sign in to view cases.');
          }
          return [SELECT Id, CaseNumber, Subject
                  FROM Case WHERE ContactId = :currentUserContactId() WITH USER_MODE];
      }
  }
```

Also enumerate, in the site and network metadata: whether guest users can see other site members, whether guest file access is on, the `clickjackProtectionLevel`, and the default owner assigned to records a guest creates. **Two of those four are Experience Cloud concepts and live only in `networks/*.network-meta.xml`** — member visibility and guest file access. On a `<siteType>Visualforce</siteType>` site there is no network file to read them from and no analogue to read instead: take `clickjackProtectionLevel` and the guest record default owner from `site-meta.xml` and record the other two as **not applicable**, not as unretrieved. And read every field permission on the guest profile — a `readable` field permission on a sensitive field is a direct public disclosure, and it is a single line of XML.

**The runtime half is not in the repository.** Which permission sets are assigned to the guest user, and whether the org's guest hardening settings are on, are org configuration. Write those as assumptions with the verification step, never as clearances.

### 8. Output sinks in LWC, Aura and Visualforce (`lwc-aura-vf-output-sinks`)

LWC templates escape by default; the bugs are in the escape hatches.

- `lwc:dom="manual"` on an element plus a manual `innerHTML` write. The attribute is the marker — the platform requires it before a component may touch the subtree, so it is a reliable grep.
- `<iframe src={userControlledUrl}>` — validate the scheme; `javascript:` and `data:` are the ones that matter.
- HTML strings handed to a third-party library loaded with `loadScript`.
- Aura: `aura:unescapedHtml`.
- Visualforce: `<apex:outputText escape="false">`, and `{!$CurrentPage.parameters.x}` rendered anywhere — including inside a `<script>` block or an attribute, where the platform's HTML escaping is the wrong escaping.

Lightning Web Security replaced Locker Service on modern orgs and is more permissive in some directions and stricter in others; code that depends on Locker's proxied `window`/`document` behavior is a portability note, not a vulnerability on its own.

Aura's escape hatch is a component attribute rather than a JS call, so it greps differently — and an audit that only looks at LWC misses it entirely on an org with a legacy Aura estate:

```detector
match: |
  <!-- aura/noteViewer/noteViewer.cmp -->
  <aura:component>
      <aura:attribute name="note" type="Object" />
      <aura:unescapedHtml value="{!v.note.Description}" />
  </aura:component>
nomatch: |
  <!-- aura/noteViewer/noteViewer.cmp -->
  <aura:component>
      <aura:attribute name="note" type="Object" />
      <div>{!v.note.Description}</div>
  </aura:component>
```

The `iframe` and `loadScript` sinks are both attribute-shaped too, and both survive the template's escaping because neither value is being rendered as text:

```detector
match: |
  <!-- previewFrame.html -->
  <template>
      <iframe src={record.Website} width="100%" height="600"></iframe>
  </template>
nomatch: |
  <!-- previewFrame.html -->
  <template>
      <iframe src={safePreviewUrl} width="100%" height="600"></iframe>
  </template>

  // previewFrame.js — scheme allowlist, not a denylist
  get safePreviewUrl() {
      const u = new URL(this.record.Website, window.location.origin);
      return u.protocol === 'https:' ? u.href : 'about:blank';
  }
```

```detector
match: |
  <!-- noteViewer.html -->
  <template>
      <div class="note-body" lwc:dom="manual"></div>
  </template>

  // noteViewer.js
  renderedCallback() {
      this.template.querySelector('div.note-body').innerHTML = this.note.Description;
  }
nomatch: |
  <!-- noteViewer.html -->
  <template>
      <div class="note-body">{note.Description}</div>
  </template>
```

```detector
match: |
  <apex:page controller="SearchController">
      <apex:outputText escape="false"
          value="Results for {!$CurrentPage.parameters.q}" />
  </apex:page>
nomatch: |
  <apex:page controller="SearchController">
      <apex:outputText value="Results for {!$CurrentPage.parameters.q}" />
  </apex:page>
```

### 9. Redirects and trusted sites (`salesforce-redirect-and-trusted-sites`)

The platform-specific redirect parameters are `retURL`, `startURL` and `saveURL`, read through `ApexPages.currentPage().getParameters()` and returned as a `PageReference` with `setRedirect(true)`. The generic open-redirect class is web-and-api's; the platform parameter names and the `PageReference` sink stay here.

**CSP Trusted Sites** widen the org's content security policy. A wildcard endpoint applied to `script-src` or `connect-src` is a broad grant; the same wildcard applied only to `img-src` usually is not. Grade on which directives it applies to, not on the presence of the wildcard.

**Remote Site Settings** authorize Apex callouts to an endpoint. An entry broader than the endpoint the code actually calls is a finding at Low unless it reaches something sensitive — and the better remediation is nearly always to replace the setting with a Named Credential, which removes the need for it.

```detector
match: |
  <CspTrustedSite xmlns="http://soap.sforce.com/2006/04/metadata">
      <endpointUrl>https://*.example.com</endpointUrl>
      <isActive>true</isActive>
      <isApplicableToConnectSrc>true</isApplicableToConnectSrc>
      <isApplicableToScriptSrc>true</isApplicableToScriptSrc>
      <context>All</context>
  </CspTrustedSite>
nomatch: |
  <CspTrustedSite xmlns="http://soap.sforce.com/2006/04/metadata">
      <endpointUrl>https://tiles.maps.example.com</endpointUrl>
      <isActive>true</isActive>
      <isApplicableToConnectSrc>false</isApplicableToConnectSrc>
      <isApplicableToImgSrc>true</isApplicableToImgSrc>
      <isApplicableToScriptSrc>false</isApplicableToScriptSrc>
      <context>All</context>
  </CspTrustedSite>
```

```detector
match: |
  public with sharing class ReturnController {
      public PageReference go() {
          PageReference p = new PageReference(
              ApexPages.currentPage().getParameters().get('retURL'));
          p.setRedirect(true);
          return p;
      }
  }
nomatch: |
  public with sharing class ReturnController {
      private static final Map<String, String> ALLOWED = new Map<String, String>{
          'home' => '/lightning/page/home',
          'cases' => '/lightning/o/Case/list'
      };

      public PageReference go() {
          String target = ALLOWED.get(
              ApexPages.currentPage().getParameters().get('retURL'));
          PageReference p = new PageReference(target == null ? '/' : target);
          p.setRedirect(true);
          return p;
      }
  }
```

### 10. Credentials and where secrets live (`named-and-external-credentials`)

**Named Credentials and External Credentials over a hardcoded endpoint and token.** An `HttpRequest` with a literal endpoint and a literal `Authorization` header is a finding, and the callout form `callout:Your_Named_Credential/path` is the fix. External Credentials hold the authentication protocol and the principal; the permission set that grants access to the principal is the access control.

**The dominant real shape is not two literals. It is one thing done right and one done wrong, and a sweep that requires both literals reads it as clean.** A team that has adopted Named Credentials properly — `setEndpoint('callout:...')`, no literal host anywhere in the class — can still keep the secret in the org's *data model* instead of its code: the `Authorization` header is assembled at runtime from a field on a custom setting or a custom metadata record. Neither literal is present, so `setEndpoint(` shows a `callout:` and `setHeader('Authorization'` shows a variable, and an auditor who grades the two lines in front of them writes "credentials correctly externalized".

**So the pivot is mandatory, and it is a pivot to a different file.** From every `setHeader('Authorization'` hit whose second argument is not a literal, follow the expression to the field it reads — `App_Config__c.getOrgDefaults().Api_Token__c`, `getInstance('x').Secret__c`, a `SELECT` on a `__mdt` — and then to that field's **container**, `objects/X__c/X__c.object-meta.xml`. Read `<customSettingsType>` and `<visibility>` there. `<visibility>Public</visibility>` on a custom setting is the finding: public custom settings are exempt from sharing **and** from FLS, so any user with API access reads the token by SOQL, and the callout is the proof that the token is live rather than a leftover. **`callout:` in the endpoint is a clearance for the endpoint, never for the secret** — the two questions are answered in two different files, and stopping at the first one is how this finding gets closed as fixed.

**Justify the severity on durable facts.** "Apex source is readable by anyone with View All Data" is false — "View All Data" is a *data* permission and grants no access to Apex source. Reading `ApexClass.Body` needs "Author Apex" plus Setup or Metadata API access, and managed-package bodies are masked entirely. The durable reasons a hardcoded credential is Critical are these: the secret is in every metadata retrieve, every sandbox refresh and every git clone; it is visible to anyone with "Author Apex" or "Modify Metadata Through Metadata API"; and rotating it requires a deployment.

**Custom settings are not a hiding place, and the exposure is worse than it looks.** Custom settings data is exempt from sharing rules **and** from field-level security. Any user with API access can read an unprotected custom setting record through SOQL or REST regardless of profile — "View All Data" is not required. A secret in a public custom setting is a secret for the whole org.

The counterpart caveat on the recommended fix: protected custom metadata and protected custom settings are genuinely protected only when read by code in a **managed-package namespace**. In the owning org an administrator with "Customize Application" can view them in Setup. So "move it to protected custom metadata" is a real improvement inside a packaged context and a much smaller one in an unmanaged org — say which case applies.

Also in scope: `Crypto.generateAesKey()` output persisted to a custom setting or custom metadata record in plaintext; certificates and private keys committed as static resources; and any `Http` callout whose endpoint is a literal.

```detector
match: |
  HttpRequest req = new HttpRequest();
  req.setEndpoint('https://billing.example.com/v1/invoices');
  req.setHeader('Authorization', 'Bearer b7f3c1e084a24d0f9ab26c5d');
  req.setMethod('POST');
  HttpResponse res = new Http().send(req);
nomatch: |
  HttpRequest req = new HttpRequest();
  req.setEndpoint('callout:Your_Named_Credential/v1/invoices');
  req.setMethod('POST');
  HttpResponse res = new Http().send(req);
```

The detector for the pivot shape holds the endpoint constant — both arms are a correct `callout:` — so what discriminates is where the header's value comes from, which is the only thing in question once the endpoint is right.

```detector
match: |
  // BillingClient.cls — endpoint is a Named Credential, secret is not
  HttpRequest req = new HttpRequest();
  req.setEndpoint('callout:Billing_Api/v1/invoices');
  req.setHeader('Authorization',
      'Bearer ' + App_Config__c.getOrgDefaults().Api_Token__c);
  req.setMethod('POST');
  HttpResponse res = new Http().send(req);

  <!-- objects/App_Config__c/App_Config__c.object-meta.xml — the container the
       pivot lands on. Public, so exempt from sharing and from FLS. -->
  <CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">
      <customSettingsType>Hierarchy</customSettingsType>
      <visibility>Public</visibility>
  </CustomObject>
nomatch: |
  // BillingClient.cls — no Authorization header is set here at all. The External
  // Credential's named principal supplies it, and the permission set that grants
  // the principal is the access control.
  HttpRequest req = new HttpRequest();
  req.setEndpoint('callout:Billing_Api/v1/invoices');
  req.setMethod('POST');
  HttpResponse res = new Http().send(req);
```

A note on where to look, because the shape differs by project format. In **source format** — which is what `force-app/**` is — an object is decomposed: the object-level settings live in `objects/X__c/X__c.object-meta.xml` and every field is its own `objects/X__c/fields/Y__c.field-meta.xml` with a `<CustomField>` root. A single `<CustomObject>` document carrying inline `<fields>` elements is metadata-API format, which you will see in a `mdapi/` or retrieve output directory but not under `force-app`. Read both files or you will grade the container without seeing the secret.

```detector
match: |
  <!-- objects/App_Config__c/App_Config__c.object-meta.xml -->
  <CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">
      <label>App Config</label>
      <customSettingsType>List</customSettingsType>
      <visibility>Public</visibility>
  </CustomObject>

  <!-- objects/App_Config__c/fields/Api_Token__c.field-meta.xml -->
  <CustomField xmlns="http://soap.sforce.com/2006/04/metadata">
      <fullName>Api_Token__c</fullName>
      <type>Text</type>
      <length>255</length>
  </CustomField>
nomatch: |
  <!-- objects/App_Config__c/App_Config__c.object-meta.xml -->
  <CustomObject xmlns="http://soap.sforce.com/2006/04/metadata">
      <label>App Config</label>
      <customSettingsType>List</customSettingsType>
      <visibility>Public</visibility>
  </CustomObject>

  <!-- objects/App_Config__c/fields/Batch_Size__c.field-meta.xml
       The callout credential lives in an External Credential, not here. -->
  <CustomField xmlns="http://soap.sforce.com/2006/04/metadata">
      <fullName>Batch_Size__c</fullName>
      <type>Number</type>
      <precision>4</precision>
      <scale>0</scale>
  </CustomField>
```

```detector
match: |
  Blob key = Crypto.generateAesKey(256);
  upsert new App_Config__c(Name = 'default', Api_Token__c = EncodingUtil.base64Encode(key));
nomatch: |
  HttpRequest req = new HttpRequest();
  req.setEndpoint('callout:Your_Named_Credential/v1/invoices');
  HttpResponse res = new Http().send(req);
```

### 11. Connected apps (`connected-app-configuration`)

- **OAuth scopes.** `Full` is rarely needed and grants everything the authorizing user can do. `RefreshToken` / `OfflineAccess` turns a one-time consent into a durable credential. Grade on the smallest scope the integration's actual calls require.
- **IP relaxation.** `ipRelaxation` set to bypass login IP ranges removes a control the org configured deliberately.
- **Refresh-token policy.** An infinite refresh token on an integration user is a permanent credential; pair it with the question of who can read it.
- **JWT bearer flow.** The certificate is the credential. Verify it is not committed to the repository, and that a rotation path exists — rotating it is a deployment plus a connected-app edit, which is why it never happens.
- The consumer key is public; the consumer secret is not. A consumer secret in the repository is a `crypto-and-key-management` hardcoded-credential finding by class, but the connected-app configuration around it is this lens's.

**Read the two blocks separately, because they answer different questions.** `<oauthConfig>` holds what the app *is* — callback URL, consumer key, scopes, certificate. `<oauthPolicy>` holds how the org *constrains* it — `<ipRelaxation>` and `<refreshTokenPolicy>` live there, not under `oauthConfig`, and an audit that greps only the config block misses both controls entirely.

```detector
match: |
  <!-- connectedApps/Data_Warehouse_Sync.connectedApp-meta.xml -->
  <ConnectedApp xmlns="http://soap.sforce.com/2006/04/metadata">
      <label>Data Warehouse Sync</label>
      <oauthConfig>
          <callbackUrl>https://etl.example.com/oauth/callback</callbackUrl>
          <scopes>Full</scopes>
          <scopes>RefreshToken</scopes>
      </oauthConfig>
      <oauthPolicy>
          <ipRelaxation>BYPASS</ipRelaxation>
          <refreshTokenPolicy>infinite</refreshTokenPolicy>
      </oauthPolicy>
  </ConnectedApp>
nomatch: |
  <!-- connectedApps/Data_Warehouse_Sync.connectedApp-meta.xml
       JWT bearer flow, so no refresh token is issued or needed. -->
  <ConnectedApp xmlns="http://soap.sforce.com/2006/04/metadata">
      <label>Data Warehouse Sync</label>
      <oauthConfig>
          <callbackUrl>https://etl.example.com/oauth/callback</callbackUrl>
          <scopes>Api</scopes>
      </oauthConfig>
      <oauthPolicy>
          <ipRelaxation>ENFORCE</ipRelaxation>
          <refreshTokenPolicy>zero</refreshTokenPolicy>
      </oauthPolicy>
  </ConnectedApp>
```

### 12. Permission sets and profiles (`permission-set-and-profile-grants`)

Read the declarative grants as code, because they are.

- **`viewAllRecords` / `modifyAllRecords`** on an object, granted to a broadly assigned profile or permission set, defeats sharing for that object entirely.
- **`viewAllFields` is a third element on the same `<objectPermissions>` block and it defeats a different control.** It grants read on **every field** of the object, so what it bypasses is **FLS**, not sharing. Nothing about the object's org-wide default bounds it: an OWD of `ReadWrite` already hands every user every record, and it hands nobody a field their profile cannot read — only a `fieldPermissions` grant or `viewAllFields` does that. So the OWD-based downgrade that legitimately applies to the other two elements **must never be applied to this one**, and the effective-FLS question cannot be answered from `<fieldPermissions>` alone: a permission set with `<viewAllFields>true</viewAllFields>` reads fields that carry no `fieldPermissions` entry anywhere in the project. Where all three elements appear on one object, the FLS bypass is the finding and the sharing downgrade does not touch it.
- **`ViewAllData` / `ModifyAllData`** system permissions are administrator-only. On a non-admin permission set they are a finding regardless of intent.
- **`AuthorApex`** lets the holder write and run Apex as themselves, which reaches anything system-mode Apex can reach and also grants read access to Apex source. It is the platform's clearest privilege-escalation grant.
- **`ManageUsers`** is what gates `User` DML, including `ProfileId` — this, not FLS, is the path by which a profile gets reassigned.
- **`CustomizeApplication`** reaches protected custom metadata in Setup and can deploy metadata.
- **`ApiEnabled`** widens the attack surface for a compromised credential from the UI to every API.
- **Permission set groups** compose grants, and a muting permission set is the only thing subtracting from them — read the group and its mutings together or the effective grant is wrong.
- **Permission checks in code** should use custom permissions or permission sets, never a profile-name or profile-Id string comparison, which breaks on rename, clone and sandbox refresh: `FeatureManagement.checkPermission('Your_Custom_Permission_API_Name')`.
- **Granting access from Apex.** `insert new PermissionSetAssignment(...)` and `insert new <Object>Share(...)` run in system mode and grant real access. Both need an authorization check in front of them, and the check must not be the UI.

```detector
match: |
  <PermissionSet xmlns="http://soap.sforce.com/2006/04/metadata">
      <label>Support Agent</label>
      <userPermissions>
          <enabled>true</enabled>
          <name>ModifyAllData</name>
      </userPermissions>
      <userPermissions>
          <enabled>true</enabled>
          <name>AuthorApex</name>
      </userPermissions>
  </PermissionSet>
nomatch: |
  <PermissionSet xmlns="http://soap.sforce.com/2006/04/metadata">
      <label>Support Agent</label>
      <objectPermissions>
          <allowCreate>true</allowCreate>
          <allowDelete>false</allowDelete>
          <allowEdit>true</allowEdit>
          <allowRead>true</allowRead>
          <modifyAllRecords>false</modifyAllRecords>
          <object>Case</object>
          <viewAllRecords>false</viewAllRecords>
      </objectPermissions>
  </PermissionSet>
```

The `viewAllFields` detector holds the two sharing elements constant at `true` in **both** arms and holds the object's OWD at `ReadWrite` in both, so the only difference between a High and a Low is the one element — which is exactly the discrimination the severity row now turns on.

```detector
match: |
  <!-- permissionsets/Care_Coordination_Team.permissionset-meta.xml, read with
       objects/Care_Episode__c/Care_Episode__c.object-meta.xml declaring
       <sharingModel>ReadWrite</sharingModel>. The ReadWrite OWD downgrades the
       sharing pair to nothing and leaves viewAllFields at full force: no OWD
       value grants a field, so FLS is bypassed here at High. -->
  <PermissionSet xmlns="http://soap.sforce.com/2006/04/metadata">
      <label>Care Coordination Team</label>
      <objectPermissions>
          <allowRead>true</allowRead>
          <modifyAllRecords>true</modifyAllRecords>
          <object>Care_Episode__c</object>
          <viewAllFields>true</viewAllFields>
          <viewAllRecords>true</viewAllRecords>
      </objectPermissions>
  </PermissionSet>
nomatch: |
  <!-- Same grant, same ReadWrite object, one element different. Here the OWD
       downgrade applies in full and the grant is a Low hardening note: every
       user already reaches every record, and no field permission is widened. -->
  <PermissionSet xmlns="http://soap.sforce.com/2006/04/metadata">
      <label>Care Episode Reporting</label>
      <objectPermissions>
          <allowRead>true</allowRead>
          <modifyAllRecords>true</modifyAllRecords>
          <object>Care_Episode__c</object>
          <viewAllFields>false</viewAllFields>
          <viewAllRecords>true</viewAllRecords>
      </objectPermissions>
  </PermissionSet>
```

```detector
match: |
  @AuraEnabled
  public static void grantAccess(Id userId, Id permissionSetId) {
      insert new PermissionSetAssignment(
          AssigneeId = userId, PermissionSetId = permissionSetId);
  }
nomatch: |
  @AuraEnabled
  public static void grantAccess(Id userId) {
      if (!FeatureManagement.checkPermission('Your_Custom_Permission_API_Name')) {
          throw new AuraHandledException('You cannot grant access.');
      }
      PermissionSet ps = [SELECT Id FROM PermissionSet
                          WHERE Name = 'Your_Permission_Set_API_Name' LIMIT 1];
      insert new PermissionSetAssignment(AssigneeId = userId, PermissionSetId = ps.Id);
  }
```

### 13. Agent action authorization (`agentforce-action-authorization`)

An agent action is an `@InvocableMethod`, a Flow, a prompt template or an API action wired to a topic. Three questions, and only the third is this lens's:

1. Can the instruction be subverted by the input? That is `prompt-injection`, llm-and-ai's.
2. Is retrieval filtered per user? That is `rag-retrieval-authorization`, llm-and-ai's.
3. **Which identity does the action execute as, and does the Apex or Flow behind it enforce anything?** That is this lens's, and it is the one that turns a model failure into a data breach.

Topic and action assignment is model-driven routing, not an authorization control. An `@InvocableMethod` reachable from an agent is reachable with any argument the model can be persuaded to produce, so it must enforce authorization itself — in user mode, scoped to the running identity, with a permission check in front of any privileged action. Where the agent serves unauthenticated visitors, the running identity is the site guest user and item 7 applies in full.

```detector
match: |
  public with sharing class CloseOpportunityAction {
      @InvocableMethod(label='Close opportunity as won')
      public static void run(List<Id> opportunityIds) {
          List<Opportunity> opps = [SELECT Id FROM Opportunity
                                    WHERE Id IN :opportunityIds];
          for (Opportunity o : opps) {
              o.StageName = 'Closed Won';
          }
          update opps;
      }
  }
nomatch: |
  public with sharing class CloseOpportunityAction {
      public class ActionException extends Exception {}

      @InvocableMethod(label='Close opportunity as won')
      public static void run(List<Id> opportunityIds) {
          if (!FeatureManagement.checkPermission('Your_Custom_Permission_API_Name')) {
              throw new ActionException('Not permitted.');
          }
          List<Opportunity> opps = [SELECT Id FROM Opportunity
                                    WHERE Id IN :opportunityIds WITH USER_MODE];
          for (Opportunity o : opps) {
              o.StageName = 'Closed Won';
          }
          Database.update(opps, AccessLevel.USER_MODE);
      }
  }
```

### 14. Client-side state (`lwc-client-state-exposure`)

Component state lives in browser memory and reaches places the author did not choose: console logs, crash and error reporting, browser extensions, and the client-side cache the platform maintains for `@AuraEnabled(cacheable=true)` results. The narrow question here is what the *platform* puts in the browser; a secret compiled into a bundle is `secrets-in-browser-bundle` in web-and-api.

- Do not hold secrets, full government identifiers or full card numbers in tracked properties longer than the interaction needs.
- A `cacheable=true` method that returns a sensitive field caches it client-side. Return a projection instead.
- `window.localStorage` written from a component persists indefinitely on the device and survives logout — that is the one to grade highest. `sessionStorage` is cleared when the tab closes, so it does not survive the session, but it does survive navigation and reload within the tab and is readable by any script on the origin for as long as the tab lives. Neither is a safe place for a value the server would not hand to an unauthenticated caller.

```detector
match: |
  import { LightningElement, wire } from 'lwc';
  import getProfile from '@salesforce/apex/MemberController.getProfile';

  export default class MemberCard extends LightningElement {
      @wire(getProfile) profile;

      renderedCallback() {
          window.localStorage.setItem('memberProfile', JSON.stringify(this.profile));
      }
  }
nomatch: |
  import { LightningElement, wire } from 'lwc';
  import getProfileSummary from '@salesforce/apex/MemberController.getProfileSummary';

  export default class MemberCard extends LightningElement {
      @wire(getProfileSummary) summary;
  }
```

### 15. Platform logging surface (`salesforce-platform-logging-surface`)

- `System.debug` of record data is real but low-yield: debug logs require an active trace flag, are readable only with debug-log or Setup access, and expire. Report it at Info or Low, and do not let it displace a real finding.
- The higher-value sibling is on the error path and is covered in item 5: a raw exception out of an `@AuraEnabled` method returns the stack trace and the failing SOQL to the caller.
- **Whether record-level *read* auditing exists at all is the question other lenses depend on.** Setup Audit Trail records configuration changes, not data access, and keeps a limited window. Field Audit Trail and Event Monitoring both cover data access and are both licensed add-ons that may simply not be present. Their availability is not visible in a repository — report it as an assumption with the verification step, and say plainly that if neither is licensed, the org cannot answer "which records did this user read." `hipaa-and-phi` and `privacy-and-data-protection` consume that answer; supply it, and do not grade it here.

```detector
match: |
  System.debug(LoggingLevel.INFO, 'contacts: ' + JSON.serialize(contacts));
nomatch: |
  System.debug(LoggingLevel.INFO, 'contacts loaded: ' + contacts.size());
```

### 16. Shield and classic encryption caveats (`shield-encryption-caveats`)

**Neither encryption option on this platform is an access control**, and reporting one as though it were is how a real FLS finding gets closed.

- **Shield Platform Encryption** protects data at rest in the database, in the search index and in backups. It does not change who can read a field: a user with FLS on the field sees plaintext, in the UI and through the API. It does not protect debug logs, and it does not protect a report or export run by an authorized user. It carries functional limits — a probabilistically encrypted field is not filterable, sortable or usable in most formulas; deterministic encryption relaxes filtering at a cryptographic cost that should be stated when recommending it.
- **Classic Encrypted Text** custom fields do gate unmasking, behind the single org-wide "View Encrypted Data" user permission — which is commonly granted broadly, and which reveals the value through the API as well as the UI. The field type is capped at 175 characters and is not filterable, sortable or reportable. It is legacy, and choosing it for a new identifier field is usually the wrong call.
- The finding that survives in both cases is the FLS and sharing posture on the field, not the encryption flag. `crypto-and-key-management` owns primitive correctness; `hipaa-and-phi` owns whether the resulting posture is sufficient for PHI.

```detector
match: |
  <CustomField xmlns="http://soap.sforce.com/2006/04/metadata">
      <fullName>SSN__c</fullName>
      <type>EncryptedText</type>
      <length>32</length>
      <maskChar>asterisk</maskChar>
      <maskType>all</maskType>
  </CustomField>
nomatch: |
  <CustomField xmlns="http://soap.sforce.com/2006/04/metadata">
      <fullName>SSN__c</fullName>
      <type>Text</type>
      <length>32</length>
      <encryptionScheme>ProbabilisticEncryption</encryptionScheme>
  </CustomField>
```

### 17. Repository and deploy exposure (`sfdx-deploy-exposure`)

- An **SFDX auth URL** (`force://...`) is a complete org credential: client id, client secret and refresh token in one string. A committed auth file, an auth URL in a script, or `SFDX_AUTH_URL` echoed to a path inside the working tree is a Critical.
- `.sfdx/` and `.sf/` hold local auth state and belong in `.gitignore`. Confirm they are ignored *and* that they were never committed.
- Retrieved metadata carries secrets: certificates, static resources, remote site settings with embedded credentials, and any custom setting or custom metadata record retrieved with its values.
- Deploy commands that weaken the test gate. Be precise here, because the obvious version of this finding is wrong: **the platform refuses `--test-level NoTestRun` for a production deployment that contains Apex**, so you will not find that shape working against production and reporting it invites a correction that costs the whole report. `NoTestRun` is the default and is legitimate for scratch orgs, sandboxes and Apex-free metadata deploys. The real shapes are `RunSpecifiedTests` with a hand-picked list chosen to clear the 75% bar rather than to cover the change; a Quick Deploy promoted from a stale validation; `--ignore-warnings` on a production deploy; and `NoTestRun` against the staging org that was supposed to be the rehearsal, so nothing is exercised before the production run.

`--ignore-conflicts` is a **sandbox and scratch-org** finding, not a production one, and putting it on a production command is the second-fastest way to be corrected: conflict detection is a source-tracking feature, production orgs are not source-tracked, and the flag therefore does nothing there. Where it bites is a source-tracked developer sandbox or scratch org, where it overwrites whatever another developer changed without showing anyone.
- How the secret is injected into CI is `ci-secret-and-token-handling` in cicd-and-supply-chain; what the repository contains is this lens's.

```detector
match: |
  sf org login sfdx-url --sfdx-url-file ./config/prod-auth.txt --alias prod
  sf project deploy start --target-org prod --ignore-warnings \
    --test-level RunSpecifiedTests --tests SmokeTest
nomatch: |
  printf '%s' "$SFDX_AUTH_URL" > "$RUNNER_TEMP/prod-auth.txt"
  sf org login sfdx-url --sfdx-url-file "$RUNNER_TEMP/prod-auth.txt" --alias prod
  rm -f "$RUNNER_TEMP/prod-auth.txt"
  sf project deploy start --target-org prod --test-level RunLocalTests
```

### 18. Other operations worth auditing

- `Database.DMLOptions` with `allowFieldTruncation = true`, or `DuplicateRuleHeader.allowSave = true`, bypassing controls the org configured. Field truncation turns a length-validation failure into silent data loss; the duplicate-rule bypass turns a deliberate business control off for that transaction.

```detector
match: |
  Database.DMLOptions opts = new Database.DMLOptions();
  opts.allowFieldTruncation = true;
  opts.DuplicateRuleHeader.allowSave = true;
  Database.insert(leads, opts);
nomatch: |
  Database.DMLOptions opts = new Database.DMLOptions();
  opts.optAllOrNone = true;
  Database.insert(leads, opts, AccessLevel.USER_MODE);
```

- `Database.executeBatch` with a caller-controllable scope size or query, and `@future` or Queueable methods that accept an Id and act on it with no re-check. Both matter for the same reason, and it is worth stating precisely because the loose version of it produces bad advice: the asynchronous frame runs in **system mode** — object permissions, FLS and sharing are all off — but the **running user is preserved**. `UserInfo.getUserId()` inside a `@future` or a Queueable returns the user who enqueued it, and `FeatureManagement.checkPermission` and user-mode DML both evaluate against that user. So the fix is *not* to thread an acting-user id through as a parameter; a caller-supplied identity parameter is worse than useless, because it is one more input to spoof. The fix is to re-assert enforcement inside the async frame — user mode, or a permission check against the running user — because it is the **mode**, not the identity, that the entry-point check failed to carry across.

```detector
match: |
  @AuraEnabled
  public static void queueRecalc(Id accountId, Integer scopeSize) {
      Database.executeBatch(new RecalcBatch(accountId), scopeSize);
  }

  @future
  public static void closeCase(Id caseId) {
      update new Case(Id = caseId, Status = 'Closed');
  }
nomatch: |
  @AuraEnabled
  public static void queueRecalc(Id accountId) {
      if (!FeatureManagement.checkPermission('Your_Custom_Permission_API_Name')) {
          throw new AuraHandledException('Not permitted.');
      }
      Database.executeBatch(new RecalcBatch(accountId), 200);
  }

  @future
  public static void closeCase(Id caseId) {
      // The async frame runs in system mode but keeps the enqueuing user, so
      // checkPermission and user-mode DML both evaluate against the right
      // identity. No acting-user parameter is needed, and adding one would
      // introduce a spoofable input where the platform already has the answer.
      if (!FeatureManagement.checkPermission('Your_Custom_Permission_API_Name')) {
          return;
      }
      Database.update(new Case(Id = caseId, Status = 'Closed'), AccessLevel.USER_MODE);
  }
```

- Hardcoded 15- or 18-character record Ids. Org and User Ids are not secrets, and hardcoded RecordType, Profile, Queue and Group Ids are a portability defect that breaks on sandbox refresh. Report at Info or Low. The adjacent findings that *are* security findings are different objects entirely: a hardcoded session Id, an OAuth consumer secret, a certificate, an auth URL.

## Severity calibration

`severity_floor: low` is presentational. It orders this lens's findings in the report. It never suppresses a finding, and no item below may be dropped because it sits at Low or Info.

**The rule that does the most work: no unconditional High.** The source material this lens replaces carried four "flag as High" instructions with no discriminator behind them, and every one of them fires constantly on correct code. An unconditional High on a pattern that is usually benign is how a tool gets switched off. Each is re-graded below with the condition that makes the High true.

### The four re-graded instructions

| Original instruction | Why it was wrong | Re-graded |
|---|---|---|
| "Flag any `@AuraEnabled` class with `without sharing` as **High** unless there's a comment explaining why." | A comment is not a control, and the declaration is a no-op on custom metadata, custom settings, platform events and any Public Read/Write object. | **High** when the class is `without sharing`, is an entry point, and a caller-supplied Id or filter reaches a query or DML on an object whose `<sharingModel>` is `Private`, `Read` or `ControlledByParent`. **Low** when `<sharingModel>` is `ReadWrite`, or the object is a custom metadata type, custom setting or platform event — there is no record access to bypass. **Medium** *only* where the object is a **standard** object whose Sharing Settings are not in the checkout; for a custom object the OWD is in `objects/X__c/X__c.object-meta.xml` and reading it is required, not optional. A comment moves nothing; it goes in the finding's Notes as stated intent. |
| "Missing declaration entirely on a class with DML or SOQL: **High**." | An undeclared class inherits its caller's context. It defaults to without-sharing only when it is the entry point. | **High** only for an undeclared **entry point** touching a restricted-OWD object. Otherwise **Low**, worded as "declare `inherited sharing` so a future without-sharing caller cannot silently widen access" — and note that for an entry point `inherited sharing` defaults to `with sharing`. |
| "Any `@AuraEnabled` method returning SObjects without one of these: **High**." | Enforcement is often present in a form the grep misses — `WITH USER_MODE`, `Database.query(q, AccessLevel.USER_MODE)`, `WITH SECURITY_ENFORCED`, or a `SObjectAccessDecision` produced in a shared selector. | **High** when no mechanism enforces FLS anywhere on the call chain, the returned SObject carries a field the caller's profile cannot read, and that field is in the sensitive classes named in the severity table. **Medium** on the same two conditions where the field is not sensitive. **Low** when nothing enforces it but every returned field is broadly readable, since the gap then exposes nothing the caller could not already see. Establish readability from `<fieldPermissions>` in `profiles/*.profile-meta.xml` and `permissionsets/*.permissionset-meta.xml` — **and from `<viewAllFields>` in the same files, because a `true` there grants every field on the object including ones with no `fieldPermissions` entry anywhere.** Trace the selector layer before filing. |
| "Any DML on user-supplied SObjects without FLS check: **High**." | Correct in direction and too broad in reach: it fires on every `update record;` in the codebase. | **High** when the DML runs in system mode over a caller-supplied SObject **and** the writable set includes a field from the escalation classes in Checklist item 3 (decision-gating, access-determining, or monetary). **Medium** otherwise. **Critical** when the write grants access outright — a `__Share` row, a `PermissionSetAssignment`, or `OwnerId` on a restricted-OWD object. |

### Severity table

| Finding | Severity | Condition that earns it |
|---|---|---|
| SOQL or SOSL injection reachable from an entry point | Critical | Taint proven from an `@AuraEnabled`, `@RestResource`, `@InvocableMethod` or page parameter to the concatenation. Without proven taint it is Medium and written as a hardening finding. |
| Same, reachable by the site guest user | Critical | Where the class is named in a `<classAccesses>` entry with `<enabled>true</enabled>` on the profile carrying `<userLicense>Guest User License</userLicense>`, so the reachability condition is satisfied with no session at all. No further narrowing applies, and taint proof is not required — an unauthenticated visitor steering a query is Critical on reachability alone. |
| Guest-reachable Apex returning records in system mode | Critical | The class is enabled on the guest profile and runs `without sharing` or in system mode, and the object holds records not intended to be public. |
| Guest profile granting read on an object or a readable field permission, **with a named path by which records actually reach the visitor** | High–Critical | The object permission alone is not the finding. Under the floor this lens describes, guest read on an object with Private OWD, no criteria-based guest sharing rule and no system-mode path exposes **zero records**, and grading that Critical is an unearned finding that will be dismissed on sight. Name the reachability: a criteria-based guest sharing rule targeting this site; a `without sharing` or system-mode Apex class enabled on the guest profile; a Flow reachable from the site that actually runs in system context — **read `<processType>` before naming this path**: an `AutoLaunchedFlow` (including one fired by a record the guest creates) qualifies with `<runInMode>` absent, at `DefaultMode`, or at `SystemModeWithoutSharing`, but a **screen flow** (`<processType>Flow</processType>`) qualifies **only** where it names `SystemModeWithoutSharing` explicitly, because with the element absent it runs as the guest user with sharing and with FLS and is not a system-mode path at all, and a site-embedded flow is normally a screen flow, so naming this path off an absent element is the likely over-report; a stock platform Aura controller that returns the object; or an object type the sharing floor does not reach at all (custom metadata type, custom setting, platform event). Critical with a reachability path plus regulated or customer data; High with a path to internal data. The process-type partition above is the one the Flow row below states; if the two ever disagree, the disagreement is the bug. |
| Guest profile grant with **no** demonstrated reachability path | Low | Over-broad permission, graded as hardening. Say explicitly that no path was found and that the runtime guest posture — assigned permission sets, sharing rules not in the checkout — was not verifiable, so this is a bounded negative rather than a clearance. |
| SFDX auth URL, certificate, or consumer secret committed to the repository | Critical | Established by grepping the tree for `force://`, `SFDX_AUTH_URL`, `.sfdx/`, `.sf/` and committed `*.key`, `*.pem` or `*.crt` under `force-app/**/staticresources/`. The value is live. A demonstrably rotated value is a hygiene note — check history before grading. |
| Hardcoded credential in Apex | Critical | Established from `force-app/**/*.cls`, and **two shapes qualify — the two literals are not a required conjunction**. (a) A literal endpoint on `req.setEndpoint(` together with a literal `req.setHeader('Authorization'`, where the value is live: Critical on this row. (b) A correct `req.setEndpoint('callout:...')` whose `Authorization` header is built at runtime from a custom setting or custom metadata field — no literal anywhere, so a detector demanding both legs of (a) reads it as clean, and it is the more common shape in a codebase that has already adopted Named Credentials. In (b) the credential is not in the Apex: the Apex hit is the **reachability proof**, and the grade is set by the row below once you have pivoted to the field's container and read `<visibility>`. Do not close (b) as "endpoint externalized"; do not file it twice either. Justified on the durable facts: present in every metadata retrieve, sandbox refresh and clone; readable with "Author Apex" or Metadata API access; rotation requires a deploy. **Not** on "readable with View All Data", which is false. Check git history first — a value rotated long ago is a hygiene note, not a Critical. |
| Secret in a public custom setting or unprotected custom metadata | High | Established from `<customSettingsType>` plus `<visibility>Public</visibility>` in `objects/X__c/X__c.object-meta.xml`, read together with the credential-shaped field in `objects/X__c/fields/Y__c.field-meta.xml`. Custom settings are exempt from sharing *and* FLS, so any user with API access can read it. **This is the row shape (b) of the hardcoded-credential finding above lands on**, and the Apex line that reads the field — a `setHeader('Authorization', …)` fed from it, behind a `callout:` endpoint — is what establishes the secret is live and names the system it authenticates to. **Critical** with that reach into a production system of record; High where the field is credential-shaped but no callout consumes it. |
| DML that grants access — `__Share` insert, `PermissionSetAssignment` insert, `OwnerId` write — from an entry point with no authorization check | Critical | The write itself is the grant. |
| `@AuraEnabled` on a `without sharing` class returning SObjects | High | Plus the OWD condition in the table above. Uplift for regulated data comes from `phi-severity-uplift` or `personal-data-severity-uplift`; do not grade the data class here. |
| Missing FLS on read | High / Medium / Low | Both halves are required before any grade above Low: nothing on the call chain enforces FLS, **and** the query is reachable from an entry point by a caller whose profile cannot read the field — establish that from `<fieldPermissions>` in `profiles/*.profile-meta.xml` and `permissionsets/*.permissionset-meta.xml`, **and from `<viewAllFields>` on the object's `<objectPermissions>` block in the same files, since a `true` there makes every field readable regardless of any `fieldPermissions` entry**. Given both, **High** where the field is a government identifier, compensation, a financial account number, or data the compliance lens classifies as sensitive — health and behavioral-health data route to `hipaa-and-phi` for both the classification and the uplift. **Medium** on the same two conditions where the field is not sensitive. **Low** where every returned field is broadly readable, since the gap exposes nothing the caller could not already see. These three tiers are the same ones the re-graded table above states; if the two ever disagree, the disagreement is the bug. |
| Missing FLS on write | High | Established from `force-app/**/*.cls`: DML with no `AccessLevel.USER_MODE` argument and no `as user` statement form, over an SObject whose writable set includes an escalation-class field — `OwnerId`, `RecordTypeId`, `StageName`, `Status`, `Amount`, or a field named in a criteria-based sharing rule under `sharingRules/`. Per the escalation-class condition above; Critical where the write grants access. |
| Record-triggered Flow running effectively without sharing, whose Get Records is filtered only by an input variable | High | **Read the process type first; this row grades autolaunched flows.** Where `flows/*.flow-meta.xml` carries `<processType>AutoLaunchedFlow</processType>` — which covers record-triggered and scheduled — **all three metadata shapes carry the same grade**, because they have the same runtime effect: `<runInMode>SystemModeWithoutSharing</runInMode>`; `<runInMode>DefaultMode</runInMode>`; and **no `<runInMode>` element at all**, which is the shape Flow Builder produces by default and the one most likely to be present. Establish it from `flows/*.flow-meta.xml` with the three sweeps in Checklist item 6 — the third one, `<processType>`, is what makes this row gradeable at all, because neither of the other two can tell a screen flow from an autolaunched one. **A screen flow (`<processType>Flow</processType>`) with the element absent or at `DefaultMode` is not this finding at any severity**: user context is the platform default there, so the absent element means the opposite of what it means here, and grading it on this row is a refutable High. A screen flow that names `SystemModeWithoutSharing` explicitly grades here in full. Medium where the flow's inputs are all system-generated rather than caller-supplied. Grading only the explicit literal leaves the default shape priced at zero, which is the same silent all-clear the detector gap created; grading the unpartitioned sweep output inflates the count instead, and both are avoidable by reading one element. |
| Flow at `SystemModeWithSharing` writing a field the running user cannot edit | Medium | "With Sharing" enforces record-level access only. State that explicitly in the finding so the fix is not "turn on sharing". |
| Connected app with `Full` scope, or an infinite refresh token | High | Condition it only on what `connectedApps/*.connectedApp-meta.xml` actually carries: `<scopes>Full</scopes>` in `<oauthConfig>`, and in `<oauthPolicy>` either `<refreshTokenPolicy>infinite</refreshTokenPolicy>` or an `<ipRelaxation>` set to a bypass value — a durable credential with unlimited scope and no network constraint. **Medium** where the scope is narrowed to `Api` or `<ipRelaxation>` is `ENFORCE`. **The permitted-users policy — self-authorize versus admin-approved — is a Setup value this lens cannot read from the repository, so the grade must not depend on it**; record it as an assumption with the verification step. A condition no artifact in the checkout can satisfy silently downgrades every instance of the finding, which is the same failure as an unread OWD. |
| `ModifyAllData`, `ViewAllData` or `AuthorApex` on a non-administrator permission set or profile | High | Critical where the permission set is assigned broadly, which is runtime data — say which you established. |
| `viewAllRecords` / `modifyAllRecords` granted on an object | High | Two repository facts, both required: `<viewAllRecords>true</viewAllRecords>` or `<modifyAllRecords>true</modifyAllRecords>` in a `permissionsets/*.permissionset-meta.xml` or `profiles/*.profile-meta.xml` that is not an administrator's, **and** a `<sharingModel>` of `Private`, `Read` or `ControlledByParent` on the object, so there is record access to defeat. **Low** where `<sharingModel>` is `ReadWrite` **and** `viewAllFields` is false or absent on the same `<objectPermissions>` block — every user already has the records and the grant adds nothing. Both halves of that downgrade are required: it is a statement about sharing and it is void the moment the row below applies. Data class supplies the uplift through `phi-severity-uplift` or `personal-data-severity-uplift`; it never sets this grade. |
| `viewAllFields` granted on an object | High | One repository fact, and **no OWD condition** — `<viewAllFields>true</viewAllFields>` in a `permissionsets/*.permissionset-meta.xml` or `profiles/*.profile-meta.xml` that is not an administrator's. This element bypasses **field-level security**, which **no org-wide default grants at any value**: `ReadWrite` hands every user every record and hands nobody a field their profile cannot read. So the `ReadWrite` downgrade in the row above **cannot reach this finding** and must not be applied to it — a permission set carrying all three elements on a customer-data object with `<sharingModel>ReadWrite</sharingModel>` is High on this row, not Low on that one. Grading it Low is a wrong clearance, not a conservative one, and it was measured: it is the shape a real org shipped on its patient-record object. `<fieldPermissions>` cannot establish the effective grant here — the whole point of the element is that it covers fields nobody granted — so read `<objectPermissions>` for it directly, and note that a project retrieved at an older API version may not carry the element even where the org grants it. |
| Raw exception thrown out of an `@AuraEnabled` method | Medium | The response carries the failing SOQL and often field values. High where the method is guest-reachable. |
| CSP Trusted Site wildcard applied to `script-src` or `connect-src` | Medium | Low where it applies only to `img-src`, `font-src` or `style-src`. |
| Open redirect through `retURL` / `startURL` | Medium | **High** where the redirect is reachable unauthenticated — a login page or a site page — **and** the destination receives a session-bearing request, which is the shape that turns a redirect into credential capture. Medium where it is reachable only after authentication and carries no token onward. |
| Remote Site Setting broader than the endpoint the code calls | Low | The finding is breadth, and the remediation is a Named Credential. |
| Classic Encrypted Text or Shield cited as an access control | Medium | The finding is the missing FLS or sharing control behind it, not the encryption setting. Grade the underlying gap. |
| `@isTest(SeeAllData=true)` on a test covering sharing-sensitive code | Medium | The test is not evidence. Low where the code under test is not sharing-sensitive. |
| Entry point with no test exercising it under a restricted user | Low–Medium | A coverage finding, not a vulnerability. It becomes Medium when the class is `without sharing`. |
| `System.debug` of record data | Info–Low | Needs an active trace flag and debug-log access, and expires. Never let it displace a real finding. |
| Hardcoded 15- or 18-character record Id | Info–Low | Portability defect. Org and User Ids are not secrets. |

Two anti-patterns, stated as rules:

- **Never grade on the declaration alone.** `without sharing`, a missing declaration, and a bare `Database.query` are all *candidates*. The severity comes from the object's OWD, the reachability of the entry point, and whether caller-supplied data steers the query — never from the keyword.
- **Never clear a finding because a control might exist elsewhere.** Several entries above turn on facts the repository genuinely does not carry: permission-set and profile *assignment*, Event Monitoring and Field Audit Trail licensing, and the live guest posture. When you cannot establish one, the finding stays open at the lower severity with the assumption and the verification step written out. An unverified control is a hypothesis, not a clearance.
- **Custom-object OWD is not on that list, and must never be treated as if it were.** `<sharingModel>` and `<externalSharingModel>` are in `objects/X__c/X__c.object-meta.xml`. Grading a custom-object sharing finding down to the fallback because "the OWD is unknown" is not caution — it is an unread file, and because OWD is the stated condition under several rows above, doing it once silently under-reports every sharing finding in the run. Read the file. Only a standard object, or an object absent from the checkout, earns the unknown.

## Known false positives

Each entry names a pattern a competent reviewer would flag and states why it is not the finding it looks like. **None of these is a licence to drop a finding**: every one names the narrower finding that does survive.

1. **An Apex class with no sharing declaration, flagged High.** An undeclared class inherits its caller's sharing context, so a selector or service class called only from `with sharing` controllers does enforce sharing. The default-to-without-sharing behavior applies only when the class is the entry point: `@AuraEnabled`, `@RestResource`, `@InvocableMethod`, `webservice static`, a Visualforce controller, a trigger, `execute()` on Queueable/Batchable/Schedulable, a `@future` method, or anonymous Apex. Trace callers first. If all are `with sharing`, the finding is at most Low — "declare `inherited sharing` so a future without-sharing caller cannot silently widen access" — and note that for an entry point `inherited sharing` defaults to *with* sharing, which is the whole reason the keyword exists.
   **Trace the callers, do not assume them.** If the call graph cannot be resolved from the code you have, the class is an entry point for grading purposes and the finding stays open with that assumption stated.

2. **`without sharing` treated as a sharing bypass on sight.** Sharing exists only for objects with restrictive org-wide defaults: `without sharing` is a no-op on custom metadata types, custom settings, platform events, and any object whose OWD is Public Read/Write. It is also the correct declaration for rollups and denormalization in trigger handlers, Queueable and Batch jobs, sharing recalculation, approval automation, and integration paths — and the trigger itself runs in system context, so "trigger handler lacks `with sharing`" is usually low-value. **Do not overstate that carve-out**: a `with sharing` handler called from a trigger does enforce sharing, so the declaration is not decorative, and an undeclared handler simply inherits the trigger's system context. Establish the object's OWD first — for a custom object that means reading `<sharingModel>` and `<externalSharingModel>` out of the object metadata, not recording it as unknown — and then ask whether a user-supplied Id or filter crossed into the without-sharing context.
   **The trigger carve-out is narrow.** It clears the handler *as invoked from the trigger*. The same class is frequently also called from an `@AuraEnabled` method, and in that path the declaration is load-bearing again. Check every caller before applying this.

3. **Any `Database.query(...)` or `Database.getQueryLocator(...)` with string building, reported as SOQL injection.** Dynamic SOQL is injectable only if untrusted data reaches the string. Safe shapes are common: field lists from `Schema.getGlobalDescribe()`, a FieldSet, or `getDescribe().fields.getMap()`; `String.join` over hardcoded names; `:ids` / `:userInput` binds, since dynamic SOQL binds against enclosing-scope variables, so a concatenation-free `Database.query` containing a bind is already parameterized; and values coerced through `Integer.valueOf()`, `Id.valueOf()` or `Decimal.valueOf()`, which cannot carry query syntax and need no escaping. Prove taint from an `@AuraEnabled`, `@RestResource`, `@InvocableMethod` or `ApexPages.currentPage().getParameters()` source to the concatenation.
   **Two things this entry does not clear.** A colon inside a single-quoted literal is not a bind — it is text. And an `escapeSingleQuotes` call whose result is not the value interpolated is not an escape; it is the vulnerable form wearing the safe form's clothes. Read the concatenation, not the line above it.

4. **An `@AuraEnabled` method returning SObjects with no `Security.stripInaccessible()` and no `isAccessible()` checks.** Enforcement may be present in a form the grep misses: `WITH USER_MODE` in the SOQL, `Database.query(q, AccessLevel.USER_MODE)`, `WITH SECURITY_ENFORCED`, or an `SObjectAccessDecision` produced in a shared selector layer. Check the whole call chain, and whether the class is `inherited sharing` under a user-mode caller, before concluding nothing enforces FLS.
   **`WITH SECURITY_ENFORCED` is not the same clearance as user mode.** It enforces object and field permissions on selected and filtered fields; it does **not** enforce sharing, it fails all-or-nothing instead of stripping, and it does not reach polymorphic lookups or `TYPEOF`. A `without sharing` class using it still bypasses record access, and that finding stands.

5. **An LWC that reads or writes records with no Apex FLS check anywhere.** If the data path is `lightning/uiRecordApi` (`getRecord`, `getFieldValue`, `createRecord`, `updateRecord`), `lightning-record-edit-form` / `-view-form`, or a `graphql/*` wire adapter, the UI API enforces object permissions, FLS and sharing server-side and there is no Apex in the path to add a check to — fields the user cannot see are simply absent from the response. This is the recommended pattern, not a gap; the finding appears only once the same data is routed through custom Apex. Do still flag a `lightning-record-edit-form` bound to a field the author intended to hide, since FLS is the only control there and hiding it in markup is cosmetic.

6. **An `@AuraEnabled` method with no `FeatureManagement.checkPermission`, role or owner check, reported as broken function-level authorization because "any authenticated user can call it."** Callability matters only if the method grants access beyond what the caller's sharing and FLS already allow: a `with sharing` method in user mode that takes no Id and returns "my open Cases" is correctly scoped by the platform, and a permission check would be defense in depth rather than a fix. Report it when the method accepts an Id or filter that widens scope beyond the caller's own records, runs `without sharing` or in system mode, performs a privileged action (ownership change, approval, `__Share` insert, `PermissionSetAssignment`), or is reachable by the Site or Experience Cloud guest user — and confirm Apex Class Access is actually granted to non-privileged profiles before asserting "any authenticated user."

### Rejected candidates

Candidates considered for the list above and deliberately excluded. Nothing here should be quietly re-added; each would have suppressed a real finding, or moved a finding into a section that cannot enforce it.

- **"Hardcoded 15- or 18-character record Ids."** Not a false positive — a severity question. Org and User Ids are not secrets and hardcoded RecordType, Profile, Queue and Group Ids are a portability defect. It lives in `## Severity calibration` at Info–Low, where it is capped rather than suppressed, because the adjacent hits that *are* security findings — a session Id, a consumer secret, a certificate, an auth URL — must not be cleared by the same rule.
- **"`System.debug(...)` near record data."** Cut for volume, not because it is wrong: debug logs need an active trace flag, are readable only with debug-log or Setup access, and expire. It is capped at Info–Low in `## Severity calibration`. The higher-value sibling was promoted into Checklist item 5 instead — a raw exception thrown out of an `@AuraEnabled` method returns the stack trace, the failing SOQL and often field values to any caller's browser.
- **"`WITH SECURITY_ENFORCED` is present, so FLS and sharing are enforced."** Rejected: it is a false clearance, and it is the most likely wrong inference a reader would draw from entry 4. The clause does not enforce sharing at all. Written as a false positive it would close every `without sharing` record-access finding in a codebase that uses the clause.
- **"`String.escapeSingleQuotes` is present, so the dynamic SOQL is safe."** Rejected for the same reason: escaping is a defense only inside a single-quoted literal, it does not escape `%` or `_` in a `LIKE`, and calling it is not the same as using its result. As a suppression rule it would clear the exact defect this lens exists to catch.
- **"Guest user exposure is bounded by the platform, so guest findings are Low."** Rejected as over-broad. The platform floor bounds record *sharing* grants — Private OWD, read-only, criteria-based rules only. It does not bound object and field permissions on the guest profile, Apex class access, or anything running in system mode, which is where every real guest-user incident lives.
- **"`@AuraEnabled(cacheable=true)` is read-only, so it is low risk."** Rejected: read-only is a statement about DML, not about disclosure. A cacheable method is still an endpoint any authenticated user — or, on a site, any visitor — can call with arbitrary arguments, and its result is additionally cached in the browser.

## Proof recipes

Shared harness components are referenced by name and not restated here: the **registry-driven enumerator**, the **two-subject fixture**, and the **canary fixture set**. Their implementations live in `lenses/_harness.md`.

**Tier rule, and the honest headline for this lens.** T1 is a proof the repository's own test command executes. T2 requires the auditor to stand up infrastructure the repository does not already stand up, and the user is asked every time.

**Apex tests execute only inside an org, and an org is a remote host.** Under this skill's hard rails the auditor writes the Apex test and does not run it, so **every Apex recipe's behavioural half lands at T3 UNPROVEN, capped at Medium**, unless the user explicitly runs `sf apex run test` themselves and pastes the result. That is not a defect in the recipes; it is the rail, and it must be stated in the report's coverage block every run rather than left for the reader to infer.

**Do not read that as "Apex is unauditable here."** It is a statement about *behavioural* proof, not about the class of finding. Declarations in the checkout decide most authorization questions on their own: sharing keywords, query modes, `viewAllRecords`/`modifyAllRecords` grants, and object sharing models are all in the repository and all computable. R1's static half and the guest variant both reach **T1** offline, as does R3. Where a recipe has a computable half, run it and report at its tier — a capped behavioural half is not a reason to skip the class, and treating it as one has measurably cost this lens its largest finding category.

### R1 — Entry-point authorization (static half T1; behavioural half T3)

**Run the static half first, and never let the dynamic half's tier stand in for the whole recipe.** Most of what R1 asks — *can a user reach a record the sharing model should hide?* — is decided by declarations in the checkout, not by runtime behaviour. Those cases are computable offline and are **T1**, by the same method the guest variant below uses. Only the residue needs an org.

Treating the whole recipe as T3 has a measurable cost. On a real 631-class org the static rule finds ten unenforced entry points; an audit that read R1 as "capped at Medium, unprovable" reported zero Apex authorization findings and spent its effort on metadata instead. The tier label suppressed the class, not just its grade.

**The static rule.** For each Apex class containing `@AuraEnabled`, `@RestResource`, `@InvocableMethod`, or `webservice static`, and excluding `@isTest` classes, the entry point is unenforced when **both**:

1. the class declares `without sharing`, or declares no sharing keyword at all — an undeclared class entered directly from Lightning or REST runs in system mode, and `inherited sharing` entered directly runs *with* sharing and is therefore not a hit; and
2. it runs a SOQL query with no user-mode guard — none of `WITH USER_MODE`, `WITH SECURITY_ENFORCED`, `AccessLevel.USER_MODE`, `Security.stripInaccessible`, or an explicit `isAccessible()`/`isQueryable()` check.

Escalate the grade where a permission set or profile in the checkout grants `viewAllRecords` or `modifyAllRecords` on an object the class queries: the sharing model is then irrelevant to reachability, and this is computable from the same metadata the guest variant reads.

**Assert both directions, as counts, per the detector-and-fixture-pair runner.** `detect(vulnerable) == 1` on a fixture with one unenforced entry point, and `detect(clean) == 0` on the same class with `with sharing` added. Four traps, each of which produces a green result on vulnerable code:

- **Iterate methods, not files.** The failure message names class *and* method. A rule reported at file granularity hides the second unenforced method in a class whose first one you fixed.
- **The undeclared case is absence-shaped.** A rule that fires on a *missing* `with sharing` passes by matching nothing when the sweep is misconfigured. Assert it fires on a fixture with the declaration deliberately removed.
- **Exclude `@isTest` explicitly and assert the exclusion.** Test classes are routinely `without sharing` by design and will dominate the result set otherwise.
- **Assert the non-test entry-point population is non-empty.** A sweep that matches zero classes passes perfectly and proves nothing.

**Fails on:** `without sharing` or no declaration, plus a bare `[SELECT …]`. **Passes on:** `with sharing`, `inherited sharing` at the entry point, or any user-mode guard on every query.

**What the static half cannot decide, and must not claim.** Whether a filter in the method body correctly scopes to the running user. A `with sharing` class can still leak by building a predicate from a caller-supplied Id, and a `without sharing` class can be correct because it filters explicitly. The static rule reports *unenforced declaration plus unguarded query*, which is a defect in its own right; it does not report *proven cross-tenant read*. That claim needs the dynamic half.

**The dynamic half (Apex; T3 UNPROVEN unless the user runs it).**

Build two subjects once — an owning user with a record, and a second user with no share to it — using the **two-subject fixture**, and seed the record with a distinctive marker from the **canary fixture set**. Then call each entry point as the second subject and assert **both** that the record is absent from the result **and** that the marker appears nowhere in the returned payload.

Enumerate the cases rather than hand-writing them: use the **registry-driven enumerator** over the `@AuraEnabled`, `@RestResource` and `@InvocableMethod` methods in the project, with a committed exemption allowlist, and assert the discovered method count against a checked-in number so an enumerator that silently returns zero rows cannot pass.

Two sharpenings worth keeping verbatim:

- Wrap the call in `System.runAs(minimalAccessUser)`. Outside a `runAs` block the test runs as the deploying administrator and proves nothing about sharing.
- Assert field-level stripping distinctly from record-level filtering: `Assert.isFalse(result[0].isSet('SSN__c'))` distinguishes a genuine `stripInaccessible` from the cosmetic `record.SSN__c = null`, which leaves the field set and the value merely blanked.

**Fails on:** `without sharing` on an entry point, a system-mode query, a filter built from a caller-supplied Id. **Passes on:** `with sharing` plus `WITH USER_MODE`, or a selector that scopes to the running user.

**The guest variant is static, and this is a hard rail, not a tier.** Where a site exists, prove guest exposure **from the checkout** — no requests, to any host, ever:

1. Resolve the guest profile by `<userLicense>Guest User License</userLicense>`.
2. Compute its effective object and field permissions from the profile plus any permission set the repository assigns to it. `<viewAllFields>true</viewAllFields>` on an `<objectPermissions>` block is part of that computation and swallows the rest of it: it grants every field on the object, so the effective field set is not the union of the `<fieldPermissions>` entries whenever it is present.
3. Intersect that set with the Apex classes it grants `classAccesses` to, and mark every one of those that is `without sharing`, undeclared at an entry point, or runs a system-mode query.
4. Read `<sharingModel>` and `<externalSharingModel>` for each custom object in the set, and list every criteria-based sharing rule in the checkout that targets the site.
5. Assert the resulting reachable-object set is a subset of a committed allowlist of objects the site is *intended* to publish.

That assertion runs offline against the repository and is **T1**. It is also the only guest proof this skill performs.

**Do not probe a deployed site.** Sending unauthenticated requests to a live Experience Cloud endpoint reaches a remote host, which this project's hard rails forbid outright — the same rule that puts every Apex recipe at T3 — and it does not become permissible by being a scratch org, a sandbox, or an org the auditor believes they own. Unauthenticated probing of a running site is authorized-penetration-test activity governed by a scope agreement, not audit activity: it requires **written authorization naming the site, scoped and dated, obtained before the first request**, and it happens outside this skill. Do not run it here, and do not present the tier's ask-the-user prompt as if it were that authorization — it is not, and treating it as one would have this lens instruct an auditor into unauthorized testing. Where the dynamic evidence is genuinely needed, report the static result and record the dynamic half as out of scope with the authorization requirement stated.

### R2 — Injection into the secondary interpreter (Apex; T3 UNPROVEN unless the user runs it)

Insert two distinguishable records. Call the query path with an exact match and assert the result size is 1. Then call it with a tautology — `Alpha' OR Name != '` — and assert the size is **still 1**. Size 2 is the proof, and it is the whole recipe: an assertion that the call merely succeeded proves nothing.

Three rows beyond the tautology, because they cover the cases escaping does not:

- A `LIKE` case with `%` as the input, demonstrating that `String.escapeSingleQuotes` does not escape wildcards.
- A non-quoted context — an `ORDER BY` field or a field name — demonstrating that the fix there must be an allowlist, not escaping.
- A negative control: one input that legitimately returns two rows, so a query that always returns one cannot pass.

**Fails on:** concatenation of caller-supplied text into the query string, including the case where an escaped value was computed and the unescaped one interpolated. **Passes on:** a bind variable, `Database.queryWithBinds`, or an allowlist for the non-quoted position.

### R3 — Hostile-output render assertion (LWC; T1 — the one that runs locally)

This is the only proof in this lens that executes offline, under the repository's own `npm test` via `@salesforce/sfdx-lwc-jest`. Foreground it.

Feed every component that writes DOM manually a fixed hostile corpus from the **canary fixture set** — `<img src=x onerror="window.__pwned=1">`, `[click](javascript:alert(1))`, an `<iframe>`, a data-URI SVG — and assert: no `img` element exists in the rendered subtree, the payload appears as text rather than markup, `window.__pwned` is undefined, and no attacker-controlled host survives in any `src` or `href`.

Enumerate the components with the **registry-driven enumerator** over the LWC bundle directory rather than listing them, so a new component with a manual DOM write fails the test until someone looks at it.

**Fails on:** `lwc:dom="manual"` plus an `innerHTML` write of untrusted text. **Passes on:** template binding, or a sanitizer applied at the write.

### Not provable here, and reported as such every run

Name these in the coverage block rather than letting silence imply safety.

- **Apex runtime behavior** — whether a filter in a method body correctly scopes to the running user — unless the user runs the tests. This does *not* cover the declaration-level authorization questions R1's static half decides offline; those are reportable at T1 and must not be parked here.
- **Org-wide defaults for standard objects only.** These decide whether a sharing finding is real at all, and for a **custom** object they are in the checkout — `<sharingModel>` and `<externalSharingModel>` in `objects/X__c/X__c.object-meta.xml` — so a custom-object OWD must never appear in this block. Report only the standard objects, and only where Sharing Settings were not retrieved.
- **Permission set and profile assignment**, which decides who a grant actually reaches.
- **The live guest-user posture** — assigned permission sets and org guest-hardening settings.
- **Whether Event Monitoring or Field Audit Trail is licensed**, and therefore whether record-level read auditing exists at all.
- **Whether a `without sharing` declaration is justified.** A comment states intent; nothing in the repository verifies it.
