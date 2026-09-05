---
name: privacy-and-data-protection
title: Privacy and data protection
runs_in: fanout
activates_on:
  paths:
    - '**/consent/**'
    - '**/privacy/**'
    - '**/{analytics,tracking,telemetry}/**'
    - '**/*consent*.{ts,tsx,js,jsx,vue,svelte,py,rb,go,java,kt,cs,php}'
    - '**/*cookie*.{ts,tsx,js,jsx,py,rb,go,php}'
    - '**/*{gtm,gtag,pixel,tagmanager,datalayer}*.{ts,js,html}'
    - '**/*{checkout,payment,billing,subscription,card}*.{ts,tsx,js,jsx,py,rb,go,java,kt,php}'
    - '**/webhooks/**/*{stripe,braintree,adyen,paypal,square}*'
    - '**/*{dsar,dsr,data-subject,data-request,privacy-request,subject-access}*'
    - '**/*{account-deletion,delete-account,user-deletion,erasure,purge,anonymize,pseudonymize,retention}*.{ts,tsx,js,py,rb,go,java,kt,sql}'
    - '**/{migrations,Migrations,migrate,migration,versions,changelog}/**/*.{sql,py,rb,ts,js,cs,xml}'
    - '**/{entity,entities,model,models,Models,Entities,domain}/**/*.{ts,py,rb,go,java,kt,cs,php}'
    - '**/*{entity,entities,model,models,schema}*.{ts,py,rb,go,java,kt,cs,php}'
    - '**/{schema.prisma,schema.rb,models.py}'
    - '**/.well-known/gpc.json'
    - '**/{privacy-policy,cookie-policy,legal}*.{md,mdx,html,tsx,jsx}'
  signals:
    - '@iabtcf/core'
    - 'window.__tcfapi'
    - 'window.__gpp'
    - 'OneTrust'
    - 'OptanonConsent'
    - 'Cookiebot'
    - 'usercentrics'
    - 'didomi'
    - 'ketch'
    - 'osano'
    - 'klaro'
    - 'vanilla-cookieconsent'
    - 'react-cookie-consent'
    - "gtag('consent'"
    - 'dataLayer.push'
    - 'IABTCF_TCString'
    - 'Sec-GPC'
    - 'navigator.globalPrivacyControl'
    - '.well-known/gpc.json'
    - 'posthog-js'
    - 'mixpanel-browser'
    - '@amplitude/analytics-browser'
    - '@segment/analytics-next'
    - 'rudder-sdk-js'
    - '@fullstory/browser'
    - 'hotjar'
    - 'clarity.ms'
    - 'logrocket'
    - 'smartlook'
    - 'rrweb'
    - '@sentry/replay'
    - 'fbq('
    - 'ttq.'
    - 'snaptr('
    - '@stripe/stripe-js'
    - '@stripe/react-stripe-js'
    - 'braintree-web'
    - '@adyen/adyen-web'
    - '@paypal/paypal-js'
    - 'stripe.webhooks.constructEvent'
    - 'PaymentIntent'
    - 'card_number'
    - 'cardNumber'
    - 'cvv'
    - 'cvc'
    - '@fingerprintjs/fingerprintjs'
    - 'clientjs'
    - 'canvas.toDataURL'
    - 'deleted_at'
    - 'is_deleted'
    - 'SoftDeletes'
    - 'acts_as_paranoid'
    - 'paranoid: true'
    - '@SQLDelete'
    - 'expireAfterSeconds'
    - 'anonymize('
    - 'pseudonymize('
    - 'exportUserData'
    - 'List-Unsubscribe'
    - 'List-Unsubscribe-Post'
    - 'unsubscribe_token'
    - 'parental_consent'
    - 'age_gate'
    - 'coppa'
    - 'date_of_birth'
    - 'maxmind'
    - 'geoip-lite'
    - 'cf-ipcountry'
    - 'data_residency'
    - '@Entity'
    - '@Column('
    - 'gorm:"'
    - 'DbSet<'
    - 'declarative_base'
    - 'sequelize.define'
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: consumed
      may_conclude: [sensitive-data-at-rest]
    live-runtime:
      state: consumed
      may_conclude: [sensitive-data-at-rest]
owns:
  - lawful-basis-and-consent-capture
  - consent-gating-of-trackers
  - cookie-lawfulness-and-lifetime
  - collection-side-minimization
  - third-party-destination-inventory
  - processor-contracts-and-dpa
  - cross-border-transfer-route
  - retention-lawfulness-and-deletion-completeness
  - dsr-fulfillment-mechanics
  - pii-inventory-and-data-map
  - pseudonymization-and-reidentification-risk
  - pci-scope-and-cardholder-data
  - payment-page-script-authorization
  - automated-decision-making-rights
  - consumer-health-data-outside-hipaa
  - childrens-data-and-age-assurance
  - marketing-opt-out-mechanics
  - privacy-by-default-settings
  - fingerprinting-and-tracking-techniques
  - personal-data-severity-uplift
defers:
  session-and-cookie-management: web-and-api
  csrf: web-and-api
  application-log-and-url-content: web-and-api
  webhook-handler-integrity: web-and-api
  authz-object-level: web-and-api
  authz-property-level: web-and-api
  third-party-script-integrity-sri: web-and-api
  key-separation-derivation-and-destruction: crypto-and-key-management
  symmetric-encryption-and-nonce-handling: crypto-and-key-management
  object-storage-exposure: cloud-and-iac
  backup-and-replica-configuration: cloud-and-iac
  data-region-inventory: cloud-and-iac
  encryption-at-rest-configuration: cloud-and-iac
  control-plane-audit-logging: cloud-and-iac
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  artifact-signing-and-provenance-emission: cicd-and-supply-chain
  sbom-generation-and-attachment: cicd-and-supply-chain
  in-app-consent-mechanisms: mobile-app-security
  mobile-local-data-storage: mobile-app-security
  privacy-manifest-and-store-declarations: mobile-app-security
  llm-data-flow-inventory: llm-and-ai
  derived-store-data-inheritance: llm-and-ai
  prompt-injection: llm-and-ai
  apex-crud-fls-enforcement: salesforce-platform
  shield-encryption-caveats: salesforce-platform
  phi-classification: hipaa-and-phi
  minimum-necessary: hipaa-and-phi
  baa-coverage-determination: hipaa-and-phi
  phi-access-audit-controls: hipaa-and-phi
  phi-severity-uplift: hipaa-and-phi
  trust-boundary-inventory: threat-modeling
  exfiltration-path-enumeration: threat-modeling
frameworks:
  - gdpr
  - eprivacy-directive
  - edpb-guidelines-02-2023
  - can-spam
  - ccpa-cpra
  - coppa
  - pci-dss
  - global-privacy-control
  - apple-privacy-manifests
  - google-play-data-safety
severity_floor: low
---

> **Not legal advice.** This lens is an engineering checklist, not a legal opinion. Reading or applying it creates no attorney-client relationship. Privacy law, regulator guidance and payment-brand rules all move, and much of what this lens cites reaches a codebase only through a *national* transposition that differs between member states. Every provision cited here must be verified against its current text and against current **EDPB** and **PCI SSC** guidance before it is repeated to a client or relied on for a compliance decision. Where a finding below carries no instrument and no mandate strength, it is a security finding and ships with no citation.

## Scope

This lens audits **personal data that HIPAA does not reach**: the terminal-equipment and consent surface, the personal-data inventory, the processor and transfer perimeter, retention and erasure, data-subject rights, cardholder data, and the tracking, profiling and marketing machinery that touches all of them. Where the same repository also holds ePHI, `hipaa-and-phi` classifies it and this lens does not re-report it.

### Citation discipline — the four rules this lens is bound by

**A finding is a regulatory finding only if it maps to an actual regulatory requirement.** Everything else is a security finding, reported as one, with no citation attached.

1. **Every compliance claim cites a specific provision, and the citation must be correct.** "This violates GDPR" is not a finding. Article 5(3) of the ePrivacy Directive, the script that writes the identifier, the absence of any gate ahead of it, and the exemption that was considered and did not apply, is a finding.

2. **Every citation states its mandate strength, and the labels are not interchangeable.** A Regulation, a Directive that only binds through national law, a piece of regulator guidance, a contractual scheme and a voluntary specification impose four different things, and quoting them in one voice is how a report loses its reader. The vocabulary is fixed below and no citation ships without one of these labels.

3. **Name the right instrument, not the famous one.** The single most common error in this domain is filing cookie and tracker findings under the GDPR. Consent for **storing information, or gaining access to information already stored, in a user's terminal equipment** comes from **ePrivacy Directive 2002/58/EC Article 5(3)** as amended by 2009/136/EC and as transposed nationally. The GDPR supplies the *quality* standard for that consent (Art 4(11), Art 7) and the lawful basis for whatever downstream processing follows. Filing it as GDPR loses the only two defences the team has — the Art 5(3) exemptions — and hides that Art 5(3) reaches far more than cookies.

4. **Three categories, never conflated:** (a) a genuine regulatory or contractual requirement; (b) a security practice no instrument mandates; (c) general hygiene. A finding in category (b) or (c) is reported at its security severity **with no compliance citation attached**. Borrowing regulatory weight a finding has not earned is the fastest way to make the whole report untrustworthy.

### The citation set

These are the framework identifiers this lens may cite, and the mandate-strength label each one ships with. Nothing outside this table gets cited as an obligation.

| Identifier | Instrument | Label that ships on the citation |
|---|---|---|
| `gdpr` | Regulation (EU) 2016/679 | `Directly applicable` — a Regulation, binding as written in every member state |
| `eprivacy-directive` | Directive 2002/58/EC as amended by 2009/136/EC — Art 5(3) terminal equipment, Art 13 direct marketing | `Directive — national transposition governs`. Cite the Article for the rule and **name the transposition that actually binds**: UK PECR reg 6 and reg 22, German TDDDG § 25, French *Loi Informatique et Libertés* Art 82. Penalties, and sometimes the exemption wording, are national |
| `edpb-guidelines-02-2023` | EDPB Guidelines 02/2023 on the technical scope of Art 5(3) of the ePrivacy Directive | `Guidance — persuasive, not binding`. Supervisory authorities apply it; a court is not bound by it. Never write it as the source of an obligation — the obligation is Art 5(3) |
| `ccpa-cpra` | Cal. Civ. Code § 1798.100 *et seq.*, and the CCPA Regulations at 11 CCR § 7000 *et seq.* | `Statute` for the Code sections, `Regulation` for the CCPA Regulations |
| `coppa` | 15 U.S.C. §§ 6501-6506 and the FTC COPPA Rule, 16 CFR Part 312 | `Rule` |
| `can-spam` | CAN-SPAM Act, 15 U.S.C. §§ 7701-7713, and the FTC CAN-SPAM Rule, 16 CFR Part 316 | `Statute` for the Act — the ten-business-day opt-out duty is § 7704(a)(4)(A). `Rule` for 16 CFR Part 316, which carries the definitions, the multi-sender rule and the § 316.5 opt-out-mechanics prohibition, **not** the deadline. Do not merge the two under one label |
| `pci-dss` | PCI DSS **v4.0.1** — the only active version; v3.2.1 retired 31 March 2024 | `Contractual — not law`. PCI DSS is enforced through the acquirer contract and the payment brands, not by a statute. A few US states incorporate it by reference; verify before ever calling it a legal obligation |
| `global-privacy-control` | The GPC specification | `Specification — not law on its own.` It acquires force in California through CCPA Regulations § 7025, which is a `Regulation` |
| `apple-privacy-manifests`, `google-play-data-safety` | Platform policy | `Platform policy — not law.` Present so this lens recognizes the artifacts; the findings belong to `mobile-app-security` |

Two labels for things that are real but are not obligations, so an auditor is never tempted to dress them up as one: `Deliverability requirement` (mailbox-provider bulk-sender rules) and `Industry specification` (RFC 8058 one-click unsubscribe). Both are worth reporting. Neither is a legal citation.

### Owns

| Topic | What that means here |
|---|---|
| `pii-inventory-and-data-map` | Which fields in which stores are personal data, and whether that is recorded anywhere checkable. Every other item is parametrized over this. It also **classifies** personal data carried in URLs — the URL finding itself is `application-log-and-url-content` in web-and-api and is **not** re-filed here; see Checklist 10 |
| `lawful-basis-and-consent-capture` | Whether a lawful basis exists and, where it is consent, whether the record can demonstrate it |
| `consent-gating-of-trackers` | Whether terminal-equipment access actually waits for the answer |
| `cookie-lawfulness-and-lifetime` | Per-cookie and per-storage-key lawfulness, purpose and duration |
| `collection-side-minimization` | Fields collected at the form, endpoint or SDK that nothing consumes |
| `third-party-destination-inventory` | Every destination personal data reaches, enumerated and checkable |
| `processor-contracts-and-dpa` | Whether the destination is recorded as a processor with the contractual facts a reviewer needs. The **contract itself is never a code fact** |
| `cross-border-transfer-route` | Whether a transfer out of the EEA or UK has a Chapter V basis recorded, and whether the route in code matches it |
| `retention-lawfulness-and-deletion-completeness` | Whether deletion reaches every store and processor, and whether retention is bounded and enforced |
| `dsr-fulfillment-mechanics` | Access, rectification, erasure, portability and objection as they manifest in code, including the deadline arithmetic |
| `pseudonymization-and-reidentification-risk` | Whether a value the code calls anonymous is anonymous. `crypto-and-key-management` supplies the reversibility evidence under its defer; **this lens rates the risk and files the single finding** |
| `pci-scope-and-cardholder-data` | Where account data lives, moves and is logged |
| `payment-page-script-authorization` | PCI DSS v4.0.1 Reqs 6.4.3 and 11.6.1 — payment-page script inventory, authorization and integrity, and change detection on headers and page content |
| `automated-decision-making-rights` | Solely automated decisions with legal or similarly significant effects, and the information duties attached |
| `consumer-health-data-outside-hipaa` | Health data held by anyone HIPAA does not reach |
| `childrens-data-and-age-assurance` | Age assurance, parental consent, and what the product does with the answer |
| `marketing-opt-out-mechanics` | Unsubscribe, sale/share opt-out, and opt-out preference signals including GPC |
| `privacy-by-default-settings` | What is on before the user touches anything |
| `fingerprinting-and-tracking-techniques` | Identification by device characteristics, with or without storage |
| `personal-data-severity-uplift` | The uplift another lens's finding earns because the exposed data is personal data. This lens supplies the uplift; the owning lens supplies the finding |

### Does not own

Every key below is a `defers` entry in this lens's frontmatter. Do not raise a finding on any of them. Where the code shows one, note it in the candidate's `impact` as an aggravator and hand it to the owning lens with the file and line.

- **web-and-api** — `session-and-cookie-management`, `csrf`, `application-log-and-url-content`, `webhook-handler-integrity`, `authz-object-level`, `authz-property-level`, `third-party-script-integrity-sri`. Cookie *security* attributes, CSRF, the mechanics of what a log line or URL contains, webhook signature verification, object- and property-level authorization, and Subresource Integrity as a control. The split that matters most: **SRI implementation is web-and-api; whether a payment page has an authorized, inventoried script set is this lens's `payment-page-script-authorization`.** The URL split, stated here the same way it is stated from the other side: **web-and-api owns the identifier-in-URL finding under `application-log-and-url-content`; this lens supplies the personal-data classification and the severity uplift and does not re-file it.** `hipaa-and-phi` routes ePHI in URLs the same way. Separately, a **sequential or opaque identifier** in a URL is an access-control question and belongs to `authz-object-level`.
- **crypto-and-key-management** — `key-separation-derivation-and-destruction`, `symmetric-encryption-and-nonce-handling`. Also the reversibility proof behind `pseudonymization-and-reidentification-risk`: crypto establishes that the construction reverses, this lens rates the re-identification risk and files the finding. Never both.
- **cloud-and-iac** — `object-storage-exposure`, `backup-and-replica-configuration`, `data-region-inventory`, `encryption-at-rest-configuration`, `control-plane-audit-logging`. Cloud owns *where the bytes physically sit* (`data-region-inventory`); this lens owns whether a transfer to that place has a recorded Chapter V basis (`cross-border-transfer-route`). Reporting a region setting as a transfer violation is the failure mode this split exists to prevent.
- **cicd-and-supply-chain** — `dependency-pinning-and-lockfiles`, `artifact-signing-and-provenance-emission`, `sbom-generation-and-attachment`.
- **mobile-app-security** — `in-app-consent-mechanisms`, `mobile-local-data-storage`, `privacy-manifest-and-store-declarations`. `PrivacyInfo.xcprivacy` and the Play Data Safety declaration are that lens's findings even though this lens carries the framework identifiers, which exist so a web-side reviewer recognizes the artifact and routes it.
- **llm-and-ai** — `llm-data-flow-inventory`, `derived-store-data-inheritance`, `prompt-injection`. Whether personal data reaches a model, and what an embedding or fine-tune inherits, is that lens's inventory. Whether the model vendor is a recorded processor with a transfer basis is this lens's `processor-contracts-and-dpa`.
- **salesforce-platform** — `apex-crud-fls-enforcement`, `shield-encryption-caveats`.
- **hipaa-and-phi** — `phi-classification`, `minimum-necessary`, `baa-coverage-determination`, `phi-access-audit-controls`, `phi-severity-uplift`. If the data is ePHI held by a covered entity or business associate, that lens classifies it, rates it and uplifts it. This lens does not write a second finding on the same field. The reciprocal boundary is `consumer-health-data-outside-hipaa`: health data held by a party HIPAA does not reach is **this** lens's, and no HIPAA citation may appear on it.
- **threat-modeling** — `trust-boundary-inventory`, `exfiltration-path-enumeration`.

### What cannot be determined from code, ever

State these as assumptions with a verification step, never as findings. Whether a lawful basis is *adequate*. Whether a DPIA was required. Whether a party is controller, joint controller or processor. Whether a DPA, SCC set or intra-group agreement was actually executed, and what it says. Whether a specific cookie is "strictly necessary" for a service *the user explicitly requested*. Whether a chosen retention period is *appropriate*. Which PCI SAQ or validation channel applies — that is determined by the acquirer and the payment brands, not by the repository. Whether a service is child-directed, absent a repo-visible artifact. Whether an audience-measurement exemption applies under a particular national transposition. **Which national transposition of ePrivacy Art 5(3) applies to a surface, and whether that surface is within the territorial reach of it or of GDPR Art 3** — a repository carries indicators, never the answer, and the answer is never a condition on a finding's severity.

## Activation coverage

Vendor and framework activators are discovery signals. The status below says
whether this lens has an executable path beyond naming the product.

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| Browser consent, cookie, tracker and GPC surfaces | PARTIAL | `consent-gating-of-trackers` | Consent and GPC detectors exist, but the assigned multi-language brace paths make family-wide activation coverage partial |
| Privacy policy, destination, marketing and residency surfaces | PARTIAL | `third-party-destination-inventory` | Inventory and opt-out checks exist; legal basis, contracts and deployed destinations require external evidence |
| PostHog, Segment and session-replay surfaces | PARTIAL | `consent-gating-of-trackers` | PostHog, Segment and replay checks are actionable; vendor defaults and runtime initialization still require reading |
| Mixpanel, Amplitude and RudderStack signals | NOT ASSESSED | — | Named activation signals without a dedicated stack-specific actionable body path |
| CMP product signals | NOT ASSESSED | — | The generic consent model is actionable, but these products have no stack-specific review path |
| Stripe and card-data signals | COVERED | `pci-scope-and-cardholder-data` | detector:pci-scope-and-cardholder-data |
| Mixed-language payment pages and processor webhook paths | PARTIAL | `payment-page-script-authorization` | Generic payment and destination checks exist; non-Stripe provider branches remain NOT ASSESSED |
| Braintree, Adyen and PayPal SDK signals | NOT ASSESSED | — | Named provider activators without dedicated stack-specific checks |
| DSR, erasure, retention and pseudonymization paths | PARTIAL | `retention-lawfulness-and-deletion-completeness` | Actionable lifecycle checks exist; the broad multi-language paths are not stack-complete |
| Migration, schema, model and ORM inventory | PARTIAL | `collection-side-minimization` | Inventory and minimization checks exist; framework-specific schema semantics remain uneven |
| Fingerprinting and storage-free identification signals | PARTIAL | `fingerprinting-and-tracking-techniques` | Dedicated review questions exist; runtime entropy and destination use require measurement |

## Checklist

Notation: every citation below carries its instrument and one of the mandate-strength labels from `## Scope`. A check with no citation is a security check, and is reported as one.

Two habits that this checklist depends on, because both have produced silent all-clears in this domain before:

- **Search for the absence, not the value.** Consent Mode defaults, purge jobs, transfer-basis records and script inventories only appear in a repository when somebody opted in. A grep keyed to the opted-in literal reads every unprotected codebase as clean. Where an item below says *absence*, the search target is the missing artifact and the detector's `match` is the dangerous default shape.
- **Runtime beats grep for anything in the browser.** A tag in the markup is not proof that it fired; a tag absent from the markup is not proof that nothing fired. Where a runtime proof exists in `## Proof recipes`, the grep is triage and the recipe is the evidence.

### 1. Build the personal-data inventory first (`pii-inventory-and-data-map`)

Nothing below means anything until you know which fields are personal data. Personal data is any information relating to an identified or **identifiable** natural person (GDPR Art 4(1) — `Directly applicable`); an online identifier, a device ID, a cookie ID and an IP address are in scope. **Art 9** special categories — health, biometric data used for unique identification, sex life or orientation, racial or ethnic origin, political opinions, religious belief, trade-union membership — carry their own prohibition at Art 9(1) with the exhaustive exceptions at Art 9(2). Under CCPA the definition also reaches **household**-level data, and "sensitive personal information" is its own subcategory (Cal. Civ. Code § 1798.140 — `Statute`).

The record of this inventory is itself an obligation: **Art 30 records of processing — `Directly applicable`**, subject to the Art 30(5) derogation for organizations under 250 employees, which does not apply where processing is not occasional, is likely to result in risk, or includes Art 9 data. "We don't know what we have" is a finding, and it is the one that blocks breach scoping under Art 33(1) — `Directly applicable` — where the 72-hour clock runs from awareness and the notification must describe the categories and approximate number of data subjects affected.

- Sweep the schema, migrations, serializers and DTOs. Produce one inventory keyed by store and field; every later item is parametrized over it.

```detector
match: |
  model User {
    id           String   @id @default(cuid())
    email        String   @unique
    phone        String?
    dateOfBirth  DateTime?
    ipAddress    String?
    healthGoals  String[]
  }
nomatch: |
  model FeatureFlag {
    id        String   @id @default(cuid())
    key       String   @unique
    enabled   Boolean  @default(false)
    rolloutPc Int      @default(0)
  }
```

- Free-text columns, uploaded files, support-ticket bodies and event payloads carry personal data in shapes a column sweep misses. Record them as in-scope even when nothing can be asserted about their contents.
- A store nobody can enumerate cannot be searched on an erasure request and cannot be scoped after a breach. Note every store reached only by ad-hoc code paths.

### 2. Lawful basis and the consent record (`lawful-basis-and-consent-capture`)

Processing needs a basis under **Art 6(1) — `Directly applicable`**; Art 9 data needs an Art 9(2) condition *as well*. Whether a chosen basis is adequate is not a code fact. What *is* a code fact is whether a consent the product claims to have can be demonstrated: **Art 7(1) — `Directly applicable`** requires the controller to be able to demonstrate that the data subject consented, **Art 4(11)** requires it to be freely given, specific, informed and unambiguous by a **statement or clear affirmative action**, and **Art 7(3)** requires withdrawal to be as easy as giving.

- A boolean column cannot demonstrate consent. It records the current state and nothing about what was agreed to, when, or against which notice. The demonstrable shape is an append-only event carrying purpose, the notice or policy version, a timestamp and the capture method.

```detector
match: |
  class User(models.Model):
      email = models.EmailField(unique=True)
      marketing_opt_in = models.BooleanField(default=False)
      analytics_opt_in = models.BooleanField(default=False)
nomatch: |
  class ConsentEvent(models.Model):
      user = models.ForeignKey(User, on_delete=models.PROTECT)
      purpose = models.CharField(max_length=64)
      granted = models.BooleanField()
      notice_version = models.CharField(max_length=32)
      notice_hash = models.CharField(max_length=64)
      captured_at = models.DateTimeField(auto_now_add=True)
      method = models.CharField(max_length=32)
```

- A pre-ticked box, a default-on switch, silence or inactivity is not consent (Art 4(11), and Recital 32 spells out the pre-ticked case). This is a code-visible default, and it is the check most often passed over because the widget looks innocuous.

```detector
match: |
  class SignupForm(forms.Form):
      marketing_opt_in = forms.BooleanField(initial=True, required=False,
                                            label="Send me product news")
nomatch: |
  class SignupForm(forms.Form):
      marketing_opt_in = forms.BooleanField(initial=False, required=False,
                                            label="Send me product news")
```

- The consent record must survive its own application. A table the application role can `UPDATE` or `DELETE` cannot demonstrate anything under Art 7(1). Check the grants, not the ORM.

```detector
match: |
  GRANT INSERT, SELECT, UPDATE, DELETE ON consent_events TO app_role;
nomatch: |
  GRANT INSERT, SELECT ON consent_events TO app_role;
  REVOKE UPDATE, DELETE ON consent_events FROM app_role;
```

### 3. Terminal-equipment access and whether it waits (`consent-gating-of-trackers`)

**ePrivacy Directive Art 5(3) — `Directive — national transposition governs`.** Storing information, or gaining access to information already stored, in a user's terminal equipment requires the user's prior consent, having been given clear and comprehensive information. Two exemptions, and only two: access carried out **for the sole purpose of carrying out the transmission** of a communication, and access **strictly necessary in order to provide a service explicitly requested by the user**. Apply them before writing a finding, and say which one you considered.

The scope is much wider than cookies. **EDPB Guidelines 02/2023 — `Guidance — persuasive, not binding`** reads Art 5(3) onto tracking pixels and tracking links, `localStorage` and `sessionStorage`, IP-based tracking where the identifier is read back from the device, unique identifiers distributed in SDKs, and local processing whose result is later collected. A repository that gates cookies and not `localStorage` has gated the wrong thing.

- **Search for the absence.** Google Consent Mode's default call is opt-in code: it only exists where someone implemented it. A tag container with no `consent` `default` ahead of the first `config` is the dangerous and *common* shape, and a detector keyed to the presence of `'denied'` reads every unprotected page as clean.

```detector
match: |
  <script async src="https://www.googletagmanager.com/gtag/js?id=G-4KP2T9QX1B"></script>
  <script>
    window.dataLayer = window.dataLayer || [];
    function gtag(){dataLayer.push(arguments);}
    gtag('js', new Date());
    gtag('config', 'G-4KP2T9QX1B');
  </script>
nomatch: |
  <script>
    window.dataLayer = window.dataLayer || [];
    function gtag(){dataLayer.push(arguments);}
    gtag('consent', 'default', {
      ad_storage: 'denied', analytics_storage: 'denied',
      ad_user_data: 'denied', ad_personalization: 'denied'
    });
  </script>
  <script async src="https://www.googletagmanager.com/gtag/js?id=G-4KP2T9QX1B"></script>
```

- An SDK initialized at module scope runs on import, before any banner has rendered and regardless of what the banner later returns. The gate has to wrap the initializer, not the component that reads from it.

```detector
match: |
  import posthog from 'posthog-js'
  posthog.init(process.env.NEXT_PUBLIC_POSTHOG_KEY, {
    api_host: 'https://eu.i.posthog.com',
    persistence: 'localStorage+cookie',
  })
  export default function App({ Component, pageProps }) {
    return <Component {...pageProps} />
  }
nomatch: |
  import posthog from 'posthog-js'
  export default function App({ Component, pageProps }) {
    const { analytics } = useConsent()
    useEffect(() => {
      if (!analytics) return
      posthog.init(process.env.NEXT_PUBLIC_POSTHOG_KEY, {
        api_host: 'https://eu.i.posthog.com',
        persistence: 'localStorage+cookie',
      })
    }, [analytics])
    return <Component {...pageProps} />
  }
```

- **Territorial reach is an assumption you record, never a gate on the finding.** Which national transposition of Art 5(3) applies to a surface, and whether the surface is within its reach, is not a repository fact — so it must not be written into the condition of a finding, or the finding downgrades silently whenever nobody can evidence it. Grade the access on the access. Then record the indicators that bear on reach and state them as an assumption: EEA or UK locales in the i18n bundle, euro or sterling pricing, an EU data-residency endpoint or region config, a `cf-ipcountry` / `maxmind` / `geoip-lite` branch, a CMP configured for the IAB TCF, or an EEA or UK establishment named in the privacy policy. Note the limit in **both** directions — under GDPR Art 3(2), read with **Recital 23**, mere accessibility of a site from the Union does not by itself establish that goods or services are offered to data subjects there; and equally, finding no indicator is not evidence of exclusion.
- Server-side tagging does not remove the requirement. Art 5(3) is triggered by the read from or write to the device, not by where the collected data is sent afterwards. A `dataLayer.push` that carries a first-party cookie ID to a server-side container is still terminal-equipment access.
- Refusal must be as easy as acceptance and the banner must not pre-select. That is Art 4(11) and Art 7(3) doing the work — the ePrivacy consent takes its definition from the GDPR — so cite both, in that order.

### 4. Per-cookie and per-key lawfulness and duration (`cookie-lawfulness-and-lifetime`)

The unit of analysis is the individual cookie or storage key, its purpose and its lifetime — not the banner. Produce a table: name, purpose, first- or third-party, lifetime, and which Art 5(3) exemption is claimed if any.

- There is **no EU-wide numeric cap on cookie lifetime.** Some national regulators publish figures — the French CNIL's recommendation of a maximum around thirteen months for consent-based tracking cookies is the one most often quoted — and those are `Guidance — persuasive, not binding` from that authority, in that jurisdiction. Do not report a duration as a breach of a number that does not exist in the Directive; report an unjustified duration against the storage-limitation principle at **Art 5(1)(e) — `Directly applicable`** and name the national guidance you are measuring against.

```detector
match: |
  res.cookie('_analytics_id', visitorId, {
    maxAge: 63072000000,
    httpOnly: false,
    sameSite: 'lax',
  })
nomatch: |
  if (req.consent.analytics) {
    res.cookie('_analytics_id', visitorId, {
      maxAge: 34186698000,
      httpOnly: false,
      sameSite: 'lax',
    })
  }
```

- Cookie *security* attributes — `Secure`, `HttpOnly`, `SameSite`, session fixation — are `session-and-cookie-management` in web-and-api. Do not double-report them here.
- The consent state itself is usually stored in a cookie, which is exempt as strictly necessary. Do not flag `OptanonConsent`, `cookieyes-consent` or an equivalent as an ungated cookie; do check that it records granular per-purpose state rather than a single accept flag, because an all-or-nothing record cannot support per-purpose gating downstream.

### 5. Fingerprinting and storage-free identification (`fingerprinting-and-tracking-techniques`)

Reading device characteristics to build an identifier is **gaining access to information stored in terminal equipment** and falls under **Art 5(3)** exactly as a cookie does; EDPB Guidelines 02/2023 treat it that way. The consequence is the one auditors get backwards: **legitimate interest is an Art 6 basis under the GDPR and is not available to authorize Art 5(3) access.** The only routes are consent or the narrow strictly-necessary exemption, and generic "fraud prevention" is not automatically strictly necessary. An auditor who accepts a legitimate-interest assessment here has accepted a document that answers a different question.

```detector
match: |
  import FingerprintJS from '@fingerprintjs/fingerprintjs'
  const fp = await FingerprintJS.load()
  const { visitorId } = await fp.get()
  analytics.identify(visitorId, { firstSeen: Date.now() })
nomatch: |
  const decision = await riskCheck({
    ip: req.ip,
    userAgent: req.get('user-agent'),
    attemptsInWindow: await counter.incr(rateKey(req.ip)),
  })
  if (decision.block) return res.status(429).end()
```

- Browser countermeasures — Safari's ITP, Firefox's ETP, third-party cookie deprecation work — are **platform behaviour, not regulation**. Never cite them as the reason something is unlawful, and never treat their existence as a mitigation.
- `canvas.toDataURL`, `AudioContext` fingerprinting, font and plugin enumeration, and `navigator.hardwareConcurrency` combinations are the recurring implementations. A bot-detection vendor's script does the same thing on the vendor's behalf; the vendor's purpose does not change the analysis, it just adds a processor.

### 6. Destination inventory and the processor record (`third-party-destination-inventory`, `processor-contracts-and-dpa`)

Enumerate every destination personal data reaches: SDKs in the bundle, server-side API clients, webhooks out, log and telemetry sinks, email and SMS providers, warehouses and reverse-ETL. **Art 28(3) — `Directly applicable`** requires processing by a processor to be governed by a contract with a specified content set, and **Art 28(2) and 28(4)** govern sub-processors. **Whether that contract exists is not a code fact.** What is a code fact is whether the destination appears in *any* register at all, and whether the register carries the facts a reviewer would need.

- The finding is the **unenumerated destination**, not the missing contract. Write it that way, or the report asserts something the repository cannot support.

```detector
match: |
  requests.post(
      "https://api.leadvendor.example/v1/contacts",
      json={"email": lead.email, "phone": lead.phone, "notes": lead.free_text},
      timeout=5,
  )
nomatch: |
  processor("crm").post(
      "/v1/contacts",
      json={"email": lead.email, "phone": lead.phone},
  )
  # processors.yml: crm -> host, purpose, dpa_ref, transfer_basis, subprocessors, last_verified
```

- A destination reached only on an error path — a crash reporter, an APM breadcrumb, a support-tool integration — is the one most often missing from the register. Exercise the failure path when you enumerate.
- Sub-processor disclosure is an Art 28(2) obligation on the processor, and it is the reason a register entry naming only the top-level vendor is incomplete. Note the chain depth the register reaches.

### 7. Transfer route and its basis (`cross-border-transfer-route`)

Chapter V (Arts 44-49) — `Directly applicable`. A transfer of personal data outside the EEA needs a basis: an **adequacy decision (Art 45)**, an **appropriate safeguard (Art 46)** — most commonly the 2021 Standard Contractual Clauses under Commission Decision 2021/914, whose module must match the parties — or a derogation (Art 49), which is for occasional transfers and is not an architecture.

Three facts this lens's source material had wrong or missing, all of which change the finding:

- The **EU-US Data Privacy Framework adequacy decision (2023)** means a transfer to a DPF-certified recipient, for data inside the scope of that certification, is a transfer to an adequate destination. It needs **no SCCs and no transfer impact assessment**. Check the recipient on the DPF list and check the *scope*: certification can cover non-HR data only, and HR data outside it is not covered. There is also a **UK extension** to the framework and a separate Swiss arrangement — data originating in the UK or Switzerland is not carried by the EU decision alone.
- The **2021 SCCs remain valid**; a vendor still on them is fine. What is not fine is the retired 2001/2004/2010 sets.
- The DPF's continued validity has been litigated and is subject to periodic Commission review. Treat it as a fact to verify at report time, not a constant.

```detector
match: |
  ANALYTICS_ENDPOINT = "https://api.us-east.vendor.example/ingest"

  def emit(event, user):
      requests.post(ANALYTICS_ENDPOINT,
                    json={"uid": user.id, "email": user.email, "event": event})
nomatch: |
  ENDPOINTS = {"eu": "https://api.eu.vendor.example/ingest",
               "us": "https://api.us-east.vendor.example/ingest"}

  def emit(event, user):
      dest = ENDPOINTS[residency_for(user)]
      assert_transfer_basis(dest)   # processors.yml: adequacy | dpf | scc-2021-module-2
      requests.post(dest, json={"uid": pseudonymous_id(user), "event": event})
```

- **Where the bytes sit is `data-region-inventory` in cloud-and-iac.** A `us-east-1` region setting is not by itself a Chapter V finding, and reporting it as one is the standard false positive here. The finding is the absence of a recorded basis for a transfer the code demonstrably performs.
- Remote *access* from a third country to data stored in the EEA is a transfer. Support tooling, on-call access and offshore engineering are the routes that never appear in an architecture diagram.

### 8. Retention, erasure, and whether deletion actually lands (`retention-lawfulness-and-deletion-completeness`)

**Erasure is an outcome obligation, not a requirement to issue a synchronous `DELETE`.** Art 17(1) — `Directly applicable` — requires erasure without undue delay on the grounds listed; **Art 17(3)** exempts erasure where processing is necessary for compliance with a legal obligation, for the establishment, exercise or defence of legal claims, for archiving in the public interest, and more. Independent statutory duties — tax and accounting, employment, AML/KYC, product liability, litigation hold — affirmatively require keeping some records. Regulators accept irreversible anonymization, and the ICO's "put beyond use" position covers backups that cannot be selectively edited.

Stated as an absolute — "deletion must be true deletion, not flag-as-deleted" — this check turns every `deleted_at` column and every retained invoice row into a High finding. It is the largest false-positive generator in this domain. The correct test:

- **Search for the purge, not the flag.** A soft-delete flag with a scheduled, covering purge or an irreversible anonymization step is compliant. A soft-delete flag with **no purge path at all** is the finding, and the purge is the artifact to search for: a scheduled command, a cron entry, a migration, a retention policy on the store.

```detector
match: |
  class User extends Model
  {
      use SoftDeletes;

      protected $dates = ['deleted_at'];
  }
nomatch: |
  class User extends Model
  {
      use SoftDeletes;

      protected $dates = ['deleted_at'];
  }

  // app/Console/Kernel.php
  $schedule->command('privacy:purge-erased --grace=30d')->dailyAt('02:00');
```

- **Art 19 — `Directly applicable`** requires the controller to communicate erasure and rectification to **each recipient** to whom the data was disclosed. This is the half that fails silently: the row goes, the search index, the warehouse, the CRM and the email provider keep their copy. Enumerate the fan-out from the register built in Checklist 6.

```detector
match: |
  def delete_account(user_id):
      User.objects.filter(pk=user_id).delete()
      return HttpResponse(status=204)
nomatch: |
  def delete_account(user_id):
      with transaction.atomic():
          User.objects.filter(pk=user_id).delete()
          search.delete_document("users", user_id)
          warehouse.enqueue_erasure(user_id)
          for p in processors_receiving("user_profile"):
              p.request_erasure(user_id)
      return HttpResponse(status=204)
```

- Retention with no enforcement is not retention. A TTL declared in a policy document and absent from the store is a finding; a TTL present in the store with no policy is an unbounded-purpose finding, not a storage-limitation one. Both cite **Art 5(1)(e)**.
- Record which fields are retained under an Art 17(3) exemption, and confirm the retained set is minimized and no longer used for the original purpose. A "deleted" user still resolving in a marketing send is the concrete failure.

### 9. Data-subject request mechanics (`dsr-fulfillment-mechanics`)

**The deadline is not thirty days.** Under **Art 12(3) — `Directly applicable`** the controller must respond **without undue delay and in any event within one calendar month of receipt**, extendable by **two further months** for complex or numerous requests provided the data subject is informed of the extension and the reasons **within the first month**. A request received on 31 January is due 28 or 29 February. Under **CCPA § 1798.130(a)(2) — `Statute`** the period is **45 days from receipt**, extendable by a further 45 with notice. A hard-coded thirty-day timer both manufactures breaches that do not exist and hides the extension mechanism that makes an otherwise "failing" workflow compliant.

```detector
match: |
  DSAR_DEADLINE = timedelta(days=30)

  def is_overdue(request):
      return timezone.now() > request.received_at + DSAR_DEADLINE
nomatch: |
  from dateutil.relativedelta import relativedelta

  def due_at(request):
      if request.regime == "ccpa":
          base = request.received_at + timedelta(days=45)
          return base + timedelta(days=45) if request.extension_notified_at else base
      base = request.received_at + relativedelta(months=1)
      return base + relativedelta(months=2) if request.extension_notified_at else base
```

- **Art 15 access and Art 20 portability are not the same request and must not share one implementation blindly.** Art 15(3) is a copy of *all* personal data undergoing processing — including data the controller inferred or observed — accompanied by the Art 15(1)(a)-(h) information: purposes, categories, recipients, retention, the rights, the source, and the existence of automated decision-making. Art 20 is narrower: data the data subject **provided**, where processing rests on consent or contract and is automated, in a structured, commonly used, machine-readable format. An export that omits inferences is an Art 15 gap and **not** an Art 20 gap; saying otherwise is a wrong citation on a real finding.

```detector
match: |
  def export_me(request):
      return JsonResponse(model_to_dict(request.user))
nomatch: |
  def export_me(request):
      return JsonResponse({
          "provided": portable_payload(request.user),      # Art 20 subset
          "observed_and_inferred": observed_payload(request.user),
          "purposes": PURPOSES,
          "recipients": processors_receiving_for(request.user),
          "retention": RETENTION_TABLE,
          "sources": sources_for(request.user),
          "automated_decisions": adm_disclosures_for(request.user),
      })
```

- Rectification (Art 16) and objection (Art 21) need a path too, and an objection to direct marketing under Art 21(2) is **absolute** — there is no balancing test against it. A product that treats a marketing objection as a preference to be weighed has a code-visible defect.
- An export that silently omits a store is worse than no export. Parametrize the export over the inventory from Checklist 1 and assert the coverage.

### 10. Personal data in URLs — classification and uplift, not a finding (`pii-inventory-and-data-map`, `personal-data-severity-uplift`)

Query strings and path segments propagate into access logs, proxy logs, browser history, bookmarks, `Referer` headers to third parties, analytics `page_location` parameters, and error reports — every one of them a copy nobody will find on an erasure request.

**This lens does not file the URL finding.** It is `application-log-and-url-content`, owned outright by web-and-api, which this lens's frontmatter defers. What this lens contributes is the **classification** — which parameter or path segment is personal data, and whether it is Art 9 special-category data or CCPA sensitive personal information — and the **severity uplift** that classification earns. Hand web-and-api the file, the line and the classification. Do not open a second entry, and do not attach a GDPR citation to web-and-api's row: the uplift travels in that finding's severity and impact.

What classifies as personal data in a URL: an email address, a name, a national identifier, a date of birth, a phone number, a diagnosis or plan code, a precise location, or a search query over personal data. The redirect below is the shape to recognize and hand over.

```detector
match: |
  return redirect(f"/onboarding/verify?email={user.email}&dob={user.date_of_birth}")
nomatch: |
  request.session["verify_for"] = user.pk
  return redirect("/onboarding/verify")
```

- **A bearer, reset or invite token in a URL does not classify here.** It is a credential, not personal data under Art 4(1), and it is already web-and-api's own High row for a credential or reset token in a URL. Filing it here under a GDPR citation is the category-(b) error `## Scope` rule 4 forbids — a security finding wearing regulatory weight it has not earned.
- **A sequential or opaque identifier in a path is not a personal-data classification either.** Enumerability and cross-subject access are `authz-object-level` in web-and-api; where the identifier is a patient or record identifier, the classification is hipaa-and-phi's. **There is exactly one reporter**: web-and-api files the URL finding once, and the classification lenses uplift it in place.
- `Referrer-Policy` is the mitigation for the off-origin half and it belongs to web-and-api. Note it as the fix; do not raise it.
- A `dataLayer.push` is **not** a URL, and this half does not defer: personal data placed into an analytics payload is this lens's own finding under Checklist 6 (an enumerated destination) and Checklist 14 (over-collection).

```detector
match: |
  dataLayer.push({ event: 'signup_complete', email: user.email, plan: user.plan })
nomatch: |
  dataLayer.push({ event: 'signup_complete', user_ref: user.analyticsRef, plan: user.plan })
```

### 11. Pseudonymization and re-identification (`pseudonymization-and-reidentification-risk`)

**Pseudonymized data is still personal data.** Art 4(5) — `Directly applicable` — defines pseudonymization as processing such that the data can no longer be attributed to a data subject **without the use of additional information, which is kept separately and subject to technical and organizational measures**. Recital 26 puts genuinely anonymous information outside the Regulation entirely — and sets the bar at means "reasonably likely to be used" to identify, by the controller or anyone else. The operative test in practice remains the three criteria from the Article 29 Working Party's Opinion 05/2014 on anonymization techniques — `Guidance — persuasive, not binding`: **singling out, linkability, inference.** A dataset that fails any one of them is not anonymous.

The code-visible failure is a hash over a small or enumerable identifier space labelled as anonymization. There are finitely many email addresses, phone numbers, national identifiers and member numbers in any real population, so an unkeyed digest is a lookup away from the original.

```detector
match: |
  def anonymous_id(user):
      return hashlib.sha256(user.email.lower().encode()).hexdigest()
nomatch: |
  def pseudonymous_id(user):
      # personal data under Art 4(5); key held in KMS, never in the analytics estate
      return hmac.new(kms.decrypt(WRAPPED_PSEUDONYM_KEY),
                      user.email.lower().encode(), "sha256").hexdigest()
```

- **`crypto-and-key-management` supplies the reversibility evidence** — construction, salt or key presence, keyspace size, the cost of exhaustion — under its defer to this slug. This lens rates the re-identification risk and files **one** finding. Do not emit a second finding against the same `sha256(...)` call.
- Check that the additional information really is kept separately. A crosswalk table in the same database, readable by the same role that reads the "anonymized" set, means Art 4(5) is not satisfied and the set was never pseudonymized in the sense the Regulation means.
- Whether identifiability is judged relative to the specific holder or in absolute terms is a live question in EU case law. Do not assert a settled answer; state the assumption and the risk.

### 12. Cardholder data (`pci-scope-and-cardholder-data`)

**PCI DSS v4.0.1 — `Contractual — not law`** is the only active version. Which SAQ or validation channel applies is determined by the acquirer and the payment brands and is **not derivable from the repository** — do not assert one. What the repository does show is where account data lives and moves.

- **Sensitive authentication data may never be retained after authorization** — Req 3.3.1, with CVV/CVC/CID called out at 3.3.1.2 and full track data and PIN blocks alongside. This is the single most consequential shape in the domain.

```detector
match: |
  class Payment(models.Model):
      card_number = models.CharField(max_length=19)
      cvv = models.CharField(max_length=4)
      exp_month = models.IntegerField()
      exp_year = models.IntegerField()
nomatch: |
  class Payment(models.Model):
      processor_token = models.CharField(max_length=64)
      brand = models.CharField(max_length=16)
      last4 = models.CharField(max_length=4)
      exp_month = models.IntegerField()
      exp_year = models.IntegerField()
```

- Stored PAN must be rendered unreadable — Req 3.5.1 — and where a hash is the mechanism it must be a **keyed cryptographic hash** with associated key management (Req 3.5.1.1). A plain digest of a PAN is reversible by exhausting the space and does not satisfy it. Disk- or volume-level encryption alone is constrained by Req 3.5.1.2; read that requirement before treating it as sufficient.

```detector
match: |
  pan_index = hashlib.sha256(pan.encode()).hexdigest()
  db.execute("INSERT INTO card_index (pan_index, user_id) VALUES (%s, %s)",
             (pan_index, user_id))
nomatch: |
  token = processor.tokens.create(pan=pan)
  db.execute("INSERT INTO card_index (processor_token, user_id) VALUES (%s, %s)",
             (token.id, user_id))
```

- **Transmission and storage are different requirements and the source material conflated them.** PAN transmitted over open, public networks without strong cryptography is Req 4.2.1, with the trusted key and certificate inventory at 4.2.1.1. PAN sent over **end-user messaging technologies** — email, SMS, chat, a ticketing system — is Req 4.2.2 and is prohibited unless the PAN is protected. **Logging is storage** (Reqs 3.3 and 3.5), not transmission; file inadvertent logging there.

```detector
match: |
  send_email(to=customer.email,
             subject="Your receipt",
             body=f"We charged card {payment.card_number} for {payment.amount}.")
nomatch: |
  send_email(to=customer.email,
             subject="Your receipt",
             body=f"We charged the card ending {payment.last4} for {payment.amount}.")
```

- **Masking on display is Req 3.4.1, and it is a display requirement only.** The maximum that may be displayed is the **BIN and the last four digits**; a documented legitimate business need is required to see **more than** that, not for the BIN and last four themselves. So a receipt rendering `•••• 4242` needs no justification. "First six and last four" is the retired **v3.2.1** wording — since ISO/IEC 7812 permits an eight-digit IIN, a UI showing the first eight and last four can be compliant, so never raise this on digit count alone.
- **Do not cite 3.4.1 for a storage question.** What may be *stored* comes from the account-data table in Requirement 3, which treats cardholder name, expiration date and service code as storable cardholder data, with PAN storable only rendered unreadable under Req 3.5.1, and sensitive authentication data not retainable at all after authorization under Req 3.3.1. Last four is a truncated PAN, not full PAN. Card brand is not account data.
- Log retention for in-scope systems is Req 10.5.1 — at least 12 months of history, at least the most recent 3 months immediately available.
- Scope creep is the expensive finding: a change that introduces account data into a system that previously never touched it. Req 12.5.2 requires scope to be confirmed at least annually, so a diff that widens it is a reportable event even when nothing else is wrong.

### 13. Payment-page scripts (`payment-page-script-authorization`)

Two PCI DSS v4.0.1 requirements became **mandatory on 31 March 2025** and are the code-visible anchors for e-skimming exposure. Both apply to the payment page as it is **received by the consumer's browser**, which means the rendered page, not the template.

- **Req 6.4.3** — every script loaded and executed in the consumer's browser on a payment page must be (a) confirmed as authorized, (b) assured for integrity, and (c) carried in an **inventory with a written business or technical justification**. The inventory is the artifact to search for, and it is absence-shaped: it exists only where somebody built it.
- **Req 11.6.1** — a change- and tamper-detection mechanism must alert on unauthorized modification of the **HTTP headers and the contents of the payment page** as received by the browser, evaluated at least weekly or at a frequency set by a targeted risk analysis.

```detector
match: |
  <!-- templates/checkout.html -->
  <script src="https://js.stripe.com/v3/"></script>
  <script src="https://cdn.chatvendor.example/widget.js"></script>
  <script src="https://cdn.abtest.example/loader.js"></script>
nomatch: |
  <!-- templates/checkout.html
       every entry below is declared in compliance/payment-page-scripts.yml
       with owner, purpose and justification (Req 6.4.3) -->
  <script src="https://js.stripe.com/v3/"
          integrity="sha384-JWkVQKZ5j2t0Xn3sPq7fMxB1cN9dR4uYh6LTaE0oGv8W2SmqCbAyF5rHdKPuZ1Ni"
          crossorigin="anonymous"></script>
```

- **The SRI attribute itself is `third-party-script-integrity-sri` in web-and-api.** This lens's finding is the missing inventory, the unjustified script, and the missing change detection. Hand the integrity mechanism over rather than re-reporting it.
- A tag manager on a payment page defeats an inventory by design: the script set becomes editable outside the repository. Where one is present, say so — the inventory cannot be complete and the Req 6.4.3 answer has to come from the tag-manager configuration.
- Which SAQ a merchant validates under does not change what the code shows. **SAQ A-EP is not "minimal scope"** — see `## Known false positives` (3) and `## Severity calibration`.

### 14. Collection-side minimization (`collection-side-minimization`)

**Art 5(1)(c) — `Directly applicable`**: personal data must be adequate, relevant and limited to what is necessary. The code-visible version is a field that is collected and never read.

```detector
match: |
  class SignupSerializer(serializers.ModelSerializer):
      class Meta:
          model = User
          fields = "__all__"
nomatch: |
  class SignupSerializer(serializers.ModelSerializer):
      class Meta:
          model = User
          fields = ["email", "display_name", "country"]
```

- Trace each collected field to a consumer. A date of birth collected for an age check and then persisted is two findings: over-collection is one, and the retention of the raw value after the check is Checklist 15's.
- Analytics event payloads and log lines are collection surfaces too. An event schema that ships the whole user object is the same defect as a form that asks for too much.
- Minimum necessary for ePHI is hipaa-and-phi's `minimum-necessary`, and its treatment-context exceptions do not exist here. Do not import them.

### 15. Children's data and age assurance (`childrens-data-and-age-assurance`)

**COPPA — `Rule`, 16 CFR Part 312** applies to an operator of a website or online service **directed to children under 13**, or with **actual knowledge** that it collects personal information from a child under 13. **GDPR Art 8(1) — `Directly applicable`** sets 16 as the age for information-society-service consent, with member states free to lower it to no less than 13, and Art 8(2) requires reasonable efforts to verify that consent is given or authorized by the holder of parental responsibility, taking account of available technology.

The FTC amended the COPPA Rule in 2025. The amendments add a **separate verifiable parental consent for disclosure to third parties**, including for targeted advertising; a written **children's data security program**; a **published retention policy** with a prohibition on indefinite retention; and an expanded definition of personal information reaching biometric identifiers. **Compliance dates for the amended provisions run into 2026 — verify the current date before dating a finding**, and do not report an amended provision as though it were the pre-amendment Rule.

- An age gate that records the answer and proceeds anyway is the recurring defect. The question is what the branch *does*.

```detector
match: |
  if calculated_age < 13:
      user.is_minor = True
  create_account(user)
nomatch: |
  if calculated_age < 13:
      return start_parental_consent_flow(user)   # no account, no collection, until verified
  create_account(user)
```

- Third-party disclosure for advertising is where the amended Rule bites, and it is code-visible: an identifier leaving the app for an account known to be under 13.

```detector
match: |
  segment.track(user.id, 'level_complete', {
    advertising_id: device.advertisingId,
    age_band: user.ageBand,
  })
nomatch: |
  if (user.ageBand === 'under_13') return
  segment.track(user.id, 'level_complete', { advertising_id: device.advertisingId })
```

- **Child-direction is a determination, not a grep.** Before rating anything Critical, name the repo-visible artifact that establishes it: a `coppa` or `child_directed` configuration key, an age gate in the signup flow, a store-listing target-age declaration, an ad-SDK child-directed-treatment call, or a product surface that self-describes as for children. With no artifact, this is an assumption at Info naming the artifact you would need — never a High on vibes.
- The UK Age Appropriate Design Code reaches services likely to be accessed by **under-18s**, which is a wider population than either threshold above. Note it where the product plausibly qualifies.

### 16. Opt-out mechanics: marketing, sale and share, and preference signals (`marketing-opt-out-mechanics`)

- **Direct marketing by electronic mail** is **ePrivacy Art 13(1) — `Directive — national transposition governs`**: prior consent, with the Art 13(2) "soft opt-in" for an existing customer's own similar products where an objection opportunity was given at collection and in every message. Art 13(4) forbids disguising the sender's identity and requires a valid opt-out address. In the US the instrument is the **CAN-SPAM Act, 15 U.S.C. §§ 7701-7713 — `Statute`**, which is opt-out based; the duty to honour an opt-out within **ten business days** is **15 U.S.C. § 7704(a)(4)(A)**, and it is statutory. The FTC's implementing **CAN-SPAM Rule, 16 CFR Part 316 — `Rule`** does **not** set that period: it supplies the definitions, the sender rule for multi-sender messages, the transactional-or-relationship message treatment, and the § 316.5 prohibition on charging a fee or demanding anything beyond an email address to process an opt-out. Cite the Act for the deadline and the Rule for the mechanics — under `## Scope` rules 1 and 2 the two are not interchangeable and do not carry the same label. These are different regimes from ePrivacy; cite the one that applies to the recipient population.
- **RFC 8058 one-click unsubscribe** — `Industry specification` — is the code-level check the source material omitted: a `List-Unsubscribe` header carrying an `https:` URI **plus** `List-Unsubscribe-Post: List-Unsubscribe=One-Click`, and a handler that accepts the POST without requiring a login. Major mailbox providers require this of bulk senders; that is a `Deliverability requirement`, not a legal one, and it must not be cited as a regulatory finding.

```detector
match: |
  msg["List-Unsubscribe"] = "<mailto:unsubscribe@example.com>"
nomatch: |
  msg["List-Unsubscribe"] = "<https://example.com/u/9f3a>, <mailto:unsubscribe@example.com>"
  msg["List-Unsubscribe-Post"] = "List-Unsubscribe=One-Click"
```

- **Sale and share opt-out** is **Cal. Civ. Code § 1798.120 — `Statute`**, and honouring an **opt-out preference signal** is required by **CCPA Regulations § 7025 — `Regulation`** for a business that sells or shares personal information. GPC is that signal. Establish the sale-or-share predicate first — an advertising pixel almost always converts analytics into "sharing", which flips the answer.
- **Be precise about GPC's surfaces.** The user's signal arrives two ways: the `Sec-GPC` request header and the `navigator.globalPrivacyControl` DOM property. The `/.well-known/gpc.json` resource is the **site's own declaration** that it honours GPC — it is not a channel the user's preference travels on, and treating it as one produces a checklist that never looks at the half that fails. The genuine gap is a server that records the header while client-side tag loading never consults the DOM property, so the pixels fire regardless.

```detector
match: |
  app.use((req, res, next) => {
    res.locals.gpc = req.get('Sec-GPC') === '1'   // recorded, never acted on
    next()
  })
  // views/layout.ejs
  //   <script>fbq('init', PIXEL_ID); fbq('track', 'PageView')</script>
nomatch: |
  app.use((req, res, next) => {
    res.locals.gpc = req.get('Sec-GPC') === '1'
    if (res.locals.gpc) optOut.applyToBrowser(req, res)
    next()
  })
  // views/layout.ejs
  //   <script>
  //     if (!navigator.globalPrivacyControl && consent.saleShare) loadPixels()
  //   </script>
```

- The link text is not fixed. "Your Privacy Choices" with the opt-out icon is permitted, and § 1798.135(b) — `Statute` — relieves a business that processes opt-out preference signals in a frictionless manner of the link obligation on the conditions stated there. Do not report a missing exact string as a violation.

### 17. Privacy by default (`privacy-by-default-settings`)

**Art 25(2) — `Directly applicable`**: by default, only personal data necessary for each specific purpose is processed, and personal data must not by default be made accessible to an indefinite number of people without the individual's intervention. This is a default-value check and it is unusually mechanical.

```detector
match: |
  class Profile(models.Model):
      visibility = models.CharField(max_length=16, default="public")
      share_location = models.BooleanField(default=True)
      indexable_by_search = models.BooleanField(default=True)
nomatch: |
  class Profile(models.Model):
      visibility = models.CharField(max_length=16, default="private")
      share_location = models.BooleanField(default=False)
      indexable_by_search = models.BooleanField(default=False)
```

- Check the migration as well as the model: a default flipped in a later migration, or a backfill that set an existing population to the permissive value, is the same defect with no visible default.

### 18. Consumer health data outside HIPAA (`consumer-health-data-outside-hipaa`)

Health data held by a party HIPAA does not reach — a wellness or fitness app, a symptom tracker, direct-to-consumer testing, an employer program — is **outside HIPAA entirely**, and a HIPAA citation on it is a wrong citation. The instruments that do reach it: **Art 9 — `Directly applicable`** where the EU applies; **Washington's My Health My Data Act — `Statute`**, notable because it carries a **private right of action**, with comparable statutes in other states; the **FTC Act § 5 — `Statute`**; and the FTC's **Health Breach Notification Rule, 16 CFR Part 318 — `Rule`**, whose amended scope reaches health apps and connected devices.

```detector
match: |
  fbq('trackCustom', 'SymptomLogged', {
    condition_code: entry.conditionCode,
    external_id: user.email,
  })
nomatch: |
  telemetry.count('symptom_logged')   // first-party, no condition, no identifier
```

- The escalating fact is the **combination**: an identifier plus a condition, symptom, medication or clinic name leaving for an advertising destination. Either alone is a lower finding.
- If the entity *is* a covered entity or business associate, stop: this is `phi-classification` in hipaa-and-phi.

### 19. Automated decisions (`automated-decision-making-rights`)

**Art 22(1) — `Directly applicable`**: a data subject has the right not to be subject to a decision based **solely** on automated processing, including profiling, which produces legal effects or similarly significantly affects them — subject to the Art 22(2) exceptions, and where the decision rests on the contract or explicit-consent exceptions at Art 22(2)(a) and (c), Art 22(3) still requires at minimum human intervention on the controller's part, the ability to express a point of view, and the ability to contest. The transparency duties are **Arts 13(2)(f), 14(2)(g) and 15(1)(h)**: meaningful information about the logic involved and the significance and envisaged consequences.

```detector
match: |
  if model.score(application) < 0.4:
      application.status = "rejected"
      application.save()
      notify(application.user, "Your application was declined.")
nomatch: |
  score = model.score(application)
  if score < 0.4:
      application.status = "pending_review"
      review_queue.enqueue(application, reason=explain(model, application))
      application.save()
```

- "Solely" is the load-bearing word, and a rubber-stamp human is not meaningful intervention. The code-visible test is whether the reviewer receives enough to overturn the decision and whether an override path exists at all.
- California has adopted regulations on automated decision-making technology with their own compliance dates. **Verify the current status and dates before citing them**; this lens does not restate them.

### 20. Personal-data severity uplift (`personal-data-severity-uplift`)

Where another lens's finding exposes data this lens has classified as personal, this lens supplies the uplift and the other lens keeps the finding. Two rules, both of which have been broken in practice:

- **Never uplift on the presence of a privacy framework identifier.** A repository that mentions GDPR is not thereby a GDPR finding.
- **Never write a parallel finding to carry the uplift.** The uplift travels in the existing finding's severity and impact, not as a second entry in the report.

The worked case, because it is the one this lens got wrong once: **personal data in a URL.** The finding is web-and-api's `application-log-and-url-content`. This lens says which parameter is personal data and how sensitive it is, that raises web-and-api's severity, and no row appears in this lens's own `## Severity calibration` for it. See Checklist 10.

## Severity calibration

Severity is the **security and privacy impact** of the defect. Mandate strength is a separate axis and lives in the citation, never in the severity. `severity_floor: low` is presentational: it orders this lens's findings in the report and never suppresses one.

**Every Critical and High below names the concrete artifact that establishes its condition.** A severity conditioned on a property no file, key or symbol can evidence can never be satisfied, and the finding silently downgrades forever.

| Finding | Severity | Citation, mandate strength, and the artifact that establishes the condition |
|---|---|---|
| Full PAN or sensitive authentication data (CVV/CVC, track data, PIN block) persisted, or reaching a log or analytics sink | Critical | PCI DSS v4.0.1 Reqs 3.3.1 and 3.5.1 — `Contractual — not law`. **Artifact:** the column in the schema, or the canary recovered from a captured sink in recipe P1 |
| Art 9 special-category data, or consumer health data, transmitted to an advertising destination with an identifier attached | Critical | GDPR Art 9(1) — `Directly applicable`; where HIPAA does not apply, also Washington MHMDA — `Statute` — and FTC Act § 5 — `Statute`. **Artifact:** the payload key plus the destination, from the recorded destination set in recipe P3 |
| Personal data of a child disclosed to a third party for targeted advertising with no verifiable parental consent | Critical | COPPA, 16 CFR Part 312 — `Rule`. **Artifact:** a repo-visible child-direction marker — a `coppa` or `child_directed` config key; an ad-SDK child-directed call, by symbol: `setTagForChildDirectedTreatment`, `tagForChildDirectedTreatment`, `TAG_FOR_CHILD_DIRECTED_TREATMENT`, `setTagForUnderAgeOfConsent`, `child_directed_treatment`; an age gate; or a store-listing target-age declaration, by file: the Play Console target-audience declaration, or `PrivacyInfo.xcprivacy` and App Store age-rating metadata — the store-declaration finding itself is `mobile-app-security`'s under `privacy-manifest-and-store-declarations`, which this lens defers; here it is evidence of child-direction only — **plus** the outbound identifier. With no child-direction artifact this is Info with a verification step, never Critical |
| Non-essential terminal-equipment access before consent | High | ePrivacy Art 5(3) — `Directive — national transposition governs`, read with GDPR Art 4(11) and Art 7 for consent quality. **Artifact:** a request recorded before any interaction in recipe P2, or a tag initialized at module scope with no gate. **Territorial reach is not a condition on this grade.** Which national transposition applies, and whether a surface is within its reach, is not a repository fact — it is reported as a stated assumption in the coverage block, with whatever indicators Checklist 3 found. Do not withhold or downgrade the finding for want of it |
| Soft delete with no purge path — the erasure never completes | High | GDPR Art 17(1) and Art 5(1)(e) — `Directly applicable`. **Artifact:** the soft-delete column, and the **absence** of any scheduled command, cron entry, migration or store TTL referencing it |
| Erasure not propagated to a recipient — search index, warehouse, CRM, email provider | High | GDPR Art 19 — `Directly applicable`. **Artifact:** the deletion handler's call set diffed against the processor register from Checklist 6 |
| Personal data reaching a destination that appears in no register at all | High | GDPR Art 30 — `Directly applicable` — for the missing record; Art 28(3) is the contract question and is **not** a code finding. **Artifact:** the destination from recipe P3 with no matching register entry |
| Stored PAN under an unkeyed hash | High | PCI DSS v4.0.1 Reqs 3.5.1 and 3.5.1.1 — `Contractual — not law`. **Artifact:** the digest call and the column it writes |
| A value the code labels anonymous that is a hash over an enumerable identifier space, used to justify processing outside the regime | High | GDPR Art 4(5) and Recital 26 — `Directly applicable`; WP29 Opinion 05/2014 — `Guidance — persuasive, not binding`. **Artifact:** the hash construction, plus the code path that relies on the "anonymous" label. Reversibility evidence comes from crypto-and-key-management; the finding is filed once, here |
| Payment page with third-party scripts and no inventory, or no change detection on headers and page content | High | PCI DSS v4.0.1 Reqs 6.4.3 and 11.6.1 — `Contractual — not law`, mandatory since 31 March 2025. **Artifact:** the script tags on the rendered checkout page, and the **absence** of an inventory file and of a monitoring job |
| Solely automated decision with legal or similarly significant effect and no human-review path | High | GDPR Art 22(1) and 22(3) — `Directly applicable`. **Artifact:** the branch that writes the terminal status with no review-queue call |
| Transfer outside the EEA with no basis recorded anywhere | Medium–High | GDPR Chapter V, Arts 44-46 — `Directly applicable`. **Artifact:** the destination host, and a register entry with no `transfer_basis`, or no register. Escalates to High where Art 9 data is in the payload. **A region setting alone is not this finding** |
| Consent stored as a mutable boolean, so consent cannot be demonstrated | Medium | GDPR Art 7(1) — `Directly applicable`. **Artifact:** the column, and `UPDATE`/`DELETE` grants on the consent table |
| Pre-ticked or default-on consent control | Medium | GDPR Art 4(11) with Recital 32 — `Directly applicable`. **Artifact:** the default value in the form or model |
| DSR deadline hard-coded to 30 days | Medium | GDPR Art 12(3) — `Directly applicable`; CCPA § 1798.130(a)(2) — `Statute`. **Artifact:** the constant. Both directions are defects: it manufactures breaches and it hides the extension path |
| Export endpoint returning a raw model dump with no Art 15(1) information elements | Medium | GDPR Art 15(1) and 15(3) — `Directly applicable`. Omitting inferences is an Art 15 gap and **not** an Art 20 gap |
| Opt-out preference signal recorded server-side but never consulted by the client tag loader | Medium | CCPA Regulations § 7025 — `Regulation`, conditional on the sale-or-share predicate. **Artifact:** the middleware that reads `Sec-GPC`, and the tag loader that does not read `navigator.globalPrivacyControl` |
| Over-collection: a field collected and read nowhere | Low–Medium | GDPR Art 5(1)(c) — `Directly applicable`. Escalates where the field is Art 9 data or a national identifier |
| Privacy-hostile default setting | Low–Medium | GDPR Art 25(2) — `Directly applicable` |
| Cookie lifetime unjustified against the stated purpose | Low | GDPR Art 5(1)(e) — `Directly applicable`. **There is no EU-wide numeric cap**; name the national guidance you measured against and label it `Guidance` |
| `List-Unsubscribe` present with no `List-Unsubscribe-Post` one-click | Low | RFC 8058 — `Industry specification`; a `Deliverability requirement` for bulk senders. **No legal citation.** The legal finding is a missing or non-functioning opt-out, which is ePrivacy Art 13 — `Directive — national transposition governs` — or CAN-SPAM Act 15 U.S.C. § 7704(a)(4)(A) — `Statute` — for the ten-business-day duty, with 16 CFR Part 316 — `Rule` — for the opt-out mechanics |
| No self-service access or export endpoint, where a documented runbook with an owner and evidence of meeting the deadline exists | Low–Info | Arts 15 and 20 are outcome obligations. This becomes a real finding only when fulfilment is impossible or unverifiable — no data map, stores nobody can enumerate, no record of requests and response dates |
| Missing encryption, missing MFA, or a weak secret on a personal-data path | At its security severity | **No compliance citation.** Category (b) under `## Scope` rule 4. Art 32 — `Directly applicable` — may be named as context, never as a specific mandated control |

Four anti-patterns, stated as rules because each one has shipped:

- **The URL case is an uplift, not a row.** Personal data in a URL is web-and-api's finding under `application-log-and-url-content`; this lens raises its severity by classifying the content and carries **no row of its own** for it. A row here would be the parallel finding Checklist 20 forbids, and it would put a GDPR citation on a route web-and-api has already filed.
- **Never file a cookie or tracker finding under the GDPR alone.** The instrument is ePrivacy Art 5(3) and its national transposition; the GDPR supplies the consent standard. A report that gets this backwards tells the client to fix the wrong thing.
- **Never treat SAQ A-EP as a small answer.** It is the largest e-commerce SAQ, and a scoping recommendation that lands a merchant there is expensive advice. See `## Known false positives` (3).
- **Never downgrade a security finding because no regulator mandates the control.** Rule 4 removes the citation. It does not remove the finding.

## Known false positives

Each entry names a pattern a competent reviewer would flag and states why it is not the finding it looks like. **None is a licence to drop a finding**: every one names the narrower finding that survives.

1. **A soft-delete column (`deleted_at`, `is_deleted`, Laravel `SoftDeletes`, `acts_as_paranoid`, Hibernate `@SQLDelete`), or retained invoice, order and audit rows after an erasure request.** Erasure is an outcome obligation, not a requirement to issue a synchronous `DELETE`. Art 17(1) requires erasure without undue delay, Art 12(3) requires the response within one month, and Art 17(3) plus independent statutory duties — tax and accounting, employment, AML/KYC, product liability, litigation hold — affirmatively require keeping some records. Irreversible anonymization is accepted, and backups that cannot be selectively edited are handled by the "put beyond use" approach rather than by immediate deletion. Look for the purge job, its schedule and its coverage. **The surviving findings:** a soft delete with no purge path at all; a purge window that extends past the response deadline with no documented justification; and retained rows still being used for the original purpose, of which a "deleted" user still resolving in a marketing send is the concrete case.

2. **A tracking script tag, cookie write or SDK initializer that appears in code running before the banner is answered.** Two lawful explanations dominate. The access may be exempt under ePrivacy Art 5(3) as strictly necessary for a service the user explicitly requested — the consent-state cookie itself, session and CSRF tokens, load-balancer affinity, language and currency preference, fraud and rate-limit tokens, cart state — or the tag may be present but gated by a consent platform that blocks or wraps it until opt-in, or by Consent Mode with `analytics_storage` and `ad_storage` defaulted to `denied`. **Prove it at runtime:** record network requests in a fresh browser context and check whether anything carries an identifier or writes a non-essential cookie before interaction. A finding built on grepping the document head is wrong more often than right. **The surviving finding** is what the recording shows, and it is stronger evidence than the grep ever was.

3. **A Luhn-valid card-shaped string in the repository (`4242424242424242`, `4111111111111111`, `5555555555554444`), or a stored and displayed last four plus brand.** Processor test PANs in fixtures, seed data, Cypress and Playwright specs and documentation are published values that cannot authorize a transaction; flagging them as a PCI breach is the most common automated false positive in this domain. Last four plus brand plus expiry is not a finding either, and processor webhooks legitimately carry it — but cite the right requirement for each half: **display** is Req 3.4.1, whose maximum is the BIN and last four (not "first six and last four", which is the retired v3.2.1 wording); **storage** of the expiration date and cardholder name comes from the account-data table in Requirement 3, not from 3.4.1. **The surviving findings:** real PANs, full-PAN persistence or logging, and any sensitive authentication data — CVV/CVC, full track data, PIN blocks — which may never be retained after authorization.

4. **A session-replay or heatmap SDK (`@fullstory/browser`, `hotjar`, `clarity.ms`, `logrocket`, `smartlook`, `rrweb`, `@sentry/replay`) present in the bundle.** Presence alone is not the finding — but **the default is not the same across these seven, and clearing them as a group is how a genuine High gets closed.** Some mask input by default and some record it. Read the configuration object per vendor, against the defaults below:

   - `hotjar` — keystrokes on inputs suppressed by default; capture is opted into per element with `data-hj-allow`. Presence is not the finding.
   - `clarity.ms` — text and input values masked by default; unmasking is opted into with `data-clarity-unmask`. Presence is not the finding.
   - `@sentry/replay` — `maskAllText` and `maskAllInputs` both default **true**. Presence is not the finding.
   - `rrweb` — **records input by default.** `maskAllInputs` defaults to `false` and text is not masked unless a mask class or selector is configured; only password inputs are masked out of the box. **The finding is the absence** of `maskAllInputs: true`, and of any text-masking option, in the `record({ ... })` call. Do **not** grep for `maskAllInputs: false` — that is the default, so it appears only where somebody typed it redundantly, and the dangerous shape (`rrweb.record({ emit })` with no masking options at all) contains no literal to find.
   - `logrocket` — **records input by default.** `dom: { inputSanitizer: true }` is opt-in. **The finding is the absence** of `inputSanitizer: true`, or of per-field privacy classes, in the `LogRocket.init(...)` options.
   - `@fullstory/browser`, `smartlook` — **default not verified here; do not clear either on this entry.** Check the vendor's current documented default for input and text capture, record what you checked and when, and grade on that. FullStory in particular has changed its default posture, so a remembered answer is not good enough.

   **The surviving findings, all narrower:** on a vendor that masks by default, an explicit unmask allowlist (`data-hj-allow`, `fs-unmask`, `data-clarity-unmask`, a permissive block or ignore class set); on a vendor that does not, the missing masking option per the two absence checks above; sensitive values rendered as page *text* and therefore captured despite **input** masking; replay enabled before consent; the vendor absent from the processor register or with no transfer basis; and replay on an authenticated page that renders someone else's data.

5. **An application that ignores `Sec-GPC`, or that has no link reading exactly "Do Not Sell or Share My Personal Information".** Both are conditional obligations. The duty to honour an opt-out preference signal attaches to a business that sells or shares personal information or processes it for cross-context behavioural advertising; a purely first-party application with no advertising pixels and no data sales does not breach the CCPA by ignoring GPC. The link text is not fixed either — "Your Privacy Choices" with the opt-out icon is permitted, and § 1798.135(b) relieves a business that handles the signal frictionlessly, on the conditions stated there. **Establish the sale-or-share predicate first** — a Meta, Google Ads or TikTok pixel almost always converts analytics into sharing, which flips the answer. **The surviving finding** is the half-implementation: the `Sec-GPC` header honoured on document requests while client-side tag loading never consults `navigator.globalPrivacyControl`, so the pixels fire anyway. Note that `/.well-known/gpc.json` is the **site's declaration** that it honours GPC, not a channel the user's signal arrives on; its absence is a disclosure gap, not a failure to honour.

6. **Personal data flowing to a US processor with no SCCs or transfer impact assessment in the repository.** Since the 2023 EU-US Data Privacy Framework adequacy decision, a transfer to a DPF-certified recipient, within the scope of that certification, is a transfer to an adequate destination as a matter of law and needs neither SCCs nor a TIA. Check the recipient on the DPF list and check the certification **scope** — HR data is frequently outside it. A vendor on the 2021 SCCs is also fine; those did not stop being valid. **The surviving findings:** an uncertified recipient with no safeguard at all; reliance on a retired SCC set; UK or Swiss data relying on the EU-only decision; a sub-processor chain terminating somewhere nobody assessed; and the framework's own continued validity, which is subject to review and should be verified rather than assumed.

### Rejected candidates

Candidates considered and deliberately excluded. Nothing here should be quietly re-added: each would have suppressed a real finding, or belongs in a section that can enforce it rather than in a rule that suppresses.

- **"Opaque or sequential identifiers in URL paths, under personal-data-in-URLs."** Not a false positive — a duplicate. Enumerability and cross-subject access are `authz-object-level` in web-and-api, and the ePHI variant is hipaa-and-phi's. Checklist 10 keeps no URL finding at all: the finding is web-and-api's `application-log-and-url-content` and this lens supplies only the personal-data classification and the uplift.
- **"IP address or city-level geolocation treated as sensitive personal information."** The underlying fact is right — CCPA sensitivity turns on *precise* geolocation, defined by an approximately 1,850-foot radius, so an IP-derived city or region does not trigger the limitation right — but as a suppression rule it invites an auditor to dismiss IP data entirely. IP is still personal data under the GDPR, at a different finding and a different severity. Carried as a calibration note in Checklist 1, not as a false positive.
- **"No self-service SAR or export endpoint."** A severity cap, not a suppression: Arts 15 and 20 are outcome obligations, so a documented runbook with an owner and evidence of meeting the deadline is compliant. Recorded in `## Severity calibration` at Low–Info with the conditions that make it real.
- **"A cookie banner is present, therefore trackers are gated."** Rejected outright: banner presence is not gating, and this is the single most effective way to make a real pre-consent finding disappear. Entry 2 carries the narrow, evidence-based version.
- **"Analytics with IP anonymization enabled is exempt from the consent requirement."** Rejected: IP truncation is a GDPR minimization measure and has no effect on ePrivacy Art 5(3), which is triggered by the write to or read from the device. Accepting it clears a genuine pre-consent finding on a technicality that does not apply.
- **"Server-side tagging removes the consent requirement."** Rejected for the same reason: the Art 5(3) trigger is terminal-equipment access, not the destination of the data afterwards. A first-party cookie ID forwarded server-side is still an access.
- **"The vendor publishes a DPA on their website, so the Art 28 obligation is met."** Rejected as unverifiable from a repository, and it would close the one finding that *is* code-visible — the destination that appears in no register at all.
- **"PCI does not apply because the integration uses hosted fields."** Rejected: hosted fields reduce scope, they do not remove the merchant page from the e-skimming surface that Reqs 6.4.3 and 11.6.1 address, and the validation channel is not determinable from the repository in any case.
- **"Fixtures and lower environments are out of scope for privacy findings."** Rejected: production-derived personal data outside production is in scope. The discriminator is provenance evidence, not resemblance — and the resemblance-only case is an assumption at Info, not a dropped finding.
- **"Consent is implied by continued use of the site."** Not a false positive at all — it is a defect, and listing it here would have inverted the rule. Art 4(11) requires a clear affirmative action.
- **"A `deleted_at` row is acceptable because backups get overwritten eventually."** Rejected: unverifiable from the repository and it suppresses the no-purge-path finding. The backup-specific position is narrower than the sentence implies and applies to backups, not to live tables.

## Proof recipes

Shared harness components are referenced by name and not restated: the **registry-driven enumerator**, the **socket-layer destination recorder**, the **canary fixture set**, the **capturing log handler**, and the **clock control** (`freezegun` / `jest.setSystemTime`). Their implementations live in `lenses/_harness.md`.

**Tier rule.** T1 is a proof the repository's own test command executes. T2 starts infrastructure the repository does not already start. An accepted authenticated operator statement naming the target, scope, and T2 launch is the sole authorization fact; the operator is accountable for it, and the auditor does not ask again or independently adjudicate legal authority. Execute only through a matching implemented controller. A recipe that lacks that route reports `UNPROVEN` with the technical transport gap, capped at Medium — never as a silent pass.

**One rail, stated before the recipes because breaking it makes the test perform the violation it is testing for:** a browser-level tracking test must **record and abort** every request to a host outside the first-party allowlist. Letting the request continue actually sends the beacons, carrying the page URL to real advertising infrastructure.

### P1 — Registry-driven personal-data canary sweep of every sink (T1)

Populate every field in the Checklist 1 inventory with an unmistakable canary (`canary+pii@example.test`, `SENTINEL-DOB-1971-03-04`, `PAN-CANARY-4000056655665556`), attach the **capturing log handler** to the *real* logger so formatters and serializers run, stub each vendor's **transport** rather than its API, exercise the happy path *and* a forced exception inside the handler, then grep every sink for the canary and its derived encodings: base64, base64url, hex, URL-encoded, JSON-escaped, gzip+base64, reversed.

**The regression multiplier:** parametrize the sweep over the model's own field registry using the **registry-driven enumerator**, so a newly added personal-data column fails the test until it is registered with the scrubber. Assert the discovered field count against a checked-in number, so an enumerator that silently returns zero rows cannot pass.

**Fails on:** whichever field the denylist forgot; a formatter that stringifies the whole model; an exception path that logs the request body; a PAN or CVV reaching any sink. **Passes on:** an allowlist-based scrubber.

### P2 — Pre-consent terminal-equipment access, in a real browser (T2)

The primary evidence for the Art 5(3) bug class, and it is T2: it needs a browser driven against a booted application, which most repositories do not stand up in their test command. Open a **fresh context** with no storage, load the page, and **without interacting** capture (a) every outbound request and (b) every cookie and `localStorage`/`sessionStorage` key written. Assert that no request reaches a host outside the first-party allowlist and that no non-essential key was written. Then accept, then reject, and assert the difference.

```detector
match: |
  await context.route('**', (route) => {
    seen.push(route.request().url())
    route.continue()
  })
nomatch: |
  await context.route('**', (route) => {
    const url = route.request().url()
    seen.push(url)
    if (isFirstParty(url)) return route.continue()
    return route.abort()
  })
```

**The T1 fallback covers less than it looks like it does.** Server-rendered markup can be asserted for tag presence and for a `consent` `default` call ahead of the first `config`, and that is worth running — but it cannot see a tag injected by a tag manager, and it cannot prove what actually fired. Report the fallback as partial coverage, never as a clean result.

### P3 — Destination-set assertion at the socket layer (T1)

Install the guard *first* so an unexpected connection fails loudly instead of quietly reaching the internet — `pytest-socket` with `socket_allow_hosts`, a monkeypatched `socket.getaddrinfo`/`create_connection`, or `nock.disableNetConnect()`. Exercise every personal-data code path with the **socket-layer destination recorder** installed, then assert the recorded destination set is a subset of the committed register. Allowlist entries are anchored patterns, never prefix matches, with a self-test proving a longer hostname sharing a prefix is not matched.

Run the error paths too: crash reporters and APM breadcrumb uploads are the destinations most often missing from the register.

**This proves where data goes. It cannot prove a DPA exists, and it cannot prove a transfer basis is valid** — those are contract facts. The register's `last_verified` date is a human claim and the only thing the test can assert about it is staleness.

### P4 — Clock-controlled deletion, retention and DSR arithmetic (T1)

Seed canaries into every store the **registry-driven enumerator** discovers, call the deletion API, invoke the purge job **explicitly** rather than waiting on a schedule, then assert zero residue per store, that each processor stub recorded an erasure or suppression call, and that the registry is exhaustive — fail if any table matching the personal-data classifier is absent from it.

Retention: two rows per rule, one just inside and one just outside the window; advance the **clock control**; assert the outside row is gone **and the inside row is untouched**. The second half is what stops an over-broad purge from passing.

Legal hold: seed a record retained under an Art 17(3) exemption — an invoice is the canonical case — and assert it **survives** while being flagged non-marketable. Without this assertion the fix "delete everything" passes the test and breaks the law.

Deadline arithmetic: assert a request received on 31 January is due 28 or 29 February and not 2 March, that the extension path requires the notification to have been sent inside the first month, and that a CCPA-regime request computes 45 days with a further 45 available.

Consent immutability: attempt `UPDATE consent_events SET granted = false` and `DELETE FROM consent_events` **as the application role** and assert both are refused.

**Caveat, stated rather than hidden:** the grant-based assertions require a real engine with the roles the repository's own migrations provision. On SQLite, or where the migrations do not create an application role, that half is `UNPROVEN` and is reported as such.

### P5 — Detector-plus-fixture pairs for the static checks (T1)

Every Checklist detector in this lens ships as an executed pair: `detect(fixtures/vulnerable/X) == 1` **and** `detect(fixtures/clean/X) == 0`. A checker that only passes on good input proves nothing about detection. Run these over the **rendered** artifact wherever one exists — the built page markup, not the template — since that is also what PCI DSS Req 11.6.1 measures.

The absence-shaped detectors need one extra assertion each, because they fail in a way the presence-shaped ones do not: assert that the check **fires on a fixture from which the artifact has been removed**. A rule that passes by matching nothing is worthless.

### P6 — Payment-page script inventory diff (T1)

Render the checkout page, extract every `<script src>` and every dynamically injected loader, and diff the set against the committed inventory. Fail on any script absent from the inventory and on any inventory entry with no justification field. Assert that a change-detection job exists and names the payment page and its response headers.

This is the T1 half of PCI DSS Reqs 6.4.3 and 11.6.1. The monitoring half — that the alert actually fires and is actually seen — is a process fact and is reported as an assumption.

### Not provable here, and reported as such every run

Name these in the report's coverage block rather than letting silence imply safety: whether a lawful basis is adequate; whether a DPIA was required; controller, joint-controller or processor characterization; whether a DPA, SCC set or intra-group agreement was executed and what it says; whether a specific cookie is strictly necessary for a service the user explicitly requested; whether a retention period is appropriate; which PCI SAQ or validation channel applies; whether a service is child-directed absent a repo-visible artifact; **which national transposition of ePrivacy Art 5(3) applies to a surface, whether that surface is within its territorial reach or within GDPR Art 3, and whether the transposition differs in a way that changes the answer** — report the Checklist 3 indicators you found and state this as an assumption, because pre-consent findings are graded without it; and whether a monitoring alert is acted on by a human.
