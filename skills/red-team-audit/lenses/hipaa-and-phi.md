---
name: hipaa-and-phi
title: HIPAA and PHI compliance
runs_in: fanout
activates_on:
  paths:
    - '**/*patient*'
    - '**/*phi*'
    - '**/*ehr*'
    - '**/*emr*'
    - '**/*clinical*'
    - '**/*encounter*'
    - '**/*diagnos*'
    - '**/*medication*'
    - '**/*fhir*'
    - '**/*hl7*'
    - '**/*.hl7'
    - '**/*.ccda'
    - '**/*mrn*'
    - '**/*hipaa*'
    - '**/*baa*'
    - '**/*consent*'
    - '**/*deident*'
    - '**/*anonymi*'
    - '**/*claim*'
    - '**/*eligibility*'
    - '**/*x12*'
    - '**/*.edi'
    - '**/*audit*log*'
    - '**/migrations/**/*patient*'
    - '**/db/seeds/**'
    - '**/fixtures/**/*patient*'
    - '**/objects/HealthCloudGA__*/**'
    - '**/objects/**/*.object-meta.xml'
    - '**/objects/**/*.field-meta.xml'
    - '**/permissionsets/*.permissionset-meta.xml'
    - '**/profiles/*.profile-meta.xml'
    - '**/namedCredentials/*.namedCredential-meta.xml'
    - '**/remoteSiteSettings/*.remoteSite-meta.xml'
    - '**/cspTrustedSites/*.cspTrustedSite-meta.xml'
    - '**/customMetadata/*.md-meta.xml'
    - '**/index.html'
    - '**/_document.{tsx,jsx}'
    - '**/app/layout.{tsx,jsx}'
    - '**/*gtm*'
    - '**/*tagmanager*'
  signals:
    - 'fhir.resources / fhirclient / fhir-kit-client / @types/fhir / hapi-fhir / org.hl7.fhir'
    - 'hl7apy / python-hl7 / node-hl7-client / nhapi'
    - 'smart-on-fhir, launch/patient, scopes like patient/*.read or user/Observation.read'
    - '@google-cloud/healthcare / google-cloud-healthcare, boto3.client("healthlake"), Azure.Health.Deidentification'
    - 'epic / cerner / oracle-health / athenahealth / redox / metriport / 1up.health / canvas-medical SDKs or base URLs'
    - 'stedi / pyx12 / availity / changehealthcare, X12 837/835/270/271 parsing'
    - 'icd10 / simple_icd_10 / snomed / loinc / cpt / rxnorm / npi lookup libraries'
    - 'column or field names: mrn, medical_record_number, date_of_birth, dob, ssn, member_id, subscriber_id, diagnosis_code, icd10_code, npi'
    - 'HealthCloudGA__ objects, PersonAccount, Salesforce Shield Platform Encryption, Event Monitoring'
    - 'plain (non-Health-Cloud) Salesforce ePHI model: identifier-bearing fields in objects/**/*.field-meta.xml, and Case, Contact or Account carrying the patient record'
    - 'Salesforce declarative outbound destinations: namedCredentials/*.namedCredential-meta.xml, remoteSiteSettings/*.remoteSite-meta.xml, cspTrustedSites/*.cspTrustedSite-meta.xml, endpoints held in customMetadata/*.md-meta.xml'
    - 'Salesforce declarative over-grants on the ePHI object: <viewAllFields>, <viewAllRecords>, <modifyAllRecords> in permissionsets/ or profiles/'
    - 'telemetry SDKs on a PHI path: @sentry/*, datadog / dd-trace, logrocket, mixpanel, amplitude, @segment/analytics, posthog, newrelic — match the import or the initializer, never the bare vendor name'
    - 'session replay / heatmap: fullstory, hotjar, clarity.ms, smartlook'
    - 'trackers in markup or first-party bundles: googletagmanager.com/gtm.js, gtag(, connect.facebook.net, fbq(, _fbp, google-analytics.com, googleads'
    - 'exclusion the three lines above depend on: committed build output and vendored bundles — dist/, build/, out/, .next/, public/vendor/, node_modules/, vendor/, *.min.js, *.bundle.js, *.chunk.js. A hit there is not a telemetry finding until a first-party import or call site is named'
    - 'messaging clients used with patient data: twilio, @sendgrid/mail, mailgun, boto3 ses, firebase-admin messaging / apns payloads'
    - 'LLM clients on clinical text: anthropic, openai, azure-openai, bedrock-runtime invoke_model'
    - 'literal markers: PHI, ePHI, "business associate", "Safe Harbor", "minimum necessary", "break glass", "break-glass"'
    - 'audit-trail idioms: audit_log, access_log table with actor_id + record_id, pgaudit, CloudTrail data events, trigger-based history tables'
    - 'Salesforce audit idioms, which live in metadata and never in Apex: Shield Event Monitoring (EventLogFile, ApiEvent, ReportEvent), Field Audit Trail (FieldHistoryArchive, <historyRetentionPolicy>), Setup Audit Trail, <enableHistory> and <trackHistory> in object and field metadata'
    - 'de-identification idioms: faker + patient, synthea, scrub, redact, tokenize, crosswalk, re-identification key'
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: consumed
      artifact_kinds: [oci-image]
      may_conclude: [sensitive-data-at-rest]
    deployed-state:
      state: consumed
      may_conclude: [sensitive-data-at-rest]
    live-runtime:
      state: consumed
      may_conclude: [sensitive-data-at-rest]
owns:
  - phi-classification
  - baa-coverage-determination
  - minimum-necessary
  - phi-deidentification-standard
  - phi-access-audit-controls
  - phi-encryption-sufficiency
  - phi-in-lower-environments
  - breach-notification-exposure
  - hipaa-policy-documentation-retention
  - phi-severity-uplift
defers:
  authz-object-level: web-and-api
  authz-property-level: web-and-api
  error-handling-and-verbose-responses: web-and-api
  application-log-and-url-content: web-and-api
  graphql-api-surface: web-and-api
  ssrf-application-path: web-and-api
  symmetric-encryption-and-nonce-handling: crypto-and-key-management
  tls-and-certificate-validation: crypto-and-key-management
  key-separation-derivation-and-destruction: crypto-and-key-management
  password-hashing-and-kdf-parameters: crypto-and-key-management
  encryption-at-rest-configuration: cloud-and-iac
  object-storage-exposure: cloud-and-iac
  backup-and-replica-configuration: cloud-and-iac
  control-plane-audit-logging: cloud-and-iac
  kms-key-lifecycle-and-policy: cloud-and-iac
  ci-secret-and-token-handling: cicd-and-supply-chain
  privileged-deploy-gate: cicd-and-supply-chain
  prompt-injection: llm-and-ai
  llm-data-flow-inventory: llm-and-ai
  derived-store-data-inheritance: llm-and-ai
  mobile-local-data-storage: mobile-app-security
  mobile-ui-and-notification-leakage: mobile-app-security
  platform-keystore-key-custody: mobile-app-security
  apex-crud-fls-enforcement: salesforce-platform
  salesforce-platform-logging-surface: salesforce-platform
  shield-encryption-caveats: salesforce-platform
  third-party-destination-inventory: privacy-and-data-protection
  processor-contracts-and-dpa: privacy-and-data-protection
  consumer-health-data-outside-hipaa: privacy-and-data-protection
  pseudonymization-and-reidentification-risk: privacy-and-data-protection
  consent-gating-of-trackers: privacy-and-data-protection
  pci-scope-and-cardholder-data: privacy-and-data-protection
  personal-data-severity-uplift: privacy-and-data-protection
  collection-side-minimization: privacy-and-data-protection
  trust-boundary-inventory: threat-modeling
  exfiltration-path-enumeration: threat-modeling
  stride-decomposition: threat-modeling
frameworks:
  - hipaa-security-rule
  - hipaa-privacy-rule
  - hipaa-breach-notification-rule
  - 42-cfr-part-2
  - nist-sp-800-66
  - nist-sp-800-111
  - nist-sp-800-52
  - fips-140
severity_floor: low
---

> **Not legal advice.** This lens is an engineering checklist, not a legal opinion. Reading or applying it creates no attorney-client relationship. Regulatory text, HHS Office for Civil Rights (OCR) guidance and case law all move; every provision cited here must be verified against the current text of 45 CFR Parts 160 and 164, 42 CFR Part 2, and current OCR guidance before it is repeated to a client or relied on for a compliance decision. Where a provision's mandate strength is not stated below, the finding is a security finding and carries no citation.

## Scope

This lens audits **electronic** protected health information. Its subject is the HIPAA Security Rule technical safeguards at 45 CFR §164.312, the Privacy Rule provisions that manifest as code (minimum necessary, de-identification, individual rights), the Breach Notification Rule's exposure surface, and the 42 CFR Part 2 overlay for federally assisted substance-use-disorder programs.

### Citation discipline — the four rules this lens is bound by

**A finding is a HIPAA finding only if it maps to an actual HIPAA requirement.** Everything else is a security finding, reported as one.

1. **Every compliance claim cites a specific provision, and the citation must be correct.** "This violates HIPAA" is not a finding. §164.312(a)(2)(i) with the unique-user-identification requirement stated, the code path that defeats it, and the acting identity that is unrecoverable, is a finding.

2. **Required and Addressable are not the same thing.** §164.306(d) makes several §164.312 implementation specifications *addressable*. For an addressable specification the obligation under §164.306(d)(3) is to assess whether the safeguard is a reasonable and appropriate measure in the entity's environment, implement it if it is, and otherwise **document why not and implement an equivalent alternative measure** if that is reasonable and appropriate. The required artifact is therefore the *documented decision*, not the control. Encryption at rest (§164.312(a)(2)(iv)) is the canonical case: it is addressable, not mandated, so an unencrypted-PHI-column finding is a **risk-analysis and documentation** finding under §164.308(a)(1)(ii)(A) — Required — and §164.316(b)(1) — Standard — with its Required implementation specifications at §164.316(b)(2), and not a violation of §164.312. Every citation below states which kind it is. Reporting an addressable specification as a violation manufactures exposure that does not exist, and somebody acts on it.

   **The Required/Addressable split is the part of this lens most exposed to regulatory change.** A January 2025 HHS notice of proposed rulemaking would remove the addressable category from the Security Rule and make its specifications requirements. **A proposed rule is not law**, and this lens is written against the rule as it stands. **Status as of 2026-07-27, verified by web search:** the NPRM published in the Federal Register on 6 January 2025; the comment period closed 7 March 2025; no final rule has issued as of July 2026, with OCR still working through roughly 4,745 public comments; OMB's Unified Agenda (**RIN 0945-AA22**) now targets **July 2027** for final action, pushed back from an earlier spring-2026 target — not a binding date, and it could move again. **The current Security Rule remains in effect, so the Required/Addressable distinction under §164.306(d) stands and every `Addressable` label in this file is valid as written.** If that rulemaking is later finalized, the effect on this lens is wider than a set of labels. Void, and needing rework rather than a find-and-replace, are: **every `Addressable` label** in the file; **every finding written as a §164.306(d)(3) assessment-and-documentation gap**, which would become a direct Required-provision finding; **every severity cap that rests on a specification being addressable**, including the Medium caps in `## Severity calibration`; and **every passage that reasons in prose from addressability without using the label** — the §164.308(a)(3) rationale in the severity table and the §164.312(e)(1) transmission-security framing are the two that matter most. **Re-check RIN 0945-AA22 before relying on this past July 2027**, or sooner if OCR announces a final rule, and never cite a proposal as a requirement.

3. **§164.312 applies to ePHI only.** Paper, fax on an analog line, and oral PHI are outside this lens.

4. **Three categories, never conflated:** (a) a genuine regulatory requirement; (b) a security practice the regulation does not mandate; (c) general hygiene. A finding in category (b) or (c) is reported at its security severity **with no compliance citation attached**. Borrowing regulatory weight for a finding that has not earned it is the fastest way to make the whole report untrustworthy.

### Owns

| Topic | What that means here |
|---|---|
| `phi-classification` | Whether a given field, column, log line, object key or payload is ePHI at all. Every other lens's PHI question resolves here. |
| `baa-coverage-determination` | Whether ePHI reaches a destination that is inside the covered entity's business-associate perimeter, and whether that perimeter is recorded anywhere checkable. |
| `minimum-necessary` | §164.502(b), including its six statutory exceptions. |
| `phi-deidentification-standard` | §164.514(b) Safe Harbor element coverage, §164.514(c) re-identification codes, and whether the de-identified set is actually severable from the crosswalk. |
| `phi-access-audit-controls` | §164.312(b): whether activity in systems containing ePHI is recorded and examinable, and whether the acting human is recoverable from the record. |
| `phi-encryption-sufficiency` | Whether the encryption that exists is *sufficient for the stated threat model* and whether the §164.306(d)(3) assessment exists. Not whether a bucket flag is set. |
| `phi-in-lower-environments` | Production-derived ePHI in dev, staging, CI, fixtures, laptops or notebooks — judged on provenance, never on resemblance. |
| `breach-notification-exposure` | §164.400-414 exposure: whether an incident could be scoped at all, and whether the encryption safe harbor could actually apply. |
| `hipaa-policy-documentation-retention` | §164.316(b)(2)(i) documentation retention, and whether configured log retention matches the organization's own stated policy. |
| `phi-severity-uplift` | The uplift another lens's finding earns because the data is ePHI. This lens supplies the uplift; the owning lens supplies the finding. |

### Does not own

Do not raise findings on these. Where the code shows one, note it in the candidate's `impact` as an aggravator and let the owning lens raise it, or hand it over with the file and line.

- **Not ePHI at all.** Paper records, analog fax, and oral disclosure. Those route to the Privacy Rule (45 CFR §164.500-534) and to the **physical** safeguards at §164.310 — facility access, workstation use and security, device and media controls — none of which this lens audits. A surface that is paper-, fax- or oral-only produces **zero findings here**; say so explicitly rather than reaching for a §164.312 citation. The one thing that *is* in scope is the conversion point: a fax-to-email or fax-to-SFTP gateway, a scan-to-object-storage intake, or a transcription pipeline creates ePHI, and everything downstream of that point is auditable here.
- **web-and-api** — `authz-object-level`, `authz-property-level`, `error-handling-and-verbose-responses`, `application-log-and-url-content`, `graphql-api-surface`, `ssrf-application-path`. Cross-patient and cross-tenant access control, verbose error bodies, and what ends up in a log line or a URL are all that lens's findings. This lens classifies the data and supplies the uplift.
- **crypto-and-key-management** — `symmetric-encryption-and-nonce-handling`, `tls-and-certificate-validation`, `key-separation-derivation-and-destruction`, `password-hashing-and-kdf-parameters`. Cipher mode, nonce handling, TLS version and cipher suites, and KDF parameters.
- **cloud-and-iac** — `encryption-at-rest-configuration`, `object-storage-exposure`, `backup-and-replica-configuration`, `control-plane-audit-logging`, `kms-key-lifecycle-and-policy`. The storage-layer encryption *flag*, bucket exposure, backup and replica configuration, control-plane logging, and key lifecycle. This lens owns whether the resulting posture is sufficient for ePHI and whether the §164.306(d)(3) assessment exists; it does not re-report the flag.
- **cicd-and-supply-chain** — `ci-secret-and-token-handling`, `privileged-deploy-gate`.
- **llm-and-ai** — `prompt-injection`, `llm-data-flow-inventory`, `derived-store-data-inheritance`. Whether clinical text reaches a model, and what an embedding or fine-tune inherits, is that lens's inventory. Whether the destination is inside the BAA perimeter is this lens's `baa-coverage-determination`.
- **mobile-app-security** — `mobile-local-data-storage`, `mobile-ui-and-notification-leakage`, `platform-keystore-key-custody`. On-device stores, lock-screen and screenshot leakage, and keystore custody.
- **salesforce-platform** — `apex-crud-fls-enforcement`, `salesforce-platform-logging-surface`, `shield-encryption-caveats`.
- **privacy-and-data-protection** — `third-party-destination-inventory`, `processor-contracts-and-dpa`, `consumer-health-data-outside-hipaa`, `pseudonymization-and-reidentification-risk`, `consent-gating-of-trackers`, `pci-scope-and-cardholder-data`, `personal-data-severity-uplift`, `collection-side-minimization`. In particular: health data held by a party that is **not** a covered entity or business associate is outside HIPAA entirely and belongs to `consumer-health-data-outside-hipaa` — wellness apps, direct-to-consumer testing, employer programs. Do not write a HIPAA finding against an entity HIPAA does not reach.
- **threat-modeling** — `trust-boundary-inventory`, `exfiltration-path-enumeration`, `stride-decomposition`.

### What cannot be determined from code, ever

State these as assumptions with a verification step, never as findings. A BAA's existence and contractual scope. Whether a specific retention period is *appropriate*. Whether a de-identification expert determination under §164.514(b)(1) is sound. Whether fixture data is production-derived, absent repo-visible provenance. Whether a clinical field is necessary for treatment. Workforce training, sanction policy, and every physical safeguard.

## Activation coverage

The domain vocabulary in `activates_on` intentionally finds more healthcare
stacks than this lens has executable, stack-specific checks for.

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| Patient, PHI, clinical, consent and audit-data discovery | PARTIAL | `phi-classification` | Classification and audit checks exist; broad vocabulary activation is not proof that every data flow was traced |
| FHIR, HL7 and X12 content | PARTIAL | `phi-classification` | Classification and message-shaped checks exist; parser- and transaction-specific coverage is incomplete |
| Business-associate perimeter and BAA artifacts | PARTIAL | `baa-coverage-determination` | A dedicated perimeter decision path exists; executed agreements and provider status remain outside the repository |
| De-identification and anonymization paths | PARTIAL | `phi-deidentification-standard` | Safe Harbor, expert-determination and re-identification checks exist; runtime data cannot be established from source alone |
| Seed, fixture and lower-environment patient data | PARTIAL | `phi-in-lower-environments` | Provenance and crosswalk checks exist; repository fixtures do not establish every deployed lower environment |
| Salesforce declarative ePHI, grants, destinations and audit metadata | PARTIAL | `phi-classification` | Metadata detectors and reading paths exist; licensed org controls and deployed grants remain external |
| Tracking, replay, messaging and LLM flows carrying ePHI | PARTIAL | `phi-tracking-technologies` | Destination and telemetry checks exist; vendor defaults and complete data-flow tracing remain manual |
| C-CDA, clinical coding libraries and named EHR, clearinghouse or cloud-healthcare SDKs | NOT ASSESSED | — | Activation-only format and vendor families; no dedicated actionable body checks |

## Checklist

Notation: **every provision this lens cites falls into exactly one of the eleven cases below, and no citation ships without one.** Five carry a label; six are deliberately unlabelled, and the reader must be able to tell which from the citation itself.

Labels that ship on a finding's citation:

| Label | Meaning |
|---|---|
| `Required` | A §164.306(d) Required implementation specification. **Security Rule only.** |
| `Addressable` | A §164.306(d) Addressable implementation specification — assess, implement if reasonable and appropriate, otherwise document why not and adopt an equivalent measure. **Security Rule only**, and see the rulemaking caveat in `## Scope` rule 2. |
| `Standard` | A Subpart C **standard** — §164.308, §164.310, §164.312, §164.314 or §164.316. Its obligation comes from **§164.306(c)**, which requires compliance with the applicable standards. (Not §164.306(b), which is *Flexibility of approach* and mandates nothing.) The obligation does not depend on whether implementation specifications hang beneath it. Most standards *do* have specifications; **those carry their own separate `Required` or `Addressable` label and never change the standard's own force.** So a standard whose specifications are all Addressable is still obligatory: the flexibility §164.306(d) grants is in *how* it is met, never in *whether*. Where a standard has no specification at all (§164.312(b), §164.312(d)) the regulation names no mechanism, so a finding may cite the standard and must not claim the regulation requires a particular control. |
| `General rule` | §164.306 — General rule — itself neither a standard nor a classified specification, but it does impose duties: **§164.306(c)** — General rule — (comply with the applicable standards) and **§164.306(d)(3)** (for an addressable specification, assess it, then implement it or document why not and adopt an equivalent alternative measure). §164.306(d)(3) is the provision an addressable-specification finding is actually written against, so it needs a label of its own. |
| `Mandatory` | A Privacy Rule, Breach Notification Rule or 42 CFR Part 2 obligation. **Those regimes have no Required/Addressable structure at all** — that taxonomy exists only at §164.306(d). Never label a Privacy Rule provision `Required`; it imports a Security Rule concept that does not apply and invites the reader to look for an addressable escape hatch that does not exist either. |

Two consequences worth stating, because getting either backwards produces a wrong finding in opposite directions:

- **Never read "the specifications are Addressable" as "the standard is unenforceable."** That inference is wrong, and it would wave away real findings. When an Addressable specification is the control at issue, the correct move is to reframe the finding as a §164.306(d)(3) assessment-and-documentation gap — not to conclude that nothing is owed. A failure of the *standard* is separately citable when the evidence supports it.
- **Never attach `Required` or `Addressable` to a Subpart C standard.** Those words are §164.306(d)'s classification of specifications only. A **Subpart C** standard takes the `Standard` label; its specifications take theirs. Note the scoping: the Privacy Rule also heads many paragraphs "Standard" — §164.502(b)(1) — Mandatory — §164.502(e)(1) — Mandatory — §164.504(e)(1) — Mandatory — and §164.522(b)(1) — Mandatory — among them. Those are **`Mandatory`**, not `Standard`, because they sit outside Subpart C and outside §164.306 entirely.

Six cases are deliberately unlabelled, because none of them is an obligation and none can be violated. State the case when citing one, so the reader is never left guessing which:

- **Definition** — §160.103, and §164.402 with its three exceptions. Definitions and their exceptions decide whether a rule reaches a fact pattern; they impose nothing. The obligations sit in the sections that use them.
- **Permission** — §164.502(a)(1)(i), §164.506, §164.508 (authorization), §164.512(a) (uses and disclosures required by law), §164.514(c). These exist only to authorize something. Failing a condition attached to one does not violate it — it means the permission never applied, so the underlying prohibition at §164.502(a) governs. Cite it that way. The category is narrow: it does **not** reach a provision that is conditional in form but that the rule and OCR treat as the operative obligation — §164.502(e)(1) is the example, and it is `Mandatory`.
- **Condition of a claim** — §164.514(b)(2) Safe Harbor, and §164.514(b)(1) expert determination. These state the test a covered entity must satisfy *if it wants to rely on the de-identification exemption*. Failing the test does not violate §164.514; it means the data was never de-identified, §164.502(d)(2) does not apply, and it is still PHI carrying every PHI obligation. That is the finding, and its operative citation is §164.502(a) — Mandatory.
- **Exception or exemption** — §164.502(b)(2) and its six subparagraphs, §164.528(a)(1)(i), §164.502(d)(2), and §164.402's three exceptions. These carve conduct *out* of an obligation. Nothing is owed under them, so they cannot be violated and never carry a label; their whole use is to stop a finding being written where the standard does not reach. Applying them is mandatory before filing — see rule 1 in `## Scope`.
- **Scope or routing reference** — §164.310 (physical safeguards), §164.500 (Privacy Rule subpart), §164.306(b) (*Flexibility of approach*, which mandates nothing on its own), §164.306(d) (the paragraph that *classifies* specifications, cited to explain the taxonomy rather than to ground a finding; its subparagraph §164.306(d)(3) does impose a duty and is a General rule), and a bare section or range naming a body of law as a whole — §164.308, §164.312, §164.314, §164.316, §164.514, §164.400-414. A bare section number is an umbrella reference: the labelled provision is always the subsection, never the section. Cited to tell the reader where a question belongs, never as the basis of a finding, so no label attaches.
- **Other regime** — 45 CFR Part 171 (Cures Act information blocking) and SSA §1179 / 42 U.S.C. 1320d-8 (payment-processing exclusion). Named to route the reader to the right body of law or to mark where HIPAA stops. **Never cited as a HIPAA finding**, and never given a HIPAA mandate-strength label.

One convention, so the list above stays finite: **a labelled provision covers its own subparagraphs** unless the subparagraph is separately classified. §164.524 — Mandatory — carries §164.524(b)(2); §164.316(b)(2) — Required — carries (b)(2)(i). A subparagraph is called out separately only where its label differs from its parent, which inside Subpart C is the normal case and outside it is rare.

### 1. Classify the data first (`phi-classification`)

Nothing below means anything until you know which fields are ePHI. PHI is **individually identifiable health information** transmitted or maintained by a covered entity or business associate (45 CFR §160.103). The eighteen identifier categories at §164.514(b)(2)(i)(A)-(R) are the *de-identification* standard, not the definition of PHI — use them as a classification aid, and do not report "field X is one of the 18 identifiers" as a finding on its own. An identifier becomes ePHI when it is held in conjunction with health information: diagnosis, procedure, medication, condition, encounter, or payment for care. Note that category (R) is a catch-all for any other unique identifying number, characteristic or code, so the list is not the closed enumeration it appears to be — it does not let you rule a field *out*.

- Sweep schema, migrations, serializers and DTOs for identifier-bearing fields alongside clinical fields. Produce one inventory; every later item is parametrized over it.

```detector
match: |
  class Patient(Base):
      __tablename__ = "patients"
      mrn = Column(String(20), nullable=False, index=True)
      date_of_birth = Column(Date)
      icd10_code = Column(String(8))
nomatch: |
  class Clinic(Base):
      __tablename__ = "clinics"
      npi = Column(String(10), nullable=False)
      facility_name = Column(String(120))
      billing_tax_id = Column(String(9))
```

- **On a Salesforce org the data model is declarative, and it is not in Health Cloud.** There are no migrations and no ORM classes to sweep: the inventory comes from `objects/**/*.object-meta.xml` and `objects/**/*.field-meta.xml`, and `HealthCloudGA__` is one org shape out of two. The commoner shape has no `HealthCloudGA__` anywhere and carries ePHI on standard objects used by convention — `Case` as the episode or the patient record itself, `Contact` or `Account` as the patient, `Task` and `ContentVersion` as the note and the attachment — beside `__c` custom fields whose `<label>` says what they hold when the API name does not. Read the label and the `<type>`, not just the name. The same declarative surface carries the access decision: `<viewAllFields>`, `<viewAllRecords>` and `<modifyAllRecords>` in `permissionsets/` or `profiles/` grant over the whole object regardless of sharing, and `viewAllFields` bypasses field-level security, which no organization-wide default grants — that is a `minimum-necessary` input on a non-treatment role and an aggravator on every other finding against the object. The FLS mechanism itself is `apex-crud-fls-enforcement` in salesforce-platform.

```detector
match: |
  <!-- force-app/main/default/objects/Case/fields/Member_MRN__c.field-meta.xml -->
  <fullName>Member_MRN__c</fullName>
  <label>Medical record number</label>
  <type>Text</type>
nomatch: |
  <!-- force-app/main/default/objects/Provider__c/fields/NPI__c.field-meta.xml -->
  <fullName>NPI__c</fullName>
  <label>National provider identifier</label>
  <type>Text</type>
```

- Provider identifiers are not patient identifiers. An NPI, a DEA number, a practitioner name or a facility tax ID identifies the *provider*, and a table of them carries no individually identifiable health information. Do not classify a provider directory as ePHI.
- Object keys, file paths and cache keys that embed an enumerated identifier put that identifier into access logs, bucket inventories, CDN logs and error reports. This is a classification finding here; the log-content finding itself belongs to `application-log-and-url-content` in web-and-api.

```detector
match: |
  s3.put_object(Bucket="clinic-inbound-fax",
                Key=f"{patient.mrn}/{page}.tiff",
                Body=tiff)
nomatch: |
  s3.put_object(Bucket="clinic-inbound-fax",
                Key=f"{uuid4()}.tiff",
                Body=tiff,
                Metadata={"patient_ref": surrogate_key(patient)})
```

- Interchange formats carry ePHI in shapes a column sweep misses: FHIR `Patient`, `Observation`, `Condition`, `MedicationRequest` and `DocumentReference` resources; HL7 v2 `PID`, `OBX`, `DG1` segments; X12 837/835/270/271 loops. Free-text notes and scanned attachments are ePHI and are the least tractable class in the repo — record them as in-scope even when nothing can be asserted about them. The recurring miss is the **raw message or document persisted alongside the parsed columns**: the parsed fields get classified and the blob does not.

```detector
match: |
  @app.post("/hl7/inbound")
  def inbound():
      msg = hl7.parse(request.data.decode())
      Encounter.objects.create(mrn=msg.segment("PID")[3][0],
                               dx=msg.segment("DG1")[3][1],
                               raw_message=request.data.decode())
nomatch: |
  @app.post("/hl7/inbound")
  def inbound():
      msg = hl7.parse(request.data.decode())
      Encounter.objects.create(mrn=msg.segment("PID")[3][0],
                               dx=msg.segment("DG1")[3][1])
      phi_archive.put(request.data, classification="ePHI", retention="policy-4.2")
```

### 2. Access control — §164.312(a)(1) — Standard, with four implementation specifications of differing strength

**Unique user identification — §164.312(a)(2)(i) — Required.** Assign a unique name and/or number for identifying and tracking user identity. The auditable question is whether the *acting human* is recoverable from any record of the access.

```detector
match: |
  POOL_USER = "app_service"

  def get_chart(patient_id):
      rows = db.query("SELECT * FROM encounters WHERE patient_id = %s", patient_id)
      audit.write(actor=POOL_USER, action="read_chart", record=patient_id)
      return rows
nomatch: |
  def get_chart(patient_id, actor: User):
      rows = db.query("SELECT * FROM encounters WHERE patient_id = %s", patient_id)
      audit.write(actor=actor.id, on_behalf_of=actor.impersonated_by,
                  action="read_chart", record=patient_id)
      return rows
```

- A pooled connection user, a shared kiosk login, or a service account that acts on behalf of several humans without carrying the human's identity defeats this specification. Write the finding as "the acting user is unrecoverable at *every* layer" — check the application audit table, the database audit facility, and the gateway/IdP log before asserting it.
- A service-to-service identity that never acts for a human is fine and needs no per-human attribution. Do not file this against a nightly ETL that reads the whole table under its own identity — that is a `minimum-necessary` question instead.

**Emergency access procedure — §164.312(a)(2)(ii) — Required.** Establish and implement procedures for obtaining necessary ePHI during an emergency. In code this is the break-glass path, and the specification is satisfied by the path *existing and being controlled*; the audit obligation comes from §164.312(b).

```detector
match: |
  if user.has_role("emergency_override"):
      return Encounter.objects.all()
nomatch: |
  if user.has_role("emergency_override"):
      audit.write(actor=user.id, action="break_glass_read",
                  justification=request.justification, scope=request.scope)
      alerts.notify_privacy_officer(user.id, request.justification)
      return Encounter.objects.filter(facility=request.scope)
```

- The finding shape is an override path that is indistinguishable in the audit record from ordinary access, or one with no scope limit and no justification capture. An override path with distinct logging and an alert is a correct implementation, not a finding.
- The *absence* of a break-glass path is not a code finding — it is a documented-procedure question. Note it as out-of-code.

**Automatic logoff — §164.312(a)(2)(iii) — Addressable.** Implement electronic procedures that terminate an electronic session after a predetermined time of inactivity. Because it is addressable, the finding is not "the session is too long"; it is either (a) no inactivity termination exists at *any* layer, so an unattended shared workstation stays authenticated indefinitely, or (b) no §164.306(d)(3) assessment records the decision and no equivalent measure was adopted.

```detector
match: |
  app.use(session({
    cookie: { maxAge: null },
    rolling: false,
    store: new RedisStore({ client, ttl: 0 })
  }))
nomatch: |
  app.use(session({
    cookie: { maxAge: 15 * 60 * 1000 },
    rolling: true,
    store: new RedisStore({ client, ttl: 900 })
  }))
```

- Do not file a token-lifetime finding on a session that has server-side idle tracking, or where an OS lock, VDI policy or IdP session control terminates it — but do not *clear* the finding on the assumption that such a control exists either. If you cannot see the terminating layer, write it as an assumption with the verification step at Info, per rule 4.

**Encryption and decryption — §164.312(a)(2)(iv) — Addressable.** This is the provision most often misreported, and getting it wrong is why this lens was rewritten. Encryption of ePHI at rest is **not mandated**. What an auditor can actually be short of is the §164.306(d)(3) decision itself. Cite the risk-analysis specification §164.308(a)(1)(ii)(A) — Required — and the documentation standard §164.316(b)(1) — Standard — whose implementation specifications at §164.316(b)(2) are Required.

- The storage-layer configuration itself is `encryption-at-rest-configuration` and belongs to cloud-and-iac. Managed stores encrypt by default with no off switch on the major clouds, so "no encryption block in the Terraform" usually means nothing at all.
- What stays here: **self-managed storage with no encryption facility in use**, encryption verifiably disabled, and any threat model that explicitly includes the database operator or a stolen snapshot — which is an argument for application-layer envelope encryption, and must be written as that argument rather than as a bare citation.

```detector
match: |
  con = sqlite3.connect("/var/data/patients.db")
  con.execute("INSERT INTO patients (mrn, dob, icd10) VALUES (?, ?, ?)",
              (mrn, dob, icd10))
nomatch: |
  con = sqlcipher3.connect("/var/data/patients.db")
  con.execute("PRAGMA key = ?", (kms.decrypt(WRAPPED_DEK),))
  con.execute("INSERT INTO patients (mrn, dob, icd10) VALUES (?, ?, ?)",
              (mrn, dob, icd10))
```

### 3. Audit controls — §164.312(b) — Standard (no implementation specification)

Implement hardware, software, and/or procedural mechanisms that **record and examine** activity in information systems that contain or use ePHI. The regulation names no mechanism and does not require the mechanism to live in application code. A flat "there is no audit log" claim is not verifiable from one service's source — see `## Known false positives` (1).

- The defensible finding is about **attribution and examinability**, not about the presence of an `audit_log` insert. Three checkable shapes: the record exists but names only a pooled principal; the record exists but cannot answer "which records did this user read" because it logs endpoints rather than record identifiers; nothing anywhere records reads, only writes.
- §164.308(a)(1)(ii)(D) **Information system activity review — Required** is the companion: records that are written and never examined do not satisfy it. Look for the review job, dashboard or report, not just the writer.
- **Where the platform records rather than the application, name the artifact you checked.** On Salesforce the whole mechanism lives in metadata and setup and never in Apex, so a source-only sweep sees an absence that may not exist: Shield Event Monitoring and its `EventLogFile`, `ApiEvent` and `ReportEvent` records; Field Audit Trail, its `FieldHistoryArchive` big object and the object's `<historyRetentionPolicy>`; Setup Audit Trail; and `<enableHistory>` on an object with `<trackHistory>` on each tracked field. Split them by what a checkout can settle: `<enableHistory>`, `<trackHistory>` and `<historyRetentionPolicy>` are committed metadata and are checkable here; Event Monitoring is a licensed add-on whose purchase and enablement are not repository facts, so it is an assumption with a named verification step, per false positive 1. History tracking is also **not** a read log — it records field changes, so it answers "what was altered" and never "which records did this identity read", which is the §164.312(b) question and the one a breach population needs. The platform's own logging surface is `salesforce-platform-logging-surface` in salesforce-platform; what stays here is whether the acting human and the records read are recoverable at all.
- Audit records must be resistant to alteration by the application role that writes them. This is a security finding when the regulation is silent, and a §164.312(c)(1) Integrity question when the audit record is itself part of the ePHI record set.

```detector
match: |
  GRANT INSERT, SELECT, UPDATE, DELETE ON phi_access_log TO app_role;
nomatch: |
  GRANT INSERT, SELECT ON phi_access_log TO app_role;
  REVOKE UPDATE, DELETE ON phi_access_log FROM app_role;
```

- Whether an audit record itself contains ePHI is a classification call here and a log-content finding in web-and-api. A `record_id` is the point of the log; a diagnosis string in the log message is not.

### 4. Retention — §164.316(b)(2)(i) — Required, and what it does *not* cover

**HIPAA sets no audit-log retention period.** §164.316(b)(2)(i) requires that Security Rule **documentation** — policies, procedures, risk analyses, and records of the actions, activities and assessments the rule requires — be retained for six years from the date of its creation or the date when it last was in effect, whichever is later. That clock is on documentation, not on application logs.

- Organizations commonly extend the six-year documentation clock to logs *by policy*. State medical-record statutes and CMS conditions of participation may require longer. So the check is: locate every configured retention value that governs ePHI-access records, and audit it **against the organization's own stated policy**. A mismatch is the finding; "less than six years" is not.
- A finding that a required *document* class is absent or not retained cites the documentation standard §164.316(b)(1) — Standard — and its implementation specification §164.316(b)(2)(i) — Required. A finding about a log retention number carries **no citation** unless it contradicts a policy the organization has stated.

```detector
match: |
  resource "aws_cloudwatch_log_group" "phi_access" {
    name              = "/app/phi-access"
    retention_in_days = 30
  }
nomatch: |
  resource "aws_cloudwatch_log_group" "phi_access" {
    # 2557 days = 7 years, per docs/retention-policy.md section 4 (PHI access records)
    name              = "/app/phi-access"
    retention_in_days = 2557
  }
```

### 5. Integrity — §164.312(c)(1) — Standard; mechanism to authenticate ePHI — §164.312(c)(2) — Addressable

Protect ePHI from improper alteration or destruction. §164.312(c)(2) — a mechanism to corroborate that ePHI has not been altered or destroyed in an unauthorized manner — is **Addressable**, so a missing checksum or signature over stored ePHI is a §164.306(d)(3) assessment finding, not a violation.

- Checkable shapes: a destructive path with no soft-delete or restore window; a bulk update with no before-image; an import that overwrites clinical values with no provenance column. Backup and replica configuration is cloud-and-iac's.

### 6. Person or entity authentication — §164.312(d) — Standard (no implementation specification)

Implement procedures to verify that a person or entity seeking access to ePHI is the one claimed. **The Security Rule names no authentication factor and does not require multi-factor authentication.**

- Missing MFA on an ePHI path is a **security finding with no compliance citation** — category (b) under rule 4. It is genuine and often High on its own security merits; it is not a §164.312(d) violation, and writing it as one is the single most common way this lens used to manufacture exposure. Single-factor password authentication on a remotely reachable ePHI path *is* a legitimate input to the §164.308(a)(1)(ii)(A) risk analysis, and can be reported that way.
- A January 2025 HHS notice of proposed rulemaking would make MFA an express Security Rule requirement. **A proposed rule is not law.** As of 2026-07-27 it remains unfinalized — see the rulemaking-status note in `## Scope` rule 2 for the verified detail and the RIN to re-check — so this stays a security finding with no §164.312(d) citation, and a proposed rule is never cited as a requirement.
- What *is* a §164.312(d) finding: an authentication decision derived from a client-supplied claim rather than verified server-side per request, or a service-to-service path with no verification of the caller at all. Cite the standard, state that the rule prescribes no mechanism, and describe the defect.

### 7. Transmission security — §164.312(e)(1) — Standard; both implementation specifications Addressable

Integrity controls — §164.312(e)(2)(i) — **Addressable** — and Encryption — §164.312(e)(2)(ii) — **Addressable**. Both, not one. TLS version, cipher suites and certificate validation are `tls-and-certificate-validation` and belong to crypto-and-key-management; do not re-report them.

- What stays here: an ePHI-carrying transmission with **no** transport protection at all and no §164.306(d)(3) assessment; an internal service-to-service hop carrying ePHI in cleartext on the assumption that the network is trusted; and content placed into a channel the covered entity cannot protect.
- Clinical content in an email or SMS body is the highest-yield instance, **and the finding is about the endpoint, not about naming a diagnosis to the patient.** Disclosure to the individual is permitted under §164.502(a)(1)(i) and §164.506 — both permissions, neither carrying a mandate-strength label — and OCR's access guidance is explicit that a covered entity must send PHI by unencrypted email where the individual has requested it, having been warned of the risk. So a reminder that names a diagnosis, specialty, medication or program, sent to an address or number **verified as the individual's own and recorded as their requested channel**, is a permitted disclosure — not a finding, and not something to soften into a Low.
  The finding is delivery of that content to an endpoint the system has not established belongs to the individual: an address or phone number captured at intake and never verified, a value editable by a third party (a guarantor, a referring office, an employer portal), a shared family inbox or landline where the entity knows the individual is not the only recipient, a channel the individual asked *not* to be used, or a destination derived from a field that is not the patient's own contact record. Cite §164.502(a) — Mandatory — as an impermissible disclosure to a third party, and check §164.522(b) — Mandatory — confidential-communications requests, which is the provision that makes "send it to this number, not that one" binding.

```detector
match: |
  sg.send(Mail(to_emails=patient.guarantor_email,
               subject="Your visit summary",
               html_content=f"Dx {enc.icd10_code} — next infusion {enc.next_appt}"))
nomatch: |
  if patient.email_verified_at and patient.comm_pref == "email":
      sg.send(Mail(to_emails=patient.email,
                   subject="Your visit summary",
                   html_content=f"Dx {enc.icd10_code} — next infusion {enc.next_appt}"))
```

- A fax-to-email or fax-to-SFTP gateway converts an analog surface into ePHI. The gateway mailbox, the stored artifact, its object key and its retention are all in scope from that point on. Analog fax itself is not (see `## Scope`).
- Push-notification and lock-screen content is `mobile-ui-and-notification-leakage` in mobile-app-security.

### 8. Business-associate perimeter (`baa-coverage-determination`)

The citation set, with each provision's strength stated separately because they come from two different rules:

- **§164.502(e)(1)(i) — Mandatory (Privacy Rule).** A covered entity may disclose PHI to a business associate only if it obtains satisfactory assurance, through a contract or other arrangement, that the associate will appropriately safeguard it. Conditional in form, but it is the operative obligation and OCR cites §164.502(e)(1) directly, so it is Mandatory rather than the unlabelled permission-with-conditions case. Disclosing without the assurance breaches this provision, and the disclosure is also unsupported by any §164.502(a) permission.
- **§164.504(e) — Mandatory (Privacy Rule).** The business-associate-contract implementation specifications: what the contract must actually say — permitted uses and disclosures, safeguards, subcontractor flow-down, reporting, return or destruction at termination, and termination for breach of the contract. This is the provision that makes "a BAA exists" insufficient on its own, and it is the one an auditor should name when the question is contract *scope* rather than contract existence.
- **§164.308(b)(1) — Standard**, with its implementation specification **§164.308(b)(3) Written contract or other arrangement — Required.** The Security Rule counterpart, covering ePHI specifically.
- **§164.314(a)(1) — Standard**, with **§164.314(a)(2) Implementation specifications — Required.** The Security Rule organizational requirements: the security terms the contract must contain. The CFR heads §164.314(a)(2) "Implementation specifications (Required)", so that label is the regulation's own and must never be softened to Mandatory — this is a Security Rule provision, not a Privacy Rule one.

**Code cannot prove a contract exists, and it cannot read one.** What code proves is the destination set. Write the finding on the half you can prove.

- Enumerate every outbound destination on an ePHI path — HTTP clients, SDK initializers, webhook targets, queue and bus endpoints, email/SMS transports, model providers, log and metric shippers, CDN and font hosts referenced from an authenticated page.
- **On a declarative platform the destination set is declared rather than coded, and an HTTP-client sweep finds none of it.** In a Salesforce repository the outbound surface is `namedCredentials/*.namedCredential-meta.xml` and its `<endpoint>`, `remoteSiteSettings/*.remoteSite-meta.xml` and its `<url>`, `cspTrustedSites/*.cspTrustedSite-meta.xml`, and endpoints parked in `customMetadata/*.md-meta.xml` records instead of in code — plus outbound messages, email alerts and Flow HTTP callout actions. Enumerate those files before reading any Apex: a remote site setting is standing authorization for a callout that a grep for `Http.send` cannot attribute to a host, and a trusted site is a browser-side destination on a page that may hold ePHI. The general destination inventory is `third-party-destination-inventory` in privacy-and-data-protection; what stays here is whether ePHI reaches one of them and whether it is on the committed allowlist.

```detector
match: |
  <!-- force-app/main/default/namedCredentials/Population_Analytics.namedCredential-meta.xml -->
  <endpoint>https://ingest.analytics-vendor.example.invalid/v2/members</endpoint>
  <principalType>NamedUser</principalType>
nomatch: |
  <!-- force-app/main/default/namedCredentials/Claims_Clearinghouse.namedCredential-meta.xml -->
  <!-- host is in baa_approved_hosts.yml, last_verified 2026-05-14 -->
  <endpoint>https://edi.clearinghouse.example.invalid/x12</endpoint>
  <principalType>NamedUser</principalType>
```

- Compare against a **repo-committed allowlist** carrying a `last_verified` date per entry. Two findings come out of this and they are different: (i) ePHI reaches a destination not on the allowlist — provable, and the real finding; (ii) the allowlist is absent, stale, or has no owner — a documentation finding under §164.316(b)(1) — Standard — whose implementation specifications at §164.316(b)(2) are Required.
- **Never write a finding that asserts a named vendor's contractual posture.** A vendor may be named as an example of a *capability* ("this class of processor typically offers a HIPAA-eligible configuration; verify the account's is enabled"), never as an assertion about its terms. Contract status changes without notice and this lens has no mechanism to notice; a stale verdict produces a confidently wrong finding.
- **Payment processing is outside business-associate status, and the authority is statutory, not the definition in §160.103.** The exclusion is **SSA §1179 (42 U.S.C. 1320d-8)**, which disapplies HIPAA's administrative-simplification provisions to a financial institution's activities in authorizing, processing, clearing, settling, billing, transferring, reconciling or collecting payments for health care or health-plan premiums. **Do not cite 45 CFR §160.103 for this** — the exclusions in its "business associate" definition are a different and shorter list (a provider receiving treatment disclosures, a plan sponsor, certain government agencies, an organized health care arrangement) and none of them is the payment-processing exclusion. This is a scope boundary, so it carries no mandate-strength label: where §1179 applies, HIPAA does not reach the activity at all.
  Consequence: cardholder name, amount and card data flowing to a processor is **not** a BAA gap. The exclusion is scoped to the payment-processing activity, so it does not cover other services the same vendor may perform. The real finding is scope creep — clinical context stuffed into a charge description, statement descriptor, invoice line item or metadata map — which is an impermissible disclosure under §164.502(a), Mandatory, and rides on nothing §1179 excuses.

```detector
match: |
  stripe.PaymentIntent.create(
      amount=cents, currency="usd",
      description=f"Visit {visit.id} — {visit.icd10_code} / {visit.cpt_code}",
      metadata={"mrn": patient.mrn, "program": "sud_iop"})
nomatch: |
  stripe.PaymentIntent.create(
      amount=cents, currency="usd",
      description=f"Invoice {invoice.number}",
      metadata={"invoice_id": invoice.id})
```

- Telemetry and observability processors are the highest-frequency real gap, and the finding must name the field that reaches the vendor. Presence of the SDK is not the finding; the configured content class is. **And the vendor's name appearing in the tree is not presence of the SDK** — a `sentry` or `gtag(` hit inside `dist/`, `node_modules/` or a committed `*.min.js` names no initializer, no configuration and no caller. Exclude build output and vendored bundles from the sweep before grading anything, per false positive 7.

```detector
match: |
  sentry_sdk.init(dsn=DSN, send_default_pii=True, max_request_body_size="always")
nomatch: |
  sentry_sdk.init(dsn=DSN, send_default_pii=False,
                  before_send=drop_unless_allowlisted,
                  max_request_body_size="never")
```

### 9. Minimum necessary — §164.502(b) — Mandatory, with six exceptions that must be applied first

§164.502(b)(1) requires reasonable efforts to limit PHI to the minimum necessary to accomplish the intended purpose. **§164.502(b)(2) exempts six situations entirely. Check these before writing any minimum-necessary finding:**

1. Disclosures to, or requests by, a health care provider **for treatment**.
2. Uses or disclosures made **to the individual**, as permitted under §164.502(a)(1)(i) or as required by §164.502(a)(2)(i). Note the enumeration: the exception routes through §164.502(a)(2)(i) — Mandatory, the required-disclosure-to-the-individual paragraph, which is what reaches §164.524 and §164.528 — and does not name those sections directly.
3. Uses or disclosures made pursuant to a valid authorization under §164.508.
4. Disclosures to the Secretary of HHS under 45 CFR Part 160 Subpart C.
5. Uses or disclosures **required by law**, as described at §164.512(a).
6. Uses or disclosures required for compliance with the HIPAA Rules themselves.

A clinician-facing chart, encounter or patient-summary view legitimately returns the whole record, and narrowing it is a patient-safety problem rather than a compliance win. Minimum-necessary findings belong on **non-treatment surfaces**: billing and revenue-cycle, scheduling and front desk, analytics and reporting pipelines, vendor integrations, data exports, and broad internal admin tooling.

```detector
match: |
  @router.get("/analytics/cohort-export")
  def cohort_export():
      return [PatientSerializer(p).data for p in Patient.objects.all()]
nomatch: |
  @router.get("/analytics/cohort-export")
  def cohort_export():
      return Patient.objects.values("age_band", "zip3", "encounter_count")
```

- §164.514(d) — Mandatory — leaves the *implementation* to the entity's own role-based policies, so a finding must name the surface, the role, and the field that exceeds the purpose. "Returns more fields than needed" with no named surface is not a finding.
- On a Salesforce org the surface and the role arrive as one artifact, and it is committed: an `objectPermissions` block in `permissionsets/*.permissionset-meta.xml` or `profiles/*.profile-meta.xml` assigned to a non-treatment group. `<viewAllRecords>` on the object holding ePHI defeats sharing for every record; `<viewAllFields>` defeats field-level security for every field on it. A billing, scheduling, reporting or "team" permission set carrying either therefore names the surface, the role and the fields all at once, which makes it the strongest minimum-necessary artifact a declarative org produces — cite the file and the `<object>`. `<modifyAllRecords>` is the write-side counterpart and is an integrity aggravator under §164.312(c)(1), not a minimum-necessary finding. Whether the *code* under that grant re-checks CRUD and FLS is `apex-crud-fls-enforcement` in salesforce-platform.
- Field-level authorization on a non-treatment surface is `authz-property-level` in web-and-api. This lens supplies the purpose analysis and the uplift.

### 10. De-identification — §164.514 (`phi-deidentification-standard`)

Safe Harbor (§164.514(b)(2) — a condition of a claim, not an obligation) requires removal of all eighteen identifier categories **and** no actual knowledge that the residual information could identify the individual (§164.514(b)(2)(ii)). Partial masking is the standard failure: names and SSN removed while full date of birth, five-digit ZIP and admission date pass through, which is re-identifiable.

```detector
match: |
  def deidentify(row):
      row["name"] = "REDACTED"
      row["ssn"] = None
      return row
nomatch: |
  def deidentify(row):
      row.pop("name"); row.pop("ssn")
      row["birth_year"] = row.pop("dob").year
      row["zip3"] = restricted_zip3_to_000(row.pop("zip5"))
      row["admit_year"] = row.pop("admit_date").year
      row["age"] = "90+" if row["age"] > 89 else row["age"]
      return row
```

- Element-by-element expectations: all elements of dates except year suppressed for dates directly related to the individual; ages over 89 aggregated into a single 90-or-above category; geographic subdivision no finer than the initial three ZIP digits, with the restricted low-population three-digit prefixes changed to `000`.
- **Category (R) is a catch-all, and it is the one auditors forget: "any other unique identifying number, characteristic, or code."** So an opaque surrogate primary key, a research ID, a device or session token, or a tokenized member number **is** an identifier for Safe Harbor purposes and must be removed or brought inside §164.514(c) before the set can be called de-identified. The only reason a surrogate key survives in a de-identified set is §164.514(c); nothing else exempts it.
- **§164.514(c) is a permission with conditions, not a requirement** — so it is never cited as "violated". It permits assigning a code that lets the entity re-identify the data, **provided** the code is not derived from or related to information about the individual, is not otherwise capable of being translated to identify them, and the entity does not use or disclose the code or the mechanism for other purposes. A hash of the MRN fails the derivation condition outright. When the conditions fail, the code remains an identifier under (b)(2)(i)(R), so the set was never de-identified under §164.514(b) — meaning §164.502(d)(2) does not apply and the data is still PHI, with every PHI obligation attached. **That** is the finding, and its operative citation is §164.502(a) — Mandatory.
- A crosswalk table reachable by the role that reads the "de-identified" set fails the same way: the mechanism is effectively disclosed to the recipient, so the set is not de-identified in that recipient's hands.

```detector
match: |
  COPY (SELECT research_id, mrn FROM deid_crosswalk)
    TO '/exports/deid/crosswalk.csv' WITH CSV HEADER;
nomatch: |
  REVOKE ALL ON deid_crosswalk FROM research_role;
```

- Expert determination under §164.514(b)(1) — the other condition-of-a-claim route — is an alternative to Safe Harbor and cannot be assessed from code. If the repo claims it, record the claim and the verification step; do not grade it.
- Hash-as-pseudonym reversibility in the general case is `pseudonymization-and-reidentification-risk` in privacy-and-data-protection.

### 11. Lower environments (`phi-in-lower-environments`)

The finding requires **provenance evidence, not resemblance**. Synthetic data that looks like patient data is not ePHI.

```detector
match: |
  pg_restore --clean -d app_staging /backups/prod/patients-latest.dump
nomatch: |
  python manage.py loaddata fixtures/synthea_patients.json
```

- Repo-visible provenance evidence: a restore or sync script pointed at a production database, alias or snapshot; a dump command run against the production credential; an anonymization step that masks names while leaving date of birth, ZIP and admission date intact; a crosswalk shipped beside the "de-identified" set; a notebook reading a production connection string.
- If provenance cannot be resolved from the repo, report it as an assumption at Info with the verification step. Do **not** drop it silently, and do not upgrade it on resemblance alone.

### 12. Breach-notification exposure — §164.400-414 (`breach-notification-exposure`)

Two things in the source of this lens were dangerously wrong and are corrected here.

**The encryption safe harbor is narrow and conditional.** Notification obligations attach to *unsecured* PHI. PHI is "secured" only when it has been rendered unusable, unreadable or indecipherable to unauthorized persons through a technology or methodology specified in the HHS guidance issued under HITECH §13402(h)(2) — which names NIST SP 800-111 for data at rest and FIPS 140-validated encryption consistent with NIST SP 800-52/800-77 for data in transit — **and** the decryption key was not also compromised. It therefore almost never applies to the common breach: stolen credentials, session hijacking, SQL injection, or a malicious insider, where the application decrypts for the attacker. "We are encrypted, so there is nothing to report" is not a conclusion this lens supports.

**An impermissible acquisition is presumed to be a breach.** Under §164.402, acquisition, access, use or disclosure of PHI not permitted by the Privacy Rule is presumed a breach unless the entity demonstrates a low probability that the PHI has been compromised, based on a risk assessment of at least four factors: the nature and extent of the PHI involved including the identifiers and the likelihood of re-identification; the unauthorized person who used it or received it; whether the PHI was actually acquired or viewed; and the extent to which the risk has been mitigated. §164.402 also carries three exceptions — good-faith unintentional acquisition by a workforce member acting within scope, inadvertent disclosure between authorized persons at the same entity, and a good-faith belief that the recipient could not reasonably have retained the information. §164.402 is a **definition** and its exceptions are exceptions to that definition: neither carries a mandate-strength label and neither can be violated — together they decide whether the notification obligations attach at all. The obligations are §164.404 — Mandatory — §164.406 — Mandatory — §164.408 — Mandatory — and §164.410 — Mandatory. The Breach Notification Rule has no Required/Addressable structure, so a §164.400-414 finding never carries one of those labels.

- The code-visible finding is **scoping capability**: if the system cannot answer "which records did this identity read, and when", the entity cannot perform the four-factor assessment and cannot bound a notification population. That is a real, high-value finding and it cites §164.312(b) — Standard — plus §164.404 — Mandatory, notification without unreasonable delay and no later than 60 days after discovery. "We do not know what was accessed" is the worst outcome in this rule.
- Absence of encryption is **never itself** a §164.400-414 violation. Encryption is an exemption from notification, not a requirement of it.

### 13. Tracking technologies on ePHI surfaces (`phi-tracking-technologies`)

A marketing pixel, tag-manager container or analytics snippet is **not per se** a HIPAA violation. The theory that made it automatically so — that an IP address plus a visit to an unauthenticated public page about a condition is PHI — was vacated in *American Hospital Association v. Becerra* (N.D. Tex., 20 June 2024). Post-vacatur, a tracker on a public marketing or condition-information page is not a HIPAA finding.

```detector
match: |
  // app/(portal)/layout.tsx — session required by middleware
  <Script src="https://www.googletagmanager.com/gtm.js?id=GTM-XXXX" strategy="afterInteractive" />
nomatch: |
  // app/(marketing)/layout.tsx — public, unauthenticated, no condition context
  <Script src="https://www.googletagmanager.com/gtm.js?id=GTM-XXXX" strategy="afterInteractive" />
```

- **Establish that the hit is first-party before reading the route at all.** The tracker signals match plain vendor strings, and a committed build artifact contains every one of them: a minified bundle under `dist/`, `build/`, `out/`, `.next/`, `public/vendor/`, `node_modules/` or `vendor/`, or any `*.min.js` / `*.bundle.js` / `*.chunk.js`, mentions `sentry`, `gtag(`, `dataLayer` and a tag host because that is the library's own code, not a decision this repository made. Measured on a real audit: `sentry` matched eleven files and `gtag(` matched five, every one of them a vendor bundle, and first-party source contained no telemetry SDK at all — a 100% false-positive rate on two signals. So run the sweep with the build output excluded (`--glob '!**/dist/**' --glob '!**/build/**' --glob '!**/out/**' --glob '!**/.next/**' --glob '!**/public/vendor/**' --glob '!**/node_modules/**' --glob '!vendor/**' --glob '!**/*.min.js' --glob '!**/*.bundle.js' --glob '!**/*.chunk.js'`), and grade only a hit you can tie to first-party source: an import of the SDK, an initializer, a `<script>` the application's own template or component emits, or a call site. If the only hits are in build output, the finding is that there is no finding — say so, name the paths you excluded, and check the dependency manifest for the SDK as the second opinion. This is the mirror of the rule in `## Proof recipes` R5 about rendered output, and it is **not** the rejected over-broad clearance in `### Rejected candidates`: a first-party tracker on an authenticated page is still Critical, and a bundle whose build input is in the repository still routes the finding to that input.

```detector
match: |
  // src/portal/chart-panel.tsx — first-party source, session required by middleware
  window.gtag("event", "chart_view", { patient_ref: encounter.mrn });
nomatch: |
  // dist/assets/vendor.9f3c1a2b.min.js — committed build output, no first-party caller
  function q(){window.dataLayer.push(arguments)}window.gtag=q;
```

- The discriminator is the **route and the payload**, not the string. It is a finding when the page is behind authentication, is part of a scheduling, intake, symptom-checker or eligibility flow, or transmits an identifier or condition context — URL path, query string, form field, or a `dataLayer` push. Then it is a §164.502(a) impermissible disclosure and a `baa-coverage-determination` finding, and often Critical.
- Where HIPAA does not reach, other law may: FTC Act §5, the amended Health Breach Notification Rule, and state health-privacy statutes. Those are `consumer-health-data-outside-hipaa` in privacy-and-data-protection — cross-reference, do not re-cite as HIPAA.
- Consent gating of trackers is `consent-gating-of-trackers` in privacy-and-data-protection.

### 14. Individual rights that manifest in code

- **§164.524 Right of access — Mandatory.** The right is a right of access **on request**: to inspect and obtain a copy of PHI in a designated record set, and where the PHI is maintained electronically and an electronic copy is requested, in the electronic form and format requested **if readily producible**, or in a readable electronic form the entity and individual agree on.
  **A staff-mediated electronic copy complies.** There is no §164.524 requirement for a patient-facing portal, a self-service download, or an API. The finding is the absence of **any** mechanism capable of fulfilling a request within the §164.524(b)(2) timeline — a record class held in a store nobody can export from, a designated record set nobody can enumerate, a format that is not readily producible by any path including a staff one, or no owner and no runbook. Do **not** file "no patient-facing export path" as a §164.524 violation.
  Self-service and programmatic patient access is a **different regime** with different obligations: the Cures Act information-blocking rules at 45 CFR Part 171 and the certification criteria that sit beside them. If the concern is that patients must ask staff and wait, that is where it belongs — cite Part 171 or say "outside this lens", and do not borrow §164.524's weight for it.
- **§164.526 Amendment — Mandatory.** A path to *act on* a request for amendment, and the ability to record an accepted amendment, or a statement of disagreement and rebuttal, alongside the record rather than overwriting it. As with access, the request may arrive by any channel; the finding is a record class that structurally cannot carry an amendment or a disagreement, not the absence of a patient-facing amendment form.
- **§164.528 Accounting of disclosures — Mandatory.** Note the scope carefully: the accounting covers **disclosures**, and §164.528(a)(1)(i) excludes disclosures to carry out treatment, payment and health care operations. A patient-facing "who viewed my chart" report is **not** required by §164.528, and neither is an accounting of internal *uses*. Do not file the absence of either as a violation.

### 15. 42 CFR Part 2 overlay — substance-use-disorder records

If any part of the system holds records of a federally assisted substance-use-disorder program, 42 CFR Part 2 applies **on top of** HIPAA and is stricter. Part 2 has no addressable-specification structure; its requirements are mandatory where the program is a part 2 program. The February 2024 final rule reached its compliance date on 16 February 2026, so this is live regulation for any behavioral-health codebase.

- The code-visible duties: Part 2 records must be a distinguishable data class, so there has to be something in the schema that marks them. Written consent meeting §2.31 must be captured and its scope recorded — the 2024 rule permits a single consent covering all future uses and disclosures for treatment, payment and health care operations, which changes the shape of the consent record. A disclosure made with consent must be accompanied by the notice against redisclosure required by §2.32, so the notice has to travel with the exported artifact. Part 2 records may not be used in legal or administrative proceedings without consent or a qualifying court order.

```detector
match: |
  @router.get("/records/{record_id}/export")
  def export_record(record_id):
      rec = Record.objects.get(pk=record_id)
      return {"pdf": render_pdf(rec)}
nomatch: |
  @router.get("/records/{record_id}/export")
  def export_record(record_id):
      rec = Record.objects.get(pk=record_id)
      require_part2_consent(rec, purpose="tpo")
      return {"pdf": render_pdf(rec, notice=PART2_REDISCLOSURE_NOTICE)}
```

- Verify the current text of Part 2 before citing a subsection; this regime changed recently and the numbering of the consent and notice provisions is exactly the kind of detail worth re-reading.

## Severity calibration

Severity is the *security and breach* impact of the defect. Mandate strength is a separate axis and belongs in the finding's citation, not in its severity — but it constrains how a finding may be *worded*, and that is what this table encodes.

**The rule that does the most work:** a finding on an **Addressable** implementation specification is written as a risk-analysis and documentation gap and caps at **Medium** absent a concrete exposure path. With a concrete exposure path it scores on the exposure, and the citation shifts to §164.308(a)(1)(ii)(A) — Required — and §164.316(b)(1) — Standard — whose implementation specifications at §164.316(b)(2) are Required. Those are the provisions the gap actually offends.

`severity_floor: low` is presentational. It orders this lens's findings in the report. It **never** suppresses a finding, and no item below may be dropped because it sits at Low or Info.

| Finding | Severity | Citation and mandate strength |
|---|---|---|
| ePHI reaching a destination outside the recorded business-associate perimeter, in plaintext, provable from the destination set | Critical | §164.502(e)(1)(i), §164.504(e) — Mandatory (Privacy Rule); §164.308(b)(3) — Required |
| Tracker or pixel on an authenticated ePHI surface, or one transmitting an identifier or condition context, established in **first-party source or the rendered output of a first-party page** | Critical | §164.502(a) impermissible disclosure — Mandatory; plus `baa-coverage-determination`. A hit that exists only in committed build output or a vendored bundle establishes no caller and does not grade here — see false positive 7 |
| Clinical content in an outbound message body (email, SMS, push) delivered to an endpoint not verified as the individual's own, or to a third party | High | §164.502(a) — Mandatory; check §164.522(b) — Mandatory. Disclosure to the individual on a verified, requested channel is **permitted** and is not a finding. §164.312(e)(2)(ii) is Addressable and is never the citation here |
| Acting human unrecoverable from every record of ePHI access | High | §164.312(a)(2)(i) — Required |
| No record anywhere of ePHI reads, so a breach population cannot be bounded | High | §164.312(b) — Standard; §164.404 — Mandatory |
| Break-glass path indistinguishable in the audit record from ordinary access | Medium–High | §164.312(b) — Standard — is the lead citation, because the defect is an audit-controls defect; §164.312(a)(2)(ii) — Required — is secondary and is satisfied by the path existing and being controlled |
| Production-derived ePHI in a lower environment, with repo-visible provenance | High | §164.502(a) — Mandatory. **Do not cite §164.308(a)(3) for this finding** — not because its specifications are Addressable, but because the specific control at issue (workforce authorization, clearance, termination) sits inside one of those Addressable specifications, and repo-visible provenance evidences an impermissible use or disclosure rather than a failure of the workforce-security standard. §164.308(a)(3) — Standard — is obligatory under §164.306(c) and stays separately citable where the evidence does establish a failure of the standard. Without provenance evidence this is Info, not High |
| Partial de-identification passing DOB, ZIP5 or admission date | High | §164.514(b)(2) — a condition of a claim, carrying no mandate-strength label. Failing it means the data is still PHI, so the operative citation is §164.502(a) — Mandatory |
| Crosswalk reachable by the role that reads the "de-identified" set, or a code derived from the MRN | High | §164.514(c) — a **permission with conditions**, never cited as violated. Failing its conditions leaves the code an identifier under §164.514(b)(2)(i)(R), so the set is not de-identified and §164.502(a) — Mandatory — governs |
| Minimum-necessary excess on a named non-treatment surface | Medium standalone, High when systematic | §164.502(b)(1) — Mandatory, after clearing all six §164.502(b)(2) exceptions |
| Self-managed ePHI store with no encryption in use, or encryption verifiably disabled | Medium | §164.312(a)(2)(iv) — **Addressable**. Written as a §164.306(d)(3) — General rule — assessment gap, citing §164.308(a)(1)(ii)(A) — Required — and §164.316(b)(1) — Standard |
| No inactivity termination at any layer on an ePHI session | Medium | §164.312(a)(2)(iii) — **Addressable**. Same framing as above |
| No integrity mechanism over stored ePHI where tampering is in the threat model | Low–Medium | §164.312(c)(2) — **Addressable** |
| Missing MFA on an ePHI path | High as a security finding | **No compliance citation.** Category (b) under rule 4. May be reported as a §164.308(a)(1)(ii)(A) — Required — risk-analysis input |
| Configured ePHI log retention shorter than the organization's own stated policy | Low–Medium | **No citation** unless a required document class is missing, which cites §164.316(b)(2)(i) — Required |
| Required Security Rule documentation absent or not retained six years | Medium | §164.316(b)(2)(i) — Required |
| No mechanism by which a §164.524 access request could be fulfilled at all, by any path including a staff-mediated one | Medium | §164.524 — Mandatory. **Absence of a patient-facing or self-service path is not this finding**; that expectation lives in the Cures Act information-blocking rules at 45 CFR Part 171 — another regime, never given a HIPAA label — outside this lens |
| Part 2 record exported with no consent check or no redisclosure notice | High | 42 CFR §2.31 — Mandatory — and §2.32 — Mandatory, where the program is a part 2 program |
| Tracker on a public, unauthenticated marketing page with no identifier transmitted | Info | **No HIPAA citation** — the contrary theory was vacated in *AHA v. Becerra* |
| Tracker, telemetry or replay string present **only** in committed build output or a vendored bundle, with no first-party import, initializer or call site | Info, and normally not reported at all | **No citation, and no finding at any severity** — the string is the vendor library's own code, not a decision this codebase made. State the paths excluded and the dependency-manifest check that confirms it. Where the bundle's build input is in the repository, the finding belongs against that input |

Two anti-patterns, stated as rules:

- **Never uplift on the presence of a HIPAA framework identifier.** `phi-severity-uplift` applies when the data another lens's finding exposes is *classified as ePHI by this lens*. A repo that mentions HIPAA is not thereby a HIPAA finding.
- **Never downgrade a security finding because a specification is addressable.** Addressable changes the citation and the wording, not the security severity. An unencrypted ePHI store reachable from a compromised read-replica credential is still as bad as it is; what changes is that you may not call it a §164.312 violation.

## Known false positives

Each entry names a pattern a competent reviewer would flag and states why it is not the finding it looks like. None of these is a licence to drop a finding: every one names the narrower finding that *does* survive.

1. **A read path — repository method, SOQL query, FHIR read endpoint — with no `audit_log.insert(...)`, reported as a §164.312(b) Audit Controls violation.** The rule requires "hardware, software, and/or procedural mechanisms that record and examine activity"; it does not require the mechanism to live in application code. It is frequently satisfied a layer down: platform event monitoring or field audit trails, an EHR vendor's own access log, `pgaudit` or `log_statement`, SQL Server Audit, cloud data-plane events on an ePHI bucket, or a gateway access log joined to the IdP. **Name the artifact, which means having a string to check.** On Salesforce — where none of this appears in Apex, so a source-only sweep is guaranteed to see an absence — the strings are `EventLogFile`, `ApiEvent` and `ReportEvent` for Shield Event Monitoring, `FieldHistoryArchive` and `<historyRetentionPolicy>` for Field Audit Trail, Setup Audit Trail, and `<enableHistory>` / `<trackHistory>` in the object and field metadata. Two of those halves behave differently: the `<enableHistory>` / `<trackHistory>` / `<historyRetentionPolicy>` half is committed metadata and can be settled from the checkout, while Event Monitoring is a licensed add-on whose purchase and enablement are not repository facts. And history tracking records *changes*, not reads, so finding it does not answer the §164.312(b) read question or bound a breach population. The defensible finding is narrower and must be stated that way — "reads are logged at the database layer but the log records only the pooled service account, so the acting user is unrecoverable." A flat "no audit log" claim is not verifiable from one service's source.
   **This entry is an assumption, not a clearance.** A layer-down mechanism that you have not seen is a hypothesis, and this rule must never be used to close a finding on the possibility that one exists. If you cannot obtain the configuration — the audit extension's settings, the platform's monitoring state, the gateway log's fields — record it as an assumption at Info naming the exact artifact you would need, and leave the finding open. The direction of error matters: over-reporting an audit gap costs a reviewer ten minutes, and silently clearing a real one means nobody can bound a breach.

2. **A clinician-facing chart, encounter or patient-summary endpoint returning the full record via `SELECT *` or an unfiltered serializer, reported as a minimum-necessary violation.** §164.502(b)(2)(i) exempts disclosures to, and requests by, a health care provider for treatment from the minimum necessary standard entirely — a treating clinician is supposed to see the whole chart, and narrowing it is a patient-safety problem, not a compliance win. The same exemption covers disclosures to the individual (a portal returning that patient's own record), uses under a valid authorization, and disclosures required by law. Minimum-necessary findings belong on non-treatment surfaces: billing and revenue-cycle, scheduling and front-desk views, analytics pipelines, vendor integrations, and broad admin tools.

3. **A marketing pixel, tag-manager container or analytics snippet in the root layout, reported as Critical under the OCR tracking-technologies bulletin.** The theory that made this automatically Critical — IP address plus a visit to an unauthenticated public page about a condition equals PHI — was vacated in *American Hospital Association v. Becerra* (N.D. Tex., 20 June 2024). Post-vacatur, a tracker on a public marketing or condition-information page is not per se a HIPAA violation. It stays Critical when the page is behind authentication, is part of a scheduling, intake or symptom-checker flow, or transmits identifiers or condition context (URL path, query string, form field, `dataLayer` push). Verify what the tracker sends and whether the route requires a session — and note that FTC Act §5, the amended Health Breach Notification Rule, and state health-privacy statutes can still apply where HIPAA does not.

4. **`logger.info(request.body)`, `console.error(err, payload)`, or a telemetry integration capturing request bodies, reported as an active breach.** The call site is half the picture; the sink and its scrubber are the other half. Structured-logging processors, a `before_send`/`beforeBreadcrumb` denylist, `send_default_pii: false`, vendor-side sensitive-data scanning rules, or redaction middleware upstream can all mean nothing sensitive leaves the process. Trace the record from call site to transport and read the scrubber config. A genuine Critical is provable: name a field that reaches the vendor because it is absent from the denylist. Where scrubbing exists but is denylist-shaped, the defensible finding is lower and different — "any newly added ePHI column leaks until someone remembers to add it" — a design finding with a test, not a breach.

5. **A patient or record identifier in a URL path, e.g. `GET /patients/8f21c0e4-.../notes`, reported as "PHI in URLs: Critical."** Be precise about *why* this is not Critical, because the obvious argument is wrong: a surrogate key **is** an identifier — §164.514(b)(2)(i)(R) catches "any other unique identifying number, characteristic, or code" — and in a live production system the whole record is PHI regardless, so the Safe Harbor list is the wrong instrument here. It governs whether a *data set has been de-identified*, not how to score a URL.
   The reason the finding is not Critical is severity, not classification: an opaque, non-derived surrogate key reveals no condition on its own, is not enumerable, and needs a channel that carries it somewhere before anything is disclosed. If a bare surrogate key in a path were Critical, every healthcare REST API would be. The Critical case is a URL whose *content* directly identifies or reveals condition — `?patient_name=`, `?ssn=`, `?dob=`, `?mrn=`, `?dx=F33.1`, or a path segment naming a condition, program or specialty — or an identifier or token forwarded off-origin via `Referer` to a destination outside the business-associate perimeter, or embedded in a tracker's page-URL parameter, which is a §164.502(a) disclosure. Distinguish the two before scoring, and do not clear the surrogate-key case in a *de-identified export*, where (i)(R) applies with full force and §164.514(c) is the only thing that saves it. The URL-content finding itself is `application-log-and-url-content` in web-and-api; this lens supplies the classification and the uplift.

6. **Seed files, fixtures or factories containing realistic patient records** — `Jane Doe, DOB 1980-01-01, MRN 100234, dx F33.1` — reported as production ePHI in dev. Synthetic data that looks like patient data is not PHI: synthetic-patient generator output, faker demographics and hand-written fixtures are the correct way to test a clinical system. The finding requires provenance evidence, not resemblance: a restore script pointed at a production snapshot, a dump taken against the production credential, an anonymization step that masks names while leaving DOB + ZIP + admission date intact (still re-identifiable under §164.514(b)(2)), or a crosswalk table shipped beside the "de-identified" set. State the provenance evidence, or report it as an assumption at Info with the verification step — never file it at High on resemblance, and never drop it silently.

7. **A tracker, telemetry or session-replay string matched inside committed build output — `sentry` in a bundle under `dist/`, `gtag(` in a `*.min.js`, a tag host in `node_modules/` — reported as a telemetry or tracking finding.** The vendor's own library contains the vendor's own strings, and a committed bundle is a build artifact rather than a decision this codebase made. This is the highest false-positive rate this lens has measured: on a real audit `sentry` matched eleven files and `gtag(` matched five, **all sixteen of them minified bundles under `dist/` or `node_modules/`**, and first-party source contained no telemetry SDK at all. The narrower finding that survives is reached by two cheap checks: re-run the sweep with build output excluded (`--glob '!**/dist/**' --glob '!**/build/**' --glob '!**/out/**' --glob '!**/.next/**' --glob '!**/public/vendor/**' --glob '!**/node_modules/**' --glob '!vendor/**' --glob '!**/*.min.js' --glob '!**/*.bundle.js' --glob '!**/*.chunk.js'`) and read the dependency manifest for the SDK. Grade only what those establish — an import, an initializer, a `<script>` the application's own component or template emits, or a call site — and where the bundle's build input is in the repository, file against that input rather than against the artifact. **Two things this entry does not license.** It is not the over-broad clearance rejected below: a first-party tracker on an authenticated page or in an intake flow is still Critical. And it is not permission to skip the rendered artifact — `## Proof recipes` R5 requires the tracker check to run over built page markup, which is exactly where a first-party tag *does* appear, so "it was only in the build output" is established by a path plus a manifest and never by assuming that everything under a build directory is third-party.

### Rejected candidates

Candidates considered for the list above and deliberately excluded. Nothing here should be quietly re-added; each would have suppressed a real finding or moved a finding into a section that cannot enforce it.

- **"No column- or field-level encryption of ePHI, therefore §164.312(a)(2)(iv)."** Not a false positive — a duplicate. Storage-encryption defaults are `encryption-at-rest-configuration` in cloud-and-iac, which this lens defers. The HIPAA-side escalations survive in Checklist item 2 (encryption verifiably disabled, self-managed storage with none, a threat model that includes the database operator).
- **"A long session or eight-hour token, excused because an equivalent control probably exists at the badge, OS or VDI layer."** Rejected as written: the excuse is unverifiable from a repository and would let a genuine no-timeout finding be dismissed. Only the checkable half survives, as a Checklist item — no inactivity termination at *any* layer — with the addressable-specification point carried in `## Severity calibration` instead.
- **"Encryption at rest is addressable, therefore an unencrypted ePHI column is not a finding."** Rejected: this inverts rule 2. Addressable means assess, implement if reasonable and appropriate, and otherwise document why not and adopt an equivalent measure — so the *missing documented decision* is the finding. The correction is to the citation and the wording, never a suppression.
- **"Missing MFA is not a HIPAA requirement, therefore drop it."** Rejected: rule 4 demotes it to a security finding with no citation. It does not delete it. A single-factor remotely reachable ePHI path is frequently the most consequential item in the report.
- **"An analytics or tag-manager script anywhere in a healthcare repository is never a finding, post-*Becerra*."** Rejected as over-broad: the vacatur reached the unauthenticated-public-page theory only. A tracker inside an authenticated portal, an intake flow, or one receiving an identifier remains a §164.502(a) disclosure. False-positive entry 3 carries the narrow version.

## Proof recipes

Shared harness components are referenced by name and not restated here: the **registry-driven enumerator**, the **socket-layer destination recorder**, the **canary fixture set**, the **capturing log handler**, and the **clock control** (`freezegun` / `jest.setSystemTime`). Their implementations live in `lenses/_harness.md`.

**Tier rule.** T1 is a proof the repository's own test command executes. T2 requires the auditor to stand up infrastructure the repo does not already stand up, and the user is asked every time. A recipe that cannot run reports `UNPROVEN` with the blocking reason, capped at Medium — never as a silent pass.

### R1 — Registry-driven ePHI canary sweep of every output sink (T1)

The highest-value proof this lens has, because it converts a denylist into an enforced allowlist. Populate every field in the ePHI inventory with an unmistakable canary (`MRN-CANARY-8675309`, `DX-CANARY-F33-1`), attach the **capturing log handler** to the *real* logger so formatters and serializers run, stub each vendor's **transport** rather than its API, exercise the happy path *and* a forced exception inside the handler, then grep every sink for the canary and its derived encodings: base64, base64url, hex, URL-encoded, JSON-escaped, gzip+base64, reversed.

**The regression multiplier:** parametrize the sweep over the model's own field registry — the ORM model's declared fields, the serializer's field map, the live schema — using the **registry-driven enumerator**, so a newly added ePHI column fails the test until it is registered with the scrubber. Assert the discovered field count against a checked-in number, so an enumerator that silently returns zero rows cannot pass.

**Fails on:** whichever field the denylist forgot; a formatter that stringifies the whole model; an exception path that logs the request body. **Passes on:** an allowlist-based scrubber.

### R2 — Destination-set assertion at the socket layer for the BAA perimeter (T1)

Install the guard *first* so an unexpected connection fails loudly instead of reaching the internet — `pytest-socket` with `socket_allow_hosts`, a monkeypatched `socket.getaddrinfo`/`create_connection`, or `nock.disableNetConnect()`. Exercise every ePHI code path with the **socket-layer destination recorder** installed, then assert the recorded destination set is a subset of the committed allowlist (`baa_approved_hosts.yml`). Allowlist entries are anchored patterns, never prefix matches, with a self-test proving a longer hostname sharing a prefix is not matched.

**Where the destinations are declared rather than coded there is no socket to instrument**, and a declarative platform is the common case in a covered entity: a Salesforce org's outbound set lives in `namedCredentials/`, `remoteSiteSettings/`, `cspTrustedSites/` and `customMetadata/` records, and nothing in the repository executes. Run the comparison anyway — parse the `<endpoint>` and `<url>` values out of that metadata and assert the resulting host set is a subset of the committed allowlist, which is a T1 test over committed files — and report the socket half as `UNPROVEN` with that reason rather than as a pass.

**This proves where data goes. It cannot prove a BAA exists** — see `## Scope`. The allowlist's `last_verified` date is a human claim, and the only thing the test can assert about it is staleness. Report the contract half as an assumption, always.

### R3 — Two-subject minimum-necessary and cross-patient sweep (T1)

Build two subjects with distinct records once, seed each record with a distinctive marker, then request subject A's identifier as subject B and assert **both** that the status is 403 or 404 **and** that the marker is absent from the body, the headers, and any generated file or export. Add the client-supplied-identity variant (a body or query parameter naming another patient or another tenant) and the missing-scope variant that catches "no tenant" resolving to "all tenants". Enumerate the cases from the route table with the **registry-driven enumerator** rather than hand-writing them, with a committed exemption allowlist.

Cross-patient access control is `authz-object-level` in web-and-api and the finding belongs there; run this recipe here for the **minimum-necessary** half — a non-treatment surface returning fields beyond its purpose — and for the ePHI uplift on the access-control finding. **Treatment-context surfaces are excluded from the minimum-necessary assertions by design**, per §164.502(b)(2)(i); that exclusion is a permanent coverage gap, not an oversight, and must be named in the report's coverage block.

### R4 — Clock-controlled retention, deletion and de-identification (T1, with one honest caveat)

Seed canaries into every store the **registry-driven enumerator** discovers, call the deletion or purge API, invoke the purge job **explicitly** rather than waiting on a schedule, then assert zero residue per store, that each processor stub recorded a delete or suppress call, and that the registry is exhaustive — fail if any table matching the ePHI classifier is absent from it.

Retention: two rows per rule, one just inside and one just outside the window; advance the **clock control**; assert the outside row is gone **and the inside row is untouched**. The second half is what stops an over-broad purge from passing.

De-identification: populate all eighteen identifier categories with traceable canaries and assert element-by-element — ZIP truncated to three digits and a restricted prefix mapped to `000`, all date elements except year suppressed, ages over 89 collapsed to a single `90+` category — then assert the de-identified role has no grant on the crosswalk table.

Audit-record immutability: attempt an `UPDATE` and a `DELETE` against the audit table **as the application role** and assert both are refused.

**Caveat, stated rather than hidden:** the grant-based and append-only assertions require a real engine with the roles the repository's own migrations provision. On SQLite, or in a repo whose migrations do not create the application role, that half is `UNPROVEN` and is reported as such.

### R5 — Detector-plus-fixture pairs for the static checks (T1)

Every Checklist detector in this lens ships as an executed pair: `detect(fixtures/vulnerable/X) == 1` **and** `detect(fixtures/clean/X) == 0`. A checker that only passes on good input proves nothing about detection. Run these over the *rendered* artifact where one exists — the built page markup for the tracker check, the rendered infrastructure plan for a retention value — never over the template.

**The tracker check has a trap at each end, and the pair only holds if both are closed.** Running over the template misses a tag the build injects. Running over an *arbitrary* build directory manufactures the opposite error, because a committed vendor bundle contains every tracker string there is: what R5 asks for is the rendered markup of a first-party page — the HTML the application serves — and not `dist/**/*.min.js`, `node_modules/`, `vendor/` or any third-party chunk that happens to sit in the same tree. So the input to this check is named explicitly in the report: which artifact was rendered, and which paths were excluded. False positive 7 is the failure this closes, and the clean half of the pair (`fixtures/clean/telemetry_vendor_bundle/`) is a bundle that must produce zero findings.

### Not provable here, and reported as such every run

Name these in the report's coverage block rather than letting silence imply safety: BAA existence and contractual scope; whether a retention period is *appropriate*; expert-determination de-identification under §164.514(b)(1) and re-identification risk in free-text notes; provenance of fixture data beyond what the repository shows; clinical necessity on a treatment surface; and every human or physical control — training, sanction policy, incident-response readiness, facility and device safeguards.

## Report format override

HIPAA mode replaces the standard report body. Candidate findings still conform to `lenses/_schema.md` — this override governs how they are grouped and worded, not what fields they carry.

Two hard requirements on wording, both enforcing the four rules in `## Scope`:

- **Every citation states the provision and its mandate strength**, as `§164.312(a)(2)(i) — Required` or `§164.312(a)(2)(iv) — Addressable`. A finding with a compliance citation and no mandate strength does not ship.
- **A finding with no correct provision goes in the security section with no citation.** It is not moved into a safeguard section to make the compliance report look complete.

Emit these headings, at `##` level, in this order. Skip a section only where the rule below says to skip it; an empty section is more honest than a missing one.

1. `## Summary` — scope of ePHI in the system: which stores, which surfaces, which flows leave the perimeter, and the overall posture. State explicitly which surfaces are out of scope as non-electronic. One paragraph, no severity inflation.
2. `## ePHI inventory` — the classification result the rest of the report is parametrized over: field, store, and whether it was reached by a detector or asserted by a recipe. Where the model is declarative the store is the metadata file, so name it — `objects/<Object>/fields/<Field>.field-meta.xml` — and say which standard objects are carrying ePHI by convention rather than by name.
3. `## Technical safeguard findings (§164.312)` — grouped by subsection: (a)(1) access control, (b) audit controls, (c)(1) integrity, (d) authentication, (e)(1) transmission security. Every finding carries its provision **and** its mandate strength. Addressable specifications are written as risk-analysis and documentation gaps, never as violations.
4. `## Risk analysis and documentation gaps` — every addressable specification with no documented §164.306(d)(3) decision, cited to §164.308(a)(1)(ii)(A) — Required — and the documentation standard §164.316(b)(1) — Standard — plus §164.316(b)(2)(i) — Required — documentation-retention gaps. This section exists so that addressable findings have a home that does not overstate them.
5. `## Business-associate perimeter` — the destination set, proven at the socket layer, or on a declarative platform read out of the committed metadata (`namedCredentials/`, `remoteSiteSettings/`, `cspTrustedSites/`, `customMetadata/`) with the socket half reported `UNPROVEN`. Which destinations carry ePHI, which are on the committed allowlist, and the allowlist's `last_verified` date. **No named-vendor contractual verdicts**: every contract question is an item in the final section instead.
6. `## Minimum necessary (§164.502(b))` — non-treatment surfaces only. Each item names the surface, the role, and the field. State that treatment-context surfaces were excluded under §164.502(b)(2)(i) and that the exclusion is a coverage gap with no oracle.
7. `## De-identification and lower environments` — §164.514 element coverage, plus the provenance evidence for anything reported as production ePHI outside production. Resemblance alone appears here as an assumption, not a finding.
8. `## Breach-notification exposure (§164.400-414)` — scoping capability first: can the system answer "which records did this identity read". Then whether the encryption safe harbor could actually apply, addressing both of its conditions. Never conclude "encrypted, so not reportable".
9. `## 42 CFR Part 2` — only if a part 2 program's records are in scope: consent capture, redisclosure notice, and the data class that distinguishes them. Omit this heading entirely otherwise, rather than writing "not applicable" findings.
10. `## Security findings with no HIPAA citation` — category (b) and (c) findings at their security severity. Missing MFA lives here. This section is what keeps the compliance sections honest, and it is never omitted.
11. `## Recommendations` — a numbered list, prioritized by breach impact and then by remediation cost.
12. `## Patches` — code-level fixes for Critical and High. A patch for an addressable specification is still a patch; the finding's wording is what changes, not the fix.
13. `## Coverage` — what was audited, what was proven and at which tier, and what reported `UNPROVEN` and why. Name the permanent gaps from "Not provable here" explicitly.
14. `## Out of scope but worth verifying` — BAA execution and scope, risk-analysis and policy documents, training and sanction policy, physical safeguards under §164.310, and every assumption asserted above with its verification step restated.
