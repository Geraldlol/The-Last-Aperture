## Repaired: lost frontmatter blocks

### web-and-api

```yaml
---
name: web-and-api
title: Web application and API security
cross_cutting: false
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
  - request-smuggling-and-proxy-normalisation
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
  - client-trusted-business-rules      # business-logic (cross-cutting) files multi-step workflow abuse against this slug
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
  dsr-fulfilment-mechanics: privacy-and-data-protection
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
```

### crypto-and-key-management (lens formerly filed as crypto-deep-dive)

```yaml
---
name: crypto-and-key-management   # renamed from crypto-deep-dive; forced by R3 â€” all eleven surviving lenses target `crypto-and-key-management` in their defers maps, so this is the authoritative name and the file should be lenses/crypto-and-key-management.md
title: Cryptography and key management
cross_cutting: false
activates_on:
  paths:
    - '**/*crypt*.{py,js,ts,tsx,go,java,kt,rb,cs,php,rs,swift}'
    - '**/{crypto,keys,kms,signing,signature,hmac,hashing}/**'
    - '**/*{jwt,jwks,jose,oauth,oidc,saml,sso}*.{py,js,ts,go,java,kt,rb,cs,php,rs,xml}'
    - '**/*{Cipher,Crypto,KeyStore,Signer,Verifier,Digest,Hmac}*.{java,kt,cs,swift,scala}'
    - '**/{password,passwd}*.{py,js,ts,go,java,kt,rb,cs,php,rs}'
    - '**/{auth,authn,session,webhooks}/**/*.{py,js,ts,go,java,kt,rb,cs,php,rs}'
    - '**/{openssl.cnf,openssl.conf,ssl.conf,sshd_config,ssh_config}'
    - '**/{nginx,haproxy,envoy}*.{conf,yaml,yml}'
    - '**/*.{pem,key,p12,pfx,jks,keystore,asc}'
    - '**/{tls,ssl,mtls}*.{go,py,ts,js,java,yaml,yml}'
  signals:
    - 'python: cryptography, pycryptodome / Crypto.Cipher, hashlib, hmac, secrets, PyJWT (import jwt), authlib, passlib, bcrypt, argon2-cffi, PyNaCl/nacl, pyOpenSSL, python3-saml, xmlsec'
    - 'node: node:crypto, crypto.createCipheriv, crypto.timingSafeEqual, jsonwebtoken, jose, jwks-rsa, node-forge, bcrypt/bcryptjs, argon2, libsodium-wrappers, tweetnacl, @node-saml/node-saml, openid-client'
    - 'java/kotlin: javax.crypto.Cipher, SecretKeySpec, IvParameterSpec, java.security.SecureRandom, MessageDigest, Signature, SSLContext, X509TrustManager, org.bouncycastle, com.auth0:java-jwt, nimbus-jose-jwt, opensaml'
    - 'go: crypto/rand, crypto/aes, crypto/cipher, crypto/hmac, crypto/subtle, subtle.ConstantTimeCompare, golang-jwt/jwt, go-jose, golang.org/x/crypto/{bcrypt,argon2,nacl}, tls.Config MinVersion / InsecureSkipVerify'
    - 'dotnet/php/ruby/rust: System.Security.Cryptography, Aes.Create(), RandomNumberGenerator, Rfc2898DeriveBytes, ServerCertificateValidationCallback, openssl_encrypt, password_hash, hash_equals, firebase/php-jwt, OpenSSL::Cipher, ActiveSupport::MessageEncryptor, ring, aes-gcm, rustls, jsonwebtoken'
    - 'misuse idioms: MODE_ECB, "AES/ECB/PKCS5Padding", "AES/CBC/PKCS5Padding" hand-rolled with separate HMAC, new IvParameterSpec(new byte[16]), InsecureSkipVerify: true, verify=False, rejectUnauthorized: false, NODE_TLS_REJECT_UNAUTHORIZED=0, alg":"none", options={"verify_signature": False}, jwt.decode() without verify, .setSeed(, Math.random(), random.random(), md5(/sha1( near password, base64 key literals in constants files'
    - 'protocol/asset signals: X-Signature / X-Hub-Signature / Stripe-Signature style webhook headers, ecrecover / secp256k1 / low-s, /.well-known/jwks.json, SAMLResponse, InResponseTo, KeyInfo, argon2id$ / $2b$ / pbkdf2_sha256$ hash prefixes in fixtures or migrations'
owns:
  - tls-and-certificate-validation
  - jwt-jws-and-jwks-verification
  - saml-assertion-validation
  - oauth-oidc-flow-correctness
  - password-hashing-and-kdf-parameters
  - symmetric-encryption-and-nonce-handling
  - asymmetric-scheme-pitfalls
  - signature-malleability-and-curve-validation
  - hmac-and-constant-time-comparison
  - legacy-hash-and-cipher-primitives
  - csprng-and-token-entropy
  - key-separation-derivation-and-destruction
  - hash-as-pseudonym-reversibility
  - hardcoded-credentials-and-key-material
defers:
  session-and-cookie-management: web-and-api
  authentication-and-credential-flows: web-and-api
  authz-object-level: web-and-api
  csrf: web-and-api
  open-redirect: web-and-api
  webhook-handler-integrity: web-and-api
  secrets-in-browser-bundle: web-and-api
  application-log-and-url-content: web-and-api
  ci-secret-and-token-handling: cicd-and-supply-chain
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  package-dependency-cves: cicd-and-supply-chain
  artifact-signing-and-provenance-emission: cicd-and-supply-chain
  kms-key-lifecycle-and-policy: cloud-and-iac
  managed-secret-service-configuration: cloud-and-iac
  encryption-at-rest-configuration: cloud-and-iac
  resource-tls-enforcement-flags: cloud-and-iac
  model-artifact-provenance: llm-and-ai
  platform-keystore-key-custody: mobile-app-security
  certificate-pinning-implementation: mobile-app-security
  secrets-in-mobile-binary: mobile-app-security
  shield-encryption-caveats: salesforce-platform
  named-and-external-credentials: salesforce-platform
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
  - cwe                   # body must cite CWE-323, 327, 329, 338, 347, 208, 916, 295, 757 inline; a top-25 lineage, if claimed, is written exactly cwe-top-25 â€” there is no separate "SANS Top 25" list
severity_floor: low
---
```

### Slugs I claimed

- web-and-api (33): authz-object-level, authz-property-level, authz-function-level, authentication-and-credential-flows, session-and-cookie-management, tenant-isolation-enforcement, csrf, cors-policy, security-headers-and-csp, open-redirect, injection-sql-nosql-orm, injection-command-and-template, deserialization-and-xxe, xss-and-output-encoding, path-traversal-and-file-access, file-upload-handling, mass-assignment-and-parameter-binding, ssrf-application-path, request-smuggling-and-proxy-normalisation, cache-poisoning-and-deception, rate-limiting-and-request-quotas, graphql-api-surface, websocket-and-sse-authorization, api-inventory-and-version-deprecation, webhook-handler-integrity, third-party-api-response-trust, third-party-script-integrity-sri, secrets-in-browser-bundle, error-handling-and-verbose-responses, application-log-and-url-content, debug-and-admin-endpoint-exposure, client-trusted-business-rules, race-conditions-and-toctou
- crypto-and-key-management (14): tls-and-certificate-validation, jwt-jws-and-jwks-verification, saml-assertion-validation, oauth-oidc-flow-correctness, password-hashing-and-kdf-parameters, symmetric-encryption-and-nonce-handling, asymmetric-scheme-pitfalls, signature-malleability-and-curve-validation, hmac-and-constant-time-comparison, legacy-hash-and-cipher-primitives, csprng-and-token-entropy, key-separation-derivation-and-destruction, hash-as-pseudonym-reversibility, hardcoded-credentials-and-key-material
- New slugs (not referenced by any surviving defers map; registry must add them): path-traversal-and-file-access, file-upload-handling, mass-assignment-and-parameter-binding, request-smuggling-and-proxy-normalisation, cache-poisoning-and-deception, websocket-and-sse-authorization, api-inventory-and-version-deprecation, third-party-api-response-trust, debug-and-admin-endpoint-exposure, signature-malleability-and-curve-validation, legacy-hash-and-cipher-primitives

---

## 2. Overlap resolution table

Lens abbreviations in column 3: `web`=web-and-api, `crypto`=crypto-and-key-management, `cloud`=cloud-and-iac, `cicd`=cicd-and-supply-chain, `mobile`=mobile-app-security, `llm`=llm-and-ai, `hipaa`=hipaa-and-phi, `privacy`=privacy-and-data-protection, `sf`=salesforce-platform, `threat`=threat-modeling, `biz`=business-logic (cross-cutting), `chain`=attack-chaining (cross-cutting). Rows with `â€”` in column 3 are collisions the original reference files exhibited that the frontmatter now resolves by naming a single owner without a reciprocal defers entry.

| topic slug | owning lens | lenses that defer to it | note |
|---|---|---|---|
| authz-object-level | web-and-api | cicd, cloud, crypto, hipaa, mobile, privacy, threat | the most contested slug; every platform lens restated BOLA/IDOR |
| authz-property-level | web-and-api | hipaa, mobile, privacy | hipaa's "GraphQL field-level auth / API3" prose folds into this |
| authz-function-level | web-and-api | mobile, threat | also the slug `biz` files skipped-approval-step findings against |
| authentication-and-credential-flows | web-and-api | crypto, threat | threat's "account takeover" pattern list resolves here |
| session-and-cookie-management | web-and-api | cloud, crypto, privacy, sf, threat | security properties here; lawfulness/lifetime is privacy's |
| tenant-isolation-enforcement | web-and-api | threat | threat raises it as a boundary, web owns the enforcement check |
| csrf | web-and-api | crypto, privacy, threat | privacy touched it only via cookie SameSite |
| cors-policy | web-and-api | sf, threat | sf's CSP Trusted Sites is a separate platform slug |
| security-headers-and-csp | web-and-api | cloud, llm, sf | cloud's CDN/header config and llm's CSP advice both fold in |
| open-redirect | web-and-api | crypto, mobile, sf | crypto keeps only the OAuth redirect-URI exact-match rule |
| injection-sql-nosql-orm | web-and-api | cicd, cloud, llm, sf, threat | sf's SOQL variant is its own slug, not this one |
| injection-command-and-template | web-and-api | llm, sf | llm's "output to eval/exec/system" sink resolves here |
| deserialization-and-xxe | web-and-api | sf | sf's Apex XML parsing folds in |
| xss-and-output-encoding | web-and-api | cloud, llm, mobile, sf, threat | sf's LWC/Aura/VF sinks are a separate platform slug |
| mass-assignment-and-parameter-binding | web-and-api | â€” | new slug; absorbs API6 material scattered across web and sf |
| ssrf-application-path | web-and-api | cloud, hipaa, llm | app-side URL validation; IMDS hardening is cloud's |
| rate-limiting-and-request-quotas | web-and-api | llm, mobile, threat | llm keeps only cost-shaped abuse under denial-of-wallet |
| graphql-api-surface | web-and-api | hipaa, threat | introspection, depth, batching |
| webhook-handler-integrity | web-and-api | cicd, crypto, privacy | the original triple-coverage; cicd narrowed to build triggers |
| third-party-script-integrity-sri | web-and-api | cicd, privacy | browser-side SRI; privacy keeps Magecart-on-payment-page |
| third-party-api-response-trust | web-and-api | â€” | new slug; llm's model-output taint stays separate |
| secrets-in-browser-bundle | web-and-api | crypto, llm | mobile binaries are mobile's slug |
| error-handling-and-verbose-responses | web-and-api | hipaa | hipaa uplifts severity, does not re-find |
| application-log-and-url-content | web-and-api | crypto, hipaa, privacy | the PII/PHI-in-URL severity conflict resolves by uplift, not re-finding |
| debug-and-admin-endpoint-exposure | web-and-api | â€” | absorbs threat's admin-surface marker and mobile's `__DEV__` prose |
| client-trusted-business-rules | web-and-api | â€” | `biz` raises multi-step abuse against this slug; web owns it |
| race-conditions-and-toctou | web-and-api | â€” | same arrangement as above; `biz` and `chain` cite, never own |
| tls-and-certificate-validation | crypto-and-key-management | cloud, hipaa, mobile, sf, web | version floor and validation logic in one place |
| jwt-jws-and-jwks-verification | crypto-and-key-management | cloud, mobile, sf, threat, web | `alg:none` and HS/RS confusion were duplicated in web |
| saml-assertion-validation | crypto-and-key-management | sf, web | signature wrapping, InResponseTo, audience |
| oauth-oidc-flow-correctness | crypto-and-key-management | mobile, sf, web | PKCE and state; mobile keeps only native-client specifics |
| password-hashing-and-kdf-parameters | crypto-and-key-management | cloud, hipaa, mobile, web | mobile's whole M10 restatement collapses here |
| symmetric-encryption-and-nonce-handling | crypto-and-key-management | cloud, hipaa, llm, mobile, privacy, sf, web | ECB and static-IV misuse; config flags stay with cloud |
| asymmetric-scheme-pitfalls | crypto-and-key-management | cicd, mobile | padding, key size, RSA signature verification |
| hmac-and-constant-time-comparison | crypto-and-key-management | cicd, threat, web | the timing-compare semantics all three lenses had |
| legacy-hash-and-cipher-primitives | crypto-and-key-management | â€” | absorbs mobile's MD5/SHA1/3DES bullets |
| csprng-and-token-entropy | crypto-and-key-management | threat, web | `Math.random()` for tokens |
| key-separation-derivation-and-destruction | crypto-and-key-management | hipaa, llm, privacy, threat | privacy's crypto-shredding is an application of this |
| hash-as-pseudonym-reversibility | crypto-and-key-management | privacy | privacy owns the re-identification risk; crypto owns the reversibility proof |
| hardcoded-credentials-and-key-material | crypto-and-key-management | cicd, web | in-repo key material regardless of language |
| iam-policy-and-privilege-scope | cloud-and-iac | cicd, llm, mobile, sf, threat, web | sf's permission sets are a separate platform slug |
| cloud-oidc-trust-policy | cloud-and-iac | cicd | trust-policy `sub` conditions live here; workflow config is cicd's |
| network-exposure-and-segmentation | cloud-and-iac | llm, threat, web | `0.0.0.0/0` ingress moved off web's A02 |
| object-storage-exposure | cloud-and-iac | hipaa, mobile, privacy, threat, web | public bucket findings had four homes |
| imds-hardening | cloud-and-iac | threat, web | IMDSv2 enforcement; web keeps the SSRF reachability check |
| encryption-at-rest-configuration | cloud-and-iac | cicd, crypto, hipaa, llm, privacy | provider flags; sufficiency judgement is hipaa's |
| kms-key-lifecycle-and-policy | cloud-and-iac | crypto, hipaa, llm, sf | rotation and key-policy scope |
| resource-tls-enforcement-flags | cloud-and-iac | crypto | "TLS required" on managed resources, distinct from client validation |
| kubernetes-workload-hardening | cloud-and-iac | cicd, threat | includes the hostPath/docker-socket overlap with cicd |
| kubernetes-rbac-and-admission | cloud-and-iac | â€” | distinct from iam-policy-and-privilege-scope by control plane |
| dockerfile-and-image-content | cloud-and-iac | cicd | image content at authoring time; pipeline behaviour is cicd's |
| image-cve-exposure | cloud-and-iac | cicd | registry/base-image CVEs; cicd owns whether the scan gates |
| deploy-time-signature-enforcement | cloud-and-iac | cicd | verify-at-admission; cicd owns sign-at-publish |
| serverless-function-exposure | cloud-and-iac | web | `AuthType: NONE` / `--allow-unauthenticated` |
| terraform-state-protection | cloud-and-iac | cicd | state files and locking |
| managed-secret-service-configuration | cloud-and-iac | crypto, llm, sf, web | sf Named Credentials remain sf's |
| control-plane-audit-logging | cloud-and-iac | hipaa, privacy, web | CloudTrail presence; retention duration claims are hipaa's |
| backup-and-replica-configuration | cloud-and-iac | hipaa, privacy | same-region/same-account backups |
| data-region-inventory | cloud-and-iac | privacy | where data physically sits; lawfulness of the transfer is privacy's |
| baas-security-rules | cloud-and-iac | mobile | moved off mobile: Firestore rules are backend authz policy |
| helm-and-manifest-source-pinning | cloud-and-iac | â€” | deploy-manifest pinning, kept apart from cicd action pinning |
| workflow-trigger-and-script-injection | cicd-and-supply-chain | cloud | `pull_request_target`, `${{ github.event.* }}` |
| runner-and-build-environment-trust | cicd-and-supply-chain | cloud | self-hosted runners, docker socket in build |
| ci-secret-and-token-handling | cicd-and-supply-chain | cloud, crypto, hipaa, mobile, sf | includes mobile signing keys and SFDX_AUTH_URL |
| ci-oidc-workflow-configuration | cicd-and-supply-chain | cloud | workflow-side `id-token: write`; trust policy is cloud's |
| action-and-workflow-ref-pinning | cicd-and-supply-chain | cloud, threat | SHA pinning of actions and reusable workflows |
| dependency-pinning-and-lockfiles | cicd-and-supply-chain | cloud, crypto, llm, mobile, privacy, sf, threat, web | web's A03 section reduces to a pointer |
| dependency-confusion-and-registry-config | cicd-and-supply-chain | web | `.npmrc` / `--extra-index-url` scope leaks |
| package-name-squatting | cicd-and-supply-chain | llm | resolves the slopsquatting severity conflict in cicd's favour |
| install-and-lifecycle-scripts | cicd-and-supply-chain | llm | postinstall execution |
| package-dependency-cves | cicd-and-supply-chain | crypto, llm, mobile, web | llm's ML-stack CVEs are ordinary dependency auditing |
| dependency-eol-and-abandonment | cicd-and-supply-chain | â€” | absorbs web's "EOL framework serving traffic" |
| artifact-signing-and-provenance-emission | cicd-and-supply-chain | cloud, crypto, privacy, sf, threat | sign-at-publish half of the cosign split |
| sbom-generation-and-attachment | cicd-and-supply-chain | cloud, llm, mobile, privacy, web | production and attachment, not consumption |
| pipeline-scanner-gating | cicd-and-supply-chain | cloud, sf, threat | includes `terraform apply -auto-approve` and sfdx-scanner |
| privileged-deploy-gate | cicd-and-supply-chain | cloud, hipaa | environment approvals |
| unauthenticated-build-trigger | cicd-and-supply-chain | â€” | the narrowed webhook slice: `repository_dispatch`, pipeline triggers |
| mobile-local-data-storage | mobile-app-security | cloud, hipaa, privacy, threat, web | AsyncStorage / UserDefaults / SharedPreferences |
| platform-keystore-key-custody | mobile-app-security | cloud, crypto, hipaa, sf | Keychain/Keystore attributes and auth binding |
| secrets-in-mobile-binary | mobile-app-security | cicd, crypto, llm, sf | includes embedded LLM provider keys and Connected App secrets |
| mobile-network-config-artifacts | mobile-app-security | â€” | ATS / `usesCleartextTraffic` config, distinct from crypto's TLS logic |
| certificate-pinning-implementation | mobile-app-security | crypto, threat, web | crypto keeps only "pinning is appropriate here" as rationale |
| native-app-oauth-integration | mobile-app-security | â€” | public-client redirect handling only; PKCE rules are crypto's |
| deep-link-and-ipc-surface | mobile-app-security | threat, web | `android:exported`, universal links, mutable PendingIntent |
| webview-bridge-trust | mobile-app-security | web | `injectedJavaScript` and bridge exposure; DOM XSS stays web's |
| mobile-build-and-runtime-flags | mobile-app-security | â€” | `debuggable`/`allowBackup`; hipaa uplifts when PHI is present |
| mobile-ui-and-notification-leakage | mobile-app-security | hipaa | lockscreen/clipboard/screenshot leakage |
| in-app-consent-mechanisms | mobile-app-security | privacy | the in-app prompt; lawful basis is privacy's |
| privacy-manifest-and-store-declarations | mobile-app-security | privacy | `PrivacyInfo.xcprivacy`, Play Data Safety |
| ota-update-integrity | mobile-app-security | cicd | client-side signature check before applying an update |
| native-module-provenance | mobile-app-security | cicd | vendored native code in the app tree |
| prompt-injection | llm-and-ai | hipaa, mobile, privacy, sf, threat, web | direct and indirect |
| model-output-taint-propagation | llm-and-ai | web | model output as untrusted input; the sinks are web's slugs |
| chat-exfiltration-channels | llm-and-ai | â€” | markdown-image and link exfil; threat's generic paths stay separate |
| tool-call-authority-and-mediation | llm-and-ai | sf, threat, web | who the tool call runs as |
| multi-agent-trust-propagation | llm-and-ai | â€” | agent-to-agent trust, kept apart from trust-boundary-inventory |
| rag-retrieval-authorization | llm-and-ai | cloud, sf, threat, web | per-user filtering at retrieval time |
| derived-store-data-inheritance | llm-and-ai | hipaa, privacy | embeddings and caches inherit source classification |
| llm-data-flow-inventory | llm-and-ai | hipaa, privacy | what leaves for which provider |
| denial-of-wallet-controls | llm-and-ai | â€” | cost-shaped abuse only; request-count limits are web's |
| model-artifact-provenance | llm-and-ai | cicd, crypto, mobile | `torch.load`, `trust_remote_code`, on-device models |
| mcp-server-trust | llm-and-ai | cicd | MCP server as an executing dependency |
| system-prompt-as-control | llm-and-ai | â€” | treating a prompt as a security control |
| phi-classification | hipaa-and-phi | cloud, llm, mobile, privacy, sf, web | the gate every other lens's uplift depends on |
| baa-coverage-determination | hipaa-and-phi | cicd, llm, privacy | includes LLM-provider and telemetry-vendor BAAs |
| minimum-necessary | hipaa-and-phi | privacy, web | privacy's data minimisation is the collection-side sibling |
| phi-deidentification-standard | hipaa-and-phi | â€” | Safe Harbor / expert determination; privacy owns generic pseudonymisation |
| phi-access-audit-controls | hipaa-and-phi | cloud, llm, privacy, sf, threat, web | record-level read audit; also threat's repudiation angle |
| phi-encryption-sufficiency | hipaa-and-phi | crypto | Â§164.312 judgement; primitive correctness is crypto's |
| phi-in-lower-environments | hipaa-and-phi | cicd | prod clones in staging; cicd owns the pipeline that copies |
| breach-notification-exposure | hipaa-and-phi | crypto | whether encryption makes it a non-breach |
| hipaa-documentation-retention | hipaa-and-phi | cloud, sf, threat | corrects the retention-duration claim that cloud also carried |
| phi-severity-uplift | hipaa-and-phi | cloud, llm, mobile, privacy, sf, threat, web | uplift only; never a standalone finding |
| lawful-basis-and-consent-capture | privacy-and-data-protection | llm, mobile, sf, web | consent state, not the banner widget |
| consent-gating-of-trackers | privacy-and-data-protection | hipaa, web | scripts loaded before consent |
| cookie-lawfulness-and-lifetime | privacy-and-data-protection | web | lawfulness and duration; security attributes are web's |
| collection-side-minimisation | privacy-and-data-protection | â€” | the GDPR-side twin of minimum-necessary, kept separate |
| third-party-destination-inventory | privacy-and-data-protection | hipaa, web | one inventory exercise serving BAA and DPA scope both |
| processor-contracts-and-dpa | privacy-and-data-protection | cicd, hipaa, mobile | contract-side; absorbs cicd's SSDF governance questions |
| cross-border-transfer-route | privacy-and-data-protection | cloud, llm | lawfulness of the route; region facts are cloud's |
| retention-lawfulness-and-deletion-completeness | privacy-and-data-protection | cloud, crypto, llm, mobile, threat | soft-delete residue and backup residue |
| dsr-fulfilment-mechanics | privacy-and-data-protection | llm, sf, web | export/erasure endpoints and their own authz gap |
| pii-inventory-and-data-map | privacy-and-data-protection | â€” | absorbs threat's "PII inventory" section |
| pseudonymisation-and-reidentification-risk | privacy-and-data-protection | crypto, hipaa | crypto proves the hash reverses, privacy rates the risk |
| pci-scope-and-cardholder-data | privacy-and-data-protection | cloud, crypto, hipaa, sf, threat, web | PAN handling and scope creep |
| payment-page-script-authorisation | privacy-and-data-protection | cicd | Magecart-style co-tenancy on the checkout page |
| automated-decision-making-rights | privacy-and-data-protection | llm | Art. 22 exposure from model-driven decisions |
| consumer-health-data-outside-hipaa | privacy-and-data-protection | hipaa | closes the MHMDA/Nevada gap neither file covered |
| childrens-data-and-age-assurance | privacy-and-data-protection | mobile | COPPA and age gates |
| marketing-opt-out-mechanics | privacy-and-data-protection | â€” | unsubscribe and List-Unsubscribe handling |
| privacy-by-default-settings | privacy-and-data-protection | â€” | default-on sharing toggles |
| fingerprinting-and-tracking-techniques | privacy-and-data-protection | web | canvas/device fingerprinting as a tracking technique |
| personal-data-severity-uplift | privacy-and-data-protection | cloud, sf, threat, web | uplift only, mirroring phi-severity-uplift |
| apex-sharing-declaration | salesforce-platform | cloud, mobile, threat, web | `with`/`without`/`inherited sharing` |
| apex-crud-fls-enforcement | salesforce-platform | hipaa, privacy, threat, web | `stripInaccessible`, USER_MODE, describe checks |
| soql-sosl-injection | salesforce-platform | web | the platform variant of injection-sql-nosql-orm |
| apex-entry-point-exposure | salesforce-platform | web | `@AuraEnabled`/`@RestResource` treated as public endpoints |
| flow-run-context-and-authz | salesforce-platform | threat | system-context Flows |
| lwc-aura-vf-output-sinks | salesforce-platform | web | `lwc:dom="manual"`, `aura:unescapedHtml`, `escape="false"` |
| salesforce-redirect-and-trusted-sites | salesforce-platform | web | platform redirect params and CSP Trusted Sites |
| named-and-external-credentials | salesforce-platform | crypto | correct alternative to hardcoded endpoints/tokens |
| connected-app-configuration | salesforce-platform | crypto, threat | OAuth scopes, JWT bearer cert rotation |
| permission-set-and-profile-grants | salesforce-platform | â€” | platform privilege scope, distinct from cloud IAM |
| guest-user-and-site-exposure | salesforce-platform | web | Experience Cloud guest access |
| salesforce-platform-logging-surface | salesforce-platform | hipaa | `System.debug`, Event Monitoring availability |
| shield-encryption-caveats | salesforce-platform | crypto, hipaa, privacy | what Shield does and does not protect against |
| sfdx-deploy-exposure | salesforce-platform | cicd | auth URLs and metadata exports in the repo |
| agentforce-action-authorization | salesforce-platform | llm | the anticipated gap both files lacked |
| client-cached-sensitive-state | salesforce-platform | â€” | secrets/SSN/PAN in LWC component state |
| trust-boundary-inventory | threat-modeling | cicd, crypto, hipaa, llm, mobile, privacy, sf, web | the enumeration; each crossing's control is another lens's slug |
| attacker-profile-model | threat-modeling | cicd, mobile | includes "the device is attacker-controlled" premise |
| stride-decomposition | threat-modeling | crypto, hipaa, llm, sf, web | absorbs the side-channel and repudiation examples |
| attack-tree-construction | threat-modeling | llm, web | trees only; `chain` cites finding IDs instead |
| cross-boundary-attribution-logging | threat-modeling | web | can an action be attributed across a boundary |
| pivot-feasibility | threat-modeling | cloud | lateral movement and persistence reasoning |
| exfiltration-path-enumeration | threat-modeling | hipaa, privacy, web | backups, logs, integrations as egress |
| architecture-trust-design-gaps | threat-modeling | cloud, web | web's A06 "trust via network position" resolves here |
| threat-detectability-gap | threat-modeling | â€” | would the attack be noticed; distinct from any audit-control slug |

### Canonical topic registry

```markdown
# lenses/_topics.md â€” canonical topic registry
# One line per topic slug. Exactly one owning lens per slug (invariant R1).
# CI: R1 no slug in two lenses' `owns`; R2 every slug here is owned; R3 every
# `defers` key resolves to the lens named as its value.
# 165 slugs across 10 owning lenses. The three cross-cutting lenses
# (attack-chaining, business-logic, completeness) own nothing by construction.

## web-and-api (33)
authz-object-level
authz-property-level
authz-function-level
authentication-and-credential-flows
session-and-cookie-management
tenant-isolation-enforcement
csrf
cors-policy
security-headers-and-csp
open-redirect
injection-sql-nosql-orm
injection-command-and-template
deserialization-and-xxe
xss-and-output-encoding
path-traversal-and-file-access
file-upload-handling
mass-assignment-and-parameter-binding
ssrf-application-path
request-smuggling-and-proxy-normalisation
cache-poisoning-and-deception
rate-limiting-and-request-quotas
graphql-api-surface
websocket-and-sse-authorization
api-inventory-and-version-deprecation
webhook-handler-integrity
third-party-api-response-trust
third-party-script-integrity-sri
secrets-in-browser-bundle
error-handling-and-verbose-responses
application-log-and-url-content
debug-and-admin-endpoint-exposure
client-trusted-business-rules
race-conditions-and-toctou

## crypto-and-key-management (14)
tls-and-certificate-validation
jwt-jws-and-jwks-verification
saml-assertion-validation
oauth-oidc-flow-correctness
password-hashing-and-kdf-parameters
symmetric-encryption-and-nonce-handling
asymmetric-scheme-pitfalls
signature-malleability-and-curve-validation
hmac-and-constant-time-comparison
legacy-hash-and-cipher-primitives
csprng-and-token-entropy
key-separation-derivation-and-destruction
hash-as-pseudonym-reversibility
hardcoded-credentials-and-key-material

## cloud-and-iac (21)
iam-policy-and-privilege-scope
cloud-oidc-trust-policy
network-exposure-and-segmentation
object-storage-exposure
imds-hardening
encryption-at-rest-configuration
kms-key-lifecycle-and-policy
resource-tls-enforcement-flags
kubernetes-workload-hardening
kubernetes-rbac-and-admission
dockerfile-and-image-content
image-cve-exposure
deploy-time-signature-enforcement
serverless-function-exposure
terraform-state-protection
managed-secret-service-configuration
control-plane-audit-logging
backup-and-replica-configuration
data-region-inventory
baas-security-rules
helm-and-manifest-source-pinning

## cicd-and-supply-chain (16)
workflow-trigger-and-script-injection
runner-and-build-environment-trust
ci-secret-and-token-handling
ci-oidc-workflow-configuration
action-and-workflow-ref-pinning
dependency-pinning-and-lockfiles
dependency-confusion-and-registry-config
package-name-squatting
install-and-lifecycle-scripts
package-dependency-cves
dependency-eol-and-abandonment
artifact-signing-and-provenance-emission
sbom-generation-and-attachment
pipeline-scanner-gating
privileged-deploy-gate
unauthenticated-build-trigger

## mobile-app-security (14)
mobile-local-data-storage
platform-keystore-key-custody
secrets-in-mobile-binary
mobile-network-config-artifacts
certificate-pinning-implementation
native-app-oauth-integration
deep-link-and-ipc-surface
webview-bridge-trust
mobile-build-and-runtime-flags
mobile-ui-and-notification-leakage
in-app-consent-mechanisms
privacy-manifest-and-store-declarations
ota-update-integrity
native-module-provenance

## llm-and-ai (12)
prompt-injection
model-output-taint-propagation
chat-exfiltration-channels
tool-call-authority-and-mediation
multi-agent-trust-propagation
rag-retrieval-authorization
derived-store-data-inheritance
llm-data-flow-inventory
denial-of-wallet-controls
model-artifact-provenance
mcp-server-trust
system-prompt-as-control

## hipaa-and-phi (10)
phi-classification
baa-coverage-determination
minimum-necessary
phi-deidentification-standard
phi-access-audit-controls
phi-encryption-sufficiency
phi-in-lower-environments
breach-notification-exposure
hipaa-documentation-retention
phi-severity-uplift

## privacy-and-data-protection (20)
lawful-basis-and-consent-capture
consent-gating-of-trackers
cookie-lawfulness-and-lifetime
collection-side-minimisation
third-party-destination-inventory
processor-contracts-and-dpa
cross-border-transfer-route
retention-lawfulness-and-deletion-completeness
dsr-fulfilment-mechanics
pii-inventory-and-data-map
pseudonymisation-and-reidentification-risk
pci-scope-and-cardholder-data
payment-page-script-authorisation
automated-decision-making-rights
consumer-health-data-outside-hipaa
childrens-data-and-age-assurance
marketing-opt-out-mechanics
privacy-by-default-settings
fingerprinting-and-tracking-techniques
personal-data-severity-uplift

## salesforce-platform (16)
apex-sharing-declaration
apex-crud-fls-enforcement
soql-sosl-injection
apex-entry-point-exposure
flow-run-context-and-authz
lwc-aura-vf-output-sinks
salesforce-redirect-and-trusted-sites
named-and-external-credentials
connected-app-configuration
permission-set-and-profile-grants
guest-user-and-site-exposure
salesforce-platform-logging-surface
shield-encryption-caveats
sfdx-deploy-exposure
agentforce-action-authorization
client-cached-sensitive-state

## threat-modeling (9)
trust-boundary-inventory
attacker-profile-model
stride-decomposition
attack-tree-construction
cross-boundary-attribution-logging
pivot-feasibility
exfiltration-path-enumeration
architecture-trust-design-gaps
threat-detectability-gap

## attack-chaining (0) â€” cross-cutting, owns nothing
## business-logic (0) â€” cross-cutting, owns nothing
## completeness (0) â€” cross-cutting, owns nothing
```

### Final lens filename list

```
lenses/web-and-api.md
lenses/crypto-and-key-management.md
lenses/cloud-and-iac.md
lenses/cicd-and-supply-chain.md
lenses/mobile-app-security.md
lenses/llm-and-ai.md
lenses/hipaa-and-phi.md
lenses/privacy-and-data-protection.md
lenses/salesforce-platform.md
lenses/threat-modeling.md
lenses/attack-chaining.md
lenses/business-logic.md
lenses/completeness.md
```

### Self-check

I did not eyeball this. I extracted the `owns` and `defers` blocks from all thirteen frontmatter blocks mechanically (using the temporary scratchpad script `work/parse.ps1` with `work/surviving-clean.md` â€” the surviving file with the truncated leading crypto fragment stripped â€” and `work/new-two.md` holding the two newly authored blocks) and checked the invariants by set comparison.

- **R1 holds.** 165 distinct slugs, and no slug appears in more than one lens's `owns`. Per-lens counts: web-and-api 33, cloud-and-iac 21, privacy-and-data-protection 20, cicd-and-supply-chain 16, salesforce-platform 16, crypto-and-key-management 14, mobile-app-security 14, llm-and-ai 12, hipaa-and-phi 10, threat-modeling 9. Sum = 165, matching the distinct count exactly, which is the same statement.
- **R2 holds by construction.** The registry above is exactly the union of the ten `owns` lists, emitted from the same extraction, so it has no unowned entries and no missing ones.
- **R3 holds.** Every one of the ~380 `defers` keys across the thirteen blocks resolves to the lens that actually owns it: zero mismatches, and zero keys pointing at a slug no lens owns. This includes the rename hazards â€” all eleven surviving lenses target `crypto-and-key-management` (which is why the block adopts that name rather than `crypto-deep-dive`), and every reference to the other two renamed lenses uses `mobile-app-security` and `privacy-and-data-protection`, never `mobile` or `privacy-and-compliance`.

Two things CI must special-case rather than treat as violations, both already noted in the surviving file: the three cross-cutting lenses have `owns: []` and `defers: {}`, so R1 and R3 are vacuous for them and R2 must not expect them to own anything; and `web-and-api` owns `client-trusted-business-rules` and `race-conditions-and-toctou` while `business-logic` is the lens that raises findings against them, so a rule inferring ownership from which lens emits a finding would misfire.

One gap worth flagging to the parent: eleven slugs in the registry are new with this restructure and are not referenced by any surviving `defers` map (`path-traversal-and-file-access`, `file-upload-handling`, `mass-assignment-and-parameter-binding`, `request-smuggling-and-proxy-normalisation`, `cache-poisoning-and-deception`, `websocket-and-sse-authorization`, `api-inventory-and-version-deprecation`, `third-party-api-response-trust`, `debug-and-admin-endpoint-exposure`, `signature-malleability-and-curve-validation`, `legacy-hash-and-cipher-primitives`). R1â€“R3 do not constrain them, so nothing detects it if a lens body silently starts reporting one of them; only the `completeness` lens would notice.

---

## Invariant verification

**Method.** Parsed all 13 blocks with a script rather than by eye: `owns` lists, `defers` maps, `cross_cutting`, and `activates_on` extracted from `recon/s2-surviving-frontmatter.md` (the leading truncated crypto fragment, lines 1â€“23, is correctly skipped â€” it has no `name:` key â€” and I confirmed it is byte-identical in content to the tail of the authored crypto block, which independently corroborates that reconstruction). I re-transcribed the two authored blocks, the registry, and all 158 table rows into separate files rather than reusing the prior agent's `work/` files. Temporary verification scripts: `verify/check.js`, `verify/near.js`, and `verify/absorb.js`.

### Violations found

**None of the five hunted categories is violated.** Mechanically confirmed:

- **R1** â€” 165 owned slugs, 165 distinct. No slug in two `owns`; no slug repeated inside one `owns`; no lens both owns and defers the same slug.
- **R2** â€” registry is exactly the union of the ten `owns` lists, checked in both directions: 0 registry slugs unowned, 0 owned slugs missing from registry. All ten section headers' declared counts equal both the registry line counts and the frontmatter `owns` lengths.
- **R3** â€” 350 `defers` entries (not "~380"). All resolve to the actual owner. No orphan keys, no unknown lens targets, no self-defers. Zero occurrences of `crypto-deep-dive`, `privacy-and-compliance`, or bare `mobile`/`salesforce`/`privacy` as a defers target anywhere.
- **Cross-cutting** â€” all three have `cross_cutting: true`, `owns: []`, `defers: {}`, `paths: []` and `signals: []`.
- **Category 5** â€” 0 registry misattributions. (`cross_cutting: false` is present in both authored blocks; my reduced transcription omitted the line, not the source.)

**Defects outside the three rules.** These are real and several are ship-blocking, but the lint script as specified will go green on all of them â€” which is the substantive finding: R1â€“R3 are insufficient to enforce what this deliverable documents.

1. **The overlap table is incomplete: 158 rows for 165 registry slugs.** Missing rows: `path-traversal-and-file-access`, `file-upload-handling`, `request-smuggling-and-proxy-normalisation`, `cache-poisoning-and-deception`, `websocket-and-sse-authorization`, `api-inventory-and-version-deprecation` (all web-and-api), `signature-malleability-and-curve-validation` (crypto). Fix: add seven rows with `â€”` in the deferrers column. (The table's owner column and *entire* deferrer column otherwise match the frontmatter exactly â€” I checked all 158 rows against the parsed defers maps, zero discrepancies.)

2. **Six table rows assert an absorption that no `defers` entry encodes.** R3 only validates keys that *exist*, so a donor lens that keeps reporting the absorbed topic is undetectable. Fix: add each missing key.
   - `mobile-app-security` â†’ `debug-and-admin-endpoint-exposure: web-and-api`
   - `threat-modeling` â†’ `debug-and-admin-endpoint-exposure: web-and-api`
   - `mobile-app-security` â†’ `legacy-hash-and-cipher-primitives: crypto-and-key-management`
   - `web-and-api` â†’ `dependency-eol-and-abandonment: cicd-and-supply-chain`
   - `salesforce-platform` â†’ `mass-assignment-and-parameter-binding: web-and-api`
   - `threat-modeling` â†’ `pii-inventory-and-data-map: privacy-and-data-protection`

   The first is corroborated in the frontmatter itself: `mobile-app-security` still lists `__DEV__` and `android:debuggable` in `signals` (surviving file lines 491, 482) and still owns `mobile-build-and-runtime-flags`, while the table says web absorbed the `__DEV__` prose. The lens advertises a signal for a topic it neither owns nor defers.

3. **Four more missing `defers` keys that break stated mirrors.**
   - `hipaa-and-phi` â†’ `personal-data-severity-uplift: privacy-and-data-protection` (privacy defers `phi-severity-uplift` to hipaa; the table says the uplift pair mirrors â€” it does not).
   - `hipaa-and-phi` â†’ `collection-side-minimisation: privacy-and-data-protection` (privacy defers `minimum-necessary`; the table calls them twins).
   - `cloud-and-iac` â†’ `package-dependency-cves: cicd-and-supply-chain` (cicd defers `image-cve-exposure` to cloud; cloud's `activates_on` includes `**/Dockerfile`, so `RUN pip install x==old` in a Dockerfile is unrouted).
   - `llm-and-ai` â†’ `third-party-destination-inventory: privacy-and-data-protection` (privacy defers `llm-data-flow-inventory` to llm; an LLM provider is a third-party destination).

4. **The self-check's exposure number is understated by 21.** 32 slugs have zero inbound `defers`, not 11 â€” the 11 "new" ones plus `kubernetes-rbac-and-admission`, `helm-and-manifest-source-pinning`, `dependency-eol-and-abandonment`, `unauthenticated-build-trigger`, `mobile-network-config-artifacts`, `native-app-oauth-integration`, `mobile-build-and-runtime-flags`, `chat-exfiltration-channels`, `multi-agent-trust-propagation`, `denial-of-wallet-controls`, `system-prompt-as-control`, `phi-deidentification-standard`, `collection-side-minimisation`, `pii-inventory-and-data-map`, `marketing-opt-out-mechanics`, `privacy-by-default-settings`, `permission-set-and-profile-grants`, `client-cached-sensitive-state`, `threat-detectability-gap`, `client-trusted-business-rules`, `race-conditions-and-toctou`. The "nothing detects a lens silently reporting one of these" risk is 3Ã— the stated size.

5. **Mixed British/American orthography inside one slug namespace** â€” a typo and lint hazard. British: `request-smuggling-and-proxy-normalisation`, `collection-side-minimisation`, `dsr-fulfilment-mechanics`, `pseudonymisation-and-reidentification-risk`, `payment-page-script-authorisation`. American: `deserialization-and-xxe`, `websocket-and-sse-authorization`, `rag-retrieval-authorization`, `agentforce-action-authorization`. Worst case is `payment-page-script-authorisation` sitting three slugs away from `rag-retrieval-authorization`. Fix: pick one (American `-ization` is the majority convention in the frameworks list, e.g. `cyclonedx`/`spdx` tooling) and add a CI regex rejecting the other form.

### Semantic near-duplicates

Ranked. Only the first is one I would treat as an actual R1 breach.

1. **`hash-as-pseudonym-reversibility` (crypto) â†” `pseudonymisation-and-reidentification-risk` (privacy)** â€” the table's own note gives it away: "crypto proves the hash reverses, privacy rates the risk." That is one defect on one line of code, split by *analysis type*, so both lenses will emit a finding against the same `sha256(ssn)` call. Every other parallel pair in this set splits by regime (`phi-severity-uplift`/`personal-data-severity-uplift`, `baa-coverage-determination`/`processor-contracts-and-dpa`) or by platform (`soql-sosl-injection`/`injection-sql-nosql-orm`) â€” axes that partition code. This pair is the only one that does not, which is precisely the duplication R1 exists to prevent. **Recommended single name: `pseudonymisation-and-reidentification-risk`, owned by `privacy-and-data-protection`**; crypto contributes the reversibility proof as evidence under its existing defer. If the split is kept, re-cut it so it partitions code: crypto owns "unsalted/low-entropy-domain hash of an identifier", privacy owns "no pseudonymisation where required" â€” and say so in both bodies.

2. **`client-cached-sensitive-state` (sf) â†” `secrets-in-browser-bundle` (web)** â€” an LWC bundle *is* a browser bundle; "secrets/SSN/PAN in LWC component state" and "secrets in browser bundle" both mean "sensitive value readable in client-side JS". This is the **only** platform-parallel pair in the whole set with no reciprocal defers in either direction (contrast sfâ†”web on injection, which is reciprocal both ways). Recommended: rename sf's to **`lwc-client-state-exposure`** to make the narrowing explicit, and add `salesforce-platform â†’ secrets-in-browser-bundle: web-and-api` plus `web-and-api â†’ client-cached-sensitive-state: salesforce-platform`.

3. **`hipaa-documentation-retention` (hipaa) â†” `retention-lawfulness-and-deletion-completeness` (privacy)** â€” different objects (Â§164.316 policy documents vs personal data), but the names are near-indistinguishable and there is zero reciprocity either way. Recommended rename: **`hipaa-policy-documentation-retention`**.

4. **`image-cve-exposure` (cloud) â†” `package-dependency-cves` (cicd)** â€” identical defect class ("known-vulnerable third-party component present"), split by artifact type. Base-image CVEs *are* OS-package CVEs. Defensible split; needs the missing cloudâ†’cicd defer (item 3 above) and an explicit boundary sentence ("layer contents vs manifest/lockfile").

5. **`chat-exfiltration-channels` (llm) â†” `exfiltration-path-enumeration` (threat)** â€” both enumerate egress, and neither lens defers to the other for these two slugs. Recommended: keep both (sink vs architecture) but add reciprocal defers, or fold llm's into `model-output-taint-propagation` since markdown-image exfil is a taint sink.

6. **TLS/transport triple: `tls-and-certificate-validation` (crypto) / `resource-tls-enforcement-flags` (cloud) / `mobile-network-config-artifacts` (mobile)** â€” three slugs for "is transport encrypted and enforced", split config-vs-logic along platform lines. crypto defers the cloud one but **not** the mobile one. Recommended: add `crypto-and-key-management â†’ mobile-network-config-artifacts: mobile-app-security`, and rename mobile's to **`mobile-cleartext-and-ats-config`** so its scope is legible from the name.

7. **`debug-and-admin-endpoint-exposure` (web) â†” `mobile-build-and-runtime-flags` (mobile)** â€” both cover "debug mode shipped in the artifact"; see item 2 for the `__DEV__` signal evidence.

8. **Provenance triple: `artifact-signing-and-provenance-emission` (cicd) / `model-artifact-provenance` (llm) / `native-module-provenance` (mobile)** â€” `native-module-provenance` ("vendored native code in the app tree") is an unvetted-dependency question, and mobile already routes *all other* vendored code to cicd (`dependency-pinning-and-lockfiles`, `package-dependency-cves`). Recommended: either fold it into `dependency-pinning-and-lockfiles` or rename to **`vendored-native-code-provenance`** and state why it is not a cicd dependency finding.

9. **"inventory" cluster, 6 slugs across 5 lenses** â€” `api-inventory-and-version-deprecation`, `data-region-inventory`, `llm-data-flow-inventory`, `third-party-destination-inventory`, `pii-inventory-and-data-map`, `trust-boundary-inventory`. Individually distinct, but `llm-data-flow-inventory` âŠ‚ `third-party-destination-inventory` (item 3). No rename needed for the other four; do add a one-line disambiguation table to `_topics.md`, because six same-suffix slugs is where a body author picks the wrong one.

10. Checked and judged genuinely distinct, no action: `cloud-oidc-trust-policy`/`ci-oidc-workflow-configuration` (reciprocal, clean split), `deploy-time-signature-enforcement`/`artifact-signing-and-provenance-emission` (reciprocal), `certificate-pinning-implementation`/`tls-and-certificate-validation` (reciprocal), `baa-coverage-determination`/`processor-contracts-and-dpa` (fully reciprocal), `in-app-consent-mechanisms`/`lawful-basis-and-consent-capture` (reciprocal), `consumer-health-data-outside-hipaa`/`phi-classification` (reciprocal), `data-region-inventory`/`cross-border-transfer-route` (reciprocal), `permission-set-and-profile-grants`/`iam-policy-and-privilege-scope`, `baas-security-rules`/`authz-object-level`, `denial-of-wallet-controls`/`rate-limiting-and-request-quotas`, `webview-bridge-trust`/`xss-and-output-encoding`.

### Verdict

**NEEDS FIXES (15)** â€” item 1 (7 missing table rows), item 2 (6 missing defers keys), item 3 (4 more missing keys), items 4â€“5 (2 accuracy/consistency defects), and near-duplicate 1 (the one semantic R1 breach) plus renames 2/3/6/8.

Zero of these trip R1, R2 or R3 as specified, so the lint script will pass on the current text. Recommend two additional CI rules before release: (a) every registry slug must have exactly one table row; (b) an orthography regex. A third rule â€” "every pair of lenses whose bodies both mention a slug must have a defers entry" â€” is what would have caught items 2 and 3, but it needs the bodies, which do not exist yet.
