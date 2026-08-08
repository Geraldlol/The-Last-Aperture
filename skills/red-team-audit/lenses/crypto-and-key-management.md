---
name: crypto-and-key-management
title: Cryptography and key management
runs_in: fanout
activates_on:
  paths:
    - '**/*crypt*.{py,js,ts,tsx,go,java,kt,rb,cs,php,rs,swift}'
    - '**/{crypto,keys,kms,signing,signature,hmac,hashing}/**'
    - '**/*{jwt,jwks,jose,oauth,oidc,saml,sso}*.{py,js,ts,go,java,kt,rb,cs,php,rs,xml}'
    - '**/*{Cipher,Crypto,KeyStore,Signer,Verifier,Digest,Hmac}*.{java,kt,cs,swift,scala,cls}'
    - '**/*{Hmac,Crypto,Security,Signature,Signer,Webhook,Receiver,Token}*.cls'
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
    - 'go: crypto/rand, crypto/aes, crypto/cipher, crypto/hmac, crypto/subtle, subtle.ConstantTimeCompare, hmac.Equal, golang-jwt/jwt, go-jose, golang.org/x/crypto/{bcrypt,argon2,nacl}, tls.Config MinVersion / InsecureSkipVerify'
    - 'apex: Crypto.encrypt / encryptWithManagedIV / decrypt / decryptWithManagedIV, including version- and license-dependent AES-GCM (release notes document AES256-GCM and aaData), Crypto.generateMac, Crypto.generateDigest, Crypto.generateAesKey, Crypto.areEqualConstantTime, Crypto.sign, Crypto.verify, EncodingUtil.base64Decode / convertFromHex, RestContext.request.headers; prefer the built-in Blob comparator, and treat a project-local constantTimeEquals / secureCompare / safeEquals helper as a read-to-clear candidate only'
    - 'swift: CryptoKit or swift-crypto Crypto, CommonCrypto, SymmetricKey, AES.GCM, ChaChaPoly, HMAC<...>.authenticationCode / isValidAuthenticationCode, Insecure.MD5 / Insecure.SHA1, SecRandomCopyBytes, kSecAttr*'
    - 'dotnet/php/ruby/rust: System.Security.Cryptography, Aes.Create(), RandomNumberGenerator, Rfc2898DeriveBytes, ServerCertificateValidationCallback, openssl_encrypt, password_hash, hash_equals, firebase/php-jwt, OpenSSL::Cipher, ActiveSupport::MessageEncryptor, ring, aes-gcm, rustls, jsonwebtoken'
    - 'misuse idioms: MODE_ECB, "AES/ECB/PKCS5Padding", "AES/CBC/PKCS5Padding" hand-rolled with separate HMAC, new IvParameterSpec(new byte[16]), InsecureSkipVerify: true, verify=False, rejectUnauthorized: false, NODE_TLS_REJECT_UNAUTHORIZED=0, alg":"none", options={"verify_signature": False}, jwt.decode() without verify, .setSeed(, Math.random(), random.random(), md5(/sha1( near password, base64 key literals in constants files'
    - 'protocol/asset signals: X-Signature / X-Hub-Signature / Stripe-Signature style webhook headers, ecrecover / secp256k1 / low-s, /.well-known/jwks.json, SAMLResponse, InResponseTo, KeyInfo, argon2id$ / $2b$ / pbkdf2_sha256$ hash prefixes in fixtures or migrations'
    - 'node:crypto'
    - 'Ed25519'
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: consumed
      artifact_kinds: [apk, ipa, jar, oci-image]
      may_conclude: [secret-present-in-artifact]
    deployed-state:
      state: consumed
      may_conclude: [runtime-misconfiguration]
    live-runtime:
      state: consumed
      may_conclude: [runtime-misconfiguration]
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
  pseudonymization-and-reidentification-risk: privacy-and-data-protection
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
  - cwe                   # body must cite CWE-323, 327, 329, 338, 347, 208, 916, 295, 757 inline; a top-25 lineage, if claimed, is written exactly cwe-top-25 — there is no separate "SANS Top 25" list
severity_floor: low
---

## Scope

This lens audits cryptography as it is *used*: symmetric encryption and nonce handling, password hashing and key derivation, HMAC and constant-time comparison, TLS and certificate validation, JWT/JWS/JWKS and SAML signature verification, OAuth and OIDC flow correctness, asymmetric scheme selection, signature malleability, CSPRNG and token entropy, and where key material lives in the repository.

Almost nothing here is a broken primitive. AES, SHA-256, Ed25519 and X25519 are fine. The findings are correct primitives wired together wrongly, and the two failure modes that matter point in opposite directions:

- **A construction that is correct but bounded.** A fresh CSPRNG nonce per AES-GCM call is the recommended stateless design. It has real limits — an invocation cap, and a hazard if the nonce escapes the per-message path — and none of those limits is "this code is vulnerable". Reporting it as one burns the report.
- **A construction that is broken but reads as deliberate.** A nonce assigned once at module scope, a `Cipher.getInstance("AES")` that silently resolves to ECB, a `jwt.decode()` where `verify()` was meant. Each of these looks like somebody made a choice.

Three facts drive everything below.

- **Reuse, not predictability, is what breaks a nonce.** For AES-GCM, AES-CTR and ChaCha20 the requirement is *uniqueness* per key. A predictable nonce is fine if it is unique; a random nonce is fatal if it repeats. The one place predictability itself is the defect is a CBC IV (CWE-329).
- **A repeated `(key, nonce)` pair does not leak the key.** It leaks the plaintext XOR, and for GCM it leaks the GHASH subkey `H`, which enables arbitrary tag forgery *for messages carrying that nonce* (CWE-323). Forging under a *different* nonce would need `E_K(J0′)` for that nonce, which this attack does not yield — but the attacker simply keeps reusing the compromised one, so the finding is Critical on its own terms. Claiming that the AES key is recovered is both wrong and unnecessary.
- **Signatures fail at verification, not at signing.** `alg: none`, an unpinned algorithm list, a `decode` that never verified, a SAML parser that binds a signature to an element other than the one it consumes (CWE-347). The signing side is almost always correct, because a library wrote it.

### Owns

| Topic | What that means here |
|---|---|
| `tls-and-certificate-validation` | Chain and hostname verification, minimum version and cipher policy, mTLS client-certificate validation, and every "trust everything" switch (CWE-295, CWE-757). |
| `jwt-jws-and-jwks-verification` | `alg` handling, algorithm pinning, key resolution through `kid`/`jku`/`x5u`/JWKS, claim validation, and `decode` used where `verify` was meant (CWE-347). |
| `saml-assertion-validation` | Signature wrapping, what the signature actually covers, XXE in the parser, `InResponseTo`, audience restriction, assertion-ID replay. |
| `oauth-oidc-flow-correctness` | PKCE, `state`, `nonce`, `iss`, redirect-URI matching, authorization-code one-time use, refresh-token rotation, `id_token` validation (RFC 7636, RFC 9700). |
| `password-hashing-and-kdf-parameters` | Algorithm choice and the parameters on the *stored artifact* (CWE-916), plus the bcrypt input-length traps (OWASP Password Storage Cheat Sheet — RFC 9106 is Argon2 and says nothing about them). |
| `symmetric-encryption-and-nonce-handling` | Mode selection, nonce and IV construction and lifetime, AEAD versus hand-rolled composition, verify-before-decrypt ordering, padding oracles (CWE-323, CWE-329, NIST SP 800-38D). |
| `asymmetric-scheme-pitfalls` | RSA padding choice and strict parsing (RFC 8017, NIST SP 800-56B), ECDSA nonce generation (RFC 6979), Diffie-Hellman peer-key validation, Ed25519 verification semantics. |
| `signature-malleability-and-curve-validation` | `(r, s)` versus `(r, -s mod n)`, low-`s` enforcement, `ecrecover` returning the zero address, point-on-curve and subgroup checks. |
| `hmac-and-constant-time-comparison` | The MAC primitive and the comparison of its output (CWE-208), length extension, and the freshness data a MAC does not itself carry. |
| `legacy-hash-and-cipher-primitives` | MD5, SHA-1, DES, 3DES, RC4, ECB — and which security property is actually broken in the use at hand (CWE-327). |
| `csprng-and-token-entropy` | Generator choice (CWE-338), seeding, and whether a token carries enough entropy over the alphabet it is actually drawn from. |
| `key-separation-derivation-and-destruction` | HKDF versus `SHA256(key ‖ context)` (RFC 5869), one key across contexts, key lifetime, and whether anything can rotate. |
| `hardcoded-credentials-and-key-material` | Private keys, secrets and credential-shaped literals in the tree — and the discipline that separates them from public keys, CA bundles and test vectors. |

### Does not own

Do not raise findings on these. Where the code shows one, note it in the candidate's `impact` as an aggravator and hand it to the owning lens with the file and line.

- **web-and-api** — `session-and-cookie-management`, `authentication-and-credential-flows`, `authz-object-level`, `csrf`, `open-redirect`, `webhook-handler-integrity`, `secrets-in-browser-bundle`, `application-log-and-url-content`. Two of these split against topics this lens owns, so the seam is stated:
  - **`webhook-handler-integrity` is web-and-api's.** This lens owns the verification *primitive* — whether the MAC is computed over the raw request bytes, whether the comparison is constant-time, whether a timestamp is bound into the signed string. The *handler* — idempotency, a replay cache, whether the side effect happens before or after the 401, whether the endpoint is reachable unauthenticated — is theirs. One defect, one finding.
  - **`authentication-and-credential-flows` is web-and-api's** — login, lockout, reset-token lifecycle, MFA. What stays here is the stored artifact and its parameters (`password-hashing-and-kdf-parameters`) and the entropy of the token itself (`csprng-and-token-entropy`).
- **cicd-and-supply-chain** — `ci-secret-and-token-handling`, `dependency-pinning-and-lockfiles`, `package-dependency-cves`, `artifact-signing-and-provenance-emission`. A vulnerable crypto library *version* is their CVE finding; how the code calls it is this lens's. Emitting provenance is theirs; verifying a signature in application code is this lens's.
- **cloud-and-iac** — `kms-key-lifecycle-and-policy`, `managed-secret-service-configuration`, `encryption-at-rest-configuration`, `resource-tls-enforcement-flags`. Rotation policy, key policy, a bucket's SSE setting and a load balancer's TLS policy are configuration. This lens owns the code that calls the KMS, not the key's lifecycle.
- **llm-and-ai** — `model-artifact-provenance`. Whether a model artifact is authentic is theirs; the signature-verification code path, where one exists, is this lens's.
- **mobile-app-security** — `platform-keystore-key-custody`, `certificate-pinning-implementation`, `secrets-in-mobile-binary`. Keychain and Keystore custody, pin sets and their rotation story, and a secret compiled into an app binary. **`tls-and-certificate-validation` stays here**: an unconditional `URLSessionDelegate` trust callback, an empty `checkServerTrusted`, an always-true `HostnameVerifier` are this lens's findings even inside a mobile app. Pinning is theirs; validating at all is this lens's.
- **salesforce-platform** — `shield-encryption-caveats`, `named-and-external-credentials`, `connected-app-configuration`. Where a callout credential lives on-platform, and what Shield does and does not protect. Primitive correctness inside `Crypto.*` calls stays here.
- **hipaa-and-phi** — `phi-encryption-sufficiency`, `breach-notification-exposure`. Whether the resulting posture is sufficient for PHI, and what a breach requires, are decided there. This lens supplies the primitive facts they consume and does not grade the data class.
- **privacy-and-data-protection** — `pseudonymization-and-reidentification-risk`, `pci-scope-and-cardholder-data`, `retention-lawfulness-and-deletion-completeness`. Notably: **an unsalted hash used as a pseudonym is theirs**, not a `legacy-hash-and-cipher-primitives` finding here. `sha256(email)` is not a broken primitive; it is a reversible pseudonym over a small domain, which is a re-identification finding. Supply the fact, do not grade it.
- **threat-modeling** — `stride-decomposition`, `trust-boundary-inventory`.

Two boundaries with no `defers` entry, stated so they are not double-filed. **Key material committed to the repository is this lens's** (`hardcoded-credentials-and-key-material`) wherever it appears, including inside a workflow file — cicd owns how CI *injects* a secret, this lens owns a private key that is *in the tree*. And **randomness with no security meaning is not a finding**: `Math.random()` for UI jitter, a retry delay, a sample rate or a cache-buster is correct code.

### Three inversions in the source material this lens replaces

The reference file this lens supersedes taught the inverse of the truth in three places. The labels are quoted here only so that a reader who has seen them knows they were repudiated deliberately. **Nothing in this block is an instruction**; every operative statement in this lens is elsewhere.

| What the source said | What is true |
|---|---|
| Labelled a fresh per-call `secrets.token_bytes(12)` as `VULNERABLE`, while its own adjacent comment said `OK for GCM`. | It is the recommended stateless construction (NIST SP 800-38D §8.2.2, the RBG-based construction). The real caveats are the invocation cap, a nonce that escapes the per-message path, and a process-resident generator duplicated by fork or VM snapshot. See Checklist item 1. |
| Labelled a monotonic counter nonce `CATASTROPHIC`, while its own adjacent comment said it was fine if the counter is unique per key. | It is an approved construction (NIST SP 800-38D §8.2.1, the deterministic construction) and is what TLS 1.3 and QUIC do. The failure conditions are a counter that resets and per-replica counters sharing one key with no distinct fixed field. See Checklist item 1. |
| Graded "static or predictable IV in AES-GCM" as risking **key compromise**. | It does not. A repeated `(key, nonce)` pair leaks the plaintext XOR and the GHASH subkey `H`, which enables arbitrary tag forgery for messages carrying that nonce. The AES key is not recovered. Predictability by itself is fatal only for a CBC IV. See the severity table. |

Two further corrections of the same kind, because these make a check *unfireable* rather than merely wrong:

- `Crypto.AES.new(key, AES.MODE_ECB)` is not a real symbol. There is no `Crypto.AES` module in PyCrypto or PyCryptodome. A grep for it reports clean on every codebase, including the ones that do use ECB. Checklist item 2 greps the constructors that exist.
- PyJWT's `verify=False` was the 1.x spelling and stopped being the switch in PyJWT 2.0. Checklist item 5 greps the shapes that are current.

### What cannot be determined from a repository

State these as assumptions with a verification step — never as findings, and never as clearances.

- **Whether a committed key is live.** Grep finds the literal; only the operator knows whether it was rotated. Read `git log -p` for the file first — a value rotated years ago is a hygiene note, not a Critical — and say which you established.
- **Key material held outside the tree.** A KMS key policy, an HSM, a secret-manager entry, the actual bytes behind `os.environ["SECRET_KEY"]`. The entropy of a runtime-supplied secret is not knowable here. What *is* knowable is whether the code accepts a weak one: no length check, or a default fallback literal when the variable is unset.
- **How many messages a key has encrypted.** The AES-GCM invocation cap is a runtime property. What the repository shows is whether anything rotates the key at all, and whether the nonce construction has a bound the code respects.
- **The deployed TLS policy.** A reverse proxy, load balancer or service mesh may terminate TLS with a policy that is not in this repository — and may equally be absent. Do not clear an `InsecureSkipVerify` because "the mesh probably handles it"; do not assert a version floor you cannot see. Both directions are assumptions.
- **Whether a JWKS endpoint is under the same control as the issuer.** The URL is in the config; the DNS and the hosting are not.
- **Clock skew and the real replay window.** A tolerance constant is visible; whether the fleet's clocks justify it is operational.

## Activation coverage

Language activation is not a promise that a generic primitive grep understands
that language. The rows below make that boundary explicit.

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| Multi-language primitive and auth source umbrellas | PARTIAL | `legacy-hash-and-cipher-primitives` | Construction and misuse checks exist, but the composite activators span uneven language support; the Scala branch is NOT ASSESSED |
| Apex crypto, signature and webhook sources | PARTIAL | `hmac-and-constant-time-comparison` | V-014 measures the HMAC comparison path, but both assigned Apex activators are compound inventories |
| Swift CryptoKit, swift-crypto and CommonCrypto signals | PARTIAL | `csprng-and-token-entropy` | Scoped nonce, HMAC, digest and RNG checks exist; there is no compiled fixture pair |
| JWT, JWKS, JOSE, OAuth, OIDC, SAML and SSO source umbrella | PARTIAL | `jwt-jws-and-jwks-verification` | V-003 measures the JWT path; OAuth, OIDC, SAML and the remaining languages require separate checklist reads |
| Password and KDF source paths | PARTIAL | `password-hashing-and-kdf-parameters` | Parameter and storage-format checks exist, but the multi-language glob has no measured pair |
| TLS configuration and committed key assets | PARTIAL | `tls-and-certificate-validation` | Actionable checks exist; version, parser and runtime behavior still govern the verdict |

## Checklist

### 0. Highest-yield sweeps

Run these first, from the root of the source tree. Every hit is a candidate to trace, not a finding. The literals named here are demonstrated by the detector blocks in the item that owns each one; this block is an index, not a separate check.

**`--hidden` and the explicit `.` are both load-bearing.** ripgrep prunes hidden directories during
traversal, and a `--glob` does not override that pruning, so a sweep without `--hidden` cannot read
`.env`, `.aws/credentials`, `.ssh/id_rsa` or any other artifact below a dotdirectory. With no path
argument `rg` searches standard input whenever stdin is not a terminal, so the moment this block is
pasted into a script, a heredoc or a pipeline, every line returns zero hits and exits 1 — a clean
result from a sweep that never opened a file. Every repository traversal below therefore carries
`--hidden` and ends in an explicit `.`. Narrow the `.` to a subdirectory where the tree is large;
do not delete it. The inner pipeline filters intentionally omit `--hidden`: each receives one
explicit `"$f"` path from a traversal that already included hidden files, so no directory walk
occurs at that stage.

```bash
# --- symmetric encryption: constructors and the nonce/IV argument ---
# The language-specific arms matter, with Kotlin sharing Java's. Rust builds a cipher as
# `cbc::Encryptor<Aes256>` / `ctr::Ctr128BE` / `Aes256Gcm::new`, none of which
# contains `modes.` or `createCipheriv`; .NET's AEAD type is `new AesGcm(`, which
# `Aes.Create()` does not match. The CommonCrypto family pattern expands through
# `CCCryptorCreateWithMode` and `CCCryptorCreateFromDataWithMode`, not just the
# one-shot `CCCrypt` and basic `CCCryptorCreate` entry points.
rg -n --hidden 'createCipheriv\(|AES\.new\(|Cipher\(algorithms\.AES|AESGCM\(|Cipher\.getInstance\(|aes\.NewCipher\(|cipher\.NewGCM\(|Aes\.Create\(|new AesGcm\(|openssl_encrypt\(|OpenSSL::Cipher|cbc::Encryptor|cbc::Decryptor|ctr::Ctr|Aes[0-9]*Gcm::new|AES\.GCM\.(seal|open)\(|ChaChaPoly\.(seal|open)\(|CCCrypt\(|CCCryptorCreate(?:FromData)?(?:WithMode)?\(|SymmetricKey\(' .
# Mode selection. `-i` plus the added spellings are the difference between reaching
# two language families and reaching the full set named here: .NET names the mode as
# `CipherMode.CBC`/`CipherMode.ECB`, Node/Ruby/PHP name it inside the algorithm
# string (`aes-256-cbc`), Go names it in the constructor, Rust in the crate path.
rg -n --hidden -i 'MODE_ECB|MODE_CBC|/ECB/|/CBC/|modes\.(ECB|CBC)\(|CipherMode\.(ECB|CBC)|aes-[0-9]+-(ecb|cbc)|NewCBCEncrypter|NewCBCDecrypter|cbc::|ecb::|kCCOptionECBMode|kCCMode(ECB|CBC)' .
# `new` is optional and `ByteArray(` is the alternative because Kotlin writes the
# same zero-IV bug as `IvParameterSpec(ByteArray(16))`.
rg -n --hidden '(new )?IvParameterSpec\((new byte\[|ByteArray\()|GCMParameterSpec\(|AES\.GCM\.Nonce\(' .
# absence sweep: a CBC or CTR ciphertext with no authentication anywhere in the
# file (see item 3). This is the one symmetric defect with no literal of its own.
#
# The right-hand list clears, so two of its tokens are anchored on purpose and must
# stay that way: a token that matches ordinary text silently reports a vulnerable
# file as authenticated. A bare `siv` under `-i` is a substring of responsive,
# massive, passive, expensive and exclusive; a bare `gcm` under `-i` is a substring
# of configCmd, logCmd, debugCmd and stringCmp, so it is pinned to the three real
# casings. `-i` itself has to stay, for `Hmac`, `Fernet` and `Aead`.
#
# The left-hand list is the mirror-image discipline: it decides which files are
# looked at at all, so a spelling missing from it reports a whole stack clean.
# `Aes.Create()` is .NET's `Cipher.getInstance("AES")` — the framework default is
# CBC/PKCS7 and nothing on the line says so. Rust is `cbc::Encryptor` / `ctr::Ctr…`,
# never `modes.CBC(`. Ruby and PHP arrive through the `aes-256-cbc` algorithm string.
# Apex puts the mode in `algorithmName`, not in the method name. The unhyphenated
# `AES128`/`AES192`/`AES256` names are CBC with PKCS7 padding. Summer '25 (API
# 64.0) added licensed AES-GCM overloads; the release notes document `AES256-GCM`
# plus `aaData`. The Apex arm below therefore admits only literal CBC names.
# `AES*-GCM` is AEAD and must clear after its API-version and org-license
# availability are confirmed. A CBC path clears only when the `hmacSHA256`
# argument to `Crypto.generateMac` (matched by the `-i hmac` on the right) covers
# the complete envelope.
# Two shapes are still outside it and are stated rather than guessed at: a wrapper
# that takes the mode in a variable, and Go's ECB-by-omission (`block.Encrypt` used
# directly, which carries no mode literal at all).
#
# `xargs -r` is deliberately not used. `-r` is a GNU extension absent from BSD and
# macOS xargs, and xargs cannot invoke `rg` at all where it is a shell alias or
# function rather than a binary. Both failures write to stderr and leave stdout
# empty, which is indistinguishable from a clearance. The loop runs the second stage
# in the current shell instead, and its `||` prints the file when the safe pattern is
# *not* found — so a failure of the inner command over-reports rather than clears.
# The first stage has no such protection: before reading an empty result as clean,
# run that stage alone and check its exit status. 0 means candidates were found,
# 1 means there are none, and anything else (2, 127) means the sweep did not run and
# the empty output says nothing about the tree.
rg -i --hidden --files-with-matches 'modes\.CBC\(|modes\.CTR\(|createCipheriv\([^)]*(cbc|ctr)|NewCBCEncrypter|NewCTR\(|/CBC/|MODE_CBC|MODE_CTR|CipherMode\.(CBC|CTR)|aes-[0-9]+-(cbc|ctr)|cbc::Encryptor|cbc::Decryptor|ctr::Ctr|Aes\.Create\(|Crypto\.(encrypt|decrypt)(WithManagedIV)?\(\s*["'"'"']AES(128|192|256)["'"'"']|(?:CCCrypt\(|CCCryptorCreate(?:FromData)?(?:WithMode)?\()[^)]*(kCCAlgorithmAES|kCCMode(CBC|CTR))' . \
  | while IFS= read -r f; do
      rg -i -q 'hmac|poly1305|(?-i:GCM|Gcm|gcm)|aead|fernet|\bSIV\b|AESSIV|[-_]SIV\b|encrypt_then|MessageEncryptor' "$f" || printf '%s\n' "$f"
    done

# --- nonce/IV that never enters the per-message path (see item 1) ---
# The left-hand side of all three is the member-access spelling and the right-hand
# side is the generator call, and each language writes both differently: PHP is
# `$this->iv` and `random_bytes(`, Ruby is `@iv` and `SecureRandom.random_bytes`,
# Kotlin is `ByteArray(`, Node hides a hardcoded value in `Buffer.from('…','hex')`,
# Go is `make([]byte, …)` plus `rand.Read(`, Rust is `[0u8; 12]` and `OsRng`. A
# generator list that names only `os.urandom` and `crypto.randomBytes` reads four
# of those eight stacks as having no module-scope nonce at all.
# (a) object scope: an instance attribute outlives the call that set it, so every
#     message the object seals afterwards shares the value
rg -n --hidden -i '((self|this)(\.|->)|@)[A-Za-z_0-9]*(iv|nonce)[A-Za-z_0-9]*\s*=\s*(b?["'"'"']|\[|os\.urandom|secrets\.token_|getrandom\(|crypto\.randomBytes|getRandomValues|random_bytes\(|Buffer\.from\(|bytes\.fromhex\(|new byte\[|ByteArray\(|make\(\[\]byte|rand\.Read\(|SecureRandom|RandomNumberGenerator|OsRng|AES\.GCM\.Nonce\()' .
# (b) module or class scope. `rg` cannot see scope, so this is deliberately broad —
#     it also matches the correct in-function draw. Read the indentation and the
#     enclosing block on every hit; an UPPER_CASE name, a `const` at column 0 or a
#     binding inside a `class` body with no `def`/`function` between them is the bug.
#     Under `-i` an unanchored `iv` is also a substring of given, derive, private and
#     receive, so a handful of hits per file are ordinary variables — that noise is
#     the price of catching `IV`, `_iv`, `ivBytes` and `NONCE` in one pattern, and it
#     is the right way round for a sweep whose miss is a Critical.
rg -n --hidden -i '^\s*(?:(?:const|let|var|static|final|private|public|readonly|val|pub)\s+)*[@$]?[A-Za-z_0-9]*(iv|nonce)[A-Za-z_0-9]*\s*(?::[^=]*)?(?:=|:=)\s*(b?["'"'"']|\[|os\.urandom|secrets\.token_|getrandom\(|crypto\.randomBytes|getRandomValues|random_bytes\(|Buffer\.from\(|bytes\.fromhex\(|new byte\[|ByteArray\(|make\(\[\]byte|rand\.Read\(|SecureRandom|RandomNumberGenerator|OsRng|AES\.GCM\.Nonce\()' .
# (c) the unambiguous Java and .NET constant spellings. `final`/`readonly` is
#     optional on purpose — `private static byte[] IV` is the same bug — and so is a
#     leading underscore, because C# spells the same field `_iv`. A `static` holder
#     for the parameter object is the same bug again in both languages.
rg -n --hidden -i 'static\s+(final\s+|readonly\s+)?byte\[\]\s*_?(IV|NONCE)|static\s+(final\s+|readonly\s+)?(IvParameterSpec|GCMParameterSpec)\s|static\s+(let|var)\s+\w*(iv|nonce)\w*\s*(?::[^=]+)?=\s*(try[!?]?\s*)?AES\.GCM\.Nonce\(' .

# --- MAC comparison (see item 4) ---
# The construction list is one string used twice, here and in the absence sweep
# below, because the comment there requires them to be identical. `HMACSHA256`
# alone misses .NET's `HMACSHA512`; `Hmac::new` is near-dead for real Rust, which
# writes `Hmac::<Sha256>`, `type HmacSha256 = Hmac<Sha256>` and `new_from_slice`;
# CommonCrypto has both one-shot `CCHmac(` and streaming `CCHmacInit(` forms;
# Apex's keyed primitive is `Crypto.generateMac(`.
rg -n --hidden 'createHmac\(|hmac\.new\(|hmac\.digest\(|hmac\.New\(|hash_hmac\(|Mac\.getInstance\(|HMACSHA[0-9]|OpenSSL::HMAC|Hmac::<|Hmac<|HMAC<|HmacSha[0-9]|CCHmac(?:Init)?\(|Crypto\.generateMac\(' .
# The comparison itself, in two greps because it wears two shapes. First the
# equality operator: the token almost never sits against it — `hexdigest(…) == x`,
# a `$`-prefixed PHP name, a `headers.get("X-Signature")` call — so the gap is
# bounded rather than absent, the token may be on either side, and `===`/`!==` are
# included because `(==|!=)\s` cannot match PHP's. `sig` is `\b`-anchored so it does
# not fire on design and assign; the cost is that `token_source` no longer matches.
rg -n --hidden -i '(signature|\bsigs?\b|\bmac\b|digest|hmac|\btokens?\b|\bsecrets?\b)[^=!<>\n]{0,40}(===?|!==?)|(===?|!==?)[^=!<>\n]{0,40}(signature|\bsigs?\b|\bmac\b|digest|hmac|\btokens?\b|\bsecrets?\b)' .
# Then the named comparisons and validators that carry no operator at all. The
# original four are exactly
# the traps in item 4's per-language table, and the previous single grep found none
# of them: Java `Arrays.equals`, .NET `SequenceEqual`, Go `bytes.Equal`. Swift's
# `isValidAuthenticationCode` is the safe CryptoKit validator and Apex's
# `Crypto.areEqualConstantTime` is its built-in Blob comparator; both appear here
# so a correct implementation has an executable positive inventory path.
rg -n --hidden 'Arrays\.equals\(|String\.equals\(|\.SequenceEqual\(|bytes\.Equal\(|\.equals\(.*(signature|mac|digest)|isValidAuthenticationCode\(|Crypto\.areEqualConstantTime\(' .
# the absence sweep: files that compute a MAC and never compare it safely.
# The construction list here must match the positive grep above it — a Java file
# that builds a Mac and compares with Arrays.equals is invisible otherwise.
# The safe list is a clearing list. Rails's `secure_compare` and
# `fixed_length_secure_compare` are recognized only when qualified by the full
# `ActiveSupport::SecurityUtils.` namespace; a project-local helper with either
# plausible name proves nothing about its body. BouncyCastle's
# `Arrays.constantTimeAreEqual` remains
# outside the list and therefore surfaces as a candidate. That is a wrong
# finding, which is recoverable; a wrong clearance is not. Same loop, same
# reason, as the sweep above.
#
# THE SAFE LIST CONTAINS EXACT PLATFORM APIS, INCLUDING APEX'S BUILT-IN BLOB
# COMPARATOR. A `.cls` file calling it on the request value and expected MAC can
# clear at stage 2 after the executable call is read. Project-local names remain
# excluded: a length-checked branch-free accumulator and a drifted early-return
# copy look identical by name, so a file using either remains a reading candidate
# until the helper body and call site are checked.
#
# COMMENT BLINDNESS — this sweep clears on a token found ANYWHERE in the file, including
# inside a comment or a string. A line such as `// TODO: switch to AES-GCM` or
# `# was SigningMethodHMAC` silently disarms the finding, and the two files are otherwise
# byte-identical. Before clearing any file this sweep did not print, confirm the safe call
# appears in executable code on the path that handles the request. rg cannot make that
# distinction; you can, by reading the hit.
rg --hidden --files-with-matches 'createHmac\(|hmac\.new\(|hmac\.digest\(|hmac\.New\(|hash_hmac\(|Mac\.getInstance\(|HMACSHA[0-9]|OpenSSL::HMAC|Hmac::<|Hmac<|HMAC<|HmacSha[0-9]|CCHmac(?:Init)?\(|Crypto\.generateMac\(' . \
  | while IFS= read -r f; do
      # Swift is handled by the scoped sweep below. A safe CryptoKit validator
      # elsewhere in the same file cannot clear an unsafe `Data(expected) == sig`.
      case "$f" in *.swift) continue ;; esac
      # Stage 2: no constant-time comparison present. Stage 3: some equality comparison IS
      # present. Both are required, because the severity row grades on an equality operator
      # against a request value — a file that computes a keyed digest and never compares one
      # (HMAC as HKDF, or as a pseudonymiser) has nothing to compare unsafely and is not this
      # finding. Keep stage 2's list identical to the *platform* list in the row that grades
      # this — same twelve API names, same order — and do not add a project-local helper name to
      # either one. A helper is cleared by reading it, not by matching it.
      rg -q 'timingSafeEqual|compare_digest|subtle\.ConstantTimeCompare|hmac\.Equal|hash_equals|MessageDigest\.isEqual|FixedTimeEquals|ActiveSupport::SecurityUtils\.(fixed_length_secure_compare|secure_compare)|Crypto\.areEqualConstantTime|\bct_eq\b|verify_slices_are_equal' "$f" && continue
      rg -q '==|!=|===|\.equals\(' "$f" && printf '%s\n' "$f"
    done

# --- Apex: prefer the built-in comparator; read project-local fallbacks (see item 4) ---
# The first line inventories every Apex crypto entry point, including the exact
# platform comparator that stage 2 can clear after its executable call is read.
rg -n --hidden --glob '**/*.cls' 'Crypto\.(encrypt|encryptWithManagedIV|decrypt|decryptWithManagedIV|areEqualConstantTime)\(|Crypto\.generate(Mac|Digest|AesKey)\(|Crypto\.(sign|verify|signWithCertificate)\(' .
# The second enumerates candidate helpers BY NAME rather than by API. A hit is not
# a clearance — it is the body you now have to read. Prefer replacing a local
# comparator with the built-in Blob API. Until then, expect more than one: the
# shape in the field is a public
# tested helper plus private copies pasted into the classes that needed it, and a copy
# that drifted (a `break` on first difference, a loop bounded by the shorter operand)
# is the finding while its siblings are correct.
rg -n --hidden --glob '**/*.cls' -i 'constantTime[A-Za-z]*|secureCompare|safeEquals|timingSafe|slowEquals' .
# The third is the inverse and it is the one that catches the real bug: a `.cls` file
# that reads a signature off the request and compares it with an operator. Cross the
# two lists by hand — a file in this output and not in the one above compares a
# signature with nothing in front of it.
rg -n --hidden --glob '**/*.cls' -i '(signature|\bsigs?\b|\bmac\b|digest|hmac)[^=!<>\n]{0,40}(==|!=)|(==|!=)[^=!<>\n]{0,40}(signature|\bsigs?\b|\bmac\b|digest|hmac)|\.equals\([^)]*(signature|sig|mac|digest)' .

# --- Swift, where CryptoKit and CommonCrypto use spellings no other arm covers ---
# Inventory first. `SymmetricKey` is key construction rather than encryption, and
# `kSecAttr*` can be Keychain custody (owned by mobile-app-security), so these hits
# are routing and reading lists. The cipher, MAC, digest and PRNG calls beside them
# are this lens's primitive-usage surface.
rg -n --hidden --glob '**/*.swift' 'import (CryptoKit|Crypto|CommonCrypto)|SymmetricKey\(|AES\.GCM\.(seal|open)\(|ChaChaPoly\.(seal|open)\(|CCCrypt\(|CCCryptorCreate(?:FromData)?(?:WithMode)?\(|CCHmac(?:Init)?\(|kSecAttr[A-Za-z]+' .
# A default AES.GCM.Nonce() draw is safe only when it happens once per seal. This
# sweep deliberately includes local bindings: grep cannot see Swift scope, so read
# whether the binding is at module/class/object scope or inside the per-message
# function. `static let nonce = ...` is unambiguous reuse; `let nonce` is not.
rg -n --hidden --glob '**/*.swift' '^\s*(?:(?:private|fileprivate|internal|public|open|static|class)\s+)*(?:let|var)\s+\w*(iv|nonce)\w*\s*(?::[^=]+)?=\s*(?:try[!?]?\s*)?AES\.GCM\.Nonce\(' .
# CryptoKit's safe verifier computes and compares internally. A file that calls
# authenticationCode and then uses ==/!= is a candidate; a safe call elsewhere is
# not enough to clear it, so read the comparison on the request path.
rg -n --hidden --glob '**/*.swift' 'HMAC<[^>]+>\.(authenticationCode|isValidAuthenticationCode)\(|CCHmac(?:Init)?\(' .
rg --hidden --glob '**/*.swift' --files-with-matches 'HMAC<[^>]+>\.authenticationCode\(|CCHmac(?:Init)?\(' . \
  | while IFS= read -r f; do
      rg -q '==|!=' "$f" && printf '%s\n' "$f"
    done
# CryptoKit deliberately namespaces legacy digests under Insecure. CommonCrypto
# retains the CC_* entry points; both are candidates whose security use must be read.
rg -n --hidden --glob '**/*.swift' 'Insecure\.(MD5|SHA1)\.hash\(|CC_(MD5|SHA1)\(' .
# These are secure sources. Swift's `random(in:)` overloads use
# `SystemRandomNumberGenerator` by default; only `random(in:using:)` can substitute
# a custom generator, whose implementation must be traced before grading it.
rg -n --hidden --glob '**/*.swift' 'SecRandomCopyBytes\(|SystemRandomNumberGenerator|(?:Int|UInt(?:8|16|32|64)?)\.random\(in:' .

# --- JWT / JWS (see item 5) ---
# `JWT.decode(` is Ruby and java-jwt; PHP's firebase/php-jwt is `JWT::decode(`,
# nimbus is `SignedJWT.parse(`, and .NET's decode-without-verify is `ReadJwtToken(`.
rg -n --hidden 'jwt\.decode\(|jwt\.verify\(|jwt\.Parse|jwt\.NewParser\(|ParseFromRequest\(|ParseUnverified|JWT\.decode\(|JWT::decode\(|SignedJWT\.parse\(|ReadJwtToken\(|jwtVerify\(|decodeJwt\(' .
rg -n --hidden 'verify_signature|algorithms\s*[=:]|WithValidMethods|["'"'"']none["'"'"']' .
# `jwks_uri` is the OIDC discovery field; jwks-rsa and most Node config spells it
# `jwksUri`, which a case-sensitive grep for the snake_case form never sees.
rg -n --hidden -i 'jku|x5u|jwks[_-]?uri|well-known/jwks' .

# --- TLS (see item 8) ---
# One row of item 8's table had no token here at all — the curl/wget shell row —
# and .NET's modern spelling is `ServerCertificateCustomValidationCallback` on
# `HttpClientHandler`, which the older `ServerCertificateValidationCallback` literal
# does not match. `ssl.CERT_NONE` is Python's third way to say the same thing.
rg -n --hidden 'InsecureSkipVerify|rejectUnauthorized\s*[:=]\s*(false|0)|NODE_TLS_REJECT_UNAUTHORIZED|verify\s*=\s*False|CERT_NONE|CURLOPT_SSL_VERIFY|_create_unverified_context|ServerCertificate(Custom)?ValidationCallback|DangerousAcceptAnyServerCertificateValidator|checkServerTrusted|[tT]rustAllCerts|HostnameVerifier|allowsAnyHTTPSCertificate|--no-check-certificate|--insecure|curl[^\n]*\s-[a-zA-Z]*k[a-zA-Z]*(\s|$)' .
# Separate line, and separate on purpose: `urllib3.disable_warnings()` changes no
# validation behaviour and is not a finding under the row above at any severity. It
# is a pointer — read the same file for the `verify=False` or
# `_create_unverified_context()` it was added to hide, and file that.
rg -n --hidden 'urllib3\.disable_warnings|InsecureRequestWarning' .
# absence sweep: a tls.Config with no MinVersion anywhere in the file. The
# zero-value form (`var cfg tls.Config`, fields assigned afterwards) has no brace
# and is invisible to a literal-only pattern. Go-only by construction, so the
# case-sensitive `MinVersion` is correct rather than a gap — a Node `minVersion`
# never reaches this sweep. Same loop and same exit-status caveat as above.
rg --hidden --files-with-matches 'tls\.Config\{|var\s+\w+\s+tls\.Config|new\(tls\.Config\)' . \
  | while IFS= read -r f; do
      rg -q 'MinVersion' "$f" || printf '%s\n' "$f"
    done

# --- password hashing and KDF (see item 9) ---
# `-i` because the .NET one-shot is `Rfc2898DeriveBytes.Pbkdf2`, PHP's constant is
# `PASSWORD_ARGON2ID` and C#'s package is `BCrypt.Net` — none of which the
# lowercase-only tokens matched.
rg -n --hidden -i 'bcrypt|scrypt|argon2|pbkdf2|Rfc2898DeriveBytes|password_hash\(|password_verify\(' .
# `--iglob`, not `-g`: ripgrep globs are case-sensitive, so `*pass*` did not match
# PasswordService.java and `*user*` did not match UserAuth.cs — the two file names
# this sweep exists to find. `-i` for the same reason on the pattern: Java writes
# `MessageDigest.getInstance("MD5")` and .NET `MD5.Create()`, neither of which is
# `md5(`. The three bare digest calls are `\b`-anchored because `-i` otherwise makes
# `sha256\(` a substring of the correct `new HMACSHA256(key)`.
rg -n --hidden -i '\bmd5\(|\bsha1\(|\bsha256\(|hashlib\.(md5|sha1|sha256)|createHash\(|MessageDigest\.getInstance\(|MD5\.Create\(|SHA1\.Create\(|Digest::MD5|Digest::SHA1|Insecure\.(MD5|SHA1)\.hash\(|CC_(MD5|SHA1)\(' \
  --iglob '*pass*' --iglob '*auth*' --iglob '*user*' --iglob '*login*' --iglob '*credential*' .

# --- randomness (see item 13) ---
# `rand()` only matched the zero-argument form, so Ruby `rand(1_000_000)` and PHP
# `rand(1, 99)` both read clean; `random.choice(` and `ThreadLocalRandom` are named
# in item 13's own generator list and were in no grep.
rg -n --hidden 'Math\.random\(|random\.(random|randint|choice|randrange|sample)\(|new Random\(|ThreadLocalRandom|math/rand|mt_rand\(|uniqid\(|array_rand\(|\brand\(|uuid1\(|\.setSeed\(' .

# --- key material in the tree (see item 14) ---
# `PGP ` matters because `.asc` is in the file-extension sweep below: a
# `BEGIN PGP PRIVATE KEY BLOCK` has the words in the wrong order for the group.
rg -n --hidden 'BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY' .
# GitHub issues five token prefixes, not one, and Slack four.
rg -n --hidden 'sk-ant-|sk-[A-Za-z0-9]{20,}|A(KIA|SIA)[0-9A-Z]{16}|gh[oprsu]_|github_pat_|xox[abpr]-|["'"'"']type["'"'"']\s*:\s*["'"'"']service_account' .
# Literal fallbacks on environment-backed secrets fail open when deployment
# configuration is missing. This is a candidate inventory across Python, Node,
# Ruby, PHP, Spring, .NET and shell-style expansion; read whether the binding is
# actually key-shaped and whether the fallback can reach a deployed path.
# Hex escapes keep both quote characters inside one portable shell pattern.
rg -n --hidden '(?i)os\.(environ\.get|getenv)\([^,\n]+,\s*[\x22\x27][^\x22\x27\n]+[\x22\x27]|process\.env\.[A-Za-z_][A-Za-z0-9_]*\s*(\|\||\?\?)\s*[\x22\x27][^\x22\x27\n]+[\x22\x27]|ENV\.fetch\([^,\n]+,\s*[\x22\x27][^\x22\x27\n]+[\x22\x27]|\$_ENV\[[^\]\n]+\]\s*\?\?\s*[\x22\x27][^\x22\x27\n]+[\x22\x27]|Environment\.GetEnvironmentVariable\([^)\n]+\)\s*\?\?\s*[\x22\x27][^\x22\x27\n]+[\x22\x27]|@Value\(\s*[\x22\x27]\$\{[^}:\n]+:[^}\n]+\}|(?:SECRET|TOKEN|KEY|PASSWORD|CREDENTIAL)[A-Za-z0-9_]*:-[^}\n]+' .
# Go's standard library has no default-taking getenv call; the fallback is
# normally a nearby empty check. Multiline mode surfaces that shape for reading.
rg -n --hidden -U --glob '**/*.go' 'os\.Getenv\([^\n]+\)(?:[^\n]*\n){0,3}\s*if\s+\w+\s*==\s*\x22\x22\s*\{?(?:[^\n]*\n){0,2}\s*\w+\s*=\s*\x22[^\x22\n]+\x22' .
# Both globs are `--iglob` and the negative one is last, and both of those are
# load-bearing. ripgrep applies last-match-wins *within* a case-sensitivity class,
# so the shipped order (negative `--glob` first, positive `-g` second) re-admitted
# every `node_modules/**/*.pem`, and mixing `--iglob` with a case-sensitive negative
# re-admits them too. Case-insensitive extensions are the other half: `-g '*.pem'`
# does not match a committed `SERVER.PEM`.
rg --hidden --iglob '*.pem' --iglob '*.key' --iglob '*.p12' --iglob '*.pfx' --iglob '*.jks' --iglob '*.keystore' --iglob '*.asc' --iglob '!**/node_modules/**' --files .
```

**Scala is activated but not assessed by these sweeps.** A `.scala` file whose name matches
`*{Cipher,Crypto,KeyStore,Signer,Verifier,Digest,Hmac}*` activates this lens, and Java/JCA calls in
that file may incidentally match the Java tokens above. That is not Scala coverage: this body has
no detector pair for ScalaCrypto, Akka/Pekko wrappers, Scala collection equality on MAC bytes, or
Scala-specific random/token construction. Until those APIs have executable vulnerable/clean
detectors, report matching Scala source as **not assessed** and hand it to a scoped manual pass.
An exit 1 from the sweeps above is not a clean Scala result.

Three of these are **absence** sweeps and that is deliberate. The dangerous shape for a MAC comparison is a missing call, for a `tls.Config` a missing field, and for a CBC/CTR ciphertext a missing MAC — in all three cases a grep keyed to the safe literal reads every vulnerable file as clean. None of the three is precise (a helper, a base class or a wrapper in another file satisfies all of them), so treat their output as a file list to read, not as findings.

Two corollaries, and both have to be checked before an empty result is written down as a clearance.

- **A clean result from an absence sweep is only as good as the construction list feeding it.** When a target stack is missing from the left-hand grep, the sweep reports that whole stack clean and says nothing while doing it. The left-hand lists above name the ecosystems they reach and the shapes they do not; where the repository's language is not among them, the honest report is "not covered", not "no findings".
- **An empty result is only a clearance if the sweep ran.** Both stages must have executed: run the first stage on its own and require exit status 0 or 1. A 2 (unsupported pattern on this engine) or a 127 (`rg` not on `PATH`, or `rg` present only as a shell alias) prints to stderr, leaves stdout empty, and is indistinguishable from a tree with nothing to find. State which of the two you established.

### 1. Nonce and IV construction (`symmetric-encryption-and-nonce-handling`)

**Start from the requirement, not from the code.** A nonce for GCM, CTR or ChaCha20 must be **unique per key**. It does not need to be random and it does not need to be secret. An IV for CBC must additionally be **unpredictable** to an adversary who can influence plaintext — that, and only that, is where predictability is itself the defect (CWE-329).

Four constructions, three of which are correct:

| Construction | Verdict | The condition that decides it |
|---|---|---|
| Fresh CSPRNG draw inside the encrypt call, 96-bit | **Correct, bounded.** NIST SP 800-38D §8.2.2. | Invocation count under one key; whether the draw is really per-call; whether the generator survives fork or snapshot. |
| Durable per-key monotonic counter, distinct fixed field per writer | **Correct.** NIST SP 800-38D §8.2.1. TLS 1.3 (RFC 8446 §5.3) and QUIC (RFC 9001 §5.3) both do this. | Whether the counter can reset, and whether two writers share a key with the same fixed field. |
| Nonce drawn once at module, class or object scope and reused across calls | **Broken.** Every message under that key shares a nonce. | None. This is the finding. |
| Nonce derived deterministically from message content or from a record field | **Broken for GCM** whenever the derived value can repeat across two *different* plaintexts. | Whether the source value is immutable and unique per key. A mutable `record_id`/`user_id` re-encrypted after an edit, a truncated hash, and any field an attacker can steer all repeat. Use AES-GCM-SIV, AES-SIV or Deoxys-II if determinism is required. |

**Get the derived-nonce failure the right way round**, because the wrong version is easy to write and a competent engineer will reject the report over it. Two *equal* plaintexts sealed under the same derived nonce produce a byte-identical ciphertext and tag: the plaintext XOR is zero, the GHASH-`H` recovery needs two *distinct* ciphertexts under one nonce, and this is exactly what a deterministic AEAD does on purpose. The catastrophic case is the other one — two **different** plaintexts landing on the same derived value. The three artifacts that produce it are a mutable id re-encrypted after an edit, a truncated hash (grindable to a collision at roughly 2⁴⁸ work for a 96-bit output), and any field the attacker supplies or influences.

**Equality leakage over a small plaintext domain is a separate defect with a separate fix.** Where the sealed values come from a short list — a boolean, a status flag, a small enumeration — equal plaintexts giving equal ciphertexts turns the ciphertext column into a one-to-one recoding of the plaintext column that yields to frequency analysis. That is a *deterministic-encryption* leak, not nonce reuse, and **AES-GCM-SIV does not fix it**: SIV is deterministic by design, so equal plaintexts still give equal ciphertexts. The fix is a fresh random nonce per record, or padding/bucketing the plaintext so the domain is not short.

**`crypto_aead_xchacha20poly1305` is not misuse-resistant and does not clear any of this.** Its 192-bit nonce removes the *random-collision* bound — a randomly drawn XNonce will not collide in practice, so the 2³² invocation cap below does not bind it. Under a **derived** nonce it fails exactly as ChaCha20-Poly1305 and AES-GCM do: the keystream repeats and the Poly1305 one-time key is recoverable from two messages. The misuse-resistant family is AES-GCM-SIV (RFC 8452), AES-SIV (RFC 5297) and Deoxys-II — those three and nothing else. Key commitment is a different property again: it binds a ciphertext to exactly one key, against the partitioning-oracle class, and buys nothing when the nonce repeats.

**A fresh CSPRNG nonce per call is the recommended default and must not be reported as a vulnerability.** The escalations that turn it into a finding are specific and each is visible in code:

- The key plausibly encrypts near **2³²** messages before rotating. SP 800-38D §8.3 caps invocations of the authenticated-encryption function under one key at 2³², which is also roughly where the birthday collision probability for a random 96-bit nonce reaches 2⁻³². Establish it from the call site: a per-request encryption on a hot path with a key loaded once from config and never rotated is the shape that gets there.
- The nonce is generated **outside** the per-message path — assigned at import, cached on the object, or passed in by the caller from a constant.
- The generator keeps state **in the process** and the process forks or is restored from a snapshot. This applies to a buffered userspace pool (an OpenSSL `RAND_bytes` pool in a build without fork detection, a long-lived `SecureRandom` instance, a userspace generator object seeded once). It does **not** apply to a call that reaches the kernel every time — `os.urandom` / `getrandom(2)`, Python `secrets`, Go `crypto/rand`. Establish which one the code is on before writing the finding; naming the wrong one is exactly how this check becomes a false positive.
- The mode's per-message plaintext limit is exceeded. GCM's counter is 32 bits, which caps one message at 2³⁹ − 256 bits (about 64 GiB). Streaming a file of unbounded size through a single GCM operation is a real defect and a separate one from nonce reuse.

```detector
match: |
  import os
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM

  KEY = bytes.fromhex(os.environ["DATA_KEY_HEX"])
  NONCE = os.urandom(12)          # drawn once at import; every ciphertext shares it

  def encrypt(plaintext: bytes, aad: bytes) -> bytes:
      return NONCE + AESGCM(KEY).encrypt(NONCE, plaintext, aad)
nomatch: |
  import os
  from cryptography.hazmat.primitives.ciphers.aead import AESGCM

  KEY = bytes.fromhex(os.environ["DATA_KEY_HEX"])

  def encrypt(plaintext: bytes, aad: bytes) -> bytes:
      nonce = os.urandom(12)      # fresh per call: SP 800-38D 8.2.2
      return nonce + AESGCM(KEY).encrypt(nonce, plaintext, aad)
```

```detector
match: |
  const crypto = require('node:crypto');

  const KEY = Buffer.from(process.env.DATA_KEY_HEX, 'hex');
  const IV = crypto.randomBytes(12);

  function seal(plaintext) {
    const c = crypto.createCipheriv('aes-256-gcm', KEY, IV);
    const ct = Buffer.concat([c.update(plaintext), c.final()]);
    return Buffer.concat([IV, c.getAuthTag(), ct]);
  }
nomatch: |
  const crypto = require('node:crypto');

  const KEY = Buffer.from(process.env.DATA_KEY_HEX, 'hex');

  function seal(plaintext) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
    const ct = Buffer.concat([c.update(plaintext), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), ct]);
  }
```

```detector
match: |
  import CryptoKit

  private let key = SymmetricKey(data: Data(keyBytes))
  private let nonce = AES.GCM.Nonce()  // drawn once; every call reuses it

  func seal(_ plaintext: Data) throws -> AES.GCM.SealedBox {
      return try AES.GCM.seal(plaintext, using: key, nonce: nonce)
  }
nomatch: |
  import CryptoKit

  private let key = SymmetricKey(data: Data(keyBytes))

  func seal(_ plaintext: Data) throws -> AES.GCM.SealedBox {
      // Omitting nonce asks CryptoKit for a fresh random nonce for this call.
      return try AES.GCM.seal(plaintext, using: key)
  }
```

**A counter nonce is not a finding on sight.** Report it only with a named failure condition. The two that exist:

- **The counter can reset.** It lives in memory, or in a file that is recreated, or it restarts at zero when the process restarts while the key does not. Look for where the counter is *loaded*, not where it is incremented: a counter initialized to `0` in a constructor beside a key read from config is the reset case.
- **Two writers share a key and the same fixed field.** Horizontal replicas, a forked worker pool, or a Lambda-style function with a shared KMS-wrapped data key, each running its own counter from the same start. SP 800-38D §8.2.1 requires the fixed field to distinguish the writers; if every replica's nonce is `counter‖0000`, they collide immediately.

```detector
match: |
  class Sealer:
      def __init__(self, key: bytes):
          self._key = key
          self._counter = 0          # resets on every process start; key does not

      def seal(self, plaintext: bytes) -> bytes:
          nonce = struct.pack("<Q", self._counter) + b"\x00\x00\x00\x00"
          self._counter += 1
          return nonce + AESGCM(self._key).encrypt(nonce, plaintext, None)
nomatch: |
  class Sealer:
      def __init__(self, key: bytes, writer_id: int, counter_store: CounterStore):
          self._key = key
          # 32-bit fixed field distinguishes writers; 64-bit invocation field is
          # durable and fetch-and-incremented, so a restart cannot rewind it.
          self._fixed = struct.pack("<I", writer_id)
          self._counter = counter_store

      def seal(self, plaintext: bytes) -> bytes:
          nonce = self._fixed + struct.pack("<Q", self._counter.next_for(self._key))
          return nonce + AESGCM(self._key).encrypt(nonce, plaintext, None)
```

**CBC is the one place predictability is the bug.** A zero IV, a counter IV, a timestamp IV or an IV reused across messages in CBC enables chosen-plaintext recovery (CWE-329). `new IvParameterSpec(new byte[16])` is the canonical Java spelling and it is still common.

```detector
match: |
  Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
  cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(new byte[16]));
  byte[] ct = cipher.doFinal(plaintext);
nomatch: |
  byte[] iv = new byte[12];
  SecureRandom.getInstanceStrong().nextBytes(iv);
  Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
  cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
  byte[] ct = cipher.doFinal(plaintext);
```

**An API that takes no nonce argument is usually the safe one.** `Fernet.encrypt`, libsodium `crypto_secretbox_easy`, Tink's `Aead.encrypt`, the AWS Encryption SDK, `age`, Rails `MessageEncryptor`, Apex `Crypto.encryptWithManagedIV` all draw a fresh nonce internally and prepend it. Demanding an IV parameter pushes the team toward the API that can be got wrong. See Known false positives (1).

**In Apex, read both the method and `algorithmName`.** For the unhyphenated CBC names `AES128`, `AES192` and `AES256`, `Crypto.encryptWithManagedIV(algorithmName, key, clearText)` draws a fresh 16-byte IV per call and prepends it to the ciphertext, while `Crypto.encrypt(algorithmName, key, iv, clearText)` takes the IV from the caller. A class constant, `Blob.valueOf('0000000000000000')`, or a value derived from the record being sealed is the CBC rule above (CWE-329); the CBC mode uses PKCS7 padding. Summer '25 (API 64.0) added AES-GCM overloads: the [Salesforce release note](https://help.salesforce.com/s/articleView?id=release-notes.rn_256_gcm_p1363.htm&language=en_US&release=256&type=5) documents `AES256-GCM`, `aaData`, and availability only in the named editions with a Shield or Shield Platform Encryption license. Read the class's `-meta.xml` API version and the algorithm argument. The repository does not prove the org's license, so state that availability check rather than assuming either CBC-only or GCM-capable execution.

**Apex CBC does not authenticate; Apex GCM does.** An unhyphenated `AES128`/`AES192`/`AES256` ciphertext is item 3's unauthenticated-ciphertext finding unless a `Crypto.generateMac` on the path covers the version byte, the IV and the ciphertext and is verified before anything unpads or parses. `Crypto.encryptWithManagedIV('AES256', ...)` closes the CBC IV question and only that question. By contrast, a supported `AES*-GCM` call is AEAD and clears the separate-MAC requirement; do not flag it merely because there is no `Crypto.generateMac`. Where `algorithmName` is a variable, trace its values and verify the API-version/license prerequisite before grading either way.

```detector
match: |
  public with sharing class NoteSealer {
      private static final Blob IV = Blob.valueOf('0123456789abcdef');   // 16 bytes, every record

      public static String seal(String plaintext) {
          Blob ct = Crypto.encrypt('AES256', keyFromSetting(), IV, Blob.valueOf(plaintext));
          return EncodingUtil.base64Encode(ct);       // nothing authenticates this either
      }
  }
nomatch: |
  public with sharing class NoteSealer {
      private static final Integer V = 1;

      public static String seal(String plaintext) {
          // managed IV: drawn per call by the platform and prepended to the ciphertext
          Blob ct = Crypto.encryptWithManagedIV('AES256', encKey(), Blob.valueOf(plaintext));
          Blob framed = EncodingUtil.base64Decode(
              EncodingUtil.base64Encode(Blob.valueOf(String.valueOf(V))) +
              EncodingUtil.base64Encode(ct));
          // This is the unhyphenated CBC compatibility path, so the MAC is not
          // optional; it covers the version, managed IV and ciphertext.
          Blob tag = Crypto.generateMac('hmacSHA256', framed, macKey());
          return EncodingUtil.base64Encode(framed) + '.' + EncodingUtil.base64Encode(tag);
      }
  }
```

### 2. Mode and primitive selection (`legacy-hash-and-cipher-primitives`)

**ECB.** The grep that matters is not the one the source material named. `Crypto.AES` does not exist in any Python package; the real constructors are below, and the highest-yield catch of all is the Java transformation string with no mode, which resolves to ECB silently (CWE-327).

```bash
# `CipherMode.ECB` is .NET's spelling and matched nothing here or in §0 before now;
# the algorithm string is written with single quotes at least as often as double, so
# `"aes-256-ecb"` missed every JavaScript instance of it; and Rust's is `ecb::`.
rg -n --hidden -i 'AES\.new\([^)]*MODE_ECB|modes\.ECB\(|Cipher\.getInstance\("AES"\)|Cipher\.getInstance\("AES/ECB|["'"'"']aes-[0-9]+-ecb|MODE_ECB|CipherMode\.ECB|ecb::|kCCOptionECBMode|kCCModeECB' .
```

`Cipher.getInstance("AES")` takes the provider's default mode and padding. On the SunJCE provider that is `AES/ECB/PKCS5Padding`. Nothing in the source line says ECB, which is why it survives review.

```detector
match: |
  Cipher cipher = Cipher.getInstance("AES");
  cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"));
  byte[] ct = cipher.doFinal(record.getBytes(StandardCharsets.UTF_8));
nomatch: |
  Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
  cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(keyBytes, "AES"),
              new GCMParameterSpec(128, iv));
  byte[] ct = cipher.doFinal(record.getBytes(StandardCharsets.UTF_8));
```

```detector
match: |
  from Crypto.Cipher import AES
  cipher = AES.new(key, AES.MODE_ECB)
  blob = cipher.encrypt(pad(profile_json.encode(), AES.block_size))
nomatch: |
  from Crypto.Cipher import AES
  cipher = AES.new(key, AES.MODE_GCM)          # fresh nonce drawn by the library
  ct, tag = cipher.encrypt_and_digest(profile_json.encode())
  blob = cipher.nonce + tag + ct
```

**A single-block ECB operation is not the ECB bug.** ECB is the building block for CMAC, AES-KW key wrapping, AES-SIV, the GCM/CTR counter block, and format-preserving encryption; Go's API *requires* `aes.NewCipher` to produce a `cipher.Block` before `cipher.NewGCM(block)`. The bug is ECB over multi-block, attacker-visible, low-diversity plaintext. Check the plaintext length and the surrounding mode. See Known false positives (6).

**MD5 and SHA-1: name the broken property, or do not file it.** What is broken is collision resistance, and SHA-1 chosen-prefix collisions are practical. That is load-bearing only where an adversary supplies the input and the digest is trusted for identity or integrity. HMAC-SHA1 as a MAC has no practical break and is still mandated by live vendor APIs and by TOTP. Report it for password storage, signature or certificate verification, integrity of untrusted content, and dedup where a collision lets one tenant overwrite another's object. A bare "MD5 found" is the fastest way to lose the reader. See Known false positives (4).

**Ciphers that are simply out.** DES and 2-key 3DES (64-bit block, Sweet32), RC4, and any `NULL`/`EXPORT`/anonymous suite. `openssl_encrypt($data, 'aes-256-cbc', ...)` is not in this class — with a hand-rolled MAC, or with no MAC at all, it belongs to item 3.

### 3. Composition and ordering (`symmetric-encryption-and-nonce-handling`)

- **First ask whether anything authenticates the ciphertext at all.** This is the most common symmetric-crypto defect in application code and it has no literal of its own — the defect is the *absence* of a MAC, so every grep keyed to a bad literal reports it clean. `openssl_encrypt($d, 'aes-256-cbc', $k, 0, $iv)` returned raw; `createCipheriv('aes-256-cbc', …)` with the result handed straight to a cookie; `Cipher.getInstance("AES/CBC/PKCS5Padding")` in a class with no `Mac` in it; an unhyphenated `Crypto.encryptWithManagedIV('AES256', …)` CBC call in a `.cls` with no `Crypto.generateMac`. The IV can be a perfectly good random draw and the CBC finding still stands. A supported Apex `AES*-GCM` call is the counterexample: it authenticates internally and must not be sent through this absence rule. Unauthenticated ciphertext is malleable — under CBC an attacker who can flip IV bits flips the first plaintext block, and under CTR they flip any bit they like — and on a decrypt path that unpads or parses attacker-supplied input it is a padding oracle waiting for a probe. Run the absence sweep in §0 and read every file it returns; then check whether a MAC exists in a *helper* the file calls before writing the finding.
- **Prefer AEAD.** AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305, XChaCha20-Poly1305 do encrypt-then-MAC internally and bind associated data. Choosing one of these is what makes the paragraph above unnecessary.
- **If a MAC does exist and it is hand-rolled, encrypt-then-MAC is the only safe composition.** MAC-then-encrypt and encrypt-and-MAC have known failures.
- **The MAC must cover the IV and every framing field**, not just the ciphertext. A MAC over the ciphertext alone lets an attacker swap the IV, which flips the first block under CBC.
- **Verify the tag before doing anything with the plaintext** — before unpadding, before parsing, before logging. Decrypt-then-check leaks a padding or format oracle (this is what makes CBC padding oracles exploitable).
- **Two keys, not one.** A hand-rolled scheme must derive separate encryption and MAC keys from the master via HKDF (item 10).

```detector
match: |
  def open_blob(blob: bytes) -> dict:
      iv, ct, tag = blob[:16], blob[16:-32], blob[-32:]
      cipher = Cipher(algorithms.AES(ENC_KEY), modes.CBC(iv)).decryptor()
      padded = cipher.update(ct) + cipher.finalize()
      record = json.loads(unpad(padded))              # parsed before the MAC check
      if not hmac.compare_digest(tag, hmac.new(MAC_KEY, ct, sha256).digest()):
          raise ValueError("bad tag")
      return record
nomatch: |
  def open_blob(blob: bytes) -> dict:
      nonce, ct = blob[:12], blob[12:]
      # AESGCM.decrypt verifies the tag and raises before returning any plaintext,
      # and the nonce is bound in as associated data rather than left unauthenticated.
      plaintext = AESGCM(ENC_KEY).decrypt(nonce, ct, b"blob-v1")
      return json.loads(plaintext)
```

```detector
match: |
  function sealCookie(payload) {
    const iv = crypto.randomBytes(16);                  // the IV is fine
    const c = crypto.createCipheriv('aes-256-cbc', KEY, iv);
    const ct = Buffer.concat([c.update(JSON.stringify(payload)), c.final()]);
    // nothing authenticates this: no HMAC here, and none anywhere in the module
    return Buffer.concat([iv, ct]).toString('base64url');
  }
nomatch: |
  function sealCookie(payload) {
    const iv = crypto.randomBytes(12);
    const c = crypto.createCipheriv('aes-256-gcm', KEY, iv);
    c.setAAD(iv);                                       // the IV is inside the tag
    const ct = Buffer.concat([c.update(JSON.stringify(payload)), c.final()]);
    return Buffer.concat([iv, c.getAuthTag(), ct]).toString('base64url');
  }
```

### 4. HMAC, constant-time comparison and freshness (`hmac-and-constant-time-comparison`)

**Use HMAC, not `H(secret ‖ msg)`.** SHA-1, SHA-256 and SHA-512 are Merkle–Damgård and are length-extendable: an attacker who has `H(secret ‖ msg)` and the length of `secret` can compute `H(secret ‖ msg ‖ padding ‖ suffix)` without the secret. SHA-512/256, SHA-3 and BLAKE2 are not, but the fix is HMAC either way.

**`Crypto.generateDigest` is Apex's spelling of that mistake.** Apex's keyed digest primitive is `Crypto.generateMac('hmacSHA256', input, key)`; `Crypto.generateDigest('SHA-256', ...)` is unkeyed, and a secret concatenated into its input is `H(secret ‖ msg)` with the same length-extension property. Apex hides the concatenation in the `Blob` conversion — `Blob.valueOf(secret + payload)`, or two `EncodingUtil.base64Encode` results joined as strings — so it reads as a hashing call rather than as a composition. The algorithm name is the tell: an `hmacSHA*` string belongs to `generateMac`, and a `SHA-256` string on a line that also mentions a key or a secret is this finding.

**Constant-time comparison (CWE-208).** The API per language, and the trap in each:

| Language | Use | Trap |
|---|---|---|
| Python | `hmac.compare_digest` | `==` on bytes short-circuits. |
| Node | `crypto.timingSafeEqual` | Throws `RangeError` on unequal lengths, so it needs a guard: either HMAC both sides to a fixed width first, or compare lengths in front of it. Against an HMAC or a digest the length guard leaks nothing — the expected width is a public constant and the submitted value is the attacker's own input. A length comparison is a leak only where the *secret's* length is itself not public. A bare `try/catch` returning `false` is worse than the guard, because it hides a real `RangeError`. |
| Go | `hmac.Equal` (MACs) or `subtle.ConstantTimeCompare` | `hmac.Equal` is what the `crypto/hmac` docs prescribe for MAC comparison and is the form you will actually meet; it wraps `ConstantTimeCompare`. Both return early if lengths differ — the length check itself is not constant-time. |
| Java | `MessageDigest.isEqual` | `Arrays.equals` and `String.equals` are not constant-time. |
| PHP | `hash_equals` | `===` is not. |
| .NET | `CryptographicOperations.FixedTimeEquals` | `SequenceEqual` is not. |
| Ruby | `ActiveSupport::SecurityUtils.fixed_length_secure_compare` or `.secure_compare` | The variable-length form hashes first. In the §0 clearing pattern both names are anchored to the full `ActiveSupport::SecurityUtils.` namespace so a project-local helper with the same suffix cannot clear the file. |
| Rust | the `subtle` crate's `ConstantTimeEq` | `==` on `&[u8]` short-circuits. |
| Swift | `HMAC<Hash>.isValidAuthenticationCode(_:authenticating:using:)` | Computing `authenticationCode(for:using:)` and comparing the returned bytes or `Data` with `==` short-circuits. The validating API performs the comparison; use it instead of clearing on a plausible helper name. |
| Apex | `Crypto.areEqualConstantTime(Blob, Blob)` | Prefer the built-in comparator and keep both operands as `Blob`; Salesforce [documents it as the constant-time comparison API](https://developer.salesforce.com/blogs/2021/12/encryption-and-signature-techniques-in-apex). `==`, `!=`, `String.equals`, ordinary `Blob` equality and `equalsIgnoreCase` are not substitutes. A legacy project-local helper can still clear only after the body and request-path call are read. |

**A timing finding needs all four of:** an attacker-supplied guess, a byte-by-byte comparison against a secret, effectively unlimited attempts, and a signal that survives network jitter. Comparing two values the server computed itself leaks nothing. See Known false positives (3).

**On Apex, prefer `Crypto.areEqualConstantTime` and reserve the manual clearance for legacy local helpers.** For the built-in path, confirm that the request signature is decoded to `Blob` and that the call compares it with the server-computed MAC; a token in a comment is not a clearance. A grep still cannot distinguish a correct project-local accumulator from a broken one, so when a local helper remains, open its body and check all four before clearing it. (1) It compares lengths **first** and returns on a mismatch, before touching a byte; against a MAC or a digest that leaks nothing, because the expected width is a public constant. (2) It then iterates over **every** byte of the operands, not to the first difference. (3) It accumulates differences into one variable with `^` and `|=` and contains no `break`, no `return` and no branch inside the loop. (4) The verifier under review actually calls it on the value that arrived in the request — not on a value it recomputed. Quote the helper's file and line when you clear on it, and recommend migration to the built-in. Expect several legacy copies: enumerate them with §0's Apex arm and read each — the finding is the copy that drifted, or the verifier that calls neither the built-in nor a verified helper.

```detector
match: |
  @RestResource(urlMapping='/inbound/status/*')
  global with sharing class StatusReceiver {
      @HttpPost
      global static void handle() {
          String given = RestContext.request.headers.get('X-Provider-Signature');
          Blob mac = Crypto.generateMac('hmacSHA256',
              Blob.valueOf(RestContext.request.requestBody.toString()), signingKey());
          // bare == on a request signature: short-circuits on the first byte
          if (given != EncodingUtil.base64Encode(mac)) {
              RestContext.response.statusCode = 401;
              return;
          }
          Router.dispatch(RestContext.request.requestBody);
      }
  }
nomatch: |
  @RestResource(urlMapping='/inbound/status/*')
  global with sharing class StatusReceiver {
      @HttpPost
      global static void handle() {
          Blob given = EncodingUtil.base64Decode(
              RestContext.request.headers.get('X-Provider-Signature'));
          Blob mac = Crypto.generateMac('hmacSHA256',
              Blob.valueOf(RestContext.request.requestBody.toString()), signingKey());
          if (!Crypto.areEqualConstantTime(given, mac)) {
              RestContext.response.statusCode = 401;
              return;
          }
          Router.dispatch(RestContext.request.requestBody);
      }
  }
```

```detector
match: |
  @app.post("/webhooks/provider")
  def receive():
      expected = hmac.new(WEBHOOK_SECRET, request.get_data(), hashlib.sha256).hexdigest()
      if request.headers.get("X-Signature") != expected:
          abort(401)
      return handle(request.get_json())
nomatch: |
  @app.post("/webhooks/provider")
  def receive():
      expected = hmac.new(WEBHOOK_SECRET, request.get_data(), hashlib.sha256).hexdigest()
      if not hmac.compare_digest(request.headers.get("X-Signature", ""), expected):
          abort(401)
      return handle(request.get_json())
```

```detector
match: |
  function verify(req, signature) {
    const expected = crypto.createHmac('sha256', SECRET)
      .update(JSON.stringify(req.body))        // re-serialized, not the raw bytes
      .digest('hex');
    return expected === signature;
  }
nomatch: |
  function verify(rawBody, signature) {
    const expected = crypto.createHmac('sha256', SECRET).update(rawBody).digest();
    const given = Buffer.from(signature, 'hex');
    // `expected` is a fixed-width digest; `given` is decoded from the attacker's
    // header and is any length, so the guard is what stops timingSafeEqual
    // throwing. It leaks nothing: the digest width is a public constant and the
    // submitted value is the attacker's own.
    return given.length === expected.length && crypto.timingSafeEqual(given, expected);
  }
```

```detector
match: |
  import CryptoKit

  func verify(body: Data, signature: Data, key: SymmetricKey) -> Bool {
      let expected = HMAC<SHA256>.authenticationCode(for: body, using: key)
      return Data(expected) == signature
  }
nomatch: |
  import CryptoKit

  func verify(body: Data, signature: Data, key: SymmetricKey) -> Bool {
      return HMAC<SHA256>.isValidAuthenticationCode(
          signature,
          authenticating: body,
          using: key
      )
  }
```

**Verify over the raw bytes.** `JSON.stringify(req.body)` and `json.dumps(request.json)` re-serialize; key order and whitespace change and the MAC no longer describes what arrived. Worse, a verifier that re-serializes will accept a body that differs from the signed one wherever the round trip is lossy. Capture the raw body before the JSON middleware.

**A MAC proves authenticity, not freshness.** The signed string must bind a timestamp, and the verifier must actually check it (CWE-294). Report here: a signature scheme with no timestamp in the signed material, a timestamp present in the header but never compared, or a tolerance window measured in hours. The *handler* half — an idempotency key, a replay cache, a side effect that lands before the 401 — is `webhook-handler-integrity` in web-and-api. Hand it over with the file and line.

```detector
match: |
  ts = request.headers["X-Timestamp"]
  signed = f"{ts}.{request.get_data(as_text=True)}"
  if not hmac.compare_digest(sign(signed), request.headers["X-Signature"]):
      abort(401)
  return handle(request.get_json())
nomatch: |
  ts = int(request.headers["X-Timestamp"])
  if abs(time.time() - ts) > 300:
      abort(401)
  signed = f"{ts}.{request.get_data(as_text=True)}"
  if not hmac.compare_digest(sign(signed), request.headers["X-Signature"]):
      abort(401)
  return handle(request.get_json())
```

### 5. JWT, JWS and JWKS verification (`jwt-jws-and-jwks-verification`)

This lens owns JWT verification outright — nine other lenses defer it here — so the checks live in full below rather than by reference.

**The grep list, corrected.** PyJWT's `verify=False` was removed as the switch in PyJWT 2.0; a grep for it reports clean on every modern Python codebase. The shapes that are current (CWE-347):

```bash
# Python — the explicit disable, and the missing pin.
# Read the pinned PyJWT version first: from 2.0 on, decode() *raises* when
# algorithms= is absent and verify_signature is on, so a missing pin there is a
# crash, not a bypass. The live Python shape is the explicit disable below.
# The quote is a character class, not a literal `"`: Python writes this dict key
# single-quoted at least as often, and `verify_signature"?` never matched
# `{'verify_signature': False}`.
rg -n --hidden 'verify_signature["'"'"']?\s*:\s*[Ff]alse|options\s*=\s*\{[^}]*verify' .
# Three flags and one token on the next line, each doing something different, none
# of them optional:
#   -U         lets a single match span more than one line. It does *not* make `.`
#              match a newline — that is --multiline-dotall — which is why the
#              pattern crosses lines with `[\s\S]` and not with `.`. Anyone
#              "simplifying" `[\s\S]` to `.` on the strength of -U turns this into a
#              sweep that still matches single-line calls, silently stops matching
#              multi-line ones, and exits 0 while doing it.
#   --pcre2    because the negative lookahead is not supported by ripgrep's default
#              engine. Without it this line does not miss, it *errors* (`regex parse
#              error: look-around … is not supported`) and returns nothing, on a
#              vulnerable and a safe file alike. It also assumes a ripgrep with
#              PCRE2 compiled in: `rg --version` prints a `features:` line
#              containing `+pcre2` on a build that has it. Read that line rather
#              than assuming — what a build without it does with this flag is not
#              something this lens establishes, and any error from this line is an
#              error, never a clean sweep.
#   [=:]       the lookahead is `algorithms\s*[=:]`, not the bare word, so a call
#              that merely mentions "algorithms" in a comment inside the span
#              (e.g. "# algorithms intentionally omitted") does not suppress its
#              own match.
rg -nU --hidden --pcre2 'jwt\.decode\((?:(?!algorithms\s*[=:])[\s\S]){0,200}?\)' .   # decode with no algorithms=

# Node — decode() is not verify(), and the algorithms option
rg -n --hidden 'jwt\.decode\(|jsonwebtoken.*decode' .
rg -nU --hidden --pcre2 'jwt\.verify\((?:(?!algorithms\s*[=:])[\s\S]){0,200}?\)' .

# Go — the unverified parser, and a keyfunc that never checks the method.
# `jwt\.Parse` carries no closing paren on purpose: golang-jwt's most-used entry
# point is ParseWithClaims, which `jwt\.Parse\(` matches nowhere. Same for the
# parser-object and request-helper spellings.
rg -n --hidden 'ParseUnverified|jwt\.Parse|jwt\.NewParser\(|ParseFromRequest\(' .
rg --hidden --files-with-matches 'jwt\.Parse|jwt\.NewParser\(|ParseFromRequest\(' . \
  | while IFS= read -r f; do
      rg -q 'WithValidMethods|SigningMethodHMAC|SigningMethodRSA|SigningMethodECDSA|SigningMethodEd|token\.Method|\.Method\.\(' "$f" || printf '%s\n' "$f"
    done

# The other four decode-without-verify entry points, one per ecosystem: java-jwt
# and Ruby (`JWT.decode(`), firebase/php-jwt (`JWT::decode(`), nimbus-jose-jwt
# (`SignedJWT.parse(`), .NET (`ReadJwtToken(`). Each returns claims with nothing
# checked, and three of them do not contain the string `JWT.decode(`.
rg -n --hidden 'JWT\.decode\(|JWT::decode\(|SignedJWT\.parse\(|ReadJwtToken\(' .

# the header fields that fetch a key from wherever the token says
rg -n --hidden -i '"jku"|"x5u"|jku|x5u' .
```

The two negative-lookahead patterns above are triage aids, not proofs: a call spanning more than the window, or one that passes options through a variable, will not match. Read every `jwt.decode` / `jwt.verify` / `jwt.Parse` / `ParseWithClaims` call site the first grep returns.

**`decode` is not `verify`.** In `jsonwebtoken`, `jwt.decode()` base64-decodes and returns the claims without checking anything. In auth0's `java-jwt`, `JWT.decode()` is the same. In `jose`, `decodeJwt()` is the same. Every one of these is a complete authentication bypass when it stands in for the verifying call, and every one of them reads like a parse.

```detector
match: |
  const jwt = require('jsonwebtoken');

  function currentUser(req) {
    const token = req.headers.authorization.slice('Bearer '.length);
    const claims = jwt.decode(token);          // no signature check at all
    return { id: claims.sub, roles: claims.roles };
  }
nomatch: |
  const jwt = require('jsonwebtoken');

  function currentUser(req) {
    const token = req.headers.authorization.slice('Bearer '.length);
    const claims = jwt.verify(token, PUBLIC_KEY, {
      algorithms: ['RS256'],
      issuer: 'https://issuer.example.com/',
      audience: 'api://orders',
    });
    return { id: claims.sub, roles: claims.roles };
  }
```

**Pin the algorithm, and pin it to one class.** `alg: none` and the RS256→HS256 substitution are the same bug seen twice: the token tells the verifier which key interpretation to use. In the HS256 case the attacker signs with the *exact PEM bytes of the public key* as the HMAC secret. The fix is an explicit allowlist, and the allowlist must not mix an asymmetric algorithm with a symmetric one.

**Pinning is unconditional advice; a missing pin is a version-dependent finding.** Read the library and the version in the manifest before grading one. PyJWT ≥ 2 raises when `algorithms=` is absent rather than verifying, `jsonwebtoken` ≥ 9 derives the permitted family from the key type, and golang-jwt v5 offers `WithValidMethods` — on those versions an unpinned call fails closed, and filing it Critical is the false positive. What stays a finding at full weight on any version: a list that mixes classes or contains `"none"`, a verifier that dispatches on the header's own `alg`, a Go keyfunc that returns a key without looking at `t.Method`, and `options={"verify_signature": False}`.

```detector
match: |
  import jwt

  def claims_from(token: str) -> dict:
      # no algorithms= pin, and signature verification switched off outright;
      # in PyJWT >= 2 disabling verify_signature also disables exp/aud/iss checks
      return jwt.decode(token, options={"verify_signature": False})
nomatch: |
  import jwt

  def claims_from(token: str) -> dict:
      return jwt.decode(
          token,
          key=PUBLIC_KEY,
          algorithms=["RS256"],
          audience="api://orders",
          issuer="https://issuer.example.com/",
      )
```

```detector
match: |
  token, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
      return signingKey, nil          // method never inspected: HS256 is accepted
  })
  if err != nil || !token.Valid {
      return nil, errUnauthorized
  }
nomatch: |
  token, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
      if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
          return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
      }
      return rsaPublicKey, nil
  }, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(issuer),
     jwt.WithAudience(audience))
  if err != nil || !token.Valid {
      return nil, errUnauthorized
  }
```

**Key resolution is the second half, and it is where remote fetches hide.** `jku` and `x5u` name a URL *in the token*; honoring either lets the attacker supply the verification key. `kid` is attacker-controlled too — it has been used for path traversal and SQL injection into key lookup. The rules:

- Resolve keys only from a **statically configured** JWKS URI or key set. Ignore `jku`, `x5u` and `jwk` in the header.
- Treat `kid` as an opaque lookup key into that set. Never concatenate it into a path or a query.
- Cache JWKS, respect rotation, and **bound the refetch**: an unknown `kid` must not trigger an unrated outbound request, or the token becomes a DoS and SSRF primitive.

```detector
match: |
  def key_for(header):
      # the token chooses where the key comes from
      jwks = requests.get(header["jku"], timeout=5).json()
      return next(k for k in jwks["keys"] if k["kid"] == header["kid"])
nomatch: |
  _JWKS = PyJWKClient(settings.JWKS_URI, cache_keys=True, max_cached_keys=16,
                      lifespan=3600)

  def key_for(token):
      # JWKS_URI is configuration; kid is only an index into what it returned
      return _JWKS.get_signing_key_from_jwt(token).key
```

**Claims are not optional.** Verify `exp`, `nbf`, `iss` and `aud` explicitly, and do not rely on a library default to do it — several verify `exp` only, and PyJWT skips all of them when `verify_signature` is off. For an OIDC `id_token` also verify `nonce` against the value the client sent, and `azp` where multiple audiences are present.

### 6. SAML assertion validation (`saml-assertion-validation`)

Rarer than JWT and worse when wrong, because the parser and the verifier are two different pieces of code looking at the same document.

- **Signature wrapping.** The attacker adds a second `<Assertion>`, or moves the signed one into a decoy position, so the element the signature covers is not the element the application reads. The check is not "is there a `<Signature>`" — it is *does the signature reference the ID of the assertion whose attributes we consume*. Verify the reference URI, verify the assertion is signed (not merely the response), and resolve the element by that reference rather than by an XPath the attacker can also satisfy.
- **XXE.** SAML documents are XML from an untrusted party. Disable external entities and DTD loading in whatever parser the library uses.
- **Algorithms.** Require SHA-256 or better for the digest and signature; reject `rsa-sha1` and `dsa-sha1`. Reject unsigned assertions outright.
- **`InResponseTo`** must match a request this SP actually issued and has not yet consumed. Unsolicited responses must be rejected unless IdP-initiated SSO is a deliberate feature, in which case say so.
- **Audience restriction** must name this SP. **`NotBefore`/`NotOnOrAfter`** must be enforced. **Assertion IDs must be cached** for the validity window so one assertion cannot be replayed.

```detector
match: |
  parser = etree.XMLParser(resolve_entities=True, load_dtd=True)
  doc = etree.fromstring(base64.b64decode(saml_response), parser)
  assertion = doc.find(".//{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
  if doc.find(".//{http://www.w3.org/2000/09/xmldsig#}Signature") is None:
      raise ValueError("unsigned")
  return attributes_of(assertion)
nomatch: |
  parser = etree.XMLParser(resolve_entities=False, load_dtd=False,
                           no_network=True, huge_tree=False)
  doc = etree.fromstring(base64.b64decode(saml_response), parser)
  # Resolve the assertion BY the id the signature references, so a second
  # unsigned Assertion elsewhere in the document cannot be the one we read.
  signed_id = verify_signature(doc, idp_cert, allowed_digest={"sha256", "sha384"})
  assertion = doc.find(
      f".//{{urn:oasis:names:tc:SAML:2.0:assertion}}Assertion[@ID='{signed_id}']")
  require_audience(assertion, settings.SP_ENTITY_ID)
  require_in_response_to(assertion, pending_request_ids)
  require_unseen(assertion.get("ID"))
  return attributes_of(assertion)
```

```detector
match: |
  {
    "security": {
      "wantAssertionsSigned": false,
      "wantMessagesSigned": false,
      "rejectUnsolicitedResponsesWithInResponseTo": false,
      "signatureAlgorithm": "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
    }
  }
nomatch: |
  {
    "security": {
      "wantAssertionsSigned": true,
      "wantMessagesSigned": true,
      "rejectUnsolicitedResponsesWithInResponseTo": true,
      "signatureAlgorithm": "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
      "digestAlgorithm": "http://www.w3.org/2001/04/xmlenc#sha256"
    }
  }
```

### 7. OAuth 2.0 and OIDC flow correctness (`oauth-oidc-flow-correctness`)

Graded against RFC 9700 (Best Current Practice for OAuth 2.0 Security) and RFC 7636 (PKCE).

- **PKCE with `S256`.** RFC 9700 asks for PKCE on the authorization-code flow generally, not only for public clients. `code_challenge_method=plain` is not PKCE in any useful sense — the verifier is the challenge. The finding is strongest where the client is public and the redirect can be claimed by another app (item below).
- **`state`, generated per request from a CSPRNG, stored server-side or in a signed cookie, and *compared* on the callback.** A `state` that is generated and never checked is the common shape; grep for the callback handler, not the redirect builder.
- **`nonce`** for OIDC, echoed into `id_token` and compared. `state` and `nonce` are not interchangeable.
- **Redirect URI matching must be exact string comparison** against a registered list. `startswith`, a regex, a suffix check, or allowing a caller-supplied path or query is an open-redirect-into-token-theft. (The generic `open-redirect` slug is web-and-api's; a redirect that carries an authorization code or token is this lens's.)
- **Authorization code single-use**, short-lived, and bound to the client and the PKCE verifier.
- **Refresh-token rotation** — a new refresh token per redemption, with reuse detection that revokes the family.
- **No implicit flow.** `response_type=token` and `response_type=id_token token` put credentials in the fragment. Use code plus PKCE.
- **`iss` on the callback** (RFC 9207) where the client talks to more than one authorization server, which is the mix-up defense.

```detector
match: |
  @app.get("/oauth/callback")
  def callback():
      code = request.args["code"]
      # state read but never compared; no code_verifier sent
      token = requests.post(TOKEN_URL, data={
          "grant_type": "authorization_code",
          "code": code,
          "client_id": CLIENT_ID,
          "redirect_uri": request.args.get("redirect_uri", DEFAULT_REDIRECT),
      }).json()
      return login(token["access_token"])
nomatch: |
  @app.get("/oauth/callback")
  def callback():
      expected = session.pop("oauth_state", None)
      if not expected or not secrets.compare_digest(expected, request.args.get("state", "")):
          abort(400)
      verifier = session.pop("pkce_verifier")
      token = requests.post(TOKEN_URL, data={
          "grant_type": "authorization_code",
          "code": request.args["code"],
          "client_id": CLIENT_ID,
          "redirect_uri": REGISTERED_REDIRECT_URI,   # fixed, never from the request
          "code_verifier": verifier,
      }).json()
      return login(token["access_token"])
```

```detector
match: |
  def redirect_uri_allowed(candidate: str) -> bool:
      return any(candidate.startswith(r) for r in REGISTERED_REDIRECT_URIS)
nomatch: |
  def redirect_uri_allowed(candidate: str) -> bool:
      return candidate in REGISTERED_REDIRECT_URIS
```

```detector
match: |
  authorize_url = (
      f"{AUTH_URL}?response_type=token"
      f"&client_id={CLIENT_ID}&redirect_uri={REDIRECT}"
      f"&code_challenge={verifier}&code_challenge_method=plain"
  )
nomatch: |
  verifier = secrets.token_urlsafe(64)
  challenge = base64.urlsafe_b64encode(
      hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
  session["pkce_verifier"] = verifier
  session["oauth_state"] = state = secrets.token_urlsafe(32)
  authorize_url = (
      f"{AUTH_URL}?response_type=code"
      f"&client_id={CLIENT_ID}&redirect_uri={REGISTERED_REDIRECT_URI}"
      f"&state={state}&nonce={nonce}"
      f"&code_challenge={challenge}&code_challenge_method=S256"
  )
```

### 8. TLS and certificate validation (`tls-and-certificate-validation`)

**Every switch that turns validation off, by language** (CWE-295). All of these appear in production code with a comment saying "temporary":

| Language / stack | The switch |
|---|---|
| Go | `tls.Config{InsecureSkipVerify: true}` |
| Node | `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0` |
| Python | `requests.get(..., verify=False)`, `ssl._create_unverified_context()` |
| Java / Kotlin | an `X509TrustManager` with empty `checkServerTrusted`, `HostnameVerifier` returning `true`, `SSLContext.init(null, trustAllCerts, ...)` |
| .NET | `ServerCertificateValidationCallback = (s, c, ch, e) => true` |
| PHP | `CURLOPT_SSL_VERIFYPEER => false`, `CURLOPT_SSL_VERIFYHOST => 0` |
| curl / shell | `curl -k`, `--insecure`, `wget --no-check-certificate` |

**`urllib3.disable_warnings()` is deliberately not in that table, and must not be filed under the row that grades it.** It suppresses `InsecureRequestWarning`; it changes no validation behaviour, and on its own it is not a certificate-validation finding at any severity. What it is worth is a pointer: somebody silenced that warning because something nearby raises it. It has its own `rg` line in §0, deliberately separate from the switch sweep above it so its hits cannot be graded off the row below; read the same file for the `verify=False` or `_create_unverified_context()` it was added to hide, and file *that*.

**Hostname verification is a separate control from chain validation** in several APIs. A chain can validate perfectly against a trusted CA and still be for the wrong host. In Java the `HostnameVerifier` is separate from the `TrustManager`; in raw OpenSSL, `X509_VERIFY_PARAM_set1_host` must be set explicitly.

```detector
match: |
  tr := &http.Transport{
      TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
  }
  client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
nomatch: |
  pool, err := x509.SystemCertPool()
  if err != nil {
      return nil, err
  }
  tr := &http.Transport{
      TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
  }
  client := &http.Client{Transport: tr, Timeout: 10 * time.Second}
```

```detector
match: |
  TrustManager[] trustAll = new TrustManager[]{ new X509TrustManager() {
      public void checkClientTrusted(X509Certificate[] c, String a) {}
      public void checkServerTrusted(X509Certificate[] c, String a) {}
      public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
  }};
  SSLContext ctx = SSLContext.getInstance("TLS");
  ctx.init(null, trustAll, new SecureRandom());
  HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);
nomatch: |
  SSLContext ctx = SSLContext.getInstance("TLSv1.3");
  ctx.init(null, null, null);   // platform trust store, default hostname verifier
  HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
  conn.setSSLSocketFactory(ctx.getSocketFactory());
```

**Version and suite policy.** RFC 8996 deprecates TLS 1.0 and 1.1. Require 1.2 as the floor and prefer 1.3; reject RC4, 3DES, `NULL`, `EXPORT`, anonymous and MD5-based suites; prefer AEAD suites. Set `MinVersion` explicitly rather than relying on a library default — the defaults in Go, Java, OpenSSL and Node have all moved over time, so read the toolchain version pinned in the manifest rather than assuming, and say which you established. Downgrade tolerance is CWE-757.

**mTLS.** Validate client certificates against an **explicit** CA pool, not the system trust store, or any publicly trusted CA can mint a client. In Go this is `ClientCAs` plus `ClientAuth: tls.RequireAndVerifyClientCert` — `RequireAnyClientCert` requires a certificate and verifies nothing, which is the shape that reads as configured and is not.

```detector
match: |
  srv := &http.Server{
      Addr: ":8443",
      TLSConfig: &tls.Config{
          ClientAuth: tls.RequireAnyClientCert,
      },
  }
nomatch: |
  pool := x509.NewCertPool()
  pool.AppendCertsFromPEM(mustRead("internal-client-ca.pem"))
  srv := &http.Server{
      Addr: ":8443",
      TLSConfig: &tls.Config{
          ClientCAs:  pool,
          ClientAuth: tls.RequireAndVerifyClientCert,
          MinVersion: tls.VersionTLS12,
      },
  }
```

**SSH configuration**, where it is in the tree: reject `hmac-sha1` and non-ETM MACs in `MACs`, and note that `ssh-rsa` denotes an RSA key with a SHA-1 signature and has been off by default in OpenSSH for several releases — `rsa-sha2-256`/`rsa-sha2-512` are the same key type with a modern hash. `PasswordAuthentication yes` and `PermitRootLogin yes` are findings, but they are access-control ones; state them as such.

**Revocation.** Do not file "OCSP stapling is missing" as a finding on its own. Revocation practice has moved — several major CAs have shifted from OCSP toward short-lived certificates and CRLs — so grade the revocation *story*: name the mechanism the deployment relies on, and report it as an assumption where the repository does not say.

### 9. Password hashing and KDF parameters (`password-hashing-and-kdf-parameters`)

**Grade the stored artifact, not the call.** The prefix in the database says what actually ran; a `bcrypt.hashpw` call in the current code says nothing about the rows written by the version before it. Read migrations, fixtures and any seed data.

Minimums, from the OWASP Password Storage Cheat Sheet (CWE-916). Attribute them to that document and not to RFC 9106: RFC 9106 is the Argon2 specification, and the configurations *it* recommends are far above this floor — 2 GiB with t=1, p=4, or 64 MiB with t=3, p=4. The table is the level below which a finding is due, not a target.

| Algorithm | Minimum | Stored prefix |
|---|---|---|
| argon2id | m = 19 MiB, t = 2, p = 1 | `$argon2id$v=19$m=19456,t=2,p=1$` |
| scrypt | N = 2¹⁷, r = 8, p = 1 | `$scrypt$` or a library-specific encoding |
| bcrypt | cost ≥ 10, 12 preferred | `$2b$12$` |
| PBKDF2-HMAC-SHA256 | 600,000 iterations | `pbkdf2_sha256$600000$` |
| PBKDF2-HMAC-SHA512 | 210,000 iterations | — |
| PBKDF2-HMAC-SHA1 | 1,300,000 iterations | — |

Anything else — `md5(password)`, `sha256(password + salt)`, a single unsalted SHA-1, an HMAC of the password with a static key — is the finding regardless of the salt. Speed is the defect (CWE-327 for the primitive, CWE-916 for the effort).

```detector
match: |
  def store_password(user_id: int, password: str) -> None:
      salt = secrets.token_hex(16)
      digest = hashlib.sha256((salt + password).encode()).hexdigest()
      db.execute("UPDATE users SET pw_salt=?, pw_hash=? WHERE id=?",
                 (salt, digest, user_id))
nomatch: |
  _PH = argon2.PasswordHasher(memory_cost=19456, time_cost=2, parallelism=1)

  def store_password(user_id: int, password: str) -> None:
      db.execute("UPDATE users SET pw_hash=? WHERE id=?",
                 (_PH.hash(password), user_id))
```

**Two bcrypt input traps, and the second is created by the usual fix for the first.**

1. bcrypt silently truncates the password at **72 bytes**. A long passphrase is only as strong as its first 72 bytes, and two passwords sharing a 72-byte prefix are the same password.
2. The standard remedy is to pre-hash with SHA-256 — but a **raw** digest is 32 arbitrary bytes and can contain a `0x00`, and bcrypt implementations built on C strings stop at the first NUL. A digest whose first byte is zero collapses to an empty password. Base64-encode (or hex-encode) the digest before handing it to bcrypt.

A pepper is a different control for a different threat (a database read without the application secret). It does not address either trap; do not let a pepper stand in for the encoding.

```detector
match: |
  def hash_password(password: str) -> bytes:
      # pre-hash to dodge the 72-byte cap, but the raw digest may contain a NUL
      pre = hashlib.sha256(password.encode()).digest()
      return bcrypt.hashpw(pre, bcrypt.gensalt(12))
nomatch: |
  def hash_password(password: str) -> bytes:
      pre = base64.b64encode(hashlib.sha256(password.encode()).digest())
      return bcrypt.hashpw(pre, bcrypt.gensalt(12))
```

```detector
match: |
  var kdf = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA256);
  var hash = kdf.GetBytes(32);
nomatch: |
  var hash = Rfc2898DeriveBytes.Pbkdf2(
      password, salt, iterations: 600_000, HashAlgorithmName.SHA256, outputLength: 32);
```

**Also check:** that verification is constant-time (most libraries' `verify`/`checkpw` are — a hand-rolled `==` on the stored hash is not, though see Known false positives (3) on why comparing two *hashes* is weak evidence); that there is an upgrade-on-login path when parameters are raised; that the salt is per-password and from a CSPRNG; and that the password is not truncated or lowercased before hashing.

### 10. Key separation, derivation and lifetime (`key-separation-derivation-and-destruction`)

- **One key, one purpose.** A key that signs session cookies must not also sign password-reset tokens, and an encryption key must not double as a MAC key. Derive per-context subkeys from a master with HKDF (RFC 5869) and a context string in the `info` parameter.
- **`SHA256(key ‖ context)` is not a KDF.** It is length-extendable and has no domain separation between contexts that are prefixes of one another. Use HKDF, or HMAC with the context as the message if HKDF is unavailable.
- **Never derive a key from a password without a slow KDF.** `sha256(passphrase)` as an AES key is the same defect as item 9, in a place people do not look for it. Use scrypt, argon2id or PBKDF2 with a salt, then HKDF for subkeys.
- **Rotation must be possible.** A ciphertext with no key identifier cannot be re-keyed without decrypting everything. Look for a version or key-id byte in the envelope; its absence is a Low finding worth making because it is cheap now and expensive later.
- **Destruction is mostly unachievable in managed languages** — an immutable `String` holding a key cannot be zeroed. Prefer `byte[]`/`bytearray` and clear it; treat "the secret lingers in the heap" as a Low note, not a headline, unless the code deliberately persists it (a log line, a crash dump, a debug endpoint).

```detector
match: |
  MASTER = base64.b64decode(os.environ["MASTER_KEY_B64"])

  def key_for(context: str) -> bytes:
      return hashlib.sha256(MASTER + context.encode()).digest()

  session_key = key_for("session")
  reset_key = key_for("session-reset")
nomatch: |
  MASTER = base64.b64decode(os.environ["MASTER_KEY_B64"])

  def key_for(context: str) -> bytes:
      return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                  info=f"acme/v1/{context}".encode()).derive(MASTER)

  session_key = key_for("session")
  reset_key = key_for("session-reset")
```

### 11. Asymmetric scheme pitfalls (`asymmetric-scheme-pitfalls`)

- **RSA padding is the whole finding.** Textbook RSA (no padding) is broken. PKCS#1 v1.5 *encryption* is Bleichenbacher-attackable and should be OAEP (RFC 8017, NIST SP 800-56B). PKCS#1 v1.5 *signing* remains widely deployed and is acceptable where the verifier parses strictly — but a lenient verifier that ignores trailing bytes after the digest allows forgery with a small public exponent. Prefer PSS for new signing.
- **Key size.** RSA below 2048 bits is a finding; 3072+ for anything long-lived. A 1024-bit key in a fixture is not, unless the fixture is what deploys.
- **ECDSA is only as good as its `k`.** A repeated or biased per-signature nonce recovers the private key from two signatures. Use a library that implements RFC 6979 deterministic ECDSA, or one whose `k` comes from the platform CSPRNG. Report any code that *supplies* `k` itself — that is a hand-rolled signer and it is almost always wrong.
- **Diffie-Hellman peer keys must be validated, and NIST-curve ECDH is not self-protecting.** The consequence of skipping the check on P-256, P-384 and secp256k1 is not a weak session — it is **private-key recovery**. The attacker sends a point that lies on a *different* curve sharing the same field and `a` coefficient but a different `b`, chosen so the point has small order. Short-Weierstrass point arithmetic never reads `b`, so the victim happily computes `d·P` on the attacker's curve and leaks `d mod ord(P)` through whatever it derives from the result; repeat with more small orders and CRT recovers `d`. Two things decide it and both are readable at the call site: **is the private scalar long-lived** — read from config, a keystore or a KMS handle rather than generated per exchange, since an ephemeral key spends the attack — and **does the peer's point get an on-curve and subgroup check before the multiply**. A high-level API that parses an *encoded point* generally validates as part of parsing; a raw primitive handed an `(x, y)` pair, a hand-written `decode_point`, or a scalar-multiply called directly does not. Name the call that validates, or record it as unverified — "modern libraries handle it" is the sentence that made this check disappear from the source material this lens replaces. For **finite-field DH**, validate both halves: the group parameters themselves (an attacker-supplied `p`/`g` is its own break) **and** the peer's `y` for subgroup membership (small-subgroup confinement). **X25519 is the exception** and the reason it is the recommendation: every 32-byte string decodes to a valid point, so there is no invalid-curve case — the check that remains is rejecting an all-zero shared secret.
- **Ed25519** is hard to misuse, but verification semantics differ between libraries: cofactored versus cofactorless verification, and acceptance of non-canonical encodings, mean two implementations can disagree on whether a signature is valid. Where consensus across parties matters — a blockchain, a multi-verifier protocol — name the library and say which semantics it implements rather than assuming they agree.

```detector
match: |
  from cryptography.hazmat.primitives.asymmetric import padding
  ciphertext = public_key.encrypt(session_key, padding.PKCS1v15())
nomatch: |
  from cryptography.hazmat.primitives.asymmetric import padding
  ciphertext = public_key.encrypt(
      session_key,
      padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                   algorithm=hashes.SHA256(), label=None),
  )
```

### 12. Signature malleability and curve validation (`signature-malleability-and-curve-validation`)

For ECDSA on secp256k1 and P-256, `(r, s)` and `(r, n − s)` are both valid signatures of the same message under the same key. This is not a forgery — the signer's authority is unchanged — and it is a real bug whenever the signature is used as an **identity**: a transaction hash, a deduplication key, a replay-cache entry, an idempotency token. The attacker cannot change what was signed; they can produce a second distinct encoding of it and get the operation processed twice.

- Enforce low-`s` (`s ≤ n/2`) on verification wherever the signature or a hash over it is stored or compared.
- **`ecrecover` returns the zero address on failure** rather than reverting. Code that does not compare the result against `address(0)` treats a malformed signature as a signature by nobody — and `address(0)` is frequently also the uninitialized value of the variable it is compared to.
- Prefer a vetted library (for Solidity, OpenZeppelin's `ECDSA`, which rejects high-`s` and the zero address) over a raw `ecrecover`.
- Validate that a supplied public key or point is on the curve before using it, wherever the code parses points itself.

```detector
match: |
  function claim(bytes32 digest, uint8 v, bytes32 r, bytes32 s) external {
      address signer = ecrecover(digest, v, r, s);
      require(signer == owners[msg.sender], "bad signature");
      _payout(signer);
  }
nomatch: |
  using ECDSA for bytes32;

  function claim(bytes32 digest, bytes calldata signature) external {
      // ECDSA.recover rejects the zero address and rejects a high-s signature,
      // so a second encoding of the same signature cannot be replayed here.
      address signer = digest.recover(signature);
      require(signer == owners[msg.sender], "bad signature");
      require(!used[keccak256(abi.encodePacked(digest, signer))], "replayed");
      used[keccak256(abi.encodePacked(digest, signer))] = true;
      _payout(signer);
  }
```

### 13. CSPRNG and token entropy (`csprng-and-token-entropy`)

**The wrong generators** (CWE-338): `Math.random()`, Python `random.random()` / `random.randint()` / `random.choice()`, `java.util.Random` and `ThreadLocalRandom`, Go `math/rand` and `math/rand/v2`, PHP `rand()` / `mt_rand()` / `uniqid()` / `shuffle()` / `array_rand()`, Ruby `rand` and `Random`, .NET `System.Random`.

**The right ones:** `crypto.randomBytes` / `crypto.getRandomValues`, Python `secrets` (and `os.urandom`), Go `crypto/rand`, Java `SecureRandom`, PHP `random_bytes` / `random_int`, Ruby `SecureRandom`, .NET `RandomNumberGenerator.GetBytes`, Swift `SecRandomCopyBytes`, `SystemRandomNumberGenerator`, and the default `Int.random(in:)` / `UInt.random(in:)` overloads. For Swift's `random(in:using:)`, trace the supplied generator; its security is not implied by the API.

Two facts that change how the grep behaves:

- **Go 1.20 made the global `math/rand` source auto-seeded.** The old tell — a missing `rand.Seed(time.Now().UnixNano())` — is gone, and the output is no more unpredictable than it was. Grep for the *import*, not for the seeding call.
- **UUID version matters.** UUIDv4 from a CSPRNG carries **122** bits of entropy (six bits are fixed version and variant) — ample for a token, and the frequently quoted "128 bits" is wrong by a small margin that never changes a verdict. UUIDv1 and v7 embed a timestamp and, for v1, often a MAC address; they are sortable identifiers, not secrets. Python's `uuid.uuid1()` used as a token is the finding.

**Token entropy is measured over the alphabet actually used.** A 32-character token drawn from a 16-character hex alphabet carries 128 bits; the same length drawn from a 10-digit alphabet carries about 106. Require ≥ 128 bits for anything bearer-like, and check for structure: a timestamp prefix, a sequential counter, a user id concatenated to a short random tail.

```detector
match: |
  function newResetToken(userId) {
    return userId + '-' + Math.random().toString(36).slice(2);
  }
nomatch: |
  function newResetToken() {
    return crypto.randomBytes(32).toString('base64url');   // 256 bits
  }
```

```detector
match: |
  import "math/rand"

  func inviteCode() string {
      b := make([]byte, 16)
      for i := range b {
          b[i] = alphabet[rand.Intn(len(alphabet))]
      }
      return string(b)
  }
nomatch: |
  import "crypto/rand"

  func inviteCode() (string, error) {
      b := make([]byte, 32)
      if _, err := rand.Read(b); err != nil {
          return "", err
      }
      return base64.RawURLEncoding.EncodeToString(b), nil
  }
```

**Seeding.** `new SecureRandom()` followed by `setSeed(...)` on the default provider is **not** a finding — `setSeed` supplements the existing seed there (see Known false positives (2)). The forms that are findings are `new SecureRandom(byte[] seed)`, and `SecureRandom.getInstance("SHA1PRNG")` seeded before its first `nextBytes`, because SHA1PRNG defers self-seeding and the supplied value becomes the only seed. Read the provider and the call order.

```detector
match: |
  SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
  rnd.setSeed(userId * 31L + System.currentTimeMillis());
  byte[] token = new byte[16];
  rnd.nextBytes(token);
nomatch: |
  SecureRandom rnd = SecureRandom.getInstanceStrong();
  byte[] token = new byte[32];
  rnd.nextBytes(token);
```

### 14. Key material in the repository (`hardcoded-credentials-and-key-material`)

**Establish the key type before assigning a severity.** `BEGIN PUBLIC KEY`, `BEGIN CERTIFICATE`, a JWKS document, a pinned CA bundle and a vendor verification key all *belong* in source control — that is how pinning and offline verification work. So do NIST and RFC test vectors, and keys under `test/`, `fixtures/`, `__snapshots__/` and `.env.example`. Grepping `BEGIN.*KEY` and filing every hit is the fastest way to be dismissed.

What is a finding:

- `BEGIN RSA PRIVATE KEY`, `BEGIN EC PRIVATE KEY`, `BEGIN OPENSSH PRIVATE KEY`, `BEGIN PRIVATE KEY`, `BEGIN ENCRYPTED PRIVATE KEY` outside a fixture directory.
- A `.p12`, `.pfx`, `.jks` or `.keystore` committed, together with its password in a build file or workflow.
- A symmetric key or HMAC secret as a literal — a base64 or hex constant in a settings module, a `SECRET_KEY = "..."` default that applies when the environment variable is unset.
- A real provider secret, matched on the provider's actual shape: `sk-ant-`, `sk-` followed by a long body, `AKIA`/`ASIA` plus 16 uppercase alphanumerics, `ghp_`, `github_pat_`, `xoxb-`, a service-account JSON containing `"type": "service_account"` and `"private_key"`.

What is **not** a finding, and belongs in the report only as a note if at all: role ARNs, account ids, OIDC audiences, OAuth client **ids**, project numbers, publishable `pk_`-style keys, provider endpoints and model identifiers. These are public by design and match naive secret regexes constantly. See Known false positives (5).

```detector
match: |
  # settings.py
  SECRET_KEY = os.environ.get("SECRET_KEY", "django-insecure-8f3k2j4h5g6d7s8a9")
  JWT_SIGNING_KEY = "c2VjcmV0LXNpZ25pbmcta2V5LWRvLW5vdC1zaGlw"
nomatch: |
  # settings.py
  SECRET_KEY = os.environ["SECRET_KEY"]          # fail closed if unset
  JWT_SIGNING_KEY = base64.b64decode(os.environ["JWT_SIGNING_KEY_B64"])
  if len(JWT_SIGNING_KEY) < 32:
      raise ImproperlyConfigured("JWT signing key must be at least 256 bits")
```

**A default that applies when the variable is unset is the sharpest form of this finding**, because it deploys silently: nothing fails, and every instance shares the literal. Grep for the two-argument `os.environ.get`, `process.env.X ||`, and `@Value("${x:default}")` on anything key-shaped. Go's `os.Getenv` has no default argument: its equivalent is an environment read followed nearby by an empty-string check and a literal assignment, which the multiline §0 sweep inventories.

**Check history before grading.** `git log -p -- <path>` decides whether the value is live or rotated, and a rotated value is a hygiene note. Where the repository is public and the value was ever committed, say so — the exposure predates the removal.

### 15. Custom protocols (`symmetric-encryption-and-nonce-handling`, with the relevant primitive slug)

A hand-rolled handshake, encrypted channel or token format is a finding by construction unless it comes with evidence. Ask, in order:

1. Is there a written specification? If not, that is the first finding, and everything below is unverifiable.
2. Which of confidentiality, integrity, authenticity and freshness does it claim? Which does it actually provide? Name the gap concretely — "no freshness: a captured message replays forever" — not "the protocol is custom".
3. Is there a state machine, and is it enforced? Missing transitions are the recurring bug.
4. Was it reviewed by someone with cryptographic expertise?

Almost always the recommendation is to replace it with TLS, Noise, `age`, libsodium sealed boxes or a JOSE/COSE profile. File the finding against the primitive slug the defect actually lands on, so it is not double-counted with item 1 or item 4.

## Severity calibration

`severity_floor: low` is presentational. It orders this lens's findings in the report. It never suppresses a finding, and no item below may be dropped because it sits at Low or Info.

**The rule that does the most work here: no severity may rest on a condition the repository cannot establish.** Every High and Critical below names the artifact that satisfies it — a file glob, a config key, an API symbol, or a grep. A condition phrased as a property nobody can look up ("the key is used at scale", "the deployment is internet-facing") silently downgrades the finding forever, which is worse than not writing the row.

**The second rule: three re-grades, because the source material's own table was wrong.** Correcting the prose and leaving the table would leave a fully operational bug behind corrected documentation.

| Original instruction | Why it was wrong | Re-graded |
|---|---|---|
| "Static / predictable IV in AES-GCM: **Critical (key compromise potential)**." | Nonce reuse in GCM does not recover the AES key. It leaks the plaintext XOR and the GHASH subkey `H`, which is enough for arbitrary tag forgery — Critical for its real reason. And "predictable" is the wrong test for GCM: a predictable-but-unique nonce is fine. | **Critical — repeated `(key, nonce)` pair in AES-GCM.** Established from the encrypt call site: a nonce bound at module, class or object scope — the three §0 nonce sweeps cover that shape in eight ecosystems, `self._nonce = os.urandom(12)`, Ruby's `@iv = SecureRandom.random_bytes(16)`, PHP's `$this->iv = random_bytes(16)`, an indented class attribute, a lowercase `const iv = crypto.randomBytes(12)` or `const IV = Buffer.from('…','hex')` at file top level, Kotlin's `private val NONCE: ByteArray = ByteArray(12)`, Rust's `static IV: [u8; 12]`, Swift's module/class/object `let nonce = AES.GCM.Nonce()`, and the Java/.NET `static byte[] IV` / `_iv` — or a nonce parameter supplied by the caller from a constant, or a counter with no durable store. Impact: plaintext XOR, plus tag forgery for messages carrying that nonce. Not key recovery — do not write that. |
| "Missing PKCE on mobile OAuth: **Medium**." | The exploitability turns on whether another application can claim the redirect, which is visible in the manifest and the client registration, not on the platform. | **High** where the client is public (no secret in the token request) **and** the redirect is a custom scheme or a loopback port — established from `AndroidManifest.xml` `<data android:scheme=...>`, `CFBundleURLSchemes` in `Info.plist`, or a `redirect_uri` of `http://127.0.0.1:<port>` / `myapp://` in the client config. **Medium** where the redirect is a verified HTTPS app link (`android:autoVerify="true"`, an Associated Domains entitlement) — interception is materially harder. **Low** for a confidential server-side client, filed as RFC 9700 conformance. |
| "Timing-unsafe MAC comparison: **High** (Medium if the rate limit makes practical exploitation hard)." | The rate-limit clause is the whole finding in disguise and invites hand-waving. The four conditions in Checklist item 4 are checkable. | **High** when all four hold: the compared value arrives from the request, the comparison is byte-by-byte against a server-computed secret, no per-identity attempt cap is visible in the handler or its middleware, and the operand is not itself a high-entropy digest the attacker cannot steer. **"Byte-by-byte" means a comparison that stops at the first difference** — `==`, `!=`, `.equals(`, `Arrays.equals`, `SequenceEqual`. On Apex, prefer an executable `Crypto.areEqualConstantTime` call over two `Blob` operands. A length-checked, branch-free local accumulator over *every* byte is also not this finding after its body and request-path call satisfy item 4's four conditions — see Known false positives (10) — but a plausible helper name alone clears nothing. **Medium** when a cap exists but the comparison is still `==`. **Low** when the operands are two locally derived values. Establish the cap from the code, not from an assumption that "there is probably a WAF". |

### Severity table

| Finding | Severity | The artifact that establishes it |
|---|---|---|
| Repeated `(key, nonce)` in AES-GCM, AES-CTR or ChaCha20 | Critical | A nonce or IV bound outside the per-message function, in one of the spellings the §0 nonce sweeps cover across eight ecosystems: an object attribute (`self._nonce = os.urandom(12)`, `this.iv = crypto.randomBytes(12)`, `$this->iv = random_bytes(16)`, `@iv = SecureRandom.random_bytes(16)`), a class attribute or module-scope binding of any casing (`NONCE = os.urandom(12)`, `const iv = crypto.randomBytes(12)` or `const IV = Buffer.from('…','hex')` at file top level, `private val NONCE: ByteArray = ByteArray(12)`, `static IV: [u8; 12] = [0u8; 12]`, Swift's `static let nonce = AES.GCM.Nonce()`), the Java/.NET constant (`static final byte[] IV`, `static readonly byte[] _iv`, `new IvParameterSpec(new byte[16])`, a `static` `GCMParameterSpec`), or a constant passed in at the call site. Impact by mode, and state it that way (CWE-323): all three leak the XOR of the two plaintexts; **GCM additionally leaks the GHASH subkey `H`**, which forges tags for messages carrying that repeated nonce — not under any other nonce, and never the AES key. Bare AES-CTR and bare ChaCha20 have no tag to forge; ChaCha20-Poly1305 loses the Poly1305 one-time key for that nonce the same way GCM loses `H`. |
| Nonce derived deterministically from message content with no SIV construction | High | The nonce argument at the `encrypt(` / `Seal(` / `doFinal(` call is built from the plaintext or a hash of it — `sha256(plaintext)[:12]`, `md5(payload)`, a `record_id` or `user_id` that is not guaranteed unique per key. This is the catastrophic case only when two *different* plaintexts can land on the same derived value — a mutable source field, a truncated or grindable hash, or an attacker-influenced input. Cleared only by AES-GCM-SIV (RFC 8452), AES-SIV (RFC 5297) or Deoxys-II — the misuse-resistant family and nothing else. ChaCha20-Poly1305, AES-GCM and XChaCha20-Poly1305 fail identically under a derived nonce, regardless of nonce width. |
| Equal plaintexts sealing to equal ciphertext over a short, enumerable domain (booleans, status flags, small enumerations) | Critical | A distinct defect from the row above, not nonce collision: the sealed field's value space is small enough to enumerate — read from the column type, enum or schema — under *any* deterministic construction, including a genuine misuse-resistant AEAD. **Not cleared by AES-GCM-SIV, AES-SIV or Deoxys-II** — SIV is deterministic by design and preserves exactly this leak. Fix is a fresh random nonce per record, or padding/bucketing the plaintext so the domain is not short. |
| Counter nonce with a named reset or sharing condition | High | One of two, both readable at the call site: the counter is initialized to a literal in `__init__` / a constructor / a module body (`self._counter = 0`, `var seq uint64`) with no durable store, so a restart rewinds it; or two writers share a key with the same fixed field — a replica set, a forked worker pool, or a handler holding one KMS data key, where the nonce is `counter` with no per-writer prefix. Without one of those two facts this is **not a finding** — SP 800-38D §8.2.1 approves the construction. |
| Predictable IV in AES-CBC | High | A zero, counter, timestamp or reused IV at the `Cipher.init` / `modes.CBC(...)` call (CWE-329), or the third argument of Apex's `Crypto.encrypt('AES256', key, iv, …)` being a class constant, a `Blob.valueOf('…')` literal or a value derived from the record — Apex's unhyphenated `AES128`/`AES192`/`AES256` names are CBC and nothing on the line says so. Critical where the code is a decryption oracle for attacker-supplied ciphertext. Not this finding for the corresponding `Crypto.encryptWithManagedIV` CBC call, which draws the IV per call; that CBC path is graded on the row below instead. Also not this finding for a supported `AES*-GCM` call, whose nonce and authentication properties must be reviewed as GCM. |
| ECB over multi-block attacker-visible data | High | `MODE_ECB`, `modes.ECB(`, `"AES/ECB/`, `'aes-256-ecb'` in either quote style, .NET's `CipherMode.ECB`, Rust's `ecb::`, or `Cipher.getInstance("AES")` with no mode — **and** a plaintext longer than one block that is not a key-wrap, CMAC or SIV internal (CWE-327). Low where the operation is single-block or an internal of a correct mode. |
| Unauthenticated ciphertext — no MAC anywhere on the encrypt/decrypt path | Critical | The cipher construction call — `createCipheriv('aes-*-cbc'/'aes-*-ctr', ...)`, `Cipher.getInstance("AES/CBC/...")` / `"AES/CTR/..."`, `AES.new(key, AES.MODE_CBC` / `MODE_CTR)`, `openssl_encrypt($d, 'aes-256-cbc', ...)`, `OpenSSL::Cipher.new('aes-256-cbc')`, Rust's `cbc::Encryptor` / `ctr::Ctr…`, .NET's bare `Aes.Create()` whose default mode is CBC with nothing on the line saying so, or an Apex `Crypto.encrypt` / `Crypto.encryptWithManagedIV` call whose literal algorithm is the unhyphenated CBC name `AES128`, `AES192` or `AES256` — with no `Hmac`/`Mac.getInstance`/`hmac.new`/`createHmac`/`hash_hmac`/`OpenSSL::HMAC`/`HmacSha…`/`Crypto.generateMac(` call anywhere in the file or a helper it calls, and the ciphertext handed to storage, a cookie or the wire. Run the absence sweep in §0 before writing this up. Not a finding where the construction is AEAD (GCM, CCM, GCM-SIV, ChaCha20-Poly1305, XChaCha20-Poly1305, AES-SIV) — those authenticate internally. **That exemption includes supported Apex `AES*-GCM`.** Summer '25 introduced licensed GCM overloads, so confirm the class API version, literal or resolved `algorithmName`, and org entitlement; a managed IV alone does not clear CBC, while an actual GCM call does not need a separate HMAC. |
| Tag or MAC verified after unpadding, parsing or use of the plaintext | Critical | Call order in the decrypt function: the `unpad` / `json.loads` / `deserialize` call precedes the `compare_digest` / tag check. This is the padding-oracle enabler. |
| `alg: none` accepted, or an algorithm list mixing symmetric and asymmetric | Critical | An explicit allowlist containing `"none"`, or one carrying both an `HS*` and an `RS*`/`ES*`/`PS*` entry; a verifier that reads `alg` out of the header to choose the key or the algorithm; or a Go `jwt.Parse` / `jwt.ParseWithClaims` whose keyfunc hands back key material without inspecting the token's method and with no `WithValidMethods` (CWE-347). **A merely absent `algorithms=` is not automatically this finding — read the version pinned in the manifest first.** PyJWT ≥ 2 raises rather than verifying; `jsonwebtoken` ≥ 9 derives the permitted family from the key type; `jose` and golang-jwt v5 pin through their own options. Where the library fails closed like that, the missing pin is a Medium hardening note. It is Critical where the library or version does not — PyJWT 1.x, `jsonwebtoken` < 9, a hand-rolled verifier — and `options={"verify_signature": False}` is Critical on every PyJWT version. |
| `decode` used where `verify` was meant | Critical | `jwt.decode(` in `jsonwebtoken`, `JWT.decode(` in java-jwt, `decodeJwt(` in jose — with the result feeding an authorization decision. Complete bypass. |
| Signature verification switched off | Critical | `options={"verify_signature": False}`, `ParseUnverified`, `verify: false`. Medium only where the call site is provably a debugging or introspection path with no authorization consequence — quote the call site. |
| Verification key taken from the token (`jku`, `x5u`, embedded `jwk`) | Critical | The key-resolution function reads `header["jku"]`, `header["x5u"]` or `header["jwk"]`, or passes the header to a fetcher. |
| `kid` concatenated into a filesystem path or a SQL string | High | The key lookup interpolates `kid` rather than indexing a map. Critical where it reaches a query or a file read. |
| Claims unvalidated — `exp`, `iss`, `aud` | High | No `audience=` / `issuer=` argument and no explicit comparison after decode. Medium where the token is short-lived and single-issuer, stated as such. |
| SAML assertion consumed without binding it to the verified signature reference | Critical | The code finds the assertion by XPath or `find(...)` independently of the signature's `Reference URI`, or checks only that a `<Signature>` element exists. |
| SAML parser with external entities enabled | High | `resolve_entities=True` or `load_dtd=True` on the parser used for the response, or a default-configured parser where the library does not harden it. Critical where the parse runs before authentication. |
| `wantAssertionsSigned` false, or `rsa-sha1` accepted | High | The literal in the library's security settings block: `"wantAssertionsSigned": false`, `"wantMessagesSigned": false`, or a `signatureAlgorithm`/`digestAlgorithm` ending `#rsa-sha1` or `#sha1` in the SAML settings JSON, YAML or provider configuration. |
| Certificate validation disabled | Critical | Any switch in the Checklist item 8 table, in a code path that is not test-only (CWE-295). Establish "not test-only" from the file's location and its imports; a switch behind an `if settings.DEBUG` that is also reachable in production configuration is still Critical. |
| Hostname verification disabled while chain validation stays on | Critical | A `HostnameVerifier` returning `true`, `CURLOPT_SSL_VERIFYHOST => 0`, or an `X509_VERIFY_PARAM` with no host set. |
| mTLS accepting any client certificate | High | `ClientAuth: tls.RequireAnyClientCert`, or a server trust store that is the system pool rather than an explicit CA. Critical where the certificate is the only authentication. |
| TLS floor below 1.2, or a suite list containing RC4, 3DES, `NULL`, `EXPORT` or anonymous | High | An explicit `MinVersion`/`ssl_protocols`/`sslProtocol` naming 1.0 or 1.1, or a suite string in an nginx, envoy, haproxy or application config (RFC 8996, CWE-757). **Medium** where the floor is merely *unset* and the runtime default is unknown, filed with the toolchain version read from the manifest and the assumption stated. |
| Password stored with a fast hash | Critical | The stored artifact: a bare hex digest column, `md5(`/`sha1(`/`sha256(` in the write path, or a migration inserting one (CWE-916). Critical because every row is affected at once. |
| KDF parameters below the item 9 table | Medium | The parameter literal at the call site *and* the prefix on stored rows — `$2b$08$`, `pbkdf2_sha256$100000$`, `Rfc2898DeriveBytes(..., 10000, ...)`. High on two facts, both in the tree: stored rows actually carry the weak prefix — a migration, seed or fixture containing `$2b$08$`, `pbkdf2_sha256$100000$` or a bare digest column — **and** the verify path contains no rehash-on-success call (`check_needs_rehash`, `needs_rehash`, `password_needs_rehash`, or an `UPDATE … SET pw_hash` inside the login handler). Corpus size is a production property and grades nothing here. |
| Raw SHA-256 digest fed to bcrypt | Medium | A `bcrypt.hashpw` / `bcrypt.Generate` call whose input is `.digest()` rather than a base64 or hex encoding. It bites only the fraction of passwords whose digest contains a NUL, which is why it survives testing. **Establish the binding's behaviour before writing the impact**: where the implementation is built on C strings the digest is truncated at the first NUL and the failure is silent — a leading zero byte collapses the password to empty; other bindings reject a NUL in the password outright, which is a loud error on the same fraction of registrations. Both are the finding; they are not the same sentence. |
| Key derived from a password with a fast hash and used for encryption | High | `hashlib.sha256(passphrase)` or equivalent feeding a `Cipher`/`AESGCM` constructor. |
| One key across contexts, or `SHA256(key ‖ context)` as the KDF | Medium | A single key constant referenced by two or more distinct signing or encryption call sites, or a derivation function that concatenates rather than calling HKDF (RFC 5869). High where the two call sites are, specifically: one of them verifies or decrypts a value that arrived in the request — a cookie, header, query parameter or body field read in a handler — and the other mints a privileged artifact, a password-reset token, an admin or impersonation session, or a signed internal RPC. Both call sites are in the tree; name them. |
| Timing-unsafe comparison of an attacker-supplied MAC, signature, API key, TOTP code or reset token | High | `==` / `!=` / `.equals(` / `===` on a value read from the request, in a non-Swift file with none of the safe calls the §0 general absence sweep lists — `timingSafeEqual`, `compare_digest`, `subtle.ConstantTimeCompare`, `hmac.Equal`, `hash_equals`, `MessageDigest.isEqual`, `FixedTimeEquals`, Rails `ActiveSupport::SecurityUtils.fixed_length_secure_compare` / `ActiveSupport::SecurityUtils.secure_compare`, Apex `Crypto.areEqualConstantTime`, the `subtle` crate's `ct_eq`, ring's `verify_slices_are_equal` (CWE-208) — plus the four conditions in the re-grade table. **That list is a list of exact platform APIs and must stay identical to the general sweep's** — same twelve API names — because a correct file graded against a shorter list becomes a false High. The Go, Rails and Apex names are deliberately qualified: a local `ConstantTimeCompare`, `secure_compare` or `areEqualConstantTime` helper does not clear without a body read. Swift is deliberately excluded from that file-level clearance: its scoped sweep prints any file containing a CryptoKit `HMAC.authenticationCode` or CommonCrypto `CCHmac` / `CCHmacInit` construction plus an equality operator even if `isValidAuthenticationCode` also appears elsewhere, and the auditor reads the request path. On Apex, an executable `Crypto.areEqualConstantTime` call comparing the decoded request `Blob` with the expected MAC is the preferred clearance. **A project-local helper remains a manual clearance when the auditor has read its body and confirmed all four of item 4's conditions** — length check first, then a loop over every byte, differences accumulated into one variable with no `break`, `return` or branch inside the loop, and the verifier calling it on the value that arrived in the request — and the clearance names the helper's file and line. It is this finding at High where the `.cls` compares a request signature with `==`, `!=`, `.equals(` or `equalsIgnoreCase(` and calls neither the built-in nor such a verified helper, or calls a helper whose body fails any of the four. A helper the auditor did not read is neither: say so and leave it open. |
| `H(secret ‖ msg)` used as a MAC | High | A `sha256`/`sha1`/`sha512` call whose input concatenates a secret with a message, with no `hmac` in the file — or, in Apex, `Crypto.generateDigest('SHA-256', …)` over a `Blob` built from a secret plus the payload, where the keyed call `Crypto.generateMac('hmacSHA256', …)` was available. The algorithm-name argument is the artifact: an unkeyed `SHA-256`/`SHA-512` string on a line that also carries a key or secret. |
| MAC computed over a re-serialized body | High | `JSON.stringify(req.body)`, `json.dumps(request.json)` or an ORM object inside the `createHmac`/`hmac.new` update. The signature no longer describes the bytes that arrived. |
| No timestamp bound into the signed material, or a timestamp never compared | Medium | The signed string in the verifier contains no time component, or the header is read and never compared to `now` (CWE-294). High where the handler writes — an insert, update, delete, payment, provisioning or send call in its body — **and** neither the route nor its router group carries an authentication guard: no `@login_required` / `@requires_auth`, no `IsAuthenticated` permission class, no auth middleware on the mount, which is the ordinary shape of a webhook endpoint. Both facts are in the route definition. Hand the handler half to `webhook-handler-integrity`. |
| `Math.random()` / `math/rand` / `java.util.Random` / `mt_rand()` for a token, id, nonce, salt, password or key | High | The generator call — `Math.random()`, `random.random()`, `random.choice(`, `new Random(`, `ThreadLocalRandom`, an `import math/rand`, `mt_rand(`, `array_rand(`, `uniqid(`, a `rand(` with or without arguments, `new System.Random(`, `uuid.uuid1()` — inside the function that produces the value, with the value reaching an authentication, authorization or reset path (CWE-338). Critical where it produces a key, a nonce or a salt. |
| `SecureRandom.getInstance("SHA1PRNG")` seeded before first use, or `new SecureRandom(byte[])` | High | Both the provider string and the call order. The plain `new SecureRandom()` + `setSeed` form is **not** this finding. |
| Token below 128 bits over its actual alphabet | Medium | The length and alphabet at the generation site. High where the token is a bearer credential with no expiry. |
| Private key, keystore or provider secret committed | Critical | `BEGIN (RSA \| EC \| DSA \| OPENSSH \| PGP \| ENCRYPTED )?PRIVATE KEY` — the same alternation as the §0 sweep, `PGP` included because an armoured `.asc` writes `BEGIN PGP PRIVATE KEY BLOCK` — a committed `.p12`/`.pfx`/`.jks` in any letter case, or a provider-shaped literal (`sk-ant-`, `AKIA`/`ASIA`, any of `ghp_`/`gho_`/`ghs_`/`ghu_`/`ghr_`, `xoxb-`/`xoxp-`, service-account JSON) outside `test/`, `fixtures/`, `__snapshots__/` or `.env.example`. Downgrade to Info on evidence of rotation from `git log -p`; say which you established. |
| Secret literal as an environment-variable fallback | High | A two-argument `os.environ.get`, `process.env.X ||`, `@Value("${x:default}")`, or Go `os.Getenv` followed nearby by an empty-string check and a literal assignment, on a key-shaped name. Go has no default-taking `os.Getenv` overload. The fallback deploys silently and every instance shares it. |
| Public key, certificate, CA bundle or test vector in source | Not a finding | Confirm from the PEM header (`BEGIN PUBLIC KEY`, `BEGIN CERTIFICATE`) or the path. Do not file. |
| Missing PKCE, unchecked `state`, prefix-matched `redirect_uri`, implicit flow | See the re-grade table | The client type from the token request, and the redirect shape from the manifest or client config. A prefix-matched `redirect_uri` on a public client is **High** on its own: `startswith`/`^...` in the allow check plus a code or token in the response. |
| Signature malleability where the signature is an identity | Medium | The signature or a hash of it is stored, compared or used as a key, with no low-`s` check. High where it gates a payout, a mint or an idempotent state change. |
| `ecrecover` result not compared against `address(0)` | High | A raw `ecrecover(` whose return value flows into a comparison with a storage variable that can itself be zero. |
| RSA PKCS#1 v1.5 encryption | Medium | `padding.PKCS1v15()` on an `encrypt` call, `RSA/ECB/PKCS1Padding` in Java (RFC 8017). High where the endpoint returns distinguishable errors for a bad decryption. |
| ECDH or finite-field DH peer public key used without validation | High | The peer's key material arrives from the wire and reaches the scalar multiply with no on-curve or subgroup check: an `(x, y)` pair or raw coordinates lifted out of a message and handed to a point constructor, a hand-written `decode_point` / `from_coordinates`, or a raw primitive (`EC_POINT_mul`, `ECDH_compute_key` on a point the code built itself) rather than a library call that parses an encoded point. For FFDH, a peer `y` used with no subgroup check and no validation of the group parameters themselves. **Critical where the private scalar is static** — loaded from config, a keystore or a KMS handle rather than generated per exchange — because the invalid-curve attack then recovers the long-term private key, not one session. **Not a finding for X25519**, where every 32-byte string is a valid point; the X25519 check is the all-zero shared secret. |
| RSA key below 2048 bits in a deploying path | Medium | The key size at generation, or the modulus length of a committed key that is not a fixture. |
| Custom cryptographic protocol with no written specification | High | Two facts, both readable: a hand-rolled construction — a function that concatenates a payload with a MAC and base64s it, a `handshake`/`negotiate`/`seal`/`envelope`/`wrap` function calling primitives directly rather than an AEAD or a TLS/Noise/JOSE library — **and** no specification for it in `docs/`, `README`, `*.md`, or an ADR. Critical where it protects credentials or regulated data. Name the missing property (confidentiality, integrity, authenticity, freshness), not the fact that it is custom. |
| MD5 or SHA-1 where collision resistance is load-bearing | High | The call — `hashlib.md5(`, `hashlib.sha1(`, `MessageDigest.getInstance("MD5")`, `crypto.createHash('sha1')`, `md5(`, `sha1(` — **and** a use that trusts the digest for identity or integrity: signature or certificate verification, integrity of untrusted content, password storage, or a dedup key across tenants (CWE-327). **Not a finding** for ETags, cache keys, shard selection, Git object ids, or `hmac` constructed over SHA-1 as a MAC. |
| Ciphertext with no key identifier or version byte | Low | The envelope format at the encrypt site. A rotation blocker, not a vulnerability. |
| Key material left in an immutable `String` | Low | Note it; do not let it displace a real finding. |

Two anti-patterns, stated as rules:

- **Never grade a nonce on how it looks.** Random, counter and derived are all *candidates*. The severity comes from whether a repeat is possible under one key, and from a named condition that makes it possible. A construction with no such condition is correct code, and the report must say so rather than saying nothing.
- **Never clear a finding because a control might exist elsewhere.** A mesh that might terminate TLS, a WAF that might rate-limit, a KMS that might rotate — none of these is visible here. Where you cannot establish one, the finding stays open at the lower severity with the assumption and the verification step written out. An unverified control is a hypothesis, not a clearance.

## Known false positives

Each entry names a pattern a competent reviewer would flag and states why it is not the finding it looks like. **None of these is a licence to drop a finding**: every one names the narrower finding that does survive.

1. **A fresh CSPRNG nonce drawn per encryption call, reported as nonce reuse.** This is the construction NIST SP 800-38D §8.2.2 recommends and the one every well-designed sealing API implements. There is nothing to fix, and a report that says otherwise will be dismissed along with everything around it. Four things do escalate it, and each is visible at the call site: the draw happens **outside** the per-message function (module, class or object scope); the caller passes the nonce in from a constant; the key plausibly reaches **2³²** encryptions before rotating, which is SP 800-38D's invocation cap and roughly where a random 96-bit nonce's collision probability reaches 2⁻³²; or the generator keeps state in the process and the process forks or is restored from a snapshot — which is a hazard for a buffered userspace pool or a long-lived `SecureRandom`, and **not** for `os.urandom`, Python `secrets` or Go `crypto/rand`, all of which reach the kernel on every call. Name which one, or do not file.

2. **`SecureRandom rnd = new SecureRandom(); rnd.setSeed(nonRandomValue);` in Java.** For the default provider, `setSeed` *supplements* the existing seed — documented behavior — so mixing in a non-secret value cannot reduce output entropy. The dangerous forms are different and are the ones to report: `new SecureRandom(byte[] seed)`, and `SecureRandom.getInstance("SHA1PRNG")` followed by `setSeed` before the first `nextBytes`, because SHA1PRNG defers self-seeding and the supplied value becomes the only seed. Read the provider and the call order before writing it up.

3. **`==` or `.equals()` comparing a value that is merely security-adjacent.** A stored token *hash*, a UUID request id, a JWT `kid`, an algorithm or version string, a value the code computed on both sides, or a single-use code behind a strict attempt cap. A timing finding needs all four of: an attacker-supplied guess, byte-by-byte comparison against a secret, effectively unlimited attempts, and a signal that survives network jitter. Comparing two locally derived values leaks nothing, and a high-entropy digest gives no adaptive path because the attacker cannot steer the prefix. Report the ones on attacker-supplied MACs, signatures, API keys, TOTP codes and reset tokens; file the rest Low or not at all.

4. **MD5 or SHA-1 in application code.** ETag and cache-key generation, content-addressed storage of internal blobs, shard selection, dedup fingerprints, Git object ids, and HMAC-SHA1 required by a vendor API or by TOTP. What is broken is collision resistance — and SHA-1 chosen-prefix collisions — which is load-bearing only when an adversary supplies the input and the digest is trusted for identity or integrity. HMAC-SHA1 as a MAC has no practical break. Flag it for password storage, signature or certificate verification, integrity of untrusted content, or a dedup key where a collision lets one tenant overwrite another's object — and **name the broken property in the finding**. A blanket "MD5 found" is the fastest way to lose the reader's trust in the whole report.

5. **Hardcoded key material found by grep.** NIST and RFC test vectors, keys under `test/`, `fixtures/`, `__snapshots__/`, `.env.example` and documentation samples, and above all *public* keys and certificates in source: JWKS documents, pinned CA bundles, vendor verification keys, receipt-validation keys. Public keys and CA bundles belong in source control — that is how pinning and offline verification work — and a test vector must be fixed or the test proves nothing. Confirm the key type from the PEM header (`BEGIN PRIVATE KEY` versus `BEGIN PUBLIC KEY` / `BEGIN CERTIFICATE`) before assigning a severity, and read `git log -p`: a value rotated years ago is a hygiene note. The same rule covers identifiers that merely look like secrets — role ARNs, account ids, OIDC audiences, OAuth client ids, project numbers, publishable `pk_`-style keys, provider endpoints and model ids. Match the provider's real secret shapes (`sk-`, `sk-ant-`, `AKIA`/`ASIA`, `ghp_`, service-account JSON) instead.

6. **ECB or a raw block-cipher primitive appearing in code.** `AES.MODE_ECB`, `Cipher.getInstance("AES/ECB/NoPadding")` and Go's `aes.NewCipher` are the building blocks of CMAC, AES-KW key wrapping, AES-SIV, the CTR/GCM counter block and format-preserving encryption — and Go's API *requires* a `cipher.Block` before `cipher.NewGCM(block)`. A hit inside a correct larger mode is not the ECB bug. The bug is ECB over multi-block, attacker-visible, low-diversity data, or Java's `Cipher.getInstance("AES")`, which silently resolves to ECB. Check the plaintext length and the surrounding mode.

7. **An encrypt or decrypt API that takes no nonce or IV argument.** `Fernet.encrypt`, libsodium `crypto_secretbox_easy` and `crypto_box_seal`, Tink's `Aead.encrypt`, the AWS Encryption SDK, `age`, Rails `MessageEncryptor`, Apex `Crypto.encryptWithManagedIV`. These are designs that remove the choice: the library draws a fresh nonce per call and prepends it to the ciphertext precisely so the caller cannot get it wrong, and demanding an IV parameter pushes the team toward the API that can be got wrong. (That is an API property, not nonce-misuse resistance in the AES-GCM-SIV sense — do not read it as a clearance for a derived nonce.) It becomes a finding only when a wrapper derives the nonce deterministically from message content in a way that can repeat across two *different* plaintexts, caches a nonce across calls, or holds one key past the mode's message limit. Only AES-GCM-SIV, AES-SIV or Deoxys-II makes a deterministic construction safe; a key-committing scheme is a different property and clears nothing here. **For Apex, the algorithm argument decides what else this entry clears.** With the unhyphenated CBC names `AES128`/`AES192`/`AES256`, managed IV closes item 1 but leaves item 3 open until a `Crypto.generateMac` covers the complete envelope. With a supported, licensed `AES*-GCM` overload, the call is AEAD and no separate MAC is required. Confirm the source API version and org entitlement rather than applying either rule universally.

8. **A monotonic counter used as a GCM nonce, reported as a predictable-nonce bug.** Predictability is not the requirement for GCM; uniqueness is. The deterministic construction in SP 800-38D §8.2.1 is a fixed field plus an invocation counter, and it is exactly what TLS 1.3 and QUIC do per record. It becomes a finding on one of two named conditions: the counter can **reset** relative to the key (initialized in a constructor or module body with no durable store, so a restart rewinds it), or two writers share a key with the **same fixed field** (replicas, a forked worker pool, a serverless handler holding one data key). Without one of those, do not file — and do not file it under CBC's rule either, because for a CBC **IV** predictability genuinely is the defect and the two must not be conflated.

9. **A deliberate HS256 JWT reported as "should use RS256".** HS256 with `algorithms=["HS256"]` pinned and a 256-bit managed secret is a valid design for a single party that both issues and verifies. The escalations are specific: a cross-class algorithm list, or an unpinned call on a library version that does not fail closed — that is the RS256→HS256 confusion, and it is Critical; a low-entropy or password-derived secret; or a *verify-only* party holding the shared key, since a symmetric MAC gives every verifier the power to mint. Report those; do not report the algorithm choice.

10. **An Apex verifier using a verified project-local constant-time helper, reported because it does not call the preferred built-in.** Apex provides `Crypto.areEqualConstantTime(Blob, Blob)`, and new or migrated code should use it. Its existence does not make every older local accumulator a vulnerability. A local helper clears only when its body shows all four of item 4's conditions: length check first, a loop over every byte, differences accumulated into one variable with no `break`, `return` or branch inside it, and the verifier calling it on the request value. The §0 helper-name arm is a reading list, never a clearance. Two narrower findings survive. First, a **drifted copy** that returns early or loops only to the shorter operand. Second, a **verifier that calls neither the built-in nor a verified helper** and compares with `==`, `!=`, `.equals(` or `equalsIgnoreCase(`. Clear the proven legacy helper, recommend migration to the built-in, and name the helper's file and line so the reader can check the read.

### Rejected candidates

Candidates considered for the list above and deliberately excluded. Nothing here should be quietly re-added; each would have suppressed a real finding, or moved a finding into a section that cannot enforce it.

Recorded first, because it is a divergence rather than a rejection: the recon material cut **"96-bit random nonce flagged as nonce-reuse risk"** for volume and kept only a calibration note. That cut is wrong for this lens. The material this lens replaces labelled that exact construction as a vulnerability, so the false positive is not hypothetical — it is what the lens would have shipped. It is entry 1 above, with the escalation triggers preserved inside it.

- **"Verification is disabled only on an internal service, so the network is trusted."** Rejected: not establishable from a repository, and it is the single most common excuse attached to a real `InsecureSkipVerify`. Internal traffic is exactly what a foothold reaches. Where the code genuinely targets a fixture or a local emulator, the discriminator is the *host literal* at the call site — say that instead.
- **"Crypto in a test file is never a finding."** Rejected as over-broad. Test helpers are routinely imported by production code, and a private key committed under `test/` that CI uses to sign a real artifact is a live credential in a directory that looks exempt. The narrow version — test *vectors* must be fixed, and a fixture key is not a credential — is entry 5.
- **"Nonce reuse is impossible because the encrypt path is single-threaded."** Rejected: unverifiable from one file and false across processes, restarts and replicas, which is where the reuse actually happens. The checkable version is entry 8's two named conditions.
- **"A hardcoded key is acceptable because the repository is private."** Rejected: repository visibility is not a cryptographic control, and the value is present in every clone, every CI runner, every backup and the whole of history. Rotation evidence downgrades it; privacy does not.
- **"The library is FIPS-validated, so the usage is correct."** Rejected: validation covers the primitive implementation, not the protocol built from it. Every finding in this lens is reachable with a validated module.
- **"A rate limit or a WAF makes the timing comparison unexploitable."** Rejected **as written**, and replaced rather than deleted: it is the hand-wave that the timing re-grade in `## Severity calibration` exists to eliminate. A cap is only a mitigant when it is *visible in the handler or its middleware*, and even then it caps the finding at Medium rather than clearing it.
- **"TLS 1.2 rather than 1.3."** Not a false positive and not a finding — 1.2 with AEAD suites is the current floor (RFC 8996 deprecates 1.0 and 1.1, not 1.2). Recording it here so it is not re-added as a suppression rule for the version *floor* finding, which is real.
- **"Add `constantTimeEquals` or another project-local helper name to the §0 safe list."** Rejected. The exact platform call `Crypto.areEqualConstantTime` is already a clearing token; a project-local name proves nothing about a project-local body. Adding one would clear a helper whose loop breaks on the first mismatch, a file that names the helper only in a comment, or a verifier that calls it on the wrong value. Local helpers stay in the Apex reading-list arm and clear only after the four conditions in item 4 are read.
- **"`argon2` or `bcrypt` appears in the dependency manifest, so password storage is sound."** Rejected: a dependency is not a call site, and the artifact in the database is what the finding is about. This is the inference entry 5 of the checklist warns against, in a different costume.

## Proof recipes

Shared harness components are referenced by name and not restated here: the **registry-driven enumerator**, the **two-subject fixture**, and the **canary fixture set**. Their implementations live in `lenses/_harness.md`.

**Tier rule.** T1 is a proof the repository's own test command executes. T2 requires the auditor to stand up infrastructure the repository does not already stand up, and the user is asked every time.

**This lens is unusually well served by T1**, and that is worth saying in the report: cryptographic behavior is observable in-process. Every recipe below runs under `pytest` / `npm test` / `go test` with no network and no external service. There are two exceptions, each marked where it appears: R7's deployed-policy variant, and R4 on Apex, whose unit tests execute in an org rather than in-process.

**Harvest, do not reason.** The recurring failure of a crypto review is an argument about whether a nonce can repeat. Run the code two thousand times and look.

### R1 — Nonce uniqueness harvest (T1)

Call the repository's own encrypt entry point 2000 times against one key handle **with 2000 distinct plaintexts**, collect the nonce out of each ciphertext envelope, and assert `len(set(nonces)) == 2000`. Then repeat the harvest under each condition that changes the answer:

1. After re-importing the module, to catch a nonce bound at import.
2. From 16 threads.
3. From 16 processes.
4. Across `os.fork()` — parent and child each encrypt, and the union must still be distinct. This is the run that catches a buffered userspace generator; it will pass for `os.urandom`, Python `secrets` and Go `crypto/rand`, and that pass is a *result*, not a formality.
5. After restarting the object that owns a counter, if the construction is a counter — this is the reset condition from Checklist item 1 and it is the only way to observe it.

**On collision, prove the consequence rather than asserting it.** Take the two colliding ciphertexts and assert `C1 ^ C2 != P1 ^ P2`. That assertion *fails* when the nonce repeated, because under a CTR-based mode the keystreams cancel — print the recovered plaintext into the failure message so the finding carries its own evidence.

**Fails on:** a nonce assigned at module or object scope, a counter with no durable store, a caller-supplied constant. **Passes on:** a fresh draw inside the encrypt function, or a durable per-key counter with a distinct fixed field.

**Add a negative control.** Include one deliberately broken encryptor in the fixture set and assert the harvest *detects* it. A harness that finds nothing on a codebase whose entry point it failed to resolve looks exactly like a clean result; assert the harvested count against a checked-in number so a zero-row harvest cannot pass. The **registry-driven enumerator** supplies that count and the list of encrypt entry points to harvest, read out of the module rather than hand-listed, so an encryptor added later is harvested rather than silently skipped.

**Interrogate the identity in both directions before reporting either result — `len(set(nonces)) == 2000` can be satisfied by a broken construction and violated by a correct one.**

- **It passes while the nonce repeats** whenever the harvested slice is not actually the nonce. A wrong envelope offset yields 2000 distinct *ciphertext* prefixes from an encryptor that reuses one nonce for all of them. The fix is one assertion, not more samples: encrypt once with a fixture whose nonce you chose, and assert the harvested value equals that nonce byte for byte. Without it, the negative control is the only thing standing between a wrong offset and a clean report.
- **It fails while the construction is correct** under a deterministic AEAD. AES-GCM-SIV, AES-SIV and Deoxys-II derive a synthetic IV from the plaintext by design, so two equal plaintexts *must* produce the same value and the identity manufactures a Critical against exactly the construction item 1 recommends for determinism. Establish the construction before reading the count: under a deterministic AEAD this recipe is not applicable, and the assertion that belongs there instead is the small-domain equality check — seal every value in the field's actual domain and assert the ciphertext column is not a one-to-one recoding of the plaintext column. Same for an envelope that carries no nonce field at all (`age`, Rails `MessageEncryptor`): report "no per-message nonce to harvest", not a shortfall.

### R2 — Forged and mutated token table (T1)

Forge tokens **by hand** — base64url header and payload plus your own MAC — rather than with the library's `sign`, so you can produce tokens the library refuses to create. One row per mutation, each asserting the **authorization decision**, never a log line:

- `{"alg":"none"}` with an empty signature segment.
- HS256 keyed on the **exact PEM bytes** of the server's RSA public key, plus the DER and newline-stripped variants — the byte-for-byte form matters, because a verifier may accept one encoding and not another.
- Correct `alg`, wrong key.
- `kid`, `jku` and `x5u` pointing at an external host — taken from the **canary fixture set**, whose hosts are always `.test` or `.invalid` and therefore resolve nowhere — with sockets blocked and the HTTP client spied on. Assert **zero outbound calls**, not merely a rejection.
- RS256 downgraded to PS256 and to ES256.
- `exp` in the past, `nbf` in the future, wrong `aud`, wrong `iss`. Draw the wrong audience and the foreign signing key from the **two-subject fixture** rather than hand-editing a claim, so "accepted for the wrong tenant" is asserted against a principal the application really issued a token for — and so the fixture's own positive case covers the verifier that rejects everything.
- Signature segment dropped entirely, and truncated.

**Finish with one positive case**, otherwise a verifier that rejects everything passes the whole table.

**Fails on:** any verifier that accepts one of those rows — a `decode` standing in for a `verify`, a keyfunc that never inspects the token's method, an unpinned call on a library version that does not fail closed, `audience=` / `issuer=` never checked. **Passes on:** an explicit single-class algorithm list plus a statically configured JWKS source.

The same shape applies to any signed capability the application mints — a share link, an invite, a signed URL: flip the role claim, extend the expiry, swap the resource id, drop the signature, truncate, and append a duplicate parameter (`?perm=view&perm=edit`) to probe parser differentials between the signer and the consumer.

### R3 — Signed-request replay and timestamp boundary (T1)

Capture one genuinely valid signed request from the happy path, then six rows, each asserting **both** the status and the side effect:

1. Valid → 200, and exactly one row written or one mock call.
2. Body differing only in whitespace or key order, original signature → 401. This is what proves verification runs on the raw bytes rather than on `json.dumps(request.json)`.
3. One byte flipped → 401 **and** `mock.assert_not_called()`.
4. `timestamp = now − window − 1s` → reject; `now − window + 1s` → accept. This pins the boundary instead of guessing the constant.
5. Timestamp header deleted → reject. `now + 24h` → reject.
6. The same valid request delivered twice → the second is a no-op: one row, not two.

**Fails on:** a handler that 401s the replay *after* the write, or one that verifies a re-serialized body. **Passes on:** raw-body HMAC plus an idempotency key or a replay cache.

Row 6 straddles the boundary with `webhook-handler-integrity`; run it here because it is one test, and file the finding under whichever half broke.

### R4 — Comparison safety by tripwire, not by stopwatch (T1)

Do not ship a wall-clock timing benchmark as the gate. Assert instead that the constant-time API is the one that ran, using an operand that raises when compared the wrong way:

```python
class Tripwire(bytes):
    def __eq__(self, other):
        raise AssertionError("non-constant-time compare reached the signature")
```

Pass a `Tripwire` as the attacker-supplied signature, spy on `hmac.compare_digest` / `crypto.timingSafeEqual` / `hmac.Equal` / `subtle.ConstantTimeCompare`, and assert the spy was called and the tripwire never was. This turns "is the comparison constant-time" from a statistical question into a deterministic one.

**On Apex the tripwire does not exist, so combine a call-site read with an org test.** There is no operator overloading or monkey-patching to spy on the platform implementation. Prefer the built-in path: read that the verifier decodes the request signature to `Blob` and passes it with the expected MAC to `Crypto.areEqualConstantTime`, then test equal, first-byte-different, last-byte-different and unequal-length operands. Where a legacy project-local helper remains, run the same contract and additionally read its loop against item 4's four conditions. **Read the tier honestly**: `sfdx force:apex:test:run` executes in an org, so it is T1 only where the repository already runs Apex tests against one in CI, and T2 where the auditor would have to create a scratch org — ask, as the tier rule requires. Report both the call site and the test; a passing helper test on code the verifier does not call proves nothing.

A statistical timing test may be kept, marked `@pytest.mark.timing` and **non-gating**: it is flaky in CI and reviewers discount it.

### R5 — KDF parameters read back out of the store (T1)

Assert on the **stored artifact**, not on the call. Register a user through the application's own path, read the row back out of the database, and assert the prefix and its parameters:

- `$argon2id$v=19$m=19456,t=2,p=1` or stronger — parse `m`, `t` and `p` and compare numerically, so `m=8192` cannot pass a substring check.
- `$2b$` with cost ≥ 12 for a new deployment (≥ 10 as the floor).
- `pbkdf2_sha256$` with iterations ≥ 600000.
- scrypt with N ≥ 2¹⁷.

Two rows beyond the parameter check, because they are silent in production:

- **bcrypt truncation:** register with a 72-byte password, then authenticate with that password plus 40 more characters, and assert the login **fails**. It succeeds on an unmitigated bcrypt, which is the proof.
- **NUL truncation from naive pre-hashing:** find a password whose SHA-256 digest begins with `0x00` (search offline; it takes a few hundred tries), register with it, then authenticate with a *different* password whose digest also begins with `0x00`, and assert the login fails. It succeeds where the raw digest was passed to a bcrypt implementation that truncates at the NUL. Write the row to accept the other outcome as the same finding: on a binding that *rejects* a NUL in the password, the registration raises instead — assert that neither the second login succeeds nor the first registration silently swallows an error, so the row cannot pass by throwing.

### R6 — Ordering invariant on the decrypt path (T1)

Record call order in a shared list and assert the invariant directly:

```python
assert calls.index("verify_tag") < calls.index("unpad")
```

Then run the same path with a **deliberately corrupted tag** and assert the unpad, parse and deserialize spies were **never called at all**. An exception raised after the payload was parsed is the padding-oracle shape, and only the never-called assertion distinguishes it from a correct implementation.

### R7 — TLS configuration assertion against the constructed client (T1)

Build the client the application builds — call its factory — and assert on the resulting object rather than on the source text: `InsecureSkipVerify` is false, `MinVersion` is at least TLS 1.2, `RootCAs` is the pool the code intended, and for a server, `ClientAuth` is `RequireAndVerifyClientCert` with an explicit `ClientCAs`. Where the language does not expose the configuration, terminate a TLS handshake against a **locally generated, untrusted** self-signed certificate on `127.0.0.1` and assert the client refuses it.

**This is the other recipe with a T2 variant, and it is not a substitute:** asserting the *deployed* policy requires reaching the real endpoint. That is a remote host, which this project's hard rails forbid. Report the local result and record the deployed policy as an assumption.

### Not provable here, and reported as such every run

Name these in the coverage block rather than letting silence imply safety.

- **Whether a committed key is live or rotated.** `git log -p` narrows it; only the operator settles it.
- **The entropy of a runtime-supplied secret.** What the tests can prove is that the code *rejects* a short one — add that assertion where a length check exists, and report its absence where it does not.
- **How many messages a key has encrypted.** The SP 800-38D invocation cap is a runtime property. R1 proves the construction cannot repeat within the harvest; it cannot prove the key stays under the cap in production. Report the rotation story instead, and say plainly that a correct nonce construction was verified — a silent coverage block reads as if nothing was checked.
- **The deployed TLS policy** where a proxy, load balancer or mesh terminates outside this repository, and equally where no such component was found. Both directions are assumptions.
- **Whether the JWKS host is under the same control as the issuer.**
- **Whether the clock-skew tolerance the code sets is justified by the fleet.** R3 pins the boundary the code implements; it does not judge the constant.
- **The statistical timing measurement**, which is kept non-gating on purpose (R4).
