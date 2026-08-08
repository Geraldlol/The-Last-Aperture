---
name: mobile-app-security
title: Mobile application security
runs_in: fanout
activates_on:
  paths:
    - '**/app.json'
    - '**/app.config.{js,ts,cjs,mjs}'
    - '**/eas.json'
    - '**/metro.config.js'
    - '**/react-native.config.js'
    - '**/android/app/src/**/AndroidManifest.xml'
    - '**/android/app/build.gradle'
    - '**/android/app/build.gradle.kts'
    - '**/android/app/proguard-rules.pro'
    - '**/android/app/src/**/res/xml/network_security_config.xml'
    - '**/ios/**/Info.plist'
    - '**/ios/**/*.entitlements'
    - '**/ios/Podfile'
    - '**/ios/Podfile.lock'
    - '**/*.swift'
    - '**/*.{m,mm,h}'
    - '**/*.{kt,kts,java}'
    - '**/google-services.json'
    - '**/GoogleService-Info.plist'
    - '**/fastlane/**'
    - '**/.well-known/apple-app-site-association'
    - '**/.well-known/assetlinks.json'
    - '**/PrivacyInfo.xcprivacy'
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
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: consumed
      artifact_kinds: [apk, ipa]
      may_conclude: [secret-present-in-artifact, unexpected-artifact-content, vulnerable-component-present]
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
owns:
  - mobile-local-data-storage
  - platform-keystore-key-custody
  - secrets-in-mobile-binary
  - mobile-cleartext-and-ats-config
  - certificate-pinning-implementation
  - native-app-oauth-integration
  - deep-link-and-ipc-surface
  - webview-bridge-trust
  - mobile-build-and-runtime-flags
  - mobile-ui-and-notification-leakage
  - in-app-consent-mechanisms
  - privacy-manifest-and-store-declarations
  - ota-update-integrity
  - vendored-native-code-provenance
defers:
  authz-object-level: web-and-api
  authz-property-level: web-and-api
  authz-function-level: web-and-api
  rate-limiting-and-request-quotas: web-and-api
  xss-and-output-encoding: web-and-api
  open-redirect: web-and-api
  debug-and-admin-endpoint-exposure: web-and-api
  symmetric-encryption-and-nonce-handling: crypto-and-key-management
  password-hashing-and-kdf-parameters: crypto-and-key-management
  tls-and-certificate-validation: crypto-and-key-management
  oauth-oidc-flow-correctness: crypto-and-key-management
  asymmetric-scheme-pitfalls: crypto-and-key-management
  jwt-jws-and-jwks-verification: crypto-and-key-management
  legacy-hash-and-cipher-primitives: crypto-and-key-management
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

## Scope

This lens audits mobile application clients and the platform configuration that ships with them: React Native and Expo JavaScript, native iOS (Swift/Objective-C), native Android (Kotlin/Java), the Android manifest and Gradle build, the iOS `Info.plist` and entitlements, the network and privacy configuration files, the deep-link and IPC surface, and the store and over-the-air metadata that decides what actually reaches a device. Depth is greatest on React Native/Expo, the most common cross-platform stack.

Three facts drive everything below.

- **The device belongs to the attacker.** Every byte in the shipped bundle is readable, every local store is readable and writable on a rooted or jailbroken device, and every client-side check can be removed. Nothing here is a finding *because* that is true; findings are about what that fact reaches — a credential that works from anywhere, a server that trusts a client-supplied claim, a store that holds a token the platform offered to protect.
- **Configuration decides more than code does.** Cleartext policy, backup inclusion, component export, trust anchors and file protection are decided in the manifest, the plist and the network security config — and the values that matter are the ones in the **merged, release-variant** artifact, not the ones in the file you happened to open.
- **What ships is not what is in the repository.** Build variants, product flavors, source sets, the minifier, `__DEV__` elimination and the OTA channel all sit between the checkout and the binary. State which artifact your evidence came from, every time.

### Coverage this lens does not have

Say this in the coverage block rather than letting silence read as a clean result.

- **Flutter and Dart are not covered.** There is no Flutter content in this lens — no `flutter_secure_storage` accessibility check, no `--obfuscate`/`--split-debug-info` check, no platform-channel validation, no Dart HTTP client trust-callback check. If the repository under audit is a Flutter app, report its mobile surface as **unaudited**, name the missing checks, and do not emit a clean mobile result. **Expect to activate on a Flutter repository anyway:** the `*.dart` and `pubspec.yaml` path globs are gone, but the signals `flutter_secure_storage`, `dio` and `badCertificateCallback` are still live and `dio` alone is enough, and a Flutter project additionally matches the `AndroidManifest.xml`, `Info.plist`, `*.swift` and `*.{kt,kts,java}` anchors. Those anchors are real coverage — manifest, plist, IPC and keystore items all run. Dart is not. Matching is not coverage, and the three Dart signals are the ones with nothing behind them.
- **The shipped binary is not in scope, only the source of it.** Nothing here proves that the IPA or APK in the store was built from this checkout.
- **iOS device-side proofs need macOS and Xcode** and are simply unavailable on a Windows or Linux audit host. See `## Proof recipes`.

### Owns

| Topic | What that means here |
|---|---|
| `mobile-local-data-storage` | What is written to the app sandbox and in what form: `AsyncStorage`, MMKV, `SharedPreferences`, `UserDefaults`/plist, SQLite/Realm, files, and whether the value is a credential or regulated data. |
| `platform-keystore-key-custody` | Keychain and Android Keystore custody: accessibility class, access group, hardware backing, `setUserAuthenticationRequired`, and whether a key is bound to anything at all. |
| `secrets-in-mobile-binary` | Credentials compiled into the app: which strings are real credentials, which are public client identifiers, and why obfuscation moves neither. |
| `mobile-cleartext-and-ats-config` | The declared network policy: ATS keys in `Info.plist`, `android:usesCleartextTraffic`, `network_security_config.xml` including `<trust-anchors>` and `<debug-overrides>`. |
| `certificate-pinning-implementation` | Pin sets, backup pins, rotation, and whether pinning covers every HTTP client in the app. |
| `native-app-oauth-integration` | The mobile half of an OAuth client: which redirect the app registers, who else can claim it, whether a client secret is present in a public client, and whether the session ends up somewhere the platform protects. |
| `deep-link-and-ipc-surface` | Custom schemes, Universal Links and App Links, intent filters, exported components, `PendingIntent` mutability, intent redirection, ContentProviders, and every parameter that arrives through them. |
| `webview-bridge-trust` | What a `WebView`/`WKWebView` may navigate to, what it may read, and what native capability is exposed to whatever it loaded. |
| `mobile-build-and-runtime-flags` | `__DEV__`, `debuggable`, minification, dev-client and debugging surfaces, symbols and source maps, and anti-tamper controls. |
| `mobile-ui-and-notification-leakage` | Regulated data leaving through the clipboard, the app-switcher snapshot, a screenshot, a lock-screen notification, or an accessibility surface. |
| `in-app-consent-mechanisms` | The mechanism: whether an SDK is initialized before the user answered, and whether the answer is honored — not whether the legal basis is valid. |
| `privacy-manifest-and-store-declarations` | `PrivacyInfo.xcprivacy` and the Play Data Safety declaration: present, and consistent with what the code actually collects. |
| `ota-update-integrity` | Any channel that can change executing code after install, and whether that channel verifies a signature. |
| `vendored-native-code-provenance` | Native binaries and sources carried in the repository or pulled from a mutable ref, and what they are trusted to do. |

### Does not own

Do not raise findings on these. Where the code shows one, note it in the candidate's `impact` as an aggravator and hand it to the owning lens with the file and line.

- **web-and-api** — `authz-object-level`, `authz-property-level`, `authz-function-level`, `rate-limiting-and-request-quotas`, `xss-and-output-encoding`, `open-redirect`, `debug-and-admin-endpoint-exposure`. This is where "the server trusted the client" lands. A backend that accepts a client-supplied user id instead of deriving identity from the token, an entitlement the server never re-checks, a client-persisted counter the server takes at face value: the app is the *evidence*, the finding is theirs. DOM XSS inside a WebView is theirs too — the bridge that hands native capability to the page is `webview-bridge-trust` here.
- **crypto-and-key-management** — `symmetric-encryption-and-nonce-handling`, `password-hashing-and-kdf-parameters`, `tls-and-certificate-validation`, `oauth-oidc-flow-correctness`, `asymmetric-scheme-pitfalls`, `jwt-jws-and-jwks-verification`, `legacy-hash-and-cipher-primitives`. **`tls-and-certificate-validation` explicitly includes the mobile trust-bypass code** — an unconditional `URLSessionDelegate` trust callback, an empty `checkServerTrusted`, an always-true `HostnameVerifier` — by that lens's own statement. Detect them here (this lens is the one that activates on a mobile repo) and file them under that slug. **If `crypto-and-key-management` did not activate in this run, still report the finding, tagged with its slug** — a disabled chain validation is Critical and must not be lost at a lens boundary. If it did activate, hand it over and do not file it twice.
- **cicd-and-supply-chain** — `dependency-pinning-and-lockfiles`, `ci-secret-and-token-handling`, `package-dependency-cves`, `sbom-generation-and-attachment`.
- **cloud-and-iac** — `baas-security-rules`, `iam-policy-and-privilege-scope`, `object-storage-exposure`. Backend-as-a-service rules are the only control standing between a mobile client and the database, and they are graded there.
- **llm-and-ai** — `prompt-injection`, `model-artifact-provenance`.
- **salesforce-platform** — `apex-sharing-declaration`.
- **hipaa-and-phi** — `phi-classification`, `phi-severity-uplift`. Whether a stored value is PHI, and the uplift that follows, are decided there. This lens reports the store, the key and the plaintext.
- **privacy-and-data-protection** — `lawful-basis-and-consent-capture`, `processor-contracts-and-dpa`, `childrens-data-and-age-assurance`, `retention-lawfulness-and-deletion-completeness`.
- **threat-modeling** — `attacker-profile-model`, `trust-boundary-inventory`.

**Three OWASP Mobile Top 10 (2024) categories are routed wholesale.** They are named here because an auditor working the M-list will look for them; the content lives in the owning lens and is not restated.

- **M2 Inadequate Supply Chain Security → `cicd-and-supply-chain`.** Untrusted or unpinned modules, transitive native code, build pipelines that resolve "latest", and signing keys committed to the repository or passed around in chat, email or ticket attachments are all theirs (`dependency-pinning-and-lockfiles`, `package-dependency-cves`, `ci-secret-and-token-handling`). **Two pieces stay here**: whether an over-the-air channel verifies a signature (`ota-update-integrity`, item 13) and native code carried in this repository or pulled from a mutable ref (`vendored-native-code-provenance`, item 14).
- **M6 Inadequate Privacy Controls → `privacy-and-data-protection`.** Whether a transfer has a lawful basis, whether consent was validly obtained, whether a purpose is legitimate, retention and deletion: all theirs. **Three pieces stay here**: the consent *mechanism* — an SDK initialized before the user answered (`in-app-consent-mechanisms`, item 11); the store declarations (`privacy-manifest-and-store-declarations`, item 12); and data leaving through a UI surface (`mobile-ui-and-notification-leakage`, item 10). Crash reports and analytics payloads carrying tokens or regulated data are a shared case: the *sink list* is theirs, the on-device capture point is item 10. Background collection is theirs on purpose and lawful basis; what this lens hands over is the declaration, by name — `ACCESS_BACKGROUND_LOCATION` in the merged manifest, `NSLocationAlwaysAndWhenInUseUsageDescription` in `Info.plist`, a `UIBackgroundModes` entry — with the file and line, and the note that a declared permission is capability, not behavior.
- **M10 Insufficient Cryptography → `crypto-and-key-management`.** Custom constructions, ECB, static IVs, nonce handling, KDF parameters and legacy primitives are all theirs. **One piece stays here**: where the key lives and what binds it (`platform-keystore-key-custody`, item 2). One correction travels with the routing, because getting it wrong produces a confident wrong answer on a mobile app: **the 600,000-iteration PBKDF2-HMAC-SHA256 figure is a server-side password-verification parameter, and applying it to an on-device KDF is a misapplication.** On a device the answer is a hardware-backed key in the Keystore or Secure Enclave; if a KDF is genuinely unavoidable, argon2id, with the parameters decided by the crypto lens. Do not cite an "OWASP 2023" edition for any of these numbers — the Password Storage Cheat Sheet is a continuously updated document with no such edition; cite it by URL and retrieval date, and expect a team to cite RFC 9106's divergent figures instead.

### What cannot be determined from a repository

State these as assumptions with a verification step, never as findings, and never as clearances.

- **What the merged manifest says.** Library manifests contribute components, permissions and attributes. `AndroidManifest.xml` in `app/src/main/` is an input, not the answer. Name the variant you resolved, or say you could not.
- **Which build variant, flavor and source set ships.** A `src/debug/` manifest, a `Debug` plist, a staging flavor and a Gradle `buildTypes` block can each hold the value you are about to report — or the safe one.
- **Whether the store listing, the signing identity and the OTA channel are what the repository says.** Store configuration, provisioning profiles and update-server ownership are runtime facts.
- **Whether the device has hardware-backed key storage.** `KeyGenParameterSpec` with `setIsStrongBoxBacked(true)` requests StrongBox; whether the fleet has it, and whether the code falls back silently, is a runtime question.
- **What the backend enforces.** Absent the server code, "the server re-checks this" is an assumption. Write it down as one; do not clear a client-authoritative-state finding on it.
- **Whether a permission or SDK is actually exercised.** A declared permission or a linked SDK is capability, not behavior.

## Activation coverage

Platform metadata and application-language coverage are separate. Matching a
mobile repository must not silently promote an uncovered application stack to a
clean result.

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| React Native, Expo, Metro and EAS | PARTIAL | `mobile-local-data-storage` | Storage and configuration checks exist, but app.config uses a compound extension activator and the family is not uniformly measured |
| React Native Web | NOT ASSESSED | — | The signal activates the lens, but browser-only React Native Web behavior has no dedicated path |
| Android manifest, Gradle, network and platform API surfaces | COVERED | `mobile-cleartext-and-ats-config` | detector:mobile-cleartext-and-ats-config |
| iOS plist, entitlements, CocoaPods, privacy manifest and universal links | PARTIAL | `privacy-manifest-and-store-declarations` | Actionable platform checks exist; native runtime behavior remains incomplete |
| Unscoped Swift and Objective-C source globs | PARTIAL | `platform-keystore-key-custody` | Native API checks exist only after iOS corroboration; these broad globs also activate non-mobile source trees |
| Unscoped Kotlin, KTS and Java source glob | PARTIAL | `mobile-build-and-runtime-flags` | Android API checks exist only after platform corroboration; the broad glob also activates server-side JVM projects |
| Flutter and Dart application signals | NOT ASSESSED | — | Signals still activate the lens, but Dart behavior has no executable coverage |
| Fastlane repository paths | NOT ASSESSED | — | Fastlane activates inventory only; this lens has no dedicated actionable Fastlane review path |

## Checklist

Work the items in order. Every item that files a finding names the slug it files under. Two items file nothing of their own and each says so where you will read it: item 0 is a sweep block whose output is candidates, stated in the rules that open it, and item 15 is routed to other lenses, named in its heading. Treat every grep hit as a candidate to trace, never as a finding.

### 0. Highest-yield sweeps

**Five mechanical rules, each of which was a real defect in this sweep set before it was fixed.**

**(a) Every sweep is case-insensitive or explicitly named in both cases — and the spelling that breaks it is usually the *other dialect's*, not the other letter case.** The same setting has two idiomatic names on the same platform: Groovy `debuggable true` versus Kotlin-DSL `isDebuggable = true`, the react-native-webview prop `allowFileAccess` versus the Java setter `setAllowFileAccess`, `apiKey` versus `STRIPE_SECRET_KEY`, `hostnameVerifier` versus `setHostnameVerifier`. A pattern that reaches the right file and cannot read its dialect is a silent all-clear, so for every literal ask what the other language on the same platform calls it. Sweeps 5, 7 and 14 are the only case-sensitive ones and are so deliberately: every token in them is a fixed-case XML attribute name (`android:exported`) or a fixed-case platform symbol (`PendingIntent.getBroadcast`, `CFBundleURLSchemes`, `@ReactMethod`), for which `-i` would add noise and no reach.

**(b) Every sweep searches `.` and narrows with `--glob` — never a bare filename.** Two failures, both silent. `rg PATTERN` with no path reads *stdin* when stdin is not a terminal, so the same command that works in your shell hangs or returns nothing from a script or a CI step. And a **named path that does not exist makes ripgrep exit 2 even when the pattern matched in a path that did exist** (measured, ripgrep 14.1.1), so `rg X app.json app.config.* || echo "NOT CONFIGURED"` prints its fallback directly underneath its own hit. `.` plus a glob also reaches `apps/mobile/app.json` in a monorepo, which a bare `app.json` never does.

**(c) Every repository traversal carries `--hidden`.** ripgrep prunes hidden directories before it applies `--glob`, so native projects, generated configuration and nested app roots under a dot-directory otherwise vanish silently. `--hidden` still excludes `.git`; no companion exclusion is needed.

**(d) No sweep filters its own output.** There is no `rg -v` anywhere below, and adding one is how a sweep starts reporting clean on vulnerable code — see the `PendingIntent` note.

**(e) A `||` fallback may not state a verdict.** `rg … || echo "no X"` fires when the sweep ran correctly and found nothing **and also when it could not have found anything** — wrong case, wrong dialect, no matching file in the tree, exit 2 from a missing path. Those are different results and only one of them is evidence. Every fallback below therefore says what it searched and tells you to confirm the file set (`rg --files --hidden --glob '…' .`) before reading it as clean; none of them asserts a build outcome, a platform default or a clean state on its own.

```bash
# unencrypted local stores, and the keys written to them (incl. plaintext SQLite/Realm)
rg -ni --hidden --glob '!**/node_modules/**' \
  -e "AsyncStorage\.(setItem|multiSet|mergeItem|multiMerge)" \
  -e "new MMKV\(" \
  -e "UserDefaults|@AppStorage|NSUserDefaults|\.set(Value)?\([^)]*forKey" \
  -e "getSharedPreferences\(|: *SharedPreferences|\.edit\s*[({]|putString\(" \
  -e "openDatabase|expo-sqlite|react-native-sqlite-storage|new Realm\(|Realm\.open|WatermelonDB" .

# the secure stores and the encrypted-at-rest options, so you can tell what was NOT
# used for the value you found. Every token here is a *safe* state — read it that way.
rg -ni --hidden --glob '!**/node_modules/**' \
  -e "SecureStore\.setItemAsync|react-native-keychain|Keychain\.setGenericPassword|SecItemAdd" \
  -e "EncryptedSharedPreferences|MasterKey\.Builder|KeyGenParameterSpec|EncryptedFile" \
  -e "kSecAttrAccessible|SecAccessControl|SQLCipher|openHelperFactory|SupportFactory|encryptionKey" .

# declared network policy — read the merged, release-variant file.
# No `android:` prefix on the attribute names: the same keys appear unprefixed in an
# Expo config plugin (expo-build-properties) and in Gradle manifestPlaceholders.
rg -ni --hidden \
  -e "NSAppTransportSecurity|NSAllowsArbitraryLoads|NSExceptionDomains" \
  -e "usesCleartextTraffic|networkSecurityConfig|cleartextTrafficPermitted" \
  -e "<debug-overrides>|<trust-anchors>|certificates src=" .

# trust bypasses in code (file under crypto-and-key-management: tls-and-certificate-validation).
# SecTrustEvaluate is here deliberately: it also matches the *correct* SecTrustEvaluateWithError,
# and the whole question is whether the result is checked. Read each hit.
rg -ni --hidden \
  -e "URLCredential\(trust:|\.useCredential|serverTrust|SecTrustEvaluate|SecTrustSetPolicy" \
  -e "checkServerTrusted|X509TrustManager|sslSocketFactory\(" \
  -e "hostnameVerifier|ALLOW_ALL_HOSTNAME_VERIFIER|allowsAnyHTTPSCertificate" .

# IPC and deep-link surface, and the JS code-execution sink at the end of it.
# `func application\([^)]*open url:` is the shape Swift source actually has —
# the selector spelling `application(_:open:` appears in documentation, never in code.
# `<intent-filter` is deliberately unclosed: `<intent-filter android:priority="999">`
# is a real shape and `<intent-filter>` cannot match it.
rg -n --hidden \
  -e "android:exported|<intent-filter|android:autoVerify|android:grantUriPermissions" \
  -e "PendingIntent\.(getActivity|getBroadcast|getService|getForegroundService)" \
  -e "Linking\.(addEventListener|openURL|getInitialURL|useURL)|useLinkingURL" \
  -e "CFBundleURLSchemes|func application\([^)]*open url:|openURLContexts|onOpenURL" \
  -e "\beval\(|new Function\(" .

# WebView trust. The FIRST arm is the component itself: item 8's highest-value question
# is an *absence* one, and a sweep that matches only props cannot see
# `<WebView source={{uri: props.url}} />` with no other prop at all.
# `-i` is load-bearing and is rule (a) in its purest form: `allowFileAccess`,
# `allowUniversalAccessFromFileURLs` and `mixedContentMode` are the react-native-webview
# prop and Kotlin property spellings, while Java writes `setAllowFileAccess(true)`,
# `setAllowUniversalAccessFromFileURLs(true)` and `setMixedContentMode(...)` — and a
# layout-declared WebView (`findViewById`) has no `<WebView` or `WebView(` in the .java
# file either, so without `-i` that file returns nothing at all. The cost is matching a
# lower-case `<webview` in HTML, which is an over-report and not a clearance.
rg -ni --hidden \
  -e "<WebView|react-native-webview|WKWebView|WebView\(|webView\.settings" \
  -e "originWhitelist|injectedJavaScript|onMessage|onShouldStartLoadWithRequest|setSupportMultipleWindows|onOpenWindow" \
  -e "addJavascriptInterface|@JavascriptInterface|WKUserContentController|add\(scriptMessageHandler" \
  -e "allowFileAccess|allowUniversalAccessFromFileURLs|allowingReadAccessToURL|mixedContentMode|loadHTMLString|loadDataWithBaseURL" .

# the native bridge surface (item 14): a method reachable from JavaScript that
# dispatches on a caller-supplied command string is High, Critical if the string
# can come from a deep link, a WebView message or a server response.
rg -n --hidden \
  -e "@ReactMethod|RCT_EXPORT_METHOD|RCT_EXPORT_MODULE|ReactContextBaseJavaModule|TurboModule" \
  -e "NativeModules\.|requireNativeModule\(|ModuleDefinition|AsyncFunction\(" .

# build and runtime flags. `debuggable` is deliberately unprefixed, and `-ni` is what
# makes it reach both dialects: a release `buildTypes { release { debuggable true } }`
# in Groovy `build.gradle`, or `getByName("release") { isDebuggable = true }` in Kotlin
# DSL, produces a debuggable APK and appears in NO source manifest, so
# `android:debuggable` alone cannot find it and a case-sensitive `debuggable` cannot
# read the Kotlin-DSL spelling.
rg -ni --hidden \
  -e "__DEV__|debuggable|allowBackup|dataExtractionRules|expo-dev-client|sourceMap|setWebContentsDebuggingEnabled" \
  -e "extraPackagerArgs|EXTRA_PACKAGER_ARGS|bundleCommand|BUNDLE_COMMAND|project\.ext\.react|react-native-xcode\.sh" \
  -e "transformerPath|babelTransformerPath|customSerializer|SKIP_BUNDLING|FORCE_BUNDLING" \
  -e "developmentClient|gradleCommand|buildConfiguration|--dev|--minify" .

# candidate credentials in shipped config (classify before reporting — see item 3).
# `-i` is load-bearing: `apiKey` and `STRIPE_SECRET_KEY` are the real shapes.
# `[A-Za-z_]*` after the name token is what lets `SECRET_KEY = "..."` match at all.
# Arms 2-5 are name-independent, because a service-account key's field is
# `private_key` and a Stripe secret's variable may be called anything.
rg -ni --hidden --glob '!**/node_modules/**' -g '!**/*.lock' \
  -e "(api[_-]?key|client[_-]?secret|secret|token|password|credential)[A-Za-z_]*['\"]?\s*[:=]\s*['\"][A-Za-z0-9_\-]{16,}" \
  -e "service[_-]?role|private_key|-----BEGIN [A-Z ]*PRIVATE KEY|type['\"]?\s*:\s*['\"]?service_account" \
  -e "AIza[0-9A-Za-z_\-]{35}|sk_live_|rk_live_|sk-[A-Za-z0-9]{20,}" \
  -e "ghp_|gho_|ghu_|ghs_|github_pat_|xox[baprs]-|AKIA[0-9A-Z]{16}|glpat-" \
  -e "eyJ[A-Za-z0-9_-]{10,}\." .
```

Six of these questions are **absence** questions and a grep for the literal answers the wrong one. Run these too:

```bash
# OTA code signing: the dangerous state has no literal at all. Globs, not bare
# filenames, per rule (b) — a bare `app.json app.config.*` misses `apps/mobile/app.json`
# in a monorepo and exits 2 when `app.config.*` is absent, which fires the fallback
# underneath its own hit.
rg -ni --hidden "codeSigningCertificate" --glob '**/app.json' --glob '**/app.config.*' . \
  || echo "no codeSigningCertificate in any Expo config matched — confirm one was searched (rg --files --hidden --glob '**/app.json' --glob '**/app.config.*' .) before reading this as unsigned updates (item 13) rather than as an app with no Expo config at all"

# allowBackup: unset means true on the platforms where Auto Backup applies
rg -ni --hidden "allowBackup" --glob '**/AndroidManifest.xml' . \
  || echo "no allowBackup attribute in any AndroidManifest matched — if a manifest WAS searched this is the permissive default; if none was (an Expo managed project with no android/ directory, a prebuild-only tree) the question is unanswered, not clean. Say which, and resolve it on the merged release manifest"

# debuggable release build: the artifact is Gradle, not a manifest. Two traps on one
# line, and they compound — the glob decides which files are reached and the pattern
# decides which dialect can be read, so getting either wrong prints an all-clear.
# GLOB: ripgrep's globset silently DROPS the empty branch of a brace alternate, so
# `build.gradle{,.kts}` behaves as `build.gradle.kts`: it matches Kotlin-DSL projects
# and never sees the more common Groovy `build.gradle`. Measured on ripgrep 14.1.1 —
# it does not match zero files, which is the trap: the sweep returns hits on some
# repos, so it looks like it works while being blind to the majority case. Even a
# non-empty `{a,b}` alternate dies silently under the grep fallback, whose --include
# has no brace expansion. Use one repeated --glob per name, never braces.
# PATTERN: `-i` is mandatory. Kotlin DSL writes `isDebuggable = true`, which a
# case-sensitive `debuggable` cannot match — so the spelled-out glob would reach the
# Kotlin-DSL file and the pattern would then report it clean.
rg -ni --hidden "debuggable" --glob '**/build.gradle' --glob '**/build.gradle.kts' . \
  || echo "no debuggable/isDebuggable line in any Gradle file matched — confirm one was searched (rg --files --hidden --glob '**/build.gradle' --glob '**/build.gradle.kts' .); this establishes nothing about the shipped build either way, so resolve android:debuggable on the merged release manifest"

# what the shipped bundle was actually built with (item 9). `--dev true` is the signal;
# `--minify false` is NOT — react-native-xcode.sh adds it itself on every Hermes release
# build, so reading it as a finding produces a false positive per app.
# The token set is deliberately IDENTICAL to the build-flag arms of the sweep above, and
# must stay that way: this command is the one whose absence an auditor reads as the
# `dev: false` precondition of false positive 1, and every token item 9 names as an
# artifact that decides it — `developmentClient`, `gradleCommand`, `buildConfiguration`,
# `SKIP_BUNDLING`, `FORCE_BUNDLING`, `project.ext.react`, `react-native-xcode.sh` —
# has to be in it. A subset here clears the branch on a repo whose only deviation is an
# EAS profile with `developmentClient: true` or a `SKIP_BUNDLING=1` build phase.
rg -ni --hidden \
  -e "extraPackagerArgs|EXTRA_PACKAGER_ARGS|bundleCommand|BUNDLE_COMMAND|project\.ext\.react|react-native-xcode\.sh" \
  -e "transformerPath|babelTransformerPath|customSerializer|SKIP_BUNDLING|FORCE_BUNDLING" \
  -e "developmentClient|gradleCommand|buildConfiguration|--dev|--minify" \
  --glob '**/build.gradle' --glob '**/build.gradle.kts' --glob '**/metro.config.*' \
  --glob '**/eas.json' --glob '**/*.pbxproj' --glob '**/package.json' . \
  || echo "none of these tokens appear in the Gradle/Metro/EAS/Xcode/package.json files matched — this does NOT establish dev:false. Confirm which files were searched (rg --files --hidden --glob '**/build.gradle' --glob '**/build.gradle.kts' --glob '**/metro.config.*' --glob '**/eas.json' --glob '**/*.pbxproj' --glob '**/package.json' .) and read the bundling build phase and the CI job that produces the shipped bundle; false positive 1's precondition has to be established, not inferred from a quiet sweep"

# PendingIntent mutability: below targetSdk 31 the mutable default has no literal.
# List every construction site and read the flags argument yourself. Do NOT pipe this
# through `rg -v "FLAG_IMMUTABLE"`: one trailing `// TODO: FLAG_IMMUTABLE` on the same
# line deletes the vulnerable construction from the output and the sweep reports clean.
rg -n --hidden "PendingIntent\.(getActivity|getBroadcast|getService|getForegroundService)\s*\(" .

# console stripping: the safe state is a build-config line, not a code pattern.
# Globs again, per rule (b): with a `babel.config.js` that DOES configure stripping and
# no `metro.config.*` in the tree, the bare-filename form exits 2 and prints the
# not-stripped verdict directly under the line that disproves it.
rg -ni --hidden "transform-remove-console|drop_console" --glob '**/babel.config.*' --glob '**/metro.config.*' . \
  || echo "no console-stripping option in any babel/metro config matched — confirm one was searched (rg --files --hidden --glob '**/babel.config.*' --glob '**/metro.config.*' .); if a config WAS searched, console.* ships in the release bundle"
```

### 1. Local data storage (`mobile-local-data-storage`) — MASVS-STORAGE

**Name the store, quote the key, classify the value.** "Unencrypted storage" is not a finding on its own; these are the intended stores for theme, locale, onboarding flags, a feature-flag cache, drafts. The finding exists when the value is a credential, a session or refresh token, an encryption key, or regulated data — and the finding must say which key holds it.

The backing stores, because the proof depends on them and the common description is wrong:

- **`AsyncStorage` is not "a JSON file".** On Android it is SQLite: `/data/data/<pkg>/databases/RKStorage`, table `catalystLocalStorage` — **unless `AsyncStorage_useNextStorage=true` is set in `gradle.properties`**, in which case it is a Room database named `databases/AsyncStorage` and a proof pointed at `RKStorage` finds nothing and passes on a vulnerable app. On iOS the current default is `<sandbox>/Library/Application Support/<bundleID>/RCTAsyncLocalStorage_V1` (there is a one-time migration from the older `Documents/RCTAsyncLocalStorage_V1`), holding a `manifest.json` plus one file per large value — confirm the directory for the version in the lockfile and search both the `Library` and `Documents` trees rather than asserting one path. Point the proof at those paths; a sweep for a JSON blob finds nothing on Android and reports clean.
- **`react-native-mmkv` is plaintext unless constructed with an `encryptionKey`**, and an `encryptionKey` hardcoded in JavaScript is not protection — it ships in the same bundle as the data.
- **`SharedPreferences`** is a plaintext XML file in the app sandbox unless it is `EncryptedSharedPreferences`.
- **`UserDefaults` / `NSUserDefaults`** is a plaintext plist in the sandbox.
- **SQLite and Realm files** are plaintext without SQLCipher or Realm encryption. The findable openers are `openDatabase`/`openDatabaseSync` (`expo-sqlite`, `react-native-sqlite-storage`), `new Realm(`/`Realm.open`, and a WatermelonDB adapter; the safe states that would appear alongside them are `SQLCipher`, a Room database built with `.openHelperFactory(SupportFactory(passphrase))` — **those two symbols, `openHelperFactory` and `SupportFactory`; there is no `supportOpenHelperFactory` method** and searching for one returns zero on correctly encrypted code — and an `encryptionKey` on the Realm configuration. They are additionally covered by Android file-based encryption and iOS Data Protection, which is why an unencrypted database is *not* automatically a finding — escalate on a concrete exposure path: inclusion in Auto Backup or a device-transfer/iTunes backup, a shared container or an exported `ContentProvider`, `NSFileProtectionNone`, or a stated encryption-at-rest requirement.

```detector
match: |
  import AsyncStorage from '@react-native-async-storage/async-storage';

  export async function persistSession(session) {
    await AsyncStorage.setItem('auth.refreshToken', session.refreshToken);
    await AsyncStorage.setItem('auth.accessToken', session.accessToken);
  }
nomatch: |
  import * as SecureStore from 'expo-secure-store';
  import AsyncStorage from '@react-native-async-storage/async-storage';

  export async function persistSession(session) {
    await SecureStore.setItemAsync('auth.refreshToken', session.refreshToken, {
      keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
    });
    await AsyncStorage.setItem('ui.lastTab', session.lastTab);
  }
```

```detector
match: |
  import { MMKV } from 'react-native-mmkv';

  export const store = new MMKV({ id: 'user-cache' });
  store.set('patient.mrn', profile.medicalRecordNumber);
nomatch: |
  import { MMKV } from 'react-native-mmkv';
  import { getOrCreateDeviceKey } from './keystore';

  export const store = new MMKV({
    id: 'user-cache',
    encryptionKey: getOrCreateDeviceKey(),
  });
  store.set('ui.lastTab', profile.lastTab);
```

```detector
match: |
  val prefs = context.getSharedPreferences("session", Context.MODE_PRIVATE)
  prefs.edit().putString("refresh_token", token).apply()
nomatch: |
  val masterKey = MasterKey.Builder(context)
      .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
      .build()
  val prefs = EncryptedSharedPreferences.create(
      context,
      "session",
      masterKey,
      EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
      EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
  )
  prefs.edit().putString("refresh_token", token).apply()
```

**Backup inclusion is a separate question from encryption and it has no literal in the dangerous case.** `android:allowBackup` **defaults to true**, so a manifest with no such attribute is the permissive state. Read `android:dataExtractionRules` (cloud backup and device-to-device transfer are configured separately) and `android:fullBackupContent`, and resolve them in the merged manifest. Be precise about the extraction path you are claiming: the classic `adb backup` route was restricted on newer Android releases, so say whether you mean Auto Backup to the user's cloud account, device-to-device transfer, or `adb backup` against an older or debuggable build. On iOS the equivalent is not one mechanism but three, and they are routinely conflated — send the auditor to the right artifact:

- **A Keychain item without the `ThisDeviceOnly` suffix on its accessibility class is restorable from an encrypted backup onto a *different* device.** That is the real and sufficient point. It is a separate question from iCloud Keychain *sync*, which additionally requires `kSecAttrSynchronizable` on the item — do not assert sync from the absence of `ThisDeviceOnly`.
- **File backup inclusion is decided by location and by an explicit exclusion**, not by encryption: `Caches/` and `tmp/` are excluded by the platform, everything else in the container is included unless the code sets `isExcludedFromBackup` (`NSURLIsExcludedFromBackupKey`). Grep for that key, and for whether the store's path is under `Caches`.
- **`NSFileProtection*` is the at-rest encryption class and has no bearing on backup inclusion.** `NSFileProtectionNone` is an item 1 finding on its own terms; it is not evidence about backups.

```detector
match: |
  <application
      android:name=".MainApplication"
      android:label="@string/app_name">
      <!-- android:allowBackup not declared: Auto Backup is on -->
  </application>
nomatch: |
  <application
      android:name=".MainApplication"
      android:label="@string/app_name"
      android:allowBackup="false"
      android:dataExtractionRules="@xml/data_extraction_rules">
  </application>
```

**Logs are a store.** `console.log` is **not** removed from a React Native release build by default; it is removed only when the build configures it — `babel-plugin-transform-remove-console`, or a minifier `drop_console` option. Grep the build config for that line, not the code for the call. On the native side the equivalents are `Log.d`/`NSLog`/`print`, which are readable by anything with logcat access on a debuggable build and are captured by crash reporters. Report the value that reaches the sink, not the presence of logging.

```detector
match: |
  // babel.config.js
  module.exports = {
    presets: ['module:metro-react-native-babel-preset'],
  };
nomatch: |
  // babel.config.js
  module.exports = {
    presets: ['module:metro-react-native-babel-preset'],
    env: {
      production: {
        plugins: ['transform-remove-console'],
      },
    },
  };
```

### 2. Platform key custody (`platform-keystore-key-custody`) — MASVS-STORAGE, MASVS-CRYPTO

The correct destinations, and the property that makes each one correct:

- **iOS Keychain** with a deliberate accessibility class. `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` for secrets that are only needed in the foreground, `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` for tokens a background task must use. The `ThisDeviceOnly` suffix is what keeps the item from being restored onto a different device from a backup; `kSecAttrAccessibleAlways` and its variants are the finding. iCloud Keychain *sync* is the separate `kSecAttrSynchronizable` question — item 1 states the distinction, and do not collapse the two. Check `kSecAttrAccessGroup` too — a shared access group widens the item to every app in the group.
- **Android Keystore**, directly or through `EncryptedSharedPreferences`/`EncryptedFile`. The key material never leaves the Keystore; what you are auditing is the `KeyGenParameterSpec`.
- **React Native**: `react-native-keychain` or `expo-secure-store`, both of which reach the platform stores. **Reaching the platform store is not the whole rule — the accessibility rule above applies to the wrapper too, and neither wrapper defaults to `ThisDeviceOnly`.** `expo-secure-store`'s default `keychainAccessible` is `WHEN_UNLOCKED`; `react-native-keychain` has its own `accessible` and `accessGroup` options. Read the options actually passed at each call site, not the package name: a default `SecureStore.setItemAsync` write is restore-eligible on another device by this item's own test. Other wrappers the frontmatter matches on — `react-native-encrypted-storage`, `react-native-sensitive-info` — reach the platform stores only in some configurations, so a "secure"-sounding package name clears nothing: read which backend the version in the lockfile uses **on each platform** before treating the stored value as protected, and say which one you established.

**A biometric prompt is not custody.** `LAContext().evaluatePolicy` and `BiometricPrompt` that return a boolean the app then acts on are a UI gate — removable on a device the attacker controls, and irrelevant to the bytes at rest. Custody means the *key* is bound: `setUserAuthenticationRequired(true)` on the `KeyGenParameterSpec` (with a validity window and, where offered, `setInvalidatedByBiometricEnrollment(true)`), or a `SecAccessControl` with `.userPresence`/`.biometryCurrentSet` on the Keychain item. Grade the two differently and never let the presence of a prompt clear a storage finding.

```detector
match: |
  let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrAccount as String: "refreshToken",
      kSecValueData as String: tokenData,
      kSecAttrAccessible as String: kSecAttrAccessibleAlways,
  ]
  SecItemAdd(query as CFDictionary, nil)
nomatch: |
  let query: [String: Any] = [
      kSecClass as String: kSecClassGenericPassword,
      kSecAttrAccount as String: "refreshToken",
      kSecValueData as String: tokenData,
      kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
  ]
  SecItemAdd(query as CFDictionary, nil)
```

```detector
match: |
  val spec = KeyGenParameterSpec.Builder(
      "session_key",
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
  )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .build()
nomatch: |
  val spec = KeyGenParameterSpec.Builder(
      "session_key",
      KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
  )
      .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
      .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
      .setUserAuthenticationRequired(true)
      .setInvalidatedByBiometricEnrollment(true)
      .build()
```

**Do not use a device identifier as a key or as key material.** `identifierForVendor` (IDFV), `ANDROID_ID`, an advertising id and an installation id are readable by the app and are not secrets. This is a `platform-keystore-key-custody` finding here; the derivation and parameter questions that follow belong to `crypto-and-key-management`.

```detector
match: |
  val androidId = Settings.Secure.getString(contentResolver, Settings.Secure.ANDROID_ID)
  val key = SecretKeySpec(androidId.toByteArray(Charsets.UTF_8).copyOf(32), "AES")
  val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
nomatch: |
  val keyStore = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
  val key = (keyStore.getEntry("session_key", null) as KeyStore.SecretKeyEntry).secretKey
  val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
```

### 3. Credentials in the shipped app (`secrets-in-mobile-binary`) — MASVS-CODE

Everything in the bundle is extractable: the JavaScript bundle, `strings` over the binary, the asset catalog, `google-services.json`, `GoogleService-Info.plist`, `Info.plist`, `BuildConfig`, `gradle.properties` and every `.env` the bundler inlined. **Obfuscation is not a control** — neither ProGuard/R8 name mangling nor Hermes bytecode. Hermes is a compilation target, not encryption; `hbctool`, `hermes-dec` and `hasmer` recover it, subject to matching the bytecode version. Name a tool you can point at, and say which bytecode version you matched; do not cite a decompiler you have not run.

**Classify before grading. This is the single highest-volume false positive in mobile work.** Many mobile SDK keys are public client identifiers designed to ship in the binary: the Firebase `apiKey`, Maps/Places SDK keys, a Sentry DSN, a *publishable* payment key, a *public* IAP-wrapper SDK key, an OAuth **client ID**, an Expo project id, analytics write keys. Their presence is not the vulnerability. Ask one question: **does this credential authorize privileged reads or writes on its own?**

- If **yes** — a provider or admin API key, a service-account key, a signing key, a database or object-storage key with write scope, an OAuth **client secret** — it is Critical, unconditionally, and no obfuscation moves it. See `## Severity calibration`.
- If **no**, do not file "hardcoded secret". File the control that is actually missing, or drop it: absent backend authorization rules (route to `cloud-and-iac`, `baas-security-rules`), a Maps key with no bundle-id/SHA-1 restriction and no quota, or an analytics key with no server-side validation.

**Answer that question from the credential's shape and its provider, never from the file it sits in.** A `service_role` key, a service-account JSON and a `client_secret` appear in exactly the same `app.json`, `.env` and constants files as every public identifier listed above; "it was in the config" is how a Critical gets waved through.

**An OAuth client secret in a mobile app is not secret by definition.** A public client uses PKCE and no secret; a `client_secret` present in app config or in the token request is the finding regardless of how it is stored. Grading of the flow itself belongs to `crypto-and-key-management` (`oauth-oidc-flow-correctness`); the embedded secret is this lens's.

```detector
match: |
  // app/config/api.ts — bundled into the release JS
  export const CONFIG = {
    supabaseUrl: 'https://xyzcompany.supabase.co',
    supabaseServiceRoleKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.service_role.signature',
  };
nomatch: |
  // app/config/api.ts — bundled into the release JS
  export const CONFIG = {
    supabaseUrl: 'https://xyzcompany.supabase.co',
    supabaseAnonKey: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.anon.signature',
  };
```

```detector
match: |
  const discovery = { tokenEndpoint: 'https://idp.example.com/oauth2/token' };
  const result = await AuthSession.exchangeCodeAsync(
    {
      clientId: 'mobile-app',
      clientSecret: 'cs_live_9f2a41b7c0e84d6fa1b35e77',
      code,
      redirectUri,
      extraParams: { code_verifier: request.codeVerifier },
    },
    discovery,
  );
nomatch: |
  const discovery = { tokenEndpoint: 'https://idp.example.com/oauth2/token' };
  const result = await AuthSession.exchangeCodeAsync(
    {
      clientId: 'mobile-app',
      code,
      redirectUri,
      extraParams: { code_verifier: request.codeVerifier },
    },
    discovery,
  );
```

### 4. Declared network policy (`mobile-cleartext-and-ats-config`) — MASVS-NETWORK

Resolve the **merged, release-variant** manifest and plist before reporting anything in this item. Three properties decide the answer, and each one has a common misreading:

- **`android:usesCleartextTraffic` is ignored when a network security config is declared** (on the releases where both exist). A scary `android:usesCleartextTraffic="true"` next to `android:networkSecurityConfig="@xml/network_security_config"` is dead configuration; the effective answer is `cleartextTrafficPermitted` in that file. With no config declared, the platform default for apps targeting API 28+ is cleartext **denied**.
- **`NSAllowsArbitraryLoads` is overridden per-domain by `NSExceptionDomains`.** A blanket `true` with a narrow exception list is a different finding from a blanket `true` alone — and both are frequently in a `Debug`-only plist. Check which plist is in the release target.
- **`<debug-overrides>` is applied by the platform only when the app is debuggable.** A `<trust-anchors>` block containing `<certificates src="user"/>` inside `<debug-overrides>` cannot affect a release build. It becomes a real finding in exactly one shape: paired with a distributed build that is debuggable (item 9), or when the same relaxation appears in `<base-config>`/`<domain-config>` **outside** the debug-overrides element. Read which element it is in; the two look nearly identical in a diff.

```detector
match: |
  <network-security-config>
      <base-config cleartextTrafficPermitted="true">
          <trust-anchors>
              <certificates src="system" />
              <certificates src="user" />
          </trust-anchors>
      </base-config>
  </network-security-config>
nomatch: |
  <network-security-config>
      <base-config cleartextTrafficPermitted="false">
          <trust-anchors>
              <certificates src="system" />
          </trust-anchors>
      </base-config>
      <debug-overrides>
          <trust-anchors>
              <certificates src="user" />
          </trust-anchors>
      </debug-overrides>
  </network-security-config>
```

```detector
match: |
  <key>NSAppTransportSecurity</key>
  <dict>
      <key>NSAllowsArbitraryLoads</key>
      <true/>
  </dict>
nomatch: |
  <key>NSAppTransportSecurity</key>
  <dict>
      <key>NSExceptionDomains</key>
      <dict>
          <key>legacy-partner.example.com</key>
          <dict>
              <key>NSExceptionAllowsInsecureHTTPLoads</key>
              <true/>
          </dict>
      </dict>
  </dict>
```

**The check that does not exist: `fetch` with `rejectUnauthorized: false`.** Do not grep for it in React Native. `rejectUnauthorized` is a Node `tls`/`https` option; React Native's `fetch` polyfill runs over `NSURLSession` on iOS and OkHttp on Android and ignores it entirely. A sweep for it in an RN codebase matches nothing and reports clean while the app trusts every certificate presented to it. The bypasses that actually exist are these — file them under `tls-and-certificate-validation` (`crypto-and-key-management`), per `### Does not own`:

- **iOS** — a `URLSessionDelegate` whose `urlSession(_:didReceive:completionHandler:)` calls `completionHandler(.useCredential, URLCredential(trust: challenge.protectionSpace.serverTrust!))` on every challenge, with no evaluation of the trust object.
- **Android** — an `X509TrustManager` with an empty `checkServerTrusted`, a `HostnameVerifier { _, _ -> true }`, an `OkHttpClient.Builder().sslSocketFactory(...)` wired to a trust-all manager, or `SSLContext.init(null, trustAllCerts, SecureRandom())`.
- **Configuration** — the ATS and `network_security_config` relaxations above, which are this lens's.

```detector
match: |
  func urlSession(_ session: URLSession,
                  didReceive challenge: URLAuthenticationChallenge,
                  completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
      let trust = challenge.protectionSpace.serverTrust!
      completionHandler(.useCredential, URLCredential(trust: trust))
  }
nomatch: |
  func urlSession(_ session: URLSession,
                  didReceive challenge: URLAuthenticationChallenge,
                  completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
      guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
            let trust = challenge.protectionSpace.serverTrust,
            SecTrustEvaluateWithError(trust, nil) else {
          completionHandler(.cancelAuthenticationChallenge, nil)
          return
      }
      completionHandler(.performDefaultHandling, nil)
  }
```

```detector
match: |
  val trustAll = arrayOf<TrustManager>(object : X509TrustManager {
      override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
      override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {}
      override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
  })
  val ctx = SSLContext.getInstance("TLS").apply { init(null, trustAll, SecureRandom()) }
  val client = OkHttpClient.Builder()
      .sslSocketFactory(ctx.socketFactory, trustAll[0] as X509TrustManager)
      .hostnameVerifier { _, _ -> true }
      .build()
nomatch: |
  val client = OkHttpClient.Builder().build()
```

### 5. Certificate pinning (`certificate-pinning-implementation`) — MASVS-NETWORK

**Absent pinning is Low.** It is hygiene, not a vulnerability: the platform trust store already defeats passive and opportunistic interception, and on Android the default network security config additionally excludes user-added CAs from app trust for apps targeting API 24 and above. Pinning carries real availability risk, since a mis-rotated pin bricks every installed copy, and platform guidance discourages static pinning — cite the specific document if you lean on that, rather than asserting a vendor position.

**The two platforms are not symmetric here, and saying they are closes real findings.** iOS has **no** counterpart to Android's user-CA exclusion. A user- or MDM-installed root, once enabled for full trust in Certificate Trust Settings, is honored by `URLSession`; ATS constrains TLS version, cipher suites and certificate hygiene, not *which CA may issue*. So on iOS the residual exposure after this Low grade is a trusted-profile install — a managed fleet with an MDM-pushed root, or a profile-install step in a phishing chain — and that is exactly the case where the Medium elevation below actually bites. Do not use "ATS is on" to dismiss a device-local MITM on an iOS-only target.

**It elevates to Medium in exactly one case: the app is the sole client of a private API *and* handles PHI or payment data.** Both halves must be established from artifacts, not assumed:

- *Sole client* — the API host appears in this app's configuration and nowhere else in the checkout: no browser client in the workspace, no CORS allowlist naming a web origin, no published client SDK. Say which of those you checked.
- *PHI or payment data* — a health or financial entry in the `NSPrivacyCollectedDataTypes` array of `PrivacyInfo.xcprivacy`, the Play Data Safety declaration for financial or health data, a HealthKit entitlement (`com.apple.developer.healthkit`) or `NSHealthShareUsageDescription`/`NSHealthUpdateUsageDescription` in `Info.plist`, or a payment SDK in the dependency set (`PKPaymentRequest`, a Play Billing or Stripe/Adyen mobile SDK). PHI *classification* itself is `hipaa-and-phi`'s call — bring it the artifact, take its answer.

Where pinning does exist, the checkable defects are: **no backup pin**, **no rotation plan** (a pin set with no second key and no expiry story), and **pinning applied to only one of several HTTP clients** — the app pins its OkHttp client and then loads the same API through a WebView, an image loader, or a third-party SDK with its own stack. All stay in the Low band; report them as hardening, or as a gap against a standard the target is actually bound by. Do not report "the pin can be bypassed with Frida on a rooted device" as a finding: that is true of every pinning implementation ever shipped.

```detector
match: |
  val client = OkHttpClient.Builder()
      .certificatePinner(
          CertificatePinner.Builder()
              .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
              .build(),
      )
      .build()
nomatch: |
  val client = OkHttpClient.Builder()
      .certificatePinner(
          CertificatePinner.Builder()
              .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
              .add("api.example.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
              .build(),
      )
      .build()
```

### 6. Native-app OAuth integration (`native-app-oauth-integration`) — MASVS-AUTH

This lens owns the mobile-observable half of the OAuth client; `crypto-and-key-management` owns whether the flow is correct (`oauth-oidc-flow-correctness`) and grades missing PKCE, token lifetime and refresh-token rotation — a long-lived token issued to a mobile client with no rotation or revocation path is theirs, and the device-side evidence for it is where the token lands (item 1). Supply it these facts, which are only visible here:

- **The registered redirect, and who else can claim it.** `<data android:scheme="myapp"/>` inside an `<intent-filter>`, `CFBundleURLSchemes` in `Info.plist`, or an `http://127.0.0.1:<port>` loopback. Any other installed app can register the same custom scheme; a verified HTTPS App Link (`android:autoVerify="true"` plus a correctly hosted `/.well-known/assetlinks.json`) or an iOS Universal Link (Associated Domains entitlement plus `/.well-known/apple-app-site-association`) cannot be claimed that way.
- **Whether a client secret is present** — item 3.
- **Where the resulting tokens land** — item 1 and item 2. A correct flow that writes the refresh token to `AsyncStorage` is still an item 1 finding.

**Do not make a version claim about PKCE defaults.** `AuthRequestConfig.usePKCE` in `expo-auth-session` has defaulted to `true` for a long time, so "PKCE is optional before v5" both flags correct code on older SDKs and skips the check on newer ones. Check the things that are true on every version: an explicit `usePKCE: false`; `ResponseType.Token` or `response_type=token`, which is the implicit flow and bypasses PKCE regardless of the setting; whether `state` is generated *and* verified on return; and whether `makeRedirectUri()` produces a value that matches an exact registration at the provider.

**These three are graded by `crypto-and-key-management` (`oauth-oidc-flow-correctness`). If that lens did not activate in this run, still report the finding, tagged with its slug.** A React Native repository with no server code in the checkout very plausibly activates this lens only, and an implicit-flow OAuth client detected here, assigned elsewhere and reported by nobody is the lens-boundary loss this clause exists to prevent. If it did activate, hand it over and do not file it twice.

```detector
match: |
  const [request, response, promptAsync] = AuthSession.useAuthRequest(
    {
      clientId: CLIENT_ID,
      responseType: AuthSession.ResponseType.Token,
      usePKCE: false,
      redirectUri: AuthSession.makeRedirectUri({ scheme: 'myapp' }),
      scopes: ['openid', 'profile'],
    },
    discovery,
  );
nomatch: |
  const [request, response, promptAsync] = AuthSession.useAuthRequest(
    {
      clientId: CLIENT_ID,
      responseType: AuthSession.ResponseType.Code,
      redirectUri: AuthSession.makeRedirectUri({ scheme: 'myapp' }),
      scopes: ['openid', 'profile'],
    },
    discovery,
  );
```

### 7. Deep links and IPC (`deep-link-and-ipc-surface`) — MASVS-PLATFORM

**Every parameter that arrives through a link or an intent is untrusted input from an unauthenticated remote party.** Links arrive from email, SMS, a QR code, a web page, or another installed app. There is no origin on them.

**Name the sink, or there is no finding.** The ones that carry a severity here: a WebView `source.uri` or an interpolated `injectedJavaScript` (item 8), a native bridge method (item 14), `Linking.openURL` (below), a file path, and `eval` or `new Function` in the JavaScript layer — that last one executes attacker-supplied code inside the app's own bundle, with the bridge and every local store in reach, and it is usually a debug hook that was never removed from the release path.

```detector
match: |
  Linking.addEventListener('url', ({ url }) => {
    const params = new URL(url).searchParams;
    // QA bridge — still present in the release bundle
    const run = params.get('run');
    if (run) eval(run);
  });
nomatch: |
  Linking.addEventListener('url', ({ url }) => {
    const route = resolveDeepLink(url);
    if (route) navigation.navigate(route.name, route.params);
  });
```

**The source-app identifier is not an authorization signal, and the API usually cited for it is the wrong one.** `openURL:options:completionHandler:` is the *sending* API and carries no source-app identifier at all. The receiver gets one — via `application(_:open:options:)` or `scene(_:openURLContexts:)` — and it is populated by the OS from the calling process, so the caller cannot forge it. The reason not to trust it is different and more important: it is frequently **absent** (Universal Links, `SFSafariViewController`, Mail and Messages, most scene paths) and it can be laundered by chaining through a third app. Code that grants privilege when the identifier matches, and denies when it is missing, fails open the moment the link arrives by a path that does not set it.

Android specifics:

- **`android:exported`** — for components with an intent filter, apps targeting API 31+ must declare it explicitly, so most explicit `true` values in a modern manifest are compiler-forced annotations of a pre-existing filter, and many entries in the *merged* manifest belong to libraries. The finding needs an app-authored component, reachable without a signature or custom permission, that changes state or returns data the caller should not have. `exported="false"` is also not a clearance: an `<activity-alias>`, a same-signature app, or an exported component that forwards the intent all reach it.
  **What the build forced was the declaration, not the value.** A `true` typed in to make the build pass, on a component that only ever received an in-process broadcast, is an app-authored entry point and a real candidate. The classic case is a messaging service: an FCM `<service>` carrying `<action android:name="com.google.firebase.MESSAGING_EVENT"/>` is documented as `android:exported="false"` and works, because the library's own exported receiver dispatches to it inside the app — `true` there lets any installed app hand a crafted payload to `onMessageReceived`, which on most apps builds a notification and a deep link from it.
- **Intent redirection** — a component that takes an `Intent` (or a URI it converts with `Intent.parseUri`) out of its own extras and starts it. The caller chooses the destination and inherits your app's identity and permissions.
- **`PendingIntent` mutability has no literal in the dangerous case** below targetSdk 31: the default was mutable, and a mutable `PendingIntent` with an empty base intent lets the recipient fill in the destination. On targetSdk 31+ the platform requires `FLAG_IMMUTABLE` or `FLAG_MUTABLE` explicitly. List the construction sites and read the flags argument at each one; do not filter the list by a `FLAG_IMMUTABLE` match, because a line that merely mentions the token — a `// TODO`, or a second, correct call — drops the vulnerable construction out of the output and the sweep reports clean.
- **ContentProviders** with no permission, or with `android:grantUriPermissions="true"` and a broad path, are readable by other apps.
- **Implicit intents carrying sensitive extras** can be received by any app that declares a matching filter.

iOS specifics: a custom URL scheme (`myapp://`) can be registered by any other app, so it is not an identity; Universal Links require a correctly hosted `apple-app-site-association` and are the preferred entry point.

```detector
match: |
  <activity android:name=".DeepLinkActivity" android:exported="true">
      <intent-filter>
          <action android:name="android.intent.action.VIEW" />
          <category android:name="android.intent.category.DEFAULT" />
          <category android:name="android.intent.category.BROWSABLE" />
          <data android:scheme="https" android:host="app.example.com" />
      </intent-filter>
  </activity>
nomatch: |
  <activity android:name=".DeepLinkActivity" android:exported="true">
      <intent-filter android:autoVerify="true">
          <action android:name="android.intent.action.VIEW" />
          <category android:name="android.intent.category.DEFAULT" />
          <category android:name="android.intent.category.BROWSABLE" />
          <data android:scheme="https" android:host="app.example.com" />
      </intent-filter>
  </activity>
```

```detector
match: |
  <service
      android:name=".messaging.AppMessagingService"
      android:exported="true">
      <intent-filter>
          <action android:name="com.google.firebase.MESSAGING_EVENT" />
      </intent-filter>
  </service>
nomatch: |
  <service
      android:name=".messaging.AppMessagingService"
      android:exported="false">
      <intent-filter>
          <action android:name="com.google.firebase.MESSAGING_EVENT" />
      </intent-filter>
  </service>
```

```detector
match: |
  val forward = intent.getParcelableExtra<Intent>("next")
  startActivity(forward)
nomatch: |
  val route = intent.getStringExtra("next")
  when (route) {
      "settings" -> startActivity(Intent(this, SettingsActivity::class.java))
      "profile" -> startActivity(Intent(this, ProfileActivity::class.java))
      else -> startActivity(Intent(this, HomeActivity::class.java))
  }
```

```detector
match: |
  val pending = PendingIntent.getBroadcast(context, 0, Intent(), 0)
nomatch: |
  val pending = PendingIntent.getBroadcast(
      context, 0, Intent(context, AlarmReceiver::class.java), PendingIntent.FLAG_IMMUTABLE,
  )
```

**`Linking.openURL` with a value taken from an incoming link is a redirect the app performs on the attacker's behalf**, and on mobile it reaches more than the browser: `tel:`, `sms:`, `intent://`, and any custom scheme another installed app has registered. The generic open-redirect grading is `web-and-api`'s (`open-redirect`); what stays here is the scheme reachability and the fact that the source was an unauthenticated deep link.

```detector
match: |
  Linking.addEventListener('url', ({ url }) => {
    const next = new URL(url).searchParams.get('next');
    if (next) Linking.openURL(next);
  });
nomatch: |
  const ALLOWED = new Set(['https://app.example.com', 'https://help.example.com']);

  Linking.addEventListener('url', ({ url }) => {
    const next = new URL(url).searchParams.get('next');
    if (!next) return;
    const target = new URL(next);
    if (target.protocol === 'https:' && ALLOWED.has(target.origin)) Linking.openURL(target.toString());
  });
```

### 8. WebView bridge trust (`webview-bridge-trust`) — MASVS-PLATFORM

**`originWhitelist` governs top-level navigation only.** It has no bearing on iframes, on `XHR`/`fetch`, or on subresources — those are governed by the same-origin policy and by CSP, and they load even at the default. So `originWhitelist={['*']}` is not "iframes from anywhere"; it removes the navigation allowlist, so a redirect or a `window.location` write can move the WebView to an arbitrary origin, **including `file://` and custom schemes**, and whatever loads there inherits `injectedJavaScript` and the `window.ReactNativeWebView` bridge. The default allowlist is `http`/`https` only.

The absence question matters more than the literal: a WebView with **no** `onShouldStartLoadWithRequest` handler and no narrowed `originWhitelist` will follow a redirect to any https origin. **Grep for the component first, then check what constrains it** — `<WebView`, `WKWebView`, `WebView(`, `webView.settings`, an import of `react-native-webview`. A prop-only sweep cannot see `<WebView source={{ uri: props.url }} />` with no other prop, which is the worst case in this item and the one with no literal to find. Item 0's WebView sweep leads with the component for that reason.

The properties this item covers, each of which widens what the loaded page can do:

- `allowFileAccess`, `allowFileAccessFromFileURLs`, `allowUniversalAccessFromFileURLs` (Android) and `allowingReadAccessToURL` (iOS) — file-scheme reach into the app sandbox.
- `mixedContentMode="always"` — https page, http subresources.
- **`setSupportMultipleWindows` left at its default, with no `onOpenWindow` handler.** Read the Android semantics the right way round, because the intuitive reading is backwards and flags the defensive setting as the finding. With multiple-window support **on** — react-native-webview's default; confirm it against the installed version — a `target="_blank"` or `window.open()` navigation is routed to `WebChromeClient.onCreateWindow` (RN's `onOpenWindow`) and **does not reach** `shouldOverrideUrlLoading` / `onShouldStartLoadWithRequest`. So the URL guard an auditor finds in the props does not cover that navigation class at all. Setting it to **`false`** is the documented way to collapse those navigations into the same window so the guard *does* see them, and when it is `false` `onOpenWindow` can never fire — "`false` plus an unhandled `onOpenWindow`" describes a state that cannot exist. The finding is the default `true` with neither an `onOpenWindow` handler nor an equivalent constraint, which is an absence case: it has no literal in the props.
- `javaScriptEnabled` — on by default in `react-native-webview`; the safe state is an explicit `false` on a WebView that only renders static content.
- `injectedJavaScript` and `injectedJavaScriptBeforeContentLoaded` — these run on **every** page the WebView ends up on, including one it was redirected to. Interpolating user or server data into that string is script injection into a context that holds the bridge.
- `onMessage` — `window.ReactNativeWebView.postMessage` carries no origin, so any page loaded in the WebView can send anything. Validate the payload as untrusted input and never dispatch a native action from it by name.

**`injectedJavaScript` and `onMessage` carry a proof requirement, not a suppression: quote the interpolation site, or quote the native side effect the message reaches.** A WebView finding that names neither is not reportable — and their mere presence is not the finding, since both are the normal way a WebView is wired.

**`addJavascriptInterface` is not the 2013 remote-code-execution bug any more** — since API 17 only methods annotated `@JavascriptInterface` are reachable. The modern finding is narrower and still serious: an annotated method that performs privileged work — reads a token, writes storage, starts an activity — reachable from whatever page the WebView is on. Audit the annotated method surface, not the presence of the call.

```detector
match: |
  <WebView
    source={{ uri: props.route.params.url }}
    originWhitelist={['*']}
    javaScriptEnabled
    injectedJavaScript={`window.__TOKEN__ = "${session.accessToken}"; true;`}
    onMessage={(e) => dispatch(JSON.parse(e.nativeEvent.data))}
  />
nomatch: |
  <WebView
    source={{ uri: 'https://help.example.com/faq' }}
    originWhitelist={['https://help.example.com']}
    onShouldStartLoadWithRequest={(req) => req.url.startsWith('https://help.example.com/')}
    javaScriptEnabled={false}
    onMessage={(e) => handleTypedMessage(parseMessage(e.nativeEvent.data))}
  />
```

```detector
match: |
  webView.settings.javaScriptEnabled = true
  webView.settings.allowFileAccessFromFileURLs = true
  webView.settings.allowUniversalAccessFromFileURLs = true
  webView.addJavascriptInterface(TokenBridge(), "native")

  class TokenBridge {
      @JavascriptInterface
      fun getAuthToken(): String = SessionStore.accessToken
  }
nomatch: |
  webView.settings.javaScriptEnabled = true
  webView.settings.allowFileAccess = false
  webView.settings.allowFileAccessFromFileURLs = false
  webView.settings.allowUniversalAccessFromFileURLs = false
  webView.loadUrl("https://help.example.com/faq")
```

### 9. Build and runtime flags (`mobile-build-and-runtime-flags`) — MASVS-RESILIENCE, MASVS-CODE

- **`android:debuggable="true"` in a distributed build** is the finding that unlocks several others: it is what makes `<debug-overrides>` live (item 4), and it re-opens data extraction paths (item 1). Check the merged release manifest, not `src/debug/` — and check Gradle, where the attribute is set without appearing in any manifest: `debuggable true` inside a Groovy `buildTypes { release { … } }`, or `isDebuggable = true` inside a Kotlin-DSL `getByName("release") { … }`. Search for both spellings; they are the same setting under two names.
- **`expo-dev-client` or a development build distributed through TestFlight or internal testing** ships a remote debugging surface to real users. So does a packager host baked into a release build.
- **`__DEV__` is eliminated when the bundle is built with `dev: false`, and the gate is the `dev` transform option — not the minifier.** Metro's `inlinePlugin` substitutes `__DEV__` from `options.dev`, and the dead-branch pass (`constantFoldingPlugin`) runs only inside `if (!options.dev)`. Minification is a separate per-bundle `minify` option. Getting this backwards produces confident wrong answers in both directions, because **`--minify false` is the normal state of a stock Hermes release build** — `react-native-xcode.sh` adds `--minify false` itself whenever Hermes is enabled and `DEV=false`, on the grounds that Hermes does not need JS minification. So a `--minify false` sighting is not a finding, and minification being on is not a clearance.

  That is why insecure-looking code inside `if (__DEV__)` is usually not a finding, and why the *conditions under which it survives* are the actual check. Each one is a named, findable build artifact:
  - **Gradle** — `project.ext.react` (RN < 0.71) or the `react { }` block, specifically `extraPackagerArgs` containing `--dev true`, or a replaced `bundleCommand`.
  - **Xcode** — the "Bundle React Native code and images" build phase, which invokes `react-native-xcode.sh`. Its `DEV` is derived from `$CONFIGURATION` (`*Debug*` → `true`, anything else → `false`), and the phase's environment can override the outcome via `EXTRA_PACKAGER_ARGS`, `BUNDLE_COMMAND`, `FORCE_BUNDLING` and `SKIP_BUNDLING`. `SKIP_BUNDLING` is worth its own look: it ships whatever `main.jsbundle` is already in the tree.
  - **EAS / Expo** — the build profile in `eas.json`: `developmentClient: true`, or a `gradleCommand`/`buildConfiguration` pointing at a debug variant. Also read whatever line in `package.json` scripts or CI actually produces the shipped bundle, and the `--dev`/`--minify` flags on it.
  - **A custom transform or serialization path** — `transformerPath`, `transformer.babelTransformerPath`, or a custom serializer in `metro.config.js`, any of which can replace the pass that does the inlining.
  - **Not the literal at all** — a runtime guard used instead (`if (config.debug)`, or `process.env.NODE_ENV` read from remote config), or the same code duplicated outside the guard.

  Verify against the release bundle. **`minifierEnabled` is not a Metro option** — it is absent from `metro-config`'s defaults and from every `metro*`/`@expo/metro*` package, and Metro validates config against a known-key schema, so it is silently ignored. Do not grep for it and do not treat its absence as evidence.
- **Source maps and symbols.** A `.map` file served next to the bundle, or an unauthenticated upload endpoint, exposes the JavaScript source. Uploading source maps to a crash-reporting or observability backend is the correct practice — the finding is a map reachable without authentication, wherever it lives.
- **Anti-tamper and root/jailbreak detection are defense in depth, never a primary control.** Their absence is Info and is not a standalone finding above Low. Do not let their presence clear anything either.

```detector
match: |
  // android/app/build.gradle — the release bundle is built as a dev bundle,
  // so __DEV__ stays true and every branch guarded by it ships.
  react {
      extraPackagerArgs = ["--dev", "true"]
  }
nomatch: |
  // android/app/build.gradle — stock release path: the bundle is built with
  // dev:false, __DEV__ is inlined to false and the branch is folded away.
  react {
      extraPackagerArgs = []
  }
```

```detector
match: |
  if (config.debug) {
    api.defaults.headers.common['X-Debug-Token'] = STAGING_ADMIN_TOKEN;
  }
nomatch: |
  if (__DEV__) {
    api.defaults.headers.common['X-Debug-Token'] = STAGING_ADMIN_TOKEN;
  }
```

### 10. UI, clipboard and notification leakage (`mobile-ui-and-notification-leakage`) — MASVS-PRIVACY, MASVS-PLATFORM

The value never left the device and still leaked.

- **Clipboard.** Writing a credential, a one-time code or regulated data to `UIPasteboard.general` / `ClipboardManager` exposes it to every app that reads the clipboard, and on iOS to Universal Clipboard on the user's other devices. Reading the clipboard unprompted is its own finding even though iOS now shows a banner. On Android, mark sensitive clips so they are excluded from clipboard previews and history.
- **Push notifications and the lock screen.** Content that names a diagnosis, a balance, a code or a counterparty is displayed on a locked device. The mobile finding is the payload construction and the notification's visibility setting; classification of the payload is `hipaa-and-phi`'s or `privacy-and-data-protection`'s.
- **The app-switcher snapshot.** iOS screenshots the app on background; the fix is to cover the window in `sceneWillResignActive`/`applicationWillResignActive`. On Android the equivalent control is `FLAG_SECURE` on the window, which also blocks screenshots and screen recording.
- **Text fields.** `secureTextEntry` / `android:inputType="textPassword"`, plus disabling autofill and suggestion caching for credential fields.
- **Accessibility and third-party session-replay SDKs** read the view hierarchy, including fields the UI masks.

```detector
match: |
  UIPasteboard.general.string = viewModel.oneTimePasscode
nomatch: |
  UIPasteboard.general.setItems(
      [[UIPasteboardTypeAutomatic: order.publicReferenceNumber]],
      options: [.localOnly: true, .expirationDate: Date().addingTimeInterval(60)]
  )
```

```detector
match: |
  class ClinicalNoteActivity : AppCompatActivity() {
      override fun onCreate(savedInstanceState: Bundle?) {
          super.onCreate(savedInstanceState)
          setContentView(R.layout.activity_clinical_note)
      }
  }
nomatch: |
  class ClinicalNoteActivity : AppCompatActivity() {
      override fun onCreate(savedInstanceState: Bundle?) {
          super.onCreate(savedInstanceState)
          window.setFlags(
              WindowManager.LayoutParams.FLAG_SECURE,
              WindowManager.LayoutParams.FLAG_SECURE,
          )
          setContentView(R.layout.activity_clinical_note)
      }
  }
```

```detector
match: |
  await Notifications.scheduleNotificationAsync({
    content: {
      title: 'Lab results ready',
      body: `${patient.firstName}: ${result.testName} — ${result.value}`,
    },
    trigger: null,
  });
nomatch: |
  await Notifications.scheduleNotificationAsync({
    content: {
      title: 'New message',
      body: 'Open the app to view your update.',
      data: { deepLink: 'myapp://results/latest' },
    },
    trigger: null,
  });
```

### 11. Consent mechanism (`in-app-consent-mechanisms`) — MASVS-PRIVACY

This lens owns the *mechanism*: whether the code can honor an answer, and whether it asked before acting. Whether a lawful basis exists, whether the consent text is valid, and whether the purpose is legitimate belong to `privacy-and-data-protection`.

The mobile-specific defect is initialization order. Analytics, attribution, crash-reporting and ad SDKs are typically initialized in `Application.onCreate`, `AppDelegate`'s `didFinishLaunchingWithOptions`, or a top-level module import — all of which run **before** any consent UI can be presented, and several of which transmit a device identifier on init. A consent flag consulted later cannot un-send that. Check where the SDK is initialized, not where the flag is read.

On iOS, App Tracking Transparency is a platform gate, not a legal basis: `NSUserTrackingUsageDescription` must be present and `ATTrackingManager.requestTrackingAuthorization` must have returned before the IDFA is meaningful. Collecting a different persistent identifier because ATT was denied is a finding here (the mechanism was circumvented) and a routing item there.

```detector
match: |
  // App.tsx — runs at module load, before any consent UI
  import analytics from '@segment/analytics-react-native';

  analytics.setup(WRITE_KEY, { trackAppLifecycleEvents: true });
nomatch: |
  // App.tsx
  import analytics from '@segment/analytics-react-native';

  export async function initTelemetryAfterConsent(consent) {
    if (!consent.analytics) return;
    await analytics.setup(WRITE_KEY, { trackAppLifecycleEvents: true });
  }
```

### 12. Privacy manifest and store declarations (`privacy-manifest-and-store-declarations`) — MASVS-PRIVACY

`PrivacyInfo.xcprivacy` carries `NSPrivacyTracking`, `NSPrivacyTrackingDomains`, `NSPrivacyCollectedDataTypes` and `NSPrivacyAccessedAPITypes` (the required-reason API declarations). The Play Data Safety declaration is the Android counterpart and is not in the repository — say so rather than reporting it absent.

Three checks, in order of yield:

1. **Absent entirely** in an app that ships SDKs requiring one. This is a platform-policy finding, not a legal one; grade it low and say which regime it belongs to.
2. **Inconsistent with the code.** The declaration says no tracking while an attribution SDK is linked; the collected-data types omit a category the code demonstrably sends; `NSPrivacyTrackingDomains` omits a host the app calls. The code is the evidence and the declaration is the claim — report the delta, with both sides quoted.
3. **Required-reason API usage with no matching entry** — the `NSPrivacyAccessedAPICategory…` values for the file-timestamp, disk-space, system-boot-time, active-keyboard and user-defaults families.

```detector
match: |
  <key>NSPrivacyTracking</key>
  <false/>
  <key>NSPrivacyTrackingDomains</key>
  <array/>
nomatch: |
  <key>NSPrivacyTracking</key>
  <true/>
  <key>NSPrivacyTrackingDomains</key>
  <array>
      <string>attribution.example-adnetwork.com</string>
  </array>
```

### 13. Over-the-air update integrity (`ota-update-integrity`) — MASVS-CODE, MASVS-RESILIENCE

**Any channel that can change executing code after install is a code-execution path into every device**, and the only thing standing between it and an attacker is signature verification. Transport security is not signature verification: TLS authenticates the server the app happened to contact, not the payload's author.

The dangerous state has **no literal**. Grep for the absence:

- **Expo Updates** — `codeSigningCertificate` under `updates` in `app.json` / `app.config.*` (`expo.updates.codeSigningCertificate` when the config is nested under an `expo` key). Absent means updates are accepted on the strength of the update server alone. Read the `updates.url` too: a self-hosted or custom update endpoint widens the trust to whoever operates it.
- **CodePush and comparable JS-bundle channels** — the same question: is the bundle signed, and does the client verify it.
- **Anything that downloads and loads code at runtime** — a remote bundle, a downloaded native library, a script fetched into a WebView. Report the mechanism even when the vendor is not one of the known ones.

```detector
match: |
  {
    "expo": {
      "updates": {
        "url": "https://updates.internal.example.com/manifest",
        "enabled": true
      }
    }
  }
nomatch: |
  {
    "expo": {
      "updates": {
        "url": "https://updates.internal.example.com/manifest",
        "enabled": true,
        "codeSigningCertificate": "./certs/updates-cert.pem",
        "codeSigningMetadata": { "keyid": "main", "alg": "rsa-v1_5-sha256" }
      }
    }
  }
```

### 14. Vendored native code provenance (`vendored-native-code-provenance`) — MASVS-CODE

What this lens owns is native code that arrives **outside the dependency manifest**, because the supply-chain lens's pinning and CVE checks never see it:

- Checked-in binaries: `*.so`, `*.a`, `*.aar`, `*.framework`, `*.xcframework` committed to the repository with no build recipe and no provenance.
- A `Podfile` or `package.json` entry pointing at a **git ref or a tarball URL** rather than a released version, and a `Podfile.lock`/lockfile that records a moving ref.
- `patch-package` patches or `postinstall` scripts that modify native sources or build files.
- A local or autolinked native module whose exported methods perform privileged operations with no caller authentication — and in particular the "command string plus switch" shape, where the JavaScript side passes a name and the native side dispatches on it. That is a remote-code-execution primitive as soon as the string can come from a deep link, a WebView message or a server response.

`dependency-pinning-and-lockfiles`, `package-dependency-cves` and signing-key handling stay with `cicd-and-supply-chain`.

```detector
match: |
  @ReactMethod
  fun execute(command: String, args: ReadableMap, promise: Promise) {
      when (command) {
          "readFile" -> promise.resolve(File(args.getString("path")!!).readText())
          "exec" -> promise.resolve(Runtime.getRuntime().exec(args.getString("cmd")).inputStream.bufferedReader().readText())
          else -> promise.reject("E_UNKNOWN", "unknown command")
      }
  }
nomatch: |
  @ReactMethod
  fun readAppLog(promise: Promise) {
      val file = File(reactApplicationContext.filesDir, "app.log")
      promise.resolve(file.readText())
  }
```

### 15. Client-authoritative state (routed to `authz-function-level`, `authz-object-level`, `authz-property-level` → `web-and-api`; `baas-security-rules` → `cloud-and-iac`)

Applies to apps whose backend is a backend-as-a-service (Firebase, Supabase, Appwrite) and/or whose entitlements come from an in-app-purchase wrapper (RevenueCat, Adapty, or direct StoreKit 2 / Play Billing). **The findings below are not this lens's**, but the device-side evidence is only visible here, so collect it and hand it over with file and line.

**If the owning lens did not activate in this run, still report the finding, tagged with its slug.** This item is the most likely place in the lens for a finding to be lost: a React Native client repository with no server code and no `firestore.rules` in the checkout very plausibly activates *this lens only*, and a client-authoritative entitlement gate detected here, assigned to `web-and-api` and reported by nobody is a real vulnerability deleted by a routing rule. Report it here with the owning slug named and the assumption about the server written down. If the owning lens did activate, hand it over and do not file it twice.

- **Backend rules are the only control between the client and the database.** The app code enforces nothing an attacker cannot remove. Rules requiring authentication, scoping writes to the authenticated principal, and validating field types and lengths are `cloud-and-iac`'s `baas-security-rules`.
- **Entitlement state must be validated server-side against the store** — StoreKit 2 `Transaction.currentEntitlements` verified on the server, Play `purchases.subscriptions.get`, or the store's server notifications. A cached local flag is never the source of truth for unlocking paid or privileged features. The finding is `web-and-api`'s `authz-function-level`; where the cache is the store, the plaintext-cache half is item 1 here. Do not attribute correctness to a named vendor SDK — audit what this app does with its answer.
- **Client-persisted economy or scoring state** — virtual currency, credits, streaks, leaderboard positions, progression levels. Any value that gates a reward or is compared between users must be server-authoritative; local writes are attacker-controlled input. Signing or HMAC-ing the value prevents tampering but **not replay or rollback**, so it is not an acceptable substitute for server authority — say so explicitly if you see it offered as one.
- **Account pairing, invite and device-linking flows** need a single-use, short-expiry, high-entropy token (deep link or QR) bound to the inviter's session. An identifier-only flow — "enter the other person's email address" — is both an enumeration oracle and an unauthenticated write into another user's object graph. The enumeration and authorization halves are `web-and-api`'s; the link-delivery half is item 7 here.
- **The server must treat every request from the app as forgeable.** Client-supplied user ids, role claims, prices and quantities are input, not identity. That is `web-and-api`'s `authz-object-level` / `authz-property-level`.

```detector
match: |
  const isPro = await AsyncStorage.getItem('entitlement.pro');
  if (isPro === 'true') {
    unlockPremiumFeatures();
  }
nomatch: |
  const { entitlements } = await api.get('/me/entitlements');
  if (entitlements.includes('pro')) {
    unlockPremiumFeatures();
  }
```

## Severity calibration

`severity_floor: low` is presentational. It orders this lens's findings in the report. It never suppresses a finding, and no item above may be dropped because it sits at Low or Info.

**The rule that does the most work here: a mobile finding is graded on what the exposure reaches, not on the fact that the device is untrusted.** Every app can be decompiled, every local store can be read on a rooted device, and every client-side check can be patched out. A severity that follows from those facts alone applies to every mobile app ever written and tells the reader nothing.

### Corrections carried into this table

| Source instruction | Why it was wrong | Resolution |
|---|---|---|
| Checklist said certificate pinning is **Medium** when missing and **Low** when bypassable; the severity table said **Low** standalone, **Medium** for high-value apps. | Two answers in one brief, and the inline pair was backwards — it graded a bypassable pin *below* an absent one, when every pin falls to instrumentation on a rooted device. | **Resolved downward to Low.** The backwards inline pair is deleted. Item 5 and the row below now carry one answer in near-identical words — Low, with a single Medium elevation — so an auditor who reads only one of them cannot arrive at a different grade. The elevation has two conditions and both must be evidenced from artifacts; item 5 names them. |
| "**Hardcoded API key in shipped binary**: Critical if the key is high-privilege (admin API), High if it's a public/anon key." | The second half grades a *public client identifier* as High, which is the highest-volume false positive in mobile auditing, and the first half disagreed with the LLM lens's grading of the same bug. | Split into two rows. A credential that authorizes privileged reads or writes on its own is **Critical unconditionally**; a public client identifier is **not a finding on presence** and is replaced by the missing-server-control finding. |
| "`fetch` with `rejectUnauthorized: false`" as the TLS-disabled check. | A Node option React Native ignores: the check runs, matches nothing, and reports clean. | Deleted. The real bypasses are enumerated in item 4 and graded in the row below, and they are filed under `crypto-and-key-management`. |
| "PBKDF2 with low iteration counts (<600k for SHA-256 per OWASP 2023 guidance)". | There is no OWASP 2023 edition of the Password Storage Cheat Sheet, and 600k is a server-side password-verification figure misapplied to a device. | Removed from this lens; routed to `crypto-and-key-management` with the misapplication noted in `### Does not own`. |
| "`minifierEnabled: false` in `metro.config.js`" as the condition under which an `if (__DEV__)` block survives into the shipped bundle — with a detector teaching it as the vulnerable shape, and false positive 1 leaning on it as its first escape hatch. | **A dead literal: `minifierEnabled` is not a Metro option.** Absent from `metro-config`'s defaults and from every `metro*`/`@expo/metro*` package, and silently dropped by Metro's known-key schema. An escape hatch that cannot fire makes false positive 1 an unconditional clearance — the `rejectUnauthorized` defect reintroduced, and worse, because the clearance closes a shipped credential. The stated mechanism was wrong too: `__DEV__` inlining and dead-branch folding are gated on Metro's **`dev`** transform option, not on the minifier, and `--minify false` is the *normal* state of a Hermes release build. | Deleted from the sweep, item 9, the detector and false positive 1. Replaced with the artifacts that actually decide it — Gradle `project.ext.react` / `react { }` `extraPackagerArgs`, the Xcode `react-native-xcode.sh` build phase and its `DEV`/`EXTRA_PACKAGER_ARGS`/`SKIP_BUNDLING` inputs, the `eas.json` build profile, and a custom `transformerPath`/`babelTransformerPath`/serializer — and the mechanism restated as `dev: false`. |
| "Export is mandatory for … receivers of system broadcasts" (severity Low band and false-positive entry 4). | The same wrong clearance as the messaging-service one, sitting one item away in the same list and left unexamined when its neighbour was corrected. Production apps ship `android:exported="false"` on `BOOT_COMPLETED` receivers and those receivers fire, so export is not load-bearing for a protected system broadcast. `true` on one is an app-authored, unauthenticated entry point graded **Low** by the old table and waved through by the old entry 4. | Removed from both the Low band and the mandatory-export list, and graded on what the receiver does with the intent — the phrasing already used for messaging services. Recorded here because the general lesson is: when a wrong item is removed from a list, re-derive **every remaining item in that list**, not only the consumers of the removed one. |

### Severity table

| Condition | Severity | What establishes it |
|---|---|---|
| A credential that authorizes privileged reads or writes on its own, present in the shipped app — a model-provider or admin API key, a service-account key, a signing key, a storage or database key with write scope, an OAuth **client secret** | **Critical**, unconditional | The literal in bundled source, an asset, `Info.plist`, `BuildConfig`, `gradle.properties`, `google-services.json`, or `strings` over the binary. Obfuscation, Hermes and R8 move nothing. A provider key additionally grants org-scoped access to stored data and unbounded spend under the org's identity; the fix is a server-side proxy with per-user auth and budget, never obfuscation |
| A public client identifier in the shipped app — Firebase `apiKey`, a Maps/Places key, a Sentry DSN, a publishable payment key, a public IAP-wrapper SDK key, an OAuth **client ID**, an Expo project id, an analytics write key | **Not a finding on presence** | Report instead what is missing: absent backend rules (`cloud-and-iac`), a Maps key with no bundle-id/SHA-1 restriction and no quota, an analytics key with no server-side validation. Info–Low if you report the identifier itself at all. **If the owning lens did not activate in this run, still report the replacement finding here, tagged with its slug** — otherwise this row converts a Critical-looking candidate into nothing at all |
| Session token, refresh token, encryption key, or regulated data (PII, PHI, cardholder data) in an unencrypted local store | **High** | Name the store and quote the key: `AsyncStorage` (`RKStorage`/`catalystLocalStorage`, or `databases/AsyncStorage` under `AsyncStorage_useNextStorage`; `RCTAsyncLocalStorage_V1` under `Library/Application Support` on iOS), MMKV with no `encryptionKey`, `SharedPreferences` (including a `@AppStorage` or `UserDefaults(suiteName:)` write), `UserDefaults`, a plaintext SQLite/Realm file (`openDatabase`, `new Realm(`) with no SQLCipher or `encryptionKey`. Classification of the value routes to `hipaa-and-phi` / `privacy-and-data-protection` |
| Chain validation or hostname verification disabled in a shipped build | **Critical** | The code shapes in item 4. Owned by `crypto-and-key-management` (`tls-and-certificate-validation`); graded here so the two lenses do not disagree in one report |
| Cleartext HTTP carrying authentication or regulated data | **High** | The effective merged, release-variant policy — `cleartextTrafficPermitted`, ATS keys — plus an actual `http://` endpoint in the app's configuration. An ATS or NSC exception for a single non-sensitive host is **Low** |
| **Missing certificate pinning** | **Low** | Hygiene. **Medium** only where the app is the sole client of a private API **and** handles PHI or payment data, both established from artifacts (item 5). Never above Medium in this lens |
| Pinning present but weak — no backup pin, no rotation story, or applied to one of several HTTP clients | **Low** | Same band as absent pinning. "Bypassable with instrumentation on a rooted device" is true of all pinning and is not a finding |
| Exported component reachable without a signature or custom permission that performs a state change or returns data the caller should not have | **Critical** where it performs an auth-relevant action (session, entitlement, account linking); **High** where it returns another user's data; **Low** where it is the launcher activity, a share target, an app-link activity, or a library-owned component — export is load-bearing for those | The **merged** manifest, plus the component's own code. `exported="true"` alone is not the finding — see false positive 4. Two things are **not** in the Low list, and both were put there by the same wrong belief that export is load-bearing wherever the platform delivers the intent. A messaging service: a `com.google.firebase.MESSAGING_EVENT` service is documented non-exported, so grade one on what `onMessageReceived` does with the payload. **A receiver of a protected system broadcast: same answer.** A `BOOT_COMPLETED` receiver ships `android:exported="false"` in production and fires — export is not required for the system to deliver a protected broadcast — so `true` on one is an app-authored, unauthenticated entry point, graded on what the receiver does with the intent |
| A deep-link or intent parameter reaching a WebView URL, a native bridge method, or `Linking.openURL` | **High** | The handler code, from the `<intent-filter>` / `CFBundleURLSchemes` entry to the sink. The WebView case is high because the page then holds the bridge |
| A deep-link, intent or WebView-message parameter reaching `eval` or `new Function` in the JavaScript layer | **Critical** | The handler code and the taint path. This is code execution in the app's own bundle from an unauthenticated link, so it is graded above the other sinks; check the release bundle, since the shape is usually a debug hook |
| Intent redirection, or a mutable `PendingIntent` with an unspecified destination | **High** | `startActivity` on an `Intent` taken from extras; a `PendingIntent` construction with no `FLAG_IMMUTABLE` below targetSdk 31 |
| Auto Backup enabled (declared `true`, **or not declared at all**) on an app holding credentials or regulated data | **Medium**, rising to **High** where the backed-up store holds a credential or regulated data and no `dataExtractionRules` excludes it | The merged manifest. State the extraction path you mean — cloud backup, device-to-device transfer, or `adb backup` on an older or debuggable build — rather than asserting `adb backup` generically |
| Debuggable release build, or a development client distributed through TestFlight / internal testing | **High** | `android:debuggable` in the merged release manifest, **or** a Gradle release buildType carrying Groovy `debuggable true` / Kotlin-DSL `isDebuggable = true` — both spellings, since a Gradle override appears in no source manifest; `expo-dev-client`, an EAS profile with `developmentClient: true`, or a packager host in a distribution build |
| Source map or bundle reachable without authentication | **Medium** | A `.map` served next to the bundle, or an unauthenticated upload/serve endpoint. Information disclosure of business logic and internal API shape. **The condition is reachability, not minification state:** `--minify false` is the normal state of a stock Hermes release build (item 9), so an unminified bundle is not the finding and a minified one is not a clearance |
| OTA update channel with no code-signature verification | **High** | Absence of `codeSigningCertificate` (or an equivalent verified-signature mechanism) on a channel that can replace executing code. **Critical** where the update endpoint is self-hosted and its access control cannot be established |
| A native module method reachable from JavaScript that dispatches on a caller-supplied command string | **High**, **Critical** where the string can originate from a deep link, a WebView message or a server response | The `@ReactMethod` / exported native surface and the taint path to it |
| Regulated data on the lock screen, in the clipboard, in the app-switcher snapshot, or readable by a session-replay SDK | **Medium** | The notification payload construction, the clipboard write, the absence of `FLAG_SECURE` or a background-cover, the linked SDK. Non-regulated data: **Low** |
| Analytics, attribution, ad or crash SDK initialized before consent can be answered | **Medium** | The initialization site — `Application.onCreate`, `didFinishLaunchingWithOptions`, or a top-level module import — preceding any consent gate. Lawful-basis grading routes to `privacy-and-data-protection` |
| `PrivacyInfo.xcprivacy` absent, or contradicted by the code | **Low** for absent; **Medium** where it affirmatively denies tracking that the code performs | The manifest keys versus the linked SDKs and the outbound hosts. Platform policy, not law |
| Missing PKCE, implicit flow, or an unverified `state` in a native OAuth client | Graded by `crypto-and-key-management` | This lens supplies the redirect registration (`<data android:scheme>`, `CFBundleURLSchemes`, loopback), `android:autoVerify`, and the Associated Domains entitlement, which are the facts that row turns on. **If `crypto-and-key-management` did not activate in this run, still report the finding here, tagged with its slug** (item 6) — a mobile-only checkout is the common case, and this row must not be the place an implicit-flow client disappears |
| A custom URL scheme registered, with nothing else wrong — `CFBundleURLSchemes` in `Info.plist`, or `<data android:scheme="myapp"/>` in an `<intent-filter>` | **Info** | Advice, not a vulnerability: any other installed app can register the same scheme, which is why a verified App Link or Universal Link is preferred. It becomes a finding when a scheme-entered route performs an authenticated state change with no re-authentication; when it carries an OAuth response with no PKCE and no verified `state` (item 6); **or when it carries an authentication, invite, pairing, device-linking, magic-link or password-reset token.** That last case is account takeover, not advice — a single-use authentication token delivered to `myapp://` is claimable by any installed app that registers the same scheme (R1, item 15) — and this cap must never hold it at Info |
| Missing root/jailbreak detection, missing anti-tamper, missing binary protections | **Info** | Defense in depth. Never a standalone finding above Low, and never a clearance for anything else |

## Known false positives

Each entry names a pattern a competent reviewer would flag and says why it is not the finding it looks like. **None of these is a licence to drop a finding**: every one names the narrower finding that does survive.

1. **Insecure-looking code inside `if (__DEV__) { ... }`** — trust-all TLS, token logging, test credentials, debugging-tool wiring. Metro inlines `__DEV__` to `false` and folds the branch away **when the bundle is built with `dev: false`**, which is what the stock release path does, so the code is normally not in the shipped bundle. **The gate is the `dev` transform option, not the minifier** — and `--minify false` is the *normal* state of a Hermes release build, so do not read minification either way as evidence. This clearance therefore has a precondition that must be established, not assumed: that the shipped bundle was built with `dev: false`. Where it was not, the branch and **every string literal inside it** — a staging admin token, a trust-all wiring flag — ship in the bundle and are extractable.
   Report the conditions under which it survives, each of them a named build artifact (item 9): Gradle `project.ext.react` / `react { }` `extraPackagerArgs` containing `--dev true`, or a replaced `bundleCommand`; the Xcode "Bundle React Native code and images" phase running `react-native-xcode.sh` with `EXTRA_PACKAGER_ARGS`, `BUNDLE_COMMAND`, `FORCE_BUNDLING` or `SKIP_BUNDLING` set; an `eas.json` profile with `developmentClient: true` or a debug `gradleCommand`/`buildConfiguration`; a custom `transformerPath`, `transformer.babelTransformerPath` or serializer in `metro.config.js`; a runtime guard used instead of the literal (`if (config.debug)`, or `process.env.NODE_ENV` read from remote config); or the same code duplicated outside the guard. Verify against the release bundle.
   **Do not grep for `minifierEnabled`.** It is not a Metro option — absent from `metro-config`'s defaults and from every `metro*`/`@expo/metro*` package, and silently dropped by Metro's known-key schema. An escape hatch that cannot fire turns this entry into an unconditional clearance, which is how a shipped credential gets closed.
   **This does not extend to `console.log`.** Console calls are stripped only when the build configures it; absent `transform-remove-console` or a `drop_console` minifier option they ship. Do not generalize the `__DEV__` clearance to logging.

2. **`AsyncStorage` / MMKV / `UserDefaults` / `SharedPreferences` used at all.** These are the intended stores for non-secret local state: theme, locale, onboarding flags, a feature-flag cache, last-viewed screen, drafts the user typed. "Unencrypted storage" is a finding only when the value is a credential, a session or refresh token, an encryption key, or regulated data — and the finding must quote the key and classify the value. The same test governs a plaintext SQLite or Realm file in the sandbox, which is additionally protected by Android file-based encryption and iOS Data Protection; escalate that only on a concrete exposure path — inclusion in Auto Backup or a device/iTunes backup, a shared container or an exported `ContentProvider`, `NSFileProtectionNone`, or an explicit encryption-at-rest requirement.
   **The presence of a secure store elsewhere in the app clears nothing.** `expo-secure-store` used for the access token says nothing about the refresh token in `AsyncStorage` two files away.

3. **A long, high-entropy string in `google-services.json`, `GoogleService-Info.plist`, `app.json`, or a constants/env file.** Many mobile SDK keys are public client identifiers designed to ship in the binary: the Firebase `apiKey`, Maps/Places SDK keys, a Sentry DSN, a *publishable* payment key, a *public* IAP-wrapper SDK key, an OAuth *client ID*, an Expo project id, analytics write keys. Their presence is not the vulnerability. Ask whether the credential authorizes privileged reads or writes on its own; if it does not, either report the missing server-side control — absent backend rules, a Maps key with no bundle-id/SHA-1 restriction and no quota — or drop it.
   **The inverse is not a clearance.** "It is in a config file, so it must be a public key" is how a service-account JSON, a `service_role` key or a client secret gets waved through. Establish the credential's scope from its shape and its provider, not from the file it sits in.

4. **`android:exported="true"` on a component.** Export is mandatory for the launcher activity, share targets and app-link activities. Since API 31 the attribute must be declared explicitly for any component with an intent filter, so most explicit `true` values in modern manifests are compiler-forced annotations of pre-existing filters, and many entries in the *merged* manifest are library-owned. A finding needs an app-authored component, reachable without a signature or custom permission, that changes state or returns data the caller should not have.
   **Two things that look like they belong on that list do not, and the belief that they do has cleared real findings.** Both come from the same error — assuming that because the *platform* delivers an intent to a component, the component must be exported. It does not follow: the delivery path is in-process or permission-guarded.
   - **A messaging service.** An FCM `<service>` with a `com.google.firebase.MESSAGING_EVENT` intent filter is documented as `android:exported="false"` and functions that way, because the library's own exported receiver — itself guarded by `com.google.android.c2dm.permission.SEND` — dispatches to it in-process. `true` on one is an app-authored, unauthenticated entry point into `onMessageReceived`.
   - **A receiver of a protected system broadcast.** Same mechanism, same answer. Production apps ship `android:exported="false"` on `BOOT_COMPLETED` and comparable receivers and those receivers fire; a vendor library shipping to millions of installs does not declare `exported="false"` on a receiver that could then never run. Export is therefore not load-bearing here either, and `true` on such a receiver is an app-authored entry point any installed app can drive with a crafted intent.
   Trace both; do not wave either through. Grade on what the component does with the intent.
   **`exported="false"` is not the mirror-image clearance.** An `<activity-alias>`, a same-signature app, or an exported component that forwards the intent all reach a non-exported component. Check for the forwarding path before closing it.

5. **Cleartext or ATS-relaxing configuration in a manifest, plist or `network_security_config.xml`.** Three non-issues: `<debug-overrides>` is applied by the platform only when the app is debuggable, so trust-anchor relaxation there cannot affect a release build; `android:usesCleartextTraffic` is *ignored* where `android:networkSecurityConfig` is also declared, making a scary `="true"` dead configuration; and `NSAllowsArbitraryLoads` is overridden per-domain by `NSExceptionDomains` and often lives in a `Debug`-only plist or a debug source set. Always resolve the merged, release-variant manifest and plist before reporting. A fourth, purely mechanical one: `http://` inside an XML namespace declaration (`xmlns:android="http://schemas.android.com/apk/res/android"`), a schema URL, or a `localhost` development endpoint is not cleartext traffic.
   **The debug-overrides clearance has one exception and it is the whole point of item 9**: if the distributed build is debuggable, `<debug-overrides>` is live and the relaxation is real. Establish `android:debuggable` on the release variant before applying this.

6. **Missing certificate pinning.** Absent pinning is not a vulnerability: the platform trust store already defeats passive and opportunistic interception, and on Android the default network security config additionally excludes user-added CAs from app trust for apps targeting API 24 and above. Pinning is hardening with real availability risk, since a mis-rotated pin bricks every installed copy. Report it as hardening, or as a compliance gap against a standard the target is actually bound by, and never above this lens's Low/Medium band.
   **The platforms are not symmetric, so do not write the clearance as one general principle.** iOS has no counterpart to Android's user-CA exclusion: a user- or MDM-installed root enabled for full trust is honored by `URLSession`, and ATS constrains TLS version, ciphers and certificate hygiene, not which CA may issue. The grade still stands at Low. What changes is that on an iOS-only target the residual exposure is a trusted-profile install — an MDM-pushed root on a managed fleet, or a profile-install step in a phishing chain — and that is the case where item 5's Medium elevation applies. Never use "ATS is on" to dismiss a device-local MITM.
   **This clears *absent pinning only*.** It does not clear a disabled trust evaluation, a trust-all `TrustManager`, an always-true `HostnameVerifier`, or a user-CA trust anchor in `<base-config>`. Those are Critical and belong to `crypto-and-key-management`.

### Rejected candidates

Candidates considered for the list above and deliberately excluded. Each would have suppressed a real finding, or was too vague to apply. Do not quietly re-add them.

- **"Hermes bytecode / ProGuard / R8 is in use, so strings and logic are protected."** Rejected: it is a false clearance and it inverts the truth. Hermes is a compilation target, not encryption — `hbctool`, `hermes-dec` and `hasmer` recover it — and R8 renames symbols without hiding string constants. Written as a false positive it would close every embedded-credential finding in the corpus.
- **"`console.log` is stripped from release builds."** Rejected: false unless the build configures `transform-remove-console` or a `drop_console` minifier option. It reads plausible because the neighbouring `__DEV__` claim is true, which is exactly what makes it dangerous.
- **"A biometric prompt is present, so the stored token is protected."** Rejected: a `LAContext().evaluatePolicy` or `BiometricPrompt` result the app branches on is a UI gate, removable on a device the attacker controls and irrelevant to bytes at rest. Only `setUserAuthenticationRequired(true)` on the key, or a `SecAccessControl` on the Keychain item, binds the secret to the check.
- **"The finding is in test code — `__tests__`, `/e2e`, a Detox or Maestro config — so it does not ship."** Rejected as over-broad. A credential in a test file is frequently a live credential, and some harness configuration is compiled into debug artifacts that get distributed. The correct scoping question is per-artifact — is this file in the release bundle — which entry 1 already handles precisely.
- **"Mobile findings are lower severity because exploitation requires physical access to the device."** Rejected as vague and false. Rooting, malware with backup access, an emulator, a stolen backup archive and a shared family device are all non-physical paths, and the most common mobile exploitation path — a credential extracted from the bundle and replayed from anywhere — needs no device at all.
- **"ATS is on, so cleartext is impossible on iOS."** Rejected as a false clearance: ATS governs `URLSession` and `WKWebView`, not raw sockets, not every third-party networking stack, and not domains listed in `NSExceptionDomains`.
- **"Missing root/jailbreak detection."** Not a false positive — a severity question. It sits in `## Severity calibration` at Info, where it is capped rather than suppressed, so that the adjacent findings it is often bundled with are not cleared by the same rule.
- **"A messaging service has to be exported, so `android:exported="true"` on one is normal."** Rejected as a false clearance, and it arrived in the source material as an assertion. An FCM `MESSAGING_EVENT` service is documented `android:exported="false"`; the export is what turns `onMessageReceived` into an entry point any installed app can drive. Entry 4 states the correction inline so the clearance cannot be reassembled from the surrounding list.
- **"A receiver of a system broadcast has to be exported, so `android:exported="true"` on one is normal."** Rejected for the same reason and by the same evidence: production apps declare `android:exported="false"` on `BOOT_COMPLETED` receivers and those receivers fire. This one survived a round *because* its neighbour was corrected and it was not re-examined — it was one bullet away in the same mandatory-export list. When any item is removed from a list like that, re-derive every remaining item in the list.
- **"`minifierEnabled: false` is absent, so the `if (__DEV__)` block is not in the shipped bundle."** Rejected as a clearance built on a dead literal: `minifierEnabled` is not a Metro option, so its absence is guaranteed and proves nothing. The clearance that *does* hold requires establishing that the shipped bundle was built with `dev: false`, from the build artifacts item 9 names. Do not re-add any escape hatch whose literal you have not confirmed exists in the target ecosystem. **The rule covers every literal in a sweep, safe states included, not only escape hatches** — this defect recurred one round later as `supportOpenHelperFactory`, which is not a Room method (the real symbols are `openHelperFactory` and `SupportFactory`), so the sweep that lists the encrypted-at-rest safe states returned zero on a correctly SQLCipher-wired Room database.
- **"Unencrypted SQLite or Realm with no SQLCipher."** Not rejected as false — folded into entry 2, which is the same rule (classify the stored value, require a concrete exposure path) applied to a different store. Kept as one entry rather than two so the escalation list (Auto Backup, device or desktop backup, shared container, exported `ContentProvider`, `NSFileProtectionNone`, a stated encryption-at-rest requirement) lives in exactly one place and cannot drift.
- **"`react-native-webview` `injectedJavaScript` / `onMessage` is normal wiring."** Rejected as a false-positive entry, kept as a *proof requirement* in item 8 instead. Both props being ordinary is true; written as a suppression it teaches an auditor to skip the bridge, which is the highest-value surface in the lens. The operative instruction is to quote the interpolation site or the native side effect.
- **"A custom URL scheme is registered."** Rejected as a false-positive entry because the load-bearing half is advice, not a suppression — "prefer Universal Links" is hardening. It sits in `## Severity calibration` as an Info cap, where the genuine sub-cases (a scheme-entered route performing an authenticated state change; a scheme carrying an OAuth response with no PKCE and no verified `state`) still surface at their own severity.
- **"`adb backup` was restricted on modern Android, so `allowBackup` no longer matters."** Rejected: it is a true premise wired to a false conclusion, and it would close the Medium/High backup row wholesale. Auto Backup to the user's cloud account and device-to-device transfer are separate paths with separate configuration (`android:dataExtractionRules`), and both survive. Name the path you mean instead of retiring the check.
- **"The server presumably re-validates this."** Rejected outright: it is an assumption, not a control, and it is the single most common way a client-authoritative-state finding gets closed. With no server code in scope it goes in the finding as a stated assumption with a verification step, at the lower severity — never as a clearance.

## Proof recipes

Shared harness components are referenced by name and not restated here: the **canary fixture set** and the **socket-layer destination recorder**. Their implementations live in `lenses/_harness.md`.

**Tier rule.** T1 is a proof the repository's own test command executes (`npm test`, `jest`, `detox test` only if the repo already runs it in that command). T2 requires the auditor to stand up infrastructure the repository does not already stand up — an Android emulator, an iOS simulator, mitmproxy — and the user is asked every time. **The iOS half of every T2 recipe below additionally requires macOS and Xcode and is simply unavailable on a Windows or Linux audit host.** Say that in the coverage block; do not imply parity between the platforms.

### R1 — Deep-link resolution table (T1)

The single highest-value local proof in this lens, because the deep-link parser is pure logic that has been welded to a navigation container.

Refactor to a pure `resolveDeepLink(url: string): Route | null` and table-drive it. The corpus, at minimum: `javascript:alert(1)`, `file:///etc/passwd`, `//evil.tld/path`, `https://trusted.tld.evil.tld/`, `https://trusted.tld@evil.tld/`, a percent-encoded scheme (`%6a%61%76%61script:`), a homoglyph host, a scheme-relative redirect in a `next=` parameter, and a nested link (`myapp://open?url=myapp://admin`).

Where the link carries a capability — an invite, pairing or magic-link token (item 15) — table-drive the mutations in the same harness: flip the role or permission parameter, extend the expiry, swap the target id, truncate or drop the signature segment, and append a duplicate parameter (`?perm=view&perm=edit`) to see which one the parser keeps. Assert on the decision the resolver returns, never on a log line, and include one valid link, or a resolver that rejects everything passes.

**Fails on:** a resolver that returns the URL unchanged, hands it to `Linking.openURL`, or routes it into a WebView `source.uri`. **Passes on:** a resolver that returns `null` for everything outside its route table and an allowlisted origin set.

The device-side wiring shot — `adb shell am start -a android.intent.action.VIEW -d '<url>' <pkg>` and `xcrun simctl openurl booted '<url>'` — is **T2**, and proves the additional fact that the filter is registered and reachable. The pure-function table is what runs in CI.

### R2 — Destination-set assertion at the network layer (T1, with a stated blind spot)

Install the **socket-layer destination recorder** first so an unexpected connection fails loudly instead of silently reaching the internet. Record the destination set, assert it is a subset of the allowlist, and assert **ordering** where consent is involved: no analytics or attribution host may appear before the consent gate resolves (item 11).

**Install it at the layer this app's client actually uses, or the guard is the clean-looking result.** `nock.disableNetConnect()` patches Node's `http`/`https`, which is not where a React Native request goes: `react-native/Libraries/Network/fetch.js` requires `whatwg-fetch`, and that polyfill issues `new XMLHttpRequest()`, which RN binds to its native networking module. So a `nock`-only guard in an RN test records nothing, refuses nothing, and produces an empty destination set that reads as "this app talks to nobody". Guard `XMLHttpRequest` (and `global.fetch`, which some apps replace with `axios`' adapter or a custom client), assert the guard itself fires on a deliberate call to a `.test` host before trusting any result from it, and say in the finding which layer you hooked.

**The blind spot is load-bearing and must be reported with the result: native SDKs do not go through the JavaScript networking layer.** Firebase, a crash reporter's native layer, an attribution SDK and an ad SDK open their own sockets from native code, so a JS-level recorder cannot see them and a clean result proves only that the JS layer is clean. Proving the native side needs mitmproxy plus an emulator with a user CA installed — **T2**, and on a modern app the user CA is not trusted by default (item 5's own reasoning), so it also needs a debug build with a `<debug-overrides>` trust anchor. Say all of that rather than reporting a clean egress result.

### R3 — Detector-and-fixture pair over the rendered configuration (T1)

The only T1 proof for items 4, 7, 9 and 13, and the one that makes those findings defensible without a device. Write a checker over the **merged, release-variant** manifest, plist and `network_security_config.xml`, and ship it with a deliberately vulnerable fixture and a clean one, asserting `detect(fixtures/vulnerable/X) == 1` and `detect(fixtures/clean/X) == 0`. A checker that passes because it matched nothing is worthless; the vulnerable fixture is what proves it fires.

**Iterate components and count per component address, because a file-level count balances wrongly.** A merged manifest holds many components, so `detect(file) == 1` is satisfied on a fixture where one exported activity carries `android:permission` and a second does not: the protective attribute is present, the arithmetic works out, and the unprotected component is the finding. Write each rule as "for every component of this kind, the property holds", make every finding carry the component's `android:name` rather than the file it came from, and seed the vulnerable fixture with the shapes that expose the difference — two exported components and one permission attribute, an `<activity-alias>` aimed at a component declared `exported="false"`, a `debuggable`/`isDebuggable` override in a build type that several product flavors inherit.

**An absence-shaped rule needs one extra assertion.** Every assertion below fires on something *missing*, and a rule that fires on a missing artifact can pass by matching nothing at all — including when the parse failed or the fixture path was wrong. So also assert the rule fires on a fixture from which the artifact was **deliberately removed** (the manifest with the `android:allowBackup` attribute deleted, not set to `false`; the `updates` block with `codeSigningCertificate` deleted), and assert the rule set itself is non-empty, so a deleted rule cannot read as compliance.

Assertions worth encoding, each of which is an **absence** check that a value-grep would miss: `android:allowBackup` unset or true; `android:debuggable` true on the release variant; a `<certificates src="user"/>` outside `<debug-overrides>`; `cleartextTrafficPermitted="true"` in the effective config; `NSAllowsArbitraryLoads` true with no narrowing `NSExceptionDomains`; an `updates.url` with no `codeSigningCertificate`; a `PendingIntent` construction with neither mutability flag; an app-authored exported component with an intent filter and no permission attribute.

### R4 — On-device storage sentinel sweep (T2)

Write a known sentinel value through the app's real session-persistence path, background the app, then search the sandbox for it.

**Iterate the store directories; never name one database file.** `adb shell run-as <pkg> sh -c 'for f in databases/* shared_prefs/* files/*; do echo "== $f"; strings "$f" | grep -F "<sentinel>"; done'`. Naming `databases/RKStorage` specifically is how this recipe reports clean on a vulnerable app: with `AsyncStorage_useNextStorage=true` in `gradle.properties` the store is a Room database at `databases/AsyncStorage`, so check that property before you interpret a negative result. On iOS, `xcrun simctl get_app_container booted <bundle-id> data`, then grep the whole container — the `Library` tree first, since `Library/Application Support/<bundleID>/RCTAsyncLocalStorage_V1` is the current AsyncStorage default — and the `Documents` tree, which older versions used. Repeat against a backup archive to prove or disprove the Auto Backup path.

**Fails on:** the sentinel appearing in plaintext. **Passes on:** the sentinel appearing nowhere outside the Keychain or Keystore-backed store — **and only if you can state which directories you actually searched.** A pass from a sweep over one hardcoded filename is not a pass. Requires an emulator or simulator; the iOS half requires macOS.

### Not provable here, and reported as such every run

- **That the store binary was built from this checkout.** Nothing in a repository establishes what was signed and uploaded.
- **That the OTA update server is under the expected control**, or that its access control is what someone says it is. Item 13 is graded on the absence of signature verification precisely because the server's posture is not auditable from here.
- **What the backend enforces.** Every client-authoritative-state finding (item 15) rests on an assumption about the server; write the assumption down and route the finding.
- **Whether a device in the fleet has hardware-backed key storage**, or whether a silent software fallback occurred.
- **Whether the store listing, the Play Data Safety declaration or the privacy nutrition label matches the code.** One side of that comparison is not in the repository.
- **Runtime behaviour of a third-party SDK**, including what it transmits on initialization. The linked SDK and its initialization site are evidence; its payload is not.
