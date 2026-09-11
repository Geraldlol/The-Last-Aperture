---
name: desktop-and-thick-client-security
title: Desktop and thick-client security
runs_in: fanout
activates_on:
  paths:
    - '**/{desktop,electron,tauri,wpf,winforms,avalonia,winui,gtk,qt}/**'
    - '**/electron-builder.yml'
    - '**/electron-builder.yaml'
    - '**/electron-builder.json'
    - '**/electron-builder.json5'
    - '**/forge.config.js'
    - '**/forge.config.cjs'
    - '**/forge.config.mjs'
    - '**/forge.config.ts'
    - '**/tauri.conf.json'
    - '**/wails.json'
    - '**/*.appxmanifest'
    - '**/*.wixproj'
    - '**/*.wxs'
    - '**/*.iss'
    - '**/*.nsi'
    - '**/*.desktop'
    - '**/Package.appxmanifest'
  signals:
    - 'BrowserWindow('
    - 'ipcMain.handle('
    - 'ipcMain.on('
    - 'ipcRenderer.invoke('
    - 'contextBridge.exposeInMainWorld('
    - 'setAsDefaultProtocolClient('
    - 'webContents.setWindowOpenHandler('
    - 'shell.openExternal('
    - 'autoUpdater.checkForUpdates('
    - 'protocol.handle('
    - 'session.setPermissionRequestHandler('
    - 'nodeIntegration'
    - 'contextIsolation'
    - 'webviewTag'
    - 'tauri::Builder'
    - 'invoke_handler('
    - '#[tauri::command]'
    - 'wails.Run('
    - 'System.Windows.Application'
    - 'Microsoft.Web.WebView2'
    - 'NamedPipeServerStream'
    - 'WindowsIdentity.RunImpersonated'
    - 'ProcessStartInfo'
    - 'Windows.Security.Credentials.PasswordVault'
    - 'QApplication'
    - 'QLocalServer'
    - 'QDesktopServices::openUrl'
    - 'QProcess::start'
    - 'NSApplicationMain'
    - 'NSXPCConnection'
    - 'SMJobBless'
    - 'SUUpdater'
    - 'SPUUpdater'
    - 'SquirrelAwareVersion'
    - 'ClickOnce'
    - 'MSIX'
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: consumed
      artifact_kinds:
        - desktop-package
        - native-executable
        - shared-library
      may_conclude:
        - artifact-signature-invalid
        - binary-hardening-missing
        - secret-present-in-artifact
        - unexpected-artifact-content
        - vulnerable-component-present
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
owns:
  - desktop-installation-and-package-trust
  - desktop-update-authenticity-and-rollback
  - desktop-local-data-and-secret-storage
  - desktop-local-ipc-and-process-boundaries
  - desktop-uri-file-association-and-launch-handling
  - desktop-webview-and-native-bridge-trust
  - desktop-plugin-extension-and-scripting-trust
  - desktop-privilege-elevation-and-broker-boundaries
  - desktop-debug-diagnostic-and-developer-surface
  - desktop-os-integration-and-shell-invocation
defers:
  mobile-build-and-runtime-flags: mobile-app-security
  mobile-local-data-storage: mobile-app-security
  mobile-ui-and-notification-leakage: mobile-app-security
  webview-bridge-trust: mobile-app-security
  native-app-oauth-integration: mobile-app-security
  ota-update-integrity: mobile-app-security
  native-compiler-and-platform-hardening: native-and-memory-safety
  memory-bounds-and-integer-conversion: native-and-memory-safety
  unsafe-ffi-and-language-boundaries: native-and-memory-safety
  native-fuzzing-and-sanitizer-coverage: native-and-memory-safety
  authentication-and-credential-flows: web-and-api
  authz-function-level: web-and-api
  browser-origin-and-runtime-trust: web-and-api
  deserialization-and-xxe: web-and-api
  path-traversal-and-file-access: web-and-api
  open-redirect: web-and-api
  hardcoded-credentials-and-key-material: crypto-and-key-management
  key-separation-derivation-and-destruction: crypto-and-key-management
  tls-and-certificate-validation: crypto-and-key-management
  artifact-signing-and-provenance-emission: cicd-and-supply-chain
  package-dependency-cves: cicd-and-supply-chain
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  install-and-lifecycle-scripts: cicd-and-supply-chain
  personal-data-severity-uplift: privacy-and-data-protection
  pii-inventory-and-data-map: privacy-and-data-protection
  retention-lawfulness-and-deletion-completeness: privacy-and-data-protection
  security-event-coverage: security-observability-and-response
  security-control-failure-mode: failure-semantics-and-resilience
frameworks:
  - owasp-tcasvs-5.0.0
  - owasp-asvs-5.0.0
  - cwe-4.20
severity_floor: low
---

## Scope

This lens audits locally installed applications whose trust boundary includes
the operating system and other local processes: Electron, Tauri, Wails, WPF,
WinForms, WinUI, Avalonia, Qt, GTK, native desktop shells, and comparable thick
clients. It owns installer and updater consumption, local data, IPC and process
identity, protocol/file handlers, embedded web-to-native bridges, plugins,
privilege brokers, diagnostic surfaces, and operating-system launch or shell
integration.

A desktop framework, packaging file, or local API is only an activator. A
candidate requires an attacker-controlled local, remote, file, URI, plugin,
renderer, or lower-privilege input; the trusted operation it reaches; and the
missing validation, identity, authorization, or integrity boundary. “The user
controls their own computer” does not erase cross-user, low-integrity,
sandboxed-renderer, unprivileged-process, enterprise-policy, or update-server
threat models.

This lens consumes source plus canonical `desktop-package`,
`native-executable`, and `shared-library` built-artifact evidence. For exact
acquired bytes it may conclude only `artifact-signature-invalid`,
`binary-hardening-missing`, `secret-present-in-artifact`,
`unexpected-artifact-content`, or `vulnerable-component-present`. Deployed
policy, workstation state, installed ACLs, runtime IPC peers, loaded plugins,
and live renderers remain unconsumed. A package or binary proves its own
contents and properties, not that a particular workstation installed or ran it.

### Owns

| Topic | What that means here |
|---|---|
| `desktop-installation-and-package-trust` | How a thick client verifies and consumes its installer/package, publisher identity, platform signing, install scope, privileged custom actions, file and registry ACLs, repair behavior, and package replacement. |
| `desktop-update-authenticity-and-rollback` | Desktop updater metadata and payload authentication, immutable release identity, channel trust, downgrade prevention, staging, atomic activation, rollback safety, and update transport assumptions. |
| `desktop-local-data-and-secret-storage` | Placement, access control, user/profile separation, encryption binding, backups, crash artifacts, caches, logs, offline state, and credential-vault use for data stored by an installed client. |
| `desktop-local-ipc-and-process-boundaries` | Named pipes, Unix sockets, XPC, COM/RPC, D-Bus, shared memory, loopback listeners, single-instance messages, process discovery, peer identity, message authorization, framing, and replay. |
| `desktop-uri-file-association-and-launch-handling` | Custom URI schemes, file associations, command-line forwarding, drag/drop and open-file events, canonical parsing, instance handoff, and user-intent checks before a local application performs a privileged or sensitive action. |
| `desktop-webview-and-native-bridge-trust` | Electron renderers, WebView2, WKWebView, Qt WebEngine, Tauri/Wails bridges, preload scripts, navigation/origin isolation, permission mediation, exposed native methods, and renderer-to-main authorization. |
| `desktop-plugin-extension-and-scripting-trust` | Discovery, provenance, compatibility, isolation, permissions, update, revocation, and data/command boundaries for locally loaded plugins, extensions, macros, templates, and embedded scripting. |
| `desktop-privilege-elevation-and-broker-boundaries` | Helper services, privileged brokers, UAC/elevation paths, authorization services, XPC/COM helpers, setuid components, service installation, caller identity, request authorization, and confused-deputy prevention. |
| `desktop-debug-diagnostic-and-developer-surface` | Production devtools, debug ports, diagnostic consoles, crash handlers, support bundles, tracing, test hooks, remote inspection, and developer endpoints that expose data or trusted operations. |
| `desktop-os-integration-and-shell-invocation` | Process launch, shell/open operations, environment and working-directory trust, search-path resolution, registry and keychain integration, notifications, clipboard, screen capture, global shortcuts, and OS-mediated capability requests. |

### Does not own

- **mobile-app-security** retains Android/iOS packaging, storage, WebViews,
  deep links, OAuth, store declarations, OTA updates, and mobile UI leakage.
  Shared UI technology does not make a mobile bundle a desktop client.
- **native-and-memory-safety** owns buffer/lifetime defects, unsafe FFI,
  compiler/linker hardening, and sanitizer/fuzzer coverage. This lens may trace
  how untrusted local input reaches native code without duplicating the memory
  defect.
- **web-and-api** owns server/API authentication and authorization, browser
  origin controls, ordinary redirects, path traversal, deserialization, and
  network responses. This lens owns the installed client's OS/process and
  renderer-to-native trust boundary.
- **crypto-and-key-management** owns primitives, random generation, TLS,
  hardcoded keys, KDFs, and key destruction. This lens owns whether the client
  selects an OS-bound vault and whether another local principal can access the
  stored record.
- **cicd-and-supply-chain** owns dependency provenance/CVEs, lockfiles, build
  provenance, lifecycle scripts, and emission of artifact signatures. This
  lens owns the installer or updater decision that consumes a signed package.
- **privacy-and-data-protection** classifies personal data and owns retention,
  deletion, consent, and legal rights. This lens supplies the local storage or
  UI exposure mechanism and defers the regulatory conclusion.
- **failure-semantics-and-resilience** owns general cleanup, partial operations,
  retry, and fail-open behavior. Keep the desktop privilege, IPC, update, or
  renderer boundary here; file the generic failure mechanism there.

### Pinned framework sources and caveats

- The [OWASP TCASVS repository](https://github.com/OWASP/TCASVS) calls 5.0.0
  the latest stable content, with six chapters and three verification levels.
  A later `v5.0.1` GitHub release packages that 5.0 content but does not rename
  the normative standard in its source. This lens therefore pins requirement
  citations as `owasp-tcasvs-5.0.0` and records the exact repository tag or
  release asset used by an assessment.
- [OWASP ASVS 5.0.0](https://github.com/OWASP/ASVS/tree/v5.0.0) applies to the
  service/API and general application controls around a thick client. Cite
  identifiers as `v5.0.0-x.y.z`; do not use ASVS to claim a local package,
  renderer, or IPC property that TCASVS addresses directly.
- CWE 4.20 supplies weakness identifiers where source establishes a concrete
  defect, such as CWE-20, CWE-22, CWE-73, CWE-78, CWE-94, CWE-250, CWE-269,
  CWE-276, CWE-284, CWE-306, CWE-345, CWE-427, CWE-494, CWE-502, CWE-732,
  CWE-829, or CWE-939. A missing binary observation or organizational signing
  process is a coverage gap, not a forced CWE.

### What source cannot determine

- Without a canonical acquired package, the publisher/signing identity and
  timestamp, notarization, binary hardening, component inventory, and package
  contents. Even with one, whether production delivered, installed, or rejected
  that exact artifact remains unknown.
- Effective filesystem, registry, service, pipe/socket, keychain, sandbox,
  entitlement, AppContainer, integrity-level, SELinux, AppArmor, or enterprise
  policy on an installed workstation.
- Which renderer origin is live, what plugin bytes load, which local process
  connects, whether a low-privilege account can win a race, or what a runtime
  broker authorizes.
- Whether debug symbols, devtools, remote inspection, crash dumps, environment
  variables, command-line arguments, clipboard contents, or notifications
  contain production secrets.
- Effective runtime exploit mitigations and policy. An acquired executable or
  library can establish an applicable static hardening property is missing; it
  cannot prove loader, kernel, enterprise-policy, or runtime enforcement.

## Activation coverage

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| Electron and embedded web desktop shells | PARTIAL | `desktop-webview-and-native-bridge-trust` | Main/preload/renderer source and policy are reviewable; the shipped runtime, origins, flags, and loaded content are not consumed. |
| Tauri, Wails, and native web bridges | PARTIAL | `desktop-local-ipc-and-process-boundaries` | Command exposure and authorization can be traced; generated bindings and installed policy require local evidence. |
| Windows, macOS, Linux, Qt, and GTK desktop integration | PARTIAL | `desktop-os-integration-and-shell-invocation` | Source launch, broker, IPC, and storage paths are in scope; ACLs, entitlements, signatures, and runtime peers are external. |
| Installer and updater metadata | PARTIAL | `desktop-update-authenticity-and-rollback` | Source verification order and supplied package/signature evidence are reviewable; delivery, installation, channel state, and deployed updater policy remain external. |
| Plugins, diagnostics, URI and file handlers | PARTIAL | `desktop-plugin-extension-and-scripting-trust` | Enumerated handlers and gates can be fixture-tested; complete OS registration and loaded extension inventory are unavailable. |

## Candidate gate

Before assigning a candidate identifier, record:

1. the local trust boundary: another user, lower-integrity process, sandboxed
   renderer, remote content, file/URI sender, plugin author, update source, or
   unprivileged caller;
2. the exact IPC method, native bridge, handler, installer/updater action,
   broker operation, plugin load, or shell invocation reached;
3. the missing caller identity, authorization, canonicalization, provenance,
   integrity, isolation, or user-intent check;
4. a countercheck for platform enforcement and nearby validation; and
5. every package member, signature, workstation-policy, runtime-peer, and
   loaded-byte premise outside the supplied source and artifact bundles.

## Checklist

### 1. Installation and package consumption (`desktop-installation-and-package-trust`)

Trace package selection, publisher identity, signature verification, install
scope, elevation, custom actions, destination paths, ACLs, repair, uninstall,
and side-by-side/version transitions. Search for privileged installers that
load files from user-writable locations, execute unquoted or attacker-controlled
commands, inherit a weak search path, or repair a low-integrity replacement.
The build pipeline's signature emission belongs to supply chain; the local
consumer's decision belongs here.

### 2. Desktop updates (`desktop-update-authenticity-and-rollback`)

Require authenticated update metadata bound to exact payload digests,
publisher/channel/product identity, compatible platform and architecture,
monotonic security version, staged verification before execution, atomic
activation, and bounded rollback. A TLS URL or checksum fetched beside its
payload is not an authorization root. Follow alternate channels, developer
feeds, command-line overrides, and recovery updates.

```detector
match: |
  autoUpdater.setFeedURL({ url: settings.updateUrl })
  autoUpdater.checkForUpdates()
nomatch: |
  feed = updatePolicy.requireApprovedChannel(settings.channel)
  release = verifySignedUpdateMetadata(feed, TRUSTED_DESKTOP_RELEASE_KEYS)
  requireVersionAboveFloor(release.securityVersion)
  autoUpdater.checkForUpdates({ expectedDigest: release.packageSha256 })
```

### 3. Local data and secrets (`desktop-local-data-and-secret-storage`)

Inventory databases, preferences, logs, caches, session state, browser
profiles, cookies, tokens, crash artifacts, backups, exports, recent-file lists,
and OS credential vault entries. Establish user/profile separation, ACL intent,
encryption binding and recovery, logout/reset cleanup, and behavior under
roaming or backup. Obfuscation and a fixed application key do not create a
user-bound secret store.

```detector
match: |
  fs.writeFileSync(path.join(app.getPath('userData'), 'session.json'), token)
nomatch: |
  credentialRef = await osCredentialVault.store({
    account: authenticatedAccount.id,
    secret: token,
    access: 'current-user-and-current-device'
  })
  await sessionIndex.storeOpaqueReference(credentialRef)
```

### 4. IPC and process identity (`desktop-local-ipc-and-process-boundaries`)

Enumerate named pipes, Unix sockets, XPC, COM/RPC, D-Bus, shared memory,
loopback ports, single-instance messages, renderer IPC, and helper stdin/stdout.
Verify endpoint ACLs, peer identity, per-method authorization, message framing,
size and resource bounds, freshness/replay behavior, lifecycle cleanup, and
confused-deputy resistance. Possession of a pipe name or localhost connection
is not authentication.

```detector
match: |
  ipcMain.handle('export-file', async (_event, destination) => {
    return privilegedExporter.write(destination)
  })
nomatch: |
  ipcMain.handle('export-file', async (event, request) => {
    const caller = requireTrustedRenderer(event.senderFrame)
    const destination = requireUserApprovedExportPath(request.destination)
    return privilegedExporter.writeFor(caller.accountId, destination)
  })
```

### 5. URI, file association, and instance handoff (`desktop-uri-file-association-and-launch-handling`)

Trace custom schemes, file associations, startup arguments, open-file/open-URL
events, drag/drop, clipboard import, and secondary-instance forwarding. Parse
once into a typed request, reject ambiguous encodings, constrain files and
actions, bind sensitive operations to authenticated state and explicit user
intent, and prevent a low-integrity sender from inheriting a primary instance's
authority.

### 6. WebViews and native bridges (`desktop-webview-and-native-bridge-trust`)

Separate main, preload, renderer, and remote content. Enumerate every native
method/capability exposed across Electron context bridges, Tauri/Wails commands,
WebView2 host objects, WKWebView handlers, and Qt channels. Require strict
navigation and origin policy, context isolation, sandboxing where supported,
permission mediation, minimal typed APIs, per-call authorization in the trusted
process, and no raw filesystem/process/network primitive exposed to content.

```detector
match: |
  new BrowserWindow({ webPreferences: { nodeIntegration: true, contextIsolation: false } })
  contextBridge.exposeInMainWorld('desktop', { exec: require('child_process').exec })
nomatch: |
  new BrowserWindow({ webPreferences: { nodeIntegration: false, contextIsolation: true, sandbox: true } })
  contextBridge.exposeInMainWorld('desktop', {
    openInvoice: (id) => ipcRenderer.invoke('invoice:open', validateInvoiceId(id))
  })
```

### 7. Plugins and scripting (`desktop-plugin-extension-and-scripting-trust`)

Trace search roots, manifest parsing, publisher and digest checks, dependency
loading, permissions, process/sandbox separation, host API exposure, data
access, update, revocation, and compatibility. Treat macros, templates,
user-supplied automation, dynamic libraries, script engines, and package-like
extensions as code when they can reach trusted client capabilities. A signed
plugin is still subject to least privilege and revocation.

### 8. Privilege brokers (`desktop-privilege-elevation-and-broker-boundaries`)

Enumerate services, helpers, authorization plugins, setuid programs, scheduled
tasks, UAC/SMJobBless paths, installers, and privileged COM/XPC/RPC endpoints.
For every method, prove caller identity, allowed caller class, operation-level
authorization, canonical resource selection after elevation, argument and
environment validation, safe executable/library resolution, audit attribution,
and revocation. A GUI confirmation in an unprivileged process does not
authorize a separate broker request.

### 9. Debug and diagnostics (`desktop-debug-diagnostic-and-developer-surface`)

Inventory devtools, remote debugging, debug ports, inspector flags, diagnostic
RPCs, support archives, crash dumps, trace/event providers, hidden menus, test
hooks, verbose logs, and environment/CLI switches. Determine how production
builds select them, who can activate them, what data they expose, and what
trusted operations they unlock. Preserve supportability; require authenticated,
bounded, redacted diagnostics rather than assuming total removal is correct.

### 10. OS integration and shell launch (`desktop-os-integration-and-shell-invocation`)

Trace process and shell launch, open-external calls, executable search,
working directory, inherited handles and environment, registry/protocol
registration, keychain/vault access, clipboard, notifications, global hooks,
screen capture, and accessibility APIs. Prefer structured argument vectors,
absolute trusted executables, explicit schemes/hosts/actions, no shell when it
is not required, and a user-intent boundary for operations leaving the app.

```detector
match: |
  shell.openExternal(request.url)
  new ProcessStartInfo(request.command) { UseShellExecute = true }
nomatch: |
  destination = approvedExternalDestination.parse(request.url)
  requireExplicitUserIntent(destination)
  shell.openExternal(destination.canonicalHttpsUrl)
```

## Severity calibration

These are claimed-impact grades; global reachability and proof caps still
apply.

| Established condition | Claimed impact severity |
|---|---|
| Untrusted remote content or an unprivileged local process reaches an always-present privileged broker and obtains arbitrary code execution as system/root | Critical |
| A normal update path accepts an attacker-selected executable package without an authorized signature, or a renderer/URI/plugin boundary yields arbitrary native code execution with user privileges | High |
| Cross-user local data/credential theft, privileged file write, sensitive native method abuse, or persistent plugin execution has a traced reachable path | High |
| A source boundary is plausibly bypassable but shipped configuration, package, ACL, peer identity, or production origin remains unverified | Medium |
| A diagnostic, hardening, provenance, or defense-in-depth gap lacks a concrete attacker-to-impact path | Low |
| Merely using Electron, WebView2, a named pipe, updater, plugin system, or shell API | Not a finding |

## Known false positives

1. `nodeIntegration` is enabled only for bundled, immutable content with no
   navigation, injection, or untrusted-data-to-DOM path. Verify all premises;
   the flag alone is not a finding.
2. Devtools or a debug port exists only in a release-excluded development
   profile selected by the trusted build. Source does not prove the shipped
   profile, so record the artifact gap.
3. A named pipe or XPC service relies on platform-enforced peer identity and a
   restrictive descriptor. Read the actual security descriptor/entitlement and
   per-method authorization before filing.
4. A custom URI handler only opens a public, read-only view after parsing and
   explicit confirmation. Scheme registration alone is not exploitation.
5. `shell.openExternal` receives a closed set of canonical HTTPS destinations
   and cannot select local files, dangerous schemes, arguments, or commands.
6. A plaintext preference contains no secret or sensitive data. Classify the
   value before treating storage format as exposure.
7. A plugin directory is user-writable because plugins run with the same user
   authority and no application/server trust is granted to them. Establish the
   privilege or data boundary.
8. An unsigned portable build is a deliberate distribution model and the
   application never treats local integrity as a security control. Do not claim
   package-substitution impact without its delivery and trust path.
9. Rollback is an authenticated emergency recovery to a release above the
   security floor. Downgrade prevention need not forbid all older versions.
10. A process launch uses structured arguments and an absolute trusted binary;
    an attacker-controlled argument is not automatically command injection.
11. A crash dump setting in source does not prove production dumps exist or
    contain a named secret.
12. A platform vault API does not prove safe access policy. Conversely, absence
    of one API does not prove secrets are stored insecurely.

### Rejected candidates

| Candidate | Rejection reason |
|---|---|
| “Electron is insecure” | Framework choice is not a vulnerability; trace a renderer, navigation, IPC, or native-capability boundary. |
| “Named pipe found” | Endpoint existence does not establish weak ACLs, caller identity, or sensitive methods. |
| “No code-signing setting found” | Shipped package evidence is absent and signing may be external. Record a gap unless this repository owns the full release contract. |
| “The app stores JSON” | Data class, protection requirement, and local attacker path are missing. |
| “A plugin loader exists” | Establish attacker influence, trust granted to the plugin, missing provenance/isolation, and impact. |
| “The updater uses HTTPS” | HTTPS is neither a defect nor sufficient update authorization. Assess metadata and package trust. |

## Proof recipes

All proofs follow `_harness.md` in a disposable mirror. Use synthetic accounts,
files, URI values, packages, signatures, processes, plugins, and renderer
origins. Never install a package, elevate, register a global handler, mutate the
host OS, or contact a release server through an ad hoc command. Without an
authorized repository runner, preserve executable recipes as T3.

### D1 - Renderer-to-native capability table (T1 when supported)

Enumerate every preload/bridge export and every main-process or native command.
Drive calls from the trusted application origin, a remote origin, a navigated
subframe, a stale renderer, and an unauthenticated state. Put spies before
filesystem, process, credential, and privileged operations. The clean fixture
allows one least-privilege call; every negative fixture records zero trusted
operations.

### D2 - IPC peer and method authorization (T1 when supported)

Use a repository-provided in-memory or loopback-only transport fake. Submit
framed messages as the expected peer and as a wrong user, integrity level,
session, renderer, tenant, stale instance, and replayed request. Assert identity
is obtained from the transport/controller rather than message fields, and that
authorization occurs for each method before side effects.

### D3 - Update metadata and package fixture pair (T1 when supported)

Use inert package bytes and test-only keys. Mutate publisher, signature,
metadata digest, payload digest, product, architecture, channel, security
version, and component set. Place the observation boundary before staging or
launch. The valid fixture stages exactly one package; all mutations stage none.
This does not prove a production signature or installed updater configuration.

### D4 - URI/file handler decision table (T1 when supported)

Generate canonical and ambiguous URIs, encoded separators, dangerous schemes,
UNC/device-like paths, relative files, secondary-instance messages, and stale
authentication state. Assert parsing yields one typed operation, sensitive
actions require current user intent, and rejected inputs never cross the
trusted handler boundary.

### D5 - Plugin and broker negative controls (T1 when supported)

Use a synthetic plugin manifest and inert payload plus a fake broker. Mutate
signer, digest, capability, version, revocation state, caller identity,
operation, and target path. Assert no plugin load or privileged action occurs
before complete authorization. Do not load native attacker bytes or invoke
actual elevation.

### D6 - Source-only package and workstation nonclaim (T0)

Record the requested build/update/IPC/sandbox policy and list the uninspected
package, signature, entitlement, ACL, process, renderer, plugin, and workstation
state. A source option is not rendered as an effective runtime property.

### D7 - Package and native-binary reconciliation (T0/T1 when supported)

For each exact `desktop-package`, `native-executable`, or `shared-library`
bundle, verify manifest/member hashes and enumerate executables, libraries,
resources, plugins, update metadata, signatures, hardening properties, readable
secret canaries, and component identities. Reconcile every member to source and
the release manifest. Omitted architectures or nested packages make coverage
PARTIAL. Findings apply to acquired bytes only; installation and execution are
not implied.
