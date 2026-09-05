---
name: embedded-iot-ot-security
title: Embedded, IoT, OT, and cyber-physical security
runs_in: fanout
activates_on:
  paths:
    - '**/{firmware,embedded,bootloader,rtos,freertos,zephyr,esp-idf,arduino,plc,scada,ics}/**'
    - '**/{modbus,opcua,canopen,lwm2m,coap}/**'
    - '**/platformio.ini'
    - '**/sdkconfig'
    - '**/sdkconfig.*'
    - '**/west.yml'
    - '**/prj.conf'
    - '**/Kconfig'
    - '**/*.dts'
    - '**/*.dtsi'
    - '**/*.ld'
    - '**/*.svd'
    - '**/*.ino'
  signals:
    - 'CONFIG_BOOTLOADER_MCUBOOT'
    - 'BOOT_SWAP_TYPE_REVERT'
    - 'esp_ota_begin('
    - 'esp_ota_set_boot_partition('
    - 'HAL_FLASH_Unlock('
    - 'NVIC_SystemReset('
    - 'CONFIG_FREERTOS'
    - 'FreeRTOS.h'
    - 'DEVICE_DT_GET('
    - 'DT_NODELABEL('
    - 'U_BOOT_CMD('
    - 'CONFIG_SECURE_BOOT'
    - 'CONFIG_FLASH_PROTECTION'
    - 'CONFIG_ARM_MPU'
    - 'CONFIG_TRUSTED_EXECUTION_NONSECURE'
    - 'jtag_disable'
    - 'esp_efuse_disable_rom_download_mode'
    - 'NRF_UICR->APPROTECT'
    - 'modbus_receive('
    - 'eMBInit('
    - 'UA_Server_new('
    - 'CANopenNode'
    - 'coap_resource_init'
    - 'LwM2M'
    - 'esp_ble_gatts'
    - 'bt_conn_auth_cb_register'
    - 'WIFI_PROV_SECURITY_2'
    - 'device_provisioning'
    - 'factory_reset('
    - 'secure_element'
    - 'ATECC608'
    - 'TPM2_'
    - 'safety_interlock'
    - 'emergency_stop'
    - 'remote_maintenance'
    - 'OPC_UA'
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: consumed
      artifact_kinds:
        - firmware-image
      may_conclude:
        - artifact-signature-invalid
        - firmware-trust-gap
        - secret-present-in-artifact
        - unexpected-artifact-content
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
owns:
  - device-identity-and-secure-onboarding
  - firmware-boot-integrity-and-hardware-root-of-trust
  - firmware-update-authenticity-and-rollback-protection
  - embedded-debug-test-and-recovery-interface-exposure
  - device-service-and-local-protocol-hardening
  - physical-access-tamper-and-secret-extraction
  - cyberphysical-safety-interlocks-and-fail-safe-control
  - device-lifecycle-reset-and-decommissioning
  - iot-command-and-telemetry-boundary
  - ot-network-segmentation-and-remote-maintenance
  - wireless-pairing-and-provisioning
defers:
  memory-bounds-and-integer-conversion: native-and-memory-safety
  use-after-free-and-ownership-lifetime: native-and-memory-safety
  native-parser-and-state-machine-safety: native-and-memory-safety
  native-compiler-and-platform-hardening: native-and-memory-safety
  native-fuzzing-and-sanitizer-coverage: native-and-memory-safety
  hardcoded-credentials-and-key-material: crypto-and-key-management
  key-separation-derivation-and-destruction: crypto-and-key-management
  symmetric-encryption-and-nonce-handling: crypto-and-key-management
  tls-and-certificate-validation: crypto-and-key-management
  artifact-signing-and-provenance-emission: cicd-and-supply-chain
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  package-dependency-cves: cicd-and-supply-chain
  sbom-generation-and-attachment: cicd-and-supply-chain
  network-exposure-and-segmentation: cloud-and-iac
  iam-policy-and-privilege-scope: cloud-and-iac
  security-event-coverage: security-observability-and-response
  security-telemetry-pipeline-resilience: security-observability-and-response
  security-control-failure-mode: failure-semantics-and-resilience
  cleanup-and-resource-release: failure-semantics-and-resilience
  authentication-and-credential-flows: web-and-api
  authz-function-level: web-and-api
  pii-inventory-and-data-map: privacy-and-data-protection
  retention-lawfulness-and-deletion-completeness: privacy-and-data-protection
frameworks:
  - nist-ir-8259r1
  - nist-ir-8259a
  - nist-sp-800-82r3
  - iec-62443-4-2-2019
  - owasp-isvs-1.0.0-rc2
  - cwe-4.20
severity_floor: low
---

## Scope

This lens audits security properties that exist because software controls a
device or physical process: device identity and onboarding, boot and firmware
trust, update and rollback, maintenance and debug surfaces, local field
protocols, physical access assumptions, safety interlocks, reset and disposal,
radio provisioning, command/telemetry integrity, and OT remote access.

An embedded directory, RTOS include, register name, or industrial protocol is
only an activation signal. A candidate needs a quoted control path, a lower-
trust actor or input, the device or process state changed, and the security or
safety invariant that is lost. Do not infer an installed product, enabled
interface, fuse state, boot-ROM behavior, radio range, physical consequence, or
plant topology from repository source.

This lens consumes source and canonical `firmware-image` built-artifact
evidence. Linker scripts, device trees, board configuration, update manifests,
PLC programs, and synthetic protocol tests are source evidence. An exact,
content-addressed firmware bundle may support only
`artifact-signature-invalid`, `firmware-trust-gap`,
`secret-present-in-artifact`, or `unexpected-artifact-content`, with the
specific member bytes and adapter rule recorded. Hardware fuses, device
inventories, network captures, controller exports, live PLC state, and physical
observations remain unconsumed deployed/live evidence.

### Owns

| Topic | What that means here |
|---|---|
| `device-identity-and-secure-onboarding` | Per-device identity creation, factory-to-owner transfer, first-use bootstrap, credential uniqueness, authenticated enrollment, ownership rebinding, and prevention of cloned or default identities. |
| `firmware-boot-integrity-and-hardware-root-of-trust` | Boot-stage verification, immutable trust anchors, measured or verified boot policy, recovery-image trust, partition handoff, and source configuration for hardware-backed enforcement. |
| `firmware-update-authenticity-and-rollback-protection` | Complete firmware/update-set identity, authorized signature verification before write or boot, version monotonicity, anti-rollback state, interrupted-update recovery, and compatible component binding. |
| `embedded-debug-test-and-recovery-interface-exposure` | JTAG, SWD, UART consoles, bootloader shells, ROM download modes, manufacturing commands, recovery paths, test pads, diagnostic services, and production disable or authentication policy. |
| `device-service-and-local-protocol-hardening` | Device-side Modbus, OPC UA, CAN, CoAP, LwM2M, proprietary fieldbus, discovery, management, and local service operations whose protocol semantics create a device-control boundary. |
| `physical-access-tamper-and-secret-extraction` | Explicit physical-attacker assumptions, readout protection, external flash and bus exposure, secure-element use, tamper response, fault/glitch-sensitive transitions, and secrets whose custody depends on device hardware. |
| `cyberphysical-safety-interlocks-and-fail-safe-control` | Software-enforced limits, permissives, emergency stops, safety/security separation, command plausibility, manual override, and fault behavior where a cyber action can affect people, equipment, or the physical environment. |
| `device-lifecycle-reset-and-decommissioning` | Factory reset, ownership transfer, credential revocation, retained data, secure wipe, recovery, end-of-support behavior, and decommissioning paths implemented by the device. |
| `iot-command-and-telemetry-boundary` | Binding a command or telemetry record to device identity, authorization context, freshness, sequence, acknowledged state, and the correct device/product tenant across cloud-to-device and gateway paths. |
| `ot-network-segmentation-and-remote-maintenance` | Repository-declared OT zones/conduits, jump or maintenance paths, engineering-workstation trust, vendor remote access, protocol breaks, and enforcement around safety or control networks. |
| `wireless-pairing-and-provisioning` | BLE, Wi-Fi, NFC, Thread, Zigbee, or proprietary-radio discovery, pairing, proximity and user-presence assumptions, bootstrap secret exchange, re-pairing, and recovery from a lost controller. |

### Does not own

- **native-and-memory-safety** owns unsafe parsing, memory lifetime, integer
  conversion, FFI, sanitizer/fuzzer coverage, and compiler hardening. Firmware
  location does not move a buffer overflow into this lens.
- **crypto-and-key-management** owns primitive selection, randomness, nonce
  use, TLS validation, hardcoded keys, derivation, and destruction. This lens
  owns how a device provisions or uses an identity or hardware trust boundary;
  file the underlying cryptographic defect with its owner.
- **cicd-and-supply-chain** owns dependencies, CVEs, SBOM production, build
  provenance, and release-pipeline signing. This lens begins at the bootloader,
  updater, recovery path, or device admission decision that consumes a release.
- **cloud-and-iac** owns ordinary cloud IAM, storage, image admission, and
  generic network exposure. It does not own an OT zone/conduit model or a
  device's local control protocol.
- **web-and-api** owns general API authentication, authorization, injection,
  rate limiting, and webhooks. This lens keeps device identity, command
  freshness, pairing, field protocol, and physical-process consequences.
- **failure-semantics-and-resilience** owns generic cleanup, retries, resource
  bounds, and fail-open controls. This lens owns the cyber-physical safety
  interlock or device recovery invariant affected by that failure.
- **security-observability-and-response** owns event coverage, alerting, log
  integrity, and telemetry-pipeline resilience. Device event fields may be
  evidence here, but absence of detection or delivery is filed there.
- **privacy-and-data-protection** classifies personal data and owns retention,
  deletion, consent, and regulatory rights. This lens only traces device reset
  or ownership transfer mechanics; apply privacy severity through its owner.

### Pinned framework sources and caveats

- [NIST IR 8259 Rev. 1](https://doi.org/10.6028/NIST.IR.8259r1), final April
  2026, supersedes the 2020 base publication and supplies manufacturer
  activities. [NIST IR 8259A](https://doi.org/10.6028/NIST.IR.8259A), final May
  2020, supplies the device capability baseline. Neither proves that a specific
  product implements a capability.
- [NIST SP 800-82 Rev. 3](https://doi.org/10.6028/NIST.SP.800-82r3), final
  September 2023, supplies OT topology, threat, safety, reliability, and
  countermeasure context. NIST lists a Rev. 4 draft; this lens remains pinned
  to the latest final revision until that draft becomes final.
- [IEC 62443-4-2:2019](https://webstore.iec.ch/en/publication/34421) supplies
  technical security requirements for industrial automation and control-system
  components. It is a licensed standard: cite requirement identifiers only
  when the operator supplies the applicable licensed text; do not reconstruct
  normative wording here.
- The OWASP ISVS site simultaneously labels its material “Version 1.0” and
  warns that it is release candidate `1.0.0-RC2`. This lens therefore pins
  [ISVS 1.0.0-RC2](https://owasp.org/IoT-Security-Verification-Standard-ISVS/)
  as informative pre-release guidance and never claims final ISVS conformance.
- CWE 4.20 supplies weakness identifiers for concrete code defects. A missing
  product capability or unverified physical premise is not forced into a CWE.

### What source and firmware artifacts cannot determine

- Whether production fuses, secure boot, readout protection, memory
  protection, a secure element, or anti-rollback counters are actually set.
- Whether the built image equals reviewed source, which boot stage runs, which
  recovery image is installed, or which production signing key authorized it.
- Whether a debug pad is accessible, a radio can be reached, an interface is
  enabled, an OT conduit exists, or an engineering workstation is trusted.
- Whether a command changed physical state, an interlock stopped motion, a
  watchdog recovered safely, or a claimed impact is physically achievable.
- Whether device certificates are unique in the fleet, revoked, rotated, or
  rebound after ownership transfer.

## Activation coverage

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| Firmware, RTOS, board, and boot configuration | PARTIAL | `firmware-boot-integrity-and-hardware-root-of-trust` | Source establishes requested policy and a supplied firmware image can contradict it; ROM behavior, fuses, board state, and installed identity remain external. |
| Update, recovery, debug, and manufacturing APIs | PARTIAL | `firmware-update-authenticity-and-rollback-protection` | Control order and source gates are reviewable; production keys and device state are external. |
| Device and industrial protocols | PARTIAL | `device-service-and-local-protocol-hardening` | Parsers and command handlers are in scope; deployed services, topology, and wire behavior need exported evidence. |
| Wireless onboarding and identity | PARTIAL | `wireless-pairing-and-provisioning` | Pairing and enrollment source can be traced; proximity, user presence, radio range, and fleet uniqueness cannot. |
| Cyber-physical and OT maintenance paths | PARTIAL | `cyberphysical-safety-interlocks-and-fail-safe-control` | Source interlocks and declared zones are reviewable; plant topology and physical consequences are not inferred. |

## Candidate gate

Before assigning a candidate identifier, record:

1. the exact device, controller, gateway, boot stage, protocol handler, or
   safety function represented by the source;
2. the lower-trust actor or input and how it reaches the control;
3. the protected identity, update, command, process, or physical-state
   invariant;
4. the source branch that violates it, plus the countercheck that rules out a
   nearby enforcement point; and
5. every hardware, deployment, topology, fleet, and physical premise not
   consumed by this lens, plus any firmware image or partition outside the
   acquired bundle.

Use `reachable_from: unknown` when no repository-backed entry path exists. Use
one `contingent:` fact and query when exported device or topology state would
close the premise. Do not convert an uninspected fuse, controller, radio, or
plant into an asserted fact.

## Checklist

### 1. Device identity and enrollment (`device-identity-and-secure-onboarding`)

Trace identity from manufacture or first boot through enrollment, ownership
transfer, renewal, revocation, reset, and recovery. Look for shared defaults,
serial-number-derived secrets, cloneable enrollment tokens, unauthenticated
rebind, and a cloud record that accepts a device-selected tenant or owner.
Require a per-device identity or a one-time bootstrap protected by equivalent
entropy, a mutually authenticated enrollment boundary, explicit owner binding,
and a non-replayable transition.

```detector
match: |
  password = "admin"
  device_id = read_serial_number()
  cloud.enroll(device_id, password=password, owner=request.owner)
nomatch: |
  bootstrap = secure_element.consume_one_time_bootstrap()
  enrollment = cloud.begin_enrollment(attested_device=bootstrap.device_key)
  require_user_presence()
  cloud.bind_owner(enrollment, authenticated_owner.id)
```

### 2. Boot trust (`firmware-boot-integrity-and-hardware-root-of-trust`)

Enumerate every stage that selects or loads executable firmware: immutable ROM,
first-stage bootloader, recovery, second-stage bootloader, application,
coprocessor, radio, FPGA bitstream, and configuration interpreted as code.
Require the complete next stage to be authenticated before execution, trust
anchors to be immutable or authorized for rotation, and recovery to enforce no
weaker policy. A source flag is not evidence that production fuses or binaries
carry the property. When a canonical firmware image is supplied, enumerate its
boot stages, partitions, signature/manifest members, embedded trust anchors,
debug material, and source-accounted identities. File an artifact claim only
for the exact acquired bytes; the image still does not prove the device ROM,
fuses, or selected boot path.

### 3. Update and rollback (`firmware-update-authenticity-and-rollback-protection`)

Trace discovery, download, manifest parsing, signature verification, board and
product compatibility, version comparison, write, activation, health
confirmation, rollback, and interrupted-power recovery. Authenticate before
deserializing or flashing attacker-controlled payloads. Bind all partitions and
security-relevant configuration to one release identity, and store monotonic
state where an older image cannot rewrite it.

```detector
match: |
  esp_ota_begin(partition, image_size, &handle);
  stream_http_body(handle);
  esp_ota_set_boot_partition(partition);
nomatch: |
  manifest = verify_update_manifest(header, PRODUCT_UPDATE_KEYS);
  require_compatible_board(manifest.board_id);
  require_version_above_counter(manifest.security_version);
  stream_and_verify_partition(handle, manifest.image_sha256);
  commit_pending_boot(manifest.release_id);
```

### 4. Debug, test, and recovery (`embedded-debug-test-and-recovery-interface-exposure`)

Inventory JTAG/SWD, UART or USB shells, ROM download paths, bootloader commands,
factory fixtures, hidden maintenance RPCs, test modes, recovery buttons, and
diagnostic credentials. Verify the production configuration removes or
strongly authenticates dangerous operations and cannot be reverted through a
software-only flag controlled by untrusted input. Preserve a documented,
auditable recovery path instead of assuming “disable everything” is safe.

```detector
match: |
  if (gpio_read(FACTORY_MODE_PIN)) {
      console_enable_root_shell();
      jtag_enable();
  }
nomatch: |
  if (factory_fixture_attested() && lifecycle_state() == DEVICE_MANUFACTURING) {
      console_enable_bounded_fixture_commands();
  }
  assert_production_debug_policy_is_hardware_locked();
```

### 5. Local services and field protocols (`device-service-and-local-protocol-hardening`)

Enumerate function codes, methods, object identifiers, discovery endpoints,
broadcasts, maintenance commands, configuration writes, firmware triggers, and
diagnostic reads. Validate length and state first, then authenticate and
authorize against the device lifecycle and process mode. Protocols designed
without native security require a documented compensating boundary; do not
pretend that ordinary network placement is present without topology evidence.

### 6. Physical attacker model (`physical-access-tamper-and-secret-extraction`)

Map external flash, removable storage, test pads, exposed buses, debug pins,
boot straps, DMA-capable peripherals, secure elements, and key-loading paths.
Distinguish casual possession, skilled lab access, invasive extraction, and
fault injection. A repository can show that a secret is written to external
flash or that a secure-element API is used; it cannot prove package resistance,
fuse state, side-channel resistance, or tamper response.

### 7. Safety and physical control (`cyberphysical-safety-interlocks-and-fail-safe-control`)

Trace every untrusted or remote command that can move, heat, pressurize,
energize, unlock, dose, stop, or disable monitoring. Establish command bounds,
rate and sequence rules, process-state permissives, independent safety layers,
manual override, watchdog behavior, and the state selected on loss of
communications or integrity. Security “fail closed” is not automatically
physically safe; require the repository's explicit hazard and safe-state
contract.

```detector
match: |
  if (!cloud_command_valid(command)) {
      interlock_bypass = true;
      actuator_apply(command.requested_output);
  }
nomatch: |
  if (!cloud_command_valid(command)) {
      safety_controller.hold_last_verified_safe_state();
      record_rejected_command(command.sequence);
      require_local_recovery_authorization();
  }
```

### 8. Reset, transfer, and end of life (`device-lifecycle-reset-and-decommissioning`)

Follow factory reset and ownership transfer across user data, Wi-Fi and radio
credentials, device keys, cloud bindings, logs, caches, removable media,
coprocessors, backup partitions, and paired controllers. Verify that reset does
not restore a shared default credential or preserve a prior owner's control.
Separate source mechanics from retention law and from whether flash erasure is
physically effective on the shipped medium.

### 9. Command and telemetry trust (`iot-command-and-telemetry-boundary`)

Bind commands to authenticated device and service identities, intended tenant,
authorized operation, expiry, sequence or nonce, configuration/version state,
and acknowledgement. Bind telemetry to device identity, measurement context,
monotonic or otherwise defensible time, and replay handling. A valid transport
session does not by itself authorize a command or prove that telemetry reflects
physical reality.

### 10. OT zones and maintenance (`ot-network-segmentation-and-remote-maintenance`)

Read declared zones, conduits, firewall policies, protocol gateways, jump
paths, vendor tunnels, engineering workstations, remote desktop, removable
media workflows, and safety/control separation. Require least privilege,
bounded duration, strong operator/device attribution, explicit target assets,
session revocation, and a recovery path. Source can reveal an unconditionally
enabled vendor tunnel; absence of a topology export is a gap, not proof of a
flat network.

### 11. Pairing and radio provisioning (`wireless-pairing-and-provisioning`)

Trace discovery and advertisements through association, authentication, key
agreement, owner confirmation, authorization, re-pairing, controller loss, and
reset. Validate that names, MAC addresses, serial numbers, QR contents, and
proximity are not treated as authentication by themselves. Require explicit
user intent for sensitive enrollment and bind any out-of-band value to both
parties and the current transcript.

## Severity calibration

These are claimed-impact grades. The global reachability, proof-tier, and
verification caps still apply.

| Established condition | Claimed impact severity |
|---|---|
| A remote or low-privilege actor can bypass an independent safety boundary and drive a credible life-safety or catastrophic physical consequence | Critical |
| An attacker can install persistent unauthorized firmware across a production device class, extract fleet-wide identity material, or issue unauthenticated commands with major physical effect | High |
| A reachable maintenance, pairing, field-protocol, or update path yields control of one device or materially unsafe process state | High |
| Source shows a bypassable security boundary, but hardware state, deployment, topology, or physical consequence remains unknown | Medium |
| A hardening, inventory, rotation, diagnostic, or defense-in-depth gap lacks a concrete attacker-to-impact path | Low |
| Merely using an RTOS, field protocol, radio, C/C++, or a device identifier | Not a finding |

## Known false positives

1. A debug symbol or driver API exists only in a manufacturing build excluded
   by an enforced production lifecycle state. Verify the gate and release path.
2. A bootloader supports unsigned development images, while immutable
   production configuration selects a separate verified policy. Do not merge
   build profiles without evidence.
3. A rollback partition is older but is itself signed, security-compatible,
   and above the monotonic security counter. Version age alone is not rollback.
4. Modbus, CAN, or another unauthenticated field protocol sits behind a
   documented, evidenced gateway and cannot be reached by the proposed actor.
   Record the topology premise rather than assuming either exposure or safety.
5. A serial number is public metadata but not an authenticator or key input.
6. A secure-element API name appears, but the candidate assumes protection the
   source neither uses nor claims. Presence is not proof; absence is not proof
   of software key custody.
7. Factory reset intentionally retains non-sensitive calibration and safety
   counters. Establish the data class and security consequence before filing.
8. A safety controller intentionally holds the last safe output instead of
   de-energizing. Judge it against the repository-backed hazard contract.
9. BLE “Just Works” pairing is used for public, read-only telemetry with no
   ownership or control consequence. Pairing mode alone is not High severity.
10. A watchdog or retry loop has a bounded, independently enforced deadline.
11. An OT diagram is documentation rather than deployed-state evidence. It may
    identify intended zones, but neither proves nor disproves enforcement.
12. The source requests readout protection or secure boot. Without artifact or
    hardware evidence, do not report the property as enabled or disabled.

### Rejected candidates

| Candidate | Rejection reason |
|---|---|
| “The firmware is written in C” | Language choice is not a vulnerability; concrete memory defects belong to the native lens. |
| “MQTT is insecure” | A protocol name establishes neither configuration, identity, authorization, nor reachability. |
| “JTAG string found” | It may be a constant, test fixture, development profile, or bounded factory path. Trace production selection and capability. |
| “No secure element detected” | Hardware inventory is absent and a secure element is not universally required. Assess the actual key and physical-attacker contract. |
| “No OT segmentation file exists” | Network topology and enforcement may live outside the repository. Record a coverage gap unless the repository claims to define them. |
| “A remote command could cause harm” | Name the reachable command, missing control, physical action, and hazard premise; speculation is not a finding. |

## Proof recipes

All proofs follow `_harness.md`, use synthetic device identities and data, and
never connect to a real device, radio, controller, broker, engineering station,
or OT network. Public T1/T2 execution remains unavailable unless the controller
provides the required runner authority; otherwise preserve the recipe as T3.

### E1 - Update admission and anti-rollback fixture pair (T1 when supported)

Exercise the repository updater with inert byte arrays and test-only keys. Pair
one complete, correctly signed, compatible, higher-security-version manifest
with mutations for signature, component digest, board identity, version,
missing partition, and interrupted write. Put a spy before flash commit and boot
selection. Assert every mutation records zero commits; the positive fixture
records one pending release and cannot mark it healthy until the repository's
health oracle succeeds. This proves the source gate, not a shipped boot chain.

### E2 - Device enrollment and command replay oracle (T1 when supported)

Use two synthetic devices, owners, and tenants. Attempt bootstrap replay,
cloned identity, cross-owner binding, expired command, duplicate sequence,
cross-tenant device identifier, and command after revocation. Assert the device
or gateway dispatch spy remains untouched. The clean fixture enrolls exactly
once and accepts one authorized fresh command.

### E3 - Debug and lifecycle policy table (T0/T1)

Enumerate build profile, lifecycle state, boot strap, recovery mode, and
requested command. Compare the repository decision with a committed table.
Include production, manufacturing, returned-device, reset, and recovery states.
This can prove a source decision or local pure function; it cannot prove fuses,
pads, or the physical lifecycle state.

### E4 - Cyber-physical state-machine invariant (T1 when supported)

Drive a deterministic model with valid, stale, malformed, replayed, and
out-of-sequence commands plus loss of communications and integrity failures.
Assert actuator bounds, independent permissives, emergency-stop priority, and
the documented safe state. Use only a fake actuator and safety controller.
Physical timing, mechanics, and hazard severity remain unproven.

### E5 - Protocol and pairing negative controls (T1 when supported)

Replay repository parsers and authorization code over synthetic frames for
each enumerated operation. Pair an authorized frame with wrong device,
operation, lifecycle, sequence, transcript, and owner. Record the handler or
actuator boundary, not just parser return values. Fuzzing a parser does not
prove network exposure or authorization correctness.

### E6 - Source-only nonclaim (T0)

When only configuration or source exists, state exactly what it requests and
list the missing artifact, fuse, device, topology, radio, controller, or
physical oracle. Never upgrade “configured” to “deployed,” “enabled,” “safe,”
or “effective.”

### E7 - Firmware image/source reconciliation (T0/T1 when supported)

For an exact `firmware-image` bundle, verify its manifest and member hashes,
enumerate partitions and executable/configuration members, and reconcile them
to source-declared release identity. Check the applicable artifact signature,
boot/update trust metadata, readable secret canaries, and unexpected members.
Any omitted or ambiguous partition makes coverage PARTIAL. This can establish
an artifact contradiction; it cannot establish installation, fuse state, boot
selection, or physical behavior.
