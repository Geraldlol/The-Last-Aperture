---
name: smart-contract-and-web3-security
title: Smart-contract and Web3 security
runs_in: fanout
activates_on:
  paths:
    - '**/*.sol'
    - '**/*.vy'
    - '**/*.move'
    - '**/*.cairo'
    - '**/foundry.toml'
    - '**/hardhat.config.js'
    - '**/hardhat.config.cjs'
    - '**/hardhat.config.mjs'
    - '**/hardhat.config.ts'
    - '**/truffle-config.js'
    - '**/truffle-config.ts'
    - '**/brownie-config.yml'
    - '**/brownie-config.yaml'
    - '**/ape-config.yml'
    - '**/ape-config.yaml'
    - '**/remappings.txt'
    - '**/Move.toml'
    - '**/Scarb.toml'
    - '**/Anchor.toml'
  signals:
    - 'pragma solidity'
    - 'interface IERC'
    - 'msg.sender'
    - 'msg.value'
    - 'tx.origin'
    - 'delegatecall('
    - 'staticcall('
    - 'call{value:'
    - 'selfdestruct('
    - 'block.timestamp'
    - 'block.prevrandao'
    - 'block.number'
    - 'ecrecover('
    - 'abi.encodePacked('
    - 'onlyOwner'
    - 'nonReentrant'
    - 'initializer'
    - 'UUPSUpgradeable'
    - 'TransparentUpgradeableProxy'
    - 'upgradeToAndCall('
    - 'proxiableUUID('
    - 'IERC20'
    - 'IERC4626'
    - 'permit('
    - 'DOMAIN_SEPARATOR'
    - 'latestRoundData('
    - 'getReserves('
    - 'flashLoan('
    - 'CREATE2'
    - 'chainid()'
    - 'public entry fun'
    - '&signer'
    - '#[starknet::contract]'
    - 'get_caller_address('
    - '#[program]'
    - 'anchor_lang::prelude'
    - 'AccountInfo<'
    - 'invoke_signed('
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: consumed
      artifact_kinds:
        - smart-contract-build
      may_conclude:
        - smart-contract-deployment-drift
        - unexpected-artifact-content
        - secret-present-in-artifact
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
owns:
  - contract-access-control-and-privileged-roles
  - contract-initialization-and-deployment-state
  - reentrancy-and-external-call-ordering
  - delegatecall-proxy-and-target-trust
  - contract-upgradeability-and-storage-layout
  - oracle-data-and-price-manipulation
  - flash-loan-and-economic-invariant-abuse
  - transaction-ordering-front-running-and-mev
  - token-accounting-and-standard-conformance
  - onchain-arithmetic-precision-and-share-accounting
  - gas-griefing-and-unbounded-onchain-execution
  - block-context-randomness-and-time-dependence
  - onchain-signature-replay-and-domain-separation
  - cross-chain-bridge-and-message-integrity
  - emergency-governance-pause-and-recovery
defers:
  authentication-and-credential-flows: web-and-api
  authz-function-level: web-and-api
  authz-object-level: web-and-api
  client-trusted-business-rules: web-and-api
  injection-command-and-template: web-and-api
  rate-limiting-and-request-quotas: web-and-api
  race-conditions-and-toctou: web-and-api
  webhook-handler-integrity: web-and-api
  asymmetric-scheme-pitfalls: crypto-and-key-management
  csprng-and-token-entropy: crypto-and-key-management
  hardcoded-credentials-and-key-material: crypto-and-key-management
  hmac-and-constant-time-comparison: crypto-and-key-management
  key-separation-derivation-and-destruction: crypto-and-key-management
  signature-malleability-and-curve-validation: crypto-and-key-management
  artifact-signing-and-provenance-emission: cicd-and-supply-chain
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  package-dependency-cves: cicd-and-supply-chain
  runner-and-build-environment-trust: cicd-and-supply-chain
  sbom-generation-and-attachment: cicd-and-supply-chain
  deploy-time-signature-enforcement: cloud-and-iac
  iam-policy-and-privilege-scope: cloud-and-iac
  kms-key-lifecycle-and-policy: cloud-and-iac
  database-integrity-transactions-and-concurrency: database-and-data-stores
  partial-operation-and-rollback: failure-semantics-and-resilience
  resource-exhaustion-and-bounded-work: failure-semantics-and-resilience
  security-control-failure-mode: failure-semantics-and-resilience
  security-event-coverage: security-observability-and-response
  detection-alerting-and-escalation: security-observability-and-response
  architecture-trust-design-gaps: threat-modeling
  attack-tree-construction: threat-modeling
  pivot-feasibility: threat-modeling
  personal-data-severity-uplift: privacy-and-data-protection
  desktop-local-data-and-secret-storage: desktop-and-thick-client-security
  desktop-plugin-extension-and-scripting-trust: desktop-and-thick-client-security
frameworks:
  - owasp-scsvs-0.0.1
  - owasp-smart-contract-top-10-2026
  - eea-ethtrust-v3-2025
  - cwe-4.20
severity_floor: low
---

## Scope

This lens audits security properties created by deterministic, publicly
callable, economically composable state machines: EVM/Solidity and Vyper
contracts, Move modules, Cairo/Starknet contracts, and Solana/Anchor programs
when their source is present. It owns on-chain access and initialization,
external-call and reentrancy ordering, proxy/delegate targets, upgrade storage,
oracles, economic invariants, transaction ordering, token accounting,
arithmetic, gas/liveness, block-context assumptions, signed authorizations,
bridges, and emergency governance.

A language keyword, token interface, proxy base class, external call, oracle,
or flash loan is only an activator. A candidate must identify the attacker
capability, reachable transaction or message, pre-state, ordered operations,
violated invariant, beneficiaries and losers, and counterchecks. Composability
is not itself a defect; the bug is an invariant that fails under an allowed
composition.

This lens consumes source and canonical `smart-contract-build` built-artifact
evidence. Contract source, deployment scripts, configuration, interfaces, and
deterministic fixtures are source evidence. Exact build output may support only
`smart-contract-deployment-drift`, `unexpected-artifact-content`, or
`secret-present-in-artifact`; the claim must identify the acquired bytecode,
ABI, layout/compiler metadata, or controller-bound comparison record. Deployed
addresses/storage, chain history, mempool/order flow, validator behavior,
oracles, bridge committees, governance state, balances, and live execution
remain unconsumed. A build artifact never proves that its code was deployed.

### Owns

| Topic | What that means here |
|---|---|
| `contract-access-control-and-privileged-roles` | On-chain caller, signer, account, capability, role, ownership, governance, multisig, timelock, and per-function authorization, including confused-deputy and meta-transaction context. |
| `contract-initialization-and-deployment-state` | Constructor/initializer coverage, one-time state, implementation locking, deterministic deployment assumptions, initial ownership/roles, parameter validation, and source deployment ordering. |
| `reentrancy-and-external-call-ordering` | Cross-function, cross-contract, callback, hook, token-receiver, read-only, and asynchronous reentrancy plus unchecked external-call outcomes and effects/interactions ordering. |
| `delegatecall-proxy-and-target-trust` | Delegate/call target selection, code identity, storage context, fallback routing, selector collisions, proxy admin boundaries, library replacement, and arbitrary implementation execution. |
| `contract-upgradeability-and-storage-layout` | Upgrade authorization, implementation compatibility, initializer/reinitializer rules, storage-slot/layout safety, migration completeness, rollback, beacon/diamond/module governance, and immutable audit trail. |
| `oracle-data-and-price-manipulation` | Price/data source identity, freshness, decimals, confidence, quorum, deviation, fallback, liquidity/manipulation resistance, sequencer state, and use in value-sensitive decisions. |
| `flash-loan-and-economic-invariant-abuse` | Atomic capital or temporary voting/liquidity used to violate collateral, solvency, accounting, governance, reward, mint/burn, liquidation, or market invariants; the loan is an amplifier, not the root cause. |
| `transaction-ordering-front-running-and-mev` | Mempool/order-dependent outcomes, sandwiching, displacement, insertion, liquidation races, commit/reveal, slippage/deadline, batch ordering, cross-domain information leakage, and proposer/sequencer influence. |
| `token-accounting-and-standard-conformance` | Asset transfer/mint/burn semantics, fee/rebase/deflationary behavior, callbacks, return values, approvals, decimals, supply, escrow, vault shares, and repository-claimed token/interface invariants. |
| `onchain-arithmetic-precision-and-share-accounting` | Fixed-point scale, rounding direction, repeated truncation, conversion, share/asset exchange rate, overflow/underflow in checked or unchecked contexts, and value created or lost across accounting paths. |
| `gas-griefing-and-unbounded-onchain-execution` | Attacker-controlled iteration/state growth, push payments, revert griefing, stipend assumptions, storage inflation, block/transaction limits, and critical operations that can become permanently unaffordable. |
| `block-context-randomness-and-time-dependence` | Miner/proposer/sequencer-influenced timestamp, height, hash, prevrandao/randomness, finality, reorg, L2 clock, and timing-window assumptions used for value or authorization. |
| `onchain-signature-replay-and-domain-separation` | EIP-712 or equivalent typed-data binding, chain and verifying-contract domain, nonce lifecycle, signer recovery, deadline, signature form, cross-function/cross-contract replay, and smart-account validation context. |
| `cross-chain-bridge-and-message-integrity` | Source/destination domain binding, finality, proof/attestation verification, signer/quorum rotation, message uniqueness and ordering, replay, mint/release accounting, relayer trust, and failure recovery. |
| `emergency-governance-pause-and-recovery` | Pause/guardian/timelock powers, quorum and voting snapshots, emergency scope, liveness, key/role transition, incident containment, unpause/recovery invariants, and prevention of permanent or unilateral seizure. |

### Does not own

- **web-and-api** owns wallets' and dApps' web/API authentication,
  authorization, injection, rate limiting, server business rules, webhooks, and
  ordinary concurrency. This lens starts at the signed transaction, chain
  account, program instruction, or cross-chain message boundary.
- **crypto-and-key-management** owns algorithms, curves, nonce generation,
  key custody, signing services, constant-time operations, and malleability.
  This lens owns on-chain domain binding, replay state, and how a verified signer
  authorizes a particular contract action.
- **cicd-and-supply-chain** owns dependency/CVE work, compiler and toolchain
  provenance, lockfiles, SBOMs, and artifact-signing emission. A vulnerable
  imported package is not refiled as a contract defect without a concrete
  reachable weakness in the audited code.
- **cloud-and-iac** owns off-chain deployer IAM, KMS, network exposure, and
  admission policy. This lens owns the contract's deployment/initialization and
  on-chain upgrade authorization state.
- **database-and-data-stores** owns off-chain database transactions,
  authorization, backups, replication, and migration. Atomic chain state and
  contract storage semantics remain here.
- **failure-semantics-and-resilience** owns generic retries, rollback, cleanup,
  and resource bounds. This lens keeps EVM/VM atomicity, revert griefing, gas,
  bridge recovery, and on-chain invariant failures.
- **security-observability-and-response** owns event delivery, alerting,
  retention, and response pipelines. Missing or incorrect on-chain events can
  be context here, but an unmonitored event or failed alert is filed there.
- **desktop-and-thick-client-security** and **mobile-app-security** own wallet
  storage, local signing UX, deep links, plugins, and installed-client attack
  surfaces. **privacy-and-data-protection** owns personal-data classification
  and rights. Phishing, seed theft, exchange compromise, and endpoint malware
  are not smart-contract findings merely because they involve tokens.

### Pinned framework sources and caveats

- [OWASP SCSVS 0.0.1](https://owasp.org/www-project-smart-contract-security-verification-standard/)
  is the latest release explicitly called stable by the project page, dated
  September 2024. The project also calls it an initial draft/alpha and warns
  that its main branch is bleeding edge. Pin exact `0.0.1` material and never
  describe an assessment as conformance to a mature or final standard.
- [OWASP Smart Contract Top 10:2026](https://scs.owasp.org/sctop10/) is an
  awareness and prioritization document whose ordering is forward-looking and
  derived from 2025 incidents and practitioner input. Cite its edition and
  category, but do not use category membership as proof, severity, or complete
  verification coverage.
- [EEA EthTrust Security Levels Specification Version 3](https://entethalliance.org/specs/ethtrust-sl/v3/),
  EEA Specification March 2025, supplies versioned Solidity/EVM review
  requirements and levels. It does not cover Move, Cairo, Solana, every L2, or
  off-chain Web3 systems, and satisfying selected requirements is not an EEA
  certification claim. Its status text anticipates a successor in the second
  half of 2026, so re-check the EEA release URL before starting a new mapped
  assessment; this lens deliberately remains pinned to v3 until a successor is
  actually published and reviewed.
- CWE 4.20 is used only where a conventional weakness accurately names the
  demonstrated cause. Prefer the framework's native requirement/weakness IDs
  for VM, economic, bridge, oracle, and governance behavior rather than forcing
  every on-chain defect into a CWE.

### What source cannot determine

- Which bytecode and metadata were deployed, linked library addresses, or
  live proxy implementation/storage slots. A supplied build can establish its
  own compiler/settings and source relation; deployment comparison requires an
  exact controller-bound comparison record and still does not cover live state.
- Initialization, ownership, roles, multisig threshold, timelock queue,
  guardian, pause, upgrade, token balance, allowance, and bridge state on a
  live chain.
- Current oracle values, market liquidity, sequencer uptime, validator/proposer
  ordering, finality, reorg probability, fee market, or profitable MEV path.
- Whether a transaction simulation matches production state, another protocol
  composes with the contract, an attack is economically profitable, or funds
  are presently at risk.
- Off-chain signer custody, relayer policy, validator/committee compromise,
  governance participation, front-end behavior, or monitoring response.

## Activation coverage

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| Solidity, Vyper, and EVM toolchains | PARTIAL | `reentrancy-and-external-call-ordering` | Source, local fixtures, and supplied build bytecode/metadata are reviewable; deployed state and chain behavior are not consumed. |
| Move modules | PARTIAL | `contract-access-control-and-privileged-roles` | Signer/capability/resource invariants can be traced; package publication and chain state require runtime evidence. |
| Cairo and Starknet | PARTIAL | `block-context-randomness-and-time-dependence` | Caller, storage, L1/L2 messaging, and arithmetic source are in scope; sequencer and deployed-class state are not. |
| Solana and Anchor signals | PARTIAL | `contract-initialization-and-deployment-state` | Account constraints, signer/PDA and CPI paths can be traced when signals activate; program deployment and account state are unavailable. |
| DeFi, oracle, bridge, and governance composition | PARTIAL | `flash-loan-and-economic-invariant-abuse` | Repository invariants and deterministic mocks can be assessed; real liquidity, ordering, feeds, remote domains, and governance state remain gaps. |

## Candidate gate

Before assigning a candidate identifier, record:

1. chain/VM and source entry point, caller/account capability, calldata or
   instruction, and pre-state;
2. the ordered internal/external calls and state transitions;
3. the exact invariant violated, value/control created or lost, and repeat or
   composability conditions;
4. negative controls for authorization, initialization, paused state, token
   behavior, oracle freshness, ordering, rounding, and failure; and
5. every bytecode, deployed-state, chain, market, oracle, bridge, relayer,
   governance, and profitability premise unavailable to source evidence.

Do not use a mainnet address or public RPC in an improvised proof. If deployed
state is essential, record one `contingent:` fact and a bounded operator-run
query; otherwise use `unknown` and accept the global severity cap.

## Checklist

### 1. On-chain authorization (`contract-access-control-and-privileged-roles`)

Enumerate every public/external entry, instruction, callable fallback, callback,
upgrade, mint/burn, transfer, parameter, oracle, governance, pause, rescue, and
withdraw operation. Resolve the effective caller for direct, delegated,
meta-transaction, account-abstraction, cross-program, and cross-chain paths.
Require operation- and resource-specific authorization from trusted execution
context, not a caller-supplied owner, `tx.origin`, event, or front-end gate.

```detector
match: |
  function sweep(address token, address to) external {
      require(tx.origin == owner);
      IERC20(token).transfer(to, IERC20(token).balanceOf(address(this)));
  }
nomatch: |
  function sweep(address token, address to) external onlyRole(RESCUE_ROLE) {
      require(approvedRescueDestination[to]);
      IERC20(token).safeTransfer(to, IERC20(token).balanceOf(address(this)));
  }
```

### 2. Initialization and deployment (`contract-initialization-and-deployment-state`)

Trace constructor/initializer/reinitializer and deployment scripts together.
Verify every privileged and invariant-bearing field is set once, validated,
and assigned to the intended principal; implementation contracts are locked;
proxy initialization is atomic with deployment; CREATE2/address assumptions
bind chain, deployer, salt, and bytecode; and partial scripts cannot leave a
takeover window. Source cannot prove the transaction occurred.

### 3. External calls and reentrancy (`reentrancy-and-external-call-ordering`)

Enumerate value transfer, token hooks, receiver callbacks, fallbacks, arbitrary
calls, cross-program invocations, and view/read-only dependencies. Check return
values and revert behavior; update all state needed to make reentry safe before
control transfer or enforce a guard across every related entry point. Include
cross-function and cross-contract reentry, not only same-function recursion.

```detector
match: |
  (bool ok,) = msg.sender.call{value: balances[msg.sender]}("");
  require(ok);
  balances[msg.sender] = 0;
nomatch: |
  uint256 amount = balances[msg.sender];
  balances[msg.sender] = 0;
  (bool ok,) = msg.sender.call{value: amount}("");
  require(ok);
```

### 4. Delegate and proxy targets (`delegatecall-proxy-and-target-trust`)

Trace how implementation/library/program targets are selected, authenticated,
upgraded, and stored; how fallback selectors route; what storage context and
authority the target inherits; and whether a user controls target, calldata,
selector, account list, or program identifier. Verify code identity where the
platform supports it and avoid treating an address allowlist as immutable
without its update path.

### 5. Upgrades and storage (`contract-upgradeability-and-storage-layout`)

Enumerate transparent, UUPS, beacon, diamond, module, package, and program
upgrade paths. Require authorized and delayed transitions appropriate to risk,
implementation compatibility, storage-layout checks, initializer versioning,
complete migration, rollback constraints, and durable events. Test removal,
reordering, type/width change, inheritance change, namespace collision, and
new implementation that changes economic assumptions.

```detector
match: |
  function upgradeTo(address implementation) external {
      _setImplementation(implementation);
  }
nomatch: |
  function _authorizeUpgrade(address implementation) internal override onlyRole(UPGRADER_ROLE) {
      require(codeRegistry.isApproved(implementation));
      require(storageLayoutRegistry.compatible(address(this), implementation));
      require(timelock.isReady(keccak256(abi.encode(implementation))));
  }
```

### 6. Oracle decisions (`oracle-data-and-price-manipulation`)

For every value-sensitive decision, trace feed identity, aggregation, quorum,
decimals, units, sign, freshness, round completeness, confidence/deviation,
sequencer uptime, fallback, and market-liquidity assumptions. Reject spot or
same-transaction manipulable values where the attacker can move the source and
consume it before recovery. A reputable provider name does not prove correct
integration or current data.

### 7. Atomic capital and economic invariants (`flash-loan-and-economic-invariant-abuse`)

Write the solvency, conservation, collateral, share, governance, reward,
liquidation, mint/burn, and fee invariants independent of normal call order.
Test zero-cost temporary capital, temporary voting power, donated assets,
self-transfers, nested protocols, callback composition, and repeated small
operations. File the violated invariant, not “flash loans are dangerous.”

### 8. Ordering and MEV (`transaction-ordering-front-running-and-mev`)

Identify operations whose value or authorization depends on ordering: swaps,
liquidations, auctions, claims, reveals, mints, governance, bridge relays, and
oracle updates. Test attacker insertion before/between/after victim operations,
same-block batching, duplicate messages, proposer/sequencer control, deadlines,
slippage, commitment binding, and cancellation. A public mempool is context,
not a finding.

### 9. Tokens and interfaces (`token-accounting-and-standard-conformance`)

Treat tokens as adversarial implementations unless the contract explicitly
constrains them. Cover missing/false/no return values, fee-on-transfer,
rebasing, callbacks, blacklists, pausing, decimals, approval races, permit,
ERC-777-like hooks, ERC-4626 share semantics, NFTs, native assets, wrapped
assets, and duplicated accounting. Only claim standard nonconformance when the
repository claims that exact version/interface behavior.

### 10. Precision and share accounting (`onchain-arithmetic-precision-and-share-accounting`)

Track units and scale through every conversion. Check multiply/divide order,
rounding direction for each party, zero-share/zero-asset outcomes, initial and
near-empty pools, donation/inflation, accumulated dust, signedness, casts,
unchecked blocks, and repeated operations. Modern overflow checks do not
prevent exploitable rounding or unsafe explicit casts.

```detector
match: |
  shares = assets * totalSupply / totalAssets;
  require(shares > 0);
  _mint(receiver, shares);
nomatch: |
  shares = Math.mulDiv(assets, totalSupply + VIRTUAL_SHARES, totalAssets + VIRTUAL_ASSETS, Math.Rounding.Floor);
  require(shares >= minShares && shares > 0);
  _mint(receiver, shares);
```

### 11. Gas and liveness (`gas-griefing-and-unbounded-onchain-execution`)

Trace attacker-controlled arrays, enumerable mappings, queues, push payments,
callbacks, storage growth, refund assumptions, and loops in withdraw, settle,
finalize, vote, distribute, bridge, and emergency paths. Require pagination or
pull patterns with progress that one reverting recipient cannot block. Model
the chain/VM's resource rules explicitly; a long loop in an offline view helper
is not automatically a security finding.

### 12. Time, finality, and randomness (`block-context-randomness-and-time-dependence`)

Document manipulation tolerance for timestamp, height, block hash,
prevrandao/randomness, L2 timestamp, sequencer downtime, reorg, and finality.
Do not use predictable or biasable block context for lotteries, assignments,
secrets, or high-value selection without a protocol that establishes the needed
unpredictability and availability. Time windows need explicit inclusive bounds
and behavior when the clock/feed stalls.

### 13. Signed on-chain authorization (`onchain-signature-replay-and-domain-separation`)

Bind every signed action to chain/domain, verifying contract/program,
operation/type, signer/owner, resource, value, recipient, nonce, deadline, and
current authorization epoch. Consume nonce before external effects under atomic
revert semantics, handle contract/smart-account signers as specified, validate
signature form through the crypto owner, and test cross-function, cross-contract,
cross-chain, fork, upgrade, and cancellation replay.

```detector
match: |
  bytes32 digest = keccak256(abi.encodePacked(to, amount, nonce));
  address signer = ecrecover(digest, v, r, s);
  require(signer == owner);
  _transfer(owner, to, amount);
nomatch: |
  bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
      TRANSFER_TYPEHASH, owner, to, amount, nonces[owner]++, deadline, authorizationEpoch
  )));
  require(block.timestamp <= deadline);
  require(SignatureChecker.isValidSignatureNow(owner, digest, signature));
  _transfer(owner, to, amount);
```

### 14. Bridges and messages (`cross-chain-bridge-and-message-integrity`)

Trace source/destination chain and contract binding, proof or attestation
verification, quorum and signer-set epoch, finality, message ID, nonce/order,
amount/token mapping, replay state, mint/release conservation, rate limits,
pause, retry, refund, and conflicting messages. Test direction and domain
confusion. Committee-key custody is crypto/cloud context; accepting an invalid
or replayed message is this lens's contract boundary.

### 15. Emergency and governance (`emergency-governance-pause-and-recovery`)

Enumerate proposal, vote snapshot, delegation, quorum, threshold, timelock,
execution, cancellation, guardian, pause, parameter, upgrade, treasury, rescue,
unpause, and role-rotation paths. Check temporary voting power, self-delegation,
proposal substitution, queued calldata binding, bypass routes, indefinite
pause, compromised guardian containment, and recovery without unilateral asset
seizure. Emergency controls need bounded scope and liveness, not merely an
`onlyOwner` modifier.

## Severity calibration

These are claimed-impact grades; the global evidence, reachability, and proof
caps still apply.

| Established condition | Claimed impact severity |
|---|---|
| A permissionless, repeatable path can drain or irreversibly seize a protocol's material assets, mint unbounded backed claims, or take over the governing upgrade authority | Critical |
| A reachable path can steal/freeze substantial user assets, forge bridge messages, bypass a critical oracle/accounting invariant, or permanently disable withdrawals/governance | High |
| A bounded asset loss, unfair extraction, privilege bypass, replay, or liveness failure has a concrete source path but limited scope | Medium or High according to demonstrated impact |
| The code-level defect is clear but deployment, state, liquidity, composition, or profitability is unknown | Medium |
| A hardening, event, documentation, compiler, or defense-in-depth gap has no violated security/economic invariant | Low |
| Use of proxies, flash loans, external calls, oracles, unchecked blocks, assembly, tokens, or public mempools by itself | Not a finding |

## Known false positives

1. An external call precedes a local write but the affected state is immutable,
   reentry-safe, or guarded across every related entry point. Prove the whole
   invariant, not the visual ordering alone.
2. A public function is intentionally permissionless and cannot act with
   another principal's authority or value. Missing `onlyOwner` is not a finding.
3. An implementation has an initializer because the implementation is locked
   and only an atomically initialized proxy can reach user state.
4. A proxy upgrade is centralized by explicit product design with an evidenced
   multisig/timelock and user exit window. Centralization is context unless it
   violates a claimed invariant or permits an unintended principal.
5. A spot price is used only for a non-value-bearing display or as one bounded
   signal behind a manipulation-resistant decision.
6. A flash loan appears in a test or integration, but no invariant changes
   because balances, shares, price, and governance are measured defensibly.
7. A loop is bounded by a small immutable or access-controlled set and remains
   below the target VM's conservative execution budget.
8. `block.timestamp` is used with a manipulation tolerance much larger than
   proposer influence and not as randomness.
9. Solidity 0.8 checked arithmetic is used; do not file generic overflow, but
   still inspect casts, unchecked blocks, precision, and rounding.
10. A signature intentionally supports multiple chains/contracts and includes
    an explicit product domain plus replay state appropriate to that design.
11. A fee-on-transfer token is explicitly rejected, or accounting measures
    actual balance deltas rather than nominal amounts.
12. A bridge retry is idempotent and cannot mint/release twice; duplicate
    delivery is expected, not automatically replay exploitation.
13. A pause role is powerful but cannot transfer assets, upgrade code, or remain
    active beyond the documented emergency window.
14. A committed test forks a public chain. Its presence is source evidence; do
    not execute or treat its stale snapshot as live deployment proof.

### Rejected candidates

| Candidate | Rejection reason |
|---|---|
| “Contract uses `delegatecall`” | Identify attacker influence over target/calldata and the inherited storage/authority consequence. |
| “No reentrancy guard” | Guards are one mitigation; establish a reachable unsafe state transition and callback. |
| “Flash loans enabled” | The loan is a composability primitive. Name the invariant it lets an attacker violate. |
| “Owner can upgrade” | Compare with the stated governance model and show unintended authority, bypass, or asset consequence. |
| “Oracle is centralized” | Establish the required threat model, source integration defect, and value-sensitive decision. |
| “Mainnet address in config” | Source does not prove deployment or reachability, and an address alone is not a defect. |
| “No audit report found” | An absent external review is a process/coverage gap, not a code vulnerability. |

## Proof recipes

All proofs follow `_harness.md` in a disposable mirror. Use the repository's
own deterministic local runner only when controller-authorized; use synthetic
accounts, tokens, feeds, bridges, and balances. Never contact a public RPC,
fork a live chain ad hoc, deploy to a network, use real keys, or move assets.
Absent an authorized runner, retain these as T3 recipes and cap claims normally.

### W1 - State-machine invariant suite (T1 when supported)

Express conservation, solvency, collateral, share, role, pause, upgrade, and
bridge invariants independently of expected examples. Generate bounded action
sequences across at least two principals and one adversarial contract/token.
Shrink a failing sequence and record pre-state, calls, post-state, and violated
assertion. A passing bounded suite is not proof of global correctness.

### W2 - Callback and ordering adversary (T1 when supported)

Use inert local adversary contracts or program fakes that reenter through every
callback-capable edge, return false/empty/malformed values, revert selectively,
and invoke related entry points. Test victim/attacker ordering before, between,
and after operations. Assert both balances and protocol invariants, not merely
that execution reverted.

### W3 - Oracle and arithmetic boundary matrix (T1 when supported)

Drive stale, future, zero, negative, wrong-decimal, high-deviation, low-
liquidity, sequencer-down, and fallback values. Pair them with zero, one,
near-empty, maximum, repeated-dust, donation, and rounding-boundary accounting
states. Assert unsafe values stop before mint, borrow, liquidate, swap, or
withdraw; the clean fixture crosses exactly one intended boundary.

### W4 - Upgrade, initialization, and storage compatibility (T1 when supported)

Create synthetic old/new implementations and deployment state. Attempt
uninitialized takeover, reinitialization, unauthorized upgrade, wrong target,
layout reorder/type change/collision, incomplete migration, and rollback. Put a
spy before implementation selection. The valid migration preserves every
declared state invariant and emits the bound transition identity.

### W5 - Signature, replay, and bridge domain table (T1 when supported)

Use test-only keys and synthetic domain identifiers. Mutate chain, contract,
operation, signer, recipient, amount, nonce, deadline, epoch, source/destination,
message ID, signer-set epoch, and proof/attestation. Assert each mutation and
replay records zero state-changing calls. This proves local verification logic,
not committee honesty, key custody, finality, or deployed replay state.

### W6 - Gas/liveness bounded model (T1 when supported)

Grow only synthetic state up to a predeclared bound and measure the repository
runner's deterministic execution units where available. Show whether an
untrusted actor can prevent required progress or make one recipient block all
others. Do not extrapolate local gas schedules to an unspecified chain without
recording the gap.

### W7 - Source/deployment nonclaim (T0)

Record contract source, configuration, deployment script, and test assertions
actually examined. Name the missing bytecode equivalence, address, proxy slot,
initialized state, balances, roles, oracle, market, bridge, chain, and economic
premises. Never render source review as an audit of a live protocol.

### W8 - Smart-contract build reconciliation (T0/T1 when supported)

For an exact `smart-contract-build` bundle, verify manifest/member hashes and
enumerate bytecode, ABI/interface, compiler/settings, source maps, linked
libraries, storage layout, deployment metadata, and embedded secrets. Rebuild
only through an authorized deterministic repository runner. A deployment-drift
claim requires an exact controller-bound comparison record naming both sides;
otherwise deployed identity is NOT_ASSESSED. Unexpected members or readable
secret material apply only to acquired bytes.
