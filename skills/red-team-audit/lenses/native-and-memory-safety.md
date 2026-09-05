---
name: native-and-memory-safety
title: Native code and memory safety
runs_in: fanout
activates_on:
  paths:
    - '**/*.c'
    - '**/*.h'
    - '**/*.cc'
    - '**/*.cpp'
    - '**/*.cxx'
    - '**/*.hh'
    - '**/*.hpp'
    - '**/*.hxx'
    - '**/*.ipp'
    - '**/CMakeLists.txt'
    - '**/meson.build'
    - '**/meson_options.txt'
    - '**/Makefile'
    - '**/GNUmakefile'
    - '**/*.vcxproj'
    - '**/configure.ac'
    - '**/*.rs'
    - '**/Cargo.toml'
    - '**/build.rs'
    - '**/binding.gyp'
    - '**/*.pyx'
    - '**/*.pxd'
    - '**/jni/**'
    - '**/ffi/**'
    - '**/native/**'
    - '**/parser/**'
    - '**/parsers/**'
    - '**/codec/**'
    - '**/codecs/**'
    - '**/driver/**'
    - '**/drivers/**'
    - '**/firmware/**'
    - '**/kernel/**'
    - '**/fuzz/**'
    - '**/fuzzers/**'
    - '**/.clusterfuzzlite/**'
    - '**/oss-fuzz/**'
    - '**/*fuzz*.c'
    - '**/*fuzz*.cc'
    - '**/*fuzz*.cpp'
    - '**/*fuzz*.rs'
  signals:
    - 'malloc('
    - 'calloc('
    - 'realloc('
    - 'free('
    - 'memcpy('
    - 'memmove('
    - 'strcpy('
    - 'strcat('
    - 'sprintf('
    - 'snprintf('
    - 'std::span'
    - 'std::string_view'
    - 'size_t'
    - 'ptrdiff_t'
    - 'reinterpret_cast'
    - 'unsafe {'
    - 'unsafe fn'
    - 'unsafe extern'
    - '#[no_mangle]'
    - '#[unsafe(no_mangle)]'
    - '*const'
    - '*mut'
    - 'from_raw_parts'
    - 'from_raw_parts_mut'
    - 'transmute'
    - 'MaybeUninit'
    - 'ManuallyDrop'
    - 'UnsafeCell'
    - 'unsafe impl Send'
    - 'unsafe impl Sync'
    - 'extern "C"'
    - 'Py_BEGIN_ALLOW_THREADS'
    - 'PyCapsule_'
    - 'PyArg_ParseTuple'
    - 'NAPI_MODULE'
    - 'napi_create_external'
    - 'JNIEXPORT'
    - 'GetByteArrayElements'
    - 'ReleaseByteArrayElements'
    - 'DllImport('
    - 'LibraryImport('
    - 'import "C"'
    - 'ffi_call('
    - 'SWIG_'
    - 'ntohl('
    - 'be32toh('
    - 'copy_from_user('
    - 'copy_to_user('
    - 'ioctl('
    - 'DriverEntry'
    - 'IRP_MJ_'
    - 'MODULE_LICENSE('
    - 'avcodec_'
    - 'png_read_'
    - 'protobuf_c_'
    - 'flatbuffers::Verifier'
    - 'LLVMFuzzerTestOneInput'
    - 'cargo fuzz'
    - '__AFL_FUZZ_TESTCASE_BUF'
    - 'AFL_FUZZ_INIT'
    - 'honggfuzz'
    - '-fsanitize=address'
    - '-fsanitize=undefined'
    - '-fsanitize=memory'
    - '-fsanitize=thread'
    - '/fsanitize=address'
    - '_FORTIFY_SOURCE'
    - '-fstack-protector'
    - '-Wl,-z,relro'
    - '/guard:cf'
    - '/DYNAMICBASE'
    - 'unsafe_op_in_unsafe_fn'
    - 'overflow-checks'
    - 'address_sanitizer'
    - 'memory_sanitizer'
    - 'thread_sanitizer'
    - '-fno-omit-frame-pointer'
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
owns:
  - memory-bounds-and-integer-conversion
  - use-after-free-and-ownership-lifetime
  - uninitialized-memory-and-information-exposure
  - native-resource-lifetime-and-double-release
  - unsafe-ffi-and-language-boundaries
  - native-concurrency-and-data-races
  - native-parser-and-state-machine-safety
  - native-fuzzing-and-sanitizer-coverage
  - native-compiler-and-platform-hardening
defers:
  race-conditions-and-toctou: web-and-api
  deserialization-and-xxe: web-and-api
  package-dependency-cves: cicd-and-supply-chain
  dependency-pinning-and-lockfiles: cicd-and-supply-chain
  pipeline-scanner-gating: cicd-and-supply-chain
  image-cve-exposure: cloud-and-iac
  dockerfile-and-image-content: cloud-and-iac
  kubernetes-workload-hardening: cloud-and-iac
  symmetric-encryption-and-nonce-handling: crypto-and-key-management
  tls-and-certificate-validation: crypto-and-key-management
  legacy-hash-and-cipher-primitives: crypto-and-key-management
  key-separation-derivation-and-destruction: crypto-and-key-management
  mobile-build-and-runtime-flags: mobile-app-security
  vendored-native-code-provenance: mobile-app-security
  resource-exhaustion-and-bounded-work: failure-semantics-and-resilience
  cleanup-and-resource-release: failure-semantics-and-resilience
frameworks:
  - cwe
  - cwe-top-25-2025
  - cisa-memory-safe-roadmaps
  - owasp-asvs-5.0.0
severity_floor: low
---

## Scope

This lens audits memory and lifetime safety in first-party native code: C and C++, Rust where `unsafe` or a native ABI defeats compiler-enforced invariants, native extensions and FFI bridges, and the parsers, codecs, firmware, and drivers that commonly put hostile bytes next to privileged memory. It follows each candidate from a lower-trust input or concurrent actor through the conversion, allocation, access, release, or state transition that creates the defect.

Native syntax is an activator, not a finding. `memcpy`, a raw pointer, an `unsafe` block, a handwritten parser, or the absence of a sanitizer flag says only where to read. A candidate exists only when quoted source establishes the violated invariant and the path that can reach it. A dependency name or version is never a memory-safety finding here; route dependency and CVE questions to `cicd-and-supply-chain` or, for an image, `cloud-and-iac`.

The consumed evidence class is deliberately **source only**. Build files, fuzz targets, and test presets are source evidence about what the repository requests or supports. This lens does not inspect a linked binary, a shipped package, deployed process metadata, or live runtime state. It therefore cannot conclude that ASLR, DEP/NX, stack canaries, RELRO, control-flow integrity, pointer authentication, memory tagging, allocator hardening, or any sanitizer is active in production. It also cannot conclude that a committed fuzz target has ever run or reached meaningful coverage.

### Owns

| Topic | What that means here |
|---|---|
| `memory-bounds-and-integer-conversion` | Bounds, offset, length, index, element-size, signedness, narrowing, overflow, underflow, allocation-size, copy-size, and pointer-arithmetic defects that can read or write outside the intended object. |
| `use-after-free-and-ownership-lifetime` | A freed, moved, invalidated, expired, or concurrently destroyed native object used through a direct pointer, alias, iterator, callback, or unsafe Rust reference. |
| `uninitialized-memory-and-information-exposure` | Uninitialized stack, heap, padding, out-parameter, union, or `MaybeUninit` bytes that reach a decision, comparison, serialization, log, file, device, or response. |
| `native-resource-lifetime-and-double-release` | Native ownership contracts, allocator/deallocator pairing, double free or double close, error-path release, custom deleters, reference counts, maps, handles, and resources whose invalid lifetime creates memory corruption or a security boundary failure. |
| `unsafe-ffi-and-language-boundaries` | ABI layout and width, pointer and slice validity, ownership transfer, callbacks, unwinding, thread affinity, and validation at Rust/C, Python, Node-API, JNI, .NET, cgo, SWIG, or comparable native boundaries. |
| `native-concurrency-and-data-races` | C/C++ data races, unsafe Rust `Send`/`Sync` claims, lock-free ordering, refcount and callback lifetime races, and concurrent mutation that invalidates memory. |
| `native-parser-and-state-machine-safety` | Native binary/text parsers, incremental decoders, codecs, protocol machines, firmware, and driver request paths whose length, offset, transition, or reset rules can violate memory safety. |
| `native-fuzzing-and-sanitizer-coverage` | Repository-owned fuzz targets and sanitizer-capable test paths: what entry points and bug classes they cover, whether the runner can execute them, and which important native boundaries remain unexercised. |
| `native-compiler-and-platform-hardening` | Source-controlled compiler and linker hardening requests, warnings and unsafe-operation gates, target-specific applicability, and explicit gaps against a stated build policy. It never asserts the properties of an uninspected binary. |

### Does not own

- **web-and-api** owns generic `race-conditions-and-toctou`, request parsing confusion, XXE/deserialization, and web input-validation outcomes. Keep only an intra-process native memory race here. A balance double-spend, filesystem check-then-use, or concurrent workflow transition is theirs even when implemented in C++.
- **failure-semantics-and-resilience** owns generic resource exhaustion and cleanup. A socket leaked on an error path with no native ownership corruption is `cleanup-and-resource-release`; a double `free`, mismatched allocator, dangling mapping, or release race is `native-resource-lifetime-and-double-release` here. Unbounded work or allocation with no overflow or invalid access is `resource-exhaustion-and-bounded-work`.
- **cicd-and-supply-chain** owns dependency versions, lockfiles, advisories, CVEs, scanner gates, SBOMs, and toolchain provenance. The presence of an unsafe dependency may prioritize review, but it is not a finding under any topic this lens owns.
- **crypto-and-key-management** owns primitives, nonce and key handling, TLS validation, constant-time comparison, and secret destruction as a cryptographic control. This lens can report a native out-of-bounds access in that code; the primitive or key-management defect remains theirs.
- **cloud-and-iac** owns container, Kubernetes, image, and deployment hardening. **mobile-app-security** owns mobile release flags and vendored-native provenance. This lens can inspect the same source for a memory defect but must not duplicate those configuration findings.

### Framework boundaries and pinned sources

- The [CWE List Version 4.20](https://cwe.mitre.org/data/index.html), released 2026-04-30, supplies weakness names, not proof. Prefer the most specific root cause the source supports: commonly CWE-787 or CWE-125 for out-of-bounds access, CWE-131 or CWE-190/CWE-195/CWE-681 for the size conversion that caused it, CWE-416 for use after free, CWE-415 for double free, CWE-457 for uninitialized data, CWE-362/CWE-667 for native synchronization defects, and CWE-20/CWE-129/CWE-130 for parser validation and length inconsistency. Do not force a process-only fuzzing or hardening gap into a CWE.
- The [2025 CWE Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html), published 2025-12-11 and last updated 2025-12-15, places CWE-787 at #5, CWE-416 at #7, CWE-125 at #8, CWE-120 at #11, CWE-476 at #13, CWE-121 at #14, and CWE-122 at #16. Those ranks prioritize review; they do not establish reachability, exploitability, or severity for a repository finding. CWE-190 is relevant here but ranked #30 in 2025, so do not describe it as a 2025 Top 25 member.
- CISA and its co-authors published [The Case for Memory Safe Roadmaps: Why Both C-Suite Executives and Technical Experts Need to Take Memory Safe Coding Seriously](https://www.cisa.gov/resources-tools/resources/case-memory-safe-roadmaps) on 2023-12-06. This lens uses it to prioritize user-generated content, network boundaries, firmware, authentication/authorization, and other roots of trust, and to distinguish long-term language migration from short-term instrumentation and wrapping. The mere existence of C/C++ is not a finding, and the absence of a public roadmap in a checkout is not evidence that no organizational roadmap exists.
- [OWASP ASVS 5.0.0 V1.4](https://github.com/OWASP/ASVS/blob/v5.0.0/5.0/en/0x10-V1-Encoding-and-Sanitization.md) is cited only through exact, version-pinned requirements: `v5.0.0-1.4.1` for memory-safe string, copy, and pointer arithmetic; `v5.0.0-1.4.2` for sign, range, and input validation that prevents integer overflow; and `v5.0.0-1.4.3` for releasing allocated memory/resources and preventing dangling pointers and use after free. All three are Level 2 application requirements. They apply where the audited application uses systems or unmanaged code; they do not establish ASVS conformance for firmware, a driver, or an entire product, and compiler flags alone do not satisfy them.

### What cannot be determined from a repository

- The release compiler, linker, target ABI, libc, allocator, CPU feature set, or flags after environment, wrapper, CI, package-manager, and deployment overrides.
- Whether a shipped artifact has ASLR/PIE, DEP/NX, stack protection, RELRO, CFG/CFI, CET, PAC, MTE, hardened allocators, or stripped symbols. A source-controlled flag establishes only that one build description requests it.
- Whether a sanitizer, fuzzer, Miri, model checker, or race detector has run; how long it ran; what corpus and dictionary it used; which edges it reached; or whether failures were suppressed.
- Whether undefined behavior is exploitable on the production target. Source can establish an unsafe path; a T1 diagnostic can establish the fault under the repository runner. Neither silently proves code execution, privilege escalation, or a production crash.
- Whether prebuilt native dependencies contain memory defects. Inventory their boundary here, but route component provenance and known-vulnerability work to the owning supply-chain lens.
- Whether a driver or firmware image is installed, reachable, or privileged in production. If repository evidence cannot name the loading or request path, use `reachable_from: unknown` and accept the Medium cap.

## Activation coverage

| Activation family | Status | Actionable body anchor | Evidence or limit |
|---|---|---|---|
| C and C++ source surfaces | PARTIAL | `memory-bounds-and-integer-conversion` | Cross-language bounds and lifetime checks exist; macros, generated code, target ABI, and whole-program aliasing require local analysis |
| Rust unsafe and raw-memory surfaces | PARTIAL | `use-after-free-and-ownership-lifetime` | Unsafe blocks, raw parts, manual initialization, and unsafe trait claims are reviewed; safe Rust and dependency internals are not assumed vulnerable |
| FFI and native extension boundaries | PARTIAL | `unsafe-ffi-and-language-boundaries` | Major bridge APIs and ownership contracts are covered; generated glue and foreign-runtime guarantees require the selected ABI and version |
| Native parsers, codecs, drivers, and firmware | PARTIAL | `native-parser-and-state-machine-safety` | Length, offset, state, user-pointer, and incremental-input checks exist; format grammar and device reachability remain repository-specific |
| Native build, sanitizer, and fuzz configuration | PARTIAL | `native-fuzzing-and-sanitizer-coverage` | Committed targets and flags are inventoried; actual release hardening, execution history, and dynamic coverage are not consumed evidence |

## Candidate gate

Every queued candidate uses `lens: native-and-memory-safety` and one owned topic. Before assigning a `candidate_id`, record:

1. the lower-trust source: network frame, uploaded file, media/document, IPC message, FFI caller, device request, shared thread state, or persisted bytes;
2. the exact conversion, allocation, access, state transition, ownership transfer, or release that violates an invariant;
3. the resulting memory or security effect, not merely the dangerous API name;
4. `reachable_from`, including `contingent:<entry point>` where a consumer outside the repository must call the library, or `unknown` where no entry point can be established;
5. the most specific supported CWE and a proof plan with a declared assertion signature.

A sweep hit is T0 inventory. Static evidence must quote the complete guard and affected operation, including dominating checks in callers and helpers. T0 and T3 cap `effective_severity` at Medium; `reachable_from: unknown` and contingent reachability do the same. High or Critical requires a T1/T2 oracle that meets `_schema.md`, not confidence in what undefined behavior “usually” permits.

## Checklist

### 0. Highest-yield source sweep

First prove that the traversed file set is non-empty. Then enumerate candidate operations without filtering “safe-looking” lines out of the output; a check may sit on another line or govern the wrong unit.

```bash
rg --files --hidden \
  --glob '**/*.c' --glob '**/*.h' --glob '**/*.cc' --glob '**/*.cpp' \
  --glob '**/*.cxx' --glob '**/*.hh' --glob '**/*.hpp' --glob '**/*.hxx' \
  --glob '**/*.ipp' --glob '**/*.rs' .

rg -n --hidden \
  -e '\b(memcpy|memmove|strcpy|strcat|sprintf|snprintf|malloc|calloc|realloc|free)\s*\(' \
  -e '\b(new|delete)(\[\])?\b|reinterpret_cast|const_cast' \
  -e '\b(uint(8|16|32|64)_t|int(8|16|32|64)_t|size_t|ptrdiff_t)\b' \
  --glob '**/*.c' --glob '**/*.h' --glob '**/*.cc' --glob '**/*.cpp' \
  --glob '**/*.cxx' --glob '**/*.hh' --glob '**/*.hpp' --glob '**/*.hxx' \
  --glob '**/*.ipp' .

rg -n --hidden \
  -e 'unsafe\s*\{|unsafe\s+(fn|extern|impl)|from_raw_parts(_mut)?|transmute|MaybeUninit|ManuallyDrop|UnsafeCell' \
  -e '#\[(unsafe\()?no_mangle|extern\s+"C"|\*(const|mut)\s+' \
  --glob '**/*.rs' .

rg -n --hidden \
  -e 'LLVMFuzzerTestOneInput|cargo fuzz|AFL_FUZZ|honggfuzz' \
  -e 'fsanitize=(address|undefined|memory|thread)|FORTIFY_SOURCE|fstack-protector|guard:cf|DYNAMICBASE' .
```

Exit 1 with a proven non-zero file set means no candidate token matched. Exit 2, a missing tool, an unsupported regex, or an empty file set means the sweep failed; none is a clean result. Generated and vendored directories stay visible until they are classified, because silently excluding them loses FFI glue. Their provenance or CVE status is still routed elsewhere.

### 1. Bounds, sizes, and integer conversions (`memory-bounds-and-integer-conversion`)

Use one canonical checked length from parse to allocation to access. Trace every change of type and unit: wire width to host width, signed to unsigned, bytes to elements, element count to byte count, inclusive end to exclusive end, and pointer difference to integer. Check multiplication before `count * sizeof(T)`, addition before `header + payload + terminator`, subtraction only after ordering is established, and narrowing before the narrow value is used. The allocation and access must use the same validated value.

Pay special attention to flexible array members, zero-sized allocations, `realloc` assignment, one-past-the-end sentinels, negative indices, partial reads, `sizeof(pointer)` instead of `sizeof(*pointer)`, and a wide validation followed by a narrow store. `strncpy` and `snprintf` are not automatic clearances: termination, return-value interpretation, and destination capacity still matter.

```detector
match: |
  uint32_t wire_len = read_be32(frame);
  uint16_t allocation_len = (uint16_t)wire_len;
  uint8_t *out = malloc(allocation_len);
  memcpy(out, frame + 4, wire_len);
nomatch: |
  if (frame_remaining(frame, 0) < 4) return PARSE_TRUNCATED;
  uint32_t wire_len = read_be32(frame);
  if (wire_len == 0 || (uintmax_t)wire_len > SIZE_MAX ||
      wire_len > frame_remaining(frame, 4)) {
      return PARSE_INVALID_LENGTH;
  }
  size_t len = (size_t)wire_len;
  uint8_t *out = malloc(len);
  if (out == NULL) return PARSE_NO_MEMORY;
  memcpy(out, frame + 4, len);
```

The `match` side is still a detector fixture, not a finding. A real candidate must show who controls `wire_len`, whether the path is compiled, and what happens when allocation and copy disagree.

### 2. Freed, moved, and invalidated objects (`use-after-free-and-ownership-lifetime`)

Build an ownership ledger for the object: creator, owners, borrowers, aliases, callbacks, container membership, transfer points, invalidation operations, and final release. Follow error labels and cancellation paths separately. Look beyond the original pointer: iterators and views invalidated by growth, lambdas capturing `this`, callbacks firing after unregister/destruction, refcounts incremented too late, an object deleted while another thread holds a raw observer, and smart pointers independently constructed from the same raw address.

In unsafe Rust, review every place a reference lifetime is widened, a pointer becomes a slice/reference, a self-referential value moves without `Pin`, `ManuallyDrop` bypasses automatic release, or an unsafe `Send`/`Sync` claim lets a non-thread-safe object cross threads. The safe wrapper is evidence only if every way to construct and call it preserves its documented invariant.

```detector
match: |
  struct item *selected = list->head;
  list_remove_and_free(list, selected);
  return selected->kind;
nomatch: |
  struct item *selected = list->head;
  int kind = selected->kind;
  list_remove_and_free(list, selected);
  return kind;
```

Setting one pointer to null after `free` does not clear other aliases. Conversely, an API named `remove` may only detach and transfer ownership; read its contract and implementation before filing.

### 3. Uninitialized bytes and disclosure (`uninitialized-memory-and-information-exposure`)

Find values whose initialized extent is smaller than the extent later read. Common shapes are `malloc` followed by a short read, a stack struct whose padding is sent with `write(fd, &msg, sizeof msg)`, a union read through the inactive member, an output structure only partially filled on error, a comparison or hash over padding, and Rust `MaybeUninit::assume_init`, `set_len`, or `assume_init_read` before every byte and element is initialized.

The security finding needs a sink or decision. Uninitialized bytes that never leave the process and do not affect control flow may be correctness debt; bytes returned across IPC, FFI, a device boundary, a network response, a file, or a log can expose prior stack/heap content. Quote both the incomplete initialization and the whole-object read. Zeroing may prevent disclosure but does not prove semantic initialization where the value drives a privilege or length decision.

### 4. Native ownership and release (`native-resource-lifetime-and-double-release`)

Pair each acquisition with exactly one owner and a compatible release: `malloc/free`, `new/delete`, `new[]/delete[]`, platform handles with their documented closer, mappings with the correct length, and foreign allocations released by the allocator that created them. Inspect constructors/destructors, move operations, error jumps, partial initialization, refcount failure, `realloc`, callback cancellation, and cross-DLL/runtime allocation.

Keep the boundary with generic cleanup precise. A missing `close` that leaks a bounded descriptor is normally resilience or quality work. A second release, release through the wrong allocator, handle reuse that closes an unrelated object, or an error path that leaves a privileged mapping/capability reachable belongs here.

```detector
match: |
  char *buffer = new char[length];
  if (!decode(buffer, length)) {
      free(buffer);
      return false;
  }
  delete[] buffer;
nomatch: |
  std::unique_ptr<char[]> buffer(new char[length]);
  if (!decode(buffer.get(), length)) return false;
```

The clean fixture demonstrates one owner and one matching release. It does not say `unique_ptr` is sufficient when another raw alias survives or the foreign callee retains the address.

### 5. Unsafe FFI and ABI boundaries (`unsafe-ffi-and-language-boundaries`)

Write the contract in both languages and compare it field by field: integer width and sign, struct layout and packing, enum representation, calling convention, nullability, alignment, pointer extent, ownership and allocator, mutability, callback lifetime, thread affinity, and error/unwind behavior. Treat a language's safe wrapper as the boundary, not as proof that the foreign caller honored it.

For Python C APIs, check reference ownership, the GIL around callbacks and borrowed objects, buffer lengths, and capsule type names. For JNI, pair every acquire/release mode, validate array/string lengths, and keep local/global references within lifetime. For Node-API, validate external buffers and finalizers and avoid retaining stack-backed data. For .NET P/Invoke, match `CharSet`, `CallingConvention`, widths, `SafeHandle`, and ownership. For cgo and Rust ABIs, do not let panics/exceptions unwind across a boundary that forbids it.

```detector
match: |
  #[unsafe(no_mangle)]
  pub unsafe extern "C" fn parse_frame(ptr: *const u8, len: usize) -> i32 {
      let frame = unsafe { std::slice::from_raw_parts(ptr, len) };
      parse(frame) as i32
  }
nomatch: |
  /// # Safety
  /// `ptr` must address `len` readable bytes for the duration of this call.
  #[unsafe(no_mangle)]
  pub unsafe extern "C" fn parse_frame(ptr: *const u8, len: usize) -> i32 {
      if ptr.is_null() || len > MAX_FRAME { return ERR_INVALID; }
      let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
          let frame = unsafe { std::slice::from_raw_parts(ptr, len) };
          parse(frame)
      }));
      result.map_or(ERR_PANIC, |code| code as i32)
  }
```

The `nomatch` side constrains the properties visible in Rust and prevents unwinding; it cannot prove that an arbitrary non-null pointer addresses `len` readable bytes. The caller, generated shim, or higher-level safe bridge must establish that remaining precondition. Do not use this fixture as an automatic clearance.

### 6. Native concurrency and memory ordering (`native-concurrency-and-data-races`)

Identify shared objects, the operation that publishes them, every reader/writer, and the mechanism that orders lifetime and mutation. In C and C++, a data race is undefined behavior even when the observed value “looks atomic.” In unsafe Rust, an incorrect `Send`/`Sync` implementation can make otherwise safe callers unsound. Review refcounts, lazy initialization, double-checked locking, callback unregister/destruction, lock-free queues, hazard/epoch reclamation, atomics mixed with plain access, and memory-order pairs that fail to publish initialized data.

A lock token near the access is not a clearance. Prove the same lock guards every alias and that destruction cannot race a borrower. Atomics can protect a counter while leaving the pointed-to object unprotected. Route filesystem/business check-then-act, duplicated charges, balance races, and generic TOCTOU to `web-and-api`; this topic remains about native memory and ownership safety.

### 7. Native parsers, codecs, firmware, and drivers (`native-parser-and-state-machine-safety`)

Start with the grammar or request contract and make every state carry an explicit remaining extent. Validate a length before conversion and before advancing; reject `offset + length` overflow by comparing against `remaining`; handle incremental input without reusing stale state; reset partially initialized state on error; and make terminal, unknown, and duplicate transitions explicit. Check nested containers, tables of offsets, integer-coded tags, bit lengths, stride/pitch calculations, image dimensions, sample counts, and decompression output before they reach an allocation or access.

For drivers and firmware, treat request buffers, IOCTL lengths, DMA descriptors, device-reported sizes, shared memory, and user pointers as hostile. Use the platform's user-copy/probe mechanism correctly and revalidate after partial copies where the API requires it. Establish the exact request method and buffer semantics before asserting that a raw pointer is directly user controlled.

```detector
match: |
  uint32_t payload_len = read_u32(packet + 4);
  if (payload_len <= packet_len) {
      memcpy(message->payload, packet + HEADER_LEN, payload_len);
  }
nomatch: |
  if (packet_len < HEADER_LEN) return PARSE_TRUNCATED;
  uint32_t payload_len = read_u32(packet + 4);
  if (payload_len > packet_len - HEADER_LEN || payload_len > sizeof message->payload) {
      return PARSE_INVALID_LENGTH;
  }
  memcpy(message->payload, packet + HEADER_LEN, payload_len);
```

Parser acceptance differences that lead only to SSRF, authz, XXE, or object deserialization stay with `web-and-api`. This topic owns the native state or memory violation caused by the parse.

### 8. Fuzz and sanitizer coverage (`native-fuzzing-and-sanitizer-coverage`)

Inventory targets by the entry point they actually call, not by filenames. For each important native boundary record: the harness, seed corpus and dictionaries, maximum input, initialization path, deterministic mode, sanitizer set, timeout, crash artifact handling, and the repository command that runs it. A fuzzer aimed at a convenience wrapper may never reach streaming, error, FFI, driver, or alternate-codec paths.

AddressSanitizer is aimed at many bounds and lifetime defects; UndefinedBehaviorSanitizer at selected undefined operations; MemorySanitizer at uninitialized reads where the whole relevant dependency graph is instrumented; ThreadSanitizer at data races. None proves absence of its bug class, and support differs by compiler, platform, architecture, and mixed-language boundary. A suppression must name why the report is impossible or acceptable, not merely silence it.

The absence of a fuzz target or sanitizer preset is normally an **Info coverage gap**, not an exploitable vulnerability. It can rise to Medium only when the repository or stated assurance policy requires the control for a named security-critical native boundary and the committed runner omits it. Never say “sanitizers are not enabled” from a quiet source grep; say “no source-controlled sanitizer configuration was found in the files examined,” then name the build/runtime evidence needed.

### 9. Compiler and platform hardening (`native-compiler-and-platform-hardening`)

First name the compiler, linker, target, configuration, and artifact type. Then inspect the rendered or effective source-controlled build description where the repository can produce one. Typical candidates include stack protection, fortified libc calls, warnings promoted to errors for unsafe conversions, PIE for executables, non-executable stack, RELRO/immediate binding on applicable ELF targets, CFG/CFI/CET or platform equivalents, and Rust lints/overflow checks around unsafe code. Every flag is conditional: `_FORTIFY_SOURCE` depends on libc and optimization, PIE is not the same setting as PIC, ELF linker options do not apply to PE/COFF or Mach-O, and a compiler that accepts an unknown option with a warning may still produce an artifact.

Hardening is defense in depth, not a repair for undefined behavior. Missing flags alone do not justify High or Critical, and present flags do not clear the source defect. With source-only evidence, report “the committed release preset requests `/guard:cf`” or “the reviewed preset contains no stack-protection request”; do not report that the shipped process has CFG, stack canaries, ASLR, DEP, RELRO, PAC, or MTE. Deployment manifests, container runtime controls, and mobile release properties remain with their owning lenses.

## Severity calibration

`claimed_impact_severity` describes the demonstrated consequence if the path is real; `effective_severity` still obeys reachability, proof-tier, and result-state caps.

| Finding | Claimed impact | Required evidence |
|---|---|---|
| Attacker-controlled native memory corruption yields arbitrary code execution or kernel/firmware privilege compromise | Critical | A reachable trust boundary, a T1/T2 oracle confirming the corrupting primitive, and evidence tying that primitive to code execution or privilege control; a generic crash is insufficient |
| Reachable out-of-bounds write, use after free, double free, invalid release, or unsafe FFI lifetime violation in a privileged or exposed component | High where the confirmed effect compromises code/data authority; Medium where only a bounded crash is shown | Exact source-to-fault trace plus T1/T2 reproduction for an effective High; T0/T3 remains Medium |
| Out-of-bounds or uninitialized read exposes secrets or another tenant/principal's data | High for confirmed cross-boundary sensitive disclosure; Medium for process-local or unknown content | The initialized/valid extent, read extent, observable sink, and sensitivity of bytes; “may leak memory” is not enough |
| Native data race corrupts ownership, authorization-relevant state, or memory | High for confirmed cross-boundary corruption; Medium for service crash or T0-only path | Both conflicting accesses, missing/incorrect ordering, shared lifetime, and an executed race/safety oracle for effective High |
| Single-input crash of a shared parser, codec, driver, or service | High only where one untrusted action reliably removes a critical shared service; otherwise Medium | Deterministic input, path-reached evidence, diagnostic signature, benign control, and recovery scope |
| Missing or incomplete fuzz/sanitizer coverage for a named critical boundary | Info; Medium only against a cited mandatory assurance policy | Target-to-entry-point coverage and the committed runner configuration; never the absence of a token alone |
| Missing source-controlled compiler/linker hardening request | Info by default | Exact target and policy, plus the effective build description if available; no claim about the binary or runtime |
| Native API token, raw pointer, `unsafe`, C/C++ language use, or absent public migration roadmap alone | — | Not a finding |

Critical and High are not inferred from undefined behavior. A sanitizer report can confirm an out-of-bounds access or lifetime violation; it does not by itself confirm arbitrary code execution, secret disclosure, or kernel compromise. Keep the confirmed primitive and claimed impact separate.

## Known false positives

1. **A dangerous API whose extent is already dominated by a correct check.** Read callers and helpers, verify the check uses the same units and canonical length, and quote it. `memcpy` is not a vulnerability class.
2. **A narrowing cast after an explicit representability check.** The cast is safe for the validated range. What survives is a second path that skips the check or later recomputes a wider length.
3. **An apparent use after free where the API detaches but does not destroy.** Names such as `remove`, `release`, and `reset` are not ownership contracts. Read the implementation or version-pinned documentation.
4. **Arena, pool, region, or process-lifetime allocation.** Individual objects may intentionally have no `free`. What survives is reuse before borrowers finish, unbounded attacker-controlled growth, or a release through the wrong allocator.
5. **RAII, a custom deleter, or idempotent handle wrapper.** These normally clear a missing-explicit-release hit. Confirm move/copy semantics and retained raw aliases before clearing a double-release candidate.
6. **Correct `MaybeUninit`, placement new, union, or raw storage use.** Low-level containers need these tools. Prove every byte/element is initialized before a typed read and every constructed element is destroyed exactly once.
7. **An unsafe Rust block with a narrow, documented invariant.** `unsafe` is an audit boundary. File only when a safe caller can violate the invariant or the implementation fails to uphold it.
8. **A race report where the object is thread-confined or all aliases share the same lock.** Establish publication and aliasing. A test that happens to run on one thread is not proof of confinement.
9. **A parser fixture, fuzzer corpus, exploit regression, dead platform branch, or generated binding.** Classify whether it ships and whether the generated source is authoritative. Do not drop generated glue before checking its generator and boundary contract.
10. **A sanitizer or hardening flag injected outside the file searched.** Toolchain files, presets, environment wrappers, CI, package builders, and platform defaults can supply it. Their absence from consumed source is an unresolved verification step, not proof of an unprotected binary.
11. **A hardening option inappropriate for the target.** ELF RELRO flags on Windows, PIE on a shared library, MemorySanitizer with uninstrumented dependencies, or ThreadSanitizer on an unsupported runtime are not universal requirements. Grade against the declared target and policy.
12. **A null assignment offered as complete UAF prevention.** It may protect the one variable and still leave aliases, callbacks, iterators, or foreign handles live. Clear only the aliases whose lifetime is established.

## Proof recipes

All execution obeys `_harness.md`: work in a disposable mirror, deny external destinations, use only local repository-owned fixtures, and never exercise a real device, remote host, production driver, or destructive payload. The first step is always to determine whether a compatible proof target and runner exist.

### N1 — Source-to-fault trace (T0)

For any bounds, lifetime, initialization, FFI, race, or parser candidate, quote the complete path: entry point or contingent consumer, lower-trust value, every relevant type/unit conversion, the controlling guard, the allocation/object lifetime, and the faulting access/release/sink. Include dominating caller checks and build conditions. Declare the expected dynamic signature in `proof_plan` even when it cannot be executed.

This is T0 and caps at Medium. It can confirm that the cited source has an unsafe path; it cannot claim a production crash, sanitizer result, exploit, or binary hardening state.

### N2 — Repository-runner sanitizer regression (T1 only when supported)

Use this recipe only when the repository already has a test/build runner capable of compiling and executing the affected native target with the relevant sanitizer or checked runtime. Examples are a committed CTest/Meson/Bazel preset, project script, Cargo test target, or equivalent configuration that the repository owns. Do not install an unrelated toolchain, bolt a standalone compiler command onto the audit, or call an ad hoc sanitizer run T1 merely because it executed.

In the disposable mirror, add the smallest local regression fixture the existing runner accepts. Assert all five oracle parts:

1. a declared sanitizer class and stable signature, not “non-zero exit” alone;
2. path-reached evidence naming the parser/function and input branch;
3. a benign neighbor input that succeeds and a sensitivity control that proves the instrumented target can report the defect class;
4. the identical command and assertion before and after the patch;
5. relevant neighboring tests still pass after the patch.

ASan, UBSan, MSan, TSan, Miri, or a checked allocator proves only the diagnostic it actually emitted. If the repository runner cannot support the required instrumentation, stop at T0 or write N6 at T3.

### N3 — Repository-owned fuzz target and minimized reproducer (T1 only when supported)

Run a fuzz campaign only when the repository already provides the target and invokes it through its own supported runner. Keep the campaign bounded and local. Record target, engine, sanitizer, seed corpus, dictionary, time or iteration budget, and exit status. A campaign that finds nothing is coverage evidence, never proof of absence.

When it finds an input, minimize it and replay that exact input through the same repository runner as a deterministic regression. The finding's T1 oracle is the stable replay signature plus path evidence and benign control, not the stochastic campaign. If only a standalone fuzzer invocation or a newly invented harness is possible, preserve it as a T3 plan rather than upgrading the evidence.

### N4 — Native concurrency oracle (T1 when the repository runner supports overlap or a race tool)

Use a barrier to release multiple repository test workers against the same native object, callback, refcount, or state transition. Assert the memory/lifetime invariant after each run and use the repository's supported TSan, loom, Miri, model checker, or equivalent where available. Include a sensitivity control against a deliberately unguarded local fixture so a serializing test client or single-threaded build cannot pass vacuously.

If the runner serializes the calls, the platform does not support the detector, or the scheduler cannot reach the window, record `INCONCLUSIVE` with the blocking condition. Repetition without a barrier is not a race proof, and a quiet race detector does not establish thread safety.

### N5 — FFI contract boundary test (T1 when both sides are inside the repository runner)

Call through the real language bridge with boundary values: null where allowed/disallowed, zero, maximum accepted extent, just above it, misaligned or invalid-layout fixtures that remain safe to construct, callback after cancellation, foreign error, and panic/exception. Put guard canaries around repository-owned buffers and count acquire/release/finalizer calls. Assert return status, unchanged canaries, exactly-once ownership transfer, no unwind across a forbidden ABI, and a valid control call.

Never manufacture an actually invalid address or load a production driver to prove the point. If safe construction cannot reach the suspected precondition under the repository runner, retain the static contract mismatch at T0 or the written recipe at T3.

### N6 — Written reproducer when no compatible runner exists (T3)

Write the minimal local reproducer and exact expected diagnostic, but do not execute it. Set `proof_tier: T3`, `result_state: UNPROVEN`, explain that the repository lacks a compatible native runner/instrumented target, and cap effective severity at Medium. A compiler command copied from a blog, a new external harness, or a sanitizer the project does not support does not become T1.

### N7 — Hardening and coverage nonclaim (T0)

For build hardening, quote the target-specific source configuration and report only what it requests. For fuzz/sanitizer coverage, quote the committed target and runner linkage or the exact reviewed scope in which none was found. Never use the shared **local log and artifact collector** to infer binary properties here: built artifacts are declared `not-consumed`. A binary-verification or deployed-state request belongs in a separately scoped evidence adapter or audit.

The shared **detector-and-fixture-pair runner** may validate a future static checker against the `match`/`nomatch` blocks above. That makes the checker behavior T1; it does not make every checker hit a confirmed vulnerability. Each hit still needs reachability, source evidence, and an appropriate defect proof.

### Not proven by this lens, every run

- Production exploitability, crash behavior, privilege level, or secret content.
- Effective binary mitigations or runtime enforcement.
- Historical fuzz/sanitizer execution and coverage.
- Safety of prebuilt or out-of-scope dependency internals.
- Production driver/firmware loading and device reachability.
