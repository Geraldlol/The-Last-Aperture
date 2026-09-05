---
name: ai-generated-code
title: Machine-authored code tells
runs_in: fanout
always_active: true
activates_on:
  paths: []
  signals: []
  evidence_classes:
    source:
      state: consumed
    built-artifact:
      state: not-consumed
    deployed-state:
      state: not-consumed
    live-runtime:
      state: not-consumed
owns: []
defers: {}
frameworks: [cwe-top-25-2025]
severity_floor: info
---

## Scope

Every other lens in this registry is organized by domain. This one is organized by **the shape of the mistake**, which is why it activates on nothing and owns nothing.

Its audience is a developer auditing a repository they own that contains code they did not write line by line — generated or assisted code that works, passes its tests, and has never been read by anyone looking for a way through it. That code fails in a characteristic way. It is not sloppy: it is *plausible*. The wrong thing looks like a decision somebody made.

Eight shapes recur, and each one is an item in the Checklist below:

1. Crypto that is plausible and wrong, with a stated rationale that is about speed or simplicity rather than about a security property.
2. "Sanitization" by regular expression standing where context-aware encoding belongs.
3. A guard that reads correctly and runs after the operation it guards, or whose answer is discarded.
4. A swallowed exception around a security control, so the control fails open in silence.
5. A library API that compiles and does not do what its name says — including an option the library accepts and ignores.
6. A dependency name that resolves nowhere, which an attacker can register and ship malware under.
7. Deferred-work comments — "TODO: validate this", "in production, do X" — left in the deployed path.
8. Permissive defaults chosen because they made an example run: `debug=True`, `verify=False`, wildcard hosts, autoescape off.

### Three rules this lens is bound by

**1. Never report authorship. Report the defect.** "This looks machine-generated" is unfalsifiable, unactionable, and insulting to the person who has to read the report. It is also unnecessary: every item below describes something the code *does*, and that is what the finding says. A tell is evidence that **nobody read this adversarially**. It is not evidence of who wrote it, and the two must never be conflated in a finding, a title, a severity, or an aside. Human-written code contains every one of these tells, which is the subject of `## Known false positives` and the reason that section is longer here than in any domain lens.

**2. The tell is not the finding.** A tell is a pointer. `# TODO: validate this` is not a vulnerability; the missing validation on the path to the sink is. `except Exception: pass` is not a vulnerability; the signature check that now returns `True` on any input is. Every candidate this lens writes names the consequence, quotes the code, and states the path — and where the consequence cannot be established, it says so and files at Info rather than inventing one.

**3. This lens owns no topic slugs, so every finding it raises is tagged with the owning domain lens's slug.** That is what lets the registry stay a clean partition while this lens reports anywhere. The mechanics are in `### Routing` below, and they are not optional: a candidate with no `topic` cannot be deduplicated by the only mechanism the registry provides.

### The signal this lens adds that a domain lens does not

A domain lens says *this crypto is wrong*. This lens says *this pattern means the code was never read adversarially* — a different claim, with three consequences a domain lens cannot produce:

- **It runs when the owner does not.** A domain lens fires only if its `activates_on` matched. An MD5 password hash in a file no glob reached, in a language no signal named, is reported by nobody else. This lens is the safety net for that case, and it is the largest single reason it is always-on.
- **It reads clusters, not just sites.** Seven distinct tells in one module is a statement about the module, not about any one line. It changes what the *audit* should do next — widen and re-read — and it belongs in the coverage block. It is never a severity multiplier; see `## Severity calibration`.
- **It covers shapes no domain owns.** Ordering, swallowing, a name that resolves nowhere, an option the library ignores: none of these is domain-shaped. Only their *consequences* are. The shape is what you can search for; the consequence is what you file.

### Routing

This lens writes a Stage 1 candidate record per `lenses/_schema.md` with:

- `lens: ai-generated-code`
- `topic:` **the owning domain lens's slug**, taken from `lenses/_topics.md` and chosen by the *consequence*, not by the shape
- `raised_by: ai-generated-code`, which `_schema.md` defines for exactly this case — "one lens raised it against another lens's topic" — and which is what keeps a cross-cutting lens from silently acquiring topics it does not own

**Contract note.** `_schema.md` invariant 2 now implements the zero-owner
exemption used here: `lens` and `raised_by` both remain
`ai-generated-code`, while `topic` is the consequence owner's registered slug.
Do not invent a slug or put the topic owner's name into `lens`; the first breaks
the registry boundary and the second falsifies authorship.

| Shape found | Route to `topic` | Owner |
|---|---|---|
| Fast-hash rationale on a password write | `password-hashing-and-kdf-parameters` | crypto-and-key-management |
| Fast-hash rationale where collision resistance is load-bearing | `legacy-hash-and-cipher-primitives` | crypto-and-key-management |
| Unauthenticated cipher mode (CBC/CTR with no MAC), or a mode chosen for speed | `symmetric-encryption-and-nonce-handling` | crypto-and-key-management |
| Hand-rolled `H(secret ‖ msg)` or a byte-by-byte MAC compare | `hmac-and-constant-time-comparison` | crypto-and-key-management |
| Regex "sanitization" of markup | `xss-and-output-encoding` | web-and-api |
| Regex quoting or escaping of SQL | `injection-sql-nosql-orm` | web-and-api |
| Regex filtering of shell or template input | `injection-command-and-template` | web-and-api |
| Regex stripping of `../` | `path-traversal-and-file-access` | web-and-api |
| Regex allow/deny of a fetched URL | `ssrf-application-path` | web-and-api |
| Regex filtering of model input or output | `prompt-injection`, `model-output-taint-propagation` | llm-and-ai |
| Guard after the operation, on a route or method | `authz-function-level` | web-and-api |
| Guard after the operation, on a specific record | `authz-object-level` | web-and-api |
| Check-then-act across a suspension point | `race-conditions-and-toctou` | web-and-api |
| Tag or signature verified after unpadding, parsing or use | `symmetric-encryption-and-nonce-handling` | crypto-and-key-management |
| Guard after the DML, or after the SOQL that already ran | `apex-crud-fls-enforcement` | salesforce-platform |
| Swallowed signature or token verification | `jwt-jws-and-jwks-verification`, `hmac-and-constant-time-comparison` | crypto-and-key-management |
| Swallowed certificate or TLS error | `tls-and-certificate-validation` | crypto-and-key-management |
| Swallowed authorization check | `authz-function-level`, `authz-object-level` | web-and-api |
| Swallowed audit or security-event write | `threat-detectability-gap` | threat-modeling |
| Swallowed audit write on a PHI access path | `phi-access-audit-controls` | hipaa-and-phi |
| Swallowed rate-limiter or quota error | `rate-limiting-and-request-quotas` | web-and-api |
| Swallowed CSRF validation | `csrf` | web-and-api |
| Option the library accepts and ignores, leaving an algorithm unpinned | `jwt-jws-and-jwks-verification` | crypto-and-key-management |
| Removed or superseded API whose replacement is the secure one | `legacy-hash-and-cipher-primitives`, `symmetric-encryption-and-nonce-handling` | crypto-and-key-management |
| Import that resolves nowhere in the checkout | `package-name-squatting` | cicd-and-supply-chain |
| Unresolvable name under a private scope or an internal prefix | `dependency-confusion-and-registry-config` | cicd-and-supply-chain |
| Import present in code and absent from every manifest and lockfile | `dependency-pinning-and-lockfiles` | cicd-and-supply-chain |
| Deferred-work comment naming a control that is genuinely absent | the absent control's slug | whoever owns it |
| `debug=True`, verbose errors, an exposed admin or debug route | `debug-and-admin-endpoint-exposure`, `error-handling-and-verbose-responses` | web-and-api |
| Certificate verification disabled | `tls-and-certificate-validation` | crypto-and-key-management |
| Autoescape disabled on a template environment | `xss-and-output-encoding` | web-and-api |
| Wildcard hosts, wildcard CORS with credentials | `cors-policy`, `security-headers-and-csp` | web-and-api |
| Permissive default in infrastructure or a BaaS rule set | `network-exposure-and-segmentation`, `object-storage-exposure`, `baas-security-rules` | cloud-and-iac |
| Debuggable or cleartext-permitting mobile build flags | `mobile-build-and-runtime-flags`, `mobile-cleartext-and-ats-config` | mobile-app-security |

**Four routing rules that decide whether the tag is right.**

1. **Route by consequence, not by shape.** The same `except Exception: pass` routes to four different owners depending on what it swallowed. The shape tells you where to look; what the swallowed call *was* tells you where to file.
2. **Tag the owner's slug whether or not the owner ran.** The registry is static, so the slug exists regardless. When the owning lens did not activate, say so in the record — nothing domain-specific has been applied to this finding, and a reader who assumes otherwise will trust it more than they should.
3. **Where no slug covers the consequence, do not invent one.** Inventing breaks R1 and R2 the moment `npm run gen` runs. File nothing under a fabricated topic; record the finding in the audit's notes and report the registry gap. Two real gaps found while writing this lens: a swallowed error around an **idempotency or double-spend guard** (`business-logic` is a triage lens and owns no slugs), and a **per-line scanner suppression** (`# nosec`, `# noqa: S105`), whose nearest owner is `pipeline-scanner-gating` and which is a stretch there.
4. **Expect to be merged, and make the merge lossless.** Topic ownership is the dedup boundary, so when crypto-and-key-management has already filed the same MD5 line, triage merges this record into theirs. What must survive is the *tell*, carried into the survivor's `impact` as an aggravator: "the same file carries four other unreviewed-code tells". What must not survive is a second severity for one defect.

### Does not own

Nothing. That is not a formality — it is the property that keeps the registry a partition, and there are three specific temptations to refuse.

- **No topic slugs.** This lens must never appear as an owner in `_topics.md`. If a shape below seems to need a new slug, the slug belongs to a domain lens and the request goes in a report, not into this frontmatter.
- **No grading.** This lens does not decide that a repeated GCM nonce is Critical or that a missing `algorithms` pin is Medium. Those rules live in the owning lens and are applied there. Where the owning lens did not run, this lens files the consequence at the severity the artifact establishes and marks that no domain rule was applied.
- **No code quality.** Not style, not dead code, not naming, not duplication, not test coverage, not license headers, not performance, not "this function is too long". Every one of those is a real review concern and none is a security finding, and mixing them in is the fastest way to get a security report skimmed.

And explicitly: **this lens does not own the claim that code was machine-generated.** No finding, title, evidence line or note asserts it. See rule 1.

### What cannot be determined from code, ever

Name these where they bear on a finding rather than letting silence imply otherwise.

- **Who or what wrote the code.** Not from style, not from comment density, not from an assistant's configuration directory in the tree, not from a "Generated by" banner. Tooling residue is audit context at most; it is never an input to a finding or a severity.
- **Whether an unresolved dependency name is unregistered.** That is a registry query and therefore external evidence, not repository proof. See item 6 and P6: the offline half is provable; when the accepted authenticated operator statement names the registry, package, scope, and query, the external half runs without another prompt only through a matching destination-bound controller. Otherwise record the technical transport gap.
- **Whether a `TODO` is tracked somewhere.** A comment is not a work item and an issue tracker is not in the checkout. What is checkable is whether the control it names exists on the path.
- **Whether a swallowed exception ever fires in production.** Only that the handler cannot distinguish failure from success. P4 proves the consequence without needing the frequency.
- **Whether a cluster of tells means the module is worse than its neighbours.** It means it was not read. Treat it as a scope instruction, never as evidence.

## Checklist

Every item routes to a slug this lens does not own. Read `### Routing` before filing anything.

CWE identifiers are cited inline where one applies. The
`frameworks: [cwe-top-25-2025]` entry claims that edition-specific lineage for
the subset that belongs to it — CWE-862 and CWE-863 among them — and the
remaining identifiers are cited as plain CWEs with no Top-25 claim.

### 0. Highest-yield sweeps

Run these first over the in-scope file set, and treat every hit as a candidate to trace rather than as a finding. Sweep ids (`A1a`…`A16`) are referenced by the items below and by `## Proof recipes`.

**Three disciplines govern all of them, and all exist because a sweep that could not have found anything looks exactly like a sweep that found nothing.**

- **A non-zero, non-one exit status is never a verdict.** `rg` exits 0 for a match, 1 for no match, and 2 or above for an error — a bad pattern, an unreadable path, a binary it refused. Branch on the status explicitly and print "no verdict" for anything above 1. Writing `rg … || echo clean` converts every error into a clearance, and a wrong clearance is worse than a wrong finding because nobody re-opens a closed item.
- **An empty candidate set is not a clean result.** The absence half (`A10`) and the resolution sweep (`A16`) both consume a list produced by an earlier step. When that list is empty they must say "nothing to test", never "nothing found" — and `A10`'s list must never be passed to `rg --files-without-match` unguarded, because an empty argument list makes it search the whole tree and return every file in the repository as a hit. Both failures were observed while building this lens; both are in the fixture output.
- **`--hidden` is required on every repository traversal.** ripgrep prunes hidden directories before applying globs, so dot-directories containing source, configuration or agent instructions otherwise disappear without an error. `--hidden` still excludes `.git`; it does not require a companion `.git` glob. The one-file checks inside the `A10` loop are not traversals and deliberately do not carry it.

```bash
# The patterns are single-quoted, so a literal single quote is written \x27
# (Rust regex hex escape) rather than escaped out of the shell string.

# A1a/A1b — a weak primitive with a rationale about speed or simplicity.
#   The comment is the tell; the primitive is the finding. Both orders occur.
rg -n --hidden -i '(md5|sha-?1|ecb|aes|cbc|ctr|base64|token|hash).{0,70}\b(fast|faster|speed|performance|simple|simpler|lightweight|cheap|good enough|fine for)\b' .
rg -n --hidden -i '\b(fast|faster|speed|performance|simple|simpler|lightweight|cheap|good enough)\b.{0,70}(md5|sha-?1|ecb|aes|cbc|ctr|hash|encrypt|sign)' .

# A2 — deferred-work comment naming a security control (CWE-546).
rg -n --hidden -i '(TODO|FIXME|HACK|XXX)\b.{0,80}(auth|authz|permission|valid|sanitiz|escap|encod|verif|sign|token|secret|credential|csrf|inject|encrypt|hash|tls|ssl|cert)' .

# A3 — environment-split prose: the code says it is not the deployed version.
rg -n --hidden -i '(in production|in prod\b|for now\b|before (launch|deploy|shipping|prod)|\bplaceholder\b|real (secret|key|store|cert)|do not use in production)' .

# A4 — Python: a broad except that discards the exception (CWE-390, CWE-703).
#   Deliberately does NOT match `except ValueError: pass` — a narrow type on a
#   parse fallback is the clean case, and matching it would swamp the sweep.
rg -nU --hidden 'except\s*(:|(\(\s*)?(Exception|BaseException)\b[^\n]*:)[ \t]*(#[^\n]*)?\n?[ \t]*pass\b' .

# A5 — JS/TS, Java, C#, PHP: an empty catch, including one holding only a comment.
rg -nU --hidden 'catch\s*(\([^)]*\))?\s*\{\s*((//|#)[^\n]*\s*|/\*[\s\S]{0,80}?\*/\s*)?\}' .

# A6 — Ruby: inline `rescue nil`, and a rescue clause with an empty body.
rg -nU --hidden '(rescue\s+nil\b|rescue\b[^\n=]*\n[ \t]*end\b)' .

# A7 — Go: an error assigned to the blank identifier, and an empty error branch.
rg -nU --hidden '(^[ \t]*_\s*=\s*[a-zA-Z_.]*[eE]rr[a-zA-Z_]*\b|if[^\n]*err\s*!=\s*nil\s*\{[ \t]*\n[ \t]*\})' .

# A8 — a guard called as a bare statement, its answer discarded (CWE-863).
#   Matches an authorization-shaped identifier ending a statement, so an `if`
#   (which ends in `:` or `{`) and a `return` (which has a keyword prefix) do not.
rg -n --hidden '^[ \t]*[\w.$>\[\]-]*\b(\w*(perm|priv|role|access|auth|allow|owner|scope|tenant|admin|acl|entitle)\w*|\w*[Cc]an[A-Z_]\w*|\w*[Mm]ay[A-Z_]\w*)\s*\([^\n]*\)\s*;?[ \t]*$' .

# A9 — a replace/sub/gsub whose pattern is markup, a traversal or an event
#   attribute: a regex standing where an encoder belongs (CWE-116).
rg -n --hidden -i '(\.replace\(|re\.sub\(|preg_replace\(|\.gsub\(|str_replace\(|\.replaceAll\()[^\n]{0,80}([<>]|script|javascript:|on\\w|\\\.|%2e|%3c)' .

# A11 — verification and trust switched off (CWE-295).
rg -n --hidden '(verify\s*=\s*False|verify\s*:\s*false|rejectUnauthorized\s*:\s*false|InsecureSkipVerify\s*:\s*true|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*.?0|CURLOPT_SSL_VERIFY(PEER|HOST)\s*,\s*(false|0)|check_hostname\s*=\s*False|_create_unverified_context|CERT_NONE|strictSSL\s*:\s*false|ServerCertificateValidationCallback|VERIFY_NONE)' .

# A12 — debug, verbose errors, autoescape off, wildcard hosts (CWE-489, CWE-1188).
rg -n --hidden '(debug\s*=\s*True|DEBUG\s*=\s*True|debug:\s*true|FLASK_DEBUG|app\.run\([^)]*debug|autoescape\s*=\s*False|autoescape:\s*false|ALLOWED_HOSTS\s*=\s*\[\s*["\x27]\*|customErrors mode="Off"|display_errors\s*=\s*On)' .

# A13 — the permissive side chosen as an environment-variable default. This is
#   the shape that survives review, because the switch reads as configurable.
rg -n --hidden '(getenv|environ\.get|env\.get|os\.Getenv)[^\n]{0,40},\s*(True|true|1|"1"|\x271\x27|"true")|process\.env\.\w+\s*\|\|\s*(true|1)' .

# A14 — an option the library accepts and ignores: `algorithm` (singular, a
#   signing option) passed to a verify call, which leaves the algorithm unpinned.
rg -nU --hidden '\bverify\(([\s\S]{0,200}?)\balgorithm\s*:' .

# A15 — an API whose name reads current and is not: node's key-from-password
#   ciphers, superseded by the *iv forms (CWE-477).
rg -n --hidden '(crypto\.)?createCipher\(|(crypto\.)?createDecipher\(' .
```

`A10` is the absence half of `A9`: a file that sanitizes by regex **and contains no context-aware encoder anywhere**. It is written as a loop rather than a pipe so the empty-list and error cases cannot become verdicts.

```bash
A9='(\.replace\(|re\.sub\(|preg_replace\(|\.gsub\(|str_replace\(|\.replaceAll\()[^\n]{0,80}([<>]|script|javascript:|on\\w|\\\.|%2e|%3c)'
ENC='escapeHtml|escape-html|DOMPurify|sanitize-html|bleach\.clean|markupsafe|CGI\.escapeHTML|html\.escape|htmlspecialchars|ERB::Util|StringEscapeUtils|HtmlEncode|template\.HTMLEscape|autoescape\s*=\s*True|realpath\(|basename\('

n=0
while IFS= read -r f; do
  [ -z "$f" ] && continue
  n=$((n + 1))
  rg -q -i -e "$ENC" "$f"; rc=$?
  case $rc in
    0) echo "  encoder present   $f" ;;
    1) echo "  REGEX ONLY        $f" ;;
    *) echo "  RG ERROR rc=$rc   $f — no verdict" ;;
  esac
done < <(rg -li --hidden -e "$A9" .)
[ "$n" -eq 0 ] && echo "  NO SITES: nothing sanitizes by regex here, so this half tested nothing (not a clean result)"
```

`A16` is the offline dependency-name resolution described in item 6. It contacts no registry, prints the resolution basis for every name rather than a bare verdict, and refuses to run against an empty file set.

**One environment note that cost a full sweep run.** Where `rg` is provided as a shell function rather than a binary on `PATH` — which is the case in at least one common harness — a sweep executed in a child shell exits 127 and finds nothing. Every one of the sixteen sweeps above reported `RG ERROR rc=127 — NO VERDICT` on the first fixture run for exactly that reason, and only the explicit status branch stopped it reading as sixteen clean results. Run the sweeps in the shell you are in, and check the status.

### 1. Crypto that reads as a decision (`legacy-hash-and-cipher-primitives`, `password-hashing-and-kdf-parameters`, `symmetric-encryption-and-nonce-handling`)

The tell is not the primitive — `crypto-and-key-management` owns primitives and grades them. The tell is **the rationale**. A comment that justifies a cryptographic choice by speed, simplicity or weight is a comment written by something optimizing the wrong objective, and it is a reliable marker for a construction nobody checked against a threat.

- `A1a`/`A1b` find the rationale. Read the construction next, and grade it under the owning lens's rules.
- **Do not restate crypto-and-key-management's sweeps here.** Its §0 carries the no-MAC absence sweep across seven ecosystems and the nonce-scope sweeps; those are its work. What this item adds is the pairing: a rationale comment beside a construction is a reason to run that lens's sweeps *even on a repository its `activates_on` never matched*, and to file under its slugs when they fire.
- The three constructions that recur with a speed rationale: a fast hash on a password write (CWE-328, CWE-916), MD5 or SHA-1 where collision resistance is load-bearing (CWE-327), and CBC or CTR with no MAC anywhere on the path.
- **A rationale comment with a correct construction is not a finding.** "AES-GCM because it authenticates" is a good comment. Grade the code, not the prose.

```detector
match: |
  # MD5 is fast and good enough for hashing the reset tokens here.
  def token_fingerprint(token: str) -> str:
      return hashlib.md5(token.encode()).hexdigest()

  def store_password(pw: str) -> str:
      # sha1 is simpler than bcrypt and much faster for our volume
      return hashlib.sha1(pw.encode()).hexdigest()
nomatch: |
  def cache_key(blob: bytes) -> str:
      # Cache addressing only; no adversary supplies this input.
      return hashlib.md5(blob, usedforsecurity=False).hexdigest()

  def store_password(pw: str) -> str:
      return PasswordHasher(memory_cost=19456, time_cost=2, parallelism=1).hash(pw)
```

The `nomatch` above is the discrimination that keeps this item usable: MD5 for a cache key, with the non-security use stated at the call site and `usedforsecurity=False` making it explicit, is correct code. Firing on it is how a report loses its reader.

```detector
match: |
  // AES with defaults is fast enough for the session blob.
  byte[] seal(byte[] key, byte[] plaintext) throws Exception {
    Cipher c = Cipher.getInstance("AES");
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
    return c.doFinal(plaintext);
  }
nomatch: |
  byte[] seal(byte[] key, byte[] plaintext) throws Exception {
    byte[] nonce = new byte[12];
    new SecureRandom().nextBytes(nonce);
    Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
    c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
    return concat(nonce, c.doFinal(plaintext));
  }
```

`Cipher.getInstance("AES")` resolves to `AES/ECB/PKCS5Padding` on the default provider. The name says AES and nothing says ECB, which is why it survives review — and the "fast enough" comment is what tells you the mode was never considered at all. Read the provider the repository configures before writing the mode into the finding; the default is what you get when nothing sets one.

### 2. Regex where an encoder belongs (`xss-and-output-encoding`, `injection-sql-nosql-orm`, `injection-command-and-template`, `path-traversal-and-file-access`, `ssrf-application-path`)

A function named `sanitize`, `clean`, `scrub` or `escape` whose body is a chain of `replace` calls is the single most reliable tell in this lens, because it is what a generator produces when asked to make input safe without being told what it will be interpolated into (CWE-116).

- `A9` finds the sites; `A10` finds the ones where **no context-aware encoder exists anywhere in the file**, which is the version worth filing.
- **The defect is the missing context, not the regex.** State it that way: the same string is interpolated into HTML text, an unquoted attribute, a URL and a script, and one substitution cannot be correct for all four. Name the sink you can reach.
- The recurring bypasses are worth writing into the finding because they make it concrete: a tag the pattern does not enumerate (`<svg onload=>`), an attribute break with no tag at all (`" autofocus onfocus=alert(1) x="`), a payload the strip *creates* (`<scr<script>ipt>`), a double URL-encoding, and `....//` against a single-pass `../` strip.
- Route by sink, not by function name. The same `replace` chain is an XSS finding in a template, a traversal finding on a path, and an SSRF finding on a fetched URL.
- **An allowlist regex over a genuinely closed domain is the correct answer, not a tell.** A UUID, an enum member, a bounded integer, a fixed-format identifier: a full-string anchored pattern that rejects everything else is stronger than encoding. The discriminator is whether the pattern *rejects* or *rewrites*. Rewriting is the tell.
- The proof is P5: feed the hostile corpus through the repository's own sanitizer and assert the encoding at each sink, per context. A sanitizer that "removed the payload" from one test string proves nothing about the next one.

```detector
match: |
  // Strip anything dangerous out of the note before rendering it.
  function sanitizeNote(input) {
    return input.replace(/<script[^>]*>.*?<\/script>/gi, '').replace(/on\w+=/gi, '')
  }

  function renderNote(res, note) {
    res.send(`<div class="note" title=${sanitizeNote(note.title)}>${sanitizeNote(note.body)}</div>`)
  }
nomatch: |
  const escapeHtml = require('escape-html')

  function renderNote(res, note) {
    res.send(
      `<div class="note" title="${escapeHtml(note.title)}">${escapeHtml(note.body)}</div>`,
    )
  }
```

Note the unquoted `title=` in the `match` half. Even a correct HTML-text encoder is insufficient there, which is why the finding names the context rather than the function.

```detector
match: |
  // Clean the filename so it cannot escape the upload directory.
  function sanitize_name(string $name): string {
      return preg_replace('/\.\.\//', '', $name);
  }
nomatch: |
  function safe_upload_path(string $base, string $name): string {
      $resolved = realpath($base . DIRECTORY_SEPARATOR . basename($name));
      if ($resolved === false || !str_starts_with($resolved, realpath($base))) {
          throw new \RuntimeException('path escapes the upload directory');
      }
      return $resolved;
  }
```

A single-pass `../` strip turns `....//etc/passwd` into `../etc/passwd`. The clean form does not filter the input at all — it resolves the path and asserts containment, which is the shape that has no bypass to enumerate.

### 3. A guard that is in the wrong place, or whose answer is thrown away (`authz-function-level`, `authz-object-level`, `race-conditions-and-toctou`, `apex-crud-fls-enforcement`, `symmetric-encryption-and-nonce-handling`)

Two shapes, one root cause: the check is present, so it reads as done.

**The guard runs after the operation it guards** (CWE-696, CWE-862). The row is deleted and then the permission is checked; the record is returned and then the tenant is compared; the payload is unpadded and parsed and then the tag is verified. The response may even be a correct 403 — after the write, or after the bytes have gone.

**The guard's answer is discarded** (CWE-863). `request.user.has_perm(...)` on a line of its own. `userCanEditNote(req.user, id)` with no `if`. Go's `_ = err` on an authorization call, and `if err := authorize(...); err != nil {}` with an empty body. `A8` and `A7` find these; they are among the highest-signal sweeps in the lens because there is no benign reading of an authorization predicate whose result nothing consumes.

**Source order is not execution order, and this is where the lens most easily manufactures a false positive.** Before filing, establish which one you are looking at:

- A decorator, attribute, annotation or middleware registered elsewhere runs *before* the function body regardless of where it appears in the file.
- A base-class or router-group guard is not in the handler at all.
- **A lazy query has not run yet.** A Django `QuerySet`, a SQLAlchemy `Query`, a LINQ `IQueryable`, a Rails relation: constructing it touches no rows. A guard between construction and evaluation is correctly placed. Whether the query has *executed* is the question, and `list()`, `.all()`, iteration, `.first()`, `len()`, `ToList()` and serialization are what answer it.

This is why item 3's proof is P3 and not a read: a spy on the mutation and a spy on the guard settle ordering in one run, and nothing else does.

```detector
match: |
  def delete_invoice(request, invoice_id):
      invoice = Invoice.objects.get(pk=invoice_id)
      invoice.delete()
      # FIXME: check the permission before deleting, not after
      if not request.user.has_perm("billing.delete_invoice"):
          return error(403)
      return ok()
nomatch: |
  def delete_invoice(request, invoice_id):
      if not request.user.has_perm("billing.delete_invoice"):
          return error(403)
      invoice = Invoice.objects.get(pk=invoice_id)
      invoice.delete()
      return ok()
```

```detector
match: |
  function deleteNote(req, id) {
    db.notes.delete(id)
    userCanEditNote(req.user, id)
    return { ok: true }
  }
nomatch: |
  function deleteNote(req, id) {
    if (!userCanEditNote(req.user, id)) {
      const err = new Error('forbidden')
      err.status = 403
      throw err
    }
    db.notes.delete(id)
    return { ok: true }
  }
```

```detector
match: |
  def export_invoice(request, invoice_id):
      rows = list(Invoice.objects.filter(pk=invoice_id))
      if not request.user.has_perm("billing.view_invoice"):
          return error(403)
      return render_pdf(rows)
nomatch: |
  def export_invoice(request, invoice_id):
      # The queryset is lazy: nothing has been fetched at this point, so the
      # guard below still runs before any row leaves the database.
      rows = Invoice.objects.filter(pk=invoice_id)
      if not request.user.has_perm("billing.view_invoice"):
          return error(403)
      return render_pdf(list(rows))
```

That third pair is the whole discrimination in six lines: the `list()` is the operation. Move it below the guard and the identical-looking code is correct. A detector that fires on both is worse than no detector, because it teaches the reader to ignore this item.

### 4. A swallowed error around a security control (`jwt-jws-and-jwks-verification`, `tls-and-certificate-validation`, `authz-function-level`, `threat-detectability-gap`, `phi-access-audit-controls`, `rate-limiting-and-request-quotas`, `csrf`)

`except Exception: pass`, `catch (e) {}`, `rescue nil`, `_ = err`, an empty `if err != nil` block (CWE-390, CWE-703). The pattern is everywhere in every codebase, and it is only a finding when **the swallowed call is the control**. Then the control fails open, silently, on every input that makes it raise — including inputs an attacker chooses.

- `A4`, `A5`, `A6` and `A7` find the sites. For each one, answer one question: *what did the `try` block do?*
- The severe form has a specific and recognizable shape: a `try` whose body computes and compares a MAC or verifies a token, an `except` that discards, and **a fall-through that returns success**. Read the value on the path after the handler. `return True` after a swallowed verification is a complete authentication bypass and it is two lines long.
- A swallowed **audit or security-event write** is the quiet one. Nothing fails, nothing is logged, and the detection surface is gone — route it to `threat-detectability-gap`, and to `phi-access-audit-controls` where the record is a PHI access.
- **Narrow types on non-security paths are the clean case and must not be swept up.** `except ValueError: pass` around a parse fallback, `contextlib.suppress(FileNotFoundError)` around a cleanup unlink, a `catch` that logs and re-raises. The sweeps above are written to exclude those; keep it that way.
- CWE-390 is the precise identifier — *detection of error condition without action* — and it is a better title than "empty except block" because it says what is wrong.

```detector
match: |
  def verify_receipt(sig: str, body: bytes, key: bytes) -> bool:
      try:
          expected = hashlib.sha256(key + body).hexdigest()
          return sig == expected
      except Exception:
          pass
      return True
nomatch: |
  def verify_receipt(sig: str, body: bytes, key: bytes) -> bool:
      expected = hmac.new(key, body, hashlib.sha256).hexdigest()
      return hmac.compare_digest(sig, expected)
```

Three defects share those seven lines — a `H(key ‖ msg)` construction, a timing-unsafe compare, and a swallowed exception with a `return True` fall-through — and only the third is this lens's. File one candidate per defect against the three owning slugs, and let triage merge whatever crypto-and-key-management also found.

```detector
match: |
  function checkWebhook(req) {
    try {
      const mac = crypto.createHmac('sha256', SECRET).update(req.rawBody).digest('hex')
      if (mac !== req.headers['x-signature']) throw new Error('bad signature')
    } catch (e) {}
    return true
  }
nomatch: |
  function checkWebhook(req) {
    const mac = crypto.createHmac('sha256', SECRET).update(req.rawBody).digest()
    const given = Buffer.from(req.headers['x-signature'] ?? '', 'hex')
    return mac.length === given.length && crypto.timingSafeEqual(mac, given)
  }
```

```detector
match: |
  def self.audit(actor, record)
    AuditLog.create!(actor: actor, record: record)
  rescue StandardError
  end
nomatch: |
  def self.audit(actor, record)
    AuditLog.create!(actor: actor, record: record)
  rescue StandardError => e
    Rails.logger.error("audit write failed: #{e.class}")
    raise
  end
```

The `match` half is the one that will not show up in any test suite: `create!` is the bang form, so it raises, and the bare `rescue` turns every audit failure into a success. Nothing observable changes until somebody needs the log.

### 5. An API that does not do what its name says (`jwt-jws-and-jwks-verification`, `legacy-hash-and-cipher-primitives`, `symmetric-encryption-and-nonce-handling`)

Two sub-shapes, and only one of them is greppable.

**An option the library accepts and ignores.** `jwt.verify(token, key, { algorithm: 'RS256' })` looks like algorithm pinning and is not: `jsonwebtoken`'s verify option is `algorithms`, plural, an array; `algorithm` singular is a *sign* option, and an unrecognized key in an options object is silently dropped. The token's own `alg` header then selects the algorithm, which is the entire class of confusion the option exists to prevent. `A14` finds it. The generalization is the finding worth writing: **an options bag is an unchecked namespace, so a misspelled security option is a security control that does not exist.**

**A symbol that does not exist, or exists and is superseded.** `crypto.createCipher(algorithm, password)` reads exactly like `createCipheriv` and is not: it derives the key from the password with a single unsalted MD5 pass and derives the IV the same way, so equal passwords give equal keystreams (CWE-477). It has been runtime-deprecated for years and removed from recent Node majors — read the engine the repository pins before writing the impact, because "throws on startup" and "silently encrypts with an MD5-derived key" are different findings. `A15` finds it.

**The general case is not greppable and must not be guessed at.** There is no pattern for "this method does not exist"; there is a resolution. Import the module the repository has installed and assert every attribute the code calls is present — that is P2, it runs offline, and it is the only honest form of this check. Where the package is not installed in the checkout, the answer is "cannot resolve", not "hallucinated".

```detector
match: |
  function currentUser(req) {
    // jsonwebtoken pins the algorithm from this option.
    return jwt.verify(req.headers.authorization, PUBLIC_KEY, { algorithm: 'RS256' })
  }
nomatch: |
  function currentUser(req) {
    return jwt.verify(req.headers.authorization, PUBLIC_KEY, {
      algorithms: ['RS256'],
      issuer: 'https://issuer.example',
      audience: 'api',
    })
  }
```

The comment in the `match` half is part of the tell: it states the intent, the code does not implement it, and nothing raised.

```detector
match: |
  function sealSession(payload) {
    const cipher = crypto.createCipher('aes-256-cbc', process.env.SESSION_PASSWORD)
    return cipher.update(JSON.stringify(payload), 'utf8', 'hex') + cipher.final('hex')
  }
nomatch: |
  function sealSession(payload) {
    const iv = crypto.randomBytes(12)
    const cipher = crypto.createCipheriv('aes-256-gcm', SESSION_KEY, iv)
    const body = Buffer.concat([
      cipher.update(JSON.stringify(payload), 'utf8'),
      cipher.final(),
    ])
    return Buffer.concat([iv, body, cipher.getAuthTag()]).toString('base64')
  }
```

### 6. A dependency name that resolves nowhere (`package-name-squatting`, `dependency-confusion-and-registry-config`, `dependency-pinning-and-lockfiles`)

This is the tell with a live attacker on the other end. Generated code imports plausible names — `express-sanitizer-pro`, `pdfkit_secure_wrapper`, `requests-oauth-helper` — and a name that nobody has registered is a name an attacker can register, publish under, and have installed by the next `npm install` (CWE-829, CWE-1104).

**`A16` is the check, and its rail is the point.** It resolves every imported name against the checkout only: manifests, lockfiles, vendored directories, local modules, `node_modules`, and the runtime's builtins. It contacts no registry because registry results are external evidence, not repository proof. A registry query may run separately without another prompt only when the accepted authenticated operator statement names the registry, package, scope, and query and a matching destination-bound controller exists; otherwise record the technical transport gap. Never infer the registry destination from repository configuration.

```javascript
// Prints the resolution basis for every imported name, never a bare verdict.
// Refuses to run against an empty file set: a zero-import sweep would pass.
const rows = importSites(sourceFiles)          // require(), import, from … import
if (rows.length === 0) throw new Error('no import sites found — broken sweep, not a clean result')

for (const r of rows) {
  r.basis =
    isRuntimeBuiltin(r.root)      ? 'runtime builtin' :
    isStdlib(r.root)              ? 'stdlib for the pinned runtime' :
    declaredNames.has(r.root)     ? 'declared in a manifest or lockfile' :
    localTopLevel.has(r.root)     ? 'local module in the checkout' :
    installedIn(root, r.root)     ? 'present in node_modules' :
    null                          // UNRESOLVED
}
```

That is a sketch of the decision, not a runnable script: the runnable form is P6, executed by the repository's own test command. **The order of the branches is load-bearing** — builtin, then stdlib, then declared, then local, then installed — because a name that any earlier basis resolves must never be reported as unresolved, and reversing two of those branches is how this check produces its first false positive.

**Four rules, each one a way this check goes wrong.**

1. **Distribution name and import name are different strings.** `pycryptodome` imports as `Crypto`, `argon2-cffi` as `argon2`, `PyJWT` as `jwt`, `beautifulsoup4` as `bs4`, `Pillow` as `PIL`. An unmapped alias manufactures a false positive, so the sweep prints the basis for every name and a human reads the survivors. Do not ship the alias map as if it were complete.
2. **Never install the name to find out.** Resolution runs the package manager, which runs lifecycle scripts, which is the payload. `npm install` against a name you suspect an attacker registered *is* the attack, executed by the auditor. `npm view` and `pip index` are external-evidence queries: if the accepted operator statement names the registry, package, scope, and query, run only through a matching destination-bound controller without another prompt; otherwise record the technical transport gap. Never infer the registry from repository configuration.
3. **Unresolved in the checkout is not unregistered in the registry.** Those are two claims and this sweep supports only the first. State it: "the name resolves nowhere in this checkout" is T1; "the name is unregistered and therefore claimable" is the assumption, with the one-line command for the user to settle it themselves.
4. **A declared name can also be unresolvable.** A manifest entry that no registry serves is the same exposure arriving through a different door, and it is invisible to this sweep — the import resolves, because the manifest lists it. `A16` will not find it and must not be described as if it could.

The **private-scope variant routes elsewhere.** An unresolved `@acme/…` or an internal prefix is dependency confusion, not squatting: the risk is a public registry serving a name the private one was meant to own. File it under `dependency-confusion-and-registry-config` and check the registry configuration in the same pass.

```detector
match: |
  # app/report.py
  import io
  import pdfkit_secure_wrapper

  def build(invoice):
      return pdfkit_secure_wrapper.from_string(invoice.as_html(), io.BytesIO())

  # requirements.txt — the imported name appears nowhere
  # Django==5.0.6
  # requests==2.32.3
nomatch: |
  # app/report.py
  import io
  import weasyprint

  def build(invoice):
      return weasyprint.HTML(string=invoice.as_html()).write_pdf(io.BytesIO())

  # requirements.txt
  # Django==5.0.6
  # requests==2.32.3
  # weasyprint==62.3
```

### 7. Deferred-work comments as pointers (routes to the absent control's owner)

`# TODO: validate this`, `// in production, use the real key store`, `# placeholder — replace before launch` (CWE-546). `A2` and `A3` find them.

**The comment is never the finding.** Two things follow, and they point in opposite directions:

- **Verify the absence before filing.** A stale `TODO` above code that a framework validator, a schema decorator or a middleware already covers is a documentation defect. Establish that the control is missing on *every* path that reaches the sink, then file against the control's owner and quote the comment as evidence of intent rather than as the defect.
- **Verify it is not worse than the comment says.** `# TODO: validate the certificate chain before we go live` sitting above `requests.get(url, verify=False)` is not a to-do. The code is shipping with verification off, the comment is the author telling you they knew, and the finding is Critical under `tls-and-certificate-validation`.

The genuinely useful reading of a `TODO` is as a **map of what the author knew was missing**. Cluster them, and audit those areas first: they are the parts of the repository whose author already told you not to trust them.

```detector
match: |
  def fetch_jwks(url: str):
      # TODO: validate the certificate chain before we go live
      return requests.get(url, verify=False, timeout=5).json()
nomatch: |
  def fetch_jwks(url: str):
      return requests.get(url, timeout=5).json()
```

### 8. Permissive defaults that made an example run (`debug-and-admin-endpoint-exposure`, `error-handling-and-verbose-responses`, `tls-and-certificate-validation`, `xss-and-output-encoding`, `cors-policy`, `network-exposure-and-segmentation`, `mobile-build-and-runtime-flags`)

`debug=True`, `verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`, `autoescape=False`, `ALLOWED_HOSTS = ["*"]`, `strict: false` (CWE-489, CWE-1188, CWE-295). Each of these makes something work immediately, which is why it is in the file, and each of them is a control that is now off.

- `A11`, `A12` and `A13` find them. `A13` is the one worth reading twice: **the permissive side chosen as an environment-variable default** — `os.environ.get("DJANGO_DEBUG", True)`, `process.env.STRICT || true` — survives review because the switch reads as configurable. It is not: every deployment that does not set the variable gets the insecure value, and nothing in the repository records which deployments those are.
- **Assert against the rendered configuration, not the source text.** A settings module, an overlay, a profile or a compose file can flip any of these, in either direction. Import the configuration the deployment actually selects and assert on the resulting value — that is P7 and it is the difference between a finding and a guess.
- `strict` deserves a caution: name the control before filing. TypeScript's `strict`, a CSV reader's strict mode and a schema validator's `strict` are three different things and only some of them are security boundaries. "`strict: false` found" with no named control is not a finding.
- Where the switch is genuinely local-only, the discriminator is at the call site: the **host literal**. `verify=False` against `https://localhost:4443` in a file whose imports are a test emulator is a different claim from the same line against a value read from configuration. Quote the literal.

```detector
match: |
  func client() *http.Client {
    // In production, use the system cert pool. Fine for now.
    tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
    return &http.Client{Transport: tr}
  }
nomatch: |
  func client(pool *x509.CertPool) *http.Client {
    tr := &http.Transport{TLSClientConfig: &tls.Config{
      RootCAs:    pool,
      MinVersion: tls.VersionTLS12,
    }}
    return &http.Client{Transport: tr}
  }
```

```detector
match: |
  DEBUG = os.environ.get("DJANGO_DEBUG", True)
  ALLOWED_HOSTS = ["*"]

  env = Environment(autoescape=False)
nomatch: |
  DEBUG = os.environ.get("DJANGO_DEBUG", "0") == "1"
  ALLOWED_HOSTS = os.environ["DJANGO_ALLOWED_HOSTS"].split(",")

  env = Environment(autoescape=True)
```

Both halves of the second pair read the same environment variable. The difference is which way the default falls, and it is the whole finding.

### 9. The cluster read

Not a finding, and it names no literal on purpose. After the sweeps, count **distinct sweep ids per file** — a single module carrying seven of the sixteen is not unusual — and use the result to decide where the audit goes next.

- A file with several unrelated tells was not reviewed. Re-read it at full depth, and say in the coverage block that you did, and why.
- Report the cluster as **scope, never as severity**. Seven tells in a file do not make any one of them worse. See `## Severity calibration`.
- **Never write the cluster as an authorship claim.** "This module shows seven machine-authored-code tells" is rule 1 violated with a number attached. Write what the audit did: "this module carried seven distinct unreviewed-code markers and was re-read in full; the findings from that pass are below."
- A cluster of **zero** is worth one sentence too. It means these sixteen sweeps found nothing, which is a narrow statement about sixteen patterns and not a clean bill of health for the repository.

## Severity calibration

`severity_floor: info` is presentational. It orders this lens's findings in the report, it never suppresses one, and no item above may be dropped because it sits at Info.

**The floor is `info` rather than `low` deliberately, and the reason is item 9.** This lens needs a rank for a record that carries a tell whose consequence could not be established — a `TODO` beside a control that may or may not exist, a swallowed exception whose `try` block does something this audit could not resolve. That record is worth keeping and is not worth a Low. The Phase A plan specified `low`; the shipped frontmatter says `info`, and `info` is the one to keep.

**The rule that does all the work: this lens sets no severity of its own.** `claimed_impact_severity` is the severity the **owning lens's** rule gives the consequence, applied to the artifact this lens found. Where that lens's rule cannot be applied — because the artifact does not establish the condition it names, or because the lens did not run and its rules were not consulted — the record is Info or Low with the reason written in, never a guess. Refusing to guess is what keeps this lens's findings from being discounted wholesale, which is the failure mode that ends with the lens switched off.

**The second rule: a tell alone is never above Low.** It is a marker. The consequence carries the severity, and the consequence has to be established from an artifact in the repository.

### What this lens claims, and what establishes it

| Shape | What this lens claims | The artifact that establishes it | Graded by |
|---|---|---|---|
| Fast-hash rationale on a password write | The stored artifact is a fast digest | The write path, and a migration, fixture or seed carrying a bare digest column or a `md5`/`sha1` hex value | `password-hashing-and-kdf-parameters` |
| Fast-hash rationale, collision resistance load-bearing | The digest is trusted for identity or integrity | The use: signature or certificate verification, integrity of untrusted content, a cross-tenant dedup key | `legacy-hash-and-cipher-primitives` |
| Unauthenticated cipher mode | Ciphertext is malleable on this path | The construction call plus the no-MAC absence result from crypto-and-key-management's §0 | `symmetric-encryption-and-nonce-handling` |
| Regex sanitizer, no encoder in the file | Output encoding is absent for the sink reached | `A9` plus `A10`, plus the interpolation site with its context named | `xss-and-output-encoding` and siblings |
| Guard after the operation | The operation completes for an unauthorized principal | Call order **proved by spies** (P3), not source order | `authz-function-level` / `authz-object-level` |
| Guard result discarded | The check cannot refuse anything | `A8`/`A7`: the predicate is a bare statement, or the error goes to `_` | `authz-function-level` / `authz-object-level` |
| Swallowed control with a success fall-through | The control fails open on any raising input | The `except`/`catch` body plus the value returned on the path after it | the swallowed control's owner |
| Swallowed audit write | The detection surface is gone for this event | The write is inside the swallowed block and nothing else records the event | `threat-detectability-gap`, `phi-access-audit-controls` |
| Ignored library option | The security property the option names is not enforced | The library's own accepted-option set for the pinned version, read from the installed package | `jwt-jws-and-jwks-verification` |
| Unresolved dependency name | The name resolves nowhere in this checkout | `A16` with its per-name basis, and the manifest and lockfile it consulted | `package-name-squatting` |
| Deferred-work comment | Named control is absent on every path to the sink | The absence, established on the path — not the comment | the absent control's owner |
| Permissive default | The control is off in the configuration the deployment selects | The **rendered** configuration value (P7), not the source line | the disabled control's owner |
| Cluster of tells | The module was not reviewed | The per-file distinct-sweep-id count | **nobody — this is not a finding** |

### Four anti-patterns, stated as rules

- **Never uplift because the code looks generated.** There is no severity multiplier for suspected authorship. There is no "AI-generated" aggravator. Both are rule 1 wearing a severity field.
- **Never let a cluster raise a severity.** Seven tells in one module change the audit's *scope*. They do not change what any single defect does to a caller. A count in a severity justification is a category error, and it is the specific way this lens would become the AI-blamer.
- **Never grade a tell on how alarming it reads.** `except Exception: pass` around a cache warm is Info or nothing. The same three characters around a signature check is a Critical authentication bypass. The severity is entirely in the swallowed call, and the sweep cannot see it.
- **Never file the shape when you could not establish the consequence.** File the tell at Info with the blocking reason, or file nothing. A Medium invented to make a candidate look worth reading is how the whole lens gets discounted — and a wrong clearance is worse still, so "could not establish" is written down rather than dropped.

## Known false positives

**This section matters more here than in any domain lens, and the reason is structural.** Every tell in this lens also appears in code a person wrote carefully. The tells mark *unreviewed* code; they do not mark authorship, and a lens that reports them as authorship becomes the tool that blames a machine for a human's deliberate decision — and gets switched off within a day. Say what the code does wrong.

Each entry names a pattern a competent reviewer would flag and states why it is not the finding it looks like. **None of these is a licence to drop a finding**: every one names the narrower finding that does survive.

1. **`try/except: pass`, `catch {}`, `rescue nil` where nothing security-relevant was swallowed.** Best-effort telemetry, a cache prefetch, an optional import fallback, a metric emit, a cleanup unlink, a "close if still open". These are the overwhelming majority of hits from `A4`, `A5` and `A6`, and none is a finding. The narrow version is the whole item 4: the swallowed call **is** the control — a MAC computation, a token verification, a certificate check, a permission evaluation, an audit write — and the path after the handler returns success. Read the `try` body and the post-handler return value before writing anything, and if you cannot resolve what the swallowed call does, say so rather than filing.

2. **A narrow exception type on a parse or lookup fallback.** *(Scope, measured 2026-07-27: `A4`
   does exclude these — `except ValueError: pass` and `contextlib.suppress(FileNotFoundError)`
   are both unmatched. `A5` does **not**: it matches `catch (JsonParseException e) { /* fall
   through */ }`. An `A5` hit on a narrow, named type is therefore expected and is cleared by
   reading it, not by assuming §0 filtered it.)* `except ValueError: pass` around an `int()`, `contextlib.suppress(FileNotFoundError)` around an unlink, `catch (JsonParseException)` returning a default. Naming the type *is* the review; it is evidence somebody thought about which failures are expected. The sweeps in §0 are written to exclude these deliberately, and widening them to `except .*: pass` would bury item 4 under noise and cost the lens its credibility on the hits that matter.

3. **MD5 or SHA-1 in application code.** Cache keys, ETags, shard selection, content addressing of internal blobs, dedup fingerprints, Git object ids, HMAC-SHA1 required by a vendor API. `crypto-and-key-management` owns this discrimination and states it in full; this lens must not fire *at all* on those uses, and `hashlib.md5(x, usedforsecurity=False)` is an author stating the non-security intent explicitly — which is the opposite of the tell. What this lens adds is only the **rationale**: a comment justifying the primitive by speed where a security property is load-bearing. No rationale and a non-security use is not a hit.

4. **`verify=False` / `rejectUnauthorized: false` / `InsecureSkipVerify: true` against a local fixture.** A test emulator, a `localhost` dev server with a self-signed certificate, a container-to-container hop inside a compose file. The discriminator is the **host literal at the call site**, and it belongs in the finding either way: a hardcoded `https://127.0.0.1:4443` is a different claim from a value read from configuration. What does *not* clear it: "it's internal", "there's a mesh", "it's behind the VPN". None of those is in the repository, and internal traffic is exactly what a foothold reaches.

5. **`debug=True` in a path the deployment does not select.** A `if __name__ == "__main__"` block the container never runs, a `settings/dev.py` that production configuration does not import, a compose override used only locally. Establish what the deploy artifact selects — the `CMD`, the `WSGI_APPLICATION`, the profile, the `NODE_ENV` — and assert on the rendered value (P7). **The inverse trap is the more common one and it is not a false positive**: `DEBUG = os.environ.get("DEBUG", True)` is reachable in production by *omission*, which is the default state of every new deployment.

6. **A regex in front of a correct encoder.** The finding in item 2 is a regex standing *instead of* context-aware encoding, not a regex used *as well as*. A length check, a charset pre-filter, a rejection pattern, a normalization pass ahead of `escapeHtml` or a parameterized query is defence in depth. `A10` exists precisely to separate these: it keeps only the sites where no encoder appears anywhere in the file.

7. **An anchored allowlist regex over a closed domain.** `^[0-9a-f]{8}-[0-9a-f]{4}-…$` for a UUID, `^(pending|active|closed)$` for a status, `^\d{1,6}$` for an id. Rejecting everything outside a known-good set is stronger than encoding, not weaker. The discriminator is reject-versus-rewrite: a pattern that *removes* characters and continues is the tell; one that refuses the input is the fix. A pattern that is not anchored at both ends is a third case and a real finding — `^/public` matching `/publications/secret` is the same defect the shared enumerator's allowlist self-test exists to catch.

8. **A guard that follows the operation in source order but not in execution order.** A decorator, an annotation, a `before_action`, a router-group middleware, a base-class check, an `@PreAuthorize`. And above all a **lazy query**: a Django `QuerySet`, a SQLAlchemy `Query`, a LINQ `IQueryable`, an ActiveRecord relation. Constructing one touches no rows, so a guard between construction and evaluation is correctly placed. Establish where evaluation happens — `list()`, `.all()`, iteration, `.first()`, `len()`, `ToList()`, serialization — and if you cannot, prove the ordering with spies (P3) rather than filing on the reading.

9. **A validator whose return value is meaningfully discarded.** Item 3's discarded-guard sweep fires on `validate_token(t)` as a bare statement, and a validator that **raises** on failure is correctly called that way — its return value carries nothing. The discriminator is the function's contract: does it return a boolean or does it raise? Read the definition. A predicate named `has_perm`, `can_edit` or `is_authorized` whose answer nothing consumes has no benign reading; `assert_can_edit` or `require_role` probably does.

10. **A comment that describes a deployment split, badly.** "In production this comes from the secret manager" beside a local default is often *true* — the deployment does inject it, and the comment is a clumsy note about the split rather than an admission. Check the deployment configuration in the checkout before filing. The finding survives only where the insecure branch is reachable in the deployed configuration, and then it is not a comment finding at all.

11. **A `strict: false` that is not a security control.** TypeScript's `strict`, a CSV parser's strict mode, a schema library's `strict` on an internal DTO, a YAML loader's strict duplicate-key handling. Name the control the flag governs and the property that is lost. Without both, there is no finding — and `strictSSL: false` and a schema validator's `strict: false` on an externally-supplied payload are two of the cases where there is.

12. **Generated, vendored and migration files.** Protobuf output, ORM migrations, SDK clients, minified bundles, `dist/`, `vendor/`, lockfiles, snapshot fixtures. These contain every tell in this lens, are not hand-maintained, and firing on them produces a report the reader closes. Establish the file's nature from its header, its path, or a `linguist-generated` attribute in `.gitattributes`. The exception is real and narrow: a **vendored** file is shipped code and a defect in it is live — the finding then belongs to whoever owns provenance for that tree, not to a report about style.

13. **A security test's own hostile fixtures.** A vulnerable fixture under `test/security/fixtures/vulnerable/`, a payload corpus, a red-team sample, the negative half of a detector pair. This lens's sweeps will light them up, and reporting them is the self-own: it flags the audit harness as the vulnerability. Exempt them by path with an **anchored** pattern, and never by a prefix that also exempts a directory nobody reviewed.

### Rejected candidates

Candidates considered for this lens and deliberately excluded. Nothing here should be quietly re-added; each would either have manufactured findings, or made this lens the AI-blamer, or required something the hard rails forbid.

**Rejected as authorship stylometry — the whole category.** Verbose or over-explanatory comments; a comment on every line; consistent docstring formatting; emoji in output strings; tidy type hints; "the code is suspiciously clean"; enthusiastic variable naming; a `README` that reads as generated. Every one of these is a claim about *who wrote it* with no claim about what it does, and rule 1 forbids the claim outright. They are also unfalsifiable: no evidence can refute them, which is exactly what disqualifies them as findings.

**Rejected as tooling residue used as evidence.** An assistant's configuration directory or rules file in the tree; a `# Generated by …` banner; a commit message or co-author trailer naming a tool. These are true observations about tooling and they must never grade or justify a finding. A file with an assistant's config beside it and no defect has no finding, and a file with a defect has the same finding either way. Recording the residue as audit context is acceptable; using it as an input is not — and the lens deliberately names no products here, because a list of tool names would turn this section into the authorship inference that rule 1 forbids.

**Rejected because the check needs a registry.** "The package name is one edit away from a far more popular package" — typosquat proximity needs popularity data from a registry, which is external evidence under rail 1, and a typosquat *is* a real package so an existence check cannot refute it. The offline half survives as item 6: the name resolves nowhere in this checkout. The registry half stays outside repository proof and `cicd-and-supply-chain` owns the slug; when the accepted operator statement names its exact destination and query, execute it without another prompt only through a matching implemented external controller, or record the technical gap as `UNPROVEN`.

**Rejected because resolution executes the payload.** "Install the suspect package into a scratch environment and see what it does." Installation runs lifecycle scripts, which is the malware's entry point — the auditor would be executing the attack to confirm it exists. There is no safe version of this inside the skill.

**Rejected as ungreppable and therefore unownable as a sweep.** "Hallucinated library API" as a text pattern. There is no literal for "this method does not exist"; there is only symbol resolution against the installed package (P2). Keeping a grep for it would produce a sweep that returns zero on every repository and reads as clean — the exact failure this project's detector rule exists to prevent.

**Rejected as not security.** Long functions; missing tests; `# type: ignore`; `datetime.utcnow()` deprecation; duplicated blocks; unused imports; inconsistent formatting; a missing license header. All real review concerns, none a security finding, and each one dilutes the report it appears in. `completeness` covers absent-coverage reasoning as a triage lens; style has no owner here and should not acquire one.

**Rejected as a finding, kept as a routing note.** A per-line scanner suppression — `# nosec`, `# noqa: S105`, `// eslint-disable-next-line security/…`, `@SuppressWarnings`. This is genuinely informative: somebody silenced a tool at a specific line. But it is not a machine-authored-code tell (it is more often the opposite — evidence of a human interacting with a scanner), and no slug covers "a suppression was added". The nearest owner is `pipeline-scanner-gating` and it is a stretch. Sweep for them when triaging another finding at the same line; do not file them as their own.

**Rejected as a severity input.** The cluster count. Kept as a scope instruction in item 9, refused as a multiplier in `## Severity calibration`, and named here so it is not reintroduced as an aggravator field.

## Proof recipes

Shared harness components are referenced by name and not restated here: the **detector-and-fixture-pair runner**, the **registry-driven enumerator**, the **canary fixture set**, the **two-subject fixture**, the **capturing log handler**, and the **socket-layer destination recorder**. Their implementations live in `lenses/_harness.md`.

**Tier rule.** Most of this lens's evidence is static-checker shaped, so the static-checker resolution in `_harness.md` → `## Proof tiers` is what decides whether a finding lands at **T1 or T0**: a checker counts as T1 only when the repository's own runner executes it *and* it asserts both directions — fires on the vulnerable fixture, silent on the clean one. One direction is not enough, and the missing direction is always the same one. A sweep asserted in the firing direction only proves the rule runs, not that it discriminates, and it caps at T0 and therefore at Medium.

Three of the recipes below are genuinely behavioural rather than static — P3 (ordering), P4 (fault injection) and P5 (encoding) — and those are the ones that can carry a Critical.

**Prove the consequence, not the pattern.** A grep result is not a finding at any tier. Every recipe here ends in an assertion about a decision or a side effect: the row was deleted, the request was accepted, the payload reached the sink, the attribute does not exist.

### P1 — Detector-and-fixture pairs for all sixteen sweeps (T1)

Run every sweep in §0 through the **detector-and-fixture-pair runner** against a committed hostile fixture and a committed clean one, under the repository's own test command. Six of the runner's rules bear directly on this lens:

1. **Both directions, as counts.** `detect(vulnerable).length === expected` and `detect(clean).length === 0`. Counts, not booleans, so a pattern that matches twice is distinguishable from one that matches once.
2. **The clean fixture carries the false positives, not the absence of the tell.** This is the rule specific to this lens. A clean fixture that simply deletes the vulnerable line proves nothing about discrimination. It must contain `except ValueError: pass`, `contextlib.suppress(FileNotFoundError)`, `hashlib.md5(x, usedforsecurity=False)` on a cache key, a lazy queryset evaluated *after* the guard, a `catch` that logs and re-raises, and an anchored allowlist regex — the shapes from `## Known false positives` — and every sweep must stay silent on all of them.
3. **`A10` and `A16` are absence-shaped and need the extra assertion.** A rule that fires on a missing artifact can pass by matching nothing at all. Assert that `A10` fires on a fixture from which the encoder has been deliberately removed, and that `A16` fires on a fixture from which the manifest entry has been deliberately removed.
4. **Assert the rule set is non-empty.** Sixteen sweeps must be sixteen. A deleted pattern reads as compliance otherwise.
5. **Report a resource address, not a filename.** `file:line` plus the sweep id, so a reviewer can find the hit and know which rule produced it.
6. **Run a tightened pattern against the previous revision and require it to fail there.** `git show HEAD~1:path` into the same checker. A pattern that passes on both revisions of a change meant to introduce the fix is not looking at the file.

**Two failures to build the harness against, both observed on this lens's own fixture run.** A sweep that exits 127 because `rg` was a shell function invisible to the child process reported "no hits" for all sixteen rules; and an unguarded `rg --files-without-match` handed an empty file list searched the entire tree and returned every file as a hit. Branch on the exit status, and treat an empty input list as "nothing tested".

### P2 — Symbol and option resolution against the installed package (T1)

The only honest form of the hallucinated-API check. Import the module the checkout actually has and assert that every attribute the code calls exists, and that every option key the code passes is one the library accepts.

- Enumerate the call sites and option keys with the **registry-driven enumerator**, with its committed count and its zero-row guard. An enumerator that silently returns nothing passes this recipe perfectly.
- For an attribute: assert `hasattr(mod, name)` / `name in mod`. For an option: compare against the library's own accepted set for the pinned version — a TypeScript declaration file, a dataclass or Pydantic model, a documented signature, or the source of the installed package. `jsonwebtoken`'s verify options are the worked example: `algorithm` is not among them, and the assertion that fails is the finding.
- **Install the destination guard from the socket-layer destination recorder first, with an empty allowlist.** This resolution must be entirely offline; if any part of it reaches for a registry, the run fails loudly instead of quietly making a network call.
- Where the package is not installed in the checkout, the result is `INCONCLUSIVE` with the reason "the package is not present, so its symbol table could not be read" — not a hallucination finding.

### P3 — Ordering proved by spies, never by source order (T1)

The discriminator for item 3 and for false positive 8.

Take the unauthorized principal from the **two-subject fixture**. Spy on the guard and on the operation — the delete, the write, the send, the query evaluation — then make the request and assert **three** things:

1. The guard was called.
2. The operation was **not** called at all. Not "was called and then rolled back": not called.
3. The victim's marker from the **canary fixture set** appears nowhere in the response body, the headers, or any file the request produced. A handler that refuses after streaming has still leaked, and status alone will not show it.

Include the legitimate case — the principal who *should* succeed — or a handler that refuses everything passes the whole recipe.

For the crypto variant of the same shape, record call order in a list and assert `calls.index("verify_tag") < calls.index("unpad")`, then re-run with a deliberately corrupted tag and assert the unpad, parse and deserialize spies were never called. An exception raised after the payload was parsed is the padding-oracle shape, and only the never-called assertion separates it from a correct implementation.

### P4 — Fault injection into the swallowed control (T1)

The proof for item 4, and the one that turns "an exception is discarded" into "the control fails open".

Patch the control the `try` block calls so it raises — the MAC computation, the token verifier, the permission evaluator, the audit write — then exercise the path and assert:

- The request is **refused**. If it succeeds, the swallow is load-bearing and the finding is confirmed at the swallowed control's severity.
- With the **capturing log handler** attached to the real logger, assert whether anything was recorded. A silent swallow and a logged-and-swallowed one are different findings: the second is a detectability gap, the first is invisible. Raise the captured logger to `DEBUG` for the duration and record that you did, because a level-filtered record is not evidence of absence.
- For a swallowed audit write, assert the **side effect**: no row in the audit table, and the operation nonetheless succeeded. That pair is the finding.

Patch where the name is looked up, not where it is defined, or the application keeps its real control and the injection records nothing — a pass that reads as safety.

### P5 — Encoding proved at the sink, per context (T1, T2 for the browser half)

The proof for item 2. Feed the **hostile corpus** from the canary fixture set through the repository's own sanitizer and assert the **shape of the output at each sink**, never that the payload "was cleaned".

- For each context the value reaches — HTML text, a quoted attribute, an unquoted attribute, a URL parameter, a JavaScript string, a JSON body, a SQL predicate — assert the encoding that context requires is present in the rendered output. Parametrize the contexts with the enumerator so a new sink added later fails the test.
- Include the payloads that defeat a single-pass strip: `<scr<script>ipt>alert(1)</script>`, `" autofocus onfocus=alert(1) x="`, `<svg onload=alert(1)>`, `....//etc/passwd`, and a double-URL-encoded traversal.
- The browser half is **T2**: render the page in a headless browser against a booted local dev server on `127.0.0.1` and assert `window.__pwned` was never set. An accepted authenticated operator statement naming the target, scope, and browser/dev-server launch is the sole authorization fact; the operator is accountable for it, and the auditor does not ask again or independently adjudicate legal authority. Execute only through a matching implemented controller. If none exists, report the T1 result and record `UNPROVEN` with the technical transport gap rather than letting the absence read as safety.

### P6 — Offline dependency-name resolution, and the half it cannot prove (T1)

`A16`, run under the repository's own test command, with the enumerator's committed import-site count so a zero-row sweep cannot pass.

**What is provable here:** the name appears at an import site and resolves nowhere in this checkout — not in a manifest, not in a lockfile, not vendored, not local, not a builtin. That is T1, and the failure message names the file and the basis for every name it *did* resolve.

**What is not, and how to write it:** whether the name is unregistered, and therefore claimable by an attacker. That registry query is external evidence, not repository proof. Record the assumption. If the accepted operator statement names the registry, package, scope, and query, run `npm view <name>` or the equivalent index query without another prompt only through a matching destination-bound controller; otherwise record the technical transport gap. **Never install it.** Installation runs lifecycle scripts, which is the payload.

The **declared-but-unregistered** case is invisible to this recipe and must be named in the coverage block: a manifest entry no registry serves resolves fine here, and only the registry can distinguish it from a private package.

### P7 — Permissive defaults asserted against the rendered configuration (T1)

The proof for item 8, and the reason it is not a grep. Load the configuration the deployment actually selects — import the settings module the `WSGI_APPLICATION` names, build the client through the application's own factory, render the compose or manifest overlay — and assert on the resulting value:

- `DEBUG is False`, and separately that the value is `False` when the environment variable is **absent**, which is the `A13` shape.
- The constructed HTTP client verifies certificates: `verify` is truthy, `InsecureSkipVerify` is false, `MinVersion` is at least TLS 1.2, `rejectUnauthorized` is not false.
- The template environment autoescapes, asserted on the environment object rather than on the constructor call.
- The host allowlist and the CORS origin list contain no wildcard, with the credentials flag read alongside.

Parametrize over every environment the repository defines, and assert both directions: the production configuration is safe **and** the test asserts something — flip one value in a fixture and require the assertion to fail. A configuration test with no failing case passes on a deleted setting.

### Not provable here, and reported as such every run

Name these in the coverage block rather than letting silence imply safety.

- **Who or what wrote the code.** Permanently outside this lens, by rule 1, at every tier. Never reported, never assumed, never used as an input.
- **Whether an unresolved name is unregistered.** P6's offline half is T1; the registry half is an assumption with a user-runnable command, and it stays an assumption.
- **Whether a `TODO` corresponds to tracked work.** The tracker is not in the checkout. What is checkable is the absence of the control it names.
- **How often a swallowed exception fires in production.** P4 proves the control fails open when it raises. Frequency is a runtime property and grades nothing here.
- **Whether the deployment selects the configuration P7 asserted on.** Where the selection happens outside the repository — a platform environment, an orchestrator secret, a console setting — the assertion covers the rendered artifact in the checkout and nothing further. Say which.
- **Whether the sixteen sweeps are the right sixteen.** They are patterns, and a defect in a shape nobody wrote a pattern for is invisible to all of them. A cluster count of zero means these sixteen found nothing; it is not a clean bill of health, and the coverage block says so in those words.
