# The Last Aperture Burp Montoya exporter

This optional Montoya extension exports value-free protocol structure from
existing Burp Proxy HTTP history. It is target-neutral and works in Burp Suite
Community or Professional. It reads `api.proxy().history()`, uses each item's
`finalRequest()`, and never invokes Scanner, sends a request, or modifies
traffic.

## Build

Supply an existing local Montoya API JAR and JDK 17 through 21. The build makes
no network request, compiles with `--release 17` and annotation processing
disabled, excludes Burp API classes from the result, and refuses to replace an
existing output JAR. It also rejects javac internal-exception diagnostics even
when a defective compiler returns exit code zero.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File integrations\burp-montoya\build.ps1 `
  -MontoyaApiJar C:\tools\montoya-api.jar `
  -OutJar C:\reverse-output\last-aperture-burp-montoya.jar
```

Load the output JAR from Burp's Extensions settings. Unloading interrupts the
export worker and deregisters the suite tab.

## Export existing Proxy history

Open the **Last Aperture** suite tab and provide:

- one exact canonical HTTP(S) origin;
- one path prefix;
- optional comma-separated route segments reviewed as safe to retain;
- a maximum number of history records to examine, from 1 to 10,000; and
- a new absolute local `.har` or `.json` output path whose parent exists.

The exporter takes at most that many records from the Burp history snapshot,
sorts that bounded selection by timestamp and history ID, keeps requests inside
the origin and path prefix, and creates a sanitized HAR 1.2 document. The limit
therefore bounds history traversal as well as output size. The provenance block
records both available and examined record counts.
It removes header, cookie, query, and body values before writing. It retains
bounded structural names, methods, response statuses, representative body
sizes, structural content type, and templated paths. The `_lastAperture` block
records the exact scope and limits, omissions, redaction claims, Burp name,
version, build, edition, and capability declarations. It fixes
`security_verdict` to `NOT_ASSESSED`, `applied_to_audit_bundle` to `false`, and
`core_evidence_provenance` to `WEB_HAR`.

The exporter opens the final path with create-new semantics. A path created by
another process after validation wins the race and is never replaced. The write
is deliberately not described as atomic; wait for the successful export status
before reading the file. A write failure can leave its newly created incomplete
file for the operator to inspect or remove, but the exporter never deletes or
replaces a path after another process wins creation.

Import the output through the ordinary offline HAR route:

```powershell
npm.cmd run audit:reverse -- web import-har `
  --har C:\reverse-output\sanitized-session.har `
  --origin https://app.example `
  --path-literal resources `
  --out C:\reverse-output\web-session-evidence.json
```

Burp's native **Save items** XML is a separate input. Import it with
`web import-burp`; that path records `BURP_XML` provenance.

## Verify

The source invariant test needs only Node.js:

```powershell
node --test integrations/burp-montoya/test/extension.test.mjs
```

The full local conformance builds the extension, runs a mock Montoya export,
and imports its sanitized HAR through the core web evidence pipeline:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File integrations\burp-montoya\verify.ps1 `
  -MontoyaApiJar C:\tools\montoya-api.jar
```

The extension does not alter or delete Burp history. Its sanitized output is
still protocol metadata: unusual header, cookie, field, or reviewed route names
can be sensitive, so inspect the file before sharing it.
