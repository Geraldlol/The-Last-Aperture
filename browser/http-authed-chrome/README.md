# The Last Aperture Browser Bridge

This Manifest V3 extension runs a sealed authenticated campaign action in the
operator-selected Chrome tab. Fetch applies ambient browser-managed credentials
such as same-origin cookies, HTTP authentication, and client certificates. The
extension does not read or export those request credential values, page storage,
request history, or profile data. Response bodies and the discovery-compatible
`Allow`, `Content-Encoding`, `Content-Type`, `Link`, and `Location` response
values cross the loopback bridge transiently for bounded observation.
The injected fetch runs in Chrome's extension-isolated world so target-page
JavaScript cannot replace its fetch implementation or its protocol state.

By default the bridge does not inspect `localStorage`/`sessionStorage` or patch
page request libraries. An optional declarative page-session adapter covers the
common application-managed bearer shape without adding target code to the
extension.

## Load the bridge

Use Chrome 110 or newer so extension API activity refreshes the Manifest V3
worker lifetime while a campaign is open.

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Choose **Load unpacked** and select this directory.
4. Pin **The Last Aperture Browser Bridge** and copy the extension ID shown in
   its popup.

Create the authenticated scope with `--credential-browser` and that exact
`--browser-extension-id`. When `http-authed campaign-attested` starts, it prints
the loopback controller port and a one-time pairing capability.

Chrome Manifest V3 worker fetch can omit the `Origin` header. The loopback
controller accepts that originless shape only when
`x-last-aperture-extension` contains the configured extension ID and the exact
Fetch Metadata tuple is `Sec-Fetch-Site: none`, `Sec-Fetch-Mode: cors`, and
`Sec-Fetch-Dest: empty`. Requests with an unexpected origin, extension ID, or
Fetch Metadata value are refused.

## Page-managed sessions

When an application keeps a short-lived string in Web Storage and adds it to a
request header, create a local adapter document such as:

```json
{
  "schema_version": "1.0.0",
  "kind": "last-aperture/page-session-adapter",
  "adapter_id": "synthetic-application-session",
  "source": {
    "type": "WEB_STORAGE",
    "area": "LOCAL",
    "key": "application.session",
    "extraction": { "mode": "RAW" }
  },
  "carrier": {
    "type": "REQUEST_HEADER",
    "name": "authorization",
    "prefix": "Bearer "
  },
  "target_constraints": [
    {
      "origin": "https://app.example",
      "method": "GET",
      "path_prefix": "/api"
    }
  ],
  "validity": {
    "not_before": "2026-09-11T00:00:00.000Z",
    "not_after": "2026-09-12T00:00:00.000Z"
  },
  "limits": { "max_value_bytes": 4096 }
}
```

Use `area: SESSION` for `sessionStorage`. If the stored value is JSON, replace
the extraction with a strict RFC 6901 selector such as
`{ "mode": "JSON_POINTER", "pointer": "/auth/access~1token" }`; the selected
value must be a string. The format accepts no script, selector language,
transformation, wildcard origin, or wildcard path. It supports one lower-case
request-header carrier and rejects cookie, browser-controlled, method-override,
forwarding, rewrite, and proxy-routing headers before fetch.

Seal the document while planning. Add these options to the normal
`plan-attested` command and its target, authorization, scope, and request
arguments:

```powershell
npm.cmd run audit:http-authed -- plan-attested `
  <target-and-attestation-options> `
  --credential-browser `
  --browser-extension-id <32-character-extension-id> `
  --page-session-adapter C:\trusted\page-session-adapter.json
```

The adapter's origins, methods, path prefixes, and validity must stay within and
cover the sealed scope and requests. Its digest is bound through prepare, ready,
commit, and result. For each dispatch, the isolated injected function reads the
exact storage key, bounds the selected string, applies the declared prefix and
header, performs fetch, and drops the value. The value never crosses into the
service worker, loopback controller, campaign ledger, retained evidence, or
logs.

## Attach a campaign

1. Open the exact target origin in Chrome and complete its normal login.
2. Keep that target tab active and open the extension popup.
3. Enter the printed controller port and one-time pairing capability.
4. Review the target origin and campaign digest returned by the controller.
5. Choose **Attach active tab** and leave the tab open until the campaign ends.

The first pairing requests optional access to `http://127.0.0.1/*`. The bridge
uses it only to exchange the campaign protocol with the local controller. Its
declared permissions are `activeTab`, `scripting`, and `storage`; it has no
persistent target-host, cookie, debugger, tabs, or web-request permission.
`storage` is used only for a `chrome.storage.session` recovery marker restricted
to trusted extension contexts. That extension-owned marker contains the public
campaign/tab/document binding and phase, but no pairing code, controller session
capability, target credential, request, or response value.

Every request is bound to the extension ID, controller pairing, campaign,
target origin, selected tab, current document, and action digest. Navigation or
document replacement invalidates that binding. The controller rechecks scope,
authorization, ledger state, and stop state immediately before each send.

Maintainer validation on 2026-09-11 loaded and enabled this unpacked v0.13.0
extension in official Chrome for Testing 153.0.8010.36 with its real Manifest V3
worker and popup. Originless controller binding, preview, and tab attach passed.
A full synthetic page-adapter campaign completed one action with zero failed,
rejected, or uncertain actions and seven ledger records; the synthetic server
observed one authorized request and no unauthorized request. The page-session
value remained browser-side. The live run required and verified the extension
identity/Fetch Metadata binding, popup keepalive, controlled injection-error
envelope, and omitted-null scripting-serialization handling.

While a session is open, the polling loop periodically touches session storage
to keep the worker active; the recovery marker lets a restarted worker detect
unfinished work. Restart recovery is fail closed:
the worker attempts to abort any surviving injected fetch, clears the marker,
and requires a new controller pairing. It does not send a stored capability to
an old loopback port or replay a prepared/committed action.
