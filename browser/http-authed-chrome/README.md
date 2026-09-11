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

Application-managed bearer sessions are a separate shape. This bridge does not
inspect `localStorage`/`sessionStorage` or patch page request libraries to obtain
an `Authorization` value added by application JavaScript. Such a site requires a
separately reviewed, contract-bound page adapter.

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

While a session is open, the polling loop periodically touches session storage
to keep the worker active; the recovery marker lets a restarted worker detect
unfinished work. Restart recovery is fail closed:
the worker attempts to abort any surviving injected fetch, clears the marker,
and requires a new controller pairing. It does not send a stored capability to
an old loopback port or replay a prepared/committed action.
