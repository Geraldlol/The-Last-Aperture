// V-007 — VULNERABLE fixture. NOT RUNNABLE. Written from scratch.
//
// Bug class (exactly one): server-side request forgery — a caller-supplied
// destination is fetched by the server, and the validation in front of it does
// not exclude link-local, loopback or carrier-grade-NAT space, so the cloud
// instance-metadata service is reachable.
// Lens: web-and-api / topic `ssrf-application-path`
// Expected: Critical, CWE-918
//
// Three separate reasons the guard does not hold, all visible in one function:
//   1. The deny-list is hand-written and names only RFC 1918 space. Link-local
//      (169.254/16, where every major cloud parks its metadata service) and
//      CGNAT (100.64/10) are absent.
//   2. It is a check on the HOSTNAME, applied before the fetch resolves the name.
//      A name that resolves to link-local space passes the string test, and a name
//      that resolves twice — once for the check, once for the fetch — passes it
//      even when it should not.
//   3. Redirects are followed with the default policy, so a permitted host can
//      hand the fetch a Location the check never saw.
//
// NOT RUNNABLE and carries no payload. There is no app.listen, no route
// registration, no attacker-controlled URL literal, and no metadata address
// written anywhere in the file — the addresses above appear only as CIDR prose in
// this header, which is documentation, not a request.

'use strict'

const { URL } = require('node:url')

// The whole guard. A prefix test on the textual host.
const BLOCKED_PREFIXES = ['10.', '192.168.', '172.16.', '127.']

function looksInternal(hostname) {
  if (hostname === 'localhost') return true
  return BLOCKED_PREFIXES.some((prefix) => hostname.startsWith(prefix))
}

/**
 * Fetch a caller-supplied page and return the fields a link card renders.
 * `req.body.url` arrives from an authenticated but otherwise untrusted caller.
 */
async function previewHandler(req, res) {
  let target
  try {
    target = new URL(String(req.body.url ?? ''))
  } catch {
    return res.status(400).json({ error: 'not a url' })
  }

  if (target.protocol !== 'http:' && target.protocol !== 'https:') {
    return res.status(400).json({ error: 'unsupported scheme' })
  }

  // Validated here...
  if (looksInternal(target.hostname)) {
    return res.status(400).json({ error: 'internal destination' })
  }

  // ...and resolved again, separately, here. Nothing carries the address the
  // check approved into the request the runtime actually makes, and nothing
  // constrains where a redirect may lead.
  const upstream = await fetch(target.toString(), {
    headers: { 'user-agent': 'link-preview' },
  })

  const body = await upstream.text()
  return res.json({
    status: upstream.status,
    title: extractTitle(body),
    // The response body is handed back to the caller, which turns any reachable
    // internal endpoint into a read primitive rather than a blind one.
    excerpt: body.slice(0, 512),
  })
}

function extractTitle(html) {
  const match = /<title[^>]*>([^<]*)<\/title>/i.exec(html)
  return match ? match[1].trim() : null
}

module.exports = { previewHandler, looksInternal }
