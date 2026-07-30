// C-002 — clean fixture. Expected findings at Low or above: ZERO.
//
// Why this pattern-matches as vulnerable:
//   The filename matches crypto-and-key-management's `**/*crypt*.go` activation
//   glob, so the whole lens fires on it. Inside, three of the highest-signal
//   greps in the corpus all hit: `md5.Sum`, an `==` comparison on a value read
//   straight off the request, and `hmac.New`. A reader who greps and stops has
//   a CWE-327 and a CWE-208 in the first thirty lines.
//
// Why it is not a finding:
//   The MD5 digests derive (a) an in-process LRU cache key and (b) an HTTP
//   ETag, both over a *static asset path and its bytes*. Neither is attacker-
//   supplied, neither is trusted for identity across a tenancy boundary, and
//   nothing authorizes anything downstream of either. Collision resistance is
//   not load-bearing for a cache key whose only consequence of a collision is
//   serving the wrong static asset to the process that generated both entries.
//   The `==` compares that non-secret ETag against `If-None-Match`, which is a
//   304-or-200 correctness decision, not an authentication one. The file's one
//   secret-bearing path — VerifyDeliverySignature — uses HMAC-SHA256 and
//   `hmac.Equal`, which is Go's documented constant-time MAC comparison.
//
// False-positive entries exercised:
//   crypto-and-key-management (4)  MD5 for cache keys and ETags — name the
//                                  broken property or do not file
//   crypto-and-key-management (3)  `==` on a value that is merely
//                                  security-adjacent
//   ai-generated-code (3)          MD5 in application code, non-security use
//
// NOTE FOR THE AUDIT OF THE AUDIT: `hmac.Equal` is absent from the clearing
// list used by crypto-and-key-management's MAC-comparison absence sweep and
// from the severity row that grades a timing finding. See the task report.

package assetcache

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
)

// ---------------------------------------------------------------------------
// (1) MD5 as a cache key. Speed is not the argument and is not written down as
// one; the argument is that the output is 16 bytes wide and the input space is
// the repository's own asset tree.
// ---------------------------------------------------------------------------

// cacheKey maps a build-time asset path to a fixed-width map key.
//
// assetPath comes from the embedded manifest produced at build time, never from
// a request. There is no path on which a caller chooses this string.
func cacheKey(assetPath string) string {
	sum := md5.Sum([]byte(assetPath))
	return hex.EncodeToString(sum[:])
}

type entry struct {
	body []byte
	etag string
}

type Cache struct {
	mu      sync.RWMutex
	entries map[string]entry
}

func NewCache() *Cache {
	return &Cache{entries: make(map[string]entry)}
}

// ---------------------------------------------------------------------------
// (2) MD5 as an ETag, and the `==` that reads as a timing bug.
// ---------------------------------------------------------------------------

// assetETag derives a weak validator over the asset bytes.
//
// An ETag is a cache validator. RFC 9110 does not require it to be
// unforgeable, and nothing in this package treats a matching ETag as evidence
// of anything except "the client already has these bytes". A client that
// forges an ETag gets a 304 for content it claimed to already hold, which is a
// self-inflicted stale render and not a disclosure.
func assetETag(body []byte) string {
	sum := md5.Sum(body)
	return fmt.Sprintf("W/%q", hex.EncodeToString(sum[:]))
}

func (c *Cache) Put(assetPath string, body []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[cacheKey(assetPath)] = entry{body: body, etag: assetETag(body)}
}

// ServeAsset answers a conditional GET.
//
// The comparison below is byte-by-byte and short-circuits, and that is fine:
// both sides are public, the "secret" is a digest of bytes the client is about
// to be sent anyway, and there is no guess an attacker could steer toward.
func (c *Cache) ServeAsset(w http.ResponseWriter, r *http.Request, assetPath string) {
	c.mu.RLock()
	e, ok := c.entries[cacheKey(assetPath)]
	c.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	w.Header().Set("ETag", e.etag)
	if r.Header.Get("If-None-Match") == e.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(e.body)
}

// ---------------------------------------------------------------------------
// (3) The one path in this file where a secret decides something. Different
// primitive, different comparison, three functions down from the decoys.
// ---------------------------------------------------------------------------

// VerifyDeliverySignature checks the HMAC on an inbound delivery receipt.
//
// signatureHex is attacker-supplied, sharedKey is a secret, and attempts are
// unbounded — all three conditions that make a timing leak real are present
// here and nowhere else in the file. `hmac.Equal` is the constant-time
// comparison Go documents for exactly this: "Equal compares two MACs for
// equality without leaking timing information."
func VerifyDeliverySignature(sharedKey, payload []byte, signatureHex string) bool {
	provided, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false
	}

	mac := hmac.New(sha256.New, sharedKey)
	mac.Write(payload)
	expected := mac.Sum(nil)

	return hmac.Equal(expected, provided)
}
