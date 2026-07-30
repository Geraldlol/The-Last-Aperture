// V-003 — VULNERABLE fixture. NOT RUNNABLE. Written from scratch.
//
// Bug class (exactly one): JWT signature verification that never constrains the
// algorithm — the key-resolution callback returns key material without
// inspecting what the token claims its signature is, and the parser is
// constructed with no allowlist option.
// Lens: crypto-and-key-management / topic `jwt-jws-and-jwks-verification`
// Expected: Critical, CWE-347
//
// The shape golang-jwt documents against: a callback is asked "what key verifies
// this token" and answers from configuration alone. Because the token's header
// chooses the family and nothing here rejects a choice, the verifier accepts
// whichever family the attacker names — including a symmetric signature computed
// over public key material in a deployment that expects an asymmetric one.
//
// NOTE for anyone editing this file: do not add the names of the golang-jwt
// method constants, even in a comment. The owning lens's absence sweep clears any
// file containing them, so a comment mentioning one would clear this fixture
// without changing the defect. That property is recorded in EXPECTED.md.
//
// There is no main(), no HTTP server, no listener, no key value, and no forged
// token anywhere in the file. It cannot run.

package session

import (
	"errors"
	"net/http"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

var signingSecret = []byte(os.Getenv("SESSION_SIGNING_SECRET"))

type Claims struct {
	Subject string `json:"sub"`
	Role    string `json:"role"`
	jwt.RegisteredClaims
}

// keyForToken is the defect. It receives the parsed token, which carries the
// header the sender wrote, and consults none of it. Whatever the header says the
// signature is, this function supplies the same key bytes and the parser
// verifies against them under the sender's chosen family.
func keyForToken(token *jwt.Token) (interface{}, error) {
	if len(signingSecret) == 0 {
		return nil, errors.New("session: signing secret not configured")
	}
	return signingSecret, nil
}

// ClaimsFromRequest parses with no algorithm allowlist. ParseWithClaims accepts
// parser options; none is passed, so nothing pins the permitted families.
func ClaimsFromRequest(r *http.Request) (*Claims, error) {
	raw := r.Header.Get("X-Session-Token")
	if raw == "" {
		return nil, errors.New("session: no token")
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(raw, claims, keyForToken)
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, errors.New("session: token not valid")
	}
	return claims, nil
}

// Authorize is the authorization decision the claims feed, named so the
// reachability question has an answer inside the fixture.
func Authorize(r *http.Request, wantRole string) bool {
	claims, err := ClaimsFromRequest(r)
	if err != nil {
		return false
	}
	return claims.Role == wantRole
}
