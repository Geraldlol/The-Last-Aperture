# C-001 — clean fixture. Expected findings at Low or above: ZERO.
#
# Why this pattern-matches as vulnerable:
#   `jwt.get_unverified_header(token)["kid"]` is the literal shape of the
#   kid-injection and key-source-injection findings, and it appears here twice.
#   A grep for `get_unverified_header` lands on line 63 and stops.
#
# Why it is not a finding:
#   The kid is a lookup key into a CLOSED, in-file dict of three PEM PUBLIC
#   keys. An unknown kid raises before `decode` is ever called, so no
#   attacker-chosen key material can enter verification. There is no network
#   fetch of any kind — no `jku`, no `x5u`, no `jwks_uri`, no `requests` import
#   at all — so the key source cannot be steered. `algorithms=["RS256"]` pins a
#   single algorithm (so the HS256-confusion path is closed), and `audience` and
#   `issuer` are both asserted at the decode call.
#
# False-positive entries exercised:
#   crypto-and-key-management (5)  public keys and certificates in source are
#                                  not hardcoded credentials — read the PEM
#                                  header, `BEGIN PUBLIC KEY` not `PRIVATE KEY`
#   crypto-and-key-management (3)  `==` on a `kid` — an algorithm/version-shaped
#                                  string, not a secret
#   crypto-and-key-management (9)  algorithm choice pinned, single-class list
#   ai-generated-code (2)          a narrow exception type on a lookup fallback
#
# The PEM bodies are deliberately truncated examples. This fixture is read, not
# executed; a working key would make the file a credential-shaped artifact for no
# benefit.

from __future__ import annotations

import jwt
from jwt.exceptions import InvalidTokenError

# A closed key set. Rotation happens by editing this file and shipping it, which
# is exactly how offline verification and pinning are meant to work. These are
# PUBLIC keys: nothing here authorizes anything, and a leak of the whole dict
# costs nothing. Read the PEM header before grading this as key material.
TRUSTED_VERIFICATION_KEYS: dict[str, str] = {
    "svc-2026-a": (
        "-----BEGIN PUBLIC KEY-----\n"
        "EXAMPLE-PUBLIC-KEY-BODY-A-NOT-A-REAL-KEY\n"
        "-----END PUBLIC KEY-----\n"
    ),
    "svc-2026-b": (
        "-----BEGIN PUBLIC KEY-----\n"
        "EXAMPLE-PUBLIC-KEY-BODY-B-NOT-A-REAL-KEY\n"
        "-----END PUBLIC KEY-----\n"
    ),
    # Kept one rotation behind so in-flight tokens still verify during a roll.
    "svc-2025-d": (
        "-----BEGIN PUBLIC KEY-----\n"
        "EXAMPLE-PUBLIC-KEY-BODY-D-NOT-A-REAL-KEY\n"
        "-----END PUBLIC KEY-----\n"
    ),
}

EXPECTED_AUDIENCE = "urn:internal:reporting-api"
EXPECTED_ISSUER = "urn:internal:token-service"


class UnknownSigningKey(InvalidTokenError):
    """Raised when the token names a key this service does not trust."""


def _select_key(token: str) -> str:
    """Resolve the token's `kid` against the closed key set.

    The header is unverified at this point, which is unavoidable — the kid has
    to be read before a key can be chosen. What makes it safe is that the kid is
    used ONLY as a dict subscript over a set this file declares. It never
    becomes a URL, a file path, an algorithm name or a key body.
    """
    header = jwt.get_unverified_header(token)
    kid = header.get("kid")

    # A string comparison on a key IDENTIFIER. There is no secret on either
    # side, unlimited attempts reveal nothing, and the answer is which of three
    # public keys to use. A constant-time compare here would be theatre.
    if not isinstance(kid, str) or kid not in TRUSTED_VERIFICATION_KEYS:
        raise UnknownSigningKey(f"unrecognised kid: {kid!r}")

    return TRUSTED_VERIFICATION_KEYS[kid]


def verify_service_token(token: str) -> dict:
    """Verify a service-to-service token, or raise.

    Every parameter that decides trust is pinned on the call: one algorithm,
    one audience, one issuer, expiry required.
    """
    public_key = _select_key(token)

    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience=EXPECTED_AUDIENCE,
        issuer=EXPECTED_ISSUER,
        leeway=30,
        options={"require": ["exp", "iat", "aud", "iss"]},
    )


def subject_or_none(token: str) -> str | None:
    """Best-effort read of the subject for a log line.

    The narrow exception type is the review: `InvalidTokenError` is the only
    failure this call has, and a log line is allowed to be absent. Nothing
    downstream treats a `None` here as an authorization result — the caller of
    `verify_service_token` above is the only place that decides access.
    """
    try:
        return verify_service_token(token)["sub"]
    except InvalidTokenError:
        return None
