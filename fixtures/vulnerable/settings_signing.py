# V-006 — VULNERABLE fixture. NOT RUNNABLE. Written from scratch.
#
# Bug class (exactly one): hardcoded credential — a signing secret supplied as a
# literal default that applies whenever the environment variable is unset.
# Lens: crypto-and-key-management / topic `hardcoded-credentials-and-key-material`
# Expected: High, CWE-798
#
# This is the shape the owning lens calls the sharpest form of the finding,
# because it deploys silently: nothing raises, nothing logs, the service starts,
# and every instance that missed the variable shares one key. Two consumers below
# make the consequence concrete — the same fallback key both seals a session
# cookie and signs a password-reset link.
#
# THE LITERALS BELOW ARE NOT CREDENTIALS AND CANNOT BE. Each is structurally
# invalid for its stated purpose: the signing key is 21 ASCII characters of the
# word "placeholder", not 32 bytes of key material; the base64 field is not valid
# base64; the provider-shaped string is deliberately the wrong length and the
# wrong character class for any real provider token, so no secret scanner should
# match it and no scanner-shaped string is being shipped. A corpus of real-looking
# secrets is a hazard in its own right — see fixtures/README.md.
#
# NOT RUNNABLE: no framework, no app object, no import of anything installed.

import base64
import hashlib
import hmac
import os

# --- the defect ---------------------------------------------------------------
# Two arguments. The second one is what ships when the variable is absent.
SESSION_SIGNING_KEY = os.environ.get("SESSION_SIGNING_KEY", "placeholder-not-a-key")

# Same defect wearing the base64 costume. `b64decode` on a non-base64 placeholder
# raises at import in some Python versions and silently truncates in others, which
# is why the fallback is worse than useless rather than merely weak.
RESET_SIGNING_KEY_B64 = os.environ.get("RESET_SIGNING_KEY_B64", "not-valid-base64==")

# Same defect on a third-party token. Structurally invalid on purpose: no real
# provider issues a token of this shape or length.
WEBHOOK_PROVIDER_TOKEN = os.environ.get("WEBHOOK_PROVIDER_TOKEN", "provider-token-goes-here")
# --- end of the defect --------------------------------------------------------


def _reset_key() -> bytes:
    try:
        return base64.b64decode(RESET_SIGNING_KEY_B64)
    except Exception:  # noqa: BLE001 - fixture: the failure mode is the point
        return b""


def sign_session(payload: bytes) -> str:
    """Consumer 1: seals the session cookie."""
    return hmac.new(SESSION_SIGNING_KEY.encode(), payload, hashlib.sha256).hexdigest()


def sign_reset_link(user_id: str, expires_at: int) -> str:
    """Consumer 2: signs a password-reset link.

    Same key material as the session cookie in every deployment that missed the
    variable, so a caller who learns one signing key mints the other artifact.
    """
    message = f"{user_id}:{expires_at}".encode()
    return hmac.new(_reset_key() or SESSION_SIGNING_KEY.encode(), message, hashlib.sha256).hexdigest()
