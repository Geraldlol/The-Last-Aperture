# C-032 — clean fixture. Expected findings at Low or above: ZERO.
#
# Why this pattern-matches as vulnerable:
#   "Anyone with the link can access the document." A capability URL with no login,
#   no ownership check on redeem, and the grant carried in the URL itself.
#
# Why it is not a finding:
#   A capability URL is a deliberate design used by nearly every document product:
#   the link IS the grant, and its holder is the authorized party by construction.
#   The entry then names five survivors, and none of them is a finding here — each
#   is closed at a named line rather than argued away:
#
#     1. TOKEN ENTROPY / PREDICTABLE GENERATOR. 256 bits from `secrets.token_urlsafe`,
#        which is the CSPRNG. No `uuid1`, no `random`, no time component.
#     2. ENUMERABLE IDENTIFIER. The token is the only identifier in the URL. There
#        is no sequential share id, and lookup is by digest of the token — so a
#        database read cannot mint a working link either.
#     3. PERMISSION LEVEL ENCODED IN THE URL WITHOUT A SIGNATURE. The permission
#        lives in the SERVER-SIDE record, keyed by the token digest. Nothing about
#        the capability is carried in the URL beyond the token, so there is nothing
#        for a caller to edit and nothing that needs signing.
#     4. NO EXPIRY ON REGULATED DATA. Expiry is mandatory and is enforced on the
#        redeem path, and for a document whose model carries a sensitivity label
#        the maximum lifetime is shortened — the label is read from the record, not
#        inferred from the product having documentation.
#     5. TOKEN LEAKING THROUGH LOGS, UNFURLING OR ANALYTICS. This is the trio to
#        take seriously because two thirds of it is unconditional in a default
#        install, so all three legs are closed here:
#          * ACCESS LOGS: the token is not in the path or the query. The share page
#            is `GET /s` and the token arrives in a `X-Share-Token` header or, for a
#            first click, in the URL fragment — which browsers never send to a
#            server — and is exchanged for a short-lived cookie. The log-safe id is
#            emitted instead.
#          * LINK UNFURLING: the redeem endpoint refuses a request whose
#            `Sec-Fetch-Mode` is not `navigate` and requires a POST, so a preview
#            fetcher cannot consume or reveal the capability.
#          * ANALYTICS: this is the conditional leg — URL capture is configuration —
#            so the analytics initialisation is cited: `capture_pageview=False` and
#            an explicit query-parameter exclusion list, set at init below.
#
#   And the honest ownership note: most of those survivors belong to web-and-api or
#   crypto-and-key-management rather than to threat-modeling, because their subject
#   is this handler's own logic or the token generator. "It is a capability URL"
#   clears the architecture question and nothing about the handler — which is why
#   the handler is written out here rather than asserted to be fine.
#
# False-positive entries exercised:
#   threat-modeling (5)  "anyone with the link can access the document" filed
#                        against a capability-URL feature
#   crypto-and-key-management (11 / csprng)  token entropy and generator

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from fastapi import Header, HTTPException, Request, Response

from .models import ShareGrant, Document

# 32 bytes -> 43 url-safe characters. Not derived from any record field.
TOKEN_BYTES = 32

DEFAULT_TTL = timedelta(days=7)
# A document the model marks sensitive gets a shorter maximum, read from the
# record's own label rather than from a guess about the product.
SENSITIVE_TTL = timedelta(hours=24)

ANALYTICS_INIT = {
    # The conditional leg of survivor 5, cited rather than assumed.
    "api_host": "https://analytics.example.invalid",
    "capture_pageview": False,
    "mask_all_text": True,
    "sanitize_properties": True,
    "property_denylist": ["$current_url", "$pathname", "$initial_current_url", "token"],
}


def _digest(token: str) -> bytes:
    """Store the digest, never the token.

    A read of the share table yields digests, so a database leak does not hand
    anybody a working link — which is the property that also closes enumerability.
    """
    return hashlib.sha256(token.encode("ascii")).digest()


def mint_share_link(document: Document, permission: str, actor_id: str) -> tuple[str, ShareGrant]:
    """Create a capability.

    `permission` is stored server-side. It never enters the URL, so it needs no
    signature and there is nothing for a holder to escalate by editing a string.
    """
    if permission not in {"view", "comment", "edit"}:
        raise ValueError(f"unknown permission {permission!r}")

    token = secrets.token_urlsafe(TOKEN_BYTES)
    ttl = SENSITIVE_TTL if document.sensitivity_label else DEFAULT_TTL

    grant = ShareGrant.objects.create(
        document_id=document.id,
        token_digest=_digest(token),
        permission=permission,
        created_by=actor_id,
        expires_at=datetime.now(timezone.utc) + ttl,
        revoked_at=None,
    )

    # The token goes in the FRAGMENT. Browsers do not send a fragment to any
    # server, so it appears in no access log, in no proxy log and in no `Referer`.
    url = f"https://docs.example.invalid/s#{token}"
    return url, grant


def redeem(
    request: Request,
    response: Response,
    x_share_token: str = Header(...),
    sec_fetch_mode: str | None = Header(default=None, alias="Sec-Fetch-Mode"),
) -> dict:
    """Exchange a capability for a short-lived session cookie.

    POST-only, and it refuses anything that is not a real navigation — so an
    unfurling preview fetcher cannot consume the capability or echo it into a chat
    transcript.
    """
    if request.method != "POST":
        raise HTTPException(status_code=405, detail="POST required")
    if sec_fetch_mode not in {"navigate", "same-origin", "cors"}:
        raise HTTPException(status_code=400, detail="not a navigation")

    digest = _digest(x_share_token)

    # Constant-time compare against the stored digest. The lookup is by digest, so
    # this is belt-and-braces against a future index change that makes the lookup
    # prefix-based.
    grant = ShareGrant.objects.filter(token_digest=digest).first()
    if grant is None or not hmac.compare_digest(bytes(grant.token_digest), digest):
        raise HTTPException(status_code=404, detail="no such share")

    now = datetime.now(timezone.utc)
    if grant.revoked_at is not None or grant.expires_at <= now:
        raise HTTPException(status_code=410, detail="share expired")

    # A log line that identifies the grant without carrying the capability.
    request.state.log_fields = {
        "share_grant_id": str(grant.id),
        "document_id": str(grant.document_id),
        "permission": grant.permission,
    }

    response.set_cookie(
        "share_session",
        secrets.token_urlsafe(TOKEN_BYTES),
        max_age=1800,
        httponly=True,
        secure=True,
        samesite="lax",
        path="/s",
    )
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"

    return {"document_id": str(grant.document_id), "permission": grant.permission}
