"""mitmproxy addon: enforce the sealed bounty perimeter and capture flows.

Load with:
    mitmdump -s proxy/bounty_addon.py --set bounty_scope=<bundle>/scope.json \
             --set bounty_flows=<bundle>/flows.jsonl

Every request is decided by the same kernel the Node side uses, proven identical
by proxy/conformance.py. A denied request is BLOCKED and logged rather than
merely noted -- a proxy that observes an out-of-scope request after forwarding it
has already caused the thing the perimeter exists to prevent.

Flows are appended as canonical JSONL. The Node side ingests them
(scripts/lib/bounty-proxy-ingest.mjs); nothing here writes to a database, so
there is no cross-language locking and the raw capture stays replayable.
"""

from __future__ import annotations

import json
import pathlib
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from bounty_scope_kernel import SCOPE_ALLOW, decide_scope  # noqa: E402

try:  # mitmproxy is only present when the addon is actually loaded
    from mitmproxy import ctx, http
except ImportError:  # pragma: no cover - importable for unit checks without mitmproxy
    ctx = None
    http = None

MAX_BODY_BYTES = 512 * 1024

# Never persisted. A capture file is shared, attached to reports, and committed.
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
        "x-xsrf-token",
        "x-session-token",
    }
)


def redact_headers(headers):
    kept = {}
    redacted = []
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in SENSITIVE_HEADERS:
            redacted.append(lowered)
            continue
        kept[lowered] = value
    return kept, redacted


def truncate(body: bytes):
    if body is None:
        return "", False
    if len(body) <= MAX_BODY_BYTES:
        return body.decode("utf-8", errors="replace"), False
    return body[:MAX_BODY_BYTES].decode("utf-8", errors="replace"), True


class BountyPerimeter:
    def __init__(self) -> None:
        self.scope = None
        self.flows_path = None
        self.allowed = 0
        self.blocked = 0

    def load(self, loader) -> None:
        loader.add_option("bounty_scope", str, "", "Path to the sealed bounty scope.json")
        loader.add_option("bounty_flows", str, "", "Path to append captured flows as JSONL")

    def configure(self, updates) -> None:
        if "bounty_scope" in updates and ctx.options.bounty_scope:
            self.scope = json.loads(pathlib.Path(ctx.options.bounty_scope).read_text(encoding="utf-8"))
            rules = self.scope.get("scope_rules", {})
            ctx.log.info(
                "bounty perimeter loaded: "
                f"{len(rules.get('allow', []))} allow, {len(rules.get('deny', []))} deny"
            )
        if "bounty_flows" in updates and ctx.options.bounty_flows:
            self.flows_path = pathlib.Path(ctx.options.bounty_flows)
            self.flows_path.parent.mkdir(parents=True, exist_ok=True)

    def request(self, flow) -> None:
        # Fail closed on a missing scope. An unconfigured proxy must not become a
        # permissive one.
        if self.scope is None:
            self.blocked += 1
            flow.response = http.Response.make(
                403,
                b"bounty perimeter not configured; refusing to forward\n",
                {"Content-Type": "text/plain"},
            )
            return

        decision = decide_scope(self.scope, flow.request.pretty_url)
        if decision["decision"] != SCOPE_ALLOW:
            self.blocked += 1
            ctx.log.warn(
                f"BLOCKED {flow.request.method} {flow.request.pretty_url} "
                f"reason={decision['reason']} rule={decision['rule_id']}"
            )
            # Blocked before forwarding, not observed after.
            flow.response = http.Response.make(
                403,
                json.dumps(
                    {
                        "blocked_by": "red-team-audit/bounty-v1",
                        "reason": decision["reason"],
                        "rule_id": decision["rule_id"],
                    }
                ).encode("utf-8"),
                {"Content-Type": "application/json"},
            )
            self._append(flow, decision, forwarded=False)
            return
        self.allowed += 1

    def response(self, flow) -> None:
        if self.scope is None:
            return
        decision = decide_scope(self.scope, flow.request.pretty_url)
        if decision["decision"] != SCOPE_ALLOW:
            return
        self._append(flow, decision, forwarded=True)

    def _append(self, flow, decision, forwarded: bool) -> None:
        if self.flows_path is None:
            return
        request_headers, request_redacted = redact_headers(flow.request.headers)
        request_body, request_truncated = truncate(flow.request.content)
        record = {
            "kind": "red-team-audit/bounty-flow",
            "schema_version": "1.0.0",
            "observed_at": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
            "forwarded": forwarded,
            "scope_decision": decision["decision"],
            "scope_reason": decision["reason"],
            "scope_rule_id": decision["rule_id"],
            "request": {
                "method": flow.request.method,
                "url": flow.request.pretty_url,
                "headers": request_headers,
                "redacted_headers": request_redacted,
                "body": request_body,
                "body_truncated": request_truncated,
            },
            "response": None,
        }
        if forwarded and flow.response is not None:
            response_headers, response_redacted = redact_headers(flow.response.headers)
            response_body, response_truncated = truncate(flow.response.content)
            record["response"] = {
                "status": flow.response.status_code,
                "headers": response_headers,
                "redacted_headers": response_redacted,
                "body": response_body,
                "body_truncated": response_truncated,
            }
        with self.flows_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")

    def done(self) -> None:
        if ctx is not None:
            ctx.log.info(f"bounty perimeter: {self.allowed} allowed, {self.blocked} blocked")


addons = [BountyPerimeter()]
