"""Python port of the bounty-v1 scope kernel.

The Node implementation in scripts/lib/bounty-scope-kernel.mjs is the reference.
This file must produce an identical decision and reason for every case in
fixtures/bounty/scope-kernel-cases.json, which proxy/conformance.py asserts.

Two implementations of a security boundary are only safe when a machine proves
they agree, so nothing here is written from memory of the Node behaviour: the
fixtures decide.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit, unquote

SCOPE_ALLOW = "ALLOW"
SCOPE_DENY = "DENY"

_ALLOWED_SCHEMES = frozenset({"http", "https"})
_DEFAULT_PORTS = {"http": 80, "https": 443}
_MAX_CANDIDATE_LENGTH = 4096

_METADATA_HOSTS = frozenset(
    {
        "169.254.169.254",
        "100.100.100.200",
        "metadata.google.internal",
        "metadata",
    }
)

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def _refuse(reason: str):
    return {"ok": False, "reason": reason}


def _remove_dot_segments(path: str) -> str:
    """RFC 3986 section 5.2.4.

    Implemented explicitly rather than with posixpath.normpath, which collapses
    a trailing slash and treats a leading '//' specially -- both of which would
    diverge from the WHATWG normalisation the Node side performs.
    """
    output: list[str] = []
    segments = path.split("/")
    for index, segment in enumerate(segments):
        if segment == ".":
            if index == len(segments) - 1:
                output.append("")
            continue
        if segment == "..":
            if len(output) > 1:
                output.pop()
            if index == len(segments) - 1:
                output.append("")
            continue
        output.append(segment)
    normalised = "/".join(output)
    if not normalised.startswith("/"):
        normalised = "/" + normalised.lstrip("/")
    return normalised or "/"


def _normalise_host(hostname: str):
    host = hostname.lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    if host.endswith("."):
        host = host[:-1]
        if host.endswith("."):
            return None
    if not host:
        return None
    # Match the WHATWG URL parser, which stores an internationalised host as
    # punycode. A decision must not depend on which spelling reached us.
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError:
            return None
    return host


def _host_kind(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "domain"
    return "ipv4" if address.version == 4 else "ipv6"


def canonicalize_candidate(raw_url):
    try:
        if not isinstance(raw_url, str) or not raw_url:
            return _refuse("candidate-not-a-string")
        if len(raw_url) > _MAX_CANDIDATE_LENGTH:
            return _refuse("candidate-too-long")
        try:
            parts = urlsplit(raw_url)
        except ValueError:
            return _refuse("candidate-unparsable")
        if parts.scheme not in _ALLOWED_SCHEMES:
            return _refuse("scheme-not-http")
        if parts.username or parts.password:
            return _refuse("candidate-carries-userinfo")
        if not parts.hostname:
            return _refuse("candidate-unparsable")
        host = _normalise_host(parts.hostname)
        if host is None:
            return _refuse("host-not-canonicalizable")
        try:
            port = parts.port
        except ValueError:
            return _refuse("port-not-valid")
        if port is None:
            port = _DEFAULT_PORTS[parts.scheme]
        if not isinstance(port, int) or port < 1 or port > 65535:
            return _refuse("port-not-valid")
        path = _remove_dot_segments(unquote(parts.path) or "/")
        return {
            "ok": True,
            "target": {
                "scheme": f"{parts.scheme}:",
                "host": host,
                "port": port,
                "path": path,
                "hostKind": _host_kind(host),
            },
        }
    except Exception:  # noqa: BLE001 - any failure must fail closed
        return _refuse("candidate-canonicalization-failed")


def _is_private_target(target) -> bool:
    """Mirrors the Node reference's explicit ranges, deliberately NOT ipaddress.is_private.

    Python classes the RFC 5737 documentation ranges (192.0.2/24, 198.51.100/24,
    203.0.113/24) as private, so leaning on is_private denied 203.0.113.7 while
    the Node side allowed it as ordinary public space. The conformance fixtures
    caught that divergence; the ranges below are enumerated to match the
    reference exactly rather than approximately.
    """
    host = target["host"]
    if host in _METADATA_HOSTS:
        return True
    if target["hostKind"] == "domain":
        return host == "localhost"

    if target["hostKind"] == "ipv6":
        return (
            host in {"::1", "::"}
            or host.startswith("fe80:")
            or host.startswith("fc")
            or host.startswith("fd")
        )

    if not _IPV4_RE.match(host):
        return True
    octets = [int(part) for part in host.split(".")]
    if any(octet > 255 for octet in octets):
        return True
    first, second = octets[0], octets[1]
    if first in (0, 10, 127):
        return True
    if first == 172 and 16 <= second <= 31:
        return True
    if first == 192 and second == 168:
        return True
    if first == 169 and second == 254:
        return True
    if first == 100 and 64 <= second <= 127:
        return True
    return False


def _host_matches(rule, target) -> bool:
    kind = rule.get("host_kind")
    rule_host = rule.get("host")
    if not isinstance(rule_host, str):
        raise TypeError("rule host must be a string")
    if kind == "ip":
        return target["hostKind"] != "domain" and target["host"] == rule_host
    if target["hostKind"] != "domain":
        return False
    if kind == "exact":
        return target["host"] == rule_host
    if kind == "wildcard":
        # A wildcard covers subdomains and NOT the apex, which must be listed
        # separately. The most common scope error in the field.
        return target["host"] != rule_host and target["host"].endswith("." + rule_host)
    return False


def _port_matches(rule, target) -> bool:
    ports = rule.get("ports")
    if not isinstance(ports, list):
        ports = [80, 443]
    return target["port"] in ports


def _path_matches(rule, target) -> bool:
    prefix = rule.get("path_prefix")
    if not isinstance(prefix, str) or not prefix:
        return True
    if prefix.endswith("/"):
        prefix = prefix[:-1]
    return target["path"] == prefix or target["path"].startswith(prefix + "/")


def _rule_matches(rule, target) -> bool:
    if not isinstance(rule, dict):
        return False
    return _host_matches(rule, target) and _port_matches(rule, target) and _path_matches(rule, target)


def _rule_id(rule) -> str:
    value = rule.get("rule_id") if isinstance(rule, dict) else None
    return value if isinstance(value, str) else "unnamed-rule"


def decide_scope(sealed_scope, raw_candidate):
    try:
        rules = (sealed_scope or {}).get("scope_rules")
        if not isinstance(rules, dict):
            return {"decision": SCOPE_DENY, "rule_id": "none", "reason": "sealed-scope-not-usable"}
        if not isinstance(rules.get("allow"), list) or not isinstance(rules.get("deny"), list):
            return {"decision": SCOPE_DENY, "rule_id": "none", "reason": "sealed-scope-not-usable"}

        canonical = canonicalize_candidate(raw_candidate)
        if not canonical["ok"]:
            return {"decision": SCOPE_DENY, "rule_id": "none", "reason": canonical["reason"]}
        target = canonical["target"]

        for rule in rules["deny"]:
            if _rule_matches(rule, target):
                return {"decision": SCOPE_DENY, "rule_id": _rule_id(rule), "reason": "explicit-deny-rule"}

        if _is_private_target(target) and rules.get("private_targets_sealed") is not True:
            return {"decision": SCOPE_DENY, "rule_id": "none", "reason": "private-target-not-sealed"}

        for rule in rules["allow"]:
            if _rule_matches(rule, target):
                return {"decision": SCOPE_ALLOW, "rule_id": _rule_id(rule), "reason": "allow-rule-matched"}

        return {"decision": SCOPE_DENY, "rule_id": "none", "reason": "candidate-unlisted"}
    except Exception:  # noqa: BLE001 - any failure must fail closed
        return {"decision": SCOPE_DENY, "rule_id": "none", "reason": "kernel-error"}
