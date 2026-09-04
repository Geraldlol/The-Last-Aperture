"""Pure, offline helpers shared with the bounty fixture conformance test."""

from __future__ import annotations


def _is_field_separator(character):
    return character in (" ", "\t")


def _carries_marker_token(captured, marker):
    """Return true only when marker is bounded as a complete field token."""
    at = captured.find(marker)
    while at != -1:
        starts_token = at == 0 or _is_field_separator(captured[at - 1])
        end = at + len(marker)
        ends_token = end == len(captured) or _is_field_separator(captured[end])
        if starts_token and ends_token:
            return True
        at = captured.find(marker, at + 1)
    return False


def compose_user_agent(captured, marker):
    """Append one exact program marker without duplicating a complete token."""
    if not isinstance(captured, str) or captured.strip() == "":
        return marker
    if _carries_marker_token(captured, marker):
        return captured
    return f"{captured} {marker}"
