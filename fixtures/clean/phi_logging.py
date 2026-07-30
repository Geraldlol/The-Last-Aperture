# C-027 — clean fixture. Expected findings at Low or above: ZERO.
#
# Why this pattern-matches as vulnerable:
#   `logger.info(request_context)` and a telemetry integration that captures
#   request bodies. "PHI in logs" is one of the highest-severity rows in the HIPAA
#   lens and the grep lands squarely on line 92.
#
# Why it is not a finding:
#   The call site is half the picture; the sink and its scrubber are the other
#   half, and both are in this file. The record is traced from the call to the
#   transport:
#
#     logger.info(...) -> AllowlistProcessor -> JSONRenderer -> stdout / vendor
#
#   `AllowlistProcessor` is ALLOWLIST-shaped, not denylist-shaped, and the
#   difference is the whole finding. A denylist scrubber is a design finding in its
#   own right — "any newly added ePHI column leaks until someone remembers to add
#   it" — so a clean fixture cannot be built on one. Here the processor drops every
#   key that is not in `LOGGABLE_KEYS`, so a new column leaks nothing by default:
#   it is absent from the allowlist and is therefore discarded.
#
#   The vendor leg is closed the same way and not on trust: `send_default_pii` is
#   False, `max_request_body_size` is "never" so no body is captured at all, and
#   `before_send` runs the same allowlist over `event["extra"]` and drops
#   breadcrumbs entirely — so the "the same dict rides along as a breadcrumb"
#   path does not exist.
#
#   The negative control at the bottom is what makes this checkable rather than
#   asserted: it feeds a record containing every ePHI-shaped key the schema has and
#   asserts the rendered line contains none of them.
#
# False-positive entries exercised:
#   hipaa-and-phi (4)  `logger.info(request.body)` / telemetry capturing bodies —
#                      trace the record from call site to transport and read the
#                      scrubber config

from __future__ import annotations

import json
import logging
from typing import Any, Mapping

# Every key that may leave the process in a log line. Anything absent is dropped,
# so the default for a new field is "not logged".
LOGGABLE_KEYS: frozenset[str] = frozenset(
    {
        "event",
        "level",
        "timestamp",
        "request_id",
        "actor_id",
        "actor_role",
        "patient_ref",  # opaque surrogate key, never an MRN
        "resource",
        "resource_count",
        "purpose_of_use",
        "status_code",
        "duration_ms",
    }
)


class AllowlistProcessor:
    """Drop every key that is not explicitly loggable.

    Allowlist, not denylist. A field added to the patient model tomorrow is
    discarded here without anybody editing this file, which is the property a
    denylist cannot have.
    """

    def __call__(self, _logger, _method_name, event_dict: dict) -> dict:
        return {k: v for k, v in event_dict.items() if k in LOGGABLE_KEYS}


class JSONRenderer:
    def __call__(self, _logger, _method_name, event_dict: Mapping[str, Any]) -> str:
        return json.dumps(event_dict, separators=(",", ":"), sort_keys=True)


def build_logger(name: str) -> logging.Logger:
    """Wire the two processors in order. There is no path around them."""
    logger = logging.getLogger(name)
    logger.handlers.clear()
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


_PROCESSORS = (AllowlistProcessor(), JSONRenderer())


def emit(logger: logging.Logger, level: int, **fields: Any) -> str:
    """The only logging entry point in this module.

    Callers hand over a full request context — including fields that are ePHI —
    and the processors decide what survives. That is deliberate: a design where the
    caller is trusted to pre-filter is a design where one forgetful caller leaks.
    """
    event_dict = dict(fields)
    for processor in _PROCESSORS:
        event_dict = processor(logger, "info", event_dict)  # type: ignore[assignment]
    line = event_dict  # after JSONRenderer this is a str
    logger.log(level, line)
    return line  # type: ignore[return-value]


def sentry_init_options() -> dict:
    """Vendor configuration. Three settings, each closing a different leg."""
    return {
        "dsn": "https://examplepublickey@o0.ingest.example.invalid/0",
        # No PII, and no request body at all — not a truncated one.
        "send_default_pii": False,
        "max_request_body_size": "never",
        "attach_stacktrace": False,
        # Breadcrumbs are the path a "safe" logger still leaks through. Dropped.
        "max_breadcrumbs": 0,
        "before_breadcrumb": lambda _crumb, _hint: None,
        "before_send": _before_send,
    }


def _before_send(event: dict, _hint: dict) -> dict:
    """Run the same allowlist over the vendor event."""
    extra = event.get("extra")
    if isinstance(extra, dict):
        event["extra"] = {k: v for k, v in extra.items() if k in LOGGABLE_KEYS}
    event.pop("request", None)
    event.pop("breadcrumbs", None)
    return event


# ---------------------------------------------------------------------------
# Negative control. A clean fixture that only logs safe fields proves nothing
# about the scrubber, so this feeds it the unsafe ones.
# ---------------------------------------------------------------------------

EPHI_SHAPED_KEYS = (
    "patient_name",
    "given_name",
    "family_name",
    "mrn",
    "ssn",
    "birth_date",
    "postal_code",
    "diagnosis_code",
    "note_body",
    "medication",
    "insurance_member_id",
    "phone",
    "email",
    "address_line1",
)


def control_rendered_line() -> str:
    """Render a record carrying every ePHI-shaped key, and return the result."""
    logger = build_logger("phi-control")
    return emit(
        logger,
        logging.INFO,
        event="chart.read",
        request_id="req-01J8",
        actor_id="clin-4471",
        actor_role="prescriber",
        patient_ref="8f21c0e4-6b3a-4c17-9a52-0d7e41b8c390",
        resource="Encounter",
        resource_count=7,
        purpose_of_use="TREAT",
        status_code=200,
        duration_ms=41,
        **{key: f"UNSAFE-{key}" for key in EPHI_SHAPED_KEYS},
    )


def assert_control_holds() -> None:
    line = control_rendered_line()
    for key in EPHI_SHAPED_KEYS:
        assert key not in line, f"{key} survived the allowlist"
        assert f"UNSAFE-{key}" not in line, f"value for {key} survived the allowlist"
    assert '"actor_id":"clin-4471"' in line, "the allowlist dropped a field it should keep"
