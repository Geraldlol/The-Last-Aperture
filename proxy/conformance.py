"""Runs the shared scope-kernel fixtures against the Python implementation.

Emits one JSON object so the Node conformance test can compare decisions without
parsing prose. Exit 0 when every case matches, 1 otherwise.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from bounty_helpers import compose_user_agent  # noqa: E402
from bounty_scope_kernel import decide_scope  # noqa: E402

FIXTURE_DIR = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "bounty"
FIXTURES = FIXTURE_DIR / "scope-kernel-cases.json"
USER_AGENT_FIXTURES = FIXTURE_DIR / "user-agent-cases.json"


def user_agent_suite() -> dict:
    """The identifying marker is the second boundary both languages implement.

    Reported under its own key so the scope-kernel contract this file already
    emits stays byte-compatible for the Node test that reads it.
    """
    suite = json.loads(USER_AGENT_FIXTURES.read_text(encoding="utf-8"))
    results = []
    mismatches = []
    for case in suite["cases"]:
        actual = compose_user_agent(case["captured"], case["marker"])
        entry = {
            "case_id": case["case_id"],
            "composed": actual,
            "expected": case["expect"],
            "matches": actual == case["expect"],
        }
        results.append(entry)
        if not entry["matches"]:
            mismatches.append(entry)
    return {
        "total": len(results),
        "matched": len(results) - len(mismatches),
        "mismatches": mismatches,
        "results": results,
    }


def main() -> int:
    suite = json.loads(FIXTURES.read_text(encoding="utf-8"))
    scope = suite["scope"]
    results = []
    mismatches = []
    for case in suite["cases"]:
        actual = decide_scope(scope, case["candidate"])
        entry = {
            "case_id": case["case_id"],
            "decision": actual["decision"],
            "reason": actual["reason"],
            "expected_decision": case["expect"],
            "expected_reason": case["expect_reason"],
        }
        entry["matches"] = (
            actual["decision"] == case["expect"] and actual["reason"] == case["expect_reason"]
        )
        results.append(entry)
        if not entry["matches"]:
            mismatches.append(entry)

    user_agent = user_agent_suite()

    print(
        json.dumps(
            {
                "implementation": "python",
                "total": len(results),
                "matched": len(results) - len(mismatches),
                "mismatches": mismatches,
                "results": results,
                "user_agent": user_agent,
            }
        )
    )
    return 0 if not mismatches and not user_agent["mismatches"] else 1


if __name__ == "__main__":
    sys.exit(main())
