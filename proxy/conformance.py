"""Runs the shared scope-kernel fixtures against the Python implementation.

Emits one JSON object so the Node conformance test can compare decisions without
parsing prose. Exit 0 when every case matches, 1 otherwise.
"""

from __future__ import annotations

import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

from bounty_scope_kernel import decide_scope  # noqa: E402

FIXTURES = pathlib.Path(__file__).resolve().parent.parent / "fixtures" / "bounty" / "scope-kernel-cases.json"


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

    print(
        json.dumps(
            {
                "implementation": "python",
                "total": len(results),
                "matched": len(results) - len(mismatches),
                "mismatches": mismatches,
                "results": results,
            }
        )
    )
    return 0 if not mismatches else 1


if __name__ == "__main__":
    sys.exit(main())
