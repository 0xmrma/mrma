from __future__ import annotations

import argparse
import json
from pathlib import Path

CRITICAL_RUNTIME_FILES = (
    "mrma/engine/oracle.py",
    "mrma/engine/plan.py",
    "mrma/evidence/bundle.py",
    "mrma/evidence/journal.py",
    "mrma/evidence/models.py",
    "mrma/policy/authorization.py",
    "mrma/policy/budget.py",
    "mrma/policy/comparison.py",
    "mrma/policy/method_risk.py",
    "mrma/transport/semantic_http.py",
)
CORRECTED_CORE_FILES = (
    "mrma/core/compare.py",
    "mrma/core/experiment.py",
    "mrma/core/http_client.py",
    "mrma/core/http_semantics.py",
    "mrma/core/privacy.py",
    "mrma/core/sender.py",
)


def _normalized_files(document: dict[str, object]) -> dict[str, dict[str, object]]:
    files = document.get("files")
    if not isinstance(files, dict):
        raise ValueError("coverage JSON does not contain a files object")
    return {
        str(name).replace("\\", "/"): value
        for name, value in files.items()
        if isinstance(value, dict)
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("coverage_json", type=Path)
    parser.add_argument("--minimum", type=float, default=90.0)
    parser.add_argument("--core-minimum", type=float, default=85.0)
    args = parser.parse_args()
    document = json.loads(args.coverage_json.read_text(encoding="utf-8"))
    files = _normalized_files(document)
    failures: list[str] = []
    covered_total = 0
    possible_total = 0

    for name in CRITICAL_RUNTIME_FILES:
        if name not in files:
            failures.append(f"{name}: missing from coverage data")
            continue
        summary = files[name].get("summary")
        if not isinstance(summary, dict):
            failures.append(f"{name}: missing summary")
            continue
        covered = int(summary["covered_lines"]) + int(summary["covered_branches"])
        possible = int(summary["num_statements"]) + int(summary["num_branches"])
        percent = 100.0 * covered / possible if possible else 100.0
        covered_total += covered
        possible_total += possible
        print(f"{name}: {percent:.2f}% ({covered}/{possible})")
        if percent < args.minimum:
            failures.append(f"{name}: {percent:.2f}% is below {args.minimum:.2f}%")

    aggregate = 100.0 * covered_total / possible_total if possible_total else 0.0
    print(f"critical aggregate: {aggregate:.2f}% ({covered_total}/{possible_total})")
    if aggregate < args.minimum:
        failures.append(
            f"critical aggregate: {aggregate:.2f}% is below {args.minimum:.2f}%"
        )
    core_covered = 0
    core_possible = 0
    for name in CORRECTED_CORE_FILES:
        if name not in files:
            failures.append(f"{name}: missing from coverage data")
            continue
        summary = files[name].get("summary")
        if not isinstance(summary, dict):
            failures.append(f"{name}: missing summary")
            continue
        core_covered += int(summary["covered_lines"]) + int(
            summary["covered_branches"]
        )
        core_possible += int(summary["num_statements"]) + int(
            summary["num_branches"]
        )
    core_percent = 100.0 * core_covered / core_possible if core_possible else 0.0
    print(
        f"corrected core aggregate: {core_percent:.2f}% "
        f"({core_covered}/{core_possible})"
    )
    if core_percent < args.core_minimum:
        failures.append(
            f"corrected core aggregate: {core_percent:.2f}% is below "
            f"{args.core_minimum:.2f}%"
        )
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
