"""Require explicit branch measurement and preserve the project's 80% minimum for both dimensions."""

import argparse
import json
from pathlib import Path


def validate(report: dict) -> tuple[float, float]:
    totals = report["totals"]
    if totals.get("num_branches", 0) <= 0:
        raise ValueError("Coverage report contains no measured branches; run pytest --cov-branch")
    lines = totals["percent_statements_covered"]
    branches = totals["covered_branches"] / totals["num_branches"] * 100
    if lines < 80 or branches < 80:
        raise ValueError(f"Coverage below 80%: lines={lines:.2f}%, branches={branches:.2f}%")
    return lines, branches


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", nargs="?", default="coverage.json", type=Path)
    args = parser.parse_args()
    try:
        lines, branches = validate(json.loads(args.report.read_text()))
    except (ValueError, KeyError) as exc:
        raise SystemExit(str(exc)) from None
    print(f"Coverage passed: lines={lines:.2f}%, branches={branches:.2f}%")


if __name__ == "__main__":
    main()
