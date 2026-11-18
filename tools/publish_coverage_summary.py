"""Write statement and branch coverage into a GitHub Actions run summary."""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def render_summary(report: dict, platform: str) -> str:
    totals = report["totals"]
    rows = [
        f"## Python coverage — {platform}",
        "",
        "| Measure | Covered | Total | Coverage |",
        "|---|---:|---:|---:|",
        (
            f"| Statements | {totals['covered_lines']:,} | {totals['num_statements']:,} "
            f"| {totals['percent_statements_covered']:.2f}% |"
        ),
        (
            f"| Branch outcomes | {totals['covered_branches']:,} | {totals['num_branches']:,} "
            f"| {totals['percent_branches_covered']:.2f}% |"
        ),
        "",
        (
            f"Partially covered branch points: **{totals['num_partial_branches']:,}**; "
            f"uncovered branch outcomes: **{totals['missing_branches']:,}**."
        ),
        "",
        "### Module coverage",
        "",
        "| Module | Statements | Branches |",
        "|---|---:|---:|",
    ]
    files = sorted(
        report["files"].items(),
        key=lambda item: (
            item[1]["summary"].get("percent_branches_covered", 100),
            item[0],
        ),
    )
    for filename, details in files:
        summary = details["summary"]
        display_name = filename.replace("|", "\\|")
        statement = f"{summary['percent_statements_covered']:.2f}%"
        branches_total = summary["num_branches"]
        branches = (
            f"{summary['percent_branches_covered']:.2f}% "
            f"({summary['covered_branches']}/{branches_total})"
            if branches_total
            else "—"
        )
        rows.append(
            f"| `{display_name}` | {statement} "
            f"({summary['covered_lines']}/{summary['num_statements']}) | {branches} |"
        )
    rows.extend(
        [
            "",
            "The **Artifacts** section contains the detailed HTML line and branch report.",
            "",
        ]
    )
    return "\n".join(rows)


def main() -> int:
    report_path = Path("coverage.json")
    if not report_path.is_file():
        print("coverage.json was not produced; skipping the coverage summary.")
        return 0
    report = json.loads(report_path.read_text(encoding="utf-8"))
    summary = render_summary(report, os.environ.get("RUNNER_OS", "local"))
    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with Path(summary_path).open("a", encoding="utf-8") as output:
            output.write(summary)
    else:
        print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main())
