from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_coverage_summary_writes_statement_and_branch_rates_to_github_summary(tmp_path):
    report = {
        "totals": {
            "covered_lines": 8,
            "num_statements": 10,
            "percent_statements_covered": 80.0,
            "covered_branches": 6,
            "num_branches": 8,
            "percent_branches_covered": 75.0,
            "num_partial_branches": 2,
            "missing_branches": 2,
        },
        "files": {
            "src/example.py": {
                "summary": {
                    "covered_lines": 8,
                    "num_statements": 10,
                    "percent_statements_covered": 80.0,
                    "covered_branches": 6,
                    "num_branches": 8,
                    "percent_branches_covered": 75.0,
                }
            }
        },
    }
    (tmp_path / "coverage.json").write_text(json.dumps(report), encoding="utf-8")
    summary_path = tmp_path / "github-summary.md"
    environment = os.environ.copy()
    environment["GITHUB_STEP_SUMMARY"] = str(summary_path)
    environment["RUNNER_OS"] = "Linux"

    result = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "publish_coverage_summary.py")],
        cwd=tmp_path,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    markdown = summary_path.read_text(encoding="utf-8")
    assert "Python coverage — Linux" in markdown
    assert "80.00%" in markdown
    assert "75.00% (6/8)" in markdown
    assert "uncovered branch outcomes: **2**" in markdown
    assert "`src/example.py`" in markdown
