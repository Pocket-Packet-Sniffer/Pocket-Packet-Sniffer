from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_pipeline_benchmark_reports_real_replay_accounting_and_refuses_session_reuse(tmp_path):
    storage = tmp_path / "benchmark-captures"
    command = [
        sys.executable,
        "tools/benchmark_pipeline.py",
        "--repeats",
        "2",
        "--storage-dir",
        str(storage),
        "--session-id",
        "benchmark-test",
    ]
    environment = os.environ.copy()
    existing_pythonpath = environment.get("PYTHONPATH")
    environment["PYTHONPATH"] = os.pathsep.join(
        value for value in ("src", existing_pythonpath) if value
    )

    result = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert "input_packets=10" in result.stdout
    assert "seen=10" in result.stdout
    assert "stored=10" in result.stdout
    assert "ignored_or_unsupported=0" in result.stdout
    assert "not live network capture" in result.stdout

    second = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )
    assert second.returncode == 2
    assert "already contains packets" in second.stderr
