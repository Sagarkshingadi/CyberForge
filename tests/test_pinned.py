import csv
import os
import subprocess
import sys
from collections import Counter
from pathlib import Path

from responder.responder import DEFAULT_COST_TABLE


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_responder_cost_table_is_pinned() -> None:
    assert DEFAULT_COST_TABLE == {
        ("monitor", True): 100,
        ("monitor", False): 0,
        ("verify", True): 20,
        ("verify", False): 5,
        ("lock", True): 10,
        ("lock", False): 50,
    }


def test_baseline_seed_42_pipeline_is_pinned(tmp_path: Path) -> None:
    output_dir = tmp_path / "baseline"
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"

    subprocess.run(
        [
            sys.executable,
            str(PROJECT_ROOT / "scripts" / "run_pipeline.py"),
            "--seed",
            "42",
            "--output-dir",
            str(output_dir),
        ],
        cwd=PROJECT_ROOT,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )

    run_dir = output_dir / "seed_42"
    with (run_dir / "alerts.csv").open(newline="", encoding="utf-8") as alerts_file:
        alerts = list(csv.DictReader(alerts_file))

    assert len(alerts) == 114
    assert Counter(alert["rule_id"] for alert in alerts) == {
        "RULE1": 22,
        "RULE2": 12,
        "RULE3": 80,
    }

    with (run_dir / "decisions.csv").open(newline="", encoding="utf-8") as decisions_file:
        decisions = list(csv.DictReader(decisions_file))

    severity_based_cost = sum(
        float(row["cost"])
        for row in decisions
        if row["policy"] == "severity_based"
    )
    assert severity_based_cost == 875.0
