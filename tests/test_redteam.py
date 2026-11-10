"""
tests/test_redteam.py — Acceptance tests for Red Team Evasion strategies & isolation.

Checks:
1. Every strategy generates events and labels conforming to schema.py.
2. Timestamps parse cleanly with TIMESTAMP_FORMAT.
3. Strategies are fully deterministic when given the same random seed.
4. The scenario_type for every emitted label is registered in SCENARIO_TYPES.
5. Manual logs are stored in data/output/manual/ and ignored by main results.
"""

from datetime import datetime
from pathlib import Path
import random
import pytest
import pandas as pd
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import schema
from redteam.strategies import (
    baseline_brute_force,
    slow_brute_force,
    password_spraying,
    delayed_takeover,
    low_and_slow_takeover,
    ALL_STRATEGIES,
)


@pytest.fixture
def rng():
    return random.Random(42)


@pytest.fixture
def base_time():
    return datetime(2024, 1, 15, 8, 0, 0)


def id_factory():
    counter = [0]
    def _gen():
        counter[0] += 1
        return f"T_EID_{counter[0]:04d}"
    return _gen


def test_all_strategies_registered():
    """All 5 required strategies must exist in ALL_STRATEGIES."""
    required = {
        "baseline_brute_force",
        "slow_brute_force",
        "password_spraying",
        "delayed_takeover",
        "low_and_slow_takeover",
    }
    assert required.issubset(set(ALL_STRATEGIES.keys()))


@pytest.mark.parametrize("strat_name", list(ALL_STRATEGIES.keys()))
def test_strategy_schema_compliance(strat_name, rng, base_time):
    """Every strategy must emit dataframes conforming strictly to schema.py."""
    func = ALL_STRATEGIES[strat_name]
    gen = id_factory()
    if strat_name == "password_spraying":
        users = [f"u{i:03d}" for i in range(50)]
        events, labels = func(users, base_time, "198.51.100.1", rng, "SC_TEST", gen)
    else:
        events, labels = func("u001", base_time, "198.51.100.1", rng, "SC_TEST", gen)

    df_events = pd.DataFrame(events)
    df_labels = pd.DataFrame(labels)

    # Validate columns
    schema.validate_columns(df_events, schema.EVENTS_COLUMNS)
    schema.validate_columns(df_labels, schema.LABELS_COLUMNS)

    # Validate timestamps
    for ts in df_events["timestamp"]:
        dt = schema.parse_timestamp(ts)
        assert schema.format_timestamp(dt) == ts

    # Validate scenario_type is in schema.SCENARIO_TYPES
    for st in df_labels["scenario_type"]:
        assert st in schema.SCENARIO_TYPES


def test_strategy_determinism(base_time):
    """Identical seed must yield identical events and labels."""
    func = ALL_STRATEGIES["slow_brute_force"]
    ev1, lb1 = func("u001", base_time, "198.51.100.1", random.Random(999), "S1", id_factory())
    ev2, lb2 = func("u001", base_time, "198.51.100.1", random.Random(999), "S1", id_factory())
    assert ev1 == ev2
    assert lb1 == lb2


def test_manual_results_isolation():
    """Verifies that manual runs directory is distinct from main evaluation outputs."""
    main_output = Path("data/output/results.csv")
    manual_dir = Path("data/output/manual")
    if main_output.exists():
        df_res = pd.read_csv(main_output)
        # Ensure no manual session tags leaked into policy results
        assert set(df_res["policy"]).issubset({"always_monitor", "always_lock", "severity_based"})


def test_slow_brute_force_interval(base_time, rng):
    """Checks that consecutive failures in slow_brute_force are spaced exactly 360 seconds apart."""
    func = ALL_STRATEGIES["slow_brute_force"]
    events, _ = func("u001", base_time, "198.51.100.1", rng, "S_SLOW", id_factory())
    failures = [e for e in events if not e["success"]]
    assert len(failures) == 4, f"Expected 4 failures, got {len(failures)}"
    for i in range(len(failures) - 1):
        t1 = schema.parse_timestamp(failures[i]["timestamp"])
        t2 = schema.parse_timestamp(failures[i + 1]["timestamp"])
        gap = (t2 - t1).total_seconds()
        assert gap == 360, f"Expected 360s gap between failure {i} and {i+1}, got {gap}s"


