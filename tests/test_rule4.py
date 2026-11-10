"""
tests/test_rule4.py — Unit tests for Rule 4 exact specification:
"Rule 4 fires once per user per 60-minute window that contains 4 or more new
failures, where a failure already included in an earlier Rule 4 alert is not new."
"""

from pathlib import Path
import pandas as pd
import pytest
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import schema
from detector.detector import _rule4


def test_rule4_two_disjoint_bursts_give_two_alerts():
    """
    Requirement (a): Two disjoint bursts give two alerts.
    Burst 1 at 09:00-09:03 (4 failures).
    Burst 2 at 11:00-11:03 (4 failures, disjoint by >60 min).
    """
    events = [
        # Burst 1
        {"event_id": "E1", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:00:00"},
        {"event_id": "E2", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:01:00"},
        {"event_id": "E3", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:02:00"},
        {"event_id": "E4", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:03:00"},
        # Burst 2 (>60m disjoint)
        {"event_id": "E5", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T11:00:00"},
        {"event_id": "E6", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T11:01:00"},
        {"event_id": "E7", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T11:02:00"},
        {"event_id": "E8", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T11:03:00"},
    ]

    df = pd.DataFrame(events)
    df["_ts"] = df["timestamp"].apply(schema.parse_timestamp)

    alerts = _rule4(df)

    assert len(alerts) == 2, f"Expected 2 alerts for disjoint bursts, got {len(alerts)}"
    assert alerts[0]["timestamp"] == "2024-01-15T09:00:00"
    assert alerts[0]["event_ids"] == "E1;E2;E3;E4"
    assert alerts[1]["timestamp"] == "2024-01-15T11:00:00"
    assert alerts[1]["event_ids"] == "E5;E6;E7;E8"


def test_rule4_failures_spanning_within_single_60m_window():
    """
    Requirement (b): Failures at 09:00, 09:01, 09:02, 09:30, 09:31, 09:32, 09:33.
    Expected: Exactly 1 alert at 09:00:00 containing all 7 new failures (E1;E2;E3;E4;E5;E6;E7)
    because all 7 fall within the 60-minute window [09:00, 10:00] and are new.
    """
    events = [
        {"event_id": "E1", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:00:00"},
        {"event_id": "E2", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:01:00"},
        {"event_id": "E3", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:02:00"},
        {"event_id": "E4", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:30:00"},
        {"event_id": "E5", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:31:00"},
        {"event_id": "E6", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:32:00"},
        {"event_id": "E7", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:33:00"},
    ]

    df = pd.DataFrame(events)
    df["_ts"] = df["timestamp"].apply(schema.parse_timestamp)

    alerts = _rule4(df)

    assert len(alerts) == 1, f"Expected 1 alert for failures within 33m span, got {len(alerts)}"
    assert alerts[0]["timestamp"] == "2024-01-15T09:00:00"
    assert alerts[0]["event_ids"] == "E1;E2;E3;E4;E5;E6;E7"


def test_rule4_shared_events_only_count_new_failures():
    """
    Requirement (c): A burst that shares events with an earlier alert only counts its new failures.
    Burst 1 (08:30 to 09:00): E1, E2, E3, E4 -> Alert 1 has E1..E4.
    Later window starting at E4 (09:00) reaches up to 10:00.
    - If 3 new failures occur (E5..E7 at 09:40-09:42), total failures in [09:00, 10:00] is 4 (E4..E7),
      but only 3 are new. Thus, no second alert is fired.
    - If a 4th new failure occurs (E8 at 09:43), total new failures in the window is 4.
      A second alert fires containing ONLY the new failures (E5;E6;E7;E8), excluding E4.
    """
    base_events = [
        {"event_id": "E1", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T08:30:00"},
        {"event_id": "E2", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T08:35:00"},
        {"event_id": "E3", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T08:40:00"},
        {"event_id": "E4", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:00:00"},
        {"event_id": "E5", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:40:00"},
        {"event_id": "E6", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:41:00"},
        {"event_id": "E7", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:42:00"},
    ]

    # Part 1: Only 3 new failures alongside previously alerted E4 -> 0 additional alerts
    df_3 = pd.DataFrame(base_events)
    df_3["_ts"] = df_3["timestamp"].apply(schema.parse_timestamp)
    alerts_3 = _rule4(df_3)
    assert len(alerts_3) == 1, f"Expected 1 alert (only 3 new failures), got {len(alerts_3)}"
    assert alerts_3[0]["event_ids"] == "E1;E2;E3;E4"

    # Part 2: 4 new failures alongside previously alerted E4 -> second alert with only new events
    events_with_e8 = base_events + [
        {"event_id": "E8", "user_id": "u1", "event_type": "login_attempt", "success": False, "timestamp": "2024-01-15T09:43:00"}
    ]
    df_4 = pd.DataFrame(events_with_e8)
    df_4["_ts"] = df_4["timestamp"].apply(schema.parse_timestamp)
    alerts_4 = _rule4(df_4)

    assert len(alerts_4) == 2, f"Expected 2 alerts (4 new failures reached), got {len(alerts_4)}"
    assert alerts_4[0]["event_ids"] == "E1;E2;E3;E4"
    assert alerts_4[1]["event_ids"] == "E5;E6;E7;E8"
    assert alerts_4[1]["timestamp"] == "2024-01-15T09:40:00"
    assert "E4" not in alerts_4[1]["event_ids"], "Second alert must contain only new failures"
