"""
schema.py — Single source of truth for CyberForge Lite.

Every module must import column names, allowed values, timestamp format,
and rule thresholds from here. Never hardcode these strings elsewhere.
Changing a name here propagates automatically to all modules.
"""

import pandas as pd
from datetime import datetime

# ---------------------------------------------------------------------------
# Timestamp format (ISO 8601, UTC, no timezone suffix in stored strings)
# ---------------------------------------------------------------------------
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S"


def parse_timestamp(ts: str) -> datetime:
    """Parse an ISO 8601 timestamp string into a datetime object."""
    return datetime.strptime(ts, TIMESTAMP_FORMAT)


def format_timestamp(dt: datetime) -> str:
    """Format a datetime object as an ISO 8601 string."""
    return dt.strftime(TIMESTAMP_FORMAT)


# ---------------------------------------------------------------------------
# Allowed values for categorical fields
# ---------------------------------------------------------------------------
EVENT_TYPES = {"login_attempt", "account_change", "privilege_change"}

SOURCES = {"office", "home", "vpn", "unknown"}

ACTIONS = {"monitor", "verify", "lock"}

SCENARIO_TYPES = {
    # Main simulation scenarios
    "brute_force",
    "compromise",
    "suspicious_change",
    "normal_forgetful",
    "normal_vpn",
    "normal_admin",
    "normal_baseline",
    # Red Team evasion testing strategies (Addendum 2)
    "baseline_brute_force",
    "slow_brute_force",
    "password_spraying",
    "delayed_takeover",
    "low_and_slow_takeover",
}

# ---------------------------------------------------------------------------
# Column names (one list per CSV file)
# ---------------------------------------------------------------------------
EVENTS_COLUMNS = [
    "event_id",
    "timestamp",
    "user_id",
    "event_type",
    "success",
    "ip_address",
    "source",
]

LABELS_COLUMNS = [
    "event_id",
    "scenario_id",
    "scenario_type",
    "is_attack",
]

ALERTS_COLUMNS = [
    "alert_id",
    "rule_id",
    "user_id",
    "timestamp",
    "event_ids",   # semicolon-separated list of event_id values
    "note",
]

DECISIONS_COLUMNS = [
    "alert_id",
    "policy",
    "action",
    "cost",
]

RESULTS_COLUMNS = [
    "seed",
    "policy",
    "attacks_stopped",
    "normal_users_disrupted",
    "total_cost",
]

# ---------------------------------------------------------------------------
# Detection rule thresholds (all teams use these; never hardcode elsewhere)
# ---------------------------------------------------------------------------
# Rule 1: brute-force burst
RULE1_FAIL_COUNT = 5          # minimum failed login_attempts …
RULE1_WINDOW_MINUTES = 5      # … within this many minutes

# Rule 2: success after failures (possible compromise entry)
RULE2_FAIL_COUNT = 3          # minimum prior failures …
RULE2_WINDOW_MINUTES = 10     # … within this many minutes before the success

# Rule 3: account change after successful login
RULE3_WINDOW_MINUTES = 30     # account_change within this many minutes of a success


# ---------------------------------------------------------------------------
# Column validation helper
# ---------------------------------------------------------------------------
def validate_columns(df: pd.DataFrame, expected: list[str]) -> None:
    """
    Raise ValueError if df does not have exactly the expected columns
    (order-insensitive). Provides a clear diff to ease debugging.
    """
    actual = set(df.columns)
    expected_set = set(expected)
    missing = expected_set - actual
    extra = actual - expected_set
    if missing or extra:
        parts = []
        if missing:
            parts.append(f"missing columns: {sorted(missing)}")
        if extra:
            parts.append(f"unexpected columns: {sorted(extra)}")
        raise ValueError("Column mismatch — " + "; ".join(parts))

