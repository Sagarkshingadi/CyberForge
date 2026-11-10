"""
detector.py — Three rule-based detection rules applied to events.csv.

Person B owns this module.

CRITICAL: This module must NEVER import, open, or read labels.csv.
          It operates solely on events.csv.

Matching rule (used by the evaluator to decide whether an alert caught an attack):
  An alert counts as catching an attack if:
    1. The alert's user_id matches the attacked user_id in the labels.
    2. The alert's time window (earliest to latest event timestamp in
       the alert's event_ids list) overlaps the attack scenario's time window.
  This rule is stated here and must be reproduced in the report.
"""

import csv
import sys
from datetime import timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import schema


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_detector(
    events_path: Path,
    alerts_path: Path,
    with_rule4: bool = False,
) -> list[dict]:
    """
    Apply detection rules to events.csv and write alerts.csv.

    Args:
        events_path: Path to events.csv. labels.csv is NEVER opened.
        alerts_path: Path to write the resulting alerts.csv.
        with_rule4:  If True, includes Rule 4 (aggregated slow failures).
                     Default is False (baseline 3 rules).

    Returns:
        List of alert dicts (same rows as written to alerts.csv).
    """
    import pandas as pd

    df = pd.read_csv(events_path)
    schema.validate_columns(df, schema.EVENTS_COLUMNS)

    # Parse timestamps into datetime objects for arithmetic.
    # Keep the original string column intact for writing.
    df["_ts"] = df["timestamp"].apply(schema.parse_timestamp)
    df = df.sort_values("_ts").reset_index(drop=True)

    alerts: list[dict] = []
    # Collect rule outputs (without alert_id assigned yet)
    alerts += _rule1(df)
    alerts += _rule2(df)
    alerts += _rule3(df)
    if with_rule4:
        alerts += _rule4(df)

    # Sort alerts chronologically by timestamp, then by rule_id and user_id for stable ordering.
    alerts.sort(key=lambda a: (a["timestamp"], a["rule_id"], a["user_id"]))

    # Assign sequential alert_ids strictly AFTER sorting
    for idx, a in enumerate(alerts, 1):
        a["alert_id"] = f"A{idx:06d}"

    # Write alerts.csv.
    alerts_path = Path(alerts_path)
    alerts_path.parent.mkdir(parents=True, exist_ok=True)
    with open(alerts_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=schema.ALERTS_COLUMNS)
        writer.writeheader()
        writer.writerows(alerts)

    return alerts


# ---------------------------------------------------------------------------
# Rule 1 — Brute-force burst
# ---------------------------------------------------------------------------

def _rule1(df) -> list[dict]:
    """
    Rule 1: brute-force burst.

    Fires when a single user accumulates >= RULE1_FAIL_COUNT failed
    login_attempts within a sliding window of RULE1_WINDOW_MINUTES minutes.

    Implementation: for each failure event, count how many other failures by
    the same user fall within [ts, ts + window].  Emit one alert per burst
    (deduplicated on the first event in the window).
    """
    alerts     = []
    fired_keys = set()   # (user_id, first_eid_in_burst) — prevents duplicate alerts

    failures = df[
        (df["event_type"] == "login_attempt") & (df["success"] == False)
    ].copy()

    window    = timedelta(minutes=schema.RULE1_WINDOW_MINUTES)
    threshold = schema.RULE1_FAIL_COUNT

    for uid, grp in failures.groupby("user_id"):
        timestamps = grp["_ts"].tolist()
        event_ids  = grp["event_id"].tolist()

        for i, (ts_i, _) in enumerate(zip(timestamps, event_ids)):
            # Collect all failures within [ts_i, ts_i + window].
            burst_eids = [
                eid_j
                for ts_j, eid_j in zip(timestamps, event_ids)
                if timedelta(0) <= (ts_j - ts_i) <= window
            ]

            if len(burst_eids) >= threshold:
                key = (uid, burst_eids[0])
                if key not in fired_keys:
                    fired_keys.add(key)
                    alerts.append({
                        "alert_id":  "",  # assigned after sorting
                        "rule_id":   "RULE1",
                        "user_id":   uid,
                        "timestamp": schema.format_timestamp(ts_i),
                        "event_ids": ";".join(burst_eids),
                        "note": (
                            f"Rule 1: {len(burst_eids)} failed logins for "
                            f"'{uid}' within {schema.RULE1_WINDOW_MINUTES} min. "
                            "Warrants investigation — does not confirm attack."
                        ),
                    })

    return alerts


# ---------------------------------------------------------------------------
# Rule 2 — Success after failures
# ---------------------------------------------------------------------------

def _rule2(df) -> list[dict]:
    """
    Rule 2: successful login within RULE2_WINDOW_MINUTES of >= RULE2_FAIL_COUNT
    prior failed login_attempts by the same user.

    Implementation: for each successful login, look back up to window minutes
    and count prior failures.  Emit one alert per triggering success event.

    Note: this rule intentionally fires on the 'forgetful' normal user when
    their failures and success happen to cluster inside 10 minutes.  That false
    positive is an intentional hard-normal-case to study.
    """
    alerts   = []
    fired    = set()   # (user_id, success_event_id)

    attempts = df[df["event_type"] == "login_attempt"].copy()
    window   = timedelta(minutes=schema.RULE2_WINDOW_MINUTES)
    thresh   = schema.RULE2_FAIL_COUNT

    for uid, grp in attempts.groupby("user_id"):
        grp      = grp.sort_values("_ts").reset_index(drop=True)
        successes = grp[grp["success"] == True]

        for _, row in successes.iterrows():
            ts_s = row["_ts"]
            prior_fails = grp[
                (grp["success"] == False) &
                (grp["_ts"] <= ts_s) &
                (grp["_ts"] >= ts_s - window)
            ]

            if len(prior_fails) >= thresh:
                key = (uid, row["event_id"])
                if key not in fired:
                    fired.add(key)
                    all_eids = list(prior_fails["event_id"]) + [row["event_id"]]
                    alerts.append({
                        "alert_id":  "",  # assigned after sorting
                        "rule_id":   "RULE2",
                        "user_id":   uid,
                        "timestamp": schema.format_timestamp(ts_s),
                        "event_ids": ";".join(all_eids),
                        "note": (
                            f"Rule 2: {len(prior_fails)} failures then success "
                            f"for '{uid}' within {schema.RULE2_WINDOW_MINUTES} min. "
                            "Warrants investigation — does not confirm attack."
                        ),
                    })

    return alerts


# ---------------------------------------------------------------------------
# Rule 3 — Account/privilege change after successful login
# ---------------------------------------------------------------------------

def _rule3(df) -> list[dict]:
    """
    Rule 3: an account_change or privilege_change within RULE3_WINDOW_MINUTES
    of a successful login_attempt by the same user.

    Implementation: for each change event, scan backwards up to window minutes
    for a prior successful login by the same user.

    Note: legitimate admin users (normal_admin scenario) will trigger this rule.
    Those false positives are the reason the severity_based policy uses
    'verify' (not 'lock') for Rule 3 alerts.
    """
    alerts = []
    fired  = set()   # (user_id, change_event_id)

    changes   = df[df["event_type"].isin({"account_change", "privilege_change"})].copy()
    successes = df[
        (df["event_type"] == "login_attempt") & (df["success"] == True)
    ].copy()

    window = timedelta(minutes=schema.RULE3_WINDOW_MINUTES)

    for uid in sorted(changes["user_id"].unique()):
        u_changes   = changes[changes["user_id"] == uid]
        u_successes = successes[successes["user_id"] == uid]

        for _, chg in u_changes.iterrows():
            ts_c = chg["_ts"]
            prior_succ = u_successes[
                (u_successes["_ts"] <= ts_c) &
                (u_successes["_ts"] >= ts_c - window)
            ]

            if not prior_succ.empty:
                key = (uid, chg["event_id"])
                if key not in fired:
                    fired.add(key)
                    all_eids = list(prior_succ["event_id"]) + [chg["event_id"]]
                    alerts.append({
                        "alert_id":  "",  # assigned after sorting
                        "rule_id":   "RULE3",
                        "user_id":   uid,
                        "timestamp": schema.format_timestamp(ts_c),
                        "event_ids": ";".join(all_eids),
                        "note": (
                            f"Rule 3: {chg['event_type']} for '{uid}' within "
                            f"{schema.RULE3_WINDOW_MINUTES} min of a successful login. "
                            "Warrants investigation — does not confirm attack."
                        ),
                    })

    return alerts


# ---------------------------------------------------------------------------
# Rule 4 — Slow brute-force / Aggregated failures (Optional Gap Closure)
# ---------------------------------------------------------------------------

def _rule4(df) -> list[dict]:
    """
    Rule 4: aggregated slow failures / brute force.

    Rule 4 fires once per user per 60-minute window that contains 4 or more new
    failures, where a failure already included in an earlier Rule 4 alert is not new.
    """
    alerts = []

    failures = df[
        (df["event_type"] == "login_attempt") & (df["success"] == False)
    ].copy()

    window    = timedelta(minutes=60)
    threshold = 4

    for uid in sorted(failures["user_id"].unique()):
        grp = failures[failures["user_id"] == uid]
        timestamps = grp["_ts"].tolist()
        event_ids  = grp["event_id"].tolist()
        alerted_eids = set()

        for i, (ts_i, eid_i) in enumerate(zip(timestamps, event_ids)):
            # If this failure was already included in an earlier alert, it is not new
            if eid_i in alerted_eids:
                continue

            # Look forward up to 60 minutes from ts_i for new failures
            new_failures = [
                eid_j
                for ts_j, eid_j in zip(timestamps, event_ids)
                if timedelta(0) <= (ts_j - ts_i) <= window and eid_j not in alerted_eids
            ]

            if len(new_failures) >= threshold:
                alerted_eids.update(new_failures)
                alerts.append({
                    "alert_id":  "",  # assigned after sorting
                    "rule_id":   "RULE4",
                    "user_id":   uid,
                    "timestamp": schema.format_timestamp(ts_i),
                    "event_ids": ";".join(new_failures),
                    "note": (
                        f"Rule 4: {len(new_failures)} failed logins for "
                        f"'{uid}' within 60 min. "
                        "Warrants investigation — possible slow brute force."
                    ),
                })

    return alerts


# ---------------------------------------------------------------------------
# CLI: python detector/detector.py <events.csv> <alerts.csv>
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _events  = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/generated/events.csv")
    _alerts  = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("data/generated/alerts.csv")
    result   = run_detector(_events, _alerts)
    print(f"Generated {len(result)} alerts → {_alerts}")

