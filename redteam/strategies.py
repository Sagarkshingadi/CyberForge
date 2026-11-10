"""
redteam/strategies.py — Scripted Red Team Evasion Strategies (Addendum 2).

Implements 5 fixed, seeded evasion strategies designed to probe the limits
of the defender's three rules.

Each strategy is a standalone function with clear parameters and docstring:
1. baseline_brute_force: Fast burst (control group, caught by R1 and R2).
2. slow_brute_force: 4 failures every 6 min (targets R1's 5-minute threshold).
3. password_spraying: 1 failure across 50 users (targets R1's per-user threshold).
4. delayed_takeover: 6 failures, wait 15 min, then succeed (targets R2's 10-minute window).
5. low_and_slow_takeover: 2 failures every 8 min for 40 min, success, account change at +20 min
   (targets all three windows).

Rules for strategies:
- Every event emitted has an accompanying label with scenario_type = strategy_name.
- Randomness is strictly controlled by the seeded rng passed in.
- Functions are compact and easy to explain in a viva.
"""

from datetime import datetime, timedelta
import random
import schema


def baseline_brute_force(
    user_id: str,
    start_time: datetime,
    attacker_ip: str,
    rng: random.Random,
    scenario_id: str,
    id_generator,
) -> tuple[list[dict], list[dict]]:
    """
    Control strategy: 8 rapid failures in 2 minutes, followed by 1 success.
    
    Target: Baseline control group.
    Expected: Should be caught by both Rule 1 (>=5 fails in 5 min)
    and Rule 2 (success within 10 min of >=3 failures).
    """
    events, labels = [], []
    # 8 failures spaced 15 seconds apart = 105 seconds (< 2 minutes)
    for i in range(8):
        ts = start_time + timedelta(seconds=i * 15 + rng.randint(0, 3))
        eid = id_generator()
        events.append({
            "event_id": eid, "timestamp": schema.format_timestamp(ts),
            "user_id": user_id, "event_type": "login_attempt",
            "success": False, "ip_address": attacker_ip, "source": "unknown"
        })
        labels.append({
            "event_id": eid, "scenario_id": scenario_id,
            "scenario_type": "baseline_brute_force", "is_attack": True
        })

    # Success right after the 8th failure (at ~2 minutes)
    succ_ts = start_time + timedelta(seconds=125)
    succ_eid = id_generator()
    events.append({
        "event_id": succ_eid, "timestamp": schema.format_timestamp(succ_ts),
        "user_id": user_id, "event_type": "login_attempt",
        "success": True, "ip_address": attacker_ip, "source": "unknown"
    })
    labels.append({
        "event_id": succ_eid, "scenario_id": scenario_id,
        "scenario_type": "baseline_brute_force", "is_attack": True
    })
    return events, labels


def slow_brute_force(
    user_id: str,
    start_time: datetime,
    attacker_ip: str,
    rng: random.Random,
    scenario_id: str,
    id_generator,
) -> tuple[list[dict], list[dict]]:
    """
    Slow brute force: 4 failed logins every 6 minutes, then a success.
    
    Target: Evade Rule 1 (which requires >=5 failures in a 5-minute sliding window).
    Expected: Evades Rule 1 completely because no 5-minute window ever contains
    more than 4 failures. Rule 2 may or may not trigger depending on success timing.
    """
    events, labels = [], []
    # 4 failures spaced 6 minutes (360 seconds) apart (spanning 18 minutes)
    for i in range(4):
        ts = start_time + timedelta(seconds=i * 360)
        eid = id_generator()
        events.append({
            "event_id": eid, "timestamp": schema.format_timestamp(ts),
            "user_id": user_id, "event_type": "login_attempt",
            "success": False, "ip_address": attacker_ip, "source": "unknown"
        })
        labels.append({
            "event_id": eid, "scenario_id": scenario_id,
            "scenario_type": "slow_brute_force", "is_attack": True
        })

    # Success at +24 minutes (after a 6-minute pause from the last failure)
    succ_ts = start_time + timedelta(minutes=24, seconds=rng.randint(0, 15))
    succ_eid = id_generator()
    events.append({
        "event_id": succ_eid, "timestamp": schema.format_timestamp(succ_ts),
        "user_id": user_id, "event_type": "login_attempt",
        "success": True, "ip_address": attacker_ip, "source": "unknown"
    })
    labels.append({
        "event_id": succ_eid, "scenario_id": scenario_id,
        "scenario_type": "slow_brute_force", "is_attack": True
    })
    return events, labels


def password_spraying(
    users: list[str],
    start_time: datetime,
    attacker_ip: str,
    rng: random.Random,
    scenario_id: str,
    id_generator,
) -> tuple[list[dict], list[dict]]:
    """
    Password spraying: 1 failure per user across 50 users within 10 minutes.
    
    Target: Evade Rule 1 by distributing attempts across many accounts.
    Expected: Evades Rule 1 (since Rule 1 groups by user_id and no single user
    exceeds 1 failure). Evades Rule 2 because there is no successful login.
    """
    events, labels = [], []
    for i, uid in enumerate(users[:50]):
        # Spread 50 attempts evenly across 600 seconds (10 minutes)
        ts = start_time + timedelta(seconds=int(i * 12) + rng.randint(0, 3))
        eid = id_generator()
        events.append({
            "event_id": eid, "timestamp": schema.format_timestamp(ts),
            "user_id": uid, "event_type": "login_attempt",
            "success": False, "ip_address": attacker_ip, "source": "unknown"
        })
        labels.append({
            "event_id": eid, "scenario_id": scenario_id,
            "scenario_type": "password_spraying", "is_attack": True
        })
    return events, labels


def delayed_takeover(
    user_id: str,
    start_time: datetime,
    attacker_ip: str,
    rng: random.Random,
    scenario_id: str,
    id_generator,
) -> tuple[list[dict], list[dict]]:
    """
    Delayed takeover: 6 failures in 2 minutes, then wait 15 minutes before logging in.
    
    Target: Evade Rule 2 (which requires success within 10 minutes of failures).
    Expected: Rule 1 fires on the initial 6-failure burst. But Rule 2 is evading
    because the successful login occurs at +17 minutes (> 10-minute lookback).
    """
    events, labels = [], []
    # 6 failures in 2 minutes
    for i in range(6):
        ts = start_time + timedelta(seconds=i * 20)
        eid = id_generator()
        events.append({
            "event_id": eid, "timestamp": schema.format_timestamp(ts),
            "user_id": user_id, "event_type": "login_attempt",
            "success": False, "ip_address": attacker_ip, "source": "unknown"
        })
        labels.append({
            "event_id": eid, "scenario_id": scenario_id,
            "scenario_type": "delayed_takeover", "is_attack": True
        })

    # Wait 15 minutes: success at +17 minutes from start
    succ_ts = start_time + timedelta(minutes=17, seconds=rng.randint(0, 10))
    succ_eid = id_generator()
    events.append({
        "event_id": succ_eid, "timestamp": schema.format_timestamp(succ_ts),
        "user_id": user_id, "event_type": "login_attempt",
        "success": True, "ip_address": attacker_ip, "source": "unknown"
    })
    labels.append({
        "event_id": succ_eid, "scenario_id": scenario_id,
        "scenario_type": "delayed_takeover", "is_attack": True
    })
    return events, labels


def low_and_slow_takeover(
    user_id: str,
    start_time: datetime,
    attacker_ip: str,
    rng: random.Random,
    scenario_id: str,
    id_generator,
) -> tuple[list[dict], list[dict]]:
    """
    Low and slow takeover: 2 failures every 8 minutes for 40 minutes,
    success at +48 minutes, then account_change at +35 minutes after login (+83 min).
    
    Target: Evade Rule 1 (<5 fails in 5m), Rule 2 (<3 fails in prior 10m),
    and Rule 3 (change occurs >30 min after success).
    Expected: Completely slips past all 3 rules in the ideal case.
    """
    events, labels = [], []
    # 5 pairs of failures: 10 failures total spread across 40 minutes
    for pair in range(5):
        base = start_time + timedelta(minutes=pair * 8)
        for offset in (0, 30):
            ts = base + timedelta(seconds=offset)
            eid = id_generator()
            events.append({
                "event_id": eid, "timestamp": schema.format_timestamp(ts),
                "user_id": user_id, "event_type": "login_attempt",
                "success": False, "ip_address": attacker_ip, "source": "unknown"
            })
            labels.append({
                "event_id": eid, "scenario_id": scenario_id,
                "scenario_type": "low_and_slow_takeover", "is_attack": True
            })

    # Successful login at +48 minutes (8 minutes after the last failure)
    succ_ts = start_time + timedelta(minutes=48)
    succ_eid = id_generator()
    events.append({
        "event_id": succ_eid, "timestamp": schema.format_timestamp(succ_ts),
        "user_id": user_id, "event_type": "login_attempt",
        "success": True, "ip_address": attacker_ip, "source": "unknown"
    })
    labels.append({
        "event_id": succ_eid, "scenario_id": scenario_id,
        "scenario_type": "low_and_slow_takeover", "is_attack": True
    })

    # Account change at +35 minutes after successful login (> Rule 3's 30-min window)
    chg_ts = succ_ts + timedelta(minutes=35)
    chg_eid = id_generator()
    events.append({
        "event_id": chg_eid, "timestamp": schema.format_timestamp(chg_ts),
        "user_id": user_id, "event_type": "account_change",
        "success": True, "ip_address": attacker_ip, "source": "unknown"
    })
    labels.append({
        "event_id": chg_eid, "scenario_id": scenario_id,
        "scenario_type": "low_and_slow_takeover", "is_attack": True
    })

    return events, labels


ALL_STRATEGIES = {
    "baseline_brute_force": baseline_brute_force,
    "slow_brute_force": slow_brute_force,
    "password_spraying": password_spraying,
    "delayed_takeover": delayed_takeover,
    "low_and_slow_takeover": low_and_slow_takeover,
}

