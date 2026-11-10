"""
generator.py — Synthetic login event and attack label generator.

Person A owns this module.

Generates a seeded, reproducible dataset of login events (events.csv) and
ground-truth attack labels (labels.csv).  The detector module must NEVER
read labels.csv; it is written separately so it stays hidden.

Design decisions (state these in the viva if asked):
  - user IDs are "u0001" … "u0200" (zero-padded, easy to sort).
  - Timestamps are UTC, ISO 8601, no timezone suffix (matches TIMESTAMP_FORMAT).
  - Attacks are injected at off-peak hours (00:00–06:59) to keep them distinct
    from normal business-hours traffic in the sample; in a real system they
    could appear at any time.
  - The forgetful user pattern deliberately keeps failures below RULE1_FAIL_COUNT
    but sometimes triggers RULE2 — this is intentional (hard normal case).
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path
import sys

# Allow imports from the project root when run directly.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import schema

# ---------------------------------------------------------------------------
# Simulation parameters
# ---------------------------------------------------------------------------
NUM_USERS        = 200
NUM_DAYS         = 30
SIM_START        = datetime(2024, 1, 15, 0, 0, 0)   # Monday, UTC

# How many users of each special type to inject.
N_BRUTE_FORCE     = 8
N_COMPROMISE      = 6
N_SUSPICIOUS      = 5
N_FORGETFUL       = 10
N_VPN             = 10
N_ADMIN           = 8
# Remaining users are pure normal_baseline.

# IP address pools (not realistic routing; just for variety).
_OFFICE_IPS  = [f"10.0.{a}.{b}"      for a in range(5) for b in range(1, 20)]
_HOME_IPS    = [f"192.168.{a}.{b}"   for a in range(5) for b in range(1, 20)]
_VPN_IPS     = [f"172.16.{a}.{b}"    for a in range(5) for b in range(1, 20)]
_ATTACK_IPS  = [f"185.220.{a}.{b}"   for a in range(10) for b in range(1, 20)] + \
               [f"91.108.{a}.{b}"     for a in range(5)  for b in range(1, 20)]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def generate_events(seed: int, output_dir: Path) -> None:
    """
    Generate synthetic events.csv and labels.csv for the given seed.

    Both files are written to output_dir.  The function is deterministic:
    calling it twice with the same seed produces identical files.

    Args:
        seed:       Integer random seed.  Same seed → identical output.
        output_dir: Directory to create/overwrite events.csv and labels.csv.
    """
    rng = random.Random(seed)

    events: list[dict] = []   # rows for events.csv
    labels: list[dict] = []   # rows for labels.csv

    # --- Counters shared across all helper functions via closure. ---
    _event_n    = [0]
    _scenario_n = [0]

    def _eid() -> str:
        _event_n[0] += 1
        return f"E{_event_n[0]:06d}"

    def _sid() -> str:
        _scenario_n[0] += 1
        return f"SC{_scenario_n[0]:06d}"

    def _add(ts: datetime, user_id: str, event_type: str, success: bool,
             ip: str, source: str, scenario_id: str,
             scenario_type: str, is_attack: bool) -> str:
        """Append one event row and its matching label row; return the event_id."""
        eid = _eid()
        events.append({
            "event_id":   eid,
            "timestamp":  schema.format_timestamp(ts),
            "user_id":    user_id,
            "event_type": event_type,
            "success":    success,
            "ip_address": ip,
            "source":     source,
        })
        labels.append({
            "event_id":     eid,
            "scenario_id":  scenario_id,
            "scenario_type": scenario_type,
            "is_attack":    is_attack,
        })
        return eid

    # -----------------------------------------------------------------------
    # Assign roles to users.
    # -----------------------------------------------------------------------
    all_users = [f"u{i:04d}" for i in range(1, NUM_USERS + 1)]
    rng.shuffle(all_users)

    idx = 0
    def _take(n):
        nonlocal idx
        chunk = all_users[idx: idx + n]
        idx  += n
        return set(chunk)

    brute_users     = _take(N_BRUTE_FORCE)
    comp_users      = _take(N_COMPROMISE)
    susp_users      = _take(N_SUSPICIOUS)
    forgetful_users = _take(N_FORGETFUL)
    vpn_users       = _take(N_VPN)
    admin_users     = _take(N_ADMIN)
    baseline_users  = set(all_users[idx:])

    # Fixed IPs per user (consistent across days, as a real user would have).
    office_ip = {u: rng.choice(_OFFICE_IPS) for u in all_users}
    home_ip   = {u: rng.choice(_HOME_IPS)   for u in all_users}
    vpn_ip    = {u: rng.choice(_VPN_IPS)    for u in all_users}

    # Pick which day each attack is injected (avoid the first 3 days).
    # Sort the user sets so iteration order is deterministic regardless of PYTHONHASHSEED.
    brute_day = {u: rng.randint(3, NUM_DAYS - 1) for u in sorted(brute_users)}
    comp_day  = {u: rng.randint(3, NUM_DAYS - 1) for u in sorted(comp_users)}
    susp_day  = {u: rng.randint(3, NUM_DAYS - 1) for u in sorted(susp_users)}

    # -----------------------------------------------------------------------
    # Main loop: day by day, user by user.
    # -----------------------------------------------------------------------
    for day_idx in range(NUM_DAYS):
        day_start = SIM_START + timedelta(days=day_idx)
        is_weekend = (day_idx % 7) >= 5   # Sat/Sun

        for uid in all_users:
            # 80 % of users do nothing on weekends.
            if is_weekend and rng.random() < 0.80:
                continue

            # Determine source/IP for today's normal session.
            if uid in vpn_users and rng.random() < 0.35:
                src, ip = "vpn", vpn_ip[uid]
            elif rng.random() < 0.30:
                src, ip = "home", home_ip[uid]
            else:
                src, ip = "office", office_ip[uid]

            # Determine scenario_type for normal events this user generates.
            if uid in forgetful_users:
                s_type_normal = "normal_forgetful"
            elif uid in vpn_users:
                s_type_normal = "normal_vpn"
            elif uid in admin_users:
                s_type_normal = "normal_admin"
            else:
                s_type_normal = "normal_baseline"

            # --- Inject attacks (off-peak hours: 00:00–06:59) ---

            if uid in brute_users and brute_day[uid] == day_idx:
                _inject_brute_force(rng, day_start, uid,
                                    rng.choice(_ATTACK_IPS), _add, _sid)

            if uid in comp_users and comp_day[uid] == day_idx:
                _inject_compromise(rng, day_start, uid,
                                   rng.choice(_ATTACK_IPS), _add, _sid)

            if uid in susp_users and susp_day[uid] == day_idx:
                _inject_suspicious_change(rng, day_start, uid,
                                          ip, src, _add, _sid)

            # --- Normal business-hours logins (08:00–19:00) ---

            num_logins = rng.randint(1, 3)
            for _ in range(num_logins):
                hour   = rng.randint(8, 18)
                minute = rng.randint(0, 59)
                second = rng.randint(0, 59)
                ts     = day_start + timedelta(hours=hour, minutes=minute, seconds=second)

                if uid in forgetful_users and rng.random() < 0.20:
                    # Forgetful user: a few failures before they succeed.
                    _inject_forgetful(rng, ts, uid, ip, src, _add, _sid)
                else:
                    sid = _sid()
                    _add(ts, uid, "login_attempt", True, ip, src,
                         sid, s_type_normal, False)

                    # Admin users occasionally make legitimate privilege changes.
                    if uid in admin_users and rng.random() < 0.15:
                        offset = timedelta(minutes=rng.randint(2, 25))
                        _add(ts + offset, uid, "privilege_change", True,
                             ip, src, sid, "normal_admin", False)

    # -----------------------------------------------------------------------
    # Sort all events by timestamp, then write CSV files.
    # -----------------------------------------------------------------------
    events.sort(key=lambda e: e["timestamp"])

    # Reorder labels to match sorted events.
    eid_to_label = {lbl["event_id"]: lbl for lbl in labels}
    labels_sorted = [eid_to_label[e["event_id"]] for e in events]

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    _write_csv(output_dir / "events.csv", schema.EVENTS_COLUMNS, events)
    _write_csv(output_dir / "labels.csv", schema.LABELS_COLUMNS, labels_sorted)


# ---------------------------------------------------------------------------
# Attack injection helpers
# ---------------------------------------------------------------------------

def _inject_brute_force(rng, day_start, uid, attacker_ip, add, sid_fn):
    """
    Brute-force burst: >= RULE1_FAIL_COUNT failures within RULE1_WINDOW_MINUTES,
    then a successful login.

    All events use a single scenario_id so the evaluator can group them.
    """
    hour   = rng.randint(0, 5)
    minute = rng.randint(0, 54)
    base   = day_start + timedelta(hours=hour, minutes=minute)

    sid           = sid_fn()
    num_failures  = rng.randint(schema.RULE1_FAIL_COUNT, schema.RULE1_FAIL_COUNT + 4)

    # Pack failures within RULE1_WINDOW_MINUTES (288 seconds max per slot).
    window_secs = schema.RULE1_WINDOW_MINUTES * 60
    for i in range(num_failures):
        offset = timedelta(seconds=int(i * window_secs / (num_failures + 1))
                           + rng.randint(0, 10))
        add(base + offset, uid, "login_attempt", False,
            attacker_ip, "unknown", sid, "brute_force", True)

    # Success just after the last failure, still inside the 5-min window.
    add(base + timedelta(seconds=window_secs - 5 + rng.randint(1, 10)),
        uid, "login_attempt", True,
        attacker_ip, "unknown", sid, "brute_force", True)


def _inject_compromise(rng, day_start, uid, attacker_ip, add, sid_fn):
    """
    Credential-compromise chain: 3–5 failures, then success (within
    RULE2_WINDOW_MINUTES of the first failure), then an account_change
    (within RULE3_WINDOW_MINUTES of the success).
    """
    hour   = rng.randint(1, 5)
    minute = rng.randint(0, 50)
    base   = day_start + timedelta(hours=hour, minutes=minute)

    sid          = sid_fn()
    num_failures = rng.randint(schema.RULE2_FAIL_COUNT,
                               schema.RULE2_FAIL_COUNT + 2)

    # Failures spread over the first 8 minutes (< RULE2_WINDOW_MINUTES = 10).
    for i in range(num_failures):
        offset = timedelta(minutes=i * 2 + rng.randint(0, 1),
                           seconds=rng.randint(10, 50))
        add(base + offset, uid, "login_attempt", False,
            attacker_ip, "unknown", sid, "compromise", True)

    # Success within the 10-minute window.
    ts_success = base + timedelta(minutes=rng.randint(5, 9),
                                  seconds=rng.randint(0, 59))
    add(ts_success, uid, "login_attempt", True,
        attacker_ip, "unknown", sid, "compromise", True)

    # Account change within RULE3_WINDOW_MINUTES of the success.
    ts_change = ts_success + timedelta(minutes=rng.randint(5, 25))
    add(ts_change, uid, "account_change", True,
        attacker_ip, "unknown", sid, "compromise", True)


def _inject_suspicious_change(rng, day_start, uid, ip, source, add, sid_fn):
    """
    Suspicious privilege change: a successful login followed quickly by a
    privilege_change, with NO prior failures.

    This triggers Rule 3 but not Rules 1 or 2.
    """
    hour   = rng.randint(2, 6)
    minute = rng.randint(0, 59)
    base   = day_start + timedelta(hours=hour, minutes=minute)

    sid = sid_fn()
    add(base, uid, "login_attempt", True,
        ip, source, sid, "suspicious_change", True)

    offset = timedelta(minutes=rng.randint(2, 25))
    add(base + offset, uid, "privilege_change", True,
        ip, source, sid, "suspicious_change", True)


def _inject_forgetful(rng, base_ts, uid, ip, source, add, sid_fn):
    """
    Forgetful user: 2–3 failed logins then a success.

    Deliberately kept below RULE1_FAIL_COUNT (5) failures.
    Failures are spread over ~15 min to usually avoid RULE2 (10-min window),
    but tight clusters can still trigger it — that is an intentional hard case.
    """
    sid          = sid_fn()
    num_failures = rng.randint(2, 3)

    # Space failures 4–7 minutes apart → total span 8–21 min.
    gap = rng.randint(4, 7)
    for i in range(num_failures):
        offset = timedelta(minutes=i * gap, seconds=rng.randint(0, 59))
        add(base_ts + offset, uid, "login_attempt", False,
            ip, source, sid, "normal_forgetful", False)

    ts_success = base_ts + timedelta(minutes=num_failures * gap + rng.randint(1, 3))
    add(ts_success, uid, "login_attempt", True,
        ip, source, sid, "normal_forgetful", False)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    """Write a list of dicts to a CSV file with the given column order."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# CLI usage: python generator/generator.py [seed] [output_dir]
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _seed = int(sys.argv[1]) if len(sys.argv) > 1 else 42
    _out  = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("data/generated")
    print(f"Generating with seed={_seed} → {_out}")
    generate_events(_seed, _out)
    print("Done.")

