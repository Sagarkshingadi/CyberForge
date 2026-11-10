"""
recompute_tables.py — Recompute every verification table directly from
the CSV files in data/canonical, data/canonical_rule4, and data/canonical_check.
"""

import csv
import hashlib
from pathlib import Path
from collections import defaultdict
import pandas as pd


BASE_DIR = Path(__file__).resolve().parent.parent
CANONICAL_DIR = BASE_DIR / "data" / "canonical"
CANONICAL_CHECK_DIR = BASE_DIR / "data" / "canonical_check"
CANONICAL_R4_DIR = BASE_DIR / "data" / "canonical_rule4"


def hash_file(filepath: Path) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as fh:
        while chunk := fh.read(65536):
            h.update(chunk)
    return h.hexdigest()


# ==============================================================================
# TABLE 1: Baseline Hash Invariance Check (data/canonical vs data/canonical_check)
# ==============================================================================
def recompute_table1():
    files_to_check = ["results.csv"]
    for s in range(10):
        files_to_check.append(f"runs/seed_{s}/events.csv")
        files_to_check.append(f"runs/seed_{s}/labels.csv")
        files_to_check.append(f"runs/seed_{s}/alerts.csv")

    table1_rows = []
    diff_count = 0
    for rel in files_to_check:
        p_canon = CANONICAL_DIR / rel
        p_check = CANONICAL_CHECK_DIR / rel
        if not p_canon.exists() or not p_check.exists():
            table1_rows.append((rel, "MISSING", "MISSING", "MISSING"))
            diff_count += 1
            continue
        h_canon = hash_file(p_canon)
        h_check = hash_file(p_check)
        status = "MATCH" if h_canon == h_check else "DIFFER"
        if status == "DIFFER":
            diff_count += 1
        table1_rows.append((rel, h_canon[:12], h_check[:12], status))

    return table1_rows, diff_count


# ==============================================================================
# TABLE 2: Rule 4 Attacks Caught Per Attack Scenario (Not Per Alert)
# ==============================================================================
def recompute_table2():
    table2_rows = []
    total_scenarios_all = 0
    total_caught_all = 0

    for seed in range(10):
        seed_dir = CANONICAL_R4_DIR / "runs" / f"seed_{seed}"
        labels_df = pd.read_csv(seed_dir / "labels.csv")
        alerts_df = pd.read_csv(seed_dir / "alerts.csv")

        # Attack scenarios from labels.csv
        attack_events = labels_df[labels_df["is_attack"] == True]
        scenarios = attack_events.groupby("scenario_id")["event_id"].apply(set).to_dict()
        n_total = len(scenarios)

        # Rule 4 alerts
        r4_alerts = alerts_df[alerts_df["rule_id"] == "RULE4"]
        r4_eids = set()
        for eids_str in r4_alerts["event_ids"]:
            for eid in str(eids_str).split(";"):
                r4_eids.add(eid.strip())

        # Scenario is caught if any Rule 4 alert contains at least one of its event IDs
        caught_scens = {s_id for s_id, s_eids in scenarios.items() if s_eids & r4_eids}
        n_caught = len(caught_scens)
        recall = (n_caught / n_total * 100.0) if n_total > 0 else 0.0

        total_scenarios_all += n_total
        total_caught_all += n_caught

        table2_rows.append((seed, n_total, n_caught, recall))

    mean_total = total_scenarios_all / 10.0
    mean_caught = total_caught_all / 10.0
    mean_recall = (total_caught_all / total_scenarios_all * 100.0) if total_scenarios_all > 0 else 0.0

    return table2_rows, (mean_total, mean_caught, mean_recall)


# ==============================================================================
# TABLE 3: Policy Performance Comparison (Baseline vs With Rule 4)
# ==============================================================================
def recompute_table3():
    base_res = pd.read_csv(CANONICAL_DIR / "results.csv")
    r4_res = pd.read_csv(CANONICAL_R4_DIR / "results.csv")

    policies = ["always_monitor", "always_lock", "severity_based"]
    table3_rows = []

    for pol in policies:
        b_sub = base_res[base_res["policy"] == pol]
        r_sub = r4_res[r4_res["policy"] == pol]

        # attacks_stopped
        b_stopped = b_sub["attacks_stopped"].mean()
        r_stopped = r_sub["attacks_stopped"].mean()
        table3_rows.append((pol, "Attacks Stopped (alerts)", b_stopped, r_stopped, r_stopped - b_stopped))

        # normal_users_disrupted
        b_disrupt = b_sub["normal_users_disrupted"].mean()
        r_disrupt = r_sub["normal_users_disrupted"].mean()
        table3_rows.append((pol, "Normal Users Disrupted", b_disrupt, r_disrupt, r_disrupt - b_disrupt))

        # total_cost
        b_cost = b_sub["total_cost"].mean()
        r_cost = r_sub["total_cost"].mean()
        table3_rows.append((pol, "Total Cost", b_cost, r_cost, r_cost - b_cost))

    return table3_rows


# ==============================================================================
# TABLE 4: Detection Rule Metrics Comparison (Baseline vs With Rule 4)
# ==============================================================================
def recompute_table4():
    base_rules = pd.read_csv(CANONICAL_DIR / "rule_metrics.csv")
    r4_rules = pd.read_csv(CANONICAL_R4_DIR / "rule_metrics.csv")

    # Group by rule
    rules = ["RULE1", "RULE2", "RULE3", "RULE4"]
    table4_rows = []

    for rule in rules:
        b_sub = base_rules[base_rules["rule"] == rule] if rule in base_rules["rule"].values else None
        r_sub = r4_rules[r4_rules["rule"] == rule] if rule in r4_rules["rule"].values else None

        # TP
        b_tp = f"{b_sub['tp'].mean():.2f}" if (b_sub is not None and len(b_sub) > 0) else "N/A"
        r_tp = f"{r_sub['tp'].mean():.2f}" if (r_sub is not None and len(r_sub) > 0) else "N/A"
        table4_rows.append((rule, "TP", b_tp, r_tp))

        # FP
        b_fp = f"{b_sub['fp'].mean():.2f}" if (b_sub is not None and len(b_sub) > 0) else "N/A"
        r_fp = f"{r_sub['fp'].mean():.2f}" if (r_sub is not None and len(r_sub) > 0) else "N/A"
        table4_rows.append((rule, "FP", b_fp, r_fp))

        # Precision
        # Calculate mean precision across seeds where denominator > 0
        b_prec = f"{b_sub['precision'].mean():.3f}" if (b_sub is not None and len(b_sub) > 0) else "N/A"
        r_prec = f"{r_sub['precision'].mean():.3f}" if (r_sub is not None and len(r_sub) > 0) else "N/A"
        table4_rows.append((rule, "Precision", b_prec, r_prec))

    return table4_rows


# ==============================================================================
# TABLE 5: Empirical Proof for u0023 in Seed 0
# ==============================================================================
def recompute_u0023():
    seed0_events = pd.read_csv(CANONICAL_R4_DIR / "runs" / "seed_0" / "events.csv")
    seed0_alerts = pd.read_csv(CANONICAL_R4_DIR / "runs" / "seed_0" / "alerts.csv")
    seed0_labels = pd.read_csv(CANONICAL_R4_DIR / "runs" / "seed_0" / "labels.csv")

    u_events = seed0_events[(seed0_events["user_id"] == "u0023") & (seed0_events["event_type"] == "login_attempt") & (seed0_events["success"] == False)]
    u_events_details = []
    for _, row in u_events.iterrows():
        lbl = seed0_labels[seed0_labels["event_id"] == row["event_id"]]
        attack = bool(lbl["is_attack"].iloc[0]) if not lbl.empty else False
        scen = str(lbl["scenario_id"].iloc[0]) if not lbl.empty else ""
        stype = str(lbl["scenario_type"].iloc[0]) if not lbl.empty else ""
        u_events_details.append((row["event_id"], row["timestamp"], attack, scen, stype))

    u_alerts = seed0_alerts[(seed0_alerts["user_id"] == "u0023") & (seed0_alerts["rule_id"] == "RULE4")]
    u_alerts_details = []
    for _, row in u_alerts.iterrows():
        eids = str(row["event_ids"]).split(";")
        u_alerts_details.append((row["alert_id"], row["timestamp"], len(eids), row["event_ids"]))

    return u_events_details, u_alerts_details


if __name__ == "__main__":
    print("=== RECOMPUTED TABLE 1: Baseline Hash Invariance Check ===")
    t1_rows, diffs = recompute_table1()
    print(f"Total checked: {len(t1_rows)}, Differing: {diffs}")
    for r, h1, h2, status in t1_rows:
        print(f"  {r:<30} {h1}  {h2}  {status}")

    print("\n=== RECOMPUTED TABLE 2: Rule 4 Attacks Caught Per Scenario ===")
    t2_rows, (m_tot, m_cgt, m_rec) = recompute_table2()
    for s, tot, cgt, rec in t2_rows:
        print(f"  Seed {s}: {cgt}/{tot} ({rec:.1f}%)")
    print(f"  Mean: {m_cgt:.1f}/{m_tot:.1f} ({m_rec:.1f}%)")

    print("\n=== RECOMPUTED TABLE 3: Policy Performance Comparison ===")
    t3_rows = recompute_table3()
    for pol, metric, b_val, r_val, diff in t3_rows:
        print(f"  {pol:<16} | {metric:<25} | Base: {b_val:>8.2f} | R4: {r_val:>8.2f} | Diff: {diff:>+8.2f}")

    print("\n=== RECOMPUTED TABLE 4: Detection Rule Metrics Comparison ===")
    t4_rows = recompute_table4()
    for rule, metric, b_val, r_val in t4_rows:
        print(f"  {rule:<6} | {metric:<10} | Base: {b_val:>7} | R4: {r_val:>7}")

    print("\n=== RECOMPUTED TABLE 5: u0023 Seed 0 Proof ===")
    evts, alrts = recompute_u0023()
    print(f"Failures: {len(evts)}")
    for e in evts:
        print(f"  {e[0]} | {e[1]} | is_attack={e[2]} | {e[3]} | {e[4]}")
    print(f"Rule 4 Alerts: {len(alrts)}")
    for a in alrts:
        print(f"  {a[0]} | {a[1]} | count={a[2]} | {a[3]}")
