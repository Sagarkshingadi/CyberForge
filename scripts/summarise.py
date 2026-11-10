"""
scripts/summarise.py — Recomputes and validates evaluation summary metrics.

Reads ONLY data/canonical/results.csv and prints:
1. Per-seed breakdown across all 10 simulation seeds.
2. 10-seed average per-policy summary metrics.
"""

from pathlib import Path
import pandas as pd

RESULTS_PATH = Path("data/canonical/results.csv")

def main():
    if not RESULTS_PATH.exists():
        raise FileNotFoundError(f"Missing {RESULTS_PATH}. Run Step 2 evaluation first.")

    df = pd.read_csv(RESULTS_PATH)

    print("=" * 70)
    print(" 1. PER-SEED RESULTS BREAKDOWN (from data/canonical/results.csv)")
    print("=" * 70)
    print(f"{'Seed':<6} {'Policy':<18} {'Attacks Stopped':<18} {'Users Disrupted':<18} {'Total Cost'}")
    print("-" * 70)
    for _, row in df.iterrows():
        print(f"{int(row['seed']):<6} {row['policy']:<18} {int(row['attacks_stopped']):<18} {int(row['normal_users_disrupted']):<18} {row['total_cost']:<10.1f}")

    print("\n" + "=" * 75)
    print(" 2. POLICY COMPARISON SUMMARY (Averaged across all 10 simulation seeds)")
    print("=" * 75)
    summary = df.groupby("policy")[["attacks_stopped", "normal_users_disrupted", "total_cost"]].mean()
    # Ensure consistent policy order matching standard report
    policy_order = ["always_monitor", "always_lock", "severity_based"]
    summary = summary.reindex(policy_order)

    print(summary.to_string(formatters={
        "attacks_stopped": "{:15.1f}".format,
        "normal_users_disrupted": "{:23.1f}".format,
        "total_cost": "{:11.1f}".format,
    }))
    print("-" * 75)

    # Verification against canonical expected values
    expected = {
        "always_monitor": (0.0, 0.0, 3800.0),
        "always_lock": (38.0, 52.7, 3015.0),
        "severity_based": (38.0, 52.7, 759.5),
    }

    mismatches = []
    for pol, (exp_stop, exp_disr, exp_cost) in expected.items():
        actual_stop = summary.loc[pol, "attacks_stopped"]
        actual_disr = summary.loc[pol, "normal_users_disrupted"]
        actual_cost = summary.loc[pol, "total_cost"]

        if abs(actual_stop - exp_stop) > 1e-4:
            mismatches.append(f"{pol} attacks_stopped: expected {exp_stop}, got {actual_stop}")
        if abs(actual_disr - exp_disr) > 1e-4:
            mismatches.append(f"{pol} normal_users_disrupted: expected {exp_disr}, got {actual_disr}")
        if abs(actual_cost - exp_cost) > 1e-4:
            mismatches.append(f"{pol} total_cost: expected {exp_cost}, got {actual_cost}")

    if mismatches:
        print("\n[FAILED] Mismatches detected against Step 2 terminal output:")
        for m in mismatches:
            print("  •", m)
    else:
        print("\n[VERIFIED] All recomputed metrics match Step 2 terminal output exactly!")
    print("=" * 75)

if __name__ == "__main__":
    main()

