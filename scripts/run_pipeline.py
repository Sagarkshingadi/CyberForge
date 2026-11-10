"""
run_pipeline.py — Main CLI entry point for CyberForge Lite.

Usage
-----
Single run (one seed, inspect output):
    python scripts/run_pipeline.py

Custom seed and output directory:
    python scripts/run_pipeline.py --seed 7 --output-dir data/my_run

Full evaluation over 10 seeds (all policies, charts, sensitivity check):
    python scripts/run_pipeline.py --evaluate

Full evaluation to a custom directory:
    python scripts/run_pipeline.py --evaluate --output-dir data/results
"""

import argparse
import sys
from pathlib import Path

# Allow imports from the project root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="run_pipeline.py",
        description="CyberForge Lite — synthetic login-attack simulation.",
    )
    parser.add_argument(
        "--seed", type=int, default=42,
        help="Random seed for a single run (default: 42).",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=Path("data/output"),
        help="Root directory for generated files (default: data/output).",
    )
    parser.add_argument(
        "--evaluate", action="store_true",
        help="Run the full evaluator over 10 seeds (Weeks 4 feature).",
    )
    parser.add_argument(
        "--with-rule4", action="store_true",
        help="Include Rule 4 (>=4 failures in 60 min) in detection (gap closure).",
    )
    args = parser.parse_args()

    if args.evaluate:
        print("=" * 60)
        print(f"CyberForge Lite — Full Evaluation (10 seeds){' [WITH RULE 4]' if args.with_rule4 else ''}")
        print("=" * 60)
        from evaluator.evaluator import run_evaluation
        run_evaluation(args.output_dir, with_rule4=args.with_rule4)
        return

    # --- Single-seed run ---
    print("=" * 70)
    print(f" CYBERFORGE LITE — SIMULATION PIPELINE (Seed = {args.seed})")
    print("=" * 70)
    print("Goal: Simulate 200 users, inject realistic attacks, detect them with")
    print("      rule-based alerts, and evaluate 3 defensive response policies.")
    print("-" * 70)

    run_dir = args.output_dir / f"seed_{args.seed}"

    from generator.generator import generate_events
    from detector.detector   import run_detector
    from responder.responder import run_responder

    # -------------------------------------------------------------
    # Step 1: Synthetic Data Generation
    # -------------------------------------------------------------
    print("\n[STEP 1/3] Generating Synthetic Activity Logs...")
    print(f"  • Simulating 30 days of office, home, and VPN logins for 200 users")
    print(f"  • Injected attacks: Brute Force bursts, Compromises, Suspicious Changes")
    print(f"  • Injected tricky normal cases: Forgetful users, Admin routine updates")
    generate_events(args.seed, run_dir)
    import pandas as pd
    events_df = pd.read_csv(run_dir / "events.csv")
    labels_df = pd.read_csv(run_dir / "labels.csv")
    n_events = len(events_df)
    n_attacks = (labels_df["is_attack"] == True).sum()
    print(f"  --> Success: Created {n_events:,} events ({n_attacks} malicious events injected)")
    print(f"      Saved to: {run_dir / 'events.csv'}")
    print(f"      Secret labels (hidden from detector): {run_dir / 'labels.csv'}")

    # -------------------------------------------------------------
    # Step 2: Automated Rule-Based Detection
    # -------------------------------------------------------------
    print("\n[STEP 2/3] Running Intrusion Detection Rules (Independent of Labels)...")
    print("  • Rule 1 (Brute-Force):     >= 5 failed logins within 5 mins")
    print("  • Rule 2 (Compromise Entry): Success within 10 mins of >= 3 failures")
    print("  • Rule 3 (Suspicious Chg):   Privilege/Account change within 30m of login")
    alerts = run_detector(run_dir / "events.csv", run_dir / "alerts.csv", with_rule4=args.with_rule4)
    print(f"  --> Success: Detector flagged {len(alerts)} suspicious alert incidents:")
    if alerts:
        from collections import Counter
        rule_counts = Counter(a["rule_id"] for a in alerts)
        for rule, cnt in sorted(rule_counts.items()):
            desc = {
                "RULE1": "Brute-force rapid failures",
                "RULE2": "Success after prior failures",
                "RULE3": "Rapid account/privilege changes",
                "RULE4": "Aggregated slow failures (60m window)",
            }.get(rule, "")
            print(f"      - {rule:<6} ({desc}): {cnt} alert(s)")
    print(f"      Saved to: {run_dir / 'alerts.csv'}")

    # -------------------------------------------------------------
    # Step 3: Response Action & Cost Comparison
    # -------------------------------------------------------------
    print("\n[STEP 3/3] Testing Defensive Response Policies...")
    print("  Testing 3 Policies across all flagged alerts:")
    print("    1. 'always_monitor' : Do nothing / log only (cheap on normal, expensive on attack)")
    print("    2. 'always_lock'    : Lock user out immediately (stops attack, disrupts innocent)")
    print("    3. 'severity_based' : Lock on high confidence (Rule 1/2), Verify on Rule 3")
    decisions = run_responder(
        run_dir / "alerts.csv",
        run_dir / "labels.csv",
        run_dir / "decisions.csv",
    )
    print(f"  --> Success: Evaluated {len(decisions)} policy actions ({len(decisions) // 3} alerts x 3 policies)")
    print(f"      Saved to: {run_dir / 'decisions.csv'}")

    # -------------------------------------------------------------
    # Quick Summary Table
    # -------------------------------------------------------------
    decisions_df = pd.read_csv(run_dir / "decisions.csv")
    cost_summary = decisions_df.groupby("policy")["cost"].sum()
    print("\n" + "=" * 70)
    print(" POLICY COST COMPARISON (Lower is Better)")
    print("=" * 70)
    for pol, total_cost in cost_summary.items():
        print(f"  • {pol:<16} : {total_cost:,.1f} cost points")
    best_policy = cost_summary.idxmin()
    print("-" * 70)
    print(f"  WINNER FOR THIS SEED: '{best_policy}' policy achieves optimal balance!")
    print("=" * 70)
    print("\nWant the full scientific report across 10 random seeds with graphs?")
    print("Run:  python scripts/run_pipeline.py --evaluate\n")


if __name__ == "__main__":
    main()

