"""
cli.py — CyberForge Lite CLI & Manual Red Team Interactive Demo (Addendum 2 Stage B).

Allows a human operator to launch simulated attacks, choose or tune parameters,
and watch both the Red Team (attacker) and Blue Team (defender) in a turn-based
split display.

Usage examples:
    python cli.py redteam --strategy baseline_brute_force --user user_17 --attempts 8
    python cli.py redteam --strategy slow_brute_force --user user_17 --attempts 4 --interval 6m
    python cli.py redteam --strategy password_spraying --users 50
    python cli.py redteam --strategy delayed_takeover --user user_17
    python cli.py redteam --strategy low_and_slow_takeover --user user_17

    python cli.py evasion-report    # Run Stage A automated evasion testing across 10 seeds

Rules:
- Manual runs are logged to data/output/manual/<timestamp>.json
- Manual results are NEVER mixed into results.csv
"""

import argparse
from datetime import datetime, timedelta
import json
from pathlib import Path
import random
import sys
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent))
import schema
from redteam.strategies import ALL_STRATEGIES
from detector.detector import run_detector
from responder.responder import run_responder, _policy_action, DEFAULT_COST_TABLE


def main():
    parser = argparse.ArgumentParser(description="CyberForge Lite CLI")
    subparsers = parser.add_subparsers(dest="command")

    # Command: redteam (Stage B Interactive Demo)
    rt = subparsers.add_parser("redteam", help="Run interactive Red Team vs Blue Team attack demo")
    rt.add_argument("--strategy", type=str, required=True, choices=list(ALL_STRATEGIES.keys()),
                    help="Attack strategy to execute")
    rt.add_argument("--user", type=str, default="user_17", help="Target user ID")
    rt.add_argument("--attempts", type=int, default=None, help="Number of failed attempts")
    rt.add_argument("--interval", type=str, default="6m", help="Time between attempts (e.g., 15s, 6m)")
    rt.add_argument("--users", type=int, default=50, help="Number of users to spray (for password_spraying)")

    # Command: evasion-report (Stage A Automated)
    ev_parser = subparsers.add_parser("evasion-report", help="Run Stage A automated evasion suite over 10 seeds")
    ev_parser.add_argument("--output-dir", type=Path, default=Path("data/output"),
                           help="Directory for evasion evaluation outputs (default: data/output)")

    args = parser.parse_args()

    if args.command == "evasion-report":
        from evaluator.evasion import run_evasion_evaluation, run_gap_closure_iteration
        print("=" * 70)
        print(" RUNNING STAGE A: AUTOMATED EVASION EVALUATION (10 SEEDS)")
        print("=" * 70)
        out_dir = getattr(args, "output_dir", Path("data/output"))
        df_ev = run_evasion_evaluation(out_dir)
        print("\n=== EVASION RATE SUMMARY BY STRATEGY ===")
        summary = df_ev.groupby("strategy")[["instances", "evaded", "detected_by_rule1",
                                             "detected_by_rule2", "detected_by_rule3"]].sum()
        summary["evasion_rate"] = (summary["evaded"] / summary["instances"]).apply(lambda x: f"{x*100:.1f}%")
        print(summary[["instances", "evaded", "evasion_rate", "detected_by_rule1", "detected_by_rule2", "detected_by_rule3"]].to_string())

        print("\n" + "=" * 70)
        print(" STAGE A (Section 2.4): GAP CLOSURE ITERATION")
        print("=" * 70)
        gap_results = run_gap_closure_iteration(out_dir)
        for k, v in gap_results.items():
            print(f"  • {k:<38}: {v}")
        print("=" * 70)
        print(f"Chart saved → {out_dir}/charts/chart_evasion_rate.png")
        print(f"Evasion table → {out_dir}/evasion_table.csv")
        print("Evasion table → data/output/evasion_table.csv\n")
        return

    if args.command == "redteam":
        run_interactive_demo(args)
        return

    parser.print_help()


def run_interactive_demo(args):
    """Stage B interactive split display and logging."""
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    manual_dir = Path("data/output/manual")
    manual_dir.mkdir(parents=True, exist_ok=True)
    temp_dir = manual_dir / f"session_{timestamp_str}"
    temp_dir.mkdir(parents=True, exist_ok=True)

    rng = random.Random(42)
    start_ts = datetime.now().replace(microsecond=0)
    counter = [0]
    def eid_gen():
        counter[0] += 1
        return f"M_{counter[0]:04d}"

    strat_func = ALL_STRATEGIES[args.strategy]

    # Generate events
    if args.strategy == "password_spraying":
        user_list = [f"user_{i:02d}" for i in range(1, args.users + 1)]
        events, labels = strat_func(user_list, start_ts, "198.51.100.99", rng, f"M_SCEN", eid_gen)
    else:
        events, labels = strat_func(args.user, start_ts, "198.51.100.99", rng, f"M_SCEN", eid_gen)

    ev_path = temp_dir / "events.csv"
    lb_path = temp_dir / "labels.csv"
    alt_path = temp_dir / "alerts.csv"
    dec_path = temp_dir / "decisions.csv"

    # Write files
    pd.DataFrame(events).to_csv(ev_path, index=False)
    pd.DataFrame(labels).to_csv(lb_path, index=False)

    # Blue team detection
    alerts = run_detector(ev_path, alt_path)
    decisions = run_responder(alt_path, lb_path, dec_path)

    # Render Split Display in Terminal
    print("\n" + "=" * 78)
    print(f" CYBERFORGE LITE — RED TEAM VS BLUE TEAM INTERACTIVE DEMO")
    print(f" Strategy: {args.strategy} | Target: {args.user if args.strategy != 'password_spraying' else f'{args.users} users'}")
    print("=" * 78)

    print("\n" + "-" * 38 + " [ RED TEAM: INJECTED MOVES ] " + "-" * 10)
    for ev in events:
        status = "SUCCESS" if ev["success"] else "FAILED"
        print(f"  [{ev['timestamp']}] {ev['user_id']:<10} {ev['event_type']:<15} {status:<8} (from {ev['ip_address']})")
    print(f"  >> Attack emitted: {len(events)} total actions.")

    print("\n" + "-" * 38 + " [ BLUE TEAM: SOC DEFENSE ] " + "-" * 12)
    if not alerts:
        print("  [VERDICT] -> 0 ALERTS FIRED! Attack successfully EVADED detection rules.")
    else:
        print(f"  [VERDICT] -> {len(alerts)} ALERT(S) TRIGGERED:")
        for alt in alerts:
            print(f"  * {alt['rule_id']}: {alt['note']}")

    # Policy Actions
    print("\n" + "-" * 38 + " [ AUTOMATED RESPONSE VERDICT ] " + "-" * 7)
    if not alerts:
        print("  • always_monitor : No action (Attack succeeded unnoticed — Cost: 100)")
        print("  • always_lock    : No action (Attack succeeded unnoticed — Cost: 100)")
        print("  • severity_based : No action (Attack succeeded unnoticed — Cost: 100)")
    else:
        dec_df = pd.read_csv(dec_path)
        for pol in ["always_monitor", "always_lock", "severity_based"]:
            actions = list(dec_df[dec_df["policy"] == pol]["action"])
            cost = dec_df[dec_df["policy"] == pol]["cost"].sum()
            print(f"  • {pol:<16} : Action={actions} | Cost={cost:.1f} pts")

    print("=" * 78)
    result_evaded = len(alerts) == 0
    print(f" FINAL OUTCOME: {'🚨 ATTACK EVADED DETECTION' if result_evaded else '🛡️ ATTACK CAUGHT BY DEFENDER'}")
    print("=" * 78)

    # Save to manual JSON log for replay
    log_file = manual_dir / f"{timestamp_str}_{args.strategy}.json"
    session_data = {
        "timestamp": timestamp_str,
        "command": sys.argv,
        "strategy": args.strategy,
        "user": args.user,
        "events_count": len(events),
        "alerts_count": len(alerts),
        "evaded": result_evaded,
        "alerts": alerts,
    }
    with open(log_file, "w", encoding="utf-8") as f:
        json.dump(session_data, f, indent=2)

    print(f"\n[AUDIT] Session saved to: {log_file}")
    print("[NOTE] Manual runs are strictly kept out of scientific results.csv.\n")


if __name__ == "__main__":
    main()

