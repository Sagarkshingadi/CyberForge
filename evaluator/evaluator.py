"""
evaluator.py — Runs the full pipeline over 10 seeds, computes metrics,
               performs a sensitivity check, and produces three charts.

Person D owns this module.

Metrics computed per seed × policy:
  - attacks_stopped:         TP alerts where action != 'monitor'.
  - normal_users_disrupted:  FP alerts where action != 'monitor'.
  - total_cost:              sum of cost column in decisions.csv.

Precision / recall per rule (averaged over seeds):
  - Precision = TP_alerts / all_alerts_for_that_rule.
  - Recall    = attack_scenarios_caught / attack_scenarios_total.

An alert "catches" an attack scenario if:
  (a) The alert's user_id matches the attacked user.
  (b) The alert's time window [min_ts, max_ts of its event_ids] overlaps
      the attack scenario's time window [min_ts, max_ts of its event_ids].
This matching rule is stated in comments and must be in the report.

Sensitivity check:
  Lock costs are doubled (×2) and halved (×0.5).  The best policy is
  identified under each variant.  If it changes, the conclusion is
  cost-sensitive; if not, it is robust.
"""

import csv
import sys
from pathlib import Path
from collections import defaultdict

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import schema

SEEDS    = list(range(10))
POLICIES = ["always_monitor", "always_lock", "severity_based"]


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_evaluation(
    output_dir: Path,
    seeds: list[int]    | None = None,
    policies: list[str] | None = None,
    with_rule4: bool = False,
) -> None:
    """
    Run the full CyberForge Lite pipeline for every seed, aggregate results,
    perform a sensitivity check, and save charts.

    Args:
        output_dir: Root directory for all output (created if absent).
        seeds:      Random seeds to use (default: 0–9).
        policies:   Policy names to evaluate (default: all three).
        with_rule4: If True, include Rule 4 in detection (default: False).
    """
    import pandas as pd
    import matplotlib
    matplotlib.use("Agg")   # Non-interactive backend (safe on headless servers).

    from generator.generator import generate_events
    from detector.detector   import run_detector
    from responder.responder import run_responder, DEFAULT_COST_TABLE

    if seeds    is None: seeds    = SEEDS
    if policies is None: policies = POLICIES

    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    all_results: list[dict]           = []
    rule_metrics: list[dict]          = []
    per_policy_metrics: list[dict]    = []

    print(f"Running {len(seeds)} seeds × {len(policies)} policies …\n")

    for seed in seeds:
        print(f"  Seed {seed} ", end="", flush=True)
        seed_dir = output_dir / "runs" / f"seed_{seed}"
        seed_dir.mkdir(parents=True, exist_ok=True)

        # Step 1 — Generate.
        generate_events(seed, seed_dir)
        print(".", end="", flush=True)

        # Step 2 — Detect.
        run_detector(seed_dir / "events.csv", seed_dir / "alerts.csv", with_rule4=with_rule4)
        print(".", end="", flush=True)

        # Step 3 — Respond.
        run_responder(
            seed_dir / "alerts.csv",
            seed_dir / "labels.csv",
            seed_dir / "decisions.csv",
            policies=policies,
        )
        print(".", end="", flush=True)

        # Step 4 — Evaluate this seed.
        events_df    = pd.read_csv(seed_dir / "events.csv")
        labels_df    = pd.read_csv(seed_dir / "labels.csv")
        alerts_df    = pd.read_csv(seed_dir / "alerts.csv")
        decisions_df = pd.read_csv(seed_dir / "decisions.csv")

        # Tag each alert as TP or FP.
        is_attack_map = dict(
            zip(labels_df["event_id"], labels_df["is_attack"].astype(bool))
        )

        def _alert_tp(eid_str: str) -> bool:
            return any(is_attack_map.get(e.strip(), False)
                       for e in str(eid_str).split(";"))

        alerts_df["is_tp"] = alerts_df["event_ids"].apply(_alert_tp)

        # --- Rule-level metrics ---
        rules_to_eval = ["RULE1", "RULE2", "RULE3", "RULE4"] if with_rule4 else ["RULE1", "RULE2", "RULE3"]
        for rule in rules_to_eval:
            rule_alerts = alerts_df[alerts_df["rule_id"] == rule]
            tp = int(rule_alerts["is_tp"].sum())
            fp = int((~rule_alerts["is_tp"]).sum())
            precision = tp / (tp + fp) if (tp + fp) > 0 else float("nan")
            rule_metrics.append({
                "seed": seed, "rule": rule,
                "tp": tp, "fp": fp, "precision": round(precision, 4),
            })

        # --- Recall: which attack scenarios were caught? ---
        # Build scenario → {event_ids} map from labels + events.
        attack_labels = labels_df[labels_df["is_attack"] == True].copy()
        attack_labels = attack_labels.merge(
            events_df[["event_id", "user_id", "timestamp"]], on="event_id"
        )
        attack_labels["_ts"] = attack_labels["timestamp"].apply(schema.parse_timestamp)

        # Group by scenario_id to find each scenario's user and time window.
        scenarios_caught: set[str] = set()
        total_scenarios = set(attack_labels["scenario_id"])

        for scen_id, scen_grp in attack_labels.groupby("scenario_id"):
            uid       = scen_grp["user_id"].iloc[0]
            scen_min  = scen_grp["_ts"].min()
            scen_max  = scen_grp["_ts"].max()
            scen_eids = set(scen_grp["event_id"])

            # Find alerts on the same user.
            user_alerts = alerts_df[alerts_df["user_id"] == uid]
            for _, alert in user_alerts.iterrows():
                # Build the alert's time window from its event_ids.
                alert_eids = [e.strip() for e in str(alert["event_ids"]).split(";")]
                alert_times = events_df[
                    events_df["event_id"].isin(alert_eids)
                ]["timestamp"].apply(schema.parse_timestamp)

                if alert_times.empty:
                    continue

                alert_min = alert_times.min()
                alert_max = alert_times.max()

                # Overlap check: [scen_min, scen_max] ∩ [alert_min, alert_max] ≠ ∅
                if alert_min <= scen_max and alert_max >= scen_min:
                    scenarios_caught.add(scen_id)
                    break

        recall = (len(scenarios_caught) / len(total_scenarios)
                  if total_scenarios else float("nan"))
        per_policy_metrics.append({
            "seed": seed,
            "total_attack_scenarios": len(total_scenarios),
            "scenarios_caught": len(scenarios_caught),
            "recall": round(recall, 4),
        })

        # --- Per-policy cost/disruption metrics ---
        for policy in policies:
            pol_dec = decisions_df[decisions_df["policy"] == policy]
            pol_alerts = alerts_df.merge(
                pol_dec[["alert_id", "action"]], on="alert_id"
            )
            attacks_stopped     = int(pol_alerts[
                pol_alerts["is_tp"] & (pol_alerts["action"] != "monitor")
            ].shape[0])
            normal_disrupted    = int(pol_alerts[
                ~pol_alerts["is_tp"] & (pol_alerts["action"] != "monitor")
            ].shape[0])
            total_cost          = float(pol_dec["cost"].sum())

            all_results.append({
                "seed":                   seed,
                "policy":                 policy,
                "attacks_stopped":        attacks_stopped,
                "normal_users_disrupted": normal_disrupted,
                "total_cost":             round(total_cost, 2),
            })

        print(" done")

    # Write results.csv.
    _write_csv(output_dir / "results.csv",    schema.RESULTS_COLUMNS,  all_results)
    _write_csv(output_dir / "rule_metrics.csv",
               ["seed", "rule", "tp", "fp", "precision"], rule_metrics)
    _write_csv(output_dir / "recall.csv",
               ["seed", "total_attack_scenarios", "scenarios_caught", "recall"],
               per_policy_metrics)

    # --- Print summary table ---
    _print_summary(all_results, rule_metrics, policies)

    # --- Sensitivity check ---
    print("\nSensitivity check …")
    _sensitivity_check(output_dir, seeds, policies, DEFAULT_COST_TABLE)

    # --- Charts ---
    print("Generating charts …")
    _generate_charts(output_dir, all_results, rule_metrics, policies)

    print(f"\nAll output written to: {output_dir}/")


# ---------------------------------------------------------------------------
# Sensitivity check
# ---------------------------------------------------------------------------

def _sensitivity_check(
    output_dir: Path,
    seeds: list[int],
    policies: list[str],
    base_cost_table: dict,
) -> None:
    """
    Rerun the responder with lock and verify cost variants.
    Report which policy has the lowest mean total cost for each variant.
    """
    import pandas as pd
    from responder.responder import run_responder

    variants = {
        "lock_x2":  {k: (v * 2   if k[0] == "lock" else v) for k, v in base_cost_table.items()},
        "lock_x0.5":{k: (v * 0.5 if k[0] == "lock" else v) for k, v in base_cost_table.items()},
        "verify_x2": {k: (v * 2 if k[0] == "verify" else v) for k, v in base_cost_table.items()},
        "verify_fp_20": {
            k: (20.0 if k == ("verify", False) else v)
            for k, v in base_cost_table.items()
        },
    }

    rows: list[dict] = []

    for variant_name, cost_table in variants.items():
        for seed in seeds:
            seed_dir = output_dir / "runs" / f"seed_{seed}"
            if not (seed_dir / "alerts.csv").exists():
                continue
            decisions = run_responder(
                seed_dir / "alerts.csv",
                seed_dir / "labels.csv",
                seed_dir / f"decisions_{variant_name}.csv",
                policies=policies,
                cost_table=cost_table,
            )
            df = pd.DataFrame(decisions)
            for policy in policies:
                cost = float(df[df["policy"] == policy]["cost"].sum())
                rows.append({"variant": variant_name, "seed": seed,
                             "policy": policy, "total_cost": round(cost, 2)})

    _write_csv(output_dir / "sensitivity.csv",
               ["variant", "seed", "policy", "total_cost"], rows)

    # Print best policy per variant.
    df_all = pd.DataFrame(rows)
    print(f"\n{'Variant':<18}  {'Best policy (lowest mean cost)'}")
    print("-" * 54)
    # Also show baseline.
    base_df = pd.read_csv(output_dir / "results.csv")
    base_best = (base_df.groupby("policy")["total_cost"]
                 .mean().idxmin())
    print(f"{'baseline':<18}  {base_best}")
    for variant in variants:
        sub   = df_all[df_all["variant"] == variant]
        best  = sub.groupby("policy")["total_cost"].mean().idxmin()
        changed = " ← CHANGED" if best != base_best else ""
        print(f"{variant:<18}  {best}{changed}")


# ---------------------------------------------------------------------------
# Charts
# ---------------------------------------------------------------------------

def _generate_charts(
    output_dir: Path,
    results: list[dict],
    rule_metrics: list[dict],
    policies: list[str],
) -> None:
    """
    Produce three Matplotlib charts and save as PNG files.

    Chart 1: Mean total cost per policy (bar chart).
    Chart 2: Attacks stopped vs normal users disrupted per policy (scatter).
    Chart 3: Mean precision per rule (bar chart).
    """
    import pandas as pd
    import matplotlib.pyplot as plt

    charts_dir = output_dir / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)

    df  = pd.DataFrame(results)
    rdf = pd.DataFrame(rule_metrics)

    COLORS = {"always_monitor": "#4CAF50",
              "always_lock":    "#F44336",
              "severity_based": "#2196F3"}
    RULE_COLORS = {"RULE1": "#FF9800", "RULE2": "#9C27B0", "RULE3": "#00BCD4"}

    # --- Chart 1: Mean total cost per policy ---
    fig, ax = plt.subplots(figsize=(8, 5))
    means  = df.groupby("policy")["total_cost"].mean().reindex(policies)
    errors = df.groupby("policy")["total_cost"].std().reindex(policies)
    bars   = ax.bar(means.index, means.values,
                    color=[COLORS[p] for p in means.index],
                    yerr=errors.values, capsize=5, alpha=0.85)
    ax.set_title("Mean Total Cost per Policy (10 seeds ± 1 SD)", fontsize=13)
    ax.set_xlabel("Policy")
    ax.set_ylabel("Mean Total Cost (cost points)")
    ax.bar_label(bars, fmt="%.0f", padding=4)
    plt.tight_layout()
    fig.savefig(charts_dir / "chart1_mean_cost.png", dpi=150)
    plt.close(fig)

    # --- Chart 2: Trade-off scatter ---
    fig, ax = plt.subplots(figsize=(8, 6))
    markers = {"always_monitor": "o", "always_lock": "s", "severity_based": "^"}
    for policy in policies:
        sub = df[df["policy"] == policy]
        ax.scatter(sub["normal_users_disrupted"], sub["attacks_stopped"],
                   label=policy, marker=markers[policy],
                   color=COLORS[policy], s=70, alpha=0.75)
    ax.set_title("Trade-off: Attacks Stopped vs Normal Users Disrupted", fontsize=12)
    ax.set_xlabel("Normal Users Disrupted (FP actions, per seed)")
    ax.set_ylabel("Attacks Stopped (TP actions, per seed)")
    ax.legend()
    plt.tight_layout()
    fig.savefig(charts_dir / "chart2_tradeoff.png", dpi=150)
    plt.close(fig)

    # --- Chart 3: Mean precision per rule ---
    fig, ax = plt.subplots(figsize=(7, 5))
    rules = [r for r in ["RULE1", "RULE2", "RULE3", "RULE4"] if r in rdf["rule"].values]
    RULE_COLORS = {"RULE1": "#FF9800", "RULE2": "#9C27B0", "RULE3": "#00BCD4", "RULE4": "#E91E63"}
    prec_means = [rdf[rdf["rule"] == r]["precision"].mean() for r in rules]
    bars2 = ax.bar(rules, prec_means,
                   color=[RULE_COLORS.get(r, "#607D8B") for r in rules], alpha=0.85)
    ax.set_ylim(0, 1.05)
    ax.set_title("Mean Precision per Rule (10 seeds)", fontsize=13)
    ax.set_xlabel("Rule")
    ax.set_ylabel("Precision  (TP / (TP + FP))")
    ax.bar_label(bars2, fmt="%.2f", padding=4)
    plt.tight_layout()
    fig.savefig(charts_dir / "chart3_precision.png", dpi=150)
    plt.close(fig)

    print(f"  Charts saved → {charts_dir}/")


# ---------------------------------------------------------------------------
# Summary printer
# ---------------------------------------------------------------------------

def _print_summary(
    results: list[dict],
    rule_metrics: list[dict],
    policies: list[str],
) -> None:
    import pandas as pd

    df  = pd.DataFrame(results)
    rdf = pd.DataFrame(rule_metrics)

    print("\n" + "=" * 75)
    print(" 1. POLICY COMPARISON SUMMARY (Averaged across all 10 simulation seeds)")
    print("=" * 75)
    print(" • attacks_stopped        : Attacks prevented (higher is better)")
    print(" • normal_users_disrupted : Innocent users blocked by false alarms (lower is better)")
    print(" • total_cost             : Impact penalty points (lower is better)")
    print("-" * 75)
    summary = (df.groupby("policy")[["attacks_stopped",
                                     "normal_users_disrupted",
                                     "total_cost"]]
               .mean().round(2).reindex(policies))
    print(summary.to_string())
    print("-" * 75)

    print("\n" + "=" * 75)
    print(" 2. INTRUSION DETECTION RULE PERFORMANCE (Precision = TP / (TP + FP))")
    print("=" * 75)
    print(" • tp        : True Positive alerts (caught a real injected attack)")
    print(" • fp        : False Positive alerts (flagged an innocent user's activity)")
    print(" • precision : Accuracy when alerting (1.0 = 100% clean, no false alarms)")
    print("-" * 75)
    rsum = rdf.groupby("rule")[["tp", "fp", "precision"]].mean().round(3)
    print(rsum.to_string())
    print("-" * 75)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _write_csv(path: Path, fieldnames: list[str], rows: list[dict]) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


# ---------------------------------------------------------------------------
# CLI: python evaluator/evaluator.py [output_dir]
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/output")
    run_evaluation(_out)

