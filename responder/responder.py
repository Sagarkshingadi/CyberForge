"""
responder.py — Response policies and cost table.

Person C owns this module.

Three policies are compared; all run on the same alerts so only the
policy differs — not the data.

Cost table (stated assumptions — defend in the viva):
  These values are placeholders chosen to reflect qualitative ordering
  described in the brief.  The sensitivity check in the evaluator tests
  whether the best policy changes when lock costs are doubled or halved.

  | Action  | On real attack | On normal user |
  |---------|---------------|----------------|
  | monitor |     100        |       0        |  missed attack = high cost
  | verify  |      20        |       5        |  friction = low cost
  | lock    |      10        |      50        |  disruption = high cost

Units are arbitrary cost points, not £/$.
"""

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import schema

# ---------------------------------------------------------------------------
# Cost table
# ---------------------------------------------------------------------------

# Default cost table: (action, is_attack) → cost points.
# Passed explicitly to run_responder so the sensitivity check can substitute
# scaled versions without changing the source code.
DEFAULT_COST_TABLE: dict[tuple[str, bool], float] = {
    ("monitor", True):  100.0,
    ("monitor", False):   0.0,
    ("verify",  True):   20.0,
    ("verify",  False):   5.0,
    ("lock",    True):   10.0,
    ("lock",    False):  50.0,
}


# ---------------------------------------------------------------------------
# Policy logic
# ---------------------------------------------------------------------------

def _policy_action(policy: str, rule_id: str) -> str:
    """
    Return the action string for a given policy name and rule.

    Policies
    --------
    always_monitor   Baseline: monitor every alert (do nothing).
    always_lock      Baseline: lock on every alert (maximum response).
    severity_based   Lock on Rule1/Rule2 (high confidence), verify on Rule3
                     (lower confidence — could be legitimate admin activity).
    """
    if policy == "always_monitor":
        return "monitor"
    if policy == "always_lock":
        return "lock"
    if policy == "severity_based":
        # Rule 1 and 2 suggest active credential attack → lock.
        # Rule 3 alone could be legitimate → verify (ask user to confirm).
        return "lock" if rule_id in {"RULE1", "RULE2"} else "verify"
    raise ValueError(f"Unknown policy: {policy!r}.  "
                     f"Choose from: {list(schema.ACTIONS)}")


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def run_responder(
    alerts_path: Path,
    labels_path: Path,
    decisions_path: Path,
    policies: list[str] | None = None,
    cost_table: dict[tuple[str, bool], float] | None = None,
) -> list[dict]:
    """
    Apply each policy to every alert, compute costs, and write decisions.csv.

    The responder is allowed to read labels.csv because it needs to know
    whether each alerted event was a real attack in order to look up the
    correct cost.  (In a real system the label would be unknown; here it
    is used only for simulation accounting.)

    Args:
        alerts_path:    Path to alerts.csv.
        labels_path:    Path to labels.csv.
        decisions_path: Path to write decisions.csv.
        policies:       Policy names to apply (default: all three).
        cost_table:     Cost lookup (default: DEFAULT_COST_TABLE).

    Returns:
        List of decision dicts (one per alert × policy).
    """
    import pandas as pd

    if policies is None:
        policies = ["always_monitor", "always_lock", "severity_based"]
    if cost_table is None:
        cost_table = DEFAULT_COST_TABLE

    alerts_df = pd.read_csv(alerts_path)
    schema.validate_columns(alerts_df, schema.ALERTS_COLUMNS)

    labels_df = pd.read_csv(labels_path)
    schema.validate_columns(labels_df, schema.LABELS_COLUMNS)

    # Build event_id → is_attack lookup.
    is_attack_map: dict[str, bool] = dict(
        zip(labels_df["event_id"],
            labels_df["is_attack"].astype(bool))
    )

    def _alert_is_attack(event_ids_str: str) -> bool:
        """An alert is a true positive if ANY involved event is labelled is_attack."""
        return any(
            is_attack_map.get(eid.strip(), False)
            for eid in event_ids_str.split(";")
        )

    decisions: list[dict] = []

    for _, alert in alerts_df.iterrows():
        is_atk = _alert_is_attack(str(alert["event_ids"]))
        for policy in policies:
            action = _policy_action(policy, alert["rule_id"])
            cost   = cost_table[(action, is_atk)]
            decisions.append({
                "alert_id": alert["alert_id"],
                "policy":   policy,
                "action":   action,
                "cost":     cost,
            })

    decisions_path = Path(decisions_path)
    decisions_path.parent.mkdir(parents=True, exist_ok=True)
    with open(decisions_path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=schema.DECISIONS_COLUMNS)
        writer.writeheader()
        writer.writerows(decisions)

    return decisions


# ---------------------------------------------------------------------------
# CLI: python responder/responder.py <alerts.csv> <labels.csv> <decisions.csv>
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    _alerts    = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("data/generated/alerts.csv")
    _labels    = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("data/generated/labels.csv")
    _decisions = Path(sys.argv[3]) if len(sys.argv) > 3 else Path("data/generated/decisions.csv")
    result     = run_responder(_alerts, _labels, _decisions)
    print(f"Generated {len(result)} decisions → {_decisions}")

