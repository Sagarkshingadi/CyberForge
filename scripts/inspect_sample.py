"""
inspect_sample.py — Quick sanity check for the sample dataset.

Loads sample_events.csv, validates its columns against schema.py,
and prints failed-login counts per user.

Usage:
    python scripts/inspect_sample.py

This script must NOT open labels.csv.
"""

import sys
from pathlib import Path
import pandas as pd

# Allow imports from the project root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import schema

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
EVENTS_FILE = DATA_DIR / "sample_events.csv"


def main() -> None:
    df = pd.read_csv(EVENTS_FILE)

    # Validate columns — raises ValueError with a clear diff on mismatch
    schema.validate_columns(df, schema.EVENTS_COLUMNS)

    # Validate timestamps — will raise if any value doesn't match the format
    df["timestamp"] = df["timestamp"].apply(schema.parse_timestamp)

    failed = (
        df[(df["event_type"] == "login_attempt") & (df["success"] == False)]
        .groupby("user_id")
        .size()
        .sort_values(ascending=False)
    )

    print("=== Failed login counts per user ===")
    if failed.empty:
        print("  (none)")
    else:
        for user, count in failed.items():
            print(f"  {user:<15} {count}")

    total_events = len(df)
    total_failed = int(failed.sum()) if not failed.empty else 0
    print(f"\nTotal events loaded : {total_events}")
    print(f"Total failed logins : {total_failed}")
    print("\nColumns OK. Sample data loads successfully.")


if __name__ == "__main__":
    main()

