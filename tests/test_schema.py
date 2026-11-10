"""
tests/test_schema.py — pytest suite for Phase 1 acceptance criteria.

Tests:
1. sample_events.csv has exactly the expected columns.
2. sample_labels.csv has exactly the expected columns.
3. All timestamps in events parse with TIMESTAMP_FORMAT.
4. All event_type values are in the allowed set.
5. All source values are in the allowed set.
6. All scenario_type values are in the allowed set.
7. Every event_id in events appears in labels (and vice versa).
"""

import sys
from pathlib import Path
import pytest
import pandas as pd

# Allow imports from the project root
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import schema

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
EVENTS_PATH = DATA_DIR / "sample_events.csv"
LABELS_PATH = DATA_DIR / "sample_labels.csv"


@pytest.fixture(scope="module")
def events_df():
    return pd.read_csv(EVENTS_PATH)


@pytest.fixture(scope="module")
def labels_df():
    return pd.read_csv(LABELS_PATH)


# ---------------------------------------------------------------------------
# 1 & 2 — Column names
# ---------------------------------------------------------------------------

def test_events_columns(events_df):
    """sample_events.csv must have exactly the columns defined in schema.py."""
    schema.validate_columns(events_df, schema.EVENTS_COLUMNS)


def test_labels_columns(labels_df):
    """sample_labels.csv must have exactly the columns defined in schema.py."""
    schema.validate_columns(labels_df, schema.LABELS_COLUMNS)


# ---------------------------------------------------------------------------
# 3 — Timestamps
# ---------------------------------------------------------------------------

def test_timestamps_parse(events_df):
    """Every timestamp must parse with TIMESTAMP_FORMAT without error."""
    for ts in events_df["timestamp"]:
        parsed = schema.parse_timestamp(ts)
        # Round-trip: re-formatted string must match original
        assert schema.format_timestamp(parsed) == ts, (
            f"Timestamp round-trip failed for: {ts!r}"
        )


# ---------------------------------------------------------------------------
# 4 — event_type values
# ---------------------------------------------------------------------------

def test_event_type_values(events_df):
    """All event_type values must be in schema.EVENT_TYPES."""
    bad = set(events_df["event_type"]) - schema.EVENT_TYPES
    assert not bad, f"Unknown event_type values: {bad}"


# ---------------------------------------------------------------------------
# 5 — source values
# ---------------------------------------------------------------------------

def test_source_values(events_df):
    """All source values must be in schema.SOURCES."""
    bad = set(events_df["source"]) - schema.SOURCES
    assert not bad, f"Unknown source values: {bad}"


# ---------------------------------------------------------------------------
# 6 — scenario_type values
# ---------------------------------------------------------------------------

def test_scenario_type_values(labels_df):
    """All scenario_type values must be in schema.SCENARIO_TYPES."""
    bad = set(labels_df["scenario_type"]) - schema.SCENARIO_TYPES
    assert not bad, f"Unknown scenario_type values: {bad}"


# ---------------------------------------------------------------------------
# 7 — event_id cross-reference
# ---------------------------------------------------------------------------

def test_every_event_id_in_labels(events_df, labels_df):
    """Every event_id in events must appear in labels."""
    event_ids = set(events_df["event_id"])
    label_ids = set(labels_df["event_id"])
    missing = event_ids - label_ids
    assert not missing, f"event_ids in events but not in labels: {missing}"


def test_every_label_id_in_events(events_df, labels_df):
    """Every event_id in labels must appear in events."""
    event_ids = set(events_df["event_id"])
    label_ids = set(labels_df["event_id"])
    extra = label_ids - event_ids
    assert not extra, f"event_ids in labels but not in events: {extra}"


# ---------------------------------------------------------------------------
# 8 — Boolean sanity for 'success' field
# ---------------------------------------------------------------------------

def test_success_is_boolean(events_df):
    """The 'success' column must contain only True/False (boolean) values."""
    allowed = {True, False}
    bad = set(events_df["success"]) - allowed
    assert not bad, f"Non-boolean values in 'success': {bad}"

