# CyberForge Lite: Project Reference for AI Tools

Use this file as the current source of project context. Keep the baseline and the optional Rule 4 experiment separate. Do not infer results that are not listed here.

## Project purpose and data flow

CyberForge Lite generates synthetic login events and separate ground-truth labels, detects suspicious activity from events alone, applies response policies, and evaluates outcomes against labels. The detector must never read `labels.csv`; labels are for responder/evaluator accounting after detection.

## Schema authority

`schema.py` is the single source of truth for column names, timestamp format, thresholds, and shared constants. Do not hardcode a conflicting schema or threshold elsewhere.

## Folder map

- `generator/`: creates seeded synthetic events and attack labels.
- `detector/`: applies Rules 1–3 by default and includes Rule 4 only when its optional flag is enabled.
- `responder/`: applies `always_monitor`, `always_lock`, and `severity_based`, then assigns assumed penalty-point costs.
- `redteam/`: scripted attack/evasion patterns.
- `evaluator/`: multi-seed evaluation, metrics, sensitivity checks, and chart generation.
- `scripts/`: command-line and utility scripts.
- `tests/`: automated tests; the suite count is **23 tests**.
- `data/canonical/`: verified three-rule baseline data and source folder for its charts.
- `data/canonical_rule4/`: clean, separate evaluation with Rule 4 turned on.
- `data/`: other sample and generated data; do not treat unverified outputs as canonical.

## Exact detector rules

1. **Rule 1:** For a given user, at least 5 failed `login_attempt` events within a forward/sliding 5-minute window trigger an alert.
2. **Rule 2:** A successful `login_attempt` triggers an alert when that same user has at least 3 failed login attempts in the previous 10 minutes (failures at or before success and no earlier than success minus ten minutes).
3. **Rule 3:** An `account_change` or `privilege_change` triggers an alert when the same user had a successful login within the previous 30 minutes.
4. **Rule 4 (optional):** Applied only with Rule 4 turned on. It groups new failed logins per user in anchored forward 60-minute windows. A window triggers at 4 or more new failures; failures included in an earlier Rule 4 alert are no longer new. The alert includes all new failures in that window and is timestamped at the anchor failure.

**Rule 4 design sentence from `STATUS.md`:** “With Rule 4 turned on, it fires once per user per 60-minute window that contains 4 or more new failures, where a failure already included in an earlier Rule 4 alert is not new.”

## Response and measurement semantics

- `always_monitor` maps every alert to monitor; `always_lock` maps every alert to lock.
- `severity_based` locks Rules 1 and 2, verifies Rule 3, and verifies Rule 4 only with Rule 4 turned on.
- “Attacks stopped” counts alerts with a non-monitor response, not distinct attacks.
- Lock and verify count the same in attacks stopped and innocent users disrupted; only their costs differ.
- Costs are stated assumptions. The sensitivity check tests lock and verify cost changes only.

## Verified results only

| Run | `severity_based` cost | `always_lock` cost | `always_monitor` cost |
|---|---:|---:|---:|
| Baseline, Rule 4 off | **759.5 penalty points** | **3,015 penalty points** | **3,800 penalty points** |
| Clean rerun, with Rule 4 turned on | **961 penalty points** | **3,244 penalty points** | **4,740 penalty points** |

- Baseline Rule 3 precision: **13.3%**.
- With Rule 4 turned on: compromise recall **32 of 44 (72.7%)**; brute-force recall **6.2 of 6.2**.
- All data is synthetic. Never imply these are production-system guarantees.

## Known caveats and provenance

- Rule 4 was redesigned mid-project; all earlier Rule 4 numbers are superseded. Use only the clean `data/canonical_rule4/` rerun for Rule 4 results.
- The first clean Rule 4 run attempt encountered a permission issue; the second run completed cleanly.
- `data/canonical/` is the baseline canonical folder; `data/canonical_rule4/` is the separate Rule 4 canonical folder.
- Some verification was performed by AI tools, not by this assistant. Run `pytest` yourself before presenting or claiming current test status; the known suite count is 23.
- Treat `cli.py redteam` and `cli.py evasion-report` as optional; their operation has not been confirmed.
- The literature section has not yet been written. Cite only the four supplied references, and phrase their support as “argues” or “motivated by”; do not invent citations or claim stronger proof.
- Author names remain placeholders.

## Do not

- Do not quote superseded numbers: **746, 3,153, 3,630, 12.2%, 36.3, 55.8, 4.5x, 74.8%, 76.5%**.
- Do not present Rule 4 as always on; say **“with Rule 4 turned on”** and describe its results as a separate run from the baseline.
- Do not claim the detector reads labels. It only reads event records; labels are used later for evaluation/accounting.
- Do not treat attacks-stopped counts as unique attacks.
- Do not describe assumed costs as measured real-world losses; use “penalty points.”
- Do not claim test results unless `pytest` was run; the suite contains 23 tests.
