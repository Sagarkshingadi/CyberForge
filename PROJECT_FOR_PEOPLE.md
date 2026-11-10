# CyberForge Lite: An Easy Guide for Friends and Teachers

## The story

Imagine a college library with an online account for each student. CyberForge Lite is a pretend security guard that watches pretend login records. Some students make normal password mistakes, while pretend attackers try to guess passwords. The project tests alarms and guards in synthetic data; it does not protect a real library.

## The three alarms and optional fourth alarm

- **Rule 1 — quick guesses:** Sounds when one user has **five or more failed logins within five minutes**. Four failures are not enough.
- **Rule 2 — guesses then success:** Sounds when a user successfully logs in after **at least three failures within the previous ten minutes**.
- **Rule 3 — account change:** Sounds when an account or privilege change happens within **30 minutes after a successful login**.
- **Rule 4 — repeated failures:** **With Rule 4 turned on**, sounds when a user has **four or more new failed logins within a 60-minute window**. Rule 4 catches patterns that meet that threshold; it does not catch every slow attack.

## The three guards

- **Sleepy Guard (`always_monitor`):** Records alerts and takes no action.
- **Strict Guard (`always_lock`):** Locks the account for every alert.
- **Careful Guard (`severity_based`):** Locks for Rules 1 and 2; verifies the user for Rule 3 and, **with Rule 4 turned on**, Rule 4. Rule 3 can flag ordinary administrator work. With Rule 4 turned on, repeated mistakes by a forgetful user can also trigger an alert.

The project uses pretend **penalty points**. Locking can stop an attacker, while a mistaken lock disrupts an innocent student. Verification is a gentler response. These costs are assumptions, not real-world measurements.

## Walkthrough: `user_17`

Imagine someone guesses `user_17`’s password incorrectly at 9:00, 9:06, 9:12, and 9:18, then logs in successfully at 9:24.

1. Rule 1 stays quiet: there are only four failures, spread across more than five minutes.
2. Rule 2 stays quiet: at 9:24, only the 9:18 failure falls within the previous ten minutes, and the rule needs at least three failures in that window.
3. Rule 3 stays quiet: there is no account or privilege change after the login.
4. **With Rule 4 turned on**, Rule 4 sounds because all four failures happened within an hour.

The useful viva sentence is: **“Rule 2 stays quiet in the walkthrough because only one failure falls in its ten-minute window, and Rule 4 is what catches that pattern.”**

The same Rule 4 alarm can also go off for an innocent student who forgets a password. That is a trade-off. After an alert, the sleepy guard monitors, the strict guard locks, and the careful guard verifies for this Rule 4 alert.

## Results

| Run | `severity_based` | `always_lock` | `always_monitor` |
|---|---:|---:|---:|
| Baseline, Rule 4 off | **759.5 penalty points** | **3,015 penalty points** | **3,800 penalty points** |
| Separate clean run, with Rule 4 turned on | **961 penalty points** | **3,244 penalty points** | **4,740 penalty points** |

In the baseline, Rule 3 precision is **13.3%**. With Rule 4 turned on, compromise recall is **32 of 44 (72.7%)**, and brute-force recall is **6.2 of 6.2**.

“Attacks stopped” counts alerts, not attacks. Lock and verify count the same in “attacks stopped” and “users disrupted”; only their costs differ. Costs are assumptions, tested only for lock and verify cost in the sensitivity check. The data is synthetic.

## Folder map

- `generator/` makes pretend login events and their separate answer labels.
- `detector/` checks event records and creates alerts.
- `responder/` applies monitor, lock, or verify and calculates penalty points.
- `redteam/` contains scripted pretend attacker patterns.
- `evaluator/` scores runs and creates summaries and charts.
- `scripts/` contains helper commands.
- `tests/` contains automated checks.
- `data/` stores sample and simulation data.

## A couple of `run.bat` notes

- **Button [1]** runs the automated test suite, which has **23 tests**.
- **Button [9]** demonstrates a delayed takeover: the attacker waits before succeeding, but Rule 1 still alerts on the initial burst of failures.

## Likely viva questions

**What is CyberForge Lite?**  
A simulator that creates pretend login records, checks them for suspicious patterns, and compares responses.

**Why are labels separate from events?**  
The detector must decide from the event records; the evaluator uses the answer labels afterward to score it.

**Why does Rule 2 stay quiet for `user_17`?**  
At 9:24 only one failure is in the previous ten minutes, but Rule 2 needs at least three.

**What does Rule 4 add?**  
With Rule 4 turned on, it can alert on four or more new failures by one user within an hour, even when they are too spread out for Rule 1.

**What is a false alarm?**  
An alert caused by ordinary activity, such as a student forgetting a password.

**What does precision mean?**  
The share of alerts that match labelled attacks.

**What does recall mean?**  
The share of labelled attack scenarios that were caught.

**Does this prove it will work the same way at a real library?**  
No. The project uses synthetic data and assumed penalty points.
