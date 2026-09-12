# Detection Validation Matrix

This matrix makes the validation standard explicit: a detection is not considered mature solely because the query parses or returns rows. Each analytic should have a defined behavior, telemetry dependency, expected evidence, tuning boundary, and revalidation condition.

| Detection / control | Primary telemetry | ATT&CK context | Validation evidence | Common benign context | Revalidation condition |
|---|---|---|---|---|---|
| Encoded PowerShell | Process creation / `DeviceProcessEvents` | T1059.001 | Expected synthetic encoded-command event produces a finding with preserved command-line evidence | Approved automation, packaging, administration frameworks | Known-positive fixture remains detected after any query or exclusion change |
| Remote logon fan-out | Logon / `DeviceLogonEvents` | T1021, T1078 | One source/account pair crossing the configured host threshold produces a correlated finding | Jump hosts, scanners, patch systems, service accounts | Threshold and exclusion changes still detect the known-positive multi-host fixture |
| Security-control impairment | Endpoint audit / `DeviceEvents` | T1562.001, T1070.001 | Synthetic impairment event produces a finding tied to device, actor, action, and time | Approved maintenance or controlled security tooling changes | Authorized maintenance can be excluded narrowly while the impairment fixture remains detectable |
| Privileged sign-in without MFA | Identity sign-in telemetry | T1078 | Privileged successful sign-in without expected MFA produces a finding | Break-glass procedures or documented emergency access | Exceptions are identity-specific/time-bounded and the known-positive fixture remains detected |

## Validation states

Use the following states when discussing detection maturity:

- **Designed** — behavioral intent, telemetry assumptions, ATT&CK context, and initial query are documented.
- **Structurally validated** — metadata, schema expectations, query quality, and deterministic identifiers pass local checks.
- **Behaviorally validated** — authorized synthetic or lab telemetry demonstrates that the analytic detects the intended behavior.
- **Tuned** — known-benign context has been reduced through narrow, documented exclusions or thresholds.
- **Revalidated** — the tuned analytic still detects the known-positive fixture and required telemetry remains healthy.
- **Degraded** — required telemetry is absent, delayed, malformed, or otherwise unable to support the stated detection objective.

## Evidence quality

| Level | Evidence | Interpretation |
|---|---|---|
| 1 | Query exists or ticket states that a rule was created | Administrative evidence only; not sufficient for technical validation |
| 2 | Query parses and metadata/catalog checks pass | Structural evidence; useful but does not prove behavioral detection |
| 3 | Known-positive synthetic/lab fixture produces the expected finding | Behavioral validation under controlled conditions |
| 4 | Positive and negative fixtures, tuning regression, telemetry-health checks, and documented re-test results | Strongest evidence represented by this public lab model |

## Tuning guardrails

Tuning should reduce expected benign activity without deleting the behavioral signal. Prefer narrowly scoped identity, host, signer, maintenance-window, or process-context exclusions. Avoid broad suppression based solely on a command name, generic administrator role, subnet, or high-volume source when that exclusion could mask the intended behavior.

Every tuning change should answer three questions:

1. What specific benign condition is being excluded?
2. What evidence shows that the exclusion is safe and bounded?
3. Which known-positive fixture proves the analytic still detects the intended behavior after the change?

## Closure rule

A detection-related remediation item is not technically closed because a ticket is closed, a query was edited, or an exception was approved. Closure requires evidence that the original gap is resolved and that the analytic still behaves as intended during revalidation. Risk acceptance should remain a separate governance state rather than being represented as technical remediation.