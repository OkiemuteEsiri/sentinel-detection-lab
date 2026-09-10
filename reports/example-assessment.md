# Example Sentinel Detection Assessment

Synthetic defensive telemetry only.

## Executive summary

The sample dataset demonstrates four investigation patterns: a privileged sign-in without MFA, encoded PowerShell execution, remote-logon fan-out across three hosts, and security telemetry impairment. These findings are intentionally synthetic and illustrate prioritization and analyst workflow rather than real compromise.

| Severity | Detection | ATT&CK | Primary response |
|---|---|---|---|
| Critical | Security telemetry impairment | T1562.001, T1070.001 | Restore telemetry, preserve evidence, validate authorization |
| High | Privileged sign-in without MFA | T1078 | Enforce MFA/Conditional Access and review account activity |
| High | Encoded PowerShell execution | T1059.001 | Validate parent process/user and inspect script telemetry |
| Medium | Remote logon fan-out | T1021, T1078 | Confirm admin intent and investigate lateral-movement context |

## Validation standard

A finding is not considered confirmed solely because an analytic fired. Closure requires documented analyst disposition, remediation evidence where applicable, and post-change validation showing the control or behaviour is no longer present outside approved exceptions.
