# MITRE ATT&CK Mapping

ATT&CK mappings in this repository are used to explain the behavior a detection is intended to surface. They are investigation and coverage context only. A rule match does not establish compromise, attribution, intent, or successful technique execution.

| Detection | ATT&CK technique | Why it is relevant | Required analyst caution |
|---|---|---|---|
| Encoded PowerShell | T1059.001 — PowerShell | Encoded or obfuscated PowerShell can appear in suspicious command execution as well as legitimate administration | Validate parent process, signer, user, device, script context, and approved automation before escalation |
| Remote logon fan-out | T1021 — Remote Services | Authentication across multiple systems can be associated with remote administration or lateral movement | Jump hosts, service accounts, patching, scanners, and maintenance windows can create similar patterns |
| Remote logon fan-out | T1078 — Valid Accounts | Legitimate credentials may be used across multiple endpoints | The detection shows account usage patterns, not credential theft or malicious intent |
| Security-control impairment | T1562.001 — Impair Defenses: Disable or Modify Tools | Endpoint security controls may be disabled or modified during malicious activity | Authorized maintenance and approved security-tool operations can produce related telemetry |
| Security-control impairment | T1070.001 — Clear Windows Event Logs | Loss or clearing of audit evidence can reduce investigation visibility | Telemetry loss must be corroborated with device, actor, and change context before drawing conclusions |
| Privileged sign-in without MFA | T1078 — Valid Accounts | Privileged authentication without the expected MFA control increases identity risk | Break-glass or documented emergency access can be legitimate and must be validated against policy |

## Mapping standard

For each detection, the repository aims to keep four concepts separate:

1. **Observed evidence** — the process, authentication, audit, or identity event actually present in telemetry.
2. **Detection inference** — the behavior the analytic is designed to surface.
3. **ATT&CK context** — a technique that may be relevant to investigation or coverage reporting.
4. **Incident conclusion** — a separate analyst determination requiring corroborating evidence.

This separation prevents a common reporting error: converting a telemetry match directly into an assertion that an adversary executed a particular ATT&CK technique.

## Coverage limitations

A mapped detection should not be interpreted as comprehensive coverage of an ATT&CK technique. Each analytic covers only the observable behavior represented by its telemetry, query logic, thresholds, and environmental assumptions. Technique-level coverage should therefore be described with explicit data-source and validation caveats.