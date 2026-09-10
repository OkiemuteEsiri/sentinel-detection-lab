# Detection Engineering Methodology

## Objective

This lab demonstrates how Microsoft Sentinel / Microsoft Defender telemetry can be translated into explainable defensive analytics with explicit assumptions, ATT&CK context, triage guidance and validation requirements.

## Workflow

1. Define the behavior to detect rather than starting from a product alert name.
2. Identify the minimum telemetry tables and fields needed to express the behavior.
3. Implement the KQL with bounded time windows and explicit filters.
4. Add ATT&CK mappings as threat context, not as evidence of compromise.
5. Validate query structure and metadata through the local Python catalog checks.
6. Exercise detections against authorized synthetic or lab telemetry.
7. Tune known-benign activity using documented, narrow exclusions.
8. Re-test after tuning to ensure true-positive coverage remains intact.

## Included analytics

### Encoded PowerShell
Detects PowerShell or pwsh command lines containing common encoded-command indicators. ATT&CK T1059.001. Expected benign sources can include administration frameworks, packaging systems and approved automation, so command line, signer, parent process, account and device context should be reviewed before escalation.

### Remote logon fan-out
Surfaces accounts and source IPs that authenticate across an unusual number of endpoints within a short window. ATT&CK T1021 and T1078. Analysts should validate jump hosts, scanners, service accounts, patch infrastructure, administrative windows and expected automation.

### Security-control impairment
Surfaces endpoint-protection tampering or disablement telemetry. ATT&CK T1562.001. Investigation should correlate the action with initiating process, identity, change windows, endpoint-health state and subsequent suspicious activity.

## Triage standard

Every alert should preserve the original evidence and answer: who acted, from where, on which asset, what preceded the event, what followed it, whether the activity was authorized, and whether the pattern is isolated or fleet-wide. Severity reflects analytical priority; confidence reflects evidence quality. Neither should be interpreted as proof of compromise.

## Remediation and validation

Confirmed incidents should follow approved containment and incident-response procedures. Potential actions can include account containment, endpoint isolation, control restoration and hunting for related behavior. Closure requires validation that the risky condition or behavior no longer appears and that affected controls are healthy. Exceptions and suppressions should be documented, attributable and time-bounded.

## Limitations

These KQL examples are portable defensive patterns rather than production-ready tenant rules. Table availability, field names, ingestion latency, baselines and thresholds vary between environments. No customer or employer telemetry is included.
