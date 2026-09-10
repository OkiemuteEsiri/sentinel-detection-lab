# Architecture and Methodology

## Purpose

This repository demonstrates a defensive Microsoft Sentinel-style detection engineering workflow using synthetic telemetry. It models how normalized events can be transformed into explainable findings that support analyst triage, remediation and revalidation.

## Processing flow

`Synthetic telemetry -> validation -> UTC normalization -> detection analytics -> evidence-preserving finding -> severity/confidence -> analyst triage -> remediation -> validation`

The implementation deliberately separates event ingestion from detection logic so new analytics can be added without changing the telemetry model.

## Detection coverage

- Privileged successful sign-in without MFA — ATT&CK T1078.
- Encoded PowerShell execution — ATT&CK T1059.001.
- Remote-logon fan-out — ATT&CK T1021 and T1078.
- Security telemetry/logging impairment — ATT&CK T1562.001 and T1070.001.

ATT&CK mappings provide adversary-behaviour context. They are not proof of compromise and should never replace evidence-based investigation.

## Confidence and severity

Severity represents potential security impact. Confidence represents how strongly the observed telemetry matches the analytic. Keeping these dimensions separate prevents a high-impact hypothesis from being misrepresented as high-certainty compromise.

## Validation workflow

1. Confirm event source, timestamp scope and parser integrity.
2. Validate the account, endpoint and source-network context.
3. Review expected administration/change activity.
4. Correlate related identity, endpoint and network events.
5. Escalate when evidence supports unauthorized behaviour.
6. Apply containment/remediation using approved operational procedures.
7. Re-run the analytic against post-change telemetry and document validation evidence.

## False-positive considerations

Legitimate privileged administration, automation accounts, approved remote-management activity and security testing can resemble suspicious patterns. Production detections therefore require allowlisting, maintenance-window context, entity baselines and time-window tuning.

## Limitations

This lab does not connect to a live Sentinel workspace, execute KQL against production data, impair controls, run offensive payloads or claim that synthetic findings reflect real incidents. It demonstrates detection engineering, data modelling, triage logic and remediation design only.
