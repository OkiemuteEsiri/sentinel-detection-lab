# Microsoft Sentinel Detection Engineering Lab

A defensive detection-engineering portfolio project focused on Microsoft Sentinel / Microsoft Defender-style telemetry, KQL analytics, ATT&CK mapping, validation, tuning and incident-response handoff.

## Problem statement

Detection programs fail when analytics are created without clear behavioral intent, telemetry assumptions, testability or remediation context. This lab demonstrates a structured approach for turning observable endpoint and identity behavior into explainable KQL detections that can be reviewed, validated, tuned and maintained.

## Architecture

```text
Endpoint / identity telemetry
        |
        v
Behavior hypothesis
        |
        v
KQL analytic rule
        |
        v
Detection catalog + validation
        |
        v
Alert triage / investigation
        |
        v
Containment -> remediation -> re-test
```

## Included detections

| Detection | Data source | ATT&CK | Purpose |
|---|---|---|---|
| Encoded PowerShell | `DeviceProcessEvents` | T1059.001 | Surface suspicious encoded or base64-oriented PowerShell execution for analyst review |
| Remote logon fan-out | `DeviceLogonEvents` | T1021, T1078 | Identify identities authenticating across an unusual number of endpoints in a short period |
| Security control impairment | `DeviceEvents` | T1562.001 | Surface endpoint protection tampering or disablement telemetry |

These detections are intentionally defensive and require analyst validation. A match is not proof of compromise.

## Repository structure

```text
detections/
  encoded-powershell.kql
  remote-logon-fanout.kql
  security-control-impairment.kql
src/
  detection_catalog.py
tests/
  test_detection_catalog.py
docs/
  methodology.md
.github/workflows/
  ci.yml
```

## Detection engineering controls

The local Python catalog provides deterministic detection IDs, metadata validation, ATT&CK-ID format checks, required-table assertions and simple query-quality checks for filters and output shaping. This makes the repository more than a loose collection of KQL snippets: analytics are treated as maintained engineering artifacts.

## Validation approach

The unit suite covers catalog integrity, deterministic IDs, invalid severity rejection, invalid ATT&CK mappings, missing filters, missing data tables, missing ATT&CK annotations and missing repository files. CI compiles the Python modules and runs the unit test suite with read-only repository permissions.

Run locally with:

```bash
python -m unittest discover -s tests -v
```

## Triage methodology

Analysts should validate identity, device, process ancestry, source IP, time window, administrative context and expected automation before escalating. Narrow, documented exclusions are preferred over broad suppression. Tuning must be followed by re-testing to confirm true-positive coverage was not removed.

## Remediation and revalidation

Confirmed incidents should follow authorized response procedures such as identity containment, endpoint isolation, security-control restoration and related-activity hunting. Closure should include evidence that the suspicious behavior has ceased and affected controls are healthy.

## Skills demonstrated

Microsoft Sentinel concepts, KQL detection development, Microsoft Defender telemetry reasoning, detection-as-code practices, MITRE ATT&CK mapping, analytic validation, false-positive analysis, SOC triage, incident-response handoff, Python testing and CI hygiene.

## Limitations

This is a public lab using portable patterns rather than production tenant data. Schema availability, ingestion latency, thresholds and field behavior vary by environment. No employer/client telemetry, production targets, credentials, exploit payloads or offensive automation are included.

## Roadmap

- add synthetic tabular event fixtures for offline detection simulation
- add scheduled-task and privileged-group-change detections
- add severity/confidence metadata and rule ownership
- add analytics-rule ARM/Bicep examples using non-secret placeholders
- add detection coverage matrix and validation reports
- add KQL linting and regression fixtures

## Safety

All content is designed for defensive detection engineering and authorized lab validation only.
