# Microsoft Sentinel Detection Engineering Lab

A defensive detection-engineering portfolio project focused on Microsoft Sentinel / Microsoft Defender-style telemetry, KQL analytics, ATT&CK mapping, executable offline detection simulation, validation, tuning and incident-response handoff.

## Problem statement

Detection programs fail when analytics are created without clear behavioral intent, telemetry assumptions, testability or remediation context. This lab demonstrates a structured approach for turning observable endpoint and identity behavior into explainable KQL detections and executable Python analytics that can be reviewed, validated, tuned and maintained.

## Architecture

```text
Synthetic / Sentinel-style telemetry
        |
        v
Schema validation + UTC normalization
        |
        +-------------------+
        |                   |
        v                   v
KQL analytics        Python simulation engine
        |                   |
        +---------+---------+
                  v
       Evidence-preserving findings
                  |
                  v
      Severity + confidence + ATT&CK
                  |
                  v
      Analyst triage / investigation
                  |
                  v
      Containment -> remediation -> re-test
```

## Included detections

| Detection | Data source / model | ATT&CK | Purpose |
|---|---|---|---|
| Encoded PowerShell | `DeviceProcessEvents` / process events | T1059.001 | Surface suspicious encoded PowerShell execution for analyst review |
| Remote logon fan-out | `DeviceLogonEvents` / sign-in events | T1021, T1078 | Identify identities authenticating across multiple endpoints |
| Security control impairment | `DeviceEvents` / audit events | T1562.001, T1070.001 | Surface security-control or logging impairment telemetry |
| Privileged sign-in without MFA | identity sign-in events | T1078 | Identify privileged successful authentication without expected MFA |

A detection match is not proof of compromise. ATT&CK mappings provide investigation context only.

## Repository structure

```text
detections/
  encoded-powershell.kql
  remote-logon-fanout.kql
  security-control-impairment.kql
src/
  detection_catalog.py
  models.py
  detections.py
  io.py
  cli.py
data/
  synthetic_sentinel_events.json
tests/
  test_detection_catalog.py
  test_detections.py
docs/
  methodology.md
  architecture-methodology.md
reports/
  example-assessment.md
.github/workflows/
  ci.yml
```

## Detection engineering controls

The repository combines a KQL detection catalog with an executable Python simulation layer. The catalog provides deterministic detection IDs, metadata validation, ATT&CK-ID checks, required-table assertions and query-quality checks. The simulation layer provides immutable event/finding models, timezone-aware timestamp handling, fail-closed ingestion, deterministic evidence-backed finding IDs, separate severity and confidence, modular analytics and Markdown report generation.

## Executable offline simulation

The included synthetic telemetry lets the detection logic be exercised without connecting to a live tenant or production workspace.

```bash
python -m unittest discover -s tests -v
python -m src.cli data/synthetic_sentinel_events.json --output reports/generated-assessment.md
```

The synthetic dataset covers privileged sign-in without MFA, encoded PowerShell, remote-logon fan-out across three hosts and security telemetry impairment. It contains no real credentials, customer data or production identifiers.

## Validation approach

The unit suites cover detection-catalog integrity, deterministic IDs, severity validation, ATT&CK mappings, query filters, required data tables, UTC timestamp normalization, MFA control logic, encoded-command detection, remote-logon thresholds, telemetry impairment, deterministic finding IDs and severity ordering. CI compiles the Python modules and runs the tests with read-only repository permissions.

## Triage methodology

Analysts should validate identity, device, process ancestry, source IP, time window, administrative context, expected automation and maintenance windows before escalating. Narrow, documented exclusions are preferred over broad suppression. Tuning must be followed by re-testing to confirm true-positive coverage was not removed.

## Remediation and revalidation

Confirmed incidents should follow authorized response procedures such as identity containment, endpoint isolation, security-control restoration and related-activity hunting. Closure should include evidence that suspicious behavior has ceased, affected controls are healthy, and the analytic still detects the intended behavior after tuning.

Example remediation patterns include enforcing phishing-resistant MFA for privileged identities, validating encoded PowerShell ancestry and script telemetry, reviewing remote-admin fan-out for lateral-movement context, and restoring security telemetry immediately after authorized validation of an impairment alert.

## Skills demonstrated

Microsoft Sentinel concepts, KQL detection development, Microsoft Defender telemetry reasoning, Python detection engineering, detection-as-code practices, MITRE ATT&CK mapping, analytic validation, false-positive analysis, SOC triage, incident-response handoff, evidence handling, unit testing, Markdown reporting and CI hygiene.

## Limitations

This is a public lab using portable patterns and synthetic data rather than production tenant telemetry. Schema availability, ingestion latency, thresholds and field behavior vary by environment. The Python simulation is intentionally provider-neutral and does not claim parity with Sentinel query execution or production-scale correlation.

## Roadmap

- add scheduled-task and privileged-group-change detections
- add analytics-rule ARM/Bicep examples using non-secret placeholders
- add entity baselines and maintenance-window context
- add suppression/exception governance
- add incident grouping and alert-to-case correlation
- add KQL linting and regression fixtures
- add validation coverage matrix and tuning history

## Safety

All content is designed for defensive detection engineering and authorized lab validation only. No employer/client telemetry, production targets, real credentials, malware, exploit payloads or offensive automation are included.
