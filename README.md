# Microsoft Sentinel Detection Engineering Lab

A defensive Detection Engineering flagship project focused on Microsoft Sentinel / Microsoft Defender-style telemetry, KQL analytics, detection-as-code controls, ATT&CK-informed investigation context, offline validation, tuning governance, remediation, and revalidation.

The project uses **synthetic telemetry only**. It does not connect to a live Sentinel workspace, Defender tenant, production endpoint, identity provider, or employer/client environment.

## Recruiter quick review

For a fast technical review:

1. Read this README for the problem statement and architecture.
2. Inspect `detections/` for the KQL analytics.
3. Review `src/detection_catalog.py` and `src/detections.py` for validation and executable offline detection logic.
4. Review `tests/` for regression coverage.
5. Open `reports/example-assessment.md` for an analyst-facing output example.
6. Use `docs/recruiter-review.md` for the full five-minute review path.
7. Review `docs/detection-validation-matrix.md` and `docs/remediation-revalidation.md` for evidence, tuning, and closure standards.

## Problem statement

Detection programs fail when analytics are created without clear behavioral intent, telemetry assumptions, repeatable testing, tuning discipline, or defensible closure criteria. A query returning rows is not the same as a validated security control.

This lab demonstrates a structured workflow for turning observable endpoint and identity behavior into explainable KQL detections and equivalent offline Python analytics that can be reviewed, tested, tuned, reported, and revalidated.

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
          +-------+-------+
          |               |
      benign/noisy     confirmed/gap
          |               |
       tuning        remediation/restore
          |               |
          +-------+-------+
                  v
           regression re-test
                  |
                  v
            validated closure
```

## Recruiter signal at a glance

| Capability | Evidence in repository | Engineering signal |
|---|---|---|
| KQL detection development | `detections/*.kql` | Behavior-based analytics using Sentinel/Defender-style schemas |
| Detection-as-code | `src/detection_catalog.py` | Deterministic IDs, metadata checks, ATT&CK validation, required-table assertions |
| Offline detection simulation | `src/detections.py`, `data/synthetic_sentinel_events.json` | Repeatable defensive testing without production access |
| Evidence handling | `src/models.py`, `reports/example-assessment.md` | Structured findings with severity, confidence, evidence, and investigation context |
| Unit/regression testing | `tests/` | Positive/negative logic validation and deterministic behavior |
| Tuning governance | `docs/detection-validation-matrix.md` | Narrow exclusions, known-positive regression tests, evidence-quality model |
| Remediation/revalidation | `docs/remediation-revalidation.md` | Technical closure criteria, telemetry restoration, re-test and reopen conditions |
| ATT&CK mapping | `docs/attack-mapping.md` | Technique context kept separate from incident conclusions |
| CI hygiene | `.github/workflows/ci.yml` | Source compilation and test execution with read-only repository permissions |

## Included detections

| Detection | Data source / model | ATT&CK context | Purpose |
|---|---|---|---|
| Encoded PowerShell | `DeviceProcessEvents` / process events | T1059.001 | Surface suspicious encoded PowerShell execution for analyst review |
| Remote logon fan-out | `DeviceLogonEvents` / sign-in events | T1021, T1078 | Identify identities authenticating across multiple endpoints within a bounded window |
| Security-control impairment | `DeviceEvents` / audit events | T1562.001, T1070.001 | Surface security-control or logging impairment telemetry |
| Privileged sign-in without MFA | identity sign-in events | T1078 | Identify privileged successful authentication without the expected MFA control |

A detection match is **not proof of compromise**. ATT&CK mappings provide investigation and coverage context only; see `docs/attack-mapping.md`.

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
  architecture-methodology.md
  methodology.md
  recruiter-review.md
  detection-validation-matrix.md
  remediation-revalidation.md
  attack-mapping.md
reports/
  example-assessment.md
.github/workflows/
  ci.yml
```

## Detection engineering controls

The repository combines a KQL detection catalog with an executable Python simulation layer. The catalog provides deterministic detection IDs, metadata validation, ATT&CK-ID checks, required-table assertions, and query-quality checks. The simulation layer provides immutable event/finding models, timezone-aware timestamp handling, fail-closed ingestion, deterministic evidence-backed finding IDs, separate severity and confidence, modular analytics, and Markdown reporting.

This separation makes it possible to review the detection intent independently from the Microsoft platform while keeping the KQL implementation visible for product-specific reasoning.

## Executable offline simulation

```bash
python -m unittest discover -s tests -v
python -m src.cli data/synthetic_sentinel_events.json --output reports/generated-assessment.md
```

The synthetic dataset covers privileged sign-in without MFA, encoded PowerShell, remote-logon fan-out across multiple hosts, and security telemetry impairment. It contains no real credentials, customer data, production identifiers, or production targets.

## Validation standard

A detection is not treated as mature merely because a query exists or parses. The project distinguishes:

- **Designed** — behavior, telemetry assumptions, and initial query are documented.
- **Structurally validated** — catalog, metadata, schema assumptions, and deterministic identifiers pass checks.
- **Behaviorally validated** — authorized synthetic/lab telemetry triggers the intended finding.
- **Tuned** — known-benign activity is reduced with narrow, documented changes.
- **Revalidated** — the known-positive fixture remains detectable after tuning or remediation.
- **Degraded** — telemetry health is insufficient to support the stated detection objective.

See `docs/detection-validation-matrix.md` for the evidence model and per-detection revalidation criteria.

## Triage methodology

Analysts should validate identity, device, process ancestry, source IP, time window, administrative context, expected automation, and maintenance windows before escalation. Narrow, documented exclusions are preferred over broad suppression.

Severity reflects analytical priority. Confidence reflects evidence quality. ATT&CK mapping provides threat context. None of these alone establishes that compromise occurred.

## Remediation and revalidation

Confirmed conditions and detection gaps should move through an evidence-based lifecycle rather than being closed administratively.

Typical paths include:

- identity-control restoration or authorized containment;
- endpoint/security-control restoration;
- telemetry-health correction;
- narrow tuning for documented benign behavior;
- regression testing against known-positive fixtures;
- reopen when telemetry degrades, the condition returns, or the known-positive fixture stops triggering.

Risk acceptance is deliberately kept separate from technical remediation. An accepted exception can govern residual risk, but it does not prove that the underlying technical condition has been removed.

See `docs/remediation-revalidation.md` for the full workflow.

## Design decisions

- **Synthetic data only:** keeps the project safe, reproducible, and free of confidential telemetry.
- **Provider-neutral Python simulation:** demonstrates logic and testing without claiming parity with Sentinel's execution engine.
- **Deterministic findings:** supports repeatable test expectations and evidence traceability.
- **Separate severity and confidence:** prevents urgency from being confused with evidence quality.
- **Behavior-first detection design:** reduces dependence on product alert names.
- **Narrow tuning:** avoids hiding the behavior the analytic is intended to detect.
- **Exact-commit CI verification:** avoids using an old successful workflow run as evidence for a newer commit.

## Skills demonstrated

Microsoft Sentinel concepts, KQL detection development, Microsoft Defender telemetry reasoning, Python detection engineering, detection-as-code practices, MITRE ATT&CK mapping, analytic validation, false-positive analysis, SOC triage, incident-response handoff, telemetry-health reasoning, evidence handling, unit testing, Markdown reporting, remediation/revalidation governance, and CI hygiene.

## Limitations

This is a public lab using portable patterns and synthetic data rather than production tenant telemetry. Schema availability, ingestion latency, field names, thresholds, baselines, identity context, and endpoint behavior vary by environment. The Python simulation does not claim parity with Sentinel query execution, scheduled analytics, incident grouping, or production-scale correlation.

ATT&CK mappings describe relevant behavioral context, not comprehensive technique coverage. Before operational use, every rule would require validation against the authorized target environment, its actual telemetry, expected administrative activity, and local response procedures.

## CI policy

The GitHub Actions workflow compiles the Python source and runs the unit tests with read-only repository permissions. A historic green run is not treated as evidence for a later commit: CI is only described as green when the workflow status has been checked for the exact commit being referenced.

## Roadmap

- add scheduled-task and privileged-group-change detections;
- add analytics-rule ARM/Bicep examples using non-secret placeholders;
- add entity baselines and maintenance-window context;
- add suppression/exception governance fixtures;
- add incident grouping and alert-to-case correlation models;
- add KQL linting and regression fixtures;
- expand telemetry-health validation and tuning history.

## Safety

All content is designed for defensive Detection Engineering and authorized lab validation only. No employer/client telemetry, production targets, real credentials, malware, exploit payloads, destructive actions, credential theft, persistence tooling, or offensive automation are included.