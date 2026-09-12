# Recruiter / Technical Review Guide

This repository is intended to be reviewed as a defensive Detection Engineering project rather than as a collection of isolated KQL snippets.

## Five-minute review path

1. Start with `README.md` for the problem statement, architecture, scope, and safety boundaries.
2. Review `detections/` to inspect the KQL analytics and their telemetry assumptions.
3. Review `src/detection_catalog.py` and `src/detections.py` to see how rule metadata and equivalent offline analytics are validated and exercised.
4. Review `tests/` to see the regression coverage for catalog integrity, timestamps, ATT&CK mappings, thresholds, and deterministic findings.
5. Review `reports/example-assessment.md` to see how findings are translated into analyst-facing evidence and next actions.
6. Review `docs/detection-validation-matrix.md` and `docs/remediation-revalidation.md` for control validation, tuning, closure evidence, and re-test requirements.

## Capability-to-evidence map

| Capability | Repository evidence | What it demonstrates |
|---|---|---|
| Detection design | `detections/*.kql`, `docs/methodology.md` | Behavior-first detection logic with explicit telemetry assumptions |
| Detection-as-code | `src/detection_catalog.py` | Deterministic IDs, metadata validation, ATT&CK checks, required-table assertions |
| Detection simulation | `src/detections.py`, `data/synthetic_sentinel_events.json` | Offline defensive validation using synthetic events rather than live production data |
| Evidence handling | `src/models.py`, `reports/example-assessment.md` | Structured findings with severity, confidence, ATT&CK context, and preserved evidence |
| Quality assurance | `tests/`, `.github/workflows/ci.yml` | Unit tests, source compilation, and CI-based regression checking |
| Tuning governance | `docs/methodology.md`, `docs/remediation-revalidation.md` | Narrow exclusions, re-test requirements, and evidence-based closure |
| Threat-context mapping | `docs/attack-mapping.md` | ATT&CK used as investigation context rather than proof of compromise |

## Technical questions this project can support

A reviewer can use this repository to discuss:

- how detection intent is separated from product-specific alert names;
- what telemetry is required before a rule can be considered valid;
- how false positives and expected administrative behavior should be tuned without broad suppression;
- why severity, confidence, and ATT&CK mapping are distinct concepts;
- how deterministic IDs and regression fixtures improve detection maintenance;
- how a rule should be revalidated after query or threshold changes;
- what evidence is necessary before a detection-related remediation item can be closed.

## Safety and scope

All included data is fictional and synthetic. The repository does not connect to a Microsoft Sentinel workspace, Defender tenant, production endpoint, identity provider, or employer/client environment. It contains no credentials, exploit payloads, malware, destructive actions, or offensive automation.

The KQL is intentionally portable and illustrative. Field names, schemas, baselines, thresholds, and ingestion behavior must be validated against an authorized environment before operational use.

## CI interpretation

A workflow badge or historic successful run should never be treated as proof that an arbitrary later commit is green. CI claims for this portfolio are made only when the GitHub Actions status for the exact referenced commit has been checked.