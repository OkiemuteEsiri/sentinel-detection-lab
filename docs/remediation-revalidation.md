# Remediation and Revalidation Workflow

Detection engineering does not end when an alert is generated. This document defines how findings, tuning changes, telemetry gaps, and confirmed security conditions should move toward defensible closure.

## Lifecycle

```text
Finding / validation gap
        |
        v
Triage and evidence review
        |
        +--> benign but noisy --> narrow tuning --> regression re-test
        |
        +--> telemetry gap -----> restore telemetry --> health validation --> re-test
        |
        +--> confirmed condition -> authorized remediation / response
                                      |
                                      v
                              technical validation
                                      |
                        +-------------+-------------+
                        |                           |
                     validated                 failed/partial
                                                    |
                                                    v
                                                  reopen
```

## Required closure evidence

A technically validated closure should record, as applicable:

- the original finding or validation gap;
- the affected identity, device, process, control, or telemetry source;
- the authorized remediation or tuning action;
- evidence that the risky condition has ceased or the control has been restored;
- evidence that expected telemetry is still arriving with required fields;
- the known-positive regression fixture used for re-test;
- the re-test result and timestamp;
- any residual limitation or accepted exception.

## Scenario guidance

### Encoded PowerShell

Review process ancestry, signer, user, device, script/command context, and expected administrative automation. If the event is known benign, tune only the narrow context that makes it expected. Revalidate by confirming the authorized benign fixture is reduced while the synthetic suspicious encoded-command fixture continues to produce a finding.

### Remote logon fan-out

Validate jump hosts, administrative tools, service accounts, maintenance windows, source IP ownership, and target-host population. If a threshold or allowlist changes, replay the known-positive multi-host fixture and confirm that the expected fan-out remains detectable.

### Security-control impairment

Treat loss or impairment of defensive telemetry as both a security concern and a detection-coverage concern. After authorized restoration, verify control health, expected event flow, field completeness, and the ability of the impairment fixture to trigger the analytic.

### Privileged sign-in without MFA

Validate account privilege, authentication method, break-glass status, source context, and applicable identity policy. Remediation may include restoring the expected MFA control or correcting a narrowly scoped exception. Re-test with synthetic identity events to ensure the analytic still distinguishes expected MFA from the risky condition.

## Exceptions and risk acceptance

Exceptions should be attributable, narrowly scoped, time-bounded, and reviewed. They should document the reason, owner, expiry, compensating controls, and residual risk.

An accepted exception is not equivalent to technical remediation. The underlying exposure or detection limitation should remain visible in engineering records even when governance accepts the residual risk.

## Reopen criteria

Reopen the remediation or validation item when:

- the known-positive fixture no longer triggers after tuning;
- required telemetry becomes unavailable or materially incomplete;
- the same risky condition reappears;
- an exclusion expands beyond its documented scope;
- remediation evidence is administrative only and does not demonstrate technical change;
- an exception expires without renewed review.

## Safety

All examples in this repository use synthetic data and defensive validation patterns. This workflow does not authorize containment, account changes, endpoint actions, tenant changes, or testing against systems without explicit permission.