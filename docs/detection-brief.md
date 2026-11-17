# Detection Brief — Repeated Entra ID Failed Sign-Ins

## Objective

Detect repeated failed Microsoft Entra ID sign-ins from the same account and source IP. This behavior can be consistent with password spraying, brute-force attempts, or credential stuffing.

## Data source

- **Table:** `SigninLogs`
- **Collection path:** Microsoft Entra ID diagnostic settings → Log Analytics workspace → Microsoft Sentinel
- **Required fields:** `TimeGenerated`, `UserPrincipalName`, `IPAddress`, and `ResultType`

## Detection logic

The scheduled KQL rule (**Multiple Failed Entra ID Sign-ins**) runs every 5 minutes with a 5-minute lookback, groups failed sign-ins by account, IP address, and a 10-minute time bin, then alerts at three or more failures.

| Setting | Lab value | Rationale |
|---|---:|---|
| Query frequency | 5 minutes | Provides regular coverage for a scheduled lab rule |
| Lookback window | 5 minutes | Rule scheduling setting; bounds the query's `ago(30m)` filter to the most recent 5 minutes |
| Threshold | 3 failed attempts | Low threshold for controlled validation; not a production baseline |
| Severity | Medium | Requires analyst review, but does not prove compromise |
| Entity mapping | Account and IP address | Gives the analyst an investigation starting point |
| Alert grouping | Disabled | Lab setting; see tuning notes |

## ATT&CK context

| Tactic | Technique | Why it applies |
|---|---|---|
| Credential Access | T1110.001 Brute Force: Password Guessing | Repeated failed authentication may indicate attempted password guessing |

> The ATT&CK mapping is contextual, not an attribution. A failed-sign-in pattern alone does not prove malicious intent.

## Controlled validation

1. Use a non-privileged lab account.
2. Generate at least three failed sign-ins from the same source IP within one 10-minute window.
3. Confirm `SigninLogs` ingestion in Log Analytics.
4. Verify the scheduled rule creates an alert and Sentinel incident.
5. Review the mapped account and IP entities.
6. Record the expected lab disposition: **Benign — controlled test**.

## Analyst triage checklist

- Confirm the affected account, source IP, time window, and failure count.
- Check whether successful sign-ins occurred before or after the failures.
- Review application, location, device, conditional-access, and result-description fields where present.
- Determine whether the IP and sign-in pattern are expected.
- Document a disposition and, if suspicious, escalate according to the organization’s incident process.

## Tuning and limitations

- Alert grouping and suppression should be configured before production use to avoid duplicate incidents from overlapping lookback windows.
- Thresholds should be baselined against tenant activity; three failures is intentionally sensitive for this lab.
- Approved service accounts, test automation, and known network ranges require evidence-based tuning—not blanket exclusions.
- Scheduled analytics rules are not real-time detections.

## Evidence

- [Detection query](../detections/entra-id-failed-signins.kql)
- [Incident walkthrough](incident-walkthrough.md)
- [Lab screenshots](../screenshots/)
