# Analyst Triage Checklist

Use this checklist as a repeatable starting point when the **Entra ID Failed Sign-In Detection** creates an incident.

## Scope the alert

- [ ] Confirm the alert rule, severity, and time window.
- [ ] Record the affected `UserPrincipalName`, `IPAddress`, and failed-attempt count.
- [ ] Confirm the entity mapping is populated.

## Investigate

- [ ] Query nearby `SigninLogs` activity for the user and IP.
- [ ] Look for a successful sign-in near the failed attempts.
- [ ] Review `ResultDescription`, `AppDisplayName`, location, device, and conditional-access context when available.
- [ ] Determine whether the account is privileged or otherwise high impact.
- [ ] Compare the activity with known user behavior and approved testing.

## Decide and document

- [ ] Mark a controlled lab test as **Benign — controlled test**.
- [ ] If suspicious, document the evidence, time range, affected identity, and recommended escalation.
- [ ] Note any tuning candidate only after evidence supports it.

## Investigation query

```kql
SigninLogs
| where TimeGenerated > ago(30m)
| where UserPrincipalName == "<affected-user>"
| where IPAddress == "<source-ip>"
| project TimeGenerated, UserPrincipalName, IPAddress, ResultType, ResultDescription, AppDisplayName, Location
| order by TimeGenerated desc
```

This is a lab workflow, not a substitute for an organization’s incident-response procedures.
