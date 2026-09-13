# Suspicious Activity Correlation

## Case 04 — Correlation Exercise

> **Evidence note:** This case is a documented correlation exercise based on the investigation scenario we worked through. It is **not presented as a raw-evidence-backed lab incident**. No claim is made that these events occurred on a real production system.

## Objective

Practice correlating multiple Windows security events into a single incident timeline instead of investigating each alert in isolation.

## Scenario

The activity includes a combination of:

- External Remote Desktop Protocol (RDP) activity
- Failed and successful authentication
- Creation of a new account
- Addition of the account to an administrative group
- PowerShell and command-line activity
- Security-control tampering
- Outbound network activity to the same external address

The key SOC task is to determine whether these events form a meaningful attack chain.

## Correlation Timeline

```text
External source
     |
     +--> Failed authentication attempts
     |
     +--> Successful RDP authentication
             |
             +--> Reconnaissance / discovery
             |
             +--> New account created
             |
             +--> Account added to administrator group
             |
             +--> PowerShell / command-line activity
             |
             +--> Security controls weakened
             |
             +--> Outbound network activity
```

## Analysis

Looking at any single event could produce an incomplete or misleading conclusion. The combination is much more important.

### 1. Authentication

A successful external RDP logon after failed authentication attempts is a significant starting point for investigation. The source address, account, timing and logon type should be checked against known remote-access activity.

### 2. Account Creation

Creation of a new account shortly after the remote session increases suspicion, especially when the account is subsequently granted administrative privileges.

### 3. Privilege Escalation

Adding the newly created account to an administrator group provides the account with elevated privileges. In an unexpected sequence, this is a strong indicator of potential attacker persistence or privilege escalation.

### 4. Command Execution

PowerShell and command-line activity following account creation should be investigated for the commands executed, parent process, user context and purpose.

### 5. Security-Control Tampering

Stopping or weakening endpoint security controls is a high-risk behavior. If Defender or real-time monitoring is disabled without an approved administrative reason, the activity should be treated as highly suspicious.

### 6. Outbound Communication

Outbound traffic to the same external source associated with the remote session can strengthen the correlation. However, network traffic alone does not prove data exfiltration; the actual destination, protocol, transferred data and timing would need to be investigated.

## Verdict

**Likely True Positive / Escalate**

The combined sequence contains multiple high-risk behaviors that are consistent with a possible compromise:

- External remote access
- Account creation
- Administrative privilege assignment
- Command execution
- Security-control tampering
- Related outbound communication

A SOC analyst should escalate the incident and preserve relevant evidence rather than close the alerts individually.

## Recommended SOC Actions

1. Isolate the affected endpoint if the organization's incident-response process permits it.
2. Identify the compromised or accessed account.
3. Validate whether the RDP access was authorized.
4. Review authentication events around the source IP and time window.
5. Investigate the newly created account and administrative-group membership.
6. Collect PowerShell/process telemetry and command-line details.
7. Determine what security controls were disabled and when.
8. Investigate outbound connections and any evidence of data transfer.
9. Preserve relevant logs and endpoint evidence.
10. Escalate to the incident-response team according to the organization's procedure.

## Analyst Lesson

This exercise demonstrates why SOC investigations depend on **correlation**.

One event may be explainable. A connected sequence of events can tell a very different story.

> **Don't assume. Find the evidence. Correlate the events. Then decide.**
