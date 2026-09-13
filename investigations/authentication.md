# Authentication Log Investigation

## Scope

This investigation focuses on Windows authentication-related security events collected from a controlled Windows 11 lab environment.

The main case examined is a failed logon event (Event ID 4625) and its correlation with a nearby group-membership enumeration event (Event ID 4799).

## Investigation Question

> Who did what, when, from where, and was it normal?

The goal was not to treat a single alert as an incident. The events were correlated with process and system context before reaching a conclusion.

---

## Case 01 — Failed Logon (Event ID 4625)

### Event Summary

| Field | Observed value |
|---|---|
| Event ID | 4625 |
| Event type | Failed logon |
| Timestamp | 13 Sep 2026, 18:01:46 IST |
| Target account | LAB_USER |
| Logon type | 2 — Interactive |
| Source address | 127.0.0.1 |
| Status | 0xC000006D |
| Substatus | 0xC000006A — incorrect password |
| Logon process | User32 |
| Authentication package | Negotiate |
| Caller process | `C:\Windows\System32\svchost.exe` |
| Caller PID | 2636 |

### Initial Assessment

At first glance, Event ID 4625 could indicate an incorrect password, a misconfigured application/service, or an attempted unauthorized login.

The source address was `127.0.0.1`, meaning the event originated locally rather than from a remote host.

The failed authentication was therefore investigated further instead of being immediately classified as malicious.

---

## Process Correlation

The caller PID from the 4625 event was mapped to the Windows User Manager service.

Observed process/service context:

- PID: `2636`
- Process: `svchost.exe`
- Service: `UserManager`
- Display name: `User Manager`
- Account: `LocalSystem`
- Startup: `Auto`
- Status: `Running`
- Command line: `C:\WINDOWS\system32\svchost.exe -k netsvcs -p`

This provided additional context that the failed authentication attempt was associated with a legitimate Windows service process rather than an obviously suspicious executable.

---

## Correlated Event — Event ID 4799

A nearby Event ID 4799 was also observed.

**Event ID 4799:** Security-enabled local group membership was enumerated.

The event was associated with the Windows `taskhostw.exe` process. The process was no longer running when it was checked later, so the original event data was treated as the authoritative evidence rather than assuming a current process state.

The presence of 4799 by itself was not treated as malicious. Group-membership enumeration can occur as part of normal Windows activity.

---

## Correlation Logic

The investigation considered the following evidence together:

```text
Event 4625
Failed interactive logon
        |
        +--> Source: 127.0.0.1
        |
        +--> Wrong-password status
        |
        +--> Caller: svchost.exe
        |       |
        |       +--> UserManager service
        |
        +--> Nearby Event 4799
                |
                +--> Local group membership enumeration
```

No evidence in this case established an external source, repeated authentication failures, privilege escalation, malicious process execution, or successful unauthorized access.

---

## Verdict

**Classification: Likely Benign / False Positive**

**Confidence: Moderate**

The available evidence is more consistent with normal Windows/system activity than with an attack.

However, the exact reason the User Manager service generated the authentication-related activity was not established. Therefore, the conclusion is deliberately written as **likely benign** rather than claiming absolute certainty.

### Why it was not escalated as a confirmed incident

- Source was local (`127.0.0.1`).
- Failure reason indicated an incorrect password.
- Caller was the legitimate Windows `svchost.exe` process.
- PID 2636 mapped to the Windows User Manager service.
- The nearby 4799 event represented group-membership enumeration, which can be legitimate.
- No additional evidence showed a malicious process or remote attacker.

---

## Evidence

Sanitized screenshots collected during the investigation are stored under:

```text
screenshots/windows_events/
├── 01_4625_failed_logon_general.png
└── 02_4799_group_enumeration_general.png
```

Sensitive host/user information was sanitized before being prepared for the public repository.

---

## Analyst Takeaway

A failed logon is an **alert**, not automatically an **incident**.

The important part of the investigation was correlating the authentication event with the source, caller process, Windows service context, and nearby events.

> Don't assume. Find the evidence. Correlate the events. Then decide.
