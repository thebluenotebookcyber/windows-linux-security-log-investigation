# Windows Security Event ID Reference

A quick reference for the Windows Event IDs used during this project.

## Authentication and Account Events

| Event ID | What it means | What a SOC analyst should check |
|---|---|---|
| **4624** | Successful account logon | Account, time, source IP, logon type, authentication context |
| **4625** | Failed account logon | Account, time, source IP, logon type, failure reason, repeated attempts |
| **4672** | Special privileges assigned to a new logon | Account, logon ID, whether privileged access was expected |
| **4720** | User account created | New account name, creator, time, whether creation was approved |
| **4732** | Member added to a security-enabled local group | Account added, group name, actor, time, whether admin access was expected |
| **4799** | Security-enabled local group membership was enumerated | Account/process context, time, why group membership was queried |

## Process Activity

| Event ID | What it means | What a SOC analyst should check |
|---|---|---|
| **4688** | A new process was created | New process, creator process, account, command line, path, parent-child relationship |

## Logon Types

Logon type is important when investigating Event IDs such as 4624 and 4625.

| Logon Type | Meaning | Example |
|---|---|---|
| **2** | Interactive | User signs in locally at the computer |
| **3** | Network | Access to a resource over the network |
| **5** | Service | A Windows service starts or authenticates |
| **10** | Remote Interactive | Remote Desktop Protocol (RDP) logon |

## Important Investigation Notes

### Event ID alone is not enough

An Event ID tells you what happened, but not whether it was malicious.

For example:

```text
4625 = failed logon
```

That does **not** automatically mean:

```text
4625 = attack
```

The analyst needs to investigate the surrounding fields and events.

### Correlate events

A suspicious sequence can become much more meaningful when multiple events are connected:

```text
4625  Failed logon
  |
  +--> 4624  Successful logon
          |
          +--> 4688  PowerShell/process creation
                  |
                  +--> 4720  New account created
                          |
                          +--> 4732  Added to Administrators
```

The exact sequence will vary by incident. The goal is to understand **who did what, when, from where, and whether it was normal**.

### Account name is not automatically the human

An account recorded in an event is the security context involved in the action. It should not automatically be treated as proof that the named person personally performed the activity.

### Parent process matters

For Event ID 4688, compare the new process with its creator process.

Example from this project:

```text
SYSTEM
  |
  +--> wininit.exe
          |
          +--> lsass.exe
```

This process relationship was consistent with normal Windows activity and was supported by additional verification of the executable and its Microsoft Authenticode signature.

## SOC Investigation Checklist

When reviewing a Windows security event, ask:

1. **Who** was involved?
2. **What** happened?
3. **When** did it happen?
4. **From where** did it originate?
5. **Was it normal** for this account, host, and time?
6. What happened immediately before and after it?
7. Is there a legitimate change, maintenance task, or user action explaining it?
8. Do multiple events support the same conclusion?

## Project Verdicts

| Case | Main Event(s) | Verdict |
|---|---|---|
| **Case 01** | 4625 + 4799 | Likely benign / false positive |
| **Case 02** | 4688 | Likely benign / normal Windows activity |
| **Case 03** | Linux `auth.log` | Likely benign / normal lab activity |
| **Case 04** | Correlation exercise | Likely true positive / escalate |

## Golden Rule

> **Don't assume. Find the evidence. Correlate the events. Then decide.**
