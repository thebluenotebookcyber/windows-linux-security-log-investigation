# Windows & Linux Security Log Investigation Report

## 1. Executive Summary

This project documents a hands-on security log investigation performed in a controlled lab environment using Windows 11 and an Ubuntu Linux virtual machine.

The investigation focused on authentication activity, process creation, account and group activity, SSH authentication, privilege use, and event correlation.

The project produced three evidence-backed lab investigations and one separate correlation exercise:

- **Case 01:** Windows failed logon and local group enumeration — likely benign / false positive
- **Case 02:** Windows process creation involving `lsass.exe` — likely benign / normal Windows activity
- **Case 03:** Linux SSH and authentication activity — likely benign / normal lab activity
- **Case 04:** Suspicious activity correlation exercise — likely true positive / escalate

The main lesson from the project was that a security alert or event ID should not be treated as an incident by itself. The analyst must correlate events, inspect context, verify evidence, and then make a decision.

---

## 2. Investigation Objective

The objective was to practice the core workflow of a SOC Analyst L1:

1. Identify relevant security events.
2. Understand what each event means.
3. Collect supporting evidence.
4. Correlate related events.
5. Determine whether the activity is normal or suspicious.
6. Assign a defensible verdict.
7. Document the reasoning and limitations.

The investigation was guided by one question:

> **WHO did WHAT, WHEN, FROM WHERE, and WAS IT NORMAL?**

---

## 3. Lab Environment

### Windows

- Windows 11
- Windows Event Viewer
- PowerShell
- Windows Security event logs

### Linux

- Ubuntu Linux virtual machine
- Hostname: `blue-notebook`
- SSH service
- `/var/log/auth.log`

### Virtualization

- Oracle VirtualBox
- Windows host and Ubuntu VM connected through a host-only lab network

---

## 4. Methodology

The investigation followed a simple SOC workflow:

```text
Alert / Event
     |
     v
Triage
     |
     v
Collect Evidence
     |
     v
Correlate Events
     |
     v
Determine Normal vs Suspicious
     |
     v
Verdict
     |
     v
Document / Escalate
```

The investigation avoided treating individual Event IDs as automatic proof of compromise.

For each case, the analysis considered:

- Account involved
- Timestamp
- Source address or origin
- Logon type
- Process and parent process
- Authentication result
- Related events
- Expected lab activity
- Available evidence

### Golden Rule

> **Don't assume. Find the evidence. Correlate the events. Then decide.**

---

# 5. Case Investigations

## Case 01 — Windows Failed Logon + Group Enumeration

### Evidence Type

**Lab evidence**

### Events Investigated

- Event ID **4625** — failed logon
- Event ID **4672** — special privileges assigned
- Event ID **4624** — successful logon
- Event ID **4799** — local security-enabled group membership enumeration

### Key Findings

A failed interactive logon was recorded for the lab user. The 4625 event showed:

- Logon type: **2 (Interactive)**
- Source address: `127.0.0.1`
- Failure status: `0xC000006D`
- Substatus: `0xC000006A` indicating an incorrect password
- Caller process: `svchost.exe`

The caller process was investigated further. The relevant process ID mapped to the legitimate Windows **User Manager** service running under `LocalSystem`.

A related 4799 group enumeration event was also reviewed. The activity was not treated as malicious solely because group membership was queried.

### Evidence Files

```text
screenshots/windows_events/01_4625_failed_logon_general.png
screenshots/windows_events/02_4799_group_enumeration_general.png
```

### Verdict

**Likely Benign / False Positive**

**Confidence: Moderate**

The evidence did not establish malicious activity. However, the exact reason for the User Manager authentication attempt was not completely determined, so the confidence was kept at moderate rather than high.

### SOC Lesson

A failed logon should be investigated using source, logon type, failure reason, surrounding events, and process context. One failed password does not automatically equal an attack.

---

## Case 02 — Windows Process Creation: `lsass.exe`

### Evidence Type

**Lab evidence**

### Event Investigated

- Event ID **4688** — new process created

### Key Findings

The event recorded the creation of:

```text
C:\Windows\System32\lsass.exe
```

Relevant process information:

| Field | Value |
|---|---|
| Creator | SYSTEM |
| Creator Logon ID | `0x3E7` |
| New Process ID | `0x650` / 1616 |
| New Process | `lsass.exe` |
| Creator Process ID | `0x5A4` / 1444 |
| Creator Process | `wininit.exe` |
| Integrity | System |
| Command Line | Blank |

### Process Chain

```text
SYSTEM
  |
  +--> wininit.exe (PID 1444)
          |
          +--> lsass.exe (PID 1616)
```

The process relationship was consistent with normal Windows system activity.

Additional verification was performed with PowerShell and Authenticode signature validation. The executable was reported with a **Valid** signature from Microsoft Windows / Microsoft Corporation.

### Verdict

**Likely Benign / Normal Windows Activity**

**Confidence: High**

### SOC Lesson

Process names alone are not enough to determine maliciousness. Parent-child relationships, execution context, file location, signer information, and surrounding events provide stronger evidence.

---

## Case 03 — Linux SSH and Authentication Activity

### Evidence Type

**Lab evidence**

### Log Investigated

```text
/var/log/auth.log
```

### Key Findings

The Ubuntu authentication log showed:

- Local console activity for the lab user
- SSH service verification
- SSH listening-port verification
- A successful SSH login from the known Windows host-only address `192.168.96.1`
- One failed `sudo` authentication
- A successful `sudo` authentication shortly afterward

The SSH log was searched for failed password activity. No repeated SSH failed-password pattern was identified.

The observed `sudo` failure was immediately followed by a successful authentication, which was more consistent with an incorrect password entry than an ongoing privilege-escalation attempt.

### Correlation

```text
Known lab Windows host
        |
        +--> SSH connection
                |
                +--> Successful authentication
                        |
                        +--> Local sudo attempt
                                |
                                +--> Failed once
                                |
                                +--> Succeeded shortly after
```

### Verdict

**Likely Benign / Normal Lab Activity**

**Confidence: High**

### SOC Lesson

Linux authentication investigations should consider the source IP, frequency of failures, timing, target account, SSH context, privilege use, and what happened immediately before and after the authentication event.

---

## Case 04 — Suspicious Activity Correlation Exercise

### Evidence Type

**Correlation exercise — not raw evidence-backed lab activity**

This case is intentionally separated from Cases 01–03. It is a practice scenario used to demonstrate how a SOC analyst would correlate multiple suspicious events.

### Exercise Scenario

A workstation shows the following sequence:

```text
External RDP logon (Type 10)
        |
        v
New user account created (4720)
        |
        v
Account added to Administrators (4732)
        |
        v
PowerShell / CMD execution (4688)
        |
        v
Security-control tampering
        |
        v
Outbound network activity
```

### Analysis

Each event on its own requires investigation. Together, the sequence is significantly more concerning because it shows a progression from remote access to privilege establishment and command execution.

Important questions for a real investigation would include:

- Was the RDP source expected?
- Was there an approved maintenance or change request?
- Who owns the newly created account?
- Why was administrative membership required?
- What commands were executed?
- Was a security control disabled?
- Was outbound communication authorized?
- Are there additional related events on the host or network?

### Verdict

**Likely True Positive / Escalate for Further Investigation**

The correlation strongly supports suspicious activity, but a real SOC investigation would continue collecting host, identity, network, and change-management evidence before declaring the full incident scope.

### SOC Lesson

The strongest signal is often the **sequence of related events**, not one isolated alert.

---

# 6. Findings Summary

| Case | Platform | Main Activity | Evidence | Verdict | Confidence |
|---|---|---|---|---|---|
| 01 | Windows | Failed logon + group enumeration | Lab evidence | Likely benign / FP | Moderate |
| 02 | Windows | `lsass.exe` process creation | Lab evidence | Likely benign | High |
| 03 | Linux | SSH + authentication logs | Lab evidence | Likely benign | High |
| 04 | Windows-style scenario | Correlated suspicious sequence | Exercise | Likely TP / escalate | Practice assessment |

---

# 7. Skills Demonstrated

This project demonstrates practical experience with:

- Windows Event Viewer
- Windows Security Event IDs
- Authentication log analysis
- Failed and successful logon investigation
- Logon type analysis
- Process creation analysis
- Parent-child process correlation
- PowerShell-based verification
- Windows service/process investigation
- Authenticode signature verification
- Linux authentication logs
- SSH investigation
- `sudo` authentication analysis
- Timeline correlation
- False-positive identification
- True-positive triage
- Evidence handling
- SOC-style incident documentation

---

# 8. Limitations

This project was performed in a controlled personal lab environment and does not represent investigation of a production security incident.

Cases 01–03 contain evidence collected from the lab. Case 04 is a correlation exercise and does not include raw event artifacts.

The investigation also had limited telemetry compared with a production SOC. A real enterprise environment would typically provide additional sources such as SIEM data, endpoint telemetry, network logs, identity-provider logs, firewall records, DNS logs, and centralized authentication records.

Therefore, the conclusions are limited to the evidence available in the lab.

---

# 9. Lessons Learned

### 1. An alert is not automatically an incident

A failed login, process creation, or group enumeration event needs context.

### 2. Correlation is critical

Events become more meaningful when connected into a timeline.

### 3. Process context matters

A process that looks suspicious by name may be completely normal when its parent, path, signer, and execution context are verified.

### 4. Source matters

A known lab source and an unknown external source should not be treated the same way.

### 5. Evidence beats assumptions

The analyst should clearly separate what the evidence proves from what is only possible.

### 6. Documentation is part of the investigation

A good SOC analyst should be able to explain not only the verdict, but **why** the verdict was reached and what remains unknown.

---

# 10. Final Conclusion

The investigation successfully demonstrated a basic SOC Analyst L1 workflow across Windows and Linux environments.

The most important skill developed through this project was not memorizing Event IDs. It was learning to investigate activity as a timeline, correlate multiple data points, verify evidence, and avoid jumping to conclusions.

The project reinforces the core SOC mindset:

> **WHO did WHAT, WHEN, FROM WHERE, and WAS IT NORMAL?**

And the final rule remains:

> **Don't assume. Find the evidence. Correlate the events. Then decide.**
