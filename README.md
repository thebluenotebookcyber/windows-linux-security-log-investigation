# Windows & Linux Security Log Investigation

A hands-on security log investigation project built in a controlled lab environment.

The goal of this project was to practice how a SOC analyst investigates authentication, process-creation, and suspicious activity events using real Windows and Linux logs rather than simply trusting an alert.

## Objective

- Investigate Windows Security Events and Linux authentication logs
- Understand authentication and process-creation activity
- Correlate related events and build timelines
- Distinguish normal activity from suspicious activity
- Practice false-positive / true-positive triage
- Document findings using evidence and clear reasoning

## Lab Environment

- Windows 11
- VirtualBox
- Ubuntu Linux VM (`blue-notebook`)
- Windows Event Viewer
- Windows PowerShell
- Linux `/var/log/auth.log`

## Skills Demonstrated

- Windows Event Log analysis
- Event ID investigation
- Authentication analysis
- Process creation analysis
- Linux SSH and authentication log analysis
- Event correlation and timeline building
- SOC alert triage
- Evidence handling
- False-positive / suspicious-activity assessment

## Project Structure

```text
Windows-Security-Log-Investigation/
├── screenshots/
│   └── windows_events/
├── investigations/
│   ├── authentication.md
│   ├── process_creation.md
│   └── suspicious_activity.md
├── notes/
│   └── event_id_reference.md
├── final-report/
│   └── windows_security_log_investigation_report.md
└── README.md
```

## Investigations

### Case 01 — Windows Authentication & Group Enumeration

Investigated a Windows Event ID 4625 failed logon and correlated it with surrounding system activity, including Event ID 4799 group enumeration.

**Assessment:** Likely benign / false positive — moderate confidence.

The investigation found the failed authentication associated with a legitimate Windows User Manager service context. The exact reason for the authentication attempt was not established, so the conclusion remains appropriately cautious.

Evidence includes sanitized Event Viewer screenshots and correlated event details.

### Case 02 — Windows Process Creation

Investigated Event ID 4688 for the creation of `lsass.exe`.

The process chain was correlated as:

```text
SYSTEM
  ↓
wininit.exe
  ↓
lsass.exe
```

The executable was confirmed as a Microsoft-signed Windows system binary and the process relationship matched expected Windows behavior.

**Assessment:** Likely benign / normal Windows activity — high confidence.

### Case 03 — Linux Authentication & SSH Logs

Investigated Linux authentication activity from `/var/log/auth.log`, including SSH connections and sudo authentication events.

The activity showed a successful SSH connection from the known lab Windows host, followed by normal session activity. A single failed sudo authentication was immediately followed by a successful sudo authentication, with no evidence of repeated SSH password failures or brute-force behavior.

**Assessment:** Likely benign / normal lab activity — high confidence.

### Case 04 — Suspicious Activity Correlation Exercise

A separate correlation exercise was used to practice identifying a suspicious sequence involving remote access, account creation, privilege changes, security-control modification, and outbound communication.

This case is intentionally documented as a **correlation exercise**, not as raw evidence-backed lab telemetry. The purpose was to practice SOC reasoning and escalation decisions without presenting simulated events as captured evidence.

## Investigation Methodology

For every investigation, the core questions were:

> **WHO did WHAT, WHEN, FROM WHERE, and WAS IT NORMAL?**

The investigation approach was:

1. Start with the alert or event
2. Read the important fields instead of relying only on the Event ID
3. Identify the user, process, source, and timestamp
4. Correlate related events
5. Check whether the activity matches expected behavior
6. Gather supporting evidence
7. Decide whether the activity is benign or suspicious
8. Document the reasoning and confidence level

### Golden Rule

> **Don't assume. Find the evidence. Correlate the events. Then decide.**

## Evidence Handling

Only sanitized evidence is intended for this repository. Personal usernames, hostnames, and other unnecessary identifying details are removed from screenshots before publication.

Raw security logs or sensitive system information should not be uploaded to a public repository.

## Key Lessons

- An alert is not automatically an incident.
- An Event ID is only a starting point; the surrounding fields matter.
- Correlation is often more useful than looking at one event in isolation.
- A legitimate process can still appear in a suspicious-looking event and needs context.
- Approved activity should still be checked against what actually happened.
- Evidence and confidence matter when making a SOC decision.

## Author

**Mayur Tayade**  
Cybersecurity learner | SOC / Blue Team path  
GitHub: `thebluenotebookcyber`
