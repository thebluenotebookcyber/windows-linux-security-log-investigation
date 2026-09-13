# Process Creation Investigation

## Case 02 — Windows Event ID 4688

### Objective

Investigate a Windows process-creation event and determine whether the observed process execution is normal system activity or suspicious behavior.

### Event Summary

| Field | Observed Value |
|---|---|
| Event ID | 4688 — A new process has been created |
| Timestamp | 13 September 2026, 18:01:35 IST |
| Creator Account | SYSTEM |
| Creator Logon ID | `0x3E7` |
| New Process ID | `0x650` / `1616` |
| New Process | `C:\Windows\System32\lsass.exe` |
| Creator Process ID | `0x5A4` / `1444` |
| Creator Process | `C:\Windows\System32\wininit.exe` |
| Token Elevation Type | Default |
| Integrity Level | System |
| Command Line | Blank |

## Investigation

The first step was to identify what process was created and which process created it.

The event showed:

```text
SYSTEM
  |
  +-- wininit.exe (PID 1444)
        |
        +-- lsass.exe (PID 1616)
```

`lsass.exe` is the Windows Local Security Authority process. The important question was not simply whether the process name looked familiar, but whether the process path, parent process and execution context were consistent with normal Windows behavior.

### Process Verification

The process ID from the event was checked locally with PowerShell:

```powershell
Get-Process -Id 1616 | Select-Object Id,ProcessName,Path,StartTime
```

The result confirmed PID `1616` as `lsass`.

The creator process was also checked:

```powershell
Get-Process -Id 1444 | Select-Object Id,ProcessName
```

The result confirmed PID `1444` as `wininit`.

### File Signature Verification

The Windows executable was checked using Authenticode signature validation:

```powershell
Get-AuthenticodeSignature "C:\Windows\System32\lsass.exe" | Select-Object Status,SignerCertificate
```

The signature status was **Valid** and the signer was Microsoft Windows / Microsoft Corporation.

Additional file information identified the executable as:

- Product: Microsoft Windows Operating System
- Description: Local Security Authority Process
- Version: 10.0.26100.9278

## Analysis

Several indicators supported normal Windows activity:

1. The process was `lsass.exe`, a legitimate Windows security process.
2. The process was running in the SYSTEM context.
3. The parent process was `wininit.exe`, which is consistent with normal Windows startup/system process relationships.
4. The executable was located at `C:\Windows\System32\lsass.exe`.
5. Authenticode validation returned a valid Microsoft signature.
6. No suspicious command line was present in the event.

The event should still be evaluated using the surrounding process tree and execution context rather than trusting the process name alone.

## Verdict

**Likely Benign / Normal Windows Activity**

**Confidence: High**

The available evidence is consistent with a legitimate Windows `lsass.exe` process created in the expected SYSTEM context and associated with `wininit.exe`. No suspicious indicators were identified during this investigation.

## SOC Analyst Takeaway

A process-creation alert is not automatically an incident. For Event ID 4688, investigate:

- What process was created?
- Who created it?
- What was the parent process?
- What was the command line?
- Where is the executable located?
- Is the executable signed and trusted?
- Does the process relationship make sense?

The goal is to **correlate the evidence before making a decision**.
