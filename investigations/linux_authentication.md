# Linux Authentication Log Investigation

## Case 03 — Ubuntu SSH and Authentication Logs

### Objective

Investigate authentication activity recorded in `/var/log/auth.log` and determine whether the observed SSH and privilege-use events indicate suspicious activity.

### Lab Environment

- Operating system: Ubuntu Linux virtual machine
- Hostname: `blue-notebook`
- Lab user: `mayur`
- SSH source: Windows host-only interface `192.168.96.1`
- Authentication log: `/var/log/auth.log`

## Evidence Collection

The authentication log was reviewed directly from the Ubuntu VM:

```bash
sudo tail -n 20 /var/log/auth.log
```

The relevant activity included:

| Time (UTC) | Activity | Source / Context |
|---|---|---|
| 15:51:32 | Local console login/session for `mayur` | Local system |
| 15:53:43 | `sudo systemctl status ssh` | Local `sudo` activity |
| 15:54:35 | `sudo ss -tlnp` | Local `sudo` activity |
| 15:55:36 | SSH connection closed | `192.168.96.1` |
| 15:56:41 | Successful SSH password authentication for `mayur` | `192.168.96.1` |
| 15:56:41 | SSH session opened | `192.168.96.1` |
| 15:58:01 | Failed `sudo` authentication | Local session |
| 15:58:07 | Successful `sudo` authentication | Local session |

## SSH Investigation

The log was searched for failed password attempts:

```bash
sudo grep -a "Failed password" /var/log/auth.log
```

No repeated SSH failed-password pattern was identified.

SSH-related entries were then reviewed with:

```bash
sudo grep -aE "sshd|ssh" /var/log/auth.log | tail -n 30
```

The output showed the successful SSH activity from the known lab Windows host and did not show a sequence of repeated failed SSH attempts.

## Sudo Investigation

One failed `sudo` authentication was observed at 15:58:01 UTC. A successful `sudo` authentication followed only a few seconds later at 15:58:07 UTC.

This pattern is more consistent with a local user entering an incorrect password and then successfully authenticating than with an ongoing privilege-escalation attack.

The commands associated with the session were normal lab administration commands used while configuring and verifying SSH:

```text
systemctl status ssh
ss -tlnp
```

## Correlation

The events were evaluated as a timeline rather than as isolated alerts:

```text
Local Ubuntu session
      |
      +--> SSH service checked
      |
      +--> Listening port 22 verified
      |
      +--> SSH connection from 192.168.96.1
      |
      +--> Successful SSH authentication for mayur
      |
      +--> One failed sudo authentication
      |
      +--> Successful sudo authentication 6 seconds later
```

The source IP `192.168.96.1` was the known Windows host-only interface used for the controlled lab connection. There was no evidence of an unknown external source, repeated authentication failures, or a brute-force pattern in the collected entries.

## Verdict

**Likely Benign / Normal Lab Activity**

**Confidence: High**

The observed events are consistent with controlled lab administration and testing. The single failed `sudo` authentication was immediately followed by a successful authentication, while the SSH activity originated from the known lab host. No repeated failed SSH login pattern or other clear indicators of malicious authentication activity were identified.

## SOC Analyst Takeaway

For Linux authentication investigations, do not treat one failed login as proof of an attack. Look at:

- Source IP and whether it is expected
- Success and failure frequency
- Timing between attempts
- Target account
- SSH or local authentication context
- Privilege-use activity such as `sudo`
- What happened immediately before and after the alert

The same SOC principle applies here:

> **Don't assume. Find the evidence. Correlate the events. Then decide.**
