# 🛡️ SIEM Detection Lab

**Tools:** Splunk Enterprise · Ubuntu Server 24.04 LTS · VirtualBox · Windows PowerShell  
**Skills Demonstrated:** Log ingestion · Attack simulation · SPL querying · Dashboard visualization · Network configuration

---

## Overview

A home lab SIEM (Security Information and Event Management) environment built to simulate real-world attack scenarios and practice threat detection. Splunk Enterprise runs on a Windows host and ingests authentication logs forwarded from an Ubuntu Server VM via the Splunk Universal Forwarder. The lab simulates brute force SSH attacks, successful logins, and privilege escalation — then visualizes the results on a custom Splunk dashboard.

---

## Architecture

```
Windows Desktop (Host)
        │
   VirtualBox
        │
   Ubuntu Server VM  ──►  generates auth logs (/var/log/auth.log, /var/log/syslog)
        │
   Splunk Universal Forwarder  ──►  ships logs via TCP 9997
        │
   Splunk Enterprise (Windows)  ──►  ingests, indexes, and analyzes logs
        │
   Security Monitoring Dashboard  ──►  visualizes attack patterns
```

---

## Lab Setup

### Phase 1 — Splunk Enterprise on Windows
- Downloaded and installed Splunk Enterprise on the Windows host
- Accessed the web interface at `http://localhost:8000`
- Configured receiving port `9997` for Universal Forwarder traffic

### Phase 2 — Ubuntu Server VM (VirtualBox)
| Setting | Value |
|---|---|
| Name | Ubuntu-LogServer |
| OS | Ubuntu Server 24.04 LTS |
| RAM | 4096 MB |
| CPU | 2 cores |
| Disk | 25 GB dynamic |
| Adapter 1 | NAT (internet access) |
| Adapter 2 | Host-Only (lab traffic — `192.168.56.10`) |

Additional package installed during setup: **OpenSSH Server**

### Phase 3 — Splunk Universal Forwarder on Ubuntu
Transferred the `.deb` package from Windows to the VM via `scp` over the Host-Only adapter, then installed and configured:

```bash
sudo dpkg -i splunkforwarder-10.2.1-*.deb
sudo /opt/splunkforwarder/bin/splunk start --accept-license

# Point forwarder at Splunk server
sudo /opt/splunkforwarder/bin/splunk add forward-server 192.168.56.1:9997

# Monitor authentication and system logs
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/auth.log
sudo /opt/splunkforwarder/bin/splunk add monitor /var/log/syslog
```

---

## Attack Simulations

### Attack 1 — SSH Brute Force
Ran a PowerShell loop from the Windows host attempting 20 SSH connections as a non-existent user:

```powershell
for ($i=1; $i -le 20; $i++) {
    ssh fakeuser@192.168.56.10
}
```

**Result:** 24 `Failed password` events captured in Splunk from source IP `192.168.56.1`.

### Attack 2 — Successful SSH Login
SSH'd into the Ubuntu VM using valid credentials to generate a contrasting `Accepted password` event.

**Result:** 1 `Accepted password` event confirmed in Splunk — demonstrates normal vs. malicious authentication pattern.

### Attack 3 — Privilege Escalation via Sudo
Ran a sensitive command requiring root privileges inside the VM:

```bash
sudo cat /etc/shadow
```

**Result:** `sudo` session open/close events logged to `auth.log` and captured in Splunk with full command context (`COMMAND=/usr/bin/cat /var/log/auth.log`).

---

## Splunk Detection Queries (SPL)

See [`queries/splunk-searches.md`](queries/splunk-searches.md) for the full documented query set.

| Query Purpose | SPL |
|---|---|
| All indexed events | `index=*` |
| Auth log events | `index=main source="/var/log/auth.log"` |
| Failed login attempts | `index=main source="/var/log/auth.log" "Failed password"` |
| Successful logins | `index=main source="/var/log/auth.log" "Accepted password"` |
| Sudo escalation events | `index=main source="/var/log/auth.log" "sudo"` |

---

## Security Monitoring Dashboard

Built a 3-panel dashboard in Splunk named **"Security Monitoring Dashboard"**:

| Panel | Query |
|---|---|
| Failed Login Attempts Over Time | `index=main "Failed password" \| timechart count by host` |
| Top Source IPs of Failed Logins | `index=main "Failed password" \| rex "from (?P<src_ip>\d+\.\d+\.\d+\.\d+)" \| top src_ip` |
| Successful vs Failed Logins | `index=main ("Failed password" OR "Accepted password") \| eval status=if(searchmatch("Failed"),"Failed","Success") \| timechart count by status` |

The dashboard clearly shows the spike in failed logins from `192.168.56.1` during the brute force simulation, contrasted against the single successful login event.

---

## Screenshots

| Screenshot | Description |
|---|---|
| [`splunk-dashboard.png`](screenshots/splunk-dashboard.png) | Splunk first login / home screen |
| [`ubuntu-ip-addr.png`](screenshots/ubuntu-ip-addr.png) | Ubuntu VM network — Host-Only adapter at `192.168.56.10` |
| [`forwarder-install.png`](screenshots/forwarder-install.png) | Splunk Universal Forwarder install via `dpkg` |
| [`logs-flowing.png`](screenshots/logs-flowing.png) | 3,901 events indexed — logs confirmed flowing into Splunk |
| [`auth-log-ingestion.png`](screenshots/auth-log-ingestion.png) | Auth log events visible in Splunk Search |
| [`brute-force-splunk.png`](screenshots/brute-force-splunk.png) | 24 `Failed password` events from brute force simulation |
| [`brute-force-powershell.png`](screenshots/brute-force-powershell.png) | PowerShell brute force loop running |
| [`successful-login.png`](screenshots/successful-login.png) | `Accepted password` event — successful SSH login detected |
| [`sudo-escalation.png`](screenshots/sudo-escalation.png) | `sudo cat /etc/shadow` privilege escalation captured |
| [`security-dashboard.png`](screenshots/security-dashboard.png) | Final Security Monitoring Dashboard with all 3 panels |

---

## Key Findings

- **3,901 total events** ingested across `auth.log` and `syslog` sources
- **24 failed login attempts** detected from a single source IP (`192.168.56.1`) within a 1-minute window — consistent with automated brute force behavior
- **1 successful login** recorded immediately after, illustrating how an attacker could succeed after repeated attempts
- **Privilege escalation** logged with full command context, including working directory, TTY, and the exact command executed
- The dashboard's "Top Source IPs" panel correctly identified the attacker IP with the highest failed login count

---

## Resume Bullet

```
SIEM Detection Lab | Splunk, Ubuntu Server, VirtualBox                    2026
Deployed Splunk Enterprise ingesting Ubuntu auth logs via Universal Forwarder;
simulated brute force SSH attacks and privilege escalation; built detection
dashboard visualizing authentication patterns and threat indicators.
```

---

## What I Learned

- How authentication events flow from OS logs → log shipper → SIEM
- The difference between `auth.log` sourcetype patterns for failed vs. accepted logins
- How to use SPL `rex` to extract fields like source IP from unstructured log data
- How a spike in failed logins from a single IP looks in a timechart — the visual signature of a brute force attack
- Network adapter configuration in VirtualBox (NAT vs. Host-Only) for isolated lab traffic
