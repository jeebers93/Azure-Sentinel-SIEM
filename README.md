# 🛡️ Azure Sentinel SIEM Home Lab

A hands-on security monitoring lab built in Microsoft Azure, using Microsoft Sentinel as the SIEM. This project demonstrates real-world skills in log ingestion, data connector configuration, and analytics rule development — core competencies for Help Desk, IT Support, and Junior SOC Analyst roles.

---

## 📋 Table of Contents

- [Lab Overview](#lab-overview)
- [Architecture](#architecture)
- [Environment Setup](#environment-setup)
- [Data Connectors & Log Ingestion](#data-connectors--log-ingestion)
- [Analytics Rules & Alerting](#analytics-rules--alerting)
- [Sample Detections](#sample-detections)
- [Key Takeaways](#key-takeaways)

---

## Lab Overview

| Item | Detail |
|---|---|
| **Platform** | Microsoft Azure (Free Trial / Pay-As-You-Go) |
| **SIEM** | Microsoft Sentinel |
| **Log Sources** | Azure AD / Entra ID, Microsoft Defender, Windows Event Logs |
| **Focus Areas** | Data ingestion, connector configuration, analytics rules, alert tuning |
| **Goal** | Simulate an enterprise SOC environment and detect common attack patterns |

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Microsoft Azure                      │
│                                                         │
│  ┌─────────────────┐      ┌──────────────────────────┐  │
│  │  Entra ID (AAD) │─────▶│                          │  │
│  └─────────────────┘      │    Log Analytics         │  │
│                           │    Workspace             │  │
│  ┌─────────────────┐      │                          │  │
│  │ Microsoft       │─────▶│  (Central log store)     │  │
│  │ Defender        │      │                          │  │
│  └─────────────────┘      └────────────┬─────────────┘  │
│                                        │                 │
│  ┌─────────────────┐                   ▼                 │
│  │ Windows VM      │      ┌──────────────────────────┐  │
│  │ (Event Logs via │─────▶│   Microsoft Sentinel     │  │
│  │  Azure Monitor) │      │   - Analytics Rules      │  │
│  └─────────────────┘      │   - Incidents            │  │
│                           │   - Alerts               │  │
│                           └──────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## Environment Setup

### 1. Azure Resource Group
Created a dedicated resource group (`sentinel-homelab-rg`) to contain all lab resources and make cost tracking straightforward.

### 2. Log Analytics Workspace
Deployed a Log Analytics Workspace (`sentinel-lab-law`) — this is the data store that Sentinel sits on top of. All connected log sources ship data here first.

### 3. Microsoft Sentinel Enabled
Enabled Microsoft Sentinel on top of the Log Analytics Workspace. This activates the SIEM layer: analytics rules, incident management, and alerting.

### 4. Windows Virtual Machine
Deployed a Windows Server VM within the same resource group. Installed the **Azure Monitor Agent (AMA)** and created a **Data Collection Rule (DCR)** to forward Windows Security Event Logs to the workspace.

---

## Data Connectors & Log Ingestion

Configured three data connectors within Sentinel to establish log pipelines from each source:

### 🔵 Microsoft Entra ID (Azure AD)

**Connector:** Microsoft Entra ID (built-in Sentinel connector)

**Log tables ingested:**
- `SigninLogs` — all interactive and non-interactive sign-in events
- `AuditLogs` — user provisioning, role assignments, MFA changes

**Why it matters:** Sign-in logs are the primary source for detecting credential-based attacks — password sprays, impossible travel, MFA bypass attempts, and account takeovers.

**Verification:** Confirmed data flowing by running the following KQL in Log Analytics:
```kql
SigninLogs
| take 10
```

---

### 🔴 Microsoft Defender (XDR)

**Connector:** Microsoft Defender XDR (built-in Sentinel connector)

**Log tables ingested:**
- `SecurityAlert` — Defender-generated alerts (malware detections, suspicious behaviour)
- `DeviceEvents` — endpoint telemetry from Defender for Endpoint

**Why it matters:** Pulls endpoint detection alerts directly into Sentinel so they can be correlated with identity and network logs — moving from siloed alerts to unified incidents.

**Verification:**
```kql
SecurityAlert
| where ProductName == "Microsoft Defender Advanced Threat Protection"
| take 10
```

---

### 🟢 Windows Event Logs (via Azure Monitor Agent)

**Connector:** Windows Security Events via AMA

**Log table ingested:**
- `SecurityEvent` — Windows Security Event Log (Event IDs forwarded per DCR filter)

**Key Event IDs collected:**

| Event ID | Description |
|---|---|
| 4624 | Successful logon |
| 4625 | Failed logon |
| 4648 | Logon using explicit credentials |
| 4720 | User account created |
| 4732 | User added to privileged group |
| 4767 | User account unlocked |

**Why it matters:** Windows Security Events are the backbone of endpoint threat detection. Failed logon patterns, privilege escalation, and account manipulation all surface here.

**Verification:**
```kql
SecurityEvent
| where EventID == 4625
| take 10
```

---

## Analytics Rules & Alerting

Created custom **Scheduled Analytics Rules** in Sentinel to detect suspicious patterns across ingested logs. Each rule runs on a defined schedule, queries the Log Analytics workspace via KQL, and generates an incident when the threshold is met.

---

### Rule 1: Brute Force Detection — Failed Logins (Windows)

**Tactic:** Credential Access  
**Technique:** T1110 — Brute Force  
**Severity:** Medium  
**Query schedule:** Every 5 minutes, looking back 1 hour

**Logic:** Alert when a single account accumulates 10 or more failed logon attempts (Event ID 4625) within 1 hour from the same source IP.

```kql
SecurityEvent
| where EventID == 4625
| where TimeGenerated > ago(1h)
| summarize FailedAttempts = count() by Account, IpAddress, bin(TimeGenerated, 5m)
| where FailedAttempts >= 10
| project TimeGenerated, Account, IpAddress, FailedAttempts
```

**Alert trigger:** Generates a Sentinel incident with account name, source IP, and attempt count — ready for analyst triage.

---

### Rule 2: Successful Login After Multiple Failures (Windows)

**Tactic:** Credential Access  
**Technique:** T1110.001 — Password Guessing  
**Severity:** High  
**Query schedule:** Every 15 minutes, looking back 1 hour

**Logic:** Detects accounts that had 5+ failed logons (4625) followed by a successful logon (4624) within the same hour — a strong indicator of a successful brute force.

```kql
let failed = SecurityEvent
    | where EventID == 4625
    | where TimeGenerated > ago(1h)
    | summarize FailCount = count() by Account
    | where FailCount >= 5;
SecurityEvent
| where EventID == 4624
| where TimeGenerated > ago(1h)
| join kind=inner failed on Account
| project TimeGenerated, Account, FailCount, Computer
```

---

### Rule 3: Entra ID — Sign-in From Unfamiliar Location

**Tactic:** Initial Access  
**Technique:** T1078 — Valid Accounts  
**Severity:** Medium  
**Query schedule:** Every 1 hour

**Logic:** Flags sign-ins that Entra ID's risk engine has tagged as unfamiliar location or atypical travel — useful for catching compromised credentials used from a new geography.

```kql
SigninLogs
| where TimeGenerated > ago(1h)
| where RiskLevelDuringSignIn in ("medium", "high")
| where LocationDetails.countryOrRegion != "CA"
| project TimeGenerated, UserPrincipalName, IPAddress, LocationDetails, RiskLevelDuringSignIn, ResultType
```

---

### Rule 4: New Privileged Account Created (Windows)

**Tactic:** Privilege Escalation / Persistence  
**Technique:** T1136 — Create Account  
**Severity:** High  
**Query schedule:** Every 5 minutes

**Logic:** Alerts any time a new local user account is created on a monitored Windows host — a common persistence technique after initial compromise.

```kql
SecurityEvent
| where EventID == 4720
| project TimeGenerated, Account, SubjectAccount = SubjectUserName, Computer
```

---

## Sample Detections

Below are examples of incidents generated during lab testing, created by simulating attack scenarios against the lab environment:

### 🚨 Incident: Brute Force Attempt — Local Admin Account

- **Triggered by:** Rule 1 (Failed Logins threshold)
- **Simulation:** Used a script to generate 15 rapid failed logon attempts against the Windows VM's local administrator account
- **Result:** Sentinel generated an incident within 5 minutes; alert included source IP, account targeted, and attempt count
- **Response actions taken:** Reviewed the `SecurityEvent` logs, confirmed the attempts were from a single source IP, documented the timeline

### 🚨 Incident: Risky Entra ID Sign-in Detected

- **Triggered by:** Rule 3 (Unfamiliar location / risk score)
- **Simulation:** Signed into the lab Azure AD tenant from a VPN endpoint assigned a non-Canadian exit IP
- **Result:** Sentinel flagged the sign-in as medium-risk; `SigninLogs` showed the login, IP geolocation, and Entra risk assessment
- **Response actions taken:** Correlated the sign-in with `AuditLogs` to check for any account changes post-login; none found — marked as false positive with documented reasoning

---

## Key Takeaways

Working through this lab produced practical experience with concepts directly relevant to IT Support and SOC roles:

- **Data connector configuration** is non-trivial — understanding the difference between the legacy MMA agent and the newer AMA/DCR model, and why it matters for log fidelity
- **KQL is the core skill** for Sentinel work — even basic `summarize`, `join`, and `where` clauses unlock powerful detection logic
- **Alert tuning matters more than alert volume** — the goal is high-fidelity, actionable incidents, not noise. Learning to set appropriate thresholds (e.g., 10 failed logins vs. 3) reduces false positive fatigue
- **MITRE ATT&CK mapping** gives detections professional structure and makes it easier to communicate what a rule is designed to catch and why
- **Incident documentation** is as important as detection — each simulated incident was written up with the trigger, evidence reviewed, and conclusion, mirroring real SOC workflows

---

## 📁 Repository Structure

```
azure-sentinel-homelab/
│
├── README.md                  # This file
├── analytics-rules/
│   ├── brute-force-detection.json
│   ├── success-after-failures.json
│   ├── entra-risky-signin.json
│   └── new-account-created.json
└── screenshots/
    ├── sentinel-dashboard.png
    ├── data-connectors.png
    ├── analytics-rules-list.png
    └── sample-incident.png
```

> 💡 **Note:** The `analytics-rules/` folder contains the exported ARM templates for each rule so they can be imported directly into another Sentinel workspace. The `screenshots/` folder documents the live lab environment.

---

*Built by Jong Beom Chun | Vancouver, BC | [jongbeom.chun@gmail.com](mailto:jongbeom.chun@gmail.com)*
