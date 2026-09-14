# Technical Architecture & Open-Source Threat Intelligence Pipeline

This document outlines the core architecture, agentless discovery mechanics, open-source algorithms, MITRE ATT&CK framework mapping, and Prometheus telemetry definitions for the Institute Cyber Security SOC & Network Monitor.

---

## High-Level System Architecture

```
                                  [ INSTITUTE MULTI-SUBNET LAB NETWORK ]
                                (Lab 1: 10.13.109.0/24, Lab 2: 110.0/24, Lab 3: 111.0/24)
                                                    │
                                                    │ (1. Multi-threaded TCP Probes [135,445,80,3389,5985])
                                                    │ (2. Windows Native Kernel ARP Cache Resolution)
                                                    │ (3. Defensive Vulnerability Probes [SMBv1, RDP, HTTP])
                                                    │ (4. Remote WMI Threat Audits [Events & Processes])
                                                    ▼
                             +----------------------------------------------+
                             |   Python Cyber SOC Engine (src\agentless_*)  |
                             |      - 80-Worker Multi-Threaded Sweeper      |
                             |      - IEEE Standards MAC OUI Identification |
                             |      - MITRE ATT&CK & CVSS 3.1 Risk Scoring  |
                             |      - Welford Z-Score Anomaly Detection    |
                             |      - Multi-Channel Webhook Dispatcher      |
                             |      - Exposes Prometheus Metrics on :8000   |
                             +----------------------------------------------+
                                                    │
                                                    │ Scrapes :8000/metrics every 5-15s
                                                    ▼
                             +----------------------------------------------+
                             |    Standalone Prometheus Server (:9090)      |
                             |      - Time-Series Database (TSDB)           |
                             |      - Gorilla Double-Delta Compression      |
                             |      - Evaluates PromQL Queries & Vectors    |
                             +----------------------------------------------+
                                                    │
                                                    │ Queries /api/ds/query
                                                    ▼
                             +----------------------------------------------+
                             |        Grafana Enterprise SOC (:3000)        |
                             |      - Master Endpoint Matrix (OUI Vendors)  |
                             |      - MITRE ATT&CK Framework Table          |
                             |      - CVSS v3.1 Quantitative Risk Gauges    |
                             |      - Rogue Device Alarms & Incident Streams|
                             +----------------------------------------------+
                                                    │
                                                    ▼
                                  [ Access from Any Browser in Institute ]
                                      http://10.13.109.50:3000
```

---

## Open-Source Algorithms & Intelligence Datasets

### 1. IEEE Standards MAC OUI Vendor Recognition (`src/oui_database.py`)
* Comprehensive open-source hardware identifier dataset mapped from the IEEE Standards Association.
* Resolves NIC prefixes to identify physical equipment manufacturers (Intel, Realtek, Dell, HP, Apple, Cisco, TP-Link, MikroTik, Ubiquiti, VMware, Hyper-V, Raspberry Pi).

### 2. MITRE ATT&CK Matrix Threat Mapping (`src/threat_intel.py`)
* Maps discovered events, exposed ports, and active processes directly to standardized MITRE ATT&CK techniques:
  * `T1110.001`: Brute Force Password Guessing (Event ID 4625)
  * `T1003.001`: OS Credential Dumping (`mimikatz.exe`)
  * `T1569.002`: System Service Execution (`psexec.exe`)
  * `T1059.003`: Windows Command Shell (`cmd.exe`, `netcat.exe`)
  * `T1059.001`: PowerShell Scripting Interpreter (`powershell.exe`)
  * `T1210`: Exploitation of Remote Services (Legacy SMBv1 / EternalBlue)
  * `T1021.001`: Remote Desktop Protocol Exposure (Port 3389)

### 3. CVSS v3.1 Quantitative Risk Scoring Algorithm
* Dynamic risk engine calculates a standardized $0.0 - 100.0$ risk score per workstation based on:
  $$\text{Risk Score} = \min\left( \sum \text{CVSS}_{\text{vuln}} \times 3.5 + \sum \text{CVSS}_{\text{proc}} \times 4.0 + \text{BruteForcePenalty} + \text{RoguePenalty},\ 100.0 \right)$$

### 4. Welford Online Z-Score Statistical Anomaly Algorithm
* Computes running mean ($\mu$) and sample variance ($\sigma^2$) in $\mathcal{O}(1)$ time complexity without storing historical arrays in memory.
* Flags network anomalies if $Z = \frac{\text{latency} - \mu}{\sigma} > 3.0$ (indicating network congestion, ARP poisoning, or MITM activity).

---

## Prometheus Metric Dictionary

| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `total_active_endpoints` | `Gauge` | None | Total active computers across all subnets |
| `total_rogue_devices` | `Gauge` | None | Total count of unauthorized / rogue devices detected |
| `total_vulnerabilities_detected` | `Gauge` | None | Total active vulnerability and exposure risks |
| `endpoint_risk_score` | `Gauge` | `target_ip`, `hostname`, `subnet`, `lab_name` | CVSS v3.1 calculated security risk score (0-100) |
| `mitre_attack_technique` | `Gauge` | `target_ip`, `technique_id`, `technique_name`, `tactic`, `severity` | Active MITRE ATT&CK technique indicator |
| `network_latency_anomaly` | `Gauge` | `target_ip`, `subnet` | Value 1 when Z-score exceeds 3 sigma |
| `endpoint_status` | `Gauge` | `target_ip`, `hostname`, `subnet`, `lab_name`, `mac`, `vendor`, `open_services` | Value 1 indicating online machine with full hardware metadata |
| `endpoint_latency_ms` | `Gauge` | `target_ip`, `subnet`, `lab_name` | Round-trip network response latency (in ms) |
| `endpoint_port_exposure`| `Gauge` | `target_ip`, `subnet`, `service` | Value 1 for each open service (RDP, SMB, WMI, WinRM, HTTP) |
| `rogue_device_detected` | `Gauge` | `target_ip`, `mac`, `hostname`, `lab_name` | Value 1 if device is not in asset_whitelist |
| `vulnerability_exposure`| `Gauge` | `target_ip`, `cve_id`, `severity`, `description` | Value 1 when an attack surface vulnerability is flagged |
| `brute_force_attempts_total` | `Counter` | `target_ip`, `lab_name` | Accumulated failed logon events per target IP |
| `suspicious_process_detected` | `Gauge` | `target_ip`, `process_name`, `lab_name` | Value 1 when a blacklisted binary is detected |
| `network_scan_duration_seconds` | `Gauge` | None | Total elapsed time to complete a full network cycle |

---

## Grafana Dashboard Architecture

* Deduplication Strategy: Metrics are queried using `max by (target_ip, hostname, subnet, mac, vendor) (endpoint_status)` to prevent multi-target duplicate rows.
* Transformation Pipeline: Uses Grafana's native `labelsToFields` (mode: `columns`) and `organize` to map Prometheus multi-series dataframes directly into structured table columns.
* Auto-Refresh Interval: Configured for 5 seconds real-time streaming updates.
