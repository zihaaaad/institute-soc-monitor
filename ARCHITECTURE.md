# Technical Architecture & Data Pipeline

This document outlines the core architecture, agentless discovery mechanics, Prometheus telemetry definitions, and Grafana integration for the Institute Cyber Security SOC & Network Monitor.

---

## High-Level System Architecture

```
                                  [ INSTITUTE MULTI-SUBNET LAB NETWORK ]
                                (Lab 1: 10.13.109.0/24, Lab 2: 110.0/24, Lab 3: 111.0/24)
                                                    │
                                                    │ (1. Multi-threaded TCP Probe [135,445,80,3389,5985])
                                                    │ (2. Windows Native ARP Table Resolution)
                                                    │ (3. Remote WMI Security Audit [Events & Processes])
                                                    ▼
                             +----------------------------------------------+
                             |   Python Agentless Engine (src\agentless_*)  |
                             |      - Multi-threaded Sweep (80 Workers)     |
                             |      - Hardware Vendor (MAC OUI) Mapping     |
                             |      - Exposes Prometheus Metrics on :8000   |
                             +----------------------------------------------+
                                                    │
                                                    │ Scrapes :8000/metrics every 5-15s
                                                    ▼
                             +----------------------------------------------+
                             |    Standalone Prometheus Server (:9090)      |
                             |      - Time-Series Database (TSDB)           |
                             |      - Evaluates PromQL Queries & Vectors    |
                             +----------------------------------------------+
                                                    │
                                                    │ Queries /api/ds/query
                                                    ▼
                             +----------------------------------------------+
                             |        Grafana Enterprise SOC (:3000)        |
                             |      - High-Readability Interactive Panels   |
                             |      - Master Endpoint Matrix with organize  |
                             |      - Attack Surface & Threat Trajectories  |
                             +----------------------------------------------+
                                                    │
                                                    ▼
                                  [ Access from Any Browser in Institute ]
                                      http://10.13.109.50:3000
```

---

## Agentless Discovery Engine Mechanics

### 1. Multi-Threaded TCP Port Sweep
* Standard ICMP Ping or Layer-2 broadcast ARP cannot cross routed switches/VLANs without router reconfiguration.
* The engine uses `concurrent.futures.ThreadPoolExecutor` (80 parallel workers) with non-blocking socket connections (`connect_ex`) across standard Windows service ports (135, 445, 80, 443, 3389, 5985, 8080).
* Performance: An entire `/24` subnet (254 addresses) is fully scanned in under 1.8 seconds.

### 2. MAC Address & Vendor OUI Extraction
* For local broadcast segments, the engine extracts physical hardware addresses from the kernel ARP table (`arp -a`).
* Matches the first 3 octets against a local Organizationally Unique Identifier (OUI) dictionary to identify the hardware manufacturer (such as Intel, Realtek, Dell, HP, VMware, Hyper-V).

### 3. Agentless Remote WMI Security Auditing
* Connects remotely using native Windows Management Instrumentation (WMI):
  * Failed Authentication Audits: Queries `Win32_NTLogEvent(Logfile='Security', EventCode='4625')` to detect brute-force attacks in progress.
  * Process Tree Inspection: Inspects `Win32_Process` against a security blacklist of unauthorized shells and pen-testing tools.

---

## Prometheus Metric Dictionary

| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `total_active_endpoints` | `Gauge` | None | Total active computers across all subnets |
| `total_rogue_devices` | `Gauge` | None | Total count of unauthorized / rogue devices detected |
| `total_vulnerabilities_detected` | `Gauge` | None | Total active vulnerability and exposure risks |
| `active_network_hosts` | `Gauge` | `subnet`, `lab_name` | Number of active endpoints in each lab segment |
| `endpoint_status` | `Gauge` | `target_ip`, `hostname`, `subnet`, `lab_name`, `mac`, `vendor`, `open_services` | Value 1 indicating an online machine with full hardware metadata |
| `endpoint_latency_ms` | `Gauge` | `target_ip`, `subnet`, `lab_name` | Round-trip network response latency (in ms) |
| `endpoint_port_exposure`| `Gauge` | `target_ip`, `subnet`, `service` | Value 1 for each open service (RDP, SMB, WMI, WinRM, HTTP) |
| `rogue_device_detected` | `Gauge` | `target_ip`, `mac`, `hostname`, `lab_name` | Value 1 if the device is not in asset_whitelist |
| `vulnerability_exposure`| `Gauge` | `target_ip`, `cve_id`, `severity`, `description` | Value 1 when an attack surface vulnerability is flagged |
| `brute_force_attempts_total` | `Counter` | `target_ip`, `lab_name` | Accumulated failed logon events per target IP |
| `suspicious_process_detected` | `Gauge` | `target_ip`, `process_name`, `lab_name` | Value 1 when a blacklisted binary is detected |
| `network_scan_duration_seconds` | `Gauge` | None | Total elapsed time to complete a full network cycle |

---

## Grafana Dashboard Architecture

* Deduplication Strategy: Metrics are queried using `max by (target_ip, hostname, subnet, mac) (endpoint_status)` to prevent multi-target duplicate rows.
* Transformation Pipeline: Uses Grafana's native `labelsToFields` (mode: `columns`) and `organize` to map Prometheus multi-series dataframes directly into structured table columns.
* Auto-Refresh Interval: Configured for 5 seconds real-time streaming updates.

