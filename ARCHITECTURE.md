# Architecture

## Data flow

```
                    subnets in config.json (authorised, private ranges)
                                         |
      TCP connect probes / arp -a / SendARP (local segment) / NetBIOS + rDNS / SMBv1 negotiate
                                         v
+-----------------------------------------------------------------------------------------+
| agentless_monitor_win.py                                                                |
|   engine.SweepEngine      schedule probes, classify assets, map exposures, ARP checks    |
|   wmi_audit.WmiAuditor    bounded pool, whitelisted hosts only, 4625 + processes         |
|   alerting.AlertDispatcher logs/alerts.jsonl + Discord/Telegram queue                    |
|   metrics_collector.SocCollector  -> 127.0.0.1:8000/metrics (rebuilt on every scrape)   |
+-----------------------------------------------------------------------------------------+
                                         | scrape every 30s
                                         v
                   Prometheus 127.0.0.1:9090 (30 day retention)
                         |                               |
                         v                               v
              Grafana :3000 dashboard           generate_report.py (MD + HTML)
```

`soc_dashboard.py` is an alternative front end. It embeds the same engine and auditor and serves a
JSON API and UI on 127.0.0.1:5000 without Prometheus or Grafana.

## Sweep cycle (`engine.py`)

1. Read the ARP cache.
2. Pick candidate IPs: known hosts, ARP entries, and dark IPs that are either in their first three
   misses or due in the 1-in-5 rotation.
3. For each candidate, in a `probe_workers` thread pool:
   * resolve the MAC with `SendARP` if the IP is on the sensor's own segment;
   * run a quick probe of the last known open ports, then `DISCOVERY_PORTS`, stopping at the first
     answer (an RST also counts as alive);
   * for new hosts, or every `service_scan_interval_seconds`, fingerprint all of `PORT_SERVICE_MAP`
     and run the SMBv1 check if 445 is open;
   * resolve the name (NetBIOS, then reverse DNS, cached for 1 hour).
4. Build `HostRecord`s: vendor, `asset_status`, exposures, latency anomaly (per-host Welford z-score
   on TCP round-trip time).
5. Flag MACs claimed by several IPs (T1557.002 indicator).
6. Publish the snapshot atomically, raise alerts (rogue, HIGH+ exposures, ARP), submit eligible hosts
   for WMI audit.

### Asset status

| Status | Meaning | WMI audit |
| :--- | :--- | :--- |
| `authorized` | MAC visible and on the whitelist | yes |
| `rogue` | MAC visible and not on the whitelist | never |
| `unverified` | Routed segment, MAC not visible | only with `audit_unverified_hosts` |
| `unmanaged` | Whitelist is empty | only with `audit_unverified_hosts` |

## Evidence model (`threat_intel.py`)

* **Exposures** are network-observed configuration weaknesses, each linked to the ATT&CK technique it
  *enables*: SMBV1-ENABLED, TELNET-CLEARTEXT, FTP-CLEARTEXT, RDP-EXPOSURE, VNC-EXPOSURE,
  DATABASE-EXPOSURE, HTTP-CLEARTEXT, RPC-EXPOSURE (INFO).
* **Detections** are observed behaviour: BRUTE-FORCE (T1110.001), PASSWORD-SPRAY (T1110.003),
  ARP-DUPLICATE-MAC (T1557.002), known tooling by process name (mimikatz T1003.001, rubeus T1558,
  psexec T1569.002, ...), and command-line rules (PS-ENCODED T1027, PS-DOWNLOAD-CRADLE T1059.001,
  LSASS-MINIDUMP T1003.001, SHADOW-COPY-DELETE T1490, CERTUTIL-DOWNLOAD T1105, ...).

**Risk score (0-100):** weights (0-10) sorted in descending order, where finding *i* contributes
`weight x 10 / 2^i`, plus 30 for a rogue device, capped at 100. These are analyst-assigned weights,
not computed CVSS base scores.

**Compliance (`network_health_index`):** the percentage of live hosts that are not rogue, have no
MEDIUM-or-higher exposure, and have no detection. It is not emitted when there are no hosts, so it
never shows a fake 100%.

## WMI auditing (`wmi_audit.py`)

* `SWbemLocator.ConnectServer` with a 2-minute connect cap, `Impersonate`, and **packet privacy**
  authentication.
* Event 4625 is queried with a `TimeGenerated` lookback window and de-duplicated by `RecordNumber`,
  so repeated audits never double count.
* `Win32_Process` Name, ProcessId and CommandLine are checked against the blacklist and the
  command-line rules.
* Up to `max_concurrent_audits` run at a time. A host still in flight is skipped. Results expire after
  3 x the scan interval (minimum 10 minutes).

## Metric dictionary

All series are rebuilt from the latest snapshot on every scrape. Offline hosts and remediated findings
disappear immediately.

| Metric | Labels | Meaning |
| :--- | :--- | :--- |
| `monitor_last_scan_timestamp_seconds` | - | Unix time of last completed sweep (heartbeat) |
| `monitor_scanning` | - | 1 while a sweep runs |
| `network_scan_duration_seconds` | - | Last sweep duration |
| `monitor_ips_probed` | `scope` | Addresses probed vs configured |
| `total_active_endpoints` | - | Live hosts |
| `total_rogue_devices` / `total_unverified_devices` | - | Asset status counts |
| `total_vulnerabilities_detected` | - | Exposures of LOW or higher |
| `total_threat_endpoints` | - | Hosts with at least one detection |
| `network_health_index` | - | Compliance percentage (absent with no hosts) |
| `endpoint_status` | `target_ip, hostname, subnet, lab_name, mac, vendor, open_services, asset_status` | Inventory, value 1 |
| `endpoint_latency_ms` | `target_ip, subnet, lab_name` | TCP round-trip time |
| `network_latency_anomaly` | `target_ip, subnet` | 1 if above the host's 3-sigma baseline and at least 15 ms over the mean |
| `endpoint_port_exposure` | `target_ip, subnet, service` | Open service, value 1 |
| `endpoint_risk_score` | `target_ip, hostname, subnet, lab_name` | 0-100 |
| `rogue_device_detected` | `target_ip, mac, hostname, lab_name` | Rogue host, value 1 |
| `vulnerability_exposure` | `target_ip, cve_id, severity, description` | Exposure finding (`cve_id` holds the finding ID) |
| `mitre_attack_technique` | `target_ip, technique_id, technique_name, tactic, severity, evidence` | `evidence` is `exposure` or `detection` |
| `suspicious_process_detected` | `target_ip, process_name, lab_name` | Blacklisted process running, value 1 |
| `wmi_audit_success` | `target_ip` | 1 or 0 for the last fresh audit |
| `brute_force_attempts_total` | `target_ip, lab_name` | Failed logons since monitor start (counter) |
| `active_network_hosts` / `lab_threat_count` | `subnet, lab_name` | Per-segment counts |

## Grafana dashboard (`setup_grafana.py`)

The dashboard uses schema version 41 with native `table` format queries plus `merge` and `organize`
transformations. The top row is heartbeat and KPIs. Below it: a triage table of detections, the
inventory, exposures, rogue alarms, top-20 risk and latency, and live hosts per segment.
