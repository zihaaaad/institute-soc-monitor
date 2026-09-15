# Security Model

Monitro holds a live map of the network and its weaknesses, and optionally privileged credentials.
Treat the monitoring host as a sensitive system.

## Threat model

| Threat | Control |
| :--- | :--- |
| Rogue device harvests the audit account's NTLM response when the monitor authenticates to it | WMI credentials are sent only to hosts whose MAC is on `asset_whitelist`. Rogue, unverified (routed) and unmanaged hosts are never audited unless `wmi_audit.audit_unverified_hosts` is enabled, and rogue hosts never are. Use a dedicated low-privilege account. |
| Credential leakage through source control | Secrets are read from `config.local.json` (git-ignored) or `MONITRO_*` environment variables. A warning is logged if a secret appears in tracked `config.json`. |
| Network inventory disclosure | Exporter and Prometheus bind to `127.0.0.1`. The standalone console binds to loopback and refuses other addresses without credentials. Scan output (`scratch/`, `logs/`, `asset_baseline.json`, reports) is git-ignored. |
| Stored XSS via hostnames (reverse DNS, NetBIOS and LLMNR are attacker-controlled) | Hostnames are reduced to RFC 1123 characters. Reports are HTML-escaped with a hash-based CSP. The console renders with `textContent` under a strict CSP and no third-party scripts. |
| Webhook abuse | `https://` only, `@everyone`/role mentions disabled, evidence (command lines, account names) kept local unless `alerts.include_evidence` is true. Webhook URLs are never logged. |
| CSRF against the console | State-changing requests require a custom header, and CORS is not enabled. |
| Tampered Prometheus download | `setup.bat` verifies the pinned SHA-256 from the official release before extracting. |
| Monitoring silently stops | `monitor_last_scan_timestamp_seconds` drives a heartbeat panel. Reports refuse to claim a healthy posture from stale or missing data. |
| Scanning disrupts fragile devices (BMS, CCTV, VoIP) or trips IDS | Short discovery probes, full fingerprinting only every 15 minutes, dark address space backed off, no UDP or exploit traffic. Remove sensitive segments from `subnets` if their owners have not approved scanning. |

## Least-privilege WMI account

Do not use a domain admin. Create `svc-monitro-audit` and on target hosts (via GPO):

1. Add it to **Event Log Readers** (Security log access for event 4625).
2. Grant **Remote Enable** and **Enable Account** on the `root\cimv2` WMI namespace (`wmimgmt.msc`).
3. Grant **Remote Activation** in DCOM security (`dcomcnfg`), or add it to **Distributed COM Users**.
4. Deny interactive and RDP logon for the account.

Seeing other users' process command lines needs local administrator rights. Without them, command-line
rules only see the account's own processes, while process-name detection still works.

Prefer Kerberos: set `credentials.windows_authority` to `kerberos:DOMAIN\HOSTNAME` where possible, and
restrict or disable NTLM in the domain.

## Known limitations

* MAC allow-listing is spoofable and blind across routers. Use 802.1X/NAC for enforcement; Monitro is a detective control.
* WMI polling is not a substitute for EDR, Sysmon or Windows Event Forwarding into a SIEM. Renamed binaries evade name-based detection.
* HTTP Basic auth on the console must be wrapped in TLS (reverse proxy) for any non-local access.

## Reporting a vulnerability

Please report security issues privately to the repository owner instead of opening a public issue.
