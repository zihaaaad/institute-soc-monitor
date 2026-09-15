# Monitro - Agentless SOC Network Monitor

Agentless network security monitoring for institute and campus LANs: asset discovery, rogue-device
detection, exposure auditing, and optional WMI endpoint threat detection, visualised in Grafana.
Nothing is installed on monitored hosts and no switch or router changes are needed.

> **Authorised use only.** Scanning networks you do not own or administer may be illegal. Monitro
> refuses public IP ranges unless explicitly enabled. Read [SECURITY.md](SECURITY.md) before deploying.

## What it does

| Capability | How | Limits |
| :--- | :--- | :--- |
| Asset discovery | TCP connect probes, ARP cache, Win32 `SendARP` on the local segment | ICMP is not used; hosts that answer on no probed port and are off-segment are invisible |
| Device identity | MAC -> vendor via the IEEE registry (`data/oui.csv`), NetBIOS / reverse DNS names | MACs are only visible on the sensor's own L2 segment; everything routed is `unverified` |
| Rogue devices | MAC compared with `asset_whitelist` | MAC spoofing defeats it; it complements, not replaces, 802.1X/NAC |
| Exposures | SMBv1 negotiate probe, RDP, VNC, Telnet, FTP, HTTP, databases, RPC | Exposure means "reachable", not "exploitable" |
| ARP spoofing indicator | One MAC answering for several IPs | Proxy-ARP routers and multi-homed servers can trigger it |
| Endpoint detections (WMI) | Event 4625 brute force / password spray, offensive tooling by process name, malicious command lines (encoded PowerShell, LSASS dumps, shadow-copy deletion...) | Needs credentials; only runs against whitelisted hosts; not a replacement for EDR/Sysmon |
| Alerting | `logs/alerts.jsonl` always; Discord / Telegram optionally | Webhooks leave your network - evidence is excluded by default |

## Quick start

Prerequisites: Windows, Python 3.10+, [Grafana OSS](https://grafana.com/grafana/download). Administrator rights are **not** needed.

1. **Configure** the subnets you are authorised to monitor in `config.json`. Put anything secret in
   `config.local.json` (git-ignored) or environment variables - never in `config.json`.
2. **Set up:** run `setup.bat`. It installs dependencies, downloads Prometheus (SHA-256 verified),
   fetches the IEEE vendor registry and provisions the Grafana dashboard (it asks for your Grafana
   credentials, or uses `GRAFANA_TOKEN`).
3. **Baseline assets:** `python src\agentless_monitor_win.py --export-baseline`, review
   `asset_baseline.json` line by line, then copy its `asset_whitelist` into `config.local.json`.
   Until you do, rogue detection and WMI auditing stay off.
4. **Start:** `start.bat`, then open http://localhost:3000/d/institute-soc-overview. Stop with `stop.bat`.

### Optional: endpoint auditing over WMI

```cmd
setx MONITRO_WINDOWS_USER "CORP\svc-monitro-audit"
setx MONITRO_WINDOWS_PASSWORD "..."
```

Use a dedicated low-privilege account (see [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md#least-privilege-wmi-account)),
never a domain admin. Credentials are only sent to hosts whose MAC is on the whitelist.

### Optional: alerts

```cmd
setx MONITRO_DISCORD_WEBHOOK_URL "https://discord.com/api/webhooks/..."
```
and set `"alerts": {"enabled": true}` in `config.local.json`.

## Commands

| Command | Purpose |
| :--- | :--- |
| `python src\agentless_monitor_win.py` | Run the monitor and Prometheus exporter (127.0.0.1:8000) |
| `python src\agentless_monitor_win.py --once` | One sweep, JSON summary to stdout |
| `python src\agentless_monitor_win.py --export-baseline` | One sweep, write `asset_baseline.json` for review |
| `python src\generate_report.py` | Markdown + HTML audit report. Exit 0 = fresh, 1 = stale, 2 = no data |
| `python src\soc_dashboard.py` | Standalone web console on 127.0.0.1:5000 (use *instead of* the monitor) |
| `python src\setup_grafana.py` | Re-provision the Grafana dashboard |
| `python -m unittest discover -s tests -t .` | Test suite (`pip install -r requirements-dev.txt` for dashboard tests) |

## Services and exposure

| Service | Address | Exposure |
| :--- | :--- | :--- |
| Grafana | `:3000` | The only UI meant for the network. Change the admin password; put HTTPS in front |
| Prometheus | `127.0.0.1:9090` | Loopback only (no authentication) |
| Monitor metrics | `127.0.0.1:8000` | Loopback only (contains the full network map) |
| Standalone console | `127.0.0.1:5000` | Loopback by default; other addresses require credentials |

## Layout

```
config.json / config.example.json   tracked settings (no secrets) / template for config.local.json
setup.bat, start.bat, stop.bat      install, launch, stop (tools\stop-monitro.ps1 stops only this folder's processes)
src/
  agentless_monitor_win.py          entry point: sweep loop + Prometheus exporter
  engine.py                         discovery scheduling, asset classification, host views
  scanner.py                        TCP/ARP/NetBIOS/SMBv1 primitives
  wmi_audit.py                      WMI endpoint auditing and detection logic
  threat_intel.py                   exposure/detection catalogs, ATT&CK mapping, risk score, latency anomalies
  metrics_collector.py              Prometheus collector (series rebuilt every scrape)
  alerting.py                       JSONL audit log + webhooks
  oui_database.py                   MAC vendor lookup
  generate_report.py                executive report
  soc_dashboard.py                  standalone FastAPI console
  setup_grafana.py                  Grafana provisioning
tests/                              unit and socket-level tests
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the data flow and metric dictionary, [ANALYSIS.md](ANALYSIS.md)
for performance and failure modes, and [SECURITY.md](SECURITY.md) for the threat model.

## License

MIT - see [LICENSE](LICENSE).
