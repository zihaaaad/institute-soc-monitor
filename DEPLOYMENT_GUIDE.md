# Deployment Guide

## Placement

Run the sensor on a dedicated, patched Windows host inside the SOC/admin VLAN (e.g. `10.13.109.0/24`).

* MAC visibility, and therefore rogue detection, only exists on the sensor's own segment. For other
  VLANs, either accept `unverified` status, run an additional sensor per VLAN, or feed DHCP/switch data
  into your SIEM.
* Allow the sensor through inter-VLAN ACLs for the probed TCP ports and UDP 137. Tell the network team
  and whitelist the sensor in IDS/IPS, otherwise the sweep looks like a port scan (because it is one).
* Get written approval before scanning facility (BMS), CCTV and VoIP segments. If fragile devices are
  affected, remove those subnets or raise `probe_timeout_seconds` and `scan_interval_seconds`.

## Configuration files

| File | Tracked in git | Use |
| :--- | :--- | :--- |
| `config.json` | yes | Subnets and non-secret settings |
| `config.local.json` | no | Site overrides and secrets (deep-merged over `config.json`) |
| Environment variables | - | `MONITRO_WINDOWS_USER`, `MONITRO_WINDOWS_PASSWORD`, `MONITRO_WINDOWS_AUTHORITY`, `MONITRO_DISCORD_WEBHOOK_URL`, `MONITRO_TELEGRAM_BOT_TOKEN`, `MONITRO_TELEGRAM_CHAT_ID`, `MONITRO_DASHBOARD_USER`, `MONITRO_DASHBOARD_PASSWORD` |

See `config.example.json` for every option. Maps such as `subnets` are merged, not replaced.

## First deployment

1. Install Python 3.10+ ("Add to PATH") and Grafana OSS, then change Grafana's admin password.
2. Run `setup.bat`.
3. Run `python src\agentless_monitor_win.py --once` to confirm reachability and sweep time.
4. Build the whitelist:
   `python src\agentless_monitor_win.py --export-baseline`, then verify each device against your asset
   register and copy the MACs into `config.local.json`.
5. Optionally, set WMI credentials (least-privilege account, see [SECURITY.md](SECURITY.md)) and
   webhooks.
6. Run `start.bat`.

To run at boot, use Task Scheduler "At startup" with a service account, running
`python <folder>\src\agentless_monitor_win.py`, plus Prometheus with the same flags as in `start.bat`.

## Least-privilege WMI account

Covered in [SECURITY.md](SECURITY.md#least-privilege-wmi-account).

## Moving the installation

All scripts use paths relative to the install folder. After moving, run `stop.bat` in the old location
first (it only matches processes from its own folder), then run `start.bat` from the new one.

## Troubleshooting

| Symptom | Cause | Fix |
| :--- | :--- | :--- |
| `Cannot bind metrics endpoint` | Another instance is running, or port 8000 is taken | `stop.bat`, or change `settings.metrics_port` and `prometheus.yml` together |
| Heartbeat panel shows "no data" | Monitor not running or Prometheus cannot scrape it | Check the monitor window and `logs\monitor.log`; open http://127.0.0.1:9090/targets |
| Everything is `unverified` | Sensor is not on those segments | Expected for routed subnets; see Placement |
| Rogue count is 0 | Whitelist empty (`unmanaged`) | Build the baseline (step 4) |
| WMI audit shows `failed (com_error...)` | Firewall, DCOM or WMI permissions | Allow "Windows Management Instrumentation (DCOM-In)" and check the account rights |
| WMI never runs | No credentials, host not whitelisted, or 135 closed | See `wmi_status` in the console or `wmi_audit_success` in Prometheus |
| Sweep slower than interval | Too much dark space or too low a timeout budget | Raise `scan_interval_seconds`, remove unused subnets, raise `probe_workers` |
| Report exits with code 2 | Prometheus unreachable or no sweep yet | Start the stack, wait for one sweep |
