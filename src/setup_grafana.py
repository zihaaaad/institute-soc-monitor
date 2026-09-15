"""Provision the Prometheus data source and the Monitro SOC dashboard in Grafana.

Authentication (first match wins):
  GRAFANA_TOKEN                      service-account token (recommended)
  GRAFANA_USER + GRAFANA_PASSWORD    basic auth
  interactive prompt                 when run from a terminal
Default admin/admin credentials are never assumed.
"""
from __future__ import annotations

import base64
import getpass
import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any

from config_loader import ConfigError, load_config

DASHBOARD_UID = "institute-soc-overview"


class GrafanaClient:
    def __init__(self, base_url: str, auth_header: str):
        self.base_url = base_url.rstrip("/")
        self.auth_header = auth_header

    def request(self, path: str, method: str = "GET", data: Any = None) -> Any:
        body = json.dumps(data).encode("utf-8") if data is not None else None
        req = urllib.request.Request(f"{self.base_url}{path}", data=body, method=method, headers={
            "Authorization": self.auth_header, "Content-Type": "application/json", "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"Grafana {method} {path} failed: HTTP {e.code} {detail}") from None
        return json.loads(raw) if raw else {}


def resolve_auth() -> str:
    token = os.environ.get("GRAFANA_TOKEN", "").strip()
    if token:
        return f"Bearer {token}"
    user = os.environ.get("GRAFANA_USER", "").strip()
    password = os.environ.get("GRAFANA_PASSWORD", "")
    if not (user and password):
        if not sys.stdin.isatty():
            raise RuntimeError("Set GRAFANA_TOKEN or GRAFANA_USER/GRAFANA_PASSWORD (no terminal available to prompt).")
        user = input("Grafana admin username [admin]: ").strip() or "admin"
        password = getpass.getpass("Grafana password: ")
    if password == "admin":
        print("[WARNING] Grafana is using the default password. Change it before exposing port 3000 on the network.")
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


# ---------------------------------------------------------------------------
# Panel builders (schema 41, native table format + merge transformation)
# ---------------------------------------------------------------------------
def _thresholds(*steps: tuple[str, float | None]) -> dict[str, Any]:
    return {"mode": "absolute", "steps": [{"color": c, "value": v} for c, v in steps]}


def stat_panel(pid: int, title: str, expr: str, x: int, ds: dict, thresholds: dict, unit: str = "short",
               color_mode: str = "background", description: str = "") -> dict[str, Any]:
    return {
        "id": pid, "title": title, "description": description, "type": "stat", "datasource": ds,
        "gridPos": {"h": 4, "w": 3, "x": x, "y": 0},
        "targets": [{"expr": expr, "refId": "A", "instant": True}],
        "options": {"colorMode": color_mode, "graphMode": "none", "justifyMode": "center", "textMode": "value",
                    "reduceOptions": {"calcs": ["lastNotNull"], "values": False}},
        "fieldConfig": {"defaults": {"unit": unit, "decimals": 0, "color": {"mode": "thresholds"},
                                     "thresholds": thresholds, "noValue": "no data"}, "overrides": []},
    }


def table_panel(pid: int, title: str, expr: str, grid: dict, ds: dict, rename: dict[str, str],
                exclude: tuple[str, ...] = ("Time", "__name__", "Value"), overrides: list | None = None) -> dict[str, Any]:
    return {
        "id": pid, "title": title, "type": "table", "datasource": ds, "gridPos": grid,
        "targets": [{"expr": expr, "instant": True, "format": "table", "refId": "A"}],
        "transformations": [
            {"id": "merge", "options": {}},
            {"id": "organize", "options": {"excludeByName": {k: True for k in exclude},
                                           "indexByName": {k: i for i, k in enumerate(rename)},
                                           "renameByName": rename}},
        ],
        "options": {"frameIndex": 0, "showHeader": True, "showTypeIcons": False, "sortBy": []},
        "fieldConfig": {"defaults": {"custom": {"align": "auto", "cellOptions": {"type": "auto"}, "filterable": True}},
                        "overrides": overrides or []},
    }


def severity_override(field: str) -> dict[str, Any]:
    colors = {"CRITICAL": "dark-red", "HIGH": "red", "MEDIUM": "dark-orange", "LOW": "blue", "INFO": "text"}
    return {"matcher": {"id": "byName", "options": field}, "properties": [
        {"id": "custom.cellOptions", "value": {"type": "color-text"}},
        {"id": "mappings", "value": [{"type": "value", "options": {k: {"text": k, "color": c} for k, c in colors.items()}}]},
    ]}


def bargauge_panel(pid: int, title: str, expr: str, grid: dict, ds: dict, unit: str, thresholds: dict, maximum: float | None) -> dict[str, Any]:
    defaults: dict[str, Any] = {"unit": unit, "min": 0, "decimals": 1 if unit == "ms" else 0,
                                "color": {"mode": "thresholds"}, "thresholds": thresholds}
    if maximum is not None:
        defaults["max"] = maximum
    return {
        "id": pid, "title": title, "type": "bargauge", "datasource": ds, "gridPos": grid,
        "targets": [{"expr": expr, "legendFormat": "{{target_ip}}", "refId": "A", "instant": True}],
        "options": {"displayMode": "gradient", "orientation": "horizontal", "showUnfilled": True,
                    "reduceOptions": {"calcs": ["lastNotNull"], "values": False}},
        "fieldConfig": {"defaults": defaults, "overrides": []},
    }


def build_dashboard(ds_uid: str) -> dict[str, Any]:
    ds = {"type": "prometheus", "uid": ds_uid}
    green, amber, red = "#10B981", "#F59E0B", "#EF4444"
    panels = [
        stat_panel(1, "Live Hosts", "total_active_endpoints", 0, ds, _thresholds(("dark-green", None)), color_mode="value"),
        stat_panel(2, "Rogue Devices", "total_rogue_devices", 3, ds, _thresholds((green, None), (red, 1)),
                   description="MAC visible and not on asset_whitelist"),
        stat_panel(3, "Unverified (Routed)", "total_unverified_devices", 6, ds, _thresholds(("text", None)), color_mode="value",
                   description="Hosts on routed segments: MAC not visible, identity cannot be verified"),
        stat_panel(4, "Exposures (LOW+)", "total_vulnerabilities_detected", 9, ds, _thresholds((green, None), (amber, 1), (red, 20))),
        stat_panel(5, "Hosts with Detections", "total_threat_endpoints", 12, ds, _thresholds((green, None), (red, 1))),
        stat_panel(6, "Compliant Hosts", "network_health_index", 15, ds, _thresholds((red, None), (amber, 70), (green, 90)),
                   unit="percent", color_mode="value", description="Not rogue, no MEDIUM+ exposure, no detection"),
        stat_panel(7, "Failed Logons (15m)", "sum(increase(brute_force_attempts_total[15m])) or vector(0)", 18, ds,
                   _thresholds((green, None), (amber, 5), (red, 20))),
        stat_panel(8, "Monitor Heartbeat", "time() - monitor_last_scan_timestamp_seconds", 21, ds,
                   _thresholds((green, None), (amber, 180), (red, 600)), unit="s", color_mode="value",
                   description="Seconds since the last completed sweep. 'no data' means the monitor is down."),
        table_panel(9, "Active Threat Detections (triage first)",
                    'max by (target_ip, severity, technique_id, technique_name, tactic) (mitre_attack_technique{evidence="detection"})',
                    {"h": 7, "w": 24, "x": 0, "y": 4}, ds,
                    {"target_ip": "Host", "severity": "Severity", "technique_id": "ATT&CK ID", "technique_name": "Technique", "tactic": "Tactic"},
                    overrides=[severity_override("Severity")]),
        table_panel(10, "Endpoint Inventory",
                    "max by (target_ip, hostname, lab_name, mac, vendor, open_services, asset_status) (endpoint_status)",
                    {"h": 11, "w": 24, "x": 0, "y": 11}, ds,
                    {"target_ip": "IP", "hostname": "Hostname", "lab_name": "Segment", "mac": "MAC", "vendor": "Vendor",
                     "open_services": "Services", "asset_status": "Asset Status"}),
        table_panel(11, "Exposure Findings",
                    'max by (target_ip, cve_id, severity, description) (vulnerability_exposure{severity!="INFO"})',
                    {"h": 9, "w": 14, "x": 0, "y": 22}, ds,
                    {"target_ip": "Host", "cve_id": "Finding", "severity": "Severity", "description": "Description"},
                    overrides=[severity_override("Severity")]),
        table_panel(12, "Rogue Device Alarms", "max by (target_ip, mac, hostname, lab_name) (rogue_device_detected)",
                    {"h": 9, "w": 10, "x": 14, "y": 22}, ds,
                    {"target_ip": "IP", "mac": "MAC", "hostname": "Hostname", "lab_name": "Segment"}),
        bargauge_panel(13, "Highest Endpoint Risk Scores", "topk(20, max by (target_ip) (endpoint_risk_score))",
                       {"h": 9, "w": 12, "x": 0, "y": 31}, ds, "short", _thresholds((green, None), (amber, 30), (red, 60)), 100),
        bargauge_panel(14, "Slowest Endpoints (TCP RTT)", "topk(20, max by (target_ip) (endpoint_latency_ms))",
                       {"h": 9, "w": 12, "x": 12, "y": 31}, ds, "ms", _thresholds((green, None), (amber, 30), (red, 100)), None),
        {
            "id": 15, "title": "Live Hosts per Segment", "type": "timeseries", "datasource": ds,
            "gridPos": {"h": 8, "w": 24, "x": 0, "y": 40},
            "targets": [{"expr": "active_network_hosts > 0", "legendFormat": "{{lab_name}}", "refId": "A"}],
            "options": {"legend": {"calcs": ["lastNotNull", "max", "min"], "displayMode": "table", "placement": "right"},
                        "tooltip": {"mode": "multi", "sort": "desc"}},
            "fieldConfig": {"defaults": {"unit": "short", "custom": {"drawStyle": "line", "lineWidth": 2, "fillOpacity": 10, "spanNulls": False},
                                         "color": {"mode": "palette-classic"}}, "overrides": []},
        },
    ]
    return {
        "dashboard": {
            "id": None, "uid": DASHBOARD_UID, "title": "Monitro SOC - Network Security Monitor",
            "tags": ["soc", "security", "network", "mitre-attack"], "timezone": "browser",
            "schemaVersion": 41, "refresh": "30s", "time": {"from": "now-6h", "to": "now"}, "panels": panels,
        },
        "overwrite": True,
    }


def deploy(client: GrafanaClient, prometheus_url: str) -> str:
    datasources = client.request("/api/datasources")
    prom = next((d for d in datasources if d.get("type") == "prometheus"), None)
    if prom:
        ds_uid = prom["uid"]
        print(f"[OK] Using existing Prometheus data source (uid {ds_uid}, url {prom.get('url')})")
    else:
        res = client.request("/api/datasources", "POST", {
            "name": "Prometheus", "type": "prometheus", "access": "proxy", "url": prometheus_url,
            "isDefault": True, "jsonData": {"httpMethod": "POST"}})
        ds_uid = res.get("datasource", {}).get("uid", "")
        print(f"[OK] Created Prometheus data source -> {prometheus_url}")

    res = client.request("/api/dashboards/db", "POST", build_dashboard(ds_uid))
    try:
        client.request("/api/org/preferences", "PATCH", {"homeDashboardUID": DASHBOARD_UID})
    except RuntimeError as e:
        print(f"[WARN] Could not set home dashboard: {e}")
    return f"{client.base_url}{res.get('url', '/d/' + DASHBOARD_UID)}"


def main() -> int:
    try:
        config = load_config()
        client = GrafanaClient(config["settings"]["grafana_url"], resolve_auth())
        url = deploy(client, config["settings"]["prometheus_url"])
    except (ConfigError, RuntimeError, urllib.error.URLError, OSError) as e:
        print(f"[ERROR] Grafana provisioning failed: {e}")
        return 1
    print(f"[SUCCESS] Dashboard deployed: {url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
