import os
import time
import socket
import threading
import logging
import subprocess
import re
import html
import json
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any
from datetime import datetime

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn
import pythoncom
import wmi

from config_loader import load_config, BASE_DIR
from oui_database import lookup_mac_vendor
from threat_intel import MITRE_TECHNIQUES, calculate_endpoint_risk_score

log = logging.getLogger("monitro.dashboard")
config = load_config()

SUBNET_LAB_MAP = config.get("subnets", {})
PROBE_PORTS = [135, 445, 80, 443, 3389, 5985, 8080]
WINDOWS_USER = config.get("credentials", {}).get("windows_user", "")
WINDOWS_PASS = config.get("credentials", {}).get("windows_password", "")
SUSPICIOUS_PROCESSES = [p.lower() for p in config.get("suspicious_processes", [])]
ASSET_WHITELIST = set(m.lower().replace("-", ":") for m in config.get("asset_whitelist", []))

app = FastAPI(title="Institute Cyber SOC Web Console")

# In-Memory State Store
state: Dict[str, Any] = {
    "is_scanning": False,
    "last_scan_time": "Never",
    "total_hosts_count": 0,
    "subnet_stats": {},
    "hosts": {},
    "alerts": [],
    "history": []
}
state_lock = threading.Lock()

def add_alert(ip: str, alert_type: str, severity: str, message: str):
    with state_lock:
        alert_entry = {
            "id": len(state["alerts"]) + 1,
            "time": datetime.now().strftime("%H:%M:%S"),
            "ip": ip,
            "type": alert_type,
            "severity": severity,
            "message": message
        }
        state["alerts"].insert(0, alert_entry)
        if len(state["alerts"]) > 100:
            state["alerts"] = state["alerts"][:100]

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return f"PC-{ip.split('.')[-1]}"

def get_arp_cache() -> Dict[str, str]:
    try:
        out = subprocess.check_output('arp -a', shell=True).decode('cp1252', errors='ignore')
        arp_map = {}
        for line in out.splitlines():
            m = re.search(r'([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\s+([0-9a-fA-F\-]{17})', line)
            if m:
                arp_map[m.group(1)] = m.group(2).replace('-', ':').lower()
        return arp_map
    except Exception:
        return {}

def probe_single_host(ip_str: str) -> Dict[str, Any]:
    open_ports = []
    t_start = time.time()
    for port in PROBE_PORTS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.10)
                if s.connect_ex((ip_str, port)) == 0:
                    open_ports.append(port)
        except Exception:
            pass
    latency = (time.time() - t_start) * 1000 if open_ports else 0.0
    return {"ip": ip_str, "is_active": len(open_ports) > 0, "open_ports": open_ports, "latency": round(latency, 2)}

def audit_wmi_host(ip: str, username: str, password: str, is_approved: bool):
    if not password or not username or not is_approved:
        return
    try:
        pythoncom.CoInitialize()
        try:
            connection = wmi.WMI(ip, user=username, password=password)
            failed_logins = connection.query("SELECT TimeGenerated FROM Win32_NTLogEvent WHERE Logfile='Security' AND EventCode='4625'")
            failed_count = len(failed_logins) if failed_logins else 0
            
            if failed_count > 0:
                add_alert(ip, "Brute-force / Failed Logon", "danger", f"{failed_count} failed logon attempts detected!")

            running_suspicious = []
            try:
                procs = connection.Win32_Process(["Name"])
                for p in procs:
                    p_name = (p.Name or "").lower()
                    if p_name in SUSPICIOUS_PROCESSES:
                        running_suspicious.append(p_name)
                
                if running_suspicious:
                    add_alert(ip, "Suspicious Process", "warning", f"Suspicious processes: {', '.join(set(running_suspicious))}")
            except Exception:
                pass

            with state_lock:
                if ip in state["hosts"]:
                    state["hosts"][ip]["failed_logins"] = failed_count
                    state["hosts"][ip]["suspicious_procs"] = list(set(running_suspicious))
                    state["hosts"][ip]["wmi_status"] = "Audited"
        finally:
            pythoncom.CoUninitialize()
    except Exception as e:
        log.debug(f"Dashboard WMI audit failed on {ip}: {e}")
        with state_lock:
            if ip in state["hosts"]:
                state["hosts"][ip]["wmi_status"] = "No WMI / Protected"

def run_network_sweep():
    with state_lock:
        state["is_scanning"] = True

    arp_map = get_arp_cache()
    current_hosts = {}
    subnet_counts = {}

    for subnet, lab_name in SUBNET_LAB_MAP.items():
        try:
            ips = [str(ip) for ip in ipaddress.IPv4Network(subnet, strict=False).hosts()]
            with ThreadPoolExecutor(max_workers=80) as executor:
                results = list(executor.map(probe_single_host, ips))
            
            active_in_subnet = 0
            for r in results:
                ip = r["ip"]
                in_arp = ip in arp_map
                if r["is_active"] or in_arp:
                    active_in_subnet += 1
                    mac = arp_map.get(ip, "Static/LAN")
                    vendor = lookup_mac_vendor(mac)
                    hostname = resolve_hostname(ip)
                    is_rogue = False
                    is_approved = True
                    if ASSET_WHITELIST and mac != "Static/LAN":
                        if mac.lower() not in ASSET_WHITELIST and ip not in ASSET_WHITELIST:
                            is_rogue = True
                            is_approved = False
                            add_alert(ip, "Rogue Device Alert", "danger", f"Unauthorized device {hostname} ({mac})")

                    current_hosts[ip] = {
                        "ip": ip,
                        "hostname": hostname,
                        "mac": mac,
                        "vendor": vendor,
                        "subnet": subnet,
                        "lab_name": lab_name,
                        "ports": r["open_ports"],
                        "latency": r["latency"],
                        "is_rogue": is_rogue,
                        "is_approved": is_approved,
                        "wmi_status": "Pending",
                        "failed_logins": 0,
                        "suspicious_procs": []
                    }
                    
                    if WINDOWS_PASS and is_approved:
                        threading.Thread(target=audit_wmi_host, args=(ip, WINDOWS_USER, WINDOWS_PASS, is_approved), daemon=True).start()

            subnet_counts[lab_name] = active_in_subnet
        except Exception as e:
            log.error(f"Error scanning {subnet}: {e}")

    with state_lock:
        state["hosts"] = current_hosts
        state["subnet_stats"] = subnet_counts
        state["total_hosts_count"] = len(current_hosts)
        state["last_scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        state["is_scanning"] = False

def background_loop():
    while True:
        run_network_sweep()
        time.sleep(config.get("settings", {}).get("scan_interval_seconds", 60))

@app.on_event("startup")
def startup_event():
    threading.Thread(target=background_loop, daemon=True).start()

@app.get("/api/state")
def get_state():
    with state_lock:
        return JSONResponse(state)

@app.post("/api/scan-now")
def trigger_scan():
    threading.Thread(target=run_network_sweep, daemon=True).start()
    return {"status": "Scan initiated"}

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    with state_lock:
        hosts_list = list(state["hosts"].values())
        alerts_list = list(state["alerts"])
        stats = dict(state["subnet_stats"])
        total_count = state["total_hosts_count"]
        last_scan = state["last_scan_time"]

    # Safe HTML construction with html.escape
    rows_html = ""
    for h in hosts_list:
        rogue_badge = "<span style='color:#dc2626;font-weight:700;'>ROGUE</span>" if h.get("is_rogue") else "<span style='color:#16a34a;'>APPROVED</span>"
        ports_str = html.escape(", ".join(map(str, h.get("ports", [])))) if h.get("ports") else "None"
        rows_html += f"""
        <tr>
            <td><code>{html.escape(h.get('ip', '-'))}</code></td>
            <td><strong>{html.escape(h.get('hostname', '-'))}</strong></td>
            <td>{html.escape(h.get('lab_name', '-'))}</td>
            <td><code>{html.escape(h.get('mac', '-'))}</code></td>
            <td>{html.escape(h.get('vendor', '-'))}</td>
            <td>{ports_str}</td>
            <td>{rogue_badge}</td>
        </tr>
        """

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Institute Cyber SOC - Web Console</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #f8fafc; color: #0f172a; margin: 30px; }}
        .header {{ background: #ffffff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 20px; margin-bottom: 20px; display: flex; justify-content: space-between; align-items: center; }}
        .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .card {{ background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; }}
        .card-val {{ font-size: 24px; font-weight: 700; color: #0284c7; margin-top: 4px; }}
        table {{ width: 100%; border-collapse: collapse; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; }}
        th, td {{ padding: 10px 14px; border-bottom: 1px solid #e2e8f0; text-align: left; font-size: 13px; }}
        th {{ background: #f1f5f9; font-weight: 600; color: #334155; }}
        code {{ background: #f1f5f9; padding: 2px 5px; border-radius: 4px; font-size: 12px; }}
    </style>
</head>
<body>
    <div class="header">
        <div>
            <h2>Institute Cyber SOC - Standalone Web Console</h2>
            <div style="font-size: 13px; color: #64748b;">Last Updated: {html.escape(last_scan)} | Total Discovered: {total_count}</div>
        </div>
    </div>
    <div class="cards">
        <div class="card"><div>Active Workstations</div><div class="card-val">{total_count}</div></div>
        <div class="card"><div>Monitored Labs</div><div class="card-val">{len(stats)}</div></div>
        <div class="card"><div>Active Alerts</div><div class="card-val">{len(alerts_list)}</div></div>
    </div>
    <table>
        <thead>
            <tr><th>IP Address</th><th>Computer Name</th><th>Lab Location</th><th>MAC Address</th><th>Hardware Vendor</th><th>Open Ports</th><th>Status</th></tr>
        </thead>
        <tbody>
            {rows_html}
        </tbody>
    </table>
</body>
</html>"""

if __name__ == "__main__":
    bind_ip = config.get("dashboard", {}).get("bind_address", "127.0.0.1")
    port = config.get("dashboard", {}).get("port", 5000)
    uvicorn.run(app, host=bind_ip, port=port)
