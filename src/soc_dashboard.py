import os
import time
import socket
import threading
import logging
import subprocess
import re
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any
from datetime import datetime

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import wmi

# ---------------------------------------------------------
# Configuration
# ---------------------------------------------------------
MONITORING_NODE_IP = "10.13.109.50"
WEB_PORT = 5000
SCAN_INTERVAL_SECONDS = 60

# Institute Lab / Subnet Configuration
SUBNET_LAB_MAP = {
    "10.13.109.0/24": "Lab 1 (Computer Science)",
    "10.13.110.0/24": "Lab 2 (Software Engineering)",
    "10.13.111.0/24": "Lab 3 (Networking & Cyber)"
}
TARGET_SUBNETS = list(SUBNET_LAB_MAP.keys())

# Monitored Port Services
PROBE_PORTS = [135, 445, 80, 443, 3389, 5985, 8080]

# Windows Domain / Local Admin credentials for WMI
WINDOWS_USER = "Administrator"
WINDOWS_PASS = "YourAdminPasswordHere"

# Suspicious executables list
SUSPICIOUS_PROCESSES = [
    "powershell.exe", "cmd.exe", "netcat.exe", "nc.exe", 
    "mimikatz.exe", "psexec.exe", "wireshark.exe", "nmap.exe",
    "tor.exe", "anydesk.exe", "teamviewer.exe"
]

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

# ---------------------------------------------------------
# In-Memory State Store
# ---------------------------------------------------------
state = {
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
                arp_map[m.group(1)] = m.group(2).replace('-', ':')
        return arp_map
    except Exception:
        return {}

def probe_single_host(ip_str: str) -> bool:
    for port in [135, 445, 80, 5985, 3389]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.10)
            res = s.connect_ex((ip_str, port))
            s.close()
            if res == 0:
                return True
        except Exception:
            pass
    return False

def scan_subnet(subnet_range: str) -> List[Dict[str, str]]:
    discovered = []
    arp_map = get_arp_cache()
    try:
        ips = [str(ip) for ip in ipaddress.IPv4Network(subnet_range, strict=False).hosts()]
        with ThreadPoolExecutor(max_workers=80) as executor:
            probe_results = list(executor.map(probe_single_host, ips))
            
        for ip, is_active in zip(ips, probe_results):
            if is_active or ip in arp_map:
                mac = arp_map.get(ip, "Static/LAN")
                discovered.append({'ip': ip, 'mac': mac})
        return discovered
    except Exception as e:
        logging.error(f"Error scanning subnet {subnet_range}: {e}")
        return []

def audit_wmi_host(ip: str, username: str, password: str):
    try:
        connection = wmi.WMI(ip, user=username, password=password, timeout=5)
        
        # 1. Failed Logons (Event 4625)
        failed_logins = connection.Win32_NTLogEvent(Logfile='Security', EventCode='4625')
        failed_count = len(failed_logins) if failed_logins else 0
        
        if failed_count > 0:
            add_alert(ip, "Brute-force / Failed Logon", "danger", f"{failed_count} failed logon attempts detected!")

        # 2. Running Processes
        running_suspicious = []
        try:
            procs = connection.Win32_Process()
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
    except Exception:
        with state_lock:
            if ip in state["hosts"]:
                state["hosts"][ip]["wmi_status"] = "No WMI / Protected"

def run_network_sweep():
    with state_lock:
        state["is_scanning"] = True

    logging.info("Starting complete network scan cycle...")
    all_discovered = []
    subnet_counts = {}

    for subnet in TARGET_SUBNETS:
        hosts = scan_subnet(subnet)
        lab_label = SUBNET_LAB_MAP.get(subnet, subnet)
        subnet_counts[lab_label] = len(hosts)
        for h in hosts:
            h["subnet"] = subnet
            h["lab_name"] = lab_label
        all_discovered.extend(hosts)

    now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    with state_lock:
        state["total_hosts_count"] = len(all_discovered)
        state["subnet_stats"] = subnet_counts
        state["last_scan_time"] = now_str
        state["history"].append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "count": len(all_discovered)
        })
        if len(state["history"]) > 20:
            state["history"] = state["history"][-20:]

        active_ips = set()
        for d in all_discovered:
            ip = d["ip"]
            active_ips.add(ip)
            if ip not in state["hosts"]:
                state["hosts"][ip] = {
                    "ip": ip,
                    "mac": d["mac"],
                    "hostname": resolve_hostname(ip),
                    "subnet": d["subnet"],
                    "lab_name": d["lab_name"],
                    "last_seen": now_str,
                    "status": "Online",
                    "failed_logins": 0,
                    "suspicious_procs": [],
                    "wmi_status": "Pending"
                }
                add_alert(ip, "New Device", "info", f"New host discovered on {d['lab_name']} ({d['subnet']})")
            else:
                state["hosts"][ip]["last_seen"] = now_str
                state["hosts"][ip]["status"] = "Online"

        for ip, data in state["hosts"].items():
            if ip not in active_ips:
                data["status"] = "Offline"

    for h in all_discovered:
        ip = h["ip"]
        if ip != MONITORING_NODE_IP:
            threading.Thread(target=audit_wmi_host, args=(ip, WINDOWS_USER, WINDOWS_PASS), daemon=True).start()

    with state_lock:
        state["is_scanning"] = False
    logging.info(f"Scan finished. Total online: {len(all_discovered)}")

def background_scheduler():
    time.sleep(2)
    while True:
        run_network_sweep()
        time.sleep(SCAN_INTERVAL_SECONDS)

# ---------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------
app = FastAPI(title="Institute Network Security SOC")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/summary")
def get_summary():
    with state_lock:
        online_count = sum(1 for h in state["hosts"].values() if h["status"] == "Online")
        threat_count = sum(1 for h in state["hosts"].values() if h.get("failed_logins", 0) > 0 or len(h.get("suspicious_procs", [])) > 0)
        return {
            "total_discovered": len(state["hosts"]),
            "online_hosts": online_count,
            "offline_hosts": len(state["hosts"]) - online_count,
            "threat_hosts": threat_count,
            "is_scanning": state["is_scanning"],
            "last_scan_time": state["last_scan_time"],
            "subnet_stats": state["subnet_stats"],
            "history": state["history"]
        }

@app.get("/api/hosts")
def get_hosts():
    with state_lock:
        return list(state["hosts"].values())

@app.get("/api/alerts")
def get_alerts():
    with state_lock:
        return state["alerts"]

@app.post("/api/scan-now")
def trigger_scan():
    if not state["is_scanning"]:
        threading.Thread(target=run_network_sweep, daemon=True).start()
        return {"status": "Scan started"}
    return {"status": "Scan already in progress"}

DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SOC Cyber Monitoring Console - Institute Lab</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" rel="stylesheet">
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    colors: {
                        darkbg: '#0B1120',
                        darkcard: '#151F32',
                        darkborder: '#1E293B',
                        accent: '#38BDF8',
                        danger: '#F43F5E',
                        warning: '#F59E0B',
                        success: '#10B981'
                    }
                }
            }
        }
    </script>
    <style>
        body { background-color: #0B1120; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: #0B1120; }
        ::-webkit-scrollbar-thumb { background: #1E293B; border-radius: 4px; }
        .pulse-dot { animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
        @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: .4; } }
    </style>
</head>
<body class="text-slate-200 min-h-screen">

    <header class="border-b border-darkborder bg-darkcard/80 backdrop-blur sticky top-0 z-50 px-6 py-3.5 flex justify-between items-center">
        <div class="flex items-center space-x-3">
            <div class="p-2.5 bg-sky-500/10 text-sky-400 rounded-xl border border-sky-500/20">
                <i class="fa-solid fa-shield-halved text-xl"></i>
            </div>
            <div>
                <h1 class="font-bold text-lg text-white flex items-center gap-2">
                    Institute SOC Security Console
                    <span class="text-xs font-mono bg-sky-500/20 text-sky-400 border border-sky-500/30 px-2 py-0.5 rounded-full">Standalone Engine</span>
                </h1>
                <p class="text-xs text-slate-400">Node: <span class="text-sky-300 font-mono">10.13.109.50</span> • All Institute Labs Active</p>
            </div>
        </div>

        <div class="flex items-center space-x-4">
            <div id="scanStatusBadge" class="flex items-center space-x-2 text-xs bg-slate-800 px-3 py-1.5 rounded-lg border border-slate-700">
                <span class="w-2 h-2 rounded-full bg-emerald-500 pulse-dot"></span>
                <span id="scanStatusText" class="text-slate-300">Live Monitor Active</span>
            </div>
            <button onclick="triggerManualScan()" id="scanBtn" class="flex items-center space-x-2 bg-sky-600 hover:bg-sky-500 text-white text-xs font-semibold px-4 py-2 rounded-lg transition active:scale-95 shadow-lg shadow-sky-600/20">
                <i class="fa-solid fa-rotate" id="scanIcon"></i>
                <span>Scan Subnets Now</span>
            </button>
        </div>
    </header>

    <div class="max-w-7xl mx-auto p-6 space-y-6">

        <div class="grid grid-cols-1 md:grid-cols-4 gap-5">
            <div class="bg-darkcard border border-darkborder p-5 rounded-2xl">
                <div class="flex justify-between items-start">
                    <div>
                        <p class="text-xs uppercase tracking-wider text-slate-400 font-semibold">Active Online PCs</p>
                        <h2 id="totalOnlineCount" class="text-3xl font-extrabold text-white mt-1">--</h2>
                    </div>
                    <div class="p-3 bg-emerald-500/10 text-emerald-400 rounded-xl border border-emerald-500/20">
                        <i class="fa-solid fa-desktop text-xl"></i>
                    </div>
                </div>
                <p class="text-xs text-slate-500 mt-3 flex items-center gap-1">
                    <span id="totalDiscoveredCount" class="text-slate-300 font-medium">--</span> Total Discovered Devices
                </p>
            </div>

            <div class="bg-darkcard border border-darkborder p-5 rounded-2xl">
                <div class="flex justify-between items-start">
                    <div>
                        <p class="text-xs uppercase tracking-wider text-slate-400 font-semibold">Security Threats</p>
                        <h2 id="threatCount" class="text-3xl font-extrabold text-rose-400 mt-1">0</h2>
                    </div>
                    <div class="p-3 bg-rose-500/10 text-rose-400 rounded-xl border border-rose-500/20">
                        <i class="fa-solid fa-triangle-exclamation text-xl"></i>
                    </div>
                </div>
                <p class="text-xs text-slate-500 mt-3">Brute-force or Malicious Procs</p>
            </div>

            <div class="bg-darkcard border border-darkborder p-5 rounded-2xl">
                <div class="flex justify-between items-start">
                    <div>
                        <p class="text-xs uppercase tracking-wider text-slate-400 font-semibold">Monitored Labs</p>
                        <h2 id="subnetsCount" class="text-3xl font-extrabold text-sky-400 mt-1">3</h2>
                    </div>
                    <div class="p-3 bg-sky-500/10 text-sky-400 rounded-xl border border-sky-500/20">
                        <i class="fa-solid fa-network-wired text-xl"></i>
                    </div>
                </div>
                <p class="text-xs text-slate-500 mt-3 font-mono">CS, Software, Cyber</p>
            </div>

            <div class="bg-darkcard border border-darkborder p-5 rounded-2xl">
                <div class="flex justify-between items-start">
                    <div>
                        <p class="text-xs uppercase tracking-wider text-slate-400 font-semibold">Last Auto-Sweep</p>
                        <h2 id="lastScanTime" class="text-lg font-bold text-slate-200 mt-2 font-mono">--</h2>
                    </div>
                    <div class="p-3 bg-purple-500/10 text-purple-400 rounded-xl border border-purple-500/20">
                        <i class="fa-solid fa-clock-rotate-left text-xl"></i>
                    </div>
                </div>
                <p class="text-xs text-slate-500 mt-3">Periodic interval: 60s</p>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div class="bg-darkcard border border-darkborder p-5 rounded-2xl">
                <h3 class="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                    <i class="fa-solid fa-chart-pie text-sky-400"></i> Devices per Lab
                </h3>
                <div class="h-56 relative flex items-center justify-center">
                    <canvas id="subnetChart"></canvas>
                </div>
            </div>

            <div class="bg-darkcard border border-darkborder p-5 rounded-2xl lg:col-span-2">
                <h3 class="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                    <i class="fa-solid fa-chart-line text-emerald-400"></i> Active Network Presence Trend
                </h3>
                <div class="h-56 relative">
                    <canvas id="trendChart"></canvas>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div class="bg-darkcard border border-darkborder p-5 rounded-2xl flex flex-col h-[550px]">
                <div class="flex justify-between items-center mb-4">
                    <h3 class="text-sm font-semibold text-white flex items-center gap-2">
                        <i class="fa-solid fa-bell text-amber-400"></i> Security Alerts Feed
                    </h3>
                    <span id="alertCountBadge" class="text-xs font-mono bg-slate-800 px-2 py-0.5 rounded text-slate-400">0 events</span>
                </div>
                <div id="alertsContainer" class="flex-1 overflow-y-auto space-y-2.5 pr-1">
                    <div class="text-center text-slate-500 text-xs py-10">No critical security events recorded yet.</div>
                </div>
            </div>

            <div class="bg-darkcard border border-darkborder p-5 rounded-2xl lg:col-span-2 flex flex-col h-[550px]">
                <div class="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 mb-4">
                    <h3 class="text-sm font-semibold text-white flex items-center gap-2">
                        <i class="fa-solid fa-server text-sky-400"></i> Master Host Inventory Table
                    </h3>
                    <div class="flex items-center gap-2 w-full sm:w-auto">
                        <input type="text" id="searchInput" placeholder="Search IP / Hostname..." 
                            class="w-full sm:w-48 bg-slate-900 border border-darkborder text-xs rounded-lg px-3 py-1.5 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-sky-500">
                    </div>
                </div>

                <div class="flex-1 overflow-y-auto overflow-x-auto pr-1">
                    <table class="w-full text-left text-xs text-slate-300">
                        <thead class="text-slate-400 uppercase bg-slate-900/60 sticky top-0 border-b border-darkborder">
                            <tr>
                                <th class="py-2.5 px-3">IP Address</th>
                                <th class="py-2.5 px-3">Hostname</th>
                                <th class="py-2.5 px-3">Hardware MAC</th>
                                <th class="py-2.5 px-3">Lab / Zone</th>
                                <th class="py-2.5 px-3">WMI Audit</th>
                                <th class="py-2.5 px-3">Status</th>
                            </tr>
                        </thead>
                        <tbody id="hostsTableBody" class="divide-y divide-darkborder font-mono">
                            <tr>
                                <td colspan="6" class="text-center py-10 text-slate-500">Scanning network for hosts...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

    </div>

    <script>
        let subnetChartInstance = null;
        let trendChartInstance = null;
        let allHostsData = [];

        async function fetchSummary() {
            try {
                const res = await fetch('/api/summary');
                const data = await res.json();
                
                document.getElementById('totalOnlineCount').innerText = data.online_hosts;
                document.getElementById('totalDiscoveredCount').innerText = data.total_discovered;
                document.getElementById('threatCount').innerText = data.threat_hosts;
                document.getElementById('lastScanTime').innerText = data.last_scan_time.split(' ')[1] || data.last_scan_time;
                
                if (data.is_scanning) {
                    document.getElementById('scanStatusText').innerText = "Sweeping Subnets...";
                    document.getElementById('scanIcon').classList.add('fa-spin');
                } else {
                    document.getElementById('scanStatusText').innerText = "Live Monitor Active";
                    document.getElementById('scanIcon').classList.remove('fa-spin');
                }

                updateSubnetChart(data.subnet_stats);
                updateTrendChart(data.history);
            } catch(e) {
                console.error("Error loading summary:", e);
            }
        }

        async function fetchHosts() {
            try {
                const res = await fetch('/api/hosts');
                allHostsData = await res.json();
                renderHostsTable();
            } catch(e) {
                console.error("Error loading hosts:", e);
            }
        }

        async function fetchAlerts() {
            try {
                const res = await fetch('/api/alerts');
                const alerts = await res.json();
                document.getElementById('alertCountBadge').innerText = `${alerts.length} events`;
                const container = document.getElementById('alertsContainer');
                
                if (alerts.length === 0) {
                    container.innerHTML = `<div class="text-center text-slate-500 text-xs py-10">No critical security events recorded.</div>`;
                    return;
                }

                container.innerHTML = alerts.map(a => {
                    let borderClass = 'border-sky-500/30 bg-sky-500/5 text-sky-300';
                    let icon = 'fa-circle-info';
                    if (a.severity === 'danger') {
                        borderClass = 'border-rose-500/30 bg-rose-500/10 text-rose-300';
                        icon = 'fa-skull-crossbones';
                    } else if (a.severity === 'warning') {
                        borderClass = 'border-amber-500/30 bg-amber-500/10 text-amber-300';
                        icon = 'fa-triangle-exclamation';
                    }

                    return `
                        <div class="p-3 rounded-xl border ${borderClass} text-xs">
                            <div class="flex justify-between items-start">
                                <span class="font-bold flex items-center gap-1.5"><i class="fa-solid ${icon}"></i> ${a.type}</span>
                                <span class="text-[10px] text-slate-400 font-mono">${a.time}</span>
                            </div>
                            <p class="text-slate-300 mt-1">${a.message}</p>
                            <span class="inline-block mt-1 font-mono text-[10px] bg-slate-900/80 px-1.5 py-0.5 rounded text-slate-400">${a.ip}</span>
                        </div>
                    `;
                }).join('');
            } catch(e) {
                console.error("Error loading alerts:", e);
            }
        }

        function renderHostsTable() {
            const tbody = document.getElementById('hostsTableBody');
            const search = document.getElementById('searchInput').value.toLowerCase();

            const filtered = allHostsData.filter(h => {
                return h.ip.toLowerCase().includes(search) || (h.hostname && h.hostname.toLowerCase().includes(search));
            });

            if (filtered.length === 0) {
                tbody.innerHTML = `<tr><td colspan="6" class="text-center py-6 text-slate-500 font-sans">No hosts match search criteria.</td></tr>`;
                return;
            }

            tbody.innerHTML = filtered.map(h => {
                const statusBadge = h.status === 'Online' 
                    ? `<span class="px-2 py-0.5 rounded-full text-[10px] bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">Online</span>`
                    : `<span class="px-2 py-0.5 rounded-full text-[10px] bg-slate-800 text-slate-400 border border-slate-700">Offline</span>`;

                return `
                    <tr class="hover:bg-slate-800/40 transition">
                        <td class="py-2.5 px-3 font-semibold text-white">${h.ip}</td>
                        <td class="py-2.5 px-3 text-slate-300 font-sans">${h.hostname || '--'}</td>
                        <td class="py-2.5 px-3 text-slate-400">${h.mac}</td>
                        <td class="py-2.5 px-3 text-sky-400 font-sans">${h.lab_name || h.subnet}</td>
                        <td class="py-2.5 px-3 text-slate-400 font-sans">${h.wmi_status || 'Audited'}</td>
                        <td class="py-2.5 px-3">${statusBadge}</td>
                    </tr>
                `;
            }).join('');
        }

        function updateSubnetChart(stats) {
            const labels = Object.keys(stats || {});
            const counts = Object.values(stats || {});

            if (!subnetChartInstance) {
                const ctx = document.getElementById('subnetChart').getContext('2d');
                subnetChartInstance = new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: labels,
                        datasets: [{
                            data: counts,
                            backgroundColor: ['#38BDF8', '#818CF8', '#34D399', '#F472B6'],
                            borderColor: '#151F32',
                            borderWidth: 3
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: { position: 'bottom', labels: { color: '#94A3B8', font: { size: 10 } } }
                        }
                    }
                });
            } else {
                subnetChartInstance.data.labels = labels;
                subnetChartInstance.data.datasets[0].data = counts;
                subnetChartInstance.update();
            }
        }

        function updateTrendChart(history) {
            const labels = (history || []).map(h => h.time);
            const counts = (history || []).map(h => h.count);

            if (!trendChartInstance) {
                const ctx = document.getElementById('trendChart').getContext('2d');
                trendChartInstance = new Chart(ctx, {
                    type: 'line',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: 'Active PCs',
                            data: counts,
                            borderColor: '#10B981',
                            backgroundColor: 'rgba(16, 185, 129, 0.1)',
                            fill: true,
                            tension: 0.35,
                            borderWidth: 2,
                            pointRadius: 3
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: { legend: { display: false } },
                        scales: {
                            x: { ticks: { color: '#64748B', font: { size: 10 } }, grid: { color: '#1E293B' } },
                            y: { ticks: { color: '#64748B', font: { size: 10 } }, grid: { color: '#1E293B' }, beginAtZero: true }
                        }
                    }
                });
            } else {
                trendChartInstance.data.labels = labels;
                trendChartInstance.data.datasets[0].data = counts;
                trendChartInstance.update();
            }
        }

        async function triggerManualScan() {
            const btn = document.getElementById('scanBtn');
            btn.disabled = true;
            try {
                await fetch('/api/scan-now', { method: 'POST' });
                fetchSummary();
            } catch(e) {
                console.error(e);
            }
            setTimeout(() => { btn.disabled = false; }, 3000);
        }

        document.getElementById('searchInput').addEventListener('input', renderHostsTable);

        fetchSummary();
        fetchHosts();
        fetchAlerts();

        setInterval(() => {
            fetchSummary();
            fetchHosts();
            fetchAlerts();
        }, 5000);
    </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def serve_dashboard():
    return HTMLResponse(content=DASHBOARD_HTML)

if __name__ == "__main__":
    scan_thread = threading.Thread(target=background_scheduler, daemon=True)
    scan_thread.start()

    logging.info(f"==================================================")
    logging.info(f" Standalone SOC Web Console started successfully!")
    logging.info(f" Open Dashboard at: http://{MONITORING_NODE_IP}:{WEB_PORT}")
    logging.info(f" Or on localhost at: http://localhost:{WEB_PORT}")
    logging.info(f"==================================================")

    uvicorn.run(app, host="0.0.0.0", port=WEB_PORT, log_level="warning")
