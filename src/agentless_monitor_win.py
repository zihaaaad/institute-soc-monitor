import os
import time
import json
import threading
import logging
import subprocess
import re
import socket
import ipaddress
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any, Set
from prometheus_client import start_http_server, Gauge, Counter
import wmi

from oui_database import lookup_mac_vendor
from threat_intel import MITRE_TECHNIQUES, calculate_endpoint_risk_score, LatencyAnomalyDetector

# ---------------------------------------------------------
# Dynamic Configuration Loader
# ---------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())

LOCAL_IP = get_local_ip()

def load_config() -> Dict[str, Any]:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logging.error(f"Error reading config.json: {e}")
    
    # Auto-detected fallback config
    octets = LOCAL_IP.split(".")
    default_subnet = f"{octets[0]}.{octets[1]}.{octets[2]}.0/24"
    return {
        "subnets": {default_subnet: "Local Network Lab"},
        "credentials": {"windows_user": "Administrator", "windows_password": ""},
        "settings": {"scan_interval_seconds": 60, "metrics_port": 8000},
        "asset_whitelist": [],
        "alerts": {"enabled": False, "discord_webhook_url": "", "telegram_bot_token": "", "telegram_chat_id": "", "alert_cooldown_seconds": 300},
        "vulnerability_audit": {"enabled": True, "check_smbv1": True, "check_rdp_exposure": True, "check_cleartext_http": True, "check_rpc_mapper": True},
        "suspicious_processes": ["powershell.exe", "cmd.exe", "netcat.exe", "mimikatz.exe", "psexec.exe", "nmap.exe"]
    }

config = load_config()
SUBNET_LAB_MAPPING = config.get("subnets", {})
WINDOWS_USER = config.get("credentials", {}).get("windows_user", "Administrator")
WINDOWS_PASS = config.get("credentials", {}).get("windows_password", "")
SCAN_INTERVAL_SECONDS = config.get("settings", {}).get("scan_interval_seconds", 60)
PROMETHEUS_PORT = config.get("settings", {}).get("metrics_port", 8000)
FALLBACK_PORT = 8001

ASSET_WHITELIST = set(m.lower().replace("-", ":") for m in config.get("asset_whitelist", []))
ALERTS_CONFIG = config.get("alerts", {})
VULN_CONFIG = config.get("vulnerability_audit", {})
SUSPICIOUS_LIST = [p.lower() for p in config.get("suspicious_processes", [])]

# Anomaly Detector per subnet
ANOMALY_DETECTORS: Dict[str, LatencyAnomalyDetector] = {}
ALERT_COOLDOWN_MAP: Dict[str, float] = {}

# Monitored Port Services (Attack Surface)
PORT_SERVICE_MAP = {
    135: "RPC/WMI",
    445: "SMB/Shares",
    80: "HTTP",
    443: "HTTPS",
    3389: "RDP/Remote",
    5985: "WinRM",
    8080: "Web Proxy"
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

# ---------------------------------------------------------
# Prometheus Metrics Setup
# ---------------------------------------------------------
TOTAL_ENDPOINTS_GAUGE = Gauge("total_active_endpoints", "Total active computers discovered across all labs")
TOTAL_THREATS_GAUGE = Gauge("total_threat_endpoints", "Total endpoints flagged with security alerts")
TOTAL_ROGUE_DEVICES_GAUGE = Gauge("total_rogue_devices", "Total unauthorized or rogue devices detected")
TOTAL_VULNERABILITIES_GAUGE = Gauge("total_vulnerabilities_detected", "Total active vulnerability and exposure risks")
NETWORK_HEALTH_INDEX = Gauge("network_health_index", "Calculated overall network health percentage (0-100)")
ACTIVE_HOSTS_GAUGE = Gauge("active_network_hosts", "Active hosts count per lab subnet", ["subnet", "lab_name"])
LAB_THREAT_GAUGE = Gauge("lab_threat_count", "Threat count per lab subnet", ["subnet", "lab_name"])

ENDPOINT_STATUS_GAUGE = Gauge(
    "endpoint_status",
    "Endpoint online status and hardware inventory",
    ["target_ip", "hostname", "subnet", "lab_name", "mac", "vendor", "open_services"]
)
ENDPOINT_LATENCY_GAUGE = Gauge("endpoint_latency_ms", "Endpoint round-trip network response time", ["target_ip", "subnet", "lab_name"])
ENDPOINT_PORT_EXPOSURE = Gauge("endpoint_port_exposure", "Count of exposed management & service ports", ["target_ip", "subnet", "service"])

# Open-Source MITRE ATT&CK & CVSS Risk Metrics
ENDPOINT_RISK_SCORE = Gauge("endpoint_risk_score", "Calculated CVSS v3.1 quantitative risk score (0-100)", ["target_ip", "hostname", "subnet", "lab_name"])
MITRE_ATTACK_GAUGE = Gauge("mitre_attack_technique", "MITRE ATT&CK mapped security technique active", ["target_ip", "technique_id", "technique_name", "tactic", "severity"])
LATENCY_ANOMALY_GAUGE = Gauge("network_latency_anomaly", "Statistical Z-Score anomaly flag (>3 sigma)", ["target_ip", "subnet"])

# Security Incident & Threat Gauges
ROGUE_DEVICE_GAUGE = Gauge("rogue_device_detected", "Rogue or unauthorized device flag", ["target_ip", "mac", "hostname", "lab_name"])
VULNERABILITY_GAUGE = Gauge("vulnerability_exposure", "Vulnerability & exposure audit flags", ["target_ip", "cve_id", "severity", "description"])
BRUTE_FORCE_COUNTER = Counter("brute_force_attempts_total", "Failed logons detected (Event ID 4625)", ["target_ip", "lab_name"])
SUSPICIOUS_PROC_GAUGE = Gauge("suspicious_process_detected", "Suspicious process execution flag", ["target_ip", "process_name", "lab_name"])
SCAN_DURATION_GAUGE = Gauge("network_scan_duration_seconds", "Duration of network sweep in seconds")

# ---------------------------------------------------------
# Multi-Channel Webhook Alerting
# ---------------------------------------------------------
def dispatch_alert(title: str, message: str, severity: str, target_ip: str, alert_type: str):
    if not ALERTS_CONFIG.get("enabled", False):
        return

    cooldown_seconds = ALERTS_CONFIG.get("alert_cooldown_seconds", 300)
    key = f"{target_ip}:{alert_type}"
    now = time.time()
    if key in ALERT_COOLDOWN_MAP and (now - ALERT_COOLDOWN_MAP[key]) < cooldown_seconds:
        return
    ALERT_COOLDOWN_MAP[key] = now

    def _send():
        # 1. Discord Webhook
        discord_url = ALERTS_CONFIG.get("discord_webhook_url", "").strip()
        if discord_url:
            try:
                payload = {
                    "username": "Institute Cyber SOC Monitor",
                    "embeds": [{
                        "title": f"[{severity.upper()}] {title}",
                        "description": message,
                        "color": 15158332 if severity.upper() in ["CRITICAL", "HIGH"] else 15844367,
                        "fields": [
                            {"name": "Target IP", "value": target_ip, "inline": True},
                            {"name": "Timestamp", "value": time.strftime("%Y-%m-%d %H:%M:%S"), "inline": True}
                        ]
                    }]
                }
                req = urllib.request.Request(discord_url, method="POST", data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5)
            except Exception as e:
                logging.error(f"Failed to send Discord alert: {e}")

        # 2. Telegram Bot API
        tg_token = ALERTS_CONFIG.get("telegram_bot_token", "").strip()
        tg_chat = ALERTS_CONFIG.get("telegram_chat_id", "").strip()
        if tg_token and tg_chat:
            try:
                tg_text = f"[{severity.upper()}] {title}\n{message}\nTarget IP: {target_ip}\nTime: {time.strftime('%Y-%m-%d %H:%M:%S')}"
                tg_url = f"https://api.telegram.org/bot{tg_token}/sendMessage"
                tg_payload = {"chat_id": tg_chat, "text": tg_text}
                req = urllib.request.Request(tg_url, method="POST", data=json.dumps(tg_payload).encode("utf-8"), headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=5)
            except Exception as e:
                logging.error(f"Failed to send Telegram alert: {e}")

    threading.Thread(target=_send, daemon=True).start()

# ---------------------------------------------------------
# Network Probing Utilities
# ---------------------------------------------------------
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

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return f"PC-{ip.split('.')[-1]}"

def check_smbv1(ip_str: str) -> bool:
    """Defensive check to see if target host supports legacy SMBv1 dialect negotiation."""
    try:
        smbv1_packet = (
            b'\x00\x00\x00\x85'
            b'\xff\x53\x4d\x42'
            b'\x72'
            b'\x00\x00\x00\x00'
            b'\x18'
            b'\x53\xc8'
            b'\x00\x00'
            b'\x00\x00\x00\x00\x00\x00\x00\x00'
            b'\x00\x00'
            b'\x00\x00'
            b'\x00\x00'
            b'\x00\x00'
            b'\x00\x00'
            b'\x00'
            b'\x62\x00'
            b'\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
        )
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.25)
        s.connect((ip_str, 445))
        s.sendall(smbv1_packet)
        response = s.recv(1024)
        s.close()
        if len(response) >= 8 and response[4:8] == b'\xffSMB' and response[8] == 0x72:
            return True
    except Exception:
        pass
    return False

def audit_vulnerabilities(ip_str: str, open_services: List[str], lab_name: str) -> List[Dict[str, str]]:
    if not VULN_CONFIG.get("enabled", True):
        return []

    findings = []
    
    # 1. SMBv1 Legacy Protocol & EternalBlue Attack Surface
    if "SMB/Shares" in open_services and VULN_CONFIG.get("check_smbv1", True):
        has_smbv1 = check_smbv1(ip_str)
        if has_smbv1:
            findings.append({"cve_id": "MS17-010-RISK", "severity": "HIGH", "description": "Legacy SMBv1 Protocol Active on Port 445"})
            VULNERABILITY_GAUGE.labels(target_ip=ip_str, cve_id="MS17-010-RISK", severity="HIGH", description="Legacy SMBv1 Protocol Active").set(1)
            
            # Map MITRE Technique
            t_info = MITRE_TECHNIQUES["MS17-010-RISK"]
            MITRE_ATTACK_GAUGE.labels(target_ip=ip_str, technique_id=t_info["technique_id"], technique_name=t_info["technique_name"], tactic=t_info["tactic"], severity=t_info["severity"]).set(1)
            dispatch_alert("Legacy SMBv1 Protocol Detected", f"Host {ip_str} in {lab_name} has SMBv1 enabled. Vulnerable to lateral movement.", "HIGH", ip_str, "smbv1")

    # 2. Exposed RDP Management Port
    if "RDP/Remote" in open_services and VULN_CONFIG.get("check_rdp_exposure", True):
        findings.append({"cve_id": "RDP-EXPOSURE", "severity": "MEDIUM", "description": "Exposed Remote Desktop Port 3389"})
        VULNERABILITY_GAUGE.labels(target_ip=ip_str, cve_id="RDP-EXPOSURE", severity="MEDIUM", description="Exposed Remote Desktop Port 3389").set(1)
        t_info = MITRE_TECHNIQUES["RDP-EXPOSURE"]
        MITRE_ATTACK_GAUGE.labels(target_ip=ip_str, technique_id=t_info["technique_id"], technique_name=t_info["technique_name"], tactic=t_info["tactic"], severity=t_info["severity"]).set(1)

    # 3. Unencrypted Cleartext HTTP Service
    if "HTTP" in open_services and VULN_CONFIG.get("check_cleartext_http", True):
        findings.append({"cve_id": "CLEARTEXT-HTTP", "severity": "LOW", "description": "Unencrypted HTTP Port 80 Active"})
        VULNERABILITY_GAUGE.labels(target_ip=ip_str, cve_id="CLEARTEXT-HTTP", severity="LOW", description="Unencrypted HTTP Port 80").set(1)

    # 4. RPC / DCOM Port Exposure
    if "RPC/WMI" in open_services and VULN_CONFIG.get("check_rpc_mapper", True):
        findings.append({"cve_id": "RPC-DCOM-EXPOSURE", "severity": "LOW", "description": "Windows RPC Endpoint Mapper Port 135 Exposed"})
        VULNERABILITY_GAUGE.labels(target_ip=ip_str, cve_id="RPC-DCOM-EXPOSURE", severity="LOW", description="RPC Endpoint Mapper Port 135").set(1)

    return findings

def probe_host(ip_str: str) -> Dict[str, Any]:
    open_services = []
    t_start = time.time()
    is_up = False
    
    for port, service_name in PORT_SERVICE_MAP.items():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.10)
            res = s.connect_ex((ip_str, port))
            s.close()
            if res == 0:
                is_up = True
                open_services.append(service_name)
        except Exception:
            pass

    t_latency = (time.time() - t_start) * 1000  # ms
    return {
        "ip": ip_str,
        "is_up": is_up,
        "latency_ms": round(t_latency, 2),
        "open_services": open_services
    }

# ---------------------------------------------------------
# Agentless WMI Security Audit
# ---------------------------------------------------------
def audit_windows_pc(ip_address: str, lab_name: str, username: str, password: str):
    if not password:
        return
    try:
        connection = wmi.WMI(ip_address, user=username, password=password, timeout=5)
        
        # A. Check Failed Logons (Event 4625 - Brute force indicator)
        failed_logins = connection.Win32_NTLogEvent(Logfile='Security', EventCode='4625')
        if failed_logins:
            count = len(failed_logins)
            logging.warning(f"[SECURITY ALERT] {count} failed logon attempts on {ip_address} ({lab_name})")
            BRUTE_FORCE_COUNTER.labels(target_ip=ip_address, lab_name=lab_name).inc(count)
            t_info = MITRE_TECHNIQUES["bruteforce"]
            MITRE_ATTACK_GAUGE.labels(target_ip=ip_address, technique_id=t_info["technique_id"], technique_name=t_info["technique_name"], tactic=t_info["tactic"], severity=t_info["severity"]).set(1)
            if count >= 3:
                dispatch_alert("Brute-Force Logon Spikes Detected", f"{count} failed authentication events (Event 4625) recorded on {ip_address} in {lab_name}.", "CRITICAL", ip_address, "bruteforce")

        # B. Check Running Processes against Blacklist
        processes = connection.Win32_Process()
        running_names = set()
        for proc in processes:
            p_name = (proc.Name or "").lower()
            running_names.add(p_name)
            if p_name in SUSPICIOUS_LIST:
                logging.warning(f"[SECURITY ALERT] Suspicious process '{p_name}' running on {ip_address} ({lab_name})")
                SUSPICIOUS_PROC_GAUGE.labels(target_ip=ip_address, process_name=p_name, lab_name=lab_name).set(1)
                
                # Map to MITRE
                if p_name in MITRE_TECHNIQUES:
                    t_info = MITRE_TECHNIQUES[p_name]
                    MITRE_ATTACK_GAUGE.labels(target_ip=ip_address, technique_id=t_info["technique_id"], technique_name=t_info["technique_name"], tactic=t_info["tactic"], severity=t_info["severity"]).set(1)

                dispatch_alert("Blacklisted Process Execution", f"Suspicious binary '{p_name}' detected active on {ip_address} ({lab_name}).", "HIGH", ip_address, f"proc_{p_name}")

        for s_proc in SUSPICIOUS_LIST:
            if s_proc not in running_names:
                SUSPICIOUS_PROC_GAUGE.labels(target_ip=ip_address, process_name=s_proc, lab_name=lab_name).set(0)

    except Exception:
        pass

# ---------------------------------------------------------
# Subnet Scanner Engine
# ---------------------------------------------------------
def sweep_subnet(subnet_range: str, lab_name: str, arp_cache: Dict[str, str]) -> List[Dict[str, Any]]:
    logging.info(f"Sweeping {lab_name} [{subnet_range}]...")
    discovered = []
    
    if subnet_range not in ANOMALY_DETECTORS:
        ANOMALY_DETECTORS[subnet_range] = LatencyAnomalyDetector(z_threshold=3.0)
    detector = ANOMALY_DETECTORS[subnet_range]

    try:
        ips = [str(ip) for ip in ipaddress.IPv4Network(subnet_range, strict=False).hosts()]
        with ThreadPoolExecutor(max_workers=80) as executor:
            probe_results = list(executor.map(probe_host, ips))
            
        for r in probe_results:
            ip = r["ip"]
            in_arp = ip in arp_cache
            if r["is_up"] or in_arp:
                mac = arp_cache.get(ip, "Static/LAN")
                vendor = lookup_mac_vendor(mac)
                hostname = resolve_hostname(ip)
                services_str = ", ".join(r["open_services"]) if r["open_services"] else "ICMP/ARP Only"
                
                # Check Statistical Z-Score Latency Anomaly
                is_anomaly, z_val = detector.update(r["latency_ms"])
                LATENCY_ANOMALY_GAUGE.labels(target_ip=ip, subnet=subnet_range).set(1 if is_anomaly else 0)

                # Check Rogue / Unauthorized Device Whitelist
                is_rogue = False
                if ASSET_WHITELIST and mac != "Static/LAN":
                    if mac.lower() not in ASSET_WHITELIST and ip not in ASSET_WHITELIST:
                        is_rogue = True
                        ROGUE_DEVICE_GAUGE.labels(target_ip=ip, mac=mac, hostname=hostname, lab_name=lab_name).set(1)
                        dispatch_alert("Unauthorized Rogue Device Detected", f"Rogue machine {hostname} ({ip} / {mac}) connected to {lab_name}.", "HIGH", ip, "rogue")
                    else:
                        ROGUE_DEVICE_GAUGE.labels(target_ip=ip, mac=mac, hostname=hostname, lab_name=lab_name).set(0)

                # Defensive Vulnerability & Exposure Audit
                vulns = audit_vulnerabilities(ip, r["open_services"], lab_name)
                vuln_ids = [v["cve_id"] for v in vulns]

                # Compute CVSS 3.1 Quantitative Risk Score
                risk_score = calculate_endpoint_risk_score(vuln_ids, [], 0, is_rogue)
                ENDPOINT_RISK_SCORE.labels(target_ip=ip, hostname=hostname, subnet=subnet_range, lab_name=lab_name).set(risk_score)

                ENDPOINT_STATUS_GAUGE.labels(
                    target_ip=ip,
                    hostname=hostname,
                    subnet=subnet_range,
                    lab_name=lab_name,
                    mac=mac,
                    vendor=vendor,
                    open_services=services_str
                ).set(1)
                
                ENDPOINT_LATENCY_GAUGE.labels(target_ip=ip, subnet=subnet_range, lab_name=lab_name).set(r["latency_ms"])
                
                for srv in r["open_services"]:
                    ENDPOINT_PORT_EXPOSURE.labels(target_ip=ip, subnet=subnet_range, service=srv).set(1)
                
                discovered.append({
                    "ip": ip,
                    "subnet": subnet_range,
                    "lab_name": lab_name,
                    "mac": mac,
                    "vendor": vendor,
                    "hostname": hostname,
                    "latency": r["latency_ms"],
                    "services": services_str,
                    "is_rogue": is_rogue,
                    "risk_score": risk_score,
                    "vulnerabilities": vulns
                })
                
        ACTIVE_HOSTS_GAUGE.labels(subnet=subnet_range, lab_name=lab_name).set(len(discovered))
        return discovered
    except Exception as e:
        logging.error(f"Error scanning subnet {subnet_range}: {e}")
        return []

# ---------------------------------------------------------
# Main Monitoring Loop
# ---------------------------------------------------------
def start_monitoring():
    logging.info(f"Starting Universal Agentless Security Engine on Host IP: {LOCAL_IP}...")
    
    used_port = PROMETHEUS_PORT
    try:
        start_http_server(used_port, addr="0.0.0.0")
        logging.info(f"Prometheus Metrics Exporter running at http://0.0.0.0:{used_port}/metrics")
    except Exception:
        used_port = FALLBACK_PORT
        start_http_server(used_port, addr="0.0.0.0")
        logging.info(f"Prometheus Metrics Exporter running at http://0.0.0.0:{used_port}/metrics")

    while True:
        t_sweep_start = time.time()
        arp_cache = get_arp_cache()
        all_hosts = []
        total_rogue = 0
        total_vulns = 0
        
        for subnet, lab_name in SUBNET_LAB_MAPPING.items():
            hosts = sweep_subnet(subnet, lab_name, arp_cache)
            all_hosts.extend(hosts)
            
        for h in all_hosts:
            if h.get("is_rogue"):
                total_rogue += 1
            total_vulns += len(h.get("vulnerabilities", []))

        TOTAL_ENDPOINTS_GAUGE.set(len(all_hosts))
        TOTAL_ROGUE_DEVICES_GAUGE.set(total_rogue)
        TOTAL_VULNERABILITIES_GAUGE.set(total_vulns)
        sweep_duration = round(time.time() - t_sweep_start, 2)
        SCAN_DURATION_GAUGE.set(sweep_duration)
        
        health_penalty = min(total_rogue * 15 + total_vulns * 5, 100)
        NETWORK_HEALTH_INDEX.set(max(100 - health_penalty, 0) if len(all_hosts) > 0 else 0)
        
        logging.info(f"Cycle completed in {sweep_duration}s. Active: {len(all_hosts)} | Rogues: {total_rogue} | Vulns: {total_vulns}")

        for host in all_hosts:
            host_ip = host["ip"]
            lab_name = host["lab_name"]
            if host_ip != LOCAL_IP and WINDOWS_PASS:
                threading.Thread(target=audit_windows_pc, args=(host_ip, lab_name, WINDOWS_USER, WINDOWS_PASS), daemon=True).start()

        time.sleep(SCAN_INTERVAL_SECONDS)

if __name__ == "__main__":
    start_monitoring()
