import os
import time
import json
import threading
import logging
import subprocess
import re
import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any
from prometheus_client import start_http_server, Gauge, Counter
import wmi

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
        "suspicious_processes": ["powershell.exe", "cmd.exe", "netcat.exe", "mimikatz.exe", "psexec.exe", "nmap.exe"]
    }

config = load_config()
SUBNET_LAB_MAPPING = config.get("subnets", {})
WINDOWS_USER = config.get("credentials", {}).get("windows_user", "Administrator")
WINDOWS_PASS = config.get("credentials", {}).get("windows_password", "")
SCAN_INTERVAL_SECONDS = config.get("settings", {}).get("scan_interval_seconds", 60)
PROMETHEUS_PORT = config.get("settings", {}).get("metrics_port", 8000)
FALLBACK_PORT = 8001
SUSPICIOUS_LIST = [p.lower() for p in config.get("suspicious_processes", [])]

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

# MAC OUI prefixes for hardware vendor recognition
VENDOR_PREFIXES = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:15:5d": "Microsoft Hyper-V",
    "34:5a:60": "Realtek / Intel LAN",
    "10:7c:61": "Intel NIC",
    "b0:19:21": "Realtek PCIe",
    "08:bf:b8": "ASRock / ASUS",
    "d4:01:c3": "Cisco / Router",
    "00:80:91": "D-Link / Switch",
    "e4:54:e8": "Dell",
    "70:85:c2": "HP"
}

logging.basicConfig(level=logging.INFO, format="%(asctime)s - [%(levelname)s] - %(message)s")

# ---------------------------------------------------------
# Prometheus Metrics Setup
# ---------------------------------------------------------
TOTAL_ENDPOINTS_GAUGE = Gauge("total_active_endpoints", "Total active computers discovered across all labs")
TOTAL_THREATS_GAUGE = Gauge("total_threat_endpoints", "Total endpoints flagged with security alerts")
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

BRUTE_FORCE_COUNTER = Counter("brute_force_attempts_total", "Failed logons detected (Event ID 4625)", ["target_ip", "lab_name"])
SUSPICIOUS_PROC_GAUGE = Gauge("suspicious_process_detected", "Suspicious process execution flag", ["target_ip", "process_name", "lab_name"])
SCAN_DURATION_GAUGE = Gauge("network_scan_duration_seconds", "Duration of network sweep in seconds")

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

def resolve_vendor(mac: str) -> str:
    if not mac or mac == "dynamic/lan" or mac == "static/lan":
        return "Generic LAN"
    mac_prefix = mac[:8].lower()
    for prefix, vendor in VENDOR_PREFIXES.items():
        if mac_prefix.startswith(prefix.lower()):
            return vendor
    return "Standard PC / NIC"

def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return f"PC-{ip.split('.')[-1]}"

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

        # B. Check Running Processes against Blacklist
        processes = connection.Win32_Process()
        running_names = set()
        for proc in processes:
            p_name = (proc.Name or "").lower()
            running_names.add(p_name)
            if p_name in SUSPICIOUS_LIST:
                logging.warning(f"[SECURITY ALERT] Suspicious process '{p_name}' running on {ip_address} ({lab_name})")
                SUSPICIOUS_PROC_GAUGE.labels(target_ip=ip_address, process_name=p_name, lab_name=lab_name).set(1)

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
    try:
        ips = [str(ip) for ip in ipaddress.IPv4Network(subnet_range, strict=False).hosts()]
        with ThreadPoolExecutor(max_workers=80) as executor:
            probe_results = list(executor.map(probe_host, ips))
            
        for r in probe_results:
            ip = r["ip"]
            in_arp = ip in arp_cache
            if r["is_up"] or in_arp:
                mac = arp_cache.get(ip, "Static/LAN")
                vendor = resolve_vendor(mac)
                hostname = resolve_hostname(ip)
                services_str = ", ".join(r["open_services"]) if r["open_services"] else "ICMP/ARP Only"
                
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
                    "services": services_str
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
        
        for subnet, lab_name in SUBNET_LAB_MAPPING.items():
            hosts = sweep_subnet(subnet, lab_name, arp_cache)
            all_hosts.extend(hosts)
            
        TOTAL_ENDPOINTS_GAUGE.set(len(all_hosts))
        sweep_duration = round(time.time() - t_sweep_start, 2)
        SCAN_DURATION_GAUGE.set(sweep_duration)
        NETWORK_HEALTH_INDEX.set(100 if len(all_hosts) > 0 else 0)
        logging.info(f"Cycle completed in {sweep_duration}s. Discovered {len(all_hosts)} active hosts across {len(SUBNET_LAB_MAPPING)} configured segments.")

        for host in all_hosts:
            host_ip = host["ip"]
            lab_name = host["lab_name"]
            if host_ip != LOCAL_IP and WINDOWS_PASS:
                threading.Thread(target=audit_windows_pc, args=(host_ip, lab_name, WINDOWS_USER, WINDOWS_PASS), daemon=True).start()

        time.sleep(SCAN_INTERVAL_SECONDS)

if __name__ == "__main__":
    start_monitoring()
