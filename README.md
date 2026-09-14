# Institute Cyber Security SOC & Agentless Network Monitor

An enterprise-grade, lightweight, and 100% agentless network security monitoring and endpoint discovery platform designed for educational institutes, corporate labs, and multi-subnet local area networks (100 to 300+ PCs).

> Zero Software on Client PCs: Monitors Windows workstations across multiple subnets without installing any agent or client software, and without modifying network switches or core routers.

---

## Prerequisites (One-Time)

Before running the system on a new PC, ensure you have:
1. **Python 3.10+** (from [python.org](https://www.python.org/downloads/)) - *Make sure to check "Add Python to PATH" during installation.*
2. **Grafana OSS** (from [grafana.com](https://grafana.com/grafana/download)) - *Standard Windows installer.*

---

## 3-Step Quick Start

### Step 1: Customize Your Network (Optional)
Open `config.json` in any text editor (Notepad, VS Code) and add your IP ranges or lab names:
```json
{
  "subnets": {
    "192.168.1.0/24": "Main Lab",
    "10.13.109.0/24": "Computer Science Lab"
  }
}
```
*(If you leave `config.json` untouched, it will automatically detect and scan your current local network).*

### Step 2: Run Setup (First Time Only)
Double-click `setup.bat` (or right-click and select **Run as Administrator**).
* Installs required Python libraries.
* Downloads Prometheus automatically.
* Automatically imports and deploys the Grafana SOC Dashboard.

### Step 3: Start Monitoring
Right-click `start.bat` and select **Run as Administrator**.
* Automatically launches the Python Scanner and Prometheus TSDB.
* Opens your browser directly to the live dashboard:
  http://localhost:3000/d/institute-soc-overview

### To Stop All Monitoring:
Double-click `stop.bat` to cleanly shut down all background services.

---

## Universal Configuration (`config.json`)

You do not need to modify any Python code. All subnet ranges, lab names, and admin credentials are configured in a single file: `config.json` located in the root directory.

```json
{
  "subnets": {
    "10.13.109.0/24": "Lab 1 (Computer Science)",
    "10.13.110.0/24": "Lab 2 (Software Engineering)",
    "10.13.111.0/24": "Lab 3 (Networking & Cyber)"
  },
  "credentials": {
    "windows_user": "Administrator",
    "windows_password": "YourAdminPasswordHere"
  },
  "settings": {
    "scan_interval_seconds": 60,
    "metrics_port": 8000,
    "prometheus_port": 9090,
    "grafana_port": 3000
  }
}
```

*Note: If `config.json` is left unchanged or empty, the engine automatically detects your local IP and scans your active local subnet.*

---

## Directory Structure

```
monitro/
│
├── config.json             # Universal user configuration (Subnets, Passwords, Ports)
├── setup.bat               # 1-Click Universal Installer & Configurator
├── start.bat               # 1-Click Master Launcher (Starts Monitor + Prometheus + Grafana)
├── stop.bat                # 1-Click Clean Shutdown
├── requirements.txt        # Python package dependencies
├── LICENSE                 # MIT Open Source License
│
├── src/                    # Python Source Engines
│   ├── agentless_monitor_win.py  # Background network scanner & Prometheus exporter
│   ├── setup_grafana.py          # Automated Grafana API Dashboard Deployer
│   └── soc_dashboard.py          # Standalone FastAPI Cyber Console (Optional port 5000)
│
├── prometheus-3.14.0.windows-amd64/ # Standalone Prometheus Server & Config
│
└── Documentation
    ├── README.md           # System overview & quickstart
    ├── ARCHITECTURE.md     # Technical data flow & metrics dictionary
    └── DEPLOYMENT_GUIDE.md # Portability guide & troubleshooting
```

---

## Monitored Intelligence & Metrics

1. **Master Endpoint & Hardware Directory:**
   * Real-time discovery of all active PCs across all labs and subnets.
   * Device IP Address, Hostname, Subnet/Lab, and Hardware MAC Address.
   * Network Interface Card (NIC) Vendor recognition (Intel, Realtek, Dell, HP, ASUS, etc.).
2. **Network Performance & Connectivity:**
   * Round-trip network response latency (in milliseconds) for every machine.
   * Real-time online host density timeline per lab segment.
   * Lab-by-lab capacity distribution bar gauge.
3. **Attack Surface & Open Services:**
   * Active inspection of open Windows management ports:
     * RDP (3389) - Remote Desktop exposure
     * SMB (445) - Windows File Sharing
     * WMI/RPC (135) - Remote Management
     * WinRM (5985) - Remote PowerShell
     * HTTP/HTTPS (80/443) - Local Web Services
4. **Cybersecurity & Threat Detection (SOC):**
   * Authentication Anomalies (Event ID 4625): Tracks failed logon spikes and brute-force attempts per target IP.
   * Suspicious & Malicious Process Execution: Flags blacklisted binaries (powershell.exe, mimikatz.exe, netcat.exe, tor.exe, psexec.exe, wireshark.exe, nmap.exe, anydesk.exe).
   * Network Security Posture Index: Live 0 to 100% computed health rating.

---

## Web Access URLs

| Dashboard / Service | Local URL | Network / Remote URL | Description |
| :--- | :--- | :--- | :--- |
| **Grafana Enterprise SOC** | `http://localhost:3000` | `http://<YOUR_IP>:3000` | Full analytics, charts, tables & metrics |
| **Direct Dashboard Link** | `http://localhost:3000/d/institute-soc-overview` | `http://<YOUR_IP>:3000/d/institute-soc-overview` | Primary landing page |
| **Prometheus Server** | `http://localhost:9090` | `http://<YOUR_IP>:9090` | Metric database & scraper health |
| **Python Metrics Endpoint**| `http://localhost:8000/metrics` | `http://<YOUR_IP>:8000/metrics` | Raw Prometheus text metrics |
| **Standalone Web Console** | `http://localhost:5000` | `http://<YOUR_IP>:5000` | Optional zero-Grafana lightweight web UI |

---

## Future Feature Roadmap

* **Automated Multi-Channel Alerting**: Direct notifications to Telegram, Discord, Microsoft Teams, and Email when brute-force spikes (Event 4625) or blacklisted tools are detected.
* **Rogue Device Detection**: Asset whitelist comparison to immediately flag unauthorized laptops, mobile devices, or rogue routers connected to lab ports.
* **SNMP Switch & Router Monitoring**: Telemetry collection for port link status, bandwidth throughput, and CPU/RAM from Cisco, MikroTik, and TP-Link core switches.
* **Agentless Vulnerability Checks**: Network-level exposure checks for critical unpatched Windows vulnerabilities (MS17-010 EternalBlue, CVE-2019-0708 BlueKeep, PrintNightmare).
* **Automated PDF / Excel Compliance Reports**: Scheduled executive summary reports covering lab uptime, threat statistics, and inventory metrics.
* **Dynamic Network Topology Map**: Visual node-graph illustrating routers, switches, and active workstations in real time.

