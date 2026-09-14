# Institute Cyber Security SOC & Agentless Network Monitor

An enterprise-grade, lightweight, and 100% agentless network security monitoring, rogue device detection, and endpoint discovery platform designed for educational institutes, corporate labs, and multi-subnet local area networks (100 to 300+ PCs).

> Zero Software on Client PCs: Monitors Windows workstations across multiple subnets without installing any agent or client software, and without modifying network switches or core routers.

---

## Prerequisites (One-Time)

Before running the system on a new PC, ensure you have:
1. **Python 3.10+** (from [python.org](https://www.python.org/downloads/)) - *Make sure to check "Add Python to PATH" during installation.*
2. **Grafana OSS** (from [grafana.com](https://grafana.com/grafana/download)) - *Standard Windows installer.*

---

## 3-Step Quick Start

### Step 1: Customize Your Network (Optional)
Open `config.json` in any text editor (Notepad, VS Code) and add your IP ranges, lab names, or alert webhooks:
```json
{
  "subnets": {
    "192.168.1.0/24": "Main Lab",
    "10.13.109.0/24": "Computer Science Lab"
  },
  "asset_whitelist": [
    "00:15:5d:00:00:01",
    "34:5a:60:11:22:33"
  ],
  "alerts": {
    "enabled": false,
    "discord_webhook_url": "https://discord.com/api/webhooks/...",
    "telegram_bot_token": "",
    "telegram_chat_id": ""
  }
}
```
*(If you leave `config.json` untouched, it will automatically detect and scan your current local network).*

### Step 2: Run Setup (First Time Only)
Double-click `setup.bat` (or right-click and select **Run as Administrator**).
* Installs required Python libraries.
* Downloads Prometheus automatically.
* Automatically imports and deploys the complete Grafana SOC Dashboard.

### Step 3: Start Monitoring
Right-click `start.bat` and select **Run as Administrator**.
* Automatically launches the Python Scanner and Prometheus TSDB.
* Opens your browser directly to the live dashboard:
  http://localhost:3000/d/institute-soc-overview

### To Stop All Monitoring:
Double-click `stop.bat` to cleanly shut down all background services.

---

## Executive Audit & Compliance Report Generator

To generate an immediate audit report (in Markdown and HTML format):
```cmd
python src\generate_report.py
```
This produces `EXECUTIVE_AUDIT_REPORT.md` and `executive_audit_report.html` summarizing all active assets, rogue devices, attack surface exposures, and compliance health.

---

## Directory Structure

```
monitro/
│
├── config.json                     # Universal configuration (Subnets, Whitelists, Webhooks)
├── setup.bat                       # 1-Click Universal Installer & Configurator
├── start.bat                       # 1-Click Master Launcher (Starts Monitor + Prometheus + Grafana)
├── stop.bat                        # 1-Click Clean Shutdown
├── requirements.txt                # Python package dependencies
├── LICENSE                         # MIT Open Source License
│
├── src/                            # Python Source Engines
│   ├── agentless_monitor_win.py    # Background network scanner, rogue detector & Prometheus exporter
│   ├── oui_database.py             # IEEE Standards MAC OUI Hardware Vendor Database
│   ├── threat_intel.py             # MITRE ATT&CK Mapping & CVSS 3.1 Risk Scoring Engine
│   ├── setup_grafana.py            # Automated Grafana API Dashboard Deployer
│   ├── generate_report.py          # Executive SOC Compliance & Incident Report Generator
│   └── soc_dashboard.py            # Standalone FastAPI Cyber Console (Optional port 5000)
│
├── prometheus-3.14.0.windows-amd64/ # Standalone Prometheus Server & Config
│
└── Documentation
    ├── README.md                   # System overview, quickstart & features
    ├── ARCHITECTURE.md             # Technical data flow & metrics dictionary
    ├── ANALYSIS.md                 # Formal time/space complexity & edge cases analysis
    └── DEPLOYMENT_GUIDE.md         # Portability guide & troubleshooting
```

---

## Monitored Intelligence & SOC Capabilities

1. **Master Endpoint & Hardware Directory:**
   * Real-time discovery of all active PCs across all labs and subnets.
   * Device IP Address, Hostname, Subnet/Lab, and Hardware MAC Address.
   * Network Interface Card (NIC) Vendor recognition (Intel, Realtek, Dell, HP, ASUS, VMware, etc.).
2. **Rogue Device Detection & Whitelisting:**
   * Flags unauthorized student laptops, mobile phones, or rogue wireless routers connected to lab ports.
   * Compares active devices against `asset_whitelist` and highlights unauthorized units in red.
3. **Defensive Vulnerability & Attack Surface Auditing:**
   * **SMBv1 Dialect Inspection**: Detects legacy SMBv1 on port 445 (MS17-010 exposure).
   * **RDP Exposure Check**: Flags open RDP port 3389 across the network.
   * **Cleartext Protocol Check**: Highlights unencrypted HTTP port 80/8080 services.
   * **RPC/DCOM Mapper**: Tracks endpoint mapper exposure on port 135.
4. **Automated Incident Webhook Alerts:**
   * Multi-channel alerts sent asynchronously to Discord Webhooks and Telegram Bots.
   * Automatic alert cooldown and deduplication prevents notification flooding.
5. **Cybersecurity & Threat Detection (SOC):**
   * Authentication Anomalies (Event ID 4625): Tracks failed logon spikes and brute-force attempts per target IP.
   * Suspicious & Malicious Process Execution: Flags blacklisted binaries (powershell.exe, mimikatz.exe, netcat.exe, tor.exe, psexec.exe, wireshark.exe, nmap.exe, anydesk.exe).
   * Security Posture Index: Dynamic 0 to 100% computed health rating.

---

## Web Access URLs

| Dashboard / Service | Local URL | Network / Remote URL | Description |
| :--- | :--- | :--- | :--- |
| **Grafana Enterprise SOC** | `http://localhost:3000` | `http://<YOUR_IP>:3000` | Full analytics, charts, tables & metrics |
| **Direct Dashboard Link** | `http://localhost:3000/d/institute-soc-overview` | `http://<YOUR_IP>:3000/d/institute-soc-overview` | Primary landing page |
| **Prometheus Server** | `http://localhost:9090` | `http://<YOUR_IP>:9090` | Metric database & scraper health |
| **Python Metrics Endpoint**| `http://localhost:8000/metrics` | `http://<YOUR_IP>:8000/metrics` | Raw Prometheus text metrics |
| **Standalone Web Console** | `http://localhost:5000` | `http://<YOUR_IP>:5000` | Optional zero-Grafana lightweight web UI |
