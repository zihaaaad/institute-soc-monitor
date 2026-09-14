# Institute Cyber Security SOC & Agentless Network Monitor

An enterprise-grade, lightweight, and 100% agentless network security monitoring and endpoint discovery platform designed for educational institutes, corporate labs, and multi-subnet local area networks (100 to 300+ PCs).

> Zero Software on Client PCs: Monitors Windows workstations across multiple subnets without installing any agent or client software, and without modifying network switches or core routers.

---

## Directory Structure

This project is built to be 100% portable. You can move this entire folder to any directory or drive (for example: D:\SOC_Monitor, C:\monitro, E:\Security) and run it immediately with zero configuration changes.

```
monitro/
│
├── 1-Click Launchers (Root)
│   ├── start_all.bat               # Master Launcher: Starts Monitor + Prometheus + Opens Grafana
│   ├── stop_all.bat                # Master Killer: Terminates all running monitor processes
│   ├── start_monitor.bat           # Starts only the Python Agentless Engine (Port 8000)
│   ├── start_prometheus.bat        # Starts only the Prometheus Server (Port 9090)
│   └── start_web_soc_dashboard.bat # Starts standalone lightweight Web UI (Port 5000)
│
├── src/                            # Python Source Code
│   ├── agentless_monitor_win.py    # Main background scanner & Prometheus Exporter
│   ├── setup_grafana.py            # Automated Grafana API Dashboard Deployer
│   └── soc_dashboard.py            # Standalone FastAPI Dark-Mode Cyber Console
│
├── prometheus-3.14.0.windows-amd64/ # Embedded Prometheus Server
│   ├── prometheus.exe              # Standalone Prometheus engine binary
│   └── prometheus.yml              # Pre-configured scrape target configuration
│
└── Documentation & Setup
    ├── README.md                   # System overview & quick start guide
    ├── ARCHITECTURE.md             # Technical data flow & metrics dictionary
    ├── DEPLOYMENT_GUIDE.md         # Portability, multi-subnet setup & troubleshooting
    └── requirements.txt            # Python dependencies
```

---

## Quick Start Guide

### Step 1: Install Python Dependencies (Initial Setup Only)
Open a terminal in this folder and run:
```cmd
pip install -r requirements.txt
```

### Step 2: Launch the System (1-Click)
Right-click `start_all.bat` and select **Run as Administrator**.

This will automatically:
1. Start the Python Agentless Security Engine on port `8000`.
2. Start the Prometheus Server on port `9090`.
3. Open your browser directly to the Grafana SOC Dashboard:
   http://localhost:3000/d/institute-soc-overview

### Step 3: Stop or Restart
To stop all services cleanly, right-click `stop_all.bat` and select **Run as Administrator**.

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

## Web Dashboards & Port Access

| Dashboard / Service | Local URL | Network / Remote URL | Description |
| :--- | :--- | :--- | :--- |
| **Grafana Enterprise SOC** | `http://localhost:3000` | `http://<YOUR_IP>:3000` | Full analytics, charts, tables & metrics |
| **Direct Dashboard Link** | `http://localhost:3000/d/institute-soc-overview` | `http://<YOUR_IP>:3000/d/institute-soc-overview` | Primary landing page |
| **Prometheus Server** | `http://localhost:9090` | `http://<YOUR_IP>:9090` | Metric database & scraper health |
| **Python Metrics Endpoint**| `http://localhost:8000/metrics` | `http://<YOUR_IP>:8000/metrics` | Raw Prometheus text metrics |
| **Standalone Web Console** | `http://localhost:5000` | `http://<YOUR_IP>:5000` | Optional zero-Grafana lightweight web UI |

---

## Customization & Adding Subnets

Open `src\agentless_monitor_win.py` and modify the configuration section:

```python
# Configure your institute subnets and lab names:
SUBNET_LAB_MAPPING = {
    "10.13.109.0/24": "Lab 1 (Computer Science)",
    "10.13.110.0/24": "Lab 2 (Software Engineering)",
    "10.13.111.0/24": "Lab 3 (Networking & Cyber)",
    "10.13.112.0/24": "Lab 4 (Hardware & Robotics)"  # Add as many as needed
}

# Windows Administrator credentials for WMI audits:
WINDOWS_USER = "Administrator"
WINDOWS_PASS = "YourActualPasswordHere"
```

---

## Technical Documentation Links

* [ARCHITECTURE.md](ARCHITECTURE.md): Technical details on the agentless scanning engine, data pipeline, and Prometheus metrics.
* [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md): Portability guide, multi-drive relocation, and troubleshooting.
