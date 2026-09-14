# Portability & Deployment Guide

This guide explains how to move, configure, and operate the monitoring suite across different folders, drives (C:\, D:\, E:\), or entirely new monitoring host machines.

---

## Drive & Folder Portability

All batch launchers and Python scripts use relative path referencing (`%~dp0` in Windows batch and `os.path` in Python).

### Moving to Another Drive or Folder:
1. Copy or move the entire `monitro` folder anywhere:
   * Example 1: `D:\SOC_Monitor`
   * Example 2: `C:\SecurityTools\monitro`
   * Example 3: `E:\Institute_Monitor`
2. Open the folder in its new location.
3. Run `setup.bat` once to ensure dependencies and Grafana bindings are verified.
4. Right-click `start.bat` and select **Run as Administrator**.
5. The system will function immediately without needing any manual path adjustments.

---

## Universal Network Configuration (`config.json`)

To add, remove, or modify monitored subnets, open `config.json` in any text editor:

```json
{
  "subnets": {
    "10.13.109.0/24": "Lab 1 (Computer Science)",
    "10.13.110.0/24": "Lab 2 (Software Engineering)",
    "10.13.111.0/24": "Lab 3 (Networking & Cyber)",
    "10.13.112.0/24": "Lab 4 (Hardware Lab)",
    "192.168.1.0/24": "Admin & Faculty Office"
  },
  "credentials": {
    "windows_user": "Administrator",
    "windows_password": "YourActualPassword"
  },
  "settings": {
    "scan_interval_seconds": 60,
    "metrics_port": 8000
  }
}
```

---

## Deploying on a Fresh New Machine

When cloning or copying this repository to a completely new Windows PC:

1. **Install Python 3.10+**:
   * Download from python.org (ensure "Add Python to PATH" is checked during installation).
2. **Install Grafana OSS**:
   * Download the Windows MSI installer from grafana.com and install it.
3. **Run 1-Click Setup**:
   * Double-click `setup.bat`. It will automatically:
     * Install Python dependencies (`pip install -r requirements.txt`).
     * Download and extract the Prometheus binary.
     * Configure Grafana data sources and deploy the SOC dashboard.
4. **Start Monitoring**:
   * Right-click `start.bat` and select **Run as Administrator**.
   * Open the dashboard at `http://localhost:3000/d/institute-soc-overview`.

---

## Troubleshooting Guide

| Issue / Error | Root Cause | Solution |
| :--- | :--- | :--- |
| **Port 8000 in use** | An old Python instance is still running | Run `stop.bat` as Administrator to kill previous processes |
| **Table says "No data"** | The network sweep has not finished yet | Wait 30 to 60 seconds for the first sweep cycle to complete |
| **Table hangs on loading** | Browser cached old broken schema | Press `Ctrl + F5` to hard-refresh browser cache |
| **Prometheus target shows "DOWN"** | Python monitor is not running | Run `start.bat` as Administrator |
| **WMI Access Denied on target PC** | Remote WMI / WinRM is blocked on target | Run `Enable-PSRemoting -Force` on the target Windows machine |
