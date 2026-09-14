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
3. Right-click `start_all.bat` and select **Run as Administrator**.
4. The system will function immediately without needing manual path adjustments.

---

## Network Configuration

### 1. Adding or Modifying Subnets & Lab Names
Open `src\agentless_monitor_win.py` in any text editor and edit the `SUBNET_LAB_MAPPING` block:

```python
SUBNET_LAB_MAPPING = {
    "10.13.109.0/24": "Lab 1 (Computer Science)",
    "10.13.110.0/24": "Lab 2 (Software Engineering)",
    "10.13.111.0/24": "Lab 3 (Networking & Cyber)",
    "10.13.112.0/24": "Lab 4 (Hardware Lab)",         # Add new lab
    "192.168.1.0/24": "Admin & Faculty Office"         # Add additional subnet
}
```

### 2. Updating Windows Administrator Credentials
For agentless WMI audits (Event Log reading & process inspection), update the credentials in `src\agentless_monitor_win.py`:

```python
WINDOWS_USER = "Administrator"        # Or Domain Admin (e.g., "DOMAIN\\Admin")
WINDOWS_PASS = "YourActualPassword"   # The administrative password
```

---

## Deploying to a New Machine (Fresh Setup)

If setting up this system on a new Windows machine:

1. **Install Python 3.10+**:
   * Download from python.org (ensure "Add Python to PATH" is checked during installation).
2. **Install Grafana OSS**:
   * Download the Windows MSI installer from grafana.com and install it.
3. **Install Dependencies**:
   * In the `monitro` folder, open Command Prompt and run:
     ```cmd
     pip install -r requirements.txt
     ```
4. **Automated Grafana Dashboard Deployment**:
   * Run the deployment script once:
     ```cmd
     python src\setup_grafana.py
     ```
   * It creates the Prometheus data source and configures the SOC dashboard in Grafana automatically.
5. **Start Monitoring**:
   * Run `start_all.bat` as Administrator.

---

## Troubleshooting Guide

| Issue / Error | Root Cause | Solution |
| :--- | :--- | :--- |
| **Port 8000 in use** | An old Python instance is still running | Run `stop_all.bat` as Administrator to kill previous processes |
| **Table says "No data"** | The network sweep has not finished yet | Wait 30 to 60 seconds for the first sweep cycle to complete |
| **Table hangs on loading** | Browser cached old broken schema | Press `Ctrl + F5` to hard-refresh browser cache |
| **Prometheus target shows "DOWN"** | Python monitor is not running | Run `start_monitor.bat` as Administrator |
| **WMI Access Denied on target PC** | Remote WMI / WinRM is blocked on target | Run `Enable-PSRemoting -Force` on the target Windows machine |
