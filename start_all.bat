@echo off
title Institute SOC Master Launcher
echo ======================================================
echo   Institute Cyber SOC & Network Monitor Launcher
echo ======================================================
echo.

cd /d "%~dp0"

if not exist "%~dp0prometheus-3.14.0.windows-amd64\prometheus.exe" (
    echo [!] Prometheus binary not found. Downloading automatically...
    call download_prometheus.bat
)

echo [1/3] Starting Python Agentless Security Engine...
start "Python Security Monitor (Port 8000)" cmd /k "cd /d ""%~dp0"" && python src\agentless_monitor_win.py"

timeout /t 3 /nobreak >nul

echo [2/3] Starting Prometheus Server...
start "Prometheus Server (Port 9090)" cmd /k "cd /d ""%~dp0prometheus-3.14.0.windows-amd64"" && prometheus.exe --config.file=prometheus.yml"


timeout /t 3 /nobreak >nul

echo [3/3] Opening Grafana Enterprise SOC Dashboard...
start http://localhost:3000/d/institute-soc-overview

echo.
echo ======================================================
echo   All systems started successfully!
echo   - Python Monitor:  http://10.13.109.50:8000/metrics
echo   - Prometheus API:  http://localhost:9090
echo   - Grafana Console: http://localhost:3000/d/institute-soc-overview
echo ======================================================
pause
