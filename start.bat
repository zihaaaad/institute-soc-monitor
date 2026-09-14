@echo off
title Institute SOC Launcher
cd /d "%~dp0"

echo ============================================================
echo   Starting Institute SOC & Network Monitoring Engine...
echo ============================================================
echo.

if not exist "%~dp0prometheus-3.14.0.windows-amd64\prometheus.exe" (
    echo [!] First time run detected. Running automated setup...
    call setup.bat
)

echo [1/3] Launching Python Agentless Security Engine...
start "Python Security Monitor (Port 8000)" cmd /k "cd /d ""%~dp0"" && python src\agentless_monitor_win.py"

timeout /t 3 /nobreak >nul

echo [2/3] Launching Prometheus Server...
start "Prometheus Server (Port 9090)" cmd /k "cd /d ""%~dp0prometheus-3.14.0.windows-amd64"" && prometheus.exe --config.file=prometheus.yml"

timeout /t 3 /nobreak >nul

echo [3/3] Opening Grafana SOC Dashboard...
start http://localhost:3000/d/institute-soc-overview

echo.
echo ============================================================
echo   All monitoring systems are now RUNNING!
echo   Dashboard URL: http://localhost:3000/d/institute-soc-overview
echo   To stop all services anytime, run: stop.bat
echo ============================================================
pause
