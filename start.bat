@echo off
title Monitro Launcher
cd /d "%~dp0"

echo ============================================================
echo   Starting Monitro SOC network monitoring
echo ============================================================
echo   Administrator rights are NOT required. Run as a normal user.
echo.

where python >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Python was not found on PATH. Install Python 3.10+ first.
    pause
    exit /b 1
)

if not exist "%~dp0prometheus-3.14.0.windows-amd64\prometheus.exe" (
    echo [!] Prometheus not found. Running setup first...
    call "%~dp0setup.bat"
    if not exist "%~dp0prometheus-3.14.0.windows-amd64\prometheus.exe" exit /b 1
)

echo [1/3] Starting security monitor (metrics on 127.0.0.1:8000)...
start "Monitro Security Monitor" cmd /k python "%~dp0src\agentless_monitor_win.py"

timeout /t 3 /nobreak >nul

echo [2/3] Starting Prometheus (127.0.0.1:9090, 30 day retention)...
start "Monitro Prometheus" /D "%~dp0prometheus-3.14.0.windows-amd64" cmd /k prometheus.exe --config.file=prometheus.yml --web.listen-address=127.0.0.1:9090 --storage.tsdb.retention.time=30d

timeout /t 3 /nobreak >nul

echo [3/3] Opening Grafana dashboard...
start "" http://localhost:3000/d/institute-soc-overview

echo.
echo ============================================================
echo   Monitro is running.
echo   Dashboard : http://localhost:3000/d/institute-soc-overview
echo   Logs      : %~dp0logs\monitor.log  and  logs\alerts.jsonl
echo   Stop      : stop.bat
echo ============================================================
pause
