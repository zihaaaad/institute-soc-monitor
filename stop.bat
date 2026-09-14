@echo off
title Stop Monitoring Engine
cd /d "%~dp0"

echo ============================================================
echo   Stopping Monitro SOC Services...
echo ============================================================
echo.

powershell -Command "Get-NetTCPConnection -LocalPort 8000,9090,5000 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique | ForEach-Object { Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }" 2>nul

taskkill /FI "WINDOWTITLE eq Python Security Monitor*" /F /T 2>nul
taskkill /FI "WINDOWTITLE eq Prometheus Server*" /F /T 2>nul
taskkill /IM prometheus.exe /F /T 2>nul

echo.
echo All Monitro monitoring processes have been stopped cleanly.
pause
