@echo off
title Prometheus Server
cd /d "%~dp0"
if not exist "%~dp0prometheus-3.14.0.windows-amd64\prometheus.exe" (
    echo [!] Prometheus binary not found. Downloading automatically...
    call download_prometheus.bat
)
cd /d "%~dp0prometheus-3.14.0.windows-amd64"
echo Starting Prometheus Server on port 9090...
prometheus.exe --config.file=prometheus.yml
pause

