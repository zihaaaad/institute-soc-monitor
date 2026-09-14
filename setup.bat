@echo off
title Institute SOC Universal Setup
cd /d "%~dp0"

echo ============================================================
echo   Institute SOC Universal Installation and Setup Wizard
echo ============================================================
echo.

echo [1/3] Installing Python Dependencies...
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Failed to install Python dependencies. Please ensure Python is installed and added to PATH.
    pause
    exit /b 1
)

echo.
echo [2/3] Checking Prometheus Server Binary...
if not exist "%~dp0prometheus-3.14.0.windows-amd64\prometheus.exe" (
    echo Prometheus binary not found. Downloading automatically...
    powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/prometheus/prometheus/releases/download/v3.14.0/prometheus-3.14.0.windows-amd64.zip' -OutFile 'prometheus.zip'"
    powershell -Command "Expand-Archive -Path 'prometheus.zip' -DestinationPath '.' -Force"
    del /f /q prometheus.zip
    echo Prometheus successfully downloaded and extracted!
) else (
    echo Prometheus binary is already present.
)

echo.
echo [3/3] Configuring Grafana Dashboard...
python src\setup_grafana.py

echo.
echo ============================================================
echo   Setup Completed Successfully!
echo   You can now start monitoring by running: start.bat
echo ============================================================
pause
