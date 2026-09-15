@echo off
setlocal
title Monitro Setup
cd /d "%~dp0"

set "PROM_VERSION=3.14.0"
set "PROM_ZIP=prometheus-%PROM_VERSION%.windows-amd64.zip"
rem SHA-256 from https://github.com/prometheus/prometheus/releases/download/v3.14.0/sha256sums.txt
set "PROM_SHA256=e57fbb99e4d0bc734d2f2b3aeb68c02fba38862259dc99a95c27ea46d9ccba0a"

echo ============================================================
echo   Monitro setup
echo ============================================================
echo.

echo [1/4] Installing Python dependencies...
python -m pip install --upgrade -r requirements.txt
if errorlevel 1 (
    echo [ERROR] Dependency installation failed. Is Python 3.10+ installed and on PATH?
    pause
    exit /b 1
)

echo.
echo [2/4] Prometheus %PROM_VERSION%...
if exist "%~dp0prometheus-%PROM_VERSION%.windows-amd64\prometheus.exe" (
    echo Prometheus already present.
) else (
    powershell -NoProfile -Command "$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $cfg='prometheus-%PROM_VERSION%.windows-amd64\prometheus.yml'; $bak=$null; if (Test-Path $cfg) { $bak=Get-Content -Raw $cfg }; Invoke-WebRequest -UseBasicParsing -Uri 'https://github.com/prometheus/prometheus/releases/download/v%PROM_VERSION%/%PROM_ZIP%' -OutFile '%PROM_ZIP%'; $h=(Get-FileHash '%PROM_ZIP%' -Algorithm SHA256).Hash.ToLower(); if ($h -ne '%PROM_SHA256%') { Remove-Item '%PROM_ZIP%'; throw ('Checksum mismatch: ' + $h) }; Expand-Archive -Path '%PROM_ZIP%' -DestinationPath '.' -Force; Remove-Item '%PROM_ZIP%'; if ($bak) { Set-Content -NoNewline -Path $cfg -Value $bak }"
    if errorlevel 1 (
        echo [ERROR] Prometheus download or checksum verification failed. Nothing was installed.
        pause
        exit /b 1
    )
    echo Prometheus downloaded and SHA-256 verified.
)

echo.
echo [3/4] IEEE OUI vendor registry (optional)...
if not exist "%~dp0data" mkdir "%~dp0data"
powershell -NoProfile -Command "$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -UseBasicParsing -UserAgent 'Monitro-Setup' -Uri 'https://standards-oui.ieee.org/oui/oui.csv' -OutFile 'data\oui.csv.tmp'; if ((Get-Item 'data\oui.csv.tmp').Length -lt 1000000) { throw 'download too small' }; Move-Item -Force 'data\oui.csv.tmp' 'data\oui.csv'"
if errorlevel 1 (
    echo [WARN] Could not download the IEEE registry; the built-in vendor table will be used.
) else (
    echo Saved data\oui.csv
)

echo.
echo [4/4] Grafana dashboard...
echo   Needs Grafana running on http://localhost:3000. Provide GRAFANA_TOKEN, or enter credentials when prompted.
python src\setup_grafana.py
if errorlevel 1 (
    echo [WARN] Grafana provisioning skipped. Install/start Grafana and re-run: python src\setup_grafana.py
)

echo.
echo ============================================================
echo   Setup finished. Next steps:
echo     1. Put secrets in environment variables or config.local.json (never config.json)
echo     2. Build the asset whitelist: python src\agentless_monitor_win.py --export-baseline
echo     3. Run start.bat
echo ============================================================
pause
