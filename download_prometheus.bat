@echo off
title Download Prometheus Binary
cd /d "%~dp0"

set PROM_DIR=%~dp0prometheus-3.14.0.windows-amd64
set PROM_EXE=%PROM_DIR%\prometheus.exe

if exist "%PROM_EXE%" (
    echo Prometheus binary already exists at: %PROM_EXE%
    pause
    exit /b 0
)

echo Downloading Prometheus Windows 64-bit binary...
powershell -Command "[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://github.com/prometheus/prometheus/releases/download/v3.14.0/prometheus-3.14.0.windows-amd64.zip' -OutFile 'prometheus.zip'"

echo Extracting Prometheus...
powershell -Command "Expand-Archive -Path 'prometheus.zip' -DestinationPath '.' -Force"
del /f /q prometheus.zip

echo.
echo Prometheus has been successfully downloaded and extracted!
pause
