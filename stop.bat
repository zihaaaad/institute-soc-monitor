@echo off
title Monitro - Stop Services
cd /d "%~dp0"

echo ============================================================
echo   Stopping Monitro services started from this folder...
echo ============================================================
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\stop-monitro.ps1"
echo.
pause
