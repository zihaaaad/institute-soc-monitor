@echo off
title SOC Web Dashboard Console (Port 5000)
cd /d "%~dp0"
echo Starting Standalone SOC Web Console on port 5000...
python src\soc_dashboard.py
pause
