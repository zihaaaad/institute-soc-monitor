@echo off
title Python Security Monitor (Port 8000)
cd /d "%~dp0"
echo Starting Agentless Security Engine on port 8000...
python src\agentless_monitor_win.py
pause
