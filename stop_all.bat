@echo off
title Stop All Monitoring Services
echo Stopping all running monitoring processes...
taskkill /F /IM python.exe /T 2>nul
taskkill /F /IM prometheus.exe /T 2>nul
echo.
echo All monitoring processes have been stopped!
echo Ports 8000, 8001, 9090, and 5000 are now free.
pause
