@echo off
title Stop Monitoring Engine
echo Stopping all running monitoring processes...
taskkill /F /IM python.exe /T 2>nul
taskkill /F /IM prometheus.exe /T 2>nul
echo.
echo All monitoring processes have been stopped cleanly.
pause
