@echo off
REM Simple auto-start script for backend-OA
REM This will be placed in Windows Startup folder

echo Starting Backend-OA...
cd /d "D:\backend-OA"

REM Kill any existing processes to avoid conflicts
taskkill /f /im python.exe 2>nul
pm2 kill 2>nul

REM Wait for cleanup
timeout /t 5 /nobreak >nul

REM Start PM2 daemon
pm2 ping >nul 2>&1

REM Start backend-oa
pm2 start app.py --name backend-oa --interpreter python

REM Check if started successfully
pm2 list | findstr "backend-oa.*online" >nul
if %errorlevel% == 0 (
    echo Backend-OA started successfully!
) else (
    echo Failed to start Backend-OA
)

REM Keep window open for 5 seconds then minimize
timeout /t 5 /nobreak
exit
