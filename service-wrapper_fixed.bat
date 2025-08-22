@echo off
REM Service wrapper script for backend-OA
REM This script will be run by the Windows Service

REM Set up logging
set LOGFILE=D:\backend-OA\logs\service-wrapper.log
echo %date% %time% - Service wrapper starting... >> %LOGFILE%

REM Change to backend directory
cd /d "D:\backend-OA"

REM Set environment variables
set PYTHONPATH=D:\backend-OA
set PYTHONUNBUFFERED=1

REM Kill any existing PM2 processes to avoid conflicts
echo %date% %time% - Cleaning up existing processes... >> %LOGFILE%
REM DISABLED: taskkill /f /im python.exe
pm2 kill 2>>%LOGFILE%

REM Wait for cleanup
timeout /t 5 /nobreak >nul

REM Start PM2 daemon
echo %date% %time% - Starting PM2 daemon... >> %LOGFILE%
pm2 ping >> %LOGFILE% 2>&1

REM Start the application
echo %date% %time% - Starting backend-oa application... >> %LOGFILE%
pm2 start app.py --name backend-oa --interpreter python >> %LOGFILE% 2>&1

REM Keep the service running by monitoring PM2
:monitor_loop
timeout /t 30 /nobreak >nul
pm2 list | findstr "backend-oa.*online" >nul
if %errorlevel% neq 0 (
    echo %date% %time% - Backend-oa not running, restarting... >> %LOGFILE%
    pm2 start app.py --name backend-oa --interpreter python >> %LOGFILE% 2>&1
)
goto monitor_loop
