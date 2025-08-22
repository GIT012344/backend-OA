@echo off
REM Auto-start backend-OA service script
REM This script will be used by Windows Task Scheduler to start the backend automatically

REM Set up logging
set LOGFILE=D:\backend-OA\logs\autostart.log
echo %date% %time% - Starting backend-OA application... >> %LOGFILE%

REM Change to backend directory
cd /d "D:\backend-OA"

REM Kill any existing PM2 processes for backend-oa to avoid conflicts
echo %date% %time% - Stopping existing backend-oa processes... >> %LOGFILE%
pm2 delete backend-oa 2>>%LOGFILE%

REM Wait a moment for cleanup
timeout /t 3 /nobreak >nul

REM Start the application with PM2
echo %date% %time% - Starting backend-oa with PM2... >> %LOGFILE%
pm2 start app.py --name backend-oa --interpreter python >> %LOGFILE% 2>&1

REM Check if the process started successfully
pm2 list | findstr "backend-oa" >> %LOGFILE%
if %errorlevel% == 0 (
    echo %date% %time% - Backend-OA started successfully! >> %LOGFILE%
) else (
    echo %date% %time% - ERROR: Failed to start Backend-OA >> %LOGFILE%
)

echo %date% %time% - Auto-start script completed >> %LOGFILE%
