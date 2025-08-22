@echo off
REM Service wrapper script for backend-OA (Direct Python version - no PM2)
REM This script will be run by the Windows Service

REM Set up logging
set LOGFILE=D:\backend-OA\logs\service-wrapper.log
echo %date% %time% - Service wrapper starting (Direct mode)... >> %LOGFILE%

REM Change to backend directory
cd /d "D:\backend-OA"

REM Set environment variables
set PYTHONPATH=D:\backend-OA
set PYTHONUNBUFFERED=1
set FLASK_ENV=production

REM Kill any existing processes on port 5004 only
echo %date% %time% - Cleaning up port 5004... >> %LOGFILE%
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5004') do (
    echo Killing PID %%a on port 5004 >> %LOGFILE%
    taskkill /f /pid %%a 2>>%LOGFILE%
)

REM Wait for cleanup
timeout /t 3 /nobreak >nul

REM Start the application directly with Python
echo %date% %time% - Starting backend-oa directly with Python... >> %LOGFILE%

REM Check if launcher.py exists
if exist "launcher.py" (
    echo %date% %time% - Running launcher.py... >> %LOGFILE%
    python launcher.py >> %LOGFILE% 2>&1
) else if exist "app.py" (
    echo %date% %time% - Running app.py... >> %LOGFILE%
    python app.py >> %LOGFILE% 2>&1
) else (
    echo %date% %time% - ERROR: No Python app found! >> %LOGFILE%
)

echo %date% %time% - Service wrapper ended >> %LOGFILE%
