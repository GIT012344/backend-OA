@echo off
title Backend-OA Application

:start
echo Starting Backend-OA Application...
echo =================================

:: Set working directory
cd /d "D:\backend-OA"

:: Set environment variables
set FLASK_ENV=production
set FLASK_DEBUG=0
set PYTHONIOENCODING=utf-8:replace
set PYTHONUTF8=1
set PYTHONUNBUFFERED=1

:: Start the application
echo Starting Backend-OA on port 5004...
python app.py

:: If the app crashes, wait before exit
if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Application exited with error code %ERRORLEVEL%
    echo Restarting in 10 seconds...
    timeout /t 10 /nobreak
    goto start
)
