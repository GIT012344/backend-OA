@echo off
title Backend-OA Application

:loop
echo.
echo =================================
echo Starting Backend-OA Application...
echo Time: %date% %time%
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

:: Check exit code
echo.
echo Application exited with code %ERRORLEVEL%
echo Restarting in 10 seconds...
timeout /t 10 /nobreak >nul

:: Always restart
goto loop
