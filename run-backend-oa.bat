@echo off
title Backend-OA Application
color 0B

:start
cls
echo ==================================
echo   Backend-OA Application Runner
echo ==================================
echo.

:: Kill any existing process on port 5004
echo Cleaning up port 5004...
for /f "tokens=5" %%a in ('netstat -aon ^| findstr :5004 ^| findstr LISTENING') do (
    echo Killing process %%a on port 5004...
    taskkill /F /PID %%a 2>nul
)
timeout /t 2 /nobreak >nul

:: Set environment
set FLASK_ENV=production
set FLASK_DEBUG=0
set PYTHONIOENCODING=utf-8:replace
set PYTHONUTF8=1
set PYTHONUNBUFFERED=1

:: Change to app directory
cd /d D:\backend-OA

:: Start Backend-OA
echo Starting Backend-OA on port 5004...
echo Time: %date% %time%
echo.
python app.py

:: If we get here, app crashed
echo.
echo Application stopped. Restarting in 10 seconds...
timeout /t 10
goto start
