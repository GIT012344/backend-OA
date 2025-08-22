@echo off
title Backend-OA Application
color 0A

echo ==================================
echo    Backend-OA Application
echo ==================================
echo.

:: Set environment
set FLASK_ENV=production
set FLASK_DEBUG=0
set PYTHONIOENCODING=utf-8:replace

:: Change to app directory
cd /d D:\backend-OA

:: Start Backend-OA
echo Starting Backend-OA on port 5004...
python app.py

echo.
echo Application stopped.
pause
