@echo off
REM Backend-OA runner with UTF-8 encoding fix
REM Prevents UnicodeEncodeError on Thai Windows

REM Force UTF-8 encoding
chcp 65001 >nul 2>&1
set PYTHONIOENCODING=utf-8
set PYTHONUNBUFFERED=1
set FLASK_ENV=production

REM Change to backend directory
cd /d "D:\backend-OA"

REM Clear screen for clean start
cls

echo ========================================
echo Starting Backend-OA with UTF-8 Support
echo ========================================
echo.

REM Check which Python file to run
if exist "launcher.py" (
    echo Running launcher.py...
    python launcher.py
) else if exist "app.py" (
    echo Running app.py...
    python app.py
) else (
    echo ERROR: No Python app found!
    pause
    exit /b 1
)

echo.
echo Backend-OA stopped.
pause
