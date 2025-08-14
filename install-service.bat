@echo off
echo Installing Backend OA as Windows Service...
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo This script must be run as Administrator!
    echo Right-click and select "Run as administrator"
    pause
    exit /b 1
)

REM Install PM2 Windows Service
echo Installing PM2 Windows Service...
npm install -g pm2-windows-service

REM Setup PM2 service
echo Setting up PM2 service...
pm2-service-install -n "PM2-BackendOA"

REM Start PM2 service
echo Starting PM2 service...
net start "PM2-BackendOA"

REM Save PM2 configuration
echo Saving PM2 configuration...
pm2 start ecosystem.config.js
pm2 save
pm2 startup

echo.
echo Windows Service installed successfully!
echo Service Name: PM2-BackendOA
echo.
echo The backend will now start automatically when Windows boots.
echo.
pause
