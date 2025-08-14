@echo off
echo Starting Backend OA with PM2...
echo.

REM Check if PM2 is installed
pm2 --version >nul 2>&1
if %errorlevel% neq 0 (
    echo PM2 is not installed. Installing PM2...
    npm install -g pm2
    if %errorlevel% neq 0 (
        echo Failed to install PM2. Please install Node.js first.
        pause
        exit /b 1
    )
)

REM Stop existing process if running
echo Stopping existing backend process...
pm2 stop backend-oa 2>nul
pm2 delete backend-oa 2>nul

REM Start the backend with PM2
echo Starting backend with PM2...
pm2 start ecosystem.config.js

REM Show status
echo.
echo Backend Status:
pm2 status

echo.
echo Backend started successfully!
echo.
echo Useful PM2 commands:
echo   pm2 status          - Show process status
echo   pm2 logs backend-oa - Show logs
echo   pm2 restart backend-oa - Restart backend
echo   pm2 stop backend-oa - Stop backend
echo   pm2 delete backend-oa - Delete process
echo.
pause
