@echo off
echo Backend OA Logs Viewer
echo.
echo Choose an option:
echo 1. View live logs (real-time)
echo 2. View error logs only
echo 3. View output logs only
echo 4. View all logs (combined)
echo 5. Clear logs
echo.
set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" (
    echo Showing live logs... (Press Ctrl+C to exit)
    pm2 logs backend-oa --lines 50
) else if "%choice%"=="2" (
    echo Showing error logs...
    type logs\err.log
) else if "%choice%"=="3" (
    echo Showing output logs...
    type logs\out.log
) else if "%choice%"=="4" (
    echo Showing combined logs...
    type logs\combined.log
) else if "%choice%"=="5" (
    echo Clearing logs...
    pm2 flush backend-oa
    echo Logs cleared!
) else (
    echo Invalid choice!
)

echo.
pause
