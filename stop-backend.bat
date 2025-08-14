@echo off
echo Stopping Backend OA...
echo.

REM Stop the backend process
pm2 stop backend-oa
pm2 delete backend-oa

echo.
echo Backend stopped successfully!
echo.
pause
