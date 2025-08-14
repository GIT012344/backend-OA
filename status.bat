@echo off
echo Backend OA Status Monitor
echo ========================
echo.

REM Check PM2 status
echo PM2 Process Status:
pm2 status

echo.
echo Backend Health Check:
echo ---------------------

REM Test backend endpoint
curl -s -o nul -w "HTTP Status: %%{http_code}\n" http://localhost:5004/api/data 2>nul
if %errorlevel% neq 0 (
    echo Backend is not responding on HTTP port 5004
) else (
    echo Backend is responding on HTTP port 5004
)

REM Test HTTPS endpoint if certificates exist
if exist cert.pem (
    curl -k -s -o nul -w "HTTPS Status: %%{http_code}\n" https://localhost:5004/api/data 2>nul
    if %errorlevel% neq 0 (
        echo Backend is not responding on HTTPS port 5004
    ) else (
        echo Backend is responding on HTTPS port 5004
    )
)

echo.
echo System Information:
echo ------------------
echo Current Time: %date% %time%
echo Computer: %computername%
echo User: %username%

echo.
echo Log Files:
echo ----------
if exist logs\combined.log (
    echo Combined Log Size: 
    for %%A in (logs\combined.log) do echo   %%~zA bytes
)
if exist logs\err.log (
    echo Error Log Size: 
    for %%A in (logs\err.log) do echo   %%~zA bytes
)

echo.
pause
