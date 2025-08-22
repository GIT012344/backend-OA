@echo off
REM Install backend-OA as Windows Service using NSSM (Non-Sucking Service Manager)
REM This will ensure the backend starts automatically on reboot

echo Installing backend-OA as Windows Service...

REM Check if NSSM exists, if not download it
if not exist "nssm.exe" (
    echo Downloading NSSM...
    powershell -Command "Invoke-WebRequest -Uri 'https://nssm.cc/release/nssm-2.24.zip' -OutFile 'nssm.zip'"
    powershell -Command "Expand-Archive -Path 'nssm.zip' -DestinationPath '.'"
    copy "nssm-2.24\win64\nssm.exe" "nssm.exe"
    rmdir /s /q "nssm-2.24"
    del "nssm.zip"
)

REM Stop and remove existing service if it exists
nssm stop backend-oa-service 2>nul
nssm remove backend-oa-service confirm 2>nul

REM Install the service
echo Installing backend-oa-service...
nssm install backend-oa-service "D:\backend-OA\service-wrapper.bat"

REM Configure service parameters
nssm set backend-oa-service DisplayName "Backend OA Service"
nssm set backend-oa-service Description "Backend OA Python Application Service"
nssm set backend-oa-service Start SERVICE_AUTO_START
nssm set backend-oa-service AppDirectory "D:\backend-OA"
nssm set backend-oa-service AppStdout "D:\backend-OA\logs\service-stdout.log"
nssm set backend-oa-service AppStderr "D:\backend-OA\logs\service-stderr.log"
nssm set backend-oa-service AppRotateFiles 1
nssm set backend-oa-service AppRotateOnline 1
nssm set backend-oa-service AppRotateSeconds 86400
nssm set backend-oa-service AppRotateBytes 1048576

REM Start the service
echo Starting backend-oa-service...
nssm start backend-oa-service

if %errorlevel% == 0 (
    echo SUCCESS: Backend-OA service installed and started!
    echo The service will now start automatically on reboot.
    echo.
    echo Service commands:
    echo   Start:   nssm start backend-oa-service
    echo   Stop:    nssm stop backend-oa-service
    echo   Status:  nssm status backend-oa-service
    echo   Remove:  nssm remove backend-oa-service confirm
) else (
    echo ERROR: Failed to install or start the service.
)

pause
