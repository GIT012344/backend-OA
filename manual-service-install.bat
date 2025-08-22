@echo off
REM Manual installation steps for backend-OA Windows Service
REM Run this as Administrator

echo Manual installation of backend-OA as Windows Service
echo.

REM Step 1: Download NSSM if not exists
if not exist "nssm.exe" (
    echo Step 1: Downloading NSSM...
    curl -L -o nssm.zip "https://nssm.cc/release/nssm-2.24.zip"
    powershell -Command "Expand-Archive -Path 'nssm.zip' -DestinationPath '.'"
    copy "nssm-2.24\win64\nssm.exe" "nssm.exe"
    rmdir /s /q "nssm-2.24"
    del "nssm.zip"
    echo NSSM downloaded successfully!
) else (
    echo NSSM already exists, skipping download.
)

REM Step 2: Stop and remove existing service
echo.
echo Step 2: Removing existing service...
nssm stop backend-oa-service 2>nul
nssm remove backend-oa-service confirm 2>nul

REM Step 3: Install new service
echo.
echo Step 3: Installing backend-oa-service...
nssm install backend-oa-service "cmd.exe"
nssm set backend-oa-service AppParameters "/c cd /d D:\backend-OA && pm2 start app.py --name backend-oa --interpreter python --no-daemon"
nssm set backend-oa-service DisplayName "Backend OA Service"
nssm set backend-oa-service Description "Backend OA Python Application Service"
nssm set backend-oa-service Start SERVICE_AUTO_START
nssm set backend-oa-service AppDirectory "D:\backend-OA"
nssm set backend-oa-service AppStdout "D:\backend-OA\logs\service-stdout.log"
nssm set backend-oa-service AppStderr "D:\backend-OA\logs\service-stderr.log"

REM Step 4: Start the service
echo.
echo Step 4: Starting service...
nssm start backend-oa-service

echo.
echo Installation completed!
echo Service commands:
echo   Start:   nssm start backend-oa-service
echo   Stop:    nssm stop backend-oa-service  
echo   Status:  nssm status backend-oa-service
echo   Remove:  nssm remove backend-oa-service confirm

pause
