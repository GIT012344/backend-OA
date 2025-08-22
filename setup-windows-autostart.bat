@echo off
REM Setup Windows Task Scheduler for backend-OA auto-start
REM Run this script as Administrator to configure automatic startup

echo Setting up Windows Task Scheduler for backend-OA auto-start...

REM Create a scheduled task that runs at startup
schtasks /create /tn "Backend-OA-AutoStart" /tr "D:\backend-OA\auto-start-service.bat" /sc onstart /ru "SYSTEM" /f

if %errorlevel% == 0 (
    echo SUCCESS: Task scheduled successfully!
    echo The backend-OA will now start automatically when Windows boots.
    echo.
    echo To verify the task was created, run:
    echo schtasks /query /tn "Backend-OA-AutoStart"
    echo.
    echo To delete the task later, run:
    echo schtasks /delete /tn "Backend-OA-AutoStart" /f
) else (
    echo ERROR: Failed to create scheduled task.
    echo Please run this script as Administrator.
)

pause
