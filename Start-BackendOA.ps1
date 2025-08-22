# Backend-OA Application Launcher with Single Instance Protection
$AppName = "Backend-OA"
$Port = 5004
$WorkDir = "D:\backend-OA"

# Function to check if port is in use
function Test-Port {
    param($Port)
    $connection = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
    return $connection -ne $null
}

# Function to kill existing Backend-OA processes
function Stop-BackendOA {
    Write-Host "Stopping existing Backend-OA processes..." -ForegroundColor Yellow
    
    # Find Python processes using port 5004
    $connections = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
    foreach ($conn in $connections) {
        if ($conn.OwningProcess -gt 0) {
            Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
            Write-Host "Killed process $($conn.OwningProcess) using port $Port"
        }
    }
    
    # Clean up any orphaned Python processes in backend-OA directory
    $pythonProcs = Get-WmiObject Win32_Process -Filter "Name='python.exe'" | 
        Where-Object { $_.CommandLine -like "*backend-OA*" }
    
    foreach ($proc in $pythonProcs) {
        Stop-Process -Id $proc.ProcessId -Force -ErrorAction SilentlyContinue
        Write-Host "Killed orphaned Python process $($proc.ProcessId)"
    }
    
    Start-Sleep -Seconds 2
}

# Main loop
Write-Host "==================================" -ForegroundColor Cyan
Write-Host "Backend-OA Application Manager" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan

while ($true) {
    # Check if port is already in use
    if (Test-Port -Port $Port) {
        Write-Host "Port $Port is already in use. Checking if it's our app..." -ForegroundColor Yellow
        
        # Test if the app responds
        try {
            $response = Invoke-WebRequest -Uri "http://localhost:$Port/health" -TimeoutSec 5 -ErrorAction Stop
            Write-Host "Backend-OA is already running and responding. Monitoring..." -ForegroundColor Green
            Start-Sleep -Seconds 30
            continue
        }
        catch {
            Write-Host "Port $Port is blocked but app not responding. Cleaning up..." -ForegroundColor Red
            Stop-BackendOA
        }
    }
    
    # Start the application
    Write-Host "`nStarting Backend-OA on port $Port..." -ForegroundColor Green
    Write-Host "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Gray
    
    # Set environment variables
    $env:FLASK_ENV = "production"
    $env:FLASK_DEBUG = "0"
    $env:PYTHONIOENCODING = "utf-8:replace"
    $env:PYTHONUTF8 = "1"
    $env:PYTHONUNBUFFERED = "1"
    
    # Change to app directory
    Set-Location -Path $WorkDir
    
    # Start Python app
    $pythonCmd = "from app import app; app.run(host='0.0.0.0', port=$Port, debug=False)"
    $process = Start-Process -FilePath "python" -ArgumentList "-c", "`"$pythonCmd`"" -PassThru -NoNewWindow -RedirectStandardOutput "backend_output.log" -RedirectStandardError "backend_error.log"
    
    Write-Host "Started Backend-OA with PID: $($process.Id)" -ForegroundColor Green
    
    # Wait for process to exit
    $process.WaitForExit()
    
    Write-Host "`nBackend-OA exited with code: $($process.ExitCode)" -ForegroundColor Red
    Write-Host "Restarting in 10 seconds..." -ForegroundColor Yellow
    
    # Clean up before restart
    Stop-BackendOA
    Start-Sleep -Seconds 10
}
