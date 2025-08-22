#!/usr/bin/env python3
"""
Backend-OA Application Launcher with Auto-Restart
Handles process management and auto-restart on failure
"""

import os
import sys
import time
import socket
import signal
import subprocess
from datetime import datetime

# Configuration
APP_NAME = "Backend-OA"
PORT = 5004
RESTART_DELAY = 10

def check_port(port):
    """Check if port is in use"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex(('127.0.0.1', port))
    sock.close()
    return result == 0

def kill_process_on_port(port):
    """Kill process using specific port"""
    try:
        # Windows command to find and kill process on port
        cmd = f'for /f "tokens=5" %a in (\'netstat -aon ^| findstr :{port}\') do taskkill /F /PID %a'
        subprocess.run(cmd, shell=True, capture_output=True)
        time.sleep(2)
    except:
        pass

def run_app():
    """Run the Flask application"""
    print(f"\n{'='*50}")
    print(f"Starting {APP_NAME} on port {PORT}")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*50}\n")
    
    # Set environment variables
    os.environ['FLASK_ENV'] = 'production'
    os.environ['FLASK_DEBUG'] = '0'
    os.environ['PYTHONIOENCODING'] = 'utf-8:replace'
    os.environ['PYTHONUTF8'] = '1'
    os.environ['PYTHONUNBUFFERED'] = '1'
    
    # Import and run the app
    try:
        from app import app
        print(f"✓ {APP_NAME} imported successfully")
        
        # Check if port is already in use
        if check_port(PORT):
            print(f"⚠ Port {PORT} is already in use, cleaning up...")
            kill_process_on_port(PORT)
        
        print(f"✓ Starting {APP_NAME} server...")
        app.run(host='0.0.0.0', port=PORT, debug=False)
        
    except KeyboardInterrupt:
        print(f"\n✓ {APP_NAME} stopped by user")
        return 0
    except Exception as e:
        print(f"\n✗ {APP_NAME} crashed with error: {e}")
        return 1

def main():
    """Main loop with auto-restart"""
    print(f"\n{'='*50}")
    print(f"{APP_NAME} Launcher v2.0")
    print(f"Auto-restart enabled with {RESTART_DELAY}s delay")
    print(f"{'='*50}")
    
    # Ignore Windows signals that cause issues
    if hasattr(signal, 'SIGBREAK'):
        signal.signal(signal.SIGBREAK, signal.SIG_IGN)
    
    while True:
        exit_code = run_app()
        
        if exit_code == 0:
            print(f"\n✓ {APP_NAME} exited normally")
            break
        else:
            print(f"\n⚠ {APP_NAME} exited with code {exit_code}")
            print(f"↻ Restarting in {RESTART_DELAY} seconds...")
            time.sleep(RESTART_DELAY)

if __name__ == '__main__':
    main()
