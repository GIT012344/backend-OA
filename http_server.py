"""
Backend-OA HTTP Server using werkzeug
"""
import os
import sys
import time
from werkzeug.serving import run_simple

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import Flask app
from app import app

print("Starting Backend-OA on port 5004...")
print("Using Werkzeug HTTP server")

# Keep trying to run the server
while True:
    try:
        # Run with Werkzeug's simple server (Flask's underlying server)
        run_simple('0.0.0.0', 5004, app, use_reloader=False, use_debugger=False)
    except KeyboardInterrupt:
        print("\nStopping Backend-OA...")
        break
    except SystemExit as e:
        if e.code == 0:
            break
        print(f"Server exited with code {e.code}, restarting...")
        time.sleep(10)
    except Exception as e:
        print(f"Error: {e}, restarting...")
        time.sleep(10)
