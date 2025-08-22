"""
Backend-OA Threaded Runner
Uses threading to run Flask app and keep process alive
"""
import os
import sys
import time
import threading
import signal

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import Flask app
from app import app

def run_flask():
    """Run Flask app in a thread"""
    try:
        app.run(host='0.0.0.0', port=5004, debug=False, use_reloader=False, threaded=True)
    except:
        pass

def signal_handler(sig, frame):
    """Handle shutdown signals"""
    print("\nShutting down Backend-OA...")
    sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)

print("Starting Backend-OA on port 5004...")
print("Using threaded Flask server")

# Start Flask in a daemon thread
flask_thread = threading.Thread(target=run_flask, daemon=True)
flask_thread.start()

# Keep the main thread alive
try:
    while True:
        time.sleep(1)
        if not flask_thread.is_alive():
            print("Flask thread died, restarting...")
            flask_thread = threading.Thread(target=run_flask, daemon=True)
            flask_thread.start()
            time.sleep(5)
except KeyboardInterrupt:
    print("\nStopping Backend-OA...")
    sys.exit(0)
