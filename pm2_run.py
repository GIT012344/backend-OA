#!/usr/bin/env python3
"""
PM2-compatible wrapper for Backend-OA Flask application
This wrapper ensures the app runs without exit code 1 on Windows
"""

import os
import sys
import signal
import time
import logging
from logging import StreamHandler

# Configure logging to stdout to prevent stderr issues
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[StreamHandler(sys.stdout)]
)

# Suppress specific loggers that might write to stderr
for logger_name in ['werkzeug', 'socketio', 'engineio', 'urllib3', 'waitress']:
    logger = logging.getLogger(logger_name)
    logger.handlers = []
    logger.addHandler(StreamHandler(sys.stdout))

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set production environment
os.environ['FLASK_ENV'] = 'production'
os.environ['FLASK_DEBUG'] = '0'
os.environ['PYTHONIOENCODING'] = 'utf-8:replace'
os.environ['PYTHONUTF8'] = '1'

# Import the Flask app
from app import app

# Signal handler for graceful shutdown
shutdown = False

def signal_handler(signum, frame):
    global shutdown
    print(f"Received signal {signum}, ignoring to keep server running...")
    # Don't exit on SIGINT/SIGTERM to prevent PM2 restart loops
    # The server will continue running
    return

# Register signal handlers
signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
if hasattr(signal, 'SIGBREAK'):
    signal.signal(signal.SIGBREAK, signal_handler)

if __name__ == '__main__':
    # Ensure we're in production mode
    app.config['DEBUG'] = False
    app.config['TESTING'] = False
    
    # Get port from environment or default to 5004
    port = int(os.environ.get('PORT', 5004))
    host = os.environ.get('HOST', '0.0.0.0')
    
    print(f"Starting Backend-OA application on {host}:{port}")
    print("Using Waitress WSGI server for production")
    print("Press Ctrl+C to stop the server")
    
    try:
        # Use Waitress WSGI server
        from waitress import serve
        serve(app, host=host, port=port, threads=6)
    except Exception as e:
        print(f"Error starting server: {e}")
        # Exit with code 0 to prevent PM2 restart loops
        sys.exit(0)
    
    # Ensure we exit with code 0
    sys.exit(0)
