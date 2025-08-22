#!/usr/bin/env python
"""
PM2 Wrapper Script for Backend-OA Application
Handles signals properly on Windows to prevent restart loops
"""

import signal
import sys
import time
import os

# Flag to track if we're shutting down
shutting_down = False

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully"""
    global shutting_down
    if not shutting_down:
        shutting_down = True
        print(f"Received signal {signum}, shutting down gracefully...")
        sys.exit(0)

# Register signal handlers
signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

# On Windows, also handle SIGBREAK
if hasattr(signal, 'SIGBREAK'):
    signal.signal(signal.SIGBREAK, signal_handler)

try:
    # Run the actual application
    print("Starting Backend-OA application via wrapper...")
    
    # Import and run the app
    import app
    
except KeyboardInterrupt:
    print("Keyboard interrupt received, shutting down...")
    sys.exit(0)
except Exception as e:
    print(f"Error in wrapper: {e}")
    sys.exit(1)
