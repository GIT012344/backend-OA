"""
Backend-OA WSGI Server
Uses Python's built-in wsgiref server
"""
import os
import sys
import time
from wsgiref.simple_server import make_server

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import Flask app
from app import app

def run_server():
    """Run WSGI server"""
    print("Starting Backend-OA on port 5004...")
    print("Using Python's built-in WSGI server")
    
    # Create WSGI server
    server = make_server('0.0.0.0', 5004, app)
    
    try:
        print("Server is running on http://0.0.0.0:5004")
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server...")
        server.shutdown()

if __name__ == "__main__":
    while True:
        try:
            run_server()
            break
        except Exception as e:
            print(f"Server error: {e}")
            print("Restarting in 10 seconds...")
            time.sleep(10)
