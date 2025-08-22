"""
Simple Backend-OA Runner
"""
import os
import sys
import time

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import Flask app
from app import app

print("Starting Backend-OA on port 5004...")

# Run Flask app with infinite retry
while True:
    try:
        # Try to run the Flask app
        app.run(host='0.0.0.0', port=5004, debug=False, use_reloader=False)
    except SystemExit:
        pass  # Ignore SystemExit
    except KeyboardInterrupt:
        print("\nStopping Backend-OA...")
        break
    except Exception as e:
        print(f"Error: {e}")
    
    print("Restarting in 10 seconds...")
    time.sleep(10)
