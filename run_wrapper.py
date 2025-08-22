"""
Backend-OA Subprocess Wrapper
Runs Flask app in a subprocess to avoid exit code 1 issues
"""
import subprocess
import sys
import time
import os

def run_backend():
    """Run Backend-OA Flask app in subprocess"""
    while True:
        try:
            print("[Wrapper] Starting Backend-OA on port 5004...")
            
            # Create Python code to run
            code = """
import sys
sys.path.insert(0, r'D:\\backend-OA')
from app import app
print('Backend-OA server starting...')
app.run(host='0.0.0.0', port=5004, debug=False, use_reloader=False)
"""
            
            # Run in subprocess
            process = subprocess.Popen(
                [sys.executable, "-c", code],
                cwd=r"D:\backend-OA",
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )
            
            # Stream output
            try:
                for line in process.stdout:
                    print(line, end='')
            except:
                pass
            
            # Wait for process to complete
            return_code = process.wait()
            
            if return_code == 0:
                print("[Wrapper] Backend-OA stopped normally")
                break
            else:
                print(f"[Wrapper] Backend-OA exited with code {return_code}")
            
        except KeyboardInterrupt:
            print("[Wrapper] Stopping Backend-OA...")
            if 'process' in locals():
                process.terminate()
            break
        except Exception as e:
            print(f"[Wrapper] Error: {e}")
        
        print("[Wrapper] Restarting in 10 seconds...")
        time.sleep(10)

if __name__ == "__main__":
    run_backend()
