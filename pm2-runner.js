const { spawn } = require('child_process');
const path = require('path');

// Configuration
const PYTHON_SCRIPT = 'app.py';
const PYTHON_PATH = 'python';

console.log(`[PM2-Runner] Starting ${PYTHON_SCRIPT}...`);

// Spawn Python process
const pythonProcess = spawn(PYTHON_PATH, [PYTHON_SCRIPT], {
  cwd: __dirname,
  env: process.env,
  stdio: 'inherit',
  windowsHide: true,
  detached: false
});

// Handle process events
pythonProcess.on('error', (err) => {
  console.error(`[PM2-Runner] Failed to start Python process: ${err.message}`);
  process.exit(1);
});

pythonProcess.on('close', (code) => {
  console.log(`[PM2-Runner] Python process exited with code ${code}`);
  process.exit(code || 0);
});

// Handle signals gracefully
const gracefulShutdown = (signal) => {
  console.log(`[PM2-Runner] Received ${signal}, shutting down gracefully...`);
  
  // Don't forward SIGINT to Python on Windows
  if (signal !== 'SIGINT' || process.platform !== 'win32') {
    pythonProcess.kill(signal);
  }
  
  // Give Python time to shutdown
  setTimeout(() => {
    console.log('[PM2-Runner] Force killing Python process...');
    pythonProcess.kill('SIGKILL');
    process.exit(0);
  }, 5000);
};

// Register signal handlers
process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Keep Node process alive
process.stdin.resume();
