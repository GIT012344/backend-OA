module.exports = {
  apps: [{
    name: 'backend-oa',
    script: 'pm2_run.py',  // Use wrapper with signal handling
    interpreter: 'python',
    cwd: 'D:\\backend-OA',
    instances: 1,
    exec_mode: 'fork',
    autorestart: true,  // Enable auto-restart for production stability
    watch: false,
    max_memory_restart: '500M',
    
    // Restart behavior tuning for Windows
    max_restarts: 50,  // Allow many restarts before giving up
    min_uptime: '60s',  // Consider app stable after 60 seconds
    restart_delay: 10000,  // Wait 10 seconds between restarts
    
    // Environment variables
    env: {
      PORT: 5004,
      HOST: '0.0.0.0',
      FLASK_ENV: 'production',
      FLASK_DEBUG: '0',
      PYTHONIOENCODING: 'utf-8:replace',
      PYTHONUTF8: '1',
      PYTHONUNBUFFERED: '1'
    },
    
    // Windows-specific options
    windowsHide: true,  // Hide console window on Windows
    
    // PM2 monitoring settings
    listen_timeout: 0,  // Disable listen timeout
    wait_ready: false,
    kill_timeout: 60000,  // 60 seconds before force kill
    
    // Logging
    out_file: './logs/out.log',
    error_file: './logs/err.log',
    log_date_format: 'YYYY-MM-DD HH:mm:ss Z'
  }]
};
