# -*- coding: utf-8 -*-
import psycopg2
from datetime import datetime, timedelta
import sys

# Set UTF-8 encoding
sys.stdout.reconfigure(encoding='utf-8')

# Database connection
conn = psycopg2.connect(
    host="localhost",
    database="postgres",
    user="postgres",
    password="4321"
)
cur = conn.cursor()

print("=" * 80)
print("EMAIL SYSTEM CHECK")
print("=" * 80)

# Check if email_alerts table exists
print("\n[1] Checking email_alerts table...")
cur.execute("""
    SELECT column_name, data_type 
    FROM information_schema.columns 
    WHERE table_name = 'email_alerts'
    ORDER BY ordinal_position
""")
columns = cur.fetchall()

if columns:
    print("  Email alerts table structure:")
    for col in columns:
        print(f"    - {col[0]}: {col[1]}")
else:
    print("  ❌ email_alerts table not found!")

# Check recent email activity
print("\n[2] Recent email activity (last 7 days)...")
try:
    cur.execute("""
        SELECT COUNT(*) as total,
               SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END) as sent,
               SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
               SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending
        FROM email_alerts
        WHERE timestamp >= CURRENT_DATE - INTERVAL '7 days'
    """)
    email_stats = cur.fetchone()
    
    if email_stats and email_stats[0]:
        print(f"  Total emails: {email_stats[0]}")
        print(f"  ✅ Sent: {email_stats[1] or 0}")
        print(f"  ❌ Failed: {email_stats[2] or 0}")
        print(f"  ⏳ Pending: {email_stats[3] or 0}")
    else:
        print("  No email activity in the last 7 days")
        
    # Get last 5 emails
    print("\n[3] Last 5 email attempts...")
    cur.execute("""
        SELECT alert_type, recipient_email, subject, status, error_message, timestamp
        FROM email_alerts
        ORDER BY timestamp DESC
        LIMIT 5
    """)
    recent_emails = cur.fetchall()
    
    if recent_emails:
        for email in recent_emails:
            status_icon = "✅" if email[3] == 'sent' else "❌" if email[3] == 'failed' else "⏳"
            print(f"\n  {status_icon} Type: {email[0]}")
            print(f"     To: {email[1]}")
            print(f"     Subject: {email[2][:50]}...")
            print(f"     Status: {email[3]}")
            if email[4]:
                print(f"     Error: {email[4]}")
            print(f"     Time: {email[5]}")
    else:
        print("  No email records found")
        
except Exception as e:
    print(f"  Error checking emails: {e}")

# Check email configuration in app
print("\n[4] Testing email configuration...")
print("  Checking if SMTP is configured properly...")

# Import app to check config
import sys
sys.path.append('D:\\backend-OA')
try:
    from app import app
    
    with app.app_context():
        smtp_server = app.config.get('MAIL_SERVER')
        smtp_port = app.config.get('MAIL_PORT')
        smtp_username = app.config.get('MAIL_USERNAME')
        smtp_password = app.config.get('MAIL_PASSWORD')
        sender_email = app.config.get('MAIL_DEFAULT_SENDER')
        
        print(f"  SMTP Server: {smtp_server or 'NOT SET'}")
        print(f"  SMTP Port: {smtp_port or 'NOT SET'}")
        print(f"  SMTP Username: {smtp_username or 'NOT SET'}")
        print(f"  SMTP Password: {'SET' if smtp_password else 'NOT SET'}")
        print(f"  Sender Email: {sender_email or 'NOT SET'}")
        
        if all([smtp_server, smtp_port, smtp_username, smtp_password, sender_email]):
            print("\n  ✅ Email configuration appears complete")
        else:
            print("\n  ❌ Email configuration is incomplete")
            
except Exception as e:
    print(f"  Could not check app config: {e}")

print("\n" + "=" * 80)
conn.close()
