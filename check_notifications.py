import psycopg2
from datetime import datetime
import json

# Database connection
conn = psycopg2.connect(
    host="localhost",
    database="postgres",
    user="postgres",
    password="4321"
)

cur = conn.cursor()

# Check notifications table
print("=== CHECKING NOTIFICATIONS TABLE ===")
cur.execute("""
    SELECT id, message, sender_name, user_id, timestamp, read, meta_data 
    FROM notifications 
    ORDER BY timestamp DESC 
    LIMIT 10
""")
notifications = cur.fetchall()

if notifications:
    print(f"Found {len(notifications)} recent notifications:")
    for notif in notifications:
        print(f"\nID: {notif[0]}")
        print(f"Message: {notif[1][:100]}...")
        print(f"Sender: {notif[2]}")
        print(f"User ID: {notif[3]}")
        print(f"Time: {notif[4]}")
        print(f"Read: {notif[5]}")
        print(f"Meta: {notif[6][:100] if notif[6] else 'None'}...")
else:
    print("No notifications found in database!")

# Check messages table
print("\n=== CHECKING MESSAGES TABLE ===")
cur.execute("""
    SELECT id, user_id, sender_type, message, timestamp 
    FROM messages 
    ORDER BY timestamp DESC 
    LIMIT 5
""")
messages = cur.fetchall()

if messages:
    print(f"Found {len(messages)} recent messages:")
    for msg in messages:
        print(f"\nID: {msg[0]}")
        print(f"User ID: {msg[1]}")
        print(f"Sender Type: {msg[2]}")
        print(f"Message: {msg[3][:100]}...")
        print(f"Time: {msg[4]}")
else:
    print("No messages found in database!")

# Check email configuration
print("\n=== CHECKING EMAIL SYSTEM ===")
cur.execute("""
    SELECT COUNT(*) as total,
           SUM(CASE WHEN status = 'sent' THEN 1 ELSE 0 END) as sent,
           SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
           SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending
    FROM email_alerts
    WHERE created_at >= CURRENT_DATE - INTERVAL '7 days'
""")
email_stats = cur.fetchone()

if email_stats and email_stats[0] > 0:
    print(f"Email stats (last 7 days):")
    print(f"Total: {email_stats[0]}")
    print(f"Sent: {email_stats[1]}")
    print(f"Failed: {email_stats[2]}")
    print(f"Pending: {email_stats[3]}")
    
    # Get recent failed emails
    cur.execute("""
        SELECT recipient_email, subject, error_message, created_at
        FROM email_alerts
        WHERE status = 'failed'
        ORDER BY created_at DESC
        LIMIT 3
    """)
    failed_emails = cur.fetchall()
    
    if failed_emails:
        print("\nRecent failed emails:")
        for email in failed_emails:
            print(f"  - To: {email[0]}, Subject: {email[1][:50]}...")
            print(f"    Error: {email[2]}")
            print(f"    Time: {email[3]}")
else:
    print("No email activity in the last 7 days")

cur.close()
conn.close()

print("\n=== CHECK COMPLETE ===")
