# -*- coding: utf-8 -*-
import psycopg2
from datetime import datetime, timedelta
import json
import sys
import time

# Set UTF-8 encoding
sys.stdout.reconfigure(encoding='utf-8')

# Database connection
conn = psycopg2.connect(
    host="localhost",
    database="postgres",
    user="postgres",
    password="4321"
)

print("=" * 80)
print("REAL-TIME MESSAGE & NOTIFICATION MONITORING")
print("=" * 80)
print("Monitoring for new messages and notifications...")
print("Press Ctrl+C to stop\n")

def get_latest_counts():
    cur = conn.cursor()
    
    # Get message count
    cur.execute("SELECT COUNT(*) FROM messages")
    msg_count = cur.fetchone()[0]
    
    # Get notification count
    cur.execute("SELECT COUNT(*) FROM notifications")
    notif_count = cur.fetchone()[0]
    
    # Get latest message
    cur.execute("""
        SELECT id, user_id, sender_type, message, timestamp 
        FROM messages 
        ORDER BY id DESC 
        LIMIT 1
    """)
    latest_msg = cur.fetchone()
    
    # Get latest notification
    cur.execute("""
        SELECT id, message, user_id, read, timestamp 
        FROM notifications 
        ORDER BY id DESC 
        LIMIT 1
    """)
    latest_notif = cur.fetchone()
    
    cur.close()
    return msg_count, notif_count, latest_msg, latest_notif

# Initial counts
prev_msg_count, prev_notif_count, _, _ = get_latest_counts()
print(f"Initial state:")
print(f"  Messages: {prev_msg_count}")
print(f"  Notifications: {prev_notif_count}")
print("\nWaiting for new messages...\n")

try:
    while True:
        time.sleep(2)  # Check every 2 seconds
        
        msg_count, notif_count, latest_msg, latest_notif = get_latest_counts()
        
        # Check for new messages
        if msg_count > prev_msg_count:
            print(f"\n🆕 NEW MESSAGE DETECTED!")
            print(f"  ID: {latest_msg[0]}")
            print(f"  User: {latest_msg[1]}")
            print(f"  Type: {latest_msg[2]}")
            print(f"  Message: {latest_msg[3][:50]}...")
            print(f"  Time: {latest_msg[4]}")
            
            # Check if notification was created
            if notif_count > prev_notif_count:
                print(f"  ✅ Notification created!")
                print(f"     Notif ID: {latest_notif[0]}")
                print(f"     Notif Message: {latest_notif[1][:50]}...")
            else:
                print(f"  ❌ NO NOTIFICATION CREATED!")
            
            prev_msg_count = msg_count
            prev_notif_count = notif_count
            
        elif notif_count > prev_notif_count:
            print(f"\n📢 New notification without message:")
            print(f"  ID: {latest_notif[0]}")
            print(f"  Message: {latest_notif[1][:50]}...")
            prev_notif_count = notif_count
            
except KeyboardInterrupt:
    print("\n\nMonitoring stopped.")
    
conn.close()
