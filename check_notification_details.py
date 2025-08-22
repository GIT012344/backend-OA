# -*- coding: utf-8 -*-
import psycopg2
import json
import sys

# Set UTF-8 encoding for console output
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
print("CHECKING NOTIFICATION DETAILS")
print("=" * 80)

# Get recent notifications with full details
cur.execute("""
    SELECT id, message, sender_name, user_id, read, timestamp, meta_data
    FROM notifications
    ORDER BY timestamp DESC
    LIMIT 5
""")
notifications = cur.fetchall()

print("\n[RECENT NOTIFICATIONS WITH FULL META_DATA]")
print("-" * 40)
for notif in notifications:
    print(f"\nID: {notif[0]}")
    print(f"  Message: {notif[1][:60]}...")
    print(f"  Sender: {notif[2]}")
    print(f"  User ID: {notif[3]}")
    print(f"  Read: {notif[4]}")
    print(f"  Timestamp: {notif[5]}")
    
    # Parse and display meta_data
    if notif[6]:
        if isinstance(notif[6], dict):
            meta_data = notif[6]
        else:
            try:
                meta_data = json.loads(notif[6])
            except:
                meta_data = {"raw": str(notif[6])}
    else:
        meta_data = {}
    
    print(f"  Meta Data:")
    for key, value in meta_data.items():
        print(f"    - {key}: {value}")

# Check for notifications that should trigger popup
print("\n" + "=" * 80)
print("NOTIFICATIONS THAT SHOULD TRIGGER POPUP:")
print("-" * 40)

cur.execute("""
    SELECT id, message, sender_name, user_id, read, timestamp, meta_data
    FROM notifications
    WHERE read = false
    ORDER BY timestamp DESC
""")
unread_notifs = cur.fetchall()

popup_count = 0
for notif in unread_notifs:
    if notif[6]:
        if isinstance(notif[6], dict):
            meta_data = notif[6]
        else:
            try:
                meta_data = json.loads(notif[6])
            except:
                continue
        
        # Check if this should trigger popup (based on frontend logic)
        is_new_message = meta_data.get('type') in ['new_message', 'textbox_message']
        is_from_user = meta_data.get('sender_type') == 'user' or meta_data.get('type') == 'textbox_message'
        
        if is_new_message:
            popup_count += 1
            print(f"\n✓ Notification {notif[0]} SHOULD trigger popup:")
            print(f"  - Type: {meta_data.get('type')}")
            print(f"  - Sender Type: {meta_data.get('sender_type', 'N/A')}")
            print(f"  - Message: {notif[1][:50]}...")

print(f"\nTotal notifications that should trigger popup: {popup_count}")

conn.close()
print("\n" + "=" * 80)
