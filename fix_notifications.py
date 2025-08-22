# -*- coding: utf-8 -*-
import psycopg2
from datetime import datetime
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
print("FIXING NOTIFICATIONS META_DATA")
print("=" * 80)

# First, update existing notifications that don't have proper meta_data
print("\n[1] Updating existing notifications without sender_type...")
cur.execute("""
    SELECT id, message, sender_name, user_id, meta_data
    FROM notifications
    WHERE read = false
    ORDER BY timestamp DESC
""")
notifications = cur.fetchall()

fixed_count = 0
for notif in notifications:
    notif_id = notif[0]
    message = notif[1]
    sender_name = notif[2]
    user_id = notif[3]
    meta_data = notif[4]
    
    # Parse existing meta_data
    if meta_data:
        if isinstance(meta_data, dict):
            existing_meta = meta_data
        else:
            try:
                existing_meta = json.loads(meta_data)
            except:
                existing_meta = {}
    else:
        existing_meta = {}
    
    # Check if it's a message notification that needs fixing
    if 'ข้อความใหม่จาก' in message and ('sender_type' not in existing_meta or existing_meta.get('type') != 'new_message'):
        # Update meta_data with proper fields
        updated_meta = {
            "type": "new_message",
            "sender_type": "user",
            "user_id": user_id,
            "sender_name": sender_name or "User",
            "ticket_id": existing_meta.get('ticket_id', user_id),
            "message_id": existing_meta.get('message_id')
        }
        
        cur.execute("""
            UPDATE notifications
            SET meta_data = %s
            WHERE id = %s
        """, (json.dumps(updated_meta), notif_id))
        
        fixed_count += 1
        print(f"  ✓ Fixed notification {notif_id}: {message[:40]}...")

if fixed_count > 0:
    conn.commit()
    print(f"\n✅ Fixed {fixed_count} notifications")
else:
    print("\n  No notifications needed fixing")

# Now create a test notification with proper meta_data to trigger popup
print("\n[2] Creating test notification with proper meta_data...")

# Find a recent user message to create notification for
cur.execute("""
    SELECT id, user_id, message, timestamp
    FROM messages
    WHERE sender_type = 'user'
    ORDER BY timestamp DESC
    LIMIT 1
""")
user_message = cur.fetchone()

if user_message:
    msg_id = user_message[0]
    user_id = user_message[1]
    message_text = user_message[2]
    
    # Get user name from tickets
    cur.execute("""
        SELECT name FROM tickets
        WHERE ticket_id = %s
        LIMIT 1
    """, (user_id,))
    user_info = cur.fetchone()
    user_name = user_info[0] if user_info else "User"
    
    # Create new notification with proper meta_data
    notification_msg = f"ข้อความใหม่จาก {user_name}: {message_text[:50]}..."
    meta_data = json.dumps({
        "type": "new_message",
        "sender_type": "user",
        "user_id": user_id,
        "sender_name": user_name,
        "ticket_id": user_id,
        "message_id": msg_id
    })
    
    cur.execute("""
        INSERT INTO notifications (message, sender_name, user_id, read, timestamp, meta_data)
        VALUES (%s, %s, %s, false, %s, %s)
        RETURNING id
    """, (notification_msg, user_name, user_id, datetime.utcnow(), meta_data))
    
    new_notif_id = cur.fetchone()[0]
    conn.commit()
    
    print(f"  ✓ Created notification {new_notif_id}")
    print(f"    Message: {notification_msg}")
    print(f"    Meta Data: {meta_data}")
else:
    print("  No user messages found to create notification for")

# Show summary
print("\n" + "=" * 80)
print("SUMMARY OF UNREAD NOTIFICATIONS:")
print("-" * 40)

cur.execute("""
    SELECT COUNT(*) FROM notifications WHERE read = false
""")
unread_count = cur.fetchone()[0]

cur.execute("""
    SELECT COUNT(*) 
    FROM notifications 
    WHERE read = false 
    AND meta_data::text LIKE '%"type"%"new_message"%'
    AND meta_data::text LIKE '%"sender_type"%"user"%'
""")
popup_ready_count = cur.fetchone()[0]

print(f"  Total unread notifications: {unread_count}")
print(f"  Notifications ready for popup: {popup_ready_count}")
print("=" * 80)

conn.close()
