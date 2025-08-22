# -*- coding: utf-8 -*-
import psycopg2
from datetime import datetime, timedelta
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
print("CHECKING MESSAGES AND NOTIFICATIONS")
print("=" * 80)

# Check recent messages
print("\n[1] RECENT MESSAGES (Last 10):")
print("-" * 40)
cur.execute("""
    SELECT id, user_id, admin_id, sender_type, message, timestamp 
    FROM messages 
    ORDER BY timestamp DESC 
    LIMIT 10
""")
messages = cur.fetchall()

for msg in messages:
    user_display = msg[1][:30] if msg[1] else "None"
    admin_display = msg[2][:30] if msg[2] else "None"
    msg_display = msg[4][:50] if msg[4] else ""
    print(f"ID: {msg[0]}")
    print(f"  User: {user_display}")
    print(f"  Admin: {admin_display}")
    print(f"  Type: {msg[3]}")
    print(f"  Message: {msg_display}...")
    print(f"  Time: {msg[5]}")
    print()

# Check recent notifications
print("\n[2] RECENT NOTIFICATIONS (Last 10):")
print("-" * 40)
cur.execute("""
    SELECT id, message, sender_name, user_id, read, timestamp, meta_data
    FROM notifications 
    ORDER BY timestamp DESC 
    LIMIT 10
""")
notifications = cur.fetchall()

for notif in notifications:
    msg_display = notif[1][:50] if notif[1] else ""
    user_display = notif[3][:30] if notif[3] else "None"
    # Handle meta_data that might already be a dict or a string
    if notif[6]:
        if isinstance(notif[6], dict):
            meta_data = notif[6]
        else:
            try:
                meta_data = json.loads(notif[6])
            except:
                meta_data = {}
    else:
        meta_data = {}
    print(f"ID: {notif[0]}")
    print(f"  Message: {msg_display}...")
    print(f"  Sender: {notif[2]}")
    print(f"  User: {user_display}")
    print(f"  Read: {notif[4]}")
    print(f"  Time: {notif[5]}")
    print(f"  Type: {meta_data.get('type', 'N/A')}")
    print()

# Check tickets with textbox content
print("\n[3] TICKETS WITH TEXTBOX CONTENT:")
print("-" * 40)
cur.execute("""
    SELECT ticket_id, name, type, textbox 
    FROM tickets 
    WHERE textbox IS NOT NULL AND textbox != ''
    LIMIT 10
""")
tickets = cur.fetchall()

if tickets:
    for ticket in tickets:
        textbox_display = ticket[3][:50] if ticket[3] else ""
        print(f"Ticket: {ticket[0]}")
        print(f"  Name: {ticket[1]}")
        print(f"  Type: {ticket[2]}")
        print(f"  Textbox: {textbox_display}...")
        print()
else:
    print("No tickets with textbox content found")

# Check messages in last hour
print("\n[4] MESSAGES IN LAST HOUR:")
print("-" * 40)
one_hour_ago = datetime.now() - timedelta(hours=1)
cur.execute("""
    SELECT COUNT(*) as total,
           SUM(CASE WHEN sender_type = 'user' THEN 1 ELSE 0 END) as from_user,
           SUM(CASE WHEN sender_type = 'admin' THEN 1 ELSE 0 END) as from_admin
    FROM messages 
    WHERE timestamp > %s
""", (one_hour_ago,))
stats = cur.fetchone()
print(f"Total messages: {stats[0]}")
print(f"From users: {stats[1]}")
print(f"From admin: {stats[2]}")

# Check unread notifications
print("\n[5] UNREAD NOTIFICATIONS COUNT:")
print("-" * 40)
cur.execute("SELECT COUNT(*) FROM notifications WHERE read = false")
unread_count = cur.fetchone()[0]
print(f"Unread notifications: {unread_count}")

conn.close()
print("\n" + "=" * 80)
print("CHECK COMPLETE")
print("=" * 80)
