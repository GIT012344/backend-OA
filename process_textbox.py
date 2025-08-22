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
print("PROCESSING TEXTBOX CONTENT TO MESSAGES")
print("=" * 80)

# Find tickets with textbox content
cur.execute("""
    SELECT ticket_id, name, type, textbox 
    FROM tickets 
    WHERE textbox IS NOT NULL AND textbox != ''
""")
tickets = cur.fetchall()

if tickets:
    print(f"\nFound {len(tickets)} tickets with textbox content")
    
    for ticket in tickets:
        ticket_id = ticket[0]
        name = ticket[1] if ticket[1] else f"User {ticket_id[:8]}..."
        ticket_type = ticket[2]
        textbox = ticket[3]
        
        print(f"\nProcessing ticket: {ticket_id}")
        print(f"  Name: {name}")
        print(f"  Type: {ticket_type}")
        print(f"  Textbox: {textbox[:50]}...")
        
        # Create message from textbox
        cur.execute("""
            INSERT INTO messages (ticket_id, user_id, admin_id, sender_type, message, timestamp)
            VALUES (%s, %s, NULL, 'user', %s, %s)
            RETURNING id
        """, (ticket_id, ticket_id, textbox, datetime.utcnow()))
        
        message_id = cur.fetchone()[0]
        print(f"  ✓ Created message ID: {message_id}")
        
        # Create notification for admin
        notification_msg = f"ข้อความใหม่จาก {name}: {textbox[:50]}..."
        meta_data = json.dumps({
            "type": "new_message",
            "sender_type": "user",
            "user_id": ticket_id,
            "sender_name": name,
            "ticket_id": ticket_id,
            "message_id": message_id
        })
        
        cur.execute("""
            INSERT INTO notifications (message, sender_name, user_id, read, timestamp, meta_data)
            VALUES (%s, %s, %s, false, %s, %s)
            RETURNING id
        """, (notification_msg, name, ticket_id, datetime.utcnow(), meta_data))
        
        notification_id = cur.fetchone()[0]
        print(f"  ✓ Created notification ID: {notification_id}")
        
        # Clear the textbox
        cur.execute("""
            UPDATE tickets 
            SET textbox = NULL 
            WHERE ticket_id = %s
        """, (ticket_id,))
        print(f"  ✓ Cleared textbox for ticket {ticket_id}")
    
    # Commit all changes
    conn.commit()
    print(f"\n✅ Successfully processed {len(tickets)} tickets")
else:
    print("\nNo tickets with textbox content found")

# Show current message and notification counts
cur.execute("SELECT COUNT(*) FROM messages WHERE sender_type = 'user'")
user_msg_count = cur.fetchone()[0]

cur.execute("SELECT COUNT(*) FROM notifications WHERE read = false")
unread_notif_count = cur.fetchone()[0]

print("\n" + "=" * 80)
print("SUMMARY:")
print(f"  Total user messages: {user_msg_count}")
print(f"  Unread notifications: {unread_notif_count}")
print("=" * 80)

conn.close()
