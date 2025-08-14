#!/usr/bin/env python3
"""
Quick Fix Script for Backend 500 Error
Run this to diagnose and fix common issues
"""

import psycopg2
import sys
import traceback
from datetime import datetime

# Database configuration
DB_NAME = 'postgres'
DB_USER = 'postgres'
DB_PASSWORD = '4321'
DB_HOST = 'localhost'
DB_PORT = 5432

def test_database_connection():
    """Test database connection"""
    try:
        print("[INFO] Testing database connection...")
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        cur = conn.cursor()
        
        # Test basic query
        cur.execute("SELECT version();")
        version = cur.fetchone()
        print(f"[OK] Database connected successfully: {version[0][:50]}...")
        
        # Test tickets table
        cur.execute("SELECT COUNT(*) FROM tickets;")
        ticket_count = cur.fetchone()[0]
        print(f"[OK] Tickets table accessible: {ticket_count} records")
        
        # Test for tickets with textbox
        cur.execute("SELECT COUNT(*) FROM tickets WHERE textbox IS NOT NULL AND textbox != '' AND type = 'information';")
        textbox_count = cur.fetchone()[0]
        print(f"[INFO] Tickets with textbox content: {textbox_count} records")
        
        # Test messages table
        cur.execute("SELECT COUNT(*) FROM messages;")
        message_count = cur.fetchone()[0]
        print(f"[OK] Messages table accessible: {message_count} records")
        
        # Test notifications table
        cur.execute("SELECT COUNT(*) FROM notifications;")
        notif_count = cur.fetchone()[0]
        print(f"[OK] Notifications table accessible: {notif_count} records")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"[ERROR] Database connection failed: {str(e)}")
        print(f"Full error: {traceback.format_exc()}")
        return False

def check_ssl_certificates():
    """Check SSL certificate files"""
    import os
    
    cert_file = 'cert.pem'
    key_file = 'key.pem'
    
    if os.path.exists(cert_file) and os.path.exists(key_file):
        print("[OK] SSL certificates found")
        
        # Check certificate validity
        try:
            import ssl
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.load_cert_chain(cert_file, key_file)
            print("[OK] SSL certificates are valid")
            return True
        except Exception as e:
            print(f"[ERROR] SSL certificate error: {str(e)}")
            return False
    else:
        print("[ERROR] SSL certificates missing")
        return False

def check_table_schemas():
    """Check if all required tables exist with correct schema"""
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        cur = conn.cursor()
        
        # Check tickets table schema
        cur.execute("""
            SELECT column_name, data_type, is_nullable 
            FROM information_schema.columns 
            WHERE table_name = 'tickets' 
            ORDER BY ordinal_position;
        """)
        tickets_schema = cur.fetchall()
        print(f"[INFO] Tickets table schema: {len(tickets_schema)} columns")
        
        # Check messages table schema
        cur.execute("""
            SELECT column_name, data_type, is_nullable 
            FROM information_schema.columns 
            WHERE table_name = 'messages' 
            ORDER BY ordinal_position;
        """)
        messages_schema = cur.fetchall()
        print(f"[INFO] Messages table schema: {len(messages_schema)} columns")
        
        # Check notifications table schema
        cur.execute("""
            SELECT column_name, data_type, is_nullable 
            FROM information_schema.columns 
            WHERE table_name = 'notifications' 
            ORDER BY ordinal_position;
        """)
        notifications_schema = cur.fetchall()
        print(f"[INFO] Notifications table schema: {len(notifications_schema)} columns")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"[ERROR] Schema check failed: {str(e)}")
        return False

def simulate_scheduler_job():
    """Simulate the scheduler job that's causing 500 error"""
    try:
        print("[INFO] Simulating scheduler job...")
        
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        cur = conn.cursor()
        
        # Find tickets with textbox content (same query as scheduler)
        cur.execute("""
            SELECT ticket_id, textbox, name, type 
            FROM tickets 
            WHERE textbox IS NOT NULL 
            AND textbox != '' 
            AND textbox != 'null'
            AND type = 'information'
            LIMIT 5;
        """)
        
        tickets = cur.fetchall()
        print(f"[INFO] Found {len(tickets)} tickets with textbox content")
        
        for ticket in tickets:
            ticket_id, textbox, name, ticket_type = ticket
            print(f"  - {ticket_id}: {textbox[:30]}... (type: {ticket_type})")
        
        conn.close()
        return True
        
    except Exception as e:
        print(f"[ERROR] Scheduler simulation failed: {str(e)}")
        print(f"Full error: {traceback.format_exc()}")
        return False

def main():
    print("[URGENT] Backend 500 Error Diagnosis Tool")
    print("=" * 50)
    print(f"Timestamp: {datetime.now().isoformat()}")
    print()
    
    # Run all checks
    db_ok = test_database_connection()
    ssl_ok = check_ssl_certificates()
    schema_ok = check_table_schemas()
    scheduler_ok = simulate_scheduler_job()
    
    print("\n" + "=" * 50)
    print("[SUMMARY] DIAGNOSIS SUMMARY:")
    print(f"Database Connection: {'[OK]' if db_ok else '[FAILED]'}")
    print(f"SSL Certificates: {'[OK]' if ssl_ok else '[FAILED]'}")
    print(f"Table Schemas: {'[OK]' if schema_ok else '[FAILED]'}")
    print(f"Scheduler Simulation: {'[OK]' if scheduler_ok else '[FAILED]'}")
    
    if all([db_ok, ssl_ok, schema_ok, scheduler_ok]):
        print("\n[SUCCESS] All checks passed! The issue might be intermittent.")
        print("[RECOMMENDATION] Monitor backend_error.log for specific error details")
    else:
        print("\n[WARNING] Issues found! Check the failed components above.")
        
    print("\n[NEXT STEPS]")
    print("1. Start backend: python app.py")
    print("2. Monitor logs: type backend_error.log")
    print("3. Check HTTPS endpoint: https://10.10.1.53:5004/api/process-all-textbox-messages")

if __name__ == "__main__":
    main()
