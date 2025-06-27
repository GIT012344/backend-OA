from gevent import monkey
monkey.patch_all()
from flask import Flask, jsonify, request
import requests
from flask_cors import CORS 
import psycopg2
from datetime import datetime
import os
from flask_caching import Cache
from flask_sqlalchemy import SQLAlchemy
from flask_socketio import SocketIO
import traceback

LINE_ACCESS_TOKEN = "0C9ZwOVQ7BOY9dLLfvEqAP+RhpIXmlpcuHf4fgJ184c0nvKzc5S+rKAyjh7yDqadGK1VNxe36n+nswrYaDSLCKOGmhuXjrsRgspH1RF4hGWdgOrrMlBhGnYQjxB9jHDSXVHO5HYkjLJdWOarG8PXKQdB04t89/1O/w1cDnyilFU="

app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="gevent")
CORS(app)

DB_NAME = 'datagit'
DB_USER = 'git'
DB_PASSWORD = '4H9c9zbnSxqdrQVUY2ErAtJwzJINcfNn'
DB_HOST = 'dpg-d19qj8bipnbc739c4aq0-a.singapore-postgres.render.com'
DB_PORT = 5432

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define SQLAlchemy models
class Ticket(db.Model):
    __tablename__ = 'tickets'
    
    ticket_id = db.Column(db.String, primary_key=True)
    user_id = db.Column(db.String)
    email = db.Column(db.String)
    name = db.Column(db.String)
    phone = db.Column(db.String)
    department = db.Column(db.String)
    created_at = db.Column(db.DateTime)
    status = db.Column(db.String)
    appointment = db.Column(db.DateTime, nullable=True)
    requested = db.Column(db.String)
    report = db.Column(db.String)
    type = db.Column(db.String)
    textbox = db.Column(db.String)

class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

class Message(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.String, db.ForeignKey('tickets.ticket_id'))
    admin_id = db.Column(db.String)
    sender_name = db.Column(db.String)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    is_admin_message = db.Column(db.Boolean, default=False)
    user_id = db.Column(db.String, nullable=True)
    line_id = db.Column(db.String, nullable=True)
    platform = db.Column(db.String, nullable=True)

def send_textbox_message(user_id, message_text):
    url = "https://api.line.me/v2/bot/message/push"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LINE_ACCESS_TOKEN}"
    }

    # สร้าง Flex Message สำหรับ textbox reply
    payload = {
        "to": user_id,
        "messages": [
            {
                "type": "flex",
                "altText": "ข้อความจากเจ้าหน้าที่",
                "contents": {
                    "type": "bubble",
                    "body": {
                        "type": "box",
                        "layout": "vertical",
                        "contents": [
                            {
                                "type": "text",
                                "text": "💼 ตอบกลับจากเจ้าหน้าที่",
                                "weight": "bold",
                                "size": "lg",
                                "color": "#005BBB"
                            },
                            {
                                "type": "text",
                                "text": message_text,
                                "wrap": True,
                                "margin": "md"
                            },
                            {
                                "type": "text",
                                "text": "พิมพ์ 'จบ' เพื่อสิ้นสุดการสนทนา",
                                "size": "sm",
                                "color": "#AAAAAA",
                                "margin": "md"
                            }
                        ]
                    }
                }
            }
        ]
    }

    # ส่งข้อความไปยัง LINE Messaging API
    response = requests.post(url, headers=headers, json=payload)
    return response.status_code == 200

def notify_user(payload):
    url = "https://api.line.me/v2/bot/message/push"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LINE_ACCESS_TOKEN}"
    }

    # แปลง payload เป็น Flex Message แบบเดียวกับใน Apps Script
    flex_message = create_flex_message(payload)

    body = {
        "to": payload['user_id'],
        "messages": [flex_message]
    }

    response = requests.post(url, headers=headers, json=body)
    return response.status_code == 200



def create_flex_message(payload):
    appointment_date = '-'
    if payload.get('appointment'):
        try:
            dt = datetime.strptime(payload['appointment'], '%Y-%m-%d %H:%M:%S')
            appointment_date = dt.strftime('%d/%m/%Y %H:%M')
        except:
            appointment_date = payload['appointment']
    status = payload.get('status', 'ไม่ระบุ')
    status_color = {
        'Pending': '#FF9900',
        'Completed': '#00AA00',
        'Rejected': '#FF0000',
        'In Progress': '#0066FF'
    }.get(status, '#666666')

    return {
        "type": "flex",
        "altText": "อัปเดตสถานะ Ticket ของคุณ",
        "contents": {
            "type": "bubble",
            "size": "giga",
            "header": {
                "type": "box",
                "layout": "vertical",
                "contents": [
                    {
                        "type": "text",
                        "text": "📢 อัปเดตสถานะ Ticket",
                        "weight": "bold",
                        "size": "lg",
                        "color": "#FFFFFF",
                        "align": "center"
                    }
                ],
                "backgroundColor": "#005BBB",
                "paddingAll": "20px"
            },
            "body": {
                "type": "box",
                "layout": "vertical",
                "contents": [
                    {
                        "type": "box",
                        "layout": "horizontal",
                        "contents": [
                            {
                                "type": "text",
                                "text": "หมายเลข",
                                "weight": "bold",
                                "size": "sm",
                                "flex": 2,
                                "color": "#666666"
                            },
                            {
                                "type": "text",
                                "text": payload.get('ticket_id', ''),
                                "size": "sm",
                                "flex": 4,
                                "align": "end"
                            }
                        ],
                        "spacing": "sm",
                        "margin": "md"
                    },
                    {
                        "type": "separator",
                        "margin": "md"
                    },
                    {
                        "type": "box",
                        "layout": "horizontal",
                        "contents": [
                            {
                                "type": "text",
                                "text": "ชื่อ",
                                "weight": "bold",
                                "size": "sm",
                                "flex": 2,
                                "color": "#666666"
                            },
                            {
                                "type": "text",
                                "text": payload.get('name', ''),
                                "size": "sm",
                                "flex": 4,
                                "align": "end"
                            }
                        ],
                        "spacing": "sm",
                        "margin": "md"
                    },
                    {
                        "type": "separator",
                        "margin": "md"
                    },
                    {
                        "type": "box",
                        "layout": "horizontal",
                        "contents": [
                            {
                                "type": "text",
                                "text": "แผนก",
                                "weight": "bold",
                                "size": "sm",
                                "flex": 2,
                                "color": "#666666"
                            },
                            {
                                "type": "text",
                                "text": payload.get('department', ''),
                                "size": "sm",
                                "flex": 4,
                                "align": "end"
                            }
                        ],
                        "spacing": "sm",
                        "margin": "md"
                    },
                    {
                        "type": "separator",
                        "margin": "md"
                    },
                    {
                        "type": "box",
                        "layout": "horizontal",
                        "contents": [
                            {
                                "type": "text",
                                "text": "เบอร์ติดต่อ",
                                "weight": "bold",
                                "size": "sm",
                                "flex": 2,
                                "color": "#666666"
                            },
                            {
                                "type": "text",
                                "text": payload.get('phone', ''),
                                "size": "sm",
                                "flex": 4,
                                "align": "end"
                            }
                        ],
                        "spacing": "sm",
                        "margin": "md"
                    },
                    {
                        "type": "separator",
                        "margin": "md"
                    },
                    {
                        "type": "box",
                        "layout": "horizontal",
                        "contents": [
                            {
                                "type": "text",
                                "text": "Type",
                                "weight": "bold",
                                "size": "sm",
                                "flex": 2,
                                "color": "#666666"
                            },
                            {
                                "type": "text",
                                "text": payload.get('type', ''),
                                "size": "sm",
                                "flex": 4,
                                "align": "end"
                            }
                        ],
                        "spacing": "sm",
                        "margin": "md"
                    },
                    {
                        "type": "separator",
                        "margin": "md"
                    },
                    {
                        "type": "box",
                        "layout": "horizontal",
                        "contents": [
                            {
                                "type": "text",
                                "text": "ปัญหา",
                                "weight": "bold",
                                "size": "sm",
                                "flex": 2,
                                "color": "#666666"
                            },
                            {
                                "type": "text",
                                "text": payload.get('report', 'ไม่มีข้อมูล'),
                                "size": "sm",
                                "flex": 4,
                                "align": "end",
                                "wrap": True
                            }
                        ],
                        "spacing": "sm",
                        "margin": "md"
                    },
                    {
                        "type": "separator",
                        "margin": "md"
                    },
                    {
                        "type": "box",
                        "layout": "horizontal",
                        "contents": [
                            {
                                "type": "text",
                                "text": "วันที่นัดหมาย",
                                "weight": "bold",
                                "size": "sm",
                                "flex": 2,
                                "color": "#666666"
                            },
                            {
                                "type": "text",
                                "text": appointment_date,
                                "size": "sm",
                                "flex": 4,
                                "align": "end"
                            }
                        ],
                        "spacing": "sm",
                        "margin": "md"
                    },
                    {
                        "type": "box",
                        "layout": "vertical",
                        "contents": [
                            {
                                "type": "text",
                                "text": "สถานะล่าสุด",
                                "weight": "bold",
                                "size": "sm",
                                "color": "#666666",
                                "margin": "md"
                            },
                            {
                                "type": "text",
                                "text": status,
                                "weight": "bold",
                                "size": "xl",
                                "color": status_color,
                                "align": "center",
                                "margin": "sm"
                            }
                        ],
                        "backgroundColor": "#F5F5F5",
                        "cornerRadius": "md",
                        "margin": "xl",
                        "paddingAll": "md"
                    }
                ],
                "spacing": "md",
                "paddingAll": "20px"
            },
            "footer": {
                "type": "box",
                "layout": "vertical",
                "contents": [
                    {
                        "type": "text",
                        "text": "ขอบคุณที่ใช้บริการของเรา",
                        "size": "xs",
                        "color": "#888888",
                        "align": "center"
                    }
                ],
                "paddingAll": "10px"
            }
        }
    }


@app.route('/api/notifications')
def get_notifications():
    # Get last 20 notifications, newest first using SQLAlchemy
    notifications = Notification.query.order_by(Notification.timestamp.desc()).limit(20).all()
    
    result = []
    for notification in notifications:
        result.append({
            "id": notification.id,
            "message": notification.message,
            "timestamp": notification.timestamp.isoformat(),
            "read": notification.read
        })
    
    return jsonify(result)

# Add a route to mark notifications as read
@app.route('/mark-notification-read', methods=['POST'])
def mark_notification_read():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    notification_id = data.get('id')
    
    if not notification_id:
        return jsonify({"error": "Notification ID required"}), 400
    
    try:
        notification = Notification.query.get(notification_id)
        if notification:
            notification.read = True
            db.session.commit()
            return jsonify({"success": True})
        else:
            return jsonify({"error": "Notification not found"}), 404
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# Add a route to mark all notifications as read
@app.route('/mark-all-notifications-read', methods=['POST'])
def mark_all_notifications_read():
    try:
        # Update all unread notifications
        Notification.query.filter_by(read=False).update({"read": True})
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

def create_tickets_table():
    # Create all tables using SQLAlchemy
    db.create_all()

def parse_datetime(date_str):
    try:
        return datetime.fromisoformat(date_str)
    except Exception:
        return None

@app.route('/')
def home():
    return jsonify({
        "message": "Backend is running",
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/test')
def test_api():
    return jsonify({
        "message": "API is working",
        "status": "ok",
        "timestamp": datetime.now().isoformat()
    })

@app.route('/api/sync-simple')
def sync_simple():
    try:
        print("Starting simple sync process...")
        
        # สร้างตาราง
        try:
            with app.app_context():
                print("Creating tables...")
                create_tickets_table()
                print("Tables created successfully")
        except Exception as table_error:
            print(f"Table creation error: {str(table_error)}")
            return jsonify({
                "error": "Table creation failed",
                "message": str(table_error)
            }), 500
        
        # ดึงข้อมูลจากฐานข้อมูล
        try:
            conn = psycopg2.connect(
                dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, 
                host=DB_HOST, port=DB_PORT
            )
            cur = conn.cursor()
            
            # ตรวจสอบว่าตาราง tickets มีอยู่หรือไม่
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_name = 'tickets'
                );
            """)
            result = cur.fetchone()
            table_exists = result[0] if result else False
            
            if not table_exists:
                print("Tickets table does not exist")
                return jsonify({
                    "error": "Tickets table not found",
                    "message": "Table creation failed"
                }), 500
            
            cur.execute("""
                SELECT ticket_id, email, name, phone, department, created_at, 
                       status, appointment, requested, report, type, textbox 
                FROM tickets
                ORDER BY created_at DESC;
            """)
            rows = cur.fetchall()
            print(f"Retrieved {len(rows)} tickets from database")
            conn.close()
            
            result = [
                {
                    "Ticket ID": row[0],
                    "อีเมล": row[1],
                    "ชื่อ": row[2],
                    "เบอร์ติดต่อ": row[3],
                    "แผนก": row[4],
                    "วันที่แจ้ง": row[5].isoformat() if row[5] else "",
                    "สถานะ": row[6],
                    "Appointment": row[7],
                    "Requeste": row[8],
                    "Report": row[9],
                    "Type": row[10],
                    "TEXTBOX": row[11]
                }
                for row in rows
            ]
            
            print("Simple sync process completed successfully")
            return jsonify({
                "success": True,
                "message": "Tables created and data retrieved successfully",
                "ticket_count": len(rows),
                "data": result
            })
            
        except Exception as query_error:
            print(f"Query error: {str(query_error)}")
            return jsonify({
                "error": "Database query failed",
                "message": str(query_error)
            }), 500
        
    except Exception as e:
        print(f"Unexpected error in sync_simple: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "error": "Internal Server Error",
            "message": str(e)
        }), 500

if __name__ == '__main__':
    with app.app_context():
        create_tickets_table()
    socketio.run(app, host='0.0.0.0', port=5001, debug=False)