from flask import Flask, jsonify, request
import requests
from flask_cors import CORS 
import psycopg2
from datetime import datetime, timezone, timedelta
import os
from datetime import timedelta
from flask_caching import Cache
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
    get_jwt_identity
)
from werkzeug.security import generate_password_hash, check_password_hash
import bcrypt

LINE_ACCESS_TOKEN = "SaXxPgiqWnhbTbwQRoJDnvALTrp+ymslDXHUUo/+Tg1VeqzyGZu7iATjq0EiMYiSGAYKmiuMntQTaOuet4VUiz349QnmJXrKrYWR5k+PDDM1QRebmq5N2Z0kWsmDNBa+3EKmFQUAtuq9SYnXp97+ywdB04t89/1O/w1cDnyilFU="

app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

app.config['JWT_SECRET_KEY'] = 'your-secret-key-here'  # ควรเปลี่ยนเป็นค่าที่ปลอดภัยใน production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)  # Token หมดอายุใน 24 ชั่วโมง
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
jwt = JWTManager(app)

# แก้ไข CORS ให้รองรับทุก origin
CORS(app, origins=["*"], supports_credentials=True)

DB_NAME = 'datagit'
DB_USER = 'git'
DB_PASSWORD = '4H9c9zbnSxqdrQVUY2ErAtJwzJINcfNn'
DB_HOST = 'dpg-d19qj8bipnbc739c4aq0-a.singapore-postgres.render.com'
DB_PORT = 5432

# Flask-SQLAlchemy configuration
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
    appointment = db.Column(db.String)
    requested = db.Column(db.String)
    report = db.Column(db.String)
    type = db.Column(db.String)
    textbox = db.Column(db.String)
    subgroup = db.Column(db.String)
class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    
    def get_thai_time(self):
        # Convert stored UTC time to Thai time when retrieving
        if self.timestamp:
            return self.timestamp.replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=7)))
        return None
        
    def to_dict(self):
        return {
            'id': self.id,
            'message': self.message,
            'timestamp': self.get_thai_time().isoformat() if self.timestamp else None,
            'timestamp_utc': self.timestamp.isoformat() if self.timestamp else None,
            'read': self.read
        }

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String, nullable=False)
    admin_id = db.Column(db.String, nullable=True)
    sender_type = db.Column(db.String, nullable=False)  # 'user' or 'admin'
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    def get_thai_time(self):
        # Convert stored UTC time to Thai time when retrieving
        if self.timestamp:
            return self.timestamp.replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=7)))
        return None
        
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'admin_id': self.admin_id,
            'sender_type': self.sender_type,
            'message': self.message,
            'timestamp': self.get_thai_time().isoformat() if self.timestamp else None,
            'timestamp_utc': self.timestamp.isoformat() if self.timestamp else None
        }

class TicketStatusLog(db.Model):
    __tablename__ = 'ticket_status_logs'
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    ticket_id = db.Column(db.String, db.ForeignKey('tickets.ticket_id'), nullable=False)
    old_status = db.Column(db.String, nullable=False)
    new_status = db.Column(db.String, nullable=False)
    changed_by = db.Column(db.String, nullable=False)
    changed_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    def __init__(self, **kwargs):
        # Convert any provided datetime to UTC before saving
        if 'changed_at' in kwargs and kwargs['changed_at']:
            if kwargs['changed_at'].tzinfo is not None:
                kwargs['changed_at'] = kwargs['changed_at'].astimezone(timezone.utc).replace(tzinfo=None)
        super(TicketStatusLog, self).__init__(**kwargs)
        
    def get_thai_time(self):
        # Convert stored UTC time to Thai time when retrieving
        if self.changed_at:
            return self.changed_at.replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=7)))
        return None
    
    def to_dict(self):
        return {
            'id': self.id,
            'ticket_id': self.ticket_id,
            'old_status': self.old_status,
            'new_status': self.new_status,
            'changed_by': self.changed_by,
            'changed_at': self.get_thai_time().isoformat() if self.changed_at else None,
            'changed_at_utc': self.changed_at.isoformat() if self.changed_at else None
        }

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    pin = db.Column(db.String(10), unique=True, nullable=False)  # รหัส PIN
    role = db.Column(db.String(20), default='user')  # 'user' หรือ 'admin'
    name = db.Column(db.String(100), nullable=False)  # ชื่อผู้ใช้
    is_active = db.Column(db.Boolean, default=True)  # สถานะการใช้งาน

    def check_pin(self, pin):
        return self.pin == pin and self.is_active

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
        'New': '#00BFFF',           # ฟ้าอ่อน
        'In Progress': '#0066FF',   # ฟ้าเข้ม
        'Pending': '#FF9900',       # ส้ม
        'Closed': '#00AA00',        # เขียว
        'Cancelled': '#666666',     # เทาเข้ม
        'On Hold': '#A020F0',       # ม่วง
        'Rejected': '#FF0000',      # แดง (ถ้ามี)
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

def create_tables():
    db.create_all()
    
    # สร้างผู้ใช้เริ่มต้นถ้ายังไม่มี
    if not User.query.filter_by(pin='123456').first():
        admin = User()
        admin.pin = '123456'
        admin.role = 'admin'
        admin.name = 'ผู้ดูแลระบบ'
        db.session.add(admin)
        db.session.commit()
    
    # สร้างผู้ใช้ทั่วไป
    if not User.query.filter_by(pin='000000').first():
        user = User()
        user.pin = '000000'
        user.role = 'user'
        user.name = 'ผู้ใช้ทั่วไป'
        db.session.add(user)
        db.session.commit()

# เพิ่ม route สำหรับ login
@app.route('/api/login', methods=['POST'])
def login():
    try:
        print("=" * 50)
        print("LOGIN REQUEST RECEIVED")
        print("=" * 50)
        print(f"Method: {request.method}")
        print(f"URL: {request.url}")
        print(f"Content-Type: {request.content_type}")
        print(f"Content-Length: {request.content_length}")
        print(f"Headers: {dict(request.headers)}")
        
        # ตรวจสอบ Content-Type
        if request.content_type and 'application/json' not in request.content_type:
            print(f"ERROR: Invalid content type: {request.content_type}")
            return jsonify({"msg": "Content-Type must be application/json"}), 400

        # ตรวจสอบว่าเป็น JSON หรือไม่
        if not request.is_json:
            print("ERROR: Request is not JSON")
            # ลองอ่าน raw data
            raw_data = request.get_data(as_text=True)
            print(f"Raw data: {raw_data}")
            return jsonify({"msg": "Missing JSON in request"}), 400

        data = request.get_json()
        print(f"SUCCESS: Received JSON data: {data}")
        print(f"Data type: {type(data)}")
        
        if not data:
            print("ERROR: No data received")
            return jsonify({"msg": "Missing JSON data"}), 400

        # รองรับหลายรูปแบบของ PIN
        pin = None
        print(f"Checking for pin in data keys: {list(data.keys())}")
        
        if 'pin' in data:
            pin = data['pin']
            print(f"Found 'pin' field: {pin}")
        elif 'username' in data:
            pin = data['username']
            print(f"Found 'username' field: {pin}")
        elif 'password' in data:
            pin = data['password']
            print(f"Found 'password' field: {pin}")
        elif 'email' in data:
            pin = data['email']
            print(f"Found 'email' field: {pin}")
        else:
            print(f"ERROR: No valid field found. Available fields: {list(data.keys())}")
            return jsonify({"msg": "Missing PIN/username/password/email field"}), 400

        if not pin:
            print("ERROR: PIN is empty or None")
            return jsonify({"msg": "Missing PIN/username/password"}), 400

        # แปลง PIN เป็น string
        pin = str(pin).strip()
        print(f"LOGIN: Login attempt with PIN: '{pin}' (length: {len(pin)})")

        # ตรวจสอบว่ามีตาราง users หรือไม่
        try:
            user = User.query.filter_by(pin=pin).first()
            print(f"USER: User found: {user}")
            if user:
                print(f"   - ID: {user.id}")
                print(f"   - Name: {user.name}")
                print(f"   - Role: {user.role}")
                print(f"   - Active: {user.is_active}")
        except Exception as db_error:
            print(f"ERROR: Database error: {db_error}")
            return jsonify({"msg": "Database connection error"}), 500

        if not user:
            print(f"ERROR: No user found with PIN: {pin}")
            return jsonify({"msg": "Invalid PIN - User not found"}), 401
        
        if not user.check_pin(pin):
            print(f"ERROR: PIN check failed for user: {user.name}")
            return jsonify({"msg": "Invalid PIN - User inactive or PIN mismatch"}), 401

        access_token = create_access_token(identity={
            'pin': user.pin,
            'role': user.role,
            'name': user.name
        })
        
        print(f"SUCCESS: Login successful for user: {user.name} (PIN: {user.pin})")
        print("=" * 50)
        
        return jsonify({
            "access_token": access_token,
            "user": {
                "name": user.name,
                "role": user.role
            }
        }), 200
        
    except Exception as e:
        print(f"ERROR: Login error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({"msg": "Internal server error", "error": str(e)}), 500

# เพิ่ม route สำหรับ logout
@app.route('/api/logout', methods=['POST'])
def logout():
    try:
        # ในระบบ JWT ไม่จำเป็นต้องทำอะไรกับ token เพราะ client จะลบ token เอง
        # แต่เราสามารถเพิ่ม token ลงใน blacklist ได้ถ้าต้องการ
        return jsonify({"msg": "Logout successful"}), 200
    except Exception as e:
        print(f"Logout error: {str(e)}")
        return jsonify({"msg": "Logout error"}), 500

# เพิ่ม route สำหรับตรวจสอบ token
@app.route('/api/protected', methods=['GET'])
@jwt_required()
def protected():
    try:
        current_user = get_jwt_identity()
        print(f"Protected route accessed by: {current_user}")
        return jsonify(logged_in_as=current_user), 200
    except Exception as e:
        print(f"JWT validation error: {str(e)}")
        return jsonify({"error": "Invalid token"}), 422

# เพิ่ม route สำหรับตรวจสอบสถานะการล็อกอิน
@app.route('/api/auth/status', methods=['GET'])
def auth_status():
    try:
        # ตรวจสอบว่ามี Authorization header หรือไม่
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({"authenticated": False, "message": "No token provided"}), 401
        
        # ลบ "Bearer " ออกจาก token
        if not auth_header.startswith('Bearer '):
            return jsonify({"authenticated": False, "message": "Invalid token format"}), 401
        
        token = auth_header.replace('Bearer ', '')
        
        # ตรวจสอบ token โดยใช้ JWT
        try:
            current_user = get_jwt_identity()
            return jsonify({
                "authenticated": True,
                "user": current_user
            }), 200
        except Exception as jwt_error:
            print(f"JWT validation error: {str(jwt_error)}")
            return jsonify({"authenticated": False, "message": "Invalid token"}), 401
        
    except Exception as e:
        print(f"Auth status error: {str(e)}")
        return jsonify({"authenticated": False, "message": "Server error"}), 500

@app.route('/api/data')
@cache.cached(timeout=60) 
def get_data():
    try:
        # Use SQLAlchemy to query tickets
        tickets = Ticket.query.order_by(Ticket.created_at.desc()).limit(1000).all()
        
        result = [
            {
                "Ticket ID": ticket.ticket_id,
                "อีเมล": ticket.email,
                "ชื่อ": ticket.name,
                "เบอร์ติดต่อ": ticket.phone,
                "แผนก": ticket.department,
                "วันที่แจ้ง": ticket.created_at.isoformat() if ticket.created_at else "",
                "สถานะ": ticket.status,
                "Appointment": ticket.appointment,
                "Requested": ticket.requested,
                "Report": ticket.report,
                "Type": ticket.type,
                # Determine effective group from requested/report, ignore literal "None"
                # compute effective group and expose in common key variants
                **(lambda eg: {"Group": eg, "group": eg, "GROUP": eg})(
                    ticket.requested if (ticket.requested and str(ticket.requested).lower() != "none") else (
                        ticket.report if (ticket.report and str(ticket.report).lower() != "none") else None
                    )
                ),
                "Subgroup": ticket.subgroup
            }
            for ticket in tickets
        ]
        
        return jsonify(result)
        
    except Exception as e:
        print(f"ERROR: Unexpected error in get_data: {str(e)}")
        return jsonify({
            "error": "Internal server error",
            "message": str(e)
        }), 500

# ---------- New endpoint for dashboard appointments ----------
@app.route('/api/appointments')
@cache.cached(timeout=60)
def get_appointments():
    """Return tickets where name, appointment and requested are all present."""
    try:
        tickets = Ticket.query.filter(
            Ticket.name.isnot(None), Ticket.name != '',
            Ticket.appointment.isnot(None), Ticket.appointment != '',
            Ticket.requested.isnot(None), Ticket.requested != ''
        ).order_by(Ticket.created_at.desc()).limit(1000).all()

        result = [
            {
                "name": ticket.name,
                "appointment": ticket.appointment,
                "requested": ticket.requested
            }
            for ticket in tickets
        ]
        return jsonify(result)
    except Exception as e:
        print(f"ERROR: get_appointments: {e}")
        return jsonify({"error": str(e)}), 500

@app.route('/update-status', methods=['POST'])
def update_status():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    ticket_id = data.get("ticket_id")
    new_status = data.get("status")

    if not ticket_id or not new_status:
        return jsonify({"error": "ticket_id and status required"}), 400

    try:
        # Update PostgreSQL using SQLAlchemy
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
            
        current_status = ticket.status

        # Only proceed if status is actually changing
        if current_status != new_status:
            # Update status
            ticket.status = new_status
            ticket.subgroup = data.get('subgroup', ticket.subgroup)

            # Determine who performed the change (either supplied in payload or from JWT token)
            actor = data.get("changed_by")
            if not actor:
                try:
                    current_user = get_jwt_identity()  # may fail if no valid JWT context
                    if isinstance(current_user, dict):
                        actor = current_user.get("name") or current_user.get("pin")
                    else:
                        actor = str(current_user)
                except Exception:
                    actor = "admin"

            # Create a log entry for this status change
            log_entry = TicketStatusLog(
                ticket_id=ticket.ticket_id,
                old_status=current_status,
                new_status=new_status,
                changed_by=actor,
                changed_at=datetime.utcnow()
            )
            db.session.add(log_entry)

            # Create notification
            notification = Notification()
            notification.message = f"Ticket #{ticket_id} ({ticket.name}) changed from {current_status} to {new_status}"
            db.session.add(notification)

            # Commit all changes in a single transaction
            db.session.commit()
            
            # Send LINE notification if user_id exists
            if ticket.user_id:
                payload = {
                    'ticket_id': ticket.ticket_id,
                    'user_id': ticket.user_id,
                    'status': new_status,
                    'email': ticket.email,
                    'name': ticket.name,
                    'phone': ticket.phone,
                    'department': ticket.department,
                    'created_at': ticket.created_at.isoformat() if ticket.created_at else None,
                    'appointment': ticket.appointment,
                    'requested': ticket.requested,
                    'report': ticket.report,
                    'type': ticket.type,
                    'textbox': ticket.textbox,
                }
                notify_user(payload)
                    
            return jsonify({"message": "Status updated in PostgreSQL"})
        else:
            return jsonify({"message": "Status unchanged"})
            
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/delete-ticket', methods=['POST'])
def delete_ticket():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    ticket_id = data.get('ticket_id')

    if not ticket_id:
        return jsonify({"error": "Ticket ID is required"}), 400

    try:
        # 1. ลบข้อความที่เกี่ยวข้อง
        Message.query.filter_by(user_id=ticket_id).delete()
        
        # 2. ลบ ticket จาก PostgreSQL
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            return jsonify({"error": "Ticket not found in database"}), 404
        
        db.session.delete(ticket)
        
        # 3. สร้าง notification
        notification = Notification()
        notification.message = f"Ticket {ticket_id} has been deleted"
        db.session.add(notification)
        
        db.session.commit()

        return jsonify({
            "success": True, 
            "message": "Ticket deleted from PostgreSQL"
        })

    except Exception as e:
        db.session.rollback()
        print(f"Error deleting ticket: {str(e)}")
        return jsonify({
            "error": "Failed to delete ticket",
            "details": str(e)
        }), 500

@app.route('/auto-clear-textbox', methods=['POST'])
def auto_clear_textbox():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    ticket_id = data.get('ticket_id')

    if not ticket_id:
        return jsonify({"error": "Ticket ID is required"}), 400

    try:
        # เชื่อมต่อกับฐานข้อมูล using SQLAlchemy
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404

        # ลบข้อมูลในตาราง tickets
        ticket.textbox = ''
        db.session.commit()

        return jsonify({"success": True, "message": "Textbox cleared automatically"})

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/clear-textboxes', methods=['POST'])
def clear_textboxes():
    try:
        # 1. ค้นหา tickets ที่มี textbox ไม่ว่าง using SQLAlchemy
        tickets_with_textbox = Ticket.query.filter(
            Ticket.textbox.isnot(None), 
            Ticket.textbox != ''
        ).all()

        # 2. ลบ textbox ใน PostgreSQL
        for ticket in tickets_with_textbox:
            ticket.textbox = ''
        db.session.commit()

        return jsonify({
            "success": True,
            "cleared_count": len(tickets_with_textbox),
            "message": f"Cleared {len(tickets_with_textbox)} textboxes"
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/refresh-messages', methods=['POST'])
def refresh_messages():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    ticket_id = data.get('ticket_id')
    admin_id = data.get('admin_id')

    if not ticket_id:
        return jsonify({"error": "Ticket ID is required"}), 400

    try:
        # ดึงข้อความล่าสุด using SQLAlchemy
        messages = Message.query.filter_by(user_id=ticket_id).order_by(Message.timestamp.asc()).all()
        
        result = []
        for message in messages:
            result.append({
                "id": message.id,
                "user_id": message.user_id,
                "admin_id": message.admin_id,
                "sender_type": message.sender_type,
                "message": message.message,
                "timestamp": message.timestamp.isoformat()
            })
        
        # No marking as read, just return the result
        return jsonify({"messages": result, "success": True})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/update-textbox', methods=['POST', 'OPTIONS'])
def update_textbox():
    if request.method == 'OPTIONS':
        return '', 200

    if request.content_type != 'application/json':
        return jsonify({"error": "Content-Type must be application/json"}), 415

    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
        
    ticket_id = data.get("ticket_id")
    new_text = data.get("textbox")
    is_announcement = data.get("is_announcement", False)
    admin_id = data.get("admin_id")
    sender_type = data.get("sender_type", "Admin"),
    

    if not ticket_id or new_text is None:
        return jsonify({"error": "ticket_id and text required"}), 400

    try:
        # Update PostgreSQL using SQLAlchemy
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
            
        current_text = ticket.textbox
        
        # Only proceed if text is actually changing
        if current_text != new_text:
            # บันทึกข้อความลงในตาราง messages ก่อน
            new_message = Message()
            new_message.user_id = ticket_id
            new_message.admin_id = admin_id
            new_message.sender_type = sender_type
            new_message.message = new_text
            db.session.add(new_message)
            
            # Update textbox ในตาราง tickets
            ticket.textbox = new_text
            
            # Create notification (ไม่สร้าง notification สำหรับประกาศ)
            if not is_announcement:
                notification = Notification()
                notification.message = f"New message for ticket {ticket_id} ({ticket.name}): {new_text}"
                db.session.add(notification)
            
            # Send LINE message if user_id exists
            if ticket.user_id and not is_announcement:
                send_textbox_message(ticket.user_id, new_text)
                
            db.session.commit()
            
        return jsonify({"message": "Message saved and textbox updated in PostgreSQL"})
        
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/email-rankings')
def get_email_rankings():
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, 
            host=DB_HOST, port=DB_PORT
        )
        cur = conn.cursor()
        
        # Query to get top 5 emails by ticket count
        cur.execute("""
            SELECT email, COUNT(*) as ticket_count
            FROM tickets
            WHERE email IS NOT NULL AND email != ''
            GROUP BY email
            ORDER BY ticket_count DESC
            LIMIT 5
        """)
        
        rankings = [
            {"email": row[0], "count": row[1]}
            for row in cur.fetchall()
        ]
        
        return jsonify(rankings)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/send-announcement', methods=['POST'])
def send_announcement():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    
    message = data.get('message')
    if not message:
        return jsonify({"error": "Message is required"}), 400

    try:
        # ดึง user_id ที่ type == 'Information' จาก tickets
        users = (
            db.session.query(Ticket.user_id, Ticket.name)
            .filter(Ticket.type == 'Information')
            .distinct()
            .all()
        )
        recipient_count = 0

        for user in users:
            user_id = user.user_id
            if user_id:
                if send_announcement_message(user_id, message, user.name):
                    recipient_count += 1

        # Create notification
        notification = Notification()
        notification.message = f"New announcement: {message}"
        notification.read = False
        db.session.add(notification)
        db.session.commit()

        return jsonify({
            "success": True,
            "recipient_count": recipient_count,
            "message": "Announcement sent successfully"
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

def send_announcement_message(user_id, message, recipient_name=None):
    url = "https://api.line.me/v2/bot/message/push"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LINE_ACCESS_TOKEN}"
    }

    # สร้าง Flex Message สำหรับประกาศ
    payload = {
        "to": user_id,
        "messages": [
            {
                "type": "flex",
                "altText": "ประกาศจากระบบ",
                "contents": {
                    "type": "bubble",
                    "size": "giga",
                    "header": {
                        "type": "box",
                        "layout": "vertical",
                        "contents": [
                            {
                                "type": "text",
                                "text": "📢 ประกาศจากระบบ",
                                "weight": "bold",
                                "size": "lg",
                                "color": "#FFFFFF",
                                "align": "center"
                            }
                        ],
                        "backgroundColor": "#FF6B6B",  # สีแดงสำหรับประกาศ
                        "paddingAll": "20px"
                    },
                    "body": {
                        "type": "box",
                        "layout": "vertical",
                        "contents": [
                            {
                                "type": "text",
                                "text": message,
                                "wrap": True,
                                "margin": "md"
                            },
                            {
                                "type": "separator",
                                "margin": "md"
                            },
                            {
                                "type": "text",
                                "text": "นี่คือข้อความประกาศจากระบบ กรุณาอ่านให้ละเอียด",
                                "size": "sm",
                                "color": "#888888",
                                "margin": "md",
                                "wrap": True
                            }
                        ],
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
        ]
    }

    try:
        response = requests.post(url, headers=headers, json=payload)
        if response.status_code != 200:
            print(f"LINE API Error: {response.status_code} - {response.text}")
        return response.status_code == 200
    except Exception as e:
        print(f"Error sending LINE announcement: {str(e)}")
        return False

@app.route('/delete-notification', methods=['POST'])
def delete_notification():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    
    notification_id = data.get('id')
    
    if not notification_id:
        return jsonify({"error": "Notification ID required"}), 400
    
    conn = psycopg2.connect(
        dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, host=DB_HOST, port=DB_PORT
    )
    cur = conn.cursor()
    cur.execute("DELETE FROM notifications WHERE id = %s", (notification_id,))
    conn.commit()
    conn.close()
    
    return jsonify({"success": True})

@app.route('/health')
def health_check():
    return jsonify({"status": "healthy", "timestamp": datetime.now().isoformat()})

@app.route('/update-ticket', methods=['POST', 'OPTIONS'])
def update_ticket():
    if request.method == 'OPTIONS':
        return '', 200  # สำหรับ CORS preflight

    if request.content_type != 'application/json':
        return jsonify({"error": "Content-Type must be application/json"}), 415

    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    
    ticket_id = data.get("ticket_id")
    if not ticket_id:
        return jsonify({"error": "ticket_id is required"}), 400
    # This check is redundant since we've added 'subgroup' to editable_fields
    # and it will be handled in the loop below
    try:
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404

        # เก็บสถานะเดิมไว้เพื่อตรวจสอบหลังอัปเดต
        previous_status = ticket.status

        # รายชื่อ field ที่อนุญาตให้แก้ไข (ยกเว้น ticket_id)
        editable_fields = [
            'user_id', 'email', 'name', 'phone', 'department', 'created_at',
            'status', 'appointment', 'requested', 'report', 'type', 'textbox', 'subgroup'
        ]
        updated_fields = []
        for field in editable_fields:
            # Skip if the field isn't provided or the new value is None (to avoid unintended blanking)
            if field not in data or data[field] is None:
                continue
            if getattr(ticket, field) != data[field]:
                setattr(ticket, field, data[field])
                updated_fields.append(field)

        # ---------------- Specific business rules for Service / Helpdesk ----------------
        # Normalise the type value (case-insensitive) and map to canonical Title-case for storage
        raw_type_val = (data.get('type') or ticket.type or '').strip()
        type_upper = raw_type_val.upper()
        canonical_type = None  # Will be 'Service' / 'Helpdesk' when recognised
        if type_upper == 'SERVICE':
            canonical_type = 'Service'
        elif type_upper == 'HELPDESK':
            canonical_type = 'Helpdesk'

        # Take provided group/subgroup values (may be None)
        group_val = data.get('group')
        subgroup_val = data.get('subgroup')

        # Process only for recognised ticket types
        if canonical_type:
            # Example mappings – replace with the organisation's real mappings as needed

            # Example mappings – replace with the organisation's real mappings as needed
            # Define allowed SERVICE groups here; leave empty set to disable strict check
            SERVICE_GROUPS: set[str] = set()
            # Define allowed HELPDESK group->subgroup mapping here; leave empty dict to disable strict check
            HELPDESK_GROUPS: dict[str, set[str]] = {}

            if type_upper == 'SERVICE':
                # Determine current group and subgroup (SERVICE keeps group in `requested`)
                group_effective = group_val or ticket.requested
                subgroup_effective = subgroup_val or ticket.subgroup

                # Require both group and subgroup if the caller is explicitly trying to modify them
                if (group_val is not None and not group_effective) or (subgroup_val is not None and not subgroup_effective):
                    return jsonify({"error": "group and subgroup are required for SERVICE type"}), 400

                if SERVICE_GROUPS and group_effective not in SERVICE_GROUPS:
                    return jsonify({"error": "Invalid group for SERVICE type"}), 400

                # Update group (stored in requested column)
                if group_val is not None and ticket.requested != group_val:
                    ticket.requested = group_val
                    if 'requested' not in updated_fields:
                        updated_fields.append('requested')

                # Update subgroup (stored in dedicated column)
                if subgroup_val is not None and ticket.subgroup != subgroup_val:
                    ticket.subgroup = subgroup_val
                    if 'subgroup' not in updated_fields:
                        updated_fields.append('subgroup')

                # Clear report column (not used for SERVICE)
                if ticket.report is not None:
                    ticket.report = None
                    if 'report' not in updated_fields:
                        updated_fields.append('report')

            else:  # HELPDESK
                # HELPDESK requires both group and subgroup and clears requested
                # Fallback to existing values when not provided
                group_effective = group_val or ticket.report
                subgroup_effective = subgroup_val or ticket.subgroup
                # Only raise error if caller attempts to modify and omitted required fields
                if (group_val is not None and not group_effective) or (subgroup_val is not None and not subgroup_effective):
                    return jsonify({"error": "group and subgroup are required for HELPDESK type"}), 400
                if HELPDESK_GROUPS and (group_effective not in HELPDESK_GROUPS or subgroup_effective not in HELPDESK_GROUPS[group_effective]):
                    return jsonify({"error": "Invalid group/subgroup for HELPDESK type"}), 400

                if group_val is not None and ticket.report != group_val:
                    ticket.report = group_val
                    if 'report' not in updated_fields:
                        updated_fields.append('report')
                if ticket.requested is not None:
                    ticket.requested = None
                    if 'requested' not in updated_fields:
                        updated_fields.append('requested')
                if subgroup_val is not None and ticket.subgroup != subgroup_val:
                    ticket.subgroup = subgroup_val
                    if 'subgroup' not in updated_fields:
                        updated_fields.append('subgroup')

            # Finally update the type field itself if changed to canonical value
            if canonical_type and ticket.type != canonical_type:
                ticket.type = canonical_type
                if 'type' not in updated_fields:
                    updated_fields.append('type')

        # หากสถานะมีการเปลี่ยนแปลง (ไม่นับ Cancelled ที่จะลบ)
        if 'status' in updated_fields and ticket.status != previous_status and data.get('status') != 'Cancelled':
            # หาผู้กระทำ
            actor = data.get('changed_by')
            if not actor:
                try:
                    current_user = get_jwt_identity()
                    if isinstance(current_user, dict):
                        actor = current_user.get('name') or current_user.get('pin')
                    else:
                        actor = str(current_user)
                except Exception:
                    actor = 'admin'

            # บันทึก log การเปลี่ยนสถานะ
            log_entry = TicketStatusLog(
                ticket_id=ticket.ticket_id,
                old_status=previous_status,
                new_status=ticket.status,
                changed_by=actor,
                changed_at=datetime.utcnow()
            )
            db.session.add(log_entry)

            # สร้าง Notification ภายในระบบ
            notification = Notification(message=f"Ticket #{ticket_id} ({ticket.name}) changed from {previous_status} to {ticket.status}")
            db.session.add(notification)

        # ถ้า status ใหม่เป็น Cancelled ให้ลบ ticket และ message ที่เกี่ยวข้องทันที
        if 'status' in data and data['status'] == 'Cancelled':
            # ลบ message ที่เกี่ยวข้อง
            Message.query.filter_by(user_id=ticket_id).delete()
            db.session.delete(ticket)
            # สร้าง notification
            notification = Notification()
            notification.message = f"Ticket {ticket_id} has been cancelled and deleted."
            db.session.add(notification)
            db.session.commit()
            return jsonify({
                "success": True,
                "message": "Ticket cancelled and deleted successfully"
            })

        db.session.commit()

        # เคลียร์ cache ของ /api/data เพื่อให้ frontend เห็นข้อมูลล่าสุดทันที
        try:
            cache.delete_memoized(get_data)
        except Exception:
            pass  # ไม่ขัดขวาง flow หลัก หากล้าง cache ล้มเหลว

        # ส่งแจ้งเตือน LINE เฉพาะเมื่อสถานะมีการเปลี่ยนแปลงจริง (ไม่ใช่ Cancelled) และ ticket มี user_id
        if 'status' in updated_fields and ticket.user_id and ticket.status != previous_status and ticket.status != 'Cancelled':
            payload = {
                'ticket_id': ticket.ticket_id,
                'user_id': ticket.user_id,
                'status': ticket.status,
                'email': ticket.email,
                'name': ticket.name,
                'phone': ticket.phone,
                'department': ticket.department,
                'created_at': ticket.created_at.isoformat() if ticket.created_at else None,
                'appointment': ticket.appointment,
                'requested': ticket.requested,
                'report': ticket.report,
                'type': ticket.type,
                'textbox': ticket.textbox,
                'subgroup': ticket.subgroup,
            }
            notify_user(payload)

        return jsonify({
            "success": True,
            "message": "Ticket updated successfully",
            "updated_fields": updated_fields
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/data-by-date', methods=['GET'])
def get_data_by_date():
    date_str = request.args.get('date')
    
    if not date_str:
        return jsonify({"error": "Date parameter is required"}), 400
    
    try:
        # แปลงวันที่เป็นรูปแบบที่ PostgreSQL เข้าใจ
        selected_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        
        # กำหนดช่วงเวลาเป็นทั้งวัน (00:00:00 - 23:59:59)
        start_datetime = datetime.combine(selected_date, datetime.min.time())
        end_datetime = datetime.combine(selected_date, datetime.max.time())
        
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, 
            host=DB_HOST, port=DB_PORT
        )
        cur = conn.cursor()
        
        # คิวรี่ข้อมูลโดยใช้ created_at
        cur.execute("""
            SELECT ticket_id, email, name, phone, department, 
                   created_at, status, appointment, 
                   requested, report, type, textbox 
            FROM tickets 
            WHERE created_at BETWEEN %s AND %s
            ORDER BY created_at DESC
        """, (start_datetime, end_datetime))
        
        rows = cur.fetchall()
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
        if not rows:
            return jsonify({"message": "No data found for the selected date", "data": []})
        return jsonify(result)
    
    except ValueError:
        return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        if 'conn' in locals():
            conn.close()

@app.route('/api/messages', methods=['GET'])
def get_messages():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"error": "user_id is required"}), 400
    messages = Message.query.filter_by(user_id=user_id).order_by(Message.timestamp.asc()).all()
    result = [
        {
            "id": m.id,
            "user_id": m.user_id,
            "admin_id": m.admin_id,
            "sender_type": m.sender_type,
            "message": m.message,
            "timestamp": m.timestamp.isoformat()
        }
        for m in messages
    ]
    return jsonify(result)

@app.route('/api/messages', methods=['POST'])
def send_message():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    user_id = data.get('user_id')
    admin_id = data.get('admin_id')
    sender_type = data.get('sender_type')
    message = data.get('message')
    if not user_id or not sender_type or not message:
        return jsonify({"error": "user_id, sender_type, and message are required"}), 400
    if sender_type not in ['user', 'admin']:
        return jsonify({"error": "sender_type must be 'user' or 'admin'"}), 400
    msg = Message()
    msg.user_id = user_id
    msg.admin_id = admin_id
    msg.sender_type = sender_type
    msg.message = message
    # กำหนด timestamp เป็นเวลาปัจจุบัน (UTC) เสมอ
    msg.timestamp = datetime.utcnow()
    db.session.add(msg)
    db.session.commit()
    # ถ้าเป็น admin ส่งข้อความ ให้ push ข้อความไป LINE user ด้วย
    if sender_type == 'admin':
        send_textbox_message(user_id, message)
    return jsonify({
        "id": msg.id,
        "user_id": msg.user_id,
        "admin_id": msg.admin_id,
        "sender_type": msg.sender_type,
        "message": msg.message,
        "timestamp": msg.timestamp.isoformat(),
        "success": True
    })

@app.route('/api/status')
def system_status():
    try:
        # ตรวจสอบการเชื่อมต่อฐานข้อมูล
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, 
            host=DB_HOST, port=DB_PORT
        )
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM tickets")
        result = cur.fetchone()
        ticket_count = result[0] if result else 0
        conn.close()
        
        return jsonify({
            "status": "healthy",
            "database": "connected",
            "ticket_count": ticket_count,
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            "status": "error",
            "database": "disconnected",
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }), 500

@app.route('/api/init-users')
def init_users():
    try:
        with app.app_context():
            # สร้างตารางทั้งหมด
            db.create_all()
            
            # สร้างผู้ใช้เริ่มต้นถ้ายังไม่มี
            if not User.query.filter_by(pin='123456').first():
                admin = User()
                admin.pin = '123456'
                admin.role = 'admin'
                admin.name = 'ผู้ดูแลระบบ'
                db.session.add(admin)
                print("Created admin user with PIN: 123456")
            
            if not User.query.filter_by(pin='000000').first():
                user = User()
                user.pin = '000000'
                user.role = 'user'
                user.name = 'ผู้ใช้ทั่วไป'
                db.session.add(user)
                print("Created regular user with PIN: 000000")
            
            db.session.commit()
            
            # ดึงรายชื่อผู้ใช้ทั้งหมด
            users = User.query.all()
            user_list = []
            for user in users:
                user_list.append({
                    "id": user.id,
                    "pin": user.pin,
                    "name": user.name,
                    "role": user.role,
                    "is_active": user.is_active
                })
            
            return jsonify({
                "success": True,
                "message": "Users initialized successfully",
                "users": user_list
            })
            
    except Exception as e:
        print(f"Error initializing users: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

@app.route('/api/test-db')
def test_database():
    try:
        # ทดสอบการเชื่อมต่อ PostgreSQL
        conn = psycopg2.connect(
            dbname=DB_NAME, user=DB_USER, password=DB_PASSWORD, 
            host=DB_HOST, port=DB_PORT
        )
        cur = conn.cursor()
        
        # ตรวจสอบว่าตาราง users มีอยู่หรือไม่
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'users'
            );
        """)
        result = cur.fetchone()
        users_table_exists = result[0] if result else False
        
        # ตรวจสอบว่าตาราง tickets มีอยู่หรือไม่
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'tickets'
            );
        """)
        result = cur.fetchone()
        tickets_table_exists = result[0] if result else False
        
        # นับจำนวนผู้ใช้
        user_count = 0
        if users_table_exists:
            cur.execute("SELECT COUNT(*) FROM users")
            result = cur.fetchone()
            user_count = result[0] if result else 0
        
        # นับจำนวน tickets
        ticket_count = 0
        if tickets_table_exists:
            cur.execute("SELECT COUNT(*) FROM tickets")
            result = cur.fetchone()
            ticket_count = result[0] if result else 0
        
        conn.close()
        
        return jsonify({
            "success": True,
            "database_connected": True,
            "users_table_exists": users_table_exists,
            "tickets_table_exists": tickets_table_exists,
            "user_count": user_count,
            "ticket_count": ticket_count
        })
        
    except Exception as e:
        print(f"Database test error: {str(e)}")
        return jsonify({
            "success": False,
            "database_connected": False,
            "error": str(e)
        }), 500

@app.route('/api/reset-users')
def reset_users():
    try:
        with app.app_context():
            # ลบผู้ใช้เก่าทั้งหมด
            User.query.delete()
            db.session.commit()
            print("Deleted all existing users")
            
            # สร้างผู้ใช้ใหม่
            admin = User()
            admin.pin = '123456'
            admin.role = 'admin'
            admin.name = 'ผู้ดูแลระบบ'
            db.session.add(admin)
            print("Created admin user with PIN: 123456")
            
            user = User()
            user.pin = '000000'
            user.role = 'user'
            user.name = 'ผู้ใช้ทั่วไป'
            db.session.add(user)
            print("Created regular user with PIN: 000000")
            
            db.session.commit()
            
            # ดึงรายชื่อผู้ใช้ทั้งหมด
            users = User.query.all()
            user_list = []
            for user in users:
                user_list.append({
                    "id": user.id,
                    "pin": user.pin,
                    "name": user.name,
                    "role": user.role,
                    "is_active": user.is_active
                })
            
            return jsonify({
                "success": True,
                "message": "Users reset successfully",
                "users": user_list
            })
            
    except Exception as e:
        print(f"Error resetting users: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

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

@app.route('/api/chat-users', methods=['GET'])
def get_chat_users():
    # ดึงผู้ใช้ที่มี type == 'Information' จากตาราง tickets
    users = (
        db.session.query(Ticket.user_id, Ticket.name)
        .filter(Ticket.type == 'Information')
        .distinct()
        .all()
    )
    result = [
        {
            'user_id': user.user_id,
            'name': user.name
        }
        for user in users if user.user_id
    ]
    return jsonify(result)

@app.route('/api/messages/delete', methods=['POST', 'OPTIONS'])
def delete_chat_history():
    if request.method == 'OPTIONS':
        return '', 200
    data = request.get_json()
    if not data or not data.get('user_id'):
        return jsonify({"error": "user_id is required"}), 400
    user_id = data['user_id']
    try:
        Message.query.filter_by(user_id=user_id).delete()
        db.session.commit()
        return jsonify({"success": True, "message": "Messages deleted successfully"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# --- API: Log Status Change ---
from sqlalchemy import Index

@app.route('/api/log-status-change', methods=['POST'])
def log_status_change():
    data = request.get_json()
    required_fields = ['ticket_id', 'old_status', 'new_status', 'changed_by', 'changed_at']
    missing = [f for f in required_fields if not data or not data.get(f)]
    if missing:
        return jsonify({'error': f'Missing fields: {", ".join(missing)}'}), 400
    if data['old_status'] == data['new_status']:
        return jsonify({'error': 'new_status must be different from old_status'}), 400
    # Validate ticket exists
    ticket = Ticket.query.get(data['ticket_id'])
    if not ticket:
        return jsonify({'error': 'Ticket not found'}), 404
    try:
        # Parse timestamp
        ts = data['changed_at']
        if isinstance(ts, str):
            try:
                # Accept ISO8601 with or without 'Z' UTC designator
                if ts.endswith('Z'):
                    ts = ts[:-1] + '+00:00'  # convert Z to +00:00 for fromisoformat
                dt = datetime.fromisoformat(ts)
            except Exception:
                return jsonify({'error': 'Invalid timestamp format, must be ISO8601'}), 400
        else:
            return jsonify({'error': 'changed_at must be string'}), 400

        log = TicketStatusLog(
            ticket_id=data['ticket_id'],
            old_status=data['old_status'],
            new_status=data['new_status'],
            changed_by=data['changed_by'],
            changed_at=dt
        )
        db.session.add(log)
        db.session.commit()
        return jsonify({'success': True}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/log-status-change', methods=['GET'])
def get_status_logs():
    ticket_id = request.args.get('ticket_id')
    if ticket_id:
        logs = TicketStatusLog.query.filter_by(ticket_id=ticket_id).order_by(TicketStatusLog.changed_at.asc()).all()
    else:
        logs = TicketStatusLog.query.order_by(TicketStatusLog.changed_at.desc()).all()
    return jsonify([l.to_dict() for l in logs])

# Create index for ticket_id, change_timestamp for performance (if not exists)
Index('idx_ticket_status_logs_ticket_id_changed_at', TicketStatusLog.ticket_id, TicketStatusLog.changed_at)

from sqlalchemy import inspect

def create_ticket_status_logs_table():
    # For manual migration support
    with app.app_context():
        inspector = inspect(db.engine)
        if not inspector.has_table('ticket_status_logs'):
            db.create_all()

if __name__ == '__main__':
    with app.app_context():
        create_tickets_table()
        create_ticket_status_logs_table()
    app.run(host='0.0.0.0', port=5001, debug=False)