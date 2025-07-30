from flask import Flask, jsonify, request
import requests
from flask_cors import CORS 
import psycopg2
import uuid
import json
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
from sqlalchemy import desc

LINE_ACCESS_TOKEN = "O02yXH2dlIyu9da3bJPfhtHTZYkDJR/wy1TnWj5ZAgBUr0zfiNrY9mC3qm5nEWyILuI+rcVftmsvsQZp+AB8Hf6f5UmDosjtkQY0ufX+JrVwa3i+UwlAXa7UvBQ/JBef2pRD4wJ3QttJyLn1nfh1dQdB04t89/1O/w1cDnyilFU="

app = Flask(__name__)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})

app.config['JWT_SECRET_KEY'] = 'your-secret-key-here'  # ควรเปลี่ยนเป็นค่าที่ปลอดภัยใน production
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(hours=24)  # Token หมดอายุใน 24 ชั่วโมง
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
jwt = JWTManager(app)

# JWT Error Handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'error': 'Invalid token'}), 422

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'error': 'Authorization token is required'}), 401

@jwt.needs_fresh_token_loader
def token_not_fresh_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Fresh token required'}), 401

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({'error': 'Token has been revoked'}), 401

# แก้ไข CORS ให้รองรับทุก origin
CORS(app, origins=["*"], supports_credentials=True)

DB_NAME = 'neondb'
DB_USER = 'neondb_owner'
DB_PASSWORD = 'npg_EWHCa2rPg7wK'
DB_HOST = 'ep-dark-math-a1oavnp6-pooler.ap-southeast-1.aws.neon.tech'
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
    # Relationship to cascade delete messages when a ticket is removed
    messages = db.relationship('Message', backref='ticket', cascade='all, delete, delete-orphan', passive_deletes=True)
class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    sender_name = db.Column(db.String, nullable=True)  # เพิ่ม
    user_id = db.Column(db.String, nullable=True)      # เพิ่ม
    meta_data = db.Column(db.JSON, nullable=True)       # เปลี่ยนชื่อ field
    
    def __init__(self, message, read=False, sender_name=None, user_id=None, meta_data=None, **kwargs):
        super().__init__(**kwargs)
        self.message = message
        self.read = read
        self.sender_name = sender_name
        self.user_id = user_id
        self.meta_data = meta_data
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
            'read': self.read,
            'sender_name': self.sender_name,
            'user_id': self.user_id,
            'meta_data': self.meta_data,
        }

class Message(db.Model):
    __tablename__ = 'messages'
    id = db.Column(db.Integer, primary_key=True)
    ticket_id = db.Column(db.String, db.ForeignKey('tickets.ticket_id', ondelete='CASCADE'), nullable=False)
    user_id = db.Column(db.String, nullable=False)
    admin_id = db.Column(db.String, nullable=True)
    sender_type = db.Column(db.String, nullable=False)  # 'user' or 'admin', ป้องกัน null
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
    note = db.Column(db.Text)
    remarks = db.Column(db.Text)   
    
    def __init__(self, **kwargs):
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
            'changed_at_utc': self.changed_at.isoformat() if self.changed_at else None,
            'note': self.note,
            'remarks': self.remarks
        }

class User(db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=True)  # Username for login
    password_hash = db.Column(db.String(255), nullable=True)  # Hashed password
    email = db.Column(db.String(100), unique=True, nullable=True)  # Email address
    pin = db.Column(db.String(10), unique=True, nullable=False)  # รหัส PIN
    role = db.Column(db.String(20), default='user')  # 'user' หรือ 'admin'
    name = db.Column(db.String(100), nullable=False)  # ชื่อผู้ใช้
    is_active = db.Column(db.Boolean, default=True)  # สถานะการใช้งาน
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    failed_login_attempts = db.Column(db.Integer, default=0)
    account_locked_until = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    sessions = db.relationship('UserSession', backref='user', cascade='all, delete-orphan')
    activity_logs = db.relationship('UserActivityLog', backref='user', cascade='all, delete-orphan')

    def check_pin(self, pin):
        return self.pin == pin and self.is_active
    
    def check_password(self, password):
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def is_account_locked(self):
        if not self.account_locked_until:
            return False
        try:
            current_time = datetime.utcnow()
            locked_until = self.account_locked_until
            
            # Handle timezone-aware vs timezone-naive datetime comparison
            if locked_until.tzinfo is not None and current_time.tzinfo is None:
                current_time = current_time.replace(tzinfo=locked_until.tzinfo)
            elif locked_until.tzinfo is None and current_time.tzinfo is not None:
                locked_until = locked_until.replace(tzinfo=current_time.tzinfo)
            
            return current_time < locked_until
        except Exception as e:
            print(f"Error in is_account_locked: {str(e)}")
            return False
    
    def lock_account(self, duration_minutes=30):
        self.account_locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        db.session.commit()
    
    def unlock_account(self):
        self.account_locked_until = None
        self.failed_login_attempts = 0
        db.session.commit()
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'name': self.name,
            'role': self.role,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'is_locked': self.is_account_locked()
        }

class UserSession(db.Model):
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    session_token = db.Column(db.String(255), unique=True, nullable=False)
    pin_verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(45))  # IPv6 compatible
    user_agent = db.Column(db.Text)
    is_active = db.Column(db.Boolean, default=True)
    
    def is_expired(self):
        try:
            current_time = datetime.utcnow()
            expires_time = self.expires_at
            
            # Handle timezone-aware vs timezone-naive datetime comparison
            if expires_time.tzinfo is not None and current_time.tzinfo is None:
                # expires_at is timezone-aware, current_time is naive
                current_time = current_time.replace(tzinfo=expires_time.tzinfo)
            elif expires_time.tzinfo is None and current_time.tzinfo is not None:
                # expires_at is naive, current_time is timezone-aware
                expires_time = expires_time.replace(tzinfo=current_time.tzinfo)
            
            return current_time > expires_time
        except Exception as e:
            print(f"Error in is_expired: {str(e)}")
            # If there's an error, assume not expired for safety
            return False
    
    def extend_session(self, hours=24):
        self.expires_at = datetime.utcnow() + timedelta(hours=hours)
        self.last_activity = datetime.utcnow()
        db.session.commit()
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'pin_verified': self.pin_verified,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None,
            'is_active': self.is_active,
            'is_expired': self.is_expired()
        }

class UserActivityLog(db.Model):
    __tablename__ = 'user_activity_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    session_id = db.Column(db.Integer, db.ForeignKey('user_sessions.id'), nullable=True)
    action_type = db.Column(db.String(50), nullable=False)  # login, logout, pin_verify, create_ticket, etc.
    resource_type = db.Column(db.String(50), nullable=True)  # ticket, message, user, etc.
    resource_id = db.Column(db.String(100), nullable=True)  # ID of resource
    action_details = db.Column(db.JSON, nullable=True)  # Additional details
    ip_address = db.Column(db.String(45))
    user_agent = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    success = db.Column(db.Boolean, default=True)
    error_message = db.Column(db.Text)
    
    def get_thai_time(self):
        if self.created_at:
            return self.created_at.replace(tzinfo=timezone.utc).astimezone(timezone(timedelta(hours=7)))
        return None
    
    def to_dict(self):
        return {
            'id': self.id,
            'user_id': self.user_id,
            'session_id': self.session_id,
            'action_type': self.action_type,
            'resource_type': self.resource_type,
            'resource_id': self.resource_id,
            'action_details': self.action_details,
            'created_at': self.get_thai_time().isoformat() if self.created_at else None,
            'success': self.success,
            'error_message': self.error_message
        }

# Helper functions for activity logging and session management
def log_user_activity(user_id=None, session_id=None, action_type=None, resource_type=None, 
                     resource_id=None, action_details=None, success=True, error_message=None, 
                     ip_address=None, user_agent=None):
    """Log user activity for audit trail"""
    try:
        activity_log = UserActivityLog(
            user_id=user_id,
            session_id=session_id,
            action_type=action_type,
            resource_type=resource_type,
            resource_id=resource_id,
            action_details=action_details,
            success=success,
            error_message=error_message,
            ip_address=ip_address,
            user_agent=user_agent
        )
        db.session.add(activity_log)
        db.session.commit()
        return activity_log
    except Exception as e:
        print(f"Error logging activity: {str(e)}")
        db.session.rollback()
        return None

def get_user_from_token():
    """Get user from JWT token with new structure"""
    try:
        # get_jwt_identity() now returns user_id as string
        user_id = get_jwt_identity()
        if user_id:
            # Convert to int and get user
            user = User.query.get(int(user_id))
            return user
    except Exception as e:
        print(f"Error getting user from token: {str(e)}")
        pass
    return None

def get_session_from_token():
    """Get active session from JWT token with new structure"""
    try:
        from flask_jwt_extended import get_jwt
        
        # Get additional claims from JWT
        claims = get_jwt()
        session_token = claims.get('session_token')
        
        if session_token:
            session = UserSession.query.filter_by(
                session_token=session_token,
                is_active=True
            ).first()
            if session and not session.is_expired():
                return session
    except Exception as e:
        print(f"Error getting session from token: {str(e)}")
        pass
    return None

def require_pin_verification():
    """Decorator to require PIN verification after login"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            session = get_session_from_token()
            if not session or not session.pin_verified:
                return jsonify({'error': 'PIN verification required'}), 403
            return f(*args, **kwargs)
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

def get_client_info(request):
    """Extract client IP and User-Agent from request"""
    ip_address = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    if ip_address and ',' in ip_address:
        ip_address = ip_address.split(',')[0].strip()
    user_agent = request.headers.get('User-Agent', '')
    return ip_address, user_agent

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
    # ตรวจสอบและกำหนดค่าเริ่มต้นสำหรับฟิลด์ที่อาจเป็น None
    payload['report'] = payload.get('report') if payload.get('report') is not None else 'ไม่มีข้อมูล'
    payload['requested'] = payload.get('requested') if payload.get('requested') is not None else 'ไม่มีข้อมูล'
    payload['textbox'] = payload.get('textbox') if payload.get('textbox') is not None else 'ไม่มีข้อมูล'
    payload['subgroup'] = payload.get('subgroup') if payload.get('subgroup') is not None else 'ไม่มีข้อมูล'
    payload['note'] = payload.get('note', 'ไม่มีหมายเหตุเพิ่มเติม')
    # Log payload หลังจากแก้ไขแล้ว
    print(f"[notify_user] Final payload: {payload}")
    url = "https://api.line.me/v2/bot/message/push"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {LINE_ACCESS_TOKEN}"
    }
    flex_message = create_flex_message(payload)
    body = {
        "to": payload['user_id'],
        "messages": [flex_message]
    }
    response = requests.post(url, headers=headers, json=body)
    print(f"[notify_user] LINE API response: {response.status_code} {response.text}")
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
    print(f"[create_flex_message] payload type: {payload.get('type')}")
    ticket_type = (payload.get('type') or '').upper()
    if ticket_type == 'SERVICE':
        problem_text = payload.get('requested', 'ไม่มีข้อมูล')
    else:
        problem_text = payload.get('report', 'ไม่มีข้อมูล')
    if problem_text is None:
        problem_text = 'ไม่มีข้อมูล'
    note_text = payload.get('note', 'ไม่มีหมายเหตุเพิ่มเติม')
    flex_body = [
        {
            "type": "box",
            "layout": "horizontal",
            "contents": [
                {"type": "text", "text": "หมายเลข", "weight": "bold", "size": "sm", "flex": 2, "color": "#666666"},
                {"type": "text", "text": payload.get('ticket_id', ''), "size": "sm", "flex": 4, "align": "end"}
            ],
            "spacing": "sm",
            "margin": "md"
        },
        {"type": "separator", "margin": "md"},
        {
            "type": "box",
            "layout": "horizontal",
            "contents": [
                {"type": "text", "text": "ชื่อ", "weight": "bold", "size": "sm", "flex": 2, "color": "#666666"},
                {"type": "text", "text": payload.get('name', ''), "size": "sm", "flex": 4, "align": "end"}
            ],
            "spacing": "sm",
            "margin": "md"
        },
        {"type": "separator", "margin": "md"},
        {
            "type": "box",
            "layout": "horizontal",
            "contents": [
                {"type": "text", "text": "แผนก", "weight": "bold", "size": "sm", "flex": 2, "color": "#666666"},
                {"type": "text", "text": payload.get('department', ''), "size": "sm", "flex": 4, "align": "end"}
            ],
            "spacing": "sm",
            "margin": "md"
        },
        {"type": "separator", "margin": "md"},
        {
            "type": "box",
            "layout": "horizontal",
            "contents": [
                {"type": "text", "text": "เบอร์ติดต่อ", "weight": "bold", "size": "sm", "flex": 2, "color": "#666666"},
                {"type": "text", "text": payload.get('phone', ''), "size": "sm", "flex": 4, "align": "end"}
            ],
            "spacing": "sm",
            "margin": "md"
        },
        {"type": "separator", "margin": "md"},
        {
            "type": "box",
            "layout": "horizontal",
            "contents": [
                {"type": "text", "text": "Type", "weight": "bold", "size": "sm", "flex": 2, "color": "#666666"},
                {"type": "text", "text": payload.get('type', ''), "size": "sm", "flex": 4, "align": "end"}
            ],
            "spacing": "sm",
            "margin": "md"
        },
        {"type": "separator", "margin": "md"},
        {
            "type": "box",
            "layout": "horizontal",
            "contents": [
                {"type": "text", "text": "ปัญหา", "weight": "bold", "size": "sm", "flex": 2, "color": "#666666"},
                {"type": "text", "text": problem_text, "size": "sm", "flex": 4, "align": "end", "wrap": True}
            ],
            "spacing": "sm",
            "margin": "md"
        },
        {"type": "separator", "margin": "md"},
        {
            "type": "box",
            "layout": "horizontal",
            "contents": [
                {"type": "text", "text": "วันที่นัดหมาย", "weight": "bold", "size": "sm", "flex": 2, "color": "#666666"},
                {"type": "text", "text": appointment_date, "size": "sm", "flex": 4, "align": "end"}
            ],
            "spacing": "sm",
            "margin": "md"
        },
        {
            "type": "box",
            "layout": "vertical",
            "contents": [
                {"type": "text", "text": "สถานะล่าสุด", "weight": "bold", "size": "sm", "color": "#666666", "margin": "md"},
                {"type": "text", "text": status, "weight": "bold", "size": "xl", "color": status_color, "align": "center", "margin": "sm"},
                {"type": "text", "text": "หมายเหตุ: " + note_text, "size": "sm", "color": "#64748b", "wrap": True, "margin": "md"}
            ],
            "backgroundColor": "#F5F5F5",
            "cornerRadius": "md",
            "margin": "xl",
            "paddingAll": "md"
        }
    ]
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
                "contents": flex_body,
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
    result = [n.to_dict() for n in notifications]
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

# ================= AUTHENTICATION APIs =================

@app.route('/api/register', methods=['POST'])
def register():
    """Register new user with username, password, email, and PIN"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Missing JSON data'}), 400
        
        # Validate required fields
        required_fields = ['username', 'password', 'email', 'pin', 'name']
        for field in required_fields:
            if field not in data or not data[field]:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        username = data['username'].strip()
        password = data['password']
        email = data['email'].strip().lower()
        pin = data['pin'].strip()
        name = data['name'].strip()
        role = data.get('role', 'user')  # Default to 'user' role
        
        # Validate input lengths and formats
        if len(username) < 3 or len(username) > 50:
            return jsonify({'error': 'Username must be between 3-50 characters'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        if len(pin) < 4 or len(pin) > 10:
            return jsonify({'error': 'PIN must be between 4-10 characters'}), 400
        
        if '@' not in email or len(email) > 100:
            return jsonify({'error': 'Invalid email format'}), 400
        
        # Check if username, email, or PIN already exists
        existing_user = User.query.filter(
            (User.username == username) | 
            (User.email == email) | 
            (User.pin == pin)
        ).first()
        
        if existing_user:
            if existing_user.username == username:
                return jsonify({'error': 'Username already exists'}), 409
            elif existing_user.email == email:
                return jsonify({'error': 'Email already exists'}), 409
            elif existing_user.pin == pin:
                return jsonify({'error': 'PIN already exists'}), 409
        
        # Create new user
        new_user = User(
            username=username,
            email=email,
            pin=pin,
            name=name,
            role=role,
            is_active=True
        )
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        # Log registration activity
        ip_address, user_agent = get_client_info(request)
        log_user_activity(
            user_id=new_user.id,
            action_type='register',
            action_details={
                'username': username,
                'email': email,
                'role': role
            },
            success=True,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return jsonify({
            'message': 'User registered successfully',
            'user': new_user.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed', 'details': str(e)}), 500

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

@app.route('/api/login', methods=['POST'])
def login():
    """Login with username/password only - all users must have accounts"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'Missing JSON data'}), 400
        
        ip_address, user_agent = get_client_info(request)
        
        # Require username and password for all users
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400
        
        user = User.query.filter_by(username=username).first()
        
        if not user:
            # Log failed login attempt
            log_user_activity(
                action_type='login_failed',
                action_details={'username': username, 'reason': 'user_not_found'},
                success=False,
                error_message='User not found',
                ip_address=ip_address,
                user_agent=user_agent
            )
            return jsonify({'error': 'Invalid username or password'}), 401
        
        # Check if account is locked
        if user.is_account_locked():
            log_user_activity(
                user_id=user.id,
                action_type='login_failed',
                action_details={'username': username, 'reason': 'account_locked'},
                success=False,
                error_message='Account locked',
                ip_address=ip_address,
                user_agent=user_agent
            )
            return jsonify({'error': 'Account is locked. Please try again later.'}), 423
        
        # Verify password
        if not user.check_password(password):
            # Increment failed login attempts
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= 5:
                user.lock_account(30)  # Lock for 30 minutes
                db.session.commit()
                
                log_user_activity(
                    user_id=user.id,
                    action_type='account_locked',
                    action_details={'username': username, 'failed_attempts': user.failed_login_attempts},
                    success=False,
                    error_message='Too many failed attempts',
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                return jsonify({'error': 'Account locked due to too many failed attempts'}), 423
            else:
                db.session.commit()
                log_user_activity(
                    user_id=user.id,
                    action_type='login_failed',
                    action_details={'username': username, 'reason': 'wrong_password', 'attempts': user.failed_login_attempts},
                    success=False,
                    error_message='Wrong password',
                    ip_address=ip_address,
                    user_agent=user_agent
                )
                return jsonify({'error': 'Invalid username or password'}), 401
        
        # Check if user is active
        if not user.is_active:
            log_user_activity(
                user_id=user.id,
                action_type='login_failed',
                action_details={'reason': 'account_inactive'},
                success=False,
                error_message='Account inactive',
                ip_address=ip_address,
                user_agent=user_agent
            )
            return jsonify({'error': 'Account is inactive'}), 403
        
        # Reset failed login attempts on successful login
        if user.failed_login_attempts > 0:
            user.failed_login_attempts = 0
            user.account_locked_until = None
        
        # Update last login time
        user.last_login = datetime.utcnow()
        
        # Create session
        session_token = str(uuid.uuid4())
        expires_at = datetime.utcnow() + timedelta(hours=24)
        
        user_session = UserSession(
            user_id=user.id,
            session_token=session_token,
            pin_verified=False,  # Will be set to True after PIN verification
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        db.session.add(user_session)
        db.session.commit()
        
        # Create JWT token with standard structure
        # Use user_id as subject (string) and other data as additional claims
        access_token = create_access_token(
            identity=str(user.id),  # Standard JWT subject as string
            additional_claims={
                'pin': user.pin,
                'role': user.role,
                'name': user.name,
                'session_token': session_token,
                'login_method': 'username_password',
                'user_id': user.id  # Keep for backward compatibility
            }
        )
        
        # Log successful login
        log_user_activity(
            user_id=user.id,
            session_id=user_session.id,
            action_type='login_success',
            action_details={
                'login_method': 'username_password',
                'username': username
            },
            success=True,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return jsonify({
            'access_token': access_token,
            'user': user.to_dict(),
            'session': user_session.to_dict(),
            'requires_pin': True,  # Always require PIN after login
            'message': 'Login successful. Please enter your PIN (000000) to continue.'
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Login error: {str(e)}")
        import traceback
        traceback.print_exc()
        return jsonify({'error': 'Login failed', 'details': str(e)}), 500

@app.route('/api/verify-pin', methods=['POST'])
@jwt_required()
def verify_pin():
    """Verify PIN after login to enable full access - expects only {"pin": "000000"}"""
    try:
        data = request.get_json()
        if not data or 'pin' not in data:
            return jsonify({'error': 'PIN is required'}), 400
        
        pin = str(data['pin']).strip()
        
        # Get user from new JWT structure
        user = get_user_from_token()
        if not user:
            return jsonify({'error': 'Invalid session or user not found'}), 401
        
        # Verify PIN
        if not user.check_pin(pin):
            ip_address, user_agent = get_client_info(request)
            log_user_activity(
                user_id=user.id,
                action_type='pin_verification_failed',
                action_details={'pin_attempt': pin},
                success=False,
                error_message='Invalid PIN',
                ip_address=ip_address,
                user_agent=user_agent
            )
            return jsonify({'error': 'Invalid PIN'}), 401
        
        # Update session to mark PIN as verified
        session = get_session_from_token()
        if not session or session.user_id != user.id:
            return jsonify({'error': 'Session not found or invalid'}), 404
        
        # Update session PIN verification status
        session.pin_verified = True
        session.last_activity = datetime.utcnow()
        db.session.commit()
        
        # Log successful PIN verification
        ip_address, user_agent = get_client_info(request)
        from flask_jwt_extended import get_jwt
        claims = get_jwt()
        
        log_user_activity(
            user_id=user.id,
            session_id=session.id,
            action_type='pin_verification_success',
            action_details={'login_method': claims.get('login_method', 'unknown')},
            success=True,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return jsonify({
            'message': 'PIN verified successfully',
            'user': user.to_dict(),
            'session': session.to_dict()
        }), 200
            
    except Exception as e:
        db.session.rollback()
        print(f"PIN verification error: {str(e)}")
        return jsonify({'error': 'PIN verification failed', 'details': str(e)}), 500

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    """Enhanced logout with session management"""
    try:
        # Get user and session from new JWT structure
        user = get_user_from_token()
        session = get_session_from_token()
        
        if user and session:
            # Deactivate session
            if session.user_id == user.id:
                session.is_active = False
                db.session.commit()
                
                # Log logout activity
                ip_address, user_agent = get_client_info(request)
                log_user_activity(
                    user_id=user.id,
                    session_id=session.id,
                    action_type='logout',
                    action_details={'session_duration': str(datetime.utcnow() - session.created_at)},
                    success=True,
                    ip_address=ip_address,
                    user_agent=user_agent
                )
        
        return jsonify({'message': 'Logout successful'}), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed', 'details': str(e)}), 500

# ================= USER ACTIVITY & MANAGEMENT APIs =================

@app.route('/api/user/activity-logs', methods=['GET'])
@jwt_required()
def get_user_activity_logs():
    """Get activity logs for current user or all users (admin only)"""
    try:
        current_user_data = get_jwt_identity()
        current_user = User.query.get(current_user_data['user_id'])
        
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check PIN verification
        session = get_session_from_token()
        if not session or not session.pin_verified:
            return jsonify({'error': 'PIN verification required'}), 403
        
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        per_page = min(request.args.get('per_page', 50, type=int), 100)
        user_id = request.args.get('user_id', type=int)
        action_type = request.args.get('action_type')
        
        # Build query
        query = UserActivityLog.query
        
        # If not admin, only show own logs
        if current_user.role != 'admin':
            query = query.filter_by(user_id=current_user.id)
        elif user_id:  # Admin can filter by specific user
            query = query.filter_by(user_id=user_id)
        
        # Filter by action type if specified
        if action_type:
            query = query.filter_by(action_type=action_type)
        
        # Order by most recent first
        query = query.order_by(UserActivityLog.created_at.desc())
        
        # Paginate
        logs = query.paginate(page=page, per_page=per_page, error_out=False)
        
        return jsonify({
            'logs': [log.to_dict() for log in logs.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': logs.total,
                'pages': logs.pages,
                'has_next': logs.has_next,
                'has_prev': logs.has_prev
            }
        }), 200
        
    except Exception as e:
        print(f"Activity logs error: {str(e)}")
        return jsonify({'error': 'Failed to fetch activity logs', 'details': str(e)}), 500

@app.route('/api/admin/users', methods=['GET'])
@jwt_required()
def get_all_users():
    """Get all users (admin only)"""
    try:
        current_user_data = get_jwt_identity()
        current_user = User.query.get(current_user_data['user_id'])
        
        if not current_user or current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        # Check PIN verification
        session = get_session_from_token()
        if not session or not session.pin_verified:
            return jsonify({'error': 'PIN verification required'}), 403
        
        users = User.query.all()
        return jsonify({
            'users': [user.to_dict() for user in users]
        }), 200
        
    except Exception as e:
        print(f"Get users error: {str(e)}")
        return jsonify({'error': 'Failed to fetch users', 'details': str(e)}), 500

@app.route('/api/admin/users/<int:user_id>/toggle-status', methods=['POST'])
@jwt_required()
def toggle_user_status(user_id):
    """Toggle user active status (admin only)"""
    try:
        current_user_data = get_jwt_identity()
        current_user = User.query.get(current_user_data['user_id'])
        
        if not current_user or current_user.role != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        
        # Check PIN verification
        session = get_session_from_token()
        if not session or not session.pin_verified:
            return jsonify({'error': 'PIN verification required'}), 403
        
        target_user = User.query.get(user_id)
        if not target_user:
            return jsonify({'error': 'User not found'}), 404
        
        # Don't allow deactivating self
        if target_user.id == current_user.id:
            return jsonify({'error': 'Cannot deactivate your own account'}), 400
        
        # Toggle status
        target_user.is_active = not target_user.is_active
        db.session.commit()
        
        # Log the action
        ip_address, user_agent = get_client_info(request)
        log_user_activity(
            user_id=current_user.id,
            session_id=session.id,
            action_type='user_status_changed',
            resource_type='user',
            resource_id=str(target_user.id),
            action_details={
                'target_user': target_user.username,
                'new_status': 'active' if target_user.is_active else 'inactive'
            },
            success=True,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return jsonify({
            'message': f'User {target_user.username} has been {"activated" if target_user.is_active else "deactivated"}',
            'user': target_user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        print(f"Toggle user status error: {str(e)}")
        return jsonify({'error': 'Failed to toggle user status', 'details': str(e)}), 500

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
@cache.cached(timeout=60, query_string=True) 
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
                "วันที่แจ้ง": ticket.created_at.strftime('%Y-%m-%d %H:%M') if ticket.created_at else "",
                "สถานะ": ticket.status,
                "Appointment": validate_appointment_field(ticket.appointment, ticket.created_at),
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

# ---------- Type-Group-Subgroup endpoints ----------
TYPE_GROUP_FILE = 'type_group.json'

def _load_tgs() -> dict:
    if os.path.exists(TYPE_GROUP_FILE):
        try:
            with open(TYPE_GROUP_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def _save_tgs(data: dict) -> None:
    with open(TYPE_GROUP_FILE, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

@app.route('/type-group-subgroup', methods=['GET', 'OPTIONS'])
def get_type_group_subgroup():
    """Return mapping of Type->Group->Subgroup. Returns {{}} if none."""
    return jsonify(_load_tgs())

@app.route('/type-group-subgroup', methods=['POST', 'OPTIONS'])
def save_type_group_subgroup():
    """Save full mapping JSON sent from frontend."""
    data = request.get_json()
    if not isinstance(data, dict):
        return jsonify({'error': 'invalid format'}), 400
    try:
        _save_tgs(data)
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ---------- Ticket create & update endpoints ----------

@app.route('/create-ticket', methods=['POST'])
@jwt_required()
def create_ticket():
    """Create a new ticket with user activity logging"""
    try:
        # Get current user and session
        current_user_data = get_jwt_identity()
        current_user = User.query.get(current_user_data['user_id'])
        
        if not current_user:
            return jsonify({'error': 'User not found'}), 404
        
        # Check PIN verification
        session = get_session_from_token()
        if not session or not session.pin_verified:
            return jsonify({'error': 'PIN verification required'}), 403
        
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        ticket_id = data.get('ticket_id') or str(uuid.uuid4())
        if Ticket.query.get(ticket_id):
            return jsonify({"error": "Ticket ID already exists"}), 400

        # Create new ticket
        new_ticket = Ticket()
        new_ticket.ticket_id  = ticket_id
        new_ticket.user_id    = str(current_user.id)  # Link ticket to user
        new_ticket.email      = data.get('email')
        new_ticket.name       = data.get('name')
        new_ticket.phone      = data.get('phone')
        new_ticket.department = data.get('department')
        new_ticket.created_at = datetime.utcnow()
        new_ticket.status     = data.get('status', 'OPEN')
        new_ticket.appointment= data.get('appointment')
        new_ticket.type       = data.get('type')
        new_ticket.subgroup   = data.get('subgroup')
        new_ticket.requested  = data.get('request', data.get('requested'))
        new_ticket.report     = data.get('report')
        new_ticket.textbox    = data.get('textbox')
        
        db.session.add(new_ticket)
        db.session.commit()
        
        # Log ticket creation activity
        ip_address, user_agent = get_client_info(request)
        log_user_activity(
            user_id=current_user.id,
            session_id=session.id,
            action_type='create_ticket',
            resource_type='ticket',
            resource_id=ticket_id,
            action_details={
                'ticket_type': data.get('type'),
                'status': data.get('status', 'OPEN'),
                'department': data.get('department'),
                'customer_name': data.get('name'),
                'customer_email': data.get('email')
            },
            success=True,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        return jsonify({"success": True, "ticket_id": ticket_id}), 201
        
    except Exception as e:
        db.session.rollback()
        print(f"Create ticket error: {str(e)}")
        
        # Log failed ticket creation
        try:
            current_user_data = get_jwt_identity()
            if current_user_data:
                ip_address, user_agent = get_client_info(request)
                log_user_activity(
                    user_id=current_user_data.get('user_id'),
                    action_type='create_ticket_failed',
                    action_details={'error': str(e)},
                    success=False,
                    error_message=str(e),
                    ip_address=ip_address,
                    user_agent=user_agent
                )
        except:
            pass
            
        return jsonify({"error": str(e)}), 500


def update_ticket():

    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400

    ticket_id = data.get('ticket_id')
    if not ticket_id:
        return jsonify({"error": "ticket_id required"}), 400

    try:
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404

        # update general fields
        ticket.type       = data.get('type', ticket.type)
        ticket.subgroup   = data.get('subgroup', ticket.subgroup)
        ticket.appointment= data.get('appointment', ticket.appointment)
        ticket.status     = data.get('status', ticket.status)
        
        ticket.requested  = data.get('request', data.get('requested', ticket.requested))
        ticket.report     = data.get('report', ticket.report)
        # ----------------------------
        db.session.commit()
        return jsonify({"success": True}), 200
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

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
                "appointment": validate_appointment_field(ticket.appointment, ticket.created_at),
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
    note = data.get("note", "")  # รับหมายเหตุจาก frontend
    remarks = data.get("remarks", "")  # หมายเหตุเพิ่มเติมจาก frontend (ถ้ามี)

    if not ticket_id or not new_status:
        return jsonify({"error": "ticket_id and status required"}), 400

    try:
        # Update PostgreSQL using SQLAlchemy
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
            
        current_status = ticket.status

        # ---- Enhanced field updates ----
        original_type = ticket.type
        original_requested = ticket.requested
        original_report = ticket.report
        original_subgroup = ticket.subgroup

        # Apply updates from payload (group/request/report/type)
        ticket.type = data.get('type', ticket.type)
        ticket.subgroup = data.get('subgroup', ticket.subgroup)
        ticket.requested = data.get('request', data.get('requested', ticket.requested))
        ticket.report = data.get('report', ticket.report)

        fields_changed = (
            current_status != new_status or
            original_type != ticket.type or
            original_requested != ticket.requested or
            original_report != ticket.report or
            original_subgroup != ticket.subgroup
        )
        # ---------------------------------
        if current_status != new_status:
            ticket.status = new_status
            ticket.subgroup = data.get('subgroup', ticket.subgroup)

            # Determine who performed the change
            actor = data.get("changed_by")
            if not actor:
                try:
                    current_user = get_jwt_identity()
                    if isinstance(current_user, dict):
                        actor = current_user.get("name") or current_user.get("pin")
                    else:
                        actor = str(current_user)
                except Exception:
                    actor = "admin"

            # Create a log entry for this status change with note
            log_entry = TicketStatusLog(
                ticket_id=ticket.ticket_id,
                old_status=current_status,
                new_status=new_status,
                changed_by=actor,
                changed_at=datetime.utcnow(),
                note=note,
                remarks=remarks
            )
            db.session.add(log_entry)

            # Create notification with note if provided
            notification_msg = f"Ticket #{ticket_id} ({ticket.name}) changed from {current_status} to {new_status}"
            if note:
                notification_msg += f"\nหมายเหตุ: {note}"
            add_notification_to_db(
                message=notification_msg,
                sender_name=actor,
                user_id=ticket.user_id,
                meta_data={
                    "type": "status_change",
                    "ticket_id": ticket_id,
                    "old_status": current_status,
                    "new_status": new_status,
                    "note": note,
                    "remarks": remarks
                }
            )

            db.session.commit()
            # Clear cache so that clients receive the latest data immediately after an update
            try:
                # Attempt to remove specifically memoized get_data and get_appointments endpoints
                if 'get_data' in globals():
                    cache.delete_memoized(get_data)
                cache.delete_memoized(get_appointments)
            except Exception as cache_err:
                # As a fallback (e.g. when running with SimpleCache) clear all cache
                cache.clear()
                print(f"[update_status] Cache clear fallback triggered: {cache_err}")

            # ส่ง LINE notification
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
                    'note': note,  # ส่งหมายเหตุไปด้วย
                    'remarks': remarks
                }
                notify_user(payload)
                
            return jsonify({
                "success": True,
                "message": "Status updated with note",
                "note": note,
                "remarks": remarks
            })
        else:
            return jsonify({"message": "Status unchanged"})
            
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route("/delete-ticket", methods=["POST"])
def delete_ticket():
    data       = request.get_json()
    ticket_id  = data.get("ticket_id")

    if not ticket_id:
        return jsonify({"error": "ticket_id required"}), 400

    try:
        # 1) ลบ TicketStatusLog และ Message ที่อ้างถึง ticket_id นี้ก่อน แล้ว commit แยก
        try:
            TicketStatusLog.query.filter_by(ticket_id=ticket_id).delete(synchronize_session=False)
            Message.query.filter_by(ticket_id=ticket_id).delete(synchronize_session=False)
            db.session.commit()  # commit ทันทีเพื่อให้ DB ลบ record เหล่านั้นจริง ๆ
        except Exception as msg_err:
            db.session.rollback()
            return jsonify({"error": f"Failed to delete related messages: {msg_err}"}), 500

        # 2) ลบ ticket หลังจากข้อความถูกลบไปแล้ว จึงไม่ติด FK
        try:
            ticket = Ticket.query.get(ticket_id)
            if not ticket:
                return jsonify({"error": "Ticket not found"}), 404

            db.session.delete(ticket)
            db.session.commit()
            return jsonify({"success": True}), 200
        except Exception as tk_err:
            db.session.rollback()
            return jsonify({"error": f"Failed to delete ticket: {tk_err}"}), 500

    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

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
    sender_type = data.get("sender_type")

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
            # validation sender_type
            if not sender_type:
                if admin_id:
                    sender_type = 'admin'
                else:
                    sender_type = 'user'
            if sender_type not in ['user', 'admin']:
                return jsonify({"error": "sender_type must be 'user' or 'admin'"}), 400
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
                if sender_type == 'admin':
                    notif_msg = f"New message from admin to user {ticket_id}: {new_text}"
                else:
                    notif_msg = f"New message from user {ticket_id}: {new_text}"
                add_notification_to_db(
                    message=notif_msg,
                    sender_name=admin_id if sender_type == 'admin' else ticket.name,
                    user_id=ticket_id,
                    meta_data={
                        "type": "new_message",
                        "user_id": ticket_id,
                        "sender_type": sender_type
                    }
                )
            
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
        add_notification_to_db(
            message=f"New announcement: {message}",
            sender_name="system",
            user_id=None,
            meta_data={"type": "announcement"}
        )

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
            add_notification_to_db(
                message=f"Ticket #{ticket_id} ({ticket.name}) changed from {previous_status} to {ticket.status}",
                sender_name=actor,
                user_id=ticket.user_id,
                meta_data={
                    "type": "status_change",
                    "ticket_id": ticket_id,
                    "old_status": previous_status,
                    "new_status": ticket.status
                }
            )

        # ถ้า status ใหม่เป็น Cancelled ให้ลบ ticket และ message ที่เกี่ยวข้องทันที
        if 'status' in data and data['status'] == 'Cancelled':
            # ลบ message ที่เกี่ยวข้อง
            Message.query.filter_by(user_id=ticket_id).delete()
            db.session.delete(ticket)
            # สร้าง notification
            add_notification_to_db(
                message=f"Ticket {ticket_id} has been cancelled and deleted.",
                sender_name="system",
                user_id=ticket_id,
                meta_data={"type": "ticket_cancelled", "ticket_id": ticket_id}
            )
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
                "วันที่แจ้ง": row[5].strftime('%Y-%m-%d %H:%M') if row[5] else "",
                "สถานะ": row[6],
                "Appointment": validate_appointment_field(row[7], row[5]),
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

# Helper function to validate appointment field
def validate_appointment_field(appointment_value, created_at_value):
    """Return None only when appointment exactly equals created_at timestamp.
    Supports both formats:
    - Service type: 2025-07-30 08:00-09:00 (time range)
    - Helpdesk type: 2025-07-30 13:00:28 (timestamp, but not created_at)
    """
    if not appointment_value or not created_at_value:
        return appointment_value
    
    # Convert appointment to string and strip whitespace
    appointment_str = str(appointment_value).strip()
    
    # If appointment is empty after stripping, return None
    if not appointment_str:
        return None
    
    # Convert created_at to exact format for comparison
    created_at_exact = created_at_value.strftime('%Y-%m-%d %H:%M:%S')
    
    # Only filter out if appointment EXACTLY matches created_at timestamp
    # This preserves both Service format (2025-07-30 08:00-09:00) 
    # and valid Helpdesk timestamps that differ from created_at
    if appointment_str == created_at_exact:
        return None  # This is invalid - appointment should not equal created_at
    
    # All other formats are valid (Service time ranges, different timestamps, etc.)
    return appointment_value

# ------------------- API: /api/data-by-date-range -------------------
@app.route('/api/data-by-date-range', methods=['GET'])
def get_data_by_date_range():
    """Return tickets whose created_at falls between start_date and end_date (inclusive).
    Query params:
        start_date: YYYY-MM-DD
        end_date:   YYYY-MM-DD
    """
    start_date_str = request.args.get('start_date')
    end_date_str = request.args.get('end_date')

    if not start_date_str or not end_date_str:
        return jsonify({"error": "start_date and end_date parameters are required"}), 400

    try:
        # Parse input dates
        start_date = datetime.strptime(start_date_str, '%Y-%m-%d').date()
        end_date = datetime.strptime(end_date_str, '%Y-%m-%d').date()

        if start_date > end_date:
            return jsonify({"error": "start_date cannot be after end_date"}), 400

        # Query database
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        cur = conn.cursor()
        
        # Filter by created_at date range using exclusive upper bound
        start_datetime = datetime.combine(start_date, datetime.min.time())
        # Use next day at 00:00:00 as exclusive upper bound
        next_day = end_date + timedelta(days=1)
        end_datetime = datetime.combine(next_day, datetime.min.time())
        
        # Filter by created_at date range (removed debug print for production)
        
        cur.execute(
            """
            SELECT ticket_id, email, name, phone, department,
                   created_at, status, appointment,
                   requested, report, type, textbox
            FROM tickets
            WHERE created_at >= %s AND created_at < %s
            ORDER BY created_at DESC
            """,
            (start_datetime, end_datetime)
        )

        rows = cur.fetchall()
        result = [
            {
                "Ticket ID": row[0],
                "อีเมล": row[1],
                "ชื่อ": row[2],
                "เบอร์ติดต่อ": row[3],
                "แผนก": row[4],
                "วันที่แจ้ง": row[5].strftime('%Y-%m-%d %H:%M') if row[5] else "",
                "สถานะ": row[6],
                "Appointment": validate_appointment_field(row[7], row[5]),
                "Requeste": row[8],
                "Report": row[9],
                "Type": row[10],
                "TEXTBOX": row[11]
            }
            for row in rows
        ]

        if not rows:
            return jsonify({"message": "No data found for the selected date range", "data": []})
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
    if not user_id or not message:
        return jsonify({"error": "user_id and message are required"}), 400
    # validation sender_type
    if not sender_type:
        # ถ้า admin_id มีค่า ให้ default เป็น 'admin' ถ้าไม่มีก็ 'user'
        if admin_id:
            sender_type = 'admin'
        else:
            sender_type = 'user'
    if sender_type not in ['user', 'admin']:
        return jsonify({"error": "sender_type must be 'user' or 'admin'"}), 400
    msg = Message()
    msg.user_id = user_id
    msg.admin_id = admin_id
    msg.sender_type = sender_type
    msg.message = message
    msg.timestamp = datetime.utcnow()
    db.session.add(msg)
    # --- เพิ่ม Notification ทุกครั้งที่มีข้อความใหม่ ---
    # ดึงชื่อผู้ใช้จาก ticket
    ticket = Ticket.query.filter_by(ticket_id=user_id).first()
    user_name = ticket.name if ticket else user_id
    notif_msg = f"New message from {'admin' if sender_type == 'admin' else 'user'} to user {user_id}: {message}"
    add_notification_to_db(
        message=notif_msg,
        sender_name=user_name,
        user_id=user_id,
        meta_data={
            "type": "new_message",
            "user_id": user_id,
            "sender_name": user_name
        }
    )
    db.session.commit()
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
                    "วันที่แจ้ง": row[5].strftime('%Y-%m-%d %H:%M') if row[5] else "",
                    "สถานะ": row[6],
                    "Appointment": validate_appointment_field(row[7], row[5]),
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

@app.route('/update-status-with-note', methods=['POST'])
def update_status_with_note():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    
    ticket_id = data.get("ticket_id")
    new_status = data.get("status")
    note = data.get("note", "")
    remarks = data.get("remarks", "")

    if not ticket_id or not new_status:
        return jsonify({"error": "ticket_id and status required"}), 400

    try:
        ticket = Ticket.query.get(ticket_id)
        if not ticket:
            return jsonify({"error": "Ticket not found"}), 404
            
        current_status = ticket.status
        if current_status != new_status:
            ticket.status = new_status
            ticket.subgroup = data.get('subgroup', ticket.subgroup)
            
            actor = data.get("changed_by")
            if not actor:
                try:
                    current_user = get_jwt_identity()
                    if isinstance(current_user, dict):
                        actor = current_user.get("name") or current_user.get("pin")
                    else:
                        actor = str(current_user)
                except Exception:
                    actor = "admin"
                    
            log_entry = TicketStatusLog(
                ticket_id=ticket.ticket_id,
                old_status=current_status,
                new_status=new_status,
                changed_by=actor,
                changed_at=datetime.utcnow()
            )
            db.session.add(log_entry)
            
            notification_msg = f"Ticket #{ticket_id} ({ticket.name}) changed from {current_status} to {new_status}"
            if note:
                notification_msg += f"\nหมายเหตุ: {note}"
            add_notification_to_db(
                message=notification_msg,
                sender_name=actor,
                user_id=ticket.user_id,
                meta_data={
                    "type": "status_change",
                    "ticket_id": ticket_id,
                    "old_status": current_status,
                    "new_status": new_status,
                    "note": note,
                    "remarks": remarks
                }
            )
            
            db.session.commit()
            
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
                    'note': note
                }
                notify_user(payload)
                
            return jsonify({
                "success": True,
                "message": "Status updated with notes",
                "note": note,
                "remarks": remarks
            })
        else:
            return jsonify({"message": "Status unchanged"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

@app.route('/api/check-new-messages', methods=['GET'])
def check_new_messages():
    # รับ last_checked เป็น ISO8601 string
    last_checked = request.args.get('last_checked')
    if not last_checked:
        return jsonify({"error": "last_checked required"}), 400

    try:
        last_checked_dt = datetime.fromisoformat(last_checked)
    except Exception:
        return jsonify({"error": "Invalid last_checked format"}), 400

    # ดึงเฉพาะข้อความใหม่ที่ sender_type == 'user' และ timestamp > last_checked
    new_msgs = (
        Message.query
        .filter(Message.sender_type == 'user', Message.timestamp > last_checked_dt)
        .order_by(desc(Message.timestamp))
        .all()
    )
    # รวมกลุ่มตาม user_id
    user_map = {}
    for msg in new_msgs:
        if msg.user_id not in user_map:
            user_map[msg.user_id] = {
                "user_id": msg.user_id,
                "messages": [],
                "name": None  # จะเติมชื่อจาก ticket
            }
        user_map[msg.user_id]["messages"].append(msg.to_dict())

    # เติมชื่อผู้ใช้จาก ticket
    for user_id in user_map:
        ticket = Ticket.query.filter_by(ticket_id=user_id).first()
        user_map[user_id]["name"] = ticket.name if ticket else user_id

    return jsonify({"new_messages": list(user_map.values())})

# เพิ่ม endpoint สำหรับแก้ sender_type ที่เป็น null ในฐานข้อมูล (ใช้สำหรับแก้ข้อมูลเก่า)
@app.route('/api/fix-null-sender-type', methods=['POST'])
def fix_null_sender_type():
    try:
        from sqlalchemy import text
        # update sender_type = 'admin' ถ้า admin_id ไม่เป็น null
        db.session.execute(text("""
            UPDATE messages SET sender_type = 'admin' WHERE sender_type IS NULL AND admin_id IS NOT NULL;
        """))
        # update sender_type = 'user' ถ้า admin_id เป็น null
        db.session.execute(text("""
            UPDATE messages SET sender_type = 'user' WHERE sender_type IS NULL AND admin_id IS NULL;
        """))
        db.session.commit()
        return jsonify({"success": True, "message": "Fixed null sender_type in messages table"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500

# เพิ่ม endpoint สำหรับเพิ่ม notification โดยตรง (optional)
@app.route('/api/add-notification', methods=['POST'])
def api_add_notification():
    data = request.get_json()
    if not data:
        return jsonify({"error": "No JSON data provided"}), 400
    message = data.get('message')
    sender_name = data.get('sender_name')
    user_id = data.get('user_id')
    meta_data = data.get('meta_data')
    if not message or not sender_name:
        return jsonify({"error": "message and sender_name are required"}), 400
    notif = add_notification_to_db(message, sender_name, user_id, meta_data)
    return jsonify({"success": True, "notification": notif.to_dict()})

from datetime import datetime, timedelta

def add_notification_to_db(message, sender_name, user_id=None, meta_data=None):
    now = datetime.utcnow()
    # ตรวจสอบซ้ำ (เช่น 10 วินาที)
    duplicate = db.session.query(Notification).filter(
        Notification.user_id == user_id,
        Notification.message == message,
        Notification.sender_name == sender_name,
        Notification.timestamp > now - timedelta(seconds=10)
    ).first()
    if duplicate:
        return duplicate  # return ตัวเดิม ไม่ต้อง insert ใหม่

    notif = Notification(
        message=message,
        timestamp=now,
        read=False,
        sender_name=sender_name,
        user_id=user_id,
        meta_data=meta_data if meta_data else None
    )
    db.session.add(notif)
    db.session.commit()
    return notif

# ------------------- In-memory data for types, groups, subgroups -------------------
TICKET_TYPES = [
    {"id": 1, "name": "Service"},
    {"id": 2, "name": "Helpdesk"},
    {"id": 3, "name": "Information"}
]

# ตัวอย่าง groups และ subgroups (สามารถแก้ไข/เพิ่มได้)
TICKET_GROUPS = {
    "Service": [
        {"id": 1, "name": "Hardware"},
        {"id": 2, "name": "Software"}
    ],
    "Helpdesk": [
        {"id": 3, "name": "Network"},
        {"id": 4, "name": "Account"}
    ]
}
TICKET_SUBGROUPS = {
    ("Service", "Hardware"): [
        {"id": 1, "name": "PC"},
        {"id": 2, "name": "Printer"}
    ],
    ("Service", "Software"): [
        {"id": 3, "name": "Windows"},
        {"id": 4, "name": "Office"}
    ],
    ("Helpdesk", "Network"): [
        {"id": 5, "name": "WiFi"},
        {"id": 6, "name": "LAN"}
    ],
    ("Helpdesk", "Account"): [
        {"id": 7, "name": "Email"},
        {"id": 8, "name": "AD"}
    ]
}
# ------------------- API: /api/types -------------------
from flask import abort

@app.route('/api/types', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_types():
    if request.method == 'GET':
        return jsonify(TICKET_TYPES)
    elif request.method == 'POST':
        data = request.get_json()
        if not data or 'name' not in data:
            return jsonify({'error': 'name is required'}), 400
        new_id = max([t['id'] for t in TICKET_TYPES], default=0) + 1
        new_type = {"id": new_id, "name": data['name']}
        TICKET_TYPES.append(new_type)
        return jsonify(new_type), 201
    elif request.method == 'PUT':
        data = request.get_json()
        if not data or 'id' not in data or 'name' not in data:
            return jsonify({'error': 'id and name are required'}), 400
        for t in TICKET_TYPES:
            if t['id'] == data['id']:
                t['name'] = data['name']
                return jsonify(t)
        return jsonify({'error': 'type not found'}), 404
    elif request.method == 'DELETE':
        data = request.get_json()
        if not data or 'id' not in data:
            return jsonify({'error': 'id is required'}), 400
        for t in TICKET_TYPES:
            if t['id'] == data['id']:
                TICKET_TYPES.remove(t)
                return jsonify({'success': True})
        return jsonify({'error': 'type not found'}), 404

# ------------------- API: /api/groups -------------------
@app.route('/api/groups', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_groups():
    type_name = request.args.get('type')
    if not type_name:
        return jsonify({'error': 'type parameter is required'}), 400
    if request.method == 'GET':
        return jsonify(TICKET_GROUPS.get(type_name, []))
    elif request.method == 'POST':
        data = request.get_json()
        if not data or 'name' not in data:
            return jsonify({'error': 'name is required'}), 400
        group_list = TICKET_GROUPS.setdefault(type_name, [])
        new_id = max([g['id'] for g in group_list], default=0) + 1
        new_group = {"id": new_id, "name": data['name']}
        group_list.append(new_group)
        return jsonify(new_group), 201
    elif request.method == 'PUT':
        data = request.get_json()
        if not data or 'id' not in data or 'name' not in data:
            return jsonify({'error': 'id and name are required'}), 400
        group_list = TICKET_GROUPS.get(type_name, [])
        for g in group_list:
            if g['id'] == data['id']:
                g['name'] = data['name']
                return jsonify(g)
        return jsonify({'error': 'group not found'}), 404
    elif request.method == 'DELETE':
        data = request.get_json()
        if not data or 'id' not in data:
            return jsonify({'error': 'id is required'}), 400
        group_list = TICKET_GROUPS.get(type_name, [])
        for g in group_list:
            if g['id'] == data['id']:
                group_list.remove(g)
                return jsonify({'success': True})
        return jsonify({'error': 'group not found'}), 404

# ------------------- API: /api/subgroups -------------------
@app.route('/api/subgroups', methods=['GET', 'POST', 'PUT', 'DELETE'])
def api_subgroups():
    type_name = request.args.get('type')
    group_name = request.args.get('group')
    if not type_name or not group_name:
        return jsonify({'error': 'type and group parameters are required'}), 400
    key = (type_name, group_name)
    if request.method == 'GET':
        return jsonify(TICKET_SUBGROUPS.get(key, []))
    elif request.method == 'POST':
        data = request.get_json()
        if not data or 'name' not in data:
            return jsonify({'error': 'name is required'}), 400
        sub_list = TICKET_SUBGROUPS.setdefault(key, [])
        new_id = max([s['id'] for s in sub_list], default=0) + 1
        new_sub = {"id": new_id, "name": data['name']}
        sub_list.append(new_sub)
        return jsonify(new_sub), 201
    elif request.method == 'PUT':
        data = request.get_json()
        if not data or 'id' not in data or 'name' not in data:
            return jsonify({'error': 'id and name are required'}), 400
        sub_list = TICKET_SUBGROUPS.get(key, [])
        for s in sub_list:
            if s['id'] == data['id']:
                s['name'] = data['name']
                return jsonify(s)
        return jsonify({'error': 'subgroup not found'}), 404
    elif request.method == 'DELETE':
        data = request.get_json()
        if not data or 'id' not in data:
            return jsonify({'error': 'id is required'}), 400
        sub_list = TICKET_SUBGROUPS.get(key, [])
        for s in sub_list:
            if s['id'] == data['id']:
                sub_list.remove(s)
                return jsonify({'success': True})
        return jsonify({'error': 'subgroup not found'}), 404

if __name__ == '__main__':
    with app.app_context():
        create_tickets_table()
        create_ticket_status_logs_table()
    app.run(host='0.0.0.0', port=5001, debug=False)